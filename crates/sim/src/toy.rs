// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A toy peer that proves the harness: a set-union replicator.
//!
//! Each peer creates a few items of its own at start, persists every item it
//! holds, and gossips its whole set: to each peer as it connects, to one peer
//! chosen at random on every tick, and to everyone else as soon as it learns
//! something new; a peer that receives a set it can add to replies with its own.
//! Set union is a join, so the peers converge however connections drop (every
//! reconnection starts with a fresh exchange, so nothing relies on a lost
//! message being sent again) and however messages on different connections
//! overtake each other, and a restarted peer comes back with what it had
//! committed. The transport carries bytes in chunks split anywhere, so each
//! set travels as one frame of the [`crate::frame`] format and each
//! connection has its own [`Deframer`]; a frame that announces more than a
//! set may hold makes the receiver hang up. It reads the wall clock on every
//! tick, only to show that the clock reaches a peer; nothing it decides
//! depends on it. It is deliberately
//! simple: it exists so that every handler of the engine's [`Peer`] trait and
//! every fault the simulator injects is exercised by the tests, not to resemble
//! the real engine.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use licketysync_engine::runtime::{Context, Instant, Peer, PeerId, TimerId};

use crate::frame::{frame, Deframer};
use crate::scenario::Sim;

/// The gossip tick.
pub const TICK: TimerId = TimerId::new(1);

/// The most items a message may carry; a frame announcing more makes the
/// receiver hang up before it buffers any of it, as every peer must refuse
/// what it cannot afford to parse.
pub const MAX_ITEMS_PER_MESSAGE: usize = 65_536;

/// The longest frame payload a toy peer accepts: a full set.
const MAX_FRAME: usize = MAX_ITEMS_PER_MESSAGE * 8;

const ITEM_PREFIX: &[u8] = b"item/";
const CLEAN_STOP_KEY: &[u8] = b"clean-stop";

/// A set-union replicator.
#[derive(Debug)]
pub struct SetUnion {
    items: BTreeSet<u64>,
    unsaved: BTreeSet<u64>,
    peers: BTreeSet<PeerId>,
    streams: BTreeMap<PeerId, Deframer>,
    items_per_peer: u32,
    tick: Duration,
    deaf: bool,
    ticks: u64,
    wall: u64,
}

impl SetUnion {
    /// A peer that creates `items_per_peer` items at start and gossips every
    /// `tick`.
    #[must_use]
    pub const fn new(items_per_peer: u32, tick: Duration) -> Self {
        Self {
            items: BTreeSet::new(),
            unsaved: BTreeSet::new(),
            peers: BTreeSet::new(),
            streams: BTreeMap::new(),
            items_per_peer,
            tick,
            deaf: false,
            ticks: 0,
            wall: 0,
        }
    }

    /// A broken peer that ignores everything it receives, so that a run of
    /// them never converges: the harness must report that, with the seed.
    #[must_use]
    pub fn deaf(items_per_peer: u32, tick: Duration) -> Self {
        let mut peer = Self::new(items_per_peer, tick);
        peer.deaf = true;
        peer
    }

    /// The items this peer holds.
    #[must_use]
    pub const fn items(&self) -> &BTreeSet<u64> {
        &self.items
    }

    /// Items held in memory that are not yet committed to storage.
    #[must_use]
    pub fn unsaved(&self) -> usize {
        self.unsaved.len()
    }

    /// The peers this peer believes it is connected to.
    #[must_use]
    pub const fn connected(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    /// How many ticks fired since this instance started.
    #[must_use]
    pub const fn ticks(&self) -> u64 {
        self.ticks
    }

    /// What the wall clock read, in seconds since the Unix epoch, when this
    /// instance last started or ticked.
    #[must_use]
    pub const fn wall_time(&self) -> u64 {
        self.wall
    }

    /// The items `peer` creates at start: its id in the high half, a counter
    /// in the low half, so no two peers create the same item.
    pub fn own_items(peer: PeerId, items_per_peer: u32) -> impl Iterator<Item = u64> {
        (0..items_per_peer).map(move |k| (peer.as_u64() << 32) | u64::from(k))
    }

    /// Items as a message: each as eight big-endian bytes, ascending.
    #[must_use]
    pub fn encode(items: &BTreeSet<u64>) -> Vec<u8> {
        let mut out = Vec::with_capacity(items.len().saturating_mul(8));
        for item in items {
            out.extend_from_slice(&item.to_be_bytes());
        }
        out
    }

    /// A message back into items, or `None` when it is not a whole number of
    /// items or carries more than [`MAX_ITEMS_PER_MESSAGE`].
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Vec<u64>> {
        if bytes.len() % 8 != 0 || bytes.len() / 8 > MAX_ITEMS_PER_MESSAGE {
            return None;
        }
        bytes
            .chunks_exact(8)
            .map(|chunk| <[u8; 8]>::try_from(chunk).ok().map(u64::from_be_bytes))
            .collect()
    }

    fn key(item: u64) -> Vec<u8> {
        let mut key = ITEM_PREFIX.to_vec();
        key.extend_from_slice(&item.to_be_bytes());
        key
    }

    fn item_of(key: &[u8]) -> Option<u64> {
        let rest = key.strip_prefix(ITEM_PREFIX)?;
        <[u8; 8]>::try_from(rest).ok().map(u64::from_be_bytes)
    }

    /// Writes every unsaved item and commits. What the disk refuses stays
    /// unsaved and is tried again on the next tick.
    fn persist(&mut self, cx: &mut dyn Context) {
        if self.unsaved.is_empty() {
            return;
        }
        let mut staged = BTreeSet::new();
        let mut refused = BTreeSet::new();
        for item in std::mem::take(&mut self.unsaved) {
            if cx.storage().put(&Self::key(item), &[]).is_ok() {
                staged.insert(item);
            } else {
                refused.insert(item);
            }
        }
        if !staged.is_empty() && cx.storage().commit().is_err() {
            cx.storage().rollback();
            refused.append(&mut staged);
        }
        self.unsaved = refused;
    }

    fn send_to(&mut self, cx: &mut dyn Context, to: PeerId) {
        let Some(message) = frame(&Self::encode(&self.items)) else {
            return;
        };
        if cx.send(to, message).is_err() {
            self.peers.remove(&to);
        }
    }

    /// One whole set from `from`.
    fn on_set(&mut self, cx: &mut dyn Context, from: PeerId, payload: &[u8]) {
        let Some(theirs) = Self::decode(payload) else {
            return;
        };
        let theirs: BTreeSet<u64> = theirs.into_iter().collect();
        let mut learned = false;
        for item in &theirs {
            if self.items.insert(*item) {
                self.unsaved.insert(*item);
                learned = true;
            }
        }
        if learned {
            self.persist(cx);
            self.broadcast(cx, Some(from));
        }
        if self.items.iter().any(|item| !theirs.contains(item)) {
            self.send_to(cx, from);
        }
    }

    fn broadcast(&mut self, cx: &mut dyn Context, except: Option<PeerId>) {
        for to in self.peers.clone() {
            if Some(to) != except {
                self.send_to(cx, to);
            }
        }
    }

    fn arm_tick(&self, cx: &mut dyn Context) {
        let at = cx.now().saturating_add(self.tick);
        cx.set_timer(TICK, at);
    }
}

impl Peer for SetUnion {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let local = cx.local_id();
        self.wall = cx.wall_time();
        for (key, _) in cx.storage().scan(ITEM_PREFIX).unwrap_or_default() {
            if let Some(item) = Self::item_of(&key) {
                self.items.insert(item);
            }
        }
        for item in Self::own_items(local, self.items_per_peer) {
            if self.items.insert(item) {
                self.unsaved.insert(item);
            }
        }
        self.persist(cx);
        self.arm_tick(cx);
    }

    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        if self.deaf {
            return;
        }
        let Some(stream) = self.streams.get_mut(&from) else {
            return;
        };
        if let Ok(frames) = stream.push(bytes) {
            for payload in frames {
                self.on_set(cx, from, &payload);
            }
        } else {
            self.streams.remove(&from);
            self.peers.remove(&from);
            cx.close(from);
        }
    }

    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        if id != TICK {
            return;
        }
        self.ticks = self.ticks.saturating_add(1);
        self.wall = cx.wall_time();
        self.persist(cx);
        let count = u64::try_from(self.peers.len()).unwrap_or(u64::MAX);
        if count > 0 {
            let mut pick = [0u8; 8];
            cx.fill_random(&mut pick);
            let index = usize::try_from(u64::from_le_bytes(pick) % count).unwrap_or(0);
            if let Some(to) = self.peers.iter().nth(index).copied() {
                self.send_to(cx, to);
            }
        }
        self.arm_tick(cx);
    }

    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.peers.insert(peer);
        self.streams.insert(peer, Deframer::new(MAX_FRAME));
        self.send_to(cx, peer);
    }

    fn on_disconnected(&mut self, _cx: &mut dyn Context, peer: PeerId) {
        self.peers.remove(&peer);
        self.streams.remove(&peer);
    }

    fn on_stop(&mut self, cx: &mut dyn Context) {
        self.persist(cx);
        let storage = cx.storage();
        if storage
            .put(CLEAN_STOP_KEY, &self.ticks.to_le_bytes())
            .is_ok()
        {
            // A failed commit here is the same as a crash: the simulator's
            // storage shows which it was.
            let _: Result<(), _> = storage.commit();
        }
    }
}

/// How many distinct items `peers` peers create between them.
#[must_use]
pub fn total_items(peers: u32, items_per_peer: u32) -> usize {
    usize::try_from(u64::from(peers) * u64::from(items_per_peer)).unwrap_or(usize::MAX)
}

/// Converged when at least one peer runs and every running peer holds all
/// `total` items with nothing left unsaved. Items are drawn from a universe of
/// exactly `total`, so holding `total` of them is holding them all.
pub fn all_hold(total: usize) -> impl Fn(&Sim<SetUnion>) -> bool {
    move |sim| {
        let mut any = false;
        for (_, peer) in sim.peers() {
            any = true;
            if peer.items().len() != total || peer.unsaved() != 0 {
                return false;
            }
        }
        any
    }
}

/// The time a run gives up: well past what any of the shipped scenarios need.
pub const LIMIT: Instant = Instant::from_secs(120);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_round_trip() {
        let items: BTreeSet<u64> = [3, 1, u64::MAX].into_iter().collect();
        let bytes = SetUnion::encode(&items);
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            SetUnion::decode(&bytes),
            Some(vec![1, 3, u64::MAX]),
            "ascending"
        );
        assert_eq!(SetUnion::decode(&[]), Some(vec![]));
    }

    #[test]
    fn decode_rejects_ragged_and_oversized_messages() {
        assert_eq!(SetUnion::decode(&[0; 7]), None);
        assert_eq!(SetUnion::decode(&[0; 9]), None);
        let too_many = vec![0u8; (MAX_ITEMS_PER_MESSAGE + 1) * 8];
        assert_eq!(SetUnion::decode(&too_many), None);
        let just_enough = vec![0u8; MAX_ITEMS_PER_MESSAGE * 8];
        assert_eq!(
            SetUnion::decode(&just_enough).map(|v| v.len()),
            Some(MAX_ITEMS_PER_MESSAGE)
        );
    }

    #[test]
    fn own_items_are_disjoint_between_peers() {
        let a: BTreeSet<u64> = SetUnion::own_items(PeerId::new(1), 3).collect();
        let b: BTreeSet<u64> = SetUnion::own_items(PeerId::new(2), 3).collect();
        assert_eq!(a.len(), 3);
        assert!(a.is_disjoint(&b));
        assert_eq!(total_items(5, 3), 15);
        assert_eq!(SetUnion::own_items(PeerId::new(0), 0).count(), 0);
    }

    #[test]
    fn storage_keys_round_trip_and_reject_strangers() {
        let key = SetUnion::key(42);
        assert!(key.starts_with(ITEM_PREFIX));
        assert_eq!(SetUnion::item_of(&key), Some(42));
        assert_eq!(SetUnion::item_of(b"item/short"), None);
        assert_eq!(SetUnion::item_of(b"other/00000000"), None);
        assert_eq!(SetUnion::item_of(CLEAN_STOP_KEY), None);
    }

    #[test]
    fn constructors_set_the_mode() {
        let p = SetUnion::new(2, Duration::from_secs(1));
        assert!(!p.deaf);
        assert_eq!(p.ticks(), 0);
        assert_eq!(p.wall_time(), 0, "no clock read yet");
        assert_eq!(p.items().len(), 0);
        assert_eq!(p.connected().len(), 0);
        assert_eq!(p.unsaved(), 0);
        let d = SetUnion::deaf(2, Duration::from_secs(1));
        assert!(d.deaf);
        assert_eq!(d.items_per_peer, 2);
    }
}
