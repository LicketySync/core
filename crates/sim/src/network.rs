// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The simulated network: its configuration, partitions, and the connection
//! state the scheduler consults.
//!
//! The network honours the transport contract of the protocol spec (3.1): one
//! reliable, ordered byte stream per connection. A connection joins two running
//! peers, and each direction of it is a stream: what the sender writes at one
//! instant is gathered, then cut at seeded boundaries into pieces of at most
//! `MAX_CHUNK` bytes, so writes made together coalesce and long ones fragment;
//! each piece travels with its own latency and is handed to the receiver as one
//! `on_message` call, first in first out. While the connection lasts, its bytes
//! arrive once and in order. Loss is modelled as the connection ending: with
//! the configured probability a piece takes its connection down instead of
//! arriving, and the two reconnect after a delay. A connection also ends when a
//! partition cuts it, a peer stops or crashes, a peer hangs up
//! (`Transport::close`), or a sender's unsent queue passes its bound; only a
//! drop reconnects by itself, and a hang-up on a pair with no connection open
//! (after `on_disconnected`, say) changes nothing. When a connection ends, each
//! side that can still receive is handed a seeded prefix of what the other side
//! had in flight, before it hears `on_disconnected`; the rest is lost, so both
//! outcomes of "may be lost" happen. Every ending bumps the connection's epoch,
//! so a piece of the old connection can never reach a new one. Nothing orders
//! different connections: with a wide latency range a piece on one connection
//! overtakes one on another.
//!
//! Phase-0 simplifications: both sides learn that a connection ended at the
//! same instant. In reality one side may believe the connection alive until its
//! own timeout expires, sending into the void meanwhile. And there is no
//! bandwidth model: whatever is written at one instant, however much, is cut
//! into pieces and sent at the end of that instant, so `Transport::unsent`
//! counts only bytes written at the current instant and is back to 0 by the
//! next one. A per-side detection delay, a bandwidth model, and a
//! `WallClockStep` fault that jumps one peer's wall clock mid-run, are
//! follow-ups once the engine has something to lose by them.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use licketysync_engine::runtime::{Instant, PeerId, MAX_SEND_QUEUE};

/// A probability in millionths, so that no floating point is used while the
/// simulation runs and two platforms cannot round differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Probability {
    per_million: u32,
}

impl Probability {
    /// The denominator.
    pub const ONE_MILLION: u64 = 1_000_000;
    /// Never happens.
    pub const NEVER: Self = Self { per_million: 0 };
    /// Always happens.
    pub const ALWAYS: Self = Self {
        per_million: 1_000_000,
    };

    /// `per_million` in a million, clamped to one million.
    #[must_use]
    pub const fn per_million(self) -> u32 {
        self.per_million
    }

    /// From millionths, clamped to one million.
    #[must_use]
    pub const fn from_per_million(per_million: u32) -> Self {
        if per_million > 1_000_000 {
            Self::ALWAYS
        } else {
            Self { per_million }
        }
    }

    /// From a fraction in `0.0..=1.0`, rounded to the nearest millionth;
    /// values outside the range are clamped and NaN counts as zero.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "p is clamped to [0, 1] first, so the product lies in [0, 1_000_000]"
    )]
    pub fn from_f64(p: f64) -> Self {
        let p = if p.is_nan() { 0.0 } else { p.clamp(0.0, 1.0) };
        Self::from_per_million((p * 1_000_000.0).round() as u32)
    }
}

/// How the simulated network treats every message and connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    /// The least one-way latency.
    pub min_latency: Duration,
    /// The greatest one-way latency; each message draws its own between the
    /// two. Within a connection a message still waits behind the one before
    /// it, so a wide range reorders messages across connections only.
    pub max_latency: Duration,
    /// The chance that a piece takes its connection down instead of
    /// arriving: when its latency has elapsed, the piece is dropped, the
    /// connection ends (what the sender wrote after it is lost; what the
    /// other direction carried may still arrive, see `deliver_at_close`), and
    /// the two peers reconnect after a delay drawn between `min_reconnect` and
    /// `max_reconnect`.
    pub drop: Probability,
    /// The least time from a dropped connection to its reconnection.
    pub min_reconnect: Duration,
    /// The greatest time from a dropped connection to its reconnection.
    pub max_reconnect: Duration,
    /// When a connection ends, the chance that each piece still travelling
    /// towards a side that can receive reaches it, before it hears
    /// `on_disconnected`. The first piece that does not ends the stream, so a
    /// receiver always gets a prefix of what was sent; everything after it,
    /// and whatever the sender had written but not yet handed to the network,
    /// is lost.
    pub deliver_at_close: Probability,
    /// The most bytes a stream's unsent queue may hold: what its sender has
    /// written and the network has not yet cut into pieces, which is what
    /// `Transport::unsent` reports. Bytes already travelling do not count. A
    /// write that would take the unsent queue past it ends the connection.
    /// `MAX_SEND_QUEUE` by default, as the runtime contract allows.
    pub max_send_queue: usize,
}

impl Default for NetworkConfig {
    /// A quiet local network: 10 to 50 ms, no drops, reconnects (if a fault
    /// ever asks for one) in 100 ms to 1 s, half of what is in flight at a
    /// close delivered, and the contract's send-queue bound.
    fn default() -> Self {
        Self {
            min_latency: Duration::from_millis(10),
            max_latency: Duration::from_millis(50),
            drop: Probability::NEVER,
            min_reconnect: Duration::from_millis(100),
            max_reconnect: Duration::from_secs(1),
            deliver_at_close: Probability::from_per_million(500_000),
            max_send_queue: MAX_SEND_QUEUE,
        }
    }
}

impl NetworkConfig {
    /// Latency bounds, in either order.
    #[must_use]
    pub fn latency(mut self, lo: Duration, hi: Duration) -> Self {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        self.min_latency = lo;
        self.max_latency = hi;
        self
    }

    /// The chance each piece takes its connection down instead of arriving.
    #[must_use]
    pub fn drops(mut self, p: f64) -> Self {
        self.drop = Probability::from_f64(p);
        self
    }

    /// The chance each piece in flight at a connection's end still arrives.
    #[must_use]
    pub fn deliver_at_close(mut self, p: f64) -> Self {
        self.deliver_at_close = Probability::from_f64(p);
        self
    }

    /// The bound on a stream's unsent bytes (written, not yet cut into
    /// pieces).
    #[must_use]
    pub const fn max_send_queue(mut self, bytes: usize) -> Self {
        self.max_send_queue = bytes;
        self
    }

    /// Bounds on the time from a dropped connection to its reconnection, in
    /// either order.
    #[must_use]
    pub fn reconnect(mut self, lo: Duration, hi: Duration) -> Self {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        self.min_reconnect = lo;
        self.max_reconnect = hi;
        self
    }
}

/// A cut between two sets of peers: every link with one end in `a` and the
/// other in `b` is down while the partition is active. Peers in neither set are
/// unaffected; a peer in both is cut from both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    a: Vec<PeerId>,
    b: Vec<PeerId>,
}

impl Partition {
    /// Cuts every link between a member of `a` and a member of `b`.
    #[must_use]
    pub fn between(a: Vec<PeerId>, b: Vec<PeerId>) -> Self {
        Self { a, b }
    }

    /// Cuts `peer` off from every peer in `others`.
    #[must_use]
    pub fn isolate(peer: PeerId, others: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            a: vec![peer],
            b: others.into_iter().filter(|p| *p != peer).collect(),
        }
    }

    /// Whether this partition cuts the link between `x` and `y`.
    #[must_use]
    pub fn cuts(&self, x: PeerId, y: PeerId) -> bool {
        x != y
            && ((self.a.contains(&x) && self.b.contains(&y))
                || (self.a.contains(&y) && self.b.contains(&x)))
    }
}

/// A piece of a stream on its way: bytes cut from what the sender wrote,
/// numbered so the scheduler can tell its arrival from a dead one's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Piece {
    pub(crate) id: u64,
    pub(crate) bytes: Vec<u8>,
    /// This piece takes its connection down instead of arriving.
    pub(crate) lost: bool,
}

/// One direction of one connection: what the sender wrote and the receiver
/// has not yet been handed.
#[derive(Debug, Default)]
pub(crate) struct Stream {
    /// Written at the current instant, to be cut into pieces at its end.
    pub(crate) unsent: Vec<u8>,
    /// Whether the cut of `unsent` is scheduled.
    pub(crate) cut_pending: bool,
    /// Cut and travelling, oldest first.
    pub(crate) travelling: VecDeque<Piece>,
    /// Bytes in `unsent` and `travelling` together.
    pub(crate) queued: usize,
    /// When the last travelling piece arrives: a later piece never arrives
    /// before it.
    last_arrival: Option<Instant>,
}

impl Stream {
    /// The arrival time that keeps the stream in order: `proposed`, or the
    /// last piece's arrival if that is later.
    pub(crate) fn arrival(&mut self, proposed: Instant) -> Instant {
        let at = match self.last_arrival {
            Some(last) if last > proposed => last,
            _ => proposed,
        };
        self.last_arrival = Some(at);
        at
    }

    /// Whether nothing is written and not yet handed over.
    pub(crate) fn is_empty(&self) -> bool {
        self.queued == 0
    }
}

/// Connection state for the scheduler: which pairs have a connection open,
/// the active partitions, each pair's epoch, each open connection's two
/// streams, and the streams of stopped senders that are draining.
#[derive(Debug, Default)]
pub(crate) struct Links {
    open: BTreeSet<(PeerId, PeerId)>,
    partitions: BTreeMap<u64, Partition>,
    epochs: BTreeMap<(PeerId, PeerId), u64>,
    streams: BTreeMap<(PeerId, PeerId), Stream>,
    draining: BTreeSet<(PeerId, PeerId)>,
}

fn unordered(a: PeerId, b: PeerId) -> (PeerId, PeerId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

impl Links {
    /// Whether a connection between `a` and `b` is open: both have heard
    /// `on_connected` for the other and neither has heard `on_disconnected`
    /// since, or one of them has stopped cleanly and its stream to the other
    /// is still draining (for up to `STOP_FLUSH`), so that only the other side
    /// is still listening.
    pub(crate) fn is_open(&self, a: PeerId, b: PeerId) -> bool {
        self.open.contains(&unordered(a, b))
    }

    /// The peers `a` has an open connection to, in id order.
    pub(crate) fn open_with(&self, a: PeerId) -> Vec<PeerId> {
        self.open
            .iter()
            .filter_map(|(x, y)| {
                if *x == a {
                    Some(*y)
                } else if *y == a {
                    Some(*x)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Opens the connection between `a` and `b`. Returns `false`, changing
    /// nothing, when it is already open.
    pub(crate) fn open(&mut self, a: PeerId, b: PeerId) -> bool {
        a != b && self.open.insert(unordered(a, b))
    }

    /// Closes the connection between `a` and `b` and hands back its two
    /// streams, `a -> b` first. The epoch moves, so nothing of the old
    /// connection can reach a new one, and the next connection starts with
    /// empty streams. When no connection is open (a hang-up after
    /// `on_disconnected`, say) it returns `None` and changes nothing, the
    /// epoch included: nothing of an ended connection is still travelling,
    /// and a reconnection waiting on that epoch (the network's own, after a
    /// drop) must still happen.
    pub(crate) fn close(&mut self, a: PeerId, b: PeerId) -> Option<(Stream, Stream)> {
        if !self.open.remove(&unordered(a, b)) {
            return None;
        }
        let e = self.epochs.entry(unordered(a, b)).or_insert(0);
        *e = e.wrapping_add(1);
        self.draining.remove(&(a, b));
        self.draining.remove(&(b, a));
        let a_to_b = self.streams.remove(&(a, b)).unwrap_or_default();
        let b_to_a = self.streams.remove(&(b, a)).unwrap_or_default();
        Some((a_to_b, b_to_a))
    }

    /// The stream `from -> to` of the open connection, created empty on
    /// first use.
    pub(crate) fn stream_mut(&mut self, from: PeerId, to: PeerId) -> &mut Stream {
        self.streams.entry((from, to)).or_default()
    }

    /// The stream `from -> to`, if anything was ever written to it on the
    /// open connection.
    pub(crate) fn stream(&self, from: PeerId, to: PeerId) -> Option<&Stream> {
        self.streams.get(&(from, to))
    }

    /// Marks `from -> to` as the stream of a stopped sender that is draining.
    pub(crate) fn start_draining(&mut self, from: PeerId, to: PeerId) {
        self.draining.insert((from, to));
    }

    /// Whether `from` has stopped and its stream to `to` is draining.
    pub(crate) fn is_draining(&self, from: PeerId, to: PeerId) -> bool {
        self.draining.contains(&(from, to))
    }

    /// Whether any active partition cuts the link between `a` and `b`.
    pub(crate) fn cut(&self, a: PeerId, b: PeerId) -> bool {
        self.partitions.values().any(|p| p.cuts(a, b))
    }

    /// Activates `partition` under `handle`.
    pub(crate) fn add_partition(&mut self, handle: u64, partition: Partition) {
        self.partitions.insert(handle, partition);
    }

    /// Deactivates the partition under `handle`, returning it.
    pub(crate) fn remove_partition(&mut self, handle: u64) -> Option<Partition> {
        self.partitions.remove(&handle)
    }

    /// The current epoch of the connection between `a` and `b`: bumped each
    /// time an open connection between them closes, so a piece or a
    /// reconnection carries the epoch it belongs to and is dead when that is
    /// no longer the current one.
    pub(crate) fn epoch(&self, a: PeerId, b: PeerId) -> u64 {
        self.epochs.get(&unordered(a, b)).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: [PeerId; 4] = [
        PeerId::new(0),
        PeerId::new(1),
        PeerId::new(2),
        PeerId::new(3),
    ];

    #[test]
    fn probability_clamps_and_rounds() {
        assert_eq!(Probability::from_f64(0.0), Probability::NEVER);
        assert_eq!(Probability::from_f64(1.0), Probability::ALWAYS);
        assert_eq!(Probability::from_f64(7.0), Probability::ALWAYS);
        assert_eq!(Probability::from_f64(-1.0), Probability::NEVER);
        assert_eq!(Probability::from_f64(f64::NAN), Probability::NEVER);
        assert_eq!(Probability::from_f64(0.25).per_million(), 250_000);
        assert_eq!(Probability::from_f64(0.000_000_4).per_million(), 0);
        assert_eq!(
            Probability::from_per_million(5_000_000),
            Probability::ALWAYS
        );
        assert_eq!(Probability::from_per_million(12).per_million(), 12);
    }

    #[test]
    fn network_config_builders_normalise() {
        let c = NetworkConfig::default()
            .latency(Duration::from_millis(80), Duration::from_millis(20))
            .drops(0.5)
            .reconnect(Duration::from_secs(9), Duration::from_secs(2))
            .deliver_at_close(0.25)
            .max_send_queue(1000);
        assert_eq!(c.min_latency, Duration::from_millis(20));
        assert_eq!(c.max_latency, Duration::from_millis(80));
        assert_eq!(c.drop.per_million(), 500_000);
        assert_eq!(c.min_reconnect, Duration::from_secs(2));
        assert_eq!(c.max_reconnect, Duration::from_secs(9));
        assert_eq!(c.deliver_at_close.per_million(), 250_000);
        assert_eq!(c.max_send_queue, 1000);
        assert_eq!(
            NetworkConfig::default().drops(2.0).drop,
            Probability::ALWAYS
        );
        let d = NetworkConfig::default();
        assert_eq!(d.drop, Probability::NEVER);
        assert_eq!(d.deliver_at_close.per_million(), 500_000);
        assert_eq!(d.max_send_queue, MAX_SEND_QUEUE);
        assert!(d.min_latency <= d.max_latency);
        assert!(d.min_reconnect <= d.max_reconnect);
    }

    #[test]
    fn partition_cuts_only_across_the_split() {
        let p = Partition::between(vec![P[0], P[1]], vec![P[2]]);
        assert!(p.cuts(P[0], P[2]));
        assert!(p.cuts(P[2], P[1]));
        assert!(!p.cuts(P[0], P[1]));
        assert!(!p.cuts(P[2], P[3]));
        assert!(!p.cuts(P[0], P[3]));
        assert!(!p.cuts(P[0], P[0]));
        let i = Partition::isolate(P[3], P);
        assert!(i.cuts(P[3], P[0]));
        assert!(i.cuts(P[1], P[3]));
        assert!(!i.cuts(P[0], P[1]));
        assert!(!i.cuts(P[3], P[3]));
    }

    #[test]
    fn links_track_partitions_and_epochs() {
        let mut l = Links::default();
        assert!(!l.cut(P[0], P[2]));
        l.add_partition(1, Partition::between(vec![P[0]], vec![P[2]]));
        l.add_partition(2, Partition::between(vec![P[1]], vec![P[3]]));
        assert!(l.cut(P[0], P[2]));
        assert!(l.cut(P[3], P[1]));
        assert!(!l.cut(P[0], P[1]));
        assert!(l.remove_partition(1).is_some());
        assert!(l.remove_partition(1).is_none());
        assert!(!l.cut(P[0], P[2]));
        assert!(l.cut(P[1], P[3]));

        assert_eq!(l.epoch(P[0], P[1]), 0);
        assert!(l.close(P[1], P[0]).is_none(), "nothing was open");
        assert_eq!(
            l.epoch(P[0], P[1]),
            0,
            "a close of a pair with no connection open moves no epoch"
        );
        assert!(l.open(P[0], P[1]));
        assert!(l.close(P[1], P[0]).is_some());
        assert_eq!(l.epoch(P[0], P[1]), 1, "a close of an open one does");
        assert_eq!(l.epoch(P[1], P[0]), 1, "in either order");
        assert_eq!(l.epoch(P[0], P[2]), 0, "and only its own pair's");
    }

    #[test]
    fn a_stream_keeps_arrivals_in_order_and_a_close_hands_both_back() {
        let mut l = Links::default();
        assert!(l.open(P[0], P[1]));
        let t1 = Instant::from_millis(10);
        let t2 = Instant::from_millis(30);
        let t3 = Instant::from_millis(20);
        let s = l.stream_mut(P[0], P[1]);
        assert!(s.is_empty());
        assert_eq!(s.arrival(t1), t1);
        assert_eq!(s.arrival(t2), t2);
        assert_eq!(
            s.arrival(t3),
            t2,
            "an earlier proposal waits behind the last"
        );
        s.unsent.extend_from_slice(b"abc");
        s.queued = 3;
        assert!(!s.is_empty());
        assert_eq!(
            l.stream_mut(P[1], P[0]).arrival(t3),
            t3,
            "the reverse direction is its own stream"
        );
        assert!(l.stream(P[0], P[1]).is_some());
        assert!(l.stream(P[2], P[0]).is_none());
        l.start_draining(P[0], P[1]);
        assert!(l.is_draining(P[0], P[1]));
        assert!(!l.is_draining(P[1], P[0]));
        let closed = l.close(P[0], P[1]);
        assert!(closed.is_some(), "the connection was open");
        let (a_to_b, b_to_a) = closed.unwrap_or_default();
        assert_eq!(a_to_b.unsent, b"abc".to_vec(), "a -> b comes first");
        assert!(b_to_a.is_empty());
        assert!(!l.is_draining(P[0], P[1]), "a close ends the draining");
        assert!(
            l.stream(P[0], P[1]).is_none(),
            "the next connection starts empty"
        );
        assert!(l.open(P[0], P[1]));
        assert_eq!(
            l.stream_mut(P[0], P[1]).arrival(t1),
            t1,
            "a new stream, a new order"
        );
    }

    #[test]
    fn links_track_which_connections_are_open() {
        let mut l = Links::default();
        assert!(!l.is_open(P[0], P[1]));
        assert!(l.open(P[1], P[0]), "opening a closed pair opens it");
        assert!(!l.open(P[0], P[1]), "opening it again changes nothing");
        assert!(!l.open(P[2], P[2]), "a peer has no connection to itself");
        assert!(l.is_open(P[0], P[1]));
        assert!(l.is_open(P[1], P[0]));
        assert!(l.open(P[0], P[3]));
        assert_eq!(l.open_with(P[0]), vec![P[1], P[3]]);
        assert_eq!(l.open_with(P[1]), vec![P[0]]);
        assert_eq!(l.open_with(P[2]), Vec::new());
        assert!(
            l.close(P[0], P[1]).is_some(),
            "closing an open pair hands back its streams"
        );
        assert!(!l.is_open(P[0], P[1]));
        assert_eq!(
            l.epoch(P[0], P[1]),
            1,
            "and moves its epoch, so nothing in flight can slip through"
        );
        assert!(
            l.close(P[0], P[1]).is_none(),
            "closing a closed pair reports nothing was open"
        );
        assert_eq!(
            l.epoch(P[0], P[1]),
            1,
            "and changes nothing: a reconnection waiting on that epoch still happens"
        );
        assert_eq!(l.open_with(P[0]), vec![P[3]]);
    }
}
