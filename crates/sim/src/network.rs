// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The simulated network: its configuration, partitions, and the connection
//! state the scheduler consults.
//!
//! The network honours the transport contract of the protocol spec (3.1): one
//! reliable, ordered stream per connection. A connection joins two running
//! peers; while it is open, every message sent on it arrives whole, once and in
//! order (each direction is first-in first-out, with its own latency per
//! message), or the connection ends. Loss is modelled as exactly that: with the
//! configured probability a message takes its connection down instead of
//! arriving, both sides hear `on_disconnected`, and the two reconnect after a
//! delay. A connection also closes when a partition cuts it, a peer stops, or
//! a peer hangs up (`Transport::close`); only the first of those reconnects by
//! itself. Every closing bumps the connection's epoch, so messages that were
//! in flight on the old connection are dropped on arrival, as segments of a
//! closed TCP or QUIC connection would be. Nothing orders different
//! connections: with a wide latency range a message on one connection
//! overtakes one on another.
//!
//! Phase-0 simplification: both sides learn that a connection ended at the
//! same instant. In reality one side may believe the connection alive until
//! its own timeout expires, sending into the void meanwhile. A per-side
//! detection delay, and a `WallClockStep` fault that jumps one peer's wall
//! clock mid-run, are follow-ups once the engine has something to lose by
//! them.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use licketysync_engine::runtime::{Instant, PeerId};

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
    /// The chance that a message takes its connection down instead of
    /// arriving: when its latency has elapsed, the message is dropped, both
    /// sides hear `on_disconnected`, everything else in flight on the
    /// connection is lost, and the two peers reconnect after a delay drawn
    /// between `min_reconnect` and `max_reconnect`.
    pub drop: Probability,
    /// The least time from a dropped connection to its reconnection.
    pub min_reconnect: Duration,
    /// The greatest time from a dropped connection to its reconnection.
    pub max_reconnect: Duration,
}

impl Default for NetworkConfig {
    /// A quiet local network: 10 to 50 ms, no drops, reconnects (if a fault
    /// ever asks for one) in 100 ms to 1 s.
    fn default() -> Self {
        Self {
            min_latency: Duration::from_millis(10),
            max_latency: Duration::from_millis(50),
            drop: Probability::NEVER,
            min_reconnect: Duration::from_millis(100),
            max_reconnect: Duration::from_secs(1),
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

    /// The chance each message takes its connection down instead of arriving.
    #[must_use]
    pub fn drops(mut self, p: f64) -> Self {
        self.drop = Probability::from_f64(p);
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

/// Connection state for the scheduler: which pairs have a connection open,
/// the active partitions, each pair's epoch and each direction's FIFO deadline.
#[derive(Debug, Default)]
pub(crate) struct Links {
    open: BTreeSet<(PeerId, PeerId)>,
    partitions: BTreeMap<u64, Partition>,
    epochs: BTreeMap<(PeerId, PeerId), u64>,
    last_delivery: BTreeMap<(PeerId, PeerId), Instant>,
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
    /// since.
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

    /// Closes the connection between `a` and `b`: messages in flight on it are
    /// stale from now on and the next connection starts new FIFO queues.
    /// Returns whether a connection was open.
    pub(crate) fn close(&mut self, a: PeerId, b: PeerId) -> bool {
        let was_open = self.open.remove(&unordered(a, b));
        let e = self.epochs.entry(unordered(a, b)).or_insert(0);
        *e = e.wrapping_add(1);
        self.last_delivery.remove(&(a, b));
        self.last_delivery.remove(&(b, a));
        was_open
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

    /// The current epoch of the connection between `a` and `b`: bumped by
    /// every close, so a message carries the epoch it was sent in and is stale
    /// when that is no longer the current one.
    pub(crate) fn epoch(&self, a: PeerId, b: PeerId) -> u64 {
        self.epochs.get(&unordered(a, b)).copied().unwrap_or(0)
    }

    /// The delivery time that keeps the directed stream `from -> to` in order:
    /// `proposed`, or the last delivery scheduled on it if that is later.
    pub(crate) fn fifo(&mut self, from: PeerId, to: PeerId, proposed: Instant) -> Instant {
        let slot = self.last_delivery.entry((from, to)).or_insert(proposed);
        if proposed > *slot {
            *slot = proposed;
        }
        *slot
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
            .reconnect(Duration::from_secs(9), Duration::from_secs(2));
        assert_eq!(c.min_latency, Duration::from_millis(20));
        assert_eq!(c.max_latency, Duration::from_millis(80));
        assert_eq!(c.drop.per_million(), 500_000);
        assert_eq!(c.min_reconnect, Duration::from_secs(2));
        assert_eq!(c.max_reconnect, Duration::from_secs(9));
        assert_eq!(
            NetworkConfig::default().drops(2.0).drop,
            Probability::ALWAYS
        );
        let d = NetworkConfig::default();
        assert_eq!(d.drop, Probability::NEVER);
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
    fn links_track_partitions_epochs_and_fifo() {
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
        l.close(P[1], P[0]);
        assert_eq!(l.epoch(P[0], P[1]), 1);
        assert_eq!(l.epoch(P[1], P[0]), 1);
        assert_eq!(l.epoch(P[0], P[2]), 0);

        let t1 = Instant::from_millis(10);
        let t2 = Instant::from_millis(30);
        let t3 = Instant::from_millis(20);
        assert_eq!(l.fifo(P[0], P[1], t1), t1);
        assert_eq!(l.fifo(P[0], P[1], t2), t2);
        assert_eq!(
            l.fifo(P[0], P[1], t3),
            t2,
            "an earlier proposal waits behind the last"
        );
        assert_eq!(
            l.fifo(P[1], P[0], t3),
            t3,
            "the reverse direction is its own queue"
        );
        l.close(P[0], P[1]);
        assert_eq!(
            l.fifo(P[0], P[1], t1),
            t1,
            "a new connection starts a new queue"
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
            l.close(P[0], P[1]),
            "closing an open pair reports it was open"
        );
        assert!(!l.is_open(P[0], P[1]));
        assert!(
            !l.close(P[0], P[1]),
            "closing a closed pair reports nothing was open"
        );
        assert_eq!(
            l.epoch(P[0], P[1]),
            2,
            "but still bumps the epoch, so nothing in flight can slip through"
        );
        assert_eq!(l.open_with(P[0]), vec![P[3]]);
    }
}
