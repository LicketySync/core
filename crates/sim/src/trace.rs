// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The record of a run: every event with its time, peer and kind, a running
//! hash of all of them, and the last few kept in full for the failure report.
//!
//! The hash is FNV-1a over a canonical byte encoding of each event, message
//! payloads included. It is a checksum for comparing two runs, not a
//! cryptographic hash, and it is written here because it is eight lines and
//! must never change between releases, or every recorded fingerprint changes.
//! The encoding is the tag numbers in [`TraceEvent::feed`] and the explicit
//! discriminants of [`DropReason`] and [`StorageOp`]; they are part of every
//! fingerprint and must not be renumbered once one has been published.

use core::fmt;
use std::collections::VecDeque;

use licketysync_engine::runtime::{Instant, PeerId, TimerId};

/// Why bytes were not handed to their receiver. `len` in the event says how
/// many: one piece for `Lost`, `NotRunning` and `Stale`, one write for
/// `Closed` and `Overflow`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The network lost this piece and took its connection down with it (the
    /// configured drop probability).
    Lost = 0,
    /// The receiver was not running: it had crashed or stopped.
    NotRunning = 1,
    /// The connection ended while this piece was in flight, and it was not
    /// among the prefix that still arrived (`deliver_at_close`).
    Stale = 2,
    /// The connection had closed before the write was taken. The sender was
    /// right to write: it had heard `on_connected` and not yet
    /// `on_disconnected`, either because the other side hung up inside its own
    /// `on_connected` in the same batch, or because the notice of the close
    /// had not reached the sender yet.
    Closed = 3,
    /// The write would have taken the stream past its bound on bytes not yet
    /// handed over (`max_send_queue`), so the connection was ended instead.
    Overflow = 4,
}

/// Which storage call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOp {
    /// `Storage::put`.
    Put = 0,
    /// `Storage::delete`.
    Delete = 1,
    /// `Storage::commit`.
    Commit = 2,
}

/// What happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// The peer started (first start or restart).
    Start,
    /// The peer stopped cleanly; `on_stop` ran.
    Stop,
    /// The peer crashed; `on_stop` did not run and staged writes were lost.
    Crash,
    /// A connection to `PeerId` opened.
    Connected(PeerId),
    /// The connection to `PeerId` closed.
    Disconnected(PeerId),
    /// The peer sent these bytes to `to`.
    Send {
        /// The destination.
        to: PeerId,
        /// The payload.
        bytes: Vec<u8>,
    },
    /// A send was refused because `to` was not connected.
    SendRefused {
        /// The destination.
        to: PeerId,
    },
    /// The peer hung up on `PeerId`; the `Disconnected` events follow when a
    /// connection was open.
    Close(PeerId),
    /// These bytes from `from` reached the peer's `on_message`: one chunk of
    /// the stream, cut wherever the network chose.
    Deliver {
        /// The sender.
        from: PeerId,
        /// The payload.
        bytes: Vec<u8>,
    },
    /// A message to `to` was not delivered.
    Dropped {
        /// The destination.
        to: PeerId,
        /// The payload length.
        len: usize,
        /// Why.
        reason: DropReason,
    },
    /// The peer armed a timer for `at` on its own clock.
    TimerSet {
        /// The timer.
        id: TimerId,
        /// The deadline as the peer sees it.
        at: Instant,
    },
    /// The peer disarmed a timer.
    TimerCancelled(TimerId),
    /// A timer fired into `on_timer`.
    TimerFired(TimerId),
    /// A value was staged at `key`.
    Put {
        /// The key.
        key: Vec<u8>,
        /// The value's length.
        len: usize,
    },
    /// A delete was staged for `key`.
    Delete {
        /// The key.
        key: Vec<u8>,
    },
    /// Staged writes became durable.
    Commit,
    /// Staged writes were discarded by the peer.
    Rollback,
    /// A storage call failed.
    StorageFailed {
        /// The call.
        op: StorageOp,
        /// The error's text.
        error: String,
    },
    /// A partition began; the peer field is empty.
    PartitionStart,
    /// A partition ended; the peer field is empty.
    PartitionEnd,
    /// The peer's disk is full from now on.
    DiskFull,
    /// The peer's disk has room again.
    DiskFreed,
}

/// One event of the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEvent {
    /// Simulation time (not any peer's skewed view).
    pub time: Instant,
    /// The peer it happened to, or `None` for network-wide events.
    pub peer: Option<PeerId>,
    /// What happened.
    pub kind: EventKind,
}

impl fmt::Display for TraceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} ", self.time)?;
        match self.peer {
            Some(p) => write!(f, "{p:<4} ")?,
            None => f.write_str("net  ")?,
        }
        match &self.kind {
            EventKind::Start => f.write_str("start"),
            EventKind::Stop => f.write_str("stop"),
            EventKind::Crash => f.write_str("crash"),
            EventKind::Connected(p) => write!(f, "connected {p}"),
            EventKind::Disconnected(p) => write!(f, "disconnected {p}"),
            EventKind::Send { to, bytes } => write!(f, "send to {to} ({} bytes)", bytes.len()),
            EventKind::SendRefused { to } => write!(f, "send to {to} refused: not connected"),
            EventKind::Close(p) => write!(f, "close {p}"),
            EventKind::Deliver { from, bytes } => {
                write!(f, "deliver from {from} ({} bytes)", bytes.len())
            }
            EventKind::Dropped { to, len, reason } => {
                write!(f, "dropped to {to} ({len} bytes): {reason:?}")
            }
            EventKind::TimerSet { id, at } => write!(f, "timer {id} set for {at}"),
            EventKind::TimerCancelled(id) => write!(f, "timer {id} cancelled"),
            EventKind::TimerFired(id) => write!(f, "timer {id} fired"),
            EventKind::Put { key, len } => {
                write!(f, "put {} ({len} bytes)", String::from_utf8_lossy(key))
            }
            EventKind::Delete { key } => write!(f, "delete {}", String::from_utf8_lossy(key)),
            EventKind::Commit => f.write_str("commit"),
            EventKind::Rollback => f.write_str("rollback"),
            EventKind::StorageFailed { op, error } => write!(f, "{op:?} failed: {error}"),
            EventKind::PartitionStart => f.write_str("partition starts"),
            EventKind::PartitionEnd => f.write_str("partition ends"),
            EventKind::DiskFull => f.write_str("disk full"),
            EventKind::DiskFreed => f.write_str("disk freed"),
        }
    }
}

/// FNV-1a, 64 bits. A checksum, not a cryptographic hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceHasher {
    state: u64,
}

impl Default for TraceHasher {
    fn default() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

impl TraceHasher {
    /// Feeds bytes.
    pub fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.state ^= u64::from(*b);
            self.state = self.state.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    /// Feeds a number, little-endian.
    pub fn write_u64(&mut self, n: u64) {
        self.write(&n.to_le_bytes());
    }

    /// Feeds a length (as `u64`) and then the bytes, so that adjacent fields
    /// cannot shift into each other.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);
        self.write(bytes);
    }

    /// The hash so far.
    #[must_use]
    pub const fn finish(self) -> u64 {
        self.state
    }
}

impl TraceEvent {
    /// Feeds a canonical encoding of this event: time, peer, a tag per kind,
    /// then the kind's fields.
    pub fn feed(&self, h: &mut TraceHasher) {
        h.write_u64(self.time.as_nanos());
        match self.peer {
            Some(p) => {
                h.write(&[1]);
                h.write_u64(p.as_u64());
            }
            None => h.write(&[0]),
        }
        match &self.kind {
            EventKind::Start => h.write(&[1]),
            EventKind::Stop => h.write(&[2]),
            EventKind::Crash => h.write(&[3]),
            EventKind::Connected(p) => {
                h.write(&[4]);
                h.write_u64(p.as_u64());
            }
            EventKind::Disconnected(p) => {
                h.write(&[5]);
                h.write_u64(p.as_u64());
            }
            EventKind::Send { to, bytes } => {
                h.write(&[6]);
                h.write_u64(to.as_u64());
                h.write_bytes(bytes);
            }
            EventKind::SendRefused { to } => {
                h.write(&[7]);
                h.write_u64(to.as_u64());
            }
            EventKind::Deliver { from, bytes } => {
                h.write(&[8]);
                h.write_u64(from.as_u64());
                h.write_bytes(bytes);
            }
            EventKind::Dropped { to, len, reason } => {
                h.write(&[9, *reason as u8]);
                h.write_u64(to.as_u64());
                h.write_u64(*len as u64);
            }
            EventKind::TimerSet { id, at } => {
                h.write(&[10]);
                h.write_u64(id.as_u64());
                h.write_u64(at.as_nanos());
            }
            EventKind::TimerCancelled(id) => {
                h.write(&[11]);
                h.write_u64(id.as_u64());
            }
            EventKind::TimerFired(id) => {
                h.write(&[12]);
                h.write_u64(id.as_u64());
            }
            EventKind::Put { key, len } => {
                h.write(&[13]);
                h.write_bytes(key);
                h.write_u64(*len as u64);
            }
            EventKind::Delete { key } => {
                h.write(&[14]);
                h.write_bytes(key);
            }
            EventKind::Commit => h.write(&[15]),
            EventKind::Rollback => h.write(&[16]),
            EventKind::StorageFailed { op, error } => {
                h.write(&[17, *op as u8]);
                h.write_bytes(error.as_bytes());
            }
            EventKind::PartitionStart => h.write(&[18]),
            EventKind::PartitionEnd => h.write(&[19]),
            EventKind::DiskFull => h.write(&[20]),
            EventKind::DiskFreed => h.write(&[21]),
            EventKind::Close(p) => {
                h.write(&[22]);
                h.write_u64(p.as_u64());
            }
        }
    }
}

/// The run's record: a hash of every event, the last `keep_last` events in
/// full, and optionally all of them.
#[derive(Clone, Debug)]
pub struct Trace {
    hasher: TraceHasher,
    count: u64,
    keep_last: usize,
    last: VecDeque<TraceEvent>,
    all: Option<Vec<TraceEvent>>,
}

impl Trace {
    /// A trace keeping the last `keep_last` events, and every event when
    /// `record_all` is set.
    #[must_use]
    pub fn new(keep_last: usize, record_all: bool) -> Self {
        Self {
            hasher: TraceHasher::default(),
            count: 0,
            keep_last,
            last: VecDeque::with_capacity(keep_last),
            all: record_all.then(Vec::new),
        }
    }

    /// Records an event.
    pub fn push(&mut self, event: TraceEvent) {
        event.feed(&mut self.hasher);
        self.count = self.count.saturating_add(1);
        if self.keep_last > 0 {
            if self.last.len() == self.keep_last {
                self.last.pop_front();
            }
            self.last.push_back(event.clone());
        }
        if let Some(all) = &mut self.all {
            all.push(event);
        }
    }

    /// The hash of every event so far.
    #[must_use]
    pub const fn hash(&self) -> u64 {
        self.hasher.finish()
    }

    /// How many events were recorded.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.count
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The most recent events, oldest first.
    #[must_use]
    pub fn last_events(&self) -> Vec<TraceEvent> {
        self.last.iter().cloned().collect()
    }

    /// Every event, when recording all was asked for.
    #[must_use]
    pub fn all(&self) -> Option<&[TraceEvent]> {
        self.all.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(nanos: u64, peer: Option<u64>, kind: EventKind) -> TraceEvent {
        TraceEvent {
            time: Instant::from_nanos(nanos),
            peer: peer.map(PeerId::new),
            kind,
        }
    }

    #[test]
    fn fnv1a_matches_the_published_vectors() {
        let mut h = TraceHasher::default();
        assert_eq!(h.finish(), 0xcbf2_9ce4_8422_2325);
        h.write(b"a");
        assert_eq!(h.finish(), 0xaf63_dc4c_8601_ec8c);
        let mut h = TraceHasher::default();
        h.write(b"foobar");
        assert_eq!(h.finish(), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn reason_and_op_discriminants_are_the_documented_encoding() {
        assert_eq!(
            [
                DropReason::Lost as u8,
                DropReason::NotRunning as u8,
                DropReason::Stale as u8,
                DropReason::Closed as u8,
                DropReason::Overflow as u8
            ],
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            [
                StorageOp::Put as u8,
                StorageOp::Delete as u8,
                StorageOp::Commit as u8
            ],
            [0, 1, 2]
        );
    }

    #[test]
    fn length_prefix_separates_fields() {
        let mut a = TraceHasher::default();
        a.write_bytes(b"ab");
        a.write_bytes(b"c");
        let mut b = TraceHasher::default();
        b.write_bytes(b"a");
        b.write_bytes(b"bc");
        assert_ne!(a.finish(), b.finish());
    }

    fn every_kind() -> Vec<EventKind> {
        let p = PeerId::new(2);
        let t = TimerId::new(1);
        vec![
            EventKind::Start,
            EventKind::Stop,
            EventKind::Crash,
            EventKind::Connected(p),
            EventKind::Disconnected(p),
            EventKind::Send {
                to: p,
                bytes: vec![1, 2],
            },
            EventKind::SendRefused { to: p },
            EventKind::Close(p),
            EventKind::Deliver {
                from: p,
                bytes: vec![3],
            },
            EventKind::Dropped {
                to: p,
                len: 4,
                reason: DropReason::Lost,
            },
            EventKind::Dropped {
                to: p,
                len: 4,
                reason: DropReason::NotRunning,
            },
            EventKind::Dropped {
                to: p,
                len: 4,
                reason: DropReason::Stale,
            },
            EventKind::Dropped {
                to: p,
                len: 4,
                reason: DropReason::Closed,
            },
            EventKind::Dropped {
                to: p,
                len: 4,
                reason: DropReason::Overflow,
            },
            EventKind::TimerSet {
                id: t,
                at: Instant::from_secs(1),
            },
            EventKind::TimerCancelled(t),
            EventKind::TimerFired(t),
            EventKind::Put {
                key: b"k".to_vec(),
                len: 9,
            },
            EventKind::Delete { key: b"k".to_vec() },
            EventKind::Commit,
            EventKind::Rollback,
            EventKind::StorageFailed {
                op: StorageOp::Put,
                error: "storage is full".into(),
            },
            EventKind::StorageFailed {
                op: StorageOp::Delete,
                error: "x".into(),
            },
            EventKind::StorageFailed {
                op: StorageOp::Commit,
                error: "y".into(),
            },
            EventKind::PartitionStart,
            EventKind::PartitionEnd,
            EventKind::DiskFull,
            EventKind::DiskFreed,
        ]
    }

    #[test]
    fn every_kind_hashes_differently_and_displays() {
        let kinds = every_kind();
        let mut hashes = Vec::new();
        for kind in kinds {
            let e = ev(5, Some(1), kind);
            let mut h = TraceHasher::default();
            e.feed(&mut h);
            hashes.push(h.finish());
            let text = e.to_string();
            assert!(text.starts_with("t=0.000000005s p1   "), "{text}");
        }
        let distinct: std::collections::BTreeSet<u64> = hashes.iter().copied().collect();
        assert_eq!(distinct.len(), hashes.len(), "two kinds hashed alike");
        let net = ev(0, None, EventKind::PartitionStart);
        assert_eq!(net.to_string(), "t=0.000000000s net  partition starts");
        let mut h1 = TraceHasher::default();
        net.feed(&mut h1);
        let mut h2 = TraceHasher::default();
        ev(0, Some(0), EventKind::PartitionStart).feed(&mut h2);
        assert_ne!(h1.finish(), h2.finish(), "no peer and peer 0 differ");
    }

    #[test]
    fn display_shows_lengths_and_keys() {
        let e = ev(
            1_000_000_000,
            Some(3),
            EventKind::Send {
                to: PeerId::new(4),
                bytes: vec![0; 16],
            },
        );
        assert_eq!(e.to_string(), "t=1.000000000s p3   send to p4 (16 bytes)");
        let e = ev(
            0,
            Some(3),
            EventKind::Put {
                key: b"item/1".to_vec(),
                len: 0,
            },
        );
        assert_eq!(e.to_string(), "t=0.000000000s p3   put item/1 (0 bytes)");
        let e = ev(
            0,
            Some(3),
            EventKind::Dropped {
                to: PeerId::new(1),
                len: 2,
                reason: DropReason::Stale,
            },
        );
        assert_eq!(
            e.to_string(),
            "t=0.000000000s p3   dropped to p1 (2 bytes): Stale"
        );
    }

    #[test]
    fn trace_keeps_the_hash_the_tail_and_optionally_everything() {
        let mut t = Trace::new(2, false);
        assert!(t.is_empty());
        let h0 = t.hash();
        t.push(ev(1, Some(0), EventKind::Start));
        t.push(ev(2, Some(1), EventKind::Start));
        t.push(ev(3, Some(2), EventKind::Start));
        assert_eq!(t.len(), 3);
        assert!(!t.is_empty());
        assert_ne!(t.hash(), h0);
        let last = t.last_events();
        assert_eq!(last.len(), 2);
        assert_eq!(last.first().map(|e| e.time), Some(Instant::from_nanos(2)));
        assert!(t.all().is_none());

        let mut full = Trace::new(0, true);
        full.push(ev(1, Some(0), EventKind::Start));
        full.push(ev(2, Some(1), EventKind::Start));
        assert_eq!(full.last_events(), Vec::new());
        assert_eq!(full.all().map(<[TraceEvent]>::len), Some(2));

        let mut same = Trace::new(2, false);
        same.push(ev(1, Some(0), EventKind::Start));
        same.push(ev(2, Some(1), EventKind::Start));
        same.push(ev(3, Some(2), EventKind::Start));
        assert_eq!(same.hash(), t.hash());
        let mut other = Trace::new(2, false);
        other.push(ev(1, Some(0), EventKind::Start));
        other.push(ev(2, Some(1), EventKind::Start));
        other.push(ev(4, Some(2), EventKind::Start));
        assert_ne!(other.hash(), t.hash());
    }
}
