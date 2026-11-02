// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The engine's timers: one id per purpose (a connection's wake-up, its send
//! poll, the resume probe, the chunk patience, the deferred commit, the
//! clock rule's opening, the free tick), allocated from a counter that never
//! repeats within an instance, and every id below [`HARNESS_TIMERS`].
//!
//! Ids of 2^63 and up belong to whatever wraps the engine (the simulator's
//! workload, later the daemon's own timers): the engine never arms one and
//! ignores one that fires ([`TimerTable::fired`]). An id is forgotten when its
//! connection ends, so a timer of an old connection can never be taken for
//! one of a new connection to the same peer (TM-22: per-connection state is
//! freed on disconnect).

use std::collections::{BTreeMap, BTreeSet};

use crate::runtime::{Instant, PeerId, TimerId, Timers};

/// The first timer id that is not the engine's: ids from here up belong to
/// the harness that wraps it.
pub const HARNESS_TIMERS: u64 = 1 << 63;

/// What an engine timer is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Purpose {
    /// The connection's one deadline (`Output::wake_at`).
    Wake(PeerId),
    /// The engine is over its send budget on the connection: read
    /// `Transport::unsent` again (`runtime.rs`, `MAX_SEND_QUEUE`).
    SendPoll(PeerId),
    /// A folder is paused for a store failure: try the store again.
    ResumeProbe,
    /// A chunk request outstanding runs out of patience: drive the passes,
    /// which may now ask another connection (`crate::inflight`).
    ChunkPatience,
    /// Index work that phase C brought waits for a commit: make it now, in
    /// a handler of its own (`crate::sync`).
    Deferred,
    /// A folder kept closed by the clock rule may open: check the clock.
    OpensAt,
    /// Once a minute: the chunk frees of folders open on no connection
    /// (`protocol.md` 4.7 item 1).
    FreeTick,
}

impl Purpose {
    const fn peer(self) -> Option<PeerId> {
        match self {
            Self::Wake(p) | Self::SendPoll(p) => Some(p),
            Self::ResumeProbe
            | Self::ChunkPatience
            | Self::Deferred
            | Self::OpensAt
            | Self::FreeTick => None,
        }
    }
}

/// The table of purpose to id, both ways, and which are armed.
#[derive(Debug)]
pub(crate) struct TimerTable {
    next: u64,
    by_id: BTreeMap<TimerId, Purpose>,
    by_purpose: BTreeMap<Purpose, TimerId>,
    armed: BTreeSet<Purpose>,
}

impl TimerTable {
    pub(crate) const fn new() -> Self {
        Self {
            next: 1,
            by_id: BTreeMap::new(),
            by_purpose: BTreeMap::new(),
            armed: BTreeSet::new(),
        }
    }

    /// The id of `purpose`, allocating the next one the first time.
    fn id_for(&mut self, purpose: Purpose) -> Option<TimerId> {
        if let Some(id) = self.by_purpose.get(&purpose) {
            return Some(*id);
        }
        if self.next >= HARNESS_TIMERS {
            return None;
        }
        let id = TimerId::new(self.next);
        self.next += 1;
        self.by_id.insert(id, purpose);
        self.by_purpose.insert(purpose, id);
        Some(id)
    }

    /// Arms `purpose` at `at`, replacing its deadline; `false` only when no
    /// id is left below [`HARNESS_TIMERS`], which never happens in practice.
    pub(crate) fn arm<T: Timers + ?Sized>(
        &mut self,
        cx: &mut T,
        purpose: Purpose,
        at: Instant,
    ) -> bool {
        let Some(id) = self.id_for(purpose) else {
            return false;
        };
        cx.set_timer(id, at);
        self.armed.insert(purpose);
        true
    }

    /// Arms `purpose` at `at` unless it is armed already, so that a poll is
    /// never pushed later by each new deferral.
    pub(crate) fn arm_once<T: Timers + ?Sized>(
        &mut self,
        cx: &mut T,
        purpose: Purpose,
        at: Instant,
    ) -> bool {
        self.armed.contains(&purpose) || self.arm(cx, purpose, at)
    }

    /// Whether `purpose` is armed.
    #[cfg(test)]
    pub(crate) fn is_armed(&self, purpose: Purpose) -> bool {
        self.armed.contains(&purpose)
    }

    /// Disarms `purpose`; its id stays its own.
    pub(crate) fn cancel<T: Timers + ?Sized>(&mut self, cx: &mut T, purpose: Purpose) {
        if self.armed.remove(&purpose) {
            if let Some(id) = self.by_purpose.get(&purpose) {
                cx.cancel_timer(*id);
            }
        }
    }

    /// The purpose of a timer that fired, now no longer armed; `None` for a
    /// harness id, or an id this instance does not know (forgotten with its
    /// connection).
    pub(crate) fn fired(&mut self, id: TimerId) -> Option<Purpose> {
        if id.as_u64() >= HARNESS_TIMERS {
            return None;
        }
        let purpose = *self.by_id.get(&id)?;
        self.armed.remove(&purpose);
        Some(purpose)
    }

    /// Cancels and forgets every timer of `peer`'s connection.
    pub(crate) fn forget_peer<T: Timers + ?Sized>(&mut self, cx: &mut T, peer: PeerId) {
        let gone: Vec<Purpose> = self
            .by_purpose
            .keys()
            .filter(|p| p.peer() == Some(peer))
            .copied()
            .collect();
        for purpose in gone {
            self.cancel(cx, purpose);
            if let Some(id) = self.by_purpose.remove(&purpose) {
                self.by_id.remove(&id);
            }
        }
    }

    /// Timer ids known, for the tests of the bound.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names,
    clippy::field_reassign_with_default,
    clippy::map_unwrap_or,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        set: Vec<(TimerId, Instant)>,
        cancelled: Vec<TimerId>,
    }

    impl Timers for Recorder {
        fn set_timer(&mut self, id: TimerId, at: Instant) {
            self.set.push((id, at));
        }
        fn cancel_timer(&mut self, id: TimerId) {
            self.cancelled.push(id);
        }
    }

    #[test]
    fn ids_are_per_purpose_below_the_harness_range_and_never_repeat() {
        let mut t = TimerTable::new();
        let mut cx = Recorder::default();
        let (p1, p2) = (PeerId::new(1), PeerId::new(2));
        t.arm(&mut cx, Purpose::Wake(p1), Instant::from_secs(1));
        t.arm(&mut cx, Purpose::Wake(p1), Instant::from_secs(2));
        t.arm(&mut cx, Purpose::SendPoll(p1), Instant::from_secs(1));
        t.arm(&mut cx, Purpose::ResumeProbe, Instant::from_secs(1));
        let wake = cx.set.first().map(|(id, _)| *id);
        assert_eq!(cx.set.get(1).map(|(id, _)| *id), wake, "one id per purpose");
        assert!(cx.set.iter().all(|(id, _)| id.as_u64() < HARNESS_TIMERS));
        assert_eq!(t.len(), 3);
        // A new connection to the same peer gets new ids.
        t.forget_peer(&mut cx, p1);
        assert_eq!(t.len(), 1, "only the probe is left");
        assert_eq!(cx.cancelled.len(), 2, "both armed timers of p1 cancelled");
        t.arm(&mut cx, Purpose::Wake(p1), Instant::from_secs(3));
        let again = cx.set.last().map(|(id, _)| *id);
        assert_ne!(again, wake, "an id never repeats within an instance");
        assert_eq!(
            wake.and_then(|w| t.fired(w)),
            None,
            "the old id is forgotten"
        );
        t.arm(&mut cx, Purpose::Wake(p2), Instant::from_secs(3));
        assert_eq!(cx.set.len(), 6);
    }

    #[test]
    fn harness_ids_are_ignored_and_a_fired_timer_is_disarmed() {
        let mut t = TimerTable::new();
        let mut cx = Recorder::default();
        assert_eq!(t.fired(TimerId::new(HARNESS_TIMERS)), None);
        assert_eq!(t.fired(TimerId::new(u64::MAX)), None);
        assert_eq!(t.fired(TimerId::new(7)), None, "unknown");
        let poll = Purpose::SendPoll(PeerId::new(4));
        t.arm_once(&mut cx, poll, Instant::from_secs(1));
        t.arm_once(&mut cx, poll, Instant::from_secs(2));
        assert_eq!(cx.set.len(), 1, "an armed poll is not pushed later");
        assert!(t.is_armed(poll));
        let id = cx.set.first().map(|(id, _)| *id).unwrap_or(TimerId::new(0));
        assert_eq!(t.fired(id), Some(poll));
        assert!(!t.is_armed(poll));
        t.cancel(&mut cx, poll);
        assert!(cx.cancelled.is_empty(), "nothing armed, nothing to cancel");
        t.arm_once(&mut cx, poll, Instant::from_secs(3));
        assert_eq!(cx.set.len(), 2);
    }

    #[test]
    fn allocation_stops_below_the_harness_range() {
        let mut t = TimerTable::new();
        let mut cx = Recorder::default();
        t.next = HARNESS_TIMERS - 1;
        assert!(t.arm(&mut cx, Purpose::Wake(PeerId::new(1)), Instant::ZERO));
        assert!(!t.arm(&mut cx, Purpose::Wake(PeerId::new(2)), Instant::ZERO));
        assert_eq!(cx.set.len(), 1);
        assert_eq!(
            cx.set.first().map(|(id, _)| id.as_u64()),
            Some(HARNESS_TIMERS - 1)
        );
    }
}
