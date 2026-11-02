// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One folder as the engine keeps it: its index, its chunks, whether it is
//! usable, paused, kept closed or misconfigured, and its state words.
//!
//! # Folder state (the engine's own; the Status message does not carry it)
//!
//! The plan's state words are "Up to date, Syncing 64%, Checking, Paused,
//! Waiting for peers, 3 issues" (plan, "Three depths"). [`FolderState`] is the
//! state machine behind them:
//!
//! - **Checking** while the index opens and checks every stored record
//!   (`protocol.md` 4.4, "Opening a folder"; TM-9). Phase 0 opens
//!   synchronously in `on_start`, before any connection (gap G5).
//! - **Misconfigured** when the store returned records and none passed: an
//!   index that holds nothing, and something dropped or undecodable. The
//!   folder is never proven to a peer and an error issue is raised; the
//!   engine never fills an empty index from such a store.
//! - **Unreadable** when the store could not be read at the open; never
//!   retried within an instance.
//! - **Closed** while the records stored lie more than a year ahead of this
//!   device's clock (4.4, "A clock set back"; the clock rule): it counts as
//!   a paused folder for folder proofs (3.5 step 2), so it is not proven to
//!   peers and their proofs for it are answered REJECTED; it judges nothing,
//!   refuses writes and raises the clock-rule issue (`IssueKind::KeptClosed`).
//!   Every handler compares the time the open gave with the wall clock, and
//!   a timer looks at least once a minute, so the folder opens, its
//!   credential back, once the clock passes that time, however the clock got
//!   there.
//! - **Paused** from a store failure until a resume probe commits (section 5,
//!   "Store failure"). The folder stays proven (decision for gap G4): only
//!   accepting records and writing stop. A pause also ends every round
//!   caught up, so a resumed folder reads Syncing until a round completes
//!   caught up again.
//! - **Syncing**, naming what it waits for: chunks lacking, the bytes they
//!   need, connections whose last round did not end caught up, and how many
//!   connections have the folder open ("no state shows Syncing without naming
//!   what it is waiting for", plan, "Recovery is local"); with nothing open
//!   it is the plan's "Waiting for peers".
//! - **Up to date**: usable, nothing lacking, open on at least one
//!   connection, and the last round on every connection where it is open
//!   ended caught up (4.5, "Rounds": at `EQUAL` or after a quiet pass; 4.7
//!   item 4).

use core::fmt;
use std::collections::{BTreeSet, VecDeque};

use licketysync_index::Index;
use licketysync_keys::chunk::ChunkKeys;
use licketysync_keys::sealed_meta::RecordKeys;
use licketysync_keys::{CipherHash, FolderId, Tier};

use crate::chunks::ChunkBook;
use crate::issues::StoreFailureCause;
use crate::runtime::Instant;

/// The most state transitions a folder keeps: the first of the instance
/// (Checking) and the latest after it.
pub const MAX_TRANSITIONS: usize = 16;

/// A folder's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderState {
    /// The index is being opened and every stored record checked.
    Checking,
    /// The store returned records and none passed; the folder is not used.
    Misconfigured {
        /// Stored records that failed their checks.
        dropped: u64,
        /// Stored entries that did not decode.
        undecodable: u64,
    },
    /// The store could not be read; the folder is not used.
    Unreadable,
    /// The records stored lie more than a year ahead of this device's
    /// clock: the folder stays closed until the clock reaches this, in
    /// microseconds since the Unix epoch.
    Closed {
        /// When the folder opens.
        opens_at_us: u64,
    },
    /// A store failure paused the folder.
    Paused(StoreFailureCause),
    /// Not up to date, and why.
    Syncing {
        /// Chunks the folder lacks.
        lacking_chunks: u64,
        /// Their stored bytes.
        bytes_needed: u64,
        /// Connections where the folder is open and whose last round did not
        /// end caught up (or has not ended yet).
        rounds_pending: u64,
        /// Connections where the folder is open; 0 is "Waiting for peers".
        open_on: u64,
    },
    /// Nothing lacks and every connection's round has completed.
    UpToDate,
}

impl FolderState {
    /// Whether two states are the same word (their counts aside): what the
    /// transition log records a change of.
    #[must_use]
    pub fn same_word(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

/// Whether a folder can be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Health {
    /// It opened and is proven to peers.
    Usable,
    /// See [`FolderState::Misconfigured`].
    Misconfigured { dropped: u64, undecodable: u64 },
    /// See [`FolderState::Unreadable`].
    Unreadable,
}

/// What the open found (4.4, "Opening a folder"; 4.7 item 8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenCounts {
    /// Stored records and bases that failed step 1 or their signature.
    pub dropped: u64,
    /// Stored entries that did not decode (gap G6).
    pub undecodable: u64,
    /// The stored high-water mark was corrupt and was replaced.
    pub hw_corrupt: bool,
    /// The stored local sequence numbers were broken and every record was
    /// numbered afresh.
    pub renumbered: bool,
    /// Stored base slots dropped because their record lies at another path.
    pub misplaced_bases: u64,
    /// The folder was kept closed by the clock rule (4.7 item 8).
    pub kept_closed: bool,
}

/// The transitions of one instance: the first (Checking) kept for good, the
/// latest after it up to [`MAX_TRANSITIONS`] in all, one entry per change of
/// state word.
#[derive(Clone, Debug, Default)]
pub(crate) struct Transitions {
    first: Option<(Instant, FolderState)>,
    rest: VecDeque<(Instant, FolderState)>,
}

impl Transitions {
    /// Records `state` at `at` if its word differs from the last one's.
    pub(crate) fn record(&mut self, at: Instant, state: FolderState) {
        let last = self.rest.back().or(self.first.as_ref());
        if last.is_some_and(|(_, s)| s.same_word(&state)) {
            return;
        }
        if self.first.is_none() {
            self.first = Some((at, state));
            return;
        }
        if self.rest.len() + 1 >= MAX_TRANSITIONS {
            self.rest.pop_front();
        }
        self.rest.push_back((at, state));
    }

    /// Every kept transition, oldest first.
    pub(crate) fn list(&self) -> Vec<(Instant, FolderState)> {
        self.first.iter().chain(self.rest.iter()).copied().collect()
    }
}

/// One folder's engine state (module documentation).
pub(crate) struct Folder {
    pub(crate) id: FolderId,
    pub(crate) tier: Tier,
    /// The folder's index; it changes only through the one transaction of
    /// each handler (the `sync` module).
    pub(crate) index: Index,
    /// The chunk keys, for the write and read tiers.
    pub(crate) chunk_keys: Option<ChunkKeys>,
    /// The record keys, for the write and read tiers.
    pub(crate) record_keys: Option<RecordKeys>,
    pub(crate) book: ChunkBook,
    pub(crate) health: Health,
    pub(crate) paused: Option<StoreFailureCause>,
    /// Kept closed by the clock rule until the clock reaches this, in
    /// microseconds (`FolderState::Closed`).
    pub(crate) closed_until: Option<u64>,
    pub(crate) open: OpenCounts,
    pub(crate) state: FolderState,
    pub(crate) transitions: Transitions,
    /// Paths whose heads are not all on the (simulated) disk yet: their
    /// content is still arriving, so their bases lag (the `sync::disk`
    /// module). Bounded by the paths held.
    pub(crate) unapplied: BTreeSet<String>,
    /// Chunks that no held record named when their record went, persisted,
    /// freed at the end of the next round (4.7 item 1). Bounded by the
    /// chunks the folder stores.
    pub(crate) pending_free: BTreeSet<CipherHash>,
    /// A round ended, or a minute passed with no connection open: the next
    /// commit frees what is pending.
    pub(crate) free_due: bool,
    /// The next commit applies the `unapplied` paths again: chunks may have
    /// arrived, or the folder opened or resumed.
    pub(crate) recheck_disk: bool,
    /// What the open changed (records dropped or renumbered, repairs, the
    /// first epoch), staged with the folder's next transaction and kept
    /// until a commit carries it, so that a failed one loses nothing of it.
    pub(crate) open_changes: Option<licketysync_index::ChangeSet>,
}

impl Folder {
    /// Whether its store opened and is usable (not misconfigured or
    /// unreadable).
    pub(crate) fn usable(&self) -> bool {
        self.health == Health::Usable
    }

    /// Whether the folder is proven to peers: usable and not kept closed by
    /// the clock rule (a store-failure pause keeps it proven, gap G4).
    pub(crate) fn credentialed(&self) -> bool {
        self.usable() && self.closed_until.is_none()
    }

    /// Whether it accepts records and writes now.
    pub(crate) fn accepting(&self) -> bool {
        self.credentialed() && self.paused.is_none()
    }

    /// Whether its connections hold it paused: a store failure, or the
    /// clock rule at open (`Connection::set_paused`).
    pub(crate) fn held_paused(&self) -> bool {
        self.paused.is_some() || self.closed_until.is_some()
    }

    /// Moves to `state`, logging a change of word at `at`.
    pub(crate) fn set_state(&mut self, at: Instant, state: FolderState) {
        self.state = state;
        self.transitions.record(at, state);
    }
}

impl fmt::Debug for Folder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Folder")
            .field("id", &self.id)
            .field("tier", &self.tier)
            .field("index", &self.index)
            .field("state", &self.state)
            .finish_non_exhaustive()
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

    fn syncing(n: u64) -> FolderState {
        FolderState::Syncing {
            lacking_chunks: n,
            bytes_needed: n,
            rounds_pending: 0,
            open_on: 1,
        }
    }

    #[test]
    fn transitions_log_word_changes_and_keep_checking_first() {
        let mut t = Transitions::default();
        t.record(Instant::ZERO, FolderState::Checking);
        t.record(Instant::from_secs(1), syncing(3));
        t.record(Instant::from_secs(2), syncing(2));
        assert_eq!(t.list().len(), 2, "a count change is the same word");
        for i in 0..40 {
            let s = if i % 2 == 0 {
                FolderState::UpToDate
            } else {
                syncing(1)
            };
            t.record(Instant::from_secs(3 + i), s);
        }
        let list = t.list();
        assert_eq!(list.len(), MAX_TRANSITIONS);
        assert_eq!(list.first(), Some(&(Instant::ZERO, FolderState::Checking)));
        assert_eq!(list.last().map(|(at, _)| *at), Some(Instant::from_secs(42)));
    }

    #[test]
    fn words_compare_without_their_counts() {
        assert!(syncing(1).same_word(&syncing(9)));
        assert!(!syncing(1).same_word(&FolderState::UpToDate));
        assert!(FolderState::Paused(StoreFailureCause::Full)
            .same_word(&FolderState::Paused(StoreFailureCause::Io)));
    }
}
