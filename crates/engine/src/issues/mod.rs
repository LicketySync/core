// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The engine's Issues list and its log counters (`protocol.md` section 5,
//! "Nothing is silently skipped"; TM-10).
//!
//! Every outcome leaves a trace: an issue for what the section 5 table says
//! raises one ([`licketysync_protocol::Report`]), a counter per cause for the
//! rest. Each issue names its cause and at most one subject:
//!
//! - a peer ([`Subject::Peer`]) only for a close this side made for the
//!   peer's fault (`Report::IssueNamingPeer`), with whether it had proven a
//!   folder key on the connection;
//! - a record by hash, never a device (ruling S-4), for a writer fault, a
//!   chunk corrupt for that record, and a size mismatch at reassembly;
//! - a device without blaming it, for the clock rule's issues: the peer whose
//!   Hello was more than a year from this device's, the device a record from
//!   the future claims, the device a record far ahead claims;
//! - nothing, for a hint that this device was restored or cloned.
//!
//! No issue carries a path or a secret (TM-6): the subjects are record and
//! chunk hashes, peer handles and device IDs, and counts. The list keeps
//! each source of issues within a bound of its own (`list`; TM-22, TM-10).

use std::collections::BTreeMap;

use licketysync_keys::{CipherHash, DeviceId, FolderId, RecordHash};
use licketysync_protocol::{Cause, CloseReason};

use crate::runtime::{PeerId, StorageError};

mod list;

pub use list::{
    IssueClass, IssueEntry, Issues, MAX_LOCAL_ISSUES, MAX_PEER_ISSUES, MAX_RECORD_ISSUES_PER_FOLDER,
};

/// The most record hashes the open issue names (`protocol.md` section 5,
/// "Stored record fails its check": a fixed engine constant).
pub const OPEN_ISSUE_HASHES: usize = 16;

/// What went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssueKind {
    /// This side closed the connection for the peer's fault, with this cause
    /// (`Report::IssueNamingPeer`: malformed, forged, a sender violation …).
    PeerFault(Cause),
    /// Step 7 found a writer fault: the record is held opaque, and a path
    /// whose live records are all opaque shows no version (4.4). A shared
    /// fault (`shared`: every release of major 1 judges it so,
    /// `WriterFault::is_shared`) lasts only until its path is next written,
    /// since every write there names it: saving the file again clears it
    /// (4.4, "Heads, display order and conflicts"). Any other is a `kind`
    /// this release does not know, which a later release reads.
    WriterFault {
        /// Every release finds the record faulty, and saving the file again
        /// clears it.
        shared: bool,
    },
    /// A chunk with the right ciphertext hash failed for this record: its
    /// stored length, seal, padding, compression or plaintext hash (4.6).
    ChunkCorrupt,
    /// Every chunk of the file verified, but their plaintext lengths do not
    /// sum to the record's size (4.6; spec confirm 5d78a87).
    SizeMismatch,
    /// A record under this device's own ID with a counter above its
    /// high-water mark: the mark rose to it and a new epoch was drawn (4.5,
    /// "Durability before transmission"). A hint, naming no one: this device
    /// was restored from a backup, or a cloned disk image runs beside it
    /// (`keys.md` 8.1).
    OwnCounterAhead,
    /// The open dropped stored records, met bytes that do not decode, found
    /// the high-water mark corrupt, numbered the records afresh or dropped a
    /// misplaced base (4.4, "Opening a folder"; 4.7 item 8).
    OpenReport,
    /// The clock rule at the handshake (3.2): when the folder opened, this
    /// device's clock and the peer's differed by more than a year, and the
    /// connection closed. Neither reading can say which clock is wrong:
    /// compare this device's clock with a trusted one. The remedy, on the
    /// device whose clock is wrong: unlink the folder keeping its files, set
    /// the clock right, then add the folder again over the same files, which
    /// starts its index afresh (4.4, "What adding the folder again resets on
    /// that device").
    ClockOutOfRange,
    /// A record dated more than a year ahead of this device's clock was
    /// refused (4.4, "The clock rule"): compare this device's clock with a
    /// trusted one; the remedy is as for [`IssueKind::ClockOutOfRange`].
    FromTheFuture,
    /// The clock rule at the open (4.4, "A clock set back"): records here
    /// are dated more than a year ahead of this device's clock: it was set
    /// back, or was ahead when they arrived. The folder stays closed (not
    /// proven to peers, receiving nothing) until the clock is within a year
    /// of its newest record (`FolderState::Closed` gives when), and opens by
    /// itself then. The remedy, if the clock is wrong: set it right, and the
    /// folder opens; otherwise unlink the folder keeping its files and add it
    /// again over the same files, which starts its index afresh (4.4, "What
    /// adding the folder again resets on that device").
    KeptClosed,
    /// This folder's time is more than `CLOCK_AHEAD_WARNING` (a day) ahead of
    /// this device's clock (4.4, "A fast clock carries forward"): deletions
    /// up to that much early may be forgotten.
    ClockAhead,
    /// The folder's store failed: it is paused until a probe commits.
    StoreFailure(StoreFailureCause),
    /// The store returned records and none passed: the folder is not used.
    Misconfigured,
    /// The store could not be read when the folder opened.
    Unreadable,
    /// A stored chunk blob changed in this device's storage (TM-10): it is
    /// forgotten as stored and fetched again.
    LocalChunkCorrupt,
    /// The peer refused the folder's proof while 64 folders were open on the
    /// connection (`MAX_OPEN_FOLDERS_PER_CONNECTION`): possibly the open
    /// limit (`protocol.md` 3.5 step 6). REJECTED is uniform by design, so
    /// the peer may as well hold no key of the folder; either way the folder
    /// does not sync with that peer over this connection. The issue names no
    /// peer (it is merged per folder, as every local issue is) and stays
    /// until this instance ends, even if a later connection opens the folder.
    OpenLimit,
}

/// Why a store failed, without the runtime's text (which could carry
/// anything).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoreFailureCause {
    /// The disk is full.
    Full,
    /// Any other failure.
    Io,
}

impl StoreFailureCause {
    pub(crate) fn of(e: &StorageError) -> Self {
        match e {
            StorageError::Full => Self::Full,
            _ => Self::Io,
        }
    }
}

/// The one subject an issue names.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Subject {
    /// Nobody.
    None,
    /// A peer: the runtime's handle, its device ID once proven, and whether
    /// it holds a key of a folder this device holds.
    Peer {
        /// The connection's handle.
        peer: PeerId,
        /// The device ID its `DeviceProof` proved, when it had. Anyone can
        /// mint a device key, so this alone proves nothing more.
        device: Option<DeviceId>,
        /// A folder was open on the connection: the peer proved a key of a
        /// folder this device holds (`protocol.md` 3.5). What puts its issue
        /// in the [`IssueClass::ProvenPeer`] class.
        holder: bool,
    },
    /// A record, by hash.
    Record(RecordHash),
    /// A device, named without blame: where a record from the future says
    /// it came from.
    Device(DeviceId),
    /// The clock rule at the handshake: the peer's proven device ID and the
    /// two Hellos' `clock_days`.
    Clock {
        /// The peer.
        device: DeviceId,
        /// This device's reading, in whole days since the Unix epoch.
        ours: u32,
        /// The peer's.
        theirs: u32,
    },
    /// How far the folder's time is ahead of this device's clock, and the
    /// device the record that carried it claims (which may only have carried
    /// a fast device's time forward).
    ClockAhead {
        /// The lead, in microseconds.
        lead_us: u64,
        /// The device the record claims.
        device: DeviceId,
    },
    /// A stored chunk, by ciphertext hash.
    Chunk(CipherHash),
    /// What an open found (4.7 item 8), with at most [`OPEN_ISSUE_HASHES`]
    /// of the record hashes it dropped.
    Open {
        /// Stored records and bases that failed their checks.
        dropped: u64,
        /// Stored entries that did not decode.
        undecodable: u64,
        /// The stored high-water mark was corrupt.
        hw_corrupt: bool,
        /// The records were numbered afresh.
        renumbered: bool,
        /// Misplaced base slots dropped.
        misplaced_bases: u64,
        /// Some of the dropped record hashes, ascending.
        hashes: Vec<RecordHash>,
    },
}

/// One issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// The folder it is about, when it is about one.
    pub folder: Option<FolderId>,
    /// What went wrong.
    pub kind: IssueKind,
    /// Who or what it names.
    pub subject: Subject,
}

impl Issue {
    /// Whether the issue names a peer or a record: what an honest run never
    /// raises (the phase 0 gate, criterion (d)).
    #[must_use]
    pub fn blames(&self) -> bool {
        matches!(self.subject, Subject::Peer { .. } | Subject::Record(_))
    }
}

/// Log lines, counted: one counter per section 5 cause that leaves a log
/// line, and the engine's own counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Per cause, every outcome whose report is a log line (and the causes
    /// that also raised an issue, so every row reached shows here).
    pub causes: BTreeMap<Cause, u64>,
    /// Closes this side sent, by reason.
    pub closes_sent: CloseCounts,
    /// Closes the peer sent, by reason: a peer picks the number, so every
    /// number this release does not define shares one count (TM-22).
    pub closes_received: CloseCounts,
    /// Engine bugs: a typed send error that should not happen, a send to a
    /// peer the engine believed connected, a judgement for another folder.
    /// Honest runs keep it at 0.
    pub internal_errors: u64,
    /// Reply pages and `CHUNK_OK` frames held back by the send budget.
    pub deferrals: u64,
    /// Records not judged and chunks not stored because their folder was
    /// held paused (a store failure, or the clock rule at open).
    pub skipped_while_paused: u64,
    /// Rounds owed on connections: when a folder resumed, after a failed
    /// handler skipped a folder's records, or after a round's end issued a
    /// cleanup.
    pub rounds_owed: u64,
    /// Pages of a reply reported skipped, unjudged, because an earlier page
    /// of the same reply was skipped (the reply is void; the owed round
    /// brings its records back).
    pub void_reply_pages: u64,
    /// Records a write holder noted as stale copies or forgotten records,
    /// for a cleanup at a round's end (4.5, "Stale copies").
    pub stale_noted: u64,
    /// Records a write holder would have noted but did not: the peer's names
    /// or the connection's verifications for notes were spent (`NotNoted`).
    pub stale_not_noted: u64,
    /// Connections that ended with no folder opened and Hellos more than a
    /// year apart (3.2: a log line, never an issue).
    pub stranger_clocks: u64,
    /// Chunks that arrived for a hash already stored: a second connection's
    /// answer to a request asked again after the chunk patience.
    pub late_chunks: u64,
    /// Reads of a stored blob that failed: the blob was forgotten and
    /// fetched (or staged) again; nothing was deleted and no issue raised.
    pub read_errors: u64,
    /// Proofs the peer refused while the connection had 64 folders open:
    /// possibly the open limit (`IssueKind::OpenLimit`).
    pub open_limit_refusals: u64,
    /// Our `FolderProof`s the peer answered REJECTED.
    pub proofs_rejected: u64,
    /// Unknown non-critical frames ignored and `Unsupported` answers received.
    pub unsupported: u64,
    /// The most reply pages carrying records received on one connection.
    pub most_reply_pages: u64,
    /// Stores that failed (a put or a commit).
    pub store_failures: u64,
    /// Write attempts refused locally (a read or sealed key, a pause …).
    pub writes_refused: u64,
    /// The paths applied to the disk, for the test that holding a tree
    /// delete applies only what it dropped.
    #[cfg(test)]
    pub(crate) paths_applied: u64,
}

impl Counters {
    /// Counts one outcome of `cause`.
    pub(crate) fn log(&mut self, cause: Cause) {
        let n = self.causes.entry(cause).or_insert(0);
        *n = n.saturating_add(1);
    }

    /// The count for `cause`.
    #[must_use]
    pub fn of(&self, cause: Cause) -> u64 {
        self.causes.get(&cause).copied().unwrap_or(0)
    }

    pub(crate) fn close(&mut self, sent: bool, reason: CloseReason) {
        if sent {
            self.closes_sent.add(reason);
        } else {
            self.closes_received.add(reason);
        }
    }

    /// Closes sent or received for `reason` (for a number this release does
    /// not define, every such number's).
    #[must_use]
    pub fn closes(&self, reason: CloseReason) -> u64 {
        self.closes_sent
            .of(reason)
            .saturating_add(self.closes_received.of(reason))
    }

    /// Closes, sent or received, for the reasons an honest run never sees:
    /// `PROTOCOL_ERROR`, `VERIFICATION_FAILED`, `MESSAGE_TOO_LARGE`, `TIMEOUT`
    /// and `NO_COMMON_FOLDER` (the phase 0 gate's criterion (d)).
    #[must_use]
    pub fn blaming_closes(&self) -> u64 {
        [
            CloseReason::ProtocolError,
            CloseReason::VerificationFailed,
            CloseReason::MessageTooLarge,
            CloseReason::Timeout,
            CloseReason::NoCommonFolder,
        ]
        .into_iter()
        .map(|r| self.closes(r))
        .fold(0, u64::saturating_add)
    }

    pub(crate) fn bug(&mut self) {
        self.internal_errors = self.internal_errors.saturating_add(1);
    }
}

/// `*n += 1`, saturating.
pub(crate) fn bump(n: &mut u64) {
    *n = n.saturating_add(1);
}

/// Closes counted by reason: one count per reason this release defines and
/// one for every other number, so the table has a fixed size however many
/// numbers peers send (TM-22). A reason's slot is its place in
/// `CloseReason::ALL`, found by its wire number, which is not its place
/// (`CLOCK_OUT_OF_RANGE` is 13, after 11): the numbers there are distinct,
/// checked when the crate builds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloseCounts {
    /// By the reason's place in `CloseReason::ALL`.
    defined: [u64; CloseReason::ALL.len()],
    /// Every number this release does not define.
    other: u64,
}

// The defined reasons' wire numbers are distinct, so a number finds at most
// one slot; checked at build time.
#[allow(
    clippy::indexing_slicing,
    reason = "a compile-time check: an index out of range fails the build"
)]
const _: () = {
    let mut i = 0;
    while i < CloseReason::ALL.len() {
        let mut j = i + 1;
        while j < CloseReason::ALL.len() {
            assert!(CloseReason::ALL[i].as_u32() != CloseReason::ALL[j].as_u32());
            j += 1;
        }
        i += 1;
    }
};

impl CloseCounts {
    fn slot(reason: CloseReason) -> Option<usize> {
        let n = reason.as_u32();
        CloseReason::ALL.iter().position(|r| r.as_u32() == n)
    }

    pub(crate) fn add(&mut self, reason: CloseReason) {
        match Self::slot(reason).and_then(|i| self.defined.get_mut(i)) {
            Some(n) => bump(n),
            None => bump(&mut self.other),
        }
    }

    /// The count for `reason`; for a number this release does not define,
    /// the count of every such number.
    #[must_use]
    pub fn of(&self, reason: CloseReason) -> u64 {
        match Self::slot(reason) {
            Some(i) => self.defined.get(i).copied().unwrap_or(0),
            None => self.other,
        }
    }

    /// The closes for numbers this release does not define.
    #[must_use]
    pub const fn other(&self) -> u64 {
        self.other
    }

    /// Every count: each defined reason, then `None` for the other numbers.
    pub fn iter(&self) -> impl Iterator<Item = (Option<CloseReason>, u64)> + '_ {
        CloseReason::ALL
            .iter()
            .zip(self.defined)
            .map(|(r, n)| (Some(*r), n))
            .chain(core::iter::once((None, self.other)))
    }
}

/// The open issue's subject (4.7 item 8), or `None` when the open found
/// nothing to report.
pub(crate) fn open_subject(report: &licketysync_index::OpenReport) -> Option<Subject> {
    let clean = report.dropped.is_empty()
        && report.undecodable == 0
        && !report.hw_corrupt
        && !report.renumbered
        && report.misplaced_bases.is_empty();
    (!clean).then(|| Subject::Open {
        dropped: report.dropped.len() as u64,
        undecodable: report.undecodable as u64,
        hw_corrupt: report.hw_corrupt,
        renumbered: report.renumbered,
        misplaced_bases: report.misplaced_bases.len() as u64,
        hashes: report
            .dropped
            .iter()
            .take(OPEN_ISSUE_HASHES)
            .copied()
            .collect(),
    })
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

    #[test]
    fn the_open_issue_names_at_most_sixteen_dropped_hashes_and_a_clean_open_none() {
        let mut report = licketysync_index::OpenReport::default();
        assert!(open_subject(&report).is_none());
        report.dropped = (0..30).map(|i| RecordHash([i; 32])).collect();
        report.undecodable = 2;
        report.renumbered = true;
        let Some(Subject::Open {
            dropped,
            undecodable,
            hw_corrupt,
            renumbered,
            misplaced_bases,
            hashes,
        }) = open_subject(&report)
        else {
            unreachable!("a report with drops has a subject");
        };
        assert_eq!(
            (
                dropped,
                undecodable,
                hw_corrupt,
                renumbered,
                misplaced_bases
            ),
            (30, 2, false, true, 0)
        );
        assert_eq!(hashes.len(), OPEN_ISSUE_HASHES);
        assert_eq!(hashes.first(), report.dropped.first());
    }

    #[test]
    fn only_issues_naming_a_peer_or_a_record_blame() {
        let issue = |subject| Issue {
            folder: None,
            kind: IssueKind::WriterFault { shared: true },
            subject,
        };
        assert!(issue(Subject::Record(RecordHash([1; 32]))).blames());
        assert!(issue(Subject::Peer {
            peer: PeerId::new(1),
            device: None,
            holder: false,
        })
        .blames());
        assert!(!issue(Subject::None).blames());
        assert!(!issue(Subject::Chunk(CipherHash([1; 32]))).blames());
        assert!(!issue(Subject::Device(DeviceId([1; 32]))).blames());
        assert!(!issue(Subject::Clock {
            device: DeviceId([1; 32]),
            ours: 1,
            theirs: 900
        })
        .blames());
    }

    #[test]
    fn counters_count_causes_closes_and_bugs() {
        let mut c = Counters::default();
        c.log(Cause::Duplicate);
        c.log(Cause::Duplicate);
        assert_eq!(c.of(Cause::Duplicate), 2);
        assert_eq!(c.of(Cause::EmptyPush), 0);
        c.close(true, CloseReason::Shutdown);
        c.close(false, CloseReason::Shutdown);
        assert_eq!(c.closes(CloseReason::Shutdown), 2);
        assert_eq!(c.closes(CloseReason::Timeout), 0);
        assert_eq!(c.closes_sent.of(CloseReason::Shutdown), 1);
        c.bug();
        assert_eq!(c.internal_errors, 1);
        assert_eq!(
            StoreFailureCause::of(&StorageError::Full),
            StoreFailureCause::Full
        );
        assert_eq!(
            StoreFailureCause::of(&StorageError::Io("x".into())),
            StoreFailureCause::Io
        );
    }

    #[test]
    fn close_reasons_a_peer_invents_share_one_count_so_the_table_never_grows() {
        // TM-22: a peer picks the reason number of its Close, so a table
        // keyed by the number would grow with every fresh one.
        let mut c = Counters::default();
        for n in 1_000..3_000 {
            c.close(false, CloseReason::Other(n));
        }
        c.close(false, CloseReason::Timeout);
        assert_eq!(c.closes_received.other(), 2_000);
        assert_eq!(c.closes(CloseReason::Other(77)), 2_000);
        assert_eq!(c.closes(CloseReason::Timeout), 1);
        assert_eq!(
            c.closes_received.iter().count(),
            CloseReason::ALL.len() + 1,
            "one count per defined reason and one for the rest"
        );
        // A defined number built as `Other` counts as its reason, and a
        // reason whose number is not its place keeps a slot of its own.
        c.close(true, CloseReason::Other(11));
        assert_eq!(c.closes_sent.of(CloseReason::Timeout), 1);
        assert_eq!(c.blaming_closes(), 2);
        c.close(false, CloseReason::ClockOutOfRange);
        assert_eq!(c.closes_received.of(CloseReason::ClockOutOfRange), 1);
        assert_eq!(c.closes_received.other(), 2_000);
    }
}
