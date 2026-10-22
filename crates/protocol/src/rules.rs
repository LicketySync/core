// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The complete mapping of `protocol.md` section 5: every failure has exactly
//! one of three outcomes (TM-10). *Close* is for what only the sender can be
//! blamed for: bytes that do not parse or do not verify, a broken order or
//! bound. *Set aside and keep* is for differences in what two peers hold.
//! *Issue against the record* is for what a valid signature covers: the body
//! is what a write holder signed and the sender merely carried it, so the
//! issue names the record, never a device (ruling S-4), and the connection
//! stays open. [`Cause`] names every row of the table and [`Cause::outcome`]
//! is the table; [`Cause::report`] says what each row leaves behind, since
//! nothing is dropped without trace. The connection acts on the outcomes it
//! can see itself; the index judges the records of each page and hands its
//! judgements to it through [`crate::connection::Connection::judged`].

use crate::messages::CloseReason;

/// Why something failed or was set aside: one variant per row of the
/// section 5 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Cause {
    /// A frame length below 2, a body that does not parse, a bound or grammar
    /// violated, a fixed-size field absent or of another size, a message out
    /// of order or for a folder not open here, more proofs or chunk requests
    /// than allowed, a stray `ProofResult`, a second request before the reply
    /// to the first has queued its last page, a page for no outstanding
    /// request, a reply page with `more` and no records, an unsolicited
    /// `ChunkReply`.
    Malformed,
    /// A frame longer than the limit; nothing was allocated.
    FrameOverLimit,
    /// A type with the critical bit set that this peer does not know.
    UnknownCriticalType,
    /// A type with the critical bit clear that this peer does not know.
    UnknownNonCriticalType,
    /// The Hellos share no implemented suite.
    NoCommonSuite,
    /// The peer's `max_message_size` is below `MIN_MESSAGE_SIZE`.
    LimitTooSmall,
    /// The `DeviceProof` does not verify.
    DeviceProofRejected,
    /// `HELLO_TIMEOUT` elapsed.
    HelloTimeout,
    /// `IDLE_TIMEOUT` elapsed with no frame, or with unsent bytes and none
    /// delivered.
    IdleTimeout,
    /// The reply to this side's outstanding `IndexRequest` brought no page for
    /// `REPLY_PAGE_TIMEOUT`.
    ReplyPageTimeout,
    /// `PROOF_TIMEOUT` elapsed with nothing opened.
    ProofTimeout,
    /// An index record, neither a duplicate nor a gap, whose signature does
    /// not verify under the folder key; a chunk whose ciphertext hash fails.
    Forged,
    /// Inside a reply: a gap (a record whose `seq` is above the requester's
    /// cursor for its writer plus one), or a record of a writer outside the
    /// request's range or list. The sender's, whatever the signature.
    SenderViolation,
    /// A `FolderProof` that fails for any reason (hint, seal, payload, the
    /// folder's suite missing from the peer's Hello, the open-folder bound).
    FolderProofRejected,
    /// A pushed record with `seq > cursor + 1`.
    PushGap,
    /// An index record whose record hash is already held.
    Duplicate,
    /// A record of a writer at a `seq` where another record of that writer
    /// is held (ruling R-K5).
    ConcurrentVersion,
    /// A record whose `supersedes` names a record not held (ruling R-K6).
    Waiting,
    /// While serving: the requester's digest at its `seq` differs from this
    /// side's (4.5 case (c)).
    DigestMismatch,
    /// An empty push: the sender dropped pushes for the folder.
    EmptyPush,
    /// A peer offers cursors below those stored here.
    Rollback,
    /// What a valid signature covers but a key holder cannot apply: a seal
    /// that will not open, bad padding, a malformed path, an unknown kind or a
    /// hash-count mismatch; a chunk with a correct ciphertext hash whose
    /// length, seal, padding, compression or plaintext hash fails.
    WriterFault,
    /// The holder answered `CHUNK_BUSY`.
    ChunkBusy,
    /// The holder answered `CHUNK_NOT_FOUND`.
    ChunkNotFound,
    /// A record under this device's own device ID at or above the next `seq`
    /// it would use (4.5, "Durability before transmission").
    OwnSequenceAhead,
}

/// What happens to the item, the connection kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Keep {
    /// Answer `Unsupported`, at most once per type per connection; continue.
    ReplyUnsupported,
    /// Answer `ProofResult(REJECTED)`; nothing of any folder is sent before it
    /// is open.
    ProofRejected,
    /// Ignore without verifying; mark the writer for a listed request.
    IgnoreAndMark,
    /// Ignore (without verifying, for a record).
    Ignore,
    /// Store, and apply unless step 6 finds a writer fault; the writer's
    /// cached digests recomputed from the record's `seq` up.
    Store,
    /// Store; it takes no part in heads until every record it names is held
    /// and none of them waits.
    StoreWaiting,
    /// Send every record of the writer and mark it for a listed request.
    ResendAndMark,
    /// Owe a round.
    OweRound,
    /// Send no chunk request on the connection for `CHUNK_BUSY_BACKOFF`; ask
    /// other peers meanwhile.
    BackOff,
    /// Ask other peers for the chunk; the pass to this peer goes on.
    AskElsewhere,
    /// Store and apply; move this device's sequence counter past it before
    /// writing again.
    MoveCounter,
}

/// The three-way outcome of section 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// Close the connection with this reason: only the sender can be blamed.
    Close(CloseReason),
    /// Keep the connection; the item is handled as `Keep` says.
    Keep(Keep),
    /// Keep the connection; raise an issue naming the record (never a
    /// device), store the record opaque or mark the chunk corrupt for that
    /// record.
    IssueAgainstRecord,
}

/// What an outcome leaves behind, so that nothing is dropped without trace
/// (section 5, "Nothing is silently skipped").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Report {
    /// An issue naming the peer that sent it, and the cause.
    IssueNamingPeer,
    /// An issue naming the record, by hash (and by path where the seal
    /// opened), never a device.
    IssueNamingRecord,
    /// An informational issue that names no one.
    InformationalIssue,
    /// A log line naming the cause (a waiting record also raises an
    /// informational issue later, the index's rule of 4.4).
    Log,
}

impl Cause {
    /// Every row, in the order of section 5's table.
    pub const ALL: [Self; 25] = [
        Self::Malformed,
        Self::FrameOverLimit,
        Self::UnknownCriticalType,
        Self::UnknownNonCriticalType,
        Self::NoCommonSuite,
        Self::LimitTooSmall,
        Self::DeviceProofRejected,
        Self::HelloTimeout,
        Self::IdleTimeout,
        Self::ReplyPageTimeout,
        Self::ProofTimeout,
        Self::Forged,
        Self::SenderViolation,
        Self::FolderProofRejected,
        Self::PushGap,
        Self::Duplicate,
        Self::ConcurrentVersion,
        Self::Waiting,
        Self::DigestMismatch,
        Self::EmptyPush,
        Self::Rollback,
        Self::WriterFault,
        Self::ChunkBusy,
        Self::ChunkNotFound,
        Self::OwnSequenceAhead,
    ];

    /// The row of the section 5 table for this cause.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        match self {
            Self::Malformed | Self::SenderViolation => Outcome::Close(CloseReason::ProtocolError),
            Self::FrameOverLimit => Outcome::Close(CloseReason::MessageTooLarge),
            Self::UnknownCriticalType => Outcome::Close(CloseReason::UnsupportedCriticalType),
            Self::NoCommonSuite => Outcome::Close(CloseReason::NoCommonSuite),
            Self::LimitTooSmall => Outcome::Close(CloseReason::LimitTooSmall),
            Self::DeviceProofRejected => Outcome::Close(CloseReason::ProofRejected),
            Self::HelloTimeout | Self::IdleTimeout | Self::ReplyPageTimeout => {
                Outcome::Close(CloseReason::Timeout)
            }
            Self::ProofTimeout => Outcome::Close(CloseReason::NoCommonFolder),
            Self::Forged => Outcome::Close(CloseReason::VerificationFailed),
            Self::UnknownNonCriticalType => Outcome::Keep(Keep::ReplyUnsupported),
            Self::FolderProofRejected => Outcome::Keep(Keep::ProofRejected),
            Self::PushGap => Outcome::Keep(Keep::IgnoreAndMark),
            Self::Duplicate | Self::Rollback => Outcome::Keep(Keep::Ignore),
            Self::ConcurrentVersion => Outcome::Keep(Keep::Store),
            Self::Waiting => Outcome::Keep(Keep::StoreWaiting),
            Self::DigestMismatch => Outcome::Keep(Keep::ResendAndMark),
            Self::EmptyPush => Outcome::Keep(Keep::OweRound),
            Self::ChunkBusy => Outcome::Keep(Keep::BackOff),
            Self::ChunkNotFound => Outcome::Keep(Keep::AskElsewhere),
            Self::OwnSequenceAhead => Outcome::Keep(Keep::MoveCounter),
            Self::WriterFault => Outcome::IssueAgainstRecord,
        }
    }

    /// What the outcome leaves behind. A close for the sender's fault raises
    /// an issue naming the peer (TM-10); a timeout, which an honest peer on a
    /// bad network can cause, and every difference in knowledge, a log line;
    /// a writer fault, an issue naming the record; a record under this
    /// device's own ID ahead of its counter, an informational issue naming no
    /// one.
    #[must_use]
    pub const fn report(self) -> Report {
        match self {
            Self::Malformed
            | Self::FrameOverLimit
            | Self::UnknownCriticalType
            | Self::NoCommonSuite
            | Self::LimitTooSmall
            | Self::DeviceProofRejected
            | Self::Forged
            | Self::SenderViolation => Report::IssueNamingPeer,
            Self::WriterFault => Report::IssueNamingRecord,
            Self::OwnSequenceAhead => Report::InformationalIssue,
            Self::HelloTimeout
            | Self::IdleTimeout
            | Self::ReplyPageTimeout
            | Self::ProofTimeout
            | Self::UnknownNonCriticalType
            | Self::FolderProofRejected
            | Self::PushGap
            | Self::Duplicate
            | Self::ConcurrentVersion
            | Self::Waiting
            | Self::DigestMismatch
            | Self::EmptyPush
            | Self::Rollback
            | Self::ChunkBusy
            | Self::ChunkNotFound => Report::Log,
        }
    }

    /// Whether this cause closes the connection.
    #[must_use]
    pub const fn closes(self) -> bool {
        matches!(self.outcome(), Outcome::Close(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_of_section_5() {
        use CloseReason as R;
        let closes = [
            (Cause::Malformed, R::ProtocolError),
            (Cause::SenderViolation, R::ProtocolError),
            (Cause::FrameOverLimit, R::MessageTooLarge),
            (Cause::UnknownCriticalType, R::UnsupportedCriticalType),
            (Cause::NoCommonSuite, R::NoCommonSuite),
            (Cause::LimitTooSmall, R::LimitTooSmall),
            (Cause::DeviceProofRejected, R::ProofRejected),
            (Cause::HelloTimeout, R::Timeout),
            (Cause::IdleTimeout, R::Timeout),
            (Cause::ReplyPageTimeout, R::Timeout),
            (Cause::ProofTimeout, R::NoCommonFolder),
            (Cause::Forged, R::VerificationFailed),
        ];
        for (cause, reason) in closes {
            assert_eq!(cause.outcome(), Outcome::Close(reason), "{cause:?}");
            assert!(cause.closes());
        }
        let keeps = [
            (Cause::UnknownNonCriticalType, Keep::ReplyUnsupported),
            (Cause::FolderProofRejected, Keep::ProofRejected),
            (Cause::PushGap, Keep::IgnoreAndMark),
            (Cause::Duplicate, Keep::Ignore),
            (Cause::Rollback, Keep::Ignore),
            (Cause::ConcurrentVersion, Keep::Store),
            (Cause::Waiting, Keep::StoreWaiting),
            (Cause::DigestMismatch, Keep::ResendAndMark),
            (Cause::EmptyPush, Keep::OweRound),
            (Cause::ChunkBusy, Keep::BackOff),
            (Cause::ChunkNotFound, Keep::AskElsewhere),
            (Cause::OwnSequenceAhead, Keep::MoveCounter),
        ];
        for (cause, keep) in keeps {
            assert_eq!(cause.outcome(), Outcome::Keep(keep), "{cause:?}");
            assert!(!cause.closes());
        }
        assert_eq!(Cause::WriterFault.outcome(), Outcome::IssueAgainstRecord);
        assert_eq!(closes.len() + keeps.len() + 1, Cause::ALL.len());
    }

    #[test]
    fn every_outcome_leaves_a_trace() {
        for cause in Cause::ALL {
            let report = cause.report();
            match cause.outcome() {
                Outcome::Close(CloseReason::Timeout | CloseReason::NoCommonFolder) => {
                    assert_eq!(report, Report::Log, "{cause:?}");
                }
                Outcome::Close(_) => assert_eq!(report, Report::IssueNamingPeer, "{cause:?}"),
                Outcome::IssueAgainstRecord => assert_eq!(report, Report::IssueNamingRecord),
                Outcome::Keep(Keep::MoveCounter) => {
                    assert_eq!(report, Report::InformationalIssue);
                }
                Outcome::Keep(_) => assert_eq!(report, Report::Log, "{cause:?}"),
            }
        }
    }
}
