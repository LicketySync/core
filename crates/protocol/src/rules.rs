// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The mapping of `protocol.md` section 5 for what arrives on a connection:
//! every such failure has exactly one of three outcomes (TM-10). *Close* is
//! for what only the sender can be blamed for: bytes that do not parse or do
//! not verify, a broken order or bound. *Set aside and keep* is for
//! differences in what two peers hold. *Issue against the record* is for
//! what a valid signature covers: the body is what a write holder signed and
//! the sender merely carried it, so the issue names the record, never a
//! device (ruling S-4), and the connection stays open. [`Cause`] names every
//! row of the table but the two about this device's own index store, which
//! are the index's and the engine's: "Store failure", for a record that
//! arrived on a connection and that the store cannot take, and "Stored
//! record fails its check" when a folder opens, which involves no connection
//! (TM-9). [`Cause::outcome`] is the table for the rows it names;
//! [`Cause::report`] says what each row leaves behind, since nothing is
//! dropped without trace. The connection acts on the outcomes it can see
//! itself; the index judges the records of each page and the engine hands
//! those judgements to it through [`crate::connection::Connection::judged`].

use crate::messages::CloseReason;

/// Why something failed or was set aside: one variant per row of the
/// section 5 table, but the two rows about this device's own index store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Cause {
    /// A frame length below 2, a body that does not parse, a bound or grammar
    /// violated, a fixed-size field absent or of another size, a message out
    /// of order or for a folder not open here, more proofs or chunk requests
    /// than allowed, a stray `ProofResult`, a second request before the reply
    /// to the first has queued its end, a page or reply for no outstanding
    /// request or of the wrong kind for it, an unsolicited `ChunkReply`.
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
    /// The reply to this side's outstanding request brought nothing for
    /// `REPLY_PAGE_TIMEOUT`.
    ReplyPageTimeout,
    /// `PROOF_TIMEOUT` elapsed with nothing opened.
    ProofTimeout,
    /// A record that is neither a duplicate, nor expired, nor obsolete, or
    /// that a write holder verifies before noting it, whose signature does
    /// not verify under the folder key with its record type's label; a chunk
    /// whose ciphertext hash fails.
    Forged,
    /// Inside a reconciliation: a `RECORDS` record whose key does not begin
    /// with the request's prefix, `CHILDREN` for a 128-nibble prefix or
    /// answering a zero digest, or `RECORDS` of more than
    /// `RECONCILE_LEAF_MAX` records at a shorter prefix answering a non-zero
    /// digest. The sender's, whatever the signature.
    SenderViolation,
    /// A `FolderProof` that fails for any reason (hint, seal, payload, the
    /// folder's suite missing from the peer's Hello, the open-folder bound).
    FolderProofRejected,
    /// A record whose record hash is already held.
    Duplicate,
    /// At a read or write holder, a tombstone or tree delete that the folder's
    /// own time has passed by `TOMBSTONE_HORIZON`, or a cleanup it has passed
    /// by `CLEANUP_HORIZON`.
    Expired,
    /// A record that something held replaces, and that replaces nothing held.
    Obsolete,
    /// A record that names, covers or (for a cleanup) forgets records held.
    ReplacesHeld,
    /// A cleanup group whose `because` names a record not held.
    CleanupGroupWaiting,
    /// At a read or write holder, a record whose counter is more than
    /// `CLOCK_RULE_LIMIT` ahead of this device's clock.
    FromTheFuture,
    /// The two Hellos' `clock_days` differ by more than `CLOCK_RULE_LIMIT`,
    /// judged when the first folder opens on the connection.
    ClockOutOfRange,
    /// An `IndexRequest` whose epoch is not this side's, or whose `since` is
    /// above its local sequence.
    Reset,
    /// A `ReconcileRequest` whose digest is not this side's.
    DigestDiffers,
    /// An empty push: the sender dropped pushes for the folder.
    EmptyPush,
    /// What a valid signature covers but a key holder cannot apply (4.4 step
    /// 7); a chunk with a correct ciphertext hash whose length, seal,
    /// padding, compression or plaintext hash fails.
    WriterFault,
    /// The holder answered `CHUNK_BUSY`.
    ChunkBusy,
    /// The holder answered `CHUNK_NOT_FOUND`.
    ChunkNotFound,
    /// A record under this device's own device ID with a counter above its
    /// high-water mark (4.5, "Durability before transmission").
    OwnCounterAhead,
    /// A held record whose counter is more than `CLOCK_AHEAD_WARNING` ahead
    /// of this device's clock (4.4, "A fast clock carries forward").
    ClockAhead,
    /// This device's next counter would pass `MAX_COUNTER` (4.4).
    CounterExhausted,
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
    /// Ignore without verifying (a write holder that would note it as a stale
    /// copy or forgotten record verifies it first).
    Ignore,
    /// Verify; drop what it replaces; hold it unless something held replaces
    /// it.
    Replace,
    /// Hold the cleanup; the group applies while its `because` is held.
    HoldWaiting,
    /// Verify; neither hold nor relay it.
    Refuse,
    /// Answer one page with `reset` (and, for a `since` above the local
    /// sequence, draw a new epoch); the requester reconciles.
    AnswerReset,
    /// Answer `CHILDREN` or `RECORDS`; the requester descends.
    Descend,
    /// Stop counting the peer's pushes and owe a round.
    OweRound,
    /// Send no chunk request on the connection for `CHUNK_BUSY_BACKOFF`; ask
    /// other peers meanwhile.
    BackOff,
    /// Ask other peers for the chunk; the pass to this peer goes on.
    AskElsewhere,
    /// Hold and apply; raise the high-water mark to it; draw a new epoch.
    RaiseMark,
    /// Judge it as any record.
    Judge,
    /// Write nothing more in the folder; keep syncing what others write.
    StopWriting,
}

/// The three-way outcome of section 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// Close the connection with this reason.
    Close(CloseReason),
    /// Keep the connection; the item is handled as `Keep` says.
    Keep(Keep),
    /// Keep the connection; raise an issue naming the record (never a
    /// device), hold the record opaque or mark the chunk corrupt for that
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
    /// The clock-rule issue, which blames no device and offers the remedy:
    /// for a peer, naming its proven device ID and both readings; for a
    /// record, naming the device ID it claims as where it came from.
    ClockRuleIssue,
    /// An informational issue that blames no one.
    InformationalIssue,
    /// An issue about the folder itself (it must be shared again).
    FolderIssue,
    /// A log line naming the cause.
    Log,
}

impl Cause {
    /// Every row it names, in the order of section 5's table: all but the
    /// two rows about this device's own index store.
    pub const ALL: [Self; 30] = [
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
        Self::Duplicate,
        Self::Expired,
        Self::Obsolete,
        Self::ReplacesHeld,
        Self::CleanupGroupWaiting,
        Self::FromTheFuture,
        Self::ClockOutOfRange,
        Self::Reset,
        Self::DigestDiffers,
        Self::EmptyPush,
        Self::WriterFault,
        Self::ChunkBusy,
        Self::ChunkNotFound,
        Self::OwnCounterAhead,
        Self::ClockAhead,
        Self::CounterExhausted,
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
            Self::ClockOutOfRange => Outcome::Close(CloseReason::ClockOutOfRange),
            Self::UnknownNonCriticalType => Outcome::Keep(Keep::ReplyUnsupported),
            Self::FolderProofRejected => Outcome::Keep(Keep::ProofRejected),
            Self::Duplicate | Self::Expired | Self::Obsolete => Outcome::Keep(Keep::Ignore),
            Self::ReplacesHeld => Outcome::Keep(Keep::Replace),
            Self::CleanupGroupWaiting => Outcome::Keep(Keep::HoldWaiting),
            Self::FromTheFuture => Outcome::Keep(Keep::Refuse),
            Self::Reset => Outcome::Keep(Keep::AnswerReset),
            Self::DigestDiffers => Outcome::Keep(Keep::Descend),
            Self::EmptyPush => Outcome::Keep(Keep::OweRound),
            Self::ChunkBusy => Outcome::Keep(Keep::BackOff),
            Self::ChunkNotFound => Outcome::Keep(Keep::AskElsewhere),
            Self::OwnCounterAhead => Outcome::Keep(Keep::RaiseMark),
            Self::ClockAhead => Outcome::Keep(Keep::Judge),
            Self::CounterExhausted => Outcome::Keep(Keep::StopWriting),
            Self::WriterFault => Outcome::IssueAgainstRecord,
        }
    }

    /// What the outcome leaves behind. A close for the sender's fault raises
    /// an issue naming the peer (TM-10); a timeout, which an honest peer on a
    /// bad network can cause, and every difference in knowledge, a log line;
    /// a writer fault, an issue naming the record; the clock rule, its issue,
    /// which blames no device; a record under this device's own ID ahead of
    /// its mark and a fast clock, an informational issue naming no one; an
    /// exhausted counter, an issue about the folder.
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
            Self::FromTheFuture | Self::ClockOutOfRange => Report::ClockRuleIssue,
            Self::OwnCounterAhead | Self::ClockAhead => Report::InformationalIssue,
            Self::CounterExhausted => Report::FolderIssue,
            Self::HelloTimeout
            | Self::IdleTimeout
            | Self::ReplyPageTimeout
            | Self::ProofTimeout
            | Self::UnknownNonCriticalType
            | Self::FolderProofRejected
            | Self::Duplicate
            | Self::Expired
            | Self::Obsolete
            | Self::ReplacesHeld
            | Self::CleanupGroupWaiting
            | Self::Reset
            | Self::DigestDiffers
            | Self::EmptyPush
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
            (Cause::ClockOutOfRange, R::ClockOutOfRange),
        ];
        for (cause, reason) in closes {
            assert_eq!(cause.outcome(), Outcome::Close(reason), "{cause:?}");
            assert!(cause.closes());
        }
        let keeps = [
            (Cause::UnknownNonCriticalType, Keep::ReplyUnsupported),
            (Cause::FolderProofRejected, Keep::ProofRejected),
            (Cause::Duplicate, Keep::Ignore),
            (Cause::Expired, Keep::Ignore),
            (Cause::Obsolete, Keep::Ignore),
            (Cause::ReplacesHeld, Keep::Replace),
            (Cause::CleanupGroupWaiting, Keep::HoldWaiting),
            (Cause::FromTheFuture, Keep::Refuse),
            (Cause::Reset, Keep::AnswerReset),
            (Cause::DigestDiffers, Keep::Descend),
            (Cause::EmptyPush, Keep::OweRound),
            (Cause::ChunkBusy, Keep::BackOff),
            (Cause::ChunkNotFound, Keep::AskElsewhere),
            (Cause::OwnCounterAhead, Keep::RaiseMark),
            (Cause::ClockAhead, Keep::Judge),
            (Cause::CounterExhausted, Keep::StopWriting),
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
                Outcome::Close(CloseReason::ClockOutOfRange) => {
                    assert_eq!(report, Report::ClockRuleIssue);
                }
                Outcome::Close(_) => assert_eq!(report, Report::IssueNamingPeer, "{cause:?}"),
                Outcome::IssueAgainstRecord => assert_eq!(report, Report::IssueNamingRecord),
                Outcome::Keep(Keep::Refuse) => assert_eq!(report, Report::ClockRuleIssue),
                Outcome::Keep(Keep::RaiseMark | Keep::Judge) => {
                    assert_eq!(report, Report::InformationalIssue, "{cause:?}");
                }
                Outcome::Keep(Keep::StopWriting) => assert_eq!(report, Report::FolderIssue),
                Outcome::Keep(_) => assert_eq!(report, Report::Log, "{cause:?}"),
            }
        }
    }
}
