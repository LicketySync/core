// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every message of `protocol.md` section 4, as prost-derived structs that
//! mirror the spec's `.proto` text field for field (numbers, types, names),
//! the three enums, and [`Message`], the typed union the connection routes.
//!
//! Encoding is prost's, which is the canonical proto3 encoding `keys.md`
//! section 5.2 requires: fields in ascending number order, each once, defaults
//! omitted, repeated scalars packed, minimal varints. Decoding of peer bytes
//! never uses prost: every message implements [`crate::parse::Parse`], a
//! bounded reader that checks each length, count and fixed size as it is read
//! (TM-2, TM-23). The `prost::Message::decode` these types also carry is not
//! called on peer bytes by any code path of this crate.
//!
//! Field numbers the drafts used and the spec marks `reserved` are absent
//! here, so they read as unknown fields: skipped, and inside a signed body
//! kept, since a body is forwarded exactly as received.

use crate::frame::{Frame, FrameError, MessageType};
use crate::parse::Parse;
use crate::wire::WireError;

/// Identity, capabilities and limits; the first frame of a connection (4.2).
/// Field 2 is reserved (it was `device_name`, which now travels in Status
/// once a folder is open).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Hello {
    /// `be16(suite) || Ed25519 public key`, canonical and not of small order;
    /// 34 bytes under suite 1.
    #[prost(bytes = "vec", tag = "1")]
    pub device_public_key: Vec<u8>,
    /// Implemented suites, preferred first; 1 to 16 entries, each 1 to 65 535,
    /// no duplicates; must share one with the peer.
    #[prost(uint32, repeated, tag = "3")]
    pub suites: Vec<u32>,
    /// Chunk compressions this device can decode: `none` always; at most 32,
    /// each `[a-z0-9-]{1,20}`.
    #[prost(string, repeated, tag = "4")]
    pub compressions: Vec<String>,
    /// `blake3` required in major 1; at most 32, each `[a-z0-9-]{1,20}`.
    #[prost(string, repeated, tag = "5")]
    pub hashes: Vec<String>,
    /// Optional feature names this device supports; at most 32.
    #[prost(string, repeated, tag = "6")]
    pub features: Vec<String>,
    /// Frames this device accepts, bytes; `MIN_MESSAGE_SIZE ..= MAX_MESSAGE_SIZE`.
    #[prost(uint32, tag = "7")]
    pub max_message_size: u32,
    /// Chunk requests this device will hold open per connection; at least 1.
    #[prost(uint32, tag = "8")]
    pub max_requests_in_flight: u32,
    /// 32 random bytes; makes the transcript unique to this connection.
    #[prost(bytes = "vec", tag = "9")]
    pub nonce: Vec<u8>,
    /// 32 bytes: the Ed25519 public key of the libp2p identity (`keys.md` 8.1).
    #[prost(bytes = "vec", tag = "10")]
    pub libp2p_identity: Vec<u8>,
    /// The sender's wall clock in whole days since the Unix epoch, 0 to
    /// `MAX_CLOCK_DAYS` (0 for a clock before 1970); for the clock rule (3.2,
    /// 4.4). Whole days, so that the Hello gives no finer clock reading to
    /// anyone who connects.
    #[prost(uint32, tag = "11")]
    pub clock_days: u32,
}

/// Why a side is closing; the last frame (4.2).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Close {
    /// A [`CloseReason`] number.
    #[prost(uint32, tag = "1")]
    pub reason: u32,
    /// At most 256 bytes, optional; UTF-8 with no control characters; text
    /// only; never a folder ID, record hash, path or name.
    #[prost(string, tag = "2")]
    pub detail: String,
}

/// The `CloseReason` enum of 4.2. Numbers this release does not define are
/// kept as [`CloseReason::Other`] so that a newer peer's reason is reported,
/// not refused; 12 was the drafts' `FEATURE_REQUIRED` and reads as `Other(12)`.
/// [`CloseReason::ALL`] lists every defined reason in wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// 0: no reason given.
    Unspecified,
    /// 1: orderly: the device is stopping or the folder was paused.
    Shutdown,
    /// 2: a frame or body could not be parsed, broke a bound, or arrived out of order.
    ProtocolError,
    /// 3: a frame exceeded the limit; nothing was allocated.
    MessageTooLarge,
    /// 4: a critical type this peer does not know.
    UnsupportedCriticalType,
    /// 5: the Hellos share no suite.
    NoCommonSuite,
    /// 6: `max_message_size` below the floor.
    LimitTooSmall,
    /// 7: the `DeviceProof` did not verify.
    ProofRejected,
    /// 8: nothing opened within `PROOF_TIMEOUT`.
    NoCommonFolder,
    /// 9: this peer forwarded a record whose signature fails or a chunk whose
    /// ciphertext hash fails.
    VerificationFailed,
    /// 10: this device's connection limit is reached (phase 1).
    TooManyConnections,
    /// 11: `HELLO_TIMEOUT`, `IDLE_TIMEOUT` or `REPLY_PAGE_TIMEOUT` elapsed, or
    /// no unsent byte was delivered for `IDLE_TIMEOUT`.
    Timeout,
    /// 13: the clock rule (3.2, 4.4): the two Hellos' `clock_days` differ by
    /// more than `CLOCK_RULE_LIMIT`; sent only when the first folder opens on
    /// the connection.
    ClockOutOfRange,
    /// A number this release does not define.
    Other(u32),
}

impl CloseReason {
    /// Every reason this release defines, in wire order.
    pub const ALL: [Self; 13] = [
        Self::Unspecified,
        Self::Shutdown,
        Self::ProtocolError,
        Self::MessageTooLarge,
        Self::UnsupportedCriticalType,
        Self::NoCommonSuite,
        Self::LimitTooSmall,
        Self::ProofRejected,
        Self::NoCommonFolder,
        Self::VerificationFailed,
        Self::TooManyConnections,
        Self::Timeout,
        Self::ClockOutOfRange,
    ];

    /// The reason for a wire number.
    #[must_use]
    pub const fn from_u32(n: u32) -> Self {
        match n {
            0 => Self::Unspecified,
            1 => Self::Shutdown,
            2 => Self::ProtocolError,
            3 => Self::MessageTooLarge,
            4 => Self::UnsupportedCriticalType,
            5 => Self::NoCommonSuite,
            6 => Self::LimitTooSmall,
            7 => Self::ProofRejected,
            8 => Self::NoCommonFolder,
            9 => Self::VerificationFailed,
            10 => Self::TooManyConnections,
            11 => Self::Timeout,
            13 => Self::ClockOutOfRange,
            other => Self::Other(other),
        }
    }

    /// The wire number.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Unspecified => 0,
            Self::Shutdown => 1,
            Self::ProtocolError => 2,
            Self::MessageTooLarge => 3,
            Self::UnsupportedCriticalType => 4,
            Self::NoCommonSuite => 5,
            Self::LimitTooSmall => 6,
            Self::ProofRejected => 7,
            Self::NoCommonFolder => 8,
            Self::VerificationFailed => 9,
            Self::TooManyConnections => 10,
            Self::Timeout => 11,
            Self::ClockOutOfRange => 13,
            Self::Other(n) => n,
        }
    }

    /// The spec's name, for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "CLOSE_UNSPECIFIED",
            Self::Shutdown => "SHUTDOWN",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::MessageTooLarge => "MESSAGE_TOO_LARGE",
            Self::UnsupportedCriticalType => "UNSUPPORTED_CRITICAL_TYPE",
            Self::NoCommonSuite => "NO_COMMON_SUITE",
            Self::LimitTooSmall => "LIMIT_TOO_SMALL",
            Self::ProofRejected => "PROOF_REJECTED",
            Self::NoCommonFolder => "NO_COMMON_FOLDER",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::TooManyConnections => "TOO_MANY_CONNECTIONS",
            Self::Timeout => "TIMEOUT",
            Self::ClockOutOfRange => "CLOCK_OUT_OF_RANGE",
            Self::Other(_) => "UNKNOWN",
        }
    }
}

/// "I do not know that non-critical type" (4.2).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Unsupported {
    /// The full 16-bit type that was not understood.
    #[prost(uint32, tag = "1")]
    pub message_type: u32,
}

/// The device key's signature over the transcript (4.3).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct DeviceProof {
    /// `Sign(device key, "licketysync/v1/sig/device-proof", th || role)`; 64 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub signature: Vec<u8>,
}

/// A sealed proof of holding a key to one folder (4.3).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct FolderProof {
    /// 32 bytes (3.5); never repeated on a connection.
    #[prost(bytes = "vec", tag = "1")]
    pub hint: Vec<u8>,
    /// `XChaCha(proof_key, nonce, aad = hint, ProofPayload)`; 16 to 1 024 bytes.
    #[prost(bytes = "vec", tag = "2")]
    pub sealed: Vec<u8>,
    /// 24 random bytes, fresh for every `FolderProof`.
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: Vec<u8>,
}

/// What a `FolderProof` seals (4.3). Fields 1 to 3 are reserved (they were
/// `key_id`, the tier's proof and the grant chain).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ProofPayload {
    /// The tier the prover reports, for display only: 1 write, 2 read, 3
    /// sealed; any other value is REJECTED.
    #[prost(uint32, tag = "4")]
    pub tier: u32,
}

/// The answer to one `FolderProof` (4.3). Fields 3 and 4 are reserved (they
/// were `missing_features` and `evidence`).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ProofResult {
    /// Echoes the `FolderProof`'s hint.
    #[prost(bytes = "vec", tag = "1")]
    pub hint: Vec<u8>,
    /// A [`ProofStatus`] number.
    #[prost(uint32, tag = "2")]
    pub status: u32,
}

/// The `ProofStatus` enum of 4.3. Any other number is `Close(PROTOCOL_ERROR)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProofStatus {
    /// 1: the proof opened the folder here.
    Accepted,
    /// 2: the uniform refusal.
    Rejected,
}

impl ProofStatus {
    /// The status for a wire number, or `None` for any other.
    #[must_use]
    pub const fn from_u32(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::Accepted),
            2 => Some(Self::Rejected),
            _ => None,
        }
    }

    /// The wire number.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Accepted => 1,
            Self::Rejected => 2,
        }
    }
}

/// The index record on the wire (4.4): the body of a `SignedRecord` of record
/// type 16 (a cleanup, type 17, is [`CleanupRecord`]). Fields 4, 7, 8, 10 and
/// 14 are reserved (`writer_key_id`, `previous`, `supersedes`, `epoch`,
/// `resumes`), and so are 5, 6, 9, 11 and 16 (`device_id`, `counter`,
/// `vector`, `deleted` and `tree` in the clear, inside the seal since
/// 2026-10-25).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct IndexRecord {
    /// The folder's suite.
    #[prost(uint32, tag = "1")]
    pub suite: u32,
    /// 16.
    #[prost(uint32, tag = "2")]
    pub record_type: u32,
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "3")]
    pub folder_id: Vec<u8>,
    /// In file order; at most 32 768; empty for directories, tombstones, tree
    /// deletes and empty files.
    #[prost(message, repeated, tag = "12")]
    pub chunks: Vec<ChunkRef>,
    /// `nonce (24) || XChaCha(rk, nonce, aad, padded SealedMeta)` under `aad =
    /// folder_id || path_tag`; 40 bytes plus a power of two from 256 to 2^21.
    #[prost(bytes = "vec", tag = "13")]
    pub sealed: Vec<u8>,
    /// 32 bytes: the file ID, `BLAKE3_keyed(tk, path)` (`keys.md` 3.5).
    #[prost(bytes = "vec", tag = "15")]
    pub path_tag: Vec<u8>,
    /// 32 bytes each: the record hashes of the versions this record replaces;
    /// at most `MAX_REPLACES` (64), ascending, no repeats.
    #[prost(bytes = "vec", repeated, tag = "17")]
    pub replaces: Vec<Vec<u8>>,
}

/// One chunk of a file (4.4). Field 3 is reserved (it was `epoch`).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ChunkRef {
    /// 32 bytes: `H("licketysync/v1/hash/chunk", stored)`.
    #[prost(bytes = "vec", tag = "1")]
    pub cipher_hash: Vec<u8>,
    /// Bytes of the stored blob: 46 to 4 325 416, and a Padmé length plus 40.
    #[prost(uint32, tag = "2")]
    pub stored_len: u32,
}

/// Inside `IndexRecord.sealed`, visible to write and read holders only (4.4).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct SealedMeta {
    /// UTF-8, `/` separated, relative, no empty, `.` or `..` component, no
    /// NUL, no backslash; at most 4 096 bytes; NFC by the writer's duty; for a
    /// tree delete, the deleted directory.
    #[prost(string, tag = "1")]
    pub path: String,
    /// 1 file, 2 directory; others reserved.
    #[prost(uint32, tag = "2")]
    pub kind: u32,
    /// Bytes of plaintext content; 0 for an empty file, which has no chunks.
    #[prost(uint64, tag = "3")]
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    #[prost(int64, tag = "4")]
    pub mtime_ns: i64,
    /// Unix permission bits; 0 when the writer has none.
    #[prost(uint32, tag = "5")]
    pub mode: u32,
    /// Keyed BLAKE3 per chunk, same order and count as `chunks`.
    #[prost(bytes = "vec", repeated, tag = "6")]
    pub plain_hashes: Vec<Vec<u8>>,
    /// The writer's wall clock in microseconds since the Unix epoch, the unit
    /// of `clock_us` (0 for a clock before 1970); informational only, never
    /// used for ordering.
    #[prost(uint64, tag = "7")]
    pub written_at: u64,
    /// 32 bytes: the writer's device ID, as the signer claims it; with
    /// `counter`, the record's dot; never shown as an author.
    #[prost(bytes = "vec", tag = "8")]
    pub device_id: Vec<u8>,
    /// The writer's counter: 1 to `MAX_COUNTER`.
    #[prost(uint64, tag = "9")]
    pub counter: u64,
    /// The version vector: at most `MAX_VECTOR_ENTRIES` entries, ascending by
    /// `device_id`, no device twice, every counter below `counter`.
    #[prost(message, repeated, tag = "10")]
    pub vector: Vec<VectorEntry>,
    /// A tombstone, or with `tree` a tree delete; the record then has no chunks.
    #[prost(bool, tag = "11")]
    pub deleted: bool,
    /// A tree delete of the path and of everything beneath it; requires
    /// `deleted`, `kind` 2 and `size` 0.
    #[prost(bool, tag = "12")]
    pub tree: bool,
}

/// One entry of a version vector (4.4).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct VectorEntry {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// 1 to `MAX_COUNTER`.
    #[prost(uint64, tag = "2")]
    pub counter: u64,
}

/// A cleanup (4.4, "Cleanup"): the body of a `SignedRecord`, record type 17,
/// by which a write holder tells every peer to forget exact fingerprints.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct CleanupRecord {
    /// The folder's suite.
    #[prost(uint32, tag = "1")]
    pub suite: u32,
    /// 17.
    #[prost(uint32, tag = "2")]
    pub record_type: u32,
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "3")]
    pub folder_id: Vec<u8>,
    /// 1 to `MAX_CLEANUP_GROUPS` (1 024).
    #[prost(message, repeated, tag = "4")]
    pub groups: Vec<CleanupGroup>,
    /// `nonce (24) || XChaCha(rk, nonce, aad = folder_id, padded CleanupMeta)`;
    /// 40 bytes plus 256, 512 or 1 024.
    #[prost(bytes = "vec", tag = "5")]
    pub sealed: Vec<u8>,
}

/// One group of a cleanup (4.4).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct CleanupGroup {
    /// Empty, or 32: the fingerprint of the record that replaces those named.
    #[prost(bytes = "vec", tag = "1")]
    pub because: Vec<u8>,
    /// 32 each: the fingerprints of the records to forget; 1 to
    /// `MAX_CLEANUP_ENTRIES` across the record's groups; ascending within a
    /// group, no repeats.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub forget: Vec<Vec<u8>>,
}

/// Inside a cleanup's `sealed`, visible to write and read holders only (4.4).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct CleanupMeta {
    /// 32: the issuer's device ID, as the signer claims it.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// The issuer's counter, by the writer's rule.
    #[prost(uint64, tag = "2")]
    pub counter: u64,
}

/// "Send what you came to hold since" (4.5). Fields 2, 5, 6 and 7 are reserved
/// (the drafts' cursors and ranges).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct IndexRequest {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// Per reply page: 0, or above 4 096, means 4 096; below 64 means 64.
    #[prost(uint32, tag = "3")]
    pub max_records: u32,
    /// At least 1, chosen by the requester, unique among its requests
    /// outstanding on the connection (`IndexRequest` and `ReconcileRequest`
    /// alike); every page of the reply echoes it.
    #[prost(uint32, tag = "4")]
    pub request_id: u32,
    /// The responder's index epoch the requester's cursor belongs to; never 0.
    #[prost(fixed64, tag = "8")]
    pub epoch: u64,
    /// The requester's cursor: the responder's local sequence through which it
    /// holds what the responder held; at most `MAX_LOCAL_SEQ`.
    #[prost(uint64, tag = "9")]
    pub since: u64,
}

/// Signed index records, paged or pushed (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct IndexRecords {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// At most 4 096 encoded `SignedRecord`s (`keys.md` 5.1). Each is carried
    /// as raw bytes and read only through the keys crate's
    /// `SignedRecord::from_bytes`, so that its envelope checks always run; the
    /// wire form is that of an embedded message.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub records: Vec<Vec<u8>>,
    /// Another page of the same reply follows; never on a push, nor on a page
    /// without records.
    #[prost(bool, tag = "3")]
    pub more: bool,
    /// The request this page answers; 0 marks a push.
    #[prost(uint32, tag = "4")]
    pub request_id: u32,
    /// The sender's index epoch; never 0.
    #[prost(fixed64, tag = "5")]
    pub epoch: u64,
    /// A local sequence of the sender's that the receiver may count through,
    /// or 0; at most `MAX_LOCAL_SEQ`.
    #[prost(uint64, tag = "6")]
    pub through: u64,
    /// A reply to an `IndexRequest` whose epoch is not the sender's, or whose
    /// `since` is above the sender's local sequence: one page with no records,
    /// `more` and `through` not set.
    #[prost(bool, tag = "7")]
    pub reset: bool,
}

/// "Here is my digest of this subtree" (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ReconcileRequest {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// As in `IndexRequest`.
    #[prost(uint32, tag = "2")]
    pub request_id: u32,
    /// 0 to 128 bytes, each 0 to 15: the leading nibbles of a record's key
    /// (4.5, "Set digests"), high nibble first, naming a subtree; empty: the
    /// root.
    #[prost(bytes = "vec", tag = "3")]
    pub prefix: Vec<u8>,
    /// 32: the requester's digest of that subtree.
    #[prost(bytes = "vec", tag = "4")]
    pub digest: Vec<u8>,
}

/// Equal, the subtree's 16 child digests, or its records (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ReconcileReply {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// The request answered.
    #[prost(uint32, tag = "2")]
    pub request_id: u32,
    /// A [`ReconcileOutcome`] number.
    #[prost(uint32, tag = "3")]
    pub outcome: u32,
    /// `CHILDREN` only, and then exactly 16 digests of 32 bytes: the subtrees
    /// at the prefix followed by 0, 1 … 15.
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub children: Vec<Vec<u8>>,
    /// The responder's index epoch; never 0.
    #[prost(fixed64, tag = "5")]
    pub epoch: u64,
    /// For the root: the responder's local sequence when it answered; for any
    /// other prefix, not set.
    #[prost(uint64, tag = "6")]
    pub through: u64,
}

/// The `ReconcileOutcome` enum of 4.5. Any other number is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReconcileOutcome {
    /// 1: the digests are equal.
    Equal,
    /// 2: the 16 child digests follow.
    Children,
    /// 3: the subtree's records follow, as `IndexRecords` pages.
    Records,
}

impl ReconcileOutcome {
    /// The outcome for a wire number, or `None` for any other.
    #[must_use]
    pub const fn from_u32(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::Equal),
            2 => Some(Self::Children),
            3 => Some(Self::Records),
            _ => None,
        }
    }

    /// The wire number.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Equal => 1,
            Self::Children => 2,
            Self::Records => 3,
        }
    }
}

/// Progress per open folder; periodic, non-critical (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Status {
    /// Open folders only; at most 1 024.
    #[prost(message, repeated, tag = "1")]
    pub folders: Vec<FolderStatus>,
    /// The sender's self-reported device name: at most 64 bytes of UTF-8, no
    /// control characters; set in the first Status after the first folder
    /// opens on the connection, and again when it changes.
    #[prost(string, tag = "2")]
    pub device_name: String,
}

/// One open folder's progress (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct FolderStatus {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// Index records held for the folder (the "index version"): live records,
    /// tree deletes and cleanups.
    #[prost(uint64, tag = "2")]
    pub index_records: u64,
    /// Ciphertext bytes still to fetch.
    #[prost(uint64, tag = "3")]
    pub bytes_needed: u64,
    /// Whether the folder is paused here.
    #[prost(bool, tag = "4")]
    pub paused: bool,
    /// Free disk bytes.
    #[prost(uint64, tag = "5")]
    pub free_disk_bytes: u64,
    /// The chunks this device has stored for the folder since the folder
    /// opened on this connection: 0 in the first Status, one more with each
    /// chunk stored, never falling.
    #[prost(uint64, tag = "6")]
    pub chunks_stored: u64,
    /// Records held beyond one per file ID: at a sealed peer its stale copies
    /// and the folder's real conflicts together, which it cannot tell apart;
    /// at a read or write holder the extra heads of its conflicts.
    #[prost(uint64, tag = "7")]
    pub extra_versions: u64,
}

/// One chunk by ciphertext hash (4.6).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ChunkRequest {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// 32 bytes; absent or any other size is malformed.
    #[prost(bytes = "vec", tag = "2")]
    pub cipher_hash: Vec<u8>,
}

/// The chunk, or why not (4.6).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ChunkReply {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// 32 bytes, as requested.
    #[prost(bytes = "vec", tag = "2")]
    pub cipher_hash: Vec<u8>,
    /// A [`ChunkStatus`] number.
    #[prost(uint32, tag = "3")]
    pub status: u32,
    /// The stored blob (`nonce || ciphertext`), present iff `status =
    /// CHUNK_OK`; at most 4 325 416 bytes.
    #[prost(bytes = "vec", tag = "4")]
    pub data: Vec<u8>,
}

/// The `ChunkStatus` enum of 4.6. Any other number is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChunkStatus {
    /// 1: the chunk follows.
    Ok,
    /// 2: the holder does not hold the chunk for the folder.
    NotFound,
    /// 3: the holder's send queue was at least half full; back off.
    Busy,
}

impl ChunkStatus {
    /// The status for a wire number, or `None` for 0 and unknown numbers.
    #[must_use]
    pub const fn from_u32(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::Ok),
            2 => Some(Self::NotFound),
            3 => Some(Self::Busy),
            _ => None,
        }
    }

    /// The wire number.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 1,
            Self::NotFound => 2,
            Self::Busy => 3,
        }
    }
}

/// One decoded message of any type, as the connection routes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// 0x8001.
    Hello(Box<Hello>),
    /// 0x8002.
    Close(Close),
    /// 0x8003.
    DeviceProof(DeviceProof),
    /// 0x8004.
    FolderProof(FolderProof),
    /// 0x8005.
    ProofResult(ProofResult),
    /// 0x8007.
    IndexRequest(IndexRequest),
    /// 0x8008.
    IndexRecords(IndexRecords),
    /// 0x8009.
    ChunkRequest(ChunkRequest),
    /// 0x800A.
    ChunkReply(ChunkReply),
    /// 0x800B.
    ReconcileRequest(ReconcileRequest),
    /// 0x800C.
    ReconcileReply(ReconcileReply),
    /// 0x0001.
    Status(Status),
    /// 0x0002.
    Unsupported(Unsupported),
}

impl Message {
    /// The type number this message travels under.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Hello(_) => MessageType::Hello,
            Self::Close(_) => MessageType::Close,
            Self::DeviceProof(_) => MessageType::DeviceProof,
            Self::FolderProof(_) => MessageType::FolderProof,
            Self::ProofResult(_) => MessageType::ProofResult,
            Self::IndexRequest(_) => MessageType::IndexRequest,
            Self::IndexRecords(_) => MessageType::IndexRecords,
            Self::ChunkRequest(_) => MessageType::ChunkRequest,
            Self::ChunkReply(_) => MessageType::ChunkReply,
            Self::ReconcileRequest(_) => MessageType::ReconcileRequest,
            Self::ReconcileReply(_) => MessageType::ReconcileReply,
            Self::Status(_) => MessageType::Status,
            Self::Unsupported(_) => MessageType::Unsupported,
        }
    }

    /// The canonical body bytes (`keys.md` 5.2).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        use prost::Message as _;
        match self {
            Self::Hello(m) => m.encode_to_vec(),
            Self::Close(m) => m.encode_to_vec(),
            Self::DeviceProof(m) => m.encode_to_vec(),
            Self::FolderProof(m) => m.encode_to_vec(),
            Self::ProofResult(m) => m.encode_to_vec(),
            Self::IndexRequest(m) => m.encode_to_vec(),
            Self::IndexRecords(m) => m.encode_to_vec(),
            Self::ChunkRequest(m) => m.encode_to_vec(),
            Self::ChunkReply(m) => m.encode_to_vec(),
            Self::ReconcileRequest(m) => m.encode_to_vec(),
            Self::ReconcileReply(m) => m.encode_to_vec(),
            Self::Status(m) => m.encode_to_vec(),
            Self::Unsupported(m) => m.encode_to_vec(),
        }
    }

    /// The frame carrying this message.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] when the body would not fit any frame.
    pub fn to_frame(&self) -> Result<Frame, FrameError> {
        Frame::new(self.message_type().as_u16(), self.encode_body())
    }

    /// Parses a body of the given type under every bound of section 4.
    ///
    /// # Errors
    /// Any [`WireError`]: the body is malformed and the sender is to blame.
    pub fn parse(message_type: MessageType, body: &[u8]) -> Result<Self, WireError> {
        Ok(match message_type {
            MessageType::Hello => Self::Hello(Box::new(Hello::parse(body)?)),
            MessageType::Close => Self::Close(Close::parse(body)?),
            MessageType::DeviceProof => Self::DeviceProof(DeviceProof::parse(body)?),
            MessageType::FolderProof => Self::FolderProof(FolderProof::parse(body)?),
            MessageType::ProofResult => Self::ProofResult(ProofResult::parse(body)?),
            MessageType::IndexRequest => Self::IndexRequest(IndexRequest::parse(body)?),
            MessageType::IndexRecords => Self::IndexRecords(IndexRecords::parse(body)?),
            MessageType::ChunkRequest => Self::ChunkRequest(ChunkRequest::parse(body)?),
            MessageType::ChunkReply => Self::ChunkReply(ChunkReply::parse(body)?),
            MessageType::ReconcileRequest => Self::ReconcileRequest(ReconcileRequest::parse(body)?),
            MessageType::ReconcileReply => Self::ReconcileReply(ReconcileReply::parse(body)?),
            MessageType::Status => Self::Status(Status::parse(body)?),
            MessageType::Unsupported => Self::Unsupported(Unsupported::parse(body)?),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use prost::Message as _;

    use super::*;

    #[test]
    fn close_reasons_round_trip_their_numbers() {
        for (i, r) in CloseReason::ALL.iter().enumerate() {
            // 12 is reserved, so the defined reasons skip it.
            let n = u32::try_from(i).unwrap();
            assert_eq!(r.as_u32(), if n >= 12 { n + 1 } else { n });
            assert_eq!(CloseReason::from_u32(r.as_u32()), *r);
            assert_ne!(r.name(), "UNKNOWN");
        }
        // 12 was FEATURE_REQUIRED in the drafts: reserved, reported as other.
        assert_eq!(CloseReason::from_u32(12), CloseReason::Other(12));
        assert_eq!(CloseReason::ClockOutOfRange.as_u32(), 13);
        assert_eq!(CloseReason::from_u32(13), CloseReason::ClockOutOfRange);
        assert_eq!(CloseReason::ClockOutOfRange.name(), "CLOCK_OUT_OF_RANGE");
        assert_eq!(CloseReason::Other(99).as_u32(), 99);
        assert_eq!(CloseReason::Other(99).name(), "UNKNOWN");
        assert_eq!(CloseReason::ProtocolError.name(), "PROTOCOL_ERROR");
    }

    #[test]
    fn proof_and_chunk_status_numbers() {
        for n in [0, 3, 4] {
            assert_eq!(ProofStatus::from_u32(n), None);
        }
        for s in [ProofStatus::Accepted, ProofStatus::Rejected] {
            assert_eq!(ProofStatus::from_u32(s.as_u32()), Some(s));
        }
        assert_eq!(ChunkStatus::from_u32(0), None);
        assert_eq!(ChunkStatus::from_u32(4), None);
        for s in [ChunkStatus::Ok, ChunkStatus::NotFound, ChunkStatus::Busy] {
            assert_eq!(ChunkStatus::from_u32(s.as_u32()), Some(s));
        }
        for n in [0, 4] {
            assert_eq!(ReconcileOutcome::from_u32(n), None);
        }
        for o in [
            ReconcileOutcome::Equal,
            ReconcileOutcome::Children,
            ReconcileOutcome::Records,
        ] {
            assert_eq!(ReconcileOutcome::from_u32(o.as_u32()), Some(o));
        }
    }

    #[test]
    fn canonical_encoding_omits_defaults_and_orders_fields() {
        assert!(
            Hello::default().encode_to_vec().is_empty(),
            "defaults are omitted"
        );
        let m = IndexRequest {
            folder_id: vec![1; 32],
            request_id: 7,
            ..IndexRequest::default()
        };
        let bytes = m.encode_to_vec();
        // field 1 bytes(32) then field 4 varint 7: ascending, nothing for 3.
        assert_eq!(bytes.first(), Some(&0x0a));
        assert_eq!(&bytes[bytes.len() - 2..], &[0x20, 7]);
        // The epoch is a fixed64: tag 0x41, then eight little-endian bytes.
        let with_epoch = IndexRequest {
            epoch: 0x0102_0304_0506_0708,
            ..IndexRequest::default()
        }
        .encode_to_vec();
        assert_eq!(with_epoch, vec![0x41, 8, 7, 6, 5, 4, 3, 2, 1]);
        let packed = Hello {
            suites: vec![1, 2],
            ..Hello::default()
        }
        .encode_to_vec();
        assert_eq!(packed, vec![0x1a, 2, 1, 2], "repeated scalars are packed");
        // The proof payload's one field is number 4: `2001` for write.
        assert_eq!(ProofPayload { tier: 1 }.encode_to_vec(), vec![0x20, 1]);
    }

    #[test]
    fn the_union_knows_its_types_and_round_trips() {
        let messages = [
            Message::Hello(Box::default()),
            Message::Close(Close::default()),
            Message::DeviceProof(DeviceProof::default()),
            Message::FolderProof(FolderProof::default()),
            Message::ProofResult(ProofResult::default()),
            Message::IndexRequest(IndexRequest::default()),
            Message::IndexRecords(IndexRecords::default()),
            Message::ChunkRequest(ChunkRequest::default()),
            Message::ChunkReply(ChunkReply::default()),
            Message::ReconcileRequest(ReconcileRequest::default()),
            Message::ReconcileReply(ReconcileReply::default()),
            Message::Status(Status::default()),
            Message::Unsupported(Unsupported::default()),
        ];
        for (m, t) in messages.iter().zip(MessageType::ALL) {
            assert_eq!(m.message_type(), t);
            assert_eq!(m.to_frame().unwrap().type_number(), t.as_u16());
        }
        let m = Message::ChunkRequest(ChunkRequest {
            folder_id: vec![5; 32],
            cipher_hash: vec![6; 32],
        });
        let frame = m.to_frame().unwrap();
        assert_eq!(frame.type_number(), 0x8009);
        assert_eq!(
            Message::parse(MessageType::ChunkRequest, frame.body()).unwrap(),
            m
        );
    }
}
