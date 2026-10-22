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
    /// A number this release does not define.
    Other(u32),
}

impl CloseReason {
    /// Every reason this release defines, in wire order.
    pub const ALL: [Self; 12] = [
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

/// The index record on the wire (4.4): the body of a `SignedRecord`. Fields
/// 4, 7, 9, 10 and 14 are reserved (`writer_key_id`, `previous`, the version
/// vector, `epoch`, `resumes`).
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
    /// 32 bytes: the writer's device ID, as the signer claims it; a sync key
    /// only, never shown as an author.
    #[prost(bytes = "vec", tag = "5")]
    pub device_id: Vec<u8>,
    /// Per `device_id`: 1, 2, 3 … up to `MAX_SEQ`; one device may have several
    /// records at one `seq` (concurrent versions).
    #[prost(uint64, tag = "6")]
    pub seq: u64,
    /// A set: the record hash of each version this record replaces; each 32
    /// bytes; at most 16; written sorted ascending without repeats.
    #[prost(bytes = "vec", repeated, tag = "8")]
    pub supersedes: Vec<Vec<u8>>,
    /// Tombstone: `chunks` is empty.
    #[prost(bool, tag = "11")]
    pub deleted: bool,
    /// In file order; at most 32 768; empty for directories, tombstones and
    /// empty files.
    #[prost(message, repeated, tag = "12")]
    pub chunks: Vec<ChunkRef>,
    /// `nonce (24) || XChaCha(rk, nonce, aad, padded SealedMeta)`; 40 to
    /// 1 572 864 bytes.
    #[prost(bytes = "vec", tag = "13")]
    pub sealed: Vec<u8>,
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
    /// UTF-8, NFC, `/` separated, relative, no empty, `.` or `..` component, no
    /// NUL, no backslash; at most 4 096 bytes.
    #[prost(string, tag = "1")]
    pub path: String,
    /// 1 file, 2 directory; others reserved.
    #[prost(uint32, tag = "2")]
    pub kind: u32,
    /// Bytes of plaintext content; 0 for an empty file.
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
    /// The writer's wall clock; informational only, never used for ordering.
    #[prost(uint64, tag = "7")]
    pub written_at: u64,
}

/// "I hold this writer's records through `seq`, and their digest there is
/// `digest`" (4.5). `seq = 0` with `digest` empty means "I hold none". Fields
/// 1, 4 and 5 are reserved (`key_id`, `fork`, `head_hash`).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Cursor {
    /// 32 bytes: the writer.
    #[prost(bytes = "vec", tag = "2")]
    pub device_id: Vec<u8>,
    /// The requester's cursor for the writer; at most `MAX_SEQ`.
    #[prost(uint64, tag = "3")]
    pub seq: u64,
    /// The requester's digest at `seq`: empty iff `seq = 0`, else 32 bytes.
    #[prost(bytes = "vec", tag = "6")]
    pub digest: Vec<u8>,
}

/// "Send what I lack", by range or list and cursor (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct IndexRequest {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// Ascending by `device_id`, each writer at most once, every entry inside
    /// the request's range; at most 16 384.
    #[prost(message, repeated, tag = "2")]
    pub have: Vec<Cursor>,
    /// Per reply page: 0, or above 4 096, means 4 096; below 64 means 64.
    #[prost(uint32, tag = "3")]
    pub max_records: u32,
    /// At least 1, chosen by the requester, unique among its requests
    /// outstanding on the connection; every page of the reply echoes it.
    #[prost(uint32, tag = "4")]
    pub request_id: u32,
    /// Empty, or 32: the range holds the device IDs strictly above this one.
    #[prost(bytes = "vec", tag = "5")]
    pub after: Vec<u8>,
    /// Empty, or 32: the range holds the device IDs up to and including this
    /// one; `after < through` when both are set.
    #[prost(bytes = "vec", tag = "6")]
    pub through: Vec<u8>,
    /// The request is for exactly the writers in `have`, which is then
    /// non-empty, with `after` and `through` empty.
    #[prost(bool, tag = "7")]
    pub listed: bool,
}

/// Signed index records, paged or pushed (4.5).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct IndexRecords {
    /// 32 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub folder_id: Vec<u8>,
    /// At most 4 096 encoded `SignedRecord`s (`keys.md` 5.1), per writer in
    /// canonical order. Each is carried as raw bytes and read only through
    /// the keys crate's `SignedRecord::from_bytes`, so that its envelope
    /// checks always run; the wire form is that of an embedded message.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub records: Vec<Vec<u8>>,
    /// Another page follows for the same request; never with `request_id = 0`.
    #[prost(bool, tag = "3")]
    pub more: bool,
    /// The request this page answers; 0 marks a push.
    #[prost(uint32, tag = "4")]
    pub request_id: u32,
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
    /// Index records held for the folder (the "index version").
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
            assert_eq!(r.as_u32(), u32::try_from(i).unwrap());
            assert_eq!(CloseReason::from_u32(r.as_u32()), *r);
            assert_ne!(r.name(), "UNKNOWN");
        }
        // 12 was FEATURE_REQUIRED in the drafts: reserved, reported as other.
        assert_eq!(CloseReason::from_u32(12), CloseReason::Other(12));
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
        // field 1 bytes(32) then field 4 varint 7: ascending, nothing for 2 and 3.
        assert_eq!(bytes.first(), Some(&0x0a));
        assert_eq!(&bytes[bytes.len() - 2..], &[0x20, 7]);
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
