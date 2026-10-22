// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every size, count and interval `protocol.md` fixes, in one place. Every
//! peer-controlled length or count is checked against one of these before the
//! bytes behind it are allocated (TM-2), and every per-connection table is
//! bounded by one of them (`protocol.md` section 5, "Limits are per
//! connection"; TM-22). None grows with the number of writers in a folder
//! (ruling R-K4). The intervals are the spec's; the simulator may scale them,
//! both sides alike, through [`crate::connection::Timing`].

use core::time::Duration;

// Section 2: frames.

/// The limit on every frame received before the peer's `DeviceProof` has
/// verified (its Hello, its `DeviceProof` or a Close), and on anything sent
/// before the peer's Hello has arrived.
pub const PRE_HELLO_LIMIT: u32 = 65_536;
/// The smallest `max_message_size` a Hello may advertise; smaller is
/// `Close(LIMIT_TOO_SMALL)`.
pub const MIN_MESSAGE_SIZE: u32 = 8_388_608;
/// What a device advertises unless configured otherwise.
pub const DEFAULT_MESSAGE_SIZE: u32 = 16_777_216;
/// The largest value a Hello may advertise; larger is treated as this value.
pub const MAX_MESSAGE_SIZE: u32 = 67_108_864;
/// The largest Protocol Buffers field number any decoder accepts, 2^29 − 1:
/// a larger one is malformed, so that every implementation judges a signed
/// body alike (`protocol.md` section 2).
pub const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
/// `MAX_INDEX_RECORD_BYTES`: the largest encoded `SignedRecord`; a larger one
/// is malformed at parse, before any duplicate check (the keys crate's bound).
pub const MAX_INDEX_RECORD_BYTES: usize = licketysync_keys::records::MAX_INDEX_RECORD_BYTES;

// Section 3: transport and handshake.

/// `MAX_SEND_QUEUE`: the unsent bytes a connection may hold. A side hands its
/// next frame (any but Close) to the transport only while the unsent bytes
/// plus that frame stay below it, a push that does not fit is dropped, and a
/// chunk request dispatched with half of it unsent is answered `CHUNK_BUSY`
/// (`protocol.md` 3.1, 4.6).
pub const MAX_SEND_QUEUE: usize = 128 << 20;
/// `MAX_PROOFS_PER_CONNECTION`: `FolderProof`s a verifier accepts on one
/// connection; one more is `Close(PROTOCOL_ERROR)` (3.5 step 1).
pub const MAX_PROOFS_PER_CONNECTION: usize = 256;
/// `MAX_OPEN_FOLDERS_PER_CONNECTION`: a proof that would open one more folder
/// on the connection is answered REJECTED (3.5 step 6).
pub const MAX_OPEN_FOLDERS_PER_CONNECTION: usize = 64;

// Section 4.2: Hello, Close, Unsupported.

/// `Hello.suites`: 1 to this many entries.
pub const MAX_SUITES: usize = 16;
/// `Hello.compressions` and `Hello.hashes`: at most this many entries each.
pub const MAX_LIST_ENTRIES: usize = 32;
/// A `compressions` or `hashes` entry: `[a-z0-9-]{1,20}`, so that
/// `compression:<c>` and `hash:<h>` fit the feature grammar.
pub const MAX_LIST_ENTRY_BYTES: usize = 20;
/// `Hello.features`: at most this many entries.
pub const MAX_FEATURES: usize = 32;
/// A feature name (section 5): `[a-z0-9:-]{1,32}`.
pub const MAX_FEATURE_NAME_BYTES: usize = 32;
/// `Hello.nonce`: exactly this many bytes.
pub const HELLO_NONCE_LEN: usize = 32;
/// `Hello.libp2p_identity`: exactly this many bytes, an Ed25519 public key.
pub const LIBP2P_IDENTITY_LEN: usize = 32;
/// `Close.detail`: at most this many bytes.
pub const MAX_CLOSE_DETAIL_BYTES: usize = 256;

// Section 4.3: proofs.

/// `DeviceProof.signature`: exactly this many bytes (Ed25519).
pub const DEVICE_SIGNATURE_LEN: usize = 64;
/// `FolderProof.hint` and `ProofResult.hint`: exactly this many bytes.
pub const HINT_LEN: usize = 32;
/// `FolderProof.nonce`: exactly this many bytes.
pub const PROOF_NONCE_LEN: usize = 24;
/// `FolderProof.sealed`: at least the AEAD tag.
pub const MIN_PROOF_SEALED: usize = 16;
/// `FolderProof.sealed`: at most this many bytes (a full payload seals to 18).
pub const MAX_PROOF_SEALED: usize = 1_024;

// Section 4.4: the index record.

/// The `record_type` of an index record.
pub const INDEX_RECORD_TYPE: u32 = licketysync_keys::records::INDEX_RECORD_TYPE;
/// `MAX_SUPERSEDES`: entries in a record's `supersedes`.
pub const MAX_SUPERSEDES: usize = 16;
/// `MAX_SEQ`: the largest `seq` of a record or cursor, 2^62, so that no
/// arithmetic on sequence numbers can overflow.
pub const MAX_SEQ: u64 = 1 << 62;
/// `IndexRecord.chunks` and `SealedMeta.plain_hashes`: at most this many.
pub const MAX_CHUNKS: usize = 32_768;
/// `IndexRecord.sealed`: at least its nonce and tag.
pub const MIN_SEALED_BYTES: usize = licketysync_keys::sealed_meta::MIN_SEALED_BYTES;
/// `MAX_SEALED_BYTES`: `IndexRecord.sealed` at most, 1.5 MiB.
pub const MAX_SEALED_BYTES: usize = licketysync_keys::sealed_meta::MAX_SEALED_BYTES;
/// `SealedMeta.path`: at most this many bytes.
pub const MAX_PATH_BYTES: usize = 4_096;
/// `MAX_CHUNK_PLAINTEXT`: the largest raw chunk, 4 MiB.
pub const MAX_CHUNK_PLAINTEXT: usize = licketysync_keys::chunk::MAX_CHUNK_PLAINTEXT;
/// `ChunkRef.stored_len` at least: one byte of payload, padded, plus nonce and tag.
pub const MIN_STORED_LEN: usize = licketysync_keys::chunk::MIN_STORED_LEN;
/// `ChunkRef.stored_len` and `ChunkReply.data` at most:
/// `padme(MAX_CHUNK_PLAINTEXT + 5) + 40` = 4 325 416.
pub const MAX_STORED_LEN: usize = licketysync_keys::chunk::MAX_STORED_LEN;

// Section 4.5: index exchange and Status.

/// `MAX_CURSORS_PER_REQUEST`: entries in one `IndexRequest.have`; a round of
/// range requests covers any number of writers.
pub const MAX_CURSORS_PER_REQUEST: usize = 16_384;
/// `MAX_PAGE_RECORDS`: records per `IndexRecords` page or push. It caps
/// `max_records` (0 or above means this) and is the receiver's bound.
pub const MAX_PAGE_RECORDS: usize = 4_096;
/// The floor of a request's `max_records`: a smaller value is served as this.
pub const MIN_PAGE_RECORDS: usize = 64;
/// `MAX_MARKED_WRITERS`: marks a side holds per folder per connection; one
/// more drops them all and owes a round.
pub const MAX_MARKED_WRITERS: usize = 1_024;
/// `Status.folders`: at most this many.
pub const MAX_STATUS_FOLDERS: usize = 1_024;
/// `Status.device_name`: at most this many bytes.
pub const MAX_DEVICE_NAME_BYTES: usize = 64;

// Section 5: per-connection bounds and intervals.

/// Default `max_requests_in_flight`.
pub const DEFAULT_REQUESTS_IN_FLIGHT: u32 = 64;
/// `MAX_REQUESTS_IN_FLIGHT`: the largest `max_requests_in_flight` a Hello
/// may advertise; a larger one is treated as this (sections 2, 4.2), so a
/// requester never keeps more chunk requests outstanding on a connection
/// whatever the peer advertises, and no device advertises more.
pub const MAX_REQUESTS_IN_FLIGHT: u32 = 1_024;
/// Non-critical types: the set of types already answered with `Unsupported`
/// holds at most this many (every number below the critical bit, a 4 KiB set).
pub const MAX_UNSUPPORTED_TYPES: usize = 32_768;
/// `HELLO_TIMEOUT`: channel up to the peer's Hello and `DeviceProof`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// `PROOF_TIMEOUT`: the `DeviceProof`s to the first open folder.
pub const PROOF_TIMEOUT: Duration = Duration::from_secs(30);
/// `IDLE_TIMEOUT`: no frame in either direction; also, while unsent bytes
/// remain, the longest a connection may go without delivering one (3.1).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// `STATUS_INTERVAL`.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(30);
/// `REPLY_PAGE_TIMEOUT`: the longest a requester waits for the next page of
/// the reply to its outstanding `IndexRequest` (4.5).
pub const REPLY_PAGE_TIMEOUT: Duration = Duration::from_secs(600);
/// `INDEX_RESYNC_INTERVAL`: the least gap between gap-triggered listed
/// requests, and between the starts of owed rounds, per folder per connection.
pub const INDEX_RESYNC_INTERVAL: Duration = Duration::from_secs(10);
/// `INDEX_REQUEST_MIN_INTERVAL`: a responder serves a folder's
/// `IndexRequest`s on a connection at most this often, delaying the rest.
pub const INDEX_REQUEST_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// `CHUNK_BUSY_BACKOFF` at first: no chunk request on a connection for this
/// long after a `CHUNK_BUSY`; also the least wait before the next chunk pass
/// to a peer that answered `CHUNK_NOT_FOUND` (4.6).
pub const CHUNK_BUSY_BACKOFF: Duration = Duration::from_secs(1);
/// The longest `CHUNK_BUSY_BACKOFF` doubles to.
pub const MAX_CHUNK_BUSY_BACKOFF: Duration = Duration::from_secs(64);
/// A change in `chunks_stored` alone sends at most one Status this often per
/// folder per connection (4.5).
pub const STATUS_CHUNKS_INTERVAL: Duration = Duration::from_secs(1);
/// How long a side that sent Close waits before it asks the runtime to close
/// the transport (4.2).
pub const CLOSE_FLUSH: Duration = Duration::from_secs(1);
/// How often a connection that waits on the transport's send queue (queued
/// frames waiting for room, or a request whose departure from the queue starts
/// its reply deadline) asks to be called again, since the transport drains
/// between handler calls and calls no handler when it has (decision: the spec
/// leaves the poll to the implementation).
pub const SEND_POLL_INTERVAL: Duration = Duration::from_secs(1);

// The bounds nest as the spec sizes them, checked when the crate compiles.
const _: () = assert!(PRE_HELLO_LIMIT < MIN_MESSAGE_SIZE);
const _: () = assert!(MIN_MESSAGE_SIZE <= DEFAULT_MESSAGE_SIZE);
const _: () = assert!(DEFAULT_MESSAGE_SIZE <= MAX_MESSAGE_SIZE);
const _: () = assert!(MAX_MESSAGE_SIZE as usize <= MAX_SEND_QUEUE);
const _: () = assert!(MAX_PROOFS_PER_CONNECTION == 4 * MAX_OPEN_FOLDERS_PER_CONNECTION);
const _: () = assert!(MIN_PAGE_RECORDS <= MAX_PAGE_RECORDS);
// The largest record fits one page of the smallest limit (section 2).
const _: () = assert!(MAX_INDEX_RECORD_BYTES + 64 < MIN_MESSAGE_SIZE as usize);
// One ChunkReply with the largest chunk always fits (section 2).
const _: () = assert!(MAX_STORED_LEN + 128 < MIN_MESSAGE_SIZE as usize);
// A full IndexRequest fits: 81 bytes per cursor at most (4.5).
const _: () = assert!(MAX_CURSORS_PER_REQUEST * 81 + 256 < MIN_MESSAGE_SIZE as usize);
const _: () = assert!(MAX_UNSUPPORTED_TYPES == 1 << 15);
const _: () = assert!(DEFAULT_REQUESTS_IN_FLIGHT <= MAX_REQUESTS_IN_FLIGHT);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn the_constants_are_the_specs() {
        assert_eq!(PRE_HELLO_LIMIT, 65_536);
        assert_eq!(MIN_MESSAGE_SIZE, 8 << 20);
        assert_eq!(DEFAULT_MESSAGE_SIZE, 16 << 20);
        assert_eq!(MAX_MESSAGE_SIZE, 64 << 20);
        assert_eq!(MAX_INDEX_RECORD_BYTES, 4_000_000);
        assert_eq!(MAX_FIELD_NUMBER, 536_870_911);
        assert_eq!(MAX_SEND_QUEUE, 134_217_728);
        assert_eq!(MAX_SEALED_BYTES, 1_572_864);
        assert_eq!(MIN_SEALED_BYTES, 40);
        assert_eq!(MAX_STORED_LEN, 4_325_416);
        assert_eq!(MIN_STORED_LEN, 46);
        assert_eq!(MAX_CHUNK_PLAINTEXT, 4_194_304);
        assert_eq!(MAX_SEQ, 4_611_686_018_427_387_904);
        assert_eq!(INDEX_RECORD_TYPE, 16);
        assert_eq!(REPLY_PAGE_TIMEOUT.as_secs(), 600);
        assert_eq!(IDLE_TIMEOUT.as_secs(), 300);
        assert_eq!(MAX_CHUNK_BUSY_BACKOFF.as_secs(), 64);
        assert_eq!(DEFAULT_REQUESTS_IN_FLIGHT, 64);
        assert_eq!(MAX_REQUESTS_IN_FLIGHT, 1_024);
    }
}
