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
//!
//! Counters (`protocol.md` 4.4, "Dots and counters") are microseconds since the
//! Unix epoch, so every bound on them (the horizons, the clock rule, the fast
//! clock warning) is given here in microseconds; the clock rule is also given
//! in whole days, the unit of Hello's `clock_days` (3.2).

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
/// `Hello.clock_days` at most: 2 097 151 (2^21 − 1, in the year 7711), so that
/// it takes at most a 3-byte varint, which the largest Hello of section 2
/// counts; a value above it is malformed (3.2, 4.2).
pub const MAX_CLOCK_DAYS: u32 = (1 << 21) - 1;

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

// Section 4.4: the index record and the cleanup.

/// The `record_type` of an index record.
pub const INDEX_RECORD_TYPE: u32 = licketysync_keys::records::INDEX_RECORD_TYPE;
/// The `record_type` of a cleanup record.
pub const CLEANUP_RECORD_TYPE: u32 = licketysync_keys::records::CLEANUP_RECORD_TYPE;
/// `IndexRecord.chunks` and `SealedMeta.plain_hashes`: at most this many.
pub const MAX_CHUNKS: usize = 32_768;
/// `MAX_SEALED_BYTES`: an index record's `sealed` at most, 40 + 2^21 =
/// 2 097 192 bytes (`keys.md` 3.4).
pub const MAX_SEALED_BYTES: usize = licketysync_keys::sealed_meta::MAX_INDEX_SEALED_BYTES;
/// A cleanup's `sealed` at most: 40 + 1 024 = 1 064 bytes (`keys.md` 3.4).
pub const MAX_CLEANUP_SEALED_BYTES: usize = licketysync_keys::sealed_meta::MAX_CLEANUP_SEALED_BYTES;
/// `MAX_VECTOR_ENTRIES`: entries in a record's vector, and records a write
/// covers at once (4.4).
pub const MAX_VECTOR_ENTRIES: usize = 32;
/// `MAX_COUNTER`: the largest counter, 2^62, so that no arithmetic on
/// counters can overflow (4.4).
pub const MAX_COUNTER: u64 = 1 << 62;
/// `CLOCK_FLOOR_MAX`: the most the clock floor of a new counter may be, 2^61
/// (4.4, "The writer's rule").
pub const CLOCK_FLOOR_MAX: u64 = 1 << 61;
/// One day in counter units (microseconds).
pub const DAY_US: u64 = 86_400_000_000;
/// `CLOCK_AHEAD_WARNING`: a received counter this far ahead of the local
/// clock raises an issue; a stored high-water mark this far above what the
/// records and the clock justify is corrupt (4.4). One day, in microseconds.
pub const CLOCK_AHEAD_WARNING: u64 = DAY_US;
/// `TOMBSTONE_HORIZON`, the deletion horizon: a tombstone or tree delete
/// expires at a read or write holder once the folder's own time passes its
/// counter by more than this (4.4). 365 days, in microseconds.
pub const TOMBSTONE_HORIZON: u64 = 365 * DAY_US;
/// `CLEANUP_HORIZON`: a cleanup expires at a read or write holder once the
/// folder's own time passes its counter by more than this; also the window of
/// `MAX_PEER_NAMES`, by the write holder's wall clock (4.4). 30 days, in
/// microseconds.
pub const CLEANUP_HORIZON: u64 = 30 * DAY_US;
/// `CLOCK_RULE_LIMIT` in whole days, the unit of Hello's `clock_days`: two
/// devices whose clocks differ by more do not sync (3.2, 4.4).
pub const CLOCK_RULE_LIMIT_DAYS: u32 = 365;
/// `CLOCK_RULE_LIMIT` in counter units: a record whose counter is more than
/// this ahead of the receiver's clock is from the future (4.4 step 4). A
/// different rule from the deletion horizon, of the same length.
pub const CLOCK_RULE_LIMIT: u64 = CLOCK_RULE_LIMIT_DAYS as u64 * DAY_US;
/// `MAX_REPLACES`: names in an index record's `replaces` (4.4).
pub const MAX_REPLACES: usize = 64;
/// `MAX_CLEANUP_ENTRIES`: names in one cleanup record, across its groups
/// (4.4).
pub const MAX_CLEANUP_ENTRIES: usize = 16_384;
/// `MAX_CLEANUP_GROUPS`: groups in one cleanup record (4.4).
pub const MAX_CLEANUP_GROUPS: usize = 1_024;
/// `MAX_STALE_KNOWN`: stale copies and forgotten records a write holder notes
/// per folder, kept in memory across connections, the oldest dropped first
/// (4.5, "Stale copies").
pub const MAX_STALE_KNOWN: usize = 65_536;
/// The pushes of one folder whose judgements a connection awaits at most:
/// the engine judges every page it is handed, so only an engine that lags
/// this far behind reaches it, and then the counting stops rather than the
/// table grow (TM-22). An implementation's bound, not a constant of section
/// 5.
pub const MAX_PENDING_PUSHES: usize = 4_096;
/// `MAX_NOTE_VERIFICATIONS`: records a write holder verifies for notes per
/// connection per `INDEX_RESYNC_INTERVAL`, one budget shared by every folder
/// open on the connection (4.5, "Stale copies"): about 0.24 s of one core.
pub const MAX_NOTE_VERIFICATIONS: usize = 4_096;
/// `MAX_PEER_NAMES`: records of one peer's that a write holder names, in
/// writes and cleanups, per window of `CLEANUP_HORIZON` by its wall clock
/// (4.4, 4.5).
pub const MAX_PEER_NAMES: u64 = 1_048_576;
/// `MAX_FUTURE_KNOWN`: record hashes of refused records from the future a
/// device remembers per folder on a connection (4.4 step 4).
pub const MAX_FUTURE_KNOWN: usize = 1_024;
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

/// `MAX_PAGE_RECORDS`: records per `IndexRecords` page or push. It caps
/// `max_records` (0 or above means this) and is the receiver's bound.
pub const MAX_PAGE_RECORDS: usize = 4_096;
/// The floor of a request's `max_records`: a smaller value is served as this.
pub const MIN_PAGE_RECORDS: usize = 64;
/// `MAX_LOCAL_SEQ`: the largest local sequence number, 2^62 (4.5).
pub const MAX_LOCAL_SEQ: u64 = 1 << 62;
/// `RECONCILE_LEAF_MAX`: the most records a subtree holds in leaf form (4.5).
pub const RECONCILE_LEAF_MAX: usize = 64;
/// The bytes of a record's key in the set digests (4.5, "Set digests"): an
/// index record's path tag then its record hash, a cleanup's record hash
/// twice.
pub const KEY_BYTES: usize = 64;
/// The nibbles of a full key: the deepest prefix of the set-digest trie,
/// whose subtree holds at most one record (4.5).
pub const MAX_PREFIX_NIBBLES: usize = 2 * KEY_BYTES;
/// The reconciliation's work list at most: 15 unvisited siblings at each of
/// 128 levels, and the one being visited (4.5, "Reconciling").
pub const MAX_WORK_LIST: usize = 15 * MAX_PREFIX_NIBBLES + 1;
/// `MAX_RECONCILE_PASSES`: reconcile passes in one round (4.5).
pub const MAX_RECONCILE_PASSES: usize = 4;
/// `MAX_PASS_REQUESTS`: `ReconcileRequest`s in one pass (4.5).
pub const MAX_PASS_REQUESTS: usize = 65_536;
/// `PEER_STATE_HORIZON`: per-peer state kept without a round that ended, by
/// the device's wall clock (4.5). 90 days, in microseconds.
pub const PEER_STATE_HORIZON: u64 = 90 * DAY_US;
/// `MAX_PEER_STATES`: per-peer states kept per folder (4.5).
pub const MAX_PEER_STATES: usize = 4_096;
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
/// `REPLY_PAGE_TIMEOUT`: the longest a requester waits for the next part of
/// the reply to its outstanding request, an `IndexRequest` or a
/// `ReconcileRequest` (4.5).
pub const REPLY_PAGE_TIMEOUT: Duration = Duration::from_secs(600);
/// `INDEX_RESYNC_INTERVAL`: the least gap between the starts of owed rounds,
/// per folder per connection (4.5).
pub const INDEX_RESYNC_INTERVAL: Duration = Duration::from_secs(10);
/// `INDEX_REQUEST_MIN_INTERVAL`: a responder serves a folder's
/// `IndexRequest`s and root `ReconcileRequest`s on a connection at most this
/// often, delaying the rest (4.5).
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
// The horizons and the clock rule nest under the counter bounds (4.4).
const _: () = assert!(CLOCK_FLOOR_MAX < MAX_COUNTER);
const _: () = assert!(CLEANUP_HORIZON < TOMBSTONE_HORIZON);
const _: () = assert!(CLOCK_RULE_LIMIT == TOMBSTONE_HORIZON);
const _: () = assert!(MAX_REPLACES >= 2 * MAX_VECTOR_ENTRIES);
const _: () = assert!(MAX_WORK_LIST == 1_921);
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
        assert_eq!(MAX_SEALED_BYTES, 2_097_192);
        assert_eq!(MAX_CLEANUP_SEALED_BYTES, 1_064);
        assert_eq!(MAX_STORED_LEN, 4_325_416);
        assert_eq!(MIN_STORED_LEN, 46);
        assert_eq!(MAX_CHUNK_PLAINTEXT, 4_194_304);
        assert_eq!(INDEX_RECORD_TYPE, 16);
        assert_eq!(CLEANUP_RECORD_TYPE, 17);
        assert_eq!(MAX_VECTOR_ENTRIES, 32);
        assert_eq!(MAX_COUNTER, 4_611_686_018_427_387_904);
        assert_eq!(CLOCK_FLOOR_MAX, 2_305_843_009_213_693_952);
        assert_eq!(CLOCK_AHEAD_WARNING, 86_400_000_000);
        assert_eq!(TOMBSTONE_HORIZON, 31_536_000_000_000);
        assert_eq!(CLEANUP_HORIZON, 2_592_000_000_000);
        assert_eq!(CLOCK_RULE_LIMIT, 31_536_000_000_000);
        assert_eq!(CLOCK_RULE_LIMIT_DAYS, 365);
        assert_eq!(MAX_CLOCK_DAYS, 2_097_151);
        assert_eq!(MAX_REPLACES, 64);
        assert_eq!(MAX_CLEANUP_ENTRIES, 16_384);
        assert_eq!(MAX_CLEANUP_GROUPS, 1_024);
        assert_eq!(MAX_STALE_KNOWN, 65_536);
        assert_eq!(MAX_NOTE_VERIFICATIONS, 4_096);
        assert_eq!(MAX_PEER_NAMES, 1_048_576);
        assert_eq!(MAX_FUTURE_KNOWN, 1_024);
        assert_eq!(MAX_LOCAL_SEQ, 1 << 62);
        assert_eq!(RECONCILE_LEAF_MAX, 64);
        assert_eq!(MAX_RECONCILE_PASSES, 4);
        assert_eq!(MAX_PASS_REQUESTS, 65_536);
        assert_eq!(PEER_STATE_HORIZON, 90 * 86_400_000_000);
        assert_eq!(MAX_PEER_STATES, 4_096);
        assert_eq!(MAX_WORK_LIST, 1_921);
        assert_eq!(MAX_PREFIX_NIBBLES, 128);
        assert_eq!(REPLY_PAGE_TIMEOUT.as_secs(), 600);
        assert_eq!(IDLE_TIMEOUT.as_secs(), 300);
        assert_eq!(MAX_CHUNK_BUSY_BACKOFF.as_secs(), 64);
        assert_eq!(DEFAULT_REQUESTS_IN_FLIGHT, 64);
        assert_eq!(MAX_REQUESTS_IN_FLIGHT, 1_024);
    }
}
