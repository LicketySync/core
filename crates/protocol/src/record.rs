// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index record (`protocol.md` 4.4) as the protocol layer sees it, and
//! the order in which every peer, sealed ones included, judges one:
//!
//! 1. **Parse** ([`Record::parse`], [`Record::from_bytes`]): the keys crate's
//!    envelope decoder, then the body under every size and bound, its suite
//!    the folder's and its `folder_id` the open folder. Failure: malformed.
//! 2. **Duplicate**, 3. **Placement**, 4. **Signature**, 5. **Store**:
//!    [`judge`], over the index's [`Held`] view. A duplicate is ignored
//!    without verifying; a gap on a push is ignored without verifying and the
//!    writer marked; inside a reply a gap, or a writer outside the request's
//!    scope, is a sender violation whatever the signature; then the folder
//!    key's signature (forged closes); then the record is the writer's next
//!    or a concurrent version.
//! 6. **Seal** ([`Record::open`], read and write holders): the sealed
//!    metadata under the record key, its grammar, its kind and its chunk
//!    count. Failure: a writer fault, the record stored opaque.
//! 7. **Heads**: the index's (`supersedes`, waiting records, display order).
//!
//! What stays with the index and the engine: holding records and cursors,
//! the cached digests, heads and waiting, and every issue the outcomes raise.
//! [`writer_digests`] is the reference computation of the cursor digests that
//! the index's cache must equal; [`Draft::sign`] is the writer's side, which
//! never emits what a reader refuses.

use std::collections::BTreeMap;

use core::fmt;

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::{Malformed, SignedRecord};
use licketysync_keys::sealed_meta::{open_meta, seal_meta, MetaError};
use licketysync_keys::secret::DataKey;
use licketysync_keys::{
    CipherHash, DeviceId, FolderId, FolderVerifier, RandomFill, RecordHash, WriteKey, WriterDigest,
};
use prost::Message as _;

use crate::limits::{
    INDEX_RECORD_TYPE, MAX_CHUNKS, MAX_INDEX_RECORD_BYTES, MAX_PATH_BYTES, MAX_SEQ, MAX_SUPERSEDES,
};
use crate::messages::{ChunkRef, IndexRecord, SealedMeta};
use crate::parse::{is_stored_len, Parse};
use crate::rules::Cause;
use crate::wire::WireError;

/// One chunk reference of a record: what sealed peers fetch, verify and
/// deduplicate by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Chunk {
    /// `H("licketysync/v1/hash/chunk", stored)`.
    pub cipher_hash: CipherHash,
    /// Bytes of the stored blob.
    pub stored_len: u32,
}

/// An index record that passed step 1: the envelope exactly as received, its
/// record hash, and the clear fields of its body, typed. The body is never
/// re-encoded; [`Record::signed`] is what is stored and forwarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    signed: SignedRecord,
    hash: RecordHash,
    folder_id: FolderId,
    device_id: DeviceId,
    seq: u64,
    supersedes: Vec<RecordHash>,
    deleted: bool,
    chunks: Vec<Chunk>,
    sealed: Vec<u8>,
}

fn id32<T>(bytes: &[u8], make: fn([u8; 32]) -> T, what: &'static str) -> Result<T, WireError> {
    <[u8; 32]>::try_from(bytes)
        .map(make)
        .map_err(|_| WireError::WrongLength {
            what,
            expected: 32,
            got: bytes.len(),
        })
}

/// The length of `signed`'s wire bytes (`SignedRecord::to_bytes`), computed
/// without encoding it: the body field (omitted when empty, as proto3 omits a
/// default) and the 64-byte signature field.
#[must_use]
pub fn envelope_len(signed: &SignedRecord) -> usize {
    let field = |len: usize| 1 + prost::encoding::encoded_len_varint(len as u64) + len;
    let body = signed.body().len();
    (if body == 0 { 0 } else { field(body) }) + field(signed.signature().as_bytes().len())
}

impl Record {
    /// Step 1 on an encoded `SignedRecord` from a peer, for the open folder
    /// `folder`.
    ///
    /// # Errors
    /// [`WireError`]: malformed, the sender's fault.
    pub fn from_bytes(raw: &[u8], folder: &FolderVerifier) -> Result<Self, WireError> {
        Self::parse(SignedRecord::from_bytes(raw)?, folder)
    }

    /// Step 1 on an envelope already decoded by `SignedRecord::from_bytes`
    /// (or built by this device): its encoded size again, then the body under
    /// every bound of 4.4, its `suite` the folder's and its `folder_id` the
    /// folder's. The keys crate's decoder has checked the envelope's shape,
    /// the signature's 64 bytes and the record type.
    ///
    /// # Errors
    /// [`WireError`]: malformed, the sender's fault.
    pub fn parse(signed: SignedRecord, folder: &FolderVerifier) -> Result<Self, WireError> {
        let encoded = envelope_len(&signed);
        if encoded > MAX_INDEX_RECORD_BYTES {
            return Err(WireError::Record(Malformed::TooLarge(encoded)));
        }
        let body = IndexRecord::parse(signed.body())?;
        if body.suite != folder.suite().to_wire() {
            return Err(WireError::Grammar {
                what: "suite: not the folder's",
            });
        }
        let folder_id = id32(&body.folder_id, FolderId, "folder_id")?;
        if folder_id != folder.folder_id() {
            return Err(WireError::Grammar {
                what: "folder_id: not the open folder",
            });
        }
        let mut supersedes = body
            .supersedes
            .iter()
            .map(|h| id32(h, RecordHash, "supersedes"))
            .collect::<Result<Vec<_>, _>>()?;
        // A set: read in any order, a repeated entry counting once (keys.md 5.2).
        supersedes.sort_unstable();
        supersedes.dedup();
        let chunks = body
            .chunks
            .iter()
            .map(|c| {
                Ok(Chunk {
                    cipher_hash: id32(&c.cipher_hash, CipherHash, "chunks.cipher_hash")?,
                    stored_len: c.stored_len,
                })
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        Ok(Self {
            hash: signed.hash(),
            device_id: id32(&body.device_id, DeviceId, "device_id")?,
            folder_id,
            seq: body.seq,
            supersedes,
            deleted: body.deleted,
            chunks,
            sealed: body.sealed,
            signed,
        })
    }

    /// The envelope exactly as received: what is stored and forwarded.
    #[must_use]
    pub fn signed(&self) -> &SignedRecord {
        &self.signed
    }

    /// The envelope, by value.
    #[must_use]
    pub fn into_signed(self) -> SignedRecord {
        self.signed
    }

    /// `H("licketysync/v1/hash/record", body)`.
    #[must_use]
    pub fn hash(&self) -> RecordHash {
        self.hash
    }

    /// The folder.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }

    /// The writer's device ID as the signer claims it: the key of a sequence,
    /// never shown as an author (ruling S-4).
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The sequence number, 1 to `MAX_SEQ`.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The record hashes this record replaces, as a set: ascending, unique.
    #[must_use]
    pub fn supersedes(&self) -> &[RecordHash] {
        &self.supersedes
    }

    /// Whether the record is a tombstone.
    #[must_use]
    pub fn deleted(&self) -> bool {
        self.deleted
    }

    /// The chunk references, in file order.
    #[must_use]
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// The sealed metadata, nonce first.
    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }

    /// Step 4: `Verify(folder_vk, "licketysync/v1/sig/index", body, signature)`.
    ///
    /// # Errors
    /// [`Cause::Forged`]: `Close(VERIFICATION_FAILED)`.
    pub fn verify(&self, folder: &FolderVerifier) -> Result<(), Cause> {
        folder
            .verify_index_record(&self.signed)
            .map_err(|_| Cause::Forged)
    }

    /// Step 6, for a read or write holder whose data key is `data_key`: opens
    /// the sealed part under the record key with `aad = folder_id ||
    /// device_id || be64(seq)` rebuilt from this record, parses
    /// `SealedMeta`, and checks its path grammar, its kind, its chunk count,
    /// and that a directory has no chunks and a file of size above 0 has some
    /// (coordinator ruling of 2026-10-22). A tombstone's kind and size name
    /// what was deleted, so the last two rules do not apply to it. Readers do
    /// not check that the path is NFC: that is the writer's duty (ruling of
    /// 2026-10-22), so no release can judge a path differently.
    ///
    /// # Errors
    /// [`WriterFault`]: the record is stored opaque and an issue names it.
    pub fn open(&self, data_key: &DataKey) -> Result<Meta, WriterFault> {
        let plain = open_meta(
            &data_key.record_key(),
            &self.folder_id,
            &self.device_id,
            self.seq,
            &self.sealed,
        )
        .map_err(WriterFault::Seal)?;
        let sealed = SealedMeta::parse(&plain).map_err(WriterFault::Meta)?;
        check_path(&sealed.path).map_err(WriterFault::Path)?;
        let kind = Kind::from_wire(sealed.kind).ok_or(WriterFault::Kind(sealed.kind))?;
        if sealed.plain_hashes.len() != self.chunks.len() {
            return Err(WriterFault::HashCount {
                chunks: self.chunks.len(),
                hashes: sealed.plain_hashes.len(),
            });
        }
        if !self.deleted {
            match kind {
                Kind::Directory if !self.chunks.is_empty() => {
                    return Err(WriterFault::DirectoryWithChunks)
                }
                Kind::File if sealed.size > 0 && self.chunks.is_empty() => {
                    return Err(WriterFault::FileWithoutChunks)
                }
                Kind::File | Kind::Directory => {}
            }
        }
        // `SealedMeta::parse` checked every hash at 32 bytes; were one not,
        // the metadata is the writer's fault, never silently shortened.
        let plain_hashes = sealed
            .plain_hashes
            .iter()
            .map(|h| {
                PlainHash::from_slice(h).ok_or(WriterFault::Meta(WireError::WrongLength {
                    what: "plain_hashes",
                    expected: 32,
                    got: h.len(),
                }))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Meta {
            plain_hashes,
            path: sealed.path,
            kind,
            size: sealed.size,
            mtime_ns: sealed.mtime_ns,
            mode: sealed.mode,
            written_at: sealed.written_at,
        })
    }
}

/// `SealedMeta.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// 1.
    File,
    /// 2.
    Directory,
}

impl Kind {
    /// The kind of a wire value; any other is reserved (a writer fault here).
    #[must_use]
    pub const fn from_wire(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::File),
            2 => Some(Self::Directory),
            _ => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        match self {
            Self::File => 1,
            Self::Directory => 2,
        }
    }
}

/// A record's opened metadata (4.4, `SealedMeta`), checked by step 6.
#[derive(Clone, Debug)]
pub struct Meta {
    /// `/` separated, relative, no empty, `.` or `..` component, no NUL, no
    /// backslash; at most 4 096 bytes; NFC by the writer's duty.
    pub path: String,
    /// File or directory.
    pub kind: Kind,
    /// Bytes of plaintext content.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch; compared, never
    /// subtracted (TM-40).
    pub mtime_ns: i64,
    /// Unix permission bits; 0 when the writer has none.
    pub mode: u32,
    /// Keyed BLAKE3 per chunk, same order and count as the record's chunks.
    pub plain_hashes: Vec<PlainHash>,
    /// The writer's wall clock; informational only.
    pub written_at: u64,
}

/// Why a path breaks the grammar of `SealedMeta.path`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// Longer than 4 096 bytes.
    TooLong(usize),
    /// It starts with `/`.
    Absolute,
    /// An empty component (`a//b`, a trailing `/`).
    EmptyComponent,
    /// A `.` or `..` component.
    DotComponent,
    /// A NUL byte.
    Nul,
    /// A backslash.
    Backslash,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the path is empty"),
            Self::TooLong(n) => write!(f, "the path is {n} bytes, over {MAX_PATH_BYTES}"),
            Self::Absolute => f.write_str("the path is absolute"),
            Self::EmptyComponent => f.write_str("the path has an empty component"),
            Self::DotComponent => f.write_str("the path has a . or .. component"),
            Self::Nul => f.write_str("the path holds a NUL"),
            Self::Backslash => f.write_str("the path holds a backslash"),
        }
    }
}

impl std::error::Error for PathError {}

/// The grammar of `SealedMeta.path` (4.4), without NFC, which is the
/// writer's duty. A name that is merely invalid on some platform is the path
/// resolver's concern (TM-4), not a writer fault.
///
/// # Errors
/// [`PathError`].
pub fn check_path(path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong(path.len()));
    }
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    if path.contains('\0') {
        return Err(PathError::Nul);
    }
    if path.contains('\\') {
        return Err(PathError::Backslash);
    }
    for component in path.split('/') {
        match component {
            "" => return Err(PathError::EmptyComponent),
            "." | ".." => return Err(PathError::DotComponent),
            _ => {}
        }
    }
    Ok(())
}

/// Why step 6 refused a record whose signature verified: the signer's doing
/// (4.4 step 6), so an issue names the record and it is stored opaque. Besides
/// the seal, the metadata's grammar, an unknown kind and the hash count, two
/// rules judge what a record that is not a tombstone describes (coordinator
/// ruling of 2026-10-22): a directory has no chunks
/// ([`WriterFault::DirectoryWithChunks`]), and a file of size above 0 has
/// some ([`WriterFault::FileWithoutChunks`]). A tombstone's kind and size
/// name what was deleted, so neither rule applies to one (decision).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriterFault {
    /// The seal will not open, or its length field or padding is wrong.
    Seal(MetaError),
    /// The opened metadata does not parse.
    Meta(WireError),
    /// The path breaks the grammar.
    Path(PathError),
    /// A kind this release does not know.
    Kind(u32),
    /// `plain_hashes` and `chunks` differ in count.
    HashCount {
        /// The record's chunks.
        chunks: usize,
        /// The metadata's plaintext hashes.
        hashes: usize,
    },
    /// A directory (not a tombstone) with chunks.
    DirectoryWithChunks,
    /// A file (not a tombstone) of size above 0 without chunks.
    FileWithoutChunks,
}

impl fmt::Display for WriterFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal(e) => write!(f, "sealed metadata: {e}"),
            Self::Meta(e) => write!(f, "sealed metadata does not parse: {e}"),
            Self::Path(e) => write!(f, "{e}"),
            Self::Kind(k) => write!(f, "kind {k} is not known"),
            Self::HashCount { chunks, hashes } => {
                write!(f, "{hashes} plaintext hashes for {chunks} chunks")
            }
            Self::DirectoryWithChunks => f.write_str("a directory with chunks"),
            Self::FileWithoutChunks => f.write_str("a non-empty file without chunks"),
        }
    }
}

impl std::error::Error for WriterFault {}

/// What the index holds for one folder, as steps 2 and 3 read it.
pub trait Held {
    /// Whether a record with this hash is held for the folder.
    fn holds(&self, record: &RecordHash) -> bool;
    /// This peer's cursor for the writer: the highest `seq` it holds, 0 for
    /// none.
    fn cursor(&self, writer: &DeviceId) -> u64;
}

/// How a record arrived (4.5): in a push, which answers for nothing, or in a
/// reply, which answers for contiguity and for the request's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// An unsolicited page (`request_id = 0`).
    Push,
    /// A page of the reply to this side's request; `in_scope` when the
    /// record's writer lies in the request's range (or, for a listed request,
    /// in its `have`), as the connection judged it.
    Reply {
        /// The writer is inside the request's scope.
        in_scope: bool,
    },
}

/// The fate of a record after steps 2 to 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// Already held: ignored, not verified (ruling DUP).
    Duplicate,
    /// A gap on a push: ignored, not verified; mark the writer.
    PushGap,
    /// Verified, at the cursor plus one: store it; the cursor becomes its `seq`.
    Next,
    /// Verified, at or below the cursor: a concurrent version (ruling R-K5);
    /// store it and recompute the writer's cached digests from its `seq` up.
    Concurrent,
}

impl Judgement {
    /// The section 5 row, for the outcomes that have one.
    #[must_use]
    pub const fn cause(self) -> Option<Cause> {
        match self {
            Self::Duplicate => Some(Cause::Duplicate),
            Self::PushGap => Some(Cause::PushGap),
            Self::Concurrent => Some(Cause::ConcurrentVersion),
            Self::Next => None,
        }
    }

    /// Whether the record is to be stored.
    #[must_use]
    pub const fn stores(self) -> bool {
        matches!(self, Self::Next | Self::Concurrent)
    }
}

/// Steps 2 to 5 of 4.4 for a record that passed step 1, in that order, so
/// that nothing is charged to anyone before the folder key's signature has
/// verified and every signature verified either stores a record this peer
/// did not hold or closes the connection (TM-22).
///
/// # Errors
/// [`Cause::SenderViolation`] for a gap or an out-of-scope writer inside a
/// reply (before the signature is looked at); [`Cause::Forged`] for a
/// signature that does not verify. Both close the connection.
pub fn judge<H: Held + ?Sized>(
    record: &Record,
    arrival: Arrival,
    held: &H,
    folder: &FolderVerifier,
) -> Result<Judgement, Cause> {
    if held.holds(&record.hash) {
        return Ok(Judgement::Duplicate);
    }
    let cursor = held.cursor(&record.device_id);
    let gap = record.seq > cursor.saturating_add(1);
    match arrival {
        Arrival::Reply { in_scope: false } => return Err(Cause::SenderViolation),
        Arrival::Reply { in_scope: true } if gap => return Err(Cause::SenderViolation),
        Arrival::Push if gap => return Ok(Judgement::PushGap),
        Arrival::Push | Arrival::Reply { .. } => {}
    }
    record.verify(folder)?;
    Ok(if record.seq <= cursor {
        Judgement::Concurrent
    } else {
        Judgement::Next
    })
}

/// Whether a stored record is under this device's own device ID at or above
/// the next `seq` it would use (4.5, "Durability before transmission"): the
/// device moves its counter past it before it writes again and raises an
/// informational issue that names no one ([`Cause::OwnSequenceAhead`]).
#[must_use]
pub fn own_sequence_ahead(record: &Record, own: &DeviceId, next_seq: u64) -> bool {
    record.device_id == *own && record.seq >= next_seq
}

/// The cursor digests of one writer (4.4): its records in canonical order
/// (ascending `seq`, then ascending record hash; a repeated hash counting
/// once), `D` starting as 32 zero bytes and each record setting
/// `D = H("licketysync/v1/hash/writer-digest", D || record_hash)`; the digest
/// at `s` is `D` after the last record with `seq ≤ s`. The map holds every
/// `seq` that has a record. This is the reference the index's cache equals;
/// serving never computes it (4.5).
#[must_use]
pub fn writer_digests<I: IntoIterator<Item = (u64, RecordHash)>>(
    records: I,
) -> BTreeMap<u64, WriterDigest> {
    let mut sorted: Vec<(u64, RecordHash)> = records.into_iter().collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut digest = WriterDigest::ZERO;
    let mut out = BTreeMap::new();
    for (seq, hash) in sorted {
        digest = digest.then(&hash);
        out.insert(seq, digest);
    }
    out
}

/// A record a writer is about to sign (4.4): the clear fields and the
/// metadata that will be sealed.
#[derive(Clone, Debug)]
pub struct Draft {
    /// This device's ID.
    pub device_id: DeviceId,
    /// The next sequence number this device uses, committed before any peer
    /// may receive the record.
    pub seq: u64,
    /// Every head of the path (and, for a rename, of the old path) it
    /// replaces; at most 16 once repeats are dropped.
    pub supersedes: Vec<RecordHash>,
    /// A tombstone.
    pub deleted: bool,
    /// The chunk references, in file order.
    pub chunks: Vec<Chunk>,
    /// The metadata; its path NFC-normalised by the caller.
    pub meta: Meta,
}

/// Why [`Draft::sign`] refused: the record would break a rule a reader
/// enforces, so it is not written (an issue on the writer's side).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DraftError {
    /// `seq` is 0 or above `MAX_SEQ`.
    Seq(u64),
    /// More than 16 distinct `supersedes` entries.
    Supersedes(usize),
    /// More than 32 768 chunks.
    Chunks(usize),
    /// A chunk's stored length is not one a reader accepts.
    StoredLen(u32),
    /// A tombstone with chunks.
    DeletedWithChunks,
    /// The metadata's checks of step 6 fail.
    Fault(WriterFault),
    /// The sealed part would exceed `MAX_SEALED_BYTES`.
    Seal(MetaError),
    /// The signed record does not pass a reader's step 1, its size included.
    /// Unreachable for a draft within the caps above, since the largest one
    /// encodes below `MAX_INDEX_RECORD_BYTES` (section 2's sizing; tested).
    Refused(WireError),
}

impl fmt::Display for DraftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seq(n) => write!(f, "sequence number {n} is out of range"),
            Self::Supersedes(n) => write!(f, "{n} superseded versions, over {MAX_SUPERSEDES}"),
            Self::Chunks(n) => write!(f, "{n} chunks, over {MAX_CHUNKS}"),
            Self::StoredLen(n) => write!(f, "stored length {n} is not valid"),
            Self::DeletedWithChunks => f.write_str("a tombstone with chunks"),
            Self::Fault(e) => write!(f, "{e}"),
            Self::Seal(e) => write!(f, "{e}"),
            Self::Refused(e) => write!(f, "a reader would refuse it: {e}"),
        }
    }
}

impl std::error::Error for DraftError {}

impl Draft {
    /// The fields' rules, checked before anything is sealed.
    fn check(&self, supersedes: usize) -> Result<(), DraftError> {
        if !(1..=MAX_SEQ).contains(&self.seq) {
            return Err(DraftError::Seq(self.seq));
        }
        if supersedes > MAX_SUPERSEDES {
            return Err(DraftError::Supersedes(supersedes));
        }
        if self.chunks.len() > MAX_CHUNKS {
            return Err(DraftError::Chunks(self.chunks.len()));
        }
        if let Some(c) = self.chunks.iter().find(|c| !is_stored_len(c.stored_len)) {
            return Err(DraftError::StoredLen(c.stored_len));
        }
        if self.deleted && !self.chunks.is_empty() {
            return Err(DraftError::DeletedWithChunks);
        }
        check_path(&self.meta.path).map_err(|e| DraftError::Fault(WriterFault::Path(e)))?;
        if self.meta.plain_hashes.len() != self.chunks.len() {
            return Err(DraftError::Fault(WriterFault::HashCount {
                chunks: self.chunks.len(),
                hashes: self.meta.plain_hashes.len(),
            }));
        }
        Ok(())
    }

    /// Seals the metadata under the folder's record key with 24 fresh bytes
    /// from `rng`, encodes the body canonically (`keys.md` 5.2, `supersedes`
    /// sorted without repeats) and signs it with the folder key. The result
    /// passes every check a reader's steps 1, 4 and 6 make: it goes through
    /// step 1 ([`Record::parse`], the size cap included) and step 6 before it
    /// is returned.
    ///
    /// # Errors
    /// [`DraftError`].
    pub fn sign(
        &self,
        key: &WriteKey,
        rng: &mut RandomFill<'_>,
    ) -> Result<SignedRecord, DraftError> {
        let mut supersedes = self.supersedes.clone();
        supersedes.sort_unstable();
        supersedes.dedup();
        self.check(supersedes.len())?;
        let folder = key.verifier();
        let meta = SealedMeta {
            path: self.meta.path.clone(),
            kind: self.meta.kind.to_wire(),
            size: self.meta.size,
            mtime_ns: self.meta.mtime_ns,
            mode: self.meta.mode,
            plain_hashes: self
                .meta
                .plain_hashes
                .iter()
                .map(|h| h.0.to_vec())
                .collect(),
            written_at: self.meta.written_at,
        }
        .encode_to_vec();
        let sealed = seal_meta(
            &key.data_key().record_key(),
            &folder.folder_id(),
            &self.device_id,
            self.seq,
            &meta,
            rng,
        )
        .map_err(DraftError::Seal)?;
        let body = IndexRecord {
            suite: folder.suite().to_wire(),
            record_type: INDEX_RECORD_TYPE,
            folder_id: folder.folder_id().0.to_vec(),
            device_id: self.device_id.0.to_vec(),
            seq: self.seq,
            supersedes: supersedes.iter().map(|h| h.0.to_vec()).collect(),
            deleted: self.deleted,
            chunks: self
                .chunks
                .iter()
                .map(|c| ChunkRef {
                    cipher_hash: c.cipher_hash.0.to_vec(),
                    stored_len: c.stored_len,
                })
                .collect(),
            sealed,
        }
        .encode_to_vec();
        let signed = key.sign_index_record(body);
        let record = Record::parse(signed, folder).map_err(DraftError::Refused)?;
        record.open(key.data_key()).map_err(DraftError::Fault)?;
        Ok(record.into_signed())
    }
}

#[cfg(test)]
mod tests;
