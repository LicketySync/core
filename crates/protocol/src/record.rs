// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The two signed records of major 1 (`protocol.md` 4.4) as the protocol layer
//! sees them, an index record (type 16) and a cleanup (type 17), and the two
//! steps of their verification that need no index:
//!
//! - **Step 1** ([`Record::parse`], [`Record::from_bytes`]): the keys crate's
//!   envelope decoder, then the body under every size and bound of its type,
//!   its suite the folder's and its `folder_id` the open folder. Failure:
//!   malformed, the sender's.
//! - **Step 7** ([`Record::open`]), for read and write holders: the seal under
//!   the folder's record key and `aad = folder_id || path_tag` (or
//!   `folder_id`, for a cleanup), the metadata's grammar, the path's tag, the
//!   dot, the vector and the deletion marks. Failure: a [`WriterFault`], one
//!   variant per check, the record then held opaque. It is a pure function of
//!   the record and the folder's keys, cheap to call once and its [`Verdict`]
//!   easy to keep: the index runs it at step 3, before the signature, charging
//!   no one, and reuses the verdict at step 7 (4.4 "Coverage": coverage never
//!   reads a vector that has not been checked).
//!
//! Steps 2 to 6, 8 and 9 (duplicates, names, coverage, expiry, the clock
//! rule, the signature, what is held) are the index's: it holds the records
//! they are about. [`Record::verify`] is step 5. The writer's side,
//! [`IndexDraft::sign`] and [`CleanupDraft::sign`], encodes, seals and signs
//! what the index decided (dot, vector, names, groups) and never emits a
//! record a reader's steps 1 and 7 would refuse.
//!
//! Dots and vectors ([`Dot`], [`Vector`]) live inside the seal; what a sealed
//! peer reads is the record's clear fields: its key in the set digests
//! ([`Record::key`]), its names ([`Record::replaces`], [`Record::groups`]),
//! its chunks and its signature.

use core::fmt;

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::{RecordType, SignedRecord};
use licketysync_keys::sealed_meta::{MetaError, RecordKeys};
use licketysync_keys::{
    CipherHash, DeviceId, FolderId, FolderVerifier, PathTag, RandomFill, RecordHash, WriteKey,
};
use prost::Message as _;

use crate::limits::{
    CLEANUP_RECORD_TYPE, INDEX_RECORD_TYPE, MAX_CHUNKS, MAX_CLEANUP_ENTRIES, MAX_CLEANUP_GROUPS,
    MAX_COUNTER, MAX_PATH_BYTES, MAX_REPLACES, MAX_VECTOR_ENTRIES,
};
use crate::messages::{
    ChunkRef, CleanupGroup, CleanupMeta, CleanupRecord, IndexRecord, SealedMeta, VectorEntry,
};
use crate::parse::{is_stored_len, Parse};
use crate::rules::Cause;
use crate::wire::WireError;

/// One chunk reference of a record: what sealed peers fetch, verify and
/// deduplicate by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Chunk {
    /// `H("licketysync/v1/hash/chunk", stored)`.
    pub cipher_hash: CipherHash,
    /// Bytes of the stored blob, its padded size.
    pub stored_len: u32,
}

/// One group of a cleanup (4.4, "Cleanup"): the records it names, which it
/// drops at every tier while it applies, that is while `because` is `None` or
/// names a record the device holds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    /// The record that replaces those named, or `None` (forgotten records).
    pub because: Option<RecordHash>,
    /// The fingerprints to forget, ascending, no repeats.
    pub forget: Vec<RecordHash>,
}

/// The clear fields of a record's body, by record type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    /// An index record.
    Index {
        /// The file ID.
        path_tag: PathTag,
        /// The fingerprints it names: ascending, no repeats, at most 64.
        replaces: Vec<RecordHash>,
        /// The chunk references, in file order.
        chunks: Vec<Chunk>,
    },
    /// A cleanup.
    Cleanup {
        /// 1 to `MAX_CLEANUP_GROUPS` groups.
        groups: Vec<Group>,
    },
}

/// A record that passed step 1: the envelope exactly as received, its record
/// hash, and the clear fields of its body, typed. The body is never
/// re-encoded; [`Record::signed`] is what is stored and forwarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    signed: SignedRecord,
    hash: RecordHash,
    folder_id: FolderId,
    body: Body,
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

fn hashes(list: &[Vec<u8>], what: &'static str) -> Result<Vec<RecordHash>, WireError> {
    list.iter().map(|h| id32(h, RecordHash, what)).collect()
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

    /// Step 1 on an envelope already decoded by `SignedRecord::from_bytes` (or
    /// built by this device): the body of its record type under every bound
    /// of 4.4, its `suite` the folder's and its `folder_id` the folder's. The
    /// keys crate has checked the envelope's shape and encoded size (its
    /// decoder before anything is decoded, its signer before signing: no
    /// [`SignedRecord`] passes `MAX_INDEX_RECORD_BYTES`), the signature's 64
    /// bytes and the record type.
    ///
    /// # Errors
    /// [`WireError`]: malformed, the sender's fault.
    pub fn parse(signed: SignedRecord, folder: &FolderVerifier) -> Result<Self, WireError> {
        let (suite, folder_id, body, sealed) = match signed.record_type() {
            RecordType::Index => {
                let b = IndexRecord::parse(signed.body())?;
                let chunks = b
                    .chunks
                    .iter()
                    .map(|c| {
                        Ok(Chunk {
                            cipher_hash: id32(&c.cipher_hash, CipherHash, "chunks.cipher_hash")?,
                            stored_len: c.stored_len,
                        })
                    })
                    .collect::<Result<Vec<_>, WireError>>()?;
                let body = Body::Index {
                    path_tag: id32(&b.path_tag, PathTag, "path_tag")?,
                    replaces: hashes(&b.replaces, "replaces")?,
                    chunks,
                };
                (b.suite, b.folder_id, body, b.sealed)
            }
            RecordType::Cleanup => {
                let b = CleanupRecord::parse(signed.body())?;
                let groups = b
                    .groups
                    .iter()
                    .map(|g| {
                        Ok(Group {
                            because: if g.because.is_empty() {
                                None
                            } else {
                                Some(id32(&g.because, RecordHash, "groups.because")?)
                            },
                            forget: hashes(&g.forget, "groups.forget")?,
                        })
                    })
                    .collect::<Result<Vec<_>, WireError>>()?;
                (b.suite, b.folder_id, Body::Cleanup { groups }, b.sealed)
            }
        };
        if suite != folder.suite().to_wire() {
            return Err(WireError::Grammar {
                what: "suite: not the folder's",
            });
        }
        let folder_id = id32(&folder_id, FolderId, "folder_id")?;
        if folder_id != folder.folder_id() {
            return Err(WireError::Grammar {
                what: "folder_id: not the open folder",
            });
        }
        Ok(Self {
            hash: signed.hash(),
            folder_id,
            body,
            sealed,
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

    /// `H("licketysync/v1/hash/record", body)`: the record's fingerprint.
    #[must_use]
    pub fn hash(&self) -> RecordHash {
        self.hash
    }

    /// The record type, 16 or 17 (the tests'; the engine port makes it
    /// public if it needs it).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn record_type(&self) -> RecordType {
        self.signed.record_type()
    }

    /// Whether the record is a cleanup.
    #[must_use]
    pub fn is_cleanup(&self) -> bool {
        matches!(self.body, Body::Cleanup { .. })
    }

    /// The folder.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }

    /// The clear fields of the body (the tests').
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn body(&self) -> &Body {
        &self.body
    }

    /// An index record's file ID; `None` for a cleanup.
    #[must_use]
    pub fn path_tag(&self) -> Option<PathTag> {
        match &self.body {
            Body::Index { path_tag, .. } => Some(*path_tag),
            Body::Cleanup { .. } => None,
        }
    }

    /// The record's key in the set digests (4.5, "Set digests"): an index
    /// record's path tag followed by its record hash, a cleanup's record hash
    /// twice.
    #[must_use]
    pub fn key(&self) -> crate::exchange::Key {
        let first = match &self.body {
            Body::Index { path_tag, .. } => path_tag.0,
            Body::Cleanup { .. } => self.hash.0,
        };
        let mut key = [0u8; crate::limits::KEY_BYTES];
        let (a, b) = key.split_at_mut(32);
        a.copy_from_slice(&first);
        b.copy_from_slice(&self.hash.0);
        key
    }

    /// The fingerprints an index record names in `replaces`, ascending; empty
    /// for a cleanup.
    #[must_use]
    pub fn replaces(&self) -> &[RecordHash] {
        match &self.body {
            Body::Index { replaces, .. } => replaces,
            Body::Cleanup { .. } => &[],
        }
    }

    /// A cleanup's groups; empty for an index record.
    #[must_use]
    pub fn groups(&self) -> &[Group] {
        match &self.body {
            Body::Index { .. } => &[],
            Body::Cleanup { groups } => groups,
        }
    }

    /// An index record's chunk references, in file order; empty for a cleanup.
    #[must_use]
    pub fn chunks(&self) -> &[Chunk] {
        match &self.body {
            Body::Index { chunks, .. } => chunks,
            Body::Cleanup { .. } => &[],
        }
    }

    /// The sealed part, nonce first.
    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }

    /// Step 5: `Verify(folder_vk, label, body, signature)` under the label of
    /// the record's type (`keys.md` 5.1).
    ///
    /// # Errors
    /// [`Cause::Forged`]: `Close(VERIFICATION_FAILED)`.
    pub fn verify(&self, folder: &FolderVerifier) -> Result<(), Cause> {
        folder
            .verify_record(&self.signed)
            .map_err(|_| Cause::Forged)
    }

    /// Step 7, for a read or write holder whose record keys (`rk`, `tk` and
    /// the folder ID) are `keys`: opens the seal under the aad rebuilt from
    /// this record's clear fields and checks what it holds, in the order the
    /// [`WriterFault`] variants list them but for the kind, which is checked
    /// after every check that does not depend on it and before the two that
    /// do (a directory with chunks, a file of some size without), so that a
    /// record whose only fault is a `kind` this release does not know is told
    /// apart from a shared writer fault ([`WriterFault::is_shared`]). NFC is
    /// not checked: it is the writer's duty (4.4 step 7).
    ///
    /// # Errors
    /// A [`WriterFault`]: the record is held opaque and an issue names it.
    pub fn open(&self, keys: &RecordKeys) -> Verdict {
        match &self.body {
            Body::Index {
                path_tag, chunks, ..
            } => open_index(keys, path_tag, chunks, &self.sealed).map(Applied::Index),
            Body::Cleanup { .. } => open_cleanup(keys, &self.sealed).map(Applied::Cleanup),
        }
    }
}

/// A record's dot: the device that wrote it, as the signer claims it, and its
/// counter (4.4, "Dots and counters").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dot {
    /// The writer's device ID.
    pub device: DeviceId,
    /// 1 to `MAX_COUNTER`.
    pub counter: u64,
}

/// A version vector (4.4): at most `MAX_VECTOR_ENTRIES` entries, ascending by
/// device ID, each device once, each counter at least 1. A device absent
/// counts 0.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Vector(Vec<Dot>);

impl Vector {
    /// A vector of `entries`, which must be ascending by device ID, each
    /// device once, each counter at least 1; `None` otherwise. Its length is
    /// not bounded here: a writer prunes before it signs, and a reader's
    /// step 7 refuses more than 32.
    #[must_use]
    pub fn from_sorted(entries: Vec<Dot>) -> Option<Self> {
        let ascending = entries
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.device < b.device));
        (ascending && entries.iter().all(|d| d.counter >= 1)).then_some(Self(entries))
    }

    /// The counter the vector gives `device`, 0 when absent.
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> u64 {
        self.0
            .binary_search_by(|d| d.device.cmp(device))
            .ok()
            .and_then(|i| self.0.get(i))
            .map_or(0, |d| d.counter)
    }

    /// Whether the vector covers a record whose dot is `dot`:
    /// `vector[dot.device] ≥ dot.counter` (4.4, "Coverage"). One entry is
    /// read, never the whole vector.
    #[must_use]
    pub fn covers(&self, dot: &Dot) -> bool {
        self.get(&dot.device) >= dot.counter
    }

    /// The entries, ascending by device ID.
    #[must_use]
    pub fn entries(&self) -> &[Dot] {
        &self.0
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the vector has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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

/// An index record's opened metadata (4.4, `SealedMeta`), checked by step 7.
/// It has no `==`: its plaintext hashes compare only in constant time
/// ([`PlainHash::ct_eq`]).
#[derive(Clone, Debug)]
pub struct Meta {
    /// `/` separated, relative, no empty, `.` or `..` component, no NUL, no
    /// backslash; at most 4 096 bytes; NFC by the writer's duty; for a tree
    /// delete, the deleted directory.
    pub path: String,
    /// File or directory; a tree delete is a directory.
    pub kind: Kind,
    /// Bytes of plaintext content; 0 for a tree delete.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch; compared, never
    /// subtracted (TM-40).
    pub mtime_ns: i64,
    /// Unix permission bits; 0 when the writer has none.
    pub mode: u32,
    /// Keyed BLAKE3 per chunk, same order and count as the record's chunks.
    pub plain_hashes: Vec<PlainHash>,
    /// The writer's wall clock in microseconds since the Unix epoch;
    /// informational only.
    pub written_at: u64,
    /// The record's dot.
    pub dot: Dot,
    /// The version vector, every counter below the dot's.
    pub vector: Vector,
    /// A tombstone, or with `tree` a tree delete.
    pub deleted: bool,
    /// A tree delete of the path and everything beneath it.
    pub tree: bool,
}

impl Meta {
    /// A tombstone: deleted, and not a tree delete.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.deleted && !self.tree
    }

    /// A tree delete (the tests').
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_tree_delete(&self) -> bool {
        self.tree
    }

    /// A deletion of either kind, which expires after `TOMBSTONE_HORIZON`
    /// (the tests').
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_deletion(&self) -> bool {
        self.deleted
    }
}

/// What step 7 found a record to be, when every check passed.
#[derive(Clone, Debug)]
pub enum Applied {
    /// An index record's metadata.
    Index(Meta),
    /// A cleanup's dot (its issuer and counter).
    Cleanup(Dot),
}

impl Applied {
    /// The record's dot.
    #[must_use]
    pub const fn dot(&self) -> &Dot {
        match self {
            Self::Index(meta) => &meta.dot,
            Self::Cleanup(dot) => dot,
        }
    }

    /// The index record's metadata; `None` for a cleanup.
    #[must_use]
    pub const fn meta(&self) -> Option<&Meta> {
        match self {
            Self::Index(meta) => Some(meta),
            Self::Cleanup(_) => None,
        }
    }
}

/// Step 7's verdict on a record: applied, or a writer fault.
pub type Verdict = Result<Applied, WriterFault>;

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

/// Whether `path` lies at or beneath the directory `dir`: it is `dir`, or it
/// begins with `dir` and a separator (4.4, "File IDs").
#[must_use]
pub fn at_or_beneath(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Why step 7 refused a record whose seal a read or write holder opened: the
/// signer's doing, since the body verifies under the folder key, so the
/// record is held opaque and an issue names it by its hash, never a device
/// (4.4 step 7). One variant per check of 4.4 step 7, in the order they run,
/// but for [`WriterFault::Kind`], listed last, which runs after every check
/// that does not depend on the kind and before the two that do
/// ([`WriterFault::DirectoryWithChunks`], [`WriterFault::FileWithoutChunks`]).
/// Every variant but [`WriterFault::Kind`] is a **shared writer fault**, one
/// that every release of major 1 judges alike (section 6), which the next
/// write at the record's path names ([`WriterFault::is_shared`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriterFault {
    /// The seal will not open, its length field does not fit, its padding is
    /// not zero, or it is padded past the least power of two that holds the
    /// metadata (`keys.md` 3.4).
    Seal(MetaError),
    /// The opened metadata does not parse.
    Meta(WireError),
    /// The path breaks the grammar.
    Path(PathError),
    /// The path's tag is not the record's `path_tag`.
    PathTag,
    /// `device_id` is not 32 bytes: its length.
    DeviceId(usize),
    /// `counter` is 0 or above `MAX_COUNTER`.
    Counter(u64),
    /// The vector has more than `MAX_VECTOR_ENTRIES` entries.
    VectorLength,
    /// A vector entry's `device_id` is not 32 bytes: its length.
    VectorDevice(usize),
    /// A vector entry's counter is 0.
    VectorCounterZero,
    /// A vector entry's counter is not below the record's.
    VectorCounterNotBelow,
    /// The vector is not ascending by device ID.
    VectorOrder,
    /// The vector names a device twice.
    VectorDuplicate,
    /// `tree` without `deleted`.
    TreeWithoutDeleted,
    /// `deleted` with chunks.
    DeletedWithChunks,
    /// A tree delete whose `kind` is not 2 or whose `size` is not 0.
    TreeKindOrSize,
    /// `plain_hashes` and `chunks` differ in count.
    HashCount {
        /// The record's chunks.
        chunks: usize,
        /// The metadata's plaintext hashes.
        hashes: usize,
    },
    /// A directory that is not a tombstone, with chunks.
    DirectoryWithChunks,
    /// A file that is not a tombstone, with `size > 0` and no chunks.
    FileWithoutChunks,
    /// A `kind` this release does not know. The one fault that is not
    /// shared: the record may be a newer release's version, which this
    /// release never names (4.4, "A newer release's version").
    Kind(u32),
}

impl WriterFault {
    /// Whether every release of major 1 judges the record a fault (4.4, "Its
    /// names"): every fault but an unknown `kind`.
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        !matches!(self, Self::Kind(_))
    }
}

impl fmt::Display for WriterFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal(e) => write!(f, "sealed metadata: {e}"),
            Self::Meta(e) => write!(f, "sealed metadata does not parse: {e}"),
            Self::Path(e) => write!(f, "{e}"),
            Self::PathTag => f.write_str("the path's tag is not the record's path tag"),
            Self::DeviceId(n) => write!(f, "a device ID of {n} bytes"),
            Self::Counter(n) => write!(f, "counter {n} is out of range"),
            Self::VectorLength => write!(f, "a vector of more than {MAX_VECTOR_ENTRIES} entries"),
            Self::VectorDevice(n) => write!(f, "a vector entry's device ID of {n} bytes"),
            Self::VectorCounterZero => f.write_str("a vector entry with counter 0"),
            Self::VectorCounterNotBelow => {
                f.write_str("a vector entry whose counter is not below the record's")
            }
            Self::VectorOrder => f.write_str("a vector not ascending by device ID"),
            Self::VectorDuplicate => f.write_str("a vector naming one device twice"),
            Self::TreeWithoutDeleted => f.write_str("a tree delete that is not deleted"),
            Self::DeletedWithChunks => f.write_str("a deletion with chunks"),
            Self::TreeKindOrSize => f.write_str("a tree delete that is not a directory of size 0"),
            Self::HashCount { chunks, hashes } => {
                write!(f, "{hashes} plaintext hashes for {chunks} chunks")
            }
            Self::DirectoryWithChunks => f.write_str("a directory with chunks"),
            Self::FileWithoutChunks => f.write_str("a non-empty file without chunks"),
            Self::Kind(k) => write!(f, "kind {k} is not known"),
        }
    }
}

impl std::error::Error for WriterFault {}

/// The dot of opened metadata: a 32-byte device ID and a counter from 1 to
/// `MAX_COUNTER`.
fn dot_of(device_id: &[u8], counter: u64) -> Result<Dot, WriterFault> {
    let device = DeviceId::from_slice(device_id).ok_or(WriterFault::DeviceId(device_id.len()))?;
    if !(1..=MAX_COUNTER).contains(&counter) {
        return Err(WriterFault::Counter(counter));
    }
    Ok(Dot { device, counter })
}

/// The vector's checks of step 7, in order: its length, each entry's device ID
/// and counter (at least 1, below the record's), then its order.
fn vector_of(entries: &[VectorEntry], own: u64) -> Result<Vector, WriterFault> {
    if entries.len() > MAX_VECTOR_ENTRIES {
        return Err(WriterFault::VectorLength);
    }
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let device = DeviceId::from_slice(&e.device_id)
            .ok_or(WriterFault::VectorDevice(e.device_id.len()))?;
        if e.counter == 0 {
            return Err(WriterFault::VectorCounterZero);
        }
        if e.counter >= own {
            return Err(WriterFault::VectorCounterNotBelow);
        }
        out.push(Dot {
            device,
            counter: e.counter,
        });
    }
    for w in out.windows(2) {
        if let [a, b] = w {
            match a.device.cmp(&b.device) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return Err(WriterFault::VectorDuplicate),
                core::cmp::Ordering::Greater => return Err(WriterFault::VectorOrder),
            }
        }
    }
    Ok(Vector(out))
}

fn open_index(
    keys: &RecordKeys,
    path_tag: &PathTag,
    chunks: &[Chunk],
    sealed: &[u8],
) -> Result<Meta, WriterFault> {
    let plain = keys
        .open_index_meta(path_tag, sealed)
        .map_err(WriterFault::Seal)?;
    let m = SealedMeta::parse(&plain).map_err(WriterFault::Meta)?;
    check_path(&m.path).map_err(WriterFault::Path)?;
    if keys.path_tag(&m.path) != *path_tag {
        return Err(WriterFault::PathTag);
    }
    let dot = dot_of(&m.device_id, m.counter)?;
    let vector = vector_of(&m.vector, m.counter)?;
    if m.tree && !m.deleted {
        return Err(WriterFault::TreeWithoutDeleted);
    }
    if m.deleted && !chunks.is_empty() {
        return Err(WriterFault::DeletedWithChunks);
    }
    if m.tree && (m.kind != Kind::Directory.to_wire() || m.size != 0) {
        return Err(WriterFault::TreeKindOrSize);
    }
    if m.plain_hashes.len() != chunks.len() {
        return Err(WriterFault::HashCount {
            chunks: chunks.len(),
            hashes: m.plain_hashes.len(),
        });
    }
    let kind = Kind::from_wire(m.kind).ok_or(WriterFault::Kind(m.kind))?;
    if !m.deleted {
        match kind {
            Kind::Directory if !chunks.is_empty() => return Err(WriterFault::DirectoryWithChunks),
            Kind::File if m.size > 0 && chunks.is_empty() => {
                return Err(WriterFault::FileWithoutChunks)
            }
            Kind::File | Kind::Directory => {}
        }
    }
    let plain_hashes = m
        .plain_hashes
        .iter()
        .map(|h| {
            // `SealedMeta::parse` checked every hash at 32 bytes; were one
            // not, the metadata is the writer's fault, never shortened.
            PlainHash::from_slice(h).ok_or(WriterFault::Meta(WireError::WrongLength {
                what: "plain_hashes",
                expected: 32,
                got: h.len(),
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Meta {
        path: m.path,
        kind,
        size: m.size,
        mtime_ns: m.mtime_ns,
        mode: m.mode,
        plain_hashes,
        written_at: m.written_at,
        dot,
        vector,
        deleted: m.deleted,
        tree: m.tree,
    })
}

fn open_cleanup(keys: &RecordKeys, sealed: &[u8]) -> Result<Dot, WriterFault> {
    let plain = keys.open_cleanup_meta(sealed).map_err(WriterFault::Seal)?;
    let m = CleanupMeta::parse(&plain).map_err(WriterFault::Meta)?;
    dot_of(&m.device_id, m.counter)
}

/// Why a draft was refused: the record would break a rule a reader
/// enforces, so it is not written (an issue on the writer's side). Every
/// error names what the writer did; none is a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DraftError {
    /// The record keys are not the write key's folder's.
    WrongKeys,
    /// More than `MAX_REPLACES` distinct names.
    Replaces(usize),
    /// More than `MAX_VECTOR_ENTRIES` vector entries.
    Vector(usize),
    /// A vector entry for one device twice.
    VectorDuplicate,
    /// A vector entry whose counter is 0 or not below the record's.
    VectorCounter,
    /// The record's counter is 0 or above `MAX_COUNTER`.
    Counter(u64),
    /// More than 32 768 chunks.
    Chunks(usize),
    /// A chunk's stored length is not one a reader accepts.
    StoredLen(u32),
    /// No group, or more than `MAX_CLEANUP_GROUPS`.
    Groups(usize),
    /// No name, or more than `MAX_CLEANUP_ENTRIES` in all.
    Names(usize),
    /// The metadata fails a check of step 7.
    Fault(WriterFault),
    /// The sealed part would pass its record type's cap, or the cipher
    /// refused.
    Seal(MetaError),
    /// The signed record does not pass a reader's step 1, its size included.
    /// Unreachable for a draft within the caps above, since the largest one
    /// encodes below `MAX_INDEX_RECORD_BYTES` (section 2's sizing; tested).
    Refused(WireError),
}

impl fmt::Display for DraftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKeys => f.write_str("record keys of another folder"),
            Self::Replaces(n) => write!(f, "{n} names, over {MAX_REPLACES}"),
            Self::Vector(n) => write!(f, "{n} vector entries, over {MAX_VECTOR_ENTRIES}"),
            Self::VectorDuplicate => f.write_str("a vector naming one device twice"),
            Self::VectorCounter => f.write_str("a vector entry not below the record's counter"),
            Self::Counter(n) => write!(f, "counter {n} is out of range"),
            Self::Chunks(n) => write!(f, "{n} chunks, over {MAX_CHUNKS}"),
            Self::StoredLen(n) => write!(f, "stored length {n} is not valid"),
            Self::Groups(n) => write!(f, "{n} cleanup groups"),
            Self::Names(n) => write!(f, "{n} cleanup names"),
            Self::Fault(e) => write!(f, "{e}"),
            Self::Seal(e) => write!(f, "{e}"),
            Self::Refused(e) => write!(f, "a reader would refuse it: {e}"),
        }
    }
}

impl std::error::Error for DraftError {}

/// An index record a writer is about to sign: what the index decided for it
/// (its metadata with the dot and vector, its chunks, and its names), which
/// this crate encodes, seals and signs. The vector's entries may come in any
/// order; the names may repeat.
#[derive(Clone, Debug)]
pub struct IndexDraft {
    /// The metadata, its path NFC-normalised by the caller.
    pub meta: Meta,
    /// The chunk references, in file order.
    pub chunks: Vec<Chunk>,
    /// The fingerprints the record names.
    pub replaces: Vec<RecordHash>,
}

/// A cleanup a write holder is about to sign: its dot and its groups. Each
/// group's names may come in any order and may repeat.
#[derive(Clone, Debug)]
pub struct CleanupDraft {
    /// The issuer's device ID and counter.
    pub dot: Dot,
    /// 1 to `MAX_CLEANUP_GROUPS` groups, 1 to `MAX_CLEANUP_ENTRIES` names in all.
    pub groups: Vec<Group>,
}

fn sorted_unique(list: &[RecordHash]) -> Vec<RecordHash> {
    let mut v = list.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

fn check_dot(dot: &Dot) -> Result<(), DraftError> {
    if (1..=MAX_COUNTER).contains(&dot.counter) {
        Ok(())
    } else {
        Err(DraftError::Counter(dot.counter))
    }
}

/// Steps 1 and 7 on what a writer just signed, so that it never emits what a
/// reader would refuse.
fn as_reader_would(
    signed: SignedRecord,
    key: &WriteKey,
    keys: &RecordKeys,
) -> Result<SignedRecord, DraftError> {
    let record = Record::parse(signed, key.verifier()).map_err(DraftError::Refused)?;
    record.open(keys).map_err(DraftError::Fault)?;
    Ok(record.into_signed())
}

impl IndexDraft {
    /// The vector sorted ascending by device ID (`keys.md` 5.2 rule 5) and
    /// checked as a reader's step 7 checks it.
    fn vector_entries(&self) -> Result<Vec<VectorEntry>, DraftError> {
        let mut entries = self.meta.vector.entries().to_vec();
        entries.sort_unstable();
        if entries.len() > MAX_VECTOR_ENTRIES {
            return Err(DraftError::Vector(entries.len()));
        }
        if entries
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.device == b.device))
        {
            return Err(DraftError::VectorDuplicate);
        }
        if entries
            .iter()
            .any(|d| d.counter == 0 || d.counter >= self.meta.dot.counter)
        {
            return Err(DraftError::VectorCounter);
        }
        Ok(entries
            .iter()
            .map(|d| VectorEntry {
                device_id: d.device.0.to_vec(),
                counter: d.counter,
            })
            .collect())
    }

    /// Seals the metadata under the folder's record keys and `aad = folder_id
    /// || path_tag`, with 24 fresh bytes from `rng`, encodes the body
    /// canonically (`keys.md` 5.2: `replaces` ascending without repeats, the
    /// vector ascending by device ID) and signs it with the folder key under
    /// `sig/index`. The result passes a reader's steps 1 and 7 (it goes
    /// through both before it is returned): a draft whose metadata fails a
    /// check of step 7 is refused with that fault.
    ///
    /// # Errors
    /// [`DraftError`].
    pub fn sign(
        &self,
        key: &WriteKey,
        keys: &RecordKeys,
        rng: &mut RandomFill<'_>,
    ) -> Result<SignedRecord, DraftError> {
        let folder = key.verifier();
        if keys.folder_id() != folder.folder_id() {
            return Err(DraftError::WrongKeys);
        }
        let replaces = sorted_unique(&self.replaces);
        if replaces.len() > MAX_REPLACES {
            return Err(DraftError::Replaces(replaces.len()));
        }
        check_dot(&self.meta.dot)?;
        let vector = self.vector_entries()?;
        if self.chunks.len() > MAX_CHUNKS {
            return Err(DraftError::Chunks(self.chunks.len()));
        }
        if let Some(c) = self.chunks.iter().find(|c| !is_stored_len(c.stored_len)) {
            return Err(DraftError::StoredLen(c.stored_len));
        }
        let path_tag = keys.path_tag(&self.meta.path);
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
            device_id: self.meta.dot.device.0.to_vec(),
            counter: self.meta.dot.counter,
            vector,
            deleted: self.meta.deleted,
            tree: self.meta.tree,
        }
        .encode_to_vec();
        let sealed = keys
            .seal_index_meta(&path_tag, &meta, rng)
            .map_err(DraftError::Seal)?;
        let body = IndexRecord {
            suite: folder.suite().to_wire(),
            record_type: INDEX_RECORD_TYPE,
            folder_id: folder.folder_id().0.to_vec(),
            chunks: self
                .chunks
                .iter()
                .map(|c| ChunkRef {
                    cipher_hash: c.cipher_hash.0.to_vec(),
                    stored_len: c.stored_len,
                })
                .collect(),
            sealed,
            path_tag: path_tag.0.to_vec(),
            replaces: replaces.iter().map(|h| h.0.to_vec()).collect(),
        }
        .encode_to_vec();
        let signed = key
            .sign_index_record(body)
            .map_err(|e| DraftError::Refused(WireError::Record(e)))?;
        as_reader_would(signed, key, keys)
    }
}

impl CleanupDraft {
    /// Seals the dot as `CleanupMeta` under `aad = folder_id`, encodes the
    /// groups canonically (each group's names ascending without repeats) and
    /// signs the body with the folder key under `sig/cleanup`; the result
    /// passes a reader's steps 1 and 7.
    ///
    /// # Errors
    /// [`DraftError`].
    pub fn sign(
        &self,
        key: &WriteKey,
        keys: &RecordKeys,
        rng: &mut RandomFill<'_>,
    ) -> Result<SignedRecord, DraftError> {
        let folder = key.verifier();
        if keys.folder_id() != folder.folder_id() {
            return Err(DraftError::WrongKeys);
        }
        check_dot(&self.dot)?;
        if self.groups.is_empty() || self.groups.len() > MAX_CLEANUP_GROUPS {
            return Err(DraftError::Groups(self.groups.len()));
        }
        let groups: Vec<CleanupGroup> = self
            .groups
            .iter()
            .map(|g| CleanupGroup {
                because: g.because.map(|b| b.0.to_vec()).unwrap_or_default(),
                forget: sorted_unique(&g.forget)
                    .iter()
                    .map(|h| h.0.to_vec())
                    .collect(),
            })
            .collect();
        let names: usize = groups.iter().map(|g| g.forget.len()).sum();
        if names == 0 || names > MAX_CLEANUP_ENTRIES {
            return Err(DraftError::Names(names));
        }
        let meta = CleanupMeta {
            device_id: self.dot.device.0.to_vec(),
            counter: self.dot.counter,
        }
        .encode_to_vec();
        let sealed = keys
            .seal_cleanup_meta(&meta, rng)
            .map_err(DraftError::Seal)?;
        let body = CleanupRecord {
            suite: folder.suite().to_wire(),
            record_type: CLEANUP_RECORD_TYPE,
            folder_id: folder.folder_id().0.to_vec(),
            groups,
            sealed,
        }
        .encode_to_vec();
        let signed = key
            .sign_cleanup_record(body)
            .map_err(|e| DraftError::Refused(WireError::Record(e)))?;
        as_reader_would(signed, key, keys)
    }
}

#[cfg(test)]
mod tests;
