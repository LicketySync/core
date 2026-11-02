// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Read-only views of the engine's folders, for tests, the simulator's
//! oracle and, later, the local API.
//!
//! Conflicts are the index's (`protocol.md` 4.4, "Heads, display order and
//! conflicts"): a path's heads in display order, the version at the path,
//! deletion, the conflict copies (heads whose content differs from the
//! current one's), and the opaque records at the path, shown as updates this
//! release cannot read. An edit beats a delete (a file head and a tombstone
//! head show the file), and of two different files the one with the greater
//! `mtime_ns` shows and the other is copied beside it. The bases are what
//! this device has on its disk (`crate::sync::disk`).
//!
//! The views' `Debug` prints no path (TM-6); [`FileView::path`] and the
//! copies' names hold them for display and tests.

use core::fmt;

pub use licketysync_index::{Place, RecordState};
use licketysync_keys::chunk::{open_chunk, ChunkError};
use licketysync_keys::{CipherHash, FolderId, RecordHash, Tier};
use licketysync_protocol::record::{Chunk, Dot, Kind, Record};

use crate::engine::Engine;
use crate::folder::{FolderState, OpenCounts};
use crate::runtime::{Instant, Storage};
use crate::store::chunk_key;

/// One held record (live, a tree delete or a cleanup).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordView {
    /// The record hash.
    pub hash: RecordHash,
    /// How this device holds it: applied, opaque (a writer fault) or sealed.
    pub state: RecordState,
    /// A cleanup.
    pub cleanup: bool,
    /// Its dot (writer device ID and counter), for an applied record at a
    /// read or write holder.
    pub dot: Option<Dot>,
    /// The chunks it names, in file order, from its clear part.
    pub chunks: Vec<Chunk>,
}

/// One folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderView {
    /// The folder.
    pub folder: FolderId,
    /// This device's tier.
    pub tier: Tier,
    /// Its state now.
    pub state: FolderState,
    /// The state transitions of this instance: the first (Checking), then
    /// the latest.
    pub transitions: Vec<(Instant, FolderState)>,
    /// What the open found.
    pub open: OpenCounts,
    /// Whether it is proven to peers.
    pub credentialed: bool,
    /// Every record held, in local-sequence order.
    pub records: Vec<RecordView>,
    /// Records held beyond one per file ID (`FolderStatus.extra_versions`).
    pub extra_versions: u64,
    /// The high-water mark: the greatest counter of a record this device
    /// wrote or applied, above which its next write's counter lies; it never
    /// falls (0 at a sealed holder).
    pub hw: u64,
    /// The folder's own time: the greatest counter of an applied record held
    /// (0 at a sealed holder).
    pub folder_time: u64,
    /// The chunks stored, ascending.
    pub stored_chunks: Vec<CipherHash>,
    /// The chunks no held record names any more, freed at the end of the
    /// next round (`protocol.md` 4.7 item 1), ascending.
    pub pending_free: Vec<CipherHash>,
    /// The chunks lacking, ascending.
    pub lacking: Vec<CipherHash>,
    /// Their stored bytes.
    pub bytes_needed: u64,
}

/// One head of a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadView {
    /// The record hash.
    pub hash: RecordHash,
    /// Whether it is a tombstone.
    pub tombstone: bool,
    /// File or directory (for a tombstone, what it deleted).
    pub kind: Kind,
    /// Plaintext bytes.
    pub size: u64,
    /// The writer's modification time.
    pub mtime_ns: i64,
}

impl HeadView {
    /// Whether the head is a file that is not a tombstone: one whose bytes
    /// [`Engine::read_file`] gives.
    #[must_use]
    pub fn is_file(&self) -> bool {
        !self.tombstone && self.kind == Kind::File
    }
}

/// The stored blob of `hash` in `folder`, as this engine's storage layout
/// keeps it, for checks from outside (the simulator's oracle).
///
/// # Errors
/// The storage's own error.
pub fn stored_blob(
    storage: &dyn Storage,
    folder: &FolderId,
    hash: &CipherHash,
) -> Result<Option<Vec<u8>>, crate::runtime::StorageError> {
    storage.get(&chunk_key(folder, hash))
}

/// The name of the conflict copy of `record` beside `path`: the path, then
/// ` (conflict `, the first eight hex digits of the record hash, then `)`
/// (`crate::sync::disk`), for checks from outside (the simulator's oracle).
#[must_use]
pub fn conflict_copy_name(path: &str, record: &RecordHash) -> String {
    crate::sync::disk::copy_name(path, record)
}

/// One path and its heads, for a write or read holder.
#[derive(Clone, PartialEq, Eq)]
pub struct FileView {
    /// The path, for display and tests; `Debug` leaves it out.
    pub path: String,
    /// The heads, in display order.
    pub heads: Vec<HeadView>,
    /// The version at the path: the first head, unless every head is a
    /// tombstone.
    pub current: Option<RecordHash>,
    /// The heads that become conflict copies, in display order.
    pub conflict_copies: Vec<RecordHash>,
    /// Whether the path is deleted.
    pub deleted: bool,
    /// Opaque records at the path, by record hash: updates this release
    /// cannot read.
    pub opaque: Vec<RecordHash>,
    /// What this device has on its disk there: the path itself and each
    /// conflict copy beside it, with the record whose content each holds.
    pub bases: Vec<(Place, RecordHash)>,
}

impl fmt::Debug for FileView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bases: Vec<(bool, RecordHash)> = self
            .bases
            .iter()
            .map(|(p, h)| (matches!(p, Place::Copy(_)), *h))
            .collect();
        f.debug_struct("FileView")
            .field("path", &"[path]")
            .field("heads", &self.heads)
            .field("current", &self.current)
            .field("conflict_copies", &self.conflict_copies)
            .field("deleted", &self.deleted)
            .field("opaque", &self.opaque)
            .field("bases (copy?, record)", &bases)
            .finish()
    }
}

/// Why [`Engine::read_file`] could not give a version's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadError {
    /// No such folder.
    UnknownFolder,
    /// No such record held, or not one of a file.
    NotAFile,
    /// A sealed holder opens nothing.
    Sealed,
    /// The chunk at this position is not stored.
    Missing(CipherHash),
    /// The chunk at this position failed to open for the record.
    Corrupt(ChunkError),
    /// The chunks open but do not add up to the record's size.
    SizeMismatch,
    /// The storage could not be read.
    Storage,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFolder => f.write_str("no such folder"),
            Self::NotAFile => f.write_str("no file version held under that record"),
            Self::Sealed => f.write_str("a sealed holder cannot open the folder's chunks"),
            Self::Missing(hash) => write!(f, "chunk {hash} is not stored"),
            Self::Corrupt(e) => write!(f, "a chunk failed to open: {e}"),
            Self::SizeMismatch => f.write_str("the chunks do not add up to the file's size"),
            Self::Storage => f.write_str("the storage could not be read"),
        }
    }
}

impl std::error::Error for ReadError {}

impl Engine {
    /// The folders this device holds, ascending.
    pub fn folder_ids(&self) -> impl Iterator<Item = FolderId> + '_ {
        self.folders.keys().copied()
    }

    /// The view of `folder`.
    #[must_use]
    pub fn folder(&self, folder: &FolderId) -> Option<FolderView> {
        let f = self.folders.get(folder)?;
        Some(FolderView {
            folder: *folder,
            tier: f.tier,
            state: f.state,
            transitions: f.transitions.list(),
            open: f.open,
            credentialed: f.credentialed(),
            records: f
                .index
                .records()
                .map(|r| RecordView {
                    hash: r.hash,
                    state: r.state,
                    cleanup: r.cleanup,
                    dot: r.dot,
                    chunks: f
                        .index
                        .signed(&r.hash)
                        .and_then(|s| Record::parse(s.clone(), f.index.key().verifier()).ok())
                        .map(|rec| rec.chunks().to_vec())
                        .unwrap_or_default(),
                })
                .collect(),
            extra_versions: f.index.extra_versions(),
            hw: f.index.hw(),
            folder_time: f.index.folder_time(),
            stored_chunks: f.book.stored().iter().copied().collect(),
            pending_free: f.pending_free.iter().copied().collect(),
            lacking: f.book.lacking().iter().copied().collect(),
            bytes_needed: f.book.bytes_needed(),
        })
    }

    /// The high-water mark of `folder` ([`FolderView::hw`]), cheaply.
    #[must_use]
    pub fn high_water(&self, folder: &FolderId) -> Option<u64> {
        self.folders.get(folder).map(|f| f.index.hw())
    }

    /// What this device has on its disk at `path` of `folder` (the path
    /// itself and the conflict copies beside it), whether or not the path
    /// has heads: a removed file's base shows here until it goes.
    #[must_use]
    pub fn bases(&self, folder: &FolderId, path: &str) -> Vec<(Place, RecordHash)> {
        self.folders
            .get(folder)
            .map(|f| f.index.bases(path))
            .unwrap_or_default()
    }

    /// Every base slot of `folder` at or beneath `dir` (`""` for all), in
    /// path order: the path of its base record, its place, its record;
    /// whether or not the path has heads (a tree delete's own, or one a
    /// tree delete should have cleared). None at a sealed holder.
    #[must_use]
    pub fn bases_beneath(&self, folder: &FolderId, dir: &str) -> Vec<(String, Place, RecordHash)> {
        self.folders
            .get(folder)
            .map(|f| {
                f.index
                    .bases_beneath(dir)
                    .map(|(p, place, h)| (p.to_owned(), place.clone(), *h))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The dot of the record `record` of `folder`, when it is held and
    /// applied ([`RecordView::dot`]).
    #[must_use]
    pub fn dot(&self, folder: &FolderId, record: &RecordHash) -> Option<Dot> {
        self.folders.get(folder)?.index.record(record)?.dot
    }

    /// Every path of `folder` with heads, in path order (none for a sealed
    /// holder, which computes no heads).
    #[must_use]
    pub fn files(&self, folder: &FolderId) -> Vec<FileView> {
        let Some(f) = self.folders.get(folder) else {
            return Vec::new();
        };
        f.index
            .paths()
            .filter_map(|p| f.index.path(p))
            .map(|v| FileView {
                bases: f.index.bases(&v.path),
                heads: v
                    .heads
                    .iter()
                    .map(|h| HeadView {
                        hash: h.hash,
                        tombstone: h.tombstone,
                        kind: h.kind,
                        size: h.size,
                        mtime_ns: h.mtime_ns,
                    })
                    .collect(),
                current: v.current,
                conflict_copies: v.conflict_copies,
                deleted: v.deleted,
                opaque: v.opaque,
                path: v.path,
            })
            .collect()
    }

    /// The bytes of one version of a file, any head, reassembled from
    /// `storage`: each chunk opened against the plaintext hash at its
    /// position, then the size checked (TM-13). What the simulator's oracle
    /// uses.
    ///
    /// # Errors
    /// [`ReadError`].
    pub fn read_file(
        &self,
        storage: &dyn Storage,
        folder: &FolderId,
        record: &RecordHash,
    ) -> Result<Vec<u8>, ReadError> {
        let f = self.folders.get(folder).ok_or(ReadError::UnknownFolder)?;
        let keys = f.chunk_keys.as_ref().ok_or(ReadError::Sealed)?;
        let file = f.index.file(record).ok_or(ReadError::NotAFile)?;
        let mut out = Vec::new();
        for (i, c) in file.chunks.iter().enumerate() {
            let blob = storage
                .get(&chunk_key(folder, &c.cipher_hash))
                .map_err(|_| ReadError::Storage)?
                .ok_or(ReadError::Missing(c.cipher_hash))?;
            let plain = file.plain_hashes.get(i).ok_or(ReadError::NotAFile)?;
            let raw = open_chunk(keys, &blob, plain).map_err(ReadError::Corrupt)?;
            out.extend_from_slice(&raw);
        }
        if out.len() as u64 != file.size {
            return Err(ReadError::SizeMismatch);
        }
        Ok(out)
    }

    /// Feeds `out` what peers that have converged on `folder` agree on (4.7
    /// item 6, "Conflicts"): the root set digest, equal on every tier for
    /// equal records, then, at a read or write holder, each path's heads by
    /// hash in display order. The simulator hashes it for its cheap
    /// convergence predicate; no path is fed.
    pub fn fingerprint(&self, folder: &FolderId, out: &mut dyn FnMut(&[u8])) {
        if let Some(f) = self.folders.get(folder) {
            f.index.fingerprint(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_read_error_displays_and_is_an_error() {
        for e in [
            ReadError::UnknownFolder,
            ReadError::NotAFile,
            ReadError::Sealed,
            ReadError::Missing(CipherHash([1; 32])),
            ReadError::Corrupt(ChunkError::Open),
            ReadError::SizeMismatch,
            ReadError::Storage,
        ] {
            let as_error: &dyn std::error::Error = &e;
            assert_ne!(as_error.to_string(), "");
        }
    }

    #[test]
    fn a_file_views_debug_names_no_path_and_no_copy_name() {
        let v = FileView {
            path: "secret/name.txt".into(),
            heads: vec![],
            current: None,
            conflict_copies: vec![],
            deleted: false,
            opaque: vec![],
            bases: vec![(
                Place::Copy("secret/name.txt (conflict 01)".into()),
                RecordHash([1; 32]),
            )],
        };
        let text = format!("{v:?}");
        assert!(!text.contains("secret"), "{text}");
    }
}
