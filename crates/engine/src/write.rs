// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Local writes in the simulator's file model, where a folder's files are its
//! bases plus its chunk store (there is no disk in phase 0; the scanner,
//! journals, the path resolver and atomic writes are phase 1's, TM-4, TM-35;
//! `crate::sync::disk`).
//!
//! Each write is a handler of its own, with the same three phases as any
//! other ([`crate::work`]), called by the harness from its own timers:
//!
//! 1. It refuses up front, recording nothing and sending nothing, for a read
//!    or sealed key (`keys.md` 1.3: it cannot sign), a folder paused, kept
//!    closed or not usable, or a path that `check_path` refuses. NFC is the
//!    caller's duty in phase 0 (gap G8: no normaliser is in the dependency
//!    set; the workloads use ASCII; phase 1's scanner adds one).
//! 2. A file is cut into fixed-size chunks of `chunk_size` (decision:
//!    `FastCDC` is phase 1, a recorded deviation from `keys.md` 3.2), and an
//!    empty file has none. Each chunk is sealed by the keys crate
//!    (`seal_chunk`: convergent, Padmé-padded, TM-12, TM-15).
//! 3. The change, built from what is on the disk, never from what the index
//!    holds (4.4, "The vector and names of a new record"; 4.7 item 6): an
//!    edit, a delete (a tombstone taking the kind of the base it deletes) or
//!    a new file is a put at the path; a rename is a put at the new path with
//!    the old path's base content, then a tombstone at the old path; deleting
//!    a directory is one tree delete of it. The index builds every vector
//!    from the path's bases and their twins (the heads of a base's content
//!    concurrent with it and, at the path, after it in display order, never
//!    the first head), so a version still arriving (not yet a base, its
//!    content not on the disk, or a later version of a base with its
//!    content) stays a head beside the write: a conflict, never a silent
//!    loss, while a twin is covered with its base. A write over a conflict
//!    first writes each conflict copy on the disk as a version at its own
//!    path (`Change::Promote`), in the same commit, so it becomes an
//!    ordinary file (4.4, "What becomes of a conflict copy").
//! 4. In phase B the index signs the records (`Txn::write`, counters from the
//!    high-water mark and the wall clock), and each blob that is not stored
//!    as it should be is staged then: a blob the book counts as stored is
//!    read back first, and one that changed at rest (TM-10) is staged again,
//!    with an issue, so that the new record never names a blob this device
//!    cannot serve; one that cannot be read is staged again too, counted,
//!    with no issue. Everything is committed, and only then pushed to every
//!    connection where the folder is open. A failed put or commit rolls back
//!    and pauses the folder, and the write returns [`WriteFailure::Store`]
//!    with nothing sent.

use core::fmt;
use std::collections::BTreeSet;

use licketysync_index::{Change, Place, Put, WriteError};
use licketysync_keys::chunk::{seal_chunk, SealedChunk};
use licketysync_keys::{CipherHash, FolderId, RecordHash};
use licketysync_protocol::limits::MAX_CHUNKS;
use licketysync_protocol::record::{check_path, Chunk, Kind, PathError};

use crate::engine::Engine;
use crate::issues::{bump, Issue, IssueKind, StoreFailureCause, Subject};
use crate::runtime::Context;
use crate::store::chunk_key;
use crate::sync::Op;
use crate::work::Work;

/// Why a write made no record. Nothing was staged or sent, but for
/// [`WriteFailure::Store`], whose staging was rolled back. No variant carries
/// a path (TM-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteFailure {
    /// No such folder.
    UnknownFolder,
    /// This device holds the read or sealed key, which cannot sign
    /// (`keys.md` 1.3; the index's `WriteError::NotWriteKey`).
    NotWriteKey,
    /// The folder is paused for a store failure, or kept closed by the
    /// clock rule.
    Paused,
    /// The folder is misconfigured or its store unreadable.
    NotUsable,
    /// The path breaks the grammar of `SealedMeta.path` (4.4).
    Path(PathError),
    /// A delete or a rename of a path with nothing on the disk.
    NoSuchPath,
    /// More chunks than a record may name (`MAX_CHUNKS`).
    TooLarge,
    /// The next counter would pass `MAX_COUNTER`: the folder must be shared
    /// again (4.4, section 5).
    CounterExhausted,
    /// A put or the commit failed: the folder is paused.
    Store(StoreFailureCause),
    /// The index or the keys crate refused what the engine built: an engine
    /// bug, counted.
    Internal,
}

impl fmt::Display for WriteFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFolder => f.write_str("no such folder"),
            Self::NotWriteKey => f.write_str("this device holds no write key for the folder"),
            Self::Paused => f.write_str("the folder is paused"),
            Self::NotUsable => f.write_str("the folder cannot be used"),
            Self::Path(e) => write!(f, "{e}"),
            Self::NoSuchPath => f.write_str("nothing is on the disk at that path"),
            Self::TooLarge => f.write_str("the file needs more chunks than a record names"),
            Self::CounterExhausted => {
                f.write_str("the folder's counter is exhausted: share it again")
            }
            Self::Store(c) => write!(f, "the store failed ({c:?})"),
            Self::Internal => f.write_str("internal error"),
        }
    }
}

impl std::error::Error for WriteFailure {}

/// The index's refusal as a write failure.
pub(crate) fn write_error(e: &WriteError) -> WriteFailure {
    match e {
        WriteError::NotWriteKey => WriteFailure::NotWriteKey,
        WriteError::CounterExhausted => WriteFailure::CounterExhausted,
        WriteError::Path(p) => WriteFailure::Path(*p),
        _ => WriteFailure::Internal,
    }
}

/// What a write is.
#[derive(Clone, Copy, Debug)]
enum Edit<'a> {
    File { path: &'a str, content: &'a [u8] },
    Delete { path: &'a str },
    Rename { from: &'a str, to: &'a str },
    Mkdir { path: &'a str },
}

impl Edit<'_> {
    /// The path whose version the write returns.
    fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Delete { path } | Self::Mkdir { path } => path,
            Self::Rename { to, .. } => to,
        }
    }
}

/// The plaintext pieces of `content`: fixed-size chunks of `chunk_size`
/// bytes, the last one shorter; none for an empty file.
pub(crate) fn cut(content: &[u8], chunk_size: usize) -> impl Iterator<Item = &[u8]> + '_ {
    content.chunks(chunk_size.max(1))
}

impl Engine {
    /// Writes `content` at `path` (module documentation).
    ///
    /// # Errors
    /// [`WriteFailure`].
    pub fn write_file(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        path: &str,
        content: &[u8],
        mtime_ns: i64,
    ) -> Result<RecordHash, WriteFailure> {
        self.write(cx, folder, Edit::File { path, content }, mtime_ns)
    }

    /// Deletes what is on the disk at `path`: a tombstone for a file, one
    /// tree delete for a directory and everything beneath it (4.4, "Tree
    /// deletes").
    ///
    /// # Errors
    /// [`WriteFailure`].
    pub fn delete(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        path: &str,
        mtime_ns: i64,
    ) -> Result<RecordHash, WriteFailure> {
        self.write(cx, folder, Edit::Delete { path }, mtime_ns)
    }

    /// Renames `from` to `to`: a version at `to` with the content of `from`'s
    /// base, then a tombstone at `from`, in one commit (4.7 item 6).
    ///
    /// # Errors
    /// [`WriteFailure`].
    pub fn rename(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        from: &str,
        to: &str,
        mtime_ns: i64,
    ) -> Result<RecordHash, WriteFailure> {
        self.write(cx, folder, Edit::Rename { from, to }, mtime_ns)
    }

    /// Makes a directory at `path`.
    ///
    /// # Errors
    /// [`WriteFailure`].
    pub fn mkdir(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        path: &str,
        mtime_ns: i64,
    ) -> Result<RecordHash, WriteFailure> {
        self.write(cx, folder, Edit::Mkdir { path }, mtime_ns)
    }

    fn write(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        op: Edit<'_>,
        mtime_ns: i64,
    ) -> Result<RecordHash, WriteFailure> {
        let (queued, mut work) =
            self.run(cx, |e, cx, w| e.decide_write(cx, w, folder, op, mtime_ns));
        let result = queued.and_then(|()| {
            work.sync
                .written
                .take()
                .unwrap_or(Err(WriteFailure::Internal))
        });
        if result.is_err() {
            bump(&mut self.counters.writes_refused);
        }
        if result == Err(WriteFailure::Internal) {
            self.counters.bug();
        }
        result
    }

    /// Steps 1 to 3 of the module documentation, in phase A: the write is
    /// queued for phase B.
    fn decide_write(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
        op: Edit<'_>,
        mtime_ns: i64,
    ) -> Result<(), WriteFailure> {
        self.refuse_up_front(folder, &op)?;
        let (mut changes, blobs, target) = self.changes(cx, folder, op, mtime_ns)?;
        let promotes = self.promotions(folder, &op);
        promotes
            .into_iter()
            .rev()
            .for_each(|c| changes.insert(0, c));
        work.wrote = true;
        work.sync.queue(
            folder,
            Op::Write {
                changes,
                blobs,
                target,
            },
        );
        Ok(())
    }

    fn refuse_up_front(&self, folder: FolderId, op: &Edit<'_>) -> Result<(), WriteFailure> {
        let f = self
            .folders
            .get(&folder)
            .ok_or(WriteFailure::UnknownFolder)?;
        if f.index.key().write_key().is_none() {
            return Err(WriteFailure::NotWriteKey);
        }
        if !f.usable() {
            return Err(WriteFailure::NotUsable);
        }
        if f.held_paused() {
            return Err(WriteFailure::Paused);
        }
        check_path(op.path()).map_err(WriteFailure::Path)?;
        if let Edit::Rename { from, .. } = op {
            check_path(from).map_err(WriteFailure::Path)?;
        }
        Ok(())
    }

    /// The changes of `op` from the disk, the blobs to stage, and the path
    /// whose version the write returns.
    #[allow(clippy::type_complexity, reason = "one write's three parts")]
    fn changes(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        op: Edit<'_>,
        mtime_ns: i64,
    ) -> Result<(Vec<Change>, Vec<SealedChunk>, Option<String>), WriteFailure> {
        let f = self
            .folders
            .get(&folder)
            .ok_or(WriteFailure::UnknownFolder)?;
        let put = |path: &str, kind, size, chunks, plain_hashes, deleted| Put {
            path: path.to_owned(),
            kind,
            size,
            mtime_ns,
            mode: 0,
            chunks,
            plain_hashes,
            deleted,
        };
        let target = Some(op.path().to_owned());
        match op {
            Edit::Mkdir { path } => Ok((
                vec![Change::Put(put(
                    path,
                    Kind::Directory,
                    0,
                    vec![],
                    vec![],
                    false,
                ))],
                vec![],
                target,
            )),
            Edit::Delete { path } => {
                let base = f
                    .index
                    .current(path)
                    .filter(|c| !c.deleted)
                    .ok_or(WriteFailure::NoSuchPath)?;
                if base.kind == Kind::Directory {
                    return Ok((
                        vec![Change::TreeDelete {
                            path: path.to_owned(),
                            mtime_ns,
                        }],
                        vec![],
                        None,
                    ));
                }
                Ok((
                    vec![Change::Put(put(path, base.kind, 0, vec![], vec![], true))],
                    vec![],
                    target,
                ))
            }
            Edit::Rename { from, to } => {
                let base = f
                    .index
                    .current(from)
                    .filter(|c| !c.deleted)
                    .ok_or(WriteFailure::NoSuchPath)?;
                Ok((
                    vec![Change::Rename {
                        from: from.to_owned(),
                        to: put(
                            to,
                            base.kind,
                            base.size,
                            base.chunks,
                            base.plain_hashes,
                            false,
                        ),
                    }],
                    vec![],
                    target,
                ))
            }
            Edit::File { path, content } => {
                let (chunks, plain_hashes, blobs) = self.seal(cx, folder, content)?;
                Ok((
                    vec![Change::Put(put(
                        path,
                        Kind::File,
                        content.len() as u64,
                        chunks,
                        plain_hashes,
                        false,
                    ))],
                    blobs,
                    target,
                ))
            }
        }
    }

    /// The conflict copies on the disk at the paths `op` writes, each written
    /// as a version at its own path first (4.4, "What becomes of a conflict
    /// copy").
    fn promotions(&self, folder: FolderId, op: &Edit<'_>) -> Vec<Change> {
        let Some(f) = self.folders.get(&folder) else {
            return Vec::new();
        };
        let paths: Vec<&str> = match op {
            Edit::Rename { from, to } => vec![*from, *to],
            _ => vec![op.path()],
        };
        let mut out = Vec::new();
        for path in paths {
            let heads = f.index.path(path).map(|v| v.heads).unwrap_or_default();
            for (place, record) in f.index.bases(path) {
                let Place::Copy(name) = place else {
                    continue;
                };
                let Some(head) = heads.iter().find(|h| h.hash == record) else {
                    continue;
                };
                let content = f.index.file(&record);
                out.push(Change::Promote {
                    from: path.to_owned(),
                    copy: name.clone(),
                    to: Put {
                        path: name,
                        kind: head.kind,
                        size: head.size,
                        mtime_ns: head.mtime_ns,
                        mode: 0,
                        chunks: content
                            .as_ref()
                            .map(|c| c.chunks.clone())
                            .unwrap_or_default(),
                        plain_hashes: content.map(|c| c.plain_hashes).unwrap_or_default(),
                        deleted: false,
                    },
                });
            }
        }
        out
    }

    /// A file's chunks sealed, and the blobs among them not stored as they
    /// are (module documentation, step 4).
    #[allow(clippy::type_complexity, reason = "the chunks, their hashes and blobs")]
    fn seal(
        &mut self,
        cx: &mut dyn Context,
        folder: FolderId,
        content: &[u8],
    ) -> Result<
        (
            Vec<Chunk>,
            Vec<licketysync_keys::chunk::PlainHash>,
            Vec<SealedChunk>,
        ),
        WriteFailure,
    > {
        let chunk_size = self.settings.chunk_size;
        if content.len().div_ceil(chunk_size) > MAX_CHUNKS {
            return Err(WriteFailure::TooLarge);
        }
        let f = self
            .folders
            .get(&folder)
            .ok_or(WriteFailure::UnknownFolder)?;
        let keys = f.chunk_keys.as_ref().ok_or(WriteFailure::NotWriteKey)?;
        let sealed: Vec<SealedChunk> = cut(content, chunk_size)
            .map(|raw| seal_chunk(keys, raw))
            .collect::<Result<_, _>>()
            .map_err(|_| WriteFailure::Internal)?;
        let mut chunks = Vec::with_capacity(sealed.len());
        let mut plain_hashes = Vec::with_capacity(sealed.len());
        let mut changed: Vec<CipherHash> = Vec::new();
        let mut blobs = Vec::new();
        let mut seen = BTreeSet::new();
        for s in sealed {
            chunks.push(Chunk {
                cipher_hash: s.cipher_hash,
                stored_len: u32::try_from(s.stored.len()).map_err(|_| WriteFailure::Internal)?,
            });
            plain_hashes.push(s.plain_hash);
            if f.book.is_stored(&s.cipher_hash) {
                match cx.storage().get(&chunk_key(&folder, &s.cipher_hash)) {
                    Ok(Some(b)) if b == s.stored => continue,
                    Ok(_) => changed.push(s.cipher_hash),
                    // No sign it changed: staged again, no issue.
                    Err(_) => bump(&mut self.counters.read_errors),
                }
            }
            if seen.insert(s.cipher_hash) {
                blobs.push(s);
            }
        }
        for hash in changed {
            self.issues.raise(Issue {
                folder: Some(folder),
                kind: IssueKind::LocalChunkCorrupt,
                subject: Subject::Chunk(hash),
            });
        }
        Ok((chunks, plain_hashes, blobs))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Any content cuts into chunks that join back to it, of the size
        /// asked but the last, and as many as the size says.
        #[test]
        fn fixed_size_chunks_reassemble(content in proptest::collection::vec(any::<u8>(), 0..5_000), size in 1usize..700) {
            let pieces: Vec<&[u8]> = cut(&content, size).collect();
            prop_assert_eq!(pieces.concat(), content.clone());
            prop_assert_eq!(pieces.len(), content.len().div_ceil(size));
            if let Some((last, rest)) = pieces.split_last() {
                prop_assert!(rest.iter().all(|p| p.len() == size));
                prop_assert!(!last.is_empty() && last.len() <= size);
            }
        }
    }

    #[test]
    fn an_empty_file_has_no_chunks() {
        assert_eq!(cut(&[], 10).count(), 0);
        assert_eq!(cut(&[1], 10).count(), 1);
    }

    #[test]
    fn every_write_failure_displays() {
        for e in [
            WriteFailure::UnknownFolder,
            WriteFailure::NotWriteKey,
            WriteFailure::Paused,
            WriteFailure::NotUsable,
            WriteFailure::Path(PathError::Empty),
            WriteFailure::NoSuchPath,
            WriteFailure::TooLarge,
            WriteFailure::CounterExhausted,
            WriteFailure::Store(StoreFailureCause::Full),
            WriteFailure::Internal,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    #[test]
    fn index_refusals_map_to_write_failures() {
        assert_eq!(
            write_error(&WriteError::NotWriteKey),
            WriteFailure::NotWriteKey
        );
        assert_eq!(
            write_error(&WriteError::CounterExhausted),
            WriteFailure::CounterExhausted
        );
        assert_eq!(
            write_error(&WriteError::DuplicatePath("a".into())),
            WriteFailure::Internal
        );
    }
}
