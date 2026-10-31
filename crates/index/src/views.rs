// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the engine reads of a folder's index (`protocol.md` 4.4 "Heads,
//! display order and conflicts", "Bases"; 4.7 items 5 and 6): the
//! heads of each path in display order with the version at the path and the
//! conflict copies, the opaque records after them, the record and file views,
//! the chunks the folder wants and which hashes held records name, the
//! `extra_versions` of Status, the fingerprint the simulator compares, and
//! the bases the engine names.

use core::cmp::Reverse;
use core::fmt;
use std::collections::BTreeSet;

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::{CipherHash, PathTag, RecordHash, Tier};
use licketysync_protocol::record::{Chunk, Dot, Kind, Meta};

use crate::index::{Index, Txn};
use crate::state::BaseRecord;
use crate::store::{BaseSlot, Place};

/// One head of a path, in display order (4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The record.
    pub hash: RecordHash,
    /// A tombstone.
    pub tombstone: bool,
    /// File or directory.
    pub kind: Kind,
    /// Bytes of content.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
}

/// One path as a read or write holder sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathView {
    /// The path.
    pub path: String,
    /// Its heads in display order: non-tombstones first, directories before
    /// files; tombstones last, their kind not compared; then the greater
    /// `mtime_ns`; then the smaller record hash.
    pub heads: Vec<Head>,
    /// The first head that is not a tombstone, which sits at the path; `None`
    /// when every head is a tombstone (the path is deleted) or there is none.
    pub current: Option<RecordHash>,
    /// Every other head that is not a tombstone and whose content differs
    /// from the current one's (another kind, or other plaintext hashes).
    pub conflict_copies: Vec<RecordHash>,
    /// Every head is a tombstone.
    pub deleted: bool,
    /// Opaque records live at the path's tag, after every head, by ascending
    /// record hash: shown as updates this release cannot read.
    pub opaque: Vec<RecordHash>,
}

/// What a record is to this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordState {
    /// Applied: step 7 found nothing wrong.
    Applied,
    /// Held opaque: a writer fault.
    Opaque,
    /// Held unopened, at a sealed holder.
    Sealed,
}

/// One held record, for the engine's views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordView {
    /// The record.
    pub hash: RecordHash,
    /// How this device holds it.
    pub state: RecordState,
    /// Its local sequence number.
    pub seq: u64,
    /// Its dot, for an applied record at a read or write holder.
    pub dot: Option<Dot>,
    /// A cleanup.
    pub cleanup: bool,
}

/// A file version's content, by record hash, for reassembly.
#[derive(Clone, Debug)]
pub struct FileContent {
    /// The chunks in file order.
    pub chunks: Vec<Chunk>,
    /// The plaintext hash per chunk.
    pub plain_hashes: Vec<PlainHash>,
    /// Bytes of content.
    pub size: u64,
}

/// The base at a path, for a rename's content and the kind a delete takes.
#[derive(Clone, Debug)]
pub struct Current {
    /// The base record.
    pub hash: RecordHash,
    /// File or directory.
    pub kind: Kind,
    /// Bytes of content.
    pub size: u64,
    /// The chunks.
    pub chunks: Vec<Chunk>,
    /// The plaintext hashes.
    pub plain_hashes: Vec<PlainHash>,
    /// A deletion.
    pub deleted: bool,
}

/// One chunk a wanted record names.
#[derive(Clone, Copy, Debug)]
pub struct WantedChunk {
    /// The ciphertext hash.
    pub hash: CipherHash,
    /// The stored length the record names.
    pub stored_len: u32,
    /// The plaintext hash at its position, for an applied record at a read
    /// or write holder.
    pub plain: Option<PlainHash>,
}

/// A held record whose chunks the folder wants (4.7 item 5).
#[derive(Clone, Debug)]
pub struct Wanted {
    /// The record.
    pub record: RecordHash,
    /// Its chunks in file order.
    pub chunks: Vec<WantedChunk>,
    /// The file's size, for an applied record at a read or write holder.
    pub size: Option<u64>,
}

/// Why a base could not be set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BaseError {
    /// This device keeps no bases: a sealed holder puts nothing on disk.
    Sealed,
    /// The record is neither held nor kept as a base here.
    Unknown,
    /// The record is not applied (opaque records are never bases).
    NotApplied,
    /// The record lies at another path.
    OtherPath,
}

impl fmt::Display for BaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sealed => "a sealed holder keeps no bases",
            Self::Unknown => "the record is not held here",
            Self::NotApplied => "an opaque record is never a base",
            Self::OtherPath => "the record lies at another path",
        })
    }
}

impl std::error::Error for BaseError {}

/// The display order's key (4.4), for heads and for `S` alike:
/// non-tombstones first, directories before files, tombstones last; then
/// the greater `mtime_ns`; then the smaller record hash.
pub(crate) fn display_rank(hash: &RecordHash, m: &Meta) -> (bool, bool, Reverse<i64>, RecordHash) {
    (
        m.deleted,
        !m.deleted && m.kind == Kind::File,
        Reverse(m.mtime_ns),
        *hash,
    )
}

/// Whether two heads' contents differ: another kind, or, between two files,
/// other plaintext hashes (compared in constant time, each pair).
fn differs(a: &Meta, b: &Meta) -> bool {
    if a.kind != b.kind {
        return true;
    }
    if a.kind == Kind::Directory {
        return false;
    }
    a.plain_hashes.len() != b.plain_hashes.len()
        || a.plain_hashes
            .iter()
            .zip(&b.plain_hashes)
            .any(|(x, y)| !bool::from(x.ct_eq(y)))
}

impl Index {
    /// The heads and opaque records at a tag.
    fn view_at(&self, tag: &PathTag, path: &str) -> PathView {
        let mut heads: Vec<(RecordHash, &Meta)> = Vec::new();
        let mut opaque = Vec::new();
        for h in self.s.at_tag.get(tag).into_iter().flatten() {
            let Some(held) = self.s.held.get(h) else {
                continue;
            };
            match held.meta() {
                Some(m) if !m.tree => heads.push((*h, m)),
                Some(_) => {}
                None => opaque.push(*h),
            }
        }
        heads.sort_by_key(|(h, m)| display_rank(h, m));
        let current = heads.iter().find(|(_, m)| !m.deleted).copied();
        let conflict_copies = match current {
            Some((ch, cm)) => heads
                .iter()
                .filter(|(h, m)| *h != ch && !m.deleted && differs(cm, m))
                .map(|(h, _)| *h)
                .collect(),
            None => Vec::new(),
        };
        PathView {
            path: path.to_owned(),
            deleted: !heads.is_empty() && current.is_none(),
            current: current.map(|(h, _)| h),
            conflict_copies,
            heads: heads
                .iter()
                .map(|(h, m)| Head {
                    hash: *h,
                    tombstone: m.deleted,
                    kind: m.kind,
                    size: m.size,
                    mtime_ns: m.mtime_ns,
                })
                .collect(),
            opaque,
        }
    }

    /// The path `path` (read and write holders; `None` at a sealed holder).
    #[must_use]
    pub fn path(&self, path: &str) -> Option<PathView> {
        let tag = self.keys.as_ref()?.path_tag(path);
        Some(self.view_at(&tag, path))
    }

    /// Every path that has heads, in path order.
    pub fn paths(&self) -> impl Iterator<Item = &str> + '_ {
        self.s
            .paths
            .iter()
            .filter(|(_, hs)| self.holds_a_version(hs))
            .map(|(p, _)| p.as_str())
    }

    /// The paths at or beneath `dir` that [`Index::paths`] gives, in path
    /// order: two ranges of the paths by name (`dir` itself, then `dir/` up
    /// to `dir0`; the root, `""`, is every path), so that the engine holding
    /// a tree delete of `dir` reads what lies beneath it, never every path
    /// (TM-22).
    pub fn paths_at_or_beneath<'a>(&'a self, dir: &str) -> impl Iterator<Item = &'a str> + 'a {
        self.s
            .paths_at_or_beneath(dir)
            .filter(|(_, hs)| self.holds_a_version(hs))
            .map(|(p, _)| p.as_str())
    }

    /// The base slots at or beneath `dir`, in path order (a path's slots
    /// in [`Place`] order, its own first): each slot's path (its base
    /// record's), its place and its base record. The root, `""`, is every
    /// slot. A slot is listed whether or not its path has heads, so that a
    /// base without a head, kept only as a base, can be seen from outside
    /// the index; the slots come from the path-ordered index of the slots,
    /// two ranges by path (`dir` itself, then `dir/` up to `dir0`), never a
    /// walk of every slot. A sealed holder keeps none.
    pub fn bases_beneath<'a>(
        &'a self,
        dir: &str,
    ) -> impl Iterator<Item = (&'a str, &'a Place, &'a RecordHash)> + 'a {
        self.s
            .base_slots_at_or_beneath(dir)
            .map(|(path, slot, hash)| (path, &slot.1, hash))
    }

    /// Whether one of `hashes` is an applied record held that is not a tree
    /// delete.
    fn holds_a_version(&self, hashes: &BTreeSet<RecordHash>) -> bool {
        hashes.iter().any(|h| {
            self.s
                .held
                .get(h)
                .and_then(|r| r.meta())
                .is_some_and(|m| !m.tree)
        })
    }

    /// Every held record, in local-sequence order.
    pub fn records(&self) -> impl Iterator<Item = RecordView> + '_ {
        self.s.by_seq.values().filter_map(|h| self.record(h))
    }

    /// One held record.
    #[must_use]
    pub fn record(&self, hash: &RecordHash) -> Option<RecordView> {
        let held = self.s.held.get(hash)?;
        let state = match &held.verdict {
            None => RecordState::Sealed,
            Some(Ok(_)) => RecordState::Applied,
            Some(Err(_)) => RecordState::Opaque,
        };
        Some(RecordView {
            hash: *hash,
            state,
            seq: held.seq,
            dot: held.applied().map(|a| *a.dot()),
            cleanup: held.record.is_cleanup(),
        })
    }

    /// The held record itself, as received.
    #[must_use]
    pub fn signed(&self, hash: &RecordHash) -> Option<&licketysync_keys::records::SignedRecord> {
        self.s.held.get(hash).map(|h| h.record.signed())
    }

    /// The writer fault of an opaque record held.
    #[must_use]
    pub fn fault(&self, hash: &RecordHash) -> Option<&licketysync_protocol::record::WriterFault> {
        self.s.held.get(hash)?.verdict.as_ref()?.as_ref().err()
    }

    /// The content of an applied file version held (any head).
    #[must_use]
    pub fn file(&self, hash: &RecordHash) -> Option<FileContent> {
        let held = self.s.held.get(hash)?;
        let m = held.meta()?;
        (m.kind == Kind::File && !m.deleted).then(|| FileContent {
            chunks: held.record.chunks().to_vec(),
            plain_hashes: m.plain_hashes.clone(),
            size: m.size,
        })
    }

    /// The base at `path` (its `Place::Path` slot), for a rename's content
    /// and the kind a delete takes.
    #[must_use]
    pub fn current(&self, path: &str) -> Option<Current> {
        let tag = self.keys.as_ref()?.path_tag(path);
        let hash = *self.s.bases.get(&(tag, Place::Path))?;
        let m = self.s.base_meta(&hash)?;
        let record = self.s.base_record(&hash)?;
        Some(Current {
            hash,
            kind: m.kind,
            size: m.size,
            chunks: record.chunks().to_vec(),
            plain_hashes: m.plain_hashes.clone(),
            deleted: m.deleted,
        })
    }

    /// The bases at `path`: each place and its record.
    #[must_use]
    pub fn bases(&self, path: &str) -> Vec<(Place, RecordHash)> {
        let Some(tag) = self.keys.as_ref().map(|k| k.path_tag(path)) else {
            return Vec::new();
        };
        self.s
            .bases_at(&tag)
            .into_iter()
            .map(|((_, place), h)| (place, h))
            .collect()
    }

    /// The records whose chunks the folder wants (4.7 item 5): every held
    /// record with chunks (at a key holder every head of a conflict and the
    /// opaque records too, which it keeps to serve to a release that reads
    /// them; their plaintext hashes are not to be trusted, so none is given).
    #[must_use]
    pub fn wanted(&self) -> Vec<Wanted> {
        self.s
            .by_seq
            .values()
            .filter_map(|h| self.s.held.get(h))
            .filter(|held| !held.record.chunks().is_empty())
            .map(|held| {
                let meta = held.meta();
                Wanted {
                    record: held.record.hash(),
                    chunks: held
                        .record
                        .chunks()
                        .iter()
                        .enumerate()
                        .map(|(i, c)| WantedChunk {
                            hash: c.cipher_hash,
                            stored_len: c.stored_len,
                            plain: meta.and_then(|m| m.plain_hashes.get(i).copied()),
                        })
                        .collect(),
                    size: meta.map(|m| m.size),
                }
            })
            .collect()
    }

    /// Whether a held record names this chunk: what this device may serve
    /// when it stores the blob, and the re-check before a pending free.
    #[must_use]
    pub fn names_chunk(&self, hash: &CipherHash) -> bool {
        self.s.chunks.contains_key(hash)
    }

    /// `FolderStatus.extra_versions` (4.5): at a sealed holder the index
    /// records it holds beyond one per file ID; at a read or write holder the
    /// extra heads of its conflicts, that is its heads beyond one per path,
    /// every one counted: a tombstone beside a version, and two heads of one
    /// content, are heads too. Latest only, so every applied record held at a
    /// tag, other than a tree delete, is a head there: counted per tag, with
    /// no view built.
    #[must_use]
    pub fn extra_versions(&self) -> u64 {
        let sealed = self.key.tier() == Tier::Sealed;
        let n: usize = self
            .s
            .at_tag
            .values()
            .map(|hs| {
                let heads = if sealed {
                    hs.len()
                } else {
                    hs.iter()
                        .filter(|h| {
                            self.s
                                .held
                                .get(h)
                                .and_then(|r| r.meta())
                                .is_some_and(|m| !m.tree)
                        })
                        .count()
                };
                heads.saturating_sub(1)
            })
            .sum();
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    /// What two devices that converged on the folder agree on (4.7 item 6,
    /// "Conflicts"): the root set digest, equal on every tier for equal
    /// records, then, at a read or write holder, each path's heads by hash in
    /// display order.
    pub fn fingerprint(&self, out: &mut dyn FnMut(&[u8])) {
        out(b"root");
        out(self.root_digest().as_bytes());
        if self.keys.is_some() {
            out(b"heads");
            for path in self.paths() {
                out(b"/");
                out(path.as_bytes());
                if let Some(v) = self.path(path) {
                    for h in v.heads {
                        out(h.hash.as_bytes());
                    }
                }
            }
        }
    }
}

impl Txn<'_> {
    /// Names the base of `path` at `place` (4.4, "Bases"): the record
    /// applied there (its content in place, or the path removed), the record
    /// whose content a conflict copy holds, or `None` to clear the slot. A
    /// record replaced stays, kept only as a base, until the engine names a
    /// newer one there.
    ///
    /// # Errors
    /// [`BaseError`].
    pub fn set_base(
        &mut self,
        path: &str,
        place: Place,
        record: Option<RecordHash>,
    ) -> Result<(), BaseError> {
        let tag = self.tag(path).ok_or(BaseError::Sealed)?;
        let Some(hash) = record else {
            self.ix
                .s
                .set_base((tag, place), None, None, Some(&mut self.undo));
            return Ok(());
        };
        let held = self.ix.s.held.get(&hash);
        let (rec, meta) = match (held, self.ix.s.base_only.get(&hash)) {
            (Some(h), _) => (
                h.record.clone(),
                h.meta().ok_or(BaseError::NotApplied)?.clone(),
            ),
            (None, Some(b)) => (b.record.clone(), b.meta.clone()),
            (None, None) => return Err(BaseError::Unknown),
        };
        if meta.path != path {
            return Err(BaseError::OtherPath);
        }
        self.ix.s.set_base(
            (tag, place),
            Some(hash),
            Some(BaseRecord { record: rec, meta }),
            Some(&mut self.undo),
        );
        Ok(())
    }

    /// Clears every base slot at or beneath `dir` but its own `Place::Path`
    /// slot: what the engine does when it applies a tree delete of `dir`,
    /// whose own base it then names. The slots there are ranges of a
    /// path-ordered index of the slots, so this reads what lies beneath
    /// `dir`, never every slot (TM-22).
    pub fn clear_bases_beneath(&mut self, dir: &str) {
        let Some(own) = self.tag(dir) else {
            return;
        };
        let slots: Vec<BaseSlot> = self
            .ix
            .s
            .base_slots_at_or_beneath(dir)
            .map(|(_, slot, _)| slot)
            .filter(|(t, place)| !(*t == own && *place == Place::Path))
            .cloned()
            .collect();
        for slot in slots {
            self.ix.s.set_base(slot, None, None, Some(&mut self.undo));
        }
    }
}
