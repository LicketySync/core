// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One folder's chunks (`protocol.md` 4.6, `keys.md` 3.2): which records it
//! wants chunks for, which hashes it stores, lacks or found corrupt for a
//! record, and how a chunk is judged per record that names it.
//!
//! # What a folder wants
//!
//! Which records a folder wants chunks for is the index's to say
//! (`Index::wanted`, 4.7 item 5: at a key holder every held record with
//! chunks, every head of a conflict and the opaque records included; at a
//! sealed holder those the sealed-peer rule keeps): each record with its
//! ordered chunks, each chunk's stored length and, for a key holder, its
//! plaintext hash and the file's size. This module keeps the rest, the same
//! whatever the index design.
//!
//! A hash **lacks** when it is not stored and some wanted record names it for
//! which it is not corrupt; `bytes_needed` sums the stored lengths of the
//! hashes lacking. Everything here is recomputed from the index when it
//! changes ([`ChunkBook::refresh`]), so it is a function of the wanted
//! records and the chunks stored.
//!
//! # Judging a chunk, per record (TM-13)
//!
//! The connection has checked the ciphertext hash before the engine sees the
//! chunk, so every later failure is a writer fault of the record that names
//! it, judged for that record alone: the stored length the record names,
//! then, for a key holder, `open_chunk` against the plaintext hash at that
//! position of the record's sealed metadata. A failure marks the pair (hash,
//! record) corrupt, so the hash is not fetched again for that record (else a
//! pass would ask for it forever), and raises an issue naming the record. The
//! blob is stored when at least one record is satisfied. When every position
//! of a file record has verified, the plaintext lengths must sum to the
//! record's size, or that too is a writer fault naming the record. A record
//! that comes to name a hash already stored is judged against the stored blob
//! then; after a restart every wanted position is judged again the same way,
//! once, since what was verified is not stored (decision).
//!
//! # A stored blob changed at rest (TM-10)
//!
//! A stored blob is this device's own, so before it is judged for any record
//! its ciphertext hash is computed again: a blob that no longer hashes to its
//! name, or is gone, changed in this device's storage. No record is to blame
//! and no pair is marked corrupt: the hash is forgotten as stored, so it
//! lacks and is fetched again, and the engine raises `LocalChunkCorrupt` and
//! deletes the blob and its marker at the next commit ([`Finding::Changed`]).
//! A blob that cannot be read is only forgotten and counted
//! ([`Finding::Unread`]), and read again, hash-checked, on the free tick
//! ([`ChunkBook::reread`]): a device that is the only holder of a chunk can
//! serve it again once its storage reads again, without a restart.
//!
//! # On the disk
//!
//! A version counts as on the (simulated) disk only while every chunk it
//! names is stored and has verified for it, that is no pair of it is
//! corrupt, and its size checked ([`ChunkBook::ready`]): a chunk stored
//! because another record it satisfies names it puts nothing of this one in
//! place, and one forgotten after it verified (changed at rest, unread,
//! rolled back) takes the version off the disk until it is stored again.
//!
//! # Bounds
//!
//! The corrupt pairs are kept while a held record names their hash, and the
//! size faults while their record is wanted; both are bounded by what the
//! index holds.

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::chunk::{cipher_hash, open_chunk, ChunkKeys, PlainHash};
use licketysync_keys::{CipherHash, FolderId, RecordHash};

use crate::runtime::Storage;
use crate::store::chunk_key;
use licketysync_index::Wanted as WantedRecord;

/// One chunk position of a wanted record.
#[derive(Clone, Copy, Debug)]
struct Position {
    hash: CipherHash,
    stored_len: u32,
    /// The plaintext hash at this position, for a key holder.
    plain: Option<PlainHash>,
    /// Once judged good: the plaintext length (key holder) or the stored
    /// length (sealed holder).
    verified: Option<u64>,
}

/// One wanted record's positions, and its size for the reassembly check.
#[derive(Clone, Debug)]
struct Wanted {
    positions: Vec<Position>,
    /// `Meta.size` of a file record, for a key holder.
    size: Option<u64>,
}

/// What judging found that the Issues list must name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Finding {
    /// The chunk failed for this record (4.6).
    Corrupt(RecordHash),
    /// The record's chunks verified but do not sum to its size.
    SizeMismatch(RecordHash),
    /// The stored blob of this hash is gone or no longer hashes to its name:
    /// changed in this device's storage (TM-10), the fault of no record.
    Changed(CipherHash),
    /// The stored blob of this hash could not be read: forgotten as stored
    /// and fetched again, which overwrites it; counted, nothing deleted, no
    /// issue.
    Unread(CipherHash),
}

/// One folder's chunk state.
#[derive(Debug, Default)]
pub(crate) struct ChunkBook {
    /// Hashes whose blob is stored (committed, or staged by this handler).
    stored: BTreeSet<CipherHash>,
    /// Hashes some held record names: what this device may serve (4.6, "a
    /// device holds a chunk for the folder when it has the stored blob and
    /// holds a record of the folder that names its `cipher_hash`").
    named_by_held: BTreeSet<CipherHash>,
    wanted: BTreeMap<RecordHash, Wanted>,
    /// Hash to the wanted (record, position) pairs naming it.
    naming: BTreeMap<CipherHash, Vec<(RecordHash, usize)>>,
    corrupt: BTreeSet<(CipherHash, RecordHash)>,
    size_faults: BTreeSet<RecordHash>,
    /// Hashes whose stored blob could not be read, forgotten as stored and
    /// read again on the free tick. Bounded by the chunks stored.
    unread: BTreeSet<CipherHash>,
    lacking: BTreeSet<CipherHash>,
    bytes_needed: u64,
    /// The index changed since the last refresh.
    pub(crate) dirty: bool,
    /// The refreshes made, for the test that a page of duplicates makes
    /// none.
    #[cfg(test)]
    pub(crate) refreshes: u64,
}

impl ChunkBook {
    /// A book over the chunks a start found stored; everything else is
    /// computed by the first refresh.
    pub(crate) fn new(stored: BTreeSet<CipherHash>) -> Self {
        Self {
            stored,
            dirty: true,
            ..Self::default()
        }
    }

    /// Whether the blob of `hash` is stored.
    pub(crate) fn is_stored(&self, hash: &CipherHash) -> bool {
        self.stored.contains(hash)
    }

    /// Whether this device holds `hash` for the folder: stored and named by
    /// a held record.
    pub(crate) fn holds(&self, hash: &CipherHash) -> bool {
        self.stored.contains(hash) && self.named_by_held.contains(hash)
    }

    /// The largest stored length a wanted record names for `hash`: an upper
    /// bound on the blob, for pacing.
    pub(crate) fn stored_len(&self, hash: &CipherHash) -> Option<u32> {
        self.naming
            .get(hash)?
            .iter()
            .filter_map(|(r, i)| self.wanted.get(r)?.positions.get(*i))
            .map(|p| p.stored_len)
            .max()
    }

    /// Marks `hash` stored (its blob staged).
    pub(crate) fn mark_stored(&mut self, hash: CipherHash) {
        self.unread.remove(&hash);
        self.stored.insert(hash);
        self.dirty = true;
    }

    /// Whether every chunk `record` names is stored and has verified for
    /// it, and its size checked: its content is whole (the module
    /// documentation, "On the disk"). A record this book does not know yet is
    /// not, nor one with a chunk forgotten since it verified (changed at
    /// rest, unreadable, or rolled back with a failed commit).
    pub(crate) fn ready(&self, record: &RecordHash) -> bool {
        self.wanted.get(record).is_some_and(|w| {
            w.positions
                .iter()
                .all(|p| p.verified.is_some() && self.stored.contains(&p.hash))
        }) && !self.size_faults.contains(record)
    }

    /// Forgets `hash` as stored because its blob could not be read, to read
    /// it again on the free tick ([`Self::reread`]).
    pub(crate) fn mark_unread(&mut self, hash: CipherHash) {
        self.forget(&hash);
        self.unread.insert(hash);
    }

    /// Whether a blob waits to be read again.
    pub(crate) fn has_unread(&self) -> bool {
        !self.unread.is_empty()
    }

    /// Reads again every blob that could not be read: one that reads and
    /// hashes to its name is stored again; one that is gone or no longer
    /// hashes to its name changed at rest (TM-10), to be handled as a blob
    /// found so at a refresh (`Finding::Changed`: it lacks and is fetched
    /// again, its blob and marker deleted); one that still cannot be read
    /// waits for the next tick. The hashes stored again, and those changed.
    pub(crate) fn reread(
        &mut self,
        folder: &FolderId,
        storage: &dyn Storage,
    ) -> (Vec<CipherHash>, Vec<CipherHash>) {
        let (mut again, mut changed) = (Vec::new(), Vec::new());
        for hash in core::mem::take(&mut self.unread) {
            match storage.get(&chunk_key(folder, &hash)) {
                Ok(Some(blob)) if cipher_hash(&blob) == hash => again.push(hash),
                Ok(_) => changed.push(hash),
                Err(_) => {
                    self.unread.insert(hash);
                }
            }
        }
        for hash in &again {
            self.mark_stored(*hash);
        }
        (again, changed)
    }

    /// Forgets `hash` as stored: its blob is gone or changed (TM-10), or
    /// this device freed it, so it is fetched again if wanted; and it is no
    /// longer one to read again (a blob this device deleted is no blob
    /// changed at rest).
    pub(crate) fn forget(&mut self, hash: &CipherHash) {
        self.stored.remove(hash);
        self.unread.remove(hash);
        self.dirty = true;
    }

    /// Replaces the stored set with what storage holds now (after a rollback).
    pub(crate) fn reset_stored(&mut self, stored: BTreeSet<CipherHash>) {
        self.stored = stored;
        self.dirty = true;
    }

    /// The hashes lacking, ascending.
    pub(crate) fn lacking(&self) -> &BTreeSet<CipherHash> {
        &self.lacking
    }

    /// The stored lengths of the hashes lacking, summed.
    pub(crate) const fn bytes_needed(&self) -> u64 {
        self.bytes_needed
    }

    /// The stored hashes, ascending.
    pub(crate) fn stored(&self) -> &BTreeSet<CipherHash> {
        &self.stored
    }

    /// The smallest hash lacking above `after` (from the smallest for `None`)
    /// that `free` accepts (not in flight on any connection): the next
    /// request of a pass (4.6, "Passes").
    pub(crate) fn next_lacking(
        &self,
        after: Option<CipherHash>,
        free: impl Fn(&CipherHash) -> bool,
    ) -> Option<CipherHash> {
        let mut range = match after {
            None => self.lacking.range(..),
            Some(a) => self
                .lacking
                .range((core::ops::Bound::Excluded(a), core::ops::Bound::Unbounded)),
        };
        range.find(|h| free(h)).copied()
    }

    /// Whether any hash lacks that `free` accepts.
    pub(crate) fn any_lacking(&self, free: impl Fn(&CipherHash) -> bool) -> bool {
        self.lacking.iter().any(free)
    }

    /// Recomputes what the folder wants and lacks from the records the index
    /// says it wants and the hashes its held records name, judging every
    /// wanted position whose hash is stored and not yet judged against the
    /// stored blob. Returns what the Issues list must name, and whether a
    /// hash newly lacks (a pass trigger).
    pub(crate) fn refresh(
        &mut self,
        folder: &FolderId,
        wanted: Vec<WantedRecord>,
        named: BTreeSet<CipherHash>,
        keys: Option<&ChunkKeys>,
        storage: &dyn Storage,
    ) -> (Vec<Finding>, bool) {
        self.dirty = false;
        #[cfg(test)]
        {
            self.refreshes += 1;
        }
        let mut wanted: BTreeMap<RecordHash, Wanted> = wanted
            .into_iter()
            .map(|w| {
                let positions = w
                    .chunks
                    .iter()
                    .map(|c| Position {
                        hash: c.hash,
                        stored_len: c.stored_len,
                        plain: c.plain,
                        verified: None,
                    })
                    .collect();
                (
                    w.record,
                    Wanted {
                        positions,
                        size: w.size,
                    },
                )
            })
            .collect();
        for (hash, w) in &mut wanted {
            if let Some(old) = self.wanted.get(hash) {
                for (new, before) in w.positions.iter_mut().zip(&old.positions) {
                    new.verified = before.verified;
                }
            }
        }
        self.wanted = wanted;
        self.named_by_held = named;
        let held = &self.named_by_held;
        self.corrupt.retain(|(h, _)| held.contains(h));
        let wanted = &self.wanted;
        self.size_faults.retain(|r| wanted.contains_key(r));
        self.naming = BTreeMap::new();
        for (record, w) in &self.wanted {
            for (i, p) in w.positions.iter().enumerate() {
                self.naming.entry(p.hash).or_default().push((*record, i));
            }
        }
        let mut findings = Vec::new();
        let stored_unjudged: Vec<CipherHash> = self
            .naming
            .iter()
            .filter(|(h, _)| self.stored.contains(h))
            .filter(|(h, pairs)| {
                pairs.iter().any(|(r, i)| {
                    !self.corrupt.contains(&(**h, *r))
                        && self.position(r, *i).is_some_and(|p| p.verified.is_none())
                })
            })
            .map(|(h, _)| *h)
            .collect();
        for hash in stored_unjudged {
            match storage.get(&chunk_key(folder, &hash)) {
                Ok(Some(blob)) if cipher_hash(&blob) == hash => {
                    findings.extend(self.judge(hash, &blob, keys).1);
                }
                // Changed or gone at rest (module documentation): fetched
                // again, no record blamed.
                Ok(_) => {
                    self.stored.remove(&hash);
                    findings.push(Finding::Changed(hash));
                }
                // The storage could not be read (`Finding::Unread`).
                Err(_) => {
                    self.stored.remove(&hash);
                    self.unread.insert(hash);
                    findings.push(Finding::Unread(hash));
                }
            }
        }
        let grew = self.recompute_lacking();
        (findings, grew)
    }

    fn position(&self, record: &RecordHash, i: usize) -> Option<&Position> {
        self.wanted.get(record)?.positions.get(i)
    }

    /// Recomputes the lacking set and `bytes_needed`; whether a hash was
    /// added.
    fn recompute_lacking(&mut self) -> bool {
        let lacking: BTreeSet<CipherHash> = self
            .naming
            .iter()
            .filter(|(h, pairs)| {
                !self.stored.contains(h)
                    && pairs
                        .iter()
                        .any(|(r, _)| !self.corrupt.contains(&(**h, *r)))
            })
            .map(|(h, _)| *h)
            .collect();
        let grew = lacking.iter().any(|h| !self.lacking.contains(h));
        self.bytes_needed = lacking
            .iter()
            .filter_map(|h| self.stored_len(h))
            .map(u64::from)
            .sum();
        self.lacking = lacking;
        grew
    }

    /// Judges `blob`, whose ciphertext hash is `hash`, for every wanted record
    /// naming it (module documentation). Returns whether at least one record
    /// is satisfied, and the findings for the Issues list. The book's lacking
    /// set is brought up to date by the next refresh.
    pub(crate) fn judge(
        &mut self,
        hash: CipherHash,
        blob: &[u8],
        keys: Option<&ChunkKeys>,
    ) -> (bool, Vec<Finding>) {
        let pairs = self.naming.get(&hash).cloned().unwrap_or_default();
        let mut satisfied = false;
        let mut findings = Vec::new();
        for (record, i) in pairs {
            if self.corrupt.contains(&(hash, record)) {
                continue;
            }
            let Some(p) = self
                .wanted
                .get_mut(&record)
                .and_then(|w| w.positions.get_mut(i))
            else {
                continue;
            };
            if let Some(len) = judge_position(p, blob, keys) {
                p.verified = Some(len);
                satisfied = true;
                findings.extend(self.check_size(&record));
            } else {
                self.corrupt.insert((hash, record));
                findings.push(Finding::Corrupt(record));
            }
        }
        self.dirty = true;
        (satisfied, findings)
    }

    /// The reassembly check of a file record whose every position verified.
    fn check_size(&mut self, record: &RecordHash) -> Option<Finding> {
        let w = self.wanted.get(record)?;
        let size = w.size?;
        let total: Option<u64> = w.positions.iter().map(|p| p.verified).sum();
        let total = total?;
        if total != size && self.size_faults.insert(*record) {
            return Some(Finding::SizeMismatch(*record));
        }
        None
    }

    /// The pairs (hash, record) found corrupt, for tests.
    #[cfg(test)]
    #[allow(dead_code, reason = "read by the unit tests")]
    pub(crate) fn corrupt(&self) -> &BTreeSet<(CipherHash, RecordHash)> {
        &self.corrupt
    }
}

/// One position judged for its record: the stored length the record names,
/// then, for a key holder, the seal and the plaintext hash. The plaintext
/// length (or the stored length, for a sealed holder and for an opaque
/// record, whose plaintext hashes are not to be trusted, 4.7 item 5) when it
/// passes.
fn judge_position(p: &Position, blob: &[u8], keys: Option<&ChunkKeys>) -> Option<u64> {
    if usize::try_from(p.stored_len).ok()? != blob.len() {
        return None;
    }
    match (keys, p.plain) {
        (Some(keys), Some(plain)) => {
            let raw = open_chunk(keys, blob, &plain).ok()?;
            u64::try_from(raw.len()).ok()
        }
        _ => Some(u64::from(p.stored_len)),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use super::*;
    use crate::testkit::{write_key, FakeStorage};
    use licketysync_index::WantedChunk;
    use licketysync_keys::chunk::seal_chunk;

    fn want(record: u8, chunks: &[(CipherHash, u32, PlainHash)], size: u64) -> WantedRecord {
        WantedRecord {
            record: RecordHash([record; 32]),
            chunks: chunks
                .iter()
                .map(|(hash, stored_len, plain)| WantedChunk {
                    hash: *hash,
                    stored_len: *stored_len,
                    plain: Some(*plain),
                })
                .collect(),
            size: Some(size),
        }
    }

    #[test]
    fn a_chunk_named_by_two_records_is_judged_for_each_and_stored_for_the_one_it_satisfies() {
        let keys = write_key(1).chunk_keys();
        let s = seal_chunk(&keys, &[9u8; 700]).unwrap();
        let len = s.stored.len() as u32;
        let folder = FolderId([1; 32]);
        let mut book = ChunkBook::new(BTreeSet::new());
        let good = want(1, &[(s.cipher_hash, len, s.plain_hash)], 700);
        // The same hash named with another stored length: a writer fault of
        // that record alone (4.6, TM-13).
        let bad = want(2, &[(s.cipher_hash, len + 8, s.plain_hash)], 700);
        let named: BTreeSet<CipherHash> = [s.cipher_hash].into_iter().collect();
        let (findings, grew) = book.refresh(
            &folder,
            vec![good, bad],
            named.clone(),
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(findings.is_empty() && grew);
        assert_eq!(
            book.lacking().iter().copied().collect::<Vec<_>>(),
            vec![s.cipher_hash]
        );
        assert_eq!(
            book.bytes_needed(),
            u64::from(len + 8),
            "the largest stored length named"
        );
        let (satisfied, findings) = book.judge(s.cipher_hash, &s.stored, Some(&keys));
        assert!(satisfied);
        assert_eq!(findings, vec![Finding::Corrupt(RecordHash([2; 32]))]);
        assert!(book
            .corrupt()
            .contains(&(s.cipher_hash, RecordHash([2; 32]))));
        assert!(
            !book.holds(&s.cipher_hash),
            "not stored until the blob is staged"
        );
        book.mark_stored(s.cipher_hash);
        assert!(book.holds(&s.cipher_hash));
    }

    /// The bug: a key holder judged the chunk of an opaque record against
    /// a plaintext hash it was never given, found it corrupt and never kept
    /// it; 4.7 item 5 has it kept, checked by its ciphertext hash and stored
    /// length alone.
    #[test]
    fn a_key_holder_keeps_an_opaque_records_chunk_by_its_stored_length() {
        let keys = write_key(1).chunk_keys();
        let s = seal_chunk(&keys, &[4u8; 500]).unwrap();
        let len = s.stored.len() as u32;
        let opaque = WantedRecord {
            record: RecordHash([5; 32]),
            chunks: vec![WantedChunk {
                hash: s.cipher_hash,
                stored_len: len,
                plain: None,
            }],
            size: None,
        };
        let mut book = ChunkBook::new(BTreeSet::new());
        let named: BTreeSet<CipherHash> = [s.cipher_hash].into_iter().collect();
        book.refresh(
            &FolderId([1; 32]),
            vec![opaque],
            named,
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(book.lacking().contains(&s.cipher_hash));
        let (satisfied, findings) = book.judge(s.cipher_hash, &s.stored, Some(&keys));
        assert!(satisfied && findings.is_empty(), "{findings:?}");
        let (wrong, _) = book.judge(s.cipher_hash, &s.stored[1..], Some(&keys));
        assert!(!wrong, "another length is still refused");
    }

    /// CS-2: a version is ready (on the disk) only while every chunk it
    /// names is stored as well as verified for it, so forgetting a chunk
    /// (changed at rest, unreadable, rolled back) takes it off the disk; and
    /// chunks that verify but do not add up to its size never make it ready
    /// (CS-N1).
    #[test]
    fn a_version_is_ready_only_while_its_verified_chunks_are_stored() {
        let keys = write_key(1).chunk_keys();
        let s = seal_chunk(&keys, &[6u8; 400]).unwrap();
        let len = s.stored.len() as u32;
        let folder = FolderId([1; 32]);
        let named: BTreeSet<CipherHash> = [s.cipher_hash].into_iter().collect();
        let record = RecordHash([7; 32]);
        let mut book = ChunkBook::new(BTreeSet::new());
        let w = want(7, &[(s.cipher_hash, len, s.plain_hash)], 400);
        book.refresh(
            &folder,
            vec![w],
            named.clone(),
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(!book.ready(&record), "nothing stored yet");
        assert!(book.judge(s.cipher_hash, &s.stored, Some(&keys)).0);
        assert!(!book.ready(&record), "verified, not stored yet");
        book.mark_stored(s.cipher_hash);
        assert!(book.ready(&record));
        book.forget(&s.cipher_hash);
        assert!(!book.ready(&record), "forgotten");
        book.mark_stored(s.cipher_hash);
        book.reset_stored(BTreeSet::new());
        assert!(!book.ready(&record), "rolled back with a failed commit");
        book.mark_stored(s.cipher_hash);
        book.mark_unread(s.cipher_hash);
        assert!(!book.ready(&record), "unreadable");
        // The same chunk named for a size it does not add up to.
        let mut wrong = ChunkBook::new(BTreeSet::new());
        let w = want(8, &[(s.cipher_hash, len, s.plain_hash)], 999);
        wrong.refresh(
            &folder,
            vec![w],
            named,
            Some(&keys),
            &FakeStorage::default(),
        );
        let (satisfied, findings) = wrong.judge(s.cipher_hash, &s.stored, Some(&keys));
        assert!(satisfied);
        assert_eq!(findings, vec![Finding::SizeMismatch(RecordHash([8; 32]))]);
        wrong.mark_stored(s.cipher_hash);
        assert!(!wrong.ready(&RecordHash([8; 32])), "its size did not check");
    }

    /// CS-N2 (probe P4b): reading again a blob that could not be read checks
    /// its ciphertext hash: one that hashes to its name is stored again, one
    /// changed or gone is reported changed, one still unreadable waits.
    #[test]
    fn reading_a_blob_again_checks_its_hash() {
        let keys = write_key(1).chunk_keys();
        let folder = FolderId([1; 32]);
        let good = seal_chunk(&keys, &[1u8; 300]).unwrap();
        let bad = seal_chunk(&keys, &[2u8; 300]).unwrap();
        let gone = seal_chunk(&keys, &[3u8; 300]).unwrap();
        let mut storage = FakeStorage::default();
        storage
            .committed
            .insert(chunk_key(&folder, &good.cipher_hash), good.stored.clone());
        let mut changed = bad.stored.clone();
        changed[0] ^= 1;
        storage
            .committed
            .insert(chunk_key(&folder, &bad.cipher_hash), changed);
        let mut book = ChunkBook::new(BTreeSet::new());
        for h in [good.cipher_hash, bad.cipher_hash, gone.cipher_hash] {
            book.mark_unread(h);
        }
        let (again, changed) = book.reread(&folder, &storage);
        assert_eq!(again, vec![good.cipher_hash]);
        let mut want = vec![bad.cipher_hash, gone.cipher_hash];
        want.sort_unstable();
        let mut changed = changed;
        changed.sort_unstable();
        assert_eq!(changed, want);
        assert!(book.is_stored(&good.cipher_hash) && !book.is_stored(&bad.cipher_hash));
        assert!(!book.has_unread());
        book.mark_unread(good.cipher_hash);
        storage.get_fails = true;
        assert_eq!(book.reread(&folder, &storage), (vec![], vec![]));
        assert!(book.has_unread(), "still unreadable: it waits");
    }

    #[test]
    fn a_chunk_corrupt_for_every_record_is_not_lacking_and_never_asked_again() {
        let keys = write_key(1).chunk_keys();
        let other = write_key(2).chunk_keys();
        let s = seal_chunk(&other, &[1u8; 300]).unwrap();
        let folder = FolderId([1; 32]);
        let mut book = ChunkBook::new(BTreeSet::new());
        let named: BTreeSet<CipherHash> = [s.cipher_hash].into_iter().collect();
        let w = want(
            3,
            &[(s.cipher_hash, s.stored.len() as u32, s.plain_hash)],
            300,
        );
        book.refresh(
            &folder,
            vec![w.clone()],
            named.clone(),
            Some(&keys),
            &FakeStorage::default(),
        );
        let (satisfied, findings) = book.judge(s.cipher_hash, &s.stored, Some(&keys));
        assert!(
            !satisfied,
            "the seal does not open under this folder's keys"
        );
        assert_eq!(findings, vec![Finding::Corrupt(RecordHash([3; 32]))]);
        book.refresh(
            &folder,
            vec![w.clone()],
            named,
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(
            book.lacking().is_empty(),
            "corrupt for its one record: not fetched again"
        );
        assert_eq!(book.next_lacking(None, |_| true), None);
        // Once no held record names the hash, its pairs go (they are
        // bounded by what the index holds).
        book.refresh(
            &folder,
            vec![],
            BTreeSet::new(),
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(book.corrupt().is_empty());
    }

    #[test]
    fn chunks_that_open_but_miss_the_size_are_a_size_mismatch_once() {
        let keys = write_key(1).chunk_keys();
        let a = seal_chunk(&keys, &[5u8; 100]).unwrap();
        let b = seal_chunk(&keys, &[6u8; 50]).unwrap();
        let folder = FolderId([1; 32]);
        let mut book = ChunkBook::new(BTreeSet::new());
        let w = want(
            4,
            &[
                (a.cipher_hash, a.stored.len() as u32, a.plain_hash),
                (b.cipher_hash, b.stored.len() as u32, b.plain_hash),
            ],
            151,
        );
        book.refresh(
            &folder,
            vec![w],
            BTreeSet::new(),
            Some(&keys),
            &FakeStorage::default(),
        );
        assert_eq!(book.judge(a.cipher_hash, &a.stored, Some(&keys)).1, vec![]);
        assert_eq!(
            book.judge(b.cipher_hash, &b.stored, Some(&keys)).1,
            vec![Finding::SizeMismatch(RecordHash([4; 32]))]
        );
        assert_eq!(
            book.judge(b.cipher_hash, &b.stored, Some(&keys)).1,
            vec![],
            "named once"
        );
        // Once the record is no longer wanted, its fault goes (bounded by
        // what the index holds).
        book.refresh(
            &folder,
            vec![],
            BTreeSet::new(),
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(book.size_faults.is_empty());
    }

    #[test]
    fn a_stored_blob_changed_at_rest_is_forgotten_and_blames_no_record() {
        // TM-10: the blob is this device's own; its record did nothing.
        let keys = write_key(1).chunk_keys();
        let s = seal_chunk(&keys, &[2u8; 400]).unwrap();
        let folder = FolderId([1; 32]);
        let mut storage = FakeStorage::default();
        let mut changed = s.stored.clone();
        changed[0] ^= 1;
        crate::store::stage_chunk(&mut storage, &folder, &s.cipher_hash, &changed).unwrap();
        let mut book = ChunkBook::new([s.cipher_hash].into_iter().collect());
        let w = want(
            8,
            &[(s.cipher_hash, s.stored.len() as u32, s.plain_hash)],
            400,
        );
        let named: BTreeSet<CipherHash> = [s.cipher_hash].into_iter().collect();
        let (findings, grew) = book.refresh(&folder, vec![w], named, Some(&keys), &storage);
        assert_eq!(findings, vec![Finding::Changed(s.cipher_hash)]);
        assert!(grew && book.lacking().contains(&s.cipher_hash));
        assert!(book.corrupt().is_empty(), "no pair marked corrupt");
        assert!(!book.is_stored(&s.cipher_hash));
    }

    #[test]
    fn a_record_that_names_a_stored_hash_is_judged_against_the_stored_blob() {
        let keys = write_key(1).chunk_keys();
        let s = seal_chunk(&keys, &[7u8; 400]).unwrap();
        let folder = FolderId([1; 32]);
        let mut storage = FakeStorage::default();
        crate::store::stage_chunk(&mut storage, &folder, &s.cipher_hash, &s.stored).unwrap();
        let mut book = ChunkBook::new([s.cipher_hash].into_iter().collect());
        let good = want(
            5,
            &[(s.cipher_hash, s.stored.len() as u32, s.plain_hash)],
            400,
        );
        let wrong = want(
            6,
            &[(s.cipher_hash, s.stored.len() as u32, PlainHash([0; 32]))],
            400,
        );
        let (findings, _) = book.refresh(
            &folder,
            vec![good, wrong],
            BTreeSet::new(),
            Some(&keys),
            &storage,
        );
        assert_eq!(findings, vec![Finding::Corrupt(RecordHash([6; 32]))]);
        assert!(book.lacking().is_empty());
        // A stored hash whose blob is gone is fetched again.
        let mut book = ChunkBook::new([s.cipher_hash].into_iter().collect());
        let w = want(
            5,
            &[(s.cipher_hash, s.stored.len() as u32, s.plain_hash)],
            400,
        );
        book.refresh(
            &folder,
            vec![w],
            BTreeSet::new(),
            Some(&keys),
            &FakeStorage::default(),
        );
        assert!(!book.is_stored(&s.cipher_hash));
        assert_eq!(book.lacking().len(), 1);
    }

    #[test]
    fn a_sealed_holder_judges_the_stored_length_only_and_passes_go_in_ascending_order() {
        let mut book = ChunkBook::new(BTreeSet::new());
        let hashes: Vec<CipherHash> = (1..=3u8).map(|i| CipherHash([i; 32])).collect();
        let w = WantedRecord {
            record: RecordHash([7; 32]),
            chunks: hashes
                .iter()
                .map(|h| WantedChunk {
                    hash: *h,
                    stored_len: 46,
                    plain: None,
                })
                .collect(),
            size: None,
        };
        book.refresh(
            &FolderId([1; 32]),
            vec![w],
            BTreeSet::new(),
            None,
            &FakeStorage::default(),
        );
        assert_eq!(book.next_lacking(None, |_| true), Some(hashes[0]));
        assert_eq!(
            book.next_lacking(Some(hashes[0]), |_| true),
            Some(hashes[1])
        );
        assert_eq!(
            book.next_lacking(None, |h| *h != hashes[0]),
            Some(hashes[1]),
            "in flight elsewhere: skipped"
        );
        assert_eq!(book.next_lacking(Some(hashes[2]), |_| true), None);
        assert!(book.any_lacking(|_| true));
        assert_eq!(book.stored_len(&hashes[1]), Some(46));
        assert!(
            book.judge(hashes[0], &[0; 46], None).0,
            "a sealed holder checks the length"
        );
        assert_eq!(
            book.judge(hashes[1], &[0; 47], None).1,
            vec![Finding::Corrupt(RecordHash([7; 32]))]
        );
        book.mark_stored(hashes[0]);
        book.forget(&hashes[0]);
        assert!(!book.is_stored(&hashes[0]));
        book.reset_stored([hashes[2]].into_iter().collect());
        assert_eq!(book.stored().len(), 1);
    }
}
