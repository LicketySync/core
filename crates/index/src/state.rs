// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One folder's index state and the primitives every change goes through.
//!
//! The state holds the records a device holds for the folder (live records,
//! tree deletes, cleanups, opaque records), each with its local sequence
//! number and, at a read or write holder, step 7's verdict on its seal; the
//! records kept only as bases and the base slots; the folder's metadata; the
//! per-peer state; and a write holder's notes of stale copies. Everything
//! else here is derived from the records held and kept in step with them by
//! [`State::hold`] and [`State::unhold`]: the records by tag and by path, the
//! names (`replaces` at their tag) and the cleanup groups by what they forget
//! and by their `because`, the counters of the applied records (the folder's
//! own time), the deletions and cleanups by counter (expiry), the chunk
//! counts and the set digests.
//!
//! Every primitive logs its inverse in an undo log ([`Undo`]) when it is
//! given one, so that a transaction that is dropped is undone exactly, with
//! nothing rebuilt ([`State::rollback`]), and so that the change set to
//! persist is read off the log ([`State::changes`]).

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::{CipherHash, DeviceId, PathTag, RecordHash};
use licketysync_protocol::exchange::Prefix;
use licketysync_protocol::record::{Applied, Dot, Meta, Record, Vector, Verdict};

use crate::bypath::ByPath;
use crate::dirs::Dirs;
use crate::store::{BaseSlot, ChangeSet, PeerState, StoredMeta};
use crate::trie::Trie;

/// A record the device holds.
#[derive(Clone, Debug)]
pub(crate) struct Held {
    pub(crate) record: Record,
    pub(crate) seq: u64,
    /// Step 7's verdict at a read or write holder; `None` at a sealed holder.
    pub(crate) verdict: Option<Verdict>,
}

impl Held {
    pub(crate) fn applied(&self) -> Option<&Applied> {
        self.verdict.as_ref().and_then(|v| v.as_ref().ok())
    }

    pub(crate) fn meta(&self) -> Option<&Meta> {
        self.applied().and_then(Applied::meta)
    }

    fn counter(&self) -> Option<u64> {
        self.applied().map(|a| a.dot().counter)
    }
}

/// A record kept only as a base: not held, not served, not counted in any
/// digest, not pushed, not part of the folder's time (4.4, "Bases").
#[derive(Clone, Debug)]
pub(crate) struct BaseRecord {
    pub(crate) record: Record,
    pub(crate) meta: Meta,
}

/// What a stale-copy note remembers of the record it names (4.5, "Stale
/// copies").
#[derive(Clone, Debug)]
pub(crate) enum Noted {
    /// A record something held replaces: its tag, path and dot, to judge
    /// again what replaces it when it is named.
    Stale {
        tag: PathTag,
        path: String,
        dot: Dot,
        tree: bool,
    },
    /// A tombstone, tree delete or cleanup forgotten past its horizon.
    Forgotten,
}

/// One note of a write holder: a record a peer offered, verified, which the
/// write holder will name.
#[derive(Clone, Debug)]
pub(crate) struct Note {
    pub(crate) hash: RecordHash,
    pub(crate) peer: DeviceId,
    pub(crate) noted: Noted,
    /// The note's place in the order of notes, oldest first.
    pub(crate) nr: u64,
}

/// One entry of the undo log: what to restore.
#[derive(Clone, Debug)]
pub(crate) enum Undo {
    /// This record came to be held; undo: unhold it.
    Held(RecordHash),
    /// This record was held; undo: hold it again.
    Unheld(Box<Held>),
    /// This record came to be kept only as a base; undo: forget it.
    BaseOnlyPut(RecordHash),
    /// This record was kept only as a base; undo: keep it again.
    BaseOnlyRemoved(Box<BaseRecord>),
    /// A base slot held this before.
    Base(BaseSlot, Option<RecordHash>),
    /// The metadata was this before.
    Meta(StoredMeta),
    /// A peer's state was this before.
    Peer(DeviceId, Option<PeerState>),
    /// A note was added, the next note number being this before; undo:
    /// remove it and restore the number.
    NoteAdded(RecordHash, u64),
    /// A note was removed; undo: add it again.
    NoteRemoved(Box<Note>),
}

/// A count only tests read, left out of the state's `Debug`, so that a
/// rollback compares exactly.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Meter(core::cell::Cell<usize>);

#[cfg(test)]
impl Meter {
    pub(crate) fn add(&self, n: usize) {
        self.0.set(self.0.get() + n);
    }

    pub(crate) fn take(&self) -> usize {
        self.0.replace(0)
    }
}

#[cfg(test)]
impl core::fmt::Debug for Meter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("-")
    }
}

/// The state of one folder's index.
#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(crate) held: BTreeMap<RecordHash, Held>,
    pub(crate) by_seq: BTreeMap<u64, RecordHash>,
    /// Index records held, by path tag (tree deletes and opaque ones
    /// included).
    pub(crate) at_tag: BTreeMap<PathTag, BTreeSet<RecordHash>>,
    pub(crate) cleanups: BTreeSet<RecordHash>,
    /// `(tag, fingerprint)` named by held index records at that tag: how
    /// many.
    named_at: BTreeMap<(PathTag, RecordHash), u32>,
    /// Fingerprint → the `(cleanup, group)` that forget it.
    forgets: BTreeMap<RecordHash, BTreeSet<(RecordHash, u32)>>,
    /// `because` → the `(cleanup, group)` it is the `because` of.
    by_because: BTreeMap<RecordHash, BTreeSet<(RecordHash, u32)>>,
    /// Applied index records held, by path.
    pub(crate) paths: BTreeMap<String, BTreeSet<RecordHash>>,
    /// Applied index records held, per device by path with least counters:
    /// what a tree delete covers, without a walk.
    pub(crate) by_path: ByPath,
    /// Applied tree deletes held, by directory: what a record lies beneath.
    pub(crate) tree_dirs: Dirs,
    /// The counters of applied records held, with how many: the folder's
    /// own time is the greatest.
    counters: BTreeMap<u64, u32>,
    /// Applied deletions (tombstones and tree deletes) held, by counter.
    deletions: BTreeSet<(u64, RecordHash)>,
    /// Applied cleanups held, by counter.
    cleanup_counters: BTreeSet<(u64, RecordHash)>,
    /// Chunk hash → held records naming it.
    pub(crate) chunks: BTreeMap<CipherHash, u32>,
    pub(crate) trie: Trie,
    /// Base slots.
    pub(crate) bases: BTreeMap<BaseSlot, RecordHash>,
    /// Base record → the slots it stands in.
    pub(crate) slots_of: BTreeMap<RecordHash, BTreeSet<BaseSlot>>,
    /// The file IDs with a base slot, by path: the slots at or beneath a
    /// directory are a range, never a walk of every slot.
    base_paths: BTreeMap<String, PathTag>,
    /// Each file ID with a base slot: its path and how many slots it has.
    base_tags: BTreeMap<PathTag, (String, usize)>,
    /// Records kept only as bases.
    pub(crate) base_only: BTreeMap<RecordHash, BaseRecord>,
    /// Base-only deletions by counter, for expiry.
    base_deletions: BTreeSet<(u64, RecordHash)>,
    pub(crate) meta: StoredMeta,
    pub(crate) peers: BTreeMap<DeviceId, PeerState>,
    pub(crate) notes: BTreeMap<RecordHash, Note>,
    pub(crate) note_order: BTreeMap<u64, RecordHash>,
    /// The paths and base slots the ranges at or beneath a directory read,
    /// for the test of what holding a tree delete costs.
    #[cfg(test)]
    pub(crate) beneath_read: Meter,
    pub(crate) notes_at: BTreeMap<PathTag, BTreeSet<RecordHash>>,
    pub(crate) next_note: u64,
}

/// The entries of `map` at `dir` itself and beneath it, in path order: the
/// runs `[dir]` and `[dir/, dir0)`, `0` being the byte after `/`, as the
/// index by path brackets them (`at_or_beneath` of the protocol crate is
/// the same set, one path at a time). The root, `""`, is every entry: no
/// record lies at `""`, and none beneath it by that rule.
fn at_or_beneath<'a, V>(
    map: &'a BTreeMap<String, V>,
    dir: &str,
) -> impl Iterator<Item = (&'a String, &'a V)> + 'a {
    let every = dir.is_empty().then(|| map.iter());
    let runs = (!dir.is_empty()).then(|| {
        let first = format!("{dir}/");
        let past = format!("{dir}0");
        map.get_key_value(dir)
            .into_iter()
            .chain(map.range::<str, _>((
                core::ops::Bound::Included(first.as_str()),
                core::ops::Bound::Excluded(past.as_str()),
            )))
    });
    every
        .into_iter()
        .flatten()
        .chain(runs.into_iter().flatten())
}

fn log(undo: Option<&mut Vec<Undo>>, entry: Undo) {
    if let Some(u) = undo {
        u.push(entry);
    }
}

impl State {
    // Queries.

    pub(crate) fn is_held(&self, hash: &RecordHash) -> bool {
        self.held.contains_key(hash)
    }

    /// The folder's own time `G`: the greatest counter of an applied record
    /// held (4.4, "Expiry"); 0 when none is.
    pub(crate) fn folder_time(&self) -> u64 {
        self.counters.keys().next_back().copied().unwrap_or(0)
    }

    /// The greatest counter of an applied record held or kept as a base.
    pub(crate) fn greatest_counter(&self) -> u64 {
        let bases = self
            .base_only
            .values()
            .map(|b| b.meta.dot.counter)
            .max()
            .unwrap_or(0);
        self.folder_time().max(bases)
    }

    /// Whether a held record at `tag` names `hash`.
    pub(crate) fn named_at(&self, tag: &PathTag, hash: &RecordHash) -> bool {
        self.named_at.contains_key(&(*tag, *hash))
    }

    /// Whether a cleanup group applies: its `because` is empty or names a
    /// record held (4.4, "Cleanup"). No device remembers that a group once
    /// applied.
    pub(crate) fn group_applies(&self, cleanup: &RecordHash, group: u32) -> bool {
        self.held
            .get(cleanup)
            .and_then(|c| c.record.groups().get(usize::try_from(group).ok()?))
            .is_some_and(|g| g.because.as_ref().is_none_or(|b| self.is_held(b)))
    }

    /// Whether a held cleanup names `hash` in a group that applies.
    pub(crate) fn forgotten_by_group(&self, hash: &RecordHash) -> bool {
        self.forgets
            .get(hash)
            .is_some_and(|gs| gs.iter().any(|(c, g)| self.group_applies(c, *g)))
    }

    /// Whether a held cleanup names `hash` in any group, applying or not.
    pub(crate) fn named_by_any_group(&self, hash: &RecordHash) -> bool {
        self.forgets.get(hash).is_some_and(|gs| !gs.is_empty())
    }

    /// Whether a held record names `record` (at its tag) or a held cleanup
    /// names it in a group that applies: obsolete by a name, on every tier.
    pub(crate) fn named(&self, record: &Record) -> bool {
        let hash = record.hash();
        record.path_tag().is_some_and(|t| self.named_at(&t, &hash))
            || self.forgotten_by_group(&hash)
    }

    /// A held tree delete at or above `path` whose vector covers `dot`
    /// (4.4, "Tree deletes"), other than `except`: the deepest first, found
    /// in one pass down the trie of tree deletes along the path, `O(L)` work
    /// for a path of `L` bytes (4.4 step 3), stopping at the first that
    /// covers it.
    pub(crate) fn covering_tree_delete(
        &self,
        path: &str,
        dot: &Dot,
        except: Option<&RecordHash>,
    ) -> Option<RecordHash> {
        self.tree_dirs
            .at_and_above(path)
            .into_iter()
            .find_map(|set| {
                set.iter()
                    .find(|h| {
                        Some(*h) != except
                            && self
                                .held
                                .get(h)
                                .and_then(Held::meta)
                                .is_some_and(|m| m.vector.covers(dot))
                    })
                    .copied()
            })
    }

    /// The held applied records at or beneath `dir` that `vector` covers: per
    /// entry `(d, c)`, device `d`'s records there with counters at most `c`,
    /// found through the index by path, never by a walk (4.4, "Judging a
    /// tree delete without a walk").
    pub(crate) fn covered_beneath(&self, dir: &str, vector: &Vector) -> Vec<RecordHash> {
        let mut out = Vec::new();
        for e in vector.entries() {
            self.by_path.at_most(&e.device, dir, e.counter, &mut out);
        }
        out
    }

    /// Whether `vector` covers some held applied record at or beneath `dir`:
    /// at most two queries per entry.
    pub(crate) fn covers_beneath(&self, dir: &str, vector: &Vector) -> bool {
        vector
            .entries()
            .iter()
            .any(|e| self.by_path.any_at_most(&e.device, dir, e.counter))
    }

    /// A held applied record at `tag`, not a tree delete, whose vector covers
    /// `dot`.
    pub(crate) fn covering_at_tag(&self, tag: &PathTag, dot: &Dot) -> Option<RecordHash> {
        self.at_tag.get(tag).into_iter().flatten().find_map(|h| {
            let m = self.held.get(h)?.meta()?;
            (!m.tree && m.vector.covers(dot)).then_some(*h)
        })
    }

    /// What the groups whose `because` is `hash` name, held or not.
    pub(crate) fn groups_because(&self, hash: &RecordHash) -> Vec<RecordHash> {
        self.by_because
            .get(hash)
            .into_iter()
            .flatten()
            .filter_map(|(c, g)| {
                self.held
                    .get(c)?
                    .record
                    .groups()
                    .get(usize::try_from(*g).ok()?)
                    .map(|grp| grp.forget.clone())
            })
            .flatten()
            .collect()
    }

    /// What held replaces an applied index record by coverage (4.4, "Latest
    /// only"): a record at its tag (for a version or tombstone) or a tree
    /// delete at or above its path. A tree delete is covered only by a later
    /// tree delete.
    pub(crate) fn covered(
        &self,
        tag: &PathTag,
        meta: &Meta,
        except: Option<&RecordHash>,
    ) -> Option<RecordHash> {
        if !meta.tree {
            if let Some(h) = self.covering_at_tag(tag, &meta.dot) {
                return Some(h);
            }
        }
        self.covering_tree_delete(&meta.path, &meta.dot, except)
    }

    /// The held records `record` replaces (4.4 step 6): those at its tag it
    /// names; for a cleanup, those its applying groups name; at a read or
    /// write holder, for an applied record, those at its tag it covers, and,
    /// for a tree delete, those at or beneath it it covers.
    pub(crate) fn replaced_by(
        &self,
        record: &Record,
        applied: Option<&Applied>,
    ) -> BTreeSet<RecordHash> {
        let mut out = BTreeSet::new();
        if let Some(tag) = record.path_tag() {
            if let Some(at) = self.at_tag.get(&tag) {
                out.extend(record.replaces().iter().filter(|h| at.contains(h)));
            }
        }
        for g in record.groups() {
            if g.because.as_ref().is_none_or(|b| self.is_held(b)) {
                out.extend(g.forget.iter().filter(|h| self.is_held(h)));
            }
        }
        if let (Some(tag), Some(meta)) = (record.path_tag(), applied.and_then(Applied::meta)) {
            if meta.tree {
                out.extend(self.covered_beneath(&meta.path, &meta.vector));
            } else {
                for h in self.at_tag.get(&tag).into_iter().flatten() {
                    if let Some(m) = self.held.get(h).and_then(Held::meta) {
                        if !m.tree && meta.vector.covers(&m.dot) {
                            out.insert(*h);
                        }
                    }
                }
            }
        }
        out.remove(&record.hash());
        out
    }

    /// Whether `record` replaces anything held (4.4 step 3, "and that replaces
    /// nothing held"), the cheap way: its names at its tag, its applying
    /// groups, and, for an applied record, what it covers at its tag, or, for
    /// a tree delete, beneath it through the index by path.
    pub(crate) fn replaces_any(&self, record: &Record, applied: Option<&Applied>) -> bool {
        let hash = record.hash();
        if let Some(tag) = record.path_tag() {
            if let Some(at) = self.at_tag.get(&tag) {
                if record
                    .replaces()
                    .iter()
                    .any(|h| *h != hash && at.contains(h))
                {
                    return true;
                }
            }
        }
        if record.groups().iter().any(|g| {
            g.because.as_ref().is_none_or(|b| self.is_held(b))
                && g.forget.iter().any(|h| *h != hash && self.is_held(h))
        }) {
            return true;
        }
        match (record.path_tag(), applied.and_then(Applied::meta)) {
            (Some(_), Some(meta)) if meta.tree => self.covers_beneath(&meta.path, &meta.vector),
            (Some(tag), Some(meta)) => self.at_tag.get(&tag).into_iter().flatten().any(|h| {
                *h != hash
                    && self
                        .held
                        .get(h)
                        .and_then(Held::meta)
                        .is_some_and(|m| !m.tree && meta.vector.covers(&m.dot))
            }),
            _ => false,
        }
    }

    /// What held replaces `record` (named, forgotten by an applying group,
    /// or, at a read or write holder, covered): the record that does, or the
    /// record itself for a name with no single replacer.
    pub(crate) fn replacer(&self, record: &Record, applied: Option<&Applied>) -> Option<Replacer> {
        if self.named(record) {
            return Some(Replacer::Name);
        }
        let (tag, meta) = (record.path_tag()?, applied?.meta()?);
        if !meta.tree {
            if let Some(h) = self.covering_at_tag(&tag, &meta.dot) {
                return Some(Replacer::Covered(h));
            }
        }
        self.covering_tree_delete(&meta.path, &meta.dot, Some(&record.hash()))
            .map(Replacer::Beneath)
    }

    /// The deletions and cleanups the folder's own time has passed by their
    /// horizon: strictly more than (4.4, "Expiry").
    pub(crate) fn expired(&self, tombstone_horizon: u64, cleanup_horizon: u64) -> Vec<RecordHash> {
        let g = self.folder_time();
        let mut out = Vec::new();
        if let Some(limit) = g.checked_sub(tombstone_horizon) {
            out.extend(
                self.deletions
                    .range(..(limit, RecordHash([0; 32])))
                    .map(|(_, h)| *h),
            );
            out.extend(
                self.base_deletions
                    .range(..(limit, RecordHash([0; 32])))
                    .map(|(_, h)| *h),
            );
        }
        if let Some(limit) = g.checked_sub(cleanup_horizon) {
            out.extend(
                self.cleanup_counters
                    .range(..(limit, RecordHash([0; 32])))
                    .map(|(_, h)| *h),
            );
        }
        out
    }

    /// The metadata of an applied record held or kept as a base.
    pub(crate) fn base_meta(&self, hash: &RecordHash) -> Option<&Meta> {
        self.held
            .get(hash)
            .and_then(Held::meta)
            .or_else(|| self.base_only.get(hash).map(|b| &b.meta))
    }

    /// The record held or kept as a base.
    pub(crate) fn base_record(&self, hash: &RecordHash) -> Option<&Record> {
        self.held
            .get(hash)
            .map(|h| &h.record)
            .or_else(|| self.base_only.get(hash).map(|b| &b.record))
    }

    /// The base slots at `tag`, with their records.
    pub(crate) fn bases_at(&self, tag: &PathTag) -> Vec<(BaseSlot, RecordHash)> {
        use crate::store::Place;
        let lo = (*tag, Place::Path);
        self.bases
            .range(lo..)
            .take_while(|((t, _), _)| t == tag)
            .map(|(s, h)| (s.clone(), *h))
            .collect()
    }

    // Primitives.

    /// Holds `held`, keeping every derived structure in step.
    pub(crate) fn hold(&mut self, held: Held, undo: Option<&mut Vec<Undo>>) {
        let hash = held.record.hash();
        if self.held.contains_key(&hash) {
            return;
        }
        let mut undo = undo;
        if let Some(b) = self.base_only.remove(&hash) {
            if let Some(m) = Some(&b.meta).filter(|m| m.deleted) {
                self.base_deletions.remove(&(m.dot.counter, hash));
            }
            log(undo.as_deref_mut(), Undo::BaseOnlyRemoved(Box::new(b)));
        }
        self.raw_hold(held);
        log(undo, Undo::Held(hash));
    }

    fn raw_hold(&mut self, held: Held) {
        let hash = held.record.hash();
        self.by_seq.insert(held.seq, hash);
        self.trie.insert(held.record.key());
        for c in held.record.chunks() {
            *self.chunks.entry(c.cipher_hash).or_insert(0) += 1;
        }
        if let Some(tag) = held.record.path_tag() {
            self.at_tag.entry(tag).or_default().insert(hash);
            for name in held.record.replaces() {
                *self.named_at.entry((tag, *name)).or_insert(0) += 1;
            }
        } else {
            self.cleanups.insert(hash);
        }
        for (i, g) in held.record.groups().iter().enumerate() {
            let gi = u32::try_from(i).unwrap_or(u32::MAX);
            for name in &g.forget {
                self.forgets.entry(*name).or_default().insert((hash, gi));
            }
            if let Some(b) = g.because {
                self.by_because.entry(b).or_default().insert((hash, gi));
            }
        }
        if let Some(c) = held.counter() {
            *self.counters.entry(c).or_insert(0) += 1;
            match held.meta() {
                Some(m) => {
                    if m.deleted {
                        self.deletions.insert((c, hash));
                    }
                    self.paths.entry(m.path.clone()).or_default().insert(hash);
                    self.by_path
                        .insert(m.dot.device, m.path.as_bytes(), hash, m.dot.counter);
                    if m.tree {
                        self.tree_dirs.insert(&m.path, hash);
                    }
                }
                None => {
                    self.cleanup_counters.insert((c, hash));
                }
            }
        }
        self.held.insert(hash, held);
    }

    /// Stops holding `hash`. A record that is a base stays, kept only as a
    /// base, while it is applied.
    pub(crate) fn unhold(
        &mut self,
        hash: &RecordHash,
        undo: Option<&mut Vec<Undo>>,
    ) -> Option<RecordHash> {
        let held = self.raw_unhold(hash)?;
        let mut undo = undo;
        let keep = self.slots_of.get(hash).is_some_and(|s| !s.is_empty());
        let base = keep
            .then(|| held.meta().cloned())
            .flatten()
            .map(|meta| BaseRecord {
                record: held.record.clone(),
                meta,
            });
        log(undo.as_deref_mut(), Undo::Unheld(Box::new(held)));
        if let Some(b) = base {
            self.put_base_only(b, undo);
        }
        Some(*hash)
    }

    fn raw_unhold(&mut self, hash: &RecordHash) -> Option<Held> {
        let held = self.held.remove(hash)?;
        // Only its own entry: a number another record holds stays its
        // (the coordinator's ruling IS-3).
        if self.by_seq.get(&held.seq) == Some(hash) {
            self.by_seq.remove(&held.seq);
        }
        self.trie.remove(held.record.key());
        for c in held.record.chunks() {
            if let Some(n) = self.chunks.get_mut(&c.cipher_hash) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.chunks.remove(&c.cipher_hash);
                }
            }
        }
        if let Some(tag) = held.record.path_tag() {
            if let Some(set) = self.at_tag.get_mut(&tag) {
                set.remove(hash);
                if set.is_empty() {
                    self.at_tag.remove(&tag);
                }
            }
            for name in held.record.replaces() {
                if let Some(n) = self.named_at.get_mut(&(tag, *name)) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.named_at.remove(&(tag, *name));
                    }
                }
            }
        } else {
            self.cleanups.remove(hash);
        }
        for (i, g) in held.record.groups().iter().enumerate() {
            let gi = u32::try_from(i).unwrap_or(u32::MAX);
            for name in &g.forget {
                if let Some(set) = self.forgets.get_mut(name) {
                    set.remove(&(*hash, gi));
                    if set.is_empty() {
                        self.forgets.remove(name);
                    }
                }
            }
            if let Some(b) = g.because {
                if let Some(set) = self.by_because.get_mut(&b) {
                    set.remove(&(*hash, gi));
                    if set.is_empty() {
                        self.by_because.remove(&b);
                    }
                }
            }
        }
        if let Some(c) = held.counter() {
            if let Some(n) = self.counters.get_mut(&c) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.counters.remove(&c);
                }
            }
            match held.meta() {
                Some(m) => {
                    self.deletions.remove(&(c, *hash));
                    self.by_path.remove(&m.dot.device, m.path.as_bytes(), hash);
                    if m.tree {
                        self.tree_dirs.remove(&m.path, hash);
                    }
                    if let Some(set) = self.paths.get_mut(&m.path) {
                        set.remove(hash);
                        if set.is_empty() {
                            self.paths.remove(&m.path);
                        }
                    }
                }
                None => {
                    self.cleanup_counters.remove(&(c, *hash));
                }
            }
        }
        Some(held)
    }

    fn put_base_only(&mut self, base: BaseRecord, undo: Option<&mut Vec<Undo>>) {
        let hash = base.record.hash();
        if base.meta.deleted {
            self.base_deletions.insert((base.meta.dot.counter, hash));
        }
        self.base_only.insert(hash, base);
        log(undo, Undo::BaseOnlyPut(hash));
    }

    fn remove_base_only(&mut self, hash: &RecordHash, undo: Option<&mut Vec<Undo>>) {
        if let Some(b) = self.base_only.remove(hash) {
            if b.meta.deleted {
                self.base_deletions.remove(&(b.meta.dot.counter, *hash));
            }
            log(undo, Undo::BaseOnlyRemoved(Box::new(b)));
        }
    }

    /// Sets a base slot (or clears it, `None`). A record that stops being a
    /// base anywhere and is not held is forgotten; a record that becomes a
    /// base while it is kept nowhere is kept only as a base (`base`, which
    /// the caller gives when the record is not held).
    pub(crate) fn set_base(
        &mut self,
        slot: BaseSlot,
        hash: Option<RecordHash>,
        base: Option<BaseRecord>,
        undo: Option<&mut Vec<Undo>>,
    ) {
        let mut undo = undo;
        let old = match hash {
            Some(h) => self.bases.insert(slot.clone(), h),
            None => self.bases.remove(&slot),
        };
        if old == hash {
            return;
        }
        log(undo.as_deref_mut(), Undo::Base(slot.clone(), old));
        if hash.is_none() {
            self.base_slot_removed(&slot.0);
        }
        if let Some(o) = old {
            if let Some(set) = self.slots_of.get_mut(&o) {
                set.remove(&slot);
                if set.is_empty() {
                    self.slots_of.remove(&o);
                    self.remove_base_only(&o, undo.as_deref_mut());
                }
            }
        }
        if let Some(h) = hash {
            let tag = slot.0;
            self.slots_of.entry(h).or_default().insert(slot);
            if !self.held.contains_key(&h) && !self.base_only.contains_key(&h) {
                if let Some(b) = base {
                    self.put_base_only(b, undo);
                }
            }
            if old.is_none() {
                self.base_slot_added(tag, &h);
            }
        }
    }

    /// Counts a new base slot at `tag`, whose record is `hash`: the first
    /// slot of a file ID enters the paths with a base slot, at the path of
    /// its record (a base slot's record lies at its file ID).
    fn base_slot_added(&mut self, tag: PathTag, hash: &RecordHash) {
        if let Some(entry) = self.base_tags.get_mut(&tag) {
            entry.1 += 1;
            return;
        }
        if let Some(path) = self.base_meta(hash).map(|m| m.path.clone()) {
            self.base_paths.insert(path.clone(), tag);
            self.base_tags.insert(tag, (path, 1));
        }
    }

    /// Counts a base slot gone from `tag`: the last one takes the file ID
    /// out of the paths with a base slot.
    fn base_slot_removed(&mut self, tag: &PathTag) {
        let last = self.base_tags.get_mut(tag).is_some_and(|entry| {
            entry.1 = entry.1.saturating_sub(1);
            entry.1 == 0
        });
        if last {
            if let Some((path, _)) = self.base_tags.remove(tag) {
                self.base_paths.remove(&path);
            }
        }
    }

    /// The base slots at or beneath `dir`, in path order, each with its
    /// path and its record: the file IDs with a base slot there, two ranges
    /// by path (`dir` itself, then `dir/` up to `dir0`; the root, `""`, is
    /// every one), and each one's slots, a range by file ID. What it reads
    /// is what lies beneath `dir`, whatever else is held.
    pub(crate) fn base_slots_at_or_beneath<'a>(
        &'a self,
        dir: &str,
    ) -> impl Iterator<Item = (&'a str, &'a BaseSlot, &'a RecordHash)> + 'a {
        at_or_beneath(&self.base_paths, dir).flat_map(move |(path, tag)| {
            self.read_beneath();
            self.bases
                .range((*tag, crate::Place::Path)..)
                .take_while(move |((t, _), _)| t == tag)
                .inspect(|_| self.read_beneath())
                .map(move |(slot, hash)| (path.as_str(), slot, hash))
        })
    }

    /// The applied index records held at or beneath `dir`, by path: two
    /// ranges of the paths (`dir` itself, then `dir/` up to `dir0`).
    pub(crate) fn paths_at_or_beneath<'a>(
        &'a self,
        dir: &str,
    ) -> impl Iterator<Item = (&'a String, &'a BTreeSet<RecordHash>)> + 'a {
        at_or_beneath(&self.paths, dir).inspect(|_| self.read_beneath())
    }

    /// Counts one entry a range at or beneath a directory read, in the
    /// tests.
    #[cfg(test)]
    fn read_beneath(&self) {
        self.beneath_read.add(1);
    }

    /// Counts nothing outside the tests.
    #[cfg(not(test))]
    #[allow(clippy::unused_self, reason = "the tests' twin reads self")]
    const fn read_beneath(&self) {}

    pub(crate) fn set_meta(&mut self, meta: StoredMeta, undo: Option<&mut Vec<Undo>>) {
        if meta != self.meta {
            log(undo, Undo::Meta(self.meta));
            self.meta = meta;
        }
    }

    pub(crate) fn set_peer(
        &mut self,
        peer: DeviceId,
        state: Option<PeerState>,
        undo: Option<&mut Vec<Undo>>,
    ) {
        let old = match state {
            Some(s) => self.peers.insert(peer, s),
            None => self.peers.remove(&peer),
        };
        if old != state {
            log(undo, Undo::Peer(peer, old));
        }
    }

    pub(crate) fn add_note(&mut self, note: Note, undo: Option<&mut Vec<Undo>>) {
        let hash = note.hash;
        if self.notes.contains_key(&hash) {
            return;
        }
        if let Noted::Stale { tag, .. } = &note.noted {
            self.notes_at.entry(*tag).or_default().insert(hash);
        }
        self.note_order.insert(note.nr, hash);
        let before = self.next_note;
        self.next_note = self.next_note.max(note.nr.saturating_add(1));
        self.notes.insert(hash, note);
        log(undo, Undo::NoteAdded(hash, before));
    }

    pub(crate) fn remove_note(&mut self, hash: &RecordHash, undo: Option<&mut Vec<Undo>>) {
        let Some(note) = self.notes.remove(hash) else {
            return;
        };
        self.note_order.remove(&note.nr);
        if let Noted::Stale { tag, .. } = &note.noted {
            if let Some(set) = self.notes_at.get_mut(tag) {
                set.remove(hash);
                if set.is_empty() {
                    self.notes_at.remove(tag);
                }
            }
        }
        log(undo, Undo::NoteRemoved(Box::new(note)));
    }

    /// Undoes `undo`, newest first, restoring exactly what was before.
    pub(crate) fn rollback(&mut self, undo: Vec<Undo>) {
        for entry in undo.into_iter().rev() {
            match entry {
                Undo::Held(h) => {
                    self.raw_unhold(&h);
                }
                Undo::Unheld(held) => self.raw_hold(*held),
                Undo::BaseOnlyPut(h) => {
                    if let Some(b) = self.base_only.remove(&h) {
                        if b.meta.deleted {
                            self.base_deletions.remove(&(b.meta.dot.counter, h));
                        }
                    }
                }
                Undo::BaseOnlyRemoved(b) => self.put_base_only(*b, None),
                Undo::Base(slot, old) => {
                    let now = match old {
                        Some(h) => self.bases.insert(slot.clone(), h),
                        None => self.bases.remove(&slot),
                    };
                    // The undone change added the slot, or took it away:
                    // its record is held or kept as a base again by now,
                    // the later entries being undone first.
                    match (now, old) {
                        (Some(_), None) => self.base_slot_removed(&slot.0),
                        (None, Some(o)) => self.base_slot_added(slot.0, &o),
                        _ => {}
                    }
                    if let Some(n) = now {
                        if let Some(set) = self.slots_of.get_mut(&n) {
                            set.remove(&slot);
                            if set.is_empty() {
                                self.slots_of.remove(&n);
                            }
                        }
                    }
                    if let Some(o) = old {
                        self.slots_of.entry(o).or_default().insert(slot);
                    }
                }
                Undo::Meta(m) => self.meta = m,
                Undo::Peer(p, s) => {
                    match s {
                        Some(s) => self.peers.insert(p, s),
                        None => self.peers.remove(&p),
                    };
                }
                Undo::NoteAdded(h, next) => {
                    self.remove_note(&h, None);
                    self.next_note = next;
                }
                Undo::NoteRemoved(n) => self.add_note(*n, None),
            }
        }
    }

    /// The change set an undo log stands for, against the state as it now is
    /// (4.7 item 1).
    pub(crate) fn changes(&self, undo: &[Undo]) -> ChangeSet {
        let mut before_held: BTreeMap<RecordHash, Option<u64>> = BTreeMap::new();
        let mut before_base: BTreeMap<RecordHash, bool> = BTreeMap::new();
        let mut before_slots: BTreeMap<BaseSlot, Option<RecordHash>> = BTreeMap::new();
        let mut before_meta = None;
        let mut before_peers: BTreeMap<DeviceId, Option<PeerState>> = BTreeMap::new();
        let mut removed_chunks = BTreeSet::new();
        for entry in undo {
            match entry {
                Undo::Held(h) => {
                    before_held.entry(*h).or_insert(None);
                }
                Undo::Unheld(held) => {
                    before_held
                        .entry(held.record.hash())
                        .or_insert(Some(held.seq));
                    removed_chunks.extend(held.record.chunks().iter().map(|c| c.cipher_hash));
                }
                Undo::BaseOnlyPut(h) => {
                    before_base.entry(*h).or_insert(false);
                }
                Undo::BaseOnlyRemoved(b) => {
                    before_base.entry(b.record.hash()).or_insert(true);
                }
                Undo::Base(slot, old) => {
                    before_slots.entry(slot.clone()).or_insert(*old);
                }
                Undo::Meta(m) => {
                    before_meta.get_or_insert(*m);
                }
                Undo::Peer(p, s) => {
                    before_peers.entry(*p).or_insert(*s);
                }
                Undo::NoteAdded(..) | Undo::NoteRemoved(_) => {}
            }
        }
        let mut out = ChangeSet::default();
        let mut puts: Vec<(u64, RecordHash)> = Vec::new();
        for (h, before) in &before_held {
            match (before, self.held.get(h)) {
                (Some(s), Some(now)) if *s == now.seq => {}
                (_, Some(now)) => puts.push((now.seq, *h)),
                (Some(_), None) => out.remove.push(*h),
                (None, None) => {}
            }
        }
        puts.sort_unstable();
        out.put = puts
            .iter()
            .filter_map(|(s, h)| Some((self.held.get(h)?.record.signed().clone(), *s)))
            .collect();
        for (h, before) in &before_base {
            match (before, self.base_only.get(h)) {
                (false, Some(b)) => out.base_only_put.push(b.record.signed().clone()),
                (true, None) => out.base_only_remove.push(*h),
                _ => {}
            }
        }
        for (slot, before) in before_slots {
            let now = self.bases.get(&slot).copied();
            if now != before {
                out.bases.push((slot, now));
            }
        }
        if before_meta.is_some_and(|m| m != self.meta) {
            out.meta = Some(self.meta);
        }
        for (p, before) in before_peers {
            let now = self.peers.get(&p).copied();
            if now != before {
                out.peers.push((p, now));
            }
        }
        out.freed = removed_chunks
            .into_iter()
            .filter(|c| !self.chunks.contains_key(c))
            .collect();
        out
    }

    /// The record hashes held in the subtree at `prefix`, in key order.
    pub(crate) fn subtree(&self, prefix: &Prefix) -> Vec<RecordHash> {
        self.trie.records(prefix)
    }
}

/// What replaces a record that arrives (4.4 steps 3, 6 and 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Replacer {
    /// A held record names it at its tag, or a held cleanup in a group that
    /// applies.
    Name,
    /// A held record at its tag covers it.
    Covered(RecordHash),
    /// A held tree delete at or above its path covers it.
    Beneath(RecordHash),
}
