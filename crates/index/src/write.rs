// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A write holder's records (`protocol.md` 4.4, "The writer's rule", "The
//! vector and names of a new record", "Cleanup"; 4.7 item 6): a batch of
//! changes is one commit, its records taking consecutive counters from one
//! reading of the clock, versions, then tree deletes, then tombstones, then
//! cleanups, each kind by ascending path tag (cleanups in page order); and
//! the cleanups a write holder issues at the end of a round for the stale
//! copies and forgotten records it noted.
//!
//! Every vector is built from the content on this device's disk, never from
//! records held whose content has not reached it ("Why it is safe" 9): `S`
//! is the bases at the path and their twins, the live heads there of a
//! base's content that are concurrent with it, are never the first head in
//! display order at the path and, for the base at the path itself, come
//! after it in display order (never a tree delete, at most
//! `MAX_VECTOR_ENTRIES`: the bases first, then the twins, this device's own
//! records first within each, then display order), and the vector is the
//! join of their dots and vectors, pruned to `MAX_VECTOR_ENTRIES` with the
//! entries of `S`'s devices kept. The names are `S`'s fingerprints, then the
//! shared writer faults held at the path that no held cleanup names, then
//! the noted stale copies at the path that the new vector covers, up to
//! `MAX_REPLACES`. A tree delete's join takes the bases at or beneath its
//! directory and their twins alike; it names the first 32 of those at its
//! own path in `S`'s order, their devices mandatory in its prune, so that
//! it names only what its vector covers.

use std::collections::{BTreeMap, BTreeSet};

use core::cmp::Reverse;
use core::fmt;

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, PathTag, RandomFill, RecordHash};
use licketysync_protocol::limits::{MAX_COUNTER, MAX_REPLACES};
use licketysync_protocol::record::{
    at_or_beneath, check_path, Chunk, CleanupDraft, Dot, DraftError, Group, IndexDraft, Kind, Meta,
    PathError, Record, Vector, WriterFault,
};

use crate::index::{Accepted, Seq, Txn};
use crate::state::{BaseRecord, Noted};
use crate::store::Place;
use crate::views::{display_rank, same_content};

/// A version or a tombstone at `path` (4.7 item 6, "The current version"):
/// what the engine found on its disk.
#[derive(Clone, Debug)]
pub struct Put {
    /// The path, NFC-normalised by the engine.
    pub path: String,
    /// File or directory; for a tombstone, the kind of the version deleted.
    pub kind: Kind,
    /// Bytes of content; 0 for a tombstone.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    /// Unix permission bits; 0 when the device has none.
    pub mode: u32,
    /// The chunk references, in file order; none for a tombstone.
    pub chunks: Vec<Chunk>,
    /// The plaintext hash of each chunk.
    pub plain_hashes: Vec<PlainHash>,
    /// A tombstone.
    pub deleted: bool,
}

/// One change of a batch (4.7 item 6).
#[derive(Clone, Debug)]
pub enum Change {
    /// An edit, a delete (a tombstone) or a write that resolves a conflict:
    /// one record at its path.
    Put(Put),
    /// A rename: a version at the new path (`to`), then a tombstone at
    /// `from`, two records in that order.
    Rename {
        /// The old path.
        from: String,
        /// The version at the new path.
        to: Put,
    },
    /// A tree delete of a directory gone from the disk with everything
    /// beneath it, with the tombstones its pruned vector leaves to write and
    /// the cleanup `because` it.
    TreeDelete {
        /// The directory.
        path: String,
        /// When it was found gone, nanoseconds since the Unix epoch.
        mtime_ns: i64,
    },
    /// A conflict copy on the disk written as a version at its own path, `S`
    /// empty, before a write over the conflict ("What becomes of a conflict
    /// copy"): it stops being a base of the original path's `copy` slot and
    /// becomes the base of its own path.
    Promote {
        /// The original path.
        from: String,
        /// The copy's name in the original path's base slots.
        copy: String,
        /// The version at the copy's own path.
        to: Put,
    },
}

/// Why a write was refused; nothing was staged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteError {
    /// This device holds no write key for the folder: read and sealed holders
    /// write nothing (4.4).
    NotWriteKey,
    /// The next counter would pass `MAX_COUNTER`: the folder must be shared
    /// again (4.4, section 5).
    CounterExhausted,
    /// A path breaks the grammar.
    Path(PathError),
    /// One path twice in a batch.
    DuplicatePath(String),
    /// A record would break a reader's rule (its sealed part over the cap
    /// included).
    Draft(DraftError),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWriteKey => f.write_str("this device holds no write key for the folder"),
            Self::CounterExhausted => {
                f.write_str("the folder's counter is exhausted: share it again")
            }
            Self::Path(e) => write!(f, "{e}"),
            Self::DuplicatePath(p) => write!(f, "the path {p} twice in one batch"),
            Self::Draft(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// What a write (or a round's end) made: every record signed, in counter
/// order, with its local sequence number when it is held, and what the batch
/// dropped. Push the held ones to every connection where the folder is open.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Written {
    /// The records signed, in counter order, with their local sequence
    /// numbers.
    pub records: Vec<(RecordHash, Option<u64>)>,
    /// The records the batch dropped.
    pub dropped: Vec<RecordHash>,
    /// The paths whose heads changed, and those of the base slots the
    /// batch cleared (sorted, each once).
    pub paths: Vec<String>,
    /// Whether a cleanup was issued (at a round's end: the round owes
    /// another).
    pub cleanup: bool,
}

/// The order of kinds in a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Order {
    Version,
    TreeDelete,
    Tombstone,
}

/// One index record of a batch, planned before counters are given.
#[derive(Clone, Debug)]
struct Plan {
    order: Order,
    tag: PathTag,
    put: Put,
    tree: bool,
    vector: Vector,
    replaces: Vec<RecordHash>,
    /// Shared writer faults that did not fit `replaces`: a cleanup group
    /// `because` this record names them.
    overflow: Vec<RecordHash>,
    /// The notes this record names.
    noted: Vec<RecordHash>,
    /// The base slots this record clears (a promoted copy's original slot;
    /// a tree delete's slots beneath it).
    clears: Vec<(PathTag, Place)>,
    /// A tree delete's cleanup: what it covers at or beneath its directory.
    covers: Vec<RecordHash>,
}

/// The names a batch gives each offering peer's noted copies, counted
/// against that peer's `MAX_PEER_NAMES` window, as the round's cleanups are
/// ("at most `MAX_PEER_NAMES` in writes and cleanups together", 4.5; the R2
/// review's N10).
struct Spent {
    clock_us: u64,
    by_peer: BTreeMap<DeviceId, u64>,
}

/// A base at a tag (4.4, "Bases"): the place it stands for (the path
/// itself, or one of its conflict copies), its record and its metadata.
type Base = (Place, RecordHash, Meta);

/// Whether the record `h` (`m`) held at a base's tag is a **twin** of that
/// base, `b` (`bm`) standing for `place` (4.4, "Bases"): it holds the base's
/// content ([`same_content`]: two tombstones, two directories, or two files
/// with the same plaintext hashes; never a tree delete); it is concurrent
/// with the base, its vector not covering the base's dot, so a later
/// version of the base, one that changed only its mode or time say, is
/// never its twin (the R2 review's R2-1); and, for the base at the path
/// itself, it comes after the base in display order (the security review's
/// F1). Neither of the last two implies the other: a concurrent record with
/// a later `mtime_ns` comes first, and a later version with the same or an
/// earlier one can come after. A conflict copy's base is matched by the
/// first two alone: its place is beside the path, whatever the display
/// order. (Two records' display ranks are never equal, the record hash
/// ending them, so "after" is a strict order.) [`Txn::twins_at`] adds the
/// last condition, for every base: a twin is never the first head in
/// display order at its path, so it is never the head the engine has yet to
/// put at the path, its time and mode not on the disk (the confirm review's
/// C1).
fn twin_of(place: &Place, b: &RecordHash, bm: &Meta, h: &RecordHash, m: &Meta) -> bool {
    same_content(bm, m)
        && !m.vector.covers(&bm.dot)
        && (*place != Place::Path || display_rank(b, bm).cmp(&display_rank(h, m)).is_lt())
}

/// The join of dots and vectors: for each device, the greatest counter any
/// gives it.
fn join<'a>(metas: impl IntoIterator<Item = &'a Meta>) -> BTreeMap<DeviceId, u64> {
    let mut out: BTreeMap<DeviceId, u64> = BTreeMap::new();
    for m in metas {
        for d in m.vector.entries().iter().chain(core::iter::once(&m.dot)) {
            let e = out.entry(d.device).or_insert(0);
            *e = (*e).max(d.counter);
        }
    }
    out
}

/// Prunes a join to `cap` entries: the `mandatory` devices' entries are kept,
/// and the rest of the places go to the greatest counters, the smaller device
/// ID first between equal counters (4.4, "Pruning"). A join of applied
/// records' dots is ascending with counters of at least 1, so the vector is
/// always one; were it not, the write is refused, never signed with a vector
/// that covers less than its join (the R1 review's NIT on the silent
/// fallback).
///
/// # Errors
/// [`WriteError::Draft`] with [`DraftError::VectorCounter`], unreachable.
pub(crate) fn prune(
    joined: &BTreeMap<DeviceId, u64>,
    mandatory: &BTreeSet<DeviceId>,
    cap: usize,
) -> Result<Vector, WriteError> {
    let mut keep: BTreeSet<DeviceId> = mandatory
        .iter()
        .filter(|d| joined.contains_key(d))
        .copied()
        .collect();
    let mut others: Vec<(Reverse<u64>, DeviceId)> = joined
        .iter()
        .filter(|(d, _)| !keep.contains(d))
        .map(|(d, c)| (Reverse(*c), *d))
        .collect();
    others.sort_unstable();
    for (_, d) in others {
        if keep.len() >= cap {
            break;
        }
        keep.insert(d);
    }
    let entries = joined
        .iter()
        .filter(|(d, _)| keep.contains(d))
        .map(|(d, c)| Dot {
            device: *d,
            counter: *c,
        })
        .collect();
    Vector::from_sorted(entries).ok_or(WriteError::Draft(DraftError::VectorCounter))
}

impl Txn<'_> {
    /// `S` at a tag (4.4, "The vector and names of a new record"): its
    /// bases, never a tree delete, and their twins ([`Self::twins_at`]), the
    /// first `MAX_VECTOR_ENTRIES` in `S`'s order ([`Self::first_in_s_order`]).
    /// A twin's content is a base's, so it is on the disk as much as that
    /// base is ("Why it is safe" 9); past the cap, the twins last in that
    /// order are left out and stay heads until the next write there.
    fn s_at(&self, tag: &PathTag) -> Vec<(RecordHash, Meta)> {
        let bases: Vec<Base> = self
            .ix
            .s
            .bases_at(tag)
            .into_iter()
            .filter_map(|((_, place), h)| Some((place, h, self.ix.s.base_meta(&h)?.clone())))
            .filter(|(_, _, m)| !m.tree)
            .collect();
        let twins = self.twins_at(tag, &bases);
        self.first_in_s_order(bases, twins)
    }

    /// `bases` and `twins` (at one tag), each record once, in `S`'s order:
    /// the bases first, then the twins, this device's own records first
    /// within each, then display order; the first `MAX_VECTOR_ENTRIES` of
    /// them. So a twin never takes a place a base would have had, and
    /// records signed under this device's ID with a base's content (a
    /// cloned image, or a write holder writing under it, "Why it is safe"
    /// 8(b)) cannot push the base out (the security review's F5).
    fn first_in_s_order(
        &self,
        bases: Vec<Base>,
        twins: Vec<(RecordHash, Meta)>,
    ) -> Vec<(RecordHash, Meta)> {
        let own = self.ix.own;
        let mut s: Vec<(bool, RecordHash, Meta)> = bases
            .into_iter()
            .map(|(_, h, m)| (false, h, m))
            .chain(twins.into_iter().map(|(h, m)| (true, h, m)))
            .collect();
        s.sort_by_key(|(twin, h, m)| (*twin, m.dot.device != own, display_rank(h, m)));
        // One record in two slots (the path and a copy) is one member.
        s.dedup_by_key(|(_, h, _)| *h);
        s.truncate(self.ix.bounds.vector);
        s.into_iter().map(|(_, h, m)| (h, m)).collect()
    }

    /// The **twins** at `tag` of `bases` (records at `tag`; 4.4, "Bases"):
    /// every other applied record held there that is a twin of one of them
    /// ([`twin_of`]) and is not the first head there in display order, in
    /// ascending record hash. At a read or write holder every such record is
    /// live, a head beside the base it matches, which the display order
    /// shows as one file with no conflict copy. The first head (never a tree
    /// delete) is the record the engine puts at the path, its time and mode
    /// not on the disk until it is a base; it is no twin even where
    /// [`twin_of`]'s display order does not keep it out: when the base at the
    /// path is no longer the first head (a later version still arriving
    /// replaced it), or when it matches a conflict copy's base (the confirm
    /// review's C1).
    fn twins_at(&self, tag: &PathTag, bases: &[Base]) -> Vec<(RecordHash, Meta)> {
        let applied: Vec<(RecordHash, &Meta)> = self
            .ix
            .s
            .at_tag
            .get(tag)
            .into_iter()
            .flatten()
            .filter_map(|h| Some((*h, self.ix.s.held.get(h)?.meta()?)))
            .collect();
        let first = applied
            .iter()
            .filter(|(_, m)| !m.tree)
            .min_by_key(|(h, m)| display_rank(h, m))
            .map(|(h, _)| *h);
        applied
            .into_iter()
            .filter(|(h, _)| bases.iter().all(|(_, b, _)| b != h))
            .filter(|(h, _)| Some(*h) != first)
            .filter(|(h, m)| {
                bases
                    .iter()
                    .any(|(place, b, bm)| twin_of(place, b, bm, h, m))
            })
            .map(|(h, m)| (h, m.clone()))
            .collect()
    }

    /// The twins of the bases `beneath` a tree delete's directory, path by
    /// path ([`Self::twins_at`]), each with its tag.
    fn twins_beneath(
        &self,
        beneath: &[((PathTag, Place), RecordHash, Meta)],
    ) -> Vec<(PathTag, RecordHash, Meta)> {
        let mut by_tag: BTreeMap<PathTag, Vec<Base>> = BTreeMap::new();
        for ((t, place), h, m) in beneath {
            by_tag
                .entry(*t)
                .or_default()
                .push((place.clone(), *h, m.clone()));
        }
        by_tag
            .iter()
            .flat_map(|(t, bases)| {
                self.twins_at(t, bases)
                    .into_iter()
                    .map(move |(h, m)| (*t, h, m))
            })
            .collect()
    }

    /// The shared writer faults held at `tag` that no held cleanup names:
    /// records every release judges faults, which the next write there names
    /// (4.4, "Its names").
    fn shared_faults(&self, tag: &PathTag) -> Vec<RecordHash> {
        self.ix
            .s
            .at_tag
            .get(tag)
            .into_iter()
            .flatten()
            .filter(|h| {
                self.ix
                    .s
                    .held
                    .get(h)
                    .and_then(|r| r.verdict.as_ref())
                    .is_some_and(|v| v.as_ref().err().is_some_and(WriterFault::is_shared))
            })
            .filter(|h| !self.ix.s.named_by_any_group(h))
            .copied()
            .collect()
    }

    /// The vector and names of a version or tombstone at `tag` (`S` the
    /// bases there and their twins, or empty for a promoted copy), naming
    /// the noted copies the vector covers while their peers are within their
    /// windows.
    fn plan_put(
        &self,
        order: Order,
        tag: PathTag,
        put: Put,
        s_empty: bool,
        spent: &mut Spent,
    ) -> Result<Plan, WriteError> {
        let s = if s_empty { Vec::new() } else { self.s_at(&tag) };
        let joined = join(s.iter().map(|(_, m)| m));
        let mandatory: BTreeSet<DeviceId> = s.iter().map(|(_, m)| m.dot.device).collect();
        let vector = prune(&joined, &mandatory, self.ix.bounds.vector)?;
        let mut replaces: Vec<RecordHash> = s.iter().map(|(h, _)| *h).collect();
        let mut overflow = Vec::new();
        for f in self.shared_faults(&tag) {
            if replaces.len() < MAX_REPLACES {
                replaces.push(f);
            } else {
                overflow.push(f);
            }
        }
        let mut noted = Vec::new();
        for h in self.ix.s.notes_at.get(&tag).into_iter().flatten() {
            if replaces.len() >= MAX_REPLACES {
                break;
            }
            let Some(note) = self.ix.s.notes.get(h) else {
                continue;
            };
            if let Noted::Stale { dot, .. } = &note.noted {
                if vector.covers(dot) && !replaces.contains(h) {
                    let used = spent.by_peer.get(&note.peer).copied().unwrap_or(0);
                    if self
                        .peer_names(&note.peer, spent.clock_us)
                        .saturating_add(used)
                        >= self.ix.bounds.peer_names
                    {
                        continue;
                    }
                    spent.by_peer.insert(note.peer, used + 1);
                    replaces.push(*h);
                    noted.push(*h);
                }
            }
        }
        Ok(Plan {
            order,
            tag,
            put,
            tree: false,
            vector,
            replaces,
            overflow,
            noted,
            clears: Vec::new(),
            covers: Vec::new(),
        })
    }

    /// A tree delete of `dir`: its vector the join of every base at or
    /// beneath it and of their twins, pruned with the devices of the records
    /// it names at its own tag mandatory; those names the first
    /// `MAX_VECTOR_ENTRIES` of the bases at its own tag and their twins, in
    /// `S`'s order ([`Self::first_in_s_order`]), so that every record it
    /// names its vector covers (4.4, "Names"; "Why it is safe" 10; the
    /// security review's F2 and F4), then the shared faults there; the
    /// tombstones for bases and twins beneath it that the pruned vector
    /// misses; and its cleanup's names, every record at or beneath it held
    /// or kept as a base that it covers. A record at its own tag past those
    /// names goes if the vector covers it, and otherwise stays a head until
    /// the next delete there (more than 32 device IDs at the directory
    /// itself; a stated residual). The cap also keeps the names within
    /// `MAX_REPLACES` however many conflict copies sit at the directory's
    /// path (the R1 review's outside finding: 64 or more made the directory
    /// undeletable from that device). With no base at or beneath `dir` its
    /// vector is empty: it covers nothing, and is written as asked, a record
    /// of the directory's deletion that any later version beneath it
    /// outlives (the R1 review's NIT: the engine writes one for a directory
    /// gone from its disk, which had a base; this one is documented rather
    /// than refused).
    fn plan_tree_delete(
        &self,
        dir: String,
        mtime_ns: i64,
        plans: &mut Vec<Plan>,
        spent: &mut Spent,
    ) -> Result<(), WriteError> {
        let tag = self.tag(&dir).ok_or(WriteError::NotWriteKey)?;
        let beneath: Vec<((PathTag, Place), RecordHash, Meta)> = self
            .ix
            .s
            .bases
            .iter()
            .filter_map(|(slot, h)| Some((slot.clone(), *h, self.ix.s.base_meta(h)?.clone())))
            .filter(|(_, _, m)| at_or_beneath(&m.path, &dir))
            .collect();
        // The twins of those bases, on the disk as much as they are (4.4,
        // "The vector and names of a new record"; the identical-heads bug of
        // 2026-11-08: two identical directories, one deleted, came back).
        let twins = self.twins_beneath(&beneath);
        let joined = join(
            beneath
                .iter()
                .map(|(_, _, m)| m)
                .chain(twins.iter().map(|(_, _, m)| m)),
        );
        // The records it names at its own tag, each in the join: their
        // devices mandatory, the pruned vector covers every one.
        let named = self.first_in_s_order(
            beneath
                .iter()
                .filter(|((t, _), _, _)| *t == tag)
                .map(|((_, place), h, m)| (place.clone(), *h, m.clone()))
                .collect(),
            twins
                .iter()
                .filter(|(t, _, _)| *t == tag)
                .map(|(_, h, m)| (*h, m.clone()))
                .collect(),
        );
        let mandatory: BTreeSet<DeviceId> = named.iter().map(|(_, m)| m.dot.device).collect();
        let vector = prune(&joined, &mandatory, self.ix.bounds.vector)?;
        let mut replaces: Vec<RecordHash> = named.into_iter().map(|(h, _)| h).collect();
        let mut overflow = Vec::new();
        for f in self.shared_faults(&tag) {
            if replaces.len() < MAX_REPLACES {
                replaces.push(f);
            } else {
                overflow.push(f);
            }
        }
        // Tombstones for the bases beneath it that the pruned vector misses:
        // one per path, whatever the bases there (the path itself and its
        // conflict copies, which may be of another kind), its kind the
        // `Place::Path` base's when it has one (the R1 review's IR-3: two
        // tombstones at one path made the tree delete one path twice); and
        // for the twins it misses, at a path with no such base, the kind of
        // the twin. Each tombstone's `S` holds that path's bases and twins.
        let mut tomb_paths: BTreeMap<String, Kind> = BTreeMap::new();
        for ((_, place), _, m) in &beneath {
            if m.path != dir && !m.deleted && !vector.covers(&m.dot) {
                let kind = tomb_paths.entry(m.path.clone()).or_insert(m.kind);
                if *place == Place::Path {
                    *kind = m.kind;
                }
            }
        }
        for (_, _, m) in &twins {
            if m.path != dir && !m.deleted && !vector.covers(&m.dot) {
                tomb_paths.entry(m.path.clone()).or_insert(m.kind);
            }
        }
        // What it covers, held (through the index by path, 4.4 "Judging a
        // tree delete without a walk") or kept as a base, at or beneath it.
        let mut covers: BTreeSet<RecordHash> = self
            .ix
            .s
            .covered_beneath(&dir, &vector)
            .into_iter()
            .collect();
        covers.extend(
            self.ix
                .s
                .base_only
                .iter()
                .filter(|(_, b)| at_or_beneath(&b.meta.path, &dir) && vector.covers(&b.meta.dot))
                .map(|(h, _)| *h),
        );
        let clears = beneath.iter().map(|(slot, _, _)| slot.clone()).collect();
        plans.push(Plan {
            order: Order::TreeDelete,
            tag,
            put: Put {
                path: dir,
                kind: Kind::Directory,
                size: 0,
                mtime_ns,
                mode: 0,
                chunks: Vec::new(),
                plain_hashes: Vec::new(),
                deleted: true,
            },
            tree: true,
            vector,
            replaces,
            overflow,
            noted: Vec::new(),
            clears,
            covers: covers.into_iter().collect(),
        });
        for (path, kind) in tomb_paths {
            let t = self.tag(&path).ok_or(WriteError::NotWriteKey)?;
            plans.push(self.plan_put(
                Order::Tombstone,
                t,
                Put {
                    path,
                    kind,
                    size: 0,
                    mtime_ns,
                    mode: 0,
                    chunks: Vec::new(),
                    plain_hashes: Vec::new(),
                    deleted: true,
                },
                false,
                spent,
            )?);
        }
        Ok(())
    }

    /// Writes a batch of changes as one commit (4.7 item 6): plans every
    /// record's vector and names from the bases and their twins, gives them
    /// consecutive counters from one reading of `clock_us` in the order of
    /// the writer's rule, seals and signs them (`rng` draws the seals'
    /// nonces), holds them, writes the cleanups that go with them (a tree
    /// delete's, `because` it, and one for shared writer faults that did not
    /// fit a record's names), and makes each record the base of its path.
    ///
    /// # Errors
    /// [`WriteError`]. The refusals of the batch itself (no write key, the
    /// counter exhausted, a path, one path twice, a record a reader would
    /// refuse) come before anything is staged; on any error the handler drops
    /// the transaction, which undoes whatever was.
    pub fn write(
        &mut self,
        changes: &[Change],
        clock_us: u64,
        rng: &mut RandomFill<'_>,
    ) -> Result<Written, WriteError> {
        if !self.ix.writer() {
            return Err(WriteError::NotWriteKey);
        }
        let mut plans = Vec::new();
        let mut paths = BTreeSet::new();
        let mut spent = Spent {
            clock_us,
            by_peer: BTreeMap::new(),
        };
        let put_plan = |txn: &Self,
                        order: Order,
                        put: &Put,
                        s_empty: bool,
                        spent: &mut Spent|
         -> Result<Plan, WriteError> {
            check_path(&put.path).map_err(WriteError::Path)?;
            let tag = txn.tag(&put.path).ok_or(WriteError::NotWriteKey)?;
            txn.plan_put(order, tag, put.clone(), s_empty, spent)
        };
        for change in changes {
            match change {
                Change::Put(p) => {
                    let order = if p.deleted {
                        Order::Tombstone
                    } else {
                        Order::Version
                    };
                    plans.push(put_plan(self, order, p, false, &mut spent)?);
                }
                Change::Rename { from, to } => {
                    plans.push(put_plan(self, Order::Version, to, false, &mut spent)?);
                    let tomb = Put {
                        path: from.clone(),
                        kind: to.kind,
                        size: 0,
                        mtime_ns: to.mtime_ns,
                        mode: 0,
                        chunks: Vec::new(),
                        plain_hashes: Vec::new(),
                        deleted: true,
                    };
                    plans.push(put_plan(self, Order::Tombstone, &tomb, false, &mut spent)?);
                }
                Change::TreeDelete { path, mtime_ns } => {
                    check_path(path).map_err(WriteError::Path)?;
                    self.plan_tree_delete(path.clone(), *mtime_ns, &mut plans, &mut spent)?;
                }
                Change::Promote { from, copy, to } => {
                    let mut plan = put_plan(self, Order::Version, to, true, &mut spent)?;
                    let from_tag = self.tag(from).ok_or(WriteError::NotWriteKey)?;
                    plan.clears.push((from_tag, Place::Copy(copy.clone())));
                    plans.push(plan);
                }
            }
        }
        for p in &plans {
            if !paths.insert(p.put.path.clone()) {
                return Err(WriteError::DuplicatePath(p.put.path.clone()));
            }
        }
        plans.sort_by_key(|p| (p.order, p.tag));
        self.sign_and_hold(plans, clock_us, rng)
    }

    /// Gives the plans consecutive counters from one reading of `clock_us`,
    /// refusing a batch whose records and cleanups would pass `MAX_COUNTER`,
    /// and signs each, checked as a reader would before anything is staged:
    /// the records with their plans, and the counter the batch's cleanups
    /// take next.
    fn sign_plans(
        &self,
        plans: Vec<Plan>,
        clock_us: u64,
        rng: &mut RandomFill<'_>,
    ) -> Result<(Vec<(SignedRecord, Plan)>, u64), WriteError> {
        let (Some(key), Some(keys)) = (self.ix.key.write_key(), self.ix.keys.as_ref()) else {
            return Err(WriteError::NotWriteKey);
        };
        let first = self
            .ix
            .next_counter(clock_us)
            .ok_or(WriteError::CounterExhausted)?;
        // Cleanups, for the count: one page per MAX_CLEANUP_ENTRIES names.
        let per = self.ix.bounds.cleanup_entries;
        let cleanup_pages: u64 = plans
            .iter()
            .map(|p| pages(because_names(p).len(), per))
            .sum();
        let total = u64::try_from(plans.len())
            .unwrap_or(u64::MAX)
            .saturating_add(cleanup_pages);
        if total > 0 && first.saturating_add(total - 1) > MAX_COUNTER {
            return Err(WriteError::CounterExhausted);
        }
        let mut counter = first;
        let mut signed: Vec<(SignedRecord, Plan)> = Vec::with_capacity(plans.len());
        for plan in plans {
            let meta = Meta {
                path: plan.put.path.clone(),
                kind: plan.put.kind,
                size: plan.put.size,
                mtime_ns: plan.put.mtime_ns,
                mode: plan.put.mode,
                plain_hashes: plan.put.plain_hashes.clone(),
                written_at: clock_us,
                dot: Dot {
                    device: self.ix.own,
                    counter,
                },
                vector: plan.vector.clone(),
                deleted: plan.put.deleted,
                tree: plan.tree,
            };
            let draft = IndexDraft {
                meta,
                chunks: plan.put.chunks.clone(),
                replaces: plan.replaces.clone(),
            };
            let record = draft.sign(key, keys, rng).map_err(WriteError::Draft)?;
            signed.push((record, plan));
            counter += 1;
        }
        Ok((signed, counter))
    }

    /// Gives the plans their counters, signs and holds them, then the
    /// cleanups that go with them, and sets the bases.
    fn sign_and_hold(
        &mut self,
        plans: Vec<Plan>,
        clock_us: u64,
        rng: &mut RandomFill<'_>,
    ) -> Result<Written, WriteError> {
        let per = self.ix.bounds.cleanup_entries;
        let own = self.ix.own;
        let (signed, mut counter) = self.sign_plans(plans, clock_us, rng)?;
        // Every record is checked before anything is staged; now hold them.
        let mut written = Written::default();
        let mut out = Accepted::scratch();
        let mut cleanups: Vec<CleanupDraft> = Vec::new();
        for (record, plan) in &signed {
            let parsed = Record::parse(record.clone(), &self.ix.verifier)
                .map_err(|e| WriteError::Draft(DraftError::Refused(e)))?;
            let hash = parsed.hash();
            let verdict = self.ix.verdict(&parsed);
            let applied = verdict.as_ref().and_then(|v| v.as_ref().ok()).cloned();
            let replaces = self.ix.s.replaced_by(&parsed, applied.as_ref());
            let seq = self
                .store(
                    parsed.clone(),
                    verdict,
                    &replaces,
                    Seq::Own(rng),
                    clock_us,
                    &mut out,
                )
                .ok();
            written.records.push((hash, seq));
            for h in &plan.noted {
                self.named_note(h, clock_us);
            }
            // The bases: this record at its path; what it clears goes, and
            // each cleared slot's path is reported with the paths whose heads
            // changed, so that the engine names that path's disk again (a
            // tree delete whose pruned vector misses a tree delete beneath it
            // clears that one's slot and leaves it held, R3-1).
            for slot in &plan.clears {
                let at = self
                    .ix
                    .s
                    .bases
                    .get(slot)
                    .and_then(|h| self.ix.s.base_meta(h))
                    .map(|m| m.path.clone());
                out.paths.extend(at);
                self.ix
                    .s
                    .set_base(slot.clone(), None, None, Some(&mut self.undo));
            }
            if let Some(meta) = applied.as_ref().and_then(|a| a.meta()) {
                let base = BaseRecord {
                    record: parsed.clone(),
                    meta: meta.clone(),
                };
                self.ix.s.set_base(
                    (plan.tag, Place::Path),
                    Some(hash),
                    Some(base),
                    Some(&mut self.undo),
                );
            }
            cleanups.extend(cleanups_because(own, hash, plan, per));
        }
        for mut c in cleanups {
            c.dot.counter = counter;
            counter += 1;
            let record = self.sign_cleanup(&c, rng)?;
            self.hold_own(record, clock_us, rng, &mut written, &mut out)?;
            written.cleanup = true;
        }
        let meta = crate::store::StoredMeta {
            hw: self.ix.s.meta.hw.max(counter.saturating_sub(1)),
            ..self.ix.s.meta
        };
        self.ix.s.set_meta(meta, Some(&mut self.undo));
        written.dropped = out.dropped;
        written.paths = out.paths;
        written.paths.sort();
        written.paths.dedup();
        Ok(written)
    }

    /// Holds a record this device signed (a cleanup).
    fn hold_own(
        &mut self,
        record: SignedRecord,
        clock_us: u64,
        rng: &mut RandomFill<'_>,
        written: &mut Written,
        out: &mut Accepted,
    ) -> Result<(), WriteError> {
        let parsed = Record::parse(record, &self.ix.verifier)
            .map_err(|e| WriteError::Draft(DraftError::Refused(e)))?;
        let hash = parsed.hash();
        let verdict = self.ix.verdict(&parsed);
        let applied = verdict.as_ref().and_then(|v| v.as_ref().ok()).cloned();
        let replaces = self.ix.s.replaced_by(&parsed, applied.as_ref());
        let seq = self
            .store(parsed, verdict, &replaces, Seq::Own(rng), clock_us, out)
            .ok();
        written.records.push((hash, seq));
        Ok(())
    }

    /// Signs a cleanup with the folder's write key.
    fn sign_cleanup(
        &self,
        draft: &CleanupDraft,
        rng: &mut RandomFill<'_>,
    ) -> Result<SignedRecord, WriteError> {
        let (Some(key), Some(keys)) = (self.ix.key.write_key(), self.ix.keys.as_ref()) else {
            return Err(WriteError::NotWriteKey);
        };
        draft.sign(key, keys, rng).map_err(WriteError::Draft)
    }

    /// A noted record named: its note goes, and the name counts against its
    /// peer's `MAX_PEER_NAMES` window.
    fn named_note(&mut self, hash: &RecordHash, clock_us: u64) {
        if let Some(peer) = self.ix.s.notes.get(hash).map(|n| n.peer) {
            self.ix.s.remove_note(hash, Some(&mut self.undo));
            self.count_names(&peer, 1, clock_us);
        }
    }

    /// The cleanups of the end of a round with a peer (4.4, "Cleanup", cases
    /// (b) and (c)): each stale copy noted, from any peer, that no write
    /// has named yet, judged again now and named in a group `because` the
    /// held record that replaces it (a note that nothing held replaces any
    /// more is dropped, unnamed); each forgotten record noted, named with
    /// `because` empty; none that a held record names at its tag or a held
    /// cleanup names in any group; of the records one peer offered, at most
    /// `MAX_PEER_NAMES` in its current window, counted against the peer that
    /// offered each. Paged by `MAX_CLEANUP_GROUPS` and `MAX_CLEANUP_ENTRIES`.
    /// Read and sealed holders issue none. Every note is named at the first
    /// round's end, whichever peer's, so a note made from a peer that never
    /// ends a round still goes.
    ///
    /// # Errors
    /// [`WriteError::CounterExhausted`] or [`WriteError::Draft`].
    pub fn end_round(
        &mut self,
        clock_us: u64,
        rng: &mut RandomFill<'_>,
    ) -> Result<Written, WriteError> {
        if !self.ix.writer() {
            return Ok(Written::default());
        }
        let notes: Vec<(RecordHash, DeviceId, Noted)> = self
            .ix
            .s
            .notes
            .values()
            .map(|n| (n.hash, n.peer, n.noted.clone()))
            .collect();
        let mut groups: BTreeMap<Option<RecordHash>, Vec<RecordHash>> = BTreeMap::new();
        let mut spent: BTreeMap<DeviceId, u64> = BTreeMap::new();
        let mut named = Vec::new();
        for (h, from, noted) in notes {
            let already = self.ix.s.named_by_any_group(&h)
                || matches!(&noted, Noted::Stale { tag, .. } if self.ix.s.named_at(tag, &h));
            let because = match &noted {
                Noted::Stale {
                    tag,
                    path,
                    dot,
                    tree,
                } => {
                    let at = (!tree)
                        .then(|| self.ix.s.covering_at_tag(tag, dot))
                        .flatten();
                    at.or_else(|| self.ix.s.covering_tree_delete(path, dot, Some(&h)))
                        .map(Some)
                }
                Noted::Forgotten => Some(None),
            };
            match because {
                Some(b) if !already => {
                    let used = spent.get(&from).copied().unwrap_or(0);
                    if self.peer_names(&from, clock_us).saturating_add(used)
                        >= self.ix.bounds.peer_names
                    {
                        continue;
                    }
                    spent.insert(from, used + 1);
                    groups.entry(b).or_default().push(h);
                    named.push(h);
                }
                _ => self.ix.s.remove_note(&h, Some(&mut self.undo)),
            }
        }
        if named.is_empty() {
            return Ok(Written::default());
        }
        let drafts = page_groups(
            self.ix.own,
            groups,
            self.ix.bounds.cleanup_entries,
            self.ix.bounds.cleanup_groups,
        );
        let first = self
            .ix
            .next_counter(clock_us)
            .ok_or(WriteError::CounterExhausted)?;
        let n = u64::try_from(drafts.len()).unwrap_or(u64::MAX);
        if first.saturating_add(n.saturating_sub(1)) > MAX_COUNTER {
            return Err(WriteError::CounterExhausted);
        }
        let mut written = Written::default();
        let mut out = Accepted::scratch();
        let mut counter = first;
        for mut d in drafts {
            d.dot.counter = counter;
            counter += 1;
            let record = self.sign_cleanup(&d, rng)?;
            self.hold_own(record, clock_us, rng, &mut written, &mut out)?;
        }
        let meta = crate::store::StoredMeta {
            hw: self.ix.s.meta.hw.max(counter.saturating_sub(1)),
            ..self.ix.s.meta
        };
        self.ix.s.set_meta(meta, Some(&mut self.undo));
        for h in &named {
            self.ix.s.remove_note(h, Some(&mut self.undo));
        }
        for (from, n) in spent {
            self.count_names(&from, n, clock_us);
        }
        written.cleanup = true;
        written.dropped = out.dropped;
        // The paths of what its cleanups dropped, those they expired by
        // raising the folder's time included (S3-C).
        written.paths = out.paths;
        written.paths.sort();
        written.paths.dedup();
        Ok(written)
    }
}

/// The cleanups of a round's end: the groups, in `because` order, paged into
/// records of at most `max_groups` groups and `per` names each, a group
/// split where its names pass a record's.
fn page_groups(
    own: DeviceId,
    groups: BTreeMap<Option<RecordHash>, Vec<RecordHash>>,
    per: usize,
    max_groups: usize,
) -> Vec<CleanupDraft> {
    let draft = |groups| CleanupDraft {
        dot: Dot {
            device: own,
            counter: 0,
        },
        groups,
    };
    let mut drafts: Vec<CleanupDraft> = Vec::new();
    let mut current: Vec<Group> = Vec::new();
    let mut entries = 0usize;
    for (because, list) in groups {
        for chunk in list.chunks(per.max(1)) {
            if current.len() >= max_groups || entries + chunk.len() > per {
                drafts.push(draft(core::mem::take(&mut current)));
                entries = 0;
            }
            entries += chunk.len();
            current.push(Group {
                because,
                forget: chunk.to_vec(),
            });
        }
    }
    if !current.is_empty() {
        drafts.push(draft(current));
    }
    drafts
}

/// The number of cleanup records `n` names take.
fn pages(n: usize, per: usize) -> u64 {
    u64::try_from(n.div_ceil(per.max(1))).unwrap_or(u64::MAX)
}

/// What a planned record's cleanup names `because` it: what its tree delete
/// covers and the shared writer faults its names had no room for, ascending.
fn because_names(plan: &Plan) -> BTreeSet<RecordHash> {
    plan.covers.iter().chain(&plan.overflow).copied().collect()
}

/// The cleanups `because` the record `hash` of `plan`, one per
/// `MAX_CLEANUP_ENTRIES` names, their counters still to be given.
fn cleanups_because(own: DeviceId, hash: RecordHash, plan: &Plan, per: usize) -> Vec<CleanupDraft> {
    let names: Vec<RecordHash> = because_names(plan).into_iter().collect();
    page_names(&names, per)
        .into_iter()
        .map(|forget| CleanupDraft {
            dot: Dot {
                device: own,
                counter: 0,
            },
            groups: vec![Group {
                because: Some(hash),
                forget,
            }],
        })
        .collect()
}

/// `names` in pages of at most `per` (`MAX_CLEANUP_ENTRIES`), in order.
pub(crate) fn page_names(names: &[RecordHash], per: usize) -> Vec<Vec<RecordHash>> {
    names
        .chunks(per.max(1))
        .map(<[RecordHash]>::to_vec)
        .collect()
}
