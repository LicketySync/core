// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The property tests of `protocol.md` section 8 item 7, (a) to (l) ((m),
//! the digests' property, is `structures`' and `digests`'), over random
//! histories of writes (some made while a version of the path is still
//! arriving), directories made, deletes, tree deletes and renames by several
//! devices at every tier, with deliveries in any order (replays of old
//! records included), rounds of exchange with their notes and cleanups,
//! clocks that move by days and by horizons, and restored stores. Signing is
//! slow in a debug build, so histories are short and cases few; the vector
//! cap is lowered to 2 and 3, and a third of the histories are lines of
//! versions through more writers than that, so that pruning takes place; the
//! tests at the real cap are item 7's vectors. Every device of a history
//! moves its clock by the same days, so the holders (e) compares share one
//! clock; clocks apart within the clock rule are (d)'s. Files take one of
//! three contents, directories are made at `d` and `d/e`, and a third of the
//! histories start with every writer writing one path apart, so that twins
//! are common (4.4, "Bases"; the R1 review of the identical-heads fix,
//! R1-5).

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::{DeviceId, RecordHash};
use licketysync_protocol::limits::{CLEANUP_HORIZON, CLOCK_RULE_LIMIT, TOMBSTONE_HORIZON};
use licketysync_protocol::record::{Applied, Dot, Kind, Meta, Record};
use proptest::prelude::*;

use super::kit::{converge, round, take_own_held, take_unexplained, write_key, Dev, DAY, T0};
use super::open::snapshot;
use crate::{Change, Place};

const PATHS: [&str; 5] = ["a", "b", "d/x", "d/y", "d/e/z"];

/// Where a history makes directories: the tree deletes' own directory and
/// one beneath it, so that a tree delete meets twins at its own path.
const DIRS: [&str; 2] = ["d", "d/e"];

/// The contents a history writes: few, so that twins are common.
const CONTENTS: u8 = 3;

/// The writers of a history: more than the lowered vector caps of 2 and 3,
/// so that a line of versions at one path, or the bases beneath a tree
/// delete, can hold more devices than the cap and pruning takes place.
const WRITERS: usize = 5;

/// One step of a history. Device and record indexes are taken modulo what
/// exists.
#[derive(Clone, Debug)]
enum Op {
    Write {
        dev: u8,
        path: u8,
        content: u8,
    },
    /// A write made before the path is applied: the person edits the file
    /// while a version of it is still arriving (4.7 item 6).
    Edit {
        dev: u8,
        path: u8,
        content: u8,
    },
    Mkdir {
        dev: u8,
        path: u8,
    },
    Delete {
        dev: u8,
        path: u8,
    },
    TreeDelete {
        dev: u8,
    },
    Rename {
        dev: u8,
        from: u8,
        to: u8,
    },
    Apply {
        dev: u8,
    },
    Deliver {
        to: u8,
        pick: u16,
    },
    Round {
        a: u8,
        b: u8,
    },
    Days {
        n: u16,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (any::<u8>(), 0u8..5, 0..CONTENTS).prop_map(|(dev, path, content)| Op::Write { dev, path, content }),
        2 => (any::<u8>(), 0u8..5, 0..CONTENTS).prop_map(|(dev, path, content)| Op::Edit { dev, path, content }),
        1 => (any::<u8>(), 0u8..2).prop_map(|(dev, path)| Op::Mkdir { dev, path }),
        2 => (any::<u8>(), 0u8..5).prop_map(|(dev, path)| Op::Delete { dev, path }),
        1 => any::<u8>().prop_map(|dev| Op::TreeDelete { dev }),
        1 => (any::<u8>(), 0u8..5, 0u8..5).prop_map(|(dev, from, to)| Op::Rename { dev, from, to }),
        3 => any::<u8>().prop_map(|dev| Op::Apply { dev }),
        6 => (any::<u8>(), any::<u16>()).prop_map(|(to, pick)| Op::Deliver { to, pick }),
        2 => (any::<u8>(), any::<u8>()).prop_map(|(a, b)| Op::Round { a, b }),
        1 => prop_oneof![1u16..40, Just(366u16), Just(31u16)].prop_map(|n| Op::Days { n }),
    ]
}

/// A history that grows lines of versions (property (c)): each step a round
/// between the last writer and a random writer, then that writer's write at
/// one of two paths (one beneath the directory tree deletes take), now and
/// then a tree delete, a delete or a stray delivery. Each write's base has
/// passed through the writers before it, so a line soon holds more devices
/// than the lowered cap and pruning takes place.
fn line() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec((0u8..5, 0u8..8, 0..CONTENTS, any::<u16>()), 4..14).prop_map(
        |steps| {
            let mut ops = Vec::new();
            let mut prev = 0u8;
            for (dev, extra, content, pick) in steps {
                ops.push(Op::Round { a: prev, b: dev });
                let path = if extra % 4 == 3 { 2 } else { 0 };
                ops.push(Op::Write { dev, path, content });
                match extra {
                    0 => ops.push(Op::TreeDelete { dev }),
                    1 => ops.push(Op::Deliver { to: content, pick }),
                    2 => ops.push(Op::Delete { dev, path: 0 }),
                    _ => {}
                }
                prev = dev;
            }
            ops
        },
    )
}

/// A history that makes twins (the R1 review of the identical-heads fix,
/// R1-5): every writer writes one path with one of two contents, or makes
/// one directory, apart from the others; device 0 then holds every one of
/// them and a random device what a round with it brings; one of them
/// writes over the path (now and then before applying it), deletes it,
/// renames it or deletes `d`, or, over a directory, makes it again or
/// deletes `d`; then random steps of every kind. So writes and tree deletes
/// meet twins at their own path and beneath, with pruning at the lowered
/// caps.
fn twins() -> impl Strategy<Value = Vec<Op>> {
    (
        (0u8..5, 0u8..2, any::<bool>()),
        proptest::collection::vec(0u8..2, WRITERS),
        (any::<u8>(), 0u8..4, 0..CONTENTS),
        proptest::collection::vec(op(), 0..16),
    )
        .prop_map(
            |((path, dir, mkdir), contents, (dev, then, content), rest)| {
                let mut ops = Vec::new();
                for (d, c) in (0u8..).zip(contents) {
                    ops.push(if mkdir {
                        Op::Mkdir { dev: d, path: dir }
                    } else {
                        Op::Write {
                            dev: d,
                            path,
                            content: c,
                        }
                    });
                }
                for b in 1..WRITERS {
                    ops.push(Op::Round {
                        a: 0,
                        b: u8::try_from(b).unwrap_or(0),
                    });
                }
                ops.push(Op::Round {
                    a: 0,
                    b: dev % u8::try_from(WRITERS).unwrap_or(1),
                });
                ops.push(match then {
                    0..=2 if mkdir => Op::Mkdir { dev, path: dir },
                    0 if content == 0 => Op::Edit { dev, path, content },
                    0 => Op::Write { dev, path, content },
                    1 => Op::Delete { dev, path },
                    2 => Op::Rename {
                        dev,
                        from: path,
                        to: content,
                    },
                    _ => Op::TreeDelete { dev },
                });
                ops.extend(rest);
                ops
            },
        )
}

/// A history: random steps of every kind, a line of versions, or a history
/// of twins (a third each), so that every property also meets pruning and
/// twins.
fn history(max: usize) -> impl Strategy<Value = Vec<Op>> {
    prop_oneof![proptest::collection::vec(op(), 1..max), line(), twins()]
}

/// What a device has on its disk, by its index: its bases, then their twins
/// (4.4, "Bases"; stated here apart from the index's own test of it): every
/// applied record held at a base's path, not a tree delete, whose content is
/// that base's (two tombstones, two directories, or two files with the same
/// plaintext hashes), whose vector does not cover the base's dot, which is
/// not the first head at its path in display order (non-tombstones first,
/// directories before files, the greater `mtime_ns` first, then the smaller
/// record hash), the record the engine puts there, and which, for the base
/// at the path itself, comes after it in display order.
fn on_disk(d: &Dev) -> (Vec<Meta>, Vec<Meta>) {
    let s = &d.ix.s;
    let bases: Vec<(bool, RecordHash, Meta)> = s
        .bases
        .iter()
        .filter_map(|((_, place), h)| Some((*place == Place::Path, *h, s.base_meta(h)?.clone())))
        .collect();
    let base_hashes: BTreeSet<RecordHash> = s.bases.values().copied().collect();
    let same = |b: &Meta, m: &Meta| {
        !b.tree
            && !m.tree
            && b.path == m.path
            && b.deleted == m.deleted
            && (b.deleted
                || (b.kind == m.kind
                    && (b.kind == Kind::Directory
                        || b.plain_hashes
                            .iter()
                            .map(|x| x.0)
                            .eq(m.plain_hashes.iter().map(|x| x.0)))))
    };
    let rank = |h: &RecordHash, m: &Meta| {
        (
            m.deleted,
            !m.deleted && m.kind == Kind::File,
            core::cmp::Reverse(m.mtime_ns),
            *h,
        )
    };
    let mut first: BTreeMap<&str, (RecordHash, &Meta)> = BTreeMap::new();
    for (h, m) in s.held.iter().filter_map(|(h, r)| Some((*h, r.meta()?))) {
        if !m.tree {
            let f = first.entry(m.path.as_str()).or_insert((h, m));
            if rank(&h, m) < rank(&f.0, f.1) {
                *f = (h, m);
            }
        }
    }
    let twin = |(at_path, bh, b): &(bool, RecordHash, Meta), h: &RecordHash, m: &Meta| {
        same(b, m)
            && !m.vector.covers(&b.dot)
            && first.get(m.path.as_str()).is_none_or(|(f, _)| f != h)
            && (!*at_path || rank(bh, b) < rank(h, m))
    };
    let twins: Vec<Meta> = s
        .held
        .iter()
        .filter(|(h, _)| !base_hashes.contains(h))
        .filter_map(|(h, r)| Some((h, r.meta()?)))
        .filter(|(h, m)| bases.iter().any(|b| twin(b, h, m)))
        .map(|(_, m)| m.clone())
        .collect();
    (bases.into_iter().map(|(_, _, m)| m).collect(), twins)
}

/// A drop observed at a device: what was dropped, the records that may
/// have dropped it (the one accepted or the ones written), and the device's
/// folder time after the change, by which expiry is judged.
#[derive(Clone, Debug)]
struct Drop {
    dropped: RecordHash,
    by: Vec<RecordHash>,
    sealed: bool,
    folder_time: u64,
}

/// The world of a history: its devices (writers first, then a reader and a
/// sealed peer), every record any of them signed, what each record's writer
/// knew as it wrote it, and every drop seen.
struct World {
    devs: Vec<Dev>,
    writers: usize,
    archive: BTreeMap<RecordHash, licketysync_keys::records::SignedRecord>,
    order: Vec<RecordHash>,
    knows: BTreeMap<RecordHash, BTreeSet<RecordHash>>,
    seen: Vec<BTreeSet<RecordHash>>,
    drops: Vec<Drop>,
    meta: BTreeMap<RecordHash, Option<Applied>>,
    /// Property (k)'s check failed at this write.
    k_failures: Vec<String>,
    /// Property (c)'s check failed at this write.
    c_failures: Vec<String>,
    /// Drops nothing explained (the kit's check, every change).
    unexplained: Vec<String>,
    /// The records written whose vector pruning shortened.
    pruned: usize,
    /// The writes made with a twin on the disk where they wrote (R1-5: the
    /// histories meet twins).
    twinned: usize,
}

impl World {
    fn new(writers: usize, cap: usize) -> Self {
        let mut devs: Vec<Dev> = (0..writers).map(|i| Dev::writer(0x10 + i as u8)).collect();
        devs.push(Dev::reader(0x80));
        devs.push(Dev::sealed(0x90));
        for d in &mut devs {
            d.ix.bounds.vector = cap;
        }
        let n = devs.len();
        Self {
            devs,
            writers,
            archive: BTreeMap::new(),
            order: Vec::new(),
            knows: BTreeMap::new(),
            seen: vec![BTreeSet::new(); n],
            drops: Vec::new(),
            meta: BTreeMap::new(),
            k_failures: Vec::new(),
            c_failures: Vec::new(),
            unexplained: Vec::new(),
            pruned: 0,
            twinned: 0,
        }
    }

    fn opened(&mut self, h: RecordHash) {
        if self.meta.contains_key(&h) {
            return;
        }
        let keys = write_key().record_keys();
        let r = Record::parse(self.archive[&h].clone(), write_key().verifier()).unwrap();
        self.meta.insert(h, r.open(&keys).ok());
    }

    fn closure(&self, of: &BTreeSet<RecordHash>) -> BTreeSet<RecordHash> {
        let mut out = of.clone();
        for h in of {
            if let Some(k) = self.knows.get(h) {
                out.extend(k.iter().copied());
            }
        }
        out
    }

    fn note_held(&mut self, i: usize) {
        let held: Vec<RecordHash> = self.devs[i]
            .all()
            .into_iter()
            .chain(self.devs[i].ix.s.base_only.keys().copied())
            .collect();
        self.seen[i].extend(held);
    }

    fn write(&mut self, i: usize, changes: &[Change]) {
        let before_seen = self.closure(&self.seen[i]);
        let held_before: BTreeMap<RecordHash, Meta> = self.devs[i]
            .ix
            .s
            .held
            .iter()
            .filter_map(|(h, r)| Some((*h, r.meta()?.clone())))
            .collect();
        let (mut bases, twins) = on_disk(&self.devs[i]);
        let Ok(w) = self.devs[i].write(changes) else {
            return;
        };
        let at = |t: &Meta| {
            changes.iter().any(|c| match c {
                Change::Put(p) => t.path == p.path,
                Change::Rename { from, to } => t.path == *from || t.path == to.path,
                Change::TreeDelete { path, .. } => {
                    licketysync_protocol::record::at_or_beneath(&t.path, path)
                }
                Change::Promote { to, .. } => t.path == to.path,
            })
        };
        self.twinned += usize::from(twins.iter().any(at));
        bases.extend(twins);
        for (h, _) in &w.records {
            let s = self.devs[i].signed(h).clone();
            self.archive.insert(*h, s);
            self.order.push(*h);
            self.knows.insert(*h, before_seen.clone());
            self.opened(*h);
            self.check_c(h, &bases);
        }
        // Property (k), as bases.py states it (the R1 review's IR-6), its
        // content on the disk counted as on the disk (the identical-heads
        // fix of 2026-11-08): a version the write dropped was on the disk
        // there, a base at its own path or a twin of one (or, for a scan's
        // tree delete, at or beneath its directory), or one of those there
        // covered it, or one of those there is a later record of its device
        // (for a tree delete, at another path beneath its directory too:
        // "Why it is safe" 8(a), a version held but not yet on the disk
        // included, the owner's decision of 2026-11-08).
        let tree_dirs: Vec<&str> = changes
            .iter()
            .filter_map(|c| match c {
                Change::TreeDelete { path, .. } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        for u in &w.dropped {
            if let Some(m) = held_before.get(u) {
                if m.deleted {
                    continue;
                }
                let there = |b: &&Meta| {
                    b.path == m.path
                        || tree_dirs.iter().any(|d| {
                            licketysync_protocol::record::at_or_beneath(&m.path, d)
                                && licketysync_protocol::record::at_or_beneath(&b.path, d)
                        })
                };
                let ok = bases.iter().filter(there).any(|b| {
                    b.dot == m.dot
                        || b.vector.covers(&m.dot)
                        || (b.dot.device == m.dot.device && b.dot.counter >= m.dot.counter)
                });
                if !ok {
                    self.k_failures.push(format!("{u:?} at {}", m.path));
                }
            }
        }
        let by: Vec<RecordHash> = w.records.iter().map(|(h, _)| *h).collect();
        let folder_time = self.devs[i].ix.s.folder_time();
        for u in w.dropped {
            self.drops.push(Drop {
                dropped: u,
                by: by.clone(),
                sealed: false,
                folder_time,
            });
        }
        self.note_held(i);
    }

    fn accept(&mut self, i: usize, h: RecordHash) {
        let s = self.archive[&h].clone();
        let from = super::kit::dev(0xee);
        let Ok(a) = self.devs[i].accept_from(from, &s) else {
            panic!("an honest record refused");
        };
        let sealed = self.devs[i].ix.tier() == licketysync_keys::Tier::Sealed;
        let folder_time = self.devs[i].ix.s.folder_time();
        for u in a.dropped {
            self.drops.push(Drop {
                dropped: u,
                by: vec![h],
                sealed,
                folder_time,
            });
        }
        self.note_held(i);
    }

    fn apply(&mut self, op: &Op) {
        let n = self.devs.len();
        let w = self.writers;
        let pick = |x: u8, m: usize| usize::from(x) % m;
        match *op {
            Op::Write { dev, path, content } => {
                let i = pick(dev, w);
                self.devs[i].apply(PATHS[usize::from(path)]);
                let m = self.devs[i].mtime + 1_000;
                self.devs[i].mtime = m;
                self.write(
                    i,
                    &[Change::Put(super::kit::file(
                        PATHS[usize::from(path)],
                        content,
                        m,
                    ))],
                );
            }
            Op::Edit { dev, path, content } => {
                // What the engine has put on the disk stays as it was: a
                // version still arriving there is no base.
                let i = pick(dev, w);
                let m = self.devs[i].mtime + 1_000;
                self.devs[i].mtime = m;
                self.write(
                    i,
                    &[Change::Put(super::kit::file(
                        PATHS[usize::from(path)],
                        content,
                        m,
                    ))],
                );
            }
            Op::Mkdir { dev, path } => {
                let i = pick(dev, w);
                let p = DIRS[usize::from(path) % DIRS.len()];
                self.devs[i].apply(p);
                let m = self.devs[i].mtime + 1_000;
                self.devs[i].mtime = m;
                self.write(i, &[Change::Put(super::kit::dir(p, m))]);
            }
            Op::Delete { dev, path } => {
                let i = pick(dev, w);
                let p = PATHS[usize::from(path)];
                self.devs[i].apply(p);
                if self.devs[i].ix.current(p).is_some_and(|c| !c.deleted) {
                    let kind = self.devs[i].ix.current(p).unwrap().kind;
                    self.write(i, &[Change::Put(super::kit::tombstone(p, kind, 77))]);
                }
            }
            Op::TreeDelete { dev } => {
                let i = pick(dev, w);
                self.devs[i].apply_all();
                self.write(
                    i,
                    &[Change::TreeDelete {
                        path: "d".into(),
                        mtime_ns: 88,
                    }],
                );
            }
            Op::Rename { dev, from, to } => {
                let i = pick(dev, w);
                let (f, t) = (PATHS[usize::from(from)], PATHS[usize::from(to)]);
                self.devs[i].apply(f);
                self.devs[i].apply(t);
                if f != t {
                    if let Some(c) = self.devs[i].ix.current(f).filter(|c| !c.deleted) {
                        let put = crate::Put {
                            path: t.into(),
                            kind: c.kind,
                            size: c.size,
                            mtime_ns: 99,
                            mode: 0,
                            chunks: c.chunks,
                            plain_hashes: c.plain_hashes,
                            deleted: false,
                        };
                        self.write(
                            i,
                            &[Change::Rename {
                                from: f.into(),
                                to: put,
                            }],
                        );
                    }
                }
            }
            Op::Apply { dev } => {
                let i = pick(dev, n);
                if self.devs[i].ix.tier() != licketysync_keys::Tier::Sealed {
                    self.devs[i].apply_all();
                    self.note_held(i);
                }
            }
            Op::Deliver { to, pick: p } => {
                if self.order.is_empty() {
                    return;
                }
                let h = self.order[usize::from(p) % self.order.len()];
                self.accept(pick(to, n), h);
            }
            Op::Round { a, b } => {
                let (i, j) = (pick(a, n), pick(b, n));
                if i == j {
                    return;
                }
                self.exchange(i, j);
            }
            Op::Days { n: days } => {
                for d in &mut self.devs {
                    d.clock += u64::from(days) * DAY;
                }
            }
        }
    }

    /// One round of `i`'s with `j`, observing every drop and record.
    fn exchange(&mut self, i: usize, j: usize) {
        let (lo, hi) = (i.min(j), i.max(j));
        let (left, right) = self.devs.split_at_mut(hi);
        let (a, b) = if i < j {
            (&mut left[lo], &mut right[0])
        } else {
            (&mut right[0], &mut left[lo])
        };
        let before_a = a.all();
        let before_b = b.all();
        let seen_a = self.seen[i].clone();
        round(a, b);
        // Cleanups `a` issued: what its writer knew.
        for (h, s) in &a.archive {
            if !self.archive.contains_key(h) {
                self.archive.insert(*h, s.clone());
                self.order.push(*h);
                self.knows.insert(*h, seen_a.clone());
            }
        }
        let (after_a, after_b) = (a.all(), b.all());
        let (sa, sb) = (
            a.ix.tier() == licketysync_keys::Tier::Sealed,
            b.ix.tier() == licketysync_keys::Tier::Sealed,
        );
        let (ga, gb) = (a.ix.s.folder_time(), b.ix.s.folder_time());
        let offered_by_b: BTreeSet<RecordHash> = before_b.union(&after_b).copied().collect();
        let offered_by_a: BTreeSet<RecordHash> = before_a.union(&after_a).copied().collect();
        for (before, after, sealed, offered, folder_time) in [
            (before_a, after_a, sa, offered_by_b, ga),
            (before_b, after_b, sb, offered_by_a, gb),
        ] {
            for u in before.difference(&after) {
                // Dropped during the exchange: by any record that may have
                // come in, held after or not (one dropped beneath a tree
                // delete at step 8 has dropped what it names at step 6).
                let by: Vec<RecordHash> = offered.difference(&before).copied().collect();
                self.drops.push(Drop {
                    dropped: *u,
                    by,
                    sealed,
                    folder_time,
                });
            }
        }
        let new: Vec<RecordHash> = self.order.clone();
        for h in new {
            self.opened(h);
        }
        self.note_held(i);
        self.note_held(j);
    }

    /// Property (c), for a record just written from `bases` (what the writer
    /// had on its disk before the write, [`on_disk`]: its bases and their
    /// twins): its vector is the full join of those it was written from (at
    /// its path, or at and beneath a tree delete's directory), with entries
    /// taken out and none added or raised, so it covers a subset of what that
    /// join covers, and what it drops with pruning it drops without (4.4 "Why
    /// it is safe" 5 and 7).
    fn check_c(&mut self, h: &RecordHash, bases: &[Meta]) {
        let Some(m) = self.index_meta(h) else {
            return; // a cleanup: no vector
        };
        let mut full: BTreeMap<DeviceId, u64> = BTreeMap::new();
        let from = bases.iter().filter(|b| {
            if m.tree {
                b.path == m.path || b.path.starts_with(&format!("{}/", m.path))
            } else {
                b.path == m.path && !b.tree
            }
        });
        for b in from {
            for d in b.vector.entries().iter().chain(core::iter::once(&b.dot)) {
                let e = full.entry(d.device).or_insert(0);
                *e = (*e).max(d.counter);
            }
        }
        let mut failures = Vec::new();
        for e in m.vector.entries() {
            if full.get(&e.device).is_none_or(|c| *c < e.counter) {
                failures.push(format!("{h:?} at {}: {e:?} beyond the full join", m.path));
            }
        }
        let pruned = full.keys().any(|d| m.vector.get(d) == 0);
        self.c_failures.extend(failures);
        self.pruned += usize::from(pruned);
    }

    fn dot(&self, h: &RecordHash) -> Option<Dot> {
        self.meta.get(h).and_then(|m| m.as_ref().map(|a| *a.dot()))
    }

    fn index_meta(&self, h: &RecordHash) -> Option<&Meta> {
        self.meta
            .get(h)
            .and_then(|m| m.as_ref())
            .and_then(Applied::meta)
    }

    /// Property (a), for a read or write holder's drop: by a record that
    /// knows it, or that knows a later record of its device at its path or
    /// beneath the deleted directory; or by a name of a cleanup group whose
    /// `because` does; or by expiry, for a deletion or a cleanup the
    /// device's folder time after the change has passed by more than its
    /// horizon (4.4, "Expiry"; that time only grows within a change, so one
    /// dropped early in a change that ends past the horizon passes too).
    fn justified(&self, d: &Drop) -> bool {
        let u = d.dropped;
        let Some(ud) = self.dot(&u) else {
            return true; // opaque or unknown: goes only by a name
        };
        let um = self.index_meta(&u);
        let horizon = match um {
            None => Some(CLEANUP_HORIZON),
            Some(m) if m.deleted => Some(TOMBSTONE_HORIZON),
            Some(_) => None,
        };
        if horizon.is_some_and(|h| d.folder_time.saturating_sub(ud.counter) > h) {
            return true;
        }
        let Some(um) = um else {
            return self.named_by_a_group(&u, |_| true);
        };
        let knows_it = |r: &RecordHash| -> bool {
            let Some(k) = self.knows.get(r) else {
                return false;
            };
            let rm = self.index_meta(r);
            k.contains(&u)
                || k.iter().any(|x| {
                    self.index_meta(x).is_some_and(|xm| {
                        xm.dot.device == ud.device
                            && xm.dot.counter > ud.counter
                            && (xm.path == um.path
                                || rm.is_some_and(|rm| {
                                    rm.tree
                                        && licketysync_protocol::record::at_or_beneath(
                                            &xm.path, &rm.path,
                                        )
                                }))
                    })
                })
        };
        if d.by.iter().any(knows_it) {
            return true;
        }
        // By a cleanup's group: its because (any record that names u in a
        // group).
        self.named_by_a_group(&u, knows_it)
    }

    /// Whether a cleanup of the history names `u` in a group whose
    /// `because` passes `because`.
    fn named_by_a_group(&self, u: &RecordHash, because: impl Fn(&RecordHash) -> bool) -> bool {
        self.archive.values().any(|s| {
            let r = Record::parse(s.clone(), write_key().verifier()).unwrap();
            r.groups()
                .iter()
                .any(|g| g.forget.contains(u) && g.because.as_ref().is_some_and(&because))
        })
    }
}

fn run(ops: &[Op], writers: usize, cap: usize) -> World {
    let _ = take_unexplained();
    let mut w = World::new(writers, cap);
    for op in ops {
        w.apply(op);
    }
    w.unexplained = take_unexplained();
    w
}

/// Property (l): for every tree delete of the history, at every read or
/// write holder, the index by path finds exactly the held records a walk
/// over every record held at or beneath its directory finds covered.
fn check_l(w: &World) -> Result<(), String> {
    for (h, m) in w.archive.keys().filter_map(|h| Some((h, w.index_meta(h)?))) {
        if !m.tree {
            continue;
        }
        for d in w
            .devs
            .iter()
            .filter(|d| d.ix.tier() != licketysync_keys::Tier::Sealed)
        {
            let ours: BTreeSet<RecordHash> =
                d.ix.s
                    .covered_beneath(&m.path, &m.vector)
                    .into_iter()
                    .collect();
            let walk: BTreeSet<RecordHash> =
                d.ix.s
                    .held
                    .iter()
                    .filter_map(|(x, r)| Some((*x, r.meta()?)))
                    .filter(|(_, um)| {
                        licketysync_protocol::record::at_or_beneath(&um.path, &m.path)
                            && m.vector.covers(&um.dot)
                    })
                    .map(|(x, _)| x)
                    .collect();
            if ours != walk {
                return Err(format!(
                    "(l) {h:?} at {:?}: index {ours:?}, walk {walk:?}",
                    d.id()
                ));
            }
        }
    }
    Ok(())
}

/// A line of versions through five writers at one path prunes at caps of
/// 2 and 3 (each write's base carries the devices before it), and each
/// pruned vector is still within the full join (property (c)), so that the
/// gate meets pruning whatever the random cases are.
#[test]
fn a_line_through_five_writers_prunes_c() {
    let ops = [
        Op::Write {
            dev: 0,
            path: 0,
            content: 1,
        },
        Op::Round { a: 0, b: 1 },
        Op::Write {
            dev: 1,
            path: 0,
            content: 2,
        },
        Op::Round { a: 1, b: 2 },
        Op::Write {
            dev: 2,
            path: 0,
            content: 3,
        },
        Op::Round { a: 2, b: 3 },
        Op::Write {
            dev: 3,
            path: 0,
            content: 4,
        },
        Op::Round { a: 3, b: 4 },
        Op::Write {
            dev: 4,
            path: 0,
            content: 5,
        },
    ];
    for (cap, pruned) in [(2, 2), (3, 1), (32, 0)] {
        let w = run(&ops, WRITERS, cap);
        assert!(w.c_failures.is_empty(), "(c) at {cap}: {:?}", w.c_failures);
        assert_eq!(w.pruned, pruned, "the writes pruning shortened at {cap}");
    }
}

/// Two writers make one file and one directory alike, apart; after a round
/// one writes over the file and the other deletes `d`, each with a twin on
/// its disk where it writes, at the directory's own path and beneath it,
/// and (c) and (k) hold at every cap: the histories meet twins whatever the
/// random cases are (R1-5).
#[test]
fn a_history_of_twins_meets_them_c_k() {
    let ops = [
        Op::Write {
            dev: 0,
            path: 2,
            content: 1,
        },
        Op::Write {
            dev: 1,
            path: 2,
            content: 1,
        },
        Op::Mkdir { dev: 0, path: 0 },
        Op::Mkdir { dev: 1, path: 0 },
        Op::Round { a: 0, b: 1 },
        Op::Write {
            dev: 0,
            path: 2,
            content: 2,
        },
        Op::TreeDelete { dev: 1 },
    ];
    for cap in [2, 3, 32] {
        let w = run(&ops, WRITERS, cap);
        assert_eq!(w.twinned, 2, "both writes over twins at {cap}");
        assert!(w.unexplained.is_empty(), "at {cap}: {:?}", w.unexplained);
        assert!(w.k_failures.is_empty(), "(k) at {cap}: {:?}", w.k_failures);
        assert!(w.c_failures.is_empty(), "(c) at {cap}: {:?}", w.c_failures);
    }
}

/// A write made while versions of its path are still arriving, beside a
/// concurrent record of its base's content that is first among the heads
/// (the confirm review's C1): device 0's base at `a` is X (`mtime_ns`
/// 4 000); device 1, holding X on its disk, writes Y over it, other
/// content, at 2 000; device 2 writes Z apart, X's content, at 3 000, so
/// that Z comes after X in display order but first among the heads, the
/// record the engine would put at `a`. Device 0 holds Y and Z, applies
/// neither, and edits `a`: Z is not on its disk, the edit leaves it and Y
/// beside it, and (k) holds at every cap. Before, the edit covered Z as X's
/// twin, and (k) failed.
#[test]
fn a_write_beside_a_twin_first_among_the_heads_leaves_it_k() {
    let ops = [
        Op::Write {
            dev: 0,
            path: 1,
            content: 0,
        },
        Op::Write {
            dev: 0,
            path: 1,
            content: 1,
        },
        Op::Write {
            dev: 0,
            path: 0,
            content: 1,
        },
        Op::Round { a: 0, b: 1 },
        Op::Write {
            dev: 1,
            path: 0,
            content: 2,
        },
        Op::Write {
            dev: 2,
            path: 1,
            content: 2,
        },
        Op::Write {
            dev: 2,
            path: 0,
            content: 1,
        },
        Op::Round { a: 0, b: 1 },
        Op::Round { a: 0, b: 2 },
        Op::Edit {
            dev: 0,
            path: 0,
            content: 0,
        },
    ];
    for cap in [2, 3, 32] {
        let w = run(&ops, WRITERS, cap);
        assert!(w.unexplained.is_empty(), "at {cap}: {:?}", w.unexplained);
        assert!(w.k_failures.is_empty(), "(k) at {cap}: {:?}", w.k_failures);
        assert_eq!(w.devs[0].heads("a").len(), 3, "the edit, Z and Y at {cap}");
    }
}

/// The steps each history of `every_record_this_device_signs_is_held`
/// starts with, so that a round's end has a note to clean up: writer 0
/// writes three versions of `a`, each from the one before; writer 1 takes
/// the newest in a round; the oldest is offered to writer 1 again, a stale
/// copy that nothing it holds names, and noted; and writer 1's next round's
/// end names it in a cleanup.
fn a_note_to_clean_up() -> Vec<Op> {
    vec![
        Op::Write {
            dev: 0,
            path: 0,
            content: 0,
        },
        Op::Write {
            dev: 0,
            path: 0,
            content: 1,
        },
        Op::Write {
            dev: 0,
            path: 0,
            content: 2,
        },
        Op::Round { a: 1, b: 0 },
        Op::Deliver { to: 1, pick: 0 },
        Op::Round { a: 1, b: 0 },
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { max_shrink_iters: 256, ..super::proptest_config(12) })]

    /// Every record this device signs is held (the rule `Txn::sign_and_hold`
    /// and `Txn::end_round` state; the F-1 fix's security review, N1): over
    /// histories of writes of every kind, deliveries and rounds, each
    /// starting with a round's end that has a note to clean up, every record
    /// a write or a round's end returns comes back with its local sequence
    /// number, and the high-water mark is then the counter of the last of
    /// them. The kit checks each write and round's end of a device, and
    /// panics if `store` refused one of the device's own records; this test
    /// makes sure both kinds were checked.
    #[test]
    fn every_record_this_device_signs_is_held(ops in history(24), cap in prop_oneof![Just(2usize), Just(32)]) {
        let mut all = a_note_to_clean_up();
        all.extend(ops);
        let _ = take_own_held();
        run(&all, WRITERS, cap);
        let (writes, ends) = take_own_held();
        prop_assert!(writes >= 3 && ends >= 1, "checked {writes} writes and {ends} rounds' ends");
    }

    /// (a) no record is dropped except by a record that knows it or a later
    /// record of its device at its path or beneath the deleted directory;
    /// (b) no record covers a record that knows it; (f) a sealed peer drops a
    /// record only when a held record or an applying group names it; (k) no
    /// write covers a held version whose content was not on the writer's
    /// disk (a base there or a twin of one) unless one of those there covered
    /// it or is a later record of its device (for a tree delete, at or
    /// beneath its directory); (j) a reopen of the store gives the same
    /// index, on every device.
    #[test]
    fn histories_keep_claims_a_b_c_f_j_k(ops in history(28), cap in prop_oneof![Just(2usize), Just(3), Just(32)]) {
        let mut w = run(&ops, WRITERS, cap);
        // (f), and no silent loss on any tier: every drop is explained by
        // the change that made it (a name at the tag, an applying group, its
        // `because` arriving, coverage at a key holder, expiry of a deletion
        // or cleanup), the kit's check of every change.
        prop_assert!(w.unexplained.is_empty(), "(f) {:#?}", w.unexplained);
        for d in w.drops.iter().filter(|d| !d.sealed) {
            prop_assert!(w.justified(d), "(a) {d:?}");
        }
        // (l)
        if let Err(e) = check_l(&w) {
            prop_assert!(false, "{}", e);
        }
        // (b)
        for (r, k) in &w.knows {
            let Some(rm) = w.index_meta(r) else { continue };
            for u in k {
                if let Some(um) = w.index_meta(u) {
                    prop_assert!(!um.vector.covers(&rm.dot), "(b) {u:?} covers {r:?}, which knows it");
                }
            }
        }
        prop_assert!(w.k_failures.is_empty(), "(k) {:?}", w.k_failures);
        // (c)
        prop_assert!(w.c_failures.is_empty(), "(c) {:?}", w.c_failures);
        // (j), at each device's clock: per-peer state past its horizon goes
        // in memory as at open.
        for d in &mut w.devs {
            let clock = d.clock;
            let mut txn = d.ix.begin();
            txn.forget_peers(clock);
            let (ch, pending) = txn.finish();
            crate::Store::commit(&mut d.store, &ch).unwrap();
            pending.commit();
            let before = snapshot(&d.ix);
            let report = d.reopen();
            prop_assert!(report.dropped.is_empty());
            prop_assert_eq!(snapshot(&d.ix), before);
        }
    }

    /// (c) with pruning on, a record's vector is the full join it was
    /// written from with entries taken out, none added or raised, so the
    /// records dropped are a subset of those the full join drops; with (a)
    /// and (b) on the same histories, at the caps of 2 and 3.
    #[test]
    fn pruning_takes_entries_out_only_c(ops in line(), cap in prop_oneof![Just(2usize), Just(3)]) {
        let w = run(&ops, WRITERS, cap);
        prop_assert!(w.unexplained.is_empty(), "{:#?}", w.unexplained);
        if let Err(e) = check_l(&w) {
            prop_assert!(false, "{}", e);
        }
        prop_assert!(w.c_failures.is_empty(), "(c) {:?}", w.c_failures);
        for d in w.drops.iter().filter(|d| !d.sealed) {
            prop_assert!(w.justified(d), "(a) {d:?}");
        }
        for (r, k) in &w.knows {
            let Some(rm) = w.index_meta(r) else { continue };
            for u in k {
                if let Some(um) = w.index_meta(u) {
                    prop_assert!(!um.vector.covers(&rm.dot), "(b) {u:?} covers {r:?}, which knows it");
                }
            }
        }
    }

    /// (d) the live records, the expired ones, the heads and the records
    /// refused depend only on the records held: a read holder fed every
    /// record of a history in its order, and a fresh one fed what the first
    /// holds in another order, with clocks apart within the clock rule, hold
    /// exactly the same records and heads, and judge every record of the
    /// history alike afterwards, one by one, staying alike (the models' K2
    /// and K4).
    #[test]
    fn order_and_clock_do_not_matter_d(ops in history(24), seed in any::<u64>(), ahead in 0u64..200, behind in 0u64..200, cap in prop_oneof![Just(2usize), Just(3), Just(32)]) {
        let w = run(&ops, WRITERS, cap);
        let newest = w.order.iter().filter_map(|h| w.dot(h)).map(|d| d.counter).max().unwrap_or(T0);
        let mut x = Dev::reader(0xa1);
        let mut y = Dev::reader(0xa2);
        x.clock = newest + ahead * DAY;
        y.clock = newest.saturating_sub(behind * DAY).max(newest.saturating_sub(CLOCK_RULE_LIMIT));
        for h in &w.order {
            x.accept(&w.archive[h]).unwrap();
        }
        let mut held: Vec<RecordHash> = x.all().into_iter().collect();
        let mut s = seed;
        for i in (1..held.len()).rev() {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            held.swap(i, (s >> 33) as usize % (i + 1));
        }
        for h in &held {
            y.accept(&w.archive[h]).unwrap();
        }
        prop_assert_eq!(x.all(), y.all());
        for p in PATHS {
            prop_assert_eq!(x.heads(p), y.heads(p));
        }
        for h in &w.order {
            let a = x.judge(&w.archive[h]).unwrap();
            let b = y.judge(&w.archive[h]).unwrap();
            prop_assert_eq!(a, b);
            prop_assert_eq!(x.all(), y.all());
        }
    }

    /// (e) two read or write holders that end caught-up rounds with each
    /// other hold the same records and heads; (g) a sealed peer a write
    /// holder meets holds what it holds after the rounds its cleanups owe,
    /// short of stale copies a cleanup it holds names in a group that no
    /// longer applies. The devices of a history share one clock, not the
    /// spec's random clocks within the clock rule: (d) is the test of
    /// clocks apart.
    #[test]
    fn caught_up_holders_agree_e_g(ops in history(24), cap in prop_oneof![Just(2usize), Just(3)]) {
        let mut w = run(&ops, WRITERS, cap);
        let (left, right) = w.devs.split_at_mut(1);
        let a = &mut left[0];
        let b = &mut right[0];
        converge(a, b, 6);
        prop_assert_eq!(a.all(), b.all());
        for p in PATHS {
            prop_assert_eq!(a.heads(p), b.heads(p));
        }
        let sealed = w.devs.len() - 1;
        let (left, right) = w.devs.split_at_mut(sealed);
        let wh = &mut left[0];
        let s = &mut right[0];
        for _ in 0..4 {
            let x = round(wh, s);
            round(s, wh);
            if x.caught_up && !x.cleanup {
                break;
            }
        }
        let extra: Vec<RecordHash> = s.all().difference(&wh.all()).copied().collect();
        for u in extra {
            let named_by_dead_group = wh.ix.s.held.values().any(|c| {
                c.record.groups().iter().any(|g| g.forget.contains(&u) && g.because.as_ref().is_some_and(|b| !wh.holds(b)))
            });
            prop_assert!(named_by_dead_group, "(g) {u:?} only at the sealed peer");
        }
        prop_assert!(wh.all().is_subset(&s.all()));
    }

    /// (h) a cleanup replayed at any later point removes no record written
    /// after it.
    #[test]
    fn a_replayed_cleanup_removes_nothing_newer_h(ops in history(24), cap in prop_oneof![Just(2usize), Just(32)]) {
        let mut w = run(&ops, WRITERS, cap);
        let cleanups: Vec<RecordHash> = w
            .order
            .iter()
            .copied()
            .filter(|h| w.index_meta(h).is_none() && w.dot(h).is_some())
            .collect();
        for c in cleanups {
            let cd = w.dot(&c).unwrap();
            for i in 0..w.devs.len() {
                let s = w.archive[&c].clone();
                if let Ok(a) = w.devs[i].accept(&s) {
                    for u in a.dropped {
                        let ud = w.dot(&u);
                        prop_assert!(ud.is_none_or(|d| d.counter < cd.counter), "(h) {u:?} after {c:?}");
                    }
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(super::proptest_config(12))]

    /// (i) two records with one dot are both held on every tier, and two
    /// devices that hold one each find the difference and end holding both
    /// (a restored store writing again under its old counter).
    #[test]
    fn two_records_with_one_dot_i(content in any::<u8>(), path in 0usize..5) {
        let p = PATHS[path];
        let mut d = Dev::writer(0x20);
        d.put("seed", 1);
        let backup = d.store.clone();
        let one = d.put(p, content);
        d.store = backup;
        d.reopen();
        let other = d.put(p, content.wrapping_add(1));
        let dot = |dev: &Dev, h: &RecordHash| dev.ix.record(h).unwrap().dot.unwrap();
        let mut a = Dev::writer(0x30);
        a.accept(d.signed(&one)).unwrap();
        prop_assert_eq!(dot(&a, &one), dot(&d, &other), "one dot");
        for tier in [licketysync_keys::Tier::Write, licketysync_keys::Tier::Read, licketysync_keys::Tier::Sealed] {
            let mut x = Dev::new(tier, 0x40);
            let mut y = Dev::new(tier, 0x41);
            x.accept(d.signed(&one)).unwrap();
            y.accept(d.signed(&other)).unwrap();
            prop_assert_ne!(x.root(), y.root());
            round(&mut x, &mut y);
            round(&mut y, &mut x);
            prop_assert!(x.holds(&one) && x.holds(&other));
            prop_assert_eq!(x.all(), y.all());
        }
    }

    /// (j) after the ordered crash between a change's records and its
    /// removals, the next open gives the index the change would have made,
    /// its bases included. The device is reopened first, so that it and the
    /// copy it is compared with hold the same notes (none: notes live in
    /// memory only), as the review's IR-4 found.
    #[test]
    fn a_reopen_after_the_crash_is_the_change_j(ops in proptest::collection::vec(op(), 1..12), content in any::<u8>()) {
        let mut w = run(&ops, 2, 32);
        let d = &mut w.devs[0];
        d.reopen();
        d.apply("a");
        let want = {
            let mut copy = Dev::writer(0x10);
            copy.store = d.store.clone();
            copy.clock = d.clock;
            copy.rng = d.rng.clone();
            copy.reopen();
            copy.apply("a");
            copy.write(&[Change::Put(super::kit::file("a", content, 5))]).unwrap();
            copy
        };
        d.store.mode = crate::Commit::CrashBeforeRemovals;
        {
            let Dev { ix, store, rng, clock, .. } = &mut *d;
            let mut txn = ix.begin();
            let _ = txn.write(&[Change::Put(super::kit::file("a", content, 5))], *clock, &mut |b| rng.fill(b));
            let (changes, pending) = txn.finish();
            let _ = crate::Store::commit(store, &changes);
            drop(pending);
        }
        d.reopen();
        let mut fp = Vec::new();
        d.ix.fingerprint(&mut |b| fp.extend_from_slice(b));
        let mut fw = Vec::new();
        want.ix.fingerprint(&mut |b| fw.extend_from_slice(b));
        prop_assert_eq!(fp, fw);
        prop_assert_eq!(d.ix.bases("a"), want.ix.bases("a"), "the write is the base of its path");
    }
}

/// `v` shuffled by a seeded generator.
fn shuffled(mut v: Vec<RecordHash>, seed: u64) -> Vec<RecordHash> {
    let mut s = seed | 1;
    for i in (1..v.len()).rev() {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        v.swap(i, (s >> 33) as usize % (i + 1));
    }
    v
}

/// K2 (and so K1) of the models: a fresh holder of the device's kind (a
/// reader for a writer) fed the device's records in a shuffled order holds
/// exactly them, with the same heads.
fn k2(d: &Dev, seed: u64) -> Result<(), String> {
    use licketysync_keys::Tier;
    let tier = match d.ix.tier() {
        Tier::Write => Tier::Read,
        t => t,
    };
    let mut f = Dev::new(tier, 0xb7);
    f.clock = d.clock;
    f.ix.bounds = d.ix.bounds;
    for h in shuffled(d.all().into_iter().collect(), seed) {
        f.accept(d.signed(&h))
            .map_err(|e| format!("K2 refused {e:?}"))?;
    }
    if f.all() != d.all() {
        return Err(format!(
            "K2 at {:?} {:?}: fresh and device differ",
            d.ix.tier(),
            d.id()
        ));
    }
    if tier != Tier::Sealed {
        for p in PATHS {
            if f.heads(p) != d.heads(p) {
                return Err(format!("K2 heads at {p}"));
            }
        }
    }
    Ok(())
}

/// What the store holds, opened again, is what memory holds (per-peer state
/// aside, which an open ages).
fn store_matches(d: &Dev) -> Result<(), String> {
    let strip = |ix: &crate::Index| -> String {
        let mut fp = Vec::new();
        ix.fingerprint(&mut |b| fp.extend_from_slice(b));
        let mut out = format!("{fp:?}");
        for r in ix.records() {
            out.push_str(&format!("\n{r:?}"));
        }
        out.push_str(&format!(
            "\n{:?}\n{:?}\n{:?}",
            ix.s.meta,
            ix.s.bases,
            ix.s.base_only.keys().collect::<Vec<_>>()
        ));
        out
    };
    let stored = crate::Store::load(&d.store).unwrap();
    let mut rng = d.rng.clone();
    let (ix, report) = crate::Index::open(
        super::kit::folder_key(d.ix.tier()),
        d.id(),
        stored,
        d.clock,
        &mut |b| rng.fill(b),
    );
    if !report.dropped.is_empty() || report.hw_corrupt || report.epoch_redrawn {
        return Err(format!("the store differs: {report:?}"));
    }
    if strip(&d.ix) != strip(&ix) {
        return Err("the store differs from memory".into());
    }
    Ok(())
}

/// Runs `f` in a transaction that is dropped, and checks that the whole
/// state (every derived table, the trie, the index by path, the notes) is
/// exactly as before.
fn dry(
    d: &mut Dev,
    what: &str,
    f: impl FnOnce(&mut crate::Txn<'_>, &mut super::kit::Rng, u64),
) -> Result<(), String> {
    let before = format!("{:#?}", d.ix.s);
    let mut rng = d.rng.clone();
    let clock = d.clock;
    {
        let mut txn = d.ix.begin();
        f(&mut txn, &mut rng, clock);
    }
    if format!("{:#?}", d.ix.s) == before {
        Ok(())
    } else {
        Err(format!("the rollback of {what} is not exact"))
    }
}

impl World {
    /// Before `op` is done, what it would do is done in a transaction that
    /// is dropped: the state must come back exactly.
    fn dry_run(&mut self, op: &Op) -> Result<(), String> {
        let n = self.devs.len();
        let wr = self.writers;
        let pick = |x: u8, m: usize| usize::from(x) % m;
        match *op {
            Op::Deliver { to, pick: p } if !self.order.is_empty() => {
                let h = self.order[usize::from(p) % self.order.len()];
                let s = self.archive[&h].clone();
                let d = &mut self.devs[pick(to, n)];
                let record = Record::parse(s, d.ix.key().verifier()).unwrap();
                let mut memory = d.memory.clone();
                // A budget of the dry run's own: the device's stays unspent.
                let mut notes = licketysync_protocol::connection::NoteBudget::for_tests();
                dry(d, "an accept", |txn, rng, clock| {
                    let mut fill = |b: &mut [u8]| rng.fill(b);
                    let mut arrival = crate::Arrival {
                        peer: super::kit::dev(0xee),
                        memory: &mut memory,
                        notes: &mut notes,
                        clock_us: clock,
                        rng: &mut fill,
                    };
                    let _ = txn.accept(record, &mut arrival);
                })
            }
            Op::Write { dev, path, content } => {
                let d = &mut self.devs[pick(dev, wr)];
                let m = d.mtime + 1_000;
                let change = Change::Put(super::kit::file(PATHS[usize::from(path)], content, m));
                dry(d, "a write", |txn, rng, clock| {
                    let _ = txn.write(&[change], clock, &mut |b| rng.fill(b));
                })
            }
            Op::TreeDelete { dev } => {
                let d = &mut self.devs[pick(dev, wr)];
                dry(d, "a tree delete", |txn, rng, clock| {
                    let _ = txn.write(
                        &[Change::TreeDelete {
                            path: "d".into(),
                            mtime_ns: 88,
                        }],
                        clock,
                        &mut |b| rng.fill(b),
                    );
                })
            }
            Op::Round { a, .. } => {
                let d = &mut self.devs[pick(a, n)];
                dry(d, "a round's end", |txn, rng, clock| {
                    let _ = txn.end_round(clock, &mut |b| rng.fill(b));
                    txn.round_ended(super::kit::dev(0x55), true, Some((7, 3)), clock);
                    txn.cursor_advanced(super::kit::dev(0x55), 7, 9);
                })
            }
            _ => Ok(()),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { max_shrink_iters: 256, ..super::proptest_config(12) })]

    /// The models' checks, as strictly as the R1 review's probes put them
    /// (IR-6): every step's change, dropped, gives the state back exactly;
    /// no change drops a record nothing explains; at the end K2 holds on
    /// every device, every store opens to what memory holds, and two key
    /// holders whose rounds with each other both end caught up hold the same
    /// records (K3 strictly).
    #[test]
    fn every_step_rolls_back_exactly_and_holders_agree_k1_k2_k3(ops in history(24), cap in prop_oneof![Just(2usize), Just(3), Just(32)]) {
        let _ = take_unexplained();
        let mut w = World::new(WRITERS, cap);
        let mut fails = Vec::new();
        for op in &ops {
            if let Err(e) = w.dry_run(op) {
                fails.push(format!("{op:?}: {e}"));
            }
            w.apply(op);
        }
        fails.extend(take_unexplained());
        for (i, d) in w.devs.iter().enumerate() {
            if let Err(e) = k2(d, i as u64 + 7) {
                fails.push(e);
            }
            if let Err(e) = store_matches(d) {
                fails.push(format!("device {i}: {e}"));
            }
        }
        let holders: Vec<usize> = (0..w.devs.len())
            .filter(|i| w.devs[*i].ix.tier() != licketysync_keys::Tier::Sealed)
            .collect();
        for &i in &holders {
            for &j in holders.iter().filter(|j| **j > i) {
                let (left, right) = w.devs.split_at_mut(j);
                let (a, b) = (&mut left[i], &mut right[0]);
                let x = round(a, b);
                let y = round(b, a);
                if x.caught_up && y.caught_up && a.all() != b.all() {
                    fails.push(format!("K3: {i} and {j} both caught up, holding different records"));
                }
            }
        }
        fails.extend(take_unexplained());
        prop_assert!(fails.is_empty(), "{:#?}", fails);
    }

    /// Pruning at the real cap: the mandatory devices' entries kept, then the
    /// greatest counters, the smaller device ID first; counters unchanged
    /// (the R1 review's `probe_prune`).
    #[test]
    fn pruning_keeps_the_mandatory_then_the_greatest(
        entries in proptest::collection::btree_map(any::<u8>(), 1u64..50, 0..64),
        mand in proptest::collection::btree_set(any::<u8>(), 0..32),
    ) {
        use licketysync_keys::DeviceId;
        let joined: BTreeMap<DeviceId, u64> = entries.iter().map(|(d, c)| (DeviceId([*d; 32]), *c)).collect();
        let mandatory: BTreeSet<DeviceId> = mand.iter().map(|d| DeviceId([*d; 32])).collect();
        let v = crate::write::prune(&joined, &mandatory, 32).unwrap();
        let present = mandatory.iter().filter(|d| joined.contains_key(d)).count();
        prop_assert_eq!(v.len(), joined.len().min(32.max(present)));
        for d in mandatory.iter().filter(|d| joined.contains_key(d)) {
            prop_assert_eq!(v.get(d), joined[d], "mandatory kept");
        }
        for e in v.entries() {
            prop_assert_eq!(Some(&e.counter), joined.get(&e.device));
        }
        let kept: BTreeSet<DeviceId> = v.entries().iter().map(|e| e.device).collect();
        for (d, c) in &joined {
            if kept.contains(d) || mandatory.contains(d) {
                continue;
            }
            for e in v.entries().iter().filter(|e| !mandatory.contains(&e.device)) {
                prop_assert!((e.counter, core::cmp::Reverse(e.device)) > (*c, core::cmp::Reverse(*d)), "a dropped entry outranks a kept one");
            }
        }
    }
}
