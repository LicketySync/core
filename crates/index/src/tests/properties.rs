// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Properties over arrival orders (`protocol.md` 4.4: "every peer that holds
//! the same records applies the same ones and computes the same heads, in
//! any arrival order"): the same set of held records gives the same cursors,
//! digests, waiting records and heads whatever the order, after a restart,
//! and as a naive reference computes them from the set alone; histories with
//! no concurrent edit, whose records the index's own drafts make, never show
//! a conflict on the way, renames and paths written again after a rename
//! included; and two indexes that exchange end with the same records and
//! heads.
//!
//! Records are signed for real, which a debug build makes slow, so the cases
//! are few and small; each covers concurrent versions, out-of-order
//! `supersedes`, renames, tombstones, opaque records and records that wait
//! for good.

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::{DeviceId, FolderKey, RecordHash};
use licketysync_protocol::record::{writer_digests, Arrival, Judgement, Kind, Record};
use proptest::prelude::*;

use super::kit::{
    converge, dev, display_order, index_as, key, push, snapshot, write_key, Fault, Snapshot, Spec,
    OWN,
};
use crate::{Index, Kept, MemoryStore};

/// One generated record: indices are reduced modulo what exists when it is
/// built, so every generated list is valid.
#[derive(Clone, Debug)]
struct Gen {
    writer: u8,
    /// Reuse a `seq` at or below the writer's top (a concurrent version).
    concurrent: Option<u8>,
    path: u8,
    shape: u8,
    mtime: i8,
    content: u8,
    names: Vec<u8>,
    phantom: bool,
}

fn gen() -> impl Strategy<Value = Gen> {
    (
        0..3u8,
        prop::option::weighted(0.2, any::<u8>()),
        0..3u8,
        0..10u8,
        -2..3i8,
        1..3u8,
        prop::collection::vec(any::<u8>(), 0..3),
        prop::bool::weighted(0.08),
    )
        .prop_map(
            |(writer, concurrent, path, shape, mtime, content, names, phantom)| Gen {
                writer,
                concurrent,
                path,
                shape,
                mtime,
                content,
                names,
                phantom,
            },
        )
}

/// Signs the generated records in order, so that `supersedes` only names
/// records built before (or a hash no one holds).
fn build(gens: &[Gen]) -> Vec<Record> {
    let mut top: BTreeMap<u8, u64> = BTreeMap::new();
    let mut out: Vec<Record> = Vec::new();
    for (i, g) in gens.iter().enumerate() {
        let t = top.entry(g.writer).or_insert(0);
        let seq = match g.concurrent {
            Some(k) if *t > 0 => 1 + u64::from(k) % *t,
            _ => {
                *t += 1;
                *t
            }
        };
        let writer = dev(g.writer + 1);
        let path = ["a", "b", "c/d"][usize::from(g.path)];
        let base = match g.shape {
            0 => Spec::tombstone(writer, seq, path),
            1 => Spec::dir(writer, seq, path),
            2 => Spec::file(writer, seq, path).fault(Fault::Seal),
            _ => Spec::file(writer, seq, path).content(g.content),
        };
        let mut names: Vec<RecordHash> = g
            .names
            .iter()
            .filter(|_| !out.is_empty())
            .map(|n| out[usize::from(*n) % out.len()].hash())
            .collect();
        if g.phantom {
            names.push(RecordHash([0xee; 32]));
        }
        let spec = base
            .names(&names)
            .mtime(i64::from(g.mtime))
            .salt(u8::try_from(i).unwrap());
        out.push(spec.record());
    }
    out
}

/// Delivers `records` in the order `order` gives, as pushes; a record that
/// is a gap is ignored, as the protocol does, and comes again later, as the
/// exchange brings it, until a pass stores nothing more (a subset may leave
/// some records gaps for good). `again` re-delivers an already held record
/// after a delivery (a duplicate). Returns the index and checks `each` after
/// every step.
fn deliver(
    records: &[Record],
    order: &[usize],
    again: &[bool],
    mut each: impl FnMut(&Index<MemoryStore>),
) -> Index<MemoryStore> {
    let mut ix = index_as(OWN);
    let mut queue: Vec<usize> = order.to_vec();
    let mut delivered: Vec<usize> = Vec::new();
    let mut step = 0;
    while !queue.is_empty() {
        let before = queue.len();
        let mut later = Vec::new();
        for i in queue {
            let o = ix.accept(records[i].clone(), Arrival::Push).unwrap();
            match o.judgement {
                Judgement::PushGap => later.push(i),
                Judgement::Duplicate => {}
                Judgement::Next | Judgement::Concurrent => delivered.push(i),
            }
            if again.get(step).copied().unwrap_or(false) && !delivered.is_empty() {
                let d = delivered[step % delivered.len()];
                let o = ix.accept(records[d].clone(), Arrival::Push).unwrap();
                assert_eq!(o.judgement, Judgement::Duplicate);
            }
            step += 1;
            each(&ix);
        }
        if later.len() == before {
            break;
        }
        queue = later;
    }
    ix
}

/// What the spec's definitions give for a set of held records, computed
/// directly: a record is resolved when it is held and either opaque or
/// applied with every record it names resolved; the heads of a path are its
/// applied, resolved records that no applied, resolved record names; and its
/// last known versions beside the heads are those that some such record
/// names but none at the path itself.
fn reference(records: &[Record]) -> Snapshot {
    let data_key = key().data_key();
    let held: BTreeMap<RecordHash, &Record> = records.iter().map(|r| (r.hash(), r)).collect();
    let opened: BTreeMap<RecordHash, Option<String>> = held
        .iter()
        .map(|(h, r)| (*h, r.open(data_key).ok().map(|m| m.path)))
        .collect();
    // The records form a DAG in build order, so one pass in that order
    // resolves each after everything it names.
    let mut resolved: BTreeSet<RecordHash> = BTreeSet::new();
    for r in records {
        let ok = match opened[&r.hash()] {
            None => true,
            Some(_) => r.supersedes().iter().all(|n| resolved.contains(n)),
        };
        if ok {
            resolved.insert(r.hash());
        }
    }
    let active: Vec<&Record> = records
        .iter()
        .filter(|r| opened[&r.hash()].is_some() && resolved.contains(&r.hash()))
        .collect();
    let opened_ref = &opened;
    let path_of = |h: &RecordHash| opened_ref[h].clone().unwrap();
    let superseded: BTreeSet<RecordHash> = active
        .iter()
        .flat_map(|r| r.supersedes().iter().copied())
        .collect();
    let replaced_at_own_path: BTreeSet<RecordHash> = active
        .iter()
        .flat_map(|r| {
            let path = path_of(&r.hash());
            r.supersedes()
                .iter()
                .filter(move |n| {
                    opened_ref
                        .get(*n)
                        .is_some_and(|p| p.as_ref() == Some(&path))
                })
                .copied()
        })
        .collect();
    let mut heads: BTreeMap<String, BTreeSet<RecordHash>> = BTreeMap::new();
    let mut renamed_away: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in &active {
        let path = path_of(&r.hash());
        if !superseded.contains(&r.hash()) {
            heads.entry(path).or_default().insert(r.hash());
        } else if !replaced_at_own_path.contains(&r.hash()) {
            renamed_away.entry(path).or_default().push(r);
        }
    }
    // In display order, which for these versions (none a head) the reference
    // takes from their metadata directly.
    let data_key = key().data_key();
    let renamed_away: Vec<(String, Vec<RecordHash>)> = renamed_away
        .into_iter()
        .map(|(path, mut rs)| {
            rs.sort_by_key(|r| {
                let m = r.open(data_key).unwrap();
                (
                    r.deleted(),
                    !r.deleted() && m.kind == Kind::File,
                    core::cmp::Reverse(m.mtime_ns),
                    r.hash(),
                )
            });
            (path, rs.iter().map(|r| r.hash()).collect())
        })
        .collect();
    let mut by_writer: BTreeMap<DeviceId, Vec<&Record>> = BTreeMap::new();
    for r in held.values() {
        by_writer.entry(r.device_id()).or_default().push(r);
    }
    let writers = by_writer
        .into_iter()
        .map(|(w, rs)| {
            let digests = writer_digests(rs.iter().map(|r| (r.seq(), r.hash())));
            let mut order: Vec<(u64, RecordHash)> =
                rs.iter().map(|r| (r.seq(), r.hash())).collect();
            order.sort();
            let cursor = *digests.keys().next_back().unwrap();
            (
                w,
                cursor,
                digests.values().copied().collect(),
                order.into_iter().map(|(_, h)| h).collect(),
            )
        })
        .collect();
    Snapshot {
        held: held.keys().copied().collect(),
        writers,
        waiting: held
            .keys()
            .filter(|h| opened[h].is_some() && !resolved.contains(h))
            .copied()
            .collect(),
        // Heads compare as sets here; their display order is checked apart.
        heads: heads
            .into_iter()
            .map(|(p, hs)| (p, hs.into_iter().collect()))
            .collect(),
        renamed_away,
        opaque: held
            .keys()
            .filter(|h| opened[h].is_none())
            .copied()
            .collect(),
    }
}

/// The snapshot with each path's heads sorted by hash, to compare with the
/// reference; and a check that the index's own order is the display order.
fn as_sets(index: &Index<MemoryStore>) -> Snapshot {
    for path in index.paths() {
        let heads = index.heads(path);
        assert!(!heads.is_empty(), "a listed path has a head");
        let versions: Vec<_> = heads.versions().collect();
        assert!(versions
            .windows(2)
            .all(|w| display_order(&w[0], &w[1]).is_lt()));
        assert!(heads.versions().all(|v| !index.is_waiting(&v.hash())));
        assert!(heads
            .versions()
            .all(|v| matches!(index.kept(&v.hash()), Some(Kept::Applied(m)) if m.path == path)));
    }
    let mut s = snapshot(index);
    for (_, hs) in &mut s.heads {
        hs.sort();
    }
    s
}

/// Two arrival orders and where duplicates come (or how a set is split).
type Orders = (Vec<usize>, Vec<usize>, Vec<bool>);

fn orders(n: usize) -> impl Strategy<Value = Orders> {
    let indices: Vec<usize> = (0..n).collect();
    (
        Just(indices.clone()).prop_shuffle(),
        Just(indices).prop_shuffle(),
        prop::collection::vec(prop::bool::weighted(0.2), n * 2),
    )
}

fn case() -> impl Strategy<Value = (Vec<Gen>, Orders)> {
    prop::collection::vec(gen(), 1..10).prop_flat_map(|gens| {
        let n = gens.len();
        (Just(gens), orders(n))
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Arrival order never changes cursors, digests, waiting records or
    /// heads; neither does a restart; and all equal the reference.
    #[test]
    fn arrival_order_never_changes_heads_or_digests((gens, (first, second, again)) in case()) {
        let records = build(&gens);
        let one = deliver(&records, &first, &again, |_| {});
        let two = deliver(&records, &second, &[], |_| {});
        let s1 = snapshot(&one);
        prop_assert_eq!(&s1, &snapshot(&two));
        prop_assert_eq!(as_sets(&one), reference(&records));
        prop_assert_eq!(s1.held.len(), records.len());
        let reopened = Index::open(FolderKey::from(write_key()), OWN, one.into_store()).unwrap();
        prop_assert_eq!(&snapshot(&reopened), &s1);
    }

    /// Two indexes that each hold part of a set of records, and exchange
    /// through rounds of range and listed requests, end with the same
    /// records, digests and heads: those of an index that holds them all.
    #[test]
    fn indexes_that_exchange_converge((gens, (order, _, split)) in case()) {
        let records = build(&gens);
        let (to_a, to_b): (Vec<usize>, Vec<usize>) = order
            .iter()
            .copied()
            .partition(|i| split.get(*i).copied().unwrap_or(false));
        let mut a = deliver(&records, &to_a, &[], |_| {});
        let mut b = deliver(&records, &to_b, &[], |_| {});
        // What the two hold between them (a record either side refused as a
        // gap reaches neither).
        let union: BTreeSet<RecordHash> = snapshot(&a).held.union(&snapshot(&b).held).copied().collect();
        converge(&mut a, &mut b);
        let both: Vec<usize> = order
            .iter()
            .copied()
            .filter(|i| union.contains(&records[*i].hash()))
            .collect();
        let expected = deliver(&records, &both, &[], |_| {});
        prop_assert_eq!(snapshot(&a), snapshot(&b));
        prop_assert_eq!(&snapshot(&a).held, &union);
        prop_assert_eq!(snapshot(&a), snapshot(&expected));
    }
}

/// One step of a history without concurrent edits.
#[derive(Clone, Debug)]
enum Op {
    Edit(u8),
    Delete(u8),
    Rename(u8, u8),
}

fn op() -> impl Strategy<Value = (u8, Op)> {
    (
        0..3u8,
        prop_oneof![
            4 => (0..3u8).prop_map(Op::Edit),
            1 => (0..3u8).prop_map(Op::Delete),
            2 => (0..3u8, 0..3u8).prop_map(|(a, b)| Op::Rename(a, b)),
        ],
    )
}

/// Builds a history without concurrent edits: each write is drafted by an
/// index that holds every record before it, so it names the last known
/// versions of the paths it writes (`protocol.md` 4.4), and a path a rename
/// vacated may be written again; the draft is then signed under its writer's
/// device ID and next `seq`. No conflict should ever show. Returns the
/// records and each path's final head, as the operations alone give it.
fn linear(ops: &[(u8, Op)]) -> (Vec<Record>, BTreeMap<String, RecordHash>) {
    let paths = ["a", "b", "c"];
    let mut author = index_as(dev(0xaa));
    let mut seq: BTreeMap<u8, u64> = BTreeMap::new();
    let mut head: BTreeMap<String, RecordHash> = BTreeMap::new();
    let mut out = Vec::new();
    for (i, (writer, op)) in ops.iter().enumerate() {
        let (to, from) = match op {
            Op::Edit(p) | Op::Delete(p) => (paths[usize::from(*p)], None),
            Op::Rename(f, t) => (paths[usize::from(*t)], Some(paths[usize::from(*f)])),
        };
        let salt = u8::try_from(i).unwrap();
        // Only the metadata and chunks are read from the Spec.
        let spec = match op {
            Op::Edit(_) => Spec::file(OWN, 1, to).content(salt % 3 + 1),
            Op::Delete(_) => Spec::tombstone(OWN, 1, to),
            Op::Rename(..) => Spec::file(OWN, 1, to),
        };
        let mut draft = match from {
            Some(f) => author.draft_rename(f, spec.meta(), spec.chunks()),
            None => author.draft(spec.meta(), spec.chunks(), spec.deleted),
        }
        .unwrap();
        let s = seq.entry(*writer).or_insert(0);
        *s += 1;
        draft.device_id = dev(writer + 1);
        draft.seq = *s;
        let signed = draft.sign(key(), &mut |b: &mut [u8]| b.fill(salt)).unwrap();
        let r = Record::parse(signed, key().verifier()).unwrap();
        push(&mut author, &r);
        if let Some(f) = from {
            head.remove(f);
        }
        head.insert(to.to_string(), r.hash());
        out.push(r);
    }
    (out, head)
}

fn linear_case() -> impl Strategy<Value = (Vec<(u8, Op)>, Vec<usize>)> {
    prop::collection::vec(op(), 1..10).prop_flat_map(|ops| {
        let n = ops.len();
        (Just(ops), Just((0..n).collect::<Vec<_>>()).prop_shuffle())
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Out-of-order chains never make a false conflict: at every step of
    /// every arrival order, no path of a history without concurrent edits
    /// has two heads, a path renamed away and written again included, and at
    /// the end each path's head is the history's.
    #[test]
    fn out_of_order_chains_never_make_a_false_conflict((ops, order) in linear_case()) {
        let (records, last) = linear(&ops);
        let ix = deliver(&records, &order, &[], |ix| {
            for path in ix.paths() {
                assert!(ix.heads(path).len() <= 1, "a false conflict at {path}");
            }
        });
        let end: BTreeMap<String, RecordHash> = ix
            .paths()
            .map(|p| (p.to_string(), ix.heads(p).first().unwrap().hash()))
            .collect();
        prop_assert_eq!(end, last);
        prop_assert_eq!(ix.waiting().count(), 0);
        prop_assert!(ix.paths().all(|p| ix.heads(p).first().unwrap().meta().kind == Kind::File));
    }
}
