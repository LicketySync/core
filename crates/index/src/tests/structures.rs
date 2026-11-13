// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index's derived structures against definitions computed from nothing
//! but the spec: the index of held records by device and path that judges a
//! tree delete without a walk (`protocol.md` 4.4, property (l)), and the trie
//! of held tree deletes whose lookup costs `O(L)` for a path of `L` bytes
//! (4.4 step 3).

use std::collections::BTreeSet;

use licketysync_keys::{DeviceId, RecordHash};
use licketysync_protocol::limits::MAX_PATH_BYTES;
use proptest::prelude::*;

use crate::bypath::ByPath;
use crate::dirs::Dirs;

/// Paths over a small alphabet that crowds the edges of the two runs at or
/// beneath a directory: `d`, `d/x`, `d-x`, `d.x`, `d0`, `d/x/y`, `dd`.
const PATHS: [&str; 10] = [
    "d", "d/x", "d-x", "d.x", "d0", "d/x/y", "d/y", "dd", "e", "d/x-y",
];

fn dirs() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("d".to_string()),
        Just("d/x".to_string()),
        Just("e".to_string()),
        Just("d-x".to_string()),
        Just("dd".to_string()),
    ]
}

/// At or beneath `dir`, by the definition: `dir` itself, or a path that
/// begins with `dir/`.
fn beneath(path: &str, dir: &str) -> bool {
    path == dir || path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

fn dev(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

proptest! {
    #![proptest_config(super::proptest_config(64))]

    /// (l) the index by path finds the same held records covered as a walk
    /// over every record held at or beneath the directory, after any
    /// sequence of records held and dropped, with at most two queries per
    /// vector entry; and its trees stay balanced.
    #[test]
    fn the_index_by_path_agrees_with_a_walk_l(
        ops in proptest::collection::vec((any::<bool>(), 0u8..3, 0usize..PATHS.len(), any::<u8>(), 1u64..40), 1..200),
        probes in proptest::collection::vec((0u8..3, dirs(), 0u64..45), 1..20),
    ) {
        let mut ix = ByPath::default();
        let mut held: BTreeSet<(DeviceId, String, RecordHash, u64)> = BTreeSet::new();
        for (add, d, pi, h, c) in ops {
            // A record is at one path: its hash names the path too.
            let p = PATHS[pi].to_string();
            let mut hb = [h; 32];
            hb[0] = u8::try_from(pi).unwrap();
            let hash = RecordHash(hb);
            let existing = held.iter().find(|(dd, pp, hh, _)| *dd == dev(d) && *pp == p && *hh == hash).cloned();
            if add {
                if let Some(e) = existing {
                    held.remove(&e);
                    ix.remove(&e.0, e.1.as_bytes(), &e.2);
                }
                held.insert((dev(d), p.clone(), hash, c));
                ix.insert(dev(d), p.as_bytes(), hash, c);
            } else if let Some(e) = existing {
                held.remove(&e);
                ix.remove(&e.0, e.1.as_bytes(), &e.2);
            }
            for (pd, dir, c) in &probes {
                let want: BTreeSet<RecordHash> = held
                    .iter()
                    .filter(|(d, p, _, k)| *d == dev(*pd) && beneath(p, dir) && *k <= *c)
                    .map(|(_, _, h, _)| *h)
                    .collect();
                let mut got = Vec::new();
                ix.at_most(&dev(*pd), dir, *c, &mut got);
                let got_set: BTreeSet<RecordHash> = got.iter().copied().collect();
                prop_assert_eq!(got.len(), got_set.len(), "each once");
                prop_assert_eq!(&got_set, &want, "at {} for {} at most {}", dir, pd, c);
                ix.queries.set(0);
                prop_assert_eq!(ix.any_at_most(&dev(*pd), dir, *c), !want.is_empty());
                prop_assert!(ix.queries.get() <= 2, "two queries at most");
            }
            let ours: BTreeSet<(DeviceId, String, RecordHash, u64)> = ix.entries().into_iter().collect();
            prop_assert_eq!(&ours, &held);
            for d in 0..3 {
                let n = held.iter().filter(|e| e.0 == dev(d)).count();
                // An AVL tree of n nodes is at most 1.44 log2(n + 2) high.
                let bound = 1.45 * f64::from(u32::try_from(n + 2).unwrap()).log2() + 1.0;
                prop_assert!(f64::from(ix.height(&dev(d))) <= bound, "AVL height");
            }
        }
    }
}

/// The greatest height of an AVL tree of `n` nodes: the sparsest AVL tree of
/// height `h`, a Fibonacci tree, has `N(h) = N(h - 1) + N(h - 2) + 1` nodes
/// (`N(0) = 0`, `N(1) = 1`), and no AVL tree of height `h` has fewer, so a
/// tree of `n` nodes is at most the greatest `h` with `N(h) <= n` high (about
/// `1.44 log2 n`, the bound `bypath` states).
fn avl_max_height(n: usize) -> u8 {
    let (mut sparsest, mut next, mut h) = (0usize, 1usize, 0u8);
    while next <= n {
        (sparsest, next) = (next, sparsest + next + 1);
        h += 1;
    }
    h
}

/// The record of device 1 numbered `k`, at `d/<k>`: its path and hash.
fn numbered(k: u16) -> (String, RecordHash) {
    let mut h = [0u8; 32];
    h[..2].copy_from_slice(&k.to_be_bytes());
    (format!("d/{k:05}"), RecordHash(h))
}

/// Holds and drops the records numbered by `ops` (`true` holds, `false`
/// drops) at device 1, checking after each that its tree is no higher than
/// an AVL tree of as many records can be; the records held at the end.
fn hold_and_drop_staying_avl(ix: &mut ByPath, ops: &[(bool, u16)]) -> BTreeSet<u16> {
    let mut held = BTreeSet::new();
    for (step, &(hold, k)) in ops.iter().enumerate() {
        let (path, hash) = numbered(k);
        if hold && held.insert(k) {
            ix.insert(dev(1), path.as_bytes(), hash, u64::from(k) + 1);
        } else if !hold && held.remove(&k) {
            ix.remove(&dev(1), path.as_bytes(), &hash);
        }
        let (height, bound) = (ix.height(&dev(1)), avl_max_height(held.len()));
        assert!(
            height <= bound,
            "step {step} ({}{k}): {} records {height} high, an AVL tree of as many at most {bound}",
            if hold { "+" } else { "-" },
            held.len(),
        );
    }
    held
}

/// The bound the tests of the trees by path use: an AVL tree of height `h`
/// has at least 0, 1, 2, 4, 7, 12, 20, 33, 54, 88 … nodes for `h` = 0, 1, 2 ….
#[test]
fn the_avl_height_bound_is_the_fibonacci_trees() {
    let bounds: Vec<u8> = [0, 1, 2, 3, 4, 6, 7, 11, 12, 20, 33, 54, 88]
        .iter()
        .map(|&n| avl_max_height(n))
        .collect();
    assert_eq!(bounds, [0, 1, 2, 2, 3, 3, 4, 4, 5, 6, 7, 8, 9]);
    assert_eq!(avl_max_height(20_000), 20);
}

/// The trees by path are AVL trees (`bypath`; `protocol.md` 4.4, "Judging a
/// tree delete without a walk": each query `O(log n)` whatever the order of
/// the records): held in each of five orders (ascending, descending, outside
/// in, inside out, every other one first) and dropped in each, and dropped
/// half way and held again, each tree stays no higher than an AVL tree of as
/// many records can be, after every record held or dropped.
#[test]
fn the_trees_by_path_stay_avl_trees_in_every_order_of_holding_and_dropping() {
    let n: u16 = 300;
    let up: Vec<u16> = (0..n).collect();
    let down: Vec<u16> = (0..n).rev().collect();
    // 0, 299, 1, 298, …: outside in.
    let zigzag: Vec<u16> = (0..n / 2).flat_map(|i| [i, n - 1 - i]).collect();
    // 150, 149, 151, 148, …: inside out.
    let middle_out: Vec<u16> = (0..n / 2)
        .flat_map(|i| [n / 2 + i, n / 2 - 1 - i])
        .collect();
    // Every other one, then the rest.
    let alternate: Vec<u16> = (0..n).step_by(2).chain((1..n).step_by(2)).collect();
    let orders = [&up, &down, &zigzag, &middle_out, &alternate];
    for hold in orders {
        for drop in orders {
            let mut ix = ByPath::default();
            let mut ops: Vec<(bool, u16)> = hold.iter().map(|&k| (true, k)).collect();
            ops.extend(drop.iter().map(|&k| (false, k)));
            let left = hold_and_drop_staying_avl(&mut ix, &ops);
            assert!(left.is_empty());
            assert!(ix.entries().is_empty(), "every record dropped");
        }
        // Dropped half way, then held again: the trees rebalance both ways.
        let mut ix = ByPath::default();
        let mut ops: Vec<(bool, u16)> = hold.iter().map(|&k| (true, k)).collect();
        ops.extend(hold.iter().step_by(2).map(|&k| (false, k)));
        ops.extend(down.iter().step_by(3).map(|&k| (true, k)));
        ops.extend(up.iter().step_by(5).map(|&k| (false, k)));
        hold_and_drop_staying_avl(&mut ix, &ops);
    }
}

/// Holds (`+k`) and drops (`-k`) of the records numbered `k`.
fn steps(s: &str) -> Vec<(bool, u16)> {
    s.split_whitespace()
        .map(|t| (t.starts_with('+'), t[1..].parse().unwrap()))
        .collect()
}

/// The rebalancing cases of an AVL tree, each in an order of holds and
/// drops that ends six records four high, one higher than any AVL tree of
/// six can be, when the case is handled otherwise (found by a search over
/// random orders; random orders reach them rarely): a node one higher on
/// its left, or on its right, is balanced and stays as it is; and a drop
/// that leaves a node two higher on its left (right) over a left (right)
/// child whose two sides are equal takes one rotation, not two (two would
/// leave that child two higher on one side). After every step each tree is
/// no higher than an AVL tree of as many records.
#[test]
fn the_trees_by_path_stay_avl_trees_through_each_rebalancing_case() {
    for (case, order) in [
        (
            "one higher on the left: no rotation",
            "+2 +4 +9 +1 +3 +0 +6 +7 +8 +5 -8 -1 -9 -0",
        ),
        (
            "one higher on the right: no rotation",
            "+1 +9 +8 +4 +5 +3 +7 +0 +2 +6 -2 -8 -0 -9",
        ),
        (
            "two higher on the left over a balanced child: one rotation",
            "+5 +7 +2 +1 +3 +6 +0 +4 -6 -5",
        ),
        (
            "two higher on the right over a balanced child: one rotation",
            "+1 +2 +5 +4 +0 +7 +6 +3 -0 -1",
        ),
    ] {
        let mut ix = ByPath::default();
        let held = hold_and_drop_staying_avl(&mut ix, &steps(order));
        assert_eq!(held.len(), 6, "{case}");
        assert_eq!(ix.height(&dev(1)), 3, "{case}: six records three high");
    }
}

proptest! {
    #![proptest_config(super::proptest_config(256))]

    /// The trees by path stay AVL trees through any sequence of records held
    /// and dropped: after each, no higher than an AVL tree of as many
    /// records can be (`N(h)` records at least for a height `h`).
    #[test]
    fn the_trees_by_path_stay_avl_trees_through_any_holds_and_drops(
        holding in 1u8..4,
        ops in proptest::collection::vec((0u8..4, 0u16..48), 1..400),
    ) {
        // `holding` in 4 of the steps hold, the others drop: trees that grow,
        // hover and shrink.
        let ops: Vec<(bool, u16)> = ops.into_iter().map(|(o, k)| (o < holding, k)).collect();
        let mut ix = ByPath::default();
        let held = hold_and_drop_staying_avl(&mut ix, &ops);
        let ours: BTreeSet<String> = ix.entries().into_iter().map(|e| e.1).collect();
        let want: BTreeSet<String> = held.iter().map(|&k| numbered(k).0).collect();
        prop_assert_eq!(ours, want);
    }
}

/// The count of nodes a query reads, by which the tests bound a query's cost
/// (`O(log n)`, 4.4 "Judging a tree delete without a walk"), counts every
/// node read, in each of the three walks a query makes. Records of one
/// device at `c` and `e` at counter 1 and at `d/x` at 50 make a tree of
/// three (an AVL tree of three is perfect, whatever their order: `d/x` at
/// the root). Asked whether a record at or beneath `d` has a counter of at
/// most 10, which none has, a search answers no only after both runs: the
/// run at `d` (nothing there) reads the root and the leaf its search passes,
/// and the run beneath `d` reads the root, which lies in it, and both leaves,
/// whose counters of 1 it must find outside the run. So any correct search
/// reads at least five nodes, whichever run it walks first, and no query
/// reads a node twice: at most three each, six for the two. Without the
/// count, the bounds of `visited` would hold for a query that read the
/// whole tree.
#[test]
fn a_query_counts_every_node_it_reads() {
    let records = [("c", 1u64), ("d/x", 50), ("e", 1)];
    for order in [[0usize, 1, 2], [2, 1, 0], [1, 0, 2], [0, 2, 1]] {
        let mut ix = ByPath::default();
        for i in order {
            let (path, counter) = records[i];
            let mut h = [0u8; 32];
            h[0] = u8::try_from(i).unwrap();
            ix.insert(dev(1), path.as_bytes(), RecordHash(h), counter);
        }
        assert_eq!(ix.height(&dev(1)), 2, "{order:?}");
        ix.queries.set(0);
        ix.visited.set(0);
        assert!(!ix.any_at_most(&dev(1), "d", 10), "{order:?}");
        assert_eq!(ix.queries.get(), 2, "{order:?}: both runs");
        let visited = ix.visited.get();
        assert!(
            (5..=6).contains(&visited),
            "{order:?}: {visited} nodes read, at least the five any search reads"
        );
        // A device with nothing reads nothing; the count goes on from 0.
        ix.visited.set(0);
        assert!(!ix.any_at_most(&dev(2), "d", u64::MAX));
        assert_eq!(ix.visited.get(), 0);
    }
}

/// Tree-delete directories whose trie paths share components: `a` above
/// `a/b` above `a/b/c` above `a/b/c/d`, `a/bc` beside `a/b`, `b` beside `a`.
const TREE_DIRS: [&str; 6] = ["a", "a/b", "a/b/c", "a/b/c/d", "a/bc", "b"];

/// Paths looked up: at, beneath and beside those directories.
const LOOKUPS: [&str; 9] = [
    "a",
    "a/b",
    "a/b/c/d",
    "a/b/c/d/e",
    "a/bc/x",
    "a/bcd",
    "b/x",
    "ab",
    "c",
];

proptest! {
    #![proptest_config(super::proptest_config(256))]

    /// 4.4 step 3: the trie of held tree deletes finds, for any path, the
    /// tree deletes held at the path itself and at each of its ancestor
    /// directories, deepest first, after any sequence of tree deletes held
    /// and dropped, whichever of them share components; dropping one at a
    /// directory loses none at the directories beneath or above it; and once
    /// every one is dropped the trie is as new.
    #[test]
    fn the_trie_of_tree_deletes_finds_those_at_and_above_a_path(
        ops in proptest::collection::vec((any::<bool>(), 0usize..TREE_DIRS.len(), 0u8..3), 1..60),
    ) {
        let mut dirs = Dirs::default();
        let mut held: BTreeSet<(&str, RecordHash)> = BTreeSet::new();
        for (hold, di, n) in ops {
            let dir = TREE_DIRS[di];
            let mut h = [n; 32];
            h[0] = u8::try_from(di).unwrap();
            let hash = RecordHash(h);
            if hold {
                held.insert((dir, hash));
                dirs.insert(dir, hash);
            } else {
                held.remove(&(dir, hash));
                dirs.remove(dir, &hash);
            }
            for path in LOOKUPS {
                // The definition: the path itself and every directory above
                // it, deepest first, each with the tree deletes held there.
                let parts: Vec<&str> = path.split('/').collect();
                let want: Vec<BTreeSet<RecordHash>> = (1..=parts.len())
                    .rev()
                    .map(|k| parts[..k].join("/"))
                    .map(|at| held.iter().filter(|(d, _)| *d == at).map(|(_, h)| *h).collect::<BTreeSet<_>>())
                    .filter(|set| !set.is_empty())
                    .collect();
                let got: Vec<BTreeSet<RecordHash>> = dirs.at_and_above(path).into_iter().cloned().collect();
                prop_assert_eq!(&got, &want, "at {}", path);
            }
        }
        for (dir, hash) in core::mem::take(&mut held) {
            dirs.remove(dir, &hash);
        }
        prop_assert_eq!(format!("{dirs:?}"), format!("{:?}", Dirs::default()));
    }
}

/// The tree by path stays balanced however the records come: 20 000 records
/// at paths in ascending order, the case a naive search tree degrades on.
#[test]
fn the_index_by_path_is_balanced_for_records_in_path_order() {
    let mut ix = ByPath::default();
    let n = 20_000u32;
    for i in 0..n {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_be_bytes());
        ix.insert(
            dev(1),
            format!("d/{i:08}").as_bytes(),
            RecordHash(h),
            u64::from(i) + 1,
        );
    }
    assert!(ix.height(&dev(1)) <= 21, "height {}", ix.height(&dev(1)));
    ix.queries.set(0);
    assert!(!ix.any_at_most(&dev(1), "e", u64::MAX));
    assert!(ix.any_at_most(&dev(1), "d", 1));
    assert!(!ix.any_at_most(&dev(2), "d", u64::MAX), "another device");
    assert_eq!(
        ix.queries.get(),
        6,
        "two queries for each, whatever lies beneath (none to visit for a device with nothing)"
    );
}

/// A path of 4 096 bytes, beneath a chain of 2 047 held tree deletes, one at
/// each of its ancestors: the lookup walks each byte of the path once (4.4
/// step 3, `O(L)`), where building and comparing or hashing every ancestor
/// would cost the square of the path.
#[test]
fn the_ancestor_lookup_of_a_4096_byte_path_walks_it_once() {
    let mut dirs = Dirs::default();
    let path: String = "a/".repeat(MAX_PATH_BYTES / 2 - 1) + "zz";
    assert_eq!(path.len(), MAX_PATH_BYTES);
    let parts: Vec<&str> = path.split('/').collect();
    for k in 1..parts.len() {
        let dir = parts[..k].join("/");
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&u32::try_from(k).unwrap().to_be_bytes());
        dirs.insert(&dir, RecordHash(h));
    }
    dirs.walked.set(0);
    let found = dirs.at_and_above(&path);
    assert_eq!(
        found.len(),
        parts.len() - 1,
        "every ancestor's tree delete, deepest first"
    );
    assert!(
        dirs.walked.get() <= MAX_PATH_BYTES + 1,
        "walked {} bytes of a {}-byte path",
        dirs.walked.get(),
        MAX_PATH_BYTES
    );
    // A path that leaves the trie stops the walk there.
    dirs.walked.set(0);
    assert!(dirs
        .at_and_above(&format!("b/{}", "a/".repeat(2000)))
        .is_empty());
    assert_eq!(dirs.walked.get(), 2, "one component");
    // Removing them all leaves an empty trie.
    for k in 1..parts.len() {
        let dir = parts[..k].join("/");
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&u32::try_from(k).unwrap().to_be_bytes());
        dirs.remove(&dir, &RecordHash(h));
    }
    assert!(dirs.at_and_above(&path).is_empty());
    assert_eq!(format!("{dirs:?}"), format!("{:?}", Dirs::default()));
}

/// The set digest of `keys` at `prefix` from nothing but `protocol.md` 4.5.
fn reference(
    keys: &BTreeSet<[u8; 64]>,
    prefix: &licketysync_protocol::exchange::Prefix,
) -> licketysync_keys::SetDigest {
    let mut hs: Vec<RecordHash> = keys
        .iter()
        .filter(|k| prefix.contains(k))
        .map(|k| RecordHash(k[32..].try_into().unwrap()))
        .collect();
    if hs.is_empty() {
        return licketysync_keys::SetDigest::EMPTY;
    }
    if hs.len() <= 64 || prefix.is_full() {
        hs.sort_unstable();
        return licketysync_keys::SetDigest::leaf(&hs);
    }
    let children: [licketysync_keys::SetDigest; 16] =
        core::array::from_fn(|i| reference(keys, &prefix.child(u8::try_from(i).unwrap()).unwrap()));
    licketysync_keys::SetDigest::node(&children)
}

proptest! {
    #![proptest_config(super::proptest_config(48))]

    /// (m) the incremental trie's digests, counts and records equal the
    /// spec's definition computed afresh, after every insert and remove, at
    /// every prefix along the key changed and at its children, with many
    /// records at one tag so that subtrees split beneath it by record-hash
    /// nibbles; no change rehashes more than one leaf of 65 hashes and 128
    /// nodes (the R1 review's `probe_trie`, at 64-byte keys).
    #[test]
    fn the_trie_is_the_digest_after_every_change_m(ops in proptest::collection::vec((any::<bool>(), 0u8..4, any::<u8>(), any::<u8>()), 1..300)) {
        use licketysync_protocol::exchange::Prefix;
        let mut t = crate::trie::Trie::default();
        let mut keys: BTreeSet<[u8; 64]> = BTreeSet::new();
        for (add, shape, a, b) in ops {
            let mut k = [0u8; 64];
            match shape {
                // One tag, many records.
                0 => k[..32].copy_from_slice(&[0x5a; 32]),
                // Tags sharing two nibbles.
                1 => { k[0] = 0x31; k[1] = a; }
                // Random tags.
                2 => { k[0] = a; k[1] = b; k[31] = a ^ b; }
                // One tag, record hashes sharing a long run of nibbles.
                _ => { k[..32].copy_from_slice(&[0x77; 32]); k[32..60].copy_from_slice(&[0x11; 28]); }
            }
            k[60] = a;
            k[61] = b;
            k[63] = shape;
            t.max_cost = crate::trie::Cost::default();
            if add {
                if keys.insert(k) { t.insert(k); }
            } else if keys.remove(&k) {
                t.remove(k);
            }
            prop_assert!(t.max_cost.leaf_records <= 65 && t.max_cost.nodes <= 128, "{:?}", t.max_cost);
            prop_assert_eq!(t.digest(&Prefix::ROOT), reference(&keys, &Prefix::ROOT));
            for d in [1usize, 2, 63, 64, 65, 70, 100, 127, 128] {
                let p = Prefix::of_key(&k, d);
                prop_assert_eq!(t.digest(&p), reference(&keys, &p), "depth {}", d);
                prop_assert_eq!(t.count(&p), keys.iter().filter(|x| p.contains(x)).count());
                if d % 32 == 0 {
                    for (n, kd) in t.children(&p).iter().enumerate() {
                        if let Some(c) = p.child(u8::try_from(n).unwrap()) {
                            prop_assert_eq!(*kd, reference(&keys, &c));
                        }
                    }
                }
            }
        }
    }
}

/// 8 000 records at one tag, inserted then removed, straight on the trie:
/// no change reads more than 65 record hashes or rehashes more than 128
/// nodes, and the digest stays the definition's (`protocol.md` 8 item 8,
/// counted, not timed).
#[test]
fn eight_thousand_records_at_one_tag_cost_one_leaf_and_128_nodes_each() {
    let mut t = crate::trie::Trie::default();
    let mut keys = BTreeSet::new();
    let mut s: u64 = 7;
    let mut all = Vec::new();
    for _ in 0..8_000 {
        let mut k = [0x42u8; 64];
        for chunk in k[32..].chunks_mut(8) {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            chunk.copy_from_slice(&s.to_be_bytes());
        }
        t.max_cost = crate::trie::Cost::default();
        t.insert(k);
        keys.insert(k);
        all.push(k);
        assert!(
            t.max_cost.leaf_records <= 65 && t.max_cost.nodes <= 128,
            "{:?}",
            t.max_cost
        );
    }
    let root = licketysync_protocol::exchange::Prefix::ROOT;
    assert_eq!(t.digest(&root), reference(&keys, &root));
    for k in &all {
        t.max_cost = crate::trie::Cost::default();
        t.remove(*k);
        assert!(
            t.max_cost.leaf_records <= 64 && t.max_cost.nodes <= 128,
            "{:?}",
            t.max_cost
        );
    }
    assert_eq!(t.digest(&root), licketysync_keys::SetDigest::EMPTY);
}
