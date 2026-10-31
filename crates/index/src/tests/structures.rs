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
