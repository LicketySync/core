// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The set digests of one folder's held records and their cache
//! (`protocol.md` 4.5, "Set digests").
//!
//! Each record has a 64-byte key, an index record's path tag then its record
//! hash, a cleanup's record hash twice ([`Key`]), and the subtree at a prefix
//! of `k` nibbles (0 to 128) holds the records whose key begins with them. A
//! subtree's digest is 32 zero bytes when it holds no record; its leaf form
//! when it holds at most `RECONCILE_LEAF_MAX` records or sits at depth 128
//! (one record at most, a key being unique); otherwise its node form over its
//! 16 children. The digest functions are the keys crate's
//! ([`SetDigest::leaf`], [`SetDigest::node`]).
//!
//! The cache keeps a node per subtree in node form, each with the digests of
//! its 16 children, and a count and digest for every subtree a node holds as
//! a child, leaves included. The leaf form begins at the shortest prefix
//! whose subtree holds at most 64 records, above or below 64 nibbles, so no
//! leaf holds more than 64: a change rehashes one leaf of at most 64 record
//! hashes and the nodes above it, at most 128, however many records one file
//! ID holds (the coordinator's ruling IS-2; TM-22). Serving reads the cache
//! and computes no digest; the children of a subtree in leaf form are
//! computed on demand from its at most 64 records.

use std::collections::BTreeSet;

use core::ops::Bound;

use licketysync_keys::{RecordHash, SetDigest};
use licketysync_protocol::exchange::{nibble, Key, Prefix};
use licketysync_protocol::limits::RECONCILE_LEAF_MAX;

/// One subtree's cached state.
#[derive(Clone, Debug)]
struct Node {
    count: usize,
    digest: SetDigest,
    /// Present while the subtree is in node form.
    children: Option<Box<[Node; 16]>>,
}

impl Node {
    fn empty() -> Self {
        Self {
            count: 0,
            digest: SetDigest::EMPTY,
            children: None,
        }
    }
}

/// What a change cost the cache, for the tests that count it (`protocol.md`
/// 8 item 8: "counted, not timed").
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cost {
    /// The record hashes read into leaf digests: the one leaf rehashed, or,
    /// when a subtree passes 64 records and splits, the at most 65 records
    /// spread over its new leaves.
    pub(crate) leaf_records: usize,
    /// The node-form subtrees rehashed.
    pub(crate) nodes: usize,
}

/// The digests of one folder's held records, keyed by set-digest key.
#[derive(Clone)]
pub(crate) struct Trie {
    /// Every held record by key, so that a subtree's records are a range.
    entries: BTreeSet<Key>,
    root: Node,
    /// The greatest cost of any one change since the tests last reset it.
    #[cfg(test)]
    pub(crate) max_cost: Cost,
    /// The keys [`Trie::keys_after`] read from the key set, for the test of
    /// what a `RECORDS` page costs.
    #[cfg(test)]
    pub(crate) read: crate::state::Meter,
}

impl Default for Trie {
    fn default() -> Self {
        Self {
            entries: BTreeSet::new(),
            root: Node::empty(),
            #[cfg(test)]
            max_cost: Cost::default(),
            #[cfg(test)]
            read: crate::state::Meter::default(),
        }
    }
}

/// The records and the root digest, without the tests' cost meter, so that a
/// rollback compares exactly (the cache's shape is a function of the
/// records).
impl core::fmt::Debug for Trie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Trie")
            .field("entries", &self.entries.len())
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

/// The record hash a key ends with.
pub(crate) fn hash_of(key: &Key) -> RecordHash {
    let mut h = [0u8; 32];
    if let Some(tail) = key.get(32..) {
        h.copy_from_slice(tail);
    }
    RecordHash(h)
}

impl Trie {
    /// The record hashes in the subtree at `prefix`, ascending by key.
    fn range(&self, prefix: &Prefix) -> impl Iterator<Item = RecordHash> + '_ {
        let (lo, hi) = prefix.bounds();
        self.entries.range(lo..=hi).map(hash_of)
    }

    /// The leaf digest of the records in the subtree at `prefix`.
    fn leaf_digest(&self, prefix: &Prefix) -> SetDigest {
        leaf_digest(&self.entries, prefix)
    }

    /// Adds a held record.
    pub(crate) fn insert(&mut self, key: Key) {
        if self.entries.insert(key) {
            self.update(&key, true);
        }
    }

    /// Removes a record no longer held.
    pub(crate) fn remove(&mut self, key: Key) {
        if self.entries.remove(&key) {
            self.update(&key, false);
        }
    }

    /// Counts the change down the path of `key` and rehashes that path
    /// bottom up, in one walk of at most 129 levels: one leaf and the nodes
    /// above it, each node rehashed from its 16 children's cached digests. A
    /// subtree that passes `RECONCILE_LEAF_MAX` becomes a node (its children
    /// built from its records), and a node that falls to it becomes a leaf.
    fn update(&mut self, key: &Key, added: bool) {
        let cost = update_at(&mut self.root, &self.entries, key, 0, added);
        #[cfg(test)]
        {
            self.max_cost.leaf_records = self.max_cost.leaf_records.max(cost.0);
            self.max_cost.nodes = self.max_cost.nodes.max(cost.1);
        }
        #[cfg(not(test))]
        let _ = cost;
    }

    /// The digest of the subtree at `prefix`: the cache's, or, beneath a
    /// subtree in leaf form, computed from its at most 64 records.
    pub(crate) fn digest(&self, prefix: &Prefix) -> SetDigest {
        let mut node = &self.root;
        for n in prefix.nibbles() {
            match &node.children {
                Some(children) => match children.get(usize::from(n)) {
                    Some(child) => node = child,
                    None => return SetDigest::EMPTY,
                },
                // A leaf above the prefix: the prefix's records are some of
                // its at most 64.
                None => return self.leaf_digest(prefix),
            }
        }
        node.digest
    }

    /// The number of records in the subtree at `prefix`.
    pub(crate) fn count(&self, prefix: &Prefix) -> usize {
        let mut node = &self.root;
        for n in prefix.nibbles() {
            match &node.children {
                Some(children) => match children.get(usize::from(n)) {
                    Some(child) => node = child,
                    None => return 0,
                },
                None => return self.range(prefix).count(),
            }
        }
        node.count
    }

    /// The 16 child digests of the subtree at `prefix`.
    pub(crate) fn children(&self, prefix: &Prefix) -> [SetDigest; 16] {
        core::array::from_fn(|i| {
            u8::try_from(i)
                .ok()
                .and_then(|n| prefix.child(n))
                .map_or(SetDigest::EMPTY, |child| self.digest(&child))
        })
    }

    /// The record hashes in the subtree at `prefix`, in ascending key order.
    pub(crate) fn records(&self, prefix: &Prefix) -> Vec<RecordHash> {
        self.range(prefix).collect()
    }

    /// The keys of the subtree at `prefix` in ascending order, after `after`
    /// (a key of that subtree, the last one sent) or from its first: the
    /// subtree is a range of keys, read one key at a time, `O(log n)` to
    /// begin and constant memory (4.5, "Serving a `ReconcileRequest`"; the
    /// coordinator's ruling CR-1).
    pub(crate) fn keys_after<'a>(
        &'a self,
        prefix: &Prefix,
        after: Option<&Key>,
    ) -> impl Iterator<Item = &'a Key> + 'a {
        let (lo, hi) = prefix.bounds();
        let from = after.map_or(Bound::Included(lo), |a| Bound::Excluded(*a));
        self.entries
            .range((from, Bound::Included(hi)))
            .inspect(|_| self.metered())
    }

    /// Counts one key read from the key set, in the tests.
    #[cfg(test)]
    fn metered(&self) {
        self.read.add(1);
    }

    /// Counts nothing outside the tests.
    #[cfg(not(test))]
    #[allow(clippy::unused_self, reason = "the tests' twin reads self")]
    const fn metered(&self) {}
}

/// The leaf digest of the records of `entries` in the subtree at `prefix`.
fn leaf_digest(entries: &BTreeSet<Key>, prefix: &Prefix) -> SetDigest {
    let (lo, hi) = prefix.bounds();
    let mut hashes: Vec<RecordHash> = entries.range(lo..=hi).map(hash_of).collect();
    hashes.sort_unstable();
    SetDigest::leaf(&hashes)
}

/// The digest of a node from its 16 children's cached digests.
fn node_digest(children: &[Node; 16]) -> SetDigest {
    let digests: [SetDigest; 16] =
        core::array::from_fn(|i| children.get(i).map_or(SetDigest::EMPTY, |c| c.digest));
    SetDigest::node(&digests)
}

/// One level of [`Trie::update`], at depth `depth` on the path of `key`:
/// counts the change here, goes on into the child the key lies in while
/// this subtree stays in node form, and rehashes this subtree on the way
/// back. Recursion bounded by the trie's 129 levels. Returns what it cost,
/// for the tests' meter: the record hashes read into leaf digests (the one
/// leaf, or the records of a subtree that has just split) and the
/// node-form subtrees rehashed.
#[allow(
    clippy::indexing_slicing,
    reason = "a nibble is 0 to 15, and a node has 16 children"
)]
fn update_at(
    node: &mut Node,
    entries: &BTreeSet<Key>,
    key: &Key,
    depth: usize,
    added: bool,
) -> (usize, usize) {
    if added {
        node.count += 1;
    } else {
        node.count = node.count.saturating_sub(1);
    }
    let prefix = Prefix::of_key(key, depth);
    if node.count <= RECONCILE_LEAF_MAX || prefix.is_full() {
        node.children = None;
        if node.count == 0 {
            node.digest = SetDigest::EMPTY;
            return (0, 0);
        }
        node.digest = leaf_digest(entries, &prefix);
        return (node.count, 0);
    }
    let (leaf_records, nodes) = if let Some(children) = node.children.as_mut() {
        update_at(
            &mut children[usize::from(nibble(key, depth) & 0x0f)],
            entries,
            key,
            depth + 1,
            added,
        )
    } else {
        let mut hashed = 0;
        node.children = Some(Box::new(build_children(entries, &prefix, &mut hashed)));
        (hashed, 0)
    };
    if let Some(children) = &node.children {
        node.digest = node_digest(children);
    }
    (leaf_records, nodes + 1)
}

/// The 16 children of a subtree that has just passed `RECONCILE_LEAF_MAX`,
/// built from its records: each child is a leaf unless it too passes the
/// bound, in which case it is built the same way one level down.
fn build_children(entries: &BTreeSet<Key>, prefix: &Prefix, hashed: &mut usize) -> [Node; 16] {
    core::array::from_fn(|i| {
        u8::try_from(i)
            .ok()
            .and_then(|n| prefix.child(n))
            .map_or_else(Node::empty, |p| build(entries, &p, hashed))
    })
}

/// The cached state of the subtree at `prefix`, built from `entries`. It
/// recurses only through `build_children`, one nibble level each time, so its
/// depth is bounded by the 128 levels of the trie, never by the number of
/// records. `hashed` counts the record hashes read into its leaves.
fn build(entries: &BTreeSet<Key>, prefix: &Prefix, hashed: &mut usize) -> Node {
    let (lo, hi) = prefix.bounds();
    let range = entries.range(lo..=hi);
    let count = range.clone().count();
    if count <= RECONCILE_LEAF_MAX || prefix.is_full() {
        let mut leaf: Vec<RecordHash> = range.map(hash_of).collect();
        leaf.sort_unstable();
        *hashed += leaf.len();
        return Node {
            count,
            digest: SetDigest::leaf(&leaf),
            children: None,
        };
    }
    let children = build_children(entries, prefix, hashed);
    Node {
        count,
        digest: node_digest(&children),
        children: Some(Box::new(children)),
    }
}
