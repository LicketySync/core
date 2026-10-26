// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Set digests (`protocol.md` 4.5; labels in `keys.md` section 10): the hashes
//! by which two devices compare the records they hold for a folder, subtree by
//! subtree of a 16-way trie of keys (path tags, or a cleanup's own record
//! hash).
//!
//! ```text
//! empty subtree : 32 zero bytes
//! leaf form     : H("licketysync/v1/hash/set-leaf", be32(n) || h_1 || … || h_n)   # record hashes ascending
//! node form     : H("licketysync/v1/hash/set-node", d_0 || d_1 || … || d_15)      # the 16 child digests
//! ```
//!
//! Which form a subtree takes (at most `RECONCILE_LEAF_MAX` records or full
//! depth: leaf; otherwise node) is the index's decision; this module only
//! computes each form. The empty subtree's digest is
//! [`SetDigest::EMPTY`], and [`SetDigest::leaf`] returns it for no record
//! hashes, so that no caller ever hashes an empty leaf: an empty subtree has
//! one digest whoever computes it. The index keeps the cache of digests; the
//! protocol crate's tests use these functions as their reference.

use crate::ids::{RecordHash, SetDigest};
use crate::labels::{self, labelled_hash};

/// The children of a subtree in node form: one per nibble, 0 to 15.
pub const CHILDREN: usize = 16;

impl SetDigest {
    /// The digest of an empty subtree: 32 zero bytes (`protocol.md` 4.5). It is
    /// what [`SetDigest::leaf`] returns for no record hashes.
    pub const EMPTY: SetDigest = SetDigest([0; 32]);

    /// Whether this is the empty subtree's digest.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == SetDigest::EMPTY
    }

    /// The digest of a subtree that holds the records `hashes`: 32 zero bytes
    /// when there are none, otherwise the leaf form
    /// `H("licketysync/v1/hash/set-leaf", be32(n) || h_1 || … || h_n)` over the
    /// hashes ascending, each once. The digest is that of the set: hashes
    /// given out of order or with repeats are sorted and deduplicated in a
    /// copy first, so that two callers holding the same records always agree;
    /// a caller that keeps them sorted (the index does) pays one comparison
    /// per hash for that check.
    #[must_use]
    pub fn leaf(hashes: &[RecordHash]) -> SetDigest {
        if hashes.is_empty() {
            return SetDigest::EMPTY;
        }
        if hashes.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
            return leaf_of_sorted(hashes);
        }
        let mut sorted = hashes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        leaf_of_sorted(&sorted)
    }

    /// The node form `H("licketysync/v1/hash/set-node", d_0 || … || d_15)`
    /// over the digests of the 16 subtrees at the prefix followed by 0 to 15.
    /// A subtree is in node form only when it holds more than
    /// `RECONCILE_LEAF_MAX` records, so its children are never all empty.
    #[must_use]
    pub fn node(children: &[SetDigest; CHILDREN]) -> SetDigest {
        let parts: Vec<&[u8]> = children.iter().map(|d| d.as_bytes().as_slice()).collect();
        SetDigest(labelled_hash(labels::HASH_SET_NODE, &parts))
    }
}

/// The leaf form over hashes already ascending without repeats.
fn leaf_of_sorted(hashes: &[RecordHash]) -> SetDigest {
    // A count past 2^32 - 1 would need more than 128 GiB of record hashes in
    // memory for one subtree; it cannot occur, so the count saturates rather
    // than fail.
    let count = u32::try_from(hashes.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(hashes.len() + 1);
    parts.push(&count);
    parts.extend(hashes.iter().map(|h| h.as_bytes().as_slice()));
    SetDigest(labelled_hash(labels::HASH_SET_LEAF, &parts))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rh(b: u8) -> RecordHash {
        RecordHash([b; 32])
    }

    #[test]
    fn the_empty_subtree_is_zero_and_no_leaf_is_hashed_for_it() {
        assert_eq!(SetDigest::leaf(&[]), SetDigest::EMPTY);
        assert_eq!(SetDigest::EMPTY.0, [0; 32]);
        assert!(SetDigest::EMPTY.is_empty());
        assert!(!SetDigest::leaf(&[rh(1)]).is_empty());
    }

    #[test]
    fn the_leaf_form_is_the_count_then_the_hashes_ascending() {
        let leaf = SetDigest::leaf(&[rh(1), rh(2), rh(3)]);
        let mut expected = Vec::new();
        expected.extend(3u32.to_be_bytes());
        for b in [1u8, 2, 3] {
            expected.extend([b; 32]);
        }
        assert_eq!(
            leaf.0,
            labelled_hash(labels::HASH_SET_LEAF, &[&expected]),
            "be32(n) || h_1 || h_2 || h_3 under hash/set-leaf"
        );
        // The set's digest whatever order or repeats the caller gives.
        assert_eq!(SetDigest::leaf(&[rh(3), rh(1), rh(2)]), leaf);
        assert_eq!(SetDigest::leaf(&[rh(1), rh(2), rh(2), rh(3)]), leaf);
        assert_ne!(SetDigest::leaf(&[rh(1), rh(2)]), leaf);
    }

    #[test]
    fn the_node_form_is_the_sixteen_children_in_order() {
        let children: [SetDigest; 16] =
            core::array::from_fn(|i| SetDigest::leaf(&[rh(u8::try_from(i).unwrap() + 1)]));
        let node = SetDigest::node(&children);
        let joined: Vec<u8> = children.iter().flat_map(|c| c.0).collect();
        assert_eq!(node.0, labelled_hash(labels::HASH_SET_NODE, &[&joined]));
        let mut swapped = children;
        swapped.swap(0, 1);
        assert_ne!(SetDigest::node(&swapped), node);
        // The two labels keep the forms apart over the same bytes.
        assert_ne!(labelled_hash(labels::HASH_SET_LEAF, &[&joined]), node.0);
    }

    proptest! {
        /// A leaf's digest depends only on the set of hashes.
        #[test]
        fn a_leaf_is_a_function_of_the_set(mut v in proptest::collection::vec(any::<[u8; 32]>(), 0..20)) {
            let hashes: Vec<RecordHash> = v.iter().copied().map(RecordHash).collect();
            let digest = SetDigest::leaf(&hashes);
            v.sort_unstable();
            v.dedup();
            let sorted: Vec<RecordHash> = v.into_iter().map(RecordHash).collect();
            prop_assert_eq!(SetDigest::leaf(&sorted), digest);
            prop_assert_eq!(digest.is_empty(), sorted.is_empty());
        }
    }
}
