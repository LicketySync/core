// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The held applied tree deletes by directory, in a trie of path components
//! (`protocol.md` 4.4 step 3: "the held tree deletes are kept in a trie by
//! path, so the lookup costs `O(L)` work").
//!
//! Whether a record lies beneath a held tree delete that covers it is a walk
//! down the trie along its path's components, one map lookup each, so a path
//! of `L` bytes costs `O(L)` work up to the logarithm of the trie's fan-out,
//! however deep the path and however many tree deletes are held; no ancestor
//! path is built, compared whole or hashed. The trie holds one node per
//! directory component of a held tree delete's path, and nothing for any
//! other record. Recursion here is bounded by the components of one path, at
//! most `MAX_PATH_BYTES / 2`.

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::RecordHash;

/// One directory of the trie: the tree deletes held at it, and the
/// directories beneath it that hold one at or beneath them.
#[derive(Clone, Debug, Default)]
struct Dir {
    children: BTreeMap<Box<str>, Dir>,
    here: BTreeSet<RecordHash>,
}

impl Dir {
    fn is_empty(&self) -> bool {
        self.here.is_empty() && self.children.is_empty()
    }

    fn insert<'p>(&mut self, mut parts: impl Iterator<Item = &'p str>, hash: RecordHash) {
        match parts.next() {
            Some(p) => self
                .children
                .entry(p.into())
                .or_default()
                .insert(parts, hash),
            None => {
                self.here.insert(hash);
            }
        }
    }

    fn remove<'p>(&mut self, mut parts: impl Iterator<Item = &'p str>, hash: &RecordHash) {
        match parts.next() {
            Some(p) => {
                if let Some(child) = self.children.get_mut(p) {
                    child.remove(parts, hash);
                    if child.is_empty() {
                        self.children.remove(p);
                    }
                }
            }
            None => {
                self.here.remove(hash);
            }
        }
    }
}

/// The held applied tree deletes, by the components of their directory.
#[derive(Clone, Default)]
pub(crate) struct Dirs {
    root: Dir,
    /// The path bytes the lookups walked, for the test of the `O(L)` bound.
    #[cfg(test)]
    pub(crate) walked: core::cell::Cell<usize>,
}

/// The trie alone, without the tests' count, so that a rollback compares
/// exactly.
impl core::fmt::Debug for Dirs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.root.fmt(f)
    }
}

impl Dirs {
    /// Adds a held tree delete of `dir`.
    pub(crate) fn insert(&mut self, dir: &str, hash: RecordHash) {
        self.root.insert(dir.split('/'), hash);
    }

    /// Removes a tree delete no longer held.
    pub(crate) fn remove(&mut self, dir: &str, hash: &RecordHash) {
        self.root.remove(dir.split('/'), hash);
    }

    /// The tree deletes held at `path` itself and at each of its ancestor
    /// directories, deepest first, found in one pass down the trie along the
    /// path: it stops where the trie holds nothing deeper.
    pub(crate) fn at_and_above(&self, path: &str) -> Vec<&BTreeSet<RecordHash>> {
        let mut found = Vec::new();
        let mut node = &self.root;
        for part in path.split('/') {
            #[cfg(test)]
            self.walked.set(self.walked.get() + part.len() + 1);
            match node.children.get(part) {
                Some(next) => {
                    node = next;
                    if !node.here.is_empty() {
                        found.push(&node.here);
                    }
                }
                None => break,
            }
        }
        found.reverse();
        found
    }
}
