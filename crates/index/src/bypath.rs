// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Judging a tree delete without a walk (`protocol.md` 4.4, "Judging a tree
//! delete without a walk").
//!
//! A read or write holder keeps, per device ID, the applied records it holds
//! (live versions and tombstones, and tree deletes; not opaque records, nor
//! cleanups, nor records kept only as bases) in a search tree ordered by path
//! bytewise, then record hash, whose every node also keeps the least counter
//! in its subtree. In that order the records at or beneath a directory `P`
//! are those at `P` itself and the run from `P/` up to, not including, `P0`
//! (`0` is the byte after `/`). A tree delete of `P` covers some held record
//! exactly when, for some entry `(d, c)` of its vector, the least counter of
//! device `d`'s records in those two runs is at most `c`: two queries per
//! entry, each `O(log n)`, whatever lies beneath `P`. The records it covers
//! are found by descending only into the parts of each run whose least
//! counter is at most `c`, `O(log n)` per record found.
//!
//! The trees are AVL trees, so their height is at most about `1.44 log2 n`
//! whatever the order of the records, and every recursion here is bounded by
//! it.

#![allow(
    clippy::unnecessary_box_returns,
    reason = "a tree's nodes live boxed in their parents; handing the box back moves no node"
)]

use std::collections::BTreeMap;

use core::cmp::Ordering;
use core::fmt;

use licketysync_keys::{DeviceId, RecordHash};

/// One node: a held record of one device, by `(path, hash)`.
#[derive(Clone)]
struct Node {
    path: Box<[u8]>,
    hash: RecordHash,
    counter: u64,
    /// The least counter in this subtree.
    least: u64,
    height: u8,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

type Link = Option<Box<Node>>;

fn height(n: Option<&Node>) -> u8 {
    n.map_or(0, |n| n.height)
}

fn least(n: Option<&Node>) -> u64 {
    n.map_or(u64::MAX, |n| n.least)
}

impl Node {
    fn new(path: &[u8], hash: RecordHash, counter: u64) -> Box<Self> {
        Box::new(Self {
            path: path.into(),
            hash,
            counter,
            least: counter,
            height: 1,
            left: None,
            right: None,
        })
    }

    fn cmp_key(&self, path: &[u8], hash: &RecordHash) -> Ordering {
        (&*self.path, &self.hash).cmp(&(path, hash))
    }

    fn update(&mut self) {
        let (l, r) = (self.left.as_deref(), self.right.as_deref());
        self.height = 1 + height(l).max(height(r));
        self.least = self.counter.min(least(l)).min(least(r));
    }

    fn balance(&self) -> i16 {
        i16::from(height(self.left.as_deref())) - i16::from(height(self.right.as_deref()))
    }
}

fn rotate_right(mut n: Box<Node>) -> Box<Node> {
    match n.left.take() {
        Some(mut l) => {
            n.left = l.right.take();
            n.update();
            l.right = Some(n);
            l.update();
            l
        }
        None => n,
    }
}

fn rotate_left(mut n: Box<Node>) -> Box<Node> {
    match n.right.take() {
        Some(mut r) => {
            n.right = r.left.take();
            n.update();
            r.left = Some(n);
            r.update();
            r
        }
        None => n,
    }
}

fn rebalance(mut n: Box<Node>) -> Box<Node> {
    n.update();
    let b = n.balance();
    if b > 1 {
        if n.left.as_ref().is_some_and(|l| l.balance() < 0) {
            n.left = n.left.take().map(rotate_left);
        }
        return rotate_right(n);
    }
    if b < -1 {
        if n.right.as_ref().is_some_and(|r| r.balance() > 0) {
            n.right = n.right.take().map(rotate_right);
        }
        return rotate_left(n);
    }
    n
}

fn insert(link: Link, path: &[u8], hash: RecordHash, counter: u64) -> Box<Node> {
    let Some(mut n) = link else {
        return Node::new(path, hash, counter);
    };
    match n.cmp_key(path, &hash) {
        Ordering::Greater => n.left = Some(insert(n.left.take(), path, hash, counter)),
        Ordering::Less => n.right = Some(insert(n.right.take(), path, hash, counter)),
        Ordering::Equal => n.counter = counter,
    }
    rebalance(n)
}

/// Takes the least node out of a subtree: the rest, and that node.
fn take_least(mut n: Box<Node>) -> (Link, Box<Node>) {
    match n.left.take() {
        Some(l) => {
            let (rest, min) = take_least(l);
            n.left = rest;
            (Some(rebalance(n)), min)
        }
        None => (n.right.take(), n),
    }
}

fn remove(link: Link, path: &[u8], hash: &RecordHash) -> Link {
    let mut n = link?;
    match n.cmp_key(path, hash) {
        Ordering::Greater => n.left = remove(n.left.take(), path, hash),
        Ordering::Less => n.right = remove(n.right.take(), path, hash),
        Ordering::Equal => {
            return match (n.left.take(), n.right.take()) {
                (None, r) => r,
                (l, None) => l,
                (l, Some(r)) => {
                    let (rest, mut m) = take_least(r);
                    m.left = l;
                    m.right = rest;
                    Some(rebalance(m))
                }
            };
        }
    }
    Some(rebalance(n))
}

/// One of the two runs at or beneath a directory, compared without building
/// its bounds: `At(dir)` is `dir` itself, `[dir, dir\0)`; `Beneath(dir)` is
/// `[dir/, dir0)`, `0` being the byte after `/`.
#[derive(Clone, Copy)]
enum Run<'a> {
    At(&'a [u8]),
    Beneath(&'a [u8]),
}

impl Run<'_> {
    /// Where `path` lies against the run: `Less` below it, `Equal` in it,
    /// `Greater` above it.
    fn place(self, path: &[u8]) -> Ordering {
        match self {
            Self::At(dir) => path.cmp(dir),
            Self::Beneath(dir) => match path.strip_prefix(dir) {
                // `dir` itself lies below `dir/`; then the byte after `dir`
                // decides: below `/`, in at `/`, above past it.
                Some(rest) => rest.first().map_or(Ordering::Less, |b| b.cmp(&b'/')),
                // Not beginning with `dir`: as `dir` itself (a proper prefix
                // of `dir` is below it).
                None => match path.cmp(dir) {
                    Ordering::Equal => Ordering::Less,
                    o => o,
                },
            },
        }
    }
}

/// The least counter of the records not below `run` in this subtree, all of
/// which lie below its end (`u64::MAX` for none: callers ask only for
/// counters below it). `seen` counts the nodes visited.
fn least_from(link: Option<&Node>, run: Run<'_>, seen: &mut usize) -> u64 {
    let Some(n) = link else { return u64::MAX };
    *seen += 1;
    if run.place(&n.path) == Ordering::Less {
        least_from(n.right.as_deref(), run, seen)
    } else {
        n.counter
            .min(least(n.right.as_deref()))
            .min(least_from(n.left.as_deref(), run, seen))
    }
}

/// The least counter of the records not above `run` in this subtree, all of
/// which lie at or past its start.
fn least_below(link: Option<&Node>, run: Run<'_>, seen: &mut usize) -> u64 {
    let Some(n) = link else { return u64::MAX };
    *seen += 1;
    if run.place(&n.path) == Ordering::Greater {
        least_below(n.left.as_deref(), run, seen)
    } else {
        n.counter
            .min(least(n.left.as_deref()))
            .min(least_below(n.right.as_deref(), run, seen))
    }
}

/// The least counter of the records in `run`.
fn least_in(link: Option<&Node>, run: Run<'_>, seen: &mut usize) -> u64 {
    let Some(n) = link else { return u64::MAX };
    *seen += 1;
    match run.place(&n.path) {
        Ordering::Less => least_in(n.right.as_deref(), run, seen),
        Ordering::Greater => least_in(n.left.as_deref(), run, seen),
        Ordering::Equal => n
            .counter
            .min(least_from(n.left.as_deref(), run, seen))
            .min(least_below(n.right.as_deref(), run, seen)),
    }
}

/// The records in `run` whose counter is at most `c`, descending only into
/// subtrees whose least counter is at most `c`.
fn collect(link: Option<&Node>, run: Run<'_>, c: u64, out: &mut Vec<RecordHash>) {
    let Some(n) = link else { return };
    if n.least > c {
        return;
    }
    let place = run.place(&n.path);
    if place != Ordering::Less {
        collect(n.left.as_deref(), run, c, out);
    }
    if place == Ordering::Equal && n.counter <= c {
        out.push(n.hash);
    }
    if place != Ordering::Greater {
        collect(n.right.as_deref(), run, c, out);
    }
}

fn in_order<'a>(link: Option<&'a Node>, out: &mut Vec<(&'a [u8], RecordHash, u64)>) {
    if let Some(n) = link {
        in_order(n.left.as_deref(), out);
        out.push((&n.path, n.hash, n.counter));
        in_order(n.right.as_deref(), out);
    }
}

/// The two runs at or beneath `dir`, borrowed: no bound is built.
fn runs(dir: &str) -> [Run<'_>; 2] {
    [Run::At(dir.as_bytes()), Run::Beneath(dir.as_bytes())]
}

/// The held applied records, per device, by path with least counters.
#[derive(Clone, Default)]
pub(crate) struct ByPath {
    trees: BTreeMap<DeviceId, Box<Node>>,
    /// The queries the tests count: two per vector entry at most.
    #[cfg(test)]
    pub(crate) queries: core::cell::Cell<usize>,
    /// The nodes those queries visited, for the tests that bound them.
    #[cfg(test)]
    pub(crate) visited: core::cell::Cell<usize>,
}

/// The contents, in order: equal for equal records whatever the trees'
/// shapes, so that a rollback compares exactly.
impl fmt::Debug for ByPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for (d, root) in &self.trees {
            let mut all = Vec::new();
            in_order(Some(root), &mut all);
            let all: Vec<(String, RecordHash, u64)> = all
                .into_iter()
                .map(|(p, h, c)| (String::from_utf8_lossy(p).into_owned(), h, c))
                .collect();
            m.entry(d, &all);
        }
        m.finish()
    }
}

impl ByPath {
    /// Adds a held applied record of `device` at `path`.
    pub(crate) fn insert(&mut self, device: DeviceId, path: &[u8], hash: RecordHash, counter: u64) {
        let root = self.trees.remove(&device);
        self.trees.insert(device, insert(root, path, hash, counter));
    }

    /// Removes a record no longer held.
    pub(crate) fn remove(&mut self, device: &DeviceId, path: &[u8], hash: &RecordHash) {
        if let Some(root) = self.trees.remove(device) {
            if let Some(rest) = remove(Some(root), path, hash) {
                self.trees.insert(*device, rest);
            }
        }
    }

    /// Whether some record of `device` at or beneath `dir` has a counter of
    /// at most `c`: two queries. Counters are at most `MAX_COUNTER`, below
    /// `u64::MAX`, which stands for an empty run.
    pub(crate) fn any_at_most(&self, device: &DeviceId, dir: &str, c: u64) -> bool {
        let root = self.trees.get(device).map(|b| &**b);
        let c = c.min(u64::MAX - 1);
        runs(dir).into_iter().any(|run| {
            let mut seen = 0;
            let least = least_in(root, run, &mut seen);
            #[cfg(test)]
            {
                self.queries.set(self.queries.get() + 1);
                self.visited.set(self.visited.get() + seen);
            }
            let _ = seen;
            least <= c
        })
    }

    /// The records of `device` at or beneath `dir` whose counter is at most
    /// `c`.
    pub(crate) fn at_most(&self, device: &DeviceId, dir: &str, c: u64, out: &mut Vec<RecordHash>) {
        if let Some(root) = self.trees.get(device) {
            for run in runs(dir) {
                collect(Some(root), run, c, out);
            }
        }
    }

    /// Every entry, in order, for the tests that compare it with a walk.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> Vec<(DeviceId, String, RecordHash, u64)> {
        let mut out = Vec::new();
        for (d, root) in &self.trees {
            let mut all = Vec::new();
            in_order(Some(root), &mut all);
            out.extend(
                all.into_iter()
                    .map(|(p, h, c)| (*d, String::from_utf8_lossy(p).into_owned(), h, c)),
            );
        }
        out
    }

    /// The height of `device`'s tree, for the test of the AVL bound.
    #[cfg(test)]
    pub(crate) fn height(&self, device: &DeviceId) -> u8 {
        height(self.trees.get(device).map(|b| &**b))
    }
}
