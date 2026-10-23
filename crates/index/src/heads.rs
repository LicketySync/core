// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The heads of one path and what they mean (`protocol.md` 4.4, "Versions
//! and heads"): the display order, the version at the path, deletion, and
//! which heads become conflict copies.
//!
//! A **version** of a path is an applied record that is not waiting and whose
//! sealed path is that path; its **heads** are the versions no applied,
//! non-waiting record supersedes. One head is the path's current version, or
//! its deletion when it is a tombstone; two or more are a conflict, and every
//! head stays until a write names it. The order below is a deterministic
//! tie-break among heads that are all kept, never an ordering of versions:
//! which versions are heads follows from `supersedes` alone (TM-40).
//!
//! The index keeps each path's heads sorted in display order, so the version
//! at a path and the first heads a write names cost a lookup, however many
//! heads a path has.

use std::collections::{BTreeMap, BTreeSet};

use core::cmp::Reverse;

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::RecordHash;
use licketysync_protocol::record::{Kind, Meta, Record};

use crate::index::{Entry, Kept};

/// A head's place in display order (`protocol.md` 4.4): heads that are not
/// tombstones first, directories before files among them, and tombstones
/// last, whose kind is not compared; then, within each of those groups, the
/// greater `mtime_ns` first; then the smaller record hash first. Record
/// hashes differ, so the order is total. The modification time is only
/// compared, never subtracted (TM-40).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rank {
    tombstone: bool,
    /// A file that is not a tombstone (directories sort first); false for
    /// every tombstone, since the kind orders only the heads that are not.
    file: bool,
    newer: Reverse<i64>,
    pub(crate) hash: RecordHash,
}

impl Rank {
    pub(crate) fn of(hash: RecordHash, record: &Record, meta: &Meta) -> Self {
        Self {
            tombstone: record.deleted(),
            file: !record.deleted() && meta.kind != Kind::Directory,
            newer: Reverse(meta.mtime_ns),
            hash,
        }
    }
}

/// One head of a path: an applied, non-waiting record no such record
/// supersedes, with its opened metadata.
#[derive(Clone, Copy, Debug)]
pub struct Version<'a> {
    hash: RecordHash,
    record: &'a Record,
    meta: &'a Meta,
}

impl<'a> Version<'a> {
    /// The record hash: what a later write names in `supersedes`.
    #[must_use]
    pub fn hash(&self) -> RecordHash {
        self.hash
    }

    /// The record, as received.
    #[must_use]
    pub fn record(&self) -> &'a Record {
        self.record
    }

    /// The opened metadata.
    #[must_use]
    pub fn meta(&self) -> &'a Meta {
        self.meta
    }

    /// Whether the version is a tombstone (the path deleted).
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.record.deleted()
    }
}

/// Whether two versions' content differs (`protocol.md` 4.4): when their
/// kinds differ or, between two files, when their `plain_hashes` lists
/// differ. Two directories never differ, nor do two files with the same
/// `plain_hashes`, whatever their times or modes. The hashes are keyed, so
/// they are compared in constant time and without stopping at the first
/// difference; their count is public (sealed peers see the chunk count).
#[must_use]
pub fn content_differs(a: &Meta, b: &Meta) -> bool {
    a.kind != b.kind || (a.kind == Kind::File && !same_hashes(&a.plain_hashes, &b.plain_hashes))
}

fn same_hashes(a: &[PlainHash], b: &[PlainHash]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .fold(true, |same, (x, y)| same & bool::from(x.ct_eq(y)))
}

/// The heads of one path, in display order; empty for a path with none
/// (never written, renamed away, or not computed: sealed holders compute no
/// heads). A view into the index, read without sorting or copying.
#[derive(Clone, Copy, Debug)]
pub struct Heads<'a> {
    ranks: Option<&'a BTreeSet<Rank>>,
    entries: &'a BTreeMap<RecordHash, Entry>,
}

impl<'a> Heads<'a> {
    pub(crate) fn new(
        ranks: Option<&'a BTreeSet<Rank>>,
        entries: &'a BTreeMap<RecordHash, Entry>,
    ) -> Self {
        Self { ranks, entries }
    }

    /// Every head, in display order.
    pub fn versions(&self) -> impl Iterator<Item = Version<'a>> + 'a {
        let entries = self.entries;
        self.ranks
            .into_iter()
            .flatten()
            .filter_map(move |rank| match entries.get(&rank.hash)? {
                Entry {
                    record,
                    kept: Kept::Applied(meta),
                } => Some(Version {
                    hash: rank.hash,
                    record,
                    meta,
                }),
                Entry { .. } => None,
            })
    }

    /// The number of heads.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ranks.map_or(0, BTreeSet::len)
    }

    /// Whether the path has no head.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The first head in display order, tombstone or not.
    #[must_use]
    pub fn first(&self) -> Option<Version<'a>> {
        self.versions().next()
    }

    /// The version at the path: the first head in display order, unless it
    /// is a tombstone, in which case every head is one and the path is
    /// deleted.
    #[must_use]
    pub fn current(&self) -> Option<Version<'a>> {
        self.first().filter(|v| !v.is_tombstone())
    }

    /// Whether the path is deleted: it has heads and all are tombstones.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.first().is_some_and(|v| v.is_tombstone())
    }

    /// Whether the path is in conflict: two or more heads, every one kept
    /// until a write names them.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        self.len() >= 2
    }

    /// The heads that become conflict copies, in display order: every head
    /// after the first that is not a tombstone and whose content differs from
    /// the first's (TM-40). So a file beside a tombstone makes no copy (an
    /// edit beats a delete), a file beside a directory is copied, and
    /// identical files or two directories make none. Writing them to disk is
    /// the engine's (phase 1).
    pub fn conflict_copies(&self) -> impl Iterator<Item = Version<'a>> + 'a {
        let first = self.current();
        self.versions().skip(1).filter(move |v| {
            !v.is_tombstone() && first.is_some_and(|f| content_differs(f.meta, v.meta))
        })
    }
}
