// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The simulator's disk, as bases (`protocol.md` 4.4, "Bases"; 4.7 item 6).
//!
//! Phase 0 has no file system: a read or write holder's disk is, per path,
//! the version whose content it has put there, which is the record the
//! engine names to the index as that path's base. A version is **on the
//! disk** once every chunk it names is stored and has verified for it and
//! its size checked (a directory, a tombstone and an empty file at once),
//! and only then does the engine name it:
//!
//! - the path's first head in display order (its version, or the tombstone
//!   it was removed for) is the base of the path itself (`Place::Path`);
//! - each conflict copy is the base of a copy beside the path
//!   (`Place::Copy`), named by [`copy_name`], added once it is on the disk;
//!   a copy slot goes once its record is no longer a conflict copy;
//! - a path with no heads (a tree delete took its versions, or it is the
//!   tree delete's own directory) has one slot, its `Place::Path`: the
//!   greatest, by record hash, of the tree deletes held at its tag
//!   (`PathView::trees`), or none. It is a function of the records held, so
//!   every device that holds the same records keeps the same disk there,
//!   whatever order they came in; the files a tree delete removed go (phase
//!   1's archive), and every other path beneath it, a concurrent edit's say,
//!   keeps its disk. A path whose live records are all opaque is left as it
//!   is (4.4, "leaves the path on disk as it is": nothing this device cannot
//!   judge is removed). That is a stated residual (S3-A, for the owner's
//!   review, and a phase 1 question): such a path keeps whatever the disk
//!   had when its last readable record went, so two devices that held the
//!   same records in another order can differ there. The simulator's
//!   oracle needs no carve-out for it: its check (b) refuses opaque records
//!   in every gate scenario. A future scenario that plants them must make
//!   its check (b′) skip each path with no heads and an opaque record.
//!
//! The paths applied are those whose heads a record changed, those of the
//! base slots a local write cleared (`Written::paths`) and those still
//! arriving, never what else lies beneath a tree delete (TM-22).
//!
//! Until a version is on the disk the old one stays the base, so the file
//! there stays as it was (4.7 item 1), and a local write is built from that
//! old base: the version still arriving and the write are then both heads,
//! a conflict, never one written over the other (4.4, "Why it is safe" 9).
//! A path whose heads are not all on the disk stays in the folder's
//! `unapplied` set and is applied again as its chunks arrive. Writes need
//! none of this: the index makes each record it writes the base of its path.
//! A local write still applies the paths of the base slots it cleared
//! (`Written::paths`).

use std::collections::BTreeSet;

use licketysync_index::{Place, Txn};
use licketysync_keys::RecordHash;

use crate::chunks::ChunkBook;
use crate::issues::Counters;

/// The name of the conflict copy of `record` beside `path`: the path, then
/// ` (conflict ` and the first eight hex digits of the record hash, then
/// `)`. It is the copy's base slot, and the path its version gets when a
/// write over the conflict turns it into an ordinary file (4.4, "What
/// becomes of a conflict copy").
#[must_use]
pub(crate) fn copy_name(path: &str, record: &RecordHash) -> String {
    let [a, b, c, d, ..] = *record.as_bytes();
    format!("{path} (conflict {a:02x}{b:02x}{c:02x}{d:02x})")
}

/// Whether `record`'s content is on the disk: it names no chunk, or every
/// chunk it names is stored and has verified for it and its size checked
/// (`ChunkBook::ready`; a chunk stored for another record it fails for puts
/// nothing of this one in place).
fn on_disk(txn: &Txn<'_>, book: &ChunkBook, record: &RecordHash) -> bool {
    txn.index()
        .file(record)
        .is_none_or(|f| f.chunks.is_empty() || book.ready(record))
}

/// Names `path`'s bases from its heads (module documentation). Whether
/// every head is on the disk.
fn apply_path(txn: &mut Txn<'_>, book: &ChunkBook, path: &str, counters: &mut Counters) -> bool {
    #[cfg(test)]
    {
        counters.paths_applied += 1;
    }
    let Some(view) = txn.index().path(path) else {
        return true;
    };
    let bases = txn.index().bases(path);
    let mut set = |txn: &mut Txn<'_>, place: Place, record: Option<RecordHash>| {
        if txn.set_base(path, place, record).is_err() {
            counters.bug();
        }
    };
    if view.heads.is_empty() {
        if !view.opaque.is_empty() {
            // Its live records are all opaque: the disk there is left as it
            // is (4.4, "Heads, display order and conflicts").
            return true;
        }
        // A path with no heads: its one slot is the greatest tree delete
        // held there, or none, the same on every device that holds the
        // same records.
        let want = view.trees.last().copied();
        for (place, record) in &bases {
            if !(*place == Place::Path && Some(*record) == want) {
                set(txn, place.clone(), None);
            }
        }
        if let Some(tree) = want {
            if !bases.contains(&(Place::Path, tree)) {
                set(txn, Place::Path, Some(tree));
            }
        }
        return true;
    }
    let mut done = true;
    if let Some(first) = view.current.or_else(|| view.heads.first().map(|h| h.hash)) {
        if on_disk(txn, book, &first) {
            if !bases.contains(&(Place::Path, first)) {
                set(txn, Place::Path, Some(first));
            }
        } else {
            done = false;
        }
    }
    // A copy slot goes only once its record is no conflict copy any more,
    // whether or not its chunks are stored now (one forgotten after it
    // verified comes again); a new one is added only once its record is on
    // the disk.
    for (place, record) in &bases {
        if let Place::Copy(name) = place {
            if !view.conflict_copies.contains(record) || *name != copy_name(path, record) {
                set(txn, place.clone(), None);
            }
        }
    }
    for c in &view.conflict_copies {
        let place = Place::Copy(copy_name(path, c));
        if bases.contains(&(place.clone(), *c)) {
            continue;
        }
        if on_disk(txn, book, c) {
            set(txn, place, Some(*c));
        } else {
            done = false;
        }
    }
    done
}

/// Applies to the disk, in one handler's transaction, every path whose
/// heads changed (each record's `Accepted::paths` or `Written::paths`: a
/// tree delete's own directory and the paths where it dropped records among
/// them), the paths of the base slots a local write cleared (its
/// `Written::paths` too) and every path still arriving (module
/// documentation). What it reads is those paths, never what else lies
/// beneath a tree delete (TM-22).
pub(crate) fn apply(
    txn: &mut Txn<'_>,
    book: &ChunkBook,
    unapplied: &mut BTreeSet<String>,
    mut paths: BTreeSet<String>,
    counters: &mut Counters,
) {
    paths.extend(core::mem::take(unapplied));
    for path in paths {
        if !apply_path(txn, book, &path, counters) {
            unapplied.insert(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_is_named_after_its_path_and_record() {
        assert_eq!(
            copy_name("docs/a.txt", &RecordHash([0xab; 32])),
            "docs/a.txt (conflict abababab)"
        );
    }
}
