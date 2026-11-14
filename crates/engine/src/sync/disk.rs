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
//!   a copy slot goes once it no longer holds the copy it is for. Of the
//!   copies that share one name (two of one path kept whole, whose record
//!   hashes share their first four bytes), the first in display order has
//!   the slot, on every device alike. A copy with no slot has no place on
//!   the disk, and one that no name fits or whose name another has is
//!   counted (`copies_unplaced`): a write leaves it a head, and its own
//!   writer refuses to write the path (`WriteFailure::OwnVersionNotOnDisk`),
//!   as it does while any version of its own there is not on its disk.
//!   A tree delete of a directory above the path, by any device, covers a
//!   copy with no place once the delete's join reaches a later record of
//!   the copy's writer beneath that directory (4.4, "Why it is safe" 8a),
//!   and then it is gone from every device, none having had it on its disk;
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

use core::fmt::Write as _;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use licketysync_index::{Place, Txn};
use licketysync_keys::RecordHash;
use licketysync_protocol::limits::{MAX_NAME_BYTES, MAX_PATH_BYTES};

use crate::chunks::ChunkBook;
use crate::issues::{bump, Counters};

/// The bytes of the record hash a shortened copy name shows, as 32 hex
/// digits: copies of two records then share a shortened name only if their
/// hashes collide in 128 bits, about 2^64 hashes of work even for a key
/// holder grinding for it.
const SHORTENED_HASH_BYTES: usize = 16;

/// The name of the conflict copy of `record` beside `path` (4.4, "What
/// becomes of a conflict copy"): the path with ` (conflict `, the first four
/// bytes of the record hash in lowercase hex and `)` added. Where that would
/// pass `MAX_PATH_BYTES` in all or `MAX_NAME_BYTES` in its last component,
/// the name is **shortened**: the first [`SHORTENED_HASH_BYTES`] of the
/// hash go there instead, and the last component's stem (what comes before
/// its last `.`, or the whole component when it has none) is cut on a
/// character (Unicode scalar value) boundary until that component is at most
/// `MAX_NAME_BYTES` and shorter than the path's own, its extension kept, or
/// the whole component is cut when not one character of the stem fits beside
/// the extension.
///
/// It depends on the path and the record alone, so every device names a copy
/// alike. A copy's name is never its own path: kept whole it is longer,
/// shortened its last component is shorter. Each name ends in a suffix of
/// fixed length for its kind, 20 bytes kept whole or 44 shortened, whose
/// 20th byte from the end is a space in the first kind and a hex digit in
/// the second; so two equal names are of one kind and hold the same
/// directories, kept part and suffix. Kept whole, they are copies of one
/// path; shortened, their records share 16 bytes of hash. Records at two
/// paths are two records, so the copies of two paths share a name only if
/// two record hashes collide in 128 bits; two copies of one path kept whole
/// share one when their hashes share their first four bytes, and the first
/// in display order has its slot (`apply_path`). A `path` that
/// passes `check_path` gives a name that does, or `None` when not one
/// character of its last component fits: such a copy has no place on the
/// disk (module documentation). The name is the copy's base slot, and the
/// path its version gets when a write over the conflict turns it into an
/// ordinary file.
#[must_use]
pub(crate) fn copy_name(path: &str, record: &RecordHash) -> Option<String> {
    let hash = record.as_bytes();
    let short = suffix(hash, 4);
    let (dir, name) = path
        .rfind('/')
        .and_then(|i| path.split_at_checked(i + 1))
        .unwrap_or(("", path));
    let limit = MAX_NAME_BYTES.min(MAX_PATH_BYTES.checked_sub(dir.len())?);
    if name.len() + short.len() <= limit {
        return Some(format!("{path}{short}"));
    }
    let long = suffix(hash, SHORTENED_HASH_BYTES);
    let room = limit
        .min(name.len().saturating_sub(1))
        .checked_sub(long.len())?;
    let (stem, ext) = name
        .rfind('.')
        .and_then(|i| name.split_at_checked(i))
        .unwrap_or((name, ""));
    let (kept, ext) = match room.checked_sub(ext.len()).map(|r| prefix(stem, r)) {
        Some(cut) if !cut.is_empty() => (cut, ext),
        _ => (prefix(name, room), ""),
    };
    if kept.is_empty() {
        return None;
    }
    Some(format!("{dir}{kept}{ext}{long}"))
}

/// ` (conflict `, the first `bytes` bytes of `hash` in lowercase hex, `)`.
fn suffix(hash: &[u8; 32], bytes: usize) -> String {
    let mut out = String::from(" (conflict ");
    for byte in hash.iter().take(bytes) {
        // A write to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out.push(')');
    out
}

/// The longest prefix of `s` of at most `max` bytes that ends on a character
/// boundary.
fn prefix(s: &str, max: usize) -> &str {
    let end = (0..=max.min(s.len()))
        .rev()
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(0);
    s.get(..end).unwrap_or_default()
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
    // Each name's slot is for the first conflict copy in display order that
    // has the name, on every device alike. A copy that no name fits, or whose
    // name a copy before it has, has no place on the disk: no write covers
    // it (`crate::write`), and it is counted.
    let mut slots: BTreeMap<String, RecordHash> = BTreeMap::new();
    let mut unplaced = 0;
    for c in &view.conflict_copies {
        match copy_name(path, c).map(|name| slots.entry(name)) {
            Some(Entry::Vacant(slot)) => {
                slot.insert(*c);
            }
            _ => bump(&mut unplaced),
        }
    }
    // A copy slot goes only once it no longer holds the copy it is for,
    // whether or not that copy's chunks are stored now (one forgotten after
    // it verified comes again); a new one is added only once its copy is on
    // the disk.
    for (place, record) in &bases {
        if let Place::Copy(name) = place {
            if slots.get(name) != Some(record) {
                set(txn, place.clone(), None);
            }
        }
    }
    for (name, c) in &slots {
        let place = Place::Copy(name.clone());
        if bases.contains(&(place.clone(), *c)) {
            continue;
        }
        if on_disk(txn, book, c) {
            set(txn, place, Some(*c));
        } else {
            done = false;
        }
    }
    counters.copies_unplaced = counters.copies_unplaced.saturating_add(unplaced);
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use licketysync_protocol::record::check_path;
    use proptest::prelude::*;

    use super::*;

    const R: RecordHash = RecordHash([0xab; 32]);
    const TAG: &str = " (conflict abababab)";
    const LONG: &str = " (conflict abababababababababababababababab)";

    /// `copy_name` of `path` and [`R`].
    fn named(path: &str) -> Option<String> {
        copy_name(path, &R)
    }

    /// The record hash whose first bytes are `head`, the rest zero.
    fn hash(head: &[u8]) -> RecordHash {
        let mut h = [0u8; 32];
        h[..head.len()].copy_from_slice(head);
        RecordHash(h)
    }

    /// A directory of `n` bytes, its `/` included: one component of `d`s.
    fn dir(n: usize) -> String {
        if n == 0 {
            return String::new();
        }
        format!("{}/", "d".repeat(n - 1))
    }

    #[test]
    fn a_copy_is_named_after_its_path_and_record() {
        assert_eq!(
            named("docs/a.txt").as_deref(),
            Some("docs/a.txt (conflict abababab)")
        );
        let h = hash(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD]);
        assert_eq!(
            copy_name("a", &h).as_deref(),
            Some("a (conflict 01234567)"),
            "the first four bytes of the hash, in order, in lowercase"
        );
        assert_eq!(
            named(".bashrc").as_deref(),
            Some(".bashrc (conflict abababab)"),
            "a name that fits is kept whole, a leading dot too"
        );
        assert_eq!(
            copy_name(&format!("{}.txt", "n".repeat(300)), &h),
            Some(format!(
                "{}.txt (conflict 0123456789abcd000000000000000000)",
                "n".repeat(207)
            )),
            "a shortened name: the first 16 bytes of the hash, in lowercase"
        );
    }

    #[test]
    fn a_long_last_component_is_cut_to_255_bytes_keeping_its_extension() {
        let fits = format!("{}.txt", "n".repeat(231));
        assert_eq!(
            named(&format!("docs/{fits}")),
            Some(format!("docs/{fits}{TAG}")),
            "255 bytes with the tag: kept whole"
        );
        let over = format!("docs/{}.txt", "n".repeat(300));
        let want = format!("docs/{}.txt{LONG}", "n".repeat(207));
        assert_eq!(named(&over), Some(want.clone()));
        assert_eq!(want.len() - "docs/".len(), MAX_NAME_BYTES);
        assert_eq!(
            named(&format!("docs/{}.txt", "n".repeat(232))),
            Some(format!("docs/{}.txt{LONG}", "n".repeat(187))),
            "236 bytes: shortened to 235, one byte shorter than the name"
        );
        assert_eq!(
            named(&format!("docs/{}.tar.gz", "n".repeat(600))),
            Some(format!("docs/{}.gz{LONG}", "n".repeat(208))),
            "the extension is what follows the last dot"
        );
    }

    #[test]
    fn a_path_of_4077_bytes_or_more_gets_a_copy_name_shorter_than_itself() {
        let name = format!("{}.txt", "r".repeat(96));
        let at = |len: usize| format!("{}{name}", dir(len - name.len()));
        assert_eq!(
            named(&at(4_076)),
            Some(format!("{}{TAG}", at(4_076))),
            "4 096 bytes with the tag: kept whole"
        );
        for len in [4_077, 4_096] {
            let copy = named(&at(len)).unwrap();
            let want = format!("{}{}.txt{LONG}", dir(len - 100), "r".repeat(51));
            assert_eq!(copy, want, "{len}");
            assert_eq!(copy.len(), len - 1, "{len}");
        }
    }

    #[test]
    fn a_copy_name_is_never_its_own_path() {
        // Kept whole, the name is the path and 20 bytes more; shortened, its
        // last component is shorter than the path's, even for a name that
        // already ends as its own shortened copy name does.
        let tagged = format!("docs/{}.txt{LONG}", "n".repeat(207));
        for path in [
            "docs/a.txt".to_owned(),
            format!("docs/{}.txt", "n".repeat(232)),
            tagged,
        ] {
            let copy = named(&path).unwrap();
            assert_ne!(copy, path);
            let last = |p: &str| p.rsplit('/').next().unwrap().len();
            assert!(
                copy.len() > path.len() || last(&copy) < last(&path),
                "{copy}"
            );
        }
    }

    #[test]
    fn a_cut_falls_on_a_character_boundary() {
        // 208 bytes of stem fit beside `.md` and the suffix, 207 beside
        // `.txt`: é is 2 bytes, € 3 and 😀 4.
        for (c, ext, n) in [("é", ".txt", 103), ("€", ".md", 69), ("😀", ".txt", 51)] {
            let path = format!("{}{ext}", c.repeat(300));
            let want = format!("{}{ext}{LONG}", c.repeat(n));
            assert_eq!(named(&path), Some(want), "{c}");
        }
        assert_eq!(
            named(&format!("a{}.md", "😀".repeat(80))),
            Some(format!("a{}.md{LONG}", "😀".repeat(51))),
            "1 + 4 × 51 = 205 of the 208 bytes beside `.md`"
        );
        // A name of 50 bytes: its copy's last component is at most 49, five
        // bytes beside the suffix.
        let path = format!("{}{}.txt", dir(4_027), "é".repeat(23));
        assert_eq!(
            named(&path),
            Some(format!("{}éé{LONG}", dir(4_027))),
            "one byte is left for the stem beside `.txt`, half an é, so the whole name is cut, \
             to two é"
        );
    }

    #[test]
    fn an_extension_with_no_room_beside_it_is_cut_with_the_name() {
        assert_eq!(
            named(&format!("a.{}", "x".repeat(300))),
            Some(format!("a.{}{LONG}", "x".repeat(209)))
        );
        assert_eq!(
            named(&format!(".{}", "b".repeat(300))),
            Some(format!(".{}{LONG}", "b".repeat(210))),
            "a leading dot begins a stem of nothing"
        );
        assert_eq!(
            named(&"b".repeat(300)),
            Some(format!("{}{LONG}", "b".repeat(211))),
            "a name with no dot is all stem"
        );
    }

    #[test]
    fn no_copy_is_named_where_not_one_character_of_its_name_fits() {
        assert_eq!(
            named(&format!("{}f", dir(4_075))),
            Some(format!("{}f{TAG}", dir(4_075)))
        );
        assert_eq!(named(&format!("{}f", dir(4_076))), None, "no room");
        assert_eq!(named(&format!("{}fg", dir(4_077))), None, "less than none");
        assert_eq!(named(&format!("{}é", dir(4_074))).unwrap().len(), 4_096);
        assert_eq!(named(&format!("{}é", dir(4_075))), None, "half an é");
        let path = format!("{}{}", dir(4_051), "n".repeat(60));
        assert_eq!(
            named(&path),
            Some(format!("{}n{LONG}", dir(4_051))),
            "one character beside the suffix"
        );
        let path = format!("{}{}", dir(4_052), "n".repeat(60));
        assert_eq!(named(&path), None, "none beside the suffix");
        let path = format!("{}{}", dir(4_036), "n".repeat(46));
        assert_eq!(
            named(&path),
            Some(format!("{}n{LONG}", dir(4_036))),
            "46 bytes that do not fit whole: one character, 45 bytes"
        );
        let path = format!("{}{}", dir(4_036), "n".repeat(45));
        assert_eq!(
            named(&path),
            None,
            "45 bytes that do not fit whole: a shortened name would be no shorter"
        );
        assert_eq!(
            named(&format!("{}d", "d/".repeat(2_047))),
            None,
            "two bytes beside 2 047 directories"
        );
    }

    #[test]
    fn two_paths_never_share_a_copy_name() {
        // Two long names in one directory that keep the same part when
        // shortened, with records whose first four bytes match, differ in
        // the rest of the 16; and a shortened name differs from the whole
        // name of the path that is its kept part.
        let a = format!("docs/{}a.txt", "n".repeat(300));
        let b = format!("docs/{}b.txt", "n".repeat(300));
        let kept = format!("docs/{}.txt", "n".repeat(207));
        let (ra, rb) = (hash(&[1, 2, 3, 4, 5]), hash(&[1, 2, 3, 4, 6]));
        let (na, nb, nk) = (
            copy_name(&a, &ra).unwrap(),
            copy_name(&b, &rb).unwrap(),
            copy_name(&kept, &ra).unwrap(),
        );
        assert_ne!(na, nb);
        assert_ne!(na, nk);
        assert_ne!(nb, nk);
        assert!(na.starts_with(&kept) && nb.starts_with(&kept), "{na} {nb}");
        assert_eq!(nk, format!("{kept} (conflict 01020304)"), "kept whole");
    }

    proptest! {
        #![proptest_config(crate::testkit::proptest_config(1_024))]

        /// For every path in the grammar, the copy's name is in it too,
        /// beside the same directories, its last component within
        /// `MAX_NAME_BYTES`: the name and the record's short suffix when
        /// they fit, else a shortened name, shorter than the name, cut only
        /// as far as it must be, to a prefix of the name or of its stem
        /// before the name's extension, with 16 bytes of the record hash in
        /// its suffix. It is never the path. There is no name only when
        /// neither fits. A longer name in the same directory, whose record's
        /// hash shares its first four bytes, never gets the same copy name.
        #[test]
        fn every_copy_name_passes_check_path(
            dir_bytes in prop_oneof![0usize..=4_100, 4_000usize..=4_100],
            odd in any::<bool>(),
            name in prop_oneof!["[a.é€😀 ()_-]{1,300}", "[a.é€😀]{1,60}"],
            more in "[a.é]{1,4}",
            record in any::<[u8; 32]>(),
        ) {
            let k = dir_bytes.min(MAX_PATH_BYTES - name.len() - more.len()) / 2;
            let pad = if odd && k > 1 { "e" } else { "" };
            let dir = format!("{pad}{}", "d/".repeat(k.saturating_sub(pad.len())));
            let path = format!("{dir}{name}");
            prop_assume!(check_path(&path).is_ok());
            let mut neighbour = record;
            neighbour[31] ^= 1;
            neighbour[4] ^= 1;
            let (record, neighbour) = (RecordHash(record), RecordHash(neighbour));
            let short = suffix(record.as_bytes(), 4);
            let long = suffix(record.as_bytes(), 16);
            let limit = MAX_NAME_BYTES.min(MAX_PATH_BYTES - dir.len());
            let bound = limit.min(name.len() - 1);
            let first = name.chars().next().unwrap().len_utf8();
            let copy = copy_name(&path, &record);
            let other = format!("{path}{more}");
            if check_path(&other).is_ok() {
                if let (Some(x), Some(y)) = (&copy, copy_name(&other, &neighbour)) {
                    prop_assert_ne!(x, &y);
                }
            }
            match &copy {
                None => prop_assert!(
                    name.len() + short.len() > limit && bound < long.len() + first,
                    "{path:?}"
                ),
                Some(copy) => {
                    prop_assert_ne!(copy, &path);
                    prop_assert_eq!(check_path(copy), Ok(()));
                    let component = copy.strip_prefix(&dir).unwrap();
                    prop_assert!(!component.contains('/'));
                    prop_assert!(component.len() <= MAX_NAME_BYTES);
                    if name.len() + short.len() <= limit {
                        prop_assert_eq!(copy, &format!("{path}{short}"));
                    } else {
                        let kept = component.strip_suffix(&long).unwrap();
                        prop_assert!(component.len() < name.len());
                        let unused = bound - component.len();
                        prop_assert!(unused < 4, "{} unused", unused);
                        let (stem, ext) = name
                            .rfind('.')
                            .map_or((name.as_str(), ""), |i| name.split_at(i));
                        let in_stem = kept
                            .strip_suffix(ext)
                            .is_some_and(|s| !s.is_empty() && stem.starts_with(s));
                        prop_assert!(in_stem || name.starts_with(kept), "{kept:?}");
                    }
                }
            }
        }
    }
}
