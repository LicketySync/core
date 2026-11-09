// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Concurrent heads with identical content, **twins** (the identical-heads
//! bug of 2026-11-08). `protocol.md` 4.4 shows two heads whose content does
//! not differ as one file with no conflict copy, and section 9 ("Two devices
//! create the same file independently") says the next save covers both. The
//! engine names one base per path, the first head in display order (4.4,
//! "Bases"), and `S` was built from the bases alone, so a write over the path
//! covered only that one, and the other head stayed live on every device:
//! after an edit as a conflict copy of the old content, after a delete or a
//! rename as the file at the path, after a tree delete as the directory,
//! after a new version over two tombstones as a second head. `S`, and a tree
//! delete's join, now hold the bases' twins too (4.4, "The vector and names
//! of a new record"), whose content is on the disk as much as a base's ("Why
//! it is safe" 9).
//!
//! Each test here makes the twins at the record level, applies them to every
//! device's disk as the engine does (`Dev::apply`), then writes over the path
//! and checks that nothing of the old content is left; the variants are the
//! editing device (its own head at the path, or the other's), equal and
//! different `mtime_ns`, three devices, a delete, a rename, two identical
//! directories under a tree delete, and two tombstones under a new version.
//! The first eight failed on `main` before the fix, every one on every
//! editor. Then more twins than `S` has places: 40, of which one write
//! covers 32 (the bases first, then the twins, its own records first within
//! each, then display order) and the next write the rest, under a save, a
//! delete and a tree delete, whose names at its own path its vector covers;
//! a tree delete whose pruned vector misses a twin, and the tombstone after
//! it; a tree delete, which is no one's twin; and the vector of `heads.json`
//! ([`twins_vector`]).
//!
//! Then what a twin is not, and what the reviews of the fix found (round 1,
//! 2026-11-08, and the confirm review): a later version of a base with its
//! content (a mode change still arriving) and a concurrent record of it the
//! engine has yet to put at the path stay conflicts, the latter whether the
//! base is still the first head, was replaced by a later version still
//! arriving (under an edit and under a tree delete) or is a conflict copy's
//! base; records under the writer's own ID cannot push
//! the base out of `S`; a twin arriving after the write and a tombstone
//! beside a live base stay heads; a directory with 64 or more conflict
//! copies at its path can be deleted; and a folder delete takes a file
//! beneath it still arriving, through a twin's dot or a base's (the owner's
//! decision of 2026-11-08, "Why it is safe" 8(a)).

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, RecordHash};
use licketysync_protocol::limits::{MAX_REPLACES, MAX_VECTOR_ENTRIES};
use licketysync_protocol::record::{Dot, Meta};
use serde_json::{json, Value};

use super::kit::{dir, file, Dev};
use super::vectors::h;
use crate::{Change, PathView};

/// `mtimes.len()` write holders, each writing `path` with the same content
/// (`file(path, 1, _)`: one chunk, one plaintext hash) apart from the
/// others, the `i`th with `mtime_ns` `mtimes[i]`; then each takes every
/// other's record and applies the path to its disk. The devices and their
/// records, in device order. Every device shows every record as a head and
/// makes no conflict copy (checked).
fn twins(path: &str, mtimes: &[i64]) -> (Vec<Dev>, Vec<RecordHash>) {
    let mut devs: Vec<Dev> = (0..mtimes.len())
        .map(|i| Dev::writer(0xa0 + u8::try_from(i).unwrap()))
        .collect();
    let mut recs = Vec::new();
    for (d, m) in devs.iter_mut().zip(mtimes) {
        // `put` steps the device's mtime by 1 000 first.
        d.mtime = *m - 1_000;
        recs.push(d.put(path, 1));
    }
    share(&mut devs, &recs, path);
    for d in &devs {
        let v = view(d, path);
        assert_eq!(v.heads.len(), devs.len(), "every twin is a head");
        assert!(v.conflict_copies.is_empty(), "identical content: no copy");
    }
    (devs, recs)
}

/// As [`twins`], with two identical directories at `path`.
fn twin_dirs(path: &str) -> (Vec<Dev>, Vec<RecordHash>) {
    let mut devs = vec![Dev::writer(0xa0), Dev::writer(0xa1)];
    let mut recs = Vec::new();
    for d in &mut devs {
        recs.push(d.write(&[Change::Put(dir(path, 5_000))]).unwrap().records[0].0);
    }
    share(&mut devs, &recs, path);
    for d in &devs {
        assert_eq!(view(d, path).heads.len(), 2, "both directories are heads");
    }
    (devs, recs)
}

/// Every device takes every other's record of `recs` (in device order) and
/// applies `path` to its disk.
fn share(devs: &mut [Dev], recs: &[RecordHash], path: &str) {
    let signed: Vec<(DeviceId, SignedRecord)> = devs
        .iter()
        .zip(recs)
        .map(|(d, h)| (d.id(), d.signed(h).clone()))
        .collect();
    for (i, d) in devs.iter_mut().enumerate() {
        for (j, (from, s)) in signed.iter().enumerate() {
            if i != j {
                d.accept_from(*from, s).unwrap();
            }
        }
        d.apply(path);
    }
}

fn view(d: &Dev, path: &str) -> PathView {
    d.ix.path(path).unwrap()
}

/// The index, in `recs`, of the head that sits at `path` on every device
/// (the first in display order, the same everywhere).
fn at_the_path(devs: &[Dev], recs: &[RecordHash], path: &str) -> usize {
    let first = view(&devs[0], path).heads[0].hash;
    for d in devs {
        assert_eq!(view(d, path).heads[0].hash, first, "one display order");
    }
    recs.iter().position(|h| *h == first).unwrap()
}

/// Every device but `editor` takes the records `editor` wrote and applies
/// `paths`.
fn spread(devs: &mut [Dev], editor: usize, written: &[RecordHash], paths: &[&str]) {
    let from = devs[editor].id();
    let signed: Vec<SignedRecord> = written
        .iter()
        .map(|h| devs[editor].signed(h).clone())
        .collect();
    for (i, d) in devs.iter_mut().enumerate() {
        if i == editor {
            continue;
        }
        for s in &signed {
            d.accept_from(from, s).unwrap();
        }
        for p in paths {
            d.apply(p);
        }
    }
}

/// What each device shows at `path`, naming each head by who wrote it:
/// `twin <i>` for `recs[i]`, `the change` for `change`.
fn shown(devs: &[Dev], recs: &[RecordHash], change: RecordHash, path: &str) -> String {
    let name = |h: &RecordHash| {
        if *h == change {
            "the change".to_owned()
        } else if let Some(i) = recs.iter().position(|r| r == h) {
            format!("twin {i}")
        } else {
            format!("{h}")
        }
    };
    devs.iter()
        .enumerate()
        .map(|(i, d)| {
            let heads: Vec<String> = d.heads(path).iter().map(name).collect();
            let copies: Vec<String> = copies(d, path).iter().map(name).collect();
            format!("device {i}: heads {heads:?}, conflict copies {copies:?}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn copies(d: &Dev, path: &str) -> Vec<RecordHash> {
    d.ix.path(path)
        .map(|v| v.conflict_copies)
        .unwrap_or_default()
}

/// `None` when every device shows `want` alone at `path` (the change, or no
/// head at all after a tree delete) and no conflict copy; otherwise what
/// each device shows there.
fn left_over(
    devs: &[Dev],
    recs: &[RecordHash],
    change: RecordHash,
    path: &str,
    want: &[RecordHash],
) -> Option<String> {
    let clean = devs
        .iter()
        .all(|d| d.heads(path) == want && copies(d, path).is_empty());
    (!clean).then(|| shown(devs, recs, change, path))
}

/// No case, each made by the editor it names, left anything of the old
/// content; otherwise every case that did, and what it left.
fn assert_clean(what: &str, cases: impl IntoIterator<Item = (usize, Option<String>)>) {
    let failures: Vec<String> = cases
        .into_iter()
        .filter_map(|(editor, f)| f.map(|f| format!("device {editor} changing: {f}")))
        .collect();
    assert!(
        failures.is_empty(),
        "{what} over identical heads left the old content:\n{}",
        failures.join("\n")
    );
}

/// An edit over twins of `mtimes` by device `editor`: what it left.
fn edit(mtimes: &[i64], editor: usize) -> Option<String> {
    let (mut devs, recs) = twins("p", mtimes);
    let w = devs[editor].put("p", 2);
    spread(&mut devs, editor, &[w], &["p"]);
    left_over(&devs, &recs, w, "p", &[w])
}

#[test]
fn identical_concurrent_heads_next_save_covers_both() {
    // Equal mtime_ns: the smaller record hash sits at the path; the device
    // that wrote it edits, its own head its base. The fixtures are
    // deterministic, so the twins `edit` makes again are these records.
    let (devs, recs) = twins("p", &[2_000, 2_000]);
    let first = at_the_path(&devs, &recs, "p");
    assert_clean("a save", [(first, edit(&[2_000, 2_000], first))]);
}

#[test]
fn identical_concurrent_heads_a_save_where_the_other_twin_sits_at_the_path_covers_both() {
    // The device whose own head is not at the path edits: its base is the
    // other's record (the same records again, as above).
    let (devs, recs) = twins("p", &[2_000, 2_000]);
    let other = 1 - at_the_path(&devs, &recs, "p");
    assert_clean("a save", [(other, edit(&[2_000, 2_000], other))]);
}

#[test]
fn identical_concurrent_heads_with_different_mtimes_next_save_covers_both() {
    // Device 1's later mtime_ns puts its head at the path everywhere; each
    // device edits in turn.
    let (devs, recs) = twins("p", &[2_000, 9_000]);
    assert_eq!(at_the_path(&devs, &recs, "p"), 1, "the later twin first");
    assert_clean(
        "a save",
        [0, 1].map(|editor| (editor, edit(&[2_000, 9_000], editor))),
    );
}

#[test]
fn three_identical_concurrent_heads_next_save_covers_all_three() {
    assert_clean(
        "a save",
        [0, 1, 2].map(|editor| (editor, edit(&[2_000, 2_000, 2_000], editor))),
    );
}

#[test]
fn identical_concurrent_heads_next_delete_covers_both() {
    let delete = |editor: usize| {
        let (mut devs, recs) = twins("p", &[2_000, 2_000]);
        let t = devs[editor].delete("p");
        spread(&mut devs, editor, &[t], &["p"]);
        let file_back = devs.iter().any(|d| !view(d, "p").deleted);
        left_over(&devs, &recs, t, "p", &[t]).map(|f| {
            if file_back {
                format!("the path is not deleted: {f}")
            } else {
                f
            }
        })
    };
    assert_clean("a delete", [0, 1].map(|editor| (editor, delete(editor))));
}

#[test]
fn identical_concurrent_heads_a_rename_leaves_nothing_at_the_old_path() {
    let rename = |editor: usize| {
        let (mut devs, recs) = twins("p", &[2_000, 2_000]);
        let written = devs[editor].rename("p", "q");
        let hashes: Vec<RecordHash> = written.records.iter().map(|(h, _)| *h).collect();
        let (moved, tomb) = (hashes[0], hashes[1]);
        spread(&mut devs, editor, &hashes, &["p", "q"]);
        assert!(
            devs.iter().all(|d| d.heads("q") == [moved]),
            "one version at the new path"
        );
        left_over(&devs, &recs, tomb, "p", &[tomb])
    };
    assert_clean("a rename", [0, 1].map(|editor| (editor, rename(editor))));
}

#[test]
fn identical_concurrent_directories_a_tree_delete_covers_both() {
    let tree_delete = |editor: usize| {
        let (mut devs, recs) = twin_dirs("d");
        let written = devs[editor].tree_delete("d");
        let hashes: Vec<RecordHash> = written.records.iter().map(|(h, _)| *h).collect();
        spread(&mut devs, editor, &hashes, &["d"]);
        left_over(&devs, &recs, hashes[0], "d", &[])
    };
    assert_clean(
        "a tree delete",
        [0, 1].map(|editor| (editor, tree_delete(editor))),
    );
}

#[test]
fn identical_concurrent_tombstones_a_save_covers_both() {
    // Two devices delete one file they both had on their disks, apart: two
    // tombstones, the path deleted, one tombstone its base and the other its
    // twin. A new version written there covers both; before the fix it
    // covered only the base, and the other tombstone stayed a head beside
    // it: no copy and nothing shown (a tombstone is never one), but a
    // second head, a conflict to whatever counts heads, until it expired.
    let recreate = |editor: usize| {
        let mut devs = vec![Dev::writer(0xa0), Dev::writer(0xa1)];
        let v0 = devs[0].put("p", 1);
        let first = devs[0].signed(&v0).clone();
        let from = devs[0].id();
        devs[1].accept_from(from, &first).unwrap();
        devs[1].apply("p");
        let mut recs = Vec::new();
        for d in &mut devs {
            d.mtime = 4_000;
            recs.push(d.delete("p"));
        }
        share(&mut devs, &recs, "p");
        for d in &devs {
            let v = view(d, "p");
            assert!(v.deleted && v.heads.len() == 2, "two tombstones");
        }
        let w = devs[editor].put("p", 3);
        spread(&mut devs, editor, &[w], &["p"]);
        left_over(&devs, &recs, w, "p", &[w])
    };
    assert_clean("a save", [0, 1].map(|editor| (editor, recreate(editor))));
}

/// What `record`, a record `d` holds, names in its `replaces`: ascending,
/// as a record lists them.
fn names(d: &Dev, record: &RecordHash) -> Vec<RecordHash> {
    d.ix.s.held[record].record.replaces().to_vec()
}

/// `v` ascending, as a record lists its names.
fn sorted(mut v: Vec<RecordHash>) -> Vec<RecordHash> {
    v.sort_unstable();
    v
}

/// Hex of each record hash, in order.
fn hashes(v: &[RecordHash]) -> Value {
    Value::Array(v.iter().map(|x| h(&x.0)).collect())
}

/// More twins than `S` has places: 40 write holders write `p` with the same
/// content apart, the `i`th at `mtime_ns` 10 000 + 1 000 `i`, so that the
/// 39th's sits at the path and the 0th's is the last in display order; with
/// `copy`, a 41st writes other content at the earliest `mtime_ns`, a conflict
/// copy. Device 0 takes every other record and applies the path: its bases
/// are the 39th's twin (at the path) and the copy, and its own twin is one of
/// the 39 twins of the one at the path. The devices and their records, in
/// device order.
fn forty(copy: bool) -> (Vec<Dev>, Vec<RecordHash>) {
    let n: u8 = if copy { 41 } else { 40 };
    let mut devs: Vec<Dev> = (0..n).map(|i| Dev::writer(0x40 + i)).collect();
    let mut recs = Vec::new();
    for (i, d) in (0i64..).zip(devs.iter_mut()) {
        // `put` steps the device's mtime by 1 000 first.
        if i == 40 {
            d.mtime = 0;
            recs.push(d.put("p", 2));
        } else {
            d.mtime = 9_000 + 1_000 * i;
            recs.push(d.put("p", 1));
        }
    }
    let signed: Vec<(DeviceId, SignedRecord)> = devs
        .iter()
        .zip(&recs)
        .map(|(d, h)| (d.id(), d.signed(h).clone()))
        .collect();
    for (from, s) in &signed[1..] {
        devs[0].accept_from(*from, s).unwrap();
    }
    devs[0].apply("p");
    let v = view(&devs[0], "p");
    assert_eq!(v.heads.len(), usize::from(n), "every record a head");
    assert_eq!(v.current, Some(recs[39]), "the 39th's twin at the path");
    let copies: &[RecordHash] = if copy { &recs[40..] } else { &[] };
    assert_eq!(v.conflict_copies, copies, "twins make no copy");
    (devs, recs)
}

/// A read holder given every record of `devs` (`recs`, in device order) and
/// then `then`, written by device 0: the heads it shows at `p`.
fn on_a_reader(devs: &[Dev], recs: &[RecordHash], then: &[RecordHash]) -> Vec<RecordHash> {
    let mut r = Dev::reader(0x90);
    for (d, h) in devs.iter().zip(recs) {
        r.accept_from(d.id(), d.signed(h)).unwrap();
    }
    for h in then {
        r.accept_from(devs[0].id(), devs[0].signed(h)).unwrap();
    }
    r.heads("p")
}

/// 40 twins and a copy under one save by device 0 (whose own twin is the
/// last in display order): `S` takes its two bases (the twin at the path,
/// then the copy, in display order), then its own twin, then the other twins
/// in display order, 32 in all; the nine twins left are heads beside the
/// save, conflict copies of the old content, until the next save, made with
/// them on the disk, covers them. What it shows, for `heads.json`.
fn forty_twins_under_a_save() -> Value {
    let (mut devs, recs) = forty(true);
    let copy = recs[40];
    assert_eq!(
        devs[0].ix.bases("p").len(),
        2,
        "the twin at the path, the copy"
    );
    devs[0].mtime = 1_000_000;
    let w = devs[0].put("p", 3);
    let mut s = vec![recs[39], copy, recs[0]];
    s.extend((10..39).rev().map(|i| recs[i]));
    assert_eq!(s.len(), MAX_VECTOR_ENTRIES);
    assert_eq!(names(&devs[0], &w), sorted(s.clone()), "bases, own, twins");
    let left: Vec<RecordHash> = (1..10).rev().map(|i| recs[i]).collect();
    let mut heads = vec![w];
    heads.extend(&left);
    assert_eq!(devs[0].heads("p"), heads, "the save and the nine left");
    assert_eq!(view(&devs[0], "p").conflict_copies, left);
    assert_eq!(on_a_reader(&devs, &recs, &[w]), heads);
    devs[0].apply("p");
    let w2 = devs[0].put("p", 4);
    assert_eq!(
        devs[0].heads("p"),
        vec![w2],
        "the next save covers the rest"
    );
    assert_eq!(on_a_reader(&devs, &recs, &[w, w2]), vec![w2]);
    json!({
        "name": "40-twins-and-a-copy-under-a-save",
        "s": hashes(&s),
        "heads": hashes(&heads),
        "after_the_next_save": hashes(&[w2]),
    })
}

#[test]
fn forty_identical_heads_a_save_covers_its_own_its_bases_then_the_first_twins_up_to_32() {
    forty_twins_under_a_save();
}

#[test]
fn forty_identical_heads_a_delete_covers_32_and_the_file_is_back_until_the_next_delete() {
    let (mut devs, recs) = forty(false);
    let t = devs[0].delete("p");
    let mut s = vec![recs[39], recs[0]];
    s.extend((9..39).rev().map(|i| recs[i]));
    assert_eq!(s.len(), MAX_VECTOR_ENTRIES);
    assert_eq!(names(&devs[0], &t), sorted(s), "the base, own, twins");
    // The eight twins left are heads: the file is back at the path, shown
    // once, no copy.
    let mut heads: Vec<RecordHash> = (1..9).rev().map(|i| recs[i]).collect();
    heads.push(t);
    assert_eq!(devs[0].heads("p"), heads);
    let v = view(&devs[0], "p");
    assert!(
        !v.deleted && v.conflict_copies.is_empty(),
        "the file is back"
    );
    assert_eq!(on_a_reader(&devs, &recs, &[t]), heads);
    // The next delete, made with the file back on the disk, covers them;
    // the first tombstone, no twin of a file, stays a head beside it, the
    // path deleted, and a save over the two tombstones, twins, covers both.
    devs[0].apply("p");
    let t2 = devs[0].delete("p");
    assert_eq!(devs[0].heads("p"), vec![t2, t]);
    assert!(view(&devs[0], "p").deleted);
    devs[0].apply("p");
    let w = devs[0].put("p", 5);
    assert_eq!(names(&devs[0], &w), sorted(vec![t2, t]));
    assert_eq!(devs[0].heads("p"), vec![w]);
    assert_eq!(on_a_reader(&devs, &recs, &[t, t2, w]), vec![w]);
}

/// The twins of `protocol.md` section 8 item 7, for `heads.json`: two files
/// with the same plaintext hashes under a save by the device whose twin is
/// not at the path, two directories under a tree delete, two tombstones
/// under a new version (each write naming both twins, and nothing of the
/// old content left on either device), 40 twins and a copy under a save, a
/// later version of the base's content still arriving under a save (no
/// twin: both heads), and 40 identical directories under two tree deletes
/// (the first names 32 and leaves eight, the next takes them).
pub(crate) fn twins_vector() -> Value {
    let mut out = Vec::new();
    let (mut devs, recs) = twins("p", &[2_000, 2_000]);
    let editor = 1 - at_the_path(&devs, &recs, "p");
    let w = devs[editor].put("p", 2);
    let both = sorted(recs.clone());
    assert_eq!(names(&devs[editor], &w), both, "both twins named");
    spread(&mut devs, editor, &[w], &["p"]);
    assert_eq!(left_over(&devs, &recs, w, "p", &[w]), None);
    out.push(json!({ "name": "two-file-twins-under-a-save", "names": hashes(&both), "heads": hashes(&[w]) }));
    let (mut devs, recs) = twin_dirs("d");
    let written = devs[0].tree_delete("d");
    let td = written.records[0].0;
    let both = sorted(recs.clone());
    assert_eq!(names(&devs[0], &td), both, "the tree delete names both");
    spread(&mut devs, 0, &[td], &["d"]);
    assert_eq!(left_over(&devs, &recs, td, "d", &[]), None);
    out.push(json!({ "name": "two-directory-twins-under-a-tree-delete", "names": hashes(&both), "heads": [] }));
    let mut devs = vec![Dev::writer(0xa0), Dev::writer(0xa1)];
    let v0 = devs[0].put("p", 1);
    let first = devs[0].signed(&v0).clone();
    let from = devs[0].id();
    devs[1].accept_from(from, &first).unwrap();
    devs[1].apply("p");
    let mut recs = Vec::new();
    for d in &mut devs {
        d.mtime = 4_000;
        recs.push(d.delete("p"));
    }
    share(&mut devs, &recs, "p");
    let w = devs[0].put("p", 3);
    let both = sorted(recs.clone());
    assert_eq!(names(&devs[0], &w), both, "both tombstones named");
    spread(&mut devs, 0, &[w], &["p"]);
    assert_eq!(left_over(&devs, &recs, w, "p", &[w]), None);
    out.push(json!({ "name": "two-tombstone-twins-under-a-new-version", "names": hashes(&both), "heads": hashes(&[w]) }));
    out.push(forty_twins_under_a_save());
    let (a, _, y, w) = a_mode_change_still_arriving(0, an_edit);
    assert_eq!(a, sorted(vec![y, w]));
    out.push(
        json!({ "name": "a-later-version-of-the-base-content-under-a-save", "heads": hashes(&a) }),
    );
    let mut f = FortyDirs::new(ascending_mtimes, 0);
    let named: Vec<RecordHash> = f.named.iter().map(|i| f.recs[*i]).collect();
    let left: Vec<RecordHash> = f
        .take_32_then_the_rest()
        .iter()
        .map(|i| f.recs[*i])
        .collect();
    out.push(json!({ "name": "40-directory-twins-under-two-tree-deletes", "names": hashes(&sorted(named)), "left_by_the_first": hashes(&left), "heads": [] }));
    json!(out)
}

/// A tree delete whose pruned vector misses a twin and covers the base it
/// matches: the tombstone written after it, at the twin's path, covers the
/// twin, and a path whose twins it covers gets none. More than 32 device IDs
/// wrote beneath `d`, all at one counter, so pruning keeps the 32 smallest:
/// `d/f`'s base (device 0x10, the greater `mtime_ns`) is kept and its twin
/// (device 0xf0) is dropped, as are the files of devices 0x3d to 0x3f;
/// `d/h`'s two twins (devices 0x11 and 0x12) are kept.
#[test]
fn a_tree_delete_whose_pruned_vector_misses_a_twin_writes_a_tombstone_over_it() {
    let mut d = Dev::writer(0xd0);
    let mut recs = Vec::new();
    let mut write = |own: u8, path: &str, content: u8, mtime: i64| {
        let mut e = Dev::writer(own);
        e.mtime = mtime - 1_000;
        let v = e.put(path, content);
        recs.push((e.id(), e.signed(&v).clone()));
        v
    };
    let base = write(0x10, "d/f", 7, 900_000);
    let twin = write(0xf0, "d/f", 7, 2_000);
    write(0x11, "d/h", 9, 5_000);
    write(0x12, "d/h", 9, 6_000);
    let paths: Vec<String> = (0..32u8).map(|i| format!("d/g{i:02}")).collect();
    for (i, p) in (0..32u8).zip(&paths) {
        write(0x20 + i, p, i, 3_000);
    }
    for (from, s) in &recs {
        d.accept_from(*from, s).unwrap();
    }
    d.apply_all();
    assert_eq!(d.ix.current("d/f").unwrap().hash, base, "the base at d/f");
    assert_eq!(d.heads("d/f"), vec![base, twin], "and its twin");
    let written = d.tree_delete("d");
    let mut tombs: Vec<String> = written
        .records
        .iter()
        .filter_map(|(h, _)| {
            d.ix.s
                .held
                .get(h)?
                .meta()
                .filter(|m| m.is_tombstone())
                .map(|m| m.path.clone())
        })
        .collect();
    tombs.sort();
    let want = ["d/f", "d/g29", "d/g30", "d/g31"];
    assert_eq!(tombs, want, "the missed twin's path and the missed bases'");
    let all: Vec<&str> = ["d/f", "d/h"]
        .into_iter()
        .chain(paths.iter().map(String::as_str))
        .collect();
    for p in &all {
        assert_eq!(view(&d, p).current, None, "{p}: nothing left");
    }
    let mut r = Dev::reader(0x90);
    for (from, s) in &recs {
        r.accept_from(*from, s).unwrap();
    }
    for (h, _) in &written.records {
        r.accept_from(d.id(), d.signed(h)).unwrap();
    }
    for p in &all {
        assert_eq!(view(&r, p).current, None, "{p}: nothing left on a reader");
    }
}

/// 40 write holders, devices 0x40 to 0x67, each make the directory `d`
/// apart, the `i`th at `mtime_ns` `mtime(i)`, all at one counter; device
/// `deleter` takes every other's record, applies `d` and deletes it, and a
/// read holder takes every record. Which of the 40 the tree delete names and
/// which its vector covers, as indexes into the records, in device order.
struct FortyDirs {
    devs: Vec<Dev>,
    recs: Vec<RecordHash>,
    deleter: usize,
    reader: Dev,
    /// The directory at the path before the delete.
    at_path: usize,
    named: Vec<usize>,
    covered: Vec<usize>,
}

impl FortyDirs {
    fn new(mtime: fn(i64) -> i64, deleter: usize) -> Self {
        let mut devs: Vec<Dev> = (0..40u8).map(|i| Dev::writer(0x40 + i)).collect();
        let recs: Vec<RecordHash> = (0i64..)
            .zip(devs.iter_mut())
            .map(|(i, d)| d.write(&[Change::Put(dir("d", mtime(i)))]).unwrap().records[0].0)
            .collect();
        let dots: Vec<Dot> = devs
            .iter()
            .zip(&recs)
            .map(|(d, h)| d.ix.s.held[h].meta().unwrap().dot)
            .collect();
        let signed: Vec<(DeviceId, SignedRecord)> = devs
            .iter()
            .zip(&recs)
            .map(|(d, h)| (d.id(), d.signed(h).clone()))
            .collect();
        let mut reader = Dev::reader(0x90);
        for (j, (from, s)) in signed.iter().enumerate() {
            reader.accept_from(*from, s).unwrap();
            if j != deleter {
                devs[deleter].accept_from(*from, s).unwrap();
            }
        }
        devs[deleter].apply("d");
        let first = view(&devs[deleter], "d").heads[0].hash;
        let at_path = recs.iter().position(|r| *r == first).unwrap();
        let mut f = Self {
            devs,
            recs,
            deleter,
            reader,
            at_path,
            named: Vec::new(),
            covered: Vec::new(),
        };
        let td = f.delete()[0];
        let m: Meta = f.devs[deleter].ix.s.held[&td].meta().unwrap().clone();
        let names = names(&f.devs[deleter], &td);
        f.named = (0..40).filter(|i| names.contains(&f.recs[*i])).collect();
        f.covered = (0..40).filter(|i| m.vector.covers(&dots[*i])).collect();
        assert_eq!(f.named.len(), MAX_VECTOR_ENTRIES, "32 names at d");
        f
    }

    /// The deleter deletes `d` (from what it has applied there), and the
    /// reader takes what it wrote.
    fn delete(&mut self) -> Vec<RecordHash> {
        let d = &mut self.devs[self.deleter];
        d.apply("d");
        let written: Vec<RecordHash> = d.tree_delete("d").records.iter().map(|(h, _)| *h).collect();
        let d = &self.devs[self.deleter];
        for h in &written {
            self.reader.accept_from(d.id(), d.signed(h)).unwrap();
        }
        written
    }

    /// The heads at `d` on the deleter and on the reader, as indexes, the
    /// same on both (checked), ascending.
    fn left(&self) -> Vec<usize> {
        let at = |d: &Dev| -> Vec<usize> {
            let mut v: Vec<usize> = d
                .heads("d")
                .iter()
                .map(|h| self.recs.iter().position(|r| r == h).unwrap())
                .collect();
            v.sort_unstable();
            v
        };
        let left = at(&self.devs[self.deleter]);
        assert_eq!(at(&self.reader), left, "the same on a reader");
        left
    }

    /// The first tree delete took what its vector covers, its 32 names
    /// among them, and left the rest at `d`, the directory back; the next,
    /// made with them on the deleter's disk, takes them. Those left by the
    /// first, as indexes.
    fn take_32_then_the_rest(&mut self) -> Vec<usize> {
        let left = self.left();
        let gone: Vec<usize> = (0..40).filter(|i| !left.contains(i)).collect();
        assert_eq!(gone, self.covered, "what its vector covers goes");
        assert_eq!(left.len(), 40 - MAX_VECTOR_ENTRIES, "the rest stay");
        self.delete();
        assert!(self.left().is_empty(), "the next delete takes the rest");
        left
    }
}

/// The author's fixture: the `i`th directory at `mtime_ns` 10 000 + 1 000
/// `i`, so that the 39th's sits at the path; deleted by device 0, whose own
/// is the last in display order.
fn ascending_mtimes(i: i64) -> i64 {
    10_000 + 1_000 * i
}

/// The fixtures of the reviews of the fix (R1-1's, mirrored: the display
/// order ascending by device ID; R2-3's and the security review's P1: the
/// deleter's own first in display order).
fn descending_mtimes(i: i64) -> i64 {
    100_000 - 1_000 * i
}

/// A tree delete names at its own path only records its pruned vector
/// covers (4.4, "Names": a name says no more than coverage, "Why it is
/// safe" 10): the devices of the records it names there are mandatory in
/// its prune. Before, with no mandatory entry, the 32 smallest device IDs
/// kept their places whatever it named, and of 40 identical directories it
/// named records its vector missed (the security review's F4, probe P7:
/// eight with the author's fixture, one with R1-1's).
#[test]
fn a_tree_delete_names_at_its_own_path_only_what_its_vector_covers() {
    for (mtime, deleter, what) in [
        (
            ascending_mtimes as fn(i64) -> i64,
            0,
            "the author's fixture",
        ),
        (descending_mtimes, 39, "R1-1's, mirrored"),
        (descending_mtimes, 0, "R2-3's and P1"),
    ] {
        let f = FortyDirs::new(mtime, deleter);
        let missed: Vec<usize> = f
            .named
            .iter()
            .copied()
            .filter(|i| !f.covered.contains(i))
            .collect();
        assert!(
            missed.is_empty(),
            "{what}: named but not covered: {missed:?}"
        );
    }
}

/// 40 identical directories under a tree delete by device 0, whose own is
/// the last in display order: the tree delete names the base at the path
/// (the 39th's), then its own twin, then the other twins in display order,
/// 32 names in all, and its vector covers those 32 devices' records alone.
/// The eight left, devices 0x41 to 0x48, are heads at `d`, the directory
/// back on every device, until the next delete, made with them on the disk,
/// takes them (more than 32 device IDs at the deleted directory itself: a
/// stated residual, 4.4, "A tree delete").
#[test]
fn forty_identical_directories_a_tree_delete_names_its_own_twin_first() {
    let mut f = FortyDirs::new(ascending_mtimes, 0);
    assert_eq!(f.at_path, 39, "the 39th's at the path");
    let mut named = vec![39, 0];
    named.extend(9..39);
    named.sort_unstable();
    assert_eq!(f.named, named, "the base, its own twin, then display order");
    assert_eq!(f.take_32_then_the_rest(), (1..9).collect::<Vec<_>>());
}

/// The same in the reviews' display orders (R1-1's mirrored fixture, the
/// deleter last; R2-3's and P1, its own first): 32 go, those of the eight
/// devices named nowhere stay at `d` on the deleter and on a reader, and the
/// next delete takes them. Before, R1-1's left seven and named one its vector
/// missed; R2-3's left the same eight.
#[test]
fn forty_identical_directories_in_any_display_order_go_within_two_tree_deletes() {
    let mut f = FortyDirs::new(descending_mtimes, 39);
    assert_eq!(f.at_path, 0, "the 0th's at the path");
    let mut named = vec![0, 39];
    named.extend(1..31);
    named.sort_unstable();
    assert_eq!(f.named, named, "the base, its own twin, then display order");
    assert_eq!(f.take_32_then_the_rest(), (31..39).collect::<Vec<_>>());
    let mut f = FortyDirs::new(descending_mtimes, 0);
    assert_eq!(f.at_path, 0, "its own at the path");
    assert_eq!(f.named, (0..32).collect::<Vec<_>>(), "its own base first");
    assert_eq!(f.take_32_then_the_rest(), (32..40).collect::<Vec<_>>());
}

/// A tree delete names at most 32 records at its own path, so a directory
/// with 64 or more conflict copies at its path can be deleted. Before, it
/// named every base there, here the directory and 71 copies, past
/// `MAX_REPLACES`, and the write was refused (`Draft(Replaces(72))`): the
/// directory could not be deleted from that device (the R1 review's finding
/// outside the fix). The 40 copies past its names, which its vector does not
/// cover, stay heads at `d` until the next delete there.
#[test]
fn a_directory_with_64_or_more_conflict_copies_at_its_path_can_be_deleted() {
    let mut d = Dev::writer(0x10);
    d.mtime = 900_000;
    let own = d.mkdir("d");
    let mut dots = vec![(own, d.ix.s.held[&own].meta().unwrap().dot)];
    for i in 0..71u8 {
        let mut e = Dev::writer(0x20 + i);
        e.mtime = 1_000 * i64::from(i);
        let h = e.put("d", i);
        dots.push((h, e.ix.s.held[&h].meta().unwrap().dot));
        d.take(&e, &[h]);
    }
    d.apply("d");
    assert_eq!(view(&d, "d").current, Some(own));
    assert_eq!(d.ix.bases("d").len(), 72, "the directory and 71 copies");
    let written = d
        .write(&[Change::TreeDelete {
            path: "d".into(),
            mtime_ns: 1_000_000,
        }])
        .expect("the tree delete is written");
    let td = written.records[0].0;
    let m: Meta = d.ix.s.held[&td].meta().unwrap().clone();
    let named = names(&d, &td);
    assert_eq!(
        named.len(),
        MAX_VECTOR_ENTRIES,
        "32 names, within {MAX_REPLACES}"
    );
    assert!(named.contains(&own), "its own directory among them");
    for (h, dot) in dots.iter().filter(|(h, _)| named.contains(h)) {
        assert!(!d.holds(h), "a record named goes");
        assert!(m.vector.covers(dot), "and its vector covers it");
    }
    assert_eq!(
        d.heads("d").len(),
        71 - 31,
        "the copies past the names stay"
    );
}

/// A tree delete is no one's twin. A deleted directory whose base is a
/// tombstone, beside a concurrent tree delete of it held at its tag (no head,
/// held until a later tree delete covers it): the directory made again
/// covers and names the tombstone alone, and the tree delete stays held.
#[test]
fn a_tree_delete_held_beside_a_tombstone_base_is_no_twin_of_it() {
    let mut x = Dev::writer(0xa0);
    let mut y = Dev::writer(0xa1);
    let v = x.mkdir("d");
    y.take(&x, &[v]);
    y.apply("d");
    let t = x.delete("d");
    let written = y.tree_delete("d");
    let hashes: Vec<RecordHash> = written.records.iter().map(|(h, _)| *h).collect();
    let td = hashes[0];
    x.take(&y, &hashes);
    x.apply("d");
    assert_eq!(x.heads("d"), vec![t], "the tombstone the one head");
    assert_eq!(x.ix.current("d").unwrap().hash, t, "and the base");
    assert!(x.holds(&td), "the tree delete held beside it");
    let w = x.mkdir("d");
    assert_eq!(names(&x, &w), vec![t], "the tombstone alone named");
    assert!(x.holds(&td), "the tree delete still held");
    assert_eq!(x.heads("d"), vec![w]);
}

/// A later version of the base with its content, which changed only its
/// mode, is no twin of it (the R2 review's R2-1, the security review's F1
/// and probe P3): A writes `p`, X; B, holding X on its disk, makes `p`
/// executable, the same bytes, at X's `mtime_ns` moved by `shift` (0, as a
/// `chmod` leaves it, or later, or earlier), Y, whose vector covers X. A
/// holds Y but has not put it on its disk, X still its base, and its person
/// changes `p` (`change`). Y covers X's dot, so it is no twin of X, and the
/// change leaves it a head beside it, a conflict, on both devices, as 4.7
/// item 6 says ("never one over the other"); before, Y counted as X's twin
/// and the change covered it with no copy and nothing shown. A's heads, then
/// B's, ascending; Y; the change.
fn a_mode_change_still_arriving(
    shift: i64,
    change: fn(&mut Dev) -> RecordHash,
) -> (Vec<RecordHash>, Vec<RecordHash>, RecordHash, RecordHash) {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    let x = a.put("p", 1);
    b.take(&a, &[x]);
    b.apply("p");
    let mut chmod = file("p", 1, a.mtime + shift);
    chmod.mode = 0o755;
    let y = b.write(&[Change::Put(chmod)]).unwrap().records[0].0;
    a.take(&b, &[y]);
    assert_eq!(a.heads("p"), vec![y], "Y covers X");
    assert_eq!(a.ix.current("p").unwrap().hash, x, "not on A's disk yet");
    let w = change(&mut a);
    assert!(!names(&a, &w).contains(&y), "Y is not named");
    b.take(&a, &[w]);
    (sorted(a.heads("p")), sorted(b.heads("p")), y, w)
}

/// An edit: a version of other content.
fn an_edit(d: &mut Dev) -> RecordHash {
    d.put("p", 2)
}

/// A delete.
fn a_delete(d: &mut Dev) -> RecordHash {
    d.delete("p")
}

#[test]
fn a_later_version_that_changed_only_the_mode_at_the_same_mtime_stays_a_conflict() {
    let (a, b, y, w) = a_mode_change_still_arriving(0, an_edit);
    assert_eq!(a, sorted(vec![y, w]), "both heads on A");
    assert_eq!(b, a, "and on B");
}

#[test]
fn a_later_version_that_changed_only_the_mode_at_a_later_mtime_stays_a_conflict() {
    let (a, b, y, w) = a_mode_change_still_arriving(1_000, an_edit);
    assert_eq!(a, sorted(vec![y, w]), "both heads on A");
    assert_eq!(b, a, "and on B");
}

/// At an earlier `mtime_ns` Y comes after X in display order, so only its
/// covering X's dot tells it from a twin of X.
#[test]
fn a_later_version_that_changed_only_the_mode_at_an_earlier_mtime_stays_a_conflict() {
    let (a, b, y, w) = a_mode_change_still_arriving(-500, an_edit);
    assert_eq!(a, sorted(vec![y, w]), "both heads on A");
    assert_eq!(b, a, "and on B");
}

/// Against a delete made before the mode change reached the disk, the file
/// stays, with its new mode (an edit beats a delete).
#[test]
fn a_later_version_that_changed_only_the_mode_outlives_a_delete_made_before_it_reached_the_disk() {
    for shift in [0, 1_000, -500] {
        let (a, b, y, t) = a_mode_change_still_arriving(shift, a_delete);
        assert_eq!(a, sorted(vec![y, t]), "the version and the tombstone");
        assert_eq!(b, a, "on both devices");
    }
}

/// A record of the base's content, concurrent with it, that comes before it
/// in display order is the head the engine has yet to put at the path, its
/// time and mode not on the disk: it is no twin of the base until then (the
/// security review's F1, its option (a)), so an edit made meanwhile leaves
/// it a head, a conflict copy of the old content, as before the fix. B
/// writes `p` with A's bytes apart from it, at a later `mtime_ns` and mode
/// 0o755; A holds it, not yet applied, and edits `p`. (Once A has applied
/// it, B's record is the base and A's own its twin, and an edit covers both:
/// `identical_concurrent_heads_with_different_mtimes_next_save_covers_both`.)
#[test]
fn a_concurrent_twin_the_engine_has_yet_to_put_at_the_path_stays_a_conflict() {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xa1);
    let x = a.put("p", 1);
    let mut later = file("p", 1, 9_000);
    later.mode = 0o755;
    let t = b.write(&[Change::Put(later)]).unwrap().records[0].0;
    a.take(&b, &[t]);
    assert_eq!(a.heads("p"), vec![t, x], "B's first in display order");
    assert_eq!(
        a.ix.current("p").unwrap().hash,
        x,
        "not applied: X the base"
    );
    a.mtime = 20_000;
    let w = a.put("p", 2);
    assert_eq!(names(&a, &w), vec![x], "X alone named");
    b.take(&a, &[w]);
    for d in [&a, &b] {
        assert_eq!(d.heads("p"), vec![w, t], "the edit and B's version");
        assert_eq!(view(d, "p").conflict_copies, vec![t], "a copy of it");
    }
}

/// A concurrent record of the base's content that comes before the base at
/// the path in display order but is not the first head is no twin either:
/// the display-order condition, kept beside the first-head one (the confirm
/// review's C1), keeps out what the display shows ahead of the version on
/// the disk. A's X (`mtime_ns` 10 000) sits at `p`; B writes Q apart, other
/// content, at 30 000, first among the heads; C writes T apart, X's bytes,
/// mode 0o755, at 20 000, between the two. A holds both, applies neither,
/// and edits `p`: the edit names X alone, and Q and T stay beside it,
/// conflict copies, on A, B and C.
#[test]
fn a_concurrent_record_of_the_bases_content_ahead_of_it_but_not_first_stays_a_conflict() {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    let mut c = Dev::writer(0xc0);
    a.mtime = 9_000;
    let x = a.put("p", 1);
    let q = b
        .write(&[Change::Put(file("p", 2, 30_000))])
        .unwrap()
        .records[0]
        .0;
    let mut apart = file("p", 1, 20_000);
    apart.mode = 0o755;
    let t = c.write(&[Change::Put(apart)]).unwrap().records[0].0;
    a.take(&b, &[q]);
    a.take(&c, &[t]);
    assert_eq!(a.heads("p"), vec![q, t, x], "Q first, T ahead of X");
    assert_eq!(
        a.ix.current("p").unwrap().hash,
        x,
        "not applied: X the base"
    );
    a.mtime = 49_000;
    let w = a.put("p", 3);
    assert_eq!(names(&a, &w), vec![x], "X alone named");
    b.take(&c, &[t]);
    b.take(&a, &[w]);
    c.take(&b, &[q]);
    c.take(&a, &[w]);
    for d in [&a, &b, &c] {
        assert_eq!(d.heads("p"), vec![w, q, t], "the edit, Q and T");
        assert_eq!(view(d, "p").conflict_copies, vec![q, t], "Q and T copies");
    }
}

/// What a device shows at `p`: its heads, then its conflict copies.
type Shown = (Vec<RecordHash>, Vec<RecordHash>);

/// A's base at `p` replaced by a later version still arriving, beside a
/// concurrent record of the base's content that comes after the base in
/// display order but first among the heads (the confirm review's C1). A's
/// X (`mtime_ns` 10 000) is A's base; B, holding X on its disk, writes Y
/// over it at `mtime_ns` 400, mode 0o700 (`same`: X's bytes; otherwise
/// other content); C writes Z apart, X's bytes, mode 0o755, `mtime_ns` 500.
/// A holds Y and Z, has applied neither, and edits `p`: W. X, Y, Z and W;
/// what W names; what A, B and C show once each holds Y, Z and W.
fn a_twin_first_among_the_heads_once_its_base_is_replaced(
    same: bool,
) -> ([RecordHash; 4], Vec<RecordHash>, Vec<Shown>) {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    let mut c = Dev::writer(0xc0);
    a.mtime = 9_000;
    let x = a.put("p", 1);
    b.take(&a, &[x]);
    b.apply("p");
    let mut over = file("p", if same { 1 } else { 2 }, 400);
    over.mode = 0o700;
    let y = b.write(&[Change::Put(over)]).unwrap().records[0].0;
    let mut apart = file("p", 1, 500);
    apart.mode = 0o755;
    let z = c.write(&[Change::Put(apart)]).unwrap().records[0].0;
    a.take(&b, &[y]);
    a.take(&c, &[z]);
    assert_eq!(a.heads("p"), vec![z, y], "Z first among the heads");
    assert_eq!(
        view(&a, "p").current,
        Some(z),
        "Z is what the engine puts at p"
    );
    assert_eq!(
        a.ix.current("p").unwrap().hash,
        x,
        "not applied: X the base"
    );
    a.mtime = 49_000;
    let w = a.put("p", 3);
    let named = names(&a, &w);
    b.take(&c, &[z]);
    b.take(&a, &[w]);
    c.take(&b, &[y]);
    c.take(&a, &[w]);
    let shown = [&a, &b, &c]
        .into_iter()
        .map(|d| (d.heads("p"), view(d, "p").conflict_copies))
        .collect();
    ([x, y, z, w], named, shown)
}

/// Y of other content: Z, first among the heads, is no twin of X, and the
/// edit names X alone and leaves Z beside it, a conflict copy with Y, on
/// every device. Before, Z counted as X's twin (concurrent, and after X in
/// display order) and the edit covered it, its mode and time gone with no
/// copy: Y alone was left.
#[test]
fn a_twin_first_among_the_heads_once_its_base_is_replaced_by_other_content_stays_a_conflict() {
    let ([x, y, z, w], named, shown) =
        a_twin_first_among_the_heads_once_its_base_is_replaced(false);
    assert_eq!(named, vec![x], "X alone named");
    for s in shown {
        assert_eq!(s, (vec![w, z, y], vec![z, y]), "the edit; Z and Y copies");
    }
}

/// Y a mode change of X's bytes: no twin of X either (it covers X's dot),
/// and both Y and Z stay beside the edit, two conflict copies of X's bytes,
/// on every device. Before, the edit covered Z, Y alone left.
#[test]
fn a_twin_first_among_the_heads_once_its_base_is_replaced_by_its_content_stays_a_conflict() {
    let ([x, y, z, w], named, shown) = a_twin_first_among_the_heads_once_its_base_is_replaced(true);
    assert_eq!(named, vec![x], "X alone named");
    for s in shown {
        assert_eq!(s, (vec![w, z, y], vec![z, y]), "the edit; Z and Y copies");
    }
}

/// A twin of a conflict copy's base that is first in display order is the
/// head the engine has yet to put at the path: no twin (the confirm review's
/// C1; a copy's base has twins whatever the display order, so only the
/// first-head rule keeps it out). A's X (`mtime_ns` 10 000) sits at `p` and
/// C's V, other content, at 5 000, is a conflict copy beside it on A's disk;
/// E writes T apart, V's bytes, mode 0o755, at 20 000, so T comes first. A
/// holds T, has not applied it, and edits `p`: the edit names X and V, and
/// leaves T beside it, a conflict copy, on A, C and E. Before, T counted as
/// V's twin and the edit covered it too, its mode and time gone with no
/// copy, nothing left beside the edit.
#[test]
fn a_twin_of_a_conflict_copy_first_in_display_order_stays_a_conflict() {
    let mut a = Dev::writer(0xa0);
    let mut c = Dev::writer(0xc0);
    let mut e = Dev::writer(0xe0);
    a.mtime = 9_000;
    let x = a.put("p", 1);
    c.mtime = 4_000;
    let v = c.put("p", 2);
    a.take(&c, &[v]);
    a.apply("p");
    assert_eq!(view(&a, "p").conflict_copies, vec![v]);
    let mut apart = file("p", 2, 20_000);
    apart.mode = 0o755;
    let t = e.write(&[Change::Put(apart)]).unwrap().records[0].0;
    a.take(&e, &[t]);
    assert_eq!(
        a.heads("p"),
        vec![t, x, v],
        "T first: the engine puts it at p"
    );
    assert_eq!(
        a.ix.current("p").unwrap().hash,
        x,
        "not applied: X the base"
    );
    a.mtime = 49_000;
    let w = a.put("p", 3);
    assert_eq!(names(&a, &w), sorted(vec![x, v]), "X and V, not T");
    c.take(&e, &[t]);
    c.take(&a, &[w]);
    e.take(&a, &[w]);
    for d in [&a, &c, &e] {
        assert_eq!(d.heads("p"), vec![w, t], "the edit and T");
        assert_eq!(view(d, "p").conflict_copies, vec![t], "a copy of T");
    }
}

/// The same beneath a tree delete (the confirm review's C1, "wherever twins
/// are found beneath a tree delete"): A's X at `d/p` replaced by B's Y,
/// other content, still arriving, beside C's Z, X's bytes, apart, first
/// among the heads. A deletes `d`: the tree delete's join takes X alone at
/// `d/p`, not Z, so Z and Y stay heads there, `d/p` back (against a delete,
/// a version still arriving is a file that comes back, "Why it is safe"
/// 9). Before, the join took Z as X's twin and the delete covered it, Y
/// alone left.
#[test]
fn a_tree_delete_leaves_a_twin_first_among_the_heads_beneath_it_once_its_base_is_replaced() {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    let mut c = Dev::writer(0xc0);
    a.mtime = 9_000;
    let x = a.put("d/p", 1);
    b.take(&a, &[x]);
    b.apply("d/p");
    let y = b
        .write(&[Change::Put(file("d/p", 2, 400))])
        .unwrap()
        .records[0]
        .0;
    let mut apart = file("d/p", 1, 500);
    apart.mode = 0o755;
    let z = c.write(&[Change::Put(apart)]).unwrap().records[0].0;
    a.take(&b, &[y]);
    a.take(&c, &[z]);
    assert_eq!(a.heads("d/p"), vec![z, y], "Z first among the heads");
    assert_eq!(
        a.ix.current("d/p").unwrap().hash,
        x,
        "not applied: X the base"
    );
    let written: Vec<RecordHash> = a.tree_delete("d").records.iter().map(|(h, _)| *h).collect();
    assert!(
        !a.ix.s.held[&written[0]]
            .meta()
            .unwrap()
            .vector
            .covers(&a.ix.s.held[&z].meta().unwrap().dot),
        "Z's dot not joined"
    );
    b.take(&c, &[z]);
    b.take(&a, &written);
    for d in [&a, &b] {
        assert_eq!(d.heads("d/p"), vec![z, y], "Z and Y stay");
    }
}

/// A later version of a conflict copy's content is no twin of the copy
/// either (the security review's F1: the first rule holds for every base):
/// A's X sits at the path and C's Z, other content, is a conflict copy
/// beside it on A's disk; C then changes only Z's mode, Z2, whose vector
/// covers Z, and A holds Z2 but has not yet written it beside the path. A's
/// edit covers X and Z, and leaves Z2 a head, a conflict copy, on both
/// devices.
#[test]
fn a_later_version_of_a_conflict_copy_with_its_content_stays_beside_an_edit() {
    let mut a = Dev::writer(0xa0);
    let mut c = Dev::writer(0xa2);
    a.mtime = 8_000;
    let x = a.put("p", 1);
    let z = c.put("p", 2);
    a.take(&c, &[z]);
    a.apply("p");
    assert_eq!(view(&a, "p").conflict_copies, vec![z]);
    let mut chmod = file("p", 2, c.mtime);
    chmod.mode = 0o755;
    let z2 = c.write(&[Change::Put(chmod)]).unwrap().records[0].0;
    a.take(&c, &[z2]);
    assert_eq!(a.heads("p"), vec![x, z2], "Z2 covers Z");
    assert!(
        a.ix.bases("p").iter().any(|(_, h)| *h == z),
        "Z still the copy on A's disk"
    );
    let w = a.put("p", 3);
    assert_eq!(names(&a, &w), sorted(vec![x, z]), "X and Z, not Z2");
    c.take(&a, &[w]);
    for d in [&a, &c] {
        assert_eq!(d.heads("p"), vec![w, z2]);
        assert_eq!(view(d, "p").conflict_copies, vec![z2]);
    }
}

/// Records signed under the writer's own device ID with its base's content
/// (a cloned disk image, or a write holder writing under its ID: "Why it is
/// safe" 8(b)) cannot push the base out of `S` (the security review's F5,
/// probe P6): `S` takes the bases first, then the twins. F's version is V's
/// base; 32 records under V's ID with its content come after it in display
/// order. V's save names and covers F's version and 31 of them, and the
/// last, under the same dot, with them. Before, V's own records came first,
/// the 32 took every place, and F's version stayed beside the save, a
/// conflict copy of the old content.
#[test]
fn records_under_the_writers_own_id_cannot_push_its_base_out_of_s() {
    let mut f = Dev::writer(0xf0);
    let mut v = Dev::writer(0x77);
    f.mtime = 500_000;
    let b = f.put("p", 1);
    v.take(&f, &[b]);
    v.apply("p");
    for i in 0..32i64 {
        let mut x = Dev::writer(0x77);
        x.mtime = 1_000 + i;
        let h = x.put("p", 1);
        v.accept_from(x.id(), x.signed(&h)).unwrap();
    }
    v.apply("p");
    assert_eq!(v.ix.current("p").unwrap().hash, b, "F's version the base");
    assert_eq!(v.heads("p").len(), 33);
    let w = v.put("p", 2);
    assert!(names(&v, &w).contains(&b), "the base named");
    assert!(!v.holds(&b), "and covered");
    assert_eq!(v.heads("p"), vec![w]);
}

/// A twin that arrives after the write stays a head beside it, a conflict
/// copy of the old content, on every device: the write did not hold it, so
/// its vector does not cover it (the R2 review's R2-5, the security review's
/// P4). The common case: a folder linked on devices that already hold it,
/// edited before every device's records have arrived.
#[test]
fn a_twin_arriving_after_the_write_stays_a_head_a_conflict_copy_of_the_old_content() {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xa1);
    let mut c = Dev::writer(0xa2);
    let ra = a.put("p", 1);
    let rb = b.put("p", 1);
    let rc = c.put("p", 1);
    a.take(&b, &[rb]);
    a.apply("p");
    let w = a.put("p", 2);
    assert_eq!(names(&a, &w), sorted(vec![ra, rb]), "the two it held");
    a.take(&c, &[rc]);
    b.take(&a, &[w]);
    b.take(&c, &[rc]);
    c.take(&a, &[w]);
    for d in [&mut a, &mut b, &mut c] {
        d.apply("p");
        assert_eq!(d.heads("p"), vec![w, rc]);
        assert_eq!(view(d, "p").conflict_copies, vec![rc]);
    }
}

/// A tombstone is no twin of a live version: beside a live base and its
/// twin, a concurrent delete stays a head after the save that covers the
/// two, the path not deleted (an edit beats a delete; the R2 review's R2-5).
#[test]
fn a_tombstone_beside_a_live_base_and_its_twin_is_no_twin_and_stays_a_head() {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xa1);
    let mut c = Dev::writer(0xa2);
    let x = a.put("p", 1);
    let y = b.put("p", 1);
    let t = c.delete("p");
    a.take(&b, &[y]);
    a.take(&c, &[t]);
    a.apply("p");
    assert_eq!(view(&a, "p").heads.len(), 3);
    let w = a.put("p", 2);
    assert_eq!(
        names(&a, &w),
        sorted(vec![x, y]),
        "the twins, not the tombstone"
    );
    b.take(&a, &[w]);
    b.take(&c, &[t]);
    for d in [&a, &b] {
        assert_eq!(d.heads("p"), vec![w, t]);
        assert!(!view(d, "p").deleted);
    }
}

/// Three twins beside two conflict copies of one other content, the
/// writer's own record neither at the path nor a copy (the security
/// review's P5): one save names and covers all five. The two copies are
/// both bases, one slot each.
#[test]
fn three_twins_and_two_identical_conflict_copies_go_with_one_save() {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xa1);
    let mut c = Dev::writer(0xa2);
    let mut e = Dev::writer(0xa3);
    let mut g = Dev::writer(0xa4);
    a.mtime = 1_000;
    b.mtime = 9_000;
    c.mtime = 5_000;
    e.mtime = 0;
    g.mtime = 100;
    let ra = a.put("p", 1);
    let rb = b.put("p", 1);
    let rc = c.put("p", 1);
    let re = e.put("p", 7);
    let rg = g.put("p", 7);
    a.take(&b, &[rb]);
    a.take(&c, &[rc]);
    a.take(&e, &[re]);
    a.take(&g, &[rg]);
    a.apply("p");
    let v = view(&a, "p");
    assert_eq!(v.current, Some(rb), "B's twin at the path");
    assert_eq!(v.conflict_copies, vec![rg, re], "a copy each");
    let w = a.put("p", 3);
    assert_eq!(names(&a, &w), sorted(vec![ra, rb, rc, re, rg]));
    assert_eq!(a.heads("p"), vec![w]);
}

/// A folder delete takes a file beneath it that the deleting device holds
/// but has not yet put on its disk, when the file's device later wrote, at
/// another path beneath the folder, a version the deleter has on its disk
/// there (the owner's decision of 2026-11-08, "Delete it, archive"; 4.4
/// "Why it is safe" 8(a) and 9; the R2 review's R2-2, the security review's
/// F3 and probes P2 and P2b). F writes `P/y`, then `P/x` with the bytes of
/// D's `P/x`; D holds both, but only `P/x` is on its disk, where F's version
/// is the twin of D's own (`base` false: D's at the path, F's after it) or
/// D's base (`base` true: F's later `mtime_ns` puts it at the path). D
/// deletes `P`: the tree delete's join takes F's dot from `P/x`, which
/// covers F's earlier `P/y`, so `P/y` goes on D, and on F when the delete
/// reaches it (where the engine moves its file to the archive, TM-35).
fn a_folder_delete_over_a_file_still_arriving(base: bool) {
    let mut d = Dev::writer(0xd0);
    let mut f = Dev::writer(0xf0);
    d.mtime = 50_000;
    let dx = d.put("P/x", 1);
    f.mtime = if base { 90_000 } else { 1_000 };
    let fy = f.put("P/y", 2);
    let fx = f.put("P/x", 1);
    d.take(&f, &[fy, fx]);
    d.apply("P/x");
    let at_path = if base { fx } else { dx };
    assert_eq!(d.ix.current("P/x").unwrap().hash, at_path);
    assert!(d.ix.current("P/y").is_none(), "P/y is not on D's disk");
    assert!(d.holds(&fy));
    let written: Vec<RecordHash> = d.tree_delete("P").records.iter().map(|(h, _)| *h).collect();
    assert!(!d.holds(&fy), "P/y goes with the folder");
    assert!(d.heads("P/x").is_empty() && d.heads("P/y").is_empty());
    f.take(&d, &written);
    assert!(!f.holds(&fy) && !f.holds(&fx), "on F, which had it, too");
}

#[test]
fn a_folder_delete_takes_a_file_beneath_still_arriving_through_a_twins_dot() {
    a_folder_delete_over_a_file_still_arriving(false);
}

#[test]
fn a_folder_delete_takes_a_file_beneath_still_arriving_through_a_bases_dot() {
    a_folder_delete_over_a_file_still_arriving(true);
}
