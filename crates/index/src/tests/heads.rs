// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `protocol.md` section 8 item 7 whole (`heads.json`): file IDs, coverage,
//! arrival order, display order and "content differs", pruning, a restored
//! device, the lost update (ruling S-1), conflict copies, the clock rule at
//! open, a base that fails at open, renames, opaque records and shared
//! writer faults, tree deletes, expiry by the folder's own time, and the
//! spread of clocks; each case that shows a write holder's heads is checked
//! on a read holder given the same records (`same_on_a_reader`), and the
//! display-order pairs, built on a read holder, on a write holder too; the
//! cases that only a read holder or only one tier can show say so.

use std::collections::BTreeSet;

use licketysync_keys::RecordHash;
use licketysync_protocol::connection::Judgement;
use licketysync_protocol::limits::{
    CLEANUP_HORIZON, CLOCK_RULE_LIMIT, MAX_REPLACES, MAX_VECTOR_ENTRIES, TOMBSTONE_HORIZON,
};
use licketysync_protocol::record::{Kind, Record};
use serde_json::{json, Value};

use super::kit::{
    chunk, dev, dir, file, forge, sealed_file, tombstone, write_key, Dev, DAY, SEC, T0,
};
use super::vectors::{check, h};
use crate::{Change, Place, Put, Store};

fn hashes(v: &[RecordHash]) -> Value {
    json!(v.iter().map(|x| h(&x.0)).collect::<Vec<_>>())
}

/// A reader given every record `w` holds, in its order: the same heads.
fn same_on_a_reader(w: &Dev, paths: &[&str]) {
    let mut r = Dev::reader(0xb1);
    r.clock = w.clock;
    r.take_all(w);
    for p in paths {
        assert_eq!(r.heads(p), w.heads(p), "a read holder shows {p} alike");
    }
    assert_eq!(r.root(), w.root());
}

fn file_ids() -> Value {
    let keys = write_key().record_keys();
    let tags: Vec<Value> = ["docs", "docs/notes", "docs/notes/a.txt"]
        .iter()
        .map(|p| json!({ "path": p, "path_tag": h(&keys.path_tag(p).0) }))
        .collect();
    let keys_vector: Value =
        serde_json::from_str(include_str!("../../../keys/tests/vectors/path_tag.json")).unwrap();
    let shared = keys_vector.to_string();
    for t in &tags {
        assert!(
            shared.contains(t["path_tag"].as_str().unwrap()),
            "shared with keys.md 9 item 13"
        );
    }
    json!(tags)
}

fn coverage() -> Value {
    let mut out = Vec::new();
    // An edit covering the one head.
    let mut w = Dev::writer(0xa0);
    let v1 = w.put("p", 1);
    let v2 = w.put("p", 2);
    assert_eq!(w.heads("p"), vec![v2]);
    assert!(!w.holds(&v1));
    same_on_a_reader(&w, &["p"]);
    out.push(json!({ "name": "an-edit-covers-the-one-head", "heads": hashes(&w.heads("p")) }));
    // Two edits of one head, by two devices: two heads, the greater mtime_ns
    // first; on equal mtime_ns the smaller record hash.
    let mut a = Dev::writer(0xa0);
    let base = a.put("p", 1);
    let mut b = Dev::writer(0xb0);
    b.take(&a, &[base]);
    b.apply("p");
    a.mtime = 50_000;
    b.mtime = 40_000;
    let ea = a.put("p", 2);
    let eb = b.put("p", 3);
    a.take(&b, &[eb]);
    assert_eq!(a.heads("p"), vec![ea, eb], "the greater mtime_ns first");
    let mut c = Dev::writer(0xc0);
    c.take(&a, &[base]);
    c.apply("p");
    c.mtime = a.mtime - 1_000;
    let mut c2 = Dev::writer(0xc1);
    c2.take(&a, &[base]);
    c2.apply("p");
    c2.mtime = a.mtime - 1_000;
    let x = c.put("q-tie", 4);
    let y = c2.put("q-tie", 5);
    let mut t = Dev::writer(0xa9);
    t.take(&c, &[x]);
    t.take(&c2, &[y]);
    let mut tie = vec![x, y];
    tie.sort();
    assert_eq!(
        t.heads("q-tie"),
        tie,
        "equal mtime_ns: the smaller hash first"
    );
    same_on_a_reader(&a, &["p"]);
    out.push(json!({ "name": "two-edits-of-one-head", "heads": hashes(&a.heads("p")), "equal_mtime_heads": hashes(&t.heads("q-tie")) }));
    // A write covering both: one head again.
    a.apply("p");
    let both = a.put("p", 6);
    assert_eq!(a.heads("p"), vec![both]);
    same_on_a_reader(&a, &["p"]);
    out.push(json!({ "name": "a-write-covers-both", "heads": hashes(&a.heads("p")) }));
    // Two records with one dot and different bodies: both held, a conflict.
    let one = forge("dot", &[chunk(1)], &sealed_file("dot", dev(0xd0), 100), &[]);
    let mut m = sealed_file("dot", dev(0xd0), 100);
    m.mtime_ns = 6;
    m.plain_hashes = vec![vec![8; 32]];
    let other = forge("dot", &[chunk(2)], &m, &[]);
    for mut x in [Dev::writer(0xa0), Dev::reader(0xa1)] {
        x.accept(&one).unwrap();
        x.accept(&other).unwrap();
        assert_eq!(x.heads("dot").len(), 2);
    }
    out.push(json!({ "name": "two-records-with-one-dot", "records": hashes(&[one.hash(), other.hash()]) }));
    // A vector one below another record's counter does not cover it; equal
    // covers it.
    let held = forge("cov", &[chunk(1)], &sealed_file("cov", dev(0xd0), 50), &[]);
    for (counter, covered) in [(49u64, false), (50, true)] {
        let mut m = sealed_file("cov", dev(0xe0), 60);
        m.vector = vec![super::kit::entry(dev(0xd0), counter)];
        let later = forge("cov", &[chunk(2)], &m, &[]);
        let mut x = Dev::reader(0xa1);
        x.accept(&held).unwrap();
        x.accept(&later).unwrap();
        assert_eq!(x.holds(&held.hash()), !covered, "entry {counter}");
        out.push(json!({ "name": format!("vector-entry-{}-the-counter", if covered { "equal-to" } else { "one-below" }), "covered": covered }));
    }
    json!(out)
}

fn arrival_order() -> Value {
    let mut out = Vec::new();
    // An edit arriving before the version it covers: the version, after it,
    // is obsolete and ignored.
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("p", 1);
    let v2 = d.put("p", 2);
    let mut x = Dev::writer(0xa0);
    let j = x.take(&d, &[v2, v1]);
    assert_eq!(j, vec![Judgement::Held, Judgement::Obsolete]);
    same_on_a_reader(&x, &["p"]);
    out.push(json!({ "name": "an-edit-before-the-version-it-covers", "judgements": ["held", "obsolete"] }));
    // Every order of a chain of three edits by three devices.
    let mut a = Dev::writer(0xa0);
    let e1 = a.put("chain", 1);
    let mut b = Dev::writer(0xb0);
    b.take(&a, &[e1]);
    b.apply("chain");
    let e2 = b.put("chain", 2);
    let mut c = Dev::writer(0xc0);
    c.take(&b, &[e2]);
    c.apply("chain");
    let e3 = c.put("chain", 3);
    let chain = [(e1, &a), (e2, &b), (e3, &c)];
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut ends = BTreeSet::new();
    for o in orders {
        let mut x = Dev::reader(0xa1);
        for i in o {
            let (h, from) = chain[i];
            x.accept(from.signed(&h)).unwrap();
        }
        assert_eq!(x.heads("chain"), vec![e3], "order {o:?}");
        ends.insert(x.root());
    }
    assert_eq!(ends.len(), 1, "the same on every order");
    out.push(json!({ "name": "every-order-of-a-chain-of-three", "head": h(&e3.0) }));
    json!(out)
}

/// Two heads at one path: `first` from one device, `second` from another,
/// both over nothing, on a reader; its view, the same on a write holder.
fn pair(path: &str, first: Put, second: Put) -> crate::PathView {
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    let x = a.write(&[Change::Put(first)]).unwrap().records[0].0;
    let y = b.write(&[Change::Put(second)]).unwrap().records[0].0;
    let mut r = Dev::reader(0xa1);
    r.take(&a, &[x]);
    r.take(&b, &[y]);
    let mut w = Dev::writer(0xa9);
    w.take(&a, &[x]);
    w.take(&b, &[y]);
    let view = r.ix.path(path).unwrap();
    let on_w = w.ix.path(path).unwrap();
    assert_eq!(
        (
            &on_w.heads,
            &on_w.current,
            &on_w.conflict_copies,
            on_w.deleted
        ),
        (
            &view.heads,
            &view.current,
            &view.conflict_copies,
            view.deleted
        ),
        "a write holder shows it alike"
    );
    view
}

fn display_order() -> Value {
    let mut out = Vec::new();
    let v = pair("p", file("p", 1, 5), tombstone("p", Kind::File, 9));
    assert!(!v.heads[0].tombstone && v.conflict_copies.is_empty() && !v.deleted);
    out.push(json!({ "name": "a-file-and-a-tombstone", "shown": "the file", "copies": 0 }));
    let v = pair("p", file("p", 1, 9), dir("p", 5));
    assert_eq!(v.heads[0].kind, Kind::Directory);
    assert_eq!(v.conflict_copies.len(), 1, "the file a conflict copy");
    out.push(json!({ "name": "a-file-and-a-directory", "shown": "the directory", "copies": 1 }));
    let v = pair("p", file("p", 1, 9), file("p", 2, 5));
    assert_eq!(v.conflict_copies.len(), 1);
    out.push(json!({ "name": "two-files-with-different-plain-hashes", "copies": 1 }));
    let mut same = file("p", 1, 5);
    same.mode = 0o600;
    let v = pair("p", file("p", 1, 9), same);
    assert!(v.conflict_copies.is_empty(), "same content: no copy");
    assert_eq!(v.heads.len(), 2);
    out.push(json!({ "name": "two-files-with-the-same-plain-hashes", "copies": 0, "heads": 2 }));
    let v = pair("p", dir("p", 9), dir("p", 5));
    assert!(v.conflict_copies.is_empty());
    out.push(json!({ "name": "two-directories", "copies": 0 }));
    let v = pair(
        "p",
        tombstone("p", Kind::File, 9),
        tombstone("p", Kind::File, 5),
    );
    assert!(v.deleted && v.current.is_none());
    out.push(json!({ "name": "only-tombstones", "deleted": true }));
    json!(out)
}

fn pruning() -> Value {
    let mut out = Vec::new();
    // A line of versions by 40 devices in turn, each over the one before.
    let mut line: Vec<(RecordHash, Dev)> = Vec::new();
    let mut prev: Option<(RecordHash, licketysync_keys::records::SignedRecord)> = None;
    for i in 0..40u8 {
        let mut d = Dev::writer(0x10 + i);
        if let Some((_, s)) = &prev {
            d.accept(s).unwrap();
            d.apply("line");
        }
        let v = d.put("line", i);
        prev = Some((v, d.signed(&v).clone()));
        line.push((v, d));
    }
    let vectors: Vec<usize> = line
        .iter()
        .map(|(v, d)| d.ix.s.held[v].meta().unwrap().vector.len())
        .collect();
    assert!(vectors.iter().all(|n| *n <= MAX_VECTOR_ENTRIES));
    assert_eq!(vectors[39], MAX_VECTOR_ENTRIES);
    // The 40th's vector dropped the 7 smallest counters: the first 7 writers.
    let last = &line[39];
    let lv = &last.1.ix.s.held[&last.0].meta().unwrap().vector;
    for i in 0..7u8 {
        assert_eq!(lv.get(&dev(0x10 + i)), 0, "writer {i} pruned");
    }
    assert!(lv.get(&dev(0x10 + 7)) > 0);
    same_on_a_reader(&last.1, &["line"]);
    // Each version covers the one before.
    for k in 1..40 {
        let (vk, dk) = &line[k];
        assert!(!dk.holds(&line[k - 1].0), "{k} covers {}", k - 1);
        assert!(dk.holds(vk));
    }
    // A device holding the 5th receives the 40th: both heads (the spurious
    // conflict, nothing dropped); one holding the 20th: covered, dropped.
    let mut fifth = Dev::reader(0xa1);
    fifth.accept(line[4].1.signed(&line[4].0)).unwrap();
    fifth.accept(last.1.signed(&last.0)).unwrap();
    assert_eq!(fifth.heads("line").len(), 2);
    let mut twentieth = Dev::reader(0xa2);
    twentieth.accept(line[19].1.signed(&line[19].0)).unwrap();
    twentieth.accept(last.1.signed(&last.0)).unwrap();
    assert_eq!(twentieth.heads("line"), vec![last.0]);
    // A write over the 40th and an old concurrent version X: S's two dots
    // and the 40th's 32 entries make 34, pruned to 32. X's entry has the
    // smallest counter, but it is mandatory (X is in S), so the write covers
    // what X covered too: a holder of the version before X drops it when the
    // write arrives (names reach only S itself).
    let mut old_dev = Dev::writer(0x5f);
    old_dev.clock = T0 - 1_000 * SEC;
    let before_x = old_dev.put("line", 76);
    let x = old_dev.put("line", 77);
    let mut over_both = Dev::writer(0xa7);
    over_both.accept(last.1.signed(&last.0)).unwrap();
    over_both.accept(old_dev.signed(&x)).unwrap();
    over_both.apply("line");
    assert_eq!(over_both.ix.bases("line").len(), 2);
    let top = over_both.put("line", 78);
    assert_eq!(over_both.heads("line"), vec![top]);
    same_on_a_reader(&over_both, &["line"]);
    let mut holder = Dev::reader(0xa8);
    holder.take(&old_dev, &[before_x]);
    let a = holder.accept(over_both.signed(&top)).unwrap();
    assert_eq!(
        a.dropped,
        vec![before_x],
        "covered through X's mandatory entry"
    );
    out.push(json!({
        "name": "a-line-of-40-devices",
        "vector_lengths": vectors,
        "holder_of_the_5th_heads": 2,
        "holder_of_the_20th_heads": 1,
    }));
    // A write over 33 heads: 32 covered, one left a head. The first device
    // wrote earlier (the smallest counter) and last in time on disk (the
    // greatest mtime_ns, so first in display order and in S): its entry is
    // mandatory, and pruning by counter alone would drop it.
    let mut w = Dev::writer(0xa0);
    let mut heads = Vec::new();
    for i in 0..33u8 {
        let mut d = Dev::writer(0x60 + i);
        if i == 0 {
            d.clock = T0 - 1_000 * SEC;
            d.mtime = 900_000;
        }
        let v = d.put("many", i);
        w.accept(d.signed(&v)).unwrap();
        heads.push(v);
    }
    w.apply("many");
    assert_eq!(w.ix.bases("many").len(), 33);
    // S is the earliest device's record, then 31 others by record hash
    // (equal mtime_ns): the one left out is the greatest hash among those.
    let excluded = *heads[1..].iter().max().unwrap();
    let over = w.put("many", 99);
    let mut left = w.heads("many");
    left.sort();
    let mut want = vec![over, excluded];
    want.sort();
    assert_eq!(left, want, "the write and the one head S left out");
    same_on_a_reader(&w, &["many"]);
    out.push(json!({ "name": "a-write-over-33-heads", "heads_left": 2 }));
    // 32 heads under one write: all covered (the mandatory entries fit).
    let mut w = Dev::writer(0xa0);
    for i in 0..32u8 {
        let mut d = Dev::writer(0x60 + i);
        let v = d.put("thirty-two", i);
        w.accept(d.signed(&v)).unwrap();
    }
    w.apply("thirty-two");
    let over = w.put("thirty-two", 99);
    assert_eq!(w.heads("thirty-two"), vec![over]);
    same_on_a_reader(&w, &["thirty-two"]);
    out.push(json!({ "name": "32-heads-under-one-write", "heads_left": 1 }));
    json!(out)
}

fn restored_device() -> Value {
    // D's index restored from before its edit R1; D edits again while its
    // peer holds R1: both end with two heads, nothing lost, and D's mark has
    // moved past R1's counter.
    let mut d = Dev::writer(0xd0);
    let v = d.put("p", 1);
    let backup = d.store.clone();
    let r1 = d.put("p", 2);
    let mut peer = Dev::writer(0xb0);
    peer.take(&d, &[v, r1]);
    d.store = backup;
    let report = d.reopen();
    assert!(report.is_clean());
    assert!(d.holds(&v) && !d.holds(&r1));
    let r2 = d.put("p", 3);
    let back = d.take(&peer, &[r1]);
    peer.take(&d, &[r2]);
    assert_eq!(back, vec![Judgement::Held]);
    let mut both = vec![r1, r2];
    both.sort();
    let mut dh = d.heads("p");
    dh.sort();
    let mut ph = peer.heads("p");
    ph.sort();
    assert_eq!(dh, both, "a conflict, nothing lost");
    assert_eq!(ph, both);
    same_on_a_reader(&d, &["p"]);
    same_on_a_reader(&peer, &["p"]);
    let r1_counter = peer.ix.s.held[&r1].meta().unwrap().dot.counter;
    assert!(d.ix.hw() >= r1_counter);
    json!({ "heads": hashes(&both), "hw_past_r1": d.ix.hw() >= r1_counter })
}

/// The lost update (rulings R1 B2 and S-1): S is the bases, never the
/// records held.
pub(crate) fn lost_update_s1() -> Value {
    let mut a = Dev::writer(0xa0);
    let v1 = a.put("f", 1);
    let mut d = Dev::writer(0xd0);
    d.take(&a, &[v1]);
    d.apply("f");
    let v2 = a.put("f", 2);
    // D holds V2, which covers V1, but its disk still holds V1.
    d.take(&a, &[v2]);
    assert_eq!(d.heads("f"), vec![v2]);
    assert_eq!(d.ix.current("f").unwrap().hash, v1, "V1 its base");
    assert!(!d
        .ix
        .subtree(&licketysync_protocol::exchange::Prefix::ROOT)
        .contains(&v1));
    let w = d.put("f", 3);
    let mut heads = d.heads("f");
    heads.sort();
    let mut want = vec![v2, w];
    want.sort();
    assert_eq!(heads, want, "W covers V1 only: V2 and W are both heads");
    same_on_a_reader(&d, &["f"]);
    // V1 is never served or counted.
    let root_without = d.root();
    assert!(!d
        .ix
        .subtree(&licketysync_protocol::exchange::Prefix::ROOT)
        .contains(&v1));
    // The tree delete variant: V2 survives a scan's tree delete of the
    // directory holding the path.
    let mut a = Dev::writer(0xa0);
    let u1 = a.put("dir/f", 1);
    let mut d = Dev::writer(0xd0);
    d.take(&a, &[u1]);
    d.apply("dir/f");
    let u2 = a.put("dir/f", 2);
    d.take(&a, &[u2]);
    d.tree_delete("dir");
    assert!(d.holds(&u2), "V2 survives: a file that comes back");
    same_on_a_reader(&d, &["dir", "dir/f"]);
    json!({ "heads_after_the_edit": hashes(&want), "root": h(root_without.as_bytes()), "v2_survives_the_tree_delete": true })
}

fn conflict_copy_promoted() -> Value {
    // A conflict copy beside the path: its record a base of the path's file
    // ID; after a write over the conflict that makes it a version at its own
    // path, the base of its own path and no longer of the original.
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    a.mtime = 10_000;
    b.mtime = 20_000;
    let x = a.put("doc", 1);
    let y = b.put("doc", 2);
    a.take(&b, &[y]);
    a.apply("doc");
    let bases = a.ix.bases("doc");
    assert_eq!(bases.len(), 2);
    let copy = bases
        .iter()
        .find_map(|(p, h)| match p {
            Place::Copy(name) => Some((name.clone(), *h)),
            Place::Path => None,
        })
        .unwrap();
    assert_eq!(copy.1, x, "the earlier mtime is the copy");
    let m = 30_000;
    let promoted = a
        .write(&[
            Change::Promote {
                from: "doc".into(),
                copy: copy.0.clone(),
                to: file("doc (conflict)", 1, m),
            },
            Change::Put(file("doc", 3, m)),
        ])
        .unwrap();
    assert_eq!(promoted.records.len(), 2);
    let copy_version = a.heads("doc (conflict)")[0];
    assert!(a.ix.bases("doc").iter().all(|(p, _)| *p == Place::Path));
    assert_eq!(
        a.ix.bases("doc (conflict)"),
        vec![(Place::Path, copy_version)]
    );
    same_on_a_reader(&a, &["doc", "doc (conflict)"]);
    json!({ "copy_base_before": h(&x.0), "own_path_after": h(&copy_version.0) })
}

fn clock_set_back_at_open() -> Value {
    // A store whose newest applied record lies more than CLOCK_RULE_LIMIT
    // ahead of the clock at open: the folder does not open, nothing is
    // removed, the mark kept; once the clock passes the time it needs, it
    // opens; opened with the clock right, it opens.
    let mut d = Dev::writer(0xd0);
    d.put("p", 1);
    let newest = d.ix.folder_time();
    let hw = d.ix.hw();
    let held = d.all();
    d.clock = T0 - CLOCK_RULE_LIMIT - 2 * SEC;
    let report = d.reopen();
    let opens_at = report.opens_at.unwrap();
    assert_eq!(opens_at, newest - CLOCK_RULE_LIMIT);
    assert_eq!(d.all(), held, "nothing removed");
    assert_eq!(d.ix.hw(), hw, "the mark kept");
    d.clock = opens_at;
    assert_eq!(d.reopen().opens_at, None, "opens once the clock reaches it");
    d.clock = T0;
    assert!(d.reopen().is_clean());
    same_on_a_reader(&d, &["p"]);
    json!({ "opens_at": opens_at, "newest_counter": newest })
}

fn base_failing_at_open() -> Value {
    // A base that fails its check at open: dropped and reported; the next
    // write covers nothing, a conflict.
    let mut a = Dev::writer(0xa0);
    let v1 = a.put("f", 1);
    let mut d = Dev::writer(0xd0);
    d.take(&a, &[v1]);
    d.apply("f");
    let v2 = a.put("f", 2);
    d.take(&a, &[v2]);
    // V1 is kept only as a base now; damage it at rest.
    let mut stored = d.store.load().unwrap();
    assert_eq!(stored.base_only.len(), 1);
    stored.base_only[0] = super::kit::flipped_body(&stored.base_only[0]);
    let mut rng = d.rng.clone();
    let (ix, report) = crate::Index::open(
        super::kit::folder_key(licketysync_keys::Tier::Write),
        d.id(),
        stored,
        d.clock,
        &mut |b| rng.fill(b),
    );
    d.ix = ix;
    assert_eq!(report.dropped.len(), 1, "dropped and reported");
    assert!(report.epoch_redrawn);
    let w = d.put("f", 3);
    let mut heads = d.heads("f");
    heads.sort();
    let mut want = vec![v2, w];
    want.sort();
    assert_eq!(heads, want, "the next write covers nothing: a conflict");
    same_on_a_reader(&d, &["f"]);
    json!({ "dropped": hashes(&report.dropped), "heads": hashes(&want) })
}

fn renames() -> Value {
    let mut out = Vec::new();
    let mut d = Dev::writer(0xd0);
    let v = d.put("old", 1);
    d.apply("old");
    let written = d.rename("old", "new");
    let (version, tomb) = (written.records[0].0, written.records[1].0);
    assert_eq!(d.heads("new"), vec![version]);
    let old = d.ix.path("old").unwrap();
    assert!(old.deleted && old.heads.len() == 1 && old.heads[0].tombstone);
    same_on_a_reader(&d, &["old", "new"]);
    for order in [[version, tomb], [tomb, version]] {
        let mut r = Dev::reader(0xa1);
        r.take(&d, &[v]);
        r.take(&d, &order);
        assert_eq!(r.heads("new"), vec![version]);
        assert_eq!(r.heads("old"), vec![tomb]);
        out.push(json!({ "order": hashes(&order), "new": h(&version.0), "old": h(&tomb.0) }));
    }
    json!(out)
}

fn opaque_and_shared_faults() -> Value {
    let mut out = Vec::new();
    // An opaque record beside the one head: both kept; the next write names
    // it (a shared writer fault), and every tier drops it.
    let mut d = Dev::writer(0xd0);
    let head = d.put("f", 1);
    let mut m = sealed_file("f", dev(0xe0), T0 + 5);
    m.tree = true;
    let bad = forge("f", &[chunk(2)], &m, &[]);
    d.accept(&bad).unwrap();
    assert!(d.holds(&bad.hash()) && d.holds(&head));
    let mut r = Dev::reader(0xa1);
    let mut s = Dev::sealed(0xa2);
    for x in [&mut r, &mut s] {
        x.take(&d, &[head]);
        x.accept(&bad).unwrap();
    }
    d.apply("f");
    let next = d.put("f", 3);
    assert!(!d.holds(&bad.hash()));
    same_on_a_reader(&d, &["f"]);
    for x in [&mut r, &mut s] {
        let a = x.accept(d.signed(&next)).unwrap();
        assert!(a.dropped.contains(&bad.hash()), "every tier drops it");
    }
    out.push(json!({ "name": "an-opaque-record-beside-the-head-sr-1", "named_by": h(&next.0) }));
    // 70 shared writer faults at one path: the next write names its bases
    // and as many as fit 64 names, and a cleanup because it, in the same
    // commit, names the rest.
    let mut d = Dev::writer(0xd0);
    let head = d.put("g", 1);
    d.apply("g");
    let mut faults = Vec::new();
    for i in 0..70u64 {
        let mut m = sealed_file("g", dev(0xe0), T0 + 10 + i);
        m.tree = true;
        let bad = forge("g", &[chunk(2)], &m, &[]);
        d.accept(&bad).unwrap();
        faults.push(bad.hash());
    }
    let written = d.write(&[Change::Put(file("g", 5, 99_000))]).unwrap();
    assert!(written.cleanup, "a cleanup because the write");
    assert_eq!(written.records.len(), 2);
    let names = d.ix.s.held[&written.records[0].0].record.replaces().len();
    assert_eq!(names, MAX_REPLACES, "its base and 63 faults");
    assert!(faults.iter().all(|f| !d.holds(f)), "all 70 gone");
    assert!(!d.holds(&head));
    same_on_a_reader(&d, &["g"]);
    out.push(json!({ "name": "70-shared-writer-faults-sr-1", "names": names, "cleanup": true }));
    // A record opaque only because its kind is unknown: the next write here
    // neither names nor covers it.
    let mut d = Dev::writer(0xd0);
    d.put("k", 1);
    d.apply("k");
    let mut m = sealed_file("k", dev(0xe0), T0 + 5);
    m.kind = 3;
    let newer = forge("k", &[chunk(2)], &m, &[]);
    d.accept(&newer).unwrap();
    let w = d.put("k", 4);
    assert!(d.holds(&newer.hash()), "not named, not covered");
    assert!(!d.ix.s.held[&w].record.replaces().contains(&newer.hash()));
    same_on_a_reader(&d, &["k"]);
    out.push(json!({ "name": "an-unknown-kind", "kept": true }));
    json!(out)
}

fn tree_deletes() -> Value {
    let mut out = Vec::new();
    // Over a directory of three files and a subdirectory: every record
    // beneath it dropped on a read holder, the cleanup naming the four.
    let mut d = Dev::writer(0xd0);
    let files: Vec<RecordHash> = vec![
        d.put("dir/a", 1),
        d.put("dir/b", 2),
        d.put("dir/c", 3),
        d.mkdir("dir/sub"),
    ];
    d.apply_all();
    let written = d.tree_delete("dir");
    let tree = written.records[0].0;
    assert!(written.cleanup);
    let cleanup_hash = written.records.last().unwrap().0;
    let named: BTreeSet<RecordHash> = d.ix.s.held[&cleanup_hash]
        .record
        .groups()
        .iter()
        .flat_map(|g| g.forget.clone())
        .collect();
    assert_eq!(named, files.iter().copied().collect::<BTreeSet<_>>());
    let mut r = Dev::reader(0xa1);
    r.take(&d, &files);
    r.take(&d, &[tree, cleanup_hash]);
    assert!(files.iter().all(|f| !r.holds(f)), "dropped beneath it");
    same_on_a_reader(&d, &["dir", "dir/a", "dir/b", "dir/c", "dir/sub"]);
    out.push(json!({ "name": "over-three-files-and-a-subdirectory", "cleanup_names": 4 }));
    // A version beneath it written concurrently: kept, a head.
    let mut e = Dev::writer(0xe0);
    let concurrent = e.put("dir/new", 7);
    r.take(&e, &[concurrent]);
    assert_eq!(r.heads("dir/new"), vec![concurrent]);
    out.push(json!({ "name": "a-concurrent-version-beneath-it", "kept": true }));
    // The residual of "Why it is safe" 8a, the rename within the directory:
    // E renames P/a to P/b (a version at P/b, then a tombstone at P/a); the
    // deleter received only the tombstone, and its tree delete of P covers
    // the version at P/b, which it never saw: ignored at a holder of the
    // tree delete, dropped at one that held the version first.
    let mut e = Dev::writer(0xe0);
    let a0 = e.put("P/a", 1);
    e.apply("P/a");
    let renamed = e.rename("P/a", "P/b");
    let (pb, pa_tomb) = (renamed.records[0].0, renamed.records[1].0);
    let mut d = Dev::writer(0xd0);
    d.take(&e, &[a0, pa_tomb]);
    d.apply_all();
    let td = d.tree_delete("P").records[0].0;
    let mut late = Dev::reader(0xa1);
    late.take(&d, &[td]);
    assert_eq!(
        late.take(&e, &[pb]),
        vec![Judgement::Obsolete],
        "tombstone first: P/b goes too"
    );
    let mut early = Dev::reader(0xa2);
    early.take(&e, &[pb]);
    let dropped = early.accept(d.signed(&td)).unwrap().dropped;
    assert_eq!(dropped, vec![pb]);
    out.push(json!({ "name": "the-8a-residual-a-rename-within-the-directory", "ignored_after": true, "dropped_before": hashes(&dropped) }));
    // Dropped at once beneath a tree delete (step 8): a record that replaces
    // something held (here a shared writer fault it names) but that a held
    // tree delete covers is verified, drops what it replaces, and is not
    // held or numbered.
    let mut m = sealed_file("Q/x", dev(0xe1), T0 + 1);
    m.tree = true;
    let fault = forge("Q/x", &[chunk(2)], &m, &[]);
    let mut e = Dev::writer(0xe0);
    e.accept(&fault).unwrap();
    let e1 = e.put("Q/x", 1);
    let mut d = Dev::writer(0xd0);
    d.take(&e, &[e1]);
    d.apply_all();
    let td = d.tree_delete("Q").records[0].0;
    let mut l = Dev::reader(0xa3);
    l.accept(&fault).unwrap();
    l.take(&d, &[td]);
    let a = l.accept(e.signed(&e1)).unwrap();
    assert_eq!(a.judgement, Judgement::DroppedBeneath);
    assert_eq!(a.seq, None);
    assert_eq!(a.dropped, vec![fault.hash()]);
    out.push(json!({ "name": "dropped-at-once-beneath-a-tree-delete", "judgement": "dropped beneath a tree delete" }));
    // Nested tree deletes: a second of the same directory covers the first,
    // which its cleanup names; a parent's covers a child's.
    let mut d = Dev::writer(0xd0);
    d.put("n/c/f", 1);
    d.apply_all();
    let child = d.tree_delete("n/c").records[0].0;
    d.apply("n/c");
    d.put("n/g", 2);
    d.apply_all();
    let parent = d.tree_delete("n");
    assert!(
        !d.holds(&child),
        "the parent's tree delete covers the child's"
    );
    assert!(parent.cleanup);
    same_on_a_reader(&d, &["n", "n/c", "n/c/f", "n/g"]);
    out.push(json!({ "name": "nested-tree-deletes", "child_dropped": true }));
    // A second tree delete of the same directory covers the first, which it
    // names, its base there.
    let mut d = Dev::writer(0xd0);
    d.put("s/f", 1);
    d.apply_all();
    let first = d.tree_delete("s").records[0].0;
    d.apply("s");
    let second = d.tree_delete("s");
    assert!(!d.holds(&first));
    let names: Vec<RecordHash> = second
        .records
        .iter()
        .filter_map(|(h, _)| d.ix.s.held.get(h))
        .flat_map(|r| r.record.replaces().to_vec())
        .collect();
    assert!(names.contains(&first), "named by the second, its base");
    same_on_a_reader(&d, &["s", "s/f"]);
    out.push(
        json!({ "name": "a-second-tree-delete-of-the-same-directory", "first_dropped": true }),
    );
    // A tree delete whose pruned vector misses a held record: the tombstone
    // written after it in the same commit.
    let mut d = Dev::writer(0xd0);
    for i in 0..33u8 {
        let mut e = Dev::writer(0x60 + i);
        let v = e.put(&format!("big/f{i:02}"), i);
        d.take(&e, &[v]);
    }
    d.apply_all();
    let written = d.tree_delete("big");
    let tombs: Vec<String> = written
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
    assert_eq!(tombs.len(), 1, "one device's file the pruned vector missed");
    assert!(d.ix.path(&tombs[0]).unwrap().deleted);
    let big: Vec<String> = (0..33u8).map(|i| format!("big/f{i:02}")).collect();
    let big: Vec<&str> = big.iter().map(String::as_str).chain(["big"]).collect();
    same_on_a_reader(&d, &big);
    out.push(json!({ "name": "a-pruned-tree-delete-and-its-tombstone", "tombstones": tombs }));
    // A new file written beneath it afterwards: kept.
    let mut d = Dev::writer(0xd0);
    d.put("m/f", 1);
    d.apply_all();
    d.tree_delete("m");
    let after = d.put("m/g", 2);
    assert_eq!(d.heads("m/g"), vec![after]);
    same_on_a_reader(&d, &["m", "m/f", "m/g"]);
    out.push(json!({ "name": "a-new-file-beneath-it-afterwards", "kept": true }));
    json!(out)
}

/// Expiry by the folder's own time (B1 of all three reviewers: never by the
/// local clock).
pub(crate) fn expiry_b1() -> Value {
    let mut out = Vec::new();
    for (by, kept) in [
        (TOMBSTONE_HORIZON - 1, true),
        (TOMBSTONE_HORIZON, true),
        (TOMBSTONE_HORIZON + 1, false),
    ] {
        // The same history on two devices whose wall clocks differ by six
        // months: the same outcome.
        let mut outcomes = Vec::new();
        for skew in [0, 182 * DAY] {
            let t = forge(
                "t",
                &[],
                &{
                    let mut m = sealed_file("t", dev(0xd0), T0);
                    m.deleted = true;
                    m.size = 0;
                    m.plain_hashes.clear();
                    m
                },
                &[],
            );
            let later = forge("u", &[chunk(1)], &sealed_file("u", dev(0xd0), T0 + by), &[]);
            let mut x = Dev::reader(0xa1);
            x.clock = T0 + by + skew;
            x.accept(&t).unwrap();
            x.accept(&later).unwrap();
            outcomes.push(x.holds(&t.hash()));
            if !kept {
                assert_eq!(
                    x.judge(&t),
                    Ok(Judgement::Expired),
                    "ignored when it arrives again"
                );
            }
        }
        assert_eq!(outcomes, vec![kept, kept], "the same on both clocks");
        let name = match by.cmp(&TOMBSTONE_HORIZON) {
            core::cmp::Ordering::Less => "a-tombstone-exceeded-by-the-horizon-less-one-microsecond",
            core::cmp::Ordering::Equal => "a-tombstone-exceeded-by-exactly-the-horizon",
            core::cmp::Ordering::Greater => {
                "a-tombstone-exceeded-by-the-horizon-plus-one-microsecond"
            }
        };
        out.push(json!({ "name": name, "kept": kept }));
    }
    // A cleanup past CLEANUP_HORIZON.
    let c = super::kit::cleanup(dev(0xd0), T0, &[(None, vec![RecordHash([1; 32])])]);
    let later = forge(
        "u",
        &[chunk(1)],
        &sealed_file("u", dev(0xd0), T0 + CLEANUP_HORIZON + 1),
        &[],
    );
    let mut x = Dev::reader(0xa1);
    x.accept(&c).unwrap();
    x.accept(&later).unwrap();
    assert!(!x.holds(&c.hash()));
    out.push(json!({ "name": "a-cleanup-past-its-horizon", "kept": false }));
    // A folder with no write for two years: nothing expires.
    let mut d = Dev::writer(0xd0);
    d.put("z", 1);
    let t = d.delete("z");
    d.clock = T0 + 730 * DAY;
    let report = d.reopen();
    assert!(report.is_clean());
    assert!(d.holds(&t), "the folder's time stands still");
    same_on_a_reader(&d, &["z"]);
    out.push(json!({ "name": "no-write-for-two-years", "kept": true }));
    // A record 11 months ahead raises the folder's time: deletions older than
    // that time less the horizon are forgotten at once.
    let mut x = Dev::reader(0xa1);
    let old = forge(
        "o",
        &[],
        &{
            let mut m = sealed_file("o", dev(0xd0), T0 - 40 * DAY);
            m.deleted = true;
            m.size = 0;
            m.plain_hashes.clear();
            m
        },
        &[],
    );
    x.accept(&old).unwrap();
    let ahead = forge(
        "a",
        &[chunk(1)],
        &sealed_file("a", dev(0xf0), T0 + 330 * DAY),
        &[],
    );
    let a = x.accept(&ahead).unwrap();
    assert_eq!(a.dropped, vec![old.hash()]);
    out.push(json!({ "name": "a-record-11-months-ahead", "forgotten": 1 }));
    // The version a tombstone covered, offered again after the tombstone
    // expired: live again.
    let mut d = Dev::writer(0xd0);
    let v = d.put("back", 1);
    d.apply("back");
    let t = d.delete("back");
    let mut x = Dev::reader(0xa1);
    x.take(&d, &[t]);
    x.clock = T0 + TOMBSTONE_HORIZON + 10 * SEC;
    let raise = forge(
        "r",
        &[chunk(1)],
        &sealed_file("r", dev(0xd1), T0 + TOMBSTONE_HORIZON + 5 * SEC),
        &[],
    );
    x.accept(&raise).unwrap();
    assert!(!x.holds(&t));
    assert_eq!(
        x.take(&d, &[v]),
        vec![Judgement::Held],
        "the deleted file reappears"
    );
    out.push(json!({ "name": "a-version-after-its-tombstone-expired", "live_again": true }));
    json!(out)
}

/// Holds `records` at `d` as an open would, without verifying them.
fn hold_directly(d: &mut Dev, records: &[licketysync_keys::records::SignedRecord]) {
    for r in records {
        let record = Record::parse(r.clone(), write_key().verifier()).unwrap();
        let verdict = d.ix.verdict(&record);
        let seq = d.ix.s.meta.next_seq;
        d.ix.s.meta.next_seq += 1;
        d.ix.s.hold(
            crate::state::Held {
                record,
                seq,
                verdict,
            },
            None,
        );
    }
}

/// What a walk over every applied record held at or beneath `dir` finds
/// that `vector` covers: the definition the index must agree with.
fn walk_covered(
    d: &Dev,
    dir: &str,
    vector: &licketysync_protocol::record::Vector,
) -> BTreeSet<RecordHash> {
    d.ix.s
        .held
        .iter()
        .filter_map(|(h, r)| Some((*h, r.meta()?)))
        .filter(|(_, m)| {
            licketysync_protocol::record::at_or_beneath(&m.path, dir) && vector.covers(&m.dot)
        })
        .map(|(h, _)| h)
        .collect()
}

/// A tree delete of `dir` by `device` at `counter`, its vector `entries`.
fn tree_delete_record(
    dir: &str,
    device: u8,
    counter: u64,
    entries: &[(u8, u64)],
) -> licketysync_keys::records::SignedRecord {
    let mut m = sealed_file(dir, dev(device), counter);
    m.kind = 2;
    m.size = 0;
    m.plain_hashes.clear();
    m.deleted = true;
    m.tree = true;
    m.vector = entries
        .iter()
        .map(|(d, c)| super::kit::entry(dev(*d), *c))
        .collect();
    forge(dir, &[], &m, &[])
}

/// The base slots at or beneath a directory are read from the path-ordered
/// index of the slots, never a walk of every slot (TM-22; the engine port's
/// security review, EP-S1): `bases_beneath`, which the engine's views and
/// the simulator's oracle use. At a read holder with 20 000 files at `d/…`,
/// a file `e` with ten files at `e/…`, and neighbours that sort beside `e`'s
/// runs (`e-x`, `e.x`, `e0`), each file its path's base: the slots at or
/// beneath a directory are what a walk finds, read in as many entries as
/// they hold; and a tree delete of `e` that covers `e` and its ten, not its
/// neighbours, drops those eleven. (What the engine reads when it holds a
/// tree delete, only the paths where it dropped records, is the engine's
/// test.)
#[test]
fn the_base_slots_beneath_a_directory_are_read_by_range_ep_s1() {
    use licketysync_protocol::record::at_or_beneath;
    let mut r = Dev::reader(0xa1);
    let mut paths: Vec<(String, u8)> = (0..20_000).map(|i| (format!("d/{i:05}"), 0x31)).collect();
    paths.push(("e".to_string(), 0x32));
    paths.extend((0..10).map(|i| (format!("e/{i}"), 0x32)));
    paths.extend(["e-x", "e.x", "e0"].map(|p| (p.to_string(), 0x33)));
    let files: Vec<_> = paths
        .iter()
        .enumerate()
        .map(|(i, (p, d))| {
            super::kit::unsigned(
                p,
                &[chunk(1)],
                &sealed_file(p, dev(*d), T0 + 1 + i as u64),
                &[],
            )
        })
        .collect();
    hold_directly(&mut r, &files);
    let mut txn = r.ix.begin();
    for ((p, _), f) in paths.iter().zip(&files) {
        txn.set_base(p, Place::Path, Some(f.hash())).unwrap();
    }
    let (changes, pending) = txn.finish();
    r.store.commit(&changes).unwrap();
    pending.commit();
    for dir in ["e", "d", "e/3", "e-x", "d/0000", "nothing"] {
        let walk: Vec<&str> = r.ix.paths().filter(|p| at_or_beneath(p, dir)).collect();
        let _ = r.ix.s.beneath_read.take();
        let got: Vec<&str> = r.ix.bases_beneath(dir).map(|(p, _, _)| p).collect();
        assert_eq!(got, walk, "{dir}: the slots a walk finds, one a file");
        assert_eq!(
            r.ix.s.beneath_read.take(),
            2 * got.len(),
            "{dir}: a file ID and its slot each"
        );
    }
    // The root, `""`, is every slot.
    assert_eq!(r.ix.bases_beneath("").count(), r.ix.paths().count());
    // A tree delete of `e` that covers `e` and `e/…`, not its neighbours.
    let tree = tree_delete_record("e", 0x44, T0 + 40_000, &[(0x32, T0 + 30_000)]);
    let a = r.accept(&tree).unwrap();
    assert_eq!(a.judgement, Judgement::Held);
    assert_eq!(a.dropped.len(), 11, "e and its ten");
    let mut at: Vec<&str> = a.paths.iter().map(String::as_str).collect();
    at.sort_unstable();
    at.dedup();
    assert!(
        at.contains(&"e") && at.contains(&"e/9") && !at.contains(&"e-x"),
        "{at:?}"
    );
}

/// 4.4 "Judging a tree delete without a walk" (`protocol.md` 8 item 7; the
/// coordinator's ruling IS-1(b)): a tree delete over 20 000 held files
/// judged with at most two queries per vector entry and no walk, obsolete or
/// not as a walk would judge it; one at `d` beside held records at `d-x`,
/// `d.x`, `d0` and `d/x`; and one that covers only an earlier tree delete
/// beneath its directory.
fn tree_deletes_by_the_index() -> Value {
    let mut out = Vec::new();
    let mut r = Dev::reader(0xa1);
    let n = 20_000u64;
    let files: Vec<_> = (0..n)
        .map(|i| {
            let p = format!("d/{i:05}");
            super::kit::unsigned(
                &p,
                &[chunk(1)],
                &sealed_file(&p, dev(0x31), T0 + 1 + i),
                &[],
            )
        })
        .collect();
    hold_directly(&mut r, &files);
    assert_eq!(r.ix.len(), 20_000);
    // A held tree delete of d by F that covers only E's records, so that an
    // older tree delete of E's at d is covered by it.
    let tf = tree_delete_record("d", 0x41, T0 + 30_000, &[(0x42, T0 + 25_000)]);
    r.accept(&tf).unwrap();
    assert_eq!(r.ix.len(), 20_001, "it covers none of the files");
    // E's older tree delete: its vector covers nothing held beneath d, and
    // F's covers it: obsolete, judged with at most two queries, no walk.
    let te = tree_delete_record("d", 0x42, T0 + 20_500, &[(0x43, 5)]);
    let te_meta =
        r.ix.verdict(&Record::parse(te.clone(), write_key().verifier()).unwrap())
            .unwrap()
            .unwrap();
    assert!(
        walk_covered(&r, "d", &te_meta.meta().unwrap().vector).is_empty(),
        "a walk: covers nothing held"
    );
    r.ix.s.by_path.queries.set(0);
    r.ix.s.by_path.visited.set(0);
    let j = r.judge(&te).unwrap();
    assert_eq!(j, Judgement::Obsolete);
    assert_eq!(
        r.ix.s.by_path.queries.get(),
        2,
        "judged through the index: two queries for its one entry, not a walk"
    );
    assert_eq!(
        r.ix.s.by_path.visited.get(),
        0,
        "its device holds nothing here"
    );
    // A tree delete that covers the 20 000: not obsolete, held, every file
    // dropped, the same as a walk finds.
    let tc = tree_delete_record("d", 0x44, T0 + 40_000, &[(0x31, T0 + n)]);
    let tc_meta =
        r.ix.verdict(&Record::parse(tc.clone(), write_key().verifier()).unwrap())
            .unwrap()
            .unwrap();
    let walked = walk_covered(&r, "d", &tc_meta.meta().unwrap().vector);
    assert_eq!(walked.len(), 20_000);
    // Its judgement (step 3: does it replace anything held?) asks the index
    // once or twice and visits a few dozen of its nodes, not the 20 000 files
    // beneath it (the security review's CS-1).
    let tc_record = Record::parse(tc.clone(), write_key().verifier()).unwrap();
    r.ix.s.by_path.queries.set(0);
    r.ix.s.by_path.visited.set(0);
    assert!(r.ix.s.replaces_any(&tc_record, Some(&tc_meta)));
    let (queries, visited) = (r.ix.s.by_path.queries.get(), r.ix.s.by_path.visited.get());
    assert!((1..=2).contains(&queries), "{queries} queries");
    assert!(
        visited <= 100,
        "{visited} nodes visited for 20 000 files beneath"
    );
    let a = r.accept(&tc).unwrap();
    assert_eq!(a.judgement, Judgement::Held);
    let dropped: BTreeSet<RecordHash> = a.dropped.iter().copied().collect();
    assert_eq!(dropped, walked, "the records a walk finds, and no other");
    out.push(json!({ "name": "a-tree-delete-over-20000-files", "obsolete_one": "obsolete", "covering_one_dropped": a.dropped.len(), "queries_per_entry": 2 }));
    // One at d beside records at d-x, d.x, d0 and d/x: only d itself and
    // d/x are at or beneath it.
    let mut x = Dev::reader(0xa2);
    let beside: Vec<_> = ["d", "d-x", "d.x", "d0", "d/x"]
        .iter()
        .enumerate()
        .map(|(i, p)| {
            forge(
                p,
                &[chunk(1)],
                &sealed_file(p, dev(0x31), T0 + 1 + i as u64),
                &[],
            )
        })
        .collect();
    for b in &beside {
        x.accept(b).unwrap();
    }
    let t = tree_delete_record("d", 0x44, T0 + 200, &[(0x31, T0 + 100)]);
    let a = x.accept(&t).unwrap();
    assert_eq!(a.judgement, Judgement::Held);
    let mut got = a.dropped.clone();
    got.sort();
    let mut want = vec![beside[0].hash(), beside[4].hash()];
    want.sort();
    assert_eq!(got, want, "d and d/x only");
    out.push(json!({ "name": "d-beside-d-x-d.x-d0-and-d/x", "dropped": hashes(&got) }));
    // One that covers only an earlier tree delete beneath its directory: not
    // obsolete, it replaces that one.
    let mut y = Dev::reader(0xa3);
    let other = forge(
        "e/c/f",
        &[chunk(1)],
        &sealed_file("e/c/f", dev(0x51), T0 + 1),
        &[],
    );
    y.accept(&other).unwrap();
    let child = tree_delete_record("e/c", 0x52, T0 + 10, &[(0x53, 1)]);
    y.accept(&child).unwrap();
    assert!(y.holds(&child.hash()) && y.holds(&other.hash()));
    let parent = tree_delete_record("e", 0x54, T0 + 20, &[(0x52, T0 + 10)]);
    let a = y.accept(&parent).unwrap();
    assert_eq!(a.judgement, Judgement::Held, "not obsolete");
    assert_eq!(
        a.dropped,
        vec![child.hash()],
        "it replaces the earlier tree delete only"
    );
    assert!(y.holds(&other.hash()));
    out.push(json!({ "name": "one-that-covers-only-an-earlier-tree-delete", "replaces": h(&child.hash().0) }));
    // A record beneath two concurrent tree deletes, the inner one not
    // covering it and the outer one covering it: obsolete, every ancestor
    // looked at, not only the deepest.
    let mut z = Dev::reader(0xa4);
    let inner = tree_delete_record("g/h", 0x61, T0 + 30, &[(0x62, 1)]);
    let outer = tree_delete_record("g", 0x63, T0 + 40, &[(0x64, T0 + 20)]);
    z.accept(&inner).unwrap();
    z.accept(&outer).unwrap();
    assert!(
        z.holds(&inner.hash()) && z.holds(&outer.hash()),
        "concurrent: both held"
    );
    let under = forge(
        "g/h/f",
        &[chunk(1)],
        &sealed_file("g/h/f", dev(0x64), T0 + 10),
        &[],
    );
    let j = z.judge(&under).unwrap();
    assert_eq!(
        j,
        Judgement::Obsolete,
        "beneath the outer tree delete that covers it"
    );
    out.push(
        json!({ "name": "beneath-two-tree-deletes-the-outer-covering", "judgement": "obsolete" }),
    );
    // A tree delete beneath a held one that covers it, which still covers a
    // record held beneath it that the outer one does not: it replaces
    // something held, so it is not obsolete: verified, it drops that record
    // and is dropped at once beneath the outer one (steps 3, 6 and 8).
    let mut q = Dev::reader(0xa5);
    let outer = tree_delete_record("p", 0x71, T0 + 50, &[(0x72, T0 + 40)]);
    let u = forge(
        "p/q/f",
        &[chunk(1)],
        &sealed_file("p/q/f", dev(0x73), T0 + 5),
        &[],
    );
    q.accept(&outer).unwrap();
    q.accept(&u).unwrap();
    assert!(q.holds(&u.hash()), "the outer one does not cover it");
    let inner = tree_delete_record("p/q", 0x72, T0 + 40, &[(0x73, T0 + 10)]);
    let a = q.accept(&inner).unwrap();
    assert_eq!(a.judgement, Judgement::DroppedBeneath);
    assert_eq!(a.dropped, vec![u.hash()], "what it replaces dropped");
    out.push(json!({ "name": "covered-from-above-and-covering-beneath", "judgement": "dropped beneath", "dropped": hashes(&a.dropped) }));
    json!(out)
}

/// The open-time check of the stored high-water mark (`protocol.md` 8 item
/// 7, a connection-free vector; the R2 review's N6): above the greatest
/// counter held and the clock floor by more than `CLOCK_AHEAD_WARNING`,
/// reported corrupt and replaced; by exactly that, kept.
fn the_open_time_high_water_mark() -> Value {
    use licketysync_protocol::limits::CLOCK_AHEAD_WARNING;
    let mut out = Vec::new();
    for (over, corrupt) in [
        (CLOCK_AHEAD_WARNING, false),
        (CLOCK_AHEAD_WARNING + 1, true),
    ] {
        let mut d = Dev::writer(0xd0);
        d.put("p", 1);
        let justified = d.ix.folder_time().max(d.clock);
        let meta = d.store.meta().unwrap();
        d.store.set_meta(crate::StoredMeta {
            hw: justified + over,
            ..meta
        });
        let report = d.reopen();
        assert_eq!(report.hw_corrupt, corrupt, "{over}");
        assert_eq!(
            d.ix.hw(),
            if corrupt { justified } else { justified + over }
        );
        out.push(json!({ "name": format!("a-stored-mark-{}-the-warning-ahead", if corrupt { "past" } else { "exactly" }), "corrupt": corrupt, "hw": d.ix.hw() }));
    }
    json!(out)
}

fn the_spread() -> Value {
    // Three holders 300 days ahead, right, and 70 days behind: the right one
    // accepts the fast one's record; the slow one then refuses the right
    // one's next record; the folder's time on the two sides.
    let mut fast = Dev::writer(0xf0);
    fast.clock = T0 + 300 * DAY;
    let mut right = Dev::writer(0xa0);
    let mut slow = Dev::writer(0xc0);
    slow.clock = T0 - 70 * DAY;
    let f = fast.put("x", 1);
    assert_eq!(right.take(&fast, &[f]), vec![Judgement::Held]);
    let next = right.put("y", 2);
    let j = slow.take(&right, &[next]);
    assert_eq!(j, vec![Judgement::FromTheFuture], "the slow one refuses");
    same_on_a_reader(&right, &["x", "y"]);
    json!({ "right_folder_time": right.ix.folder_time(), "slow_folder_time": slow.ix.folder_time(), "slow_refuses": true })
}

#[test]
fn vector_heads() {
    check(
        "heads",
        &json!({
            "description": "protocol.md 8 item 7 whole: latest only, coverage, display order, pruning, bases and the lost update, conflict copies, the clock rule at open, renames, opaque records and shared writer faults, tree deletes, expiry by the folder's own time and the spread of clocks; records of the keys crate's fixed folder written at the fixed clock T0, or forged with fixed nonces. Heads are listed by record hash in display order.",
            "file_ids": file_ids(),
            "coverage": coverage(),
            "arrival_order": arrival_order(),
            "display_order": display_order(),
            "pruning": pruning(),
            "restored_device": restored_device(),
            "lost_update": lost_update_s1(),
            "conflict_copy": conflict_copy_promoted(),
            "clock_set_back_at_open": clock_set_back_at_open(),
            "base_failing_at_open": base_failing_at_open(),
            "renames": renames(),
            "opaque_and_shared_faults": opaque_and_shared_faults(),
            "tree_deletes": tree_deletes(),
            "expiry": expiry_b1(),
            "spread": the_spread(),
            "tree_deletes_by_the_index": tree_deletes_by_the_index(),
            "open_time_high_water_mark": the_open_time_high_water_mark(),
        }),
    );
}

#[test]
fn the_lost_update_r1_b2_s1() {
    lost_update_s1();
}

#[test]
fn expiry_by_the_folders_own_time_b1() {
    expiry_b1();
}

/// A tree delete whose pruned vector misses a tree delete held beneath its
/// directory clears that one's slot and leaves it held; the write reports
/// the slot's path with the paths whose heads changed, so that the engine
/// names that path's disk again (the engine port's round-3 review, R3-1;
/// the engine's test is `rules::a_local_tree_delete_with_a_pruned_vector_keeps_the_disk_of_a_tree_delete_it_leaves`).
#[test]
fn a_tree_delete_reports_the_path_of_a_slot_it_clears_and_leaves_held_r3_1() {
    let mut w = Dev::writer(0xb0);
    // B, a tree delete of `d/sub` with the lowest counter beneath `d`.
    let b = tree_delete_record("d/sub", 0x60, T0 + 1, &[]);
    assert_eq!(w.accept(&b).unwrap().judgement, Judgement::Held);
    // One file each beneath `d` from 32 more devices, later.
    for i in 1..=32u8 {
        let p = format!("d/f{i:02}");
        let r = forge(
            &p,
            &[chunk(1)],
            &sealed_file(&p, dev(i), T0 + 100 + u64::from(i)),
            &[],
        );
        assert_eq!(w.accept(&r).unwrap().judgement, Judgement::Held);
        w.apply(&p);
    }
    // The engine's disk: B is `d/sub`'s base.
    let mut txn = w.ix.begin();
    txn.set_base("d/sub", Place::Path, Some(b.hash())).unwrap();
    let (changes, pending) = txn.finish();
    w.store.commit(&changes).unwrap();
    pending.commit();
    w.clock = T0 + 1_000 * SEC;
    let written = w.tree_delete("d");
    assert!(w.holds(&b.hash()), "the pruned vector misses B: it stays");
    assert!(w.ix.bases("d/sub").is_empty(), "its slot cleared");
    assert!(
        written.paths.iter().any(|p| p == "d/sub"),
        "the cleared slot's path is reported: {:?}",
        written.paths
    );
    let mut sorted = written.paths.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(written.paths, sorted, "sorted, each once");
}
