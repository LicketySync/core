// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `protocol.md` section 8 item 12, the index's part (`cleanups.json`): the
//! sealed-peer rule and every cleanup outcome, on a sealed holder unless
//! named: names, stale replays, the NAS case and its V4 variant, waiting
//! groups, empty `because`, a name of a record not held, a replay after a
//! later version, a large tree delete with its paged cleanups, a cleanup
//! naming a cleanup, a read holder's cleanups, a read holder meeting stale
//! copies, two records with one dot, a replaced `because`, the two read
//! holders of ruling R1 B-1, the replayed old tombstone, and a write
//! holder's notes.

use std::collections::BTreeSet;

use licketysync_keys::RecordHash;
use licketysync_protocol::connection::Judgement;
use licketysync_protocol::limits::{CLEANUP_HORIZON, MAX_CLEANUP_ENTRIES, TOMBSTONE_HORIZON};
use serde_json::{json, Value};

use super::kit::{
    chunk, cleanup, dev, forge, forged, garbage, round, sealed_file, write_key, Dev, DAY, SEC, T0,
};
use super::vectors::{check, h};

fn hashes(v: &[RecordHash]) -> Value {
    json!(v.iter().map(|x| h(&x.0)).collect::<Vec<_>>())
}

/// A writer's three versions of one path, each over the one before.
fn three_versions() -> (Dev, [RecordHash; 3]) {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("f", 1);
    let v2 = d.put("f", 2);
    let v3 = d.put("f", 3);
    (d, [v1, v2, v3])
}

fn names() -> Value {
    let mut out = Vec::new();
    let (d, [v1, v2, v3]) = three_versions();
    // A record that names the one version held at its file ID.
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v1]);
    let a = s.accept(d.signed(&v2)).unwrap();
    assert_eq!(a.dropped, vec![v1]);
    out.push(json!({ "name": "names-the-one-version-held", "dropped": hashes(&a.dropped) }));
    // One that names nothing held: both kept.
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v1]);
    let j = s.take(&d, &[v3]);
    assert_eq!(j, vec![Judgement::Held]);
    assert!(s.holds(&v1) && s.holds(&v3));
    out.push(json!({ "name": "names-nothing-held", "kept": 2 }));
    // A stale replay of an old version that no held record names: kept beside
    // the head.
    let j = s.take(&d, &[v2]);
    assert_eq!(j, vec![Judgement::Obsolete], "V3 names V2");
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v3]);
    let j = s.take(&d, &[v1]);
    assert_eq!(j, vec![Judgement::Held], "nothing held names V1: kept");
    out.push(json!({ "name": "stale-replays", "named_one": "obsolete", "unnamed_one": "held" }));
    json!(out)
}

fn the_nas_case() -> Value {
    let mut out = Vec::new();
    // V1 held at the NAS; V3 arrives naming V2: V1 and V3 held.
    let (d, [v1, _v2, v3]) = three_versions();
    let mut nas = Dev::sealed(0xa2);
    nas.take(&d, &[v1, v3]);
    assert!(nas.holds(&v1) && nas.holds(&v3));
    // A write holder's round with it: V1 verified and noted as a stale copy,
    // the cleanup at the round's end names V1 because V3, V1 dropped and its
    // chunks freed.
    let mut w = Dev::writer(0xb0);
    w.take(&d, &[v3]);
    let x = round(&mut w, &mut nas);
    assert!(x.cleanup, "a cleanup at the round's end");
    assert!(!nas.holds(&v1), "V1 dropped");
    assert!(
        !nas.ix.names_chunk(&chunk(1).cipher_hash),
        "its chunks freed"
    );
    let c = w.ix.records().find(|r| r.cleanup).map(|r| r.hash).unwrap();
    let groups = w.ix.s.held[&c].record.groups().to_vec();
    assert_eq!(groups.len(), 1);
    assert_eq!(
        (groups[0].because, groups[0].forget.clone()),
        (Some(v3), vec![v1])
    );
    out.push(json!({ "name": "the-nas-case", "cleanup": h(&c.0), "because": h(&v3.0), "forget": hashes(&[v1]) }));
    // The same when the write holder writes V4 first: V4 names V3 and V1.
    let (d, [v1, _v2, v3]) = three_versions();
    // W learns of V1 from the NAS first (noted), then writes V4.
    let mut nas = Dev::sealed(0xa3);
    nas.take(&d, &[v1, v3]);
    let mut w = Dev::writer(0xb1);
    w.take(&d, &[v3]);
    w.apply("f");
    let offered = w.accept_from(nas.id(), nas.signed(&v1)).unwrap();
    assert!(offered.noted);
    let v4 = w.put("f", 4);
    let named = w.ix.s.held[&v4].record.replaces().to_vec();
    assert!(
        named.contains(&v3) && named.contains(&v1),
        "V4 names V3 and V1"
    );
    let a = nas.accept(w.signed(&v4)).unwrap();
    let mut dropped = a.dropped.clone();
    dropped.sort();
    let mut want = vec![v1, v3];
    want.sort();
    assert_eq!(dropped, want);
    out.push(json!({ "name": "v4-first", "v4_names": hashes(&named) }));
    json!(out)
}

fn groups() -> Value {
    let mut out = Vec::new();
    // A group whose because is not held: waiting; applied when that record
    // arrives, and never before. The `because` lies at another path and
    // names nothing, so that only the group can drop V1 (the R2 review's
    // I-1: a `because` that named V1 itself tested the name, not the group).
    let (mut d, [v1, _, _]) = three_versions();
    let v2 = d.put("other", 9);
    assert!(!d.ix.s.held[&v2].record.replaces().contains(&v1));
    let c = cleanup(dev(0xd0), T0 + 10, &[(Some(v2), vec![v1])]);
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v1]);
    let a = s.accept(&c).unwrap();
    assert!(a
        .rows
        .contains(&licketysync_protocol::Cause::CleanupGroupWaiting));
    assert!(s.holds(&v1), "never before");
    let mut fresh = Dev::sealed(0xa3);
    fresh.accept(&c).unwrap();
    assert_eq!(
        fresh.take(&d, &[v1]),
        vec![Judgement::Held],
        "a waiting group names nothing away"
    );
    let b = s.accept(d.signed(&v2)).unwrap();
    assert!(b.dropped.contains(&v1));
    out.push(json!({ "name": "a-waiting-group", "rows": ["Cleanup group waiting"], "applied_on_arrival": true }));
    // A group with empty because naming an expired tombstone: dropped.
    let mut d = Dev::writer(0xd0);
    d.put("t", 1);
    let t = d.delete("t");
    let c = cleanup(
        dev(0xd0),
        T0 + TOMBSTONE_HORIZON + 10 * SEC,
        &[(None, vec![t])],
    );
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[t]);
    let a = s.accept(&c).unwrap();
    assert_eq!(a.dropped, vec![t]);
    out.push(json!({ "name": "an-empty-because", "dropped": hashes(&[t]) }));
    // A cleanup naming a record not held: nothing; the record refused when it
    // arrives later.
    let (d, [v1, _, _]) = three_versions();
    let c = cleanup(dev(0xd0), T0 + 10, &[(None, vec![v1])]);
    let mut s = Dev::sealed(0xa2);
    let a = s.accept(&c).unwrap();
    assert!(a.dropped.is_empty());
    assert_eq!(s.take(&d, &[v1]), vec![Judgement::Obsolete]);
    out.push(json!({ "name": "a-name-of-a-record-not-held", "later": "obsolete" }));
    // A cleanup replayed after a later version of a named file was written:
    // the later version kept.
    let (mut d, [v1, _, v3]) = three_versions();
    let c = cleanup(dev(0xd0), T0 + 3, &[(Some(v3), vec![v1])]);
    let v4 = d.put("f", 4);
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v4]);
    s.accept(&c).unwrap();
    assert!(s.holds(&v4));
    out.push(json!({ "name": "a-replay-after-a-later-version", "kept": h(&v4.0) }));
    // A later cleanup naming an earlier one: the earlier dropped.
    let early = cleanup(dev(0xd0), T0 + 1, &[(None, vec![RecordHash([1; 32])])]);
    let later = cleanup(dev(0xd0), T0 + 2, &[(None, vec![early.hash()])]);
    let mut s = Dev::sealed(0xa2);
    s.accept(&early).unwrap();
    let a = s.accept(&later).unwrap();
    assert_eq!(a.dropped, vec![early.hash()]);
    out.push(json!({ "name": "a-cleanup-naming-a-cleanup", "dropped": hashes(&[early.hash()]) }));
    json!(out)
}

fn a_large_tree_delete() -> Value {
    // Scaled (signing is slow in a debug build): 100 records beneath one
    // directory with MAX_CLEANUP_ENTRIES lowered to 16 (the test parameter of
    // ruling Q7), which pages the tree delete's cleanup into seven records,
    // as 100 000 records do at 16 384 a record; every record dropped at a
    // sealed peer and its chunks freed, the tree delete kept. The paging at
    // the real bound is `paging_at_the_real_bound`.
    let n = 100usize;
    let mut d = Dev::writer(0xd0);
    d.ix.bounds.cleanup_entries = 16;
    let changes: Vec<crate::Change> = (0..n)
        .map(|i| crate::Change::Put(super::kit::file(&format!("big/{i:05}"), (i % 251) as u8, 1)))
        .collect();
    let records: Vec<RecordHash> = d
        .write(&changes)
        .unwrap()
        .records
        .iter()
        .map(|(h, _)| *h)
        .collect();
    d.apply_all();
    let w = d.tree_delete("big");
    let cleanups: Vec<RecordHash> = w
        .records
        .iter()
        .map(|(h, _)| *h)
        .filter(|h| d.ix.s.held[h].record.is_cleanup())
        .collect();
    assert_eq!(
        cleanups.len(),
        7,
        "paged as 100 000 records are at the real bound"
    );
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &records);
    let freed_before = s.ix.names_chunk(&chunk(1).cipher_hash);
    s.take(&d, &[w.records[0].0]);
    assert_eq!(
        s.ix.len(),
        n + 1,
        "a sealed peer cannot apply the tree delete itself"
    );
    s.take(&d, &cleanups);
    assert!(freed_before);
    assert_eq!(s.ix.len(), 8, "the tree delete and its seven cleanups");
    assert!(!s.ix.names_chunk(&chunk(1).cipher_hash), "chunks freed");
    json!({ "records": n, "cleanup_entries": 16, "cleanup_records": cleanups.len(), "scaled_from": 100_000 })
}

/// §8 item 12's case at its own size, outside the gate (ruling Q7): run it
/// with `cargo test --release -p licketysync-index -- --ignored`.
#[test]
#[ignore = "100 000 signed records: release builds only"]
fn a_tree_delete_over_100_000_records_and_its_seven_cleanups() {
    let n = 100_000usize;
    let mut d = Dev::writer(0xd0);
    let changes: Vec<crate::Change> = (0..n)
        .map(|i| crate::Change::Put(super::kit::file(&format!("big/{i:06}"), (i % 251) as u8, 1)))
        .collect();
    let records: Vec<RecordHash> = d
        .write(&changes)
        .unwrap()
        .records
        .iter()
        .map(|(h, _)| *h)
        .collect();
    d.apply_all();
    let w = d.tree_delete("big");
    let cleanups: Vec<RecordHash> = w
        .records
        .iter()
        .map(|(h, _)| *h)
        .filter(|h| d.ix.s.held[h].record.is_cleanup())
        .collect();
    assert_eq!(cleanups.len(), 7);
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &records);
    s.take(&d, &[w.records[0].0]);
    assert_eq!(s.ix.len(), n + 1);
    s.take(&d, &cleanups);
    assert_eq!(s.ix.len(), 8, "the tree delete and its seven cleanups");
    assert!(!s.ix.names_chunk(&chunk(1).cipher_hash), "chunks freed");
}

#[test]
fn paging_at_the_real_bound() {
    // 100 000 names at MAX_CLEANUP_ENTRIES a record: seven records, the last
    // of 1 696 names, every page signable.
    let names: Vec<RecordHash> = (0..100_000u32)
        .map(|i| {
            let mut x = [0u8; 32];
            x[..4].copy_from_slice(&i.to_be_bytes());
            RecordHash(x)
        })
        .collect();
    let pages = crate::write::page_names(&names, MAX_CLEANUP_ENTRIES);
    assert_eq!(pages.len(), 7);
    assert!(pages[..6].iter().all(|p| p.len() == MAX_CLEANUP_ENTRIES));
    assert_eq!(pages[6].len(), 100_000 - 6 * MAX_CLEANUP_ENTRIES);
    let w = write_key();
    let signed = licketysync_protocol::record::CleanupDraft {
        dot: licketysync_protocol::record::Dot {
            device: dev(0xd0),
            counter: T0,
        },
        groups: vec![licketysync_protocol::record::Group {
            because: Some(RecordHash([1; 32])),
            forget: pages[0].clone(),
        }],
    }
    .sign(&w, &w.record_keys(), &mut |b: &mut [u8]| b.fill(3));
    assert!(signed.is_ok(), "a full page signs");
}

fn at_a_read_holder() -> Value {
    let mut out = Vec::new();
    // A cleanup naming a record its vectors already replace: no change.
    let (d, [v1, v2, _]) = three_versions();
    let mut r = Dev::reader(0xa1);
    r.take(&d, &[v2]);
    let c = cleanup(dev(0xd0), T0 + 9, &[(Some(v2), vec![v1])]);
    let a = r.accept(&c).unwrap();
    assert!(a.dropped.is_empty());
    out.push(json!({ "name": "names-what-its-vectors-replace", "dropped": 0 }));
    // A cleanup naming an opaque record: dropped.
    let mut m = sealed_file("o", dev(0xe0), T0);
    m.tree = true;
    let bad = forge("o", &[chunk(2)], &m, &[]);
    let mut r = Dev::reader(0xa1);
    r.accept(&bad).unwrap();
    let c = cleanup(dev(0xd0), T0 + 9, &[(None, vec![bad.hash()])]);
    let a = r.accept(&c).unwrap();
    assert_eq!(a.dropped, vec![bad.hash()]);
    out.push(json!({ "name": "names-an-opaque-record", "dropped": 1 }));
    // A read holder meets a sealed peer holding stale copies: a caught-up
    // round, the copies kept, nothing issued.
    let (d, [v1, _, v3]) = three_versions();
    let mut nas = Dev::sealed(0xa2);
    nas.take(&d, &[v1, v3]);
    let mut r = Dev::reader(0xa1);
    r.take(&d, &[v3]);
    let x = round(&mut r, &mut nas);
    assert!(x.caught_up && !x.cleanup);
    assert!(nas.holds(&v1), "read holders note nothing");
    out.push(json!({ "name": "a-read-holder-meets-stale-copies", "caught_up": true, "copies_kept": true }));
    json!(out)
}

fn one_dot_two_sealed_peers() -> Value {
    let one = forge("dot", &[chunk(1)], &sealed_file("dot", dev(0xd0), 100), &[]);
    let mut m = sealed_file("dot", dev(0xd0), 100);
    m.mtime_ns = 77;
    let other = forge("dot", &[chunk(2)], &m, &[]);
    let mut a = Dev::sealed(0xa2);
    let mut b = Dev::sealed(0xa3);
    a.accept(&one).unwrap();
    b.accept(&other).unwrap();
    assert_ne!(a.root(), b.root(), "their digests differ");
    round(&mut a, &mut b);
    round(&mut b, &mut a);
    assert_eq!(a.all(), b.all());
    assert_eq!(a.ix.len(), 2, "both end holding both");
    json!({ "records": hashes(&[one.hash(), other.hash()]) })
}

fn a_replaced_because() -> Value {
    // A group whose because record is then replaced by a later version: the
    // group no longer applies; the record it named, offered again, is held
    // as a stale copy on a sealed holder, and judged by coverage on a read
    // holder.
    let (d, [v1, v2, _]) = three_versions();
    let c = cleanup(dev(0xd0), T0 + 5, &[(Some(v2), vec![v1])]);
    let mut later_v2 = sealed_file("f", dev(0xe0), T0 + 50);
    later_v2.vector = vec![super::kit::entry(dev(0xd0), T0 + 1)];
    let over_v2 = forge("f", &[chunk(5)], &later_v2, &[v2]);
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v2]);
    s.accept(&c).unwrap();
    s.accept(&over_v2).unwrap();
    assert!(!s.holds(&v2), "the because replaced");
    assert_eq!(
        s.take(&d, &[v1]),
        vec![Judgement::Held],
        "a stale copy: the group no longer applies"
    );
    let mut r = Dev::reader(0xa1);
    r.take(&d, &[v2]);
    r.accept(&c).unwrap();
    r.accept(&over_v2).unwrap();
    assert_eq!(
        r.take(&d, &[v1]),
        vec![Judgement::Obsolete],
        "covered by what replaced V2"
    );
    json!({ "sealed": "held", "read": "obsolete" })
}

/// Ruling R1 B-1: no applied bit. Two read holders, one that held a group's
/// `because` and the group, one that received the cleanup after the
/// `because` had expired, judge the record the group named alike.
pub(crate) fn cleanup_group_acts_only_while_its_because_is_held() -> Value {
    let mut d = Dev::writer(0xd0);
    let f1 = d.put("x", 1);
    d.apply("x");
    let t = d.delete("x");
    // The cleanup names the version because the tombstone; issued late
    // enough that it outlives the tombstone (CLEANUP_HORIZON is shorter).
    let c = cleanup(
        dev(0xd0),
        T0 + TOMBSTONE_HORIZON - 10 * super::kit::DAY,
        &[(Some(t), vec![f1])],
    );
    let raise = forge(
        "y",
        &[chunk(3)],
        &sealed_file("y", dev(0xd1), T0 + TOMBSTONE_HORIZON + 20 * SEC),
        &[],
    );
    // One held the because and the group, then the because expired.
    let mut one = Dev::reader(0xa1);
    one.clock = T0 + TOMBSTONE_HORIZON + 30 * SEC;
    one.take(&d, &[t]);
    one.accept(&c).unwrap();
    one.accept(&raise).unwrap();
    assert!(!one.holds(&t), "the because expired");
    assert!(one.holds(&c.hash()), "the cleanup has not");
    // The other received the cleanup after the because had expired.
    let mut other = Dev::reader(0xa2);
    other.clock = one.clock;
    other.accept(&raise).unwrap();
    other.accept(&c).unwrap();
    let a = one.take(&d, &[f1]);
    let b = other.take(&d, &[f1]);
    assert_eq!(a, b, "both hold it, or both refuse it");
    assert_eq!(a, vec![Judgement::Held]);
    json!({ "first": "held", "second": "held" })
}

fn the_replayed_old_tombstone() -> Value {
    // A case-(c) cleanup named a forgotten tombstone; that cleanup was itself
    // named away. The tombstone, replayed to a sealed holder, is held, and
    // the version it names, live at read holders, drops there until a write
    // holder's round names the tombstone again, then is held again.
    let mut d = Dev::writer(0xd0);
    let v = d.put("z", 1);
    d.apply("z");
    let t = d.delete("z");
    let case_c = cleanup(dev(0xd0), T0 + 10, &[(None, vec![t])]);
    let away = cleanup(dev(0xd0), T0 + 11, &[(None, vec![case_c.hash()])]);
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v]);
    s.accept(&case_c).unwrap();
    s.accept(&away).unwrap();
    assert!(!s.holds(&case_c.hash()));
    let j = s.take(&d, &[t]);
    assert_eq!(j, vec![Judgement::Held], "nothing names it any more");
    assert!(
        !s.holds(&v),
        "the version it names dropped at the sealed holder"
    );
    let mut r = Dev::reader(0xa1);
    r.take(&d, &[v]);
    r.take(&d, &[t]);
    assert!(
        !r.holds(&v),
        "the version dropped where the tombstone came back"
    );
    // A write holder whose folder's time has passed the tombstone by its
    // horizon, holding the version that came back, meets the sealed holder:
    // offered the tombstone, it finds it forgotten, notes it, and names it
    // again at the round's end, `because` empty (case (c)); the sealed
    // holder drops it, and the next round brings the version back.
    let mut w = Dev::writer(0xb0);
    w.clock = T0 + TOMBSTONE_HORIZON + 10 * SEC;
    w.put("later", 2);
    w.take(&d, &[v]);
    let first = round(&mut w, &mut s);
    assert!(first.cleanup, "the case-(c) cleanup at the round's end");
    let case_c_again =
        w.ix.records()
            .filter(|r| r.cleanup)
            .filter_map(|r| w.ix.s.held.get(&r.hash))
            .find(|c| c.record.groups().iter().any(|g| g.forget.contains(&t)))
            .unwrap();
    assert!(
        case_c_again
            .record
            .groups()
            .iter()
            .all(|g| g.because.is_none()),
        "named with `because` empty: forgotten, not replaced"
    );
    assert!(!s.holds(&t), "the replayed tombstone named away again");
    round(&mut w, &mut s);
    assert!(s.holds(&v), "then the version is held again");
    json!({ "sealed": "held", "read_version": "dropped", "named_again": true, "version_back": true })
}

fn a_write_holders_notes() -> Value {
    let mut out = Vec::new();
    // The same copy already named by a held cleanup whose group applies: not
    // verified, not noted, no new cleanup.
    let (d, [v1, _, v3]) = three_versions();
    let mut w = Dev::writer(0xb0);
    w.take(&d, &[v3]);
    let c = cleanup(dev(0xd0), T0 + 10, &[(Some(v3), vec![v1])]);
    w.accept(&c).unwrap();
    let a = w.accept(&garbage(d.signed(&v1))).unwrap();
    assert_eq!(a.judgement, Judgement::Obsolete);
    assert!(!a.noted, "not verified, not noted");
    assert!(!w.end_round().cleanup);
    out.push(json!({ "name": "already-named-by-a-group-that-applies", "noted": false }));
    // The same copy named only in a held cleanup's group that waits (its
    // `because` is not held): obsolete by coverage, yet not verified and not
    // noted either, since a held cleanup names it in a group (the fifth
    // fixup's SC-2).
    let mut w = Dev::writer(0xb0);
    w.take(&d, &[v3]);
    let waits = cleanup(
        dev(0xd0),
        T0 + 10,
        &[(Some(RecordHash([0x77; 32])), vec![v1])],
    );
    w.accept(&waits).unwrap();
    let a = w.accept(&garbage(d.signed(&v1))).unwrap();
    assert_eq!(a.judgement, Judgement::Obsolete);
    assert!(
        !a.noted,
        "named in a group that waits: not verified, not noted"
    );
    assert!(!w.end_round().cleanup);
    out.push(json!({ "name": "named-in-a-group-that-waits-sc-2", "noted": false }));
    // A stale copy offered with a forged signature: closed.
    let mut w = Dev::writer(0xb1);
    let mut m = sealed_file("f", dev(0xc0), T0 + 50);
    m.vector = vec![super::kit::entry(dev(0xd0), T0 + 2)];
    let over = forge("f", &[chunk(7)], &m, &[]);
    w.accept(&over).unwrap();
    assert_eq!(
        w.accept(&forged(d.signed(&v1))),
        Err(licketysync_protocol::Cause::Forged)
    );
    out.push(json!({ "name": "a-forged-stale-copy", "closes": "Forged" }));
    // A round at whose end a cleanup was issued owes a round (the engine's);
    // the index says so.
    let mut nas = Dev::sealed(0xa2);
    nas.take(&d, &[v1]);
    let mut w = Dev::writer(0xb2);
    w.take(&d, &[v3]);
    let x = round(&mut w, &mut nas);
    assert!(x.cleanup);
    let y = round(&mut w, &mut nas);
    assert!(y.caught_up && !y.cleanup, "the next round ends at EQUAL");
    out.push(json!({ "name": "a-cleanup-at-a-rounds-end", "then": "EQUAL" }));
    json!(out)
}

fn file_ids() -> Value {
    let keys = write_key().record_keys();
    let paths = [
        "docs",
        "docs/notes",
        "docs/notes/a.txt",
        "Docs",
        "docs/not\u{e9}s",
        "docs/note\u{301}s",
    ];
    let tags: BTreeSet<[u8; 32]> = paths.iter().map(|p| keys.path_tag(p).0).collect();
    assert_eq!(tags.len(), paths.len(), "byte for byte: six tags");
    json!(paths
        .iter()
        .map(|p| json!({ "path": p, "path_tag": h(&keys.path_tag(p).0) }))
        .collect::<Vec<_>>())
}

#[test]
fn vector_cleanups() {
    check(
        "cleanups",
        &json!({
            "description": "protocol.md 8 item 12, the index's part: the sealed-peer rule and every cleanup outcome, on a sealed holder unless named; records of the keys crate's fixed folder written at T0 or forged with fixed nonces. The 100 000-record tree delete is scaled to 100 records at 16 names a cleanup record, which pages into seven records as 100 000 do at 16 384.",
            "names": names(),
            "nas": the_nas_case(),
            "groups": groups(),
            "large_tree_delete": a_large_tree_delete(),
            "read_holder": at_a_read_holder(),
            "one_dot_two_sealed_peers": one_dot_two_sealed_peers(),
            "replaced_because": a_replaced_because(),
            "r1_b1": cleanup_group_acts_only_while_its_because_is_held(),
            "replayed_old_tombstone": the_replayed_old_tombstone(),
            "write_holder_notes": a_write_holders_notes(),
            "file_ids": file_ids(),
            "cleanup_horizon_days": CLEANUP_HORIZON / super::kit::DAY,
        }),
    );
}

#[test]
fn cleanup_group_acts_only_while_its_because_is_held_r1_b1() {
    cleanup_group_acts_only_while_its_because_is_held();
}

/// A round's end whose cleanup raises the folder's time past a tree
/// delete's horizon expires it, and reports its path with what it dropped,
/// as accepting a record that expires it does, so that the engine names that
/// path's disk again (the engine port's round-3 security review, S3-C; the
/// engine's test is
/// `rules::a_rounds_end_cleanup_that_expires_the_greater_tree_delete_leaves_the_other_as_the_base`).
#[test]
fn a_rounds_end_reports_the_paths_of_what_its_cleanup_expires_s3_c() {
    let (d, [v1, _, v3]) = three_versions();
    let mut w = Dev::writer(0xb0);
    w.take(&d, &[v3]);
    // Two tree deletes of `t`, 200 days apart.
    let tree = |device: u8, counter: u64| {
        let mut m = sealed_file("t", dev(device), counter);
        m.kind = 2;
        m.size = 0;
        m.plain_hashes.clear();
        m.deleted = true;
        m.tree = true;
        forge("t", &[], &m, &[])
    };
    let old = tree(0x61, T0 + 2 * SEC);
    let new = tree(0x62, T0 + 200 * DAY);
    assert_eq!(w.accept(&old).unwrap().judgement, Judgement::Held);
    assert_eq!(w.accept(&new).unwrap().judgement, Judgement::Held);
    // 400 days on, V1 is offered: a stale copy, noted, named at the
    // round's end by a cleanup whose counter expires the older delete.
    w.clock = T0 + 400 * DAY;
    assert!(w.accept(d.signed(&v1)).unwrap().noted);
    let written = w.end_round();
    assert!(written.cleanup);
    assert!(written.dropped.contains(&old.hash()), "expired");
    assert!(w.holds(&new.hash()), "within its horizon");
    assert_eq!(
        written.paths,
        vec!["t".to_owned()],
        "the expired delete's path"
    );
}
