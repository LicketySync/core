// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One focused test per rule the review found no test of (its I-3, I-5 and
//! IR-1): the write refusals, each staging nothing; the two fixes of the
//! first round that had no regression test; and the rules of the open, of
//! writing, of notes and the end of a round, of expiry, of serving and of the
//! undo log, each of which a test here fails without.

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{RecordHash, Tier};
use licketysync_protocol::exchange::Prefix;
use licketysync_protocol::limits::{MAX_COUNTER, MAX_REPLACES, TOMBSTONE_HORIZON};
use licketysync_protocol::record::{PathError, Record};

use super::kit::{cleanup, dev, file, forge, round, sealed_file, Dev, Rng, SEC, T0};
use licketysync_protocol::connection::ReconcileServe;

use crate::{Change, Place, StoredMeta, WriteError};

/// Three versions of `f`, each from the one before, by one writer.
fn three_versions() -> (Dev, [RecordHash; 3]) {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("f", 1);
    let v2 = d.put("f", 2);
    let v3 = d.put("f", 3);
    (d, [v1, v2, v3])
}

/// The whole in-memory state, every derived table included: what a dropped
/// transaction must give back exactly.
fn state(d: &Dev) -> String {
    format!("{:#?}", d.ix.s)
}

/// Two states equal, or a panic naming the lines that differ.
fn assert_same(before: &str, after: &str, what: &str) {
    if before == after {
        return;
    }
    let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
    let differ: Vec<String> = (0..b.len().max(a.len()))
        .filter(|i| b.get(*i) != a.get(*i))
        .take(6)
        .map(|i| format!("line {i}: {:?} / {:?}", b.get(i), a.get(i)))
        .collect();
    panic!("{what}: not given back exactly: {differ:#?}");
}

/// The record `hash` held at `d`, parsed.
fn held_record(d: &Dev, hash: &RecordHash) -> Record {
    d.ix.s.held[hash].record.clone()
}

/// `w` accepts `signed` from `peer` in a transaction it then drops.
fn dry_accept(w: &mut Dev, peer: licketysync_keys::DeviceId, signed: &SignedRecord) {
    let record = Record::parse(signed.clone(), w.ix.key().verifier()).unwrap();
    let mut rng = w.rng.clone();
    let mut memory = w.memory.clone();
    // A budget of the dry run's own: the device's stays unspent.
    let mut notes = licketysync_protocol::connection::NoteBudget::for_tests();
    let mut txn = w.ix.begin();
    let mut fill = |b: &mut [u8]| rng.fill(b);
    let mut arrival = crate::Arrival {
        peer,
        memory: &mut memory,
        notes: &mut notes,
        clock_us: w.clock,
        rng: &mut fill,
    };
    let _ = txn.accept(record, &mut arrival);
}

// I-3: the write refusals, each staging nothing.

#[test]
fn a_read_or_sealed_holder_writes_nothing_not_write_key_i3() {
    for tier in [Tier::Read, Tier::Sealed] {
        let mut x = Dev::new(tier, 0xa0);
        let clock = x.clock;
        let mut txn = x.ix.begin();
        let r = txn.write(&[Change::Put(file("f", 1, 5))], clock, &mut |b| b.fill(1));
        assert_eq!(r, Err(WriteError::NotWriteKey), "{tier:?}");
        let r = txn.write(
            &[Change::TreeDelete {
                path: "d".into(),
                mtime_ns: 5,
            }],
            clock,
            &mut |b| b.fill(1),
        );
        assert_eq!(r, Err(WriteError::NotWriteKey));
        assert!(txn.finish().0.is_empty(), "{tier:?}: nothing staged");
    }
}

#[test]
fn a_counter_past_max_counter_is_refused_counter_exhausted_i3() {
    let mut d = Dev::writer(0xd0);
    d.put("f", 1);
    // One counter left: one record fits, a batch of two does not.
    d.ix.s.meta.hw = MAX_COUNTER - 1;
    let clock = d.clock;
    let mut txn = d.ix.begin();
    let two = [Change::Put(file("a", 1, 5)), Change::Put(file("b", 2, 5))];
    assert_eq!(
        txn.write(&two, clock, &mut |b| b.fill(1)),
        Err(WriteError::CounterExhausted)
    );
    assert!(txn.finish().0.is_empty(), "nothing staged");
    let w = d.write(&[Change::Put(file("a", 1, 5))]).unwrap();
    assert_eq!(d.ix.hw(), MAX_COUNTER, "the last counter taken");
    assert_eq!(w.records.len(), 1);
    let mut txn = d.ix.begin();
    assert_eq!(
        txn.write(&[Change::Put(file("c", 3, 5))], clock, &mut |b| b.fill(1)),
        Err(WriteError::CounterExhausted)
    );
    assert!(txn.finish().0.is_empty());
    assert!(!WriteError::CounterExhausted.to_string().is_empty());
}

#[test]
fn one_path_twice_in_a_batch_is_refused_duplicate_path_i3() {
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    d.apply("a");
    let clock = d.clock;
    let mut txn = d.ix.begin();
    let r = txn.write(
        &[Change::Put(file("x", 1, 5)), Change::Put(file("x", 2, 6))],
        clock,
        &mut |b| b.fill(1),
    );
    assert_eq!(r, Err(WriteError::DuplicatePath("x".into())));
    // A rename's tombstone at its old path, and a version there too.
    let r = txn.write(
        &[
            Change::Rename {
                from: "a".into(),
                to: file("b", 1, 7),
            },
            Change::Put(file("a", 3, 8)),
        ],
        clock,
        &mut |b| b.fill(1),
    );
    assert_eq!(r, Err(WriteError::DuplicatePath("a".into())));
    assert!(txn.finish().0.is_empty(), "nothing staged");
}

#[test]
fn a_path_that_breaks_the_grammar_is_refused_path_i3() {
    let mut d = Dev::writer(0xd0);
    let clock = d.clock;
    let mut txn = d.ix.begin();
    for (path, why) in [
        ("", PathError::Empty),
        ("/a", PathError::Absolute),
        ("a//b", PathError::EmptyComponent),
        ("a/../b", PathError::DotComponent),
        ("a\\b", PathError::Backslash),
    ] {
        let r = txn.write(&[Change::Put(file(path, 1, 5))], clock, &mut |b| b.fill(1));
        assert_eq!(r, Err(WriteError::Path(why)), "{path:?}");
        let r = txn.write(
            &[Change::TreeDelete {
                path: path.into(),
                mtime_ns: 5,
            }],
            clock,
            &mut |b| b.fill(1),
        );
        assert!(
            matches!(r, Err(WriteError::Path(_))),
            "{path:?} as a tree delete"
        );
    }
    assert!(txn.finish().0.is_empty(), "nothing staged");
}

// I-5: the two fixes of the first round that had no regression test.

/// The bug: per-peer state made by the names count at a round's end carried
/// no round end, so the next open dropped it as past `PEER_STATE_HORIZON`,
/// and the peer's `MAX_PEER_NAMES` window with it.
#[test]
fn per_peer_state_made_by_a_names_count_survives_a_reopen_round_ended_us() {
    let (d, [v1, _, v3]) = three_versions();
    let mut w = Dev::writer(0xa0);
    w.take(&d, &[v3]);
    // A peer that is not the round's partner offers a stale copy.
    let peer = dev(0x77);
    assert!(w.accept_from(peer, d.signed(&v1)).unwrap().noted);
    assert!(w.ix.peer(&peer).is_none(), "no state for it yet");
    assert!(w.end_round().cleanup, "the note named");
    let made = *w.ix.peer(&peer).unwrap();
    assert_eq!(made.names, 1);
    assert_eq!(
        made.round_ended_us, w.clock,
        "the names count's state carries its time"
    );
    w.clock += SEC;
    let report = w.reopen();
    assert!(
        report.changes.peers.is_empty(),
        "nothing dropped: {:?}",
        report.changes.peers
    );
    assert_eq!(
        w.ix.peer(&peer).map(|p| p.names),
        Some(1),
        "kept across the reopen"
    );
}

/// The R7 deviation (`protocol.md` 4.4 (b)): every note is named at the end
/// of any round, so one from a peer that never ends a round with this device
/// still goes, at another peer's round's end.
#[test]
fn a_note_from_a_peer_that_never_ends_a_round_is_named_at_another_peers_r7() {
    let (d, [v1, _, v3]) = three_versions();
    let mut w = Dev::writer(0xa0);
    w.take(&d, &[v3]);
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v3, v1]);
    assert!(s.holds(&v1), "a stale copy at the sealed peer");
    assert!(
        w.accept_from(dev(0x77), d.signed(&v1)).unwrap().noted,
        "from 0x77"
    );
    let x = round(&mut w, &mut s);
    assert!(x.cleanup, "named at the round with the sealed peer");
    assert!(w.ix.s.notes.is_empty());
    let c =
        w.ix.records()
            .find(|r| r.cleanup)
            .map(|r| held_record(&w, &r.hash))
            .unwrap();
    assert_eq!(c.groups()[0].because, Some(v3));
    assert_eq!(c.groups()[0].forget, vec![v1]);
    assert!(!s.holds(&v1), "the sealed peer drops it");
}

// IR-1: the open.

#[test]
fn the_open_raises_a_stored_high_water_mark_below_the_greatest_counter() {
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    let greatest = d.ix.hw();
    let meta = d.store.meta().unwrap();
    d.store.set_meta(StoredMeta { hw: 1, ..meta });
    let report = d.reopen();
    assert!(!report.hw_corrupt, "below the records is not corrupt");
    assert_eq!(d.ix.hw(), greatest, "raised to the greatest counter held");
    let next = d.put("b", 2);
    let dot = d.ix.record(&next).unwrap().dot.unwrap();
    assert!(
        dot.counter > greatest,
        "the next write passes every counter held"
    );
}

#[test]
fn a_silent_drop_at_the_open_draws_a_new_epoch() {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("a", 1);
    let before = d.ix.epoch();
    d.store.mode = crate::Commit::CrashBeforeRemovals;
    {
        let Dev {
            ix,
            store,
            rng,
            clock,
            ..
        } = &mut d;
        let mut txn = ix.begin();
        txn.write(&[Change::Put(file("a", 2, 9))], *clock, &mut |b| {
            rng.fill(b);
        })
        .unwrap();
        let (changes, pending) = txn.finish();
        assert!(crate::Store::commit(store, &changes).is_err());
        drop(pending);
    }
    let report = d.reopen();
    assert!(!d.holds(&v1), "the record a stored one replaces dropped");
    assert!(report.dropped.is_empty(), "silently");
    assert!(report.epoch_redrawn, "a new epoch for the silent drop");
    assert_ne!(d.ix.epoch(), before);
}

// IR-1: writing.

/// `S` puts this device's own records first: with room for one base, a
/// write at a path with a conflict copy of its own names its own version,
/// though another device's sorts first in display order.
#[test]
fn s_takes_this_devices_own_records_first() {
    let mut w = Dev::writer(0xa0);
    w.ix.bounds.vector = 1;
    let mine = w.put("f", 1);
    let mut e = Dev::writer(0xe0);
    e.mtime = 1_000_000;
    let theirs = e.put("f", 2);
    w.take(&e, &[theirs]);
    assert_eq!(
        w.heads("f"),
        vec![theirs, mine],
        "theirs first: a later mtime"
    );
    w.apply("f");
    assert_eq!(w.ix.bases("f").len(), 2, "the path and a conflict copy");
    let next = w.put("f", 3);
    assert_eq!(
        held_record(&w, &next).replaces(),
        &[mine],
        "its own version, not the first in display order"
    );
}

/// A tree delete names the shared writer faults held at its directory's tag
/// (4.4, "Its names"), so every tier drops them with it.
#[test]
fn a_tree_delete_names_the_shared_writer_faults_at_its_tag() {
    let mut w = Dev::writer(0xa0);
    w.mkdir("d");
    w.put("d/x", 1);
    let mut m = sealed_file("d", dev(0xe0), T0 + 5);
    m.kind = 2;
    m.size = 0;
    m.plain_hashes = vec![];
    m.tree = true;
    let bad = forge("d", &[], &m, &[]);
    let mut s = Dev::sealed(0xa2);
    assert_eq!(
        w.accept(&bad).unwrap().judgement,
        licketysync_protocol::connection::Judgement::HeldOpaque
    );
    assert_eq!(
        s.accept(&bad).unwrap().judgement,
        licketysync_protocol::connection::Judgement::Held,
        "a sealed peer cannot tell"
    );
    w.apply_all();
    let written = w.tree_delete("d");
    let td = written.records[0].0;
    assert!(
        held_record(&w, &td).replaces().contains(&bad.hash()),
        "named by the tree delete"
    );
    assert!(!w.holds(&bad.hash()));
    s.accept(w.signed(&td)).unwrap();
    assert!(
        !s.holds(&bad.hash()),
        "and the sealed peer drops it by that name"
    );
}

/// A write names its path's notes up to `MAX_REPLACES` names; the rest stay
/// notes, which the round's end names in a cleanup `because` that write.
#[test]
fn notes_beyond_max_replaces_wait_for_the_rounds_cleanup() {
    let mut d = Dev::writer(0xd0);
    let versions: Vec<RecordHash> = (0..70u8).map(|i| d.put("f", i)).collect();
    let newest = versions[69];
    let mut w = Dev::writer(0xa0);
    w.take(&d, &[newest]);
    // The 69th is named by the newest, so not noted; the 68 before are.
    assert!(
        !w.accept(d.signed(&versions[68])).unwrap().noted,
        "named already"
    );
    for v in &versions[..68] {
        assert!(w.accept(d.signed(v)).unwrap().noted, "a stale copy noted");
    }
    let noted = 68;
    assert_eq!(w.ix.s.notes.len(), noted);
    w.apply("f");
    let next = w.put("f", 200);
    let names = held_record(&w, &next).replaces().len();
    assert_eq!(names, MAX_REPLACES, "its base and 63 notes");
    let left = noted - (MAX_REPLACES - 1);
    assert_eq!(w.ix.s.notes.len(), left, "the rest wait");
    let end = w.end_round();
    assert!(end.cleanup);
    assert!(w.ix.s.notes.is_empty());
    let c = held_record(&w, &end.records[0].0);
    assert_eq!(c.groups().len(), 1);
    assert_eq!(
        c.groups()[0].because,
        Some(next),
        "because the write that covers them"
    );
    assert_eq!(c.groups()[0].forget.len(), left);
}

// IR-1: expiry.

/// Expiry drops a deletion that is its path's base with its base slot, so
/// the path has no base and no record kept only as a base is left.
#[test]
fn expiry_drops_the_deletions_base_with_it() {
    let mut w = Dev::writer(0xa0);
    w.put("f", 1);
    let t = w.delete("f");
    assert_eq!(
        w.ix.bases("f"),
        vec![(Place::Path, t)],
        "the tombstone is the base"
    );
    w.clock += TOMBSTONE_HORIZON + 2 * SEC;
    w.put("g", 2);
    assert!(!w.holds(&t), "expired");
    assert!(w.ix.bases("f").is_empty(), "its base slot with it");
    assert!(!w.ix.s.base_only.contains_key(&t), "not kept as a base");
    assert!(w.ix.current("f").is_none());
}

// IR-1: notes and the end of a round.

/// At a round's end a note already named by a held cleanup, in any group,
/// is dropped unnamed, and so is one that nothing held replaces any more.
#[test]
fn the_rounds_end_drops_a_note_named_already_or_replaced_by_nothing() {
    let (d, [v1, _, v3]) = three_versions();
    // Named already: a cleanup naming the copy arrives after the note.
    let mut w = Dev::writer(0xa0);
    w.take(&d, &[v3]);
    assert!(w.accept(d.signed(&v1)).unwrap().noted);
    let c = cleanup(dev(0xd0), T0 + 10, &[(Some(v3), vec![v1])]);
    w.accept(&c).unwrap();
    let end = w.end_round();
    assert!(!end.cleanup, "not named again");
    assert!(w.ix.s.notes.is_empty(), "the note dropped");
    // Replaced by nothing: what covered the copy is gone when the round ends.
    let mut w = Dev::writer(0xa0);
    w.take(&d, &[v3]);
    assert!(w.accept(d.signed(&v1)).unwrap().noted);
    let gone = cleanup(dev(0xd0), T0 + 20, &[(None, vec![v3])]);
    w.accept(&gone).unwrap();
    assert!(!w.holds(&v3), "the covering version forgotten");
    let end = w.end_round();
    assert!(!end.cleanup, "nothing replaces the copy: not named");
    assert!(w.ix.s.notes.is_empty(), "the note dropped");
}

/// A held cleanup's group whose `because` is at another path, and so names
/// nothing of what the group forgets, waits until that record arrives and
/// then drops what it names, on every tier.
#[test]
fn a_waiting_group_applies_when_its_because_arrives() {
    for tier in [Tier::Sealed, Tier::Read, Tier::Write] {
        let mut w = Dev::writer(0xd0);
        let x = w.put("x", 1);
        let b = w.put("other", 2);
        let c = cleanup(dev(0xd0), T0 + 10, &[(Some(b), vec![x])]);
        let mut s = Dev::new(tier, 0xa2);
        s.take(&w, &[x]);
        s.accept(&c).unwrap();
        assert!(s.holds(&x), "{tier:?}: the group waits");
        let a = s.accept_from(w.id(), w.signed(&b)).unwrap();
        assert!(
            a.dropped.contains(&x),
            "{tier:?}: the group applies once its because is held"
        );
        assert!(!s.holds(&x));
    }
}

// IR-1: serving.

/// The last page of a Since reply carries the local sequence when serving
/// began as its `through`, not its last record's number: a record numbered
/// last and dropped meanwhile is still passed.
#[test]
fn the_last_since_page_carries_the_local_sequence() {
    let mut a = Dev::writer(0xa0);
    a.put("x", 1);
    a.put("y", 2);
    a.put("z", 3);
    let crate::SincePlan::Pages(mut reply) = a.ix.since_plan(a.ix.epoch(), 0) else {
        panic!("pages")
    };
    // The record numbered 3 is replaced (the new one is numbered 4, past
    // the reply's end).
    a.apply("z");
    a.put("z", 4);
    let page = a.ix.since_page(
        &mut reply,
        1,
        64,
        licketysync_protocol::limits::DEFAULT_MESSAGE_SIZE,
    );
    assert_eq!(page.records.len(), 2, "x and y");
    assert!(!page.more && reply.is_done());
    assert_eq!(page.through, 3, "the local sequence when serving began");
}

/// A `RECORDS` reply and pushes larger than one page: every page but the
/// last has `more`, the records ascend by key (path tag, then record hash),
/// each once; pushes carry their last record's local sequence, and a
/// reconciliation's pushes none.
#[test]
fn records_replies_and_pushes_take_several_pages() {
    let mut a = Dev::writer(0xa0);
    let mut all: Vec<RecordHash> = (0..12u8).map(|i| a.put(&format!("p{i}"), i)).collect();
    let small = 2_000;
    let request = ReconcileServe {
        request_id: 4,
        prefix: Prefix::ROOT,
        digest: licketysync_keys::SetDigest::EMPTY,
    };
    let (_, records) = a.ix.reconcile_reply(&request);
    let mut reply = records.unwrap();
    let mut got = Vec::new();
    let mut pages = 0;
    loop {
        let page = a.ix.records_page(&mut reply, 4, small);
        pages += 1;
        assert!(pages <= all.len() + 1, "the reply ends");
        assert_eq!(page.request_id, 4);
        assert_eq!(page.through, 0, "a RECORDS page carries no through");
        got.extend(
            page.records
                .iter()
                .map(|r| SignedRecord::from_bytes(r).unwrap().hash()),
        );
        if !page.more {
            assert!(reply.is_done());
            break;
        }
        assert!(!page.records.is_empty(), "a page with more holds records");
    }
    assert!(pages > 2, "{pages} pages");
    let mut sorted = all.clone();
    sorted.sort_by_key(|h| a.ix.s.held[h].record.key());
    assert_eq!(got, sorted, "every record once, ascending by key");
    // Pushes: local-sequence order, each page's through its last record's.
    let pushes = a.ix.push_pages(&all, small);
    assert!(pushes.len() > 2);
    let mut pushed = Vec::new();
    for p in &pushes {
        let hashes: Vec<RecordHash> = p
            .records
            .iter()
            .map(|r| SignedRecord::from_bytes(r).unwrap().hash())
            .collect();
        let last = a.ix.record(hashes.last().unwrap()).unwrap().seq;
        assert_eq!(p.through, last, "a push's through is its last record's");
        assert!(!p.more && !p.reset);
        pushed.extend(hashes);
    }
    assert_eq!(pushed, all, "in local-sequence order");
    let subtree = a.ix.subtree_pushes(&Prefix::ROOT, None, small);
    assert!(subtree.len() > 2);
    assert!(subtree.iter().all(|p| p.through == 0), "no through");
    let mut sub: Vec<RecordHash> = subtree
        .iter()
        .flat_map(|p| {
            p.records
                .iter()
                .map(|r| SignedRecord::from_bytes(r).unwrap().hash())
        })
        .collect();
    sub.sort();
    all.sort();
    assert_eq!(sub, all);
}

// IR-1: the undo log.

/// A dropped transaction gives back the whole state exactly: notes made and
/// dropped, records kept only as bases, base slots, metadata and per-peer
/// state, and every table derived from them.
#[test]
fn a_dropped_transaction_gives_back_the_whole_state() {
    let (d, [v1, v2, v3]) = three_versions();
    let mut w = Dev::writer(0xa0);
    w.take(&d, &[v3]);
    // An accept that makes a note.
    let before = state(&w);
    dry_accept(&mut w, dev(0x77), d.signed(&v1));
    assert_same(&before, &state(&w), "a note made");
    assert!(w.ix.s.notes.is_empty());
    // An end of round that names a note, issues a cleanup, counts the names
    // and ends rounds with peers.
    assert!(w.accept_from(dev(0x77), d.signed(&v1)).unwrap().noted);
    let before = state(&w);
    {
        let clock = w.clock;
        let mut rng = w.rng.clone();
        let mut txn = w.ix.begin();
        assert!(txn.end_round(clock, &mut |b| rng.fill(b)).unwrap().cleanup);
        txn.round_ended(dev(0x55), true, Some((7, 3)), clock);
        txn.cursor_advanced(dev(0x55), 7, 9);
    }
    assert_same(&before, &state(&w), "a round's end");
    assert_eq!(w.ix.s.notes.len(), 1);
    // A reader keeps a replaced base only as a base; undone, it is held.
    let mut r = Dev::reader(0xa1);
    r.take(&d, &[v1]);
    r.apply("f");
    let before = state(&r);
    dry_accept(&mut r, d.id(), d.signed(&v2));
    assert_same(&before, &state(&r), "a base kept only as a base");
    r.take(&d, &[v2]);
    assert!(r.ix.s.base_only.contains_key(&v1), "kept only as a base");
    // A write over that base: the record kept only as a base goes; undone.
    let mut w2 = Dev::writer(0xa3);
    w2.take(&d, &[v1]);
    w2.apply("f");
    w2.take(&d, &[v2]);
    assert!(w2.ix.s.base_only.contains_key(&v1));
    let before = state(&w2);
    {
        let clock = w2.clock;
        let mut rng = Rng(9);
        let mut txn = w2.ix.begin();
        txn.write(&[Change::Put(file("f", 9, 77))], clock, &mut |b| {
            rng.fill(b);
        })
        .unwrap();
        txn.set_base("f", Place::Copy("c".into()), Some(v2))
            .unwrap();
    }
    assert_same(
        &before,
        &state(&w2),
        "a write over a base kept only as a base",
    );
}

/// A tree delete whose pruned vector misses two bases at one path, the path
/// itself and a conflict copy of another kind (a directory and a file), was
/// refused for ever: it planned two tombstones at that path, one path twice
/// in one batch. Now one tombstone is planned per path, of the kind of the
/// base at the path itself (the R1 review's IR-3,
/// `probe_tree_delete_two_uncovered_bases_at_one_path`).
#[test]
fn a_pruned_tree_delete_over_two_kinds_of_base_at_one_path_is_written_ir3() {
    let mut w = Dev::writer(0xa0);
    w.ix.bounds.vector = 2;
    let mut a = Dev::writer(0x01);
    a.clock = T0 - 100 * SEC;
    let fa = a.put("d/x", 1);
    let mut b = Dev::writer(0x02);
    b.clock = T0 - 90 * SEC;
    let m = b.mtime + 1;
    let db = b
        .write(&[Change::Put(super::kit::dir("d/x", m))])
        .unwrap()
        .records[0]
        .0;
    let mut c = Dev::writer(0x03);
    let yc = c.put("d/y", 3);
    let mut e = Dev::writer(0x04);
    let ze = e.put("d/z", 4);
    w.take(&a, &[fa]);
    w.take(&b, &[db]);
    w.take(&c, &[yc]);
    w.take(&e, &[ze]);
    w.apply_all();
    let bases = w.ix.bases("d/x");
    assert_eq!(bases.len(), 2, "the path itself and a conflict copy");
    let at_path = bases.iter().find(|(p, _)| *p == Place::Path).unwrap().1;
    let kind_at_path = w.ix.s.base_meta(&at_path).unwrap().kind;
    let written = w
        .write(&[Change::TreeDelete {
            path: "d".into(),
            mtime_ns: 5,
        }])
        .expect("the tree delete is written");
    let tombstones: Vec<_> = written
        .records
        .iter()
        .filter_map(|(h, _)| w.ix.s.base_meta(h).or_else(|| w.ix.s.held.get(h)?.meta()))
        .filter(|m| m.path == "d/x" && m.deleted)
        .map(|m| m.kind)
        .collect();
    assert_eq!(
        tombstones,
        vec![kind_at_path],
        "one tombstone at d/x, of the kind of the base at the path itself"
    );
}

/// An expired tree delete is judged by the folder's time alone, before
/// anything it may replace is looked at, so that a peer cannot make a key
/// holder search beneath a directory for each replayed old tree delete (the
/// index security review's IS-1(a): 24 to 48 ms each at 20 000 files, before).
#[test]
fn an_expired_tree_delete_is_judged_before_what_it_replaces_is1() {
    use licketysync_protocol::limits::TOMBSTONE_HORIZON;
    let mut d = Dev::writer(0xd0);
    let files: Vec<RecordHash> = (0..20u8).map(|i| d.put(&format!("d/{i:02}"), i)).collect();
    d.apply_all();
    let old = d.tree_delete("d").records[0].0;
    let old = d.signed(&old).clone();
    // The reader holds the files the tree delete covers, so that judging
    // what it replaces would query the index by path.
    let mut r = Dev::reader(0xa1);
    r.take(&d, &files);
    // The folder's time a horizon past the tree delete.
    let mut late = Dev::writer(0xe1);
    late.clock = T0 + TOMBSTONE_HORIZON + 10 * SEC;
    let raise = late.put("z", 1);
    r.clock = late.clock;
    r.take(&late, &[raise]);
    r.ix.s.by_path.queries.set(0);
    let a = r.accept(&old).unwrap();
    assert_eq!(
        a.judgement,
        licketysync_protocol::connection::Judgement::Expired
    );
    assert_eq!(
        r.ix.s.by_path.queries.get(),
        0,
        "nothing beneath it looked at"
    );
}

/// A record's `written_at` is its writer's clock in microseconds since the
/// Unix epoch, the unit of the clock (the coordinator's ruling I-6, the
/// spec's ninth fixup): it was whole seconds.
#[test]
fn written_at_is_the_clock_in_microseconds_i6() {
    let mut d = Dev::writer(0xd0);
    d.clock = T0 + 123_456;
    let v = d.put("f", 1);
    assert_eq!(d.ix.s.held[&v].meta().unwrap().written_at, T0 + 123_456);
}
