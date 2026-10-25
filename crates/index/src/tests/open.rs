// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Opening checks every stored record again (the owner's decision of
//! 2026-10-25, `threat-model.md` TM-9): a record whose signature or body
//! changed at rest, or that is not this folder's, is dropped and reported;
//! the records of its writer above the gap it leaves are set aside and land,
//! without a second append, once a record at the gap lands, so the index
//! stays what a reopen of the store gives; every tier checks alike; the
//! result does not depend on how many threads verify; and what was dropped
//! comes back by index sync like any record this device lacks.

use licketysync_keys::{DeviceId, FolderKey, RecordHash};
use licketysync_protocol::record::{Arrival, Draft, Held, Judgement, Record};
use licketysync_protocol::Cause;

use super::kit::{
    converge, dev, flipped_body, flipped_signature, index, index_as, other_key, push, reopen,
    signed_by_other_key, snapshot, with_set_aside, write_key, Flaky, Snapshot, Spec, OWN,
};
use crate::{Index, Kept, MemoryStore, OpenReport, Store};

/// Three writers: A writes a1, a2 and a3 at "a", each naming the one before;
/// B writes b1, a file at "b", and b2, a directory at "d"; C writes c1, a
/// tombstone at "c".
struct History {
    a: [Record; 3],
    b: [Record; 2],
    c1: Record,
}

fn history() -> History {
    let a1 = Spec::file(dev(1), 1, "a").record();
    let a2 = Spec::file(dev(1), 2, "a")
        .names(&[a1.hash()])
        .content(2)
        .record();
    let a3 = Spec::file(dev(1), 3, "a")
        .names(&[a2.hash()])
        .content(3)
        .record();
    let b1 = Spec::file(dev(2), 1, "b").record();
    let b2 = Spec::dir(dev(2), 2, "d").record();
    let c1 = Spec::tombstone(dev(3), 1, "c").record();
    History {
        a: [a1, a2, a3],
        b: [b1, b2],
        c1,
    }
}

impl History {
    fn all(&self) -> Vec<&Record> {
        self.a.iter().chain(&self.b).chain([&self.c1]).collect()
    }
}

/// An index that accepted `records` as pushes, in this order.
fn accepted(records: &[&Record]) -> Index<MemoryStore> {
    let mut ix = index();
    for r in records {
        push(&mut ix, r);
    }
    ix
}

fn store_of(records: &[&Record]) -> MemoryStore {
    let mut store = MemoryStore::new();
    for r in records {
        store.append(r).unwrap();
    }
    store
}

/// The history as stored with a2's signature and b2's body each changed by
/// one bit at rest; and b2 as stored.
fn corrupted(h: &History) -> (MemoryStore, Record) {
    let bad_b2 = flipped_body(&h.b[1]);
    let store = store_of(&[
        &h.a[0],
        &flipped_signature(&h.a[1]),
        &h.a[2],
        &h.b[0],
        &bad_b2,
        &h.c1,
    ]);
    (store, bad_b2)
}

fn sorted(mut hashes: Vec<RecordHash>) -> Vec<RecordHash> {
    hashes.sort_unstable();
    hashes
}

#[test]
fn opening_drops_a_record_whose_signature_or_body_changed_at_rest() {
    let h = history();
    let (store, bad_b2) = corrupted(&h);
    // b2's changed body still parses: only its signature tells.
    assert_ne!(bad_b2.hash(), h.b[1].hash());
    assert_eq!(bad_b2.device_id(), dev(2));
    let (ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(report.dropped, sorted(vec![h.a[1].hash(), bad_b2.hash()]));
    assert_eq!(
        report.set_aside,
        vec![h.a[2].hash()],
        "a3 lies past a2's gap"
    );
    assert!(!report.is_clean());
    for gone in [&h.a[1], &h.a[2], &h.b[1], &bad_b2] {
        assert!(!ix.holds(&gone.hash()) && ix.record(&gone.hash()).is_none());
    }
    // The index is the one that accepting the records that passed builds,
    // and opening cost one digest step per record held.
    let expected = accepted(&[&h.a[0], &h.b[0], &h.c1]);
    assert_eq!(
        snapshot(&ix),
        with_set_aside(snapshot(&expected), &report.set_aside)
    );
    assert_eq!(ix.work, 3);
    assert_eq!(ix.writer_cursor(&dev(1)).seq, 1);
    assert_eq!(ix.writer_cursor(&dev(2)).seq, 1);
}

#[test]
fn read_and_sealed_holders_check_the_same_way() {
    let h = history();
    let (store, _) = corrupted(&h);
    let (writer, expected) = Index::open(FolderKey::from(write_key()), OWN, store.clone()).unwrap();
    assert_eq!((expected.dropped.len(), expected.set_aside.len()), (2, 1));
    for key in [
        FolderKey::from(write_key().read_key()),
        FolderKey::from(write_key().sealed_key()),
    ] {
        let sealed = key.data_key().is_none();
        let (ix, report) = Index::open(key, OWN, store.clone()).unwrap();
        assert_eq!(report, expected);
        let (s, w) = (snapshot(&ix), snapshot(&writer));
        assert_eq!((&s.held, &s.writers), (&w.held, &w.writers));
        if !sealed {
            assert_eq!(s, w);
        }
    }
}

#[test]
fn records_of_another_folders_key_are_dropped() {
    let h = history();
    // Another folder's record, with its own folder ID: step 1 refuses it.
    let foreign = Draft {
        device_id: dev(1),
        seq: 1,
        supersedes: vec![],
        deleted: false,
        chunks: vec![],
        meta: Spec::file(dev(1), 1, "f").content(0).meta(),
    }
    .sign(&other_key(), &mut |b: &mut [u8]| b.fill(7))
    .unwrap();
    // This folder's a1, signed by another folder's key: it parses, and its
    // signature does not verify under this folder's verification key.
    let a1_forged = signed_by_other_key(h.a[0].signed().body());
    assert_eq!(a1_forged.hash(), h.a[0].hash());
    let store = Flaky {
        inner: store_of(&[&h.a[1], &h.a[2], &h.b[0]]),
        extra: vec![foreign.clone(), a1_forged],
        ..Flaky::default()
    };
    let (ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(report.dropped, sorted(vec![foreign.hash(), h.a[0].hash()]));
    assert_eq!(report.set_aside, vec![h.a[1].hash(), h.a[2].hash()]);
    assert_eq!(
        snapshot(&ix),
        with_set_aside(snapshot(&accepted(&[&h.b[0]])), &report.set_aside)
    );
    assert_eq!(ix.writer_cursor(&dev(1)).seq, 0);
}

#[test]
fn a_bad_copy_beside_a_good_one_drops_nothing_and_a_bad_one_twice_is_named_once() {
    let h = history();
    let good = store_of(&[&h.a[0], &h.b[0]]);
    let store = Flaky {
        inner: good.clone(),
        extra: vec![flipped_signature(&h.a[0]).signed().clone()],
        ..Flaky::default()
    };
    let ix = reopen(FolderKey::from(write_key()), OWN, store);
    assert_eq!(snapshot(&ix), snapshot(&accepted(&[&h.a[0], &h.b[0]])));
    let twice = flipped_signature(&h.c1).signed().clone();
    let store = Flaky {
        inner: good,
        extra: vec![twice.clone(), twice],
        ..Flaky::default()
    };
    let (_, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(
        report,
        OpenReport {
            dropped: vec![h.c1.hash()],
            set_aside: vec![],
        }
    );
}

#[test]
fn a_dropped_record_arriving_later_is_applied_and_lands_what_was_set_aside() {
    let h = history();
    let (store, bad_b2) = corrupted(&h);
    let store = Flaky {
        inner: store,
        ..Flaky::default()
    };
    let (mut ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(report.set_aside, vec![h.a[2].hash()]);
    assert_eq!(snapshot(&ix).set_aside, vec![h.a[2].hash()]);
    let work = ix.work;
    let o = ix.accept(h.a[1].clone(), Arrival::Push).unwrap();
    assert_eq!(o.judgement, Judgement::Next);
    assert_eq!(o.landed, vec![h.a[2].hash()], "a3 lands behind a2");
    assert_eq!(o.changed, vec!["a".to_string()]);
    assert!(o.rows().is_empty() && !o.waits && o.released.is_empty());
    assert_eq!(ix.work - work, 2, "one digest step each");
    assert_eq!(
        ix.store().appended,
        vec![h.a[1].hash()],
        "a3 is not appended again"
    );
    assert_eq!(ix.writer_cursor(&dev(1)).seq, 3);
    // a3 from a peer is now a duplicate.
    assert_eq!(push(&mut ix, &h.a[2]).judgement, Judgement::Duplicate);
    let o = ix.accept(h.b[1].clone(), Arrival::Push).unwrap();
    assert_eq!(o.judgement, Judgement::Next);
    assert_eq!(o.landed, Vec::<RecordHash>::new());
    let all = accepted(&h.all());
    assert_eq!(snapshot(&ix), snapshot(&all));
    // a2's good copy replaced the bad one under the same hash; b2's changed
    // body has a hash of its own, so it stays in the store and every open
    // names it again, while nothing of it is applied.
    let (reopened, report) =
        Index::open(FolderKey::from(write_key()), OWN, ix.into_store()).unwrap();
    assert_eq!(report.dropped, vec![bad_b2.hash()]);
    assert_eq!(report.set_aside, Vec::<RecordHash>::new());
    assert_eq!(snapshot(&reopened), snapshot(&all));
}

#[test]
fn a_good_copy_arriving_later_replaces_the_bad_one_so_the_next_open_is_clean() {
    let h = history();
    let store = store_of(&[&h.a[0], &flipped_signature(&h.a[1]), &h.a[2]]);
    let (mut ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(
        (report.dropped, report.set_aside),
        (vec![h.a[1].hash()], vec![h.a[2].hash()])
    );
    assert_eq!(push(&mut ix, &h.a[1]).judgement, Judgement::Next);
    // The store kept the envelope it was given in place of the one it had.
    let stored = ix.store().load().unwrap();
    assert!(stored.contains(h.a[1].signed()));
    assert!(!stored.contains(flipped_signature(&h.a[1]).signed()));
    let reopened = reopen(FolderKey::from(write_key()), OWN, ix.into_store());
    assert_eq!(
        snapshot(&reopened),
        snapshot(&accepted(&[&h.a[0], &h.a[1], &h.a[2]]))
    );
}

/// Writer W's records 1 to 5 at paths of their own, with 2 stored with its
/// signature changed.
fn w_with_seq_2_changed() -> (DeviceId, Vec<Record>, Flaky) {
    let w = dev(5);
    let rs: Vec<Record> = (1..=5)
        .map(|seq| Spec::file(w, seq, &format!("w{seq}")).record())
        .collect();
    let bad = flipped_signature(&rs[1]);
    let inner = store_of(&[&rs[0], &bad, &rs[2], &rs[3], &rs[4]]);
    (
        w,
        rs,
        Flaky {
            inner,
            ..Flaky::default()
        },
    )
}

#[test]
fn a_record_another_write_holder_signs_at_the_gap_lands_the_rest_as_a_reopen_would() {
    let (w, rs, store) = w_with_seq_2_changed();
    let (mut ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    let above: Vec<RecordHash> = rs[2..].iter().map(Record::hash).collect();
    assert_eq!(report.dropped, vec![rs[1].hash()]);
    assert_eq!(report.set_aside, above);
    assert_eq!(ix.writer_cursor(&w).seq, 1);
    // A push of a record above the gap is a gap like any other.
    assert_eq!(push(&mut ix, &rs[3]).judgement, Judgement::PushGap);
    // Any write holder can sign under W's device ID at seq 2.
    let filler = Spec::file(w, 2, "other").salt(9).record();
    let work = ix.work;
    let o = ix.accept(filler.clone(), Arrival::Push).unwrap();
    assert_eq!(o.judgement, Judgement::Next);
    assert_eq!(o.landed, above);
    // The outcome's flags are the filler's; each landed record's own state
    // shows through the index.
    assert!(!o.own_ahead && !o.waits && o.rows().is_empty());
    assert!(above
        .iter()
        .all(|h| matches!(ix.kept(h), Some(Kept::Applied(_))) && !ix.is_waiting(h)));
    assert_eq!(ix.work - work, 4, "one digest step per record");
    assert_eq!(ix.store().appended, vec![filler.hash()]);
    assert_eq!(ix.writer_cursor(&w).seq, 5);
    let state = snapshot(&ix);
    assert_eq!(state.set_aside, Vec::<RecordHash>::new());
    // The store's records give the same index: the bad copy of rs[1] is
    // still there and dropped again, and nothing is set aside.
    let (reopened, report) =
        Index::open(FolderKey::from(write_key()), OWN, ix.into_store()).unwrap();
    assert_eq!(snapshot(&reopened), state);
    assert_eq!(report.dropped, vec![rs[1].hash()]);
    assert_eq!(report.set_aside, Vec::<RecordHash>::new());
}

#[test]
fn this_device_writing_at_its_lost_seq_lands_the_rest_and_writes_next_above_them() {
    let mine: Vec<Record> = (1..=3)
        .map(|seq| Spec::file(OWN, seq, &format!("m{seq}")).record())
        .collect();
    let store = store_of(&[&mine[0], &flipped_signature(&mine[1]), &mine[2]]);
    let (mut ix, _) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(ix.next_seq(), Some(2));
    let mut fill = |b: &mut [u8]| b.fill(3);
    let draft = ix
        .draft(Spec::file(OWN, 2, "new").content(0).meta(), vec![], false)
        .unwrap();
    assert_eq!(draft.seq, 2, "the lost seq is used again");
    let o = ix.write(&draft, &mut fill).unwrap();
    assert_eq!(o.landed, vec![mine[2].hash()]);
    assert_eq!(ix.next_seq(), Some(4), "and only the lost one");
    // A record of this device's own landed above the write: the counter moved
    // past it, which raises the informational issue of 4.5.
    assert!(o.own_ahead);
    assert_eq!(o.rows(), vec![Cause::OwnSequenceAhead]);
    let draft = ix
        .draft(Spec::file(OWN, 4, "next").content(0).meta(), vec![], false)
        .unwrap();
    let o = ix.write(&draft, &mut fill).unwrap();
    assert_eq!(ix.record(&o.hash).unwrap().seq(), 4);
    let state = snapshot(&ix);
    let (reopened, _) = Index::open(FolderKey::from(write_key()), OWN, ix.into_store()).unwrap();
    assert_eq!(snapshot(&reopened), state);
}

#[test]
fn index_sync_brings_back_what_opening_dropped_or_set_aside() {
    let h = history();
    let (store, _) = corrupted(&h);
    let (mut ix, _) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    let mut peer = index_as(dev(0xb0));
    for r in h.all() {
        push(&mut peer, r);
    }
    // The cursors and digests describe only the records held, so the
    // peer's replies, through real requests and pages, carry the rest.
    converge(&mut ix, &mut peer);
    assert_eq!(snapshot(&ix), snapshot(&peer));
    assert_eq!(snapshot(&ix), snapshot(&accepted(&h.all())));
}

#[test]
fn a_dropped_concurrent_version_is_found_by_the_digest() {
    // Two records of one writer at seq 1: dropping one leaves the cursor
    // where it was, and the digest there differs from a peer's.
    let w = dev(4);
    let one = Spec::file(w, 1, "p").record();
    let other = Spec::file(w, 1, "q").salt(1).record();
    let store = store_of(&[&one, &flipped_signature(&other)]);
    let (mut ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(report.dropped, vec![other.hash()]);
    assert_eq!(ix.writer_cursor(&w).seq, 1);
    let mut peer = accepted(&[&one, &other]);
    assert_ne!(ix.writer_cursor(&w).digest, peer.writer_cursor(&w).digest);
    converge(&mut ix, &mut peer);
    assert_eq!(snapshot(&ix), snapshot(&accepted(&[&one, &other])));
}

#[test]
fn a_dropped_record_of_this_device_lowers_its_next_seq_until_it_returns() {
    let mine: Vec<Record> = (1..=3)
        .map(|seq| Spec::file(OWN, seq, &format!("m{seq}")).record())
        .collect();
    let store = store_of(&[&mine[0], &flipped_signature(&mine[1]), &mine[2]]);
    let (mut ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!(report.set_aside, vec![mine[2].hash()]);
    assert_eq!(ix.next_seq(), Some(2));
    // Back from a peer, it is ahead of the counter and moves it, as for a
    // restored backup (`protocol.md` 4.5), and the record set aside above it
    // lands with it.
    let o = ix.accept(mine[1].clone(), Arrival::Push).unwrap();
    assert!(o.own_ahead);
    assert_eq!(o.landed, vec![mine[2].hash()]);
    assert_eq!(ix.next_seq(), Some(4));
    assert_eq!(push(&mut ix, &mine[2]).judgement, Judgement::Duplicate);
}

/// Four writers of twelve records each, with concurrent versions, records
/// that wait and opaque ones; every fifth stored with its signature or body
/// changed at rest.
fn larger_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    let mut last: Vec<RecordHash> = Vec::new();
    for w in 1..=4u8 {
        for n in 0..12u8 {
            let seq = u64::from(n.min(10)) + 1;
            let mut spec = Spec::file(dev(w), seq, &format!("p{}", n % 5))
                .salt(n)
                .names(&last);
            if n % 7 == 3 {
                spec = spec.fault(super::kit::Fault::Seal);
            }
            let r = spec.record();
            last = vec![r.hash()];
            let stored = match (w + n) % 10 {
                0 => flipped_signature(&r),
                5 => flipped_body(&r),
                _ => r,
            };
            store.append(&stored).unwrap();
        }
    }
    store
}

#[test]
fn one_thread_and_many_give_the_same_index_and_report() {
    let store = larger_store();
    let open = |threads: usize| -> (Snapshot, OpenReport, Option<u64>) {
        let (ix, report) =
            Index::open_with_threads(FolderKey::from(write_key()), OWN, store.clone(), threads)
                .unwrap();
        (snapshot(&ix), report, ix.next_seq())
    };
    let one = open(1);
    assert!(!one.1.dropped.is_empty() && !one.1.set_aside.is_empty());
    assert!(!one.0.held.is_empty() && !one.0.waiting.is_empty());
    for threads in [0, 2, 3, 4, 7, 47, 48, 64, 1000] {
        assert_eq!(open(threads), one, "{threads} threads");
    }
    let (ix, report) = Index::open(FolderKey::from(write_key()), OWN, store).unwrap();
    assert_eq!((snapshot(&ix), report, ix.next_seq()), one);
}

#[test]
fn an_empty_store_opens_clean_on_any_number_of_threads() {
    for threads in [0, 1, 8] {
        let (ix, report) = Index::open_with_threads(
            FolderKey::from(write_key()),
            DeviceId([1; 32]),
            MemoryStore::new(),
            threads,
        )
        .unwrap();
        assert!(ix.is_empty() && report.is_clean());
    }
}
