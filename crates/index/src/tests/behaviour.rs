// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a record does to the index, what the index persists and rebuilds,
//! what it writes, what it serves, and how much work each costs.

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::{DeviceId, FolderKey, RecordHash, WriterDigest};
use licketysync_protocol::exchange::{range_request, Scope, ServeRequest, WriterCursor};
use licketysync_protocol::limits::{DEFAULT_MESSAGE_SIZE, MAX_SUPERSEDES};
use licketysync_protocol::messages::IndexRequest;
use licketysync_protocol::record::{writer_digests, Arrival, Judgement, Kind, Record, WriterFault};
use licketysync_protocol::Cause;

use super::kit::{
    converge, dev, display_order, flipped_signature, garbage_signature, heads, index, index_as,
    other_key, push, read_index, reopen, sealed_index, snapshot, verifier, with_set_aside,
    write_key, Fault, Flaky, Spec, OWN,
};
use crate::{
    AcceptError, Index, Kept, MemoryStore, OpenError, Reply, Store, StoreError, WriteError,
};

fn reference_digests<S>(index: &Index<S>, writer: &DeviceId) -> BTreeMap<u64, WriterDigest> {
    writer_digests(index.records_of(writer).map(|r| (r.seq(), r.hash())))
}

fn cached_digests<S>(index: &Index<S>, writer: &DeviceId) -> BTreeMap<u64, WriterDigest> {
    let cursor = index.writer_cursor(writer).seq;
    (1..=cursor)
        .map(|s| (s, index.digest_at(writer, s).unwrap()))
        .collect()
}

#[test]
fn next_records_extend_the_cursor_and_the_cached_digest() {
    let mut ix = index();
    let w = dev(1);
    assert_eq!(ix.writer_cursor(&w), WriterCursor::none(w));
    for seq in 1..=3 {
        let o = push(&mut ix, &Spec::file(w, seq, &format!("f{seq}")).record());
        assert_eq!(o.judgement, Judgement::Next);
        assert!(o.stored() && o.rows().is_empty());
        assert_eq!(ix.writer_cursor(&w).seq, seq);
    }
    assert_eq!(cached_digests(&ix, &w), reference_digests(&ix, &w));
    let c = ix.writer_cursor(&w);
    assert_eq!(c.digest, ix.digest_at(&w, 3));
    assert_eq!(ix.digest_at(&w, 0), None);
    assert_eq!(ix.digest_at(&w, 4), None);
    assert_eq!(ix.digest_at(&dev(9), 1), None);
    assert_eq!(ix.len(), 3);
    assert_eq!(ix.writer_count(), 1);
    assert!(!ix.is_empty());
    push(&mut ix, &Spec::file(dev(2), 1, "g").record());
    assert_eq!((ix.len(), ix.writer_count()), (4, 2));
}

#[test]
fn a_duplicate_is_ignored_without_verifying_its_signature() {
    let mut ix = index();
    let r = Spec::file(dev(1), 1, "a").record();
    push(&mut ix, &r);
    let before = snapshot(&ix);
    // Garbage in place of the signature: verifying it would be a forgery.
    let o = push(&mut ix, &garbage_signature(&r));
    assert_eq!(o.judgement, Judgement::Duplicate);
    assert!(!o.stored());
    assert_eq!(o.rows(), vec![Cause::Duplicate]);
    assert_eq!(snapshot(&ix), before);
}

#[test]
fn a_push_gap_is_ignored_without_verifying_and_stores_nothing() {
    let mut ix = index();
    let gap = Spec::file(dev(1), 2, "a").record();
    for r in [gap.clone(), flipped_signature(&gap)] {
        let o = push(&mut ix, &r);
        assert_eq!(o.judgement, Judgement::PushGap);
        assert_eq!(o.rows(), vec![Cause::PushGap]);
        assert!(ix.is_empty() && ix.store().is_empty());
    }
}

#[test]
fn inside_a_reply_a_gap_or_a_writer_out_of_scope_is_a_sender_violation() {
    let mut ix = index();
    let gap = Spec::file(dev(1), 2, "a").record();
    let first = Spec::file(dev(1), 1, "a").record();
    for (r, in_scope) in [
        (gap.clone(), true),
        (flipped_signature(&gap), true),
        (first.clone(), false),
        (flipped_signature(&first), false),
    ] {
        assert_eq!(
            ix.accept(r, Arrival::Reply { in_scope }),
            Err(AcceptError::Refused(Cause::SenderViolation))
        );
    }
    assert!(ix.is_empty() && ix.store().is_empty());
    // In scope and in place, a reply's record is stored like a push's.
    let o = ix.accept(first, Arrival::Reply { in_scope: true }).unwrap();
    assert_eq!(o.judgement, Judgement::Next);
}

#[test]
fn a_forged_record_is_refused_and_forged_beats_a_writer_fault() {
    let mut ix = index();
    for spec in [
        Spec::file(dev(1), 1, "a"),
        Spec::file(dev(1), 1, "a").fault(Fault::Seal),
    ] {
        assert_eq!(
            ix.accept(flipped_signature(&spec.record()), Arrival::Push),
            Err(AcceptError::Refused(Cause::Forged))
        );
    }
    assert!(ix.is_empty() && ix.store().is_empty());
}

#[test]
fn a_record_of_another_folder_is_refused() {
    let key = other_key();
    let signed = licketysync_protocol::record::Draft {
        device_id: dev(1),
        seq: 1,
        supersedes: vec![],
        deleted: false,
        chunks: vec![],
        meta: Spec::file(dev(1), 1, "a").content(0).meta(),
    }
    .sign(&key, &mut |b: &mut [u8]| b.fill(1))
    .unwrap();
    let r = Record::parse(signed, key.verifier()).unwrap();
    let mut ix = index();
    assert_eq!(ix.accept(r, Arrival::Push), Err(AcceptError::OtherFolder));
}

#[test]
fn a_concurrent_version_below_the_cursor_recomputes_the_digests_from_its_seq() {
    let mut ix = index();
    let w = dev(1);
    for seq in 1..=4 {
        push(&mut ix, &Spec::file(w, seq, "a").salt(1).record());
    }
    let before = cached_digests(&ix, &w);
    let work = ix.work;
    let low = Spec::file(w, 2, "b").salt(2).record();
    let o = push(&mut ix, &low);
    assert_eq!(o.judgement, Judgement::Concurrent);
    assert_eq!(o.rows(), vec![Cause::ConcurrentVersion]);
    assert_eq!(ix.writer_cursor(&w).seq, 4);
    let after = cached_digests(&ix, &w);
    assert_eq!(after, reference_digests(&ix, &w));
    assert_eq!(
        after[&1], before[&1],
        "below its seq the cache is untouched"
    );
    for s in 2..=4 {
        assert_ne!(after[&s], before[&s], "from its seq up the cache moved");
    }
    // Seq 2 holds two records now, seqs 3 and 4 one each: four digest steps
    // (an activation that notifies no waiter counts nothing).
    assert_eq!(ix.work - work, 4);
    // At the cursor: only the cursor's digest moves.
    let before = cached_digests(&ix, &w);
    push(&mut ix, &Spec::file(w, 4, "c").salt(3).record());
    let after = cached_digests(&ix, &w);
    assert_eq!(after, reference_digests(&ix, &w));
    assert_eq!(after[&3], before[&3]);
    assert_ne!(after[&4], before[&4]);
}

#[test]
fn writer_faults_are_stored_opaque_and_counted() {
    let mut ix = index();
    let w = dev(1);
    let cases = [
        (Fault::Seal, "seal"),
        (Fault::DirectoryWithChunk, "dir"),
        (Fault::FileWithoutChunks, "nochunks"),
    ];
    for (i, (fault, path)) in cases.into_iter().enumerate() {
        let seq = u64::try_from(i).unwrap() + 1;
        let mut spec = Spec::file(w, seq, path).fault(fault);
        if fault == Fault::DirectoryWithChunk {
            spec.kind = Kind::Directory;
        }
        let r = spec.record();
        let o = push(&mut ix, &r);
        assert_eq!(o.judgement, Judgement::Next);
        assert!(o.fault.is_some(), "{fault:?}");
        assert_eq!(o.rows(), vec![Cause::WriterFault]);
        let expected = match fault {
            Fault::Seal => matches!(o.fault, Some(WriterFault::Seal(_))),
            Fault::DirectoryWithChunk => o.fault == Some(WriterFault::DirectoryWithChunks),
            Fault::FileWithoutChunks => o.fault == Some(WriterFault::FileWithoutChunks),
        };
        assert!(expected, "{fault:?}: {:?}", o.fault);
        assert!(matches!(ix.kept(&r.hash()), Some(Kept::Opaque(f)) if Some(f) == o.fault.as_ref()));
        assert_eq!(ix.writer_cursor(&w).seq, seq);
        assert!(ix.heads(path).is_empty());
        assert_eq!(o.changed, Vec::<String>::new());
    }
    assert_eq!(cached_digests(&ix, &w), reference_digests(&ix, &w));
    assert_eq!(ix.paths().count(), 0);
}

#[test]
fn a_path_that_is_not_nfc_is_a_distinct_path_not_a_fault() {
    let mut ix = index();
    // "é" composed and decomposed.
    let nfc = Spec::file(dev(1), 1, "nfc-\u{e9}").record();
    let nfd = Spec::file(dev(2), 1, "nfc-e\u{301}").record();
    assert!(push(&mut ix, &nfc).fault.is_none());
    assert!(push(&mut ix, &nfd).fault.is_none());
    assert_eq!(heads(&ix, "nfc-\u{e9}"), vec![nfc.hash()]);
    assert_eq!(heads(&ix, "nfc-e\u{301}"), vec![nfd.hash()]);
}

#[test]
fn a_record_under_this_devices_own_id_moves_its_counter() {
    let mut ix = index();
    assert_eq!(ix.next_seq(), Some(1));
    let theirs = Spec::file(OWN, 1, "a").record();
    let o = push(&mut ix, &theirs);
    assert!(o.own_ahead);
    assert_eq!(o.rows(), vec![Cause::OwnSequenceAhead]);
    assert_eq!(ix.next_seq(), Some(2));
    // A concurrent version under the own ID below the counter is not ahead.
    let o = push(&mut ix, &Spec::file(OWN, 1, "b").salt(5).record());
    assert!(!o.own_ahead);
    assert_eq!(ix.next_seq(), Some(2));
    // Another writer's record never is.
    assert!(!push(&mut ix, &Spec::file(dev(1), 1, "c").record()).own_ahead);
}

#[test]
fn a_write_commits_the_record_and_its_counter_before_it_returns() {
    let mut ix = index();
    let spec = Spec::file(OWN, 1, "a").content(0);
    let draft = ix.draft(spec.meta(), vec![], false).unwrap();
    assert_eq!((draft.device_id, draft.seq), (OWN, 1));
    assert!(draft.supersedes.is_empty() && !draft.deleted);
    let o = ix.write(&draft, &mut |b: &mut [u8]| b.fill(7)).unwrap();
    assert_eq!(o.judgement, Judgement::Next);
    assert!(!o.own_ahead && o.rows().is_empty());
    assert_eq!(o.changed, vec!["a".to_string()]);
    assert_eq!(ix.next_seq(), Some(2));
    assert_eq!(ix.store().len(), 1, "appended before write returned");
    assert_eq!(heads(&ix, "a"), vec![o.hash]);
    assert_eq!(ix.record(&o.hash).unwrap().device_id(), OWN);
    // The next write names the head.
    let next = ix
        .draft(spec.clone().mtime(5).meta(), vec![], false)
        .unwrap();
    assert_eq!(next.supersedes, vec![o.hash]);
    assert_eq!(next.seq, 2);
    // A stale draft, or one under another device ID, is refused.
    assert_eq!(
        ix.write(&draft, &mut |b: &mut [u8]| b.fill(8)),
        Err(WriteError::NotNext { expected: 2 })
    );
    let mut foreign = next.clone();
    foreign.device_id = dev(1);
    assert_eq!(
        ix.write(&foreign, &mut |b: &mut [u8]| b.fill(8)),
        Err(WriteError::NotNext { expected: 2 })
    );
    let o2 = ix.write(&next, &mut |b: &mut [u8]| b.fill(8)).unwrap();
    assert_eq!(heads(&ix, "a"), vec![o2.hash]);
    // What a reader would refuse is never written: a path outside the
    // grammar, and a non-empty file's metadata without its chunk.
    let mut bad = ix.draft(spec.meta(), vec![], false).unwrap();
    bad.meta.path = "/abs".into();
    assert!(matches!(
        ix.write(&bad, &mut |b: &mut [u8]| b.fill(9)),
        Err(WriteError::Draft(_))
    ));
    let hashless = ix
        .draft(Spec::file(OWN, 3, "a").meta(), vec![], false)
        .unwrap();
    assert!(matches!(
        ix.write(&hashless, &mut |b: &mut [u8]| b.fill(9)),
        Err(WriteError::Draft(_))
    ));
    assert_eq!(ix.next_seq(), Some(3));
    assert_eq!(ix.store().len(), 2);
    // A tombstone deletes the path.
    let tomb = ix.draft(spec.meta(), vec![], true).unwrap();
    assert_eq!(tomb.supersedes, vec![o2.hash]);
    ix.write(&tomb, &mut |b: &mut [u8]| b.fill(10)).unwrap();
    assert!(ix.heads("a").is_deleted());
}

#[test]
fn only_a_write_holder_writes() {
    assert_eq!(index().key().tier(), licketysync_keys::Tier::Write);
    for mut ix in [read_index(), sealed_index()] {
        assert_ne!(ix.key().tier(), licketysync_keys::Tier::Write);
        assert_eq!(ix.folder_id(), index().folder_id());
        let meta = Spec::file(OWN, 1, "a").content(0).meta();
        assert_eq!(
            ix.draft(meta.clone(), vec![], false).unwrap_err(),
            WriteError::NotWriteKey
        );
        assert_eq!(
            ix.draft_rename("b", meta.clone(), vec![]).unwrap_err(),
            WriteError::NotWriteKey
        );
        let draft = index().draft(meta, vec![], false).unwrap();
        assert_eq!(
            ix.write(&draft, &mut |b: &mut [u8]| b.fill(1)),
            Err(WriteError::NotWriteKey)
        );
    }
}

#[test]
fn a_store_failure_changes_nothing() {
    let r = Spec::file(dev(1), 1, "a").record();
    let store = Flaky {
        fail_append: true,
        ..Flaky::default()
    };
    let mut ix = reopen(FolderKey::from(write_key()), OWN, store);
    let before = snapshot(&ix);
    let err = ix.accept(r.clone(), Arrival::Push).unwrap_err();
    assert_eq!(err, AcceptError::Store(StoreError::Full));
    assert!(ix.is_empty());
    assert!(!licketysync_protocol::record::Held::holds(&ix, &r.hash()));
    assert!(ix.store().inner.is_empty());
    assert_eq!(snapshot(&ix), before);
    let draft = ix
        .draft(Spec::file(OWN, 1, "a").content(0).meta(), vec![], false)
        .unwrap();
    assert_eq!(
        ix.write(&draft, &mut |b: &mut [u8]| b.fill(1)),
        Err(WriteError::Store(StoreError::Full))
    );
    assert_eq!(ix.next_seq(), Some(1));
    assert!(ix.is_empty() && ix.store().inner.is_empty());
    // Once the store takes records again, the same record is held: the
    // failure left nothing behind that would make it a duplicate.
    let mut store = ix.into_store();
    store.fail_append = false;
    let mut ix = reopen(FolderKey::from(write_key()), OWN, store);
    assert_eq!(
        ix.accept(r, Arrival::Push).unwrap().judgement,
        Judgement::Next
    );
    assert_eq!(ix.store().inner.len(), 1);
}

fn assorted() -> Vec<Record> {
    let r0 = Spec::file(dev(1), 1, "a").record();
    let r1 = Spec::file(dev(1), 2, "a")
        .names(&[r0.hash()])
        .mtime(5)
        .record();
    let r2 = Spec::file(dev(2), 1, "a")
        .names(&[r0.hash()])
        .content(2)
        .record();
    let opaque = Spec::file(dev(2), 2, "x").fault(Fault::Seal).record();
    let waits = Spec::file(dev(3), 1, "b")
        .names(&[RecordHash([0xee; 32])])
        .record();
    let dir = Spec::dir(dev(3), 2, "d").names(&[opaque.hash()]).record();
    let rename = Spec::file(dev(1), 3, "c")
        .names(&[r1.hash(), r2.hash()])
        .record();
    let tomb = Spec::tombstone(dev(2), 3, "c")
        .names(&[rename.hash()])
        .record();
    let concurrent = Spec::file(dev(1), 2, "e").salt(9).record();
    vec![r0, r1, r2, opaque, waits, dir, rename, tomb, concurrent]
}

#[test]
fn reopening_rebuilds_the_same_state_from_the_records() {
    let mut ix = index();
    for r in assorted() {
        push(&mut ix, &r);
    }
    let state = snapshot(&ix);
    assert_eq!(state.waiting.len(), 1);
    assert_eq!(state.opaque.len(), 1);
    assert!(ix.heads("c").is_deleted());
    let reopened = reopen(FolderKey::from(write_key()), OWN, ix.into_store());
    assert_eq!(snapshot(&reopened), state);
    assert_eq!(reopened.next_seq(), Some(1));
}

/// Regression test for the dedup in `Index::open` (R1 SF2 on e304e07): a repeat of a
/// record that a record of a lower-sorted device ID names would, replayed
/// twice, join the heads again after the record naming it had replaced it.
#[test]
fn opening_counts_a_record_loaded_twice_once_even_when_a_lower_writer_names_it() {
    let named = Spec::file(dev(2), 1, "p").record();
    let naming = Spec::file(dev(1), 1, "p")
        .names(&[named.hash()])
        .content(2)
        .record();
    let mut ix = reopen(FolderKey::from(write_key()), OWN, Flaky::default());
    push(&mut ix, &named);
    push(&mut ix, &naming);
    let state = snapshot(&ix);
    assert_eq!(state.heads, vec![("p".to_string(), vec![naming.hash()])]);
    let mut store = ix.into_store();
    store.extra = vec![named.signed().clone(), named.signed().clone()];
    let reopened = reopen(FolderKey::from(write_key()), OWN, store);
    assert_eq!(snapshot(&reopened), state);
    // One digest step per distinct record, and the one waiter notified.
    assert_eq!(reopened.work, 3);
}

/// Was "opening refuses a corrupt store": a gap in the store and a record of
/// another folder made `open` fail. Each is now set aside or dropped and
/// reported, and the rest opens as before (the owner's decision of
/// 2026-10-25).
#[test]
fn opening_sets_aside_a_gap_drops_a_foreign_record_and_tolerates_repeats() {
    let records = assorted();
    let mut ix = reopen(FolderKey::from(write_key()), OWN, Flaky::default());
    for r in &records {
        push(&mut ix, r);
    }
    let state = snapshot(&ix);
    let mut store = ix.into_store();
    store.extra = vec![
        records[0].signed().clone(),
        records[2].signed().clone(),
        records[6].signed().clone(),
    ];
    let ix = reopen(FolderKey::from(write_key()), OWN, store.clone());
    assert_eq!(snapshot(&ix), state, "a record loaded twice counts once");
    // A record past a gap, here one the store never held below it.
    let past_gap = Spec::file(dev(7), 3, "gap").record();
    store.extra = vec![past_gap.signed().clone()];
    let (ix, report) = Index::open(FolderKey::from(write_key()), OWN, store.clone()).unwrap();
    assert_eq!(report.set_aside, vec![past_gap.hash()]);
    assert!(report.dropped.is_empty() && !report.is_clean());
    assert_eq!(
        snapshot(&ix),
        with_set_aside(state.clone(), &report.set_aside)
    );
    // A record of another folder fails step 1 against this one.
    let key = other_key();
    let foreign = licketysync_protocol::record::Draft {
        device_id: dev(1),
        seq: 1,
        supersedes: vec![],
        deleted: false,
        chunks: vec![],
        meta: Spec::file(dev(1), 1, "a").content(0).meta(),
    }
    .sign(&key, &mut |b: &mut [u8]| b.fill(1))
    .unwrap();
    store.extra = vec![foreign.clone()];
    let (ix, report) = Index::open(FolderKey::from(write_key()), OWN, store.clone()).unwrap();
    assert_eq!(report.dropped, vec![foreign.hash()]);
    assert_eq!(report.set_aside, Vec::<RecordHash>::new());
    assert_eq!(snapshot(&ix), state);
    store.extra.clear();
    store.fail_load = true;
    assert_eq!(
        Index::open(FolderKey::from(write_key()), OWN, store).unwrap_err(),
        OpenError::Store(StoreError::Io("cannot read".into()))
    );
}

#[test]
fn a_sealed_holder_stores_unopened_and_computes_no_heads() {
    let mut sealed = sealed_index();
    let mut writer = index();
    for r in assorted() {
        let o = push(&mut sealed, &r);
        assert!(o.fault.is_none() && !o.waits && o.changed.is_empty());
        assert!(matches!(sealed.kept(&r.hash()), Some(Kept::Sealed)));
        push(&mut writer, &r);
    }
    let (s, w) = (snapshot(&sealed), snapshot(&writer));
    assert_eq!(s.held, w.held);
    assert_eq!(s.writers, w.writers, "cursors and digests are every tier's");
    assert!(s.heads.is_empty() && s.waiting.is_empty() && s.opaque.is_empty());
    assert!(sealed.heads("a").is_empty());
    // A sealed holder rebuilds the same way.
    let reopened = reopen(
        FolderKey::from(write_key().sealed_key()),
        OWN,
        sealed.into_store(),
    );
    assert_eq!(snapshot(&reopened), s);
}

#[test]
fn a_read_holder_opens_and_computes_heads_like_a_write_holder() {
    let mut read = read_index();
    let mut writer = index();
    for r in assorted() {
        push(&mut read, &r);
        push(&mut writer, &r);
    }
    assert_eq!(snapshot(&read), snapshot(&writer));
}

#[test]
fn display_order_and_conflict_copies_follow_the_spec() {
    let mut ix = index();
    let t_old = Spec::tombstone(dev(1), 1, "p").mtime(1).record();
    let t_new = Spec::tombstone(dev(2), 1, "p").mtime(9).record();
    push(&mut ix, &t_old);
    push(&mut ix, &t_new);
    // Tombstones only: the later first, the path deleted, no copy.
    let h = ix.heads("p");
    assert_eq!(heads(&ix, "p"), vec![t_new.hash(), t_old.hash()]);
    assert!(h.is_deleted() && h.is_conflict() && h.current().is_none());
    assert_eq!(h.conflict_copies().count(), 0);
    // A directory sits before any file, whatever the times, and a tombstone
    // after both.
    let file = Spec::file(dev(3), 1, "p").mtime(100).record();
    let dir = Spec::dir(dev(4), 1, "p").mtime(0).record();
    push(&mut ix, &file);
    push(&mut ix, &dir);
    let h = ix.heads("p");
    assert_eq!(
        heads(&ix, "p"),
        vec![dir.hash(), file.hash(), t_new.hash(), t_old.hash()]
    );
    assert_eq!(h.current().unwrap().hash(), dir.hash());
    assert!(!h.is_deleted());
    assert_eq!(h.len(), 4);
    let copies: Vec<RecordHash> = h.conflict_copies().map(|v| v.hash()).collect();
    assert_eq!(copies, vec![file.hash()]);
    let versions: Vec<_> = h.versions().collect();
    assert!(versions
        .windows(2)
        .all(|w| display_order(&w[0], &w[1]).is_lt()));
    assert!(versions[3].is_tombstone() && !versions[0].is_tombstone());
    assert_eq!(versions[0].meta().kind, Kind::Directory);
    assert_eq!(versions[0].record().hash(), dir.hash());
    // An empty path.
    let none = ix.heads("nothing");
    assert!(none.is_empty() && !none.is_deleted() && !none.is_conflict());
    assert!(none.current().is_none());
}

#[test]
fn a_draft_names_at_most_sixteen_heads_in_display_order() {
    let mut ix = index();
    let mut all = Vec::new();
    for i in 0..20u8 {
        let r = Spec::file(dev(i + 1), 1, "p").mtime(i64::from(i)).record();
        push(&mut ix, &r);
        all.push(r.hash());
    }
    let expected: Vec<RecordHash> = heads(&ix, "p").into_iter().take(MAX_SUPERSEDES).collect();
    let d = ix
        .draft(Spec::file(OWN, 1, "p").content(0).meta(), vec![], false)
        .unwrap();
    assert_eq!(d.supersedes, expected);
    // A rename onto the same path names each head once.
    let d = ix
        .draft_rename("p", Spec::file(OWN, 1, "p").content(0).meta(), vec![])
        .unwrap();
    assert_eq!(d.supersedes, expected);
    assert!(!d.deleted);
    let o = ix.write(&d, &mut |b: &mut [u8]| b.fill(2)).unwrap();
    assert_eq!(ix.heads("p").len(), 20 - MAX_SUPERSEDES + 1);
    assert!(heads(&ix, "p").contains(&o.hash));
}

#[test]
fn records_waiting_for_a_missing_record_are_released_in_one_cascade() {
    let mut ix = index();
    let root = Spec::file(dev(1), 1, "a").record();
    // A chain whose members name the one before, each by its own writer.
    let mut chain = vec![root.clone()];
    for i in 1..50u8 {
        let prev = chain.last().unwrap().hash();
        chain.push(Spec::file(dev(i + 1), 1, "a").names(&[prev]).record());
    }
    for r in chain.iter().skip(1).rev() {
        let o = push(&mut ix, r);
        assert!(o.waits);
        assert_eq!(o.rows(), vec![Cause::Waiting]);
        assert!(ix.heads("a").is_empty(), "nothing waiting makes a head");
    }
    assert_eq!(ix.waiting().count(), 49);
    let work = ix.work;
    let o = push(&mut ix, &root);
    assert!(!o.waits);
    assert_eq!(o.released.len(), 49);
    assert_eq!(o.changed, vec!["a".to_string()]);
    assert_eq!(heads(&ix, "a"), vec![chain.last().unwrap().hash()]);
    assert_eq!(ix.waiting().count(), 0);
    // One digest step, and one release per waiting record: linear.
    assert_eq!(ix.work - work, 1 + 49);
    assert!(chain.iter().all(|r| !ix.is_waiting(&r.hash())));
}

#[test]
fn the_work_of_each_record_is_bounded_by_what_it_touches() {
    let mut ix = index();
    // Many heads at one path and a long history of one writer: each further
    // record costs one digest step (its activation notifies no waiter),
    // never the path's heads or the writer's history.
    let n = 40u64;
    for seq in 1..=n {
        let work = ix.work;
        push(&mut ix, &Spec::file(dev(1), seq, "p").salt(1).record());
        assert_eq!(ix.work - work, 1, "record {seq}");
    }
    assert_eq!(ix.heads("p").len(), usize::try_from(n).unwrap());
    let head = heads(&ix, "p")[0];
    let work = ix.work;
    push(&mut ix, &Spec::file(dev(2), 1, "p").names(&[head]).record());
    assert_eq!(ix.work - work, 1);
    assert_eq!(ix.heads("p").len(), usize::try_from(n).unwrap());
}

/// Regression test for SEC-B1 on e304e07: versions of one writer at one
/// `seq` that arrive in canonical order, as every reply and push sends them,
/// cost k(k+1)/2 digest steps for k of them, and the same again on every
/// reopen. A record that sorts last now takes one step; one that sorts below
/// another at the cursor recomputes that `seq` alone.
#[test]
fn versions_at_one_seq_in_canonical_order_cost_one_step_each_even_on_reopen() {
    let w = dev(1);
    let k: u64 = 24;
    let mut at_one: Vec<Record> = (0..k)
        .map(|i| Spec::file(w, 1, &format!("p{i}")).record())
        .collect();
    at_one.sort_by_key(Record::hash);
    let mut ix = index();
    for r in &at_one {
        let work = ix.work;
        push(&mut ix, r);
        assert_eq!(ix.work - work, 1);
    }
    assert_eq!(cached_digests(&ix, &w), reference_digests(&ix, &w));
    let reopened = reopen(FolderKey::from(write_key()), OWN, ix.into_store());
    assert_eq!(reopened.work, k, "a reopen is linear");
    assert_eq!(
        cached_digests(&reopened, &w),
        reference_digests(&reopened, &w)
    );
    // At a cursor above 1.
    let mut ix = index();
    push(&mut ix, &Spec::file(w, 1, "a").record());
    let mut at_two: Vec<Record> = (0..3u8)
        .map(|i| Spec::file(w, 2, "b").salt(i).record())
        .collect();
    at_two.sort_by_key(Record::hash);
    push(&mut ix, &at_two[1]);
    let before = ix.digest_at(&w, 1);
    let mut steps = |r: &Record| {
        let work = ix.work;
        push(&mut ix, r);
        ix.work - work
    };
    assert_eq!(steps(&at_two[2]), 1, "last at the cursor: one step");
    assert_eq!(steps(&at_two[0]), 3, "first at the cursor: its seq again");
    assert_eq!(ix.digest_at(&w, 1), before, "below its seq, untouched");
    assert_eq!(cached_digests(&ix, &w), reference_digests(&ix, &w));
}

/// Writes `spec`'s path as this device's next record (renaming `from` to it
/// when given); returns what the draft named, in the order it named them (the
/// signed record holds them sorted), and the record.
fn write_as_own(
    ix: &mut Index<MemoryStore>,
    spec: &Spec,
    from: Option<&str>,
) -> (Vec<RecordHash>, Record) {
    let draft = match from {
        None => ix.draft(spec.meta(), spec.chunks(), spec.deleted),
        Some(old) => ix.draft_rename(old, spec.meta(), spec.chunks()),
    }
    .unwrap();
    let salt = spec.salt;
    let o = ix.write(&draft, &mut |b: &mut [u8]| b.fill(salt)).unwrap();
    (draft.supersedes, ix.record(&o.hash).unwrap().clone())
}

/// A file renamed away on one device and a new file then written at the old
/// name on another (R2 SF2, R1 SF1 and security N5 on e304e07, ruled
/// 2026-10-22; `protocol.md` 4.4): the new record names the version the
/// rename superseded, so a peer that holds that version and the new file,
/// but not yet the rename, shows one head at the old name, in every arrival
/// order.
#[test]
fn a_new_file_at_a_path_renamed_away_names_the_renamed_version() {
    let old = Spec::file(dev(1), 1, "a").record();
    let mut renamer = index();
    push(&mut renamer, &old);
    let (named, rename) = write_as_own(&mut renamer, &Spec::file(OWN, 1, "b").salt(1), Some("a"));
    assert_eq!(named, vec![old.hash()]);
    assert!(renamer.heads("a").is_empty() && renamer.paths().eq(["b"]));
    let mut ix = index_as(dev(5));
    push(&mut ix, &old);
    push(&mut ix, &rename);
    let (named, new) = write_as_own(
        &mut ix,
        &Spec::file(dev(5), 1, "a").content(2).salt(2),
        None,
    );
    assert_eq!(named, vec![old.hash()], "the renamed version");
    assert_eq!(new.supersedes(), &[old.hash()]);
    assert_eq!(heads(&ix, "a"), vec![new.hash()]);
    // Replaced for good: the next write there names the new file alone.
    let spec = Spec::file(dev(5), 2, "a").content(3);
    let next = ix.draft(spec.meta(), spec.chunks(), false).unwrap();
    assert_eq!(next.supersedes, vec![new.hash()]);
    // A rename back onto the old name names the rename and the new file.
    let back = ix.draft_rename("b", spec.meta(), spec.chunks()).unwrap();
    assert_eq!(back.supersedes, vec![rename.hash(), new.hash()]);
    let records = [&old, &rename, &new];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut peer = index_as(dev(0xb0));
        for i in order {
            push(&mut peer, records[i]);
            assert!(peer.heads("a").len() <= 1, "a false conflict in {order:?}");
        }
        assert_eq!(heads(&peer, "a"), vec![new.hash()]);
        assert_eq!(heads(&peer, "b"), vec![rename.hash()]);
        assert_eq!(snapshot(&peer), snapshot(&ix));
    }
}

/// A write names the path's heads before the versions a rename superseded,
/// in display order, up to `MAX_SUPERSEDES`, and what it leaves unnamed it
/// names next time.
#[test]
fn a_write_names_heads_before_renamed_versions_up_to_sixteen() {
    let mut ix = index();
    for i in 0..17u8 {
        let r = Spec::file(dev(i + 1), 1, "p").mtime(i64::from(i)).record();
        push(&mut ix, &r);
    }
    let before = heads(&ix, "p");
    let (named, _) = write_as_own(&mut ix, &Spec::file(OWN, 1, "q").salt(1), Some("p"));
    assert_eq!(named, before[..MAX_SUPERSEDES]);
    assert_eq!(heads(&ix, "p"), vec![before[16]]);
    let (named, first) = write_as_own(&mut ix, &Spec::file(OWN, 2, "p").salt(2), None);
    let mut expected = vec![before[16]];
    expected.extend_from_slice(&before[..MAX_SUPERSEDES - 1]);
    assert_eq!(named, expected);
    let spec = Spec::file(OWN, 3, "p").content(2);
    let second = ix.draft(spec.meta(), spec.chunks(), false).unwrap();
    assert_eq!(second.supersedes, vec![first.hash(), before[15]]);
}

fn request(have: &[WriterCursor], scope: Scope, page_limit: usize) -> ServeRequest {
    ServeRequest {
        request_id: 7,
        scope,
        cursors: have.iter().map(|c| (c.writer, *c)).collect(),
        page_limit,
    }
}

/// Every page of a reply, with the hashes on each and the marks.
fn reply<S>(ix: &Index<S>, req: ServeRequest, size: u32) -> (Vec<Vec<RecordHash>>, Vec<DeviceId>) {
    let mut reply = Reply::new(req);
    let mut pages = Vec::new();
    let mut marks = Vec::new();
    while let Some(p) = reply.next_page(ix, size).unwrap() {
        assert_eq!(p.page.request_id, 7);
        assert_eq!(p.page.folder_id, ix.folder_id().0.to_vec());
        pages.push((
            p.page.more,
            p.page
                .records
                .iter()
                .map(|b| Record::from_bytes(b, &verifier()).unwrap().hash())
                .collect::<Vec<_>>(),
        ));
        marks.extend(p.marks);
    }
    assert!(reply.is_done());
    assert_eq!(reply.next_page(ix, size).unwrap(), None);
    let n = pages.len();
    for (i, (more, _)) in pages.iter().enumerate() {
        assert_eq!(*more, i + 1 < n, "more on every page but the last");
    }
    (pages.into_iter().map(|(_, r)| r).collect(), marks)
}

#[test]
fn serving_follows_cases_a_to_d_from_the_cached_digests() {
    let mut ix = index();
    let w = dev(1);
    let mut hashes = Vec::new();
    for seq in 1..=3 {
        let r = Spec::file(w, seq, "a").salt(1).record();
        push(&mut ix, &r);
        hashes.push(r.hash());
    }
    let at = |s: u64| WriterCursor {
        writer: w,
        seq: s,
        digest: ix.digest_at(&w, s),
    };
    // (a) absent from have: every record.
    let (pages, marks) = reply(&ix, request(&[], Scope::ALL, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![hashes.clone()]);
    assert_eq!(marks, Vec::<DeviceId>::new());
    // (b) matching digest at 1: the records above it.
    let (pages, marks) = reply(&ix, request(&[at(1)], Scope::ALL, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![hashes[1..].to_vec()]);
    assert_eq!(marks, Vec::<DeviceId>::new());
    // (c) a different digest at 2: every record, and the writer marked.
    let other = WriterCursor {
        digest: Some(WriterDigest([9; 32])),
        ..at(2)
    };
    let (pages, marks) = reply(&ix, request(&[other], Scope::ALL, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![hashes.clone()]);
    assert_eq!(marks, vec![w]);
    // (d) a cursor above this side's: nothing, one empty page.
    let ahead = WriterCursor {
        writer: w,
        seq: 9,
        digest: Some(WriterDigest([1; 32])),
    };
    let (pages, _) = reply(&ix, request(&[ahead], Scope::ALL, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![Vec::<RecordHash>::new()]);
    // Equal cursors with equal digests: nothing.
    let (pages, _) = reply(&ix, request(&[at(3)], Scope::ALL, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![Vec::<RecordHash>::new()]);
}

#[test]
fn serving_covers_exactly_the_requests_scope() {
    let mut ix = index();
    let mut by_writer = BTreeMap::new();
    for w in 1..=5u8 {
        let r = Spec::file(dev(w), 1, "a").record();
        push(&mut ix, &r);
        by_writer.insert(dev(w), r.hash());
    }
    let range = Scope::Range {
        after: Some(dev(1)),
        through: Some(dev(3)),
    };
    let (pages, _) = reply(&ix, request(&[], range, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![vec![by_writer[&dev(2)], by_writer[&dev(3)]]]);
    let open_ended = Scope::Range {
        after: Some(dev(4)),
        through: None,
    };
    let (pages, _) = reply(&ix, request(&[], open_ended, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![vec![by_writer[&dev(5)]]]);
    // A listed request: exactly its writers, held or not.
    let listed = Scope::Listed(BTreeSet::from([dev(2), dev(4), dev(9)]));
    let have = [
        WriterCursor::none(dev(2)),
        WriterCursor::none(dev(4)),
        WriterCursor::none(dev(9)),
    ];
    let (pages, _) = reply(&ix, request(&have, listed, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages, vec![vec![by_writer[&dev(2)], by_writer[&dev(4)]]]);
    // A request built by the protocol crate from another index's cursors.
    let other = index();
    let built: IndexRequest = range_request(&ix.folder_id(), None, other.cursors(None), 0).unwrap();
    let mut req = ServeRequest::of(&built);
    req.request_id = 7;
    let (pages, _) = reply(&ix, req, DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages[0].len(), 5);
}

#[test]
fn pages_hold_at_most_the_page_limit_and_fit_the_frame() {
    let mut ix = index();
    let w = dev(1);
    let mut all = Vec::new();
    for seq in 1..=70 {
        let r = Spec::file(w, seq, "a").salt(1).record();
        push(&mut ix, &r);
        all.push(r.hash());
    }
    let (pages, _) = reply(&ix, request(&[], Scope::ALL, 64), DEFAULT_MESSAGE_SIZE);
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), vec![64, 6]);
    assert_eq!(pages.concat(), all);
    // A frame that fits about two records cuts every page there.
    let one =
        licketysync_protocol::exchange::encoded_record_len(ix.record(&all[0]).unwrap().signed());
    let size =
        u32::try_from(licketysync_protocol::exchange::PAGE_FIXED_OVERHEAD + 2 * one + 1).unwrap();
    let (pages, _) = reply(&ix, request(&[], Scope::ALL, 64), size);
    assert!(pages.iter().all(|p| p.len() <= 2 && !p.is_empty()));
    assert_eq!(pages.concat(), all);
    // A frame too small for any record.
    let mut r = Reply::new(request(&[], Scope::ALL, 64));
    assert!(r.next_page(&ix, 10).is_err());
}

#[test]
fn a_reply_resumes_where_it_stopped_while_records_land() {
    let mut ix = index();
    let w = dev(1);
    for seq in 1..=66 {
        push(&mut ix, &Spec::file(w, seq, "a").salt(1).record());
    }
    let mut r = Reply::new(request(&[], Scope::ALL, 64));
    assert!(!r.is_done());
    let first = r.next_page(&ix, DEFAULT_MESSAGE_SIZE).unwrap().unwrap();
    assert!(first.page.more && !r.is_done());
    assert_eq!(first.page.records.len(), 64);
    // A concurrent version lands below the position, a next record above it.
    push(&mut ix, &Spec::file(w, 3, "b").salt(2).record());
    let next = Spec::file(w, 67, "a").salt(1).record();
    push(&mut ix, &next);
    let second = r.next_page(&ix, DEFAULT_MESSAGE_SIZE).unwrap().unwrap();
    assert!(!second.page.more && r.is_done());
    let hashes: Vec<RecordHash> = second
        .page
        .records
        .iter()
        .map(|b| Record::from_bytes(b, &verifier()).unwrap().hash())
        .collect();
    assert_eq!(
        hashes.len(),
        3,
        "seqs 65 to 67, the one below the position left to the push"
    );
    assert_eq!(hashes.last(), Some(&next.hash()));
}

#[test]
fn two_indexes_that_exchange_converge_on_concurrent_versions() {
    // Equal cursors, a concurrent version only one side holds.
    let base: Vec<Record> = (1..=3)
        .map(|s| Spec::file(dev(1), s, "a").salt(1).record())
        .collect();
    let extra = Spec::file(dev(1), 2, "b").salt(2).record();
    let mut a = index_as(dev(0xa1));
    let mut b = index_as(dev(0xb1));
    for r in &base {
        push(&mut a, r);
        push(&mut b, r);
    }
    push(&mut b, &extra);
    converge(&mut a, &mut b);
    assert_eq!(snapshot(&a), snapshot(&b));
    assert!(licketysync_protocol::record::Held::holds(&a, &extra.hash()));
    // A concurrent version behind a lower cursor.
    let mut a = index_as(dev(0xa1));
    let mut b = index_as(dev(0xb1));
    for r in &base {
        push(&mut b, r);
    }
    push(&mut a, &base[0]);
    push(&mut a, &extra);
    converge(&mut a, &mut b);
    assert_eq!(snapshot(&a), snapshot(&b));
    assert_eq!(a.len(), 4);
}

#[test]
fn errors_and_debug_name_their_cause() {
    let texts = [
        AcceptError::Refused(Cause::Forged).to_string(),
        AcceptError::OtherFolder.to_string(),
        AcceptError::Store(StoreError::Full).to_string(),
        WriteError::NotWriteKey.to_string(),
        WriteError::SeqExhausted.to_string(),
        WriteError::NotNext { expected: 3 }.to_string(),
        WriteError::Draft(licketysync_protocol::record::DraftError::Seq(0)).to_string(),
        WriteError::Store(StoreError::Io("x".into())).to_string(),
        OpenError::Store(StoreError::Full).to_string(),
    ];
    for t in &texts {
        assert_ne!(t, "");
    }
    assert!(texts[5].contains('3') && texts[8].contains("full"));
    let ix = index();
    let debug = format!("{ix:?}");
    assert!(debug.starts_with("Index") && debug.contains("records: 0"));
    assert!(!debug.contains("secret"));
}

#[test]
fn the_memory_store_keeps_what_is_appended() {
    let mut s = MemoryStore::new();
    assert!(s.is_empty() && s.load().unwrap().is_empty());
    let r = Spec::file(dev(1), 1, "a").record();
    s.append(&r).unwrap();
    assert!(!s.is_empty());
    assert_eq!(s.len(), 1);
    assert_eq!(s.load().unwrap(), vec![r.signed().clone()]);
    // The same record again is kept once.
    s.append(&r).unwrap();
    assert_eq!(s.len(), 1);
    // A copy under the same hash replaces the envelope kept: a bad one is
    // replaced by the good one appended after it.
    let bad = flipped_signature(&r);
    assert_eq!(bad.hash(), r.hash());
    s.append(&bad).unwrap();
    assert_eq!(s.load().unwrap(), vec![bad.signed().clone()]);
    s.append(&r).unwrap();
    assert_eq!((s.len(), s.load().unwrap()), (1, vec![r.signed().clone()]));
    // A backup is a clone; it does not see what lands later.
    let backup = s.clone();
    s.append(&Spec::file(dev(1), 2, "a").record()).unwrap();
    assert_eq!((s.len(), backup.len()), (2, 1));
}
