// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Opening a folder (`protocol.md` 4.4 "Opening a folder", 4.7 items 1 and 8,
//! TM-9), the store and the transaction overlay (ruling Q2): a reopen gives
//! the same index; a record changed at rest is dropped and reported at every
//! tier, once per open, with one new epoch; the ordered crash between a
//! change's records and its removals is repaired; a store that refuses a
//! change leaves the index exactly as it was; the stored high-water mark is
//! checked; per-peer state past its horizon goes; the result is the same on
//! any number of verifying threads.

use licketysync_keys::Tier;
use licketysync_protocol::limits::{CLOCK_AHEAD_WARNING, MAX_COUNTER, PEER_STATE_HORIZON};

use licketysync_keys::RecordHash;

use super::kit::{cleanup, dev, flipped_body, folder_key, Dev, DAY, T0};
use crate::{Change, Commit, Index, MemoryStore, Place, Store, StoreError, StoredMeta};

/// Everything the index persists or derives from what it persists, as text:
/// the fingerprint, every record's view, the metadata, the bases, the
/// records kept only as bases and the per-peer state. Stale-copy notes are
/// memory only (4.5): a restart forgets them.
pub(crate) fn snapshot(ix: &Index) -> String {
    let mut fp = Vec::new();
    ix.fingerprint(&mut |b| fp.extend_from_slice(b));
    let mut out = hex::encode(fp);
    for r in ix.records() {
        out.push_str(&format!("\n{r:?}"));
    }
    out.push_str(&format!("\n{:?}", ix.s.meta));
    out.push_str(&format!("\n{:?}", ix.s.bases));
    out.push_str(&format!("\n{:?}", ix.s.peers));
    out.push_str(&format!(
        "\n{:?}",
        ix.s.base_only.keys().collect::<Vec<_>>()
    ));
    out
}

/// A writer with a little of everything: versions, a conflict, a
/// tombstone, a rename, a tree delete with its cleanup, bases kept only as
/// bases, a cleanup from a peer, per-peer state.
fn busy() -> Dev {
    let mut d = Dev::writer(0xd0);
    let mut e = Dev::writer(0xe0);
    d.put("a", 1);
    d.put("a", 2);
    let x = e.put("a", 3);
    d.take(&e, &[x]);
    d.put("b", 4);
    d.apply_all();
    d.rename("b", "c");
    d.put("t/1", 5);
    d.put("t/2", 6);
    d.apply_all();
    d.tree_delete("t");
    let v = e.put("e", 7);
    d.take(&e, &[v]);
    d.apply("e");
    let v2 = e.put("e", 8);
    d.take(&e, &[v2]);
    let c = cleanup(
        dev(0xe0),
        T0 + 100,
        &[(None, vec![licketysync_keys::RecordHash([3; 32])])],
    );
    d.accept(&c).unwrap();
    let mut txn = d.ix.begin();
    txn.round_ended(dev(0xe0), true, Some((9, 3)), T0);
    let (ch, pending) = txn.finish();
    d.store.commit(&ch).unwrap();
    pending.commit();
    d
}

#[test]
fn a_reopen_gives_the_same_index() {
    let mut d = busy();
    assert!(!d.ix.s.base_only.is_empty(), "a base kept only as a base");
    let before = snapshot(&d.ix);
    let report = d.reopen();
    assert!(report.is_clean(), "{report:?}");
    assert!(report.changes.is_empty(), "nothing to repair");
    assert_eq!(snapshot(&d.ix), before);
    // At the other tiers too, from the same records.
    for tier in [Tier::Read, Tier::Sealed] {
        let mut x = Dev::new(tier, 0xd1);
        x.take_all(&d);
        let before = snapshot(&x.ix);
        assert!(x.reopen().is_clean());
        assert_eq!(snapshot(&x.ix), before, "{tier:?}");
    }
}

#[test]
fn a_record_changed_at_rest_is_dropped_and_reported_at_every_tier() {
    for tier in [Tier::Write, Tier::Read, Tier::Sealed] {
        let mut d = Dev::new(tier, 0xd0);
        let mut w = Dev::writer(0xe0);
        let v = w.put("a", 1);
        let keep = w.put("b", 2);
        d.take(&w, &[v, keep]);
        let epoch = d.ix.epoch();
        let damaged = flipped_body(w.signed(&v));
        d.store.tamper(&v, damaged.clone());
        let report = d.reopen();
        assert_eq!(report.dropped, vec![damaged.hash()], "{tier:?}");
        assert!(report.epoch_redrawn);
        assert_ne!(d.ix.epoch(), epoch, "one new epoch");
        assert!(!d.holds(&v) && d.holds(&keep));
        // Reported again at the next open, since it stays in the store, and
        // with another new epoch: every open that drops a record draws one.
        let again = d.reopen();
        assert_eq!(again.dropped, vec![damaged.hash()]);
        // A record signed by another folder's key is dropped alike.
        let alien = super::kit::other_key()
            .sign_index_record(w.signed(&keep).body().to_vec())
            .unwrap();
        d.store.tamper(&keep, alien.clone());
        let report = d.reopen();
        assert!(report.dropped.contains(&alien.hash()));
    }
}

#[test]
fn the_crash_between_a_change_and_its_removals_is_repaired() {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("a", 1);
    d.store.mode = Commit::CrashBeforeRemovals;
    {
        let Dev {
            ix,
            store,
            rng,
            clock,
            ..
        } = &mut d;
        let mut txn = ix.begin();
        let w = txn
            .write(
                &[Change::Put(super::kit::file("a", 2, 9))],
                *clock,
                &mut |b| rng.fill(b),
            )
            .unwrap();
        assert_eq!(w.dropped, vec![v1]);
        let (changes, pending) = txn.finish();
        let err = store.commit(&changes);
        assert!(matches!(err, Err(StoreError::Io(_))));
        drop(pending);
        // The handler drops the transaction: memory is as before.
    }
    assert!(d.holds(&v1), "undone in memory");
    let stored = d.store.load().unwrap();
    assert_eq!(
        stored.records.len(),
        2,
        "the new record and the one it replaces"
    );
    let report = d.reopen();
    assert!(report.dropped.is_empty(), "repaired without a report");
    assert!(!d.holds(&v1));
    assert_eq!(report.changes.remove, vec![v1], "the removal staged again");
    assert_eq!(d.ix.len(), 1);
    // Numbering goes on from the greatest stored number.
    let seq = d.ix.records().map(|r| r.seq).max().unwrap();
    let v3 = d.put("b", 3);
    assert_eq!(d.ix.record(&v3).unwrap().seq, seq + 1);
}

#[test]
fn a_refused_commit_leaves_the_index_as_it_was() {
    let mut d = busy();
    let before = snapshot(&d.ix);
    d.store.mode = Commit::Refuse;
    let mut e = Dev::writer(0xe0);
    let r = e.put("z", 9);
    for _ in 0..2 {
        let Dev {
            ix,
            store,
            rng,
            clock,
            memory,
            notes,
            ..
        } = &mut d;
        let mut txn = ix.begin();
        let w = txn.write(
            &[Change::Put(super::kit::file("a", 5, 7))],
            *clock,
            &mut |b| rng.fill(b),
        );
        assert!(w.is_ok());
        let record = licketysync_protocol::record::Record::parse(
            e.signed(&r).clone(),
            folder_key(Tier::Write).verifier(),
        )
        .unwrap();
        let mut fill = |b: &mut [u8]| b.fill(1);
        let mut arrival = crate::Arrival {
            peer: dev(0xe0),
            memory,
            notes,
            clock_us: *clock,
            rng: &mut fill,
        };
        txn.accept(record, &mut arrival).unwrap();
        txn.set_base("a", Place::Path, None).unwrap();
        txn.round_ended(dev(0x77), true, Some((1, 1)), T0);
        let (changes, pending) = txn.finish();
        assert_eq!(store.commit(&changes), Err(StoreError::Full));
        pending.abort();
    }
    assert_eq!(snapshot(&d.ix), before, "exactly as before");
    d.store.mode = Commit::Atomic;
    assert!(d.reopen().is_clean());
    assert_eq!(snapshot(&d.ix), before);
    assert_ne!(StoreError::Io("x".into()).to_string(), "");
    assert_ne!(StoreError::Full.to_string(), "");
}

#[test]
fn the_stored_high_water_mark_is_checked() {
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    let greatest = d.ix.folder_time();
    // Above the greatest counter held and the clock floor by more than
    // CLOCK_AHEAD_WARNING: corrupt, replaced.
    for hw in [greatest.max(T0) + CLOCK_AHEAD_WARNING + 1, MAX_COUNTER] {
        let meta = d.store.meta().unwrap();
        d.store.set_meta(StoredMeta { hw, ..meta });
        let report = d.reopen();
        assert!(report.hw_corrupt, "{hw}");
        assert_eq!(d.ix.hw(), greatest.max(T0));
        assert_eq!(report.changes.meta.map(|m| m.hw), Some(greatest.max(T0)));
    }
    // Within the warning: kept (a write's mark, or a clock read just ahead).
    let meta = d.store.meta().unwrap();
    let within = greatest.max(T0) + CLOCK_AHEAD_WARNING;
    d.store.set_meta(StoredMeta { hw: within, ..meta });
    let report = d.reopen();
    assert!(!report.hw_corrupt);
    assert_eq!(d.ix.hw(), within);
    // A sealed holder keeps none.
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &d.all().into_iter().collect::<Vec<_>>());
    assert_eq!(s.ix.hw(), 0);
    assert!(s.reopen().is_clean());
}

#[test]
fn a_lost_next_sequence_number_and_epoch_are_rebuilt() {
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    d.put("b", 2);
    let meta = d.store.meta().unwrap();
    d.store.set_meta(StoredMeta {
        next_seq: 1,
        ..meta
    });
    d.reopen();
    assert_eq!(d.ix.local_seq(), 2, "from the greatest stored number");
    // A store with no metadata at all: a first epoch drawn, numbering on.
    let stored = {
        let mut s = d.store.load().unwrap();
        s.meta = None;
        s
    };
    let mut rng = super::kit::Rng(5);
    let (ix, report) = Index::open(folder_key(Tier::Write), d.id(), stored, d.clock, &mut |b| {
        rng.fill(b);
    });
    assert_ne!(ix.epoch(), 0);
    assert!(!report.epoch_redrawn, "a first epoch, not a redraw");
    assert_eq!(ix.local_seq(), 2);
}

#[test]
fn per_peer_state_past_its_horizon_goes_at_open() {
    let mut d = Dev::writer(0xd0);
    let mut txn = d.ix.begin();
    txn.round_ended(dev(1), true, Some((1, 2)), T0);
    txn.round_ended(dev(2), true, Some((1, 2)), T0 + 50 * DAY);
    let (ch, pending) = txn.finish();
    d.store.commit(&ch).unwrap();
    pending.commit();
    d.clock = T0 + PEER_STATE_HORIZON + 1;
    let report = d.reopen();
    assert!(d.ix.peer(&dev(1)).is_none());
    assert!(d.ix.peer(&dev(2)).is_some());
    assert_eq!(report.changes.peers, vec![(dev(1), None)]);
}

#[test]
fn open_is_the_same_on_any_number_of_threads() {
    let d = busy();
    let mut results = Vec::new();
    for threads in [1, 2, 7] {
        let mut stored = d.store.load().unwrap();
        stored.records.push(stored.records[0].clone());
        let flipped = flipped_body(&stored.records[1].0);
        stored.records[1].0 = flipped;
        let mut rng = super::kit::Rng(1);
        let (ix, report) = Index::open_with_threads(
            folder_key(Tier::Write),
            d.id(),
            stored,
            d.clock,
            &mut |b| rng.fill(b),
            threads,
        );
        results.push((snapshot(&ix), report));
    }
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(results[0].1.dropped.len(), 1);
}

#[test]
fn the_memory_store_counts_and_modes() {
    let mut m = MemoryStore::new();
    assert!(m.is_empty() && m.meta().is_none());
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    m.commit(
        &d.store
            .load()
            .map(|s| crate::ChangeSet {
                put: s.records.clone(),
                meta: s.meta,
                ..crate::ChangeSet::default()
            })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(Commit::default(), Commit::Atomic);
}

/// Opens `d`'s stored state as changed by `change`, at `d`'s clock.
fn open_changed(d: &Dev, change: impl FnOnce(&mut crate::Stored)) -> (Index, crate::OpenReport) {
    let mut stored = d.store.load().unwrap();
    change(&mut stored);
    let mut rng = d.rng.clone();
    Index::open(
        folder_key(d.ix.tier()),
        d.ix.own(),
        stored,
        d.clock,
        &mut |b| rng.fill(b),
    )
}

/// Every record held is in the local-sequence order, once, numbered from 1.
fn numbered_from_one(ix: &Index) {
    let seqs: Vec<u64> = ix.records().map(|r| r.seq).collect();
    assert_eq!(
        seqs.len(),
        ix.len(),
        "every record held is in the local-sequence order"
    );
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert!(ix.local_seq() <= licketysync_protocol::limits::MAX_LOCAL_SEQ);
}

/// Two stored records under one local sequence number (a store changed at
/// rest, or a non-atomic store resumed without a reopen): the open used to
/// hold both and keep one in its local-sequence map, so the other was never
/// served, pushed or fetched. Now every record is numbered afresh under a
/// new epoch, and put again with its number (the coordinator's ruling IS-3).
#[test]
fn a_repeated_stored_local_sequence_number_is_renumbered_is3() {
    let mut d = Dev::writer(0xd0);
    let a = d.put("a", 1);
    let b = d.put("b", 2);
    let c = d.put("c", 3);
    let seq_a = d.ix.record(&a).unwrap().seq;
    let (ix, report) = open_changed(&d, |s| {
        for (r, seq) in &mut s.records {
            if r.hash() == b {
                *seq = seq_a;
            }
        }
    });
    assert!(report.renumbered && report.epoch_redrawn && !report.is_clean());
    assert_ne!(ix.epoch(), d.ix.epoch());
    numbered_from_one(&ix);
    assert_eq!(ix.local_seq(), 3);
    let put: Vec<(RecordHash, u64)> = report
        .changes
        .put
        .iter()
        .map(|(r, s)| (r.hash(), *s))
        .collect();
    assert_eq!(put.len(), 3, "every record put again with its new number");
    assert!(put.iter().all(|(h, _)| [a, b, c].contains(h)));
    // Stored, it opens clean.
    d.ix = ix;
    d.store.commit(&report.changes).unwrap();
    assert!(d.reopen().is_clean());
}

/// Two stored copies of one record, at its number or at another (a store
/// not keyed by hash that kept a row twice): one record at the first of
/// its numbers, never a repeated number, so nothing is renumbered and the
/// epoch stays.
#[test]
fn a_stored_copy_of_a_record_is_not_a_repeated_number() {
    for other in [false, true] {
        let mut d = Dev::writer(0xd0);
        let a = d.put("a", 1);
        let b = d.put("b", 2);
        let seq_a = d.ix.record(&a).unwrap().seq;
        let seq_b = d.ix.record(&b).unwrap().seq;
        let (ix, report) = open_changed(&d, |s| {
            let copy = s
                .records
                .iter()
                .find(|(r, _)| r.hash() == a)
                .unwrap()
                .clone();
            let at = if other { seq_b } else { copy.1 };
            s.records.push((copy.0, at));
        });
        assert!(
            !report.renumbered && !report.epoch_redrawn,
            "other number: {other}"
        );
        assert!(report.dropped.is_empty());
        assert_eq!(ix.epoch(), d.ix.epoch());
        assert_eq!(ix.len(), 2);
        assert_eq!(ix.record(&a).unwrap().seq, seq_a);
        assert_eq!(ix.record(&b).unwrap().seq, seq_b);
    }
}

/// A stored local sequence number of 0 or above `MAX_LOCAL_SEQ`: renumbered
/// alike (IS-3).
#[test]
fn a_stored_local_sequence_number_out_of_range_is_renumbered_is3() {
    for bad in [0, licketysync_protocol::limits::MAX_LOCAL_SEQ + 1, u64::MAX] {
        let mut d = Dev::writer(0xd0);
        let a = d.put("a", 1);
        d.put("b", 2);
        let (ix, report) = open_changed(&d, |s| {
            for (r, seq) in &mut s.records {
                if r.hash() == a {
                    *seq = bad;
                }
            }
        });
        assert!(report.renumbered, "{bad}");
        numbered_from_one(&ix);
    }
}

/// A stored next local sequence number past `MAX_LOCAL_SEQ + 1` used to be
/// taken as it was, so that root replies carried a `through` every peer
/// refuses: renumbered under a new epoch now (IS-3).
#[test]
fn a_stored_next_local_sequence_past_the_bound_is_renumbered_is3() {
    for next in [licketysync_protocol::limits::MAX_LOCAL_SEQ + 2, u64::MAX] {
        let mut d = Dev::writer(0xd0);
        d.put("a", 1);
        let meta = d.store.meta().unwrap();
        d.store.set_meta(StoredMeta {
            next_seq: next,
            ..meta
        });
        let report = d.reopen();
        assert!(report.renumbered && report.epoch_redrawn, "{next}");
        numbered_from_one(&d.ix);
        assert_eq!(d.ix.local_seq(), 1);
    }
    // MAX_LOCAL_SEQ + 1 is a next number the spec allows: kept.
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    let meta = d.store.meta().unwrap();
    let limit = licketysync_protocol::limits::MAX_LOCAL_SEQ + 1;
    d.store.set_meta(StoredMeta {
        next_seq: limit,
        ..meta
    });
    assert!(!d.reopen().renumbered);
    assert_eq!(
        d.ix.local_seq(),
        licketysync_protocol::limits::MAX_LOCAL_SEQ
    );
}

/// Dropping a record removes only its own entry of the local-sequence map,
/// so that a number two records share cannot lose the other's (IS-3).
#[test]
fn dropping_a_record_removes_only_its_own_local_sequence_entry_is3() {
    let mut d = Dev::writer(0xd0);
    let a = d.put("a", 1);
    let b = d.put("b", 2);
    let held_b = d.ix.s.held.get(&b).cloned().unwrap();
    let seq_a = d.ix.record(&a).unwrap().seq;
    // Two records under one number, as an open before the fix held them.
    d.ix.s.unhold(&b, None);
    d.ix.s.hold(
        crate::state::Held {
            seq: seq_a,
            ..held_b
        },
        None,
    );
    assert_eq!(d.ix.s.by_seq.get(&seq_a), Some(&b));
    d.ix.s.unhold(&a, None);
    assert_eq!(d.ix.s.by_seq.get(&seq_a), Some(&b), "b's entry stays");
}

/// A stored base slot whose record lies at another file ID is dropped and
/// reported: `Txn::set_base` refuses such a base, and the next write would
/// join an unrelated record's vector (the index security review's NIT 5).
#[test]
fn a_stored_base_at_another_path_is_dropped_and_reported() {
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    let b = d.put("b", 2);
    let tag_a = super::kit::tag("a");
    let (ix, report) = open_changed(&d, |s| {
        for (slot, h) in &mut s.bases {
            if slot.0 == tag_a {
                *h = b;
            }
        }
    });
    assert_eq!(report.misplaced_bases, vec![(tag_a, Place::Path)]);
    assert!(!report.is_clean());
    assert!(ix.bases("a").is_empty(), "no base at a");
    assert!(
        report.changes.bases.contains(&((tag_a, Place::Path), None)),
        "cleared in the store"
    );
}

/// Stored per-peer state is clamped to the clock, so that a time ahead of it
/// neither keeps an entry for ever nor keeps its names window from ending,
/// and at most `MAX_PEER_STATES` entries are kept, the longest without a
/// round going first (the index security review's NIT 4).
#[test]
fn stored_per_peer_state_is_clamped_to_the_clock_and_capped() {
    use licketysync_protocol::limits::MAX_PEER_STATES;
    let d = Dev::writer(0xd0);
    let ahead = crate::PeerState {
        epoch: 1,
        cursor: 2,
        round_ended_us: u64::MAX,
        caught_up: true,
        names_window_us: u64::MAX,
        names: 7,
    };
    let (ix, report) = open_changed(&d, |s| {
        s.peers.push((dev(1), ahead));
        for i in 0..MAX_PEER_STATES {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
            id[31] = 0x99;
            s.peers.push((
                licketysync_keys::DeviceId(id),
                crate::PeerState {
                    round_ended_us: T0 - DAY + i as u64,
                    ..crate::PeerState::default()
                },
            ));
        }
    });
    let p = ix.peer(&dev(1)).unwrap();
    assert_eq!(
        (p.round_ended_us, p.names_window_us),
        (d.clock, d.clock),
        "clamped"
    );
    assert_eq!(ix.s.peers.len(), MAX_PEER_STATES, "capped");
    let mut first = [0u8; 32];
    first[31] = 0x99;
    assert!(
        ix.peer(&licketysync_keys::DeviceId(first)).is_none(),
        "the longest without a round went"
    );
    assert!(
        report.changes.peers.contains(&(dev(1), Some(*p))),
        "the clamped state stored"
    );
    assert!(report
        .changes
        .peers
        .contains(&(licketysync_keys::DeviceId(first), None)));
}

/// After the ordered crash between a write's records and its removals, the
/// next open keeps the write as its path's base: a store that cannot stage
/// atomically writes the base slots with the metadata, after the records
/// (the spec's twelfth fixup; the R1 review's NIT 8, `probe_crash_keeps_base`).
#[test]
fn the_crash_after_the_records_keeps_the_write_as_its_paths_base() {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("a", 1);
    d.store.mode = Commit::CrashBeforeRemovals;
    let v2 = {
        let Dev {
            ix,
            store,
            rng,
            clock,
            ..
        } = &mut d;
        let mut txn = ix.begin();
        let w = txn
            .write(
                &[Change::Put(super::kit::file("a", 2, 9))],
                *clock,
                &mut |b| rng.fill(b),
            )
            .unwrap();
        let (changes, pending) = txn.finish();
        assert!(store.commit(&changes).is_err());
        drop(pending);
        w.records[0].0
    };
    d.reopen();
    assert!(d.holds(&v2) && !d.holds(&v1));
    assert_eq!(
        d.ix.bases("a"),
        vec![(Place::Path, v2)],
        "the write is the base of its path"
    );
}

/// The open reports the count of entries a phase 1 store could no longer
/// decode (4.4 "Opening a folder"; 4.7 item 8), and an open that found any
/// is not clean.
#[test]
fn the_open_reports_the_entries_the_store_could_not_decode() {
    let mut d = Dev::writer(0xd0);
    let a = d.put("a", 1);
    let (ix, report) = open_changed(&d, |s| s.undecodable = 3);
    assert_eq!(report.undecodable, 3);
    assert!(!report.is_clean(), "{report:?}");
    assert!(ix.record(&a).is_some(), "what did decode is held");
    let (_, report) = open_changed(&d, |_| {});
    assert_eq!(report.undecodable, 0);
    assert!(report.is_clean());
}

/// F-2: an open that finds entries the store could not decode draws a new
/// index epoch, once, and stages it (4.4 "Opening a folder": the store drops
/// such bytes as the open drops a record that fails its checks; 4.7 item 8:
/// an open that dropped anything draws a new epoch, once; 4.5; TM-9), so that
/// every peer reconciles with this device and sends again what the store
/// lost. Beside a record changed at rest, still one epoch: the first the
/// open's randomness gives.
#[test]
fn an_open_with_entries_the_store_could_not_decode_draws_a_new_epoch_once_f2() {
    let mut d = Dev::writer(0xd0);
    let a = d.put("a", 1);
    let b = d.put("b", 2);
    let first = {
        let mut rng = d.rng.clone();
        crate::index::draw_epoch(&mut |x| rng.fill(x))
    };
    assert_ne!(first, d.ix.epoch());
    let (ix, report) = open_changed(&d, |s| s.undecodable = 1);
    assert!(report.epoch_redrawn, "{report:?}");
    assert!(
        report.dropped.is_empty() && !report.renumbered,
        "{report:?}"
    );
    assert_eq!(ix.epoch(), first, "one new epoch");
    assert_eq!(
        report.changes.meta.map(|m| m.epoch),
        Some(first),
        "the new epoch stored"
    );
    assert!(ix.record(&a).is_some() && ix.record(&b).is_some());
    let (ix, report) = open_changed(&d, |s| {
        s.undecodable = 1;
        for (r, _) in &mut s.records {
            if r.hash() == b {
                *r = flipped_body(r);
            }
        }
    });
    assert!(
        report.epoch_redrawn && report.dropped.len() == 1,
        "{report:?}"
    );
    assert_eq!(ix.epoch(), first, "drawn once");
}

/// `MAX_LOCAL_SEQ` itself is a local sequence number (4.5: "at most
/// `MAX_LOCAL_SEQ`"): a record stored under it, the next number
/// `MAX_LOCAL_SEQ + 1`, is held under it, nothing numbered afresh, the epoch
/// kept (IS-3's bound, from below).
#[test]
fn a_stored_local_sequence_number_of_max_local_seq_is_kept_is3() {
    use licketysync_protocol::limits::MAX_LOCAL_SEQ;
    let mut d = Dev::writer(0xd0);
    let a = d.put("a", 1);
    let b = d.put("b", 2);
    let (ix, report) = open_changed(&d, |s| {
        for (r, seq) in &mut s.records {
            if r.hash() == b {
                *seq = MAX_LOCAL_SEQ;
            }
        }
        s.meta = s.meta.map(|m| StoredMeta {
            next_seq: MAX_LOCAL_SEQ + 1,
            ..m
        });
    });
    assert!(!report.renumbered && !report.epoch_redrawn, "{report:?}");
    assert!(report.is_clean());
    assert_eq!(ix.record(&b).unwrap().seq, MAX_LOCAL_SEQ);
    assert_eq!(ix.record(&a).unwrap().seq, d.ix.record(&a).unwrap().seq);
    assert_eq!(ix.local_seq(), MAX_LOCAL_SEQ);
    assert_eq!(ix.epoch(), d.ix.epoch());
}

/// Per-peer state goes after `PEER_STATE_HORIZON` without a round that
/// ended (4.5), not at it: an entry exactly that old stays at the open, one
/// a microsecond older goes.
#[test]
fn per_peer_state_at_its_horizon_stays_at_open_and_goes_past_it() {
    let mut d = Dev::writer(0xd0);
    let mut txn = d.ix.begin();
    txn.round_ended(dev(1), true, Some((1, 2)), T0);
    let (ch, pending) = txn.finish();
    d.store.commit(&ch).unwrap();
    pending.commit();
    d.clock = T0 + PEER_STATE_HORIZON;
    let report = d.reopen();
    assert!(d.ix.peer(&dev(1)).is_some(), "at the horizon: kept");
    assert!(report.changes.peers.is_empty(), "nothing to store");
    d.clock += 1;
    let report = d.reopen();
    assert!(d.ix.peer(&dev(1)).is_none(), "past it: gone");
    assert_eq!(report.changes.peers, vec![(dev(1), None)]);
}

/// A base slot whose record the store no longer has, neither held nor kept
/// only as a base (a store that lost a record it held), is cleared, and the
/// open draws a new epoch, since the local sequence lost that record (4.5,
/// "Local sequence and epoch": drawn again whenever it may have lost
/// records), so that every peer reconciles once and sends it again.
#[test]
fn a_base_whose_record_the_store_lost_is_cleared_under_a_new_epoch() {
    let mut d = Dev::writer(0xd0);
    let a = d.put("a", 1);
    let b = d.put("b", 2);
    let (ix, report) = open_changed(&d, |s| s.records.retain(|(r, _)| r.hash() != a));
    assert!(report.dropped.is_empty(), "nothing failed its check");
    assert!(!report.renumbered);
    assert!(report.epoch_redrawn, "{report:?}");
    assert_ne!(ix.epoch(), d.ix.epoch());
    assert!(ix.record(&a).is_none() && ix.record(&b).is_some());
    assert!(ix.bases("a").is_empty(), "no base at a");
    assert!(
        report
            .changes
            .bases
            .contains(&((super::kit::tag("a"), Place::Path), None)),
        "cleared in the store"
    );
    assert_eq!(ix.bases("b"), vec![(Place::Path, b)], "b's base kept");
}

/// The open verifies the stored records' signatures across the threads it
/// is given (4.4 "Opening a folder": "verified across the processor's
/// cores, and the result does not depend on how many"; 4.7 item 8; TM-9):
/// eight records, one of them changed at rest, on four threads take worker
/// threads beside the calling one, at most three, and open exactly as on one
/// thread, which takes none.
#[test]
fn the_open_verifies_signatures_across_the_threads_it_is_given() {
    let mut d = Dev::writer(0xd0);
    for i in 0..8u8 {
        d.put(&format!("f{i}"), i);
    }
    let mut stored = d.store.load().unwrap();
    assert_eq!(stored.records.len(), 8);
    stored.records[3].0 = flipped_body(&stored.records[3].0);
    let open = |threads: usize| {
        crate::verify::SPAWNED.with(|n| n.set(0));
        let mut rng = super::kit::Rng(1);
        let (ix, report) = Index::open_with_threads(
            folder_key(Tier::Write),
            d.id(),
            stored.clone(),
            d.clock,
            &mut |b| rng.fill(b),
            threads,
        );
        let spawned = crate::verify::SPAWNED.with(core::cell::Cell::get);
        (snapshot(&ix), report, spawned)
    };
    let (one, one_report, none) = open(1);
    assert_eq!(none, 0, "one thread: the calling thread alone");
    assert_eq!(one_report.dropped.len(), 1, "the record changed at rest");
    let (four, four_report, spawned) = open(4);
    assert!(
        (1..=3).contains(&spawned),
        "{spawned} worker threads beside the calling one"
    );
    assert_eq!((four, four_report), (one, one_report), "the same open");
}
