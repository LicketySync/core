// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Expiry by the watermark (`protocol.md` 4.4, "Expiry by the watermark";
//! section 8 items 7 and 13, the index's part): the candidate ("Wait, never
//! early"), the conditions on signing and the interval, the arrivals kept
//! with the records and read back at open, the greatest watermark held and
//! what a rise or a fall of it owes, every cleanup carrying it, case (c)
//! judged against it, and property (p): the index by counter finds what a
//! scan of every record finds.

use core::time::Duration;
use std::collections::BTreeSet;

use licketysync_keys::RecordHash;
use licketysync_protocol::connection::Judgement;
use licketysync_protocol::limits::{TOMBSTONE_HORIZON, WATERMARK_INTERVAL};
use licketysync_protocol::record::Applied;
use proptest::prelude::*;

use super::kit::{
    DAY, Dev, SEC, T0, chunk, cleanup, dev, forge, round, sealed_file, watermarked, write_key,
};
use crate::Store as _;

/// A tombstone by `device` at `counter`, forged.
fn tombstone_at(path: &str, device: u8, counter: u64) -> licketysync_keys::records::SignedRecord {
    let mut m = sealed_file(path, dev(device), counter);
    m.deleted = true;
    m.size = 0;
    m.plain_hashes.clear();
    forge(path, &[], &m, &[])
}

/// A write holder holding, by its own clock, a tombstone that arrived at
/// `T0` and one that arrived `young_by` later: the check at `T0 +
/// TOMBSTONE_HORIZON` then holds the first old and the second young.
fn two_arrivals(first: u64, second: u64, young_by: u64) -> (Dev, RecordHash, RecordHash) {
    let mut w = Dev::writer(0xa0);
    let a = tombstone_at("a", 0xd1, first);
    let b = tombstone_at("b", 0xd2, second);
    w.accept(&a).unwrap();
    w.clock = T0 + young_by;
    w.accept(&b).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    (w, a.hash(), b.hash())
}

/// "Wait, never early" (4.4, "When a write holder signs one"): the candidate
/// is the greatest counter of an old record below every young one. A young
/// record dated below an old one holds the old one back; dated above, it
/// does not.
#[test]
fn the_candidate_waits_for_every_young_record_dated_below_it() {
    // The old one first in counters: the candidate passes it, and stops at
    // the young one.
    let (mut w, a, b) = two_arrivals(T0 + 10, T0 + 20, 1);
    let (signed, moved) = w.check(None);
    assert_eq!(signed.watermark, Some(T0 + 10));
    assert!(moved, "it expired a record");
    assert!(!w.holds(&a) && w.holds(&b));
    // The young one dated below the old one: no candidate.
    let (mut w, a, b) = two_arrivals(T0 + 20, T0 + 10, 1);
    let (signed, moved) = w.check(None);
    assert_eq!(signed.watermark, None, "a late arrival holds it back");
    assert!(signed.records.is_empty() && !moved);
    assert!(w.holds(&a) && w.holds(&b));
    // Once the late one is old too, both go.
    w.clock += 1;
    assert_eq!(w.check(None).0.watermark, Some(T0 + 20));
    assert!(!w.holds(&a) && !w.holds(&b));
}

/// An old record that shares the stopping young record's counter is not
/// passed: the candidate lies below the stopping record's counter.
#[test]
fn an_old_record_at_the_young_ones_counter_is_not_passed() {
    let (mut w, a, b) = two_arrivals(T0 + 10, T0 + 10, 1);
    // Ordered by counter, then record hash: whichever is first, the young
    // one shares its counter.
    let (signed, _) = w.check(None);
    assert_eq!(signed.watermark, None);
    assert!(w.holds(&a) && w.holds(&b));
}

/// A record is old when its arrival is at most the reading and the reading
/// less its arrival is at least `TOMBSTONE_HORIZON`, with no overflow: an
/// arrival later than the reading, whatever its value, is young.
#[test]
fn old_and_young_are_judged_without_overflow() {
    let mut w = Dev::writer(0xa0);
    let t = tombstone_at("t", 0xd1, T0 + 5);
    w.accept(&t).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON - 1;
    assert_eq!(w.check(None).0.watermark, None, "a microsecond short");
    w.clock = T0 + TOMBSTONE_HORIZON;
    assert_eq!(
        w.check(None).0.watermark,
        Some(T0 + 5),
        "exactly the horizon"
    );
    // An arrival later than the clock: young, however far.
    for arrival in [T0 + 1, u64::MAX] {
        let mut w = Dev::writer(0xa0);
        w.clock = arrival;
        w.accept(&t).unwrap();
        w.clock = T0;
        assert_eq!(w.check(None).0.watermark, None, "{arrival}");
        w.clock = 0;
        assert_eq!(w.check(None).0.watermark, None, "a clock before 1970");
    }
}

/// Condition (2): a candidate that passes only cleanups without a `because`
/// (case (d), and case (c) with an empty `because`) signs nothing; one that
/// passes a tombstone, a tree delete or a cleanup with a `because` signs.
#[test]
fn a_check_signs_only_past_a_deletion_or_a_cleanup_with_a_because() {
    let watermark_only = watermarked(dev(0xd1), T0 + 10, 5, &[]);
    let case_c = cleanup(dev(0xd1), T0 + 11, &[(None, vec![RecordHash([7; 32])])]);
    let case_b = cleanup(
        dev(0xd1),
        T0 + 12,
        &[(Some(RecordHash([8; 32])), vec![RecordHash([9; 32])])],
    );
    let mut w = Dev::writer(0xa0);
    w.accept(&watermark_only).unwrap();
    w.accept(&case_c).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    let (signed, moved) = w.check(None);
    assert_eq!(signed.watermark, None, "no echo");
    assert!(!moved && w.holds(&case_c.hash()));
    // With a case-(b) cleanup among them: signs, and forgets all three.
    w.clock = T0;
    w.accept(&case_b).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    let (signed, moved) = w.check(None);
    assert_eq!(signed.watermark, Some(T0 + 12));
    assert!(moved);
    for h in [watermark_only.hash(), case_c.hash(), case_b.hash()] {
        assert!(!w.holds(&h));
    }
    // A tombstone alone signs too.
    let mut w = Dev::writer(0xa0);
    w.accept(&tombstone_at("t", 0xd1, T0 + 3)).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    assert_eq!(w.check(None).0.watermark, Some(T0 + 3));
}

/// Condition (1): a candidate at or below the greatest watermark held signs
/// nothing: another write holder's watermark spares this one its own.
#[test]
fn a_candidate_at_or_below_the_greatest_watermark_signs_nothing() {
    let mut w = Dev::writer(0xa0);
    let t = tombstone_at("t", 0xd1, T0 + 3);
    let u = tombstone_at("u", 0xd1, T0 + 4);
    w.accept(&t).unwrap();
    w.accept(&u).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    // The candidate is u's counter; a watermark there already: nothing.
    w.accept(&watermarked(dev(0xd2), T0 + 20, T0 + 4, &[]))
        .unwrap();
    assert!(!w.holds(&t.hash()) && !w.holds(&u.hash()));
    assert_eq!(w.check(None).0.watermark, None);
}

/// Condition (3): at most one watermark per `WATERMARK_INTERVAL`, counted
/// within one opening by the monotonic time since the last signing, across
/// openings by the wall-clock reading kept with the folder's metadata, a
/// reading earlier than that one counting as passed.
#[test]
fn a_write_holder_signs_at_most_once_per_interval() {
    let mut w = Dev::writer(0xa0);
    w.accept(&tombstone_at("a", 0xd1, T0 + 1)).unwrap();
    w.clock = T0 + 2 * SEC;
    w.accept(&tombstone_at("b", 0xd1, T0 + 2)).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    assert_eq!(w.check(None).0.watermark, Some(T0 + 1));
    assert_eq!(w.ix.last_signed_us(), Some(w.clock));
    w.clock += 2 * SEC;
    let just_short = WATERMARK_INTERVAL
        .checked_sub(Duration::from_micros(1))
        .unwrap();
    // Within this opening, by the monotonic time alone, whatever the wall
    // clock reads.
    w.clock += 400 * DAY;
    assert_eq!(w.check(Some(just_short)).0.watermark, None);
    w.clock -= 400 * DAY;
    assert_eq!(w.check(Some(WATERMARK_INTERVAL)).0.watermark, Some(T0 + 2));
    // Across openings, by the stored reading.
    let mut w = Dev::writer(0xa0);
    w.accept(&tombstone_at("a", 0xd1, T0 + 1)).unwrap();
    w.clock = T0 + 2 * SEC;
    w.accept(&tombstone_at("b", 0xd1, T0 + 2)).unwrap();
    w.clock = T0 + TOMBSTONE_HORIZON;
    let signed_at = w.clock;
    assert_eq!(w.check(None).0.watermark, Some(T0 + 1));
    w.clock += 2 * SEC;
    assert!(w.reopen().is_clean());
    assert_eq!(
        w.ix.last_signed_us(),
        Some(signed_at),
        "kept with the metadata"
    );
    w.clock = signed_at;
    assert_eq!(w.check(None).0.watermark, None, "the same reading");
    w.clock = signed_at + DAY - 1;
    assert_eq!(w.check(None).0.watermark, None, "a day less a microsecond");
    w.clock = signed_at + DAY;
    assert_eq!(w.check(None).0.watermark, Some(T0 + 2), "a day later");
    // A reading earlier than the stored one counts as passed; the stored
    // reading itself does not.
    let mut x = Dev::writer(0xa1);
    x.accept(&tombstone_at("a", 0xd1, T0 + 1)).unwrap();
    x.clock = T0 + TOMBSTONE_HORIZON;
    let meta = x.ix.s.meta;
    x.ix.s.meta = crate::StoredMeta {
        last_signed_us: Some(x.clock),
        ..meta
    };
    assert_eq!(x.check(None).0.watermark, None, "the stored reading itself");
    x.ix.s.meta = crate::StoredMeta {
        last_signed_us: Some(T0 + TOMBSTONE_HORIZON + 50 * DAY),
        ..meta
    };
    assert_eq!(
        x.check(None).0.watermark,
        Some(T0 + 1),
        "a stored reading ahead of the clock counts as passed"
    );
}

/// Only write holders sign, and keep arrivals.
#[test]
fn read_and_sealed_holders_sign_nothing_and_keep_no_arrival() {
    let t = tombstone_at("t", 0xd1, T0 + 3);
    for mut x in [Dev::reader(0xa1), Dev::sealed(0xa2)] {
        x.accept(&t).unwrap();
        assert_eq!(x.store.arrival(&t.hash()), None);
        x.clock = T0 + 2 * TOMBSTONE_HORIZON;
        let (signed, moved) = x.check(None);
        assert!(signed.records.is_empty() && !moved);
    }
    let mut w = Dev::writer(0xa0);
    w.clock = T0 + 7;
    w.accept(&t).unwrap();
    assert_eq!(w.store.arrival(&t.hash()), Some(T0 + 7), "kept, persisted");
    // A version keeps none.
    let v = forge("v", &[chunk(1)], &sealed_file("v", dev(0xd1), T0 + 4), &[]);
    w.accept(&v).unwrap();
    assert_eq!(w.store.arrival(&v.hash()), None);
}

/// Arrivals at open (4.4, "Arrivals when a folder opens"): read as stored
/// and checked against nothing; one the store lacks takes the open's
/// reading, kept from then on; one later than the clock is kept as it is.
/// A record dropped and held again arrives again.
#[test]
fn arrivals_are_read_back_at_open_and_a_missing_one_takes_the_opens_reading() {
    let mut w = Dev::writer(0xa0);
    let t = tombstone_at("t", 0xd1, T0 + 3);
    let u = tombstone_at("u", 0xd1, T0 + 4);
    w.clock = T0 + 10 * DAY;
    w.accept(&t).unwrap();
    w.accept(&u).unwrap();
    // Lost at rest; and one later than the clock the open reads.
    w.store.set_arrival(t.hash(), None);
    w.store.set_arrival(u.hash(), Some(T0 + 900 * DAY));
    w.clock = T0 + 20 * DAY;
    let report = w.reopen();
    assert!(report.changes.arrivals.contains(&(t.hash(), T0 + 20 * DAY)));
    assert_eq!(
        w.store.arrival(&t.hash()),
        Some(T0 + 20 * DAY),
        "stored now"
    );
    assert_eq!(
        w.store.arrival(&u.hash()),
        Some(T0 + 900 * DAY),
        "as stored"
    );
    // t is old a horizon after the open, u only once its stored arrival is.
    w.clock = T0 + 20 * DAY + TOMBSTONE_HORIZON;
    assert_eq!(w.check(None).0.watermark, Some(T0 + 3));
    assert!(w.holds(&u.hash()));
    // A record dropped and held again arrives again: u expires, and is
    // offered again after the watermark that expired it was named away.
    let mut x = Dev::writer(0xa1);
    x.clock = T0;
    x.accept(&u).unwrap();
    let w1 = watermarked(dev(0xd2), T0 + 50, T0 + 4, &[]);
    x.accept(&w1).unwrap();
    assert!(!x.holds(&u.hash()));
    let away = cleanup(dev(0xd3), T0 + 60, &[(None, vec![w1.hash()])]);
    x.clock = T0 + 30 * DAY;
    x.accept(&away).unwrap();
    x.accept(&u).unwrap();
    assert_eq!(x.store.arrival(&u.hash()), Some(T0 + 30 * DAY));
}

/// The greatest watermark held is the greatest `forget_before` of the
/// applied cleanups held; it rises and expires in the commit that holds
/// the cleanup, owing rounds; it falls when a dishonest write holder's
/// cleanup names the cleanup that carries it, which owes rounds too; and a
/// rise that expires nothing owes none.
#[test]
fn a_rise_that_expires_a_record_and_a_fall_owe_rounds() {
    use super::kit::Rng;
    let mut x = Dev::reader(0xa1);
    let t = tombstone_at("t", 0xd1, T0 + 3);
    x.accept(&t).unwrap();
    let moved = |x: &mut Dev, r: &licketysync_keys::records::SignedRecord| {
        let record =
            licketysync_protocol::record::Record::parse(r.clone(), write_key().verifier()).unwrap();
        let mut rng = Rng(1);
        let mut fill = |b: &mut [u8]| rng.fill(b);
        let mut notes = licketysync_protocol::connection::NoteBudget::for_tests();
        let mut arrival = crate::Arrival {
            peer: dev(0xee),
            notes: &mut notes,
            clock_us: x.clock,
            rng: &mut fill,
        };
        let mut txn = x.ix.begin();
        txn.accept(record, &mut arrival).unwrap();
        let m = txn.watermark_moved();
        let (changes, pending) = txn.finish();
        x.store.commit(&changes).unwrap();
        pending.commit();
        m
    };
    // A rise below the tombstone: nothing expired, no round owed.
    let low = watermarked(dev(0xd2), T0 + 20, T0 + 2, &[]);
    assert!(!moved(&mut x, &low));
    assert_eq!(x.ix.watermark(), T0 + 2);
    // A rise past it: expired, a round owed.
    let high = watermarked(dev(0xd2), T0 + 21, T0 + 3, &[]);
    assert!(moved(&mut x, &high));
    assert!(!x.holds(&t.hash()));
    // A fall: the cleanup that carries H named away.
    let away = cleanup(dev(0xd3), T0 + 22, &[(None, vec![high.hash()])]);
    assert!(moved(&mut x, &away));
    assert_eq!(x.ix.watermark(), T0 + 2);
    // The deletion is expired no longer: held when offered again.
    assert_eq!(x.judge(&t), Ok(Judgement::Held));
}

/// Every cleanup a write holder writes carries the greatest watermark it
/// holds: a tree delete's, and a round's end.
#[test]
fn every_cleanup_carries_the_greatest_watermark_held() {
    let mut w = Dev::writer(0xa0);
    w.accept(&watermarked(dev(0xd2), T0 + 2, T0 + 1, &[]))
        .unwrap();
    assert_eq!(w.ix.watermark(), T0 + 1);
    w.put("m/f", 1);
    w.apply_all();
    let written = w.tree_delete("m");
    let keys = write_key().record_keys();
    let carried = |w: &Dev, h: &RecordHash| -> Option<u64> {
        let r = licketysync_protocol::record::Record::parse(
            w.signed(h).clone(),
            write_key().verifier(),
        )
        .unwrap();
        match r.open(&keys) {
            Ok(Applied::Cleanup(c)) => Some(c.forget_before),
            _ => None,
        }
    };
    let cleanups: Vec<u64> = written
        .records
        .iter()
        .filter_map(|(h, _)| carried(&w, h))
        .collect();
    assert_eq!(cleanups, vec![T0 + 1], "the tree delete's cleanup");
}

/// Case (c), judged again when the cleanup is written (4.4, "Cleanup"): a
/// forgotten record noted under a watermark is named with `because` empty
/// when its counter is at most the watermark the cleanup carries; noted
/// under a watermark that a dishonest write holder's cleanup has named away
/// since, it is dropped, unnamed.
#[test]
fn a_forgotten_record_above_the_rounds_watermark_is_dropped_unnamed() {
    let t = tombstone_at("t", 0xd1, T0 + 3);
    let high = watermarked(dev(0xd2), T0 + 21, T0 + 3, &[]);
    let mut w = Dev::writer(0xa0);
    w.accept(&high).unwrap();
    let a = w.accept(&t).unwrap();
    assert_eq!(a.judgement, Judgement::Expired);
    assert!(a.noted, "a forgotten record, noted");
    // The round's end names it, under the watermark it carries.
    let mut named = Dev::writer(0xa0);
    named.accept(&high).unwrap();
    named.accept(&t).unwrap();
    let end = named.end_round();
    assert!(end.cleanup);
    // H falls before the round's end: the note is dropped, unnamed.
    let away = cleanup(dev(0xd3), T0 + 22, &[(None, vec![high.hash()])]);
    w.accept(&away).unwrap();
    assert_eq!(w.ix.watermark(), 0);
    let end = w.end_round();
    assert!(!end.cleanup, "nothing named");
    assert!(w.ix.s.notes.is_empty(), "the note dropped");
}

/// The cleanup that carries `H` lost from the store at rest: `H` lower
/// after the open, a deletion its peers forgot held meanwhile when offered,
/// and the same records once the cleanup is back.
#[test]
fn the_cleanup_carrying_h_lost_at_rest_comes_back_from_a_peer() {
    let t = tombstone_at("t", 0xd1, T0 + 3);
    let high = watermarked(dev(0xd2), T0 + 21, T0 + 3, &[]);
    let mut x = Dev::reader(0xa1);
    let mut peer = Dev::reader(0xa2);
    for d in [&mut x, &mut peer] {
        d.accept(&t).unwrap();
        d.accept(&high).unwrap();
    }
    x.store.lose(&high.hash());
    x.reopen();
    assert_eq!(x.ix.watermark(), 0, "lower until it is fetched again");
    assert_eq!(x.judge(&t), Ok(Judgement::Held), "held meanwhile");
    round(&mut x, &mut peer);
    assert_eq!(x.ix.watermark(), T0 + 3);
    assert!(!x.holds(&t.hash()));
    assert_eq!(x.all(), peer.all(), "the same records");
}

/// A replayed old deletion after a watermark (§8 item 7): ignored
/// unverified at a read holder; at a write holder verified, noted, and
/// named at the round's end in a case-(c) cleanup that carries the greatest
/// watermark held.
#[test]
fn a_replayed_old_deletion_is_named_under_the_watermark_held() {
    let t = tombstone_at("t", 0xd1, T0 + 3);
    let high = watermarked(dev(0xd2), T0 + 21, T0 + 3, &[]);
    let mut w = Dev::writer(0xa0);
    w.accept(&high).unwrap();
    assert!(w.accept(&t).unwrap().noted);
    let end = w.end_round();
    let c = end.records[0].0;
    let r =
        licketysync_protocol::record::Record::parse(w.signed(&c).clone(), write_key().verifier())
            .unwrap();
    assert_eq!(r.groups().len(), 1);
    assert_eq!(r.groups()[0].because, None);
    assert_eq!(r.groups()[0].forget, vec![t.hash()]);
    match r.open(&write_key().record_keys()) {
        Ok(Applied::Cleanup(seal)) => assert_eq!(seal.forget_before, T0 + 3),
        other => panic!("{other:?}"),
    }
}

/// A transaction that signed a cleanup already (a round's end here) signs
/// no watermark: a watermark goes in a cleanup with no group only when no
/// other cleanup goes in its commit (4.4, "Cleanup", case (d)); the next
/// transaction's check signs.
#[test]
fn a_check_signs_nothing_in_a_transaction_that_signed_a_cleanup() {
    // A stale copy to name at the round's end: a version the held
    // tombstone covers.
    let old = forge("t", &[chunk(1)], &sealed_file("t", dev(0xd1), T0 + 1), &[]);
    let mut covering = sealed_file("t", dev(0xd1), T0 + 3);
    covering.deleted = true;
    covering.size = 0;
    covering.plain_hashes.clear();
    covering.vector = vec![super::kit::entry(dev(0xd1), T0 + 1)];
    let tomb = forge("t", &[], &covering, &[]);
    let mut x = Dev::writer(0xa1);
    x.accept(&tomb).unwrap();
    assert!(x.accept(&old).unwrap().noted);
    x.clock = T0 + TOMBSTONE_HORIZON;
    let Dev { ix, rng, clock, .. } = &mut x;
    let mut txn = ix.begin();
    assert!(!txn.wrote_cleanup());
    let end = txn.end_round(*clock, &mut |b| rng.fill(b)).unwrap();
    assert!(end.cleanup && txn.wrote_cleanup());
    let signed = txn
        .check_watermark(*clock, None, WATERMARK_INTERVAL, &mut |b| rng.fill(b))
        .unwrap();
    assert_eq!(signed.watermark, None, "the check waits");
    drop(txn);
    assert_eq!(
        x.check(None).0.watermark,
        Some(T0 + 3),
        "in a transaction of its own"
    );
}

/// Two cleanups carrying one watermark: `H` stays while either is held,
/// and falls once neither is.
#[test]
fn h_stays_while_any_cleanup_carrying_it_is_held() {
    let w1 = watermarked(dev(0xd1), T0 + 30, T0 + 10, &[]);
    let w2 = watermarked(dev(0xd2), T0 + 31, T0 + 10, &[]);
    let mut x = Dev::reader(0xa1);
    x.accept(&w1).unwrap();
    x.accept(&w2).unwrap();
    assert_eq!(x.ix.watermark(), T0 + 10);
    x.accept(&cleanup(dev(0xd4), T0 + 50, &[(None, vec![w1.hash()])]))
        .unwrap();
    assert!(!x.holds(&w1.hash()) && x.holds(&w2.hash()));
    assert_eq!(x.ix.watermark(), T0 + 10, "the other still carries it");
    x.accept(&cleanup(dev(0xd5), T0 + 51, &[(None, vec![w2.hash()])]))
        .unwrap();
    assert!(!x.holds(&w2.hash()));
    assert_eq!(x.ix.watermark(), 0, "none carries it");
}

/// The open expires once every stored record is in (4.4, "Opening a
/// folder"), so that what it holds depends on the records stored and not on
/// their order: a store that lists a deletion, the watermark that passes
/// it, then the version the deletion replaced (a store changed at rest)
/// opens as one that lists them in the order they came.
#[test]
fn the_open_expires_once_every_stored_record_is_in_whatever_their_order() {
    let mut d = Dev::writer(0xd0);
    let v = d.put("t", 1);
    d.apply("t");
    let t = d.delete("t");
    let w = watermarked(dev(0xd1), T0 + 500 * SEC, d.counter(&t), &[]);
    let records = [d.signed(&v).clone(), d.signed(&t).clone(), w.clone()];
    let mut held = Vec::new();
    for order in [[0, 1, 2], [1, 2, 0]] {
        let x = Dev::reader(0xa1);
        let mut stored = x.store.load().unwrap();
        stored.records = order
            .iter()
            .zip(1u64..)
            .map(|(&i, seq)| (records[i].clone(), seq))
            .collect();
        let mut rng = x.rng.clone();
        let (ix, _) = crate::Index::open(
            super::kit::folder_key(x.ix.tier()),
            x.ix.own(),
            stored,
            x.clock,
            &mut |b| rng.fill(b),
        );
        held.push(ix.records().map(|r| r.hash).collect::<BTreeSet<_>>());
    }
    assert_eq!(
        held[0],
        BTreeSet::from([w.hash()]),
        "the deletion expired, and the version it replaced gone"
    );
    assert_eq!(held[1], held[0], "in either order");
}

proptest! {
    #![proptest_config(super::proptest_config(64))]

    /// Property (p): the index by counter drops, at each rise of the
    /// greatest watermark, exactly what a scan of every record held finds
    /// at or below it, and a check finds the candidate a scan finds, never
    /// at or above the counter of a record young at the check's reading,
    /// and signs only when, by the scan too, it passes a deletion or a
    /// cleanup with a `because`.
    #[test]
    fn the_index_by_counter_agrees_with_a_scan_p(
        records in proptest::collection::vec((1u64..40, 0u8..4, 0u64..3), 1..24),
        now in 0u64..6,
        watermark in 0u64..40,
    ) {
        let mut w = Dev::writer(0xa0);
        for (i, (counter, kind, arrived)) in records.iter().enumerate() {
            let n = u8::try_from(i).unwrap();
            let r = match kind {
                0 => tombstone_at(&format!("t{i}"), 0xd1, *counter),
                1 => forge(&format!("v{i}"), &[chunk(n)], &sealed_file(&format!("v{i}"), dev(0xd1), *counter), &[]),
                2 => cleanup(dev(0xd1), *counter, &[(None, vec![RecordHash([n; 32])])]),
                _ => cleanup(dev(0xd1), *counter, &[(Some(RecordHash([n; 32])), vec![RecordHash([n.wrapping_add(100); 32])])]),
            };
            w.clock = *arrived * TOMBSTONE_HORIZON;
            w.accept(&r).unwrap();
        }
        // The scan: every applied tombstone, tree delete and cleanup held,
        // with its counter, arrival and whether it lets a check sign.
        let scan: Vec<(u64, u64, bool)> = w.ix.s.held.values()
            .filter_map(|h| {
                let a = h.applied()?;
                a.expirable().then(|| (a.dot().counter, h.arrival.unwrap(), h.lets_sign()))
            })
            .collect();
        let reading = now * TOMBSTONE_HORIZON;
        let young = |a: u64| a > reading || reading - a < TOMBSTONE_HORIZON;
        let stop = scan.iter().filter(|(_, a, _)| young(*a)).map(|(c, _, _)| *c).min();
        let passed: Vec<&(u64, u64, bool)> = scan.iter().filter(|(c, _, _)| stop.is_none_or(|s| *c < s)).collect();
        let expected = passed.iter().map(|(c, _, _)| *c).max();
        let lets = passed.iter().any(|(_, _, l)| *l);
        prop_assert_eq!(w.ix.s.candidate(reading, TOMBSTONE_HORIZON), expected.map(|c| (c, lets)));
        if let Some(c) = expected {
            prop_assert!(stop.is_none_or(|s| c < s), "never at or above a young record");
        }
        // Expiry by a watermark: the index's low end against the scan.
        let by_scan: BTreeSet<RecordHash> = w.ix.s.held.iter()
            .filter(|(_, h)| h.applied().is_some_and(|a| a.expirable() && a.dot().counter <= watermark))
            .map(|(r, _)| *r)
            .collect();
        let by_index: BTreeSet<RecordHash> = w.ix.s.expired(watermark).into_iter().collect();
        prop_assert_eq!(by_index, by_scan);
    }
}
