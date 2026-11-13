// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `protocol.md` section 8 item 6, the index's part: each record's outcome
//! (duplicate, expired, obsolete, held, replacing, opaque, from the future,
//! a record under the device's own ID), with the section 5 row of each, on a
//! write holder and, where the tier changes nothing, on a read holder given
//! the same records (`outcomes.json`); then expiry on arrival at its horizon,
//! and step 3's obsolete records: ignored unverified when they replace
//! nothing held, verified and dropping what they replace otherwise.

use licketysync_keys::RecordHash;
use licketysync_protocol::connection::Judgement;
use licketysync_protocol::limits::{CLOCK_AHEAD_WARNING, CLOCK_RULE_LIMIT, TOMBSTONE_HORIZON};
use licketysync_protocol::record::{Kind, WriterFault};
use licketysync_protocol::Cause;
use prost::Message as _;
use serde_json::{json, Value};

use super::kit::{
    chunk, cleanup, dev, entry, forge, forged, garbage, judgement, row, sealed_file, Dev, DAY, SEC,
    T0,
};
use super::vectors::{check, h};
use crate::{Accepted, Change};

fn accepted(a: &Accepted) -> Value {
    json!({
        "record": h(&a.hash.0),
        "judgement": judgement(a.judgement),
        "rows": a.rows.iter().map(|c| row(*c)).collect::<Vec<_>>(),
        "dropped": a.dropped.iter().map(|d| h(&d.0)).collect::<Vec<_>>(),
        "own_counter_ahead": a.own_ahead,
        "clock_ahead_us": a.clock_ahead.map(|(n, _)| n),
        "writer_fault": a.writer_fault.as_ref().map(ToString::to_string),
        "from_the_future": a.from_future.is_some(),
    })
}

fn refused(c: Cause) -> Value {
    json!({ "closes": row(c) })
}

fn outcome(r: Result<Accepted, Cause>) -> Value {
    match r {
        Ok(a) => accepted(&a),
        Err(c) => refused(c),
    }
}

/// A writer D's two versions of one path, the second over the first.
fn two_versions() -> (Dev, RecordHash, RecordHash) {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("docs/a", 1);
    let v2 = d.put("docs/a", 2);
    (d, v1, v2)
}

#[test]
fn vector_outcomes() {
    let mut cases = Vec::new();
    let mut case = |name: &str, notes: &str, steps: Vec<Value>| {
        cases.push(json!({ "name": name, "notes": notes, "steps": steps }));
    };

    // A duplicate whose signature bytes are garbage: ignored, never verified.
    for (tier, holder) in [(0u8, "write"), (1, "read"), (2, "sealed")] {
        let (d, v1, _) = two_versions();
        let mut w = match tier {
            0 => Dev::writer(0xa0),
            1 => Dev::reader(0xa0),
            _ => Dev::sealed(0xa0),
        };
        let first = w.accept(d.signed(&v1)).unwrap();
        assert_eq!(first.judgement, Judgement::Held);
        let again = w.accept(&garbage(d.signed(&v1))).unwrap();
        assert_eq!(again.judgement, Judgement::Duplicate);
        assert_eq!(again.rows, vec![Cause::Duplicate]);
        case(
            &format!("duplicate-with-garbage-signature-{holder}-holder"),
            "held once; the same body again with a garbage signature is a duplicate, not verified",
            vec![accepted(&first), accepted(&again)],
        );
    }

    // Obsolete with a forged signature: named by the version held (its base
    // when it was written), ignored unverified at every tier; the same forged
    // envelope of a record that replaces the version held is verified: closed,
    // nothing staged.
    {
        let (mut d, v1, v2) = two_versions();
        let v3 = d.put("docs/a", 3);
        for mut w in [Dev::writer(0xa0), Dev::reader(0xa1), Dev::sealed(0xa2)] {
            w.accept(d.signed(&v2)).unwrap();
            let old = w.accept(&forged(d.signed(&v1))).unwrap();
            assert_eq!(old.judgement, Judgement::Obsolete);
            let over = w.accept(&forged(d.signed(&v3)));
            assert_eq!(over, Err(Cause::Forged));
            assert!(w.holds(&v2) && !w.holds(&v3), "nothing staged");
            if w.ix.key().write_key().is_some() {
                case(
                    "obsolete-forged-and-forged-covering-the-live-version",
                    "v2 held; v1 forged is obsolete (v2 names it), ignored unverified; v3 forged replaces v2, so it is verified: closed",
                    vec![accepted(&old), refused(Cause::Forged)],
                );
            }
        }
    }

    // Expired: a tombstone the folder's own time has passed by more than
    // TOMBSTONE_HORIZON is dropped, and ignored when it arrives again with a
    // forged signature at a read holder; a write holder that would note it as
    // a forgotten record verifies it first.
    {
        let mut d = Dev::writer(0xd0);
        d.put("docs/gone", 1);
        let t = d.delete("docs/gone");
        d.clock = T0 + TOMBSTONE_HORIZON + 2 * SEC;
        let later = d.put("docs/later", 2);
        for (mut x, holder) in [(Dev::reader(0xa1), "read"), (Dev::writer(0xa0), "write")] {
            x.accept(d.signed(&t)).unwrap();
            x.clock = d.clock;
            let raised = x.accept(d.signed(&later)).unwrap();
            assert_eq!(raised.dropped, vec![t], "expired by the folder's own time");
            let again = x.accept(&forged(d.signed(&t)));
            if holder == "read" {
                assert_eq!(again.as_ref().map(|a| a.judgement), Ok(Judgement::Expired));
            } else {
                assert_eq!(again, Err(Cause::Forged), "verified before it is noted");
            }
            case(
                &format!("expired-tombstone-forged-{holder}-holder"),
                "a tombstone, then a record a horizon and a second later: the tombstone expires; offered again forged",
                vec![accepted(&raised), outcome(again)],
            );
        }
    }

    // A writer fault in the seal, held opaque: counted in the digest,
    // covering nothing, replaced only by a name; the issue names the record.
    {
        let bad = {
            let mut m = sealed_file("docs/f", dev(0xd0), T0);
            m.vector = vec![entry(dev(0xd1), T0)];
            forge("docs/f", &[chunk(1)], &m, &[])
        };
        let mut w = Dev::writer(0xa0);
        let before = w.root();
        let a = w.accept(&bad).unwrap();
        assert_eq!(a.judgement, Judgement::HeldOpaque);
        assert_eq!(a.writer_fault, Some(WriterFault::VectorCounterNotBelow));
        assert!(a.rows.contains(&Cause::WriterFault));
        assert_ne!(w.root(), before, "counted in the digest");
        assert!(w.heads("docs/f").is_empty());
        assert_eq!(w.ix.path("docs/f").unwrap().opaque, vec![a.hash]);
        // The next write at the path names it (a shared writer fault).
        let next = w.put("docs/f", 5);
        assert!(!w.holds(&a.hash), "named by the next write");
        case(
            "writer-fault-in-the-seal",
            "a vector entry equal to the counter: held opaque, counted in the digest; the next write at the path names it",
            vec![accepted(&a), json!({ "next_write": h(&next.0), "names_it": true })],
        );
    }

    // A record under this device's own ID above its high-water mark: held,
    // the mark raised to it, a new epoch, the informational row; one at the
    // mark: nothing.
    {
        let mut w = Dev::writer(0xa0);
        w.put("docs/mine", 1);
        let hw = w.ix.hw();
        let epoch = w.ix.epoch();
        let ahead = forge(
            "docs/other",
            &[chunk(2)],
            &sealed_file("docs/other", w.id(), hw + 5),
            &[],
        );
        let a = w.accept(&ahead).unwrap();
        assert!(a.own_ahead && a.rows.contains(&Cause::OwnCounterAhead));
        assert_eq!(w.ix.hw(), hw + 5);
        assert_ne!(w.ix.epoch(), epoch, "a new epoch");
        let at = forge(
            "docs/third",
            &[chunk(3)],
            &sealed_file("docs/third", w.id(), hw + 5),
            &[],
        );
        let b = w.accept(&at).unwrap();
        assert!(!b.own_ahead);
        case(
            "own-device-id-above-and-at-the-high-water-mark",
            "a record under this device's ID five above its mark, then one at the mark",
            vec![accepted(&a), accepted(&b)],
        );
    }

    // A counter a day and a microsecond ahead of the receiver's clock: held,
    // the warning naming its device; exactly a day ahead: no warning; the
    // first again forged and obsolete: ignored, no warning.
    {
        let mut w = Dev::writer(0xa0);
        let fast = dev(0xf0);
        let over = forge(
            "docs/fast",
            &[chunk(1)],
            &sealed_file("docs/fast", fast, T0 + CLOCK_AHEAD_WARNING + 1),
            &[],
        );
        let at = forge(
            "docs/at",
            &[chunk(2)],
            &sealed_file("docs/at", fast, T0 + CLOCK_AHEAD_WARNING),
            &[],
        );
        let a = w.accept(&over).unwrap();
        assert_eq!(a.clock_ahead, Some((DAY + 1, fast)));
        assert!(a.rows.contains(&Cause::ClockAhead));
        let b = w.accept(&at).unwrap();
        assert_eq!(b.clock_ahead, None);
        // A version over the fast one, then the fast one again forged.
        let mut m = sealed_file("docs/fast", fast, T0 + CLOCK_AHEAD_WARNING + 2);
        m.vector = vec![entry(fast, T0 + CLOCK_AHEAD_WARNING + 1)];
        let newer = forge("docs/fast", &[chunk(3)], &m, &[a.hash]);
        w.accept(&newer).unwrap();
        let mut r = Dev::reader(0xa1);
        r.accept(&newer).unwrap();
        let c = r.accept(&forged(&over)).unwrap();
        assert_eq!(c.judgement, Judgement::Obsolete);
        assert_eq!(c.clock_ahead, None);
        case(
            "counter-ahead-of-the-clock",
            "a day and a microsecond ahead (warned), exactly a day (not), and the first forged once something replaces it (ignored, read holder)",
            vec![accepted(&a), accepted(&b), accepted(&c)],
        );
    }

    // From the future: more than CLOCK_RULE_LIMIT ahead, verified and refused,
    // not held; again on the same connection, ignored unverified; forged, the
    // first time, closed; exactly at the limit: held.
    {
        let mut w = Dev::writer(0xa0);
        let far = forge(
            "docs/far",
            &[chunk(1)],
            &sealed_file("docs/far", dev(0xf1), T0 + CLOCK_RULE_LIMIT + 1),
            &[],
        );
        let edge = forge(
            "docs/edge",
            &[chunk(2)],
            &sealed_file("docs/edge", dev(0xf1), T0 + CLOCK_RULE_LIMIT),
            &[],
        );
        let mut fresh = Dev::writer(0xa2);
        assert_eq!(fresh.accept(&forged(&far)), Err(Cause::Forged), "verified");
        let a = w.accept(&far).unwrap();
        assert_eq!(a.judgement, Judgement::FromTheFuture);
        assert_eq!(a.from_future, Some(dev(0xf1)));
        assert!(!w.holds(&a.hash), "neither held nor relayed");
        let again = w.accept(&garbage(&far)).unwrap();
        assert_eq!(again.judgement, Judgement::FromTheFuture);
        assert_eq!(
            again.from_future, None,
            "known on this connection: not verified"
        );
        let b = w.accept(&edge).unwrap();
        assert_eq!(b.judgement, Judgement::Held);
        case(
            "from-the-future",
            "a year and a microsecond ahead (refused, verified, remembered on the connection), again with a garbage signature (ignored), forged on a fresh connection (closed), exactly a year (held)",
            vec![accepted(&a), accepted(&again), refused(Cause::Forged), accepted(&b)],
        );
    }

    // R2 S-B: a record whose vector fails step 7 (an entry equal to its
    // counter), which a held record would cover by that vector, in both
    // arrival orders: both held, the bad one opaque, covering nothing and
    // covered by nothing.
    for first_bad in [true, false] {
        let good = forge(
            "docs/s",
            &[chunk(1)],
            &sealed_file("docs/s", dev(0xd0), 10),
            &[],
        );
        let mut m = sealed_file("docs/s", dev(0xe0), 20);
        m.vector = vec![entry(dev(0xd0), 20)];
        let bad = forge("docs/s", &[chunk(2)], &m, &[]);
        let mut cover = sealed_file("docs/s", dev(0xd0), 30);
        cover.vector = vec![entry(dev(0xd0), 10), entry(dev(0xe0), 20)];
        cover.vector.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let later = forge("docs/s", &[chunk(3)], &cover, &[]);
        for mut x in [Dev::writer(0xa0), Dev::reader(0xa1)] {
            let order: [&licketysync_keys::records::SignedRecord; 2] = if first_bad {
                [&bad, &good]
            } else {
                [&good, &bad]
            };
            let steps: Vec<Value> = order.iter().map(|r| outcome(x.accept(r))).collect();
            assert!(x.holds(&good.hash()) && x.holds(&bad.hash()));
            assert_eq!(x.heads("docs/s"), vec![good.hash()]);
            // A later version whose vector covers both dots drops the good
            // one (covered) and not the opaque one (only a name does).
            let l = x.accept(&later).unwrap();
            assert_eq!(l.dropped, vec![good.hash()]);
            assert!(x.holds(&bad.hash()));
            if x.ix.key().write_key().is_some() {
                case(
                    &format!(
                        "unchecked-vector-r2-s-b-{}",
                        if first_bad { "bad-first" } else { "good-first" }
                    ),
                    "a vector entry equal to its counter that would cover the good record: opaque, covers nothing; a later version covering both dots drops only the good one",
                    steps.into_iter().chain([accepted(&l)]).collect(),
                );
            }
        }
    }

    // A sealed part padded one power of two past what its metadata needs.
    {
        let w = crate::tests::kit::write_key();
        let keys = w.record_keys();
        let tag = keys.path_tag("docs/report.txt");
        let over = include_bytes!("../../../../fuzz/seeds/sealed_meta_open/index-300-in-1024");
        let body = licketysync_protocol::messages::IndexRecord {
            suite: 1,
            record_type: 16,
            folder_id: w.verifier().folder_id().0.to_vec(),
            chunks: vec![],
            sealed: over.to_vec(),
            path_tag: tag.0.to_vec(),
            replaces: vec![],
        };
        let r = w.sign_index_record(body.encode_to_vec()).unwrap();
        let mut x = Dev::writer(0xa0);
        let a = x.accept(&r).unwrap();
        assert_eq!(a.judgement, Judgement::HeldOpaque);
        case(
            "sealed-part-over-padded",
            "300 bytes of metadata padded to 1 024: a writer fault",
            vec![accepted(&a)],
        );
    }

    // The counters of one commit: versions, tree deletes, tombstones, then
    // cleanups, consecutive, each kind by ascending path tag.
    {
        let mut d = Dev::writer(0xd0);
        d.put("t/one", 1);
        d.put("x", 2);
        d.put("y", 3);
        d.apply_all();
        let m = 9_000;
        let written = d
            .write(&[
                Change::Put(super::kit::tombstone("y", Kind::File, m)),
                Change::Put(super::kit::file("v", 4, m)),
                Change::TreeDelete {
                    path: "t".into(),
                    mtime_ns: m,
                },
                Change::Put(super::kit::tombstone("x", Kind::File, m)),
            ])
            .unwrap();
        let dots: Vec<(u64, String)> = written
            .records
            .iter()
            .map(|(hash, _)| {
                let held = &d.ix.s.held[hash];
                let kind = match held.meta() {
                    None => "cleanup".to_string(),
                    Some(m) if m.tree => "tree delete".to_string(),
                    Some(m) => m.path.clone(),
                };
                (held.applied().unwrap().dot().counter, kind)
            })
            .collect();
        for w in dots.windows(2) {
            assert_eq!(w[1].0, w[0].0 + 1, "consecutive");
        }
        let kinds: Vec<&str> = dots.iter().map(|(_, k)| k.as_str()).collect();
        assert_eq!(kinds[0], "v");
        assert_eq!(kinds[1], "tree delete");
        let tag = |p: &str| super::kit::tag(p);
        let (a, b) = if tag("x") < tag("y") {
            ("x", "y")
        } else {
            ("y", "x")
        };
        assert_eq!(&kinds[2..4], &[a, b], "tombstones by ascending tag");
        assert_eq!(kinds[4], "cleanup");
        case(
            "the-counters-of-one-commit",
            "a version, a tree delete (with its cleanup), two tombstones: consecutive counters in the writer's order",
            vec![json!(dots.iter().map(|(c, k)| json!([c, k])).collect::<Vec<_>>())],
        );
    }

    // A tree delete of kind 1, and one of size 5: shared writer faults, held
    // opaque, named by the next write at the path, which every tier drops.
    {
        let mut m1 = sealed_file("docs", dev(0xd0), 10);
        m1.deleted = true;
        m1.tree = true;
        m1.size = 0;
        m1.plain_hashes.clear();
        let kind1 = forge("docs", &[], &m1, &[]);
        let mut m2 = m1.clone();
        m2.kind = 2;
        m2.size = 5;
        m2.counter = 11;
        let size5 = forge("docs", &[], &m2, &[]);
        let mut w = Dev::writer(0xa0);
        let mut s = Dev::sealed(0xa3);
        let a = w.accept(&kind1).unwrap();
        let b = w.accept(&size5).unwrap();
        s.accept(&kind1).unwrap();
        s.accept(&size5).unwrap();
        assert_eq!(a.judgement, Judgement::HeldOpaque);
        assert_eq!(b.writer_fault, Some(WriterFault::TreeKindOrSize));
        let next = w.mkdir("docs");
        assert!(!w.holds(&kind1.hash()) && !w.holds(&size5.hash()));
        let at_sealed = s.accept(w.signed(&next)).unwrap();
        assert_eq!(
            at_sealed.dropped.len(),
            2,
            "the sealed peer drops both by name"
        );
        case(
            "tree-delete-of-kind-1-and-of-size-5",
            "shared writer faults: held opaque, named by the next write at the path, dropped at a sealed peer by those names",
            vec![accepted(&a), accepted(&b), accepted(&at_sealed)],
        );
    }

    // A record that is forged and a writer fault too: the index opens its
    // seal before the signature (step 3, judging no one), but a fault is a
    // verdict only once the signature verifies, so it is forged that closes,
    // at every tier, and nothing is staged (the R2 review's N6).
    {
        let mut m = sealed_file("docs/faulty", dev(0xd0), 12);
        m.tree = true;
        let faulty = forged(&forge("docs/faulty", &[chunk(4)], &m, &[]));
        for mut x in [Dev::writer(0xa0), Dev::reader(0xa1), Dev::sealed(0xa2)] {
            let before = x.root();
            assert_eq!(x.accept(&faulty), Err(Cause::Forged));
            assert_eq!(x.root(), before, "nothing staged");
        }
        case(
            "forged-and-a-writer-fault",
            "a tree mark on a file, and its signature forged: closed as forged at every tier, never held opaque",
            vec![refused(Cause::Forged)],
        );
    }

    // A cleanup is held at every tier; at a sealed holder its counter is not
    // read.
    {
        let c = cleanup(dev(0xd0), T0, &[(None, vec![RecordHash([7; 32])])]);
        let mut s = Dev::sealed(0xa3);
        let a = s.accept(&c).unwrap();
        assert_eq!(a.judgement, Judgement::Held);
        assert_eq!(s.ix.hw(), 0, "a sealed holder keeps no mark");
        case(
            "a-cleanup-at-a-sealed-holder",
            "held; nothing of its seal read",
            vec![accepted(&a)],
        );
    }

    check(
        "outcomes",
        &json!({
            "description": "protocol.md 8 item 6, the index's part: each record's outcome and its section 5 rows, records of the keys crate's fixed folder written or forged with fixed nonces at the fixed clock T0 (2027-01-15, microseconds). A refusal that closes is { closes: row }.",
            "clock_t0_us": T0,
            "cases": cases,
        }),
    );
}

#[test]
fn an_opaque_record_moves_neither_the_mark_nor_the_folders_time() {
    // An opaque record covers nothing and counts for nothing: its counter,
    // were it read past a failed check, would expire the tombstone and
    // raise the mark (4.4 step 6).
    let mut w = Dev::writer(0xa0);
    w.put("t", 1);
    w.apply("t");
    let t = w.delete("t");
    let (g, hw) = (w.ix.folder_time(), w.ix.hw());
    let mut m = sealed_file("x", w.id(), T0 + TOMBSTONE_HORIZON + 10 * SEC);
    m.tree = true;
    let bad = forge("x", &[chunk(1)], &m, &[]);
    w.clock = T0 + TOMBSTONE_HORIZON + 20 * SEC;
    let a = w.accept(&bad).unwrap();
    assert_eq!(a.judgement, Judgement::HeldOpaque);
    assert!(!a.own_ahead);
    assert_eq!((w.ix.folder_time(), w.ix.hw()), (g, hw));
    assert!(w.holds(&t), "the tombstone not expired");
}

#[test]
fn a_stale_copy_is_verified_before_it_is_noted_c1_sc1() {
    // Security C1 / SC-1: a write holder notes a record a peer offers that it
    // holds replaced (a stale copy) only after its signature verifies; a
    // forged one closes, and nothing is noted.
    let (d, v1, v2) = two_versions();
    let mut e = Dev::writer(0xe0);
    e.accept(d.signed(&v1)).unwrap();
    e.apply_all();
    let e2 = e.put("docs/a", 9);
    let mut w = Dev::writer(0xa0);
    // E's version names v1, its base, so v1 is no stale copy at W: the
    // copy is D's v2, which W holds covered by a third record that does not
    // name it.
    w.accept(e.signed(&e2)).unwrap();
    let mut m = sealed_file("docs/a", dev(0xc0), T0 + 50);
    m.vector = vec![entry(d.id(), T0 + 1), entry(e.id(), T0 + 2)];
    m.vector.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let over = forge("docs/a", &[chunk(4)], &m, &[e2]);
    w.accept(&over).unwrap();
    // v2 is covered by `over` (d: T0 + 1) and named by nothing W holds.
    assert_eq!(w.accept(&forged(d.signed(&v2))), Err(Cause::Forged));
    assert!(w.ix.s.notes.is_empty(), "nothing noted");
    let a = w.accept(d.signed(&v2)).unwrap();
    assert_eq!(a.judgement, Judgement::Obsolete);
    assert!(a.noted, "noted once verified");
    // Noted once: never verified again while the note lasts.
    let again = w.accept(&garbage(d.signed(&v2))).unwrap();
    assert!(!again.noted);
}

/// Phase 0's expiry by the folder's own time `G` on arrival (step 3, as the
/// CHANGELOG's index entry of phase 0 has it: expired once `G` has passed
/// the record's counter by strictly more than its horizon, 365 days for a
/// tombstone or tree delete, 30 for a cleanup): one exactly its horizon
/// behind `G` is held, one a microsecond older is expired. The signed
/// watermark (`protocol.md` 4.4, "Expiry by the watermark", spec 59783b1)
/// replaces this rule in phase 1, and this test with it.
#[test]
fn a_deletion_or_cleanup_exactly_its_horizon_behind_the_folders_time_is_not_expired() {
    use licketysync_protocol::limits::CLEANUP_HORIZON;
    let g = T0 + TOMBSTONE_HORIZON + 10 * SEC;
    let tombstone = |path: &str, counter: u64| {
        let mut m = sealed_file(path, dev(2), counter);
        m.deleted = true;
        m.size = 0;
        m.plain_hashes.clear();
        forge(path, &[], &m, &[])
    };
    for mut x in [Dev::reader(0xa1), Dev::writer(0xa0)] {
        x.clock = g;
        let late = forge("late", &[chunk(1)], &sealed_file("late", dev(1), g), &[]);
        assert_eq!(x.judge(&late), Ok(Judgement::Held));
        assert_eq!(x.ix.folder_time(), g);
        let at = tombstone("at", g - TOMBSTONE_HORIZON);
        assert_eq!(x.judge(&at), Ok(Judgement::Held), "a tombstone at it");
        assert!(x.holds(&at.hash()), "and kept");
        let past = tombstone("past", g - TOMBSTONE_HORIZON - 1);
        assert_eq!(
            x.judge(&past),
            Ok(Judgement::Expired),
            "a tombstone past it"
        );
        let at = cleanup(
            dev(3),
            g - CLEANUP_HORIZON,
            &[(None, vec![RecordHash([7; 32])])],
        );
        assert_eq!(x.judge(&at), Ok(Judgement::Held), "a cleanup at it");
        assert!(x.holds(&at.hash()), "and kept");
        let past = cleanup(
            dev(3),
            g - CLEANUP_HORIZON - 1,
            &[(None, vec![RecordHash([8; 32])])],
        );
        assert_eq!(x.judge(&past), Ok(Judgement::Expired), "a cleanup past it");
    }
}

// Step 3 (`protocol.md` 4.4): a record that something held names, covers or
// forgets is obsolete only when it replaces nothing held; then it is ignored
// unverified (TM-22: no peer makes this device verify what changes
// nothing), and otherwise it is verified and drops what it replaces, and
// step 6 then leaves it unheld.

/// A cleanup that a held cleanup forgets in a group that applies, and whose
/// own groups forget nothing held, is obsolete: ignored unverified at every
/// tier, so a copy with a garbage signature is judged obsolete, not forged.
#[test]
fn a_cleanup_a_held_cleanup_forgets_that_forgets_nothing_held_is_obsolete_unverified() {
    let c1 = cleanup(dev(1), T0 + 10, &[(None, vec![RecordHash([7; 32])])]);
    let c2 = cleanup(dev(1), T0 + 20, &[(None, vec![c1.hash()])]);
    for mut x in [Dev::writer(0xa0), Dev::reader(0xa1), Dev::sealed(0xa2)] {
        assert_eq!(x.judge(&c2), Ok(Judgement::Held));
        let a = x.accept(&garbage(&c1));
        assert_eq!(
            a.map(|a| a.judgement),
            Ok(Judgement::Obsolete),
            "unverified"
        );
        assert!(!x.holds(&c1.hash()));
    }
}

/// A cleanup that a held cleanup forgets, but whose own group that applies
/// forgets a record held, replaces something: it is verified, drops that
/// record (step 6), and is not held, since the held cleanup forgets it.
#[test]
fn a_cleanup_a_held_cleanup_forgets_still_drops_what_its_own_groups_forget() {
    let mut d = Dev::writer(0xd0);
    let v = d.put("f", 1);
    let c1 = cleanup(dev(1), T0 + 10, &[(None, vec![v])]);
    let c2 = cleanup(dev(1), T0 + 20, &[(None, vec![c1.hash()])]);
    for mut x in [Dev::writer(0xa0), Dev::reader(0xa1), Dev::sealed(0xa2)] {
        x.take(&d, &[v]);
        assert_eq!(x.judge(&c2), Ok(Judgement::Held));
        assert_eq!(x.accept(&forged(&c1)), Err(Cause::Forged), "verified");
        assert!(x.holds(&v), "nothing staged");
        let a = x.accept(&c1).unwrap();
        assert!(!a.judgement.held(), "not held: c2 forgets it");
        assert!(a.rows.contains(&Cause::ReplacesHeld), "{:?}", a.rows);
        assert_eq!(a.dropped, vec![v], "what it forgets goes all the same");
        assert!(!x.holds(&v) && !x.holds(&c1.hash()));
    }
}

/// A version that a record held at its tag names, but that covers another
/// version held there, replaces something at a read or write holder: it is
/// verified, drops the version it covers (step 6), and is not held, since
/// the held record names it. U by device 1 and W by device 2 are concurrent
/// heads; V by device 3 covers U, and W names V.
#[test]
fn a_version_a_held_record_names_still_drops_the_versions_at_its_tag_it_covers() {
    let u = forge("f", &[chunk(1)], &sealed_file("f", dev(1), T0), &[]);
    let mut mv = sealed_file("f", dev(3), T0 + 3);
    mv.vector = vec![entry(dev(1), T0)];
    let v = forge("f", &[chunk(3)], &mv, &[]);
    let w = forge(
        "f",
        &[chunk(2)],
        &sealed_file("f", dev(2), T0 + 5),
        &[v.hash()],
    );
    for mut x in [Dev::writer(0xa0), Dev::reader(0xa1)] {
        assert_eq!(x.judge(&u), Ok(Judgement::Held));
        assert_eq!(x.judge(&w), Ok(Judgement::Held));
        assert_eq!(x.accept(&forged(&v)), Err(Cause::Forged), "verified");
        let a = x.accept(&v).unwrap();
        assert!(!a.judgement.held(), "not held: w names it");
        assert!(a.rows.contains(&Cause::ReplacesHeld), "{:?}", a.rows);
        assert_eq!(a.dropped, vec![u.hash()], "it covers u");
        assert!(!x.holds(&u.hash()) && !x.holds(&v.hash()) && x.holds(&w.hash()));
    }
}

/// A version covered at its tag replaces nothing held when it covers no
/// version held at its tag, whatever it covers beneath its path: step 3
/// judges a version by its tag, and only a tree delete by what lies
/// beneath it. D, a directory version at `a` by device 2, covers V, a
/// directory version there by device 3 whose vector covers U, a file in
/// `a`: V is obsolete, ignored unverified at a read holder (a write holder
/// would verify it to note it), and U stays.
#[test]
fn a_version_covered_at_its_tag_is_obsolete_unverified_whatever_it_covers_beneath_it() {
    let directory = |device, counter| licketysync_protocol::messages::SealedMeta {
        kind: 2,
        size: 0,
        mode: 0o755,
        plain_hashes: vec![],
        ..sealed_file("a", device, counter)
    };
    let u = forge("a/x", &[chunk(1)], &sealed_file("a/x", dev(1), T0), &[]);
    let mut mv = directory(dev(3), T0 + 5);
    mv.vector = vec![entry(dev(1), T0)];
    let v = forge("a", &[], &mv, &[]);
    let mut md = directory(dev(2), T0 + 10);
    md.vector = vec![entry(dev(3), T0 + 5)];
    let d = forge("a", &[], &md, &[]);
    let mut x = Dev::reader(0xa1);
    assert_eq!(x.judge(&u), Ok(Judgement::Held));
    assert_eq!(x.judge(&d), Ok(Judgement::Held));
    let a = x.accept(&garbage(&v));
    assert_eq!(
        a.map(|a| a.judgement),
        Ok(Judgement::Obsolete),
        "unverified"
    );
    assert!(x.holds(&u.hash()) && x.holds(&d.hash()));
    let a = x.accept(&v).unwrap();
    assert_eq!(a.judgement, Judgement::Obsolete);
    assert!(a.dropped.is_empty() && x.holds(&u.hash()));
}
