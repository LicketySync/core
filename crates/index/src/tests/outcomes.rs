// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `protocol.md` section 8 item 6, the index's part: each record's outcome
//! (duplicate, expired, obsolete, held, replacing, opaque, a record under
//! the device's own ID, records far from the clock, cleanups that carry a
//! watermark or none), with the section 5 row of each, on a write holder
//! and, where the tier changes nothing, on a read holder given the same
//! records (`outcomes.json`); then expiry on arrival at the greatest
//! watermark held, and step 3's obsolete records: ignored unverified when
//! they replace nothing held, verified and dropping what they replace
//! otherwise.

use licketysync_keys::RecordHash;
use licketysync_protocol::Cause;
use licketysync_protocol::connection::Judgement;
use licketysync_protocol::limits::{MAX_COUNTER, TOMBSTONE_HORIZON};
use licketysync_protocol::record::{Kind, WriterFault};
use prost::Message as _;
use serde_json::{Value, json};

use super::kit::{
    Dev, SEC, T0, chunk, cleanup, dev, entry, forge, forged, garbage, judgement, row, sealed_file,
    watermarked,
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
        "writer_fault": a.writer_fault.as_ref().map(ToString::to_string),
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

    // Expired: a tombstone that a watermark passes is dropped when the
    // watermark arrives, and ignored when it arrives again with a forged
    // signature at a read holder; a write holder that would note it as a
    // forgotten record verifies it first. D holds its tombstone a year and
    // signs the watermark, in a cleanup with no group (case (d)).
    {
        let mut d = Dev::writer(0xd0);
        d.put("docs/gone", 1);
        let t = d.delete("docs/gone");
        d.clock = T0 + TOMBSTONE_HORIZON + 2 * SEC;
        let (signed, _) = d.check(None);
        let later = signed.records[0].0;
        for (mut x, holder) in [(Dev::reader(0xa1), "read"), (Dev::writer(0xa0), "write")] {
            x.accept(d.signed(&t)).unwrap();
            x.clock = d.clock;
            let raised = x.accept(d.signed(&later)).unwrap();
            assert_eq!(raised.dropped, vec![t], "expired by the watermark");
            let again = x.accept(&forged(d.signed(&t)));
            if holder == "read" {
                assert_eq!(again.as_ref().map(|a| a.judgement), Ok(Judgement::Expired));
            } else {
                assert_eq!(again, Err(Cause::Forged), "verified before it is noted");
            }
            case(
                &format!("expired-tombstone-forged-{holder}-holder"),
                "a tombstone, then the watermark its writer signed a horizon and two seconds later: the tombstone expires; offered again forged",
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
            vec![
                accepted(&a),
                json!({ "next_write": h(&next.0), "names_it": true }),
            ],
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

    // Records far ahead of or behind the clock are judged as any record: no
    // record is refused, kept or forgotten for its counter against a clock
    // (4.4, "Dots and counters"). A counter of 1, one a year and a
    // microsecond ahead, and the counter ceiling itself: all held.
    {
        let mut w = Dev::writer(0xa0);
        let far = dev(0xf1);
        let steps: Vec<Value> = [
            ("docs/behind", 1),
            ("docs/ahead", T0 + TOMBSTONE_HORIZON + 1),
            ("docs/ceiling", MAX_COUNTER),
        ]
        .iter()
        .enumerate()
        .map(|(i, (path, counter))| {
            let r = forge(
                path,
                &[chunk(u8::try_from(i).unwrap() + 1)],
                &sealed_file(path, far, *counter),
                &[],
            );
            let a = w.accept(&r).unwrap();
            assert_eq!(a.judgement, Judgement::Held, "{path}");
            assert!(!a.own_ahead && a.writer_fault.is_none());
            accepted(&a)
        })
        .collect();
        assert_eq!(w.ix.hw(), MAX_COUNTER, "the mark rose to the ceiling");
        case(
            "far-from-the-clock",
            "counters of 1, a year and a microsecond ahead of T0, and MAX_COUNTER: each held, as any record",
            steps,
        );
    }

    // Cleanups and the watermark (4.4, "Cleanup", case (d)): one with no
    // group that carries a watermark is accepted on every tier and, at a key
    // holder, raises the greatest watermark held; one with no group and no
    // watermark is accepted and held, changing nothing until a watermark
    // passes it; one whose watermark equals its counter is a writer fault,
    // held opaque, its watermark counting for nothing.
    {
        let only = watermarked(dev(0xd2), T0 + 20, T0 + 10, &[]);
        let none = watermarked(dev(0xd2), T0 + 5, 0, &[]);
        let fault = watermarked(dev(0xd2), T0 + 30, T0 + 30, &[]);
        let mut steps = Vec::new();
        for mut x in [Dev::writer(0xa0), Dev::reader(0xa1), Dev::sealed(0xa2)] {
            let key_holder = x.ix.tier() != licketysync_keys::Tier::Sealed;
            let n = x.accept(&none).unwrap();
            assert_eq!(n.judgement, Judgement::Held);
            assert_eq!(x.ix.watermark(), 0);
            let f = x.accept(&fault).unwrap();
            if key_holder {
                assert_eq!(f.judgement, Judgement::HeldOpaque);
                assert_eq!(
                    f.writer_fault,
                    Some(WriterFault::Watermark {
                        forget_before: T0 + 30,
                        counter: T0 + 30
                    })
                );
            } else {
                assert_eq!(f.judgement, Judgement::Held, "a sealed peer reads no seal");
            }
            assert_eq!(x.ix.watermark(), 0, "an opaque cleanup counts for nothing");
            let o = x.accept(&only).unwrap();
            assert_eq!(o.judgement, Judgement::Held);
            if key_holder {
                assert_eq!(x.ix.watermark(), T0 + 10);
                assert_eq!(o.dropped, vec![none.hash()], "the watermark passes it");
            } else {
                assert_eq!(x.ix.watermark(), 0, "a sealed peer reads no watermark");
                assert!(o.dropped.is_empty() && x.holds(&none.hash()));
            }
            if x.ix.key().write_key().is_some() {
                steps = vec![accepted(&n), accepted(&f), accepted(&o)];
            }
        }
        case(
            "cleanups-with-no-group",
            "a cleanup with no group and no watermark (held, changing nothing), one whose watermark equals its counter (a writer fault, counting for nothing), and one with no group carrying the watermark T0 + 10, which expires the first",
            steps,
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
            vec![json!(
                dots.iter().map(|(c, k)| json!([c, k])).collect::<Vec<_>>()
            )],
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
fn an_opaque_record_moves_neither_the_mark_nor_the_greatest_watermark() {
    // An opaque record covers nothing and counts for nothing (4.4 step 6):
    // an index record whose seal fails a check raises no mark, and a cleanup
    // whose watermark is not below its counter raises no watermark, so the
    // tombstone it would pass stays held.
    let mut w = Dev::writer(0xa0);
    w.put("t", 1);
    w.apply("t");
    let t = w.delete("t");
    let t_counter = w.counter(&t);
    let hw = w.ix.hw();
    let mut m = sealed_file("x", w.id(), hw + 10);
    m.tree = true;
    let bad = forge("x", &[chunk(1)], &m, &[]);
    let a = w.accept(&bad).unwrap();
    assert_eq!(a.judgement, Judgement::HeldOpaque);
    assert!(!a.own_ahead);
    assert_eq!(w.ix.hw(), hw);
    let c = watermarked(dev(0xd2), t_counter, t_counter, &[]);
    let a = w.accept(&c).unwrap();
    assert_eq!(a.judgement, Judgement::HeldOpaque);
    assert_eq!((w.ix.hw(), w.ix.watermark()), (hw, 0));
    assert!(w.holds(&t), "the tombstone not expired");
    // The same watermark one below its own counter passes the tombstone.
    let c = watermarked(dev(0xd2), t_counter + 1, t_counter, &[]);
    let a = w.accept(&c).unwrap();
    assert_eq!(a.judgement, Judgement::Held);
    assert_eq!(a.dropped, vec![t]);
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

/// Expiry on arrival (4.4, "Expiry by the watermark"; step 3): at a read
/// or write holder whose greatest watermark is `H`, a tombstone, tree delete
/// or cleanup whose counter is `H` is expired, ignored unverified (a read
/// holder) and one at `H + 1` is held; a version at or below `H` is held,
/// since no version expires.
#[test]
fn a_deletion_or_cleanup_at_the_greatest_watermark_expires_and_one_above_it_does_not() {
    let h = T0 + 100;
    let deletion = |path: &str, counter: u64, tree: bool| {
        let mut m = sealed_file(path, dev(2), counter);
        m.deleted = true;
        m.size = 0;
        m.plain_hashes.clear();
        if tree {
            m.kind = 2;
            m.tree = true;
        }
        forge(path, &[], &m, &[])
    };
    for mut x in [Dev::reader(0xa1), Dev::writer(0xa0)] {
        let w = watermarked(dev(1), h + 50, h, &[]);
        assert_eq!(x.judge(&w), Ok(Judgement::Held));
        assert_eq!(x.ix.watermark(), h);
        for (name, at, above) in [
            (
                "tombstone",
                deletion("t-at", h, false),
                deletion("t-above", h + 1, false),
            ),
            (
                "tree delete",
                deletion("d-at", h, true),
                deletion("d-above", h + 1, true),
            ),
            (
                "cleanup",
                cleanup(dev(3), h, &[(None, vec![RecordHash([7; 32])])]),
                cleanup(dev(3), h + 1, &[(None, vec![RecordHash([8; 32])])]),
            ),
        ] {
            let judged = if x.ix.key().write_key().is_some() {
                x.judge(&at)
            } else {
                x.accept(&garbage(&at)).map(|a| a.judgement)
            };
            assert_eq!(judged, Ok(Judgement::Expired), "a {name} at H");
            assert!(!x.holds(&at.hash()));
            assert_eq!(x.judge(&above), Ok(Judgement::Held), "a {name} above H");
            assert!(x.holds(&above.hash()), "and kept");
        }
        let version = forge("v", &[chunk(1)], &sealed_file("v", dev(4), h - 1), &[]);
        assert_eq!(x.judge(&version), Ok(Judgement::Held), "a version below H");
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
