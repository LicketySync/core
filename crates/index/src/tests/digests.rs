// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `protocol.md` section 8 item 8, the index's part (`digests.json`): set
//! digests of an empty subtree, a leaf of one and of 64 records, a node over
//! 65, and a full-depth leaf over 65 records at one tag; the cache after a
//! record joins and one leaves a leaf; serving an `IndexRequest` (pages and
//! `through`, nothing to send, another epoch, a `since` above the local
//! sequence), `RECORDS` and `CHILDREN`; and what the index keeps for the
//! exchange: local sequence numbers, renumbering past `MAX_LOCAL_SEQ`, a
//! cleanup numbered and served, and per-peer state.

use std::collections::BTreeMap;

use licketysync_keys::{RecordHash, SetDigest};
use licketysync_protocol::connection::ReconcileServe;
use licketysync_protocol::exchange::{IndexView, Key, Prefix};
use licketysync_protocol::limits::{
    DEFAULT_MESSAGE_SIZE, MAX_LOCAL_SEQ, MAX_PEER_STATES, PEER_STATE_HORIZON, RECONCILE_LEAF_MAX,
};
use licketysync_protocol::messages::ReconcileOutcome;
use licketysync_protocol::record::Record;
use proptest::prelude::*;
use serde_json::{json, Value};

use super::kit::{chunk, cleanup, converge, dev, forge, round, sealed_file, Dev, DAY, T0};
use super::vectors::{check, h};
use crate::SincePlan;

/// The record hash a set-digest key ends with.
fn hash_in(key: &Key) -> RecordHash {
    RecordHash(key[32..].try_into().unwrap())
}

/// A key at `tag` beginning the record-hash half with `hash`'s bytes: the
/// 64-nibble prefix of every record at that tag is `Prefix::of_key(&k, 64)`.
fn key_at(tag: &licketysync_keys::PathTag, hash: &RecordHash) -> Key {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(&tag.0);
    k[32..].copy_from_slice(&hash.0);
    k
}

/// The set digest of the records with `keys` at `prefix`, computed from
/// nothing but `protocol.md` 4.5: what the index's cache must equal.
pub(crate) fn reference(keys: &[Key], prefix: &Prefix) -> SetDigest {
    let mut inside: Vec<RecordHash> = keys
        .iter()
        .filter(|k| prefix.contains(k))
        .map(hash_in)
        .collect();
    inside.sort();
    if inside.is_empty() {
        SetDigest::EMPTY
    } else if inside.len() <= RECONCILE_LEAF_MAX || prefix.is_full() {
        SetDigest::leaf(&inside)
    } else {
        let children: [SetDigest; 16] =
            core::array::from_fn(|i| reference(keys, &prefix.child(i as u8).unwrap()));
        SetDigest::node(&children)
    }
}

fn keys_of(d: &Dev) -> Vec<Key> {
    d.ix.s.held.values().map(|h| h.record.key()).collect()
}

/// `n` forged records at distinct paths.
fn spread(n: usize) -> Vec<licketysync_keys::records::SignedRecord> {
    (0..n)
        .map(|i| {
            let p = format!("spread/{i}");
            forge(
                &p,
                &[chunk(1)],
                &sealed_file(&p, dev(0xd0), T0 + i as u64),
                &[],
            )
        })
        .collect()
}

fn digests() -> Value {
    let mut out = Vec::new();
    let mut x = Dev::sealed(0xa2);
    assert_eq!(
        x.root(),
        SetDigest::EMPTY,
        "an empty subtree: 32 zero bytes"
    );
    out.push(json!({ "name": "empty", "digest": h(x.root().as_bytes()) }));
    let records = spread(65);
    x.accept(&records[0]).unwrap();
    assert_eq!(x.root(), SetDigest::leaf(&[records[0].hash()]));
    out.push(json!({ "name": "a-leaf-of-one", "digest": h(x.root().as_bytes()) }));
    for r in &records[1..64] {
        x.accept(r).unwrap();
    }
    let mut all: Vec<RecordHash> = records[..64]
        .iter()
        .map(licketysync_keys::records::SignedRecord::hash)
        .collect();
    all.sort();
    assert_eq!(x.root(), SetDigest::leaf(&all), "64 records: leaf form");
    out.push(json!({ "name": "a-leaf-of-64", "digest": h(x.root().as_bytes()) }));
    x.accept(&records[64]).unwrap();
    let keyed = keys_of(&x);
    assert_eq!(x.root(), reference(&keyed, &Prefix::ROOT));
    assert_ne!(
        x.root(),
        SetDigest::leaf(&{
            let mut v: Vec<RecordHash> = keyed.iter().map(hash_in).collect();
            v.sort();
            v
        }),
        "65: node form"
    );
    out.push(json!({ "name": "a-node-over-65", "digest": h(x.root().as_bytes()) }));
    // 65 records at one tag: node form at its 64-nibble prefix, its children
    // split by the first nibble of each record hash.
    let mut y = Dev::sealed(0xa3);
    let mut at_tag = Vec::new();
    for i in 0..65u8 {
        let mut m = sealed_file("one", dev(0x40 + i), T0);
        m.plain_hashes = vec![vec![i; 32]];
        let r = forge("one", &[chunk(i)], &m, &[]);
        y.accept(&r).unwrap();
        at_tag.push(r.hash());
    }
    at_tag.sort();
    let tag = super::kit::tag("one");
    let at = Prefix::of_key(&key_at(&tag, &at_tag[0]), 64);
    let keyed = keys_of(&y);
    assert_eq!(y.ix.digest(&at), reference(&keyed, &at));
    assert_ne!(
        y.ix.digest(&at),
        SetDigest::leaf(&at_tag),
        "65 at one tag: node form"
    );
    let children = y.ix.children(&at);
    for (n, d) in children.iter().enumerate() {
        let below: Vec<RecordHash> = at_tag
            .iter()
            .filter(|h| usize::from(h.0[0] >> 4) == n)
            .copied()
            .collect();
        let want = if below.is_empty() {
            SetDigest::EMPTY
        } else {
            SetDigest::leaf(&below)
        };
        assert_eq!(
            *d, want,
            "child {n}: the records whose hash begins with {n:x}"
        );
    }
    assert_eq!(y.root(), reference(&keyed, &Prefix::ROOT));
    out.push(json!({
        "name": "65-records-at-one-tag",
        "digest": h(y.ix.digest(&at).as_bytes()),
        "children": children.iter().map(|d| h(d.as_bytes())).collect::<Vec<_>>(),
    }));
    // A 128-nibble prefix: at most one record, in leaf form.
    let full = Prefix::of_key(&key_at(&tag, &at_tag[7]), 128);
    assert_eq!(y.ix.digest(&full), SetDigest::leaf(&[at_tag[7]]));
    assert_eq!(y.ix.subtree(&full), vec![at_tag[7]]);
    out.push(json!({ "name": "a-128-nibble-prefix", "digest": h(y.ix.digest(&full).as_bytes()) }));
    // A cleanup's key: its record hash twice.
    let c = cleanup(dev(0xd0), T0 + 50, &[(None, vec![RecordHash([0x42; 32])])]);
    y.accept(&c).unwrap();
    let mut ck = [0u8; 64];
    ck[..32].copy_from_slice(&c.hash().0);
    ck[32..].copy_from_slice(&c.hash().0);
    assert_eq!(y.ix.subtree(&Prefix::of_key(&ck, 128)), vec![c.hash()]);
    assert_eq!(
        y.ix.subtree(&Prefix::of_key(&ck, 64)),
        vec![c.hash()],
        "alone at its first half"
    );
    assert_eq!(y.root(), reference(&keys_of(&y), &Prefix::ROOT));
    out.push(json!({ "name": "a-cleanups-key", "key": h(&ck), "root": h(y.root().as_bytes()) }));
    // 8 000 records at one tag held one at a time, then dropped by one
    // cleanup: each change rehashes at most one leaf of at most 64 record
    // hashes (65 when a subtree splits, spread over its new leaves) and at
    // most 128 node-form subtrees, counted, not timed (the coordinator's
    // ruling IS-2: before it, one file ID's leaf was rehashed whole, the
    // square of its history). Held directly, unverified: the cost is the
    // cache's.
    let mut big = Dev::sealed(0xa5);
    let many: Vec<licketysync_keys::records::SignedRecord> = (0..8_000u32)
        .map(|i| {
            let mut m = sealed_file("crowd", dev(0x77), T0 + u64::from(i));
            m.mtime_ns = i64::from(i);
            super::kit::unsigned("crowd", &[chunk(1)], &m, &[])
        })
        .collect();
    let mut worst = crate::trie::Cost::default();
    for (i, r) in many.iter().enumerate() {
        let record = Record::parse(r.clone(), super::kit::write_key().verifier()).unwrap();
        big.ix.s.trie.max_cost = crate::trie::Cost::default();
        big.ix.s.hold(
            crate::state::Held {
                record,
                seq: i as u64 + 1,
                verdict: None,
            },
            None,
        );
        let c = big.ix.s.trie.max_cost;
        assert!(
            c.leaf_records <= RECONCILE_LEAF_MAX + 1 && c.nodes <= 128,
            "{c:?}"
        );
        worst.leaf_records = worst.leaf_records.max(c.leaf_records);
        worst.nodes = worst.nodes.max(c.nodes);
    }
    assert_eq!(big.root(), reference(&keys_of(&big), &Prefix::ROOT));
    let all: Vec<RecordHash> = many
        .iter()
        .map(licketysync_keys::records::SignedRecord::hash)
        .collect();
    let c = cleanup(dev(0xd0), T0 + 9_000, &[(None, all.clone())]);
    big.ix.s.trie.max_cost = crate::trie::Cost::default();
    let a = big.accept(&c).unwrap();
    assert_eq!(a.dropped.len(), 8_000, "one cleanup drops them all");
    let c_cost = big.ix.s.trie.max_cost;
    assert!(
        c_cost.leaf_records <= RECONCILE_LEAF_MAX && c_cost.nodes <= 128,
        "{c_cost:?}"
    );
    assert_eq!(big.root(), SetDigest::leaf(&[c.hash()]));
    out.push(json!({
        "name": "8000-records-at-one-tag",
        "worst_hold": { "leaf_records": worst.leaf_records, "nodes": worst.nodes },
        "worst_drop": { "leaf_records": c_cost.leaf_records, "nodes": c_cost.nodes },
    }));
    // The cache after a record joins and one leaves a leaf.
    let mut z = Dev::sealed(0xa4);
    for r in &records[..3] {
        z.accept(r).unwrap();
    }
    let before = z.root();
    z.accept(&records[3]).unwrap();
    assert_eq!(z.root(), reference(&keys_of(&z), &Prefix::ROOT), "a join");
    let named = cleanup(dev(0xd0), T0 + 100, &[(None, vec![records[3].hash()])]);
    z.accept(&named).unwrap();
    assert!(!z.holds(&records[3].hash()));
    assert_eq!(
        z.root(),
        reference(&keys_of(&z), &Prefix::ROOT),
        "a leave (and the cleanup's join)"
    );
    out.push(json!({ "name": "the-cache-after-a-join-and-a-leave", "before": h(before.as_bytes()), "after": h(z.root().as_bytes()) }));
    // The connection reads the same digests.
    assert_eq!(IndexView::digest(&z.ix, &Prefix::ROOT), z.root());
    json!(out)
}

fn serving() -> Value {
    let mut out = Vec::new();
    let mut a = Dev::writer(0xa0);
    let written: Vec<RecordHash> = (0..70u8).map(|i| a.put(&format!("f{i}"), i)).collect();
    let epoch = a.ix.epoch();
    // A matching epoch and since: the records above it in local-sequence
    // order, each page's through its last record's, the last page's the
    // local sequence when serving began.
    let SincePlan::Pages(mut reply) = a.ix.since_plan(epoch, 3) else {
        panic!()
    };
    let p1 = a.ix.since_page(&mut reply, 7, 64, DEFAULT_MESSAGE_SIZE);
    assert!(p1.more && p1.records.len() == 64 && p1.through == 67);
    let p2 = a.ix.since_page(&mut reply, 7, 64, DEFAULT_MESSAGE_SIZE);
    assert!(!p2.more && p2.records.len() == 3 && p2.through == 70 && reply.is_done());
    let first: Vec<RecordHash> = p1
        .records
        .iter()
        .take(2)
        .map(|r| {
            licketysync_keys::records::SignedRecord::from_bytes(r)
                .unwrap()
                .hash()
        })
        .collect();
    assert_eq!(first, written[3..5].to_vec(), "in local-sequence order");
    out.push(json!({ "name": "since-3-of-70", "pages": [[p1.records.len(), p1.through, p1.more], [p2.records.len(), p2.through, p2.more]] }));
    // Nothing to send: one empty page carrying through.
    let SincePlan::Pages(mut reply) = a.ix.since_plan(epoch, 70) else {
        panic!()
    };
    let p = a.ix.since_page(&mut reply, 8, 64, DEFAULT_MESSAGE_SIZE);
    assert!(p.records.is_empty() && !p.more && p.through == 70);
    out.push(json!({ "name": "nothing-to-send", "through": p.through }));
    // Another epoch, and a since above the local sequence (which draws a new
    // epoch).
    assert_eq!(
        a.ix.since_plan(epoch + 1, 3),
        SincePlan::Reset { redraw: false }
    );
    assert_eq!(
        a.ix.since_plan(epoch, 71),
        SincePlan::Reset { redraw: true }
    );
    out.push(json!({ "name": "resets", "another_epoch": "reset", "since_above_the_local_sequence": "reset and a new epoch" }));
    // A requester holding nothing: RECORDS of every record; one holding one
    // record less at the root's 70: CHILDREN.
    let (reply, records) = a.ix.reconcile_reply(&ReconcileServe {
        request_id: 3,
        prefix: Prefix::ROOT,
        digest: SetDigest::EMPTY,
    });
    assert_eq!(reply.outcome, ReconcileOutcome::Records.as_u32());
    assert_eq!(
        reply.through, 70,
        "the root's reply carries the local sequence"
    );
    let mut rr = records.unwrap();
    let page = a.ix.records_page(&mut rr, 3, DEFAULT_MESSAGE_SIZE);
    assert_eq!(page.records.len(), 70);
    assert!(rr.is_done() && page.through == 0);
    let keys: Vec<_> = page
        .records
        .iter()
        .map(|r| {
            let h = licketysync_keys::records::SignedRecord::from_bytes(r)
                .unwrap()
                .hash();
            a.ix.s.held[&h].record.key()
        })
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "ascending by key");
    let (reply, records) = a.ix.reconcile_reply(&ReconcileServe {
        request_id: 4,
        prefix: Prefix::ROOT,
        digest: SetDigest([1; 32]),
    });
    assert_eq!(reply.outcome, ReconcileOutcome::Children.as_u32());
    assert!(records.is_none());
    assert_eq!(reply.children.len(), 16);
    for (i, c) in reply.children.iter().enumerate() {
        assert_eq!(
            c.as_slice(),
            a.ix.digest(&Prefix::ROOT.child(i as u8).unwrap())
                .as_bytes()
        );
    }
    let (reply, _) = a.ix.reconcile_reply(&ReconcileServe {
        request_id: 5,
        prefix: Prefix::ROOT,
        digest: a.root(),
    });
    assert_eq!(reply.outcome, ReconcileOutcome::Equal.as_u32());
    // A responder holding nothing in a subtree: RECORDS, one empty page.
    let e = Dev::sealed(0xa5);
    let (reply, records) = e.ix.reconcile_reply(&ReconcileServe {
        request_id: 6,
        prefix: Prefix::from_wire(&[3]).unwrap(),
        digest: SetDigest([1; 32]),
    });
    assert_eq!(reply.outcome, ReconcileOutcome::Records.as_u32());
    assert_eq!(reply.through, 0, "not the root");
    let mut rr = records.unwrap();
    let empty = e.ix.records_page(&mut rr, 6, DEFAULT_MESSAGE_SIZE);
    assert!(empty.records.is_empty() && !empty.more);
    out.push(json!({ "name": "reconcile-replies", "zero_digest": "RECORDS of 70", "other_digest": "CHILDREN", "own_digest": "EQUAL", "empty_subtree": "RECORDS, one empty page" }));
    // Pushes: in local-sequence order with through; a reconciliation's
    // pushes carry none.
    let pushes =
        a.ix.push_pages(&[written[5], written[2]], DEFAULT_MESSAGE_SIZE);
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].through, 6);
    let sub =
        a.ix.subtree_pushes(&Prefix::ROOT, Some(&written[..60]), DEFAULT_MESSAGE_SIZE);
    assert_eq!(sub[0].records.len(), 10);
    assert_eq!(sub[0].through, 0);
    out.push(
        json!({ "name": "pushes", "through": pushes[0].through, "reconciliation_through": 0 }),
    );
    json!(out)
}

fn exchange() -> Value {
    let mut out = Vec::new();
    // Two devices with different histories of one path and records each
    // lacks: equal records after the round.
    let mut a = Dev::writer(0xa0);
    let mut b = Dev::writer(0xb0);
    a.put("same", 1);
    b.put("same", 2);
    for i in 0..80u8 {
        if i % 2 == 0 {
            a.put(&format!("a{i}"), i);
        } else {
            b.put(&format!("b{i}"), i);
        }
    }
    let rounds = converge(&mut a, &mut b, 4);
    assert_eq!(a.all(), b.all());
    assert_eq!(a.heads("same").len(), 2, "a conflict, both kept");
    out.push(json!({ "name": "different-histories-converge", "rounds": rounds, "records": a.all().len() }));
    // A sealed peer and a read holder converge on the same digest.
    let mut s = Dev::sealed(0xa2);
    let x = round(&mut s, &mut a);
    assert!(x.caught_up || round(&mut s, &mut a).caught_up);
    assert_eq!(s.root(), a.root());
    out.push(json!({ "name": "a-sealed-peer-converges", "root": h(s.root().as_bytes()) }));
    json!(out)
}

fn local_sequence() -> Value {
    let mut out = Vec::new();
    // A dropped record's number is never given to another.
    let mut a = Dev::writer(0xa0);
    let v1 = a.put("p", 1);
    let n1 = a.ix.record(&v1).unwrap().seq;
    let v2 = a.put("p", 2);
    let n2 = a.ix.record(&v2).unwrap().seq;
    assert!(n2 > n1 && !a.holds(&v1));
    // V3 drops V2, the greatest number held: it still takes the next.
    let v3 = a.put("p", 3);
    assert!(!a.holds(&v2));
    assert_eq!(a.ix.record(&v3).unwrap().seq, n2 + 1);
    // A cleanup takes one too, is pushed with its through and served in a
    // Since reply.
    let c = cleanup(dev(0xd0), T0, &[(None, vec![RecordHash([9; 32])])]);
    let held = a.accept(&c).unwrap();
    let seq = held.seq.unwrap();
    let pushes = a.ix.push_pages(&[c.hash()], DEFAULT_MESSAGE_SIZE);
    assert_eq!(pushes[0].through, seq);
    let SincePlan::Pages(mut reply) = a.ix.since_plan(a.ix.epoch(), seq - 1) else {
        panic!()
    };
    let page = a.ix.since_page(&mut reply, 1, 64, DEFAULT_MESSAGE_SIZE);
    assert_eq!(page.records, vec![c.to_bytes()]);
    out.push(json!({ "name": "numbers-and-a-cleanup", "cleanup_seq": seq }));
    // The next number would pass MAX_LOCAL_SEQ: every record renumbered from
    // 1 in its order, under a new epoch.
    let mut b = Dev::writer(0xb0);
    b.put("x", 1);
    b.put("y", 2);
    let mut meta = b.ix.s.meta;
    meta.next_seq = MAX_LOCAL_SEQ + 1;
    b.ix.s.meta = meta;
    let epoch = b.ix.epoch();
    let z = b.put("z", 3);
    let seqs: Vec<u64> = b.ix.records().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    assert_eq!(b.ix.record(&z).unwrap().seq, 3);
    assert_ne!(b.ix.epoch(), epoch);
    out.push(json!({ "name": "renumbered-past-max-local-seq", "seqs": seqs }));
    json!(out)
}

fn peer_state() -> Value {
    let mut a = Dev::writer(0xa0);
    let mut txn = a.ix.begin();
    txn.round_ended(dev(1), true, Some((5, 9)), T0);
    txn.cursor_advanced(dev(1), 5, 12);
    txn.cursor_advanced(dev(1), 6, 99);
    txn.finish().1.commit();
    let p = *a.ix.peer(&dev(1)).unwrap();
    assert_eq!(
        (p.epoch, p.cursor, p.caught_up),
        (5, 12, true),
        "another epoch's push moves nothing"
    );
    // Dropped after PEER_STATE_HORIZON without a round.
    let mut txn = a.ix.begin();
    txn.round_ended(dev(2), false, None, T0 + PEER_STATE_HORIZON + 1);
    txn.finish().1.commit();
    assert!(a.ix.peer(&dev(1)).is_none(), "past the horizon");
    // The 4 097th evicts the one longest without a round.
    let mut b = Dev::writer(0xb0);
    let mut txn = b.ix.begin();
    for i in 0..MAX_PEER_STATES {
        let mut d = [0u8; 32];
        d[..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        txn.round_ended(
            licketysync_keys::DeviceId(d),
            true,
            Some((1, 1)),
            T0 + i as u64,
        );
    }
    txn.round_ended(dev(0xff), true, Some((1, 1)), T0 + DAY);
    let (changes, pending) = txn.finish();
    pending.commit();
    assert_eq!(b.ix.s.peers.len(), MAX_PEER_STATES);
    assert!(
        b.ix.peer(&licketysync_keys::DeviceId([0; 32])).is_none(),
        "the oldest evicted"
    );
    assert!(b.ix.peer(&dev(0xff)).is_some());
    assert_eq!(
        changes.peers.len(),
        MAX_PEER_STATES,
        "one state set per peer kept, the evicted one gone"
    );
    json!({ "cursor_after_pushes": p.cursor, "kept": MAX_PEER_STATES })
}

#[test]
fn vector_digests() {
    check(
        "digests",
        &json!({
            "description": "protocol.md 8 item 8, the index's part: set digests and their cache, serving IndexRequests and ReconcileRequests from committed state, pushes, two indexes reconciled through those replies, local sequence numbers and per-peer state; records of the keys crate's fixed folder written at T0 or forged with fixed nonces.",
            "digests": digests(),
            "serving": serving(),
            "exchange": exchange(),
            "local_sequence": local_sequence(),
            "peer_state": peer_state(),
        }),
    );
}

#[test]
fn a_since_reply_with_nothing_to_send_is_one_empty_page() {
    // Found by this suite: a `since` at the local sequence (0 on an empty
    // index, or a peer that is caught up) made the reply's range start past
    // its end, which panics.
    let mut a = Dev::writer(0xa0);
    let SincePlan::Pages(mut reply) = a.ix.since_plan(a.ix.epoch(), 0) else {
        panic!()
    };
    let p = a.ix.since_page(&mut reply, 1, 64, DEFAULT_MESSAGE_SIZE);
    assert!(p.records.is_empty() && !p.more && reply.is_done());
    assert_eq!(p.through, 0);
    a.put("x", 1);
    let SincePlan::Pages(mut reply) = a.ix.since_plan(a.ix.epoch(), 1) else {
        panic!()
    };
    let p = a.ix.since_page(&mut reply, 2, 64, DEFAULT_MESSAGE_SIZE);
    assert_eq!((p.records.len(), p.through), (0, 1));
}

/// A counted push for a peer without per-peer state creates none, whatever
/// its epoch and `through` (4.5, "Per-peer state" and "Cursors": the cursor
/// and its epoch come from a round's end, and pushes move it on from there),
/// so at `MAX_PEER_STATES` it evicts no peer's state (TM-22). Before, a push
/// of epoch 0, which the wire refuses, made `{epoch 0, cursor through}`.
#[test]
fn a_counted_push_for_a_peer_without_state_creates_none_whatever_its_epoch() {
    let mut a = Dev::writer(0xa0);
    for epoch in [0, 1, 5, u64::MAX] {
        for through in [0, 1, 12, MAX_LOCAL_SEQ] {
            let mut txn = a.ix.begin();
            txn.cursor_advanced(dev(1), epoch, through);
            let (changes, pending) = txn.finish();
            assert!(changes.is_empty(), "epoch {epoch}, through {through}");
            pending.commit();
            assert!(
                a.ix.peer(&dev(1)).is_none(),
                "epoch {epoch}, through {through}"
            );
        }
    }
    // At the cap.
    let mut txn = a.ix.begin();
    for i in 0..MAX_PEER_STATES {
        let mut d = [0u8; 32];
        d[..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        txn.round_ended(
            licketysync_keys::DeviceId(d),
            true,
            Some((1, 1)),
            T0 + i as u64,
        );
    }
    txn.finish().1.commit();
    let before = a.ix.s.peers.clone();
    let mut txn = a.ix.begin();
    txn.cursor_advanced(dev(0xff), 0, 5);
    txn.cursor_advanced(dev(0xff), 1, 5);
    let (changes, pending) = txn.finish();
    assert!(changes.is_empty());
    pending.commit();
    assert_eq!(a.ix.s.peers, before, "none made, none evicted");
}

/// A counted push raises the cursor held for its epoch to its `through`,
/// and never lowers it; a push of another epoch moves nothing (4.5,
/// "Cursors").
#[test]
fn a_counted_push_raises_the_cursor_of_its_epoch_and_never_lowers_it() {
    let mut a = Dev::writer(0xa0);
    let mut txn = a.ix.begin();
    txn.round_ended(dev(1), true, Some((5, 9)), T0);
    txn.finish().1.commit();
    let state = *a.ix.peer(&dev(1)).unwrap();
    for (epoch, through) in [(5, 0), (5, 3), (5, 9), (4, 99), (6, 99), (0, 99)] {
        let mut txn = a.ix.begin();
        txn.cursor_advanced(dev(1), epoch, through);
        let (changes, pending) = txn.finish();
        assert!(changes.is_empty(), "epoch {epoch}, through {through}");
        pending.commit();
        assert_eq!(a.ix.peer(&dev(1)), Some(&state));
    }
    let mut txn = a.ix.begin();
    txn.cursor_advanced(dev(1), 5, 12);
    let (changes, pending) = txn.finish();
    let raised = crate::PeerState {
        cursor: 12,
        ..state
    };
    assert_eq!(changes.peers, vec![(dev(1), Some(raised))]);
    pending.commit();
    assert_eq!(a.ix.peer(&dev(1)), Some(&raised));
}

#[test]
fn a_record_parsed_has_its_key_in_the_digests() {
    let r = spread(1).pop().unwrap();
    let rec = Record::parse(r.clone(), super::kit::write_key().verifier()).unwrap();
    let mut x = Dev::sealed(0xa2);
    x.accept(&r).unwrap();
    let full = Prefix::of_key(&rec.key(), 128);
    assert_eq!(x.ix.subtree(&full), vec![r.hash()]);
    let tag = Prefix::of_key(&rec.key(), 64);
    assert_eq!(x.ix.subtree(&tag), vec![r.hash()]);
}

proptest! {
    #![proptest_config(super::proptest_config(24))]

    /// (m) the cache equals a digest computed from nothing but 4.5, after any
    /// sequence of records joining and leaving (some at one tag, so that the
    /// subtree beneath that tag passes 64 and splits by record-hash
    /// nibbles), at every prefix asked for; and a failed transaction leaves
    /// it as it was.
    #[test]
    fn the_cache_is_the_digest_m(ops in proptest::collection::vec((0u8..80, any::<bool>()), 1..120)) {
        let mut x = Dev::sealed(0xa2);
        let mut by_id: BTreeMap<u8, licketysync_keys::records::SignedRecord> = BTreeMap::new();
        for (id, keep) in ops {
            let r = by_id.entry(id).or_insert_with(|| {
                let p = if id < 40 { format!("p{id}") } else { "crowd".to_string() };
                let mut m = sealed_file(&p, dev(id), T0 + u64::from(id));
                m.plain_hashes = vec![vec![id; 32]];
                forge(&p, &[chunk(id)], &m, &[])
            }).clone();
            if keep {
                x.accept(&r).unwrap();
            } else if x.holds(&r.hash()) {
                let c = cleanup(dev(0xd0), T0 + 1_000 + u64::from(id), &[(None, vec![r.hash()])]);
                x.accept(&c).unwrap();
            }
            let keyed = keys_of(&x);
            prop_assert_eq!(x.root(), reference(&keyed, &Prefix::ROOT));
            let crowd = Prefix::of_key(&key_at(&super::kit::tag("crowd"), &RecordHash([0; 32])), 64);
            prop_assert_eq!(x.ix.digest(&crowd), reference(&keyed, &crowd));
            for i in 0..16u8 {
                let p = crowd.child(i).unwrap();
                prop_assert_eq!(x.ix.digest(&p), reference(&keyed, &p));
            }
            for i in 0..16u8 {
                let p = Prefix::ROOT.child(i).unwrap();
                prop_assert_eq!(x.ix.digest(&p), reference(&keyed, &p));
            }
        }
        let before = x.root();
        {
            let mut txn = x.ix.begin();
            let mut fill = |b: &mut [u8]| b.fill(1);
            let mut mem = licketysync_protocol::connection::FolderMemory::default();
            let r = spread(1).pop().unwrap();
            let rec = Record::parse(r, super::kit::write_key().verifier()).unwrap();
            let mut notes = licketysync_protocol::connection::NoteBudget::for_tests();
            let mut arrival = crate::Arrival { peer: dev(1), memory: &mut mem, notes: &mut notes, clock_us: T0, rng: &mut fill };
            let _ = txn.accept(rec, &mut arrival);
            // Dropped: undone.
        }
        prop_assert_eq!(x.root(), before);
        prop_assert_eq!(x.root(), reference(&keys_of(&x), &Prefix::ROOT));
    }
}

/// `n` records held at a sealed holder without signing or verifying them
/// (a sealed holder opens nothing), each at its own tag: the shape of a big
/// folder, cheap to build in a debug build.
fn held_unsigned(d: &mut Dev, n: u32) -> Vec<RecordHash> {
    use prost::Message as _;
    let base = forge("x", &[chunk(1)], &sealed_file("x", dev(0xd0), T0), &[]);
    let body = licketysync_protocol::messages::IndexRecord::decode(base.body()).unwrap();
    let mut out = Vec::new();
    for i in 0..n {
        let mut b = body.clone();
        let mut tag = [0u8; 32];
        tag[..4].copy_from_slice(&i.wrapping_mul(2_654_435_761).to_be_bytes());
        tag[4..8].copy_from_slice(&i.to_be_bytes());
        b.path_tag = tag.to_vec();
        let mut env = Vec::new();
        prost::encoding::bytes::encode(1, &b.encode_to_vec(), &mut env);
        prost::encoding::bytes::encode(2, &vec![0x5a; 64], &mut env);
        let signed = licketysync_keys::records::SignedRecord::from_bytes(&env).unwrap();
        let record = Record::parse(signed, super::kit::write_key().verifier()).unwrap();
        out.push(record.hash());
        d.ix.s.hold(
            crate::state::Held {
                record,
                seq: u64::from(i) + 1,
                verdict: None,
            },
            None,
        );
    }
    out
}

/// Every page of a `RECORDS` reply of the subtree at `prefix` at
/// `max_message_size`: the records sent, the pages, and the keys read.
fn serve_records(
    d: &Dev,
    prefix: Prefix,
    max_message_size: u32,
) -> (Vec<RecordHash>, usize, usize) {
    let (reply, records) =
        d.ix.reconcile_reply(&licketysync_protocol::connection::ReconcileServe {
            request_id: 3,
            prefix,
            digest: SetDigest::EMPTY,
        });
    assert_eq!(reply.outcome, ReconcileOutcome::Records.as_u32());
    let mut records = records.unwrap();
    let _ = d.ix.s.trie.read.take();
    let mut sent = Vec::new();
    let mut pages = 0;
    while !records.is_done() {
        let page = d.ix.records_page(&mut records, 3, max_message_size);
        pages += 1;
        assert!(
            pages <= d.ix.len() + 1,
            "every page but the last sends a record: the reply ends"
        );
        sent.extend(page.records.iter().map(|r| {
            licketysync_keys::records::SignedRecord::from_bytes(r)
                .unwrap()
                .hash()
        }));
    }
    (sent, pages, d.ix.s.trie.read.take())
}

/// A `RECORDS` reply pages its subtree in ascending key order from the last
/// key sent (the spec's fifteenth fixup; the coordinator's ruling CR-1): at
/// the root and at every 1-, 2- and 3-nibble prefix that holds a record, with
/// pages of one record and of the default size, every record of the subtree
/// is sent once, in key order, and a page reads only the keys it sends and
/// the one that did not fit, never the records held beside its subtree,
/// never the subtree again (the R1 review's IR-5 and CR2-1, its
/// `probe_records_paths_at_prefixes_and_pages`).
#[test]
fn a_records_reply_pages_its_subtree_by_key_cr1() {
    let mut d = Dev::sealed(0xa2);
    let all = held_unsigned(&mut d, 400);
    let key = |h: &RecordHash| d.ix.s.held[h].record.key();
    let one_record = {
        let r = d.ix.s.held[&all[0]].record.signed();
        u32::try_from(
            licketysync_protocol::exchange::PAGE_FIXED_OVERHEAD
                + licketysync_protocol::exchange::encoded_record_len(r),
        )
        .unwrap()
    };
    let mut prefixes = vec![Prefix::ROOT];
    for depth in [1usize, 2, 3] {
        let mut at: Vec<Prefix> = all.iter().map(|h| Prefix::of_key(&key(h), depth)).collect();
        at.sort();
        at.dedup();
        prefixes.extend(at);
    }
    for prefix in prefixes {
        let mut want: Vec<RecordHash> = all
            .iter()
            .copied()
            .filter(|h| prefix.contains(&key(h)))
            .collect();
        want.sort_by_key(|h| key(h));
        for size in [one_record, DEFAULT_MESSAGE_SIZE] {
            let (sent, pages, read) = serve_records(&d, prefix, size);
            assert_eq!(
                sent, want,
                "{prefix:?} at {size}: its records, in key order"
            );
            if size == one_record {
                assert_eq!(pages, want.len().max(1), "{prefix:?}: one record a page");
            }
            assert!(
                read <= sent.len() + pages,
                "{prefix:?} at {size}: read {read} for {} sent in {pages} pages",
                sent.len()
            );
        }
    }
}

/// The same in a large index: the root (more than two pages) and a deep and a
/// one-nibble prefix read only their records, plus one key a page.
#[test]
fn a_records_reply_reads_only_its_subtree_ir5() {
    let mut d = Dev::sealed(0xa2);
    let n = 9_000;
    let all = held_unsigned(&mut d, n);
    let key = |h: &RecordHash| d.ix.s.held[h].record.key();
    for (depth, min_pages) in [(0usize, 3usize), (3, 1), (1, 1)] {
        let prefix = Prefix::of_key(&key(&all[0]), depth);
        let mut want: Vec<RecordHash> = all
            .iter()
            .copied()
            .filter(|h| prefix.contains(&key(h)))
            .collect();
        want.sort_by_key(|h| key(h));
        let (sent, pages, read) = serve_records(&d, prefix, DEFAULT_MESSAGE_SIZE);
        assert!(pages >= min_pages, "depth {depth}: {pages} pages");
        assert_eq!(sent, want, "depth {depth}");
        assert!(
            read <= want.len() + pages,
            "depth {depth}: read {read} for {} of {n}",
            want.len()
        );
    }
}

/// `RECORDS` paging by key over records that share file IDs (keys differing
/// only in the record-hash half) and cleanups (keys of their hash twice), at
/// prefixes above, at and beneath 64 nibbles and at full keys, at pages of
/// one record and of the default size, with records held and dropped between
/// pages: every record of the subtree that is held throughout is sent exactly
/// once, in key order, nothing outside the subtree, nothing twice. A key
/// range that left out its own first or last key sent nothing for a
/// 128-nibble prefix, and no other test showed it (the final review's FC-2).
#[test]
fn records_by_key_over_shared_tags_cleanups_and_changes_fc2() {
    use prost::Message as _;
    let mut d = Dev::sealed(0xa2);
    // 6 file IDs, 40 records each (one tag, many hashes), held directly.
    let base = forge("x", &[chunk(1)], &sealed_file("x", dev(0xd0), T0), &[]);
    let body = licketysync_protocol::messages::IndexRecord::decode(base.body()).unwrap();
    let mut n = 0u32;
    let hold = |d: &mut Dev, tag: [u8; 32], i: u32| {
        let mut b = body.clone();
        b.path_tag = tag.to_vec();
        b.chunks[0].cipher_hash = {
            let mut c = vec![0u8; 32];
            c[..4].copy_from_slice(&i.to_be_bytes());
            c
        };
        let mut env = Vec::new();
        prost::encoding::bytes::encode(1, &b.encode_to_vec(), &mut env);
        prost::encoding::bytes::encode(2, &vec![0x5a; 64], &mut env);
        let signed = licketysync_keys::records::SignedRecord::from_bytes(&env).unwrap();
        let record = Record::parse(signed, super::kit::write_key().verifier()).unwrap();
        let h = record.hash();
        d.ix.s.hold(
            crate::state::Held {
                record,
                seq: u64::from(i) + 1,
                verdict: None,
            },
            None,
        );
        h
    };
    let mut all = Vec::new();
    for t in 0..6u8 {
        let mut tag = [0u8; 32];
        tag[0] = 0x30 + t / 2; // tags share their first nibble in pairs
        tag[1] = t;
        for _ in 0..40 {
            all.push(hold(&mut d, tag, n));
            n += 1;
        }
    }
    // A few cleanups, held directly too.
    for i in 0..10u8 {
        let c = cleanup(
            dev(0xd0),
            T0 + u64::from(i),
            &[(None, vec![RecordHash([i; 32])])],
        );
        let record = Record::parse(c, super::kit::write_key().verifier()).unwrap();
        all.push(record.hash());
        d.ix.s.hold(
            crate::state::Held {
                record,
                seq: 10_000 + u64::from(i),
                verdict: None,
            },
            None,
        );
    }
    let key = |d: &Dev, h: &RecordHash| d.ix.s.held[h].record.key();
    let one = {
        let r = d.ix.s.held[&all[0]].record.signed();
        u32::try_from(
            licketysync_protocol::exchange::PAGE_FIXED_OVERHEAD
                + licketysync_protocol::exchange::encoded_record_len(r),
        )
        .unwrap()
    };
    let mut prefixes = vec![Prefix::ROOT];
    for h in &all {
        for depth in [1usize, 2, 3, 63, 64, 65, 66, 127, 128] {
            prefixes.push(Prefix::of_key(&key(&d, h), depth));
        }
    }
    prefixes.sort();
    prefixes.dedup();
    for prefix in &prefixes {
        let mut want: Vec<RecordHash> = all
            .iter()
            .copied()
            .filter(|h| prefix.contains(&key(&d, h)))
            .collect();
        want.sort_by_key(|h| key(&d, h));
        for size in [one, DEFAULT_MESSAGE_SIZE] {
            let (sent, _, _) = serve_records(&d, *prefix, size);
            assert_eq!(sent, want, "{prefix:?} at {size}");
        }
    }
    // Changes between pages: drop every third record not yet sent, and hold
    // new ones after and before the position; each held throughout is sent
    // once, nothing outside the subtree, nothing twice.
    let prefix = Prefix::of_key(&key(&d, &all[0]), 1);
    let (reply, records) =
        d.ix.reconcile_reply(&licketysync_protocol::connection::ReconcileServe {
            request_id: 3,
            prefix,
            digest: SetDigest::EMPTY,
        });
    assert_eq!(reply.outcome, ReconcileOutcome::Records.as_u32());
    let mut records = records.unwrap();
    let mut sent: Vec<RecordHash> = Vec::new();
    let mut dropped = std::collections::BTreeSet::new();
    let mut round = 0u32;
    while !records.is_done() {
        let page = d.ix.records_page(&mut records, 3, one);
        // One record a page, and one record held every third page.
        assert!(round as usize <= 2 * all.len() + 2, "the reply ends");
        sent.extend(page.records.iter().map(|r| {
            licketysync_keys::records::SignedRecord::from_bytes(r)
                .unwrap()
                .hash()
        }));
        round += 1;
        if round.is_multiple_of(3) {
            let in_sub: Vec<RecordHash> =
                d.ix.s
                    .held
                    .keys()
                    .copied()
                    .filter(|h| prefix.contains(&key(&d, h)) && !sent.contains(h))
                    .collect();
            if let Some(h) = in_sub.get(1) {
                d.ix.s.unhold(h, None);
                dropped.insert(*h);
            }
            let mut tag = [0u8; 32];
            tag[0] = 0x30;
            tag[1] = 0x99;
            hold(&mut d, tag, 50_000 + round);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for h in &sent {
        assert!(seen.insert(*h), "sent twice");
        assert!(!dropped.contains(h), "a dropped record sent");
        assert!(
            d.ix.s
                .held
                .get(h)
                .is_none_or(|r| prefix.contains(&r.record.key())),
            "outside the subtree"
        );
    }
    for h in all
        .iter()
        .filter(|h| !dropped.contains(h) && prefix.contains(&key(&d, h)))
    {
        assert!(seen.contains(h), "a record held throughout not sent");
    }
    let keys: Vec<_> = sent
        .iter()
        .filter_map(|h| d.ix.s.held.get(h).map(|r| r.record.key()))
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "key order");
}

/// A reconciliation's pushes after a `RECORDS` reply carry only the
/// subtree's records, at prefixes of 1, 2, 64 and 128 nibbles: pushes read
/// from the root sent the whole folder, and no other test showed it (the
/// final review's FC-2).
#[test]
fn subtree_pushes_stay_in_their_subtree_fc2() {
    let mut d = Dev::sealed(0xa2);
    let all = held_unsigned(&mut d, 300);
    let key = |h: &RecordHash| d.ix.s.held[h].record.key();
    for depth in [1usize, 2, 64, 128] {
        let prefix = Prefix::of_key(&key(&all[7]), depth);
        let mut want: Vec<RecordHash> = all
            .iter()
            .copied()
            .filter(|h| prefix.contains(&key(h)))
            .collect();
        want.sort();
        let mut got: Vec<RecordHash> =
            d.ix.subtree_pushes(&prefix, None, DEFAULT_MESSAGE_SIZE)
                .iter()
                .flat_map(|p| {
                    p.records.iter().map(|r| {
                        licketysync_keys::records::SignedRecord::from_bytes(r)
                            .unwrap()
                            .hash()
                    })
                })
                .collect();
        got.sort();
        assert_eq!(got, want, "depth {depth}");
    }
}

/// `n` records held at a sealed holder at the one file ID `tag`, without
/// signing or verifying them: keys that differ only in their record hash.
fn held_at_one_tag(d: &mut Dev, tag: [u8; 32], n: u32) -> Vec<RecordHash> {
    use prost::Message as _;
    let base = forge("x", &[chunk(1)], &sealed_file("x", dev(0xd0), T0), &[]);
    let body = licketysync_protocol::messages::IndexRecord::decode(base.body()).unwrap();
    let mut out = Vec::new();
    for i in 0..n {
        let mut b = body.clone();
        b.path_tag = tag.to_vec();
        let mut cipher = vec![0u8; 32];
        cipher[..4].copy_from_slice(&i.to_be_bytes());
        b.chunks[0].cipher_hash = cipher;
        let mut env = Vec::new();
        prost::encoding::bytes::encode(1, &b.encode_to_vec(), &mut env);
        prost::encoding::bytes::encode(2, &vec![0x5a; 64], &mut env);
        let signed = licketysync_keys::records::SignedRecord::from_bytes(&env).unwrap();
        let record = Record::parse(signed, super::kit::write_key().verifier()).unwrap();
        out.push(record.hash());
        d.ix.s.hold(
            crate::state::Held {
                record,
                seq: u64::from(i) + 1,
                verdict: None,
            },
            None,
        );
    }
    out
}

/// `protocol.md` 8 item 8's `RECORDS` reply over more than one page at a
/// file ID holding many records (the spec's fifteenth fixup): 300 records at
/// one tag, served over pages of one record each at the tag's 64-nibble
/// prefix and at each of its 65-nibble children (split by the first nibble
/// of the record hash). Every page sends one record, in ascending key order,
/// each once and nothing else; between pages the reply keeps only the last
/// key sent (its state is the prefix, that key and whether it is done); and
/// a page reads the key it sends and the one that did not fit.
#[test]
fn records_pages_at_one_file_id_of_hundreds_go_by_key_fixup15() {
    let mut d = Dev::sealed(0xa2);
    let mut tag = [0u8; 32];
    tag[0] = 0x6b;
    tag[31] = 0x01;
    let all = held_at_one_tag(&mut d, tag, 300);
    // A record at another tag beside it, which no page may carry.
    let other = held_unsigned(&mut d, 1);
    let key = |h: &RecordHash| d.ix.s.held[h].record.key();
    let tag_prefix = Prefix::of_key(&key(&all[0]), 64);
    assert!(all.iter().all(|h| tag_prefix.contains(&key(h))));
    assert!(!tag_prefix.contains(&key(&other[0])));
    assert!(
        d.ix.s.trie.count(&tag_prefix) > RECONCILE_LEAF_MAX,
        "node form at the tag"
    );
    let one = {
        let r = d.ix.s.held[&all[0]].record.signed();
        u32::try_from(
            licketysync_protocol::exchange::PAGE_FIXED_OVERHEAD
                + licketysync_protocol::exchange::encoded_record_len(r),
        )
        .unwrap()
    };
    // The packed prefix (65 bytes), the last key sent (64 and its tag) and
    // done: no list of records.
    assert!(
        core::mem::size_of::<crate::serve::RecordsReply>() <= 65 + 65 + 1,
        "the prefix, the last key and done"
    );
    let mut prefixes = vec![tag_prefix];
    prefixes.extend((0..16u8).filter_map(|n| tag_prefix.child(n)));
    let mut across_children = 0;
    for prefix in &prefixes {
        let mut want: Vec<RecordHash> = all
            .iter()
            .copied()
            .filter(|h| prefix.contains(&key(h)))
            .collect();
        want.sort_by_key(|h| key(h));
        if prefix.depth() == 65 {
            across_children += want.len();
        }
        let (sent, pages, read) = serve_records(&d, *prefix, one);
        assert_eq!(sent, want, "{prefix:?}: every record once, by key");
        assert_eq!(pages, want.len().max(1), "{prefix:?}: one record a page");
        assert!(
            read <= 2 * pages,
            "{prefix:?}: {read} keys read over {pages} pages"
        );
    }
    assert_eq!(across_children, all.len(), "the children split the tag");
}
