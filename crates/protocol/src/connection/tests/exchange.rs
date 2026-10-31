// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index exchange on one connection (4.5): rounds, Since and resets, the
//! Check and the passes, quiet, cut and skipped passes, the descent and its
//! work list, every sender violation of a reconcile reply, pushes, counting
//! and the round owed, one request at a time across both kinds, the serving
//! interval for `IndexRequest`s and root `ReconcileRequest`s only, and the
//! reply deadline. The other side runs the testkit's reference engine over a
//! toy index, or is scripted by hand.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::panic,
    clippy::unchecked_time_subtraction,
    clippy::doc_markdown,
    clippy::type_complexity,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "test code"
)]

use core::time::Duration;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, FolderId, SetDigest};
use proptest::prelude::*;

use crate::connection::{Config, Event, Judgement, Page, SendError, Side as Who, State, Tick};
use crate::exchange::{Pager, Prefix};
use crate::limits::{
    MAX_LOCAL_SEQ, MAX_PAGE_RECORDS, MAX_PASS_REQUESTS, MAX_RECONCILE_PASSES, MAX_SEND_QUEUE,
    MAX_WORK_LIST, RECONCILE_LEAF_MAX,
};
use crate::messages::{
    CloseReason, IndexRecords, IndexRequest, Message, ReconcileOutcome, ReconcileReply,
    ReconcileRequest,
};
use crate::parse::Parse;
use crate::rules::Cause;
use crate::testkit::{device, folder, s, signed, Pair, Part, Side};

fn bodies(side: &Side, t: u16) -> Vec<Vec<u8>> {
    side.sent
        .iter()
        .filter(|(_, f)| f[4..6] == t.to_be_bytes())
        .map(|(_, f)| f[6..].to_vec())
        .collect()
}

fn index_requests(side: &Side) -> Vec<IndexRequest> {
    bodies(side, 0x8007)
        .iter()
        .map(|b| IndexRequest::parse(b).unwrap())
        .collect()
}

fn pages(side: &Side) -> Vec<IndexRecords> {
    bodies(side, 0x8008)
        .iter()
        .map(|b| IndexRecords::parse(b).unwrap())
        .collect()
}

fn reconciles(side: &Side) -> Vec<ReconcileRequest> {
    bodies(side, 0x800B)
        .iter()
        .map(|b| ReconcileRequest::parse(b).unwrap())
        .collect()
}

fn replies(side: &Side) -> Vec<ReconcileReply> {
    bodies(side, 0x800C)
        .iter()
        .map(|b| ReconcileReply::parse(b).unwrap())
        .collect()
}

fn closed(side: &Side) -> Option<(CloseReason, Option<Cause>)> {
    side.events.iter().find_map(|e| match e {
        Event::Closed {
            reason,
            by: Who::Local,
            cause,
            ..
        } => Some((*reason, *cause)),
        _ => None,
    })
}

/// The rounds a side completed: caught up, and the cursor set.
fn rounds(side: &Side) -> Vec<(bool, Option<(u64, u64)>)> {
    side.events
        .iter()
        .filter_map(|e| match e {
            Event::RoundCompleted {
                caught_up, cursor, ..
            } => Some((*caught_up, *cursor)),
            _ => None,
        })
        .collect()
}

/// The cursors a side was told to persist after counted pushes.
fn advanced(side: &Side) -> Vec<(u64, u64)> {
    side.events
        .iter()
        .filter_map(|e| match e {
            Event::CursorAdvanced { epoch, through, .. } => Some((*epoch, *through)),
            _ => None,
        })
        .collect()
}

/// Records of writer `w` at counters `1..=n`, salt `salt`.
fn records(w: u8, n: u64, salt: u8) -> Vec<SignedRecord> {
    let key = folder(0x10);
    (1..=n).map(|c| signed(&key, w, c, salt)).collect()
}

fn frame(m: &Message) -> Vec<u8> {
    m.to_frame().unwrap().encode()
}

/// An empty push of `epoch`: the peer dropped pushes, this side owes a round.
fn empty_push(f: &FolderId, epoch: u64) -> Vec<u8> {
    frame(&Message::IndexRecords(IndexRecords {
        folder_id: f.0.to_vec(),
        epoch,
        ..IndexRecords::default()
    }))
}

/// A pair set up by `setup` before the folder opens, opened, its rounds on
/// open run (the serving interval let pass); B configured by `config_b`.
fn open_with(setup: impl FnOnce(&mut Pair), config_b: impl FnOnce(&mut Config)) -> Pair {
    let key = || licketysync_keys::folder::FolderKey::from(folder(0x10));
    let mut p = Pair::with(0xa0, 0xb0, &[key()], &[key()], |_| {}, config_b);
    setup(&mut p);
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    p.advance(s(10));
    p
}

/// A pair whose sides start with these records, then open.
fn pair_with(a: &[SignedRecord], b: &[SignedRecord]) -> Pair {
    let v = *folder(0x10).verifier();
    open_with(
        |p| {
            for r in a {
                p.a.store.insert_signed(r, &v);
            }
            for r in b {
                p.b.store.insert_signed(r, &v);
            }
        },
        |_| {},
    )
}

fn device_a() -> DeviceId {
    device(0xa0).0.device_id()
}

/// The request A was handed to serve last, of either kind.
fn last_serve(side: &Side) -> Option<Event> {
    side.events
        .iter()
        .rev()
        .find(|e| matches!(e, Event::ServeIndex { .. } | Event::ServeReconcile { .. }))
        .cloned()
}

/// A scripted reply part from A (auto off): sends it and delivers until
/// nothing moves (no time passes).
fn a_sends(p: &mut Pair, part: Part) {
    p.a.replies.push_back(part);
    p.a.serve_replies(p.now);
    p.settle();
}

fn children_reply(f: &FolderId, request_id: u32, epoch: u64, digests: &[SetDigest; 16]) -> Part {
    Part::Reconcile(ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id,
        outcome: ReconcileOutcome::Children.as_u32(),
        children: digests.iter().map(|d| d.0.to_vec()).collect(),
        epoch,
        through: 0,
    })
}

fn outcome_reply(
    f: &FolderId,
    request_id: u32,
    epoch: u64,
    outcome: ReconcileOutcome,
    through: u64,
) -> Part {
    Part::Reconcile(ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id,
        outcome: outcome.as_u32(),
        children: vec![],
        epoch,
        through,
    })
}

fn records_page(f: &FolderId, request_id: u32, epoch: u64, records: &[SignedRecord]) -> Part {
    let mut pager = Pager::new(MAX_PAGE_RECORDS, 64 << 20);
    for r in records {
        assert!(pager.push(r).unwrap());
    }
    Part::Page(pager.page(f, request_id, false, epoch, 0))
}

/// Digests that differ from any real one, the empty one included: a liar's.
fn lies(seed: u8) -> [SetDigest; 16] {
    core::array::from_fn(|i| {
        let mut d = [0xa5; 32];
        d[0] = seed;
        d[1] = i as u8;
        SetDigest(d)
    })
}

#[test]
fn the_first_round_reconciles_both_ways() {
    let p = pair_with(&records(1, 3, 1), &records(2, 2, 1));
    assert_eq!(p.a.store.len(), 5);
    assert_eq!(p.a.store.all(), p.b.store.all());
    for side in [&p.a, &p.b] {
        assert!(index_requests(side).is_empty(), "no state: no Since");
        assert!(reconciles(side)[0].prefix.is_empty(), "the Check first");
        let r = rounds(side);
        assert_eq!(r.len(), 1);
        assert!(r[0].0, "caught up");
    }
    // B's cursor is A's epoch and the through of A's first root reply.
    let first_root = replies(&p.a)
        .into_iter()
        .find(|r| r.request_id == reconciles(&p.b)[0].request_id)
        .unwrap();
    assert_eq!(first_root.through, 3, "A held 3 when it answered");
    assert_eq!(rounds(&p.b)[0].1, Some((p.a.store.epoch, 3)));
    assert_eq!(p.b.store.peers[&device_a()], (p.a.store.epoch, 3));
    // A pushed what B's RECORDS reply lacked, with through 0.
    assert!(pages(&p.a)
        .iter()
        .any(|pg| pg.request_id == 0 && pg.through == 0 && pg.records.len() == 3));
}

#[test]
fn a_round_with_state_asks_since_then_checks() {
    let all = records(1, 5, 1);
    let v = *folder(0x10).verifier();
    let p = open_with(
        |p| {
            for r in &all {
                p.a.store.insert_signed(r, &v);
            }
            for r in &all[..3] {
                p.b.store.insert_signed(r, &v);
            }
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 3));
        },
        |_| {},
    );
    let epoch = p.a.store.epoch;
    let since = index_requests(&p.b);
    assert_eq!(since.len(), 1);
    assert_eq!((since[0].epoch, since[0].since), (epoch, 3));
    let reply: Vec<IndexRecords> = pages(&p.a)
        .into_iter()
        .filter(|pg| pg.request_id == since[0].request_id)
        .collect();
    assert_eq!(reply.len(), 1);
    assert_eq!((reply[0].records.len(), reply[0].through), (2, 5));
    // The Check after it: EQUAL, the round caught up at the Since cursor.
    let check = reconciles(&p.b);
    assert_eq!(check.len(), 1);
    assert!(check[0].prefix.is_empty());
    let answer = replies(&p.a)
        .into_iter()
        .find(|r| r.request_id == check[0].request_id)
        .unwrap();
    assert_eq!(answer.outcome, ReconcileOutcome::Equal.as_u32());
    assert_eq!(rounds(&p.b), vec![(true, Some((epoch, 5)))]);
    assert_eq!(p.b.store.len(), 5);
}

#[test]
fn a_reconnection_from_the_counted_cursor_is_sent_nothing_it_held() {
    let all = records(1, 4, 1);
    let v = *folder(0x10).verifier();
    let p = open_with(
        |p| {
            for r in &all {
                p.a.store.insert_signed(r, &v);
                p.b.store.insert_signed(r, &v);
            }
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 4));
        },
        |_| {},
    );
    let since = index_requests(&p.b);
    let reply: Vec<IndexRecords> = pages(&p.a)
        .into_iter()
        .filter(|pg| pg.request_id == since[0].request_id)
        .collect();
    assert_eq!(reply.len(), 1, "one empty page");
    assert!(reply[0].records.is_empty());
    assert_eq!(reply[0].through, 4, "carrying the local sequence");
}

#[test]
fn a_reset_for_another_epoch_and_a_since_above_the_local_sequence() {
    let all = records(1, 3, 1);
    let v = *folder(0x10).verifier();
    // Another epoch: one reset page, no new epoch; the round reconciles.
    let p = open_with(
        |p| {
            for r in &all {
                p.a.store.insert_signed(r, &v);
            }
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch + 1, 2));
        },
        |_| {},
    );
    let since = index_requests(&p.b);
    let reset: Vec<IndexRecords> = pages(&p.a)
        .into_iter()
        .filter(|pg| pg.request_id == since[0].request_id)
        .collect();
    assert_eq!(reset.len(), 1);
    assert!(reset[0].reset && reset[0].records.is_empty() && reset[0].through == 0);
    assert_eq!(reset[0].epoch, p.a.store.epoch, "the responder's epoch");
    assert_eq!(p.a.store.epoch, u64::from(0xa0u8) << 8 | 1, "not redrawn");
    assert_eq!(p.b.store.len(), 3, "the Check reconciled");
    let (caught_up, cursor) = rounds(&p.b)[0];
    assert!(caught_up);
    assert_eq!(
        cursor,
        Some((p.a.store.epoch, 3)),
        "from the first root reply"
    );
    // A since above the local sequence, with the right epoch: a reset that
    // draws a new epoch, once per connection.
    let mut p = open_with(
        |p| {
            for r in &all {
                p.a.store.insert_signed(r, &v);
                p.b.store.insert_signed(r, &v);
            }
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, MAX_LOCAL_SEQ));
        },
        |_| {},
    );
    let first = p.a.store.epoch;
    assert_ne!(first, u64::from(0xa0u8) << 8 | 1, "redrawn");
    assert!(p
        .a
        .saw(|e| matches!(e, Event::ServeIndex { request, .. } if request.redraw_allowed)));
    // Again on the same connection: a reset, no new epoch.
    p.b.store.peers.insert(device_a(), (first, MAX_LOCAL_SEQ));
    let f = p.b.folder_id();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.advance(s(5));
    assert_eq!(p.a.store.epoch, first, "at most once per connection");
    let last = last_serve(&p.a).unwrap();
    assert!(
        matches!(last, Event::ServeReconcile { .. }),
        "then the Check"
    );
    let served: Vec<bool> =
        p.a.events
            .iter()
            .filter_map(|e| match e {
                Event::ServeIndex { request, .. } => Some(request.redraw_allowed),
                _ => None,
            })
            .collect();
    assert_eq!(served, vec![true, false]);
    assert_eq!(index_requests(&p.b).len(), 2);
    assert_eq!(pages(&p.a).iter().filter(|pg| pg.reset).count(), 2);
}

#[test]
fn the_descent_children_then_records_then_the_pushes() {
    // A holds 130 records: its root is a node. B holds them and one more.
    let base = records(1, 130, 1);
    let extra = records(2, 1, 1);
    let mut b = base.clone();
    b.extend(extra.clone());
    let p = pair_with(&base, &b);
    assert_eq!(p.a.store.all(), p.b.store.all());
    let b_asks = reconciles(&p.b);
    let a_answers = replies(&p.a);
    let outcome_of = |id: u32| {
        a_answers
            .iter()
            .find(|r| r.request_id == id)
            .map(|r| r.outcome)
    };
    assert_eq!(
        outcome_of(b_asks[0].request_id),
        Some(ReconcileOutcome::Children.as_u32())
    );
    assert_eq!(b_asks[1].prefix.len(), 1, "the one child that differs");
    let key = crate::record::Record::parse(extra[0].clone(), &p.b.verifier())
        .unwrap()
        .key();
    assert!(Prefix::from_wire(&b_asks[1].prefix).unwrap().contains(&key));
    assert_eq!(
        outcome_of(b_asks[1].request_id),
        Some(ReconcileOutcome::Records.as_u32())
    );
    // B's pass brought nothing: quiet, the round caught up after it.
    assert_eq!(b_asks.len(), 2);
    assert_eq!(rounds(&p.b), vec![(true, Some((p.a.store.epoch, 130)))]);
    // A's round: the same descent, a record brought, then EQUAL.
    assert!(reconciles(&p.a).len() >= 3);
    assert!(rounds(&p.a)[0].0);
}

#[test]
fn a_cleanup_takes_a_local_sequence_number_and_is_keyed_by_its_hash() {
    // Pushed with its through, served in a Since reply, and found by the
    // digests under its key, its own record hash twice.
    let key = folder(0x10);
    let named = records(1, 2, 1);
    let groups = vec![crate::record::Group {
        because: None,
        forget: vec![named[0].hash()],
    }];
    let c = crate::testkit::cleanup(&key, 1, 3, groups);
    let mut p = pair_with(&named, &named);
    let e = p.a.store.epoch;
    let frames = p.a.push(p.now, core::slice::from_ref(&c));
    assert_eq!(frames.len(), 1);
    p.settle();
    assert!(p.b.store.holds(&c.hash()));
    assert_eq!(advanced(&p.b).last(), Some(&(e, 3)), "counted through it");
    let held = &p.b.store.held[&c.hash()];
    assert_eq!(
        held.key[..32],
        c.hash().0,
        "a cleanup's key: its record hash"
    );
    assert_eq!(held.key[32..], c.hash().0, "twice");
    // A requester without it finds it by reconciliation.
    let p = pair_with(&[named[0].clone(), c.clone()], &named[..1]);
    assert!(p.b.store.holds(&c.hash()));
    // And a Since reply serves it.
    let v = *key.verifier();
    let p = open_with(
        |p| {
            for r in [&named[0], &c] {
                p.a.store.insert_signed(r, &v);
            }
            p.b.store.insert_signed(&named[0], &v);
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 1));
        },
        |_| {},
    );
    let since = index_requests(&p.b).pop().unwrap();
    let reply: Vec<IndexRecords> = pages(&p.a)
        .into_iter()
        .filter(|pg| pg.request_id == since.request_id)
        .collect();
    assert_eq!(reply[0].records, vec![c.to_bytes()]);
    assert_eq!(reply[0].through, 2);
}

#[test]
fn a_requester_holding_nothing_and_a_responder_holding_nothing() {
    let p = pair_with(&records(1, 100, 1), &[]);
    assert_eq!(p.b.store.len(), 100);
    // B's root digest is zero: one RECORDS reply of every record.
    let b_root = &reconciles(&p.b)[0];
    assert_eq!(b_root.digest, vec![0; 32]);
    let answer = replies(&p.a)
        .into_iter()
        .find(|r| r.request_id == b_root.request_id)
        .unwrap();
    assert_eq!(answer.outcome, ReconcileOutcome::Records.as_u32());
    let served: usize = pages(&p.a)
        .iter()
        .filter(|pg| pg.request_id == b_root.request_id)
        .map(|pg| pg.records.len())
        .sum();
    assert_eq!(served, 100);
    // A's root asked a responder holding nothing: RECORDS, one empty page.
    let a_root = &reconciles(&p.a)[0];
    let empty: Vec<IndexRecords> = pages(&p.b)
        .into_iter()
        .filter(|pg| pg.request_id == a_root.request_id)
        .collect();
    assert_eq!(empty.len(), 1);
    assert!(empty[0].records.is_empty() && !empty[0].more);
    assert!(rounds(&p.a)[0].0 && rounds(&p.b)[0].0);
}

/// Opens a pair whose B holds `b_records` (A none), turns A's engine off, and
/// starts an owed round of B's; the root request A was handed.
fn scripted(b_records: u64) -> (Pair, FolderId, u32) {
    let mut p = pair_with(&[], &records(2, b_records, 1));
    p.a.auto = false;
    p.a.events.clear();
    // Without state for A, B's round reconciles.
    p.b.store.peers.clear();
    let f = p.b.folder_id();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.deliver();
    p.advance(s(2));
    let Some(Event::ServeReconcile { request, .. }) = last_serve(&p.a) else {
        panic!("a root request")
    };
    assert!(request.prefix.is_root());
    (p, f, request.request_id)
}

/// The next request A was handed, after `before` events.
fn next_serve(p: &mut Pair, before: usize) -> crate::connection::ReconcileServe {
    p.advance(s(2));
    p.a.events[before..]
        .iter()
        .find_map(|e| match e {
            Event::ServeReconcile { request, .. } => Some(*request),
            _ => None,
        })
        .unwrap()
}

#[test]
fn children_for_a_zero_digest_is_a_sender_violation() {
    let (mut p, f, id) = scripted(0);
    let e = p.a.store.epoch;
    a_sends(&mut p, children_reply(&f, id, e, &lies(1)));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::SenderViolation)))
    );
}

#[test]
fn children_for_a_full_key_is_a_sender_violation_and_the_work_list_holds_1921() {
    // A liar answers CHILDREN with digests B never holds: B descends depth
    // first, child 0 first, to a 128-nibble prefix, where CHILDREN is a
    // sender violation. Its work list then holds 15 siblings a level.
    let (mut p, f, mut id) = scripted(1);
    // B's own digests are never zero, so that CHILDREN is allowed below.
    p.b.store.lying = true;
    let e = p.a.store.epoch;
    for depth in 0..128 {
        let before = p.a.events.len();
        a_sends(&mut p, children_reply(&f, id, e, &lies(depth)));
        let next = next_serve(&mut p, before);
        assert_eq!(next.prefix.depth(), depth as usize + 1);
        assert!(next.prefix.nibbles().all(|n| n == 0), "child 0 first");
        id = next.request_id;
        assert!(p.b.conn.work_list_len(&f) <= MAX_WORK_LIST);
    }
    assert_eq!(p.b.conn.work_list_len(&f), 15 * 128);
    a_sends(&mut p, children_reply(&f, id, e, &lies(99)));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::SenderViolation)))
    );
}

#[test]
fn records_past_the_leaf_and_outside_the_prefix_are_sender_violations() {
    // 65 records answering a non-zero digest at the root.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    a_sends(
        &mut p,
        outcome_reply(&f, id, e, ReconcileOutcome::Records, 0),
    );
    let many = records(3, RECONCILE_LEAF_MAX as u64 + 1, 1);
    a_sends(&mut p, records_page(&f, id, e, &many));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::SenderViolation)))
    );
    // A record outside the prefix of a RECORDS reply, with a garbage
    // signature: a sender violation, whatever the signature.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    let before = p.a.events.len();
    a_sends(&mut p, children_reply(&f, id, e, &lies(5)));
    let child = next_serve(&mut p, before);
    assert_eq!(child.prefix.to_wire(), [0]);
    a_sends(
        &mut p,
        outcome_reply(&f, child.request_id, e, ReconcileOutcome::Records, 0),
    );
    let v = p.b.verifier();
    let outside = records(4, 40, 1)
        .into_iter()
        .find(|r| {
            let key = crate::record::Record::parse(r.clone(), &v).unwrap().key();
            !child.prefix.contains(&key)
        })
        .unwrap();
    let garbage = crate::testkit::resigned(&outside, [0; 64]);
    a_sends(&mut p, records_page(&f, child.request_id, e, &[garbage]));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::SenderViolation)))
    );
    assert!(p.b.reported.is_empty(), "never judged");
}

/// `n` versions of one path, writer 3 at counters `1..=n`: one path tag,
/// so all of them lie beneath one 64-nibble prefix.
fn versions_of_one_path(n: u64) -> Vec<SignedRecord> {
    let key = folder(0x10);
    (1..=n)
        .map(|c| {
            let draft = crate::record::IndexDraft {
                meta: crate::testkit::meta("one/path", 3, c),
                chunks: vec![],
                replaces: vec![],
            };
            crate::testkit::sign(&key, &draft, 1)
        })
        .collect()
}

/// Leads B's pass from the root request `id` down to `target`, one
/// `CHILDREN` reply a level whose digests equal B's own but on the path to
/// it; the request for `target` A was handed.
fn descend_to(p: &mut Pair, f: &FolderId, mut id: u32, target: &Prefix) -> u32 {
    use crate::exchange::IndexView as _;
    let e = p.a.store.epoch;
    let path = target.to_wire();
    let mut here = Prefix::ROOT;
    for (depth, want) in path.iter().enumerate() {
        let digests: [SetDigest; 16] = core::array::from_fn(|n| {
            let child = here.child(n as u8).unwrap();
            if n as u8 == *want {
                lies(depth as u8)[n]
            } else {
                p.b.store.digest(&child)
            }
        });
        let before = p.a.events.len();
        a_sends(p, children_reply(f, id, e, &digests));
        let next = next_serve(p, before);
        here = here.child(*want).unwrap();
        assert_eq!(next.prefix, here, "only the path to the target differs");
        id = next.request_id;
    }
    id
}

#[test]
fn records_past_the_leaf_beneath_a_path_tag_are_a_sender_violation() {
    // Only a full key (128 nibbles) may carry more than RECONCILE_LEAF_MAX
    // records answering a digest that is not zero. At a 64-nibble prefix,
    // one path tag and any record hash, 65 versions of one path are a
    // sender violation, and 64 are not.
    for (n, violation) in [
        (RECONCILE_LEAF_MAX as u64 + 1, true),
        (RECONCILE_LEAF_MAX as u64, false),
    ] {
        let (mut p, f, id) = scripted(1);
        // B's own digests are never zero, so that CHILDREN is allowed.
        p.b.store.lying = true;
        let e = p.a.store.epoch;
        let many = versions_of_one_path(n);
        let v = p.b.verifier();
        let key = crate::record::Record::parse(many[0].clone(), &v)
            .unwrap()
            .key();
        let tag = Prefix::of_key(&key, 64);
        for r in &many {
            let k = crate::record::Record::parse(r.clone(), &v).unwrap().key();
            assert!(tag.contains(&k), "one path tag");
        }
        let id = descend_to(&mut p, &f, id, &tag);
        a_sends(
            &mut p,
            outcome_reply(&f, id, e, ReconcileOutcome::Records, 0),
        );
        a_sends(&mut p, records_page(&f, id, e, &many));
        let want = violation.then_some((CloseReason::ProtocolError, Some(Cause::SenderViolation)));
        assert_eq!(closed(&p.b), want, "{n} records");
    }
}

#[test]
fn replies_of_the_wrong_kind_or_shape_are_malformed() {
    let malformed = Some((CloseReason::ProtocolError, Some(Cause::Malformed)));
    // A RECORDS page carrying through.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    a_sends(
        &mut p,
        outcome_reply(&f, id, e, ReconcileOutcome::Records, 0),
    );
    let page = IndexRecords {
        folder_id: f.0.to_vec(),
        request_id: id,
        epoch: e,
        through: 3,
        ..IndexRecords::default()
    };
    p.b.receive(p.now, &frame(&Message::IndexRecords(page)));
    assert_eq!(closed(&p.b), malformed, "a RECORDS page with through");
    // A reset answering a ReconcileRequest.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    a_sends(
        &mut p,
        outcome_reply(&f, id, e, ReconcileOutcome::Records, 0),
    );
    let reset = crate::exchange::reset_page(&f, id, e);
    p.b.receive(p.now, &frame(&Message::IndexRecords(reset)));
    assert_eq!(closed(&p.b), malformed, "a reset for a ReconcileRequest");
    // Pages before the ReconcileReply.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    let early = IndexRecords {
        folder_id: f.0.to_vec(),
        request_id: id,
        epoch: e,
        ..IndexRecords::default()
    };
    p.b.receive(p.now, &frame(&Message::IndexRecords(early)));
    assert_eq!(closed(&p.b), malformed, "a page before the reply");
    // A ReconcileReply with through for a prefix other than the root.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    let before = p.a.events.len();
    a_sends(&mut p, children_reply(&f, id, e, &lies(5)));
    let child = next_serve(&mut p, before);
    let bad = ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id: child.request_id,
        outcome: ReconcileOutcome::Equal.as_u32(),
        children: vec![],
        epoch: e,
        through: 9,
    };
    p.b.receive(p.now, &frame(&Message::ReconcileReply(bad)));
    assert_eq!(closed(&p.b), malformed, "through on a non-root prefix");
    // A second ReconcileReply for one request.
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    a_sends(
        &mut p,
        outcome_reply(&f, id, e, ReconcileOutcome::Records, 0),
    );
    let again = ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id: id,
        outcome: ReconcileOutcome::Equal.as_u32(),
        children: vec![],
        epoch: e,
        through: 0,
    };
    p.b.receive(p.now, &frame(&Message::ReconcileReply(again)));
    assert_eq!(closed(&p.b), malformed, "a second reply");
    // A ReconcileReply answering an IndexRequest.
    let v = *folder(0x10).verifier();
    let mut p = open_with(
        |p| {
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 0));
            for r in records(1, 1, 1) {
                p.a.store.insert_signed(&r, &v);
            }
        },
        |_| {},
    );
    p.a.auto = false;
    let f = p.b.folder_id();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.deliver();
    let since = index_requests(&p.b).pop().unwrap();
    let wrong = ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id: since.request_id,
        outcome: ReconcileOutcome::Equal.as_u32(),
        children: vec![],
        epoch: 1,
        through: 0,
    };
    p.b.receive(p.now, &frame(&Message::ReconcileReply(wrong)));
    assert_eq!(
        closed(&p.b),
        malformed,
        "a ReconcileReply for an IndexRequest"
    );
}

#[test]
fn a_round_that_never_goes_quiet_ends_after_its_passes_and_owes_one() {
    // A liar's root RECORDS replies each bring B a record it then holds, so
    // that no pass is quiet: the round ends after MAX_RECONCILE_PASSES, not
    // caught up, and owes a round, which starts INDEX_RESYNC_INTERVAL after
    // this owed round began.
    let (mut p, f, mut id) = scripted(1);
    let start = p.now - s(2);
    let e = p.a.store.epoch;
    let fresh = records(5, 10, 1);
    for pass in 0..MAX_RECONCILE_PASSES {
        a_sends(
            &mut p,
            outcome_reply(&f, id, e, ReconcileOutcome::Records, 1),
        );
        let before = p.a.events.len();
        a_sends(&mut p, records_page(&f, id, e, &fresh[pass..=pass]));
        if pass + 1 < MAX_RECONCILE_PASSES {
            assert_eq!(rounds(&p.b).len(), 1, "still the owed round");
            let next = next_serve(&mut p, before);
            assert!(next.prefix.is_root(), "the next pass");
            id = next.request_id;
        }
    }
    let r = rounds(&p.b);
    assert_eq!(r.len(), 2);
    assert!(!r[1].0, "not caught up");
    assert!(p.b.conn.round_owed(&f));
    assert!(!p.b.conn.round_under_way(&f));
    p.advance_to(start + s(9));
    assert!(!p.b.conn.round_under_way(&f), "waits its interval");
    p.advance_to(start + s(11));
    assert!(p.b.conn.round_under_way(&f));
}

#[test]
fn a_pass_cut_at_its_request_cap_is_never_quiet() {
    // A liar's CHILDREN at the root and below fill the work list; the pass is
    // cut at its cap (lowered here to 3 requests; the real one below) and is
    // never quiet though it brought nothing; the next pass, from the root,
    // finds EQUAL and ends the round caught up.
    let (mut p, f, id) = scripted(1);
    p.b.store.lying = true;
    p.b.conn.set_pass_cap(&f, 3);
    let e = p.a.store.epoch;
    let before = p.a.events.len();
    a_sends(&mut p, children_reply(&f, id, e, &lies(1)));
    let c1 = next_serve(&mut p, before);
    let before = p.a.events.len();
    a_sends(&mut p, children_reply(&f, c1.request_id, e, &lies(2)));
    let c2 = next_serve(&mut p, before);
    assert_eq!(p.b.conn.pass_of(&f), Some((1, 3)));
    let before = p.a.events.len();
    a_sends(
        &mut p,
        outcome_reply(&f, c2.request_id, e, ReconcileOutcome::Equal, 0),
    );
    let root = next_serve(&mut p, before);
    assert!(root.prefix.is_root(), "cut: the next pass begins");
    assert_eq!(p.b.conn.pass_of(&f), Some((2, 1)));
    a_sends(
        &mut p,
        outcome_reply(&f, root.request_id, e, ReconcileOutcome::Equal, 1),
    );
    assert!(rounds(&p.b).last().unwrap().0);
}

#[test]
fn a_pass_stops_at_max_pass_requests() {
    // The real bound: a liar's CHILDREN at every prefix shorter than 128
    // nibbles and RECORDS of nothing at full keys never let the list run out;
    // the pass sends exactly MAX_PASS_REQUESTS requests.
    let (mut p, f, mut id) = scripted(1);
    p.b.store.lying = true;
    let e = p.a.store.epoch;
    let mut sent = 1;
    let mut prefix = Prefix::ROOT;
    loop {
        p.a.events.clear();
        if prefix.is_full() {
            a_sends(
                &mut p,
                outcome_reply(&f, id, e, ReconcileOutcome::Records, 0),
            );
            a_sends(&mut p, records_page(&f, id, e, &[]));
        } else {
            a_sends(&mut p, children_reply(&f, id, e, &lies(3)));
        }
        let next = p.a.events.iter().find_map(|ev| match ev {
            Event::ServeReconcile { request, .. } => Some(*request),
            _ => None,
        });
        let Some(request) = next else {
            // The next pass's root request, held for the serving interval.
            break;
        };
        id = request.request_id;
        prefix = request.prefix;
        sent += 1;
    }
    assert_eq!(sent, MAX_PASS_REQUESTS);
    assert_eq!(
        p.b.conn.pass_of(&f).unwrap().0,
        2,
        "cut, then the next pass"
    );
}

#[test]
fn a_skipped_page_makes_its_pass_not_quiet_r4() {
    // R4, revert check 16: B's store refuses every record of A's RECORDS
    // replies. No pass is quiet, no cursor moves, the round owes another,
    // and the next round, once the store takes changes, brings them.
    let v = *folder(0x10).verifier();
    let mut p = open_with(
        |p| {
            for r in records(1, 3, 1) {
                p.a.store.insert_signed(&r, &v);
            }
            p.b.store.refusing = true;
        },
        |_| {},
    );
    let f = p.b.folder_id();
    assert_eq!(p.b.store.len(), 0);
    let r = rounds(&p.b);
    assert_eq!(r[0], (false, None), "not caught up, no cursor");
    // The round on open ran every pass, then the round it owed (no owed
    // round began before it, so it starts at once) did too.
    assert_eq!(r[1], (false, None));
    assert_eq!(
        reconciles(&p.b)
            .iter()
            .filter(|q| q.prefix.is_empty())
            .count(),
        2 * MAX_RECONCILE_PASSES,
        "every pass ran"
    );
    assert!(p.b.conn.round_owed(&f) || p.b.conn.round_under_way(&f));
    assert_eq!(p.b.conn.counting(&f), None, "no cursor: no counting");
    p.b.store.refusing = false;
    p.advance(s(30));
    assert_eq!(p.b.store.len(), 3);
    assert!(rounds(&p.b).last().unwrap().0);
    // The same for a Since reply's records.
    let mut p = open_with(
        |p| {
            for r in records(1, 3, 1) {
                p.a.store.insert_signed(&r, &v);
            }
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 0));
            p.b.store.refusing = true;
        },
        |_| {},
    );
    assert!(!index_requests(&p.b).is_empty());
    assert_eq!(rounds(&p.b)[0], (false, None));
    assert_eq!(
        p.b.store.peers[&device_a()],
        (p.a.store.epoch, 0),
        "unmoved"
    );
    p.b.store.refusing = false;
    p.advance(s(30));
    assert_eq!(p.b.store.len(), 3);
}

/// A round that skipped a record is never caught up (4.5 "Rounds"; the
/// review's P-2): a record pushed while B's store refuses changes is skipped
/// during B's round, the store takes records again, the record comes back in
/// that round's RECORDS reply and the root ends EQUAL; the round still ends
/// not caught up, with no cursor, and owes another.
#[test]
fn a_round_that_skipped_a_record_is_never_caught_up_p2() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    // No stored cursor: B's next round is the Check, and it starts at once.
    p.b.store.peers.clear();
    let before = rounds(&p.b).len();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    assert!(p.b.conn.round_under_way(&f));
    let r = records(1, 1, 7);
    p.b.store.refusing = true;
    p.a.push(p.now, &r);
    // B judges the push (skipped); A answers B's root request (RECORDS).
    p.deliver();
    assert!(!p.b.store.holds(&r[0].hash()), "skipped");
    p.b.store.refusing = false;
    // The next pass's root request waits out INDEX_REQUEST_MIN_INTERVAL.
    p.advance(s(2));
    assert!(p.b.store.holds(&r[0].hash()), "back in the RECORDS reply");
    let last = replies(&p.a).pop().unwrap();
    assert_eq!(
        last.outcome,
        ReconcileOutcome::Equal.as_u32(),
        "the root ended EQUAL"
    );
    assert_eq!(
        rounds(&p.b)[before..],
        [(false, None)],
        "never caught up, no cursor"
    );
    assert!(p.b.conn.round_owed(&f));
}

/// The pushes B receives in `bytes` with its engine off: their pages.
fn push_pages(p: &mut Pair, bytes: &[u8]) -> Vec<Page> {
    p.b.auto = false;
    let now = p.now;
    p.b.receive(now, bytes)
        .iter()
        .filter_map(|ev| match ev {
            Event::Records { page, .. } => Some(*page),
            _ => None,
        })
        .collect()
}

/// One push frame of `r` for `f` under `epoch`, `through` as given.
fn push_frame(f: &FolderId, epoch: u64, through: u64, r: &SignedRecord) -> Vec<u8> {
    frame(&Message::IndexRecords(IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![r.to_bytes()],
        more: false,
        request_id: 0,
        epoch,
        through,
        reset: false,
    }))
}

/// The cursors one judgement raised.
fn raised(out: &crate::connection::Output) -> Vec<(u64, u64)> {
    out.events
        .iter()
        .filter_map(|e| match e {
            Event::CursorAdvanced { epoch, through, .. } => Some((*epoch, *through)),
            _ => None,
        })
        .collect()
}

/// A push's judgement is matched to its own entry by its number (the
/// review's PS NIT 6): judged out of order, no cursor rises to another
/// push's `through`, and a late judgement finds no entry.
#[test]
fn a_push_judgement_finds_its_own_entry_ps6() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.b.conn.counting(&f).unwrap();
    let three = records(5, 3, 3);
    let mut bytes = Vec::new();
    for (i, r) in three.iter().enumerate() {
        bytes.extend(push_frame(&f, e, i as u64 + 1, r));
    }
    let got = push_pages(&mut p, &bytes);
    assert_eq!(got.len(), 3);
    assert_ne!(got[0], got[1], "numbered");
    let t = p.b.tick(p.now);
    // In order, each its own through.
    let out = p.b.conn.judged(t, f, got[0], &[Ok(Judgement::Held)]);
    assert_eq!(raised(&out), vec![(e, 1)], "its own through");
    // Out of order: the third judged before the second fails closed, the
    // cursor never passing a push whose records were not judged, and the
    // counting stops (the confirm review's NIT).
    let out = p.b.conn.judged(t, f, got[2], &[Ok(Judgement::Held)]);
    assert!(raised(&out).is_empty(), "the second is still unjudged");
    assert_eq!(p.b.conn.counting(&f), None, "the counting stopped");
    assert_eq!(p.b.conn.pending_pushes(&f), 0);
    let out = p.b.conn.judged(t, f, got[1], &[Ok(Judgement::Held)]);
    assert!(raised(&out).is_empty());
}

/// A judgement whose push's entry is gone (dropped as an earlier one, or
/// forgotten past the bound) leaves the later entries alone: the search for
/// its entry stops at the first later number (the confirm review's pin of
/// the `n > push` break).
#[test]
fn a_judgement_of_a_forgotten_push_leaves_the_later_ones() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.b.conn.counting(&f).unwrap();
    let three = records(5, 3, 3);
    let mut bytes = Vec::new();
    for (i, r) in three.iter().enumerate() {
        bytes.extend(push_frame(&f, e, i as u64 + 1, r));
    }
    let got = push_pages(&mut p, &bytes);
    let t = p.b.tick(p.now);
    // The second judged first drops the first's entry, leaving the third's.
    let _ = p.b.conn.judged(t, f, got[1], &[Ok(Judgement::Held)]);
    assert_eq!(p.b.conn.pending_pushes(&f), 1);
    // The first's late judgement finds no entry and keeps the third's.
    let _ = p.b.conn.judged(t, f, got[0], &[Ok(Judgement::Held)]);
    assert_eq!(p.b.conn.pending_pushes(&f), 1, "the third's entry kept");
    let _ = p.b.conn.judged(t, f, got[2], &[Ok(Judgement::Held)]);
    assert_eq!(p.b.conn.pending_pushes(&f), 0);
}

/// Pushes left unjudged past `MAX_PENDING_PUSHES` stop the counting rather
/// than grow the table, and their late judgements raise no cursor (the
/// review's P NIT and PS NIT 6, from the security reviewer's probe).
#[test]
fn pushes_left_unjudged_past_the_bound_stop_the_counting() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.b.conn.counting(&f).unwrap();
    let one = records(5, 1, 3).pop().unwrap();
    let n = crate::limits::MAX_PENDING_PUSHES;
    let mut bytes = Vec::new();
    for i in 0..=n {
        bytes.extend(push_frame(&f, e, i as u64 + 1, &one));
    }
    let got = push_pages(&mut p, &bytes);
    assert_eq!(got.len(), n + 1);
    assert_eq!(p.b.conn.counting(&f), None, "the counting stopped");
    assert!(p.b.conn.pending_pushes(&f) <= n, "bounded");
    let t = p.b.tick(p.now);
    for page in got {
        let out = p.b.conn.judged(t, f, page, &[Ok(Judgement::Held)]);
        assert!(raised(&out).is_empty());
    }
    assert_eq!(p.b.conn.pending_pushes(&f), 0);
}

/// A push with `through` 0, as a reconciliation's pushes are, moves no
/// cursor while pushes are counted (4.5, "Cursors").
#[test]
fn a_push_with_through_zero_is_not_counted() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    assert_eq!(p.b.conn.counting(&f), Some(e));
    let r = records(1, 1, 1);
    p.a.push_page(p.now, &r, 0);
    p.settle();
    assert!(p.b.store.holds(&r[0].hash()));
    assert!(advanced(&p.b).is_empty(), "not counted");
    assert_eq!(p.b.conn.counting(&f), Some(e), "still counting");
}

/// An empty push uncounts the pushes before it whose judgements have not
/// come back: once a round's end counts again, their late judgements raise
/// no cursor (4.5, "Cursors": the counting stops at an empty push).
#[test]
fn an_empty_push_uncounts_the_pushes_awaiting_judgement() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.b.conn.counting(&f).unwrap();
    let r = records(1, 1, 1);
    let mut bytes = Vec::new();
    for frame in p.a.push(p.now, &r) {
        bytes.extend(frame);
    }
    p.a.outbox.clear();
    let got = push_pages(&mut p, &bytes);
    assert_eq!(got.len(), 1);
    p.b.receive(p.now, &empty_push(&f, e));
    assert_eq!(p.b.conn.counting(&f), None);
    // B's owed round, by hand (its engine was off when it fell due), then
    // the round's end counts again.
    p.b.auto = true;
    p.b.request(p.now).unwrap();
    p.settle();
    p.advance(s(2));
    assert_eq!(p.b.conn.counting(&f), Some(e), "counting again");
    let t = p.b.tick(p.now);
    let out = p.b.conn.judged(t, f, got[0], &[Ok(Judgement::Duplicate)]);
    assert!(raised(&out).is_empty(), "uncounted by the empty push");
}

/// Which cursor a round keeps (4.5, "Rounds"): the `through` of the Since
/// reply's last page, not the Check's root reply's; and without Since, the
/// first root reply's, not a later pass's (the review's P NIT).
#[test]
fn a_round_keeps_the_since_cursor_or_the_first_root_reply() {
    let v = *folder(0x10).verifier();
    let all = records(1, 6, 1);
    // With Since: A holds 3 and B's cursor is at 3; A comes to hold a 4th
    // between its Since reply and B's Check.
    let mut p = pair_with(&all[..3], &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    assert_eq!(p.b.store.peers[&device_a()], (e, 3));
    let before = rounds(&p.b).len();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.deliver(); // A serves the Since reply.
    p.a.store.insert_signed(&all[3], &v);
    p.deliver(); // B judges it and sends the Check.
    p.advance(s(2));
    assert!(p.b.store.holds(&all[3].hash()), "the Check brought it");
    assert_eq!(
        rounds(&p.b)[before..].first(),
        Some(&(true, Some((e, 3)))),
        "the Since reply's cursor"
    );
    // Without Since: the first root reply's through (5, A then holding 5),
    // not the second pass's (6).
    p.b.store.peers.clear();
    p.a.store.insert_signed(&all[4], &v);
    let before = rounds(&p.b).len();
    p.advance(s(10));
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.deliver(); // A answers the first root request: RECORDS, through 5.
    p.deliver(); // B judges them; its next pass's root request goes.
    p.a.store.insert_signed(&all[5], &v);
    p.advance(s(4));
    assert!(p.b.store.holds(&all[5].hash()));
    assert_eq!(
        rounds(&p.b)[before..].first(),
        Some(&(true, Some((e, 5)))),
        "the first root reply's cursor"
    );
}

/// A request ID repeated while the first request is being served, even for
/// another folder, closes; and an `IndexRequest`, a `ReconcileRequest` or a
/// page for a folder not open closes (`Close(PROTOCOL_ERROR)`, section 5;
/// the reviews' P and PS NITs, the latter from the security reviewer's
/// probe).
#[test]
fn a_request_id_reused_and_a_folder_not_open_close() {
    let keys = [
        licketysync_keys::folder::FolderKey::from(folder(0x10)),
        licketysync_keys::folder::FolderKey::from(folder(0x20)),
    ];
    let mut p = Pair::new(0xa0, 0xb0, &keys, &keys);
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    p.advance(s(10));
    let (f, g) = (
        keys[0].verifier().folder_id(),
        keys[1].verifier().folder_id(),
    );
    let request = |folder: &FolderId| {
        frame(&Message::IndexRequest(IndexRequest {
            folder_id: folder.0.to_vec(),
            max_records: 0,
            request_id: 77,
            epoch: 1,
            since: 0,
        }))
    };
    p.b.auto = false;
    let mut bytes = request(&f);
    bytes.extend(request(&g));
    let now = p.now;
    p.b.receive(now, &bytes);
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    let other = FolderId([0x77; 32]);
    let messages = [
        Message::IndexRequest(IndexRequest {
            folder_id: other.0.to_vec(),
            max_records: 0,
            request_id: 99,
            epoch: 1,
            since: 0,
        }),
        Message::ReconcileRequest(ReconcileRequest {
            folder_id: other.0.to_vec(),
            request_id: 99,
            prefix: vec![],
            digest: vec![0; 32],
        }),
        Message::IndexRecords(IndexRecords {
            folder_id: other.0.to_vec(),
            epoch: 1,
            ..IndexRecords::default()
        }),
    ];
    for m in messages {
        let mut p = pair_with(&[], &[]);
        let now = p.now;
        p.b.receive(now, &frame(&m));
        assert_eq!(
            closed(&p.b),
            Some((CloseReason::ProtocolError, Some(Cause::Malformed))),
            "{m:?}"
        );
    }
}

/// A page after a reply's last page, in the same delivery, before the last
/// is judged, is malformed (4.5, "Replies and pushes"; the security
/// reviewer's probe).
#[test]
fn a_page_after_the_last_page_is_malformed() {
    let (mut p, f, id) = scripted(1);
    let e = p.a.store.epoch;
    let one = records(3, 1, 9);
    let mut bytes = frame(&Message::ReconcileReply(ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id: id,
        outcome: ReconcileOutcome::Records.as_u32(),
        children: vec![],
        epoch: e,
        through: 0,
    }));
    let page = || {
        let mut pager = Pager::new(MAX_PAGE_RECORDS, 64 << 20);
        assert!(pager.push(&one[0]).unwrap());
        frame(&Message::IndexRecords(pager.page(&f, id, false, e, 0)))
    };
    bytes.extend(page());
    bytes.extend(page());
    p.b.auto = false;
    let now = p.now;
    p.b.receive(now, &bytes);
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
}

/// A `through` above `MAX_LOCAL_SEQ` is never sent (the review's IS-3): a
/// store whose numbers are out of range cannot make this side send a push,
/// a page or a root reply that every peer refuses as malformed.
#[test]
fn a_through_above_max_local_seq_is_never_sent_is3() {
    let over = MAX_LOCAL_SEQ + 1;
    let mut p = pair_with(&[], &[]);
    let f = p.a.folder_id();
    let t = Tick::at(p.now);
    let one = records(1, 1, 1)[0].to_bytes();
    let push = IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![one],
        more: false,
        request_id: 0,
        epoch: 5,
        through: over,
        reset: false,
    };
    assert_eq!(p.a.conn.push(t, &push).err(), Some(SendError::Malformed));
    let at_bound = IndexRecords {
        through: MAX_LOCAL_SEQ,
        ..push
    };
    assert!(p.a.conn.push(t, &at_bound).is_ok(), "at the bound");
    // A Since reply's page.
    let mut q = open_with(
        |q| {
            let epoch = q.a.store.epoch;
            q.b.store.peers.insert(device_a(), (epoch, 0));
        },
        |_| {},
    );
    q.a.serving = false;
    let fq = q.b.folder_id();
    let e = q.a.store.epoch;
    q.b.receive(q.now, &empty_push(&fq, e));
    q.settle();
    let Some(Event::ServeIndex { request: r, .. }) = last_serve(&q.a) else {
        panic!()
    };
    let tq = Tick::at(q.now);
    let page = |through: u64| IndexRecords {
        folder_id: fq.0.to_vec(),
        records: vec![],
        more: false,
        request_id: r.request_id,
        epoch: e,
        through,
        reset: false,
    };
    assert_eq!(
        q.a.conn.send_page(tq, &page(over)).err(),
        Some(SendError::Malformed)
    );
    assert!(q.a.conn.send_page(tq, &page(MAX_LOCAL_SEQ)).is_ok());
    // A root ReconcileReply.
    let (mut p2, f2, id) = scripted(1);
    let e2 = p2.a.store.epoch;
    let t2 = Tick::at(p2.now);
    let reply = |through: u64| ReconcileReply {
        folder_id: f2.0.to_vec(),
        request_id: id,
        outcome: ReconcileOutcome::Equal.as_u32(),
        children: vec![],
        epoch: e2,
        through,
    };
    assert_eq!(
        p2.a.conn.send_reconcile_reply(t2, &reply(over)).err(),
        Some(SendError::Malformed)
    );
    assert!(p2
        .a
        .conn
        .send_reconcile_reply(t2, &reply(MAX_LOCAL_SEQ))
        .is_ok());
}

/// The epoch is redrawn at most once per connection, and the connection
/// holds the engine to it (the review's PS NIT 7): a reset that claims a
/// second redraw is refused.
#[test]
fn a_second_redraw_on_one_connection_is_refused() {
    let mut q = open_with(
        |q| {
            let epoch = q.a.store.epoch;
            q.b.store.peers.insert(device_a(), (epoch, MAX_LOCAL_SEQ));
        },
        |_| {},
    );
    assert!(q
        .a
        .saw(|e| matches!(e, Event::ServeIndex { request, .. } if request.redraw_allowed)));
    q.a.serving = false;
    let f = q.b.folder_id();
    let e = q.a.store.epoch;
    q.b.store.peers.insert(device_a(), (e, MAX_LOCAL_SEQ));
    q.advance(s(10));
    let out = q.b.conn.owe_round(q.b.tick(q.now), f);
    q.b.apply(q.now, out);
    q.b.pump(q.now);
    q.settle();
    q.advance(s(2));
    let Some(Event::ServeIndex { request, .. }) = last_serve(&q.a) else {
        panic!("the second request")
    };
    assert!(!request.redraw_allowed);
    let t = Tick::at(q.now);
    assert_eq!(
        q.a.conn.send_reset(t, f, request.request_id, e, true).err(),
        Some(SendError::RedrawSpent)
    );
    assert!(q
        .a
        .conn
        .send_reset(t, f, request.request_id, e, false)
        .is_ok());
}

#[test]
fn judged_closes_on_the_first_refusal_that_closes() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    p.b.auto = false;
    let out = p.b.conn.judged(
        Tick::at(p.now),
        f,
        Page::Push { push: 0 },
        &[
            Ok(Judgement::Duplicate),
            Err(Cause::Expired),
            Ok(Judgement::Held),
        ],
    );
    p.b.apply(p.now, out);
    assert_eq!(p.b.conn.state(), State::Established);
    let out = p.b.conn.judged(
        Tick::at(p.now),
        f,
        Page::Push { push: 1 },
        &[Err(Cause::Forged), Ok(Judgement::Held)],
    );
    p.b.apply(p.now, out);
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::VerificationFailed, Some(Cause::Forged)))
    );
    for j in [
        Judgement::Duplicate,
        Judgement::Expired,
        Judgement::Obsolete,
        Judgement::FromTheFuture,
        Judgement::Held,
        Judgement::HeldOpaque,
        Judgement::DroppedBeneath,
        Judgement::Skipped,
    ] {
        assert_eq!(
            j.held(),
            matches!(j, Judgement::Held | Judgement::HeldOpaque)
        );
        assert_eq!(
            j.cause().is_none(),
            matches!(j, Judgement::Held | Judgement::Skipped)
        );
    }
}

#[test]
fn pushes_are_counted_after_a_round_until_an_empty_push() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    assert_eq!(
        p.b.conn.counting(&f),
        Some(e),
        "counting from the round's end"
    );
    let h = records(1, 3, 1);
    p.a.push(p.now, &h[..2]);
    p.settle();
    assert_eq!(
        advanced(&p.b),
        vec![(e, 2)],
        "the cursor at the push's through"
    );
    assert_eq!(p.b.store.peers[&device_a()], (e, 2));
    // An empty push stops the counting and owes a round, whose end counts
    // again from its cursor.
    p.b.receive(p.now, &empty_push(&f, e));
    assert!(p.b.saw(|ev| matches!(ev, Event::EmptyPush { .. })));
    p.settle();
    p.advance(s(2));
    assert!(rounds(&p.b).len() >= 2);
    assert_eq!(p.b.conn.counting(&f), Some(e));
    p.a.push(p.now, &h[2..]);
    p.settle();
    assert_eq!(advanced(&p.b).last(), Some(&(e, 3)));
    // A push of another epoch: not counted, the counting stops, a round owed.
    let before = advanced(&p.b).len();
    p.a.store.epoch = e + 1;
    p.a.push(p.now, &records(2, 1, 1));
    p.b.events.clear();
    p.deliver();
    assert_eq!(advanced(&p.b).len(), 0, "{before}: not counted");
    assert_eq!(p.b.conn.counting(&f), None);
    assert!(
        p.b.conn.round_owed(&f) || p.b.conn.round_under_way(&f),
        "a round owed (the review's P-3)"
    );
    // A skipped record in a push stops the counting too.
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    p.b.store.refusing = true;
    p.a.push(p.now, &records(3, 1, 1));
    p.settle();
    assert!(advanced(&p.b).is_empty());
    assert_eq!(p.b.conn.counting(&f), None);
}

#[test]
fn an_empty_push_during_a_round_keeps_the_counting_off_after_it() {
    let mut p = pair_with(&[], &records(1, 1, 1));
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    p.a.serving = false;
    p.a.events.clear();
    p.b.store.peers.clear();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.deliver();
    assert!(p.b.conn.round_under_way(&f));
    p.b.receive(p.now, &empty_push(&f, e));
    // A serves the round by hand: EQUAL at the root.
    let Some(Event::ServeReconcile { request, .. }) = last_serve(&p.a) else {
        panic!()
    };
    a_sends(
        &mut p,
        outcome_reply(&f, request.request_id, e, ReconcileOutcome::Equal, 1),
    );
    assert!(rounds(&p.b).last().unwrap().0);
    assert_eq!(p.b.conn.counting(&f), None, "an empty push came during it");
    assert!(p.b.conn.round_owed(&f), "the next round after it");
}

#[test]
fn a_paused_folder_starts_no_round_and_resuming_owes_one() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    let out = p.b.conn.set_paused(p.b.tick(p.now), f, true);
    p.b.apply(p.now, out);
    assert_eq!(p.b.conn.counting(&f), None, "pushes not counted");
    p.b.receive(p.now, &empty_push(&f, e));
    p.advance(s(30));
    assert!(!p.b.conn.round_under_way(&f), "no round while paused");
    assert!(p.b.conn.round_owed(&f));
    let v = p.a.verifier();
    for r in records(1, 2, 1) {
        p.a.store.insert_signed(&r, &v);
    }
    let out = p.b.conn.set_paused(p.b.tick(p.now), f, false);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.advance(s(5));
    assert_eq!(
        p.b.store.len(),
        2,
        "resuming owed the round that brings them"
    );
}

#[test]
fn owe_round_starts_a_round_that_brings_what_the_peer_holds() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let v = p.a.verifier();
    for r in records(1, 2, 1) {
        p.a.store.insert_signed(&r, &v);
    }
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    assert_eq!(
        out.events,
        vec![Event::RequestDue { folder: f }],
        "due at once: no owed round began before"
    );
    assert!(p.b.conn.is_due(&f));
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.advance(s(5));
    assert_eq!(p.b.store.len(), 2);
    assert!(!p.b.conn.round_owed(&f));
}

#[test]
fn owe_round_waits_for_the_round_under_way_and_the_resync_interval() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    p.b.auto = false;
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.request(p.now).unwrap();
    let start = p.now;
    assert!(!p.b.conn.round_owed(&f));
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    assert!(out.events.is_empty(), "the owed round still runs");
    assert!(p.b.conn.round_owed(&f), "owed again, kept");
    p.b.auto = true;
    p.advance(s(3));
    assert!(!p.b.conn.round_under_way(&f));
    assert!(p.b.conn.round_owed(&f), "the interval has not passed");
    p.advance_to(start + s(9));
    assert!(!p.b.conn.round_under_way(&f));
    p.advance_to(start + s(10));
    assert!(!p.b.conn.round_owed(&f), "started at the interval");
}

#[test]
fn owe_round_leaves_a_folder_not_open_and_a_closed_connection_as_they_are() {
    let key = || licketysync_keys::folder::FolderKey::from(folder(0x10));
    let mut p = Pair::new(0xa0, 0xb0, &[key()], &[key()]);
    let fid = p.b.folder_id();
    let out = p.b.conn.owe_round(p.b.tick(p.now), fid);
    assert!(
        out.events.is_empty() && out.frames.is_empty(),
        "not established"
    );
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    let other = folder(0x20).verifier().folder_id();
    let out = p.b.conn.owe_round(p.b.tick(p.now), other);
    assert!(out.events.is_empty() && out.frames.is_empty(), "not open");
    assert!(!p.b.conn.round_owed(&other));
    let out = p.b.conn.close(p.b.tick(p.now), CloseReason::Shutdown);
    p.b.apply(p.now, out);
    let out = p.b.conn.owe_round(p.b.tick(p.now), fid);
    assert!(out.events.is_empty() && out.frames.is_empty(), "closed");
    assert!(!p.b.conn.round_owed(&fid));
    assert_eq!(
        p.b.conn.memories_mut(p.b.tick(p.now), &fid).map(|_| ()),
        None,
        "freed"
    );
}

#[test]
fn one_request_at_a_time_across_both_kinds() {
    for since_first in [true, false] {
        let v = *folder(0x10).verifier();
        let mut p = open_with(
            |p| {
                if since_first {
                    let epoch = p.a.store.epoch;
                    p.b.store.peers.insert(device_a(), (epoch, 0));
                }
                for r in records(1, 1, 1) {
                    p.a.store.insert_signed(&r, &v);
                }
            },
            |_| {},
        );
        let f = p.b.folder_id();
        p.a.serving = false;
        p.b.auto = false;
        let out = p.b.conn.owe_round(p.b.tick(p.now), f);
        p.b.apply(p.now, out);
        p.b.request(p.now).unwrap();
        assert_eq!(
            p.b.request(p.now).err(),
            Some(SendError::NotDue),
            "one at a time"
        );
        p.deliver();
        // A second request of the other kind before the first's reply ended.
        let second = if since_first {
            Message::ReconcileRequest(ReconcileRequest {
                folder_id: f.0.to_vec(),
                request_id: 900,
                prefix: vec![],
                digest: vec![1; 32],
            })
        } else {
            Message::IndexRequest(IndexRequest {
                folder_id: f.0.to_vec(),
                max_records: 0,
                request_id: 900,
                epoch: 1,
                since: 0,
            })
        };
        p.a.receive(p.now, &frame(&second));
        assert_eq!(
            closed(&p.a),
            Some((CloseReason::ProtocolError, Some(Cause::Malformed))),
            "since first: {since_first}"
        );
    }
}

#[test]
fn the_serving_interval_holds_index_and_root_requests_only() {
    // B with state for A: its round is Since, then the Check. A serves the
    // Since request at once and holds the root request until
    // INDEX_REQUEST_MIN_INTERVAL after serving the Since began; a non-root
    // request is served at once.
    let v = *folder(0x10).verifier();
    let mut p = open_with(
        |p| {
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 0));
            for r in records(1, 1, 1) {
                p.b.store.insert_signed(&r, &v);
            }
        },
        |_| {},
    );
    let f = p.b.folder_id();
    p.a.auto = false;
    p.a.events.clear();
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.deliver();
    let Some(Event::ServeIndex { request, .. }) = last_serve(&p.a) else {
        panic!("the Since request, at once")
    };
    let began = p.now;
    let e = p.a.store.epoch;
    let checks = reconciles(&p.b).len();
    let parts = p.a.store.index_reply(f, &request, 64 << 20);
    for part in parts {
        a_sends(&mut p, part);
    }
    // B's Check arrived; A holds it.
    assert_eq!(reconciles(&p.b).len(), checks + 1);
    assert!(
        !matches!(last_serve(&p.a), Some(Event::ServeReconcile { .. })),
        "held"
    );
    assert_eq!(p.a.wake, Some(began + s(1)), "the one wake-up serves it");
    let early = outcome_reply(
        &f,
        reconciles(&p.b).last().unwrap().request_id,
        e,
        ReconcileOutcome::Equal,
        0,
    );
    let Part::Reconcile(early) = early else {
        panic!()
    };
    assert_eq!(
        p.a.conn.send_reconcile_reply(Tick::at(p.now), &early).err(),
        Some(SendError::UnknownRequest),
        "a held request is not the engine's yet"
    );
    p.now = began + s(1);
    p.a.wake(p.now);
    let Some(Event::ServeReconcile { request: root, .. }) = last_serve(&p.a) else {
        panic!("served at the interval")
    };
    assert!(root.prefix.is_root());
    let at = p.now;
    let before = p.a.events.len();
    a_sends(&mut p, children_reply(&f, root.request_id, e, &lies(1)));
    // The child request is served at once, within the interval.
    let child = p.a.events[before..]
        .iter()
        .find_map(|ev| match ev {
            Event::ServeReconcile { request, .. } => Some(*request),
            _ => None,
        })
        .unwrap();
    assert_eq!(child.prefix.depth(), 1);
    assert_eq!(p.now, at, "at once");
}

#[test]
fn a_push_between_two_pages_of_a_reply_is_told_apart() {
    // PUSH-2: A serves B's Since request page by page; a record A comes to
    // hold meanwhile is pushed at once, between the pages, and told apart by
    // request_id 0. B asks with max_records 1, served as 64.
    let v = *folder(0x10).verifier();
    let mut p = open_with(
        |p| {
            let epoch = p.a.store.epoch;
            p.b.store.peers.insert(device_a(), (epoch, 0));
        },
        |c| c.max_records = 1,
    );
    for r in records(3, 100, 1) {
        p.a.store.insert_signed(&r, &v);
    }
    let f = p.a.folder_id();
    p.a.serving = false;
    p.b.events.clear();
    p.a.events.clear();
    let e = p.a.store.epoch;
    p.b.receive(p.now, &empty_push(&f, e));
    p.settle();
    let Some(Event::ServeIndex { request, .. }) = last_serve(&p.a) else {
        panic!()
    };
    assert_eq!(request.page_limit, 64);
    let mut parts = p.a.store.index_reply(f, &request, 64 << 20);
    assert_eq!(parts.len(), 2);
    let second = parts.pop().unwrap();
    let first = parts.pop().unwrap();
    a_sends(&mut p, first);
    let fresh = records(4, 1, 1);
    assert_eq!(p.a.push(p.now, &fresh).len(), 1, "the push went");
    a_sends(&mut p, second);
    p.advance(s(2));
    let Some(Event::ServeReconcile { request: check, .. }) = last_serve(&p.a) else {
        panic!("the Check")
    };
    for part in p.a.store.reconcile_reply(f, &check, 64 << 20) {
        a_sends(&mut p, part);
    }
    let id = request.request_id;
    let got: Vec<Page> =
        p.b.events
            .iter()
            .filter_map(|ev| match ev {
                Event::Records { page, .. } => Some(*page),
                _ => None,
            })
            .collect();
    assert_eq!(
        got[0],
        Page::Reply {
            request_id: id,
            last: false
        }
    );
    assert!(matches!(got[1], Page::Push { .. }));
    assert_eq!(
        got[2],
        Page::Reply {
            request_id: id,
            last: true
        }
    );
    let since_pages: Vec<IndexRecords> = pages(&p.a)
        .into_iter()
        .filter(|pg| pg.request_id == id)
        .collect();
    assert_eq!(
        (since_pages[0].through, since_pages[1].through),
        (64, 100),
        "each page's through its last record's, the last the local sequence when serving began"
    );
    assert!(rounds(&p.b).last().unwrap().0);
    assert_eq!(p.b.store.len(), 101);
}

#[test]
fn a_reply_waits_for_room_and_goes_on_room() {
    let mut p = pair_with(&[], &[]);
    let v = p.a.verifier();
    let f = p.a.folder_id();
    for r in records(5, 3, 1) {
        p.a.store.insert_signed(&r, &v);
    }
    p.a.unsent = MAX_SEND_QUEUE - 100;
    p.a.events.clear();
    let e = p.a.store.epoch;
    p.b.receive(p.now, &empty_push(&f, e));
    p.settle();
    assert!(last_serve(&p.a).is_some());
    assert_eq!(p.a.conn.backlog(), 0, "the reply waits in the engine");
    assert_eq!(p.b.store.len(), 0);
    assert!(!p.a.saw(|ev| matches!(ev, Event::Room)));
    p.a.unsent = 0;
    p.advance(s(5));
    assert!(p.a.saw(|ev| matches!(ev, Event::Room)));
    assert_eq!(p.b.store.len(), 3);
}

#[test]
fn push_dropped_owes_an_empty_push_and_a_round() {
    // PUSH-1: A's send queue is full: its push is dropped, an empty push
    // waits and goes when there is room, and B's owed round fetches it.
    let mut p = pair_with(&[], &[]);
    let h = records(1, 2, 1);
    p.a.unsent = MAX_SEND_QUEUE - 10;
    assert!(p.a.push(p.now, &h[..1]).is_empty(), "dropped");
    let owed = p.a.conn.backlog();
    assert!(owed > 0, "the empty push waits");
    assert!(p.a.push_page(p.now, &h[..1], 1).is_empty());
    assert_eq!(p.a.conn.backlog(), owed, "one empty push owed, not two");
    p.a.unsent = 0;
    p.advance(s(2));
    assert!(p.b.saw(|ev| matches!(ev, Event::EmptyPush { .. })));
    assert_eq!(p.b.store.len(), 1);
    // A second empty push within INDEX_RESYNC_INTERVAL of the owed round's
    // start: the flag kept, the next round once the interval has passed, and
    // the record dropped in between held at the end.
    let start = p.now - s(2);
    p.a.unsent = MAX_SEND_QUEUE - 10;
    assert!(p.a.push(p.now, &h[1..]).is_empty());
    p.a.unsent = 0;
    p.advance(s(1));
    let f = p.b.folder_id();
    assert!(p.b.conn.round_owed(&f));
    assert_eq!(p.b.store.len(), 1);
    p.advance_to(start + s(9));
    assert_eq!(p.b.store.len(), 1);
    p.advance_to(start + s(15));
    assert_eq!(p.b.store.len(), 2);
    assert!(!p.b.conn.round_owed(&f));
}

#[test]
fn the_reply_deadline() {
    // The responder never ends its reply: Status and duplicate pushes do not
    // restart REPLY_PAGE_TIMEOUT; the requester closes with TIMEOUT.
    let mut p = pair_with(&records(1, 1, 1), &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    p.a.serving = false;
    p.b.receive(p.now, &empty_push(&f, e));
    p.settle();
    let start = p.now;
    let dup = records(1, 1, 1);
    for minute in 1..10 {
        p.advance_to(start + s(60 * minute));
        p.a.push_page(p.now, &dup, 0);
        p.settle();
    }
    assert_eq!(p.b.conn.state(), State::Established);
    p.advance_to(start + s(599));
    assert_eq!(p.b.conn.state(), State::Established);
    p.advance_to(start + s(602));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::Timeout, Some(Cause::ReplyPageTimeout)))
    );
    // A push that brings a new record restarts it.
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    p.a.serving = false;
    p.b.receive(p.now, &empty_push(&f, e));
    p.settle();
    let start = p.now;
    p.advance_to(start + s(500));
    p.a.push(p.now, &records(7, 1, 1));
    p.settle();
    p.advance_to(start + s(700));
    assert_eq!(p.b.conn.state(), State::Established);
    p.advance_to(start + s(1102));
    assert_eq!(
        closed(&p.b).map(|c| c.1),
        Some(Some(Cause::ReplyPageTimeout))
    );
}

#[test]
fn the_reply_deadline_starts_when_the_request_leaves_the_queue() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    p.a.serving = false;
    p.b.unsent = MAX_SEND_QUEUE - 1;
    p.b.receive(p.now, &empty_push(&f, e));
    assert!(p.b.conn.backlog() > 0, "the request waits in the backlog");
    let start = p.now;
    for minute in 1..=20 {
        p.b.unsent = MAX_SEND_QUEUE - 1 - minute;
        p.advance_to(start + s(60 * minute as u64));
    }
    assert_eq!(closed(&p.b), None, "a paced queue keeps it open");
    p.b.unsent = 0;
    p.advance(s(1));
    let left = p.now;
    p.advance_to(left + s(599));
    assert_eq!(p.b.conn.state(), State::Established);
    p.advance_to(left + s(602));
    assert_eq!(
        closed(&p.b).map(|c| c.1),
        Some(Some(Cause::ReplyPageTimeout))
    );
}

#[test]
fn the_reply_deadline_starts_when_unsent_falls_past_the_request() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let e = p.a.store.epoch;
    p.a.serving = false;
    p.b.unsent = 1 << 20;
    p.b.receive(p.now, &empty_push(&f, e));
    assert_eq!(p.b.conn.backlog(), 0, "handed over");
    assert!(!reconciles(&p.b).is_empty());
    let start = p.now;
    p.advance_to(start + s(900));
    assert_eq!(closed(&p.b), None, "not yet departed: no deadline");
    p.b.unsent = 0;
    p.advance(s(1));
    let left = p.now;
    p.advance_to(left + s(599));
    assert_eq!(p.b.conn.state(), State::Established);
    p.advance_to(left + s(602));
    assert_eq!(
        closed(&p.b).map(|c| c.1),
        Some(Some(Cause::ReplyPageTimeout))
    );
}

#[test]
fn idle_and_stalled_delivery() {
    let mut p = pair_with(&[], &[]);
    p.advance(s(299));
    assert_eq!(p.a.conn.state(), State::Established);
    p.a.auto = false;
    p.b.auto = false;
    p.advance(s(301));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::Timeout, Some(Cause::IdleTimeout)))
    );
    let mut p = pair_with(&[], &[]);
    p.a.auto = false;
    p.a.unsent = 1000;
    let out = p.a.conn.wake(p.a.tick(p.now));
    p.a.apply(p.now, out);
    let start = p.now;
    for k in 1..=11u64 {
        p.advance_to(start + s(29 * k));
    }
    assert_eq!(closed(&p.a).map(|c| c.1), Some(Some(Cause::IdleTimeout)));
}

#[test]
fn pages_for_no_request_and_records_that_fail_step_one_close() {
    let malformed = Some((CloseReason::ProtocolError, Some(Cause::Malformed)));
    let mut p = pair_with(&[], &[]);
    let f = p.a.folder_id();
    let page = |records: Vec<Vec<u8>>, request_id: u32, folder: Vec<u8>| IndexRecords {
        folder_id: folder,
        records,
        request_id,
        epoch: 1,
        ..IndexRecords::default()
    };
    p.a.receive(
        p.now,
        &frame(&Message::IndexRecords(page(vec![], 99, f.0.to_vec()))),
    );
    assert_eq!(closed(&p.a), malformed);
    let mut p = pair_with(&[], &[]);
    let alien = signed(&folder(0x20), 1, 1, 1);
    p.a.receive(
        p.now,
        &frame(&Message::IndexRecords(page(
            vec![alien.to_bytes()],
            0,
            f.0.to_vec(),
        ))),
    );
    assert_eq!(closed(&p.a), malformed, "a record of another folder");
    let mut p = pair_with(&[], &[]);
    p.a.receive(
        p.now,
        &frame(&Message::IndexRecords(page(vec![], 0, vec![9; 32]))),
    );
    assert_eq!(closed(&p.a), malformed, "a folder not open here");
    let mut p = pair_with(&[], &[]);
    let request = ReconcileRequest {
        folder_id: vec![9; 32],
        request_id: 3,
        prefix: vec![],
        digest: vec![0; 32],
    };
    p.a.receive(p.now, &frame(&Message::ReconcileRequest(request)));
    assert_eq!(
        closed(&p.a),
        malformed,
        "a reconcile for a folder not open here"
    );
    // A forged record in a push: VERIFICATION_FAILED.
    let mut p = pair_with(&[], &[]);
    let forged = crate::testkit::flipped(&signed(&folder(0x10), 1, 4, 1), 5);
    p.a.push_page(p.now, &[forged], 0);
    p.settle();
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::VerificationFailed, Some(Cause::Forged)))
    );
}

#[test]
fn sending_rules() {
    let mut p = pair_with(&[], &[]);
    let f = p.a.folder_id();
    let t = Tick::at(p.now);
    let page = |records: Vec<Vec<u8>>, more: bool, request_id: u32| IndexRecords {
        folder_id: f.0.to_vec(),
        records,
        more,
        request_id,
        epoch: 5,
        through: 0,
        reset: false,
    };
    let one = records(1, 1, 1)[0].to_bytes();
    for (bad, why) in [
        (page(vec![one.clone()], true, 0), "a push with more"),
        (
            page(vec![], false, 0),
            "the empty push is the connection's own",
        ),
        (page(vec![one.clone()], false, 5), "a push has request_id 0"),
        (
            IndexRecords {
                reset: true,
                ..page(vec![one.clone()], false, 0)
            },
            "a push with reset",
        ),
        (
            IndexRecords {
                epoch: 0,
                ..page(vec![one.clone()], false, 0)
            },
            "epoch 0",
        ),
    ] {
        assert_eq!(
            p.a.conn.push(t, &bad).err(),
            Some(SendError::Malformed),
            "{why}"
        );
    }
    assert_eq!(
        p.a.conn.send_page(t, &page(vec![], false, 5)).err(),
        Some(SendError::UnknownRequest)
    );
    assert_eq!(
        p.a.conn.send_reset(t, f, 5, 1, false).err(),
        Some(SendError::UnknownRequest)
    );
    let elsewhere = IndexRecords {
        folder_id: vec![3; 32],
        ..page(vec![one.clone()], false, 0)
    };
    assert_eq!(
        p.a.conn.push(t, &elsewhere).err(),
        Some(SendError::FolderNotOpen)
    );
    assert_eq!(
        p.a.conn.send_reset(t, FolderId([3; 32]), 5, 1, false).err(),
        Some(SendError::FolderNotOpen)
    );
    let short = IndexRecords {
        folder_id: vec![3; 31],
        ..page(vec![one.clone()], false, 0)
    };
    assert_eq!(p.a.conn.push(t, &short).err(), Some(SendError::Malformed));
    assert_eq!(
        p.a.conn
            .push(t, &page(vec![one.clone(); MAX_PAGE_RECORDS + 1], false, 0))
            .err(),
        Some(SendError::PageTooLong)
    );
    let store = p.a.store.clone();
    assert_eq!(
        p.a.conn.send_request(t, f, &store).err(),
        Some(SendError::NotDue)
    );
    // An IndexRequest being served: pages within its limit, a page with more
    // holds a record, no reset page through send_page, epoch never 0; and a
    // reconcile reply is the wrong kind for it.
    let mut q = open_with(
        |q| {
            let epoch = q.a.store.epoch;
            q.b.store.peers.insert(device_a(), (epoch, 0));
        },
        |_| {},
    );
    q.a.serving = false;
    let fq = q.b.folder_id();
    let e = q.a.store.epoch;
    q.a.events.clear();
    q.b.receive(q.now, &empty_push(&fq, e));
    q.settle();
    let Some(Event::ServeIndex { request: r, .. }) = last_serve(&q.a) else {
        panic!()
    };
    let tq = Tick::at(q.now);
    let served = |records: Vec<Vec<u8>>, more: bool| IndexRecords {
        folder_id: fq.0.to_vec(),
        records,
        more,
        request_id: r.request_id,
        epoch: e,
        through: 0,
        reset: false,
    };
    assert_eq!(
        q.a.conn.send_page(tq, &served(vec![], true)).err(),
        Some(SendError::Malformed)
    );
    assert_eq!(
        q.a.conn
            .send_page(
                tq,
                &IndexRecords {
                    reset: true,
                    ..served(vec![], false)
                }
            )
            .err(),
        Some(SendError::Malformed)
    );
    assert_eq!(
        q.a.conn
            .send_page(
                tq,
                &IndexRecords {
                    epoch: 0,
                    ..served(vec![], false)
                }
            )
            .err(),
        Some(SendError::Malformed)
    );
    assert_eq!(
        q.a.conn
            .send_page(tq, &served(vec![one.clone(); r.page_limit + 1], true))
            .err(),
        Some(SendError::PageTooLong)
    );
    let Part::Reconcile(wrong) = outcome_reply(&fq, r.request_id, e, ReconcileOutcome::Equal, 0)
    else {
        panic!()
    };
    assert_eq!(
        q.a.conn.send_reconcile_reply(tq, &wrong).err(),
        Some(SendError::Malformed),
        "the wrong kind"
    );
    assert_eq!(
        q.a.conn.send_reset(tq, fq, r.request_id, 0, false).err(),
        Some(SendError::Malformed)
    );
    let out = q.a.conn.send_page(tq, &served(vec![], false)).unwrap();
    assert_eq!(out.frames.len(), 1);
    // A ReconcileRequest being served: the reply's shape, then RECORDS pages
    // carry no through and are not resets.
    let (mut p2, f2, id) = scripted(1);
    let e2 = p2.a.store.epoch;
    let t2 = Tick::at(p2.now);
    let reply =
        |outcome: ReconcileOutcome, children: usize, through: u64, epoch: u64| ReconcileReply {
            folder_id: f2.0.to_vec(),
            request_id: id,
            outcome: outcome.as_u32(),
            children: vec![vec![1; 32]; children],
            epoch,
            through,
        };
    for (bad, why) in [
        (reply(ReconcileOutcome::Children, 15, 0, e2), "15 children"),
        (
            reply(ReconcileOutcome::Equal, 16, 0, e2),
            "children on EQUAL",
        ),
        (reply(ReconcileOutcome::Equal, 0, 0, 0), "epoch 0"),
        (
            ReconcileReply {
                outcome: 9,
                ..reply(ReconcileOutcome::Equal, 0, 0, e2)
            },
            "outcome 9",
        ),
        (
            ReconcileReply {
                children: vec![vec![1; 31]; 16],
                ..reply(ReconcileOutcome::Children, 0, 0, e2)
            },
            "a child of 31 bytes",
        ),
    ] {
        assert_eq!(
            p2.a.conn.send_reconcile_reply(t2, &bad).err(),
            Some(SendError::Malformed),
            "{why}"
        );
    }
    let page_before = IndexRecords {
        folder_id: f2.0.to_vec(),
        request_id: id,
        epoch: e2,
        ..IndexRecords::default()
    };
    assert_eq!(
        p2.a.conn.send_page(t2, &page_before).err(),
        Some(SendError::Malformed),
        "pages only after RECORDS"
    );
    assert_eq!(
        p2.a.conn.send_reset(t2, f2, id, e2, false).err(),
        Some(SendError::Malformed),
        "no reset for a ReconcileRequest"
    );
    p2.a.conn
        .send_reconcile_reply(t2, &reply(ReconcileOutcome::Records, 0, 1, e2))
        .unwrap();
    assert_eq!(
        p2.a.conn
            .send_page(
                t2,
                &IndexRecords {
                    through: 1,
                    ..page_before.clone()
                }
            )
            .err(),
        Some(SendError::Malformed),
        "a RECORDS page carries no through"
    );
    assert_eq!(
        p2.a.conn
            .send_page(
                t2,
                &IndexRecords {
                    records: vec![one.clone(); MAX_PAGE_RECORDS + 1],
                    more: true,
                    ..page_before.clone()
                }
            )
            .err(),
        Some(SendError::PageTooLong)
    );
    p2.a.conn.send_page(t2, &page_before).unwrap();
    // Room, exactly at MAX_SEND_QUEUE.
    let at = |unsent| Tick { now: p.now, unsent };
    assert!(p.a.conn.has_room(at(MAX_SEND_QUEUE - 101), 100));
    assert!(!p.a.conn.has_room(at(MAX_SEND_QUEUE - 100), 100));
    let push = page(vec![one.clone()], false, 0);
    let len = Message::IndexRecords(push.clone())
        .to_frame()
        .unwrap()
        .wire_len();
    let out = p.a.conn.push(at(MAX_SEND_QUEUE - len), &push).unwrap();
    assert!(
        out.frames.iter().all(|fr| fr.len() != len),
        "unsent + frame at MAX_SEND_QUEUE: dropped"
    );
    let mut p = pair_with(&[], &[]);
    let out = p.a.conn.push(at(MAX_SEND_QUEUE - len - 1), &push).unwrap();
    assert_eq!(out.frames.len(), 1, "a byte below: handed over");
    assert!(!p.a.conn.has_room(at(0), 1));
    assert!(p.a.conn.has_room(at(0), 0));
    for e in [
        SendError::NotEstablished,
        SendError::Closed,
        SendError::FolderNotOpen,
        SendError::Malformed,
        SendError::TooLarge,
        SendError::WouldBlock { len: 7 },
        SendError::NotDue,
        SendError::UnknownRequest,
        SendError::PageTooLong,
        SendError::InFlightFull,
        SendError::AlreadyRequested,
        SendError::BackingOff,
        SendError::PassWaiting,
        SendError::OutOfOrder,
        SendError::Unrequested,
        SendError::Corrupt,
    ] {
        assert_ne!(e.to_string(), "");
    }
    // Before the handshake ends nothing goes.
    let key = licketysync_keys::folder::FolderKey::from(folder(0x10));
    let mut q = Pair::new(0xa0, 0xb0, &[key], &[]);
    assert_eq!(
        q.a.conn.send_status(Tick::default(), &[]).err(),
        Some(SendError::NotEstablished)
    );
    assert_eq!(
        q.a.conn
            .push(Tick::default(), &page(vec![one], false, 0))
            .err(),
        Some(SendError::NotEstablished)
    );
    assert_eq!(
        q.a.conn.send_request(Tick::default(), f, &store).err(),
        Some(SendError::NotEstablished)
    );
    q.settle();
}

#[test]
fn the_memories_of_a_connection_are_bounded() {
    let mut p = pair_with(&[], &[]);
    let f = p.b.folder_id();
    let tick = p.b.tick(p.now);
    let (m, _) = p.b.conn.memories_mut(tick, &f).unwrap();
    for i in 0..=crate::limits::MAX_FUTURE_KNOWN {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(i as u64).to_be_bytes());
        m.remember_future(licketysync_keys::RecordHash(h));
    }
    assert_eq!(m.future().count(), crate::limits::MAX_FUTURE_KNOWN);
    assert!(
        !m.knows_future(&licketysync_keys::RecordHash([0; 32])),
        "the oldest forgotten"
    );
    let mut h1 = [0u8; 32];
    h1[..8].copy_from_slice(&1u64.to_be_bytes());
    assert!(m.knows_future(&licketysync_keys::RecordHash(h1)));
    m.remember_future(licketysync_keys::RecordHash(h1));
    assert_eq!(m.future().count(), crate::limits::MAX_FUTURE_KNOWN, "once");
    assert!(p.b.conn.peer_device().is_some());
}

/// The note-verification budget is one per connection, shared by every
/// folder open on it, and refilled once a window of `INDEX_RESYNC_INTERVAL`
/// has passed, not at a round's end (`protocol.md` 4.5 "Stale copies"; the
/// coordinator's ruling PS-1).
#[test]
fn one_note_budget_per_connection_ps1() {
    let keys = [
        licketysync_keys::folder::FolderKey::from(folder(0x10)),
        licketysync_keys::folder::FolderKey::from(folder(0x20)),
    ];
    let mut p = Pair::new(0xa0, 0xb0, &keys, &keys);
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    let (f, g) = (
        keys[0].verifier().folder_id(),
        keys[1].verifier().folder_id(),
    );
    assert!(p.b.conn.is_open(&f) && p.b.conn.is_open(&g));
    let start = p.now;
    let half = crate::limits::MAX_NOTE_VERIFICATIONS / 2;
    for (folder, n) in [(f, half), (g, crate::limits::MAX_NOTE_VERIFICATIONS - half)] {
        let (_, notes) = p.b.conn.memories_mut(Tick::at(start), &folder).unwrap();
        for _ in 0..n {
            assert!(notes.may_verify());
            notes.verified();
        }
    }
    let (_, notes) = p.b.conn.memories_mut(Tick::at(start), &f).unwrap();
    assert!(!notes.may_verify(), "both folders spent the one budget");
    // A round's end does not refill it; the window's end does.
    let out = p.b.conn.owe_round(p.b.tick(p.now), f);
    p.b.apply(p.now, out);
    p.b.pump(p.now);
    p.advance(s(5));
    let late = start + crate::limits::INDEX_RESYNC_INTERVAL - Duration::from_millis(1);
    let (_, notes) = p.b.conn.memories_mut(Tick::at(late), &g).unwrap();
    assert!(!notes.may_verify(), "still the window's budget");
    let next = start + crate::limits::INDEX_RESYNC_INTERVAL;
    let (_, notes) = p.b.conn.memories_mut(Tick::at(next), &g).unwrap();
    assert!(notes.may_verify(), "a new window, a new budget");
}

proptest! {
    #![proptest_config(crate::testkit::proptest_config(16))]

    /// Whatever a responder answers (EQUAL, CHILDREN of any digests where
    /// they are allowed, RECORDS of nothing), a pass never sends more than
    /// its cap, its work list never passes MAX_WORK_LIST, and no round runs
    /// more than MAX_RECONCILE_PASSES passes.
    #[test]
    fn a_pass_is_bounded_whatever_the_responder_answers(
        answers in proptest::collection::vec((0u8..3, any::<u8>()), 1..120),
        cap in 2usize..40,
    ) {
        let (mut p, f, mut id) = scripted(1);
        p.b.store.lying = true;
        p.b.conn.set_pass_cap(&f, cap);
        let e = p.a.store.epoch;
        let mut passes_seen = 1;
        for (kind, seed) in answers {
            let Some(Event::ServeReconcile { request, .. }) = last_serve(&p.a) else { break };
            if request.request_id != id { break; }
            let before = p.a.events.len();
            let full = request.prefix.is_full();
            match kind {
                0 => a_sends(&mut p, outcome_reply(&f, id, e, ReconcileOutcome::Equal, u64::from(request.prefix.is_root()))),
                1 if !full => a_sends(&mut p, children_reply(&f, id, e, &lies(seed))),
                _ => {
                    a_sends(&mut p, outcome_reply(&f, id, e, ReconcileOutcome::Records, u64::from(request.prefix.is_root())));
                    a_sends(&mut p, records_page(&f, id, e, &[]));
                }
            }
            prop_assert!(p.b.conn.work_list_len(&f) <= MAX_WORK_LIST);
            if let Some((pass, sent)) = p.b.conn.pass_of(&f) {
                prop_assert!(sent <= cap);
                prop_assert!(pass <= MAX_RECONCILE_PASSES);
                passes_seen = passes_seen.max(pass);
            }
            p.advance(s(2));
            let next = p.a.events[before..].iter().find_map(|ev| match ev {
                Event::ServeReconcile { request, .. } => Some(request.request_id),
                _ => None,
            });
            match next {
                Some(n) => id = n,
                None => break,
            }
        }
        prop_assert!(passes_seen <= MAX_RECONCILE_PASSES);
        prop_assert_eq!(p.b.conn.state(), State::Established);
    }
}
