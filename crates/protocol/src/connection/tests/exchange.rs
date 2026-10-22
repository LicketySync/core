// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, WriterDigest};

use crate::connection::{Config, Due, Event, MarkKind, Page, SendError, Side, State, Tick};
use crate::exchange::{range_request, Pager, ServeRequest, WriterCursor};
use crate::limits::{MAX_CURSORS_PER_REQUEST, MAX_MARKED_WRITERS, MAX_SEND_QUEUE};
use crate::messages::{CloseReason, IndexRecords, IndexRequest, Message};
use crate::parse::Parse;
use crate::record::Judgement;
use crate::rules::Cause;
use crate::testkit::{folder, s, signed, Pair, Reply};

fn requests(side: &crate::testkit::Side) -> Vec<IndexRequest> {
    side.sent
        .iter()
        .filter(|(_, f)| f[4..6] == [0x80, 0x07])
        .map(|(_, f)| IndexRequest::parse(&f[6..]).unwrap())
        .collect()
}

fn pages(side: &crate::testkit::Side) -> Vec<IndexRecords> {
    side.sent
        .iter()
        .filter(|(_, f)| f[4..6] == [0x80, 0x08])
        .map(|(_, f)| IndexRecords::parse(&f[6..]).unwrap())
        .collect()
}

fn closed(side: &crate::testkit::Side) -> Option<(CloseReason, Option<Cause>)> {
    side.events.iter().find_map(|e| match e {
        Event::Closed {
            reason,
            by: Side::Local,
            cause,
            ..
        } => Some((*reason, *cause)),
        _ => None,
    })
}

/// The requests handed to the engine to serve, in order.
fn serves(side: &crate::testkit::Side) -> Vec<ServeRequest> {
    side.events
        .iter()
        .filter_map(|e| match e {
            Event::Serve { request, .. } => Some(request.clone()),
            _ => None,
        })
        .collect()
}

/// Records of writer `w` at sequences `1..=n`, salt `salt`.
fn history(w: u8, n: u64, salt: u8) -> Vec<SignedRecord> {
    let key = folder(0x10);
    (1..=n).map(|seq| signed(&key, w, seq, salt)).collect()
}

fn dev(n: u32) -> DeviceId {
    let mut d = [0u8; 32];
    d[28..].copy_from_slice(&n.to_be_bytes());
    DeviceId(d)
}

/// `n` cursors of writers `dev(0)..dev(n - 1)` at seq 1.
fn fake_cursors(n: u32) -> Vec<WriterCursor> {
    (0..n)
        .map(|i| WriterCursor {
            writer: dev(i),
            seq: 1,
            digest: Some(WriterDigest([7; 32])),
        })
        .collect()
}

/// An empty push: the peer dropped pushes, this side owes a round.
fn empty_push(f: &licketysync_keys::FolderId) -> Vec<u8> {
    Message::IndexRecords(IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![],
        more: false,
        request_id: 0,
    })
    .to_frame()
    .unwrap()
    .encode()
}

/// A pair whose sides start with these records, then open; B configured.
fn pair_configured(
    a: &[SignedRecord],
    b: &[SignedRecord],
    config_b: impl FnOnce(&mut Config),
) -> Pair {
    let key = licketysync_keys::folder::FolderKey::from(folder(0x10));
    let mut p = Pair::with(
        0xa0,
        0xb0,
        &[key],
        &[licketysync_keys::folder::FolderKey::from(folder(0x10))],
        |_| {},
        config_b,
    );
    let v = *folder(0x10).verifier();
    for r in a {
        p.a.store.insert_signed(r, &v);
    }
    for r in b {
        p.b.store.insert_signed(r, &v);
    }
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    // Requests after the round on open are served INDEX_REQUEST_MIN_INTERVAL
    // apart: let them run.
    p.advance(s(5));
    p
}

/// A pair whose sides start with these records, then open.
fn pair_with(a: &[SignedRecord], b: &[SignedRecord]) -> Pair {
    pair_configured(a, b, |_| {})
}

/// Sends every page of `reply` from A by hand.
fn serve_all(p: &mut Pair, reply: &mut Reply) {
    loop {
        let page = reply.next_page(p.a.conn.peer_max_message_size());
        let out = p.a.conn.send_page(Tick::at(p.now), &page, &[]).unwrap();
        p.a.apply(p.now, out);
        if !page.more {
            return;
        }
    }
}

#[test]
fn the_round_on_open_brings_each_side_what_it_lacks() {
    let p = pair_with(&history(1, 3, 1), &history(2, 2, 1));
    assert_eq!(p.a.store.len(), 5);
    assert_eq!(p.b.store.all(), p.a.store.all());
    // One request each, with have empty and no range, then cursors.
    let ra = requests(&p.a);
    assert_eq!(ra.len(), 1);
    assert_eq!(ra[0].have.len(), 1, "A's own writer");
    assert!(ra[0].after.is_empty() && ra[0].through.is_empty() && !ra[0].listed);
}

#[test]
fn concurrent_versions_converge_at_equal_cursors() {
    // TM-41, ruling R-K5: two records of one writer at seq 1, one each side;
    // equal cursors, different digests: case (c) both ways, then the listed
    // request finds equal digests.
    let a = history(1, 1, 1);
    let b = history(1, 1, 2);
    assert_ne!(a[0].hash(), b[0].hash());
    let p = pair_with(&a, &b);
    assert_eq!(p.a.store.len(), 2);
    assert_eq!(p.a.store.all(), p.b.store.all());
    assert!(
        requests(&p.a).iter().any(|r| r.listed),
        "the mark's listed request"
    );
    let w = DeviceId([1; 32]);
    assert_eq!(p.a.store.digest_at(&w, 1), p.b.store.digest_at(&w, 1));
}

#[test]
fn a_concurrent_version_behind_a_lower_cursor_converges() {
    // A: W1, W2. B: W1' only (concurrent with W1). B's cursor is lower: A
    // compares at B's seq 1 (case (c)), B serves nothing for A's cursor 2
    // (case (d)), and A's listed request brings W1' back.
    let a = history(1, 2, 1);
    let b = history(1, 1, 2);
    let p = pair_with(&a, &b);
    assert_eq!(p.a.store.len(), 3);
    assert_eq!(p.a.store.all(), p.b.store.all());
}

#[test]
fn a_matching_digest_gets_the_increment_only() {
    let all = history(1, 5, 1);
    let p = pair_with(&all, &all[..2]);
    assert_eq!(p.b.store.len(), 5);
    // A served B's cursor 2 by case (b): three records.
    let served: usize = pages(&p.a).iter().map(|pg| pg.records.len()).sum();
    assert_eq!(served, 3);
}

#[test]
fn a_push_between_two_pages_of_a_reply_is_told_apart() {
    // R1-SF4: A serves B's request by hand, page 1, then a push of a record
    // it newly accepted, then page 2; B tells them apart by request_id and
    // holds everything at the end. B asks with max_records = 1, served as 64.
    let mut p = pair_configured(&[], &[], |c| c.max_records = 1);
    let v = p.a.verifier();
    for r in history(3, 100, 1) {
        p.a.store.insert_signed(&r, &v);
    }
    let folder = p.a.folder_id();
    p.a.serving = false;
    p.b.events.clear();
    p.b.receive(p.now, &empty_push(&folder));
    p.settle();
    let request = serves(&p.a).pop().unwrap();
    assert_eq!(request.page_limit, 64);
    let mut reply = Reply::new(folder, &request, &p.a.store);
    let max = p.a.conn.peer_max_message_size();
    let first = reply.next_page(max);
    assert!(first.more && first.records.len() == 64);
    let out = p.a.conn.send_page(Tick::at(p.now), &first, &[]).unwrap();
    p.a.apply(p.now, out);
    let fresh = history(4, 1, 1);
    p.a.store.insert_signed(&fresh[0], &v);
    assert_eq!(p.a.push(p.now, &fresh).len(), 1, "the push went");
    let second = reply.next_page(max);
    assert!(!second.more && second.records.len() == 36);
    let out = p.a.conn.send_page(Tick::at(p.now), &second, &[]).unwrap();
    p.a.apply(p.now, out);
    p.settle();
    let id = request.request_id;
    let got: Vec<Page> =
        p.b.events
            .iter()
            .filter_map(|e| match e {
                Event::Records { page, .. } => Some(*page),
                _ => None,
            })
            .collect();
    assert_eq!(
        got,
        vec![
            Page::Reply {
                request_id: id,
                last: false
            },
            Page::Push,
            Page::Reply {
                request_id: id,
                last: true
            },
        ]
    );
    assert!(p.b.saw(|e| matches!(e, Event::RoundCompleted { .. })));
    assert_eq!(p.b.store.len(), 101);
}

#[test]
fn one_request_at_a_time_and_the_serving_interval() {
    let mut p = pair_with(&history(1, 1, 1), &[]);
    let folder = p.a.folder_id();
    p.b.auto = false;
    p.a.auto = false;
    p.a.events.clear();
    // B's owed round: request 1.
    p.b.receive(p.now, &empty_push(&folder));
    p.b.request(p.now).unwrap();
    // Not due any more: the connection refuses a second.
    assert_eq!(p.b.request(p.now).err(), Some(SendError::NotDue));
    p.deliver();
    let first = serves(&p.a).pop().unwrap();
    let at = p.now;
    let mut reply = Reply::new(folder, &first, &p.a.store);
    serve_all(&mut p, &mut reply);
    p.deliver();
    // B marks a writer (a full resend): a listed request goes at once, and A
    // holds it until INDEX_REQUEST_MIN_INTERVAL after it began serving the
    // first: delayed, never refused.
    let out =
        p.b.conn
            .mark(Tick::at(p.now), folder, DeviceId([1; 32]), MarkKind::Resend);
    p.b.apply(p.now, out);
    p.b.request(p.now).unwrap();
    let listed_id = requests(&p.b).last().unwrap().request_id;
    p.deliver();
    assert_eq!(serves(&p.a).len(), 1, "held");
    assert_eq!(p.a.wake, Some(at + s(1)), "the one wake-up serves it");
    let early = IndexRecords {
        folder_id: folder.0.to_vec(),
        records: vec![],
        more: false,
        request_id: listed_id,
    };
    assert_eq!(
        p.a.conn.send_page(Tick::at(p.now), &early, &[]).err(),
        Some(SendError::UnknownRequest),
        "a held request is not the engine's yet"
    );
    p.now = at + s(1);
    p.a.wake(p.now);
    let second = serves(&p.a).pop().unwrap();
    assert_eq!(second.request_id, listed_id);
    // A second request from B before the reply's last page: closes.
    let again = Message::IndexRequest(IndexRequest {
        request_id: 77,
        ..requests(&p.b).pop().unwrap()
    });
    p.a.receive(p.now, &again.to_frame().unwrap().encode());
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
}

#[test]
fn the_serving_interval_counts_from_when_serving_began() {
    // R1 N5: the engine began serving the first request 5 s after it came;
    // the next request is held until a second after that, not after when the
    // first could have been served.
    let mut p = pair_with(&history(1, 1, 1), &[]);
    let folder = p.a.folder_id();
    p.b.auto = false;
    p.a.auto = false;
    p.a.events.clear();
    p.b.receive(p.now, &empty_push(&folder));
    p.b.request(p.now).unwrap();
    p.deliver();
    let first = serves(&p.a).pop().unwrap();
    p.now += s(5);
    let began = p.now;
    let mut reply = Reply::new(folder, &first, &p.a.store);
    serve_all(&mut p, &mut reply);
    p.deliver();
    let out =
        p.b.conn
            .mark(Tick::at(p.now), folder, DeviceId([1; 32]), MarkKind::Resend);
    p.b.apply(p.now, out);
    p.b.request(p.now).unwrap();
    p.now += core::time::Duration::from_millis(500);
    p.deliver();
    assert_eq!(serves(&p.a).len(), 1, "held");
    assert_eq!(p.a.wake, Some(began + s(1)));
    p.now = began + s(1);
    p.a.wake(p.now);
    assert_eq!(serves(&p.a).len(), 2);
}

#[test]
fn a_reply_waits_for_room_and_goes_on_room() {
    // SF2, SEC-SF2: a reply page never waits in the backlog; the engine keeps
    // it, asks for room and sends it on Event::Room, which the send poll
    // brings once the transport drains.
    let mut p = pair_with(&[], &[]);
    let v = p.a.verifier();
    let folder = p.a.folder_id();
    let later = history(5, 3, 1);
    for r in &later {
        p.a.store.insert_signed(r, &v);
    }
    p.a.unsent = MAX_SEND_QUEUE - 100;
    p.a.events.clear();
    p.b.receive(p.now, &empty_push(&folder));
    p.settle();
    assert_eq!(serves(&p.a).len(), 1);
    assert_eq!(p.a.conn.backlog(), 0, "the page waits in the engine");
    assert_eq!(p.b.store.len(), 0);
    assert!(!p.a.saw(|e| matches!(e, Event::Room)));
    p.a.unsent = 0;
    p.advance(s(2));
    assert!(p.a.saw(|e| matches!(e, Event::Room)));
    assert_eq!(p.b.store.len(), 3);
}

#[test]
fn pages_for_no_request_and_records_that_fail_step_one_close() {
    let mut p = pair_with(&[], &[]);
    let folder = p.a.folder_id();
    let page = Message::IndexRecords(IndexRecords {
        folder_id: folder.0.to_vec(),
        records: vec![],
        more: false,
        request_id: 99,
    });
    p.a.receive(p.now, &page.to_frame().unwrap().encode());
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // A record of another folder in a push.
    let mut p = pair_with(&[], &[]);
    let alien = signed(&crate::testkit::folder(0x20), 1, 1, 1);
    let push = Message::IndexRecords(IndexRecords {
        folder_id: p.a.folder_id().0.to_vec(),
        records: vec![alien.to_bytes()],
        more: false,
        request_id: 0,
    });
    p.a.receive(p.now, &push.to_frame().unwrap().encode());
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // A message for a folder not open here.
    let mut p = pair_with(&[], &[]);
    let other = Message::IndexRecords(IndexRecords {
        folder_id: vec![9; 32],
        records: vec![],
        more: false,
        request_id: 0,
    });
    p.a.receive(p.now, &other.to_frame().unwrap().encode());
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
}

#[test]
fn a_reply_page_for_another_request_id_closes() {
    // R2-SF4: a request of B's is outstanding; a page naming another ID is
    // malformed, and so is a page of the right one with more and no records
    // (SEC-SF3).
    for wrong in [true, false] {
        let mut p = pair_with(&[], &[]);
        let folder = p.b.folder_id();
        p.a.serving = false;
        p.b.receive(p.now, &empty_push(&folder));
        p.settle();
        let id = requests(&p.b).last().unwrap().request_id;
        let page = Message::IndexRecords(IndexRecords {
            folder_id: folder.0.to_vec(),
            records: vec![],
            more: !wrong,
            request_id: if wrong { id.wrapping_add(1).max(1) } else { id },
        });
        p.b.receive(p.now, &page.to_frame().unwrap().encode());
        assert_eq!(
            closed(&p.b),
            Some((CloseReason::ProtocolError, Some(Cause::Malformed))),
            "wrong id {wrong}"
        );
    }
}

#[test]
fn record_outcomes_on_a_push_and_in_a_reply() {
    // A gap on a push: ignored unverified, the writer marked, then a listed
    // request (gap-triggered) fetches it.
    let mut p = pair_with(&history(1, 1, 1), &history(1, 1, 1));
    let h = history(1, 3, 1);
    let v = p.a.verifier();
    p.a.store.insert_signed(&h[1], &v);
    p.a.store.insert_signed(&h[2], &v);
    p.a.push(p.now, &h[2..]);
    p.settle();
    assert_eq!(p.b.store.len(), 3, "the listed request brought seq 2 and 3");
    assert!(requests(&p.b).last().unwrap().listed);
    // A duplicate with a garbage signature: ignored, the connection open.
    let dup = crate::testkit::resigned(&h[0], [0; 64]);
    p.a.push(p.now, &[dup]);
    p.settle();
    assert_eq!(p.b.conn.state(), State::Established);
    // A forged record in a push: VERIFICATION_FAILED.
    let forged = crate::testkit::flipped(&signed(&folder(0x10), 1, 4, 1), 5);
    p.a.push(p.now, &[forged]);
    p.settle();
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::VerificationFailed, Some(Cause::Forged)))
    );
}

#[test]
fn judged_marks_gaps_restarts_the_deadline_and_closes() {
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.b.auto = false;
    let w = DeviceId([3; 32]);
    // A gap on a push marks its writer; non-closing causes leave it open.
    let out = p.b.conn.judged(
        Tick::at(p.now),
        folder,
        Page::Push,
        &[
            (w, Ok(Judgement::PushGap)),
            (w, Ok(Judgement::Duplicate)),
            (w, Err(Cause::Duplicate)),
        ],
    );
    p.b.apply(p.now, out);
    assert_eq!(p.b.conn.marks(&folder), vec![(w, MarkKind::Gap)]);
    assert_eq!(p.b.conn.state(), State::Established);
    // A close stops the rest.
    let out = p.b.conn.judged(
        Tick::at(p.now),
        folder,
        Page::Push,
        &[
            (w, Err(Cause::Forged)),
            (DeviceId([4; 32]), Ok(Judgement::PushGap)),
        ],
    );
    p.b.apply(p.now, out);
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::VerificationFailed, Some(Cause::Forged)))
    );
}

#[test]
fn a_gap_in_a_reply_is_a_sender_violation() {
    let mut p = pair_with(&[], &[]);
    let folder = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    p.b.receive(p.now, &empty_push(&folder));
    p.b.request(p.now).unwrap();
    let id = requests(&p.b).last().unwrap().request_id;
    // A reply carrying seq 2 of a writer B holds none of; valid signature.
    let gap = history(1, 2, 1).pop().unwrap();
    let reply = Message::IndexRecords(IndexRecords {
        folder_id: folder.0.to_vec(),
        records: vec![gap.to_bytes()],
        more: false,
        request_id: id,
    });
    p.b.auto = true;
    p.b.receive(p.now, &reply.to_frame().unwrap().encode());
    assert_eq!(p.b.reported, vec![Cause::SenderViolation]);
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::SenderViolation)))
    );
}

#[test]
fn a_writer_outside_a_listed_request_is_out_of_scope() {
    let mut p = pair_with(&[], &[]);
    let folder = p.a.folder_id();
    p.b.auto = false;
    let out =
        p.b.conn
            .mark(Tick::at(p.now), folder, DeviceId([5; 32]), MarkKind::Resend);
    p.b.apply(p.now, out);
    assert!(p.b.saw(|e| matches!(
        e,
        Event::RequestDue {
            due: Due::Listed { .. },
            ..
        }
    )));
    p.b.request(p.now).unwrap();
    let id = requests(&p.b).last().unwrap().request_id;
    assert!(
        p.b.conn.marks(&folder).is_empty(),
        "sending clears the marks it lists"
    );
    let other = history(6, 1, 1).pop().unwrap();
    let reply = Message::IndexRecords(IndexRecords {
        folder_id: folder.0.to_vec(),
        records: vec![other.to_bytes()],
        more: false,
        request_id: id,
    });
    let events = p.b.receive(p.now, &reply.to_frame().unwrap().encode());
    let Some(Event::Records { records, .. }) = events.first() else {
        panic!()
    };
    assert_eq!(
        records[0].arrival,
        crate::record::Arrival::Reply { in_scope: false }
    );
}

#[test]
fn a_listed_reply_is_not_a_completed_round() {
    // R1-SF3: only a range request's reply without `through` ends a round.
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.b.auto = false;
    let out =
        p.b.conn
            .mark(Tick::at(p.now), folder, dev(1), MarkKind::Resend);
    p.b.apply(p.now, out);
    p.b.events.clear();
    p.b.request(p.now).unwrap();
    assert!(requests(&p.b).last().unwrap().listed);
    p.advance(s(2));
    assert!(p.b.saw(|e| matches!(
        e,
        Event::Records {
            page: Page::Reply { last: true, .. },
            ..
        }
    )));
    assert!(!p.b.saw(|e| matches!(e, Event::RoundCompleted { .. })));
}

#[test]
fn push_dropped_owes_an_empty_push_and_a_round() {
    // PUSH-1: A's send queue is full: its push is dropped, an empty push
    // waits and goes when there is room, and B's owed round fetches it.
    let mut p = pair_with(&[], &[]);
    let h = history(1, 1, 1);
    let v = p.a.verifier();
    p.a.store.insert_signed(&h[0], &v);
    p.a.unsent = MAX_SEND_QUEUE - 10;
    assert!(p.a.push(p.now, &h).is_empty(), "dropped");
    let owed = p.a.conn.backlog();
    assert!(owed > 0, "the empty push waits");
    assert!(p.a.push(p.now, &h).is_empty());
    assert_eq!(p.a.conn.backlog(), owed, "one empty push owed, not two");
    assert!(p.a.outbox.is_empty());
    p.a.unsent = 0;
    p.advance(s(1));
    assert!(p.b.saw(|e| matches!(e, Event::EmptyPush { .. })));
    assert_eq!(p.b.store.len(), 1);
    // Once handed over, the next dropped push owes another.
    p.a.unsent = MAX_SEND_QUEUE - 10;
    p.a.push(p.now, &h);
    assert_eq!(p.a.conn.backlog(), owed);
    p.a.unsent = 0;
    p.advance(s(1));
    // A second empty push within INDEX_RESYNC_INTERVAL of the owed round's
    // start: the flag kept, the next round 10 s after the first began.
    let mut p = pair_with(&[], &[]);
    p.a.store.insert_signed(&h[0], &v);
    p.a.unsent = MAX_SEND_QUEUE - 10;
    p.a.push(p.now, &h);
    p.a.unsent = 0;
    p.advance(s(1));
    let start = p.now - s(1);
    let h2 = history(1, 2, 1);
    p.a.store.insert_signed(&h2[1], &v);
    p.a.unsent = MAX_SEND_QUEUE - 10;
    assert!(p.a.push(p.now, &h2[1..]).is_empty());
    p.a.unsent = 0;
    p.advance(s(1));
    assert!(p.b.conn.round_owed(&p.b.folder_id()));
    assert_eq!(p.b.store.len(), 1);
    p.advance_to(start + s(9));
    assert_eq!(p.b.store.len(), 1);
    p.advance_to(start + s(11));
    assert_eq!(p.b.store.len(), 2);
    assert!(!p.b.conn.round_owed(&p.b.folder_id()));
}

#[test]
fn a_push_is_dropped_while_the_backlog_is_not_empty() {
    // R1-SF3: a push that alone would fit the transport is dropped while
    // frames wait in the backlog; the empty push queues behind them.
    let mut p = pair_with(&[], &[]);
    let folder = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    p.a.receive(p.now, &empty_push(&folder));
    // A's owed round of 16 384 cursors (about 1.3 MiB) waits behind a
    // transport with a MiB of room.
    p.a.unsent = MAX_SEND_QUEUE - (1 << 20);
    let cursors = fake_cursors(16_384);
    let out =
        p.a.conn
            .send_request(p.a.tick(p.now), folder, &cursors[..])
            .unwrap();
    p.a.apply(p.now, out);
    let waiting = p.a.conn.backlog();
    assert!(waiting > 1 << 20, "the request waits");
    let small = history(2, 1, 1);
    let frames = p.a.push(p.now, &small);
    assert!(frames.is_empty(), "dropped, although it alone would fit");
    let empty_len = empty_push(&folder).len();
    assert_eq!(
        p.a.conn.backlog(),
        waiting + empty_len,
        "only the empty push queued behind"
    );
    assert!(!p.a.conn.has_room(p.a.tick(p.now), 1));
}

#[test]
fn marks_set_before_and_after_a_range_request() {
    // MARK: a range request clears the marks for writers in its range set
    // before it was sent; a mark set after it stays, and a listed request
    // serves it once the reply has completed.
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.b.auto = false;
    let (w1, w2) = (DeviceId([1; 32]), DeviceId([2; 32]));
    p.b.receive(p.now, &empty_push(&folder));
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Range { after: None }),
        "the round owed"
    );
    let out = p.b.conn.mark(Tick::at(p.now), folder, w1, MarkKind::Gap);
    p.b.apply(p.now, out);
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Range { after: None }),
        "already due"
    );
    p.b.request(p.now).unwrap();
    assert!(
        p.b.conn.marks(&folder).is_empty(),
        "w1, set before the request, is cleared"
    );
    assert!(
        !p.b.conn.round_owed(&folder),
        "sending the owed round clears the flag"
    );
    let out = p.b.conn.mark(Tick::at(p.now), folder, w2, MarkKind::Resend);
    p.b.apply(p.now, out);
    assert_eq!(
        p.b.conn.marks(&folder),
        vec![(w2, MarkKind::Resend)],
        "set after: kept"
    );
    assert_eq!(p.b.conn.due(&folder), None, "one request at a time");
    p.advance(s(2));
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Listed { writers: vec![w2] })
    );
    p.b.request(p.now).unwrap();
    let listed = requests(&p.b).pop().unwrap();
    assert!(listed.listed);
    assert_eq!(listed.have.len(), 1);
    assert_eq!(listed.have[0].device_id, w2.0.to_vec());
    assert_eq!(listed.have[0].seq, 0, "a writer B holds none of");
    assert!(p.b.conn.marks(&folder).is_empty());
}

#[test]
fn gap_listed_requests_are_rate_limited_and_owed_rounds_go_first() {
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.b.auto = false;
    let w = |n: u8| DeviceId([n; 32]);
    // The first gap mark: its listed request goes at once.
    let out = p.b.conn.mark(Tick::at(p.now), folder, w(1), MarkKind::Gap);
    p.b.apply(p.now, out);
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Listed {
            writers: vec![w(1)]
        })
    );
    let first = p.now;
    p.b.request(p.now).unwrap();
    p.advance(s(2));
    // A second gap mark: due only INDEX_RESYNC_INTERVAL after the first.
    let out = p.b.conn.mark(Tick::at(p.now), folder, w(2), MarkKind::Gap);
    p.b.apply(p.now, out);
    assert_eq!(p.b.conn.due(&folder), None);
    p.advance_to(first + s(9));
    assert_eq!(p.b.conn.due(&folder), None);
    // An empty push meanwhile: the owed round and the listed request fall
    // due together at 10 s, and the owed round goes first (its range covers
    // the marks).
    p.b.receive(p.now, &empty_push(&folder));
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Range { after: None }),
        "the first owed round is not rate-limited"
    );
    p.b.request(p.now).unwrap();
    assert!(
        p.b.conn.marks(&folder).is_empty(),
        "the round's range covered the mark"
    );
    // A resend mark is not rate-limited.
    p.advance(s(2));
    let out =
        p.b.conn
            .mark(Tick::at(p.now), folder, w(3), MarkKind::Resend);
    p.b.apply(p.now, out);
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Listed {
            writers: vec![w(3)]
        })
    );
}

#[test]
fn too_many_marks_owe_a_round_instead() {
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.b.auto = false;
    // Gap marks only, rate-limited after the first listed request.
    for i in 0..=MAX_MARKED_WRITERS + 1 {
        let mut w = [0u8; 32];
        w[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let out =
            p.b.conn
                .mark(Tick::at(p.now), folder, DeviceId(w), MarkKind::Gap);
        p.b.apply(p.now, out);
        if i == 0 {
            // The first goes as a listed request at once; keep it outstanding.
            p.b.request(p.now).unwrap();
        }
        if i == MAX_MARKED_WRITERS {
            assert_eq!(
                p.b.conn.marks(&folder).len(),
                MAX_MARKED_WRITERS,
                "exactly MAX_MARKED_WRITERS kept"
            );
        }
    }
    assert!(p.b.conn.marks(&folder).is_empty(), "1 025 marks: dropped");
    assert!(p.b.conn.round_owed(&folder));
}

#[test]
fn the_reply_deadline() {
    // The responder never sends its last page: Status and duplicate pushes
    // do not restart REPLY_PAGE_TIMEOUT; the requester closes with TIMEOUT.
    let mut p = pair_with(&history(1, 1, 1), &[]);
    let folder = p.b.folder_id();
    p.a.auto = false;
    p.b.receive(p.now, &empty_push(&folder));
    p.settle();
    let start = p.now;
    for minute in 1..10 {
        p.advance_to(start + s(60 * minute));
        // A duplicate push and a Status keep frames moving (idle stays off).
        p.a.push(p.now, &history(1, 1, 1));
        p.settle();
    }
    assert_eq!(p.b.conn.state(), State::Established);
    // The departure is seen at the next poll, within SEND_POLL_INTERVAL.
    p.advance_to(start + s(599));
    assert_eq!(p.b.conn.state(), State::Established);
    p.advance_to(start + s(602));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::Timeout, Some(Cause::ReplyPageTimeout)))
    );
    // A push that brings a new record restarts it.
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.a.auto = false;
    p.b.receive(p.now, &empty_push(&folder));
    p.settle();
    let start = p.now;
    p.advance_to(start + s(500));
    p.a.push(p.now, &history(7, 1, 1));
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
    let folder = p.b.folder_id();
    p.a.serving = false;
    // B's request waits behind a full transport queue that drains slowly.
    p.b.unsent = MAX_SEND_QUEUE - 1;
    p.b.receive(p.now, &empty_push(&folder));
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
    // R1-SF3: the request was handed to the transport at once, but a MiB it
    // had not yet sent lay before it; the deadline counts from when the
    // transport's unsent bytes fell past the request, not from the handing.
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.a.serving = false;
    p.b.unsent = 1 << 20;
    p.b.receive(p.now, &empty_push(&folder));
    assert_eq!(p.b.conn.backlog(), 0, "handed over");
    assert!(!requests(&p.b).is_empty());
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
    // Status every 30 s is a frame both ways; without it the idle timer
    // fires. Turn the engines off so that nobody answers StatusDue.
    p.a.auto = false;
    p.b.auto = false;
    p.advance(s(301));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::Timeout, Some(Cause::IdleTimeout)))
    );
    // Unsent bytes that never fall while A hands nothing more: TIMEOUT after
    // IDLE_TIMEOUT, even though B's Status frames keep arriving.
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
fn sending_rules() {
    let mut p = pair_with(&[], &[]);
    let folder = p.a.folder_id();
    let t = Tick::at(p.now);
    let page = |records: Vec<Vec<u8>>, more: bool, request_id: u32| IndexRecords {
        folder_id: folder.0.to_vec(),
        records,
        more,
        request_id,
    };
    let one = history(1, 1, 1)[0].to_bytes();
    assert_eq!(
        p.a.conn.push(t, &page(vec![one.clone()], true, 0)).err(),
        Some(SendError::Malformed),
        "a push with more"
    );
    assert_eq!(
        p.a.conn.push(t, &page(vec![], false, 0)).err(),
        Some(SendError::Malformed),
        "the empty push is the connection's own"
    );
    assert_eq!(
        p.a.conn.push(t, &page(vec![one.clone()], false, 5)).err(),
        Some(SendError::Malformed),
        "a push has request_id 0"
    );
    assert_eq!(
        p.a.conn.send_page(t, &page(vec![], false, 5), &[]).err(),
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
    let short = IndexRecords {
        folder_id: vec![3; 31],
        ..page(vec![one.clone()], false, 0)
    };
    assert_eq!(p.a.conn.push(t, &short).err(), Some(SendError::Malformed));
    assert_eq!(
        p.a.conn
            .push(t, &page(vec![one.clone(); 4097], false, 0))
            .err(),
        Some(SendError::PageTooLong)
    );
    assert_eq!(
        p.a.conn.send_request(t, folder, &[][..]).err(),
        Some(SendError::NotDue)
    );
    // A page of a request being served: within its limit, and a page with
    // more holds a record.
    let mut q = pair_with(&[], &[]);
    q.a.serving = false;
    let f = q.b.folder_id();
    q.b.receive(q.now, &empty_push(&f));
    q.settle();
    let r = serves(&q.a).pop().unwrap();
    let tq = Tick::at(q.now);
    let served = |records: Vec<Vec<u8>>, more: bool| IndexRecords {
        folder_id: f.0.to_vec(),
        records,
        more,
        request_id: r.request_id,
    };
    assert_eq!(
        q.a.conn.send_page(tq, &served(vec![], true), &[]).err(),
        Some(SendError::Malformed)
    );
    assert_eq!(
        q.a.conn
            .send_page(tq, &served(vec![one.clone(); r.page_limit + 1], true), &[])
            .err(),
        Some(SendError::PageTooLong)
    );
    let out = q.a.conn.send_page(tq, &served(vec![], false), &[]).unwrap();
    assert_eq!(out.frames.len(), 1);
    // Room, exactly at MAX_SEND_QUEUE: a frame goes while unsent + frame stay
    // below it.
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
        out.frames.iter().all(|f| f.len() != len),
        "unsent + frame at MAX_SEND_QUEUE: dropped"
    );
    let mut p = pair_with(&[], &[]);
    let out = p.a.conn.push(at(MAX_SEND_QUEUE - len - 1), &push).unwrap();
    assert_eq!(out.frames.len(), 1, "a byte below: handed over");
    // SEC N5: what this side handed over counts even when the transport has
    // not reported it yet (a tick read before the frames went).
    assert!(!p.a.conn.has_room(at(0), 1));
    assert!(
        p.a.conn.has_room(at(0), 0),
        "unsent + 0 stays below the queue"
    );
    let pager = Pager::new(64, p.a.conn.peer_max_message_size());
    drop(pager);
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
    let mut q = Pair::new(
        0xa0,
        0xb0,
        &[licketysync_keys::folder::FolderKey::from(
            crate::testkit::folder(0x10),
        )],
        &[],
    );
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
    q.settle();
}

#[test]
fn a_round_of_several_ranges_runs_to_its_end() {
    // A requester with 16 385 writers splits its round in two ranges; the
    // connection asks for the next range after the reply to the first, whose
    // `through` is the 16 384th writer, and the round completes after the
    // one without `through` (4.5; R-K4).
    let mut p = pair_with(&[], &[]);
    let folder = p.b.folder_id();
    p.b.auto = false;
    p.b.events.clear();
    p.b.receive(p.now, &empty_push(&folder));
    let cursors = fake_cursors(16_385);
    let out =
        p.b.conn
            .send_request(Tick::at(p.now), folder, &cursors[..])
            .unwrap();
    p.b.apply(p.now, out);
    let first = requests(&p.b).pop().unwrap();
    assert_eq!(first.have.len(), MAX_CURSORS_PER_REQUEST);
    assert!(first.after.is_empty());
    assert_eq!(first.through, dev(16_383).0.to_vec());
    p.advance(s(2));
    assert_eq!(
        p.b.conn.due(&folder),
        Some(&Due::Range {
            after: Some(dev(16_383))
        })
    );
    assert!(!p.b.saw(|e| matches!(e, Event::RoundCompleted { .. })));
    // The marks of writers in the next range set meanwhile are cleared by it.
    let last = dev(16_384);
    let out = p.b.conn.mark(Tick::at(p.now), folder, last, MarkKind::Gap);
    p.b.apply(p.now, out);
    let out =
        p.b.conn
            .mark(Tick::at(p.now), folder, last, MarkKind::Resend);
    p.b.apply(p.now, out);
    assert_eq!(
        p.b.conn.marks(&folder),
        vec![(last, MarkKind::Resend)],
        "the stronger kind"
    );
    let out =
        p.b.conn
            .send_request(Tick::at(p.now), folder, &cursors[..])
            .unwrap();
    p.b.apply(p.now, out);
    let second = requests(&p.b).pop().unwrap();
    assert_eq!(second.have.len(), 1);
    assert_eq!(second.after, dev(16_383).0.to_vec());
    assert!(second.through.is_empty());
    assert!(p.b.conn.marks(&folder).is_empty());
    p.advance(s(2));
    assert!(p.b.saw(|e| matches!(e, Event::RoundCompleted { .. })));
    assert_eq!(p.b.conn.due(&folder), None);
    // The other split boundaries: 16 384 writers is one request with no
    // range, and a listed request of exactly 16 384 writers is accepted.
    let one = range_request(&folder, None, fake_cursors(16_384), 0).unwrap();
    assert!(one.through.is_empty());
}
