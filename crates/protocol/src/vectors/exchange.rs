// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Item 8: cursors, rounds and pages. The cached-digest vectors are the
//! index crate's; the digests here are the reference values a `Cursor`
//! carries.

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{CipherHash, DeviceId, RecordHash, WriterDigest};
use prost::Message as _;
use serde_json::{json, Value};

use super::{check, ending, feed, h, key, scenario, seed};
use crate::connection::{ChunkAnswer, Due, Event, Tick};
use crate::exchange::{page_limit, range_request, Pager, WriterCursor};
use crate::limits::{MAX_CURSORS_PER_REQUEST, MAX_PAGE_RECORDS, MAX_SEND_QUEUE, MIN_MESSAGE_SIZE};
use crate::messages::{Cursor, IndexRecords, IndexRequest, Message};
use crate::parse::Parse;
use crate::record::writer_digests;
use crate::testkit::{folder, s, signed, Pair, Reply};

fn dev(n: u32) -> DeviceId {
    let mut d = [0u8; 32];
    d[28..].copy_from_slice(&n.to_be_bytes());
    DeviceId(d)
}

fn cursors(n: u32) -> impl Iterator<Item = WriterCursor> {
    (0..n).map(|i| WriterCursor {
        writer: dev(i),
        seq: 1,
        digest: Some(WriterDigest([7; 32])),
    })
}

fn history(w: u8, n: u64, salt: u8) -> Vec<SignedRecord> {
    let k = folder(0x10);
    (1..=n).map(|seq| signed(&k, w, seq, salt)).collect()
}

fn pair_with(a: &[SignedRecord], b: &[SignedRecord]) -> Pair {
    let p = Pair::new(0xa0, 0xb0, &[key()], &[key()]);
    open_with(p, a, b)
}

fn open_with(mut p: Pair, a: &[SignedRecord], b: &[SignedRecord]) -> Pair {
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
    p.advance(s(5));
    p
}

fn decoder(name: &str, r: &IndexRequest, accepted: bool) -> Value {
    let body = r.encode_to_vec();
    let got = IndexRequest::parse(&body);
    assert_eq!(got.is_ok(), accepted, "{name}: {got:?}");
    seed(
        "message_parse",
        name,
        &[
            &[super::frames::selector(
                crate::frame::MessageType::IndexRequest,
            )],
            &body[..],
        ]
        .concat(),
    );
    json!({ "name": name, "body": super::input(&body), "outcome": got.map_or_else(|e| format!("malformed: {e}"), |_| "accepted".into()) })
}

#[test]
fn vector_exchange() {
    let f = folder(0x10).verifier().folder_id();
    let hash = |b: u8| RecordHash([b; 32]);
    // Digests: one record per seq, and two at one seq in canonical order.
    let one = writer_digests([(1, hash(5)), (2, hash(3)), (3, hash(9))]);
    let two = writer_digests([(1, hash(5)), (2, hash(9)), (2, hash(3))]);
    assert_eq!(
        two[&2],
        WriterDigest::ZERO
            .then(&hash(5))
            .then(&hash(3))
            .then(&hash(9))
    );
    let digests = json!({
        "records_one_per_seq": [[1, h(&[5; 32])], [2, h(&[3; 32])], [3, h(&[9; 32])]],
        "digests_one_per_seq": one.iter().map(|(s, d)| json!([s, h(&d.0)])).collect::<Vec<_>>(),
        "records_two_at_seq_2": [[1, h(&[5; 32])], [2, h(&[9; 32])], [2, h(&[3; 32])]],
        "digests_two_at_seq_2": two.iter().map(|(s, d)| json!([s, h(&d.0)])).collect::<Vec<_>>(),
    });

    // The round split for 0, 16 384 and 16 385 writers.
    let split = |n: u32| {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let r = range_request(&f, after, cursors(n), 0).unwrap();
            let through = DeviceId::from_slice(&r.through);
            out.push(
                json!({ "after": h(&r.after), "through": h(&r.through), "have": r.have.len() }),
            );
            match through {
                Some(t) => after = Some(t),
                None => break,
            }
        }
        out
    };
    let rounds = json!({ "0": split(0), "16384": split(16_384), "16385": split(16_385) });
    assert_eq!(rounds["16385"].as_array().unwrap().len(), 2);
    assert_eq!(rounds["16385"][0]["through"], h(&dev(16_383).0));

    // Request decoder vectors.
    let base = || IndexRequest {
        folder_id: f.0.to_vec(),
        request_id: 1,
        ..IndexRequest::default()
    };
    let c = |n: u32, seq: u64, d: usize| Cursor {
        device_id: dev(n).0.to_vec(),
        seq,
        digest: vec![7; d],
    };
    let full = IndexRequest {
        request_id: 1,
        ..range_request(&f, None, cursors(MAX_CURSORS_PER_REQUEST as u32), 0).unwrap()
    };
    let mut over = full.clone();
    over.have.push(c(MAX_CURSORS_PER_REQUEST as u32, 0, 0));
    let full_body = full.encode_to_vec();
    assert!(IndexRequest::parse(&full_body).is_ok());
    assert!(IndexRequest::parse(&over.encode_to_vec()).is_err());
    let requests = vec![
        decoder(
            "listed",
            &IndexRequest {
                listed: true,
                have: vec![c(1, 0, 0), c(2, 3, 32)],
                ..base()
            },
            true,
        ),
        decoder(
            "have-unsorted",
            &IndexRequest {
                have: vec![c(2, 0, 0), c(1, 0, 0)],
                ..base()
            },
            false,
        ),
        decoder(
            "writer-twice",
            &IndexRequest {
                have: vec![c(1, 0, 0), c(1, 0, 0)],
                ..base()
            },
            false,
        ),
        decoder(
            "writer-outside-the-range",
            &IndexRequest {
                have: vec![c(9, 0, 0)],
                after: dev(1).0.to_vec(),
                through: dev(5).0.to_vec(),
                ..base()
            },
            false,
        ),
        decoder(
            "after-not-below-through",
            &IndexRequest {
                after: dev(5).0.to_vec(),
                through: dev(5).0.to_vec(),
                ..base()
            },
            false,
        ),
        decoder(
            "listed-with-a-range",
            &IndexRequest {
                listed: true,
                have: vec![c(6, 0, 0)],
                after: dev(5).0.to_vec(),
                ..base()
            },
            false,
        ),
        decoder(
            "listed-with-have-empty",
            &IndexRequest {
                listed: true,
                ..base()
            },
            false,
        ),
        decoder(
            "digest-of-the-wrong-length",
            &IndexRequest {
                have: vec![c(1, 3, 31)],
                ..base()
            },
            false,
        ),
        decoder(
            "digest-at-seq-0",
            &IndexRequest {
                have: vec![c(1, 0, 32)],
                ..base()
            },
            false,
        ),
        decoder(
            "request-id-0",
            &IndexRequest {
                request_id: 0,
                ..base()
            },
            false,
        ),
    ];

    // Pages.
    let r = history(3, 2, 1);
    let mut pager = Pager::new(page_limit(64), MIN_MESSAGE_SIZE);
    let limits = json!({
        "max_records_1": page_limit(1), "max_records_64": page_limit(64),
        "max_records_0": page_limit(0), "max_records_5000": page_limit(5000),
    });
    assert!(pager.push(&r[0]).unwrap());
    let page_bytes = Message::IndexRecords(pager.page(&f, 1, false))
        .to_frame()
        .unwrap()
        .encode();
    seed("index_records", "one-record", &page_bytes[6..]);
    let outcome = |body: &[u8]| {
        IndexRecords::parse(body).map_or_else(|e| format!("malformed: {e}"), |_| "accepted".into())
    };
    let page_of = |n: usize, more: bool, request_id: u32| {
        IndexRecords {
            folder_id: f.0.to_vec(),
            records: vec![r[0].to_bytes(); n],
            more,
            request_id,
        }
        .encode_to_vec()
    };
    // MAX_PAGE_RECORDS records pass; one more is malformed.
    let page4096 = page_of(MAX_PAGE_RECORDS, true, 1);
    assert_eq!(outcome(&page4096), "accepted");
    let page4097 = page_of(MAX_PAGE_RECORDS + 1, false, 1);
    assert!(IndexRecords::parse(&page4097).is_err());
    let push_more = page_of(0, true, 0);
    assert!(IndexRecords::parse(&push_more).is_err());
    seed("index_records", "push-with-more", &push_more);
    // SEC-SF3: a reply page with more and no records.
    let more_empty = page_of(0, true, 1);
    assert!(IndexRecords::parse(&more_empty).is_err());
    seed("index_records", "more-without-records", &more_empty);
    let page_vectors = json!([
        { "name": "4096-records", "body": super::input(&page4096), "records": MAX_PAGE_RECORDS, "outcome": outcome(&page4096) },
        { "name": "4097-records", "body": super::input(&page4097), "records": MAX_PAGE_RECORDS + 1, "outcome": outcome(&page4097) },
        { "name": "push-with-more", "body": h(&push_more), "outcome": outcome(&push_more) },
        { "name": "reply-page-with-more-and-no-records", "body": h(&more_empty), "outcome": outcome(&more_empty) },
    ]);
    // A page whose request_id names no outstanding request, fed to an open
    // connection with none outstanding.
    let unknown = Message::IndexRecords(IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![],
        more: false,
        request_id: 99,
    })
    .to_frame()
    .unwrap()
    .encode();
    let unknown_request_id =
        json!({ "input": h(&unknown), "outcome": feed("established", &unknown) });
    assert!(unknown_request_id["outcome"]
        .as_str()
        .unwrap()
        .starts_with("close PROTOCOL_ERROR"));

    // Connection vectors.
    let equal = pair_with(&history(1, 1, 1), &history(1, 1, 2));
    assert_eq!(equal.a.store.all(), equal.b.store.all());
    let lower = pair_with(&history(1, 2, 1), &history(1, 1, 2));
    assert_eq!(lower.a.store.len(), 3);
    assert_eq!(lower.a.store.all(), lower.b.store.all());
    let incremental = pair_with(&history(1, 5, 1), &history(1, 2, 1));
    assert_eq!(incremental.b.store.len(), 5);

    // PUSH-2 (R1-SF4), served by hand: B's round on open asks with
    // max_records 64; A's reply is page 1 (writer 01..'s 64 records), then A
    // accepts writer 01..'s seq 65 and pushes it at once, the reply being past
    // that writer, then page 2 (writer 02..'s 6 records); B holds all 71.
    let v = *folder(0x10).verifier();
    let mut push2 = Pair::with(
        0xa0,
        0xb0,
        &[key()],
        &[key()],
        |_| {},
        |c| c.max_records = 64,
    );
    for r in history(1, 64, 1).iter().chain(&history(2, 6, 1)) {
        push2.a.store.insert_signed(r, &v);
    }
    push2.a.serving = false;
    push2.settle();
    push2.a.prove_all(push2.now);
    push2.settle();
    let request = push2
        .a
        .events
        .iter()
        .find_map(|e| match e {
            Event::Serve { request, .. } => Some(request.clone()),
            _ => None,
        })
        .unwrap();
    let mut reply = Reply::new(f, &request, &push2.a.store);
    let max = push2.a.conn.peer_max_message_size();
    let first = reply.next_page(max);
    assert!(first.more && first.records.len() == 64);
    let out = push2
        .a
        .conn
        .send_page(Tick::at(push2.now), &first, &[])
        .unwrap();
    push2.a.apply(push2.now, out);
    let fresh = signed(&folder(0x10), 1, 65, 1);
    push2.a.store.insert_signed(&fresh, &v);
    assert_eq!(push2.a.push(push2.now, &[fresh]).len(), 1, "pushed at once");
    let second = reply.next_page(max);
    assert!(!second.more && second.records.len() == 6);
    let out = push2
        .a
        .conn
        .send_page(Tick::at(push2.now), &second, &[])
        .unwrap();
    push2.a.apply(push2.now, out);
    push2.settle();
    assert_eq!(push2.b.store.len(), 71);

    // PUSH-1: pushes dropped while the send queue is full, then the empty
    // push, the round owed and the round.
    let mut push1 = pair_with(&[], &[]);
    let h1 = history(1, 1, 1);
    push1.a.store.insert_signed(&h1[0], &v);
    push1.a.unsent = MAX_SEND_QUEUE - 10;
    assert!(push1.a.push(push1.now, &h1).is_empty(), "dropped");
    push1.a.unsent = 0;
    push1.advance(s(2));
    assert!(push1.b.saw(|e| matches!(e, Event::EmptyPush { .. })));
    assert_eq!(push1.b.store.len(), 1);

    // MARK: set before the range request (cleared), set after (kept, then
    // served by a listed request).
    let mut mark = pair_with(&[], &[]);
    mark.b.auto = false;
    let folder_id = mark.b.folder_id();
    let empty = Message::IndexRecords(IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![],
        more: false,
        request_id: 0,
    });
    mark.b
        .receive(mark.now, &empty.to_frame().unwrap().encode());
    let out = mark.b.conn.mark(
        Tick::at(mark.now),
        folder_id,
        dev(1),
        crate::connection::MarkKind::Gap,
    );
    mark.b.apply(mark.now, out);
    mark.b.request(mark.now).unwrap();
    let out = mark.b.conn.mark(
        Tick::at(mark.now),
        folder_id,
        dev(2),
        crate::connection::MarkKind::Resend,
    );
    mark.b.apply(mark.now, out);
    mark.advance(s(2));
    assert_eq!(
        mark.b.conn.due(&folder_id),
        Some(&Due::Listed {
            writers: vec![dev(2)]
        })
    );
    mark.b.request(mark.now).unwrap();
    mark.advance(s(2));

    // REPLY_PAGE_TIMEOUT while only duplicate pushes arrive.
    let mut deadline = pair_with(&history(1, 1, 1), &[]);
    deadline.a.serving = false;
    deadline
        .b
        .receive(deadline.now, &empty.to_frame().unwrap().encode());
    let start = deadline.now;
    for minute in 1..10u64 {
        deadline.advance_to(start + s(60 * minute));
        deadline.a.push(deadline.now, &history(1, 1, 1));
    }
    deadline.advance_to(start + s(602));
    assert_eq!(ending(&deadline.b)["row"], "ReplyPageTimeout");

    // SEC-SF4: the reply's next page never comes while the responder answers
    // every chunk request CHUNK_BUSY (its queue half full): Close(TIMEOUT).
    let mut busy = pair_with(&[], &[]);
    busy.a.serving = false;
    busy.a.unsent = MAX_SEND_QUEUE / 2;
    busy.b
        .receive(busy.now, &empty.to_frame().unwrap().encode());
    busy.settle();
    let start = busy.now;
    let mut k = 0u8;
    while ending(&busy.b) == json!("open") && busy.now < start + s(700) {
        if busy
            .b
            .conn
            .chunk_position(busy.b.tick(busy.now), &f)
            .is_ok()
        {
            busy.b.request_chunk(busy.now, CipherHash([k; 32])).unwrap();
            busy.b.pass_done(busy.now);
            k += 1;
            busy.settle();
        }
        busy.advance(s(1));
    }
    assert!(k > 5, "B kept asking: {k}");
    assert_eq!(ending(&busy.b)["row"], "ReplyPageTimeout");

    // SEC-SF4: the reply's next page waits behind CHUNK_OK replies to the
    // requester's own chunk requests: each restarts the deadline, kept open.
    let mut ok = pair_with(&[], &[]);
    ok.a.serving = false;
    ok.b.receive(ok.now, &empty.to_frame().unwrap().encode());
    ok.settle();
    let start = ok.now;
    for minute in 1..=15u8 {
        ok.advance_to(start + s(60 * u64::from(minute)));
        let data = vec![minute; 46];
        let hash = licketysync_keys::chunk::cipher_hash(&data);
        ok.b.request_chunk(ok.now, hash).unwrap();
        ok.b.pass_done(ok.now);
        ok.settle();
        ok.a.reply_chunk(ok.now, hash, ChunkAnswer::Ok(&data))
            .unwrap();
        ok.settle();
    }
    assert_eq!(ending(&ok.b), json!("open"));

    let value: Value = json!({
        "description": "protocol.md 8 item 8: reference digests (the index's cached digests are its own vectors), the round split by writer count, IndexRequest decoder vectors (one at MAX_CURSORS_PER_REQUEST cursors accepted, one more refused, as sizes), page limits, IndexRecords decoder vectors (4 096 records accepted, 4 097 refused, a push with more, a reply page with more and no records), a page with an unknown request_id, and connection vectors: concurrent versions at equal cursors and behind a lower cursor (both end with the same records), an incremental reply (case b), PUSH-2 served by hand (page 1, the push of a record accepted meanwhile for a writer the reply is past, page 2), PUSH-1, MARK, and REPLY_PAGE_TIMEOUT while only duplicate pushes arrive, while every chunk request is answered CHUNK_BUSY (both close), and while CHUNK_OK replies arrive (kept open).",
        "digests": digests,
        "round_split": rounds,
        "max_cursors_request_len": full_body.len(),
        "requests": requests,
        "page_limits": limits,
        "one_record_page": h(&page_bytes),
        "pages": page_vectors,
        "unknown_request_id": unknown_request_id,
        "concurrent_at_equal_cursors": scenario(&equal, &["DigestMismatch", "ConcurrentVersion"], json!("A and B each hold one record of writer 01.. at seq 1")),
        "concurrent_behind_a_lower_cursor": scenario(&lower, &["DigestMismatch", "ConcurrentVersion"], json!("A holds seq 1 and 2, B another seq 1")),
        "incremental": scenario(&incremental, &[], json!("B holds seq 1 and 2 of A's five")),
        "push_2": scenario(&push2, &[], json!("B asks with max_records 64; A sends page 1 (writer 01.., seq 1 to 64), pushes writer 01..'s seq 65 accepted meanwhile, then page 2 (writer 02.., seq 1 to 6)")),
        "push_1": scenario(&push1, &["EmptyPush"], json!("A's queue full: push dropped, empty push, B's owed round")),
        "mark": scenario(&mark, &[], json!("01.. marked before B's range request (cleared), 02.. after (listed)")),
        "reply_page_timeout": scenario(&deadline, &["Duplicate", "ReplyPageTimeout"], json!("A never answers B's request; duplicate pushes do not restart the deadline")),
        "reply_page_timeout_chunk_busy": scenario(&busy, &["ChunkBusy", "ReplyPageTimeout"], json!("A never answers B's request and answers every chunk request CHUNK_BUSY; busy answers do not restart the deadline")),
        "reply_page_waits_behind_chunk_ok": scenario(&ok, &[], json!("A never answers B's request but answers a chunk request of B's with CHUNK_OK each minute for 15 minutes; each restarts the deadline")),
    });
    check("exchange", &value);
}
