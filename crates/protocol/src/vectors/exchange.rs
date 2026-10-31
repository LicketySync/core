// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Item 8, the protocol's part: the decoder vectors of `IndexRequest`,
//! `ReconcileRequest`, `ReconcileReply` and `IndexRecords`, the page limits,
//! and a page whose `request_id` names no outstanding request, fed to an
//! open connection. The set digests and serving are the index crate's
//! vectors; rounds, cursors, pushes and timeouts are the engine's connection
//! vectors (`protocol.md` 8, "Who checks what").

use prost::Message as _;
use serde_json::{json, Value};

use super::{check, feed, h, input, seed};
use crate::exchange::{page_limit, Pager};
use crate::frame::MessageType;
use crate::limits::{MAX_LOCAL_SEQ, MAX_PAGE_RECORDS, MIN_MESSAGE_SIZE};
use crate::messages::{IndexRecords, IndexRequest, Message, ReconcileReply, ReconcileRequest};
use crate::parse::Parse;
use crate::testkit::{folder, signed};

/// A decoder vector of `M`, seeded for `message_parse` under `t`.
fn decoder<M: prost::Message + Parse>(t: MessageType, name: &str, m: &M, accepted: bool) -> Value {
    let body = m.encode_to_vec();
    let got = M::parse(&body);
    assert_eq!(got.is_ok(), accepted, "{name}");
    seed(
        "message_parse",
        name,
        &[&[super::frames::selector(t)], &body[..]].concat(),
    );
    // The reconcile target: an even first byte for a request, odd for a reply.
    match t {
        MessageType::ReconcileRequest => seed("reconcile", name, &[&[0u8], &body[..]].concat()),
        MessageType::ReconcileReply => seed("reconcile", name, &[&[1u8], &body[..]].concat()),
        _ => {}
    }
    json!({ "name": name, "body": input(&body), "outcome": got.map_or_else(|e| format!("malformed: {e}"), |_| "accepted".into()) })
}

#[test]
fn vector_exchange() {
    let f = folder(0x10).verifier().folder_id();
    let request = || IndexRequest {
        folder_id: f.0.to_vec(),
        max_records: 0,
        request_id: 1,
        epoch: 0x0123_4567_89ab_cdef,
        since: 41,
    };
    let t = MessageType::IndexRequest;
    let requests = vec![
        decoder(t, "index-request", &request(), true),
        decoder(
            t,
            "index-request-epoch-0",
            &IndexRequest {
                epoch: 0,
                ..request()
            },
            false,
        ),
        decoder(
            t,
            "index-request-since-max-local-seq",
            &IndexRequest {
                since: MAX_LOCAL_SEQ,
                ..request()
            },
            true,
        ),
        decoder(
            t,
            "index-request-since-max-local-seq-plus-1",
            &IndexRequest {
                since: MAX_LOCAL_SEQ + 1,
                ..request()
            },
            false,
        ),
        decoder(
            t,
            "index-request-request-id-0",
            &IndexRequest {
                request_id: 0,
                ..request()
            },
            false,
        ),
    ];
    let reconcile = || ReconcileRequest {
        folder_id: f.0.to_vec(),
        request_id: 2,
        prefix: vec![],
        digest: vec![0x5d; 32],
    };
    let t = MessageType::ReconcileRequest;
    let reconciles = vec![
        decoder(t, "reconcile-request-root", &reconcile(), true),
        decoder(
            t,
            "reconcile-request-128-nibbles",
            &ReconcileRequest {
                prefix: (0..128u8).map(|i| i % 16).collect(),
                ..reconcile()
            },
            true,
        ),
        decoder(
            t,
            "reconcile-request-129-byte-prefix",
            &ReconcileRequest {
                prefix: vec![0; 129],
                ..reconcile()
            },
            false,
        ),
        decoder(
            t,
            "reconcile-request-nibble-of-16",
            &ReconcileRequest {
                prefix: vec![3, 16],
                ..reconcile()
            },
            false,
        ),
        decoder(
            t,
            "reconcile-request-request-id-0",
            &ReconcileRequest {
                request_id: 0,
                ..reconcile()
            },
            false,
        ),
        decoder(
            t,
            "reconcile-request-digest-31-bytes",
            &ReconcileRequest {
                digest: vec![0x5d; 31],
                ..reconcile()
            },
            false,
        ),
    ];
    let reply = |outcome: u32, children: usize| ReconcileReply {
        folder_id: f.0.to_vec(),
        request_id: 2,
        outcome,
        children: (0..children)
            .map(|i| vec![u8::try_from(i).unwrap(); 32])
            .collect(),
        epoch: 0x0123_4567_89ab_cdef,
        through: 0,
    };
    let t = MessageType::ReconcileReply;
    let replies = vec![
        decoder(
            t,
            "reconcile-reply-equal-with-through",
            &ReconcileReply {
                through: 7,
                ..reply(1, 0)
            },
            true,
        ),
        decoder(t, "reconcile-reply-children", &reply(2, 16), true),
        decoder(t, "reconcile-reply-records", &reply(3, 0), true),
        decoder(t, "reconcile-reply-outcome-4", &reply(4, 0), false),
        decoder(t, "reconcile-reply-15-children", &reply(2, 15), false),
        decoder(t, "reconcile-reply-children-on-equal", &reply(1, 16), false),
        decoder(
            t,
            "reconcile-reply-epoch-0",
            &ReconcileReply {
                epoch: 0,
                ..reply(1, 0)
            },
            false,
        ),
    ];

    // Pages.
    let r = signed(&folder(0x10), 3, 1, 1);
    let limits = json!({
        "max_records_1": page_limit(1), "max_records_64": page_limit(64),
        "max_records_0": page_limit(0), "max_records_5000": page_limit(5000),
    });
    let mut pager = Pager::new(page_limit(64), MIN_MESSAGE_SIZE);
    assert!(pager.push(&r).unwrap());
    let page_bytes = Message::IndexRecords(pager.page(&f, 1, false, 9, 1))
        .to_frame()
        .unwrap()
        .encode();
    seed("index_records", "one-record", &page_bytes[6..]);
    let outcome = |body: &[u8]| {
        IndexRecords::parse(body).map_or_else(|e| format!("malformed: {e}"), |_| "accepted".into())
    };
    let page = |n: usize, more: bool, request_id: u32| IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![r.to_bytes(); n],
        more,
        request_id,
        epoch: 9,
        through: 0,
        reset: false,
    };
    let cases = [
        ("4096-records", page(MAX_PAGE_RECORDS, true, 1), true),
        ("4097-records", page(MAX_PAGE_RECORDS + 1, false, 1), false),
        ("push-with-more", page(1, true, 0), false),
        (
            "reply-page-with-more-and-no-records",
            page(0, true, 1),
            false,
        ),
        (
            "reset",
            IndexRecords {
                reset: true,
                ..page(0, false, 1)
            },
            true,
        ),
        (
            "reset-with-a-record",
            IndexRecords {
                reset: true,
                ..page(1, false, 1)
            },
            false,
        ),
        (
            "reset-with-through",
            IndexRecords {
                reset: true,
                through: 4,
                ..page(0, false, 1)
            },
            false,
        ),
        (
            "push-with-reset",
            IndexRecords {
                reset: true,
                ..page(0, false, 0)
            },
            false,
        ),
        (
            "epoch-0",
            IndexRecords {
                epoch: 0,
                ..page(1, false, 0)
            },
            false,
        ),
        (
            "through-max-local-seq-plus-1",
            IndexRecords {
                through: MAX_LOCAL_SEQ + 1,
                ..page(1, false, 0)
            },
            false,
        ),
        ("empty-push", page(0, false, 0), true),
    ];
    let mut pages = Vec::new();
    for (name, p, accepted) in cases {
        let body = p.encode_to_vec();
        assert_eq!(IndexRecords::parse(&body).is_ok(), accepted, "{name}");
        seed("index_records", name, &body);
        pages.push(json!({ "name": name, "body": input(&body), "records": p.records.len(), "outcome": outcome(&body) }));
    }
    // A page whose request_id names no outstanding request, fed to an open
    // connection with none outstanding.
    let unknown = Message::IndexRecords(page(0, false, 99))
        .to_frame()
        .unwrap()
        .encode();
    let unknown_request_id =
        json!({ "input": h(&unknown), "outcome": feed("established", &unknown) });
    assert!(unknown_request_id["outcome"]
        .as_str()
        .unwrap()
        .starts_with("close PROTOCOL_ERROR"));
    // A ReconcileReply when no request is outstanding.
    let stray = Message::ReconcileReply(reply(1, 0))
        .to_frame()
        .unwrap()
        .encode();
    let stray_reply = json!({ "input": h(&stray), "outcome": feed("established", &stray) });
    assert!(stray_reply["outcome"]
        .as_str()
        .unwrap()
        .starts_with("close PROTOCOL_ERROR"));

    let value: Value = json!({
        "description": "protocol.md 8 item 8, the protocol's part: decoder vectors of IndexRequest, ReconcileRequest (prefixes of 0 to 128 nibbles, a record's 64-byte key), ReconcileReply and IndexRecords (bodies, as the decoder alone judges them), the page limits, one page of one record, and a page with an unknown request_id and a ReconcileReply with none outstanding, each fed to an open connection. A ReconcileReply that carries through for a prefix other than the root, and a RECORDS page that carries through, pass the decoder alone (their entries say accepted) and are refused by the connection, which knows the request they answer (the unit test replies_of_the_wrong_kind_or_shape_are_malformed). Set digests and serving are the index crate's vectors; rounds, cursors, pushes and timeouts are the engine's connection vectors.",
        "index_requests": requests,
        "reconcile_requests": reconciles,
        "reconcile_replies": replies,
        "page_limits": limits,
        "one_record_page": h(&page_bytes),
        "pages": pages,
        "unknown_request_id": unknown_request_id,
        "reconcile_reply_with_none_outstanding": stray_reply,
    });
    check("exchange", &value);
}

/// The fuzz target `handshake`'s odd mode, the one copy in
/// `handshake_harness.rs` that the target includes too, so that its seeds
/// are written, and checked, by a test.
mod harness {
    use crate as protocol;

    include!("handshake_harness.rs");

    /// What [`drive`] keeps: the first side's events, and the frames it
    /// handed over from the round due on open on.
    #[derive(Default)]
    struct Kept {
        seen: Vec<Event>,
        sent: Vec<Vec<u8>>,
    }

    impl Watch for Kept {
        fn event(&mut self, e: &Event) {
            self.seen.push(e.clone());
        }

        fn handed(&mut self, _: &Connection, out: &Output, stage: Stage) {
            if stage == Stage::Exchange {
                self.sent.extend(out.frames.iter().cloned());
            }
        }
    }

    /// Drives the odd mode over `data` (its first byte the mode): the first
    /// side's events and the frames it handed over after the handshake.
    pub(super) fn drive(data: &[u8]) -> (Vec<Event>, Vec<Vec<u8>>) {
        let (&mode, rest) = data.split_first().unwrap();
        assert_eq!(mode % 2, 1, "the odd mode");
        let mut kept = Kept::default();
        odd_mode(mode, rest, &mut kept);
        (kept.seen, kept.sent)
    }
}

/// One piece of the odd mode's stream: its two-byte length, then it.
fn piece(bytes: &[u8]) -> Vec<u8> {
    let len = u16::try_from(bytes.len()).unwrap();
    [&len.to_be_bytes()[..], bytes].concat()
}

fn wire(m: &Message) -> Vec<u8> {
    m.to_frame().unwrap().encode()
}

/// The fuzz seeds of the `handshake` target that start inside the exchange
/// (the review's PS-3), written by this test and checked through the
/// target's twin ([`harness::drive`]): a `RECORDS` reply and its pages, then
/// `EQUAL`; `CHILDREN` answering a zero digest (a sender violation); `EQUAL`,
/// then a push, an `IndexRequest`, a `ReconcileRequest` and an empty push; a
/// descent through `CHILDREN` replies to `RECORDS` and `EQUAL`; a Since round
/// then the Check; and requests the first side answers with `CHILDREN`.
#[test]
fn vector_exchange_fuzz_seeds() {
    use crate::connection::Event;
    use crate::frame::FrameDecoder;
    use crate::messages::ReconcileOutcome;
    use crate::rules::Cause;

    let f = folder(0x10).verifier().folder_id();
    let e = 7u64;
    let recs: Vec<_> = (1..=3).map(|i| signed(&folder(0x10), 3, i, 1)).collect();
    let page =
        |id: u32, more: bool, through: u64, rs: &[licketysync_keys::records::SignedRecord]| {
            wire(&Message::IndexRecords(IndexRecords {
                folder_id: f.0.to_vec(),
                records: rs
                    .iter()
                    .map(licketysync_keys::records::SignedRecord::to_bytes)
                    .collect(),
                more,
                request_id: id,
                epoch: e,
                through,
                reset: false,
            }))
        };
    let reply = |id: u32, outcome: ReconcileOutcome, children: Vec<Vec<u8>>, through: u64| {
        wire(&Message::ReconcileReply(ReconcileReply {
            folder_id: f.0.to_vec(),
            request_id: id,
            outcome: outcome.as_u32(),
            children,
            epoch: e,
            through,
        }))
    };
    let children = |b: u8| {
        (0..16u8)
            .map(|i| vec![b.wrapping_add(i); 32])
            .collect::<Vec<_>>()
    };
    let requests = |sent: &[Vec<u8>]| -> Vec<ReconcileRequest> {
        sent.iter()
            .filter_map(|fr| {
                let frame = FrameDecoder::decode_one(fr, u32::MAX).ok()?;
                (frame.type_number() == MessageType::ReconcileRequest.as_u16())
                    .then(|| ReconcileRequest::parse(frame.body()).ok())
                    .flatten()
            })
            .collect()
    };
    let replies_sent = |sent: &[Vec<u8>]| -> Vec<ReconcileReply> {
        sent.iter()
            .filter_map(|fr| {
                let frame = FrameDecoder::decode_one(fr, u32::MAX).ok()?;
                (frame.type_number() == MessageType::ReconcileReply.as_u16())
                    .then(|| ReconcileReply::parse(frame.body()).ok())
                    .flatten()
            })
            .collect()
    };
    let caught_up = |events: &[Event], cursor: Option<(u64, u64)>| {
        events.iter().any(|ev| {
            matches!(ev, Event::RoundCompleted { caught_up: true, cursor: c, .. } if *c == cursor)
        })
    };
    let closed = |events: &[Event]| {
        events.iter().find_map(|ev| match ev {
            Event::Closed { cause, .. } => Some(*cause),
            _ => None,
        })
    };
    // The first side's opening request in each mode: a root ReconcileRequest
    // (request 1), or, with a cursor, an IndexRequest.
    let (_, sent) = harness::drive(&[1]);
    assert_eq!(requests(&sent)[0].request_id, 1);
    assert!(requests(&sent)[0].prefix.is_empty() && requests(&sent)[0].digest == [0; 32]);

    let mut seeds: Vec<(&str, Vec<u8>)> = Vec::new();
    // RECORDS and its pages, then EQUAL at the next pass's root.
    let mut s = vec![1u8];
    s.extend(piece(
        &[
            reply(1, ReconcileOutcome::Records, vec![], 3),
            page(1, true, 0, &recs[..1]),
            page(1, false, 0, &recs[1..]),
        ]
        .concat(),
    ));
    s.extend(piece(&reply(2, ReconcileOutcome::Equal, vec![], 3)));
    let (events, _) = harness::drive(&s);
    assert!(caught_up(&events, Some((e, 3))), "records then equal");
    assert_eq!(closed(&events), None);
    seeds.push(("exchange-records-then-equal", s));
    // CHILDREN answering a zero digest: a sender violation.
    let mut s = vec![1u8];
    s.extend(piece(&reply(1, ReconcileOutcome::Children, children(1), 3)));
    let (events, _) = harness::drive(&s);
    assert_eq!(closed(&events), Some(Some(Cause::SenderViolation)));
    seeds.push(("exchange-children-answering-a-zero-digest", s));
    // EQUAL, a counted push, an IndexRequest (reset), a root
    // ReconcileRequest (EQUAL) and an empty push.
    let mut s = vec![1u8];
    s.extend(piece(&reply(1, ReconcileOutcome::Equal, vec![], 3)));
    s.extend(piece(&page(0, false, 2, &recs)));
    s.extend(piece(&wire(&Message::IndexRequest(IndexRequest {
        folder_id: f.0.to_vec(),
        max_records: 0,
        request_id: 5,
        epoch: 9,
        since: 0,
    }))));
    s.extend(piece(&wire(&Message::ReconcileRequest(ReconcileRequest {
        folder_id: f.0.to_vec(),
        request_id: 6,
        prefix: vec![],
        digest: vec![0; 32],
    }))));
    s.extend(piece(&page(0, false, 0, &[])));
    let (events, _) = harness::drive(&s);
    assert!(caught_up(&events, Some((e, 3))));
    assert!(events.iter().any(|ev| matches!(
        ev,
        Event::CursorAdvanced {
            epoch: 7,
            through: 2,
            ..
        }
    )));
    assert!(events
        .iter()
        .any(|ev| matches!(ev, Event::ServeIndex { .. })));
    assert!(events
        .iter()
        .any(|ev| matches!(ev, Event::ServeReconcile { .. })));
    assert!(events
        .iter()
        .any(|ev| matches!(ev, Event::EmptyPush { .. })));
    assert_eq!(closed(&events), None);
    seeds.push(("exchange-equal-push-requests-empty-push", s));
    // A descent: the first side's digests are not zero (mode 3), so CHILDREN
    // takes it to [0] and [0, 0], RECORDS there, then [0, 1] is EQUAL.
    let mut s = vec![3u8];
    s.extend(piece(&reply(
        1,
        ReconcileOutcome::Children,
        children(0x40),
        3,
    )));
    s.extend(piece(&reply(
        2,
        ReconcileOutcome::Children,
        children(0x60),
        0,
    )));
    s.extend(piece(
        &[
            reply(3, ReconcileOutcome::Records, vec![], 0),
            page(3, false, 0, &[]),
        ]
        .concat(),
    ));
    s.extend(piece(&reply(4, ReconcileOutcome::Equal, vec![], 0)));
    let (events, sent) = harness::drive(&s);
    let prefixes: Vec<Vec<u8>> = requests(&sent).into_iter().map(|q| q.prefix).collect();
    assert_eq!(
        prefixes[..4],
        [vec![], vec![0], vec![0, 0], vec![0, 1]],
        "depth first, child 0 first"
    );
    assert_eq!(closed(&events), None);
    seeds.push(("exchange-children-descent", s));
    // A Since round (mode 5, a cursor at epoch 7), then the Check.
    let mut s = vec![5u8];
    s.extend(piece(&page(1, false, 3, &recs)));
    s.extend(piece(&reply(2, ReconcileOutcome::Equal, vec![], 3)));
    let (events, _) = harness::drive(&s);
    assert!(caught_up(&events, Some((e, 3))), "the Since cursor");
    seeds.push(("exchange-since-then-check", s));
    // The first side answers CHILDREN (mode 11: digests not zero, more
    // records than a leaf), at the root and below it.
    let mut s = vec![11u8];
    s.extend(piece(&reply(1, ReconcileOutcome::Equal, vec![], 0)));
    for (id, prefix) in [(9u32, vec![]), (10, vec![3])] {
        s.extend(piece(&wire(&Message::ReconcileRequest(ReconcileRequest {
            folder_id: f.0.to_vec(),
            request_id: id,
            prefix,
            digest: vec![0x22; 32],
        }))));
    }
    let (events, sent) = harness::drive(&s);
    let answered: Vec<u32> = replies_sent(&sent).iter().map(|r| r.outcome).collect();
    assert_eq!(answered, vec![ReconcileOutcome::Children.as_u32(); 2]);
    assert_eq!(closed(&events), None);
    seeds.push(("exchange-serving-children", s));
    for (name, bytes) in seeds {
        seed("handshake", name, &bytes);
    }
}
