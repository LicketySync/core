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
    reason = "test code"
)]

use core::time::Duration;

use licketysync_keys::chunk::cipher_hash;
use licketysync_keys::folder::FolderKey;
use licketysync_keys::{CipherHash, FolderId, Tier};

use crate::connection::{ChunkAnswer, Event, SendError, Side, State, Tick};
use crate::limits::{MAX_REQUESTS_IN_FLIGHT, MAX_SEND_QUEUE, MAX_STORED_LEN};
use crate::messages::{ChunkReply, ChunkRequest, CloseReason, FolderStatus, Message, Status};
use crate::parse::Parse;
use crate::record::Chunk;
use crate::rules::Cause;
use crate::testkit::{folder, s, with_chunk, Pair};

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

fn request(f: &FolderId, h: CipherHash) -> Message {
    Message::ChunkRequest(ChunkRequest {
        folder_id: f.0.to_vec(),
        cipher_hash: h.0.to_vec(),
    })
}

fn reply(f: &FolderId, h: CipherHash, status: u32, data: Vec<u8>) -> Message {
    Message::ChunkReply(ChunkReply {
        folder_id: f.0.to_vec(),
        cipher_hash: h.0.to_vec(),
        status,
        data,
    })
}

fn frame(m: &Message) -> Vec<u8> {
    m.to_frame().unwrap().encode()
}

fn replies(side: &crate::testkit::Side) -> Vec<ChunkReply> {
    side.sent
        .iter()
        .filter(|(_, f)| f[4..6] == [0x80, 0x0a])
        .map(|(_, f)| ChunkReply::parse(&f[6..]).unwrap())
        .collect()
}

/// A stored blob of 46 bytes and its hash.
fn blob(byte: u8) -> (Vec<u8>, CipherHash) {
    let data = vec![byte; 46];
    let h = cipher_hash(&data);
    (data, h)
}

/// A Status frame for one folder with `n` chunks stored.
fn status_frame(f: &FolderId, n: u64) -> Vec<u8> {
    frame(&Message::Status(Status {
        folders: vec![FolderStatus {
            folder_id: f.0.to_vec(),
            chunks_stored: n,
            ..FolderStatus::default()
        }],
        device_name: String::new(),
    }))
}

/// Fires B's wake-ups up to `t` (B alone; A's engine is off).
fn wake_b_until(p: &mut Pair, t: Duration) {
    while let Some(w) = p.b.wake.filter(|w| *w <= t) {
        p.now = p.now.max(w);
        let out = p.b.conn.wake(Tick::at(p.now));
        p.b.apply(p.now, out);
    }
    p.now = t;
}

#[test]
fn a_chunk_is_requested_served_and_verified() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    let (data, h) = blob(1);
    assert_eq!(p.b.conn.chunk_position(p.b.tick(p.now), &f), Ok(None));
    p.b.request_chunk(p.now, h).unwrap();
    p.settle();
    assert!(p
        .a
        .saw(|e| matches!(e, Event::ChunkRequested { cipher_hash, .. } if *cipher_hash == h)));
    p.a.reply_chunk(p.now, h, ChunkAnswer::Ok(&data)).unwrap();
    p.settle();
    assert!(p
        .b
        .saw(|e| matches!(e, Event::Chunk { data: d, .. } if *d == data)));
    // The record that names it judges the length: the writer's fault.
    let key = folder(0x10);
    let rec = with_chunk(
        &key,
        1,
        1,
        Chunk {
            cipher_hash: h,
            stored_len: 49 + 1,
        },
        [0; 32],
    );
    let r = crate::record::Record::parse(rec, key.verifier()).unwrap();
    assert_ne!(r.chunks()[0].stored_len as usize, data.len());
    // The request is answered: a second reply has nothing to answer.
    assert_eq!(
        p.a.reply_chunk(p.now, h, ChunkAnswer::Ok(&data)).err(),
        Some(SendError::Unrequested)
    );
}

#[test]
fn a_chunk_corrupt_in_storage_is_never_sent() {
    // R2-SF5, TM-10: the holder checks the blob against the hash asked, one
    // BLAKE3 pass, before it sends it; and its length first.
    let mut p = Pair::open();
    p.a.auto = false;
    let (data, h) = blob(1);
    p.b.request_chunk(p.now, h).unwrap();
    p.settle();
    let before = p.a.sent.len();
    for bad in [vec![2u8; 46], vec![], vec![0u8; MAX_STORED_LEN + 1]] {
        assert_eq!(
            p.a.reply_chunk(p.now, h, ChunkAnswer::Ok(&bad)).err(),
            Some(SendError::Corrupt)
        );
    }
    assert_eq!(p.a.sent.len(), before, "nothing sent");
    // The request is still there to answer.
    p.a.reply_chunk(p.now, h, ChunkAnswer::Ok(&data)).unwrap();
    // A blob of exactly the largest stored length passes the length check
    // (and then the hash check decides).
    let (big, bh) = (
        vec![3u8; MAX_STORED_LEN],
        cipher_hash(&vec![3u8; MAX_STORED_LEN]),
    );
    p.b.pass_done(p.now);
    p.b.request_chunk(p.now, bh).unwrap();
    p.settle();
    p.a.reply_chunk(p.now, bh, ChunkAnswer::Ok(&big)).unwrap();
    p.settle();
    assert!(p
        .b
        .saw(|e| matches!(e, Event::Chunk { cipher_hash, .. } if *cipher_hash == bh)));
}

#[test]
fn replies_that_close() {
    // An unsolicited reply.
    let mut p = Pair::open();
    let f = p.a.folder_id();
    let (data, h) = blob(1);
    p.b.receive(p.now, &frame(&reply(&f, h, 1, data.clone())));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // Data whose ciphertext hash fails: forged.
    let mut p = Pair::open();
    p.b.request_chunk(p.now, h).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, h, 1, vec![9; 46])));
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::VerificationFailed, Some(Cause::Forged)))
    );
    // Data of 4 325 417 bytes: malformed before any hash.
    let mut p = Pair::open();
    p.b.request_chunk(p.now, h).unwrap();
    let mut big = Vec::new();
    prost::encoding::bytes::encode(1, &f.0.to_vec(), &mut big);
    prost::encoding::bytes::encode(2, &h.0.to_vec(), &mut big);
    prost::encoding::uint32::encode(3, &1, &mut big);
    prost::encoding::bytes::encode(4, &vec![0u8; 4_325_417], &mut big);
    let raw = crate::frame::Frame::new(0x800a, big).unwrap().encode();
    p.b.receive(p.now, &raw);
    assert_eq!(
        closed(&p.b),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // A request with no cipher_hash.
    let mut p = Pair::open();
    let bad = Message::ChunkRequest(ChunkRequest {
        folder_id: f.0.to_vec(),
        cipher_hash: vec![],
    });
    p.a.receive(p.now, &frame(&bad));
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
    // A request naming a folder not open here (R1-SF3).
    let mut p = Pair::open();
    p.a.receive(p.now, &frame(&request(&FolderId([9; 32]), h)));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // One request more than max_requests_in_flight outstanding.
    let mut p = Pair::open();
    for i in 0..=64u8 {
        p.a.receive(p.now, &frame(&request(&f, CipherHash([i; 32]))));
    }
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
}

#[test]
fn not_found_is_an_ordinary_answer() {
    // Any number of NOT_FOUND within the in-flight limit keeps the connection.
    let mut p = Pair::open();
    let f = p.a.folder_id();
    for round in 0..2u8 {
        for i in 0..64u8 {
            p.a.receive(
                p.now,
                &frame(&request(&f, CipherHash([round * 64 + i; 32]))),
            );
        }
        for i in 0..64u8 {
            p.a.reply_chunk(
                p.now,
                CipherHash([round * 64 + i; 32]),
                ChunkAnswer::NotFound,
            )
            .unwrap();
        }
    }
    assert_eq!(p.a.conn.state(), State::Established);
    assert_eq!(replies(&p.a).len(), 128);
    // A request never made has nothing to answer, and a folder not open none.
    assert_eq!(
        p.a.reply_chunk(p.now, CipherHash([200; 32]), ChunkAnswer::NotFound)
            .err(),
        Some(SendError::Unrequested)
    );
    assert_eq!(
        p.a.conn
            .reply_chunk(
                Tick::at(p.now),
                FolderId([9; 32]),
                CipherHash([1; 32]),
                ChunkAnswer::NotFound
            )
            .err(),
        Some(SendError::FolderNotOpen)
    );
}

#[test]
fn busy_at_dispatch_exactly_at_half_the_queue() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.unsent = MAX_SEND_QUEUE / 2;
    p.a.receive(p.now, &frame(&request(&f, CipherHash([1; 32]))));
    assert_eq!(replies(&p.a).last().unwrap().status, 3, "BUSY");
    assert!(!p.a.saw(|e| matches!(e, Event::ChunkRequested { .. })));
    p.a.unsent = MAX_SEND_QUEUE / 2 - 1;
    p.a.receive(p.now, &frame(&request(&f, CipherHash([2; 32]))));
    assert!(p.a.saw(|e| matches!(e, Event::ChunkRequested { cipher_hash, .. } if *cipher_hash == CipherHash([2; 32]))));
}

#[test]
fn chunk_ok_waits_for_room_and_not_found_does_not() {
    // SEC-SF2: a CHUNK_OK never waits in the backlog; with no room it is
    // refused, the engine waits for Event::Room and sends it then. A
    // CHUNK_NOT_FOUND is small and bounded by the in-flight limit: it queues.
    let mut p = Pair::open();
    p.a.auto = false;
    let mut two = [blob(4), blob(5)];
    two.sort_by_key(|(_, h)| *h);
    let [(data, lo), (_, hi)] = two;
    p.b.request_chunk(p.now, lo).unwrap();
    p.b.request_chunk(p.now, hi).unwrap();
    p.settle();
    p.a.unsent = MAX_SEND_QUEUE - 10;
    let Err(SendError::WouldBlock { len }) = p.a.reply_chunk(p.now, lo, ChunkAnswer::Ok(&data))
    else {
        panic!("no room")
    };
    assert_eq!(
        len,
        frame(&reply(&p.a.folder_id(), lo, 1, data.clone())).len()
    );
    assert_eq!(p.a.conn.backlog(), 0, "nothing waits here");
    let tick = p.a.tick(p.now);
    let out = p.a.conn.want_room(tick, len);
    let events = p.a.apply(p.now, out);
    assert!(!events.iter().any(|e| matches!(e, Event::Room)));
    assert!(p.a.wake.unwrap() <= p.now + s(1), "the send poll");
    // The transport drains: the next wake-up announces room.
    p.a.unsent = 0;
    p.now += s(1);
    let out = p.a.conn.wake(p.a.tick(p.now));
    let events = p.a.apply(p.now, out);
    assert_eq!(
        events.iter().filter(|e| matches!(e, Event::Room)).count(),
        1,
        "once"
    );
    p.a.reply_chunk(p.now, lo, ChunkAnswer::Ok(&data)).unwrap();
    // Room already there: want_room answers in its own output.
    let out = p.a.conn.want_room(p.a.tick(p.now), 10);
    assert!(out.events.iter().any(|e| matches!(e, Event::Room)));
    // A NOT_FOUND queues behind a full transport.
    p.a.unsent = MAX_SEND_QUEUE - 10;
    p.a.reply_chunk(p.now, hi, ChunkAnswer::NotFound).unwrap();
    assert!(p.a.conn.backlog() > 0);
}

#[test]
fn the_busy_backoff_doubles_to_64_s_and_resets_on_ok() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    let mut expect = Vec::new();
    for k in 0..8u8 {
        let h = CipherHash([k; 32]);
        assert_eq!(
            p.b.conn.chunk_position(p.b.tick(p.now), &f).map(|_| ()),
            Ok(()),
            "k = {k}"
        );
        p.b.request_chunk(p.now, h).unwrap();
        p.b.receive(p.now, &frame(&reply(&f, h, 3, vec![])));
        let blocked = p.b.request_chunk(p.now, CipherHash([k + 100; 32]));
        assert_eq!(blocked.err(), Some(SendError::BackingOff));
        // Wake at each deadline until the backoff ends.
        let busy_at = p.now;
        loop {
            p.now = p.b.wake.unwrap();
            let out = p.b.conn.wake(Tick::at(p.now));
            let events = p.b.apply(p.now, out);
            if events.iter().any(|e| matches!(e, Event::ChunksAllowed)) {
                break;
            }
            assert_eq!(
                p.b.request_chunk(p.now, CipherHash([k + 100; 32])).err(),
                Some(SendError::BackingOff)
            );
        }
        expect.push((p.now - busy_at).as_secs());
        p.b.events.clear();
        // The chunk pass would refuse a lower hash; end it for the next one.
        p.b.pass_done(p.now);
    }
    assert_eq!(expect, vec![1, 2, 4, 8, 16, 32, 64, 64]);
    // A BUSY for a request sent before the backoff began leaves it
    // unchanged: the backoff is still the 64 s the first one imposed.
    let (h1, h2) = (CipherHash([200; 32]), CipherHash([201; 32]));
    p.b.request_chunk(p.now, h1).unwrap();
    p.b.request_chunk(p.now, h2).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, h1, 3, vec![])));
    let busy_at = p.now;
    p.now += Duration::from_millis(10);
    p.b.receive(p.now, &frame(&reply(&f, h2, 3, vec![])));
    let expected = s(64) - (p.now - busy_at);
    assert_eq!(allowed_after(&mut p), expected);
    // A CHUNK_OK sets it back to 1 s.
    p.b.pass_done(p.now);
    let (data, h) = blob(7);
    p.b.request_chunk(p.now, h).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, h, 1, data)));
    p.b.pass_done(p.now);
    let h3 = CipherHash([250; 32]);
    p.b.request_chunk(p.now, h3).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, h3, 3, vec![])));
    assert_eq!(allowed_after(&mut p), s(1));
}

/// Wakes B at each deadline until the backoff ends; how long that took.
fn allowed_after(p: &mut Pair) -> Duration {
    let start = p.now;
    loop {
        p.now = p.b.wake.unwrap();
        let out = p.b.conn.wake(Tick::at(p.now));
        let events = p.b.apply(p.now, out);
        if events.iter().any(|e| matches!(e, Event::ChunksAllowed)) {
            return p.now - start;
        }
        assert_eq!(
            p.b.request_chunk(p.now, CipherHash([255; 32])).err(),
            Some(SendError::BackingOff)
        );
    }
}

#[test]
fn passes_go_up_and_wait_for_a_trigger_after_not_found() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    // A pass in ascending hash order: one NOT_FOUND among OKs.
    let mut hashes: Vec<(Vec<u8>, CipherHash)> = (1..=5u8).map(blob).collect();
    hashes.sort_by_key(|(_, h)| *h);
    for (i, (data, h)) in hashes.iter().enumerate() {
        let pos = p.b.conn.chunk_position(Tick::at(p.now), &f).unwrap();
        assert!(pos.is_none_or(|x| x < *h));
        p.b.request_chunk(p.now, *h).unwrap();
        let status = if i == 2 { 2 } else { 1 };
        let data = if status == 1 { data.clone() } else { vec![] };
        p.b.receive(p.now, &frame(&reply(&f, *h, status, data)));
    }
    // A lower hash is out of order inside the pass.
    assert_eq!(
        p.b.request_chunk(p.now, hashes[0].1).err(),
        Some(SendError::OutOfOrder)
    );
    let nf_at = p.now;
    p.b.pass_done(p.now);
    assert_eq!(
        p.b.conn.chunk_position(Tick::at(p.now), &f),
        Err(SendError::PassWaiting)
    );
    // A Status with a greater chunks_stored before 1 s: the pass waits for 1 s.
    p.now += Duration::from_millis(300);
    p.b.receive(p.now, &status_frame(&f, 1));
    assert!(!p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
    assert_eq!(p.b.wake, Some(nf_at + s(1)), "the earliest deadline");
    // A wake-up a millisecond early: still waiting.
    p.now = nf_at + s(1) - Duration::from_millis(1);
    let out = p.b.conn.wake(Tick::at(p.now));
    p.b.apply(p.now, out);
    assert!(!p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
    p.now = nf_at + s(1);
    let out = p.b.conn.wake(Tick::at(p.now));
    p.b.apply(p.now, out);
    assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
    assert_eq!(p.b.conn.chunk_position(Tick::at(p.now), &f), Ok(None));
    // Another pass with a NOT_FOUND; a second greater Status within
    // STATUS_INTERVAL of the last evaluation is deferred, not dropped.
    let h = hashes[0].1;
    p.b.request_chunk(p.now, h).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, h, 2, vec![])));
    p.b.pass_done(p.now);
    p.b.events.clear();
    let eval = nf_at + Duration::from_millis(300);
    p.now += s(2);
    p.b.receive(p.now, &status_frame(&f, 2));
    assert!(
        !p.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
        "deferred"
    );
    // Woken before the window ends (the periodic Status at 30 s): still
    // waiting; at the window's end the pending trigger is evaluated.
    p.now = eval + s(30) - Duration::from_millis(1);
    let out = p.b.conn.wake(Tick::at(p.now));
    p.b.apply(p.now, out);
    assert!(!p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
    assert!(p.b.wake.unwrap() <= eval + s(30));
    p.now = eval + s(30);
    let out = p.b.conn.wake(Tick::at(p.now));
    p.b.apply(p.now, out);
    assert!(
        p.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
        "evaluated at the window's end"
    );
}

#[test]
fn a_trigger_exactly_at_the_windows_end_is_acted_on() {
    // Window edges: a trigger STATUS_INTERVAL after the last one acted on is
    // acted on at once; one a millisecond earlier is deferred to that time.
    for early in [false, true] {
        let mut p = Pair::open();
        let f = p.a.folder_id();
        p.a.auto = false;
        p.b.auto = false;
        let not_found = |p: &mut Pair, h: u8| {
            p.b.request_chunk(p.now, CipherHash([h; 32])).unwrap();
            p.b.receive(p.now, &frame(&reply(&f, CipherHash([h; 32]), 2, vec![])));
            p.b.pass_done(p.now);
        };
        not_found(&mut p, 1);
        p.now += s(1);
        p.b.receive(p.now, &status_frame(&f, 1));
        assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
        let acted = p.now;
        not_found(&mut p, 2);
        p.b.events.clear();
        p.now = acted + s(30)
            - if early {
                Duration::from_millis(1)
            } else {
                Duration::ZERO
            };
        p.b.receive(p.now, &status_frame(&f, 2));
        assert_eq!(
            p.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
            !early,
            "early {early}"
        );
        if early {
            // Deferred to the window's end, never dropped.
            wake_b_until(&mut p, acted + s(30) - Duration::from_millis(1));
            assert!(!p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
            wake_b_until(&mut p, acted + s(30));
            assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
        }
    }
}

#[test]
fn a_round_completed_while_the_pass_still_asks_is_a_trigger() {
    // R2-B1 / R1-SF1, the regression: the NOT_FOUND comes during a pass, and
    // the round with the peer completes while the pass is still asking; the
    // pass then ends, and that round is judged at once.
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.auto = false;
    p.b.request_chunk(p.now, CipherHash([1; 32])).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, CipherHash([1; 32]), 2, vec![])));
    // Still asking: a second request of the pass.
    p.b.request_chunk(p.now, CipherHash([2; 32])).unwrap();
    p.now += s(2);
    // An owed round of B's completes (A serves it by hand).
    p.a.serving = false;
    p.a.auto = true;
    let empty = Message::IndexRecords(crate::messages::IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![],
        more: false,
        request_id: 0,
    });
    p.b.receive(p.now, &frame(&empty));
    p.settle();
    let request =
        p.a.events
            .iter()
            .rev()
            .find_map(|e| match e {
                Event::Serve { request, .. } => Some(request.clone()),
                _ => None,
            })
            .unwrap();
    let mut reply = crate::testkit::Reply::new(f, &request, &p.a.store);
    let page = reply.next_page(p.a.conn.peer_max_message_size());
    let out = p.a.conn.send_page(Tick::at(p.now), &page, &[]).unwrap();
    p.a.apply(p.now, out);
    p.settle();
    assert!(p.b.saw(|e| matches!(e, Event::RoundCompleted { .. })));
    assert!(
        !p.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
        "still asking"
    );
    // The pass ends: the round counts.
    p.b.events.clear();
    p.b.pass_done(p.now);
    assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
}

#[test]
fn a_status_above_the_baseline_while_the_pass_asks_is_a_trigger() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    p.b.receive(p.now, &status_frame(&f, 4));
    p.b.request_chunk(p.now, CipherHash([1; 32])).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, CipherHash([1; 32]), 2, vec![])));
    p.b.request_chunk(p.now, CipherHash([2; 32])).unwrap();
    p.now += s(2);
    // Unchanged: no trigger.
    p.b.receive(p.now, &status_frame(&f, 4));
    p.b.pass_done(p.now);
    assert!(
        !p.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
        "an unchanged chunks_stored starts no pass"
    );
    assert_eq!(
        p.b.conn.chunk_position(Tick::at(p.now), &f),
        Err(SendError::PassWaiting)
    );
    // Again, with a greater count while asking.
    let mut q = Pair::open();
    q.a.auto = false;
    q.b.auto = false;
    q.b.receive(q.now, &status_frame(&f, 4));
    q.b.request_chunk(q.now, CipherHash([1; 32])).unwrap();
    q.b.receive(q.now, &frame(&reply(&f, CipherHash([1; 32]), 2, vec![])));
    q.b.request_chunk(q.now, CipherHash([2; 32])).unwrap();
    q.now += s(2);
    q.b.receive(q.now, &status_frame(&f, 5));
    assert!(
        !q.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
        "still asking"
    );
    q.b.pass_done(q.now);
    assert!(q.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
}

#[test]
fn a_completed_round_is_a_trigger_too() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    let h = CipherHash([3; 32]);
    p.b.request_chunk(p.now, h).unwrap();
    p.settle();
    p.a.reply_chunk(p.now, h, ChunkAnswer::NotFound).unwrap();
    p.settle();
    p.b.pass_done(p.now);
    assert_eq!(
        p.b.conn.chunk_position(Tick::at(p.now), &f),
        Err(SendError::PassWaiting)
    );
    p.advance(s(2));
    // An owed round completes: the pass may start.
    let empty = Message::IndexRecords(crate::messages::IndexRecords {
        folder_id: f.0.to_vec(),
        records: vec![],
        more: false,
        request_id: 0,
    });
    p.b.receive(p.now, &frame(&empty));
    p.settle();
    assert!(p.b.saw(|e| matches!(e, Event::RoundCompleted { .. })));
    assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
}

#[test]
fn a_sealed_peer_may_ask_for_any_chunk() {
    // Ruling S-3: no permission rule, whatever tier the peer reports.
    let sealed = FolderKey::from(folder(0x10)).lowered(Tier::Sealed).unwrap();
    let mut p = Pair::new(0xa0, 0xb0, &[FolderKey::from(folder(0x10))], &[sealed]);
    p.settle();
    p.b.prove_all(p.now);
    p.settle();
    p.b.request_chunk(p.now, CipherHash([5; 32])).unwrap();
    p.settle();
    assert!(p.a.saw(|e| matches!(e, Event::ChunkRequested { .. })));
}

#[test]
fn in_flight_limit_on_the_requester() {
    let mut p = Pair::open();
    p.a.auto = false;
    for i in 0..64u8 {
        p.b.request_chunk(p.now, CipherHash([i; 32])).unwrap();
    }
    assert_eq!(
        p.b.request_chunk(p.now, CipherHash([100; 32])).err(),
        Some(SendError::InFlightFull)
    );
}

#[test]
fn a_peer_advertising_u32_max_gets_max_requests_in_flight() {
    // SEC-B1: a requester keeps min(peer's max_requests_in_flight,
    // MAX_REQUESTS_IN_FLIGHT) outstanding, whatever the peer advertises.
    let mut p = Pair::new(
        0xa0,
        0xb0,
        &[FolderKey::from(folder(0x10))],
        &[FolderKey::from(folder(0x10))],
    );
    // A's Hello, before anything is delivered, advertises u32::MAX: the
    // connection's own Hello and the frame its transcript covers change alike
    // (white box: no Config may advertise more than MAX_REQUESTS_IN_FLIGHT).
    p.a.conn.hello.max_requests_in_flight = u32::MAX;
    p.a.conn.hello_frame = Message::Hello(Box::new(p.a.conn.hello.clone()))
        .to_frame()
        .unwrap();
    p.a.outbox = p.a.conn.hello_frame.encode();
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    assert!(p.b.conn.is_open(&p.b.folder_id()));
    assert_eq!(
        p.b.conn.peer().unwrap().hello.max_requests_in_flight,
        u32::MAX
    );
    p.a.auto = false;
    let n = usize::try_from(MAX_REQUESTS_IN_FLIGHT).unwrap();
    for i in 0..n {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(i as u64).to_be_bytes());
        p.b.request_chunk(p.now, CipherHash(h)).unwrap();
    }
    assert_eq!(
        p.b.request_chunk(p.now, CipherHash([0xff; 32])).err(),
        Some(SendError::InFlightFull)
    );
}

#[test]
fn a_hash_already_outstanding_is_not_asked_again() {
    // SEC-B1: one request per (folder, hash), across passes too.
    let mut p = Pair::open();
    p.a.auto = false;
    let h = CipherHash([7; 32]);
    p.b.request_chunk(p.now, h).unwrap();
    p.b.pass_done(p.now);
    assert_eq!(
        p.b.request_chunk(p.now, h).err(),
        Some(SendError::AlreadyRequested)
    );
    p.settle();
    p.a.reply_chunk(p.now, h, ChunkAnswer::NotFound).unwrap();
    p.settle();
    // Answered: no longer outstanding (the pass now waits for a trigger).
    assert_eq!(
        p.b.request_chunk(p.now, h).err(),
        Some(SendError::PassWaiting)
    );
}

#[test]
fn status_carries_chunks_stored_and_the_name_once() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    let status = |p: &crate::testkit::Side| -> Vec<Status> {
        p.sent
            .iter()
            .filter(|(_, fr)| fr[4..6] == [0x00, 0x01])
            .map(|(_, fr)| Status::parse(&fr[6..]).unwrap())
            .collect()
    };
    let one = |n: u64| FolderStatus {
        folder_id: f.0.to_vec(),
        chunks_stored: n,
        ..FolderStatus::default()
    };
    let out = p.a.conn.send_status(Tick::at(p.now), &[one(99)]).unwrap();
    p.a.apply(p.now, out);
    p.settle();
    assert!(p
        .b
        .saw(|e| matches!(e, Event::PeerNamed { device_name } if device_name == "device-a0")));
    // Fifty chunks within one second: one Status falls due, after 1 s.
    p.a.events.clear();
    for _ in 0..50 {
        let out = p.a.conn.chunk_stored(Tick::at(p.now), f);
        p.a.apply(p.now, out);
    }
    assert!(!p.a.saw(|e| matches!(e, Event::StatusDue)));
    p.a.auto = false;
    p.advance(s(1));
    assert_eq!(
        p.a.events
            .iter()
            .filter(|e| matches!(e, Event::StatusDue))
            .count(),
        1
    );
    let out = p.a.conn.send_status(Tick::at(p.now), &[one(0)]).unwrap();
    p.a.apply(p.now, out);
    let sent = status(&p.a);
    // The engine's Status at open carried the name and a count of 0; the
    // one sent by hand with 99 went out with the connection's count, 0; the
    // last with 50.
    assert_eq!(sent[0].folders[0].chunks_stored, 0, "0 in the first Status");
    assert_eq!(sent[0].device_name, "device-a0");
    let n = sent.len();
    assert_eq!(
        sent[n - 2].folders[0].chunks_stored,
        0,
        "the connection's count, not 99"
    );
    assert_eq!(sent[n - 1].folders[0].chunks_stored, 50);
    assert!(
        sent[1..].iter().all(|s| s.device_name.is_empty()),
        "only when it changes"
    );
    // A renamed device sends the name again.
    p.a.conn.set_device_name("new name".into()).unwrap();
    let out = p.a.conn.send_status(Tick::at(p.now), &[one(0)]).unwrap();
    p.a.apply(p.now, out);
    assert_eq!(status(&p.a).last().unwrap().device_name, "new name");
    // A Status naming a folder not open, and one with a bad name: closed.
    let mut q = Pair::open();
    let bad = Status {
        folders: vec![FolderStatus {
            folder_id: vec![8; 32],
            ..FolderStatus::default()
        }],
        device_name: String::new(),
    };
    q.b.receive(q.now, &frame(&Message::Status(bad)));
    assert_eq!(closed(&q.b).map(|c| c.0), Some(CloseReason::ProtocolError));
    let mut q = Pair::open();
    let mut body = Vec::new();
    prost::encoding::string::encode(2, &"a\u{1}b".to_string(), &mut body);
    q.b.receive(
        q.now,
        &crate::frame::Frame::new(0x0001, body).unwrap().encode(),
    );
    assert_eq!(closed(&q.b).map(|c| c.0), Some(CloseReason::ProtocolError));
    // Every STATUS_INTERVAL a Status falls due.
    let mut q = Pair::open();
    q.a.auto = false;
    q.a.events.clear();
    q.advance(s(30));
    assert!(q.a.saw(|e| matches!(e, Event::StatusDue)));
    // The engine may not name a folder that is not open, nor list more
    // entries than a Status holds.
    let bad = FolderStatus {
        folder_id: vec![8; 32],
        ..FolderStatus::default()
    };
    assert_eq!(
        q.a.conn.send_status(Tick::at(q.now), &[bad]).err(),
        Some(SendError::FolderNotOpen)
    );
    assert_eq!(
        q.a.conn
            .send_status(Tick::at(q.now), &vec![one(0); 1025])
            .err(),
        Some(SendError::Malformed)
    );
}

#[test]
fn a_status_without_room_is_skipped() {
    // SEC-SF2: a Status never waits behind other frames: with no room it is
    // refused, and the next one carries what it would have (the name too).
    let mut p = Pair::open();
    p.a.auto = false;
    p.a.conn.set_device_name("renamed".into()).unwrap();
    p.a.unsent = MAX_SEND_QUEUE - 10;
    let before = p.a.sent.len();
    assert!(matches!(
        p.a.status(p.now),
        Err(SendError::WouldBlock { .. })
    ));
    assert_eq!(p.a.sent.len(), before);
    assert_eq!(p.a.conn.backlog(), 0);
    p.a.unsent = 0;
    p.a.status(p.now).unwrap();
    let last = Status::parse(&p.a.sent.last().unwrap().1[6..]).unwrap();
    assert_eq!(last.device_name, "renamed");
}

#[test]
fn status_before_any_open_folder() {
    let mut p = Pair::new(
        0xa0,
        0xb0,
        &[FolderKey::from(folder(0x10))],
        &[FolderKey::from(folder(0x10))],
    );
    p.b.auto = false;
    p.settle();
    assert_eq!(p.a.conn.state(), State::Established);
    assert_eq!(
        p.a.conn.send_status(Tick::at(p.now), &[]).err(),
        Some(SendError::FolderNotOpen)
    );
    p.a.receive(p.now, &frame(&Message::Status(Status::default())));
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
}

#[test]
fn a_late_not_found_after_a_clean_pass_waits_too() {
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    let (h1, h2) = (CipherHash([1; 32]), CipherHash([2; 32]));
    p.b.request_chunk(p.now, h1).unwrap();
    p.b.request_chunk(p.now, h2).unwrap();
    // The engine ends the pass before the answers come: clean so far.
    p.b.pass_done(p.now);
    assert_eq!(p.b.conn.chunk_position(Tick::at(p.now), &f), Ok(None));
    // A NOT_FOUND arrives late: the next pass waits for a trigger.
    p.b.receive(p.now, &frame(&reply(&f, h1, 2, vec![])));
    assert_eq!(
        p.b.conn.chunk_position(Tick::at(p.now), &f),
        Err(SendError::PassWaiting)
    );
    // A second NOT_FOUND while waiting moves the earliest restart.
    p.now += s(5);
    p.b.receive(p.now, &frame(&reply(&f, h2, 2, vec![])));
    p.now += Duration::from_millis(500);
    p.b.receive(p.now, &status_frame(&f, 3));
    assert!(
        !p.b.saw(|e| matches!(e, Event::PassAllowed { .. })),
        "1 s after the latest NOT_FOUND"
    );
    let until = p.now + Duration::from_millis(500);
    wake_b_until(&mut p, until);
    assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
    assert_eq!(
        p.b.conn.chunk_position(Tick::at(p.now), &FolderId([9; 32])),
        Err(SendError::FolderNotOpen)
    );
}

#[test]
fn a_not_found_after_the_trigger_fired_needs_a_new_one() {
    // A trigger counts from the latest CHUNK_NOT_FOUND: a late one, after a
    // trigger was accepted and before the 1 s passed, spends it.
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.auto = false;
    p.b.auto = false;
    let (h1, h2) = (CipherHash([1; 32]), CipherHash([2; 32]));
    p.b.request_chunk(p.now, h1).unwrap();
    p.b.request_chunk(p.now, h2).unwrap();
    p.b.receive(p.now, &frame(&reply(&f, h1, 2, vec![])));
    p.b.pass_done(p.now);
    p.now += Duration::from_millis(200);
    p.b.receive(p.now, &status_frame(&f, 1));
    p.now += Duration::from_millis(200);
    p.b.receive(p.now, &frame(&reply(&f, h2, 2, vec![])));
    let until = p.now + s(5);
    wake_b_until(&mut p, until);
    assert!(!p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
    // A Status above the new baseline (1) is a new trigger, acted on at the
    // end of the window the first one opened.
    p.b.receive(p.now, &status_frame(&f, 2));
    let until = p.now + s(30);
    wake_b_until(&mut p, until);
    assert!(p.b.saw(|e| matches!(e, Event::PassAllowed { .. })));
}

#[test]
fn a_peer_that_floods_requests_and_never_reads_is_bounded() {
    // TM-22: every request counts against max_requests_in_flight until its
    // reply has left the backlog, BUSY ones included; a peer that never reads
    // fills at most that many replies here, and one request more closes.
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.a.unsent = MAX_SEND_QUEUE - 10;
    let limit = usize::try_from(p.a.conn.local_hello().max_requests_in_flight).unwrap();
    for i in 0..limit {
        let h = CipherHash([u8::try_from(i).unwrap(); 32]);
        p.a.receive(p.now, &frame(&request(&f, h)));
    }
    assert_eq!(p.a.conn.state(), State::Established);
    assert!(
        !p.a.saw(|e| matches!(e, Event::ChunkRequested { .. })),
        "all answered BUSY"
    );
    let busy = frame(&reply(&f, CipherHash([0; 32]), 3, vec![])).len();
    assert_eq!(
        p.a.conn.backlog(),
        limit * busy,
        "bounded by the in-flight limit"
    );
    p.a.receive(p.now, &frame(&request(&f, CipherHash([200; 32]))));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // Once the replies leave the backlog the peer may ask again.
    let mut p = Pair::open();
    p.a.auto = false;
    p.a.unsent = MAX_SEND_QUEUE - 10;
    for i in 0..limit {
        p.a.receive(
            p.now,
            &frame(&request(&f, CipherHash([u8::try_from(i).unwrap(); 32]))),
        );
    }
    p.a.unsent = 0;
    p.a.wake(p.now);
    assert_eq!(p.a.conn.backlog(), 0);
    p.a.receive(p.now, &frame(&request(&f, CipherHash([200; 32]))));
    assert_eq!(p.a.conn.state(), State::Established);
    // An engine reply counts too until it is handed over.
    let mut p = Pair::open();
    p.a.auto = false;
    for i in 0..limit {
        p.a.receive(
            p.now,
            &frame(&request(&f, CipherHash([u8::try_from(i).unwrap(); 32]))),
        );
    }
    p.a.unsent = MAX_SEND_QUEUE - 10;
    for i in 0..limit {
        p.a.reply_chunk(
            p.now,
            CipherHash([u8::try_from(i).unwrap(); 32]),
            ChunkAnswer::NotFound,
        )
        .unwrap();
    }
    p.a.receive(p.now, &frame(&request(&f, CipherHash([201; 32]))));
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
}
