// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Item 9: chunks.

use licketysync_keys::chunk::seal_chunk;
use licketysync_keys::CipherHash;
use prost::Message as _;
use serde_json::{json, Value};

use super::{check, ending, h, scenario, seed};
use crate::connection::{ChunkAnswer, Event};
use crate::limits::{MAX_SEND_QUEUE, MAX_STORED_LEN};
use crate::messages::{ChunkReply, ChunkRequest, Message};
use crate::parse::Parse;
use crate::record::{Chunk, Record};
use crate::testkit::{folder, with_chunk, Pair};

fn frame(m: &Message) -> Vec<u8> {
    m.to_frame().unwrap().encode()
}

#[test]
fn vector_chunks() {
    let key = folder(0x10);
    let v = *key.verifier();
    let f = v.folder_id();
    // The keys crate's chunk vector: the bytes "chunk" sealed under the folder.
    let keys = key.chunk_keys();
    let raw = b"lickety-sync chunk vector";
    let sealed = seal_chunk(&keys, raw).unwrap();
    let plain = sealed.plain_hash;
    assert!(bool::from(plain.ct_eq(&keys.plain_hash(raw))));
    let req = ChunkRequest {
        folder_id: f.0.to_vec(),
        cipher_hash: sealed.cipher_hash.0.to_vec(),
    };
    let ok = ChunkReply {
        folder_id: f.0.to_vec(),
        cipher_hash: sealed.cipher_hash.0.to_vec(),
        status: 1,
        data: sealed.stored.clone(),
    };
    let nf = ChunkReply {
        status: 2,
        data: vec![],
        ..ok.clone()
    };
    let busy = ChunkReply {
        status: 3,
        data: vec![],
        ..ok.clone()
    };
    for (name, m) in [("ok", &ok), ("not-found", &nf), ("busy", &busy)] {
        assert!(ChunkReply::parse(&m.encode_to_vec()).is_ok());
        seed(
            "message_parse",
            &format!("chunk-reply-{name}"),
            &[&[8u8], &m.encode_to_vec()[..]].concat(),
        );
    }
    seed(
        "message_parse",
        "chunk-request",
        &[&[7u8], &req.encode_to_vec()[..]].concat(),
    );
    // Two records name the chunk; only one's stored_len and plain hash fit it.
    let good = Record::parse(
        with_chunk(
            &key,
            1,
            1,
            Chunk {
                cipher_hash: sealed.cipher_hash,
                stored_len: u32::try_from(sealed.stored.len()).unwrap(),
            },
            plain.0,
        ),
        &v,
    )
    .unwrap();
    let wrong = Record::parse(
        with_chunk(
            &key,
            1,
            2,
            Chunk {
                cipher_hash: sealed.cipher_hash,
                stored_len: 1064,
            },
            plain.0,
        ),
        &v,
    )
    .unwrap();
    let fits = |r: &Record| r.chunks()[0].stored_len as usize == sealed.stored.len();
    assert!(
        fits(&good) && !fits(&wrong),
        "a writer fault of the second record only"
    );
    let opened = licketysync_keys::chunk::open_chunk(&keys, &sealed.stored, &plain).unwrap();
    assert_eq!(opened.as_slice(), raw);

    // Served end to end, and the statuses.
    let mut p = Pair::open();
    p.a.auto = false;
    p.b.request_chunk(p.now, sealed.cipher_hash).unwrap();
    p.settle();
    assert!(p.a.saw(|e| matches!(e, Event::ChunkRequested { .. })));
    p.a.reply_chunk(p.now, sealed.cipher_hash, ChunkAnswer::Ok(&sealed.stored))
        .unwrap();
    p.settle();
    assert!(p.b.saw(|e| matches!(e, Event::Chunk { .. })));
    // Refusals.
    let refusals = {
        let mut out = Vec::new();
        let mut one = |name: &str, setup: &dyn Fn(&mut Pair), bytes: Vec<u8>, want: &str| {
            let mut q = Pair::open();
            q.b.auto = false;
            setup(&mut q);
            q.b.receive(q.now, &bytes);
            assert_eq!(ending(&q.b)["closed"], want, "{name}");
            seed("frame_decode", &format!("chunk-{name}"), &bytes);
            out.push(
                json!({ "name": name, "input": super::input(&bytes), "outcome": ending(&q.b) }),
            );
        };
        let asked = |q: &mut Pair| {
            q.b.request_chunk(q.now, CipherHash([5; 32])).unwrap();
        };
        let forged = ChunkReply {
            folder_id: f.0.to_vec(),
            cipher_hash: CipherHash([5; 32]).0.to_vec(),
            status: 1,
            data: vec![1; 46],
        };
        one(
            "forged",
            &asked,
            frame(&Message::ChunkReply(forged.clone())),
            "VERIFICATION_FAILED",
        );
        one(
            "unsolicited",
            &|_| {},
            frame(&Message::ChunkReply(forged)),
            "PROTOCOL_ERROR",
        );
        let mut big = Vec::new();
        prost::encoding::bytes::encode(1, &f.0.to_vec(), &mut big);
        prost::encoding::bytes::encode(2, &vec![5u8; 32], &mut big);
        prost::encoding::uint32::encode(3, &1, &mut big);
        prost::encoding::bytes::encode(4, &vec![0u8; MAX_STORED_LEN + 1], &mut big);
        one(
            "data-4325417-bytes",
            &asked,
            crate::frame::Frame::new(0x800a, big).unwrap().encode(),
            "PROTOCOL_ERROR",
        );
        let no_hash = ChunkRequest {
            folder_id: f.0.to_vec(),
            cipher_hash: vec![],
        };
        one(
            "request-without-cipher-hash",
            &|_| {},
            frame(&Message::ChunkRequest(no_hash)),
            "PROTOCOL_ERROR",
        );
        out
    };
    // CHUNK_BUSY exactly at half the queue; queued a byte below.
    let mut half = Pair::open();
    half.a.auto = false;
    half.a.unsent = MAX_SEND_QUEUE / 2;
    half.a
        .receive(half.now, &frame(&Message::ChunkRequest(req.clone())));
    let busy_sent = half.a.sent.last().unwrap().1.clone();
    assert_eq!(ChunkReply::parse(&busy_sent[6..]).unwrap().status, 3);
    half.a.unsent = MAX_SEND_QUEUE / 2 - 1;
    half.a
        .receive(half.now, &frame(&Message::ChunkRequest(req.clone())));
    assert!(half.a.saw(|e| matches!(e, Event::ChunkRequested { .. })));
    // A sealed peer is served (no permission rule).
    let sealed_key = licketysync_keys::folder::FolderKey::from(folder(0x10))
        .lowered(licketysync_keys::Tier::Sealed)
        .unwrap();
    let mut s3 = Pair::new(0xa0, 0xb0, &[super::key()], &[sealed_key]);
    s3.settle();
    s3.b.prove_all(s3.now);
    s3.settle();
    s3.a.auto = false;
    s3.b.request_chunk(s3.now, sealed.cipher_hash).unwrap();
    s3.settle();
    assert!(s3.a.saw(|e| matches!(e, Event::ChunkRequested { .. })));

    let value: Value = json!({
        "description": "protocol.md 8 item 9: a chunk of the fixed folder (raw bytes 'lickety-sync chunk vector'), its request and the three replies, a record whose stored_len fits it and one whose does not (a writer fault of that record only), the chunk served end to end, the replies that close, CHUNK_BUSY at exactly half of MAX_SEND_QUEUE and a queued request a byte below, and a request from a peer reporting the sealed tier, served. The backoff sequence (1, 2, 4 ... 64 s, back to 1 s) and the passes are the connection tests chunks::*.",
        "stored": h(&sealed.stored),
        "cipher_hash": h(&sealed.cipher_hash.0),
        "plain_hash": h(&plain.0),
        "request": h(&req.encode_to_vec()),
        "reply_ok": h(&ok.encode_to_vec()),
        "reply_not_found": h(&nf.encode_to_vec()),
        "reply_busy": h(&busy.encode_to_vec()),
        "record_fits": h(&good.signed().to_bytes()),
        "record_writer_fault": h(&wrong.signed().to_bytes()),
        "served": scenario(&p, &[], json!("B asks A for the chunk; A serves it")),
        "refusals": refusals,
        "busy_at_half": h(&busy_sent),
        "sealed_peer_served": scenario(&s3, &[], json!("B holds the sealed key")),
    });
    check("chunks", &value);
}
