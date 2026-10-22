// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Item 6: index records, their decoder variants and the outcomes of steps 2
//! to 6.

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::{CipherHash, DeviceId, RecordHash};
use prost::Message as _;
use serde_json::{json, Value};

use super::{check, h, seed};
use crate::limits::{MAX_INDEX_RECORD_BYTES, MAX_SEALED_BYTES, MAX_SEQ};
use crate::messages::{ChunkRef, IndexRecord, SealedMeta};
use crate::parse::Parse;
use crate::record::{
    judge, own_sequence_ahead, Arrival, Chunk, Draft, Kind, Meta, Record, WriterFault,
};
use crate::testkit::{device, envelope, flipped, folder, record_of, resigned, Store};

fn meta(path: &str, kind: Kind, hashes: usize, size: u64) -> Meta {
    Meta {
        path: path.into(),
        kind,
        size,
        mtime_ns: 1_760_000_000_000_000_000,
        mode: if kind == Kind::Directory {
            0o755
        } else {
            0o644
        },
        plain_hashes: (0..hashes)
            .map(|i| PlainHash([0x50 + u8::try_from(i).unwrap(); 32]))
            .collect(),
        written_at: 1_760_000_000,
    }
}

fn chunk(byte: u8) -> Chunk {
    Chunk {
        cipher_hash: CipherHash([byte; 32]),
        stored_len: 1064,
    }
}

fn record_json(r: &SignedRecord) -> Value {
    json!({ "signed_record": h(&r.to_bytes()), "body": h(r.body()), "signature": h(r.signature().as_bytes()), "record_hash": h(&r.hash().0) })
}

/// The vectors' writer: the device of seed a0.
fn writer() -> DeviceId {
    device(0xa0).0.device_id()
}

#[test]
fn vector_index_record() {
    let key = folder(0x10);
    let v = *key.verifier();
    let sign = |d: Draft, nonce: u8| d.sign(&key, &mut |b: &mut [u8]| b.fill(nonce)).unwrap();
    let draft =
        |seq: u64, supersedes: Vec<RecordHash>, deleted: bool, chunks: Vec<Chunk>, meta: Meta| {
            Draft {
                device_id: writer(),
                seq,
                supersedes,
                deleted,
                chunks,
                meta,
            }
        };
    let file = sign(
        draft(
            1,
            vec![],
            false,
            vec![chunk(0x61), chunk(0x62)],
            meta("docs/plan.txt", Kind::File, 2, 2000),
        ),
        0x31,
    );
    let edit = sign(
        draft(
            2,
            vec![file.hash()],
            false,
            vec![chunk(0x63)],
            meta("docs/plan.txt", Kind::File, 1, 900),
        ),
        0x32,
    );
    let dir = sign(
        draft(
            3,
            vec![],
            false,
            vec![],
            meta("docs", Kind::Directory, 0, 0),
        ),
        0x33,
    );
    let empty = sign(
        draft(
            4,
            vec![],
            false,
            vec![],
            meta("docs/empty", Kind::File, 0, 0),
        ),
        0x34,
    );
    let tomb = sign(
        draft(
            5,
            vec![empty.hash()],
            true,
            vec![],
            meta("docs/empty", Kind::File, 0, 0),
        ),
        0x35,
    );
    let rename = sign(
        draft(
            6,
            vec![edit.hash()],
            false,
            vec![chunk(0x63)],
            meta("docs/renamed.txt", Kind::File, 1, 900),
        ),
        0x36,
    );
    let mut canonical = Vec::new();
    for (name, r) in [
        ("new-file", &file),
        ("supersedes-one-version", &edit),
        ("directory", &dir),
        ("empty-file", &empty),
        ("tombstone", &tomb),
        ("rename", &rename),
    ] {
        let parsed = Record::parse(r.clone(), &v).unwrap();
        parsed.verify(&v).unwrap();
        let m = parsed.open(key.data_key()).unwrap();
        seed("index_record", name, &r.to_bytes());
        seed(
            "sealed_meta",
            name,
            &SealedMeta {
                path: m.path.clone(),
                kind: m.kind.to_wire(),
                ..SealedMeta::default()
            }
            .encode_to_vec(),
        );
        canonical.push(json!({ "name": name, "record": record_json(r), "path": m.path, "supersedes": parsed.supersedes().iter().map(|x| h(&x.0)).collect::<Vec<_>>() }));
    }

    // Decoder variants of step 1: re-signed so that only the variant differs.
    let body = IndexRecord::parse(file.body()).unwrap();
    let mut malformed = Vec::new();
    let mut variant = |name: &str, f: &dyn Fn(&mut IndexRecord), accepted: bool| {
        let mut b = body.clone();
        f(&mut b);
        let signed = key.sign_index_record(b.encode_to_vec());
        let got = Record::from_bytes(&signed.to_bytes(), &v);
        assert_eq!(got.is_ok(), accepted, "{name}: {got:?}");
        seed("index_record", name, &signed.to_bytes());
        malformed.push(json!({ "name": name, "signed_record": super::input(&signed.to_bytes()), "outcome": got.map_or_else(|e| format!("malformed: {e}"), |_| "accepted".into()) }));
    };
    variant("suite-0", &|b| b.suite = 0, false);
    variant("suite-other-than-the-folders", &|b| b.suite = 2, false);
    variant("record-type-1", &|b| b.record_type = 1, false);
    variant("seq-0", &|b| b.seq = 0, false);
    variant("seq-max-seq-plus-1", &|b| b.seq = MAX_SEQ + 1, false);
    variant("seq-max-seq", &|b| b.seq = MAX_SEQ, true);
    variant("device-id-31-bytes", &|b| b.device_id.truncate(31), false);
    variant("deleted-with-chunks", &|b| b.deleted = true, false);
    variant(
        "17-supersedes",
        &|b| b.supersedes = (0..17).map(|i| vec![i; 32]).collect(),
        false,
    );
    variant(
        "supersedes-entry-31-bytes",
        &|b| b.supersedes = vec![vec![1; 31]],
        false,
    );
    variant(
        "stored-len-not-padme-plus-40",
        &|b| {
            b.chunks[0] = ChunkRef {
                cipher_hash: vec![1; 32],
                stored_len: 1063,
            }
        },
        false,
    );
    variant("sealed-39-bytes", &|b| b.sealed = vec![0; 39], false);
    variant(
        "sealed-1572865-bytes",
        &|b| b.sealed = vec![0; MAX_SEALED_BYTES + 1],
        false,
    );
    variant("another-folder", &|b| b.folder_id = vec![9; 32], false);
    let long_sig = envelope(file.body(), &[0; 65]);
    assert!(Record::from_bytes(&long_sig, &v).is_err());
    malformed.push(json!({ "name": "signature-65-bytes", "signed_record": h(&long_sig), "outcome": "malformed" }));
    // An envelope one byte over MAX_INDEX_RECORD_BYTES: the file's body and
    // an unknown field of padding, refused at parse, before anything else.
    let mut pad = MAX_INDEX_RECORD_BYTES - file.to_bytes().len();
    let over = loop {
        let mut body = file.body().to_vec();
        prost::encoding::bytes::encode(99, &vec![0u8; pad], &mut body);
        let raw = envelope(&body, &[0; 64]);
        match raw.len().cmp(&(MAX_INDEX_RECORD_BYTES + 1)) {
            core::cmp::Ordering::Equal => break raw,
            core::cmp::Ordering::Greater => pad -= 1,
            core::cmp::Ordering::Less => pad += 1,
        }
    };
    assert_eq!(
        Record::from_bytes(&over, &v),
        Err(crate::wire::WireError::Record(
            licketysync_keys::records::Malformed::TooLarge(MAX_INDEX_RECORD_BYTES + 1)
        ))
    );
    malformed.push(json!({ "name": "one-byte-over-max-index-record-bytes", "encoded_len": over.len(), "prefix": h(&over[..64]), "outcome": "malformed" }));

    // Steps 2 to 6 against a holder whose index holds `file` (seq 1).
    let mut held = Store::default();
    held.insert(&Record::parse(file.clone(), &v).unwrap());
    let judged = |name: &str, r: &SignedRecord, arrival: Arrival| {
        let rec = Record::parse(r.clone(), &v).unwrap();
        let got = match judge(&rec, arrival, &held, &v) {
            Ok(j) => format!("{j:?}"),
            Err(c) => format!("close ({c:?})"),
        };
        json!({ "name": name, "signed_record": h(&r.to_bytes()), "arrival": format!("{arrival:?}"), "outcome": got })
    };
    let garbage = resigned(&file, [0; 64]);
    let mut fb = IndexRecord::parse(edit.body()).unwrap();
    fb.chunks[0].cipher_hash[0] ^= 1;
    let forged_flip = record_of(&fb.encode_to_vec(), edit.signature().as_bytes());
    let alien = {
        let mut b = IndexRecord::parse(edit.body()).unwrap();
        b.seq = 2;
        folder(0x20).sign_index_record(b.encode_to_vec())
    };
    let gap = sign(
        draft(3, vec![], false, vec![], meta("x", Kind::File, 0, 0)),
        0x40,
    );
    let gap_forged = flipped(&gap, 0);
    let concurrent_below = sign(
        draft(1, vec![], false, vec![], meta("other", Kind::File, 0, 0)),
        0x41,
    );
    let reply = Arrival::Reply { in_scope: true };
    let outcomes = vec![
        judged("duplicate-with-garbage-signature", &garbage, Arrival::Push),
        judged("gap-on-a-push", &gap, Arrival::Push),
        judged("gap-on-a-push-forged", &gap_forged, Arrival::Push),
        judged("gap-in-a-reply", &gap, reply),
        judged("gap-in-a-reply-forged", &gap_forged, reply),
        judged(
            "writer-outside-the-scope",
            &edit,
            Arrival::Reply { in_scope: false },
        ),
        judged("concurrent-version-at-the-cursor", &concurrent_below, reply),
        judged("at-cursor-plus-one", &edit, reply),
        judged(
            "forged-bit-flipped-in-a-bytes-field",
            &forged_flip,
            Arrival::Push,
        ),
        judged("forged-another-folders-key", &alien, Arrival::Push),
    ];
    let want = [
        "Duplicate",
        "PushGap",
        "PushGap",
        "close (SenderViolation)",
        "close (SenderViolation)",
        "close (SenderViolation)",
        "Concurrent",
        "Next",
        "close (Forged)",
        "close (Forged)",
    ];
    for (o, w) in outcomes.iter().zip(want) {
        assert_eq!(o["outcome"], w, "{}", o["name"]);
    }
    // A writer fault in the seal (moved from another record: the aad
    // differs), stored opaque; and a forged record that would also be one.
    let mut moved = IndexRecord::parse(edit.body()).unwrap();
    moved.sealed = IndexRecord::parse(file.body()).unwrap().sealed;
    let fault = key.sign_index_record(moved.encode_to_vec());
    let fault_rec = Record::parse(fault.clone(), &v).unwrap();
    assert_eq!(
        judge(&fault_rec, reply, &held, &v),
        Ok(crate::record::Judgement::Next),
        "stored, counted"
    );
    assert!(matches!(
        fault_rec.open(key.data_key()),
        Err(WriterFault::Seal(_))
    ));
    let fault_forged = flipped(&fault, 1);
    let ff = Record::parse(fault_forged.clone(), &v).unwrap();
    assert_eq!(
        judge(&ff, reply, &held, &v),
        Err(crate::rules::Cause::Forged),
        "forged wins"
    );
    // Writer faults in the metadata (step 6), sealed and signed as a writer
    // would not: a directory with one chunk, a file of size 5 without
    // chunks; and a path that is not NFC, accepted (NFC is the writer's
    // duty, so it is a path distinct from its NFC form).
    let forge = |seq: u64, chunks: Vec<ChunkRef>, meta: SealedMeta| {
        let sealed = licketysync_keys::sealed_meta::seal_meta(
            &key.data_key().record_key(),
            &v.folder_id(),
            &writer(),
            seq,
            &meta.encode_to_vec(),
            &mut |b: &mut [u8]| b.fill(0x44),
        )
        .unwrap();
        let body = IndexRecord {
            suite: 1,
            record_type: 16,
            folder_id: v.folder_id().0.to_vec(),
            device_id: writer().0.to_vec(),
            seq,
            chunks,
            sealed,
            ..IndexRecord::default()
        };
        key.sign_index_record(body.encode_to_vec())
    };
    let one_chunk = vec![ChunkRef {
        cipher_hash: vec![0x61; 32],
        stored_len: 1064,
    }];
    let dir_with_chunk = forge(
        7,
        one_chunk.clone(),
        SealedMeta {
            path: "d".into(),
            kind: 2,
            plain_hashes: vec![vec![1; 32]],
            ..SealedMeta::default()
        },
    );
    let file_without_chunks = forge(
        8,
        vec![],
        SealedMeta {
            path: "f".into(),
            kind: 1,
            size: 5,
            ..SealedMeta::default()
        },
    );
    let not_nfc = forge(
        9,
        vec![],
        SealedMeta {
            path: "cafe\u{301}".into(),
            kind: 1,
            ..SealedMeta::default()
        },
    );
    let opened = |r: &SignedRecord| {
        Record::parse(r.clone(), &v)
            .unwrap()
            .open(key.data_key())
            .map(|m| m.path)
    };
    assert_eq!(
        opened(&dir_with_chunk),
        Err(WriterFault::DirectoryWithChunks)
    );
    assert_eq!(
        opened(&file_without_chunks),
        Err(WriterFault::FileWithoutChunks)
    );
    assert_eq!(opened(&not_nfc).unwrap(), "cafe\u{301}");
    let metadata = json!([
        { "name": "directory-with-one-chunk", "record": record_json(&dir_with_chunk), "outcome": "WriterFault (DirectoryWithChunks)" },
        { "name": "file-of-size-5-without-chunks", "record": record_json(&file_without_chunks), "outcome": "WriterFault (FileWithoutChunks)" },
        { "name": "path-not-nfc", "record": record_json(&not_nfc), "outcome": "applied: a path distinct from its NFC form" },
    ]);
    for (name, r) in [
        ("directory-with-one-chunk", &dir_with_chunk),
        ("file-without-chunks", &file_without_chunks),
        ("path-not-nfc", &not_nfc),
    ] {
        seed("index_record", name, &r.to_bytes());
    }
    // A record under this device's own ID above its counter.
    let own = Record::parse(gap.clone(), &v).unwrap();
    assert!(own_sequence_ahead(&own, &writer(), 2));

    let value: Value = json!({
        "description": "protocol.md 8 item 6: canonical index records of device a0 in the fixed folder (seal nonces 31..36 repeated), step-1 variants re-signed so that only the variant differs, and the outcomes of steps 2 to 5 for a holder of the new-file record (seq 1), with a writer fault in the seal (stored and counted, opened by no one), a forged record that would also be one (forged wins), and a record under the holder's own device ID at or above its next seq.",
        "records": canonical,
        "malformed": malformed,
        "judged": outcomes,
        "writer_fault_in_the_seal": record_json(&fault),
        "writer_faults_in_the_metadata": metadata,
        "forged_writer_fault": record_json(&fault_forged),
        "own_device_above_its_counter": { "record": record_json(&gap), "next_seq": 2, "moves_the_counter": true },
    });
    check("index_record", &value);
}
