// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Items 6 and 12, the protocol's part: canonical index records and a
//! cleanup (bodies, record hashes, signatures, sealed parts and aads), the
//! decoder variants of step 1 for both record types, the step-7 verdicts of
//! writer faults inside the seal, and forged records (step 5). What a record
//! then does to an index is the index crate's vectors.

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::{Malformed, SignedRecord};
use licketysync_keys::{CipherHash, DeviceId, RecordHash};
use prost::Message as _;
use serde_json::{json, Value};

use super::{check, h, input, seed};
use crate::limits::{
    MAX_CLEANUP_ENTRIES, MAX_CLEANUP_GROUPS, MAX_COUNTER, MAX_INDEX_RECORD_BYTES, MAX_REPLACES,
    MAX_SEALED_BYTES,
};
use crate::messages::{
    ChunkRef, CleanupGroup, CleanupRecord, IndexRecord, SealedMeta, VectorEntry,
};
use crate::parse::Parse;
use crate::record::{
    Applied, Chunk, CleanupDraft, Dot, Group, IndexDraft, Kind, Meta, Record, Vector, WriterFault,
};
use crate::rules::Cause;
use crate::testkit::{device, envelope, flipped, folder, record_of};
use crate::wire::WireError;

/// A decoder variant: its name, the change to the body, and whether a
/// reader accepts it.
type Variant<'a, T> = (&'static str, Box<dyn Fn(&mut T) + 'a>, bool);

/// The first counter of the vectors' writer: 2027-01-15, in microseconds.
const C: u64 = 1_800_000_000_000_000;

fn chunk(byte: u8) -> Chunk {
    Chunk {
        cipher_hash: CipherHash([byte; 32]),
        stored_len: 1064,
    }
}

/// A fixed seal nonce: `byte` repeated after one zero byte. The zero keeps
/// every record's fuzz seed binary to the repository's spelling check, which
/// otherwise reads words into random bytes.
fn nonce_of(b: &mut [u8], byte: u8) {
    b.fill(byte);
    if let Some(first) = b.first_mut() {
        *first = 0;
    }
}

/// The vectors' writer: the device of seed a0.
fn writer() -> DeviceId {
    device(0xa0).0.device_id()
}

fn dot(counter: u64) -> Dot {
    Dot {
        device: writer(),
        counter,
    }
}

fn meta(path: &str, kind: Kind, hashes: usize, size: u64, counter: u64) -> Meta {
    Meta {
        path: path.into(),
        kind,
        size,
        mtime_ns: 1_800_000_000_000_000_000,
        mode: if kind == Kind::Directory {
            0o755
        } else {
            0o644
        },
        plain_hashes: (0..hashes)
            .map(|i| PlainHash([0x50 + u8::try_from(i).unwrap(); 32]))
            .collect(),
        written_at: 1_800_000_000_000_000,
        dot: dot(counter),
        vector: Vector::default(),
        deleted: false,
        tree: false,
    }
}

fn record_json(r: &SignedRecord) -> Value {
    json!({ "signed_record": input(&r.to_bytes()), "body": input(r.body()), "signature": h(r.signature().as_bytes()), "record_hash": h(&r.hash().0) })
}

/// A step-7 verdict as a vector names it.
fn verdict(v: &Result<Applied, WriterFault>) -> String {
    match v {
        Ok(Applied::Index(m)) => format!("applied: {}", m.path),
        Ok(Applied::Cleanup(d)) => format!("applied: cleanup at counter {}", d.counter),
        Err(f) if f.is_shared() => format!("writer fault, shared ({f:?})"),
        Err(f) => format!("writer fault, not shared ({f:?})"),
    }
}

#[test]
fn vector_index_record() {
    let key = folder(0x10);
    let v = *key.verifier();
    let keys = key.record_keys();
    let sign = |d: IndexDraft, nonce: u8| {
        d.sign(&key, &keys, &mut |b: &mut [u8]| nonce_of(b, nonce))
            .unwrap()
    };
    let draft = |m: Meta, chunks: Vec<Chunk>, replaces: Vec<RecordHash>| IndexDraft {
        meta: m,
        chunks,
        replaces,
    };
    let with = |mut m: Meta, f: &dyn Fn(&mut Meta)| {
        f(&mut m);
        m
    };
    let one_entry = |counter: u64| Vector::from_sorted(vec![dot(counter)]).unwrap();

    // Item 6's canonical records, each with a fixed seal nonce.
    let file = sign(
        draft(
            meta("docs/plan.txt", Kind::File, 2, 2000, C),
            vec![chunk(0x61), chunk(0x62)],
            vec![],
        ),
        0x31,
    );
    let edit = sign(
        draft(
            with(meta("docs/plan.txt", Kind::File, 1, 900, C + 1), &|m| {
                m.vector = one_entry(C);
            }),
            vec![chunk(0x63)],
            vec![file.hash()],
        ),
        0x32,
    );
    let dir = sign(
        draft(meta("docs", Kind::Directory, 0, 0, C + 2), vec![], vec![]),
        0x33,
    );
    let empty = sign(
        draft(meta("docs/empty", Kind::File, 0, 0, C + 3), vec![], vec![]),
        0x34,
    );
    let tomb = sign(
        draft(
            with(meta("docs/empty", Kind::File, 0, 0, C + 4), &|m| {
                m.deleted = true;
                m.vector = one_entry(C + 3);
            }),
            vec![],
            vec![empty.hash()],
        ),
        0x35,
    );
    // A rename: the version at the new path, then the tombstone at the old.
    let renamed = sign(
        draft(
            with(meta("docs/renamed.txt", Kind::File, 1, 900, C + 5), &|m| {
                m.vector = one_entry(C + 1);
            }),
            vec![chunk(0x63)],
            vec![],
        ),
        0x36,
    );
    let renamed_from = sign(
        draft(
            with(meta("docs/plan.txt", Kind::File, 0, 0, C + 6), &|m| {
                m.deleted = true;
                m.vector = one_entry(C + 1);
            }),
            vec![],
            vec![edit.hash()],
        ),
        0x37,
    );
    let tree = sign(
        draft(
            with(meta("docs", Kind::Directory, 0, 0, C + 7), &|m| {
                m.deleted = true;
                m.tree = true;
                m.vector = one_entry(C + 6);
            }),
            vec![],
            vec![dir.hash()],
        ),
        0x38,
    );
    let wide = sign(
        draft(
            with(meta("wide", Kind::File, 0, 0, C + 8), &|m| {
                let mut entries: Vec<Dot> = (0..32u8)
                    .map(|i| Dot {
                        device: DeviceId(crate::testkit::fixed32(i.wrapping_mul(7))),
                        counter: C - u64::from(i) - 1,
                    })
                    .collect();
                entries.sort();
                m.vector = Vector::from_sorted(entries).unwrap();
            }),
            vec![],
            vec![],
        ),
        0x39,
    );
    let names_64: Vec<RecordHash> = (0..64u8)
        .map(|i| RecordHash(crate::testkit::fixed32(i.wrapping_mul(3))))
        .collect();
    let many = sign(
        draft(
            meta("many", Kind::File, 0, 0, C + 9),
            vec![],
            names_64.clone(),
        ),
        0x3a,
    );
    let cleanup = CleanupDraft {
        dot: dot(C + 10),
        groups: vec![
            Group {
                because: Some(edit.hash()),
                forget: vec![file.hash()],
            },
            Group {
                because: None,
                forget: vec![tomb.hash()],
            },
        ],
    }
    .sign(&key, &keys, &mut |b: &mut [u8]| nonce_of(b, 0x3b))
    .unwrap();
    let mut canonical = Vec::new();
    for (name, r) in [
        ("new-file", &file),
        ("edit-one-entry-one-name", &edit),
        ("directory", &dir),
        ("empty-file", &empty),
        ("tombstone", &tomb),
        ("rename-version-at-the-new-path", &renamed),
        ("rename-tombstone-at-the-old-path", &renamed_from),
        ("tree-delete", &tree),
        ("32-vector-entries", &wide),
        ("64-names", &many),
        ("cleanup-of-two-groups", &cleanup),
    ] {
        let parsed = Record::parse(r.clone(), &v).unwrap();
        parsed.verify(&v).unwrap();
        let opened = parsed.open(&keys);
        assert!(opened.is_ok(), "{name}");
        seed("index_record", name, &r.to_bytes());
        let (aad, plain) = match parsed.path_tag() {
            Some(tag) => {
                let mut aad = v.folder_id().0.to_vec();
                aad.extend_from_slice(&tag.0);
                (
                    aad,
                    keys.open_index_meta(&tag, parsed.sealed())
                        .unwrap()
                        .to_vec(),
                )
            }
            None => (
                v.folder_id().0.to_vec(),
                keys.open_cleanup_meta(parsed.sealed()).unwrap().to_vec(),
            ),
        };
        if parsed.path_tag().is_some() {
            seed("sealed_meta", name, &plain);
        }
        canonical.push(json!({
            "name": name,
            "record": record_json(r),
            "record_type": parsed.record_type().code(),
            "key": h(&parsed.key()),
            "aad": h(&aad),
            "sealed": input(parsed.sealed()),
            "opened_meta": h(&plain),
            "verdict": verdict(&opened),
            "replaces": parsed.replaces().iter().map(|x| h(&x.0)).collect::<Vec<_>>(),
        }));
    }

    // Decoder variants of step 1: re-signed so that only the variant differs.
    // A body the keys crate refuses to sign as its type (another record type)
    // gets a zero signature by hand, which step 1 refuses before any
    // signature is read.
    let mut malformed = Vec::new();
    let mut emit = |name: &str, bytes: Vec<u8>, accepted: bool| {
        let got = Record::from_bytes(&bytes, &v);
        assert_eq!(got.is_ok(), accepted, "{name}: {got:?}");
        seed("index_record", name, &bytes);
        malformed.push(json!({ "name": name, "signed_record": input(&bytes), "outcome": got.map_or_else(|e| format!("malformed: {e}"), |_| "accepted".into()) }));
    };
    let resign = |body: Vec<u8>, cleanup: bool| {
        let signed = if cleanup {
            key.sign_cleanup_record(body.clone())
        } else {
            key.sign_index_record(body.clone())
        };
        match signed {
            Ok(s) => s.to_bytes(),
            Err(Malformed::RecordType(_)) => envelope(&body, &[0; 64]),
            Err(e) => panic!("{e}"),
        }
    };
    let body = IndexRecord::parse(edit.body()).unwrap();
    let index_variants: Vec<Variant<'_, IndexRecord>> = vec![
        ("suite-0", Box::new(|b| b.suite = 0), false),
        (
            "suite-other-than-the-folders",
            Box::new(|b| b.suite = 2),
            false,
        ),
        ("record-type-1", Box::new(|b| b.record_type = 1), false),
        ("record-type-18", Box::new(|b| b.record_type = 18), false),
        (
            "path-tag-31-bytes",
            Box::new(|b| b.path_tag.truncate(31)),
            false,
        ),
        (
            "65-names",
            Box::new(|b| {
                b.replaces = (0..=MAX_REPLACES)
                    .map(|i| {
                        let mut x = vec![0; 32];
                        x[31] = u8::try_from(i).unwrap();
                        x
                    })
                    .collect();
            }),
            false,
        ),
        (
            "names-out-of-order",
            Box::new(|b| b.replaces = vec![vec![2; 32], vec![1; 32]]),
            false,
        ),
        (
            "a-repeated-name",
            Box::new(|b| b.replaces = vec![vec![1; 32], vec![1; 32]]),
            false,
        ),
        (
            "a-name-of-31-bytes",
            Box::new(|b| b.replaces = vec![vec![1; 31]]),
            false,
        ),
        (
            "stored-len-not-padme-plus-40",
            Box::new(|b| {
                b.chunks[0] = ChunkRef {
                    cipher_hash: vec![1; 32],
                    stored_len: 1063,
                };
            }),
            false,
        ),
        (
            "sealed-295-bytes",
            Box::new(|b| b.sealed.truncate(295)),
            false,
        ),
        ("sealed-297-bytes", Box::new(|b| b.sealed.push(0)), false),
        (
            "sealed-2097193-bytes",
            Box::new(|b| b.sealed = vec![0; MAX_SEALED_BYTES + 1]),
            false,
        ),
        (
            "sealed-2097192-bytes",
            Box::new(|b| b.sealed = vec![0; MAX_SEALED_BYTES]),
            true,
        ),
        (
            "another-folder",
            Box::new(|b| b.folder_id = vec![9; 32]),
            false,
        ),
    ];
    for (name, f, accepted) in &index_variants {
        let mut b = body.clone();
        f(&mut b);
        emit(name, resign(b.encode_to_vec(), false), *accepted);
    }
    let cbody = CleanupRecord::parse(cleanup.body()).unwrap();
    let name_of = |i: usize| {
        let mut x = vec![0; 32];
        x[28..].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        x
    };
    let cleanup_variants: Vec<Variant<'_, CleanupRecord>> = vec![
        (
            "cleanup-with-no-group",
            Box::new(|b| b.groups.clear()),
            false,
        ),
        (
            "cleanup-with-1025-groups",
            Box::new(|b| {
                b.groups = (0..=MAX_CLEANUP_GROUPS)
                    .map(|i| CleanupGroup {
                        because: vec![],
                        forget: vec![name_of(i)],
                    })
                    .collect();
            }),
            false,
        ),
        (
            "cleanup-with-16385-names",
            Box::new(|b| {
                b.groups = vec![CleanupGroup {
                    because: vec![],
                    forget: (0..=MAX_CLEANUP_ENTRIES).map(name_of).collect(),
                }];
            }),
            false,
        ),
        (
            "cleanup-with-16384-names",
            Box::new(|b| {
                b.groups = vec![CleanupGroup {
                    because: vec![],
                    forget: (0..MAX_CLEANUP_ENTRIES).map(name_of).collect(),
                }];
            }),
            true,
        ),
        // The record-wide budget at its edge (the review's P-4): 16 385 names
        // over two groups, each within the per-group bound, and 16 384.
        (
            "cleanup-with-16385-names-over-two-groups",
            Box::new(|b| {
                b.groups = vec![
                    CleanupGroup {
                        because: vec![],
                        forget: (0..MAX_CLEANUP_ENTRIES / 2).map(name_of).collect(),
                    },
                    CleanupGroup {
                        because: vec![],
                        forget: (MAX_CLEANUP_ENTRIES / 2..=MAX_CLEANUP_ENTRIES)
                            .map(name_of)
                            .collect(),
                    },
                ];
            }),
            false,
        ),
        (
            "cleanup-with-16384-names-over-two-groups",
            Box::new(|b| {
                b.groups = vec![
                    CleanupGroup {
                        because: vec![],
                        forget: (0..MAX_CLEANUP_ENTRIES / 2).map(name_of).collect(),
                    },
                    CleanupGroup {
                        because: vec![],
                        forget: (MAX_CLEANUP_ENTRIES / 2..MAX_CLEANUP_ENTRIES)
                            .map(name_of)
                            .collect(),
                    },
                ];
            }),
            true,
        ),
        (
            "cleanup-because-31-bytes",
            Box::new(|b| b.groups[0].because.truncate(31)),
            false,
        ),
        (
            "cleanup-names-out-of-order",
            Box::new(|b| b.groups[0].forget = vec![vec![2; 32], vec![1; 32]]),
            false,
        ),
        (
            "cleanup-sealed-297-bytes",
            Box::new(|b| b.sealed.push(0)),
            false,
        ),
        (
            "cleanup-record-type-16",
            Box::new(|b| b.record_type = 16),
            false,
        ),
    ];
    for (name, f, accepted) in &cleanup_variants {
        let mut b = cbody.clone();
        f(&mut b);
        emit(name, resign(b.encode_to_vec(), true), *accepted);
    }
    let long_sig = envelope(edit.body(), &[0; 65]);
    emit("signature-65-bytes", long_sig, false);
    // An envelope one byte over MAX_INDEX_RECORD_BYTES: the record's body and
    // an unknown field of padding, refused before anything else.
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
        Err(WireError::Record(Malformed::TooLarge(
            MAX_INDEX_RECORD_BYTES + 1
        )))
    );
    malformed.push(json!({ "name": "one-byte-over-max-index-record-bytes", "signed_record": input(&over), "outcome": "malformed" }));

    // Writer faults inside the seal (step 7), sealed and signed as a writer
    // would not, each beside the edge it is checked against.
    let base = SealedMeta {
        path: "f".into(),
        kind: 1,
        size: 1,
        mtime_ns: 1,
        mode: 0o644,
        plain_hashes: vec![vec![0x50; 32]],
        written_at: 1_800_000_000_000_000,
        device_id: writer().0.to_vec(),
        counter: C,
        vector: vec![],
        deleted: false,
        tree: false,
    };
    let one_chunk = vec![chunk(0x61)];
    let forge = |tag_path: &str, chunks: &[Chunk], m: &SealedMeta| {
        let tag = keys.path_tag(tag_path);
        let sealed = keys
            .seal_index_meta(&tag, &m.encode_to_vec(), &mut |b: &mut [u8]| {
                nonce_of(b, 0x44);
            })
            .unwrap();
        forge_body(&key, tag.0.to_vec(), chunks, sealed)
    };
    let entry = |device: u8, len: usize, counter: u64| VectorEntry {
        device_id: vec![device; len],
        counter,
    };
    let sm = |f: &dyn Fn(&mut SealedMeta)| {
        let mut m = base.clone();
        f(&mut m);
        m
    };
    let no_content = |m: &mut SealedMeta| {
        m.size = 0;
        m.plain_hashes.clear();
    };
    let cases: Vec<(&str, SealedMeta, &[Chunk], Option<WriterFault>)> = vec![
        (
            "counter-0",
            sm(&|m| m.counter = 0),
            &one_chunk,
            Some(WriterFault::Counter(0)),
        ),
        (
            "counter-max-counter-plus-1",
            sm(&|m| m.counter = MAX_COUNTER + 1),
            &one_chunk,
            Some(WriterFault::Counter(MAX_COUNTER + 1)),
        ),
        (
            "counter-max-counter",
            sm(&|m| m.counter = MAX_COUNTER),
            &one_chunk,
            None,
        ),
        (
            "device-id-31-bytes",
            sm(&|m| m.device_id.truncate(31)),
            &one_chunk,
            Some(WriterFault::DeviceId(31)),
        ),
        (
            "deleted-with-chunks",
            sm(&|m| m.deleted = true),
            &one_chunk,
            Some(WriterFault::DeletedWithChunks),
        ),
        (
            "tree-without-deleted",
            sm(&|m| m.tree = true),
            &one_chunk,
            Some(WriterFault::TreeWithoutDeleted),
        ),
        (
            "33-vector-entries",
            sm(&|m| m.vector = (0..33).map(|i| entry(i, 32, 1)).collect()),
            &one_chunk,
            Some(WriterFault::VectorLength),
        ),
        (
            "vector-entry-31-bytes",
            sm(&|m| m.vector = vec![entry(1, 31, 1)]),
            &one_chunk,
            Some(WriterFault::VectorDevice(31)),
        ),
        (
            "two-entries-for-one-device",
            sm(&|m| m.vector = vec![entry(1, 32, 1), entry(1, 32, 2)]),
            &one_chunk,
            Some(WriterFault::VectorDuplicate),
        ),
        (
            "entries-out-of-order",
            sm(&|m| m.vector = vec![entry(2, 32, 1), entry(1, 32, 1)]),
            &one_chunk,
            Some(WriterFault::VectorOrder),
        ),
        (
            "entry-equal-to-the-counter",
            sm(&|m| m.vector = vec![entry(1, 32, C)]),
            &one_chunk,
            Some(WriterFault::VectorCounterNotBelow),
        ),
        (
            "entry-one-below-the-counter",
            sm(&|m| m.vector = vec![entry(1, 32, C - 1)]),
            &one_chunk,
            None,
        ),
        (
            "entry-with-counter-0",
            sm(&|m| m.vector = vec![entry(1, 32, 0)]),
            &one_chunk,
            Some(WriterFault::VectorCounterZero),
        ),
        (
            "directory-with-one-chunk",
            sm(&|m| m.kind = 2),
            &one_chunk,
            Some(WriterFault::DirectoryWithChunks),
        ),
        (
            "file-of-size-5-without-chunks",
            sm(&|m| {
                m.size = 5;
                m.plain_hashes.clear();
            }),
            &[],
            Some(WriterFault::FileWithoutChunks),
        ),
        (
            "path-not-nfc",
            sm(&|m| m.path = "cafe\u{301}".into()),
            &one_chunk,
            None,
        ),
        (
            "tree-delete-of-kind-1",
            sm(&|m| {
                no_content(m);
                m.deleted = true;
                m.tree = true;
            }),
            &[],
            Some(WriterFault::TreeKindOrSize),
        ),
        (
            "tree-delete-of-size-5",
            sm(&|m| {
                no_content(m);
                m.kind = 2;
                m.size = 5;
                m.deleted = true;
                m.tree = true;
            }),
            &[],
            Some(WriterFault::TreeKindOrSize),
        ),
        (
            "unknown-kind",
            sm(&|m| m.kind = 3),
            &one_chunk,
            Some(WriterFault::Kind(3)),
        ),
    ];
    let mut faults = Vec::new();
    for (name, m, chunks, want) in &cases {
        let r = forge(&m.path, chunks, m);
        let parsed = Record::parse(r.clone(), &v).unwrap();
        parsed.verify(&v).unwrap();
        let got = parsed.open(&keys);
        assert_eq!(got.as_ref().err(), want.as_ref(), "{name}");
        seed("index_record", name, &r.to_bytes());
        faults.push(json!({ "name": name, "record": record_json(&r), "outcome": verdict(&got) }));
    }
    // A path whose tag is not `path_tag`; a seal moved from another record
    // (its aad differs); a seal padded one power of two past the least (the
    // keys crate's case, at its fixed path).
    let wrong_tag = forge("other", &one_chunk, &base);
    let mut moved = IndexRecord::parse(edit.body()).unwrap();
    moved.sealed = IndexRecord::parse(file.body()).unwrap().sealed;
    moved.path_tag = keys.path_tag("docs/elsewhere").0.to_vec();
    let moved = key.sign_index_record(moved.encode_to_vec()).unwrap();
    let over_padded = forge_body(
        &key,
        keys.path_tag("docs/report.txt").0.to_vec(),
        &[],
        include_bytes!("../../../../fuzz/seeds/sealed_meta_open/index-300-in-1024").to_vec(),
    );
    for (name, r, want) in [
        ("path-tag-not-the-paths", &wrong_tag, "PathTag"),
        ("seal-moved-from-another-path", &moved, "Seal(Open)"),
        (
            "sealed-one-power-of-two-past-the-least",
            &over_padded,
            "Seal(OverPadded)",
        ),
    ] {
        let parsed = Record::parse(r.clone(), &v).unwrap();
        let got = parsed.open(&keys);
        assert!(verdict(&got).contains(want), "{name}: {got:?}");
        seed("index_record", name, &r.to_bytes());
        faults.push(json!({ "name": name, "record": record_json(r), "outcome": verdict(&got) }));
    }

    // Forged (step 5): a bit flipped inside a bytes field, so that the body
    // still parses; a record signed by another folder's key; a cleanup signed
    // under the index label (the keys crate's vector, signed as only a test
    // can); a forged record that would also be a writer fault.
    let mut fb = IndexRecord::parse(edit.body()).unwrap();
    fb.chunks[0].cipher_hash[0] ^= 1;
    let flipped_body = record_of(&fb.encode_to_vec(), edit.signature().as_bytes());
    let alien = folder(0x20)
        .sign_index_record(edit.body().to_vec())
        .unwrap();
    let keys_vector: Value = serde_json::from_str(include_str!(
        "../../../keys/tests/vectors/index_record.json"
    ))
    .unwrap();
    let under_index = &keys_vector["cleanup"]["signed_under_sig_index"]["record"];
    let hex_of = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let cleanup_as_index = record_of(
        &hex_of(&under_index["body"]),
        &hex_of(&under_index["signature"]).try_into().unwrap(),
    );
    let forged_fault = flipped(&moved, 1);
    let mut forged = Vec::new();
    for (name, r) in [
        ("bit-flipped-in-a-bytes-field", &flipped_body),
        ("signed-by-another-folders-key", &alien),
        ("cleanup-signed-under-the-index-label", &cleanup_as_index),
        ("forged-and-a-writer-fault", &forged_fault),
    ] {
        let parsed = Record::parse(r.clone(), &v).unwrap();
        assert_eq!(parsed.verify(&v), Err(Cause::Forged), "{name}");
        seed("index_record", name, &r.to_bytes());
        forged.push(json!({ "name": name, "record": record_json(r), "outcome": "forged: Close(VERIFICATION_FAILED)" }));
    }
    assert!(matches!(
        Record::parse(forged_fault.clone(), &v).unwrap().open(&keys),
        Err(WriterFault::Seal(_))
    ));

    let value: Value = json!({
        "description": "protocol.md 8 items 6 and 12, the protocol's part: canonical records of device a0 in the fixed folder (seal nonces a zero byte, then 31 to 3b repeated; the cleanup's groups name the new file because the edit, and the tombstone with because empty), the decoder variants of step 1 re-signed so that only the variant differs (another record type with a zero signature by hand), the step-7 verdicts of writer faults inside the seal and of the edges beside them, and forged records (step 5). What each record does to an index is the index crate's vector.",
        "first_counter": C,
        "writer": h(&writer().0),
        "records": canonical,
        "malformed": malformed,
        "writer_faults": faults,
        "forged": forged,
    });
    check("index_record", &value);
}

/// An index record body around `sealed`, signed by the folder key.
fn forge_body(
    key: &licketysync_keys::WriteKey,
    path_tag: Vec<u8>,
    chunks: &[Chunk],
    sealed: Vec<u8>,
) -> SignedRecord {
    let body = IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: key.verifier().folder_id().0.to_vec(),
        chunks: chunks
            .iter()
            .map(|c| ChunkRef {
                cipher_hash: c.cipher_hash.0.to_vec(),
                stored_len: c.stored_len,
            })
            .collect(),
        sealed,
        path_tag,
        replaces: vec![],
    };
    key.sign_index_record(body.encode_to_vec()).unwrap()
}
