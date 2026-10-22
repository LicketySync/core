// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code"
)]

use proptest::prelude::*;
use prost::encoding::{encode_key, encode_varint, WireType as PWT};
use prost::Message as _;

use super::*;
use crate::frame::MessageType;
use crate::messages::Message;

fn varint(buf: &mut Vec<u8>, field: u32, v: u64) {
    encode_key(field, PWT::Varint, buf);
    encode_varint(v, buf);
}

fn bytes_field(buf: &mut Vec<u8>, field: u32, b: &[u8]) {
    encode_key(field, PWT::LengthDelimited, buf);
    encode_varint(b.len() as u64, buf);
    buf.extend_from_slice(b);
}

fn hello() -> Hello {
    Hello {
        device_public_key: vec![0, 1, 7, 7],
        suites: vec![1],
        compressions: vec!["none".into()],
        hashes: vec!["blake3".into()],
        features: vec!["x-y:z".into()],
        max_message_size: 16 << 20,
        max_requests_in_flight: 64,
        nonce: vec![9; 32],
        libp2p_identity: vec![8; 32],
    }
}

fn signed(body: &IndexRecord) -> Vec<u8> {
    crate::testkit::envelope(&body.encode_to_vec(), &[5; 64])
}

fn record() -> IndexRecord {
    IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: vec![1; 32],
        device_id: vec![2; 32],
        seq: 1,
        supersedes: vec![vec![3; 32], vec![4; 32]],
        deleted: false,
        chunks: vec![ChunkRef {
            cipher_hash: vec![6; 32],
            stored_len: 46,
        }],
        sealed: vec![0; 40],
    }
}

fn request() -> IndexRequest {
    IndexRequest {
        folder_id: vec![1; 32],
        have: vec![
            Cursor {
                device_id: vec![2; 32],
                seq: 0,
                digest: vec![],
            },
            Cursor {
                device_id: vec![3; 32],
                seq: 4,
                digest: vec![5; 32],
            },
        ],
        max_records: 0,
        request_id: 1,
        after: vec![],
        through: vec![],
        listed: false,
    }
}

/// Encodes `m` and parses it back: the value is the same.
fn round_trip<M: prost::Message + Parse + PartialEq + core::fmt::Debug>(m: &M) {
    assert_eq!(&M::parse(&m.encode_to_vec()).unwrap(), m);
}

#[test]
fn every_message_round_trips() {
    round_trip(&hello());
    round_trip(&Close {
        reason: 1,
        detail: "bye".into(),
    });
    round_trip(&Unsupported {
        message_type: 0x7fff,
    });
    round_trip(&DeviceProof {
        signature: vec![1; 64],
    });
    round_trip(&FolderProof {
        hint: vec![1; 32],
        sealed: vec![2; 18],
        nonce: vec![3; 24],
    });
    round_trip(&ProofPayload { tier: 3 });
    round_trip(&ProofResult {
        hint: vec![1; 32],
        status: 2,
    });
    round_trip(&record());
    round_trip(&SealedMeta {
        path: "a/b".into(),
        kind: 1,
        size: 9,
        mtime_ns: -5,
        mode: 0o644,
        plain_hashes: vec![vec![1; 32]],
        written_at: 77,
    });
    round_trip(&request());
    round_trip(&IndexRecords {
        folder_id: vec![1; 32],
        records: vec![signed(&record())],
        more: true,
        request_id: 3,
    });
    round_trip(&Status {
        folders: vec![FolderStatus {
            folder_id: vec![1; 32],
            index_records: 1,
            bytes_needed: 2,
            paused: true,
            free_disk_bytes: 3,
            chunks_stored: 4,
        }],
        device_name: "laptop".into(),
    });
    round_trip(&ChunkRequest {
        folder_id: vec![1; 32],
        cipher_hash: vec![2; 32],
    });
    round_trip(&ChunkReply {
        folder_id: vec![1; 32],
        cipher_hash: vec![2; 32],
        status: 1,
        data: vec![3; 46],
    });
}

#[test]
fn decoder_rules_shared_by_every_body() {
    // A field number of 2^29 and a group wire type are malformed, known field
    // or not; 2^29 - 1 is an unknown field and skipped.
    let mut body = Close::default().encode_to_vec();
    body.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x10, 0]);
    assert_eq!(Close::parse(&body), Err(WireError::FieldNumber(1 << 29)));
    let mut body = Vec::new();
    body.extend_from_slice(&[0xf8, 0xff, 0xff, 0xff, 0x0f, 0]);
    assert_eq!(Close::parse(&body).unwrap(), Close::default());
    assert_eq!(Close::parse(&[0x0b]), Err(WireError::UnknownWireType(3)));
    assert_eq!(Close::parse(&[0x13]), Err(WireError::UnknownWireType(3)));
    // A singular field twice is malformed; an unknown one twice is skipped.
    let mut body = Vec::new();
    varint(&mut body, 1, 1);
    varint(&mut body, 1, 2);
    assert_eq!(Close::parse(&body), Err(WireError::Repeated { field: 1 }));
    let mut body = Vec::new();
    varint(&mut body, 9, 1);
    varint(&mut body, 9, 2);
    assert_eq!(Close::parse(&body).unwrap(), Close::default());
    // bool 2 and uint32 2^32 are malformed.
    let mut body = request().encode_to_vec();
    varint(&mut body, 7, 2);
    assert_eq!(
        IndexRequest::parse(&body),
        Err(WireError::OutOfRange { what: "listed" })
    );
    let mut body = Vec::new();
    varint(&mut body, 1, 1 << 32);
    assert_eq!(
        Close::parse(&body),
        Err(WireError::OutOfRange { what: "reason" })
    );
    // A known field of the wrong wire type is malformed.
    let mut body = Vec::new();
    bytes_field(&mut body, 1, b"x");
    assert_eq!(
        Close::parse(&body),
        Err(WireError::WrongWireType { field: 1 })
    );
}

#[test]
fn hello_lists_and_grammar() {
    // suites packed, unpacked and partly each mean the same.
    let base = Hello {
        suites: vec![],
        ..hello()
    }
    .encode_to_vec();
    let mut packed = base.clone();
    bytes_field(&mut packed, 3, &[1, 2, 3]);
    let mut unpacked = base.clone();
    for s in [1, 2, 3] {
        varint(&mut unpacked, 3, s);
    }
    let mut mixed = base.clone();
    varint(&mut mixed, 3, 1);
    bytes_field(&mut mixed, 3, &[2, 3]);
    for body in [&packed, &unpacked, &mixed] {
        assert_eq!(Hello::parse(body).unwrap().suites, vec![1, 2, 3]);
    }
    // Reserved field 2 (the drafts' device_name) is skipped.
    let mut with_name = hello().encode_to_vec();
    bytes_field(&mut with_name, 2, b"old name");
    assert_eq!(Hello::parse(&with_name).unwrap(), hello());
    for (h, what) in [
        (
            Hello {
                suites: vec![0],
                ..hello()
            },
            WireError::OutOfRange { what: "suites" },
        ),
        (
            Hello {
                suites: vec![65_536],
                ..hello()
            },
            WireError::OutOfRange { what: "suites" },
        ),
        (
            Hello {
                suites: vec![1; 17],
                ..hello()
            },
            WireError::LimitExceeded {
                what: "suites",
                limit: 16,
                offered: 17,
            },
        ),
        (
            Hello {
                features: vec!["Bad".into()],
                ..hello()
            },
            WireError::Grammar { what: "features" },
        ),
        (
            Hello {
                features: vec!["f".into(); 33],
                ..hello()
            },
            WireError::LimitExceeded {
                what: "features",
                limit: 32,
                offered: 33,
            },
        ),
        (
            Hello {
                compressions: vec!["a:b".into()],
                ..hello()
            },
            WireError::Grammar {
                what: "compressions",
            },
        ),
        (
            Hello {
                hashes: vec!["h".into(); 33],
                ..hello()
            },
            WireError::LimitExceeded {
                what: "hashes",
                limit: 32,
                offered: 33,
            },
        ),
    ] {
        assert_eq!(Hello::parse(&h.encode_to_vec()), Err(what));
    }
    let long = Hello {
        compressions: vec!["c".repeat(21)],
        ..hello()
    };
    assert!(matches!(
        Hello::parse(&long.encode_to_vec()),
        Err(WireError::LimitExceeded { .. })
    ));
}

#[test]
fn close_detail_grammar_and_the_reason_kept_without_it() {
    let bad = Close {
        reason: 7,
        detail: "a\u{7}b".into(),
    }
    .encode_to_vec();
    assert_eq!(
        Close::parse(&bad),
        Err(WireError::Grammar { what: "detail" })
    );
    assert_eq!(
        close_without_detail(&bad),
        Close {
            reason: 7,
            detail: String::new()
        }
    );
    let long = Close {
        reason: 3,
        detail: "x".repeat(257),
    }
    .encode_to_vec();
    assert!(Close::parse(&long).is_err());
    assert_eq!(close_without_detail(&long).reason, 3);
    assert_eq!(
        close_without_detail(&[0x0b]).reason,
        0,
        "a body that does not parse: 0"
    );
    let at_bound = Close {
        reason: 3,
        detail: "x".repeat(256),
    };
    assert_eq!(Close::parse(&at_bound.encode_to_vec()), Ok(at_bound));
    assert!(is_device_name("Pixel \u{200d} 9"), "format characters pass");
    assert!(!is_device_name("tab\there"));
    assert!(!is_device_name(&"n".repeat(65)));
}

#[test]
fn proof_messages_sizes() {
    let mut body = Vec::new();
    bytes_field(&mut body, 1, &[1; 63]);
    assert_eq!(
        DeviceProof::parse(&body),
        Err(WireError::WrongLength {
            what: "signature",
            expected: 64,
            got: 63
        })
    );
    assert!(DeviceProof::parse(&[]).is_err(), "absent is malformed");
    let ok = FolderProof {
        hint: vec![1; 32],
        sealed: vec![2; 16],
        nonce: vec![3; 24],
    };
    round_trip(&ok);
    for bad in [
        FolderProof {
            hint: vec![1; 31],
            ..ok.clone()
        },
        FolderProof {
            nonce: vec![3; 12],
            ..ok.clone()
        },
        FolderProof {
            sealed: vec![2; 15],
            ..ok.clone()
        },
        FolderProof {
            sealed: vec![2; 1_025],
            ..ok.clone()
        },
    ] {
        assert!(FolderProof::parse(&bad.encode_to_vec()).is_err(), "{bad:?}");
    }
    let max = FolderProof {
        sealed: vec![2; 1_024],
        ..ok
    };
    round_trip(&max);
    // ProofPayload: the drafts' fields 1 to 3 are skipped, tier read.
    let mut payload = Vec::new();
    bytes_field(&mut payload, 1, &[0; 16]);
    bytes_field(&mut payload, 3, &[0; 4]);
    varint(&mut payload, 4, 2);
    assert_eq!(ProofPayload::parse(&payload).unwrap().tier, 2);
    for status in [0, 3] {
        let r = ProofResult {
            hint: vec![1; 32],
            status,
        };
        assert_eq!(
            ProofResult::parse(&r.encode_to_vec()),
            Err(WireError::OutOfRange { what: "status" })
        );
    }
    assert!(ProofResult::parse(&[]).is_err(), "hint absent");
    let mut evidence = ProofResult {
        hint: vec![1; 32],
        status: 2,
    }
    .encode_to_vec();
    bytes_field(&mut evidence, 4, &[1, 2, 3]);
    assert_eq!(ProofResult::parse(&evidence).unwrap().status, 2);
    assert_eq!(
        Unsupported::parse(
            &Unsupported {
                message_type: 0x1_0000
            }
            .encode_to_vec()
        ),
        Err(WireError::OutOfRange {
            what: "message_type"
        })
    );
}

#[test]
fn index_record_step_one() {
    let ok = record();
    round_trip(&ok);
    let at_max = IndexRecord {
        seq: MAX_SEQ,
        ..record()
    };
    round_trip(&at_max);
    let cases: Vec<(IndexRecord, &str)> = vec![
        (
            IndexRecord {
                suite: 0,
                ..record()
            },
            "suite 0",
        ),
        (
            IndexRecord {
                suite: 65_536,
                ..record()
            },
            "suite too large",
        ),
        (
            IndexRecord {
                record_type: 1,
                ..record()
            },
            "record type",
        ),
        (IndexRecord { seq: 0, ..record() }, "seq 0"),
        (
            IndexRecord {
                seq: MAX_SEQ + 1,
                ..record()
            },
            "seq over",
        ),
        (
            IndexRecord {
                device_id: vec![2; 31],
                ..record()
            },
            "device id 31",
        ),
        (
            IndexRecord {
                folder_id: vec![],
                ..record()
            },
            "folder id absent",
        ),
        (
            IndexRecord {
                deleted: true,
                ..record()
            },
            "deleted with chunks",
        ),
        (
            IndexRecord {
                supersedes: vec![vec![3; 32]; 17],
                ..record()
            },
            "17 supersedes",
        ),
        (
            IndexRecord {
                supersedes: vec![vec![3; 31]],
                ..record()
            },
            "supersedes 31",
        ),
        (
            IndexRecord {
                sealed: vec![0; 39],
                ..record()
            },
            "sealed 39",
        ),
        (
            IndexRecord {
                sealed: vec![0; MAX_SEALED_BYTES + 1],
                ..record()
            },
            "sealed over",
        ),
        (
            IndexRecord {
                chunks: vec![ChunkRef {
                    cipher_hash: vec![6; 32],
                    stored_len: 49,
                }],
                ..record()
            },
            "stored_len not padme + 40",
        ),
        (
            IndexRecord {
                chunks: vec![ChunkRef {
                    cipher_hash: vec![6; 32],
                    stored_len: 45,
                }],
                ..record()
            },
            "stored_len below 46",
        ),
        (
            IndexRecord {
                chunks: vec![ChunkRef {
                    cipher_hash: vec![6; 31],
                    stored_len: 46,
                }],
                ..record()
            },
            "cipher hash 31",
        ),
    ];
    for (bad, why) in cases {
        assert!(IndexRecord::parse(&bad.encode_to_vec()).is_err(), "{why}");
    }
    let sealed_max = IndexRecord {
        sealed: vec![0; MAX_SEALED_BYTES],
        ..record()
    };
    round_trip(&sealed_max);
    let tomb = IndexRecord {
        deleted: true,
        chunks: vec![],
        ..record()
    };
    round_trip(&tomb);
    // Reserved fields (4 writer_key_id, 7 previous, 9 version, 10 epoch, 14
    // resumes) read as unknown fields: skipped.
    let mut body = record().encode_to_vec();
    bytes_field(&mut body, 4, &[0; 16]);
    bytes_field(&mut body, 7, &[0; 32]);
    varint(&mut body, 10, 3);
    bytes_field(&mut body, 14, &[0; 32]);
    assert_eq!(IndexRecord::parse(&body).unwrap(), record());
    // The largest and smallest stored lengths are fine.
    assert!(is_stored_len(46));
    assert!(is_stored_len(4_325_416));
    assert!(!is_stored_len(4_325_417));
    assert!(!is_stored_len(4_325_416 - 1));
}

#[test]
fn cursors_and_requests() {
    let c = |device: u8, seq: u64, digest: usize| Cursor {
        device_id: vec![device; 32],
        seq,
        digest: vec![7; digest],
    };
    round_trip(&c(1, 0, 0));
    round_trip(&c(1, MAX_SEQ, 32));
    for bad in [c(1, 0, 32), c(1, 1, 0), c(1, 1, 31), c(1, MAX_SEQ + 1, 32)] {
        assert!(Cursor::parse(&bad.encode_to_vec()).is_err(), "{bad:?}");
    }
    let with = |have: Vec<Cursor>, after: Vec<u8>, through: Vec<u8>, listed: bool| IndexRequest {
        have,
        after,
        through,
        listed,
        ..request()
    };
    // Accepted shapes.
    for ok in [
        with(vec![], vec![], vec![], false),
        with(vec![c(5, 1, 32)], vec![4; 32], vec![5; 32], false),
        with(vec![c(5, 1, 32), c(6, 0, 0)], vec![], vec![], true),
    ] {
        round_trip(&ok);
    }
    // Refused shapes.
    for (bad, why) in [
        (
            with(vec![c(3, 0, 0), c(2, 0, 0)], vec![], vec![], false),
            "unsorted",
        ),
        (
            with(vec![c(2, 0, 0), c(2, 0, 0)], vec![], vec![], false),
            "twice",
        ),
        (
            with(vec![c(4, 0, 0)], vec![4; 32], vec![], false),
            "at after",
        ),
        (
            with(vec![c(6, 0, 0)], vec![], vec![5; 32], false),
            "past through",
        ),
        (
            with(vec![], vec![5; 32], vec![5; 32], false),
            "after = through",
        ),
        (
            with(vec![], vec![6; 32], vec![5; 32], false),
            "after > through",
        ),
        (
            with(vec![c(5, 0, 0)], vec![4; 32], vec![], true),
            "listed with a range",
        ),
        (with(vec![], vec![], vec![], true), "listed empty"),
        (with(vec![], vec![4; 31], vec![], false), "after 31"),
        (with(vec![], vec![], vec![4; 33], false), "through 33"),
    ] {
        assert!(IndexRequest::parse(&bad.encode_to_vec()).is_err(), "{why}");
    }
    assert!(IndexRequest::parse(
        &IndexRequest {
            request_id: 0,
            ..request()
        }
        .encode_to_vec()
    )
    .is_err());
    // MAX_CURSORS_PER_REQUEST cursors pass; one more is malformed.
    let many = |n: usize| IndexRequest {
        have: (0..n)
            .map(|i| Cursor {
                device_id: {
                    let mut d = vec![0; 32];
                    d[28..].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
                    d
                },
                seq: 0,
                digest: vec![],
            })
            .collect(),
        ..request()
    };
    round_trip(&many(MAX_CURSORS_PER_REQUEST));
    assert_eq!(
        IndexRequest::parse(&many(MAX_CURSORS_PER_REQUEST + 1).encode_to_vec()),
        Err(WireError::LimitExceeded {
            what: "have",
            limit: MAX_CURSORS_PER_REQUEST,
            offered: MAX_CURSORS_PER_REQUEST as u64 + 1
        })
    );
}

#[test]
fn index_records_pages_and_embedded_envelopes() {
    let page = |records: Vec<Vec<u8>>, more: bool, request_id: u32| IndexRecords {
        folder_id: vec![1; 32],
        records,
        more,
        request_id,
    };
    round_trip(&page(vec![], false, 0));
    assert_eq!(
        IndexRecords::parse(&page(vec![], true, 0).encode_to_vec()),
        Err(WireError::Grammar {
            what: "a push with more"
        })
    );
    // A reply page with more must hold a record (4.5); the last may be empty.
    round_trip(&page(vec![], false, 9));
    assert_eq!(
        IndexRecords::parse(&page(vec![], true, 9).encode_to_vec()),
        Err(WireError::Grammar {
            what: "a page with more and no records"
        })
    );
    let one = signed(&record());
    round_trip(&page(vec![one.clone()], true, 9));
    // Exactly MAX_PAGE_RECORDS records pass; one more is malformed.
    round_trip(&page(vec![one.clone(); MAX_PAGE_RECORDS], true, 9));
    assert!(matches!(
        IndexRecords::parse(
            &page(vec![one.clone(); MAX_PAGE_RECORDS + 1], false, 9).encode_to_vec()
        ),
        Err(WireError::LimitExceeded { .. })
    ));
    // Every embedded record passes keys' envelope decoder.
    let short_sig = crate::testkit::envelope(&record().encode_to_vec(), &[0; 63]);
    assert_eq!(
        IndexRecords::parse(&page(vec![short_sig], false, 1).encode_to_vec()),
        Err(WireError::Record(
            licketysync_keys::records::Malformed::SignatureSize(63)
        ))
    );
    let not_index = crate::testkit::envelope(
        &IndexRecord {
            record_type: 2,
            ..record()
        }
        .encode_to_vec(),
        &[0; 64],
    );
    assert!(matches!(
        IndexRecords::parse(&page(vec![not_index], false, 1).encode_to_vec()),
        Err(WireError::Record(_))
    ));
    let mut twice = one.clone();
    twice.extend_from_slice(&[0x12, 0]);
    assert!(matches!(
        IndexRecords::parse(&page(vec![twice], false, 1).encode_to_vec()),
        Err(WireError::Record(_))
    ));
}

#[test]
fn status_and_chunks() {
    let status = |name: &str, folders: usize| Status {
        folders: vec![
            FolderStatus {
                folder_id: vec![1; 32],
                ..FolderStatus::default()
            };
            folders
        ],
        device_name: name.into(),
    };
    round_trip(&status("", MAX_STATUS_FOLDERS));
    assert!(Status::parse(&status("", MAX_STATUS_FOLDERS + 1).encode_to_vec()).is_err());
    assert!(Status::parse(&status("bad\nname", 1).encode_to_vec()).is_err());
    assert!(Status::parse(&status(&"n".repeat(65), 1).encode_to_vec()).is_err());
    let no_folder_id = Status {
        folders: vec![FolderStatus::default()],
        device_name: String::new(),
    };
    assert!(Status::parse(&no_folder_id.encode_to_vec()).is_err());
    let mut bad_bool = Vec::new();
    bytes_field(&mut bad_bool, 1, &[1; 32]);
    varint(&mut bad_bool, 4, 2);
    let mut body = Vec::new();
    bytes_field(&mut body, 1, &bad_bool);
    assert!(Status::parse(&body).is_err(), "paused 2");

    assert!(ChunkRequest::parse(
        &ChunkRequest {
            folder_id: vec![1; 32],
            cipher_hash: vec![],
        }
        .encode_to_vec()
    )
    .is_err());
    assert!(ChunkRequest::parse(
        &ChunkRequest {
            folder_id: vec![1; 32],
            cipher_hash: vec![2; 31],
        }
        .encode_to_vec()
    )
    .is_err());
    let reply = |status: u32, data: usize| ChunkReply {
        folder_id: vec![1; 32],
        cipher_hash: vec![2; 32],
        status,
        data: vec![3; data],
    };
    round_trip(&reply(1, MAX_STORED_LEN));
    round_trip(&reply(2, 0));
    round_trip(&reply(3, 0));
    for (bad, why) in [
        (reply(1, MAX_STORED_LEN + 1), "data over the bound"),
        (reply(1, 0), "OK without data"),
        (reply(2, 46), "NOT_FOUND with data"),
        (reply(3, 46), "BUSY with data"),
        (reply(0, 0), "status 0"),
        (reply(4, 0), "status 4"),
    ] {
        assert!(ChunkReply::parse(&bad.encode_to_vec()).is_err(), "{why}");
    }
}

#[test]
fn sealed_meta_bounds() {
    let meta = |hashes: usize| SealedMeta {
        path: "p".into(),
        kind: 1,
        plain_hashes: vec![vec![1; 32]; hashes],
        ..SealedMeta::default()
    };
    round_trip(&meta(MAX_CHUNKS));
    assert!(SealedMeta::parse(&meta(MAX_CHUNKS + 1).encode_to_vec()).is_err());
    let long = SealedMeta {
        path: "p".repeat(MAX_PATH_BYTES + 1),
        ..SealedMeta::default()
    };
    assert!(SealedMeta::parse(&long.encode_to_vec()).is_err());
    let short_hash = SealedMeta {
        plain_hashes: vec![vec![1; 31]],
        ..SealedMeta::default()
    };
    assert!(SealedMeta::parse(&short_hash.encode_to_vec()).is_err());
}

proptest! {
    #[test]
    fn random_bodies_never_panic_and_accepted_ones_reparse(t in 0usize..11, body in proptest::collection::vec(any::<u8>(), 0..=200)) {
        let message_type = MessageType::ALL[t];
        if let Ok(m) = Message::parse(message_type, &body) {
            // A body that parsed re-encodes canonically to one that parses to
            // the same value: unknown fields are dropped, nothing else changes.
            let again = Message::parse(message_type, &m.encode_body()).unwrap();
            prop_assert_eq!(again, m);
        }
    }

    #[test]
    fn index_records_round_trip(seq in 1u64..=MAX_SEQ, deleted in any::<bool>(), sealed in 40usize..200, n in 0usize..4) {
        let m = IndexRecord {
            seq,
            deleted,
            chunks: if deleted { vec![] } else { vec![ChunkRef { cipher_hash: vec![6; 32], stored_len: 46 }; n] },
            sealed: vec![1; sealed],
            ..record()
        };
        prop_assert_eq!(IndexRecord::parse(&m.encode_to_vec()).unwrap(), m);
    }
}
