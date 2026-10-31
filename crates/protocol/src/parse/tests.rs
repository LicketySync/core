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
        clock_days: 20_000,
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
        chunks: vec![ChunkRef {
            cipher_hash: vec![6; 32],
            stored_len: 46,
        }],
        sealed: vec![0; 296],
        path_tag: vec![2; 32],
        replaces: vec![vec![3; 32], vec![4; 32]],
    }
}

fn group(because: usize, names: &[u8]) -> CleanupGroup {
    CleanupGroup {
        because: vec![9; because],
        forget: names.iter().map(|n| vec![*n; 32]).collect(),
    }
}

fn cleanup() -> CleanupRecord {
    CleanupRecord {
        suite: 1,
        record_type: 17,
        folder_id: vec![1; 32],
        groups: vec![group(32, &[1, 2]), group(0, &[3])],
        sealed: vec![0; 296],
    }
}

fn request() -> IndexRequest {
    IndexRequest {
        folder_id: vec![1; 32],
        max_records: 0,
        request_id: 1,
        epoch: 7,
        since: 3,
    }
}

fn reconcile() -> ReconcileRequest {
    ReconcileRequest {
        folder_id: vec![1; 32],
        request_id: 2,
        prefix: vec![1, 15],
        digest: vec![4; 32],
    }
}

fn reply(outcome: u32, children: usize) -> ReconcileReply {
    ReconcileReply {
        folder_id: vec![1; 32],
        request_id: 2,
        outcome,
        children: vec![vec![5; 32]; children],
        epoch: 7,
        through: 0,
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
    round_trip(&cleanup());
    round_trip(&SealedMeta {
        path: "a/b".into(),
        kind: 1,
        size: 9,
        mtime_ns: -5,
        mode: 0o644,
        plain_hashes: vec![vec![1; 32]],
        written_at: 77,
        device_id: vec![2; 32],
        counter: 5,
        vector: vec![VectorEntry {
            device_id: vec![3; 32],
            counter: 4,
        }],
        deleted: true,
        tree: true,
    });
    round_trip(&CleanupMeta {
        device_id: vec![2; 32],
        counter: 9,
    });
    round_trip(&request());
    round_trip(&reconcile());
    round_trip(&reply(1, 0));
    round_trip(&reply(2, 16));
    round_trip(&ReconcileReply {
        through: MAX_LOCAL_SEQ,
        ..reply(3, 0)
    });
    round_trip(&IndexRecords {
        folder_id: vec![1; 32],
        records: vec![signed(&record())],
        more: true,
        request_id: 3,
        epoch: u64::MAX,
        through: MAX_LOCAL_SEQ,
        reset: false,
    });
    round_trip(&Status {
        folders: vec![FolderStatus {
            folder_id: vec![1; 32],
            index_records: 1,
            bytes_needed: 2,
            paused: true,
            free_disk_bytes: 3,
            chunks_stored: 4,
            extra_versions: 5,
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
    let mut body = IndexRecords {
        folder_id: vec![1; 32],
        epoch: 1,
        ..IndexRecords::default()
    }
    .encode_to_vec();
    varint(&mut body, 3, 2);
    assert_eq!(
        IndexRecords::parse(&body),
        Err(WireError::OutOfRange { what: "more" })
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
    // clock_days: 2 097 151 is the bound, one more is malformed.
    round_trip(&Hello {
        clock_days: MAX_CLOCK_DAYS,
        ..hello()
    });
    assert_eq!(
        Hello::parse(
            &Hello {
                clock_days: MAX_CLOCK_DAYS + 1,
                ..hello()
            }
            .encode_to_vec()
        ),
        Err(WireError::OutOfRange { what: "clock_days" })
    );
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
    round_trip(&record());
    let names = |n: usize| -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut h = vec![0; 32];
                h[31] = u8::try_from(i).unwrap();
                h
            })
            .collect()
    };
    round_trip(&IndexRecord {
        replaces: names(MAX_REPLACES),
        ..record()
    });
    round_trip(&IndexRecord {
        sealed: vec![0; MAX_SEALED_BYTES],
        ..record()
    });
    round_trip(&IndexRecord {
        chunks: vec![],
        replaces: vec![],
        sealed: vec![0; 40 + 512],
        ..record()
    });
    let cases: Vec<(IndexRecord, WireError)> = vec![
        (
            IndexRecord {
                suite: 0,
                ..record()
            },
            WireError::OutOfRange { what: "suite" },
        ),
        (
            IndexRecord {
                suite: 65_536,
                ..record()
            },
            WireError::OutOfRange { what: "suite" },
        ),
        (
            IndexRecord {
                record_type: 1,
                ..record()
            },
            WireError::OutOfRange {
                what: "record_type",
            },
        ),
        (
            IndexRecord {
                record_type: 17,
                ..record()
            },
            WireError::OutOfRange {
                what: "record_type",
            },
        ),
        (
            IndexRecord {
                folder_id: vec![],
                ..record()
            },
            WireError::WrongLength {
                what: "folder_id",
                expected: 32,
                got: 0,
            },
        ),
        (
            IndexRecord {
                path_tag: vec![2; 31],
                ..record()
            },
            WireError::WrongLength {
                what: "path_tag",
                expected: 32,
                got: 31,
            },
        ),
        (
            IndexRecord {
                replaces: names(MAX_REPLACES + 1),
                ..record()
            },
            WireError::LimitExceeded {
                what: "replaces",
                limit: MAX_REPLACES,
                offered: MAX_REPLACES as u64 + 1,
            },
        ),
        (
            IndexRecord {
                replaces: vec![vec![4; 32], vec![3; 32]],
                ..record()
            },
            WireError::Grammar {
                what: "replaces: ascending, no repeats",
            },
        ),
        (
            IndexRecord {
                replaces: vec![vec![3; 32], vec![3; 32]],
                ..record()
            },
            WireError::Grammar {
                what: "replaces: ascending, no repeats",
            },
        ),
        (
            IndexRecord {
                sealed: vec![0; 295],
                ..record()
            },
            WireError::OutOfRange { what: "sealed" },
        ),
        (
            IndexRecord {
                sealed: vec![0; 297],
                ..record()
            },
            WireError::OutOfRange { what: "sealed" },
        ),
        (
            IndexRecord {
                sealed: vec![0; 40 + 128],
                ..record()
            },
            WireError::OutOfRange { what: "sealed" },
        ),
        (
            IndexRecord {
                chunks: vec![ChunkRef {
                    cipher_hash: vec![6; 32],
                    stored_len: 49,
                }],
                ..record()
            },
            WireError::OutOfRange {
                what: "chunks.stored_len",
            },
        ),
    ];
    for (bad, why) in cases {
        assert_eq!(IndexRecord::parse(&bad.encode_to_vec()), Err(why));
    }
    for (bad, why) in [
        (
            IndexRecord {
                replaces: vec![vec![3; 31]],
                ..record()
            },
            "a name of 31 bytes",
        ),
        (
            IndexRecord {
                sealed: vec![0; MAX_SEALED_BYTES + 1],
                ..record()
            },
            "sealed 2^21 + 41",
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
    ] {
        assert!(IndexRecord::parse(&bad.encode_to_vec()).is_err(), "{why}");
    }
    // Reserved fields (4 to 11, 14, 16: the drafts' writer, sequence,
    // supersedes and deletion fields) read as unknown fields: skipped.
    let mut body = record().encode_to_vec();
    bytes_field(&mut body, 4, &[0; 32]);
    varint(&mut body, 5, 3);
    bytes_field(&mut body, 7, &[0; 32]);
    varint(&mut body, 11, 1);
    bytes_field(&mut body, 14, &[0; 32]);
    varint(&mut body, 16, 1);
    assert_eq!(IndexRecord::parse(&body).unwrap(), record());
    // The largest and smallest stored lengths are fine.
    assert!(is_stored_len(46));
    assert!(is_stored_len(4_325_416));
    assert!(!is_stored_len(4_325_417));
    assert!(!is_stored_len(4_325_416 - 1));
}

#[test]
fn cleanup_record_step_one() {
    round_trip(&cleanup());
    for sealed in [296, 552, 1064] {
        round_trip(&CleanupRecord {
            sealed: vec![0; sealed],
            ..cleanup()
        });
    }
    // At the bounds: 1 024 groups, 16 384 names in all.
    let name = |i: usize| -> Vec<u8> {
        let mut h = vec![0; 32];
        h[28..].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        h
    };
    let groups = |g: usize, per: usize| -> Vec<CleanupGroup> {
        (0..g)
            .map(|k| CleanupGroup {
                because: vec![],
                forget: (0..per).map(|i| name(k * per + i)).collect(),
            })
            .collect()
    };
    round_trip(&CleanupRecord {
        groups: groups(MAX_CLEANUP_GROUPS, MAX_CLEANUP_ENTRIES / MAX_CLEANUP_GROUPS),
        ..cleanup()
    });
    round_trip(&CleanupRecord {
        groups: groups(2, MAX_CLEANUP_ENTRIES / 2),
        ..cleanup()
    });
    let cases: Vec<(CleanupRecord, &str)> = vec![
        (
            CleanupRecord {
                suite: 0,
                ..cleanup()
            },
            "suite 0",
        ),
        (
            CleanupRecord {
                record_type: 16,
                ..cleanup()
            },
            "record type 16",
        ),
        (
            CleanupRecord {
                record_type: 18,
                ..cleanup()
            },
            "record type 18",
        ),
        (
            CleanupRecord {
                folder_id: vec![1; 31],
                ..cleanup()
            },
            "folder id 31",
        ),
        (
            CleanupRecord {
                groups: vec![],
                ..cleanup()
            },
            "no group",
        ),
        (
            CleanupRecord {
                groups: groups(MAX_CLEANUP_GROUPS + 1, 1),
                ..cleanup()
            },
            "1 025 groups",
        ),
        (
            CleanupRecord {
                groups: groups(1, MAX_CLEANUP_ENTRIES + 1),
                ..cleanup()
            },
            "16 385 names",
        ),
        (
            CleanupRecord {
                groups: groups(2, MAX_CLEANUP_ENTRIES / 2 + 1),
                ..cleanup()
            },
            "16 386 names over two groups",
        ),
        (
            CleanupRecord {
                groups: vec![
                    CleanupGroup {
                        because: vec![],
                        forget: (0..MAX_CLEANUP_ENTRIES / 2).map(name).collect(),
                    },
                    CleanupGroup {
                        because: vec![],
                        forget: (MAX_CLEANUP_ENTRIES / 2..=MAX_CLEANUP_ENTRIES)
                            .map(name)
                            .collect(),
                    },
                ],
                ..cleanup()
            },
            "16 385 names over two groups (P-4)",
        ),
        (
            CleanupRecord {
                groups: vec![group(32, &[])],
                ..cleanup()
            },
            "no name",
        ),
        (
            CleanupRecord {
                groups: vec![group(31, &[1])],
                ..cleanup()
            },
            "a because of 31 bytes",
        ),
        (
            CleanupRecord {
                groups: vec![group(0, &[2, 1])],
                ..cleanup()
            },
            "names out of order",
        ),
        (
            CleanupRecord {
                groups: vec![group(0, &[1, 1])],
                ..cleanup()
            },
            "a repeated name",
        ),
        (
            CleanupRecord {
                groups: vec![CleanupGroup {
                    because: vec![],
                    forget: vec![vec![1; 31]],
                }],
                ..cleanup()
            },
            "a name of 31 bytes",
        ),
        (
            CleanupRecord {
                sealed: vec![0; 297],
                ..cleanup()
            },
            "sealed 297",
        ),
        (
            CleanupRecord {
                sealed: vec![0; 40 + 2048],
                ..cleanup()
            },
            "sealed past the cleanup cap",
        ),
    ];
    for (bad, why) in cases {
        assert!(CleanupRecord::parse(&bad.encode_to_vec()).is_err(), "{why}");
    }
    // A group and a vector entry on their own (the fuzz target's entries).
    round_trip(&group(32, &[1, 2]));
    round_trip(&group(0, &[1]));
    assert!(CleanupGroup::parse(&group(31, &[1]).encode_to_vec()).is_err());
    assert!(CleanupGroup::parse(&group(0, &[2, 1]).encode_to_vec()).is_err());
    let many = CleanupGroup {
        because: vec![],
        forget: (0..=MAX_CLEANUP_ENTRIES).map(name).collect(),
    };
    assert!(CleanupGroup::parse(&many.encode_to_vec()).is_err());
    round_trip(&VectorEntry {
        device_id: vec![1; 7],
        counter: 9,
    });
    // The same name in two groups, and an empty group beside a full one,
    // are within the text of 4.4 (a spec point the CHANGELOG records): accepted.
    round_trip(&CleanupRecord {
        groups: vec![group(0, &[1]), group(32, &[1])],
        ..cleanup()
    });
    round_trip(&CleanupRecord {
        groups: vec![group(0, &[]), group(32, &[1])],
        ..cleanup()
    });
}

#[test]
fn exchange_requests_and_replies() {
    round_trip(&IndexRequest {
        since: MAX_LOCAL_SEQ,
        ..request()
    });
    round_trip(&IndexRequest {
        since: 0,
        ..request()
    });
    for (bad, why) in [
        (
            IndexRequest {
                epoch: 0,
                ..request()
            },
            WireError::OutOfRange { what: "epoch" },
        ),
        (
            IndexRequest {
                since: MAX_LOCAL_SEQ + 1,
                ..request()
            },
            WireError::OutOfRange { what: "since" },
        ),
        (
            IndexRequest {
                request_id: 0,
                ..request()
            },
            WireError::OutOfRange { what: "request_id" },
        ),
    ] {
        assert_eq!(IndexRequest::parse(&bad.encode_to_vec()), Err(why));
    }
    // The drafts' cursor fields (2, 5, 6, 7) are reserved: skipped.
    let mut body = request().encode_to_vec();
    bytes_field(&mut body, 2, &[1, 2]);
    bytes_field(&mut body, 5, &[0; 32]);
    varint(&mut body, 7, 1);
    assert_eq!(IndexRequest::parse(&body).unwrap(), request());
    // ReconcileRequest: a prefix of 0 to 128 nibbles.
    round_trip(&ReconcileRequest {
        prefix: vec![],
        ..reconcile()
    });
    round_trip(&ReconcileRequest {
        prefix: vec![15; 64],
        ..reconcile()
    });
    round_trip(&ReconcileRequest {
        prefix: vec![15; 128],
        ..reconcile()
    });
    for (bad, why) in [
        (
            ReconcileRequest {
                prefix: vec![0; 129],
                ..reconcile()
            },
            "a 129-byte prefix",
        ),
        (
            ReconcileRequest {
                prefix: vec![1, 16],
                ..reconcile()
            },
            "a nibble of 16",
        ),
        (
            ReconcileRequest {
                digest: vec![4; 31],
                ..reconcile()
            },
            "a digest of 31 bytes",
        ),
        (
            ReconcileRequest {
                digest: vec![],
                ..reconcile()
            },
            "no digest",
        ),
        (
            ReconcileRequest {
                request_id: 0,
                ..reconcile()
            },
            "request_id 0",
        ),
    ] {
        assert!(
            ReconcileRequest::parse(&bad.encode_to_vec()).is_err(),
            "{why}"
        );
    }
    // ReconcileReply.
    for (bad, why) in [
        (reply(4, 0), "outcome 4"),
        (reply(0, 0), "outcome 0"),
        (reply(2, 15), "15 children"),
        (reply(1, 16), "children on EQUAL"),
        (reply(3, 1), "children on RECORDS"),
        (
            ReconcileReply {
                epoch: 0,
                ..reply(1, 0)
            },
            "epoch 0",
        ),
        (
            ReconcileReply {
                through: MAX_LOCAL_SEQ + 1,
                ..reply(1, 0)
            },
            "through past MAX_LOCAL_SEQ",
        ),
        (
            ReconcileReply {
                children: vec![vec![5; 31]; 16],
                ..reply(2, 0)
            },
            "a child of 31 bytes",
        ),
    ] {
        assert!(
            ReconcileReply::parse(&bad.encode_to_vec()).is_err(),
            "{why}"
        );
    }
    let mut seventeen = reply(2, 16).encode_to_vec();
    bytes_field(&mut seventeen, 4, &[5; 32]);
    assert!(ReconcileReply::parse(&seventeen).is_err(), "17 children");
}

#[test]
fn index_records_pages_and_embedded_envelopes() {
    let page = |records: Vec<Vec<u8>>, more: bool, request_id: u32| IndexRecords {
        folder_id: vec![1; 32],
        records,
        more,
        request_id,
        epoch: 5,
        through: 0,
        reset: false,
    };
    round_trip(&page(vec![], false, 0));
    let grammar = |what| Err(WireError::Grammar { what });
    assert_eq!(
        IndexRecords::parse(&page(vec![], true, 0).encode_to_vec()),
        grammar("a push with more or reset")
    );
    let one = signed(&record());
    assert_eq!(
        IndexRecords::parse(&page(vec![one.clone()], true, 0).encode_to_vec()),
        grammar("a push with more or reset")
    );
    assert_eq!(
        IndexRecords::parse(
            &IndexRecords {
                reset: true,
                ..page(vec![], false, 0)
            }
            .encode_to_vec()
        ),
        grammar("a push with more or reset")
    );
    // A reply page with more must hold a record (4.5); the last may be empty.
    round_trip(&page(vec![], false, 9));
    assert_eq!(
        IndexRecords::parse(&page(vec![], true, 9).encode_to_vec()),
        grammar("a page with more and no records")
    );
    round_trip(&page(vec![one.clone()], true, 9));
    // A reset: no records, more or through.
    let reset = IndexRecords {
        reset: true,
        ..page(vec![], false, 9)
    };
    round_trip(&reset);
    for bad in [
        IndexRecords {
            records: vec![one.clone()],
            ..reset.clone()
        },
        IndexRecords {
            through: 1,
            ..reset.clone()
        },
        IndexRecords {
            records: vec![one.clone()],
            more: true,
            ..reset.clone()
        },
    ] {
        assert_eq!(
            IndexRecords::parse(&bad.encode_to_vec()),
            grammar("a reset with records, more or through")
        );
    }
    // The epoch is never 0; through at most MAX_LOCAL_SEQ.
    assert_eq!(
        IndexRecords::parse(
            &IndexRecords {
                epoch: 0,
                ..page(vec![], false, 0)
            }
            .encode_to_vec()
        ),
        Err(WireError::OutOfRange { what: "epoch" })
    );
    round_trip(&IndexRecords {
        through: MAX_LOCAL_SEQ,
        ..page(vec![], false, 0)
    });
    assert_eq!(
        IndexRecords::parse(
            &IndexRecords {
                through: MAX_LOCAL_SEQ + 1,
                ..page(vec![], false, 0)
            }
            .encode_to_vec()
        ),
        Err(WireError::OutOfRange { what: "through" })
    );
    // Exactly MAX_PAGE_RECORDS records pass; one more is malformed.
    round_trip(&page(vec![one.clone(); MAX_PAGE_RECORDS], true, 9));
    assert!(matches!(
        IndexRecords::parse(
            &page(vec![one.clone(); MAX_PAGE_RECORDS + 1], false, 9).encode_to_vec()
        ),
        Err(WireError::LimitExceeded { .. })
    ));
    // Every embedded record passes keys' envelope decoder, both types
    // included, and the connection's form agrees.
    let c = crate::testkit::envelope(&cleanup().encode_to_vec(), &[5; 64]);
    let both = page(vec![one.clone(), c], false, 1).encode_to_vec();
    assert_eq!(IndexRecords::parse(&both).unwrap().records.len(), 2);
    let rp = parse_records_page(&both).unwrap();
    assert_eq!(rp.records.len(), 2);
    assert_eq!((rp.request_id, rp.epoch, rp.more), (1, 5, false));
    let short_sig = crate::testkit::envelope(&record().encode_to_vec(), &[0; 63]);
    assert_eq!(
        IndexRecords::parse(&page(vec![short_sig], false, 1).encode_to_vec()),
        Err(WireError::Record(
            licketysync_keys::records::Malformed::SignatureSize(63)
        ))
    );
    for record_type in [1, 18] {
        let other = crate::testkit::envelope(
            &IndexRecord {
                record_type,
                ..record()
            }
            .encode_to_vec(),
            &[0; 64],
        );
        assert!(matches!(
            IndexRecords::parse(&page(vec![other], false, 1).encode_to_vec()),
            Err(WireError::Record(_))
        ));
    }
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
fn sealed_meta_is_lax_where_step_seven_judges() {
    let meta = |hashes: usize| SealedMeta {
        path: "p".into(),
        kind: 1,
        plain_hashes: vec![vec![1; 32]; hashes],
        ..SealedMeta::default()
    };
    round_trip(&meta(MAX_CHUNKS));
    assert!(SealedMeta::parse(&meta(MAX_CHUNKS + 1).encode_to_vec()).is_err());
    let short_hash = SealedMeta {
        plain_hashes: vec![vec![1; 31]],
        ..SealedMeta::default()
    };
    assert!(SealedMeta::parse(&short_hash.encode_to_vec()).is_err());
    // A long path, a device ID of any size, a counter of 0, a vector entry
    // of any size: step 7's writer faults, not malformed here.
    let lax = SealedMeta {
        path: "p".repeat(crate::limits::MAX_PATH_BYTES + 1),
        device_id: vec![2; 31],
        counter: 0,
        vector: vec![VectorEntry {
            device_id: vec![1; 3],
            counter: 0,
        }],
        ..SealedMeta::default()
    };
    round_trip(&lax);
    // Past the 33rd vector entry the rest are read and skipped.
    let long = SealedMeta {
        vector: (0..40u8)
            .map(|i| VectorEntry {
                device_id: vec![i; 32],
                counter: 1,
            })
            .collect(),
        ..SealedMeta::default()
    };
    assert_eq!(
        SealedMeta::parse(&long.encode_to_vec())
            .unwrap()
            .vector
            .len(),
        MAX_VECTOR_ENTRIES + 1
    );
    // A bool of 2 in the metadata, and a vector entry field twice, are
    // malformed metadata.
    let mut body = SealedMeta::default().encode_to_vec();
    varint(&mut body, 11, 2);
    assert!(SealedMeta::parse(&body).is_err());
    let mut entry = Vec::new();
    varint(&mut entry, 2, 1);
    varint(&mut entry, 2, 2);
    let mut body = Vec::new();
    bytes_field(&mut body, 10, &entry);
    assert!(SealedMeta::parse(&body).is_err());
    // CleanupMeta: lax on its sizes too.
    round_trip(&CleanupMeta {
        device_id: vec![1; 5],
        counter: 0,
    });
    let mut body = Vec::new();
    varint(&mut body, 2, 1);
    varint(&mut body, 2, 1);
    assert!(CleanupMeta::parse(&body).is_err());
}

proptest! {
    #![proptest_config(crate::testkit::proptest_config(256))]

    #[test]
    fn random_bodies_never_panic_and_accepted_ones_reparse(t in 0usize..13, body in proptest::collection::vec(any::<u8>(), 0..=200)) {
        let message_type = MessageType::ALL[t];
        if let Ok(m) = Message::parse(message_type, &body) {
            // A body that parsed re-encodes canonically to one that parses to
            // the same value: unknown fields are dropped, nothing else changes.
            let again = Message::parse(message_type, &m.encode_body()).unwrap();
            prop_assert_eq!(again, m);
        }
    }

    #[test]
    fn index_records_round_trip(n in 0usize..4, names in 0usize..65, bucket in 8u32..=21) {
        let m = IndexRecord {
            chunks: vec![ChunkRef { cipher_hash: vec![6; 32], stored_len: 46 }; n],
            sealed: vec![1; 40 + (1usize << bucket)],
            replaces: (0..names).map(|i| { let mut h = vec![0; 32]; h[31] = u8::try_from(i).unwrap(); h }).collect(),
            ..record()
        };
        prop_assert_eq!(IndexRecord::parse(&m.encode_to_vec()).unwrap(), m);
    }

    #[test]
    fn cleanups_round_trip(groups in proptest::collection::vec((any::<bool>(), 1usize..20), 1..20), bucket in 8u32..=10) {
        let mut next = 0u32;
        let m = CleanupRecord {
            groups: groups.iter().map(|(because, n)| CleanupGroup {
                because: if *because { vec![9; 32] } else { vec![] },
                forget: (0..*n).map(|_| { next += 1; let mut h = vec![0; 32]; h[28..].copy_from_slice(&next.to_be_bytes()); h }).collect(),
            }).collect(),
            sealed: vec![1; 40 + (1usize << bucket)],
            ..cleanup()
        };
        prop_assert_eq!(CleanupRecord::parse(&m.encode_to_vec()).unwrap(), m);
    }

    #[test]
    fn exchange_messages_round_trip(epoch in 1u64.., since in 0u64..=MAX_LOCAL_SEQ, prefix in proptest::collection::vec(0u8..16, 0..=64), outcome in 1u32..=3) {
        let r = IndexRequest { epoch, since, ..request() };
        prop_assert_eq!(IndexRequest::parse(&r.encode_to_vec()).unwrap(), r);
        let q = ReconcileRequest { prefix, ..reconcile() };
        prop_assert_eq!(ReconcileRequest::parse(&q.encode_to_vec()).unwrap(), q);
        let p = ReconcileReply { epoch, through: since, ..reply(outcome, if outcome == 2 { 16 } else { 0 }) };
        prop_assert_eq!(ReconcileReply::parse(&p.encode_to_vec()).unwrap(), p);
    }
}
