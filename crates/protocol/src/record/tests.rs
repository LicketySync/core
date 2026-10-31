// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::assert_is_empty,
    clippy::panic,
    reason = "test code"
)]

use licketysync_keys::folder::FolderKey;
use licketysync_keys::records::Malformed;
use licketysync_keys::WriteKey;
use proptest::prelude::*;

use super::*;
use crate::limits::MAX_INDEX_RECORD_BYTES;
use crate::testkit::folder;

fn fill(byte: u8) -> impl FnMut(&mut [u8]) {
    move |b: &mut [u8]| b.fill(byte)
}

fn dev(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

fn dot(n: u8, counter: u64) -> Dot {
    Dot {
        device: dev(n),
        counter,
    }
}

fn chunk(byte: u8) -> Chunk {
    Chunk {
        cipher_hash: CipherHash([byte; 32]),
        stored_len: 46,
    }
}

fn meta(path: &str, counter: u64) -> Meta {
    Meta {
        path: path.into(),
        kind: Kind::File,
        size: 10,
        mtime_ns: 1_700_000_000_000_000_000,
        mode: 0o644,
        plain_hashes: vec![PlainHash([0; 32])],
        written_at: 1_700_000_000,
        dot: dot(2, counter),
        vector: Vector::default(),
        deleted: false,
        tree: false,
    }
}

fn draft(counter: u64) -> IndexDraft {
    IndexDraft {
        meta: meta("docs/a.txt", counter),
        chunks: vec![chunk(1)],
        replaces: vec![],
    }
}

fn sign(key: &WriteKey, d: &IndexDraft) -> Result<SignedRecord, DraftError> {
    d.sign(key, &key.record_keys(), &mut fill(4))
}

fn parsed(key: &WriteKey, signed: SignedRecord) -> Record {
    Record::parse(signed, key.verifier()).unwrap()
}

/// The `SealedMeta` of a valid file at `path`, counter 100.
fn sealed_meta(path: &str) -> SealedMeta {
    SealedMeta {
        path: path.into(),
        kind: 1,
        size: 10,
        mtime_ns: 5,
        mode: 0,
        plain_hashes: vec![vec![0; 32]],
        written_at: 0,
        device_id: vec![2; 32],
        counter: 100,
        vector: vec![],
        deleted: false,
        tree: false,
    }
}

/// Signs a body around arbitrary sealed metadata bytes at `path_tag`,
/// bypassing the writer's rules, so that every reader refusal of step 7 can
/// be reached.
fn forge_at(key: &WriteKey, path_tag: PathTag, chunks: &[Chunk], plain: &[u8]) -> Record {
    let keys = key.record_keys();
    let sealed = keys
        .seal_index_meta(&path_tag, plain, &mut fill(3))
        .unwrap();
    forge_sealed(key, path_tag, chunks, sealed)
}

fn forge_sealed(key: &WriteKey, path_tag: PathTag, chunks: &[Chunk], sealed: Vec<u8>) -> Record {
    let folder = key.verifier();
    let body = IndexRecord {
        suite: 1,
        record_type: INDEX_RECORD_TYPE,
        folder_id: folder.folder_id().0.to_vec(),
        chunks: chunks
            .iter()
            .map(|c| ChunkRef {
                cipher_hash: c.cipher_hash.0.to_vec(),
                stored_len: c.stored_len,
            })
            .collect(),
        sealed,
        path_tag: path_tag.0.to_vec(),
        replaces: vec![],
    }
    .encode_to_vec();
    Record::parse(key.sign_index_record(body).unwrap(), folder).unwrap()
}

/// [`forge_at`] at the tag of the metadata's own path.
fn forge(key: &WriteKey, chunks: &[Chunk], m: &SealedMeta) -> Record {
    let tag = key.record_keys().path_tag(&m.path);
    forge_at(key, tag, chunks, &m.encode_to_vec())
}

fn forge_cleanup(key: &WriteKey, plain: &[u8]) -> Record {
    let folder = key.verifier();
    let sealed = key
        .record_keys()
        .seal_cleanup_meta(plain, &mut fill(3))
        .unwrap();
    let body = CleanupRecord {
        suite: 1,
        record_type: CLEANUP_RECORD_TYPE,
        folder_id: folder.folder_id().0.to_vec(),
        groups: vec![CleanupGroup {
            because: vec![],
            forget: vec![vec![1; 32]],
        }],
        sealed,
    }
    .encode_to_vec();
    Record::parse(key.sign_cleanup_record(body).unwrap(), folder).unwrap()
}

#[test]
fn an_index_draft_signs_parses_verifies_and_opens() {
    let key = folder(0x10);
    let keys = key.record_keys();
    let mut d = draft(100);
    d.replaces = vec![
        RecordHash([9; 32]),
        RecordHash([8; 32]),
        RecordHash([9; 32]),
    ];
    // The vector's entries in any order: signed ascending by device ID.
    d.meta.vector = Vector(vec![dot(7, 99), dot(3, 50)]);
    let signed = sign(&key, &d).unwrap();
    let r = Record::from_bytes(&signed.to_bytes(), key.verifier()).unwrap();
    assert_eq!(r.signed(), &signed);
    assert_eq!(r.hash(), signed.hash());
    assert_eq!(r.record_type(), RecordType::Index);
    assert!(!r.is_cleanup());
    assert_eq!(r.folder_id(), key.verifier().folder_id());
    let tag = keys.path_tag("docs/a.txt");
    assert_eq!(r.path_tag(), Some(tag));
    assert_eq!(r.key()[..32], tag.0, "keyed by its path tag in the digests");
    assert_eq!(r.key()[32..], r.hash().0, "then its record hash");
    assert_eq!(
        r.replaces(),
        &[RecordHash([8; 32]), RecordHash([9; 32])],
        "a set: sorted, repeats dropped"
    );
    assert!(r.groups().is_empty());
    assert_eq!(r.chunks(), &[chunk(1)]);
    assert!(matches!(r.body(), Body::Index { .. }));
    assert_eq!(&r.sealed()[..24], &[4; 24], "the nonce drawn from rng");
    r.verify(key.verifier()).unwrap();
    let Ok(Applied::Index(m)) = r.open(&keys) else {
        panic!("opens")
    };
    assert_eq!(m.path, "docs/a.txt");
    assert_eq!(m.kind, Kind::File);
    assert_eq!((m.size, m.mode, m.written_at), (10, 0o644, 1_700_000_000));
    assert_eq!(m.mtime_ns, 1_700_000_000_000_000_000);
    assert_eq!(m.plain_hashes.len(), 1);
    assert_eq!(m.dot, dot(2, 100));
    assert_eq!(m.vector.entries(), &[dot(3, 50), dot(7, 99)]);
    assert!(!m.is_deletion() && !m.is_tombstone() && !m.is_tree_delete());
    let applied = r.open(&keys).unwrap();
    assert_eq!(applied.dot(), &dot(2, 100));
    assert!(applied.meta().is_some());
    // A read key opens it too; a sealed key has no record keys.
    let read = key.read_key();
    assert!(r.open(&read.record_keys()).is_ok());
    assert!(FolderKey::from(key.sealed_key()).record_keys().is_none());
    assert!(FolderKey::from(key.read_key()).record_keys().is_some());
    assert_eq!(r.clone().into_signed(), signed);
    // The same record parsed under another folder's verifier is malformed.
    assert!(Record::parse(signed, folder(0x20).verifier()).is_err());
}

#[test]
fn a_cleanup_draft_signs_parses_and_opens() {
    let key = folder(0x10);
    let c = CleanupDraft {
        dot: dot(2, 7),
        groups: vec![
            Group {
                because: Some(RecordHash([5; 32])),
                forget: vec![
                    RecordHash([9; 32]),
                    RecordHash([1; 32]),
                    RecordHash([9; 32]),
                ],
            },
            Group {
                because: None,
                forget: vec![RecordHash([3; 32])],
            },
        ],
    };
    let signed = c.sign(&key, &key.record_keys(), &mut fill(6)).unwrap();
    let r = parsed(&key, signed.clone());
    assert_eq!(r.record_type(), RecordType::Cleanup);
    assert!(r.is_cleanup());
    assert_eq!(r.path_tag(), None);
    assert_eq!(
        r.key()[..32],
        r.hash().0,
        "keyed by its own hash in the digests"
    );
    assert_eq!(r.key()[32..], r.hash().0, "twice");
    assert!(r.replaces().is_empty() && r.chunks().is_empty());
    assert_eq!(
        r.groups(),
        &[
            Group {
                because: Some(RecordHash([5; 32])),
                forget: vec![RecordHash([1; 32]), RecordHash([9; 32])],
            },
            Group {
                because: None,
                forget: vec![RecordHash([3; 32])],
            },
        ],
        "each group's names ascending, no repeats"
    );
    assert_eq!(r.sealed().len(), 296, "the least cleanup bucket");
    r.verify(key.verifier()).unwrap();
    let applied = r.open(&key.record_keys()).unwrap();
    assert!(matches!(applied, Applied::Cleanup(d) if d == dot(2, 7)));
    assert!(applied.meta().is_none());
    assert_eq!(applied.dot(), &dot(2, 7));
    // Signed under the other label it would be forged; the keys crate's
    // signer refuses to sign a cleanup body as an index record.
    assert!(key.sign_index_record(signed.body().to_vec()).is_err());
}

#[test]
fn step_one_binds_the_record_to_the_open_folder() {
    let key = folder(0x10);
    let other = folder(0x20);
    let signed = sign(&key, &draft(1)).unwrap();
    assert_eq!(
        Record::parse(signed.clone(), other.verifier()),
        Err(WireError::Grammar {
            what: "folder_id: not the open folder"
        })
    );
    let mut body = IndexRecord::parse(signed.body()).unwrap();
    body.suite = 2;
    let resigned = key.sign_index_record(body.encode_to_vec()).unwrap();
    assert_eq!(
        Record::parse(resigned, key.verifier()),
        Err(WireError::Grammar {
            what: "suite: not the folder's"
        })
    );
    let short = crate::testkit::envelope(signed.body(), &[0; 63]);
    assert_eq!(
        Record::from_bytes(&short, key.verifier()),
        Err(WireError::Record(Malformed::SignatureSize(63)))
    );
    assert!(matches!(
        Record::from_bytes(&[0x0b], key.verifier()),
        Err(WireError::Record(_))
    ));
    // A cleanup of another folder, and of another suite.
    let c = CleanupDraft {
        dot: dot(2, 1),
        groups: vec![Group {
            because: None,
            forget: vec![RecordHash([1; 32])],
        }],
    };
    let cs = c.sign(&key, &key.record_keys(), &mut fill(1)).unwrap();
    assert!(Record::parse(cs.clone(), other.verifier()).is_err());
    let mut cb = CleanupRecord::parse(cs.body()).unwrap();
    cb.suite = 3;
    assert_eq!(
        Record::parse(
            key.sign_cleanup_record(cb.encode_to_vec()).unwrap(),
            key.verifier()
        ),
        Err(WireError::Grammar {
            what: "suite: not the folder's"
        })
    );
    // A forged record still parses: step 5 refuses it.
    let flipped = crate::testkit::flipped(&signed, 0);
    let f = Record::parse(flipped, key.verifier()).unwrap();
    assert_eq!(f.verify(key.verifier()), Err(Cause::Forged));
}

#[test]
fn every_writer_fault_of_step_seven() {
    let key = folder(0x10);
    let keys = key.record_keys();
    let open = |r: &Record| r.open(&keys).err();
    let ok = sealed_meta("a/b");
    assert!(forge(&key, &[chunk(1)], &ok).open(&keys).is_ok());
    // The seal: moved to another path tag (the aad fails), not zero padded,
    // and padded one power of two past the least (the keys crate's seeds,
    // under this folder's keys at "docs/report.txt").
    let under_ab = keys
        .seal_index_meta(&keys.path_tag("a/b"), &ok.encode_to_vec(), &mut fill(3))
        .unwrap();
    let moved = forge_sealed(&key, keys.path_tag("x"), &[chunk(1)], under_ab);
    assert!(matches!(open(&moved), Some(WriterFault::Seal(_))));
    let report = keys.path_tag("docs/report.txt");
    let padding = include_bytes!("../../../../fuzz/seeds/sealed_meta_open/index-non-zero-padding");
    assert_eq!(
        open(&forge_sealed(&key, report, &[], padding.to_vec())),
        Some(WriterFault::Seal(MetaError::Padding))
    );
    let over = include_bytes!("../../../../fuzz/seeds/sealed_meta_open/index-300-in-1024");
    assert_eq!(
        open(&forge_sealed(&key, report, &[], over.to_vec())),
        Some(WriterFault::Seal(MetaError::OverPadded))
    );
    // Metadata that does not parse: a bool of 2.
    let mut bad = ok.encode_to_vec();
    bad.extend_from_slice(&[0x58, 0x02]);
    assert!(matches!(
        open(&forge_at(&key, keys.path_tag("a/b"), &[chunk(1)], &bad)),
        Some(WriterFault::Meta(_))
    ));
    let with = |f: &dyn Fn(&mut SealedMeta)| {
        let mut m = sealed_meta("a/b");
        f(&mut m);
        m
    };
    let one = [chunk(1)];
    let cases: Vec<(SealedMeta, &[Chunk], WriterFault)> = vec![
        (
            with(&|m| m.path = "/abs".into()),
            &one,
            WriterFault::Path(PathError::Absolute),
        ),
        (
            with(&|m| m.device_id = vec![2; 31]),
            &one,
            WriterFault::DeviceId(31),
        ),
        (with(&|m| m.counter = 0), &one, WriterFault::Counter(0)),
        (
            with(&|m| m.counter = MAX_COUNTER + 1),
            &one,
            WriterFault::Counter(MAX_COUNTER + 1),
        ),
        (
            with(&|m| {
                m.vector = (0..33u8)
                    .map(|i| VectorEntry {
                        device_id: vec![i; 32],
                        counter: 1,
                    })
                    .collect();
            }),
            &one,
            WriterFault::VectorLength,
        ),
        (
            with(&|m| {
                m.vector = vec![VectorEntry {
                    device_id: vec![1; 31],
                    counter: 1,
                }];
            }),
            &one,
            WriterFault::VectorDevice(31),
        ),
        (
            with(&|m| {
                m.vector = vec![VectorEntry {
                    device_id: vec![1; 32],
                    counter: 0,
                }];
            }),
            &one,
            WriterFault::VectorCounterZero,
        ),
        (
            with(&|m| {
                m.vector = vec![VectorEntry {
                    device_id: vec![1; 32],
                    counter: 100,
                }];
            }),
            &one,
            WriterFault::VectorCounterNotBelow,
        ),
        (
            with(&|m| {
                m.vector = vec![
                    VectorEntry {
                        device_id: vec![3; 32],
                        counter: 1,
                    },
                    VectorEntry {
                        device_id: vec![1; 32],
                        counter: 1,
                    },
                ];
            }),
            &one,
            WriterFault::VectorOrder,
        ),
        (
            with(&|m| {
                m.vector = vec![
                    VectorEntry {
                        device_id: vec![1; 32],
                        counter: 1,
                    },
                    VectorEntry {
                        device_id: vec![1; 32],
                        counter: 2,
                    },
                ];
            }),
            &one,
            WriterFault::VectorDuplicate,
        ),
        (
            with(&|m| m.tree = true),
            &one,
            WriterFault::TreeWithoutDeleted,
        ),
        (
            with(&|m| m.deleted = true),
            &one,
            WriterFault::DeletedWithChunks,
        ),
        (
            with(&|m| {
                m.deleted = true;
                m.tree = true;
                m.size = 0;
                m.plain_hashes.clear();
            }),
            &[],
            WriterFault::TreeKindOrSize,
        ),
        (
            with(&|m| {
                m.deleted = true;
                m.tree = true;
                m.kind = 2;
                m.size = 5;
                m.plain_hashes.clear();
            }),
            &[],
            WriterFault::TreeKindOrSize,
        ),
        (
            with(&|m| m.plain_hashes.clear()),
            &one,
            WriterFault::HashCount {
                chunks: 1,
                hashes: 0,
            },
        ),
        (
            with(&|m| m.kind = 2),
            &one,
            WriterFault::DirectoryWithChunks,
        ),
        (
            with(&|m| m.plain_hashes.clear()),
            &[],
            WriterFault::FileWithoutChunks,
        ),
        (with(&|m| m.kind = 3), &one, WriterFault::Kind(3)),
        // The kind is checked after every check that does not depend on it
        // (the review's P-1): a record with an unknown kind and a shared
        // fault is the shared fault, whichever check finds it.
        (
            with(&|m| {
                m.kind = 3;
                m.counter = 0;
            }),
            &one,
            WriterFault::Counter(0),
        ),
        (
            with(&|m| {
                m.kind = 3;
                m.vector = vec![VectorEntry {
                    device_id: vec![1; 32],
                    counter: 0,
                }];
            }),
            &one,
            WriterFault::VectorCounterZero,
        ),
        (
            with(&|m| {
                m.kind = 3;
                m.tree = true;
            }),
            &one,
            WriterFault::TreeWithoutDeleted,
        ),
        (
            with(&|m| {
                m.kind = 3;
                m.deleted = true;
            }),
            &one,
            WriterFault::DeletedWithChunks,
        ),
        (
            with(&|m| {
                m.kind = 3;
                m.deleted = true;
                m.tree = true;
                m.size = 0;
                m.plain_hashes.clear();
            }),
            &[],
            WriterFault::TreeKindOrSize,
        ),
        (
            with(&|m| {
                m.kind = 3;
                m.plain_hashes.clear();
            }),
            &one,
            WriterFault::HashCount {
                chunks: 1,
                hashes: 0,
            },
        ),
        // The checks run in order: the device ID before the counter.
        (
            with(&|m| {
                m.device_id = vec![];
                m.counter = 0;
            }),
            &one,
            WriterFault::DeviceId(0),
        ),
    ];
    for (m, chunks, fault) in cases {
        assert_eq!(
            open(&forge(&key, chunks, &m)),
            Some(fault.clone()),
            "{fault}"
        );
        assert_eq!(fault.is_shared(), !matches!(fault, WriterFault::Kind(_)));
    }
    // The path's tag is not the record's, with and without an unknown kind
    // (P-1: the shared fault comes back).
    assert_eq!(
        open(&forge_at(
            &key,
            keys.path_tag("c"),
            &one,
            &ok.encode_to_vec()
        )),
        Some(WriterFault::PathTag)
    );
    assert_eq!(
        open(&forge_at(
            &key,
            keys.path_tag("c"),
            &one,
            &with(&|m| m.kind = 3).encode_to_vec()
        )),
        Some(WriterFault::PathTag)
    );
    // Accepted at the edges: MAX_COUNTER itself, an entry one below the
    // counter, 32 entries, a tombstone directory, an empty file, and a path
    // that is not NFC (the writer's duty: a path of its own, not a fault).
    let accepted = [
        with(&|m| m.counter = MAX_COUNTER),
        with(&|m| {
            m.vector = vec![VectorEntry {
                device_id: vec![1; 32],
                counter: 99,
            }];
        }),
        with(&|m| {
            m.vector = (0..32u8)
                .map(|i| VectorEntry {
                    device_id: vec![i; 32],
                    counter: 1,
                })
                .collect();
        }),
        with(&|m| m.path = "docs/note\u{301}s".into()),
    ];
    for m in &accepted {
        assert!(forge(&key, &one, m).open(&keys).is_ok());
    }
    let empty = with(&|m| {
        m.size = 0;
        m.plain_hashes.clear();
    });
    assert!(forge(&key, &[], &empty).open(&keys).is_ok());
    let dir_tomb = with(&|m| {
        m.kind = 2;
        m.size = 0;
        m.deleted = true;
        m.plain_hashes.clear();
    });
    assert!(forge(&key, &[], &dir_tomb).open(&keys).is_ok());
    // A cleanup's faults: the seal, the metadata, the device ID, the counter.
    let cm = |device: usize, counter: u64| {
        CleanupMeta {
            device_id: vec![2; device],
            counter,
        }
        .encode_to_vec()
    };
    assert!(forge_cleanup(&key, &cm(32, 1)).open(&keys).is_ok());
    assert_eq!(
        forge_cleanup(&key, &cm(31, 1)).open(&keys).err(),
        Some(WriterFault::DeviceId(31))
    );
    assert_eq!(
        forge_cleanup(&key, &cm(32, 0)).open(&keys).err(),
        Some(WriterFault::Counter(0))
    );
    assert!(matches!(
        forge_cleanup(&key, &[0x10, 0x02, 0x00]).open(&keys).err(),
        Some(WriterFault::Meta(_))
    ));
    // An index record's seal in a cleanup does not open (its aad differs).
    let index_sealed = keys
        .seal_index_meta(&keys.path_tag("a/b"), &ok.encode_to_vec(), &mut fill(3))
        .unwrap();
    let c = forge_cleanup(&key, &cm(32, 1));
    let mut body = CleanupRecord::parse(c.signed().body()).unwrap();
    body.sealed = index_sealed;
    let swapped = parsed(&key, key.sign_cleanup_record(body.encode_to_vec()).unwrap());
    assert!(matches!(
        swapped.open(&keys).err(),
        Some(WriterFault::Seal(_))
    ));
    for fault in [
        WriterFault::Seal(MetaError::OverPadded),
        WriterFault::Meta(WireError::Truncated),
        WriterFault::Path(PathError::Nul),
        WriterFault::PathTag,
        WriterFault::DeviceId(1),
        WriterFault::Counter(0),
        WriterFault::VectorLength,
        WriterFault::VectorDevice(1),
        WriterFault::VectorCounterZero,
        WriterFault::VectorCounterNotBelow,
        WriterFault::VectorOrder,
        WriterFault::VectorDuplicate,
        WriterFault::TreeWithoutDeleted,
        WriterFault::DeletedWithChunks,
        WriterFault::TreeKindOrSize,
        WriterFault::HashCount {
            chunks: 1,
            hashes: 2,
        },
        WriterFault::DirectoryWithChunks,
        WriterFault::FileWithoutChunks,
        WriterFault::Kind(9),
    ] {
        assert_ne!(fault.to_string(), "");
    }
}

#[test]
fn paths() {
    assert_eq!(check_path("a/b/c.txt"), Ok(()));
    assert_eq!(check_path(".hidden/..x/x.."), Ok(()));
    assert_eq!(check_path(&"a".repeat(MAX_PATH_BYTES)), Ok(()));
    assert_eq!(
        check_path(&"a".repeat(MAX_PATH_BYTES + 1)),
        Err(PathError::TooLong(MAX_PATH_BYTES + 1))
    );
    assert_eq!(check_path(""), Err(PathError::Empty));
    assert_eq!(check_path("/a"), Err(PathError::Absolute));
    assert_eq!(check_path("a//b"), Err(PathError::EmptyComponent));
    assert_eq!(check_path("a/"), Err(PathError::EmptyComponent));
    assert_eq!(check_path("a/./b"), Err(PathError::DotComponent));
    assert_eq!(check_path("a/.."), Err(PathError::DotComponent));
    assert_eq!(check_path("a\0b"), Err(PathError::Nul));
    assert_eq!(check_path("a\\b"), Err(PathError::Backslash));
    for e in [
        PathError::Empty,
        PathError::TooLong(5000),
        PathError::Absolute,
        PathError::EmptyComponent,
        PathError::DotComponent,
        PathError::Nul,
        PathError::Backslash,
    ] {
        assert_ne!(e.to_string(), "");
    }
    assert!(at_or_beneath("a/b", "a/b"));
    assert!(at_or_beneath("a/b/c", "a/b"));
    assert!(!at_or_beneath("a/bc", "a/b"));
    assert!(!at_or_beneath("a", "a/b"));
}

#[test]
fn kinds() {
    assert_eq!(Kind::from_wire(1), Some(Kind::File));
    assert_eq!(Kind::from_wire(2), Some(Kind::Directory));
    assert_eq!(Kind::from_wire(0), None);
    assert_eq!(Kind::from_wire(3), None);
    assert_eq!(Kind::File.to_wire(), 1);
    assert_eq!(Kind::Directory.to_wire(), 2);
}

#[test]
fn vectors_and_coverage() {
    assert!(Vector::from_sorted(vec![dot(1, 5), dot(3, 2)]).is_some());
    assert!(Vector::from_sorted(vec![dot(3, 5), dot(1, 2)]).is_none());
    assert!(Vector::from_sorted(vec![dot(1, 5), dot(1, 6)]).is_none());
    assert!(Vector::from_sorted(vec![dot(1, 0)]).is_none());
    let v = Vector::from_sorted(vec![dot(1, 5), dot(3, 2)]).unwrap();
    assert_eq!((v.get(&dev(1)), v.get(&dev(2)), v.get(&dev(3))), (5, 0, 2));
    assert_eq!((v.len(), v.is_empty()), (2, false));
    assert!(Vector::default().is_empty());
    // Coverage reads one entry: equal covers, one below does not.
    assert!(v.covers(&dot(1, 5)));
    assert!(v.covers(&dot(1, 4)));
    assert!(!v.covers(&dot(1, 6)));
    assert!(!v.covers(&dot(2, 1)));
    let mut m = meta("a", 1);
    m.deleted = true;
    assert!(m.is_tombstone() && m.is_deletion() && !m.is_tree_delete());
    m.tree = true;
    assert!(!m.is_tombstone() && m.is_deletion() && m.is_tree_delete());
}

#[test]
fn the_writer_refuses_what_a_reader_would() {
    let key = folder(0x10);
    let s = |d: &IndexDraft| sign(&key, d).err();
    assert_eq!(s(&draft(0)), Some(DraftError::Counter(0)));
    assert_eq!(
        s(&draft(MAX_COUNTER + 1)),
        Some(DraftError::Counter(MAX_COUNTER + 1))
    );
    assert!(s(&draft(MAX_COUNTER)).is_none());
    let mut d = draft(100);
    d.replaces = (0..65).map(|i| RecordHash([i; 32])).collect();
    assert_eq!(s(&d), Some(DraftError::Replaces(65)));
    d.replaces = (0..64).map(|i| RecordHash([i; 32])).collect();
    assert!(s(&d).is_none(), "64 names fit");
    d.replaces = vec![RecordHash([1; 32]); 100];
    assert!(s(&d).is_none(), "repeats count once");
    let mut d = draft(100);
    d.meta.vector = Vector((0..33).map(|i| dot(i, 1)).collect());
    assert_eq!(s(&d), Some(DraftError::Vector(33)));
    d.meta.vector = Vector(vec![dot(1, 1), dot(1, 2)]);
    assert_eq!(s(&d), Some(DraftError::VectorDuplicate));
    d.meta.vector = Vector(vec![dot(1, 0)]);
    assert_eq!(s(&d), Some(DraftError::VectorCounter));
    d.meta.vector = Vector(vec![dot(1, 100)]);
    assert_eq!(s(&d), Some(DraftError::VectorCounter));
    let mut d = draft(100);
    d.chunks[0].stored_len = 47 + 2;
    assert_eq!(s(&d), Some(DraftError::StoredLen(49)));
    let mut d = draft(100);
    d.chunks = vec![chunk(1); MAX_CHUNKS + 1];
    assert_eq!(s(&d), Some(DraftError::Chunks(MAX_CHUNKS + 1)));
    let mut d = draft(100);
    d.meta.deleted = true;
    assert_eq!(
        s(&d),
        Some(DraftError::Fault(WriterFault::DeletedWithChunks))
    );
    let mut d = draft(100);
    d.meta.path = "/abs".into();
    assert_eq!(
        s(&d),
        Some(DraftError::Fault(WriterFault::Path(PathError::Absolute)))
    );
    let mut d = draft(100);
    d.meta.plain_hashes.clear();
    assert!(matches!(
        s(&d),
        Some(DraftError::Fault(WriterFault::HashCount { .. }))
    ));
    let mut d = draft(100);
    d.meta.kind = Kind::Directory;
    assert_eq!(
        s(&d),
        Some(DraftError::Fault(WriterFault::DirectoryWithChunks))
    );
    let mut d = draft(100);
    d.meta.tree = true;
    assert_eq!(
        s(&d),
        Some(DraftError::Fault(WriterFault::TreeWithoutDeleted))
    );
    // Record keys of another folder.
    assert_eq!(
        draft(1)
            .sign(&key, &folder(0x20).record_keys(), &mut fill(1))
            .err(),
        Some(DraftError::WrongKeys)
    );
    // Cleanups.
    let c = |groups: Vec<Group>, counter: u64| {
        CleanupDraft {
            dot: dot(2, counter),
            groups,
        }
        .sign(&key, &key.record_keys(), &mut fill(1))
        .err()
    };
    let g = |n: usize| Group {
        because: None,
        forget: (0..n)
            .map(|i| RecordHash(core::array::from_fn(|j| (i >> (8 * (j % 4))) as u8)))
            .collect(),
    };
    assert_eq!(c(vec![], 1), Some(DraftError::Groups(0)));
    assert_eq!(
        c(vec![g(1); MAX_CLEANUP_GROUPS + 1], 1),
        Some(DraftError::Groups(MAX_CLEANUP_GROUPS + 1))
    );
    assert!(c(vec![g(1); MAX_CLEANUP_GROUPS], 1).is_none());
    assert_eq!(c(vec![g(0)], 1), Some(DraftError::Names(0)));
    assert_eq!(
        c(vec![g(MAX_CLEANUP_ENTRIES + 1)], 1),
        Some(DraftError::Names(MAX_CLEANUP_ENTRIES + 1))
    );
    assert!(c(vec![g(MAX_CLEANUP_ENTRIES)], 1).is_none());
    assert_eq!(c(vec![g(1)], 0), Some(DraftError::Counter(0)));
    assert_eq!(
        CleanupDraft {
            dot: dot(2, 1),
            groups: vec![g(1)],
        }
        .sign(&key, &folder(0x20).record_keys(), &mut fill(1))
        .err(),
        Some(DraftError::WrongKeys)
    );
    for e in [
        DraftError::WrongKeys,
        DraftError::Replaces(65),
        DraftError::Vector(33),
        DraftError::VectorDuplicate,
        DraftError::VectorCounter,
        DraftError::Counter(0),
        DraftError::Chunks(1),
        DraftError::StoredLen(1),
        DraftError::Groups(0),
        DraftError::Names(0),
        DraftError::Fault(WriterFault::Kind(3)),
        DraftError::Seal(MetaError::OverPadded),
        DraftError::Refused(WireError::Truncated),
    ] {
        assert_ne!(e.to_string(), "");
    }
}

#[test]
fn the_largest_records_fit() {
    // Section 2's sizing: the largest index record a writer can draft and
    // the largest cleanup both encode below MAX_INDEX_RECORD_BYTES.
    let key = folder(0x10);
    let mut d = draft(MAX_COUNTER);
    d.chunks = (0..MAX_CHUNKS)
        .map(|i| Chunk {
            cipher_hash: CipherHash([u8::try_from(i % 251).unwrap(); 32]),
            stored_len: 4_325_416,
        })
        .collect();
    d.meta.path = "p".repeat(MAX_PATH_BYTES);
    d.meta.plain_hashes = vec![PlainHash([1; 32]); MAX_CHUNKS];
    d.meta.vector = Vector((0..32).map(|i| dot(i, MAX_COUNTER - 1)).collect());
    d.replaces = (0..64).map(|i| RecordHash([i; 32])).collect();
    let signed = sign(&key, &d).unwrap();
    assert!(envelope_len(&signed) < MAX_INDEX_RECORD_BYTES);
    assert_eq!(envelope_len(&signed), signed.to_bytes().len());
    let groups: Vec<Group> = (0..MAX_CLEANUP_GROUPS)
        .map(|g| Group {
            because: Some(RecordHash([0xee; 32])),
            forget: (0..MAX_CLEANUP_ENTRIES / MAX_CLEANUP_GROUPS)
                .map(|i| {
                    let mut h = [0u8; 32];
                    h[..4].copy_from_slice(&u32::try_from(g).unwrap().to_be_bytes());
                    h[4..8].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
                    RecordHash(h)
                })
                .collect(),
        })
        .collect();
    let c = CleanupDraft {
        dot: dot(2, MAX_COUNTER),
        groups,
    }
    .sign(&key, &key.record_keys(), &mut fill(1))
    .unwrap();
    assert!(envelope_len(&c) < MAX_INDEX_RECORD_BYTES);
    // A tombstone and a tree delete sign.
    let mut t = draft(5);
    t.chunks.clear();
    t.meta.plain_hashes.clear();
    t.meta.size = 0;
    t.meta.deleted = true;
    let tomb = parsed(&key, sign(&key, &t).unwrap());
    let m = tomb.open(&key.record_keys()).unwrap();
    assert!(m.meta().unwrap().is_tombstone());
    t.meta.tree = true;
    t.meta.kind = Kind::Directory;
    let tree = parsed(&key, sign(&key, &t).unwrap());
    assert!(tree
        .open(&key.record_keys())
        .unwrap()
        .meta()
        .unwrap()
        .is_tree_delete());
}

/// A draft's record with an unknown field of `extra` bytes added to its body,
/// signed again: what a later release's writer may send.
fn padded(key: &WriteKey, extra: usize) -> Result<SignedRecord, Malformed> {
    let base = sign(key, &draft(1)).unwrap();
    let mut body = base.body().to_vec();
    prost::encoding::bytes::encode(99, &vec![7u8; extra], &mut body);
    key.sign_index_record(body)
}

#[test]
fn a_record_of_exactly_max_index_record_bytes_is_accepted() {
    // R2-SF4: the cap is inclusive, and judged on the encoded envelope.
    let key = folder(0x10);
    let mut extra = MAX_INDEX_RECORD_BYTES - 2_000;
    let mut exact = padded(&key, extra).unwrap();
    for _ in 0..8 {
        let len = envelope_len(&exact);
        if len == MAX_INDEX_RECORD_BYTES {
            break;
        }
        extra = extra + MAX_INDEX_RECORD_BYTES - len;
        exact = padded(&key, extra).unwrap();
    }
    assert_eq!(envelope_len(&exact), MAX_INDEX_RECORD_BYTES);
    let bytes = exact.to_bytes();
    assert_eq!(bytes.len(), MAX_INDEX_RECORD_BYTES);
    let r = Record::from_bytes(&bytes, key.verifier()).unwrap();
    assert!(r.verify(key.verifier()).is_ok());
    // One byte more is never signed (the keys crate's K-3), and the bytes
    // of such an envelope are refused before anything is decoded.
    assert_eq!(
        padded(&key, extra + 1),
        Err(Malformed::TooLarge(MAX_INDEX_RECORD_BYTES + 1))
    );
    let mut over = bytes.clone();
    over.push(0);
    assert!(matches!(
        Record::from_bytes(&over, key.verifier()),
        Err(WireError::Record(Malformed::TooLarge(_)))
    ));
}

fn arb_dot() -> impl Strategy<Value = Dot> {
    (0u8..6, 0u64..12).prop_map(|(d, c)| dot(d, c))
}

proptest! {
    #![proptest_config(crate::testkit::proptest_config(256))]

    /// `envelope_len` is the length `SignedRecord::to_bytes` lays out, for
    /// bodies of any length across the varint boundaries (R2 N10).
    #[test]
    fn envelope_len_is_the_encoded_length(len in 0usize..70_000, byte in any::<u8>()) {
        let body = vec![byte; len];
        let signed = crate::testkit::record_of_any(&body, &[byte; 64]);
        prop_assert_eq!(envelope_len(&signed), signed.to_bytes().len());
    }

    /// A draft never emits what a reader's step 1 or step 7 refuses: it is
    /// refused with a reason, or it parses, verifies and opens to what was
    /// drafted.
    #[test]
    fn a_draft_never_emits_what_a_reader_refuses(
        counter in 0u64..12,
        vector in proptest::collection::vec(arb_dot(), 0..5),
        names in proptest::collection::vec(any::<u8>(), 0..4),
        path in "[a-c/.]{0,6}",
        kind in prop_oneof![Just(Kind::File), Just(Kind::Directory)],
        deleted in any::<bool>(),
        tree in any::<bool>(),
        chunks in 0usize..3,
        hashes in 0usize..3,
        size in 0u64..3,
    ) {
        let key = folder(0x10);
        let keys = key.record_keys();
        let mut m = meta(&path, counter);
        m.kind = kind;
        m.deleted = deleted;
        m.tree = tree;
        m.size = size;
        m.plain_hashes = vec![PlainHash([1; 32]); hashes];
        m.vector = Vector(vector);
        let d = IndexDraft {
            meta: m.clone(),
            chunks: (0..chunks).map(|i| chunk(i as u8)).collect(),
            replaces: names.iter().map(|n| RecordHash([*n; 32])).collect(),
        };
        match d.sign(&key, &keys, &mut fill(1)) {
            Err(e) => prop_assert_ne!(e.to_string(), ""),
            Ok(signed) => {
                let r = Record::from_bytes(&signed.to_bytes(), key.verifier()).unwrap();
                prop_assert!(r.verify(key.verifier()).is_ok());
                let Ok(Applied::Index(opened)) = r.open(&keys) else {
                    return Err(TestCaseError::fail("a signed draft does not open"));
                };
                prop_assert_eq!(opened.path, m.path);
                prop_assert_eq!(opened.dot, m.dot);
                prop_assert!(opened.vector.len() <= m.vector.len());
                prop_assert_eq!((opened.deleted, opened.tree), (deleted, tree));
            }
        }
    }
}
