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

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::secret::WriteSecret;
use licketysync_keys::{Suite, WriteKey};

use super::*;

pub(crate) fn folder(byte: u8) -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes([byte; 32])).unwrap()
}

fn meta(path: &str, kind: Kind, hashes: usize) -> Meta {
    Meta {
        path: path.into(),
        kind,
        size: if kind == Kind::File && hashes > 0 {
            10
        } else {
            0
        },
        mtime_ns: 1_700_000_000_000_000_000,
        mode: 0o644,
        plain_hashes: (0..hashes)
            .map(|i| PlainHash([u8::try_from(i % 251).unwrap(); 32]))
            .collect(),
        written_at: 1_700_000_000,
    }
}

fn chunk(byte: u8) -> Chunk {
    Chunk {
        cipher_hash: CipherHash([byte; 32]),
        stored_len: 46,
    }
}

pub(crate) fn draft(device: u8, seq: u64) -> Draft {
    Draft {
        device_id: DeviceId([device; 32]),
        seq,
        supersedes: vec![],
        deleted: false,
        chunks: vec![chunk(1)],
        meta: meta("docs/a.txt", Kind::File, 1),
    }
}

fn fill(byte: u8) -> impl FnMut(&mut [u8]) {
    move |b: &mut [u8]| b.fill(byte)
}

/// Signs a body around arbitrary sealed metadata bytes, bypassing the
/// writer's rules, so that every reader refusal can be reached.
fn forge(key: &WriteKey, seq: u64, chunks: &[Chunk], deleted: bool, meta: &[u8]) -> Record {
    let folder = key.verifier();
    let sealed = seal_meta(
        &key.data_key().record_key(),
        &folder.folder_id(),
        &DeviceId([7; 32]),
        seq,
        meta,
        &mut fill(3),
    )
    .unwrap();
    let body = IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: folder.folder_id().0.to_vec(),
        device_id: vec![7; 32],
        seq,
        supersedes: vec![],
        deleted,
        chunks: chunks
            .iter()
            .map(|c| ChunkRef {
                cipher_hash: c.cipher_hash.0.to_vec(),
                stored_len: c.stored_len,
            })
            .collect(),
        sealed,
    }
    .encode_to_vec();
    Record::parse(key.sign_index_record(body), folder).unwrap()
}

#[derive(Default)]
struct Index {
    held: BTreeSet<RecordHash>,
    cursors: BTreeMap<DeviceId, u64>,
}

impl Held for Index {
    fn holds(&self, record: &RecordHash) -> bool {
        self.held.contains(record)
    }
    fn cursor(&self, writer: &DeviceId) -> u64 {
        self.cursors.get(writer).copied().unwrap_or(0)
    }
}

impl Index {
    fn store(&mut self, r: &Record) {
        self.held.insert(r.hash());
        let c = self.cursors.entry(r.device_id()).or_insert(0);
        *c = (*c).max(r.seq());
    }
}

#[test]
fn a_draft_signs_parses_verifies_and_opens() {
    let key = folder(1);
    let mut d = draft(2, 1);
    d.supersedes = vec![
        RecordHash([9; 32]),
        RecordHash([8; 32]),
        RecordHash([9; 32]),
    ];
    let signed = d.sign(&key, &mut fill(4)).unwrap();
    let r = Record::from_bytes(&signed.to_bytes(), key.verifier()).unwrap();
    assert_eq!(r.signed(), &signed);
    assert_eq!(r.hash(), signed.hash());
    assert_eq!(r.folder_id(), key.verifier().folder_id());
    assert_eq!(r.device_id(), DeviceId([2; 32]));
    assert_eq!(r.seq(), 1);
    assert_eq!(
        r.supersedes(),
        &[RecordHash([8; 32]), RecordHash([9; 32])],
        "a set: sorted, repeats dropped"
    );
    assert!(!r.deleted());
    assert_eq!(r.chunks(), &[chunk(1)]);
    assert_eq!(&r.sealed()[..24], &[4; 24], "the nonce drawn from rng");
    r.verify(key.verifier()).unwrap();
    let m = r.open(key.data_key()).unwrap();
    assert_eq!(m.path, "docs/a.txt");
    assert_eq!(m.kind, Kind::File);
    assert_eq!(m.size, 10);
    assert_eq!(m.mode, 0o644);
    assert_eq!(m.plain_hashes.len(), 1);
    assert_eq!(m.plain_hashes[0].0, [0; 32]);
    assert_eq!(m.written_at, 1_700_000_000);
    assert_eq!(m.mtime_ns, 1_700_000_000_000_000_000);
    // A read key opens it too; it is the folder's data key.
    let read = key.read_key();
    assert!(r.open(read.data_key()).is_ok());
    assert_eq!(r.clone().into_signed(), signed);
}

#[test]
fn step_one_binds_the_record_to_the_open_folder() {
    let key = folder(1);
    let other = folder(2);
    let signed = draft(2, 1).sign(&key, &mut fill(4)).unwrap();
    assert_eq!(
        Record::parse(signed.clone(), other.verifier()),
        Err(WireError::Grammar {
            what: "folder_id: not the open folder"
        })
    );
    let mut body = IndexRecord::parse(signed.body()).unwrap();
    body.suite = 2;
    let resigned = key.sign_index_record(body.encode_to_vec());
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
    let big = key.sign_index_record(vec![0; MAX_INDEX_RECORD_BYTES]);
    assert!(matches!(
        Record::parse(big, key.verifier()),
        Err(WireError::Record(Malformed::TooLarge(_)))
    ));
    assert!(matches!(
        Record::from_bytes(&[0x0b], key.verifier()),
        Err(WireError::Record(_))
    ));
}

#[test]
fn judge_follows_the_steps_in_order() {
    let key = folder(1);
    let v = key.verifier();
    let rec = |seq| Record::parse(draft(2, seq).sign(&key, &mut fill(4)).unwrap(), v).unwrap();
    let forged = |seq| {
        let s = draft(2, seq).sign(&key, &mut fill(5)).unwrap();
        Record::parse(crate::testkit::flipped(&s, 0), v).unwrap()
    };
    let mut index = Index::default();
    let r1 = rec(1);
    assert_eq!(judge(&r1, Arrival::Push, &index, v), Ok(Judgement::Next));
    index.store(&r1);
    // A duplicate is ignored without verifying, its signature garbage or not.
    let garbage = crate::testkit::resigned(r1.signed(), [0; 64]);
    let dup = Record::parse(garbage, v).unwrap();
    for arrival in [Arrival::Push, Arrival::Reply { in_scope: false }] {
        assert_eq!(judge(&dup, arrival, &index, v), Ok(Judgement::Duplicate));
    }
    // A gap: on a push ignored unverified (forged or not); in a reply a
    // sender violation, before and whatever the signature.
    assert_eq!(
        judge(&rec(3), Arrival::Push, &index, v),
        Ok(Judgement::PushGap)
    );
    assert_eq!(
        judge(&forged(3), Arrival::Push, &index, v),
        Ok(Judgement::PushGap)
    );
    let reply = Arrival::Reply { in_scope: true };
    assert_eq!(
        judge(&rec(3), reply, &index, v),
        Err(Cause::SenderViolation)
    );
    assert_eq!(
        judge(&forged(3), reply, &index, v),
        Err(Cause::SenderViolation)
    );
    // Out of scope in a reply: a violation even when it would be next.
    assert_eq!(
        judge(&rec(2), Arrival::Reply { in_scope: false }, &index, v),
        Err(Cause::SenderViolation)
    );
    // Forged, and forged wins over a writer fault inside.
    assert_eq!(judge(&forged(2), reply, &index, v), Err(Cause::Forged));
    // The next record, and a concurrent version at and below the cursor.
    assert_eq!(judge(&rec(2), reply, &index, v), Ok(Judgement::Next));
    let r2 = rec(2);
    index.store(&r2);
    let other_at_2 = Record::parse(draft(2, 2).sign(&key, &mut fill(6)).unwrap(), v).unwrap();
    assert_ne!(other_at_2.hash(), r2.hash());
    assert_eq!(
        judge(&other_at_2, reply, &index, v),
        Ok(Judgement::Concurrent)
    );
    let other_at_1 = Record::parse(draft(2, 1).sign(&key, &mut fill(7)).unwrap(), v).unwrap();
    assert_eq!(
        judge(&other_at_1, Arrival::Push, &index, v),
        Ok(Judgement::Concurrent)
    );
    assert_eq!(
        Judgement::Concurrent.cause(),
        Some(Cause::ConcurrentVersion)
    );
    assert_eq!(Judgement::Duplicate.cause(), Some(Cause::Duplicate));
    assert_eq!(Judgement::PushGap.cause(), Some(Cause::PushGap));
    assert_eq!(Judgement::Next.cause(), None);
    assert!(Judgement::Next.stores() && Judgement::Concurrent.stores());
    assert!(!Judgement::Duplicate.stores() && !Judgement::PushGap.stores());
    // A record of another folder's key verifies nowhere here.
    let mut alien = draft(2, 3).sign(&folder(2), &mut fill(4)).unwrap();
    let mut body = IndexRecord::parse(alien.body()).unwrap();
    body.folder_id = v.folder_id().0.to_vec();
    alien = folder(2).sign_index_record(body.encode_to_vec());
    let alien = Record::parse(alien, v).unwrap();
    assert_eq!(judge(&alien, Arrival::Push, &index, v), Err(Cause::Forged));
}

#[test]
fn own_sequence_ahead_is_at_or_above_the_next_seq() {
    let key = folder(1);
    let r = Record::parse(
        draft(2, 5).sign(&key, &mut fill(4)).unwrap(),
        key.verifier(),
    )
    .unwrap();
    assert!(own_sequence_ahead(&r, &DeviceId([2; 32]), 5));
    assert!(own_sequence_ahead(&r, &DeviceId([2; 32]), 4));
    assert!(!own_sequence_ahead(&r, &DeviceId([2; 32]), 6));
    assert!(!own_sequence_ahead(&r, &DeviceId([3; 32]), 1));
}

#[test]
fn every_writer_fault_of_step_six() {
    let key = folder(1);
    let encode = |m: SealedMeta| m.encode_to_vec();
    let good = || SealedMeta {
        path: "a".into(),
        kind: 1,
        size: 1,
        plain_hashes: vec![vec![1; 32]],
        ..SealedMeta::default()
    };
    let dk = key.data_key();
    let open = |r: Record| r.open(dk);
    assert!(open(forge(&key, 1, &[chunk(1)], false, &encode(good()))).is_ok());
    // A seal from another folder does not open here.
    let alien = forge(&folder(2), 1, &[], false, &encode(good()));
    let mut body = IndexRecord::parse(alien.signed().body()).unwrap();
    body.folder_id = key.verifier().folder_id().0.to_vec();
    let moved = Record::parse(key.sign_index_record(body.encode_to_vec()), key.verifier()).unwrap();
    assert_eq!(open(moved).err(), Some(WriterFault::Seal(MetaError::Open)));
    assert!(matches!(
        open(forge(&key, 1, &[], false, &[0x0b])).err(),
        Some(WriterFault::Meta(_))
    ));
    for (path, err) in [
        ("", PathError::Empty),
        ("/a", PathError::Absolute),
        ("a//b", PathError::EmptyComponent),
        ("a/", PathError::EmptyComponent),
        ("a/./b", PathError::DotComponent),
        ("..", PathError::DotComponent),
        ("a\0b", PathError::Nul),
        ("a\\b", PathError::Backslash),
    ] {
        let m = SealedMeta {
            path: path.into(),
            ..good()
        };
        assert_eq!(
            open(forge(&key, 1, &[chunk(1)], false, &encode(m))).err(),
            Some(WriterFault::Path(err)),
            "{path:?}"
        );
    }
    // Not NFC ("e" + combining acute): accepted, NFC is the writer's duty.
    let nfd = SealedMeta {
        path: "cafe\u{301}".into(),
        ..good()
    };
    assert!(open(forge(&key, 1, &[chunk(1)], false, &encode(nfd))).is_ok());
    let kind3 = SealedMeta { kind: 3, ..good() };
    assert_eq!(
        open(forge(&key, 1, &[chunk(1)], false, &encode(kind3))).err(),
        Some(WriterFault::Kind(3))
    );
    assert_eq!(
        open(forge(
            &key,
            1,
            &[chunk(1), chunk(2)],
            false,
            &encode(good())
        ))
        .err(),
        Some(WriterFault::HashCount {
            chunks: 2,
            hashes: 1
        })
    );
    let dir = SealedMeta {
        kind: 2,
        size: 0,
        ..good()
    };
    assert_eq!(
        open(forge(&key, 1, &[chunk(1)], false, &encode(dir))).err(),
        Some(WriterFault::DirectoryWithChunks)
    );
    let file = SealedMeta {
        plain_hashes: vec![],
        ..good()
    };
    assert_eq!(
        open(forge(&key, 1, &[], false, &encode(file.clone()))).err(),
        Some(WriterFault::FileWithoutChunks)
    );
    // A tombstone names what was deleted: no chunk rule applies to it.
    assert!(open(forge(&key, 1, &[], true, &encode(file))).is_ok());
    // An empty file and a directory without chunks are fine.
    let empty = SealedMeta {
        size: 0,
        plain_hashes: vec![],
        ..good()
    };
    assert!(open(forge(&key, 1, &[], false, &encode(empty))).is_ok());
    let dir = SealedMeta {
        kind: 2,
        size: 0,
        plain_hashes: vec![],
        ..good()
    };
    assert!(open(forge(&key, 1, &[], false, &encode(dir))).is_ok());
    for fault in [
        WriterFault::Seal(MetaError::Padding),
        WriterFault::Meta(WireError::Truncated),
        WriterFault::Path(PathError::Nul),
        WriterFault::Kind(9),
        WriterFault::HashCount {
            chunks: 1,
            hashes: 2,
        },
        WriterFault::DirectoryWithChunks,
        WriterFault::FileWithoutChunks,
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
}

#[test]
fn the_writer_refuses_what_a_reader_would() {
    let key = folder(1);
    let sign = |d: &Draft| d.sign(&key, &mut fill(1)).err();
    assert_eq!(sign(&draft(2, 0)), Some(DraftError::Seq(0)));
    assert_eq!(
        sign(&draft(2, MAX_SEQ + 1)),
        Some(DraftError::Seq(MAX_SEQ + 1))
    );
    assert!(sign(&draft(2, MAX_SEQ)).is_none());
    let mut d = draft(2, 1);
    d.supersedes = (0..17).map(|i| RecordHash([i; 32])).collect();
    assert_eq!(sign(&d), Some(DraftError::Supersedes(17)));
    d.supersedes = vec![RecordHash([1; 32]); 20];
    assert!(sign(&d).is_none(), "repeats count once");
    let mut d = draft(2, 1);
    d.chunks[0].stored_len = 47 + 2;
    assert_eq!(sign(&d), Some(DraftError::StoredLen(49)));
    let mut d = draft(2, 1);
    d.deleted = true;
    assert_eq!(sign(&d), Some(DraftError::DeletedWithChunks));
    let mut d = draft(2, 1);
    d.meta.path = "/abs".into();
    assert_eq!(
        sign(&d),
        Some(DraftError::Fault(WriterFault::Path(PathError::Absolute)))
    );
    let mut d = draft(2, 1);
    d.meta.plain_hashes.clear();
    assert!(matches!(
        sign(&d),
        Some(DraftError::Fault(WriterFault::HashCount { .. }))
    ));
    let mut d = draft(2, 1);
    d.meta.kind = Kind::Directory;
    assert_eq!(
        sign(&d),
        Some(DraftError::Fault(WriterFault::DirectoryWithChunks))
    );
    let mut d = draft(2, 1);
    d.chunks = vec![chunk(1); MAX_CHUNKS + 1];
    assert_eq!(sign(&d), Some(DraftError::Chunks(MAX_CHUNKS + 1)));
    for e in [
        DraftError::Seq(0),
        DraftError::Supersedes(17),
        DraftError::Chunks(1),
        DraftError::StoredLen(1),
        DraftError::DeletedWithChunks,
        DraftError::Fault(WriterFault::Kind(3)),
        DraftError::Seal(MetaError::TooLong(1)),
        DraftError::Refused(WireError::Truncated),
    ] {
        assert_ne!(e.to_string(), "");
    }
}

#[test]
fn the_largest_record_fits_and_a_tombstone_signs() {
    let key = folder(1);
    let mut d = draft(2, 1);
    d.chunks = (0..MAX_CHUNKS)
        .map(|i| Chunk {
            cipher_hash: CipherHash([u8::try_from(i % 251).unwrap(); 32]),
            stored_len: 4_325_416,
        })
        .collect();
    d.meta = meta(&"p".repeat(MAX_PATH_BYTES), Kind::File, MAX_CHUNKS);
    d.supersedes = (0..16).map(|i| RecordHash([i; 32])).collect();
    let signed = d.sign(&key, &mut fill(1)).unwrap();
    assert!(envelope_len(&signed) < MAX_INDEX_RECORD_BYTES);
    assert_eq!(envelope_len(&signed), signed.to_bytes().len());
    let tomb = Draft {
        deleted: true,
        chunks: vec![],
        meta: Meta {
            plain_hashes: vec![],
            ..meta("x", Kind::File, 0)
        },
        ..draft(2, 2)
    };
    let r = Record::parse(tomb.sign(&key, &mut fill(1)).unwrap(), key.verifier()).unwrap();
    assert!(r.deleted());
}

#[test]
fn writer_digests_follow_canonical_order() {
    let h = |b: u8| RecordHash([b; 32]);
    let one_per_seq = writer_digests([(1, h(5)), (2, h(3)), (3, h(9))]);
    let d1 = WriterDigest::ZERO.then(&h(5));
    let d2 = d1.then(&h(3));
    let d3 = d2.then(&h(9));
    assert_eq!(one_per_seq, BTreeMap::from([(1, d1), (2, d2), (3, d3)]));
    // Two records at one seq: canonical order is the smaller hash first, in
    // any arrival order, and the digest at 2 is after both.
    let a = writer_digests([(1, h(5)), (2, h(9)), (2, h(3))]);
    let b = writer_digests([(2, h(3)), (1, h(5)), (2, h(9)), (2, h(3))]);
    assert_eq!(a, b);
    assert_eq!(a[&2], d1.then(&h(3)).then(&h(9)));
    assert_eq!(a.len(), 2);
    // A concurrent version below the cursor changes every digest from its seq up.
    let c = writer_digests([(1, h(5)), (2, h(3)), (3, h(9)), (1, h(1))]);
    assert_ne!(c[&1], one_per_seq[&1]);
    assert_ne!(c[&3], one_per_seq[&3]);
    assert!(writer_digests([]).is_empty());
}

#[test]
fn kinds() {
    assert_eq!(Kind::from_wire(1), Some(Kind::File));
    assert_eq!(Kind::from_wire(2), Some(Kind::Directory));
    assert_eq!(Kind::from_wire(0), None);
    assert_eq!(Kind::File.to_wire(), 1);
    assert_eq!(Kind::Directory.to_wire(), 2);
}

/// A draft's record with an unknown field of `extra` bytes added to its body,
/// signed again: what a later release's writer may send.
fn padded(key: &WriteKey, extra: usize) -> SignedRecord {
    let base = draft(2, 1).sign(key, &mut fill(4)).unwrap();
    let mut body = base.body().to_vec();
    prost::encoding::bytes::encode(99, &vec![7u8; extra], &mut body);
    key.sign_index_record(body)
}

#[test]
fn a_record_of_exactly_max_index_record_bytes_is_accepted() {
    // R2-SF4: the cap is inclusive, and judged on the encoded envelope.
    let key = folder(1);
    let mut extra = MAX_INDEX_RECORD_BYTES - 2_000;
    let mut exact = padded(&key, extra);
    for _ in 0..8 {
        let len = envelope_len(&exact);
        if len == MAX_INDEX_RECORD_BYTES {
            break;
        }
        extra = extra + MAX_INDEX_RECORD_BYTES - len;
        exact = padded(&key, extra);
    }
    assert_eq!(envelope_len(&exact), MAX_INDEX_RECORD_BYTES);
    let bytes = exact.to_bytes();
    assert_eq!(bytes.len(), MAX_INDEX_RECORD_BYTES);
    let r = Record::from_bytes(&bytes, key.verifier()).unwrap();
    assert!(r.verify(key.verifier()).is_ok());
    let over = padded(&key, extra + 1);
    assert_eq!(envelope_len(&over), MAX_INDEX_RECORD_BYTES + 1);
    assert!(matches!(
        Record::parse(over.clone(), key.verifier()),
        Err(WireError::Record(Malformed::TooLarge(_)))
    ));
    assert!(matches!(
        Record::from_bytes(&over.to_bytes(), key.verifier()),
        Err(WireError::Record(Malformed::TooLarge(_)))
    ));
}

proptest::proptest! {
    /// `envelope_len` is the length `SignedRecord::to_bytes` lays out, for
    /// bodies of any length across the varint boundaries (R2 N10).
    #[test]
    fn envelope_len_is_the_encoded_length(len in 0usize..70_000, byte in proptest::prelude::any::<u8>()) {
        let body = vec![byte; len];
        let signed = crate::testkit::record_of_any(&body, &[byte; 64]);
        proptest::prop_assert_eq!(envelope_len(&signed), signed.to_bytes().len());
    }
}
