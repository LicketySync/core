#![no_main]
//! Opened sealed metadata (`SealedMeta`, `protocol.md` 4.4 step 7): the
//! bounded decoder, lax on what step 7 judges, then step 7 itself. What
//! parses is sealed at its own path's tag under the test vectors' folder
//! (write secret `10 11 .. 2f`), signed into an index record with as many
//! chunks as it has plaintext hashes, and opened again: the verdict of the
//! vector's length, order and duplicates, the counters, the deletion marks
//! and the path is the step-7 function's, and an applied record gives back
//! the parsed metadata. The path grammar runs on any UTF-8 input too.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::sealed_meta::RecordKeys;
use licketysync_keys::{Suite, WriteKey, WriteSecret};
use licketysync_protocol::messages::{ChunkRef, IndexRecord, SealedMeta};
use licketysync_protocol::record::{check_path, Applied, Record, WriterFault};
use licketysync_protocol::Parse;
use prost::Message as _;

fn key() -> &'static (WriteKey, RecordKeys) {
    static K: OnceLock<(WriteKey, RecordKeys)> = OnceLock::new();
    K.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        let keys = w.record_keys();
        (w, keys)
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = check_path(text);
    }
    let Ok(meta) = SealedMeta::parse(data) else {
        return;
    };
    let _ = check_path(&meta.path);
    let (w, keys) = key();
    let tag = keys.path_tag(&meta.path);
    let Ok(sealed) = keys.seal_index_meta(&tag, data, &mut |b: &mut [u8]| b.fill(7)) else {
        return;
    };
    let body = IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: w.verifier().folder_id().0.to_vec(),
        chunks: meta
            .plain_hashes
            .iter()
            .map(|_| ChunkRef {
                cipher_hash: vec![1; 32],
                stored_len: 46,
            })
            .collect(),
        sealed,
        path_tag: tag.0.to_vec(),
        replaces: vec![],
    };
    let Ok(signed) = w.sign_index_record(body.encode_to_vec()) else {
        return;
    };
    let record = Record::parse(signed, w.verifier()).expect("a body this target built");
    match record.open(keys) {
        Ok(Applied::Index(m)) => {
            assert_eq!(m.path, meta.path);
            assert_eq!(m.dot.counter, meta.counter);
            assert_eq!(m.vector.len(), meta.vector.len());
            assert_eq!((m.deleted, m.tree), (meta.deleted, meta.tree));
        }
        Ok(Applied::Cleanup(_)) => panic!("an index record"),
        Err(WriterFault::Seal(_) | WriterFault::Meta(_) | WriterFault::PathTag) => {
            panic!("the seal and the tag are this target's own")
        }
        Err(_) => {}
    }
});
