#![no_main]
//! An encoded `SignedRecord` from a peer, an index record or a cleanup,
//! through the two steps of `protocol.md` 4.4 that need no index, under the
//! test vectors' folder (write secret `10 11 .. 2f`): step 1 (the envelope and
//! the body of its record type), then step 7 (the seal and every check of the
//! metadata) for a write holder. What passes step 1 keeps its body byte for
//! byte (its envelope encodes again to the same record) and has its key in
//! the set digests (path tag or own hash, then its hash); step 7 is a pure
//! function of the record, its verdict the same each time; an applied
//! record's metadata is consistent with its clear fields; and a forged
//! record, whatever it is, is refused by the signature check without a
//! panic.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::sealed_meta::RecordKeys;
use licketysync_keys::{Suite, WriteKey, WriteSecret};
use licketysync_protocol::limits::{MAX_COUNTER, MAX_VECTOR_ENTRIES};
use licketysync_protocol::record::{Applied, Record};

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
    let (w, keys) = key();
    let Ok(record) = Record::from_bytes(data, w.verifier()) else {
        return;
    };
    assert_eq!(record.hash(), record.signed().hash());
    let again = licketysync_keys::records::SignedRecord::from_bytes(&record.signed().to_bytes());
    assert_eq!(again.as_ref(), Ok(record.signed()), "the body kept byte for byte");
    let key = record.key();
    match record.path_tag() {
        Some(tag) => assert_eq!(key[..32], tag.0),
        None => assert_eq!(key[..32], record.hash().0),
    }
    assert_eq!(key[32..], record.hash().0);
    let _ = record.verify(w.verifier());
    let verdict = record.open(keys);
    let again = record.open(keys);
    assert_eq!(
        format!("{verdict:?}"),
        format!("{again:?}"),
        "step 7 is a pure function of the record"
    );
    match verdict {
        Ok(Applied::Index(m)) => {
            assert!(!record.is_cleanup());
            assert_eq!(record.path_tag(), Some(keys.path_tag(&m.path)));
            assert!((1..=MAX_COUNTER).contains(&m.dot.counter));
            assert!(m.vector.len() <= MAX_VECTOR_ENTRIES);
            assert!(m
                .vector
                .entries()
                .iter()
                .all(|d| d.counter >= 1 && d.counter < m.dot.counter));
            assert!(m.vector.entries().windows(2).all(|p| p[0].device < p[1].device));
            assert!(!m.tree || (m.deleted && m.size == 0));
            assert!(!m.deleted || record.chunks().is_empty());
            assert_eq!(m.plain_hashes.len(), record.chunks().len());
        }
        Ok(Applied::Cleanup(dot)) => {
            assert!(record.is_cleanup());
            assert!((1..=MAX_COUNTER).contains(&dot.counter));
        }
        Err(fault) => {
            assert_ne!(fault.to_string(), "");
        }
    }
});
