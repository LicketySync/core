#![no_main]
//! A stored chunk from a peer, opened under the test vectors' folder (write
//! secret `10 11 .. 2f`) against the plaintext hash of the vectors' raw chunk,
//! so that the committed seeds reach every step of `open_chunk`. What opens
//! must be that raw chunk, and must seal and open again to itself.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::chunk::{open_chunk, seal_chunk, ChunkKeys, PlainHash, MAX_CHUNK_PLAINTEXT};
use licketysync_keys::{Suite, WriteKey, WriteSecret};

fn keys() -> &'static (ChunkKeys, PlainHash, Vec<u8>) {
    static KEYS: OnceLock<(ChunkKeys, PlainHash, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        let keys = w.chunk_keys();
        let raw: Vec<u8> = (0..300u32).map(|i| (i * 7 % 256) as u8).collect();
        let expected = keys.plain_hash(&raw);
        (keys, expected, raw)
    })
}

fuzz_target!(|data: &[u8]| {
    let (keys, expected, raw) = keys();
    if let Ok(opened) = open_chunk(keys, data, expected) {
        assert_eq!(&*opened, &raw[..]);
        assert!((1..=MAX_CHUNK_PLAINTEXT).contains(&opened.len()));
        let sealed = seal_chunk(keys, &opened).expect("a chunk that opened seals");
        assert!(bool::from(sealed.plain_hash.ct_eq(expected)));
        let again = open_chunk(keys, &sealed.stored, &sealed.plain_hash).expect("and opens");
        assert_eq!(&*again, &*opened);
    }
});
