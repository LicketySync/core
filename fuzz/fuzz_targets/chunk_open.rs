#![no_main]
//! A stored chunk from a peer, opened under the test vectors' keys.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::chunk::{open_chunk, ChunkKeys, PlainHash};
use licketysync_keys::secret::ChunkHashKey;
use licketysync_keys::{DataKey, FolderId};

fuzz_target!(|data: &[u8]| {
    let dk = DataKey::from_bytes([0x44; 32]);
    let keys = ChunkKeys::new(&dk, &FolderId([0x45; 32]), 1);
    let hk = ChunkHashKey::from_bytes([0x46; 32]);
    let _ = open_chunk(&keys, &hk, data, &PlainHash([0x47; 32]));
});
