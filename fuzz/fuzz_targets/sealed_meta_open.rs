#![no_main]
//! The sealed part of an index record from a peer, opened under the test
//! vectors' folder (write secret `10 11 .. 2f`) as a record of the vectors'
//! device (device seed `a0 a1 .. bf`) at sequence 1. What opens fits the
//! sealed part it came from, and seals again, under the same nonce, to a part
//! that opens to it.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::device::DeviceKey;
use licketysync_keys::sealed_meta::{open_meta, seal_meta, MIN_SEALED_BYTES};
use licketysync_keys::secret::{DeviceSeed, RecordKey};
use licketysync_keys::{DeviceId, FolderId, Suite, WriteKey, WriteSecret};

fn place() -> &'static (RecordKey, FolderId, DeviceId) {
    static PLACE: OnceLock<(RecordKey, FolderId, DeviceId)> = OnceLock::new();
    PLACE.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        let seed: [u8; 32] = core::array::from_fn(|i| 0xa0 + i as u8);
        let device = DeviceKey::from_device_seed(&DeviceSeed::from_bytes(seed)).device_id();
        (w.data_key().record_key(), w.verifier().folder_id(), device)
    })
}

fuzz_target!(|data: &[u8]| {
    let (rk, folder, device) = place();
    if let Ok(meta) = open_meta(rk, folder, device, 1, data) {
        assert!(meta.len() + 4 + MIN_SEALED_BYTES <= data.len());
        let nonce = data.first_chunk::<24>().expect("a sealed part has its nonce");
        let sealed = seal_meta(rk, folder, device, 1, &meta, &mut |b| b.copy_from_slice(nonce))
            .expect("metadata that opened seals");
        assert_eq!(*open_meta(rk, folder, device, 1, &sealed).expect("and opens"), *meta);
    }
});
