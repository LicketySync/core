#![no_main]
//! A sealed part from a peer, opened under the test vectors' folder (write
//! secret `10 11 .. 2f`) by both readers of the keys crate.
//!
//! - The layout of `keys.md` 3.4 since 2026-10-25, as an index record's
//!   sealed part at the vectors' path tag (of `docs/report.txt`) and as a
//!   cleanup's: a length its kind does not allow is refused as malformed
//!   before anything is decrypted (`SealedKind::is_sealed_len`); what opens
//!   fills exactly the least bucket, does not open as the other kind (whose
//!   aad differs), and seals again, under the same nonce and place, to the
//!   very bytes it came from.
//! - The old layout, kept for one commit of the series that replaces it, as a
//!   record of the vectors' device (device seed `a0 a1 .. bf`) at sequence 1:
//!   what opens fits the sealed part it came from and seals again, under the
//!   same nonce, to a part that opens to it.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::device::DeviceKey;
use licketysync_keys::sealed_meta::{
    bucket, open_meta, seal_meta, MetaError, RecordKeys, SealedKind, MIN_SEALED_BYTES,
};
use licketysync_keys::secret::{DeviceSeed, RecordKey};
use licketysync_keys::{DeviceId, FolderId, PathTag, Suite, WriteKey, WriteSecret};

struct Place {
    keys: RecordKeys,
    tag: PathTag,
    rk: RecordKey,
    folder: FolderId,
    device: DeviceId,
}

fn place() -> &'static Place {
    static PLACE: OnceLock<Place> = OnceLock::new();
    PLACE.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        let seed: [u8; 32] = core::array::from_fn(|i| 0xa0 + i as u8);
        let device = DeviceKey::from_device_seed(&DeviceSeed::from_bytes(seed)).device_id();
        let keys = w.record_keys();
        Place {
            tag: keys.path_tag("docs/report.txt"),
            keys,
            rk: w.data_key().record_key(),
            folder: w.verifier().folder_id(),
            device,
        }
    })
}

/// One kind's reader on `data`, with the properties the module names.
fn new_reader(p: &Place, kind: SealedKind, data: &[u8]) {
    let open = |bytes: &[u8]| match kind {
        SealedKind::Index => p.keys.open_index_meta(&p.tag, bytes),
        SealedKind::Cleanup => p.keys.open_cleanup_meta(bytes),
    };
    let other = |bytes: &[u8]| match kind {
        SealedKind::Index => p.keys.open_cleanup_meta(bytes),
        SealedKind::Cleanup => p.keys.open_index_meta(&p.tag, bytes),
    };
    let result = open(data);
    if !kind.is_sealed_len(data.len()) {
        assert_eq!(result, Err(MetaError::SealedLength(data.len())));
        return;
    }
    let Ok(meta) = result else {
        return;
    };
    assert_eq!(
        bucket(meta.len()).map(|b| b + MIN_SEALED_BYTES),
        Some(data.len())
    );
    assert!(other(data).is_err(), "one aad per kind");
    let nonce = *data
        .first_chunk::<24>()
        .expect("a sealed part has its nonce");
    let mut fill = |b: &mut [u8]| b.copy_from_slice(&nonce);
    let sealed = match kind {
        SealedKind::Index => p.keys.seal_index_meta(&p.tag, &meta, &mut fill),
        SealedKind::Cleanup => p.keys.seal_cleanup_meta(&meta, &mut fill),
    }
    .expect("metadata that opened seals");
    assert_eq!(
        sealed, data,
        "the least bucket and zero padding: one sealed form"
    );
}

fuzz_target!(|data: &[u8]| {
    let p = place();
    new_reader(p, SealedKind::Index, data);
    new_reader(p, SealedKind::Cleanup, data);
    // The old layout, removed with its reader in the next commit.
    if let Ok(meta) = open_meta(&p.rk, &p.folder, &p.device, 1, data) {
        assert!(meta.len() + 4 + MIN_SEALED_BYTES <= data.len());
        let nonce = data
            .first_chunk::<24>()
            .expect("a sealed part has its nonce");
        let sealed = seal_meta(&p.rk, &p.folder, &p.device, 1, &meta, &mut |b| {
            b.copy_from_slice(nonce)
        })
        .expect("metadata that opened seals");
        assert_eq!(
            *open_meta(&p.rk, &p.folder, &p.device, 1, &sealed).expect("and opens"),
            *meta
        );
    }
});
