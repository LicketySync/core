#![no_main]
//! A sealed part from a peer, opened under the test vectors' folder (write
//! secret `10 11 .. 2f`) by the keys crate's reader (`keys.md` 3.4), as an
//! index record's sealed part at the vectors' path tag (of `docs/report.txt`)
//! and as a cleanup's: a length its kind does not allow is refused as
//! malformed before anything is decrypted (`SealedKind::is_sealed_len`); what
//! opens fills exactly the least bucket, does not open as the other kind
//! (whose aad differs), and seals again, under the same nonce and place, to
//! the very bytes it came from.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::sealed_meta::{bucket, MetaError, RecordKeys, SealedKind, MIN_SEALED_BYTES};
use licketysync_keys::{PathTag, Suite, WriteKey, WriteSecret};

struct Place {
    keys: RecordKeys,
    tag: PathTag,
}

fn place() -> &'static Place {
    static PLACE: OnceLock<Place> = OnceLock::new();
    PLACE.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        let keys = w.record_keys();
        Place {
            tag: keys.path_tag("docs/report.txt"),
            keys,
        }
    })
}

/// One kind's reader on `data`, with the properties the module names.
fn reader(p: &Place, kind: SealedKind, data: &[u8]) {
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
    reader(p, SealedKind::Index, data);
    reader(p, SealedKind::Cleanup, data);
});
