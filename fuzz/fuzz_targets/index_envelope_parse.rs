#![no_main]
//! An index record's envelope from a peer: decoded by
//! `SignedRecord::from_bytes` and, when it decodes, verified under the test
//! vectors' folder (write secret `10 11 .. 2f`). What decodes keeps its body
//! byte for byte and encodes to an envelope that decodes to the same record.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::{FolderVerifier, SignedRecord, Suite, WriteKey, WriteSecret};

fn folder() -> &'static FolderVerifier {
    static FOLDER: OnceLock<FolderVerifier> = OnceLock::new();
    FOLDER.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        *WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws))
            .expect("suite 1")
            .verifier()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = SignedRecord::from_bytes(data) {
        // The canonical form drops unknown envelope fields and never grows.
        let bytes = record.to_bytes();
        assert!(bytes.len() <= data.len());
        // A body holds at least its record type, and is the input's own bytes.
        assert!(!record.body().is_empty());
        assert!(data.windows(record.body().len()).any(|w| w == record.body()));
        assert_eq!(SignedRecord::from_bytes(&bytes), Ok(record.clone()));
        let _ = record.hash();
        let _ = folder().verify_index_record(&record);
    }
});
