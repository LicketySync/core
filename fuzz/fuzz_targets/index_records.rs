#![no_main]
//! `IndexRecords` bodies from a peer and the keys crate's envelope decoder
//! (keys review ruling SF6). Two checks: the input as a page, every embedded
//! record of which the keys crate's `SignedRecord::from_bytes` must accept and
//! step 1 then judges for the test vectors' folder; and the input as one
//! embedded record, which the page decoder must accept exactly when
//! `SignedRecord::from_bytes` does.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::{FolderVerifier, Suite, WriteKey, WriteSecret};
use licketysync_protocol::messages::IndexRecords;
use licketysync_protocol::record::Record;
use licketysync_protocol::Parse;
use prost::Message as _;

fn verifier() -> &'static FolderVerifier {
    static V: OnceLock<FolderVerifier> = OnceLock::new();
    V.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        *WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1").verifier()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(page) = IndexRecords::parse(data) {
        for raw in &page.records {
            let envelope = SignedRecord::from_bytes(raw);
            assert!(envelope.is_ok(), "the page decoder accepted what keys refuses");
            let _ = Record::from_bytes(raw, verifier());
        }
    }
    let one = IndexRecords {
        folder_id: vec![1; 32],
        records: vec![data.to_vec()],
        more: false,
        request_id: 0,
    }
    .encode_to_vec();
    assert_eq!(
        IndexRecords::parse(&one).is_ok(),
        SignedRecord::from_bytes(data).is_ok(),
        "the page decoder and keys' envelope decoder disagree"
    );
});
