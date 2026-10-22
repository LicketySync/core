#![no_main]
//! An encoded `SignedRecord` from a peer through steps 1 to 6 of
//! `protocol.md` 4.4 under the test vectors' folder (write secret
//! `10 11 .. 2f`): step 1, steps 2 to 5 against an index holding nothing (and
//! one holding the record), and the seal for a write holder.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::{DeviceId, RecordHash, Suite, WriteKey, WriteSecret};
use licketysync_protocol::record::{judge, Arrival, Held, Record};

fn key() -> &'static WriteKey {
    static K: OnceLock<WriteKey> = OnceLock::new();
    K.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1")
    })
}

struct Index(Option<(RecordHash, DeviceId, u64)>);

impl Held for Index {
    fn holds(&self, record: &RecordHash) -> bool {
        self.0.is_some_and(|(h, _, _)| h == *record)
    }
    fn cursor(&self, writer: &DeviceId) -> u64 {
        self.0.filter(|(_, d, _)| d == writer).map_or(0, |(_, _, s)| s)
    }
}

fuzz_target!(|data: &[u8]| {
    let key = key();
    let Ok(record) = Record::from_bytes(data, key.verifier()) else {
        return;
    };
    assert_eq!(record.hash(), record.signed().hash());
    for arrival in [Arrival::Push, Arrival::Reply { in_scope: true }, Arrival::Reply { in_scope: false }] {
        let _ = judge(&record, arrival, &Index(None), key.verifier());
    }
    let held = Index(Some((record.hash(), record.device_id(), record.seq())));
    let again = judge(&record, Arrival::Push, &held, key.verifier());
    assert_eq!(again, Ok(licketysync_protocol::record::Judgement::Duplicate));
    let _ = record.open(key.data_key());
});
