#![no_main]
//! Key records from a peer: each input is a sequence of `be32(len) || bytes`
//! envelopes, decoded by `SignedRecord::from_bytes` and inserted in order into
//! a fresh copy of one folder's store (the test vectors' folder: the same
//! body, signed hedged under a fixed randomness, so no `test-vectors`
//! feature is needed), then asked the validity questions an insertion and a
//! handshake ask.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::derive::FolderNonce;
use licketysync_keys::records::{create_folder, FolderGenesis, FolderKeys, SignedRecord};
use licketysync_keys::{DataKey, MasterSecret, Tier};

const NOW: u64 = 1_800_000_000;

fn base() -> &'static FolderKeys {
    static BASE: OnceLock<FolderKeys> = OnceLock::new();
    BASE.get_or_init(|| {
        let ms = MasterSecret::from_bytes([1; 32]);
        let dk = DataKey::from_bytes([2; 32]);
        let genesis = FolderGenesis {
            master: &ms,
            nonce: FolderNonce([3; 32]),
            data_key: &dk,
            created_at: 1_700_000_000,
            required_features: vec![],
        };
        let folder = create_folder(&genesis, &mut |b: &mut [u8]| b.fill(3))
            .expect("the vectors' folder");
        FolderKeys::new(&folder.body.folder_id, folder.record).expect("its own record")
    })
}

fuzz_target!(|data: &[u8]| {
    let mut keys = base().clone();
    let mut rest = data;
    let mut stored = Vec::new();
    while let Some((len, tail)) = rest.split_first_chunk::<4>() {
        let len = u32::from_be_bytes(*len) as usize;
        let Some((record, tail)) = tail.split_at_checked(len.min(tail.len())) else {
            break;
        };
        rest = tail;
        if let Ok(record) = SignedRecord::from_bytes(record) {
            if keys.insert(&record, NOW).is_ok() {
                stored.push(record.hash());
            }
        }
    }
    let v = keys.validity(NOW);
    for (_, record) in keys.records() {
        if let Ok(prefix) = record.prefix() {
            let _ = prefix;
        }
    }
    for hash in &stored {
        let _ = v.is_grant_valid(hash);
    }
    let ids: Vec<_> = keys
        .records()
        .filter_map(|(_, r)| licketysync_keys::records::GrantBody::parse(&r.body).ok())
        .map(|g| g.key_id)
        .collect();
    for id in &ids {
        let _ = v.governing_grant(id);
        let _ = v.canonical_chain(id);
        let _ = v.presentable_chain(id);
        let _ = v.ancestors(id);
        let _ = v.may_issue(id, Tier::Read);
        let _ = v.effective_tier(id);
    }
});
