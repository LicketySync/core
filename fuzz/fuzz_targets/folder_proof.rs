#![no_main]
//! A peer's `FolderProof` body, parsed and opened (`protocol.md` 3.5 steps 1,
//! 3 and 4) under the test vectors' folder (write secret `10 11 .. 2f`) and
//! transcript hash `70 71 .. 8f`, as the prover of either role.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::folder::FolderKey;
use licketysync_keys::{Role, Suite, WriteKey, WriteSecret};
use licketysync_protocol::hello::TranscriptHash;
use licketysync_protocol::messages::FolderProof;
use licketysync_protocol::proof::FolderCredential;
use licketysync_protocol::Parse;

fn credential() -> &'static FolderCredential {
    static C: OnceLock<FolderCredential> = OnceLock::new();
    C.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let key = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        FolderCredential::new(&FolderKey::from(key))
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(proof) = FolderProof::parse(data) else {
        return;
    };
    let th = TranscriptHash(core::array::from_fn(|i| 0x70 + i as u8));
    for role in [Role::A, Role::B] {
        let _ = credential().open(&th, role, &proof);
    }
});
