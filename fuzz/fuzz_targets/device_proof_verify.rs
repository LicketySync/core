#![no_main]
//! A peer's Hello device key and device proof: `device_public_key (34) ||
//! signature (64) || th (32) || role (1)`, parsed and verified. A key that
//! parses writes back to the same 34 bytes and parses again to itself.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::device::DevicePublicKey;
use licketysync_keys::{Role, Signature};

fuzz_target!(|data: &[u8]| {
    let Some((key_bytes, rest)) = data.split_at_checked(34) else {
        return;
    };
    let Ok(key) = DevicePublicKey::from_hello(key_bytes) else {
        return;
    };
    assert_eq!(&key.to_hello()[..], key_bytes);
    assert_eq!(DevicePublicKey::from_hello(&key.to_hello()), Ok(key));
    let _ = key.device_id();
    let Some((sig, rest)) = rest.split_at_checked(64) else {
        return;
    };
    let (Some(sig), Some((th, role))) =
        (Signature::from_slice(sig), rest.split_first_chunk::<32>())
    else {
        return;
    };
    let role = if role.first() == Some(&2) {
        Role::B
    } else {
        Role::A
    };
    let _ = key.verify_device_proof(th, role, &sig);
});
