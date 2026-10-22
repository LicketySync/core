#![no_main]
//! A folder key as the local key store keeps it, `u8(tier) || payload`.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::FolderKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = FolderKey::from_stored(data) {
        assert_eq!(&*key.to_stored(), data);
    }
});
