#![no_main]
//! A key string as a person pastes it, of any tier.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::FolderKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(key) = FolderKey::from_key_string(text) {
            assert_eq!(*key.to_key_string(), text.to_ascii_lowercase());
        }
    }
});
