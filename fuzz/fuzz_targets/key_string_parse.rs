#![no_main]
//! A key string as a person pastes it.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::keystring::KeyString;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(key) = KeyString::parse(text) {
            let _ = key.to_text();
        }
    }
});
