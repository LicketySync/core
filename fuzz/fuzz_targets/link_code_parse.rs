#![no_main]
//! A device-link code as a person types it.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::linking::LinkCode;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(code) = LinkCode::parse(text) {
            let _ = code.to_text(false);
        }
    }
});
