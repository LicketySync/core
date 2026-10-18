#![no_main]
//! A recovery phrase as a person types it.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::phrase::Phrase;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(phrase) = Phrase::parse(text) {
            let _ = phrase.to_text();
        }
    }
});
