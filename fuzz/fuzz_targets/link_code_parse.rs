#![no_main]
//! A device-link code as a person types it. What parses is its own text, in
//! one case.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::linking::LinkCode;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(code) = LinkCode::parse(text) {
            assert_eq!(*code.to_text(false), text.to_ascii_lowercase());
            let again = LinkCode::parse(&code.to_text(true)).expect("its own text parses");
            assert_eq!(again.device_id, code.device_id);
            assert!(bool::from(again.secret.ct_eq(&code.secret)));
        }
    }
});
