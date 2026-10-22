#![no_main]
//! The write key's 24 words as a person types them. What parses writes back
//! to 24 lower-case words that parse to the same key.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::WriteKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(key) = WriteKey::from_words(text) {
            let words = key.to_words().expect("a write key has words");
            assert_eq!(words.split(' ').count(), 24);
            assert_eq!(words.to_ascii_lowercase(), *words);
            let again = WriteKey::from_words(&words).expect("its words parse");
            assert!(bool::from(again.secret().ct_eq(key.secret())));
            assert_eq!(again.verifier(), key.verifier());
        }
    }
});
