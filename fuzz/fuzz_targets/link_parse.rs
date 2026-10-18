#![no_main]
//! A link and a `.lskey` file, and the bundle a link carries, verified.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::keystring::Link;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for link in [Link::parse(text), Link::parse_file(text)].into_iter().flatten() {
            let _ = link.verify_bundle(1_800_000_000);
            let _ = link.to_text();
        }
    }
});
