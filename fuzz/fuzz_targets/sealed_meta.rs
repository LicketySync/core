#![no_main]
//! Opened sealed metadata (`SealedMeta`, `protocol.md` 4.4 step 6): the
//! bounded decoder and the path grammar.
use libfuzzer_sys::fuzz_target;
use licketysync_protocol::messages::SealedMeta;
use licketysync_protocol::record::check_path;
use licketysync_protocol::Parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(meta) = SealedMeta::parse(data) {
        let _ = check_path(&meta.path);
    }
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = check_path(text);
    }
});
