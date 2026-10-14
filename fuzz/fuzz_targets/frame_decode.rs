#![no_main]
//! Fuzz target placeholder for the wire framing decoder. It is replaced by the
//! real decoder in phase 0; until then it exercises the crate boundary.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = licketysync_protocol::CRATE.len() + data.len();
});
