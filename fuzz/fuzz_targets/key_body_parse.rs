#![no_main]
//! Every key-record body parser on bytes from a peer; the first byte picks
//! the parser.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::records::{
    FolderBody, GrantBody, LiftBody, RevocationBody, RotationBody, SuspensionBody, WrapBody,
};

fuzz_target!(|data: &[u8]| {
    let Some((which, body)) = data.split_first() else {
        return;
    };
    match which % 7 {
        0 => drop(FolderBody::parse(body)),
        1 => drop(GrantBody::parse(body)),
        2 => drop(RotationBody::parse(body)),
        3 => drop(WrapBody::parse(body)),
        4 => drop(RevocationBody::parse(body)),
        5 => drop(SuspensionBody::parse(body)),
        _ => drop(LiftBody::parse(body)),
    }
});
