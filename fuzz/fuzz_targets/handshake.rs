#![no_main]
//! The connection state machine fed a peer's bytes. The first byte picks the
//! mode. Even: a fresh connection receives the rest as the peer's whole
//! stream (Hello, DeviceProof, anything). Odd: the odd mode of
//! `crates/protocol/src/vectors/handshake_harness.rs`, included below and
//! shared with the protocol crate's test `vector_exchange_fuzz_seeds`, which
//! writes the seeds that start inside the exchange: two real connections
//! complete the handshake and open the folder, and the first receives the
//! rest as the second's further bytes in pieces (pages, pushes, requests,
//! chunks, Status, unknown types, split anywhere), answering from an index
//! the mode's bits describe. Nothing may panic, every frame handed over must
//! fit the peer's limit, and time moves on through the connection's
//! wake-ups.
use libfuzzer_sys::fuzz_target;
use licketysync_protocol as protocol;

include!("../../crates/protocol/src/vectors/handshake_harness.rs");

/// Checks that every frame of `out` fits `limit`, and joins them.
fn bytes(out: &Output, limit: u32) -> Vec<u8> {
    let mut all = Vec::new();
    for f in &out.frames {
        assert!(f.len() - 4 <= limit as usize, "a frame over the peer's limit");
        all.extend_from_slice(f);
    }
    all
}

/// The odd mode's checks: every frame handed over fits the peer's limit.
struct Limits;

impl Watch for Limits {
    fn event(&mut self, _: &Event) {}

    fn handed(&mut self, from: &Connection, out: &Output, _: Stage) {
        let _ = bytes(out, from.peer_max_message_size());
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 1 {
        odd_mode(mode, rest, &mut Limits);
        return;
    }
    let (ka, ia) = device(0xa0);
    let creds = [FolderCredential::new(&folder().expect("the fixed folder"))];
    let mut fill = |b: &mut [u8]| b.fill(3);
    let keys_a = Keys { device: &ka, folders: &creds };
    let t0 = Tick::default();
    let (mut a, _) = Connection::new(&ka, Config::new(ia, 20_751), &mut fill, t0).expect("valid config");
    let out = a.receive(&keys_a, &mut fill, t0, rest);
    let _ = bytes(&out, a.peer_max_message_size());
    if let Some(at) = out.wake_at {
        let _ = a.wake(Tick::at(at));
    }
});
