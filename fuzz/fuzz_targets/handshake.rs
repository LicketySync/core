#![no_main]
//! The connection state machine fed a peer's bytes. The first byte picks the
//! mode: even, a fresh connection receives the rest as the peer's whole
//! stream (Hello, DeviceProof, anything); odd, two real connections (device
//! seeds a0 and b0, the test vectors' folder) complete the handshake and open
//! the folder, the first sends the round due on open, and then receives the
//! rest as the second's further bytes (pages, pushes, requests, chunks,
//! Status, unknown types), split where the second byte says. Nothing may
//! panic, every frame handed over must fit the peer's limit, and time moves
//! on through the connection's wake-ups.
use core::time::Duration;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::device::{DeviceKey, Libp2pIdentity};
use licketysync_keys::folder::FolderKey;
use licketysync_keys::secret::{DeviceSeed, WriteSecret};
use licketysync_keys::{Suite, WriteKey};
use licketysync_protocol::connection::{Config, Connection, Event, Keys, Output, Tick};
use licketysync_protocol::exchange::WriterCursor;
use licketysync_protocol::proof::FolderCredential;

fn device(seed: u8) -> (DeviceKey, [u8; 32]) {
    let s = DeviceSeed::from_bytes(core::array::from_fn(|i| seed.wrapping_add(i as u8)));
    (DeviceKey::from_device_seed(&s), Libp2pIdentity::from_device_seed(&s).public_key())
}

fn folder() -> FolderKey {
    let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
    FolderKey::from(WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1"))
}

fn bytes(out: &Output, limit: u32) -> Vec<u8> {
    let mut all = Vec::new();
    for f in &out.frames {
        assert!(f.len() - 4 <= limit as usize, "a frame over the peer's limit");
        all.extend_from_slice(f);
    }
    all
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let (ka, ia) = device(0xa0);
    let (kb, ib) = device(0xb0);
    let creds = [FolderCredential::new(&folder())];
    let mut fill = |b: &mut [u8]| b.fill(3);
    let keys_a = Keys { device: &ka, folders: &creds };
    let keys_b = Keys { device: &kb, folders: &creds };
    let t0 = Tick::default();
    let (mut a, out_a) = Connection::new(&ka, Config::new(ia), &mut fill, t0).expect("valid config");
    if mode % 2 == 0 {
        let out = a.receive(&keys_a, &mut fill, t0, rest);
        let _ = bytes(&out, a.peer_max_message_size());
        if let Some(at) = out.wake_at {
            let _ = a.wake(Tick::at(at));
        }
        return;
    }
    let (mut b, out_b) = Connection::new(&kb, Config::new(ib), &mut fill, t0).expect("valid config");
    let mut to_b = bytes(&out_a, u32::MAX);
    let mut to_a = bytes(&out_b, u32::MAX);
    let id = creds[0].folder_id();
    let mut proved = false;
    for _ in 0..8 {
        let oa = a.receive(&keys_a, &mut fill, t0, &core::mem::take(&mut to_a));
        let ob = b.receive(&keys_b, &mut fill, t0, &core::mem::take(&mut to_b));
        to_b.extend(bytes(&oa, a.peer_max_message_size()));
        to_a.extend(bytes(&ob, b.peer_max_message_size()));
        if !proved && a.peer().is_some() && b.peer().is_some() {
            if let Ok(out) = b.prove(&keys_b, &mut fill, t0, id) {
                to_a.extend(bytes(&out, b.peer_max_message_size()));
                proved = true;
            }
        }
        for e in oa.events {
            if let Event::RequestDue { folder, .. } = e {
                let none: &[WriterCursor] = &[];
                if let Ok(out) = a.send_request(t0, folder, none) {
                    to_b.extend(bytes(&out, a.peer_max_message_size()));
                }
            }
        }
    }
    let cut = rest.first().map_or(0, |c| usize::from(*c) % (rest.len() + 1));
    let mut now = Duration::ZERO;
    for piece in [&rest[..cut], &rest[cut..]] {
        now += Duration::from_millis(1500);
        let out = a.receive(&keys_a, &mut fill, Tick::at(now), piece);
        let _ = bytes(&out, a.peer_max_message_size());
        if let Some(at) = out.wake_at {
            let _ = bytes(&a.wake(Tick::at(at)), a.peer_max_message_size());
        }
    }
});
