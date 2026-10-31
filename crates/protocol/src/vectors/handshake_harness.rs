// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// The odd mode of the fuzz target `handshake`, one copy for two users, each
// of which brings it in with `include!`: the target itself
// (`fuzz/fuzz_targets/handshake.rs`) and this crate's test
// `vector_exchange_fuzz_seeds`, which writes the target's seeds that start
// inside the exchange and checks what they reach through it. The includer
// names this crate `protocol` in the scope it includes into
// (`use crate as protocol;` here, `use licketysync_protocol as protocol;` in
// the target).
//
// Two real connections (device seeds a0 and b0, the keys crate's folder,
// write secret 10 11 .. 2f) complete the handshake and open the folder, the
// first sends the round due on open, and then it receives `rest` as the
// second's further bytes in pieces, each a two-byte big-endian length and
// that many bytes, 1.5 s apart. Its engine judges every record handed over
// as held, sends every request that falls due, and serves the second's
// requests from a `View`. Nothing here panics: a connection's error is an
// output like any other, and were the fixed keys or configuration refused,
// the run would do nothing, which the seeds test would show.

use core::time::Duration;

use licketysync_keys::device::{DeviceKey, Libp2pIdentity};
use licketysync_keys::folder::FolderKey;
use licketysync_keys::secret::{DeviceSeed, WriteSecret};
use licketysync_keys::{DeviceId, FolderId, SetDigest, Suite, WriteKey};
use protocol::connection::{
    Config, Connection, Event, Judgement, Keys, Output, ReconcileServe, Tick,
};
use protocol::exchange::{reconcile_outcome, IndexView, Prefix};
use protocol::messages::{IndexRecords, ReconcileOutcome, ReconcileReply};
use protocol::proof::FolderCredential;

/// The epoch of the first side's index.
const EPOCH: u64 = 5;

/// The first side's index: its digests (zero, or not zero and differing by
/// prefix), its record count, and its stored cursor for the second. Bit 1 of
/// the mode gives digests that are not zero (so that `CHILDREN` replies are
/// allowed) and, when bit 3 is set too, more records than a leaf holds (so
/// that it answers `CHILDREN`); bit 2 gives a stored cursor for the second,
/// epoch 7 at 0, so that its round asks Since first.
struct View {
    salt: Option<u8>,
    many: bool,
    cursor: Option<(u64, u64)>,
}

impl View {
    fn of(mode: u8) -> Self {
        Self {
            salt: (mode & 2 != 0).then_some(mode | 1),
            many: mode & 0b1010 == 0b1010,
            cursor: (mode & 4 != 0).then_some((7, 0)),
        }
    }

    fn count(&self) -> usize {
        if self.many {
            65
        } else {
            0
        }
    }
}

impl IndexView for View {
    fn digest(&self, prefix: &Prefix) -> SetDigest {
        let Some(salt) = self.salt else {
            return SetDigest::EMPTY;
        };
        let mut d = [salt; 32];
        for (i, n) in prefix.nibbles().enumerate() {
            d[i % 31] ^= n.wrapping_add(u8::try_from(i % 256).unwrap_or(0));
        }
        d[31] = u8::try_from(prefix.depth()).unwrap_or(0);
        SetDigest(d)
    }

    fn peer_cursor(&self, _: &DeviceId) -> Option<(u64, u64)> {
        self.cursor
    }
}

/// When an output was handed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// The second side's, during the handshake.
    Second,
    /// The first side's replies to the second's handshake bytes.
    Handshake,
    /// The first side's answers to its events (from the round due on open
    /// on) and its replies to the stream and to its wake-ups.
    Exchange,
}

/// What a run shows its user.
trait Watch {
    /// An event of the first side, before it is answered.
    fn event(&mut self, e: &Event);
    /// An output handed over by `from`, before its own events are answered.
    fn handed(&mut self, from: &Connection, out: &Output, stage: Stage);
}

/// The fixed device of `seed`: its key and its libp2p public key.
fn device(seed: u8) -> (DeviceKey, [u8; 32]) {
    let s = DeviceSeed::from_bytes(core::array::from_fn(|i| {
        seed.wrapping_add(u8::try_from(i).unwrap_or(0))
    }));
    (
        DeviceKey::from_device_seed(&s),
        Libp2pIdentity::from_device_seed(&s).public_key(),
    )
}

/// The keys crate's folder, write secret `10 11 .. 2f`.
fn folder() -> Option<FolderKey> {
    let ws = core::array::from_fn(|i| 0x10u8.wrapping_add(u8::try_from(i).unwrap_or(0)));
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws))
        .ok()
        .map(FolderKey::from)
}

/// A page of no records for the second's request `request_id`.
fn empty_page(folder: &FolderId, request_id: u32) -> IndexRecords {
    IndexRecords {
        folder_id: folder.0.to_vec(),
        records: vec![],
        more: false,
        request_id,
        epoch: EPOCH,
        through: 0,
        reset: false,
    }
}

/// The reply to the second's `ReconcileRequest`, from the view, and its one
/// empty page after `RECORDS`.
fn serve_reconcile(
    a: &mut Connection,
    tick: Tick,
    view: &View,
    folder: FolderId,
    r: &ReconcileServe,
) -> Vec<Output> {
    let own = view.digest(&r.prefix);
    let outcome = reconcile_outcome(r.prefix.depth(), &r.digest, &own, view.count());
    let children = if outcome == ReconcileOutcome::Children {
        (0..16u8)
            .filter_map(|n| r.prefix.child(n))
            .map(|c| view.digest(&c).0.to_vec())
            .collect()
    } else {
        vec![]
    };
    let reply = ReconcileReply {
        folder_id: folder.0.to_vec(),
        request_id: r.request_id,
        outcome: outcome.as_u32(),
        children,
        epoch: EPOCH,
        through: 0,
    };
    let mut outs = Vec::new();
    if let Ok(out) = a.send_reconcile_reply(tick, &reply) {
        outs.push(out);
        if outcome == ReconcileOutcome::Records {
            outs.extend(a.send_page(tick, &empty_page(&folder, r.request_id)).ok());
        }
    }
    outs
}

/// The engine's answers to `a`'s events: requests sent, records judged
/// held, the second's requests served. Each answer's frames go to `to_b`.
fn react(
    a: &mut Connection,
    tick: Tick,
    view: &View,
    events: Vec<Event>,
    to_b: &mut Vec<u8>,
    watch: &mut dyn Watch,
) {
    for e in events {
        watch.event(&e);
        let outs = match e {
            Event::RequestDue { folder } => a
                .send_request(tick, folder, view)
                .ok()
                .into_iter()
                .collect(),
            Event::Records {
                folder,
                records,
                page,
            } => {
                let held = vec![Ok(Judgement::Held); records.len()];
                vec![a.judged(tick, folder, page, &held)]
            }
            Event::ServeIndex { folder, request } => {
                let out = if request.epoch == EPOCH && request.since == 0 {
                    a.send_page(tick, &empty_page(&folder, request.request_id))
                } else {
                    a.send_reset(tick, folder, request.request_id, EPOCH, false)
                };
                out.ok().into_iter().collect()
            }
            Event::ServeReconcile { folder, request } => {
                serve_reconcile(a, tick, view, folder, &request)
            }
            _ => Vec::new(),
        };
        for out in outs {
            watch.handed(a, &out, Stage::Exchange);
            to_b.extend(out.frames.concat());
            react(a, tick, view, out.events, to_b, watch);
        }
    }
}

/// Runs the odd mode `mode` over `rest`, the stream after the mode byte.
fn odd_mode(mode: u8, mut rest: &[u8], watch: &mut dyn Watch) {
    let (ka, ia) = device(0xa0);
    let (kb, ib) = device(0xb0);
    let Some(folder) = folder() else {
        return;
    };
    let creds = [FolderCredential::new(&folder)];
    let mut fill = |b: &mut [u8]| b.fill(3);
    let keys_a = Keys {
        device: &ka,
        folders: &creds,
    };
    let keys_b = Keys {
        device: &kb,
        folders: &creds,
    };
    let t0 = Tick::default();
    let view = View::of(mode);
    let Ok((mut a, out_a)) = Connection::new(&ka, Config::new(ia, 20_751), &mut fill, t0) else {
        return;
    };
    let Ok((mut b, out_b)) = Connection::new(&kb, Config::new(ib, 20_751), &mut fill, t0) else {
        return;
    };
    let mut to_b = out_a.frames.concat();
    let mut to_a = out_b.frames.concat();
    let id = creds[0].folder_id();
    let mut proved = false;
    for _ in 0..8 {
        let oa = a.receive(&keys_a, &mut fill, t0, &core::mem::take(&mut to_a));
        let ob = b.receive(&keys_b, &mut fill, t0, &core::mem::take(&mut to_b));
        watch.handed(&a, &oa, Stage::Handshake);
        watch.handed(&b, &ob, Stage::Second);
        to_b.extend(oa.frames.concat());
        to_a.extend(ob.frames.concat());
        if !proved && a.peer().is_some() && b.peer().is_some() {
            if let Ok(out) = b.prove(&keys_b, &mut fill, t0, id) {
                watch.handed(&b, &out, Stage::Second);
                to_a.extend(out.frames.concat());
                proved = true;
            }
        }
        react(&mut a, t0, &view, oa.events, &mut to_b, watch);
    }
    let mut sink = Vec::new();
    let mut now = Duration::ZERO;
    while !rest.is_empty() {
        let len = match rest {
            [hi, lo, ..] => usize::from(u16::from_be_bytes([*hi, *lo])),
            _ => rest.len(),
        };
        let body = rest.get(2..).unwrap_or(&[]);
        let (piece, after) = body.split_at(len.min(body.len()));
        rest = after;
        now += Duration::from_millis(1500);
        let out = a.receive(&keys_a, &mut fill, Tick::at(now), piece);
        watch.handed(&a, &out, Stage::Exchange);
        react(&mut a, Tick::at(now), &view, out.events, &mut sink, watch);
        if let Some(at) = out.wake_at {
            let woke = a.wake(Tick::at(at));
            watch.handed(&a, &woke, Stage::Exchange);
            react(&mut a, Tick::at(at), &view, woke.events, &mut sink, watch);
        }
        sink.clear();
    }
}
