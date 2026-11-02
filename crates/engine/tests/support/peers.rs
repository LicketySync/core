// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Scripted peers beside the honest [`Member`]s: an [`Adversary`], a real
//! protocol [`Connection`] with real keys that carries out one [`Attack`],
//! and an outsider, a member whose received frames a [`Sniffer`] reads, so
//! that a test can see what crossed. One [`TestPeer`] type holds all three,
//! since a simulation runs one peer type.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

use core::cell::RefCell;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::runtime::{Context, Instant, Peer, PeerId, TimerId};
use licketysync_keys::chunk::{seal_chunk, PlainHash};
use licketysync_keys::device::{DeviceKey, Libp2pIdentity};
use licketysync_keys::records::SignedRecord;
use licketysync_keys::secret::{DeviceSeed, WriteSecret};
use licketysync_keys::SetDigest;
use licketysync_keys::{CipherHash, DeviceId, FolderId, FolderKey, RecordHash, Suite, WriteKey};
use licketysync_protocol::connection::{
    ChunkAnswer, Config, Connection, Event, Judgement, Keys, Output, Tick,
};
use licketysync_protocol::exchange::{reconcile_outcome, Pager};
use licketysync_protocol::frame::{FrameDecoder, FrameKind, MessageType};
use licketysync_protocol::limits::{MAX_MESSAGE_SIZE, MAX_PAGE_RECORDS, TOMBSTONE_HORIZON};
use licketysync_protocol::messages::{
    ChunkReply, ChunkRequest, FolderStatus, IndexRecords, Message, ReconcileOutcome, ReconcileReply,
};
use licketysync_protocol::proof::FolderCredential;
use licketysync_protocol::record::{Applied, Chunk, Dot, IndexDraft, Kind, Meta, Record, Vector};
use licketysync_protocol::{CloseReason, Parse};
use licketysync_sim::member::Member;

/// The write secret of the folder every test syncs.
pub(crate) const FOLDER_A: [u8; 32] = [0x10; 32];
/// The write secret of a second folder.
pub(crate) const FOLDER_B: [u8; 32] = [0x11; 32];

/// A write key from its secret.
pub(crate) fn write_key(secret: [u8; 32]) -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(secret)).unwrap()
}

/// What an adversary does (the brief's 13.5, items 1 to 9 as the port brief
/// changes them, the review's E2, and the port brief's three new attacks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Attack {
    /// 1: pushes a record with one bit flipped inside its body.
    FlippedBody,
    /// 2: pushes a body of the folder signed with another folder's write key,
    /// all a read holder can produce.
    OtherFolderKey,
    /// 4: pushes a validly signed record whose sealed metadata is garbage,
    /// naming a chunk it serves.
    GarbageSeal,
    /// 5: pushes a record whose chunk has the right ciphertext hash and a
    /// seal that will not open, and serves that chunk.
    CorruptChunk,
    /// 5 beside 4: pushes an applied record whose chunk does not open for
    /// it and an opaque record naming the same chunk by its stored length,
    /// which keeps it (the security review's probe N3), and serves it.
    CorruptBesideOpaque,
    /// Pushes a record whose chunk opens for it but whose size is not the
    /// chunk's plaintext length, and serves the chunk.
    WrongSize,
    /// 6: pushes a record naming a stored length other than its chunk's.
    StoredLenMismatch,
    /// 7: sends a `ChunkReply` nobody asked for.
    UnsolicitedReply,
    /// 7: sends more chunk requests than the peer advertised.
    TooManyRequests,
    /// E2: takes chunk requests and never answers them, so that each hash
    /// it was asked for would wait on it for as long as it stays connected.
    Silent,
    /// 3, which the new design changes (there are no gaps): pushes two
    /// records under its own device ID whose counters lie 1 000 s apart, the
    /// later first.
    CounterJump,
    /// 8: on the first record of member 0's it sees, pushes a twin under the
    /// same dot (equivocation) and a record under member 0's device ID above
    /// member 0's high-water mark.
    HonestId,
    /// 9: pushes a record naming a chunk nobody holds.
    UnknownHash,
    /// Pushes, in one page, records of the deepest paths the grammar allows
    /// (4 095 bytes, 2 048 components), each with a forged signature.
    DeepPath,
    /// Once a member has sent it records, replays to it a tree delete of
    /// `p0` whose counter the folder's own time has passed by more than the
    /// deletion horizon: genuinely signed, or with its signature forged.
    ExpiredTreeDelete {
        /// The signature is forged.
        forged: bool,
    },
    /// Keeps every record pushed to it and, at [`REPLAY_AT`], pushes them
    /// all back (a sealed peer replaying the folder's history).
    ReplayHistory,
}

/// When [`Attack::ReplayHistory`] replays what it kept.
pub(crate) const REPLAY_AT: Instant = Instant::from_secs(10);

/// The deepest path the grammar allows, ending in `leaf`: 2 048 components
/// in 4 095 bytes.
pub(crate) fn deep_path(leaf: char) -> String {
    let mut path = "a/".repeat(2_047);
    path.push(leaf);
    path
}

/// What an adversary saw and did.
#[derive(Clone, Debug, Default)]
pub(crate) struct AdversaryLog {
    /// Closes the honest side sent it.
    pub(crate) closed_by_peer: Vec<(PeerId, CloseReason)>,
    /// Chunk requests received, by hash.
    pub(crate) chunk_requests: BTreeMap<CipherHash, u64>,
    /// The records it signed for its attack.
    pub(crate) records: Vec<RecordHash>,
    /// The chunks it serves.
    pub(crate) blobs: Vec<CipherHash>,
    /// Frames it sent outside its connection's rules.
    pub(crate) raw_frames: u64,
    /// The records it replayed ([`Attack::ReplayHistory`]).
    pub(crate) replayed: Vec<RecordHash>,
}

const ATTACK_TIMER: TimerId = TimerId::new(1 << 40);
const REPLAY_TIMER: TimerId = TimerId::new((1 << 40) + 1);

/// A scripted peer on a real connection (module documentation).
pub(crate) struct Adversary {
    device: DeviceKey,
    libp2p: [u8; 32],
    credentials: Vec<FolderCredential>,
    /// The folder key it signs with (for attack 2, another folder's).
    signer: WriteKey,
    folder: FolderId,
    attack: Attack,
    conns: BTreeMap<PeerId, Connection>,
    open: BTreeSet<PeerId>,
    blobs: BTreeMap<CipherHash, Vec<u8>>,
    /// Records pushed when a folder opens.
    on_open: Vec<SignedRecord>,
    /// The connections a one-shot attack has fired on.
    fired: BTreeSet<PeerId>,
    /// What it kept of the records pushed to it, by hash.
    kept: BTreeMap<RecordHash, SignedRecord>,
    pub(crate) log: Rc<RefCell<AdversaryLog>>,
}

/// The adversary's index epoch: it holds nothing, so every Since request
/// it serves is answered with a reset.
const EPOCH: u64 = 0x5eed;

/// The wall clock every peer of these tests reads: the simulator's epoch,
/// 2026-01-01, in microseconds.
const CLOCK_US: u64 = 1_767_225_600_000_000;

/// A record of `writer` with counter `counter` signed with `key`, at
/// `path`, replacing nothing.
pub(crate) fn signed(
    key: &WriteKey,
    writer: DeviceId,
    counter: u64,
    path: &str,
    chunks: Vec<Chunk>,
    plain: Vec<PlainHash>,
    size: u64,
) -> SignedRecord {
    IndexDraft {
        meta: Meta {
            path: path.to_owned(),
            kind: Kind::File,
            size,
            mtime_ns: 0,
            mode: 0,
            plain_hashes: plain,
            written_at: 0,
            dot: Dot {
                device: writer,
                counter,
            },
            vector: Vector::default(),
            deleted: false,
            tree: false,
        },
        chunks,
        replaces: Vec::new(),
    }
    .sign(key, &key.record_keys(), &mut |b: &mut [u8]| b.fill(0x5a))
    .unwrap()
}

/// `body` with its last byte flipped. A record that replaces nothing ends in
/// field 15, its path tag, not in the sealed part: the flip changes the path
/// tag, which is also the seal's associated data (`keys.md` 3.4), so the old
/// signature no longer covers the body, and a body signed again carries a
/// seal that no longer opens (an opaque record at key holders).
fn flip_last(body: &[u8]) -> Vec<u8> {
    let mut b = body.to_vec();
    if let Some(last) = b.last_mut() {
        *last ^= 1;
    }
    b
}

fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The envelope `SignedRecord::to_bytes` lays out, with any body and
/// signature: what a peer may send.
fn envelope(body: &[u8], signature: &[u8; 64]) -> SignedRecord {
    let mut out = vec![0x0a];
    varint(body.len(), &mut out);
    out.extend_from_slice(body);
    out.push(0x12);
    out.push(64);
    out.extend_from_slice(signature);
    SignedRecord::from_bytes(&out).unwrap()
}

impl Adversary {
    /// An adversary of device seed `seed`, holding `folder_a` at its key's
    /// tier, carrying out `attack`.
    pub(crate) fn new(
        seed: u8,
        folder_a: &FolderKey,
        attack: Attack,
        log: Rc<RefCell<AdversaryLog>>,
    ) -> Self {
        let s = DeviceSeed::from_bytes([seed; 32]);
        let device = DeviceKey::from_device_seed(&s);
        let libp2p = Libp2pIdentity::from_device_seed(&s).public_key();
        let folder = folder_a.folder_id();
        let a = write_key(FOLDER_A);
        let me = device.device_id();
        let mut adv = Self {
            device,
            libp2p,
            credentials: vec![FolderCredential::new(folder_a)],
            signer: if attack == Attack::OtherFolderKey {
                write_key(FOLDER_B)
            } else {
                write_key(FOLDER_A)
            },
            folder,
            attack,
            conns: BTreeMap::new(),
            open: BTreeSet::new(),
            blobs: BTreeMap::new(),
            on_open: Vec::new(),
            fired: BTreeSet::new(),
            kept: BTreeMap::new(),
            log,
        };
        adv.prepare(&a, me);
        adv
    }

    /// Builds the records and chunks of the attack.
    fn prepare(&mut self, a: &WriteKey, me: DeviceId) {
        let keys = a.chunk_keys();
        match self.attack {
            Attack::FlippedBody => {
                let r = signed(a, me, CLOCK_US, "adv/flipped.txt", vec![], vec![], 0);
                self.on_open
                    .push(envelope(&flip_last(r.body()), r.signature().as_bytes()));
            }
            Attack::OtherFolderKey => {
                let r = signed(a, me, CLOCK_US, "adv/other-key.txt", vec![], vec![], 0);
                self.on_open
                    .push(self.signer.sign_index_record(r.body().to_vec()).unwrap());
            }
            Attack::GarbageSeal => {
                // It names a chunk, which it serves: key holders fetch the
                // chunks of opaque records too (4.7 item 5).
                let blob = seal_chunk(&keys, &[5u8; 400]).unwrap();
                let chunk = Chunk {
                    cipher_hash: blob.cipher_hash,
                    stored_len: blob.stored.len() as u32,
                };
                let r = signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/garbage.txt",
                    vec![chunk],
                    vec![blob.plain_hash],
                    400,
                );
                self.on_open
                    .push(a.sign_index_record(flip_last(r.body())).unwrap());
                self.blobs.insert(blob.cipher_hash, blob.stored);
            }
            Attack::CorruptChunk => {
                // Sealed under another folder's chunk keys: the right length
                // and ciphertext hash, a seal that will not open here.
                let other = write_key(FOLDER_B).chunk_keys();
                let raw = vec![7u8; 500];
                let blob = seal_chunk(&other, &raw).unwrap();
                let chunk = Chunk {
                    cipher_hash: blob.cipher_hash,
                    stored_len: blob.stored.len() as u32,
                };
                let plain = keys.plain_hash(&raw);
                self.on_open.push(signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/corrupt.bin",
                    vec![chunk],
                    vec![plain],
                    500,
                ));
                self.blobs.insert(blob.cipher_hash, blob.stored);
            }
            Attack::CorruptBesideOpaque | Attack::UnknownHash | Attack::WrongSize => {
                self.prepare_more(a, me);
            }
            Attack::StoredLenMismatch => {
                let small = seal_chunk(&keys, &[3u8; 100]).unwrap();
                let large = seal_chunk(&keys, &[4u8; 3000]).unwrap();
                let chunk = Chunk {
                    cipher_hash: small.cipher_hash,
                    stored_len: large.stored.len() as u32,
                };
                self.on_open.push(signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/length.bin",
                    vec![chunk],
                    vec![small.plain_hash],
                    100,
                ));
                self.blobs.insert(small.cipher_hash, small.stored);
            }
            Attack::CounterJump => {
                let late = CLOCK_US + 1_000_000_000;
                self.on_open
                    .push(signed(a, me, late, "adv/jump-late.txt", vec![], vec![], 0));
                self.on_open.push(signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/jump-early.txt",
                    vec![],
                    vec![],
                    0,
                ));
            }
            Attack::DeepPath => {
                for leaf in 'a'..='p' {
                    let r = signed(a, me, CLOCK_US, &deep_path(leaf), vec![], vec![], 0);
                    self.on_open.push(envelope(r.body(), &[0x42; 64]));
                }
            }
            Attack::UnsolicitedReply
            | Attack::TooManyRequests
            | Attack::Silent
            | Attack::HonestId
            | Attack::ExpiredTreeDelete { .. }
            | Attack::ReplayHistory => {}
        }
        let mut log = self.log.borrow_mut();
        log.records
            .extend(self.on_open.iter().map(SignedRecord::hash));
        log.blobs.extend(self.blobs.keys().copied());
    }

    /// The records and chunks of the attacks that pair a record with a
    /// chunk nobody else has (beside `prepare`, which would grow too long).
    fn prepare_more(&mut self, a: &WriteKey, me: DeviceId) {
        let keys = a.chunk_keys();
        match self.attack {
            Attack::CorruptBesideOpaque => {
                let other = write_key(FOLDER_B).chunk_keys();
                let raw = vec![8u8; 500];
                let blob = seal_chunk(&other, &raw).unwrap();
                let chunk = Chunk {
                    cipher_hash: blob.cipher_hash,
                    stored_len: blob.stored.len() as u32,
                };
                self.on_open.push(signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/corrupt.bin",
                    vec![chunk],
                    vec![keys.plain_hash(&raw)],
                    500,
                ));
                let opaque = signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/opaque.bin",
                    vec![chunk],
                    vec![keys.plain_hash(&raw)],
                    500,
                );
                self.on_open
                    .push(a.sign_index_record(flip_last(opaque.body())).unwrap());
                self.blobs.insert(blob.cipher_hash, blob.stored);
            }
            Attack::UnknownHash => {
                let chunk = Chunk {
                    cipher_hash: CipherHash([0xee; 32]),
                    stored_len: 200,
                };
                let plain = keys.plain_hash(&[9u8; 150]);
                self.on_open.push(signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/unknown.bin",
                    vec![chunk],
                    vec![plain],
                    150,
                ));
            }
            Attack::WrongSize => {
                let blob = seal_chunk(&keys, &[4u8; 300]).unwrap();
                let chunk = Chunk {
                    cipher_hash: blob.cipher_hash,
                    stored_len: blob.stored.len() as u32,
                };
                self.on_open.push(signed(
                    a,
                    me,
                    CLOCK_US,
                    "adv/wrong-size.bin",
                    vec![chunk],
                    vec![blob.plain_hash],
                    999,
                ));
                self.blobs.insert(blob.cipher_hash, blob.stored);
            }
            _ => {}
        }
    }

    fn tick(cx: &dyn Context, peer: PeerId) -> Tick {
        Tick {
            now: Duration::from_nanos(cx.now().as_nanos()),
            unsent: cx.unsent(peer),
        }
    }

    fn wake_timer(peer: PeerId) -> TimerId {
        TimerId::new(peer.as_u64() + 1)
    }

    fn apply(&mut self, cx: &mut dyn Context, peer: PeerId, out: Output) {
        for frame in out.frames {
            let _ = cx.send(peer, frame);
        }
        match out.wake_at {
            Some(d) => cx.set_timer(
                Self::wake_timer(peer),
                Instant::from_nanos(d.as_nanos() as u64),
            ),
            None => cx.cancel_timer(Self::wake_timer(peer)),
        }
        for event in out.events {
            self.react(cx, peer, event);
        }
        if out.close {
            cx.close(peer);
        }
    }

    fn react(&mut self, cx: &mut dyn Context, peer: PeerId, event: Event) {
        match event {
            Event::FolderOpened { .. } => {
                self.open.insert(peer);
                self.on_opened(cx, peer);
            }
            // An honest-looking peer that holds nothing, so that the
            // member's round with it completes: a reset for a Since request,
            // and for a reconcile request `EQUAL` or `RECORDS` with no
            // record (after which the member pushes what it holds).
            Event::ServeIndex { folder, request } => {
                self.call(cx, peer, |c, t| {
                    c.send_reset(t, folder, request.request_id, EPOCH, false)
                        .ok()
                });
            }
            Event::ServeReconcile { folder, request } => {
                let outcome = reconcile_outcome(
                    request.prefix.depth(),
                    &request.digest,
                    &SetDigest::EMPTY,
                    0,
                );
                let reply = ReconcileReply {
                    folder_id: folder.0.to_vec(),
                    request_id: request.request_id,
                    outcome: outcome.as_u32(),
                    children: Vec::new(),
                    epoch: EPOCH,
                    through: 0,
                };
                self.call(cx, peer, |c, t| c.send_reconcile_reply(t, &reply).ok());
                if outcome == ReconcileOutcome::Records {
                    let page = IndexRecords {
                        folder_id: folder.0.to_vec(),
                        records: Vec::new(),
                        more: false,
                        request_id: request.request_id,
                        epoch: EPOCH,
                        through: 0,
                        reset: false,
                    };
                    self.call(cx, peer, |c, t| c.send_page(t, &page).ok());
                }
            }
            Event::Records {
                folder,
                records,
                page,
            } => {
                let results = vec![Ok(Judgement::Duplicate); records.len()];
                self.call(cx, peer, |c, t| Some(c.judged(t, folder, page, &results)));
                self.on_records(cx, peer, &records);
            }
            Event::ChunkRequested {
                folder,
                cipher_hash,
            } => {
                *self
                    .log
                    .borrow_mut()
                    .chunk_requests
                    .entry(cipher_hash)
                    .or_insert(0) += 1;
                if self.attack == Attack::Silent {
                    return;
                }
                let blob = self.blobs.get(&cipher_hash).cloned();
                self.call(cx, peer, |c, t| {
                    let answer = blob
                        .as_deref()
                        .map_or(ChunkAnswer::NotFound, ChunkAnswer::Ok);
                    c.reply_chunk(t, folder, cipher_hash, answer).ok()
                });
            }
            Event::StatusDue => {
                let entries = vec![FolderStatus {
                    folder_id: self.folder.0.to_vec(),
                    ..FolderStatus::default()
                }];
                self.call(cx, peer, |c, t| c.send_status(t, &entries).ok());
            }
            Event::Closed {
                reason,
                by: licketysync_protocol::connection::Side::Peer,
                ..
            } => self.log.borrow_mut().closed_by_peer.push((peer, reason)),
            _ => {}
        }
    }

    /// Calls the connection to `peer`, applying the output it gives.
    fn call(
        &mut self,
        cx: &mut dyn Context,
        peer: PeerId,
        f: impl FnOnce(&mut Connection, Tick) -> Option<Output>,
    ) {
        let t = Self::tick(cx, peer);
        let Some(c) = self.conns.get_mut(&peer) else {
            return;
        };
        if let Some(out) = f(c, t) {
            self.apply(cx, peer, out);
        }
    }

    fn push(&mut self, cx: &mut dyn Context, peer: PeerId, records: &[SignedRecord]) {
        if records.is_empty() {
            return;
        }
        let mut pager = Pager::new(MAX_PAGE_RECORDS, MAX_MESSAGE_SIZE);
        for r in records {
            assert!(pager.push(r).unwrap());
        }
        let page = pager.page(&self.folder, 0, false, EPOCH, 0);
        self.call(cx, peer, |c, t| c.push(t, &page).ok());
    }

    fn raw(&mut self, cx: &mut dyn Context, peer: PeerId, frames: Vec<Message>) {
        let mut bytes = Vec::new();
        for m in frames {
            bytes.extend(m.to_frame().unwrap().encode());
            self.log.borrow_mut().raw_frames += 1;
        }
        let _ = cx.send(peer, bytes);
    }

    fn on_opened(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let records = self.on_open.clone();
        self.push(cx, peer, &records);
        match self.attack {
            Attack::UnsolicitedReply => {
                let m = Message::ChunkReply(ChunkReply {
                    folder_id: self.folder.0.to_vec(),
                    cipher_hash: vec![0xcc; 32],
                    status: 1,
                    data: vec![1; 100],
                });
                self.raw(cx, peer, vec![m]);
            }
            Attack::TooManyRequests => self.too_many(cx, peer),
            _ => {}
        }
    }

    /// What a page pushed or served to it sets off.
    fn on_records(&mut self, cx: &mut dyn Context, peer: PeerId, records: &[Record]) {
        if records.is_empty() {
            return;
        }
        let a = write_key(FOLDER_A);
        match self.attack {
            Attack::HonestId if self.fired.is_empty() => {
                let first = records.iter().find_map(|r| match r.open(&a.record_keys()) {
                    Ok(Applied::Index(m)) if peer == PeerId::new(0) && !m.deleted => Some(m),
                    _ => None,
                });
                let Some(m) = first else {
                    return;
                };
                self.fired.insert(peer);
                let (device, counter) = (m.dot.device, m.dot.counter);
                let twin = signed(&a, device, counter, &m.path, vec![], vec![], 0);
                let ahead = signed(
                    &a,
                    device,
                    counter + 10_000_000,
                    "adv/as-member-0.txt",
                    vec![],
                    vec![],
                    0,
                );
                self.log
                    .borrow_mut()
                    .records
                    .extend([twin.hash(), ahead.hash()]);
                for p in self.open.clone() {
                    self.push(cx, p, &[twin.clone(), ahead.clone()]);
                }
            }
            Attack::ExpiredTreeDelete { forged } if !self.fired.contains(&peer) => {
                self.fired.insert(peer);
                let me = self.device.device_id();
                let counter = CLOCK_US - TOMBSTONE_HORIZON - 10 * 86_400_000_000;
                let r = IndexDraft {
                    meta: Meta {
                        path: "p0".to_owned(),
                        kind: Kind::Directory,
                        size: 0,
                        mtime_ns: 0,
                        mode: 0,
                        plain_hashes: Vec::new(),
                        written_at: 0,
                        dot: Dot {
                            device: me,
                            counter,
                        },
                        vector: Vector::default(),
                        deleted: true,
                        tree: true,
                    },
                    chunks: Vec::new(),
                    replaces: Vec::new(),
                }
                .sign(&a, &a.record_keys(), &mut |b: &mut [u8]| b.fill(0x5b))
                .unwrap();
                let r = if forged {
                    envelope(r.body(), &[0x43; 64])
                } else {
                    r
                };
                self.log.borrow_mut().records.push(r.hash());
                self.push(cx, peer, &[r]);
            }
            Attack::ReplayHistory => {
                for r in records {
                    self.kept.insert(r.hash(), r.signed().clone());
                }
            }
            _ => {}
        }
    }

    /// Pushes every record it kept to every connection.
    fn replay(&mut self, cx: &mut dyn Context) {
        let kept: Vec<SignedRecord> = self.kept.values().cloned().collect();
        self.log
            .borrow_mut()
            .replayed
            .extend(kept.iter().map(SignedRecord::hash));
        for peer in self.open.clone() {
            for page in kept.chunks(64) {
                self.push(cx, peer, page);
            }
        }
    }

    fn too_many(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let requests = (0..64u8)
            .map(|i| {
                Message::ChunkRequest(ChunkRequest {
                    folder_id: self.folder.0.to_vec(),
                    cipher_hash: vec![i; 32],
                })
            })
            .collect();
        self.raw(cx, peer, requests);
        cx.set_timer(
            ATTACK_TIMER,
            cx.now().saturating_add(Duration::from_millis(200)),
        );
    }
}

impl Peer for Adversary {
    fn on_start(&mut self, cx: &mut dyn Context) {
        if self.attack == Attack::ReplayHistory {
            cx.set_timer(REPLAY_TIMER, REPLAY_AT);
        }
    }

    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        let t = Self::tick(cx, from);
        let Some(c) = self.conns.get_mut(&from) else {
            return;
        };
        let keys = Keys {
            device: &self.device,
            folders: &self.credentials,
        };
        let out = c.receive(&keys, &mut |b: &mut [u8]| cx.fill_random(b), t, bytes);
        self.apply(cx, from, out);
    }

    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        if id == REPLAY_TIMER {
            self.replay(cx);
            return;
        }
        if id == ATTACK_TIMER {
            for peer in self.open.clone() {
                self.too_many(cx, peer);
            }
            return;
        }
        let peer = PeerId::new(id.as_u64() - 1);
        self.call(cx, peer, |c, t| Some(c.wake(t)));
    }

    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let mut config = Config::new(self.libp2p, (CLOCK_US / 86_400_000_000) as u32);
        "adversary".clone_into(&mut config.device_name);
        let t = Self::tick(cx, peer);
        let (conn, out) = Connection::new(
            &self.device,
            config,
            &mut |b: &mut [u8]| cx.fill_random(b),
            t,
        )
        .unwrap();
        self.conns.insert(peer, conn);
        self.apply(cx, peer, out);
        let keys = Keys {
            device: &self.device,
            folders: &self.credentials,
        };
        let c = self.conns.get_mut(&peer).unwrap();
        let out = c
            .prove(&keys, &mut |b: &mut [u8]| cx.fill_random(b), t, self.folder)
            .unwrap();
        self.apply(cx, peer, out);
    }

    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.conns.remove(&peer);
        self.open.remove(&peer);
        cx.cancel_timer(Self::wake_timer(peer));
    }

    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

/// What an outsider received: the type and folder of each `IndexRecords`
/// and `ChunkReply` frame.
#[derive(Clone, Debug, Default)]
pub(crate) struct Sniffed {
    pub(crate) index_records: Vec<FolderId>,
    pub(crate) chunk_replies: Vec<FolderId>,
}

/// A member whose received frames are decoded and noted before the member
/// sees them.
pub(crate) struct Sniffer {
    pub(crate) member: Member,
    decoders: BTreeMap<PeerId, FrameDecoder>,
    pub(crate) seen: Rc<RefCell<Sniffed>>,
}

impl Sniffer {
    pub(crate) fn new(member: Member, seen: Rc<RefCell<Sniffed>>) -> Self {
        Self {
            member,
            decoders: BTreeMap::new(),
            seen,
        }
    }

    fn sniff(&mut self, from: PeerId, bytes: &[u8]) {
        let decoder = self
            .decoders
            .entry(from)
            .or_insert_with(|| FrameDecoder::new(MAX_MESSAGE_SIZE));
        let mut input = bytes;
        while let Ok(Some(frame)) = decoder.next_frame(&mut input) {
            let folder = match frame.kind() {
                FrameKind::Known(MessageType::IndexRecords) => IndexRecords::parse(frame.body())
                    .ok()
                    .map(|m| (true, m.folder_id)),
                FrameKind::Known(MessageType::ChunkReply) => ChunkReply::parse(frame.body())
                    .ok()
                    .map(|m| (false, m.folder_id)),
                _ => None,
            };
            if let Some((records, id)) = folder {
                let id = FolderId::from_slice(&id).unwrap_or(FolderId([0; 32]));
                let mut seen = self.seen.borrow_mut();
                if records {
                    seen.index_records.push(id);
                } else {
                    seen.chunk_replies.push(id);
                }
            }
            if input.is_empty() {
                break;
            }
        }
    }
}

/// One peer of an adversary or outsider test.
pub(crate) enum TestPeer {
    Member(Member),
    Adversary(Adversary),
    Outsider(Sniffer),
}

impl TestPeer {
    /// The member, an outsider's included.
    pub(crate) fn member(&self) -> Option<&Member> {
        match self {
            Self::Member(m) => Some(m),
            Self::Outsider(s) => Some(&s.member),
            Self::Adversary(_) => None,
        }
    }

    fn peer(&mut self) -> &mut dyn Peer {
        match self {
            Self::Member(m) => m,
            Self::Adversary(a) => a,
            Self::Outsider(s) => &mut s.member,
        }
    }
}

impl Peer for TestPeer {
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.peer().on_start(cx);
    }
    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        if let Self::Outsider(s) = self {
            s.sniff(from, bytes);
        }
        self.peer().on_message(cx, from, bytes);
    }
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        self.peer().on_timer(cx, id);
    }
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.peer().on_connected(cx, peer);
    }
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        if let Self::Outsider(s) = self {
            s.decoders.remove(&peer);
        }
        self.peer().on_disconnected(cx, peer);
    }
    fn on_stop(&mut self, cx: &mut dyn Context) {
        self.peer().on_stop(cx);
    }
}
