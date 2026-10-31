// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test fixtures: fixed devices, folders and randomness; records signed
//! with fixed nonces; a toy index (records by local sequence and by key, an
//! epoch, the set digests of 4.5 computed from the records, and the peer's
//! cursor) that implements [`IndexView`] and serves both request kinds; and
//! a [`Pair`] of real [`Connection`]s wired through a simulated clock, with a
//! small reference engine that answers what the connection asks (requests
//! due, requests to serve, page by page as the send queue has room, records
//! to judge, the subtrees to push, cursors to keep, Status), so that tests
//! drive whole rounds. The engine stops reacting once its connection is
//! closed. The toy index holds every record it is given that verifies:
//! latest only is the index crate's, not the connection's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use core::time::Duration;

use licketysync_keys::device::{DeviceKey, Libp2pIdentity};
use licketysync_keys::folder::FolderKey;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::secret::{DeviceSeed, WriteSecret};
use licketysync_keys::{
    DeviceId, FolderId, FolderVerifier, RecordHash, SetDigest, Suite, WriteKey,
};

use prost::Message as _;

use crate::connection::{
    Config, Connection, Event, IndexServe, Judgement, Keys, Output, ReconcileServe, SendError,
    State, Tick,
};
use crate::exchange::{reconcile_outcome, IndexView, Pager, Prefix};
use crate::limits::{MAX_PAGE_RECORDS, RECONCILE_LEAF_MAX};
use crate::messages::{FolderStatus, IndexRecords, ReconcileOutcome, ReconcileReply};
use crate::proof::FolderCredential;
use crate::record::{Chunk, CleanupDraft, Dot, Group, IndexDraft, Kind, Meta, Record, Vector};
use crate::rules::Cause;

/// `n, n+1, … n+31`.
pub(crate) fn fixed32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

/// The fixed seed every property test of this crate runs from in the gate,
/// so that the gate is deterministic; the keys and index crates' tests run
/// from the same one.
pub(crate) const PROPTEST_SEED: u64 = 0x6c69_636b_6574_7379;

/// The proptest configuration of every property test of this crate: `cases` cases, or
/// `PROPTEST_CASES` when it is set, from the fixed [`PROPTEST_SEED`], or
/// from the seed `LICKETYSYNC_PROPTEST_SEED` names: `random` for a random
/// one (a long run outside the gate), or a number.
pub(crate) fn proptest_config(cases: u32) -> proptest::test_runner::Config {
    use proptest::test_runner::{Config, RngSeed};
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cases);
    let rng_seed = match std::env::var("LICKETYSYNC_PROPTEST_SEED") {
        Ok(v) if v == "random" => RngSeed::Random,
        Ok(v) => RngSeed::Fixed(
            v.parse()
                .unwrap_or_else(|_| panic!("LICKETYSYNC_PROPTEST_SEED={v}: random or a u64")),
        ),
        Err(_) => RngSeed::Fixed(PROPTEST_SEED),
    };
    Config {
        cases,
        rng_seed,
        ..Config::default()
    }
}

/// The device of `seed` (the keys crate's vectors use `0xa0`).
pub(crate) fn device(seed: u8) -> (DeviceKey, [u8; 32]) {
    let s = DeviceSeed::from_bytes(fixed32(seed));
    (
        DeviceKey::from_device_seed(&s),
        Libp2pIdentity::from_device_seed(&s).public_key(),
    )
}

/// The write key of `seed` (the keys crate's vectors use `0x10`).
pub(crate) fn folder(seed: u8) -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(seed))).unwrap()
}

/// A deterministic generator: the bytes of a counter, stepped per byte.
#[derive(Clone, Debug)]
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (self.0 >> 56) as u8;
        }
    }
}

/// The metadata of a file at `path` written by `writer` at `counter`, with
/// an empty vector.
pub(crate) fn meta(path: &str, writer: u8, counter: u64) -> Meta {
    Meta {
        path: path.to_owned(),
        kind: Kind::File,
        size: 0,
        mtime_ns: 0,
        mode: 0,
        plain_hashes: vec![],
        written_at: 0,
        dot: Dot {
            device: DeviceId([writer; 32]),
            counter,
        },
        vector: Vector::default(),
        deleted: false,
        tree: false,
    }
}

/// Signs `draft` with fixed seal nonces of `salt`.
pub(crate) fn sign(key: &WriteKey, draft: &IndexDraft, salt: u8) -> SignedRecord {
    draft
        .sign(key, &key.record_keys(), &mut |b: &mut [u8]| b.fill(salt))
        .unwrap()
}

/// One record a writer signs at `counter` with a recognisable path.
pub(crate) fn signed(key: &WriteKey, writer: u8, counter: u64, salt: u8) -> SignedRecord {
    let mut m = meta(&format!("w{writer}/c{counter}/{salt}"), writer, counter);
    m.mtime_ns = i64::from(salt);
    sign(
        key,
        &IndexDraft {
            meta: m,
            chunks: vec![],
            replaces: vec![],
        },
        salt,
    )
}

/// A record with one chunk named `cipher_hash`.
pub(crate) fn with_chunk(
    key: &WriteKey,
    writer: u8,
    counter: u64,
    chunk: Chunk,
    plain: [u8; 32],
) -> SignedRecord {
    let mut m = meta(&format!("c/{counter}"), writer, counter);
    m.size = 1;
    m.plain_hashes = vec![licketysync_keys::chunk::PlainHash(plain)];
    sign(
        key,
        &IndexDraft {
            meta: m,
            chunks: vec![chunk],
            replaces: vec![],
        },
        9,
    )
}

/// A cleanup by `writer` at `counter` with these groups.
pub(crate) fn cleanup(
    key: &WriteKey,
    writer: u8,
    counter: u64,
    groups: Vec<Group>,
) -> SignedRecord {
    CleanupDraft {
        dot: Dot {
            device: DeviceId([writer; 32]),
            counter,
        },
        groups,
    }
    .sign(key, &key.record_keys(), &mut |b: &mut [u8]| b.fill(7))
    .unwrap()
}

/// The raw envelope `SignedRecord::to_bytes` lays out, with any signature
/// bytes: what a peer may send.
pub(crate) fn envelope(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if !body.is_empty() {
        prost::encoding::bytes::encode(1, &body.to_vec(), &mut out);
    }
    prost::encoding::bytes::encode(2, &signature.to_vec(), &mut out);
    out
}

/// `body` and a 64-byte `signature`, through the keys crate's decoder.
pub(crate) fn record_of(body: &[u8], signature: &[u8; 64]) -> SignedRecord {
    SignedRecord::from_bytes(&envelope(body, signature)).unwrap()
}

/// `body` (any bytes, not only a record's) and a 64-byte `signature` as a
/// `SignedRecord`: a folder key signs any body, and the keys crate's decoder
/// would refuse one without the record prefix.
pub(crate) fn record_of_any(body: &[u8], signature: &[u8; 64]) -> SignedRecord {
    let mut prefixed = crate::messages::IndexRecord {
        suite: 1,
        record_type: 16,
        ..crate::messages::IndexRecord::default()
    }
    .encode_to_vec();
    if !body.is_empty() {
        prost::encoding::bytes::encode(99, &body.to_vec(), &mut prefixed);
    }
    record_of(&prefixed, signature)
}

/// `r` with another signature (garbage, or one bit flipped).
pub(crate) fn resigned(r: &SignedRecord, signature: [u8; 64]) -> SignedRecord {
    record_of(r.body(), &signature)
}

/// `r`'s signature with one bit flipped.
pub(crate) fn flipped(r: &SignedRecord, byte: usize) -> SignedRecord {
    let mut sig = *r.signature().as_bytes();
    sig[byte] ^= 1;
    resigned(r, sig)
}

/// One record the toy index holds.
#[derive(Clone, Debug)]
pub(crate) struct Held {
    pub(crate) seq: u64,
    pub(crate) key: crate::exchange::Key,
    pub(crate) signed: SignedRecord,
}

/// A toy index of one folder: every record it was given that verified, by
/// local sequence and by key, its epoch, and the cursor of each peer.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    pub(crate) held: BTreeMap<RecordHash, Held>,
    pub(crate) by_seq: BTreeMap<u64, RecordHash>,
    pub(crate) next_seq: u64,
    pub(crate) epoch: u64,
    pub(crate) peers: BTreeMap<DeviceId, (u64, u64)>,
    /// Records that change nothing when they arrive: the store refuses
    /// (judged [`Judgement::Skipped`]).
    pub(crate) refusing: bool,
    /// The toy index lies about every digest: none is ever zero, nor any
    /// real set's (for tests that need a requester to descend anywhere).
    pub(crate) lying: bool,
}

impl Default for Store {
    fn default() -> Self {
        Self::with_epoch(1)
    }
}

impl IndexView for Store {
    fn digest(&self, prefix: &Prefix) -> SetDigest {
        if self.lying {
            let mut d = [0x6c; 32];
            for (i, n) in prefix.nibbles().enumerate() {
                d[(i / 2) % 31] ^= if i % 2 == 0 { n << 4 } else { n };
            }
            d[31] = u8::try_from(prefix.depth()).unwrap();
            return SetDigest(d);
        }
        let hashes = self.hashes_in(prefix);
        if hashes.is_empty() {
            SetDigest::EMPTY
        } else if hashes.len() <= RECONCILE_LEAF_MAX || prefix.is_full() {
            SetDigest::leaf(&hashes)
        } else {
            let children: [SetDigest; 16] =
                core::array::from_fn(|i| self.digest(&prefix.child(i as u8).unwrap()));
            SetDigest::node(&children)
        }
    }

    fn peer_cursor(&self, peer: &DeviceId) -> Option<(u64, u64)> {
        self.peers.get(peer).copied()
    }
}

impl Store {
    pub(crate) fn with_epoch(epoch: u64) -> Self {
        Self {
            held: BTreeMap::new(),
            by_seq: BTreeMap::new(),
            next_seq: 1,
            epoch,
            peers: BTreeMap::new(),
            refusing: false,
            lying: false,
        }
    }

    /// Holds `record` (once), numbering it next; its local sequence.
    pub(crate) fn insert(&mut self, record: &Record) -> u64 {
        if let Some(h) = self.held.get(&record.hash()) {
            return h.seq;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.by_seq.insert(seq, record.hash());
        self.held.insert(
            record.hash(),
            Held {
                seq,
                key: record.key(),
                signed: record.signed().clone(),
            },
        );
        seq
    }

    pub(crate) fn insert_signed(&mut self, signed: &SignedRecord, folder: &FolderVerifier) -> u64 {
        self.insert(&Record::parse(signed.clone(), folder).unwrap())
    }

    pub(crate) fn holds(&self, hash: &RecordHash) -> bool {
        self.held.contains_key(hash)
    }

    /// The local sequence: the greatest number given.
    pub(crate) fn local_seq(&self) -> u64 {
        self.next_seq - 1
    }

    /// The records in the subtree at `prefix`, ascending by record hash.
    pub(crate) fn in_prefix(&self, prefix: &Prefix) -> Vec<(RecordHash, SignedRecord)> {
        self.held
            .iter()
            .filter(|(_, h)| prefix.contains(&h.key))
            .map(|(hash, h)| (*hash, h.signed.clone()))
            .collect()
    }

    fn hashes_in(&self, prefix: &Prefix) -> Vec<RecordHash> {
        self.in_prefix(prefix).into_iter().map(|(h, _)| h).collect()
    }

    /// The parts of the reply to an `IndexRequest` (4.5, "Serving an
    /// `IndexRequest`"), drawing a new epoch for a `since` above the local
    /// sequence when that is allowed.
    pub(crate) fn index_reply(
        &mut self,
        folder: FolderId,
        request: &IndexServe,
        max_message_size: u32,
    ) -> Vec<Part> {
        let local = self.local_seq();
        if request.epoch != self.epoch || request.since > local {
            let redrew =
                request.epoch == self.epoch && request.since > local && request.redraw_allowed;
            if redrew {
                self.epoch = self.epoch.wrapping_mul(31).wrapping_add(7).max(1);
            }
            return vec![Part::Reset {
                folder,
                request_id: request.request_id,
                epoch: self.epoch,
                redrew,
            }];
        }
        let records: Vec<(u64, SignedRecord)> = self
            .by_seq
            .range(request.since + 1..)
            .map(|(seq, h)| (*seq, self.held[h].signed.clone()))
            .collect();
        let mut pages = Vec::new();
        let mut pager = Pager::new(request.page_limit, max_message_size);
        let mut last = request.since;
        for (seq, r) in records {
            if !pager.push(&r).unwrap() {
                pages.push(pager.page(&folder, request.request_id, true, self.epoch, last));
                assert!(pager.push(&r).unwrap());
            }
            last = seq;
        }
        pages.push(pager.page(&folder, request.request_id, false, self.epoch, local));
        pages.into_iter().map(Part::Page).collect()
    }

    /// The parts of the reply to a `ReconcileRequest` (4.5, "Serving a
    /// `ReconcileRequest`").
    pub(crate) fn reconcile_reply(
        &self,
        folder: FolderId,
        request: &ReconcileServe,
        max_message_size: u32,
    ) -> Vec<Part> {
        let own = self.digest(&request.prefix);
        let records = self.in_prefix(&request.prefix);
        let outcome =
            reconcile_outcome(request.prefix.depth(), &request.digest, &own, records.len());
        let children = if outcome == ReconcileOutcome::Children {
            (0..16u8)
                .map(|i| self.digest(&request.prefix.child(i).unwrap()).0.to_vec())
                .collect()
        } else {
            vec![]
        };
        let mut parts = vec![Part::Reconcile(ReconcileReply {
            folder_id: folder.0.to_vec(),
            request_id: request.request_id,
            outcome: outcome.as_u32(),
            children,
            epoch: self.epoch,
            through: if request.prefix.is_root() {
                self.local_seq()
            } else {
                0
            },
        })];
        if outcome == ReconcileOutcome::Records {
            // In ascending key order (4.5, "Serving a `ReconcileRequest`").
            let mut records = records;
            records.sort_by_key(|(h, _)| self.held[h].key);
            let mut pages = Vec::new();
            let mut pager = Pager::new(MAX_PAGE_RECORDS, max_message_size);
            for (_, r) in records {
                if !pager.push(&r).unwrap() {
                    pages.push(pager.page(&folder, request.request_id, true, self.epoch, 0));
                    assert!(pager.push(&r).unwrap());
                }
            }
            pages.push(pager.page(&folder, request.request_id, false, self.epoch, 0));
            parts.extend(pages.into_iter().map(Part::Page));
        }
        parts
    }

    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }

    /// Every record held, for convergence checks.
    pub(crate) fn all(&self) -> BTreeSet<RecordHash> {
        self.held.keys().copied().collect()
    }
}

/// One part of a reply the reference engine is sending.
#[derive(Clone, Debug)]
pub(crate) enum Part {
    Page(IndexRecords),
    Reset {
        folder: FolderId,
        request_id: u32,
        epoch: u64,
        redrew: bool,
    },
    Reconcile(ReconcileReply),
}

/// One side of a [`Pair`]: its device, folder, connection, toy index and
/// what the reference engine saw.
pub(crate) struct Side {
    pub(crate) key: DeviceKey,
    pub(crate) credentials: Vec<FolderCredential>,
    pub(crate) conn: Connection,
    pub(crate) rng: Rng,
    pub(crate) store: Store,
    pub(crate) events: Vec<Event>,
    pub(crate) wake: Option<Duration>,
    pub(crate) transport_closed: bool,
    pub(crate) outbox: Vec<u8>,
    /// Frames this side handed to the transport, with the time.
    pub(crate) sent: Vec<(Duration, Vec<u8>)>,
    /// The parts of replies under way, in order.
    pub(crate) replies: VecDeque<Part>,
    /// The engine reacts to events when set; tests that script one side by
    /// hand turn it off.
    pub(crate) auto: bool,
    /// Simulated unsent bytes the transport reports.
    pub(crate) unsent: usize,
    /// Causes the reference engine reported.
    pub(crate) reported: Vec<Cause>,
    /// Events not yet reacted to.
    queue: VecDeque<Event>,
    /// The reference engine serves the peer's index requests (tests of the
    /// reply deadline turn it off and keep the rest).
    pub(crate) serving: bool,
}

impl Side {
    fn new(seed: u8, folders: &[FolderKey], config: impl FnOnce(&mut Config)) -> (Self, Output) {
        let (key, libp2p) = device(seed);
        // 2026-10-25, the day these vectors were made.
        let mut cfg = Config::new(libp2p, 20_751);
        cfg.device_name = format!("device-{seed:02x}");
        config(&mut cfg);
        let mut rng = Rng(u64::from(seed));
        let (conn, out) =
            Connection::new(&key, cfg, &mut |b| rng.fill(b), Tick::default()).unwrap();
        let side = Self {
            credentials: folders.iter().map(FolderCredential::new).collect(),
            key,
            conn,
            rng,
            store: Store::with_epoch(u64::from(seed) << 8 | 1),
            events: Vec::new(),
            wake: None,
            transport_closed: false,
            outbox: Vec::new(),
            sent: Vec::new(),
            replies: VecDeque::new(),
            auto: true,
            unsent: 0,
            reported: Vec::new(),
            queue: VecDeque::new(),
            serving: true,
        };
        (side, out)
    }

    pub(crate) fn tick(&self, now: Duration) -> Tick {
        Tick {
            now,
            unsent: self.unsent,
        }
    }

    pub(crate) fn apply(&mut self, now: Duration, out: Output) -> Vec<Event> {
        for f in out.frames {
            self.outbox.extend_from_slice(&f);
            self.sent.push((now, f));
        }
        self.wake = out.wake_at;
        if out.close {
            self.transport_closed = true;
        }
        self.events.extend(out.events.iter().cloned());
        self.queue.extend(out.events.iter().cloned());
        out.events
    }

    /// Reacts to every queued event, the reactions' own events included,
    /// while the connection is open (SEC N6).
    pub(crate) fn pump(&mut self, now: Duration) {
        while let Some(e) = self.queue.pop_front() {
            if self.auto && !self.transport_closed && self.conn.state() != State::Closed {
                self.react(now, &e);
            }
        }
    }

    pub(crate) fn folder_id(&self) -> FolderId {
        self.credentials[0].folder_id()
    }

    pub(crate) fn verifier(&self) -> FolderVerifier {
        *self.credentials[0].verifier()
    }

    /// Receives `bytes` from the peer.
    pub(crate) fn receive(&mut self, now: Duration, bytes: &[u8]) -> Vec<Event> {
        let keys = Keys {
            device: &self.key,
            folders: &self.credentials,
        };
        let tick = self.tick(now);
        let mut rng = self.rng.clone();
        let out = self.conn.receive(&keys, &mut |b| rng.fill(b), tick, bytes);
        self.rng = rng;
        let events = self.apply(now, out);
        self.pump(now);
        events
    }

    pub(crate) fn prove_all(&mut self, now: Duration) {
        let ids: Vec<FolderId> = self
            .credentials
            .iter()
            .map(FolderCredential::folder_id)
            .collect();
        for id in ids {
            let keys = Keys {
                device: &self.key,
                folders: &self.credentials,
            };
            let tick = self.tick(now);
            let mut rng = self.rng.clone();
            let out = self
                .conn
                .prove(&keys, &mut |b| rng.fill(b), tick, id)
                .unwrap();
            self.rng = rng;
            self.apply(now, out);
        }
        self.pump(now);
    }

    /// Applies a send's output, or returns its error.
    pub(crate) fn sent_or(
        &mut self,
        now: Duration,
        result: Result<Output, SendError>,
    ) -> Result<Vec<Event>, SendError> {
        result.map(|out| self.apply(now, out))
    }

    /// Sends this side's due request for the folder from its store.
    pub(crate) fn request(&mut self, now: Duration) -> Result<Vec<Event>, SendError> {
        let (tick, folder) = (self.tick(now), self.folder_id());
        let result = self.conn.send_request(tick, folder, &self.store);
        self.sent_or(now, result)
    }

    /// Asks the peer for a chunk.
    pub(crate) fn request_chunk(
        &mut self,
        now: Duration,
        hash: licketysync_keys::CipherHash,
    ) -> Result<Vec<Event>, SendError> {
        let (tick, folder) = (self.tick(now), self.folder_id());
        let result = self.conn.request_chunk(tick, folder, hash);
        self.sent_or(now, result)
    }

    /// Answers the peer's chunk request.
    pub(crate) fn reply_chunk(
        &mut self,
        now: Duration,
        hash: licketysync_keys::CipherHash,
        answer: crate::connection::ChunkAnswer<'_>,
    ) -> Result<Vec<Event>, SendError> {
        let (tick, folder) = (self.tick(now), self.folder_id());
        let result = self.conn.reply_chunk(tick, folder, hash, answer);
        self.sent_or(now, result)
    }

    /// Sends a Status for every open folder.
    pub(crate) fn status(&mut self, now: Duration) -> Result<Vec<Event>, SendError> {
        let folders: Vec<FolderStatus> = self
            .conn
            .open_folders()
            .map(|f| FolderStatus {
                folder_id: f.0.to_vec(),
                index_records: self.store.len() as u64,
                ..FolderStatus::default()
            })
            .collect();
        let tick = self.tick(now);
        let result = self.conn.send_status(tick, &folders);
        self.sent_or(now, result)
    }

    /// Ends this side's chunk pass.
    pub(crate) fn pass_done(&mut self, now: Duration) {
        let (tick, folder) = (self.tick(now), self.folder_id());
        let out = self.conn.pass_done(tick, folder);
        self.apply(now, out);
    }

    /// Fires this side's wake-up.
    pub(crate) fn wake(&mut self, now: Duration) {
        let tick = self.tick(now);
        let out = self.conn.wake(tick);
        self.apply(now, out);
        self.pump(now);
    }

    /// The reference engine's reaction to one event.
    fn react(&mut self, now: Duration, event: &Event) {
        let mms = self.conn.peer_max_message_size();
        match event {
            Event::RequestDue { .. } => {
                let _ = self.request(now);
            }
            // A Status the send queue cannot take is skipped (SEC-SF2).
            Event::StatusDue => {
                let _ = self.status(now);
            }
            Event::ServeIndex { folder, request } if self.serving => {
                let parts = self.store.index_reply(*folder, request, mms);
                self.replies.extend(parts);
                self.serve_replies(now);
            }
            Event::ServeReconcile { folder, request } if self.serving => {
                let parts = self.store.reconcile_reply(*folder, request, mms);
                self.replies.extend(parts);
                self.serve_replies(now);
            }
            Event::Room => self.serve_replies(now),
            Event::Records {
                folder,
                records,
                page,
            } => {
                let results = self.judge(records);
                let tick = self.tick(now);
                let out = self.conn.judged(tick, *folder, *page, &results);
                self.apply(now, out);
            }
            Event::PushSubtree {
                prefix, carried, ..
            } => {
                let carried: BTreeSet<RecordHash> = carried.iter().flatten().copied().collect();
                let records: Vec<SignedRecord> = self
                    .store
                    .in_prefix(prefix)
                    .into_iter()
                    .filter(|(h, _)| !carried.contains(h))
                    .map(|(_, r)| r)
                    .collect();
                for chunk in records.chunks(MAX_PAGE_RECORDS) {
                    self.push_page(now, chunk, 0);
                }
            }
            Event::RoundCompleted {
                cursor: Some(c), ..
            } => {
                if let Some(peer) = self.conn.peer_device() {
                    self.store.peers.insert(peer, *c);
                }
            }
            Event::CursorAdvanced { epoch, through, .. } => {
                if let Some(peer) = self.conn.peer_device() {
                    self.store.peers.insert(peer, (*epoch, *through));
                }
            }
            _ => {}
        }
    }

    /// The toy index's judgements of a page's records, in order, stopping
    /// at the first that closes.
    pub(crate) fn judge(&mut self, records: &[Record]) -> Vec<Result<Judgement, Cause>> {
        let verifier = self.verifier();
        let mut results = Vec::new();
        for r in records {
            let judged = if self.store.holds(&r.hash()) {
                Ok(Judgement::Duplicate)
            } else if let Err(cause) = r.verify(&verifier) {
                Err(cause)
            } else if self.store.refusing {
                Ok(Judgement::Skipped)
            } else {
                self.store.insert(r);
                Ok(Judgement::Held)
            };
            results.push(judged);
            if let Err(cause) = judged {
                self.reported.push(cause);
                break;
            }
        }
        results
    }

    /// Sends the parts of the replies under way while the send queue has
    /// room; on a refusal for room, waits for [`Event::Room`].
    pub(crate) fn serve_replies(&mut self, now: Duration) {
        while let Some(part) = self.replies.pop_front() {
            let tick = self.tick(now);
            let result = match &part {
                Part::Page(page) => self.conn.send_page(tick, page),
                Part::Reset {
                    folder,
                    request_id,
                    epoch,
                    redrew,
                } => self
                    .conn
                    .send_reset(tick, *folder, *request_id, *epoch, *redrew),
                Part::Reconcile(reply) => self.conn.send_reconcile_reply(tick, reply),
            };
            match result {
                Ok(out) => {
                    self.apply(now, out);
                }
                Err(SendError::WouldBlock { len }) => {
                    self.replies.push_front(part);
                    let out = self.conn.want_room(tick, len);
                    self.apply(now, out);
                    return;
                }
                // The connection closed meanwhile: the reply is dropped.
                Err(_) => {}
            }
        }
    }

    /// Pushes one page of `records` with `through`; the frames it handed
    /// over (the push, the empty push owed, or none).
    pub(crate) fn push_page(
        &mut self,
        now: Duration,
        records: &[SignedRecord],
        through: u64,
    ) -> Vec<Vec<u8>> {
        let folder = self.folder_id();
        let mut pager = Pager::new(MAX_PAGE_RECORDS, self.conn.peer_max_message_size());
        for r in records {
            assert!(pager.push(r).unwrap());
        }
        let page: IndexRecords = pager.page(&folder, 0, false, self.store.epoch, through);
        let before = self.sent.len();
        let tick = self.tick(now);
        let out = self.conn.push(tick, &page).unwrap();
        self.apply(now, out);
        self.sent[before..].iter().map(|(_, f)| f.clone()).collect()
    }

    /// This side comes to hold `records` (it wrote them) and pushes them,
    /// `through` the local sequence of the last; the frames it handed over.
    pub(crate) fn push(&mut self, now: Duration, records: &[SignedRecord]) -> Vec<Vec<u8>> {
        let verifier = self.verifier();
        let mut through = 0;
        for r in records {
            through = self.store.insert_signed(r, &verifier);
        }
        self.push_page(now, records, through)
    }

    /// Whether the event list holds an event matching `f`.
    pub(crate) fn saw(&self, f: impl Fn(&Event) -> bool) -> bool {
        self.events.iter().any(f)
    }
}

/// Two connected sides and the clock.
pub(crate) struct Pair {
    pub(crate) now: Duration,
    pub(crate) a: Side,
    pub(crate) b: Side,
}

impl Pair {
    /// Two devices (seeds `a`, `b`) holding `folders_a` and `folders_b`;
    /// both Hellos are sent, nothing delivered yet.
    pub(crate) fn new(a: u8, b: u8, folders_a: &[FolderKey], folders_b: &[FolderKey]) -> Self {
        Self::with(a, b, folders_a, folders_b, |_| {}, |_| {})
    }

    pub(crate) fn with(
        a: u8,
        b: u8,
        folders_a: &[FolderKey],
        folders_b: &[FolderKey],
        config_a: impl FnOnce(&mut Config),
        config_b: impl FnOnce(&mut Config),
    ) -> Self {
        let (mut sa, oa) = Side::new(a, folders_a, config_a);
        let (mut sb, ob) = Side::new(b, folders_b, config_b);
        sa.apply(Duration::ZERO, oa);
        sb.apply(Duration::ZERO, ob);
        Self {
            now: Duration::ZERO,
            a: sa,
            b: sb,
        }
    }

    /// A pair with the folder of seed `0x10` open between write holders,
    /// both rounds done.
    pub(crate) fn open() -> Self {
        let mut p = Self::new(
            0xa0,
            0xb0,
            &[FolderKey::from(folder(0x10))],
            &[FolderKey::from(folder(0x10))],
        );
        p.settle();
        p.a.prove_all(p.now);
        p.settle();
        assert!(p.a.conn.is_open(&p.a.folder_id()) && p.b.conn.is_open(&p.b.folder_id()));
        p
    }

    /// Delivers every frame in flight both ways once; whether any moved.
    pub(crate) fn deliver(&mut self) -> bool {
        let now = self.now;
        let to_b = core::mem::take(&mut self.a.outbox);
        let to_a = core::mem::take(&mut self.b.outbox);
        let moved = !to_b.is_empty() || !to_a.is_empty();
        if !to_b.is_empty() && !self.b.transport_closed {
            self.b.receive(now, &to_b);
        }
        if !to_a.is_empty() && !self.a.transport_closed {
            self.a.receive(now, &to_a);
        }
        self.a.pump(now);
        self.b.pump(now);
        moved || !self.a.outbox.is_empty() || !self.b.outbox.is_empty()
    }

    /// Delivers until nothing moves.
    pub(crate) fn settle(&mut self) {
        for _ in 0..10_000 {
            if !self.deliver() {
                return;
            }
        }
        panic!("the pair did not settle");
    }

    /// Advances the clock to `t`, firing each side's wake-up in time order
    /// and settling after each.
    pub(crate) fn advance_to(&mut self, t: Duration) {
        loop {
            let next = [self.a.wake, self.b.wake]
                .into_iter()
                .flatten()
                .filter(|w| *w <= t)
                .min();
            let Some(w) = next else {
                break;
            };
            self.now = self.now.max(w);
            let now = self.now;
            for side in [&mut self.a, &mut self.b] {
                if side.wake.is_some_and(|x| x <= now) {
                    if side.transport_closed {
                        side.wake = None;
                    } else {
                        side.wake(now);
                    }
                }
            }
            self.settle();
        }
        self.now = self.now.max(t);
        self.settle();
    }

    /// Advances the clock by `d`.
    pub(crate) fn advance(&mut self, d: Duration) {
        self.advance_to(self.now + d);
    }
}

/// Seconds.
pub(crate) const fn s(n: u64) -> Duration {
    Duration::from_secs(n)
}
