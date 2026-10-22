// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test fixtures: fixed devices, folders and randomness; a toy index that
//! implements [`Held`] and [`Cursors`] with the cached digests of 4.4; and a
//! [`Pair`] of real [`Connection`]s wired through a simulated clock, with a
//! small reference engine that answers what the connection asks (requests
//! due, requests to serve, page by page as the send queue has room, records
//! to judge, Status), so that tests drive whole exchanges. The engine stops
//! reacting once its connection is closed.

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
    DeviceId, FolderId, FolderVerifier, RecordHash, Suite, WriteKey, WriterDigest,
};

use prost::Message as _;

use crate::connection::{Config, Connection, Event, Keys, Output, SendError, State, Tick};
use crate::exchange::{serve, Cursors, Pager, Serve, ServeRequest, WriterCursor};
use crate::messages::{FolderStatus, IndexRecords};
use crate::proof::FolderCredential;
use crate::record::{judge, writer_digests, Chunk, Draft, Held, Kind, Meta, Record};
use crate::rules::Cause;

/// `n, n+1, … n+31`.
pub(crate) fn fixed32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
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

/// One record a writer signs at `seq` with a recognisable path.
pub(crate) fn signed(key: &WriteKey, writer: u8, seq: u64, salt: u8) -> SignedRecord {
    Draft {
        device_id: DeviceId([writer; 32]),
        seq,
        supersedes: vec![],
        deleted: false,
        chunks: vec![],
        meta: Meta {
            path: format!("w{writer}/s{seq}/{salt}"),
            kind: Kind::File,
            size: 0,
            mtime_ns: i64::from(salt),
            mode: 0,
            plain_hashes: vec![],
            written_at: 0,
        },
    }
    .sign(key, &mut |b: &mut [u8]| b.fill(salt))
    .unwrap()
}

/// A record with one chunk named `cipher_hash`.
pub(crate) fn with_chunk(
    key: &WriteKey,
    writer: u8,
    seq: u64,
    chunk: Chunk,
    plain: [u8; 32],
) -> SignedRecord {
    Draft {
        device_id: DeviceId([writer; 32]),
        seq,
        supersedes: vec![],
        deleted: false,
        chunks: vec![chunk],
        meta: Meta {
            path: format!("c/{seq}"),
            kind: Kind::File,
            size: 1,
            mtime_ns: 0,
            mode: 0,
            plain_hashes: vec![licketysync_keys::chunk::PlainHash(plain)],
            written_at: 0,
        },
    }
    .sign(key, &mut |b: &mut [u8]| b.fill(9))
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

/// A toy index of one folder: every record by writer, in canonical order,
/// with the cached digests of 4.4.
#[derive(Clone, Debug, Default)]
pub(crate) struct Store {
    pub(crate) by_writer: BTreeMap<DeviceId, BTreeMap<(u64, RecordHash), SignedRecord>>,
    pub(crate) hashes: BTreeSet<RecordHash>,
}

impl Held for Store {
    fn holds(&self, record: &RecordHash) -> bool {
        self.hashes.contains(record)
    }
    fn cursor(&self, writer: &DeviceId) -> u64 {
        self.by_writer
            .get(writer)
            .and_then(|r| r.keys().next_back())
            .map_or(0, |(s, _)| *s)
    }
}

impl Store {
    pub(crate) fn insert(&mut self, record: &Record) {
        self.hashes.insert(record.hash());
        self.by_writer
            .entry(record.device_id())
            .or_default()
            .insert((record.seq(), record.hash()), record.signed().clone());
    }

    pub(crate) fn insert_signed(&mut self, signed: &SignedRecord, folder: &FolderVerifier) {
        self.insert(&Record::parse(signed.clone(), folder).unwrap());
    }

    pub(crate) fn digest_at(&self, writer: &DeviceId, seq: u64) -> Option<WriterDigest> {
        let records = self.by_writer.get(writer)?;
        writer_digests(records.keys().copied())
            .range(..=seq)
            .next_back()
            .map(|(_, d)| *d)
    }

    pub(crate) fn cursor_of(&self, writer: &DeviceId) -> WriterCursor {
        let seq = self.cursor(writer);
        WriterCursor {
            writer: *writer,
            seq,
            digest: (seq > 0).then(|| self.digest_at(writer, seq)).flatten(),
        }
    }

    /// The records of every writer in `scope` this side serves for
    /// `request`, in the order of 4.5, and the writers resent in full (case
    /// (c)).
    pub(crate) fn reply(&self, request: &ServeRequest) -> (Vec<SignedRecord>, Vec<DeviceId>) {
        let mut records = Vec::new();
        let mut resent = Vec::new();
        for (w, held) in &self.by_writer {
            if !request.scope.contains(w) {
                continue;
            }
            let requester = request.requester(w);
            let from = match serve(requester, self.cursor(w), self.digest_at(w, requester.0)) {
                Serve::All { mark } => {
                    if mark {
                        resent.push(*w);
                    }
                    0
                }
                Serve::After(s) => s,
                Serve::Nothing => continue,
            };
            records.extend(
                held.iter()
                    .filter(|((s, _), _)| *s > from)
                    .map(|(_, r)| r.clone()),
            );
        }
        (records, resent)
    }

    pub(crate) fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Every record held, for convergence checks.
    pub(crate) fn all(&self) -> BTreeSet<RecordHash> {
        self.hashes.clone()
    }
}

impl Cursors for Store {
    fn cursors_after(&self, after: Option<DeviceId>) -> impl Iterator<Item = WriterCursor> + '_ {
        let from = after.map_or(core::ops::Bound::Unbounded, core::ops::Bound::Excluded);
        self.by_writer
            .range((from, core::ops::Bound::Unbounded))
            .map(|(w, _)| self.cursor_of(w))
    }

    fn cursor_of(&self, writer: &DeviceId) -> WriterCursor {
        Store::cursor_of(self, writer)
    }
}

/// A reply the reference engine is sending, page by page.
#[derive(Clone, Debug)]
pub(crate) struct Reply {
    pub(crate) folder: FolderId,
    pub(crate) request_id: u32,
    pub(crate) page_limit: usize,
    /// The records not yet on a page.
    pub(crate) records: VecDeque<SignedRecord>,
    /// The writers resent in full, marked with the first page.
    pub(crate) resent: Vec<DeviceId>,
    /// A page built and refused for want of room.
    pub(crate) built: Option<IndexRecords>,
}

impl Reply {
    pub(crate) fn new(folder: FolderId, request: &ServeRequest, store: &Store) -> Self {
        let (records, resent) = store.reply(request);
        Self {
            folder,
            request_id: request.request_id,
            page_limit: request.page_limit,
            records: records.into(),
            resent,
            built: None,
        }
    }

    /// The next page for a peer that accepts frames of `max_message_size`.
    pub(crate) fn next_page(&mut self, max_message_size: u32) -> IndexRecords {
        if let Some(page) = self.built.take() {
            return page;
        }
        let mut pager = Pager::new(self.page_limit, max_message_size);
        while let Some(r) = self.records.front() {
            if !pager.push(r).unwrap() {
                break;
            }
            self.records.pop_front();
        }
        let more = !self.records.is_empty();
        pager.page(&self.folder, self.request_id, more)
    }
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
    /// Replies under way, page by page.
    pub(crate) replies: VecDeque<Reply>,
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
        let mut cfg = Config::new(libp2p);
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
            store: Store::default(),
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
        match event {
            Event::RequestDue { .. } => {
                let _ = self.request(now);
            }
            // A Status the send queue cannot take is skipped (SEC-SF2).
            Event::StatusDue => {
                let _ = self.status(now);
            }
            Event::Serve { folder, request } if self.serving => {
                let reply = Reply::new(*folder, request, &self.store);
                self.replies.push_back(reply);
                self.serve_replies(now);
            }
            Event::Room => self.serve_replies(now),
            Event::Records {
                folder,
                records,
                page,
            } => {
                let verifier = self.verifier();
                let mut results = Vec::new();
                for r in records {
                    let judged = judge(&r.record, r.arrival, &self.store, &verifier);
                    if judged.is_ok_and(crate::record::Judgement::stores) {
                        self.store.insert(&r.record);
                    }
                    results.push((r.record.device_id(), judged));
                    if let Err(cause) = judged {
                        self.reported.push(cause);
                        break;
                    }
                }
                let tick = self.tick(now);
                let out = self.conn.judged(tick, *folder, *page, &results);
                self.apply(now, out);
            }
            _ => {}
        }
    }

    /// Sends the pages of the replies under way while the send queue has
    /// room; on a refusal for room, waits for [`Event::Room`].
    pub(crate) fn serve_replies(&mut self, now: Duration) {
        while let Some(mut reply) = self.replies.pop_front() {
            let page = reply.next_page(self.conn.peer_max_message_size());
            let resent = core::mem::take(&mut reply.resent);
            let tick = self.tick(now);
            match self.conn.send_page(tick, &page, &resent) {
                Ok(out) => {
                    self.apply(now, out);
                    if page.more {
                        self.replies.push_front(reply);
                    }
                }
                Err(SendError::WouldBlock { len }) => {
                    reply.resent = resent;
                    reply.built = Some(page);
                    self.replies.push_front(reply);
                    let out = self.conn.want_room(tick, len);
                    self.apply(now, out);
                    return;
                }
                // The connection closed meanwhile: the reply is dropped.
                Err(_) => {}
            }
        }
    }

    /// Pushes records this side newly accepted (it wrote them); the frames
    /// it handed over (the push, the empty push owed, or none).
    pub(crate) fn push(&mut self, now: Duration, records: &[SignedRecord]) -> Vec<Vec<u8>> {
        let folder = self.folder_id();
        let mut pager = Pager::new(
            crate::limits::MAX_PAGE_RECORDS,
            self.conn.peer_max_message_size(),
        );
        for r in records {
            assert!(pager.push(r).unwrap());
        }
        let page: IndexRecords = pager.page(&folder, 0, false);
        let before = self.sent.len();
        let tick = self.tick(now);
        let out = self.conn.push(tick, &page).unwrap();
        self.apply(now, out);
        self.sent[before..].iter().map(|(_, f)| f.clone()).collect()
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
