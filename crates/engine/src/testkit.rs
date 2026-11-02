// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Unit-test fixtures: a fake storage and context, fixed keys, records, and
//! [`Net`], a few engines connected through fake contexts, every byte
//! delivered at once and every timer fired in deadline order. The simulator's
//! types are not used here: this build holds a second copy of the engine's
//! types, which the simulator's would not match.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::struct_excessive_bools,
    reason = "test code"
)]

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use licketysync_index::{Change, Index, Put};
use licketysync_keys::records::SignedRecord;
use licketysync_keys::secret::{DeviceSeed, WriteSecret};
use licketysync_keys::{DeviceId, FolderKey, Suite, WriteKey};
use licketysync_protocol::record::Kind;

use crate::config::EngineConfig;
use crate::engine::Engine;
use crate::runtime::{
    Clock, Context, Entry, Instant, Peer, PeerId, Randomness, SendError, Storage, StorageError,
    TimerId, Timers, Transport,
};

/// The write key of `seed`.
pub(crate) fn write_key(seed: u8) -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes([seed; 32])).unwrap()
}

/// `seed`'s folder at `tier` (1 write, 2 read, 3 sealed).
pub(crate) fn folder_key(seed: u8, tier: u8) -> FolderKey {
    let w = write_key(seed);
    match tier {
        1 => FolderKey::from(w),
        2 => FolderKey::from(w.read_key()),
        _ => FolderKey::from(w.sealed_key()),
    }
}

/// A config for device `n` holding `folders`, with small chunks.
pub(crate) fn config(n: u8, folders: Vec<FolderKey>) -> EngineConfig {
    let mut c = EngineConfig::new(DeviceSeed::from_bytes([0x40 + n; 32]), folders);
    c.chunk_size = 1024;
    c
}

/// `n` records of `folder_key(seed, 1)`'s folder, each a directory at its
/// own path, written by device `[writer; 32]` through a real index: what a
/// store of that folder holds.
pub(crate) fn records_of(seed: u8, writer: u8, n: usize) -> Vec<SignedRecord> {
    let mut rng = |b: &mut [u8]| b.fill(7);
    let (mut index, _) = Index::create(folder_key(seed, 1), DeviceId([writer; 32]), &mut rng);
    let mut txn = index.begin();
    let changes: Vec<Change> = (0..n)
        .map(|i| {
            Change::Put(Put {
                path: format!("w{writer}/{i}"),
                kind: Kind::Directory,
                size: 0,
                mtime_ns: 0,
                mode: 0,
                chunks: vec![],
                plain_hashes: vec![],
                deleted: false,
            })
        })
        .collect();
    let written = txn
        .write(&changes, 1_767_225_600_000_000, &mut rng)
        .unwrap();
    let hashes: Vec<_> = written.records.iter().map(|(h, _)| *h).collect();
    let out = hashes
        .iter()
        .map(|h| txn.index().signed(h).unwrap().clone())
        .collect();
    txn.abort();
    out
}

/// One valid record of folder 1, the `n`th of writer `[n; 32]`.
pub(crate) fn signed_record(n: u8) -> SignedRecord {
    records_of(1, n, 1).remove(0)
}

/// `r` with another signature: what a store changed at rest holds.
pub(crate) fn with_signature(r: &SignedRecord, signature: [u8; 64]) -> SignedRecord {
    let body = r.body();
    let mut out = vec![0x0a];
    let mut n = body.len();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out.extend_from_slice(body);
    out.extend_from_slice(&[0x12, 64]);
    out.extend_from_slice(&signature);
    SignedRecord::from_bytes(&out).unwrap()
}

/// A storage with the trait's transaction semantics and failure switches.
#[derive(Clone, Debug, Default)]
pub(crate) struct FakeStorage {
    pub(crate) committed: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) staged: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Every put and commit fails with `Full`.
    pub(crate) full: bool,
    /// Puts under this prefix fail with `Full`, this many times more
    /// (`u64::MAX`: always); every other put and every commit succeed.
    pub(crate) fail_prefix: Option<(Vec<u8>, u64)>,
    /// Every put succeeds and every commit fails.
    pub(crate) commit_fails: bool,
    /// Every scan fails.
    pub(crate) scan_fails: bool,
    /// Every get fails.
    pub(crate) get_fails: bool,
    /// Gets under this prefix fail.
    pub(crate) get_fail_prefix: Option<Vec<u8>>,
    pub(crate) commits: u64,
    /// The keys each commit carried, in order.
    pub(crate) commit_log: Vec<BTreeSet<Vec<u8>>>,
}

impl FakeStorage {
    /// Flips one byte of the committed value at `key`, as a disk would.
    pub(crate) fn flip(&mut self, key: &[u8]) {
        let value = self.committed.get_mut(key).expect("a committed value");
        value[0] ^= 1;
    }
}

impl Storage for FakeStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if self.get_fails
            || self
                .get_fail_prefix
                .as_ref()
                .is_some_and(|p| key.starts_with(p))
        {
            return Err(StorageError::Io("get".into()));
        }
        Ok(match self.staged.get(key) {
            Some(v) => v.clone(),
            None => self.committed.get(key).cloned(),
        })
    }
    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError> {
        if self.scan_fails {
            return Err(StorageError::Io("scan".into()));
        }
        let mut all = self.committed.clone();
        for (k, v) in &self.staged {
            match v {
                Some(v) => all.insert(k.clone(), v.clone()),
                None => all.remove(k),
            };
        }
        Ok(all
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect())
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        if self.full {
            return Err(StorageError::Full);
        }
        if let Some((prefix, left)) = &mut self.fail_prefix {
            if key.starts_with(prefix) && *left > 0 {
                *left = left.saturating_sub(1);
                return Err(StorageError::Full);
            }
        }
        self.staged.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), StorageError> {
        self.staged.insert(key.to_vec(), None);
        Ok(())
    }
    fn commit(&mut self) -> Result<(), StorageError> {
        if self.full {
            return Err(StorageError::Full);
        }
        if self.commit_fails {
            return Err(StorageError::Io("commit".into()));
        }
        self.commit_log.push(self.staged.keys().cloned().collect());
        for (k, v) in std::mem::take(&mut self.staged) {
            match v {
                Some(v) => self.committed.insert(k, v),
                None => self.committed.remove(&k),
            };
        }
        self.commits += 1;
        Ok(())
    }
    fn rollback(&mut self) {
        self.staged.clear();
    }
}

/// One engine's view of the world for one call.
#[derive(Debug, Default)]
pub(crate) struct FakeCx {
    pub(crate) id: u64,
    pub(crate) now: u64,
    pub(crate) wall: u64,
    pub(crate) storage: FakeStorage,
    pub(crate) connected: BTreeSet<PeerId>,
    /// Bytes sent this call and not yet taken by the net, per peer.
    pub(crate) outbox: BTreeMap<PeerId, Vec<u8>>,
    /// Unsent bytes the transport reports on top of the outbox.
    pub(crate) extra_unsent: BTreeMap<PeerId, usize>,
    pub(crate) timers: BTreeMap<TimerId, Instant>,
    pub(crate) closed: Vec<PeerId>,
    pub(crate) refused: u64,
    pub(crate) rng: u64,
}

impl Clock for FakeCx {
    fn now(&self) -> Instant {
        Instant::from_nanos(self.now)
    }
    fn wall_time(&self) -> u64 {
        self.wall + self.now / 1_000_000_000
    }
}

impl Timers for FakeCx {
    fn set_timer(&mut self, id: TimerId, at: Instant) {
        self.timers.insert(id, at);
    }
    fn cancel_timer(&mut self, id: TimerId) {
        self.timers.remove(&id);
    }
}

impl Transport for FakeCx {
    fn local_id(&self) -> PeerId {
        PeerId::new(self.id)
    }
    fn send(&mut self, to: PeerId, bytes: Vec<u8>) -> Result<(), SendError> {
        if !self.connected.contains(&to) {
            self.refused += 1;
            return Err(SendError::NotConnected);
        }
        self.outbox.entry(to).or_default().extend_from_slice(&bytes);
        Ok(())
    }
    fn unsent(&self, to: PeerId) -> usize {
        if !self.connected.contains(&to) {
            return 0;
        }
        self.outbox.get(&to).map_or(0, Vec::len) + self.extra_unsent.get(&to).copied().unwrap_or(0)
    }
    fn close(&mut self, to: PeerId) {
        self.connected.remove(&to);
        self.outbox.remove(&to);
        self.closed.push(to);
    }
}

impl Randomness for FakeCx {
    fn fill_random(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.rng = self
                .rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407 + self.id);
            *b = (self.rng >> 56) as u8;
        }
    }
}

impl Context for FakeCx {
    fn storage(&mut self) -> &mut dyn Storage {
        &mut self.storage
    }
}

/// One engine and its context.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) engine: Engine,
    pub(crate) cx: FakeCx,
}

/// The bytes one stream holds back, from the first that carries a frame of
/// one type until [`Net::release`].
#[derive(Debug)]
pub(crate) struct Hold {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) from_frame: licketysync_protocol::frame::MessageType,
    started: bool,
    bytes: Vec<u8>,
}

impl Hold {
    /// Holds `from`'s bytes to `to` from its first frame of `from_frame`.
    pub(crate) fn new(
        from: usize,
        to: usize,
        from_frame: licketysync_protocol::frame::MessageType,
    ) -> Self {
        Self {
            from,
            to,
            from_frame,
            started: false,
            bytes: Vec::new(),
        }
    }

    /// Whether it takes `bytes` (from, to) instead of their delivery.
    fn takes(&mut self, from: usize, to: usize, bytes: &[u8]) -> bool {
        if (from, to) != (self.from, self.to) {
            return false;
        }
        if !self.started {
            use licketysync_protocol::frame::{FrameDecoder, FrameKind};
            let mut decoder = FrameDecoder::new(licketysync_protocol::limits::MAX_MESSAGE_SIZE);
            let mut input = bytes;
            while let Ok(Some(frame)) = decoder.next_frame(&mut input) {
                if frame.kind() == FrameKind::Known(self.from_frame) {
                    self.started = true;
                }
            }
        }
        if self.started {
            self.bytes.extend_from_slice(bytes);
        }
        self.started
    }
}

/// A few engines, ids `0..n`, every byte delivered at once.
#[derive(Debug)]
pub(crate) struct Net {
    pub(crate) nodes: Vec<Node>,
    pub(crate) now: u64,
    /// Every byte delivered, by stream (from, to), in order.
    pub(crate) streams: BTreeMap<(usize, usize), Vec<u8>>,
    /// A stream held back, if any.
    pub(crate) hold: Option<Hold>,
}

impl Net {
    /// Starts one engine per config.
    pub(crate) fn new(configs: Vec<EngineConfig>) -> Self {
        let mut nodes = Vec::new();
        for (i, c) in configs.into_iter().enumerate() {
            let mut node = Node {
                engine: Engine::new(c).unwrap(),
                cx: FakeCx {
                    id: i as u64,
                    wall: 1_767_225_600,
                    rng: i as u64,
                    ..FakeCx::default()
                },
            };
            node.engine.on_start(&mut node.cx);
            nodes.push(node);
        }
        Self {
            nodes,
            now: 0,
            streams: BTreeMap::new(),
            hold: None,
        }
    }

    /// Delivers what the hold kept back, in order, and settles.
    pub(crate) fn release(&mut self) {
        self.release_unsettled();
        self.settle();
    }

    /// Delivers what the hold kept back, in order, without settling: the
    /// receiver's handlers run, and what they send waits for the next
    /// [`Net::settle`], so a test reads the receiver's state in between.
    pub(crate) fn release_unsettled(&mut self) {
        let Some(hold) = self.hold.take() else {
            return;
        };
        let from = PeerId::new(hold.from as u64);
        self.streams
            .entry((hold.from, hold.to))
            .or_default()
            .extend_from_slice(&hold.bytes);
        for piece in hold.bytes.chunks(crate::runtime::MAX_CHUNK) {
            let n = &mut self.nodes[hold.to];
            n.engine.on_message(&mut n.cx, from, piece);
        }
    }

    /// Restarts node `i` over its committed storage, as after a crash.
    pub(crate) fn restart(&mut self, i: usize, config: EngineConfig) {
        let n = &mut self.nodes[i];
        for p in core::mem::take(&mut n.cx.connected) {
            let other = &mut self.nodes[p.as_u64() as usize];
            other.cx.connected.remove(&PeerId::new(i as u64));
            let me = PeerId::new(i as u64);
            other.engine.on_disconnected(&mut other.cx, me);
        }
        let n = &mut self.nodes[i];
        n.cx.storage.staged.clear();
        n.cx.timers.clear();
        n.cx.outbox.clear();
        n.engine = Engine::new(config).unwrap();
        n.engine.on_start(&mut n.cx);
    }

    /// Connects `a` and `b`, both hearing `on_connected`.
    pub(crate) fn connect(&mut self, a: usize, b: usize) {
        let (pa, pb) = (PeerId::new(a as u64), PeerId::new(b as u64));
        self.nodes[a].cx.connected.insert(pb);
        self.nodes[b].cx.connected.insert(pa);
        let n = &mut self.nodes[a];
        n.engine.on_connected(&mut n.cx, pb);
        let n = &mut self.nodes[b];
        n.engine.on_connected(&mut n.cx, pa);
        self.settle();
    }

    /// Disconnects `a` and `b`, both hearing `on_disconnected`.
    pub(crate) fn disconnect(&mut self, a: usize, b: usize) {
        let (pa, pb) = (PeerId::new(a as u64), PeerId::new(b as u64));
        self.nodes[a].cx.connected.remove(&pb);
        self.nodes[b].cx.connected.remove(&pa);
        let n = &mut self.nodes[a];
        n.engine.on_disconnected(&mut n.cx, pb);
        let n = &mut self.nodes[b];
        n.engine.on_disconnected(&mut n.cx, pa);
        self.settle();
    }

    /// Delivers what every engine sent until nobody sends.
    pub(crate) fn settle(&mut self) {
        for _ in 0..100_000 {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                let outbox = core::mem::take(&mut self.nodes[i].cx.outbox);
                for (to, bytes) in outbox {
                    let j = to.as_u64() as usize;
                    let from = PeerId::new(i as u64);
                    if !self.nodes[j].cx.connected.contains(&from) {
                        continue;
                    }
                    if self.hold.as_mut().is_some_and(|h| h.takes(i, j, &bytes)) {
                        continue;
                    }
                    moved = true;
                    self.streams
                        .entry((i, j))
                        .or_default()
                        .extend_from_slice(&bytes);
                    for piece in bytes.chunks(crate::runtime::MAX_CHUNK) {
                        let n = &mut self.nodes[j];
                        n.engine.on_message(&mut n.cx, from, piece);
                    }
                }
                self.hang_ups(i);
            }
            if !moved {
                return;
            }
        }
        panic!("the net did not settle");
    }

    /// The hang-ups node `i` asked for reach both sides.
    fn hang_ups(&mut self, i: usize) {
        for p in core::mem::take(&mut self.nodes[i].cx.closed) {
            let me = PeerId::new(i as u64);
            let n = &mut self.nodes[i];
            n.engine.on_disconnected(&mut n.cx, p);
            let j = p.as_u64() as usize;
            if self.nodes[j].cx.connected.remove(&me) {
                let n = &mut self.nodes[j];
                n.engine.on_disconnected(&mut n.cx, me);
            }
        }
    }

    /// Fires every timer due by `now + d`, in deadline order, settling after
    /// each.
    pub(crate) fn advance(&mut self, d: Duration) {
        let end = self.now + d.as_nanos() as u64;
        loop {
            let next = self
                .nodes
                .iter()
                .enumerate()
                .flat_map(|(i, n)| {
                    n.cx.timers
                        .iter()
                        .map(move |(id, at)| (at.as_nanos(), i, *id))
                })
                .filter(|(at, _, _)| *at <= end)
                .min();
            let Some((at, i, id)) = next else {
                break;
            };
            self.now = self.now.max(at);
            for n in &mut self.nodes {
                n.cx.now = self.now;
            }
            let n = &mut self.nodes[i];
            n.cx.timers.remove(&id);
            n.engine.on_timer(&mut n.cx, id);
            self.settle();
        }
        self.now = end;
        for n in &mut self.nodes {
            n.cx.now = end;
        }
        self.settle();
    }

    /// The Status messages `from` sent `to`, in order.
    pub(crate) fn statuses(
        &self,
        from: usize,
        to: usize,
    ) -> Vec<licketysync_protocol::messages::Status> {
        use licketysync_protocol::frame::{FrameDecoder, FrameKind, MessageType};
        use licketysync_protocol::Parse;
        let bytes = self.streams.get(&(from, to)).cloned().unwrap_or_default();
        let mut decoder = FrameDecoder::new(licketysync_protocol::limits::MAX_MESSAGE_SIZE);
        let mut input = bytes.as_slice();
        let mut out = Vec::new();
        while let Ok(Some(frame)) = decoder.next_frame(&mut input) {
            if frame.kind() == FrameKind::Known(MessageType::Status) {
                out.push(licketysync_protocol::messages::Status::parse(frame.body()).unwrap());
            }
        }
        out
    }

    /// Runs `f` as a call of node `i` (a write, say), then settles.
    pub(crate) fn with<R>(&mut self, i: usize, f: impl FnOnce(&mut Engine, &mut FakeCx) -> R) -> R {
        let n = &mut self.nodes[i];
        let r = f(&mut n.engine, &mut n.cx);
        self.settle();
        r
    }
}
