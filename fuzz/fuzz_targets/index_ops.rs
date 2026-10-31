#![no_main]
//! The index crate from fuzzed stored state and fuzzed operations (the index
//! security review's NIT 9, under `protocol.md` 4.4, 4.5 and 4.7): one
//! device's index at a tier the input picks, under the test vectors' folder
//! (write secret `10 11 .. 2f`).
//!
//! The input is a byte stream: a header (the tier, then this device's ID),
//! then operations, each an opcode byte and its operands. A byte read past
//! the end is 0. The operations:
//!
//! - build a record into the pool (at most 32): an index record around
//!   fuzz-chosen sealed metadata (path, the path its tag is of, kind,
//!   deleted and tree marks, size, chunks, plain hashes, device, counter, a
//!   vector of up to three entries, names of earlier records), or a cleanup
//!   (device, counter, one or two groups with a `because` and names of
//!   earlier records), each genuine, forged (a signature bit flipped) or with
//!   a garbage signature;
//! - before the folder opens, stage stored state: a pool record with a
//!   local sequence number (the next one, 0, a repeat, `MAX_LOCAL_SEQ` or
//!   past it), a record kept only as a base, a base slot (for any record,
//!   at any path, so possibly one at another path), the metadata (a high-
//!   water mark, a next local sequence number of 0, past `MAX_LOCAL_SEQ` or
//!   `u64::MAX`, an epoch) and per-peer state (times past or ahead of the
//!   clock);
//! - open the folder from the stored state (the open's changes committed);
//! - deliver a pool record from a peer, write (a file, a tombstone, a tree
//!   delete or a rename), set or clear a base, end a round, record a round's
//!   end or a counted push: each in one transaction, finished, then
//!   committed through the store or dropped;
//! - move the clock (days ahead, a year ahead, or a year back);
//! - make the store's next commit crash between its records and its
//!   removals (the store then reopens, as a store that cannot stage
//!   atomically does after a failure);
//! - reopen from the store.
//!
//! What must hold: no panic; a dropped transaction leaves every public view
//! of the index exactly as before; a reopen of a committed store gives the
//! same records and fingerprint; the local sequence never passes
//! `MAX_LOCAL_SEQ`; and every record held is in the local-sequence order.

use std::fmt::Write as _;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_index::{
    Arrival, Change, ChangeSet, Commit, Index, MemoryStore, PeerState, Place, Put, Store,
    StoredMeta,
};
use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::sealed_meta::RecordKeys;
use licketysync_keys::{
    CipherHash, DeviceId, FolderKey, RecordHash, Suite, Tier, WriteKey, WriteSecret,
};
use licketysync_protocol::connection::{FolderMemory, NoteBudget};
use licketysync_protocol::limits::{DAY_US, MAX_COUNTER, MAX_LOCAL_SEQ};
use licketysync_protocol::messages::{
    ChunkRef, CleanupGroup, CleanupMeta, CleanupRecord, IndexRecord, SealedMeta, VectorEntry,
};
use licketysync_protocol::record::{Chunk, Kind, Record};
use prost::Message as _;

const PATHS: [&str; 8] = ["a", "b", "d", "d/x", "d/y", "d/x/z", "d-x", "e"];
const DEVICES: [u8; 5] = [1, 2, 3, 4, 9];
/// The fixtures' clock: 2027-01-15 in microseconds since the epoch.
const T0: u64 = 1_800_000_000_000_000;
const SEC: u64 = 1_000_000;
const MAX_POOL: usize = 32;
const MAX_OPS: usize = 160;

fn new_write_key() -> WriteKey {
    let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1")
}

fn write_key() -> &'static (WriteKey, RecordKeys) {
    static K: OnceLock<(WriteKey, RecordKeys)> = OnceLock::new();
    K.get_or_init(|| {
        let w = new_write_key();
        let keys = w.record_keys();
        (w, keys)
    })
}

fn folder_key(tier: Tier) -> FolderKey {
    FolderKey::from(new_write_key())
        .lowered(tier)
        .expect("a lower tier")
}

fn dev(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

/// The input, read a byte at a time.
struct In<'a> {
    data: &'a [u8],
    at: usize,
}

impl In<'_> {
    fn b(&mut self) -> u8 {
        let v = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        v
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.b(), self.b()])
    }

    fn done(&self) -> bool {
        self.at >= self.data.len()
    }

    fn path(&mut self) -> &'static str {
        PATHS[usize::from(self.b()) % PATHS.len()]
    }

    fn device(&mut self) -> DeviceId {
        dev(DEVICES[usize::from(self.b()) % DEVICES.len()])
    }

    /// A counter: mostly near the clock, sometimes at an edge.
    fn counter(&mut self) -> u64 {
        match self.b() % 8 {
            0 => 0,
            1 => MAX_COUNTER,
            2 => MAX_COUNTER + 1,
            3 => T0 + 400 * DAY_US,
            4 => T0.saturating_sub(400 * DAY_US),
            _ => T0 + u64::from(self.u16()) * SEC,
        }
    }
}

/// A deterministic source of randomness for seals' nonces and epochs.
struct Rng(u64);

impl Rng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fn with_signature(r: &SignedRecord, sig: &[u8]) -> Option<SignedRecord> {
    let mut out = Vec::new();
    prost::encoding::bytes::encode(1, &r.body().to_vec(), &mut out);
    prost::encoding::bytes::encode(2, &sig.to_vec(), &mut out);
    SignedRecord::from_bytes(&out).ok()
}

/// Genuine, forged or with a garbage signature, as the input says.
fn variant(r: SignedRecord, how: u8) -> Option<SignedRecord> {
    match how % 4 {
        1 => {
            let mut sig = *r.signature().as_bytes();
            sig[0] ^= 1;
            with_signature(&r, &sig)
        }
        2 => with_signature(&r, &[0x5a; 64]),
        _ => Some(r),
    }
}

fn names(i: &mut In<'_>, pool: &[SignedRecord], n: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = (0..n)
        .map(|_| {
            let r = i.b();
            if pool.is_empty() || r == 0xff {
                vec![r; 32]
            } else {
                pool[usize::from(r) % pool.len()].hash().0.to_vec()
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn index_record(i: &mut In<'_>, pool: &[SignedRecord], rng: &mut Rng) -> Option<SignedRecord> {
    let (w, keys) = write_key();
    let path = i.path();
    let tag_path = if i.b() % 8 == 7 { i.path() } else { path };
    let kind = u32::from(i.b() % 4);
    let flags = i.b();
    let deleted = flags & 1 != 0;
    let tree = flags & 2 != 0;
    let n_chunks = usize::from((flags >> 2) & 3);
    let n_hashes = if flags & 16 != 0 {
        n_chunks + 1
    } else {
        n_chunks
    };
    let size = if flags & 32 != 0 {
        0
    } else {
        u64::from(i.b()) + 1
    };
    let device = i.device();
    let counter = i.counter();
    let n_vec = usize::from(i.b() % 4);
    let vector: Vec<VectorEntry> = {
        let mut v: Vec<(DeviceId, u64)> = (0..n_vec)
            .map(|_| (i.device(), T0 + u64::from(i.b()) * SEC))
            .collect();
        v.sort();
        v.dedup_by_key(|e| e.0);
        v.into_iter()
            .map(|(d, c)| VectorEntry {
                device_id: d.0.to_vec(),
                counter: c,
            })
            .collect()
    };
    let n_names = usize::from(i.b() % 3);
    let replaces = names(i, pool, n_names);
    // A stored length is a padded size plus 40 (46 is the least); bit 7 of
    // the flags makes it one step 1 refuses.
    let stored_len = if flags & 0x80 != 0 { 256 } else { 46 };
    let chunks: Vec<ChunkRef> = (0..n_chunks)
        .map(|_| ChunkRef {
            cipher_hash: vec![i.b(); 32],
            stored_len,
        })
        .collect();
    let meta = SealedMeta {
        path: path.into(),
        kind,
        size,
        mtime_ns: 5,
        mode: 0o644,
        plain_hashes: (0..n_hashes).map(|k| vec![k as u8; 32]).collect(),
        written_at: T0,
        device_id: device.0.to_vec(),
        counter,
        vector,
        deleted,
        tree,
    };
    let tag = keys.path_tag(tag_path);
    let sealed = keys
        .seal_index_meta(&tag, &meta.encode_to_vec(), &mut |b: &mut [u8]| rng.fill(b))
        .ok()?;
    let body = IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: w.verifier().folder_id().0.to_vec(),
        chunks,
        sealed,
        path_tag: tag.0.to_vec(),
        replaces,
    };
    let r = w.sign_index_record(body.encode_to_vec()).ok()?;
    variant(r, i.b())
}

fn cleanup_record(i: &mut In<'_>, pool: &[SignedRecord], rng: &mut Rng) -> Option<SignedRecord> {
    let (w, keys) = write_key();
    let device = i.device();
    let counter = i.counter();
    let meta = CleanupMeta {
        device_id: device.0.to_vec(),
        counter,
    };
    let sealed = keys
        .seal_cleanup_meta(&meta.encode_to_vec(), &mut |b: &mut [u8]| rng.fill(b))
        .ok()?;
    let n_groups = 1 + usize::from(i.b() % 2);
    let groups = (0..n_groups)
        .map(|_| {
            let because = match i.b() {
                0 => Vec::new(),
                r if pool.is_empty() => vec![r; 32],
                r => pool[usize::from(r) % pool.len()].hash().0.to_vec(),
            };
            let n = 1 + usize::from(i.b() % 3);
            CleanupGroup {
                because,
                forget: names(i, pool, n),
            }
        })
        .collect();
    let body = CleanupRecord {
        suite: 1,
        record_type: 17,
        folder_id: w.verifier().folder_id().0.to_vec(),
        groups,
        sealed,
    };
    let r = w.sign_cleanup_record(body.encode_to_vec()).ok()?;
    variant(r, i.b())
}

/// Every public view of an index, for comparing before and after.
fn snapshot(ix: &Index) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "len {} seq {} epoch {} hw {} g {} extra {}",
        ix.len(),
        ix.local_seq(),
        ix.epoch(),
        ix.hw(),
        ix.folder_time(),
        ix.extra_versions()
    );
    for r in ix.records() {
        let _ = write!(s, "\n{r:?}");
    }
    let mut fp = Vec::new();
    ix.fingerprint(&mut |b| fp.extend_from_slice(b));
    let _ = write!(s, "\nfp {fp:?}\nroot {:?}", ix.root_digest());
    for p in PATHS {
        let _ = write!(
            s,
            "\n{p}: {:?} {:?} {:?}",
            ix.bases(p),
            ix.current(p),
            ix.path(p)
        );
    }
    for d in DEVICES {
        let _ = write!(s, "\npeer {d}: {:?}", ix.peer(&dev(d)));
    }
    let _ = write!(s, "\nwanted {:?}", ix.wanted());
    s
}

/// What a reopen must give again: the records and the fingerprint.
fn held(ix: &Index) -> (Vec<String>, Vec<u8>) {
    let records = ix.records().map(|r| format!("{r:?}")).collect();
    let mut fp = Vec::new();
    ix.fingerprint(&mut |b| fp.extend_from_slice(b));
    (records, fp)
}

fn invariants(ix: &Index) {
    assert!(
        ix.local_seq() <= MAX_LOCAL_SEQ,
        "local sequence {} past MAX_LOCAL_SEQ",
        ix.local_seq()
    );
    assert_eq!(
        ix.records().count(),
        ix.len(),
        "every record held is in the local-sequence order"
    );
}

struct World {
    tier: Tier,
    own: DeviceId,
    ix: Option<Index>,
    store: MemoryStore,
    pre: ChangeSet,
    last_seq: u64,
    pool: Vec<SignedRecord>,
    clock: u64,
    rng: Rng,
    memory: FolderMemory,
    notes: NoteBudget,
}

impl World {
    /// Opens the folder from the store, the staged stored state first; the
    /// open's changes are committed. A folder whose records lie more than a
    /// year ahead of the clock does not open.
    fn open(&mut self) {
        let pre = core::mem::take(&mut self.pre);
        if !pre.is_empty() {
            let _ = self.store.commit(&pre);
        }
        let Ok(stored) = self.store.load() else {
            return;
        };
        let rng = &mut self.rng;
        let (ix, report) = Index::open(
            folder_key(self.tier),
            self.own,
            stored,
            self.clock,
            &mut |b: &mut [u8]| rng.fill(b),
        );
        if report.opens_at.is_some() {
            self.ix = None;
            return;
        }
        if self.store.commit(&report.changes).is_err() {
            self.ix = None;
            return;
        }
        invariants(&ix);
        self.ix = Some(ix);
    }

    fn ensure_open(&mut self) -> bool {
        if self.ix.is_none() {
            self.open();
        }
        self.ix.is_some()
    }

    /// Runs one handler's change in a transaction: `stage` stages it and says
    /// whether it succeeded; then the transaction is committed through the
    /// store (`commit`) or dropped, which must leave every view as it was. A
    /// commit the store fails is dropped too, and the store reopens.
    fn handler(
        &mut self,
        commit: bool,
        stage: impl FnOnce(
            &mut licketysync_index::Txn<'_>,
            &mut Rng,
            &mut FolderMemory,
            &mut NoteBudget,
            u64,
        ) -> bool,
    ) {
        let Some(ix) = self.ix.as_mut() else { return };
        let before = snapshot(ix);
        let clock = self.clock;
        let mut txn = ix.begin();
        let ok = stage(
            &mut txn,
            &mut self.rng,
            &mut self.memory,
            &mut self.notes,
            clock,
        );
        let (changes, pending) = txn.finish();
        let mut reopen = false;
        if ok && commit {
            match self.store.commit(&changes) {
                Ok(()) => pending.commit(),
                Err(_) => {
                    drop(pending);
                    reopen = true;
                }
            }
        } else {
            drop(pending);
            let after = snapshot(self.ix.as_ref().expect("open"));
            assert_eq!(
                before, after,
                "a dropped transaction leaves the index as it was"
            );
        }
        if let Some(ix) = self.ix.as_ref() {
            invariants(ix);
        }
        if reopen {
            self.ix = None;
            self.open();
        }
    }

    fn reopen_and_compare(&mut self) {
        let Some(ix) = self.ix.as_ref() else {
            self.open();
            return;
        };
        let want = held(ix);
        let Ok(stored) = self.store.load() else {
            return;
        };
        let rng = &mut self.rng;
        let (again, report) = Index::open(
            folder_key(self.tier),
            self.own,
            stored,
            self.clock,
            &mut |b: &mut [u8]| rng.fill(b),
        );
        if report.opens_at.is_some() {
            return;
        }
        assert_eq!(
            held(&again),
            want,
            "a reopen of a committed store gives the same index"
        );
        invariants(&again);
        if self.store.commit(&report.changes).is_ok() {
            self.ix = Some(again);
        }
    }

    fn step(&mut self, i: &mut In<'_>) {
        match i.b() % 16 {
            0 => {
                if self.pool.len() < MAX_POOL {
                    if let Some(r) = index_record(i, &self.pool, &mut self.rng) {
                        self.pool.push(r);
                    }
                }
            }
            1 => {
                if self.pool.len() < MAX_POOL {
                    if let Some(r) = cleanup_record(i, &self.pool, &mut self.rng) {
                        self.pool.push(r);
                    }
                }
            }
            2 => {
                // A stored record with a local sequence number.
                let (r, how) = (i.b(), i.b());
                if self.ix.is_none() && !self.pool.is_empty() {
                    let rec = self.pool[usize::from(r) % self.pool.len()].clone();
                    let seq = match how % 6 {
                        0 => 0,
                        1 => self.last_seq,
                        2 => MAX_LOCAL_SEQ,
                        3 => MAX_LOCAL_SEQ + 1,
                        _ => self.last_seq + 1,
                    };
                    self.last_seq = self.last_seq.max(seq.min(MAX_LOCAL_SEQ));
                    self.pre.put.push((rec, seq));
                }
            }
            3 => {
                let r = i.b();
                if self.ix.is_none() && !self.pool.is_empty() {
                    let rec = self.pool[usize::from(r) % self.pool.len()].clone();
                    self.pre.base_only_put.push(rec);
                }
            }
            4 => {
                // A stored base slot, for any record at any path.
                let (p, copy, r) = (i.path(), i.b(), i.b());
                if self.ix.is_none() && !self.pool.is_empty() {
                    let place = if copy % 4 == 3 {
                        Place::Copy("c".into())
                    } else {
                        Place::Path
                    };
                    let hash = self.pool[usize::from(r) % self.pool.len()].hash();
                    let tag = write_key().1.path_tag(p);
                    self.pre.bases.push(((tag, place), Some(hash)));
                }
            }
            5 => {
                let (hw, next, epoch) = (i.counter(), i.b(), i.b());
                if self.ix.is_none() {
                    let next_seq = match next % 5 {
                        0 => 0,
                        1 => MAX_LOCAL_SEQ + 1,
                        2 => MAX_LOCAL_SEQ + 2,
                        3 => u64::MAX,
                        _ => self.last_seq + 1,
                    };
                    self.pre.meta = Some(StoredMeta {
                        hw,
                        next_seq,
                        epoch: u64::from(epoch),
                    });
                }
            }
            6 => {
                let (d, ended, window, names) = (i.device(), i.counter(), i.counter(), i.b());
                if self.ix.is_none() {
                    let state = PeerState {
                        epoch: 1,
                        cursor: u64::from(names),
                        round_ended_us: ended,
                        caught_up: names % 2 == 0,
                        names_window_us: window,
                        names: u64::from(names),
                    };
                    self.pre.peers.push((d, Some(state)));
                }
            }
            7 => self.open(),
            8 => {
                let (r, peer, commit) = (i.b(), i.device(), i.b() % 4 != 0);
                if self.pool.is_empty() || !self.ensure_open() {
                    return;
                }
                let signed = self.pool[usize::from(r) % self.pool.len()].clone();
                let Ok(record) = Record::parse(signed, write_key().0.verifier()) else {
                    return;
                };
                self.handler(commit, |txn, rng, memory, notes, clock| {
                    let mut fill = |b: &mut [u8]| rng.fill(b);
                    let mut arrival = Arrival {
                        peer,
                        memory,
                        notes,
                        clock_us: clock,
                        rng: &mut fill,
                    };
                    txn.accept(record, &mut arrival).is_ok()
                });
            }
            9 => {
                let (how, p, q, content, commit) =
                    (i.b(), i.path(), i.path(), i.b(), i.b() % 4 != 0);
                if !self.ensure_open() {
                    return;
                }
                let file = |path: &str, content: u8| Put {
                    path: path.into(),
                    kind: Kind::File,
                    size: u64::from(content) + 1,
                    mtime_ns: i64::from(content),
                    mode: 0o644,
                    chunks: vec![Chunk {
                        cipher_hash: CipherHash([content; 32]),
                        stored_len: 46,
                    }],
                    plain_hashes: vec![PlainHash([content; 32])],
                    deleted: false,
                };
                let change = match how % 4 {
                    0 => Change::Put(file(p, content)),
                    1 => Change::Put(Put {
                        path: p.into(),
                        kind: Kind::File,
                        size: 0,
                        mtime_ns: 7,
                        mode: 0,
                        chunks: Vec::new(),
                        plain_hashes: Vec::new(),
                        deleted: true,
                    }),
                    2 => Change::TreeDelete {
                        path: if content % 2 == 0 {
                            "d".into()
                        } else {
                            "d/x".into()
                        },
                        mtime_ns: 9,
                    },
                    _ => Change::Rename {
                        from: p.into(),
                        to: file(q, content),
                    },
                };
                self.handler(commit, |txn, rng, _, _, clock| {
                    txn.write(&[change], clock, &mut |b: &mut [u8]| rng.fill(b))
                        .is_ok()
                });
            }
            10 => {
                let (p, r, commit) = (i.path(), i.b(), i.b() % 4 != 0);
                if !self.ensure_open() {
                    return;
                }
                let hash: Option<RecordHash> = if r == 0xff || self.pool.is_empty() {
                    None
                } else {
                    Some(self.pool[usize::from(r) % self.pool.len()].hash())
                };
                self.handler(commit, |txn, _, _, _, _| {
                    txn.set_base(p, Place::Path, hash).is_ok()
                });
            }
            11 => {
                let commit = i.b() % 4 != 0;
                if !self.ensure_open() {
                    return;
                }
                self.handler(commit, |txn, rng, _, _, clock| {
                    txn.end_round(clock, &mut |b: &mut [u8]| rng.fill(b))
                        .is_ok()
                });
                self.memory = FolderMemory::default();
            }
            12 => {
                let (peer, how, cursor, commit) = (i.device(), i.b(), i.b(), i.b() % 4 != 0);
                if !self.ensure_open() {
                    return;
                }
                self.handler(commit, |txn, _, _, _, clock| {
                    if how % 3 == 2 {
                        txn.cursor_advanced(peer, 1, u64::from(cursor));
                    } else {
                        let c = (how % 3 == 1).then_some((1, u64::from(cursor)));
                        txn.round_ended(peer, how % 2 == 0, c, clock);
                    }
                    true
                });
            }
            13 => {
                let d = i.b();
                self.clock = match d % 8 {
                    0 => self.clock + 366 * DAY_US,
                    1 => self.clock.saturating_sub(400 * DAY_US),
                    _ => self.clock + u64::from(d) * DAY_US,
                };
                self.notes = NoteBudget::for_tests();
            }
            14 => self.store.mode = Commit::CrashBeforeRemovals,
            _ => self.reopen_and_compare(),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut i = In { data, at: 0 };
    let tier = match i.b() % 3 {
        0 => Tier::Write,
        1 => Tier::Read,
        _ => Tier::Sealed,
    };
    let own = i.device();
    let mut w = World {
        tier,
        own,
        ix: None,
        store: MemoryStore::new(),
        pre: ChangeSet::default(),
        last_seq: 0,
        pool: Vec::new(),
        clock: T0,
        rng: Rng(data.len() as u64),
        memory: FolderMemory::default(),
        notes: NoteBudget::for_tests(),
    };
    let mut ops = 0;
    while !i.done() && ops < MAX_OPS {
        w.step(&mut i);
        ops += 1;
    }
    if w.ensure_open() {
        w.reopen_and_compare();
    }
});
