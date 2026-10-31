// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fixtures: the keys crate's fixed folder at each tier, a device ([`Dev`])
//! holding one index over a memory store with its own clock and randomness,
//! which writes, accepts, applies heads to its disk (the engine's naming of
//! bases), reopens and ends rounds as the engine would, each change one
//! transaction persisted in one commit; records forged with any sealed
//! metadata (the writer faults a writer's draft refuses to sign); and an
//! exchange between two devices through the index's own digests and serving
//! (the protocol's `Connection` drives the real one), with the stale-copy
//! notes and the cleanups a write holder issues at a round's end.

use std::collections::BTreeSet;

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::secret::WriteSecret;
use licketysync_keys::{
    CipherHash, DeviceId, FolderKey, PathTag, RecordHash, SetDigest, Suite, Tier, WriteKey,
};
use licketysync_protocol::connection::{FolderMemory, Judgement, NoteBudget, ReconcileServe};
use licketysync_protocol::exchange::Prefix;
use licketysync_protocol::limits::{DAY_US, DEFAULT_MESSAGE_SIZE, MAX_RECONCILE_PASSES};
use licketysync_protocol::messages::{
    ChunkRef, CleanupGroup, CleanupMeta, CleanupRecord, IndexRecord, ReconcileOutcome, SealedMeta,
    VectorEntry,
};
use licketysync_protocol::record::{Chunk, Kind, Record};
use licketysync_protocol::Cause;
use prost::Message as _;

use crate::{
    Accepted, Change, Index, MemoryStore, OpenReport, Place, Put, Store, WriteError, Written,
};

/// `n, n+1, … n+31`.
pub(crate) fn fixed32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

/// The write key of the keys crate's vectors: write secret `10 11 .. 2f`.
pub(crate) fn write_key() -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(0x10))).unwrap()
}

/// The folder key at `tier`.
pub(crate) fn folder_key(tier: Tier) -> FolderKey {
    FolderKey::from(write_key()).lowered(tier).unwrap()
}

/// Another folder's write key.
pub(crate) fn other_key() -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(0x40))).unwrap()
}

/// A device ID: 32 bytes of `n`.
pub(crate) fn dev(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

/// The clock of the fixtures: 2027-01-15 in microseconds since the epoch.
pub(crate) const T0: u64 = 1_800_000_000_000_000;

/// One second in microseconds.
pub(crate) const SEC: u64 = 1_000_000;

/// One day in microseconds.
pub(crate) const DAY: u64 = DAY_US;

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

/// The content a fixture file of `content` holds: one chunk and its
/// plaintext hash, both named after `content`.
pub(crate) fn file(path: &str, content: u8, mtime_ns: i64) -> Put {
    Put {
        path: path.into(),
        kind: Kind::File,
        size: 1,
        mtime_ns,
        mode: 0o644,
        chunks: vec![Chunk {
            cipher_hash: CipherHash([content; 32]),
            stored_len: 46,
        }],
        plain_hashes: vec![PlainHash([content; 32])],
        deleted: false,
    }
}

/// A directory version at `path`.
pub(crate) fn dir(path: &str, mtime_ns: i64) -> Put {
    Put {
        path: path.into(),
        kind: Kind::Directory,
        size: 0,
        mtime_ns,
        mode: 0o755,
        chunks: vec![],
        plain_hashes: vec![],
        deleted: false,
    }
}

/// A tombstone of a `kind` at `path`.
pub(crate) fn tombstone(path: &str, kind: Kind, mtime_ns: i64) -> Put {
    Put {
        path: path.into(),
        kind,
        size: 0,
        mtime_ns,
        mode: 0,
        chunks: vec![],
        plain_hashes: vec![],
        deleted: true,
    }
}

/// A device: one folder's index at a tier, over a memory store, with its own
/// wall clock (microseconds), randomness, connection memories and the
/// `mtime_ns` its next fixture write takes.
pub(crate) struct Dev {
    pub(crate) ix: Index,
    pub(crate) store: MemoryStore,
    pub(crate) rng: Rng,
    pub(crate) clock: u64,
    pub(crate) memory: FolderMemory,
    /// The connection's note budget; the tests give each round a new one.
    pub(crate) notes: NoteBudget,
    pub(crate) mtime: i64,
    /// Every record this device signed or accepted, held or not any more.
    pub(crate) archive: std::collections::BTreeMap<RecordHash, SignedRecord>,
}

impl Dev {
    /// A new device `own` at `tier`, its store made now (the first epoch
    /// committed).
    pub(crate) fn new(tier: Tier, own: u8) -> Self {
        let mut rng = Rng(u64::from(own) << 16 | 7);
        let (ix, created) = Index::create(folder_key(tier), dev(own), &mut |b| rng.fill(b));
        let mut store = MemoryStore::new();
        store.commit(&created).unwrap();
        Self {
            ix,
            store,
            rng,
            clock: T0,
            memory: FolderMemory::default(),
            notes: NoteBudget::for_tests(),
            mtime: 1_000,
            archive: std::collections::BTreeMap::new(),
        }
    }

    pub(crate) fn writer(own: u8) -> Self {
        Self::new(Tier::Write, own)
    }

    pub(crate) fn reader(own: u8) -> Self {
        Self::new(Tier::Read, own)
    }

    pub(crate) fn sealed(own: u8) -> Self {
        Self::new(Tier::Sealed, own)
    }

    /// This device's ID.
    pub(crate) fn id(&self) -> DeviceId {
        self.ix.own()
    }

    /// Writes `changes` in one commit at this device's clock.
    pub(crate) fn write(&mut self, changes: &[Change]) -> Result<Written, WriteError> {
        let Self {
            ix,
            store,
            rng,
            clock,
            archive,
            ..
        } = self;
        let mut txn = ix.begin();
        let written = txn.write(changes, *clock, &mut |b| rng.fill(b))?;
        for (h, _) in &written.records {
            if let Some(r) = txn.index().s.base_record(h) {
                archive.insert(*h, r.signed().clone());
            }
        }
        let (changes, pending) = txn.finish();
        store.commit(&changes).unwrap();
        pending.commit();
        let recs = records_of(archive, &written.records);
        check_drops(&self.ix, &self.archive, &recs, &written.dropped, "write");
        Ok(written)
    }

    fn next_mtime(&mut self) -> i64 {
        self.mtime += 1_000;
        self.mtime
    }

    /// Writes one file version of `content` at `path`; its record hash.
    pub(crate) fn put(&mut self, path: &str, content: u8) -> RecordHash {
        let m = self.next_mtime();
        self.write(&[Change::Put(file(path, content, m))])
            .unwrap()
            .records[0]
            .0
    }

    /// Writes a directory version at `path`.
    pub(crate) fn mkdir(&mut self, path: &str) -> RecordHash {
        let m = self.next_mtime();
        self.write(&[Change::Put(dir(path, m))]).unwrap().records[0].0
    }

    /// Deletes `path` with a tombstone of the kind its base has.
    pub(crate) fn delete(&mut self, path: &str) -> RecordHash {
        let kind = self.ix.current(path).map_or(Kind::File, |c| c.kind);
        let m = self.next_mtime();
        self.write(&[Change::Put(tombstone(path, kind, m))])
            .unwrap()
            .records[0]
            .0
    }

    /// Renames `from` to `to`, its content kept.
    pub(crate) fn rename(&mut self, from: &str, to: &str) -> Written {
        let c = self.ix.current(from).unwrap();
        let m = self.next_mtime();
        self.write(&[Change::Rename {
            from: from.into(),
            to: Put {
                path: to.into(),
                kind: c.kind,
                size: c.size,
                mtime_ns: m,
                mode: 0o644,
                chunks: c.chunks,
                plain_hashes: c.plain_hashes,
                deleted: false,
            },
        }])
        .unwrap()
    }

    /// A tree delete of `path`, with its tombstones and cleanup.
    pub(crate) fn tree_delete(&mut self, path: &str) -> Written {
        let m = self.next_mtime();
        self.write(&[Change::TreeDelete {
            path: path.into(),
            mtime_ns: m,
        }])
        .unwrap()
    }

    /// Accepts one record from `peer` in one transaction, persisted in one
    /// commit; a refusal that closes stages nothing.
    pub(crate) fn accept_from(
        &mut self,
        peer: DeviceId,
        signed: &SignedRecord,
    ) -> Result<Accepted, Cause> {
        let record = Record::parse(signed.clone(), self.ix.key().verifier()).unwrap();
        self.archive.insert(signed.hash(), signed.clone());
        let Self {
            ix,
            store,
            rng,
            clock,
            memory,
            notes,
            ..
        } = self;
        let mut txn = ix.begin();
        let mut fill = |b: &mut [u8]| rng.fill(b);
        let mut arrival = crate::Arrival {
            peer,
            memory,
            notes,
            clock_us: *clock,
            rng: &mut fill,
        };
        let out = txn.accept(record.clone(), &mut arrival)?;
        let (changes, pending) = txn.finish();
        store.commit(&changes).unwrap();
        pending.commit();
        check_drops(&self.ix, &self.archive, &[record], &out.dropped, "accept");
        Ok(out)
    }

    /// Accepts a record from a peer of ID 0xee.
    pub(crate) fn accept(&mut self, signed: &SignedRecord) -> Result<Accepted, Cause> {
        self.accept_from(dev(0xee), signed)
    }

    /// The judgement of one record from a peer.
    pub(crate) fn judge(&mut self, signed: &SignedRecord) -> Result<Judgement, Cause> {
        self.accept(signed).map(|a| a.judgement)
    }

    /// Accepts the records `hashes` of `from`, in that order.
    pub(crate) fn take(&mut self, from: &Dev, hashes: &[RecordHash]) -> Vec<Judgement> {
        hashes
            .iter()
            .map(|h| {
                self.accept_from(from.id(), from.signed(h))
                    .unwrap()
                    .judgement
            })
            .collect()
    }

    /// Accepts every record `from` holds, in its local-sequence order.
    pub(crate) fn take_all(&mut self, from: &Dev) -> Vec<Judgement> {
        let hashes: Vec<RecordHash> = from.ix.records().map(|r| r.hash).collect();
        self.take(from, &hashes)
    }

    /// The envelope of a record this device signed or received, held or not.
    pub(crate) fn signed(&self, hash: &RecordHash) -> &SignedRecord {
        self.ix
            .signed(hash)
            .or_else(|| self.archive.get(hash))
            .unwrap()
    }

    /// Every record held.
    pub(crate) fn all(&self) -> BTreeSet<RecordHash> {
        self.ix.records().map(|r| r.hash).collect()
    }

    /// Whether a record is held.
    pub(crate) fn holds(&self, hash: &RecordHash) -> bool {
        self.ix.record(hash).is_some()
    }

    /// The heads at `path`, in display order.
    pub(crate) fn heads(&self, path: &str) -> Vec<RecordHash> {
        self.ix
            .path(path)
            .map(|v| v.heads.iter().map(|h| h.hash).collect())
            .unwrap_or_default()
    }

    /// The engine applies the heads at `path` to its disk: the first in
    /// display order at the path itself (a version, or the tombstone it
    /// removed the path for), and each conflict copy beside it; a slot of a
    /// copy no longer a conflict is cleared.
    pub(crate) fn apply(&mut self, path: &str) {
        let Some(view) = self.ix.path(path) else {
            return;
        };
        let Self { ix, store, .. } = self;
        let mut txn = ix.begin();
        for (place, _) in txn.index().bases(path) {
            if let Place::Copy(_) = place {
                txn.set_base(path, place, None).unwrap();
            }
        }
        if let Some(first) = view.current.or_else(|| view.heads.first().map(|h| h.hash)) {
            txn.set_base(path, Place::Path, Some(first)).unwrap();
        }
        for c in &view.conflict_copies {
            txn.set_base(path, Place::Copy(hex::encode(&c.0[..4])), Some(*c))
                .unwrap();
        }
        let (changes, pending) = txn.finish();
        store.commit(&changes).unwrap();
        pending.commit();
    }

    /// The engine applies every path's heads to its disk.
    pub(crate) fn apply_all(&mut self) {
        let paths: Vec<String> = self.ix.paths().map(str::to_owned).collect();
        for p in paths {
            self.apply(&p);
        }
    }

    /// Reopens the index from the store at this device's clock.
    pub(crate) fn reopen(&mut self) -> OpenReport {
        let key = folder_key(self.ix.tier());
        let own = self.ix.own();
        let stored = self.store.load().unwrap();
        let mut rng = self.rng.clone();
        let (ix, report) = Index::open(key, own, stored, self.clock, &mut |b| rng.fill(b));
        self.rng = rng;
        self.ix = ix;
        self.store.commit(&report.changes).unwrap();
        report
    }

    /// The end of a round of this side's with a peer (a write holder issues
    /// its cleanups); what it wrote.
    pub(crate) fn end_round(&mut self) -> Written {
        let Self {
            ix,
            store,
            rng,
            clock,
            memory,
            notes,
            archive,
            ..
        } = self;
        let mut txn = ix.begin();
        let w = txn.end_round(*clock, &mut |b| rng.fill(b)).unwrap();
        for (h, _) in &w.records {
            if let Some(r) = txn.index().s.base_record(h) {
                archive.insert(*h, r.signed().clone());
            }
        }
        let (changes, pending) = txn.finish();
        store.commit(&changes).unwrap();
        pending.commit();
        *memory = FolderMemory::default();
        *notes = NoteBudget::for_tests();
        let recs = records_of(archive, &w.records);
        check_drops(&self.ix, &self.archive, &recs, &w.dropped, "end_round");
        w
    }

    /// The root set digest.
    pub(crate) fn root(&self) -> SetDigest {
        self.ix.root_digest()
    }
}

/// The tag of `path` in the fixed folder.
pub(crate) fn tag(path: &str) -> PathTag {
    write_key().record_keys().path_tag(path)
}

/// A record signed by the folder key around arbitrary sealed metadata at the
/// tag of `tag_path`, bypassing the writer's rules.
pub(crate) fn forge(
    tag_path: &str,
    chunks: &[Chunk],
    meta: &SealedMeta,
    replaces: &[RecordHash],
) -> SignedRecord {
    write_key()
        .sign_index_record(forge_body(tag_path, chunks, meta, replaces))
        .unwrap()
}

/// [`forge`]'s record with a garbage signature, never signed: for building
/// many held records cheaply where only the index's judgement is tested,
/// held directly or at a sealed holder.
pub(crate) fn unsigned(
    tag_path: &str,
    chunks: &[Chunk],
    meta: &SealedMeta,
    replaces: &[RecordHash],
) -> SignedRecord {
    let mut env = Vec::new();
    prost::encoding::bytes::encode(1, &forge_body(tag_path, chunks, meta, replaces), &mut env);
    prost::encoding::bytes::encode(2, &vec![0x5a; 64], &mut env);
    SignedRecord::from_bytes(&env).unwrap()
}

fn forge_body(
    tag_path: &str,
    chunks: &[Chunk],
    meta: &SealedMeta,
    replaces: &[RecordHash],
) -> Vec<u8> {
    let w = write_key();
    let keys = w.record_keys();
    let tag = keys.path_tag(tag_path);
    let sealed = keys
        .seal_index_meta(&tag, &meta.encode_to_vec(), &mut |b: &mut [u8]| {
            b.fill(0x44);
        })
        .unwrap();
    let mut names: Vec<Vec<u8>> = replaces.iter().map(|h| h.0.to_vec()).collect();
    names.sort();
    names.dedup();
    let body = IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: w.verifier().folder_id().0.to_vec(),
        chunks: chunks
            .iter()
            .map(|c| ChunkRef {
                cipher_hash: c.cipher_hash.0.to_vec(),
                stored_len: c.stored_len,
            })
            .collect(),
        sealed,
        path_tag: tag.0.to_vec(),
        replaces: names,
    };
    body.encode_to_vec()
}

/// The sealed metadata of a valid file at `path` by `device` at `counter`.
pub(crate) fn sealed_file(path: &str, device: DeviceId, counter: u64) -> SealedMeta {
    SealedMeta {
        path: path.into(),
        kind: 1,
        size: 1,
        mtime_ns: 5,
        mode: 0o644,
        plain_hashes: vec![vec![9; 32]],
        written_at: 0,
        device_id: device.0.to_vec(),
        counter,
        vector: vec![],
        deleted: false,
        tree: false,
    }
}

/// A vector entry.
pub(crate) fn entry(device: DeviceId, counter: u64) -> VectorEntry {
    VectorEntry {
        device_id: device.0.to_vec(),
        counter,
    }
}

/// One chunk named after `n`.
pub(crate) fn chunk(n: u8) -> Chunk {
    Chunk {
        cipher_hash: CipherHash([n; 32]),
        stored_len: 46,
    }
}

/// A cleanup signed by the folder key: `device` at `counter`, these groups.
pub(crate) fn cleanup(
    device: DeviceId,
    counter: u64,
    groups: &[(Option<RecordHash>, Vec<RecordHash>)],
) -> SignedRecord {
    let w = write_key();
    let keys = w.record_keys();
    let meta = CleanupMeta {
        device_id: device.0.to_vec(),
        counter,
    }
    .encode_to_vec();
    let sealed = keys
        .seal_cleanup_meta(&meta, &mut |b: &mut [u8]| b.fill(0x45))
        .unwrap();
    let body = CleanupRecord {
        suite: 1,
        record_type: 17,
        folder_id: w.verifier().folder_id().0.to_vec(),
        groups: groups
            .iter()
            .map(|(because, forget)| {
                let mut f: Vec<Vec<u8>> = forget.iter().map(|h| h.0.to_vec()).collect();
                f.sort();
                f.dedup();
                CleanupGroup {
                    because: because.map(|b| b.0.to_vec()).unwrap_or_default(),
                    forget: f,
                }
            })
            .collect(),
        sealed,
    };
    w.sign_cleanup_record(body.encode_to_vec()).unwrap()
}

/// `r` with its signature's first bit flipped: forged.
pub(crate) fn forged(r: &SignedRecord) -> SignedRecord {
    let mut sig = *r.signature().as_bytes();
    sig[0] ^= 1;
    with_signature(r, &sig)
}

/// `r` with a signature of garbage bytes.
pub(crate) fn garbage(r: &SignedRecord) -> SignedRecord {
    with_signature(r, &[0x5a; 64])
}

fn with_signature(r: &SignedRecord, sig: &[u8; 64]) -> SignedRecord {
    let mut out = Vec::new();
    prost::encoding::bytes::encode(1, &r.body().to_vec(), &mut out);
    prost::encoding::bytes::encode(2, &sig.to_vec(), &mut out);
    SignedRecord::from_bytes(&out).unwrap()
}

/// `r` as stored after one bit of its body flipped at rest (in `sealed`, so
/// the body still passes step 1): its hash is another's, and only the
/// signature tells.
pub(crate) fn flipped_body(r: &SignedRecord) -> SignedRecord {
    let mut body = r.body().to_vec();
    *body.last_mut().unwrap() ^= 1;
    let mut out = Vec::new();
    prost::encoding::bytes::encode(1, &body, &mut out);
    prost::encoding::bytes::encode(2, &r.signature().as_bytes().to_vec(), &mut out);
    SignedRecord::from_bytes(&out).unwrap()
}

/// The outcome of one exchange between two devices.
#[derive(Clone, Debug, Default)]
pub(crate) struct Exchanged {
    /// Whether `a`'s round with `b` ended caught up.
    pub(crate) caught_up: bool,
    /// The passes it took.
    pub(crate) passes: usize,
    /// What `a` judged of `b`'s records.
    pub(crate) judged: Vec<Judgement>,
    /// The cleanups `a` issued at the round's end.
    pub(crate) cleanup: bool,
}

/// One round of `a`'s with `b` (4.5), through the index's own digests and
/// serving: the Check, then up to `MAX_RECONCILE_PASSES` passes over the
/// trie, `b` answering each `ReconcileRequest` from its cache and serving
/// `RECORDS` pages, `a` accepting each record and pushing what the reply
/// lacked, which `b` accepts; then `a`'s round end (its cleanups, which go to
/// `b` as pushes). A forged record panics: these exchanges are between
/// honest devices.
pub(crate) fn round(a: &mut Dev, b: &mut Dev) -> Exchanged {
    let mut out = Exchanged::default();
    for pass in 1..=MAX_RECONCILE_PASSES {
        out.passes = pass;
        let mut brought = false;
        let mut work = vec![Prefix::ROOT];
        while let Some(prefix) = work.pop() {
            let request = ReconcileServe {
                request_id: 1,
                prefix,
                digest: a.ix.digest(&prefix),
            };
            let (reply, records) = b.ix.reconcile_reply(&request);
            match ReconcileOutcome::from_u32(reply.outcome).unwrap() {
                ReconcileOutcome::Equal => {
                    if prefix.is_root() {
                        out.caught_up = true;
                        a.ix_round_end(b, &mut out);
                        return out;
                    }
                }
                ReconcileOutcome::Children => {
                    let mut differ = Vec::new();
                    for (i, d) in reply.children.iter().enumerate() {
                        let child = prefix.child(u8::try_from(i).unwrap()).unwrap();
                        if a.ix.digest(&child).0.as_slice() != d.as_slice() {
                            differ.push(child);
                        }
                    }
                    work.extend(differ.into_iter().rev());
                }
                ReconcileOutcome::Records => {
                    let mut reply_state = records.unwrap();
                    let mut carried = Vec::new();
                    loop {
                        let page = b.ix.records_page(&mut reply_state, 1, DEFAULT_MESSAGE_SIZE);
                        assert!(carried.len() <= b.ix.len(), "the reply ends");
                        for raw in &page.records {
                            let signed = SignedRecord::from_bytes(raw).unwrap();
                            carried.push(signed.hash());
                            let j = a.accept_from(b.id(), &signed).unwrap().judgement;
                            brought |= j.held();
                            out.judged.push(j);
                        }
                        if !page.more {
                            break;
                        }
                    }
                    for page in
                        a.ix.subtree_pushes(&prefix, Some(&carried), DEFAULT_MESSAGE_SIZE)
                    {
                        for raw in &page.records {
                            let signed = SignedRecord::from_bytes(raw).unwrap();
                            b.accept_from(a.id(), &signed).unwrap();
                        }
                    }
                }
            }
        }
        if !brought {
            out.caught_up = true;
            a.ix_round_end(b, &mut out);
            return out;
        }
    }
    a.ix_round_end(b, &mut out);
    out
}

impl Dev {
    fn ix_round_end(&mut self, b: &mut Dev, out: &mut Exchanged) {
        let w = self.end_round();
        let (peer, clock, caught_up) = (b.id(), self.clock, out.caught_up);
        let mut txn = self.ix.begin();
        txn.round_ended(peer, caught_up, None, clock);
        let (changes, pending) = txn.finish();
        self.store.commit(&changes).unwrap();
        pending.commit();
        out.cleanup = w.cleanup;
        let hashes: Vec<RecordHash> = w.records.iter().map(|(h, _)| *h).collect();
        for h in hashes {
            if let Some(s) = self.ix.signed(&h).cloned() {
                b.accept_from(self.id(), &s).unwrap();
            }
        }
    }
}

/// Rounds both ways until both end caught up with nothing issued, at most
/// `limit` times; how many it took.
pub(crate) fn converge(a: &mut Dev, b: &mut Dev, limit: usize) -> usize {
    for i in 1..=limit {
        let x = round(a, b);
        let y = round(b, a);
        if x.caught_up && y.caught_up && !x.cleanup && !y.cleanup && a.root() == b.root() {
            return i;
        }
    }
    panic!("no convergence in {limit} rounds");
}

/// The section 5 row of a cause, spelled out.
pub(crate) fn row(c: Cause) -> &'static str {
    match c {
        Cause::Duplicate => "Duplicate",
        Cause::Expired => "Expired",
        Cause::Obsolete => "Obsolete",
        Cause::ReplacesHeld => "Replaces held records",
        Cause::CleanupGroupWaiting => "Cleanup group waiting",
        Cause::FromTheFuture => "From the future",
        Cause::Forged => "Forged",
        Cause::WriterFault => "Writer fault",
        Cause::OwnCounterAhead => "Own counter ahead",
        Cause::ClockAhead => "Counter ahead of the clock",
        Cause::CounterExhausted => "Counter exhausted",
        _ => "other",
    }
}

/// A judgement spelled out.
pub(crate) fn judgement(j: Judgement) -> &'static str {
    match j {
        Judgement::Duplicate => "duplicate",
        Judgement::Expired => "expired",
        Judgement::Obsolete => "obsolete",
        Judgement::FromTheFuture => "from the future",
        Judgement::Held => "held",
        Judgement::HeldOpaque => "held opaque",
        Judgement::DroppedBeneath => "dropped beneath a tree delete",
        Judgement::Skipped => "skipped",
        _ => "other",
    }
}

// What explains each drop (the R1 review's IR-6, its `probe_check_drops`):
// the properties assert that no change ever drops a record nothing explains.

thread_local! {
    static UNEXPLAINED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The drops no change explained since the last call, on this thread.
pub(crate) fn take_unexplained() -> Vec<String> {
    UNEXPLAINED.with(|f| core::mem::take(&mut *f.borrow_mut()))
}

fn records_of(
    archive: &std::collections::BTreeMap<RecordHash, SignedRecord>,
    written: &[(RecordHash, Option<u64>)],
) -> Vec<Record> {
    written
        .iter()
        .filter_map(|(h, _)| archive.get(h))
        .map(|s| Record::parse(s.clone(), write_key().verifier()).unwrap())
        .collect()
}

/// Every record a change dropped is explained by the change's records: a
/// name at its tag, coverage at its tag or beneath a tree delete (at a read
/// or write holder), a group of the change's own cleanups or of a held
/// cleanup that applies, a group whose `because` is one of the change's
/// records, or, at a key holder, expiry of a deletion or cleanup: the
/// folder's time after the change past its counter by more than its horizon
/// (that time only grows within a change, so one dropped early in a change
/// that ends past the horizon passes too). Anything else would be a silent
/// loss, and is recorded.
pub(crate) fn check_drops(
    ix: &Index,
    archive: &std::collections::BTreeMap<RecordHash, SignedRecord>,
    by: &[Record],
    dropped: &[RecordHash],
    what: &str,
) {
    use licketysync_protocol::limits::{CLEANUP_HORIZON, TOMBSTONE_HORIZON};
    use licketysync_protocol::record::{at_or_beneath, Applied};
    let keys = write_key().record_keys();
    let key_holder = ix.tier() != Tier::Sealed;
    let by_hashes: BTreeSet<RecordHash> = by.iter().map(Record::hash).collect();
    // Per record of the change, read once: what its seal says, and what the
    // groups `because` it name, so that a change dropping n records costs n
    // lookups, not n times what it names.
    let by_info: Vec<(&Record, Option<Applied>, BTreeSet<RecordHash>)> = by
        .iter()
        .map(|r| {
            let because: BTreeSet<RecordHash> =
                ix.s.groups_because(&r.hash()).into_iter().collect();
            (r, r.open(&keys).ok(), because)
        })
        .collect();
    for u in dropped {
        let Some(us) = archive.get(u) else {
            UNEXPLAINED.with(|f| {
                f.borrow_mut()
                    .push(format!("{what}: {u:?} not in the archive"));
            });
            continue;
        };
        let ur = Record::parse(us.clone(), write_key().verifier()).unwrap();
        let uv = ur.open(&keys);
        let um = uv.as_ref().ok();
        if key_holder {
            let horizon = match um {
                Some(Applied::Cleanup(_)) => Some(CLEANUP_HORIZON),
                Some(Applied::Index(m)) if m.deleted => Some(TOMBSTONE_HORIZON),
                _ => None,
            };
            let age = um.map_or(0, |a| ix.s.folder_time().saturating_sub(a.dot().counter));
            if horizon.is_some_and(|h| age > h) {
                continue;
            }
        }
        let mut ok = ix.s.forgotten_by_group(u);
        for (r, ra, because) in &by_info {
            if r.path_tag().is_some() && r.path_tag() == ur.path_tag() && r.replaces().contains(u) {
                ok = true;
            }
            for g in r.groups() {
                if g.forget.contains(u)
                    && g.because
                        .is_none_or(|b| ix.s.is_held(&b) || by_hashes.contains(&b))
                {
                    ok = true;
                }
            }
            if because.contains(u) {
                ok = true;
            }
            if key_holder {
                if let (Some(Applied::Index(rm)), Some(Applied::Index(m))) = (ra, um) {
                    if rm.tree {
                        if at_or_beneath(&m.path, &rm.path) && rm.vector.covers(&m.dot) {
                            ok = true;
                        }
                    } else if !m.tree && r.path_tag() == ur.path_tag() && rm.vector.covers(&m.dot) {
                        ok = true;
                    }
                }
            }
            if ok {
                break;
            }
        }
        if !ok {
            UNEXPLAINED.with(|f| {
                f.borrow_mut().push(format!(
                    "{what} at {:?}: {u:?} ({:?}) dropped by nothing that names or covers it",
                    ix.tier(),
                    um.and_then(Applied::meta)
                        .map(|m| (&m.path, m.dot.counter, m.deleted, m.tree))
                ));
            });
        }
    }
}
