// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fixtures: the keys crate's fixed folder, records built from a small
//! description (including the writer faults a writer's `Draft` refuses to
//! sign), a store that fails on demand, a snapshot of everything the index
//! derives, the display order as the spec words it, and an index-level
//! exchange between two indexes through real requests, replies and pages.

use std::collections::BTreeSet;

use core::cmp::{Ordering, Reverse};

use licketysync_keys::chunk::PlainHash;
use licketysync_keys::records::SignedRecord;
use licketysync_keys::sealed_meta::seal_meta;
use licketysync_keys::secret::WriteSecret;
use licketysync_keys::{
    CipherHash, DeviceId, FolderKey, FolderVerifier, RecordHash, Suite, WriteKey, WriterDigest,
};
use licketysync_protocol::exchange::{listed_request, range_request, Cursors, Scope, ServeRequest};
use licketysync_protocol::limits::DEFAULT_MESSAGE_SIZE;
use licketysync_protocol::messages::{ChunkRef, IndexRecord, SealedMeta};
use licketysync_protocol::record::{Arrival, Chunk, Draft, Kind, Meta, Record};
use prost::Message as _;

use crate::{Index, MemoryStore, Outcome, Reply, Store, StoreError, Version};

/// `n, n+1, … n+31`.
pub(crate) fn fixed32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

/// The write key of the keys crate's vectors: write secret `10 11 .. 2f`.
pub(crate) fn write_key() -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(0x10))).unwrap()
}

/// The same key, derived once: signing many records in a debug build.
pub(crate) fn key() -> &'static WriteKey {
    static KEY: std::sync::OnceLock<WriteKey> = std::sync::OnceLock::new();
    KEY.get_or_init(write_key)
}

/// Another folder's write key.
pub(crate) fn other_key() -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(0x40))).unwrap()
}

pub(crate) fn verifier() -> FolderVerifier {
    *key().verifier()
}

/// This device in the fixtures.
pub(crate) const OWN: DeviceId = DeviceId([0xa0; 32]);

pub(crate) fn dev(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

/// An index of a write holder over an empty memory store.
pub(crate) fn index() -> Index<MemoryStore> {
    index_as(OWN)
}

pub(crate) fn index_as(own: DeviceId) -> Index<MemoryStore> {
    Index::open(FolderKey::from(write_key()), own, MemoryStore::new()).unwrap()
}

pub(crate) fn read_index() -> Index<MemoryStore> {
    Index::open(
        FolderKey::from(write_key().read_key()),
        OWN,
        MemoryStore::new(),
    )
    .unwrap()
}

pub(crate) fn sealed_index() -> Index<MemoryStore> {
    Index::open(
        FolderKey::from(write_key().sealed_key()),
        OWN,
        MemoryStore::new(),
    )
    .unwrap()
}

/// A writer fault a record is built with, bypassing the writer's checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Sealed bytes that open under no key.
    Seal,
    /// A directory (not a tombstone) with one chunk.
    DirectoryWithChunk,
    /// A file of size 5 with no chunks.
    FileWithoutChunks,
}

/// What a record says.
#[derive(Clone, Debug)]
pub(crate) struct Spec {
    pub(crate) writer: DeviceId,
    pub(crate) seq: u64,
    pub(crate) path: String,
    pub(crate) kind: Kind,
    pub(crate) deleted: bool,
    pub(crate) mtime: i64,
    pub(crate) mode: u32,
    /// The content: 0 is an empty file, any other byte one chunk whose
    /// plaintext hash is that byte repeated.
    pub(crate) content: u8,
    pub(crate) supersedes: Vec<RecordHash>,
    pub(crate) fault: Option<Fault>,
    /// The seal's nonce byte, so that two otherwise equal specs differ.
    pub(crate) salt: u8,
}

impl Spec {
    /// A file at `path` by `writer` at `seq`.
    pub(crate) fn file(writer: DeviceId, seq: u64, path: &str) -> Self {
        Self {
            writer,
            seq,
            path: path.into(),
            kind: Kind::File,
            deleted: false,
            mtime: 1_000,
            mode: 0o644,
            content: 1,
            supersedes: Vec::new(),
            fault: None,
            salt: 0,
        }
    }

    pub(crate) fn dir(writer: DeviceId, seq: u64, path: &str) -> Self {
        Self {
            kind: Kind::Directory,
            content: 0,
            ..Self::file(writer, seq, path)
        }
    }

    pub(crate) fn tombstone(writer: DeviceId, seq: u64, path: &str) -> Self {
        Self {
            deleted: true,
            content: 0,
            ..Self::file(writer, seq, path)
        }
    }

    pub(crate) fn names(mut self, hashes: &[RecordHash]) -> Self {
        self.supersedes = hashes.to_vec();
        self
    }

    pub(crate) fn mtime(mut self, mtime: i64) -> Self {
        self.mtime = mtime;
        self
    }

    pub(crate) fn content(mut self, content: u8) -> Self {
        self.content = content;
        self
    }

    pub(crate) fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    pub(crate) fn salt(mut self, salt: u8) -> Self {
        self.salt = salt;
        self
    }

    pub(crate) fn fault(mut self, fault: Fault) -> Self {
        self.fault = Some(fault);
        self
    }

    pub(crate) fn chunks(&self) -> Vec<Chunk> {
        if self.deleted || self.content == 0 || self.fault == Some(Fault::FileWithoutChunks) {
            Vec::new()
        } else {
            vec![Chunk {
                cipher_hash: CipherHash([self.content; 32]),
                stored_len: 46,
            }]
        }
    }

    pub(crate) fn meta(&self) -> Meta {
        let chunks = self.chunks().len();
        Meta {
            path: self.path.clone(),
            kind: self.kind,
            size: match self.fault {
                Some(Fault::FileWithoutChunks) => 5,
                _ => u64::try_from(chunks).unwrap(),
            },
            mtime_ns: self.mtime,
            mode: self.mode,
            plain_hashes: (0..chunks).map(|_| PlainHash([self.content; 32])).collect(),
            written_at: 0,
        }
    }

    /// The signed record, through the writer's `Draft::sign` unless a fault
    /// is asked for.
    pub(crate) fn signed(&self) -> SignedRecord {
        let key = key();
        let salt = self.salt;
        let mut fill = move |b: &mut [u8]| b.fill(salt);
        if self.fault.is_none() {
            return Draft {
                device_id: self.writer,
                seq: self.seq,
                supersedes: self.supersedes.clone(),
                deleted: self.deleted,
                chunks: self.chunks(),
                meta: self.meta(),
            }
            .sign(key, &mut fill)
            .unwrap();
        }
        let folder = key.verifier();
        let sealed = if self.fault == Some(Fault::Seal) {
            vec![salt; 64]
        } else {
            let meta = self.meta();
            let plain = SealedMeta {
                path: meta.path,
                kind: meta.kind.to_wire(),
                size: meta.size,
                mtime_ns: meta.mtime_ns,
                mode: meta.mode,
                plain_hashes: meta.plain_hashes.iter().map(|h| h.0.to_vec()).collect(),
                written_at: 0,
            }
            .encode_to_vec();
            seal_meta(
                &key.data_key().record_key(),
                &folder.folder_id(),
                &self.writer,
                self.seq,
                &plain,
                &mut fill,
            )
            .unwrap()
        };
        let mut supersedes: Vec<Vec<u8>> = self.supersedes.iter().map(|h| h.0.to_vec()).collect();
        supersedes.sort();
        supersedes.dedup();
        let body = IndexRecord {
            suite: folder.suite().to_wire(),
            record_type: 16,
            folder_id: folder.folder_id().0.to_vec(),
            device_id: self.writer.0.to_vec(),
            seq: self.seq,
            supersedes,
            deleted: self.deleted,
            chunks: self
                .chunks()
                .iter()
                .map(|c| ChunkRef {
                    cipher_hash: c.cipher_hash.0.to_vec(),
                    stored_len: c.stored_len,
                })
                .collect(),
            sealed,
        }
        .encode_to_vec();
        key.sign_index_record(body)
    }

    pub(crate) fn record(&self) -> Record {
        Record::parse(self.signed(), &verifier()).unwrap()
    }
}

/// `r` with garbage in place of its signature.
pub(crate) fn garbage_signature(r: &Record) -> Record {
    reparse(r.signed().body(), &[0x55; 64])
}

/// `r` with one bit of its signature flipped.
pub(crate) fn flipped_signature(r: &Record) -> Record {
    let mut sig = *r.signed().signature().as_bytes();
    sig[0] ^= 1;
    reparse(r.signed().body(), &sig)
}

fn reparse(body: &[u8], signature: &[u8; 64]) -> Record {
    let mut out = Vec::new();
    prost::encoding::bytes::encode(1, &body.to_vec(), &mut out);
    prost::encoding::bytes::encode(2, &signature.to_vec(), &mut out);
    Record::from_bytes(&out, &verifier()).unwrap()
}

/// Accepts `r` as a push; panics on an error.
pub(crate) fn push<S: Store>(index: &mut Index<S>, r: &Record) -> Outcome {
    index.accept(r.clone(), Arrival::Push).unwrap()
}

/// The hashes of `path`'s heads, in display order.
pub(crate) fn heads<S>(index: &Index<S>, path: &str) -> Vec<RecordHash> {
    index.heads(path).versions().map(|v| v.hash()).collect()
}

/// The display order of two heads as `protocol.md` 4.4 words it, written
/// apart from the index's own: heads that are not tombstones first; among
/// those, directories before files; then the greater `mtime_ns` first; then
/// the smaller record hash first (among tombstones too, whose kind is not
/// compared).
pub(crate) fn display_order(a: &Version<'_>, b: &Version<'_>) -> Ordering {
    let key = |v: &Version<'_>| {
        (
            v.is_tombstone(),
            !v.is_tombstone() && v.meta().kind == Kind::File,
            Reverse(v.meta().mtime_ns),
            v.hash(),
        )
    };
    key(a).cmp(&key(b))
}

/// Everything the index derives from the records it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) held: BTreeSet<RecordHash>,
    pub(crate) writers: Vec<(DeviceId, u64, Vec<WriterDigest>, Vec<RecordHash>)>,
    pub(crate) waiting: Vec<RecordHash>,
    pub(crate) heads: Vec<(String, Vec<RecordHash>)>,
    /// What a write at each path names besides its heads.
    pub(crate) renamed_away: Vec<(String, Vec<RecordHash>)>,
    pub(crate) opaque: BTreeSet<RecordHash>,
}

pub(crate) fn snapshot<S>(index: &Index<S>) -> Snapshot {
    let writers: Vec<_> = index
        .cursors(None)
        .map(|c| {
            let digests = (1..=c.seq)
                .map(|s| index.digest_at(&c.writer, s).unwrap())
                .collect();
            let order: Vec<RecordHash> = index.records_of(&c.writer).map(Record::hash).collect();
            (c.writer, c.seq, digests, order)
        })
        .collect();
    let held: BTreeSet<RecordHash> = writers
        .iter()
        .flat_map(|(_, _, _, order)| order.iter().copied())
        .collect();
    let opaque = held
        .iter()
        .filter(|h| matches!(index.kept(h), Some(crate::Kept::Opaque(_))))
        .copied()
        .collect();
    Snapshot {
        waiting: index.waiting().collect(),
        heads: index
            .paths()
            .map(|p| (p.to_string(), heads(index, p)))
            .collect(),
        renamed_away: index.renamed_away(),
        held,
        writers,
        opaque,
    }
}

/// Serves `request` from `responder` and accepts every page into
/// `requester` as a reply; returns the writers the responder marked.
pub(crate) fn serve_into(
    requester: &mut Index<MemoryStore>,
    responder: &Index<MemoryStore>,
    request: &licketysync_protocol::messages::IndexRequest,
) -> Vec<DeviceId> {
    let mut request = request.clone();
    request.request_id = 1;
    let serving = ServeRequest::of(&request);
    let scope: Scope = serving.scope.clone();
    let mut reply = Reply::new(serving);
    let mut marks = Vec::new();
    while let Some(page) = reply.next_page(responder, DEFAULT_MESSAGE_SIZE).unwrap() {
        marks.extend(page.marks);
        for bytes in &page.page.records {
            let r = Record::from_bytes(bytes, &verifier()).unwrap();
            let in_scope = scope.contains(&r.device_id());
            requester.accept(r, Arrival::Reply { in_scope }).unwrap();
        }
    }
    marks
}

/// One round of `requester`'s range requests served by `responder`, then the
/// responder's listed request for its marks served by the requester.
pub(crate) fn round(requester: &mut Index<MemoryStore>, responder: &mut Index<MemoryStore>) {
    let folder = requester.folder_id();
    let mut after = None;
    let mut marks = Vec::new();
    loop {
        // The cursors as the connection reads them (the `Cursors` trait).
        let request = range_request(&folder, after, requester.cursors_after(after), 0).unwrap();
        let through = DeviceId::from_slice(&request.through);
        marks.extend(serve_into(requester, responder, &request));
        match through {
            Some(t) => after = Some(t),
            None => break,
        }
    }
    marks.sort();
    marks.dedup();
    if !marks.is_empty() {
        let listed =
            listed_request(&folder, marks.iter().map(|w| responder.cursor_of(w)), 0).unwrap();
        // The listed request finds equal digests, or resends in full and
        // marks again, which the next round covers.
        serve_into(responder, requester, &listed);
    }
}

/// Rounds both ways until neither side changes.
pub(crate) fn converge(a: &mut Index<MemoryStore>, b: &mut Index<MemoryStore>) {
    for _ in 0..8 {
        let before = (snapshot(a), snapshot(b));
        round(a, b);
        round(b, a);
        if (snapshot(a), snapshot(b)) == before {
            return;
        }
    }
    panic!("the indexes did not converge");
}

/// A store whose `append` or `load` fails on demand.
#[derive(Clone, Debug, Default)]
pub(crate) struct Flaky {
    pub(crate) inner: MemoryStore,
    pub(crate) fail_append: bool,
    pub(crate) fail_load: bool,
    /// Records `load` returns besides the inner store's.
    pub(crate) extra: Vec<SignedRecord>,
}

impl Store for Flaky {
    fn load(&self) -> Result<Vec<SignedRecord>, StoreError> {
        if self.fail_load {
            return Err(StoreError::Io("cannot read".into()));
        }
        let mut all = self.inner.load()?;
        all.extend(self.extra.iter().cloned());
        Ok(all)
    }

    fn append(&mut self, record: &Record) -> Result<(), StoreError> {
        if self.fail_append {
            return Err(StoreError::Full);
        }
        self.inner.append(record)
    }
}
