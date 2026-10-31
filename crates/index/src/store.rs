// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the index persists, and how a change reaches the store
//! (`protocol.md` 4.5 "Durability before transmission", 4.7 item 1).
//!
//! The index does not own a store. Each engine handler opens one transaction
//! on the index ([`crate::Index::begin`]), stages every change of that handler
//! in it, finishes it ([`crate::Txn::finish`]) for the [`ChangeSet`] to
//! persist in its one commit, and then commits the pending transaction (its
//! changes stay in memory) or drops it (they are undone, nothing to
//! rebuild): nothing is served from what the store does not hold yet.
//! [`Store`] is the shape
//! of a store that takes a [`ChangeSet`] and gives back the [`Stored`] state
//! at open; [`MemoryStore`] is phase 0's, which can also model a store that
//! cannot stage atomically and crashes between a change's record and its
//! removals.
//!
//! # What is persisted
//!
//! - every record held, its envelope exactly as received, with its local
//!   sequence number;
//! - every record kept only as a base (its envelope), and the base slots: per
//!   file ID and place (the path itself or one of its conflict copies on the
//!   disk), the record that is the base there;
//! - the folder's metadata: the high-water mark, the next local sequence
//!   number and the index epoch;
//! - the per-peer state.
//!
//! Everything else (the live sets, the names and groups, heads, set digests,
//! chunk counts, the folder's own time) is a function of the records held
//! and is rebuilt from them at open, after every stored record has passed
//! step 1 and its signature again (`protocol.md` 4.4, "Opening a folder";
//! TM-9). The store is trusted to keep what it is given, not for its
//! authenticity.
//!
//! # A store that cannot stage atomically
//!
//! It writes, in this order, the records a change puts, then the metadata
//! (the next local sequence number and the high-water mark) with the base
//! slots, then the removals, so that a crash after the records never leaves a
//! path's base on an older version than its newest applied record. A crash
//! between them leaves records that another stored record replaces; the next
//! open drops them and numbers on from the greatest stored local sequence,
//! whatever the stored metadata says (4.7 item 1). Such a store is reopened
//! ([`crate::Index::open`]) before its folder resumes after a store failure,
//! since the failed commit may have stopped between those writes; an atomic
//! store left nothing of the failed change and resumes without it (4.7
//! item 1).

use std::collections::BTreeMap;

use core::fmt;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{CipherHash, DeviceId, PathTag, RecordHash};

/// Why the store did not take a change. Nothing was persisted, and the
/// transaction is to be dropped, which undoes it in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// The disk has no room.
    Full,
    /// Any other failure, described for the Issues list.
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("index store: the disk is full"),
            Self::Io(why) => write!(f, "index store: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The place a base stands for at its file ID (`protocol.md` 4.4, "Bases"):
/// the path itself, or one of its conflict copies on the disk, named by the
/// engine (phase 1 gives copies their names; phase 0 has none).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Place {
    /// The file or directory at the path.
    Path,
    /// A conflict copy beside the path, by the name the engine gave it.
    Copy(String),
}

/// One base slot: a file ID and a place there.
pub type BaseSlot = (PathTag, Place);

/// The folder's metadata as stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredMeta {
    /// The high-water mark: the greatest counter of every applied record held
    /// or written (0 at a sealed holder, which keeps none).
    pub hw: u64,
    /// The next local sequence number.
    pub next_seq: u64,
    /// The index epoch, never 0.
    pub epoch: u64,
}

/// What this device keeps for one peer of a folder (`protocol.md` 4.5,
/// "Per-peer state"), by the device ID its `DeviceProof` proved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerState {
    /// The peer's index epoch the cursor belongs to.
    pub epoch: u64,
    /// The peer's local sequence through which this device holds what the
    /// peer held.
    pub cursor: u64,
    /// When the two last ended a round, by this device's wall clock in
    /// microseconds; 0 for never.
    pub round_ended_us: u64,
    /// Whether that round ended caught up.
    pub caught_up: bool,
    /// The start of the current `MAX_PEER_NAMES` window, by this device's
    /// wall clock in microseconds.
    pub names_window_us: u64,
    /// The peer's records named in that window, in writes and cleanups.
    pub names: u64,
}

/// One folder's stored state, as [`Store::load`] returns it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stored {
    /// Every record held, with its local sequence number, in any order; a
    /// record may appear twice.
    pub records: Vec<(SignedRecord, u64)>,
    /// Every record kept only as a base.
    pub base_only: Vec<SignedRecord>,
    /// The base slots.
    pub bases: Vec<(BaseSlot, RecordHash)>,
    /// The metadata, if any was stored.
    pub meta: Option<StoredMeta>,
    /// The per-peer state.
    pub peers: Vec<(DeviceId, PeerState)>,
    /// Entries a store that keeps bytes found it could no longer decode (a
    /// phase 1 store); counted in the open's report.
    pub undecodable: usize,
}

/// Everything one transaction changed, to be persisted in one commit
/// (`protocol.md` 4.7 item 1): the records it came to hold (their envelopes
/// and local sequence numbers), the records it dropped, the records kept only
/// as bases that came or went, the base slots set or cleared, the folder's
/// metadata, the per-peer state set or dropped, and the chunk hashes whose
/// count of held records naming them fell to zero, for the engine's
/// pending-free list. A removal is never staged without the record that
/// replaces it, which is in `put`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    /// Records now held, with their local sequence numbers, in that order.
    pub put: Vec<(SignedRecord, u64)>,
    /// Records no longer held.
    pub remove: Vec<RecordHash>,
    /// Records now kept only as bases.
    pub base_only_put: Vec<SignedRecord>,
    /// Records no longer kept only as bases.
    pub base_only_remove: Vec<RecordHash>,
    /// Base slots and the record each now holds, or `None` for a slot cleared.
    pub bases: Vec<(BaseSlot, Option<RecordHash>)>,
    /// The folder's metadata, when it changed.
    pub meta: Option<StoredMeta>,
    /// Per-peer states set, or `None` for one dropped.
    pub peers: Vec<(DeviceId, Option<PeerState>)>,
    /// Chunk hashes that no held record names any more.
    pub freed: Vec<CipherHash>,
}

impl ChangeSet {
    /// Whether the transaction changed nothing that is persisted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.put.is_empty()
            && self.remove.is_empty()
            && self.base_only_put.is_empty()
            && self.base_only_remove.is_empty()
            && self.bases.is_empty()
            && self.meta.is_none()
            && self.peers.is_empty()
    }
}

/// A folder's index store: [`Store::load`] gives back what was committed,
/// [`Store::commit`] makes one [`ChangeSet`] durable before it returns.
pub trait Store {
    /// The stored state. What it returns is checked again before any of it
    /// is used: a record changed at rest is dropped and reported, not an
    /// error.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn load(&self) -> Result<Stored, StoreError>;

    /// Makes `changes` durable: all of it, or, for a store that cannot stage
    /// atomically, in the order of the module documentation.
    ///
    /// # Errors
    /// [`StoreError`]; nothing was persisted then (an atomic store), or a
    /// prefix in that order (one that is not).
    fn commit(&mut self, changes: &ChangeSet) -> Result<(), StoreError>;
}

/// How [`MemoryStore`] commits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Commit {
    /// All of a change or nothing.
    #[default]
    Atomic,
    /// The records, then the metadata with the base slots and the per-peer
    /// state, then the removals; and the next commit crashes after its
    /// records, metadata and base slots, before its removals, failing with
    /// [`StoreError::Io`]: the case the next open must repair.
    CrashBeforeRemovals,
    /// Every commit fails with [`StoreError::Full`]: a store failure.
    Refuse,
}

/// The phase 0 store: everything in memory. Cloning one is taking a backup of
/// the index, which tests and the simulator restore from.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    records: BTreeMap<RecordHash, (SignedRecord, u64)>,
    base_only: BTreeMap<RecordHash, SignedRecord>,
    bases: BTreeMap<BaseSlot, RecordHash>,
    meta: Option<StoredMeta>,
    peers: BTreeMap<DeviceId, PeerState>,
    /// How the next commits go.
    pub mode: Commit,
}

impl MemoryStore {
    /// An empty store that commits atomically.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no record is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The stored metadata.
    #[must_use]
    pub fn meta(&self) -> Option<StoredMeta> {
        self.meta
    }

    /// Replaces the stored record under `hash`, as damage at rest would, for
    /// tests of the open-time check.
    pub fn tamper(&mut self, hash: &RecordHash, with: SignedRecord) {
        if let Some((record, _)) = self.records.get_mut(hash) {
            *record = with;
        }
    }

    /// Sets the stored metadata, as damage at rest would.
    pub fn set_meta(&mut self, meta: StoredMeta) {
        self.meta = Some(meta);
    }

    fn put(&mut self, changes: &ChangeSet) {
        for (record, seq) in &changes.put {
            self.records.insert(record.hash(), (record.clone(), *seq));
        }
        for record in &changes.base_only_put {
            self.base_only.insert(record.hash(), record.clone());
        }
    }

    fn rest(&mut self, changes: &ChangeSet) {
        for (slot, hash) in &changes.bases {
            match hash {
                Some(h) => self.bases.insert(slot.clone(), *h),
                None => self.bases.remove(slot),
            };
        }
        for (peer, state) in &changes.peers {
            match state {
                Some(s) => self.peers.insert(*peer, *s),
                None => self.peers.remove(peer),
            };
        }
    }

    fn removals(&mut self, changes: &ChangeSet) {
        for hash in &changes.remove {
            self.records.remove(hash);
        }
        for hash in &changes.base_only_remove {
            self.base_only.remove(hash);
        }
    }
}

impl Store for MemoryStore {
    fn load(&self) -> Result<Stored, StoreError> {
        Ok(Stored {
            records: self.records.values().cloned().collect(),
            base_only: self.base_only.values().cloned().collect(),
            bases: self.bases.iter().map(|(s, h)| (s.clone(), *h)).collect(),
            meta: self.meta,
            peers: self.peers.iter().map(|(d, s)| (*d, *s)).collect(),
            undecodable: 0,
        })
    }

    fn commit(&mut self, changes: &ChangeSet) -> Result<(), StoreError> {
        match self.mode {
            Commit::Refuse => Err(StoreError::Full),
            Commit::Atomic => {
                self.put(changes);
                if changes.meta.is_some() {
                    self.meta = changes.meta;
                }
                self.rest(changes);
                self.removals(changes);
                Ok(())
            }
            Commit::CrashBeforeRemovals => {
                self.put(changes);
                if changes.meta.is_some() {
                    self.meta = changes.meta;
                }
                self.rest(changes);
                self.mode = Commit::Atomic;
                Err(StoreError::Io("crashed before the removals".into()))
            }
        }
    }
}
