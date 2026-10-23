// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the index persists, behind [`Store`]: the signed records it holds,
//! exactly as received, and nothing else.
//!
//! Every other piece of the index's state is a function of that set of
//! records and is rebuilt from it when the index opens: each writer's cursor
//! (the highest `seq` held, which never decreases because no record is ever
//! removed, TM-17), the cached writer digests, which records are applied,
//! opaque or waiting, the heads of every path and the versions a write there
//! still names. The rebuild gives the same state as the arrivals did,
//! whatever their order (`protocol.md` 4.4), so nothing derived needs storing
//! to be correct. This device's own sequence counter is its cursor for its
//! own device ID plus one, so appending a record commits the counter with it
//! ("Durability before transmission", `protocol.md` 4.5).
//!
//! # The store is trusted
//!
//! A record is verified under the folder key before it is appended, and not
//! again when the index opens: [`Index::open`](crate::Index::open) parses each
//! stored record (step 1) and opens its seal (step 6) but does not check its
//! signature. The store, and any backup restored into it, is this device's
//! own state and is trusted like the key store (`threat-model.md` TM-9,
//! §3.12). A store corrupted or edited at rest would make the device apply a
//! change no write holder signed, serve records its peers refuse as forged
//! (each such connection closes, naming this device), or count a junk record
//! in a writer's digest, so that every exchange resends that writer in full.
//! Phase 1, which puts the index on disk, decides between verifying every
//! record when the index opens (batch verification, or in `doctor`, as the
//! plan's "Recovery is local" says) and a labelled keyed checksum per stored
//! record from the keys crate: a question for the owner.
//!
//! # A seam for durability only
//!
//! The trait is the durability seam of phase 0, not the phase 1 storage
//! design: whatever the store, the [`Index`](crate::Index) keeps every record
//! and everything derived from it in memory, and [`Store::load`] returns every
//! record at once. Phase 1 moves those in-memory maps into `SQLite` on disk
//! (the plan's best-in-class row: on disk, under 1 KB of index per file), and
//! this trait changes with it. [`MemoryStore`] is phase 0's store (the plan's
//! index decision of 2026-10-14/15).

use std::collections::BTreeMap;

use core::fmt;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::RecordHash;
use licketysync_protocol::record::Record;

/// Why the store did not keep a record. Nothing was appended, and the index
/// changes nothing in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// The disk has no room for the record.
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

/// The records of one folder that a crash must not lose.
///
/// The contract: [`Store::append`] makes one record durable, atomically (all
/// of it or nothing), before it returns, and [`Store::load`] returns every
/// record appended. The index appends each record it comes to hold before it
/// changes anything in memory and before the engine may send the record to
/// anyone. A store never removes a record: nothing the index does deletes one
/// (TM-17). The store is trusted (the module documentation).
pub trait Store {
    /// Every appended record, in any order; a record may appear twice.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn load(&self) -> Result<Vec<SignedRecord>, StoreError>;

    /// Makes `record`, which the index has judged and will hold, durable:
    /// its envelope ([`Record::signed`]) is what to keep, and its hash,
    /// writer and sequence number are there for a store that keys by them.
    ///
    /// # Errors
    /// [`StoreError`]; nothing is appended then.
    fn append(&mut self, record: &Record) -> Result<(), StoreError>;
}

/// The phase 0 store: records in memory, by hash. Cloning one is taking a
/// backup of the index, which tests and the simulator restore from.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    records: BTreeMap<RecordHash, SignedRecord>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records appended.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing is appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Store for MemoryStore {
    fn load(&self) -> Result<Vec<SignedRecord>, StoreError> {
        Ok(self.records.values().cloned().collect())
    }

    fn append(&mut self, record: &Record) -> Result<(), StoreError> {
        self.records.insert(record.hash(), record.signed().clone());
        Ok(())
    }
}
