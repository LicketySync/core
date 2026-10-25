// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the index persists, behind [`Store`]: the signed records it holds,
//! exactly as received, and nothing else.
//!
//! Every other piece of the index's state is a function of that set of
//! records and is rebuilt from it when the index opens: each writer's cursor
//! (the highest `seq` held, which never decreases while the store keeps its
//! records; one lost or corrupted at rest lowers it at the next open,
//! TM-17), the cached writer digests, which records are applied, opaque,
//! waiting or set aside, the heads of every path and the versions a write
//! there still names. The rebuild gives the same state as the arrivals did,
//! whatever their order (`protocol.md` 4.4), so nothing derived needs storing
//! to be correct. This device's own sequence counter is its cursor for its
//! own device ID plus one, so appending a record commits the counter with it
//! ("Durability before transmission", `protocol.md` 4.5).
//!
//! # The store is checked when the index opens
//!
//! A record is verified under the folder key before it is appended, and
//! again every time the index opens: [`Index::open`](crate::Index::open)
//! gives each stored record step 1 against the folder and its signature
//! under the folder's verification key, the checks a record from a peer
//! gets, spread across the processor's cores, before it opens any seal (step
//! 6). The store, and any backup restored into it, is trusted to keep the
//! records appended, not for their authenticity (`threat-model.md` TM-9,
//! §3.12; the owner's decision of 2026-10-25, which chose this over a
//! labelled keyed checksum per stored record, kept as the fallback should
//! measurements on a phone or NAS show start-up too slow). A record
//! corrupted or edited at rest is dropped, never applied, counted in a
//! digest or served, and reported ([`OpenReport`](crate::OpenReport)); the
//! records of its writer above the gap it leaves are set aside, reported
//! too, and land once a record at the gap does. Peers send the genuine ones
//! again, and [`Store::append`] then replaces a bad copy kept under the same
//! hash. What the store can still do is lose records, which the device then
//! lacks until index sync brings them back. The key store stays trusted.
//!
//! In phase 0 the envelope decoding of step 1 is done before a record reaches
//! a store: a [`SignedRecord`] is made only by the keys crate's decoder,
//! `SignedRecord::from_bytes`, or by signing. A phase 1 store that keeps bytes
//! runs that decoder in [`Store::load`]; bytes that no longer decode it must
//! drop and report, as the index does for a record that fails its checks,
//! and never fail the whole load for them or lose them without trace
//! (`protocol.md` 4.4, "Opening a folder"); [`Store::load`] will need a way
//! to report them then, for example into the
//! [`OpenReport`](crate::OpenReport).
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
/// (TM-17). The store is trusted to keep records, not for their authenticity
/// (the module documentation).
pub trait Store {
    /// Every appended record, in any order; a record may appear twice. What
    /// it returns is checked again before any of it is used: a record that
    /// changed at rest is dropped and reported, not an error.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be read.
    fn load(&self) -> Result<Vec<SignedRecord>, StoreError>;

    /// Makes `record`, which the index has judged and will hold, durable:
    /// its envelope ([`Record::signed`]) is what to keep, and its hash,
    /// writer and sequence number are there for a store that keys by them.
    ///
    /// A record whose hash the store already holds is appended like any
    /// other, and the store keeps the envelope it is given in place of the
    /// one it had: opening may have dropped that copy (its signature bytes
    /// changed at rest, under the same hash), and the index holds the record
    /// now only because this copy verified.
    ///
    /// # Errors
    /// [`StoreError`]; nothing is appended then.
    fn append(&mut self, record: &Record) -> Result<(), StoreError>;
}

/// The phase 0 store: records in memory, by hash, a record appended again
/// replacing the envelope kept under its hash. Cloning one is taking a backup
/// of the index, which tests and the simulator restore from.
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
