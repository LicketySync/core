// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index of one folder: every signed record it holds, by record hash and
//! by writer in canonical order, each writer's cursor and cached digests,
//! what step 6 made of each record, which records wait, and the heads of
//! every path (`protocol.md` 4.4).
//!
//! # How a record lands
//!
//! [`Index::accept`] runs steps 2 to 5 through the protocol crate's
//! [`judge`] over this index's [`Held`] view, so nothing is stored or charged
//! to anyone before the folder key's signature has verified (TM-9, TM-22);
//! step 6 opens the seal with the folder's data key (a sealed holder stores
//! the record unopened); the record is committed to the [`Store`] before
//! anything changes in memory; then step 7 brings the heads up to date.
//!
//! # Opening
//!
//! [`Index::open`] rebuilds everything from the store, which is not trusted
//! for the records' authenticity (TM-9): every stored record passes step 1
//! and its signature again, through the same functions as a peer's record,
//! with the signatures verified on every core (`verify`). A record that
//! fails is dropped. A record that passes but lies above a `seq` at which its
//! writer has no record that passed is set aside: kept in memory, not held,
//! and landed without a second append as soon as a record at that `seq`
//! lands (from a peer, or written here). The [`OpenReport`] names both
//! lists. The rest are replayed in canonical order, as below, and so are the
//! set-aside records when they land, so the index stays a function of the
//! records in the store.
//!
//! # Digests
//!
//! Each writer's records are kept in canonical order (ascending `seq`, then
//! ascending record hash) with the digest at every `seq` from 1 to the
//! cursor. A record that sorts last (at the cursor plus one, or at the cursor
//! with the greatest hash there) costs one step; one that lands below others
//! recomputes the cache from its own `seq` up, as the spec states and TM-22
//! prices. Opening replays the stored records in canonical order, so each
//! costs one step and a reopen is linear in the records held; a set-aside
//! record lands at the cursor plus one, or at the cursor above the others
//! there, so it too costs one step. Serving reads the cache and computes
//! nothing.
//!
//! # Heads and waiting
//!
//! An applied record **waits** while some record it names in `supersedes` is
//! not held or itself waits; an opaque record never waits, whatever it names,
//! and since it is held, a record that names one does not wait for it. A
//! record that stops waiting (or arrives not waiting) is **activated**: the
//! versions it names leave the heads of their paths and it joins the heads of
//! its own. Nothing can name a record before it is activated without waiting
//! for it, so activation order cannot change the result: the heads are the
//! applied, non-waiting records that no applied, non-waiting record
//! supersedes, a function of the set of records held alone, in any arrival
//! order (TM-40, TM-41). Activation goes through a work list, never
//! recursion, and each record is activated once in its life, so a record that
//! releases a long chain costs time linear in the chain and no stack.
//!
//! # What a write names
//!
//! A write at a path names the path's **last known versions** (`protocol.md`
//! 4.4): its heads, and the versions of the path a record at another path
//! superseded (a rename away) that no record at the path has replaced since.
//! The second set is kept beside the heads, per path, and kept current the
//! same way on activation, so it too is a function of the records held. So a
//! file renamed away and a new file then written at the old name never show
//! as a conflict on a peer that holds the new file and the renamed version
//! but not yet the rename: the new file names the renamed version.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use core::fmt;
use core::num::NonZeroUsize;
use core::ops::Bound;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, FolderId, FolderKey, RandomFill, RecordHash, WriterDigest};
use licketysync_protocol::exchange::{Cursors, Scope, WriterCursor};
use licketysync_protocol::limits::{MAX_SEQ, MAX_SUPERSEDES};
use licketysync_protocol::record::{
    judge, own_sequence_ahead, Arrival, Chunk, Draft, DraftError, Held, Judgement, Meta, Record,
    WriterFault,
};
use licketysync_protocol::Cause;

use crate::heads::{Heads, Rank};
use crate::store::{Store, StoreError};
use crate::verify::authentic;

/// What step 6 made of a held record.
#[derive(Clone, Debug)]
pub enum Kept {
    /// The seal opened and the metadata passed: the record is applied, and a
    /// version of its path once it does not wait.
    Applied(Meta),
    /// A writer fault: the record is stored opaque, counts in its writer's
    /// records, cursor and digest, and is applied by no one; an issue names
    /// the record by its hash, never a device (ruling S-4).
    Opaque(WriterFault),
    /// Stored unopened: this device holds the sealed key, cannot read paths
    /// and computes no heads.
    Sealed,
}

/// What became of a record handed to [`Index::accept`] or [`Index::write`].
///
/// `fault` and `waits` describe the record passed in alone, and so does
/// `own_ahead` but for one case it names; so [`Outcome::rows`] does too. The
/// records it let land are listed in `landed`, and their effects are in
/// `released` and `changed`; each landed record's step 6 result and waiting
/// state show through [`Index::kept`] and [`Index::is_waiting`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The record's hash.
    pub hash: RecordHash,
    /// Steps 2 to 5: a duplicate or a push gap (ignored, not verified,
    /// nothing stored), the writer's next record, or a concurrent version.
    pub judgement: Judgement,
    /// Step 6 found a writer fault in the record passed in: it is stored
    /// opaque and an issue names it.
    pub fault: Option<WriterFault>,
    /// The record passed in is under this device's own device ID at or above
    /// the next `seq` it would use, or it is this device's own and let
    /// records of this device's own land, which lie above it: the counter
    /// has moved past them (it is this device's cursor for itself plus one),
    /// and an informational issue names no one (`protocol.md` 4.5).
    pub own_ahead: bool,
    /// The record passed in waits for a record it names: a log line now,
    /// and the engine raises the informational issue if it still waits after
    /// a round with every peer that has the folder open.
    pub waits: bool,
    /// Records that stopped waiting because this one landed, or because a
    /// record it let land did, in the order they stopped waiting.
    pub released: Vec<RecordHash>,
    /// Records that opening set aside and that landed because this one
    /// filled the last gap below them, in canonical order: they were in the
    /// store already and are not appended again. They count as newly
    /// accepted, so the engine pushes them to every connection where the
    /// folder is open, the one this record arrived on included (`protocol.md`
    /// 4.5, "Pushes").
    pub landed: Vec<RecordHash>,
    /// The paths whose heads changed, in byte order, those of the records it
    /// let land included.
    pub changed: Vec<String>,
}

impl Outcome {
    fn ignored(hash: RecordHash, judgement: Judgement) -> Self {
        Self {
            hash,
            judgement,
            fault: None,
            own_ahead: false,
            waits: false,
            released: Vec::new(),
            landed: Vec::new(),
            changed: Vec::new(),
        }
    }

    /// Whether the record is now held.
    #[must_use]
    pub fn stored(&self) -> bool {
        self.judgement.stores()
    }

    /// The section 5 rows the record passed in reached (with `own_ahead`'s
    /// one case for the records it let land), each of which the engine turns
    /// into the log line or issue its row names.
    #[must_use]
    pub fn rows(&self) -> Vec<Cause> {
        let mut rows: Vec<Cause> = self.judgement.cause().into_iter().collect();
        if self.fault.is_some() {
            rows.push(Cause::WriterFault);
        }
        if self.waits {
            rows.push(Cause::Waiting);
        }
        if self.own_ahead {
            rows.push(Cause::OwnSequenceAhead);
        }
        rows
    }
}

/// Why [`Index::accept`] did not hold a record. Nothing was stored and
/// nothing changed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptError {
    /// Steps 2 to 5 refused it: a sender violation inside a reply, or a
    /// signature that does not verify. Both close the connection (section 5).
    Refused(Cause),
    /// The record is of another folder: the engine handed it to the wrong
    /// index.
    OtherFolder,
    /// The store could not append the record, whose signature had verified:
    /// nothing is held and nothing changed. The engine pauses the folder,
    /// accepting none of its records, so that no peer can make this device
    /// verify the same record again and again (TM-22), until an append
    /// succeeds, and then owes each connection where the folder is open a
    /// round, which brings back what it set aside (`protocol.md` section 5).
    Store(StoreError),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(cause) => write!(f, "record refused: {cause:?}"),
            Self::OtherFolder => f.write_str("record of another folder"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Why [`Index::draft`] or [`Index::write`] made no record.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteError {
    /// This device holds the read or sealed key, which cannot sign.
    NotWriteKey,
    /// The next `seq` would pass `MAX_SEQ`: the device takes a new device ID
    /// (`keys.md` 8.1).
    SeqExhausted,
    /// The draft is not under this device's own ID at its next `seq`.
    NotNext {
        /// The `seq` this device writes next.
        expected: u64,
    },
    /// The writer's checks refused the draft.
    Draft(DraftError),
    /// The store failed; the record was not appended and must not be sent.
    Store(StoreError),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWriteKey => f.write_str("this device holds no write key for the folder"),
            Self::SeqExhausted => f.write_str("sequence numbers exhausted: take a new device ID"),
            Self::NotNext { expected } => {
                write!(f, "not this device's next record (expected seq {expected})")
            }
            Self::Draft(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// Why [`Index::open`] could not rebuild the index from its store. A stored
/// record that fails its checks is no error: it is dropped and reported
/// ([`OpenReport`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenError {
    /// The store could not be read.
    Store(StoreError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// What [`Index::open`] did not take into the index of what the store
/// returned, so that nothing is skipped without trace (`protocol.md` section
/// 5, "Stored record fails its check"). The engine (when it lands) shows the
/// counts in the folder's state and raises an issue naming the records by
/// hash; index sync fetches every genuine one again from the peers that hold
/// it, since the cursors and digests describe only the records held.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenReport {
    /// The stored records that fail step 1 against the folder (the folder ID
    /// included) or whose signature does not verify under its verification
    /// key: corrupted or edited at rest, or not this folder's. Each is named
    /// by the hash of its body as stored, which for a body that changed at
    /// rest is the hash of no record a writer signed; ascending, each once. A
    /// failing copy of a record of which the store also returned a copy that
    /// passed is dropped without being listed: the record is held or set
    /// aside.
    pub dropped: Vec<RecordHash>,
    /// Stored records that passed but lie above a `seq` at which their
    /// writer has no stored record that passes (a gap that a dropped or lost
    /// record left): kept in memory but not held, since a writer's records are
    /// held contiguously from `seq` 1, and landed without a second append as
    /// soon as a record at the gap lands ([`Outcome::landed`]); in canonical
    /// order by writer.
    pub set_aside: Vec<RecordHash>,
}

impl OpenReport {
    /// Whether nothing was dropped or set aside.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.dropped.is_empty() && self.set_aside.is_empty()
    }
}

/// One held record and what step 6 made of it.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) record: Record,
    pub(crate) kept: Kept,
}

/// One writer's records in canonical order and its cached digests.
#[derive(Debug, Default)]
struct Writer {
    order: BTreeSet<(u64, RecordHash)>,
    /// The digest at `s` is `digests[s - 1]`. The records are contiguous from
    /// `seq` 1 (step 3 admits only `seq ≤ cursor + 1`), so the length is the
    /// cursor and never exceeds the number of records held.
    digests: Vec<WriterDigest>,
}

/// The cache slot of `seq`, from 1.
fn slot(seq: u64) -> Option<usize> {
    usize::try_from(seq.checked_sub(1)?).ok()
}

impl Writer {
    fn cursor(&self) -> u64 {
        u64::try_from(self.digests.len()).unwrap_or(u64::MAX)
    }

    fn digest_at(&self, seq: u64) -> Option<WriterDigest> {
        self.digests.get(slot(seq)?).copied()
    }

    /// The writer's cursor and its digest there, as a request lists it.
    fn cursor_of(&self, writer: DeviceId) -> WriterCursor {
        WriterCursor {
            writer,
            seq: self.cursor(),
            digest: self.digests.last().copied(),
        }
    }

    /// Adds a record at `seq`, at most the cursor plus one, and brings the
    /// cache up to date; returns the digest steps taken. A record that sorts
    /// last in canonical order takes one step from the digest before it: at
    /// the cursor plus one it extends the cache, and at the cursor it moves
    /// the cursor's digest alone (records below are unchanged). Any other
    /// recomputes from its `seq` up.
    fn add(&mut self, seq: u64, hash: RecordHash) -> usize {
        self.order.insert((seq, hash));
        if self.order.last() != Some(&(seq, hash)) {
            return self.recompute_from(seq);
        }
        if seq > self.cursor() {
            let last = self.digests.last().copied().unwrap_or(WriterDigest::ZERO);
            self.digests.push(last.then(&hash));
        } else if let Some(at_cursor) = self.digests.last_mut() {
            *at_cursor = at_cursor.then(&hash);
        }
        1
    }

    /// Recomputes the cached digests from `seq` up, starting from the digest
    /// at `seq - 1` (32 zero bytes below 1).
    fn recompute_from(&mut self, seq: u64) -> usize {
        let mut digest = self
            .digest_at(seq.saturating_sub(1))
            .unwrap_or(WriterDigest::ZERO);
        let mut steps = 0;
        for (s, hash) in self.order.range((seq, RecordHash([0; 32]))..) {
            digest = digest.then(hash);
            if let Some(cached) = slot(*s).and_then(|i| self.digests.get_mut(i)) {
                *cached = digest;
            }
            steps += 1;
        }
        steps
    }
}

/// What one landing changed, for its [`Outcome`].
#[derive(Default)]
struct Effects {
    waits: bool,
    released: Vec<RecordHash>,
    landed: Vec<RecordHash>,
    changed: BTreeSet<String>,
}

/// The index of one folder, over a [`Store`].
///
/// It holds the folder's key, at whatever tier this device has: the
/// verification key every tier carries checks each record's signature, the
/// data key (write and read tiers) opens its seal, and the write key signs
/// this device's own records.
pub struct Index<S> {
    key: FolderKey,
    own: DeviceId,
    store: S,
    entries: BTreeMap<RecordHash, Entry>,
    writers: BTreeMap<DeviceId, Writer>,
    /// The heads of every path that has one, in display order.
    heads: BTreeMap<String, BTreeSet<Rank>>,
    /// Each path's versions that a record at another path superseded (a
    /// rename away) and that no record at the path has superseded since, in
    /// display order: with the heads, the path's last known versions, which a
    /// write there names.
    moved: BTreeMap<String, BTreeSet<Rank>>,
    /// Each waiting record, with how many records it names are not held or
    /// still wait.
    waiting: BTreeMap<RecordHash, usize>,
    /// Each record a waiting record names and that is not held or still
    /// waits, with the records that wait for it.
    waiters: BTreeMap<RecordHash, Vec<RecordHash>>,
    /// The records opening set aside, by writer, in canonical order: in the
    /// store, verified, and not held. Each lies above a `seq` at which its
    /// writer has no record held, so a peer's copy of it is a gap; it lands
    /// once the writer's cursor reaches its `seq` minus one.
    set_aside: BTreeMap<DeviceId, VecDeque<Record>>,
    /// Digest steps and waiter notifications so far, for the bounded-work
    /// tests.
    #[cfg(test)]
    pub(crate) work: u64,
}

impl<S> fmt::Debug for Index<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Index")
            .field("folder", &self.folder_id())
            .field("tier", &self.key.tier())
            .field("records", &self.entries.len())
            .field("writers", &self.writers.len())
            .field("paths", &self.heads.len())
            .field("waiting", &self.waiting.len())
            .field(
                "set_aside",
                &self.set_aside.values().map(VecDeque::len).sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

impl<S: Store> Index<S> {
    /// Opens the index of `key`'s folder for the device `own` over `store`,
    /// rebuilding everything from the records the store holds, which is not
    /// trusted for their authenticity (`threat-model.md` TM-9; the
    /// [`store`](crate::store) module documentation). Every record gets the
    /// checks a record from a peer gets before it is stored, with the same
    /// functions: step 1 against the folder, its folder ID included, and its
    /// signature under the folder's verification key, which every tier holds
    /// (`protocol.md` 4.4), the signatures spread across the processor's
    /// cores. A record that fails is dropped: nothing of it is applied,
    /// counted or served. The records that pass are replayed in canonical
    /// order, once each, at one digest step a record, with their seals opened
    /// again (step 6), so the index is the one that accepting them from peers
    /// builds; a writer's records above a `seq` at which none of its records
    /// passed are set aside, since a writer's records are held contiguously
    /// from `seq` 1, and land when a record at that `seq` does. The cursors
    /// and digests are rebuilt from the records held, so index sync fetches
    /// every genuine record dropped or missing again from the peers that hold
    /// it (`protocol.md` 4.5, "Why it converges").
    ///
    /// It blocks the calling thread for the whole check, one signature
    /// verification per stored record, so the engine (when it lands) runs it
    /// off any async executor and shows the folder as Checking until it
    /// returns.
    ///
    /// # Errors
    /// [`OpenError`] when the store cannot be read. What was dropped or set
    /// aside is in the [`OpenReport`].
    pub fn open(key: FolderKey, own: DeviceId, store: S) -> Result<(Self, OpenReport), OpenError> {
        let threads = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        Self::open_with_threads(key, own, store, threads)
    }

    /// [`Index::open`] with the signatures verified on up to `threads`
    /// threads, the calling thread included; the result is the same for any
    /// number.
    pub(crate) fn open_with_threads(
        key: FolderKey,
        own: DeviceId,
        store: S,
        threads: usize,
    ) -> Result<(Self, OpenReport), OpenError> {
        let loaded = store.load().map_err(OpenError::Store)?;
        let (mut records, mut dropped) = authentic(loaded, key.verifier(), threads);
        if !dropped.is_empty() {
            let passed: BTreeSet<RecordHash> = records.iter().map(Record::hash).collect();
            dropped.retain(|hash| !passed.contains(hash));
            dropped.sort_unstable();
            dropped.dedup();
        }
        records.sort_unstable_by_key(|r| (r.device_id(), r.seq(), r.hash()));
        records.dedup_by_key(|r| r.hash());
        let mut index = Self {
            key,
            own,
            store,
            entries: BTreeMap::new(),
            writers: BTreeMap::new(),
            heads: BTreeMap::new(),
            moved: BTreeMap::new(),
            waiting: BTreeMap::new(),
            waiters: BTreeMap::new(),
            set_aside: BTreeMap::new(),
            #[cfg(test)]
            work: 0,
        };
        let mut set_aside = Vec::new();
        for record in records {
            // Sorted by writer then `seq`, so once a writer's next record is
            // past a gap, so is every later one of it, and no record of the
            // writer lands here after it.
            let writer = record.device_id();
            if record.seq() > index.cursor_of(&writer).saturating_add(1) {
                set_aside.push(record.hash());
                index.set_aside.entry(writer).or_default().push_back(record);
                continue;
            }
            let kept = index.open_seal(&record);
            index.insert(record, kept, &mut Effects::default());
        }
        Ok((index, OpenReport { dropped, set_aside }))
    }

    /// Steps 2 to 7 of `protocol.md` 4.4 for a record that passed step 1
    /// against this folder (the connection parsed it), arriving as `arrival`
    /// says.
    ///
    /// A duplicate or a gap on a push is ignored without verifying it and
    /// nothing is stored (the engine marks the writer for a push gap). Any
    /// other record has its signature verified, is opened (or kept unopened
    /// by a sealed holder), appended to the store, and only then counted in
    /// its writer's records, cursor and digests and in the heads.
    ///
    /// # Errors
    /// [`AcceptError`]; nothing is stored then.
    pub fn accept(&mut self, record: Record, arrival: Arrival) -> Result<Outcome, AcceptError> {
        if record.folder_id() != self.folder_id() {
            return Err(AcceptError::OtherFolder);
        }
        let verifier = *self.key.verifier();
        let judgement = judge(&record, arrival, self, &verifier).map_err(AcceptError::Refused)?;
        if !judgement.stores() {
            return Ok(Outcome::ignored(record.hash(), judgement));
        }
        let next = self.cursor_of(&self.own).saturating_add(1);
        let own_ahead = own_sequence_ahead(&record, &self.own, next);
        self.hold(record, judgement, own_ahead)
            .map_err(AcceptError::Store)
    }

    /// Signs `draft` with the folder's write key and appends it to the store
    /// as this device's next record before returning, so that it may be sent
    /// ("Durability before transmission", `protocol.md` 4.5). The draft is
    /// under this device's own ID at its next `seq`, as [`Index::draft`] and
    /// [`Index::draft_rename`] make it. The record is then held like any
    /// other: [`Index::record`] gives it for pushing.
    ///
    /// # Errors
    /// [`WriteError`]; nothing is appended then.
    pub fn write(
        &mut self,
        draft: &Draft,
        rng: &mut RandomFill<'_>,
    ) -> Result<Outcome, WriteError> {
        let key = self.key.write_key().ok_or(WriteError::NotWriteKey)?;
        let expected = self.next_seq().ok_or(WriteError::SeqExhausted)?;
        if draft.device_id != self.own || draft.seq != expected {
            return Err(WriteError::NotNext { expected });
        }
        let signed = draft.sign(key, rng).map_err(WriteError::Draft)?;
        let record = Record::parse(signed, key.verifier())
            .map_err(|e| WriteError::Draft(DraftError::Refused(e)))?;
        self.hold(record, Judgement::Next, false)
            .map_err(WriteError::Store)
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Closes the index, returning its store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Appends a judged record to the store, then lands it in memory, and
    /// after it every record of its writer that opening set aside and that
    /// the cursor now reaches.
    fn hold(
        &mut self,
        record: Record,
        judgement: Judgement,
        own_ahead: bool,
    ) -> Result<Outcome, StoreError> {
        let kept = self.open_seal(&record);
        self.store.append(&record)?;
        let hash = record.hash();
        let writer = record.device_id();
        let fault = match &kept {
            Kept::Opaque(fault) => Some(fault.clone()),
            Kept::Applied(_) | Kept::Sealed => None,
        };
        let mut effects = Effects::default();
        self.insert(record, kept, &mut effects);
        let waits = effects.waits;
        self.land_set_aside(writer, &mut effects);
        // This device's own records landing above this one moved the counter
        // past them (`protocol.md` 4.5).
        let own_ahead = own_ahead || (writer == self.own && !effects.landed.is_empty());
        Ok(Outcome {
            hash,
            judgement,
            fault,
            own_ahead,
            waits,
            released: effects.released,
            landed: effects.landed,
            changed: effects.changed.into_iter().collect(),
        })
    }
}

impl<S> Index<S> {
    /// The folder's key, at this device's tier.
    #[must_use]
    pub fn key(&self) -> &FolderKey {
        &self.key
    }

    /// The folder.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.key.folder_id()
    }

    /// This device's ID: the writer of the records [`Index::write`] makes.
    #[must_use]
    pub fn own(&self) -> DeviceId {
        self.own
    }

    /// Records held: the Status's `index_records`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no record is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writers held.
    #[must_use]
    pub fn writer_count(&self) -> usize {
        self.writers.len()
    }

    /// The `seq` this device writes next: its cursor for its own device ID
    /// plus one, so it moves past any record under that ID that arrives from
    /// elsewhere (a restored backup, or another write holder writing under
    /// this ID). `None` past `MAX_SEQ`.
    #[must_use]
    pub fn next_seq(&self) -> Option<u64> {
        Some(self.cursor_of(&self.own).saturating_add(1)).filter(|s| *s <= MAX_SEQ)
    }

    /// A held record.
    #[must_use]
    pub fn record(&self, hash: &RecordHash) -> Option<&Record> {
        self.entries.get(hash).map(|e| &e.record)
    }

    /// What step 6 made of a held record.
    #[must_use]
    pub fn kept(&self, hash: &RecordHash) -> Option<&Kept> {
        self.entries.get(hash).map(|e| &e.kept)
    }

    /// Whether a held record waits.
    #[must_use]
    pub fn is_waiting(&self, hash: &RecordHash) -> bool {
        self.waiting.contains_key(hash)
    }

    /// Every waiting record, by hash.
    pub fn waiting(&self) -> impl Iterator<Item = RecordHash> + '_ {
        self.waiting.keys().copied()
    }

    /// This device's cursor for `writer` (0 when it holds none) and its
    /// cached digest there: what a request lists for the writer.
    #[must_use]
    pub fn writer_cursor(&self, writer: &DeviceId) -> WriterCursor {
        self.writers
            .get(writer)
            .map_or(WriterCursor::none(*writer), |w| w.cursor_of(*writer))
    }

    /// The cursors of every writer held strictly above `after` (every writer
    /// for `None`), in ascending device-ID order: what the next range request
    /// of a round lists.
    pub fn cursors(&self, after: Option<DeviceId>) -> impl Iterator<Item = WriterCursor> + '_ {
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        self.writers
            .range((lower, Bound::Unbounded))
            .map(|(writer, w)| w.cursor_of(*writer))
    }

    /// The cached digest of `writer` at `seq`, for `1 ≤ seq ≤` its cursor.
    #[must_use]
    pub fn digest_at(&self, writer: &DeviceId, seq: u64) -> Option<WriterDigest> {
        self.writers.get(writer)?.digest_at(seq)
    }

    /// Every record of `writer` held, in canonical order.
    pub fn records_of(&self, writer: &DeviceId) -> impl Iterator<Item = &Record> + '_ {
        self.writers
            .get(writer)
            .into_iter()
            .flat_map(|w| w.order.iter())
            .filter_map(|(_, hash)| self.record(hash))
    }

    /// The heads of `path`, in display order: empty for a path with none, and
    /// always empty for a sealed holder, which computes no heads.
    #[must_use]
    pub fn heads(&self, path: &str) -> Heads<'_> {
        Heads::new(self.heads.get(path), &self.entries)
    }

    /// Every path with at least one head, deleted ones included, in byte
    /// order.
    pub fn paths(&self) -> impl Iterator<Item = &str> + '_ {
        self.heads.keys().map(String::as_str)
    }

    /// The records opening set aside that have not landed, by writer in
    /// canonical order: for the tests, which check that they too follow from
    /// the store's records.
    #[cfg(test)]
    pub(crate) fn set_aside(&self) -> Vec<RecordHash> {
        self.set_aside
            .values()
            .flatten()
            .map(Record::hash)
            .collect()
    }

    /// Each path's versions that a write there names besides its heads (the
    /// ones a rename superseded), in display order, by path: for the tests,
    /// which check that they too follow from the records alone.
    #[cfg(test)]
    pub(crate) fn renamed_away(&self) -> Vec<(String, Vec<RecordHash>)> {
        self.moved
            .iter()
            .map(|(path, set)| (path.clone(), set.iter().map(|rank| rank.hash).collect()))
            .collect()
    }

    /// A draft of this device's next record at `meta.path`, naming the
    /// path's last known versions in `supersedes` (`protocol.md` 4.4): its
    /// heads, then the versions of the path a rename superseded that no
    /// record at the path has replaced since, each in display order, up to
    /// `MAX_SUPERSEDES`; heads left unnamed stay heads until a later write
    /// names them. `deleted` makes it a tombstone, whose `chunks` are empty.
    ///
    /// # Errors
    /// [`WriteError::NotWriteKey`] or [`WriteError::SeqExhausted`].
    pub fn draft(
        &self,
        meta: Meta,
        chunks: Vec<Chunk>,
        deleted: bool,
    ) -> Result<Draft, WriteError> {
        let supersedes = self.names(&[&meta.path]);
        self.draft_naming(meta, chunks, deleted, supersedes)
    }

    /// A draft of a rename from `from` to `meta.path`: one record at the new
    /// path naming the last known versions of the old path and of the new
    /// (`protocol.md` 4.4): the old path's heads, then the new path's, then
    /// the versions of each a rename superseded, each in display order, up to
    /// `MAX_SUPERSEDES` together; the old path is left with no head unless it
    /// had more than that.
    ///
    /// # Errors
    /// [`WriteError::NotWriteKey`] or [`WriteError::SeqExhausted`].
    pub fn draft_rename(
        &self,
        from: &str,
        meta: Meta,
        chunks: Vec<Chunk>,
    ) -> Result<Draft, WriteError> {
        let supersedes = self.names(&[from, &meta.path]);
        self.draft_naming(meta, chunks, false, supersedes)
    }

    fn draft_naming(
        &self,
        meta: Meta,
        chunks: Vec<Chunk>,
        deleted: bool,
        supersedes: Vec<RecordHash>,
    ) -> Result<Draft, WriteError> {
        if self.key.write_key().is_none() {
            return Err(WriteError::NotWriteKey);
        }
        Ok(Draft {
            device_id: self.own,
            seq: self.next_seq().ok_or(WriteError::SeqExhausted)?,
            supersedes,
            deleted,
            chunks,
            meta,
        })
    }

    /// The last known versions of `paths`: the heads of each path in turn,
    /// then the versions a rename moved away from each, in display order,
    /// without repeats, up to `MAX_SUPERSEDES`.
    fn names(&self, paths: &[&str]) -> Vec<RecordHash> {
        let mut out = Vec::new();
        for hash in ranked(&self.heads, paths).chain(ranked(&self.moved, paths)) {
            if out.len() == MAX_SUPERSEDES {
                break;
            }
            if !out.contains(&hash) {
                out.push(hash);
            }
        }
        out
    }

    /// The next writer in `scope` strictly above `after`: a writer held in a
    /// range, or any listed writer.
    pub(crate) fn next_writer(&self, scope: &Scope, after: Option<DeviceId>) -> Option<DeviceId> {
        match scope {
            Scope::Range {
                after: from,
                through,
            } => {
                let lower = after.max(*from).map_or(Bound::Unbounded, Bound::Excluded);
                self.writers
                    .range((lower, Bound::Unbounded))
                    .map(|(w, _)| *w)
                    .next()
                    .filter(|w| through.is_none_or(|t| *w <= t))
            }
            Scope::Listed(writers) => {
                let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
                writers.range((lower, Bound::Unbounded)).next().copied()
            }
        }
    }

    /// The first record of `writer` at or after `from` in canonical order.
    pub(crate) fn record_from(
        &self,
        writer: &DeviceId,
        from: Bound<(u64, RecordHash)>,
    ) -> Option<((u64, RecordHash), &SignedRecord)> {
        let position = *self
            .writers
            .get(writer)?
            .order
            .range((from, Bound::Unbounded))
            .next()?;
        Some((position, self.record(&position.1)?.signed()))
    }

    fn cursor_of(&self, writer: &DeviceId) -> u64 {
        self.writers.get(writer).map_or(0, Writer::cursor)
    }

    /// Step 6, or nothing for a sealed holder.
    fn open_seal(&self, record: &Record) -> Kept {
        match self.key.data_key() {
            None => Kept::Sealed,
            Some(data_key) => record
                .open(data_key)
                .map_or_else(Kept::Opaque, Kept::Applied),
        }
    }

    /// Whether `hash` is held and does not wait: a record naming it does not
    /// wait for it.
    fn resolved(&self, hash: &RecordHash) -> bool {
        self.entries.contains_key(hash) && !self.waiting.contains_key(hash)
    }

    /// Lands a stored record in memory: its writer's records and digests,
    /// then waiting and heads (step 7).
    fn insert(&mut self, record: Record, kept: Kept, effects: &mut Effects) {
        let hash = record.hash();
        let steps = self
            .writers
            .entry(record.device_id())
            .or_default()
            .add(record.seq(), hash);
        self.count(steps);
        let pending: Vec<RecordHash> = match kept {
            Kept::Applied(_) => record
                .supersedes()
                .iter()
                .filter(|named| !self.resolved(named))
                .copied()
                .collect(),
            Kept::Opaque(_) | Kept::Sealed => Vec::new(),
        };
        let sealed = matches!(kept, Kept::Sealed);
        self.entries.insert(hash, Entry { record, kept });
        if sealed {
            return;
        }
        if pending.is_empty() {
            self.activate(hash, effects);
        } else {
            self.waiting.insert(hash, pending.len());
            for named in pending {
                self.waiters.entry(named).or_default().push(hash);
            }
            effects.waits = true;
        }
    }

    /// Lands, in canonical order and without an append (each is in the store
    /// already), every record of `writer` that opening set aside and whose
    /// `seq` is at most the cursor plus one, the cursor rising as each
    /// lands. Each sorts last in the writer's canonical order when it lands,
    /// so it costs one digest step.
    fn land_set_aside(&mut self, writer: DeviceId, effects: &mut Effects) {
        let Some(mut queue) = self.set_aside.remove(&writer) else {
            return;
        };
        while queue
            .front()
            .is_some_and(|r| r.seq() <= self.cursor_of(&writer).saturating_add(1))
        {
            let Some(record) = queue.pop_front() else {
                break;
            };
            effects.landed.push(record.hash());
            let kept = self.open_seal(&record);
            self.insert(record, kept, effects);
        }
        if !queue.is_empty() {
            self.set_aside.insert(writer, queue);
        }
    }

    /// `first` has just become held and not waiting: it joins the heads if
    /// it is applied, and every record that waited only for it is activated
    /// in turn, through a work list.
    fn activate(&mut self, first: RecordHash, effects: &mut Effects) {
        let mut queue = vec![first];
        while let Some(hash) = queue.pop() {
            self.join_heads(&hash, effects);
            let waiters = self.waiters.remove(&hash).unwrap_or_default();
            self.count(waiters.len());
            for waiter in waiters {
                let Some(left) = self.waiting.get_mut(&waiter) else {
                    continue;
                };
                *left = left.saturating_sub(1);
                if *left == 0 {
                    self.waiting.remove(&waiter);
                    effects.released.push(waiter);
                    queue.push(waiter);
                }
            }
        }
    }

    /// An applied record that no longer waits: the versions it names leave
    /// the heads of their paths, and it joins the heads of its own. A version
    /// of another path that leaves its heads becomes one the path's next
    /// write still names, and one of its own path is replaced for good. No
    /// record supersedes it yet, since one that names it waited for it.
    fn join_heads(&mut self, hash: &RecordHash, effects: &mut Effects) {
        let Some(Entry {
            record,
            kept: Kept::Applied(meta),
        }) = self.entries.get(hash)
        else {
            return;
        };
        for named in record.supersedes() {
            let Some(Entry {
                record: old_record,
                kept: Kept::Applied(old),
            }) = self.entries.get(named)
            else {
                continue;
            };
            let rank = Rank::of(*named, old_record, old);
            let was_head = take(&mut self.heads, &old.path, &rank);
            if was_head {
                effects.changed.insert(old.path.clone());
            }
            if old.path == meta.path {
                take(&mut self.moved, &old.path, &rank);
            } else if was_head {
                self.moved.entry(old.path.clone()).or_default().insert(rank);
            }
        }
        self.heads
            .entry(meta.path.clone())
            .or_default()
            .insert(Rank::of(*hash, record, meta));
        effects.changed.insert(meta.path.clone());
    }

    #[cfg(test)]
    fn count(&mut self, steps: usize) {
        self.work = self
            .work
            .saturating_add(u64::try_from(steps).unwrap_or(u64::MAX));
    }

    #[cfg(not(test))]
    #[allow(
        clippy::unused_self,
        reason = "the work count exists for the bounded-work tests only"
    )]
    fn count(&mut self, _: usize) {}
}

/// The record hashes in `paths`' sets in `map`, path by path, each set in
/// display order.
fn ranked<'a>(
    map: &'a BTreeMap<String, BTreeSet<Rank>>,
    paths: &'a [&'a str],
) -> impl Iterator<Item = RecordHash> + 'a {
    paths
        .iter()
        .flat_map(move |p| map.get(*p).into_iter().flatten().map(|rank| rank.hash))
}

/// Removes `rank` from `path`'s set in `map`, dropping a set left empty;
/// whether it was there.
fn take(map: &mut BTreeMap<String, BTreeSet<Rank>>, path: &str, rank: &Rank) -> bool {
    let Some(set) = map.get_mut(path) else {
        return false;
    };
    let was = set.remove(rank);
    if set.is_empty() {
        map.remove(path);
    }
    was
}

/// The cursors the connection lists in the requests it builds
/// (`Connection::send_request`): [`Index::cursors`] and
/// [`Index::writer_cursor`].
impl<S> Cursors for Index<S> {
    fn cursors_after(&self, after: Option<DeviceId>) -> impl Iterator<Item = WriterCursor> + '_ {
        self.cursors(after)
    }

    fn cursor_of(&self, writer: &DeviceId) -> WriterCursor {
        self.writer_cursor(writer)
    }
}

impl<S> Held for Index<S> {
    fn holds(&self, record: &RecordHash) -> bool {
        self.entries.contains_key(record)
    }

    fn cursor(&self, writer: &DeviceId) -> u64 {
        self.cursor_of(writer)
    }
}
