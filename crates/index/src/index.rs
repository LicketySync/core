// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index of one folder and its transactions (`protocol.md` 4.4, 4.5,
//! 4.7): [`Index::open`], [`Index::begin`], and arrival, steps 2 to 9 of
//! 4.4's verification ([`Txn::accept`]).

use core::fmt;

use licketysync_keys::sealed_meta::RecordKeys;
use licketysync_keys::{
    DeviceId, FolderId, FolderKey, FolderVerifier, PathTag, RandomFill, RecordHash, Tier,
};
use licketysync_protocol::connection::{FolderMemory, Judgement, NoteBudget};
use licketysync_protocol::limits::{
    CLEANUP_HORIZON, CLOCK_AHEAD_WARNING, CLOCK_FLOOR_MAX, CLOCK_RULE_LIMIT, MAX_COUNTER,
    MAX_LOCAL_SEQ, MAX_PEER_NAMES, MAX_STALE_KNOWN, TOMBSTONE_HORIZON,
};
use licketysync_protocol::record::{Applied, Record, Verdict, WriterFault};
use licketysync_protocol::Cause;

use crate::state::{Held, Note, Noted, Replacer, State, Undo};
use crate::store::{ChangeSet, PeerState, Stored, StoredMeta};

/// Where a record held gets its local sequence number.
pub(crate) enum Seq<'b, 'r> {
    /// Its stored number, at open.
    Stored(u64),
    /// The next number, for a record from a peer; the randomness draws an
    /// epoch should one be drawn.
    Next(&'b mut RandomFill<'r>),
    /// The next number, for a record this device wrote: it is no record
    /// "under its own ID above its mark", and no fast clock's.
    Own(&'b mut RandomFill<'r>),
}

/// The bounds a test may lower (the coordinator's ruling Q7: the vector cap
/// and similar bounds may be crate-private test parameters; production uses
/// the spec's constants, and at least one test runs at the real cap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// `MAX_VECTOR_ENTRIES`.
    pub(crate) vector: usize,
    /// `MAX_CLEANUP_ENTRIES`, the names of one cleanup record.
    pub(crate) cleanup_entries: usize,
    /// `MAX_CLEANUP_GROUPS`, the groups of one cleanup record.
    pub(crate) cleanup_groups: usize,
    /// `MAX_STALE_KNOWN`, the notes a write holder keeps.
    pub(crate) stale_known: usize,
    /// `MAX_PEER_NAMES`, the names of one peer's records in a window.
    pub(crate) peer_names: u64,
}

impl Bounds {
    pub(crate) const SPEC: Self = Self {
        vector: licketysync_protocol::limits::MAX_VECTOR_ENTRIES,
        cleanup_entries: licketysync_protocol::limits::MAX_CLEANUP_ENTRIES,
        cleanup_groups: licketysync_protocol::limits::MAX_CLEANUP_GROUPS,
        stale_known: MAX_STALE_KNOWN,
        peer_names: MAX_PEER_NAMES,
    };
}

/// Why a write holder did not note a record a peer offered that it would
/// otherwise have noted, for the spec's log lines (4.5, "Stale copies").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotNoted {
    /// The peer has had `MAX_PEER_NAMES` of its records named in the
    /// current window.
    PeerNames,
    /// The connection has spent its `MAX_NOTE_VERIFICATIONS` in the current
    /// window; the record waits for the next.
    Verifications,
}

/// One folder's index. Its state changes only through a [`Txn`]; every read
/// here is of committed state.
pub struct Index {
    pub(crate) key: FolderKey,
    pub(crate) verifier: FolderVerifier,
    /// `rk`, `tk` and the folder ID, at a read or write holder.
    pub(crate) keys: Option<RecordKeys>,
    pub(crate) own: DeviceId,
    pub(crate) s: State,
    pub(crate) bounds: Bounds,
}

impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Index")
            .field("folder", &self.verifier.folder_id())
            .field("tier", &self.key.tier())
            .field("held", &self.s.held.len())
            .field("epoch", &self.s.meta.epoch)
            .finish_non_exhaustive()
    }
}

/// A random, non-zero 64-bit index epoch through the caller's randomness
/// (4.5, "Local sequence and epoch").
pub(crate) fn draw_epoch(rng: &mut RandomFill<'_>) -> u64 {
    let mut b = [0u8; 8];
    rng(&mut b);
    u64::from_le_bytes(b).max(1)
}

/// What an open did not take in, and what it found (`protocol.md` 4.4,
/// "Opening a folder"; 4.7 item 8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenReport {
    /// Stored records and bases kept only as bases that failed step 1 or
    /// their signature, by the record hash of the body as stored, ascending,
    /// each once. They stay in the store and are reported again at the next
    /// open.
    pub dropped: Vec<RecordHash>,
    /// The stored high-water mark was above what the records held and the
    /// clock floor justify by more than `CLOCK_AHEAD_WARNING`, or at or above
    /// `MAX_COUNTER`, and was replaced.
    pub hw_corrupt: bool,
    /// Entries the store could no longer decode (a phase 1 store): dropped,
    /// as a record that fails its checks is, so the open draws a new epoch.
    pub undecodable: usize,
    /// A new index epoch was drawn, once, because the open dropped something
    /// (a stored record or base that failed its checks, a record another
    /// stored record replaces or that expired, a base slot whose record is
    /// gone, an entry the store could not decode) or numbered the records
    /// afresh (`protocol.md` 4.4, "Opening a folder"; 4.7 item 8). A store
    /// with no epoch, none stored or its metadata one of the entries it could
    /// not decode, gets its first epoch, not a redraw, and this stays false.
    pub epoch_redrawn: bool,
    /// A stored local sequence number was 0, above `MAX_LOCAL_SEQ` or
    /// repeated, or the stored next one past `MAX_LOCAL_SEQ + 1`: every
    /// record held was numbered afresh from 1 in stored order, under a new
    /// epoch, and is put again with its new number, so that a number two
    /// records share cannot lose one of them.
    pub renumbered: bool,
    /// Stored base slots whose record lies at another file ID, dropped, as
    /// [`Txn::set_base`] would refuse them.
    pub misplaced_bases: Vec<crate::store::BaseSlot>,
    /// The folder does not open yet: the greatest counter of an applied record
    /// stored lies more than `CLOCK_RULE_LIMIT` ahead of this device's clock
    /// ("records here are dated more than a year ahead of this device's
    /// clock: it was set back, or was ahead when they arrived"). It opens
    /// once the clock, in microseconds since the epoch, reaches this value;
    /// the engine checks again then, through the clock trait.
    pub opens_at: Option<u64>,
    /// What the open changed that the store is to keep: records another
    /// stored record replaces, or that expired (dropped without a report),
    /// the metadata (a new epoch, a repaired high-water mark or next local
    /// sequence number) and per-peer state past `PEER_STATE_HORIZON`.
    pub changes: ChangeSet,
}

impl OpenReport {
    /// Whether the open found nothing to report.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.dropped.is_empty()
            && !self.hw_corrupt
            && self.undecodable == 0
            && self.opens_at.is_none()
            && !self.renumbered
            && self.misplaced_bases.is_empty()
    }
}

/// The per-arrival context of one record from a peer (`protocol.md` 4.7 item
/// 2): the peer's proven device ID, the connection's memories
/// ([`licketysync_protocol::connection::Connection::memories_mut`]), this
/// device's wall clock (microseconds since the Unix epoch, 0 before 1970)
/// and the runtime's randomness.
pub struct Arrival<'a, 'r> {
    /// The peer, by the device ID its `DeviceProof` proved.
    pub peer: DeviceId,
    /// The connection's memory of the folder: records from the future
    /// refused on it.
    pub memory: &'a mut FolderMemory,
    /// The connection's one budget of verifications for notes, shared by
    /// every folder open on it: the engine passes the one
    /// [`licketysync_protocol::connection::Connection::memories_mut`] gives
    /// for the connection the record came on, never a budget of its own, or
    /// the bound on what a peer can make this device verify (about 2.4 % of a
    /// core per connection) no longer holds.
    pub notes: &'a mut NoteBudget,
    /// This device's wall clock, in microseconds.
    pub clock_us: u64,
    /// For a new epoch, should one be drawn.
    pub rng: &'a mut RandomFill<'r>,
}

/// What accepting one record did (`protocol.md` 4.7 item 2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Accepted {
    /// The record's hash.
    pub hash: RecordHash,
    /// The judgement for `Connection::judged`.
    pub judgement: Judgement,
    /// The section 5 rows it reached, for log lines.
    pub rows: Vec<Cause>,
    /// Its local sequence number, when it is now held.
    pub seq: Option<u64>,
    /// The records it dropped.
    pub dropped: Vec<RecordHash>,
    /// The paths whose heads changed (read and write holders).
    pub paths: Vec<String>,
    /// Whether what the folder wants of chunks changed.
    pub chunks_changed: bool,
    /// A record under this device's own ID above its high-water mark: the
    /// mark rose to it, and a new epoch was drawn.
    pub own_ahead: bool,
    /// A held record more than `CLOCK_AHEAD_WARNING` ahead of this device's
    /// clock: the lead, in microseconds, and the device ID it claims.
    pub clock_ahead: Option<(u64, DeviceId)>,
    /// A writer fault, held opaque; the issue names the record by its hash.
    pub writer_fault: Option<WriterFault>,
    /// From the future: the device ID it claims, as where it came from.
    pub from_future: Option<DeviceId>,
    /// A write holder noted it as a stale copy or a forgotten record.
    pub noted: bool,
    /// Why a write holder that would have noted it did not.
    pub not_noted: Option<NotNoted>,
}

impl Accepted {
    fn new(hash: RecordHash, judgement: Judgement) -> Self {
        Self {
            hash,
            judgement,
            rows: judgement.cause().into_iter().collect(),
            seq: None,
            dropped: Vec::new(),
            paths: Vec::new(),
            chunks_changed: false,
            own_ahead: false,
            clock_ahead: None,
            writer_fault: None,
            from_future: None,
            noted: false,
            not_noted: None,
        }
    }

    /// An outcome to collect a write's effects in.
    pub(crate) fn scratch() -> Self {
        Self::new(RecordHash([0; 32]), Judgement::Held)
    }

    fn judged(&mut self, judgement: Judgement) {
        self.judgement = judgement;
        if let Some(c) = judgement.cause() {
            if !self.rows.contains(&c) {
                self.rows.push(c);
            }
        }
    }
}

/// A transaction on an [`Index`]: every change of one engine handler is
/// staged in it, in memory, with an undo log. The handler then calls
/// [`Txn::finish`], which gives the change set to persist in its one commit
/// and a [`Pending`] that keeps the index borrowed until the commit's
/// outcome is known: [`Pending::commit`] keeps the changes, and dropping it
/// (or the transaction, at any point before) undoes them exactly, with
/// nothing rebuilt. While the index is borrowed, nothing outside the handler
/// can read or serve it; the handler itself reads staged state through
/// [`Txn::index`], the whole index, its serving methods included, and
/// nothing in the types stops it sending what it reads there. Serving and
/// sending only after the commit (4.5, "Durability before transmission") is
/// the engine's duty. On any error a method returns, the handler drops the
/// transaction.
pub struct Txn<'a> {
    pub(crate) ix: &'a mut Index,
    pub(crate) undo: Vec<Undo>,
    done: bool,
}

impl fmt::Debug for Txn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Txn")
            .field("changes", &self.undo.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.done {
            let undo = core::mem::take(&mut self.undo);
            self.ix.s.rollback(undo);
        }
    }
}

/// A finished transaction whose change set the store is committing:
/// [`Pending::commit`] once the commit succeeded,
/// or drop it (or [`Pending::abort`]) when it failed, which undoes every
/// staged change. The index stays borrowed meanwhile.
#[derive(Debug)]
pub struct Pending<'a>(Txn<'a>);

impl Pending<'_> {
    /// The store's commit succeeded: the staged changes stay.
    pub fn commit(mut self) {
        self.0.done = true;
        self.0.undo.clear();
    }

    /// The store's commit failed: every staged change is undone (as dropping
    /// the pending transaction does).
    pub fn abort(self) {}
}

impl Index {
    /// A new, empty index for a folder whose store is being made: the first
    /// epoch is drawn, the next local sequence number is 1 (4.5). The change
    /// set holds that metadata, for the engine to persist when it creates the
    /// store.
    #[must_use]
    pub fn create(key: FolderKey, own: DeviceId, rng: &mut RandomFill<'_>) -> (Self, ChangeSet) {
        let mut ix = Self::empty(key, own);
        ix.s.meta = StoredMeta {
            hw: 0,
            next_seq: 1,
            epoch: draw_epoch(rng),
        };
        let changes = ChangeSet {
            meta: Some(ix.s.meta),
            ..ChangeSet::default()
        };
        (ix, changes)
    }

    fn empty(key: FolderKey, own: DeviceId) -> Self {
        Self {
            verifier: *key.verifier(),
            keys: key.record_keys(),
            key,
            own,
            s: State::default(),
            bounds: Bounds::SPEC,
        }
    }

    /// Opens a transaction.
    pub fn begin(&mut self) -> Txn<'_> {
        Txn {
            ix: self,
            undo: Vec::new(),
            done: false,
        }
    }

    /// The folder's key.
    #[must_use]
    pub fn key(&self) -> &FolderKey {
        &self.key
    }

    /// The folder.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.verifier.folder_id()
    }

    /// This device's ID.
    #[must_use]
    pub fn own(&self) -> DeviceId {
        self.own
    }

    /// This device's tier for the folder.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.key.tier()
    }

    /// Records held: live records, tree deletes and cleanups (the Status's
    /// `index_records`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.s.held.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.s.held.is_empty()
    }

    /// The index epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.s.meta.epoch
    }

    /// The local sequence: the last number given to a record held, 0 for
    /// none (4.5).
    #[must_use]
    pub fn local_seq(&self) -> u64 {
        self.s.meta.next_seq.saturating_sub(1)
    }

    /// The high-water mark (0 at a sealed holder).
    #[must_use]
    pub fn hw(&self) -> u64 {
        self.s.meta.hw
    }

    /// The folder's own time `G`: the greatest counter of an applied record
    /// held (read and write holders; 0 at a sealed holder).
    #[must_use]
    pub fn folder_time(&self) -> u64 {
        self.s.folder_time()
    }

    /// The stored per-peer state of `peer`.
    #[must_use]
    pub fn peer(&self, peer: &DeviceId) -> Option<&PeerState> {
        self.s.peers.get(peer)
    }

    /// The next counter this device would write with at wall clock
    /// `clock_us` (4.4, "The writer's rule"): `max(hw + 1, min(clock_us,
    /// CLOCK_FLOOR_MAX))`, or `None` when it would pass `MAX_COUNTER`.
    #[must_use]
    pub fn next_counter(&self, clock_us: u64) -> Option<u64> {
        let next = self
            .s
            .meta
            .hw
            .saturating_add(1)
            .max(clock_us.min(CLOCK_FLOOR_MAX));
        (next <= MAX_COUNTER).then_some(next)
    }

    /// Whether this device is a read or write holder: it opens seals.
    pub(crate) fn key_holder(&self) -> bool {
        self.keys.is_some()
    }

    /// Whether this device is a write holder: it writes and notes.
    pub(crate) fn writer(&self) -> bool {
        self.key.write_key().is_some()
    }

    /// Step 7's verdict on `record` at a read or write holder.
    pub(crate) fn verdict(&self, record: &Record) -> Option<Verdict> {
        self.keys.as_ref().map(|k| record.open(k))
    }

    /// Opens a folder's index from its stored state (`protocol.md` 4.4,
    /// "Opening a folder"): every stored record and base kept only as a base
    /// gets step 1 against the folder and its signature again, at every tier,
    /// across the processor's cores; the records that pass are held again in
    /// their stored local-sequence order, with their stored numbers, as steps
    /// 6 to 9 would hold them, those another stored record replaces or that
    /// have expired dropped without a report; the stored high-water mark is
    /// checked; and a new epoch is drawn once if anything was dropped. The
    /// clock rule judges records on arrival only: nothing stored is removed
    /// for its counter, and a store whose newest applied record lies more than
    /// `CLOCK_RULE_LIMIT` ahead of `clock_us` keeps the folder from opening
    /// ([`OpenReport::opens_at`]).
    pub fn open(
        key: FolderKey,
        own: DeviceId,
        stored: Stored,
        clock_us: u64,
        rng: &mut RandomFill<'_>,
    ) -> (Self, OpenReport) {
        let threads = std::thread::available_parallelism().map_or(1, usize::from);
        Self::open_with_threads(key, own, stored, clock_us, rng, threads)
    }

    /// [`Index::open`] on at most `threads` verifying threads: the result is
    /// the same on any number.
    pub(crate) fn open_with_threads(
        key: FolderKey,
        own: DeviceId,
        stored: Stored,
        clock_us: u64,
        rng: &mut RandomFill<'_>,
        threads: usize,
    ) -> (Self, OpenReport) {
        crate::open::open(Self::empty(key, own), stored, clock_us, rng, threads)
    }
}

impl<'a> Txn<'a> {
    /// Ends the handler's staging: the change set to persist in its one
    /// commit, and the [`Pending`] transaction to commit or drop once the
    /// store's commit has succeeded or failed.
    #[must_use]
    pub fn finish(self) -> (ChangeSet, Pending<'a>) {
        let changes = self.ix.s.changes(&self.undo);
        (changes, Pending(self))
    }
}

impl Txn<'_> {
    /// The index as staged so far, for the handler's own decisions: reads
    /// see its changes. It is the whole [`Index`], its serving methods
    /// included, and nothing in the type stops a handler sending what it
    /// reads here: serving only after the commit (4.5, "Durability before
    /// transmission") is the engine's duty, since a page served from staged
    /// changes could send what a failed commit never stored.
    #[must_use]
    pub fn index(&self) -> &Index {
        self.ix
    }

    /// Keeps the staged changes in memory with nothing persisted: for the
    /// open, whose changes the caller persists from its report.
    pub(crate) fn keep(mut self) {
        self.done = true;
        self.undo.clear();
    }

    /// The handler gave up: every staged change is undone (as dropping the
    /// transaction does).
    pub fn abort(self) {}

    /// Draws a new index epoch (4.5): for a peer's `since` above the local
    /// sequence (at most once per connection), and for the rules that draw
    /// one inside the index.
    pub fn redraw_epoch(&mut self, rng: &mut RandomFill<'_>) {
        let meta = StoredMeta {
            epoch: draw_epoch(rng),
            ..self.ix.s.meta
        };
        self.ix.s.set_meta(meta, Some(&mut self.undo));
    }

    /// The next local sequence number, renumbering every record held afresh
    /// from 1 under a new epoch when it would pass `MAX_LOCAL_SEQ` (4.5).
    pub(crate) fn next_seq(&mut self, rng: &mut RandomFill<'_>) -> u64 {
        if self.ix.s.meta.next_seq > MAX_LOCAL_SEQ {
            self.renumber(rng);
        }
        let seq = self.ix.s.meta.next_seq.max(1);
        let meta = StoredMeta {
            next_seq: seq + 1,
            ..self.ix.s.meta
        };
        self.ix.s.set_meta(meta, Some(&mut self.undo));
        seq
    }

    fn renumber(&mut self, rng: &mut RandomFill<'_>) {
        let order: Vec<RecordHash> = self.ix.s.by_seq.values().copied().collect();
        let mut next = 1;
        for h in order {
            if let Some(held) = self.ix.s.held.get(&h).cloned() {
                self.ix.s.unhold(&h, Some(&mut self.undo));
                self.ix
                    .s
                    .hold(Held { seq: next, ..held }, Some(&mut self.undo));
                next += 1;
            }
        }
        let meta = StoredMeta {
            next_seq: next,
            epoch: draw_epoch(rng),
            ..self.ix.s.meta
        };
        self.ix.s.set_meta(meta, Some(&mut self.undo));
    }

    /// Steps 2 to 9 of 4.4 for one record from a peer that passed step 1
    /// (`Record::from_bytes` on the connection), in this order and at these
    /// costs (TM-22):
    ///
    /// - a duplicate is ignored, never verified;
    /// - at a read or write holder its seal is checked by step 7 first,
    ///   charging no one, and a deletion or cleanup the folder's own time has
    ///   passed by its horizon is expired, before anything it replaces is
    ///   looked at;
    /// - a record that replaces nothing held (for a tree delete, judged
    ///   through the index by path, never by a walk) and that something held
    ///   names, or covers at its tag or from a tree delete above it (found in
    ///   `O(L)` for a path of `L` bytes), is obsolete;
    /// - both are ignored unverified, unless a write holder would note it,
    ///   which verifies it first;
    /// - a record more than `CLOCK_RULE_LIMIT` ahead of the clock is from the
    ///   future, verified and refused (once per connection);
    /// - then the signature;
    /// - then the store: what it replaces is dropped, it is held unless
    ///   something held replaces it (beneath a tree delete, step 8), the
    ///   cleanup groups whose `because` it is apply, and an applied record
    ///   raises the high-water mark and the folder's own time, which expires
    ///   what it passes by a horizon.
    ///
    /// # Errors
    /// [`Cause::Forged`] when the signature fails where it is verified: the
    /// connection closes, and nothing was staged for the record.
    pub fn accept(&mut self, record: Record, a: &mut Arrival<'_, '_>) -> Result<Accepted, Cause> {
        let hash = record.hash();
        if self.ix.s.is_held(&hash) {
            return Ok(Accepted::new(hash, Judgement::Duplicate));
        }
        let verdict = self.ix.verdict(&record);
        let applied = verdict.as_ref().and_then(|v| v.as_ref().ok());
        // Step 3. Expiry first: it reads only the folder's time, whatever
        // the record replaces (the coordinator's ruling IS-1(a)).
        if let Some(app) = applied {
            if self.expired(app) {
                let mut out = Accepted::new(hash, Judgement::Expired);
                (out.noted, out.not_noted) = self.note(&record, applied, false, a)?;
                return Ok(out);
            }
        }
        // Then obsolete, when it replaces nothing held: for a tree delete,
        // judged through the index by path, never by a walk.
        if !self.ix.s.replaces_any(&record, applied) {
            if self.ix.s.named(&record) {
                return Ok(Accepted::new(hash, Judgement::Obsolete));
            }
            if let (Some(tag), Some(meta)) = (record.path_tag(), applied.and_then(Applied::meta)) {
                if self.ix.s.covered(&tag, meta, None).is_some() {
                    let mut out = Accepted::new(hash, Judgement::Obsolete);
                    (out.noted, out.not_noted) = self.note(&record, applied, false, a)?;
                    return Ok(out);
                }
            }
        }
        if let Some(app) = applied {
            // Step 4, the clock rule.
            if app.dot().counter > a.clock_us.saturating_add(CLOCK_RULE_LIMIT) {
                let mut out = Accepted::new(hash, Judgement::FromTheFuture);
                if !a.memory.knows_future(&hash) {
                    record.verify(&self.ix.verifier)?;
                    a.memory.remember_future(hash);
                    out.from_future = Some(app.dot().device);
                }
                return Ok(out);
            }
        }
        // Step 5.
        record.verify(&self.ix.verifier)?;
        // Steps 6 to 9.
        let replaces = self.ix.s.replaced_by(&record, applied);
        let mut out = Accepted::new(hash, Judgement::Held);
        if !replaces.is_empty() {
            out.rows.push(Cause::ReplacesHeld);
        }
        if let Some(Err(fault)) = &verdict {
            out.writer_fault = Some(fault.clone());
        }
        let applied = applied.cloned();
        let clock_us = a.clock_us;
        match self.store(
            record,
            verdict,
            &replaces,
            Seq::Next(a.rng),
            clock_us,
            &mut out,
        ) {
            Ok(seq) => {
                out.seq = Some(seq);
                if out.writer_fault.is_some() {
                    out.judged(Judgement::HeldOpaque);
                }
            }
            Err(refused) => {
                let (record, by) = *refused;
                out.judged(if matches!(by, Replacer::Beneath(_)) {
                    Judgement::DroppedBeneath
                } else {
                    Judgement::Obsolete
                });
                (out.noted, out.not_noted) = self.note(&record, applied.as_ref(), true, a)?;
            }
        }
        Ok(out)
    }

    /// Whether an applied deletion or cleanup has expired: the folder's own
    /// time has passed its counter by more than its horizon.
    fn expired(&self, applied: &Applied) -> bool {
        let horizon = match applied {
            Applied::Index(m) if m.deleted => TOMBSTONE_HORIZON,
            Applied::Index(_) => return false,
            Applied::Cleanup(_) => CLEANUP_HORIZON,
        };
        self.ix
            .s
            .folder_time()
            .saturating_sub(applied.dot().counter)
            > horizon
    }

    /// Step 6 for a record verified (or written here, or replayed at open):
    /// drops what it replaces, holds it unless something held replaces it
    /// (giving it back, with what replaces it), lets the groups whose
    /// `because` it is apply, and, for an applied record held, raises the
    /// high-water mark and the folder's own time and expires what that
    /// passes. Returns its local sequence number when it is held.
    pub(crate) fn store(
        &mut self,
        record: Record,
        verdict: Option<Verdict>,
        replaces: &std::collections::BTreeSet<RecordHash>,
        seq: Seq<'_, '_>,
        clock_us: u64,
        out: &mut Accepted,
    ) -> Result<u64, Box<(Record, Replacer)>> {
        let hash = record.hash();
        for h in replaces {
            self.drop_record(h, out);
        }
        let applied = verdict.as_ref().and_then(|v| v.as_ref().ok()).cloned();
        if let Some(rep) = self.ix.s.replacer(&record, applied.as_ref()) {
            return Err(Box::new((record, rep)));
        }
        let (seq, rng, own_write) = match seq {
            Seq::Stored(n) => (n, None, false),
            Seq::Next(r) => (self.next_seq(r), Some(r), false),
            Seq::Own(r) => (self.next_seq(r), None, true),
        };
        if let Some(meta) = applied.as_ref().and_then(Applied::meta) {
            out.paths.push(meta.path.clone());
        }
        out.chunks_changed |= !record.chunks().is_empty();
        if record
            .groups()
            .iter()
            .any(|g| g.because.is_some_and(|b| !self.ix.s.is_held(&b)))
        {
            out.rows.push(Cause::CleanupGroupWaiting);
        }
        self.ix.s.hold(
            Held {
                record,
                seq,
                verdict,
            },
            Some(&mut self.undo),
        );
        // The groups whose `because` this record is now apply.
        self.apply_groups_because(&hash, out);
        if let Some(app) = applied {
            let counter = app.dot().counter;
            let meta = self.ix.s.meta;
            if counter > meta.hw {
                if !own_write && app.dot().device == self.ix.own && self.ix.key_holder() {
                    out.own_ahead = true;
                    out.rows.push(Cause::OwnCounterAhead);
                    if let Some(r) = rng {
                        self.redraw_epoch(r);
                    }
                }
                let meta = StoredMeta {
                    hw: counter,
                    ..self.ix.s.meta
                };
                self.ix.s.set_meta(meta, Some(&mut self.undo));
            }
            if !own_write && counter > clock_us.saturating_add(CLOCK_AHEAD_WARNING) {
                out.clock_ahead = Some((counter - clock_us, app.dot().device));
                out.rows.push(Cause::ClockAhead);
            }
            self.expire(out);
        }
        Ok(seq)
    }

    /// Drops a held record, with the paths and chunks it touches.
    pub(crate) fn drop_record(&mut self, hash: &RecordHash, out: &mut Accepted) {
        if let Some(h) = self.ix.s.held.get(hash) {
            if let Some(m) = h.meta() {
                out.paths.push(m.path.clone());
            }
            out.chunks_changed |= !h.record.chunks().is_empty();
        }
        if self.ix.s.unhold(hash, Some(&mut self.undo)).is_some() {
            out.dropped.push(*hash);
        }
    }

    /// The groups whose `because` is `hash` apply: what they name is dropped.
    fn apply_groups_because(&mut self, hash: &RecordHash, out: &mut Accepted) {
        let named: Vec<RecordHash> = self
            .ix
            .s
            .groups_because(hash)
            .into_iter()
            .filter(|h| self.ix.s.is_held(h))
            .collect();
        for h in named {
            self.drop_record(&h, out);
        }
    }

    /// Expiry by the folder's own time (4.4, "Expiry"): every deletion and
    /// cleanup the folder's time has passed by its horizon is dropped, with
    /// any base that is that deletion.
    pub(crate) fn expire(&mut self, out: &mut Accepted) {
        if !self.ix.key_holder() {
            return;
        }
        for h in self.ix.s.expired(TOMBSTONE_HORIZON, CLEANUP_HORIZON) {
            let slots: Vec<_> = self
                .ix
                .s
                .slots_of
                .get(&h)
                .into_iter()
                .flatten()
                .cloned()
                .collect();
            for slot in slots {
                self.ix.s.set_base(slot, None, None, Some(&mut self.undo));
            }
            self.drop_record(&h, out);
        }
    }

    /// A write holder notes a record a peer offered (4.5, "Stale copies"),
    /// when all of these hold, in this order: no note of it exists; nothing
    /// held names it at its tag and no held cleanup names it in any group;
    /// the peer is within `MAX_PEER_NAMES` in the current window; this round
    /// has verified fewer than `MAX_NOTE_VERIFICATIONS` records for notes
    /// (unless it is `verified` already); and its signature verifies. A
    /// record something held replaces is a stale copy, noted with its tag,
    /// path and dot; an expired one is a forgotten record. At most
    /// `MAX_STALE_KNOWN` notes are kept, the oldest dropped first.
    ///
    /// # Errors
    /// [`Cause::Forged`].
    fn note(
        &mut self,
        record: &Record,
        applied: Option<&Applied>,
        verified: bool,
        a: &mut Arrival<'_, '_>,
    ) -> Result<(bool, Option<NotNoted>), Cause> {
        let hash = record.hash();
        if !self.ix.writer() || self.ix.s.notes.contains_key(&hash) {
            return Ok((false, None));
        }
        if record
            .path_tag()
            .is_some_and(|t| self.ix.s.named_at(&t, &hash))
            || self.ix.s.named_by_any_group(&hash)
        {
            return Ok((false, None));
        }
        if self.peer_names(&a.peer, a.clock_us) >= self.ix.bounds.peer_names {
            return Ok((false, Some(NotNoted::PeerNames)));
        }
        if !verified {
            if !a.notes.may_verify() {
                return Ok((false, Some(NotNoted::Verifications)));
            }
            a.notes.verified();
            record.verify(&self.ix.verifier)?;
        }
        let expired = applied.is_some_and(|app| self.expired(app));
        let noted = match (record.path_tag(), applied.and_then(Applied::meta)) {
            (Some(tag), Some(m)) if !expired => Noted::Stale {
                tag,
                path: m.path.clone(),
                dot: m.dot,
                tree: m.tree,
            },
            _ => Noted::Forgotten,
        };
        while self.ix.s.notes.len() >= self.ix.bounds.stale_known {
            let Some((_, oldest)) = self.ix.s.note_order.iter().next().map(|(n, h)| (*n, *h))
            else {
                break;
            };
            self.ix.s.remove_note(&oldest, Some(&mut self.undo));
        }
        let nr = self.ix.s.next_note;
        self.ix.s.add_note(
            Note {
                hash,
                peer: a.peer,
                noted,
                nr,
            },
            Some(&mut self.undo),
        );
        Ok((true, None))
    }

    /// The names of `peer`'s records this write holder has given in the
    /// current window of `CLEANUP_HORIZON`, by its wall clock.
    pub(crate) fn peer_names(&self, peer: &DeviceId, clock_us: u64) -> u64 {
        self.ix
            .s
            .peers
            .get(peer)
            .filter(|p| clock_us < p.names_window_us.saturating_add(CLEANUP_HORIZON))
            .map_or(0, |p| p.names)
    }

    /// Counts `n` names of `peer`'s records given now, at the end of a round
    /// with it (which a state made here records as its last round's end, so
    /// that `PEER_STATE_HORIZON` counts from it as at open).
    pub(crate) fn count_names(&mut self, peer: &DeviceId, n: u64, clock_us: u64) {
        let mut state = self.ix.s.peers.get(peer).copied().unwrap_or(PeerState {
            round_ended_us: clock_us,
            ..PeerState::default()
        });
        if clock_us >= state.names_window_us.saturating_add(CLEANUP_HORIZON) {
            state.names_window_us = clock_us;
            state.names = 0;
        }
        state.names = state.names.saturating_add(n);
        self.set_peer(*peer, state);
    }

    /// Sets a peer's state, keeping at most `MAX_PEER_STATES` per folder: the
    /// one longest without a round goes to admit another.
    pub(crate) fn set_peer(&mut self, peer: DeviceId, state: PeerState) {
        use licketysync_protocol::limits::MAX_PEER_STATES;
        if !self.ix.s.peers.contains_key(&peer) && self.ix.s.peers.len() >= MAX_PEER_STATES {
            let oldest = self
                .ix
                .s
                .peers
                .iter()
                .min_by_key(|(d, p)| (p.round_ended_us, **d))
                .map(|(d, _)| *d);
            if let Some(d) = oldest {
                self.ix.s.set_peer(d, None, Some(&mut self.undo));
            }
        }
        self.ix.s.set_peer(peer, Some(state), Some(&mut self.undo));
    }

    /// A round of this side's with `peer` ended (4.5, "Per-peer state";
    /// [`licketysync_protocol::connection::Event::RoundCompleted`]): the
    /// cursor it sets, unless it skipped a record, and when it ended, caught
    /// up or not. Per-peer state past `PEER_STATE_HORIZON` without a round is
    /// dropped meanwhile.
    pub fn round_ended(
        &mut self,
        peer: DeviceId,
        caught_up: bool,
        cursor: Option<(u64, u64)>,
        clock_us: u64,
    ) {
        let mut state = self.ix.s.peers.get(&peer).copied().unwrap_or_default();
        if let Some((epoch, c)) = cursor {
            state.epoch = epoch;
            state.cursor = c;
        }
        state.round_ended_us = clock_us;
        state.caught_up = caught_up;
        self.set_peer(peer, state);
        self.forget_peers(clock_us);
    }

    /// A counted push raised `peer`'s cursor (4.5, "Cursors").
    pub fn cursor_advanced(&mut self, peer: DeviceId, epoch: u64, through: u64) {
        let mut state = self.ix.s.peers.get(&peer).copied().unwrap_or_default();
        if state.epoch == epoch && through > state.cursor {
            state.cursor = through;
            self.set_peer(peer, state);
        }
    }

    /// Drops per-peer state past `PEER_STATE_HORIZON` without a round that
    /// ended, by this device's wall clock.
    pub(crate) fn forget_peers(&mut self, clock_us: u64) {
        use licketysync_protocol::limits::PEER_STATE_HORIZON;
        let old: Vec<DeviceId> = self
            .ix
            .s
            .peers
            .iter()
            .filter(|(_, p)| clock_us.saturating_sub(p.round_ended_us) > PEER_STATE_HORIZON)
            .map(|(d, _)| *d)
            .collect();
        for d in old {
            self.ix.s.set_peer(d, None, Some(&mut self.undo));
        }
    }

    /// The tag a path has, at a read or write holder.
    pub(crate) fn tag(&self, path: &str) -> Option<PathTag> {
        self.ix.keys.as_ref().map(|k| k.path_tag(path))
    }
}
