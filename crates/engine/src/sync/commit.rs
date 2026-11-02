// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Phase B: one transaction per folder with work, one storage commit
//! (`protocol.md` 4.7 item 1; the module documentation of `super`).
//!
//! Per folder, in this order: a local write (first, so that a write the
//! index refuses is dropped with nothing else staged), the records of each
//! queued page, the ends of rounds with their cleanups, the cursors, an epoch
//! drawn for a reset, the chunk frees due, then the bases of every path
//! whose content is now on the disk (`super::disk`). Each transaction's
//! change set is staged, with the chunks it left unnamed onto the
//! pending-free list, beside the chunk blobs phase A staged and the blobs
//! found changed at rest whose deletion was pending; then one commit. On
//! success every transaction is committed; on failure they are dropped,
//! which undoes them exactly, and the folders they changed are paused
//! (`crate::pause`).

use std::collections::BTreeSet;

use licketysync_index::{Arrival, Change, ChangeSet, Pending, Txn, WriteError};
use licketysync_keys::chunk::SealedChunk;
use licketysync_keys::{CipherHash, FolderId, RecordHash};
use licketysync_protocol::connection::{Judgement, Page};
use licketysync_protocol::record::Record;
use licketysync_protocol::Cause;

use super::{Judged, Op, SyncWork};
use crate::chunks::ChunkBook;
use crate::conn::Conn;
use crate::engine::{tick, Engine};
use crate::folder::Folder;
use crate::issues::{bump, Counters, Issue, IssueKind, Issues, Subject};
use crate::runtime::{Context, PeerId, StorageError};
use crate::store::{free_key, stage_changes, stage_chunk, stage_chunk_delete};
use crate::work::Work;
use crate::write::WriteFailure;

/// What one folder's transaction leaves for after the commit.
struct Done<'a> {
    folder: FolderId,
    pending: Pending<'a>,
    /// The chunks it left unnamed, now on the pending-free list.
    freed: Vec<CipherHash>,
    /// The pending frees it carried out: deleted (not named any more).
    deleted: Vec<CipherHash>,
    /// The pending frees it took off the list.
    took_frees: bool,
    /// It carried what the open changed (`Folder::open_changes`).
    took_open: bool,
}

/// The engine's state one folder's transaction reads and writes beside the
/// folder.
struct Shared<'e> {
    conns: &'e mut std::collections::BTreeMap<PeerId, Conn>,
    sync: &'e mut SyncWork,
    counters: &'e mut Counters,
    issues: &'e mut Issues,
    clock_us: u64,
}

impl Engine {
    /// Phase B (module documentation): on success the handler may send; on
    /// failure every folder it changed is paused.
    pub(crate) fn commit(&mut self, cx: &mut dyn Context, work: &mut Work) {
        for (folder, ops) in core::mem::take(&mut self.deferred) {
            for op in ops {
                work.sync.queue(folder, op);
            }
        }
        let result = match work.failed.take() {
            Some(e) => Err(e),
            None => self.run_transactions(cx, work),
        };
        match result {
            Ok(()) => {
                work.committed = true;
                for (folder, n) in core::mem::take(&mut work.sync.new_chunks) {
                    for _ in 0..n {
                        work.chunk_stored(folder);
                    }
                }
                if core::mem::take(&mut work.sync.probing) {
                    self.resume(cx, work);
                }
            }
            Err(e) => {
                // The folders phase B meant to change, or that staged a
                // chunk in phase A, changed; any other folder with work had
                // its pages skipped.
                let changed: BTreeSet<FolderId> = work
                    .sync
                    .changed
                    .iter()
                    .chain(work.touched.iter())
                    .copied()
                    .collect();
                self.failed_commit(cx, work, &changed, e);
            }
        }
    }

    /// Every folder's transaction, the staging and the one commit.
    fn run_transactions(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
    ) -> Result<(), StorageError> {
        let clock_us = cx.wall_time_us();
        let Self {
            folders,
            conns,
            counters,
            issues,
            forget,
            ..
        } = self;
        let mut shared = Shared {
            conns,
            sync: &mut work.sync,
            counters,
            issues,
            clock_us,
        };
        let mut done: Vec<Done<'_>> = Vec::new();
        let mut staged = work.staged;
        for (id, f) in folders.iter_mut() {
            let ops = shared.sync.ops.remove(id).unwrap_or_default();
            let recheck =
                core::mem::take(&mut f.recheck_disk) || work.chunks_stored.contains_key(id);
            if ops.is_empty() && !f.free_due && !recheck && f.open_changes.is_none() {
                continue;
            }
            if f.held_paused() || !f.credentialed() {
                // Held paused: its store refuses changes until it resumes;
                // pages were answered skipped in phase A, writes refused up
                // front, and the ends of rounds and cursors wait for a round
                // after the resume.
                continue;
            }
            if !ops.is_empty() {
                shared.sync.changed.insert(*id);
            }
            let outcome = match run_folder(f, ops, &mut shared, cx) {
                Ok(o) => o,
                Err(e) => {
                    shared.sync.changed.insert(*id);
                    return Err(e);
                }
            };
            if outcome.staged {
                shared.sync.changed.insert(*id);
            }
            staged |= outcome.staged;
            done.push(outcome.done);
        }
        // A handler whose change sets are all empty (a page of duplicates,
        // say) commits nothing: its transactions are committed in memory
        // only. The deletions of blobs found changed at rest ride a commit
        // that happens anyway (the `work` module).
        let mut forgotten = Vec::new();
        if staged {
            forgotten = stage_forgotten(forget, cx)?;
        }
        let commit = if staged {
            cx.storage().commit()
        } else {
            Ok(())
        };
        if let Err(e) = commit {
            forget.extend(forgotten);
            return Err(e);
        }
        let mut after = Vec::new();
        for d in done {
            d.pending.commit();
            after.push((d.folder, d.freed, d.deleted, d.took_frees, d.took_open));
        }
        for (id, freed, deleted, took, took_open) in after {
            if let Some(f) = folders.get_mut(&id) {
                if took {
                    f.pending_free.clear();
                    f.free_due = false;
                }
                if took_open {
                    if let Some(open) = f.open_changes.take() {
                        f.pending_free.extend(open.freed);
                    }
                }
                f.pending_free.extend(freed);
                // Each deleted blob marks the book; what the transaction
                // held or dropped marked it in phase B.
                for h in &deleted {
                    f.book.forget(h);
                }
            }
        }
        Ok(())
    }
}

/// Stages the deletion of each blob found changed at rest whose deletion was
/// pending, and its marker. Returns what it took from the pending set, to
/// put back if the commit fails (and every entry is put back then, a blob
/// stored again in this handler included: its good copy was rolled back with
/// the rest, C-H). A blob stored again since overwrote both, so its deletion
/// is not staged; such an entry goes only once the commit succeeds.
fn stage_forgotten(
    forget: &mut BTreeSet<(FolderId, CipherHash)>,
    cx: &mut dyn Context,
) -> Result<Vec<(FolderId, CipherHash)>, StorageError> {
    let taken: Vec<(FolderId, CipherHash)> = core::mem::take(forget).into_iter().collect();
    let storage = cx.storage();
    let staged = taken.iter().try_for_each(|(f, h)| {
        // A blob stored again in this handler has a staged put over it;
        // reading back what is staged tells: if it is there and hashes to
        // its name, it is the good copy, and nothing is deleted.
        match storage.get(&crate::store::chunk_key(f, h)) {
            Ok(Some(blob)) if licketysync_keys::chunk::cipher_hash(&blob) == *h => Ok(()),
            _ => stage_chunk_delete(storage, f, h),
        }
    });
    match staged {
        Ok(()) => Ok(taken),
        Err(e) => {
            forget.extend(taken);
            Err(e)
        }
    }
}

/// What one folder's transaction gave.
struct FolderOutcome<'a> {
    done: Done<'a>,
    staged: bool,
}

/// One folder's transaction (module documentation).
fn run_folder<'f>(
    f: &'f mut Folder,
    ops: Vec<Op>,
    shared: &mut Shared<'_>,
    cx: &mut dyn Context,
) -> Result<FolderOutcome<'f>, StorageError> {
    let Folder {
        id,
        index,
        book,
        unapplied,
        record_keys,
        pending_free,
        free_due,
        open_changes,
        ..
    } = f;
    let folder = *id;
    let mut staged = false;
    let took_open = open_changes.is_some();
    if let Some(open) = open_changes {
        stage_changes(cx.storage(), &folder, open)?;
        staged = true;
    }
    let mut txn = index.begin();
    let mut paths: BTreeSet<String> = BTreeSet::new();
    let mut do_free = *free_due;
    for op in ops {
        match op {
            Op::Write {
                changes,
                blobs,
                target,
            } => {
                match write(
                    &mut txn,
                    &changes,
                    &blobs,
                    target.as_deref(),
                    folder,
                    shared,
                    cx,
                    book,
                ) {
                    Ok(written_paths) => {
                        staged = true;
                        paths.extend(written_paths);
                    }
                    Err(Stop::Store(e)) => return Err(e),
                    // The index refuses a batch before it stages anything of
                    // it (`Txn::write`), so the transaction goes on.
                    Err(Stop::Refused(why)) => shared.sync.written = Some(Err(why)),
                }
            }
            Op::Records {
                peer,
                page,
                records,
            } => {
                let (judged, changed) = accept_page(
                    &mut txn, folder, peer, page, records, shared, cx, &mut paths,
                );
                // A page that held or dropped nothing (duplicates, say)
                // changes nothing the chunk book is computed from.
                book.dirty |= changed;
                shared.sync.judged.push(judged);
            }
            Op::RoundEnded {
                peer,
                device,
                caught_up,
                cursor,
            } => {
                txn.round_ended(device, caught_up, cursor, shared.clock_us);
                round_cleanups(&mut txn, folder, peer, shared, cx, book, &mut paths);
                do_free = true;
            }
            Op::CursorAdvanced {
                device,
                epoch,
                through,
            } => txn.cursor_advanced(device, epoch, through),
            Op::Redraw => txn.redraw_epoch(&mut |b: &mut [u8]| cx.fill_random(b)),
        }
    }
    let mut deleted = Vec::new();
    if do_free {
        for h in pending_free.iter() {
            cx.storage().delete(&free_key(&folder, h))?;
            if !txn.index().names_chunk(h) {
                stage_chunk_delete(cx.storage(), &folder, h)?;
                deleted.push(*h);
            }
        }
        staged |= !pending_free.is_empty();
    }
    if record_keys.is_some() {
        super::disk::apply(&mut txn, book, unapplied, paths, shared.counters);
    }
    let (changes, pending): (ChangeSet, Pending<'f>) = txn.finish();
    if !changes.is_empty() || !changes.freed.is_empty() {
        stage_changes(cx.storage(), &folder, &changes)?;
        staged = true;
    }
    Ok(FolderOutcome {
        done: Done {
            folder,
            pending,
            freed: changes.freed,
            deleted,
            took_frees: do_free,
            took_open,
        },
        staged,
    })
}

/// The cleanups of a round's end (4.4, "Cleanup", cases (b) and (c)):
/// pushed once committed, and, when one was written, another round owed on
/// the connection whose round ended, so that the next ends at `EQUAL` once
/// they have done their work (4.5, "Round owed").
fn round_cleanups(
    txn: &mut Txn<'_>,
    folder: FolderId,
    peer: PeerId,
    shared: &mut Shared<'_>,
    cx: &mut dyn Context,
    book: &mut ChunkBook,
    paths: &mut BTreeSet<String>,
) {
    match txn.end_round(shared.clock_us, &mut |b: &mut [u8]| cx.fill_random(b)) {
        Ok(w) => {
            for (hash, seq) in &w.records {
                if seq.is_some() {
                    shared.sync.push(folder, *hash, None);
                }
            }
            if w.cleanup {
                shared.sync.owe.insert((folder, Some(peer)));
            }
            if !w.dropped.is_empty() {
                book.dirty = true;
            }
            paths.extend(w.paths);
        }
        Err(WriteError::CounterExhausted) => shared.counters.log(Cause::CounterExhausted),
        Err(_) => shared.counters.bug(),
    }
}

/// Why a write stopped.
enum Stop {
    /// The store failed: the handler rolls back.
    Store(StorageError),
    /// The index refused the write; nothing of it was staged.
    Refused(WriteFailure),
}

/// A local write in the transaction: the records signed, the new chunks'
/// blobs staged, the records to push, and the version the write returns.
#[allow(
    clippy::too_many_arguments,
    reason = "one phase B step and its context"
)]
fn write(
    txn: &mut Txn<'_>,
    changes: &[Change],
    blobs: &[SealedChunk],
    target: Option<&str>,
    folder: FolderId,
    shared: &mut Shared<'_>,
    cx: &mut dyn Context,
    book: &mut ChunkBook,
) -> Result<Vec<String>, Stop> {
    let written = txn
        .write(changes, shared.clock_us, &mut |b: &mut [u8]| {
            cx.fill_random(b);
        })
        .map_err(|e| Stop::Refused(crate::write::write_error(&e)))?;
    for blob in blobs {
        stage_chunk(cx.storage(), &folder, &blob.cipher_hash, &blob.stored).map_err(Stop::Store)?;
        if !book.is_stored(&blob.cipher_hash) {
            let n = shared.sync.new_chunks.entry(folder).or_insert(0);
            *n = n.saturating_add(1);
        }
        book.mark_stored(blob.cipher_hash);
    }
    let held: BTreeSet<RecordHash> = written.records.iter().map(|(h, _)| *h).collect();
    for (hash, seq) in &written.records {
        if seq.is_some() {
            shared.sync.push(folder, *hash, None);
        }
    }
    let at = match target {
        Some(path) => txn
            .index()
            .path(path)
            .and_then(|v| v.heads.iter().map(|h| h.hash).find(|h| held.contains(h))),
        None => written.records.first().map(|(h, _)| *h),
    };
    shared.sync.written = Some(at.ok_or(WriteFailure::Internal));
    // A write holds what it signed, so the chunk book is computed again.
    book.dirty = true;
    Ok(written.paths)
}

/// Steps 2 to 9 of 4.4 for one page's records from `peer`, in order, up to
/// and including the first refusal that closes (a forged record), with the
/// connection's own memories and verification budget. Its judgements, and
/// whether a record was held or dropped.
#[allow(
    clippy::too_many_arguments,
    reason = "one phase B step and its context"
)]
fn accept_page(
    txn: &mut Txn<'_>,
    folder: FolderId,
    peer: PeerId,
    page: Page,
    records: Vec<Record>,
    shared: &mut Shared<'_>,
    cx: &mut dyn Context,
    paths: &mut BTreeSet<String>,
) -> (Judged, bool) {
    let n = records.len();
    let t = tick(cx, peer);
    let Shared {
        conns,
        sync,
        counters,
        issues,
        clock_us,
    } = shared;
    let device = conns.get(&peer).and_then(|c| c.device);
    let memories = conns
        .get_mut(&peer)
        .and_then(|c| c.protocol.memories_mut(t, &folder));
    let (Some(device), Some((memory, notes))) = (device, memories) else {
        // The connection closed since the page came: nothing to judge for.
        return (Judged::skipped(peer, folder, page, n), false);
    };
    let mut fill = |b: &mut [u8]| cx.fill_random(b);
    let mut arrival = Arrival {
        peer: device,
        memory,
        notes,
        clock_us: *clock_us,
        rng: &mut fill,
    };
    let mut results = Vec::with_capacity(n);
    let mut changed = false;
    for record in records {
        match txn.accept(record, &mut arrival) {
            Ok(acc) => {
                results.push(Ok(acc.judgement));
                for cause in &acc.rows {
                    counters.log(*cause);
                }
                if acc.judgement.held() {
                    sync.push(folder, acc.hash, Some(peer));
                }
                changed |= acc.judgement.held() || !acc.dropped.is_empty();
                paths.extend(acc.paths.iter().cloned());
                note(folder, acc.hash, &acc, issues, counters);
            }
            Err(cause) => {
                counters.log(cause);
                results.push(Err(cause));
                break;
            }
        }
    }
    let judged = Judged {
        peer,
        folder,
        page,
        results,
    };
    (judged, changed)
}

/// The issues and counters one accepted record raises (4.7 item 7).
fn note(
    folder: FolderId,
    hash: RecordHash,
    acc: &licketysync_index::Accepted,
    issues: &mut Issues,
    counters: &mut Counters,
) {
    let mut raise = |kind, subject| {
        issues.raise(Issue {
            folder: Some(folder),
            kind,
            subject,
        });
    };
    if let Some(fault) = &acc.writer_fault {
        let shared = fault.is_shared();
        raise(IssueKind::WriterFault { shared }, Subject::Record(hash));
    }
    if acc.own_ahead {
        raise(IssueKind::OwnCounterAhead, Subject::None);
    }
    if let Some((lead_us, device)) = acc.clock_ahead {
        raise(
            IssueKind::ClockAhead,
            Subject::ClockAhead { lead_us, device },
        );
    }
    if let Some(device) = acc.from_future {
        raise(IssueKind::FromTheFuture, Subject::Device(device));
    }
    if acc.noted {
        bump(&mut counters.stale_noted);
    }
    if acc.not_noted.is_some() {
        bump(&mut counters.stale_not_noted);
    }
}

impl Engine {
    /// The commit failed (or a put before it): every transaction was
    /// dropped, which undid it, and the storage is rolled back. The pages
    /// judged report their held records skipped (a reply that lost a page
    /// is void up to its last), nothing is pushed, a local write fails, and
    /// every folder the handler meant to change is paused; any other folder
    /// whose records it skipped is owed a round.
    fn failed_commit(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        changed: &BTreeSet<FolderId>,
        e: StorageError,
    ) {
        cx.storage().rollback();
        bump(&mut self.counters.store_failures);
        let cause = crate::issues::StoreFailureCause::of(&e);
        work.chunks_stored.clear();
        work.sync.pushes.clear();
        if work.wrote && !matches!(work.sync.written, Some(Err(_))) {
            work.sync.written = Some(Err(WriteFailure::Store(cause)));
        }
        // Pages queued but never judged, because a put in phase A failed.
        for (folder, ops) in core::mem::take(&mut work.sync.ops) {
            for op in ops {
                if let Op::Records {
                    peer,
                    page,
                    records,
                } = op
                {
                    work.sync
                        .judged
                        .push(Judged::skipped(peer, folder, page, records.len()));
                }
            }
        }
        for j in &mut work.sync.judged {
            let mut lost = false;
            for r in &mut j.results {
                if matches!(r, Ok(x) if x.held()) {
                    *r = Ok(Judgement::Skipped);
                    lost = true;
                }
            }
            if lost
                || j.results
                    .iter()
                    .any(|r| matches!(r, Ok(Judgement::Skipped)))
            {
                work.skipped.insert(j.folder);
                if let (Page::Reply { last: false, .. }, Some(c)) =
                    (j.page, self.conns.get_mut(&j.peer))
                {
                    c.sync.void.insert(j.folder);
                }
            }
        }
        for c in self.conns.values_mut() {
            c.sync.undo_redraws(changed);
        }
        for folder in changed {
            self.reset_book(cx, folder);
            self.pause(cx, work, *folder, cause);
        }
        // Re-reading the markers counts a blob changed at rest as stored
        // again, since its marker stays until its deletion commits: it is
        // not, so it lacks and is fetched again (C-H).
        let pending: Vec<(FolderId, CipherHash)> = self.forget.iter().copied().collect();
        for (folder, hash) in pending {
            if let Some(f) = self.folders.get_mut(&folder) {
                f.book.forget(&hash);
            }
        }
        let skipped: Vec<FolderId> = work.skipped.difference(changed).copied().collect();
        for folder in skipped {
            if self.folders.get(&folder).is_some_and(|f| !f.held_paused()) {
                self.lost_rounds(&folder);
                work.sync.owe.insert((folder, None));
            }
        }
        work.failed = Some(e);
    }

    /// The chunks `folder` stores, read again after a rollback.
    fn reset_book(&mut self, cx: &mut dyn Context, folder: &FolderId) {
        let stored = crate::store::load_stored_chunks(cx.storage(), folder).unwrap_or_default();
        if let Some(f) = self.folders.get_mut(folder) {
            f.book.reset_stored(stored);
            // The transaction that applied paths to the disk was dropped,
            // but the paths it took off `unapplied` were not put back: every
            // path is applied again, as at the open, so no base stays old.
            f.unapplied = f.index.paths().map(str::to_owned).collect();
            f.recheck_disk = true;
        }
    }

    /// Every connection where `folder` is open: no longer caught up.
    pub(crate) fn lost_rounds(&mut self, folder: &FolderId) {
        for c in self.conns.values_mut() {
            c.sync.lost_round(folder);
        }
    }
}
