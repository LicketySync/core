// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Index sync: the index exchange of `protocol.md` 4.5 driven over each
//! protocol [`Connection`](licketysync_protocol::connection::Connection), and
//! every change to a folder's [`Index`](licketysync_index::Index) made through
//! the one transaction of each handler (4.7).
//!
//! # Where each step runs
//!
//! Every handler runs in the three phases of the `work` module, and index
//! sync follows them:
//!
//! - **A, decide** (`exchange`). The index exchange's events are reacted to:
//!   a page of records is queued for phase B (or, for a folder that judges
//!   nothing, answered with `Judgement::Skipped` for each record); a request
//!   to serve becomes a reply under way on the connection, built from the
//!   committed index as it is sent; a request due, a subtree to push and the
//!   end of a round are noted for phase C or the next commit.
//! - **B, commit** (`commit`). One [`Txn`](licketysync_index::Txn) per folder
//!   that has work: local writes, the records of each queued page (steps 2 to
//!   9 of 4.4, with the connection's own memories and verification budget,
//!   `Connection::memories_mut`), the ends of rounds with their cleanups, the
//!   cursors, an epoch drawn for a reset, the chunk frees due, and the bases
//!   of every path whose content is now on the (simulated) disk (`disk`).
//!   Each transaction's change set is staged with the handler's chunk blobs,
//!   then one storage commit; the transactions are then committed, or, if the
//!   commit failed, dropped, which undoes them exactly with nothing rebuilt.
//! - **C, send** (`exchange`, `serve`). The judgements go back to each
//!   connection (`Connection::judged`, for every page, so a page whose
//!   records were not judged reports them skipped), the records newly held
//!   are pushed (ruling PUSH-2: to every connection where the folder is open
//!   but the one each came on), the requests due are sent from the committed
//!   index, replies are served page by page under the send budget, and the
//!   subtrees a `RECORDS` reply ends with are pushed.
//!
//! What phase C itself brings that changes the index (a round that ended, a
//! cursor a counted push raised) waits for the next commit, made by a
//! handler of its own at once (`Purpose::Deferred`), so a handler still
//! commits at most once.
//!
//! # The rules kept (4.7 items 2 to 4)
//!
//! - **Skipped records.** A record that this side received and could not
//!   judge (its folder paused for a store failure, kept closed by the clock
//!   rule, or its handler's commit failed) is reported
//!   `Judgement::Skipped`: the connection then moves no cursor past it, its
//!   round is never caught up and owes another, and pushes stop being
//!   counted (4.5, "Cursors").
//! - **Void replies.** Once one page of a reply is skipped, its later pages
//!   are reported skipped too, unjudged and counted, up to its last
//!   (`Counters::void_reply_pages`): the round is not caught up anyway, and
//!   the round it owes brings them all back in order.
//! - **Rounds.** No round of a folder held paused starts
//!   (`Connection::set_paused` on every connection where it is open), and
//!   resuming owes a round on each. A connection is caught up with a folder
//!   only when its last round ended caught up, at `EQUAL` or after a quiet
//!   pass ([`ConnSync::caught_up`]; `Event::RoundCompleted`); a pause ends
//!   that until a round ends caught up again. A handler whose commit failed
//!   pauses every folder it changed and owes a round to every other folder
//!   whose records it skipped.
//! - **Durability before transmission.** Nothing that carries a record goes
//!   out before the commit that holds it: pages are built lazily from the
//!   committed index, pushes after the commit, a reset that draws an epoch
//!   only once that epoch is committed.

mod commit;
pub(crate) mod disk;
mod exchange;
mod serve;

use std::collections::{BTreeMap, BTreeSet};

use licketysync_index::{Change, RecordsReply, SinceReply};
use licketysync_keys::chunk::SealedChunk;
use licketysync_keys::{DeviceId, FolderId, RecordHash};
use licketysync_protocol::connection::{Judgement, Page, ReconcileServe};
use licketysync_protocol::exchange::Prefix;
use licketysync_protocol::record::Record;
use licketysync_protocol::Cause;

use crate::runtime::PeerId;

/// One piece of index work for phase B, in the order queued.
#[derive(Debug)]
pub(crate) enum Op {
    /// A local write (`crate::write`): its changes, and the blobs of its new
    /// chunks, staged once its records are signed.
    Write {
        changes: Vec<Change>,
        blobs: Vec<SealedChunk>,
        /// The path whose version the write returns, or `None` for the first
        /// record of the batch (a tree delete's).
        target: Option<String>,
    },
    /// A page of records from a peer, judged record by record.
    Records {
        peer: PeerId,
        page: Page,
        records: Vec<Record>,
    },
    /// A round of this side's with `device` ended on `peer`'s connection.
    RoundEnded {
        peer: PeerId,
        device: DeviceId,
        caught_up: bool,
        cursor: Option<(u64, u64)>,
    },
    /// A counted push raised `device`'s cursor.
    CursorAdvanced {
        device: DeviceId,
        epoch: u64,
        through: u64,
    },
    /// A reset that draws a new epoch is to be served (4.5).
    Redraw,
}

/// The judgements of one `IndexRecords` page, for `Connection::judged`.
#[derive(Debug)]
pub(crate) struct Judged {
    pub(crate) peer: PeerId,
    pub(crate) folder: FolderId,
    pub(crate) page: Page,
    pub(crate) results: Vec<Result<Judgement, Cause>>,
}

impl Judged {
    /// Every record of a page reported skipped.
    pub(crate) fn skipped(peer: PeerId, folder: FolderId, page: Page, n: usize) -> Self {
        Self {
            peer,
            folder,
            page,
            results: vec![Ok(Judgement::Skipped); n],
        }
    }
}

/// A record to push: to every connection where its folder is open, except
/// the one it arrived on (`protocol.md` 4.5, "Pushes", ruling PUSH-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ToPush {
    pub(crate) hash: RecordHash,
    pub(crate) except: Option<PeerId>,
}

/// One handler's index-sync work for phases B and C.
#[derive(Debug, Default)]
pub(crate) struct SyncWork {
    /// Phase B's work, per folder.
    pub(crate) ops: BTreeMap<FolderId, Vec<Op>>,
    /// The judgements of each page, for phase C.
    pub(crate) judged: Vec<Judged>,
    /// The records to push, per folder.
    pub(crate) pushes: BTreeMap<FolderId, Vec<ToPush>>,
    /// Requests due, sent in C from the committed index.
    pub(crate) requests: BTreeSet<(PeerId, FolderId)>,
    /// Rounds owed: on one connection, or on every connection where the
    /// folder is open (`None`).
    pub(crate) owe: BTreeSet<(FolderId, Option<PeerId>)>,
    /// The subtrees to push after a `RECORDS` reply ended.
    pub(crate) subtrees: Vec<(PeerId, FolderId, Prefix, Option<Vec<RecordHash>>)>,
    /// What the handler's local write made.
    pub(crate) written: Option<Result<RecordHash, crate::write::WriteFailure>>,
    /// Chunks phase B newly stored, per folder: one `chunk_stored` each.
    pub(crate) new_chunks: BTreeMap<FolderId, u64>,
    /// The resume probe staged `e/probe`: this commit's success resumes the
    /// folders paused for a store failure (`crate::pause`).
    pub(crate) probing: bool,
    /// The folders phase B meant to change: those whose transaction had
    /// work queued, staged something, or failed. On a failed commit they are
    /// paused (with those that staged a blob in phase A).
    pub(crate) changed: BTreeSet<FolderId>,
}

impl SyncWork {
    /// Queues `op` for `folder`; a write goes first, so that a write the
    /// index refuses is dropped with nothing else of the folder staged yet.
    pub(crate) fn queue(&mut self, folder: FolderId, op: Op) {
        let ops = self.ops.entry(folder).or_default();
        if matches!(op, Op::Write { .. }) {
            ops.insert(0, op);
        } else {
            ops.push(op);
        }
    }

    /// Queues `hash` for pushing.
    pub(crate) fn push(&mut self, folder: FolderId, hash: RecordHash, except: Option<PeerId>) {
        self.pushes
            .entry(folder)
            .or_default()
            .push(ToPush { hash, except });
    }
}

/// A reply this side is serving, built from the committed index as it is
/// sent (4.7 item 3: only the starting point and the last sent are kept).
#[derive(Debug)]
pub(crate) enum Serving {
    /// The pages of an `IndexRequest`'s reply.
    Since {
        request_id: u32,
        page_limit: usize,
        reply: SinceReply,
    },
    /// One `reset` page; `redrew` when a new epoch was drawn for it.
    Reset { request_id: u32, redrew: bool },
    /// A `ReconcileRequest`, answered from the digest cache.
    Reconcile(ReconcileServe),
    /// The pages of a `RECORDS` reply.
    Records {
        request_id: u32,
        reply: RecordsReply,
    },
}

/// A reply under way, and a page of it built but not yet sent (over the
/// budget, or the queue full): that page goes before any other is built.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) serving: Serving,
    pub(crate) built: Option<licketysync_protocol::messages::IndexRecords>,
}

/// One connection's index-sync state. Bounded: one entry of each table per
/// folder open on the connection (the peer has at most one request per
/// folder outstanding, and so has this side, `protocol.md` 4.5), and dropped
/// with the connection (TM-22).
#[derive(Debug, Default)]
pub(crate) struct ConnSync {
    replies: BTreeMap<FolderId, Reply>,
    /// Per folder, whether the last round of this side's ended caught up.
    caught_up: BTreeMap<FolderId, bool>,
    /// Folders whose reply under way here lost a page: its later pages are
    /// reported skipped, unjudged, up to its last (module documentation).
    void: BTreeSet<FolderId>,
    /// Reply pages carrying records received on this connection.
    pub(crate) reply_pages: u64,
}

impl ConnSync {
    /// Whether this side's last round with the peer on `folder` ended caught
    /// up.
    pub(crate) fn caught_up(&self, folder: &FolderId) -> bool {
        self.caught_up.get(folder).copied().unwrap_or(false)
    }

    /// `folder` paused: no longer caught up until a round ends caught up.
    pub(crate) fn lost_round(&mut self, folder: &FolderId) {
        self.caught_up.remove(folder);
    }

    /// The first folder with a reply being served.
    pub(crate) fn serving(&self) -> Option<FolderId> {
        self.replies.keys().next().copied()
    }

    /// A failed commit undid the epoch drawn for a reset of one of
    /// `folders`: the reset goes without it.
    pub(crate) fn undo_redraws(&mut self, folders: &BTreeSet<FolderId>) {
        for (folder, reply) in &mut self.replies {
            if let Serving::Reset { redrew, .. } = &mut reply.serving {
                if folders.contains(folder) {
                    *redrew = false;
                }
            }
        }
    }

    /// Drops every table: the connection closed.
    pub(crate) fn clear(&mut self) {
        self.replies.clear();
        self.caught_up.clear();
        self.void.clear();
    }
}
