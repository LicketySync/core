// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index exchange on one connection (`protocol.md` 4.5): this side's
//! rounds (Since, then the Check and up to `MAX_RECONCILE_PASSES` passes of
//! reconciliation over the set-digest trie), one request at a time per
//! folder across both request kinds, the reply deadline, the serving of the
//! peer's requests with `INDEX_REQUEST_MIN_INTERVAL` for its `IndexRequest`s
//! and root `ReconcileRequest`s, pushes and the empty push owed, the counting
//! of the peer's pushes into its cursor, and the round owed.
//!
//! Every table here is per open folder and bounded (TM-22, section 5 "Limits
//! are per connection"): one outstanding request each way, the work list of
//! at most `MAX_WORK_LIST` prefixes, the record hashes of the current
//! `RECORDS` reply (at most `RECONCILE_LEAF_MAX`), one pending set of 16 child
//! digests, the records from the future refused on this connection (at most
//! `MAX_FUTURE_KNOWN`), the pushes awaiting their judgements (at most
//! `MAX_PENDING_PUSHES`), and a few flags and times; and, for the whole
//! connection, one count of note verifications (at most
//! `MAX_NOTE_VERIFICATIONS` a window, [`NoteBudget`]). All of it is freed
//! when the connection closes.
//!
//! The connection keeps no records: it reads the index through
//! [`IndexView`] (its digests and a peer's stored cursor) when it builds a
//! request, and hands every record it receives to the engine, which has the
//! index judge it and returns the judgements through
//! [`Connection::judged`]. A reply's next step waits for the judgements of its
//! pages, so that whether a pass brought a record, or skipped one, is known
//! before the pass ends.

use std::collections::{BTreeSet, VecDeque};

use core::time::Duration;

use licketysync_keys::{DeviceId, FolderId, FolderVerifier, RecordHash, SetDigest};

use super::{open_mut, Connection, Event, Output, SendError, State, Tag, Tick};
use crate::exchange::{page_limit, IndexView, Prefix};
use crate::limits::{
    MAX_FUTURE_KNOWN, MAX_LOCAL_SEQ, MAX_NOTE_VERIFICATIONS, MAX_PAGE_RECORDS, MAX_PASS_REQUESTS,
    MAX_PENDING_PUSHES, MAX_RECONCILE_PASSES, MAX_WORK_LIST, RECONCILE_LEAF_MAX,
};
use crate::messages::{
    IndexRecords, IndexRequest, Message, ReconcileOutcome, ReconcileReply, ReconcileRequest,
};
use crate::parse::RecordsPage;
use crate::record::Record;
use crate::rules::Cause;

/// What the index made of one record of an [`Event::Records`] page: the
/// judgement [`Connection::judged`] takes for it (`protocol.md` 4.7 item 2).
/// A refusal that closes (a forged record) is passed as the [`Cause`]
/// instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Judgement {
    /// Already held: ignored, not verified.
    Duplicate,
    /// Past the folder's own time by its horizon: ignored, not verified.
    Expired,
    /// Something held replaces it and it replaces nothing held: ignored.
    Obsolete,
    /// More than `CLOCK_RULE_LIMIT` ahead of this device's clock: verified,
    /// neither held nor relayed (or ignored again unverified on this
    /// connection).
    FromTheFuture,
    /// Verified and held, applied.
    Held,
    /// Verified and held opaque: a writer fault.
    HeldOpaque,
    /// Verified, and dropped at once because a held tree delete covers it (4.4
    /// step 8): neither held nor numbered.
    DroppedBeneath,
    /// Not judged: the folder's store refused the change, or the folder was
    /// paused meanwhile. No cursor moves past it and no pass that skipped one
    /// is quiet (4.5).
    Skipped,
}

impl Judgement {
    /// Whether the record is now held: it "brought this side a record it then
    /// held" (4.5).
    #[must_use]
    pub const fn held(self) -> bool {
        matches!(self, Self::Held | Self::HeldOpaque)
    }

    /// The section 5 row, for the outcomes that have one.
    #[must_use]
    pub const fn cause(self) -> Option<Cause> {
        match self {
            Self::Duplicate => Some(Cause::Duplicate),
            Self::Expired => Some(Cause::Expired),
            Self::Obsolete | Self::DroppedBeneath => Some(Cause::Obsolete),
            Self::FromTheFuture => Some(Cause::FromTheFuture),
            Self::HeldOpaque => Some(Cause::WriterFault),
            Self::Held | Self::Skipped => None,
        }
    }
}

/// Which `IndexRecords` arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// A push (`request_id = 0`), numbered in the order it arrived for its
    /// folder on this connection, so that its judgement is matched to its own
    /// entry whatever was dropped meanwhile.
    Push {
        /// The push's number.
        push: u64,
    },
    /// A page of the reply to this side's request `request_id`; `last` when
    /// `more` was false.
    Reply {
        /// The request it answers.
        request_id: u32,
        /// The reply's last page.
        last: bool,
    },
}

/// The peer's `IndexRequest`, for the engine to serve (4.5, "Serving an
/// `IndexRequest`").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexServe {
    /// Every page of the reply echoes it.
    pub request_id: u32,
    /// The epoch the requester's cursor belongs to.
    pub epoch: u64,
    /// The requester's cursor.
    pub since: u64,
    /// Records per page, from `max_records` ([`page_limit`]).
    pub page_limit: usize,
    /// Whether a `since` above this side's local sequence may draw a new
    /// epoch: at most once per connection (4.5).
    pub redraw_allowed: bool,
}

/// The peer's `ReconcileRequest`, for the engine to serve (4.5, "Serving a
/// `ReconcileRequest`").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileServe {
    /// The reply echoes it.
    pub request_id: u32,
    /// The subtree.
    pub prefix: Prefix,
    /// The requester's digest of it.
    pub digest: SetDigest,
}

/// The memory one connection keeps for one open folder that the index reads
/// and updates when it judges a record from this peer (`protocol.md` 4.4
/// step 4; it lives with the connection and is freed when it closes): the
/// record hashes of records from the future
/// refused on this connection, at most `MAX_FUTURE_KNOWN`, the oldest
/// forgotten first.
#[derive(Clone, Debug, Default)]
pub struct FolderMemory {
    future: VecDeque<RecordHash>,
    future_set: BTreeSet<RecordHash>,
}

/// The one budget of verifications for notes of stale copies that a
/// connection spends across every folder open on it (`protocol.md` 4.5
/// "Stale copies"): at most `MAX_NOTE_VERIFICATIONS` in each window of
/// `INDEX_RESYNC_INTERVAL` of monotonic time. A window starts at the first
/// reading after the last one ended and is fixed, so a burst across a
/// window's boundary can spend two windows' budget, as the spec states.
/// Only a [`Connection`] makes one ([`Connection::memories_mut`]), so that
/// the bound is the connection's, whatever the number of folders; outside
/// this crate, tests make one with [`NoteBudget::for_tests`]. It is
/// neither `Clone` nor `Copy`, so that a copy cannot spend a budget of its
/// own beside the connection's:
///
/// ```compile_fail
/// let budget = licketysync_protocol::connection::NoteBudget::for_tests();
/// let first = budget;
/// let second = budget; // moved: not `Copy`
/// ```
///
/// ```compile_fail
/// let budget = licketysync_protocol::connection::NoteBudget::for_tests();
/// let copy = budget.clone(); // not `Clone`
/// ```
#[derive(Debug)]
pub struct NoteBudget {
    used: usize,
    window_end: Option<Duration>,
}

impl NoteBudget {
    /// A fresh budget, for tests of the index outside a connection; an
    /// engine takes the connection's, never this.
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests() -> Self {
        Self::new()
    }

    /// A fresh budget, its first window not begun.
    pub(crate) const fn new() -> Self {
        Self {
            used: 0,
            window_end: None,
        }
    }

    /// Whether one more record may be verified for a note in this window.
    #[must_use]
    pub const fn may_verify(&self) -> bool {
        self.used < MAX_NOTE_VERIFICATIONS
    }

    /// Counts one verification for a note.
    pub fn verified(&mut self) {
        self.used = self.used.saturating_add(1);
    }

    /// Starts a new window at `now` once the current one has ended.
    fn refill(&mut self, now: Duration, window: Duration) {
        if self.window_end.is_none_or(|end| now >= end) {
            self.used = 0;
            self.window_end = Some(now.saturating_add(window));
        }
    }
}

impl FolderMemory {
    /// Whether a record from the future with this hash was refused on this
    /// connection already: it is ignored again without verifying.
    #[must_use]
    pub fn knows_future(&self, hash: &RecordHash) -> bool {
        self.future_set.contains(hash)
    }

    /// Remembers a record from the future refused on this connection.
    pub fn remember_future(&mut self, hash: RecordHash) {
        if !self.future_set.insert(hash) {
            return;
        }
        self.future.push_back(hash);
        if self.future.len() > MAX_FUTURE_KNOWN {
            if let Some(old) = self.future.pop_front() {
                self.future_set.remove(&old);
            }
        }
    }

    /// The records from the future remembered, oldest first (the tests').
    #[cfg(test)]
    pub(crate) fn future(&self) -> impl Iterator<Item = &RecordHash> + '_ {
        self.future.iter()
    }
}

/// One request of this side's, outstanding.
#[derive(Clone, Debug)]
struct Outstanding {
    request_id: u32,
    kind: Asked,
    handed_end: Option<u64>,
    departed_at: Option<Duration>,
}

/// What was asked, and how far its reply has come.
#[derive(Clone, Debug)]
enum Asked {
    /// The Since request.
    Since,
    /// A `ReconcileRequest` for `prefix`, with whether its digest was zero.
    Reconcile {
        prefix: Prefix,
        digest_zero: bool,
        reply: ReconcileProgress,
    },
}

#[derive(Clone, Debug)]
enum ReconcileProgress {
    /// No `ReconcileReply` yet.
    Awaiting,
    /// `RECORDS` came: its pages so far, and the record hashes they carried
    /// (at most `RECONCILE_LEAF_MAX`; `overflow` once more came).
    Records {
        count: usize,
        carried: Vec<RecordHash>,
        overflow: bool,
    },
}

/// Where a round of this side's is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Not begun: the first request decides between Since and the Check.
    Start,
    /// The Since request.
    Since,
    /// The passes of reconciliation, the Check being pass 1's root request.
    Passes,
}

/// A round of this side's under way (4.5, "Rounds").
#[derive(Clone, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of one round, each a rule of 4.5"
)]
struct Round {
    stage: Stage,
    /// The pass under way, 1 to `MAX_RECONCILE_PASSES`; 0 before the Check.
    pass: usize,
    /// Requests sent in the pass.
    pass_requests: usize,
    /// Prefixes still to visit, the next on top.
    work: Vec<Prefix>,
    /// The next request is the root's (a pass begins).
    root_next: bool,
    /// A `CHILDREN` reply's prefix and digests, to compare with this side's.
    children: Option<(Prefix, Box<[SetDigest; 16]>)>,
    /// A record of a reply of this pass came to be held.
    brought: bool,
    /// The pass was cut at `MAX_PASS_REQUESTS`.
    cut: bool,
    /// A record of the round was skipped.
    skipped: bool,
    /// An empty push arrived since the round began.
    empty_push: bool,
    /// The cursor the round sets: the epoch and `through` of the Since
    /// reply's last page, or of the first root reply.
    cursor: Option<(u64, u64)>,
    /// The root reply has come once in the round.
    root_answered: bool,
}

impl Round {
    const fn new() -> Self {
        Self {
            stage: Stage::Start,
            pass: 0,
            pass_requests: 0,
            work: Vec::new(),
            root_next: true,
            children: None,
            brought: false,
            cut: false,
            skipped: false,
            empty_push: false,
            cursor: None,
            root_answered: false,
        }
    }
}

/// The peer's request this side is serving, or holds until it may.
#[derive(Clone, Debug)]
struct Serving {
    request_id: u32,
    kind: Served,
    serve_at: Duration,
    /// The event to hand the engine at `serve_at`; `None` once handed.
    held: Option<Event>,
    /// The first part of the reply went: serving began.
    began: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Served {
    /// An `IndexRequest`, served in pages of at most this many records.
    Index { page_limit: usize },
    /// A `ReconcileRequest` for this prefix, before its reply went.
    Reconcile { root: bool },
    /// A `RECORDS` reply's pages.
    Records,
}

/// One open folder's exchange state on this connection.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent flags of 4.5, each one bit per folder per connection"
)]
pub(super) struct Exchange {
    pub(super) verifier: FolderVerifier,
    pub(super) memory: FolderMemory,
    outstanding: Option<Outstanding>,
    round: Option<Round>,
    /// A [`Event::RequestDue`] went: the engine is to call
    /// [`Connection::send_request`].
    due: bool,
    /// Reply pages of this side's outstanding request whose judgements have
    /// not come back.
    awaiting: usize,
    /// The last page of the outstanding reply has arrived.
    reply_ended: bool,
    round_owed: bool,
    last_owed_start: Option<Duration>,
    /// The folder is paused (a store failure): no round starts, pushes are
    /// not counted.
    paused: bool,
    /// Counting the peer's pushes into its cursor, under this epoch.
    counting: Option<u64>,
    /// For each push whose judgements have not come back, in order: its
    /// number and the `through` it would raise the cursor to, if counted; at
    /// most `MAX_PENDING_PUSHES`.
    pending_pushes: VecDeque<(u64, Option<u64>)>,
    /// The number the next push takes.
    next_push: u64,
    /// A new epoch was drawn for a peer's request on this connection.
    epoch_redrawn: bool,
    serving: Option<Serving>,
    /// When this side began serving the peer's previous `IndexRequest` or
    /// root `ReconcileRequest` (`INDEX_REQUEST_MIN_INTERVAL` counts from it).
    last_serve_began: Option<Duration>,
    empty_push_queued: bool,
    /// `MAX_PASS_REQUESTS`; tests of the cut lower it.
    pass_cap: usize,
    pub(super) chunks: super::chunks::FolderChunks,
}

impl Exchange {
    pub(super) fn new(verifier: FolderVerifier) -> Self {
        Self {
            verifier,
            memory: FolderMemory::default(),
            outstanding: None,
            round: None,
            due: false,
            awaiting: 0,
            reply_ended: false,
            round_owed: false,
            last_owed_start: None,
            paused: false,
            counting: None,
            pending_pushes: VecDeque::new(),
            next_push: 0,
            epoch_redrawn: false,
            serving: None,
            last_serve_began: None,
            empty_push_queued: false,
            pass_cap: MAX_PASS_REQUESTS,
            chunks: super::chunks::FolderChunks::new(),
        }
    }

    /// When an owed round may start, or a held request of the peer's may be
    /// served.
    fn wake(&self, resync: Duration) -> Option<Duration> {
        let serve = self
            .serving
            .as_ref()
            .filter(|s| s.held.is_some())
            .map(|s| s.serve_at);
        let owed = (self.round_owed && self.round.is_none() && !self.paused)
            .then_some(self.last_owed_start)
            .flatten()
            .map(|l| l.saturating_add(resync));
        [serve, owed].into_iter().flatten().min()
    }

    fn stop_counting(&mut self) {
        self.counting = None;
        for (_, p) in &mut self.pending_pushes {
            *p = None;
        }
    }
}

/// The children of `prefix` whose digest in the responder's list (`theirs`)
/// differs from this side's own, in ascending order.
fn differing(prefix: &Prefix, theirs: &[SetDigest; 16], view: &dyn IndexView) -> Vec<Prefix> {
    (0..16u8)
        .filter_map(|i| prefix.child(i))
        .zip(theirs.iter())
        .filter(|(child, d)| view.digest(child) != **d)
        .map(|(child, _)| child)
        .collect()
}

impl Connection {
    /// The deadline of the reply to this side's outstanding requests: nothing
    /// for `REPLY_PAGE_TIMEOUT` since the request left the send queue or since
    /// the last restart (any part of a reply to this side's requests, a
    /// `CHUNK_OK`, a push that brought a record held).
    pub(super) fn reply_deadline(&self) -> Option<Duration> {
        self.folders
            .values()
            .filter_map(|f| f.open.as_ref()?.outstanding.as_ref()?.departed_at)
            .map(|d| {
                d.max(self.last_progress)
                    .saturating_add(self.config.timing.reply_page)
            })
            .min()
    }

    /// Whether a request of this side was handed over and is not yet known
    /// to have left the transport's queue.
    pub(super) fn awaiting_departure(&self) -> bool {
        self.folders.values().any(|f| {
            f.open
                .as_ref()
                .and_then(|x| x.outstanding.as_ref())
                .is_some_and(|o| o.handed_end.is_some() && o.departed_at.is_none())
        })
    }

    pub(super) fn note_departures(&mut self) {
        let (delivered, now) = (self.delivered, self.now);
        for f in self.folders.values_mut() {
            if let Some(o) = f.open.as_mut().and_then(|x| x.outstanding.as_mut()) {
                if o.departed_at.is_none()
                    && o.handed_end.is_some_and(|e| i128::from(e) <= delivered)
                {
                    o.departed_at = Some(now);
                }
            }
        }
    }

    pub(super) fn request_handed(&mut self, folder: FolderId) {
        let handed = self.handed;
        if let Some(o) = open_mut(&mut self.folders, &folder).and_then(|x| x.outstanding.as_mut()) {
            o.handed_end = Some(handed);
        }
    }

    pub(super) fn empty_push_handed(&mut self, folder: FolderId) {
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.empty_push_queued = false;
        }
    }

    pub(super) fn exchange_wake(&self) -> Option<Duration> {
        let resync = self.config.timing.index_resync;
        self.folders
            .values()
            .filter_map(|f| f.open.as_ref()?.wake(resync))
            .min()
    }

    pub(super) fn wake_exchange(&mut self, out: &mut Output) {
        let folders: Vec<FolderId> = self.open_folders().copied().collect();
        for folder in folders {
            self.announce_serve(folder, out);
            self.start_owed_round(folder, out);
        }
    }

    /// Hands a held request of the peer's to the engine once its
    /// `INDEX_REQUEST_MIN_INTERVAL` has passed.
    fn announce_serve(&mut self, folder: FolderId, out: &mut Output) {
        let now = self.now;
        let Some(serving) = open_mut(&mut self.folders, &folder).and_then(|x| x.serving.as_mut())
        else {
            return;
        };
        if now < serving.serve_at {
            return;
        }
        if let Some(event) = serving.held.take() {
            out.events.push(event);
        }
    }

    /// The round a side sends when a folder opens on the connection.
    pub(super) fn round_on_open(&mut self, folder: FolderId, out: &mut Output) {
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            // A folder opens unpaused (`Exchange::new`): its round starts.
            x.round = Some(Round::new());
            x.due = true;
            out.events.push(Event::RequestDue { folder });
        }
    }

    /// Starts an owed round once nothing of this side's is outstanding, no
    /// round of its own is under way, the folder is not paused, and
    /// `INDEX_RESYNC_INTERVAL` has passed since the previous owed round began
    /// (4.5, "Round owed").
    fn start_owed_round(&mut self, folder: FolderId, out: &mut Output) {
        let (now, resync) = (self.now, self.config.timing.index_resync);
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let allowed = x
            .last_owed_start
            .is_none_or(|l| now >= l.saturating_add(resync));
        if !x.round_owed || x.paused || x.round.is_some() || x.outstanding.is_some() || !allowed {
            return;
        }
        x.round_owed = false;
        x.last_owed_start = Some(now);
        x.round = Some(Round::new());
        x.due = true;
        out.events.push(Event::RequestDue { folder });
    }

    /// Whether a request of this side's is due for `folder` (the tests'; the
    /// engine learns it from [`Event::RequestDue`]).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_due(&self, folder: &FolderId) -> bool {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .is_some_and(|x| x.due)
    }

    /// Encodes `message` and checks it fits the peer's limit.
    pub(super) fn frame_for(&self, message: &Message) -> Result<Vec<u8>, SendError> {
        let frame = message.to_frame().map_err(|_| SendError::TooLarge)?;
        if !frame.fits(self.peer_max_message_size()) {
            return Err(SendError::TooLarge);
        }
        Ok(frame.encode())
    }

    /// Refuses a send before the handshake has finished or after a close.
    pub(super) const fn established(&self) -> Result<(), SendError> {
        match self.state {
            State::Established => Ok(()),
            State::Closed => Err(SendError::Closed),
            State::AwaitingHello | State::AwaitingDeviceProof => Err(SendError::NotEstablished),
        }
    }

    /// The open folder an `IndexRecords` this side sends names.
    fn page_folder(&self, page: &IndexRecords) -> Result<FolderId, SendError> {
        let folder = FolderId::from_slice(&page.folder_id).ok_or(SendError::Malformed)?;
        if self.is_open(&folder) {
            Ok(folder)
        } else {
            Err(SendError::FolderNotOpen)
        }
    }

    fn fresh_request_id(&self) -> u32 {
        let mut id = self.next_request_id;
        loop {
            id = id.wrapping_add(1).max(1);
            if !self.ours_by_id.contains_key(&id) {
                return id;
            }
        }
    }

    /// The next step of this side's round for `folder` after
    /// [`Event::RequestDue`], read from the index through `view`: the Since
    /// request (an `IndexRequest` with the peer's stored epoch and cursor,
    /// when the index holds state for the peer), the Check or a pass's root
    /// request, or the next prefix of the pass's work list, after comparing a
    /// `CHILDREN` reply's digests with this side's and putting every child
    /// that differs on the list (depth first, ascending). When the work list
    /// runs out the pass ends, and so may the round, in which case nothing is
    /// sent and the output carries [`Event::RoundCompleted`]. Every request
    /// gets a fresh `request_id`, unique across both kinds.
    ///
    /// # Errors
    /// [`SendError::NotDue`], [`SendError::FolderNotOpen`],
    /// [`SendError::TooLarge`], or the connection's state.
    pub fn send_request(
        &mut self,
        tick: Tick,
        folder: FolderId,
        view: &dyn IndexView,
    ) -> Result<Output, SendError> {
        self.established()?;
        let peer = self.peer.as_ref().map(|p| p.device_id);
        let x = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref())
            .ok_or(SendError::FolderNotOpen)?;
        if !x.due || x.outstanding.is_some() {
            return Err(SendError::NotDue);
        }
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let request_id = self.fresh_request_id();
        let max_records = self.config.max_records;
        let mut message = None;
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.due = false;
            if let Some(round) = x.round.as_mut() {
                if round.stage == Stage::Start {
                    if let Some((epoch, since)) = peer.and_then(|p| view.peer_cursor(&p)) {
                        round.stage = Stage::Since;
                        x.outstanding = Some(Outstanding {
                            request_id,
                            kind: Asked::Since,
                            handed_end: None,
                            departed_at: None,
                        });
                        message = Some(Message::IndexRequest(IndexRequest {
                            folder_id: folder.0.to_vec(),
                            max_records,
                            request_id,
                            epoch: epoch.max(1),
                            since: since.min(MAX_LOCAL_SEQ),
                        }));
                    } else {
                        round.stage = Stage::Passes;
                    }
                }
                if message.is_none() {
                    if let Some((prefix, theirs)) = round.children.take() {
                        let next = differing(&prefix, &theirs, view);
                        // Depth first, ascending: the smallest on top. The
                        // list cannot pass its bound (15 siblings a level);
                        // were it to, the pass is cut rather than quiet.
                        for child in next.into_iter().rev() {
                            if round.work.len() < MAX_WORK_LIST {
                                round.work.push(child);
                            } else {
                                round.cut = true;
                            }
                        }
                    }
                }
            }
        }
        if message.is_none() {
            message = self.next_reconcile(folder, request_id, view, &mut out);
        }
        let Some(message) = message else {
            self.finish(&mut out);
            return Ok(out);
        };
        let frame = match self.frame_for(&message) {
            Ok(frame) => frame,
            Err(e) => {
                if let Some(x) = open_mut(&mut self.folders, &folder) {
                    x.outstanding = None;
                    x.due = true;
                }
                return Err(e);
            }
        };
        self.next_request_id = request_id;
        self.ours_by_id.insert(request_id, folder);
        self.enqueue(frame, Tag::Request(folder), &mut out);
        self.finish(&mut out);
        Ok(out)
    }

    /// The next `ReconcileRequest` of the pass, or, when the pass has ended,
    /// the next pass's root request or the end of the round.
    fn next_reconcile(
        &mut self,
        folder: FolderId,
        request_id: u32,
        view: &dyn IndexView,
        out: &mut Output,
    ) -> Option<Message> {
        loop {
            let x = open_mut(&mut self.folders, &folder)?;
            let cap = x.pass_cap;
            let round = x.round.as_mut()?;
            let prefix = if round.root_next {
                round.root_next = false;
                round.pass += 1;
                round.pass_requests = 0;
                round.brought = false;
                round.cut = false;
                round.work.clear();
                Prefix::ROOT
            } else if round.pass_requests >= cap && !round.work.is_empty() {
                round.cut = true;
                round.work.clear();
                if self.pass_ended(folder, out) {
                    return None;
                }
                continue;
            } else if let Some(p) = round.work.pop() {
                p
            } else {
                if self.pass_ended(folder, out) {
                    return None;
                }
                continue;
            };
            round.pass_requests += 1;
            let digest = view.digest(&prefix);
            x.outstanding = Some(Outstanding {
                request_id,
                kind: Asked::Reconcile {
                    prefix,
                    digest_zero: digest.is_empty(),
                    reply: ReconcileProgress::Awaiting,
                },
                handed_end: None,
                departed_at: None,
            });
            return Some(Message::ReconcileRequest(ReconcileRequest {
                folder_id: folder.0.to_vec(),
                request_id,
                prefix: prefix.to_wire(),
                digest: digest.0.to_vec(),
            }));
        }
    }

    /// The pass ended (its work list ran out, or it was cut): the round ends
    /// caught up after a quiet pass, ends not caught up after its last pass,
    /// and otherwise goes on with the next pass's root request. `true` when
    /// the round ended.
    fn pass_ended(&mut self, folder: FolderId, out: &mut Output) -> bool {
        let Some(round) = open_mut(&mut self.folders, &folder).and_then(|x| x.round.as_mut())
        else {
            return true;
        };
        let quiet = !round.cut && !round.skipped && !round.brought;
        let last = round.pass >= MAX_RECONCILE_PASSES;
        if !quiet && !last {
            round.root_next = true;
            return false;
        }
        self.round_ended(folder, quiet, out);
        true
    }

    /// A round of this side's ended (4.5): the cursor it sets unless it
    /// skipped a record, the counting of the peer's pushes from now unless an
    /// empty push came during the round, a round owed unless it was caught
    /// up, and [`Event::RoundCompleted`].
    fn round_ended(&mut self, folder: FolderId, caught_up: bool, out: &mut Output) {
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let Some(round) = x.round.take() else {
            return;
        };
        x.due = false;
        let caught_up = caught_up && !round.skipped;
        let cursor = if round.skipped { None } else { round.cursor };
        x.counting = match cursor {
            Some((epoch, _)) if !round.empty_push && !x.paused => Some(epoch),
            _ => None,
        };
        if !caught_up {
            x.round_owed = true;
        }
        out.events.push(Event::RoundCompleted {
            folder,
            caught_up,
            cursor,
        });
        self.round_completed_for_chunks(folder, out);
        self.start_owed_round(folder, out);
    }

    /// This side owes itself a round for `folder` (4.5, "Round owed"): the
    /// one flag per folder per connection is set as an empty push sets it, so
    /// the round starts once nothing of this side's is outstanding, no round
    /// of its own is under way, the folder is not paused, and no sooner than
    /// `INDEX_RESYNC_INTERVAL` after the previous owed round began for the
    /// folder on this connection ([`Event::RequestDue`] when it starts). The
    /// engine calls it after a round at whose end it issued a cleanup. A
    /// folder not open here, or a connection not established, is left as it
    /// is.
    pub fn owe_round(&mut self, tick: Tick, folder: FolderId) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if self.state == State::Established {
            if let Some(x) = open_mut(&mut self.folders, &folder) {
                x.round_owed = true;
                self.start_owed_round(folder, &mut out);
            }
        }
        self.finish(&mut out);
        out
    }

    /// The folder's store refuses changes (`paused`), or takes them again
    /// (section 5, "Store failure"; 4.7 item 4). While paused, no round of
    /// this side's starts for the folder on this connection and the peer's
    /// pushes are not counted, so that no cursor passes a record that was
    /// refused; a round under way runs to its end, its refused records
    /// skipped. Resuming owes a round, which brings back what was refused.
    /// The engine calls it on every connection where the folder is open.
    pub fn set_paused(&mut self, tick: Tick, folder: FolderId, paused: bool) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if self.state == State::Established {
            if let Some(x) = open_mut(&mut self.folders, &folder) {
                let was = x.paused;
                x.paused = paused;
                if paused {
                    x.stop_counting();
                } else if was {
                    x.round_owed = true;
                    self.start_owed_round(folder, &mut out);
                }
            }
        }
        self.finish(&mut out);
        out
    }

    /// The connection's memories that the index reads and updates when it
    /// judges this peer's records of `folder`: the folder's
    /// [`FolderMemory`], and the connection's one [`NoteBudget`], whose
    /// window this call moves on at `tick`. `None` when the folder is not
    /// open.
    pub fn memories_mut(
        &mut self,
        tick: Tick,
        folder: &FolderId,
    ) -> Option<(&mut FolderMemory, &mut NoteBudget)> {
        self.notes.refill(tick.now, self.config.timing.index_resync);
        let notes = &mut self.notes;
        open_mut(&mut self.folders, folder).map(|x| (&mut x.memory, notes))
    }

    /// Sends one page of the reply to the peer's request that
    /// [`Event::ServeIndex`] or (after `RECORDS`) [`Event::ServeReconcile`]
    /// handed over, at most the request's page limit and the peer's frame
    /// limit (build it with [`crate::exchange::Pager`]); `more` on every page
    /// but the last, and a page with `more` holds a record. An `IndexRequest`'s
    /// pages carry `through`; a `RECORDS` reply's carry none. The first page
    /// begins the serving, from which `INDEX_REQUEST_MIN_INTERVAL` counts; the
    /// last ends it, and the peer may send its next request.
    ///
    /// # Errors
    /// [`SendError::WouldBlock`] when the send queue has no room for the page:
    /// keep it, call [`Connection::want_room`] and send it on
    /// [`Event::Room`]; [`SendError::UnknownRequest`],
    /// [`SendError::PageTooLong`], [`SendError::Malformed`],
    /// [`SendError::TooLarge`], [`SendError::FolderNotOpen`], or the
    /// connection's state.
    pub fn send_page(&mut self, tick: Tick, page: &IndexRecords) -> Result<Output, SendError> {
        self.established()?;
        let folder = self.page_folder(page)?;
        let serving = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref()?.serving.as_ref())
            .filter(|s| s.request_id == page.request_id && s.held.is_none())
            .ok_or(SendError::UnknownRequest)?;
        let limit = match serving.kind {
            Served::Index { page_limit } => page_limit,
            Served::Records if page.through == 0 => MAX_PAGE_RECORDS,
            Served::Records | Served::Reconcile { .. } => return Err(SendError::Malformed),
        };
        if page.records.len() > limit {
            return Err(SendError::PageTooLong);
        }
        if (page.more && page.records.is_empty())
            || page.reset
            || page.epoch == 0
            || page.through > MAX_LOCAL_SEQ
        {
            return Err(SendError::Malformed);
        }
        self.serve_frame(
            tick,
            folder,
            &Message::IndexRecords(page.clone()),
            !page.more,
        )
    }

    /// Answers the peer's `IndexRequest` with one `reset` page (4.5): its
    /// epoch is not this side's, or its `since` is above this side's local
    /// sequence. `redrew` when a new epoch was drawn for it (allowed once per
    /// connection, [`IndexServe::redraw_allowed`]); `epoch` is this side's
    /// epoch, the new one if it was drawn.
    ///
    /// # Errors
    /// As [`Connection::send_page`].
    pub fn send_reset(
        &mut self,
        tick: Tick,
        folder: FolderId,
        request_id: u32,
        epoch: u64,
        redrew: bool,
    ) -> Result<Output, SendError> {
        self.established()?;
        if !self.is_open(&folder) {
            return Err(SendError::FolderNotOpen);
        }
        let serving = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref()?.serving.as_ref())
            .filter(|s| s.request_id == request_id && s.held.is_none())
            .ok_or(SendError::UnknownRequest)?;
        if !matches!(serving.kind, Served::Index { .. }) || epoch == 0 {
            return Err(SendError::Malformed);
        }
        if redrew
            && self
                .folders
                .get(&folder)
                .and_then(|f| f.open.as_ref())
                .is_some_and(|x| x.epoch_redrawn)
        {
            return Err(SendError::RedrawSpent);
        }
        let page = crate::exchange::reset_page(&folder, request_id, epoch);
        let out = self.serve_frame(tick, folder, &Message::IndexRecords(page), true)?;
        if redrew {
            if let Some(x) = open_mut(&mut self.folders, &folder) {
                x.epoch_redrawn = true;
            }
        }
        Ok(out)
    }

    /// Answers the peer's `ReconcileRequest` that [`Event::ServeReconcile`]
    /// handed over: `EQUAL`, `CHILDREN` with this side's 16 child digests, or
    /// `RECORDS`, after which the subtree's records follow as pages through
    /// [`Connection::send_page`] (one empty page when there are none). The
    /// root's reply carries `through`, this side's local sequence; any other
    /// does not (build the outcome with
    /// [`crate::exchange::reconcile_outcome`]).
    ///
    /// # Errors
    /// [`SendError::Malformed`] for a reply that breaks a rule of 4.5 (16
    /// children exactly on `CHILDREN`, `through` only for the root, a non-zero
    /// epoch), and the errors of [`Connection::send_page`].
    pub fn send_reconcile_reply(
        &mut self,
        tick: Tick,
        reply: &ReconcileReply,
    ) -> Result<Output, SendError> {
        self.established()?;
        let folder = FolderId::from_slice(&reply.folder_id).ok_or(SendError::Malformed)?;
        if !self.is_open(&folder) {
            return Err(SendError::FolderNotOpen);
        }
        let serving = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref()?.serving.as_ref())
            .filter(|s| s.request_id == reply.request_id && s.held.is_none())
            .ok_or(SendError::UnknownRequest)?;
        let Served::Reconcile { root } = serving.kind else {
            return Err(SendError::Malformed);
        };
        let outcome = ReconcileOutcome::from_u32(reply.outcome).ok_or(SendError::Malformed)?;
        let children = if outcome == ReconcileOutcome::Children {
            16
        } else {
            0
        };
        if reply.children.len() != children
            || reply.children.iter().any(|c| c.len() != 32)
            || reply.epoch == 0
            || reply.through > MAX_LOCAL_SEQ
            || (!root && reply.through != 0)
        {
            return Err(SendError::Malformed);
        }
        let records = outcome == ReconcileOutcome::Records;
        let out = self.serve_frame(
            tick,
            folder,
            &Message::ReconcileReply(reply.clone()),
            !records,
        )?;
        if records {
            if let Some(s) = open_mut(&mut self.folders, &folder).and_then(|x| x.serving.as_mut()) {
                s.kind = Served::Records;
            }
        }
        Ok(out)
    }

    /// Sends one part of a reply this side serves; `last` ends the serving.
    fn serve_frame(
        &mut self,
        tick: Tick,
        folder: FolderId,
        message: &Message,
        last: bool,
    ) -> Result<Output, SendError> {
        let frame = self.frame_for(message)?;
        if !self.has_room(tick, frame.len()) {
            return Err(SendError::WouldBlock { len: frame.len() });
        }
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let now = self.now;
        let mut ended = None;
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            if let Some(serving) = x.serving.as_mut() {
                if !serving.began {
                    serving.began = true;
                    if matches!(
                        serving.kind,
                        Served::Index { .. } | Served::Reconcile { root: true }
                    ) {
                        x.last_serve_began = Some(now);
                    }
                }
                if last {
                    ended = Some(serving.request_id);
                }
            }
            if last {
                x.serving = None;
            }
        }
        if let Some(id) = ended {
            self.theirs_by_id.remove(&id);
        }
        self.enqueue(frame, Tag::None, &mut out);
        self.finish(&mut out);
        Ok(out)
    }

    /// Pushes records this side came to hold (4.5, "Pushes"), or records a
    /// reconciliation found the peer lacking: one page with `request_id = 0`,
    /// `more` and `reset` clear, at most `MAX_PAGE_RECORDS`, its `through` the
    /// local sequence of its last record (0 for a reconciliation's push), its
    /// `epoch` this side's. It goes at once or not at all: when the send queue
    /// cannot take it, it is dropped, and the peer is owed one empty push for
    /// the folder, which waits in order and is never dropped (3.1, PUSH-1).
    /// The output's frames say which: the push, the empty push, or nothing
    /// (one already owed).
    ///
    /// # Errors
    /// [`SendError::Malformed`] for a page with `request_id`, `more` or
    /// `reset` set, no record or an epoch of 0, [`SendError::PageTooLong`],
    /// [`SendError::TooLarge`], [`SendError::FolderNotOpen`], or the
    /// connection's state.
    pub fn push(&mut self, tick: Tick, page: &IndexRecords) -> Result<Output, SendError> {
        self.established()?;
        let folder = self.page_folder(page)?;
        if page.request_id != 0
            || page.more
            || page.reset
            || page.records.is_empty()
            || page.epoch == 0
            || page.through > MAX_LOCAL_SEQ
        {
            return Err(SendError::Malformed);
        }
        if page.records.len() > MAX_PAGE_RECORDS {
            return Err(SendError::PageTooLong);
        }
        let frame = self.frame_for(&Message::IndexRecords(page.clone()))?;
        let empty = self.frame_for(&Message::IndexRecords(IndexRecords {
            folder_id: folder.0.to_vec(),
            records: Vec::new(),
            more: false,
            request_id: 0,
            epoch: page.epoch,
            through: 0,
            reset: false,
        }))?;
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let queued = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref())
            .is_some_and(|x| x.empty_push_queued);
        if !queued && self.room_for(frame.len()) {
            self.enqueue(frame, Tag::None, &mut out);
        } else if let Some(x) = open_mut(&mut self.folders, &folder) {
            if !x.empty_push_queued {
                x.empty_push_queued = true;
                self.enqueue(empty, Tag::EmptyPush(folder), &mut out);
            }
        }
        self.finish(&mut out);
        Ok(out)
    }

    /// Registers the peer's request as served by this side: at most one per
    /// folder, across both kinds, until the current reply's end has queued.
    fn begin_serving(
        &mut self,
        folder: FolderId,
        request_id: u32,
        kind: Served,
        paced: bool,
        event: Event,
        out: &mut Output,
    ) {
        if self.theirs_by_id.contains_key(&request_id) {
            return self.fail(Cause::Malformed, out);
        }
        let (now, min) = (self.now, self.config.timing.index_request_min);
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return self.fail(Cause::Malformed, out);
        };
        if x.serving.is_some() {
            return self.fail(Cause::Malformed, out);
        }
        let serve_at = if paced {
            x.last_serve_began
                .map_or(now, |began| now.max(began.saturating_add(min)))
        } else {
            now
        };
        x.serving = Some(Serving {
            request_id,
            kind,
            serve_at,
            held: Some(event),
            began: false,
        });
        self.theirs_by_id.insert(request_id, folder);
        self.announce_serve(folder, out);
    }

    /// The peer's `IndexRequest` (4.5): for an open folder, a `request_id`
    /// not outstanding, and no reply of this side's to its previous request
    /// for the folder still going out; handed to the engine
    /// ([`Event::ServeIndex`]) at once, or held until
    /// `INDEX_REQUEST_MIN_INTERVAL` after serving the previous one began.
    pub(super) fn on_index_request(&mut self, m: &IndexRequest, out: &mut Output) {
        let Some(folder) = FolderId::from_slice(&m.folder_id) else {
            return self.fail(Cause::Malformed, out);
        };
        let Some(redrawn) = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref())
            .map(|x| x.epoch_redrawn)
        else {
            return self.fail(Cause::Malformed, out);
        };
        let page_limit = page_limit(m.max_records);
        let event = Event::ServeIndex {
            folder,
            request: IndexServe {
                request_id: m.request_id,
                epoch: m.epoch,
                since: m.since,
                page_limit,
                redraw_allowed: !redrawn,
            },
        };
        self.begin_serving(
            folder,
            m.request_id,
            Served::Index { page_limit },
            true,
            event,
            out,
        );
    }

    /// The peer's `ReconcileRequest` (4.5): as an `IndexRequest`, but served
    /// at once unless it is for the root.
    pub(super) fn on_reconcile_request(&mut self, m: &ReconcileRequest, out: &mut Output) {
        let (Some(folder), Some(prefix), Some(digest)) = (
            FolderId::from_slice(&m.folder_id),
            Prefix::from_wire(&m.prefix),
            SetDigest::from_slice(&m.digest),
        ) else {
            return self.fail(Cause::Malformed, out);
        };
        if !self.is_open(&folder) {
            return self.fail(Cause::Malformed, out);
        }
        let root = prefix.is_root();
        let event = Event::ServeReconcile {
            folder,
            request: ReconcileServe {
                request_id: m.request_id,
                prefix,
                digest,
            },
        };
        self.begin_serving(
            folder,
            m.request_id,
            Served::Reconcile { root },
            root,
            event,
            out,
        );
    }

    /// The peer's `ReconcileReply` to this side's outstanding request (4.5):
    /// the reply deadline restarts; the sender violations of a `CHILDREN`
    /// reply are judged; `EQUAL` and `CHILDREN` complete the request, and
    /// `RECORDS` waits for its pages.
    pub(super) fn on_reconcile_reply(&mut self, m: &ReconcileReply, out: &mut Output) {
        let Some(folder) = FolderId::from_slice(&m.folder_id) else {
            return self.fail(Cause::Malformed, out);
        };
        let Some(outcome) = ReconcileOutcome::from_u32(m.outcome) else {
            return self.fail(Cause::Malformed, out);
        };
        let asked = open_mut(&mut self.folders, &folder)
            .and_then(|x| x.outstanding.as_ref())
            .filter(|o| o.request_id == m.request_id)
            .map(|o| match &o.kind {
                Asked::Reconcile {
                    prefix,
                    digest_zero,
                    reply: ReconcileProgress::Awaiting,
                } => Some((*prefix, *digest_zero)),
                // A ReconcileReply for an IndexRequest, or a second one.
                Asked::Since | Asked::Reconcile { .. } => None,
            });
        let Some(Some((prefix, digest_zero))) = asked else {
            return self.fail(Cause::Malformed, out);
        };
        if !prefix.is_root() && m.through != 0 {
            return self.fail(Cause::Malformed, out);
        }
        if outcome == ReconcileOutcome::Children && (prefix.is_full() || digest_zero) {
            return self.fail(Cause::SenderViolation, out);
        }
        self.last_progress = self.now;
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let mut caught_up = false;
        if let Some(round) = x.round.as_mut() {
            if prefix.is_root() && !round.root_answered {
                round.root_answered = true;
                if round.cursor.is_none() {
                    round.cursor = Some((m.epoch, m.through));
                }
            }
            match outcome {
                ReconcileOutcome::Equal => caught_up = prefix.is_root(),
                ReconcileOutcome::Children => {
                    let mut digests = Box::new([SetDigest::EMPTY; 16]);
                    for (d, c) in digests.iter_mut().zip(&m.children) {
                        *d = SetDigest::from_slice(c).unwrap_or(SetDigest::EMPTY);
                    }
                    round.children = Some((prefix, digests));
                }
                ReconcileOutcome::Records => {}
            }
        }
        if outcome == ReconcileOutcome::Records {
            if let Some(o) = x.outstanding.as_mut() {
                o.kind = Asked::Reconcile {
                    prefix,
                    digest_zero,
                    reply: ReconcileProgress::Records {
                        count: 0,
                        carried: Vec::new(),
                        overflow: false,
                    },
                };
            }
            return;
        }
        x.outstanding = None;
        self.ours_by_id.remove(&m.request_id);
        if caught_up {
            self.round_ended(folder, true, out);
        } else {
            self.advance(folder, out);
        }
    }

    /// An `IndexRecords` page or push: a reply's page checked against the
    /// request it answers (a reset only for an `IndexRequest`, no `through` on
    /// a `RECORDS` page, every `RECORDS` record inside the request's prefix,
    /// at most `RECONCILE_LEAF_MAX` of them at a shorter prefix answering a
    /// non-zero digest), each record past step 1, the reply deadline restarted
    /// by every page, and the records handed to the engine for judging
    /// ([`Event::Records`]). An empty push stops the counting of pushes and
    /// owes a round.
    pub(super) fn on_index_records(&mut self, m: RecordsPage, out: &mut Output) {
        let Some(folder) = FolderId::from_slice(&m.folder_id) else {
            return self.fail(Cause::Malformed, out);
        };
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return self.fail(Cause::Malformed, out);
        };
        let verifier = x.verifier;
        let page = if m.request_id == 0 {
            Page::Push { push: 0 }
        } else {
            Page::Reply {
                request_id: m.request_id,
                last: !m.more,
            }
        };
        // The reply this page belongs to, and the prefix of a RECORDS reply.
        let mut records_prefix = None;
        if let Page::Reply { request_id, .. } = page {
            let ended = x.reply_ended;
            let Some(o) = x
                .outstanding
                .as_mut()
                .filter(|o| o.request_id == request_id && !ended)
            else {
                return self.fail(Cause::Malformed, out);
            };
            match &mut o.kind {
                Asked::Since => {}
                Asked::Reconcile {
                    prefix,
                    digest_zero,
                    reply: ReconcileProgress::Records { count, .. },
                } => {
                    if m.reset || m.through != 0 {
                        return self.fail(Cause::Malformed, out);
                    }
                    *count = count.saturating_add(m.records.len());
                    if *count > RECONCILE_LEAF_MAX && !prefix.is_full() && !*digest_zero {
                        return self.fail(Cause::SenderViolation, out);
                    }
                    records_prefix = Some(*prefix);
                }
                // Pages for a ReconcileRequest whose reply was not RECORDS.
                Asked::Reconcile { .. } => return self.fail(Cause::Malformed, out),
            }
        }
        let mut records = Vec::with_capacity(m.records.len());
        for signed in m.records {
            let Ok(record) = Record::parse(signed, &verifier) else {
                return self.fail(Cause::Malformed, out);
            };
            if records_prefix.is_some_and(|p| !p.contains(&record.key())) {
                return self.fail(Cause::SenderViolation, out);
            }
            records.push(record);
        }
        match page {
            Page::Push { .. } => self.on_push(folder, m.epoch, m.through, records, out),
            Page::Reply { last, .. } => {
                self.on_reply_page(
                    folder, m.reset, m.epoch, m.through, last, records, page, out,
                );
            }
        }
    }

    /// A push's records, or an empty push (4.5, "Pushes", "Cursors").
    fn on_push(
        &mut self,
        folder: FolderId,
        epoch: u64,
        through: u64,
        records: Vec<Record>,
        out: &mut Output,
    ) {
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        if records.is_empty() {
            x.stop_counting();
            x.round_owed = true;
            if let Some(round) = x.round.as_mut() {
                round.empty_push = true;
            }
            out.events.push(Event::EmptyPush { folder });
            return self.start_owed_round(folder, out);
        }
        let advance = match x.counting {
            Some(e) if e == epoch => (through != 0).then_some(through),
            Some(_) => {
                // A push of another epoch: not counted, the counting stops,
                // and a round is owed.
                x.stop_counting();
                x.round_owed = true;
                None
            }
            None => None,
        };
        if x.pending_pushes.len() >= MAX_PENDING_PUSHES {
            // The engine judges every page it is handed; were it not to, the
            // counting stops rather than grow, and the judgements of the
            // pushes forgotten find no entry (their numbers).
            x.stop_counting();
            x.pending_pushes.clear();
        }
        let push = x.next_push;
        x.next_push = x.next_push.wrapping_add(1);
        x.pending_pushes.push_back((push, advance));
        out.events.push(Event::Records {
            folder,
            records,
            page: Page::Push { push },
        });
        self.start_owed_round(folder, out);
    }

    /// A page of the reply to this side's outstanding request.
    #[allow(
        clippy::too_many_arguments,
        reason = "the page's fields, read once by the decoder"
    )]
    fn on_reply_page(
        &mut self,
        folder: FolderId,
        reset: bool,
        epoch: u64,
        through: u64,
        last: bool,
        records: Vec<Record>,
        page: Page,
        out: &mut Output,
    ) {
        self.last_progress = self.now;
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        if let Some(o) = x.outstanding.as_mut() {
            if let Asked::Reconcile {
                reply:
                    ReconcileProgress::Records {
                        carried, overflow, ..
                    },
                ..
            } = &mut o.kind
            {
                for r in &records {
                    if carried.len() < RECONCILE_LEAF_MAX {
                        carried.push(r.hash());
                    } else {
                        *overflow = true;
                    }
                }
            }
            if matches!(o.kind, Asked::Since) {
                if let Some(round) = x.round.as_mut() {
                    if reset {
                        round.cursor = None;
                    } else if last {
                        round.cursor = Some((epoch, through));
                    }
                }
            }
        }
        if last {
            x.reply_ended = true;
        }
        if records.is_empty() {
            if last && x.awaiting == 0 {
                self.reply_completed(folder, out);
            }
        } else {
            x.awaiting += 1;
            out.events.push(Event::Records {
                folder,
                records,
                page,
            });
        }
    }

    /// The index judged the records of one [`Event::Records`] page of
    /// `folder`, in order, up to and including the first refusal that closes
    /// (a [`Cause`] such as [`Cause::Forged`]), after which the engine stores
    /// nothing more of the page. A record held restarts the reply deadline on
    /// a push and makes a pass not quiet; a skipped record makes the round
    /// skip (no cursor moves, it is never caught up) and stops the counting
    /// of pushes; a counted push's `through` raises the peer's cursor
    /// ([`Event::CursorAdvanced`]) once none of its records was skipped; and a
    /// reply's last page, once judged, lets the round go on.
    pub fn judged(
        &mut self,
        tick: Tick,
        folder: FolderId,
        page: Page,
        results: &[Result<Judgement, Cause>],
    ) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let (mut held, mut skipped) = (false, false);
        for result in results {
            if self.state == State::Closed {
                break;
            }
            match result {
                Ok(j) => {
                    held |= j.held();
                    skipped |= *j == Judgement::Skipped;
                }
                Err(cause) if cause.closes() => self.fail(*cause, &mut out),
                Err(_) => {}
            }
        }
        if self.state == State::Established {
            self.after_judgement(folder, page, held, skipped, &mut out);
        }
        self.finish(&mut out);
        out
    }

    fn after_judgement(
        &mut self,
        folder: FolderId,
        page: Page,
        held: bool,
        skipped: bool,
        out: &mut Output,
    ) {
        let now = self.now;
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        if let Some(round) = x.round.as_mut() {
            round.skipped |= skipped;
        }
        match page {
            Page::Push { push } => {
                if held {
                    self.last_progress = now;
                }
                let Some(x) = open_mut(&mut self.folders, &folder) else {
                    return;
                };
                // Its own entry. An earlier push still unjudged means the
                // judgements came out of order: the cursor must not pass a
                // push whose records were not judged, so the counting stops
                // (fail closed). A push forgotten past the bound, or dropped
                // so, finds none, and leaves the later entries alone.
                let mut advance = None;
                let mut earlier = false;
                while let Some(&(n, a)) = x.pending_pushes.front() {
                    if n > push {
                        break;
                    }
                    x.pending_pushes.pop_front();
                    if n == push {
                        advance = a;
                        break;
                    }
                    earlier = true;
                }
                if skipped || earlier {
                    x.stop_counting();
                } else if let (Some(epoch), Some(through)) = (x.counting, advance) {
                    out.events.push(Event::CursorAdvanced {
                        folder,
                        epoch,
                        through,
                    });
                }
            }
            Page::Reply { request_id, last } => {
                let ours = x
                    .outstanding
                    .as_ref()
                    .is_some_and(|o| o.request_id == request_id);
                if !ours {
                    return;
                }
                x.awaiting = x.awaiting.saturating_sub(1);
                if let Some(round) = x.round.as_mut() {
                    if round.stage == Stage::Passes {
                        round.brought |= held;
                    }
                }
                if last || (x.reply_ended && x.awaiting == 0) {
                    self.reply_completed(folder, out);
                }
            }
        }
    }

    /// The reply to this side's outstanding request is complete and judged:
    /// after the Since reply, the Check; after a `RECORDS` reply, the
    /// requester's pushes of what the reply lacked
    /// ([`Event::PushSubtree`]), then the next step of the pass.
    fn reply_completed(&mut self, folder: FolderId, out: &mut Output) {
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let Some(done) = x.outstanding.take() else {
            return;
        };
        x.awaiting = 0;
        x.reply_ended = false;
        self.ours_by_id.remove(&done.request_id);
        match done.kind {
            Asked::Since => {
                if let Some(round) =
                    open_mut(&mut self.folders, &folder).and_then(|x| x.round.as_mut())
                {
                    round.stage = Stage::Passes;
                }
            }
            Asked::Reconcile {
                prefix,
                reply:
                    ReconcileProgress::Records {
                        carried, overflow, ..
                    },
                ..
            } => out.events.push(Event::PushSubtree {
                folder,
                prefix,
                carried: (!overflow).then_some(carried),
            }),
            Asked::Reconcile { .. } => {}
        }
        self.advance(folder, out);
    }

    /// The round goes on: the next request is due, unless the round has
    /// ended meanwhile.
    fn advance(&mut self, folder: FolderId, out: &mut Output) {
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        // Every caller has a round under way.
        if x.round.is_some() && x.outstanding.is_none() && !x.due {
            x.due = true;
            out.events.push(Event::RequestDue { folder });
        }
    }

    /// The peer's proven device ID, once its `DeviceProof` has verified.
    #[must_use]
    pub fn peer_device(&self) -> Option<DeviceId> {
        (self.state == State::Established)
            .then(|| self.peer.as_ref().map(|p| p.device_id))
            .flatten()
    }
}

#[cfg(test)]
impl Connection {
    /// The pushes of an open folder whose judgements have not come back, for
    /// tests.
    pub(super) fn pending_pushes(&self, folder: &FolderId) -> usize {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .map_or(0, |x| x.pending_pushes.len())
    }

    /// Whether an open folder owes a round, for tests.
    pub(super) fn round_owed(&self, folder: &FolderId) -> bool {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .is_some_and(|x| x.round_owed)
    }

    /// Whether a round of this side's is under way, for tests.
    pub(super) fn round_under_way(&self, folder: &FolderId) -> bool {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .is_some_and(|x| x.round.is_some())
    }

    /// Whether the peer's pushes are counted, for tests.
    pub(super) fn counting(&self, folder: &FolderId) -> Option<u64> {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .and_then(|x| x.counting)
    }

    /// Lowers `MAX_PASS_REQUESTS` for a folder, for tests of the cut.
    pub(super) fn set_pass_cap(&mut self, folder: &FolderId, cap: usize) {
        if let Some(x) = open_mut(&mut self.folders, folder) {
            x.pass_cap = cap;
        }
    }

    /// The pass under way and its requests so far, for tests.
    pub(super) fn pass_of(&self, folder: &FolderId) -> Option<(usize, usize)> {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .and_then(|x| x.round.as_ref())
            .map(|r| (r.pass, r.pass_requests))
    }

    /// The work list of the round under way, for tests.
    pub(super) fn work_list_len(&self, folder: &FolderId) -> usize {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .and_then(|x| x.round.as_ref())
            .map_or(0, |r| r.work.len())
    }
}
