// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Step 5 on one connection (`protocol.md` 4.5): this side's rounds of range
//! requests and its listed requests for marks, the round owed, one request
//! per folder each way, the resync intervals, `INDEX_REQUEST_MIN_INTERVAL`,
//! pages and pushes, the empty push owed, and `REPLY_PAGE_TIMEOUT`. Every
//! table here is per open folder and bounded: one outstanding request each
//! way, at most `MAX_MARKED_WRITERS` marks, a few flags and times (TM-22).

use std::collections::BTreeMap;

use core::time::Duration;

use licketysync_keys::{DeviceId, FolderId, FolderVerifier};

use super::{open_mut, Connection, Event, Output, Page, Received, SendError, State, Tag, Tick};
use crate::exchange::{listed_request, range_request, Cursors, Scope, ServeRequest};
use crate::limits::{MAX_MARKED_WRITERS, MAX_PAGE_RECORDS};
use crate::messages::{IndexRecords, IndexRequest, Message};
use crate::parse::RecordsPage;
use crate::record::{Arrival, Record};
use crate::rules::Cause;

/// An `IndexRequest` this side is to send now (4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Due {
    /// A range request covering the writers above `after` (from the lowest
    /// for `None`): the first of a round, or the next one.
    Range {
        /// The range's exclusive lower bound.
        after: Option<DeviceId>,
    },
    /// A listed request for exactly these writers, ascending: this side's
    /// marks.
    Listed {
        /// The marked writers.
        writers: Vec<DeviceId>,
    },
}

/// Why a writer is marked (4.5, "Marks").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MarkKind {
    /// A gap in a push: its listed request waits for `INDEX_RESYNC_INTERVAL`
    /// since the previous gap-triggered one.
    Gap,
    /// A full resend while serving (case (c)): its listed request goes once
    /// the current reply has completed.
    Resend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    RoundStart { owed: bool },
    RoundNext,
    Listed { gap_only: bool },
}

#[derive(Clone, Debug)]
struct Outstanding {
    request_id: u32,
    scope: Scope,
    through: Option<DeviceId>,
    listed: bool,
    handed_end: Option<u64>,
    departed_at: Option<Duration>,
}

/// The peer's request this side is serving, or holds until it may.
#[derive(Clone, Debug)]
struct Serving {
    request_id: u32,
    page_limit: usize,
    serve_at: Duration,
    /// The request until [`Event::Serve`] hands it to the engine at
    /// `serve_at`; `None` once it may be served.
    held: Option<ServeRequest>,
    /// The first page has gone: serving began.
    began: bool,
}

/// One open folder's exchange state on this connection.
#[derive(Debug)]
pub(super) struct Exchange {
    pub(super) verifier: FolderVerifier,
    outstanding: Option<Outstanding>,
    /// A round under way between two of its range requests: the next starts
    /// above this device ID.
    round_next: Option<DeviceId>,
    due: Option<(Due, Why)>,
    marks: BTreeMap<DeviceId, MarkKind>,
    round_owed: bool,
    last_owed_start: Option<Duration>,
    last_gap_listed: Option<Duration>,
    serving: Option<Serving>,
    /// When this side began serving the peer's previous request: its first
    /// page went (`INDEX_REQUEST_MIN_INTERVAL` counts from then).
    last_serve_began: Option<Duration>,
    empty_push_queued: bool,
    pub(super) chunks: super::chunks::FolderChunks,
}

impl Exchange {
    pub(super) fn new(verifier: FolderVerifier) -> Self {
        Self {
            verifier,
            outstanding: None,
            round_next: None,
            due: None,
            marks: BTreeMap::new(),
            round_owed: false,
            last_owed_start: None,
            last_gap_listed: None,
            serving: None,
            last_serve_began: None,
            empty_push_queued: false,
            chunks: super::chunks::FolderChunks::new(),
        }
    }

    /// What is due now, if anything, in the order of 4.5: the next range of
    /// a round under way; an owed round (rate-limited); a listed request for
    /// the marks (gap marks alone rate-limited). Within a round the next
    /// range goes before a listed request (decision: its range may cover
    /// marks).
    fn compute_due(&self, now: Duration, resync: Duration) -> Option<(Due, Why)> {
        if self.outstanding.is_some() {
            return None;
        }
        if let Some(after) = self.round_next {
            return Some((Due::Range { after: Some(after) }, Why::RoundNext));
        }
        let allowed = |last: Option<Duration>| last.is_none_or(|l| now >= l.saturating_add(resync));
        if self.round_owed && allowed(self.last_owed_start) {
            return Some((Due::Range { after: None }, Why::RoundStart { owed: true }));
        }
        if self.marks.is_empty() {
            return None;
        }
        let gap_only = self.marks.values().all(|k| *k == MarkKind::Gap);
        if gap_only && !allowed(self.last_gap_listed) {
            return None;
        }
        Some((
            Due::Listed {
                writers: self.marks.keys().copied().collect(),
            },
            Why::Listed { gap_only },
        ))
    }

    /// When a rate-limited request of this side becomes due, or a held
    /// request of the peer's may be served.
    fn wake(&self, resync: Duration) -> Option<Duration> {
        let serve = self
            .serving
            .as_ref()
            .filter(|s| s.held.is_some())
            .map(|s| s.serve_at);
        if self.outstanding.is_some() || self.due.is_some() {
            return serve;
        }
        let owed = self
            .last_owed_start
            .filter(|_| self.round_owed)
            .map(|l| l.saturating_add(resync));
        let gap = self
            .last_gap_listed
            .filter(|_| !self.marks.is_empty())
            .map(|l| l.saturating_add(resync));
        [serve, owed, gap].into_iter().flatten().min()
    }

    /// Adds a mark; one more than `MAX_MARKED_WRITERS` drops them all and
    /// owes a round instead, which covers them.
    fn mark(&mut self, writer: DeviceId, kind: MarkKind) {
        if let Some(k) = self.marks.get_mut(&writer) {
            *k = (*k).max(kind);
            return;
        }
        if self.marks.len() >= MAX_MARKED_WRITERS {
            self.marks.clear();
            self.round_owed = true;
            return;
        }
        self.marks.insert(writer, kind);
    }
}

impl Connection {
    /// The deadline of the replies to this side's requests: no page for
    /// `REPLY_PAGE_TIMEOUT` since the request left the send queue or since
    /// the last restart (any page of a reply to this side's requests, a
    /// `CHUNK_OK`, a push that brought a stored record).
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
            self.refresh_due(folder, out);
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
        if let Some(request) = serving.held.take() {
            out.events.push(Event::Serve { folder, request });
        }
    }

    /// The round a side sends when a folder opens on the connection.
    pub(super) fn round_on_open(&mut self, folder: FolderId, out: &mut Output) {
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.due = Some((Due::Range { after: None }, Why::RoundStart { owed: false }));
            out.events.push(Event::RequestDue {
                folder,
                due: Due::Range { after: None },
            });
        }
    }

    /// Computes what is due for `folder` when nothing is, and tells the engine.
    fn refresh_due(&mut self, folder: FolderId, out: &mut Output) {
        let (now, resync) = (self.now, self.config.timing.index_resync);
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        if x.due.is_some() {
            return;
        }
        if let Some((due, why)) = x.compute_due(now, resync) {
            x.due = Some((due.clone(), why));
            out.events.push(Event::RequestDue { folder, due });
        }
    }

    /// What is due for `folder`, if anything.
    #[must_use]
    pub fn due(&self, folder: &FolderId) -> Option<&Due> {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref()?.due.as_ref())
            .map(|(d, _)| d)
    }

    /// Marks `writer` of an open folder for a listed request (4.5, "Marks"),
    /// and tells the engine if one falls due.
    pub(super) fn mark_writer(
        &mut self,
        folder: FolderId,
        writer: DeviceId,
        kind: MarkKind,
        out: &mut Output,
    ) {
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.mark(writer, kind);
            self.refresh_due(folder, out);
        }
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

    /// Sends this side's `IndexRequest` that is due for `folder`
    /// ([`Event::RequestDue`], [`Connection::due`]), built here from the
    /// index's `cursors`: for the next range of a round, its cursors from
    /// above the range's start, at most `MAX_CURSORS_PER_REQUEST` (the
    /// request's `through` then names the last, and the round goes on after
    /// its reply); for a listed request, the cursors of exactly the marked
    /// writers. The request gets a fresh `request_id` and the configured
    /// `max_records`; sending it clears the marks it covers (ruling MARK).
    ///
    /// # Errors
    /// [`SendError::NotDue`], [`SendError::FolderNotOpen`],
    /// [`SendError::Malformed`] for cursors out of order or without their
    /// digest, [`SendError::TooLarge`], or the connection's state.
    pub fn send_request<C: Cursors + ?Sized>(
        &mut self,
        tick: Tick,
        folder: FolderId,
        cursors: &C,
    ) -> Result<Output, SendError> {
        self.established()?;
        let x = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref())
            .ok_or(SendError::FolderNotOpen)?;
        let (due, why) = x.due.clone().ok_or(SendError::NotDue)?;
        let max_records = self.config.max_records;
        let mut request = match &due {
            Due::Range { after } => {
                range_request(&folder, *after, cursors.cursors_after(*after), max_records)
            }
            Due::Listed { writers } => listed_request(
                &folder,
                writers.iter().map(|w| crate::exchange::WriterCursor {
                    writer: *w,
                    ..cursors.cursor_of(w)
                }),
                max_records,
            ),
        }
        .map_err(|_| SendError::Malformed)?;
        let request_id = self.fresh_request_id();
        request.request_id = request_id;
        let scope = Scope::of(&request);
        let through = DeviceId::from_slice(&request.through);
        let listed = request.listed;
        let frame = self.frame_for(&Message::IndexRequest(request))?;
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let now = self.now;
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            match why {
                Why::RoundStart { owed: true } => {
                    x.round_owed = false;
                    x.last_owed_start = Some(now);
                }
                Why::Listed { gap_only: true } => x.last_gap_listed = Some(now),
                Why::RoundStart { owed: false }
                | Why::RoundNext
                | Why::Listed { gap_only: false } => {}
            }
            // Sending a request clears the marks it covers, set before it (MARK).
            x.marks.retain(|w, _| !scope.contains(w));
            x.round_next = None;
            x.due = None;
            x.outstanding = Some(Outstanding {
                request_id,
                through,
                listed,
                scope,
                handed_end: None,
                departed_at: None,
            });
        }
        self.next_request_id = request_id;
        self.ours_by_id.insert(request_id, folder);
        self.enqueue(frame, Tag::Request(folder), &mut out);
        self.finish(&mut out);
        Ok(out)
    }

    /// Sends one page of the reply to the peer's request that
    /// [`Event::Serve`] handed over, at most the request's page limit and the
    /// peer's frame limit (build it with [`crate::exchange::Pager`]); `more`
    /// on every page but the last, and a page with `more` holds a record.
    /// `resent` names the writers this page's serving resent in full after a
    /// digest mismatch (case (c)): each is marked for a listed request of this
    /// side's own (4.5, "Marks"). The first page begins the serving, from
    /// which `INDEX_REQUEST_MIN_INTERVAL` counts; the last ends it, and the
    /// peer may send its next request.
    ///
    /// # Errors
    /// [`SendError::WouldBlock`] when the send queue has no room for the page:
    /// keep it, call [`Connection::want_room`] and send it on
    /// [`Event::Room`]; [`SendError::UnknownRequest`],
    /// [`SendError::PageTooLong`], [`SendError::Malformed`],
    /// [`SendError::TooLarge`], [`SendError::FolderNotOpen`], or the
    /// connection's state.
    pub fn send_page(
        &mut self,
        tick: Tick,
        page: &IndexRecords,
        resent: &[DeviceId],
    ) -> Result<Output, SendError> {
        self.established()?;
        let folder = self.page_folder(page)?;
        let serving = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref()?.serving.as_ref())
            .filter(|s| s.request_id == page.request_id && s.held.is_none())
            .ok_or(SendError::UnknownRequest)?;
        if page.records.len() > serving.page_limit {
            return Err(SendError::PageTooLong);
        }
        if page.more && page.records.is_empty() {
            return Err(SendError::Malformed);
        }
        let frame = self.frame_for(&Message::IndexRecords(page.clone()))?;
        if !self.has_room(tick, frame.len()) {
            return Err(SendError::WouldBlock { len: frame.len() });
        }
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let now = self.now;
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            if let Some(serving) = x.serving.as_mut() {
                if !serving.began {
                    serving.began = true;
                    x.last_serve_began = Some(now);
                }
            }
            if !page.more {
                x.serving = None;
            }
        }
        if !page.more {
            self.theirs_by_id.remove(&page.request_id);
        }
        self.enqueue(frame, Tag::None, &mut out);
        for writer in resent {
            self.mark_writer(folder, *writer, MarkKind::Resend, &mut out);
        }
        self.finish(&mut out);
        Ok(out)
    }

    /// Pushes records the index newly accepted from elsewhere (4.5,
    /// "Pushes"): one page with `request_id = 0` and `more` false, at most
    /// `MAX_PAGE_RECORDS`, each writer's records in canonical order. It goes
    /// at once or not at all: when the send queue cannot take it, it is
    /// dropped, and the peer is owed one empty push for the folder, which
    /// waits in order and is never dropped (3.1, PUSH-1). The output's frames
    /// say which: the push, the empty push, or nothing (one already owed).
    ///
    /// # Errors
    /// [`SendError::Malformed`] for a page with `request_id` or `more` set or
    /// no record, [`SendError::PageTooLong`], [`SendError::TooLarge`],
    /// [`SendError::FolderNotOpen`], or the connection's state.
    pub fn push(&mut self, tick: Tick, page: &IndexRecords) -> Result<Output, SendError> {
        self.established()?;
        let folder = self.page_folder(page)?;
        if page.request_id != 0 || page.more || page.records.is_empty() {
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
        }))?;
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if self.room_for(frame.len()) {
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

    /// The peer's `IndexRequest` (4.5): for an open folder, a `request_id`
    /// not outstanding, and no reply to its previous request for the folder
    /// still going out; handed to the engine ([`Event::Serve`]) at once, or
    /// held until `INDEX_REQUEST_MIN_INTERVAL` after serving the previous one
    /// began.
    pub(super) fn on_index_request(&mut self, m: &IndexRequest, out: &mut Output) {
        let Some(folder) = FolderId::from_slice(&m.folder_id) else {
            return self.fail(Cause::Malformed, out);
        };
        if self.theirs_by_id.contains_key(&m.request_id) {
            return self.fail(Cause::Malformed, out);
        }
        let (now, min) = (self.now, self.config.timing.index_request_min);
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return self.fail(Cause::Malformed, out);
        };
        if x.serving.is_some() {
            return self.fail(Cause::Malformed, out);
        }
        let serve_at = x
            .last_serve_began
            .map_or(now, |began| now.max(began.saturating_add(min)));
        let request = ServeRequest::of(m);
        x.serving = Some(Serving {
            request_id: m.request_id,
            page_limit: request.page_limit,
            serve_at,
            held: Some(request),
            began: false,
        });
        self.theirs_by_id.insert(m.request_id, folder);
        self.announce_serve(folder, out);
    }

    /// An `IndexRecords` page or push: each record past step 1, a reply's
    /// records with their scope, the reply deadline restarted by every page,
    /// and the round advanced by a reply's last page.
    pub(super) fn on_index_records(&mut self, m: RecordsPage, out: &mut Output) {
        let Some(folder) = FolderId::from_slice(&m.folder_id) else {
            return self.fail(Cause::Malformed, out);
        };
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return self.fail(Cause::Malformed, out);
        };
        let verifier = x.verifier;
        let page = if m.request_id == 0 {
            Page::Push
        } else {
            match &x.outstanding {
                Some(o) if o.request_id == m.request_id => Page::Reply {
                    request_id: m.request_id,
                    last: !m.more,
                },
                // A page whose request_id names no request outstanding.
                _ => return self.fail(Cause::Malformed, out),
            }
        };
        let scope = x.outstanding.as_ref().map(|o| o.scope.clone());
        let mut records = Vec::with_capacity(m.records.len());
        for signed in m.records {
            let Ok(record) = Record::parse(signed, &verifier) else {
                return self.fail(Cause::Malformed, out);
            };
            let arrival = match (&page, &scope) {
                (Page::Reply { .. }, Some(s)) => Arrival::Reply {
                    in_scope: s.contains(&record.device_id()),
                },
                _ => Arrival::Push,
            };
            records.push(Received { record, arrival });
        }
        match page {
            Page::Push if records.is_empty() => {
                if let Some(x) = open_mut(&mut self.folders, &folder) {
                    x.round_owed = true;
                }
                out.events.push(Event::EmptyPush { folder });
                self.refresh_due(folder, out);
            }
            Page::Push => out.events.push(Event::Records {
                folder,
                records,
                page,
            }),
            Page::Reply { last, .. } => {
                self.last_progress = self.now;
                out.events.push(Event::Records {
                    folder,
                    records,
                    page,
                });
                if last {
                    self.reply_completed(folder, out);
                }
            }
        }
    }

    /// The last page of the reply to this side's request arrived.
    fn reply_completed(&mut self, folder: FolderId, out: &mut Output) {
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let Some(done) = x.outstanding.take() else {
            return;
        };
        self.ours_by_id.remove(&done.request_id);
        let round_done = if done.listed {
            false
        } else if let Some(through) = done.through {
            x.round_next = Some(through);
            false
        } else {
            true
        };
        if round_done {
            out.events.push(Event::RoundCompleted { folder });
            self.round_completed_for_chunks(folder, out);
        }
        self.refresh_due(folder, out);
    }
}

#[cfg(test)]
impl Connection {
    /// Marks a writer as the index's judgements and the serving of case (c)
    /// do, for tests and vectors that set marks up directly.
    pub(crate) fn mark(
        &mut self,
        tick: Tick,
        folder: FolderId,
        writer: DeviceId,
        kind: MarkKind,
    ) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        self.mark_writer(folder, writer, kind, &mut out);
        self.finish(&mut out);
        out
    }

    /// The marks of an open folder, for tests.
    pub(super) fn marks(&self, folder: &FolderId) -> Vec<(DeviceId, MarkKind)> {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .map(|x| x.marks.iter().map(|(w, k)| (*w, *k)).collect())
            .unwrap_or_default()
    }

    /// Whether an open folder owes a round, for tests.
    pub(super) fn round_owed(&self, folder: &FolderId) -> bool {
        self.folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .is_some_and(|x| x.round_owed)
    }
}
