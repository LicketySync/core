// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Steps 6 and 7 and Status on one connection (`protocol.md` 4.5, 4.6): chunk
//! requests in flight both ways (this side's at most the peer's
//! `max_requests_in_flight`, itself at most `MAX_REQUESTS_IN_FLIGHT`),
//! `CHUNK_BUSY` at dispatch, the requester's one `CHUNK_BUSY_BACKOFF` timer,
//! the chunk passes (one position, one number, one time and two bits per
//! folder), the ciphertext hash of every chunk sent and received, and Status
//! with `chunks_stored` and the device name. Any peer with the folder open may
//! ask for any chunk, whatever tier it reports (ruling S-3).

use std::collections::BTreeMap;

use core::time::Duration;

use licketysync_keys::chunk::cipher_hash;
use licketysync_keys::{CipherHash, FolderId};

use super::{open_mut, ChunkAnswer, Connection, Event, Output, SendError, Tag, Tick};
use crate::limits::{MAX_REQUESTS_IN_FLIGHT, MAX_SEND_QUEUE, MAX_STATUS_FOLDERS, MAX_STORED_LEN};
use crate::messages::{ChunkReply, ChunkRequest, ChunkStatus, FolderStatus, Message, Status};
use crate::rules::Cause;

/// The connection-wide chunk state.
#[derive(Debug)]
pub(super) struct Chunks {
    /// This side's requests in flight, by folder and hash, with the time
    /// each was sent (the backoff rule needs it); at most the peer's
    /// `max_requests_in_flight`, and at most `MAX_REQUESTS_IN_FLIGHT`, in all,
    /// and one per hash.
    ours: BTreeMap<(FolderId, CipherHash), Duration>,
    /// The peer's requests delivered to the engine and not yet answered.
    theirs: BTreeMap<(FolderId, CipherHash), u32>,
    /// The peer's requests whose reply (`CHUNK_OK`, `CHUNK_NOT_FOUND` or this
    /// side's `CHUNK_BUSY`) has not yet left this connection's backlog: at
    /// most this side's `max_requests_in_flight`, so that a peer that never
    /// reads cannot make replies pile up here (TM-22). Every such request is
    /// also outstanding at the peer, which has not received its reply, so an
    /// honest peer is never closed for it.
    theirs_count: usize,
    /// The backoff the next qualifying `CHUNK_BUSY` imposes.
    next_backoff: Duration,
    /// The end of the current backoff period.
    until: Option<Duration>,
    /// The end not yet announced with [`Event::ChunksAllowed`].
    announce_at: Option<Duration>,
}

impl Chunks {
    pub(super) fn new(backoff: Duration) -> Self {
        Self {
            ours: BTreeMap::new(),
            theirs: BTreeMap::new(),
            theirs_count: 0,
            next_backoff: backoff,
            until: None,
            announce_at: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pass {
    /// No pass under way; one may start.
    Free,
    /// A pass under way, at `position`, the last hash asked; `not_found` once
    /// it got a `CHUNK_NOT_FOUND`.
    Asking {
        position: CipherHash,
        not_found: bool,
    },
    /// After a pass that got a `CHUNK_NOT_FOUND`: waiting for a trigger, then,
    /// once one has fired (`ready_at`), for 1 s after that answer.
    Waiting { ready_at: Option<Duration> },
}

/// One open folder's chunk and status state on this connection.
#[derive(Debug)]
pub(super) struct FolderChunks {
    /// The chunks this device stored for the folder since it opened here.
    stored: u64,
    /// The peer's latest `chunks_stored`.
    peer_stored: Option<u64>,
    pass: Pass,
    /// The latest `CHUNK_NOT_FOUND`: its time and the peer's `chunks_stored`
    /// in its last Status before it.
    latest_not_found: Option<(Duration, u64)>,
    /// A round with the peer completed since the latest `CHUNK_NOT_FOUND`,
    /// whatever the pass was doing then: a trigger, judged when the pass
    /// comes to wait if it was still asking.
    round_since_not_found: bool,
    /// When a trigger was last acted on (at most once per
    /// `STATUS_INTERVAL`), and whether one waits for that window to end.
    last_eval: Option<Duration>,
    pending: bool,
}

impl FolderChunks {
    pub(super) const fn new() -> Self {
        Self {
            stored: 0,
            peer_stored: None,
            pass: Pass::Free,
            latest_not_found: None,
            round_since_not_found: false,
            last_eval: None,
            pending: false,
        }
    }

    /// Whether a trigger has fired since the latest `CHUNK_NOT_FOUND`: a
    /// completed round, or the peer's `chunks_stored` above its value then.
    fn triggered(&self) -> bool {
        let baseline = self.latest_not_found.map_or(0, |(_, b)| b);
        self.round_since_not_found || self.peer_stored.is_some_and(|s| s > baseline)
    }
}

impl Connection {
    /// Whether this side may send a chunk request for `folder` now, and from
    /// where: `Ok(None)` to start a pass (the smallest hash it lacks),
    /// `Ok(Some(h))` to go on above `h`.
    ///
    /// # Errors
    /// [`SendError::FolderNotOpen`], [`SendError::InFlightFull`],
    /// [`SendError::BackingOff`] or [`SendError::PassWaiting`].
    pub fn chunk_position(
        &self,
        tick: Tick,
        folder: &FolderId,
    ) -> Result<Option<CipherHash>, SendError> {
        let x = self
            .folders
            .get(folder)
            .and_then(|f| f.open.as_ref())
            .ok_or(SendError::FolderNotOpen)?;
        self.chunk_room(tick.now.max(self.now))?;
        match x.chunks.pass {
            Pass::Free => Ok(None),
            Pass::Asking { position, .. } => Ok(Some(position)),
            Pass::Waiting { .. } => Err(SendError::PassWaiting),
        }
    }

    /// The requests this side may keep outstanding: the peer's
    /// `max_requests_in_flight`, a larger value than `MAX_REQUESTS_IN_FLIGHT`
    /// taken as that (sections 2, 4.6).
    fn requests_allowed(&self) -> usize {
        let advertised = self
            .peer
            .as_ref()
            .map_or(0, |p| p.hello.max_requests_in_flight);
        usize::try_from(advertised.min(MAX_REQUESTS_IN_FLIGHT)).unwrap_or(0)
    }

    fn chunk_room(&self, now: Duration) -> Result<(), SendError> {
        if self.chunks.ours.len() >= self.requests_allowed() {
            return Err(SendError::InFlightFull);
        }
        if self.chunks.until.is_some_and(|u| now < u) {
            return Err(SendError::BackingOff);
        }
        Ok(())
    }

    /// Asks the peer for the chunk `cipher_hash` of `folder`, the next of the
    /// pass to this peer: above the pass's position ([`Self::chunk_position`]).
    ///
    /// # Errors
    /// [`SendError::InFlightFull`], [`SendError::BackingOff`],
    /// [`SendError::AlreadyRequested`], [`SendError::PassWaiting`],
    /// [`SendError::OutOfOrder`], [`SendError::FolderNotOpen`], or the
    /// connection's state.
    pub fn request_chunk(
        &mut self,
        tick: Tick,
        folder: FolderId,
        cipher_hash: CipherHash,
    ) -> Result<Output, SendError> {
        self.established()?;
        let x = self
            .folders
            .get(&folder)
            .and_then(|f| f.open.as_ref())
            .ok_or(SendError::FolderNotOpen)?;
        self.chunk_room(tick.now.max(self.now))?;
        if self.chunks.ours.contains_key(&(folder, cipher_hash)) {
            return Err(SendError::AlreadyRequested);
        }
        let not_found = match x.chunks.pass {
            Pass::Waiting { .. } => return Err(SendError::PassWaiting),
            Pass::Asking { position, .. } if cipher_hash <= position => {
                return Err(SendError::OutOfOrder)
            }
            Pass::Asking { not_found, .. } => not_found,
            Pass::Free => false,
        };
        let frame = self.frame_for(&Message::ChunkRequest(ChunkRequest {
            folder_id: folder.0.to_vec(),
            cipher_hash: cipher_hash.0.to_vec(),
        }))?;
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let now = self.now;
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.chunks.pass = Pass::Asking {
                position: cipher_hash,
                not_found,
            };
        }
        self.chunks.ours.insert((folder, cipher_hash), now);
        self.enqueue(frame, Tag::None, &mut out);
        self.finish(&mut out);
        Ok(out)
    }

    /// The engine found no chunk it lacks above the pass's position: the
    /// pass to this peer for `folder` ends. After a pass that got any
    /// `CHUNK_NOT_FOUND`, the next waits for a trigger (4.6); one that has
    /// already fired (a round completed, or a Status above the baseline, while
    /// the pass was still asking) is judged at once.
    pub fn pass_done(&mut self, tick: Tick, folder: FolderId) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let mut waits = false;
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.chunks.pass = match x.chunks.pass {
                Pass::Asking {
                    not_found: true, ..
                } => {
                    waits = true;
                    Pass::Waiting { ready_at: None }
                }
                Pass::Asking {
                    not_found: false, ..
                } => Pass::Free,
                other => other,
            };
        }
        if waits {
            self.trigger(folder, &mut out);
        }
        self.finish(&mut out);
        out
    }

    /// Answers the peer's request for the chunk `hash` of `folder`
    /// ([`Event::ChunkRequested`]): the stored blob, which is checked to be
    /// the chunk requested (at most the largest stored chunk, and its
    /// ciphertext hash the one asked; one BLAKE3 pass) so that a blob
    /// corrupted in storage is never sent (TM-10), or `CHUNK_NOT_FOUND`.
    ///
    /// # Errors
    /// [`SendError::WouldBlock`] when the send queue has no room for the
    /// chunk: keep the request, call [`Connection::want_room`] and answer on
    /// [`Event::Room`]; [`SendError::Corrupt`], [`SendError::Unrequested`],
    /// [`SendError::FolderNotOpen`], [`SendError::TooLarge`], or the
    /// connection's state.
    pub fn reply_chunk(
        &mut self,
        tick: Tick,
        folder: FolderId,
        hash: CipherHash,
        answer: ChunkAnswer<'_>,
    ) -> Result<Output, SendError> {
        self.established()?;
        if !self.is_open(&folder) {
            return Err(SendError::FolderNotOpen);
        }
        let key = (folder, hash);
        if !self.chunks.theirs.contains_key(&key) {
            return Err(SendError::Unrequested);
        }
        let (status, data) = match answer {
            ChunkAnswer::Ok(data) => {
                if data.is_empty() || data.len() > MAX_STORED_LEN {
                    return Err(SendError::Corrupt);
                }
                (ChunkStatus::Ok, data)
            }
            ChunkAnswer::NotFound => (ChunkStatus::NotFound, &[][..]),
        };
        let frame = self.frame_for(&Message::ChunkReply(ChunkReply {
            folder_id: folder.0.to_vec(),
            cipher_hash: hash.0.to_vec(),
            status: status.as_u32(),
            data: data.to_vec(),
        }))?;
        if status == ChunkStatus::Ok {
            // What a peer can make this side send in volume never waits in
            // the backlog (SEC-SF2).
            if !self.has_room(tick, frame.len()) {
                return Err(SendError::WouldBlock { len: frame.len() });
            }
            if cipher_hash(data) != hash {
                return Err(SendError::Corrupt);
            }
        }
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if let Some(n) = self.chunks.theirs.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.chunks.theirs.remove(&key);
            }
        }
        // Counted against the in-flight limit until it is handed over.
        self.enqueue(frame, Tag::ChunkReply, &mut out);
        self.finish(&mut out);
        Ok(out)
    }

    /// A chunk reply left the backlog for the transport.
    pub(super) fn chunk_reply_handed(&mut self) {
        self.chunks.theirs_count = self.chunks.theirs_count.saturating_sub(1);
    }

    /// The peer's chunk request: within this side's `max_requests_in_flight`
    /// (counting every request whose reply has not yet left the backlog),
    /// answered `CHUNK_BUSY` at once when at least half of `MAX_SEND_QUEUE`
    /// is unsent, the backlog counted, as it is dispatched (4.6), otherwise
    /// handed to the engine, which holds only the hash until it sends the
    /// chunk.
    pub(super) fn on_chunk_request(&mut self, m: &ChunkRequest, out: &mut Output) {
        let (Some(folder), Some(hash)) = (
            FolderId::from_slice(&m.folder_id),
            CipherHash::from_slice(&m.cipher_hash),
        ) else {
            return self.fail(Cause::Malformed, out);
        };
        let limit = usize::try_from(self.config.max_requests_in_flight).unwrap_or(usize::MAX);
        if !self.is_open(&folder) || self.chunks.theirs_count >= limit {
            return self.fail(Cause::Malformed, out);
        }
        self.chunks.theirs_count += 1;
        if self.unsent.saturating_add(self.backlog_bytes) >= MAX_SEND_QUEUE / 2 {
            let busy = Message::ChunkReply(ChunkReply {
                folder_id: m.folder_id.clone(),
                cipher_hash: m.cipher_hash.clone(),
                status: ChunkStatus::Busy.as_u32(),
                data: Vec::new(),
            });
            if let Ok(frame) = busy.to_frame() {
                self.enqueue(frame.encode(), Tag::ChunkReply, out);
            }
            return;
        }
        *self.chunks.theirs.entry((folder, hash)).or_insert(0) += 1;
        out.events.push(Event::ChunkRequested {
            folder,
            cipher_hash: hash,
        });
    }

    /// A reply to one of this side's chunk requests (4.6): solicited, then
    /// for `CHUNK_OK` the ciphertext hash (a mismatch is forged), which
    /// restarts the reply deadline and resets the backoff.
    pub(super) fn on_chunk_reply(&mut self, m: ChunkReply, out: &mut Output) {
        let (Some(folder), Some(hash)) = (
            FolderId::from_slice(&m.folder_id),
            CipherHash::from_slice(&m.cipher_hash),
        ) else {
            return self.fail(Cause::Malformed, out);
        };
        let Some(sent_at) = self.chunks.ours.remove(&(folder, hash)) else {
            // Unsolicited.
            return self.fail(Cause::Malformed, out);
        };
        if !self.is_open(&folder) {
            return self.fail(Cause::Malformed, out);
        }
        let now = self.now;
        match ChunkStatus::from_u32(m.status) {
            Some(ChunkStatus::Ok) => {
                if cipher_hash(&m.data) != hash {
                    return self.fail(Cause::Forged, out);
                }
                self.chunks.next_backoff = self.config.timing.busy_backoff;
                self.last_progress = now;
                out.events.push(Event::Chunk {
                    folder,
                    cipher_hash: hash,
                    data: m.data,
                });
            }
            Some(ChunkStatus::NotFound) => {
                self.not_found(folder);
                out.events.push(Event::ChunkNotFound {
                    folder,
                    cipher_hash: hash,
                });
            }
            Some(ChunkStatus::Busy) => {
                self.busy(sent_at);
                out.events.push(Event::ChunkBusy {
                    folder,
                    cipher_hash: hash,
                });
            }
            None => self.fail(Cause::Malformed, out),
        }
    }

    /// A `CHUNK_BUSY` for a request sent at `sent_at`: the first one, or one
    /// for a request sent after the current backoff ended, imposes the next
    /// backoff and doubles it, up to `MAX_CHUNK_BUSY_BACKOFF`; one for a
    /// request sent before leaves it unchanged.
    fn busy(&mut self, sent_at: Duration) {
        let qualifies = self.chunks.until.is_none_or(|end| sent_at >= end);
        if qualifies {
            let end = self.now.saturating_add(self.chunks.next_backoff);
            self.chunks.until = Some(end);
            self.chunks.announce_at = Some(end);
            self.chunks.next_backoff = self
                .chunks
                .next_backoff
                .saturating_mul(2)
                .min(self.config.timing.max_busy_backoff);
        }
    }

    /// A `CHUNK_NOT_FOUND`: the latest one's time and baseline, every earlier
    /// trigger spent; a pass under way goes on, and one ended (or a later
    /// answer to a pass already ended) waits for a new trigger.
    fn not_found(&mut self, folder: FolderId) {
        let now = self.now;
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let c = &mut x.chunks;
        c.latest_not_found = Some((now, c.peer_stored.unwrap_or(0)));
        c.round_since_not_found = false;
        c.pending = false;
        c.pass = match c.pass {
            Pass::Asking { position, .. } => Pass::Asking {
                position,
                not_found: true,
            },
            Pass::Free | Pass::Waiting { .. } => Pass::Waiting { ready_at: None },
        };
    }

    /// A round of this side's range requests with the peer completed: a
    /// trigger, remembered whatever the pass is doing (R2-B1).
    pub(super) fn round_completed_for_chunks(&mut self, folder: FolderId, out: &mut Output) {
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.chunks.round_since_not_found = true;
        }
        self.trigger(folder, out);
    }

    /// A trigger may have fired for the folder: acted on now when the pass
    /// waits for one and one has fired, or, when a trigger was acted on less
    /// than `STATUS_INTERVAL` ago, kept in one pending bit and acted on when
    /// the interval has passed (coordinator ruling of 2026-10-22: deferred,
    /// never dropped). A trigger that fires while a pass is still asking is
    /// remembered and judged when the pass ends ([`Self::pass_done`]).
    fn trigger(&mut self, folder: FolderId, out: &mut Output) {
        let (now, interval) = (self.now, self.config.timing.status);
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let c = &mut x.chunks;
        if c.pass != (Pass::Waiting { ready_at: None }) || !c.triggered() {
            return;
        }
        if c.last_eval
            .is_some_and(|l| now < l.saturating_add(interval))
        {
            c.pending = true;
            return;
        }
        self.evaluate(folder, out);
    }

    /// Acts on a trigger that fired: the next pass starts no sooner than
    /// `CHUNK_BUSY_BACKOFF`'s minimum after the latest `CHUNK_NOT_FOUND`.
    fn evaluate(&mut self, folder: FolderId, out: &mut Output) {
        let (now, ready) = (self.now, self.config.timing.busy_backoff);
        let Some(x) = open_mut(&mut self.folders, &folder) else {
            return;
        };
        let c = &mut x.chunks;
        c.pending = false;
        if c.pass != (Pass::Waiting { ready_at: None }) || !c.triggered() {
            return;
        }
        c.last_eval = Some(now);
        let allowed = c
            .latest_not_found
            .map_or(now, |(at, _)| at.saturating_add(ready));
        if now >= allowed {
            c.pass = Pass::Free;
            out.events.push(Event::PassAllowed { folder });
        } else {
            c.pass = Pass::Waiting {
                ready_at: Some(allowed),
            };
        }
    }

    pub(super) fn chunks_wake(&self) -> Option<Duration> {
        let interval = self.config.timing.status;
        let folders = self
            .folders
            .values()
            .filter_map(|f| f.open.as_ref())
            .flat_map(|x| {
                let c = &x.chunks;
                let ready = match c.pass {
                    Pass::Waiting { ready_at } => ready_at,
                    Pass::Free | Pass::Asking { .. } => None,
                };
                let pending = c
                    .last_eval
                    .filter(|_| c.pending)
                    .map(|l| l.saturating_add(interval));
                [ready, pending]
            });
        folders.chain([self.chunks.announce_at]).flatten().min()
    }

    pub(super) fn wake_chunks(&mut self, out: &mut Output) {
        let now = self.now;
        if self.chunks.announce_at.is_some_and(|a| now >= a) {
            self.chunks.announce_at = None;
            out.events.push(Event::ChunksAllowed);
        }
        let interval = self.config.timing.status;
        let folders: Vec<FolderId> = self.open_folders().copied().collect();
        for folder in folders {
            let Some(x) = open_mut(&mut self.folders, &folder) else {
                continue;
            };
            let c = &mut x.chunks;
            if let Pass::Waiting { ready_at: Some(r) } = c.pass {
                if now >= r {
                    c.pass = Pass::Free;
                    out.events.push(Event::PassAllowed { folder });
                }
                continue;
            }
            if c.pending
                && c.last_eval
                    .is_none_or(|l| now >= l.saturating_add(interval))
            {
                self.evaluate(folder, out);
            }
        }
    }

    /// The engine stored a chunk of `folder` (from any connection): the
    /// folder's `chunks_stored` here grows by one, and a Status for it falls
    /// due at most once per `STATUS_CHUNKS_INTERVAL`, the first change
    /// opening the window, so that many chunks stored within it are reported
    /// by one Status (4.5).
    pub fn chunk_stored(&mut self, tick: Tick, folder: FolderId) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let (now, gap) = (self.now, self.config.timing.status_chunks);
        if let Some(x) = open_mut(&mut self.folders, &folder) {
            x.chunks.stored = x.chunks.stored.saturating_add(1);
            if self.status_chunks_due.is_none() {
                let after_last = self.last_status_sent.map_or(now, |l| l.saturating_add(gap));
                self.status_chunks_due = Some(now.saturating_add(gap).max(after_last));
            }
        }
        self.finish(&mut out);
        out
    }

    pub(super) fn status_wake(&self) -> Option<Duration> {
        [self.next_status, self.status_chunks_due]
            .into_iter()
            .flatten()
            .min()
    }

    pub(super) fn wake_status(&mut self, out: &mut Output) {
        let now = self.now;
        let mut due = false;
        if self.next_status.is_some_and(|n| now >= n) {
            self.next_status = Some(now.saturating_add(self.config.timing.status));
            due = true;
        }
        if self.status_chunks_due.is_some_and(|d| now >= d) {
            self.status_chunks_due = None;
            due = true;
        }
        if due {
            out.events.push(Event::StatusDue);
        }
    }

    /// Sends a Status ([`Event::StatusDue`]) with one entry per folder in
    /// `folders`, each open here; the connection sets each entry's
    /// `chunks_stored` (its own count) and the device name, in the first
    /// Status after the first open and whenever the name changed. A Status
    /// never waits behind other frames: with no room it is refused, and the
    /// engine skips it (the next is due within `STATUS_INTERVAL`).
    ///
    /// # Errors
    /// [`SendError::WouldBlock`], [`SendError::FolderNotOpen`] (a folder not
    /// open, or none opened yet), [`SendError::Malformed`] for more entries
    /// than a Status holds, [`SendError::TooLarge`], or the connection's
    /// state.
    pub fn send_status(
        &mut self,
        tick: Tick,
        folders: &[FolderStatus],
    ) -> Result<Output, SendError> {
        self.established()?;
        if !self.opened_any {
            return Err(SendError::FolderNotOpen);
        }
        if folders.len() > MAX_STATUS_FOLDERS {
            return Err(SendError::Malformed);
        }
        let mut entries = Vec::with_capacity(folders.len());
        for f in folders {
            let id = FolderId::from_slice(&f.folder_id).ok_or(SendError::FolderNotOpen)?;
            let x = self
                .folders
                .get(&id)
                .and_then(|s| s.open.as_ref())
                .ok_or(SendError::FolderNotOpen)?;
            entries.push(FolderStatus {
                chunks_stored: x.chunks.stored,
                ..f.clone()
            });
        }
        let name = (self.name_sent.as_deref() != Some(self.config.device_name.as_str()))
            .then(|| self.config.device_name.clone());
        let frame = self.frame_for(&Message::Status(Status {
            folders: entries,
            device_name: name.clone().unwrap_or_default(),
        }))?;
        if !self.has_room(tick, frame.len()) {
            return Err(SendError::WouldBlock { len: frame.len() });
        }
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if name.is_some() {
            self.name_sent = name;
        }
        self.last_status_sent = Some(self.now);
        self.status_chunks_due = None;
        self.enqueue(frame, Tag::None, &mut out);
        self.finish(&mut out);
        Ok(out)
    }

    /// The peer's Status: only once a folder is open, naming open folders
    /// only; the latest `chunks_stored` per folder feeds the chunk passes.
    pub(super) fn on_status(&mut self, m: Status, out: &mut Output) {
        let mut folders = Vec::with_capacity(m.folders.len());
        for f in &m.folders {
            match FolderId::from_slice(&f.folder_id) {
                Some(id) if self.is_open(&id) => folders.push(id),
                _ => return self.fail(Cause::Malformed, out),
            }
        }
        if !self.opened_any {
            return self.fail(Cause::Malformed, out);
        }
        for (id, f) in folders.iter().zip(&m.folders) {
            if let Some(x) = open_mut(&mut self.folders, id) {
                x.chunks.peer_stored = Some(f.chunks_stored);
            }
            self.trigger(*id, out);
        }
        if !m.device_name.is_empty() {
            out.events.push(Event::PeerNamed {
                device_name: m.device_name,
            });
        }
        out.events.push(Event::PeerStatus { folders: m.folders });
    }
}
