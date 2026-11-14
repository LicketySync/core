// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! [`Engine`]: the runtime's [`Peer`], one protocol [`Connection`] per peer,
//! one index per folder, and the three phases every handler runs in
//! ([`crate::work`]).
//!
//! # Driving a connection
//!
//! Each call to a [`Connection`] takes a fresh [`Tick`] (the monotonic time,
//! and `Transport::unsent`, which changes as the engine sends), and its
//! [`Output`] is applied in order ([`Engine::apply`]): the frames go to the
//! transport, the wake-up arms or cancels the connection's timer, the events
//! join the handler's queue and are reacted to in order, the reactions' own
//! outputs included, and a close hangs up the transport. Once a connection is
//! closed the engine records its `Closed` outcome and does nothing more on it
//! (the protocol test kit's rule). The protocol owns the 1 s Close flush
//! through its wake-up.
//!
//! # Timers
//!
//! Timer ids below 2^63 are the engine's ([`crate::timers`]); ids of 2^63 and
//! up belong to the harness that wraps the engine, and the engine ignores one
//! that fires.

use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::device::{DeviceKey, Libp2pIdentity};
use licketysync_keys::{CipherHash, DeviceId, FolderId, FolderKey};
use licketysync_protocol::connection::{Config, Connection, Event, Keys, Output, Side, Tick};
use licketysync_protocol::limits::MAX_OPEN_FOLDERS_PER_CONNECTION;
use licketysync_protocol::proof::FolderCredential;
use licketysync_protocol::{Cause, CloseReason, Report};

use crate::config::{self, ConfigError, EngineConfig, Settings};
use crate::conn::Conn;
use crate::folder::FolderState;
use crate::inflight::{patience, InFlight};
use crate::issues::{bump, Counters, Issue, IssueKind, Issues, Subject};
use crate::runtime::{Context, Instant, Peer, PeerId, TimerId};
use crate::timers::{Purpose, TimerTable};
use crate::work::{pop, Work};

/// The sync engine of one device (the crate documentation).
pub struct Engine {
    pub(crate) device: DeviceKey,
    pub(crate) own: DeviceId,
    libp2p: [u8; 32],
    pub(crate) settings: Settings,
    /// The folder keys of the config, until `on_start` opens them.
    pub(crate) to_open: Vec<FolderKey>,
    pub(crate) folders: BTreeMap<FolderId, crate::folder::Folder>,
    /// One credential per folder proven to peers: opened and not
    /// misconfigured.
    pub(crate) credentials: Vec<FolderCredential>,
    pub(crate) conns: BTreeMap<PeerId, Conn>,
    pub(crate) timers: TimerTable,
    /// Chunk requests outstanding, on which connections, since when
    /// (`crate::inflight`).
    pub(crate) in_flight: InFlight,
    /// When the chunk patience timer is armed for; once that instant is not
    /// after `now`, the timer is due and is left to fire.
    patience_at: Option<Instant>,
    /// Index work that phase C brought, waiting for the next commit
    /// (`crate::sync`), which a handler of its own makes at once. Bounded by
    /// one handler's phase C: at most a round's end per connection and
    /// folder, and one cursor per counted push page it judged.
    pub(crate) deferred: BTreeMap<FolderId, Vec<crate::sync::Op>>,
    /// Stored blobs found changed at rest, whose deletion (with their
    /// markers) rides the next commit (the `work` module). Bounded by the
    /// folders' stored chunks.
    pub(crate) forget: BTreeSet<(FolderId, CipherHash)>,
    pub(crate) issues: Issues,
    pub(crate) counters: Counters,
    /// Every reset served, with whether it claimed a redraw, for the test
    /// that a folder held paused claims none.
    #[cfg(test)]
    pub(crate) resets_log: Vec<(FolderId, bool)>,
    /// Every page's judgements as handed to its connection, for the tests
    /// of what a failed commit reports.
    #[cfg(test)]
    pub(crate) judged_log: Vec<(
        FolderId,
        Vec<Result<licketysync_protocol::connection::Judgement, licketysync_protocol::Cause>>,
    )>,
}

/// Prints the device ID, the folders (their IDs, tiers and state) and counts;
/// no secret and no path. Folder IDs are not secret, but the daemon's logging
/// redacts them by default before any of this reaches a log (TM-6).
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("device", &self.own)
            .field("folders", &self.folders)
            .field("connections", &self.conns.len())
            .field("issues", &self.issues.list().len())
            .finish_non_exhaustive()
    }
}

/// The tick a connection call takes now.
pub(crate) fn tick(cx: &dyn Context, peer: PeerId) -> Tick {
    Tick {
        now: Duration::from_nanos(cx.now().as_nanos()),
        unsent: cx.unsent(peer),
    }
}

/// How often the chunk frees of a folder open on no connection run
/// (`protocol.md` 4.7 item 1: once a minute).
const FREE_TICK: Duration = Duration::from_secs(60);

/// This device's wall clock in whole days since the Unix epoch, for the
/// Hello's `clock_days` (3.2): at most 2^21 − 1.
fn clock_days(cx: &dyn Context) -> u32 {
    u32::try_from(cx.wall_time() / 86_400)
        .unwrap_or(u32::MAX)
        .min((1 << 21) - 1)
}

/// A connection's deadline as an instant of the runtime's clock.
fn instant(d: Duration) -> Instant {
    Instant::from_nanos(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

impl Engine {
    /// An engine for `config`, not yet started: the runtime calls
    /// [`Peer::on_start`] next, which opens every folder.
    ///
    /// # Errors
    /// [`ConfigError`] for a config that could not run.
    pub fn new(config: EngineConfig) -> Result<Self, ConfigError> {
        let settings = config::check(&config)?;
        let device = DeviceKey::from_device_seed(&config.device_seed);
        let libp2p = Libp2pIdentity::from_device_seed(&config.device_seed).public_key();
        let own = device.device_id();
        let EngineConfig { folders, .. } = config;
        Ok(Self {
            device,
            own,
            libp2p,
            settings,
            to_open: folders,
            folders: BTreeMap::new(),
            credentials: Vec::new(),
            conns: BTreeMap::new(),
            timers: TimerTable::new(),
            in_flight: InFlight::default(),
            patience_at: None,
            deferred: BTreeMap::new(),
            forget: BTreeSet::new(),
            issues: Issues::default(),
            counters: Counters::default(),
            #[cfg(test)]
            resets_log: Vec::new(),
            #[cfg(test)]
            judged_log: Vec::new(),
        })
    }

    /// This device's ID.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.own
    }

    /// The Issues list.
    #[must_use]
    pub const fn issues(&self) -> &Issues {
        &self.issues
    }

    /// The log counters.
    #[must_use]
    pub const fn counters(&self) -> &Counters {
        &self.counters
    }

    /// The peers the engine has a connection to, as it knows them.
    pub fn connections(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.conns.keys().copied()
    }

    /// The protocol configuration every connection starts from.
    fn connection_config(&self, cx: &dyn Context) -> Config {
        let mut c = Config::new(self.libp2p, clock_days(cx));
        c.device_name.clone_from(&self.settings.device_name);
        c.max_message_size = self.settings.max_message_size;
        c.max_requests_in_flight = self.settings.max_requests_in_flight;
        c.max_records = self.settings.max_records;
        c.timing = self.settings.timing;
        c
    }

    /// Runs one handler's three phases around `decide` (the `work` module):
    /// A in `decide` and the reactions to its events, B the commit, then the
    /// chunk state brought up to date and C, and last the folders' states.
    pub(crate) fn run<R>(
        &mut self,
        cx: &mut dyn Context,
        decide: impl FnOnce(&mut Self, &mut dyn Context, &mut Work) -> R,
    ) -> (R, Work) {
        let mut work = Work::default();
        // The clock rule's check, every handler (`pause`).
        self.opens_at(cx, &mut work);
        let result = decide(self, cx, &mut work);
        self.react_all(cx, &mut work);
        self.commit(cx, &mut work);
        self.refresh_chunks(cx, &mut work);
        self.send(cx, &mut work);
        self.settle_states(cx);
        (result, work)
    }

    /// Applies one connection call's output, in order: frames, wake-up,
    /// events (queued), close.
    pub(crate) fn apply(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        out: Output,
    ) {
        let Output {
            frames,
            events,
            wake_at,
            close,
        } = out;
        let hung_up = self.conns.get(&peer).is_none_or(|c| c.hung_up);
        if !hung_up {
            for frame in frames {
                // A connection the engine believes open refuses no send.
                if cx.send(peer, frame).is_err() {
                    self.counters.bug();
                }
            }
        }
        match wake_at {
            Some(d) => {
                if !self.timers.arm(cx, Purpose::Wake(peer), instant(d)) {
                    self.counters.bug();
                }
            }
            None => self.timers.cancel(cx, Purpose::Wake(peer)),
        }
        work.events.extend(events.into_iter().map(|e| (peer, e)));
        if close && !hung_up {
            cx.close(peer);
            if let Some(c) = self.conns.get_mut(&peer) {
                c.hung_up = true;
            }
        }
    }

    /// Phase A's reactions, and C's: every queued event in order.
    pub(crate) fn react_all(&mut self, cx: &mut dyn Context, work: &mut Work) {
        while let Some((peer, event)) = work.events.pop_front() {
            self.react(cx, work, peer, event);
        }
    }

    fn react(&mut self, cx: &mut dyn Context, work: &mut Work, peer: PeerId, event: Event) {
        if let Event::Closed {
            reason, by, cause, ..
        } = event
        {
            self.closed(work, peer, reason, by, cause);
            return;
        }
        if let Event::ClockOutOfRange { .. } | Event::StrangerClockOutOfRange { .. } = event {
            // The clock rule's events come in the output that closes the
            // connection, so they are taken whatever its state.
            let _ = self.sync_event(work, peer, event);
            return;
        }
        if !self.conns.get(&peer).is_some_and(Conn::reacts) {
            return;
        }
        // The index exchange's events go to `sync`.
        let Some(event) = self.sync_event(work, peer, event) else {
            return;
        };
        if let Event::FolderOpened { folder, .. } = &event {
            // A folder held paused is held so on every connection where it
            // opens (the `pause` module).
            if self
                .folders
                .get(folder)
                .is_some_and(crate::folder::Folder::held_paused)
            {
                let folder = *folder;
                if let Some(out) = self.with_conn(cx, peer, |c, t| c.set_paused(t, folder, true)) {
                    self.apply(cx, work, peer, out);
                }
            }
        }
        let Some(c) = self.conns.get_mut(&peer) else {
            return;
        };
        match event {
            Event::Authenticated { device_id, .. } => c.device = Some(device_id),
            Event::FolderOpened { folder, .. } => {
                c.open.insert(folder);
                work.passes.insert(folder);
            }
            Event::ChunkRequested {
                folder,
                cipher_hash,
            } => {
                c.chunk_requests.push_back((folder, cipher_hash));
                work.pump.insert(peer);
            }
            Event::ChunksAllowed => work.passes.extend(c.open.iter().copied()),
            Event::Chunk {
                folder,
                cipher_hash,
                data,
            } => self.on_chunk(cx, work, folder, peer, cipher_hash, &data),
            other => self.react_quietly(work, peer, &other),
        }
    }

    /// The events that only count, queue or note something.
    fn react_quietly(&mut self, work: &mut Work, peer: PeerId, event: &Event) {
        match event {
            Event::ProofRejected { folder } => {
                bump(&mut self.counters.proofs_rejected);
                self.counters.log(Cause::FolderProofRejected);
                // With 64 folders open here a refusal is possibly the open
                // limit's (`config::MAX_FOLDERS`): REJECTED is uniform by
                // design, so the peer may hold no key of the folder either.
                // Counted and named, with the cause left open.
                let full = self
                    .conns
                    .get(&peer)
                    .is_some_and(|c| c.open.len() >= MAX_OPEN_FOLDERS_PER_CONNECTION);
                if full {
                    bump(&mut self.counters.open_limit_refusals);
                    self.issues.raise(Issue {
                        folder: Some(*folder),
                        kind: IssueKind::OpenLimit,
                        subject: Subject::None,
                    });
                }
            }
            Event::ChunkNotFound {
                folder,
                cipher_hash,
            } => self.chunk_refused(work, peer, *folder, *cipher_hash, Cause::ChunkNotFound),
            Event::ChunkBusy {
                folder,
                cipher_hash,
            } => self.chunk_refused(work, peer, *folder, *cipher_hash, Cause::ChunkBusy),
            Event::PassAllowed { folder } => {
                work.passes.insert(*folder);
            }
            Event::StatusDue => {
                work.status.insert(peer);
            }
            Event::Room => {
                work.pump.insert(peer);
            }
            Event::PeerUnsupported { .. } => bump(&mut self.counters.unsupported),
            Event::Ignored { .. } => {
                bump(&mut self.counters.unsupported);
                self.counters.log(Cause::UnknownNonCriticalType);
            }
            // A peer's Status and name are advisory: shown as reported, never
            // relied on (TM-20); phase 0 keeps nothing of them.
            _ => {}
        }
    }

    /// A connection's end as the protocol reports it: an issue naming the
    /// peer for a close this side made for the peer's fault, a log line for
    /// everything else (`Cause::report`, section 5; TM-10). Its tables go
    /// now: nothing more is sent on it.
    fn closed(
        &mut self,
        work: &mut Work,
        peer: PeerId,
        reason: CloseReason,
        by: Side,
        cause: Option<Cause>,
    ) {
        let Some(c) = self.conns.get_mut(&peer) else {
            return;
        };
        if c.closed_noted {
            return;
        }
        c.closed_noted = true;
        c.sync.clear();
        c.chunk_requests.clear();
        work.passes.extend(c.open.iter().copied());
        let device = c.device;
        // A peer counts as proven once it proved a key of a folder this
        // device holds, not for its device ID alone (the Issues list, TM-22).
        let holder = !c.open.is_empty();
        self.in_flight.forget_peer(peer);
        self.counters.close(by == Side::Local, reason);
        let (Side::Local, Some(cause)) = (by, cause) else {
            return;
        };
        self.counters.log(cause);
        if cause.report() == Report::IssueNamingPeer {
            self.issues.raise(Issue {
                folder: None,
                kind: IssueKind::PeerFault(cause),
                subject: Subject::Peer {
                    peer,
                    device,
                    holder,
                },
            });
        }
    }

    /// Phase C: everything that carries a record or a chunk, after the
    /// commit, then whatever the outputs of those calls bring.
    fn send(&mut self, cx: &mut dyn Context, work: &mut Work) {
        self.send_records(cx, work);
        loop {
            self.react_all(cx, work);
            if self.send_next_sync(cx, work) {
                continue;
            }
            if let Some(peer) = pop(&mut work.status) {
                self.send_status(cx, work, peer);
            } else if let Some(peer) = pop(&mut work.pump) {
                self.pump(cx, work, peer);
            } else if let Some((folder, n)) = work.chunks_stored.pop_first() {
                self.notify_stored(cx, work, folder, n);
            } else if let Some(folder) = pop(&mut work.passes) {
                self.drive_passes(cx, work, folder);
            } else {
                break;
            }
        }
    }

    /// The peers where `folder` is open and the engine still acts.
    pub(crate) fn open_on(&self, folder: &FolderId) -> Vec<PeerId> {
        self.conns
            .iter()
            .filter(|(_, c)| c.has_open(folder))
            .map(|(p, _)| *p)
            .collect()
    }

    /// Brings every folder's state word up to date and keeps the timers
    /// armed that the folders' state needs: the resume probe while a folder
    /// is paused, the deferred commit while phase C left index work, the
    /// free tick while chunks wait to be freed or re-read, and the chunk
    /// patience. A patience timer that is due is left armed: a handler that
    /// runs at or after its deadline before it fires (a message, or another
    /// timer due at that instant) would find its expiry left out of
    /// `next_expiry`, and moving or cancelling the timer then would skip the
    /// passes it drives. Once it fires the timer is armed only after `now`,
    /// so it never fires twice at one instant (TM-22).
    fn settle_states(&mut self, cx: &mut dyn Context) {
        let now = cx.now();
        let ids: Vec<FolderId> = self.folders.keys().copied().collect();
        for id in ids {
            let state = self.state_of(&id);
            if let Some(f) = self.folders.get_mut(&id) {
                f.set_state(now, state);
            }
        }
        let mut arm = |cx: &mut dyn Context, purpose, at| {
            if !self.timers.arm_once(cx, purpose, at) {
                self.counters.bug();
            }
        };
        if self.folders.values().any(|f| f.paused.is_some()) {
            arm(
                cx,
                Purpose::ResumeProbe,
                now.saturating_add(self.settings.resume_probe),
            );
        }
        if !self.deferred.is_empty() {
            arm(cx, Purpose::Deferred, now);
        }
        if self
            .folders
            .values()
            .any(|f| !f.pending_free.is_empty() || f.book.has_unread())
        {
            arm(cx, Purpose::FreeTick, now.saturating_add(FREE_TICK));
        }
        let next = self
            .in_flight
            .next_expiry(patience(&self.settings.timing), now);
        let due = self.patience_at.is_some_and(|at| at <= now);
        if !due && next != self.patience_at {
            match next {
                Some(at) => {
                    if !self.timers.arm(cx, Purpose::ChunkPatience, at) {
                        self.counters.bug();
                    }
                }
                None => self.timers.cancel(cx, Purpose::ChunkPatience),
            }
            self.patience_at = next;
        }
    }

    /// The state a folder is in now (the `folder` module documentation).
    fn state_of(&self, id: &FolderId) -> FolderState {
        let Some(f) = self.folders.get(id) else {
            return FolderState::Unreadable;
        };
        match f.health {
            crate::folder::Health::Misconfigured {
                dropped,
                undecodable,
            } => {
                return FolderState::Misconfigured {
                    dropped,
                    undecodable,
                }
            }
            crate::folder::Health::Unreadable => return FolderState::Unreadable,
            crate::folder::Health::Usable => {}
        }
        if let Some(cause) = f.paused {
            return FolderState::Paused(cause);
        }
        if let Some(opens_at_us) = f.closed_until {
            return FolderState::Closed { opens_at_us };
        }
        let open: Vec<&Conn> = self.conns.values().filter(|c| c.has_open(id)).collect();
        let pending = open.iter().filter(|c| !c.sync.caught_up(id)).count();
        let lacking = f.book.lacking().len();
        if !open.is_empty() && pending == 0 && lacking == 0 {
            return FolderState::UpToDate;
        }
        FolderState::Syncing {
            lacking_chunks: lacking as u64,
            bytes_needed: f.book.bytes_needed(),
            rounds_pending: pending as u64,
            open_on: open.len() as u64,
        }
    }

    fn connect(&mut self, cx: &mut dyn Context, work: &mut Work, peer: PeerId) {
        let config = self.connection_config(cx);
        let t = tick(cx, peer);
        let made = Connection::new(
            &self.device,
            config,
            &mut |b: &mut [u8]| cx.fill_random(b),
            t,
        );
        let Ok((conn, out)) = made else {
            // The config was checked in `Engine::new`.
            self.counters.bug();
            return;
        };
        self.conns.insert(peer, Conn::new(conn));
        self.apply(cx, work, peer, out);
        let folders: Vec<FolderId> = self
            .credentials
            .iter()
            .map(FolderCredential::folder_id)
            .collect();
        for folder in folders {
            let Some(c) = self.conns.get_mut(&peer) else {
                return;
            };
            let keys = Keys {
                device: &self.device,
                folders: &self.credentials,
            };
            let t = tick(cx, peer);
            match c
                .protocol
                .prove(&keys, &mut |b: &mut [u8]| cx.fill_random(b), t, folder)
            {
                Ok(out) => self.apply(cx, work, peer, out),
                Err(_) => self.counters.bug(),
            }
        }
    }

    fn receive(&mut self, cx: &mut dyn Context, work: &mut Work, from: PeerId, bytes: &[u8]) {
        let Some(c) = self.conns.get_mut(&from) else {
            self.counters.bug();
            return;
        };
        if !c.reacts() {
            return;
        }
        let keys = Keys {
            device: &self.device,
            folders: &self.credentials,
        };
        let t = tick(cx, from);
        let out = c
            .protocol
            .receive(&keys, &mut |b: &mut [u8]| cx.fill_random(b), t, bytes);
        self.apply(cx, work, from, out);
    }

    fn timer(&mut self, cx: &mut dyn Context, work: &mut Work, purpose: Purpose) {
        match purpose {
            Purpose::Wake(peer) => {
                let t = tick(cx, peer);
                let Some(c) = self.conns.get_mut(&peer) else {
                    return;
                };
                let out = c.protocol.wake(t);
                self.apply(cx, work, peer, out);
            }
            Purpose::SendPoll(peer) => {
                work.pump.insert(peer);
            }
            Purpose::ResumeProbe => self.probe(cx, work),
            Purpose::ChunkPatience => {
                self.patience_at = None;
                work.passes.extend(self.folders.keys().copied());
            }
            // Phase B makes the commit the deferred work waits for.
            Purpose::Deferred => {}
            Purpose::OpensAt => self.opens_at(cx, work),
            Purpose::FreeTick => {
                self.reread_blobs(cx, work);
                let alone: Vec<FolderId> = self
                    .folders
                    .keys()
                    .filter(|id| self.open_on(id).is_empty())
                    .copied()
                    .collect();
                for id in alone {
                    if let Some(f) = self.folders.get_mut(&id) {
                        f.free_due |= !f.pending_free.is_empty();
                    }
                }
            }
        }
    }

    fn disconnect(&mut self, cx: &mut dyn Context, work: &mut Work, peer: PeerId) {
        // The transport dropped: the connection reports what ended with it
        // (a stranger's clock out of range is counted).
        let t = tick(cx, peer);
        if let Some(c) = self.conns.get_mut(&peer) {
            let out = c.protocol.disconnected(t);
            work.events
                .extend(out.events.into_iter().map(|e| (peer, e)));
            self.react_all(cx, work);
        }
        self.conns.remove(&peer);
        self.timers.forget_peer(cx, peer);
        self.in_flight.forget_peer(peer);
        work.passes.extend(self.folders.keys().copied());
    }

    fn stop(&mut self, cx: &mut dyn Context, work: &mut Work) {
        let peers: Vec<PeerId> = self.conns.keys().copied().collect();
        for peer in peers {
            let t = tick(cx, peer);
            let Some(c) = self.conns.get_mut(&peer) else {
                continue;
            };
            if !c.reacts() {
                continue;
            }
            let out = c.protocol.close(t, CloseReason::Shutdown);
            self.apply(cx, work, peer, out);
        }
    }

    /// Calls `f` on the connection to `peer` with a fresh tick, if the
    /// engine still acts on it.
    pub(crate) fn with_conn<R>(
        &mut self,
        cx: &dyn Context,
        peer: PeerId,
        f: impl FnOnce(&mut Connection, Tick) -> R,
    ) -> Option<R> {
        let t = tick(cx, peer);
        let c = self.conns.get_mut(&peer)?;
        if !c.reacts() {
            return None;
        }
        Some(f(&mut c.protocol, t))
    }
}

impl Peer for Engine {
    /// Opens every folder, each shown as Checking while its index checks
    /// every stored record (`protocol.md` 4.4, "Opening a folder").
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.run(cx, Self::open_folders);
    }

    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        self.run(cx, |e, cx, w| e.receive(cx, w, from, bytes));
    }

    /// Routes an engine timer; a harness id (2^63 and up) or an id this
    /// instance has forgotten is ignored.
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        let Some(purpose) = self.timers.fired(id) else {
            return;
        };
        self.run(cx, |e, cx, w| e.timer(cx, w, purpose));
    }

    /// Starts the connection (its Hello) and proves every folder that is
    /// credentialed; the proofs wait until the handshake has finished.
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.run(cx, |e, cx, w| e.connect(cx, w, peer));
    }

    /// Drops the connection and every table of it, cancels its timers, and
    /// drives the chunk passes on the other connections.
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.run(cx, |e, cx, w| e.disconnect(cx, w, peer));
    }

    /// Closes every connection with `SHUTDOWN`. Every handler committed as it
    /// went, so nothing is left to commit.
    fn on_stop(&mut self, cx: &mut dyn Context) {
        self.run(cx, Self::stop);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use core::time::Duration;

    use licketysync_protocol::frame::{Frame, FrameKind, MessageType};
    use licketysync_protocol::Cause;

    use crate::runtime::{Instant, PeerId, MAX_SEND_QUEUE};
    use crate::testkit::{config, folder_key, Hold, Net};
    use crate::tests::{folder, pair, write};
    use crate::FolderState;

    #[test]
    fn an_idle_engine_sets_no_timer_and_the_free_tick_only_while_chunks_wait() {
        // `settle_states`: the free tick is set while chunks wait to be
        // freed or read again (4.7 item 1: once a minute while the folder is
        // open on no connection), the deferred commit while phase C left
        // index work; an engine with nothing waiting sets no timer at all.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let idle = |net: &Net| net.nodes[0].cx.timers.is_empty();
        assert!(idle(&net), "{:?}", net.nodes[0].cx.timers);
        // A second version leaves the first one's chunks unnamed: listed to
        // be freed, on no connection.
        write(&mut net, 0, "a.bin", &[1u8; 3000]).unwrap();
        write(&mut net, 0, "a.bin", &[2u8; 3000]).unwrap();
        let listed = |net: &Net| {
            net.nodes[0]
                .engine
                .folder(&folder())
                .unwrap()
                .pending_free
                .len()
        };
        assert!(listed(&net) > 0);
        let in_a_minute = Instant::from_nanos(net.now).saturating_add(Duration::from_secs(60));
        assert!(
            net.nodes[0].cx.timers.values().any(|at| *at == in_a_minute),
            "the free tick, due in a minute: {:?}",
            net.nodes[0].cx.timers
        );
        net.advance(Duration::from_secs(61));
        assert_eq!(listed(&net), 0, "freed within the minute");
        assert!(idle(&net), "idle again: {:?}", net.nodes[0].cx.timers);
    }

    #[test]
    fn an_unknown_non_critical_type_is_answered_unsupported_once_then_ignored() {
        // Section 2, frames, step 4, and the section 5 table: a frame of an
        // unknown type with the critical bit clear is answered `Unsupported`
        // once per type per connection, and later frames of that type are
        // ignored with a log line; the connection continues. Each side
        // counts its part: the sender the `Unsupported` it heard, the
        // receiver the frame it ignored.
        let mut net = pair();
        let unknown = Frame::new(0x0123, vec![]).unwrap();
        assert_eq!(unknown.kind(), FrameKind::UnknownNonCritical(0x0123));
        for _ in 0..2 {
            net.nodes[1]
                .cx
                .outbox
                .entry(PeerId::new(0))
                .or_default()
                .extend(unknown.encode());
        }
        net.settle();
        let receiver = net.nodes[0].engine.counters();
        assert_eq!(receiver.unsupported, 1, "the second frame, ignored");
        assert_eq!(receiver.of(Cause::UnknownNonCriticalType), 1);
        let sender = net.nodes[1].engine.counters();
        assert_eq!(sender.unsupported, 1, "the one Unsupported answer");
        for (i, n) in net.nodes.iter().enumerate() {
            assert_eq!(n.engine.counters().blaming_closes(), 0, "node {i}");
            assert_eq!(
                n.engine.connections().count(),
                1,
                "node {i}: the connection stays"
            );
        }
    }

    #[test]
    fn a_chunk_that_waits_for_room_in_the_send_queue_goes_once_the_queue_drains() {
        // `Connection::want_room`: a `CHUNK_OK` the send queue has no room
        // for waits, and goes on `Event::Room` once the transport drains,
        // which the connection watches through its wake-ups. Node 0's
        // budget is past `MAX_SEND_QUEUE`, so the queue's room alone holds
        // the chunk back; its link stops draining at the first chunk it
        // sends, so the second waits.
        let mut zero = config(0, vec![folder_key(1, 1)]);
        zero.send_budget = usize::MAX;
        let mut net = Net::new(vec![zero, config(1, vec![folder_key(1, 1)])]);
        net.connect(0, 1);
        net.advance(Duration::from_secs(2));
        net.hold = Some(Hold::new(1, 0, MessageType::ChunkRequest));
        let content: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let hash = write(&mut net, 0, "room.bin", &content).unwrap();
        net.nodes[0]
            .cx
            .fill_on_send
            .insert(PeerId::new(1), MAX_SEND_QUEUE);
        net.release();
        let one = net.nodes[1].engine.folder(&folder()).unwrap();
        assert_eq!(
            (one.stored_chunks.len(), one.lacking.len()),
            (1, 1),
            "the first chunk went; the second waits for room"
        );
        let n = &mut net.nodes[0].cx;
        n.fill_on_send.clear();
        n.extra_unsent.clear();
        net.advance(Duration::from_secs(2));
        let n = &net.nodes[1];
        assert_eq!(
            n.engine.read_file(&n.cx.storage, &folder(), &hash),
            Ok(content)
        );
        assert_eq!(
            n.engine.folder(&folder()).unwrap().state,
            FolderState::UpToDate
        );
    }
}
