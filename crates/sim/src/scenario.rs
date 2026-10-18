// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Scenarios and the simulation they build: the discrete-event scheduler, the
//! fault schedule, the context handed to peers, and the outcome of a run.

use core::cmp::{Ordering, Reverse};
use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

use licketysync_engine::runtime::{
    Clock, Context, Entry, Instant, Peer, PeerId, Randomness, SendError, Storage, StorageError,
    TimerId, Timers, Transport, MAX_CHUNK,
};

use crate::network::{Links, NetworkConfig, Partition, Piece, Probability, Stream};
use crate::rng::SimRng;
use crate::storage::SimStorage;
use crate::trace::{DropReason, EventKind, StorageOp, Trace, TraceEvent};

/// Builds the peer with the given id, at the start and again after each restart.
pub type Factory<P> = Box<dyn Fn(PeerId) -> P>;

/// Decides whether the simulation has converged.
pub type Predicate<P> = Box<dyn Fn(&Sim<P>) -> bool>;

/// What every peer's wall clock reads at simulation time zero unless the
/// scenario says otherwise: 2026-01-01T00:00:00Z, as seconds since the Unix
/// epoch.
pub const DEFAULT_WALL_EPOCH: u64 = 1_767_225_600;

/// The event budget a scenario gets unless it asks for another: enough for
/// any run that settles, small enough that one that never settles (a handler
/// re-arming a past deadline, two peers answering each other forever at one
/// instant) stops in about a second.
pub const DEFAULT_MAX_EVENTS: u64 = 1_000_000;

/// How long a cleanly stopped peer's connections stay open so that what it
/// wrote, `on_stop` included, can still arrive (protocol spec, 4.2). A stream
/// that empties sooner ends then; what has not arrived by the end may be lost.
pub const STOP_FLUSH: Duration = Duration::from_secs(1);

/// The chance a cut takes all it can (up to `MAX_CHUNK`) as one piece rather
/// than a shorter one of seeded length.
const WHOLE_PIECE: Probability = Probability::from_per_million(500_000);

/// A fault the scenario injects at a simulation time. Every time here is
/// unskewed simulation time, not any peer's view of its clock; a window whose
/// `until` precedes its `from` is taken the other way round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The peer's process dies: no `on_stop`, memory and timers gone, staged
    /// writes lost, connections closed. Nothing until a `Restart`.
    Crash {
        /// Which peer.
        peer: PeerId,
        /// When.
        at: Instant,
    },
    /// The peer stops cleanly: `on_stop` runs first, then as a crash.
    Stop {
        /// Which peer.
        peer: PeerId,
        /// When.
        at: Instant,
    },
    /// A fresh peer instance starts over the surviving storage.
    Restart {
        /// Which peer.
        peer: PeerId,
        /// When.
        at: Instant,
    },
    /// The links the partition names are cut from `from` until `until`.
    Partition {
        /// Which links.
        partition: Partition,
        /// When the cut begins.
        from: Instant,
        /// When it heals.
        until: Instant,
    },
    /// The peer's disk refuses writes from `from` until `until`.
    DiskFull {
        /// Which peer.
        peer: PeerId,
        /// When the disk fills.
        from: Instant,
        /// When it has room again.
        until: Instant,
    },
    /// A connection between `a` and `b` opens at `at` if both run, no
    /// partition cuts them and none is open; a no-op otherwise. The way back
    /// after a peer hung up with `Transport::close`, which the simulator never
    /// undoes on its own (a partition ending or either side restarting also
    /// reconnects them).
    Reconnect {
        /// One end.
        a: PeerId,
        /// The other.
        b: PeerId,
        /// When.
        at: Instant,
    },
}

/// Everything a run needs, before it starts.
pub struct Scenario<P> {
    seed: u64,
    peers: u32,
    factory: Factory<P>,
    network: NetworkConfig,
    faults: Vec<Fault>,
    skews: BTreeMap<PeerId, Duration>,
    capacities: BTreeMap<PeerId, u64>,
    predicate: Predicate<P>,
    keep_last: usize,
    record_all: bool,
    wall_epoch: u64,
    max_events: u64,
}

impl<P: Peer> Scenario<P> {
    /// `peers` peers with ids `0..peers`, built by `factory`, over the default
    /// network, with no faults, no skew, unbounded disks, the default wall
    /// epoch and event budget, and a predicate that is always true (so
    /// "quiescent" means "nothing in flight").
    pub fn new(seed: u64, peers: u32, factory: impl Fn(PeerId) -> P + 'static) -> Self {
        Self {
            seed,
            peers,
            factory: Box::new(factory),
            network: NetworkConfig::default(),
            faults: Vec::new(),
            skews: BTreeMap::new(),
            capacities: BTreeMap::new(),
            predicate: Box::new(|_| true),
            keep_last: 64,
            record_all: false,
            wall_epoch: DEFAULT_WALL_EPOCH,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    /// The network's behaviour.
    #[must_use]
    pub fn network(mut self, network: NetworkConfig) -> Self {
        self.network = network;
        self
    }

    /// Adds a fault to the schedule.
    #[must_use]
    pub fn fault(mut self, fault: Fault) -> Self {
        self.faults.push(fault);
        self
    }

    /// Makes `peer`'s clocks read `by` ahead: its wall clock against the
    /// simulation's, and its monotonic clock against the start of each of its
    /// instances (every instance's clock starts afresh, at `by`). Relative skew
    /// is what matters; to put one peer behind the rest, put the rest ahead.
    #[must_use]
    pub fn clock_ahead(mut self, peer: PeerId, by: Duration) -> Self {
        self.skews.insert(peer, by);
        self
    }

    /// What every peer's wall clock reads at simulation time zero, in seconds
    /// since the Unix epoch (default [`DEFAULT_WALL_EPOCH`]). A peer's reading
    /// is this plus the whole seconds of its skewed instant.
    #[must_use]
    pub const fn wall_epoch(mut self, unix_secs: u64) -> Self {
        self.wall_epoch = unix_secs;
        self
    }

    /// Bounds `peer`'s disk to `bytes` of keys plus values.
    #[must_use]
    pub fn disk_capacity(mut self, peer: PeerId, bytes: u64) -> Self {
        self.capacities.insert(peer, bytes);
        self
    }

    /// The convergence predicate, evaluated over the running peers.
    #[must_use]
    pub fn converged_when(mut self, predicate: impl Fn(&Sim<P>) -> bool + 'static) -> Self {
        self.predicate = Box::new(predicate);
        self
    }

    /// How many of the most recent events the outcome reports (default 64).
    #[must_use]
    pub const fn keep_last(mut self, n: usize) -> Self {
        self.keep_last = n;
        self
    }

    /// Whether to keep every event, not only the hash and the tail.
    #[must_use]
    pub const fn record_trace(mut self, yes: bool) -> Self {
        self.record_all = yes;
        self
    }

    /// The most events a run may process (default [`DEFAULT_MAX_EVENTS`]).
    /// When the budget is spent the run stops where it is and its outcome says
    /// so, counted as not converged, so a peer that keeps the scheduler busy
    /// forever is reported with its seed instead of hanging the job.
    #[must_use]
    pub const fn max_events(mut self, n: u64) -> Self {
        self.max_events = n;
        self
    }

    /// Starts every peer at time zero, connects each pair, schedules the
    /// faults and returns the simulation ready to run.
    #[must_use]
    pub fn build(self) -> Sim<P> {
        let mut sim = Sim {
            seed: self.seed,
            now: Instant::ZERO,
            rng: SimRng::from_seed(self.seed),
            seq: 0,
            timer_generation: 0,
            queue: BinaryHeap::new(),
            nodes: BTreeMap::new(),
            factory: self.factory,
            network: self.network,
            links: Links::default(),
            predicate: self.predicate,
            trace: Trace::new(self.keep_last, self.record_all),
            in_flight: 0,
            pending_faults: 0,
            processed: 0,
            partitions: 0,
            wall_epoch: self.wall_epoch,
            max_events: self.max_events,
            exhausted: false,
            notices: VecDeque::new(),
            next_piece: 0,
            stats: NetStats::default(),
        };
        for i in 0..self.peers {
            let id = PeerId::new(u64::from(i));
            let mut storage = SimStorage::new();
            storage.set_capacity(self.capacities.get(&id).copied());
            sim.nodes.insert(
                id,
                Node {
                    peer: None,
                    storage,
                    skew: self.skews.get(&id).copied().unwrap_or(Duration::ZERO),
                    timers: BTreeMap::new(),
                    heard: BTreeSet::new(),
                    origin: Instant::ZERO,
                },
            );
        }
        for fault in self.faults {
            sim.schedule_fault(fault);
        }
        let ids: Vec<PeerId> = sim.nodes.keys().copied().collect();
        for id in &ids {
            sim.start_peer(*id);
        }
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                sim.connect(*a, *b);
            }
        }
        sim
    }
}

/// A peer's slot: the running instance, if any, and what outlives it.
struct Node<P> {
    peer: Option<P>,
    storage: SimStorage,
    skew: Duration,
    /// The generation each armed timer was armed with; a scheduled firing
    /// carrying any other generation is stale and ignored. Generations come
    /// from one counter for the whole run that is never reset, so a firing
    /// queued before a cancel, a re-arm or a crash can never match a later arm.
    timers: BTreeMap<TimerId, u64>,
    /// The peers this instance has heard `on_connected` for and not yet
    /// `on_disconnected`: what its context reports as connected. It lags the
    /// network while a notice of a close is on its way (see [`Sim::settle`]),
    /// so a send in that window is accepted, as the transport contract says it
    /// must be, and may be lost.
    heard: BTreeSet<PeerId>,
    /// Simulation time when the running instance started: its monotonic
    /// clock reads the time since, plus the skew, so no `Instant` survives a
    /// restart.
    origin: Instant,
}

/// A notice owed to `to` that its connection to `about` ended, with the bytes
/// of `about`'s stream that still reach it first (the prefix chosen when the
/// connection ended).
struct Notice {
    to: PeerId,
    about: PeerId,
    chunks: VecDeque<Vec<u8>>,
}

/// Why a connection ended, which decides who may still receive what was in
/// flight. The first peer named in [`Sim::end_connection`] is the one the
/// cause belongs to: the one that hung up, sent the lost piece or the write
/// past the bound, or went down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// It hung up: it receives nothing more; the other side may.
    HangUp,
    /// Its piece was lost: the other side receives nothing more of its
    /// stream (the prefix ended there); it may still receive.
    Drop,
    /// A partition cut them: both may.
    Partition,
    /// Its write passed the queue bound: both may.
    Overflow,
    /// It crashed: the other side may.
    Crash,
    /// It stopped cleanly and its stream drained, ran out of time or was cut
    /// by its restart: the other side may.
    Stop,
}

/// What the network did over a run, for activity floors: a run in which
/// nothing happens checks nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    /// Connections opened.
    pub opened: u64,
    /// Connections ended by a peer's `Transport::close`.
    pub hung_up: u64,
    /// Connections ended by a lost piece.
    pub dropped: u64,
    /// Connections ended by a partition starting.
    pub partitioned: u64,
    /// Connections ended because a write passed the send-queue bound.
    pub overflowed: u64,
    /// Connections ended by a crash of one end.
    pub crashed: u64,
    /// Connections ended by a clean stop of one end: at once when nothing it
    /// wrote was still on its way, otherwise once its stream drained,
    /// [`STOP_FLUSH`] ran out or it restarted.
    pub stopped: u64,
    /// Crashes and clean stops of a peer that had a connection open: some
    /// live peer was going to hear of them.
    pub downs_heard: u64,
    /// Chunks handed to `on_message` while their connection lasted.
    pub chunks: u64,
    /// Pieces handed over after their connection had ended, just before the
    /// receiver's `on_disconnected`.
    pub delivered_at_close: u64,
    /// Pieces lost because their connection ended.
    pub lost_at_close: u64,
}

impl NetStats {
    /// Adds `other`'s counts to these.
    pub fn absorb(&mut self, other: &Self) {
        for (mine, theirs) in [
            (&mut self.opened, other.opened),
            (&mut self.hung_up, other.hung_up),
            (&mut self.dropped, other.dropped),
            (&mut self.partitioned, other.partitioned),
            (&mut self.overflowed, other.overflowed),
            (&mut self.crashed, other.crashed),
            (&mut self.stopped, other.stopped),
            (&mut self.downs_heard, other.downs_heard),
            (&mut self.chunks, other.chunks),
            (&mut self.delivered_at_close, other.delivered_at_close),
            (&mut self.lost_at_close, other.lost_at_close),
        ] {
            *mine = mine.saturating_add(theirs);
        }
    }
}

impl fmt::Display for NetStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} connections opened; ended by {} hang-ups, {} drops, {} partition cuts, \
             {} overflows, {} crashes, {} stops; {} downs heard; {} chunks; at a close \
             {} pieces delivered and {} lost",
            self.opened,
            self.hung_up,
            self.dropped,
            self.partitioned,
            self.overflowed,
            self.crashed,
            self.stopped,
            self.downs_heard,
            self.chunks,
            self.delivered_at_close,
            self.lost_at_close
        )
    }
}

enum Event {
    /// The end of the instant at which `from` wrote to `to`: what it wrote is
    /// cut into pieces and sent on their way, if that connection (epoch) is
    /// still open.
    Cut {
        from: PeerId,
        to: PeerId,
        epoch: u64,
    },
    /// Piece `piece` of `from -> to` arrives (or, if it is the lost one, takes
    /// the connection down), if that connection is still open; a piece of an
    /// ended connection was dealt with when it ended.
    Arrive {
        from: PeerId,
        to: PeerId,
        epoch: u64,
        piece: u64,
    },
    Timer {
        peer: PeerId,
        id: TimerId,
        generation: u64,
    },
    Fault(FaultEvent),
}

enum FaultEvent {
    Crash(PeerId),
    Stop(PeerId),
    Restart(PeerId),
    PartitionStart(u64, Partition),
    PartitionEnd(u64),
    DiskFull(PeerId),
    DiskFreed(PeerId),
    /// From a `Fault::Reconnect`.
    Reconnect(PeerId, PeerId),
    /// The network's own reconnection after a drop, carrying the epoch the
    /// drop left: if a connection between the pair has opened and closed
    /// since, the epoch has moved and this does nothing (and while one is
    /// open, connecting does nothing either). A hang-up when no connection is
    /// open moves no epoch, so it does not cancel this.
    NetReconnect(PeerId, PeerId, u64),
    /// [`STOP_FLUSH`] after a clean stop: if the stopped peer's stream to the
    /// other is still draining on that connection (epoch), it ends now.
    DrainDeadline(PeerId, PeerId, u64),
}

/// A queue entry, ordered by time and then by creation order, so that two
/// events at the same instant always run in the order they were scheduled.
struct Scheduled {
    time: Instant,
    seq: u64,
    event: Event,
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        (self.time, self.seq) == (other.time, other.seq)
    }
}

impl Eq for Scheduled {}

impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.time, self.seq).cmp(&(other.time, other.seq))
    }
}

/// What a handler asked of the network and the timers, applied in order after
/// it returns; storage calls take effect at once (the handler reads its own
/// writes) and leave only a trace entry here, in its place among the rest.
enum Effect {
    Send { to: PeerId, bytes: Vec<u8> },
    Close(PeerId),
    SetTimer { id: TimerId, at: Instant },
    CancelTimer(TimerId),
    Trace(EventKind),
}

/// A handler call.
#[derive(Clone, Copy)]
enum Call<'a> {
    Start,
    Message(PeerId, &'a [u8]),
    Timer(TimerId),
    Connected(PeerId),
    Disconnected(PeerId),
    Stop,
}

/// The storage a handler sees: the peer's store, with every call recorded in
/// order among the handler's other effects.
struct Effects<'a> {
    storage: &'a mut SimStorage,
    list: Vec<Effect>,
}

impl Storage for Effects<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.storage.get(key)
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError> {
        self.storage.scan(prefix)
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let result = self.storage.put(key, value);
        self.list.push(Effect::Trace(match &result {
            Ok(()) => EventKind::Put {
                key: key.to_vec(),
                len: value.len(),
            },
            Err(e) => EventKind::StorageFailed {
                op: StorageOp::Put,
                error: e.to_string(),
            },
        }));
        result
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StorageError> {
        let result = self.storage.delete(key);
        self.list.push(Effect::Trace(match &result {
            Ok(()) => EventKind::Delete { key: key.to_vec() },
            Err(e) => EventKind::StorageFailed {
                op: StorageOp::Delete,
                error: e.to_string(),
            },
        }));
        result
    }

    fn commit(&mut self) -> Result<(), StorageError> {
        let result = self.storage.commit();
        self.list.push(Effect::Trace(match &result {
            Ok(()) => EventKind::Commit,
            Err(e) => EventKind::StorageFailed {
                op: StorageOp::Commit,
                error: e.to_string(),
            },
        }));
        result
    }

    fn rollback(&mut self) {
        self.storage.rollback();
        self.list.push(Effect::Trace(EventKind::Rollback));
    }
}

/// The context of one handler call.
struct SimContext<'a> {
    now: Instant,
    wall: u64,
    local: PeerId,
    connected: BTreeSet<PeerId>,
    /// Bytes written and not yet handed to the network, per connected peer,
    /// this handler's own writes included.
    unsent: BTreeMap<PeerId, usize>,
    rng: &'a mut SimRng,
    fx: Effects<'a>,
}

impl Clock for SimContext<'_> {
    fn now(&self) -> Instant {
        self.now
    }

    fn wall_time(&self) -> u64 {
        self.wall
    }
}

impl Timers for SimContext<'_> {
    fn set_timer(&mut self, id: TimerId, at: Instant) {
        self.fx.list.push(Effect::SetTimer { id, at });
    }

    fn cancel_timer(&mut self, id: TimerId) {
        self.fx.list.push(Effect::CancelTimer(id));
    }
}

impl Transport for SimContext<'_> {
    fn local_id(&self) -> PeerId {
        self.local
    }

    fn send(&mut self, to: PeerId, bytes: Vec<u8>) -> Result<(), SendError> {
        if self.connected.contains(&to) {
            let queued = self.unsent.entry(to).or_insert(0);
            *queued = queued.saturating_add(bytes.len());
            self.fx.list.push(Effect::Send { to, bytes });
            Ok(())
        } else {
            self.fx
                .list
                .push(Effect::Trace(EventKind::SendRefused { to }));
            Err(SendError::NotConnected)
        }
    }

    fn unsent(&self, to: PeerId) -> usize {
        if self.connected.contains(&to) {
            self.unsent.get(&to).copied().unwrap_or(0)
        } else {
            0
        }
    }

    fn close(&mut self, to: PeerId) {
        self.connected.remove(&to);
        self.unsent.remove(&to);
        self.fx.list.push(Effect::Close(to));
    }
}

impl Randomness for SimContext<'_> {
    fn fill_random(&mut self, buf: &mut [u8]) {
        self.rng.fill_bytes(buf);
    }
}

impl Context for SimContext<'_> {
    fn storage(&mut self) -> &mut dyn Storage {
        &mut self.fx
    }
}

/// The result of a run, with what is needed to replay and read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The scenario's seed: the same seed replays the same run.
    pub seed: u64,
    /// Simulation time when the run returned.
    pub now: Instant,
    /// Whether the convergence predicate held at the end. Always `false` when
    /// the event budget was spent: a run that was stopped did not settle.
    pub converged: bool,
    /// Whether it held with no message in flight and no fault pending.
    pub quiescent: bool,
    /// Whether the run stopped because its event budget was spent.
    pub exhausted: bool,
    /// How many events were processed.
    pub events: u64,
    /// Pieces still in flight at the end (a lost one that has not yet taken
    /// its connection down included), and streams with writes not yet cut.
    pub in_flight: usize,
    /// The hash of every event; two runs with the same seed have the same.
    pub trace_hash: u64,
    /// The most recent events, oldest first.
    pub last_events: Vec<TraceEvent>,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "seed {}: {}{}, {}, t={}, {} events, {} in flight, trace {:016x}",
            self.seed,
            if self.converged {
                "converged"
            } else {
                "NOT converged"
            },
            if self.exhausted {
                " (event budget spent)"
            } else {
                ""
            },
            if self.quiescent {
                "quiescent"
            } else {
                "not quiescent"
            },
            self.now,
            self.events,
            self.in_flight,
            self.trace_hash,
        )?;
        writeln!(f, "last {} events:", self.last_events.len())?;
        for e in &self.last_events {
            writeln!(f, "  {e}")?;
        }
        Ok(())
    }
}

/// A running simulation.
pub struct Sim<P> {
    seed: u64,
    now: Instant,
    rng: SimRng,
    seq: u64,
    /// One counter for every timer armed in the run; see [`Node::timers`].
    timer_generation: u64,
    queue: BinaryHeap<Reverse<Scheduled>>,
    nodes: BTreeMap<PeerId, Node<P>>,
    factory: Factory<P>,
    network: NetworkConfig,
    links: Links,
    predicate: Predicate<P>,
    trace: Trace,
    in_flight: usize,
    pending_faults: usize,
    processed: u64,
    partitions: u64,
    wall_epoch: u64,
    max_events: u64,
    exhausted: bool,
    /// Notices of ended connections still to be delivered. Ending a
    /// connection only queues its two notices; [`Sim::settle`] delivers them,
    /// first in first out, once the handler (or the pair of `on_connected`
    /// handlers) that caused the end has had all its effects applied.
    notices: VecDeque<Notice>,
    next_piece: u64,
    stats: NetStats,
}

impl<P: Peer> Sim<P> {
    /// The seed this run was built from.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Simulation time (no peer's skew applied).
    #[must_use]
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// What `id`'s wall clock reads now: the scenario's wall epoch plus the
    /// whole seconds of `id`'s skewed instant. `None` for an unknown peer; a
    /// stopped peer's clock keeps running.
    #[must_use]
    pub fn wall_time(&self, id: PeerId) -> Option<u64> {
        self.nodes.get(&id).map(|n| self.wall_of(n.skew))
    }

    /// The running instance of `id`, or `None` when it is crashed, stopped or
    /// unknown.
    #[must_use]
    pub fn peer(&self, id: PeerId) -> Option<&P> {
        self.nodes.get(&id).and_then(|n| n.peer.as_ref())
    }

    /// Every running peer, in id order.
    pub fn peers(&self) -> impl Iterator<Item = (PeerId, &P)> {
        self.nodes
            .iter()
            .filter_map(|(id, n)| n.peer.as_ref().map(|p| (*id, p)))
    }

    /// The store of `id`, running or not.
    #[must_use]
    pub fn storage(&self, id: PeerId) -> Option<&SimStorage> {
        self.nodes.get(&id).map(|n| &n.storage)
    }

    /// Whether `id` is running.
    #[must_use]
    pub fn is_running(&self, id: PeerId) -> bool {
        self.peer(id).is_some()
    }

    /// Whether a connection between `a` and `b` is open: both have heard
    /// `on_connected` for the other and neither `on_disconnected` since (the
    /// two agree whenever this can be asked, since every step ends with the
    /// notices of its closes delivered). Two running, unpartitioned peers are
    /// not connected while a dropped connection waits to come back. A cleanly
    /// stopped peer's connection still counts as open while its stream drains
    /// (for up to [`STOP_FLUSH`]), though only the other side is listening:
    /// it ends once the stream has drained, or the stopped peer restarts, and
    /// at the latest when the flush runs out.
    #[must_use]
    pub fn is_connected(&self, a: PeerId, b: PeerId) -> bool {
        self.links.is_open(a, b)
    }

    /// Whether the convergence predicate holds now.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        (self.predicate)(self)
    }

    /// Pieces in flight (to arrive, or to take their connection down) and
    /// streams with writes not yet cut.
    #[must_use]
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// What the network has done so far.
    #[must_use]
    pub const fn stats(&self) -> &NetStats {
        &self.stats
    }

    /// Fault events still to come, among them the reconnections after dropped
    /// connections and, for each connection a clean stop left draining, its
    /// flush deadline [`STOP_FLUSH`] (1 s) later, which counts until it comes
    /// even when the stream drained sooner.
    #[must_use]
    pub const fn pending_faults(&self) -> usize {
        self.pending_faults
    }

    /// Converged with nothing in flight and no fault pending. Timers alone do
    /// not keep a system busy: a converged system that only ticks is quiescent.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.in_flight == 0 && self.pending_faults == 0 && self.is_converged()
    }

    /// Whether the event budget is spent; nothing runs after that.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// The hash of every event so far.
    #[must_use]
    pub const fn trace_hash(&self) -> u64 {
        self.trace.hash()
    }

    /// Every event so far, when the scenario asked to record them.
    #[must_use]
    pub fn trace(&self) -> Option<&[TraceEvent]> {
        self.trace.all()
    }

    /// How many events were processed.
    #[must_use]
    pub const fn events_processed(&self) -> u64 {
        self.processed
    }

    /// The state of the run as an [`Outcome`]. A run whose budget is spent is
    /// reported as neither converged nor quiescent, whatever the predicate
    /// says at the instant it stopped.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        Outcome {
            seed: self.seed,
            now: self.now,
            converged: !self.exhausted && self.is_converged(),
            quiescent: !self.exhausted && self.is_quiescent(),
            exhausted: self.exhausted,
            events: self.processed,
            in_flight: self.in_flight,
            trace_hash: self.trace.hash(),
            last_events: self.trace.last_events(),
        }
    }

    /// Processes the next event. Returns `false`, doing nothing, when there is
    /// none or the event budget is spent.
    pub fn step(&mut self) -> bool {
        if self.processed >= self.max_events {
            self.exhausted = true;
            return false;
        }
        let Some(Reverse(next)) = self.queue.pop() else {
            return false;
        };
        self.now = next.time;
        self.processed = self.processed.saturating_add(1);
        match next.event {
            Event::Cut { from, to, epoch } => self.cut(from, to, epoch),
            Event::Arrive {
                from,
                to,
                epoch,
                piece,
            } => self.arrive(from, to, epoch, piece),
            Event::Timer {
                peer,
                id,
                generation,
            } => self.fire_timer(peer, id, generation),
            Event::Fault(fault) => {
                self.pending_faults = self.pending_faults.saturating_sub(1);
                self.apply_fault(fault);
            }
        }
        self.settle();
        true
    }

    /// Processes every event up to and including time `at`, then sets the
    /// clock to `at` if nothing moved it that far. Stops early, where it is,
    /// when the event budget runs out.
    pub fn run_until(&mut self, at: Instant) -> Outcome {
        while self.queue.peek().is_some_and(|Reverse(n)| n.time <= at) {
            if !self.step() {
                return self.outcome();
            }
        }
        if self.now < at {
            self.now = at;
        }
        self.outcome()
    }

    /// Runs until the system is quiescent (see [`Sim::is_quiescent`]), the
    /// queue is empty, the event budget is spent, or the next event lies
    /// beyond `limit`; in that last case the clock is moved up to `limit`
    /// first. The outcome says which held.
    pub fn run_until_quiescent(&mut self, limit: Instant) -> Outcome {
        loop {
            if self.is_quiescent() {
                return self.outcome();
            }
            match self.queue.peek() {
                None => return self.outcome(),
                Some(Reverse(next)) if next.time > limit => {
                    if self.now < limit {
                        self.now = limit;
                    }
                    return self.outcome();
                }
                Some(_) => {
                    if !self.step() {
                        return self.outcome();
                    }
                }
            }
        }
    }

    fn wall_of(&self, skew: Duration) -> u64 {
        self.wall_epoch
            .saturating_add(self.now.saturating_add(skew).as_secs())
    }

    fn record(&mut self, peer: Option<PeerId>, kind: EventKind) {
        self.trace.push(TraceEvent {
            time: self.now,
            peer,
            kind,
        });
    }

    fn schedule(&mut self, at: Instant, event: Event) {
        let time = if at < self.now { self.now } else { at };
        self.seq = self.seq.wrapping_add(1);
        self.queue.push(Reverse(Scheduled {
            time,
            seq: self.seq,
            event,
        }));
    }

    fn schedule_fault_event(&mut self, at: Instant, fault: FaultEvent) {
        self.pending_faults = self.pending_faults.saturating_add(1);
        self.schedule(at, Event::Fault(fault));
    }

    fn schedule_fault(&mut self, fault: Fault) {
        // A window given the wrong way round is the same window.
        let window = |from: Instant, until: Instant| {
            if until < from {
                (until, from)
            } else {
                (from, until)
            }
        };
        match fault {
            Fault::Crash { peer, at } => self.schedule_fault_event(at, FaultEvent::Crash(peer)),
            Fault::Stop { peer, at } => self.schedule_fault_event(at, FaultEvent::Stop(peer)),
            Fault::Restart { peer, at } => {
                self.schedule_fault_event(at, FaultEvent::Restart(peer));
            }
            Fault::Partition {
                partition,
                from,
                until,
            } => {
                let (from, until) = window(from, until);
                let handle = self.partitions;
                self.partitions = self.partitions.wrapping_add(1);
                self.schedule_fault_event(from, FaultEvent::PartitionStart(handle, partition));
                self.schedule_fault_event(until, FaultEvent::PartitionEnd(handle));
            }
            Fault::DiskFull { peer, from, until } => {
                let (from, until) = window(from, until);
                self.schedule_fault_event(from, FaultEvent::DiskFull(peer));
                self.schedule_fault_event(until, FaultEvent::DiskFreed(peer));
            }
            Fault::Reconnect { a, b, at } => {
                self.schedule_fault_event(at, FaultEvent::Reconnect(a, b));
            }
        }
    }

    /// Runs one handler and applies its effects: the common case. `connect`
    /// alone runs its two handlers first and applies their effects afterwards;
    /// its doc says why that split remains.
    fn invoke(&mut self, id: PeerId, call: Call<'_>) {
        let effects = self.run(id, call);
        self.apply(id, effects);
    }

    /// Runs one handler of `id` and returns what it asked for, applying
    /// nothing yet (storage calls have already taken effect). Nothing happens
    /// for a peer that is not running. The handler sees as connected exactly
    /// the peers it has heard `on_connected` for and not `on_disconnected`.
    fn run(&mut self, id: PeerId, call: Call<'_>) -> Vec<Effect> {
        let now = self.now;
        let wall_epoch = self.wall_epoch;
        let Some(node) = self.nodes.get_mut(&id) else {
            return Vec::new();
        };
        let Some(peer) = node.peer.as_mut() else {
            return Vec::new();
        };
        let connected = node.heard.clone();
        let unsent = connected
            .iter()
            .map(|q| (*q, self.links.stream(id, *q).map_or(0, |s| s.unsent.len())))
            .collect();
        let local = Instant::ZERO
            .saturating_add(now.saturating_duration_since(node.origin))
            .saturating_add(node.skew);
        let mut cx = SimContext {
            now: local,
            wall: wall_epoch.saturating_add(now.saturating_add(node.skew).as_secs()),
            local: id,
            connected,
            unsent,
            rng: &mut self.rng,
            fx: Effects {
                storage: &mut node.storage,
                list: Vec::new(),
            },
        };
        match call {
            Call::Start => peer.on_start(&mut cx),
            Call::Message(from, bytes) => peer.on_message(&mut cx, from, bytes),
            Call::Timer(timer) => peer.on_timer(&mut cx, timer),
            Call::Connected(q) => peer.on_connected(&mut cx, q),
            Call::Disconnected(q) => peer.on_disconnected(&mut cx, q),
            Call::Stop => peer.on_stop(&mut cx),
        }
        cx.fx.list
    }

    /// Applies what a handler of `id` asked for, in order.
    fn apply(&mut self, id: PeerId, effects: Vec<Effect>) {
        for effect in effects {
            self.apply_effect(id, effect);
        }
    }

    fn apply_effect(&mut self, id: PeerId, effect: Effect) {
        match effect {
            Effect::Send { to, bytes } => self.send(id, to, &bytes),
            Effect::Close(to) => {
                self.record(Some(id), EventKind::Close(to));
                self.end_connection(id, to, End::HangUp);
                self.discard_owed(id, to);
            }
            Effect::SetTimer { id: timer, at } => {
                self.timer_generation = self.timer_generation.wrapping_add(1);
                let generation = self.timer_generation;
                let Some(node) = self.nodes.get_mut(&id) else {
                    return;
                };
                node.timers.insert(timer, generation);
                let since_start = at.checked_sub(node.skew).unwrap_or(Instant::ZERO);
                let at_sim = node
                    .origin
                    .saturating_add(Duration::from_nanos(since_start.as_nanos()));
                self.record(Some(id), EventKind::TimerSet { id: timer, at });
                self.schedule(
                    at_sim,
                    Event::Timer {
                        peer: id,
                        id: timer,
                        generation,
                    },
                );
            }
            Effect::CancelTimer(timer) => {
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.timers.remove(&timer);
                }
                self.record(Some(id), EventKind::TimerCancelled(timer));
            }
            Effect::Trace(kind) => self.record(Some(id), kind),
        }
    }

    /// Appends a write to the open connection's stream `from -> to`. What is
    /// written at one instant is gathered and cut into pieces at its end (see
    /// [`Sim::cut`]). The writer had heard `on_connected` and no
    /// `on_disconnected`; if the connection has closed anyway (the other side
    /// of a `connect` hung up inside `on_connected`, or the notice of an end
    /// has not reached `from` yet), the write is lost here as
    /// `DropReason::Closed`. A write that would take the stream's unsent
    /// queue (written at this instant, not yet cut) past its bound ends the
    /// connection instead (`DropReason::Overflow`).
    fn send(&mut self, from: PeerId, to: PeerId, bytes: &[u8]) {
        self.record(
            Some(from),
            EventKind::Send {
                to,
                bytes: bytes.to_vec(),
            },
        );
        let len = bytes.len();
        let reason = if !self.links.is_open(from, to) {
            Some(DropReason::Closed)
        } else if self
            .links
            .stream(from, to)
            .map_or(0, |s| s.unsent.len())
            .saturating_add(len)
            > self.network.max_send_queue
        {
            Some(DropReason::Overflow)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.record(Some(from), EventKind::Dropped { to, len, reason });
            if reason == DropReason::Overflow {
                self.end_connection(from, to, End::Overflow);
            }
            return;
        }
        if bytes.is_empty() {
            return;
        }
        let epoch = self.links.epoch(from, to);
        let stream = self.links.stream_mut(from, to);
        stream.unsent.extend_from_slice(bytes);
        stream.queued = stream.queued.saturating_add(len);
        if !stream.cut_pending {
            stream.cut_pending = true;
            self.in_flight = self.in_flight.saturating_add(1);
            self.schedule(self.now, Event::Cut { from, to, epoch });
        }
    }

    /// Seeded piece lengths for `len` bytes: each at most `MAX_CHUNK`, half
    /// the time as long as it can be, otherwise of a length drawn below that.
    fn piece_lengths(&mut self, mut len: usize) -> Vec<usize> {
        let mut lengths = Vec::new();
        while len > 0 {
            let most = len.min(MAX_CHUNK);
            let this = if self.rng.chance(WHOLE_PIECE) {
                most
            } else {
                let bound = u64::try_from(most).unwrap_or(u64::MAX);
                usize::try_from(self.rng.below(bound)).map_or(most, |n| n.saturating_add(1))
            };
            lengths.push(this);
            len = len.saturating_sub(this);
        }
        lengths
    }

    /// Cuts `bytes` into pieces of seeded lengths.
    fn pieces_of(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut rest = bytes;
        let mut out = Vec::new();
        for n in self.piece_lengths(bytes.len()) {
            let (piece, tail) = rest.split_at(n.min(rest.len()));
            out.push(piece.to_vec());
            rest = tail;
        }
        out
    }

    /// The end of the instant at which `from` wrote to `to`: cuts what was
    /// written into pieces and sends each on its way with its own latency,
    /// behind every piece before it; each may be the one the network loses.
    fn cut(&mut self, from: PeerId, to: PeerId, epoch: u64) {
        if self.links.epoch(from, to) != epoch || !self.links.is_open(from, to) {
            return;
        }
        let unsent = {
            let stream = self.links.stream_mut(from, to);
            if !stream.cut_pending {
                return;
            }
            stream.cut_pending = false;
            core::mem::take(&mut stream.unsent)
        };
        self.in_flight = self.in_flight.saturating_sub(1);
        for bytes in self.pieces_of(&unsent) {
            self.next_piece = self.next_piece.wrapping_add(1);
            let id = self.next_piece;
            let lost = self.rng.chance(self.network.drop);
            let latency = self
                .rng
                .duration_between(self.network.min_latency, self.network.max_latency);
            let proposed = self.now.saturating_add(latency);
            let stream = self.links.stream_mut(from, to);
            let at = stream.arrival(proposed);
            stream.travelling.push_back(Piece { id, bytes, lost });
            self.in_flight = self.in_flight.saturating_add(1);
            self.schedule(
                at,
                Event::Arrive {
                    from,
                    to,
                    epoch,
                    piece: id,
                },
            );
        }
    }

    /// Piece `id` of `from -> to` reaches the far end. A lost piece takes the
    /// connection down and schedules the network's reconnection; any other
    /// is handed to the receiver as one `on_message`, or dropped if the
    /// receiver is a stopped peer whose own stream is still draining. When a
    /// stopped sender's stream has drained, its connection ends.
    fn arrive(&mut self, from: PeerId, to: PeerId, epoch: u64, id: u64) {
        if self.links.epoch(from, to) != epoch || !self.links.is_open(from, to) {
            return;
        }
        let piece = {
            let stream = self.links.stream_mut(from, to);
            if stream.travelling.front().map(|p| p.id) != Some(id) {
                return;
            }
            let Some(piece) = stream.travelling.pop_front() else {
                return;
            };
            stream.queued = stream.queued.saturating_sub(piece.bytes.len());
            piece
        };
        self.in_flight = self.in_flight.saturating_sub(1);
        let len = piece.bytes.len();
        if piece.lost {
            self.record(
                Some(from),
                EventKind::Dropped {
                    to,
                    len,
                    reason: DropReason::Lost,
                },
            );
            self.end_connection(from, to, End::Drop);
            let delay = self
                .rng
                .duration_between(self.network.min_reconnect, self.network.max_reconnect);
            let after = self.links.epoch(from, to);
            self.schedule_fault_event(
                self.now.saturating_add(delay),
                FaultEvent::NetReconnect(from, to, after),
            );
            return;
        }
        if self.is_running(to) {
            self.record(
                Some(to),
                EventKind::Deliver {
                    from,
                    bytes: piece.bytes.clone(),
                },
            );
            self.stats.chunks = self.stats.chunks.saturating_add(1);
            self.invoke(to, Call::Message(from, &piece.bytes));
        } else {
            self.record(
                Some(from),
                EventKind::Dropped {
                    to,
                    len,
                    reason: DropReason::NotRunning,
                },
            );
        }
        let drained = self.links.stream(from, to).is_none_or(Stream::is_empty);
        if self.links.is_draining(from, to) && drained {
            self.end_connection(from, to, End::Stop);
        }
    }

    /// Ends the open connection between `a` and `b`, if there is one, for the
    /// reason `how` (whose cause is `a`). Each side that can still receive
    /// is given a seeded prefix of what the other had in flight, to be handed
    /// over just before its `on_disconnected`; the rest is lost. No handler
    /// runs here: the two notices are queued, `a`'s first, and
    /// [`Sim::settle`] delivers them once the handler that caused the end has
    /// had every effect applied. Until a side has heard, it still counts the
    /// connection as open; what it writes meanwhile is accepted and lost
    /// (`DropReason::Closed`). Nothing here reconnects them: the network's
    /// own reconnection after a drop, a `Fault::Reconnect`, a partition
    /// ending or a restart does.
    fn end_connection(&mut self, a: PeerId, b: PeerId, how: End) {
        let Some((a_to_b, b_to_a)) = self.links.close(a, b) else {
            return;
        };
        let units = |s: &Stream| {
            s.travelling
                .len()
                .saturating_add(usize::from(s.cut_pending))
        };
        self.in_flight = self
            .in_flight
            .saturating_sub(units(&a_to_b).saturating_add(units(&b_to_a)));
        let count = match how {
            End::HangUp => &mut self.stats.hung_up,
            End::Drop => &mut self.stats.dropped,
            End::Partition => &mut self.stats.partitioned,
            End::Overflow => &mut self.stats.overflowed,
            End::Crash => &mut self.stats.crashed,
            End::Stop => &mut self.stats.stopped,
        };
        *count = count.saturating_add(1);
        let (a_may, b_may) = match how {
            End::HangUp | End::Crash | End::Stop => (false, true),
            End::Drop => (true, false),
            End::Partition | End::Overflow => (true, true),
        };
        let to_b = self.at_close(a, b, a_to_b, b_may && self.is_running(b));
        let to_a = self.at_close(b, a, b_to_a, a_may && self.is_running(a));
        self.notices.push_back(Notice {
            to: a,
            about: b,
            chunks: to_a,
        });
        self.notices.push_back(Notice {
            to: b,
            about: a,
            chunks: to_b,
        });
    }

    /// A hang-up on a connection whose end is already on its way to `to`
    /// (its notice still queued, or being handed over this moment) means `to`
    /// receives nothing more on it: the bytes that notice would still have
    /// handed over first are dropped.
    fn discard_owed(&mut self, to: PeerId, about: PeerId) {
        let mut owed = Vec::new();
        for notice in &mut self.notices {
            if notice.to == to && notice.about == about {
                owed.extend(notice.chunks.drain(..));
            }
        }
        for bytes in owed {
            self.stats.lost_at_close = self.stats.lost_at_close.saturating_add(1);
            self.record(
                Some(about),
                EventKind::Dropped {
                    to,
                    len: bytes.len(),
                    reason: DropReason::Stale,
                },
            );
        }
    }

    /// What of the ended stream `from -> to` still reaches `to`: when it may
    /// receive, each travelling piece in order with the configured chance,
    /// until the first that does not (or a lost one). Bytes written but not
    /// yet handed to the network never left the sender and are lost with the
    /// connection. Everything not handed over is recorded as dropped.
    fn at_close(
        &mut self,
        from: PeerId,
        to: PeerId,
        stream: Stream,
        may_receive: bool,
    ) -> VecDeque<Vec<u8>> {
        let mut pieces: Vec<(Vec<u8>, bool)> = stream
            .travelling
            .into_iter()
            .map(|p| (p.bytes, p.lost))
            .collect();
        if !stream.unsent.is_empty() {
            pieces.push((stream.unsent, true));
        }
        let reason = if self.is_running(to) {
            DropReason::Stale
        } else {
            DropReason::NotRunning
        };
        let mut open = may_receive;
        let mut handed = VecDeque::new();
        for (bytes, lost) in pieces {
            open = open && !lost && self.rng.chance(self.network.deliver_at_close);
            if open {
                handed.push_back(bytes);
            } else {
                self.stats.lost_at_close = self.stats.lost_at_close.saturating_add(1);
                self.record(
                    Some(from),
                    EventKind::Dropped {
                        to,
                        len: bytes.len(),
                        reason,
                    },
                );
            }
        }
        handed
    }

    fn fire_timer(&mut self, peer: PeerId, id: TimerId, generation: u64) {
        let Some(node) = self.nodes.get_mut(&peer) else {
            return;
        };
        if node.peer.is_none() || node.timers.get(&id) != Some(&generation) {
            return;
        }
        node.timers.remove(&id);
        self.record(Some(peer), EventKind::TimerFired(id));
        self.invoke(peer, Call::Timer(id));
    }

    fn apply_fault(&mut self, fault: FaultEvent) {
        match fault {
            FaultEvent::Crash(p) => self.take_down(p, false),
            FaultEvent::Stop(p) => self.take_down(p, true),
            FaultEvent::Restart(p) => self.bring_up(p),
            FaultEvent::PartitionStart(handle, partition) => {
                self.partition_start(handle, partition);
            }
            FaultEvent::PartitionEnd(handle) => self.partition_end(handle),
            FaultEvent::DiskFull(p) => {
                if let Some(node) = self.nodes.get_mut(&p) {
                    node.storage.set_full(true);
                    self.record(Some(p), EventKind::DiskFull);
                }
            }
            FaultEvent::DiskFreed(p) => {
                if let Some(node) = self.nodes.get_mut(&p) {
                    node.storage.set_full(false);
                    self.record(Some(p), EventKind::DiskFreed);
                }
            }
            FaultEvent::Reconnect(a, b) => self.connect(a, b),
            FaultEvent::NetReconnect(a, b, epoch) => {
                if self.links.epoch(a, b) == epoch {
                    self.connect(a, b);
                }
            }
            FaultEvent::DrainDeadline(p, q, epoch) => {
                if self.links.epoch(p, q) == epoch && self.links.is_draining(p, q) {
                    self.end_connection(p, q, End::Stop);
                }
            }
        }
    }

    fn start_peer(&mut self, id: PeerId) {
        let Some(node) = self.nodes.get_mut(&id) else {
            return;
        };
        if node.peer.is_some() {
            return;
        }
        node.peer = Some((self.factory)(id));
        node.origin = self.now;
        self.record(Some(id), EventKind::Start);
        self.invoke(id, Call::Start);
    }

    /// Opens a connection between `a` and `b` if both run, no partition cuts
    /// them and none is open already, as one batch. Notices still owed are
    /// delivered first, so neither side can hear `on_connected` for a peer it
    /// has not yet heard `on_disconnected` for. Then both sides hear
    /// `on_connected`, `a` first; only then are the two handlers' effects
    /// applied, `a`'s in full and then `b`'s; and only after both are the
    /// notices of any close they asked for delivered. So if `a` hangs up
    /// inside `on_connected`, `b` still hears `on_connected` first, every
    /// effect `b` asked for there (a timer, a message to a third peer) takes
    /// effect before `b` hears `on_disconnected`, and what `b` sent to `a` was
    /// accepted and is lost with the close (`DropReason::Closed`), as the
    /// transport contract allows. What `a` sends from inside its call is
    /// queued on the new connection and arrives after `b` has heard too.
    ///
    /// Running both handlers before applying either was needed when a close
    /// ran the other side's `on_disconnected` at once. Under the notice queue
    /// it no longer changes behaviour: applying `a`'s effects before running
    /// `b` would keep every guarantee above, and only move trace records and
    /// random draws, giving a different but equally valid run. It is kept
    /// because it keeps the trace order: both sides' `Connected` records come
    /// before either side's effects.
    fn connect(&mut self, a: PeerId, b: PeerId) {
        self.settle();
        if !self.is_running(a) || !self.is_running(b) || self.links.cut(a, b) {
            return;
        }
        if !self.links.open(a, b) {
            return;
        }
        self.stats.opened = self.stats.opened.saturating_add(1);
        self.record(Some(a), EventKind::Connected(b));
        self.hear_connected(a, b);
        let effects_a = self.run(a, Call::Connected(b));
        self.record(Some(b), EventKind::Connected(a));
        self.hear_connected(b, a);
        let effects_b = self.run(b, Call::Connected(a));
        self.apply(a, effects_a);
        self.apply(b, effects_b);
        self.settle();
    }

    fn hear_connected(&mut self, to: PeerId, about: PeerId) {
        if let Some(node) = self.nodes.get_mut(&to) {
            node.heard.insert(about);
        }
    }

    /// Delivers the notices of ended connections, first in first out: for
    /// each, `to` is handed the bytes that still reach it, one `on_message`
    /// each, then hears `on_disconnected(about)`, every call's effects applied
    /// before the next. An end those effects cause queues its own notices
    /// behind the ones already waiting, so each peer hears of its own
    /// connections' ends one at a time, in the order the simulator ended
    /// them, and never in the middle of applying another handler's effects;
    /// that the simulator also keeps one order across peers is a property of
    /// this simulator, not a promise of the runtime contract. A notice for a
    /// peer that is not running (it crashed or stopped meanwhile) or that
    /// never heard `on_connected(about)` is dropped, with its bytes. Called at
    /// the end of every step, before and after every `connect`, and at the
    /// end of a take-down. It terminates: a notice is queued only when an open
    /// connection ends, and nothing it runs can open one.
    fn settle(&mut self) {
        while let Some((to, about)) = self.notices.front().map(|n| (n.to, n.about)) {
            let listening = self
                .nodes
                .get(&to)
                .is_some_and(|n| n.peer.is_some() && n.heard.contains(&about));
            if !listening {
                let chunks = self
                    .notices
                    .pop_front()
                    .map(|n| n.chunks)
                    .unwrap_or_default();
                for bytes in chunks {
                    self.stats.lost_at_close = self.stats.lost_at_close.saturating_add(1);
                    self.record(
                        Some(about),
                        EventKind::Dropped {
                            to,
                            len: bytes.len(),
                            reason: DropReason::NotRunning,
                        },
                    );
                }
                continue;
            }
            // The notice stays at the front while its bytes are handed over,
            // one chunk per call, so that a hang-up made in one of those calls
            // still finds it and cancels the rest.
            let next = self.notices.front_mut().and_then(|n| n.chunks.pop_front());
            if let Some(bytes) = next {
                self.stats.delivered_at_close = self.stats.delivered_at_close.saturating_add(1);
                self.record(
                    Some(to),
                    EventKind::Deliver {
                        from: about,
                        bytes: bytes.clone(),
                    },
                );
                self.invoke(to, Call::Message(about, &bytes));
                continue;
            }
            self.notices.pop_front();
            if let Some(node) = self.nodes.get_mut(&to) {
                node.heard.remove(&about);
            }
            self.record(Some(to), EventKind::Disconnected(about));
            self.invoke(to, Call::Disconnected(about));
        }
    }

    /// Ends `p`'s process. A crash ends every open connection at once; the
    /// other side may still be handed part of what `p` had in flight. A clean
    /// stop runs `on_stop` first, its effects applied, and then keeps each
    /// connection open for up to [`STOP_FLUSH`] while `p`'s stream drains, so
    /// what `p` wrote, `on_stop` included, can still arrive; a stream already
    /// empty ends at once. Either way the instance, its timers, what it had
    /// heard and its staged writes go, and `p` itself is never called again:
    /// a notice owed to it (from a hang-up inside `on_stop`) is dropped.
    fn take_down(&mut self, p: PeerId, graceful: bool) {
        if !self.is_running(p) {
            return;
        }
        if graceful {
            self.invoke(p, Call::Stop);
        }
        let others = self.links.open_with(p);
        if let Some(node) = self.nodes.get_mut(&p) {
            node.peer = None;
            node.heard.clear();
            node.timers.clear();
            node.storage.crash();
        }
        self.record(
            Some(p),
            if graceful {
                EventKind::Stop
            } else {
                EventKind::Crash
            },
        );
        if !others.is_empty() {
            self.stats.downs_heard = self.stats.downs_heard.saturating_add(1);
        }
        for q in others {
            let pending = self.links.stream(p, q).is_some_and(|s| !s.is_empty());
            if graceful && pending {
                self.links.start_draining(p, q);
                let epoch = self.links.epoch(p, q);
                self.schedule_fault_event(
                    self.now.saturating_add(STOP_FLUSH),
                    FaultEvent::DrainDeadline(p, q, epoch),
                );
            } else {
                self.end_connection(p, q, if graceful { End::Stop } else { End::Crash });
            }
        }
        self.settle();
    }

    /// Starts a fresh instance of `p`, with a fresh clock, and connects it to
    /// every running peer it is not cut from. A connection the previous
    /// instance was still draining ends first: a new process never inherits
    /// one.
    fn bring_up(&mut self, p: PeerId) {
        if self.is_running(p) || !self.nodes.contains_key(&p) {
            return;
        }
        for q in self.links.open_with(p) {
            self.end_connection(p, q, End::Stop);
        }
        self.settle();
        self.start_peer(p);
        let others: Vec<PeerId> = self.nodes.keys().copied().filter(|q| *q != p).collect();
        for q in others {
            self.connect(p, q);
        }
    }

    fn pairs(&self) -> Vec<(PeerId, PeerId)> {
        let ids: Vec<PeerId> = self.nodes.keys().copied().collect();
        let mut pairs = Vec::new();
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                pairs.push((*a, *b));
            }
        }
        pairs
    }

    fn partition_start(&mut self, handle: u64, partition: Partition) {
        let newly_cut: Vec<(PeerId, PeerId)> = self
            .pairs()
            .into_iter()
            .filter(|(a, b)| partition.cuts(*a, *b) && self.links.is_open(*a, *b))
            .collect();
        self.links.add_partition(handle, partition);
        self.record(None, EventKind::PartitionStart);
        for (a, b) in newly_cut {
            self.end_connection(a, b, End::Partition);
        }
    }

    fn partition_end(&mut self, handle: u64) {
        let Some(partition) = self.links.remove_partition(handle) else {
            return;
        };
        self.record(None, EventKind::PartitionEnd);
        let healed: Vec<(PeerId, PeerId)> = self
            .pairs()
            .into_iter()
            .filter(|(a, b)| partition.cuts(*a, *b))
            .collect();
        for (a, b) in healed {
            self.connect(a, b);
        }
    }
}
