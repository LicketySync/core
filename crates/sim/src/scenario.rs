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
    TimerId, Timers, Transport,
};

use crate::network::{Links, NetworkConfig, Partition};
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

    /// Makes `peer`'s clocks, monotonic and wall, read `by` ahead of the
    /// simulation's. Relative skew is what matters; to put one peer behind the
    /// rest, put the rest ahead.
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
    /// must be, and is lost with the connection.
    heard: BTreeSet<PeerId>,
}

enum Event {
    Deliver {
        from: PeerId,
        to: PeerId,
        bytes: Vec<u8>,
        epoch: u64,
    },
    /// The message `from` sent to `to` is lost and takes the connection down
    /// when its latency has elapsed, if that connection (epoch) is still open.
    Drop {
        from: PeerId,
        to: PeerId,
        len: usize,
        epoch: u64,
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
    /// From a `Fault::Reconnect`, or the network's own after a dropped
    /// connection.
    Reconnect(PeerId, PeerId),
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
            self.fx.list.push(Effect::Send { to, bytes });
            Ok(())
        } else {
            self.fx
                .list
                .push(Effect::Trace(EventKind::SendRefused { to }));
            Err(SendError::NotConnected)
        }
    }

    fn close(&mut self, to: PeerId) {
        self.connected.remove(&to);
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
    /// Messages still in flight at the end, a lost message that has not yet
    /// taken its connection down included.
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
    /// `(to, about)`: `to` is still to hear `on_disconnected(about)`. Closing a
    /// connection only queues its two notices; [`Sim::settle`] delivers them,
    /// first in first out, once the handler (or the pair of `on_connected`
    /// handlers) that caused the close has had all its effects applied.
    notices: VecDeque<(PeerId, PeerId)>,
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
    /// not connected while a dropped connection waits to come back.
    #[must_use]
    pub fn is_connected(&self, a: PeerId, b: PeerId) -> bool {
        self.links.is_open(a, b)
    }

    /// Whether the convergence predicate holds now.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        (self.predicate)(self)
    }

    /// Messages scheduled for delivery, or to take their connection down.
    #[must_use]
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Fault events still to come, the reconnections after dropped
    /// connections among them.
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
            Event::Deliver {
                from,
                to,
                bytes,
                epoch,
            } => {
                self.in_flight = self.in_flight.saturating_sub(1);
                self.deliver(from, to, &bytes, epoch);
            }
            Event::Drop {
                from,
                to,
                len,
                epoch,
            } => {
                self.in_flight = self.in_flight.saturating_sub(1);
                self.drop_connection(from, to, len, epoch);
            }
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
        let skewed = now.saturating_add(node.skew);
        let mut cx = SimContext {
            now: skewed,
            wall: wall_epoch.saturating_add(skewed.as_secs()),
            local: id,
            connected,
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
            Effect::Send { to, bytes } => self.send(id, to, bytes),
            Effect::Close(to) => {
                self.record(Some(id), EventKind::Close(to));
                self.disconnect(id, to);
            }
            Effect::SetTimer { id: timer, at } => {
                self.timer_generation = self.timer_generation.wrapping_add(1);
                let generation = self.timer_generation;
                let Some(node) = self.nodes.get_mut(&id) else {
                    return;
                };
                node.timers.insert(timer, generation);
                let at_sim = at.checked_sub(node.skew).unwrap_or(Instant::ZERO);
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

    /// Puts a message on the open connection `from -> to`: it arrives after
    /// its latency, behind everything sent before it in that direction, or,
    /// with the configured probability, takes the connection down instead.
    /// The handler that queued it had heard `on_connected` and no
    /// `on_disconnected`; if the connection has closed anyway (the other side
    /// of a `connect` hung up inside `on_connected`, or the notice of a close
    /// has not reached `from` yet), the message is lost here as
    /// `DropReason::Closed`.
    fn send(&mut self, from: PeerId, to: PeerId, bytes: Vec<u8>) {
        self.record(
            Some(from),
            EventKind::Send {
                to,
                bytes: bytes.clone(),
            },
        );
        if !self.links.is_open(from, to) {
            self.record(
                Some(from),
                EventKind::Dropped {
                    to,
                    len: bytes.len(),
                    reason: DropReason::Closed,
                },
            );
            return;
        }
        let epoch = self.links.epoch(from, to);
        let latency = self
            .rng
            .duration_between(self.network.min_latency, self.network.max_latency);
        let at = self.links.fifo(from, to, self.now.saturating_add(latency));
        let event = if self.rng.chance(self.network.drop) {
            Event::Drop {
                from,
                to,
                len: bytes.len(),
                epoch,
            }
        } else {
            Event::Deliver {
                from,
                to,
                bytes,
                epoch,
            }
        };
        self.in_flight = self.in_flight.saturating_add(1);
        self.schedule(at, event);
    }

    fn deliver(&mut self, from: PeerId, to: PeerId, bytes: &[u8], epoch: u64) {
        let reason = if !self.is_running(to) {
            Some(DropReason::NotRunning)
        } else if self.links.epoch(from, to) != epoch {
            Some(DropReason::Stale)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.record(
                Some(from),
                EventKind::Dropped {
                    to,
                    len: bytes.len(),
                    reason,
                },
            );
        } else {
            self.record(
                Some(to),
                EventKind::Deliver {
                    from,
                    bytes: bytes.to_vec(),
                },
            );
            self.invoke(to, Call::Message(from, bytes));
        }
    }

    /// The lost message's moment: if the connection it was sent on is still
    /// the open one, it goes down now and a reconnection is scheduled; if
    /// something closed it first, the message is merely stale.
    fn drop_connection(&mut self, from: PeerId, to: PeerId, len: usize, epoch: u64) {
        let current = self.links.is_open(from, to) && self.links.epoch(from, to) == epoch;
        let reason = if current {
            DropReason::Lost
        } else {
            DropReason::Stale
        };
        self.record(Some(from), EventKind::Dropped { to, len, reason });
        if !current {
            return;
        }
        self.disconnect(from, to);
        let delay = self
            .rng
            .duration_between(self.network.min_reconnect, self.network.max_reconnect);
        self.schedule_fault_event(
            self.now.saturating_add(delay),
            FaultEvent::Reconnect(from, to),
        );
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
    /// because it fixes that order, and so keeps every fingerprint recorded so
    /// far.
    fn connect(&mut self, a: PeerId, b: PeerId) {
        self.settle();
        if !self.is_running(a) || !self.is_running(b) || self.links.cut(a, b) {
            return;
        }
        if !self.links.open(a, b) {
            return;
        }
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

    /// Delivers the notices of closed connections, first in first out: for
    /// each, `to` hears `on_disconnected(about)` and that call's effects are
    /// applied before the next notice is delivered. A close those effects ask
    /// for queues its own notices behind the ones already waiting, so every
    /// peer hears its connections end in the order they closed, and never in
    /// the middle of applying another handler's effects. A notice for a peer
    /// that is not running (it crashed or stopped meanwhile) or that never
    /// heard `on_connected(about)` is dropped. Called at the end of every
    /// step, before and after every `connect`, and at the end of a take-down.
    /// It terminates: a notice is queued only when an open connection closes,
    /// and nothing it runs can open one.
    fn settle(&mut self) {
        while let Some((to, about)) = self.notices.pop_front() {
            let Some(node) = self.nodes.get_mut(&to) else {
                continue;
            };
            if node.peer.is_none() || !node.heard.remove(&about) {
                continue;
            }
            self.record(Some(to), EventKind::Disconnected(about));
            self.invoke(to, Call::Disconnected(about));
        }
    }

    /// Closes the open connection between `a` and `b`, if there is one: what
    /// was in flight on it is stale at once, and a notice for each side is
    /// queued, `a`'s first. No handler runs here: when this is a hang-up
    /// (`Transport::close`), the closing handler's remaining effects are
    /// applied first, in the order it asked for them, and [`Sim::settle`]
    /// then has both sides hear `on_disconnected`. Until a side has heard, it
    /// still counts the connection as open; what it sends meanwhile is
    /// accepted and lost (`DropReason::Closed`). Nothing here reconnects
    /// them: the network's own reconnection after a drop, a
    /// `Fault::Reconnect`, a partition ending or a restart does.
    fn disconnect(&mut self, a: PeerId, b: PeerId) {
        if !self.links.close(a, b) {
            return;
        }
        self.notices.push_back((a, b));
        self.notices.push_back((b, a));
    }

    /// Ends `p`'s process: `on_stop` first when graceful, its effects
    /// applied; then every open connection closes, the instance, its timers,
    /// what it had heard and its staged writes go, and each peer that was
    /// connected hears `on_disconnected` with `p` already gone, in id order.
    /// `p` itself is never called again: a notice owed to it (from a hang-up
    /// inside `on_stop`) is dropped.
    fn take_down(&mut self, p: PeerId, graceful: bool) {
        if !self.is_running(p) {
            return;
        }
        if graceful {
            self.invoke(p, Call::Stop);
        }
        let others = self.links.open_with(p);
        for q in &others {
            self.links.close(p, *q);
        }
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
        for q in others {
            self.notices.push_back((q, p));
        }
        self.settle();
    }

    fn bring_up(&mut self, p: PeerId) {
        if self.is_running(p) || !self.nodes.contains_key(&p) {
            return;
        }
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
            self.disconnect(a, b);
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
