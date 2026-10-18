// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A peer that checks the runtime contract from the inside, and the
//! `contract` scenario that runs five of them under every fault at once.
//!
//! [`Prober`] behaves like the engine at its most awkward: from every handler,
//! `on_connected`, `on_disconnected` and `on_stop` included, it sends, hangs up
//! (abruptly, or the engine's way: a goodbye frame, then `close` when its own
//! 1 s timer fires or the other side hangs up) and arms or cancels a timer at
//! random; receiving a goodbye, it hangs up at once or, half the time, leaves
//! the connection for the other side to end (its goodbye timer, or the
//! runtime's flush after a clean stop). Meanwhile the scenario crashes, stops
//! and restarts peers, partitions them, reconnects every pair once a second and
//! the network drops connections. Its messages are frames (the [`crate::frame`]
//! format) on the byte stream, so every check works on whole frames reassembled
//! from chunks split anywhere. Each instance checks, as the calls arrive, what
//! the runtime documentation promises the one side it is, one [`Rule`] each:
//! calls about a peer alternate between `on_connected` and `on_disconnected`;
//! each chunk holds 1 to `MAX_CHUNK` bytes; frames arrive only inside a
//! connection, all from the sender's side of that same connection, each once
//! and in the order sent with none missing in between (a connection's end may
//! lose the tail, never the middle), and never after this side hung up; a send
//! inside a connection as this side knows it is accepted unless it hung up on
//! that peer in the same handler, and `unsent` grows by exactly what it accepts
//! (the prober paces on it, as the engine will); a timer fires only while
//! armed, never before its deadline, and never one an earlier instance armed;
//! nothing is called after `on_stop`; and every hang-up is answered by
//! `on_disconnected`. It checks nothing across machines, because the contract
//! promises nothing there. A breach goes into the [`Report`] every instance
//! shares, and the scenario converges only when there is none. The probers stop
//! acting at [`QUIET_AFTER`] so that the network drains and the run ends
//! quiescent.

use core::cell::RefCell;
use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::runtime::{
    Context, Instant, Peer, PeerId, TimerId, MAX_CHUNK, MAX_SEND_QUEUE,
};

use crate::frame::{frame, Deframer};
use crate::network::{NetworkConfig, Partition};
use crate::scenario::{Fault, NetStats, Outcome, Scenario, DEFAULT_WALL_EPOCH};
use crate::toy::LIMIT;

/// Seconds into the run, by the wall clock, after which the probers only
/// check and finish what they started (a goodbye's hang-up): no new sends,
/// hang-ups or timers. The last scheduled fault is a second earlier. It is
/// read from the wall clock because that is the one clock a restarted
/// instance shares with its predecessor; deciding when a test peer falls
/// silent is not one of the decisions the wall clock is barred from.
pub const QUIET_AFTER: u64 = 25;

/// How many probers the scenario runs.
pub const PEERS: u32 = 5;

/// Each instance numbers its timers in a block of its own, so a timer an
/// earlier instance armed can never pass for one of this instance's: slot 0
/// is the tick, slot 1 the spare, slot `2 + p` the goodbye timer for peer `p`.
const TIMER_BLOCK: u64 = 16;
const TICK_SLOT: u64 = 0;
const SPARE_SLOT: u64 = 1;
const GOODBYE_SLOT: u64 = 2;

/// How long a prober waits after its goodbye before it hangs up anyway
/// (protocol spec, 4.2).
const GOODBYE_WAIT: Duration = Duration::from_secs(1);

/// A frame's payload: instance, connection, sequence (each a big-endian
/// `u64`), then the kind.
const PAYLOAD: usize = 25;
const DATA: u8 = 0;
const GOODBYE: u8 = 1;

/// A promise of the runtime documentation that a prober checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// `on_connected` for a peer already connected, or `on_disconnected` for
    /// one that is not.
    Alternation,
    /// A chunk of no bytes, or of more than `MAX_CHUNK`.
    BadChunk,
    /// Bytes from a peer this side has not heard `on_connected` for.
    MessageOutsideConnection,
    /// Bytes from a peer after this side hung up on it.
    MessageAfterHangUp,
    /// Within one connection, a frame the sender sent on another one.
    CrossConnection,
    /// Within one connection, a frame other than the next one sent:
    /// duplicated, overtaken, or with one missing before it.
    OutOfOrder,
    /// Bytes that are no prober's frames.
    Garbled,
    /// A send refused although this side had heard `on_connected` for the
    /// peer, no `on_disconnected` since, and had not hung up on it in the
    /// same handler.
    RefusedWhileConnected,
    /// `Transport::unsent` did not grow by exactly what an accepted write
    /// added, within one handler.
    UnsentMiscount,
    /// A timer fired that was cancelled, had fired already or was never armed.
    UnarmedTimerFired,
    /// A timer fired before its deadline.
    EarlyTimer,
    /// A timer fired that an earlier instance of this peer armed.
    ForeignTimer,
    /// A handler was called after `on_stop`.
    CallAfterStop,
    /// A running peer hung up (or said goodbye) and never heard
    /// `on_disconnected` for it.
    UnansweredHangUp,
}

impl Rule {
    /// Every rule, in report order.
    pub const ALL: [Self; 14] = [
        Self::Alternation,
        Self::BadChunk,
        Self::MessageOutsideConnection,
        Self::MessageAfterHangUp,
        Self::CrossConnection,
        Self::OutOfOrder,
        Self::Garbled,
        Self::RefusedWhileConnected,
        Self::UnsentMiscount,
        Self::UnarmedTimerFired,
        Self::EarlyTimer,
        Self::ForeignTimer,
        Self::CallAfterStop,
        Self::UnansweredHangUp,
    ];
}

/// What the probers of one or more runs saw: each breach by rule (a count
/// and the first description), how much they did, and what the network did,
/// so that a clean report can be told from one where nothing was tried.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    breaches: BTreeMap<Rule, (u64, String)>,
    instances: u64,
    sends: u64,
    chunks: u64,
    frames: u64,
    hang_ups: u64,
    goodbyes_sent: u64,
    goodbyes_received: u64,
    stop_hang_ups: u64,
    cancels: u64,
    timers_fired: u64,
    net: NetStats,
}

impl Report {
    /// Breaches of every rule.
    #[must_use]
    pub fn breaches(&self) -> u64 {
        self.breaches
            .values()
            .map(|(n, _)| *n)
            .fold(0, u64::saturating_add)
    }

    /// Breaches of `rule`.
    #[must_use]
    pub fn breaches_of(&self, rule: Rule) -> u64 {
        self.breaches.get(&rule).map_or(0, |(n, _)| *n)
    }

    /// The first breach of `rule`, described.
    #[must_use]
    pub fn first(&self, rule: Rule) -> Option<&str> {
        self.breaches.get(&rule).map(|(_, s)| s.as_str())
    }

    /// Prober instances built, restarts included.
    #[must_use]
    pub const fn instances(&self) -> u64 {
        self.instances
    }

    /// Sends the runtime accepted.
    #[must_use]
    pub const fn sends(&self) -> u64 {
        self.sends
    }

    /// Chunks that arrived.
    #[must_use]
    pub const fn chunks(&self) -> u64 {
        self.chunks
    }

    /// Whole frames reassembled and checked.
    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    /// Hang-ups asked for, those that end a goodbye included.
    #[must_use]
    pub const fn hang_ups(&self) -> u64 {
        self.hang_ups
    }

    /// Goodbye frames sent (from `on_stop` too).
    #[must_use]
    pub const fn goodbyes_sent(&self) -> u64 {
        self.goodbyes_sent
    }

    /// Goodbye frames that arrived.
    #[must_use]
    pub const fn goodbyes_received(&self) -> u64 {
        self.goodbyes_received
    }

    /// Hang-ups asked for inside `on_stop`.
    #[must_use]
    pub const fn stop_hang_ups(&self) -> u64 {
        self.stop_hang_ups
    }

    /// Timer cancellations asked for.
    #[must_use]
    pub const fn cancels(&self) -> u64 {
        self.cancels
    }

    /// Timers that fired.
    #[must_use]
    pub const fn timers_fired(&self) -> u64 {
        self.timers_fired
    }

    /// What the network did in the runs.
    #[must_use]
    pub const fn net(&self) -> &NetStats {
        &self.net
    }

    /// Adds `other`'s counts to this report's, keeping this report's first
    /// description of each rule where it has one.
    pub fn absorb(&mut self, other: &Self) {
        for (rule, (n, first)) in &other.breaches {
            let entry = self
                .breaches
                .entry(*rule)
                .or_insert_with(|| (0, first.clone()));
            entry.0 = entry.0.saturating_add(*n);
        }
        for (mine, theirs) in [
            (&mut self.instances, other.instances),
            (&mut self.sends, other.sends),
            (&mut self.chunks, other.chunks),
            (&mut self.frames, other.frames),
            (&mut self.hang_ups, other.hang_ups),
            (&mut self.goodbyes_sent, other.goodbyes_sent),
            (&mut self.goodbyes_received, other.goodbyes_received),
            (&mut self.stop_hang_ups, other.stop_hang_ups),
            (&mut self.cancels, other.cancels),
            (&mut self.timers_fired, other.timers_fired),
        ] {
            *mine = mine.saturating_add(theirs);
        }
        self.net.absorb(&other.net);
    }

    fn breach(&mut self, rule: Rule, what: String) {
        let entry = self.breaches.entry(rule).or_insert((0, what));
        entry.0 = entry.0.saturating_add(1);
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} breaches; {} instances, {} sends, {} frames checked in {} chunks, \
             {} hang-ups ({} in on_stop), {} goodbyes sent and {} received, \
             {} cancels, {} timers fired",
            self.breaches(),
            self.instances,
            self.sends,
            self.frames,
            self.chunks,
            self.hang_ups,
            self.stop_hang_ups,
            self.goodbyes_sent,
            self.goodbyes_received,
            self.cancels,
            self.timers_fired
        )?;
        writeln!(f, "  network: {}", self.net)?;
        for rule in Rule::ALL {
            if let Some((n, first)) = self.breaches.get(&rule) {
                writeln!(f, "  {rule:?}: {n}, first: {first}")?;
            }
        }
        Ok(())
    }
}

/// The report every prober of one run writes to.
pub type SharedReport = Rc<RefCell<Report>>;

/// What this side sends on one connection: the connection's number among
/// this instance's connections, and the next sequence number.
#[derive(Clone, Copy, Debug)]
struct Outgoing {
    connection: u64,
    next: u64,
}

/// What this side expects next on one connection, once the first frame has
/// named the sender's instance and connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Incoming {
    instance: u64,
    connection: u64,
    next: u64,
}

/// A peer that acts at random from every handler and checks the runtime
/// contract as calls arrive.
#[derive(Debug)]
pub struct Prober {
    report: SharedReport,
    instance: u64,
    stopped: bool,
    connections: u64,
    /// The peers heard `on_connected` for and not `on_disconnected`.
    out: BTreeMap<PeerId, Outgoing>,
    incoming: BTreeMap<PeerId, Incoming>,
    streams: BTreeMap<PeerId, Deframer>,
    /// Hung up on in the current handler: a send to them is refused.
    hung_up_now: BTreeSet<PeerId>,
    /// Hung up on, `on_disconnected` not yet heard.
    hung_up: BTreeSet<PeerId>,
    /// Said goodbye to: no more sends; hang up on the goodbye timer.
    leaving: BTreeSet<PeerId>,
    /// This instance's armed timers and their deadlines.
    deadlines: BTreeMap<TimerId, Instant>,
}

fn random(cx: &mut dyn Context) -> u64 {
    let mut b = [0u8; 8];
    cx.fill_random(&mut b);
    u64::from_le_bytes(b)
}

fn quiet(cx: &dyn Context) -> bool {
    cx.wall_time() >= DEFAULT_WALL_EPOCH.saturating_add(QUIET_AFTER)
}

fn encode(instance: u64, connection: u64, seq: u64, kind: u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(PAYLOAD);
    m.extend_from_slice(&instance.to_be_bytes());
    m.extend_from_slice(&connection.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.push(kind);
    m
}

fn decode(bytes: &[u8]) -> Option<(u64, u64, u64, u8)> {
    if bytes.len() != PAYLOAD {
        return None;
    }
    let word = |i: usize| {
        bytes
            .get(i..i + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes)
    };
    let kind = *bytes.get(24)?;
    if kind != DATA && kind != GOODBYE {
        return None;
    }
    Some((word(0)?, word(8)?, word(16)?, kind))
}

impl Prober {
    /// A prober writing to `report`, numbered as the next instance there.
    #[must_use]
    pub fn new(report: SharedReport) -> Self {
        let instance = {
            let mut r = report.borrow_mut();
            r.instances = r.instances.saturating_add(1);
            r.instances
        };
        Self {
            report,
            instance,
            stopped: false,
            connections: 0,
            out: BTreeMap::new(),
            incoming: BTreeMap::new(),
            streams: BTreeMap::new(),
            hung_up_now: BTreeSet::new(),
            hung_up: BTreeSet::new(),
            leaving: BTreeSet::new(),
            deadlines: BTreeMap::new(),
        }
    }

    /// Hang-ups and goodbyes this instance began and has not yet heard
    /// `on_disconnected` for.
    #[must_use]
    pub fn pending_hang_ups(&self) -> usize {
        self.hung_up.union(&self.leaving).count()
    }

    fn count(&self, what: impl FnOnce(&mut Report) -> &mut u64) {
        let mut r = self.report.borrow_mut();
        let n = what(&mut r);
        *n = n.saturating_add(1);
    }

    fn breach(&self, cx: &dyn Context, rule: Rule, what: &str) {
        let who = cx.local_id();
        let at = cx.now();
        let instance = self.instance;
        self.report
            .borrow_mut()
            .breach(rule, format!("{who} (instance {instance}) at {at}: {what}"));
    }

    fn begin(&mut self, cx: &dyn Context, call: &str) {
        self.hung_up_now.clear();
        if self.stopped {
            self.breach(cx, Rule::CallAfterStop, &format!("{call} after on_stop"));
        }
    }

    const fn timer(&self, slot: u64) -> TimerId {
        TimerId::new(
            self.instance
                .saturating_mul(TIMER_BLOCK)
                .saturating_add(slot),
        )
    }

    fn arm(&mut self, cx: &mut dyn Context, slot: u64, at: Instant) {
        let id = self.timer(slot);
        cx.set_timer(id, at);
        self.deadlines.insert(id, at);
    }

    fn disarm(&mut self, cx: &mut dyn Context, slot: u64) {
        let id = self.timer(slot);
        cx.cancel_timer(id);
        self.deadlines.remove(&id);
        self.count(|r| &mut r.cancels);
    }

    /// A connected peer this side may still write to, chosen by `r`.
    fn pick(&self, r: u64) -> Option<PeerId> {
        let open: Vec<PeerId> = self
            .out
            .keys()
            .copied()
            .filter(|q| !self.leaving.contains(q))
            .collect();
        let n = u64::try_from(open.len()).ok()?;
        if n == 0 {
            return None;
        }
        let i = usize::try_from(r % n).ok()?;
        open.get(i).copied()
    }

    /// Writes the next frame of `kind` to `to`; whether it was accepted.
    fn write(&mut self, cx: &mut dyn Context, to: PeerId, kind: u8) -> bool {
        if self.leaving.contains(&to) {
            return false;
        }
        let Some(conn) = self.out.get(&to).copied() else {
            return false;
        };
        let Some(bytes) = frame(&encode(self.instance, conn.connection, conn.next, kind)) else {
            return false;
        };
        let len = bytes.len();
        let before = cx.unsent(to);
        if before.saturating_add(len) > MAX_SEND_QUEUE {
            return false;
        }
        if cx.send(to, bytes).is_ok() {
            let after = cx.unsent(to);
            if after != before.saturating_add(len) {
                self.breach(
                    cx,
                    Rule::UnsentMiscount,
                    &format!("unsent to {to} went from {before} to {after} on a {len}-byte write"),
                );
            }
            if let Some(c) = self.out.get_mut(&to) {
                c.next = c.next.saturating_add(1);
            }
            self.count(|r| &mut r.sends);
            true
        } else {
            if !self.hung_up_now.contains(&to) {
                self.breach(
                    cx,
                    Rule::RefusedWhileConnected,
                    &format!("send to {to} refused inside the connection"),
                );
            }
            false
        }
    }

    fn hang_up(&mut self, cx: &mut dyn Context, on: PeerId) {
        cx.close(on);
        self.hung_up_now.insert(on);
        self.hung_up.insert(on);
        self.count(|r| &mut r.hang_ups);
    }

    /// The engine's way to hang up: a goodbye frame, then `close` when the
    /// goodbye timer fires or the other side hangs up, whichever comes first.
    fn say_goodbye(&mut self, cx: &mut dyn Context, to: PeerId) {
        if self.write(cx, to, GOODBYE) {
            self.leaving.insert(to);
            self.count(|r| &mut r.goodbyes_sent);
            let at = cx.now().saturating_add(GOODBYE_WAIT);
            self.arm(cx, GOODBYE_SLOT.saturating_add(to.as_u64()), at);
        }
    }

    /// Sends, hangs up (one way or the other) and touches the spare timer at
    /// random. `eager` from timers and connection changes (up to two sends);
    /// from a frame a third of the time one send, so that replies die out.
    fn act(&mut self, cx: &mut dyn Context, eager: bool) {
        if quiet(cx) {
            return;
        }
        let r = random(cx);
        if eager || r % 3 == 0 {
            if let Some(q) = self.pick(r >> 8) {
                self.write(cx, q, DATA);
            }
        }
        if (r >> 16) % 40 == 0 {
            if let Some(q) = self.pick(r >> 22) {
                if (r >> 30) % 2 == 0 {
                    self.hang_up(cx, q);
                } else {
                    self.say_goodbye(cx, q);
                }
            }
        }
        if eager && (r >> 31) % 2 == 0 {
            if let Some(q) = self.pick(r >> 32) {
                self.write(cx, q, DATA);
            }
        }
        match (r >> 40) % 5 {
            0 => {
                let at = cx
                    .now()
                    .saturating_add(Duration::from_millis(1 + (r >> 44) % 2000));
                self.arm(cx, SPARE_SLOT, at);
            }
            1 => self.disarm(cx, SPARE_SLOT),
            _ => {}
        }
    }

    /// Checks one whole frame from `from`; its kind, if it parses.
    fn check_frame(&mut self, cx: &dyn Context, from: PeerId, payload: &[u8]) -> Option<u8> {
        self.count(|r| &mut r.frames);
        let Some((instance, connection, seq, kind)) = decode(payload) else {
            self.breach(
                cx,
                Rule::Garbled,
                &format!("a {}-byte frame from {from}", payload.len()),
            );
            return None;
        };
        let expected = self.incoming.get(&from).copied();
        match expected {
            None if seq != 0 => self.breach(
                cx,
                Rule::OutOfOrder,
                &format!("first frame from {from} on this connection is number {seq}"),
            ),
            Some(e) if (e.instance, e.connection) != (instance, connection) => self.breach(
                cx,
                Rule::CrossConnection,
                &format!(
                    "from {from}: sent on its connection {instance}/{connection}, \
                     this connection carried {}/{}",
                    e.instance, e.connection
                ),
            ),
            Some(e) if e.next != seq => self.breach(
                cx,
                Rule::OutOfOrder,
                &format!("from {from}: frame {seq}, expected {}", e.next),
            ),
            _ => {}
        }
        self.incoming.insert(
            from,
            Incoming {
                instance,
                connection,
                next: seq.saturating_add(1),
            },
        );
        Some(kind)
    }
}

impl Peer for Prober {
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.begin(cx, "on_start");
        if !quiet(cx) {
            let at = cx
                .now()
                .saturating_add(Duration::from_millis(random(cx) % 2000));
            self.arm(cx, TICK_SLOT, at);
        }
    }

    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        self.begin(cx, "on_message");
        self.count(|r| &mut r.chunks);
        if bytes.is_empty() || bytes.len() > MAX_CHUNK {
            self.breach(
                cx,
                Rule::BadChunk,
                &format!("a chunk of {} bytes from {from}", bytes.len()),
            );
        }
        if !self.out.contains_key(&from) {
            self.breach(
                cx,
                Rule::MessageOutsideConnection,
                &format!("bytes from {from}"),
            );
            return;
        }
        if self.hung_up.contains(&from) {
            self.breach(cx, Rule::MessageAfterHangUp, &format!("bytes from {from}"));
        }
        let frames = match self.streams.get_mut(&from).map(|d| d.push(bytes)) {
            Some(Ok(frames)) => frames,
            Some(Err(e)) => {
                self.breach(cx, Rule::Garbled, &format!("from {from}: {e}"));
                Vec::new()
            }
            None => Vec::new(),
        };
        for payload in frames {
            if self.check_frame(cx, from, &payload) == Some(GOODBYE) {
                self.count(|r| &mut r.goodbyes_received);
                // Half the time the receiver keeps the connection open, so
                // that the goodbye's sender ends it: its own timer, or, for a
                // stopped peer, the runtime's flush.
                if !self.hung_up.contains(&from) && random(cx) % 2 == 0 {
                    self.hang_up(cx, from);
                }
            }
        }
        self.act(cx, false);
    }

    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        self.begin(cx, "on_timer");
        self.count(|r| &mut r.timers_fired);
        if id.as_u64() / TIMER_BLOCK != self.instance {
            self.breach(
                cx,
                Rule::ForeignTimer,
                &format!("timer {id}, armed by an earlier instance"),
            );
            return;
        }
        match self.deadlines.remove(&id) {
            None => self.breach(
                cx,
                Rule::UnarmedTimerFired,
                &format!("timer {id} fired unarmed"),
            ),
            Some(at) if cx.now() < at => self.breach(
                cx,
                Rule::EarlyTimer,
                &format!("timer {id} fired before its deadline {at}"),
            ),
            Some(_) => {}
        }
        let slot = id.as_u64() % TIMER_BLOCK;
        if slot == TICK_SLOT && !quiet(cx) {
            let at = cx
                .now()
                .saturating_add(Duration::from_millis(100 + random(cx) % 900));
            self.arm(cx, TICK_SLOT, at);
        } else if slot >= GOODBYE_SLOT {
            let to = PeerId::new(slot - GOODBYE_SLOT);
            if self.leaving.contains(&to) && !self.hung_up.contains(&to) {
                self.hang_up(cx, to);
            }
            return;
        }
        self.act(cx, true);
    }

    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.begin(cx, "on_connected");
        if self.out.contains_key(&peer) {
            self.breach(
                cx,
                Rule::Alternation,
                &format!("on_connected({peer}) while connected"),
            );
        }
        self.connections = self.connections.saturating_add(1);
        self.out.insert(
            peer,
            Outgoing {
                connection: self.connections,
                next: 0,
            },
        );
        self.incoming.remove(&peer);
        self.streams.insert(peer, Deframer::new(PAYLOAD));
        if quiet(cx) {
            return;
        }
        self.write(cx, peer, DATA);
        if random(cx) % 60 == 0 {
            self.hang_up(cx, peer);
        }
        self.act(cx, true);
    }

    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.begin(cx, "on_disconnected");
        if self.out.remove(&peer).is_none() {
            self.breach(
                cx,
                Rule::Alternation,
                &format!("on_disconnected({peer}) while not connected"),
            );
        }
        self.incoming.remove(&peer);
        self.streams.remove(&peer);
        self.hung_up.remove(&peer);
        if self.leaving.remove(&peer) {
            self.disarm(cx, GOODBYE_SLOT.saturating_add(peer.as_u64()));
        }
        if quiet(cx) {
            return;
        }
        let r = random(cx);
        if r % 20 == 0 {
            if let Some(q) = self.pick(r >> 8) {
                if (r >> 16) % 2 == 0 {
                    self.hang_up(cx, q);
                } else {
                    self.say_goodbye(cx, q);
                }
            }
        }
        self.act(cx, true);
    }

    fn on_stop(&mut self, cx: &mut dyn Context) {
        self.begin(cx, "on_stop");
        if !quiet(cx) {
            let peers: Vec<PeerId> = self.out.keys().copied().collect();
            for q in peers {
                if self.leaving.contains(&q) {
                    continue;
                }
                if random(cx) % 3 == 0 {
                    self.hang_up(cx, q);
                    self.count(|r| &mut r.stop_hang_ups);
                } else if self.write(cx, q, GOODBYE) {
                    self.leaving.insert(q);
                    self.count(|r| &mut r.goodbyes_sent);
                }
            }
            self.act(cx, true);
        }
        self.stopped = true;
    }
}

/// The `contract` scenario for `seed`, and the report its probers write to.
/// Five probers over a network with latencies of 1 to 300 ms that drops one
/// piece in twenty and reconnects in 10 to 500 ms; twelve crashes or clean
/// stops, each restarted 0.7 s later, rotating over the peers by seed, half of
/// them just after a reconnection round so that they find connections open;
/// peers 0 and 1 cut from 2 and 3 from 3 s to 9 s; and a reconnection of
/// every pair at 0.333 s past each second up to 24 s, the way back after a
/// hang-up. A goodbye's receiver hangs up half the time and otherwise leaves
/// the end to the goodbye's sender, so that the flush after a clean stop also
/// ends connections by draining. Converged when no prober saw a breach and
/// none still waits for an answer to a hang-up or a goodbye.
#[must_use]
pub fn scenario(seed: u64) -> (Scenario<Prober>, SharedReport) {
    let report: SharedReport = Rc::default();
    let for_peers = Rc::clone(&report);
    let for_predicate = Rc::clone(&report);
    let peers = u64::from(PEERS);
    let mut s = Scenario::new(seed, PEERS, move |_| Prober::new(Rc::clone(&for_peers)))
        .network(
            NetworkConfig::default()
                .latency(Duration::from_millis(1), Duration::from_millis(300))
                .drops(0.05)
                .reconnect(Duration::from_millis(10), Duration::from_millis(500)),
        )
        .converged_when(move |sim| {
            let held = for_predicate.borrow().breaches() == 0;
            held && sim.peers().all(|(_, p)| p.pending_hang_ups() == 0)
        });
    for k in 0..12u64 {
        let peer = PeerId::new(seed.wrapping_add(k) % peers);
        let second = 1 + 2 * k;
        let offset = if k % 4 < 2 {
            333 + 5 + (seed % 7) * 3
        } else {
            (seed % 7) * 13
        };
        let at = Instant::from_millis(second * 1000 + offset);
        s = s.fault(if k % 2 == 0 {
            Fault::Crash { peer, at }
        } else {
            Fault::Stop { peer, at }
        });
        s = s.fault(Fault::Restart {
            peer,
            at: Instant::from_millis(second * 1000 + 700),
        });
    }
    s = s.fault(Fault::Partition {
        partition: Partition::between(
            vec![PeerId::new(0), PeerId::new(1)],
            vec![PeerId::new(2), PeerId::new(3)],
        ),
        from: Instant::from_secs(3),
        until: Instant::from_secs(9),
    });
    for second in 0..25u64 {
        for a in 0..peers {
            for b in (a + 1)..peers {
                s = s.fault(Fault::Reconnect {
                    a: PeerId::new(a),
                    b: PeerId::new(b),
                    at: Instant::from_millis(second * 1000 + 333),
                });
            }
        }
    }
    (s, report)
}

/// Runs the `contract` scenario for `seed` until it is quiescent, and returns
/// the outcome with what the probers saw and what the network did. The
/// outcome is converged only when the report is clean; the
/// [`Rule::UnansweredHangUp`] entries, which the predicate counts from the
/// probers still running, are written into the returned report here so that
/// it says which peer it was.
#[must_use]
pub fn run(seed: u64) -> (Outcome, Report) {
    let (s, shared) = scenario(seed);
    let mut sim = s.build();
    let outcome = sim.run_until_quiescent(LIMIT);
    let mut report = shared.borrow().clone();
    report.net = sim.stats().clone();
    for (id, p) in sim.peers() {
        if p.pending_hang_ups() > 0 {
            report.breach(
                Rule::UnansweredHangUp,
                format!(
                    "{id} (instance {}) at the end: {} hang-up(s) never answered",
                    p.instance,
                    p.pending_hang_ups()
                ),
            );
        }
    }
    (outcome, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_anything_else_is_garbled() {
        assert_eq!(decode(&encode(3, 4, 5, DATA)), Some((3, 4, 5, DATA)));
        assert_eq!(
            decode(&encode(u64::MAX, 0, 1, GOODBYE)),
            Some((u64::MAX, 0, 1, GOODBYE))
        );
        assert_eq!(decode(&encode(1, 1, 1, 2)), None, "an unknown kind");
        assert_eq!(decode(&[0; 24]), None);
        assert_eq!(decode(&[0; 26]), None);
        assert_eq!(decode(&[]), None);
    }

    #[test]
    fn a_report_counts_by_rule_keeps_the_first_description_and_absorbs() {
        let mut a = Report::default();
        assert_eq!(a.breaches(), 0);
        a.breach(Rule::OutOfOrder, "first".into());
        a.breach(Rule::OutOfOrder, "second".into());
        a.breach(Rule::Garbled, "g".into());
        assert_eq!(a.breaches(), 3);
        assert_eq!(a.breaches_of(Rule::OutOfOrder), 2);
        assert_eq!(a.first(Rule::OutOfOrder), Some("first"));
        assert_eq!(a.breaches_of(Rule::Alternation), 0);
        assert_eq!(a.first(Rule::Alternation), None);
        let mut b = Report {
            instances: 2,
            sends: 3,
            chunks: 4,
            frames: 5,
            hang_ups: 6,
            goodbyes_sent: 7,
            goodbyes_received: 8,
            stop_hang_ups: 9,
            cancels: 10,
            timers_fired: 11,
            net: NetStats {
                opened: 12,
                ..NetStats::default()
            },
            ..Report::default()
        };
        b.breach(Rule::OutOfOrder, "b's".into());
        b.breach(Rule::CallAfterStop, "late".into());
        a.absorb(&b);
        a.absorb(&Report::default());
        assert_eq!(a.breaches_of(Rule::OutOfOrder), 3);
        assert_eq!(a.first(Rule::OutOfOrder), Some("first"));
        assert_eq!(a.first(Rule::CallAfterStop), Some("late"));
        assert_eq!(
            [
                a.instances(),
                a.sends(),
                a.chunks(),
                a.frames(),
                a.hang_ups(),
                a.goodbyes_sent(),
                a.goodbyes_received(),
                a.stop_hang_ups(),
                a.cancels(),
                a.timers_fired(),
                a.net().opened
            ],
            [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        );
        let text = a.to_string();
        assert!(
            text.starts_with("5 breaches; 2 instances, 3 sends, 5 frames checked in 4 chunks"),
            "{text}"
        );
        assert!(text.contains("network: 12 connections opened"), "{text}");
        assert!(text.contains("OutOfOrder: 3, first: first"), "{text}");
        assert!(text.contains("CallAfterStop: 1, first: late"), "{text}");
        assert_eq!(Rule::ALL.len(), 14);
    }

    #[test]
    fn instances_are_numbered_in_the_order_they_are_built_and_own_their_timer_blocks() {
        let report: SharedReport = Rc::default();
        let a = Prober::new(Rc::clone(&report));
        let b = Prober::new(Rc::clone(&report));
        assert_eq!((a.instance, b.instance), (1, 2));
        assert_eq!(report.borrow().instances(), 2);
        assert_eq!(a.pending_hang_ups(), 0);
        assert_eq!(a.timer(TICK_SLOT), TimerId::new(16));
        assert_eq!(b.timer(SPARE_SLOT), TimerId::new(33));
        assert_eq!(
            b.timer(GOODBYE_SLOT + u64::from(PEERS) - 1).as_u64() / TIMER_BLOCK,
            2,
            "every goodbye timer of an instance stays in its block"
        );
    }
}
