// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A peer that checks the runtime contract from the inside, and the
//! `contract` scenario that runs five of them under every fault at once.
//!
//! [`Prober`] behaves like the engine at its most awkward: from every handler,
//! `on_connected`, `on_disconnected` and `on_stop` included, it sends, hangs
//! up and arms or cancels a timer at random, while the scenario crashes, stops
//! and restarts peers, partitions them, reconnects every pair once a second
//! and the network drops connections. Each instance checks, as the calls
//! arrive, what the engine's runtime documentation promises it, one [`Rule`]
//! each: calls about a peer alternate between `on_connected` and
//! `on_disconnected`; messages arrive only inside a connection, all from the
//! sender's side of that same connection, each exactly once and in the order
//! sent, and never after this side hung up; a send to a peer it has heard
//! `on_connected` for, and not `on_disconnected`, is accepted unless it hung
//! up on that peer in the same handler; a timer fires only while armed;
//! nothing is called after `on_stop`; and every hang-up is answered by
//! `on_disconnected`. A breach goes into the [`Report`] every instance
//! shares, and the scenario converges only when there is none. The probers
//! stop acting at [`QUIET_AFTER`] so that the network drains and the run ends
//! quiescent.

use core::cell::RefCell;
use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::runtime::{Context, Instant, Peer, PeerId, TimerId};

use crate::network::{NetworkConfig, Partition};
use crate::scenario::{Fault, Outcome, Scenario};
use crate::toy::LIMIT;

/// The probers' own clock time after which they only check: no sends, hang-ups
/// or timers. The last scheduled fault is a second earlier.
pub const QUIET_AFTER: Instant = Instant::from_secs(25);

/// How many probers the scenario runs.
pub const PEERS: u32 = 5;

/// The prober's tick: it acts on every one.
const KICK: TimerId = TimerId::new(1);

/// The timer it arms and cancels at random, to check cancellation.
const AUX: TimerId = TimerId::new(2);

/// A promise of the runtime documentation that a prober checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// `on_connected` for a peer already connected, or `on_disconnected` for
    /// one that is not.
    Alternation,
    /// A message from a peer this side has not heard `on_connected` for.
    MessageOutsideConnection,
    /// A message from a peer after this side hung up on it.
    MessageAfterHangUp,
    /// Within one connection, a message the sender sent on another one.
    CrossConnection,
    /// Within one connection, a message other than the next one sent: lost,
    /// duplicated or overtaken.
    OutOfOrder,
    /// A message that no prober sends.
    Garbled,
    /// A send refused although this side had heard `on_connected` for the
    /// peer, no `on_disconnected` since, and had not hung up on it in the
    /// same handler.
    RefusedWhileConnected,
    /// A timer fired that was cancelled, had fired already or was never armed.
    UnarmedTimerFired,
    /// A handler was called after `on_stop`.
    CallAfterStop,
    /// A running peer hung up and never heard `on_disconnected` for it.
    UnansweredHangUp,
}

impl Rule {
    /// Every rule, in report order.
    pub const ALL: [Self; 10] = [
        Self::Alternation,
        Self::MessageOutsideConnection,
        Self::MessageAfterHangUp,
        Self::CrossConnection,
        Self::OutOfOrder,
        Self::Garbled,
        Self::RefusedWhileConnected,
        Self::UnarmedTimerFired,
        Self::CallAfterStop,
        Self::UnansweredHangUp,
    ];
}

/// What the probers of one or more runs saw: each breach by rule (a count
/// and the first description), and how much they did, so that a clean report
/// can be told from one where nothing was tried.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    breaches: BTreeMap<Rule, (u64, String)>,
    instances: u64,
    sends: u64,
    messages: u64,
    hang_ups: u64,
    cancels: u64,
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

    /// Messages that arrived and were checked.
    #[must_use]
    pub const fn messages(&self) -> u64 {
        self.messages
    }

    /// Hang-ups asked for.
    #[must_use]
    pub const fn hang_ups(&self) -> u64 {
        self.hang_ups
    }

    /// Timer cancellations asked for.
    #[must_use]
    pub const fn cancels(&self) -> u64 {
        self.cancels
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
        self.instances = self.instances.saturating_add(other.instances);
        self.sends = self.sends.saturating_add(other.sends);
        self.messages = self.messages.saturating_add(other.messages);
        self.hang_ups = self.hang_ups.saturating_add(other.hang_ups);
        self.cancels = self.cancels.saturating_add(other.cancels);
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
            "{} breaches; {} instances, {} sends, {} messages checked, {} hang-ups, {} cancels",
            self.breaches(),
            self.instances,
            self.sends,
            self.messages,
            self.hang_ups,
            self.cancels
        )?;
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

/// What this side expects next on one connection, once the first message has
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
    /// Hung up on in the current handler: a send to them is refused.
    hung_up_now: BTreeSet<PeerId>,
    /// Hung up on, `on_disconnected` not yet heard.
    hung_up: BTreeSet<PeerId>,
    aux_armed: bool,
}

fn random(cx: &mut dyn Context) -> u64 {
    let mut b = [0u8; 8];
    cx.fill_random(&mut b);
    u64::from_le_bytes(b)
}

fn quiet(cx: &dyn Context) -> bool {
    cx.now() >= QUIET_AFTER
}

fn encode(instance: u64, connection: u64, seq: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(24);
    m.extend_from_slice(&instance.to_be_bytes());
    m.extend_from_slice(&connection.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m
}

fn decode(bytes: &[u8]) -> Option<(u64, u64, u64)> {
    if bytes.len() != 24 {
        return None;
    }
    let word = |i: usize| {
        bytes
            .get(i..i + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes)
    };
    Some((word(0)?, word(8)?, word(16)?))
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
            hung_up_now: BTreeSet::new(),
            hung_up: BTreeSet::new(),
            aux_armed: false,
        }
    }

    /// Hang-ups this instance asked for and has not yet heard
    /// `on_disconnected` for.
    #[must_use]
    pub fn pending_hang_ups(&self) -> usize {
        self.hung_up.len()
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

    fn pick(&self, r: u64) -> Option<PeerId> {
        let n = u64::try_from(self.out.len()).ok()?;
        if n == 0 {
            return None;
        }
        let i = usize::try_from(r % n).ok()?;
        self.out.keys().nth(i).copied()
    }

    fn send(&mut self, cx: &mut dyn Context, to: PeerId) {
        let Some(conn) = self.out.get(&to).copied() else {
            return;
        };
        let message = encode(self.instance, conn.connection, conn.next);
        if cx.send(to, message).is_ok() {
            if let Some(c) = self.out.get_mut(&to) {
                c.next = c.next.saturating_add(1);
            }
            let mut r = self.report.borrow_mut();
            r.sends = r.sends.saturating_add(1);
        } else if !self.hung_up_now.contains(&to) {
            self.breach(
                cx,
                Rule::RefusedWhileConnected,
                &format!("send to {to} refused inside the connection"),
            );
        }
    }

    fn hang_up(&mut self, cx: &mut dyn Context, on: PeerId) {
        cx.close(on);
        self.hung_up_now.insert(on);
        self.hung_up.insert(on);
        let mut r = self.report.borrow_mut();
        r.hang_ups = r.hang_ups.saturating_add(1);
    }

    /// Sends, hangs up and touches the spare timer at random. `eager` from
    /// timers and connection changes (up to two sends); from `on_message` a
    /// third of the time one send, so that replies die out.
    fn act(&mut self, cx: &mut dyn Context, eager: bool) {
        if quiet(cx) {
            return;
        }
        let r = random(cx);
        if eager || r % 3 == 0 {
            if let Some(q) = self.pick(r >> 8) {
                self.send(cx, q);
            }
        }
        if (r >> 16) % 7 == 0 {
            if let Some(q) = self.pick(r >> 20) {
                self.hang_up(cx, q);
            }
        }
        if eager && (r >> 28) % 2 == 0 {
            if let Some(q) = self.pick(r >> 32) {
                self.send(cx, q);
            }
        }
        match (r >> 40) % 5 {
            0 => {
                let at = cx
                    .now()
                    .saturating_add(Duration::from_millis(1 + (r >> 44) % 500));
                cx.set_timer(AUX, at);
                self.aux_armed = true;
            }
            1 => {
                cx.cancel_timer(AUX);
                self.aux_armed = false;
                let mut rep = self.report.borrow_mut();
                rep.cancels = rep.cancels.saturating_add(1);
            }
            _ => {}
        }
    }

    fn check_message(&mut self, cx: &dyn Context, from: PeerId, bytes: &[u8]) {
        if !self.out.contains_key(&from) {
            self.breach(
                cx,
                Rule::MessageOutsideConnection,
                &format!("message from {from}"),
            );
        }
        if self.hung_up.contains(&from) {
            self.breach(
                cx,
                Rule::MessageAfterHangUp,
                &format!("message from {from}"),
            );
        }
        let Some((instance, connection, seq)) = decode(bytes) else {
            self.breach(
                cx,
                Rule::Garbled,
                &format!("{} bytes from {from}", bytes.len()),
            );
            return;
        };
        let expected = self.incoming.get(&from).copied();
        match expected {
            None if seq != 0 => self.breach(
                cx,
                Rule::OutOfOrder,
                &format!("first message from {from} on this connection is number {seq}"),
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
                &format!("from {from}: message {seq}, expected {}", e.next),
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
    }
}

impl Peer for Prober {
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.begin(cx, "on_start");
        if !quiet(cx) {
            let at = cx
                .now()
                .saturating_add(Duration::from_millis(random(cx) % 2000));
            cx.set_timer(KICK, at);
        }
    }

    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        self.begin(cx, "on_message");
        {
            let mut r = self.report.borrow_mut();
            r.messages = r.messages.saturating_add(1);
        }
        self.check_message(cx, from, bytes);
        self.act(cx, false);
    }

    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        self.begin(cx, "on_timer");
        if id == AUX {
            if !self.aux_armed {
                self.breach(cx, Rule::UnarmedTimerFired, "the spare timer fired unarmed");
            }
            self.aux_armed = false;
        } else if id == KICK && !quiet(cx) {
            let at = cx
                .now()
                .saturating_add(Duration::from_millis(100 + random(cx) % 900));
            cx.set_timer(KICK, at);
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
        if quiet(cx) {
            return;
        }
        self.send(cx, peer);
        if random(cx) % 5 == 0 {
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
        self.hung_up.remove(&peer);
        if quiet(cx) {
            return;
        }
        let r = random(cx);
        if r % 3 == 0 {
            if let Some(q) = self.pick(r >> 8) {
                self.hang_up(cx, q);
            }
        }
        self.act(cx, true);
    }

    fn on_stop(&mut self, cx: &mut dyn Context) {
        self.begin(cx, "on_stop");
        self.act(cx, true);
        self.stopped = true;
    }
}

/// The `contract` scenario for `seed`, and the report its probers write to.
/// Five probers over a network with latencies of 1 to 300 ms that drops one
/// message in twenty and reconnects in 10 to 500 ms; twelve crashes or clean
/// stops, each restarted 0.7 s later, rotating over the peers by seed; peers
/// 0 and 1 cut from 2 and 3 from 3 s to 9 s; and a reconnection of every pair
/// at 0.333 s past each second up to 24 s, the way back after a hang-up.
/// Converged when no prober saw a breach and none still waits for an answer
/// to a hang-up.
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
        let at = Instant::from_millis(second * 1000 + (seed % 7) * 13);
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
/// the outcome with what the probers saw. The outcome is converged only when
/// the report is clean; the [`Rule::UnansweredHangUp`] entries, which the
/// predicate counts from the probers still running, are written into the
/// returned report here so that it says which peer it was.
#[must_use]
pub fn run(seed: u64) -> (Outcome, Report) {
    let (s, shared) = scenario(seed);
    let mut sim = s.build();
    let outcome = sim.run_until_quiescent(LIMIT);
    let mut report = shared.borrow().clone();
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
    fn messages_round_trip_and_anything_else_is_garbled() {
        assert_eq!(decode(&encode(3, 4, 5)), Some((3, 4, 5)));
        assert_eq!(decode(&encode(u64::MAX, 0, 1)), Some((u64::MAX, 0, 1)));
        assert_eq!(decode(&[0; 23]), None);
        assert_eq!(decode(&[0; 25]), None);
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
            messages: 4,
            hang_ups: 5,
            cancels: 6,
            ..Report::default()
        };
        b.breach(Rule::OutOfOrder, "b's".into());
        b.breach(Rule::CallAfterStop, "late".into());
        a.absorb(&b);
        assert_eq!(a.breaches_of(Rule::OutOfOrder), 3);
        assert_eq!(a.first(Rule::OutOfOrder), Some("first"));
        assert_eq!(a.first(Rule::CallAfterStop), Some("late"));
        assert_eq!(
            (
                a.instances(),
                a.sends(),
                a.messages(),
                a.hang_ups(),
                a.cancels()
            ),
            (2, 3, 4, 5, 6)
        );
        let text = a.to_string();
        assert!(
            text.starts_with("5 breaches; 2 instances, 3 sends"),
            "{text}"
        );
        assert!(text.contains("OutOfOrder: 3, first: first"), "{text}");
        assert!(text.contains("CallAfterStop: 1, first: late"), "{text}");
        assert_eq!(Rule::ALL.len(), 10);
    }

    #[test]
    fn instances_are_numbered_in_the_order_they_are_built() {
        let report: SharedReport = Rc::default();
        let a = Prober::new(Rc::clone(&report));
        let b = Prober::new(Rc::clone(&report));
        assert_eq!((a.instance, b.instance), (1, 2));
        assert_eq!(report.borrow().instances(), 2);
        assert_eq!(a.pending_hang_ups(), 0);
    }
}
