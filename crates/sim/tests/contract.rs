// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The runtime contract around hang-ups, from the inside: a handler's effects
//! take effect in the order it asked for them and before anyone hears of the
//! close it asked for; every peer hears its connections end in the order they
//! closed; a peer not yet told may still send, and the message is lost; a
//! stopped peer is never called again. One scripted peer per case, each case
//! named after what it pins, then the `contract` probers over a few seeds.

use core::cell::RefCell;
use core::time::Duration;
use std::collections::BTreeSet;
use std::rc::Rc;

use licketysync_engine::runtime::{Context, Instant, Peer, PeerId, TimerId};
use licketysync_sim::contract::{self, Report};
use licketysync_sim::toy::LIMIT;
use licketysync_sim::trace::DropReason;
use licketysync_sim::{EventKind, Fault, Partition, Scenario, TraceEvent};

const fn p(id: u64) -> PeerId {
    PeerId::new(id)
}

const T: TimerId = TimerId::new(7);
const KICK: TimerId = TimerId::new(1);

/// Every handler call and every send, as lines such as `p1 connected p0` or
/// `p1 send up to p2: accepted`, in the order they happened.
type Log = Rc<RefCell<Vec<String>>>;

/// What a scripted peer was called for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Start,
    Message(PeerId),
    Timer(TimerId),
    Connected(PeerId),
    Disconnected(PeerId),
    Stop,
}

/// The part of a case that differs: what the peer does on each call.
type Script = fn(&mut Scripted, &mut dyn Context, Call);

/// A peer that logs every call and send, keeps its own view of whom it is
/// connected to, and logs `BREACH` when the runtime refuses a send inside a
/// connection or calls it after `on_stop`.
struct Scripted {
    log: Log,
    script: Script,
    connected: BTreeSet<PeerId>,
    closed_now: BTreeSet<PeerId>,
    stopped: bool,
}

impl Scripted {
    fn note(&self, cx: &dyn Context, what: &str) {
        let me = cx.local_id();
        self.log.borrow_mut().push(format!("{me} {what}"));
    }

    fn enter(&mut self, cx: &mut dyn Context, call: Call, what: &str) {
        self.closed_now.clear();
        if self.stopped {
            self.note(cx, &format!("BREACH {what} after on_stop"));
        }
        match call {
            Call::Connected(q) => {
                self.connected.insert(q);
            }
            Call::Disconnected(q) => {
                self.connected.remove(&q);
            }
            _ => {}
        }
        self.note(cx, what);
        (self.script)(self, cx, call);
    }

    fn send(&mut self, cx: &mut dyn Context, to: PeerId, text: &str) {
        let accepted = cx.send(to, text.as_bytes().to_vec()).is_ok();
        if !accepted && self.connected.contains(&to) && !self.closed_now.contains(&to) {
            self.note(
                cx,
                &format!("BREACH send to {to} refused inside the connection"),
            );
        }
        let verdict = if accepted { "accepted" } else { "refused" };
        self.note(cx, &format!("send {text} to {to}: {verdict}"));
    }

    fn close(&mut self, cx: &mut dyn Context, to: PeerId) {
        cx.close(to);
        self.closed_now.insert(to);
        self.note(cx, &format!("close {to}"));
    }
}

impl Peer for Scripted {
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.enter(cx, Call::Start, "start");
    }
    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes).into_owned();
        self.enter(
            cx,
            Call::Message(from),
            &format!("message {text} from {from}"),
        );
    }
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        self.enter(cx, Call::Timer(id), &format!("timer {id} fired"));
    }
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.enter(cx, Call::Connected(peer), &format!("connected {peer}"));
    }
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        self.enter(
            cx,
            Call::Disconnected(peer),
            &format!("disconnected {peer}"),
        );
    }
    fn on_stop(&mut self, cx: &mut dyn Context) {
        self.enter(cx, Call::Stop, "stop");
        self.stopped = true;
    }
}

fn scripted(seed: u64, peers: u32, script: Script) -> (Log, Scenario<Scripted>) {
    let log: Log = Rc::default();
    let shared = Rc::clone(&log);
    let scenario = Scenario::new(seed, peers, move |_| Scripted {
        log: Rc::clone(&shared),
        script,
        connected: BTreeSet::new(),
        closed_now: BTreeSet::new(),
        stopped: false,
    })
    .record_trace(true);
    (log, scenario)
}

/// The lines of `log` that start with `prefix`, without it.
fn lines(log: &Log, prefix: &str) -> Vec<String> {
    log.borrow()
        .iter()
        .filter_map(|l| l.strip_prefix(prefix).map(str::to_owned))
        .collect()
}

fn breaches(log: &Log) -> Vec<String> {
    log.borrow()
        .iter()
        .filter(|l| l.contains("BREACH"))
        .cloned()
        .collect()
}

fn count(trace: &[TraceEvent], pred: impl Fn(&EventKind) -> bool) -> usize {
    trace.iter().filter(|e| pred(&e.kind)).count()
}

/// p0 hangs up on p1 from inside `on_connected`. p1, in its own
/// `on_connected(p0)`, arms a timer and tells p2 "up"; in `on_disconnected(p0)`
/// it cancels the timer and tells p2 "down". The scenario reconnects p0 and p1
/// at 5 s, by which time p1 and p2 are connected too.
fn bounce_with_effects(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    match call {
        Call::Connected(q) if id == p(0) && q == p(1) => me.close(cx, q),
        Call::Connected(q) if id == p(1) && q == p(0) => {
            let at = cx.now().saturating_add(Duration::from_secs(1));
            cx.set_timer(T, at);
            me.send(cx, p(2), "up");
        }
        Call::Disconnected(q) if id == p(1) && q == p(0) => {
            cx.cancel_timer(T);
            me.send(cx, p(2), "down");
        }
        _ => {}
    }
}

#[test]
fn a_hang_up_inside_on_connected_lets_the_other_sides_on_connected_effects_take_effect_before_its_on_disconnected(
) {
    let (log, scenario) = scripted(1, 3, bounce_with_effects);
    let mut sim = scenario
        .fault(Fault::Reconnect {
            a: p(0),
            b: p(1),
            at: Instant::from_secs(5),
        })
        .build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert!(
        !log.borrow().iter().any(|l| l.contains("timer t7 fired")),
        "p1 armed the timer in on_connected and cancelled it in on_disconnected: {:?}",
        log.borrow()
    );
    assert_eq!(
        lines(&log, "p2 message "),
        vec!["up from p1".to_owned(), "down from p1".to_owned()],
        "p2 hears p1's messages in the order p1 sent them"
    );
    let p1: Vec<String> = lines(&log, "p1 ")
        .into_iter()
        .filter(|l| l.ends_with(" p0"))
        .collect();
    assert_eq!(
        p1,
        vec![
            "connected p0",
            "disconnected p0",
            "connected p0",
            "disconnected p0"
        ],
        "and p1's calls about p0 alternate"
    );
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// p1, on a timer at 1 s, hangs up on p0, then tells p2 "A" and arms a timer;
/// in `on_disconnected(p0)` it tells p2 "B" and cancels that timer.
fn close_then_carry_on(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    match call {
        Call::Start if id == p(1) => cx.set_timer(KICK, Instant::from_secs(1)),
        Call::Timer(KICK) => {
            me.close(cx, p(0));
            me.send(cx, p(2), "A");
            let at = cx.now().saturating_add(Duration::from_secs(1));
            cx.set_timer(T, at);
        }
        Call::Disconnected(q) if id == p(1) && q == p(0) => {
            me.send(cx, p(2), "B");
            cx.cancel_timer(T);
        }
        _ => {}
    }
}

#[test]
fn a_handler_that_hangs_up_has_all_its_effects_applied_in_order_before_on_disconnected_runs() {
    let (log, scenario) = scripted(1, 3, close_then_carry_on);
    let mut sim = scenario.build();
    let o = sim.run_until(Instant::from_secs(10));
    assert!(!o.exhausted, "{o}");
    assert!(
        !log.borrow().iter().any(|l| l.contains("timer t7 fired")),
        "armed after the close in the same handler, cancelled in the on_disconnected that followed: {:?}",
        log.borrow()
    );
    assert_eq!(
        lines(&log, "p2 message "),
        vec!["A from p1".to_owned(), "B from p1".to_owned()],
        "A was sent first and arrives first"
    );
    assert_eq!(
        lines(&log, "p1 "),
        vec![
            "start",
            "connected p0",
            "connected p2",
            "timer t1 fired",
            "close p0",
            "send A to p2: accepted",
            "disconnected p0",
            "send B to p2: accepted",
        ],
        "p1 hears on_disconnected(p0) only after the closing handler returned"
    );
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// p0 crashes at 1 s. p1, hearing of it, hangs up on p2; p2, hearing p1 hang
/// up, tries to send to p0.
fn crash_provokes_hang_up(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    match call {
        Call::Disconnected(q) if id == p(1) && q == p(0) => me.close(cx, p(2)),
        Call::Disconnected(q) if id == p(2) && q == p(1) => me.send(cx, p(0), "x"),
        _ => {}
    }
}

#[test]
fn every_peer_hears_of_a_crash_before_it_hears_of_the_hang_ups_the_crash_provoked() {
    let (log, scenario) = scripted(1, 3, crash_provokes_hang_up);
    let mut sim = scenario
        .fault(Fault::Crash {
            peer: p(0),
            at: Instant::from_secs(1),
        })
        .build();
    sim.run_until(Instant::from_secs(2));
    let ends = |prefix: &str| -> Vec<String> {
        lines(&log, prefix)
            .into_iter()
            .filter(|l| l.starts_with("disconnected"))
            .collect()
    };
    assert_eq!(ends("p1 "), vec!["disconnected p0", "disconnected p2"]);
    assert_eq!(
        ends("p2 "),
        vec!["disconnected p0", "disconnected p1"],
        "p2 hears of p0's crash before p1's hang-up, which came after it"
    );
    assert_eq!(
        lines(&log, "p2 send "),
        vec!["x to p0: refused"],
        "refused because p2 had already been told p0 was gone"
    );
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// A partition at 1 s cuts p0 from p1 and p2 at once; hearing of p1, p0 sends
/// to p2, of which it has not heard yet.
fn told_one_at_a_time(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if cx.local_id() == p(0) && call == Call::Disconnected(p(1)) {
        me.send(cx, p(2), "still here?");
    }
}

#[test]
fn a_peer_not_yet_told_that_a_connection_closed_may_still_send_on_it_and_the_message_is_lost() {
    let (log, scenario) = scripted(1, 3, told_one_at_a_time);
    let mut sim = scenario
        .fault(Fault::Partition {
            partition: Partition::isolate(p(0), [p(1), p(2)]),
            from: Instant::from_secs(1),
            until: Instant::from_secs(60),
        })
        .build();
    sim.run_until(Instant::from_secs(2));
    assert_eq!(
        lines(&log, "p0 "),
        vec![
            "start",
            "connected p1",
            "connected p2",
            "disconnected p1",
            "send still here? to p2: accepted",
            "disconnected p2",
        ],
        "inside its connection to p2 as far as p0 knows, so the send is accepted"
    );
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Closed,
                ..
            }
        )),
        1,
        "and lost before it left: the connection had already closed"
    );
    assert_eq!(lines(&log, "p2 message"), Vec::<String>::new());
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// p0 stops cleanly at 1 s and hangs up on p1 from inside `on_stop`.
fn hang_up_on_stop(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if call == Call::Stop {
        me.close(cx, p(1));
    }
}

#[test]
fn a_hang_up_inside_on_stop_reaches_the_other_side_and_never_calls_the_stopped_peer_again() {
    let (log, scenario) = scripted(1, 2, hang_up_on_stop);
    let mut sim = scenario
        .fault(Fault::Stop {
            peer: p(0),
            at: Instant::from_secs(1),
        })
        .build();
    sim.run_until(Instant::from_secs(2));
    assert_eq!(
        lines(&log, "p0 "),
        vec!["start", "connected p1", "stop", "close p1"],
        "nothing after on_stop"
    );
    assert_eq!(
        lines(&log, "p1 "),
        vec!["start", "connected p0", "disconnected p0"],
        "p1 hears once"
    );
    let trace = sim.trace().unwrap_or_default();
    let order: Vec<&EventKind> = trace
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::Close(_) | EventKind::Stop | EventKind::Disconnected(_)
            )
        })
        .map(|e| &e.kind)
        .collect();
    assert_eq!(
        order,
        vec![
            &EventKind::Close(p(1)),
            &EventKind::Stop,
            &EventKind::Disconnected(p(0))
        ]
    );
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// p0, on a timer at 1 s, hangs up on p1; hearing of it, p0 hangs up on p2;
/// p2, hearing of that, hangs up on p1; p1, hearing of that, sends to p0.
fn chain_of_hang_ups(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    match call {
        Call::Start if id == p(0) => cx.set_timer(KICK, Instant::from_secs(1)),
        Call::Timer(KICK) => me.close(cx, p(1)),
        Call::Disconnected(q) if id == p(0) && q == p(1) => me.close(cx, p(2)),
        Call::Disconnected(q) if id == p(2) && q == p(0) => me.close(cx, p(1)),
        Call::Disconnected(q) if id == p(1) && q == p(2) => me.send(cx, p(0), "x"),
        _ => {}
    }
}

#[test]
fn nested_hang_ups_reach_each_peer_in_the_order_its_connections_closed() {
    let (log, scenario) = scripted(1, 3, chain_of_hang_ups);
    let mut sim = scenario.build();
    sim.run_until(Instant::from_secs(2));
    let ends: Vec<String> = log
        .borrow()
        .iter()
        .filter(|l| l.contains(" disconnected "))
        .cloned()
        .collect();
    assert_eq!(
        ends,
        vec![
            "p0 disconnected p1",
            "p1 disconnected p0",
            "p0 disconnected p2",
            "p2 disconnected p0",
            "p2 disconnected p1",
            "p1 disconnected p2",
        ],
        "first in first out: each close's two notices, the closer first, behind those already waiting"
    );
    assert_eq!(
        lines(&log, "p1 send "),
        vec!["x to p0: refused"],
        "refused after p1 heard p0 was gone, not before"
    );
    assert_eq!(breaches(&log), Vec::<String>::new());
}

#[test]
fn the_runtime_keeps_its_contract_with_peers_that_hang_up_send_and_rearm_from_every_handler() {
    let mut all = Report::default();
    for seed in 0..8 {
        let (o, r) = contract::run(seed);
        assert!(o.converged && o.quiescent, "seed {seed}: {o}{r}");
        all.absorb(&r);
    }
    assert_eq!(all.breaches(), 0, "{all}");
    assert!(
        all.messages() > 1000
            && all.sends() > all.messages()
            && all.hang_ups() > 1000
            && all.cancels() > 1000
            && all.instances() > 100,
        "the probers did enough of everything for a clean report to mean something: {all}"
    );
    assert_eq!(
        contract::run(3),
        contract::run(3),
        "a contract run replays from its seed"
    );
}
