// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The runtime contract around hang-ups and the byte stream, from the inside,
//! one side at a time: a handler's effects take effect in the order it asked
//! for them and before this side hears of the close it asked for; a side hears
//! of its own connections' ends one at a time; a side not yet told may still
//! send, and the bytes may be lost; what was in flight at an end may arrive
//! before `on_disconnected` or not at all, always as a prefix; what `on_stop`
//! writes is flushed for up to a second, and a restart during the flush ends
//! the old connection before the new one opens; a stopped peer is never called
//! again; chunks hold 1 to 64 KiB, split anywhere; a write past the send queue
//! ends the connection, and a writer that paces on `unsent` never gets there.
//! Where a test pins an order across peers, it is named as a property of this
//! simulator, which the contract does not promise. One scripted peer per case,
//! each case named after what it pins, then the `contract` probers over a few
//! seeds.

use core::cell::RefCell;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::runtime::{Context, Instant, Peer, PeerId, TimerId, MAX_CHUNK};
use licketysync_sim::contract::{self, Report};
use licketysync_sim::frame::{frame, Deframer};
use licketysync_sim::scenario::STOP_FLUSH;
use licketysync_sim::toy::LIMIT;
use licketysync_sim::trace::DropReason;
use licketysync_sim::{EventKind, Fault, NetworkConfig, Partition, Scenario, TraceEvent};

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

/// A peer that logs every call, every whole frame it receives and every send,
/// keeps its own view of whom it is connected to, and logs `BREACH` when the
/// runtime refuses a send inside a connection, calls it after `on_stop`, or
/// hands it a chunk outside 1 to 64 KiB. Its sends are frames (the
/// simulator's length-prefix format), reassembled per connection, so its log
/// shows messages whatever the chunk boundaries.
struct Scripted {
    log: Log,
    script: Script,
    connected: BTreeSet<PeerId>,
    closed_now: BTreeSet<PeerId>,
    streams: BTreeMap<PeerId, Deframer>,
    stopped: bool,
}

/// The longest frame a scripted peer accepts.
const SCRIPTED_FRAME: usize = 1 << 20;

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
                self.streams.insert(q, Deframer::new(SCRIPTED_FRAME));
            }
            Call::Disconnected(q) => {
                self.connected.remove(&q);
                self.streams.remove(&q);
            }
            _ => {}
        }
        self.note(cx, what);
        (self.script)(self, cx, call);
    }

    fn send(&mut self, cx: &mut dyn Context, to: PeerId, text: &str) {
        let bytes = frame(text.as_bytes()).unwrap_or_default();
        let accepted = cx.send(to, bytes).is_ok();
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
        if bytes.is_empty() || bytes.len() > MAX_CHUNK {
            self.note(cx, &format!("BREACH a chunk of {} bytes", bytes.len()));
        }
        let frames = match self.streams.get_mut(&from).map(|d| d.push(bytes)) {
            Some(Ok(frames)) => frames,
            Some(Err(e)) => {
                self.note(cx, &format!("BREACH garbled from {from}: {e}"));
                Vec::new()
            }
            None => {
                self.note(
                    cx,
                    &format!("BREACH bytes from {from} outside a connection"),
                );
                Vec::new()
            }
        };
        for payload in frames {
            let text = String::from_utf8_lossy(&payload).into_owned();
            self.enter(
                cx,
                Call::Message(from),
                &format!("message {text} from {from}"),
            );
        }
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
        streams: BTreeMap::new(),
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

/// A property of this simulator, which keeps one queue of notices for every
/// peer: a peer hears of a crash before it hears of a hang-up the crash
/// provoked elsewhere. The runtime contract promises nothing of the kind
/// across machines (a crashed peer may be learned of only by a timeout); what
/// it does promise per side, that no refusal comes inside a connection, holds
/// here too.
#[test]
fn the_simulator_reports_a_crash_before_the_hang_ups_it_provoked() {
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

/// A property of this simulator: the notices of nested hang-ups are
/// delivered first in first out across all peers, each close's two notices
/// with the closer's first. The runtime contract promises only each side's
/// own order, which this run shows too (p1 hears p0's end before p2's).
#[test]
fn the_simulator_delivers_the_notices_of_nested_hang_ups_first_in_first_out() {
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

/// A fixed one-way latency, so that a case can say what is in flight when.
fn fixed(ms: u64) -> NetworkConfig {
    NetworkConfig::default().latency(Duration::from_millis(ms), Duration::from_millis(ms))
}

fn frames_from(log: &Log, receiver: &str, sender: &str) -> Vec<String> {
    lines(log, &format!("{receiver} message "))
        .into_iter()
        .filter_map(|l| {
            l.strip_suffix(&format!(" from {sender}"))
                .map(str::to_owned)
        })
        .collect()
}

/// p0 writes ten frames to p1 at 1 s and hangs up at 1.05 s, while all of
/// them are still travelling (the network takes 100 ms).
fn write_ten_then_hang_up(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if cx.local_id() != p(0) {
        return;
    }
    match call {
        Call::Start => {
            cx.set_timer(KICK, Instant::from_secs(1));
            cx.set_timer(T, Instant::from_millis(1050));
        }
        Call::Timer(KICK) => {
            for i in 0..10 {
                me.send(cx, p(1), &format!("f{i}"));
            }
        }
        Call::Timer(_) => me.close(cx, p(1)),
        _ => {}
    }
}

#[test]
fn bytes_in_flight_when_a_connection_ends_arrive_before_on_disconnected_as_a_prefix_or_not_at_all()
{
    let all: Vec<String> = (0..10).map(|i| format!("f{i}")).collect();
    let run = |seed: u64, deliver: f64| {
        let (log, scenario) = scripted(seed, 2, write_ten_then_hang_up);
        let mut sim = scenario
            .network(fixed(100).deliver_at_close(deliver))
            .build();
        sim.run_until(Instant::from_secs(3));
        let p1 = lines(&log, "p1 ");
        let ends = p1.iter().position(|l| l == "disconnected p0");
        let last_frame = p1.iter().rposition(|l| l.starts_with("message "));
        assert!(
            last_frame.is_none() || last_frame < ends,
            "whatever arrives, arrives before on_disconnected: {p1:?}"
        );
        assert_eq!(breaches(&log), Vec::<String>::new());
        frames_from(&log, "p1", "p0")
    };
    assert_eq!(run(1, 1.0), all, "every piece in flight still arrives");
    assert_eq!(run(1, 0.0), Vec::<String>::new(), "none does");
    let mut seen = BTreeSet::new();
    for seed in 0..40 {
        let got = run(seed, 0.5);
        assert_eq!(
            got.as_slice(),
            all.get(..got.len()).unwrap_or_default(),
            "seed {seed}: always a prefix, never a gap"
        );
        seen.insert(got.len());
    }
    assert!(
        seen.contains(&0) && seen.len() >= 3,
        "both outcomes happen, and partial prefixes too: {seen:?}"
    );
}

/// p0 stops at 1 s and writes "bye" to p1 from `on_stop`.
fn goodbye_from_on_stop(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if call == Call::Stop {
        me.send(cx, p(1), "bye");
    }
}

#[test]
fn what_on_stop_writes_is_flushed_for_up_to_a_second_and_then_may_be_lost() {
    let run = |network: NetworkConfig| {
        let (log, scenario) = scripted(1, 2, goodbye_from_on_stop);
        let mut sim = scenario
            .network(network)
            .fault(Fault::Stop {
                peer: p(0),
                at: Instant::from_secs(1),
            })
            .build();
        sim.run_until(Instant::from_secs(10));
        let ended = sim
            .trace()
            .unwrap_or_default()
            .iter()
            .find(|e| e.peer == Some(p(1)) && e.kind == EventKind::Disconnected(p(0)))
            .map(|e| e.time);
        assert_eq!(breaches(&log), Vec::<String>::new());
        (frames_from(&log, "p1", "p0"), ended)
    };
    assert_eq!(
        run(fixed(100)),
        (vec!["bye".to_owned()], Some(Instant::from_millis(1100))),
        "a fast network: the goodbye arrives, and the connection ends once it has"
    );
    let flush_ends = Instant::from_secs(1).checked_add(STOP_FLUSH);
    assert_eq!(
        run(fixed(3000).deliver_at_close(0.0)),
        (Vec::new(), flush_ends),
        "a slow one: the connection ends a second after the stop, and the goodbye is lost"
    );
    assert_eq!(
        run(fixed(3000).deliver_at_close(1.0)),
        (vec!["bye".to_owned()], flush_ends),
        "or still gets through at the end"
    );
}

/// The same goodbye from `on_stop` at 1 s, on a 900 ms link, so that it is
/// still travelling when p0 restarts at 1.5 s, half way through the flush.
#[test]
fn a_restart_while_a_clean_stop_is_still_flushing_ends_the_old_connection_before_the_new_one_opens()
{
    let (log, scenario) = scripted(1, 2, goodbye_from_on_stop);
    let mut sim = scenario
        .network(fixed(900).deliver_at_close(1.0))
        .fault(Fault::Stop {
            peer: p(0),
            at: Instant::from_secs(1),
        })
        .fault(Fault::Restart {
            peer: p(0),
            at: Instant::from_millis(1500),
        })
        .build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert_eq!(
        lines(&log, "p1 "),
        vec![
            "start",
            "connected p0",
            "message bye from p0",
            "disconnected p0",
            "connected p0"
        ],
        "p1 hears the old connection end, with what was travelling on it, and then the new one open"
    );
    assert_eq!(
        lines(&log, "p0 "),
        vec![
            "start",
            "connected p1",
            "stop",
            "send bye to p1: accepted",
            "start",
            "connected p1"
        ],
        "the new instance never inherits the old connection: it hears on_connected"
    );
    let times = |kind: &EventKind| -> Vec<Instant> {
        sim.trace()
            .unwrap_or_default()
            .iter()
            .filter(|e| e.peer == Some(p(1)) && e.kind == *kind)
            .map(|e| e.time)
            .collect()
    };
    let restart = Instant::from_millis(1500);
    assert_eq!(
        times(&EventKind::Disconnected(p(0))),
        vec![restart],
        "the restart ends the old connection, before the goodbye could arrive (1.9 s) or the flush run out (2 s)"
    );
    assert_eq!(
        times(&EventKind::Connected(p(0))),
        vec![Instant::ZERO, restart]
    );
    assert!(sim.is_connected(p(0), p(1)));
    assert_eq!(sim.stats().stopped, 1);
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// On connecting, p0 writes one frame of 200 KiB and fifty small ones.
struct Splitter {
    sent: Rc<RefCell<Vec<u8>>>,
    got: Rc<RefCell<Vec<u8>>>,
    frames: Rc<RefCell<usize>>,
    stream: Deframer,
}

impl Peer for Splitter {
    fn on_start(&mut self, _cx: &mut dyn Context) {}
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, bytes: &[u8]) {
        assert!(
            !bytes.is_empty() && bytes.len() <= MAX_CHUNK,
            "{}",
            bytes.len()
        );
        self.got.borrow_mut().extend_from_slice(bytes);
        let n = self.stream.push(bytes).map_or(usize::MAX, |f| f.len());
        *self.frames.borrow_mut() += n;
    }
    fn on_timer(&mut self, _cx: &mut dyn Context, _id: TimerId) {}
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        if cx.local_id() != p(0) {
            return;
        }
        let mut writes = vec![frame(&vec![9; 200 * 1024]).unwrap_or_default()];
        writes.extend((0..50u8).map(|i| frame(&[i; 30]).unwrap_or_default()));
        for w in writes {
            self.sent.borrow_mut().extend_from_slice(&w);
            assert_eq!(cx.send(peer, w), Ok(()));
        }
    }
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn the_stream_hands_over_bytes_in_chunks_of_1_to_64_kib_split_and_joined_anywhere() {
    let sent = Rc::new(RefCell::new(Vec::new()));
    let got = Rc::new(RefCell::new(Vec::new()));
    let frames = Rc::new(RefCell::new(0));
    let (s, g, f) = (Rc::clone(&sent), Rc::clone(&got), Rc::clone(&frames));
    let mut sim = Scenario::new(4, 2, move |_| Splitter {
        sent: Rc::clone(&s),
        got: Rc::clone(&g),
        frames: Rc::clone(&f),
        stream: Deframer::new(1 << 20),
    })
    .record_trace(true)
    .build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert_eq!(*got.borrow(), *sent.borrow(), "every byte, once, in order");
    assert_eq!(*frames.borrow(), 51, "and every frame reassembled");
    let chunks: Vec<usize> = sim
        .trace()
        .unwrap_or_default()
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::Deliver { bytes, .. } => Some(bytes.len()),
            _ => None,
        })
        .collect();
    assert!(
        chunks.iter().all(|n| (1..=MAX_CHUNK).contains(n)),
        "{chunks:?}"
    );
    assert!(
        chunks.contains(&MAX_CHUNK),
        "the big frame fills whole chunks: {chunks:?}"
    );
    let mut frame_ends = BTreeSet::new();
    let mut at = 0;
    frame_ends.insert(0);
    at += 4 + 200 * 1024;
    frame_ends.insert(at);
    for _ in 0..50 {
        at += 4 + 30;
        frame_ends.insert(at);
    }
    let mut starts = Vec::new();
    let mut at = 0;
    for n in &chunks {
        starts.push((at, at + n));
        at += n;
    }
    assert!(
        starts.iter().any(|(s, _)| !frame_ends.contains(s)),
        "some chunk starts inside a frame (fragmentation)"
    );
    assert!(
        starts
            .iter()
            .any(|(s, e)| frame_ends.range(s + 1..*e).next().is_some()),
        "some chunk holds the end of one frame and the start of the next (coalescing)"
    );
}

/// p0 writes 100-byte frames to p1 on twenty ticks a millisecond apart, up
/// to thirty a tick, pacing on `unsent` against `cap` when it has one; p1
/// counts the frames it receives.
struct Firehose {
    pace: Option<usize>,
    sent: Rc<RefCell<u64>>,
    got: Rc<RefCell<u64>>,
    stream: Deframer,
    connected: bool,
    ticks: u32,
}

impl Peer for Firehose {
    fn on_start(&mut self, cx: &mut dyn Context) {
        if cx.local_id() == p(0) {
            cx.set_timer(T, Instant::from_millis(1));
        }
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, bytes: &[u8]) {
        let n = self.stream.push(bytes).map_or(0, |f| f.len());
        *self.got.borrow_mut() += u64::try_from(n).unwrap_or(0);
    }
    fn on_timer(&mut self, cx: &mut dyn Context, _id: TimerId) {
        if !self.connected {
            return;
        }
        for _ in 0..30 {
            let f = frame(&[7; 100]).unwrap_or_default();
            if let Some(cap) = self.pace {
                if cx.unsent(p(1)) + f.len() > cap {
                    break;
                }
            }
            if cx.send(p(1), f).is_ok() {
                *self.sent.borrow_mut() += 1;
            }
        }
        self.ticks += 1;
        if self.ticks < 20 {
            let at = cx.now().saturating_add(Duration::from_millis(1));
            cx.set_timer(T, at);
        }
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {
        self.connected = true;
    }
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {
        self.connected = false;
    }
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

fn firehose(pace: Option<usize>) -> (u64, u64, licketysync_sim::Sim<Firehose>) {
    let sent = Rc::new(RefCell::new(0));
    let got = Rc::new(RefCell::new(0));
    let (s, g) = (Rc::clone(&sent), Rc::clone(&got));
    let mut sim = Scenario::new(1, 2, move |_| Firehose {
        pace,
        sent: Rc::clone(&s),
        got: Rc::clone(&g),
        stream: Deframer::new(1000),
        connected: false,
        ticks: 0,
    })
    .network(fixed(10).max_send_queue(1000))
    .record_trace(true)
    .build();
    // Timers alone do not keep a run busy, so it runs to a time, not to
    // quiescence: well past the twentieth tick and its last arrival.
    let o = sim.run_until(Instant::from_millis(500));
    assert!(!o.exhausted && o.in_flight == 0, "{o}");
    let (sent, got) = (*sent.borrow(), *got.borrow());
    (sent, got, sim)
}

#[test]
fn a_write_past_the_send_queue_bound_ends_the_connection() {
    let (sent, got, sim) = firehose(None);
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Overflow,
                ..
            }
        )),
        1
    );
    assert_eq!(sim.stats().overflowed, 1);
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Disconnected(_))),
        2,
        "both sides hear of the end"
    );
    assert!(!sim.is_connected(p(0), p(1)));
    assert!(
        got < sent,
        "what the writer had queued may be lost: {got} of {sent}"
    );
}

#[test]
fn a_writer_that_paces_on_unsent_never_overruns_the_send_queue() {
    let (sent, got, sim) = firehose(Some(1000));
    assert_eq!(sim.stats().overflowed, 0);
    assert!(sim.is_connected(p(0), p(1)), "the connection is never cut");
    assert_eq!(
        sent,
        20 * 9,
        "nine 104-byte frames fit a 1000-byte queue, and it drains between ticks"
    );
    assert_eq!(got, sent, "and every one arrives");
}

/// Every piece p0 sends is lost (`drops(1.0)`), so p0's greeting at 0 s
/// takes the connection down and the network schedules a reconnection for
/// 2 s later. The scenario reconnects the pair at 1 s, and p0 hangs up at
/// 1.5 s; the network's reconnection must then do nothing.
fn hang_up_before_the_networks_reconnection(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if cx.local_id() != p(0) {
        return;
    }
    match call {
        Call::Start => cx.set_timer(T, Instant::from_millis(1500)),
        Call::Connected(q) if cx.now() < Instant::from_millis(500) => me.send(cx, q, "doomed"),
        Call::Timer(_) => me.close(cx, p(1)),
        _ => {}
    }
}

#[test]
fn a_reconnection_scheduled_by_a_drop_does_not_reopen_a_pair_that_hung_up_since() {
    let (log, scenario) = scripted(1, 2, hang_up_before_the_networks_reconnection);
    let mut sim = scenario
        .network(
            NetworkConfig::default()
                .drops(1.0)
                .reconnect(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .fault(Fault::Reconnect {
            a: p(0),
            b: p(1),
            at: Instant::from_secs(1),
        })
        .build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert_eq!(
        lines(&log, "p0 connected").len(),
        2,
        "connected at 0 s and by the scenario at 1 s, never again: {:?}",
        log.borrow()
    );
    assert!(
        !sim.is_connected(p(0), p(1)),
        "a closed pair stays closed: only the scenario reconnects it"
    );
    assert_eq!(sim.stats().dropped, 1);
}

/// Every piece is lost (`drops(1.0)`), so p0's goodbye on its first
/// connection takes the connection down and the network schedules a
/// reconnection for 2 s later. Hearing of the end, p0 hangs up, as the
/// engine does after a goodbye when the other side disconnects first
/// (protocol spec, 4.2): a no-op, since no connection is open any more.
fn goodbye_then_hang_up_on_disconnect(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if cx.local_id() != p(0) {
        return;
    }
    match call {
        Call::Connected(q) if cx.now() < Instant::from_millis(500) => me.send(cx, q, "bye"),
        Call::Disconnected(q) => me.close(cx, q),
        _ => {}
    }
}

#[test]
fn a_no_op_hang_up_after_a_drop_does_not_cancel_the_networks_reconnection() {
    let (log, scenario) = scripted(1, 2, goodbye_then_hang_up_on_disconnect);
    let mut sim = scenario
        .network(
            NetworkConfig::default()
                .drops(1.0)
                .reconnect(Duration::from_secs(2), Duration::from_secs(2)),
        )
        .build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert_eq!(
        lines(&log, "p0 "),
        vec![
            "start",
            "connected p1",
            "send bye to p1: accepted",
            "disconnected p1",
            "close p1",
            "connected p1"
        ],
        "the network brings the pair back after the drop, hang-up or not"
    );
    assert!(sim.is_connected(p(0), p(1)));
    let stats = sim.stats();
    assert_eq!(
        (stats.opened, stats.dropped, stats.hung_up),
        (2, 1, 0),
        "the hang-up ended nothing"
    );
    assert_eq!(breaches(&log), Vec::<String>::new());
}

/// p1 writes "a" to p0 at 1 s and "b" at 1.01 s and hangs up at 1.02 s, all
/// still in flight (100 ms), so both are owed to p0 before its
/// `on_disconnected`; p0 hangs up on p1 when "a" arrives.
fn hang_up_while_handed_owed_bytes(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    match call {
        Call::Start if id == p(1) => {
            cx.set_timer(KICK, Instant::from_secs(1));
            cx.set_timer(T, Instant::from_millis(1010));
            cx.set_timer(TimerId::new(9), Instant::from_millis(1020));
        }
        Call::Timer(KICK) => me.send(cx, p(0), "a"),
        Call::Timer(T) => me.send(cx, p(0), "b"),
        Call::Timer(_) => me.close(cx, p(0)),
        Call::Message(q) if id == p(0) => me.close(cx, q),
        _ => {}
    }
}

#[test]
fn a_hang_up_while_an_ended_connections_bytes_are_handed_over_stops_the_rest() {
    let (log, scenario) = scripted(1, 2, hang_up_while_handed_owed_bytes);
    let mut sim = scenario.network(fixed(100).deliver_at_close(1.0)).build();
    sim.run_until(Instant::from_secs(3));
    assert_eq!(
        frames_from(&log, "p0", "p1"),
        vec!["a".to_owned()],
        "nothing after p0's own hang-up: {:?}",
        log.borrow()
    );
    let p0 = lines(&log, "p0 ");
    let closed = p0.iter().position(|l| l == "close p1");
    let after: Vec<&String> = closed
        .map(|i| p0.iter().skip(i + 1).collect())
        .unwrap_or_default();
    assert_eq!(after, vec!["disconnected p1"], "{p0:?}");
}

/// p2 writes "x" to p0 at 1 s; at 1.05 s, with "x" in flight, a partition
/// cuts p0 from p1 and p2 at once. p0 hears of p1 first and, in that call,
/// hangs up on p2, whose end is already on its way with "x" owed.
fn hang_up_on_an_ended_connection(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    match call {
        Call::Start if id == p(2) => cx.set_timer(KICK, Instant::from_secs(1)),
        Call::Timer(KICK) => me.send(cx, p(0), "x"),
        Call::Disconnected(q) if id == p(0) && q == p(1) => me.close(cx, p(2)),
        _ => {}
    }
}

fn no_hang_up(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    if call == Call::Disconnected(p(1)) && cx.local_id() == p(0) {
        return;
    }
    hang_up_on_an_ended_connection(me, cx, call);
}

#[test]
fn a_hang_up_on_a_connection_that_already_ended_receives_nothing_more_on_it() {
    let run = |script: Script| {
        let (log, scenario) = scripted(1, 3, script);
        let mut sim = scenario
            .network(fixed(100).deliver_at_close(1.0))
            .fault(Fault::Partition {
                partition: Partition::isolate(p(0), [p(1), p(2)]),
                from: Instant::from_millis(1050),
                until: Instant::from_secs(60),
            })
            .build();
        sim.run_until(Instant::from_secs(3));
        assert_eq!(breaches(&log), Vec::<String>::new());
        frames_from(&log, "p0", "p2")
    };
    assert_eq!(
        run(no_hang_up),
        vec!["x".to_owned()],
        "without the hang-up, the owed bytes arrive before on_disconnected"
    );
    assert_eq!(
        run(hang_up_on_an_ended_connection),
        Vec::<String>::new(),
        "after it, none does"
    );
}

/// Each instance notes its clock at start and on a timer a second later.
fn note_the_clock(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    match call {
        Call::Start => {
            me.note(cx, &format!("clock {}", cx.now()));
            let at = cx.now().saturating_add(Duration::from_secs(1));
            cx.set_timer(T, at);
        }
        Call::Timer(_) => me.note(cx, &format!("clock {}", cx.now())),
        _ => {}
    }
}

#[test]
fn a_restarted_instance_gets_a_fresh_clock_and_its_timers_follow_it() {
    let (log, scenario) = scripted(1, 1, note_the_clock);
    let mut sim = scenario
        .clock_ahead(p(0), Duration::from_secs(10))
        .fault(Fault::Crash {
            peer: p(0),
            at: Instant::from_secs(5),
        })
        .fault(Fault::Restart {
            peer: p(0),
            at: Instant::from_secs(7),
        })
        .build();
    sim.run_until(Instant::from_secs(20));
    assert_eq!(
        lines(&log, "p0 clock "),
        vec![
            "10.000000000s",
            "11.000000000s",
            "10.000000000s",
            "11.000000000s"
        ],
        "the restarted instance's clock starts afresh, at its skew"
    );
    let fired: Vec<Instant> = sim
        .trace()
        .unwrap_or_default()
        .iter()
        .filter(|e| matches!(e.kind, EventKind::TimerFired(_)))
        .map(|e| e.time)
        .collect();
    assert_eq!(fired, vec![Instant::from_secs(1), Instant::from_secs(8)]);
    assert_eq!(
        sim.wall_time(p(0)),
        Some(licketysync_sim::scenario::DEFAULT_WALL_EPOCH + 30),
        "the wall clock does not restart"
    );
}

/// p0 writes to itself and hangs up on itself on connecting.
fn talk_to_itself(me: &mut Scripted, cx: &mut dyn Context, call: Call) {
    let id = cx.local_id();
    if call == Call::Connected(p(1)) && id == p(0) {
        me.send(cx, id, "me");
        me.close(cx, id);
        assert_eq!(cx.unsent(id), 0);
    }
}

#[test]
fn a_send_to_itself_is_refused_and_a_hang_up_on_itself_changes_nothing() {
    let (log, scenario) = scripted(1, 2, talk_to_itself);
    let mut sim = scenario.build();
    sim.run_until_quiescent(LIMIT);
    assert_eq!(lines(&log, "p0 send "), vec!["me to p0: refused"]);
    assert!(sim.is_connected(p(0), p(1)));
    assert_eq!(
        count(sim.trace().unwrap_or_default(), |k| matches!(
            k,
            EventKind::Disconnected(_)
        )),
        0
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
    let net = all.net();
    for (what, n, floor) in [
        ("frames checked", all.frames(), 8000),
        ("chunks", all.chunks(), 10_000),
        ("hang-ups", all.hang_ups(), 400),
        ("hang-ups inside on_stop", all.stop_hang_ups(), 20),
        ("goodbyes received", all.goodbyes_received(), 150),
        ("cancels", all.cancels(), 3000),
        ("timers fired", all.timers_fired(), 800),
        ("instances", all.instances(), 100),
        (
            "crashes and stops that a live peer heard of",
            net.downs_heard,
            40,
        ),
        ("connections a partition cut", net.partitioned, 8),
        (
            "connections a clean stop ended, not a hang-up",
            net.stopped,
            10,
        ),
        ("connections dropped by the network", net.dropped, 400),
        (
            "pieces still delivered at an end",
            net.delivered_at_close,
            500,
        ),
        ("pieces lost at an end", net.lost_at_close, 4000),
    ] {
        assert!(
            n >= floor,
            "too little {what} ({n} < {floor}) for a clean report to mean something: {all}"
        );
    }
    assert!(
        all.chunks() > all.frames(),
        "frames are split across chunks: {all}"
    );
    assert_eq!(
        contract::run(3),
        contract::run(3),
        "a contract run replays from its seed"
    );
}
