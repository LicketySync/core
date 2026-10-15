// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The harness proves itself on the toy peers: determinism, convergence under
//! every fault class, crash semantics for storage, skew, and the report for a
//! run that never converges; and on small scripted peers: the transport
//! contract (in order, once, loss only as a disconnect), timer generations,
//! connection state, the wall clock and the event budget.

use core::cell::RefCell;
use core::time::Duration;
use std::collections::BTreeMap;
use std::rc::Rc;

use licketysync_engine::runtime::{Context, Instant, Peer, PeerId, SendError, Storage, TimerId};
use licketysync_sim::scenario::{DEFAULT_MAX_EVENTS, DEFAULT_WALL_EPOCH};
use licketysync_sim::scenarios;
use licketysync_sim::toy::{all_hold, total_items, SetUnion, LIMIT};
use licketysync_sim::trace::DropReason;
use licketysync_sim::{EventKind, Fault, NetworkConfig, Partition, Scenario, TraceEvent};

const PEERS: u32 = 5;
const ITEMS: u32 = 3;
const TICK: Duration = Duration::from_secs(1);

const fn p(id: u64) -> PeerId {
    PeerId::new(id)
}

fn toy(seed: u64) -> Scenario<SetUnion> {
    Scenario::new(seed, PEERS, |_| SetUnion::new(ITEMS, TICK))
        .converged_when(all_hold(total_items(PEERS, ITEMS)))
}

#[test]
fn same_seed_same_trace_hash_and_different_seeds_differ() {
    let chaos = |seed: u64| {
        toy(seed)
            .network(
                NetworkConfig::default()
                    .latency(Duration::from_millis(5), Duration::from_millis(500))
                    .drops(0.2),
            )
            .fault(Fault::Crash {
                peer: p(1),
                at: Instant::from_secs(1),
            })
            .fault(Fault::Restart {
                peer: p(1),
                at: Instant::from_secs(4),
            })
            .build()
            .run_until_quiescent(LIMIT)
    };
    let a = chaos(11);
    let b = chaos(11);
    let c = chaos(12);
    assert!(a.converged, "{a}");
    assert_eq!(a, b, "the same seed replays the same run");
    assert_eq!(a.trace_hash, b.trace_hash);
    assert_ne!(
        a.trace_hash, c.trace_hash,
        "a different seed is a different run"
    );
}

#[test]
fn converges_on_a_clean_network() {
    let o = toy(1).build().run_until_quiescent(LIMIT);
    assert!(o.converged && o.quiescent, "{o}");
    assert_eq!(o.in_flight, 0);
    assert!(
        o.now < Instant::from_secs(5),
        "a quiet LAN converges in well under a tick: {o}"
    );
}

#[test]
fn converges_under_dropped_connections_and_cross_connection_reordering() {
    for seed in 0..4 {
        let o = toy(seed)
            .network(
                NetworkConfig::default()
                    .latency(Duration::from_millis(5), Duration::from_secs(2))
                    .drops(0.3),
            )
            .build()
            .run_until_quiescent(LIMIT);
        // Latencies of up to 2 s against a 1 s gossip tick and a 30% drop
        // rate keep something in flight most of the time, so quiescence is a
        // matter of luck here; convergence is not.
        assert!(o.converged, "{o}");
    }
}

fn count(trace: &[TraceEvent], pred: impl Fn(&EventKind) -> bool) -> usize {
    trace.iter().filter(|e| pred(&e.kind)).count()
}

#[test]
fn a_dropped_connection_disconnects_both_sides_loses_what_was_in_flight_and_comes_back() {
    let mut sim = toy(6)
        .network(NetworkConfig::default().drops(0.2))
        .record_trace(true)
        .build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.converged && o.quiescent, "{o}");
    let trace = sim.trace().unwrap_or_default();
    let lost = trace.iter().position(|e| {
        matches!(
            e.kind,
            EventKind::Dropped {
                reason: DropReason::Lost,
                ..
            }
        )
    });
    assert!(lost.is_some(), "seed 6 drops a connection somewhere: {o}");
    let at = lost.unwrap_or(0);
    let (a, b) = match trace.get(at) {
        Some(TraceEvent {
            peer: Some(a),
            kind: EventKind::Dropped { to, .. },
            ..
        }) => (*a, *to),
        _ => (p(99), p(99)),
    };
    assert_ne!(a, p(99), "the drop names its sender and destination");
    let after = trace.get(at + 1..).unwrap_or_default();
    let disconnected_a = after
        .iter()
        .position(|e| e.peer == Some(a) && e.kind == EventKind::Disconnected(b));
    let disconnected_b = after
        .iter()
        .position(|e| e.peer == Some(b) && e.kind == EventKind::Disconnected(a));
    assert_eq!(
        (disconnected_a, disconnected_b),
        (Some(0), Some(1)),
        "both sides hear of the drop at once, the sender first"
    );
    let reconnected = after
        .iter()
        .position(|e| e.peer == Some(a) && e.kind == EventKind::Connected(b));
    assert!(reconnected.is_some_and(|i| i > 1), "they reconnect later");
    let drop_time = trace.get(at).map(|e| e.time);
    let reconnect_time = reconnected.and_then(|i| after.get(i)).map(|e| e.time);
    assert!(
        reconnect_time > drop_time,
        "after the reconnect delay: {drop_time:?} then {reconnect_time:?}"
    );
    let sends = count(trace, |k| matches!(k, EventKind::Send { .. }));
    let delivered = count(trace, |k| matches!(k, EventKind::Deliver { .. }));
    let dropped = count(trace, |k| matches!(k, EventKind::Dropped { .. }));
    assert_eq!(
        sends,
        delivered + dropped,
        "every message arrives once or is dropped once; nothing is duplicated"
    );
    let stale = count(trace, |k| {
        matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Stale,
                ..
            }
        )
    });
    assert!(
        stale > 0,
        "something was in flight on a dropped connection and was lost with it"
    );
}

/// What the `Burst` peers received: by sender, receiver and connection number,
/// the message numbers in arrival order.
type Received = Rc<RefCell<BTreeMap<(PeerId, PeerId, u32), Vec<u32>>>>;

/// On every connection to a peer, sends `BURST` numbered messages tagged
/// with how many connections to that peer this side has seen; records what
/// it receives per sender and per connection.
#[derive(Default)]
struct Burst {
    connections: BTreeMap<PeerId, u32>,
    received: Received,
    me: Option<PeerId>,
}

const BURST: u32 = 16;

impl Peer for Burst {
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.me = Some(cx.local_id());
    }
    fn on_message(&mut self, _cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        let Some(me) = self.me else {
            return;
        };
        let (Some(gen), Some(i)) = (
            bytes
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes),
            bytes
                .get(4..8)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes),
        ) else {
            return;
        };
        self.received
            .borrow_mut()
            .entry((from, me, gen))
            .or_default()
            .push(i);
    }
    fn on_timer(&mut self, _cx: &mut dyn Context, _id: TimerId) {}
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let gen = self.connections.entry(peer).or_insert(0);
        *gen += 1;
        for i in 0..BURST {
            let mut msg = gen.to_be_bytes().to_vec();
            msg.extend_from_slice(&i.to_be_bytes());
            assert_eq!(cx.send(peer, msg), Ok(()));
        }
    }
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

fn bursts(seed: u64, peers: u32, network: NetworkConfig) -> (Received, Scenario<Burst>) {
    let received: Received = Rc::default();
    let shared = Rc::clone(&received);
    let scenario = Scenario::new(seed, peers, move |_| Burst {
        received: Rc::clone(&shared),
        ..Burst::default()
    })
    .network(network)
    .record_trace(true);
    (received, scenario)
}

#[test]
fn messages_on_one_connection_arrive_in_order_and_once_whatever_their_latency() {
    let wide = NetworkConfig::default().latency(Duration::from_millis(5), Duration::from_secs(2));
    let (received, scenario) = bursts(3, 3, wide);
    let mut sim = scenario.build();
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    let received = received.borrow();
    assert_eq!(
        received.len(),
        6,
        "three peers, each direction of each pair"
    );
    for ((from, to, gen), got) in received.iter() {
        assert_eq!(*gen, 1, "one connection per pair");
        let want: Vec<u32> = (0..BURST).collect();
        assert_eq!(got, &want, "{from} -> {to}: in order, each once");
    }
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Send { .. })),
        count(trace, |k| matches!(k, EventKind::Deliver { .. })),
        "as many deliveries as sends: nothing duplicated, nothing lost"
    );
    assert!(
        trace
            .windows(2)
            .filter(|w| matches!(
                (w.first().map(|e| &e.kind), w.get(1).map(|e| &e.kind)),
                (
                    Some(EventKind::Deliver { .. }),
                    Some(EventKind::Deliver { .. })
                )
            ))
            .any(|w| w.first().map(|e| e.peer) != w.get(1).map(|e| e.peer)),
        "with latencies from 5 ms to 2 s, different connections do interleave"
    );
}

#[test]
fn a_drop_cuts_the_stream_cleanly_and_the_next_connection_starts_afresh() {
    let mut any_lost = false;
    for seed in 0..4 {
        let flaky = NetworkConfig::default().drops(0.05);
        let (received, scenario) = bursts(seed, 2, flaky);
        let mut sim = scenario.build();
        let o = sim.run_until_quiescent(LIMIT);
        assert!(o.quiescent, "{o}");
        let trace = sim.trace().unwrap_or_default();
        let lost = count(trace, |k| {
            matches!(
                k,
                EventKind::Dropped {
                    reason: DropReason::Lost,
                    ..
                }
            )
        });
        any_lost |= lost > 0;
        let received = received.borrow();
        let last_gen = received.keys().map(|(_, _, g)| *g).max().unwrap_or(0);
        assert_eq!(
            last_gen as usize,
            1 + lost,
            "every lost message cost one connection and brought one back"
        );
        for ((from, to, gen), got) in received.iter() {
            let want: Vec<u32> = (0..u32::try_from(got.len()).unwrap_or(0)).collect();
            assert_eq!(
                got, &want,
                "{from} -> {to} on connection {gen}: a prefix of the burst, in order, each once"
            );
            if *gen == last_gen {
                let whole: Vec<u32> = (0..BURST).collect();
                assert_eq!(got, &whole, "the last connection carried it all");
            }
        }
        assert_eq!(
            count(trace, |k| matches!(k, EventKind::Send { .. })),
            count(trace, |k| matches!(k, EventKind::Deliver { .. }))
                + count(trace, |k| matches!(k, EventKind::Dropped { .. })),
            "every send was delivered once or dropped once"
        );
    }
    assert!(any_lost, "seeds 0 to 3 at 5% include at least one drop");
}

#[test]
fn a_partition_blocks_convergence_until_it_heals() {
    let mut sim = toy(5)
        .fault(Fault::Partition {
            partition: Partition::between(vec![p(0), p(1)], vec![p(2), p(3), p(4)]),
            from: Instant::ZERO,
            until: Instant::from_secs(10),
        })
        .record_trace(true)
        .build();
    let during = sim.run_until(Instant::from_secs(8));
    assert!(!during.converged, "{during}");
    assert!(!sim.is_connected(p(0), p(2)));
    assert!(sim.is_connected(p(0), p(1)));
    assert!(sim.is_connected(p(2), p(4)));
    // Each side agrees with itself while cut off from the other.
    let side_a: Vec<_> = [p(0), p(1)]
        .iter()
        .filter_map(|id| sim.peer(*id).map(|q| q.items().len()))
        .collect();
    assert_eq!(side_a, vec![6, 6], "two peers' items on one side");
    let after = sim.run_until_quiescent(LIMIT);
    assert!(after.converged && after.quiescent, "{after}");
    assert!(sim.is_connected(p(0), p(2)));
    let trace = sim.trace().unwrap_or_default();
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::PartitionStart && e.peer.is_none()));
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::PartitionEnd && e.peer.is_none()));
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::Disconnected(p(2)) && e.peer == Some(p(0))));
    assert!(
        trace.iter().any(|e| matches!(
            e.kind,
            EventKind::Dropped {
                reason: licketysync_sim::trace::DropReason::Stale,
                ..
            }
        )),
        "messages in flight across the cut are stale when they land"
    );
}

#[test]
fn a_crashed_peer_comes_back_with_its_committed_items_and_the_rest_converge() {
    let mut sim = toy(8)
        .fault(Fault::Crash {
            peer: p(2),
            at: Instant::ZERO,
        })
        .fault(Fault::Restart {
            peer: p(2),
            at: Instant::from_secs(5),
        })
        .build();
    let before = sim.run_until(Instant::from_secs(3));
    assert!(
        !before.converged,
        "p2's items are nowhere but its disk: {before}"
    );
    assert!(!sim.is_running(p(2)));
    assert_eq!(sim.peers().count(), 4);
    let disk = sim.storage(p(2)).map(|s| s.committed().len());
    assert_eq!(
        disk,
        Some(3),
        "p2 committed its own items before it crashed"
    );
    let after = sim.run_until_quiescent(LIMIT);
    assert!(after.converged && after.quiescent, "{after}");
    assert!(sim.is_running(p(2)));
    assert_eq!(sim.peer(p(2)).map(|q| q.items().len()), Some(15));
}

/// Writes one committed and one staged key on its first tick, so a crash or a
/// stop afterwards shows exactly what storage keeps. On a clean stop it
/// records the stop and commits when `commit_on_stop` is set, else does nothing.
struct Journal {
    commit_on_stop: bool,
}

const T: TimerId = TimerId::new(7);

impl Peer for Journal {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let at = cx.now().saturating_add(Duration::from_secs(1));
        cx.set_timer(T, at);
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        assert_eq!(id, T);
        let s = cx.storage();
        assert_eq!(s.put(b"committed", b"kept"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.put(b"staged", b"lost"), Ok(()));
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, cx: &mut dyn Context) {
        if self.commit_on_stop {
            let s = cx.storage();
            assert_eq!(s.put(b"stopped", b"cleanly"), Ok(()));
            assert_eq!(s.commit(), Ok(()));
        }
    }
}

#[test]
fn a_crash_loses_staged_writes_and_keeps_committed_ones() {
    let mut sim = Scenario::new(1, 1, |_| Journal {
        commit_on_stop: true,
    })
    .fault(Fault::Crash {
        peer: p(0),
        at: Instant::from_secs(2),
    })
    .fault(Fault::Restart {
        peer: p(0),
        at: Instant::from_secs(3),
    })
    .record_trace(true)
    .build();
    sim.run_until(Instant::from_millis(1500));
    let s = sim.storage(p(0)).cloned().unwrap_or_default();
    assert_eq!(s.get(b"committed"), Ok(Some(b"kept".to_vec())));
    assert_eq!(
        s.get(b"staged"),
        Ok(Some(b"lost".to_vec())),
        "visible to the process"
    );
    assert_eq!(s.staged_len(), 1);

    sim.run_until(Instant::from_millis(2500));
    assert!(!sim.is_running(p(0)));
    let s = sim.storage(p(0)).cloned().unwrap_or_default();
    assert_eq!(s.get(b"committed"), Ok(Some(b"kept".to_vec())));
    assert_eq!(s.get(b"staged"), Ok(None), "gone with the crash");
    assert_eq!(s.get(b"stopped"), Ok(None), "on_stop did not run");
    assert_eq!(s.staged_len(), 0);

    sim.run_until(Instant::from_secs(5));
    assert!(sim.is_running(p(0)));
    let trace = sim.trace().unwrap_or_default();
    let crashes = trace.iter().filter(|e| e.kind == EventKind::Crash).count();
    let starts = trace.iter().filter(|e| e.kind == EventKind::Start).count();
    assert_eq!((crashes, starts), (1, 2));
    assert!(!trace.iter().any(|e| e.kind == EventKind::Stop));
    // The restarted instance ticked again and left a staged write of its own.
    let s = sim.storage(p(0)).cloned().unwrap_or_default();
    assert_eq!(s.staged_len(), 1);
}

#[test]
fn a_clean_stop_runs_on_stop_and_a_commit_there_carries_every_staged_write() {
    let mut sim = Scenario::new(1, 1, |_| Journal {
        commit_on_stop: true,
    })
    .fault(Fault::Stop {
        peer: p(0),
        at: Instant::from_secs(2),
    })
    .record_trace(true)
    .build();
    sim.run_until(Instant::from_secs(3));
    assert!(!sim.is_running(p(0)));
    let s = sim.storage(p(0)).cloned().unwrap_or_default();
    assert_eq!(s.get(b"committed"), Ok(Some(b"kept".to_vec())));
    assert_eq!(
        s.get(b"stopped"),
        Ok(Some(b"cleanly".to_vec())),
        "on_stop ran"
    );
    assert_eq!(
        s.get(b"staged"),
        Ok(Some(b"lost".to_vec())),
        "a commit is a transaction: the write staged on the tick went durable with it"
    );
    assert_eq!(s.staged_len(), 0);
    let trace = sim.trace().unwrap_or_default();
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::Stop && e.peer == Some(p(0))));
    assert!(!trace.iter().any(|e| e.kind == EventKind::Crash));
}

#[test]
fn a_clean_stop_without_a_commit_loses_the_staged_writes_like_a_crash() {
    let mut sim = Scenario::new(1, 1, |_| Journal {
        commit_on_stop: false,
    })
    .fault(Fault::Stop {
        peer: p(0),
        at: Instant::from_secs(2),
    })
    .build();
    sim.run_until(Instant::from_secs(3));
    let s = sim.storage(p(0)).cloned().unwrap_or_default();
    assert_eq!(s.get(b"committed"), Ok(Some(b"kept".to_vec())));
    assert_eq!(
        s.get(b"staged"),
        Ok(None),
        "nothing committed it before the process ended"
    );
    assert_eq!(s.get(b"stopped"), Ok(None));
    assert_eq!(s.staged_len(), 0);
}

/// Replaces a timer, cancels another, and tries a send to nobody.
#[derive(Default)]
struct Ticker {
    fired: Vec<(TimerId, Instant)>,
    start_time: Option<Instant>,
}

impl Peer for Ticker {
    fn on_start(&mut self, cx: &mut dyn Context) {
        self.start_time = Some(cx.now());
        let now = cx.now();
        cx.set_timer(TimerId::new(1), now.saturating_add(Duration::from_secs(1)));
        cx.set_timer(TimerId::new(1), now.saturating_add(Duration::from_secs(2)));
        cx.set_timer(TimerId::new(2), now.saturating_add(Duration::from_secs(3)));
        cx.cancel_timer(TimerId::new(2));
        cx.set_timer(TimerId::new(3), Instant::ZERO);
        assert!(cx.send(PeerId::new(99), vec![1]).is_err());
        let mut r = [0u8; 4];
        cx.fill_random(&mut r);
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        self.fired.push((id, cx.now()));
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn timers_replace_cancel_and_fire_in_the_peers_own_time() {
    let ahead = Duration::from_secs(10);
    let mut sim = Scenario::new(1, 1, |_| Ticker::default())
        .clock_ahead(p(0), ahead)
        .record_trace(true)
        .build();
    assert_eq!(
        sim.peer(p(0)).and_then(|t| t.start_time),
        Some(Instant::from_secs(10))
    );
    assert!(
        sim.is_quiescent(),
        "with the default predicate and nothing in flight the system already counts as quiescent"
    );
    let o = sim.run_until(Instant::from_secs(5));
    assert_eq!(o.now, Instant::from_secs(5));
    assert_eq!(
        sim.peer(p(0)).map(|t| t.fired.clone()),
        Some(vec![
            (TimerId::new(3), Instant::from_secs(10)),
            (TimerId::new(1), Instant::from_secs(12)),
        ]),
        "a past deadline fires at once, a replaced timer fires once at its new deadline, a cancelled one never"
    );
    assert!(!sim.step(), "the queue is empty");
    assert_eq!(
        sim.now(),
        Instant::from_secs(5),
        "simulation time is not skewed"
    );
    let trace = sim.trace().unwrap_or_default();
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::SendRefused { to: p(99) }));
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::TimerCancelled(TimerId::new(2))));
    assert_eq!(
        trace
            .iter()
            .filter(|e| matches!(e.kind, EventKind::TimerFired(_)))
            .count(),
        2
    );
}

#[test]
fn skew_does_not_break_convergence_and_shows_in_both_clocks() {
    for seed in 0..3 {
        let mut sim = toy(seed)
            .clock_ahead(p(1), Duration::from_secs(300))
            .clock_ahead(p(3), Duration::from_secs(3600))
            .clock_ahead(p(4), Duration::from_secs(86_400))
            .network(NetworkConfig::default().drops(0.2))
            .build();
        let o = sim.run_until_quiescent(LIMIT);
        assert!(o.converged && o.quiescent, "{o}");
        let base = sim.wall_time(p(0));
        assert_eq!(base, Some(DEFAULT_WALL_EPOCH + o.now.as_secs()));
        assert_eq!(sim.wall_time(p(1)), base.map(|b| b + 300));
        assert_eq!(sim.wall_time(p(2)), base);
        assert_eq!(sim.wall_time(p(3)), base.map(|b| b + 3600));
        assert_eq!(sim.wall_time(p(4)), base.map(|b| b + 86_400));
        assert_eq!(sim.wall_time(p(9)), None);
        // Every peer last read its wall clock at the same simulation instant
        // (its start, or the tick they all share), so the readings differ by
        // exactly the skews.
        let read = |id: u64| sim.peer(p(id)).map(SetUnion::wall_time);
        let at_p0 = read(0);
        assert!(at_p0.is_some_and(|w| w >= DEFAULT_WALL_EPOCH));
        assert_eq!(read(1), at_p0.map(|w| w + 300));
        assert_eq!(read(4), at_p0.map(|w| w + 86_400));
    }
}

/// Who read the wall clock, where, and what it said.
type DateLog = Rc<RefCell<Vec<(PeerId, &'static str, u64)>>>;

/// Notes the wall clock at start and on its one timer.
struct DateStamp {
    log: DateLog,
}

impl Peer for DateStamp {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "start", cx.wall_time()));
        let at = cx.now().saturating_add(Duration::from_millis(1500));
        cx.set_timer(T, at);
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, _id: TimerId) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "timer", cx.wall_time()));
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn the_wall_clock_is_the_epoch_plus_the_peers_skewed_instant_in_whole_seconds() {
    let log = Rc::new(RefCell::new(Vec::new()));
    let shared = Rc::clone(&log);
    let mut sim = Scenario::new(1, 2, move |_| DateStamp {
        log: Rc::clone(&shared),
    })
    .wall_epoch(1000)
    .clock_ahead(p(1), Duration::from_millis(10_400))
    .build();
    assert_eq!(sim.wall_time(p(0)), Some(1000));
    assert_eq!(
        sim.wall_time(p(1)),
        Some(1010),
        "10.4 s ahead reads 10 s ahead: whole seconds"
    );
    sim.run_until(Instant::from_millis(2500));
    assert_eq!(sim.wall_time(p(0)), Some(1002));
    assert_eq!(sim.wall_time(p(1)), Some(1012));
    assert_eq!(
        *log.borrow(),
        vec![
            (p(0), "start", 1000),
            (p(1), "start", 1010),
            (p(0), "timer", 1001),
            (p(1), "timer", 1011),
        ]
    );
    let saturated = Scenario::new(1, 1, |_| Journal {
        commit_on_stop: false,
    })
    .wall_epoch(u64::MAX)
    .clock_ahead(p(0), Duration::from_secs(5))
    .build();
    assert_eq!(saturated.wall_time(p(0)), Some(u64::MAX), "never wraps");
}

#[test]
fn a_full_disk_delays_persistence_and_everything_is_saved_once_freed() {
    let mut sim = toy(3)
        .fault(Fault::DiskFull {
            peer: p(0),
            from: Instant::ZERO,
            until: Instant::from_secs(5),
        })
        .record_trace(true)
        .build();
    let during = sim.run_until(Instant::from_secs(3));
    assert!(
        !during.converged,
        "unsaved items hold the predicate off: {during}"
    );
    assert_eq!(
        sim.peer(p(0)).map(|q| q.items().len()),
        Some(15),
        "in memory, p0 has everything"
    );
    assert_eq!(sim.peer(p(0)).map(SetUnion::unsaved), Some(12));
    assert_eq!(
        sim.storage(p(0)).map(|s| s.committed().len()),
        Some(3),
        "peers start before a fault at time zero fires, so its own items were committed"
    );
    let after = sim.run_until_quiescent(LIMIT);
    assert!(after.converged && after.quiescent, "{after}");
    assert_eq!(sim.storage(p(0)).map(|s| s.committed().len()), Some(15));
    let trace = sim.trace().unwrap_or_default();
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::DiskFull && e.peer == Some(p(0))));
    assert!(trace
        .iter()
        .any(|e| e.kind == EventKind::DiskFreed && e.peer == Some(p(0))));
    assert!(trace.iter().any(
        |e| matches!(&e.kind, EventKind::StorageFailed { error, .. } if error == "storage is full")
    ));
}

#[test]
fn a_bounded_disk_refuses_what_does_not_fit() {
    let mut sim = toy(3).disk_capacity(p(1), 13 * 5).build();
    let o = sim.run_until(Instant::from_secs(30));
    assert!(
        !o.converged,
        "p1 can hold five items of thirteen bytes, not fifteen: {o}"
    );
    assert_eq!(sim.storage(p(1)).map(|s| s.committed().len()), Some(5));
    assert_eq!(sim.peer(p(1)).map(SetUnion::unsaved), Some(10));
    assert_eq!(sim.peer(p(1)).map(|q| q.items().len()), Some(15));
}

#[test]
fn a_run_that_never_converges_is_reported_with_the_seed_and_the_last_events() {
    let o = Scenario::new(77, PEERS, |_| SetUnion::deaf(ITEMS, TICK))
        .converged_when(all_hold(total_items(PEERS, ITEMS)))
        .keep_last(5)
        .build()
        .run_until_quiescent(Instant::from_secs(10));
    assert!(!o.converged && !o.quiescent, "{o}");
    assert_eq!(o.now, Instant::from_secs(10), "it gave up at the limit");
    assert_eq!(o.last_events.len(), 5);
    let text = o.to_string();
    assert!(
        text.starts_with("seed 77: NOT converged, not quiescent, t=10.000000000s"),
        "{text}"
    );
    assert!(text.contains("last 5 events:"), "{text}");
    assert!(text.lines().count() >= 7, "{text}");
}

#[test]
fn run_until_stops_at_the_time_asked_and_quiescence_needs_an_empty_network() {
    let mut sim = toy(2).build();
    let o = sim.run_until(Instant::from_millis(1));
    assert_eq!(o.now, Instant::from_millis(1));
    assert!(!o.converged, "nothing has arrived after a millisecond");
    assert!(o.in_flight > 0);
    let o = sim.run_until(Instant::from_millis(1));
    assert_eq!(
        o.now,
        Instant::from_millis(1),
        "not moved backwards or forwards"
    );
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent && o.converged, "{o}");
    assert_eq!(o.in_flight, 0);
    assert_eq!(sim.events_processed(), o.events);
    assert_eq!(sim.seed(), 2);
    assert_eq!(sim.pending_faults(), 0);
}

/// Arms a timer, cancels it and arms it again, logging every firing.
struct CancelThenRearm {
    log: Rc<RefCell<Vec<Instant>>>,
}

impl Peer for CancelThenRearm {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let now = cx.now();
        cx.set_timer(T, now.saturating_add(Duration::from_secs(1)));
        cx.cancel_timer(T);
        cx.set_timer(T, now.saturating_add(Duration::from_secs(2)));
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        assert_eq!(id, T);
        self.log.borrow_mut().push(cx.now());
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

fn firings<P: Peer + 'static>(
    make: impl Fn(Rc<RefCell<Vec<Instant>>>) -> P + 'static,
    faults: &[Fault],
) -> Vec<Instant> {
    let log = Rc::new(RefCell::new(Vec::new()));
    let shared = Rc::clone(&log);
    let mut scenario = Scenario::new(1, 1, move |_| make(Rc::clone(&shared)));
    for fault in faults {
        scenario = scenario.fault(fault.clone());
    }
    let mut sim = scenario.build();
    let o = sim.run_until(Instant::from_secs(20));
    assert!(!o.exhausted, "{o}");
    let fired = log.borrow().clone();
    fired
}

#[test]
fn timer_generations_never_reset_a_cancelled_then_rearmed_timer_fires_once_at_the_new_deadline() {
    assert_eq!(
        firings(|log| CancelThenRearm { log }, &[]),
        vec![Instant::from_secs(2)],
        "never at 1 s, where the cancelled arming was queued"
    );
}

/// Arms a timer for 3 s, then moves it to 1 s; when it fires, arms it for 3 s
/// later (4 s), logging every firing.
struct RearmInsideHandler {
    log: Rc<RefCell<Vec<Instant>>>,
}

impl Peer for RearmInsideHandler {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let now = cx.now();
        cx.set_timer(T, now.saturating_add(Duration::from_secs(3)));
        cx.set_timer(T, now.saturating_add(Duration::from_secs(1)));
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        assert_eq!(id, T);
        let now = cx.now();
        self.log.borrow_mut().push(now);
        if self.log.borrow().len() == 1 {
            cx.set_timer(T, now.saturating_add(Duration::from_secs(3)));
        }
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn timer_generations_never_reset_a_timer_rearmed_inside_its_handler_ignores_the_older_arming() {
    assert_eq!(
        firings(|log| RearmInsideHandler { log }, &[]),
        vec![Instant::from_secs(1), Instant::from_secs(4)],
        "never at 3 s, where the first arming was queued"
    );
}

/// On its first start arms a timer for 5 s; on a restart arms one for 7 s;
/// logs every firing.
struct ArmAcrossCrash {
    log: Rc<RefCell<Vec<Instant>>>,
}

impl Peer for ArmAcrossCrash {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let restarted = cx.storage().get(b"booted").ok().flatten().is_some();
        if restarted {
            cx.set_timer(T, Instant::from_secs(7));
        } else {
            assert_eq!(cx.storage().put(b"booted", b"1"), Ok(()));
            assert_eq!(cx.storage().commit(), Ok(()));
            cx.set_timer(T, Instant::from_secs(5));
        }
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        assert_eq!(id, T);
        self.log.borrow_mut().push(cx.now());
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn timer_generations_never_reset_a_timer_armed_before_a_crash_does_not_fire_on_the_restarted_instance(
) {
    let faults = [
        Fault::Crash {
            peer: p(0),
            at: Instant::from_secs(1),
        },
        Fault::Restart {
            peer: p(0),
            at: Instant::from_secs(2),
        },
    ];
    assert_eq!(
        firings(|log| ArmAcrossCrash { log }, &faults),
        vec![Instant::from_secs(7)],
        "never at 5 s, where the crashed instance's arming was queued"
    );
}

/// Sends to its neighbour from the wrong places: before `on_connected`, and
/// inside `on_disconnected` for that very peer.
struct Impatient {
    log: Rc<RefCell<Vec<(&'static str, bool)>>>,
}

impl Peer for Impatient {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let other = PeerId::new(1 - cx.local_id().as_u64());
        let ok = cx.send(other, b"too early".to_vec()).is_ok();
        self.log.borrow_mut().push(("start", ok));
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {
        self.log.borrow_mut().push(("message", true));
    }
    fn on_timer(&mut self, _cx: &mut dyn Context, _id: TimerId) {}
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let ok = cx.send(peer, b"hello".to_vec()).is_ok();
        self.log.borrow_mut().push(("connected", ok));
    }
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let ok = cx.send(peer, b"too late".to_vec()).is_ok();
        self.log.borrow_mut().push(("disconnected", ok));
    }
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn a_send_is_accepted_only_between_on_connected_and_on_disconnected() {
    let log = Rc::new(RefCell::new(Vec::new()));
    let shared = Rc::clone(&log);
    let mut sim = Scenario::new(1, 2, move |_| Impatient {
        log: Rc::clone(&shared),
    })
    .fault(Fault::Crash {
        peer: p(1),
        at: Instant::from_secs(1),
    })
    .fault(Fault::Restart {
        peer: p(1),
        at: Instant::from_secs(2),
    })
    .record_trace(true)
    .build();
    assert_eq!(
        *log.borrow(),
        vec![
            ("start", false),
            ("start", false),
            ("connected", true),
            ("connected", true)
        ],
        "before on_connected a send is refused; from on_connected on it is accepted"
    );
    sim.run_until(Instant::from_millis(1500));
    assert_eq!(
        log.borrow().get(4..),
        Some(
            &[
                ("message", true),
                ("message", true),
                ("disconnected", false)
            ][..]
        ),
        "the hellos arrived; p0's send inside on_disconnected for p1's crash was refused"
    );
    assert!(!sim.is_connected(p(0), p(1)));
    sim.run_until(Instant::from_secs(3));
    assert!(sim.is_connected(p(0), p(1)), "the restart reconnected them");
    assert_eq!(
        log.borrow().get(7..),
        Some(
            &[
                ("start", false),
                ("connected", true),
                ("connected", true),
                ("message", true),
                ("message", true)
            ][..]
        ),
        "the restarted p1 starts unconnected, then both greet again"
    );
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::SendRefused { .. })),
        4,
        "two at start, one in on_disconnected, one at the restart"
    );
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Deliver { .. })),
        4,
        "nothing sent from the wrong place was delivered"
    );
}

/// Greets the first peer to connect, once per instance, and never speaks again.
#[derive(Default)]
struct GreetOnce {
    greeted: bool,
}

impl Peer for GreetOnce {
    fn on_start(&mut self, _cx: &mut dyn Context) {}
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, _cx: &mut dyn Context, _id: TimerId) {}
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        if !self.greeted {
            self.greeted = true;
            assert_eq!(cx.send(peer, b"hi".to_vec()), Ok(()));
        }
    }
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn a_connection_is_not_open_while_a_drop_waits_to_reconnect_and_the_lost_message_stays_lost() {
    // Half the messages drop; with seed 1 both greetings do, the first taking
    // the connection down and the second going stale on it. Were the transport
    // to resend a lost message on the new connection, that resend would either
    // arrive (a delivery below) or drop again (a second loss): both fail here.
    let mut sim = Scenario::new(1, 2, |_| GreetOnce::default())
        .network(
            NetworkConfig::default()
                .drops(0.5)
                .reconnect(Duration::from_secs(30), Duration::from_secs(30)),
        )
        .record_trace(true)
        .build();
    assert!(sim.is_connected(p(0), p(1)));
    let o = sim.run_until(Instant::from_secs(1));
    assert!(!o.quiescent, "a reconnection is pending: {o}");
    assert_eq!(
        sim.pending_faults(),
        1,
        "the reconnection counts as a pending fault"
    );
    assert_eq!(o.in_flight, 0);
    assert!(sim.is_running(p(0)) && sim.is_running(p(1)));
    assert!(
        !sim.is_connected(p(0), p(1)),
        "both run and nothing partitions them, but the connection is down"
    );
    let trace = sim.trace().unwrap_or_default().to_vec();
    let lost = count(&trace, |k| {
        matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Lost,
                ..
            }
        )
    });
    let stale = count(&trace, |k| {
        matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Stale,
                ..
            }
        )
    });
    assert_eq!(
        (lost, stale),
        (1, 1),
        "the first greeting took the connection down; the other was in flight on it"
    );
    let dropped_at = trace
        .iter()
        .find(|e| matches!(e.kind, EventKind::Dropped { .. }))
        .map(|e| e.time);
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert_eq!(
        Some(o.now),
        dropped_at.map(|t| t.saturating_add(Duration::from_secs(30))),
        "quiescent the moment the connection is back"
    );
    assert!(sim.is_connected(p(0), p(1)));
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Connected(_))),
        4,
        "two peers connected, then reconnected"
    );
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Deliver { .. })),
        0,
        "the transport never resends what a dropped connection lost"
    );
}

/// Who was called, which handler, and about whom.
type CallLog = Rc<RefCell<Vec<(PeerId, &'static str, PeerId)>>>;

/// Peer 0 sends "bad" to whoever connects; a peer that receives "bad" replies
/// "bye" and hangs up in the same handler, then tries once more inside
/// `on_disconnected`. Every handler call is logged.
struct HangUp {
    log: CallLog,
}

impl Peer for HangUp {
    fn on_start(&mut self, _cx: &mut dyn Context) {}
    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "message", from));
        if bytes == b"bad" {
            assert_eq!(cx.send(from, b"bye".to_vec()), Ok(()));
            cx.close(from);
            assert_eq!(
                cx.send(from, b"after".to_vec()),
                Err(SendError::NotConnected),
                "after close, the same handler cannot send to that peer"
            );
        }
    }
    fn on_timer(&mut self, _cx: &mut dyn Context, _id: TimerId) {}
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "connected", peer));
        if me == p(0) {
            assert_eq!(cx.send(peer, b"bad".to_vec()), Ok(()));
        }
    }
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "disconnected", peer));
        cx.close(peer);
        assert_eq!(
            cx.send(peer, b"late".to_vec()),
            Err(SendError::NotConnected)
        );
    }
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn a_peer_can_hang_up_and_the_pair_stays_closed_until_the_scenario_reconnects_it() {
    let log = Rc::new(RefCell::new(Vec::new()));
    let shared = Rc::clone(&log);
    let mut sim = Scenario::new(1, 2, move |_| HangUp {
        log: Rc::clone(&shared),
    })
    .fault(Fault::Reconnect {
        a: p(0),
        b: p(1),
        at: Instant::from_secs(5),
    })
    .record_trace(true)
    .build();
    let o = sim.run_until(Instant::from_secs(2));
    assert!(!sim.is_connected(p(0), p(1)), "p1 hung up: {o}");
    assert!(sim.is_running(p(0)) && sim.is_running(p(1)));
    assert_eq!(
        *log.borrow(),
        vec![
            (p(0), "connected", p(1)),
            (p(1), "connected", p(0)),
            (p(1), "message", p(0)),
            (p(1), "disconnected", p(0)),
            (p(0), "disconnected", p(1)),
        ],
        "the side that hung up hears on_disconnected first; nothing reached p0"
    );
    assert_eq!(
        sim.pending_faults(),
        1,
        "only the scenario's reconnect is pending; the simulator schedules none of its own"
    );
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Close(_))),
        3,
        "one close that closed, two no-ops from inside on_disconnected"
    );
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Disconnected(_))),
        2,
        "a no-op close disconnects nobody"
    );
    assert!(
        trace.iter().any(|e| matches!(
            e.kind,
            EventKind::Dropped {
                reason: DropReason::Stale,
                ..
            }
        )),
        "the \"bye\" queued before the close in the same handler went down with the connection"
    );
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Deliver { .. })),
        1,
        "only \"bad\" was ever delivered"
    );
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    assert!(
        o.now >= Instant::from_secs(5),
        "the pair stayed closed until the scenario's reconnect: {o}"
    );
    assert!(
        !sim.is_connected(p(0), p(1)),
        "p0 sent \"bad\" again on the new connection and p1 hung up again"
    );
    assert_eq!(
        log.borrow().get(5..),
        Some(
            &[
                (p(0), "connected", p(1)),
                (p(1), "connected", p(0)),
                (p(1), "message", p(0)),
                (p(1), "disconnected", p(0)),
                (p(0), "disconnected", p(1)),
            ][..]
        ),
        "on_connected and on_disconnected strictly alternate for the pair"
    );
    let unchanged = Scenario::new(1, 2, |_| HangUp {
        log: Rc::new(RefCell::new(Vec::new())),
    })
    .build()
    .run_until_quiescent(LIMIT);
    assert!(
        unchanged.quiescent && unchanged.now < Instant::from_secs(1),
        "without a Reconnect fault the pair stays closed and the run is over at once: {unchanged}"
    );
}

/// Peer 0 hangs up on whoever connects, from inside `on_connected` (a
/// blocklist, a connection cap); everyone greets a new connection; every
/// handler call is logged, and a greeting must be accepted, since a
/// connection is open for as long as `on_connected` says so.
struct Bouncer {
    log: CallLog,
}

impl Peer for Bouncer {
    fn on_start(&mut self, _cx: &mut dyn Context) {}
    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, _bytes: &[u8]) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "message", from));
    }
    fn on_timer(&mut self, _cx: &mut dyn Context, _id: TimerId) {}
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "connected", peer));
        assert_eq!(
            cx.send(peer, b"hello".to_vec()),
            Ok(()),
            "{me}: on_connected({peer}) arrived with the connection open"
        );
        if me == p(0) {
            cx.close(peer);
        }
    }
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        let me = cx.local_id();
        self.log.borrow_mut().push((me, "disconnected", peer));
    }
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn a_close_inside_on_connected_does_not_hand_the_other_side_on_disconnected_before_on_connected() {
    let log = Rc::new(RefCell::new(Vec::new()));
    let shared = Rc::clone(&log);
    let mut sim = Scenario::new(1, 2, move |_| Bouncer {
        log: Rc::clone(&shared),
    })
    .fault(Fault::Reconnect {
        a: p(0),
        b: p(1),
        at: Instant::from_secs(5),
    })
    .record_trace(true)
    .build();
    let one_round = [
        (p(0), "connected", p(1)),
        (p(1), "connected", p(0)),
        (p(0), "disconnected", p(1)),
        (p(1), "disconnected", p(0)),
    ];
    assert_eq!(
        *log.borrow(),
        one_round.to_vec(),
        "p1 hears on_connected before on_disconnected although p0 hung up inside its own on_connected"
    );
    assert!(!sim.is_connected(p(0), p(1)));
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.quiescent, "{o}");
    let mut two_rounds = one_round.to_vec();
    two_rounds.extend_from_slice(&one_round);
    assert_eq!(
        *log.borrow(),
        two_rounds,
        "the same after the scenario reconnects them: strict alternation, no message ever arrives"
    );
    let trace = sim.trace().unwrap_or_default();
    assert_eq!(
        count(trace, |k| matches!(k, EventKind::Send { .. })),
        4,
        "both greetings were accepted on both connections"
    );
    assert_eq!(count(trace, |k| matches!(k, EventKind::Deliver { .. })), 0);
    assert_eq!(
        count(trace, |k| matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Closed,
                ..
            }
        )),
        2,
        "p1's greetings were queued after p0's close had been applied: lost before leaving"
    );
    assert_eq!(
        count(trace, |k| matches!(
            k,
            EventKind::Dropped {
                reason: DropReason::Stale,
                ..
            }
        )),
        2,
        "p0's greetings were queued before its close: lost in flight"
    );
}

#[test]
fn a_fault_window_given_backwards_is_the_same_window() {
    let forwards = toy(5)
        .fault(Fault::Partition {
            partition: Partition::between(vec![p(0), p(1)], vec![p(2), p(3), p(4)]),
            from: Instant::ZERO,
            until: Instant::from_secs(10),
        })
        .fault(Fault::DiskFull {
            peer: p(2),
            from: Instant::from_secs(1),
            until: Instant::from_secs(4),
        })
        .build()
        .run_until_quiescent(LIMIT);
    let backwards = toy(5)
        .fault(Fault::Partition {
            partition: Partition::between(vec![p(0), p(1)], vec![p(2), p(3), p(4)]),
            from: Instant::from_secs(10),
            until: Instant::ZERO,
        })
        .fault(Fault::DiskFull {
            peer: p(2),
            from: Instant::from_secs(4),
            until: Instant::from_secs(1),
        })
        .build()
        .run_until_quiescent(LIMIT);
    assert!(forwards.converged && forwards.quiescent, "{forwards}");
    assert_eq!(forwards, backwards, "the same run, event for event");
    assert!(
        forwards.now > Instant::from_secs(10),
        "the partition really lasted ten seconds: {forwards}"
    );
}

/// Re-arms a past deadline from its own handler: the scheduler would never
/// leave instant zero.
struct Spinner;

impl Peer for Spinner {
    fn on_start(&mut self, cx: &mut dyn Context) {
        cx.set_timer(T, Instant::ZERO);
    }
    fn on_message(&mut self, _cx: &mut dyn Context, _from: PeerId, _bytes: &[u8]) {}
    fn on_timer(&mut self, cx: &mut dyn Context, _id: TimerId) {
        cx.set_timer(T, Instant::ZERO);
    }
    fn on_connected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_disconnected(&mut self, _cx: &mut dyn Context, _peer: PeerId) {}
    fn on_stop(&mut self, _cx: &mut dyn Context) {}
}

#[test]
fn a_peer_that_never_settles_spends_the_event_budget_and_is_reported_not_converged() {
    assert_eq!(DEFAULT_MAX_EVENTS, 1_000_000);
    let mut sim = Scenario::new(1, 1, |_| Spinner)
        .converged_when(|_| false)
        .max_events(500)
        .build();
    assert!(!sim.is_exhausted());
    let o = sim.run_until_quiescent(LIMIT);
    assert!(o.exhausted && !o.converged && !o.quiescent, "{o}");
    assert_eq!(o.events, 500);
    assert_eq!(o.now, Instant::ZERO, "it never left instant zero");
    assert!(sim.is_exhausted());
    assert!(!sim.step(), "nothing runs after the budget is spent");
    assert_eq!(sim.events_processed(), 500);
    let text = o.to_string();
    assert!(
        text.starts_with(
            "seed 1: NOT converged (event budget spent), not quiescent, t=0.000000000s, 500 events"
        ),
        "{text}"
    );
    let mut sim = Scenario::new(1, 1, |_| Spinner).max_events(10).build();
    let o = sim.run_until(Instant::from_secs(5));
    assert!(o.exhausted, "run_until stops at the budget too: {o}");
    assert!(
        !o.converged && !o.quiescent,
        "a spent budget is never converged, whatever the predicate says: {o}"
    );
    assert_eq!(o.events, 10);
    assert_eq!(
        o.now,
        Instant::ZERO,
        "the clock is not moved to the time asked"
    );
    let healthy = toy(1).max_events(10_000).build().run_until_quiescent(LIMIT);
    assert!(
        healthy.converged && !healthy.exhausted,
        "a budget a run stays within changes nothing: {healthy}"
    );
    assert!(!healthy.to_string().contains("budget"), "{healthy}");
}

#[test]
fn every_shipped_scenario_converges_for_a_handful_of_seeds_and_broken_does_not() {
    for s in scenarios::expected_to_converge() {
        for seed in 0..3 {
            let o = s.run(seed);
            assert!(o.converged && o.quiescent, "{} seed {seed}: {o}", s.name);
        }
    }
    let broken = scenarios::find("broken").map(|s| s.run(0));
    assert!(broken.is_some_and(|o| !o.converged));
    assert!(scenarios::find("nothing").is_none());
    assert_eq!(scenarios::all().len(), 11);
    for gone in ["lossy", "reorder", "duplicate"] {
        assert!(
            scenarios::find(gone).is_none(),
            "{gone} described a network the transport contract rules out"
        );
    }
    for kept in ["drops", "reconnect", "cross-reorder"] {
        assert!(scenarios::find(kept).is_some(), "{kept}");
    }
}

#[test]
fn faults_aimed_at_a_peer_that_is_already_down_or_up_are_harmless() {
    let o = toy(4)
        .fault(Fault::Restart {
            peer: p(0),
            at: Instant::from_secs(1),
        })
        .fault(Fault::Crash {
            peer: p(1),
            at: Instant::from_secs(1),
        })
        .fault(Fault::Crash {
            peer: p(1),
            at: Instant::from_secs(2),
        })
        .fault(Fault::Stop {
            peer: p(1),
            at: Instant::from_secs(3),
        })
        .fault(Fault::Restart {
            peer: p(1),
            at: Instant::from_secs(4),
        })
        .fault(Fault::Restart {
            peer: p(9),
            at: Instant::from_secs(4),
        })
        .fault(Fault::DiskFull {
            peer: p(9),
            from: Instant::from_secs(4),
            until: Instant::from_secs(5),
        })
        .fault(Fault::Partition {
            partition: Partition::isolate(p(2), [p(0), p(1), p(2), p(3), p(4)]),
            from: Instant::from_secs(2),
            until: Instant::from_secs(2),
        })
        .build()
        .run_until_quiescent(LIMIT);
    assert!(o.converged && o.quiescent, "{o}");
}
