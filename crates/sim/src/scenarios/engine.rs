// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The engine scenarios: real engines as [`Member`]s, each over
//! `Timing::SPEC` with 600 s of simulated time, any probes on the way, the
//! oracle applied at the end and again, unchanged and with no new issue, at
//! the first quiet moment 60 s (two `STATUS_INTERVAL`s) or more later
//! ([`Run::check`]). They are the phase 0 gate (the engine brief's 13.1 as
//! the port brief's section 3 updates it; `crates/engine/tests/converge.rs`
//! runs every one but `engine-drops-stress` over seeds 0 to 4, and the
//! nightly job over more). Measured on seeds 0 to 9: at a drop rate of 0.2
//! (`engine-drops-stress`) none reaches a quiet moment within 600 s, since a
//! handshake and a first round need some 25 pieces in a row to survive and
//! the connections keep dropping; at 0.1 (`engine-drops`, the gate's rate)
//! every one converges.
//!
//! Unless a scenario says otherwise, peers 0 to 4 hold the write key and run
//! the default workload ([`default_workload`]), the first step at 1 s and the
//! rest 300 ms apart. `engine-clean` and `engine-pacing` write 1 MiB chunks;
//! the others write 16 KiB chunks, so that a chunk fits a piece of the
//! simulated network and lossy runs finish (decision; the brief lets
//! scenarios set a smaller `chunk_size`). Where two groups must never meet for
//! the whole run, the members are cut from each other ([`Member::cut`]):
//! a partition needs an end, which the run waits for before it can be
//! quiescent.
//!
//! Content takes its time: a chunk pass that met a `CHUNK_NOT_FOUND` waits
//! for a trigger evaluated at most once per `STATUS_INTERVAL` (`protocol.md`
//! 4.6), so in a mesh writing at once every chunk is on every disk some 35 s
//! in. A scenario whose edits must be made over versions already on the
//! editor's disk (an edit made before is concurrent with the version, 4.4
//! "Bases") makes them after that.
//!
//! The `engine-identical-*` runs (the `identical` module) are two or three
//! members that write one path with the same bytes apart, meet, and then
//! change it once: every twin is covered, and nothing of the old content is
//! left anywhere (the identical-heads bug of 2026-11-08).

use core::cell::RefCell;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::inspect::HeadView;
use licketysync_engine::runtime::{Instant, PeerId};
use licketysync_engine::{EngineConfig, IssueKind};
use licketysync_keys::{FolderId, RecordHash, Tier};

use crate::member::{content, default_workload, Action, Ledger, Member, Step};
use crate::network::{NetworkConfig, Partition};
use crate::oracle::{self, Expect};
use crate::scenario::{Fault, Outcome, Scenario, Sim};
use crate::world::{World, MAIN};

/// Simulated time a run may take.
pub const LIMIT: Instant = Instant::from_secs(600);
/// How long after converging the oracle looks again (two
/// `STATUS_INTERVAL`s), at the first quiet moment from then on.
pub const RECHECK: Duration = Duration::from_secs(60);
/// How long the recheck may wait for that quiet moment.
const LIMIT_AGAIN: Duration = Duration::from_secs(600);
/// The chunk size of `engine-clean` and `engine-pacing`.
pub const BIG_CHUNK: usize = 1 << 20;
/// The chunk size of the other scenarios.
pub const SMALL_CHUNK: usize = 16 << 10;

const FIRST: Duration = Duration::from_secs(1);
const GAP: Duration = Duration::from_millis(300);

const fn p(id: u64) -> PeerId {
    PeerId::new(id)
}

/// A scenario's own expectations beyond the oracle's (the brief's (g)).
pub type Extra = fn(&Run) -> Result<(), String>;

/// One engine scenario, built and ready to run.
pub struct Run {
    /// Its name.
    pub name: &'static str,
    /// The simulation.
    pub sim: Sim<Member>,
    /// What the members share.
    pub ledger: Rc<RefCell<Ledger>>,
    /// Who holds what.
    pub world: World,
    /// What the oracle allows.
    pub expect: Expect,
    extra: Option<Extra>,
    /// Looks taken on the way, each at its instant, in order.
    probes: Vec<(Instant, Extra)>,
}

/// What [`Run::check`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The outcome of the run to quiescence, its `failure` set by the oracle,
    /// its trace hash taken at the end of the recheck.
    pub outcome: Outcome,
    /// [`oracle::state_digest`] at the end.
    pub digest: u64,
}

impl Report {
    /// Whether the run converged, quiescent, within its budget, and every
    /// check passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.outcome.converged
            && self.outcome.quiescent
            && !self.outcome.exhausted
            && self.outcome.failure.is_none()
    }
}

impl Run {
    /// The main folder's ID.
    #[must_use]
    pub fn folder(&self) -> FolderId {
        self.world.folder_id(MAIN).unwrap_or(FolderId([0; 32]))
    }

    /// Runs to each probe's instant and takes its look, then to quiescence
    /// within [`LIMIT`], applies the oracle and the scenario's own
    /// expectations, runs [`RECHECK`] longer and checks that nothing changed
    /// and no issue was raised.
    pub fn check(&mut self) -> Report {
        let mut probed = None;
        for (at, look) in self.probes.clone() {
            self.sim.run_until(at);
            if let Err(e) = look(self) {
                probed = Some(format!("at {} ms: {e}", at.as_nanos() / 1_000_000));
                break;
            }
        }
        let mut outcome = self.sim.run_until_quiescent(LIMIT);
        let failure = if let Some(why) = probed {
            Some(why)
        } else if !(outcome.converged && outcome.quiescent) || outcome.exhausted {
            let why = self
                .verify()
                .err()
                .unwrap_or_else(|| "the predicate never held at a quiet moment".to_owned());
            Some(format!("did not converge: {why}"))
        } else {
            self.verify().err()
        };
        let failure = failure.or_else(|| {
            let before = (
                oracle::state_digest(&self.sim),
                self.ledger.borrow().issues.len(),
            );
            self.sim.run_until(self.sim.now().saturating_add(RECHECK));
            // A lossy network may be mid-handshake at that instant: look at
            // the next quiet moment.
            let again = self
                .sim
                .run_until_quiescent(self.sim.now().saturating_add(LIMIT_AGAIN));
            let after = (
                oracle::state_digest(&self.sim),
                self.ledger.borrow().issues.len(),
            );
            if !(again.converged && again.quiescent) || again.exhausted {
                Some("no quiet moment after the recheck".to_owned())
            } else if before == after {
                self.verify()
                    .err()
                    .map(|e| format!("after the recheck: {e}"))
            } else if before.0 == after.0 {
                let issues = self.ledger.borrow().issues.clone();
                Some(format!(
                    "new issues during the recheck: {:?}",
                    issues.get(before.1..)
                ))
            } else {
                Some("the state changed during the recheck".to_owned())
            }
        });
        if failure.is_some() {
            outcome.converged = false;
        }
        outcome.trace_hash = self.sim.trace_hash();
        outcome.failure = failure;
        Report {
            outcome,
            digest: oracle::state_digest(&self.sim),
        }
    }

    fn verify(&self) -> Result<(), String> {
        oracle::check(&self.sim, &self.ledger, self.expect)?;
        self.extra.map_or(Ok(()), |f| f(self))
    }

    /// The record `peer` wrote last at `path`.
    #[must_use]
    pub fn written(&self, peer: PeerId, path: &str) -> Option<RecordHash> {
        self.ledger
            .borrow()
            .written
            .iter()
            .rev()
            .find(|(w, p, _)| *w == peer && p == path)
            .map(|(_, _, h)| *h)
    }

    /// The heads of `path` on `peer`, by hash in display order.
    #[must_use]
    pub fn heads(&self, peer: PeerId, path: &str) -> Vec<RecordHash> {
        let folder = self.folder();
        self.sim
            .peer(peer)
            .and_then(Member::engine)
            .map(|e| e.files(&folder))
            .unwrap_or_default()
            .into_iter()
            .find(|f| f.path == path)
            .map(|f| f.heads.iter().map(|h| h.hash).collect())
            .unwrap_or_default()
    }
}

/// How a scenario's members are made.
struct Plan {
    world: World,
    chunk_size: usize,
    tweak: fn(PeerId, &mut EngineConfig),
    workloads: BTreeMap<PeerId, Vec<Step>>,
    cuts: Vec<(Vec<PeerId>, Vec<PeerId>)>,
    expect: Expect,
    extra: Option<Extra>,
    probes: Vec<(Instant, Extra)>,
}

impl Plan {
    /// `peers` write members, each with the default workload.
    fn new(peers: u32, chunk_size: usize) -> Self {
        let world = World::new(peers);
        let workloads = world
            .ids()
            .into_iter()
            .map(|id| (id, default_workload(id, chunk_size, FIRST, GAP)))
            .collect();
        Self {
            world,
            chunk_size,
            tweak: |_, _| {},
            workloads,
            cuts: Vec::new(),
            expect: Expect::default(),
            extra: None,
            probes: Vec::new(),
        }
    }

    /// A plan with no workload.
    fn quiet(peers: u32, chunk_size: usize) -> Self {
        let mut plan = Self::new(peers, chunk_size);
        plan.workloads = BTreeMap::new();
        plan
    }

    /// Appends `steps` to `peer`'s workload.
    fn then(mut self, peer: PeerId, steps: Vec<Step>) -> Self {
        self.workloads.entry(peer).or_default().extend(steps);
        self
    }

    fn cut(&self, id: PeerId) -> BTreeSet<PeerId> {
        let mut out = BTreeSet::new();
        for (a, b) in &self.cuts {
            if a.contains(&id) {
                out.extend(b.iter().copied());
            }
            if b.contains(&id) {
                out.extend(a.iter().copied());
            }
        }
        out
    }

    /// The run of `name` for `seed`, the network and faults set by `scene`.
    fn build(
        self,
        name: &'static str,
        seed: u64,
        scene: impl FnOnce(Scenario<Member>) -> Scenario<Member>,
    ) -> Run {
        let ledger = Rc::new(RefCell::new(Ledger::default()));
        let world = self.world.clone();
        let folder = world.folder_id(MAIN);
        let cuts: BTreeMap<PeerId, BTreeSet<PeerId>> = world
            .ids()
            .into_iter()
            .map(|id| (id, self.cut(id)))
            .collect();
        let (shared, w, workloads, chunk_size, tweak) = (
            Rc::clone(&ledger),
            world.clone(),
            self.workloads,
            self.chunk_size,
            self.tweak,
        );
        let peers = u32::try_from(world.ids().len()).unwrap_or(0);
        let factory = move |id: PeerId| {
            let mut config = EngineConfig::new(w.device_seed(id), w.keys_of(id));
            config.chunk_size = chunk_size;
            config.device_name = format!("peer-{}", id.as_u64());
            tweak(id, &mut config);
            let steps = workloads.get(&id).cloned().unwrap_or_default();
            let cut = cuts.get(&id).cloned().unwrap_or_default();
            Member::new(config, id, folder, steps, cut, Rc::clone(&shared))
        };
        let scenario = Scenario::new(seed, peers, factory).converged_when(oracle::converged);
        Run {
            name,
            sim: scene(scenario).build(),
            ledger,
            world,
            expect: self.expect,
            extra: self.extra,
            probes: self.probes,
        }
    }
}

/// A write of `len` bytes of `(peer, step)` content at `path`, `delay` after
/// the step before.
fn write(peer: u64, step: u64, path: &str, len: usize, delay: Duration) -> Step {
    Step {
        delay,
        action: Action::Write {
            path: path.to_owned(),
            content: content(peer, step, len),
        },
    }
}

fn clean(seed: u64) -> Run {
    Plan::new(5, BIG_CHUNK).build("engine-clean", seed, |s| s)
}

/// A tenth of the pieces take their connection down (the gate's rate).
fn drops(seed: u64) -> Run {
    Plan::new(5, SMALL_CHUNK).build("engine-drops", seed, |s| {
        s.network(NetworkConfig::default().drops(0.1))
    })
}

/// A fifth of the pieces take their connection down: a stress run, outside
/// the gate, whose pass rate is reported.
fn drops_stress(seed: u64) -> Run {
    Plan::new(5, SMALL_CHUNK).build("engine-drops-stress", seed, |s| {
        s.network(NetworkConfig::default().drops(0.2))
    })
}

fn reconnect(seed: u64) -> Run {
    Plan::new(5, SMALL_CHUNK).build("engine-reconnect", seed, |s| {
        s.network(
            NetworkConfig::default()
                .drops(0.02)
                .reconnect(Duration::from_secs(2), Duration::from_secs(5)),
        )
    })
}

fn cross_reorder(seed: u64) -> Run {
    Plan::new(5, SMALL_CHUNK).build("engine-cross-reorder", seed, |s| {
        s.network(
            NetworkConfig::default().latency(Duration::from_millis(5), Duration::from_secs(2)),
        )
    })
}

/// Paths of the partition scenario.
pub const P_PATH: &str = "shared/p.txt";
/// The path deleted and edited across the cut.
pub const Q_PATH: &str = "shared/q.txt";

/// When the partition scenario's cut begins: once every peer has P and Q
/// on its disk. A pass that met a `CHUNK_NOT_FOUND` waits for its next
/// trigger, evaluated at most once per `STATUS_INTERVAL` (30 s, 4.6), so a
/// five-peer mesh writing at once has every chunk some 35 s in; an edit made
/// before the version it edits is on the editor's disk is concurrent with it
/// (4.4, "Bases"), which is not what this scenario tests.
const CUT_FROM: Instant = Instant::from_secs(45);
/// When it heals.
const CUT_UNTIL: Instant = Instant::from_secs(65);
/// When the edits across the cut are made.
const CUT_EDITS: Duration = Duration::from_secs(50);

/// The cut: {0,1} from {2,3,4}, [`CUT_FROM`] to [`CUT_UNTIL`]. Peer 2
/// writes P and Q before it, which every peer has on its disk by then;
/// during it, 1 and 3 edit P, 0 deletes Q while 4 edits it.
fn partition(seed: u64) -> Run {
    // After the default workload's last step.
    let during = CUT_EDITS.saturating_sub(FIRST + GAP * 6);
    let edit = |peer: u64| vec![write(peer, 20, P_PATH, 300, during)];
    Plan::new(5, SMALL_CHUNK)
        .then(
            p(2),
            vec![
                write(2, 10, P_PATH, 200, GAP),
                write(2, 11, Q_PATH, 200, GAP),
            ],
        )
        .then(p(1), edit(1))
        .then(p(3), edit(3))
        .then(
            p(0),
            vec![Step {
                delay: during,
                action: Action::Delete {
                    path: Q_PATH.to_owned(),
                },
            }],
        )
        .then(p(4), vec![write(4, 21, Q_PATH, 250, during)])
        .with_extra(partition_expect)
        .build("engine-partition", seed, |s| {
            s.fault(Fault::Partition {
                partition: Partition::between(vec![p(0), p(1)], vec![p(2), p(3), p(4)]),
                from: CUT_FROM,
                until: CUT_UNTIL,
            })
        })
}

fn partition_expect(run: &Run) -> Result<(), String> {
    let (e1, e3) = (run.written(p(1), P_PATH), run.written(p(3), P_PATH));
    let (del, e4) = (run.written(p(0), Q_PATH), run.written(p(4), Q_PATH));
    for peer in run.world.ids() {
        let mut heads = run.heads(peer, P_PATH);
        heads.sort_unstable();
        let mut want: Vec<RecordHash> = [e1, e3].into_iter().flatten().collect();
        want.sort_unstable();
        if want.len() != 2 || heads != want {
            return Err(format!("{peer}: P's heads are not the two edits"));
        }
        let q = run.heads(peer, Q_PATH);
        if q != [e4, del].into_iter().flatten().collect::<Vec<_>>() {
            return Err(format!(
                "{peer}: Q's heads are not the edit, then the tombstone"
            ));
        }
    }
    Ok(())
}

impl Plan {
    const fn with_extra(mut self, extra: Extra) -> Self {
        self.extra = Some(extra);
        self
    }

    /// A look at the run at `at`, on the way to the end.
    fn with_probe(mut self, at: Instant, look: Extra) -> Self {
        self.probes.push((at, look));
        self
    }
}

/// The toy's crash, stop and restart schedule, plus a crash of peer 1 one
/// millisecond after its third write (committed and sent), restarted at 8 s.
/// Beyond the nine starts, the oracle checks for every scenario, over every
/// instance, that no member's high-water mark fell and that no member gave
/// one counter to two records (no counter reuse within one device).
fn crash(seed: u64) -> Run {
    let third = FIRST + GAP * 2 + Duration::from_millis(1);
    Plan::new(5, SMALL_CHUNK)
        .with_extra(crash_expect)
        .build("engine-crash", seed, |s| {
            s.fault(Fault::Crash {
                peer: p(2),
                at: Instant::ZERO,
            })
            .fault(Fault::Restart {
                peer: p(2),
                at: Instant::from_secs(5),
            })
            .fault(Fault::Crash {
                peer: p(0),
                at: Instant::from_secs(2),
            })
            .fault(Fault::Restart {
                peer: p(0),
                at: Instant::from_secs(12),
            })
            .fault(Fault::Stop {
                peer: p(4),
                at: Instant::from_secs(4),
            })
            .fault(Fault::Restart {
                peer: p(4),
                at: Instant::from_secs(6),
            })
            .fault(Fault::Crash {
                peer: p(1),
                at: Instant::ZERO.saturating_add(third),
            })
            .fault(Fault::Restart {
                peer: p(1),
                at: Instant::from_secs(8),
            })
        })
}

fn crash_expect(run: &Run) -> Result<(), String> {
    let starts = run.ledger.borrow().starts.len();
    // Five starts, then the restarts of 2, 0, 4 and 1.
    if starts != 9 {
        return Err(format!("{starts} starts, not 9"));
    }
    Ok(())
}

/// The path both a skewed and an unskewed writer edit at once.
pub const S_PATH: &str = "shared/s.txt";

/// Clocks 5 min, 1 h and 23 h ahead (peers 1, 3, 4), `mtime_ns` from each
/// writer's wall clock; 0 and 4 write [`S_PATH`] at the same instant. 23 h
/// stays inside `CLOCK_AHEAD_WARNING` (one day, which a skew of exactly a
/// day would sit on): no clock warning is allowed.
fn skew(seed: u64) -> Run {
    skewed("engine-skew", seed, Duration::from_secs(23 * 60 * 60))
}

/// As `engine-skew`, with peer 4 two days ahead: every other key holder
/// warns that the folder's time is ahead of its clock (`ClockAhead`), well
/// inside the one-year clock rule, and the run still converges.
fn clock_ahead(seed: u64) -> Run {
    let mut run = skewed(
        "engine-clock-ahead",
        seed,
        Duration::from_secs(2 * 24 * 60 * 60),
    );
    run.expect.clock_ahead = true;
    run.extra = Some(clock_ahead_expect);
    run
}

fn skewed(name: &'static str, seed: u64, four: Duration) -> Run {
    Plan::new(5, SMALL_CHUNK)
        .then(p(0), vec![write(0, 30, S_PATH, 120, GAP)])
        .then(p(4), vec![write(4, 30, S_PATH, 130, GAP)])
        .with_extra(skew_expect)
        .build(name, seed, |s| {
            s.wall_epoch(1_700_000_000)
                .clock_ahead(p(1), Duration::from_secs(5 * 60))
                .clock_ahead(p(3), Duration::from_secs(60 * 60))
                .clock_ahead(p(4), four)
        })
}

fn clock_ahead_expect(run: &Run) -> Result<(), String> {
    skew_expect(run)?;
    let warned: BTreeSet<PeerId> = run
        .ledger
        .borrow()
        .issues
        .iter()
        .filter(|(_, i)| i.kind == IssueKind::ClockAhead)
        .map(|(w, _)| *w)
        .collect();
    let want: BTreeSet<PeerId> = [p(0), p(1), p(2), p(3)].into_iter().collect();
    if warned != want {
        return Err(format!(
            "the clock warning came from {warned:?}, not 0 to 3"
        ));
    }
    Ok(())
}

fn skew_expect(run: &Run) -> Result<(), String> {
    let skewed = run.written(p(4), S_PATH);
    for peer in run.world.ids() {
        let heads = run.heads(peer, S_PATH);
        if heads.len() != 2 || heads.first().copied() != skewed {
            return Err(format!(
                "{peer}: the skewed writer's edit is not first of two heads"
            ));
        }
    }
    Ok(())
}

/// Peer 0's disk is full from 0 to 5 s while the others write; its own
/// writes start at 1 s, inside the window.
fn disk_full(seed: u64) -> Run {
    let mut plan = Plan::new(5, SMALL_CHUNK).with_extra(disk_full_expect);
    plan.expect.store_failure = true;
    plan.build("engine-disk-full", seed, |s| {
        s.fault(Fault::DiskFull {
            peer: p(0),
            from: Instant::ZERO,
            until: Instant::from_secs(5),
        })
    })
}

fn disk_full_expect(run: &Run) -> Result<(), String> {
    let paused = run
        .ledger
        .borrow()
        .issues
        .iter()
        .any(|(peer, i)| *peer == p(0) && matches!(i.kind, IssueKind::StoreFailure(_)));
    let resumed = run
        .sim
        .peer(p(0))
        .and_then(Member::engine)
        .is_some_and(|e| e.counters().rounds_owed > 0);
    if paused && resumed {
        Ok(())
    } else {
        Err("peer 0 did not pause for its store and resume".to_owned())
    }
}

/// 0 and 2 hold write, 1 and 3 read, 4 sealed; {0,1} never meet {2,3}, and
/// 4 bridges.
fn sealed_relay(seed: u64) -> Run {
    let mut plan = Plan::new(5, SMALL_CHUNK).with_extra(sealed_expect);
    plan.world = plan
        .world
        .holds(p(1), MAIN, Some(Tier::Read))
        .holds(p(3), MAIN, Some(Tier::Read))
        .holds(p(4), MAIN, Some(Tier::Sealed));
    plan.cuts.push((vec![p(0), p(1)], vec![p(2), p(3)]));
    // The default workload's seven writes, refused for each of 1, 3 and 4:
    // a read or sealed key cannot sign.
    plan.expect.refused = 21;
    plan.build("engine-sealed-relay", seed, |s| s)
}

fn sealed_expect(run: &Run) -> Result<(), String> {
    let folder = run.folder();
    let e = run
        .sim
        .peer(p(4))
        .and_then(Member::engine)
        .ok_or("no peer 4")?;
    let view = e.folder(&folder).ok_or("peer 4 lacks the folder")?;
    if view.tier != Tier::Sealed || !e.files(&folder).is_empty() || view.stored_chunks.is_empty() {
        return Err("peer 4 is not a sealed holder of every chunk".to_owned());
    }
    Ok(())
}

/// How many small files each of the late-joiner scenario's writers writes.
const LATE_FILES: u64 = 90;

/// Peer 4 (read key, `max_records` 64) meets the others, then is isolated
/// from 0.8 s to 15 s while 0 to 3 write [`LATE_FILES`] small files each from
/// 1 s: it comes back with per-peer state, so it catches up through Since
/// pages of 64 (and reconciliation, which ends each of its rounds).
fn late_joiner(seed: u64) -> Run {
    let mut plan = Plan::new(5, SMALL_CHUNK).with_extra(late_expect);
    plan.world = plan.world.holds(p(4), MAIN, Some(Tier::Read));
    plan.tweak = |id, c| {
        if id == p(4) {
            c.max_records = 64;
        }
    };
    plan.workloads = (0..4u64)
        .map(|w| {
            let steps = (0..LATE_FILES)
                .map(|i| {
                    write(
                        w,
                        100 + i,
                        &format!("p{w}/f{i:03}.txt"),
                        64,
                        if i == 0 {
                            FIRST
                        } else {
                            Duration::from_millis(100)
                        },
                    )
                })
                .collect();
            (p(w), steps)
        })
        .collect();
    plan.build("engine-late-joiner", seed, |s| {
        s.fault(Fault::Partition {
            partition: Partition::isolate(p(4), [p(0), p(1), p(2), p(3)]),
            from: Instant::from_millis(800),
            until: Instant::from_secs(15),
        })
    })
}

fn late_expect(run: &Run) -> Result<(), String> {
    let e = run
        .sim
        .peer(p(4))
        .and_then(Member::engine)
        .ok_or("no peer 4")?;
    let pages = e.counters().most_reply_pages;
    let records = e
        .folder(&run.folder())
        .map_or(0, |v| v.records.len() as u64);
    if records < 4 * LATE_FILES || pages < 5 {
        return Err(format!(
            "peer 4 caught up with {records} records over at most {pages} pages on a connection"
        ));
    }
    Ok(())
}

/// A 12 MiB file in 1 MiB chunks, a 2 MiB send budget, an 8 MiB send queue.
fn pacing(seed: u64) -> Run {
    let mut plan = Plan::new(5, BIG_CHUNK).with_extra(pacing_expect);
    plan.workloads = BTreeMap::from([(p(0), vec![write(0, 1, "p0/huge.bin", 12 << 20, FIRST)])]);
    plan.tweak = |_, c| c.send_budget = 2 << 20;
    plan.build("engine-pacing", seed, |s| {
        s.network(NetworkConfig::default().max_send_queue(8 << 20))
    })
}

fn pacing_expect(run: &Run) -> Result<(), String> {
    let deferrals = run
        .sim
        .peer(p(0))
        .and_then(Member::engine)
        .map_or(0, |e| e.counters().deferrals);
    if deferrals == 0 {
        return Err("the writer never held a frame back for its budget".to_owned());
    }
    Ok(())
}

/// The path both clones write.
pub const CLONE_PATH: &str = "clones/shared.txt";

/// Six peers; 0 and 5 share a device seed and never meet. {0,1,2} are cut
/// from {3,4,5} from 0.5 s to 20 s: both clones write [`CLONE_PATH`] at 1 s,
/// 5 then its default workload and one more file, 0 its default workload at
/// 9 s and one more file at about 31 s, and 5 one more at about 45 s. Each
/// clone so receives, under its own device ID, a record above its high-water
/// mark (0's of 9 s at 5, 5's of 45 s at 0): the own-ID hint at both.
fn clones(seed: u64) -> Run {
    let mut plan = Plan::new(6, SMALL_CHUNK).with_extra(clones_expect);
    plan.world = plan.world.clone_device(p(0), p(5));
    plan.cuts.push((vec![p(0)], vec![p(5)]));
    plan.expect.own_counter_ahead = true;
    let mut five = vec![write(5, 40, CLONE_PATH, 90, FIRST)];
    five.extend(default_workload(
        p(5),
        SMALL_CHUNK,
        GAP,
        Duration::from_millis(100),
    ));
    five.push(write(5, 41, "p5/extra.txt", 50, GAP));
    five.push(write(5, 42, "p5/later.txt", 50, Duration::from_secs(43)));
    let mut zero = vec![write(0, 40, CLONE_PATH, 80, FIRST)];
    zero.extend(default_workload(
        p(0),
        SMALL_CHUNK,
        Duration::from_secs(8),
        GAP,
    ));
    zero.push(write(0, 41, "p0/after.txt", 50, Duration::from_secs(20)));
    plan.workloads.insert(p(5), five);
    plan.workloads.insert(p(0), zero);
    plan.build("engine-clones", seed, |s| {
        s.fault(Fault::Partition {
            partition: Partition::between(vec![p(0), p(1), p(2)], vec![p(3), p(4), p(5)]),
            from: Instant::from_millis(500),
            until: Instant::from_secs(20),
        })
    })
}

fn clones_expect(run: &Run) -> Result<(), String> {
    let folder = run.folder();
    let ahead = |peer: PeerId| {
        run.ledger
            .borrow()
            .issues
            .iter()
            .any(|(w, i)| *w == peer && i.kind == IssueKind::OwnCounterAhead)
    };
    if !ahead(p(0)) || !ahead(p(5)) {
        return Err("the clones did not both move their counters".to_owned());
    }
    for (id, m) in run.sim.peers() {
        let e = m.engine().ok_or("no engine")?;
        let conflicts: Vec<String> = e
            .files(&folder)
            .into_iter()
            .filter(|f| f.heads.len() > 1)
            .map(|f| f.path)
            .collect();
        if conflicts != [CLONE_PATH] {
            return Err(format!("{id}: {} conflicts, not the one", conflicts.len()));
        }
    }
    Ok(())
}

/// Everything at once: drops 0.1, latency 5 to 500 ms, a partition, a crash
/// and a restart, a full disk and skew; 0 to 3 write, 4 reads.
fn chaos(seed: u64) -> Run {
    let mut plan = Plan::new(5, SMALL_CHUNK);
    plan.world = plan.world.holds(p(4), MAIN, Some(Tier::Read));
    plan.workloads.remove(&p(4));
    plan.expect.store_failure = true;
    plan.build("engine-chaos", seed, |s| {
        s.network(
            NetworkConfig::default()
                .latency(Duration::from_millis(5), Duration::from_millis(500))
                .drops(0.1),
        )
        .fault(Fault::Partition {
            partition: Partition::between(vec![p(0), p(1)], vec![p(2), p(3), p(4)]),
            from: Instant::from_secs(2),
            until: Instant::from_secs(6),
        })
        .fault(Fault::Crash {
            peer: p(1),
            at: Instant::from_secs(1),
        })
        .fault(Fault::Restart {
            peer: p(1),
            at: Instant::from_secs(7),
        })
        .fault(Fault::DiskFull {
            peer: p(3),
            from: Instant::from_secs(3),
            until: Instant::from_secs(9),
        })
        .clock_ahead(p(2), Duration::from_secs(3600))
    })
}

/// The directory the tree-delete scenario deletes.
pub const TREE_DIR: &str = "tree";
/// How many files lie in it.
const TREE_FILES: u64 = 200;
/// The file edited beneath it while it is deleted.
pub const TREE_EDIT: &str = "tree/f007.txt";
/// The directory beneath it that a third member deletes at the same time.
pub const TREE_SUB: &str = "tree/sub";
/// The directory two members delete while apart.
pub const TREE_TWICE: &str = "twice";

/// Three writers. Peer 0 makes [`TREE_DIR`] at 1 s, [`TREE_SUB`] in it and
/// [`TREE_TWICE`] beside it, a file in each, and writes [`TREE_FILES`] small
/// files in [`TREE_DIR`], 10 ms apart; 0 is cut from 1 and 2 from
/// [`CUT_FROM`] to [`CUT_UNTIL`]. At [`CUT_EDITS`] 0 deletes [`TREE_DIR`]
/// (one tree delete) and [`TREE_TWICE`], while 1 edits [`TREE_EDIT`] and
/// deletes [`TREE_TWICE`] too, and 2 deletes [`TREE_SUB`] (a concurrent
/// nested tree delete). The edit survives as the directory's only live
/// content, and every member holds all four tree deletes and keeps the same
/// disk (oracle b').
fn tree_delete(seed: u64) -> Run {
    let mut plan = Plan::quiet(3, SMALL_CHUNK).with_extra(tree_expect);
    let gap = Duration::from_millis(10);
    let mkdir = |path: &str, delay| Step {
        delay,
        action: Action::Mkdir {
            path: path.to_owned(),
        },
    };
    let delete = |path: &str, delay| Step {
        delay,
        action: Action::Delete {
            path: path.to_owned(),
        },
    };
    let mut zero = vec![
        mkdir(TREE_DIR, FIRST),
        mkdir(TREE_SUB, gap),
        write(0, 190, &format!("{TREE_SUB}/s.txt"), 40, gap),
        mkdir(TREE_TWICE, gap),
        write(0, 191, &format!("{TREE_TWICE}/t.txt"), 40, gap),
    ];
    zero.extend(
        (0..TREE_FILES).map(|i| write(0, 200 + i, &format!("{TREE_DIR}/f{i:03}.txt"), 40, gap)),
    );
    let steps = u32::try_from(zero.len() - 1).unwrap_or(u32::MAX);
    let wrote = FIRST + gap * steps;
    zero.push(delete(TREE_DIR, CUT_EDITS.saturating_sub(wrote)));
    zero.push(delete(TREE_TWICE, gap));
    plan.workloads.insert(p(0), zero);
    plan.workloads.insert(
        p(1),
        vec![
            write(1, 300, TREE_EDIT, 70, CUT_EDITS),
            delete(TREE_TWICE, gap),
        ],
    );
    plan.workloads
        .insert(p(2), vec![delete(TREE_SUB, CUT_EDITS)]);
    plan.build("engine-tree-delete", seed, |s| {
        s.fault(Fault::Partition {
            partition: Partition::isolate(p(0), [p(1), p(2)]),
            from: CUT_FROM,
            until: CUT_UNTIL,
        })
    })
}

/// Whether `path` is `dir` or lies beneath it.
fn at_or_beneath(path: &str, dir: &str) -> bool {
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn tree_expect(run: &Run) -> Result<(), String> {
    let folder = run.folder();
    let edit = run.written(p(1), TREE_EDIT).ok_or("no edit")?;
    let deleted = run.written(p(0), TREE_DIR).ok_or("no tree delete")?;
    let nested = run.written(p(2), TREE_SUB).ok_or("no nested tree delete")?;
    let twice = [
        run.written(p(0), TREE_TWICE)
            .ok_or("no first delete of twice")?,
        run.written(p(1), TREE_TWICE)
            .ok_or("no second delete of twice")?,
    ];
    for (id, m) in run.sim.peers() {
        let files = m.engine().ok_or("no engine")?.files(&folder);
        let live: Vec<&str> = files
            .iter()
            .filter(|f| at_or_beneath(&f.path, TREE_DIR) && f.heads.iter().any(HeadView::is_file))
            .map(|f| f.path.as_str())
            .collect();
        if live != [TREE_EDIT] {
            return Err(format!(
                "{id}: {} live files beneath the deleted directory, not the edit alone",
                live.len()
            ));
        }
        if run.heads(id, TREE_EDIT) != [edit] {
            return Err(format!("{id}: the edit is not the only head of its file"));
        }
        // A tree delete is no head of a path: it is held beside them.
        if files
            .iter()
            .flat_map(|f| f.heads.iter())
            .any(|h| h.tombstone)
        {
            return Err(format!("{id}: a tombstone is a head"));
        }
        let view = m
            .engine()
            .and_then(|e| e.folder(&folder))
            .ok_or("no folder")?;
        let held: BTreeSet<RecordHash> = view
            .records
            .iter()
            .filter(|r| !r.cleanup)
            .map(|r| r.hash)
            .collect();
        if held != BTreeSet::from([deleted, edit, nested, twice[0], twice[1]]) {
            return Err(format!(
                "{id}: {} records beside the cleanups, not the four tree deletes and the edit",
                held.len()
            ));
        }
        if files
            .iter()
            .any(|f| at_or_beneath(&f.path, TREE_TWICE) && !f.heads.is_empty())
        {
            return Err(format!("{id}: something of {TREE_TWICE} is left"));
        }
    }
    Ok(())
}

/// The file the sealed-cleanup scenario writes three times.
pub const C_PATH: &str = "c.txt";

/// Peer 0 holds the write key, 1 the read key and 2 the sealed key. 0 writes
/// V1 of [`C_PATH`] at 1 s; 2 is cut from both from 5 s while 0 writes V2 at
/// 8 s and V3 at 12 s. At 20 s 2 meets 1 again, which serves it V3: a sealed
/// peer cannot tell that V3 replaces V1 (V3 names V2, which 2 never held), so
/// it holds both (the probe at 35 s). At 40 s it meets 0, whose round with it
/// ends in a cleanup that names V1 `because` V3, and 2 drops V1. Every clock
/// is unskewed (the clock rule untouched).
fn sealed_cleanup(seed: u64) -> Run {
    let mut plan = Plan::quiet(3, SMALL_CHUNK)
        .with_extra(sealed_cleanup_expect)
        .with_probe(Instant::from_secs(35), sealed_cleanup_probe);
    plan.world =
        plan.world
            .holds(p(1), MAIN, Some(Tier::Read))
            .holds(p(2), MAIN, Some(Tier::Sealed));
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, C_PATH, 80, FIRST),
            write(0, 2, C_PATH, 90, Duration::from_secs(7)),
            write(0, 3, C_PATH, 100, Duration::from_secs(4)),
        ],
    );
    plan.build("engine-sealed-cleanup", seed, |s| {
        s.fault(Fault::Partition {
            partition: Partition::isolate(p(2), [p(1)]),
            from: Instant::from_secs(5),
            until: Instant::from_secs(20),
        })
        .fault(Fault::Partition {
            partition: Partition::isolate(p(2), [p(0)]),
            from: Instant::from_secs(5),
            until: Instant::from_secs(40),
        })
    })
}

/// The three versions of [`C_PATH`], in order.
fn versions(run: &Run) -> Result<[RecordHash; 3], String> {
    let ledger = run.ledger.borrow();
    let all: Vec<RecordHash> = ledger
        .written
        .iter()
        .filter(|(w, path, _)| *w == p(0) && path == C_PATH)
        .map(|(_, _, h)| *h)
        .collect();
    <[RecordHash; 3]>::try_from(all).map_err(|v| format!("{} versions written, not 3", v.len()))
}

fn sealed_records(run: &Run) -> Result<BTreeSet<RecordHash>, String> {
    let e = run
        .sim
        .peer(p(2))
        .and_then(Member::engine)
        .ok_or("no peer 2")?;
    let view = e.folder(&run.folder()).ok_or("peer 2 lacks the folder")?;
    Ok(view.records.iter().map(|r| r.hash).collect())
}

fn sealed_cleanup_probe(run: &Run) -> Result<(), String> {
    let [v1, v2, v3] = versions(run)?;
    let held = sealed_records(run)?;
    if !(held.contains(&v1) && held.contains(&v3)) || held.contains(&v2) {
        return Err("the sealed peer does not hold V1 and V3 (and not V2) once back".to_owned());
    }
    Ok(())
}

fn sealed_cleanup_expect(run: &Run) -> Result<(), String> {
    let [v1, _, v3] = versions(run)?;
    let held = sealed_records(run)?;
    if held.contains(&v1) || !held.contains(&v3) {
        return Err("the sealed peer did not drop V1 for V3".to_owned());
    }
    let e = run
        .sim
        .peer(p(2))
        .and_then(Member::engine)
        .ok_or("no peer 2")?;
    let cleanups = e
        .folder(&run.folder())
        .map_or(0, |v| v.records.iter().filter(|r| r.cleanup).count());
    if cleanups == 0 {
        return Err("no cleanup reached the sealed peer".to_owned());
    }
    Ok(())
}

/// The file the expiry scenario deletes.
pub const E_PATH: &str = "e.txt";
/// How far every wall clock steps ahead: past `TOMBSTONE_HORIZON` (365
/// days) with a day to spare, and well inside the one-year clock rule of a
/// device whose clock stepped too.
const EXPIRY_STEP: u64 = 366 * 24 * 60 * 60;

/// Three writers. Peer 0 writes [`E_PATH`] at 1 s; 2 stops at 4 s holding
/// it, and 0 deletes it at 6 s. At 10 s every wall clock steps
/// [`EXPIRY_STEP`] ahead; at 12 s 1 writes another file, so the folder's own
/// time passes the tombstone's counter by more than the horizon and 0 and 1
/// forget it (the probe at 25 s). 2 comes back at 30 s, still holding the old
/// file, and brings it back (the owner's decision).
fn expiry(seed: u64) -> Run {
    let mut plan = Plan::quiet(3, SMALL_CHUNK)
        .with_extra(expiry_expect)
        .with_probe(Instant::from_secs(25), expiry_probe);
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, E_PATH, 60, FIRST),
            Step {
                delay: Duration::from_secs(5),
                action: Action::Delete {
                    path: E_PATH.to_owned(),
                },
            },
        ],
    );
    plan.workloads.insert(
        p(1),
        vec![write(1, 2, "later.txt", 60, Duration::from_secs(12))],
    );
    plan.build("engine-expiry", seed, |s| {
        let mut s = s
            .fault(Fault::Stop {
                peer: p(2),
                at: Instant::from_secs(4),
            })
            .fault(Fault::Restart {
                peer: p(2),
                at: Instant::from_secs(30),
            });
        for i in 0..3 {
            s = s.fault(Fault::ClockStep {
                peer: p(i),
                at: Instant::from_secs(10),
                secs: EXPIRY_STEP,
            });
        }
        s
    })
}

/// The file and its tombstone, as peer 0 wrote them.
fn file_and_tombstone(run: &Run) -> Result<(RecordHash, RecordHash), String> {
    let ledger = run.ledger.borrow();
    let all: Vec<RecordHash> = ledger
        .written
        .iter()
        .filter(|(w, path, _)| *w == p(0) && path == E_PATH)
        .map(|(_, _, h)| *h)
        .collect();
    match all.as_slice() {
        [file, tombstone] => Ok((*file, *tombstone)),
        _ => Err(format!("{} records written at the path, not 2", all.len())),
    }
}

fn expiry_probe(run: &Run) -> Result<(), String> {
    let (_, tombstone) = file_and_tombstone(run)?;
    for id in [p(0), p(1)] {
        let e = run
            .sim
            .peer(id)
            .and_then(Member::engine)
            .ok_or("a writer is down")?;
        let view = e.folder(&run.folder()).ok_or("no folder")?;
        if view.records.iter().any(|r| r.hash == tombstone) {
            return Err(format!("{id} still holds the expired tombstone"));
        }
        if !run.heads(id, E_PATH).is_empty() {
            return Err(format!("{id} still has heads at the deleted path"));
        }
    }
    Ok(())
}

fn expiry_expect(run: &Run) -> Result<(), String> {
    let (file, tombstone) = file_and_tombstone(run)?;
    for id in run.world.ids() {
        if run.heads(id, E_PATH) != [file] {
            return Err(format!("{id}: the old file did not come back"));
        }
        let e = run
            .sim
            .peer(id)
            .and_then(Member::engine)
            .ok_or("a member is down")?;
        let view = e.folder(&run.folder()).ok_or("no folder")?;
        if view.records.iter().any(|r| r.hash == tombstone) {
            return Err(format!("{id} holds the expired tombstone"));
        }
    }
    Ok(())
}

/// What builds one engine scenario's run for a seed.
pub type Builder = fn(u64) -> Run;

/// Every engine scenario's name and builder.
pub const ALL: [(&str, Builder); 25] = [
    ("engine-clean", clean),
    ("engine-drops", drops),
    ("engine-drops-stress", drops_stress),
    ("engine-reconnect", reconnect),
    ("engine-cross-reorder", cross_reorder),
    ("engine-partition", partition),
    ("engine-crash", crash),
    ("engine-skew", skew),
    ("engine-clock-ahead", clock_ahead),
    ("engine-disk-full", disk_full),
    ("engine-sealed-relay", sealed_relay),
    ("engine-late-joiner", late_joiner),
    ("engine-pacing", pacing),
    ("engine-clones", clones),
    ("engine-chaos", chaos),
    ("engine-tree-delete", tree_delete),
    ("engine-sealed-cleanup", sealed_cleanup),
    ("engine-expiry", expiry),
    (
        "engine-identical-edit-0",
        identical::equal_mtimes_zero_edits,
    ),
    ("engine-identical-edit-1", identical::equal_mtimes_one_edits),
    ("engine-identical-later-edits", identical::later_twin_edits),
    (
        "engine-identical-earlier-edits",
        identical::earlier_twin_edits,
    ),
    ("engine-identical-three", identical::three),
    ("engine-identical-delete", identical::delete),
    ("engine-identical-directories", identical::directories),
];

/// The run of the engine scenario `name` for `seed`.
#[must_use]
pub fn build(name: &str, seed: u64) -> Option<Run> {
    ALL.iter().find(|(n, _)| *n == name).map(|(_, f)| f(seed))
}

/// Builds and checks `name` for `seed`: its outcome, `converged` only when
/// every check passed.
#[must_use]
pub fn run(name: &str, seed: u64) -> Outcome {
    if let Some(mut r) = build(name, seed) {
        return r.check().outcome;
    }
    let mut outcome = Scenario::new(seed, 0, |_| {
        crate::toy::SetUnion::new(0, Duration::from_secs(1))
    })
    .build()
    .outcome();
    outcome.converged = false;
    outcome.failure = Some(format!("no engine scenario `{name}`"));
    outcome
}

mod identical;

#[cfg(test)]
mod tests {
    use super::*;

    /// Peer 0 holds the write key and 1 the read key; 1 writes one file,
    /// which the engine refuses (`NotWriteKey`), and the run expects
    /// `refused` writes refused.
    fn one_refused(refused: u64) -> Run {
        let mut plan =
            Plan::quiet(2, SMALL_CHUNK).then(p(1), vec![write(1, 1, "r.txt", 40, FIRST)]);
        plan.world = plan.world.holds(p(1), MAIN, Some(Tier::Read));
        plan.expect.refused = refused;
        plan.build("one-refused", 0, |s| s)
    }

    /// The bug: the oracle never read the ledger's refused writes, so a run
    /// in which the engine refused writes passed (fewer writes still
    /// converge; the phase 0 gate review's finding S2). Exactly the count
    /// expected passes, any other fails.
    #[test]
    fn a_run_with_a_write_refused_unexpectedly_fails_the_oracle() {
        let failure = |refused| one_refused(refused).check().outcome.failure;
        assert_eq!(failure(0).as_deref(), Some("1 writes refused, not 0"));
        assert_eq!(failure(2).as_deref(), Some("1 writes refused, not 2"));
        assert_eq!(failure(1), None);
    }
}
