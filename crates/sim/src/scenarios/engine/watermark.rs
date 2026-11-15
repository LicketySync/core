// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Deletions forgotten by a signed watermark (`protocol.md` 4.4, "Expiry by
//! the watermark"), end to end. Every member checks for a watermark every
//! [`CHECK`] and signs at most once per [`INTERVAL`] (the protocol's hour
//! and day, scaled alike on every member, which section 5 lets the
//! simulator do); a year passes as a wall-clock step ([`Fault::ClockStep`]),
//! the deletion horizon itself unscaled. Each run ends with the full oracle
//! (every member holds the same records and heads, the same disk) and its
//! own expectations: who signed, the greatest watermark held, and which
//! deletions are gone.
//!
//! - `engine-watermark-offline`: the one write holder, offline from just
//!   after its delete until a year later, signs at its open, and the read
//!   holders forget the deletion together once it reaches them.
//! - `engine-watermark-late`: a deletion that reaches a write holder late,
//!   dated below one it has held a year, holds its signing back until it
//!   too is a year old there.
//! - `engine-watermark-two`: two write holders apart sign different
//!   watermarks; once they meet every member holds both, the greater
//!   counting.
//! - `engine-watermark-replay`: a sealed peer, which keeps the deletion,
//!   offers it again below the greatest watermark: a read holder ignores it
//!   unverified, and the write holder, once it meets the sealed peer, names
//!   it in a case-(c) cleanup, and it is gone everywhere.
//! - `engine-watermark-sealed`: a write holder whose only check after the
//!   year is the one its resume from sleep makes signs then, and a sealed
//!   peer, which reads no watermark, keeps the deletion until the round the
//!   watermark owes toward it names it (case (c)).

use core::time::Duration;
use std::collections::BTreeSet;

use licketysync_engine::EngineConfig;
use licketysync_engine::inspect::FolderView;
use licketysync_engine::runtime::{Instant, PeerId};
use licketysync_keys::{RecordHash, Tier};

use super::{FIRST, Plan, Run, SMALL_CHUNK, p, write};
use crate::member::{Action, Member, Step};
use crate::network::Partition;
use crate::scenario::Fault;
use crate::world::MAIN;

/// How often a write holder checks: `WATERMARK_CHECK_INTERVAL` scaled.
pub const CHECK: Duration = Duration::from_secs(2);
/// The least time between two watermarks a write holder signs, and between
/// two rounds a change of the greatest watermark owes toward a sealed peer:
/// `WATERMARK_INTERVAL` scaled.
pub const INTERVAL: Duration = Duration::from_secs(20);
/// A year and a day, in seconds: past `TOMBSTONE_HORIZON`.
const YEAR_AND_A_DAY: u64 = 366 * 24 * 60 * 60;

/// Every member's watermark intervals scaled ([`CHECK`], [`INTERVAL`]).
pub fn scaled(_: PeerId, config: &mut EngineConfig) {
    config.timing.watermark_check = CHECK;
    config.timing.watermark_interval = INTERVAL;
}

/// A plan of `peers` members with no workload and the scaled intervals.
fn plan(peers: u32) -> Plan {
    let mut plan = Plan::quiet(peers, SMALL_CHUNK);
    plan.tweak = scaled;
    plan
}

/// A delete of `path`, `delay` after the step before.
fn delete(path: &str, delay: Duration) -> Step {
    Step {
        delay,
        action: Action::Delete {
            path: path.to_owned(),
        },
    }
}

/// Every wall clock steps `secs` ahead at `at`.
fn step_all(
    mut s: crate::scenario::Scenario<Member>,
    peers: u64,
    at: Instant,
    secs: u64,
) -> crate::scenario::Scenario<Member> {
    for i in 0..peers {
        s = s.fault(Fault::ClockStep {
            peer: p(i),
            at,
            secs,
        });
    }
    s
}

/// `id`'s view of the main folder.
fn view(run: &Run, id: PeerId) -> Result<FolderView, String> {
    run.sim
        .peer(id)
        .and_then(Member::engine)
        .and_then(|e| e.folder(&run.folder()))
        .ok_or_else(|| format!("{id}: no folder"))
}

/// The record hashes `id` holds.
fn held(run: &Run, id: PeerId) -> Result<BTreeSet<RecordHash>, String> {
    Ok(view(run, id)?.records.iter().map(|r| r.hash).collect())
}

/// The deletion `peer` wrote last at `path`: its tombstone.
fn tombstone(run: &Run, peer: u64, path: &str) -> Result<RecordHash, String> {
    run.written(p(peer), path)
        .ok_or_else(|| format!("{} wrote nothing at {path}", p(peer)))
}

/// The watermarks `id` signed.
fn signed(run: &Run, id: PeerId) -> Result<u64, String> {
    Ok(run
        .sim
        .peer(id)
        .and_then(Member::engine)
        .ok_or_else(|| format!("{id}: down"))?
        .counters()
        .watermarks_signed)
}

/// The watermarks the cleanups `id` holds carry, above 0.
fn watermarks(run: &Run, id: PeerId) -> Result<BTreeSet<u64>, String> {
    Ok(view(run, id)?
        .records
        .iter()
        .filter(|r| r.cleanup && r.forget_before > 0)
        .map(|r| r.forget_before)
        .collect())
}

/// No member holds any of `gone`, and none has a head at `paths`.
fn forgotten(run: &Run, gone: &[RecordHash], paths: &[&str]) -> Result<(), String> {
    for id in run.world.ids() {
        let h = held(run, id)?;
        if let Some(r) = gone.iter().find(|r| h.contains(r)) {
            return Err(format!("{id} still holds {r:?}"));
        }
        if let Some(path) = paths.iter().find(|path| !run.heads(id, path).is_empty()) {
            return Err(format!("{id} has heads at {path}"));
        }
    }
    Ok(())
}

/// The file the offline write holder writes and deletes.
const OFF_PATH: &str = "off.txt";

/// Member 0 holds the write key, 1 and 2 the read key. 0 writes
/// [`OFF_PATH`] at 1 s and deletes it at 3 s, and stops at 6 s; every wall
/// clock steps a year and a day ahead at 10 s; 0 comes back at 20 s, opens,
/// finds the tombstone it has held a year by its own calendar though it was
/// offline most of it, and signs at once; 1 and 2 forget the tombstone in
/// the commit that holds the watermark.
pub(super) fn offline(seed: u64) -> Run {
    let mut plan = plan(3).with_extra(offline_expect);
    plan.world = plan
        .world
        .holds(p(1), MAIN, Some(Tier::Read))
        .holds(p(2), MAIN, Some(Tier::Read));
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, OFF_PATH, 60, FIRST),
            delete(OFF_PATH, Duration::from_secs(2)),
        ],
    );
    plan.build("engine-watermark-offline", seed, |s| {
        let s = s
            .fault(Fault::Stop {
                peer: p(0),
                at: Instant::from_secs(6),
            })
            .fault(Fault::Restart {
                peer: p(0),
                at: Instant::from_secs(20),
            });
        step_all(s, 3, Instant::from_secs(10), YEAR_AND_A_DAY)
    })
}

fn offline_expect(run: &Run) -> Result<(), String> {
    let t = tombstone(run, 0, OFF_PATH)?;
    if signed(run, p(0))? != 1 {
        return Err("member 0 did not sign one watermark at its open".to_owned());
    }
    forgotten(run, &[t], &[OFF_PATH])?;
    let h = view(run, p(0))?.watermark;
    for id in run.world.ids() {
        if view(run, id)?.watermark != h || h == 0 {
            return Err(format!("{id}: the greatest watermark differs"));
        }
    }
    Ok(())
}

/// The files of the late-arrival run: member 1's, deleted first, and member
/// 0's, deleted later.
const LATE_EARLY: &str = "early.txt";
const LATE_LATER: &str = "later.txt";

/// Members 0 and 1 hold the write key, 2 the read key. 1 writes
/// [`LATE_EARLY`] at 1 s and 0 writes [`LATE_LATER`]; 1 is cut from both
/// from 5 s to 40 s, deletes its file at 6 s, and stops at 42 s, once its
/// deletion has reached 0 and 2; 0 deletes its file at 8 s. At 45 s every
/// wall clock steps a year less 20 s ahead: 0 holds its own deletion a year,
/// but 1's, dated below it, arrived at 40 s and is young, so 0 signs
/// nothing (the probe at 55 s: both deletions still held everywhere). At
/// 60 s every clock steps 20 s more: both are old at 0, which signs past
/// both. 1 comes back at 80 s, signs at its open a watermark of its own
/// that changes nothing, and every member ends alike.
pub(super) fn late(seed: u64) -> Run {
    let mut plan = plan(3)
        .with_extra(late_expect)
        .with_probe(Instant::from_secs(55), late_probe);
    plan.world = plan.world.holds(p(2), MAIN, Some(Tier::Read));
    plan.workloads.insert(
        p(1),
        vec![
            write(1, 1, LATE_EARLY, 60, FIRST),
            delete(LATE_EARLY, Duration::from_secs(5)),
        ],
    );
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, LATE_LATER, 70, FIRST),
            delete(LATE_LATER, Duration::from_secs(7)),
        ],
    );
    plan.build("engine-watermark-late", seed, |s| {
        let s = s
            .fault(Fault::Partition {
                partition: Partition::isolate(p(1), [p(0), p(2)]),
                from: Instant::from_secs(5),
                until: Instant::from_secs(40),
            })
            .fault(Fault::Stop {
                peer: p(1),
                at: Instant::from_secs(42),
            })
            .fault(Fault::Restart {
                peer: p(1),
                at: Instant::from_secs(80),
            });
        let s = step_all(s, 3, Instant::from_secs(45), 365 * 24 * 60 * 60 - 20);
        step_all(s, 3, Instant::from_secs(60), 20)
    })
}

fn late_probe(run: &Run) -> Result<(), String> {
    let early = tombstone(run, 1, LATE_EARLY)?;
    let later = tombstone(run, 0, LATE_LATER)?;
    if signed(run, p(0))? != 0 {
        return Err("member 0 signed while the late deletion was young".to_owned());
    }
    for id in [p(0), p(2)] {
        let h = held(run, id)?;
        if !(h.contains(&early) && h.contains(&later)) {
            return Err(format!("{id} forgot a deletion early"));
        }
    }
    Ok(())
}

fn late_expect(run: &Run) -> Result<(), String> {
    let early = tombstone(run, 1, LATE_EARLY)?;
    let later = tombstone(run, 0, LATE_LATER)?;
    if signed(run, p(0))? != 1 {
        return Err("member 0 did not sign once both were old".to_owned());
    }
    forgotten(run, &[early, later], &[LATE_EARLY, LATE_LATER])
}

/// The files the two signers delete.
const TWO_A: &str = "a.txt";
const TWO_B: &str = "b.txt";

/// Members 0 and 1 hold the write key, 2 the read key; 0 is cut from both
/// from the start until 30 s. 0 writes [`TWO_A`] at 1 s and deletes it at
/// 3 s; 1 writes [`TWO_B`] at 1 s and deletes it at 5 s, a later counter.
/// Every wall clock steps a year and a day ahead at 10 s: 0 and 1 each sign
/// their own watermark apart, at their own deletion's counter. Once they
/// meet, every member holds both watermarks, the greatest counts, and no
/// deletion is left.
pub(super) fn two(seed: u64) -> Run {
    let mut plan = plan(3).with_extra(two_expect);
    plan.world = plan.world.holds(p(2), MAIN, Some(Tier::Read));
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, TWO_A, 60, FIRST),
            delete(TWO_A, Duration::from_secs(2)),
        ],
    );
    plan.workloads.insert(
        p(1),
        vec![
            write(1, 1, TWO_B, 70, FIRST),
            delete(TWO_B, Duration::from_secs(4)),
        ],
    );
    plan.build("engine-watermark-two", seed, |s| {
        let s = s.fault(Fault::Partition {
            partition: Partition::isolate(p(0), [p(1), p(2)]),
            from: Instant::ZERO,
            until: Instant::from_secs(30),
        });
        step_all(s, 3, Instant::from_secs(10), YEAR_AND_A_DAY)
    })
}

fn two_expect(run: &Run) -> Result<(), String> {
    let a = tombstone(run, 0, TWO_A)?;
    let b = tombstone(run, 1, TWO_B)?;
    for id in [p(0), p(1)] {
        if signed(run, id)? != 1 {
            return Err(format!("{id} did not sign its own watermark"));
        }
    }
    forgotten(run, &[a, b], &[TWO_A, TWO_B])?;
    let first = watermarks(run, p(0))?;
    if first.len() != 2 {
        return Err(format!("{} watermarks held, not two", first.len()));
    }
    let greatest = first.iter().max().copied().unwrap_or(0);
    for id in run.world.ids() {
        if watermarks(run, id)? != first {
            return Err(format!("{id} holds other watermarks"));
        }
        if view(run, id)?.watermark != greatest {
            return Err(format!("{id}: the greater does not count"));
        }
    }
    Ok(())
}

/// The file whose deletion is replayed.
const REPLAY_PATH: &str = "replay.txt";

/// Member 0 holds the write key, 1 the read key and 2 the sealed key. 0
/// writes [`REPLAY_PATH`] at 1 s and deletes it at 3 s; every member holds
/// the tombstone; 0 and 2 are cut from each other from 5 s to 40 s. Every
/// wall clock steps a year and a day ahead at 10 s: 0 signs, and 1 forgets
/// the tombstone once the watermark reaches it. The sealed peer, which
/// reads no watermark, keeps it, and offers it again to 1 in the round that
/// the change of the greatest watermark owes there: below the greatest
/// watermark, 1 ignores it unverified. At 40 s 0 meets 2, is offered the
/// tombstone, verifies and notes it, and names it at its round's end in a
/// case-(c) cleanup that carries the watermark; 2 drops it, and every member
/// ends alike.
pub(super) fn replay(seed: u64) -> Run {
    let mut plan = plan(3).with_extra(replay_expect);
    plan.world =
        plan.world
            .holds(p(1), MAIN, Some(Tier::Read))
            .holds(p(2), MAIN, Some(Tier::Sealed));
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, REPLAY_PATH, 60, FIRST),
            delete(REPLAY_PATH, Duration::from_secs(2)),
        ],
    );
    plan.build("engine-watermark-replay", seed, |s| {
        let s = s.fault(Fault::Partition {
            partition: Partition::isolate(p(2), [p(0)]),
            from: Instant::from_secs(5),
            until: Instant::from_secs(40),
        });
        step_all(s, 3, Instant::from_secs(10), YEAR_AND_A_DAY)
    })
}

fn replay_expect(run: &Run) -> Result<(), String> {
    let t = tombstone(run, 0, REPLAY_PATH)?;
    forgotten(run, &[t], &[REPLAY_PATH])?;
    let read = run
        .sim
        .peer(p(1))
        .and_then(Member::engine)
        .ok_or("member 1 is down")?;
    if read.counters().of(licketysync_protocol::Cause::Expired) == 0 {
        return Err("the read holder was never offered the expired tombstone".to_owned());
    }
    let carrying = view(run, p(0))?
        .records
        .iter()
        .filter(|r| r.cleanup && r.forget_before > 0)
        .count();
    if carrying < 2 {
        return Err(format!(
            "member 0 holds {carrying} cleanups carrying the watermark, not the watermark's and the case-(c) one"
        ));
    }
    Ok(())
}

/// The file whose deletion a sealed peer keeps.
const SEALED_PATH: &str = "sealed.txt";

/// Member 0's periodic check comes after the run ([`resume_only`]).
const NO_PERIODIC_CHECK: Duration = Duration::from_secs(100_000);

/// [`scaled`], with member 0's periodic check after the run's end: its
/// checks are the open's and the resume's.
fn resume_only(id: PeerId, config: &mut EngineConfig) {
    scaled(id, config);
    if id == p(0) {
        config.timing.watermark_check = NO_PERIODIC_CHECK;
    }
}

/// Member 0 holds the write key, 1 the read key and 2 the sealed key. 0
/// writes [`SEALED_PATH`] at 1 s and deletes it at 3 s; every member holds
/// the tombstone. Every wall clock steps a year and a day ahead at 10 s, and
/// member 0's device resumes from sleep at 12 s ([`Fault::Resume`]); its
/// periodic check comes after the run ([`resume_only`]), so the check the
/// resume makes is what signs (the probe at 13 s), and with 1 it forgets
/// the tombstone. The sealed peer holds the watermark's cleanup but reads
/// no watermark, and keeps the tombstone until the round that the change of
/// the greatest watermark owes toward it (at once, the first in its
/// interval) brings it to 0, which finds it expired and names it in a
/// case-(c) cleanup. Then every member holds the same records.
pub(super) fn sealed(seed: u64) -> Run {
    let mut plan = plan(3)
        .with_extra(sealed_expect)
        .with_probe(Instant::from_secs(13), sealed_probe);
    plan.tweak = resume_only;
    plan.world =
        plan.world
            .holds(p(1), MAIN, Some(Tier::Read))
            .holds(p(2), MAIN, Some(Tier::Sealed));
    plan.workloads.insert(
        p(0),
        vec![
            write(0, 1, SEALED_PATH, 60, FIRST),
            delete(SEALED_PATH, Duration::from_secs(2)),
        ],
    );
    plan.build("engine-watermark-sealed", seed, |s| {
        let s = s.fault(Fault::Resume {
            peer: p(0),
            at: Instant::from_secs(12),
        });
        step_all(s, 3, Instant::from_secs(10), YEAR_AND_A_DAY)
    })
}

fn sealed_probe(run: &Run) -> Result<(), String> {
    if signed(run, p(0))? != 1 {
        return Err("member 0 did not sign at its resume".to_owned());
    }
    Ok(())
}

fn sealed_expect(run: &Run) -> Result<(), String> {
    let t = tombstone(run, 0, SEALED_PATH)?;
    if signed(run, p(0))? != 1 {
        return Err("member 0 did not sign".to_owned());
    }
    for id in run.world.ids() {
        if held(run, id)?.contains(&t) {
            return Err(format!("{id} still holds the tombstone"));
        }
    }
    if view(run, p(2))?.watermark != 0 {
        return Err("the sealed peer read a watermark".to_owned());
    }
    Ok(())
}
