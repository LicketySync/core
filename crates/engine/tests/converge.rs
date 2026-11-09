// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The phase 0 gate: simulated peers converge (the engine brief's 13.4, as
//! the port brief's section 3 updates it). Every engine scenario of
//! `licketysync_sim::scenarios::engine` but the stress run
//! (`engine-drops-stress`, whose pass rate is reported instead) runs here,
//! one `#[test]` per scenario, over seeds 0 to 4, each with the harness's
//! full oracle at the end and again after 60 s (`Run::check`).
//! `LICKETYSYNC_ENGINE_SEEDS=<n>` runs seeds 0 to n - 1 instead. The seeds of
//! a scenario run on threads of their own, each building its own run (a run
//! is not `Send`), at most as many at once as the machine has cores. A
//! failure names the scenario and the seed and prints the outcome with its
//! last events and the oracle's first difference.
//!
//! And the proof for gap G2: a crash-and-restart scenario run twice in one
//! process gives the same trace and the same state, whatever threads the
//! index's check at open uses.

#![allow(
    unused_crate_dependencies,
    clippy::panic,
    reason = "integration tests link every dev-dependency; test code"
)]

use std::num::NonZeroUsize;
use std::thread;

use licketysync_sim::scenarios::engine;

/// The seeds each scenario runs over: [`GATE_SEEDS`] unless
/// `LICKETYSYNC_ENGINE_SEEDS` names another count.
fn seeds() -> u64 {
    std::env::var("LICKETYSYNC_ENGINE_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(GATE_SEEDS)
}

/// Seeds 0 to 4.
const GATE_SEEDS: u64 = 5;

/// `name` for one seed: its trace hash and state digest, or why it failed.
fn check(name: &str, seed: u64) -> Result<(u64, u64), String> {
    let mut run = engine::build(name, seed).ok_or_else(|| format!("no scenario {name}"))?;
    let report = run.check();
    if report.ok() {
        Ok((report.outcome.trace_hash, report.digest))
    } else {
        Err(format!("{name} seed {seed}:\n{}", report.outcome))
    }
}

/// Every seed of `name` converges.
fn gate(name: &str) {
    let width = thread::available_parallelism().map_or(1, NonZeroUsize::get) as u64;
    let all: Vec<u64> = (0..seeds()).collect();
    let mut failures = Vec::new();
    for batch in all.chunks(usize::try_from(width).unwrap_or(1).max(1)) {
        thread::scope(|s| {
            let runs: Vec<_> = batch
                .iter()
                .map(|&seed| s.spawn(move || check(name, seed)))
                .collect();
            for r in runs {
                match r.join() {
                    Ok(Ok(_)) => {}
                    Ok(Err(why)) => failures.push(why),
                    Err(_) => failures.push(format!("{name}: a seed's run panicked")),
                }
            }
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

macro_rules! gate {
    ($($test:ident => $name:literal),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                gate($name);
            }
        )*

        /// The scenarios the gate runs.
        const GATED: &[&str] = &[$($name),*];
    };
}

gate! {
    clean => "engine-clean",
    drops => "engine-drops",
    reconnect => "engine-reconnect",
    cross_reorder => "engine-cross-reorder",
    partition => "engine-partition",
    crash => "engine-crash",
    skew => "engine-skew",
    clock_ahead => "engine-clock-ahead",
    disk_full => "engine-disk-full",
    sealed_relay => "engine-sealed-relay",
    late_joiner => "engine-late-joiner",
    pacing => "engine-pacing",
    clones => "engine-clones",
    chaos => "engine-chaos",
    tree_delete => "engine-tree-delete",
    sealed_cleanup => "engine-sealed-cleanup",
    expiry => "engine-expiry",
    identical_edit_0 => "engine-identical-edit-0",
    identical_edit_1 => "engine-identical-edit-1",
    identical_later_edits => "engine-identical-later-edits",
    identical_earlier_edits => "engine-identical-earlier-edits",
    identical_three => "engine-identical-three",
    identical_delete => "engine-identical-delete",
    identical_directories => "engine-identical-directories",
}

/// The stress run, outside the gate.
const STRESS: &str = "engine-drops-stress";

#[test]
fn the_gate_runs_every_engine_scenario_but_the_stress_run() {
    let mut want: Vec<&str> = engine::ALL
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| *n != STRESS)
        .collect();
    let mut have = GATED.to_vec();
    want.sort_unstable();
    have.sort_unstable();
    assert_eq!(have, want);
}

/// The bug: the state digest left out every chunk on the pending-free
/// list, so a chunk named again while listed (here, the file a returning
/// device brings back after its tombstone expired, seed 6) entered the state
/// when the next round's end cleared the list, and the recheck saw the state
/// change.
#[test]
fn a_pending_free_chunk_named_again_is_no_change_of_state_at_the_recheck() {
    check("engine-expiry", 6).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn a_crash_and_restart_run_twice_in_one_process_replays_exactly() {
    let first = check("engine-crash", 1).unwrap_or_else(|e| panic!("{e}"));
    let again = check("engine-crash", 1).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(first, again, "the same seed gives the same trace and state");
    let other = check("engine-crash", 2).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(first.0, other.0, "another seed runs otherwise");
}
