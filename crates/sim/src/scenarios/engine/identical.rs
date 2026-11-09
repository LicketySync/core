// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Concurrent heads with identical content, twins, end to end (the
//! identical-heads bug of 2026-11-08; the index's own tests are
//! `licketysync-index`'s `tests::identical`). Two or three write members,
//! apart until [`APART_UNTIL`], each write [`T_PATH`] with the same bytes
//! (or make [`T_DIR`]); once they meet, every member holds every twin as a
//! head and shows one file, no conflict copy (the probe at [`PROBE_AT`]).
//! At [`CHANGE_AT`] one member edits or deletes the path. Each run ends with
//! the full oracle (every member holds the same records and heads and has
//! the same disk) and with [`one_head`]: nothing of the old content is left
//! anywhere, neither as a head nor as a conflict copy.
//!
//! The variants: equal `mtime_ns` (the twins written in the same second, so
//! the record hash decides which sits at the path; each member edits in a
//! run of its own, so that the editor's own twin sits at the path in one and
//! the other's in the other); member 1's twin two seconds later, so that it
//! sits at the path everywhere, with member 1 (its own head at the path) or
//! member 0 (the other's head at its path) editing; three members; a delete
//! instead of an edit; and two identical directories, one then deleted (a
//! tree delete). A failure names the twin that sat at the path before the
//! change, and what every member shows at the end.
//!
//! Every run failed on `main` before the fix, on every seed: the oracle
//! passed (every member ended with the same records, heads and disk) and
//! [`one_head`] did not, since the change covered only the twin that sat at
//! the path on the changing member's disk (its one base, 4.4 "Bases") and the
//! other twins stayed live everywhere. `S` now holds the bases' twins too
//! (4.4, "The vector and names of a new record"), and the runs are gate
//! scenarios in [`super::ALL`], `engine-identical-*`, each a few hundred
//! events; the tests here run the same builds over the gate's five seeds and
//! name, on a failure, the twin that sat at the path before the change.

use core::time::Duration;
use std::collections::BTreeSet;

use licketysync_engine::inspect::FileView;
use licketysync_engine::runtime::{Instant, PeerId};
use licketysync_keys::RecordHash;

use super::{p, Plan, Run, FIRST, SMALL_CHUNK};
use crate::member::{content, Action, Member, Step};
use crate::network::Partition;
use crate::scenario::Fault;

/// The file every twin writes.
const T_PATH: &str = "twin.txt";
/// The directory the directory variant makes twice.
const T_DIR: &str = "twin-dir";
/// The members meet here, after every twin is written.
const APART_UNTIL: Instant = Instant::from_secs(10);
/// Every twin is on every member's disk by now (a chunk pass that met a
/// `CHUNK_NOT_FOUND` waits up to a `STATUS_INTERVAL` for its next trigger).
const PROBE_AT: Instant = Instant::from_secs(45);
/// When the edit or the delete is made.
const CHANGE_AT: Duration = Duration::from_secs(50);

/// The twins' bytes: the same on every member.
fn twin_bytes() -> Vec<u8> {
    content(0, 70, 120)
}

/// What a member does, `delay` after its step before.
fn step(delay: Duration, action: Action) -> Step {
    Step { delay, action }
}

/// A twin of [`T_PATH`], `at` after the start.
fn twin(at: Duration) -> Step {
    step(
        at,
        Action::Write {
            path: T_PATH.to_owned(),
            content: twin_bytes(),
        },
    )
}

/// The change over the twins, at [`CHANGE_AT`], after a first step at `at`.
fn change(at: Duration, action: Action) -> Step {
    step(CHANGE_AT.saturating_sub(at), action)
}

/// An edit of [`T_PATH`] by `peer`: other bytes.
fn edit(peer: u64) -> Action {
    Action::Write {
        path: T_PATH.to_owned(),
        content: content(peer, 71, 150),
    }
}

/// `n` quiet write members, each cut from every other until
/// [`APART_UNTIL`], with `steps` as their workloads, the probe and the
/// final check set.
fn plan(name: &'static str, seed: u64, steps: Vec<(u64, Vec<Step>)>) -> Run {
    let n = u64::try_from(steps.len()).unwrap_or(0);
    let mut plan = Plan::quiet(u32::try_from(n).unwrap_or(0), SMALL_CHUNK)
        .with_extra(one_head)
        .with_probe(PROBE_AT, twins_shown_once);
    for (peer, s) in steps {
        plan = plan.then(p(peer), s);
    }
    plan.build(name, seed, |mut s| {
        for i in 0..n {
            s = s.fault(Fault::Partition {
                partition: Partition::isolate(p(i), (i + 1..n).map(p)),
                from: Instant::ZERO,
                until: APART_UNTIL,
            });
        }
        s
    })
}

/// Every path `peer` shows.
fn files(run: &Run, peer: PeerId) -> Vec<FileView> {
    let folder = run.folder();
    run.sim
        .peer(peer)
        .and_then(Member::engine)
        .map(|e| e.files(&folder))
        .unwrap_or_default()
}

/// `peer`'s view of `path`, if it has one.
fn file(run: &Run, peer: PeerId, path: &str) -> Option<FileView> {
    files(run, peer).into_iter().find(|f| f.path == path)
}

/// Every record written, in order, with its writer, at the path the first
/// write named (the twins' path), and that path.
fn written(run: &Run) -> (String, Vec<(PeerId, RecordHash)>) {
    let ledger = run.ledger.borrow();
    let path = ledger
        .written
        .first()
        .map(|(_, path, _)| path.clone())
        .unwrap_or_default();
    let all = ledger
        .written
        .iter()
        .filter(|(_, at, _)| *at == path)
        .map(|(w, _, h)| (*w, *h))
        .collect();
    (path, all)
}

/// The probe: before the change, every member shows every twin as a head
/// and makes no conflict copy.
fn twins_shown_once(run: &Run) -> Result<(), String> {
    let (path, twins) = written(run);
    let want: BTreeSet<RecordHash> = twins.iter().map(|(_, h)| *h).collect();
    if want.len() != run.world.ids().len() {
        return Err(format!("{} twins written, not one per member", want.len()));
    }
    for peer in run.world.ids() {
        let f = file(run, peer, &path).ok_or(format!("{peer}: no twin"))?;
        let heads: BTreeSet<RecordHash> = f.heads.iter().map(|h| h.hash).collect();
        if heads != want || !f.conflict_copies.is_empty() {
            return Err(format!(
                "{peer}: the twins are not every head with no conflict copy \
                 ({} heads, {} copies)",
                heads.len(),
                f.conflict_copies.len()
            ));
        }
    }
    Ok(())
}

/// The final check: on every member the path holds the change alone (the
/// edit, or the delete's tombstone; no head at all after a tree delete),
/// no conflict copy, and no other path (no copy made an ordinary file).
fn one_head(run: &Run) -> Result<(), String> {
    let (path, all) = written(run);
    let Some(((_, last), twins)) = all.split_last() else {
        return Err("nothing written".to_owned());
    };
    let name = |h: &RecordHash| {
        if h == last {
            "the change".to_owned()
        } else {
            twins
                .iter()
                .find(|(_, t)| t == h)
                .map_or_else(|| format!("{h}"), |(w, _)| format!("{w}'s twin"))
        }
    };
    let tree = path == T_DIR;
    let mut left = Vec::new();
    for peer in run.world.ids() {
        let files = files(run, peer);
        let others: Vec<&str> = files
            .iter()
            .filter(|f| f.path != path && !f.heads.is_empty())
            .map(|f| f.path.as_str())
            .collect();
        let at = files.iter().find(|f| f.path == path);
        let heads: Vec<String> = at
            .map(|f| f.heads.iter().map(|h| name(&h.hash)).collect())
            .unwrap_or_default();
        let copies: Vec<String> = at
            .map(|f| f.conflict_copies.iter().map(name).collect())
            .unwrap_or_default();
        let want: &[&str] = if tree { &[] } else { &["the change"] };
        if heads != want || !copies.is_empty() || !others.is_empty() {
            left.push(format!(
                "{peer}: heads {heads:?}, conflict copies {copies:?}, other paths {others:?}"
            ));
        }
    }
    if left.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the change over identical heads left the old content: {}",
            left.join("; ")
        ))
    }
}

/// Two twins, member 1's in the same second as member 0's or, when `later`,
/// two seconds after it (so that it sits at the path everywhere); `editor`
/// edits.
fn pair(name: &'static str, seed: u64, later: bool, editor: u64) -> Run {
    let at = |peer: u64| if peer == 1 && later { FIRST * 3 } else { FIRST };
    let steps = (0..2)
        .map(|peer| {
            let mut s = vec![twin(at(peer))];
            if peer == editor {
                s.push(change(at(peer), edit(peer)));
            }
            (peer, s)
        })
        .collect();
    plan(name, seed, steps)
}

/// Two twins in the same second; member 0 edits.
pub(super) fn equal_mtimes_zero_edits(seed: u64) -> Run {
    pair("engine-identical-edit-0", seed, false, 0)
}

/// Two twins in the same second; member 1 edits.
pub(super) fn equal_mtimes_one_edits(seed: u64) -> Run {
    pair("engine-identical-edit-1", seed, false, 1)
}

/// Member 1's twin two seconds later, at the path everywhere; member 1
/// edits.
pub(super) fn later_twin_edits(seed: u64) -> Run {
    pair("engine-identical-later-edits", seed, true, 1)
}

/// Member 1's twin two seconds later, at the path everywhere; member 0
/// edits.
pub(super) fn earlier_twin_edits(seed: u64) -> Run {
    pair("engine-identical-earlier-edits", seed, true, 0)
}

/// Three twins in the same second; member 0 edits.
pub(super) fn three(seed: u64) -> Run {
    plan(
        "engine-identical-three",
        seed,
        vec![
            (0, vec![twin(FIRST), change(FIRST, edit(0))]),
            (1, vec![twin(FIRST)]),
            (2, vec![twin(FIRST)]),
        ],
    )
}

/// Two twins in the same second; member 0 deletes the file.
pub(super) fn delete(seed: u64) -> Run {
    let gone = Action::Delete {
        path: T_PATH.to_owned(),
    };
    plan(
        "engine-identical-delete",
        seed,
        vec![
            (0, vec![twin(FIRST), change(FIRST, gone)]),
            (1, vec![twin(FIRST)]),
        ],
    )
}

/// Two members make [`T_DIR`] in the same second; member 0 deletes it.
pub(super) fn directories(seed: u64) -> Run {
    let mkdir = || {
        step(
            FIRST,
            Action::Mkdir {
                path: T_DIR.to_owned(),
            },
        )
    };
    let gone = Action::Delete {
        path: T_DIR.to_owned(),
    };
    plan(
        "engine-identical-directories",
        seed,
        vec![(0, vec![mkdir(), change(FIRST, gone)]), (1, vec![mkdir()])],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many seeds each variant runs: the gate's five.
    const SEEDS: u64 = 5;

    /// Which member's twin sits at the path at [`PROBE_AT`], on member 0 (the
    /// oracle checks that every member shows the same heads in the same order).
    fn at_the_path(run: &Run) -> String {
        let (path, twins) = written(run);
        let first = file(run, p(0), &path).and_then(|f| f.heads.first().map(|h| h.hash));
        twins
            .iter()
            .find(|(_, h)| Some(*h) == first)
            .map_or_else(|| "no twin".to_owned(), |(w, _)| format!("{w}'s twin"))
    }

    /// Every seed of every one of `builds` passes the oracle and its own
    /// checks; a failure names, beside the scenario and the seed, the twin that
    /// sat at the path before the change.
    fn passes(builds: &[fn(u64) -> Run]) {
        let failures: Vec<String> = builds
            .iter()
            .flat_map(|build| (0..SEEDS).map(move |seed| (build, seed)))
            .filter_map(|(build, seed)| {
                let mut run = build(seed);
                run.sim.run_until(PROBE_AT);
                let first = at_the_path(&run);
                let report = run.check();
                (!report.ok()).then(|| {
                    format!(
                        "{} seed {seed} ({first} at the path before the change):\n{}",
                        run.name, report.outcome
                    )
                })
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    }

    #[test]
    fn identical_concurrent_heads_next_save_covers_both() {
        // Equal mtime_ns: the record hash decides which twin sits at the path,
        // and each member edits in a run of its own.
        passes(&[equal_mtimes_zero_edits, equal_mtimes_one_edits]);
    }

    #[test]
    fn identical_concurrent_heads_with_different_mtimes_next_save_covers_both() {
        passes(&[later_twin_edits]);
    }

    #[test]
    fn identical_concurrent_heads_a_save_where_the_other_twin_sits_at_the_path_covers_both() {
        passes(&[earlier_twin_edits]);
    }

    #[test]
    fn three_identical_concurrent_heads_next_save_covers_all_three() {
        passes(&[three]);
    }

    #[test]
    fn identical_concurrent_heads_next_delete_covers_both() {
        passes(&[delete]);
    }

    #[test]
    fn identical_concurrent_directories_a_tree_delete_covers_both() {
        passes(&[directories]);
    }
}
