// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A [`Member`]: the real engine plus a scripted workload of writes, run on
//! the harness's own timer (id [`HARNESS_TIMERS`], which the engine ignores),
//! and the [`Ledger`] the members of one run share.
//!
//! The workload persists its next step under `w/step` in the same
//! transaction as the engine's write: it stages its key, then calls the
//! engine, whose commit carries both; when the engine fails for its store, the
//! rollback discards both and the step is tried again later. A write the
//! engine refuses up front (a read or sealed key) commits the step alone. So
//! a member continues after a crash or a restart from the step after the
//! last one committed, and a step is never done twice.
//!
//! A member may be cut from some peers for the whole run ([`Member::cut`]):
//! it never passes their connection to the engine, as if the two devices
//! never met. The simulator's partitions need an end that the run waits for,
//! and two clones that ever met would close for their equal device keys.
//!
//! The ledger maps every record hash a member wrote to the bytes it expects
//! there, so that the oracle can check every reassembly, and records what an
//! instance raised or broke before a crash took its memory: issues, closes
//! that blame a peer, internal errors, whether each start showed Checking,
//! and, over every instance of a member, its high-water mark after each
//! handler and the counter of each record it wrote, so that a mark that falls
//! or a counter given twice is seen across crashes.

use core::cell::RefCell;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::runtime::{Context, Peer, PeerId, TimerId};
use licketysync_engine::{
    ConfigError, Engine, EngineConfig, FolderState, Issue, WriteFailure, HARNESS_TIMERS,
};
use licketysync_keys::{FolderId, RecordHash};

/// The workload's timer: the first of the harness's ids.
pub const STEP_TIMER: TimerId = TimerId::new(HARNESS_TIMERS);

/// The key of the next step to run.
const STEP_KEY: &[u8] = b"w/step";

/// How long a member waits to try a step again after its store failed.
pub const RETRY: Duration = Duration::from_millis(300);

/// One write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Writes `content` at `path`.
    Write {
        /// The path.
        path: String,
        /// The bytes.
        content: Vec<u8>,
    },
    /// Deletes `path`.
    Delete {
        /// The path.
        path: String,
    },
    /// Renames `from` to `to`.
    Rename {
        /// The old path.
        from: String,
        /// The new path.
        to: String,
    },
    /// Makes a directory.
    Mkdir {
        /// The path.
        path: String,
    },
}

/// One step of a workload: its delay after the previous step (or after the
/// instance starts, for the first one it runs) and what it writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The delay.
    pub delay: Duration,
    /// The write.
    pub action: Action,
}

/// What the members of one run share (module documentation).
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    /// Each record a member wrote, and the bytes it holds (empty for a
    /// directory or a tombstone).
    pub bytes: BTreeMap<RecordHash, Vec<u8>>,
    /// Every issue any instance raised, with its peer.
    pub issues: Vec<(PeerId, Issue)>,
    /// Closes for `PROTOCOL_ERROR`, `VERIFICATION_FAILED`,
    /// `MESSAGE_TOO_LARGE`, `TIMEOUT` or `NO_COMMON_FOLDER`, sent or
    /// received, by every instance.
    pub bad_closes: u64,
    /// Internal errors of every instance.
    pub internal_errors: u64,
    /// Each start, with whether it showed Checking first and then Syncing or
    /// Up to date.
    pub starts: Vec<(PeerId, bool)>,
    /// Writes the engine refused up front (a read or sealed key).
    pub refused: u64,
    /// Every write that made a record: its peer, path and record hash.
    pub written: Vec<(PeerId, String, RecordHash)>,
    /// Configs the engine refused: a scenario bug.
    pub configs_refused: Vec<(PeerId, ConfigError)>,
    /// Each member's high-water mark when it was last looked at, over every
    /// instance.
    pub hw: BTreeMap<PeerId, u64>,
    /// Each time a member's high-water mark was lower than when it was last
    /// looked at: the member, the mark before and the mark then.
    pub hw_fell: Vec<(PeerId, u64, u64)>,
    /// The counter of each record a member wrote, over every instance.
    pub counters: BTreeMap<(PeerId, u64), RecordHash>,
    /// Each counter a member gave to two different records.
    pub counters_reused: Vec<(PeerId, u64)>,
}

/// What a member has copied into the ledger so far.
#[derive(Clone, Copy, Debug, Default)]
struct Seen {
    bad_closes: u64,
    internal: u64,
}

/// The engine and its workload.
#[derive(Debug)]
pub struct Member {
    /// The engine, or why its config was refused (a scenario bug the oracle
    /// reports; the member then does nothing).
    engine: Result<Engine, ConfigError>,
    peer: PeerId,
    folder: Option<FolderId>,
    steps: Vec<Step>,
    next: usize,
    cut: BTreeSet<PeerId>,
    ledger: Rc<RefCell<Ledger>>,
    seen: Seen,
}

impl Member {
    /// An engine built from `config` as peer `peer`, running `steps` on
    /// `folder`, never meeting the peers in `cut`.
    #[must_use]
    pub fn new(
        config: EngineConfig,
        peer: PeerId,
        folder: Option<FolderId>,
        steps: Vec<Step>,
        cut: BTreeSet<PeerId>,
        ledger: Rc<RefCell<Ledger>>,
    ) -> Self {
        let engine = Engine::new(config);
        if let Err(e) = &engine {
            ledger.borrow_mut().configs_refused.push((peer, *e));
        }
        Self {
            engine,
            peer,
            folder,
            steps,
            next: 0,
            cut,
            ledger,
            seen: Seen::default(),
        }
    }

    /// The engine, unless its config was refused.
    #[must_use]
    pub fn engine(&self) -> Option<&Engine> {
        self.engine.as_ref().ok()
    }

    /// Whether every step has run.
    #[must_use]
    pub fn done(&self) -> bool {
        self.next >= self.steps.len()
    }

    /// The peers this member never meets.
    #[must_use]
    pub const fn cut(&self) -> &BTreeSet<PeerId> {
        &self.cut
    }

    fn arm(&self, cx: &mut dyn Context, delay: Duration) {
        if !self.done() {
            let at = cx.now().saturating_add(delay);
            cx.set_timer(STEP_TIMER, at);
        }
    }

    /// Copies what the engine raised or broke since the last call into the
    /// ledger.
    fn note(&mut self) {
        let Ok(engine) = &self.engine else {
            return;
        };
        let issues = engine.issues().list();
        let counters = engine.counters();
        let hw = self.folder.and_then(|f| engine.high_water(&f));
        let mut ledger = self.ledger.borrow_mut();
        if let Some(now) = hw {
            let before = ledger.hw.insert(self.peer, now).unwrap_or(0);
            if now < before {
                ledger.hw_fell.push((self.peer, before, now));
            }
        }
        // Each entry once: an issue raised again is merged into its entry,
        // and the list evicts within its bound, so entries are matched, not
        // counted by position.
        for issue in &issues {
            let known = ledger
                .issues
                .iter()
                .any(|(p, i)| *p == self.peer && i == issue);
            if !known {
                ledger.issues.push((self.peer, issue.clone()));
            }
        }
        let bad = counters.blaming_closes();
        ledger.bad_closes = ledger
            .bad_closes
            .saturating_add(bad.saturating_sub(self.seen.bad_closes));
        self.seen.bad_closes = bad;
        let internal = counters.internal_errors;
        ledger.internal_errors = ledger
            .internal_errors
            .saturating_add(internal.saturating_sub(self.seen.internal));
        self.seen.internal = internal;
    }

    /// Runs the next step (module documentation).
    fn step(&mut self, cx: &mut dyn Context) {
        let (Some(folder), Some(step), Ok(_)) = (
            self.folder,
            self.steps.get(self.next).cloned(),
            &self.engine,
        ) else {
            return;
        };
        let after = u64::try_from(self.next + 1).unwrap_or(u64::MAX);
        if cx.storage().put(STEP_KEY, &after.to_le_bytes()).is_err() {
            cx.storage().rollback();
            self.arm(cx, RETRY);
            return;
        }
        let mtime = i64::try_from(cx.wall_time())
            .unwrap_or(i64::MAX)
            .saturating_mul(1_000_000_000);
        let renamed = match &step.action {
            Action::Rename { from, .. } => self.current(&folder, from),
            _ => None,
        };
        let Ok(engine) = &mut self.engine else {
            return;
        };
        let written = match &step.action {
            Action::Write { path, content } => engine.write_file(cx, folder, path, content, mtime),
            Action::Delete { path } => engine.delete(cx, folder, path, mtime),
            Action::Rename { from, to } => engine.rename(cx, folder, from, to, mtime),
            Action::Mkdir { path } => engine.mkdir(cx, folder, path, mtime),
        };
        match written {
            Ok(hash) => {
                let bytes = match &step.action {
                    Action::Write { content, .. } => content.clone(),
                    Action::Rename { .. } => renamed
                        .and_then(|old| self.ledger.borrow().bytes.get(&old).cloned())
                        .unwrap_or_default(),
                    Action::Delete { .. } | Action::Mkdir { .. } => Vec::new(),
                };
                let path = match &step.action {
                    Action::Write { path, .. }
                    | Action::Delete { path }
                    | Action::Mkdir { path } => path,
                    Action::Rename { to, .. } => to,
                };
                let dot = self.engine().and_then(|e| e.dot(&folder, &hash));
                let mut ledger = self.ledger.borrow_mut();
                ledger.bytes.insert(hash, bytes);
                ledger.written.push((self.peer, path.clone(), hash));
                if let Some(d) = dot {
                    let given = *ledger
                        .counters
                        .entry((self.peer, d.counter))
                        .or_insert(hash);
                    if given != hash {
                        ledger.counters_reused.push((self.peer, d.counter));
                    }
                }
                drop(ledger);
                self.advance(cx);
            }
            Err(WriteFailure::Paused | WriteFailure::Store(_)) => {
                cx.storage().rollback();
                self.arm(cx, RETRY);
            }
            Err(_) => {
                self.ledger.borrow_mut().refused += 1;
                if cx.storage().commit().is_err() {
                    cx.storage().rollback();
                    self.arm(cx, RETRY);
                    return;
                }
                self.advance(cx);
            }
        }
    }

    fn advance(&mut self, cx: &mut dyn Context) {
        self.next += 1;
        let delay = self
            .steps
            .get(self.next)
            .map_or(Duration::ZERO, |s| s.delay);
        self.arm(cx, delay);
    }

    /// The record at `path` now, for a rename's expected bytes.
    fn current(&self, folder: &FolderId, path: &str) -> Option<RecordHash> {
        self.engine()?
            .files(folder)
            .into_iter()
            .find(|f| f.path == path)
            .and_then(|f| f.current)
    }

    /// Whether the folder's start showed Checking and then Syncing or Up to
    /// date.
    fn started_checking(&self) -> bool {
        let Some(engine) = self.engine() else {
            return false;
        };
        engine.folder_ids().all(|id| {
            let t = engine
                .folder(&id)
                .map(|v| v.transitions)
                .unwrap_or_default();
            matches!(
                t.as_slice(),
                [
                    (_, FolderState::Checking),
                    (_, FolderState::Syncing { .. } | FolderState::UpToDate),
                    ..
                ]
            )
        })
    }
}

impl Peer for Member {
    fn on_start(&mut self, cx: &mut dyn Context) {
        let Ok(engine) = &mut self.engine else {
            return;
        };
        engine.on_start(cx);
        self.next = cx
            .storage()
            .get(STEP_KEY)
            .ok()
            .flatten()
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .and_then(|b| usize::try_from(u64::from_le_bytes(b)).ok())
            .unwrap_or(0);
        let checking = self.started_checking();
        self.ledger.borrow_mut().starts.push((self.peer, checking));
        let delay = self
            .steps
            .get(self.next)
            .map_or(Duration::ZERO, |s| s.delay);
        self.arm(cx, delay);
        self.note();
    }

    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
        if let (false, Ok(engine)) = (self.cut.contains(&from), &mut self.engine) {
            engine.on_message(cx, from, bytes);
            self.note();
        }
    }

    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
        if id == STEP_TIMER {
            self.step(cx);
        } else if let Ok(engine) = &mut self.engine {
            engine.on_timer(cx, id);
        }
        self.note();
    }

    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        if let (false, Ok(engine)) = (self.cut.contains(&peer), &mut self.engine) {
            engine.on_connected(cx, peer);
            self.note();
        }
    }

    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
        if let (false, Ok(engine)) = (self.cut.contains(&peer), &mut self.engine) {
            engine.on_disconnected(cx, peer);
            self.note();
        }
    }

    fn on_stop(&mut self, cx: &mut dyn Context) {
        if let Ok(engine) = &mut self.engine {
            engine.on_stop(cx);
        }
        self.note();
    }
}

/// `len` bytes that are a function of `(peer, step)` alone.
#[must_use]
pub fn content(peer: u64, step: u64, len: usize) -> Vec<u8> {
    let mut state =
        peer.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ step.wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// The default workload of a writer (the brief's 13.2): a small file, a file
/// of more than three chunks, an empty file, a directory, an edit of the
/// small file, a rename of it, and a delete of the empty file, `gap` apart,
/// the first after `first`.
#[must_use]
pub fn default_workload(
    peer: PeerId,
    chunk_size: usize,
    first: Duration,
    gap: Duration,
) -> Vec<Step> {
    let p = peer.as_u64();
    let path = |name: &str| format!("p{p}/{name}");
    let actions = vec![
        Action::Write {
            path: path("small.txt"),
            content: content(p, 1, 100),
        },
        Action::Write {
            path: path("big.bin"),
            content: content(p, 2, chunk_size * 3 + chunk_size / 2),
        },
        Action::Write {
            path: path("empty.txt"),
            content: Vec::new(),
        },
        Action::Mkdir { path: path("dir") },
        Action::Write {
            path: path("small.txt"),
            content: content(p, 5, 150),
        },
        Action::Rename {
            from: path("small.txt"),
            to: path("renamed.txt"),
        },
        Action::Delete {
            path: path("empty.txt"),
        },
    ];
    actions
        .into_iter()
        .enumerate()
        .map(|(i, action)| Step {
            delay: if i == 0 { first } else { gap },
            action,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_is_a_function_of_peer_and_step() {
        assert_eq!(content(1, 2, 64), content(1, 2, 64));
        assert_ne!(content(1, 2, 64), content(2, 1, 64));
        assert_ne!(content(1, 2, 64), content(1, 3, 64));
        assert_eq!(content(0, 0, 0), Vec::<u8>::new());
    }

    #[test]
    fn the_default_workload_has_the_seven_steps() {
        let w = default_workload(
            PeerId::new(3),
            1024,
            Duration::from_secs(1),
            Duration::from_millis(300),
        );
        assert_eq!(w.len(), 7);
        assert_eq!(w.first().map(|s| s.delay), Some(Duration::from_secs(1)));
        assert!(
            matches!(&w.get(1).map(|s| &s.action), Some(Action::Write { content, .. }) if content.len() > 3 * 1024)
        );
        assert!(matches!(
            &w.get(5).map(|s| &s.action),
            Some(Action::Rename { .. })
        ));
    }
}
