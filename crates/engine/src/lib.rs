// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The sync engine: one [`Engine`] per device drives one protocol connection
//! per peer over the runtime traits, keeps one index per folder, fetches and
//! serves chunks, and writes and reads files in the simulator's file model.
//!
//! Status: phase 0. The engine runs the real `licketysync-keys`,
//! `licketysync-protocol` and `licketysync-index` crates on the
//! deterministic simulator (`licketysync-sim`): the latest-only index, its
//! exchange and the phase 0 gate (simulated peers converge). The file system
//! (scanning, journals, the path resolver, atomic writes), conflict copies'
//! names on a real disk, the archive and the deletion brake, `FastCDC`,
//! compression, `SQLite`, selective sync, the local API and libp2p are later
//! phases'. The plan ("Lickety-Sync: Project Plan") is the specification;
//! `spec/` carries the protocol, the keys and the threat model as they are
//! written down.
//!
//! # Shape
//!
//! - [`runtime`]: the traits the engine runs on (time, timers, transport,
//!   storage, randomness) and the six handlers of [`runtime::Peer`].
//! - [`config`]: [`EngineConfig`], its defaults and checks.
//! - `engine`: [`Engine`], `impl Peer`, how a connection's output is applied,
//!   and the three phases of every handler (`work`: decide, commit, send;
//!   `protocol.md` 4.5, "Durability before transmission").
//! - `sync`: index sync. The index exchange of each connection (rounds,
//!   requests, replies, pushes, judgements), every change to a folder's
//!   index through the one transaction of each handler, and the simulated
//!   disk's bases (`sync::disk`).
//! - `chunks` and `transfer`: what a folder lacks, per-record chunk judging,
//!   passes, chunk serving, `chunk_stored`; `inflight`: the chunk requests
//!   outstanding and their patience; `status`: the Status sent.
//! - `store`: the storage layout, the index's stored state and change sets;
//!   `open`: the folders opened at start (Checking, the open issue,
//!   Misconfigured, the clock rule's Closed); `pause`: the store-failure
//!   pause and its probe.
//! - `write`: fixed-size chunking and the four writes; [`inspect`]: read-only
//!   views and [`Engine::read_file`].
//! - `issues`: the bounded Issues list and the log counters; `folder`: the
//!   folder state machine; `pacing`: the send budget; `timers`: timer ids.
//!
//! # Determinism
//!
//! The engine performs no I/O of its own and reads no clock: time, timers,
//! the network, storage and randomness reach it only through the
//! [`runtime::Context`] of each handler, its maps are ordered (`BTreeMap`),
//! and it draws randomness only through the context, so a simulator seed
//! replays a whole run to the same trace hash. The one thing that uses
//! threads is the index's check of every stored record at open, whose
//! verdicts are joined in input order, so nothing about threads reaches the
//! run (gap G2).
//!
//! # Untrusted bytes and secrets
//!
//! Every byte from a peer is untrusted (TM-2, TM-23): it reaches the engine
//! only through the protocol crate's decoders, nothing it carries is used as
//! an index without `.get()`, and every per-connection table is bounded and
//! freed when the connection ends (TM-22). Every secret comes from the config
//! at each start and none is stored (`keys.md` 8.2); no secret and no path
//! appears in a `Debug` output, an issue or a counter (TM-6). `Debug` output
//! and issues do carry folder IDs and device IDs, which are not secret: the
//! daemon's logging redacts folder IDs by default, as TM-6 requires, before
//! any of it reaches a log.

mod chunks;
pub mod config;
mod conn;
mod engine;
mod folder;
mod inflight;
pub mod inspect;
mod issues;
mod open;
mod pacing;
mod pause;
pub mod runtime;
mod status;
mod store;
mod sync;
mod timers;
mod transfer;
mod work;
mod write;

#[cfg(test)]
mod regressions;
#[cfg(test)]
mod rules;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;

pub use config::{ConfigError, EngineConfig, MAX_FOLDERS};
pub use engine::Engine;
pub use folder::{FolderState, OpenCounts, MAX_TRANSITIONS};
pub use issues::{
    CloseCounts, Counters, Issue, IssueClass, IssueEntry, IssueKind, Issues, StoreFailureCause,
    Subject, MAX_LOCAL_ISSUES, MAX_PEER_ISSUES, MAX_RECORD_ISSUES_PER_FOLDER, OPEN_ISSUE_HASHES,
};
pub use timers::HARNESS_TIMERS;
pub use write::WriteFailure;

// The integration tests' dev-dependency, which the unit tests do not use (and
// must not: that build holds a second copy of the engine's types).
#[cfg(test)]
use licketysync_sim as _;

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-engine";
