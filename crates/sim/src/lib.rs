// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Deterministic simulator: many peers in one process over a simulated clock and
//! network, seeded, with fault injection. Phase 0's gate: simulated peers
//! converge.
//!
//! Design. A [`Scenario`] names a seed, a number of peers, a factory that builds
//! each peer (any type implementing the engine's [`Peer`] trait), the network's
//! latency, connection-drop rate and reconnect delay, a schedule of faults, a
//! wall-clock epoch, an event budget and a convergence predicate.
//! [`Scenario::build`] starts the peers and returns a [`Sim`]: a discrete-event
//! scheduler whose queue is ordered by time and then by a sequence number, so
//! ties never depend on anything but the order events were created in. Every
//! random choice (a latency, a connection that drops, a reconnect delay, a
//! peer's request for random bytes) comes from one [`rng::SimRng`] seeded from
//! the scenario's seed, so the same seed replays the same run and prints the
//! same trace hash. The network keeps the transport contract of the protocol
//! spec (3.1): each connection is a reliable, ordered stream, so a message is
//! never duplicated or overtaken within a connection, and loss is a dropped
//! connection, which both sides hear about and which comes back after a delay;
//! only messages on different connections overtake each other. A peer may hang
//! up itself (`Transport::close`); such a pair stays closed until a
//! `Fault::Reconnect`, a partition ending or a restart reconnects it. However
//! a connection ends, its two notices are queued and delivered first in first
//! out once the handler that ended it has had every effect applied, so effects
//! take effect in the order asked and each peer hears its connections end in
//! the order they closed; a peer's context reports as connected exactly the
//! peers it has heard `on_connected` for and not `on_disconnected`. The
//! `contract` module's probing peers check all of this from the inside. Both
//! sides learn of a connection's end at the same instant, a phase-0
//! simplification (in reality one side may believe it alive until its own
//! timeout); a per-side detection delay and a wall-clock step fault are
//! follow-ups. Peers see time
//! only through their [`Context`], a monotonic instant and a wall clock both
//! offset by a per-peer skew; they send only through it, into the simulated
//! network; they persist only through [`storage::SimStorage`], whose staged
//! writes a crash discards and whose committed writes a restart keeps. Faults
//! are events like any other: a partition cuts links for a window and closes
//! the connections across them, a crash drops a peer's memory and timers, a
//! restart builds a fresh peer over the surviving storage, a full disk makes
//! writes fail until it is freed. A [`trace::Trace`] records every event; its
//! FNV-1a hash is the run's fingerprint and its last events are the failure
//! report, printed with the seed so that a failing run can be replayed exactly.
//! A run that spends its event budget stops and is reported as not converged,
//! so a peer that never settles cannot hang the job. The `toy` module holds a
//! set-union replicator that exercises every handler; the `scenarios` module
//! names the runs the `licketysync-sim` binary offers the nightly job.
//!
//! [`Peer`]: licketysync_engine::runtime::Peer
//! [`Context`]: licketysync_engine::runtime::Context

pub mod cli;
pub mod contract;
pub mod network;
pub mod rng;
pub mod scenario;
pub mod scenarios;
pub mod storage;
pub mod toy;
pub mod trace;

pub use network::{NetworkConfig, Partition, Probability};
pub use scenario::{Fault, Outcome, Scenario, Sim};
pub use storage::SimStorage;
pub use trace::{EventKind, TraceEvent};

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-sim";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-sim");
    }
}
