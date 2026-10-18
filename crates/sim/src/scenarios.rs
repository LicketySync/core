// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The named scenarios the `licketysync-sim` binary runs over seed ranges:
//! five set-union peers with three items each, one fault class per scenario
//! (dropped connections, slow reconnects, reordering across connections, a
//! partition, crashes and restarts, clock skew, a full disk), and `chaos` with
//! all of them at once. `contract` runs the probing peers of the `contract`
//! module, which hang up, send and re-arm from every handler under every fault
//! at once and check the runtime's own promises; for it, converged means no
//! promise was broken. `broken` is the deaf peer and is meant to fail; it is
//! there so that the reporting path is exercised too.

use core::time::Duration;

use licketysync_engine::runtime::{Instant, PeerId};

use crate::contract;
use crate::network::{NetworkConfig, Partition};
use crate::scenario::{Fault, Outcome, Scenario};
use crate::toy::{all_hold, total_items, SetUnion, LIMIT};

/// A scenario by name.
pub struct NamedScenario {
    /// The name given on the command line.
    pub name: &'static str,
    /// One line on what it injects.
    pub about: &'static str,
    run: fn(u64) -> Outcome,
}

impl NamedScenario {
    /// Runs the scenario for `seed`.
    #[must_use]
    pub fn run(&self, seed: u64) -> Outcome {
        (self.run)(seed)
    }
}

const PEERS: u32 = 5;
const ITEMS: u32 = 3;
const TICK: Duration = Duration::from_secs(1);

const fn p(id: u64) -> PeerId {
    PeerId::new(id)
}

fn base(seed: u64) -> Scenario<SetUnion> {
    Scenario::new(seed, PEERS, |_| SetUnion::new(ITEMS, TICK))
        .converged_when(all_hold(total_items(PEERS, ITEMS)))
}

fn clean(seed: u64) -> Outcome {
    base(seed).build().run_until_quiescent(LIMIT)
}

fn drops(seed: u64) -> Outcome {
    base(seed)
        .network(NetworkConfig::default().drops(0.2))
        .build()
        .run_until_quiescent(LIMIT)
}

fn reconnect(seed: u64) -> Outcome {
    base(seed)
        .network(
            NetworkConfig::default()
                .drops(0.02)
                .reconnect(Duration::from_secs(2), Duration::from_secs(5)),
        )
        .build()
        .run_until_quiescent(LIMIT)
}

/// Latencies up to 2 s against the usual 1 s tick would keep a message in
/// flight at almost every instant, so this scenario gossips every 5 s: once
/// converged, the network drains between ticks and the run is quiescent.
fn cross_reorder(seed: u64) -> Outcome {
    Scenario::new(seed, PEERS, |_| {
        SetUnion::new(ITEMS, Duration::from_secs(5))
    })
    .converged_when(all_hold(total_items(PEERS, ITEMS)))
    .network(NetworkConfig::default().latency(Duration::from_millis(5), Duration::from_secs(2)))
    .build()
    .run_until_quiescent(LIMIT)
}

fn partition(seed: u64) -> Outcome {
    base(seed)
        .fault(Fault::Partition {
            partition: Partition::between(vec![p(0), p(1)], vec![p(2), p(3), p(4)]),
            from: Instant::ZERO,
            until: Instant::from_secs(10),
        })
        .build()
        .run_until_quiescent(LIMIT)
}

fn crash(seed: u64) -> Outcome {
    base(seed)
        .fault(Fault::Crash {
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
        .build()
        .run_until_quiescent(LIMIT)
}

fn skew(seed: u64) -> Outcome {
    base(seed)
        .wall_epoch(1_700_000_000)
        .clock_ahead(p(1), Duration::from_secs(5 * 60))
        .clock_ahead(p(3), Duration::from_secs(60 * 60))
        .clock_ahead(p(4), Duration::from_secs(24 * 60 * 60))
        .build()
        .run_until_quiescent(LIMIT)
}

fn disk_full(seed: u64) -> Outcome {
    base(seed)
        .fault(Fault::DiskFull {
            peer: p(0),
            from: Instant::ZERO,
            until: Instant::from_secs(5),
        })
        .build()
        .run_until_quiescent(LIMIT)
}

fn chaos(seed: u64) -> Outcome {
    base(seed)
        .network(
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
        .build()
        .run_until_quiescent(LIMIT)
}

fn contract(seed: u64) -> Outcome {
    contract::run(seed).0
}

fn broken(seed: u64) -> Outcome {
    Scenario::new(seed, PEERS, |_| SetUnion::deaf(ITEMS, TICK))
        .converged_when(all_hold(total_items(PEERS, ITEMS)))
        .build()
        .run_until_quiescent(Instant::from_secs(10))
}

static ALL: [NamedScenario; 11] = [
    NamedScenario {
        name: "clean",
        about: "no faults; a quiet LAN",
        run: clean,
    },
    NamedScenario {
        name: "drops",
        about: "a fifth of pieces take their connection down; back in 0.1 to 1 s",
        run: drops,
    },
    NamedScenario {
        name: "reconnect",
        about: "rare drops (2%); reconnects take 2 to 5 s, peers tick meanwhile",
        run: reconnect,
    },
    NamedScenario {
        name: "cross-reorder",
        about: "latency 5 ms to 2 s: streams stay in order, connections overtake",
        run: cross_reorder,
    },
    NamedScenario {
        name: "partition",
        about: "peers 0,1 cut from 2,3,4 for the first 10 s",
        run: partition,
    },
    NamedScenario {
        name: "crash",
        about: "crashes, a clean stop and restarts",
        run: crash,
    },
    NamedScenario {
        name: "skew",
        about: "clocks (monotonic and wall) 5 min, 1 h and 1 day ahead",
        run: skew,
    },
    NamedScenario {
        name: "disk-full",
        about: "peer 0's disk full for the first 5 s",
        run: disk_full,
    },
    NamedScenario {
        name: "chaos",
        about: "all of the above at once",
        run: chaos,
    },
    NamedScenario {
        name: "contract",
        about: "probing peers hang up, send and re-arm from every handler; checks the runtime",
        run: contract,
    },
    NamedScenario {
        name: "broken",
        about: "deaf peers; never converges (checks the reporting)",
        run: broken,
    },
];

/// Every named scenario, `broken` last.
#[must_use]
pub fn all() -> &'static [NamedScenario] {
    &ALL
}

/// The scenario called `name`.
#[must_use]
pub fn find(name: &str) -> Option<&'static NamedScenario> {
    ALL.iter().find(|s| s.name == name)
}

/// The scenarios that must converge: all but `broken`.
pub fn expected_to_converge() -> impl Iterator<Item = &'static NamedScenario> {
    ALL.iter().filter(|s| s.name != "broken")
}
