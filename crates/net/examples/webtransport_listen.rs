// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Spike B: the listeners the headless-Chrome test dials, all on
//! 127.0.0.1. Prints `ADDR <name> <multiaddr>` for each, then `READY`, then
//! one `REPORT` line per session, and exits after the deadline (the first
//! argument, seconds, 180 by default). Run by `ci/webtransport-chrome.sh`:
//!
//! ```text
//! cargo run -p licketysync-net --features webtransport --example webtransport_listen -- 280
//! ```
//!
//! Identities are Ed25519 keys from fixed public test seeds, never real keys.

#![allow(
    clippy::print_stdout,
    reason = "an example that reports to the harness on standard output"
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use libp2p_core::multihash::Multihash;
use libp2p_identity::Keypair;
use licketysync_net::limits::Limits;
use licketysync_net::webtransport::{echo, KxPolicy, Listener, ListenerConfig, SHA2_256};

// The example uses a handful of the crate's dependencies; the rest are
// acknowledged so the unused-crate lint stays quiet.
#[cfg(not(target_os = "ios"))]
use libp2p_memory_connection_limits as _;
use {
    futures as _, hex as _, idna_adapter as _, libp2p_connection_limits as _, libp2p_noise as _,
    libp2p_quic as _, libp2p_swarm as _, libp2p_tcp as _, libp2p_tls as _, libp2p_yamux as _,
    licketysync_engine as _, licketysync_keys as _, licketysync_protocol as _, memory_stats as _,
    multistream_select as _, rustls as _, serde_json as _, wtransport as _,
};

const STEP: Duration = Duration::from_secs(15);
const ECHO_LIMIT: u64 = 4 * 1024 * 1024;
/// The listener's test seed byte.
const LISTENER_SEED: u8 = 1;
/// The browser's test seed byte (browser/tests/web.rs uses the same).
const BROWSER_SEED: u8 = 2;

type Error = Box<dyn std::error::Error>;

fn keypair(seed: u8) -> Result<Keypair, Error> {
    Ok(Keypair::ed25519_from_bytes([seed; 32])?)
}

fn config(kx: KxPolicy, days: u32, liar: bool, expect_seed: u8) -> Result<ListenerConfig, Error> {
    Ok(ListenerConfig {
        keypair: keypair(LISTENER_SEED)?,
        validity_days: days,
        allow_long_validity: true,
        kx,
        noise_hashes_override: liar
            .then(|| Multihash::wrap(SHA2_256, &[0xAB; 32]).map(|h| HashSet::from([h])))
            .transpose()?,
        expected_remote: Some(keypair(expect_seed)?.public().to_peer_id()),
        limits: Limits::default(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Semgrep's community rule flags every std::env::args(): argv[0] is not
    // trustworthy. Only argument 1, the deadline in seconds, is read, and it
    // decides nothing about security.
    // nosemgrep: rust.lang.security.args.args
    let seconds: u64 = std::env::args().nth(1).map_or(Ok(180), |s| s.parse())?;
    let plan = [
        ("OK", config(KxPolicy::PreferPq, 10, false, BROWSER_SEED)?),
        ("PQ", config(KxPolicy::PqOnly, 10, false, BROWSER_SEED)?),
        (
            "CLASSICAL",
            config(KxPolicy::ClassicalOnly, 10, false, BROWSER_SEED)?,
        ),
        ("LIAR", config(KxPolicy::PreferPq, 10, true, BROWSER_SEED)?),
        ("LONG", config(KxPolicy::PreferPq, 15, false, BROWSER_SEED)?),
        ("STRICT", config(KxPolicy::PreferPq, 10, false, 9)?),
    ];
    let mut tasks = Vec::new();
    for (name, cfg) in plan {
        let listener = Arc::new(Listener::bind(cfg)?);
        println!("ADDR {name} {}", listener.multiaddr());
        tasks.push(tokio::spawn(async move {
            loop {
                let incoming = match listener.accept().await {
                    Ok(incoming) => incoming,
                    Err(e) => {
                        println!("REPORT {name} stopped {e}");
                        break;
                    }
                };
                let l = Arc::clone(&listener);
                tokio::spawn(async move {
                    let session = match l.handshake(incoming, STEP).await {
                        Ok(s) => s,
                        Err(e) => return println!("REPORT {name} refused {e}"),
                    };
                    let echoed = match session.accept_stream(STEP).await {
                        Ok(io) => echo(io, ECHO_LIMIT).await,
                        Err(e) => Err(e),
                    };
                    match echoed {
                        Ok(n) => {
                            session.closed(STEP).await;
                            let f = session.facts();
                            println!(
                                "REPORT {name} ok remote={} echoed={n} kx={:?} offered={:?}",
                                session.remote(),
                                f.kx_group,
                                f.offered_groups
                            );
                        }
                        Err(e) => {
                            session.close(1, b"refused");
                            println!("REPORT {name} refused {e}");
                        }
                    }
                });
            }
        }));
    }
    println!(
        "BROWSER_PEER {}",
        keypair(BROWSER_SEED)?.public().to_peer_id()
    );
    println!("READY");
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    println!("DEADLINE");
    for t in tasks {
        t.abort();
    }
    Ok(())
}
