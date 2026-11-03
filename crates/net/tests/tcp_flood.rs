// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A2(e) for TCP (TM-22): a flood of connections that never speak, past a
//! pending limit, on loopback. A test binary of its own, so that the resident
//! memory it measures is this test's alone.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "integration tests link every dev-dependency; test code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures::channel::mpsc;
use futures::StreamExt as _;
use libp2p_core::multiaddr::Protocol;
use libp2p_core::Multiaddr;
use libp2p_identity::PeerId;
use libp2p_swarm::ListenError;
use libp2p_swarm::SwarmEvent;
use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::identity;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, dial_opts::DialOpts, Swarm};

/// Every wait's bound: a deadline, never a sleep.
const DEADLINE: Duration = Duration::from_secs(90);

/// The keys crate's fixed test seed `start, start + 1, …`: public, never a
/// real key (TM-6).
fn identity_of(start: u8) -> Libp2pIdentity {
    let seed: [u8; 32] = core::array::from_fn(|i| start.wrapping_add(i as u8));
    Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes(seed))
}

fn peer_of(start: u8) -> PeerId {
    identity::peer_id(&identity_of(start)).unwrap()
}

fn node_of(start: u8, limits: &Limits) -> Swarm {
    node::build(&identity_of(start), limits).unwrap()
}

async fn within<T>(what: &str, fut: impl core::future::Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, fut)
        .await
        .unwrap_or_else(|elapsed| panic!("{what}: not done within {DEADLINE:?} ({elapsed})"))
}

/// The process's resident memory, in bytes.
fn resident() -> usize {
    memory_stats::memory_stats().unwrap().physical_mem
}

/// Listens on `listen` and returns the address with its `/p2p/` part.
async fn listening(swarm: &mut Swarm, listen: Multiaddr) -> Multiaddr {
    swarm.listen_on(listen).unwrap();
    within("listen", async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address.with_p2p(*swarm.local_peer_id()).unwrap();
            }
        }
    })
    .await
}

/// What the listener saw, with its pending count after each event.
#[derive(Debug)]
enum Seen {
    Pending,
    Established(PeerId),
    Refused(ListenError),
}

/// Runs a listener until the test ends; each event comes with the number of
/// connections then pending.
fn watch(mut swarm: Swarm) -> mpsc::UnboundedReceiver<(Seen, u32)> {
    let (tx, rx) = mpsc::unbounded();
    tokio::spawn(async move {
        loop {
            let seen = match swarm.select_next_some().await {
                SwarmEvent::IncomingConnection { .. } => Seen::Pending,
                SwarmEvent::ConnectionEstablished { peer_id, .. } => Seen::Established(peer_id),
                SwarmEvent::IncomingConnectionError { error, .. } => Seen::Refused(error),
                _ => continue,
            };
            let pending = swarm
                .network_info()
                .connection_counters()
                .num_pending_incoming();
            if tx.unbounded_send((seen, pending)).is_err() {
                return;
            }
        }
    });
    rx
}

/// Dials the listener at `addr` (identity 0xa0) from a fresh peer until a
/// connection is established, dialing again after each refusal; returns how
/// many dials it took.
async fn real_peer_gets_through(addr: &Multiaddr) -> u32 {
    let mut dialer = node_of(0xb0, &Limits::default());
    within("a real peer gets through", async {
        let mut dials = 0;
        loop {
            dials += 1;
            dialer
                .dial(
                    DialOpts::peer_id(peer_of(0xa0))
                        .addresses(vec![addr.clone()])
                        .build(),
                )
                .unwrap();
            loop {
                match dialer.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { .. } => return dials,
                    SwarmEvent::OutgoingConnectionError { .. } => break,
                    _ => {}
                }
            }
        }
    })
    .await
}

/// The pending limit the flood runs against.
const PENDING: u32 = 4;

/// Attempts in the flood, past the pending limit.
const FLOOD: usize = 512;

/// The bound this test states for the listener's resident memory: what may be
/// added while one attempt past the limit and then 512 more are made and
/// refused. A refused attempt costs an accepted socket and its refusal and
/// nothing that stays, so the growth measured on Linux is about 0.5 MiB; a
/// leak of 32 KiB or more per attempt would exceed it, failing the test.
/// Generous for the macOS and Windows allocators.
const FLOOD_MEMORY_BOUND: usize = 16 << 20;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_flood_of_idle_connections_stays_within_the_pending_limit_and_memory_bound() {
    let limits = Limits {
        max_pending_incoming: PENDING,
        // Long, so that the idle connections stay pending for the whole test.
        handshake_timeout: Duration::from_secs(30),
        ..Limits::default()
    };
    let mut listener = node_of(0xa0, &limits);
    let loopback = Multiaddr::empty().with(Protocol::Ip4(Ipv4Addr::LOCALHOST));
    let addr = listening(&mut listener, loopback.with(Protocol::Tcp(0))).await;
    let port = addr
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .unwrap();
    let mut seen = watch(listener);
    let socket = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    // Connections that never speak fill the pending slots.
    let mut idle = Vec::new();
    for _ in 0..PENDING {
        idle.push(
            within("idle connect", tokio::net::TcpStream::connect(socket))
                .await
                .unwrap(),
        );
        within("pending", async {
            while !matches!(seen.next().await, Some((Seen::Pending, _))) {}
        })
        .await;
    }
    let before = resident();

    // One past the limit, then the flood: each is refused at once.
    let mut flood = Vec::new();
    within("flood connects", async {
        for _ in 0..=FLOOD {
            flood.push(tokio::net::TcpStream::connect(socket).await.unwrap());
        }
    })
    .await;
    let mut refused = 0;
    let mut most_pending = 0;
    within("flood refused", async {
        while refused <= FLOOD {
            let Some((event, pending)) = seen.next().await else {
                panic!("the listener stopped");
            };
            most_pending = most_pending.max(pending);
            match event {
                Seen::Refused(ListenError::Denied { cause }) => {
                    let exceeded = cause
                        .downcast_ref::<libp2p_connection_limits::Exceeded>()
                        .unwrap();
                    assert_eq!(exceeded.limit(), PENDING);
                    refused += 1;
                }
                Seen::Established(peer) => panic!("{peer} established during the flood"),
                Seen::Refused(other) => panic!("refused, but not by the limit: {other:?}"),
                Seen::Pending => {}
            }
        }
    })
    .await;
    let grown = resident().saturating_sub(before);
    assert!(
        most_pending <= PENDING,
        "at most {PENDING} pending, saw {most_pending}"
    );
    assert!(
        grown < FLOOD_MEMORY_BOUND,
        "the flood added {grown} bytes of resident memory, over the bound of {FLOOD_MEMORY_BOUND}"
    );
    drop(flood);

    // Once the idle connections go, a real peer connects.
    drop(idle);
    real_peer_gets_through(&addr).await;
}
