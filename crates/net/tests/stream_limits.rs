// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The stream limits a node holds a peer to (TM-22's residuals (c) and (h)),
//! on loopback (TM-31): a node with the default limits, and a raw libp2p
//! dialer that opens streams and stalls each one's negotiation after
//! multistream-select's header, over QUIC and over TCP with yamux. Real time,
//! as libp2p's timers keep it: each wait has a deadline, none sleeps.
//!
//! - `quic_a_fifth_stream_gets_no_credit_and_stalled_negotiations_end_at_5_s`
//! - `tcp_stalled_negotiations_end_at_5_s_and_a_fifth_stream_ends_the_connection`
//! - `quic_a_fifth_stream_waits_to_negotiate_while_four_do`
//!
//! and, at values other than the defaults, so that a fixed number fails:
//! `tcp_a_stream_past_a_lower_limit_ends_the_connection` and
//! `quic_a_third_stream_waits_to_negotiate_at_a_limit_of_two`.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "integration tests link every dev-dependency; test code"
)]

use core::future::poll_fn;
use core::task::{Context, Poll};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt as _};
use libp2p_core::multiaddr::Protocol;
use libp2p_core::muxing::{StreamMuxerBox, StreamMuxerExt as _, SubstreamBox};
use libp2p_core::transport::{DialOpts, ListenerId, PortUse, Transport as _};
use libp2p_core::upgrade::Version;
use libp2p_core::{Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::SwarmEvent;
use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::identity;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, Swarm};

/// Every wait's bound: generous for a loaded CI runner, and a deadline, not a
/// sleep.
const DEADLINE: Duration = Duration::from_secs(60);

/// The default negotiation timeout.
const NEGOTIATION: Duration = Duration::from_secs(5);

/// The negotiation timeout it was, `libp2p-swarm`'s default.
const LIBP2P_DEFAULT: Duration = Duration::from_secs(10);

/// multistream-select's header as a dialer sends it and a listener answers
/// it: its length, then the line. A dialer that sends nothing after it
/// stalls the negotiation.
const HEADER: &[u8] = b"\x13/multistream/1.0.0\n";

/// The keys crate's fixed test seed `start, start + 1, …`: public, never a
/// real key (TM-6).
fn identity_of(start: u8) -> Libp2pIdentity {
    let seed: [u8; 32] = core::array::from_fn(|i| start.wrapping_add(i as u8));
    Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes(seed))
}

fn peer_of(start: u8) -> PeerId {
    identity::peer_id(&identity_of(start)).unwrap()
}

async fn within<T>(what: &str, fut: impl core::future::Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, fut)
        .await
        .unwrap_or_else(|elapsed| panic!("{what}: not done within {DEADLINE:?} ({elapsed})"))
}

/// A node (identity 0xa0) with `limits`, listening on 127.0.0.1 over `quic`
/// or TCP and run until the test ends; returns its address, without its
/// `/p2p/` part.
async fn listener(quic: bool, limits: &Limits) -> Multiaddr {
    let mut swarm: Swarm = node::build(&identity_of(0xa0), limits).unwrap();
    let ip = Multiaddr::empty().with(Protocol::Ip4(Ipv4Addr::LOCALHOST));
    let listen = if quic {
        ip.with(Protocol::Udp(0)).with(Protocol::QuicV1)
    } else {
        ip.with(Protocol::Tcp(0))
    };
    swarm.listen_on(listen).unwrap();
    let addr = within("listen", async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await;
    tokio::spawn(async move {
        loop {
            let _ = swarm.select_next_some().await;
        }
    });
    addr
}

/// A raw QUIC connection to `addr` from identity 0xb0, with its transport,
/// which must outlive it: dropping the transport closes the endpoint and the
/// connection with it. The transport listens on 127.0.0.1 first, so that the
/// dial leaves from there (TM-31).
async fn raw_quic(addr: Multiaddr) -> (libp2p_quic::tokio::Transport, StreamMuxerBox) {
    let key = identity::keypair(&identity_of(0xb0)).unwrap();
    let mut transport = libp2p_quic::tokio::Transport::new(libp2p_quic::Config::new(&key));
    let loopback = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(0))
        .with(Protocol::QuicV1);
    transport.listen_on(ListenerId::next(), loopback).unwrap();
    let dial = transport
        .dial(
            addr,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
        .unwrap();
    let (peer, connection) = within("quic dial", dial).await.unwrap();
    assert_eq!(peer, peer_of(0xa0));
    (transport, StreamMuxerBox::new(connection))
}

/// A raw TCP connection to `addr` from identity 0xb0: TLS, then yamux with
/// its defaults (512 streams).
async fn raw_tcp(addr: Multiaddr) -> StreamMuxerBox {
    let key = identity::keypair(&identity_of(0xb0)).unwrap();
    let mut transport = libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::new())
        .upgrade(Version::V1)
        .authenticate(libp2p_tls::Config::new(&key).unwrap())
        .multiplex(libp2p_yamux::Config::default());
    let dial = transport
        .dial(
            addr,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap();
    let (peer, muxer) = within("tcp dial", dial).await.unwrap();
    assert_eq!(peer, peer_of(0xa0));
    StreamMuxerBox::new(muxer)
}

/// Opens a stream on `connection`.
async fn open(connection: &mut StreamMuxerBox) -> SubstreamBox {
    within("open", poll_fn(|cx| connection.poll_outbound_unpin(cx)))
        .await
        .unwrap()
}

/// Polls a yamux connection, whose frames move only while it is polled,
/// until it ends; the task finishes when it does.
fn drive(mut connection: StreamMuxerBox) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        poll_fn(|cx| {
            loop {
                match connection.poll_unpin(cx) {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
    })
}

/// Sends multistream-select's header on `stream` and waits for the node's
/// answer, which shows that the node took the stream into negotiation.
async fn header(stream: &mut SubstreamBox) {
    within("header sent", async {
        stream.write_all(HEADER).await.unwrap();
        stream.flush().await.unwrap();
    })
    .await;
    let mut answer = [0; HEADER.len()];
    within("header answered", stream.read_exact(&mut answer))
        .await
        .unwrap();
    assert_eq!(answer, HEADER);
}

/// Waits until the node drops `stream` (its end or an error, never more
/// bytes) and returns how long after `started` it did.
async fn dropped(stream: &mut SubstreamBox, started: Instant) -> Duration {
    let mut byte = [0; 1];
    match within("the node drops the stream", stream.read(&mut byte)).await {
        Ok(0) | Err(_) => started.elapsed(),
        Ok(_) => panic!("the node sent more than its header"),
    }
}

/// Stalls each of `streams` after the header, then checks that the node drops
/// each at its 5 s negotiation timeout, not at libp2p's 10 s.
async fn stalled_streams_are_dropped_at_5_s(streams: &mut [SubstreamBox]) {
    let started = Instant::now();
    for stream in streams.iter_mut() {
        header(stream).await;
    }
    let ends = futures::future::join_all(streams.iter_mut().map(|s| dropped(s, started))).await;
    for (i, waited) in ends.into_iter().enumerate() {
        assert!(
            waited >= NEGOTIATION && waited < LIBP2P_DEFAULT,
            "stream {i} dropped after {waited:?}"
        );
    }
}

/// QUIC (TM-22 (h)): the node grants a peer 4 streams at once, so quinn holds
/// a fifth back, and the 4 stalled in negotiation are dropped at 5 s, after
/// which the fifth opens and negotiates.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_a_fifth_stream_gets_no_credit_and_stalled_negotiations_end_at_5_s() {
    let addr = listener(true, &Limits::default()).await;
    let (_transport, mut connection) = raw_quic(addr).await;
    let mut streams = Vec::new();
    for _ in 0..4 {
        streams.push(open(&mut connection).await);
    }
    // The node's 4 are known here since the handshake (its transport
    // parameters), so the answer is final, not a race.
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(
        connection.poll_outbound_unpin(&mut cx).is_pending(),
        "a fifth stream opened while 4 were open"
    );
    stalled_streams_are_dropped_at_5_s(&mut streams).await;
    // Dropped here too (a reset), so that the node frees them and grants more.
    drop(streams);
    let mut fifth = within(
        "the fifth opens once the four are gone",
        poll_fn(|cx| connection.poll_outbound_unpin(cx)),
    )
    .await
    .unwrap();
    header(&mut fifth).await;
}

/// Fills the node's yamux with streams in negotiation, all of `streams` but
/// the last, then sends a first frame on the last, one past the node's
/// limit, which makes the node's yamux end the connection (`ended` finishes).
async fn one_more_stream_ends_the_connection(
    streams: &mut [SubstreamBox],
    ended: tokio::task::JoinHandle<()>,
) {
    let (last, filling) = streams.split_last_mut().unwrap();
    for stream in filling {
        header(stream).await;
    }
    within("one more header sent", async {
        last.write_all(HEADER).await.unwrap();
        last.flush().await.unwrap();
    })
    .await;
    let mut answer = [0; HEADER.len()];
    assert!(
        within(
            "the stream past the limit ends",
            last.read_exact(&mut answer)
        )
        .await
        .is_err(),
        "the stream past the limit was answered"
    );
    within("the node ends the connection", ended).await.unwrap();
}

/// TCP (TM-22 (c)): the node drops 4 streams stalled in negotiation at 5 s;
/// with 4 streams open again, the fifth one's first frame makes the node's
/// yamux end the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_stalled_negotiations_end_at_5_s_and_a_fifth_stream_ends_the_connection() {
    let addr = listener(false, &Limits::default()).await;
    let mut connection = raw_tcp(addr).await;
    // yamux tells the other side of a stream only with its first frame, so
    // all nine are opened here, before the driver takes the connection.
    let mut streams = Vec::new();
    for _ in 0..9 {
        streams.push(open(&mut connection).await);
    }
    let ended = drive(connection);
    let (first, second) = streams.split_at_mut(4);
    stalled_streams_are_dropped_at_5_s(first).await;
    // The node dropped those four and counts none; four more fill it again.
    one_more_stream_ends_the_connection(second, ended).await;
}

/// yamux's stream count is the limits' own, not a fixed 4: at 2, a third
/// stream ends the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_a_stream_past_a_lower_limit_ends_the_connection() {
    let limits = Limits {
        max_streams_per_connection: 2,
        ..Limits::default()
    };
    let addr = listener(false, &limits).await;
    let mut connection = raw_tcp(addr).await;
    let mut streams = Vec::new();
    for _ in 0..3 {
        streams.push(open(&mut connection).await);
    }
    let ended = drive(connection);
    one_more_stream_ends_the_connection(&mut streams, ended).await;
}

/// Against a node with `limits`, whose negotiating limit is `negotiating`
/// and whose stream limit is above it: `negotiating` stalled streams
/// negotiate at once, and one more starts only when one of them is dropped,
/// at the 5 s negotiation timeout.
async fn one_more_stream_waits_to_negotiate(limits: &Limits) {
    let negotiating = usize::try_from(limits.max_negotiating_inbound_streams).unwrap();
    assert!(limits.max_streams_per_connection > limits.max_negotiating_inbound_streams);
    let addr = listener(true, limits).await;
    let (_transport, mut connection) = raw_quic(addr).await;
    let mut streams = Vec::new();
    for _ in 0..=negotiating {
        streams.push(open(&mut connection).await);
    }
    let started = Instant::now();
    // In order: quinn hands the node its streams by number, so the last is
    // the one left waiting.
    for stream in &mut streams {
        within("header sent", async {
            stream.write_all(HEADER).await.unwrap();
            stream.flush().await.unwrap();
        })
        .await;
    }
    let (last, first) = streams.split_last_mut().unwrap();
    let mut answer = [0; HEADER.len()];
    for stream in first {
        within("header answered", stream.read_exact(&mut answer))
            .await
            .unwrap();
        assert_eq!(answer, HEADER);
    }
    let those = started.elapsed();
    assert!(
        those < NEGOTIATION,
        "{negotiating} negotiating after {those:?}"
    );
    within("one more's header answered", last.read_exact(&mut answer))
        .await
        .unwrap();
    assert_eq!(answer, HEADER);
    let one_more = started.elapsed();
    assert!(
        one_more >= NEGOTIATION && one_more < LIBP2P_DEFAULT,
        "one more answered after {one_more:?}"
    );
}

/// The negotiating limit on its own (4 by default): with 5 streams allowed, a
/// fifth stream's negotiation starts only when one of the four stalled before
/// it is dropped, at 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_a_fifth_stream_waits_to_negotiate_while_four_do() {
    one_more_stream_waits_to_negotiate(&Limits {
        max_streams_per_connection: 5,
        ..Limits::default()
    })
    .await;
}

/// The negotiating limit is the limits' own, not a fixed 4: at 2, a third
/// stream waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_a_third_stream_waits_to_negotiate_at_a_limit_of_two() {
    one_more_stream_waits_to_negotiate(&Limits {
        max_streams_per_connection: 3,
        max_negotiating_inbound_streams: 2,
        ..Limits::default()
    })
    .await;
}
