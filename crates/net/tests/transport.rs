// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Spike A's pass condition A2, on loopback (TM-31): real swarms over QUIC
//! and TCP on 127.0.0.1, each test under a deadline and none sleeping. Every
//! socket that stays bound is on 127.0.0.1; quinn-udp's GSO and GRO checks
//! open and close `[::]` sockets without sending.
//!
//! - (a) `libp2p_tls_configurations_negotiate_x25519mlkem768`
//! - (b) `installed_default_provider_is_aws_lc_rs_with_x25519mlkem768_first`,
//!   `rustls_is_built_with_tls13_only` (and `tests/provider_conflict.rs`)
//! - (c) `tcp_dialer_offering_noise_or_plaintext_gets_no_connection`
//! - (d) `{quic,tcp}_dial_expecting_another_identity_is_refused`
//! - (e) `{quic,tcp}_connection_past_the_established_limit_is_refused`,
//!   `tcp_flood_of_idle_connections_stays_within_the_pending_limit_and_memory_bound`
//!   (in `tests/tcp_flood.rs`, a binary of its own),
//!   `tcp_connection_that_never_speaks_ends_at_the_handshake_timeout`,
//!   `connections_are_refused_above_the_memory_limit`,
//!   `second_sync_stream_on_one_connection_is_refused`
//! - (f) `{quic,tcp}_pieces_arrive_in_order_at_most_64_kib_and_the_end_is_reported`
//! - (g) `peer_id_of_the_keys_test_seed_is_the_keys_vector`
//!
//! and A1's exchange, automated: `{quic,tcp}_peers_prove_identities_and_echo_1_mib_over_sync_1`.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    reason = "integration tests link every dev-dependency; test code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt as _};
use libp2p_core::multiaddr::Protocol;
use libp2p_core::transport::TransportError;
use libp2p_core::Multiaddr;
use libp2p_identity::PeerId;
use libp2p_swarm::{ConnectionId, DialError, ListenError, Stream, StreamProtocol, SwarmEvent};
use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, dial_opts::DialOpts, Event, Swarm};
use licketysync_net::pieces::{Delivery, End, Pieces, MAX_PIECE};
use licketysync_net::sync::{self, OpenError};
use licketysync_net::{identity, provider, PROTOCOL_ID};
use rustls::{CipherSuite, NamedGroup, ProtocolVersion};

/// Every test's bound on waiting: generous for a loaded CI runner, and a
/// deadline, not a sleep.
const DEADLINE: Duration = Duration::from_secs(60);

/// One mebibyte, A1's transfer.
const MIB: usize = 1 << 20;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Quic,
    Tcp,
}

impl Kind {
    fn listen_addr(self) -> Multiaddr {
        let ip = Multiaddr::empty().with(Protocol::Ip4(Ipv4Addr::LOCALHOST));
        match self {
            Kind::Quic => ip.with(Protocol::Udp(0)).with(Protocol::QuicV1),
            Kind::Tcp => ip.with(Protocol::Tcp(0)),
        }
    }
}

/// The keys crate's fixed test seed `start, start + 1, …` (its vectors use
/// 0xa0 for the device): a public test seed, never a real key (TM-6).
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

/// The byte at `i` of every transfer: a pattern that a reordered, lost or
/// repeated piece changes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ (i >> 16) as u8)
        .collect()
}

async fn within<T>(what: &str, fut: impl core::future::Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, fut)
        .await
        .unwrap_or_else(|elapsed| panic!("{what}: not done within {DEADLINE:?} ({elapsed})"))
}

/// Listens on loopback and returns the address with its `/p2p/` part.
async fn listening(swarm: &mut Swarm, kind: Kind) -> Multiaddr {
    swarm.listen_on(kind.listen_addr()).unwrap();
    within("listen", async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address.with_p2p(*swarm.local_peer_id()).unwrap();
            }
        }
    })
    .await
}

/// A node that dials over `kind`. On QUIC it listens on loopback first:
/// `libp2p-quic` dials from a QUIC listener's endpoint when the swarm has one,
/// and otherwise binds a socket of its own on every address (`0.0.0.0`, port
/// 0), so this keeps the tests' dialers on 127.0.0.1 (TM-31).
async fn dialer_of(start: u8, limits: &Limits, kind: Kind) -> Swarm {
    let mut swarm = node_of(start, limits);
    if matches!(kind, Kind::Quic) {
        listening(&mut swarm, kind).await;
    }
    swarm
}

/// What a listener saw, as the tests check it.
#[derive(Debug)]
enum Seen {
    Established(PeerId),
    Closed(PeerId),
    Refused(ListenError),
    Accepted(PeerId, StreamProtocol),
    /// What the listener's reader got: the bytes, the largest piece, the
    /// number of pieces, and how the stream ended.
    Read(Vec<u8>, usize, usize, End),
}

/// What a listener does with an accepted stream.
#[derive(Clone, Copy)]
enum Serve {
    Echo,
    Collect,
}

/// Runs a listener until the test ends, reporting what it sees.
fn serve(mut swarm: Swarm, serve: Serve) -> mpsc::UnboundedReceiver<Seen> {
    let (tx, rx) = mpsc::unbounded();
    tokio::spawn(async move {
        loop {
            let event = swarm.select_next_some().await;
            let seen = match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    Some(Seen::Established(peer_id))
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => Some(Seen::Closed(peer_id)),
                SwarmEvent::IncomingConnectionError { error, .. } => Some(Seen::Refused(error)),
                SwarmEvent::Behaviour(Event::Sync(sync::Event::Accepted {
                    peer,
                    protocol,
                    stream,
                    ..
                })) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        match serve {
                            Serve::Echo => echo(stream).await,
                            Serve::Collect => {
                                let (bytes, largest, count, end) = collect(stream).await;
                                let _ = tx.unbounded_send(Seen::Read(bytes, largest, count, end));
                            }
                        }
                    });
                    Some(Seen::Accepted(peer, protocol))
                }
                _ => None,
            };
            if let Some(seen) = seen {
                if tx.unbounded_send(seen).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

/// Echoes a stream back, piece by piece, then closes this side.
async fn echo(stream: Stream) {
    let (read, mut write) = stream.split();
    let mut pieces = Pieces::new(read);
    while let Delivery::Bytes(bytes) = pieces.next().await {
        if write.write_all(bytes).await.is_err() {
            return;
        }
    }
    let _ = write.close().await;
}

/// Reads a stream to its end in pieces.
async fn collect<S: futures::AsyncRead + Unpin>(stream: S) -> (Vec<u8>, usize, usize, End) {
    let mut pieces = Pieces::new(stream);
    let (mut bytes, mut largest, mut count) = (Vec::new(), 0, 0);
    loop {
        match pieces.next().await {
            Delivery::Bytes(piece) => {
                largest = largest.max(piece.len());
                count += 1;
                bytes.extend_from_slice(piece);
            }
            Delivery::Ended(end) => return (bytes, largest, count, end),
        }
    }
}

/// The next event a listener reports that `pick` keeps.
async fn next_seen<T>(
    rx: &mut mpsc::UnboundedReceiver<Seen>,
    what: &str,
    mut pick: impl FnMut(Seen) -> Option<T>,
) -> T {
    within(what, async {
        loop {
            let Some(seen) = rx.next().await else {
                panic!("{what}: the listener stopped");
            };
            if let Some(v) = pick(seen) {
                return v;
            }
        }
    })
    .await
}

/// Dials `addr` expecting `peer`; returns the connection once established.
async fn connect(dialer: &mut Swarm, peer: PeerId, addr: &Multiaddr) -> ConnectionId {
    dialer
        .dial(
            DialOpts::peer_id(peer)
                .addresses(vec![addr.clone()])
                .build(),
        )
        .unwrap();
    within("connect", async {
        loop {
            match dialer.select_next_some().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    ..
                } => {
                    assert_eq!(
                        peer_id, peer,
                        "the peer the dialer reports is the one it expected"
                    );
                    return connection_id;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => panic!("dial failed: {error}"),
                _ => {}
            }
        }
    })
    .await
}

/// Opens a sync stream on `connection` and waits for the answer.
async fn open(
    dialer: &mut Swarm,
    peer: PeerId,
    connection: ConnectionId,
) -> Result<(StreamProtocol, Stream), OpenError> {
    let id = dialer.behaviour_mut().sync().open(peer, connection);
    within("open", async {
        loop {
            match dialer.select_next_some().await {
                SwarmEvent::Behaviour(Event::Sync(sync::Event::Opened {
                    id: got,
                    protocol,
                    stream,
                    ..
                })) if got == id => return Ok((protocol, stream)),
                SwarmEvent::Behaviour(Event::Sync(sync::Event::OpenFailed {
                    id: got,
                    error,
                    ..
                })) if got == id => return Err(error),
                _ => {}
            }
        }
    })
    .await
}

/// Keeps a dialer's swarm polled while its streams run.
fn drive(mut swarm: Swarm) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = swarm.select_next_some().await;
        }
    })
}

// A1, automated -------------------------------------------------------------

async fn peers_prove_identities_and_echo(kind: Kind) {
    let mut listener = node_of(0xa0, &Limits::default());
    let addr = listening(&mut listener, kind).await;
    let mut seen = serve(listener, Serve::Echo);
    let mut dialer = dialer_of(0xb0, &Limits::default(), kind).await;

    let connection = connect(&mut dialer, peer_of(0xa0), &addr).await;
    let proved = next_seen(&mut seen, "listener sees the dialer", |s| match s {
        Seen::Established(peer) => Some(peer),
        _ => None,
    })
    .await;
    assert_eq!(
        proved,
        peer_of(0xb0),
        "the listener sees the identity the dialer proved"
    );

    let (protocol, stream) = open(&mut dialer, peer_of(0xa0), connection).await.unwrap();
    assert_eq!(protocol.as_ref(), PROTOCOL_ID);
    let accepted = next_seen(&mut seen, "listener accepts", |s| match s {
        Seen::Accepted(peer, protocol) => Some((peer, protocol)),
        _ => None,
    })
    .await;
    assert_eq!(accepted, (peer_of(0xb0), StreamProtocol::new(PROTOCOL_ID)));

    let driver = drive(dialer);
    let sent = pattern(MIB);
    let (read, mut write) = stream.split();
    let ((), (echoed, largest, _, end)) = within("echo 1 MiB", async {
        futures::join!(
            async {
                write.write_all(&sent).await.unwrap();
                write.close().await.unwrap();
            },
            collect(read)
        )
    })
    .await;
    driver.abort();
    assert_eq!(end, End::Closed);
    assert!(largest <= MAX_PIECE);
    assert!(echoed == sent, "1 MiB echoed in order");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_peers_prove_identities_and_echo_1_mib_over_sync_1() {
    peers_prove_identities_and_echo(Kind::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_peers_prove_identities_and_echo_1_mib_over_sync_1() {
    peers_prove_identities_and_echo(Kind::Tcp).await;
}

// (a) and (b): the TLS configurations and the provider -----------------------

/// Moves every TLS record `from` has to send into `to`.
fn transfer(from: &mut rustls::Connection, to: &mut rustls::Connection) {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).unwrap();
    }
    let mut rest = &wire[..];
    while !rest.is_empty() {
        to.read_tls(&mut rest).unwrap();
        to.process_new_packets().unwrap();
    }
}

#[test]
fn libp2p_tls_configurations_negotiate_x25519mlkem768() {
    let client_key = identity::keypair(&identity_of(0xb0)).unwrap();
    let server_key = identity::keypair(&identity_of(0xa0)).unwrap();
    let client_config = libp2p_tls::make_client_config(&client_key, Some(peer_of(0xa0))).unwrap();
    let server_config = libp2p_tls::make_server_config(&server_key).unwrap();
    // libp2p's TLS sends no server name (its specification): the unspecified
    // address, as libp2p-tls's own upgrade passes it.
    let name = rustls::pki_types::ServerName::IpAddress(Ipv4Addr::UNSPECIFIED.into());
    let mut client = rustls::Connection::Client(
        rustls::ClientConnection::new(Arc::new(client_config), name).unwrap(),
    );
    let mut server =
        rustls::Connection::Server(rustls::ServerConnection::new(Arc::new(server_config)).unwrap());
    for _ in 0..8 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        transfer(&mut client, &mut server);
        transfer(&mut server, &mut client);
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    for side in [&client, &server] {
        assert_eq!(
            side.negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
            Some(NamedGroup::X25519MLKEM768)
        );
        assert_eq!(side.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(
            side.negotiated_cipher_suite().map(|s| s.suite()),
            Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
            "two Lickety-Sync peers take the first suite of libp2p-tls's list (suites.md 2.6)"
        );
    }
    // Each side offers X25519MLKEM768 first.
    for groups in [
        &client_key_groups(&client_key),
        &server_key_groups(&server_key),
    ] {
        assert_eq!(groups.first(), Some(&NamedGroup::X25519MLKEM768));
    }
}

fn client_key_groups(key: &libp2p_identity::Keypair) -> Vec<NamedGroup> {
    let config = libp2p_tls::make_client_config(key, None).unwrap();
    config
        .crypto_provider()
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect()
}

fn server_key_groups(key: &libp2p_identity::Keypair) -> Vec<NamedGroup> {
    let config = libp2p_tls::make_server_config(key).unwrap();
    config
        .crypto_provider()
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect()
}

#[test]
fn installed_default_provider_is_aws_lc_rs_with_x25519mlkem768_first() {
    provider::install_default_provider().unwrap();
    // A second call finds its own provider.
    provider::install_default_provider().unwrap();
    let installed = rustls::crypto::CryptoProvider::get_default().unwrap();
    let aws_lc_rs = rustls::crypto::aws_lc_rs::default_provider();
    let groups = |p: &rustls::crypto::CryptoProvider| -> Vec<NamedGroup> {
        p.kx_groups.iter().map(|g| g.name()).collect()
    };
    let suites = |p: &rustls::crypto::CryptoProvider| -> Vec<CipherSuite> {
        p.cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect()
    };
    assert_eq!(
        groups(installed),
        [
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1
        ]
    );
    assert_eq!(groups(installed), groups(&aws_lc_rs));
    assert_eq!(suites(installed), suites(&aws_lc_rs));
    assert!(installed
        .cipher_suites
        .iter()
        .all(|s| s.version().version == ProtocolVersion::TLSv1_3));
    assert_eq!(provider::check(installed), Ok(()));
}

#[test]
fn rustls_is_built_with_tls13_only() {
    // rustls's `tls12` feature, a default one, is off in every crate of the
    // graph (suites.md 2.6), so TLS 1.2 does not exist in this build.
    let versions: Vec<ProtocolVersion> = rustls::ALL_VERSIONS.iter().map(|v| v.version).collect();
    assert_eq!(versions, [ProtocolVersion::TLSv1_3]);
}

// (c): nothing weaker on TCP --------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_dialer_offering_noise_or_plaintext_gets_no_connection() {
    let mut listener = node_of(0xa0, &Limits::default());
    let addr = listening(&mut listener, Kind::Tcp).await;
    let port = addr
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .unwrap();
    let mut seen = serve(listener, Serve::Echo);
    let socket = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    // Noise and plaintext are refused; the one security protocol is
    // accepted (the control that shows the dialer here speaks
    // multistream-select correctly).
    for (offer, accepted) in [
        ("/noise", false),
        ("/plaintext/2.0.0", false),
        ("/tls/1.0.0", true),
    ] {
        let tcp = libp2p_tcp::tokio::TcpStream(
            within("tcp connect", tokio::net::TcpStream::connect(socket))
                .await
                .unwrap(),
        );
        let answer = within(
            "negotiate",
            multistream_select::dialer_select_proto(tcp, [offer], multistream_select::Version::V1),
        )
        .await;
        match (answer, accepted) {
            (Err(multistream_select::NegotiationError::Failed), false) => {}
            (Ok((protocol, _)), true) => assert_eq!(protocol, offer),
            (other, _) => panic!("{offer}: {:?}", other.map(|(p, _)| p)),
        }
        // Whatever was offered, the listener ends the connection without
        // establishing it.
        let refused = next_seen(&mut seen, "listener ends the attempt", |s| match s {
            Seen::Refused(e) => Some(Ok(e)),
            Seen::Established(peer) => Some(Err(peer)),
            _ => None,
        })
        .await;
        assert!(
            matches!(refused, Ok(ListenError::Transport(_))),
            "{offer}: {refused:?}"
        );
    }
}

// (d): the identity a dial expects ------------------------------------------

async fn dial_expecting_another_identity_is_refused(kind: Kind) {
    let mut listener = node_of(0xa0, &Limits::default());
    let addr = listening(&mut listener, kind).await;
    let _seen = serve(listener, Serve::Echo);
    let mut dialer = dialer_of(0xb0, &Limits::default(), kind).await;
    let expected = peer_of(0xc0);
    // Without its /p2p/ part, so that the expectation is the dial's alone
    // and only the TLS handshake can find it wrong.
    let addr: Multiaddr = addr
        .iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect();
    dialer
        .dial(DialOpts::peer_id(expected).addresses(vec![addr]).build())
        .unwrap();
    let obtained = within("dial fails", async {
        loop {
            match dialer.select_next_some().await {
                SwarmEvent::OutgoingConnectionError {
                    error: DialError::WrongPeerId { obtained, .. },
                    ..
                } => return obtained,
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    panic!("refused, but not for the identity: {error}")
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    panic!("connected to {peer_id}, which is not the peer expected")
                }
                _ => {}
            }
        }
    })
    .await;
    assert_eq!(obtained, peer_of(0xa0), "the identity the listener proved");
    assert_eq!(dialer.network_info().num_peers(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_dial_expecting_another_identity_is_refused() {
    dial_expecting_another_identity_is_refused(Kind::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_dial_expecting_another_identity_is_refused() {
    dial_expecting_another_identity_is_refused(Kind::Tcp).await;
}

// (e): limits -------------------------------------------------------------------

async fn connection_past_the_established_limit_is_refused(kind: Kind) {
    let limits = Limits {
        max_established_incoming: 2,
        ..Limits::default()
    };
    let mut listener = node_of(0xa0, &limits);
    let addr = listening(&mut listener, kind).await;
    let mut seen = serve(listener, Serve::Echo);
    let mut dialers = Vec::new();
    for start in [0xb0, 0xc0] {
        let mut dialer = dialer_of(start, &Limits::default(), kind).await;
        connect(&mut dialer, peer_of(0xa0), &addr).await;
        let peer = next_seen(&mut seen, "established", |s| match s {
            Seen::Established(peer) => Some(peer),
            _ => None,
        })
        .await;
        assert_eq!(peer, peer_of(start));
        dialers.push(drive(dialer));
    }
    // The third, one past the limit.
    let mut third = dialer_of(0xd0, &Limits::default(), kind).await;
    third
        .dial(
            DialOpts::peer_id(peer_of(0xa0))
                .addresses(vec![addr])
                .build(),
        )
        .unwrap();
    let third = drive(third);
    let refused = next_seen(&mut seen, "third refused", |s| match s {
        Seen::Refused(e) => Some(Ok(e)),
        Seen::Established(peer) => Some(Err(peer)),
        _ => None,
    })
    .await;
    match refused {
        Ok(ListenError::Denied { cause }) => {
            let exceeded = cause
                .downcast_ref::<libp2p_connection_limits::Exceeded>()
                .unwrap();
            assert_eq!(exceeded.limit(), 2);
        }
        other => panic!("not refused by the limit: {other:?}"),
    }
    third.abort();
    for d in dialers {
        d.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_connection_past_the_established_limit_is_refused() {
    connection_past_the_established_limit_is_refused(Kind::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_connection_past_the_established_limit_is_refused() {
    connection_past_the_established_limit_is_refused(Kind::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_connection_that_never_speaks_ends_at_the_handshake_timeout() {
    let limits = Limits {
        handshake_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let mut listener = node_of(0xa0, &limits);
    let addr = listening(&mut listener, Kind::Tcp).await;
    let port = addr
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .unwrap();
    let pending = |swarm: &Swarm| {
        swarm
            .network_info()
            .connection_counters()
            .num_pending_incoming()
    };

    // One socket, held open and silent: no multistream-select header, so
    // only the timeout can end its upgrade.
    let silent = within(
        "tcp connect",
        tokio::net::TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
    )
    .await
    .unwrap();
    let connected = Instant::now();
    within("pending", async {
        while !matches!(
            listener.select_next_some().await,
            SwarmEvent::IncomingConnection { .. }
        ) {}
    })
    .await;
    assert_eq!(pending(&listener), 1);
    let error = within("the handshake times out", async {
        loop {
            match listener.select_next_some().await {
                SwarmEvent::IncomingConnectionError { error, .. } => return error,
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    panic!("{peer_id} established from a socket that never spoke")
                }
                _ => {}
            }
        }
    })
    .await;
    let waited = connected.elapsed();
    // The transport's timeout, nothing else: libp2p-core's `TransportTimeout`,
    // as the boxed transport's `io::Error` carries it.
    match &error {
        ListenError::Transport(TransportError::Other(e)) => {
            assert_eq!(e.to_string(), "Timeout has been reached", "{error:?}");
        }
        other => panic!("not the handshake timeout: {other:?}"),
    }
    // At the limit's timeout, not the default's.
    assert!(
        waited >= limits.handshake_timeout && waited < Limits::default().handshake_timeout,
        "ended after {waited:?}"
    );
    assert_eq!(pending(&listener), 0, "the pending slot is free again");
    drop(silent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_are_refused_above_the_memory_limit() {
    // Any process is above one byte.
    let tight = Limits {
        max_process_memory_bytes: 1,
        ..Limits::default()
    };
    let mut listener = node_of(0xa0, &tight);
    let addr = listening(&mut listener, Kind::Quic).await;
    let mut seen = serve(listener, Serve::Echo);
    let mut dialer = dialer_of(0xb0, &Limits::default(), Kind::Quic).await;
    dialer
        .dial(
            DialOpts::peer_id(peer_of(0xa0))
                .addresses(vec![addr.clone()])
                .build(),
        )
        .unwrap();
    let dialer = drive(dialer);
    let refused = next_seen(&mut seen, "refused", |s| match s {
        Seen::Refused(e) => Some(Ok(e)),
        Seen::Established(peer) => Some(Err(peer)),
        _ => None,
    })
    .await;
    match refused {
        Ok(ListenError::Denied { cause }) => assert!(cause
            .downcast_ref::<libp2p_memory_connection_limits::MemoryUsageLimitExceeded>()
            .is_some()),
        other => panic!("not refused by the memory limit: {other:?}"),
    }
    dialer.abort();

    // And a node above its limit dials nothing: the dial is refused before
    // any packet is sent.
    let mut tight_dialer = dialer_of(0xc0, &tight, Kind::Quic).await;
    match tight_dialer.dial(
        DialOpts::peer_id(peer_of(0xa0))
            .addresses(vec![addr])
            .build(),
    ) {
        Err(DialError::Denied { cause }) => assert!(cause
            .downcast_ref::<libp2p_memory_connection_limits::MemoryUsageLimitExceeded>()
            .is_some()),
        other => panic!("not refused by the memory limit: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_sync_stream_on_one_connection_is_refused() {
    let mut listener = node_of(0xa0, &Limits::default());
    let addr = listening(&mut listener, Kind::Quic).await;
    let mut seen = serve(listener, Serve::Echo);
    let mut dialer = dialer_of(0xb0, &Limits::default(), Kind::Quic).await;
    let connection = connect(&mut dialer, peer_of(0xa0), &addr).await;
    let (_, first) = open(&mut dialer, peer_of(0xa0), connection).await.unwrap();
    next_seen(&mut seen, "first accepted", |s| {
        matches!(s, Seen::Accepted(..)).then_some(())
    })
    .await;
    let second = open(&mut dialer, peer_of(0xa0), connection).await;
    assert!(matches!(second, Err(OpenError::Unsupported)), "{second:?}");
    drop(first);
}

// (f): the runtime contract -------------------------------------------------------

async fn pieces_arrive_in_order_and_the_end_is_reported(kind: Kind) {
    let mut listener = node_of(0xa0, &Limits::default());
    let addr = listening(&mut listener, kind).await;
    let mut seen = serve(listener, Serve::Collect);

    // A stream the dialer closes: every byte, in order, in pieces of at most
    // 64 KiB, then a clean end.
    let mut dialer = dialer_of(0xb0, &Limits::default(), kind).await;
    let connection = connect(&mut dialer, peer_of(0xa0), &addr).await;
    let (_, mut stream) = open(&mut dialer, peer_of(0xa0), connection).await.unwrap();
    let driver = drive(dialer);
    // Not a multiple of the piece size, written in one call so that the
    // transport, not the writer, decides the boundaries.
    let sent = pattern(3 * MIB + 12_345);
    within("send", async {
        stream.write_all(&sent).await.unwrap();
        stream.close().await.unwrap();
    })
    .await;
    let (got, largest, count, end) = next_seen(&mut seen, "read", |s| match s {
        Seen::Read(bytes, largest, count, end) => Some((bytes, largest, count, end)),
        _ => None,
    })
    .await;
    assert!(got == sent, "every byte, in order");
    assert!(largest <= MAX_PIECE, "a piece of {largest} bytes");
    assert!(count >= sent.len().div_ceil(MAX_PIECE));
    assert_eq!(end, End::Closed);
    driver.abort();

    // A connection that ends under an open stream: the reader reports the
    // end, and the swarm the closed connection.
    let mut dialer = dialer_of(0xc0, &Limits::default(), kind).await;
    let connection = connect(&mut dialer, peer_of(0xa0), &addr).await;
    let (_, mut stream) = open(&mut dialer, peer_of(0xa0), connection).await.unwrap();
    stream.write_all(&sent[..1000]).await.unwrap();
    stream.flush().await.unwrap();
    next_seen(&mut seen, "accepted", |s| {
        matches!(s, Seen::Accepted(..)).then_some(())
    })
    .await;
    // The stream stays open on this side; the connection under it ends.
    dialer.disconnect_peer_id(peer_of(0xa0)).unwrap();
    let driver = drive(dialer);
    let mut ended = None;
    let mut closed = false;
    within("the end is reported", async {
        while ended.is_none() || !closed {
            match seen.next().await {
                Some(Seen::Read(bytes, largest, _, end)) => {
                    assert!(bytes.len() <= 1000 && sent.starts_with(&bytes));
                    assert!(largest <= MAX_PIECE);
                    ended = Some(end);
                }
                Some(Seen::Closed(peer)) => {
                    assert_eq!(peer, peer_of(0xc0));
                    closed = true;
                }
                Some(_) => {}
                None => panic!("the listener stopped"),
            }
        }
    })
    .await;
    assert!(ended.is_some());
    driver.abort();
    drop(stream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_pieces_arrive_in_order_at_most_64_kib_and_the_end_is_reported() {
    pieces_arrive_in_order_and_the_end_is_reported(Kind::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_pieces_arrive_in_order_at_most_64_kib_and_the_end_is_reported() {
    pieces_arrive_in_order_and_the_end_is_reported(Kind::Tcp).await;
}

// (g): the identity ---------------------------------------------------------------

#[test]
fn peer_id_of_the_keys_test_seed_is_the_keys_vector() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../keys/tests/vectors/device.json")).unwrap();
    let field = |name: &str| vector[name].as_str().unwrap().to_owned();
    let seed: [u8; 32] = hex::decode(field("device_seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let identity = Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes(seed));
    let peer = identity::peer_id(&identity).unwrap();
    assert_eq!(peer.to_base58(), field("libp2p_peer_id_text"));
    assert_eq!(hex::encode(peer.to_bytes()), field("libp2p_peer_id"));
    assert!(peer.to_base58().starts_with("12D3KooW"));
    // The keypair's peer ID is the same one.
    assert_eq!(
        identity::keypair(&identity).unwrap().public().to_peer_id(),
        peer
    );
    assert_eq!(peer, peer_of(0xa0));
}
