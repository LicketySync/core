// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Spike B: the WebTransport listener against a native dialer that does what
//! the browser does (wtransport's client, certificate-hash check, Noise as
//! initiator with the dialed hashes, multistream-select), and against a raw
//! QUIC client for the TM-23 containment. No browser, so
//! these run with `--features webtransport` (and `--all-features`) on every
//! build; the browser half is `browser-tests/webtransport` and
//! `ci/webtransport-chrome.sh`. All on 127.0.0.1.

#![cfg(feature = "webtransport")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use libp2p_core::multihash::Multihash;
use libp2p_core::upgrade::OutboundConnectionUpgrade as _;
use libp2p_identity::{Keypair, PeerId};
use licketysync_net::limits::Limits;
use licketysync_net::webtransport::{
    certhash, echo, within, BiStream, KxPolicy, Listener, ListenerConfig, WebTransportError,
    MAX_VALIDITY_DAYS, NOISE_PATH, PIECE, SHA2_256,
};
use licketysync_net::PROTOCOL_ID;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::crypto::SupportedKxGroup;
use rustls::NamedGroup;
use wtransport::tls::Sha256Digest;
use wtransport::VarInt;

#[cfg(not(target_os = "ios"))]
use libp2p_memory_connection_limits as _;
use {
    hex as _, idna_adapter as _, libp2p_connection_limits as _, libp2p_quic as _,
    libp2p_swarm as _, libp2p_tcp as _, libp2p_tls as _, libp2p_yamux as _,
    licketysync_engine as _, licketysync_keys as _, licketysync_protocol as _, memory_stats as _,
    serde_json as _, tokio as _,
};

// Generous: a 1 MiB echo in a debug build took 3.6 to 4.6 s under a loaded
// review machine; a step that passes costs nothing more.
const STEP: Duration = Duration::from_secs(30);
const MIB: usize = 1024 * 1024;
const LISTENER_SEED: u8 = 1;
const BROWSER_SEED: u8 = 2;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn keypair(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn peer(seed: u8) -> PeerId {
    keypair(seed).public().to_peer_id()
}

fn config(validity_days: u32) -> ListenerConfig {
    ListenerConfig {
        keypair: keypair(LISTENER_SEED),
        validity_days,
        allow_long_validity: false,
        kx: KxPolicy::PreferPq,
        noise_hashes_override: None,
        expected_remote: None,
        limits: Limits::default(),
    }
}

fn listener(kx: KxPolicy, noise: Option<HashSet<Multihash<64>>>, expect: Option<u8>) -> Listener {
    Listener::bind(ListenerConfig {
        kx,
        noise_hashes_override: noise,
        expected_remote: expect.map(peer),
        ..config(10)
    })
    .unwrap()
}

fn digest_of(hash: &Multihash<64>) -> Sha256Digest {
    Sha256Digest::new(hash.digest().try_into().unwrap())
}

fn other_hash() -> Multihash<64> {
    Multihash::wrap(SHA2_256, &[0xAB; 32]).unwrap()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap())
        .collect()
}

struct Dial {
    addr: SocketAddr,
    tls_hashes: Vec<Sha256Digest>,
    noise_hashes: HashSet<Multihash<64>>,
    expected: Option<PeerId>,
    /// The dialer's key-exchange groups, in its order of preference.
    groups: Vec<&'static dyn SupportedKxGroup>,
    path: &'static str,
}

fn dial_for(l: &Listener) -> Dial {
    Dial {
        addr: l.local_addr(),
        tls_hashes: vec![digest_of(&l.served_hash())],
        noise_hashes: HashSet::from([l.served_hash()]),
        expected: Some(l.peer_id()),
        groups: vec![kx_group::X25519MLKEM768, kx_group::X25519],
        path: NOISE_PATH,
    }
}

/// A rustls client configuration for WebTransport that pins the hashes and
/// offers `groups` in that order.
fn client_tls(
    groups: Vec<&'static dyn SupportedKxGroup>,
    hashes: Vec<Sha256Digest>,
) -> rustls::ClientConfig {
    use wtransport::tls::client::ServerHashVerification;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = groups;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerHashVerification::new(hashes)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    tls
}

/// The browser's side, natively: the dialer's groups in its order, the
/// hash-pinning verifier, Noise as initiator, one stream echoing a mebibyte.
async fn dial(plan: Dial) -> Result<(PeerId, usize), WebTransportError> {
    let tls = client_tls(plan.groups, plan.tls_hashes);
    let config = wtransport::ClientConfig::builder()
        .with_bind_address(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .with_custom_tls(tls)
        .max_idle_timeout(Some(Duration::from_secs(20)))
        .unwrap()
        .build();
    let endpoint = wtransport::Endpoint::client(config)?;
    let url = format!("https://{}{}", plan.addr, plan.path);
    let conn = within(STEP, "connect", async { Ok(endpoint.connect(url).await?) }).await?;
    let (send, recv) = within(STEP, "open", async { Ok(conn.open_bi().await?.await?) }).await?;
    let noise = libp2p_noise::Config::new(&keypair(BROWSER_SEED))?
        .with_webtransport_certhashes(plan.noise_hashes);
    let (remote, _noise_io) = within(STEP, "noise", async {
        Ok(noise
            .upgrade_outbound(BiStream::new(send, recv), "/noise")
            .await?)
    })
    .await?;
    if plan.expected.is_some_and(|e| e != remote) {
        conn.close(VarInt::from_u32(1), b"unexpected peer");
        return Err(WebTransportError::UnexpectedPeer(remote));
    }
    let (send, recv) = within(STEP, "open", async { Ok(conn.open_bi().await?.await?) }).await?;
    let (_, io) = within(STEP, "multistream-select", async {
        Ok(multistream_select::dialer_select_proto(
            BiStream::new(send, recv),
            [PROTOCOL_ID],
            multistream_select::Version::V1,
        )
        .await?)
    })
    .await?;
    let payload = pattern(MIB);
    let (mut reader, mut writer) = io.split();
    let write = async {
        for piece in payload.chunks(PIECE) {
            writer.write_all(piece).await?;
        }
        writer.close().await
    };
    let read = async {
        let mut got = Vec::with_capacity(MIB);
        reader.read_to_end(&mut got).await.map(|_| got)
    };
    let (w, r) = within(STEP, "echo", async { Ok(futures::join!(write, read)) }).await?;
    w?;
    let got = r?;
    if got != payload {
        return Err(WebTransportError::Io(std::io::Error::other(format!(
            "echo differs: {} bytes back",
            got.len()
        ))));
    }
    conn.close(VarInt::from_u32(0), b"done");
    Ok((remote, got.len()))
}

/// What the listener saw: the dialer's identity, the bytes echoed, the
/// handshake facts.
type Served =
    Result<(PeerId, u64, licketysync_net::webtransport::HandshakeFacts), WebTransportError>;

async fn run(l: Listener, plan: Dial) -> (Served, Result<(PeerId, usize), WebTransportError>) {
    run_with(l, plan, 4 * MIB as u64).await
}

async fn run_with(
    l: Listener,
    plan: Dial,
    echo_limit: u64,
) -> (Served, Result<(PeerId, usize), WebTransportError>) {
    // One session at a time: the recorded group is the most recent
    // handshake's in the process (TM-22's residual (g)), and `cargo test`
    // runs these tests side by side in one process (nextest does not).
    let _serial = SERIAL.lock().await;
    let listening = tokio::spawn(async move {
        let incoming = within(STEP, "accept", l.accept()).await?;
        let session = l.handshake(incoming, STEP).await?;
        let n = echo(session.accept_stream(STEP).await?, echo_limit).await?;
        session.closed(STEP).await;
        Ok((session.remote(), n, session.facts().clone()))
    });
    let client = dial(plan).await;
    let served = tokio::time::timeout(STEP * 3, listening)
        .await
        .expect("listener hung")
        .unwrap();
    (served, client)
}

fn is_certhash_mismatch<T: core::fmt::Debug>(r: &Result<T, WebTransportError>) -> bool {
    matches!(
        r,
        Err(WebTransportError::Noise(
            libp2p_noise::Error::UnknownWebTransportCerthashes(..)
        ))
    )
}

#[tokio::test]
async fn one_mib_echoes_and_each_side_sees_the_expected_peer() {
    let l = listener(KxPolicy::PreferPq, None, Some(BROWSER_SEED));
    let plan = dial_for(&l);
    let (served, client) = run(l, plan).await;
    let (remote, echoed, facts) = served.unwrap();
    assert_eq!(client.unwrap(), (peer(LISTENER_SEED), MIB));
    assert_eq!(remote, peer(BROWSER_SEED));
    assert_eq!(echoed, MIB as u64);
    assert_eq!(facts.kx_group, Some(NamedGroup::X25519MLKEM768));
    assert_eq!(
        facts.offered_groups,
        vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519]
    );
}

#[tokio::test]
async fn a_pq_only_listener_completes_with_x25519mlkem768() {
    let l = listener(KxPolicy::PqOnly, None, None);
    let plan = dial_for(&l);
    let (served, client) = run(l, plan).await;
    client.unwrap();
    assert_eq!(served.unwrap().2.kx_group, Some(NamedGroup::X25519MLKEM768));
}

#[tokio::test]
async fn a_wrong_certificate_hash_is_refused_by_the_outer_tls() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let mut plan = dial_for(&l);
    plan.tls_hashes = vec![digest_of(&other_hash())];
    let (served, client) = run(l, plan).await;
    assert!(
        matches!(client, Err(WebTransportError::Connecting(_))),
        "{client:?}"
    );
    assert!(served.is_err());
}

#[tokio::test]
async fn a_listener_reporting_other_certhashes_in_noise_is_refused() {
    let l = listener(
        KxPolicy::PreferPq,
        Some(HashSet::from([other_hash()])),
        None,
    );
    let plan = dial_for(&l);
    let (served, client) = run(l, plan).await;
    assert!(is_certhash_mismatch(&client), "{client:?}");
    assert!(served.is_err());
}

#[tokio::test]
async fn a_dialed_certhash_the_listener_does_not_report_is_refused() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let mut plan = dial_for(&l);
    plan.noise_hashes.insert(other_hash());
    let (served, client) = run(l, plan).await;
    assert!(is_certhash_mismatch(&client), "{client:?}");
    assert!(served.is_err());
}

#[tokio::test]
async fn a_listener_with_another_identity_is_refused_by_the_dialer() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let mut plan = dial_for(&l);
    plan.expected = Some(peer(9));
    let (_served, client) = run(l, plan).await;
    assert!(
        matches!(client, Err(WebTransportError::UnexpectedPeer(_))),
        "{client:?}"
    );
}

#[tokio::test]
async fn a_dialer_with_another_identity_is_refused_by_the_listener() {
    let l = listener(KxPolicy::PreferPq, None, Some(9));
    let plan = dial_for(&l);
    let (served, client) = run(l, plan).await;
    assert!(
        matches!(served, Err(WebTransportError::UnexpectedPeer(_))),
        "{served:?}"
    );
    assert!(client.is_err());
}

#[tokio::test]
async fn a_validity_from_1_to_14_days_binds_and_0_or_15_is_refused() {
    assert_eq!(MAX_VALIDITY_DAYS, 14);
    for days in [1, MAX_VALIDITY_DAYS] {
        Listener::bind(config(days)).unwrap();
    }
    for days in [0, MAX_VALIDITY_DAYS + 1] {
        let r = Listener::bind(config(days));
        assert!(
            matches!(r, Err(WebTransportError::Configuration(_))),
            "{days} days: {r:?}"
        );
    }
}

#[tokio::test]
async fn the_certhash_is_the_sha2_256_multihash_of_the_der() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let h = l.served_hash();
    assert_eq!(h.code(), SHA2_256);
    assert_eq!(h.digest().len(), 32);
    assert_eq!(certhash(&digest_of(&h)), h);
    assert!(l.multiaddr().to_string().starts_with("/ip4/127.0.0.1/udp/"));
}

/// TM-23: wtransport 0.7.2's `Endpoint::accept` panics once quinn's endpoint
/// is closed or its driver is gone; `Listener::accept` contains that panic in
/// a task of its own and returns an error. Closing the endpoint is the one
/// way to reach that state on purpose.
#[tokio::test]
async fn accept_on_a_closed_endpoint_is_an_error_not_a_panic() {
    let l = listener(KxPolicy::PreferPq, None, None);
    l.close();
    let r = within(STEP, "accept", l.accept()).await;
    assert!(
        matches!(r, Err(WebTransportError::EndpointClosed)),
        "{:?}",
        r.err()
    );
    // The listener still answers, and goes on refusing.
    let again = within(STEP, "accept", l.accept()).await;
    assert!(
        matches!(again, Err(WebTransportError::EndpointClosed)),
        "{:?}",
        again.err()
    );
}

/// Dropping `Listener::accept` before a connection arrives aborts its task;
/// a later accept still gets the next connection.
#[tokio::test]
async fn a_dropped_accept_loses_no_connection() {
    let l = listener(KxPolicy::PreferPq, None, Some(BROWSER_SEED));
    assert!(tokio::time::timeout(Duration::from_millis(50), l.accept())
        .await
        .is_err());
    let plan = dial_for(&l);
    let (served, client) = run(l, plan).await;
    served.unwrap();
    client.unwrap();
}

/// C1: the dialer's preference decides. Under `PreferPq` a dialer that lists
/// X25519 first, and offers X25519MLKEM768 too, gets X25519.
#[tokio::test]
async fn an_x25519_first_dialer_gets_x25519_under_prefer_pq() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let mut plan = dial_for(&l);
    plan.groups = vec![kx_group::X25519, kx_group::X25519MLKEM768];
    let (served, client) = run(l, plan).await;
    client.unwrap();
    let facts = served.unwrap().2;
    assert_eq!(facts.kx_group, Some(NamedGroup::X25519));
    assert_eq!(
        facts.offered_groups,
        vec![NamedGroup::X25519, NamedGroup::X25519MLKEM768]
    );
}

/// C1: `PqOnly` enforces the hybrid: the same X25519-first dialer gets
/// X25519MLKEM768 (after a `HelloRetryRequest`), ...
#[tokio::test]
async fn an_x25519_first_dialer_gets_x25519mlkem768_under_pq_only() {
    let l = listener(KxPolicy::PqOnly, None, None);
    let mut plan = dial_for(&l);
    plan.groups = vec![kx_group::X25519, kx_group::X25519MLKEM768];
    let (served, client) = run(l, plan).await;
    client.unwrap();
    assert_eq!(served.unwrap().2.kx_group, Some(NamedGroup::X25519MLKEM768));
}

/// ... and a dialer without X25519MLKEM768 is refused.
#[tokio::test]
async fn a_classical_dialer_is_refused_under_pq_only() {
    let l = listener(KxPolicy::PqOnly, None, None);
    let mut plan = dial_for(&l);
    plan.groups = vec![kx_group::X25519];
    let (served, client) = run(l, plan).await;
    assert!(
        matches!(client, Err(WebTransportError::Connecting(_))),
        "{client:?}"
    );
    assert!(served.is_err());
}

/// C6: the recorded group is the one negotiated, not a constant.
#[tokio::test]
async fn a_classical_only_listener_records_x25519() {
    let l = listener(KxPolicy::ClassicalOnly, None, None);
    let plan = dial_for(&l);
    let (served, client) = run(l, plan).await;
    client.unwrap();
    assert_eq!(served.unwrap().2.kx_group, Some(NamedGroup::X25519));
}

/// C4: a session request for another path is refused with `WrongPath`,
/// within the step.
#[tokio::test]
async fn a_session_on_another_path_is_refused() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let mut plan = dial_for(&l);
    plan.path = "/.well-known/libp2p-webtransport?type=other";
    let (served, client) = run(l, plan).await;
    assert!(
        matches!(served, Err(WebTransportError::WrongPath)),
        "{served:?}"
    );
    assert!(client.is_err());
}

/// C15: an echo past its limit stops with `EchoLimit`.
#[tokio::test]
async fn an_echo_past_its_limit_stops() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let plan = dial_for(&l);
    let (served, client) = run_with(l, plan, 64 * 1024).await;
    assert!(
        matches!(served, Err(WebTransportError::EchoLimit)),
        "{served:?}"
    );
    assert!(client.is_err());
}

/// The 18-byte input the fuzz run found (`fuzz/known-crashes/`): a HEADERS
/// frame (type 1, 13 bytes) whose QPACK prefix integer runs past 64 bits of
/// shift in `wtransport-proto` 0.7.2's decoder.
const QPACK_SHIFT_OVERFLOW: [u8; 18] = [
    0x01, 0x0d, 0xff, 0xfe, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfe, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x3f,
];

/// X1 (TM-23): an unauthenticated client whose CONNECT request's HEADERS
/// overflow `wtransport-proto`'s QPACK decoder panics wtransport's driver
/// worker where overflow checks are on (this test build), and wtransport then
/// panics whoever awaits the session request. `Listener::handshake` contains
/// that in a task of its own and returns `Panicked`; where overflow checks
/// are off the decoder returns an error and the handshake fails without a
/// panic. Either way the listener goes on serving: the next dialer gets its
/// echo.
#[tokio::test]
async fn a_panicking_session_request_is_contained() {
    let l = listener(KxPolicy::PreferPq, None, None);
    let addr = l.local_addr();
    let hashes = vec![digest_of(&l.served_hash())];
    let quic = wtransport::quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(
        vec![kx_group::X25519MLKEM768],
        hashes,
    ))
    .unwrap();
    let mut endpoint = wtransport::quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .unwrap();
    endpoint.set_default_client_config(wtransport::quinn::ClientConfig::new(Arc::new(quic)));
    let bad_client = async {
        let conn = endpoint.connect(addr, "127.0.0.1").unwrap().await.unwrap();
        // HTTP/3's control stream with an empty SETTINGS frame, then the
        // request stream with the bad HEADERS frame.
        let mut control = conn.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();
        let (mut request, _response) = conn.open_bi().await.unwrap();
        request
            .write_all(QPACK_SHIFT_OVERFLOW.get(..15).unwrap())
            .await
            .unwrap();
        // Kept open: a closed control stream is an HTTP/3 error of its own.
        (conn, control, request)
    };
    let serial = SERIAL.lock().await;
    let listening = async {
        let incoming = within(STEP, "accept", l.accept()).await?;
        l.handshake(incoming, STEP).await
    };
    let (outcome, _streams) = tokio::join!(listening, bad_client);
    if cfg!(debug_assertions) {
        assert!(
            matches!(outcome, Err(WebTransportError::Panicked("handshake"))),
            "{outcome:?}"
        );
    } else {
        assert!(outcome.is_err());
    }
    drop(serial);
    let plan = Dial {
        expected: Some(l.peer_id()),
        ..dial_for(&l)
    };
    let (served, client) = run(l, plan).await;
    served.unwrap();
    client.unwrap();
}
