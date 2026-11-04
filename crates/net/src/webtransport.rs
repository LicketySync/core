// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A device-side WebTransport listener that a browser can dial with only an
//! address and a certificate hash (spike B; feature `webtransport`, off by
//! default).
//!
//! The listener is `wtransport` on `aws-lc-rs` with a rustls configuration
//! of this crate's own (`builder_with_provider` on
//! `aws_lc_rs::default_provider()` with its key-exchange groups and cipher
//! suites replaced, TLS 1.3 only; `suites.md` 2.6), `net`'s QUIC windows and
//! stream limit ([`Limits`]), and a fresh self-signed ECDSA P-256 certificate
//! valid for at most [`MAX_VALIDITY_DAYS`] days, which is what a browser
//! accepts through `serverCertificateHashes`.
//!
//! **The dialer's preference decides the key exchange.** Among the groups
//! the listener offers, rustls's server takes the one the dialer lists first
//! (`ignore_client_order` orders cipher suites only). [`KxPolicy::PreferPq`]
//! permits X25519MLKEM768 and X25519, so a dialer that lists X25519 first gets
//! X25519; [`KxPolicy::PqOnly`] enforces the hybrid by refusing a dialer that
//! does not offer it. Chrome 156 lists X25519MLKEM768 first, so it gets
//! X25519MLKEM768 under either.
//!
//! A session follows the libp2p
//! WebTransport specification: it is accepted only at [`NOISE_PATH`]; the
//! first bidirectional stream carries the Noise XX handshake
//! (`libp2p-noise`), in which this side, the responder, reports the hashes of
//! the certificate it serves, so a dialer that was handed a hash can tell
//! that the Noise identity and the TLS certificate belong together; the
//! identity the dialer proves is checked against the one expected. Every
//! later stream is one protocol, chosen by multistream-select, and only
//! [`PROTOCOL_ID`] is offered.
//!
//! [`HandshakeFacts`] records, as evidence for `suites.md` 2.6 (TM-33), the
//! outer key-exchange group rustls chose and the groups the dialer offered.

use core::fmt;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use libp2p_core::multiaddr::Protocol;
use libp2p_core::multihash::Multihash;
use libp2p_core::upgrade::InboundConnectionUpgrade as _;
use libp2p_core::Multiaddr;
use libp2p_identity::{Keypair, PeerId};
use multistream_select::Negotiated;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SupportedKxGroup};
use rustls::NamedGroup;
use tokio::io::{AsyncRead as TokioRead, AsyncWrite as TokioWrite, ReadBuf};
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::tls::Sha256Digest;
use wtransport::{Endpoint, Identity, RecvStream, SendStream, ServerConfig, VarInt};

use crate::limits::Limits;
use crate::PROTOCOL_ID;

/// The path the libp2p WebTransport specification puts the session on.
pub const NOISE_PATH: &str = "/.well-known/libp2p-webtransport?type=noise";
/// The multihash code of SHA2-256, the only certificate hash browsers take.
pub const SHA2_256: u64 = 0x12;
/// The longest certificate validity a browser accepts for a hash, in days.
pub const MAX_VALIDITY_DAYS: u32 = 14;
/// The largest piece [`echo`] reads or writes at once.
pub const PIECE: usize = 64 * 1024;
/// The most unread datagram bytes quinn holds for a connection.
pub const DATAGRAM_RECEIVE_BUFFER: usize = 64 * 1024;

/// Why a WebTransport session failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum WebTransportError {
    /// A step did not finish before its deadline.
    Timeout(&'static str),
    /// The session asked for a path other than [`NOISE_PATH`].
    WrongPath,
    /// The Noise handshake failed (including certificate hashes that do not
    /// match).
    Noise(libp2p_noise::Error),
    /// The dialer proved an identity other than the one expected.
    UnexpectedPeer(PeerId),
    /// multistream-select found no common protocol, or failed.
    Negotiation(multistream_select::NegotiationError),
    /// The WebTransport connection failed.
    Connection(wtransport::error::ConnectionError),
    /// A stream could not be opened.
    StreamOpen(wtransport::error::StreamOpeningError),
    /// Connecting failed (the native test dialer).
    Connecting(wtransport::error::ConnectingError),
    /// An I/O error on a stream or socket.
    Io(std::io::Error),
    /// The certificate could not be made.
    Certificate(String),
    /// The rustls configuration failed.
    Tls(rustls::Error),
    /// [`echo`] went past its limit.
    EchoLimit,
    /// The endpoint is closed, or its driver ended: it accepts no more.
    EndpointClosed,
    /// A listener setting is out of range (the validity, the idle timeout or
    /// a [`Limits`] value).
    Configuration(String),
    /// A step ran in a task of its own and that task panicked (inside
    /// `wtransport`, for one: TM-23), or was cancelled when the runtime shut
    /// down; it names the step.
    Panicked(&'static str),
}

impl fmt::Display for WebTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(step) => write!(f, "timed out: {step}"),
            Self::WrongPath => f.write_str("wrong path"),
            Self::Noise(e) => write!(f, "noise: {e}"),
            Self::UnexpectedPeer(p) => write!(f, "unexpected peer {p}"),
            Self::Negotiation(e) => write!(f, "multistream-select: {e}"),
            Self::Connection(e) => write!(f, "connection: {e}"),
            Self::StreamOpen(e) => write!(f, "stream open: {e}"),
            Self::Connecting(e) => write!(f, "connecting: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Certificate(e) => write!(f, "certificate: {e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::EchoLimit => f.write_str("echo limit exceeded"),
            Self::EndpointClosed => f.write_str("the endpoint accepts no more"),
            Self::Configuration(e) => write!(f, "configuration: {e}"),
            Self::Panicked(step) => write!(f, "{step}: its task panicked or was cancelled"),
        }
    }
}

impl std::error::Error for WebTransportError {}

macro_rules! from_error {
    ($($from:ty => $variant:ident),* $(,)?) => {
        $(impl From<$from> for WebTransportError {
            fn from(e: $from) -> Self {
                Self::$variant(e)
            }
        })*
    };
}

from_error! {
    libp2p_noise::Error => Noise,
    multistream_select::NegotiationError => Negotiation,
    wtransport::error::ConnectionError => Connection,
    wtransport::error::StreamOpeningError => StreamOpen,
    wtransport::error::ConnectingError => Connecting,
    std::io::Error => Io,
    rustls::Error => Tls,
}

/// Which outer key-exchange groups the listener accepts. The dialer's order
/// picks among them (the module's notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KxPolicy {
    /// X25519MLKEM768 and X25519 are both permitted; the dialer's preference
    /// decides, so a dialer listing X25519 first gets X25519 (`suites.md`
    /// 2.6). Chrome lists X25519MLKEM768 first.
    PreferPq,
    /// X25519MLKEM768 only: a dialer that does not offer it is refused, so a
    /// handshake that completes used the hybrid.
    PqOnly,
    /// X25519 only, to show what a classical-only native end gives (tests).
    ClassicalOnly,
}

/// The key-exchange group the most recent WebTransport handshake in this
/// process chose (0 before any). Evidence only: with handshakes running at
/// the same time it can belong to another session (per-connection facts are
/// TM-23's residual, phase 6).
static LAST_KX: AtomicU16 = AtomicU16::new(0);

/// A key-exchange group that delegates to an `aws-lc-rs` group and records in
/// [`LAST_KX`] that rustls chose it. It computes nothing itself. The groups
/// are statics, as rustls requires `'static` ones, so a listener allocates
/// none.
#[derive(Debug)]
struct RecordingGroup {
    inner: fn() -> &'static dyn SupportedKxGroup,
}

fn x25519mlkem768() -> &'static dyn SupportedKxGroup {
    rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768
}

fn x25519() -> &'static dyn SupportedKxGroup {
    rustls::crypto::aws_lc_rs::kx_group::X25519
}

static RECORDING_X25519MLKEM768: RecordingGroup = RecordingGroup {
    inner: x25519mlkem768,
};
static RECORDING_X25519: RecordingGroup = RecordingGroup { inner: x25519 };

impl SupportedKxGroup for RecordingGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        LAST_KX.store(u16::from(self.name()), Ordering::SeqCst);
        (self.inner)().start()
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        LAST_KX.store(u16::from(self.name()), Ordering::SeqCst);
        (self.inner)().start_and_complete(peer_pub_key)
    }

    fn name(&self) -> NamedGroup {
        (self.inner)().name()
    }

    fn fips(&self) -> bool {
        (self.inner)().fips()
    }

    fn usable_for_version(&self, version: rustls::ProtocolVersion) -> bool {
        (self.inner)().usable_for_version(version)
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        (self.inner)().ffdhe_group()
    }
}

/// Serves the one certificate and records the groups the dialer's
/// `ClientHello` lists in `supported_groups`.
#[derive(Debug)]
struct RecordingResolver {
    key: Arc<rustls::sign::CertifiedKey>,
    offered: Arc<Mutex<Vec<NamedGroup>>>,
}

impl rustls::server::ResolvesServerCert for RecordingResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Ok(mut offered) = self.offered.lock() {
            hello
                .named_groups()
                .unwrap_or_default()
                .clone_into(&mut *offered);
        }
        Some(Arc::clone(&self.key))
    }
}

/// `aws_lc_rs::default_provider()` with the groups the policy allows, each
/// wrapped to record rustls's choice, and libp2p-tls's cipher-suite order.
fn provider(policy: KxPolicy) -> CryptoProvider {
    use rustls::crypto::aws_lc_rs::{cipher_suite, default_provider};
    let groups: Vec<&'static dyn SupportedKxGroup> = match policy {
        KxPolicy::PreferPq => vec![&RECORDING_X25519MLKEM768, &RECORDING_X25519],
        KxPolicy::PqOnly => vec![&RECORDING_X25519MLKEM768],
        KxPolicy::ClassicalOnly => vec![&RECORDING_X25519],
    };
    let mut provider = default_provider();
    // QUIC needs TLS13_AES_128_GCM_SHA256 present for its Initial packets,
    // so it stays, last.
    provider.cipher_suites = vec![
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = groups;
    provider
}

/// A WebTransport bidirectional stream as one `futures` reader and writer.
#[derive(Debug)]
pub struct BiStream {
    send: SendStream,
    recv: RecvStream,
}

impl BiStream {
    /// Joins the two halves.
    #[must_use]
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl futures::AsyncRead for BiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read = ReadBuf::new(buf);
        match Pin::new(&mut self.recv).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures::AsyncWrite for BiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// The certificate hash as the multihash a `/certhash` component and the
/// Noise extension carry.
#[must_use]
pub fn certhash(digest: &Sha256Digest) -> Multihash<64> {
    // A 32-byte digest always fits a 64-byte multihash.
    Multihash::wrap(SHA2_256, digest.as_ref()).unwrap_or_default()
}

/// How a listener is set up.
#[derive(Debug)]
pub struct ListenerConfig {
    /// The listener's libp2p identity.
    pub keypair: Keypair,
    /// The certificate's validity in days, from 1 to [`MAX_VALIDITY_DAYS`]:
    /// [`Listener::bind`] refuses 0, and more than [`MAX_VALIDITY_DAYS`]
    /// unless `allow_long_validity` is set (tests show that browsers refuse
    /// such a certificate).
    pub validity_days: u32,
    /// Allows a validity above [`MAX_VALIDITY_DAYS`] (tests only; a public
    /// knob of the spike, like `noise_hashes_override` and
    /// [`KxPolicy::ClassicalOnly`], that phase 6 moves behind a test-only
    /// interface).
    pub allow_long_validity: bool,
    /// The outer key exchange.
    pub kx: KxPolicy,
    /// If set, the hashes Noise reports instead of the served certificate's
    /// (a negative test).
    pub noise_hashes_override: Option<HashSet<Multihash<64>>>,
    /// If set, the only dialer identity accepted.
    pub expected_remote: Option<PeerId>,
    /// QUIC's windows and stream count, `net`'s limits as QUIC and TCP use
    /// them: `max_streams_per_connection` bidirectional and as many
    /// unidirectional streams, `stream_receive_window` a stream and
    /// `connection_receive_window` a connection.
    pub limits: Limits,
}

/// What the outer TLS handshake showed (TM-33 evidence).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandshakeFacts {
    /// The key-exchange group rustls chose: the most recent handshake's in
    /// this process, so with handshakes at the same time it can be another
    /// session's (phase 6 makes it per connection).
    pub kx_group: Option<NamedGroup>,
    /// The groups in `supported_groups` of the most recent `ClientHello`
    /// this listener saw, unauthenticated, so with handshakes at the same
    /// time it can be another dialer's, as with `kx_group`.
    pub offered_groups: Vec<NamedGroup>,
}

/// A native WebTransport listener on 127.0.0.1.
pub struct Listener {
    endpoint: Arc<Endpoint<Server>>,
    local: SocketAddr,
    served_hash: Multihash<64>,
    noise_hashes: HashSet<Multihash<64>>,
    keypair: Keypair,
    expected_remote: Option<PeerId>,
    offered: Arc<Mutex<Vec<NamedGroup>>>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("local", &self.local)
            .field("peer_id", &self.peer_id())
            .finish_non_exhaustive()
    }
}

/// A session whose Noise handshake completed and whose dialer is the one
/// expected.
#[derive(Debug)]
pub struct Session {
    conn: wtransport::Connection,
    remote: PeerId,
    facts: HandshakeFacts,
}

impl Listener {
    /// Binds a listener on 127.0.0.1 with a fresh self-signed P-256
    /// certificate.
    ///
    /// # Errors
    ///
    /// [`WebTransportError::Configuration`] for a validity of 0 days, or
    /// above [`MAX_VALIDITY_DAYS`] without `allow_long_validity`, or limits
    /// out of range; otherwise if the certificate, the TLS configuration or
    /// the socket cannot be made.
    pub fn bind(config: ListenerConfig) -> Result<Self, WebTransportError> {
        if config.validity_days == 0
            || (config.validity_days > MAX_VALIDITY_DAYS && !config.allow_long_validity)
        {
            return Err(WebTransportError::Configuration(format!(
                "validity {} days is not from 1 to {MAX_VALIDITY_DAYS}",
                config.validity_days
            )));
        }
        config
            .limits
            .check()
            .map_err(|e| WebTransportError::Configuration(e.to_string()))?;
        let identity = Identity::self_signed_builder()
            .subject_alt_names(["127.0.0.1"])
            .from_now_utc()
            .validity_days(config.validity_days)
            .build()
            .map_err(|e| WebTransportError::Certificate(e.to_string()))?;
        let cert = identity
            .certificate_chain()
            .as_slice()
            .first()
            .ok_or_else(|| WebTransportError::Certificate("empty chain".into()))?;
        let served_hash = certhash(&cert.hash());
        // TM-6: these copies of the certificate's P-256 key are not wiped:
        // `wtransport`'s `PrivateKey` and rustls's `PrivateKeyDer`, which
        // `CertifiedKey::from_der` consumes, do not zeroize on drop
        // (`suites.md` 4.1's deviation for the WebTransport key).
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            identity.private_key().secret_der().to_vec(),
        )
        .map_err(|e| WebTransportError::Certificate(e.to_owned()))?;

        let offered = Arc::new(Mutex::new(Vec::new()));
        let provider = Arc::new(provider(config.kx));
        let key = Arc::new(rustls::sign::CertifiedKey::from_der(
            vec![cert_der],
            key_der,
            &provider,
        )?);
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RecordingResolver {
                key,
                offered: Arc::clone(&offered),
            }));
        tls.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
        tls.max_early_data_size = 0;
        // libp2p-tls's suite order wins over the browser's (Chrome lists
        // AES-128-GCM first).
        tls.ignore_client_order = true;

        let limits = &config.limits;
        let mut transport = wtransport::config::QuicTransportConfig::default();
        let streams = wtransport::quinn::VarInt::from_u32(limits.max_streams_per_connection);
        transport
            .max_concurrent_bidi_streams(streams)
            .max_concurrent_uni_streams(streams)
            .receive_window(wtransport::quinn::VarInt::from_u32(
                limits.connection_receive_window,
            ))
            .stream_receive_window(wtransport::quinn::VarInt::from_u32(
                limits.stream_receive_window,
            ))
            // Datagrams stay advertised (WebTransport sessions carry them),
            // but quinn buffers at most this much of them unread, not its
            // default of about 1.25 MB (TM-22's residual (e)).
            .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER));
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let server = ServerConfig::builder()
            .with_bind_address(bind)
            .with_custom_tls_and_transport(tls, transport)
            .max_idle_timeout(Some(Duration::from_secs(20)))
            .map_err(|e| WebTransportError::Configuration(e.to_string()))?
            .build();
        let endpoint = Arc::new(Endpoint::server(server)?);
        let local = endpoint.local_addr()?;
        let noise_hashes = config
            .noise_hashes_override
            .unwrap_or_else(|| HashSet::from([served_hash]));
        Ok(Self {
            endpoint,
            local,
            served_hash,
            noise_hashes,
            keypair: config.keypair,
            expected_remote: config.expected_remote,
            offered,
        })
    }

    /// The UDP address it listens on.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The served certificate's hash.
    #[must_use]
    pub fn served_hash(&self) -> Multihash<64> {
        self.served_hash
    }

    /// The listener's peer ID.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// `/ip4/127.0.0.1/udp/<port>/quic-v1/webtransport/certhash/<hash>/p2p/<id>`.
    #[must_use]
    pub fn multiaddr(&self) -> Multiaddr {
        multiaddr_for(self.local, &[self.served_hash], Some(self.peer_id()))
    }

    /// Waits for the next connection attempt.
    ///
    /// `wtransport` 0.7.2's `Endpoint::accept` panics ("Endpoint cannot be
    /// closed", its `src/endpoint.rs` line 150) when quinn's `accept` returns
    /// `None`. quinn 0.11.12 does that (its `src/endpoint.rs`, `impl Future
    /// for Accept`, lines 647-675) once the endpoint is closed, which nothing
    /// here does but [`Listener::close`], or once its driver is gone
    /// (`driver_lost`, set when `EndpointDriver` is dropped, lines 401-410):
    /// the driver ends on any socket error but `ConnectionReset`, which quinn
    /// ignores because an attacker can inject it (lines 843-850). Whether a
    /// remote peer can cause another receive error depends on the platform's
    /// UDP stack (ICMP errors on Windows, for one), so that panic is not
    /// provably unreachable from the network. It is therefore contained: the
    /// accept runs in a task of its own, a panic there ends only that task
    /// (tokio catches it; the workspace's profiles do not set
    /// `panic = "abort"`), and it comes back as
    /// [`WebTransportError::EndpointClosed`] (TM-23). Dropping this future
    /// aborts the task; a connection attempt the task had already taken when
    /// it was aborted is dropped with it, and so refused.
    ///
    /// # Errors
    ///
    /// [`WebTransportError::EndpointClosed`] once the endpoint can accept no
    /// more.
    pub async fn accept(&self) -> Result<IncomingSession, WebTransportError> {
        let endpoint = Arc::clone(&self.endpoint);
        let mut task = AbortOnDrop(tokio::spawn(async move { endpoint.accept().await }));
        (&mut task.0)
            .await
            .map_err(|_| WebTransportError::EndpointClosed)
    }

    /// Closes the endpoint: every session ends, and [`Listener::accept`]
    /// returns [`WebTransportError::EndpointClosed`] from then on.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"closed");
    }

    /// Runs one connection attempt up to a [`Session`]: the session request
    /// and its path, the session, Noise with the certificate hashes, and the
    /// dialer's identity, each step within `step`. A session that fails is
    /// closed; a request for another path gets a 404, itself bounded by
    /// `step`.
    ///
    /// The whole of it runs in a task of its own (TM-23): `wtransport` 0.7.2
    /// decodes the dialer's request in a worker task per connection, and when
    /// that worker panics (`wtransport-proto`'s QPACK decoder does on some
    /// unauthenticated input where overflow checks are on, TM-23's residual
    /// (a)), whoever awaits the connection next panics too ("Driver worker
    /// panic!", wtransport's `src/driver/mod.rs` lines 230-234). Here that
    /// panic ends only this task and comes back as
    /// [`WebTransportError::Panicked`]. Dropping this future aborts the task.
    ///
    /// # Errors
    ///
    /// Any step failing or taking longer than `step`;
    /// [`WebTransportError::Panicked`] if the task panicked.
    pub async fn handshake(
        &self,
        incoming: IncomingSession,
        step: Duration,
    ) -> Result<Session, WebTransportError> {
        // The Noise configuration is made here, so the task gets the
        // identity's public half and signature, not another copy of its
        // secret key (TM-6).
        let noise = libp2p_noise::Config::new(&self.keypair)?
            .with_webtransport_certhashes(self.noise_hashes.clone());
        let expected = self.expected_remote;
        let offered = Arc::clone(&self.offered);
        contained("handshake", async move {
            let request = within(step, "session request", async { Ok(incoming.await?) }).await?;
            if request.path() != NOISE_PATH {
                // The 404 is a courtesy: the dialer's flow control could
                // hold it back, so it gets `step` and no more.
                let _sent = tokio::time::timeout(step, request.not_found()).await;
                return Err(WebTransportError::WrongPath);
            }
            let conn = within(step, "session accept", async {
                Ok(request.accept().await?)
            })
            .await?;
            match noise_handshake(&conn, noise, expected, step).await {
                Ok(remote) => {
                    let kx = LAST_KX.load(Ordering::SeqCst);
                    let facts = HandshakeFacts {
                        kx_group: (kx != 0).then(|| NamedGroup::from(kx)),
                        offered_groups: offered.lock().map(|g| g.clone()).unwrap_or_default(),
                    };
                    Ok(Session {
                        conn,
                        remote,
                        facts,
                    })
                }
                Err(e) => {
                    conn.close(VarInt::from_u32(1), b"refused");
                    Err(e)
                }
            }
        })
        .await
    }
}

/// Noise XX as responder on the session's first stream, reporting the
/// certificate hashes `noise` was given; then the dialer's identity against
/// `expected`.
async fn noise_handshake(
    conn: &wtransport::Connection,
    noise: libp2p_noise::Config,
    expected: Option<PeerId>,
    step: Duration,
) -> Result<PeerId, WebTransportError> {
    let (send, recv) = within(step, "noise stream", async { Ok(conn.accept_bi().await?) }).await?;
    let (remote, _noise_io) = within(step, "noise", async {
        Ok(noise
            .upgrade_inbound(BiStream::new(send, recv), "/noise")
            .await?)
    })
    .await?;
    match expected {
        Some(expected) if expected != remote => Err(WebTransportError::UnexpectedPeer(remote)),
        _ => Ok(remote),
    }
}

/// Aborts a task when the one waiting for it stops waiting.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs `fut` in a task of its own, so that a panic inside it (in
/// `wtransport`, for one) ends only that task and comes back as
/// [`WebTransportError::Panicked`] naming `step`. Dropping the returned future
/// aborts the task.
async fn contained<T, F>(step: &'static str, fut: F) -> Result<T, WebTransportError>
where
    F: core::future::Future<Output = Result<T, WebTransportError>> + Send + 'static,
    T: Send + 'static,
{
    let mut task = AbortOnDrop(tokio::spawn(fut));
    match (&mut task.0).await {
        Ok(result) => result,
        Err(_) => Err(WebTransportError::Panicked(step)),
    }
}

impl Session {
    /// The identity the dialer proved in Noise.
    #[must_use]
    pub fn remote(&self) -> PeerId {
        self.remote
    }

    /// What the outer TLS handshake showed.
    #[must_use]
    pub fn facts(&self) -> &HandshakeFacts {
        &self.facts
    }

    /// Accepts the next stream and agrees [`PROTOCOL_ID`] on it, in a task
    /// of its own as [`Listener::handshake`] runs (a panicked `wtransport`
    /// worker panics whoever awaits the connection next).
    ///
    /// # Errors
    ///
    /// The stream failing, another protocol, or `step` passing;
    /// [`WebTransportError::Panicked`] if the task panicked.
    pub async fn accept_stream(
        &self,
        step: Duration,
    ) -> Result<Negotiated<BiStream>, WebTransportError> {
        let conn = self.conn.clone();
        contained("protocol stream", async move {
            let (send, recv) = within(step, "protocol stream", async {
                Ok(conn.accept_bi().await?)
            })
            .await?;
            let (_, io) = within(step, "multistream-select", async {
                Ok(multistream_select::listener_select_proto(
                    BiStream::new(send, recv),
                    [PROTOCOL_ID],
                )
                .await?)
            })
            .await?;
            Ok(io)
        })
        .await
    }

    /// Waits up to `step` for the dialer to close the session.
    pub async fn closed(&self, step: Duration) {
        let _closed = tokio::time::timeout(step, self.conn.closed()).await;
    }

    /// Closes the session.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(code), reason);
    }
}

/// Builds a WebTransport multiaddr.
#[must_use]
pub fn multiaddr_for(
    addr: SocketAddr,
    hashes: &[Multihash<64>],
    peer: Option<PeerId>,
) -> Multiaddr {
    let mut ma = Multiaddr::empty()
        .with(match addr.ip() {
            std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
            std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
        })
        .with(Protocol::Udp(addr.port()))
        .with(Protocol::QuicV1)
        .with(Protocol::WebTransport);
    for hash in hashes {
        ma = ma.with(Protocol::Certhash(*hash));
    }
    if let Some(peer) = peer {
        ma = ma.with(Protocol::P2p(peer));
    }
    ma
}

/// Runs `fut` for at most `step`.
///
/// # Errors
///
/// [`WebTransportError::Timeout`] naming `what`, or `fut`'s own error.
pub async fn within<T, F>(
    step: Duration,
    what: &'static str,
    fut: F,
) -> Result<T, WebTransportError>
where
    F: core::future::Future<Output = Result<T, WebTransportError>>,
{
    tokio::time::timeout(step, fut)
        .await
        .map_err(|_| WebTransportError::Timeout(what))?
}

/// The spike's stand-in for the protocol: copies what arrives back, in
/// pieces of at most [`PIECE`], until the remote finishes, then finishes.
///
/// # Errors
///
/// An I/O error, or more than `limit` bytes.
pub async fn echo<T>(mut io: T, limit: u64) -> Result<u64, WebTransportError>
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; PIECE];
    let mut total = 0u64;
    loop {
        let n = io.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > limit {
            return Err(WebTransportError::EchoLimit);
        }
        io.write_all(buf.get(..n).unwrap_or_default()).await?;
    }
    io.close().await?;
    Ok(total)
}
