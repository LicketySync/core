// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The swarm: a device's two transports, its limits and the sync behaviour
//! (`suites.md` 2.6; TM-1, TM-22).
//!
//! - **QUIC** (`libp2p-quic` on quinn): TLS 1.3 is part of QUIC, with
//!   `libp2p-tls`'s configurations on `aws-lc-rs`, X25519MLKEM768 first.
//! - **TCP** (`libp2p-tcp`): multistream-select offers exactly one security
//!   protocol, `/tls/1.0.0` (`libp2p-tls`, the same configurations), then
//!   exactly one muxer, `/yamux/1.0.0`. A dialer that proposes anything else
//!   (Noise, plaintext) is answered `na` and gets no connection: no
//!   unencrypted listener or dialer exists here.
//!
//! Each side's TLS certificate carries its libp2p identity, which the other
//! side verifies; the peer ID a connection reports is the one its peer
//! proved. A dial names the peer ID it expects ([`dial_opts`]), but only the
//! swarm compares it, after the TLS handshake, and refuses a connection whose
//! peer proved another (TM-32: the peer is known by its key); by then the
//! dialer's certificate, and so its identity, has gone to whoever answered.
//! Giving `libp2p-tls`'s verifier the expected peer, so that the handshake
//! fails first, is a phase 1 item (the threat model's 3.1). The folder proof
//! stays the protocol's.
//!
//! A QUIC dial leaves from the endpoint of a QUIC listener of the same
//! address family (one on loopback, for a loopback address) when the swarm
//! has one; with none, `libp2p-quic` binds a dialing socket of its own on
//! every address (`0.0.0.0` or `[::]`, port 0). The tests and
//! `examples/spike.rs` therefore listen on 127.0.0.1 before they dial
//! (TM-31). Beneath either, quinn-udp's checks for GSO and GRO bind a socket
//! on `[::]`, port 0, set one option and close it without sending. Phase 1:
//! the daemon listens on the addresses the user turned on before it dials, so
//! its dials leave from those endpoints, and a dial with no listener of its
//! family is an item for the phase 1 dial path.
//!
//! The TCP upgrade (negotiation, TLS, yamux) ends after
//! [`Limits::handshake_timeout`], which `libp2p`'s own `SwarmBuilder` does not
//! set, so that a connection that never speaks cannot hold a pending slot
//! for ever.
//!
//! No node is built on an operating system where `net` has no process-memory
//! limit ([`has_memory_limit`]): on iOS today (TM-22's residual (d)),
//! [`build`] returns [`BuildError::NoMemoryLimitOnThisPlatform`] before it
//! does anything else, so that `net` does not start there until the limit
//! exists (the owner's answer of 2026-11-03).

use core::convert::Infallible;
use core::fmt;
use core::task::{Context, Poll};

use futures::future::Either;
use libp2p_core::muxing::StreamMuxerBox;
use libp2p_core::transport::{Boxed, PortUse, Transport as _};
use libp2p_core::upgrade::Version;
use libp2p_core::{Endpoint, Multiaddr};
use libp2p_identity::{DecodingError, PeerId};
use libp2p_swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use licketysync_keys::device::Libp2pIdentity;

use crate::limits::{Limits, LimitsError, has_memory_limit};
use crate::provider::{self, ProviderError};
use crate::{identity, sync};

pub use libp2p_swarm::dial_opts;

/// The environment variable through which rustls's `KeyLogFile`, which
/// `libp2p-tls` installs in every configuration it builds, writes each
/// session's secrets to a file. A node is not built while it is set (TM-6:
/// session keys never reach a file or a log).
pub const KEY_LOG_VARIABLE: &str = "SSLKEYLOGFILE";

/// A device's swarm.
pub type Swarm = libp2p_swarm::Swarm<Behaviour>;

/// The behaviours of a node, in the order the swarm consults them: the
/// connection limits, the memory limit (none on iOS yet, TM-22's residual
/// (d)), then the sync streams.
///
/// Written out, not derived: the derive would run each behaviour's handler
/// beside the others, and give an inbound stream the longest of their
/// negotiation timeouts, which for the two limit behaviours' handlers (they
/// run no protocol) is `libp2p-swarm`'s 10 s default. Here a connection's one
/// handler is the sync behaviour's, so every stream negotiates within
/// [`Limits::negotiation_timeout`]; the limit behaviours give only their
/// verdicts.
pub struct Behaviour {
    connection_limits: libp2p_connection_limits::Behaviour,
    memory_limit: MemoryLimit,
    sync: sync::Behaviour,
}

/// The process-memory limit: `libp2p-memory-connection-limits`, which
/// refuses every new connection, inbound or outbound, while the process's
/// resident memory is above [`Limits::max_process_memory_bytes`].
#[cfg(not(target_os = "ios"))]
type MemoryLimit = libp2p_memory_connection_limits::Behaviour;

/// On iOS, where `libp2p-memory-connection-limits` does not build (its
/// sysinfo 0.38 needs libc items that libc keeps for macOS), a behaviour that
/// refuses nothing, there only so that [`Behaviour`] compiles: [`build`]
/// refuses on iOS before it would make one ([`has_memory_limit`]; TM-22's
/// residual (d)), so no node runs with it. Phase 4 replaces it with an iOS
/// memory check of `net`'s own or an upstream fix.
#[cfg(target_os = "ios")]
type MemoryLimit = libp2p_swarm::dummy::Behaviour;

#[cfg(not(target_os = "ios"))]
fn memory_limit(limits: &Limits) -> MemoryLimit {
    libp2p_memory_connection_limits::Behaviour::with_max_bytes(limits.max_process_memory_bytes)
}

#[cfg(target_os = "ios")]
fn memory_limit(_limits: &Limits) -> MemoryLimit {
    libp2p_swarm::dummy::Behaviour
}

impl fmt::Debug for Behaviour {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Behaviour")
            .field("sync", &self.sync)
            .finish_non_exhaustive()
    }
}

impl Behaviour {
    /// The sync behaviour, to open streams.
    pub fn sync(&mut self) -> &mut sync::Behaviour {
        &mut self.sync
    }
}

/// A limit behaviour's event, which never exists, as the node's.
fn never<T>(event: ToSwarm<Infallible, Infallible>) -> ToSwarm<Event, T> {
    event
        .map_in(|never| match never {})
        .map_out(|never| match never {})
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = sync::Handler;
    type ToSwarm = Event;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.connection_limits.handle_pending_inbound_connection(
            connection_id,
            local_addr,
            remote_addr,
        )?;
        self.memory_limit.handle_pending_inbound_connection(
            connection_id,
            local_addr,
            remote_addr,
        )?;
        self.sync
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // The limit behaviours' handlers run no protocol; only their verdicts
        // are kept.
        let libp2p_swarm::dummy::ConnectionHandler = self
            .connection_limits
            .handle_established_inbound_connection(connection_id, peer, local_addr, remote_addr)?;
        let libp2p_swarm::dummy::ConnectionHandler = self
            .memory_limit
            .handle_established_inbound_connection(connection_id, peer, local_addr, remote_addr)?;
        self.sync.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let mut combined = self.connection_limits.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )?;
        combined.extend(self.memory_limit.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )?);
        combined.extend(self.sync.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )?);
        Ok(combined)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let libp2p_swarm::dummy::ConnectionHandler = self
            .connection_limits
            .handle_established_outbound_connection(
                connection_id,
                peer,
                addr,
                role_override,
                port_use,
            )?;
        let libp2p_swarm::dummy::ConnectionHandler =
            self.memory_limit.handle_established_outbound_connection(
                connection_id,
                peer,
                addr,
                role_override,
                port_use,
            )?;
        self.sync.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.connection_limits.on_swarm_event(event);
        self.memory_limit.on_swarm_event(event);
        self.sync.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.sync
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Event, THandlerInEvent<Self>>> {
        if let Poll::Ready(event) = self.connection_limits.poll(cx) {
            return Poll::Ready(never(event));
        }
        if let Poll::Ready(event) = self.memory_limit.poll(cx) {
            return Poll::Ready(never(event));
        }
        self.sync.poll(cx).map(|event| event.map_out(Event::Sync))
    }
}

/// What a node's behaviours report.
#[derive(Debug)]
pub enum Event {
    /// The sync behaviour's event.
    Sync(sync::Event),
}

/// Why a node was not built.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// The operating system this runs on is one where `net` has no
    /// process-memory limit, iOS among them ([`has_memory_limit`]; TM-22's
    /// residual (d)).
    NoMemoryLimitOnThisPlatform,
    /// [`KEY_LOG_VARIABLE`] is set in the environment.
    KeyLogRequested,
    /// The process-default rustls provider is not the one `suites.md` 2.6
    /// requires.
    Provider(ProviderError),
    /// A limit is out of range.
    Limits(LimitsError),
    /// The identity's key was refused (not expected; see
    /// [`identity::keypair`]).
    Identity(DecodingError),
    /// The TLS certificate could not be generated.
    Certificate(libp2p_tls::certificate::GenError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMemoryLimitOnThisPlatform => write!(
                f,
                "no process-memory limit on this platform: net does not start without one"
            ),
            Self::KeyLogRequested => write!(
                f,
                "{KEY_LOG_VARIABLE} is set: TLS session secrets would be written to a file"
            ),
            Self::Provider(e) => write!(f, "{e}"),
            Self::Limits(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "the libp2p identity was refused: {e}"),
            Self::Certificate(e) => write!(f, "the TLS certificate was not generated: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Builds the swarm of the device whose libp2p identity is `identity`, with
/// `limits`. Refuses first, before anything else, on an operating system
/// where `net` has no process-memory limit ([`has_memory_limit`]: iOS
/// today). Installs the process-default rustls provider
/// ([`provider::install_default_provider`]). Must run inside a Tokio
/// runtime: connections run as Tokio tasks.
///
/// # Errors
///
/// [`BuildError`]: there is no memory limit on this platform, the key-log
/// variable is set, the process default is another provider, a limit is out
/// of range, the identity's key is refused, or the certificate could not be
/// generated.
pub fn build(identity: &Libp2pIdentity, limits: &Limits) -> Result<Swarm, BuildError> {
    build_on(std::env::consts::OS, identity, limits)
}

/// [`build`] on the operating system `os`, which `build` passes as
/// [`std::env::consts::OS`]; a test passes another, to check the refusal on
/// a platform it does not run on.
fn build_on(os: &str, identity: &Libp2pIdentity, limits: &Limits) -> Result<Swarm, BuildError> {
    if !has_memory_limit(os) {
        return Err(BuildError::NoMemoryLimitOnThisPlatform);
    }
    if std::env::var_os(KEY_LOG_VARIABLE).is_some() {
        return Err(BuildError::KeyLogRequested);
    }
    provider::install_default_provider().map_err(BuildError::Provider)?;
    limits.check().map_err(BuildError::Limits)?;
    let keypair = identity::keypair(identity).map_err(BuildError::Identity)?;
    let peer_id = keypair.public().to_peer_id();
    let transport = transport(&keypair, limits)?;
    let config = libp2p_swarm::Config::with_tokio_executor()
        .with_idle_connection_timeout(limits.idle_timeout)
        .with_max_negotiating_inbound_streams(to_usize(limits.max_negotiating_inbound_streams));
    Ok(libp2p_swarm::Swarm::new(
        transport,
        behaviour(limits),
        peer_id,
        config,
    ))
}

/// The node's behaviours, every bound taken from `limits`.
fn behaviour(limits: &Limits) -> Behaviour {
    Behaviour {
        connection_limits: libp2p_connection_limits::Behaviour::new(
            libp2p_connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(limits.max_pending_incoming))
                .with_max_pending_outgoing(Some(limits.max_pending_outgoing))
                .with_max_established_incoming(Some(limits.max_established_incoming))
                .with_max_established_outgoing(Some(limits.max_established_outgoing))
                .with_max_established_per_peer(Some(limits.max_established_per_peer))
                .with_max_established(Some(limits.max_established_total)),
        ),
        memory_limit: memory_limit(limits),
        sync: sync::Behaviour::new(limits.max_inbound_sync_streams, limits.negotiation_timeout),
    }
}

/// QUIC, then TCP with TLS and yamux, as one transport.
fn transport(
    keypair: &libp2p_identity::Keypair,
    limits: &Limits,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, BuildError> {
    // Built first: `libp2p_quic::Config::new` (in `quic_config`) makes the
    // same two rustls configurations from the same key and unwraps them, so
    // if they can be made here they can be made there, and that unwrap is
    // never reached.
    let tls = libp2p_tls::Config::new(keypair).map_err(BuildError::Certificate)?;
    let mut yamux = libp2p_yamux::Config::default();
    yamux.set_max_num_streams(to_usize(limits.max_streams_per_connection));
    let tcp = libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::new().nodelay(true))
        .upgrade(Version::V1)
        .authenticate(tls)
        .multiplex(yamux)
        .timeout(limits.handshake_timeout);
    let quic = libp2p_quic::tokio::Transport::new(quic_config(keypair, limits));

    Ok(quic
        .map(|(peer, connection), _| (peer, StreamMuxerBox::new(connection)))
        .or_transport(tcp.map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer))))
        .map(|either, _| match either {
            Either::Left(output) | Either::Right(output) => output,
        })
        .boxed())
}

/// QUIC's configuration: every bound QUIC takes from `limits`. Its
/// keep-alive (5 s) stays `libp2p-quic`'s.
fn quic_config(keypair: &libp2p_identity::Keypair, limits: &Limits) -> libp2p_quic::Config {
    let mut config = libp2p_quic::Config::new(keypair);
    config.handshake_timeout = limits.handshake_timeout;
    config.max_idle_timeout = limits.idle_timeout_millis();
    config.max_concurrent_stream_limit = limits.max_streams_per_connection;
    config.max_connection_data = limits.connection_receive_window;
    config.max_stream_data = limits.stream_receive_window;
    config
}

fn to_usize(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test code")]
mod tests {
    use core::time::Duration;

    use libp2p_core::ConnectedPoint;
    use libp2p_swarm::ConnectionHandler as _;
    use libp2p_swarm::behaviour::ConnectionEstablished;
    use licketysync_keys::secret::DeviceSeed;

    use super::*;

    /// The peer of the public test seed `[byte; 32]`, never a real key (TM-6).
    fn peer(byte: u8) -> PeerId {
        identity::peer_id(&Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes(
            [byte; 32],
        )))
        .unwrap()
    }

    #[test]
    fn each_quic_bound_comes_from_limits() {
        // A public test seed, never a real key (TM-6).
        let seed = DeviceSeed::from_bytes([0xa0; 32]);
        let keypair = identity::keypair(&Libp2pIdentity::from_device_seed(&seed)).unwrap();
        // Values that are neither the defaults of `Limits` nor `libp2p-quic`'s.
        let limits = Limits {
            handshake_timeout: Duration::from_millis(1_234),
            idle_timeout: Duration::from_millis(5_678),
            max_streams_per_connection: 7,
            connection_receive_window: 3 << 20,
            stream_receive_window: 1 << 20,
            ..Limits::default()
        };
        assert_eq!(limits.check(), Ok(()));
        let config = quic_config(&keypair, &limits);
        assert_eq!(config.handshake_timeout, Duration::from_millis(1_234));
        assert_eq!(config.max_idle_timeout, 5_678);
        assert_eq!(config.max_concurrent_stream_limit, 7);
        assert_eq!(config.max_connection_data, 3 << 20);
        assert_eq!(config.max_stream_data, 1 << 20);
    }

    /// The defaults QUIC is built with: TM-22's 5 s handshake (residual (b))
    /// and 4 streams a connection (residual (h)).
    #[test]
    fn default_quic_config_has_the_5_s_handshake_and_4_streams() {
        // A public test seed, never a real key (TM-6).
        let seed = DeviceSeed::from_bytes([0xa2; 32]);
        let keypair = identity::keypair(&Libp2pIdentity::from_device_seed(&seed)).unwrap();
        let config = quic_config(&keypair, &Limits::default());
        assert_eq!(config.handshake_timeout, Duration::from_secs(5));
        assert_eq!(config.max_concurrent_stream_limit, 4);
    }

    /// A connection's one handler is the sync behaviour's, so every stream,
    /// inbound or outbound, negotiates within the limits' 5 s. Derived, the
    /// node would run the limit behaviours' handlers beside it, and an
    /// inbound stream would get the longest of their timeouts, `libp2p-swarm`'s
    /// 10 s.
    #[test]
    fn every_stream_negotiates_within_5_s_not_the_10_s_of_libp2p() {
        let mut node = behaviour(&Limits::default());
        let addr = Multiaddr::empty();
        let inbound = node
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(1),
                peer(1),
                &addr,
                &addr,
            )
            .unwrap();
        let mut outbound = node
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(2),
                peer(2),
                &addr,
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .unwrap();
        for handler in [&inbound, &outbound] {
            assert_eq!(*handler.listen_protocol().timeout(), Duration::from_secs(5));
        }
        // An id from the behaviour (it answers at once, the swarm not having
        // told it of the connection), handed to the handler as the swarm would.
        outbound.on_behaviour_event(node.sync().open(peer(2), ConnectionId::new_unchecked(2)));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        match outbound.poll(&mut cx) {
            Poll::Ready(libp2p_swarm::ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol,
            }) => assert_eq!(*protocol.timeout(), Duration::from_secs(5)),
            _ => panic!("no outbound request"),
        }
    }

    /// Tells `node` that `connection` to `peer` is established, as the swarm
    /// does, at `endpoint`.
    fn established(
        node: &mut Behaviour,
        connection: ConnectionId,
        peer: PeerId,
        endpoint: &ConnectedPoint,
    ) {
        node.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: connection,
            endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
    }

    /// What `refused` says, as `libp2p-connection-limits` words it.
    fn exceeded(refused: Option<ConnectionDenied>) -> String {
        refused
            .unwrap()
            .downcast_ref::<libp2p_connection_limits::Exceeded>()
            .unwrap()
            .to_string()
    }

    /// The node's own behaviour, as `build` makes it, holds 32 established
    /// inbound connections and 48 in all, so that strangers who fill every
    /// inbound slot leave 16 for this side's dials (TM-22's residual (i)), and
    /// 48 outbound; each limit is named by its own refusal.
    #[test]
    fn established_connections_stop_at_32_inbound_leaving_16_for_dials_out_and_48_in_all() {
        let addr = Multiaddr::empty();
        let listener = ConnectedPoint::Listener {
            local_addr: addr.clone(),
            send_back_addr: addr.clone(),
        };
        let dialer = ConnectedPoint::Dialer {
            address: addr.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        let inbound = |node: &mut Behaviour, n: u8| {
            let connection = ConnectionId::new_unchecked(n.into());
            let handler =
                node.handle_established_inbound_connection(connection, peer(n), &addr, &addr);
            if handler.is_ok() {
                established(node, connection, peer(n), &listener);
            }
            handler.err()
        };
        let outbound = |node: &mut Behaviour, n: u8| {
            let connection = ConnectionId::new_unchecked(n.into());
            let handler = node.handle_established_outbound_connection(
                connection,
                peer(n),
                &addr,
                Endpoint::Dialer,
                PortUse::Reuse,
            );
            if handler.is_ok() {
                established(node, connection, peer(n), &dialer);
            }
            handler.err()
        };

        let mut node = behaviour(&Limits::default());
        for n in 0..32 {
            assert!(inbound(&mut node, n).is_none(), "inbound {n}");
        }
        assert_eq!(
            exceeded(inbound(&mut node, 32)),
            "connection limit exceeded: at most 32 established incoming connections are allowed"
        );
        for n in 33..49 {
            assert!(outbound(&mut node, n).is_none(), "outbound {n}");
        }
        assert_eq!(
            exceeded(outbound(&mut node, 49)),
            "connection limit exceeded: at most 48 established connections are allowed"
        );

        let mut node = behaviour(&Limits::default());
        for n in 0..48 {
            assert!(outbound(&mut node, n).is_none(), "outbound {n}");
        }
        assert_eq!(
            exceeded(outbound(&mut node, 48)),
            "connection limit exceeded: at most 48 established outgoing connections are allowed"
        );
    }

    /// TM-22's residual (d) on `build`'s own path, from any OS: a node asked
    /// for iOS is refused, for want of a memory limit, before anything is
    /// built. `build` passes `std::env::consts::OS` to `build_on`; on Linux,
    /// macOS and Windows every other test of this crate builds its nodes
    /// through it.
    #[test]
    fn a_node_on_ios_is_refused_for_want_of_a_memory_limit() {
        // A public test seed, never a real key (TM-6).
        let seed = DeviceSeed::from_bytes([0xa1; 32]);
        let identity = Libp2pIdentity::from_device_seed(&seed);
        let refused = build_on("ios", &identity, &Limits::default()).err();
        assert!(matches!(
            refused,
            Some(BuildError::NoMemoryLimitOnThisPlatform)
        ));
        assert_ne!(BuildError::NoMemoryLimitOnThisPlatform.to_string(), "");
    }

    /// The iOS build fix keeps the memory limit everywhere else, its bound
    /// taken from `limits` (`tests/transport.rs` checks that it refuses).
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn memory_limit_off_ios_takes_its_bound_from_limits() {
        let limits = Limits {
            max_process_memory_bytes: 123_456_789,
            ..Limits::default()
        };
        assert_eq!(memory_limit(&limits).max_allowed_bytes(), 123_456_789);
    }
}
