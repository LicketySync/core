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

use futures::future::Either;
use libp2p_core::muxing::StreamMuxerBox;
use libp2p_core::transport::{Boxed, Transport as _};
use libp2p_core::upgrade::Version;
use libp2p_identity::{DecodingError, PeerId};
use licketysync_keys::device::Libp2pIdentity;

use crate::limits::{has_memory_limit, Limits, LimitsError};
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

pub use behaviour::Behaviour;

mod behaviour {
    // The derive converts each behaviour's event into `Event`; the two limit
    // behaviours' events are `Infallible`, so those conversions are
    // unreachable by construction, which rustc's nightly (1.101) reports
    // inside the macro's output.
    #![allow(
        unreachable_code,
        reason = "the derive's conversions of Infallible events, unreachable by construction"
    )]

    use libp2p_swarm::NetworkBehaviour;

    use super::Event;
    use crate::sync;

    /// The behaviours of a node, in the order the swarm consults them: the
    /// connection limits, the memory limit (none on iOS yet, TM-22's
    /// residual (d)), then the sync streams.
    #[derive(NetworkBehaviour)]
    #[behaviour(prelude = "libp2p_swarm::derive_prelude", to_swarm = "Event")]
    pub struct Behaviour {
        pub(super) connection_limits: libp2p_connection_limits::Behaviour,
        pub(super) memory_limit: super::MemoryLimit,
        pub(super) sync: sync::Behaviour,
    }
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

/// What a node's behaviours report.
#[derive(Debug)]
pub enum Event {
    /// The sync behaviour's event.
    Sync(sync::Event),
}

impl From<sync::Event> for Event {
    fn from(event: sync::Event) -> Self {
        Self::Sync(event)
    }
}

impl From<Infallible> for Event {
    fn from(never: Infallible) -> Self {
        match never {}
    }
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
    let behaviour = Behaviour {
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
        sync: sync::Behaviour::new(limits.max_inbound_sync_streams),
    };
    let config = libp2p_swarm::Config::with_tokio_executor()
        .with_idle_connection_timeout(limits.idle_timeout)
        .with_max_negotiating_inbound_streams(to_usize(limits.max_negotiating_inbound_streams));
    Ok(libp2p_swarm::Swarm::new(
        transport, behaviour, peer_id, config,
    ))
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
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use core::time::Duration;

    use licketysync_keys::secret::DeviceSeed;

    use super::*;

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
