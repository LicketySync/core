// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Networking on rust-libp2p: QUIC and TCP, each with TLS 1.3 on `aws-lc-rs`
//! offering X25519MLKEM768 first, the device's libp2p identity, connection
//! limits, and the one byte stream of `/licketysync/sync/1`.
//!
//! Status: phase 0's transport spike (spike A of the phase 0 spikes). The
//! plan ("Lickety-Sync: Project Plan") is the specification; `spec/suites.md`
//! section 2.6 fixes the transport suite and section 3.1 the crates, and
//! `spec/threat-model.md` the rules this crate enforces (TM-1, TM-2, TM-6,
//! TM-22, TM-23, TM-31, TM-32). What is here:
//!
//! - [`identity`]: the libp2p keypair and peer ID of a device, from the keys
//!   crate's [`Libp2pIdentity`](licketysync_keys::device::Libp2pIdentity).
//! - [`provider`]: the process-default rustls provider, `aws-lc-rs` with
//!   X25519MLKEM768 first, installed before any connection exists.
//! - [`limits`]: every bound on connections, streams and buffers, with the
//!   defaults.
//! - [`node`]: the swarm: QUIC and TCP, each with exactly one security
//!   protocol (TLS 1.3, `libp2p-tls`), yamux on TCP, the limit behaviours and
//!   [`sync`].
//! - [`sync`]: the behaviour that opens and accepts streams of
//!   [`PROTOCOL_ID`], at most a fixed number per connection.
//! - [`pieces`]: reading such a stream as the engine's runtime contract asks:
//!   bytes in order, at most [`pieces::MAX_PIECE`] at a time, and the end
//!   reported.
//! - `webtransport` (feature `webtransport`, off by default; spike B):
//!   a device-side WebTransport listener that a browser dials with only an
//!   address and a certificate hash, Noise inside it.
//!
//! The engine is not wired to the network and no daemon runs: that is
//! phase 1. Nothing here logs; libp2p's own crates log through `tracing`,
//! and the daemon that installs a subscriber redacts addresses (TM-6).

// The dev-dependencies the integration tests and the example use, which the
// unit tests do not.
#[cfg(test)]
use {hex as _, memory_stats as _, serde_json as _};
#[cfg(all(test, not(feature = "webtransport")))]
use {multistream_select as _, tokio as _};

// idna_adapter is a dependency only to hold idna on its ASCII-only back end
// (the owner's exception of 2026-11-03; Cargo.toml says why).
use idna_adapter as _;

pub mod identity;
pub mod limits;
pub mod node;
pub mod pieces;
pub mod provider;
pub mod sync;
#[cfg(feature = "webtransport")]
pub mod webtransport;

/// The one protocol a stream carries: `/licketysync/sync/1`, the protocol
/// crate's identifier (imported, not defined here).
pub use licketysync_protocol::PROTOCOL_ID;
