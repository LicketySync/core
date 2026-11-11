// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every bound the transport sets (TM-2, TM-22), in one place, with the
//! defaults phase 0 chose. Phase 1 tunes the numbers; what is fixed here is
//! that each one exists, is set explicitly rather than left at a library's
//! default, and is checked before a swarm is built.
//!
//! What these bound, and what they do not. TM-22 is the list of what the
//! transports as built leave open: its lettered residuals (a) to (h), each
//! with the phase that closes it, all required before 1.0; the last, (h),
//! is the phase 1 item "QUIC stream memory" (the owner's decision of
//! 2026-11-08). A new one is added there, not here. The bullets below
//! are the ones that bear on these bounds, those of the swarm's QUIC and TCP,
//! each with TM-22's letter where it has one; the WebTransport listener's
//! (feature `webtransport`, off by default) are in TM-22 only.
//!
//! - At most [`Limits::max_established_total`] connections, each holding at
//!   most [`Limits::connection_receive_window`] bytes a peer sent and this
//!   side has not read, on QUIC.
//! - At most [`Limits::max_pending_incoming`] connections in their handshake
//!   as the swarm counts them, each ended by [`Limits::handshake_timeout`].
//!   On TCP a connection one past it is refused at once and costs only its
//!   socket (the TCP flood test). The counter is one for every source and
//!   transport: that many connections that never finish their handshake lock
//!   every inbound peer out for the handshake timeout, renewably (TM-22's
//!   residual (b)).
//! - No new connection while the process's resident memory is above
//!   [`Limits::max_process_memory_bytes`] (`libp2p-memory-connection-limits`,
//!   read at most every 100 ms). A node is built only on an operating system
//!   where that limit exists, [`has_memory_limit`]: Linux, Android, macOS and
//!   Windows. Elsewhere [`crate::node::build`] refuses with
//!   [`BuildError::NoMemoryLimitOnThisPlatform`](crate::node::BuildError::NoMemoryLimitOnThisPlatform),
//!   so that no node there takes a connection without it.
//! - On iOS, therefore, no node at all (TM-22's residual (d)).
//!   `libp2p-memory-connection-limits` 0.6 does not build for iOS (its
//!   sysinfo 0.38 uses libc items that libc 0.2.190 and later keep for
//!   macOS), so `net` is built there without it and refuses to start. The
//!   owner's answer of 2026-11-03 on this gap: required before 1.0, fixed in
//!   phase 4 (an iOS memory check of `net`'s own, or an upstream release on a
//!   sysinfo that builds for iOS), and `net` refuses to start on iOS until
//!   then.
//! - Not bounded by any of these: QUIC Initials (TM-22's residual (a)).
//!   `libp2p-quic` 0.14 accepts every Initial quinn hands it before the
//!   swarm's limits are asked, so each costs a QUIC connection and a TLS
//!   server handshake until it is refused and drained or times out, at
//!   whatever rate an attacker sends (the security review of 2026-11-03
//!   measured 10 000 Initials at about 412 MB, about 41 KB each, and seconds
//!   of CPU). quinn's Retry or its incoming cap would bound this;
//!   `libp2p-quic` exposes neither.
//! - Not bounded either: yamux's connection receive window on TCP (TM-22's
//!   residual (c)), which `libp2p-yamux` 0.48 does not let us set. It starts
//!   at 256 KiB per stream and auto-tunes from the round trip yamux measures
//!   with its pings and the rate this side reads, up to yamux's 1 GiB ceiling,
//!   so a remote that delays its ping answers inflates the estimate and can
//!   grow one connection's window, and what it may send unread, toward that
//!   ceiling.
//! - And not bounded: the memory behind a QUIC connection's unread bytes.
//!   [`Limits::connection_receive_window`] counts bytes, not memory: quinn
//!   keeps each frame's data as a slice of the buffer of the UDP read it came
//!   in, and frees that buffer only when every slice is gone, so many small
//!   frames can keep far more memory alive than their bytes, and the process
//!   memory limit above only refuses new connections. TM-22's residual (h),
//!   the phase 1 item "QUIC stream memory", states the figure, from reading
//!   quinn's code and not measured, and requires it bounded before 1.0.

use core::fmt;
use core::time::Duration;

/// yamux refuses (by panicking) a stream count above its 1 GiB connection
/// window divided by its 256 KiB initial stream window; `libp2p-yamux` does
/// not let the window be raised, so this is the most streams it accepts.
pub const YAMUX_MAX_STREAMS: u32 = 4096;

/// Whether `net` has its process-memory limit on the operating system `os`,
/// named as [`std::env::consts::OS`] names it. [`crate::node::build`] asks
/// this of the OS it runs on and builds no node where the answer is no.
///
/// Yes on Linux, Android, macOS and Windows, the systems besides iOS that the
/// project builds `net` for, where `libp2p-memory-connection-limits` is
/// compiled in and reads the process's resident memory through
/// `memory-stats`. No on iOS, where it is not compiled in (TM-22's residual
/// (d); the owner's answer of 2026-11-03: `net` refuses to start there until
/// the limit exists). No on every other OS too: the project neither builds
/// `net` for nor tests any of them, and on most `memory-stats` reads nothing,
/// so the limit would refuse nothing.
#[must_use]
pub fn has_memory_limit(os: &str) -> bool {
    matches!(os, "linux" | "android" | "macos" | "windows")
}

/// The bounds of one node. Build one with [`Limits::default`] and change what
/// a test or a phase needs; [`Limits::check`] runs before a swarm is built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Inbound connections still in their handshake (TCP: multistream-select,
    /// TLS and yamux; QUIC: its handshake). One past it is refused at once.
    pub max_pending_incoming: u32,
    /// Outbound connections still in their handshake.
    pub max_pending_outgoing: u32,
    /// Established inbound connections.
    pub max_established_incoming: u32,
    /// Established outbound connections.
    pub max_established_outgoing: u32,
    /// Established connections with one peer, both directions.
    pub max_established_per_peer: u32,
    /// Established connections in all.
    pub max_established_total: u32,
    /// No connection is accepted or dialed while the process's resident
    /// memory is above this many bytes. No node is built where this cannot be
    /// enforced, iOS among them ([`has_memory_limit`]; TM-22's residual (d)).
    pub max_process_memory_bytes: usize,
    /// A connection's handshake ends with an error after this long (TCP:
    /// the whole upgrade; QUIC: its handshake, at most the idle timeout).
    pub handshake_timeout: Duration,
    /// A connection with no open stream is closed after this long.
    pub idle_timeout: Duration,
    /// Streams the remote may have open at once on one connection (QUIC's
    /// concurrent bidirectional streams; yamux's stream count). At most
    /// [`YAMUX_MAX_STREAMS`].
    pub max_streams_per_connection: u32,
    /// Inbound streams still negotiating their protocol, per connection.
    pub max_negotiating_inbound_streams: u32,
    /// Streams of `/licketysync/sync/1` the remote may open over one
    /// connection's whole life; later ones are refused in negotiation. The
    /// protocol runs one stream per connection (`protocol.md` 3.1).
    pub max_inbound_sync_streams: u32,
    /// QUIC: unacknowledged bytes the remote may send on one connection.
    pub connection_receive_window: u32,
    /// QUIC: unacknowledged bytes the remote may send on one stream.
    pub stream_receive_window: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pending_incoming: 32,
            max_pending_outgoing: 32,
            max_established_incoming: 128,
            max_established_outgoing: 128,
            max_established_per_peer: 2,
            max_established_total: 128,
            max_process_memory_bytes: 1 << 30,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            max_streams_per_connection: 16,
            max_negotiating_inbound_streams: 8,
            max_inbound_sync_streams: 1,
            connection_receive_window: 4 << 20,
            stream_receive_window: 4 << 20,
        }
    }
}

/// A [`Limits`] that cannot be built: the field and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitsError {
    /// The field at fault.
    pub field: &'static str,
    /// What it must be.
    pub rule: &'static str,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "limit {} {}", self.field, self.rule)
    }
}

impl std::error::Error for LimitsError {}

impl Limits {
    /// Checks the bounds against each other and against what the libraries
    /// accept, so that building a swarm never panics on them.
    ///
    /// # Errors
    ///
    /// [`LimitsError`] naming the first field at fault.
    pub fn check(&self) -> Result<(), LimitsError> {
        let fail = |field, rule| Err(LimitsError { field, rule });
        if self.max_streams_per_connection == 0
            || self.max_streams_per_connection > YAMUX_MAX_STREAMS
        {
            return fail(
                "max_streams_per_connection",
                "must be between 1 and YAMUX_MAX_STREAMS",
            );
        }
        if self.max_negotiating_inbound_streams == 0 {
            return fail("max_negotiating_inbound_streams", "must be at least 1");
        }
        if self.handshake_timeout.is_zero() {
            return fail("handshake_timeout", "must be longer than zero");
        }
        if self.idle_timeout.is_zero() {
            return fail("idle_timeout", "must be longer than zero");
        }
        // QUIC's idle timeout is a u32 of milliseconds; a longer one would be
        // cut short.
        if u32::try_from(self.idle_timeout.as_millis()).is_err() {
            return fail("idle_timeout", "must fit in u32 milliseconds");
        }
        if self.handshake_timeout > self.idle_timeout {
            return fail("handshake_timeout", "must not be longer than idle_timeout");
        }
        if self.stream_receive_window == 0 || self.connection_receive_window == 0 {
            return fail(
                "stream_receive_window",
                "and connection_receive_window must be at least 1",
            );
        }
        if self.stream_receive_window > self.connection_receive_window {
            return fail(
                "stream_receive_window",
                "must not be more than connection_receive_window",
            );
        }
        Ok(())
    }

    /// QUIC's idle timeout in milliseconds, as [`Limits::check`] allows.
    pub(crate) fn idle_timeout_millis(&self) -> u32 {
        u32::try_from(self.idle_timeout.as_millis()).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TM-22's residual (d): no node on iOS until it has a memory limit.
    #[test]
    fn ios_has_no_memory_limit_so_no_node_is_built_there() {
        assert!(!has_memory_limit("ios"));
    }

    #[test]
    fn linux_android_macos_and_windows_have_the_memory_limit() {
        for os in ["linux", "android", "macos", "windows"] {
            assert!(has_memory_limit(os), "{os}");
        }
    }

    /// An OS the project neither builds nor tests is refused, as are the
    /// other Apple systems (whose memory `memory-stats` does not read) and
    /// names not spelled as `std::env::consts::OS` spells them.
    #[test]
    fn every_other_os_has_no_memory_limit() {
        for os in [
            "freebsd", "openbsd", "netbsd", "tvos", "watchos", "visionos", "", "IOS", "Linux",
        ] {
            assert!(!has_memory_limit(os), "{os}");
        }
    }

    #[test]
    fn defaults_pass_their_own_check() {
        assert_eq!(Limits::default().check(), Ok(()));
    }

    /// The defaults as TM-22 and the threat model's 3.10 quote them (32
    /// pending, the 10 s handshake timeout, QUIC's 4 MiB connection window)
    /// and the rest, and yamux's stream ceiling as this module derives it:
    /// changing one changes this test and those texts together.
    #[test]
    fn defaults_are_the_values_the_threat_model_quotes() {
        let quoted = Limits {
            max_pending_incoming: 32,
            max_pending_outgoing: 32,
            max_established_incoming: 128,
            max_established_outgoing: 128,
            max_established_per_peer: 2,
            max_established_total: 128,
            max_process_memory_bytes: 1 << 30,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            max_streams_per_connection: 16,
            max_negotiating_inbound_streams: 8,
            max_inbound_sync_streams: 1,
            connection_receive_window: 4 * 1024 * 1024,
            stream_receive_window: 4 * 1024 * 1024,
        };
        assert_eq!(Limits::default(), quoted);
        // 1 GiB over 256 KiB.
        assert_eq!(YAMUX_MAX_STREAMS, (1 << 30) / (256 << 10));
    }

    /// A change to the defaults and the field its check must name.
    type Case = (fn(&mut Limits), &'static str);

    #[test]
    fn each_rule_names_its_field() {
        let cases: [Case; 9] = [
            (
                |l| l.max_streams_per_connection = 0,
                "max_streams_per_connection",
            ),
            (
                |l| l.max_streams_per_connection = YAMUX_MAX_STREAMS + 1,
                "max_streams_per_connection",
            ),
            (
                |l| l.max_negotiating_inbound_streams = 0,
                "max_negotiating_inbound_streams",
            ),
            (
                |l| l.handshake_timeout = Duration::ZERO,
                "handshake_timeout",
            ),
            (|l| l.idle_timeout = Duration::ZERO, "idle_timeout"),
            (
                |l| l.idle_timeout = Duration::from_secs(u64::MAX),
                "idle_timeout",
            ),
            (
                |l| l.handshake_timeout = l.idle_timeout * 2,
                "handshake_timeout",
            ),
            (
                |l| l.stream_receive_window = l.connection_receive_window + 1,
                "stream_receive_window",
            ),
            (|l| l.connection_receive_window = 0, "stream_receive_window"),
        ];
        for (change, field) in cases {
            let mut limits = Limits::default();
            change(&mut limits);
            assert_eq!(limits.check().map_err(|e| e.field), Err(field));
        }
    }
}
