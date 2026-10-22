// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The wire protocol of `/licketysync/sync/1` (`spec/protocol.md`) for the
//! shared-key model: what crosses a connection, how every byte of it is
//! judged, and the per-connection state machine. Sans-IO: time, the
//! transport's unsent bytes and randomness come from the caller, and nothing
//! here performs I/O or reads a clock.
//!
//! # Shape
//!
//! - [`frame`]: length, type and body, and the streaming [`FrameDecoder`]
//!   that checks each length before allocating (section 2, TM-2).
//! - [`wire`], [`messages`] and [`parse`]: the strict proto3 reader every
//!   body goes through, the prost structs mirroring section 4's `.proto`
//!   text (canonical encoding), and a bounded [`Parse`] for every message.
//!   Embedded signed records travel as bytes and are read only through the
//!   keys crate's `SignedRecord::from_bytes`.
//! - [`hello`] and [`proof`]: the Hello checks, roles, the transcript hash,
//!   and the one folder proof for every tier (3.2 to 3.5, TM-30, TM-32).
//! - [`record`]: an index record's step 1 against the open folder, steps 2 to
//!   5 as [`record::judge`] over the index's [`record::Held`], step 6 (the
//!   sealed metadata and its grammar), the writer's [`record::Draft`] and the
//!   reference writer digests (4.4).
//! - [`exchange`]: typed cursors, range and listed scopes, the round split,
//!   the serving cases (a) to (d) and the [`exchange::Pager`] (4.5).
//! - [`connection`]: one [`connection::Connection`] per transport
//!   connection: the handshake, open folders, rounds, marks, the round owed,
//!   pages and pushes, the deadlines, chunks and their backoff and passes,
//!   Status (sections 3 to 5).
//! - [`rules`]: the section 5 table as [`Cause`] to [`Outcome`] (TM-10).
//! - [`limits`] and [`features`]: every constant, defined here once, and the
//!   feature grammar.
//!
//! What the index and the engine keep: records, cursors and cached digests,
//! heads and waiting records, the conflict copies, which peer to ask for a
//! chunk, and the issues every outcome raises.
//!
//! Every byte from a peer is untrusted: lengths are checked before anything is
//! allocated, every collection a peer can grow is bounded by [`limits`], no
//! decoder panics, and every decoder has a fuzz target under `fuzz/` (TM-3,
//! TM-23). All cryptography is `licketysync-keys`'.

pub mod connection;
pub mod exchange;
pub mod features;
pub mod frame;
pub mod hello;
pub mod limits;
pub mod messages;
pub mod parse;
pub mod proof;
pub mod record;
pub mod rules;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod vectors;
pub mod wire;

pub use frame::{Frame, FrameDecoder, FrameError, FrameKind, MessageType};
pub use messages::{ChunkStatus, CloseReason, Message, ProofStatus};
pub use parse::Parse;
pub use rules::{Cause, Keep, Outcome, Report};
pub use wire::WireError;

/// The protocol identifier libp2p negotiates and the transcript binds
/// (`protocol.md` section 1).
pub const PROTOCOL_ID: &str = "/licketysync/sync/1";

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-protocol";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-protocol");
        assert_eq!(super::PROTOCOL_ID, "/licketysync/sync/1");
    }
}
