// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index of one folder (`spec/protocol.md` 4.4 and 4.5): the signed
//! records a device holds, what each means for its path, and what it serves
//! to a peer that asks.
//!
//! - [`Index`]: records keyed by `(device_id, seq)` and by record hash, the
//!   protocol crate's [`Held`](licketysync_protocol::record::Held) view of
//!   them, each writer's cursor and cached digests, step 6 (applied, opaque
//!   or unopened), waiting records, the heads of every path, and this
//!   device's own next record ([`Index::draft`], [`Index::draft_rename`],
//!   [`Index::write`]).
//! - [`heads`]: one path's heads in display order, the version at the path,
//!   deletion and conflict copies; what a write names besides the heads (the
//!   versions a rename moved away) is the index's.
//! - [`serve`]: a [`Reply`] to one request, page by page, by the serving
//!   cases (a) to (d).
//! - [`store`]: what is persisted (the records, as received) behind the
//!   [`Store`] trait, one atomic append per record, and the in-memory
//!   [`MemoryStore`] of phase 0; the store is trusted to keep records, not
//!   for their authenticity, which [`Index::open`] checks again
//!   ([`OpenReport`]).
//!
//! What stays with the protocol crate: parsing (step 1), the order of steps 2
//! to 5 ([`judge`](licketysync_protocol::record::judge)), opening a seal, the
//! reference digests, the round split and the pager. What stays with the
//! engine: the connection, marks and rounds, every issue and log line an
//! [`Outcome`] names, conflict copies on disk, chunks.
//!
//! Every record from a peer is untrusted: it is stored only after its
//! signature verified under the folder key (TM-9), nothing it carries is used
//! as an index or a length, and every structure grows only with records
//! actually held (or, when the index opens, set aside from the store). The
//! store, this device's own state, is not trusted for authenticity: when the
//! index opens, every stored record passes step 1 and its signature again,
//! on every core, and one that fails is dropped and reported, never applied
//! or served (TM-9, the owner's decision of 2026-10-25; [`store`]). Ordering
//! decisions follow `supersedes` and canonical order alone, never a clock
//! (TM-40); the same set of held records gives the same cursors, digests,
//! waiting records, heads and versions a write names in any arrival order and
//! after a restart (TM-17, TM-41).

pub mod heads;
mod index;
pub mod serve;
pub mod store;
mod verify;

#[cfg(test)]
mod tests;

pub use heads::{Heads, Version};
pub use index::{AcceptError, Index, Kept, OpenError, OpenReport, Outcome, WriteError};
pub use serve::{Reply, ReplyPage};
pub use store::{MemoryStore, Store, StoreError};

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-index";
