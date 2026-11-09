// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index of one folder (`spec/protocol.md` 4.4 to 4.7): the latest
//! versions of each path, ordered by the version vectors inside their seals
//! at a read or write holder and by the names in their clear fields at a
//! sealed holder; tree deletes and signed cleanups; expiry by the folder's own
//! time; the set digests that reconcile two devices' records; and what it
//! serves to a peer that asks.
//!
//! - [`Index`]: one folder's committed state. It changes only through a
//!   [`Txn`] ([`Index::begin`]), which stages every change of one engine
//!   handler; [`Txn::finish`] gives the change set the engine persists in its
//!   one commit and a [`Pending`] it then commits, or drops, which undoes the
//!   changes exactly, with nothing rebuilt ([`store`]).
//! - Arrival, steps 2 to 9 of 4.4's verification ([`Txn::accept`]): a
//!   duplicate, an obsolete or an expired record is ignored without its
//!   signature being verified (unless a write holder notes it as a stale copy
//!   or forgotten record, which verifies it first); a record more than a year
//!   ahead of the clock is refused; everything else is verified, then held, or
//!   held opaque, or dropped at once beneath a tree delete, dropping what it
//!   replaces.
//! - Writing ([`Txn::write`], [`Change`]): `S` from the path's bases and
//!   their twins (the heads of a base's content concurrent with it and, at
//!   the path, after it in display order, never the first head), the vector
//!   its join pruned to 32, the names, tree deletes with their tombstones
//!   and cleanup, conflict copies made ordinary files, one batch one commit;
//!   and the cleanups of a round's end ([`Txn::end_round`]).
//! - Opening ([`Index::open`]): every stored record and base checked again on
//!   every core (TM-9), held again in its stored order, the high-water mark
//!   checked, a folder whose records lie more than a year ahead of the clock
//!   kept closed ([`OpenReport::opens_at`]).
//! - Serving ([`serve`]) and the views ([`views`]): Since replies, reconcile
//!   replies and `RECORDS` pages lazily from committed state (a page in key
//!   order from the last key sent), pushes, the heads of each path in display
//!   order, the chunks the folder wants, the fingerprint.
//! - Beneath them, private: the set-digest trie and its cache (`trie`); per
//!   device, the applied records by path with their least counters, which
//!   judge a tree delete without a walk, `O(L log n)` a query for paths of
//!   `L` bytes (`bypath`); and the held tree deletes in a trie of path
//!   components, which finds those above a path in `O(L)` work (`dirs`).
//!
//! Every record from a peer is untrusted: nothing is charged to anyone before
//! its signature verifies (TM-9, section 5 "No blame before a signature"),
//! nothing it carries is used as an index or a length, and every table that
//! outlives a connection is bounded by the spec's constants or by the
//! records held (TM-22). Ordering follows the vectors and the names alone,
//! never a clock (TM-40); what a device holds, refuses and shows is a
//! function of the records it holds, in any arrival order, whatever it held
//! and dropped before and whatever its clock within the clock rule (TM-17,
//! TM-41). Randomness comes only through the caller's `RandomFill`, and every
//! clock is a parameter.

mod bypath;
mod dirs;
mod index;
mod open;
pub mod serve;
mod state;
pub mod store;
mod trie;
mod verify;
pub mod views;
mod write;

#[cfg(test)]
mod tests;

pub use index::{Accepted, Arrival, Index, NotNoted, OpenReport, Pending, Txn};
pub use serve::{RecordsReply, SincePlan, SinceReply};
pub use store::{
    BaseSlot, ChangeSet, Commit, MemoryStore, PeerState, Place, Store, StoreError, Stored,
    StoredMeta,
};
pub use views::{
    BaseError, Current, FileContent, Head, PathView, RecordState, RecordView, Wanted, WantedChunk,
};
pub use write::{Change, Put, WriteError, Written};

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-index";
