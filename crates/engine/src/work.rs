// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What one handler call decided and has yet to do: the commit discipline of
//! `protocol.md` 4.5, "Durability before transmission".
//!
//! Every handler runs in three phases:
//!
//! - **A, decide.** Receive bytes and react to the events: queue the index
//!   work (pages of records, local writes) for B (`crate::sync`), judge
//!   chunks and stage their blobs, and queue (do not send) everything that
//!   carries a record or a chunk: pushes, reply pages, `CHUNK_OK` answers,
//!   `chunk_stored` notices. The connection's own frames, which carry no
//!   record, go out as their outputs arrive.
//! - **B, commit.** One transaction per folder with index work, its change
//!   set staged with the chunk blobs, then one `Storage::commit` if anything
//!   was staged; the transactions are committed after it, or dropped if it
//!   failed, which undoes them exactly (`crate::sync`).
//! - **C, send.** Only after B succeeded: hand the judgements to the
//!   connections, push, send requests and Status, serve pages and chunks,
//!   tell every connection of the chunks stored, drive the chunk passes. When
//!   a put or the commit failed, the engine rolled back and paused the
//!   folders the handler changed, and C sends nothing that depended on this
//!   handler's records or chunks: every record judged held is reported
//!   skipped.
//!
//! A handler commits at most once: what phase C brings that changes an index
//! (a round's end, a cursor) waits for the next handler's commit, made at
//! once (`Purpose::Deferred`). The blobs found changed at rest
//! (`crate::chunks`) wait in the engine's pending set, and their deletions,
//! with their markers, ride the next commit a handler makes anyway, staged
//! just before it (`Engine::commit`); a crash before then leaves the blob,
//! which the check of its hash at the next refresh finds again.
//!
//! The lists are sets where a repeat means nothing more (a connection to
//! pump, a folder whose passes to drive), so a handler does each at most once
//! per round of the send loop.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use licketysync_keys::FolderId;
use licketysync_protocol::connection::Event;

use crate::runtime::{PeerId, StorageError};
use crate::sync::SyncWork;

/// One handler's work.
#[derive(Debug, Default)]
pub(crate) struct Work {
    /// Events not yet reacted to, with their connection.
    pub(crate) events: VecDeque<(PeerId, Event)>,
    /// Something was put.
    pub(crate) staged: bool,
    /// A put failed: nothing more is staged, and B rolls back.
    pub(crate) failed: Option<StorageError>,
    /// The folders that staged a chunk blob in A.
    pub(crate) touched: BTreeSet<FolderId>,
    /// B succeeded (or had nothing to commit).
    pub(crate) committed: bool,
    /// The index work for B and what C sends of it.
    pub(crate) sync: SyncWork,
    /// The handler is a local write.
    pub(crate) wrote: bool,
    /// Chunks newly stored per folder: one `chunk_stored` each, on every
    /// connection where the folder is open.
    pub(crate) chunks_stored: BTreeMap<FolderId, u64>,
    /// Connections with replies or chunk answers to send.
    pub(crate) pump: BTreeSet<PeerId>,
    /// Connections whose Status is due.
    pub(crate) status: BTreeSet<PeerId>,
    /// Folders whose chunk passes to drive on every connection.
    pub(crate) passes: BTreeSet<FolderId>,
    /// Folders some of whose records this handler did not judge or rolled
    /// back: each is paused or owed a round (`crate::sync`).
    pub(crate) skipped: BTreeSet<FolderId>,
}

impl Work {
    /// `folder` staged a chunk blob.
    pub(crate) fn staged(&mut self, folder: FolderId) {
        self.staged = true;
        self.touched.insert(folder);
    }

    /// Counts one chunk newly stored for `folder`.
    pub(crate) fn chunk_stored(&mut self, folder: FolderId) {
        let n = self.chunks_stored.entry(folder).or_insert(0);
        *n = n.saturating_add(1);
    }
}

/// Takes the first element of a set.
pub(crate) fn pop<T: Ord + Copy>(set: &mut BTreeSet<T>) -> Option<T> {
    set.pop_first()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names,
    clippy::field_reassign_with_default,
    clippy::map_unwrap_or,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn staging_marks_the_folder_touched_and_chunks_are_counted() {
        let mut w = Work::default();
        let f = FolderId([1; 32]);
        w.staged(f);
        assert!(w.staged && w.touched.contains(&f));
        w.chunk_stored(f);
        w.chunk_stored(f);
        assert_eq!(w.chunks_stored.get(&f), Some(&2));
        let mut s: BTreeSet<u8> = [3, 1].into_iter().collect();
        assert_eq!(pop(&mut s), Some(1));
    }
}
