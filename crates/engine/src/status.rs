// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Status this side sends (`protocol.md` 4.5): one entry per folder open
//! on the connection, with the records it holds, the chunk bytes it still
//! needs, whether it is paused, `free_disk_bytes` 0 (decision: phase 0 has
//! no disk to measure), and its extra versions (at a sealed holder its
//! stale copies and the folder's real conflicts together, at a key holder
//! the extra heads of its conflicts, so that its person can see a sealed
//! peer's growth). The connection fills in `chunks_stored` and the
//! device name. A Status the send queue cannot take is skipped, never queued
//! behind other frames: the next is due within `STATUS_INTERVAL`.

use licketysync_protocol::connection::SendError;
use licketysync_protocol::messages::FolderStatus;

use crate::engine::Engine;
use crate::runtime::{Context, PeerId};
use crate::work::Work;

impl Engine {
    /// The entries of a Status for every folder open on the connection.
    pub(crate) fn status_entries(&self, peer: PeerId) -> Vec<FolderStatus> {
        let Some(c) = self.conns.get(&peer) else {
            return Vec::new();
        };
        c.open
            .iter()
            .filter_map(|id| self.folders.get(id))
            .map(|f| FolderStatus {
                folder_id: f.id.0.to_vec(),
                index_records: f.index.len() as u64,
                bytes_needed: f.book.bytes_needed(),
                paused: f.held_paused(),
                free_disk_bytes: 0,
                chunks_stored: 0,
                extra_versions: f.index.extra_versions(),
            })
            .collect()
    }

    /// Phase C: the Status due on the connection.
    pub(crate) fn send_status(&mut self, cx: &mut dyn Context, work: &mut Work, peer: PeerId) {
        let entries = self.status_entries(peer);
        match self.with_conn(cx, peer, |c, t| c.send_status(t, &entries)) {
            Some(Ok(out)) => self.apply(cx, work, peer, out),
            Some(Err(
                SendError::WouldBlock { .. } | SendError::FolderNotOpen | SendError::Closed,
            ))
            | None => {}
            Some(Err(_)) => self.counters.bug(),
        }
    }
}
