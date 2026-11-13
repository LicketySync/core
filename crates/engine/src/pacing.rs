// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The engine's send budget (`runtime.rs`, `MAX_SEND_QUEUE`; `protocol.md`
//! 3.1).
//!
//! The protocol paces against `MAX_SEND_QUEUE` (128 MiB), where the runtime
//! cuts a connection. The engine paces what a peer can make it send in
//! volume, reply pages and `CHUNK_OK` frames, to a budget of its own far
//! below that: it hands over the next such frame only while
//! `Transport::unsent` plus the frame stays within the budget, and an empty
//! queue always takes one frame, however large. Over budget it arms the
//! connection's send poll and reads `unsent` again when it fires, since
//! nothing tells it when the queue drains (gap G9: `Connection::has_room` is
//! relative to `MAX_SEND_QUEUE`, so the budget is the engine's own check).
//! Pushes and the connection's own small frames are not budgeted: a push the
//! queue cannot take is the protocol's to drop (`protocol.md` 4.5, "Pushes";
//! decision).

use licketysync_protocol::exchange::PAGE_FIXED_OVERHEAD;
use licketysync_protocol::frame::{LENGTH_LEN, TYPE_LEN};
use licketysync_protocol::messages::IndexRecords;

use crate::engine::Engine;
use crate::issues::bump;
use crate::runtime::{Context, PeerId};
use crate::timers::Purpose;

/// A frame's length and type fields.
const FRAME_HEADER: usize = LENGTH_LEN + TYPE_LEN;

/// What a record adds to a page beyond its own bytes, at most: its field tag
/// (1) and its length varint (at most 5 for a record within
/// `MAX_INDEX_RECORD_BYTES`), rounded up.
const PER_RECORD: usize = 11;

/// What a `ChunkReply` frame adds to its data, at most: the frame header, the
/// folder ID and the hash (tag, length and 32 bytes each), the status (tag
/// and value), and the data's tag and length varint, rounded up.
pub(crate) const CHUNK_REPLY_OVERHEAD: usize = 96;

/// An upper bound on the encoded frame of `page`.
pub(crate) fn page_estimate(page: &IndexRecords) -> usize {
    page.records
        .iter()
        .fold(FRAME_HEADER + PAGE_FIXED_OVERHEAD, |n, r| {
            n.saturating_add(r.len()).saturating_add(PER_RECORD)
        })
}

/// An upper bound on the `CHUNK_OK` frame of a blob of `len` bytes.
pub(crate) const fn chunk_estimate(len: usize) -> usize {
    len.saturating_add(CHUNK_REPLY_OVERHEAD)
}

/// Whether a frame of `len` bytes may be handed over with `unsent` bytes
/// already queued: an empty queue always takes one frame; otherwise only
/// while the total stays within `budget`.
pub(crate) const fn within_budget(unsent: usize, len: usize, budget: usize) -> bool {
    unsent == 0 || unsent.saturating_add(len) <= budget
}

impl Engine {
    /// A reply page or a `CHUNK_OK` waits for the budget: counted, and the
    /// connection's send poll armed.
    pub(crate) fn defer(&mut self, cx: &mut dyn Context, peer: PeerId) {
        bump(&mut self.counters.deferrals);
        let at = cx.now().saturating_add(self.settings.send_poll);
        if !self.timers.arm_once(cx, Purpose::SendPoll(peer), at) {
            self.counters.bug();
        }
    }
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
    use licketysync_keys::FolderId;
    use licketysync_protocol::messages::Message;

    #[test]
    fn an_empty_queue_takes_one_frame_and_a_busy_one_waits_past_the_budget() {
        assert!(
            within_budget(0, usize::MAX, 10),
            "an empty queue takes any frame"
        );
        assert!(within_budget(4, 6, 10));
        assert!(!within_budget(4, 7, 10));
        assert!(!within_budget(usize::MAX, 1, usize::MAX - 1), "saturates");
    }

    #[test]
    fn the_page_estimate_bounds_the_encoded_frame() {
        let folder = FolderId([7; 32]);
        for n in [0usize, 1, 5, 64] {
            let records: Vec<Vec<u8>> = (0..n).map(|i| vec![0x5a; 100 + i * 37]).collect();
            let page = IndexRecords {
                folder_id: folder.0.to_vec(),
                records,
                more: n > 3,
                request_id: u32::MAX,
                epoch: u64::MAX,
                through: u64::MAX,
                reset: true,
            };
            let frame = Message::IndexRecords(page.clone())
                .to_frame()
                .unwrap()
                .encode();
            assert!(page_estimate(&page) >= frame.len(), "{n} records");
        }
        assert_eq!(chunk_estimate(10), 106);
    }

    #[test]
    fn the_page_estimate_is_no_looser_than_its_rounding() {
        // An estimate above the frame defers a page the budget had room for
        // (the module documentation: the budget holds back a frame only when
        // the frame would pass it). At the widest fields a page may carry
        // (`PAGE_FIXED_OVERHEAD`), the estimate passes the encoded frame by
        // the frame's type, counted both in the frame header and in the
        // protocol's page overhead, and by what each record's tag and length
        // varint (at least 2 bytes) leave of `PER_RECORD`.
        use licketysync_protocol::limits::MAX_LOCAL_SEQ;
        let folder = FolderId([7; 32]);
        for n in [0usize, 1, 5, 64] {
            let records: Vec<Vec<u8>> = (0..n).map(|i| vec![0x5a; 100 + i * 37]).collect();
            let page = IndexRecords {
                folder_id: folder.0.to_vec(),
                records,
                more: true,
                request_id: u32::MAX,
                epoch: u64::MAX,
                through: MAX_LOCAL_SEQ,
                reset: true,
            };
            let frame = Message::IndexRecords(page.clone())
                .to_frame()
                .unwrap()
                .encode();
            let slack = page_estimate(&page) - frame.len();
            assert!(
                slack <= TYPE_LEN + n * (PER_RECORD - 2),
                "{n} records: {slack} bytes over"
            );
        }
    }

    #[test]
    fn the_chunk_estimate_bounds_the_encoded_frame() {
        use licketysync_protocol::messages::ChunkReply;
        for len in [1usize, 300, 70_000, 4_325_416] {
            let reply = Message::ChunkReply(ChunkReply {
                folder_id: vec![1; 32],
                cipher_hash: vec![2; 32],
                status: 1,
                data: vec![3; len],
            });
            let frame = reply.to_frame().unwrap().encode();
            assert!(chunk_estimate(len) >= frame.len(), "{len}");
        }
    }
}
