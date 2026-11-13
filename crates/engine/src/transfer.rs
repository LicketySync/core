// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Chunks on the wire as the engine drives them (`protocol.md` 4.6):
//! receiving one and judging it per record ([`crate::chunks`]), the passes
//! that ask for what a folder lacks, serving the peer's requests under the
//! send budget, and telling every connection of each chunk stored.
//!
//! - **Passes** run per connection and folder, in ascending `cipher_hash`
//!   order from the connection's position, skipping a hash already asked of
//!   another connection until its patience runs out (`crate::inflight`), and
//!   end (`pass_done`) when no lacking hash lies above the position; the
//!   connection keeps the backoff, the waits after a `CHUNK_NOT_FOUND` and
//!   their triggers. Any peer with the folder open may be asked for any hash
//!   (ruling S-3). A paused folder asks for nothing. A chunk that arrives for
//!   a hash stored already (a slow connection's answer) is dropped and
//!   counted.
//! - **Serving.** A request is answered only as its turn comes: the blob is
//!   read from storage then, and sent when this device holds it for the
//!   folder (stored, and named by a held record), `CHUNK_NOT_FOUND`
//!   otherwise. A blob that no longer hashes to its name changed in this
//!   device's storage (TM-10): it is answered not found, forgotten as stored
//!   so that it lacks and is fetched again, and an issue raised; no record
//!   is blamed, and its deletion, with its marker, rides the next commit (the
//!   `work` module). A blob that cannot be read is answered not found,
//!   forgotten and counted, and neither deleted nor named in an issue.
//! - **`chunk_stored`** goes, once per chunk newly stored, to every
//!   connection where the folder is open, after the commit: it feeds each
//!   peer's trigger for its next pass. No chunk is freed in phase 0.

use licketysync_keys::{CipherHash, FolderId};
use licketysync_protocol::connection::{ChunkAnswer, SendError};
use licketysync_protocol::limits::{MAX_REQUESTS_IN_FLIGHT, MAX_STORED_LEN};
use licketysync_protocol::Cause;

use crate::chunks::Finding;
use crate::engine::{tick, Engine};
use crate::inflight::patience;
use crate::issues::{bump, Issue, IssueKind, Subject};
use crate::pacing::{chunk_estimate, within_budget};
use crate::runtime::{Context, PeerId};
use crate::store::{chunk_key, stage_chunk};
use crate::work::Work;

/// The most steps one pass drive takes on one connection: each step asks for
/// a hash (at most the peer's in-flight limit) or ends a pass.
const DRIVE_STEPS: usize = 2 * MAX_REQUESTS_IN_FLIGHT as usize + 4;

impl Engine {
    /// Brings a folder's chunk state up to date if its index changed, and
    /// raises what judging the stored blobs found.
    ///
    /// This recomputes the folder's whole chunk state from the index (every
    /// wanted record), and a chunk stored marks it changed, so each chunk
    /// received costs a pass over the wanted records (security review #8; no
    /// change asked for in phase 0).
    pub(crate) fn fresh(&mut self, cx: &mut dyn Context, work: &mut Work, folder: FolderId) {
        let Some(f) = self.folders.get_mut(&folder) else {
            return;
        };
        if !f.book.dirty {
            return;
        }
        let wanted = f.index.wanted();
        // What a held record names: every held record with chunks is
        // wanted, so the union of what they name (4.6, "holds a chunk").
        let named = wanted
            .iter()
            .flat_map(|w| w.chunks.iter().map(|c| c.hash))
            .collect();
        let (findings, grew) =
            f.book
                .refresh(&f.id, wanted, named, f.chunk_keys.as_ref(), cx.storage());
        if grew {
            work.passes.insert(folder);
        }
        self.raise_findings(work, folder, &findings);
    }

    /// After phase B: every folder's chunk state up to date.
    pub(crate) fn refresh_chunks(&mut self, cx: &mut dyn Context, work: &mut Work) {
        let ids: Vec<FolderId> = self.folders.keys().copied().collect();
        for folder in ids {
            self.fresh(cx, work, folder);
        }
    }

    fn raise_findings(&mut self, work: &mut Work, folder: FolderId, findings: &[Finding]) {
        for finding in findings {
            let (kind, record) = match finding {
                Finding::Corrupt(r) => (IssueKind::ChunkCorrupt, *r),
                Finding::SizeMismatch(r) => (IssueKind::SizeMismatch, *r),
                Finding::Changed(hash) => {
                    self.changed_at_rest(work, folder, *hash);
                    continue;
                }
                Finding::Unread(_) => {
                    bump(&mut self.counters.read_errors);
                    work.passes.insert(folder);
                    continue;
                }
            };
            self.counters.log(Cause::WriterFault);
            self.issues.raise(Issue {
                folder: Some(folder),
                kind,
                subject: Subject::Record(record),
            });
        }
    }

    /// A stored blob changed at rest (TM-10): no longer stored, so it lacks
    /// and is fetched again; its deletion, with its marker, rides the next
    /// commit (the `work` module); an issue naming the chunk, never a record.
    fn changed_at_rest(&mut self, work: &mut Work, folder: FolderId, hash: CipherHash) {
        if let Some(f) = self.folders.get_mut(&folder) {
            f.book.forget(&hash);
        }
        work.passes.insert(folder);
        self.forget.insert((folder, hash));
        self.issues.raise(Issue {
            folder: Some(folder),
            kind: IssueKind::LocalChunkCorrupt,
            subject: Subject::Chunk(hash),
        });
    }

    /// A stored blob could not be read: forgotten as stored, so that it
    /// lacks and is fetched again, which overwrites it, and read again on
    /// the free tick ([`Engine::reread_blobs`]).
    fn blob_unread(&mut self, work: &mut Work, folder: FolderId, hash: CipherHash) {
        if let Some(f) = self.folders.get_mut(&folder) {
            f.book.mark_unread(hash);
        }
        work.passes.insert(folder);
    }

    /// The free tick: every blob that could not be read is read again,
    /// hash-checked; one that reads is stored again, announced like a chunk
    /// stored (`chunk_stored`, so that peers' passes ask again), and served;
    /// one that is gone or changed is changed at rest (`LocalChunkCorrupt`,
    /// its blob and marker deleted at the next commit, fetched again).
    pub(crate) fn reread_blobs(&mut self, cx: &mut dyn Context, work: &mut Work) {
        let mut changed = Vec::new();
        for (id, f) in &mut self.folders {
            if !f.book.has_unread() {
                continue;
            }
            let (again, gone) = f.book.reread(id, cx.storage());
            for _ in again {
                work.chunk_stored(*id);
            }
            changed.extend(gone.into_iter().map(|h| (*id, h)));
            work.passes.insert(*id);
        }
        for (folder, hash) in changed {
            self.changed_at_rest(work, folder, hash);
        }
    }

    /// Phase A for a chunk whose ciphertext hash the connection checked:
    /// judged per record, stored when one record is satisfied; dropped and
    /// counted when the hash is stored already.
    pub(crate) fn on_chunk(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
        peer: PeerId,
        hash: CipherHash,
        data: &[u8],
    ) {
        self.in_flight.answered(folder, &hash, peer);
        work.passes.insert(folder);
        let accepting = self
            .folders
            .get(&folder)
            .is_some_and(crate::folder::Folder::accepting);
        if !accepting || work.failed.is_some() {
            // It stays lacking and is fetched again once the pause ends.
            self.counters.skipped_while_paused =
                self.counters.skipped_while_paused.saturating_add(1);
            return;
        }
        self.fresh(cx, work, folder);
        let Some(f) = self.folders.get_mut(&folder) else {
            return;
        };
        if f.book.is_stored(&hash) {
            // Another connection's answer came first (the chunk patience).
            bump(&mut self.counters.late_chunks);
            return;
        }
        let (satisfied, findings) = f.book.judge(hash, data, f.chunk_keys.as_ref());
        if satisfied {
            work.staged(folder);
            match stage_chunk(cx.storage(), &folder, &hash, data) {
                Ok(()) => {
                    f.book.mark_stored(hash);
                    work.chunk_stored(folder);
                }
                // The chunk is dropped; it stays lacking.
                Err(e) => work.failed = Some(e),
            }
        }
        self.raise_findings(work, folder, &findings);
    }

    /// `CHUNK_NOT_FOUND` or `CHUNK_BUSY`: an ordinary answer (section 5).
    /// The connection keeps the pass state and the backoff; the engine
    /// counts it and asks the other connections.
    pub(crate) fn chunk_refused(
        &mut self,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        hash: CipherHash,
        cause: Cause,
    ) {
        self.in_flight.refused(folder, &hash, peer);
        self.counters.log(cause);
        work.passes.insert(folder);
    }

    /// Phase C: sends what waits on the connection (reply pages, then chunk
    /// answers) while the budget and the queue take it.
    pub(crate) fn pump(&mut self, cx: &mut dyn Context, work: &mut Work, peer: PeerId) {
        loop {
            let Some(c) = self.conns.get(&peer) else {
                return;
            };
            if !c.reacts() {
                return;
            }
            let sent = if let Some(folder) = c.sync.serving() {
                self.serve_page(cx, work, peer, folder)
            } else if let Some(&(folder, hash)) = c.chunk_requests.front() {
                self.serve_chunk(cx, work, peer, folder, hash)
            } else {
                return;
            };
            if !sent {
                return;
            }
        }
    }

    /// Answers the request at the front of the connection's queue, if the
    /// budget and the queue have room for it. Whether it was answered.
    fn serve_chunk(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        hash: CipherHash,
    ) -> bool {
        let unsent = cx.unsent(peer);
        let budget = self.settings.send_budget;
        // An upper bound on the blob: the largest stored length a wanted
        // record names, or the largest stored chunk there is.
        let held = self.folders.get(&folder).and_then(|f| {
            f.book.holds(&hash).then(|| {
                f.book
                    .stored_len(&hash)
                    .map_or(MAX_STORED_LEN, |n| n as usize)
            })
        });
        let Some(len) = held else {
            return self.answer_not_found(cx, work, peer, folder, hash);
        };
        let estimate = chunk_estimate(len);
        if !within_budget(unsent, estimate, budget) {
            self.defer(cx, peer);
            return false;
        }
        let t = tick(cx, peer);
        let Some(c) = self.conns.get_mut(&peer) else {
            return false;
        };
        if !c.protocol.has_room(t, estimate) {
            // The protocol encodes the whole frame before its own room check:
            // wait for room first.
            let out = c.protocol.want_room(t, estimate);
            self.apply(cx, work, peer, out);
            return false;
        }
        let blob = match cx.storage().get(&chunk_key(&folder, &hash)) {
            Ok(Some(blob)) => blob,
            Ok(None) => return self.lost_blob(cx, work, peer, folder, hash),
            // A read error is no sign the blob changed: forgotten and fetched
            // again, which overwrites it; nothing deleted, no issue.
            Err(_) => {
                bump(&mut self.counters.read_errors);
                self.blob_unread(work, folder, hash);
                return self.answer_not_found(cx, work, peer, folder, hash);
            }
        };
        let t = tick(cx, peer);
        let Some(c) = self.conns.get_mut(&peer) else {
            return false;
        };
        match c
            .protocol
            .reply_chunk(t, folder, hash, ChunkAnswer::Ok(&blob))
        {
            Ok(out) => {
                c.chunk_requests.pop_front();
                self.apply(cx, work, peer, out);
                true
            }
            Err(SendError::WouldBlock { len }) => {
                let out = c.protocol.want_room(t, len);
                self.apply(cx, work, peer, out);
                false
            }
            Err(SendError::Corrupt) => self.lost_blob(cx, work, peer, folder, hash),
            Err(e) => {
                if !matches!(
                    e,
                    SendError::Closed | SendError::FolderNotOpen | SendError::Unrequested
                ) {
                    self.counters.bug();
                }
                c.chunk_requests.pop_front();
                true
            }
        }
    }

    /// The stored blob is gone or no longer hashes to its name (TM-10):
    /// answered not found, and changed at rest (`changed_at_rest`).
    fn lost_blob(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        hash: CipherHash,
    ) -> bool {
        self.changed_at_rest(work, folder, hash);
        self.answer_not_found(cx, work, peer, folder, hash)
    }

    fn answer_not_found(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        hash: CipherHash,
    ) -> bool {
        let answered = self.with_conn(cx, peer, |c, t| {
            c.reply_chunk(t, folder, hash, ChunkAnswer::NotFound)
        });
        if let Some(c) = self.conns.get_mut(&peer) {
            c.chunk_requests.pop_front();
        }
        match answered {
            Some(Ok(out)) => self.apply(cx, work, peer, out),
            Some(Err(SendError::Closed | SendError::FolderNotOpen | SendError::Unrequested))
            | None => {}
            Some(Err(_)) => self.counters.bug(),
        }
        true
    }

    /// Phase C: one `chunk_stored` per chunk newly stored, on every
    /// connection where the folder is open.
    pub(crate) fn notify_stored(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
        n: u64,
    ) {
        for peer in self.open_on(&folder) {
            for _ in 0..n {
                if let Some(out) = self.with_conn(cx, peer, |c, t| c.chunk_stored(t, folder)) {
                    self.apply(cx, work, peer, out);
                }
            }
        }
    }

    /// Phase C: the folder's passes on every connection where it is open.
    pub(crate) fn drive_passes(&mut self, cx: &mut dyn Context, work: &mut Work, folder: FolderId) {
        if !self
            .folders
            .get(&folder)
            .is_some_and(crate::folder::Folder::accepting)
        {
            return;
        }
        self.fresh(cx, work, folder);
        for peer in self.open_on(&folder) {
            self.drive(cx, work, peer, folder);
        }
    }

    /// One connection's pass for `folder`, as far as it may go now.
    fn drive(&mut self, cx: &mut dyn Context, work: &mut Work, peer: PeerId, folder: FolderId) {
        let (now, wait) = (cx.now(), patience(&self.settings.timing));
        for _ in 0..DRIVE_STEPS {
            let Some(Ok(position)) = self.with_conn(cx, peer, |c, t| c.chunk_position(t, &folder))
            else {
                // In flight full, backing off, waiting for a trigger, or closed.
                return;
            };
            let in_flight = &self.in_flight;
            let free = |h: &CipherHash| in_flight.free(folder, h, peer, now, wait);
            let next = self
                .folders
                .get(&folder)
                .and_then(|f| f.book.next_lacking(position, free));
            match (next, position) {
                (Some(hash), _) => {
                    match self.with_conn(cx, peer, |c, t| c.request_chunk(t, folder, hash)) {
                        Some(Ok(out)) => {
                            self.in_flight.asked(folder, hash, peer, now);
                            self.apply(cx, work, peer, out);
                        }
                        Some(Err(
                            SendError::InFlightFull
                            | SendError::BackingOff
                            | SendError::PassWaiting
                            | SendError::FolderNotOpen
                            | SendError::Closed,
                        ))
                        | None => return,
                        Some(Err(_)) => {
                            self.counters.bug();
                            return;
                        }
                    }
                }
                (None, None) => return,
                (None, Some(_)) => {
                    if let Some(out) = self.with_conn(cx, peer, |c, t| c.pass_done(t, folder)) {
                        self.apply(cx, work, peer, out);
                    }
                    let in_flight = &self.in_flight;
                    let more = self.folders.get(&folder).is_some_and(|f| {
                        f.book
                            .any_lacking(|h| in_flight.free(folder, h, peer, now, wait))
                    });
                    if !more {
                        return;
                    }
                }
            }
        }
        self.counters.bug();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use core::time::Duration;

    use licketysync_keys::chunk::seal_chunk;
    use licketysync_protocol::frame::{FrameDecoder, FrameKind, MessageType};
    use licketysync_protocol::limits::{MAX_MESSAGE_SIZE, MAX_REQUESTS_IN_FLIGHT};

    use crate::issues::StoreFailureCause;
    use crate::runtime::PeerId;
    use crate::testkit::{config, folder_key, write_key, Hold, Net};
    use crate::tests::{folder, pair, state, write};
    use crate::{FolderState, WriteFailure};

    /// The frames of `kind` that node `from` has sent node `to`.
    fn frames_of(net: &Net, from: usize, to: usize, kind: MessageType) -> usize {
        let bytes = net.streams.get(&(from, to)).cloned().unwrap_or_default();
        let mut decoder = FrameDecoder::new(MAX_MESSAGE_SIZE);
        let mut input = bytes.as_slice();
        let mut n = 0;
        while let Ok(Some(frame)) = decoder.next_frame(&mut input) {
            if frame.kind() == FrameKind::Known(kind) {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn a_chunk_that_arrives_while_its_folder_is_paused_is_not_stored_and_comes_again_after() {
        // The `pause` module (section 5, "Store failure"): a paused folder
        // stores no chunk. One asked for before the pause that arrives
        // during it is dropped and counted, stays lacking, and is fetched
        // again once the pause ends.
        let mut net = pair();
        net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
        let hash = write(&mut net, 0, "p.bin", &[3u8; 900]).unwrap();
        net.nodes[1].cx.storage.full = true;
        assert_eq!(
            write(&mut net, 1, "x.txt", b"x"),
            Err(WriteFailure::Store(StoreFailureCause::Full))
        );
        // The store works again while the folder stays paused until its
        // probe: a chunk judged now would be stored and committed, so only
        // the pause can keep it out.
        net.nodes[1].cx.storage.full = false;
        assert_eq!(state(&net, 1), FolderState::Paused(StoreFailureCause::Full));
        let skipped = net.nodes[1].engine.counters().skipped_while_paused;
        net.release();
        let one = net.nodes[1].engine.folder(&folder()).unwrap();
        assert!(one.stored_chunks.is_empty(), "not stored while paused");
        assert_eq!(one.lacking.len(), 1, "it stays lacking");
        assert!(net.nodes[1].engine.counters().skipped_while_paused > skipped);
        net.advance(Duration::from_secs(5));
        let n = &net.nodes[1];
        assert_eq!(
            n.engine.read_file(&n.cx.storage, &folder(), &hash),
            Ok(vec![3u8; 900]),
            "fetched again once the probe resumed the folder"
        );
    }

    #[test]
    fn a_chunk_request_the_connection_does_not_hold_is_dropped_and_not_counted() {
        // `serve_chunk`: a `CHUNK_OK` the connection refuses because the
        // request is not outstanding there (UNREQUESTED; FOLDER_NOT_OPEN and
        // CLOSED alike) is dropped and the queue moves on, and it is not
        // counted in `Counters::internal_errors`. The branch is defensive:
        // the engine's queue holds exactly the requests the connection
        // handed over, so only a desync between the two reaches it. The
        // test makes one by hand: node 1 holds the chunk and finds a request
        // in its queue that node 0 never made.
        let mut net = pair();
        write(&mut net, 0, "a.bin", &[6u8; 900]).unwrap();
        net.advance(Duration::from_secs(3));
        let n = &mut net.nodes[1];
        let chunk = n.engine.folder(&folder()).unwrap().stored_chunks[0];
        let zero = PeerId::new(0);
        n.engine
            .conns
            .get_mut(&zero)
            .unwrap()
            .chunk_requests
            .push_back((folder(), chunk));
        let bugs = n.engine.counters().internal_errors;
        n.engine.run(&mut n.cx, |_, _, w| {
            w.pump.insert(zero);
        });
        assert!(n.engine.conns[&zero].chunk_requests.is_empty(), "dropped");
        assert_eq!(n.engine.counters().internal_errors, bugs);
    }

    #[test]
    fn a_chunk_that_comes_to_lack_below_a_pass_is_asked_for_when_that_pass_ends() {
        // 4.6, "Passes": a pass asks in ascending hash order from its
        // position and ends when no lacking hash lies above it; a hash that
        // came to lack below the position meanwhile is asked for by a new
        // pass at once, not left until something else drives the passes.
        // Node 0 takes one request at a time, so node 1's pass waits at the
        // chunk of `a.bin` until it arrives; `b.bin`, whose chunk hashes
        // below it, arrives with it.
        let keys = write_key(1).chunk_keys();
        let mut contents: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i; 600]).collect();
        contents.sort_by_key(|c| seal_chunk(&keys, c).unwrap().cipher_hash);
        let (low, high) = (contents[0].clone(), contents[7].clone());
        let mut zero = config(0, vec![folder_key(1, 1)]);
        zero.max_requests_in_flight = 1;
        let mut net = Net::new(vec![zero, config(1, vec![folder_key(1, 1)])]);
        net.connect(0, 1);
        net.advance(Duration::from_secs(2));
        net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
        let first = write(&mut net, 0, "a.bin", &high).unwrap();
        let second = write(&mut net, 0, "b.bin", &low).unwrap();
        let one = net.nodes[1].engine.folder(&folder()).unwrap();
        assert_eq!(
            one.lacking,
            vec![seal_chunk(&keys, &high).unwrap().cipher_hash],
            "a.bin's chunk asked for; b.bin not heard of yet"
        );
        net.release();
        let n = &net.nodes[1];
        for (record, content) in [(first, high), (second, low)] {
            assert_eq!(
                n.engine.read_file(&n.cx.storage, &folder(), &record),
                Ok(content)
            );
        }
    }

    #[test]
    fn a_pass_asks_for_as_many_chunks_as_the_peer_allows_in_one_go() {
        // 4.6, "Passes": a pass asks for each lacking hash in turn while the
        // peer's `max_requests_in_flight` has room, here the largest a Hello
        // may advertise, 1 024. The bound on a drive's steps (each asks for
        // a hash or ends a pass) leaves room for all of them, so it is never
        // reached: reaching it counts an engine bug. Node 0's answers are
        // held, so every request comes from the drive that the record
        // started, and nothing is stored, so the test stays quick whatever
        // storing a chunk costs.
        let mut zero = config(0, vec![folder_key(1, 1)]);
        zero.max_requests_in_flight = MAX_REQUESTS_IN_FLIGHT;
        let mut net = Net::new(vec![zero, config(1, vec![folder_key(1, 1)])]);
        net.connect(0, 1);
        net.advance(Duration::from_secs(2));
        net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
        let content: Vec<u8> = (0..1030u32)
            .flat_map(|k| {
                let mut chunk = vec![0u8; 1024];
                chunk[..4].copy_from_slice(&k.to_le_bytes());
                chunk
            })
            .collect();
        write(&mut net, 0, "big.bin", &content).unwrap();
        assert_eq!(
            frames_of(&net, 1, 0, MessageType::ChunkRequest),
            1024,
            "every request node 0 allows, in one go"
        );
        assert_eq!(net.nodes[1].engine.counters().internal_errors, 0);
        let one = net.nodes[1].engine.folder(&folder()).unwrap();
        assert_eq!(one.lacking.len(), 1030, "none answered yet");
    }
}
