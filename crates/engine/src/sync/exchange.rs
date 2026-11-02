// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index exchange's events (phase A) and what phase C sends of it: the
//! judgements, the pushes, the requests due, the rounds owed and the
//! subtrees a `RECORDS` reply ends with (the module documentation of
//! `super`).

use licketysync_keys::{DeviceId, FolderId, RecordHash};
use licketysync_protocol::connection::{Event, Page, SendError};
use licketysync_protocol::exchange::Prefix;
use licketysync_protocol::record::Record;
use licketysync_protocol::Cause;

use super::{Judged, Op, ToPush};
use crate::engine::{tick, Engine};
use crate::issues::{bump, Issue, IssueKind, Subject};
use crate::runtime::{Context, PeerId};
use crate::work::{pop, Work};

impl Engine {
    /// Reacts to an event of the index exchange; any other event is handed
    /// back.
    pub(crate) fn sync_event(
        &mut self,
        work: &mut Work,
        peer: PeerId,
        event: Event,
    ) -> Option<Event> {
        match event {
            Event::RequestDue { folder } => {
                work.sync.requests.insert((peer, folder));
            }
            Event::ServeIndex { folder, request } => self.serve_index(work, peer, folder, &request),
            Event::ServeReconcile { folder, request } => {
                self.serve_reconcile(work, peer, folder, request);
            }
            Event::Records {
                folder,
                records,
                page,
            } => self.on_records(work, peer, folder, records, page),
            Event::PushSubtree {
                folder,
                prefix,
                carried,
            } => work.sync.subtrees.push((peer, folder, prefix, carried)),
            Event::RoundCompleted {
                folder,
                caught_up,
                cursor,
            } => self.round_completed(peer, folder, caught_up, cursor),
            Event::CursorAdvanced {
                folder,
                epoch,
                through,
            } => {
                if let Some(device) = self.conns.get(&peer).and_then(|c| c.device) {
                    self.defer_op(
                        folder,
                        Op::CursorAdvanced {
                            device,
                            epoch,
                            through,
                        },
                    );
                }
            }
            Event::EmptyPush { .. } => self.counters.log(Cause::EmptyPush),
            Event::ClockOutOfRange {
                folder,
                peer: device,
                ours,
                theirs,
            } => self.clock_out_of_range(folder, device, ours, theirs),
            Event::StrangerClockOutOfRange { .. } => {
                bump(&mut self.counters.stranger_clocks);
            }
            other => return Some(other),
        }
        None
    }

    /// Index work that phase C brought: it waits for the next commit, which
    /// a handler of its own makes at once (`Purpose::Deferred`).
    pub(crate) fn defer_op(&mut self, folder: FolderId, op: Op) {
        self.deferred.entry(folder).or_default().push(op);
    }

    /// The clock rule at the handshake (3.2): the connection closes, and the
    /// folder's issue names the peer and both readings.
    fn clock_out_of_range(&mut self, folder: FolderId, device: DeviceId, ours: u32, theirs: u32) {
        self.counters.log(Cause::ClockOutOfRange);
        self.issues.raise(Issue {
            folder: Some(folder),
            kind: IssueKind::ClockOutOfRange,
            subject: Subject::Clock {
                device,
                ours,
                theirs,
            },
        });
    }

    /// A round of this side's ended (4.5, "Rounds"): whether it ended caught
    /// up is the connection's to say; the per-peer state, the round's
    /// cleanups and the chunk frees it makes due wait for the next commit.
    fn round_completed(
        &mut self,
        peer: PeerId,
        folder: FolderId,
        caught_up: bool,
        cursor: Option<(u64, u64)>,
    ) {
        let Some(c) = self
            .conns
            .get_mut(&peer)
            .filter(|c| c.open.contains(&folder))
        else {
            return;
        };
        c.sync.caught_up.insert(folder, caught_up);
        let Some(device) = c.device else {
            return;
        };
        self.defer_op(
            folder,
            Op::RoundEnded {
                peer,
                device,
                caught_up,
                cursor,
            },
        );
    }

    /// Phase A for one `IndexRecords` page: queued for phase B, or, when its
    /// folder judges nothing now or the reply it belongs to is void,
    /// reported skipped (the module documentation of `super`).
    fn on_records(
        &mut self,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        records: Vec<Record>,
        page: Page,
    ) {
        let n = records.len();
        let Some(c) = self.conns.get_mut(&peer) else {
            return;
        };
        if let Page::Reply { last, .. } = page {
            bump(&mut c.sync.reply_pages);
            self.counters.most_reply_pages = self.counters.most_reply_pages.max(c.sync.reply_pages);
            if c.sync.void.contains(&folder) {
                if last {
                    c.sync.void.remove(&folder);
                }
                self.counters.void_reply_pages = self.counters.void_reply_pages.saturating_add(1);
                work.sync
                    .judged
                    .push(Judged::skipped(peer, folder, page, n));
                return;
            }
        }
        let accepting = self
            .folders
            .get(&folder)
            .is_some_and(crate::folder::Folder::accepting);
        if !accepting || work.failed.is_some() {
            self.counters.skipped_while_paused =
                self.counters.skipped_while_paused.saturating_add(n as u64);
            if let Page::Reply { last: false, .. } = page {
                c.sync.void.insert(folder);
            }
            work.skipped.insert(folder);
            work.sync
                .judged
                .push(Judged::skipped(peer, folder, page, n));
            return;
        }
        work.sync.queue(
            folder,
            Op::Records {
                peer,
                page,
                records,
            },
        );
    }

    /// Phase C, first: each page's judgements back to its connection, then
    /// the pushes.
    pub(crate) fn send_records(&mut self, cx: &mut dyn Context, work: &mut Work) {
        for Judged {
            peer,
            folder,
            page,
            results,
        } in core::mem::take(&mut work.sync.judged)
        {
            #[cfg(test)]
            self.judged_log.push((folder, results.clone()));
            if let Some(out) = self.with_conn(cx, peer, |c, t| c.judged(t, folder, page, &results))
            {
                self.apply(cx, work, peer, out);
            }
        }
        if work.committed {
            for (folder, items) in core::mem::take(&mut work.sync.pushes) {
                self.push(cx, work, folder, &items);
            }
        }
    }

    /// Phase C: one request due, one round owed, or one subtree to push;
    /// whether there was one.
    pub(crate) fn send_next_sync(&mut self, cx: &mut dyn Context, work: &mut Work) -> bool {
        if let Some((peer, folder)) = pop(&mut work.sync.requests) {
            self.send_request(cx, work, peer, folder);
            return true;
        }
        if let Some((folder, peer)) = pop(&mut work.sync.owe) {
            self.owe_rounds(cx, work, folder, peer);
            return true;
        }
        if let Some((peer, folder, prefix, carried)) = work.sync.subtrees.pop() {
            self.push_subtree(cx, work, peer, folder, &prefix, carried.as_deref());
            return true;
        }
        false
    }

    /// Pushes `items` of `folder` to every connection where it is open but
    /// the one each came on, in local-sequence order (ruling PUSH-2).
    fn push(&mut self, cx: &mut dyn Context, work: &mut Work, folder: FolderId, items: &[ToPush]) {
        for peer in self.open_on(&folder) {
            let hashes: Vec<RecordHash> = items
                .iter()
                .filter(|i| i.except != Some(peer))
                .map(|i| i.hash)
                .collect();
            if hashes.is_empty() {
                continue;
            }
            let (Some(f), Some(c)) = (self.folders.get(&folder), self.conns.get(&peer)) else {
                continue;
            };
            let pages = f
                .index
                .push_pages(&hashes, c.protocol.peer_max_message_size());
            self.send_pushes(cx, work, peer, &pages);
        }
    }

    /// Hands `pages` to the connection as pushes. One the send queue cannot
    /// take is the connection's to drop, owing an empty push.
    fn send_pushes(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        pages: &[licketysync_protocol::messages::IndexRecords],
    ) {
        for page in pages {
            match self.with_conn(cx, peer, |c, t| c.push(t, page)) {
                Some(Ok(out)) => self.apply(cx, work, peer, out),
                Some(Err(SendError::Closed | SendError::FolderNotOpen)) | None => break,
                Some(Err(_)) => self.counters.bug(),
            }
        }
    }

    /// The pushes a `RECORDS` reply ends with (4.5, "Reconciling"): every
    /// record this side holds in the subtree that the reply did not carry.
    fn push_subtree(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        prefix: &Prefix,
        carried: Option<&[RecordHash]>,
    ) {
        let (Some(f), Some(c)) = (self.folders.get(&folder), self.conns.get(&peer)) else {
            return;
        };
        let pages = f
            .index
            .subtree_pushes(prefix, carried, c.protocol.peer_max_message_size());
        self.send_pushes(cx, work, peer, &pages);
    }

    /// This side's request that is due, built by the connection from the
    /// committed index.
    fn send_request(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
    ) {
        let t = tick(cx, peer);
        let (Some(f), Some(c)) = (self.folders.get(&folder), self.conns.get_mut(&peer)) else {
            return;
        };
        if !c.reacts() {
            return;
        }
        match c.protocol.send_request(t, folder, &f.index) {
            Ok(out) => self.apply(cx, work, peer, out),
            // A race with the connection's own state.
            Err(SendError::NotDue | SendError::FolderNotOpen | SendError::Closed) => {}
            Err(_) => self.counters.bug(),
        }
    }

    /// A round owed on `peer`'s connection, or on every connection where the
    /// folder is open: a failed handler skipped some of its records, or a
    /// round's end issued a cleanup.
    fn owe_rounds(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
        peer: Option<PeerId>,
    ) {
        let peers = match peer {
            Some(p) => vec![p],
            None => self.open_on(&folder),
        };
        for peer in peers {
            if let Some(out) = self.with_conn(cx, peer, |c, t| c.owe_round(t, folder)) {
                bump(&mut self.counters.rounds_owed);
                self.apply(cx, work, peer, out);
            }
        }
    }
}
