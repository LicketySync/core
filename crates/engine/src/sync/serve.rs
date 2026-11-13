// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Serving the peer's requests (`protocol.md` 4.5, "Serving an
//! `IndexRequest`", "Serving a `ReconcileRequest`"; 4.7 item 3): planned in
//! phase A from the committed index, then sent in phase C page by page,
//! each page built from the committed index only as its turn comes, under
//! the send budget (the `pacing` module). A reset that draws a new epoch is
//! sent only after the commit that holds the epoch.

use licketysync_index::SincePlan;
use licketysync_keys::FolderId;
use licketysync_protocol::connection::{IndexServe, ReconcileServe, SendError};
use licketysync_protocol::messages::IndexRecords;

use super::{Op, Reply, Serving};
use crate::engine::{tick, Engine};
use crate::pacing::{page_estimate, within_budget};
use crate::runtime::{Context, PeerId};
use crate::work::Work;

impl Engine {
    /// Phase A: the peer's `IndexRequest` may be served now.
    pub(crate) fn serve_index(
        &mut self,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        request: &IndexServe,
    ) {
        let Some(f) = self.folders.get(&folder) else {
            return;
        };
        let serving = match f.index.since_plan(request.epoch, request.since) {
            SincePlan::Pages(reply) => Serving::Since {
                request_id: request.request_id,
                page_limit: request.page_limit,
                reply,
            },
            SincePlan::Reset { redraw } => {
                // A folder held paused runs no transaction this handler, so
                // the Redraw would be dropped: no new epoch is promised then
                // (the connection's one redraw is not spent on nothing).
                let redrew = redraw && request.redraw_allowed && f.accepting();
                if redrew {
                    work.sync.queue(folder, Op::Redraw);
                }
                Serving::Reset {
                    request_id: request.request_id,
                    redrew,
                }
            }
        };
        self.start_reply(work, peer, folder, serving);
    }

    /// Phase A: the peer's `ReconcileRequest` may be served now.
    pub(crate) fn serve_reconcile(
        &mut self,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        request: ReconcileServe,
    ) {
        self.start_reply(work, peer, folder, Serving::Reconcile(request));
    }

    fn start_reply(&mut self, work: &mut Work, peer: PeerId, folder: FolderId, serving: Serving) {
        if let Some(c) = self.conns.get_mut(&peer) {
            c.sync.replies.insert(
                folder,
                Reply {
                    serving,
                    built: None,
                },
            );
            work.pump.insert(peer);
        }
    }

    /// Phase C: the next frame of the reply to `folder`'s request under way
    /// on the connection, if the budget and the queue have room. Whether one
    /// was sent (or the reply ended), so the caller may go on.
    pub(crate) fn serve_page(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
    ) -> bool {
        let t = tick(cx, peer);
        let (Some(held), Some(conn)) = (self.folders.get(&folder), self.conns.get_mut(&peer))
        else {
            return false;
        };
        let Some(reply) = conn.sync.replies.get_mut(&folder) else {
            return false;
        };
        let mms = conn.protocol.peer_max_message_size();
        let sent = match &mut reply.serving {
            Serving::Reset { request_id, redrew } => {
                let (id, redrew) = (*request_id, *redrew);
                #[cfg(test)]
                self.resets_log.push((folder, redrew));
                conn.protocol
                    .send_reset(t, folder, id, held.index.epoch(), redrew)
            }
            Serving::Reconcile(request) => {
                let (answer, records) = held.index.reconcile_reply(request);
                match conn.protocol.send_reconcile_reply(t, &answer) {
                    Ok(out) => {
                        match records {
                            Some(r) => {
                                reply.serving = Serving::Records {
                                    request_id: request.request_id,
                                    reply: r,
                                };
                            }
                            None => {
                                conn.sync.replies.remove(&folder);
                            }
                        }
                        self.apply(cx, work, peer, out);
                        return true;
                    }
                    Err(e) => Err(e),
                }
            }
            Serving::Since {
                request_id,
                page_limit,
                reply: since,
            } => {
                let page = match reply.built.take() {
                    Some(page) => page,
                    None => held.index.since_page(since, *request_id, *page_limit, mms),
                };
                return self.send_reply_page(cx, work, peer, folder, page);
            }
            Serving::Records {
                request_id,
                reply: records,
            } => {
                let page = match reply.built.take() {
                    Some(page) => page,
                    None => held.index.records_page(records, *request_id, mms),
                };
                return self.send_reply_page(cx, work, peer, folder, page);
            }
        };
        match sent {
            Ok(out) => {
                conn.sync.replies.remove(&folder);
                self.apply(cx, work, peer, out);
                true
            }
            Err(SendError::WouldBlock { len }) => {
                let out = conn.protocol.want_room(t, len);
                self.apply(cx, work, peer, out);
                false
            }
            Err(e) => self.reply_failed(peer, folder, &e),
        }
    }

    /// Sends one page of a reply under way, under the budget.
    fn send_reply_page(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        peer: PeerId,
        folder: FolderId,
        page: IndexRecords,
    ) -> bool {
        let (unsent, budget) = (cx.unsent(peer), self.settings.send_budget);
        if !within_budget(unsent, page_estimate(&page), budget) {
            self.keep_page(peer, folder, page);
            self.defer(cx, peer);
            return false;
        }
        let t = tick(cx, peer);
        let Some(conn) = self.conns.get_mut(&peer) else {
            return false;
        };
        match conn.protocol.send_page(t, &page) {
            Ok(out) => {
                if !page.more {
                    conn.sync.replies.remove(&folder);
                }
                self.apply(cx, work, peer, out);
                true
            }
            Err(SendError::WouldBlock { len }) => {
                let out = conn.protocol.want_room(t, len);
                self.keep_page(peer, folder, page);
                self.apply(cx, work, peer, out);
                false
            }
            Err(e) => self.reply_failed(peer, folder, &e),
        }
    }

    fn keep_page(&mut self, peer: PeerId, folder: FolderId, page: IndexRecords) {
        if let Some(reply) = self
            .conns
            .get_mut(&peer)
            .and_then(|c| c.sync.replies.get_mut(&folder))
        {
            reply.built = Some(page);
        }
    }

    /// The connection refused a frame of the reply: the reply ends; an error
    /// other than the connection's own state is the engine's, counted.
    fn reply_failed(&mut self, peer: PeerId, folder: FolderId, e: &SendError) -> bool {
        if !matches!(
            e,
            SendError::Closed | SendError::FolderNotOpen | SendError::UnknownRequest
        ) {
            self.counters.bug();
        }
        if let Some(c) = self.conns.get_mut(&peer) {
            c.sync.replies.remove(&folder);
        }
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;
    use crate::tests::{folder, pair};

    #[test]
    fn a_reply_the_engine_holds_for_a_request_the_connection_does_not_know_ends_and_counts_no_bug()
    {
        // The connection refuses a page of a reply for a request it does not
        // know (`SendError::UnknownRequest`, its own state, as `Closed` and
        // `FolderNotOpen` are): the reply ends there, nothing is sent, and
        // no engine bug is counted. The branch is defensive: in an honest
        // run the engine holds a reply only for a request the connection
        // handed it, so it is never reached.
        let mut net = pair();
        let peer = PeerId::new(1);
        let n = &mut net.nodes[0];
        let bugs = n.engine.counters.internal_errors;
        n.cx.outbox.clear();
        let (went_on, _) = n.engine.run(&mut n.cx, |e, cx, w| {
            // A reset for request 99, which the peer never sent.
            let reply = Reply {
                serving: Serving::Reset {
                    request_id: 99,
                    redrew: false,
                },
                built: None,
            };
            let c = e.conns.get_mut(&peer).unwrap();
            c.sync.replies.insert(folder(), reply);
            e.serve_page(cx, w, peer, folder())
        });
        assert!(went_on, "the caller may go on to the next frame");
        assert_eq!(n.engine.conns[&peer].sync.serving(), None, "it ended");
        assert!(n.cx.outbox.is_empty(), "nothing sent");
        assert_eq!(n.engine.counters.internal_errors, bugs, "no bug counted");
    }
}
