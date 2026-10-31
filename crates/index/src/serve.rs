// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Serving, lazily from committed state (`protocol.md` 4.5, "Serving an
//! `IndexRequest`", "Serving a `ReconcileRequest`"; 4.7 item 3): a Since
//! reply page by page, keeping only its starting point and the last local
//! sequence sent; a `ReconcileReply` from the digest cache, computing no
//! digest; a `RECORDS` reply's pages in ascending key order (path tag, then
//! record hash), keeping only the last key sent; and the pages of pushes. A
//! record dropped meanwhile is skipped, and one held meanwhile has a greater
//! number and goes by push. What the connection reads as a requester is
//! [`IndexView`].

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, RecordHash, SetDigest};
use licketysync_protocol::connection::ReconcileServe;
use licketysync_protocol::exchange::{reconcile_outcome, IndexView, Key, Pager, Prefix};
use licketysync_protocol::limits::MAX_PAGE_RECORDS;
use licketysync_protocol::messages::{IndexRecords, ReconcileOutcome, ReconcileReply};

use crate::index::Index;
use crate::trie::hash_of;

/// How to answer a peer's `IndexRequest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SincePlan {
    /// Pages of every record held above the request's `since`.
    Pages(SinceReply),
    /// One page with `reset`; `redraw` when the request's epoch is this
    /// side's and its `since` above the local sequence, which draws a new
    /// epoch (at most once per connection).
    Reset {
        /// Whether a new epoch is to be drawn.
        redraw: bool,
    },
}

/// A Since reply in progress: the records held with local sequence numbers
/// in `(after, through]`, in that order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinceReply {
    after: u64,
    through: u64,
    done: bool,
}

impl SinceReply {
    /// Whether the last page has been built.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }
}

/// A `RECORDS` reply in progress: the subtree's records after `after`, the
/// last key sent, in ascending key order (4.5, "Serving a
/// `ReconcileRequest`"): nothing else is kept between pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordsReply {
    prefix: Prefix,
    after: Option<Key>,
    done: bool,
}

impl RecordsReply {
    /// Whether the last page has been built.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }
}

impl IndexView for Index {
    fn digest(&self, prefix: &Prefix) -> SetDigest {
        self.s.trie.digest(prefix)
    }

    fn peer_cursor(&self, peer: &DeviceId) -> Option<(u64, u64)> {
        self.s.peers.get(peer).map(|p| (p.epoch, p.cursor))
    }
}

impl Index {
    /// The set digest of the subtree at `prefix` (4.5).
    #[must_use]
    pub fn digest(&self, prefix: &Prefix) -> SetDigest {
        self.s.trie.digest(prefix)
    }

    /// The root set digest: equal on every tier for equal records.
    #[must_use]
    pub fn root_digest(&self) -> SetDigest {
        self.digest(&Prefix::ROOT)
    }

    /// The 16 child digests of the subtree at `prefix`.
    #[must_use]
    pub fn children(&self, prefix: &Prefix) -> [SetDigest; 16] {
        self.s.trie.children(prefix)
    }

    /// The records held in the subtree at `prefix`, in ascending key order.
    #[must_use]
    pub fn subtree(&self, prefix: &Prefix) -> Vec<RecordHash> {
        self.s.subtree(prefix)
    }

    /// How to answer an `IndexRequest` for `epoch` and `since` (4.5): its
    /// records when `epoch` is this side's and `since` at most its local
    /// sequence, through the local sequence now; otherwise a reset.
    #[must_use]
    pub fn since_plan(&self, epoch: u64, since: u64) -> SincePlan {
        let local = self.local_seq();
        if epoch == self.epoch() && since <= local {
            SincePlan::Pages(SinceReply {
                after: since,
                through: local,
                done: false,
            })
        } else {
            SincePlan::Reset {
                redraw: epoch == self.epoch() && since > local,
            }
        }
    }

    /// The next page of a Since reply for `request_id`, at most `page_limit`
    /// records and the peer's `max_message_size`: each page's `through` its
    /// last record's local sequence, the last page's the local sequence when
    /// serving began, `more` on every page but the last.
    #[must_use]
    pub fn since_page(
        &self,
        reply: &mut SinceReply,
        request_id: u32,
        page_limit: usize,
        max_message_size: u32,
    ) -> IndexRecords {
        let mut pager = Pager::new(page_limit, max_message_size);
        let mut last = reply.after;
        let mut more = false;
        // `after` is at most `through`; when they are equal (nothing left to
        // send, or a `since` at the local sequence) the range is empty, and
        // a range whose start passes its end would panic.
        let lo = reply.after.saturating_add(1);
        let range = (lo <= reply.through)
            .then(|| self.s.by_seq.range(lo..=reply.through))
            .into_iter()
            .flatten();
        for (seq, hash) in range {
            let Some(held) = self.s.held.get(hash) else {
                continue;
            };
            match pager.push(held.record.signed()) {
                // A record within the caps always fits an empty page, so
                // one that does not is passed over.
                Ok(true) | Err(_) => last = *seq,
                Ok(false) => {
                    more = true;
                    break;
                }
            }
        }
        if more {
            reply.after = last;
        } else {
            reply.after = reply.through;
            reply.done = true;
            last = reply.through;
        }
        pager.page(&self.folder_id(), request_id, more, self.epoch(), last)
    }

    /// The `ReconcileReply` to a peer's `ReconcileRequest` (4.5): `EQUAL`,
    /// `CHILDREN` with the cached child digests, or `RECORDS`, whose pages
    /// follow from the returned [`RecordsReply`]; the root's carries the local
    /// sequence as `through`.
    #[must_use]
    pub fn reconcile_reply(
        &self,
        request: &ReconcileServe,
    ) -> (ReconcileReply, Option<RecordsReply>) {
        let own = self.digest(&request.prefix);
        let count = self.s.trie.count(&request.prefix);
        let outcome = reconcile_outcome(request.prefix.depth(), &request.digest, &own, count);
        let children = if outcome == ReconcileOutcome::Children {
            self.children(&request.prefix)
                .iter()
                .map(|d| d.0.to_vec())
                .collect()
        } else {
            Vec::new()
        };
        let reply = ReconcileReply {
            folder_id: self.folder_id().0.to_vec(),
            request_id: request.request_id,
            outcome: outcome.as_u32(),
            children,
            epoch: self.epoch(),
            through: if request.prefix.is_root() {
                self.local_seq()
            } else {
                0
            },
        };
        let records = (outcome == ReconcileOutcome::Records).then_some(RecordsReply {
            prefix: request.prefix,
            after: None,
            done: false,
        });
        (reply, records)
    }

    /// The next page of a `RECORDS` reply for `request_id`: the subtree's
    /// records in ascending key order after the last key sent, at most
    /// `MAX_PAGE_RECORDS` and the peer's `max_message_size`, no `through`
    /// (one empty page when there are none). The subtree is a range of the
    /// trie's keys, so a page reads the keys it sends and the one that did
    /// not fit, `O(page · log n)`, sorts nothing and keeps only the last key
    /// (4.5, "Serving a `ReconcileRequest`").
    #[must_use]
    pub fn records_page(
        &self,
        reply: &mut RecordsReply,
        request_id: u32,
        max_message_size: u32,
    ) -> IndexRecords {
        let mut pager = Pager::new(MAX_PAGE_RECORDS, max_message_size);
        let mut more = false;
        for key in self.s.trie.keys_after(&reply.prefix, reply.after.as_ref()) {
            // A record that fits no page is passed over, as before.
            if let Some(held) = self.s.held.get(&hash_of(key)) {
                if matches!(pager.push(held.record.signed()), Ok(false)) {
                    more = true;
                    break;
                }
            }
            reply.after = Some(*key);
        }
        reply.done = !more;
        pager.page(&self.folder_id(), request_id, more, self.epoch(), 0)
    }

    /// The pushes of `hashes`, records this side came to hold (4.5,
    /// "Pushes"): in local-sequence order, at most `MAX_PAGE_RECORDS` a page
    /// and the peer's `max_message_size`, each page's `through` its last
    /// record's local sequence. Records no longer held are skipped.
    #[must_use]
    pub fn push_pages(&self, hashes: &[RecordHash], max_message_size: u32) -> Vec<IndexRecords> {
        let mut held: Vec<(u64, &SignedRecord)> = hashes
            .iter()
            .filter_map(|h| self.s.held.get(h).map(|r| (r.seq, r.record.signed())))
            .collect();
        held.sort_by_key(|(s, _)| *s);
        held.dedup_by_key(|(s, _)| *s);
        self.pages(held.into_iter(), max_message_size, true)
    }

    /// The pushes a requester sends after a `RECORDS` reply (4.5,
    /// "Reconciling"): every record it holds in the subtree at `prefix` that
    /// the reply did not carry (`carried`; `None`: every one), `through` not
    /// set.
    #[must_use]
    pub fn subtree_pushes(
        &self,
        prefix: &Prefix,
        carried: Option<&[RecordHash]>,
        max_message_size: u32,
    ) -> Vec<IndexRecords> {
        let records = self
            .s
            .trie
            .keys_after(prefix, None)
            .map(hash_of)
            .filter(|h| carried.is_none_or(|c| !c.contains(h)))
            .filter_map(|h| self.s.held.get(&h).map(|r| (0, r.record.signed())))
            .collect::<Vec<_>>();
        self.pages(records.into_iter(), max_message_size, false)
    }

    fn pages<'a>(
        &self,
        records: impl Iterator<Item = (u64, &'a SignedRecord)>,
        max_message_size: u32,
        through: bool,
    ) -> Vec<IndexRecords> {
        let mut out = Vec::new();
        let mut pager = Pager::new(MAX_PAGE_RECORDS, max_message_size);
        let mut last = 0;
        for (seq, record) in records {
            if !pager.push(record).unwrap_or(true) {
                out.push(pager.page(&self.folder_id(), 0, false, self.epoch(), last));
                let _ = pager.push(record);
            }
            if through {
                last = seq;
            }
        }
        if !pager.is_empty() {
            out.push(pager.page(&self.folder_id(), 0, false, self.epoch(), last));
        }
        out
    }
}
