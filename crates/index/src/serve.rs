// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Serving one `IndexRequest` from the index, page by page (`protocol.md`
//! 4.5, "Serving" and "Pages").
//!
//! For every writer in the request, in ascending device-ID order (every
//! writer this side holds inside the range, or every writer listed), the
//! requester's cursor `(s, D)` (or `s = 0` when it is absent) and this side's
//! cursor `n` choose what to send, in canonical order, by the protocol
//! crate's [`serve`]: (a) `s = 0`, every record; (b) `1 ≤ s ≤ n` with this
//! side's cached digest at `s` equal to `D`, the records above `s`; (c) the
//! digests differ, every record, and the writer is marked; (d) `s > n`,
//! nothing. The digest is read from the cache, never computed (TM-22).
//!
//! A [`Reply`] keeps only its request and its position, so the engine builds
//! each page when the connection has room for it. Each page names the folder
//! of the index it is built from, so a page can never carry one folder's
//! records under another folder's ID. Records that land while a reply is
//! under way are pushed anyway; a reply that also carries one is answered
//! with a duplicate, which the receiver ignores.

use core::ops::Bound;

use licketysync_keys::{DeviceId, RecordHash};
use licketysync_protocol::exchange::{serve, BuildError, Pager, Serve, ServeRequest};
use licketysync_protocol::messages::IndexRecords;

use crate::index::Index;

/// Where a reply stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// The next writer is the first in the request strictly above this one.
    Writer(Option<DeviceId>),
    /// Sending this writer's records from this position in canonical order.
    Records(DeviceId, Bound<(u64, RecordHash)>),
    /// The last page has been built.
    Done,
}

/// One page of a reply and the writers it marks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyPage {
    /// The page, echoing the request's ID; `more` on every page but the
    /// last.
    pub page: IndexRecords,
    /// Writers served by case (c), a full resend after a digest mismatch:
    /// the engine marks each for a listed request of its own
    /// (`Connection::mark` with `MarkKind::Resend`).
    pub marks: Vec<DeviceId>,
}

/// The reply to one request, built a page at a time from the index of the
/// request's folder.
#[derive(Clone, Debug)]
pub struct Reply {
    request: ServeRequest,
    at: At,
}

impl Reply {
    /// The reply to `request`, nothing built yet.
    #[must_use]
    pub fn new(request: ServeRequest) -> Self {
        Self {
            request,
            at: At::Writer(None),
        }
    }

    /// Whether the last page has been built.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.at == At::Done
    }

    /// Builds the next page from `index`, for a requester that accepts frames
    /// of `max_message_size`: records in the order of the module
    /// documentation, the page ended before a record that would take it past
    /// the request's page limit or past the frame size, under `index`'s
    /// folder ID. A reply with nothing to send is one empty page. `None` once
    /// the last page has been built. Every page of a reply is built from the
    /// same index.
    ///
    /// # Errors
    /// [`BuildError::DoesNotFit`] for a record that does not fit an empty
    /// page, which no record within the spec's caps is.
    pub fn next_page<S>(
        &mut self,
        index: &Index<S>,
        max_message_size: u32,
    ) -> Result<Option<ReplyPage>, BuildError> {
        let mut pager = Pager::new(self.request.page_limit, max_message_size);
        let mut marks = Vec::new();
        loop {
            match self.at {
                At::Done => return Ok(None),
                At::Writer(after) => {
                    let Some(writer) = index.next_writer(&self.request.scope, after) else {
                        self.at = At::Done;
                        return Ok(Some(self.page(index, &mut pager, marks, false)));
                    };
                    let requester = self.request.requester(&writer);
                    let own = index.writer_cursor(&writer).seq;
                    self.at = match serve(requester, own, index.digest_at(&writer, requester.0)) {
                        Serve::All { mark } => {
                            if mark {
                                marks.push(writer);
                            }
                            At::Records(writer, Bound::Unbounded)
                        }
                        Serve::After(seq) => At::Records(
                            writer,
                            Bound::Included((seq.saturating_add(1), RecordHash([0; 32]))),
                        ),
                        Serve::Nothing => At::Writer(Some(writer)),
                    };
                }
                At::Records(writer, from) => match index.record_from(&writer, from) {
                    None => self.at = At::Writer(Some(writer)),
                    Some((position, record)) => {
                        if !pager.push(record)? {
                            return Ok(Some(self.page(index, &mut pager, marks, true)));
                        }
                        self.at = At::Records(writer, Bound::Excluded(position));
                    }
                },
            }
        }
    }

    fn page<S>(
        &self,
        index: &Index<S>,
        pager: &mut Pager,
        marks: Vec<DeviceId>,
        more: bool,
    ) -> ReplyPage {
        ReplyPage {
            page: pager.page(&index.folder_id(), self.request.request_id, more),
            marks,
        }
    }
}
