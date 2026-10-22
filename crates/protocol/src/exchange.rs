// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index exchange's pure parts (`protocol.md` 4.5): typed cursors, the
//! scope of a request (a range of device IDs, or a list), how a requester
//! splits its writers into the range requests of a round, how a responder
//! serves one writer (cases (a) to (d)), and how it pages a reply. The index
//! supplies its cursors ([`Cursors`]), its cached digests and its records; the
//! connection ([`crate::connection`]) keeps the per-connection state (rounds,
//! marks, the round owed, one request at a time) and builds this side's
//! requests itself. Nothing here grows with the number of writers past one
//! request (ruling R-K4).

use std::collections::{BTreeMap, BTreeSet};

use core::fmt;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, FolderId, WriterDigest};

use crate::limits::{MAX_CURSORS_PER_REQUEST, MAX_PAGE_RECORDS, MIN_PAGE_RECORDS};
use crate::messages::{Cursor, IndexRecords, IndexRequest};

/// Why an exchange helper refused what the engine built from its own index:
/// the engine is at fault, never the peer, so nothing is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// Cursors not in strictly ascending device-ID order.
    Unsorted,
    /// A listed request with no writer, or more than `MAX_CURSORS_PER_REQUEST`.
    ListSize(usize),
    /// A record that does not fit an empty page; records within the spec's
    /// caps never are one (section 2's sizing).
    DoesNotFit,
    /// A cursor at `seq` 1 or above without its digest, or above `MAX_SEQ`.
    Cursor,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsorted => f.write_str("cursors not in ascending device-ID order"),
            Self::ListSize(n) => write!(f, "a listed request of {n} writers"),
            Self::DoesNotFit => f.write_str("a record that does not fit an empty page"),
            Self::Cursor => f.write_str("a cursor without its digest or above MAX_SEQ"),
        }
    }
}

impl std::error::Error for BuildError {}

/// One writer's cursor, typed: "I hold this writer's records through `seq`,
/// and their digest there is `digest`" (4.5); `seq = 0` means none held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterCursor {
    /// The writer.
    pub writer: DeviceId,
    /// The cursor: the highest `seq` held, 0 for none.
    pub seq: u64,
    /// The digest at `seq`; `None` exactly when `seq` is 0.
    pub digest: Option<WriterDigest>,
}

impl WriterCursor {
    /// A writer of which nothing is held.
    #[must_use]
    pub const fn none(writer: DeviceId) -> Self {
        Self {
            writer,
            seq: 0,
            digest: None,
        }
    }

    /// The wire form.
    ///
    /// # Errors
    /// [`BuildError::Cursor`] when `seq` and `digest` disagree, or `seq` is
    /// above `MAX_SEQ`: the peer would refuse the request as malformed.
    pub fn to_wire(&self) -> Result<Cursor, BuildError> {
        let digest = match (self.seq, self.digest) {
            (0, None) => Vec::new(),
            (1..=crate::limits::MAX_SEQ, Some(d)) => d.0.to_vec(),
            _ => return Err(BuildError::Cursor),
        };
        Ok(Cursor {
            device_id: self.writer.0.to_vec(),
            seq: self.seq,
            digest,
        })
    }

    /// The typed form of a parsed cursor; `None` for one the parser would
    /// have refused.
    #[must_use]
    pub fn from_wire(c: &Cursor) -> Option<Self> {
        let writer = DeviceId::from_slice(&c.device_id)?;
        let digest = match c.seq {
            0 if c.digest.is_empty() => None,
            0 => return None,
            _ => Some(WriterDigest::from_slice(&c.digest)?),
        };
        Some(Self {
            writer,
            seq: c.seq,
            digest,
        })
    }
}

/// This side's cursors as its index holds them: what the connection lists in
/// the requests it builds ([`crate::connection::Connection::send_request`]).
pub trait Cursors {
    /// The cursors of this side's writers strictly above `after` (from the
    /// lowest for `None`), in ascending device-ID order. A round's next range
    /// reads from there, so no request walks the writers below it (4.5).
    fn cursors_after(&self, after: Option<DeviceId>) -> impl Iterator<Item = WriterCursor> + '_;

    /// This side's cursor for `writer`: [`WriterCursor::none`] when it holds
    /// none of the writer's records.
    fn cursor_of(&self, writer: &DeviceId) -> WriterCursor;
}

/// Cursors held in a slice in ascending device-ID order.
impl Cursors for [WriterCursor] {
    fn cursors_after(&self, after: Option<DeviceId>) -> impl Iterator<Item = WriterCursor> + '_ {
        let start = after.map_or(0, |a| self.partition_point(|c| c.writer <= a));
        self.get(start..).unwrap_or_default().iter().copied()
    }

    fn cursor_of(&self, writer: &DeviceId) -> WriterCursor {
        self.binary_search_by(|c| c.writer.cmp(writer))
            .ok()
            .and_then(|i| self.get(i))
            .copied()
            .unwrap_or(WriterCursor::none(*writer))
    }
}

/// The writers a request covers (4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The device IDs strictly above `after` (from the lowest when `None`)
    /// and up to and including `through` (to the highest when `None`).
    Range {
        /// The exclusive lower bound.
        after: Option<DeviceId>,
        /// The inclusive upper bound.
        through: Option<DeviceId>,
    },
    /// Exactly these writers.
    Listed(BTreeSet<DeviceId>),
}

impl Scope {
    /// Every device ID.
    pub const ALL: Self = Self::Range {
        after: None,
        through: None,
    };

    /// The scope of a parsed request.
    #[must_use]
    pub fn of(request: &IndexRequest) -> Self {
        if request.listed {
            Self::Listed(
                request
                    .have
                    .iter()
                    .filter_map(|c| DeviceId::from_slice(&c.device_id))
                    .collect(),
            )
        } else {
            Self::Range {
                after: DeviceId::from_slice(&request.after),
                through: DeviceId::from_slice(&request.through),
            }
        }
    }

    /// Whether `writer` is in the scope.
    #[must_use]
    pub fn contains(&self, writer: &DeviceId) -> bool {
        match self {
            Self::Range { after, through } => {
                after.as_ref().is_none_or(|a| writer > a)
                    && through.as_ref().is_none_or(|t| writer <= t)
            }
            Self::Listed(set) => set.contains(writer),
        }
    }
}

/// The page limit a responder serves for a request's `max_records` (4.5): 0,
/// or a value above `MAX_PAGE_RECORDS`, means 4 096, and a value below 64
/// means 64, so that no requester can pin a responder with one-record pages.
#[must_use]
pub fn page_limit(max_records: u32) -> usize {
    let n = usize::try_from(max_records).unwrap_or(MAX_PAGE_RECORDS);
    if n == 0 || n > MAX_PAGE_RECORDS {
        MAX_PAGE_RECORDS
    } else {
        n.max(MIN_PAGE_RECORDS)
    }
}

/// The next range request of a round (4.5): the requester's cursors for its
/// writers strictly above `after`, in ascending order, at most
/// `MAX_CURSORS_PER_REQUEST`; `through` is the device ID of the last writer
/// listed when another of the requester's writers lies above it, and empty
/// otherwise, which makes it the last request of the round. `cursors` are
/// the requester's in ascending device-ID order from above `after`
/// ([`Cursors::cursors_after`]); any at or below `after` is skipped, and at
/// most one past the request's last is read. `request_id` is left 0 for the
/// connection to fill.
///
/// # Errors
/// [`BuildError::Unsorted`] or [`BuildError::Cursor`].
pub fn range_request<I: IntoIterator<Item = WriterCursor>>(
    folder: &FolderId,
    after: Option<DeviceId>,
    cursors: I,
    max_records: u32,
) -> Result<IndexRequest, BuildError> {
    let mut have = Vec::new();
    let mut last: Option<DeviceId> = None;
    let mut more = false;
    for c in cursors {
        if last.is_some_and(|l| c.writer <= l) {
            return Err(BuildError::Unsorted);
        }
        last = Some(c.writer);
        if after.is_some_and(|a| c.writer <= a) {
            continue;
        }
        if have.len() == MAX_CURSORS_PER_REQUEST {
            more = true;
            break;
        }
        have.push(c.to_wire()?);
    }
    let through = if more {
        have.last().map(|c| c.device_id.clone()).unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(IndexRequest {
        folder_id: folder.0.to_vec(),
        have,
        max_records,
        request_id: 0,
        after: after.map(|a| a.0.to_vec()).unwrap_or_default(),
        through,
        listed: false,
    })
}

/// A listed request for exactly `cursors` (its marks, 4.5): ascending, unique,
/// 1 to `MAX_CURSORS_PER_REQUEST` writers. `request_id` is left 0.
///
/// # Errors
/// [`BuildError`].
pub fn listed_request<I: IntoIterator<Item = WriterCursor>>(
    folder: &FolderId,
    cursors: I,
    max_records: u32,
) -> Result<IndexRequest, BuildError> {
    let have = cursors
        .into_iter()
        .map(|c| c.to_wire())
        .collect::<Result<Vec<_>, _>>()?;
    if have.is_empty() || have.len() > MAX_CURSORS_PER_REQUEST {
        return Err(BuildError::ListSize(have.len()));
    }
    if !have
        .windows(2)
        .all(|w| matches!(w, [a, b] if a.device_id < b.device_id))
    {
        return Err(BuildError::Unsorted);
    }
    Ok(IndexRequest {
        folder_id: folder.0.to_vec(),
        have,
        max_records,
        request_id: 0,
        after: Vec::new(),
        through: Vec::new(),
        listed: true,
    })
}

/// What a responder sends for one writer (4.5, "Serving").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Serve {
    /// Every record of the writer it holds; `mark` when this is case (c), a
    /// full resend after a digest mismatch, which also marks the writer for a
    /// listed request of this side's own.
    All {
        /// Case (c): mark the writer.
        mark: bool,
    },
    /// Its records of the writer with `seq` above this (case (b)).
    After(u64),
    /// Nothing (case (d), or a writer it holds none of).
    Nothing,
}

/// The serving rule for one writer: `requester` is the requester's cursor
/// for it from `have` (`(0, None)` when absent), `own_cursor` this side's,
/// and `own_digest_at_requester_seq` this side's cached digest at the
/// requester's `seq` (read only when `1 ≤ s ≤ own_cursor`; a missing one is
/// taken as a mismatch).
///
/// - (a) `s = 0`: every record;
/// - (b) `1 ≤ s ≤ n`, equal digests: the records above `s`;
/// - (c) `1 ≤ s ≤ n`, different digests: every record, and mark the writer;
/// - (d) `s > n`: nothing.
#[must_use]
pub fn serve(
    requester: (u64, Option<WriterDigest>),
    own_cursor: u64,
    own_digest_at_requester_seq: Option<WriterDigest>,
) -> Serve {
    let (s, digest) = requester;
    if own_cursor == 0 {
        return Serve::Nothing;
    }
    if s == 0 {
        return Serve::All { mark: false };
    }
    if s > own_cursor {
        return Serve::Nothing;
    }
    match (digest, own_digest_at_requester_seq) {
        (Some(theirs), Some(ours)) if theirs == ours => Serve::After(s),
        _ => Serve::All { mark: true },
    }
}

/// A request received from the peer, typed for serving: its ID, scope,
/// cursors and page limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeRequest {
    /// Every page of the reply echoes it.
    pub request_id: u32,
    /// The writers to serve: every writer this side holds in the range, or
    /// every listed one.
    pub scope: Scope,
    /// The requester's cursors, by writer.
    pub cursors: BTreeMap<DeviceId, WriterCursor>,
    /// Records per page, from `max_records` ([`page_limit`]).
    pub page_limit: usize,
}

impl ServeRequest {
    /// The typed form of a request that parsed.
    #[must_use]
    pub fn of(request: &IndexRequest) -> Self {
        Self {
            request_id: request.request_id,
            scope: Scope::of(request),
            cursors: request
                .have
                .iter()
                .filter_map(WriterCursor::from_wire)
                .map(|c| (c.writer, c))
                .collect(),
            page_limit: page_limit(request.max_records),
        }
    }

    /// The requester's cursor for `writer`: `(0, None)` when it is absent.
    #[must_use]
    pub fn requester(&self, writer: &DeviceId) -> (u64, Option<WriterDigest>) {
        self.cursors
            .get(writer)
            .map_or((0, None), |c| (c.seq, c.digest))
    }
}

/// The bytes of an `IndexRecords` frame that are not its records, at most:
/// the frame's type (2), the folder ID (tag, length, 32 bytes), `more` (tag
/// and `true`) and the widest `request_id` (tag and the five-byte varint of
/// `u32::MAX`). A page fits when this plus each record's
/// [`encoded_record_len`] is at most the requester's `max_message_size`.
pub const PAGE_FIXED_OVERHEAD: usize = 2 + 34 + 2 + 6;

/// The bytes `record` takes on a page: its tag, its length varint and its
/// encoding.
#[must_use]
pub fn encoded_record_len(record: &SignedRecord) -> usize {
    let len = crate::record::envelope_len(record);
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// A responder's pages for one request, or a pusher's pages of newly
/// accepted records (4.5, "Pages"). It ends the page before a record when the
/// page already holds one and the record would take it past the page limit,
/// or the frame past the requester's `max_message_size`; an empty page always
/// takes the next record, which fits by section 2's sizing. A page may end
/// anywhere, two records of one writer at one `seq` included.
#[derive(Clone, Debug)]
pub struct Pager {
    page_limit: usize,
    max_bytes: usize,
    records: Vec<Vec<u8>>,
    bytes: usize,
}

impl Pager {
    /// Pages of at most `page_limit` records (a reply's [`page_limit`], or
    /// `MAX_PAGE_RECORDS` for a push) for a peer that accepts frames of
    /// `max_message_size`.
    #[must_use]
    pub fn new(page_limit: usize, max_message_size: u32) -> Self {
        Self {
            page_limit: page_limit.clamp(1, MAX_PAGE_RECORDS),
            max_bytes: usize::try_from(max_message_size)
                .unwrap_or(usize::MAX)
                .saturating_sub(PAGE_FIXED_OVERHEAD),
            records: Vec::new(),
            bytes: 0,
        }
    }

    /// Adds the next record. `Ok(true)` when it went on the current page;
    /// `Ok(false)` when the page must be sent first (take it with
    /// [`Pager::page`], then add the record again, which an empty page always
    /// takes).
    ///
    /// # Errors
    /// [`BuildError::DoesNotFit`] for a record that does not fit an empty page.
    pub fn push(&mut self, record: &SignedRecord) -> Result<bool, BuildError> {
        let size = encoded_record_len(record);
        if size > self.max_bytes {
            return Err(BuildError::DoesNotFit);
        }
        if !self.records.is_empty()
            && (self.records.len() >= self.page_limit || self.bytes + size > self.max_bytes)
        {
            return Ok(false);
        }
        self.records.push(record.to_bytes());
        self.bytes += size;
        Ok(true)
    }

    /// Takes the current page; `more` when another page of the same reply
    /// follows (never for a push, `request_id = 0`).
    pub fn page(&mut self, folder: &FolderId, request_id: u32, more: bool) -> IndexRecords {
        self.bytes = 0;
        IndexRecords {
            folder_id: folder.0.to_vec(),
            records: core::mem::take(&mut self.records),
            more,
            request_id,
        }
    }
}

#[cfg(test)]
mod tests;
