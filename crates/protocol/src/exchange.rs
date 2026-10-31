// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index exchange's pure parts (`protocol.md` 4.5): the prefixes that
//! name subtrees of the set-digest trie, the three conditions by which a
//! responder answers a `ReconcileRequest`, the page limit of a request and
//! the [`Pager`] that fills pages. The index supplies its digests and the
//! stored cursor of a peer ([`IndexView`]) and its records; the connection
//! ([`crate::connection`]) keeps the per-connection state (rounds, passes and
//! their work list, cursors and their counting, the round owed, one request
//! at a time). Nothing here grows with the number of records past one page.

use core::fmt;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{DeviceId, FolderId, SetDigest};

use crate::limits::{
    KEY_BYTES, MAX_PAGE_RECORDS, MAX_PREFIX_NIBBLES, MIN_PAGE_RECORDS, RECONCILE_LEAF_MAX,
};
use crate::messages::{IndexRecords, ReconcileOutcome};
use crate::parse::is_prefix;

/// Why an exchange helper refused what the engine built from its own index:
/// the engine is at fault, never the peer, so nothing is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// A record that does not fit an empty page; records within the spec's
    /// caps never are one (section 2's sizing).
    DoesNotFit,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoesNotFit => f.write_str("a record that does not fit an empty page"),
        }
    }
}

impl std::error::Error for BuildError {}

/// A record's key in the set digests (4.5, "Set digests"): an index
/// record's path tag followed by its record hash, a cleanup's record hash
/// twice; unique per record.
pub type Key = [u8; KEY_BYTES];

/// The nibble of `key` at position `i` (0 to 127), high nibble first: the
/// digit by which the set-digest trie descends at depth `i` (4.5).
#[must_use]
pub fn nibble(key: &Key, i: usize) -> u8 {
    key.get(i / 2)
        .map_or(0, |b| if i % 2 == 0 { b >> 4 } else { b & 0x0f })
}

/// A subtree of the set-digest trie (4.5): the leading nibbles of a record's
/// [`Key`], 0 to 128 of them, high nibble first. The empty prefix is the
/// root; a prefix of 128 nibbles names one record's key. Held packed two
/// nibbles to a byte, as in a key (65 bytes in all), so that a pass's work
/// list of up to 1 921 prefixes stays small.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Prefix {
    /// The nibbles two to a byte, high first; every nibble past `len` is 0.
    packed: [u8; KEY_BYTES],
    len: u8,
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prefix(")?;
        for n in self.nibbles() {
            write!(f, "{n:x}")?;
        }
        f.write_str(")")
    }
}

impl Default for Prefix {
    fn default() -> Self {
        Self::ROOT
    }
}

impl Prefix {
    /// The root: every record.
    pub const ROOT: Self = Self {
        packed: [0; KEY_BYTES],
        len: 0,
    };

    /// The prefix a `ReconcileRequest` carries, or `None` for one over 128
    /// bytes or holding a value above 15 (malformed).
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if !is_prefix(bytes) {
            return None;
        }
        let mut p = Self {
            len: u8::try_from(bytes.len()).ok()?,
            ..Self::ROOT
        };
        for (i, n) in bytes.iter().enumerate() {
            p.set(i, *n);
        }
        Some(p)
    }

    /// The prefix of the first `len` nibbles of `key` (`len` at most 128).
    #[must_use]
    pub fn of_key(key: &Key, len: usize) -> Self {
        let len = len.min(MAX_PREFIX_NIBBLES);
        let mut p = Self {
            len: u8::try_from(len).unwrap_or(0),
            ..Self::ROOT
        };
        for (i, b) in p.packed.iter_mut().enumerate().take(len.div_ceil(2)) {
            *b = key.get(i).copied().unwrap_or(0);
        }
        if len % 2 == 1 {
            if let Some(b) = p.packed.get_mut(len / 2) {
                *b &= 0xf0;
            }
        }
        p
    }

    /// Writes nibble `n` (at most 15) at position `i`, which must be 0.
    fn set(&mut self, i: usize, n: u8) {
        if let Some(b) = self.packed.get_mut(i / 2) {
            *b |= if i % 2 == 0 { n << 4 } else { n & 0x0f };
        }
    }

    /// The wire form: one byte per nibble.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        self.nibbles().collect()
    }

    /// The nibbles, high first.
    pub fn nibbles(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        (0..self.depth()).map(|i| nibble(&self.packed, i))
    }

    /// The number of nibbles: the subtree's depth, 0 for the root.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.len as usize
    }

    /// Whether this is the root.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.len == 0
    }

    /// Whether this is a full key: 128 nibbles, at most one record.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len as usize == MAX_PREFIX_NIBBLES
    }

    /// The child at `nibble` (0 to 15), or `None` at full depth or for a value
    /// above 15.
    #[must_use]
    pub fn child(&self, nibble: u8) -> Option<Self> {
        if self.is_full() || nibble > 15 {
            return None;
        }
        let mut next = *self;
        next.set(self.depth(), nibble);
        next.len += 1;
        Some(next)
    }

    /// Whether `key` begins with these nibbles: the record lies in this
    /// subtree.
    #[must_use]
    pub fn contains(&self, key: &Key) -> bool {
        let (lo, hi) = self.bounds();
        lo <= *key && *key <= hi
    }

    /// The least and the greatest key in this subtree, for a range scan over
    /// keys in order.
    #[must_use]
    pub fn bounds(&self) -> (Key, Key) {
        let lo = self.packed;
        let mut hi = [0xffu8; KEY_BYTES];
        let whole = self.depth() / 2;
        for (h, l) in hi.iter_mut().zip(&lo).take(whole) {
            *h = *l;
        }
        if self.depth() % 2 == 1 {
            if let (Some(h), Some(l)) = (hi.get_mut(whole), lo.get(whole)) {
                *h = l | 0x0f;
            }
        }
        (lo, hi)
    }
}

/// What a responder answers a `ReconcileRequest` for a prefix of
/// `prefix_depth` nibbles and digest `requested`, its own subtree there having
/// digest `own` and holding `records` records ("Serving a
/// `ReconcileRequest`", 4.5): `EQUAL` when the digests are equal; otherwise
/// `RECORDS` when `requested` is 32 zero bytes (the requester holds nothing
/// there), the prefix has 128 nibbles, or its own subtree is empty or in leaf
/// form (at most `RECONCILE_LEAF_MAX` records); otherwise `CHILDREN`.
#[must_use]
pub fn reconcile_outcome(
    prefix_depth: usize,
    requested: &SetDigest,
    own: &SetDigest,
    records: usize,
) -> ReconcileOutcome {
    if requested == own {
        ReconcileOutcome::Equal
    } else if requested.is_empty()
        || prefix_depth >= MAX_PREFIX_NIBBLES
        || records <= RECONCILE_LEAF_MAX
    {
        ReconcileOutcome::Records
    } else {
        ReconcileOutcome::Children
    }
}

/// What the connection reads of this side's index as a requester (4.5): the
/// digest of any subtree (from the index's cache, or, for a child of a
/// subtree in leaf form, computed from its at most 64 records), and the
/// stored cursor of a peer, the peer's epoch and local sequence through which
/// this side holds what the peer held.
pub trait IndexView {
    /// The set digest of the subtree at `prefix`: 32 zero bytes when it holds
    /// nothing.
    fn digest(&self, prefix: &Prefix) -> SetDigest;

    /// The stored cursor for `peer`, by the device ID its `DeviceProof`
    /// proved: `(epoch, cursor)`, or `None` when this side holds no state for
    /// it.
    fn peer_cursor(&self, peer: &DeviceId) -> Option<(u64, u64)>;
}

/// The page limit a responder serves for a request's `max_records` (4.5): 0,
/// or a value above `MAX_PAGE_RECORDS`, means 4 096, and a value below 64
/// means 64, so that no requester can pin a responder with one-record pages.
/// A `RECORDS` reply's limit is `MAX_PAGE_RECORDS`.
#[must_use]
pub fn page_limit(max_records: u32) -> usize {
    let n = usize::try_from(max_records).unwrap_or(MAX_PAGE_RECORDS);
    if n == 0 || n > MAX_PAGE_RECORDS {
        MAX_PAGE_RECORDS
    } else {
        n.max(MIN_PAGE_RECORDS)
    }
}

/// The bytes of an `IndexRecords` frame that are not its records, at most:
/// the frame's type (2), the folder ID (tag, length, 32 bytes), `more` (tag
/// and `true`), the widest `request_id` (tag and the five-byte varint of
/// `u32::MAX`), the `epoch` (tag and eight bytes), the widest `through` (tag
/// and the nine-byte varint of `MAX_LOCAL_SEQ`) and `reset` (tag and `true`).
/// A page fits when this plus each record's [`encoded_record_len`] is at most
/// the requester's `max_message_size`.
pub const PAGE_FIXED_OVERHEAD: usize = 2 + 34 + 2 + 6 + 9 + 10 + 2;

/// The bytes `record` takes on a page: its tag, its length varint and its
/// encoding.
#[must_use]
pub fn encoded_record_len(record: &SignedRecord) -> usize {
    let len = crate::record::envelope_len(record);
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// A responder's pages for one request, or a pusher's pages of records it came
/// to hold (4.5, "Pages"). It ends the page before a record when the page
/// already holds one and the record would take it past the page limit, or the
/// frame past the requester's `max_message_size`; an empty page always takes
/// the next record, which fits by section 2's sizing.
#[derive(Clone, Debug)]
pub struct Pager {
    page_limit: usize,
    max_bytes: usize,
    records: Vec<Vec<u8>>,
    bytes: usize,
}

impl Pager {
    /// Pages of at most `page_limit` records (a reply's [`page_limit`], or
    /// `MAX_PAGE_RECORDS` for a push or a `RECORDS` reply) for a peer that
    /// accepts frames of `max_message_size`.
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

    /// The records on the current page.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the current page holds no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Takes the current page: `more` when another page of the same reply
    /// follows (never for a push, `request_id = 0`), `epoch` this side's
    /// index epoch and `through` the local sequence the receiver may count
    /// through (0 for none: a `RECORDS` page or a reconciliation's push).
    pub fn page(
        &mut self,
        folder: &FolderId,
        request_id: u32,
        more: bool,
        epoch: u64,
        through: u64,
    ) -> IndexRecords {
        self.bytes = 0;
        IndexRecords {
            folder_id: folder.0.to_vec(),
            records: core::mem::take(&mut self.records),
            more,
            request_id,
            epoch,
            through,
            reset: false,
        }
    }
}

/// The one page of a reset (4.5, "Serving an `IndexRequest`"): no records,
/// `more` and `through` not set, `reset` set, this side's `epoch`.
#[must_use]
pub fn reset_page(folder: &FolderId, request_id: u32, epoch: u64) -> IndexRecords {
    IndexRecords {
        folder_id: folder.0.to_vec(),
        records: Vec::new(),
        more: false,
        request_id,
        epoch,
        through: 0,
        reset: true,
    }
}

#[cfg(test)]
mod tests;
