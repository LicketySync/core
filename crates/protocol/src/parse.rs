// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bounded parsing of every message body (`protocol.md` section 4). Each
//! implementation reads its body through the crate's bounded reader, checking
//! every length and count as the field is read: a list for its bound before
//! each element is pushed, a string for its grammar, a value for its range.
//! After the last field, every fixed-size field (hashes, device IDs, nonces,
//! signatures, digests) is checked present at its exact size, unless the spec
//! lets it be empty: an absent field reads as empty, which is then the wrong
//! size, so it is malformed (section 2). Unknown fields, the drafts' reserved
//! numbers among them, are skipped.
//!
//! What needs context is not judged here: a Hello's device key, nonce and
//! identity sizes and the suite in common are the connection's Hello checks
//! (3.2, with their own close reasons); a record's suite and folder against
//! the open folder are [`crate::record::Record::parse`]'s; a `ProofPayload`'s
//! tier is the folder proof's (3.5 step 4, REJECTED rather than closed); and
//! `SealedMeta`'s path grammar, kind and chunk count are step 6's writer-fault
//! checks.

use crate::features::{is_feature_name, is_list_entry};
use crate::limits::{
    DEVICE_SIGNATURE_LEN, HINT_LEN, MAX_CHUNKS, MAX_CLOSE_DETAIL_BYTES, MAX_CURSORS_PER_REQUEST,
    MAX_DEVICE_NAME_BYTES, MAX_FEATURES, MAX_FEATURE_NAME_BYTES, MAX_INDEX_RECORD_BYTES,
    MAX_LIST_ENTRIES, MAX_LIST_ENTRY_BYTES, MAX_PAGE_RECORDS, MAX_PATH_BYTES, MAX_PROOF_SEALED,
    MAX_SEALED_BYTES, MAX_SEQ, MAX_STATUS_FOLDERS, MAX_STORED_LEN, MAX_SUITES, MAX_SUPERSEDES,
    MIN_PROOF_SEALED, MIN_SEALED_BYTES, MIN_STORED_LEN, PRE_HELLO_LIMIT, PROOF_NONCE_LEN,
};
use crate::messages::{
    ChunkRef, ChunkReply, ChunkRequest, ChunkStatus, Close, Cursor, DeviceProof, FolderProof,
    FolderStatus, Hello, IndexRecord, IndexRecords, IndexRequest, ProofPayload, ProofResult,
    ProofStatus, SealedMeta, Status, Unsupported,
};
use crate::wire::{empty_or_exact, exact, push_bounded, room, Reader, Seen, WireError, WireType};
use licketysync_keys::records::SignedRecord;

/// A message body that parses under its bounds.
pub trait Parse: Sized {
    /// Parses `body`, refusing anything over a bound, of the wrong size or
    /// outside its range.
    ///
    /// # Errors
    /// Any [`WireError`]; the body is malformed and its sender is to blame.
    fn parse(body: &[u8]) -> Result<Self, WireError>;
}

const ID: usize = 32;

/// Whether `n` is a suite number: 1 to 65 535 (`keys.md` 0).
fn is_suite_number(n: u32) -> bool {
    (1..=u32::from(u16::MAX)).contains(&n)
}

/// UTF-8 of at most `limit` bytes with no control character: the grammar of
/// `Status.device_name` and `Close.detail`.
fn text(
    r: &mut Reader<'_>,
    wt: WireType,
    field: u32,
    what: &'static str,
    limit: usize,
) -> Result<String, WireError> {
    let value = r.string(wt, field, what, limit)?;
    if value.chars().any(char::is_control) {
        return Err(WireError::Grammar { what });
    }
    Ok(value)
}

/// Whether `name` is a valid `Status.device_name`: at most 64 bytes, no
/// control characters (`protocol.md` 4.5).
#[must_use]
pub fn is_device_name(name: &str) -> bool {
    name.len() <= MAX_DEVICE_NAME_BYTES && !name.chars().any(char::is_control)
}

fn list_entry(
    r: &mut Reader<'_>,
    wt: WireType,
    field: u32,
    what: &'static str,
    into: &mut Vec<String>,
) -> Result<(), WireError> {
    room(into, MAX_LIST_ENTRIES, what)?;
    let entry = r.string(wt, field, what, MAX_LIST_ENTRY_BYTES)?;
    if !is_list_entry(&entry) {
        return Err(WireError::Grammar { what });
    }
    into.push(entry);
    Ok(())
}

fn feature(
    r: &mut Reader<'_>,
    wt: WireType,
    field: u32,
    into: &mut Vec<String>,
) -> Result<(), WireError> {
    room(into, MAX_FEATURES, "features")?;
    let entry = r.string(wt, field, "features", MAX_FEATURE_NAME_BYTES)?;
    if !is_feature_name(&entry) {
        return Err(WireError::Grammar { what: "features" });
    }
    into.push(entry);
    Ok(())
}

fn to_vec(b: &[u8]) -> Vec<u8> {
    b.to_vec()
}

impl Parse for Hello {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        let any = PRE_HELLO_LIMIT as usize;
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 7, 8, 9, 10])?;
            match field {
                1 => m.device_public_key = to_vec(r.bytes(wt, field, "device_public_key", any)?),
                3 => r.repeated_uint32(wt, field, "suites", MAX_SUITES, &mut m.suites)?,
                4 => list_entry(&mut r, wt, field, "compressions", &mut m.compressions)?,
                5 => list_entry(&mut r, wt, field, "hashes", &mut m.hashes)?,
                6 => feature(&mut r, wt, field, &mut m.features)?,
                7 => m.max_message_size = r.uint32(wt, field, "max_message_size")?,
                8 => m.max_requests_in_flight = r.uint32(wt, field, "max_requests_in_flight")?,
                9 => m.nonce = to_vec(r.bytes(wt, field, "nonce", any)?),
                10 => m.libp2p_identity = to_vec(r.bytes(wt, field, "libp2p_identity", any)?),
                // Field 2 is reserved (it was `device_name`) and, like any
                // unknown field, skipped.
                _ => r.skip(wt)?,
            }
        }
        if m.suites.iter().any(|s| !is_suite_number(*s)) {
            return Err(WireError::OutOfRange { what: "suites" });
        }
        Ok(m)
    }
}

impl Parse for Close {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2])?;
            match field {
                1 => m.reason = r.uint32(wt, field, "reason")?,
                2 => m.detail = text(&mut r, wt, field, "detail", MAX_CLOSE_DETAIL_BYTES)?,
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

/// A Close whose body did not parse, read again for its reason alone: a
/// `detail` that breaks its grammar (too long, not UTF-8, a control
/// character, the wrong wire type, given twice) is dropped, never shown, and
/// the reason the peer gave is still reported. A body that is malformed in
/// any other way gives reason 0 (unspecified). The connection closes either
/// way (4.2).
#[must_use]
pub fn close_without_detail(body: &[u8]) -> Close {
    Close {
        reason: close_reason(body).unwrap_or(0),
        detail: String::new(),
    }
}

fn close_reason(body: &[u8]) -> Result<u32, WireError> {
    let mut r = Reader::new(body);
    let mut seen = Seen::default();
    let mut reason = 0;
    while let Some((field, wt)) = r.next_tag()? {
        seen.check(field, &[1])?;
        match field {
            1 => reason = r.uint32(wt, field, "reason")?,
            _ => r.skip(wt)?,
        }
    }
    Ok(reason)
}

impl Parse for Unsupported {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1])?;
            match field {
                1 => m.message_type = r.uint32(wt, field, "message_type")?,
                _ => r.skip(wt)?,
            }
        }
        if m.message_type > u32::from(u16::MAX) {
            return Err(WireError::OutOfRange {
                what: "message_type",
            });
        }
        Ok(m)
    }
}

impl Parse for DeviceProof {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1])?;
            match field {
                1 => m.signature = to_vec(r.bytes(wt, field, "signature", DEVICE_SIGNATURE_LEN)?),
                _ => r.skip(wt)?,
            }
        }
        exact(&m.signature, DEVICE_SIGNATURE_LEN, "signature")?;
        Ok(m)
    }
}

impl Parse for FolderProof {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3])?;
            match field {
                1 => m.hint = to_vec(r.bytes(wt, field, "hint", HINT_LEN)?),
                2 => m.sealed = to_vec(r.bytes(wt, field, "sealed", MAX_PROOF_SEALED)?),
                3 => m.nonce = to_vec(r.bytes(wt, field, "nonce", PROOF_NONCE_LEN)?),
                _ => r.skip(wt)?,
            }
        }
        exact(&m.hint, HINT_LEN, "hint")?;
        exact(&m.nonce, PROOF_NONCE_LEN, "nonce")?;
        if m.sealed.len() < MIN_PROOF_SEALED {
            return Err(WireError::OutOfRange { what: "sealed" });
        }
        Ok(m)
    }
}

impl Parse for ProofPayload {
    /// The opened payload. A failure here is the folder proof's step 4,
    /// answered REJECTED, never a close; the tier's range is judged there too.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[4])?;
            match field {
                4 => m.tier = r.uint32(wt, field, "tier")?,
                // Fields 1 to 3 are reserved and skipped.
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

impl Parse for ProofResult {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2])?;
            match field {
                1 => m.hint = to_vec(r.bytes(wt, field, "hint", HINT_LEN)?),
                2 => m.status = r.uint32(wt, field, "status")?,
                // Fields 3 and 4 are reserved and skipped.
                _ => r.skip(wt)?,
            }
        }
        exact(&m.hint, HINT_LEN, "hint")?;
        if ProofStatus::from_u32(m.status).is_none() {
            return Err(WireError::OutOfRange { what: "status" });
        }
        Ok(m)
    }
}

/// One `SignedRecord` embedded as field `field`: at most
/// `MAX_INDEX_RECORD_BYTES`, and decoded by the keys crate's strict decoder
/// (`keys.md` 5.1: each field once, no groups, the signature's 64 bytes, the
/// record type 16 of the body's common prefix), which every embedded record
/// passes before anything else reads it (ruling SF6 of the keys review).
/// Returns the raw bytes and the decoded envelope, so that a caller keeps
/// whichever it needs and nothing decodes the record twice.
fn signed_record<'a>(
    r: &mut Reader<'a>,
    wt: WireType,
    field: u32,
) -> Result<(&'a [u8], SignedRecord), WireError> {
    let raw = r.bytes(wt, field, "records", MAX_INDEX_RECORD_BYTES)?;
    Ok((raw, SignedRecord::from_bytes(raw)?))
}

impl Parse for ChunkRef {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2])?;
            match field {
                1 => m.cipher_hash = to_vec(r.bytes(wt, field, "chunks.cipher_hash", ID)?),
                2 => m.stored_len = r.uint32(wt, field, "chunks.stored_len")?,
                // Field 3 is reserved (it was `epoch`) and skipped.
                _ => r.skip(wt)?,
            }
        }
        exact(&m.cipher_hash, ID, "chunks.cipher_hash")?;
        if !is_stored_len(m.stored_len) {
            return Err(WireError::OutOfRange {
                what: "chunks.stored_len",
            });
        }
        Ok(m)
    }
}

/// Whether `n` is a stored chunk length: 46 to 4 325 416, and a Padmé length
/// plus 40 (`keys.md` 3.2).
#[must_use]
pub fn is_stored_len(n: u32) -> bool {
    let n = u64::from(n);
    let padded = n.saturating_sub(40);
    (MIN_STORED_LEN as u64..=MAX_STORED_LEN as u64).contains(&n)
        && licketysync_keys::chunk::padme(padded) == Some(padded)
}

impl Parse for IndexRecord {
    /// An index record body under step 1's context-free checks (4.4): the
    /// suite a suite number, the record type 16, the fixed sizes, `seq` from 1
    /// to `MAX_SEQ`, a tombstone without chunks, at most 16 `supersedes` of 32
    /// bytes, the sealed part's 40 to 1 572 864 bytes, and every chunk
    /// reference's hash and stored length.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 5, 6, 11, 13])?;
            match field {
                1 => m.suite = r.uint32(wt, field, "suite")?,
                2 => m.record_type = r.uint32(wt, field, "record_type")?,
                3 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                5 => m.device_id = to_vec(r.bytes(wt, field, "device_id", ID)?),
                6 => m.seq = r.uint64(wt, field)?,
                8 => {
                    room(&m.supersedes, MAX_SUPERSEDES, "supersedes")?;
                    let hash = r.bytes(wt, field, "supersedes", ID)?;
                    exact(hash, ID, "supersedes")?;
                    m.supersedes.push(hash.to_vec());
                }
                11 => m.deleted = r.boolean(wt, field, "deleted")?,
                12 => {
                    room(&m.chunks, MAX_CHUNKS, "chunks")?;
                    let sub = r.bytes(wt, field, "chunks", usize::MAX)?;
                    m.chunks.push(ChunkRef::parse(sub)?);
                }
                13 => m.sealed = to_vec(r.bytes(wt, field, "sealed", MAX_SEALED_BYTES)?),
                // Fields 4, 7, 9, 10 and 14 are reserved: skipped here, kept
                // in the body, which is forwarded as received.
                _ => r.skip(wt)?,
            }
        }
        if !is_suite_number(m.suite) {
            return Err(WireError::OutOfRange { what: "suite" });
        }
        if m.record_type != crate::limits::INDEX_RECORD_TYPE {
            return Err(WireError::OutOfRange {
                what: "record_type",
            });
        }
        exact(&m.folder_id, ID, "folder_id")?;
        exact(&m.device_id, ID, "device_id")?;
        if !(1..=MAX_SEQ).contains(&m.seq) {
            return Err(WireError::OutOfRange { what: "seq" });
        }
        if m.deleted && !m.chunks.is_empty() {
            return Err(WireError::Grammar {
                what: "deleted with chunks",
            });
        }
        if m.sealed.len() < MIN_SEALED_BYTES {
            return Err(WireError::OutOfRange { what: "sealed" });
        }
        Ok(m)
    }
}

impl Parse for SealedMeta {
    /// The opened metadata of a record whose signature verified. A failure
    /// here is the writer's fault (4.4 step 6), never the sender's.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 4, 5, 7])?;
            match field {
                1 => m.path = r.string(wt, field, "path", MAX_PATH_BYTES)?,
                2 => m.kind = r.uint32(wt, field, "kind")?,
                3 => m.size = r.uint64(wt, field)?,
                4 => m.mtime_ns = r.int64(wt, field)?,
                5 => m.mode = r.uint32(wt, field, "mode")?,
                6 => {
                    room(&m.plain_hashes, MAX_CHUNKS, "plain_hashes")?;
                    let hash = r.bytes(wt, field, "plain_hashes", ID)?;
                    exact(hash, ID, "plain_hashes")?;
                    m.plain_hashes.push(hash.to_vec());
                }
                7 => m.written_at = r.uint64(wt, field)?,
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

impl Parse for Cursor {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[2, 3, 6])?;
            match field {
                2 => m.device_id = to_vec(r.bytes(wt, field, "have.device_id", ID)?),
                3 => m.seq = r.uint64(wt, field)?,
                6 => m.digest = to_vec(r.bytes(wt, field, "have.digest", ID)?),
                // Fields 1, 4 and 5 are reserved and skipped.
                _ => r.skip(wt)?,
            }
        }
        exact(&m.device_id, ID, "have.device_id")?;
        if m.seq > MAX_SEQ {
            return Err(WireError::OutOfRange { what: "have.seq" });
        }
        exact(&m.digest, if m.seq == 0 { 0 } else { ID }, "have.digest")?;
        Ok(m)
    }
}

impl Parse for IndexRequest {
    /// A request under every rule of 4.5 that the request alone decides:
    /// `have` ascending and unique and inside the range, at most
    /// `MAX_CURSORS_PER_REQUEST`, `after < through` when both are set, a listed
    /// request non-empty and without a range, and a `request_id` of at least 1.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 3, 4, 5, 6, 7])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                2 => {
                    room(&m.have, MAX_CURSORS_PER_REQUEST, "have")?;
                    let sub = r.bytes(wt, field, "have", usize::MAX)?;
                    m.have.push(Cursor::parse(sub)?);
                }
                3 => m.max_records = r.uint32(wt, field, "max_records")?,
                4 => m.request_id = r.uint32(wt, field, "request_id")?,
                5 => m.after = to_vec(r.bytes(wt, field, "after", ID)?),
                6 => m.through = to_vec(r.bytes(wt, field, "through", ID)?),
                7 => m.listed = r.boolean(wt, field, "listed")?,
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folder_id")?;
        empty_or_exact(&m.after, ID, "after")?;
        empty_or_exact(&m.through, ID, "through")?;
        if m.request_id == 0 {
            return Err(WireError::OutOfRange { what: "request_id" });
        }
        check_request_shape(&m)?;
        Ok(m)
    }
}

/// The range and list rules of an `IndexRequest` (4.5), on fields whose sizes
/// are already checked.
fn check_request_shape(m: &IndexRequest) -> Result<(), WireError> {
    let grammar = |what| Err(WireError::Grammar { what });
    if m.listed && (m.have.is_empty() || !m.after.is_empty() || !m.through.is_empty()) {
        return grammar("listed: have non-empty, no range");
    }
    if !m.after.is_empty() && !m.through.is_empty() && m.after >= m.through {
        return grammar("after < through");
    }
    let ascending = m
        .have
        .windows(2)
        .all(|w| matches!(w, [a, b] if a.device_id < b.device_id));
    if !ascending {
        return grammar("have: ascending, each writer once");
    }
    let inside = |c: &Cursor| {
        (m.after.is_empty() || c.device_id > m.after)
            && (m.through.is_empty() || c.device_id <= m.through)
    };
    if !m.have.iter().all(inside) {
        return grammar("have: inside the range");
    }
    Ok(())
}

/// An `IndexRecords` body with each embedded record decoded once, by the
/// keys crate's envelope decoder: the form the connection judges (4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordsPage {
    /// 32 bytes.
    pub(crate) folder_id: Vec<u8>,
    /// At most `MAX_PAGE_RECORDS`, in the order sent.
    pub(crate) records: Vec<SignedRecord>,
    /// Another page follows; never on a push, never on a page without records.
    pub(crate) more: bool,
    /// The request answered; 0 for a push.
    pub(crate) request_id: u32,
}

/// Reads an `IndexRecords` body, handing each embedded record, decoded once,
/// to `keep`: at most `MAX_PAGE_RECORDS` records, the folder ID's 32 bytes,
/// no push with `more`, and no page with `more` that holds no record
/// (4.5: an honest responder ends a page before a record only when the page
/// already holds one).
fn records_page<T>(
    body: &[u8],
    mut keep: impl FnMut(&[u8], SignedRecord) -> T,
) -> Result<(Vec<u8>, Vec<T>, bool, u32), WireError> {
    let mut r = Reader::new(body);
    let (mut folder_id, mut records, mut more, mut request_id) = (Vec::new(), Vec::new(), false, 0);
    let mut seen = Seen::default();
    while let Some((field, wt)) = r.next_tag()? {
        seen.check(field, &[1, 3, 4])?;
        match field {
            1 => folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
            2 => {
                room(&records, MAX_PAGE_RECORDS, "records")?;
                let (raw, signed) = signed_record(&mut r, wt, field)?;
                records.push(keep(raw, signed));
            }
            3 => more = r.boolean(wt, field, "more")?,
            4 => request_id = r.uint32(wt, field, "request_id")?,
            _ => r.skip(wt)?,
        }
    }
    exact(&folder_id, ID, "folder_id")?;
    if more && request_id == 0 {
        return Err(WireError::Grammar {
            what: "a push with more",
        });
    }
    if more && records.is_empty() {
        return Err(WireError::Grammar {
            what: "a page with more and no records",
        });
    }
    Ok((folder_id, records, more, request_id))
}

/// The connection's decoder of an `IndexRecords` body ([`RecordsPage`]).
pub(crate) fn parse_records_page(body: &[u8]) -> Result<RecordsPage, WireError> {
    let (folder_id, records, more, request_id) = records_page(body, |_, signed| signed)?;
    Ok(RecordsPage {
        folder_id,
        records,
        more,
        request_id,
    })
}

impl Parse for IndexRecords {
    /// A page or push (4.5): at most `MAX_PAGE_RECORDS` records, each
    /// accepted by the keys crate's envelope decoder and kept as the bytes
    /// received; no push with `more`, and no page with `more` that holds no
    /// record.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let (folder_id, records, more, request_id) = records_page(body, |raw, _| raw.to_vec())?;
        Ok(Self {
            folder_id,
            records,
            more,
            request_id,
        })
    }
}

impl Parse for FolderStatus {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 4, 5, 6])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folders.folder_id", ID)?),
                2 => m.index_records = r.uint64(wt, field)?,
                3 => m.bytes_needed = r.uint64(wt, field)?,
                4 => m.paused = r.boolean(wt, field, "folders.paused")?,
                5 => m.free_disk_bytes = r.uint64(wt, field)?,
                6 => m.chunks_stored = r.uint64(wt, field)?,
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folders.folder_id")?;
        Ok(m)
    }
}

impl Parse for Status {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[2])?;
            match field {
                1 => {
                    let sub = r.bytes(wt, field, "folders", usize::MAX)?;
                    push_bounded(
                        &mut m.folders,
                        FolderStatus::parse(sub)?,
                        MAX_STATUS_FOLDERS,
                        "folders",
                    )?;
                }
                2 => m.device_name = text(&mut r, wt, field, "device_name", MAX_DEVICE_NAME_BYTES)?,
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

impl Parse for ChunkRequest {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                2 => m.cipher_hash = to_vec(r.bytes(wt, field, "cipher_hash", ID)?),
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folder_id")?;
        exact(&m.cipher_hash, ID, "cipher_hash")?;
        Ok(m)
    }
}

impl Parse for ChunkReply {
    /// A reply: `data` at most `MAX_STORED_LEN` (4 325 416) bytes, judged
    /// before anything is hashed, a status of 1 to 3, and `data` present iff
    /// the status is `CHUNK_OK`. The ciphertext hash is the connection's check.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 4])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                2 => m.cipher_hash = to_vec(r.bytes(wt, field, "cipher_hash", ID)?),
                3 => m.status = r.uint32(wt, field, "status")?,
                4 => m.data = to_vec(r.bytes(wt, field, "data", MAX_STORED_LEN)?),
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folder_id")?;
        exact(&m.cipher_hash, ID, "cipher_hash")?;
        let status =
            ChunkStatus::from_u32(m.status).ok_or(WireError::OutOfRange { what: "status" })?;
        if (status == ChunkStatus::Ok) == m.data.is_empty() {
            return Err(WireError::Grammar {
                what: "data iff CHUNK_OK",
            });
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests;
