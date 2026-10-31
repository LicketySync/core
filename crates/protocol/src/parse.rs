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
//! tier is the folder proof's (3.5 step 4, REJECTED rather than closed); which
//! request a reply answers, and so whether its `through`, `reset` or kind fits,
//! is the connection's (4.5); and every check of `SealedMeta` and
//! `CleanupMeta` beyond the wire format is step 7's ([`crate::record`]), each
//! a writer fault of its own, so their parsers here are lax on sizes and
//! counts and strict only on the wire format.

use crate::features::{is_feature_name, is_list_entry};
use crate::limits::{
    CLEANUP_RECORD_TYPE, DEVICE_SIGNATURE_LEN, HINT_LEN, INDEX_RECORD_TYPE, MAX_CHUNKS,
    MAX_CLEANUP_ENTRIES, MAX_CLEANUP_GROUPS, MAX_CLEANUP_SEALED_BYTES, MAX_CLOCK_DAYS,
    MAX_CLOSE_DETAIL_BYTES, MAX_DEVICE_NAME_BYTES, MAX_FEATURES, MAX_FEATURE_NAME_BYTES,
    MAX_INDEX_RECORD_BYTES, MAX_LIST_ENTRIES, MAX_LIST_ENTRY_BYTES, MAX_LOCAL_SEQ,
    MAX_PAGE_RECORDS, MAX_PREFIX_NIBBLES, MAX_PROOF_SEALED, MAX_REPLACES, MAX_SEALED_BYTES,
    MAX_STATUS_FOLDERS, MAX_STORED_LEN, MAX_SUITES, MAX_VECTOR_ENTRIES, MIN_PROOF_SEALED,
    MIN_STORED_LEN, PRE_HELLO_LIMIT, PROOF_NONCE_LEN,
};
use crate::messages::{
    ChunkRef, ChunkReply, ChunkRequest, ChunkStatus, CleanupGroup, CleanupMeta, CleanupRecord,
    Close, DeviceProof, FolderProof, FolderStatus, Hello, IndexRecord, IndexRecords, IndexRequest,
    ProofPayload, ProofResult, ProofStatus, ReconcileOutcome, ReconcileReply, ReconcileRequest,
    SealedMeta, Status, Unsupported, VectorEntry,
};
use crate::wire::{empty_or_exact, exact, push_bounded, room, Reader, Seen, WireError, WireType};
use licketysync_keys::records::SignedRecord;
use licketysync_keys::sealed_meta::SealedKind;

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
            seen.check(field, &[1, 7, 8, 9, 10, 11])?;
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
                11 => m.clock_days = r.uint32(wt, field, "clock_days")?,
                // Field 2 is reserved (it was `device_name`) and, like any
                // unknown field, skipped.
                _ => r.skip(wt)?,
            }
        }
        if m.suites.iter().any(|s| !is_suite_number(*s)) {
            return Err(WireError::OutOfRange { what: "suites" });
        }
        if m.clock_days > MAX_CLOCK_DAYS {
            return Err(WireError::OutOfRange { what: "clock_days" });
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
/// record type 16 or 17 of the body's common prefix), which every embedded record
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

/// A list of fingerprints that must be ascending without repeats (`keys.md`
/// 5.2 rule 5; `protocol.md` 4.4 step 1).
fn ascending(list: &[Vec<u8>], what: &'static str) -> Result<(), WireError> {
    if list.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
        Ok(())
    } else {
        Err(WireError::Grammar { what })
    }
}

/// One 32-byte fingerprint of a list, appended under the list's bound.
fn fingerprint(
    r: &mut Reader<'_>,
    wt: WireType,
    field: u32,
    what: &'static str,
    limit: usize,
    into: &mut Vec<Vec<u8>>,
) -> Result<(), WireError> {
    room(into, limit, what)?;
    let hash = r.bytes(wt, field, what, ID)?;
    exact(hash, ID, what)?;
    into.push(hash.to_vec());
    Ok(())
}

impl Parse for IndexRecord {
    /// An index record body under step 1's context-free checks (4.4): the
    /// suite a suite number, the record type 16, the folder ID and the path
    /// tag of 32 bytes, at most `MAX_REPLACES` names of 32 bytes, ascending
    /// without repeats, at most `MAX_CHUNKS` chunk references each with its
    /// 32-byte hash and a stored length that is a Padmé length plus 40, and a
    /// sealed part of 40 bytes plus a power of two from 256 to 2^21.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 13, 15])?;
            match field {
                1 => m.suite = r.uint32(wt, field, "suite")?,
                2 => m.record_type = r.uint32(wt, field, "record_type")?,
                3 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                12 => {
                    room(&m.chunks, MAX_CHUNKS, "chunks")?;
                    let sub = r.bytes(wt, field, "chunks", usize::MAX)?;
                    m.chunks.push(ChunkRef::parse(sub)?);
                }
                13 => m.sealed = to_vec(r.bytes(wt, field, "sealed", MAX_SEALED_BYTES)?),
                15 => m.path_tag = to_vec(r.bytes(wt, field, "path_tag", ID)?),
                17 => fingerprint(&mut r, wt, field, "replaces", MAX_REPLACES, &mut m.replaces)?,
                // Fields 4 to 11, 14 and 16 are reserved: skipped here, kept
                // in the body, which is forwarded as received.
                _ => r.skip(wt)?,
            }
        }
        if !is_suite_number(m.suite) {
            return Err(WireError::OutOfRange { what: "suite" });
        }
        if m.record_type != INDEX_RECORD_TYPE {
            return Err(WireError::OutOfRange {
                what: "record_type",
            });
        }
        exact(&m.folder_id, ID, "folder_id")?;
        exact(&m.path_tag, ID, "path_tag")?;
        ascending(&m.replaces, "replaces: ascending, no repeats")?;
        if !SealedKind::Index.is_sealed_len(m.sealed.len()) {
            return Err(WireError::OutOfRange { what: "sealed" });
        }
        Ok(m)
    }
}

/// One cleanup group, its names counted against `budget`, what is left of
/// `MAX_CLEANUP_ENTRIES` for the record.
fn cleanup_group(body: &[u8], budget: &mut usize) -> Result<CleanupGroup, WireError> {
    let mut r = Reader::new(body);
    let mut m = CleanupGroup::default();
    let mut seen = Seen::default();
    while let Some((field, wt)) = r.next_tag()? {
        seen.check(field, &[1])?;
        match field {
            1 => m.because = to_vec(r.bytes(wt, field, "groups.because", ID)?),
            2 => {
                if *budget == 0 {
                    return Err(WireError::LimitExceeded {
                        what: "groups.forget",
                        limit: MAX_CLEANUP_ENTRIES,
                        offered: u64::try_from(MAX_CLEANUP_ENTRIES + 1).unwrap_or(u64::MAX),
                    });
                }
                fingerprint(
                    &mut r,
                    wt,
                    field,
                    "groups.forget",
                    MAX_CLEANUP_ENTRIES,
                    &mut m.forget,
                )?;
                *budget -= 1;
            }
            _ => r.skip(wt)?,
        }
    }
    empty_or_exact(&m.because, ID, "groups.because")?;
    ascending(&m.forget, "groups.forget: ascending, no repeats")?;
    Ok(m)
}

impl Parse for CleanupGroup {
    /// One cleanup group on its own, under the bounds a cleanup puts on it:
    /// `because` empty or 32 bytes, at most `MAX_CLEANUP_ENTRIES` names of 32
    /// bytes, ascending without repeats (the fuzz target's entry point; a
    /// cleanup's groups share one budget of names).
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut budget = MAX_CLEANUP_ENTRIES;
        cleanup_group(body, &mut budget)
    }
}

impl Parse for CleanupRecord {
    /// A cleanup body under step 1's context-free checks (4.4): the suite a
    /// suite number, the record type 17, the folder ID of 32 bytes, 1 to
    /// `MAX_CLEANUP_GROUPS` groups, each `because` empty or 32 bytes, 1 to
    /// `MAX_CLEANUP_ENTRIES` names in all, each of 32 bytes and ascending
    /// without repeats within its group, and a sealed part of 296, 552 or
    /// 1 064 bytes.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        let mut budget = MAX_CLEANUP_ENTRIES;
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 5])?;
            match field {
                1 => m.suite = r.uint32(wt, field, "suite")?,
                2 => m.record_type = r.uint32(wt, field, "record_type")?,
                3 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                4 => {
                    room(&m.groups, MAX_CLEANUP_GROUPS, "groups")?;
                    let sub = r.bytes(wt, field, "groups", usize::MAX)?;
                    m.groups.push(cleanup_group(sub, &mut budget)?);
                }
                5 => m.sealed = to_vec(r.bytes(wt, field, "sealed", MAX_CLEANUP_SEALED_BYTES)?),
                _ => r.skip(wt)?,
            }
        }
        if !is_suite_number(m.suite) {
            return Err(WireError::OutOfRange { what: "suite" });
        }
        if m.record_type != CLEANUP_RECORD_TYPE {
            return Err(WireError::OutOfRange {
                what: "record_type",
            });
        }
        exact(&m.folder_id, ID, "folder_id")?;
        if m.groups.is_empty() {
            return Err(WireError::Grammar {
                what: "a cleanup with no group",
            });
        }
        if budget == MAX_CLEANUP_ENTRIES {
            return Err(WireError::Grammar {
                what: "a cleanup with no name",
            });
        }
        if !SealedKind::Cleanup.is_sealed_len(m.sealed.len()) {
            return Err(WireError::OutOfRange { what: "sealed" });
        }
        Ok(m)
    }
}

impl Parse for VectorEntry {
    /// One vector entry, lax on its sizes: step 7 judges them.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2])?;
            match field {
                1 => m.device_id = to_vec(r.bytes(wt, field, "vector.device_id", usize::MAX)?),
                2 => m.counter = r.uint64(wt, field)?,
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

impl Parse for SealedMeta {
    /// The opened metadata of a record (4.4 step 7). Only the wire format is
    /// judged here (each field once, the wire types, `bool`s and `uint32`s in
    /// range, valid UTF-8, plaintext hashes of 32 bytes and at most
    /// `MAX_CHUNKS`); a failure here is "metadata that does not parse". The
    /// sizes and values of the device ID, the counter and the vector are step
    /// 7's checks, each a writer fault of its own: entries past the 33rd are
    /// read and skipped, so that a vector of more than `MAX_VECTOR_ENTRIES` is
    /// still told as such without being held whole.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 4, 5, 7, 8, 9, 11, 12])?;
            match field {
                1 => m.path = r.string(wt, field, "path", usize::MAX)?,
                2 => m.kind = r.uint32(wt, field, "kind")?,
                3 => m.size = r.uint64(wt, field)?,
                4 => m.mtime_ns = r.int64(wt, field)?,
                5 => m.mode = r.uint32(wt, field, "mode")?,
                6 => fingerprint(
                    &mut r,
                    wt,
                    field,
                    "plain_hashes",
                    MAX_CHUNKS,
                    &mut m.plain_hashes,
                )?,
                7 => m.written_at = r.uint64(wt, field)?,
                8 => m.device_id = to_vec(r.bytes(wt, field, "device_id", usize::MAX)?),
                9 => m.counter = r.uint64(wt, field)?,
                10 => {
                    let sub = r.bytes(wt, field, "vector", usize::MAX)?;
                    let entry = VectorEntry::parse(sub)?;
                    if m.vector.len() <= MAX_VECTOR_ENTRIES {
                        m.vector.push(entry);
                    }
                }
                11 => m.deleted = r.boolean(wt, field, "deleted")?,
                12 => m.tree = r.boolean(wt, field, "tree")?,
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

impl Parse for CleanupMeta {
    /// A cleanup's opened metadata (4.4 step 7): the wire format only; the
    /// device ID's size and the counter's range are step 7's checks.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2])?;
            match field {
                1 => m.device_id = to_vec(r.bytes(wt, field, "device_id", usize::MAX)?),
                2 => m.counter = r.uint64(wt, field)?,
                _ => r.skip(wt)?,
            }
        }
        Ok(m)
    }
}

impl Parse for IndexRequest {
    /// A request under 4.5: the folder ID's 32 bytes, a `request_id` of at
    /// least 1, an `epoch` that is not 0, and a `since` of at most
    /// `MAX_LOCAL_SEQ`. Fields 2, 5, 6 and 7 are reserved (the drafts'
    /// cursors and ranges) and skipped.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 3, 4, 8, 9])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                3 => m.max_records = r.uint32(wt, field, "max_records")?,
                4 => m.request_id = r.uint32(wt, field, "request_id")?,
                8 => m.epoch = r.fixed64(wt, field)?,
                9 => m.since = r.uint64(wt, field)?,
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folder_id")?;
        if m.request_id == 0 {
            return Err(WireError::OutOfRange { what: "request_id" });
        }
        if m.epoch == 0 {
            return Err(WireError::OutOfRange { what: "epoch" });
        }
        if m.since > MAX_LOCAL_SEQ {
            return Err(WireError::OutOfRange { what: "since" });
        }
        Ok(m)
    }
}

/// A `ReconcileRequest`'s prefix: at most 128 bytes, each a nibble (0 to 15).
#[must_use]
pub fn is_prefix(prefix: &[u8]) -> bool {
    prefix.len() <= MAX_PREFIX_NIBBLES && prefix.iter().all(|n| *n <= 15)
}

impl Parse for ReconcileRequest {
    /// A request under 4.5: the folder ID's 32 bytes, a `request_id` of at
    /// least 1, a prefix of at most 128 nibbles, and a 32-byte digest.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 4])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                2 => m.request_id = r.uint32(wt, field, "request_id")?,
                3 => m.prefix = to_vec(r.bytes(wt, field, "prefix", MAX_PREFIX_NIBBLES)?),
                4 => m.digest = to_vec(r.bytes(wt, field, "digest", ID)?),
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folder_id")?;
        exact(&m.digest, ID, "digest")?;
        if m.request_id == 0 {
            return Err(WireError::OutOfRange { what: "request_id" });
        }
        if !is_prefix(&m.prefix) {
            return Err(WireError::OutOfRange { what: "prefix" });
        }
        Ok(m)
    }
}

impl Parse for ReconcileReply {
    /// A reply under 4.5: the folder ID's 32 bytes, an `outcome` of 1 to 3,
    /// exactly 16 children of 32 bytes on `CHILDREN` and none on another
    /// outcome, an `epoch` that is not 0, and a `through` of at most
    /// `MAX_LOCAL_SEQ`. Whether it answers a request outstanding, and whether
    /// `through` may be set for its prefix, is the connection's.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 5, 6])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
                2 => m.request_id = r.uint32(wt, field, "request_id")?,
                3 => m.outcome = r.uint32(wt, field, "outcome")?,
                4 => fingerprint(&mut r, wt, field, "children", 16, &mut m.children)?,
                5 => m.epoch = r.fixed64(wt, field)?,
                6 => m.through = r.uint64(wt, field)?,
                _ => r.skip(wt)?,
            }
        }
        exact(&m.folder_id, ID, "folder_id")?;
        let outcome = ReconcileOutcome::from_u32(m.outcome)
            .ok_or(WireError::OutOfRange { what: "outcome" })?;
        let children = if outcome == ReconcileOutcome::Children {
            16
        } else {
            0
        };
        if m.children.len() != children {
            return Err(WireError::Grammar {
                what: "children: 16 on CHILDREN, none otherwise",
            });
        }
        if m.epoch == 0 {
            return Err(WireError::OutOfRange { what: "epoch" });
        }
        if m.through > MAX_LOCAL_SEQ {
            return Err(WireError::OutOfRange { what: "through" });
        }
        Ok(m)
    }
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
    /// The sender's index epoch, never 0.
    pub(crate) epoch: u64,
    /// A local sequence of the sender's to count through, or 0.
    pub(crate) through: u64,
    /// A reset page.
    pub(crate) reset: bool,
}

/// The fields of an `IndexRecords` other than its records.
#[derive(Default)]
struct PageFields {
    folder_id: Vec<u8>,
    more: bool,
    request_id: u32,
    epoch: u64,
    through: u64,
    reset: bool,
}

/// Reads an `IndexRecords` body, handing each embedded record, decoded once,
/// to `keep`, under every rule of 4.5 the page alone decides: at most
/// `MAX_PAGE_RECORDS` records, the folder ID's 32 bytes, an `epoch` that is
/// not 0, a `through` of at most `MAX_LOCAL_SEQ`; no push with `more` or
/// `reset`; no page with `more` that holds no record (an honest responder ends
/// a page before a record only when the page already holds one); and no
/// `reset` with records, `more` or `through`.
fn records_page<T>(
    body: &[u8],
    mut keep: impl FnMut(&[u8], SignedRecord) -> T,
) -> Result<(PageFields, Vec<T>), WireError> {
    let mut r = Reader::new(body);
    let mut f = PageFields::default();
    let mut records = Vec::new();
    let mut seen = Seen::default();
    while let Some((field, wt)) = r.next_tag()? {
        seen.check(field, &[1, 3, 4, 5, 6, 7])?;
        match field {
            1 => f.folder_id = to_vec(r.bytes(wt, field, "folder_id", ID)?),
            2 => {
                room(&records, MAX_PAGE_RECORDS, "records")?;
                let (raw, signed) = signed_record(&mut r, wt, field)?;
                records.push(keep(raw, signed));
            }
            3 => f.more = r.boolean(wt, field, "more")?,
            4 => f.request_id = r.uint32(wt, field, "request_id")?,
            5 => f.epoch = r.fixed64(wt, field)?,
            6 => f.through = r.uint64(wt, field)?,
            7 => f.reset = r.boolean(wt, field, "reset")?,
            _ => r.skip(wt)?,
        }
    }
    exact(&f.folder_id, ID, "folder_id")?;
    let grammar = |what| Err(WireError::Grammar { what });
    if f.epoch == 0 {
        return Err(WireError::OutOfRange { what: "epoch" });
    }
    if f.through > MAX_LOCAL_SEQ {
        return Err(WireError::OutOfRange { what: "through" });
    }
    if f.request_id == 0 && (f.more || f.reset) {
        return grammar("a push with more or reset");
    }
    if f.more && records.is_empty() {
        return grammar("a page with more and no records");
    }
    if f.reset && (!records.is_empty() || f.more || f.through != 0) {
        return grammar("a reset with records, more or through");
    }
    Ok((f, records))
}

/// The connection's decoder of an `IndexRecords` body ([`RecordsPage`]).
pub(crate) fn parse_records_page(body: &[u8]) -> Result<RecordsPage, WireError> {
    let (f, records) = records_page(body, |_, signed| signed)?;
    Ok(RecordsPage {
        folder_id: f.folder_id,
        records,
        more: f.more,
        request_id: f.request_id,
        epoch: f.epoch,
        through: f.through,
        reset: f.reset,
    })
}

impl Parse for IndexRecords {
    /// A page or push under the rules of 4.5 the page alone decides (at most
    /// `MAX_PAGE_RECORDS` records, an `epoch` that is not 0, a `through` of
    /// at most `MAX_LOCAL_SEQ`, no push with `more` or `reset`, no page with
    /// `more` and no record, no `reset` with records, `more` or `through`), each record
    /// accepted by the keys crate's envelope decoder and kept as the bytes
    /// received.
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let (f, records) = records_page(body, |raw, _| raw.to_vec())?;
        Ok(Self {
            folder_id: f.folder_id,
            records,
            more: f.more,
            request_id: f.request_id,
            epoch: f.epoch,
            through: f.through,
            reset: f.reset,
        })
    }
}

impl Parse for FolderStatus {
    fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let mut m = Self::default();
        let mut seen = Seen::default();
        while let Some((field, wt)) = r.next_tag()? {
            seen.check(field, &[1, 2, 3, 4, 5, 6, 7])?;
            match field {
                1 => m.folder_id = to_vec(r.bytes(wt, field, "folders.folder_id", ID)?),
                2 => m.index_records = r.uint64(wt, field)?,
                3 => m.bytes_needed = r.uint64(wt, field)?,
                4 => m.paused = r.boolean(wt, field, "folders.paused")?,
                5 => m.free_disk_bytes = r.uint64(wt, field)?,
                6 => m.chunks_stored = r.uint64(wt, field)?,
                7 => m.extra_versions = r.uint64(wt, field)?,
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
