// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Signed records (`keys.md` section 5): the envelope, the record hash, and
//! signing and verification under the folder key, for the two record types
//! of major 1: the index record (type 16, label `licketysync/v1/sig/index`)
//! and the cleanup (type 17, label `licketysync/v1/sig/cleanup`), whose
//! bodies are the protocol crate's (`protocol.md` 4.4).
//!
//! Every record is signed with the folder's signing key under the label of
//! its record type and verified with `folder_vk`, at every tier, before
//! anything in it is charged to anyone (TM-9). The verifier picks the label
//! from the record type the body declares ([`FolderVerifier::verify_record`]),
//! so a cleanup body signed under the index label, or the reverse, is forged.
//! Verifiers treat the body as opaque bytes: hashed, signed and forwarded
//! exactly as received, never re-encoded. There are no key records: no key
//! ever travels inside a folder.
//!
//! # One parse for the envelope
//!
//! Protocol messages carry every embedded record as raw `bytes`, and the
//! protocol crate reads each one with [`SignedRecord::from_bytes`] and nothing
//! else: [`SignedRecord`] has no other way in (it is not a Protocol Buffers
//! message type that a lax decoder could fill), so the checks below always
//! run. The strict scan behind them is this crate's own and private to it; the
//! protocol crate keeps its own strict decoder for its messages and for the
//! body's other fields.
//!
//! Of `protocol.md` 4.4 step 1, [`SignedRecord::from_bytes`] judges:
//!
//! - the encoded envelope's size against [`MAX_INDEX_RECORD_BYTES`], before
//!   anything is decoded;
//! - the envelope's shape: fields 1 and 2 at most once each, no group wire
//!   type, no field number above 2^29 − 1, other fields skipped;
//! - the signature's 64 bytes;
//! - the body's common prefix: fields 1 to 3 at most once each, `suite` and
//!   `record_type` within 32 bits, `record_type` 16 or 17 (every other value
//!   is malformed), which [`SignedRecord::record_type`] then exposes; and,
//!   over the whole body, no group wire type and no field number above
//!   2^29 − 1.
//!
//! The rest of step 1 stays the caller's (the protocol crate's), since it
//! needs the open folder or the body's schema: `suite` is the folder's suite;
//! `folder_id` is 32 bytes and is the open folder; for an index record,
//! `path_tag` is 32 bytes, at most 64 `replaces` of 32 bytes each, ascending
//! without repeats, each chunk's `cipher_hash` 32 bytes and `stored_len` in
//! range and a Padmé length plus 40, and `sealed` an allowed length
//! ([`crate::sealed_meta::SealedKind::is_sealed_len`]); for a cleanup, its
//! groups and names within their bounds and `sealed` of 296, 552 or 1 064
//! bytes; no field other than the prefix's occurs twice unless it is
//! repeated; every `bool` is 0 or 1 and every `uint32` fits 32 bits; repeated
//! scalars are read packed or unpacked. Steps 2 to 7 follow:
//! [`SignedRecord::hash`] for the duplicate check,
//! [`FolderVerifier::verify_record`] for the signature, and
//! [`crate::sealed_meta::RecordKeys`] for the seal.

use core::fmt;

use prost::bytes::Buf;

use crate::folder::{FolderVerifier, WriteKey};
use crate::ids::{RecordHash, WriterDigest};
use crate::labels::{self, labelled_hash, SigLabel};
use crate::sig::{self, Signature, SignatureError};

/// The largest encoded [`SignedRecord`] (`protocol.md` 2,
/// `MAX_INDEX_RECORD_BYTES`), judged at parse, before the duplicate check.
pub const MAX_INDEX_RECORD_BYTES: usize = 4_000_000;

/// The `record_type` of an index record (`keys.md` 5.1).
pub const INDEX_RECORD_TYPE: u32 = 16;

/// The `record_type` of a cleanup record (`keys.md` 5.1).
pub const CLEANUP_RECORD_TYPE: u32 = 17;

/// The two record types of major 1 (`keys.md` 5.1). A record type a later
/// release adds gets a label of its own, so a body can never be presented as
/// another type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordType {
    /// An index record, type 16, signed under `licketysync/v1/sig/index`.
    Index,
    /// A cleanup record, type 17, signed under `licketysync/v1/sig/cleanup`.
    Cleanup,
}

impl RecordType {
    /// The `record_type` value: 16 or 17.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            RecordType::Index => INDEX_RECORD_TYPE,
            RecordType::Cleanup => CLEANUP_RECORD_TYPE,
        }
    }

    /// The record type of a `record_type` value, for 16 and 17 only.
    #[must_use]
    pub const fn from_code(code: u32) -> Option<RecordType> {
        match code {
            INDEX_RECORD_TYPE => Some(RecordType::Index),
            CLEANUP_RECORD_TYPE => Some(RecordType::Cleanup),
            _ => None,
        }
    }

    /// The signature label of this record type (`keys.md` 0.2, 5.1).
    const fn label(self) -> SigLabel {
        match self {
            RecordType::Index => labels::SIG_INDEX,
            RecordType::Cleanup => labels::SIG_CLEANUP,
        }
    }
}

/// The signed envelope (section 5.1): a body and the folder key's Ed25519
/// signature over it, and the record type the body declares. The body is kept
/// exactly as received; it is what is hashed, verified, stored and forwarded,
/// never re-encoded. Made only by [`WriteKey::sign_index_record`],
/// [`WriteKey::sign_cleanup_record`] and [`SignedRecord::from_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    body: Vec<u8>,
    signature: Signature,
    record_type: RecordType,
}

/// The envelope as Protocol Buffers carries it. Field 3 was the drafts'
/// `key_signature`; it is reserved and reads as an unknown field. Private, so
/// that nothing outside this module decodes an envelope without the checks of
/// [`SignedRecord::from_bytes`].
#[derive(Clone, PartialEq, Eq, prost::Message)]
struct Envelope {
    #[prost(bytes = "vec", tag = "1")]
    body: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

/// Why a record is malformed: the sender's fault (`protocol.md` 5). Nothing
/// here is charged to a signer: a malformed record is refused before its
/// signature is looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The bytes do not parse as the expected Protocol Buffers message, or
    /// use a group wire type, or a field number above 2^29 − 1.
    Decode,
    /// The encoded envelope is larger than [`MAX_INDEX_RECORD_BYTES`].
    TooLarge(usize),
    /// The body's `record_type` is neither 16 nor 17 (`keys.md` 5.1).
    RecordType(u32),
    /// A field that is not repeated occurs more than once (`protocol.md` 2:
    /// proto3 would keep the last occurrence).
    DuplicateField(u32),
    /// The varint value of the `uint32` field with this number does not fit
    /// 32 bits (prost would keep its low 32 bits).
    VarintRange(u32),
    /// The signature is not 64 bytes.
    SignatureSize(usize),
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode => f.write_str("does not parse"),
            Self::TooLarge(n) => write!(f, "record of {n} bytes is too large"),
            // This wording, from when 16 was the one record type, stays for
            // one commit: the protocol crate's vectors quote it, and the next
            // commit of this series, which rewrites them, rewords it.
            Self::RecordType(n) => write!(f, "record type {n} is not an index record"),
            Self::DuplicateField(n) => write!(f, "field number {n} occurs more than once"),
            Self::VarintRange(n) => write!(f, "the value of field number {n} does not fit 32 bits"),
            Self::SignatureSize(n) => write!(f, "signature is {n} bytes, not 64"),
        }
    }
}

impl std::error::Error for Malformed {}

/// The common prefix of every body: field numbers 1 to 3 mean this in every
/// record type, so a parser can read the suite and type before anything else.
#[derive(Clone, PartialEq, Eq, prost::Message)]
struct Prefix {
    #[prost(uint32, tag = "1")]
    suite: u32,
    #[prost(uint32, tag = "2")]
    record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    folder_id: Vec<u8>,
}

impl SignedRecord {
    /// The body, exactly as signed or received.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The signature, 64 bytes.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The record type: the one the body's prefix declares, for a record from
    /// [`SignedRecord::from_bytes`], and the one its signing function names,
    /// for a record this device signed. [`FolderVerifier::verify_record`]
    /// verifies under its label.
    #[must_use]
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// `record_hash = H("licketysync/v1/hash/record", body)`. Two records with
    /// equal bodies are the same record, whatever their signatures: a receiver
    /// that already holds one ignores the other without verifying it.
    #[must_use]
    pub fn hash(&self) -> RecordHash {
        RecordHash(labelled_hash(labels::HASH_RECORD, &[&self.body]))
    }

    /// The envelope's wire bytes, canonical (`keys.md` 5.2): the body, then
    /// the signature, each length-prefixed, an empty body omitted as proto3
    /// omits a default.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use prost::encoding::bytes;
        let signature = self.signature.as_bytes().to_vec();
        let body_len = if self.body.is_empty() {
            0
        } else {
            bytes::encoded_len(1, &self.body)
        };
        let mut out = Vec::with_capacity(body_len + bytes::encoded_len(2, &signature));
        if !self.body.is_empty() {
            bytes::encode(1, &self.body, &mut out);
        }
        bytes::encode(2, &signature, &mut out);
        out
    }

    /// Decodes an envelope in the order `protocol.md` 2 and `keys.md` 5.1 fix,
    /// with the checks the module documentation lists: the encoded size
    /// against [`MAX_INDEX_RECORD_BYTES`], before anything is decoded; the
    /// envelope's shape; the signature's 64 bytes; and the body's
    /// `record_type`, read strictly from its common prefix, 16 or 17.
    ///
    /// # Errors
    ///
    /// [`Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedRecord, Malformed> {
        if bytes.len() > MAX_INDEX_RECORD_BYTES {
            return Err(Malformed::TooLarge(bytes.len()));
        }
        let envelope: Envelope = decode_strict(bytes, &Shape::new(2, &[]))?;
        let signature = Signature::from_slice(&envelope.signature)
            .ok_or(Malformed::SignatureSize(envelope.signature.len()))?;
        // The prefix's fields are judged strictly here; the rest of the body
        // reads as unknown fields until the protocol crate's parser judges them.
        let prefix: Prefix = decode_strict(&envelope.body, &Shape::new(3, &[1, 2]))?;
        let record_type = RecordType::from_code(prefix.record_type)
            .ok_or(Malformed::RecordType(prefix.record_type))?;
        Ok(SignedRecord {
            body: envelope.body,
            signature,
            record_type,
        })
    }
}

impl WriteKey {
    /// Signs an index record body: `Sign(folder_sk, "licketysync/v1/sig/index",
    /// body)`. The caller encodes the body canonically (section 5.2), with
    /// `record_type` 16.
    ///
    /// # Errors
    ///
    /// [`Malformed`], and nothing is signed, for a body whose common prefix
    /// does not decode as [`SignedRecord::from_bytes`] decodes it, that does
    /// not declare record type 16, or whose envelope would pass
    /// [`MAX_INDEX_RECORD_BYTES`]: so every [`SignedRecord`] declares the type
    /// it was signed for, and reads back as itself.
    pub fn sign_index_record(&self, body: Vec<u8>) -> Result<SignedRecord, Malformed> {
        self.sign_record(RecordType::Index, body)
    }

    /// Signs a cleanup body: `Sign(folder_sk, "licketysync/v1/sig/cleanup",
    /// body)`, the body canonical with `record_type` 17 (section 5.3).
    ///
    /// # Errors
    ///
    /// [`Malformed`], as for [`WriteKey::sign_index_record`], for a body that
    /// does not declare record type 17.
    pub fn sign_cleanup_record(&self, body: Vec<u8>) -> Result<SignedRecord, Malformed> {
        self.sign_record(RecordType::Cleanup, body)
    }

    fn sign_record(
        &self,
        record_type: RecordType,
        body: Vec<u8>,
    ) -> Result<SignedRecord, Malformed> {
        let prefix: Prefix = decode_strict(&body, &Shape::new(3, &[1, 2]))?;
        if RecordType::from_code(prefix.record_type) != Some(record_type) {
            return Err(Malformed::RecordType(prefix.record_type));
        }
        // The envelope's length, worked out before anything is signed: the
        // body field (omitted when empty, as proto3 omits a default) and the
        // signature field, whose 64 bytes are fixed.
        let field = |len: usize| 1 + prost::encoding::encoded_len_varint(len as u64) + len;
        let encoded = if body.is_empty() {
            0
        } else {
            field(body.len())
        } + field(64);
        if encoded > MAX_INDEX_RECORD_BYTES {
            return Err(Malformed::TooLarge(encoded));
        }
        let signature = sig::sign(self.signing_key(), record_type.label(), &body);
        Ok(SignedRecord {
            body,
            signature,
            record_type,
        })
    }
}

/// Signs `body` under `label` whatever record type it declares, as only a
/// test may, so that tests and vectors can show a body signed under the other
/// type's label failing as forged; read back through
/// [`SignedRecord::from_bytes`], so `None` for a body that does not decode.
#[cfg(test)]
pub(crate) fn signed_under_for_test(
    key: &WriteKey,
    label: SigLabel,
    body: Vec<u8>,
) -> Option<SignedRecord> {
    use prost::Message as _;
    let signature = sig::sign(key.signing_key(), label, &body);
    let bytes = Envelope {
        body,
        signature: signature.as_bytes().to_vec(),
    }
    .encode_to_vec();
    SignedRecord::from_bytes(&bytes).ok()
}

impl FolderVerifier {
    /// `Verify(folder_vk, label, body, signature)` under the label of the
    /// record's type, `licketysync/v1/sig/index` or
    /// `licketysync/v1/sig/cleanup`: the step that every peer, sealed ones
    /// included, runs before anything in the record is charged to anyone
    /// (TM-9, `protocol.md` 4.4 step 5).
    ///
    /// # Errors
    ///
    /// [`SignatureError`] when the signature does not verify under the
    /// folder key and that label: the record is forged.
    pub fn verify_record(&self, record: &SignedRecord) -> Result<(), SignatureError> {
        sig::verify(
            self.verifying_key().key(),
            record.record_type.label(),
            &record.body,
            &record.signature,
        )
    }
}

/// The old index exchange's writer digests: retired by `keys.md` section 10
/// on 2026-10-25, used only by that exchange, and removed in the next commit
/// of this series.
impl WriterDigest {
    /// The digest before any record: 32 zero bytes.
    pub const ZERO: WriterDigest = WriterDigest([0u8; 32]);

    /// The digest after one more record, `H("licketysync/v1/hash/writer-digest",
    /// D || record_hash)` (`protocol.md` 4.4), the records taken in canonical
    /// order: ascending `seq`, then ascending record hash.
    #[must_use]
    pub fn then(&self, record: &RecordHash) -> WriterDigest {
        WriterDigest(labelled_hash(
            labels::HASH_WRITER_DIGEST,
            &[&self.0, record.as_bytes()],
        ))
    }
}

/// The shape [`decode_strict`] checks a message against before prost decodes
/// it: fields numbered `1..=fields`, every one singular, and the varint
/// fields in `u32_fields` declared `uint32`.
struct Shape<'b> {
    fields: u32,
    u32_fields: &'b [u32],
}

impl<'b> Shape<'b> {
    const fn new(fields: u32, u32_fields: &'b [u32]) -> Self {
        Shape { fields, u32_fields }
    }
}

/// Decodes `body` as `M` after a scan against `shape` that allocates nothing
/// (`protocol.md` 2, "every decoder judges a body the same way"):
///
/// - each known field occurs at most once (proto3 keeps the last occurrence,
///   and a body carrying two record types must mean nothing);
/// - a `uint32` field's varint fits 32 bits;
/// - no field has a group wire type, and no field number exceeds 2^29 − 1
///   (prost's key decoder refuses those).
///
/// Unknown fields may repeat, since a newer release may have added them as
/// repeated; prost skips them.
fn decode_strict<M: prost::Message + Default>(
    body: &[u8],
    shape: &Shape<'_>,
) -> Result<M, Malformed> {
    scan_fields(body, shape)?;
    M::decode(body).map_err(|_| Malformed::Decode)
}

fn scan_fields(body: &[u8], shape: &Shape<'_>) -> Result<(), Malformed> {
    let mut seen: u64 = 0;
    let mut buf = body;
    while buf.has_remaining() {
        let (field, wire_type) =
            prost::encoding::decode_key(&mut buf).map_err(|_| Malformed::Decode)?;
        let value = take_value(&mut buf, wire_type)?;
        if let Some(v) = value {
            if shape.u32_fields.contains(&field) && u32::try_from(v).is_err() {
                return Err(Malformed::VarintRange(field));
            }
        }
        if (1..=shape.fields).contains(&field) {
            let bit = 1u64.checked_shl(field).ok_or(Malformed::Decode)?;
            if seen & bit != 0 {
                return Err(Malformed::DuplicateField(field));
            }
            seen |= bit;
        }
    }
    Ok(())
}

/// Takes one value of `wire_type` off the front of `buf`; a varint's value
/// comes back, any other value is skipped.
fn take_value(
    buf: &mut &[u8],
    wire_type: prost::encoding::WireType,
) -> Result<Option<u64>, Malformed> {
    use prost::encoding::WireType;
    let len = match wire_type {
        WireType::Varint => {
            let v = prost::encoding::decode_varint(buf).map_err(|_| Malformed::Decode)?;
            return Ok(Some(v));
        }
        WireType::SixtyFourBit => 8,
        WireType::ThirtyTwoBit => 4,
        WireType::LengthDelimited => {
            let len = prost::encoding::decode_varint(buf).map_err(|_| Malformed::Decode)?;
            usize::try_from(len).map_err(|_| Malformed::Decode)?
        }
        WireType::StartGroup | WireType::EndGroup => return Err(Malformed::Decode),
    };
    let (_, rest) = buf.split_at_checked(len).ok_or(Malformed::Decode)?;
    *buf = rest;
    Ok(None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;
    use crate::folder::tests::write_key;
    use proptest::prelude::*;
    use prost::encoding::{encode_key, encode_varint, WireType};
    use prost::Message as _;

    /// A body with the common prefix and one unknown field, as an index
    /// record's would begin.
    fn body(record_type: u32) -> Vec<u8> {
        let mut b = Prefix {
            suite: 1,
            record_type,
            folder_id: vec![7; 32],
        }
        .encode_to_vec();
        encode_key(6, WireType::Varint, &mut b);
        encode_varint(3, &mut b);
        b
    }

    /// The wire bytes of an envelope with any body and signature bytes.
    fn envelope(body: Vec<u8>, signature: Vec<u8>) -> Vec<u8> {
        Envelope { body, signature }.encode_to_vec()
    }

    #[test]
    fn signing_and_verifying_under_the_folder_key() {
        let w = write_key(1);
        let record = w.sign_index_record(body(16)).unwrap();
        assert_eq!(record.body(), &body(16)[..]);
        assert_eq!(
            w.sign_index_record(body(16)),
            Ok(record.clone()),
            "deterministic through the production signing path"
        );
        let v = w.verifier();
        assert_eq!(v.verify_record(&record), Ok(()));
        assert_eq!(
            write_key(2).verifier().verify_record(&record),
            Err(SignatureError)
        );
        let mut flipped = record.clone();
        flipped.body[3] ^= 1;
        assert_eq!(v.verify_record(&flipped), Err(SignatureError));
        // Every write holder signs with the same key; the read and sealed
        // keys verify what it signs.
        assert_eq!(w.read_key().verifier().verify_record(&record), Ok(()));
        assert_eq!(w.sealed_key().verifier().verify_record(&record), Ok(()));
        // The signature is over the index label, so it is no device proof.
        assert!(sig::verify(
            v.verifying_key().key(),
            labels::SIG_DEVICE_PROOF,
            record.body(),
            record.signature()
        )
        .is_err());
        assert_eq!(
            record.hash().0,
            labelled_hash(labels::HASH_RECORD, &[record.body()])
        );
        // Equal bodies are one record, whatever the signatures.
        let other = SignedRecord {
            body: record.body.clone(),
            signature: Signature::from_bytes([0; 64]),
            record_type: RecordType::Index,
        };
        assert_eq!(other.hash(), record.hash());
    }

    #[test]
    fn the_envelope_is_bounded_and_strict() {
        let w = write_key(3);
        let record = w.sign_index_record(body(16)).unwrap();
        let bytes = record.to_bytes();
        assert_eq!(
            bytes,
            envelope(record.body.clone(), record.signature.as_bytes().to_vec()),
            "canonical: what prost's own encoder writes"
        );
        assert_eq!(SignedRecord::from_bytes(&bytes), Ok(record.clone()));
        // Every record type but 16 and 17 is malformed, the drafts' 1 to 8
        // included.
        for t in [0, 1, 2, 8, 15, 18, u32::MAX] {
            assert_eq!(
                SignedRecord::from_bytes(&envelope(body(t), vec![0; 64])),
                Err(Malformed::RecordType(t))
            );
        }
        // The cap is judged on the encoded size, before decoding: one byte
        // over is too large, exactly at the cap is decoded (and these bytes do
        // not parse).
        assert_eq!(
            SignedRecord::from_bytes(&vec![0xff; MAX_INDEX_RECORD_BYTES + 1]),
            Err(Malformed::TooLarge(MAX_INDEX_RECORD_BYTES + 1))
        );
        assert_eq!(
            SignedRecord::from_bytes(&vec![0xff; MAX_INDEX_RECORD_BYTES]),
            Err(Malformed::Decode)
        );
        // A field twice.
        let mut twice = bytes.clone();
        twice.extend(envelope(vec![], record.signature.as_bytes().to_vec()));
        assert_eq!(
            SignedRecord::from_bytes(&twice),
            Err(Malformed::DuplicateField(2))
        );
        // An unknown field (the reserved 3) is skipped.
        let mut unknown = bytes.clone();
        encode_key(3, WireType::LengthDelimited, &mut unknown);
        encode_varint(1, &mut unknown);
        unknown.push(0);
        assert_eq!(SignedRecord::from_bytes(&unknown), Ok(record.clone()));
        // A signature of 63 and of 65 bytes, a body that is not a message, a
        // group.
        for len in [0, 63, 65] {
            assert_eq!(
                SignedRecord::from_bytes(&envelope(body(16), vec![0; len])),
                Err(Malformed::SignatureSize(len))
            );
        }
        assert_eq!(
            SignedRecord::from_bytes(&envelope(vec![0xff], vec![0; 64])),
            Err(Malformed::Decode)
        );
        assert_eq!(SignedRecord::from_bytes(&[0x0b]), Err(Malformed::Decode));
        // A record_type of 2^32 + 16 would read as 16 to a lax decoder.
        let mut wide = Vec::new();
        encode_key(2, WireType::Varint, &mut wide);
        encode_varint((1u64 << 32) + 16, &mut wide);
        assert_eq!(
            SignedRecord::from_bytes(&envelope(wide, vec![0; 64])),
            Err(Malformed::VarintRange(2))
        );
        let mut type_twice = body(16);
        encode_key(2, WireType::Varint, &mut type_twice);
        encode_varint(16, &mut type_twice);
        assert_eq!(
            SignedRecord::from_bytes(&envelope(type_twice, vec![0; 64])),
            Err(Malformed::DuplicateField(2))
        );
        // An empty body is omitted from the canonical envelope, as prost
        // omits it, and reads back as a record type of 0. No signing function
        // makes such a record, so it is built by hand.
        let empty = SignedRecord {
            body: Vec::new(),
            signature: Signature::from_bytes([5; 64]),
            record_type: RecordType::Index,
        };
        assert_eq!(empty.to_bytes(), envelope(vec![], vec![5; 64]));
        assert_eq!(
            SignedRecord::from_bytes(&empty.to_bytes()),
            Err(Malformed::RecordType(0))
        );
    }

    /// Both record types of major 1 parse, and each exposes its type.
    #[test]
    fn both_record_types_through_from_bytes() {
        let w = write_key(4);
        for (t, kind) in [(16, RecordType::Index), (17, RecordType::Cleanup)] {
            let bytes = envelope(body(t), vec![0; 64]);
            let record = SignedRecord::from_bytes(&bytes).unwrap();
            assert_eq!(record.record_type(), kind);
            assert_eq!(record.record_type().code(), t);
            assert_eq!(RecordType::from_code(t), Some(kind));
            assert_eq!(record.to_bytes(), bytes);
        }
        assert_eq!(RecordType::from_code(18), None);
        let cleanup = w.sign_cleanup_record(body(17)).unwrap();
        assert_eq!(cleanup.record_type(), RecordType::Cleanup);
        assert_eq!(SignedRecord::from_bytes(&cleanup.to_bytes()), Ok(cleanup));
        assert_eq!(
            w.sign_index_record(body(16)).unwrap().record_type(),
            RecordType::Index
        );
    }

    /// Every `SignedRecord` declares the type it was signed for (security
    /// review S-1): a signing function refuses a body that declares another
    /// type, does not decode, or would pass the size cap, and signs nothing.
    #[test]
    fn signing_refuses_a_body_of_another_type_or_none() {
        let w = write_key(7);
        assert_eq!(
            w.sign_index_record(body(17)),
            Err(Malformed::RecordType(17))
        );
        assert_eq!(
            w.sign_cleanup_record(body(16)),
            Err(Malformed::RecordType(16))
        );
        assert_eq!(
            w.sign_index_record(Vec::new()),
            Err(Malformed::RecordType(0))
        );
        assert_eq!(
            w.sign_cleanup_record(Vec::new()),
            Err(Malformed::RecordType(0))
        );
        assert_eq!(w.sign_index_record(vec![0xff]), Err(Malformed::Decode));
        // The same strict decode as from_bytes: a record type twice, or one
        // past 32 bits.
        let mut twice = body(16);
        encode_key(2, WireType::Varint, &mut twice);
        encode_varint(16, &mut twice);
        assert_eq!(
            w.sign_index_record(twice),
            Err(Malformed::DuplicateField(2))
        );
        let mut wide = Vec::new();
        encode_key(2, WireType::Varint, &mut wide);
        encode_varint((1u64 << 32) + 16, &mut wide);
        assert_eq!(w.sign_index_record(wide), Err(Malformed::VarintRange(2)));
        // At the cap the record is signed; one byte over, refused.
        let signed = w
            .sign_index_record(padded_body(MAX_INDEX_RECORD_BYTES))
            .unwrap();
        assert_eq!(signed.to_bytes().len(), MAX_INDEX_RECORD_BYTES);
        assert_eq!(SignedRecord::from_bytes(&signed.to_bytes()), Ok(signed));
        assert_eq!(
            w.sign_index_record(padded_body(MAX_INDEX_RECORD_BYTES + 1)),
            Err(Malformed::TooLarge(MAX_INDEX_RECORD_BYTES + 1))
        );
    }

    /// A body declaring type 16, padded with an unknown field so that its
    /// signed envelope is exactly `envelope_len` bytes.
    fn padded_body(envelope_len: usize) -> Vec<u8> {
        let base = body(16);
        let with = |pad: usize| {
            let mut b = base.clone();
            encode_key(9, WireType::LengthDelimited, &mut b);
            encode_varint(pad as u64, &mut b);
            b.extend(core::iter::repeat_n(0u8, pad));
            b
        };
        let total = |b: &Vec<u8>| {
            Envelope {
                body: b.clone(),
                signature: vec![0; 64],
            }
            .encoded_len()
        };
        let mut pad = envelope_len - 100;
        while total(&with(pad)) > envelope_len {
            pad -= 1;
        }
        while total(&with(pad)) < envelope_len {
            pad += 1;
        }
        with(pad)
    }

    /// `keys.md` 0.2, 5.1: a cleanup is signed under `sig/cleanup` and an
    /// index record under `sig/index`, and the verifier takes the label from
    /// the body's type, so a body signed under the other label is forged.
    #[test]
    fn sig_cleanup_against_sig_index() {
        let w = write_key(5);
        let v = w.verifier();
        let cleanup = w.sign_cleanup_record(body(17)).unwrap();
        assert_eq!(v.verify_record(&cleanup), Ok(()));
        assert_eq!(w.sealed_key().verifier().verify_record(&cleanup), Ok(()));
        assert_eq!(
            cleanup.signature,
            sig::sign(w.signing_key(), labels::SIG_CLEANUP, &body(17))
        );
        // A cleanup body signed under sig/index, read back from the wire
        // (only a test can sign one: the signing functions refuse it).
        let read_back = signed_under_for_test(&w, labels::SIG_INDEX, body(17)).unwrap();
        assert_eq!(read_back.record_type(), RecordType::Cleanup);
        assert_eq!(v.verify_record(&read_back), Err(SignatureError));
        // And an index body signed under sig/cleanup.
        let read_back = signed_under_for_test(&w, labels::SIG_CLEANUP, body(16)).unwrap();
        assert_eq!(read_back.record_type(), RecordType::Index);
        assert_eq!(v.verify_record(&read_back), Err(SignatureError));
        // One body, two labels, two signatures.
        assert_ne!(
            signed_under_for_test(&w, labels::SIG_INDEX, body(17))
                .unwrap()
                .signature,
            cleanup.signature
        );
        assert!(signed_under_for_test(&w, labels::SIG_INDEX, vec![0xff]).is_none());
        // Another folder's key forges.
        assert_eq!(
            write_key(6).verifier().verify_record(&cleanup),
            Err(SignatureError)
        );
    }

    #[test]
    fn the_scan_counts_singular_fields_varint_ranges_and_groups() {
        let shape = Shape::new(5, &[1]);
        let mut ok = Vec::new();
        encode_key(1, WireType::Varint, &mut ok);
        encode_varint(u64::from(u32::MAX), &mut ok);
        // Unknown fields may repeat; fixed-width ones are skipped.
        for _ in 0..3 {
            encode_key(9, WireType::ThirtyTwoBit, &mut ok);
            ok.extend([0; 4]);
            encode_key(10, WireType::SixtyFourBit, &mut ok);
            ok.extend([0; 8]);
            encode_key(11, WireType::LengthDelimited, &mut ok);
            encode_varint(1, &mut ok);
            ok.push(0);
        }
        assert_eq!(scan_fields(&ok, &shape), Ok(()));
        let mut wide = Vec::new();
        encode_key(1, WireType::Varint, &mut wide);
        encode_varint(1u64 << 32, &mut wide);
        assert_eq!(scan_fields(&wide, &shape), Err(Malformed::VarintRange(1)));
        let mut twice = Vec::new();
        for _ in 0..2 {
            encode_key(5, WireType::LengthDelimited, &mut twice);
            encode_varint(0, &mut twice);
        }
        assert_eq!(
            scan_fields(&twice, &shape),
            Err(Malformed::DuplicateField(5))
        );
        let mut truncated = Vec::new();
        encode_key(2, WireType::LengthDelimited, &mut truncated);
        encode_varint(9, &mut truncated);
        assert_eq!(scan_fields(&truncated, &shape), Err(Malformed::Decode));
        let mut huge = Vec::new();
        encode_key(2, WireType::LengthDelimited, &mut huge);
        encode_varint(u64::MAX, &mut huge);
        assert_eq!(scan_fields(&huge, &shape), Err(Malformed::Decode));
        let mut end_group = Vec::new();
        encode_key(2, WireType::EndGroup, &mut end_group);
        assert_eq!(scan_fields(&end_group, &shape), Err(Malformed::Decode));
        // A field number above 2^29 - 1 does not even make a key.
        let mut big_field = Vec::new();
        encode_varint(1u64 << 32, &mut big_field);
        assert_eq!(scan_fields(&big_field, &shape), Err(Malformed::Decode));
        let mut bad_varint = Vec::new();
        encode_key(1, WireType::Varint, &mut bad_varint);
        bad_varint.extend([0xff; 11]);
        assert_eq!(scan_fields(&bad_varint, &shape), Err(Malformed::Decode));
    }

    #[test]
    fn writer_digests_chain_record_hashes() {
        let a = RecordHash(labelled_hash(labels::HASH_RECORD, &[b"a"]));
        let b = RecordHash(labelled_hash(labels::HASH_RECORD, &[b"b"]));
        let d1 = WriterDigest::ZERO.then(&a);
        assert_eq!(
            d1.0,
            labelled_hash(labels::HASH_WRITER_DIGEST, &[&[0u8; 32], &a.0])
        );
        let d2 = d1.then(&b);
        assert_ne!(d2, WriterDigest::ZERO.then(&b).then(&a), "order matters");
        assert_ne!(d1, d2);
    }

    #[test]
    fn errors_display() {
        for m in [
            Malformed::Decode,
            Malformed::TooLarge(1),
            Malformed::RecordType(1),
            Malformed::DuplicateField(4),
            Malformed::SignatureSize(63),
        ] {
            assert_ne!(m.to_string(), "");
        }
        assert_eq!(
            Malformed::VarintRange(2).to_string(),
            "the value of field number 2 does not fit 32 bits"
        );
    }

    /// An unknown field of the body after the prefix: a varint, a fixed64, a
    /// fixed32 or a length-delimited value, under a field number from 4 up.
    fn unknown_field() -> impl Strategy<Value = Vec<u8>> {
        (
            4u32..1000,
            0u8..4,
            any::<u64>(),
            proptest::collection::vec(any::<u8>(), 0..40),
        )
            .prop_map(|(field, kind, n, data)| {
                let mut b = Vec::new();
                match kind {
                    0 => {
                        encode_key(field, WireType::Varint, &mut b);
                        encode_varint(n, &mut b);
                    }
                    1 => {
                        encode_key(field, WireType::SixtyFourBit, &mut b);
                        b.extend(n.to_le_bytes());
                    }
                    2 => {
                        encode_key(field, WireType::ThirtyTwoBit, &mut b);
                        b.extend(n.to_le_bytes()[..4].iter());
                    }
                    _ => {
                        encode_key(field, WireType::LengthDelimited, &mut b);
                        encode_varint(data.len() as u64, &mut b);
                        b.extend(data);
                    }
                }
                b
            })
    }

    proptest! {
        /// Any body that begins with an index record's prefix, followed by any
        /// unknown fields, signs, encodes, decodes to the same record and
        /// verifies; the body comes back byte for byte.
        #[test]
        fn signed_records_round_trip(
            seed in any::<u8>(),
            suite in any::<u32>(),
            folder in proptest::collection::vec(any::<u8>(), 0..40),
            fields in proptest::collection::vec(unknown_field(), 0..6),
        ) {
            let mut b = Prefix { suite, record_type: INDEX_RECORD_TYPE, folder_id: folder }.encode_to_vec();
            for f in fields {
                b.extend(f);
            }
            let w = write_key(seed);
            let record = w.sign_index_record(b.clone()).unwrap();
            let bytes = record.to_bytes();
            let back = SignedRecord::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&back, &record);
            prop_assert_eq!(back.body(), &b[..]);
            prop_assert_eq!(back.to_bytes(), bytes);
            prop_assert_eq!(w.verifier().verify_record(&back), Ok(()));
        }

        /// Any bytes into the parser: no panic, and what it accepts encodes to
        /// an envelope that it accepts again as the same record.
        #[test]
        fn any_bytes_into_the_envelope_parser(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            if let Ok(record) = SignedRecord::from_bytes(&bytes) {
                prop_assert_eq!(SignedRecord::from_bytes(&record.to_bytes()), Ok(record));
            }
        }

        /// The same with a 64-byte signature and any body, so that the
        /// prefix's checks are reached.
        #[test]
        fn any_body_in_a_well_formed_envelope(body in proptest::collection::vec(any::<u8>(), 0..120)) {
            let bytes = envelope(body.clone(), vec![1; 64]);
            match SignedRecord::from_bytes(&bytes) {
                Ok(record) => {
                    prop_assert_eq!(record.body(), &body[..]);
                    prop_assert_eq!(record.to_bytes(), bytes);
                }
                Err(e) => prop_assert!(!matches!(e, Malformed::TooLarge(_) | Malformed::SignatureSize(_))),
            }
        }
    }
}
