// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Signed records (`keys.md` section 5): the envelope, the record hash,
//! signing and verification under the folder key, and the writer digest that
//! reconciles index records (`protocol.md` 4.4).
//!
//! There is one kind of signed record, the index record, whose body is the
//! protocol crate's (`protocol.md` 4.4). It is signed with the folder's
//! signing key under `licketysync/v1/sig/index` and verified with `folder_vk`
//! before anything in it is charged to anyone (TM-9). Verifiers treat the body
//! as opaque bytes: hashed, signed and forwarded exactly as received, never
//! re-encoded. There are no key records: no key ever travels inside a folder.
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
//!   `record_type` within 32 bits, `record_type = 16`; and, over the whole
//!   body, no group wire type and no field number above 2^29 − 1.
//!
//! The rest of step 1 stays the caller's (the protocol crate's), since it
//! needs the open folder or the body's schema: `suite` is the folder's suite;
//! `folder_id` is 32 bytes and is the open folder; every other field is
//! present at its exact size and in range (`device_id` 32 bytes,
//! `1 ≤ seq ≤ MAX_SEQ`, at most 16 `supersedes` of 32 bytes each, `deleted`
//! implies no chunks, each chunk's `cipher_hash` 32 bytes and `stored_len` in
//! range and a Padmé length plus 40, `sealed` 40 to 1 572 864 bytes); no field
//! other than the prefix's occurs twice unless it is repeated; every `bool`
//! is 0 or 1 and every `uint32` fits 32 bits; repeated scalars are read packed
//! or unpacked. Steps 2 to 7 follow: [`SignedRecord::hash`] for the duplicate
//! check, [`FolderVerifier::verify_index_record`] for the signature,
//! [`crate::sealed_meta::open_meta`] for the seal.

use core::fmt;

use prost::bytes::Buf;

use crate::folder::{FolderVerifier, WriteKey};
use crate::ids::{RecordHash, WriterDigest};
use crate::labels::{self, labelled_hash};
use crate::sig::{self, Signature, SignatureError};

/// The largest encoded [`SignedRecord`] (`protocol.md` 2,
/// `MAX_INDEX_RECORD_BYTES`), judged at parse, before the duplicate check.
pub const MAX_INDEX_RECORD_BYTES: usize = 4_000_000;

/// The `record_type` of an index record, the one record type of major 1
/// (`keys.md` 5.1). A record type a later release adds gets a label of its
/// own.
pub const INDEX_RECORD_TYPE: u32 = 16;

/// The signed envelope (section 5.1): a body and the folder key's Ed25519
/// signature over it. The body is kept exactly as received; it is what is
/// hashed, verified, stored and forwarded, never re-encoded. Made only by
/// [`WriteKey::sign_index_record`] and [`SignedRecord::from_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    body: Vec<u8>,
    signature: Signature,
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
    /// The body's `record_type` is not 16.
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
    /// `record_type`, read strictly from its common prefix.
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
        if prefix.record_type != INDEX_RECORD_TYPE {
            return Err(Malformed::RecordType(prefix.record_type));
        }
        Ok(SignedRecord {
            body: envelope.body,
            signature,
        })
    }
}

impl WriteKey {
    /// Signs an index record body: `Sign(folder_sk, "licketysync/v1/sig/index",
    /// body)`. The caller encodes the body canonically (section 5.2).
    #[must_use]
    pub fn sign_index_record(&self, body: Vec<u8>) -> SignedRecord {
        let signature = sig::sign(self.signing_key(), labels::SIG_INDEX, &body);
        SignedRecord { body, signature }
    }
}

impl FolderVerifier {
    /// `Verify(folder_vk, "licketysync/v1/sig/index", body, signature)`: the
    /// step that every peer, sealed ones included, runs before anything in the
    /// record is charged to anyone (TM-9, `protocol.md` 4.4 step 4).
    ///
    /// # Errors
    ///
    /// [`SignatureError`] when the signature does not verify under the
    /// folder key: the record is forged.
    pub fn verify_index_record(&self, record: &SignedRecord) -> Result<(), SignatureError> {
        sig::verify(
            self.verifying_key().key(),
            labels::SIG_INDEX,
            &record.body,
            &record.signature,
        )
    }
}

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
        let record = w.sign_index_record(body(16));
        assert_eq!(record.body(), &body(16)[..]);
        assert_eq!(
            w.sign_index_record(body(16)),
            record,
            "deterministic through the production signing path"
        );
        let v = w.verifier();
        assert_eq!(v.verify_index_record(&record), Ok(()));
        assert_eq!(
            write_key(2).verifier().verify_index_record(&record),
            Err(SignatureError)
        );
        let mut flipped = record.clone();
        flipped.body[3] ^= 1;
        assert_eq!(v.verify_index_record(&flipped), Err(SignatureError));
        // Every write holder signs with the same key; the read and sealed
        // keys verify what it signs.
        assert_eq!(w.read_key().verifier().verify_index_record(&record), Ok(()));
        assert_eq!(
            w.sealed_key().verifier().verify_index_record(&record),
            Ok(())
        );
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
        };
        assert_eq!(other.hash(), record.hash());
    }

    #[test]
    fn the_envelope_is_bounded_and_strict() {
        let w = write_key(3);
        let record = w.sign_index_record(body(16));
        let bytes = record.to_bytes();
        assert_eq!(
            bytes,
            envelope(record.body.clone(), record.signature.as_bytes().to_vec()),
            "canonical: what prost's own encoder writes"
        );
        assert_eq!(SignedRecord::from_bytes(&bytes), Ok(record.clone()));
        // Every record type but 16 is malformed, the drafts' 1 to 8 included.
        for t in [0, 1, 2, 8, 15, 17] {
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
        // omits it, and reads back as a record type of 0.
        let empty = w.sign_index_record(Vec::new());
        assert_eq!(
            empty.to_bytes(),
            envelope(vec![], empty.signature.as_bytes().to_vec())
        );
        assert_eq!(
            SignedRecord::from_bytes(&empty.to_bytes()),
            Err(Malformed::RecordType(0))
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
            let record = w.sign_index_record(b.clone());
            let bytes = record.to_bytes();
            let back = SignedRecord::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&back, &record);
            prop_assert_eq!(back.body(), &b[..]);
            prop_assert_eq!(back.to_bytes(), bytes);
            prop_assert_eq!(w.verifier().verify_index_record(&back), Ok(()));
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
