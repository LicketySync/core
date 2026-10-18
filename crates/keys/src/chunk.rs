// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Chunk encryption (`keys.md` section 3.3) and Padmé padding (section 3.4).
//!
//! One chunk becomes `nonce || XChaCha(ck_e, nonce, folder_id || be64(e),
//! header || payload || zeros)` where the plaintext is Padmé-padded and the
//! nonce is keyed BLAKE3 under `nk_e` over that exact padded plaintext, so the
//! encryption is deterministic for one epoch and plaintext (sealed peers
//! deduplicate and verify by `cipher_hash`) and two different plaintexts never
//! share a nonce under one key (TM-12). The plaintext hash is keyed under the
//! folder's `hk`, so it is a fingerprint only to key holders (TM-14).
//! `MAX_CHUNK_PLAINTEXT` is enforced before anything is allocated (TM-2).

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::aead::{xchacha_open, xchacha_seal, AeadError};
use crate::ids::{CipherHash, FolderId};
use crate::labels::{self, keyed_hash, labelled_hash};
use crate::secret::{ChunkHashKey, ChunkKey, ChunkNonceKey, DataKey, SecretBytes};
use crate::suite::sizes;

/// The largest raw chunk: 4 MiB. The engine's `FastCDC` maximum must not exceed it.
pub const MAX_CHUNK_PLAINTEXT: usize = 4 * 1024 * 1024;
/// The header: `u8(compression) || be32(len(payload))`.
pub const HEADER_LEN: usize = 5;
/// The smallest stored blob: Padmé(1 + 5) = 6, plus nonce and tag.
pub const MIN_STORED_LEN: usize = 46;
/// The largest stored blob: `padme(MAX_CHUNK_PLAINTEXT + 5) + 40`.
pub const MAX_STORED_LEN: usize = 4_325_416;

/// Padmé (Nikitin et al., PURBs 2019): rounds `len` up so that only about
/// `log2(log2 len) + 1` bits of the padded length carry information; overhead
/// at most 12%, 3% on average. `None` only for a length whose padded form
/// does not fit 64 bits, far beyond any chunk.
#[must_use]
pub fn padme(len: u64) -> Option<u64> {
    if len < 2 {
        return Some(len);
    }
    let e = len.ilog2(); // floor(log2(len))
    let s = u32::BITS - e.leading_zeros(); // bit_length(e)
    let last = e - s;
    let mask = (1u64 << last) - 1;
    len.checked_add(mask).map(|l| l & !mask)
}

/// A chunk's compression code (section 3.3). Phase 0 writes and reads `0` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    /// No compression; `payload = raw`.
    None = 0,
}

impl Compression {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Compression::None),
            _ => None,
        }
    }
}

/// The keyed hash of a plaintext chunk under `hk`: the key-holder-side
/// reference (section 3.3), carried inside the sealed part of index records.
/// It has no `==`: compare with [`PlainHash::ct_eq`], since an early-exit
/// comparison would time a guess at a chunk's content.
#[derive(Clone, Copy)]
pub struct PlainHash(pub [u8; 32]);

impl fmt::Debug for PlainHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlainHash({})", crate::ids::hex(&self.0))
    }
}

impl PlainHash {
    /// `plain_hash = BLAKE3_keyed(hk, raw)`.
    #[must_use]
    pub fn of(hk: &ChunkHashKey, raw: &[u8]) -> Self {
        PlainHash(keyed_hash(hk.expose(), &[raw]))
    }

    /// Reads a hash from exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }

    /// Constant-time comparison: the hash is keyed under a secret.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// `cipher_hash = H("licketysync/v1/hash/chunk", stored)`: what sealed peers
/// and relays verify and deduplicate by.
#[must_use]
pub fn cipher_hash(stored: &[u8]) -> CipherHash {
    CipherHash(labelled_hash(labels::HASH_CHUNK, &[stored]))
}

/// The keys of one epoch for one folder: `ck_e`, `nk_e` and the associated
/// data `folder_id || be64(e)`.
pub struct ChunkKeys {
    ck: ChunkKey,
    nk: ChunkNonceKey,
    aad: [u8; 40],
}

impl fmt::Debug for ChunkKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkKeys([redacted])")
    }
}

impl ChunkKeys {
    /// Derives the chunk keys of `epoch` from its data key.
    #[must_use]
    pub fn new(dk: &DataKey, folder_id: &FolderId, epoch: u64) -> Self {
        let aad = crate::bytes::fill::<40>(&[folder_id.as_bytes(), &epoch.to_be_bytes()]);
        ChunkKeys {
            ck: dk.chunk_key(),
            nk: dk.chunk_nonce_key(),
            aad,
        }
    }
}

/// Why a chunk could not be sealed or opened. The outcome for each (who is
/// blamed) is `protocol.md` 4.7's business; this type names the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// A raw chunk must be 1 to `MAX_CHUNK_PLAINTEXT` bytes.
    RawLength(usize),
    /// The stored length is outside `46 ..= 4 325 416`.
    StoredLength(usize),
    /// The stored length minus 40 is not a Padmé length.
    NotPadmeLength(usize),
    /// The AEAD did not open.
    Open,
    /// The payload length in the header is 0 or exceeds what the plaintext holds.
    PayloadLength(u32),
    /// A padding byte is not zero.
    Padding,
    /// The compression code is not one this folder decodes.
    UnsupportedCompression(u8),
    /// The plaintext hash does not match the record's.
    PlainHashMismatch,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawLength(n) => write!(
                f,
                "raw chunk of {n} bytes is outside 1..={MAX_CHUNK_PLAINTEXT}"
            ),
            Self::StoredLength(n) => write!(
                f,
                "stored chunk of {n} bytes is outside {MIN_STORED_LEN}..={MAX_STORED_LEN}"
            ),
            Self::NotPadmeLength(n) => write!(f, "{n} is not a Padmé length"),
            Self::Open => f.write_str("chunk did not decrypt"),
            Self::PayloadLength(n) => write!(f, "payload length {n} is out of range"),
            Self::Padding => f.write_str("a padding byte is not zero"),
            Self::UnsupportedCompression(c) => write!(f, "compression code {c} is not supported"),
            Self::PlainHashMismatch => f.write_str("plaintext hash does not match the record"),
        }
    }
}

impl std::error::Error for ChunkError {}

/// A sealed chunk: the stored blob and its ciphertext hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedChunk {
    /// `nonce || ct`, what peers store and serve.
    pub stored: Vec<u8>,
    /// `H("licketysync/v1/hash/chunk", stored)`.
    pub cipher_hash: CipherHash,
}

/// Seals `raw` under the epoch's keys with compression `0` (phase 0): builds
/// `header || raw || zeros` to the Padmé length, derives the nonce from that
/// plaintext under `nk_e`, and encrypts under `ck_e` with aad
/// `folder_id || be64(e)`. Deterministic.
///
/// # Errors
///
/// [`ChunkError::RawLength`] when `raw` is empty or over `MAX_CHUNK_PLAINTEXT`;
/// [`ChunkError::Open`] only if the cipher refuses, which it does not.
pub fn seal_chunk(keys: &ChunkKeys, raw: &[u8]) -> Result<SealedChunk, ChunkError> {
    if raw.is_empty() || raw.len() > MAX_CHUNK_PLAINTEXT {
        return Err(ChunkError::RawLength(raw.len()));
    }
    let payload_len = u32::try_from(raw.len()).map_err(|_| ChunkError::RawLength(raw.len()))?;
    let l = HEADER_LEN + raw.len();
    let padded = u64::try_from(l)
        .ok()
        .and_then(padme)
        .and_then(|p| usize::try_from(p).ok())
        .ok_or(ChunkError::RawLength(raw.len()))?;
    let mut plaintext: SecretBytes = Zeroizing::new(Vec::with_capacity(padded));
    plaintext.push(Compression::None as u8);
    plaintext.extend_from_slice(&payload_len.to_be_bytes());
    plaintext.extend_from_slice(raw);
    plaintext.resize(padded.max(l), 0);
    let nonce = crate::bytes::fill::<24>(&[&keyed_hash(keys.nk.expose(), &[&plaintext])]);
    let ct = xchacha_seal(keys.ck.expose(), &nonce, &keys.aad, &plaintext)
        .map_err(|AeadError| ChunkError::Open)?;
    let mut stored = Vec::with_capacity(24 + ct.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&ct);
    let cipher_hash = cipher_hash(&stored);
    Ok(SealedChunk {
        stored,
        cipher_hash,
    })
}

/// Opens a stored chunk in the order section 3.3 fixes: the stored length and
/// its Padmé shape, the nonce split, the AEAD, the header, the payload length,
/// the zero padding, the compression code, then the plaintext hash against
/// `expected` under `hk`. Nothing is allocated beyond the stored length, which
/// is bounded first (TM-2). The result is zeroized on drop.
///
/// # Errors
///
/// The [`ChunkError`] of the first failing step.
pub fn open_chunk(
    keys: &ChunkKeys,
    hk: &ChunkHashKey,
    stored: &[u8],
    expected: &PlainHash,
) -> Result<SecretBytes, ChunkError> {
    if stored.len() < MIN_STORED_LEN || stored.len() > MAX_STORED_LEN {
        return Err(ChunkError::StoredLength(stored.len()));
    }
    let padded = stored.len() - sizes::NONCE - sizes::TAG;
    if u64::try_from(padded).map_or(true, |p| padme(p) != Some(p)) {
        return Err(ChunkError::NotPadmeLength(padded));
    }
    let (nonce, ct) = stored.split_at(sizes::NONCE);
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| ChunkError::Open)?;
    let plaintext = xchacha_open(keys.ck.expose(), &nonce, &keys.aad, ct)
        .map_err(|AeadError| ChunkError::Open)?;
    let [code, l0, l1, l2, l3] =
        crate::bytes::prefix::<HEADER_LEN>(&plaintext).ok_or(ChunkError::PayloadLength(0))?;
    let payload_len = u32::from_be_bytes([l0, l1, l2, l3]);
    let payload_end = usize::try_from(payload_len)
        .ok()
        .and_then(|n| n.checked_add(HEADER_LEN))
        .filter(|&end| payload_len >= 1 && end <= plaintext.len())
        .ok_or(ChunkError::PayloadLength(payload_len))?;
    if code == Compression::None as u8 && payload_end - HEADER_LEN > MAX_CHUNK_PLAINTEXT {
        return Err(ChunkError::PayloadLength(payload_len));
    }
    if plaintext
        .get(payload_end..)
        .is_some_and(|pad| pad.iter().any(|&b| b != 0))
    {
        return Err(ChunkError::Padding);
    }
    let compression =
        Compression::from_code(code).ok_or(ChunkError::UnsupportedCompression(code))?;
    let payload = plaintext
        .get(HEADER_LEN..payload_end)
        .ok_or(ChunkError::PayloadLength(payload_len))?;
    let raw: SecretBytes = match compression {
        Compression::None => Zeroizing::new(payload.to_vec()),
    };
    if raw.is_empty() {
        return Err(ChunkError::PayloadLength(payload_len));
    }
    if !bool::from(PlainHash::of(hk, &raw).ct_eq(expected)) {
        return Err(ChunkError::PlainHashMismatch);
    }
    Ok(raw)
}

/// Seals an arbitrary padded plaintext the way [`seal_chunk`] does, without
/// the writer's rules, so that tests can reach every reader rejection.
#[cfg(test)]
pub(crate) fn seal_plaintext_for_test(keys: &ChunkKeys, plaintext: &[u8]) -> Vec<u8> {
    let nonce = crate::bytes::fill::<24>(&[&keyed_hash(keys.nk.expose(), &[plaintext])]);
    let mut stored = nonce.to_vec();
    stored.extend(xchacha_seal(keys.ck.expose(), &nonce, &keys.aad, plaintext).unwrap_or_default());
    stored
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_keys() -> (ChunkKeys, ChunkHashKey) {
        let dk = DataKey::from_bytes([1; 32]);
        (
            ChunkKeys::new(&dk, &FolderId([2; 32]), 1),
            dk.chunk_hash_key(),
        )
    }

    #[test]
    fn padme_examples_from_the_spec() {
        for (l, p) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (5, 5),
            (9, 10),
            (100, 104),
            (1000, 1024),
            (65_537, 67_584),
            (1_048_577, 1_081_344),
        ] {
            assert_eq!(padme(l), Some(p), "padme({l})");
        }
        assert_eq!(
            padme(MAX_CHUNK_PLAINTEXT as u64 + 5).unwrap() + 40,
            MAX_STORED_LEN as u64
        );
        assert_eq!(padme(6).unwrap() + 40, MIN_STORED_LEN as u64);
        // Near the top of u64 the padded form does not fit: None, never a wrap.
        assert_eq!(padme(u64::MAX), None);
        assert_eq!(padme(1u64 << 63), Some(1u64 << 63));
    }

    proptest! {
        #[test]
        fn padme_bounds(l in 0u64..(1u64 << 40)) {
            let p = padme(l).unwrap();
            prop_assert!(p >= l);
            prop_assert_eq!(padme(p), Some(p), "idempotent");
            // Overhead at most 12 % (PURBs), and strictly less than the next power of two bound.
            prop_assert!(u128::from(p) * 100 <= u128::from(l) * 112 + 100);
            if l >= 2 {
                let e = l.ilog2();
                let s = 32 - e.leading_zeros();
                prop_assert_eq!(p & ((1u64 << (e - s)) - 1), 0, "low bits zero");
            }
        }

        #[test]
        fn seal_open_round_trip(raw in proptest::collection::vec(any::<u8>(), 1..3000)) {
            let (keys, hk) = test_keys();
            let sealed = seal_chunk(&keys, &raw).unwrap();
            let again = seal_chunk(&keys, &raw).unwrap();
            prop_assert_eq!(&sealed, &again, "deterministic");
            prop_assert_eq!(sealed.stored.len() as u64, padme((raw.len() + 5) as u64).unwrap() + 40);
            prop_assert_eq!(cipher_hash(&sealed.stored), sealed.cipher_hash);
            let opened = open_chunk(&keys, &hk, &sealed.stored, &PlainHash::of(&hk, &raw)).unwrap();
            prop_assert_eq!(&*opened, &raw[..]);
        }

        #[test]
        fn tampering_is_detected(raw in proptest::collection::vec(any::<u8>(), 1..300), at in 0usize..400, bit in 0u8..8) {
            let (keys, hk) = test_keys();
            let sealed = seal_chunk(&keys, &raw).unwrap();
            let mut stored = sealed.stored.clone();
            let at = at % stored.len();
            stored[at] ^= 1 << bit;
            let r = open_chunk(&keys, &hk, &stored, &PlainHash::of(&hk, &raw));
            prop_assert_eq!(r, Err(ChunkError::Open));
            prop_assert_ne!(cipher_hash(&stored), sealed.cipher_hash);
        }
    }

    #[test]
    fn different_plaintexts_get_different_nonces_and_epochs_separate() {
        let (keys, _) = test_keys();
        let a = seal_chunk(&keys, b"a").unwrap();
        let b = seal_chunk(&keys, b"b").unwrap();
        assert_ne!(a.stored[..24], b.stored[..24]);
        let other_epoch = ChunkKeys::new(&DataKey::from_bytes([1; 32]), &FolderId([2; 32]), 2);
        let (_, hk) = test_keys();
        assert_eq!(
            open_chunk(&other_epoch, &hk, &a.stored, &PlainHash::of(&hk, b"a")),
            Err(ChunkError::Open)
        );
        assert_eq!(format!("{keys:?}"), "ChunkKeys([redacted])");
        assert!(format!("{:?}", PlainHash::of(&hk, b"a")).starts_with("PlainHash("));
        assert!(PlainHash::from_slice(&[0; 3]).is_none());
    }

    #[test]
    fn writer_bounds() {
        let (keys, _) = test_keys();
        assert_eq!(
            seal_chunk(&keys, b"").unwrap_err(),
            ChunkError::RawLength(0)
        );
        let too_big = vec![0u8; MAX_CHUNK_PLAINTEXT + 1];
        assert_eq!(
            seal_chunk(&keys, &too_big).unwrap_err(),
            ChunkError::RawLength(MAX_CHUNK_PLAINTEXT + 1)
        );
        let max = vec![7u8; MAX_CHUNK_PLAINTEXT];
        let sealed = seal_chunk(&keys, &max).unwrap();
        assert_eq!(sealed.stored.len(), MAX_STORED_LEN);
    }

    /// Builds a stored blob from an arbitrary padded plaintext, bypassing the
    /// writer rules, so that every reader rejection path can be reached.
    fn forge(keys: &ChunkKeys, plaintext: &[u8]) -> Vec<u8> {
        seal_plaintext_for_test(keys, plaintext)
    }

    #[test]
    fn every_reader_rejection_path() {
        let (keys, hk) = test_keys();
        let expected = PlainHash::of(&hk, b"hello");
        // Lengths.
        assert_eq!(
            open_chunk(&keys, &hk, &[0; 45], &expected).err(),
            Some(ChunkError::StoredLength(45))
        );
        assert_eq!(
            open_chunk(&keys, &hk, &vec![0; MAX_STORED_LEN + 1], &expected),
            Err(ChunkError::StoredLength(MAX_STORED_LEN + 1))
        );
        // 49 - 40 = 9 is not a Padmé length (lengths 8 to 15 round to even), while 47 - 40 = 7 is one.
        assert_eq!(
            open_chunk(&keys, &hk, &[0; 49], &expected),
            Err(ChunkError::NotPadmeLength(9))
        );
        assert_eq!(
            open_chunk(&keys, &hk, &[0; 47], &expected),
            Err(ChunkError::Open)
        );
        // Bad tag.
        let good = seal_chunk(&keys, b"hello").unwrap();
        let mut bad_tag = good.stored.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_chunk(&keys, &hk, &bad_tag, &expected),
            Err(ChunkError::Open)
        );
        // Non-zero padding: plaintext of Padmé length 10 with payload 3 and a stray byte.
        let mut pt = vec![0u8, 0, 0, 0, 3, b'a', b'b', b'c', 0, 1];
        assert_eq!(
            open_chunk(&keys, &hk, &forge(&keys, &pt), &expected),
            Err(ChunkError::Padding)
        );
        // Payload length over L' - 5.
        pt = vec![0u8, 0, 0, 0, 6, b'a', b'b', b'c', 0, 0];
        assert_eq!(
            open_chunk(&keys, &hk, &forge(&keys, &pt), &expected),
            Err(ChunkError::PayloadLength(6))
        );
        // Empty payload.
        pt = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            open_chunk(&keys, &hk, &forge(&keys, &pt), &expected),
            Err(ChunkError::PayloadLength(0))
        );
        // Unsupported compression code.
        pt = vec![2u8, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0];
        assert_eq!(
            open_chunk(&keys, &hk, &forge(&keys, &pt), &expected),
            Err(ChunkError::UnsupportedCompression(2))
        );
        // Bad plain hash.
        assert_eq!(
            open_chunk(&keys, &hk, &good.stored, &PlainHash::of(&hk, b"hellp")),
            Err(ChunkError::PlainHashMismatch)
        );
        // The good one opens.
        assert_eq!(
            &*open_chunk(&keys, &hk, &good.stored, &expected).unwrap(),
            b"hello"
        );
        for e in [
            ChunkError::RawLength(0),
            ChunkError::StoredLength(1),
            ChunkError::NotPadmeLength(7),
            ChunkError::Open,
            ChunkError::PayloadLength(0),
            ChunkError::Padding,
            ChunkError::UnsupportedCompression(9),
            ChunkError::PlainHashMismatch,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }
}
