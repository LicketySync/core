// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Chunk encryption (`keys.md` section 3.2) and Padmé padding (section 3.3).
//!
//! One chunk becomes `nonce || XChaCha(ck, nonce, folder_id, header || payload
//! || zeros)` where the plaintext is Padmé-padded and the nonce is keyed
//! BLAKE3 under `nk` over that exact padded plaintext, so the encryption is
//! deterministic for the folder and the plaintext (sealed peers deduplicate
//! and verify by `cipher_hash`) and two different plaintexts never share a
//! nonce under one key (TM-12); the associated data, the folder ID, is a
//! function of the key alone. The plaintext hash is keyed under the folder's
//! `hk`, so it is a fingerprint only to key holders (TM-14).
//! `MAX_CHUNK_PLAINTEXT` is enforced before anything is allocated (TM-2).
//!
//! The keys come only from a write or read key ([`FolderKey::chunk_keys`]),
//! which pairs the data key with its own folder ID; a sealed key has none.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::aead::{xchacha_open, xchacha_seal, AeadError, SealError};
use crate::folder::{FolderKey, ReadKey, WriteKey};
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

/// [`padme`] of an in-memory length.
pub(crate) fn padme_len(len: usize) -> Option<usize> {
    u64::try_from(len)
        .ok()
        .and_then(padme)
        .and_then(|p| usize::try_from(p).ok())
}

/// A chunk's compression code (section 3.2): the codes this release
/// implements, which a reader decodes; any other is a writer fault (ruling
/// S-2). Phase 0 implements, writes and reads `0` only.
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
/// reference (section 3.2), carried inside the sealed part of index records.
/// It has no `==`: compare with [`PlainHash::ct_eq`], since an early-exit
/// comparison would time a guess at a chunk's content.
#[derive(Clone, Copy)]
pub struct PlainHash(pub [u8; sizes::ID]);

impl fmt::Debug for PlainHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlainHash({})", crate::ids::hex(&self.0))
    }
}

impl PlainHash {
    /// Reads a hash from exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; sizes::ID]>::try_from(bytes).ok().map(Self)
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

/// The chunk keys of one folder: `ck`, `nk` and `hk`, derived from its data
/// key, and the associated data, the folder ID. Zeroized on drop.
pub struct ChunkKeys {
    ck: ChunkKey,
    nk: ChunkNonceKey,
    hk: ChunkHashKey,
    folder_id: FolderId,
}

impl fmt::Debug for ChunkKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkKeys({}, [redacted])", self.folder_id)
    }
}

impl ChunkKeys {
    /// The chunk keys of `folder_id` from its data key.
    fn new(dk: &DataKey, folder_id: FolderId) -> Self {
        ChunkKeys {
            ck: dk.chunk_key(),
            nk: dk.chunk_nonce_key(),
            hk: dk.chunk_hash_key(),
            folder_id,
        }
    }

    /// `plain_hash = BLAKE3_keyed(hk, raw)`, the hash an index record's
    /// sealed part names a chunk by: what a writer compares local content
    /// with, without sealing it.
    #[must_use]
    pub fn plain_hash(&self, raw: &[u8]) -> PlainHash {
        PlainHash(keyed_hash(self.hk.expose(), &[raw]))
    }
}

impl WriteKey {
    /// This folder's chunk keys.
    #[must_use]
    pub fn chunk_keys(&self) -> ChunkKeys {
        ChunkKeys::new(self.data_key(), self.verifier().folder_id())
    }
}

impl ReadKey {
    /// This folder's chunk keys.
    #[must_use]
    pub fn chunk_keys(&self) -> ChunkKeys {
        ChunkKeys::new(self.data_key(), self.verifier().folder_id())
    }
}

impl FolderKey {
    /// This folder's chunk keys, for the write and read tiers; a sealed key
    /// holds no data key and opens no chunk.
    #[must_use]
    pub fn chunk_keys(&self) -> Option<ChunkKeys> {
        match self {
            FolderKey::Write(k) => Some(k.chunk_keys()),
            FolderKey::Read(k) => Some(k.chunk_keys()),
            FolderKey::Sealed(_) => None,
        }
    }
}

/// Why a chunk could not be sealed or opened. The outcome for each (who is
/// blamed) is `protocol.md` 4.6's business; this type names the step. No
/// value here carries a length read from inside a ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// A raw chunk must be 1 to `MAX_CHUNK_PLAINTEXT` bytes.
    RawLength(usize),
    /// The stored length is outside `46 ..= 4 325 416`.
    StoredLength(usize),
    /// The stored length minus 40 is not a Padmé length.
    NotPadmeLength(usize),
    /// The cipher refused to seal, which it does only beyond its own limit.
    Seal,
    /// The AEAD did not open.
    Open,
    /// The payload length in the header is 0, exceeds what the plaintext
    /// holds, or, for compression `0`, exceeds `MAX_CHUNK_PLAINTEXT`.
    PayloadLength,
    /// A padding byte is not zero.
    Padding,
    /// The compression code is not one this release implements.
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
            Self::Seal => f.write_str("chunk could not be sealed"),
            Self::Open => f.write_str("chunk did not decrypt"),
            Self::PayloadLength => f.write_str("the chunk's payload length is out of range"),
            Self::Padding => f.write_str("a padding byte is not zero"),
            Self::UnsupportedCompression(c) => write!(f, "compression code {c} is not implemented"),
            Self::PlainHashMismatch => f.write_str("plaintext hash does not match the record"),
        }
    }
}

impl std::error::Error for ChunkError {}

/// A sealed chunk: the stored blob, its ciphertext hash, and the plaintext
/// hash that the index record's sealed part names it by.
#[derive(Clone, Debug)]
pub struct SealedChunk {
    /// `nonce || ct`, what peers store and serve.
    pub stored: Vec<u8>,
    /// `H("licketysync/v1/hash/chunk", stored)`.
    pub cipher_hash: CipherHash,
    /// `BLAKE3_keyed(hk, raw)`.
    pub plain_hash: PlainHash,
}

/// Seals `raw` under the folder's chunk keys with compression `0` (phase 0):
/// builds `header || raw || zeros` to the Padmé length, derives the nonce
/// from that plaintext under `nk`, and encrypts under `ck` with the folder ID
/// as associated data. Deterministic.
///
/// # Errors
///
/// [`ChunkError::RawLength`] when `raw` is empty or over `MAX_CHUNK_PLAINTEXT`;
/// [`ChunkError::Seal`] only if the cipher refuses, which it does not for a
/// chunk of that size.
pub fn seal_chunk(keys: &ChunkKeys, raw: &[u8]) -> Result<SealedChunk, ChunkError> {
    let (payload_len, padded) = u32::try_from(raw.len())
        .ok()
        .filter(|_| (1..=MAX_CHUNK_PLAINTEXT).contains(&raw.len()))
        .zip(padme_len(HEADER_LEN + raw.len()))
        .ok_or(ChunkError::RawLength(raw.len()))?;
    let mut plaintext: SecretBytes = Zeroizing::new(Vec::with_capacity(padded));
    plaintext.push(Compression::None as u8);
    plaintext.extend_from_slice(&payload_len.to_be_bytes());
    plaintext.extend_from_slice(raw);
    plaintext.resize(padded, 0);
    let nonce: [u8; sizes::NONCE] =
        crate::bytes::first(&keyed_hash(keys.nk.expose(), &[&plaintext]));
    let ct = xchacha_seal(
        keys.ck.expose(),
        &nonce,
        keys.folder_id.as_bytes(),
        &plaintext,
    )
    .map_err(|SealError| ChunkError::Seal)?;
    let mut stored = Vec::with_capacity(sizes::NONCE + ct.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&ct);
    Ok(SealedChunk {
        cipher_hash: cipher_hash(&stored),
        plain_hash: keys.plain_hash(raw),
        stored,
    })
}

/// Opens a stored chunk in the order section 3.2 fixes: the stored length and
/// its Padmé shape, the nonce split, the AEAD, the header and the payload
/// length, the zero padding, the compression code, then the plaintext hash
/// against `expected`. Nothing is allocated beyond the stored length, which is
/// bounded first (TM-2). The result is zeroized on drop.
///
/// # Errors
///
/// The [`ChunkError`] of the first failing step.
pub fn open_chunk(
    keys: &ChunkKeys,
    stored: &[u8],
    expected: &PlainHash,
) -> Result<SecretBytes, ChunkError> {
    let (nonce, ct) = stored
        .split_first_chunk::<{ sizes::NONCE }>()
        .filter(|_| (MIN_STORED_LEN..=MAX_STORED_LEN).contains(&stored.len()))
        .ok_or(ChunkError::StoredLength(stored.len()))?;
    let padded = ct.len() - sizes::TAG;
    if padme_len(padded) != Some(padded) {
        return Err(ChunkError::NotPadmeLength(padded));
    }
    let plaintext = xchacha_open(keys.ck.expose(), nonce, keys.folder_id.as_bytes(), ct)
        .map_err(|AeadError| ChunkError::Open)?;
    // The header, then a payload of 1 to L' - 5 bytes and the padding after it.
    let (code, payload, padding) = plaintext
        .split_first_chunk::<HEADER_LEN>()
        .and_then(|(header, rest)| {
            let [code, l0, l1, l2, l3] = *header;
            let len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3]))
                .ok()
                .filter(|&n| n >= 1)?;
            let (payload, padding) = rest.split_at_checked(len)?;
            Some((code, payload, padding))
        })
        .ok_or(ChunkError::PayloadLength)?;
    if code == Compression::None as u8 && payload.len() > MAX_CHUNK_PLAINTEXT {
        return Err(ChunkError::PayloadLength);
    }
    if padding.iter().any(|&b| b != 0) {
        return Err(ChunkError::Padding);
    }
    // Compression 0 is the payload itself, 1 to MAX_CHUNK_PLAINTEXT bytes by
    // the checks above; a decoder for another code bounds its output there and
    // requires at least one byte out.
    let raw: SecretBytes =
        match Compression::from_code(code).ok_or(ChunkError::UnsupportedCompression(code))? {
            Compression::None => Zeroizing::new(payload.to_vec()),
        };
    if !bool::from(keys.plain_hash(&raw).ct_eq(expected)) {
        return Err(ChunkError::PlainHashMismatch);
    }
    Ok(raw)
}

/// Seals an arbitrary padded plaintext the way [`seal_chunk`] does, without
/// the writer's rules, so that tests can reach every reader rejection.
#[cfg(test)]
pub(crate) fn seal_plaintext_for_test(keys: &ChunkKeys, plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; sizes::NONCE] =
        crate::bytes::first(&keyed_hash(keys.nk.expose(), &[plaintext]));
    let mut stored = nonce.to_vec();
    stored.extend(
        xchacha_seal(
            keys.ck.expose(),
            &nonce,
            keys.folder_id.as_bytes(),
            plaintext,
        )
        .unwrap_or_default(),
    );
    stored
}

/// The plaintext of `keys.md` 9 item 6's "compression 0 payload over
/// `MAX_CHUNK_PLAINTEXT`" variant: code 0, `be32(MAX_CHUNK_PLAINTEXT + 1)`,
/// zeros to `padme(MAX_CHUNK_PLAINTEXT + 6)`, so that every check before the
/// compression-0 bound passes.
#[cfg(test)]
pub(crate) fn over_the_bound_plaintext() -> Vec<u8> {
    let len = MAX_CHUNK_PLAINTEXT + 1;
    let mut plaintext = vec![0u8];
    plaintext.extend(u32::try_from(len).unwrap_or(0).to_be_bytes());
    plaintext.resize(padme_len(HEADER_LEN + len).unwrap_or(0), 0);
    plaintext
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
    use crate::folder::tests::write_key;
    use proptest::prelude::*;

    fn test_keys() -> ChunkKeys {
        ChunkKeys::new(&DataKey::fill_with(|o| *o = [1; 32]), FolderId([2; 32]))
    }

    fn hash(keys: &ChunkKeys, raw: &[u8]) -> PlainHash {
        keys.plain_hash(raw)
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
        assert_eq!(padme_len(9), Some(10));
        assert_eq!(
            padme_len(MAX_CHUNK_PLAINTEXT + 6),
            Some(4_325_376),
            "the padded length of keys.md 9 item 6's over-the-bound variant"
        );
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
            let keys = test_keys();
            let sealed = seal_chunk(&keys, &raw).unwrap();
            let again = seal_chunk(&keys, &raw).unwrap();
            prop_assert_eq!(&sealed.stored, &again.stored, "deterministic");
            prop_assert_eq!(sealed.cipher_hash, again.cipher_hash);
            prop_assert_eq!(sealed.stored.len() as u64, padme((raw.len() + 5) as u64).unwrap() + 40);
            prop_assert_eq!(cipher_hash(&sealed.stored), sealed.cipher_hash);
            prop_assert!(bool::from(sealed.plain_hash.ct_eq(&hash(&keys, &raw))));
            let opened = open_chunk(&keys, &sealed.stored, &sealed.plain_hash).unwrap();
            prop_assert_eq!(&*opened, &raw[..]);
        }

        #[test]
        fn tampering_is_detected(raw in proptest::collection::vec(any::<u8>(), 1..300), at in 0usize..400, bit in 0u8..8) {
            let keys = test_keys();
            let sealed = seal_chunk(&keys, &raw).unwrap();
            let mut stored = sealed.stored.clone();
            let at = at % stored.len();
            stored[at] ^= 1 << bit;
            let r = open_chunk(&keys, &stored, &sealed.plain_hash);
            prop_assert_eq!(r, Err(ChunkError::Open));
            prop_assert_ne!(cipher_hash(&stored), sealed.cipher_hash);
        }
    }

    #[test]
    fn different_plaintexts_get_different_nonces_and_folders_separate() {
        let keys = test_keys();
        let a = seal_chunk(&keys, b"a").unwrap();
        let b = seal_chunk(&keys, b"b").unwrap();
        assert_ne!(a.stored[..24], b.stored[..24]);
        // The same data key under another folder ID: the associated data differs.
        let other_folder = ChunkKeys::new(&DataKey::fill_with(|o| *o = [1; 32]), FolderId([3; 32]));
        assert_eq!(
            open_chunk(&other_folder, &a.stored, &a.plain_hash),
            Err(ChunkError::Open)
        );
        // Another folder's keys give other stored bytes for the same chunk.
        let other_keys = ChunkKeys::new(&DataKey::fill_with(|o| *o = [4; 32]), FolderId([2; 32]));
        assert_ne!(seal_chunk(&other_keys, b"a").unwrap().stored, a.stored);
        assert_eq!(
            format!("{keys:?}"),
            format!("ChunkKeys({}, [redacted])", FolderId([2; 32]))
        );
        assert!(format!("{:?}", a.plain_hash).starts_with("PlainHash("));
        assert!(PlainHash::from_slice(&[0; 3]).is_none());
        assert!(bool::from(
            PlainHash::from_slice(&a.plain_hash.0)
                .unwrap()
                .ct_eq(&a.plain_hash)
        ));
    }

    /// The chunk keys come from the folder key, paired with its own folder
    /// ID: the write and read keys give the same ones, a sealed key none.
    #[test]
    fn chunk_keys_come_from_write_and_read_keys_only() {
        let w = write_key(9);
        let keys = [
            FolderKey::from(write_key(9)),
            FolderKey::from(w.read_key()),
            FolderKey::from(w.sealed_key()),
        ];
        let from_write = keys[0].chunk_keys().unwrap();
        let from_read = keys[1].chunk_keys().unwrap();
        assert!(keys[2].chunk_keys().is_none());
        assert_eq!(from_write.folder_id, w.verifier().folder_id());
        let sealed = seal_chunk(&from_write, b"chunk").unwrap();
        assert_eq!(
            seal_chunk(&from_read, b"chunk").unwrap().stored,
            sealed.stored
        );
        assert_eq!(
            seal_chunk(&w.chunk_keys(), b"chunk").unwrap().stored,
            sealed.stored
        );
        assert_eq!(
            &*open_chunk(
                &w.read_key().chunk_keys(),
                &sealed.stored,
                &sealed.plain_hash
            )
            .unwrap(),
            b"chunk"
        );
        // The derivation of keys.md 3.1 under the folder ID of keys.md 2.1.
        let dk = w.data_key();
        assert_eq!(from_write.ck.expose(), dk.chunk_key().expose());
        assert_eq!(from_write.nk.expose(), dk.chunk_nonce_key().expose());
        assert_eq!(from_write.hk.expose(), dk.chunk_hash_key().expose());
    }

    #[test]
    fn writer_bounds_and_the_largest_chunk() {
        let keys = test_keys();
        assert_eq!(
            seal_chunk(&keys, b"").unwrap_err(),
            ChunkError::RawLength(0)
        );
        let too_big = vec![0u8; MAX_CHUNK_PLAINTEXT + 1];
        assert_eq!(
            seal_chunk(&keys, &too_big).unwrap_err(),
            ChunkError::RawLength(MAX_CHUNK_PLAINTEXT + 1)
        );
        // Exactly at the caps: MAX_CHUNK_PLAINTEXT seals to MAX_STORED_LEN,
        // and a reader opens a blob of exactly that length.
        let max = vec![7u8; MAX_CHUNK_PLAINTEXT];
        let sealed = seal_chunk(&keys, &max).unwrap();
        assert_eq!(sealed.stored.len(), MAX_STORED_LEN);
        assert_eq!(
            &*open_chunk(&keys, &sealed.stored, &sealed.plain_hash).unwrap(),
            &max[..]
        );
        // The smallest chunk seals to MIN_STORED_LEN and opens.
        let min = seal_chunk(&keys, b"x").unwrap();
        assert_eq!(min.stored.len(), MIN_STORED_LEN);
        assert_eq!(
            &*open_chunk(&keys, &min.stored, &min.plain_hash).unwrap(),
            b"x"
        );
    }

    /// Builds a stored blob from an arbitrary padded plaintext, bypassing the
    /// writer rules, so that every reader rejection path can be reached.
    fn forge(keys: &ChunkKeys, plaintext: &[u8]) -> Vec<u8> {
        seal_plaintext_for_test(keys, plaintext)
    }

    #[test]
    fn every_reader_rejection_path() {
        let keys = test_keys();
        let expected = hash(&keys, b"hello");
        // Lengths.
        assert_eq!(
            open_chunk(&keys, &[0; 45], &expected).err(),
            Some(ChunkError::StoredLength(45))
        );
        assert_eq!(
            open_chunk(&keys, &[0; 23], &expected).err(),
            Some(ChunkError::StoredLength(23)),
            "shorter than the nonce"
        );
        assert_eq!(
            open_chunk(&keys, &vec![0; MAX_STORED_LEN + 1], &expected),
            Err(ChunkError::StoredLength(MAX_STORED_LEN + 1))
        );
        // 49 - 40 = 9 is not a Padmé length (lengths 8 to 15 round to even), while 47 - 40 = 7 is one.
        assert_eq!(
            open_chunk(&keys, &[0; 49], &expected),
            Err(ChunkError::NotPadmeLength(9))
        );
        assert_eq!(
            open_chunk(&keys, &[0; 47], &expected),
            Err(ChunkError::Open)
        );
        // Bad tag.
        let good = seal_chunk(&keys, b"hello").unwrap();
        let mut bad_tag = good.stored.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_chunk(&keys, &bad_tag, &expected),
            Err(ChunkError::Open)
        );
        // Non-zero padding: plaintext of Padmé length 10 with payload 3 and a stray byte.
        let mut pt = vec![0u8, 0, 0, 0, 3, b'a', b'b', b'c', 0, 1];
        assert_eq!(
            open_chunk(&keys, &forge(&keys, &pt), &expected),
            Err(ChunkError::Padding)
        );
        // Payload length over L' - 5.
        pt = vec![0u8, 0, 0, 0, 6, b'a', b'b', b'c', 0, 0];
        assert_eq!(
            open_chunk(&keys, &forge(&keys, &pt), &expected),
            Err(ChunkError::PayloadLength)
        );
        // Payload length exactly L' - 5 is accepted up to the hash check.
        pt = vec![0u8, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(
            &*open_chunk(&keys, &forge(&keys, &pt), &expected).unwrap(),
            b"hello"
        );
        // Empty payload.
        pt = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            open_chunk(&keys, &forge(&keys, &pt), &expected),
            Err(ChunkError::PayloadLength)
        );
        // Compression 0 with a payload one byte over MAX_CHUNK_PLAINTEXT, in a
        // plaintext long enough to hold it (keys.md 9 item 6): every check
        // before that bound passes, the stored blob is exactly MAX_STORED_LEN.
        let over = forge(&keys, &over_the_bound_plaintext());
        assert_eq!(over.len(), MAX_STORED_LEN);
        assert_eq!(
            open_chunk(&keys, &over, &expected),
            Err(ChunkError::PayloadLength)
        );
        // The same length under a code that is not 0 passes that bound and is
        // refused for its code, as a later decoder would bound its own output.
        let mut over_code_2 = over_the_bound_plaintext();
        over_code_2[0] = 2;
        assert_eq!(
            open_chunk(&keys, &forge(&keys, &over_code_2), &expected),
            Err(ChunkError::UnsupportedCompression(2))
        );
        // Unsupported compression code.
        pt = vec![2u8, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0];
        assert_eq!(
            open_chunk(&keys, &forge(&keys, &pt), &expected),
            Err(ChunkError::UnsupportedCompression(2))
        );
        // Bad plain hash.
        assert_eq!(
            open_chunk(&keys, &good.stored, &hash(&keys, b"hellp")),
            Err(ChunkError::PlainHashMismatch)
        );
        // The good one opens.
        assert_eq!(
            &*open_chunk(&keys, &good.stored, &expected).unwrap(),
            b"hello"
        );
        for e in [
            ChunkError::RawLength(0),
            ChunkError::StoredLength(1),
            ChunkError::NotPadmeLength(7),
            ChunkError::Seal,
            ChunkError::Open,
            ChunkError::PayloadLength,
            ChunkError::Padding,
            ChunkError::UnsupportedCompression(9),
            ChunkError::PlainHashMismatch,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }
}
