// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sealed metadata (`keys.md` 3.4) and path tags (section 3.5).
//!
//! Everything that would name a file or date it (path, kind, true size,
//! times, mode, plaintext chunk hashes, the writer's device ID and counter,
//! the version vector and the deletion marks) sits in the sealed part of its
//! index record, which only read and write holders open; a cleanup's issuer
//! and counter sit in its own sealed part.
//!
//! ```text
//! bucket = the least power of two that is at least max(256, len(meta) + 4)   # 256 ..= 2^21; a cleanup's 256 ..= 1 024
//! plain  = be32(len(meta)) || meta || zeros(bucket - len(meta) - 4)
//! aad    = folder_id || path_tag            # 64 bytes, an index record
//!        | folder_id                        # 32 bytes, a cleanup
//! nonce  = 24 bytes through the caller's randomness
//! sealed = nonce || XChaCha(rk, nonce, aad, plain)
//! ```
//!
//! [`RecordKeys`] holds `rk`, `tk` and the folder ID together, made only from
//! a write or read key, so that no caller can pair a key with another
//! folder's ID; its four functions name the record type, so that no caller
//! can pass an index record's aad for a cleanup or the reverse. `meta` is the
//! canonical `SealedMeta` or `CleanupMeta` the protocol crate encodes; this
//! module neither builds nor parses it.
//!
//! On opening, a sealed part whose length is not 40 plus an allowed bucket is
//! malformed ([`MetaError::SealedLength`], `protocol.md` 4.4 step 1). Every
//! failure after that is a writer fault (step 7), since the body that holds
//! the seal verified under the folder key, each its own variant: the seal does
//! not open, the length field does not fit, the padding goes past the least
//! bucket that holds the metadata (a writer fault on every release, so that
//! implementations never split over it), a padding byte is not zero. A writer
//! whose sealed part would pass its record type's cap gets
//! [`MetaError::TooLong`] and does not write the record.
//!
//! # The old layout, kept for one commit
//!
//! [`seal_meta`], [`open_meta`], [`MAX_SEALED_BYTES`] and the error
//! [`MetaError::TooShort`] are the layout before 2026-10-25 (Padmé padding, a
//! 72-byte aad of the folder ID, device ID and sequence number, 1 572 864
//! bytes at most). They are retired by `keys.md` 3.4 on 2026-10-25, used only
//! by the old index exchange, and removed in the next commit of this series.

use core::fmt;

use zeroize::Zeroizing;

use crate::aead::{xchacha_open, xchacha_seal, AeadError, SealError};
use crate::chunk::padme_len;
use crate::folder::{FolderKey, ReadKey, WriteKey};
use crate::ids::{DeviceId, FolderId, PathTag};
use crate::labels::keyed_hash;
use crate::rng::RandomFill;
use crate::secret::{DataKey, PathTagKey, RecordKey, SecretBytes};
use crate::suite::sizes;

/// The smallest sealed part: its nonce and tag.
pub const MIN_SEALED_BYTES: usize = sizes::NONCE + sizes::TAG;

/// The least bucket a sealed part's plaintext takes: 256 bytes (`keys.md` 3.4).
pub const MIN_BUCKET: usize = 256;

/// The largest bucket of an index record's sealed part: 2^21 bytes.
pub const MAX_INDEX_BUCKET: usize = 1 << 21;

/// The largest bucket of a cleanup's sealed part: 1 024 bytes.
pub const MAX_CLEANUP_BUCKET: usize = 1024;

/// The largest sealed part of an index record, `MAX_SEALED_BYTES` of
/// `keys.md` 3.4 and `protocol.md` 4.4: 40 + 2^21 = 2 097 192 bytes.
pub const MAX_INDEX_SEALED_BYTES: usize = MIN_SEALED_BYTES + MAX_INDEX_BUCKET;

/// The largest sealed part of a cleanup: 40 + 1 024 = 1 064 bytes.
pub const MAX_CLEANUP_SEALED_BYTES: usize = MIN_SEALED_BYTES + MAX_CLEANUP_BUCKET;

/// The largest sealed part an index record could carry before 2026-10-25:
/// 1 572 864 bytes. Retired by `keys.md` 3.4 on 2026-10-25; used only by the
/// old index exchange ([`seal_meta`], [`open_meta`]); removed in the next
/// commit of this series.
pub const MAX_SEALED_BYTES: usize = 1_572_864;

/// The length field before the metadata, `be32(len(meta))`.
const LENGTH_FIELD: usize = 4;

/// Which signed record a sealed part belongs to (`keys.md` 3.4): it fixes the
/// associated data and the buckets the sealed part may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedKind {
    /// An index record's `SealedMeta`, under `folder_id || path_tag`, in a
    /// bucket of 256 to 2^21 bytes.
    Index,
    /// A cleanup's `CleanupMeta`, under `folder_id`, in a bucket of 256, 512 or
    /// 1 024 bytes.
    Cleanup,
}

impl SealedKind {
    /// The largest bucket of this kind.
    #[must_use]
    pub const fn max_bucket(self) -> usize {
        match self {
            SealedKind::Index => MAX_INDEX_BUCKET,
            SealedKind::Cleanup => MAX_CLEANUP_BUCKET,
        }
    }

    /// The largest sealed part of this kind: 2 097 192 or 1 064 bytes.
    #[must_use]
    pub const fn max_sealed_len(self) -> usize {
        MIN_SEALED_BYTES + self.max_bucket()
    }

    /// Whether `len` is a sealed part's length of this kind, 40 plus a power
    /// of two from 256 to [`SealedKind::max_bucket`]: `protocol.md` 4.4 step
    /// 1, any other length is malformed.
    #[must_use]
    pub fn is_sealed_len(self, len: usize) -> bool {
        len.checked_sub(MIN_SEALED_BYTES).is_some_and(|bucket| {
            bucket.is_power_of_two() && (MIN_BUCKET..=self.max_bucket()).contains(&bucket)
        })
    }
}

/// The bucket of `meta_len` bytes of metadata: the least power of two that is
/// at least `max(256, meta_len + 4)` (`keys.md` 3.4), or `None` when that does
/// not fit `usize`. Whether it is within a record type's cap is
/// [`SealedKind::max_bucket`]'s question.
#[must_use]
pub fn bucket(meta_len: usize) -> Option<usize> {
    meta_len
        .checked_add(LENGTH_FIELD)
        .and_then(usize::checked_next_power_of_two)
        .map(|b| b.max(MIN_BUCKET))
}

/// Why metadata could not be sealed or opened. On opening,
/// [`MetaError::SealedLength`] (and the old layout's [`MetaError::TooShort`]
/// and [`MetaError::TooLong`]) make the record malformed; every other variant
/// is a writer fault (`protocol.md` 4.4 step 7). No value here carries a
/// length read from inside a seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    /// The old layout: the sealed part is shorter than its nonce and tag.
    /// Retired with that layout; removed in the next commit of this series.
    TooShort(usize),
    /// Sealing: the sealed part this metadata would make, of this length, is
    /// longer than its record type allows (the old layout: on opening too).
    TooLong(usize),
    /// Opening: the sealed part's length is not 40 plus a power of two its
    /// record type allows (malformed).
    SealedLength(usize),
    /// The cipher refused to seal, which it does only beyond its own limit.
    Seal,
    /// The AEAD did not open: another key, another place, or damage.
    Open,
    /// The plaintext is too short for its length field, or the length in it
    /// exceeds what the plaintext holds.
    Length,
    /// The plaintext is longer than the least power of two of at least 256
    /// bytes that holds the metadata: a writer fault on every release.
    OverPadded,
    /// A padding byte is not zero.
    Padding,
}

impl MetaError {
    /// Whether the error makes the record malformed (`protocol.md` 4.4 step 1:
    /// the sender's fault) rather than a writer fault (step 7).
    #[must_use]
    pub fn is_malformed(&self) -> bool {
        matches!(
            self,
            MetaError::TooShort(_) | MetaError::TooLong(_) | MetaError::SealedLength(_)
        )
    }
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "sealed metadata of {n} bytes is too short"),
            Self::TooLong(n) => {
                write!(
                    f,
                    "sealed metadata of {n} bytes is longer than its record type allows"
                )
            }
            Self::SealedLength(n) => write!(
                f,
                "sealed metadata of {n} bytes is not 40 plus an allowed power of two"
            ),
            Self::Seal => f.write_str("metadata could not be sealed"),
            Self::Open => f.write_str("sealed metadata did not decrypt"),
            Self::Length => f.write_str("the metadata's length field does not fit the plaintext"),
            Self::OverPadded => {
                f.write_str("the metadata is padded past the least power of two that holds it")
            }
            Self::Padding => f.write_str("a padding byte is not zero"),
        }
    }
}

impl std::error::Error for MetaError {}

/// The keys of a folder's sealed metadata and file IDs: the record key `rk`,
/// the path-tag key `tk` and the folder ID they belong to (`keys.md` 3.1, 3.4,
/// 3.5). Made only from a write or read key ([`WriteKey::record_keys`],
/// [`ReadKey::record_keys`], [`FolderKey::record_keys`]); a sealed key has no
/// data key and none of these. Zeroized on drop; its `Debug` names only the
/// folder.
pub struct RecordKeys {
    rk: RecordKey,
    tk: PathTagKey,
    folder_id: FolderId,
}

impl fmt::Debug for RecordKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordKeys({}, [redacted])", self.folder_id)
    }
}

/// Where a sealed part sits, which fixes its associated data.
#[derive(Clone, Copy)]
enum Place<'a> {
    Index(&'a PathTag),
    Cleanup,
}

impl Place<'_> {
    fn kind(self) -> SealedKind {
        match self {
            Place::Index(_) => SealedKind::Index,
            Place::Cleanup => SealedKind::Cleanup,
        }
    }
}

impl RecordKeys {
    /// The record keys of `folder_id` from its data key.
    fn new(dk: &DataKey, folder_id: FolderId) -> Self {
        RecordKeys {
            rk: dk.record_key(),
            tk: dk.path_tag_key(),
            folder_id,
        }
    }

    /// The folder these keys belong to.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }

    /// The file ID of `path`: `path_tag = BLAKE3_keyed(tk, path)` over the
    /// path's UTF-8 bytes exactly as `SealedMeta.path` holds them, with no
    /// normalisation (`keys.md` 3.5): `Docs` and `docs`, or a composed and a
    /// decomposed accent, are different paths with different tags. This crate
    /// is the only caller of BLAKE3 for it (`suites.md` 2.4).
    #[must_use]
    pub fn path_tag(&self, path: &str) -> PathTag {
        PathTag(keyed_hash(self.tk.expose(), &[path.as_bytes()]))
    }

    /// The associated data of a place: `folder_id || path_tag` (64 bytes) or
    /// `folder_id` (32 bytes).
    fn aad(&self, place: Place<'_>) -> Vec<u8> {
        let mut aad = self.folder_id.as_bytes().to_vec();
        if let Place::Index(tag) = place {
            aad.extend_from_slice(tag.as_bytes());
        }
        aad
    }

    /// Seals the canonical `SealedMeta` bytes `meta` of the index record whose
    /// file ID is `path_tag`, under `aad = folder_id || path_tag`, padded to
    /// the least bucket, with 24 fresh bytes from `rng` as the nonce.
    ///
    /// # Errors
    ///
    /// [`MetaError::TooLong`], with the length the sealed part would have,
    /// when that passes [`MAX_INDEX_SEALED_BYTES`], judged before anything is
    /// allocated or drawn; [`MetaError::Seal`] only if the cipher refuses,
    /// which it does not for a seal of that size.
    pub fn seal_index_meta(
        &self,
        path_tag: &PathTag,
        meta: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<Vec<u8>, MetaError> {
        self.seal(Place::Index(path_tag), meta, rng)
    }

    /// Seals the canonical `CleanupMeta` bytes `meta` of a cleanup, under
    /// `aad = folder_id`, as [`RecordKeys::seal_index_meta`] does.
    ///
    /// # Errors
    ///
    /// [`MetaError::TooLong`] past [`MAX_CLEANUP_SEALED_BYTES`];
    /// [`MetaError::Seal`] as above.
    pub fn seal_cleanup_meta(
        &self,
        meta: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<Vec<u8>, MetaError> {
        self.seal(Place::Cleanup, meta, rng)
    }

    /// Opens an index record's sealed part under the aad rebuilt from the
    /// record's own `path_tag`, in the order of `keys.md` 3.4: the length, the
    /// AEAD, the length field, the bucket, the zero padding. The metadata
    /// comes back in a buffer that is zeroized on drop.
    ///
    /// # Errors
    ///
    /// The [`MetaError`] of the first failing step.
    pub fn open_index_meta(
        &self,
        path_tag: &PathTag,
        sealed: &[u8],
    ) -> Result<SecretBytes, MetaError> {
        self.open(Place::Index(path_tag), sealed)
    }

    /// Opens a cleanup's sealed part under `aad = folder_id`, as
    /// [`RecordKeys::open_index_meta`] does.
    ///
    /// # Errors
    ///
    /// The [`MetaError`] of the first failing step.
    pub fn open_cleanup_meta(&self, sealed: &[u8]) -> Result<SecretBytes, MetaError> {
        self.open(Place::Cleanup, sealed)
    }

    fn seal(
        &self,
        place: Place<'_>,
        meta: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<Vec<u8>, MetaError> {
        let kind = place.kind();
        let bucket = bucket(meta.len());
        let sealed_len = bucket.and_then(|b| b.checked_add(MIN_SEALED_BYTES));
        let (len, bucket) = u32::try_from(meta.len())
            .ok()
            .zip(bucket)
            .filter(|&(_, b)| b <= kind.max_bucket())
            .ok_or(MetaError::TooLong(sealed_len.unwrap_or(usize::MAX)))?;
        let mut plain: SecretBytes = Zeroizing::new(Vec::with_capacity(bucket));
        plain.extend_from_slice(&len.to_be_bytes());
        plain.extend_from_slice(meta);
        plain.resize(bucket, 0);
        let mut nonce = [0u8; sizes::NONCE];
        rng(&mut nonce);
        self.seal_plain(place, &nonce, &plain)
    }

    /// `nonce || XChaCha(rk, nonce, aad, plain)`, with no writer's rule.
    fn seal_plain(
        &self,
        place: Place<'_>,
        nonce: &[u8; sizes::NONCE],
        plain: &[u8],
    ) -> Result<Vec<u8>, MetaError> {
        let ct = xchacha_seal(self.rk.expose(), nonce, &self.aad(place), plain)
            .map_err(|SealError| MetaError::Seal)?;
        let mut sealed = Vec::with_capacity(sizes::NONCE + ct.len());
        sealed.extend_from_slice(nonce);
        sealed.extend_from_slice(&ct);
        Ok(sealed)
    }

    fn open(&self, place: Place<'_>, sealed: &[u8]) -> Result<SecretBytes, MetaError> {
        let (nonce, ct) = sealed
            .split_first_chunk::<{ sizes::NONCE }>()
            .filter(|_| place.kind().is_sealed_len(sealed.len()))
            .ok_or(MetaError::SealedLength(sealed.len()))?;
        let plain = xchacha_open(self.rk.expose(), nonce, &self.aad(place), ct)
            .map_err(|AeadError| MetaError::Open)?;
        let (meta, padding) = plain
            .split_first_chunk::<LENGTH_FIELD>()
            .and_then(|(len, rest)| {
                rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)
            })
            .ok_or(MetaError::Length)?;
        if bucket(meta.len()) != Some(plain.len()) {
            return Err(MetaError::OverPadded);
        }
        if padding.iter().any(|&b| b != 0) {
            return Err(MetaError::Padding);
        }
        Ok(Zeroizing::new(meta.to_vec()))
    }

    /// Seals an arbitrary plaintext under an index record's aad, without the
    /// writer's rules, so that tests can reach every reader rejection.
    #[cfg(test)]
    pub(crate) fn seal_index_plain_for_test(
        &self,
        path_tag: &PathTag,
        nonce: &[u8; 24],
        plain: &[u8],
    ) -> Vec<u8> {
        self.seal_plain(Place::Index(path_tag), nonce, plain)
            .unwrap_or_default()
    }

    /// The same keys paired with another folder ID, so that a test can show a
    /// seal bound to the folder ID alone.
    #[cfg(test)]
    pub(crate) fn with_folder_id_for_test(&self, folder_id: FolderId) -> RecordKeys {
        RecordKeys {
            rk: RecordKey::fill_with(|o| *o = *self.rk.expose()),
            tk: PathTagKey::fill_with(|o| *o = *self.tk.expose()),
            folder_id,
        }
    }

    /// The same under a cleanup's aad.
    #[cfg(test)]
    pub(crate) fn seal_cleanup_plain_for_test(&self, nonce: &[u8; 24], plain: &[u8]) -> Vec<u8> {
        self.seal_plain(Place::Cleanup, nonce, plain)
            .unwrap_or_default()
    }
}

impl WriteKey {
    /// This folder's record keys: `rk`, `tk` and the folder ID.
    #[must_use]
    pub fn record_keys(&self) -> RecordKeys {
        RecordKeys::new(self.data_key(), self.verifier().folder_id())
    }
}

impl ReadKey {
    /// This folder's record keys: `rk`, `tk` and the folder ID.
    #[must_use]
    pub fn record_keys(&self) -> RecordKeys {
        RecordKeys::new(self.data_key(), self.verifier().folder_id())
    }
}

impl FolderKey {
    /// This folder's record keys, for the write and read tiers; a sealed key
    /// holds no data key, opens no seal and computes no path tag.
    #[must_use]
    pub fn record_keys(&self) -> Option<RecordKeys> {
        match self {
            FolderKey::Write(k) => Some(k.record_keys()),
            FolderKey::Read(k) => Some(k.record_keys()),
            FolderKey::Sealed(_) => None,
        }
    }
}

/// The old layout's `folder_id || device_id || be64(seq)`.
fn aad(folder_id: &FolderId, device_id: &DeviceId, seq: u64) -> [u8; 72] {
    crate::bytes::join3(
        folder_id.as_bytes(),
        device_id.as_bytes(),
        &seq.to_be_bytes(),
    )
}

/// The old layout (see the module documentation; removed in the next commit of
/// this series): seals the `SealedMeta` bytes `meta` of the record that
/// `folder_id`, `device_id` and `seq` name, Padmé-padded, under the record
/// key, with 24 fresh bytes from `rng` as the nonce.
///
/// # Errors
///
/// [`MetaError::TooLong`], with the length of the padded sealed part this
/// metadata would make, when that exceeds [`MAX_SEALED_BYTES`], judged before
/// anything is allocated; [`MetaError::Seal`] only if the cipher refuses,
/// which it does not for a seal of that size.
pub fn seal_meta(
    rk: &RecordKey,
    folder_id: &FolderId,
    device_id: &DeviceId,
    seq: u64,
    meta: &[u8],
    rng: &mut RandomFill<'_>,
) -> Result<Vec<u8>, MetaError> {
    let padded = meta.len().checked_add(LENGTH_FIELD).and_then(padme_len);
    let sealed_len = padded.and_then(|p| p.checked_add(MIN_SEALED_BYTES));
    let (len, padded) = u32::try_from(meta.len())
        .ok()
        .zip(padded)
        .filter(|_| sealed_len.is_some_and(|n| n <= MAX_SEALED_BYTES))
        .ok_or(MetaError::TooLong(sealed_len.unwrap_or(usize::MAX)))?;
    let mut plain: SecretBytes = Zeroizing::new(Vec::with_capacity(padded));
    plain.extend_from_slice(&len.to_be_bytes());
    plain.extend_from_slice(meta);
    plain.resize(padded, 0);
    let mut nonce = [0u8; sizes::NONCE];
    rng(&mut nonce);
    let ct = xchacha_seal(rk.expose(), &nonce, &aad(folder_id, device_id, seq), &plain)
        .map_err(|SealError| MetaError::Seal)?;
    let mut sealed = Vec::with_capacity(sizes::NONCE + ct.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ct);
    Ok(sealed)
}

/// The old layout (see the module documentation; removed in the next commit of
/// this series): opens a record's sealed part under the associated data
/// rebuilt from the record's own `folder_id`, `device_id` and `seq`: the
/// length, the AEAD, the length field, the zero padding.
/// The metadata comes back in a buffer that is zeroized on drop.
///
/// # Errors
///
/// The [`MetaError`] of the first failing step.
pub fn open_meta(
    rk: &RecordKey,
    folder_id: &FolderId,
    device_id: &DeviceId,
    seq: u64,
    sealed: &[u8],
) -> Result<SecretBytes, MetaError> {
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(MetaError::TooLong(sealed.len()));
    }
    let (nonce, ct) = sealed
        .split_first_chunk::<{ sizes::NONCE }>()
        .filter(|_| sealed.len() >= MIN_SEALED_BYTES)
        .ok_or(MetaError::TooShort(sealed.len()))?;
    let plain = xchacha_open(rk.expose(), nonce, &aad(folder_id, device_id, seq), ct)
        .map_err(|AeadError| MetaError::Open)?;
    let (meta, padding) = plain
        .split_first_chunk::<LENGTH_FIELD>()
        .and_then(|(len, rest)| {
            rest.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)
        })
        .ok_or(MetaError::Length)?;
    if padding.iter().any(|&b| b != 0) {
        return Err(MetaError::Padding);
    }
    Ok(Zeroizing::new(meta.to_vec()))
}

/// Seals an arbitrary plaintext the way [`seal_meta`] does, without the
/// writer's rules, so that tests can reach every reader rejection.
#[cfg(test)]
pub(crate) fn seal_plain_for_test(
    rk: &RecordKey,
    folder_id: &FolderId,
    device_id: &DeviceId,
    seq: u64,
    nonce: &[u8; 24],
    plain: &[u8],
) -> Vec<u8> {
    let mut sealed = nonce.to_vec();
    sealed.extend(
        xchacha_seal(rk.expose(), nonce, &aad(folder_id, device_id, seq), plain)
            .unwrap_or_default(),
    );
    sealed
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
    use crate::chunk::padme;
    use crate::folder::tests::write_key;
    use proptest::prelude::*;

    const FOLDER: FolderId = FolderId([1; 32]);
    const DEVICE: DeviceId = DeviceId([2; 32]);

    fn rk() -> RecordKey {
        RecordKey::fill_with(|o| *o = [3; 32])
    }

    fn keys() -> RecordKeys {
        write_key(1).record_keys()
    }

    const TAG: PathTag = PathTag([0x7a; 32]);

    /// `keys.md` 3.4: the least power of two that is at least
    /// `max(256, len(meta) + 4)`, at the edges the spec's vectors name: 255,
    /// 256 and 257 bytes of metadata plus its length field, and 2^21.
    #[test]
    fn bucket_boundaries() {
        assert_eq!(bucket(0), Some(256));
        assert_eq!(bucket(255 - 4), Some(256));
        assert_eq!(bucket(256 - 4), Some(256));
        assert_eq!(bucket(257 - 4), Some(512));
        assert_eq!(bucket(300), Some(512));
        assert_eq!(bucket((1 << 21) - 4), Some(1 << 21));
        assert_eq!(bucket((1 << 21) - 3), Some(1 << 22));
        assert_eq!(bucket(usize::MAX), None);
        assert_eq!(bucket(usize::MAX - 3), None);
        assert_eq!(MAX_INDEX_SEALED_BYTES, 2_097_192);
        assert_eq!(MAX_CLEANUP_SEALED_BYTES, 1_064);
        let mut fill = |b: &mut [u8]| b.fill(1);
        let k = keys();
        // At the cap of each kind the seal is written; one byte more is the
        // writer's error, naming the sealed part it would have made.
        let at_cap = k
            .seal_index_meta(&TAG, &vec![9; (1 << 21) - 4], &mut fill)
            .unwrap();
        assert_eq!(at_cap.len(), MAX_INDEX_SEALED_BYTES);
        assert_eq!(
            &*k.open_index_meta(&TAG, &at_cap).unwrap(),
            &vec![9; (1 << 21) - 4][..]
        );
        assert_eq!(
            k.seal_index_meta(&TAG, &vec![9; (1 << 21) - 3], &mut fill),
            Err(MetaError::TooLong(40 + (1 << 22)))
        );
        let cleanup = k.seal_cleanup_meta(&[5; 1020], &mut fill).unwrap();
        assert_eq!(cleanup.len(), MAX_CLEANUP_SEALED_BYTES);
        assert_eq!(
            k.seal_cleanup_meta(&[5; 1021], &mut fill),
            Err(MetaError::TooLong(40 + 2048))
        );
    }

    #[test]
    fn sealed_lengths_of_each_kind() {
        for (len, index, cleanup) in [
            (0, false, false),
            (40, false, false),
            (295, false, false),
            (296, true, true),
            (297, false, false),
            (552, true, true),
            (1064, true, true),
            (2088, true, false),
            (440, false, false),
            (MAX_INDEX_SEALED_BYTES, true, false),
            ((1 << 21) + 41, false, false),
            (MIN_SEALED_BYTES + (1 << 22), false, false),
            (usize::MAX, false, false),
        ] {
            assert_eq!(SealedKind::Index.is_sealed_len(len), index, "index {len}");
            assert_eq!(
                SealedKind::Cleanup.is_sealed_len(len),
                cleanup,
                "cleanup {len}"
            );
        }
        assert_eq!(SealedKind::Index.max_sealed_len(), MAX_INDEX_SEALED_BYTES);
        assert_eq!(
            SealedKind::Cleanup.max_sealed_len(),
            MAX_CLEANUP_SEALED_BYTES
        );
    }

    /// A sealed part opens only under the aad its own record rebuilds: another
    /// path tag, another folder, or the other record type's aad (whose length
    /// differs) all fail to open.
    #[test]
    fn a_seal_is_bound_to_its_folder_its_path_tag_and_its_record_type() {
        let k = keys();
        let mut fill = |b: &mut [u8]| b.fill(4);
        let index = k.seal_index_meta(&TAG, b"meta", &mut fill).unwrap();
        let cleanup = k.seal_cleanup_meta(b"meta", &mut fill).unwrap();
        assert_eq!(index.len(), 296);
        assert_eq!(cleanup.len(), 296);
        assert_eq!(&*k.open_index_meta(&TAG, &index).unwrap(), b"meta");
        assert_eq!(&*k.open_cleanup_meta(&cleanup).unwrap(), b"meta");
        assert_eq!(
            k.open_index_meta(&PathTag([0x7b; 32]), &index),
            Err(MetaError::Open)
        );
        assert_eq!(k.open_cleanup_meta(&index), Err(MetaError::Open));
        assert_eq!(k.open_index_meta(&TAG, &cleanup), Err(MetaError::Open));
        let other = write_key(2).record_keys();
        assert_eq!(other.open_index_meta(&TAG, &index), Err(MetaError::Open));
        assert_eq!(other.open_cleanup_meta(&cleanup), Err(MetaError::Open));
        // The aads are the 64 and 32 bytes of keys.md 3.4.
        let mut expected = k.folder_id().0.to_vec();
        assert_eq!(k.aad(Place::Cleanup), expected);
        expected.extend(TAG.0);
        assert_eq!(k.aad(Place::Index(&TAG)), expected);
        // Random nonces keep two seals of one place distinct.
        let mut other_fill = |b: &mut [u8]| b.fill(5);
        let again = k.seal_index_meta(&TAG, b"meta", &mut other_fill).unwrap();
        assert_ne!(again, index);
        assert_eq!(&index[..24], &[4; 24]);
    }

    #[test]
    fn every_reader_rejection_of_the_new_layout() {
        let k = keys();
        let n = [8u8; 24];
        let forge = |plain: &[u8]| k.seal_index_plain_for_test(&TAG, &n, plain);
        let open = |sealed: &[u8]| k.open_index_meta(&TAG, sealed);
        let with_len = |len: u32, meta: &[u8], total: usize| {
            let mut p = len.to_be_bytes().to_vec();
            p.extend_from_slice(meta);
            p.resize(total, 0);
            p
        };
        // Lengths outside the set are malformed, whatever the bytes.
        for len in [0, 39, 40, 295, 297, 440, (1 << 21) + 41] {
            let e = open(&vec![0; len]).unwrap_err();
            assert_eq!(e, MetaError::SealedLength(len));
            assert!(e.is_malformed());
        }
        assert_eq!(
            k.open_cleanup_meta(&[0; 2088]),
            Err(MetaError::SealedLength(2088))
        );
        // At an allowed length the AEAD decides.
        assert_eq!(open(&[0; 296]), Err(MetaError::Open));
        let mut damaged = forge(&with_len(1, &[1], 256));
        damaged[30] ^= 1;
        assert_eq!(open(&damaged), Err(MetaError::Open));
        // The length field: beyond what the plaintext holds.
        assert_eq!(
            open(&forge(&with_len(253, &[], 256))),
            Err(MetaError::Length)
        );
        assert_eq!(
            open(&forge(&with_len(u32::MAX, &[], 256))),
            Err(MetaError::Length)
        );
        // 252 bytes of metadata fill the 256 bucket exactly.
        assert_eq!(
            open(&forge(&with_len(252, &[3; 252], 256))).unwrap().len(),
            252
        );
        // 300 bytes padded to 512 open; padded to 1 024 they are over-padded,
        // a writer fault; any shorter metadata in 512 is over-padded too.
        let meta = [6u8; 300];
        assert_eq!(
            &*open(&forge(&with_len(300, &meta, 512))).unwrap(),
            &meta[..]
        );
        let over = open(&forge(&with_len(300, &meta, 1024))).unwrap_err();
        assert_eq!(over, MetaError::OverPadded);
        assert!(!over.is_malformed());
        assert_eq!(
            open(&forge(&with_len(252, &[3; 252], 512))),
            Err(MetaError::OverPadded)
        );
        // A padding byte that is not zero.
        let mut spoiled = with_len(1, &[1], 256);
        spoiled[255] = 1;
        assert_eq!(open(&forge(&spoiled)), Err(MetaError::Padding));
        // The same steps under a cleanup's aad.
        let cforge = |plain: &[u8]| k.seal_cleanup_plain_for_test(&n, plain);
        assert_eq!(
            &*k.open_cleanup_meta(&cforge(&with_len(2, &[1, 2], 256)))
                .unwrap(),
            &[1, 2]
        );
        assert_eq!(
            k.open_cleanup_meta(&cforge(&with_len(2, &[1, 2], 512))),
            Err(MetaError::OverPadded)
        );
        for e in [
            MetaError::Open,
            MetaError::Length,
            MetaError::OverPadded,
            MetaError::Padding,
            MetaError::Seal,
        ] {
            assert!(!e.is_malformed(), "{e:?} is a writer fault");
            assert_ne!(e.to_string(), "");
        }
        assert_ne!(MetaError::SealedLength(3).to_string(), "");
    }

    /// `keys.md` 3.5: the tag is keyed BLAKE3 under `tk` over the path's bytes
    /// exactly as given; no normalisation, case folding or trimming.
    #[test]
    fn path_tags_are_byte_for_byte() {
        let k = keys();
        let tk = write_key(1).data_key().path_tag_key();
        let tag = k.path_tag("docs/notes");
        assert_eq!(tag.0, keyed_hash(tk.expose(), &[b"docs/notes"]));
        let composed = "not\u{e9}s";
        let decomposed = "note\u{301}s";
        let tags = [
            k.path_tag("docs"),
            tag,
            k.path_tag("docs/notes/a.txt"),
            k.path_tag("Docs"),
            k.path_tag(composed),
            k.path_tag(decomposed),
            k.path_tag("docs/"),
            k.path_tag(" docs"),
        ];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(k.path_tag("docs/notes"), tag, "one path, one tag");
        assert_eq!(
            write_key(1).read_key().record_keys().path_tag("docs/notes"),
            tag
        );
        assert_ne!(write_key(2).record_keys().path_tag("docs/notes"), tag);
    }

    #[test]
    fn record_keys_come_from_read_and_write_keys_only() {
        let w = write_key(3);
        let from_write = FolderKey::from(write_key(3)).record_keys().unwrap();
        let from_read = FolderKey::from(w.read_key()).record_keys().unwrap();
        assert!(FolderKey::from(w.sealed_key()).record_keys().is_none());
        assert_eq!(from_write.folder_id(), w.verifier().folder_id());
        let mut fill = |b: &mut [u8]| b.fill(2);
        let sealed = from_write.seal_index_meta(&TAG, b"m", &mut fill).unwrap();
        assert_eq!(&*from_read.open_index_meta(&TAG, &sealed).unwrap(), b"m");
        assert_eq!(
            format!("{from_read:?}"),
            format!("RecordKeys({}, [redacted])", w.verifier().folder_id())
        );
    }

    proptest! {
        /// Seal and open round trip for random metadata sizes under both
        /// aads, and the sealed part always takes the least bucket.
        #[test]
        fn new_layout_round_trips_in_the_least_bucket(
            meta in proptest::collection::vec(any::<u8>(), 0..2100),
            tag in any::<[u8; 32]>(),
        ) {
            let k = keys();
            let tag = PathTag(tag);
            let mut fill = |b: &mut [u8]| b.fill(9);
            let sealed = k.seal_index_meta(&tag, &meta, &mut fill).unwrap();
            let least = (meta.len() + 4).next_power_of_two().max(256);
            prop_assert_eq!(sealed.len(), least + 40);
            prop_assert!(SealedKind::Index.is_sealed_len(sealed.len()));
            prop_assert_eq!(&*k.open_index_meta(&tag, &sealed).unwrap(), &meta[..]);
            match k.seal_cleanup_meta(&meta, &mut fill) {
                Ok(c) => {
                    prop_assert!(least <= MAX_CLEANUP_BUCKET);
                    prop_assert_eq!(c.len(), least + 40);
                    prop_assert_eq!(&*k.open_cleanup_meta(&c).unwrap(), &meta[..]);
                }
                Err(e) => {
                    prop_assert!(least > MAX_CLEANUP_BUCKET);
                    prop_assert_eq!(e, MetaError::TooLong(least + 40));
                }
            }
        }

        /// Any bytes into the reader: no panic, and only allowed lengths get
        /// past the length check.
        #[test]
        fn any_bytes_into_the_new_reader(bytes in proptest::collection::vec(any::<u8>(), 0..1100)) {
            let k = keys();
            for (kind, result) in [
                (SealedKind::Index, k.open_index_meta(&TAG, &bytes)),
                (SealedKind::Cleanup, k.open_cleanup_meta(&bytes)),
            ] {
                if kind.is_sealed_len(bytes.len()) {
                    prop_assert!(result.is_err());
                } else {
                    prop_assert_eq!(result, Err(MetaError::SealedLength(bytes.len())));
                }
            }
        }
    }

    proptest! {
        #[test]
        fn seal_open_round_trip(meta in proptest::collection::vec(any::<u8>(), 0..3000), seq in any::<u64>()) {
            let mut fill = |b: &mut [u8]| b.fill(9);
            let sealed = seal_meta(&rk(), &FOLDER, &DEVICE, seq, &meta, &mut fill).unwrap();
            let padded = usize::try_from(padme(meta.len() as u64 + 4).unwrap()).unwrap();
            prop_assert_eq!(sealed.len(), padded + 40);
            prop_assert_eq!(&sealed[..24], &[9u8; 24]);
            let opened = open_meta(&rk(), &FOLDER, &DEVICE, seq, &sealed).unwrap();
            prop_assert_eq!(&*opened, &meta[..]);
        }
    }

    #[test]
    fn the_seal_is_bound_to_its_folder_device_and_sequence() {
        let mut fill = |b: &mut [u8]| b.fill(4);
        let sealed = seal_meta(&rk(), &FOLDER, &DEVICE, 7, b"meta", &mut fill).unwrap();
        assert_eq!(
            open_meta(&rk(), &FOLDER, &DEVICE, 8, &sealed),
            Err(MetaError::Open)
        );
        assert_eq!(
            open_meta(&rk(), &FOLDER, &DeviceId([5; 32]), 7, &sealed),
            Err(MetaError::Open)
        );
        assert_eq!(
            open_meta(&rk(), &FolderId([5; 32]), &DEVICE, 7, &sealed),
            Err(MetaError::Open)
        );
        assert_eq!(
            open_meta(
                &RecordKey::fill_with(|o| *o = [6; 32]),
                &FOLDER,
                &DEVICE,
                7,
                &sealed
            ),
            Err(MetaError::Open)
        );
        // Random nonces keep two seals of one place distinct.
        let mut other = |b: &mut [u8]| b.fill(5);
        let again = seal_meta(&rk(), &FOLDER, &DEVICE, 7, b"meta", &mut other).unwrap();
        assert_ne!(again, sealed);
        assert_eq!(
            &*open_meta(&rk(), &FOLDER, &DEVICE, 7, &again).unwrap(),
            b"meta"
        );
        // The aad is the 72 bytes of keys.md 3.4.
        let mut expected = FOLDER.0.to_vec();
        expected.extend(DEVICE.0);
        expected.extend(7u64.to_be_bytes());
        assert_eq!(aad(&FOLDER, &DEVICE, 7).to_vec(), expected);
    }

    #[test]
    fn every_reader_rejection_path() {
        let n = [8u8; 24];
        let forge = |plain: &[u8]| seal_plain_for_test(&rk(), &FOLDER, &DEVICE, 1, &n, plain);
        let open = |sealed: &[u8]| open_meta(&rk(), &FOLDER, &DEVICE, 1, sealed);
        assert_eq!(open(&[0; 39]), Err(MetaError::TooShort(39)));
        assert_eq!(
            open(&vec![0; MAX_SEALED_BYTES + 1]),
            Err(MetaError::TooLong(MAX_SEALED_BYTES + 1))
        );
        assert_eq!(open(&[0; 23]), Err(MetaError::TooShort(23)));
        assert_eq!(open(&[0; 40]), Err(MetaError::Open));
        // Exactly at the cap the length passes and the AEAD decides.
        assert_eq!(open(&vec![0; MAX_SEALED_BYTES]), Err(MetaError::Open));
        // Shorter than its length field, a length beyond the plaintext, padding.
        assert_eq!(open(&forge(&[])), Err(MetaError::Length));
        assert_eq!(open(&forge(&[0, 0, 0])), Err(MetaError::Length));
        assert_eq!(
            open(&forge(&[0, 0, 0, 5, 1, 2, 3, 4])),
            Err(MetaError::Length)
        );
        assert_eq!(
            open(&forge(&[0xff, 0xff, 0xff, 0xff, 1])),
            Err(MetaError::Length)
        );
        assert_eq!(
            open(&forge(&[0, 0, 0, 2, 1, 2, 0, 1])),
            Err(MetaError::Padding)
        );
        assert_eq!(&*open(&forge(&[0, 0, 0, 2, 1, 2, 0, 0])).unwrap(), &[1, 2]);
        // The reader requires only zero padding, not the writer's exact length.
        assert_eq!(
            &*open(&forge(&[0, 0, 0, 1, 1, 0, 0, 0, 0, 0])).unwrap(),
            &[1]
        );
        let mut damaged = forge(&[0, 0, 0, 0]);
        damaged[30] ^= 1;
        assert_eq!(open(&damaged), Err(MetaError::Open));
        for e in [
            MetaError::TooShort(1),
            MetaError::TooLong(2),
            MetaError::Seal,
            MetaError::Open,
            MetaError::Length,
            MetaError::Padding,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    #[test]
    fn the_writer_refuses_metadata_beyond_the_bound() {
        let mut fill = |b: &mut [u8]| b.fill(0);
        // The largest metadata whose padded seal fits the bound.
        let mut fits = 0usize;
        for n in (MAX_SEALED_BYTES - 40 - 4 - 70_000)..(MAX_SEALED_BYTES - 40 - 4) {
            if usize::try_from(padme(n as u64 + 4).unwrap()).unwrap() + 40 <= MAX_SEALED_BYTES {
                fits = n;
            }
        }
        let ok = seal_meta(&rk(), &FOLDER, &DEVICE, 1, &vec![1; fits], &mut fill).unwrap();
        assert!(ok.len() <= MAX_SEALED_BYTES);
        assert_eq!(
            &*open_meta(&rk(), &FOLDER, &DEVICE, 1, &ok).unwrap(),
            &vec![1; fits][..]
        );
        // One byte more pads past the cap; the error names the padded length.
        let over = seal_meta(&rk(), &FOLDER, &DEVICE, 1, &vec![1; fits + 1], &mut fill);
        let padded = padme_len(fits + 1 + 4).unwrap() + 40;
        assert!(padded > MAX_SEALED_BYTES);
        assert_eq!(over, Err(MetaError::TooLong(padded)));
        // Far over the cap, the error still names the padded length.
        assert_eq!(
            seal_meta(
                &rk(),
                &FOLDER,
                &DEVICE,
                1,
                &vec![1; MAX_SEALED_BYTES],
                &mut fill
            ),
            Err(MetaError::TooLong(
                padme_len(MAX_SEALED_BYTES + 4).unwrap() + 40
            ))
        );
    }
}
