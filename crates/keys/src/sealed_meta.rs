// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sealed metadata (`keys.md` 3.4): everything that would name a file (path,
//! kind, true size, times, mode, plaintext chunk hashes) sits in the sealed
//! part of its index record, which only read and write holders open.
//!
//! ```text
//! plain  = be32(len(meta)) || meta || zeros(padme(len(meta) + 4) - len(meta) - 4)
//! aad    = folder_id || device_id || be64(seq)              # 72 bytes
//! nonce  = 24 random bytes
//! sealed = nonce || XChaCha(rk, nonce, aad, plain)
//! ```
//!
//! The reader rebuilds the associated data from the record's own clear
//! fields, so a sealed part cannot be moved to a record of another folder,
//! device ID or sequence number. `meta` is the canonical `SealedMeta` the
//! protocol crate encodes; this module neither builds nor parses it. A sealed
//! part outside 40 to [`MAX_SEALED_BYTES`] bytes is malformed; failures after
//! that length check are writer faults (`protocol.md` 4.4 step 6), since the
//! body that holds the seal verified under the folder key. A writer whose
//! sealed part would pass the cap does not write the record.

use core::fmt;

use zeroize::Zeroizing;

use crate::aead::{xchacha_open, xchacha_seal, AeadError, SealError};
use crate::chunk::padme_len;
use crate::ids::{DeviceId, FolderId};
use crate::rng::RandomFill;
use crate::secret::{RecordKey, SecretBytes};
use crate::suite::sizes;

/// The smallest sealed part: its nonce and tag.
pub const MIN_SEALED_BYTES: usize = sizes::NONCE + sizes::TAG;

/// The largest sealed part an index record may carry, `MAX_SEALED_BYTES`
/// (`keys.md` 3.4, `protocol.md` 4.4): 1 572 864 bytes, 1.5 MiB. Outside 40 to
/// this the record is malformed.
pub const MAX_SEALED_BYTES: usize = 1_572_864;

/// The length field before the metadata, `be32(len(meta))`.
const LENGTH_FIELD: usize = 4;

/// Why metadata could not be sealed or opened. [`MetaError::TooShort`] and
/// [`MetaError::TooLong`] on opening make the record malformed; the others
/// are writer faults. No value here carries a length read from inside a seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    /// The sealed part is shorter than its nonce and tag.
    TooShort(usize),
    /// The sealed part, or the padded one this metadata would make, is longer
    /// than [`MAX_SEALED_BYTES`]: its length.
    TooLong(usize),
    /// The cipher refused to seal, which it does only beyond its own limit.
    Seal,
    /// The AEAD did not open: another key, another place, or damage.
    Open,
    /// The plaintext is too short for its length field, or the length in it
    /// exceeds what the plaintext holds.
    Length,
    /// A padding byte is not zero.
    Padding,
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "sealed metadata of {n} bytes is too short"),
            Self::TooLong(n) => {
                write!(f, "sealed metadata of {n} bytes exceeds {MAX_SEALED_BYTES}")
            }
            Self::Seal => f.write_str("metadata could not be sealed"),
            Self::Open => f.write_str("sealed metadata did not decrypt"),
            Self::Length => f.write_str("the metadata's length field does not fit the plaintext"),
            Self::Padding => f.write_str("a padding byte is not zero"),
        }
    }
}

impl std::error::Error for MetaError {}

/// `folder_id || device_id || be64(seq)`.
fn aad(folder_id: &FolderId, device_id: &DeviceId, seq: u64) -> [u8; 72] {
    crate::bytes::join3(
        folder_id.as_bytes(),
        device_id.as_bytes(),
        &seq.to_be_bytes(),
    )
}

/// Seals the canonical `SealedMeta` bytes `meta` of the record that
/// `folder_id`, `device_id` and `seq` name, under the record key, with 24
/// fresh bytes from `rng` as the nonce.
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

/// Opens a record's sealed part under the associated data rebuilt from the
/// record's own `folder_id`, `device_id` and `seq`, in the order of
/// `keys.md` 3.4: the length, the AEAD, the length field, the zero padding.
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
    use proptest::prelude::*;

    const FOLDER: FolderId = FolderId([1; 32]);
    const DEVICE: DeviceId = DeviceId([2; 32]);

    fn rk() -> RecordKey {
        RecordKey::fill_with(|o| *o = [3; 32])
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
