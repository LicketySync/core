// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wrapping the data key to a key (`keys.md` section 5.3, `suites.md` section
//! 2.1): HPKE (RFC 9180) base mode, single shot, with the X-Wing KEM
//! (0x647a), HKDF-SHA256 and ChaCha20-Poly1305. The associated data binds the
//! folder, the key ID, the tier and the epoch (TM-11), and the `info` is the
//! registered wrap label. The wire form is `enc (1120) || ct (48)`, 1168 bytes.

use core::fmt;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::ids::{FolderId, KeyId};
use crate::keyset::{KemPublicKey, KeyError, KeyPairSet};
use crate::labels;
use crate::rng::{Adapter, RandomFill};
use crate::secret::DataKey;
use crate::suite::{sizes, Tier};

type EncappedKey = <XWing as Kem>::EncappedKey;

/// A data key wrapped to one key: `enc || ct`, 1168 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedDataKey {
    bytes: [u8; sizes::WRAPPED_KEY],
}

impl fmt::Debug for WrappedDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WrappedDataKey({} bytes)", sizes::WRAPPED_KEY)
    }
}

impl WrappedDataKey {
    /// Reads a wrap from exactly 1168 bytes. Whether it opens is judged by
    /// [`unwrap_data_key`], never here.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(|bytes| WrappedDataKey { bytes })
    }

    /// The 1168 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::WRAPPED_KEY] {
        &self.bytes
    }
}

/// The associated data of a wrap: `folder_id || key_id || u8(tier) ||
/// be64(epoch)`, exactly 57 bytes in this order. The root's wrap in the Folder
/// record uses [`KeyId::ROOT`] and [`Tier::Root`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapAad {
    /// The folder.
    pub folder_id: FolderId,
    /// The recipient key.
    pub key_id: KeyId,
    /// The recipient's tier.
    pub tier: Tier,
    /// The epoch of the wrapped data key.
    pub epoch: u64,
}

impl WrapAad {
    /// The 57 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 57] {
        crate::bytes::fill::<57>(&[
            self.folder_id.as_bytes(),
            self.key_id.as_bytes(),
            &[self.tier.as_u8()],
            &self.epoch.to_be_bytes(),
        ])
    }
}

/// Wrapping failed: the recipient key did not load or HPKE refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapError {
    /// The recipient's X-Wing key is not valid.
    RecipientKey(KeyError),
    /// HPKE's seal failed, which for a 32-byte plaintext does not happen.
    Seal,
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecipientKey(e) => write!(f, "recipient key: {e}"),
            Self::Seal => f.write_str("HPKE seal failed"),
        }
    }
}

impl std::error::Error for WrapError {}

/// The wrap did not open: wrong key, wrong associated data, or a damaged
/// encapsulation or ciphertext. One error, on purpose (TM-10: a hard error,
/// never a default key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnwrapError;

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("wrapped data key did not open")
    }
}

impl std::error::Error for UnwrapError {}

/// `HPKE_Seal(kem_pk, info, aad, dk)` through `hpke`'s
/// `single_shot_seal_with_rng` (`suites.md` 2.1): wraps `dk` to `recipient`
/// under `aad`.
/// The encapsulation's 64 bytes of randomness come from `rng`; a fixed `rng`
/// gives a reproducible wrap, which the test vectors use.
///
/// # Errors
///
/// [`WrapError`].
pub fn wrap_data_key(
    recipient: &KemPublicKey,
    aad: &WrapAad,
    dk: &DataKey,
    rng: &mut RandomFill<'_>,
) -> Result<WrappedDataKey, WrapError> {
    let pk = recipient.to_hpke().map_err(WrapError::RecipientKey)?;
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        labels::WRAP_DATA_KEY.as_str().as_bytes(),
        dk.expose(),
        &aad.to_bytes(),
        &mut Adapter(rng),
    )
    .map_err(|_| WrapError::Seal)?;
    if ct.len() != sizes::WRAPPED_KEY - sizes::XWING_CT {
        return Err(WrapError::Seal);
    }
    let bytes = crate::bytes::fill::<{ sizes::WRAPPED_KEY }>(&[&enc.to_bytes(), &ct]);
    Ok(WrappedDataKey { bytes })
}

/// `HPKE_Open(xwing_sk, enc, info, aad, ct)` through `hpke`'s
/// `single_shot_open`: the holder of `holder`'s seed
/// recovers the data key. The caller rebuilds `aad` from the record's own
/// fields and calls this only after the record's signature chain verified
/// (section 5.4).
///
/// # Errors
///
/// [`UnwrapError`] for any failure.
pub fn unwrap_data_key(
    holder: &KeyPairSet,
    aad: &WrapAad,
    wrapped: &WrappedDataKey,
) -> Result<DataKey, UnwrapError> {
    let (enc, ct) = wrapped.bytes.split_at(sizes::XWING_CT);
    let enc = EncappedKey::from_bytes(enc).map_err(|_| UnwrapError)?;
    // The plaintext is the data key: into a zeroizing buffer at once.
    let plain = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            holder.kem_private(),
            &enc,
            labels::WRAP_DATA_KEY.as_str().as_bytes(),
            ct,
            &aad.to_bytes(),
        )
        .map_err(|_| UnwrapError)?,
    );
    let key = Zeroizing::new(<[u8; 32]>::try_from(plain.as_slice()).map_err(|_| UnwrapError)?);
    Ok(DataKey::from_bytes(*key))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;
    use crate::secret::Seed;

    fn aad() -> WrapAad {
        WrapAad {
            folder_id: FolderId([1; 32]),
            key_id: KeyId([2; 16]),
            tier: Tier::Write,
            epoch: 3,
        }
    }

    #[test]
    fn aad_layout_is_57_bytes_in_order() {
        let b = aad().to_bytes();
        assert_eq!(&b[..32], &[1u8; 32]);
        assert_eq!(&b[32..48], &[2u8; 16]);
        assert_eq!(b[48], 1);
        assert_eq!(&b[49..], &3u64.to_be_bytes());
    }

    #[test]
    fn tm_11_wrap_round_trips_and_binds_every_aad_field() {
        let holder = KeyPairSet::from_seed(&Seed::from_bytes([7; 32])).unwrap();
        let dk = DataKey::from_bytes([42; 32]);
        let mut rng = |buf: &mut [u8]| buf.fill(0x11);
        let wrapped = wrap_data_key(&holder.public().kem, &aad(), &dk, &mut rng).unwrap();
        assert_eq!(wrapped.as_bytes().len(), 1168);
        assert_eq!(format!("{wrapped:?}"), "WrappedDataKey(1168 bytes)");
        assert_eq!(
            WrappedDataKey::from_slice(wrapped.as_bytes()).as_ref(),
            Some(&wrapped)
        );
        assert!(WrappedDataKey::from_slice(&wrapped.as_bytes()[1..]).is_none());
        let opened = unwrap_data_key(&holder, &aad(), &wrapped).unwrap();
        assert!(bool::from(opened.ct_eq(&dk)));
        // Fixed randomness gives the same wrap; other randomness another.
        let mut rng_same = |buf: &mut [u8]| buf.fill(0x11);
        assert_eq!(
            wrap_data_key(&holder.public().kem, &aad(), &dk, &mut rng_same).unwrap(),
            wrapped
        );
        let mut rng_other = |buf: &mut [u8]| buf.fill(0x22);
        assert_ne!(
            wrap_data_key(&holder.public().kem, &aad(), &dk, &mut rng_other).unwrap(),
            wrapped
        );
        // TM-11: any one aad field changed, and the wrap does not open.
        for changed in [
            WrapAad {
                folder_id: FolderId([9; 32]),
                ..aad()
            },
            WrapAad {
                key_id: KeyId([9; 16]),
                ..aad()
            },
            WrapAad {
                tier: Tier::Read,
                ..aad()
            },
            WrapAad { epoch: 4, ..aad() },
        ] {
            assert_eq!(
                unwrap_data_key(&holder, &changed, &wrapped).err(),
                Some(UnwrapError)
            );
        }
        // Another holder cannot open it.
        let other = KeyPairSet::from_seed(&Seed::from_bytes([8; 32])).unwrap();
        assert_eq!(
            unwrap_data_key(&other, &aad(), &wrapped).err(),
            Some(UnwrapError)
        );
        // A damaged encapsulation, ciphertext or tag fails.
        for i in [0usize, 1120, 1167] {
            let mut damaged = *wrapped.as_bytes();
            damaged[i] ^= 1;
            let damaged = WrappedDataKey::from_slice(&damaged).unwrap();
            assert_eq!(
                unwrap_data_key(&holder, &aad(), &damaged).err(),
                Some(UnwrapError)
            );
        }
        assert_eq!(UnwrapError.to_string(), "wrapped data key did not open");
        assert_eq!(WrapError::Seal.to_string(), "HPKE seal failed");
        assert_eq!(
            WrapError::RecipientKey(KeyError::Internal).to_string(),
            "recipient key: the cryptographic library refused well-sized input"
        );
    }
}
