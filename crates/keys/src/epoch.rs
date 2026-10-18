// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The data key and epochs (`keys.md` section 3.1 and 3.2): the keys derived
//! from `dk_e` under their labels, the folder-lifetime chunk-hash key from
//! `dk_1`, the epoch ladder that leads from `dk_e` down to `dk_{e-1}`, the
//! rotation's key-confirmation value, and the record key's sealing of index
//! metadata (`protocol.md` 4.4).

use core::fmt;

use subtle::{Choice, ConstantTimeEq};

use crate::aead::{xchacha_open, xchacha_seal};
use crate::ids::{DeviceId, FolderId, KeyId};
use crate::labels::{self, derive_key};
use crate::rng::RandomFill;
use crate::secret::{
    ChunkHashKey, ChunkKey, ChunkNonceKey, DataKey, LadderKey, RecordKey, SecretBytes,
};
use crate::suite::sizes;

/// `derive_key("licketysync/v1/epoch/confirm", dk_e)`: published in the
/// Rotation (and, for epoch 1, the Folder record) so that every holder can
/// check it unwrapped the same key as everyone else (section 7.1, step 8).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Confirm(pub [u8; 32]);

impl fmt::Debug for Confirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Confirm({})", crate::ids::hex(&self.0))
    }
}

impl Confirm {
    /// Reads a value from exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }

    /// Constant-time comparison: the value derives from a secret.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl DataKey {
    /// `ck_e = derive_key("licketysync/v1/epoch/chunk-key", dk_e)`.
    #[must_use]
    pub fn chunk_key(&self) -> ChunkKey {
        ChunkKey::from_bytes(*derive_key(labels::EPOCH_CHUNK_KEY, self.expose()))
    }

    /// `nk_e = derive_key("licketysync/v1/epoch/chunk-nonce-key", dk_e)`.
    #[must_use]
    pub fn chunk_nonce_key(&self) -> ChunkNonceKey {
        ChunkNonceKey::from_bytes(*derive_key(labels::EPOCH_CHUNK_NONCE_KEY, self.expose()))
    }

    /// `rk_e = derive_key("licketysync/v1/epoch/record-key", dk_e)`.
    #[must_use]
    pub fn record_key(&self) -> RecordKey {
        RecordKey::from_bytes(*derive_key(labels::EPOCH_RECORD_KEY, self.expose()))
    }

    /// `derive_key("licketysync/v1/epoch/ladder-key", dk_e)`.
    #[must_use]
    pub fn ladder_key(&self) -> LadderKey {
        LadderKey::from_bytes(*derive_key(labels::EPOCH_LADDER_KEY, self.expose()))
    }

    /// The key-confirmation value of this data key.
    #[must_use]
    pub fn confirm(&self) -> Confirm {
        Confirm(*derive_key(labels::EPOCH_CONFIRM, self.expose()))
    }

    /// `hk = derive_key("licketysync/v1/folder/chunk-hash-key", dk_1)`: the
    /// folder-lifetime keyed-BLAKE3 key over plaintext chunks, from epoch 1's
    /// key only; it does not change with rotations. Outside the crate it is
    /// reached through [`crate::records::FolderKeys::chunk_hash_key`], which
    /// first confirms that the key it is given is `dk_1`.
    #[must_use]
    pub(crate) fn chunk_hash_key(&self) -> ChunkHashKey {
        ChunkHashKey::from_bytes(*derive_key(labels::FOLDER_CHUNK_HASH_KEY, self.expose()))
    }
}

/// A ladder link (section 3.1): `n || XChaCha(ladder_key(dk_e), n, folder_id
/// || be64(e), dk_{e-1})`, 72 bytes, published in the rotation that created
/// epoch `e`. A holder of `dk_e` recovers `dk_{e-1}`; a holder of `dk_{e-1}`
/// learns nothing about `dk_e`.
#[derive(Clone, PartialEq, Eq)]
pub struct LadderLink {
    bytes: [u8; sizes::LADDER_LINK],
}

impl fmt::Debug for LadderLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LadderLink({} bytes)", sizes::LADDER_LINK)
    }
}

pub use crate::aead::AeadError;

fn aad_folder_epoch(folder_id: &FolderId, epoch: u64) -> [u8; 40] {
    crate::bytes::fill::<40>(&[folder_id.as_bytes(), &epoch.to_be_bytes()])
}

impl LadderLink {
    /// Seals `dk_prev` (epoch `epoch - 1`) under `dk_new` (epoch `epoch`) with
    /// a random 24-byte nonce from `rng`.
    ///
    /// # Errors
    ///
    /// [`AeadError`] only if the cipher refuses, which it does not.
    pub fn seal(
        dk_new: &DataKey,
        epoch: u64,
        folder_id: &FolderId,
        dk_prev: &DataKey,
        rng: &mut RandomFill<'_>,
    ) -> Result<LadderLink, AeadError> {
        let mut nonce = [0u8; 24];
        rng(&mut nonce);
        let ladder_key = dk_new.ladder_key();
        let ct = xchacha_seal(
            ladder_key.expose(),
            &nonce,
            &aad_folder_epoch(folder_id, epoch),
            dk_prev.expose(),
        )?;
        if ct.len() != sizes::LADDER_LINK - sizes::NONCE {
            return Err(AeadError);
        }
        Ok(LadderLink {
            bytes: crate::bytes::fill::<{ sizes::LADDER_LINK }>(&[&nonce, &ct]),
        })
    }

    /// Recovers `dk_{epoch-1}` with `dk_new` (epoch `epoch`). The caller then
    /// checks the result against epoch `epoch - 1`'s confirmation value
    /// (coordinator decision 2026-10-15: a mismatch is the rotator's fault).
    ///
    /// # Errors
    ///
    /// [`AeadError`] when the link does not open under this key, epoch and folder.
    pub fn open(
        &self,
        dk_new: &DataKey,
        epoch: u64,
        folder_id: &FolderId,
    ) -> Result<DataKey, AeadError> {
        let (nonce, ct) = self.bytes.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| AeadError)?;
        let ladder_key = dk_new.ladder_key();
        let plain = xchacha_open(
            ladder_key.expose(),
            &nonce,
            &aad_folder_epoch(folder_id, epoch),
            ct,
        )?;
        let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| AeadError)?;
        Ok(DataKey::from_bytes(bytes))
    }

    /// Reads a link from exactly 72 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(|bytes| LadderLink { bytes })
    }

    /// The 72 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::LADDER_LINK] {
        &self.bytes
    }
}

/// The associated data of an index record's sealed part (`protocol.md` 4.4,
/// "Sealing"): `folder_id || writer_key_id || device_id || be64(seq)`, 88
/// bytes, rebuilt by a reader from the record's public fields so that a
/// sealed part cannot be moved between records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexSealAad {
    /// The folder.
    pub folder_id: FolderId,
    /// The writer's key.
    pub writer_key_id: KeyId,
    /// The writing device.
    pub device_id: DeviceId,
    /// The record's sequence number in the writer's chain.
    pub seq: u64,
}

impl IndexSealAad {
    /// The 88 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 88] {
        crate::bytes::fill::<88>(&[
            self.folder_id.as_bytes(),
            self.writer_key_id.as_bytes(),
            self.device_id.as_bytes(),
            &self.seq.to_be_bytes(),
        ])
    }
}

impl RecordKey {
    /// Seals the padded metadata of an index record under a random 24-byte
    /// nonce from `rng`: returns `nonce || XChaCha(rk, nonce, aad, plaintext)`
    /// (`protocol.md` 4.4, "Sealing"). The caller supplies the Padmé-padded
    /// plaintext; the aad is typed so that only the four public fields can
    /// form it.
    ///
    /// # Errors
    ///
    /// [`AeadError`] only if the cipher refuses, which it does not.
    pub fn seal(
        &self,
        aad: &IndexSealAad,
        plaintext: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<Vec<u8>, AeadError> {
        let mut nonce = [0u8; 24];
        rng(&mut nonce);
        let ct = xchacha_seal(self.expose(), &nonce, &aad.to_bytes(), plaintext)?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Opens `nonce || ciphertext` sealed by [`RecordKey::seal`] under the
    /// same `aad`.
    ///
    /// # Errors
    ///
    /// [`AeadError`] when the blob is shorter than a nonce and a tag or does not open.
    pub fn open(&self, aad: &IndexSealAad, sealed: &[u8]) -> Result<SecretBytes, AeadError> {
        if sealed.len() < sizes::NONCE + sizes::TAG {
            return Err(AeadError);
        }
        let (nonce, ct) = sealed.split_at(sizes::NONCE);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| AeadError)?;
        xchacha_open(self.expose(), &nonce, &aad.to_bytes(), ct)
    }
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

    #[test]
    fn derived_keys_are_distinct_and_deterministic() {
        let dk = DataKey::from_bytes([1; 32]);
        let keys: [[u8; 32]; 6] = [
            *dk.chunk_key().expose(),
            *dk.chunk_nonce_key().expose(),
            *dk.record_key().expose(),
            *dk.ladder_key().expose(),
            dk.confirm().0,
            *dk.chunk_hash_key().expose(),
        ];
        for i in 0..keys.len() {
            for j in 0..keys.len() {
                assert_eq!(keys[i] == keys[j], i == j);
            }
            assert_ne!(keys[i], [1; 32]);
        }
        assert_eq!(dk.confirm(), DataKey::from_bytes([1; 32]).confirm());
        assert!(bool::from(dk.confirm().ct_eq(&dk.confirm())));
        assert!(Confirm::from_slice(&[0; 31]).is_none());
        assert!(format!("{:?}", dk.confirm()).starts_with("Confirm("));
    }

    #[test]
    fn ladder_leads_down_and_never_up() {
        let folder = FolderId([3; 32]);
        let dk1 = DataKey::from_bytes([1; 32]);
        let dk2 = DataKey::from_bytes([2; 32]);
        let mut rng = |buf: &mut [u8]| buf.fill(5);
        let link = LadderLink::seal(&dk2, 2, &folder, &dk1, &mut rng).unwrap();
        assert_eq!(link.as_bytes().len(), 72);
        assert_eq!(&link.as_bytes()[..24], &[5u8; 24]);
        assert_eq!(format!("{link:?}"), "LadderLink(72 bytes)");
        assert_eq!(
            LadderLink::from_slice(link.as_bytes()).as_ref(),
            Some(&link)
        );
        assert!(LadderLink::from_slice(&[0; 71]).is_none());
        let back = link.open(&dk2, 2, &folder).unwrap();
        assert!(bool::from(back.ct_eq(&dk1)));
        assert!(bool::from(back.confirm().ct_eq(&dk1.confirm())));
        // The wrong epoch, folder or key does not open it; dk1 does not open its own link.
        assert_eq!(link.open(&dk2, 3, &folder).err(), Some(AeadError));
        assert_eq!(
            link.open(&dk2, 2, &FolderId([4; 32])).err(),
            Some(AeadError)
        );
        assert_eq!(link.open(&dk1, 2, &folder).err(), Some(AeadError));
        let mut damaged = *link.as_bytes();
        damaged[71] ^= 1;
        assert_eq!(
            LadderLink::from_slice(&damaged)
                .unwrap()
                .open(&dk2, 2, &folder)
                .err(),
            Some(AeadError)
        );
        assert_eq!(AeadError.to_string(), "authenticated decryption failed");
    }

    #[test]
    fn record_key_seals_with_a_fresh_nonce_and_binds_every_aad_field() {
        let rk = DataKey::from_bytes([6; 32]).record_key();
        let mut n = 0u8;
        let mut rng = |buf: &mut [u8]| {
            n = n.wrapping_add(1);
            buf.fill(n);
        };
        let aad = IndexSealAad {
            folder_id: FolderId([1; 32]),
            writer_key_id: KeyId([2; 16]),
            device_id: DeviceId([3; 32]),
            seq: 4,
        };
        let bytes = aad.to_bytes();
        assert_eq!(&bytes[..32], &[1; 32]);
        assert_eq!(&bytes[32..48], &[2; 16]);
        assert_eq!(&bytes[48..80], &[3; 32]);
        assert_eq!(&bytes[80..], &4u64.to_be_bytes());
        let a = rk.seal(&aad, b"meta", &mut rng).unwrap();
        let b = rk.seal(&aad, b"meta", &mut rng).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 24 + 4 + 16);
        assert_eq!(&*rk.open(&aad, &a).unwrap(), b"meta");
        // Any one public field changed and the sealed part does not open.
        for moved in [
            IndexSealAad {
                folder_id: FolderId([9; 32]),
                ..aad
            },
            IndexSealAad {
                writer_key_id: KeyId([9; 16]),
                ..aad
            },
            IndexSealAad {
                device_id: DeviceId([9; 32]),
                ..aad
            },
            IndexSealAad { seq: 5, ..aad },
        ] {
            assert_eq!(rk.open(&moved, &a), Err(AeadError));
        }
        assert_eq!(rk.open(&aad, &a[..39]), Err(AeadError));
        assert_eq!(rk.open(&aad, &[]), Err(AeadError));
        let mut damaged = a.clone();
        damaged[30] ^= 1;
        assert_eq!(rk.open(&aad, &damaged), Err(AeadError));
    }
}
