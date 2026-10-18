// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The holder's side: recovering a data key from a stored record with the
//! seed's key pair set, and checking it against its epoch's key-confirmation
//! value before any use (`keys.md` sections 2.2, 3.1, 5.3 and 7.1 step 8;
//! round 4 ruling, SF 3). A wrap sits inside a validly signed body, so a wrap
//! that does not open, or opens to a key that fails its confirmation, is a
//! signer fault of the record that carried it (`suites.md` 2.1, TM-10): the
//! error names that record's signer, and no key is ever defaulted. Only a
//! confirmed `dk_e` opens the ladder of epoch `e`.
//!
//! While an epoch is ambiguous (more than one stored rotation names it), no
//! key of it is used and no ladder rung through it is climbed (rulings 24
//! and 25). What a record says about itself is still judged and still blames
//! its signer: a wrap that does not open (HPKE), and a rotation's own
//! `KeyWrap` against its own `confirm` (section 7.1 step 8). Only a check
//! against the epoch's `confirm` in this verifier's chain, which is then one
//! chosen among rivals, is the no-blame [`HolderError::EpochAmbiguous`].

use core::fmt;

use super::store::{Body, FolderKeys};
use crate::epoch::Confirm;
use crate::ids::{KeyId, RecordHash};
use crate::keyset::KeyPairSet;
use crate::secret::{ChunkHashKey, DataKey};
use crate::wrap::{unwrap_data_key, WrapAad};

/// Why a holder could not recover a data key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderError {
    /// The key pair set's public halves are not the ones the record names.
    NotThisKey,
    /// No stored record of the right type has this hash.
    NotStored,
    /// A sealed grant carries no data key.
    Sealed,
    /// The rotation carries no wrap for this key.
    NoWrap,
    /// The wrap did not open: flag `signer`, who produced it.
    Unwrap {
        /// The issuer or rotator.
        signer: KeyId,
    },
    /// The recovered key fails the epoch's confirmation value: flag `signer`
    /// and do not use the key.
    ConfirmMismatch {
        /// The signer of the record that carried the wrap.
        signer: KeyId,
    },
    /// The epoch's confirmation value is not known here (no rotation for it
    /// in this verifier's chain), so the key cannot be used yet.
    UnknownEpoch(u64),
    /// The key offered to open a ladder is not the confirmed key of the
    /// rotation's epoch.
    NotConfirmed,
    /// More than one stored rotation names this epoch, so which key it holds
    /// is undecided until phase 7 picks the winner: nothing is adopted and
    /// nobody is blamed (security review, SF 4; ruling 24).
    EpochAmbiguous(u64),
}

impl fmt::Display for HolderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotThisKey => f.write_str("this key is not the one the record names"),
            Self::NotStored => f.write_str("no such stored record"),
            Self::Sealed => f.write_str("a sealed grant carries no data key"),
            Self::NoWrap => f.write_str("the rotation carries no wrap for this key"),
            Self::Unwrap { signer } => write!(f, "the wrap produced by {signer} did not open"),
            Self::ConfirmMismatch { signer } => {
                write!(f, "the key wrapped by {signer} fails its confirmation")
            }
            Self::UnknownEpoch(e) => write!(f, "epoch {e}'s confirmation value is not known"),
            Self::NotConfirmed => f.write_str("the key is not this epoch's confirmed key"),
            Self::EpochAmbiguous(e) => write!(f, "more than one rotation names epoch {e}"),
        }
    }
}

impl std::error::Error for HolderError {}

fn confirmed(dk: DataKey, expected: &Confirm, signer: KeyId) -> Result<DataKey, HolderError> {
    if bool::from(dk.confirm().ct_eq(expected)) {
        Ok(dk)
    } else {
        Err(HolderError::ConfirmMismatch { signer })
    }
}

impl FolderKeys {
    /// `hk`, the folder-lifetime chunk-hash key (section 3.2), derived from
    /// `dk_1` only: `None` unless `dk_1` matches the Folder record's
    /// `confirm`, so that no later epoch's key can stand in for it.
    #[must_use]
    pub fn chunk_hash_key(&self, dk_1: &DataKey) -> Option<ChunkHashKey> {
        bool::from(dk_1.confirm().ct_eq(&self.folder().confirm)).then(|| dk_1.chunk_hash_key())
    }

    /// The holder's data key through its governing grant (section 5.5) at
    /// `now_unix`: [`FolderKeys::unwrap_grant_data_key`] on the grant that
    /// governs `key_id`, so that the engine never picks a grant itself.
    ///
    /// # Errors
    ///
    /// [`HolderError::NotStored`] when no grant of `key_id` is stored, and
    /// otherwise as [`FolderKeys::unwrap_grant_data_key`].
    pub fn unwrap_governing_data_key(
        &self,
        key_id: &KeyId,
        holder: &KeyPairSet,
        now_unix: u64,
    ) -> Result<(u64, DataKey), HolderError> {
        let (hash, _) = self
            .validity(now_unix)
            .governing_grant(key_id)
            .ok_or(HolderError::NotStored)?;
        self.unwrap_grant_data_key(hash, holder)
    }

    /// The confirmation value a key of `epoch` must match in this verifier's
    /// chain, unless the epoch is ambiguous (the value would be one chosen
    /// among rivals) or unknown here.
    fn confirm_for(&self, epoch: u64) -> Result<Confirm, HolderError> {
        if self.epoch_ambiguous(epoch) {
            return Err(HolderError::EpochAmbiguous(epoch));
        }
        self.epoch_confirm(epoch)
            .ok_or(HolderError::UnknownEpoch(epoch))
    }

    /// The root holder recovers `dk_1` from the Folder record and checks it
    /// against the record's `confirm` (section 2.2).
    ///
    /// # Errors
    ///
    /// [`HolderError`].
    pub fn unwrap_root_data_key(&self, root: &KeyPairSet) -> Result<DataKey, HolderError> {
        let folder = self.folder();
        if root.public().signing != folder.root_signing_pk
            || root.public().kem != folder.root_kem_pk
        {
            return Err(HolderError::NotThisKey);
        }
        let dk = unwrap_data_key(root, &folder.root_wrap_aad(), &folder.root_wrapped_data_key)
            .map_err(|_| HolderError::Unwrap {
                signer: KeyId::ROOT,
            })?;
        confirmed(dk, &folder.confirm, KeyId::ROOT)
    }

    /// The holder of an issued key's seed recovers `dk_epoch` from one of its
    /// stored grants (section 5.4, after step 9): the key pair set must match
    /// the grant's `signing_pk` and `kem_pk`, the aad is rebuilt from the
    /// grant's own fields, and the key is checked against its epoch's
    /// `confirm`. Returns the epoch and the key.
    ///
    /// # Errors
    ///
    /// [`HolderError`].
    pub fn unwrap_grant_data_key(
        &self,
        grant: &RecordHash,
        holder: &KeyPairSet,
    ) -> Result<(u64, DataKey), HolderError> {
        let Some((_, g)) = self.grants_by_hash(grant) else {
            return Err(HolderError::NotStored);
        };
        if holder.public().signing != g.signing_pk || holder.public().kem != g.kem_pk {
            return Err(HolderError::NotThisKey);
        }
        let wrapped = g.wrapped_data_key.as_ref().ok_or(HolderError::Sealed)?;
        let signer = g.issuer_key_id;
        // The wrap is the issuer's own: one that does not open blames it,
        // ambiguous epoch or not; the confirmation is the chain's.
        let dk = unwrap_data_key(holder, &g.wrap_aad(), wrapped)
            .map_err(|_| HolderError::Unwrap { signer })?;
        let expected = self.confirm_for(g.epoch)?;
        Ok((g.epoch, confirmed(dk, &expected, signer)?))
    }

    /// The holder of `holder`'s seed recovers `dk_epoch` from a stored Wrap
    /// record and checks it against its epoch's `confirm` (section 7.1, Wrap
    /// record).
    ///
    /// # Errors
    ///
    /// [`HolderError`].
    pub fn unwrap_wrap_data_key(
        &self,
        wrap: &RecordHash,
        holder: &KeyPairSet,
    ) -> Result<(u64, DataKey), HolderError> {
        let Some(Body::Wrap(w)) = self.entries.get(wrap).map(|e| &e.body) else {
            return Err(HolderError::NotStored);
        };
        if holder.public().key_id(self.folder().suite) != w.key_id {
            return Err(HolderError::NotThisKey);
        }
        let aad = WrapAad {
            folder_id: w.folder_id,
            key_id: w.key_id,
            tier: w.tier,
            epoch: w.epoch,
        };
        let signer = w.signer_key_id;
        let dk = unwrap_data_key(holder, &aad, &w.wrapped_data_key)
            .map_err(|_| HolderError::Unwrap { signer })?;
        let expected = self.confirm_for(w.epoch)?;
        Ok((w.epoch, confirmed(dk, &expected, signer)?))
    }

    /// Section 7.1 steps 8 and 9 (phase 7): the holder of `key_id` recovers
    /// the rotation's `dk_new`, checks it against the rotation's `confirm` (a
    /// mismatch means the rotator wrapped different keys to different
    /// holders), and then checks the rotation's ladder with it
    /// ([`FolderKeys::climb_ladder`]). The key is returned for adoption only
    /// when every check passed: a ladder that fails, by its tag or by a
    /// recovered key that fails the previous epoch's `confirm`, flags the
    /// rotator and leaves the holder with nothing from this rotation (ruling
    /// 19). While `new_epoch` is ambiguous the HPKE open and step 8 still run
    /// and blame as usual, and then the key is withheld and the ladder not
    /// climbed (rulings 24 and 25).
    ///
    /// # Errors
    ///
    /// [`HolderError`]; a ladder failure is [`HolderError::Unwrap`] or
    /// [`HolderError::ConfirmMismatch`] naming the rotator, or
    /// [`HolderError::UnknownEpoch`] when the previous epoch's `confirm` is
    /// not known here; [`HolderError::EpochAmbiguous`] once the HPKE open
    /// and step 8 passed for an ambiguous `new_epoch`, or for an ambiguous
    /// previous epoch.
    pub fn unwrap_rotation_data_key(
        &self,
        rotation: &RecordHash,
        key_id: &KeyId,
        holder: &KeyPairSet,
    ) -> Result<DataKey, HolderError> {
        let Some(Body::Rotation(r)) = self.entries.get(rotation).map(|e| &e.body) else {
            return Err(HolderError::NotStored);
        };
        if self.signing_key(key_id) != Some(&holder.public().signing) {
            return Err(HolderError::NotThisKey);
        }
        let entry = r
            .wraps
            .iter()
            .find(|w| w.key_id == *key_id)
            .ok_or(HolderError::NoWrap)?;
        let tier = self
            .rotation_wrap_tier(r, key_id)
            .ok_or(HolderError::NoWrap)?;
        let aad = WrapAad {
            folder_id: r.folder_id,
            key_id: *key_id,
            tier,
            epoch: r.new_epoch,
        };
        let signer = r.signer_key_id;
        let dk = unwrap_data_key(holder, &aad, &entry.wrapped_data_key)
            .map_err(|_| HolderError::Unwrap { signer })?;
        // Step 8, the rotation's own `confirm`: a mismatch blames the rotator
        // even while the epoch is ambiguous.
        let dk_new = confirmed(dk, &r.confirm, signer)?;
        if self.epoch_ambiguous(r.new_epoch) {
            return Err(HolderError::EpochAmbiguous(r.new_epoch));
        }
        self.climb_ladder(rotation, &dk_new)?;
        Ok(dk_new)
    }

    /// Climbs one rung of the ladder (section 3.1): `dk_new` must be the
    /// rotation's confirmed key (only a confirmed key opens a ladder); then
    /// `dk_{new-1}` is recovered and checked against the previous epoch's
    /// `confirm` in this verifier's chain (the Folder record's for epoch 1).
    /// Only then does a ladder that does not open, or opens to the wrong key,
    /// charge the rotator; the holder keeps only the epochs it confirmed.
    /// No rung through an ambiguous epoch is climbed (rulings 24 and 25):
    /// not the rung down from it, and not the rung into it, whose recovered
    /// key would be judged against a `confirm` chosen among rivals.
    ///
    /// # Errors
    ///
    /// [`HolderError`].
    pub fn climb_ladder(
        &self,
        rotation: &RecordHash,
        dk_new: &DataKey,
    ) -> Result<DataKey, HolderError> {
        let Some(Body::Rotation(r)) = self.entries.get(rotation).map(|e| &e.body) else {
            return Err(HolderError::NotStored);
        };
        if !bool::from(dk_new.confirm().ct_eq(&r.confirm)) {
            return Err(HolderError::NotConfirmed);
        }
        if self.epoch_ambiguous(r.new_epoch) {
            return Err(HolderError::EpochAmbiguous(r.new_epoch));
        }
        let signer = r.signer_key_id;
        // The ladder is the rotation's own, sealed under its own confirmed
        // key: one that does not open blames the rotator.
        let dk = r
            .ladder
            .open(dk_new, r.new_epoch, &r.folder_id)
            .map_err(|_| HolderError::Unwrap { signer })?;
        let previous = self.confirm_for(r.new_epoch - 1)?;
        confirmed(dk, &previous, signer)
    }
}
