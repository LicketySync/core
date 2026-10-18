// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The bodies of the records whose effects are phase 7 (`keys.md` section 7):
//! Rotation, Wrap, Revocation, Suspension and Lift, with the Cutoff they share.
//! Their formats are fixed now; parsing runs each procedure's step 1 in full
//! (sizes, bounds, sorted lists), and [`super::FolderKeys::insert`] runs the
//! signer, signature and entitlement steps that phase 0 owes them.

use prost::Message as _;

use super::{
    check_prefix, decode_bounded, hash_field, issued_key_id_field, key_id_field,
    strictly_ascending, wire, Bound, Malformed, RecordType, Rejected, Shape, PREFIX_U32,
};
use crate::epoch::{Confirm, LadderLink};
use crate::ids::{DeviceId, FolderId, KeyId, RecordHash};
use crate::suite::{Suite, Tier};
use crate::wrap::WrappedDataKey;

/// The most wraps a Rotation carries.
pub const MAX_WRAPS: usize = 4096;
/// The most record hashes a Rotation's `view` carries.
pub const MAX_VIEW: usize = 8192;
/// The most cutoffs a Revocation or Suspension carries.
pub const MAX_CUTOFFS: usize = 4096;

/// "From writer `(key_id, device_id)` keep exactly the chain that ends at the
/// record with this `seq` and record hash" (`protocol.md` 4.5). `seq = 0` with
/// no `head_hash` keeps nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cutoff {
    /// The writer's key.
    pub key_id: KeyId,
    /// The writer's device.
    pub device_id: DeviceId,
    /// The last kept record's `seq`, or 0.
    pub seq: u64,
    /// The last kept record's hash; `None` exactly when `seq = 0`.
    pub head_hash: Option<RecordHash>,
}

impl Cutoff {
    fn parse(w: &wire::Cutoff) -> Result<Cutoff, Malformed> {
        let head_hash = match (w.seq, w.head_hash.is_empty()) {
            (0, true) => None,
            (0, false) | (_, true) => return Err(Malformed::Range("cutoff")),
            (_, false) => Some(hash_field(&w.head_hash, "cutoff.head_hash")?),
        };
        Ok(Cutoff {
            key_id: issued_key_id_field(&w.key_id, "cutoff.key_id")?,
            device_id: DeviceId::from_slice(&w.device_id)
                .ok_or(Malformed::FieldSize("cutoff.device_id"))?,
            seq: w.seq,
            head_hash,
        })
    }

    fn to_wire(self) -> wire::Cutoff {
        wire::Cutoff {
            key_id: self.key_id.0.to_vec(),
            device_id: self.device_id.0.to_vec(),
            seq: self.seq,
            head_hash: self.head_hash.map(|h| h.0.to_vec()).unwrap_or_default(),
        }
    }
}

fn parse_cutoffs(list: &[wire::Cutoff]) -> Result<Vec<Cutoff>, Malformed> {
    let cutoffs = list
        .iter()
        .map(Cutoff::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let writers: Vec<(KeyId, DeviceId)> = cutoffs.iter().map(|c| (c.key_id, c.device_id)).collect();
    if strictly_ascending(&writers) {
        Ok(cutoffs)
    } else {
        Err(Malformed::NotSorted("cutoffs"))
    }
}

fn encode_cutoffs(cutoffs: &[Cutoff]) -> Vec<wire::Cutoff> {
    let mut sorted = cutoffs.to_vec();
    sorted.sort_by_key(|c| (c.key_id, c.device_id));
    sorted.into_iter().map(Cutoff::to_wire).collect()
}

fn folder_of(bytes: &[u8]) -> Result<FolderId, Malformed> {
    FolderId::from_slice(bytes).ok_or(Malformed::FieldSize("folder_id"))
}

/// One wrap inside a Rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyWrapEntry {
    /// The recipient key, or [`KeyId::ROOT`].
    pub key_id: KeyId,
    /// `dk_new` wrapped with aad `folder_id || key_id || u8(tier) || be64(new_epoch)`.
    pub wrapped_data_key: WrappedDataKey,
}

/// A parsed Rotation body (type 3, section 7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationBody {
    /// The suite.
    pub suite: Suite,
    /// The folder.
    pub folder_id: FolderId,
    /// The epoch this rotation creates; at least 2.
    pub new_epoch: u64,
    /// Root, or the signer of `cause`.
    pub signer_key_id: KeyId,
    /// Sorted by key ID, unique, at most 4096.
    pub wraps: Vec<KeyWrapEntry>,
    /// `dk_{new-1}` under `dk_new`.
    pub ladder: LadderLink,
    /// The Revocation or Suspension (to none) this rotation accompanies.
    pub cause: Option<RecordHash>,
    /// Informational.
    pub issued_at: u64,
    /// Record hashes of the key records the signer held; sorted, unique, at most 8192.
    pub view: Vec<RecordHash>,
    /// `derive_key("licketysync/v1/epoch/confirm", dk_new)`.
    pub confirm: Confirm,
}

impl RotationBody {
    /// Parses a body and runs section 7.1 step 1's size and bound checks; the
    /// comparison of `new_epoch` with the current epoch needs the folder's
    /// state and is done on insertion.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] or [`Rejected::ValidityOnly`] (suite).
    pub fn parse(body: &[u8]) -> Result<RotationBody, Rejected> {
        let w: wire::Rotation = decode_bounded(
            body,
            &Shape::new(
                11,
                &PREFIX_U32,
                &[
                    Bound {
                        field: 6,
                        max: MAX_WRAPS,
                        name: "wraps",
                        entry_fields: 2,
                    },
                    Bound {
                        field: 10,
                        max: MAX_VIEW,
                        name: "view",
                        entry_fields: 0,
                    },
                ],
            ),
        )?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Rotation)?;
        if w.new_epoch < 2 {
            return Err(Malformed::Range("new_epoch").into());
        }
        let wraps = w
            .wraps
            .iter()
            .map(|k| {
                Ok(KeyWrapEntry {
                    key_id: key_id_field(&k.key_id, "wraps.key_id")?,
                    wrapped_data_key: WrappedDataKey::from_slice(&k.wrapped_data_key)
                        .ok_or(Malformed::FieldSize("wraps.wrapped_data_key"))?,
                })
            })
            .collect::<Result<Vec<_>, Malformed>>()?;
        if !strictly_ascending(&wraps.iter().map(|k| k.key_id).collect::<Vec<_>>()) {
            return Err(Malformed::NotSorted("wraps").into());
        }
        let view = w
            .view
            .iter()
            .map(|h| hash_field(h, "view"))
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_ascending(&view) {
            return Err(Malformed::NotSorted("view").into());
        }
        let cause = match w.cause.len() {
            0 => None,
            _ => Some(hash_field(&w.cause, "cause")?),
        };
        Ok(RotationBody {
            suite,
            folder_id: folder_of(&w.folder_id)?,
            new_epoch: w.new_epoch,
            signer_key_id: key_id_field(&w.signer_key_id, "signer_key_id")?,
            wraps,
            ladder: LadderLink::from_slice(&w.ladder).ok_or(Malformed::FieldSize("ladder"))?,
            cause,
            issued_at: w.issued_at,
            view,
            confirm: Confirm::from_slice(&w.confirm).ok_or(Malformed::FieldSize("confirm"))?,
        })
    }

    /// The canonical encoding; `wraps` and `view` are sorted first.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut wraps = self.wraps.clone();
        wraps.sort_by_key(|k| k.key_id);
        let mut view = self.view.clone();
        view.sort();
        wire::Rotation {
            suite: self.suite.to_wire(),
            record_type: RecordType::Rotation.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            new_epoch: self.new_epoch,
            signer_key_id: self.signer_key_id.0.to_vec(),
            wraps: wraps
                .iter()
                .map(|k| wire::KeyWrap {
                    key_id: k.key_id.0.to_vec(),
                    wrapped_data_key: k.wrapped_data_key.as_bytes().to_vec(),
                })
                .collect(),
            ladder: self.ladder.as_bytes().to_vec(),
            cause: self.cause.map(|h| h.0.to_vec()).unwrap_or_default(),
            issued_at: self.issued_at,
            view: view.iter().map(|h| h.0.to_vec()).collect(),
            confirm: self.confirm.0.to_vec(),
        }
        .encode_to_vec()
    }
}

/// A parsed Wrap body (type 4, section 7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapBody {
    /// The suite.
    pub suite: Suite,
    /// The folder.
    pub folder_id: FolderId,
    /// The key this wrap serves.
    pub key_id: KeyId,
    /// The epoch of the wrapped key.
    pub epoch: u64,
    /// `dk_epoch` wrapped with aad `folder_id || key_id || u8(tier) || be64(epoch)`.
    pub wrapped_data_key: WrappedDataKey,
    /// Root, the key's issuer, or an ancestor.
    pub signer_key_id: KeyId,
    /// Informational.
    pub issued_at: u64,
    /// The tier the aad uses: write or read.
    pub tier: Tier,
}

impl WrapBody {
    /// Parses a body: sizes, `epoch >= 1`, `tier` in {1, 2}.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] or [`Rejected::ValidityOnly`] (suite).
    pub fn parse(body: &[u8]) -> Result<WrapBody, Rejected> {
        let w: wire::Wrap = decode_bounded(body, &Shape::new(9, &[1, 2, 9], &[]))?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Wrap)?;
        if w.epoch == 0 {
            return Err(Malformed::Range("epoch").into());
        }
        let Some(tier @ (Tier::Write | Tier::Read)) = Tier::from_grant_wire(w.tier) else {
            return Err(Malformed::Range("tier").into());
        };
        Ok(WrapBody {
            suite,
            folder_id: folder_of(&w.folder_id)?,
            key_id: issued_key_id_field(&w.key_id, "key_id")?,
            epoch: w.epoch,
            wrapped_data_key: WrappedDataKey::from_slice(&w.wrapped_data_key)
                .ok_or(Malformed::FieldSize("wrapped_data_key"))?,
            signer_key_id: key_id_field(&w.signer_key_id, "signer_key_id")?,
            issued_at: w.issued_at,
            tier,
        })
    }

    /// The canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::Wrap {
            suite: self.suite.to_wire(),
            record_type: RecordType::Wrap.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            key_id: self.key_id.0.to_vec(),
            epoch: self.epoch,
            wrapped_data_key: self.wrapped_data_key.as_bytes().to_vec(),
            signer_key_id: self.signer_key_id.0.to_vec(),
            issued_at: self.issued_at,
            tier: self.tier.to_wire(),
        }
        .encode_to_vec()
    }
}

/// A parsed Revocation body (type 5, section 7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationBody {
    /// The suite.
    pub suite: Suite,
    /// The folder.
    pub folder_id: FolderId,
    /// The key revoked for ever, and everything beneath it.
    pub revoked_key_id: KeyId,
    /// Root, the key's issuer, or an ancestor.
    pub signer_key_id: KeyId,
    /// Per writer: the last record kept. Sorted by `(key_id, device_id)`.
    pub cutoffs: Vec<Cutoff>,
    /// Informational.
    pub issued_at: u64,
}

impl RevocationBody {
    /// Parses a body and runs section 7.2 step 1.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] or [`Rejected::ValidityOnly`] (suite).
    pub fn parse(body: &[u8]) -> Result<RevocationBody, Rejected> {
        let w: wire::Revocation = decode_bounded(
            body,
            &Shape::new(
                7,
                &PREFIX_U32,
                &[Bound {
                    field: 6,
                    max: MAX_CUTOFFS,
                    name: "cutoffs",
                    entry_fields: 4,
                }],
            ),
        )?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Revocation)?;
        Ok(RevocationBody {
            suite,
            folder_id: folder_of(&w.folder_id)?,
            revoked_key_id: issued_key_id_field(&w.revoked_key_id, "revoked_key_id")?,
            signer_key_id: key_id_field(&w.signer_key_id, "signer_key_id")?,
            cutoffs: parse_cutoffs(&w.cutoffs)?,
            issued_at: w.issued_at,
        })
    }

    /// The canonical encoding; `cutoffs` are sorted first.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::Revocation {
            suite: self.suite.to_wire(),
            record_type: RecordType::Revocation.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            revoked_key_id: self.revoked_key_id.0.to_vec(),
            signer_key_id: self.signer_key_id.0.to_vec(),
            cutoffs: encode_cutoffs(&self.cutoffs),
            issued_at: self.issued_at,
        }
        .encode_to_vec()
    }
}

/// The tier a suspended key acts at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActingTier {
    /// Read (wire `2`).
    Read,
    /// Sealed (wire `3`).
    Sealed,
    /// Not at all (wire `0`; counts as 255 in section 5.5).
    Nothing,
}

impl ActingTier {
    fn from_wire(value: u32) -> Option<ActingTier> {
        match value {
            0 => Some(ActingTier::Nothing),
            2 => Some(ActingTier::Read),
            3 => Some(ActingTier::Sealed),
            _ => None,
        }
    }

    fn to_wire(self) -> u32 {
        match self {
            ActingTier::Nothing => 0,
            ActingTier::Read => 2,
            ActingTier::Sealed => 3,
        }
    }
}

/// A parsed Suspension body (type 6, section 7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuspensionBody {
    /// The suite.
    pub suite: Suite,
    /// The folder.
    pub folder_id: FolderId,
    /// The suspended key.
    pub key_id: KeyId,
    /// What it and everything beneath it act as meanwhile.
    pub acting_tier: ActingTier,
    /// Unix seconds; `0` = until lifted.
    pub until: u64,
    /// Root, the key's issuer, or an ancestor.
    pub signer_key_id: KeyId,
    /// Informational.
    pub issued_at: u64,
    /// As for a revocation. Sorted by `(key_id, device_id)`.
    pub cutoffs: Vec<Cutoff>,
}

impl SuspensionBody {
    /// Parses a body and runs step 1 of the Suspension's procedure.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] or [`Rejected::ValidityOnly`] (suite).
    pub fn parse(body: &[u8]) -> Result<SuspensionBody, Rejected> {
        let w: wire::Suspension = decode_bounded(
            body,
            &Shape::new(
                9,
                &[1, 2, 5],
                &[Bound {
                    field: 9,
                    max: MAX_CUTOFFS,
                    name: "cutoffs",
                    entry_fields: 4,
                }],
            ),
        )?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Suspension)?;
        Ok(SuspensionBody {
            suite,
            folder_id: folder_of(&w.folder_id)?,
            key_id: issued_key_id_field(&w.key_id, "key_id")?,
            acting_tier: ActingTier::from_wire(w.acting_tier)
                .ok_or(Malformed::Range("acting_tier"))?,
            until: w.until,
            signer_key_id: key_id_field(&w.signer_key_id, "signer_key_id")?,
            issued_at: w.issued_at,
            cutoffs: parse_cutoffs(&w.cutoffs)?,
        })
    }

    /// The canonical encoding; `cutoffs` are sorted first.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::Suspension {
            suite: self.suite.to_wire(),
            record_type: RecordType::Suspension.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            key_id: self.key_id.0.to_vec(),
            acting_tier: self.acting_tier.to_wire(),
            until: self.until,
            signer_key_id: self.signer_key_id.0.to_vec(),
            issued_at: self.issued_at,
            cutoffs: encode_cutoffs(&self.cutoffs),
        }
        .encode_to_vec()
    }

    /// Whether the suspension is in force at `now_unix`, before any Lift.
    #[must_use]
    pub fn in_window(&self, now_unix: u64) -> bool {
        self.until == 0 || now_unix < self.until
    }
}

/// A parsed Lift body (type 7, section 7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftBody {
    /// The suite.
    pub suite: Suite,
    /// The folder.
    pub folder_id: FolderId,
    /// The `record_hash` of the Suspension this ends.
    pub suspension: RecordHash,
    /// Root, the suspended key's issuer, or an ancestor.
    pub signer_key_id: KeyId,
    /// Informational.
    pub issued_at: u64,
}

impl LiftBody {
    /// Parses a body.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] or [`Rejected::ValidityOnly`] (suite).
    pub fn parse(body: &[u8]) -> Result<LiftBody, Rejected> {
        let w: wire::Lift = decode_bounded(body, &Shape::new(6, &PREFIX_U32, &[]))?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Lift)?;
        Ok(LiftBody {
            suite,
            folder_id: folder_of(&w.folder_id)?,
            suspension: hash_field(&w.suspension, "suspension")?,
            signer_key_id: key_id_field(&w.signer_key_id, "signer_key_id")?,
            issued_at: w.issued_at,
        })
    }

    /// The canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::Lift {
            suite: self.suite.to_wire(),
            record_type: RecordType::Lift.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            suspension: self.suspension.0.to_vec(),
            signer_key_id: self.signer_key_id.0.to_vec(),
            issued_at: self.issued_at,
        }
        .encode_to_vec()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
pub(crate) mod tests {
    use super::*;
    use crate::records::Validity;

    pub(crate) fn cutoff(k: u8, d: u8, seq: u64) -> Cutoff {
        Cutoff {
            key_id: KeyId([k; 16]),
            device_id: DeviceId([d; 32]),
            seq,
            head_hash: (seq > 0).then_some(RecordHash([u8::try_from(seq).unwrap_or(0); 32])),
        }
    }

    pub(crate) fn wrapped() -> WrappedDataKey {
        WrappedDataKey::from_slice(&[7u8; 1168]).unwrap()
    }

    pub(crate) fn rotation() -> RotationBody {
        RotationBody {
            suite: Suite::ONE,
            folder_id: FolderId([1; 32]),
            new_epoch: 2,
            signer_key_id: KeyId::ROOT,
            wraps: vec![
                KeyWrapEntry {
                    key_id: KeyId([5; 16]),
                    wrapped_data_key: wrapped(),
                },
                KeyWrapEntry {
                    key_id: KeyId::ROOT,
                    wrapped_data_key: wrapped(),
                },
            ],
            ladder: LadderLink::from_slice(&[3; 72]).unwrap(),
            cause: None,
            issued_at: 9,
            view: vec![RecordHash([9; 32]), RecordHash([2; 32])],
            confirm: Confirm([4; 32]),
        }
    }

    #[test]
    fn rotation_round_trips_sorted_and_rejects_bad_lists() {
        let r = rotation();
        let parsed = RotationBody::parse(&r.encode()).unwrap();
        assert_eq!(parsed.wraps[0].key_id, KeyId::ROOT, "sorted on encode");
        assert_eq!(parsed.view, vec![RecordHash([2; 32]), RecordHash([9; 32])]);
        assert_eq!(parsed.encode(), r.encode());
        let mut w = wire::Rotation::decode(r.encode().as_slice()).unwrap();
        w.view.swap(0, 1);
        assert_eq!(
            RotationBody::parse(&w.encode_to_vec()).unwrap_err(),
            Rejected::Malformed(Malformed::NotSorted("view"))
        );
        let mut w = wire::Rotation::decode(r.encode().as_slice()).unwrap();
        w.wraps.swap(0, 1);
        assert_eq!(
            RotationBody::parse(&w.encode_to_vec()).unwrap_err(),
            Rejected::Malformed(Malformed::NotSorted("wraps"))
        );
        let mut w = wire::Rotation::decode(r.encode().as_slice()).unwrap();
        w.wraps[1] = w.wraps[0].clone();
        assert_eq!(
            RotationBody::parse(&w.encode_to_vec()).unwrap_err(),
            Rejected::Malformed(Malformed::NotSorted("wraps"))
        );
        let bad = |f: fn(&mut wire::Rotation)| {
            let mut w = wire::Rotation::decode(r.encode().as_slice()).unwrap();
            f(&mut w);
            RotationBody::parse(&w.encode_to_vec()).unwrap_err()
        };
        assert_eq!(
            bad(|w| w.new_epoch = 1),
            Rejected::Malformed(Malformed::Range("new_epoch"))
        );
        assert_eq!(
            bad(|w| w.ladder.truncate(71)),
            Rejected::Malformed(Malformed::FieldSize("ladder"))
        );
        assert_eq!(
            bad(|w| w.confirm.truncate(31)),
            Rejected::Malformed(Malformed::FieldSize("confirm"))
        );
        assert_eq!(
            bad(|w| w.cause = vec![1; 31]),
            Rejected::Malformed(Malformed::FieldSize("cause"))
        );
        assert_eq!(
            bad(|w| w.view[0].truncate(31)),
            Rejected::Malformed(Malformed::FieldSize("view"))
        );
        assert_eq!(
            bad(|w| w.wraps[0].wrapped_data_key.truncate(3)),
            Rejected::Malformed(Malformed::FieldSize("wraps.wrapped_data_key"))
        );
        assert_eq!(
            bad(|w| w.wraps[0].key_id.truncate(3)),
            Rejected::Malformed(Malformed::FieldSize("wraps.key_id"))
        );
        assert_eq!(
            bad(|w| w.record_type = 4),
            Rejected::Malformed(Malformed::WrongType {
                expected: RecordType::Rotation,
                found: 4
            })
        );
        assert_eq!(
            bad(|w| w.suite = 9),
            Rejected::ValidityOnly(Validity::UnimplementedSuite(9))
        );
        assert_eq!(
            bad(|w| w.folder_id.truncate(1)),
            Rejected::Malformed(Malformed::FieldSize("folder_id"))
        );
        assert_eq!(
            bad(|w| w.signer_key_id.truncate(1)),
            Rejected::Malformed(Malformed::FieldSize("signer_key_id"))
        );
        let with_cause = RotationBody {
            cause: Some(RecordHash([6; 32])),
            ..rotation()
        };
        assert_eq!(
            RotationBody::parse(&with_cause.encode()).unwrap().cause,
            Some(RecordHash([6; 32]))
        );
    }

    #[test]
    fn wrap_round_trips_and_checks_tier_and_epoch() {
        let w = WrapBody {
            suite: Suite::ONE,
            folder_id: FolderId([1; 32]),
            key_id: KeyId([2; 16]),
            epoch: 3,
            wrapped_data_key: wrapped(),
            signer_key_id: KeyId::ROOT,
            issued_at: 4,
            tier: Tier::Read,
        };
        assert_eq!(WrapBody::parse(&w.encode()).unwrap(), w);
        let bad = |f: fn(&mut wire::Wrap)| {
            let mut x = wire::Wrap::decode(w.encode().as_slice()).unwrap();
            f(&mut x);
            WrapBody::parse(&x.encode_to_vec()).unwrap_err()
        };
        assert_eq!(
            bad(|x| x.tier = 3),
            Rejected::Malformed(Malformed::Range("tier"))
        );
        assert_eq!(
            bad(|x| x.tier = 0),
            Rejected::Malformed(Malformed::Range("tier"))
        );
        assert_eq!(
            bad(|x| x.epoch = 0),
            Rejected::Malformed(Malformed::Range("epoch"))
        );
        assert_eq!(
            bad(|x| x.key_id = vec![0; 16]),
            Rejected::Malformed(Malformed::RootKeyId)
        );
        assert_eq!(
            bad(|x| x.wrapped_data_key.truncate(1)),
            Rejected::Malformed(Malformed::FieldSize("wrapped_data_key"))
        );
    }

    #[test]
    fn cutoffs_parse_sort_and_reject() {
        let r = RevocationBody {
            suite: Suite::ONE,
            folder_id: FolderId([1; 32]),
            revoked_key_id: KeyId([2; 16]),
            signer_key_id: KeyId::ROOT,
            cutoffs: vec![cutoff(3, 2, 0), cutoff(3, 1, 4)],
            issued_at: 5,
        };
        let parsed = RevocationBody::parse(&r.encode()).unwrap();
        assert_eq!(parsed.cutoffs, vec![cutoff(3, 1, 4), cutoff(3, 2, 0)]);
        let bad = |f: fn(&mut wire::Revocation)| {
            let mut x = wire::Revocation::decode(r.encode().as_slice()).unwrap();
            f(&mut x);
            RevocationBody::parse(&x.encode_to_vec()).unwrap_err()
        };
        assert_eq!(
            bad(|x| x.cutoffs.swap(0, 1)),
            Rejected::Malformed(Malformed::NotSorted("cutoffs"))
        );
        assert_eq!(
            bad(|x| x.cutoffs[0].head_hash.clear()),
            Rejected::Malformed(Malformed::Range("cutoff"))
        );
        assert_eq!(
            bad(|x| x.cutoffs[1].head_hash = vec![1; 32]),
            Rejected::Malformed(Malformed::Range("cutoff"))
        );
        assert_eq!(
            bad(|x| x.cutoffs[0].head_hash = vec![1; 31]),
            Rejected::Malformed(Malformed::FieldSize("cutoff.head_hash"))
        );
        assert_eq!(
            bad(|x| x.cutoffs[0].device_id.truncate(1)),
            Rejected::Malformed(Malformed::FieldSize("cutoff.device_id"))
        );
        assert_eq!(
            bad(|x| x.cutoffs[0].key_id = vec![0; 16]),
            Rejected::Malformed(Malformed::RootKeyId)
        );
        assert_eq!(
            bad(|x| x.revoked_key_id = vec![0; 16]),
            Rejected::Malformed(Malformed::RootKeyId)
        );
        let mut many = wire::Revocation::decode(r.encode().as_slice()).unwrap();
        many.cutoffs = (0..=MAX_CUTOFFS).map(|_| wire::Cutoff::default()).collect();
        assert_eq!(
            RevocationBody::parse(&many.encode_to_vec()).unwrap_err(),
            Rejected::Malformed(Malformed::TooMany("cutoffs"))
        );
    }

    #[test]
    fn suspension_and_lift_round_trip() {
        let s = SuspensionBody {
            suite: Suite::ONE,
            folder_id: FolderId([1; 32]),
            key_id: KeyId([2; 16]),
            acting_tier: ActingTier::Nothing,
            until: 100,
            signer_key_id: KeyId::ROOT,
            issued_at: 5,
            cutoffs: vec![cutoff(2, 1, 1)],
        };
        assert_eq!(SuspensionBody::parse(&s.encode()).unwrap(), s);
        assert!(s.in_window(99) && !s.in_window(100));
        assert!(SuspensionBody {
            until: 0,
            ..s.clone()
        }
        .in_window(u64::MAX));
        for (wire_value, tier) in [
            (2, ActingTier::Read),
            (3, ActingTier::Sealed),
            (0, ActingTier::Nothing),
        ] {
            assert_eq!(ActingTier::from_wire(wire_value), Some(tier));
            assert_eq!(tier.to_wire(), wire_value);
        }
        let mut x = wire::Suspension::decode(s.encode().as_slice()).unwrap();
        x.acting_tier = 1;
        assert_eq!(
            SuspensionBody::parse(&x.encode_to_vec()).unwrap_err(),
            Rejected::Malformed(Malformed::Range("acting_tier"))
        );
        let l = LiftBody {
            suite: Suite::ONE,
            folder_id: FolderId([1; 32]),
            suspension: RecordHash([3; 32]),
            signer_key_id: KeyId::ROOT,
            issued_at: 6,
        };
        assert_eq!(LiftBody::parse(&l.encode()).unwrap(), l);
        let mut y = wire::Lift::decode(l.encode().as_slice()).unwrap();
        y.suspension.truncate(31);
        assert_eq!(
            LiftBody::parse(&y.encode_to_vec()).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("suspension"))
        );
    }
}
