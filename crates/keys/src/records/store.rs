// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! [`FolderKeys`]: the verified key records of one folder, and the insertion
//! procedures of `keys.md` sections 2.2, 5.4 and 7 (phase 0 part).
//!
//! Persistence is the caller's: it stores the bytes of every record
//! [`FolderKeys::records`] yields and, on restart, rebuilds the set by
//! inserting them again in that order, which re-verifies each one.

use std::collections::{BTreeMap, BTreeSet};

use super::groups::{Group, GroupIndex, WalkLevels};
use super::refused::Refused;
use super::validity::{Grants, KeyValidity};
use super::{
    signature_of, Accepted, FolderBody, GrantBody, Issue, LiftBody, Malformed, Missing, RecordType,
    Rejected, RevocationBody, RotationBody, SignedRecord, SignerFault, SuspensionBody, Validity,
    WrapBody, MAX_KEY_RECORD_LEN,
};
use crate::ids::{FolderId, KeyId, RecordHash};
use crate::keyset::SigningPublicKey;
use crate::records::phase7::{ActingTier, Cutoff};
use crate::suite::Tier;

/// The most key records not signed by root that one folder's store holds,
/// named as in `protocol.md` (rulings 21 and 23). Every
/// collection a peer can grow is bounded (TM-2, TM-22); a record past this
/// or another quota is a validity-only rejection, [`Validity::QuotaExceeded`],
/// an issue naming its signer and no fault of the sender: the connection
/// stays open. Root-signed records are exempt, so root's Revocations and
/// Rotations always fit.
pub const MAX_KEY_RECORDS_PER_FOLDER: usize = 65_536;

/// The most stored key records one non-root signer may have signed (ruling
/// 23).
pub const MAX_KEY_RECORDS_PER_SIGNER: usize = 4_096;

/// The most encoded bytes the non-root key records of one folder may take
/// (ruling 23): 512 MiB.
pub const MAX_KEY_RECORD_BYTES_PER_FOLDER: usize = 512 * 1024 * 1024;

/// Which quota a refused record would have passed (ruling 23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quota {
    /// [`MAX_KEY_RECORDS_PER_FOLDER`] non-root records in the folder.
    FolderRecords,
    /// [`MAX_KEY_RECORDS_PER_SIGNER`] records by this signer.
    SignerRecords,
    /// [`MAX_KEY_RECORD_BYTES_PER_FOLDER`] bytes of non-root records.
    FolderBytes,
}

/// A stored record's parsed body.
#[derive(Clone, Debug)]
pub(crate) enum Body {
    Grant(Box<GrantBody>),
    Rotation(Box<RotationBody>),
    Wrap(Box<WrapBody>),
    Revocation(RevocationBody),
    Suspension(SuspensionBody),
    Lift(LiftBody),
}

impl Body {
    /// The key that signed the record: a grant's issuer, every other record's
    /// `signer_key_id`.
    pub(crate) fn signer(&self) -> KeyId {
        match self {
            Body::Grant(g) => g.issuer_key_id,
            Body::Rotation(r) => r.signer_key_id,
            Body::Wrap(w) => w.signer_key_id,
            Body::Revocation(r) => r.signer_key_id,
            Body::Suspension(s) => s.signer_key_id,
            Body::Lift(l) => l.signer_key_id,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) record: SignedRecord,
    pub(crate) body: Body,
}

/// The verified key records of one folder: its Folder record, then every
/// grant, rotation, wrap, revocation, suspension and lift that passed
/// verification, in the order they were stored (which is a dependency order).
#[derive(Clone, Debug)]
pub struct FolderKeys {
    folder_record: SignedRecord,
    folder: FolderBody,
    folder_hash: RecordHash,
    /// The rotation that created each epoch from 2 up: a dense chain, so the
    /// current epoch is its length plus one.
    epoch_rotations: Vec<RecordHash>,
    /// The (epoch, signer) of every stored rival or stale rotation: at most
    /// one each (ruling 22).
    rivals: BTreeSet<(u64, KeyId)>,
    /// Ruling 23's counters: stored records not signed by root, their
    /// encoded bytes, and each non-root signer's stored records.
    non_root_records: usize,
    non_root_bytes: usize,
    records_by_signer: BTreeMap<KeyId, usize>,
    /// The records refused under a quota, and those refused because they
    /// need one (rulings 24 and 25).
    pub(crate) refused: Refused,
    /// Set by [`FolderKeys::load`] for the record it is inserting: the key
    /// under which the parallel pass already verified that record's signature
    /// (and, for a grant, its proof of possession).
    pre_verified: Option<SigningPublicKey>,
    pub(crate) entries: BTreeMap<RecordHash, Entry>,
    order: Vec<RecordHash>,
    pub(crate) grants_by_key: BTreeMap<KeyId, Vec<RecordHash>>,
    /// The grants by group, for the chain searches.
    pub(crate) groups: GroupIndex,
    /// The phase 0 to 6 walk level of every group, kept as grants arrive.
    pub(crate) walks: WalkLevels,
    pub(crate) revocations_by_key: BTreeMap<KeyId, Vec<RecordHash>>,
    pub(crate) suspensions_by_key: BTreeMap<KeyId, Vec<RecordHash>>,
    pub(crate) lifts_by_suspension: BTreeMap<RecordHash, Vec<RecordHash>>,
}

/// `signer` is not entitled over `key` (root, its issuer or an ancestor). No
/// grant can make a key its own issuer or ancestor (ruling 19), nor any key
/// root's: those blame the signer. Otherwise a grant of `key` not held here
/// may entitle it, so the refusal blames nobody (rulings 25 and 26).
fn not_entitled(signer: KeyId, key: KeyId) -> Rejected {
    if signer == key || key.is_root() {
        Rejected::SignerFault {
            signer,
            fault: SignerFault::NotEntitled,
        }
    } else {
        Rejected::unprovable(signer, SignerFault::NotEntitled, key)
    }
}

/// A key record's encoded size: at most [`MAX_KEY_RECORD_LEN`] bytes, judged
/// before anything else, the duplicate check included (section 5.4 step 1).
pub(crate) fn check_size(record: &SignedRecord) -> Result<(), Rejected> {
    let len = prost::Message::encoded_len(record);
    if len > MAX_KEY_RECORD_LEN {
        Err(Malformed::TooLarge(len).into())
    } else {
        Ok(())
    }
}

impl FolderKeys {
    /// Starts a folder's set from its Folder record (section 2.2), verified
    /// in order: parse, the root's signature, the folder ID's recomputation;
    /// then it must name `expected`, the folder ID the caller was given (a key
    /// string, a link, a stored folder).
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] (including [`Malformed::OtherFolder`]),
    /// [`Rejected::Forged`] or [`Rejected::ValidityOnly`].
    pub fn new(expected: &FolderId, record: SignedRecord) -> Result<FolderKeys, Rejected> {
        if !record.key_signature.is_empty() {
            return Err(Malformed::UnexpectedKeySignature.into());
        }
        let folder = FolderBody::verify(&record)?;
        if folder.folder_id != *expected {
            return Err(Malformed::OtherFolder.into());
        }
        let folder_hash = record.hash();
        Ok(FolderKeys {
            folder_record: record,
            folder,
            folder_hash,
            epoch_rotations: Vec::new(),
            rivals: BTreeSet::new(),
            non_root_records: 0,
            non_root_bytes: 0,
            records_by_signer: BTreeMap::new(),
            refused: Refused::default(),
            pre_verified: None,
            entries: BTreeMap::new(),
            order: Vec::new(),
            grants_by_key: BTreeMap::new(),
            groups: GroupIndex::default(),
            walks: WalkLevels::default(),
            revocations_by_key: BTreeMap::new(),
            suspensions_by_key: BTreeMap::new(),
            lifts_by_suspension: BTreeMap::new(),
        })
    }

    /// The folder's ID.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder.folder_id
    }

    /// The Folder record's parsed body.
    #[must_use]
    pub fn folder(&self) -> &FolderBody {
        &self.folder
    }

    /// The folder's current epoch as this verifier knows it: one more than
    /// the length of the dense chain of stored rotations from epoch 2 (round 4
    /// ruling, SF 9). In phases 0 to 6 it is used for dependency checks only;
    /// no rotation's effects are applied.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        u64::try_from(self.epoch_rotations.len()).map_or(u64::MAX, |n| n.saturating_add(1))
    }

    /// The rotation that created `epoch` in this verifier's chain (`None` for
    /// epoch 1, which the Folder record created, and for epochs not reached).
    #[must_use]
    pub fn epoch_rotation(&self, epoch: u64) -> Option<&RecordHash> {
        epoch
            .checked_sub(2)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| self.epoch_rotations.get(i))
    }

    /// The key-confirmation value of `epoch`: the Folder record's for epoch
    /// 1, else the rotation's that created it in this verifier's chain.
    #[must_use]
    pub fn epoch_confirm(&self, epoch: u64) -> Option<crate::epoch::Confirm> {
        if epoch == 1 {
            return Some(self.folder.confirm);
        }
        match self
            .epoch_rotation(epoch)
            .and_then(|h| self.entries.get(h))
            .map(|e| &e.body)
        {
            Some(Body::Rotation(r)) => Some(r.confirm),
            _ => None,
        }
    }

    /// The number of stored records, the Folder record included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len() + 1
    }

    /// Always false: a set holds at least its Folder record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether a record with this hash is stored.
    #[must_use]
    pub fn contains(&self, hash: &RecordHash) -> bool {
        *hash == self.folder_hash || self.entries.contains_key(hash)
    }

    /// The stored record with this hash.
    #[must_use]
    pub fn get(&self, hash: &RecordHash) -> Option<&SignedRecord> {
        if *hash == self.folder_hash {
            Some(&self.folder_record)
        } else {
            self.entries.get(hash).map(|e| &e.record)
        }
    }

    /// Every stored record, the Folder record first and then in the order
    /// they were stored: a dependency order, as `KeyRecords` must send them
    /// (`protocol.md` 4.6) and as a restart must re-insert them.
    pub fn records(&self) -> impl Iterator<Item = (&RecordHash, &SignedRecord)> + '_ {
        core::iter::once((&self.folder_hash, &self.folder_record)).chain(
            self.order
                .iter()
                .filter_map(|h| self.entries.get(h).map(|e| (h, &e.record))),
        )
    }

    /// Every grant stored for `key_id`, in the order stored.
    pub fn grants_for(
        &self,
        key_id: &KeyId,
    ) -> impl Iterator<Item = (&RecordHash, &GrantBody)> + '_ {
        self.grants_by_key
            .get(key_id)
            .into_iter()
            .flatten()
            .filter_map(|h| self.grant(h).map(|g| (h, g)))
    }

    /// The hybrid signing key of an issued key with a stored grant, or of
    /// root for [`KeyId::ROOT`]. A key's ID is derived from its two public
    /// keys, so all of its grants carry the same ones.
    #[must_use]
    pub fn signing_key(&self, key_id: &KeyId) -> Option<&SigningPublicKey> {
        if key_id.is_root() {
            Some(&self.folder.root_signing_pk)
        } else {
            self.grants_for(key_id).next().map(|(_, g)| &g.signing_pk)
        }
    }

    /// The stored Revocations, with their hashes.
    pub fn revocations(&self) -> impl Iterator<Item = (&RecordHash, &RevocationBody)> + '_ {
        self.entries.iter().filter_map(|(h, e)| match &e.body {
            Body::Revocation(r) => Some((h, r)),
            _ => None,
        })
    }

    /// The stored Suspensions, with their hashes.
    pub fn suspensions(&self) -> impl Iterator<Item = (&RecordHash, &SuspensionBody)> + '_ {
        self.entries.iter().filter_map(|(h, e)| match &e.body {
            Body::Suspension(s) => Some((h, s)),
            _ => None,
        })
    }

    /// The stored Rotations, with their hashes. Phase 0 stores them without
    /// applying them.
    pub fn rotations(&self) -> impl Iterator<Item = (&RecordHash, &RotationBody)> + '_ {
        self.entries.iter().filter_map(|(h, e)| match &e.body {
            Body::Rotation(r) => Some((h, r.as_ref())),
            _ => None,
        })
    }

    /// The stored Wraps, with their hashes. Phase 0 stores them without
    /// applying them.
    pub fn wraps(&self) -> impl Iterator<Item = (&RecordHash, &WrapBody)> + '_ {
        self.entries.iter().filter_map(|(h, e)| match &e.body {
            Body::Wrap(w) => Some((h, w.as_ref())),
            _ => None,
        })
    }

    /// Whether a stored Lift ends the Suspension with this hash.
    #[must_use]
    pub fn is_lifted(&self, suspension: &RecordHash) -> bool {
        self.lifts_by_suspension
            .get(suspension)
            .is_some_and(|l| !l.is_empty())
    }

    pub(crate) fn grant(&self, hash: &RecordHash) -> Option<&GrantBody> {
        match self.entries.get(hash).map(|e| &e.body) {
            Some(Body::Grant(g)) => Some(g),
            _ => None,
        }
    }

    /// The ancestors of `key` (ruling 18): the keys on some authorizing walk
    /// of at most 16 stored grants from a grant of `key` to root.
    #[cfg(test)]
    pub(crate) fn ancestors(&self, key: &KeyId) -> BTreeSet<KeyId> {
        self.stored_grants().ancestors(key)
    }

    /// Whether `key` is `top` or lies beneath it: `top` is an ancestor of
    /// `key` (ruling 18), so a revocation or suspension of `top` reaches
    /// `key`.
    #[must_use]
    pub fn in_subtree(&self, key: &KeyId, top: &KeyId) -> bool {
        key == top || self.stored_grants().is_ancestor(top, key)
    }

    /// Stores a key record after verifying it by its procedure. `now_unix` is
    /// the device's wall clock (`Clock::wall_time()`), used only where the
    /// spec compares with now: whether a suspension is active.
    ///
    /// The encoded size is judged first (at most [`MAX_KEY_RECORD_LEN`]);
    /// then a record whose hash is already stored is a duplicate and is
    /// ignored before anything else (records are merged by `record_hash`,
    /// `protocol.md` 4.6; equal bodies are the same record whatever their
    /// signatures). Grants run all of section 5.4. Rotations, Wraps,
    /// Revocations, Suspensions and Lifts run the parse, resolve-the-signer,
    /// signature and entitlement steps phase 0 owes them and are stored with
    /// [`Issue::NotApplied`]. In phases 0 to 6 nothing applies them (ruling
    /// 21): validity, presentability and effective tier ([`Self::validity`])
    /// ignore stored Revocations, Suspensions and Lifts.
    ///
    /// # Errors
    ///
    /// [`Rejected`], whose variant is the cause in `protocol.md`'s table. A
    /// failure that rests only on a grant not being stored is
    /// [`Validity::UnprovableFault`], never a signer fault (rulings 24 and
    /// 25). A record refused under a quota is remembered
    /// ([`FolderKeys::refused_under_quota`]), and so is one that needs a
    /// remembered record: one whose missing dependency is remembered, which
    /// is [`Validity::DependencyRefused`] rather than a missing dependency,
    /// and one refused for a grant not stored of a key with a remembered
    /// refusal (ruling 26).
    pub fn insert(&mut self, record: &SignedRecord, now_unix: u64) -> Result<Accepted, Rejected> {
        check_size(record)?;
        let hash = record.hash();
        if self.contains(&hash) {
            return Ok(Accepted::Duplicate(hash));
        }
        let record_type = Self::check_envelope(record)?;
        let (body, issues) = match self.verify_record(record_type, record, now_unix) {
            Ok(verified) => verified,
            Err(rejected) => {
                let rejected = self.after_refusals(rejected);
                // A record that needs a remembered refusal is remembered in
                // turn (rulings 24 to 26): one refused for a missing
                // dependency the memory covers, or for a grant not stored
                // whose key has a remembered refusal.
                let needs_refused = match rejected {
                    Rejected::ValidityOnly(Validity::DependencyRefused(_)) => true,
                    Rejected::ValidityOnly(Validity::UnprovableFault {
                        absent_grant_of, ..
                    }) => self.refused.grants(&absent_grant_of),
                    _ => false,
                };
                if needs_refused {
                    self.refused
                        .remember_dependent(hash, record_type, &record.body);
                }
                return Err(rejected);
            }
        };
        let signer = body.signer();
        let len = prost::Message::encoded_len(record);
        if let Err(refused) = self.check_quotas(&signer, len) {
            self.refused.remember_refused(hash, &body);
            return Err(refused);
        }
        self.store(hash, record.clone(), body);
        if !signer.is_root() {
            self.non_root_records += 1;
            self.non_root_bytes = self.non_root_bytes.saturating_add(len);
            *self.records_by_signer.entry(signer).or_default() += 1;
        }
        Ok(Accepted::Stored {
            hash,
            record_type,
            issues,
        })
    }

    /// The procedure of a key record's type, from its parse to its last
    /// check before the quotas.
    fn verify_record(
        &self,
        record_type: RecordType,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<(Body, Vec<Issue>), Rejected> {
        match record_type {
            RecordType::Folder => Err(self.second_folder_record(record)),
            RecordType::Grant => {
                let (grant, issues) =
                    self.verify_grant_in(self.stored_grants(), record, now_unix, true)?;
                Ok((Body::Grant(Box::new(grant)), issues))
            }
            RecordType::Rotation => self.verify_rotation(record, now_unix),
            RecordType::Wrap => self.verify_wrap(record, now_unix),
            RecordType::Revocation => self.verify_revocation(record, now_unix),
            RecordType::Suspension => self.verify_suspension(record, now_unix),
            RecordType::Lift => self.verify_lift(record, now_unix),
            RecordType::RootRotation => {
                Err(Rejected::ValidityOnly(Validity::UnsupportedRecordType(8)))
            }
            RecordType::Index => Err(Malformed::NotAKeyRecord.into()),
        }
    }

    /// Ruling 23's quotas, judged after a record verified so that the issue
    /// can name its signer: root-signed records are exempt and always
    /// accepted; any other signer may have [`MAX_KEY_RECORDS_PER_SIGNER`]
    /// stored records, and non-root records together are at most
    /// [`MAX_KEY_RECORDS_PER_FOLDER`] in number and
    /// [`MAX_KEY_RECORD_BYTES_PER_FOLDER`] in encoded bytes. Which records fit once a quota is reached depends on
    /// the order they arrived in; root's never do not.
    fn check_quotas(&self, signer: &KeyId, len: usize) -> Result<(), Rejected> {
        if signer.is_root() {
            return Ok(());
        }
        let quota = if self.non_root_records >= MAX_KEY_RECORDS_PER_FOLDER {
            Some(Quota::FolderRecords)
        } else if self.records_by_signer.get(signer).copied().unwrap_or(0)
            >= MAX_KEY_RECORDS_PER_SIGNER
        {
            Some(Quota::SignerRecords)
        } else if self.non_root_bytes.saturating_add(len) > MAX_KEY_RECORD_BYTES_PER_FOLDER {
            Some(Quota::FolderBytes)
        } else {
            None
        };
        quota.map_or(Ok(()), |quota| {
            Err(Rejected::ValidityOnly(Validity::QuotaExceeded {
                signer: *signer,
                quota,
            }))
        })
    }

    /// What every key record's envelope must satisfy before its procedure
    /// runs: at most [`MAX_KEY_RECORD_LEN`] encoded bytes (ruling 16), a
    /// prefix that parses, and no `key_signature` unless it is a grant.
    /// Returns the record's type. Callers judge the size once more before
    /// the duplicate check, as section 5.4 step 1 orders it.
    pub(crate) fn check_envelope(record: &SignedRecord) -> Result<RecordType, Rejected> {
        check_size(record)?;
        let prefix = record.prefix()?;
        if prefix.record_type != RecordType::Grant && !record.key_signature.is_empty() {
            return Err(Malformed::UnexpectedKeySignature.into());
        }
        Ok(prefix.record_type)
    }

    pub(crate) fn store(&mut self, hash: RecordHash, record: SignedRecord, body: Body) {
        // A remembered refusal that is stored after all is forgotten.
        self.refused.forget(&hash);
        if let Body::Rotation(r) = &body {
            if r.new_epoch == self.current_epoch() + 1 {
                self.epoch_rotations.push(hash);
            } else {
                self.rivals.insert((r.new_epoch, r.signer_key_id));
            }
        }
        match &body {
            Body::Grant(g) => {
                self.groups.insert(hash, g);
                self.walks.add(Group::of(g), hash, &self.groups);
                self.grants_by_key.entry(g.key_id).or_default().push(hash);
            }
            Body::Revocation(r) => self
                .revocations_by_key
                .entry(r.revoked_key_id)
                .or_default()
                .push(hash),
            Body::Suspension(s) => self
                .suspensions_by_key
                .entry(s.key_id)
                .or_default()
                .push(hash),
            Body::Lift(l) => self
                .lifts_by_suspension
                .entry(l.suspension)
                .or_default()
                .push(hash),
            Body::Rotation(_) | Body::Wrap(_) => {}
        }
        self.entries.insert(hash, Entry { record, body });
        self.order.push(hash);
    }

    /// A Folder record other than the stored one (section 2.2).
    fn second_folder_record(&self, record: &SignedRecord) -> Rejected {
        match FolderBody::verify(record) {
            Err(e) => e,
            Ok(body) if body.folder_id != self.folder.folder_id => Malformed::OtherFolder.into(),
            // The folder ID binds the root key, so this is root's own signature.
            Ok(_) => Rejected::SignerFault {
                signer: KeyId::ROOT,
                fault: SignerFault::SecondFolderRecord,
            },
        }
    }

    fn check_folder(&self, folder_id: &FolderId) -> Result<(), Rejected> {
        if *folder_id == self.folder.folder_id {
            Ok(())
        } else {
            Err(Malformed::OtherFolder.into())
        }
    }

    /// Resolves a signer: root, or a key with a stored grant.
    fn resolve(&self, signer: &KeyId) -> Result<&SigningPublicKey, Rejected> {
        self.signing_key(signer)
            .ok_or(Rejected::Missing(Missing::Grant(*signer)))
    }

    /// Verifies the hybrid signature under `signer`'s key, after its size.
    fn verify_signature(
        &self,
        record: &SignedRecord,
        record_type: RecordType,
        signer: &KeyId,
    ) -> Result<(), Rejected> {
        let signature = signature_of(record)?;
        let pk = self.resolve(signer)?;
        if self.pre_verified.as_ref() == Some(pk) {
            return Ok(());
        }
        pk.verify(record_type.sig_label(), &record.body, &signature)
            .map_err(|_| Rejected::Forged)
    }

    /// Section 5.4, steps 1 to 9 over `view` (step 4 only when `check_epoch`:
    /// a held grant skips it, `protocol.md` 3.5 step 6); step 10 is
    /// [`FolderKeys::store`].
    pub(crate) fn verify_grant_in(
        &self,
        view: Grants<'_>,
        record: &SignedRecord,
        now_unix: u64,
        check_epoch: bool,
    ) -> Result<(GrantBody, Vec<Issue>), Rejected> {
        // Step 1: parse, sizes, ranges, the key ID's recomputation from both
        // keys, the self-grant, the minimum suite, the signature's size.
        let grant = GrantBody::parse(&record.body)?;
        if grant.suite < self.folder.minimum_suite {
            return Err(Malformed::BelowMinimumSuite.into());
        }
        let signature = signature_of(record)?;
        // Step 2: the issued key's proof of possession, before anything else
        // is judged (already verified when the bulk load's pass did).
        if self.pre_verified.is_none() {
            grant.verify_possession(record)?;
        }
        // Step 3: this folder.
        self.check_folder(&grant.folder_id)?;
        // Step 4: an epoch this verifier knows.
        if check_epoch && grant.epoch > self.current_epoch() {
            return Err(Rejected::Missing(Missing::Epoch(grant.epoch)));
        }
        // Step 5: resolve the issuer. A chain longer than 16 is judged at use,
        // as not chain-valid, not here.
        let issuer = grant.issuer_key_id;
        let issuer_pk = view
            .signing_key(&issuer)
            .ok_or(Rejected::Missing(Missing::Grant(issuer)))?;
        // Step 6: the issuer's signature. Nothing below runs without it.
        if self.pre_verified.as_ref() != Some(issuer_pk) {
            issuer_pk
                .verify(RecordType::Grant.sig_label(), &record.body, &signature)
                .map_err(|_| Rejected::Forged)?;
        }
        // Step 7: same key, another grant.
        let mut raised = Vec::new();
        if let Some((earlier_hash, earlier)) = view.of(&grant.key_id).first().copied() {
            if earlier.signing_pk != grant.signing_pk || earlier.kem_pk != grant.kem_pk {
                return Err(Rejected::ValidityOnly(Validity::KeyIdCollision {
                    key_id: grant.key_id,
                    stored_issuer: earlier.issuer_key_id,
                    new_issuer: issuer,
                }));
            }
            raised.push(Issue::SeveralGrants {
                key_id: grant.key_id,
                earlier: (*earlier_hash, earlier.issuer_key_id),
                new: (record.hash(), issuer),
            });
        }
        if !issuer.is_root() {
            let validity = KeyValidity::over(view, now_unix, false);
            // Step 8: authority, under the issuer's governing grant.
            let governing = validity
                .governing_grant(&issuer)
                .map(|(_, g)| g)
                .ok_or(Rejected::Missing(Missing::Grant(issuer)))?;
            // The governing grant is the best stored one: another grant of
            // the issuer, not held here, may give it the authority, so a
            // failure blames nobody (rulings 24 and 25).
            if !governing.may_share {
                return Err(Rejected::unprovable(
                    issuer,
                    SignerFault::NoMayShare,
                    issuer,
                ));
            }
            if governing.tier > grant.tier {
                return Err(Rejected::unprovable(
                    issuer,
                    SignerFault::TierTooHigh,
                    issuer,
                ));
            }
            // Step 9: beneath a revocation. In phases 0 to 6 the grant is
            // stored all the same, with an issue (ruling 20).
            if let Some(revocation) = self.revocation_above(view, &issuer) {
                raised.push(Issue::BeneathRevocation {
                    key_id: grant.key_id,
                    revocation,
                });
            }
        }
        Ok((grant, raised))
    }

    /// Section 5.4 step 9: when the issuer key is revoked, or none of its
    /// chains avoids a revoked key, the Revocation to name in the issue: the
    /// smallest record hash among the stored Revocations of the issuer and its
    /// ancestors. Expiry and suspension do not count; nothing is refused.
    fn revocation_above(&self, view: Grants<'_>, issuer: &KeyId) -> Option<RecordHash> {
        if self.revocation_only_validity(view, issuer) {
            return None;
        }
        let mut above = view.ancestors(issuer);
        above.insert(*issuer);
        above
            .iter()
            .filter_map(|k| self.revocations_by_key.get(k))
            .flatten()
            .min()
            .copied()
    }

    /// Whether `key` is chain-valid when only revocations count.
    fn revocation_only_validity(&self, view: Grants<'_>, key: &KeyId) -> bool {
        view.has_chain_avoiding(key, &|k| self.revoked(k))
    }

    /// Whether `signer` may sign a revocation, suspension or wrap for `key`:
    /// root, the key's issuer under one of its grants, or an ancestor of it
    /// (ruling 18). Every grant carries its key's proof of possession, so a
    /// key has only the issuers, and the ancestors through them, that its
    /// holder accepted; ancestry only grows as grants arrive, so a record
    /// entitled when stored stays entitled.
    fn entitled(&self, signer: &KeyId, key: &KeyId) -> bool {
        signer.is_root()
            || self
                .grants_for(key)
                .any(|(_, g)| g.issuer_key_id == *signer)
            || self.stored_grants().is_ancestor(signer, key)
    }

    /// The issue raised when an entitled signer is one this verifier knows
    /// to be revoked or suspended (section 7, introduction).
    fn standing(&self, signer: &KeyId, now_unix: u64) -> Option<Issue> {
        if signer.is_root() {
            return None;
        }
        // What this verifier knows, not what it applies: the stored
        // Revocations and Suspensions count here, for the issue alone.
        let v = self.validity_applying_phase_7(now_unix);
        (!v.is_chain_valid(signer) || v.under_suspension(signer))
            .then_some(Issue::SignerNotValid(*signer))
    }

    fn phase7_issues(&self, record_type: RecordType, signer: &KeyId, now_unix: u64) -> Vec<Issue> {
        let mut issues = vec![Issue::NotApplied(record_type)];
        issues.extend(self.standing(signer, now_unix));
        issues
    }

    /// Section 7.1, Rotation: step 1 (with the epoch comparison), steps 2 to 4.
    /// A rival or stale rotation (`new_epoch` at or below the current epoch)
    /// passes steps 1 to 3 and is stored as evidence (round 4 ruling, SF 9).
    fn verify_rotation(
        &self,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<(Body, Vec<Issue>), Rejected> {
        let rotation = RotationBody::parse(&record.body)?;
        self.check_folder(&rotation.folder_id)?;
        let current = self.current_epoch();
        if rotation.new_epoch > current + 1 {
            return Err(Rejected::Missing(Missing::Epoch(rotation.new_epoch - 1)));
        }
        let signer = rotation.signer_key_id;
        self.verify_signature(record, RecordType::Rotation, &signer)?;
        // Step 4, entitlement, for every rotation: a rival or stale one is
        // stored as evidence only after it passes (ruling 23).
        match rotation.cause {
            None if !signer.is_root() => {
                return Err(Rejected::SignerFault {
                    signer,
                    fault: SignerFault::EmptyCauseNotRoot,
                })
            }
            None => {}
            Some(cause) => {
                let (cause_signer, kind_ok) = match self.entries.get(&cause).map(|e| &e.body) {
                    // The Folder record is stored but is no Revocation or Suspension.
                    None if cause == self.folder_hash => (signer, false),
                    None => return Err(Rejected::Missing(Missing::Record(cause))),
                    Some(Body::Revocation(r)) => (r.signer_key_id, true),
                    Some(Body::Suspension(s)) => {
                        (s.signer_key_id, s.acting_tier == ActingTier::Nothing)
                    }
                    Some(_) => (signer, false),
                };
                if !kind_ok {
                    return Err(Rejected::SignerFault {
                        signer,
                        fault: SignerFault::CauseWrongType,
                    });
                }
                if cause_signer != signer {
                    return Err(Rejected::SignerFault {
                        signer,
                        fault: SignerFault::CauseOtherSigner,
                    });
                }
            }
        }
        // A non-root signer holds a stored grant of tier 1 or 2, validity
        // aside (ruling 21): a key granted only sealed cannot choose a
        // folder's data key. Such a grant may exist unseen here, so its
        // absence blames nobody (ruling 25).
        if !signer.is_root()
            && !self
                .grants_for(&signer)
                .any(|(_, g)| matches!(g.tier, Tier::Write | Tier::Read))
        {
            return Err(Rejected::unprovable(
                signer,
                SignerFault::SealedRotator,
                signer,
            ));
        }
        if rotation.new_epoch <= current {
            // At most one rival or stale rotation per (epoch, signer) is kept
            // as evidence (ruling 22): a key cannot fill the store with them.
            // Root's records are always accepted (ruling 23).
            if !signer.is_root() && self.rivals.contains(&(rotation.new_epoch, signer)) {
                return Err(Rejected::ValidityOnly(Validity::RivalAlreadyStored {
                    epoch: rotation.new_epoch,
                    signer,
                }));
            }
            let issues = vec![
                Issue::NotApplied(RecordType::Rotation),
                Issue::RivalRotation {
                    epoch: rotation.new_epoch,
                },
            ];
            return Ok((Body::Rotation(Box::new(rotation)), issues));
        }
        let issues = self.phase7_issues(RecordType::Rotation, &signer, now_unix);
        Ok((Body::Rotation(Box::new(rotation)), issues))
    }

    /// Section 7.1, Wrap record.
    fn verify_wrap(
        &self,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<(Body, Vec<Issue>), Rejected> {
        let wrap = WrapBody::parse(&record.body)?;
        self.check_folder(&wrap.folder_id)?;
        if wrap.epoch > self.current_epoch() {
            return Err(Rejected::Missing(Missing::Epoch(wrap.epoch)));
        }
        let signer = wrap.signer_key_id;
        self.verify_signature(record, RecordType::Wrap, &signer)?;
        if self.grants_for(&wrap.key_id).next().is_none() {
            return Err(Rejected::Missing(Missing::Grant(wrap.key_id)));
        }
        if !self
            .grants_for(&wrap.key_id)
            .any(|(_, g)| g.tier == wrap.tier)
        {
            return Err(Rejected::unprovable(
                signer,
                SignerFault::WrapTier,
                wrap.key_id,
            ));
        }
        if !self.entitled(&signer, &wrap.key_id) {
            return Err(not_entitled(signer, wrap.key_id));
        }
        // Validity, judged per grant (ruling 19): a grant at the Wrap's tier
        // that begins a valid chain, as phases 0 to 6 judge validity.
        let validity = self.validity(now_unix);
        if !self
            .grants_for(&wrap.key_id)
            .any(|(h, g)| g.tier == wrap.tier && validity.is_grant_valid(h))
        {
            return Err(Rejected::ValidityOnly(Validity::WrapToKeyWithoutChain(
                wrap.key_id,
            )));
        }
        let issues = self.phase7_issues(RecordType::Wrap, &signer, now_unix);
        Ok((Body::Wrap(Box::new(wrap)), issues))
    }

    /// Section 7.2 steps 1 to 5, and the scope rule's issue.
    fn verify_revocation(
        &self,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<(Body, Vec<Issue>), Rejected> {
        let revocation = RevocationBody::parse(&record.body)?;
        self.check_folder(&revocation.folder_id)?;
        let signer = revocation.signer_key_id;
        self.verify_signature(record, RecordType::Revocation, &signer)?;
        self.check_target(&signer, &revocation.revoked_key_id)?;
        let mut issues = self.phase7_issues(RecordType::Revocation, &signer, now_unix);
        issues.extend(self.scope_issues(&signer, &revocation.revoked_key_id, &revocation.cutoffs));
        Ok((Body::Revocation(revocation), issues))
    }

    /// Section 7.3, Suspension steps 1 to 6.
    fn verify_suspension(
        &self,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<(Body, Vec<Issue>), Rejected> {
        let suspension = SuspensionBody::parse(&record.body)?;
        self.check_folder(&suspension.folder_id)?;
        let signer = suspension.signer_key_id;
        self.verify_signature(record, RecordType::Suspension, &signer)?;
        self.check_target(&signer, &suspension.key_id)?;
        let mut issues = self.phase7_issues(RecordType::Suspension, &signer, now_unix);
        issues.extend(self.scope_issues(&signer, &suspension.key_id, &suspension.cutoffs));
        Ok((Body::Suspension(suspension), issues))
    }

    /// Section 7.3, Lift. Only root, the Suspension's own signer or an
    /// ancestor of that signer may lift it (round 4 ruling, BLOCKER 1), so the
    /// suspended key's issuer cannot lift a suspension root signed.
    fn verify_lift(
        &self,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<(Body, Vec<Issue>), Rejected> {
        let lift = LiftBody::parse(&record.body)?;
        self.check_folder(&lift.folder_id)?;
        let signer = lift.signer_key_id;
        self.verify_signature(record, RecordType::Lift, &signer)?;
        let suspender = match self.entries.get(&lift.suspension).map(|e| &e.body) {
            None if lift.suspension == self.folder_hash => {
                return Err(Rejected::SignerFault {
                    signer,
                    fault: SignerFault::LiftTarget,
                })
            }
            None => return Err(Rejected::Missing(Missing::Record(lift.suspension))),
            Some(Body::Suspension(s)) => s.signer_key_id,
            Some(_) => {
                return Err(Rejected::SignerFault {
                    signer,
                    fault: SignerFault::LiftTarget,
                })
            }
        };
        if signer != suspender && !self.entitled(&signer, &suspender) {
            return Err(not_entitled(signer, suspender));
        }
        let issues = self.phase7_issues(RecordType::Lift, &signer, now_unix);
        Ok((Body::Lift(lift), issues))
    }

    /// The target key's grant is stored, and the signer is entitled over it.
    fn check_target(&self, signer: &KeyId, key: &KeyId) -> Result<(), Rejected> {
        if self.grants_for(key).next().is_none() {
            return Err(Rejected::Missing(Missing::Grant(*key)));
        }
        if self.entitled(signer, key) {
            Ok(())
        } else {
            Err(not_entitled(*signer, *key))
        }
    }

    /// A cutoff whose writer's grant is stored and lies outside the target's
    /// subtree is ignored with an issue against the signer (section 7, scope).
    fn scope_issues(&self, signer: &KeyId, top: &KeyId, cutoffs: &[Cutoff]) -> Vec<Issue> {
        let below = self.stored_grants().beneath(top);
        cutoffs
            .iter()
            .filter(|c| {
                self.grants_for(&c.key_id).next().is_some()
                    && c.key_id != *top
                    && !below.contains(&c.key_id)
            })
            .map(|c| Issue::CutoffOutsideSubtree {
                signer: *signer,
                writer: c.key_id,
            })
            .collect()
    }

    /// Stores `grant` under `hash` without verifying anything: for the
    /// search tests, which build large or random grant graphs without
    /// signing them.
    #[cfg(test)]
    pub(crate) fn store_grant_for_test(&mut self, hash: RecordHash, grant: GrantBody) {
        let record = SignedRecord {
            body: Vec::new(),
            signature: Vec::new(),
            key_signature: Vec::new(),
        };
        self.store(hash, record, Body::Grant(Box::new(grant)));
    }

    /// See `pre_verified`: set by [`FolderKeys::load`] around one insertion.
    pub(crate) fn set_pre_verified(&mut self, pk: Option<SigningPublicKey>) {
        self.pre_verified = pk;
    }

    /// Sets ruling 23's counters, to test the quotas without storing
    /// thousands of records.
    #[cfg(test)]
    pub(crate) fn fill_quotas_for_test(
        &mut self,
        records: usize,
        bytes: usize,
        signer: Option<(KeyId, usize)>,
    ) {
        self.non_root_records = records;
        self.non_root_bytes = bytes;
        if let Some((key, n)) = signer {
            self.records_by_signer.insert(key, n);
        }
    }

    /// Whether more than one stored rotation names `epoch` (the one this
    /// verifier's chain holds and a rival or stale one): until phase 7
    /// decides the winner, nothing about that epoch's key can be judged, and
    /// a holder's unwrap or confirmation for it is the no-blame
    /// [`super::HolderError::EpochAmbiguous`] (security review, SF 4).
    #[must_use]
    pub fn epoch_ambiguous(&self, epoch: u64) -> bool {
        self.rivals
            .range((epoch, KeyId([0; 16]))..=(epoch, KeyId([0xff; 16])))
            .next()
            .is_some()
    }

    /// The validity predicates of section 5.5 at `now_unix` as phases 0 to 6
    /// judge them: stored Revocations, Suspensions and Lifts are not applied
    /// (ruling 21), so chain validity is the existence of a chain, and expiry
    /// alone limits presentability.
    #[must_use]
    pub fn validity(&self, now_unix: u64) -> KeyValidity<'_> {
        KeyValidity::over(self.stored_grants(), now_unix, false)
    }

    /// The same predicates with the stored Revocations, Suspensions and Lifts
    /// applied, as phase 7 will judge them: for the issues that report what
    /// this verifier knows of a signer and for the phase 7 rotation checks,
    /// never for whether a record is stored or a key presents.
    pub(crate) fn validity_applying_phase_7(&self, now_unix: u64) -> KeyValidity<'_> {
        KeyValidity::over(self.stored_grants(), now_unix, true)
    }
}
