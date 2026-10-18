// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Grants held for one connection (`protocol.md` section 3.5 step 6): a
//! grant in a `FolderProof` whose epoch is above this verifier's current epoch
//! is verified through every step of `keys.md` 5.4 but step 4 and held, not
//! stored, until the rotation that created its epoch arrives. At the
//! handshake held grants count as stored (`keys.md` 5.5), so the validity
//! view of [`FolderKeys::validity_with`] reads both.
//!
//! The protocol crate owns the lifecycle: a scratch copy per proof (this type
//! is cheap to clone, at most [`MAX_HELD_GRANTS`] grants), kept for the
//! connection only when the proof is ACCEPTED, its grants moved to the store
//! with [`HeldGrants::take_ready`] once their epoch is known, and dropped with
//! the connection. The per-connection total across folders,
//! `MAX_HELD_GRANTS_PER_CONNECTION`, is the protocol crate's to count; one set
//! never holds more than the same 64.

use std::collections::BTreeMap;

use super::groups::GroupIndex;
use super::store::{check_size, FolderKeys};
use super::validity::{Grants, KeyValidity};
use super::{Accepted, GrantBody, Malformed, RecordType, Rejected, SignedRecord, Validity};
use crate::ids::{FolderId, KeyId, RecordHash};

/// The most grants one [`HeldGrants`] holds: `protocol.md`'s
/// `MAX_HELD_GRANTS_PER_CONNECTION`.
pub const MAX_HELD_GRANTS: usize = 64;

#[derive(Clone, Debug)]
struct Held {
    record: SignedRecord,
    body: GrantBody,
}

/// Verified grants of one folder held for one connection, in the order they
/// were held (parent first, as a `FolderProof` carries them). Only
/// [`FolderKeys::hold_grant`] adds to it, so every grant here passed every
/// step of section 5.4 but the epoch check.
#[derive(Clone, Debug)]
pub struct HeldGrants {
    folder_id: FolderId,
    grants: BTreeMap<RecordHash, Held>,
    order: Vec<RecordHash>,
    by_key: BTreeMap<KeyId, Vec<RecordHash>>,
    pub(crate) groups: GroupIndex,
}

impl HeldGrants {
    /// An empty set for `folder_id`.
    #[must_use]
    pub fn new(folder_id: FolderId) -> HeldGrants {
        HeldGrants {
            folder_id,
            grants: BTreeMap::new(),
            order: Vec::new(),
            by_key: BTreeMap::new(),
            groups: GroupIndex::default(),
        }
    }

    /// The folder these grants belong to.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }

    /// The number of held grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no grant is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Whether a grant with this record hash is held.
    #[must_use]
    pub fn contains(&self, hash: &RecordHash) -> bool {
        self.grants.contains_key(hash)
    }

    /// The held records, in the order they were held.
    pub fn records(&self) -> impl Iterator<Item = (&RecordHash, &SignedRecord)> + '_ {
        self.order
            .iter()
            .filter_map(|h| self.grants.get_key_value(h).map(|(h, g)| (h, &g.record)))
    }

    /// Removes and returns, in the order they were held, every grant whose
    /// epoch is at most `current_epoch` (the store's
    /// [`FolderKeys::current_epoch`] after a rotation arrived), for the caller
    /// to [`FolderKeys::insert`], which verifies each again.
    pub fn take_ready(&mut self, current_epoch: u64) -> Vec<SignedRecord> {
        let ready: Vec<RecordHash> = self
            .order
            .iter()
            .filter(|h| {
                self.grants
                    .get(h)
                    .is_some_and(|g| g.body.epoch <= current_epoch)
            })
            .copied()
            .collect();
        let mut out = Vec::with_capacity(ready.len());
        for hash in &ready {
            if let Some(held) = self.grants.remove(hash) {
                self.groups.remove(hash, &held.body);
                if let Some(index) = self.by_key.get_mut(&held.body.key_id) {
                    index.retain(|h| h != hash);
                }
                out.push(held.record);
            }
        }
        self.order.retain(|h| !ready.contains(h));
        self.by_key.retain(|_, v| !v.is_empty());
        out
    }

    pub(crate) fn get(&self, hash: &RecordHash) -> Option<(&RecordHash, &GrantBody)> {
        self.grants.get_key_value(hash).map(|(h, g)| (h, &g.body))
    }

    pub(crate) fn grants_for(&self, key: &KeyId) -> Vec<(&RecordHash, &GrantBody)> {
        self.by_key
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|h| self.get(h))
            .collect()
    }

    /// Fills the set with copies of `body` under made-up hashes, to test the
    /// bound without signing dozens of grants.
    #[cfg(test)]
    pub(crate) fn pad_for_test(&mut self, body: &GrantBody, n: usize) {
        for i in 0..n {
            let index = u64::try_from(i).unwrap_or(u64::MAX).to_be_bytes();
            let hash = crate::bytes::fill::<32>(&[&index, &[0xa5; 24]]);
            let record = SignedRecord {
                body: Vec::new(),
                signature: Vec::new(),
                key_signature: Vec::new(),
            };
            self.push(RecordHash(hash), record, body.clone());
        }
    }

    fn push(&mut self, hash: RecordHash, record: SignedRecord, body: GrantBody) {
        self.by_key.entry(body.key_id).or_default().push(hash);
        self.order.push(hash);
        self.groups.insert(hash, &body);
        self.grants.insert(hash, Held { record, body });
    }
}

impl FolderKeys {
    fn check_held(&self, held: &HeldGrants) -> Result<(), Rejected> {
        if held.folder_id == self.folder_id() {
            Ok(())
        } else {
            Err(Malformed::OtherFolder.into())
        }
    }

    /// Verifies a grant for holding (`protocol.md` 3.5 step 6): every step of
    /// section 5.4 but step 4, the epoch, with the issuer resolved, the
    /// same-key check made and the authority and revocation steps judged
    /// against the stored grants and `held` together. Stores nothing.
    ///
    /// # Errors
    ///
    /// [`Rejected`] as [`FolderKeys::insert`] would give it, with
    /// [`Rejected::Missing`] for an issuer neither stored nor held, and
    /// [`Malformed::OtherFolder`] for a `held` of another folder. A missing
    /// dependency the store refused under a quota is validity-only, as on
    /// insertion (rulings 24 to 26).
    pub fn verify_held_grant(
        &self,
        record: &SignedRecord,
        held: &HeldGrants,
        now_unix: u64,
    ) -> Result<GrantBody, Rejected> {
        self.check_held(held)?;
        let prefix = Self::check_envelope(record)?;
        if prefix != RecordType::Grant {
            return Err(Malformed::WrongType {
                expected: RecordType::Grant,
                found: prefix.to_wire(),
            }
            .into());
        }
        let view = Grants::with_held(self, held);
        self.verify_grant_in(view, record, now_unix, false)
            .map(|(grant, _)| grant)
            .map_err(|e| self.after_refusals(e))
    }

    /// Verifies a grant as [`FolderKeys::verify_held_grant`] does and adds it
    /// to `held`. A grant already stored or held is a duplicate, ignored
    /// before anything else, as on insertion. A full `held` refuses the grant
    /// once its body parses, before either signature is verified (quality
    /// review NIT 6), so a prover past the bound costs no verification; since
    /// nothing in the body is verified, the refusal names no key (ruling 29).
    ///
    /// # Errors
    ///
    /// As [`FolderKeys::verify_held_grant`], and [`Validity::HeldSetFull`]
    /// when `held` already holds [`MAX_HELD_GRANTS`]: an outcome for the
    /// connection, naming no key, whichever issuer the grant claims.
    pub fn hold_grant(
        &self,
        held: &mut HeldGrants,
        record: &SignedRecord,
        now_unix: u64,
    ) -> Result<Accepted, Rejected> {
        self.check_held(held)?;
        check_size(record)?;
        let hash = record.hash();
        if self.contains(&hash) || held.contains(&hash) {
            return Ok(Accepted::Duplicate(hash));
        }
        let prefix = Self::check_envelope(record)?;
        if prefix != RecordType::Grant {
            return Err(Malformed::WrongType {
                expected: RecordType::Grant,
                found: prefix.to_wire(),
            }
            .into());
        }
        if held.len() >= MAX_HELD_GRANTS {
            // A body that does not parse is malformed whatever the set
            // holds; one that parses is believed in nothing it names.
            GrantBody::parse(&record.body)?;
            return Err(Rejected::ValidityOnly(Validity::HeldSetFull));
        }
        let (grant, issues) = self
            .verify_grant_in(Grants::with_held(self, held), record, now_unix, false)
            .map_err(|e| self.after_refusals(e))?;
        held.push(hash, record.clone(), grant);
        Ok(Accepted::Stored {
            hash,
            record_type: RecordType::Grant,
            issues,
        })
    }

    /// The validity predicates of section 5.5 over the stored grants and
    /// `held` together, as the handshake judges them (`keys.md` 5.5: held
    /// grants count as stored). Revocations, suspensions and lifts are the
    /// stored ones; a `held` of another folder counts for nothing.
    #[must_use]
    pub fn validity_with<'a>(&'a self, held: &'a HeldGrants, now_unix: u64) -> KeyValidity<'a> {
        if held.folder_id == self.folder_id() {
            KeyValidity::over(Grants::with_held(self, held), now_unix, false)
        } else {
            self.validity(now_unix)
        }
    }
}
