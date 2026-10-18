// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The phase 7 steps of a Rotation's verification (`keys.md` section 7.1,
//! steps 5 to 7): the view, coverage judged against the rotation's own
//! declared inputs (TM-38, TM-40), and the choice between two rotations to one
//! epoch. Phase 0 stores rotations after steps 1 to 4 and does not apply them;
//! these functions are what phase 7 adds, provided now so that the coverage
//! rule is tested against the format it judges.

use std::collections::{BTreeMap, BTreeSet};

use super::phase7::ActingTier;
use super::store::{Body, FolderKeys};
use super::{Issue, Missing, Rejected, RotationBody, SignerFault};
use crate::ids::{KeyId, RecordHash};
use crate::records::validity::EffectiveTier;
use crate::suite::Tier;

impl FolderKeys {
    fn rotation(&self, hash: &RecordHash) -> Result<&RotationBody, Rejected> {
        match self.entries.get(hash).map(|e| &e.body) {
            Some(Body::Rotation(r)) => Ok(r),
            _ => Err(Rejected::Missing(Missing::Record(*hash))),
        }
    }

    /// Section 7.1 step 5: every hash in `view` names a stored Grant,
    /// Revocation, Suspension or Lift, and the view is closed under issuers:
    /// for every grant in it with a non-root issuer, the view holds a grant of
    /// the issuer that gives the issuer a chain to root within the view (round
    /// 4 ruling, SF 4).
    fn check_view(&self, r: &RotationBody) -> Result<BTreeSet<RecordHash>, Rejected> {
        let signer = r.signer_key_id;
        let view: BTreeSet<RecordHash> = r.view.iter().copied().collect();
        for h in &r.view {
            match self.entries.get(h).map(|e| &e.body) {
                None if self.contains(h) => {
                    return Err(Rejected::SignerFault {
                        signer,
                        fault: SignerFault::ViewWrongType,
                    })
                }
                None => return Err(Rejected::Missing(Missing::Record(*h))),
                Some(
                    Body::Grant(_) | Body::Revocation(_) | Body::Suspension(_) | Body::Lift(_),
                ) => {}
                Some(Body::Rotation(_) | Body::Wrap(_)) => {
                    return Err(Rejected::SignerFault {
                        signer,
                        fault: SignerFault::ViewWrongType,
                    })
                }
            }
        }
        let within = self.propagate(&|_| false, &|h| view.contains(h));
        for g in view.iter().filter_map(|h| self.grant(h)) {
            let closed = g.issuer_key_id.is_root()
                || self
                    .grants_for(&g.issuer_key_id)
                    .any(|(ih, _)| within.contains_key(ih));
            // The view is the rotation's own declaration, so an open one
            // blames its signer (ruling 26).
            if !closed {
                return Err(Rejected::SignerFault {
                    signer,
                    fault: SignerFault::ViewNotClosed,
                });
            }
        }
        Ok(view)
    }

    /// The keys a rotation must keep (section 7.1 step 6), judged per grant:
    /// every tier 1 or 2 grant in `view` that itself begins a chain lying
    /// wholly within `view` on which no key is revoked, or suspended to
    /// `none`, by a record in `view` or `cause`. Each kept key maps to the
    /// most privileged tier among its kept grants, the tier its `KeyWrap`'s aad
    /// names. A key whose only surviving chain begins with a sealed grant is
    /// not kept, and leaving it out is no fault. Expiry, `until` and every
    /// other record play no part.
    fn kept(&self, r: &RotationBody, view: &BTreeSet<RecordHash>) -> BTreeMap<KeyId, Tier> {
        let lifted: BTreeSet<RecordHash> = view
            .iter()
            .filter_map(|h| match self.entries.get(h).map(|e| &e.body) {
                Some(Body::Lift(l)) => Some(l.suspension),
                _ => None,
            })
            .collect();
        let mut excluded = BTreeSet::new();
        for h in view.iter().chain(r.cause.iter()) {
            match self.entries.get(h).map(|e| &e.body) {
                Some(Body::Revocation(rv)) => {
                    excluded.insert(rv.revoked_key_id);
                }
                Some(Body::Suspension(s))
                    if s.acting_tier == ActingTier::Nothing && !lifted.contains(h) =>
                {
                    excluded.insert(s.key_id);
                }
                _ => {}
            }
        }
        let reach = self.propagate(&|k| excluded.contains(k), &|h| view.contains(h));
        let mut kept: BTreeMap<KeyId, Tier> = BTreeMap::new();
        for g in reach.keys().filter_map(|h| self.grant(h)) {
            if matches!(g.tier, Tier::Write | Tier::Read) {
                let tier = kept.entry(g.key_id).or_insert(g.tier);
                *tier = (*tier).min(g.tier);
            }
        }
        kept
    }

    /// Section 7.1 steps 5 and 6 for a stored rotation (phase 7): the view,
    /// then coverage. The wraps must be exactly one per kept key and one for
    /// root; anything else is a lockout or leak attempt by the signer. Returns
    /// the two issues that are not faults of the signer: a wrap that reaches a
    /// key this verifier knows excluded by a record outside the view, and a
    /// chain-valid write or read key left outside the view.
    ///
    /// # Errors
    ///
    /// [`Rejected::Missing`] for a view record not held (validity-only when
    /// this store refused it under a quota), or [`Rejected::SignerFault`].
    pub fn check_rotation_coverage(
        &self,
        rotation: &RecordHash,
        now_unix: u64,
    ) -> Result<Vec<Issue>, Rejected> {
        let r = self.rotation(rotation)?;
        let signer = r.signer_key_id;
        let view = self.check_view(r).map_err(|e| self.after_refusals(e))?;
        let kept = self.kept(r, &view);
        let wrapped: BTreeSet<KeyId> = r.wraps.iter().map(|w| w.key_id).collect();
        let mut expected: BTreeSet<KeyId> = kept.keys().copied().collect();
        expected.insert(KeyId::ROOT);
        if let Some(k) = expected.difference(&wrapped).next() {
            return Err(Rejected::SignerFault {
                signer,
                fault: SignerFault::Lockout(*k),
            });
        }
        if let Some(k) = wrapped.difference(&expected).next() {
            return Err(Rejected::SignerFault {
                signer,
                fault: SignerFault::ForbiddenWrap(*k),
            });
        }
        let validity = self.validity_applying_phase_7(now_unix);
        let mut issues: Vec<Issue> = kept
            .keys()
            .filter(|k| !validity.is_chain_valid(k))
            .map(|k| Issue::EpochReachedExcludedKey {
                rotator: signer,
                key_id: *k,
            })
            .collect();
        for key in self.grants_by_key.keys() {
            let reads = matches!(
                validity.effective_tier(key),
                EffectiveTier::Write | EffectiveTier::Read
            );
            if reads && !self.grants_for(key).any(|(h, _)| view.contains(h)) {
                issues.push(Issue::AwaitsWrap {
                    rotator: signer,
                    key_id: *key,
                });
            }
        }
        Ok(issues)
    }

    /// The tier a rotation's wrap for `key` uses in its aad: 0 for root, else
    /// the most privileged tier among the key's kept grants (section 7.1 step
    /// 6). `None` for a key the rotation does not keep, or a view that does
    /// not check.
    pub(crate) fn rotation_wrap_tier(&self, r: &RotationBody, key: &KeyId) -> Option<Tier> {
        if key.is_root() {
            return Some(Tier::Root);
        }
        let view = self.check_view(r).ok()?;
        self.kept(r, &view).get(key).copied()
    }

    /// Whether `x`'s cause revokes, or suspends to `none`, `y`'s signer or an
    /// ancestor of it.
    fn cause_excludes_signer(&self, x: &RotationBody, y: &RotationBody) -> bool {
        let target = match x.cause.and_then(|c| self.entries.get(&c)).map(|e| &e.body) {
            Some(Body::Revocation(r)) => r.revoked_key_id,
            Some(Body::Suspension(s)) if s.acting_tier == ActingTier::Nothing => s.key_id,
            _ => return false,
        };
        target == y.signer_key_id || self.in_subtree(&y.signer_key_id, &target)
    }

    /// Section 7.1 step 7 (phase 7): of two stored rotations to the same
    /// epoch, the one whose `cause` excludes the other's signer (or an
    /// ancestor of it) wins; otherwise, or when each excludes the other, the
    /// numerically smaller record hash. `None` when either is not a stored
    /// rotation or their epochs differ.
    #[must_use]
    pub fn rotation_winner(&self, a: &RecordHash, b: &RecordHash) -> Option<RecordHash> {
        let (ra, rb) = (self.rotation(a).ok()?, self.rotation(b).ok()?);
        if ra.new_epoch != rb.new_epoch {
            return None;
        }
        match (
            self.cause_excludes_signer(ra, rb),
            self.cause_excludes_signer(rb, ra),
        ) {
            (true, false) => Some(*a),
            (false, true) => Some(*b),
            _ => Some(*a.min(b)),
        }
    }
}
