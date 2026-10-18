// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests of [`FolderKeys`]: every rejection path of `keys.md` 5.4 and of the
//! phase 0 part of section 7, the validity predicates of 5.5 under the chain
//! ruling, the holder's side, and the phase 7 rotation checks. Test names cite
//! the TM numbers they carry.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::unused_self,
    clippy::too_many_lines,
    reason = "test code: short key names mirror the spec's examples"
)]

use prost::Message as _;

use super::folder::tests::{fixed_rng, new_folder};
use super::phase7::{ActingTier, Cutoff, KeyWrapEntry};
use super::*;
use crate::derive;
use crate::epoch::{Confirm, LadderLink};
use crate::ids::DeviceId;
use crate::rng::RandomFill;
use crate::secret::{DataKey, Seed};
use crate::suite::Tier;
use crate::wrap::{wrap_data_key, WrapAad};

pub(crate) const NOW: u64 = 1_800_000_000;

pub(crate) fn set(byte: u8) -> KeyPairSet {
    KeyPairSet::from_seed(&Seed::from_bytes([byte; 32])).unwrap()
}

pub(crate) fn id(k: &KeyPairSet) -> KeyId {
    k.public().key_id(Suite::ONE)
}

/// The root of [`world`], derived again from its phrase and nonce.
pub(crate) fn root_set() -> KeyPairSet {
    let ms = crate::secret::MasterSecret::from_bytes([1; 32]);
    KeyPairSet::from_seed(&derive::root_seed(&ms, &derive::FolderNonce([3; 32]))).unwrap()
}

/// `record`'s grant body changed by `change`, with `holder`'s proof of
/// possession and `issuer`'s signature made over the new body.
pub(crate) fn resigned(
    record: &SignedRecord,
    holder: &KeyPairSet,
    issuer: &KeyPairSet,
    change: impl FnOnce(&mut wire::Grant),
) -> SignedRecord {
    let mut g = wire::Grant::decode(record.body.as_slice()).unwrap();
    change(&mut g);
    let body = g.encode_to_vec();
    let key_signature = holder
        .sign_deterministic(labels::SIG_GRANT_POP, &body)
        .unwrap()
        .as_bytes()
        .to_vec();
    let signature = issuer
        .sign_deterministic(labels::SIG_GRANT, &body)
        .unwrap()
        .as_bytes()
        .to_vec();
    SignedRecord {
        body,
        signature,
        key_signature,
    }
}

/// A folder, its root, its epoch 1 key and its verified set.
pub(crate) struct World {
    pub(crate) folder: NewFolder,
    pub(crate) dk1: DataKey,
    pub(crate) keys: FolderKeys,
}

pub(crate) fn world() -> World {
    let (folder, dk1) = new_folder(1);
    let keys = FolderKeys::new(&folder.body.folder_id, folder.record.clone()).unwrap();
    World { folder, dk1, keys }
}

impl World {
    pub(crate) fn root(&self) -> &KeyPairSet {
        &self.folder.root
    }

    pub(crate) fn folder_id(&self) -> FolderId {
        self.folder.body.folder_id
    }

    /// A grant from `issuer` (key ID `issuer_id`) to `to`.
    pub(crate) fn grant_from(
        &self,
        issuer: &KeyPairSet,
        issuer_id: KeyId,
        to: &KeyPairSet,
        tier: Tier,
        may_share: bool,
        expires_at: u64,
    ) -> SignedRecord {
        let request = GrantRequest {
            folder_id: self.folder_id(),
            recipient: to,
            tier,
            may_share,
            expires_at,
            epoch: 1,
            data_key: tier.can_read().then_some(&self.dk1),
            issued_at: 7,
            issuer_device_id: Some(DeviceId([9; 32])),
        };
        issue_grant_deterministic(issuer, issuer_id, &request, &mut fixed_rng(5))
            .unwrap()
            .0
    }

    pub(crate) fn root_grant(&self, to: &KeyPairSet, tier: Tier, may_share: bool) -> SignedRecord {
        self.grant_from(self.root(), KeyId::ROOT, to, tier, may_share, 0)
    }

    pub(crate) fn rejects(&mut self, record: &SignedRecord) -> Rejected {
        self.keys.insert(record, NOW).unwrap_err()
    }

    pub(crate) fn add(&mut self, record: &SignedRecord) -> Vec<Issue> {
        match self.keys.insert(record, NOW).unwrap() {
            Accepted::Stored { issues, .. } => issues,
            Accepted::Duplicate(_) => panic!("duplicate"),
        }
    }

    pub(crate) fn sign(
        &self,
        signer: &KeyPairSet,
        record_type: RecordType,
        body: Vec<u8>,
    ) -> SignedRecord {
        sign_record_deterministic(signer, record_type, body).unwrap()
    }

    pub(crate) fn revocation(
        &self,
        signer: &KeyPairSet,
        signer_id: KeyId,
        revoked: KeyId,
        cutoffs: Vec<Cutoff>,
    ) -> SignedRecord {
        let body = RevocationBody {
            suite: Suite::ONE,
            folder_id: self.folder_id(),
            revoked_key_id: revoked,
            signer_key_id: signer_id,
            cutoffs,
            issued_at: 3,
        };
        self.sign(signer, RecordType::Revocation, body.encode())
    }

    pub(crate) fn suspension(
        &self,
        signer: &KeyPairSet,
        signer_id: KeyId,
        key: KeyId,
        acting_tier: ActingTier,
        until: u64,
    ) -> SignedRecord {
        let body = SuspensionBody {
            suite: Suite::ONE,
            folder_id: self.folder_id(),
            key_id: key,
            acting_tier,
            until,
            signer_key_id: signer_id,
            issued_at: 3,
            cutoffs: vec![],
        };
        self.sign(signer, RecordType::Suspension, body.encode())
    }

    pub(crate) fn lift(
        &self,
        signer: &KeyPairSet,
        signer_id: KeyId,
        suspension: RecordHash,
    ) -> SignedRecord {
        let body = LiftBody {
            suite: Suite::ONE,
            folder_id: self.folder_id(),
            suspension,
            signer_key_id: signer_id,
            issued_at: 4,
        };
        self.sign(signer, RecordType::Lift, body.encode())
    }

    pub(crate) fn wrap_record(
        &self,
        signer: &KeyPairSet,
        signer_id: KeyId,
        to: &KeyPairSet,
        tier: Tier,
        epoch: u64,
    ) -> SignedRecord {
        let aad = WrapAad {
            folder_id: self.folder_id(),
            key_id: id(to),
            tier,
            epoch,
        };
        let wrapped = wrap_data_key(&to.public().kem, &aad, &self.dk1, &mut fixed_rng(2)).unwrap();
        let body = WrapBody {
            suite: Suite::ONE,
            folder_id: self.folder_id(),
            key_id: id(to),
            epoch,
            wrapped_data_key: wrapped,
            signer_key_id: signer_id,
            issued_at: 2,
            tier,
        };
        self.sign(signer, RecordType::Wrap, body.encode())
    }

    /// A rotation to `new_epoch` under `dk2`, wrapping to each `(key, set, tier)`.
    #[allow(clippy::too_many_arguments, reason = "a test builder")]
    pub(crate) fn rotation(
        &self,
        signer: &KeyPairSet,
        signer_id: KeyId,
        dk2: &DataKey,
        recipients: &[(KeyId, &KeyPairSet, Tier)],
        cause: Option<RecordHash>,
        view: Vec<RecordHash>,
        new_epoch: u64,
    ) -> SignedRecord {
        let folder_id = self.folder_id();
        let wraps = recipients
            .iter()
            .map(|(k, s, t)| KeyWrapEntry {
                key_id: *k,
                wrapped_data_key: wrap_data_key(
                    &s.public().kem,
                    &WrapAad {
                        folder_id,
                        key_id: *k,
                        tier: *t,
                        epoch: new_epoch,
                    },
                    dk2,
                    &mut fixed_rng(4),
                )
                .unwrap(),
            })
            .collect();
        let body = RotationBody {
            suite: Suite::ONE,
            folder_id,
            new_epoch,
            signer_key_id: signer_id,
            wraps,
            ladder: LadderLink::seal(dk2, new_epoch, &folder_id, &self.dk1, &mut fixed_rng(6))
                .unwrap(),
            cause,
            issued_at: 8,
            view,
            confirm: dk2.confirm(),
        };
        self.sign(signer, RecordType::Rotation, body.encode())
    }
}

fn with_body(record: &SignedRecord, change: impl FnOnce(&mut wire::Grant)) -> Vec<u8> {
    let mut g = wire::Grant::decode(record.body.as_slice()).unwrap();
    change(&mut g);
    g.encode_to_vec()
}

#[test]
fn folder_keys_start_from_a_verified_folder_record() {
    let w = world();
    assert_eq!(w.keys.len(), 1);
    let empty = w.keys.is_empty();
    assert!(!empty);
    assert_eq!(w.keys.current_epoch(), 1);
    assert_eq!(w.keys.folder_id(), w.folder_id());
    assert_eq!(w.keys.folder(), &w.folder.body);
    assert!(w.keys.contains(&w.folder.record.hash()));
    assert_eq!(w.keys.get(&w.folder.record.hash()), Some(&w.folder.record));
    assert_eq!(w.keys.get(&RecordHash([0; 32])), None);
    assert_eq!(w.keys.records().count(), 1);
    assert_eq!(
        w.keys.signing_key(&KeyId::ROOT),
        Some(&w.folder.body.root_signing_pk)
    );
    assert_eq!(w.keys.epoch_confirm(1), Some(w.folder.body.confirm));
    assert_eq!(
        FolderKeys::new(&FolderId([0; 32]), w.folder.record.clone()).unwrap_err(),
        Rejected::Malformed(Malformed::OtherFolder)
    );
    let (other, _) = new_folder(2);
    let forged = SignedRecord {
        body: w.folder.record.body.clone(),
        signature: other.record.signature.clone(),
        key_signature: Vec::new(),
    };
    assert_eq!(
        FolderKeys::new(&w.folder_id(), forged).unwrap_err(),
        Rejected::Forged
    );
}

#[test]
fn a_second_folder_record_is_a_signer_fault_against_root() {
    let mut w = world();
    assert_eq!(
        w.keys.insert(&w.folder.record.clone(), NOW).unwrap(),
        Accepted::Duplicate(w.folder.record.hash())
    );
    let mut body = w.folder.body.clone();
    body.created_at += 1;
    let second = w.sign(w.root(), RecordType::Folder, body.encode());
    assert_eq!(
        w.rejects(&second),
        Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::SecondFolderRecord
        }
    );
    let forged = SignedRecord {
        body: second.body.clone(),
        signature: w.folder.record.signature.clone(),
        key_signature: Vec::new(),
    };
    assert_eq!(w.rejects(&forged), Rejected::Forged);
    let (other, _) = new_folder(3);
    assert_eq!(
        w.rejects(&other.record),
        Rejected::Malformed(Malformed::OtherFolder)
    );
    assert_eq!(w.keys.len(), 1);
}

#[test]
fn production_signing_is_hedged() {
    // The same body signed twice on the production path: the ML-DSA halves
    // differ (fresh randomness each time), the Ed25519 halves do not, and both verify.
    let w = world();
    let a = set(10);
    let request = GrantRequest {
        folder_id: w.folder_id(),
        recipient: &a,
        tier: Tier::Read,
        may_share: false,
        expires_at: 0,
        epoch: 1,
        data_key: Some(&w.dk1),
        issued_at: 1,
        issuer_device_id: None,
    };
    let mut counter = 0u8;
    let mut rng = |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            counter = counter.wrapping_add(1);
            *b = counter;
        }
    };
    let issued = issue_grant(w.root(), KeyId::ROOT, &request, &mut rng)
        .unwrap()
        .0;
    let resign = |rng: &mut RandomFill<'_>| SignedRecord {
        signature: w
            .root()
            .sign(labels::SIG_GRANT, &issued.body, rng)
            .unwrap()
            .as_bytes()
            .to_vec(),
        key_signature: a
            .sign(labels::SIG_GRANT_POP, &issued.body, rng)
            .unwrap()
            .as_bytes()
            .to_vec(),
        ..issued.clone()
    };
    let first = resign(&mut rng);
    let second = resign(&mut rng);
    assert_eq!(first.body, second.body);
    for (x, y) in [
        (&first.signature, &second.signature),
        (&first.key_signature, &second.key_signature),
    ] {
        assert_eq!(x[..64], y[..64], "Ed25519 is deterministic");
        assert_ne!(x[64..], y[64..], "ML-DSA is hedged");
    }
    let mut keys = w.keys.clone();
    assert!(matches!(
        keys.insert(&first, NOW),
        Ok(Accepted::Stored { .. })
    ));
    assert_eq!(
        keys.insert(&second, NOW),
        Ok(Accepted::Duplicate(first.hash()))
    );
    let pk = &w.folder.body.root_signing_pk;
    for r in [&first, &second] {
        assert!(pk
            .verify(
                labels::SIG_GRANT,
                &r.body,
                &HybridSignature::from_bytes(&r.signature).unwrap()
            )
            .is_ok());
    }
}

#[test]
fn tm_9_grants_chain_to_root_and_are_stored_once() {
    let mut w = world();
    let a = set(10);
    let g = w.root_grant(&a, Tier::Write, true);
    let issues = w.add(&g);
    assert_eq!(issues.len(), 0);
    assert!(w.keys.contains(&g.hash()));
    assert_eq!(
        w.keys.insert(&g, NOW).unwrap(),
        Accepted::Duplicate(g.hash())
    );
    // The same body under another (valid) signature is the same record.
    let resigned_root = SignedRecord {
        body: g.body.clone(),
        signature: w
            .root()
            .sign(labels::SIG_GRANT, &g.body, &mut fixed_rng(9))
            .unwrap()
            .as_bytes()
            .to_vec(),
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.keys.insert(&resigned_root, NOW).unwrap(),
        Accepted::Duplicate(g.hash())
    );
    // A child of a may_share write key.
    let b = set(11);
    let gb = w.grant_from(&a, id(&a), &b, Tier::Read, false, 0);
    w.add(&gb);
    assert_eq!(w.keys.grants_for(&id(&b)).count(), 1);
    assert_eq!(w.keys.signing_key(&id(&b)), Some(&b.public().signing));
    let order: Vec<RecordHash> = w.keys.records().map(|(h, _)| *h).collect();
    assert_eq!(order, vec![w.folder.record.hash(), g.hash(), gb.hash()]);
    assert!(w.keys.in_subtree(&id(&b), &id(&a)));
    assert!(!w.keys.in_subtree(&id(&a), &id(&b)));
}

#[test]
fn grant_steps_1_to_3_parse_possession_and_folder() {
    let mut w = world();
    let a = set(10);
    let g = w.root_grant(&a, Tier::Write, true);
    let bad_size = SignedRecord {
        body: with_body(&g, |b| b.kem_pk.truncate(10)),
        signature: g.signature.clone(),
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&bad_size),
        Rejected::Malformed(Malformed::FieldSize("kem_pk"))
    );
    let bad_id = SignedRecord {
        body: with_body(&g, |b| b.key_id[3] ^= 1),
        signature: g.signature.clone(),
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&bad_id),
        Rejected::Malformed(Malformed::KeyIdMismatch)
    );
    let zero_id = SignedRecord {
        body: with_body(&g, |b| b.key_id = vec![0; 16]),
        signature: g.signature.clone(),
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&zero_id),
        Rejected::Malformed(Malformed::RootKeyId)
    );
    // The proof of possession is judged right after the parse: missing, or by another key, is forged.
    let no_pop = SignedRecord {
        key_signature: Vec::new(),
        ..g.clone()
    };
    assert_eq!(w.rejects(&no_pop), Rejected::Forged);
    let other_pop = resigned(&g, &set(77), w.root(), |_| {});
    assert_eq!(w.rejects(&other_pop), Rejected::Forged);
    let short_sig = SignedRecord {
        body: g.body.clone(),
        signature: vec![0; 64],
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&short_sig),
        Rejected::Malformed(Malformed::SignatureSize(64))
    );
    // Another folder's ID, signed by this folder's root, with a fresh proof.
    let other = resigned(&g, &a, w.root(), |b| b.folder_id = vec![5; 32]);
    assert_eq!(
        w.rejects(&other),
        Rejected::Malformed(Malformed::OtherFolder)
    );
    let suite2 = SignedRecord {
        body: with_body(&g, |b| b.suite = 2),
        signature: g.signature.clone(),
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&suite2),
        Rejected::ValidityOnly(Validity::UnimplementedSuite(2))
    );
    assert_eq!(w.keys.len(), 1);
}

#[test]
fn grant_step_4_epoch_and_step_5_issuer() {
    let mut w = world();
    let a = set(10);
    let g = w.root_grant(&a, Tier::Write, true);
    let ahead = resigned(&g, &a, w.root(), |b| b.epoch = 2);
    assert_eq!(w.rejects(&ahead), Rejected::Missing(Missing::Epoch(2)));
    let b = set(11);
    let orphan = w.grant_from(&a, id(&a), &b, Tier::Read, false, 0);
    assert_eq!(
        w.rejects(&orphan),
        Rejected::Missing(Missing::Grant(id(&a)))
    );
}

/// A chain of `n` write `may_share` keys from root; returns the last key and its ID.
pub(crate) fn chain_of(w: &mut World, n: u8, first_seed: u8) -> (KeyPairSet, KeyId) {
    let mut issuer = root_set();
    let mut issuer_id = KeyId::ROOT;
    for i in 0..n {
        let next = set(first_seed + i);
        let g = w.grant_from(&issuer, issuer_id, &next, Tier::Write, true, 0);
        w.add(&g);
        issuer_id = id(&next);
        issuer = next;
    }
    (issuer, issuer_id)
}

#[test]
fn chain_ruling_a_17_deep_chain_is_stored_but_not_chain_valid() {
    let mut w = world();
    let (sixteenth, sixteenth_id) = chain_of(&mut w, 16, 100);
    let v = w.keys.validity(NOW);
    assert!(v.is_presentable(&sixteenth_id));
    assert_eq!(v.canonical_chain(&sixteenth_id).len(), 16);
    // The 17th grant is stored (depth is judged at use, not at storage) and is not chain-valid.
    let last = set(200);
    let deep = w.grant_from(&sixteenth, sixteenth_id, &last, Tier::Write, true, 0);
    assert_eq!(w.add(&deep).len(), 0);
    let v = w.keys.validity(NOW);
    assert!(!v.is_grant_valid(&deep.hash()));
    assert!(!v.is_chain_valid(&id(&last)));
    assert_eq!(v.effective_tier(&id(&last)), EffectiveTier::Nothing);
    // A shorter path makes the same key valid: a second grant from root.
    w.add(&w.root_grant(&last, Tier::Read, false));
    let v = w.keys.validity(NOW);
    assert!(v.is_chain_valid(&id(&last)));
    assert_eq!(
        v.governing_grant(&id(&last)).unwrap().1.tier,
        Tier::Read,
        "the deep write grant cannot govern"
    );
}

#[test]
fn chain_ruling_a_self_grant_is_malformed() {
    let mut w = world();
    let k = set(10);
    w.add(&w.root_grant(&k, Tier::Write, true));
    let own = w.grant_from(&k, id(&k), &k, Tier::Write, true, 0);
    assert_eq!(w.rejects(&own), Rejected::Malformed(Malformed::SelfIssued));
}

#[test]
fn chain_ruling_a_descendant_regrant_neither_validates_nor_escapes_expiry() {
    let mut w = world();
    let k = set(10);
    let d = set(11);
    let gk = w.grant_from(w.root(), KeyId::ROOT, &k, Tier::Write, true, NOW + 100);
    w.add(&gk);
    w.add(&w.grant_from(&k, id(&k), &d, Tier::Write, true, 0));
    // D grants its own issuer a grant without expiry, which would outrank K's own.
    let regrant = w.grant_from(&d, id(&d), &k, Tier::Write, true, 0);
    let issues = w.add(&regrant);
    assert_eq!(issues.len(), 1, "a second grant for K");
    let v = w.keys.validity(NOW);
    assert!(
        !v.is_grant_valid(&regrant.hash()),
        "its only path visits K twice"
    );
    assert_eq!(v.governing_grant(&id(&k)).map(|(h, _)| *h), Some(gk.hash()));
    assert_eq!(v.canonical_chain(&id(&k)).len(), 1);
    // At expiry K can no longer present, and neither can D beneath it.
    let later = w.keys.validity(NOW + 100);
    assert!(!later.is_presentable(&id(&k)));
    assert!(!later.is_presentable(&id(&d)));
    assert!(
        later.is_chain_valid(&id(&d)),
        "expiry is not part of chain validity"
    );
}

#[test]
fn chain_ruling_a_regrant_through_another_branch_is_valid_without_the_key() {
    // K from root; X from root; X grants K again. The second grant's path
    // (K, X, root) visits no key twice, so it is valid; the governing grant is
    // the better one by the order.
    let mut w = world();
    let k = set(10);
    let x = set(11);
    let gk = w.grant_from(w.root(), KeyId::ROOT, &k, Tier::Read, false, 0);
    w.add(&gk);
    w.add(&w.root_grant(&x, Tier::Write, true));
    let gx = w.grant_from(&x, id(&x), &k, Tier::Write, false, 0);
    w.add(&gx);
    let v = w.keys.validity(NOW);
    assert!(v.is_grant_valid(&gk.hash()) && v.is_grant_valid(&gx.hash()));
    assert_eq!(v.governing_grant(&id(&k)).map(|(h, _)| *h), Some(gx.hash()));
    // The canonical chain is the shortest (the root grant); the best
    // presentable chain starts with the governing grant.
    assert_eq!(v.canonical_chain(&id(&k)).len(), 1);
    assert_eq!(v.presentable_chain(&id(&k)).len(), 2);
    assert_eq!(*v.presentable_chain(&id(&k))[0].0, gx.hash());
    assert_eq!(v.presentable_tier(&id(&k)), EffectiveTier::Write);
    assert_eq!(v.effective_tier(&id(&k)), EffectiveTier::Write);
}

#[test]
fn chain_ruling_a_looping_shortest_path_falls_back_to_one_without_the_key() {
    // K from root; D from K (level 2); X from root, Y from X, D from Y (level 3);
    // D re-grants K. The re-grant's shortest path runs through D's grant from K
    // and so back to K; without K, D's grant from Y carries it at length 4.
    let mut w = world();
    let (k, d, x, y) = (set(10), set(11), set(12), set(13));
    w.add(&w.root_grant(&k, Tier::Write, true));
    w.add(&w.grant_from(&k, id(&k), &d, Tier::Write, true, 0));
    let gx = w.root_grant(&x, Tier::Write, true);
    w.add(&gx);
    let gy = w.grant_from(&x, id(&x), &y, Tier::Write, true, 0);
    w.add(&gy);
    let gdy = w.grant_from(&y, id(&y), &d, Tier::Write, true, 0);
    w.add(&gdy);
    let regrant = w.grant_from(&d, id(&d), &k, Tier::Read, false, 0);
    w.add(&regrant);
    let v = w.keys.validity_applying_phase_7(NOW);
    assert!(v.is_grant_valid(&regrant.hash()));
    assert_eq!(
        v.governing_grant(&id(&k)).unwrap().1.tier,
        Tier::Write,
        "the root grant still governs"
    );
    let chains: Vec<Vec<RecordHash>> = w
        .keys
        .stored_grants()
        .chains_of(&id(&k), &|_, _| true)
        .into_iter()
        .map(|path| path.into_iter().copied().collect())
        .collect();
    assert!(chains.contains(&vec![regrant.hash(), gdy.hash(), gy.hash(), gx.hash()]));
    // Revoke X: the re-grant's only path left goes through K, so it begins no valid chain.
    w.add(&w.revocation(w.root(), KeyId::ROOT, id(&x), vec![]));
    let v = w.keys.validity_applying_phase_7(NOW);
    assert!(!v.is_grant_valid(&regrant.hash()));
    assert!(!v.is_grant_valid(&gdy.hash()));
    assert!(v.is_chain_valid(&id(&k)) && v.is_chain_valid(&id(&d)));
    assert!(!v.under_suspension(&id(&x)) && !v.is_chain_valid(&id(&x)));
}

#[test]
fn chain_ruling_ties_are_broken_by_the_smaller_record_hash() {
    let w = world();
    let k = set(10);
    let g1 = w.grant_from(w.root(), KeyId::ROOT, &k, Tier::Write, true, 0);
    // The same tier, may_share and expiry; another issued_at, so another hash.
    let request = GrantRequest {
        folder_id: w.folder_id(),
        recipient: &k,
        tier: Tier::Write,
        may_share: true,
        expires_at: 0,
        epoch: 1,
        data_key: Some(&w.dk1),
        issued_at: 99,
        issuer_device_id: Some(DeviceId([9; 32])),
    };
    let (g2, _) =
        issue_grant_deterministic(w.root(), KeyId::ROOT, &request, &mut fixed_rng(5)).unwrap();
    let smaller = g1.hash().min(g2.hash());
    let c = set(11);
    let gc = w.grant_from(&k, id(&k), &c, Tier::Read, false, 0);
    // A child of K takes the same parent whichever grant was stored first.
    for order in [[&g1, &g2], [&g2, &g1]] {
        let mut v = world();
        for g in order {
            v.add(g);
        }
        v.add(&gc);
        let validity = v.keys.validity(NOW);
        assert_eq!(
            validity.governing_grant(&id(&k)).map(|(h, _)| *h),
            Some(smaller)
        );
        let chain: Vec<RecordHash> = validity
            .canonical_chain(&id(&c))
            .iter()
            .map(|(h, _)| **h)
            .collect();
        assert_eq!(chain, vec![gc.hash(), smaller]);
    }
}

#[test]
fn grant_step_6_the_signature_is_judged_before_authority() {
    let mut w = world();
    let reader = set(10);
    w.add(&w.root_grant(&reader, Tier::Read, true));
    let child = set(11);
    // A read key granting write lacks the authority (step 8), but the
    // signature is another key's, so it is forged: the signature first.
    let mut g = w.grant_from(&reader, id(&reader), &child, Tier::Write, false, 0);
    g.signature = set(12)
        .sign_deterministic(labels::SIG_GRANT, &g.body)
        .unwrap()
        .as_bytes()
        .to_vec();
    assert_eq!(w.rejects(&g), Rejected::Forged);
    // Signed by the reader, it is refused for want of authority, and blames
    // nobody: another grant of the reader may exist unseen (ruling 25).
    let g = w.grant_from(&reader, id(&reader), &child, Tier::Write, false, 0);
    assert_eq!(
        w.rejects(&g),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&reader),
            fault: SignerFault::TierTooHigh,
            absent_grant_of: id(&reader),
        })
    );
}

#[test]
fn grant_step_7_a_second_grant_for_one_key_is_stored_beside_with_an_issue() {
    let mut w = world();
    let a = set(10);
    let ga = w.root_grant(&a, Tier::Read, false);
    w.add(&ga);
    let ga2 = w.root_grant(&a, Tier::Write, true);
    let issues = w.add(&ga2);
    assert_eq!(
        issues,
        vec![Issue::SeveralGrants {
            key_id: id(&a),
            earlier: (ga.hash(), KeyId::ROOT),
            new: (ga2.hash(), KeyId::ROOT)
        }]
    );
    assert_eq!(w.keys.grants_for(&id(&a)).count(), 2);
    let v = w.keys.validity(NOW);
    let (gov, body) = v.governing_grant(&id(&a)).unwrap();
    assert_eq!(
        *gov,
        ga2.hash(),
        "the governing grant is the most privileged"
    );
    assert_eq!(body.tier, Tier::Write);
    assert_eq!(v.effective_tier(&id(&a)), EffectiveTier::Write);
}

#[test]
fn grant_step_7_a_key_id_collision_is_refused_as_a_validity_failure() {
    let mut w = world();
    let a = set(10);
    let b = set(11);
    let gb = w.root_grant(&b, Tier::Read, false);
    w.add(&gb);
    // Simulate a 128-bit collision: the stored grant for B claims A's key ID.
    let hash = gb.hash();
    if let Some(store::Entry {
        body: store::Body::Grant(g),
        ..
    }) = w.keys.entries.get_mut(&hash)
    {
        g.key_id = id(&a);
    }
    w.keys.grants_by_key.insert(id(&a), vec![hash]);
    let ga = w.root_grant(&a, Tier::Read, false);
    assert_eq!(
        w.rejects(&ga),
        Rejected::ValidityOnly(Validity::KeyIdCollision {
            key_id: id(&a),
            stored_issuer: KeyId::ROOT,
            new_issuer: KeyId::ROOT,
        })
    );
}

#[test]
fn grant_step_8_authority_needs_may_share_and_a_tier_at_or_above() {
    let mut w = world();
    let no_share = set(10);
    w.add(&w.root_grant(&no_share, Tier::Write, false));
    let child = set(11);
    let g = w.grant_from(&no_share, id(&no_share), &child, Tier::Read, false, 0);
    assert_eq!(
        w.rejects(&g),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&no_share),
            fault: SignerFault::NoMayShare,
            absent_grant_of: id(&no_share),
        })
    );
    let sealed = set(12);
    w.add(&w.root_grant(&sealed, Tier::Sealed, true));
    let g = w.grant_from(&sealed, id(&sealed), &child, Tier::Read, false, 0);
    assert_eq!(
        w.rejects(&g),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&sealed),
            fault: SignerFault::TierTooHigh,
            absent_grant_of: id(&sealed),
        })
    );
    // Sealed may issue sealed; read may issue read and sealed.
    w.add(&w.grant_from(&sealed, id(&sealed), &child, Tier::Sealed, false, 0));
    let reader = set(13);
    w.add(&w.root_grant(&reader, Tier::Read, true));
    w.add(&w.grant_from(&reader, id(&reader), &set(14), Tier::Read, false, 0));
    w.add(&w.grant_from(&reader, id(&reader), &set(15), Tier::Sealed, false, 0));
}

#[test]
fn tm_19_grant_step_9_beneath_a_known_revocation_is_stored_with_an_issue() {
    // Ruling 20: in phases 0 to 6 nothing is refused for lying beneath a
    // Revocation; the grant is stored and forwarded with an issue naming it.
    let mut w = world();
    let a = set(10);
    w.add(&w.root_grant(&a, Tier::Write, true));
    let kept = set(11);
    let cutoff = Cutoff {
        key_id: id(&kept),
        device_id: DeviceId([1; 32]),
        seq: 0,
        head_hash: None,
    };
    let rev = w.revocation(w.root(), KeyId::ROOT, id(&a), vec![cutoff]);
    w.add(&rev);
    for (seed, tier) in [(12, Tier::Read), (11, Tier::Write)] {
        let to = set(seed);
        let g = w.grant_from(&a, id(&a), &to, tier, false, 0);
        assert_eq!(
            w.add(&g),
            vec![Issue::BeneathRevocation {
                key_id: id(&to),
                revocation: rev.hash()
            }]
        );
    }
    // A grant beneath the revoked key's child is named the same Revocation.
    let deeper = set(13);
    let b = set(14);
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Write, true, 0));
    let g = w.grant_from(&b, id(&b), &deeper, Tier::Read, false, 0);
    assert_eq!(
        w.add(&g),
        vec![Issue::BeneathRevocation {
            key_id: id(&deeper),
            revocation: rev.hash()
        }]
    );
    // Not applied in phases 0 to 6 (ruling 21); phase 7 will apply it.
    assert!(w.keys.validity(NOW).is_chain_valid(&id(&kept)));
    assert!(!w
        .keys
        .validity_applying_phase_7(NOW)
        .is_chain_valid(&id(&kept)));
}

#[test]
fn ruling_20_the_stored_set_does_not_depend_on_arrival_order() {
    // R from root, A from R, W from A; root revokes R. Whichever arrives
    // first, every peer ends with the same four records stored.
    let base = world();
    let (r, a, wk) = (set(10), set(11), set(12));
    let gr = base.root_grant(&r, Tier::Write, true);
    let ga = base.grant_from(&r, id(&r), &a, Tier::Write, true, 0);
    let gw = base.grant_from(&a, id(&a), &wk, Tier::Read, false, 0);
    let rev = base.revocation(base.root(), KeyId::ROOT, id(&r), vec![]);
    let mut stored = Vec::new();
    for order in [
        [&gr, &ga, &gw, &rev],
        [&gr, &rev, &ga, &gw],
        [&gr, &ga, &rev, &gw],
    ] {
        let mut w = world();
        for record in order {
            w.add(record);
        }
        let mut hashes: Vec<RecordHash> = w.keys.records().map(|(h, _)| *h).collect();
        hashes.sort_unstable();
        stored.push(hashes);
    }
    assert!(stored.windows(2).all(|p| p[0] == p[1]));
    assert_eq!(stored[0].len(), 5);
}

#[test]
fn tm_19_validity_cascades_through_revocation_and_suspension() {
    let mut w = world();
    let a = set(10);
    let b = set(11);
    let c = set(12);
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Write, true, 0));
    w.add(&w.grant_from(&b, id(&b), &c, Tier::Write, false, 0));
    let v = w.keys.validity_applying_phase_7(NOW);
    assert!(v.is_chain_valid(&id(&c)));
    assert_eq!(v.canonical_chain(&id(&c)).len(), 3);
    assert_eq!(v.effective_tier(&id(&c)), EffectiveTier::Write);
    assert!(v.may_issue(&id(&b), Tier::Read));
    assert!(!v.may_issue(&id(&c), Tier::Read), "no may_share");
    assert!(v.may_issue(&KeyId::ROOT, Tier::Write));
    // A suspends B acting as read: C acts as read, B may not issue.
    let s = w.suspension(&a, id(&a), id(&b), ActingTier::Read, 0);
    w.add(&s);
    let v = w.keys.validity_applying_phase_7(NOW);
    assert!(v.is_chain_valid(&id(&c)));
    assert_eq!(v.effective_tier(&id(&c)), EffectiveTier::Read);
    assert!(v.under_suspension(&id(&c)));
    assert!(!v.may_issue(&id(&b), Tier::Read));
    // A second suspension acting as sealed lowers C further; lifts end both.
    let sealed = w.suspension(&a, id(&a), id(&b), ActingTier::Sealed, 0);
    w.add(&sealed);
    assert_eq!(
        w.keys
            .validity_applying_phase_7(NOW)
            .effective_tier(&id(&c)),
        EffectiveTier::Sealed
    );
    w.add(&w.lift(&a, id(&a), sealed.hash()));
    w.add(&w.lift(&a, id(&a), s.hash()));
    assert!(w.keys.is_lifted(&s.hash()));
    assert_eq!(
        w.keys
            .validity_applying_phase_7(NOW)
            .effective_tier(&id(&c)),
        EffectiveTier::Write
    );
    // Suspension to none, timed: C is not chain-valid until it passes.
    let none = w.suspension(&a, id(&a), id(&b), ActingTier::Nothing, NOW + 10);
    w.add(&none);
    assert!(!w
        .keys
        .validity_applying_phase_7(NOW)
        .is_chain_valid(&id(&c)));
    assert_eq!(
        w.keys
            .validity_applying_phase_7(NOW)
            .effective_tier(&id(&c)),
        EffectiveTier::Nothing
    );
    assert!(w
        .keys
        .validity_applying_phase_7(NOW + 10)
        .is_chain_valid(&id(&c)));
    // Revocation of A kills the subtree for ever.
    w.add(&w.revocation(w.root(), KeyId::ROOT, id(&a), vec![]));
    let v = w.keys.validity_applying_phase_7(NOW + 10);
    for (depth, k) in [&a, &b, &c].into_iter().enumerate() {
        assert!(!v.is_chain_valid(&id(k)));
        assert!(!v.is_presentable(&id(k)));
        // The canonical chain is valid or not: ancestry does not shift.
        assert_eq!(v.canonical_chain(&id(k)).len(), depth + 1);
    }
    // A suspension on a key that is not chain-valid still counts for it.
    assert!(!v.under_suspension(&id(&c)));
    w.add(&w.suspension(w.root(), KeyId::ROOT, id(&a), ActingTier::Read, 0));
    assert!(w
        .keys
        .validity_applying_phase_7(NOW + 10)
        .under_suspension(&id(&a)));
    assert_eq!(w.keys.revocations().count(), 1);
    assert_eq!(w.keys.suspensions().count(), 4);
    // Ruling 21: in phases 0 to 6 none of those records is applied. Every
    // key is chain-valid, presentable and acts at its governing grant's tier,
    // and nothing is under suspension.
    let v = w.keys.validity(NOW);
    for k in [&a, &b, &c] {
        assert!(v.is_chain_valid(&id(k)));
        assert!(v.is_presentable(&id(k)));
        assert_eq!(v.effective_tier(&id(k)), EffectiveTier::Write);
        assert_eq!(v.presentable_tier(&id(k)), EffectiveTier::Write);
        assert!(!v.under_suspension(&id(k)));
    }
    assert!(v.may_issue(&id(&b), Tier::Write));
}

#[test]
fn tm_19_a_key_on_two_chains_survives_the_revocation_of_one() {
    // K holds a read may_share grant from root and a write may_share grant
    // from X. K issues W a write grant, which only K's write grant can
    // authorize (ruling 17). X is then revoked. As phase 7 will judge it, K
    // survives on its read chain and governs as read, and W, whose one
    // authorizing link leads through X, is not chain-valid: an issuer with a
    // valid read chain and a revoked write chain cannot keep a write child
    // alive. The search is memoised per tier the link must authorize, so K's
    // read chain is never reused for W.
    let mut w = world();
    let x = set(10);
    let k = set(11);
    let wk = set(12);
    w.add(&w.root_grant(&x, Tier::Write, true));
    let gk_read = w.root_grant(&k, Tier::Read, true);
    w.add(&gk_read);
    w.add(&w.grant_from(&x, id(&x), &k, Tier::Write, true, 0));
    w.add(&w.grant_from(&k, id(&k), &wk, Tier::Write, false, 0));
    // A read child of K, which K's read grant authorizes on its own.
    let rk = set(13);
    w.add(&w.grant_from(&k, id(&k), &rk, Tier::Read, false, 0));
    assert_eq!(
        w.keys
            .validity_applying_phase_7(NOW)
            .effective_tier(&id(&wk)),
        EffectiveTier::Write
    );
    w.add(&w.revocation(w.root(), KeyId::ROOT, id(&x), vec![]));
    let v = w.keys.validity_applying_phase_7(NOW);
    assert!(v.is_chain_valid(&id(&k)));
    assert_eq!(
        v.governing_grant(&id(&k)).map(|(h, _)| *h),
        Some(gk_read.hash())
    );
    assert_eq!(v.effective_tier(&id(&k)), EffectiveTier::Read);
    assert!(!v.is_chain_valid(&id(&wk)));
    assert_eq!(v.effective_tier(&id(&wk)), EffectiveTier::Nothing);
    assert!(!v.is_presentable(&id(&wk)));
    assert!(v.is_chain_valid(&id(&rk)));
    // In phases 0 to 6 the Revocation is stored but not applied (ruling 21):
    // nothing changed for K or W, and K may still issue write.
    let v = w.keys.validity(NOW);
    assert_eq!(v.effective_tier(&id(&k)), EffectiveTier::Write);
    assert_eq!(v.effective_tier(&id(&wk)), EffectiveTier::Write);
    assert!(v.is_presentable(&id(&wk)));
    assert_eq!(
        w.add(&w.grant_from(&k, id(&k), &set(14), Tier::Write, false, 0)),
        vec![]
    );
}

#[test]
fn tm_19_without_the_victims_key_no_one_can_become_its_issuer() {
    // X, a may_share write key, drafts a grant for the victim V's public keys.
    // Without V's private half it cannot sign the proof of possession, so the
    // grant is forged: X never becomes an issuer of V, and cannot revoke it.
    let mut w = world();
    let (x, v) = (set(10), set(11));
    w.add(&w.root_grant(&x, Tier::Write, true));
    w.add(&w.root_grant(&v, Tier::Read, false));
    let honest = w.grant_from(&x, id(&x), &v, Tier::Sealed, false, 0);
    let squat = SignedRecord {
        key_signature: x
            .sign_deterministic(labels::SIG_GRANT_POP, &honest.body)
            .unwrap()
            .as_bytes()
            .to_vec(),
        ..honest.clone()
    };
    assert_eq!(w.rejects(&squat), Rejected::Forged);
    assert_eq!(
        w.rejects(&w.revocation(&x, id(&x), id(&v), vec![])),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&x),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&v),
        })
    );
    // V itself may accept a second grant from X: then X is its issuer by V's own choice.
    w.add(&honest);
    assert_eq!(w.keys.grants_for(&id(&v)).count(), 2);
}

#[test]
fn validity_does_not_depend_on_insertion_order() {
    let base = world();
    let a = set(10);
    let b = set(11);
    let c = set(12);
    let records = [
        base.root_grant(&a, Tier::Write, true),
        base.root_grant(&b, Tier::Write, true),
        base.grant_from(&a, id(&a), &c, Tier::Read, true, 0),
        base.grant_from(&b, id(&b), &c, Tier::Read, true, 50),
        base.root_grant(&c, Tier::Sealed, false),
    ];
    let mut first = world();
    for r in &records {
        first.add(r);
    }
    let mut second = world();
    for i in [1usize, 0, 4, 3, 2] {
        second.add(&records[i]);
    }
    let (v1, v2) = (first.keys.validity(NOW), second.keys.validity(NOW));
    for k in [&a, &b, &c] {
        assert_eq!(
            v1.governing_grant(&id(k)).map(|(h, _)| *h),
            v2.governing_grant(&id(k)).map(|(h, _)| *h)
        );
        let c1: Vec<RecordHash> = v1
            .canonical_chain(&id(k))
            .iter()
            .map(|(h, _)| **h)
            .collect();
        let c2: Vec<RecordHash> = v2
            .canonical_chain(&id(k))
            .iter()
            .map(|(h, _)| **h)
            .collect();
        assert_eq!(c1, c2);
        assert_eq!(v1.effective_tier(&id(k)), v2.effective_tier(&id(k)));
    }
}

#[test]
fn presentable_needs_every_grant_on_the_chain_unexpired() {
    let mut w = world();
    let a = set(10);
    let b = set(11);
    w.add(&w.grant_from(w.root(), KeyId::ROOT, &a, Tier::Write, true, NOW + 100));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Write, false, 0));
    assert!(w.keys.validity(NOW).is_presentable(&id(&b)));
    let later = w.keys.validity(NOW + 100);
    assert!(!later.is_presentable(&id(&b)), "the issuer expired");
    assert!(
        later.is_chain_valid(&id(&b)),
        "expiry is not part of chain validity"
    );
    assert!(!later.may_issue(&id(&a), Tier::Read));
    assert!(
        !w.keys.validity(NOW).is_presentable(&KeyId::ROOT),
        "root never presents"
    );
    assert!(!w.keys.validity(NOW).is_presentable(&KeyId([7; 16])));
    assert_eq!(
        w.keys.validity(NOW).effective_tier(&KeyId([7; 16])),
        EffectiveTier::Nothing
    );
    assert!(w
        .keys
        .validity(NOW)
        .governing_grant(&KeyId([7; 16]))
        .is_none());
}

#[test]
fn tm_11_holder_unwraps_and_confirms() {
    let mut w = world();
    let root_dk = w.keys.unwrap_root_data_key(w.root()).unwrap();
    assert!(bool::from(root_dk.ct_eq(&w.dk1)));
    assert_eq!(
        w.keys.unwrap_root_data_key(&set(3)).err(),
        Some(HolderError::NotThisKey)
    );
    let a = set(10);
    let s = set(11);
    let ga = w.root_grant(&a, Tier::Write, true);
    let gs = w.root_grant(&s, Tier::Sealed, false);
    w.add(&ga);
    w.add(&gs);
    let (epoch, dk) = w.keys.unwrap_grant_data_key(&ga.hash(), &a).unwrap();
    assert_eq!(epoch, 1);
    assert!(bool::from(dk.ct_eq(&w.dk1)));
    assert_eq!(
        w.keys.unwrap_grant_data_key(&ga.hash(), &s).err(),
        Some(HolderError::NotThisKey)
    );
    assert_eq!(
        w.keys.unwrap_grant_data_key(&gs.hash(), &s).err(),
        Some(HolderError::Sealed)
    );
    assert_eq!(
        w.keys.unwrap_grant_data_key(&RecordHash([0; 32]), &a).err(),
        Some(HolderError::NotStored)
    );
    // An issuer that wraps another key than dk_1: the confirmation catches it.
    let b = set(12);
    let wrong = DataKey::from_bytes([0xee; 32]);
    let request = GrantRequest {
        folder_id: w.folder_id(),
        recipient: &b,
        tier: Tier::Read,
        may_share: false,
        expires_at: 0,
        epoch: 1,
        data_key: Some(&wrong),
        issued_at: 0,
        issuer_device_id: None,
    };
    let (gb, _) = issue_grant_deterministic(&a, id(&a), &request, &mut fixed_rng(1)).unwrap();
    w.add(&gb);
    assert_eq!(
        w.keys.unwrap_grant_data_key(&gb.hash(), &b).err(),
        Some(HolderError::ConfirmMismatch { signer: id(&a) })
    );
    for e in [
        HolderError::NotThisKey,
        HolderError::NotStored,
        HolderError::Sealed,
        HolderError::NoWrap,
        HolderError::Unwrap {
            signer: KeyId::ROOT,
        },
        HolderError::ConfirmMismatch {
            signer: KeyId::ROOT,
        },
        HolderError::UnknownEpoch(3),
        HolderError::NotConfirmed,
    ] {
        assert_ne!(e.to_string(), "");
    }
}

#[test]
fn a_root_wrap_that_fails_its_confirmation_flags_root() {
    let (folder, _) = new_folder(1);
    let mut body = folder.body.clone();
    body.confirm = Confirm([0; 32]);
    let record =
        sign_record_deterministic(&folder.root, RecordType::Folder, body.encode()).unwrap();
    let keys = FolderKeys::new(&body.folder_id, record).unwrap();
    assert_eq!(
        keys.unwrap_root_data_key(&folder.root).err(),
        Some(HolderError::ConfirmMismatch {
            signer: KeyId::ROOT
        })
    );
}

#[test]
fn a_key_signature_on_a_record_that_is_not_a_grant_is_malformed() {
    let mut w = world();
    let a = set(10);
    w.add(&w.root_grant(&a, Tier::Write, true));
    let rev = w.revocation(w.root(), KeyId::ROOT, id(&a), vec![]);
    let with_pop = SignedRecord {
        key_signature: vec![1; 3373],
        ..rev.clone()
    };
    assert_eq!(
        w.rejects(&with_pop),
        Rejected::Malformed(Malformed::UnexpectedKeySignature)
    );
    let folder = SignedRecord {
        key_signature: vec![1; 3373],
        ..w.folder.record.clone()
    };
    assert_eq!(
        FolderKeys::new(&w.folder_id(), folder).unwrap_err(),
        Rejected::Malformed(Malformed::UnexpectedKeySignature)
    );
    w.add(&rev);
}

#[test]
fn ruling_18_a_key_reachable_through_a_loop_is_an_ancestor() {
    // K from A, A from root; B from K; B re-grants A (with A's consent). The
    // walk K, A (from B), B, K, A (from root), root repeats keys but is
    // authorizing and within 16 grants, so B is an ancestor of K and of A:
    // A's holder accepted B as an issuer, and with it B's power over
    // everything beneath A. Q, who issued no grant on any walk, is not.
    let mut w = world();
    let (a, k, b, q) = (set(10), set(11), set(12), set(13));
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &k, Tier::Write, true, 0));
    w.add(&w.grant_from(&k, id(&k), &b, Tier::Write, true, 0));
    w.add(&w.grant_from(&b, id(&b), &a, Tier::Write, true, 0));
    w.add(&w.root_grant(&q, Tier::Write, true));
    assert_eq!(
        w.keys.ancestors(&id(&k)),
        [id(&a), id(&b)].into_iter().collect()
    );
    assert!(w.keys.ancestors(&id(&b)).contains(&id(&a)));
    assert!(w.keys.in_subtree(&id(&k), &id(&b)));
    assert!(!w.keys.in_subtree(&id(&k), &id(&q)));
    assert_eq!(
        w.rejects(&w.revocation(&q, id(&q), id(&k), vec![])),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&q),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&k),
        })
    );
    assert_eq!(
        w.add(&w.revocation(&b, id(&b), id(&k), vec![])),
        vec![Issue::NotApplied(RecordType::Revocation)]
    );
}

#[test]
fn record_types_that_are_not_key_records() {
    let mut w = world();
    let index = SignedRecord {
        body: wire::Prefix {
            suite: 1,
            record_type: 16,
            folder_id: w.folder_id().0.to_vec(),
        }
        .encode_to_vec(),
        signature: vec![],
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&index),
        Rejected::Malformed(Malformed::NotAKeyRecord)
    );
    let root_rotation = SignedRecord {
        body: wire::Prefix {
            suite: 1,
            record_type: 8,
            folder_id: w.folder_id().0.to_vec(),
        }
        .encode_to_vec(),
        signature: vec![],
        key_signature: Vec::new(),
    };
    assert_eq!(
        w.rejects(&root_rotation),
        Rejected::ValidityOnly(Validity::UnsupportedRecordType(8))
    );
}

#[test]
fn tm_22_ruling_23_quotas_bound_every_non_root_signer_and_never_root() {
    let mut w = world();
    let a = set(10);
    w.add(&w.root_grant(&a, Tier::Write, true));
    let to = |seed: u8| set(seed);
    let from_a = |w: &World, seed: u8| w.grant_from(&a, id(&a), &to(seed), Tier::Read, false, 0);
    // The folder's record count: a validity-only rejection naming A, never a
    // close or a panic, while root's records still go in.
    w.keys
        .fill_quotas_for_test(MAX_KEY_RECORDS_PER_FOLDER, 0, None);
    assert_eq!(
        w.rejects(&from_a(&w, 11)),
        Rejected::ValidityOnly(Validity::QuotaExceeded {
            signer: id(&a),
            quota: Quota::FolderRecords
        })
    );
    let root_record = w.root_grant(&to(12), Tier::Read, false);
    w.add(&root_record);
    let revocation = w.revocation(w.root(), KeyId::ROOT, id(&a), vec![]);
    w.add(&revocation);
    // A record already held is still a duplicate, and an oversized one still
    // malformed: the size is judged first, then the duplicate, then quotas.
    assert_eq!(
        w.keys.insert(&root_record, NOW).unwrap(),
        Accepted::Duplicate(root_record.hash())
    );
    // The folder's bytes.
    w.keys
        .fill_quotas_for_test(0, MAX_KEY_RECORD_BYTES_PER_FOLDER - 100, None);
    assert_eq!(
        w.rejects(&from_a(&w, 13)),
        Rejected::ValidityOnly(Validity::QuotaExceeded {
            signer: id(&a),
            quota: Quota::FolderBytes
        })
    );
    // One signer's records.
    w.keys
        .fill_quotas_for_test(0, 0, Some((id(&a), MAX_KEY_RECORDS_PER_SIGNER)));
    assert_eq!(
        w.rejects(&from_a(&w, 14)),
        Rejected::ValidityOnly(Validity::QuotaExceeded {
            signer: id(&a),
            quota: Quota::SignerRecords
        })
    );
    w.keys
        .fill_quotas_for_test(0, 0, Some((id(&a), MAX_KEY_RECORDS_PER_SIGNER - 1)));
    w.add(&from_a(&w, 15));
}

#[test]
fn phase_0_stores_rotations_after_signer_signature_and_entitlement() {
    let mut w = world();
    let a = set(10);
    let b = set(11);
    w.add(&w.root_grant(&a, Tier::Write, true));
    let gb = w.grant_from(&a, id(&a), &b, Tier::Read, false, 0);
    w.add(&gb);
    let dk2 = DataKey::from_bytes([2; 32]);
    // Entitlement (step 4), while epoch 2 is still to be reached.
    let no_cause = w.rotation(&a, id(&a), &dk2, &[], None, vec![], 2);
    assert_eq!(
        w.rejects(&no_cause),
        Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::EmptyCauseNotRoot
        }
    );
    let missing = w.rotation(&a, id(&a), &dk2, &[], Some(RecordHash([3; 32])), vec![], 2);
    assert_eq!(
        w.rejects(&missing),
        Rejected::Missing(Missing::Record(RecordHash([3; 32])))
    );
    let grant_cause = w.rotation(&a, id(&a), &dk2, &[], Some(gb.hash()), vec![], 2);
    assert_eq!(
        w.rejects(&grant_cause),
        Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::CauseWrongType
        }
    );
    let read_suspension = w.suspension(&a, id(&a), id(&b), ActingTier::Read, 0);
    w.add(&read_suspension);
    let r = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[],
        Some(read_suspension.hash()),
        vec![],
        2,
    );
    assert_eq!(
        w.rejects(&r),
        Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::CauseWrongType
        }
    );
    let rev = w.revocation(w.root(), KeyId::ROOT, id(&b), vec![]);
    w.add(&rev);
    let other_signer = w.rotation(&a, id(&a), &dk2, &[], Some(rev.hash()), vec![], 2);
    assert_eq!(
        w.rejects(&other_signer),
        Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::CauseOtherSigner
        }
    );
    let ahead = w.rotation(w.root(), KeyId::ROOT, &dk2, &[], None, vec![], 3);
    assert_eq!(w.rejects(&ahead), Rejected::Missing(Missing::Epoch(2)));
    let unknown_signer = w.rotation(&set(30), id(&set(30)), &dk2, &[], None, vec![], 2);
    assert_eq!(
        w.rejects(&unknown_signer),
        Rejected::Missing(Missing::Grant(id(&set(30))))
    );
    // An entitled rotation by A, whose cause is its own suspension to none.
    let none = w.suspension(&a, id(&a), id(&b), ActingTier::Nothing, 0);
    w.add(&none);
    let ok = w.rotation(&a, id(&a), &dk2, &[], Some(none.hash()), vec![], 2);
    assert_eq!(w.add(&ok), vec![Issue::NotApplied(RecordType::Rotation)]);
    assert_eq!(w.keys.current_epoch(), 2);
    assert_eq!(w.keys.rotations().count(), 1);
    let mut forged = w.rotation(
        w.root(),
        KeyId::ROOT,
        &dk2,
        &[],
        None,
        vec![RecordHash([1; 32])],
        3,
    );
    forged.signature = ok.signature.clone();
    assert_eq!(w.rejects(&forged), Rejected::Forged);
}

#[test]
fn tm_38_a_dense_chain_of_rotations_sets_the_dependency_epoch() {
    let mut w = world();
    let a = set(10);
    w.add(&w.root_grant(&a, Tier::Write, true));
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let r2 = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root)],
        None,
        vec![],
        2,
    );
    assert_eq!(w.add(&r2), vec![Issue::NotApplied(RecordType::Rotation)]);
    assert_eq!(w.keys.current_epoch(), 2);
    assert_eq!(w.keys.epoch_rotation(2), Some(&r2.hash()));
    assert_eq!(w.keys.epoch_rotation(1), None);
    assert_eq!(w.keys.epoch_confirm(2), Some(dk2.confirm()));
    assert_eq!(w.keys.epoch_confirm(3), None);
    // A grant at epoch 2 is now stored, and its key confirms against epoch 2.
    let b = set(11);
    let request = GrantRequest {
        folder_id: w.folder_id(),
        recipient: &b,
        tier: Tier::Read,
        may_share: false,
        expires_at: 0,
        epoch: 2,
        data_key: Some(&dk2),
        issued_at: 0,
        issuer_device_id: None,
    };
    let (gb, _) = issue_grant_deterministic(&a, id(&a), &request, &mut fixed_rng(1)).unwrap();
    w.add(&gb);
    let (epoch, got) = w.keys.unwrap_grant_data_key(&gb.hash(), &b).unwrap();
    assert_eq!(epoch, 2);
    assert!(bool::from(got.ct_eq(&dk2)));
    // A rival to epoch 2, signature-checked, then stored as evidence; it does not move the epoch.
    let rival = w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([9; 32]),
        &[],
        None,
        vec![],
        2,
    );
    assert_eq!(
        w.add(&rival),
        vec![
            Issue::NotApplied(RecordType::Rotation),
            Issue::RivalRotation { epoch: 2 }
        ]
    );
    assert_eq!(w.keys.epoch_rotation(2), Some(&r2.hash()));
    let mut forged_rival = w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([8; 32]),
        &[],
        None,
        vec![],
        2,
    );
    forged_rival.signature = rival.signature.clone();
    assert_eq!(w.rejects(&forged_rival), Rejected::Forged);
    // Epoch 3 follows; epoch 5 is a missing dependency; a rotation to 2 is now stale.
    let r3 = w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([3; 32]),
        &[],
        None,
        vec![],
        3,
    );
    w.add(&r3);
    assert_eq!(w.keys.current_epoch(), 3);
    assert_eq!(
        w.rejects(&w.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 5)),
        Rejected::Missing(Missing::Epoch(4))
    );
    // Ruling 23: a stale rotation is evidence only once step 4 passed. A's,
    // with an empty cause, is a signer fault; with a cause it is stored, once
    // per (epoch, signer) (ruling 22), while root's are always accepted.
    let stale = |w: &World, cause: Option<RecordHash>, byte: u8| {
        w.rotation(
            &a,
            id(&a),
            &DataKey::from_bytes([byte; 32]),
            &[],
            cause,
            vec![RecordHash([1; 32])],
            2,
        )
    };
    assert_eq!(
        w.rejects(&stale(&w, None, 7)),
        Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::EmptyCauseNotRoot
        }
    );
    let rev = w.revocation(&a, id(&a), id(&b), vec![]);
    w.add(&rev);
    assert_eq!(
        w.add(&stale(&w, Some(rev.hash()), 7)),
        vec![
            Issue::NotApplied(RecordType::Rotation),
            Issue::RivalRotation { epoch: 2 }
        ]
    );
    assert_eq!(
        w.rejects(&stale(&w, Some(rev.hash()), 6)),
        Rejected::ValidityOnly(Validity::RivalAlreadyStored {
            epoch: 2,
            signer: id(&a)
        })
    );
    w.add(&w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([5; 32]),
        &[],
        None,
        vec![],
        2,
    ));
    // Epoch 2 now has several stored rotations: nothing about its key is
    // judged and nobody is blamed (security review, SF 4); epoch 3 is clear.
    assert!(w.keys.epoch_ambiguous(2));
    assert!(!w.keys.epoch_ambiguous(3) && !w.keys.epoch_ambiguous(1));
    assert_eq!(
        w.keys.unwrap_grant_data_key(&gb.hash(), &b).err(),
        Some(HolderError::EpochAmbiguous(2))
    );
    // The ladder of epoch 3 opens only with epoch 3's confirmed key.
    assert_eq!(
        w.keys.climb_ladder(&r3.hash(), &dk2).err(),
        Some(HolderError::NotConfirmed)
    );
}

#[test]
fn phase_0_wraps() {
    let mut w = world();
    let a = set(10);
    let b = set(11);
    let s = set(12);
    let stranger = set(13);
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Read, false, 0));
    w.add(&w.root_grant(&s, Tier::Sealed, false));
    w.add(&w.root_grant(&stranger, Tier::Write, false));
    assert_eq!(
        w.add(&w.wrap_record(&a, id(&a), &b, Tier::Read, 1)),
        vec![Issue::NotApplied(RecordType::Wrap)]
    );
    assert_eq!(w.keys.wraps().count(), 1);
    assert_eq!(
        w.rejects(&w.wrap_record(&a, id(&a), &b, Tier::Write, 1)),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&a),
            fault: SignerFault::WrapTier,
            absent_grant_of: id(&b),
        })
    );
    assert_eq!(
        w.rejects(&w.wrap_record(w.root(), KeyId::ROOT, &s, Tier::Read, 1)),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: KeyId::ROOT,
            fault: SignerFault::WrapTier,
            absent_grant_of: id(&s),
        })
    );
    assert_eq!(
        w.rejects(&w.wrap_record(&stranger, id(&stranger), &b, Tier::Read, 1)),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&stranger),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&b),
        })
    );
    assert_eq!(
        w.rejects(&w.wrap_record(&a, id(&a), &set(40), Tier::Read, 1)),
        Rejected::Missing(Missing::Grant(id(&set(40))))
    );
    assert_eq!(
        w.rejects(&w.wrap_record(&a, id(&a), &b, Tier::Read, 2)),
        Rejected::Missing(Missing::Epoch(2))
    );
    // Ruling 21: in phases 0 to 6 a stored Revocation excludes nobody, so a
    // Wrap for the revoked key is stored with the not-applied issue.
    w.add(&w.revocation(&a, id(&a), id(&b), vec![]));
    let late = w.wrap_record(w.root(), KeyId::ROOT, &b, Tier::Read, 1);
    w.add(&late);
    // Judged per grant (ruling 19): a key whose only grant at the Wrap's tier
    // has no chain within 16 grants is out of reach, a validity-only
    // rejection, though its sealed grant from root has a chain.
    let (deep, deep_id) = chain_of(&mut w, 16, 100);
    let far = set(41);
    w.add(&w.grant_from(&deep, deep_id, &far, Tier::Write, false, 0));
    w.add(&w.root_grant(&far, Tier::Sealed, false));
    assert_eq!(
        w.rejects(&w.wrap_record(w.root(), KeyId::ROOT, &far, Tier::Write, 1)),
        Rejected::ValidityOnly(Validity::WrapToKeyWithoutChain(id(&far)))
    );
}

#[test]
fn tm_38_wrap_records_unwrap_and_confirm() {
    let mut w = world();
    let a = set(10);
    w.add(&w.root_grant(&a, Tier::Write, true));
    let wrap = w.wrap_record(w.root(), KeyId::ROOT, &a, Tier::Write, 1);
    w.add(&wrap);
    let (epoch, dk) = w.keys.unwrap_wrap_data_key(&wrap.hash(), &a).unwrap();
    assert_eq!(epoch, 1);
    assert!(bool::from(dk.ct_eq(&w.dk1)));
    assert_eq!(
        w.keys.unwrap_wrap_data_key(&wrap.hash(), &set(11)).err(),
        Some(HolderError::NotThisKey)
    );
    assert_eq!(
        w.keys.unwrap_wrap_data_key(&RecordHash([0; 32]), &a).err(),
        Some(HolderError::NotStored)
    );
    // A Wrap of another key than dk_1: the signer of the Wrap is at fault.
    let aad = WrapAad {
        folder_id: w.folder_id(),
        key_id: id(&a),
        tier: Tier::Write,
        epoch: 1,
    };
    let wrong = wrap_data_key(
        &a.public().kem,
        &aad,
        &DataKey::from_bytes([0xee; 32]),
        &mut fixed_rng(2),
    )
    .unwrap();
    let body = WrapBody {
        suite: Suite::ONE,
        folder_id: w.folder_id(),
        key_id: id(&a),
        epoch: 1,
        wrapped_data_key: wrong,
        signer_key_id: KeyId::ROOT,
        issued_at: 9,
        tier: Tier::Write,
    };
    let bad = w.sign(w.root(), RecordType::Wrap, body.encode());
    w.add(&bad);
    assert_eq!(
        w.keys.unwrap_wrap_data_key(&bad.hash(), &a).err(),
        Some(HolderError::ConfirmMismatch {
            signer: KeyId::ROOT
        })
    );
    // One that does not open under the holder's key at all.
    let mut body = WrapBody::parse(&bad.body).unwrap();
    body.issued_at = 10;
    body.wrapped_data_key =
        wrap_data_key(&set(12).public().kem, &aad, &w.dk1, &mut fixed_rng(2)).unwrap();
    let unopenable = w.sign(w.root(), RecordType::Wrap, body.encode());
    w.add(&unopenable);
    assert_eq!(
        w.keys.unwrap_wrap_data_key(&unopenable.hash(), &a).err(),
        Some(HolderError::Unwrap {
            signer: KeyId::ROOT
        })
    );
}

#[test]
fn tm_19_revocations_suspensions_and_lifts_need_entitlement() {
    let mut w = world();
    let a = set(10);
    let b = set(11);
    let sibling = set(12);
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Write, true, 0));
    w.add(&w.root_grant(&sibling, Tier::Write, true));
    // Only root, the issuer or an ancestor: never a sibling, never upward.
    assert_eq!(
        w.rejects(&w.revocation(&sibling, id(&sibling), id(&b), vec![])),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&sibling),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&b),
        })
    );
    assert_eq!(
        w.rejects(&w.revocation(&b, id(&b), id(&a), vec![])),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&b),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&a),
        })
    );
    assert_eq!(
        w.rejects(&w.suspension(&sibling, id(&sibling), id(&b), ActingTier::Read, 0)),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&sibling),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&b),
        })
    );
    assert_eq!(
        w.rejects(&w.revocation(&a, id(&a), id(&set(50)), vec![])),
        Rejected::Missing(Missing::Grant(id(&set(50))))
    );
    let s = w.suspension(&a, id(&a), id(&b), ActingTier::Sealed, 0);
    assert_eq!(w.add(&s), vec![Issue::NotApplied(RecordType::Suspension)]);
    assert_eq!(
        w.rejects(&w.lift(&sibling, id(&sibling), s.hash())),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&sibling),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&a),
        })
    );
    assert_eq!(
        w.rejects(&w.lift(&a, id(&a), RecordHash([4; 32]))),
        Rejected::Missing(Missing::Record(RecordHash([4; 32])))
    );
    let a_grant = w.keys.grants_for(&id(&a)).next().map(|(h, _)| *h).unwrap();
    assert_eq!(
        w.rejects(&w.lift(&a, id(&a), a_grant)),
        Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::LiftTarget
        }
    );
    assert_eq!(
        w.add(&w.lift(w.root(), KeyId::ROOT, s.hash())),
        vec![Issue::NotApplied(RecordType::Lift)]
    );
    // An entitled signer this verifier knows revoked is stored with an issue.
    w.add(&w.revocation(w.root(), KeyId::ROOT, id(&a), vec![]));
    let by_revoked = w.revocation(&a, id(&a), id(&b), vec![]);
    assert_eq!(
        w.add(&by_revoked),
        vec![
            Issue::NotApplied(RecordType::Revocation),
            Issue::SignerNotValid(id(&a))
        ]
    );
    // A forged revocation.
    let mut forged = w.revocation(w.root(), KeyId::ROOT, id(&sibling), vec![]);
    forged.signature = by_revoked.signature.clone();
    assert_eq!(w.rejects(&forged), Rejected::Forged);
}

#[test]
fn a_lift_needs_the_suspensions_signer_or_an_ancestor_of_it() {
    let mut w = world();
    let (a, b, c) = (set(10), set(11), set(12));
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Write, true, 0));
    w.add(&w.grant_from(&b, id(&b), &c, Tier::Read, false, 0));
    // Root suspends C: B, C's issuer, may not lift it; root may.
    let by_root = w.suspension(w.root(), KeyId::ROOT, id(&c), ActingTier::Sealed, 0);
    w.add(&by_root);
    assert_eq!(
        w.rejects(&w.lift(&b, id(&b), by_root.hash())),
        Rejected::SignerFault {
            signer: id(&b),
            fault: SignerFault::NotEntitled
        }
    );
    w.add(&w.lift(w.root(), KeyId::ROOT, by_root.hash()));
    // B suspends C: B and A (B's ancestor) may lift it.
    let by_b = w.suspension(&b, id(&b), id(&c), ActingTier::Sealed, 0);
    w.add(&by_b);
    w.add(&w.lift(&a, id(&a), by_b.hash()));
    w.add(&w.lift(&b, id(&b), by_b.hash()));
}

#[test]
fn a_cutoff_outside_the_subtree_raises_an_issue() {
    let mut w = world();
    let a = set(10);
    let outsider = set(11);
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.root_grant(&outsider, Tier::Write, false));
    let cutoffs = vec![
        Cutoff {
            key_id: id(&outsider),
            device_id: DeviceId([1; 32]),
            seq: 0,
            head_hash: None,
        },
        Cutoff {
            key_id: id(&set(60)),
            device_id: DeviceId([1; 32]),
            seq: 0,
            head_hash: None,
        },
    ];
    let issues = w.add(&w.revocation(w.root(), KeyId::ROOT, id(&a), cutoffs));
    assert_eq!(
        issues,
        vec![
            Issue::NotApplied(RecordType::Revocation),
            Issue::CutoffOutsideSubtree {
                signer: KeyId::ROOT,
                writer: id(&outsider)
            }
        ]
    );
}

/// A, write `may_share` from root; B, read from A; S, sealed from root.
pub(crate) fn rotation_world() -> (World, KeyPairSet, KeyPairSet, KeyPairSet, [RecordHash; 3]) {
    let mut w = world();
    let (a, b, s) = (set(10), set(11), set(12));
    let ga = w.root_grant(&a, Tier::Write, true);
    let gb = w.grant_from(&a, id(&a), &b, Tier::Read, false, 0);
    let gs = w.root_grant(&s, Tier::Sealed, false);
    for g in [&ga, &gb, &gs] {
        w.add(g);
    }
    (w, a, b, s, [ga.hash(), gb.hash(), gs.hash()])
}

#[test]
fn tm_38_phase_7_coverage_keeps_exactly_the_valid_readers() {
    let (mut w, a, b, s, [ga, gb, gs]) = rotation_world();
    let dk2 = DataKey::from_bytes([2; 32]);
    let rev = w.revocation(&a, id(&a), id(&b), vec![]);
    w.add(&rev);
    let view = vec![ga, gb, gs];
    let root = root_set();
    let good = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root), (id(&a), &a, Tier::Write)],
        Some(rev.hash()),
        view.clone(),
        2,
    );
    w.add(&good);
    assert_eq!(
        w.keys.check_rotation_coverage(&good.hash(), NOW),
        Ok(vec![])
    );
    // The holders recover dk_2, confirm it, and climb to dk_1.
    let got = w
        .keys
        .unwrap_rotation_data_key(&good.hash(), &id(&a), &a)
        .unwrap();
    assert!(bool::from(got.ct_eq(&dk2)));
    let root_got = w
        .keys
        .unwrap_rotation_data_key(&good.hash(), &KeyId::ROOT, &root)
        .unwrap();
    assert!(bool::from(root_got.ct_eq(&dk2)));
    let dk1 = w.keys.climb_ladder(&good.hash(), &dk2).unwrap();
    assert!(bool::from(dk1.ct_eq(&w.dk1)));
    // Only the confirmed key opens the ladder.
    assert_eq!(
        w.keys
            .climb_ladder(&good.hash(), &DataKey::from_bytes([9; 32]))
            .err(),
        Some(HolderError::NotConfirmed)
    );
    // Each variant below is the first rotation to epoch 2 in a world of its
    // own: in one world they would be rivals, limited to one per signer
    // (ruling 22) and leaving epoch 2 ambiguous (SF 4).
    let fresh = |rotation: &SignedRecord| {
        let (mut v, ..) = rotation_world();
        v.add(&rev);
        v.add(rotation);
        v
    };
    // A ladder that does not open, or opens to a key that fails epoch 1's
    // confirmation: the rotator is at fault, and the holder adopts nothing
    // from that rotation, though its own wrap opens and confirms (ruling 19).
    let mut body = RotationBody::parse(&good.body).unwrap();
    body.ladder = LadderLink::from_slice(&[0; 72]).unwrap();
    let broken = w.sign(&a, RecordType::Rotation, body.encode());
    let v = fresh(&broken);
    assert_eq!(
        v.keys.climb_ladder(&broken.hash(), &dk2).err(),
        Some(HolderError::Unwrap { signer: id(&a) })
    );
    assert_eq!(
        v.keys
            .unwrap_rotation_data_key(&broken.hash(), &id(&a), &a)
            .err(),
        Some(HolderError::Unwrap { signer: id(&a) })
    );
    body.ladder = LadderLink::seal(
        &dk2,
        2,
        &w.folder_id(),
        &DataKey::from_bytes([9; 32]),
        &mut fixed_rng(6),
    )
    .unwrap();
    let wrong = w.sign(&a, RecordType::Rotation, body.encode());
    let v = fresh(&wrong);
    assert_eq!(
        v.keys.climb_ladder(&wrong.hash(), &dk2).err(),
        Some(HolderError::ConfirmMismatch { signer: id(&a) })
    );
    assert_eq!(
        v.keys
            .unwrap_rotation_data_key(&wrong.hash(), &id(&a), &a)
            .err(),
        Some(HolderError::ConfirmMismatch { signer: id(&a) })
    );
    assert_eq!(
        w.keys
            .unwrap_rotation_data_key(&good.hash(), &id(&b), &b)
            .err(),
        Some(HolderError::NoWrap)
    );
    assert_eq!(
        w.keys
            .unwrap_rotation_data_key(&good.hash(), &id(&a), &b)
            .err(),
        Some(HolderError::NotThisKey)
    );
    assert_eq!(
        w.keys.unwrap_rotation_data_key(&ga, &id(&a), &a).err(),
        Some(HolderError::NotStored)
    );
    assert_eq!(
        w.keys.climb_ladder(&ga, &dk2).err(),
        Some(HolderError::NotStored)
    );
    // Omitting A is a lockout; wrapping B (revoked by the cause) or S (sealed) a leak.
    let lockout = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root)],
        Some(rev.hash()),
        view.clone(),
        2,
    );
    assert_eq!(
        fresh(&lockout)
            .keys
            .check_rotation_coverage(&lockout.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::Lockout(id(&a))
        })
    );
    let leak = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[
            (KeyId::ROOT, &root, Tier::Root),
            (id(&a), &a, Tier::Write),
            (id(&b), &b, Tier::Read),
        ],
        Some(rev.hash()),
        view.clone(),
        2,
    );
    assert_eq!(
        fresh(&leak).keys.check_rotation_coverage(&leak.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::ForbiddenWrap(id(&b))
        })
    );
    let sealed = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[
            (KeyId::ROOT, &root, Tier::Root),
            (id(&a), &a, Tier::Write),
            (id(&s), &s, Tier::Sealed),
        ],
        Some(rev.hash()),
        view.clone(),
        2,
    );
    assert_eq!(
        fresh(&sealed)
            .keys
            .check_rotation_coverage(&sealed.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: id(&a),
            fault: SignerFault::ForbiddenWrap(id(&s))
        })
    );
    // A wrong confirmation value: the holder rejects it.
    let mut body = RotationBody::parse(&good.body).unwrap();
    body.confirm = Confirm([1; 32]);
    let bad_confirm = w.sign(&a, RecordType::Rotation, body.encode());
    assert_eq!(
        fresh(&bad_confirm)
            .keys
            .unwrap_rotation_data_key(&bad_confirm.hash(), &id(&a), &a)
            .err(),
        Some(HolderError::ConfirmMismatch { signer: id(&a) })
    );
    // A wrap that does not open under the holder's key.
    let mut body = RotationBody::parse(&good.body).unwrap();
    body.wraps.retain(|x| x.key_id != KeyId::ROOT);
    body.wraps.push(KeyWrapEntry {
        key_id: KeyId::ROOT,
        wrapped_data_key: body.wraps[0].wrapped_data_key.clone(),
    });
    let swapped = w.sign(&a, RecordType::Rotation, body.encode());
    assert_eq!(
        fresh(&swapped)
            .keys
            .unwrap_rotation_data_key(&swapped.hash(), &KeyId::ROOT, &root)
            .err(),
        Some(HolderError::Unwrap { signer: id(&a) })
    );
    // In the first world a second rotation by A to epoch 2 is stored as a
    // rival once, and the epoch is then ambiguous for every holder.
    w.add(&broken);
    assert_eq!(
        w.rejects(&wrong),
        Rejected::ValidityOnly(Validity::RivalAlreadyStored {
            epoch: 2,
            signer: id(&a)
        })
    );
    assert_eq!(
        w.keys
            .unwrap_rotation_data_key(&good.hash(), &id(&a), &a)
            .err(),
        Some(HolderError::EpochAmbiguous(2))
    );
    assert_eq!(
        w.keys.climb_ladder(&good.hash(), &dk2).err(),
        Some(HolderError::EpochAmbiguous(2))
    );
}

#[test]
fn phase_7_view_must_be_held_typed_and_closed() {
    let (mut w, a, _b, _s, [ga, gb, gs]) = rotation_world();
    let dk2 = DataKey::from_bytes([2; 32]);
    let root = root_set();
    let wraps = [(KeyId::ROOT, &root, Tier::Root), (id(&a), &a, Tier::Write)];
    let unknown = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &wraps,
        None,
        vec![ga, RecordHash([0xff; 32])],
        2,
    );
    w.add(&unknown);
    assert_eq!(
        w.keys.check_rotation_coverage(&unknown.hash(), NOW),
        Err(Rejected::Missing(Missing::Record(RecordHash([0xff; 32]))))
    );
    let not_closed = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root)],
        None,
        vec![gb],
        2,
    );
    w.add(&not_closed);
    assert_eq!(
        w.keys.check_rotation_coverage(&not_closed.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::ViewNotClosed
        })
    );
    let with_rotation = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &wraps,
        None,
        vec![ga, unknown.hash()],
        2,
    );
    w.add(&with_rotation);
    assert_eq!(
        w.keys.check_rotation_coverage(&with_rotation.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::ViewWrongType
        })
    );
    let with_folder = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &wraps,
        None,
        vec![ga, w.folder.record.hash()],
        2,
    );
    w.add(&with_folder);
    assert_eq!(
        w.keys.check_rotation_coverage(&with_folder.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::ViewWrongType
        })
    );
    assert_eq!(
        w.keys.check_rotation_coverage(&gs, NOW),
        Err(Rejected::Missing(Missing::Record(gs)))
    );
}

#[test]
fn phase_7_coverage_issues_that_are_not_faults_of_the_signer() {
    let (mut w, a, b, _s, [ga, gb, gs]) = rotation_world();
    let dk2 = DataKey::from_bytes([2; 32]);
    let root = root_set();
    // C, a write key root granted after the rotation's signer built its view.
    let c = set(13);
    w.add(&w.root_grant(&c, Tier::Write, false));
    // B is revoked by a record outside the view: the rotation still wraps it.
    w.add(&w.revocation(&a, id(&a), id(&b), vec![]));
    let rot = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &[
            (KeyId::ROOT, &root, Tier::Root),
            (id(&a), &a, Tier::Write),
            (id(&b), &b, Tier::Read),
        ],
        None,
        vec![ga, gb, gs],
        2,
    );
    w.add(&rot);
    let issues = w.keys.check_rotation_coverage(&rot.hash(), NOW).unwrap();
    assert_eq!(
        issues,
        vec![
            Issue::EpochReachedExcludedKey {
                rotator: KeyId::ROOT,
                key_id: id(&b)
            },
            Issue::AwaitsWrap {
                rotator: KeyId::ROOT,
                key_id: id(&c)
            }
        ]
    );
}

#[test]
fn phase_7_a_lift_in_the_view_restores_a_suspended_key() {
    let (mut w, a, b, _s, [ga, gb, gs]) = rotation_world();
    let dk2 = DataKey::from_bytes([2; 32]);
    let root = root_set();
    let s = w.suspension(&a, id(&a), id(&b), ActingTier::Nothing, 0);
    w.add(&s);
    let l = w.lift(&a, id(&a), s.hash());
    w.add(&l);
    let mut view = vec![ga, gb, gs, s.hash(), l.hash()];
    view.sort();
    let wraps = [
        (KeyId::ROOT, &root, Tier::Root),
        (id(&a), &a, Tier::Write),
        (id(&b), &b, Tier::Read),
    ];
    let rot = w.rotation(&root, KeyId::ROOT, &dk2, &wraps, None, view, 2);
    w.add(&rot);
    assert_eq!(w.keys.check_rotation_coverage(&rot.hash(), NOW), Ok(vec![]));
    // Without the Lift in the view, B is not kept.
    let mut view = vec![ga, gb, gs, s.hash()];
    view.sort();
    let rot = w.rotation(&root, KeyId::ROOT, &dk2, &wraps, None, view, 2);
    w.add(&rot);
    assert_eq!(
        w.keys.check_rotation_coverage(&rot.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::ForbiddenWrap(id(&b))
        })
    );
}

#[test]
fn phase_7_concurrent_rotations_settle_by_cause_then_hash() {
    let (mut w, a, b, _s, [ga, gb, _gs]) = rotation_world();
    let dk2 = DataKey::from_bytes([2; 32]);
    let dk2b = DataKey::from_bytes([3; 32]);
    let root = root_set();
    let r1 = w.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![ga], 2);
    let r2 = w.rotation(&root, KeyId::ROOT, &dk2b, &[], None, vec![ga], 2);
    w.add(&r1);
    w.add(&r2);
    let smaller = r1.hash().min(r2.hash());
    assert_eq!(
        w.keys.rotation_winner(&r1.hash(), &r2.hash()),
        Some(smaller)
    );
    assert_eq!(
        w.keys.rotation_winner(&r2.hash(), &r1.hash()),
        Some(smaller)
    );
    // A rotation whose cause revokes the other's signer wins.
    let c = set(13);
    let d = set(14);
    w.add(&w.grant_from(&a, id(&a), &c, Tier::Write, true, 0));
    w.add(&w.grant_from(&c, id(&c), &d, Tier::Read, false, 0));
    // C may not suspend B, which A issued; it revokes its own child D.
    assert_eq!(
        w.rejects(&w.suspension(&c, id(&c), id(&b), ActingTier::Nothing, 0)),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&c),
            fault: SignerFault::NotEntitled,
            absent_grant_of: id(&b),
        })
    );
    let rev_d = w.revocation(&c, id(&c), id(&d), vec![]);
    w.add(&rev_d);
    let rev_c = w.revocation(&a, id(&a), id(&c), vec![]);
    w.add(&rev_c);
    let by_a = w.rotation(&a, id(&a), &dk2, &[], Some(rev_c.hash()), vec![ga, gb], 2);
    let by_c = w.rotation(&c, id(&c), &dk2b, &[], Some(rev_d.hash()), vec![ga], 2);
    w.add(&by_a);
    w.add(&by_c);
    assert_eq!(
        w.keys.rotation_winner(&by_a.hash(), &by_c.hash()),
        Some(by_a.hash())
    );
    assert_eq!(
        w.keys.rotation_winner(&by_c.hash(), &by_a.hash()),
        Some(by_a.hash())
    );
    // Not rotations, or different epochs: no answer.
    assert_eq!(w.keys.rotation_winner(&by_a.hash(), &ga), None);
    if let Some(store::Entry {
        body: store::Body::Rotation(r),
        ..
    }) = w.keys.entries.get_mut(&r2.hash())
    {
        r.new_epoch = 3;
    }
    assert_eq!(w.keys.rotation_winner(&r1.hash(), &r2.hash()), None);
}
