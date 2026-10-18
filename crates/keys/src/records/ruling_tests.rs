// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests of the rulings of 2026-10-17 that the reviews of 70ff269 brought:
//! authorizing chains and presentable chains (17), ancestry by reachability
//! (18), self-ancestry, rotation signers and ladders (19, 21), quotas and
//! rival rotations (22, 23), held grants, the verification order, the bulk
//! load, and the cost of the chain searches in attacker-chosen shapes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::assert_is_empty,
    clippy::print_stdout,
    reason = "test code: short key names mirror the spec's examples; the measurements print"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::OnceLock;

use proptest::prelude::*;

use super::folder::tests::fixed_rng;
use super::phase7::ActingTier;
use super::store_tests::{chain_of, id, resigned, root_set, set, world, World, NOW};
use super::validity::VISITS;
use super::*;
use crate::secret::DataKey;
use crate::suite::Tier;

fn grant_hashes(chain: &[(&RecordHash, &GrantBody)]) -> Vec<RecordHash> {
    chain.iter().map(|(h, _)| **h).collect()
}

#[test]
fn ruling_17_a_temporary_raise_presents_until_it_expires() {
    // I holds a temporary write grant with may_share and a permanent read
    // grant without it; I issues K at write. K presents at write until the
    // temporary grant expires and not after, since the read grant cannot
    // authorize a write link; its records stay accepted (expiry is not part
    // of chain validity).
    let mut w = world();
    let (i, k) = (set(10), set(11));
    let temp = w.grant_from(w.root(), KeyId::ROOT, &i, Tier::Write, true, NOW + 100);
    let perm = w.root_grant(&i, Tier::Read, false);
    w.add(&temp);
    w.add(&perm);
    let gk = w.grant_from(&i, id(&i), &k, Tier::Write, false, 0);
    assert_eq!(w.add(&gk), vec![]);
    let before = w.keys.validity(NOW);
    assert!(before.is_presentable(&id(&k)));
    assert_eq!(before.presentable_tier(&id(&k)), EffectiveTier::Write);
    assert_eq!(
        grant_hashes(&before.presentable_chain(&id(&k))),
        vec![gk.hash(), temp.hash()]
    );
    assert!(before.may_issue(&id(&i), Tier::Write));
    let after = w.keys.validity(NOW + 100);
    assert!(!after.is_presentable(&id(&k)));
    assert_eq!(after.presentable_tier(&id(&k)), EffectiveTier::Nothing);
    assert!(after.presentable_chain(&id(&k)).is_empty());
    assert!(after.is_chain_valid(&id(&k)));
    assert_eq!(after.effective_tier(&id(&k)), EffectiveTier::Write);
    // I itself still presents, at read, through its permanent grant, and may
    // issue nothing: that grant has no may_share.
    assert_eq!(after.presentable_tier(&id(&i)), EffectiveTier::Read);
    assert!(!after.may_issue(&id(&i), Tier::Write));
    assert!(!after.may_issue(&id(&i), Tier::Read));
}

#[test]
fn ruling_17_a_chain_through_a_link_without_may_share_is_not_valid() {
    // K's issuer A authorized K through a read may_share grant from X; A
    // later gets a write grant from root without may_share, which governs A.
    // Once X's branch is revoked (as phase 7 applies it), A stays chain-valid
    // through its root grant, but that grant cannot authorize K: K is not
    // chain-valid.
    let mut w = world();
    let (x, a, k) = (set(10), set(11), set(12));
    let gx = w.root_grant(&x, Tier::Write, true);
    w.add(&gx);
    let ga_share = w.grant_from(&x, id(&x), &a, Tier::Read, true, 0);
    w.add(&ga_share);
    let gk = w.grant_from(&a, id(&a), &k, Tier::Read, false, 0);
    w.add(&gk);
    let ga_noshare = w.root_grant(&a, Tier::Write, false);
    w.add(&ga_noshare);
    let v = w.keys.validity(NOW);
    assert_eq!(
        v.governing_grant(&id(&a)).map(|(h, _)| *h),
        Some(ga_noshare.hash())
    );
    assert!(v.is_chain_valid(&id(&k)));
    assert_eq!(
        grant_hashes(&v.canonical_chain(&id(&k))),
        vec![gk.hash(), ga_share.hash(), gx.hash()],
        "the only authorizing chain runs through the may_share grant"
    );
    w.add(&w.revocation(w.root(), KeyId::ROOT, id(&x), vec![]));
    let v7 = w.keys.validity_applying_phase_7(NOW);
    assert!(v7.is_chain_valid(&id(&a)));
    assert!(!v7.is_chain_valid(&id(&k)));
    assert!(!v7.is_presentable(&id(&k)));
    // The canonical chain is valid or not: it does not move.
    assert_eq!(v7.canonical_chain(&id(&k)).len(), 3);
}

#[test]
fn a_canonical_chain_holding_an_expired_grant_presents_through_another_at_its_tier() {
    let mut w = world();
    let (k, y) = (set(10), set(11));
    let short = w.grant_from(w.root(), KeyId::ROOT, &k, Tier::Write, false, NOW + 100);
    let gy = w.root_grant(&y, Tier::Read, true);
    let long = w.grant_from(&y, id(&y), &k, Tier::Read, false, 0);
    for g in [&short, &gy, &long] {
        w.add(g);
    }
    let later = w.keys.validity(NOW + 100);
    assert_eq!(
        grant_hashes(&later.canonical_chain(&id(&k))),
        vec![short.hash()]
    );
    assert_eq!(
        later.governing_grant(&id(&k)).map(|(h, _)| *h),
        Some(short.hash())
    );
    assert_eq!(later.effective_tier(&id(&k)), EffectiveTier::Write);
    assert!(later.is_presentable(&id(&k)));
    assert_eq!(later.presentable_tier(&id(&k)), EffectiveTier::Read);
    assert_eq!(
        grant_hashes(&later.presentable_chain(&id(&k))),
        vec![long.hash(), gy.hash()]
    );
    // Before the expiry the write chain is the best presentable one.
    let now = w.keys.validity(NOW);
    assert_eq!(now.presentable_tier(&id(&k)), EffectiveTier::Write);
    assert_eq!(
        grant_hashes(&now.presentable_chain(&id(&k))),
        vec![short.hash()]
    );
}

#[test]
fn ruling_18_a_revocation_stays_entitled_in_every_arrival_order() {
    // Root grants S (write, may_share), S grants I, I grants K; S revokes K;
    // root then grants K directly, which gives K a shorter chain without S.
    // S is still an ancestor of K, so the Revocation is entitled whether the
    // direct grant arrived before it or after.
    let base = world();
    let (s, i, k) = (set(10), set(11), set(12));
    let gs = base.root_grant(&s, Tier::Write, true);
    let gi = base.grant_from(&s, id(&s), &i, Tier::Write, true, 0);
    let gk = base.grant_from(&i, id(&i), &k, Tier::Read, false, 0);
    let rev = base.revocation(&s, id(&s), id(&k), vec![]);
    let direct = base.root_grant(&k, Tier::Read, false);
    for order in [
        [&gs, &gi, &gk, &rev, &direct],
        [&gs, &gi, &gk, &direct, &rev],
    ] {
        let mut w = world();
        for record in order {
            w.add(record);
        }
        assert!(w.keys.contains(&rev.hash()));
        let ancestors = w.keys.validity(NOW).ancestors(&id(&k));
        assert!(ancestors.contains(&id(&s)) && ancestors.contains(&id(&i)));
        assert!(w.keys.in_subtree(&id(&k), &id(&s)));
        // The canonical chain names the direct grant once it is stored.
        assert_eq!(
            grant_hashes(&w.keys.validity(NOW).canonical_chain(&id(&k))),
            vec![direct.hash()]
        );
    }
}

#[test]
fn ruling_19_a_key_cannot_revoke_or_suspend_itself_through_self_ancestry() {
    // K from root, B from K, B re-grants K: K lies on its own walk to root,
    // but a key is never its own ancestor, so K may neither revoke nor
    // suspend itself; B, the issuer of a grant of K, may.
    let mut w = world();
    let (k, b) = (set(10), set(11));
    w.add(&w.root_grant(&k, Tier::Write, true));
    w.add(&w.grant_from(&k, id(&k), &b, Tier::Write, true, 0));
    w.add(&w.grant_from(&b, id(&b), &k, Tier::Write, true, 0));
    let ancestors = w.keys.validity(NOW).ancestors(&id(&k));
    assert!(!ancestors.contains(&id(&k)));
    assert!(ancestors.contains(&id(&b)));
    // No grant can make K its own ancestor, so this blames K.
    let not_entitled = Rejected::SignerFault {
        signer: id(&k),
        fault: SignerFault::NotEntitled,
    };
    assert_eq!(
        w.rejects(&w.revocation(&k, id(&k), id(&k), vec![])),
        not_entitled
    );
    assert_eq!(
        w.rejects(&w.suspension(&k, id(&k), id(&k), ActingTier::Read, 0)),
        not_entitled
    );
    assert_eq!(
        w.add(&w.revocation(&b, id(&b), id(&k), vec![])),
        vec![Issue::NotApplied(RecordType::Revocation)]
    );
}

#[test]
fn ruling_21_a_sealed_may_share_key_cannot_rotate_and_nothing_is_adopted() {
    // S, granted only sealed but with may_share, issues C, revokes it and
    // rotates with that Revocation as cause: refused, so no holder adopts
    // the rotation's key and the epoch does not move.
    let mut w = world();
    let (s, c) = (set(10), set(11));
    w.add(&w.root_grant(&s, Tier::Sealed, true));
    w.add(&w.grant_from(&s, id(&s), &c, Tier::Sealed, false, 0));
    let rev = w.revocation(&s, id(&s), id(&c), vec![]);
    w.add(&rev);
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let rotation = w.rotation(
        &s,
        id(&s),
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root)],
        Some(rev.hash()),
        vec![],
        2,
    );
    assert_eq!(
        w.rejects(&rotation),
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer: id(&s),
            fault: SignerFault::SealedRotator,
            absent_grant_of: id(&s),
        })
    );
    assert_eq!(w.keys.current_epoch(), 1);
    assert_eq!(
        w.keys
            .unwrap_rotation_data_key(&rotation.hash(), &KeyId::ROOT, &root)
            .err(),
        Some(HolderError::NotStored)
    );
    // A read key may rotate in principle (ruling 21: a stored grant of tier 1
    // or 2), but a rival it sends is refused before it is stored, since it
    // has no cause of its own (ruling 23).
    let r = set(12);
    w.add(&w.root_grant(&r, Tier::Read, false));
    let first = w.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 2);
    w.add(&first);
    let rival = w.rotation(&r, id(&r), &dk2, &[], None, vec![], 2);
    assert_eq!(
        w.rejects(&rival),
        Rejected::SignerFault {
            signer: id(&r),
            fault: SignerFault::EmptyCauseNotRoot
        }
    );
    let borrowed = w.rotation(&r, id(&r), &dk2, &[], Some(rev.hash()), vec![], 2);
    assert_eq!(
        w.rejects(&borrowed),
        Rejected::SignerFault {
            signer: id(&r),
            fault: SignerFault::CauseOtherSigner
        }
    );
    assert!(!w.keys.epoch_ambiguous(2));
}

#[test]
fn ruling_23_a_flood_by_one_may_share_key_leaves_roots_records_accepted() {
    // A, a may_share write key, has used its whole quota (and the folder's),
    // say by suspending its own child again and again: its next record is a
    // validity-only rejection naming it, while root's Revocation of A and
    // root's Rotation are still stored.
    let mut w = world();
    let (a, c) = (set(10), set(11));
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &c, Tier::Read, false, 0));
    w.keys.fill_quotas_for_test(
        MAX_KEY_RECORDS_PER_FOLDER,
        0,
        Some((id(&a), MAX_KEY_RECORDS_PER_SIGNER)),
    );
    assert_eq!(
        w.rejects(&w.suspension(&a, id(&a), id(&c), ActingTier::Read, 0)),
        Rejected::ValidityOnly(Validity::QuotaExceeded {
            signer: id(&a),
            quota: Quota::FolderRecords
        })
    );
    w.keys
        .fill_quotas_for_test(0, 0, Some((id(&a), MAX_KEY_RECORDS_PER_SIGNER)));
    assert_eq!(
        w.rejects(&w.suspension(&a, id(&a), id(&c), ActingTier::Read, 0)),
        Rejected::ValidityOnly(Validity::QuotaExceeded {
            signer: id(&a),
            quota: Quota::SignerRecords
        })
    );
    w.keys.fill_quotas_for_test(
        MAX_KEY_RECORDS_PER_FOLDER,
        MAX_KEY_RECORD_BYTES_PER_FOLDER,
        Some((id(&a), MAX_KEY_RECORDS_PER_SIGNER)),
    );
    let rev = w.revocation(w.root(), KeyId::ROOT, id(&a), vec![]);
    w.add(&rev);
    let root = root_set();
    let rotation = w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([2; 32]),
        &[(KeyId::ROOT, &root, Tier::Root)],
        None,
        vec![],
        2,
    );
    w.add(&rotation);
    assert_eq!(w.keys.current_epoch(), 2);
}

#[test]
fn phase_7_coverage_keeps_per_grant_so_a_key_left_only_a_sealed_chain_is_not_kept() {
    // K holds a read grant from X and a sealed grant from root. Root revokes
    // X and rotates with that Revocation in the view: K's read grant sits on
    // the revoked branch, and its only surviving chain begins with a sealed
    // grant, so K has no kept grant; leaving it out is no fault, and wrapping
    // to it is a leak.
    let mut w = world();
    let (x, k) = (set(10), set(11));
    let gx = w.root_grant(&x, Tier::Write, true);
    w.add(&gx);
    let read = w.grant_from(&x, id(&x), &k, Tier::Read, false, 0);
    let sealed = w.root_grant(&k, Tier::Sealed, false);
    w.add(&read);
    w.add(&sealed);
    let rev = w.revocation(w.root(), KeyId::ROOT, id(&x), vec![]);
    w.add(&rev);
    let mut view = vec![gx.hash(), read.hash(), sealed.hash(), rev.hash()];
    view.sort_unstable();
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let good = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root)],
        None,
        view.clone(),
        2,
    );
    w.add(&good);
    assert_eq!(
        w.keys.check_rotation_coverage(&good.hash(), NOW),
        Ok(vec![])
    );
    let leak = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root), (id(&k), &k, Tier::Read)],
        None,
        view,
        2,
    );
    w.add(&leak);
    assert_eq!(
        w.keys.check_rotation_coverage(&leak.hash(), NOW),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::ForbiddenWrap(id(&k))
        })
    );
}

/// A request for a grant at epoch 2.
fn at_epoch_2<'a>(
    folder_id: FolderId,
    to: &'a KeyPairSet,
    dk: &'a DataKey,
    tier: Tier,
    may_share: bool,
) -> GrantRequest<'a> {
    GrantRequest {
        folder_id,
        recipient: to,
        tier,
        may_share,
        expires_at: 0,
        epoch: 2,
        data_key: tier.can_read().then_some(dk),
        issued_at: 3,
        issuer_device_id: None,
    }
}

#[test]
fn held_grants_count_at_the_handshake_and_move_to_the_store_with_their_epoch() {
    let mut w = world();
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let (a, c) = (&set(10), &set(11));
    let folder = w.folder_id();
    let (ga, _) = issue_grant_deterministic(
        &root,
        KeyId::ROOT,
        &at_epoch_2(folder, a, &dk2, Tier::Write, true),
        &mut fixed_rng(1),
    )
    .unwrap();
    let (gc, _) = issue_grant_deterministic(
        a,
        id(a),
        &at_epoch_2(folder, c, &dk2, Tier::Read, false),
        &mut fixed_rng(1),
    )
    .unwrap();
    // Epoch 2 has not arrived: the store holds neither.
    assert_eq!(w.rejects(&ga), Rejected::Missing(Missing::Epoch(2)));
    let mut held = HeldGrants::new(w.folder_id());
    assert!(held.is_empty());
    assert_eq!(held.folder_id(), w.folder_id());
    assert_eq!(
        w.keys.verify_held_grant(&gc, &held, NOW).unwrap_err(),
        Rejected::Missing(Missing::Grant(id(a))),
        "the issuer is neither stored nor held yet"
    );
    assert_eq!(
        w.keys.verify_held_grant(&ga, &held, NOW).unwrap().key_id,
        id(a)
    );
    assert!(matches!(
        w.keys.hold_grant(&mut held, &ga, NOW),
        Ok(Accepted::Stored { .. })
    ));
    assert_eq!(
        w.keys.hold_grant(&mut held, &ga, NOW).unwrap(),
        Accepted::Duplicate(ga.hash())
    );
    // The child resolves its issuer through the held set.
    w.keys.hold_grant(&mut held, &gc, NOW).unwrap();
    assert_eq!(held.len(), 2);
    assert!(held.contains(&gc.hash()));
    assert_eq!(
        held.records().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![ga.hash(), gc.hash()]
    );
    // Held grants count at the handshake, and only there.
    assert!(!w.keys.validity(NOW).is_presentable(&id(c)));
    let v = w.keys.validity_with(&held, NOW);
    assert!(v.is_presentable(&id(c)));
    assert_eq!(
        grant_hashes(&v.presentable_chain(&id(c))),
        vec![gc.hash(), ga.hash()]
    );
    // Another folder's held set counts for nothing and holds nothing.
    let mut other = HeldGrants::new(FolderId([9; 32]));
    assert_eq!(
        w.keys.hold_grant(&mut other, &ga, NOW).unwrap_err(),
        Rejected::Malformed(Malformed::OtherFolder)
    );
    assert_eq!(
        w.keys.verify_held_grant(&ga, &other, NOW).unwrap_err(),
        Rejected::Malformed(Malformed::OtherFolder)
    );
    assert!(!w.keys.validity_with(&other, NOW).is_presentable(&id(c)));
    // A forged grant is refused as on insertion.
    let forged = SignedRecord {
        signature: gc.key_signature.clone(),
        ..gc.clone()
    };
    assert_eq!(
        w.keys.verify_held_grant(&forged, &held, NOW).unwrap_err(),
        Rejected::Forged
    );
    // Not a grant.
    let rev = w.revocation(w.root(), KeyId::ROOT, id(a), vec![]);
    assert!(matches!(
        w.keys.verify_held_grant(&rev, &held, NOW),
        Err(Rejected::Malformed(Malformed::WrongType { .. }))
    ));
    assert!(matches!(
        w.keys.hold_grant(&mut held, &rev, NOW),
        Err(Rejected::Malformed(Malformed::WrongType { .. }))
    ));
    // The bound: a full set refuses, naming no key (ruling 29).
    let mut full = held.clone();
    full.pad_for_test(
        &GrantBody::parse(&ga.body).unwrap(),
        MAX_HELD_GRANTS - full.len(),
    );
    let x = set(12);
    let (gx, _) = issue_grant_deterministic(
        &root,
        KeyId::ROOT,
        &at_epoch_2(folder, &x, &dk2, Tier::Read, false),
        &mut fixed_rng(1),
    )
    .unwrap();
    assert_eq!(
        w.keys.hold_grant(&mut full, &gx, NOW).unwrap_err(),
        Rejected::ValidityOnly(Validity::HeldSetFull)
    );
    // Judged before either signature (quality NIT 6): a full set refuses a
    // forged grant, or one with a forged proof of possession, by the bound,
    // naming no key; a body that does not parse stays malformed.
    for forged in [
        SignedRecord {
            signature: gx.key_signature.clone(),
            ..gx.clone()
        },
        SignedRecord {
            key_signature: gx.signature.clone(),
            ..gx.clone()
        },
    ] {
        assert_eq!(
            w.keys.verify_held_grant(&forged, &held, NOW).unwrap_err(),
            Rejected::Forged
        );
        assert_eq!(
            w.keys.hold_grant(&mut full, &forged, NOW).unwrap_err(),
            Rejected::ValidityOnly(Validity::HeldSetFull),
            "the bound comes before the signatures"
        );
    }
    let mut short_key_id = <wire::Grant as prost::Message>::decode(gx.body.as_slice()).unwrap();
    short_key_id.key_id.truncate(3);
    let unparsable = SignedRecord {
        body: prost::Message::encode_to_vec(&short_key_id),
        ..gx.clone()
    };
    assert!(unparsable.prefix().is_ok());
    assert_eq!(
        w.keys.hold_grant(&mut full, &unparsable, NOW).unwrap_err(),
        Rejected::Malformed(Malformed::FieldSize("key_id"))
    );
    assert_eq!(full.len(), MAX_HELD_GRANTS);
    // Epoch 2 arrives: the held grants move to the store, in order.
    assert!(held.take_ready(w.keys.current_epoch()).is_empty());
    let r2 = w.rotation(
        &root,
        KeyId::ROOT,
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root)],
        None,
        vec![],
        2,
    );
    w.add(&r2);
    let ready = held.take_ready(w.keys.current_epoch());
    assert_eq!(ready, vec![ga.clone(), gc.clone()]);
    assert!(held.is_empty());
    for record in &ready {
        w.add(record);
    }
    assert!(w.keys.validity(NOW).is_presentable(&id(c)));
}

/// Ruling 29 (security delta review, SF 2): a full held set refuses a grant
/// before either signature, so nothing its body names is believed and the
/// refusal names no key. A body naming root as its issuer, unsigned or under
/// a signature root never made, gets no root attribution: the outcome is the
/// held-set-full one, the same as for a body naming any other issuer.
#[test]
fn ruling_29_a_full_held_set_names_no_key_for_a_grant_claiming_root() {
    let w = world();
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let folder = w.folder_id();
    let (x, d) = (set(60), set(61));
    let names_root = issue_grant_deterministic(
        &root,
        KeyId::ROOT,
        &at_epoch_2(folder, &x, &dk2, Tier::Write, true),
        &mut fixed_rng(1),
    )
    .unwrap()
    .0;
    let names_d = issue_grant_deterministic(
        &d,
        id(&d),
        &at_epoch_2(folder, &x, &dk2, Tier::Read, false),
        &mut fixed_rng(1),
    )
    .unwrap()
    .0;
    assert_eq!(
        GrantBody::parse(&names_root.body).unwrap().issuer_key_id,
        KeyId::ROOT
    );
    let unsigned = |r: &SignedRecord| SignedRecord {
        signature: Vec::new(),
        key_signature: Vec::new(),
        ..r.clone()
    };
    let forged = |r: &SignedRecord| SignedRecord {
        signature: r.key_signature.clone(),
        ..r.clone()
    };
    // Root made neither signature: verified, they fail.
    let open = HeldGrants::new(folder);
    assert_eq!(
        w.keys
            .verify_held_grant(&unsigned(&names_root), &open, NOW)
            .unwrap_err(),
        Rejected::Malformed(Malformed::SignatureSize(0))
    );
    assert_eq!(
        w.keys
            .verify_held_grant(&forged(&names_root), &open, NOW)
            .unwrap_err(),
        Rejected::Forged
    );
    let mut full = HeldGrants::new(folder);
    full.pad_for_test(&GrantBody::parse(&names_d.body).unwrap(), MAX_HELD_GRANTS);
    for record in [
        unsigned(&names_root),
        forged(&names_root),
        names_root.clone(),
        unsigned(&names_d),
        forged(&names_d),
    ] {
        assert_eq!(
            w.keys.hold_grant(&mut full, &record, NOW).unwrap_err(),
            Rejected::ValidityOnly(Validity::HeldSetFull),
            "no key is named, whichever issuer the body claims"
        );
    }
    assert_eq!(full.len(), MAX_HELD_GRANTS);
}

#[test]
fn verification_order_proof_of_possession_comes_before_issuer_epoch_and_folder() {
    let mut w = world();
    let (k, x, other) = (set(10), set(11), set(12));
    let good = w.root_grant(&k, Tier::Read, false);
    let bad_pop = |record: &SignedRecord| SignedRecord {
        key_signature: other
            .sign_deterministic(labels::SIG_GRANT_POP, &record.body)
            .unwrap()
            .as_bytes()
            .to_vec(),
        ..record.clone()
    };
    // An unknown issuer would be a missing dependency, a future epoch too,
    // another folder malformed: with a bad proof of possession each is
    // forged, because the proof is checked first.
    let unknown_issuer = w.grant_from(&x, id(&x), &k, Tier::Read, false, 0);
    assert_eq!(
        w.rejects(&unknown_issuer),
        Rejected::Missing(Missing::Grant(id(&x)))
    );
    assert_eq!(w.rejects(&bad_pop(&unknown_issuer)), Rejected::Forged);
    let future = super::store_tests::resigned(&good, &k, w.root(), |g| g.epoch = 5);
    assert_eq!(w.rejects(&future), Rejected::Missing(Missing::Epoch(5)));
    assert_eq!(w.rejects(&bad_pop(&future)), Rejected::Forged);
    let elsewhere =
        super::store_tests::resigned(&good, &k, w.root(), |g| g.folder_id = vec![0x5f; 32]);
    assert_eq!(
        w.rejects(&elsewhere),
        Rejected::Malformed(Malformed::OtherFolder)
    );
    assert_eq!(w.rejects(&bad_pop(&elsewhere)), Rejected::Forged);
}

#[test]
fn verification_order_a_forged_record_from_an_unentitled_signer_is_forged() {
    // Q is stored but entitled over nothing of K's. Records naming Q as
    // signer but signed by another key are forged, not refused for Q's
    // entitlement: the signature first.
    let mut w = world();
    let (a, k, q, z) = (set(10), set(11), set(12), set(13));
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &k, Tier::Read, false, 0));
    w.add(&w.root_grant(&q, Tier::Write, true));
    let reforge = |record: SignedRecord, record_type: RecordType| SignedRecord {
        signature: z
            .sign_deterministic(record_type.sig_label(), &record.body)
            .unwrap()
            .as_bytes()
            .to_vec(),
        ..record
    };
    let suspension = w.suspension(&q, id(&q), id(&k), ActingTier::Read, 0);
    let honest_suspension = w.suspension(&a, id(&a), id(&k), ActingTier::Read, 0);
    w.add(&honest_suspension);
    for (record, record_type, over) in [
        (
            w.revocation(&q, id(&q), id(&k), vec![]),
            RecordType::Revocation,
            id(&k),
        ),
        (suspension, RecordType::Suspension, id(&k)),
        (
            w.lift(&q, id(&q), honest_suspension.hash()),
            RecordType::Lift,
            id(&a),
        ),
        (
            w.wrap_record(&q, id(&q), &k, Tier::Read, 1),
            RecordType::Wrap,
            id(&k),
        ),
    ] {
        assert_eq!(
            w.rejects(&record),
            Rejected::ValidityOnly(Validity::UnprovableFault {
                signer: id(&q),
                fault: SignerFault::NotEntitled,
                absent_grant_of: over,
            }),
            "{record_type:?} by Q, honestly signed"
        );
        assert_eq!(
            w.rejects(&reforge(record, record_type)),
            Rejected::Forged,
            "{record_type:?} claiming Q, signed by another key"
        );
    }
}

#[test]
fn a_looping_keys_only_simple_chain_counts_and_17_grants_is_one_too_many() {
    // K from root; Y from K; Y also from a chain X1..Xn from root; Y
    // re-grants K. The re-grant's shortest walk returns through K (3 grants)
    // and does not count; its shortest chain runs through X1..Xn, n + 2
    // grants: valid at n = 14 (16 grants), not at n = 15 (17).
    for (n, valid) in [(14u8, true), (15, false)] {
        let mut w = world();
        let (k, y) = (set(10), set(11));
        w.add(&w.root_grant(&k, Tier::Write, true));
        w.add(&w.grant_from(&k, id(&k), &y, Tier::Write, true, 0));
        let (xn, xn_id) = chain_of(&mut w, n, 100);
        w.add(&w.grant_from(&xn, xn_id, &y, Tier::Write, true, 0));
        let regrant = w.grant_from(&y, id(&y), &k, Tier::Read, false, 0);
        w.add(&regrant);
        let v = w.keys.validity(NOW);
        assert_eq!(v.is_grant_valid(&regrant.hash()), valid, "n = {n}");
        assert!(v.is_chain_valid(&id(&k)));
    }
}

/// The keys of [`chain_of`]`(w, n, first_seed)`, root's grantee first.
fn chain_sets(n: u8, first_seed: u8) -> Vec<KeyPairSet> {
    (0..n).map(|i| set(first_seed + i)).collect()
}

/// The 16-grant bound in the phase 7 coverage rule (quality review SF 1):
/// X1..X16 from root, each at write with `may_share`, and K at write from
/// X16, so K's only chain is 17 grants. A root rotation over all 17 grants
/// keeps root and X1..X16 and not K: wrapping to them is coverage, leaving
/// out X16 (16 grants) is a lockout, and wrapping to K as well is a leak.
#[test]
fn depth_bound_a_rotation_does_not_keep_a_write_key_whose_only_chain_is_17_grants() {
    let mut w = world();
    let xs = chain_sets(16, 100);
    let (x16, x16_id) = chain_of(&mut w, 16, 100);
    let k = set(200);
    w.add(&w.grant_from(&x16, x16_id, &k, Tier::Write, false, 0));
    let mut view: Vec<RecordHash> = w.keys.grants_by_key.values().flatten().copied().collect();
    view.sort_unstable();
    assert_eq!(view.len(), 17);
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let mut recipients: Vec<(KeyId, &KeyPairSet, Tier)> = vec![(KeyId::ROOT, &root, Tier::Root)];
    recipients.extend(xs.iter().map(|x| (id(x), x, Tier::Write)));
    let rotate = |w: &mut World, to: &[(KeyId, &KeyPairSet, Tier)]| {
        let r = w.rotation(&root, KeyId::ROOT, &dk2, to, None, view.clone(), 2);
        w.add(&r);
        w.keys.check_rotation_coverage(&r.hash(), NOW)
    };
    assert_eq!(rotate(&mut w, &recipients), Ok(vec![]));
    let without_x16: Vec<_> = recipients
        .iter()
        .copied()
        .filter(|(key, _, _)| *key != x16_id)
        .collect();
    assert_eq!(
        rotate(&mut w, &without_x16),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::Lockout(x16_id)
        })
    );
    recipients.push((id(&k), &k, Tier::Write));
    assert_eq!(
        rotate(&mut w, &recipients),
        Err(Rejected::SignerFault {
            signer: KeyId::ROOT,
            fault: SignerFault::ForbiddenWrap(id(&k))
        })
    );
}

/// The bound in the walk levels kept as grants arrive (quality review SF 1):
/// A1..A16 from root, B from A16 (17 grants) and C from B (18), all at write
/// with `may_share`. Root then grants A2, which shortens every walk below it
/// by one: B's shortest chain becomes 16 grants and C's 17, so B becomes
/// chain-valid and C stays not, by the stored levels and by the search.
#[test]
fn depth_bound_a_shorter_route_found_later_leaves_a_17_grant_key_not_chain_valid() {
    let mut w = world();
    let a = chain_sets(16, 100);
    let (a16, a16_id) = chain_of(&mut w, 16, 100);
    let (b, c) = (set(200), set(201));
    let gb = w.grant_from(&a16, a16_id, &b, Tier::Write, true, 0);
    let gc = w.grant_from(&b, id(&b), &c, Tier::Write, true, 0);
    w.add(&gb);
    w.add(&gc);
    let v = w.keys.validity(NOW);
    assert!(!v.is_chain_valid(&id(&b)) && !v.is_chain_valid(&id(&c)));
    w.add(&w.root_grant(&a[1], Tier::Write, true));
    let mut held = HeldGrants::new(w.folder_id());
    held.pad_for_test(template(), 1);
    for (v, view) in [
        (w.keys.validity(NOW), "stored levels"),
        (w.keys.validity_with(&held, NOW), "search"),
    ] {
        assert!(v.is_grant_valid(&gb.hash()), "{view}");
        assert!(v.is_chain_valid(&id(&b)), "{view}");
        assert_eq!(v.canonical_chain(&id(&b)).len(), 16, "{view}");
        assert_eq!(v.presentable_chain(&id(&b)).len(), 16, "{view}");
        assert!(!v.is_grant_valid(&gc.hash()), "{view}");
        assert!(!v.is_chain_valid(&id(&c)), "{view}");
        assert!(v.canonical_chain(&id(&c)).is_empty(), "{view}");
        assert!(!v.is_presentable(&id(&c)), "{view}");
        assert_eq!(v.effective_tier(&id(&c)), EffectiveTier::Nothing, "{view}");
    }
}

/// The bound in ancestry (quality review SF 1): X1..X16 from root, K from
/// X16 and L from X15. K's only walk is 17 grants, so X2 (or any X) is not
/// its ancestor; L's is 16, so X1..X15 are.
#[test]
fn depth_bound_a_17_grant_walk_makes_no_ancestor() {
    let mut w = world();
    let xs = chain_sets(16, 100);
    let (x16, x16_id) = chain_of(&mut w, 16, 100);
    let (k, l) = (set(200), set(201));
    w.add(&w.grant_from(&x16, x16_id, &k, Tier::Read, false, 0));
    w.add(&w.grant_from(&xs[14], id(&xs[14]), &l, Tier::Read, false, 0));
    let x2 = id(&xs[1]);
    let grants = w.keys.stored_grants();
    assert!(!grants.is_ancestor(&x2, &id(&k)));
    assert!(!grants.is_ancestor(&x16_id, &id(&k)));
    assert!(grants.is_ancestor(&x2, &id(&l)));
    assert!(grants.beneath(&x2).contains(&id(&l)));
    assert!(!grants.beneath(&x2).contains(&id(&k)));
    let above_l: BTreeSet<KeyId> = xs[..15].iter().map(id).collect();
    let mut held = HeldGrants::new(w.folder_id());
    held.pad_for_test(template(), 1);
    for (v, view) in [
        (w.keys.validity(NOW), "stored levels"),
        (w.keys.validity_with(&held, NOW), "search"),
    ] {
        assert!(v.ancestors(&id(&k)).is_empty(), "{view}");
        assert_eq!(v.ancestors(&id(&l)), above_l, "{view}");
    }
}

/// Two peers of one folder: A stored D's grants; B refused them, because D
/// had reached its quota there (ruling 23). Both hold root's grants to D
/// (write, `may_share`) and to K (`k_tier`, no `may_share`).
fn quota_split(k_tier: Tier) -> (World, World, KeyPairSet, KeyPairSet) {
    let (d, k) = (set(20), set(21));
    let (mut a, mut b) = (world(), world());
    for w in [&mut a, &mut b] {
        w.add(&w.root_grant(&d, Tier::Write, true));
        w.add(&w.root_grant(&k, k_tier, false));
    }
    (a, b, d, k)
}

fn fill_signer(w: &mut World, signer: &KeyPairSet, n: usize) {
    w.keys.fill_quotas_for_test(0, 0, Some((id(signer), n)));
}

fn unprovable(signer: KeyId, fault: SignerFault, absent_grant_of: KeyId) -> Rejected {
    Rejected::ValidityOnly(Validity::UnprovableFault {
        signer,
        fault,
        absent_grant_of,
    })
}

fn refused(missing: Missing) -> Rejected {
    Rejected::ValidityOnly(Validity::DependencyRefused(missing))
}

fn quota_refused(signer: &KeyPairSet) -> Rejected {
    Rejected::ValidityOnly(Validity::QuotaExceeded {
        signer: id(signer),
        quota: Quota::SignerRecords,
    })
}

/// Rulings 24 and 25, the first reproduced case: K's grant to M rests on D's
/// grant to K, which B refused under D's quota. B blamed K (no `may_share`);
/// it is validity-only, before any refusal and after. A grant whose issuer's
/// only grant was refused is no missing dependency.
#[test]
fn ruling_25_a_grant_beneath_a_refused_grant_does_not_blame_its_issuer() {
    let (mut a, mut b, d, k) = quota_split(Tier::Read);
    let (m, k2, m2) = (set(22), set(23), set(24));
    let d_to_k = a.grant_from(&d, id(&d), &k, Tier::Write, true, 0);
    let d_to_k2 = a.grant_from(&d, id(&d), &k2, Tier::Write, true, 0);
    let k_to_m = a.grant_from(&k, id(&k), &m, Tier::Write, false, 0);
    let k2_to_m2 = a.grant_from(&k2, id(&k2), &m2, Tier::Write, false, 0);
    for r in [&d_to_k, &d_to_k2, &k_to_m, &k2_to_m2] {
        a.add(r);
    }
    let no_may_share = unprovable(id(&k), SignerFault::NoMayShare, id(&k));
    assert_eq!(b.rejects(&k_to_m), no_may_share);
    assert_eq!(
        b.rejects(&k2_to_m2),
        Rejected::Missing(Missing::Grant(id(&k2)))
    );
    assert!(b.keys.refused_under_quota().next().is_none());
    fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
    for r in [&d_to_k, &d_to_k2] {
        assert_eq!(b.rejects(r), quota_refused(&d));
    }
    assert_eq!(
        b.keys.refused_under_quota().collect::<Vec<_>>(),
        vec![&d_to_k.hash(), &d_to_k2.hash()]
    );
    // Judged again when it arrives again, and remembered once.
    assert_eq!(b.rejects(&d_to_k), quota_refused(&d));
    assert_eq!(b.keys.refused_under_quota().count(), 2);
    assert_eq!(b.rejects(&k_to_m), no_may_share);
    assert_eq!(b.rejects(&k2_to_m2), refused(Missing::Grant(id(&k2))));
    // The same at the handshake, for a grant held for a connection.
    let held = HeldGrants::new(b.folder_id());
    assert_eq!(
        b.keys.verify_held_grant(&k_to_m, &held, NOW).unwrap_err(),
        no_may_share
    );
    assert_eq!(
        b.keys.verify_held_grant(&k2_to_m2, &held, NOW).unwrap_err(),
        refused(Missing::Grant(id(&k2)))
    );
    // A missing grant nobody refused is still missing, and a fault that does
    // not rest on a stored grant still blames.
    let stranger = set(25);
    assert_eq!(
        b.rejects(&b.grant_from(&stranger, id(&stranger), &m, Tier::Read, false, 0)),
        Rejected::Missing(Missing::Grant(id(&stranger)))
    );
    let dk2 = DataKey::from_bytes([2; 32]);
    assert_eq!(
        b.rejects(&b.rotation(&d, id(&d), &dk2, &[], None, vec![], 2)),
        Rejected::SignerFault {
            signer: id(&d),
            fault: SignerFault::EmptyCauseNotRoot
        }
    );
}

/// Rulings 24 and 25, the second reproduced case: root's Wrap to K at write
/// rests on D's write grant to K, which B refused; K holds only root's
/// sealed grant there. B blamed root (the Wrap's tier); it blames nobody.
#[test]
fn ruling_25_a_wrap_at_a_refused_grants_tier_does_not_blame_root() {
    let (mut a, mut b, d, k) = quota_split(Tier::Sealed);
    let d_to_k = a.grant_from(&d, id(&d), &k, Tier::Write, false, 0);
    a.add(&d_to_k);
    let root = root_set();
    let wrap = a.wrap_record(&root, KeyId::ROOT, &k, Tier::Write, 1);
    a.add(&wrap);
    let wrap_tier = unprovable(KeyId::ROOT, SignerFault::WrapTier, id(&k));
    assert_eq!(b.rejects(&wrap), wrap_tier);
    fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
    assert_eq!(b.rejects(&d_to_k), quota_refused(&d));
    assert_eq!(b.rejects(&wrap), wrap_tier);
}

/// Ruling 25, the deliberately reordered send: K holds root's sealed grant
/// with `may_share`, and D's write grant to K authorizes K's write grant to
/// M. Sent ahead of D's grant, K's grant to M blamed K (tier too high); it
/// blames nobody, and is stored once D's grant arrives.
#[test]
fn ruling_25_a_reordered_send_blames_nobody() {
    let (d, k, m) = (set(20), set(21), set(22));
    let mut b = world();
    b.add(&b.root_grant(&d, Tier::Write, true));
    b.add(&b.root_grant(&k, Tier::Sealed, true));
    let d_to_k = b.grant_from(&d, id(&d), &k, Tier::Write, true, 0);
    let k_to_m = b.grant_from(&k, id(&k), &m, Tier::Write, false, 0);
    assert_eq!(
        b.rejects(&k_to_m),
        unprovable(id(&k), SignerFault::TierTooHigh, id(&k))
    );
    b.add(&d_to_k);
    b.add(&k_to_m);
}

/// Rulings 24 and 25, transitively: R is refused under a quota, D needs R
/// and E needs D. Neither D nor E reports a missing dependency, now or when
/// sent again; each is remembered. Grants carry it on by the key they grant,
/// a rotation refused under a quota by the epoch it creates; a rotation that
/// needs a refused one is remembered by its hash alone (ruling 29), and what
/// needs a later epoch is still covered by the refused one. Other refusals
/// are not remembered, and a remembered record that is stored is forgotten.
#[test]
fn ruling_25_records_beneath_a_refused_one_never_report_it_missing() {
    let (_, mut b, d, reader) = quota_split(Tier::Read);
    let (k, m, n) = (set(30), set(31), set(32));
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let r = b.grant_from(&d, id(&d), &k, Tier::Write, true, 0);
    let dep = b.grant_from(&k, id(&k), &m, Tier::Write, true, 0);
    let e = b.grant_from(&m, id(&m), &n, Tier::Read, false, 0);
    // Epochs: D's rotation to 2 (with D's own Revocation as cause) is
    // refused; root's grant at epoch 2 to X needs it; X's grant to Y needs
    // that; root's rotation to 3 needs epoch 2.
    let x = set(33);
    b.add(&b.grant_from(&d, id(&d), &x, Tier::Read, false, 0));
    let revoke_x = b.revocation(&d, id(&d), id(&x), vec![]);
    b.add(&revoke_x);
    let d_rotation = b.rotation(&d, id(&d), &dk2, &[], Some(revoke_x.hash()), vec![], 2);
    let (z, y) = (set(34), set(35));
    let at_2 = issue_grant_deterministic(
        &root,
        KeyId::ROOT,
        &at_epoch_2(b.folder_id(), &z, &dk2, Tier::Write, true),
        &mut fixed_rng(1),
    )
    .unwrap()
    .0;
    let beneath_at_2 = issue_grant_deterministic(
        &z,
        id(&z),
        &at_epoch_2(b.folder_id(), &y, &dk2, Tier::Read, false),
        &mut fixed_rng(1),
    )
    .unwrap()
    .0;
    let to_3 = b.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 3);
    let to_4 = b.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 4);
    // Before any refusal these are missing dependencies, and nothing is
    // remembered.
    assert_eq!(b.rejects(&dep), Rejected::Missing(Missing::Grant(id(&k))));
    assert_eq!(b.rejects(&at_2), Rejected::Missing(Missing::Epoch(2)));
    assert!(b.keys.refused_under_quota().next().is_none());
    fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
    assert_eq!(b.rejects(&r), quota_refused(&d));
    assert_eq!(b.rejects(&d_rotation), quota_refused(&d));
    for _ in 0..2 {
        assert_eq!(b.rejects(&dep), refused(Missing::Grant(id(&k))));
        assert_eq!(b.rejects(&e), refused(Missing::Grant(id(&m))));
        assert_eq!(b.rejects(&at_2), refused(Missing::Epoch(2)));
        assert_eq!(b.rejects(&beneath_at_2), refused(Missing::Epoch(2)));
        assert_eq!(b.rejects(&to_3), refused(Missing::Epoch(2)));
        assert_eq!(b.rejects(&to_4), refused(Missing::Epoch(3)));
    }
    let remembered: Vec<RecordHash> = b.keys.refused_under_quota().copied().collect();
    assert_eq!(
        remembered,
        [
            &r,
            &d_rotation,
            &dep,
            &e,
            &at_2,
            &beneath_at_2,
            &to_3,
            &to_4
        ]
        .map(SignedRecord::hash)
        .to_vec()
    );
    // A Wrap for K, whose only grant was refused, and a Lift naming a
    // Suspension refused under the quota: no missing dependency either.
    let wrap_k = b.wrap_record(&root, KeyId::ROOT, &k, Tier::Write, 1);
    assert_eq!(b.rejects(&wrap_k), refused(Missing::Grant(id(&k))));
    let suspend_x = b.suspension(&d, id(&d), id(&x), ActingTier::Read, 0);
    assert_eq!(b.rejects(&suspend_x), quota_refused(&d));
    assert_eq!(
        b.rejects(&b.lift(&root, KeyId::ROOT, suspend_x.hash())),
        refused(Missing::Record(suspend_x.hash()))
    );
    // Other validity-only refusals are not remembered.
    let before = b.keys.refused_under_quota().count();
    assert_eq!(before, remembered.len() + 3);
    assert_eq!(
        b.rejects(&b.grant_from(&reader, id(&reader), &set(36), Tier::Read, false, 0)),
        unprovable(id(&reader), SignerFault::NoMayShare, id(&reader))
    );
    assert_eq!(b.keys.refused_under_quota().count(), before);
    // D's quota relents (as only a test can make it): R is stored, and
    // forgotten; D's and E's grants then follow, each forgotten in turn.
    fill_signer(&mut b, &d, 0);
    for record in [&r, &dep, &e] {
        b.add(record);
        assert!(!b.keys.refused_under_quota().any(|h| *h == record.hash()));
    }
}

/// Ruling 26, the chain D -> K -> M -> N: D's grant to K is refused under
/// D's quota, so K's grant to M is refused for K's authority (K holds only
/// root's read grant without `may_share` here) and, since K's curing grant
/// has a remembered refusal, remembered too; M's grant to N and N's to O
/// then never report a missing dependency. Without the remembered refusal
/// K's grant to M is refused the same, not remembered, and M's is missing.
#[test]
fn ruling_26_a_grant_refused_for_authority_beneath_a_refused_grant_carries_the_refusal_on() {
    let (mut a, mut b, d, k) = quota_split(Tier::Read);
    let (m, n, o) = (set(40), set(41), set(42));
    let d_to_k = a.grant_from(&d, id(&d), &k, Tier::Write, true, 0);
    let k_to_m = a.grant_from(&k, id(&k), &m, Tier::Write, true, 0);
    let m_to_n = a.grant_from(&m, id(&m), &n, Tier::Write, true, 0);
    let n_to_o = a.grant_from(&n, id(&n), &o, Tier::Read, false, 0);
    for r in [&d_to_k, &k_to_m, &m_to_n, &n_to_o] {
        a.add(r);
    }
    let for_authority = unprovable(id(&k), SignerFault::NoMayShare, id(&k));
    assert_eq!(b.rejects(&k_to_m), for_authority);
    assert_eq!(
        b.rejects(&m_to_n),
        Rejected::Missing(Missing::Grant(id(&m)))
    );
    assert!(b.keys.refused_under_quota().next().is_none());
    fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
    assert_eq!(b.rejects(&d_to_k), quota_refused(&d));
    for _ in 0..2 {
        assert_eq!(b.rejects(&k_to_m), for_authority);
        assert_eq!(b.rejects(&m_to_n), refused(Missing::Grant(id(&m))));
        assert_eq!(b.rejects(&n_to_o), refused(Missing::Grant(id(&n))));
    }
    assert_eq!(
        b.keys.refused_under_quota().copied().collect::<Vec<_>>(),
        [&d_to_k, &k_to_m, &m_to_n, &n_to_o]
            .map(SignedRecord::hash)
            .to_vec()
    );
}

/// Ruling 26: a Revocation, a Suspension or a Wrap whose target key's only
/// grant was refused under a quota is no missing dependency, and is
/// remembered.
#[test]
fn ruling_26_records_naming_a_key_whose_grant_was_refused_are_no_missing_dependency() {
    let (_, mut b, d, _) = quota_split(Tier::Read);
    let t = set(43);
    let root = root_set();
    let d_to_t = b.grant_from(&d, id(&d), &t, Tier::Read, false, 0);
    let revocation = b.revocation(&root, KeyId::ROOT, id(&t), vec![]);
    let suspension = b.suspension(&root, KeyId::ROOT, id(&t), ActingTier::Sealed, 0);
    let wrap = b.wrap_record(&root, KeyId::ROOT, &t, Tier::Read, 1);
    for r in [&revocation, &suspension, &wrap] {
        assert_eq!(b.rejects(r), Rejected::Missing(Missing::Grant(id(&t))));
    }
    fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
    assert_eq!(b.rejects(&d_to_t), quota_refused(&d));
    for r in [&revocation, &suspension, &wrap] {
        assert_eq!(b.rejects(r), refused(Missing::Grant(id(&t))));
    }
    assert_eq!(
        b.keys.refused_under_quota().copied().collect::<Vec<_>>(),
        [&d_to_t, &revocation, &suspension, &wrap]
            .map(SignedRecord::hash)
            .to_vec()
    );
}

/// Ruling 29 (security delta review, SF 1), the reproduced case: D's
/// rotation to epoch 2 is refused under D's quota. A rotation claiming epoch
/// 4 then needs epoch 3, which that refusal covers, so it is validity-only
/// and remembered, but by its hash alone, since its epoch is judged before
/// its signature: first one signed by nobody that claims to be root's, then
/// one well signed by S, a key granted only sealed, which may not rotate.
/// Root rotates to 2 and 3; root's grant at epoch 4 then waits for epoch 4,
/// a missing dependency, and is stored once root's rotation to 4 arrives.
/// Had the claim provided epoch 4, root's grant would have been refused as
/// needing it.
#[test]
fn ruling_29_an_unverified_rotation_provides_no_epoch_to_the_refusal_memory() {
    for signed_by_unentitled in [false, true] {
        let (_, mut b, d, _) = quota_split(Tier::Read);
        let (x, s, z) = (set(50), set(51), set(52));
        let root = root_set();
        let dk2 = DataKey::from_bytes([2; 32]);
        b.add(&b.grant_from(&d, id(&d), &x, Tier::Read, false, 0));
        let revoke_x = b.revocation(&d, id(&d), id(&x), vec![]);
        b.add(&revoke_x);
        b.add(&b.root_grant(&s, Tier::Sealed, false));
        let d_to_2 = b.rotation(&d, id(&d), &dk2, &[], Some(revoke_x.hash()), vec![], 2);
        fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
        assert_eq!(b.rejects(&d_to_2), quota_refused(&d));
        let claim = if signed_by_unentitled {
            b.rotation(&s, id(&s), &dk2, &[], None, vec![], 4)
        } else {
            let dk4 = DataKey::from_bytes([4; 32]);
            SignedRecord {
                signature: Vec::new(),
                ..b.rotation(&root, KeyId::ROOT, &dk4, &[], None, vec![], 4)
            }
        };
        assert_eq!(b.rejects(&claim), refused(Missing::Epoch(3)));
        assert_eq!(
            b.keys.refused_under_quota().copied().collect::<Vec<_>>(),
            vec![d_to_2.hash(), claim.hash()],
            "remembered, as needing a refused record"
        );
        for epoch in [2, 3] {
            b.add(&b.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], epoch));
        }
        assert_eq!(b.keys.current_epoch(), 3);
        let at_4 = issue_grant_deterministic(
            &root,
            KeyId::ROOT,
            &GrantRequest {
                epoch: 4,
                ..at_epoch_2(b.folder_id(), &z, &dk2, Tier::Read, false)
            },
            &mut fixed_rng(1),
        )
        .unwrap()
        .0;
        assert_eq!(
            b.rejects(&at_4),
            Rejected::Missing(Missing::Epoch(4)),
            "no epoch 4 was planted (signed by an unentitled key: {signed_by_unentitled})"
        );
        b.add(&b.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 4));
        b.add(&at_4);
    }
}

/// Ruling 29, a well-signed rotation with no entitlement, remembered under
/// ruling 26: S holds root's sealed grant with `may_share`, and D's write
/// grant to S, which would let S rotate, was refused under D's quota. S's
/// rotation to epoch 2, with S's own Revocation as cause, is refused for
/// S's tier and remembered, since S's curing grant was refused, but by its
/// hash alone: root's grant at epoch 2, sent before root's rotation to 2, is
/// a missing dependency, not a refused one, and is stored once that
/// rotation arrives.
#[test]
fn ruling_29_an_unentitled_rotation_beneath_a_refused_grant_provides_no_epoch() {
    let (_, mut b, d, _) = quota_split(Tier::Read);
    let (s, c, z) = (set(53), set(54), set(55));
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    b.add(&b.root_grant(&s, Tier::Sealed, true));
    b.add(&b.grant_from(&s, id(&s), &c, Tier::Sealed, false, 0));
    let revoke_c = b.revocation(&s, id(&s), id(&c), vec![]);
    b.add(&revoke_c);
    let d_to_s = b.grant_from(&d, id(&d), &s, Tier::Write, false, 0);
    fill_signer(&mut b, &d, MAX_KEY_RECORDS_PER_SIGNER);
    assert_eq!(b.rejects(&d_to_s), quota_refused(&d));
    let s_to_2 = b.rotation(&s, id(&s), &dk2, &[], Some(revoke_c.hash()), vec![], 2);
    assert_eq!(
        b.rejects(&s_to_2),
        unprovable(id(&s), SignerFault::SealedRotator, id(&s))
    );
    assert_eq!(
        b.keys.refused_under_quota().copied().collect::<Vec<_>>(),
        vec![d_to_s.hash(), s_to_2.hash()]
    );
    let at_2 = issue_grant_deterministic(
        &root,
        KeyId::ROOT,
        &at_epoch_2(b.folder_id(), &z, &dk2, Tier::Read, false),
        &mut fixed_rng(1),
    )
    .unwrap()
    .0;
    assert_eq!(b.rejects(&at_2), Rejected::Missing(Missing::Epoch(2)));
    b.add(&b.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 2));
    b.add(&at_2);
}

/// Ruling 24 and `protocol.md` 4.6: `records()` yields the records in the
/// order they were stored, refused and duplicate ones left out, so a sender
/// can send it as it is and a receiver stores every record, in that order,
/// with no blame and no missing dependency (here K's grant to M, which only
/// D's later grant to K authorizes).
#[test]
fn ruling_24_records_come_in_the_order_they_were_stored() {
    let (d, k, m) = (set(20), set(21), set(22));
    let mut a = world();
    let root = root_set();
    let dk2 = DataKey::from_bytes([2; 32]);
    let gd = a.root_grant(&d, Tier::Write, true);
    let gk = a.root_grant(&k, Tier::Sealed, true);
    let d_to_k = a.grant_from(&d, id(&d), &k, Tier::Write, true, 0);
    let k_to_m = a.grant_from(&k, id(&k), &m, Tier::Write, false, 0);
    let suspension = a.suspension(&d, id(&d), id(&k), ActingTier::Read, 0);
    let rotation = a.rotation(&root, KeyId::ROOT, &dk2, &[], None, vec![], 2);
    let rival = a.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([9; 32]),
        &[],
        None,
        vec![],
        2,
    );
    let wrap = a.wrap_record(&root, KeyId::ROOT, &k, Tier::Write, 1);
    let lift = a.lift(&d, id(&d), suspension.hash());
    let order = [
        &gk,
        &gd,
        &rotation,
        &d_to_k,
        &suspension,
        &rival,
        &k_to_m,
        &wrap,
        &lift,
    ];
    for r in order {
        a.add(r);
        assert_eq!(a.keys.insert(r, NOW), Ok(Accepted::Duplicate(r.hash())));
    }
    let sent: Vec<SignedRecord> = a.keys.records().map(|(_, r)| r.clone()).collect();
    assert_eq!(sent[0], a.folder.record);
    assert_eq!(
        sent[1..].iter().map(SignedRecord::hash).collect::<Vec<_>>(),
        order.iter().map(|r| r.hash()).collect::<Vec<_>>()
    );
    let mut b = world();
    for r in &sent[1..] {
        assert!(matches!(b.keys.insert(r, NOW), Ok(Accepted::Stored { .. })));
    }
    assert_eq!(
        b.keys.records().map(|(h, _)| *h).collect::<Vec<_>>(),
        a.keys.records().map(|(h, _)| *h).collect::<Vec<_>>()
    );
}

/// Rulings 24 and 25, an ambiguous epoch: epoch 2 has two stored rotations,
/// so no key of it is used and no ladder rung through it is climbed. What a
/// record says of itself still blames its signer: a wrap that does not open
/// (HPKE), a rotation's own `KeyWrap` against its own `confirm` (step 8). Only
/// a check against the chain's `confirm`, then one chosen among rivals,
/// blames nobody.
#[test]
fn ruling_25_an_ambiguous_epoch_withholds_its_keys_and_blames_only_what_records_say_of_themselves()
{
    let mut w = world();
    let root = root_set();
    let a = set(10);
    let ga = w.root_grant(&a, Tier::Write, true);
    w.add(&ga);
    let dk = |b: u8| DataKey::from_bytes([b; 32]);
    let (dk2, dk3, dk9) = (dk(2), dk(3), dk(9));
    let to_a = [(KeyId::ROOT, &root, Tier::Root), (id(&a), &a, Tier::Write)];
    let view = vec![ga.hash()];
    let r2 = w.rotation(&root, KeyId::ROOT, &dk2, &to_a, None, view.clone(), 2);
    w.add(&r2);
    let grant_at_2 = |w: &World, dk: &DataKey, byte: u8| {
        issue_grant_deterministic(
            &a,
            id(&a),
            &at_epoch_2(w.folder_id(), &set(byte), dk, Tier::Read, false),
            &mut fixed_rng(1),
        )
        .unwrap()
        .0
    };
    let honest = grant_at_2(&w, &dk2, 40);
    let rivals_key = grant_at_2(&w, &dk9, 41);
    let unopenable = resigned(&grant_at_2(&w, &dk2, 42), &set(42), &a, |g| {
        g.wrapped_data_key = <wire::Grant as prost::Message>::decode(honest.body.as_slice())
            .unwrap()
            .wrapped_data_key;
    });
    for g in [&honest, &rivals_key, &unopenable] {
        w.add(g);
    }
    let unwrap_grant = |w: &World, g: &SignedRecord, holder: u8| {
        w.keys.unwrap_grant_data_key(&g.hash(), &set(holder)).err()
    };
    let blame_a_unwrap = Some(HolderError::Unwrap { signer: id(&a) });
    // While epoch 2 is clear: the honest key opens; the rival's key fails
    // the chain's confirm, and the wrap that does not open, both blame A.
    assert_eq!(unwrap_grant(&w, &honest, 40), None);
    assert_eq!(
        unwrap_grant(&w, &rivals_key, 41),
        Some(HolderError::ConfirmMismatch { signer: id(&a) })
    );
    assert_eq!(unwrap_grant(&w, &unopenable, 42), blame_a_unwrap);
    // The rival, and rotations that are wrong about themselves or carry a
    // ladder that does not open.
    let rival = w.rotation(&root, KeyId::ROOT, &dk9, &to_a, None, view.clone(), 2);
    w.add(&rival);
    assert!(w.keys.epoch_ambiguous(2));
    let changed = |w: &World, r: &SignedRecord, change: &dyn Fn(&mut RotationBody)| {
        let mut body = RotationBody::parse(&r.body).unwrap();
        change(&mut body);
        w.sign(&root, RecordType::Rotation, body.encode())
    };
    let folder = w.folder_id();
    let ladder = |new: &DataKey, epoch: u64, previous: &DataKey| {
        crate::epoch::LadderLink::seal(new, epoch, &folder, previous, &mut fixed_rng(6)).unwrap()
    };
    let own_confirm = changed(&w, &r2, &|b| b.confirm = dk9.confirm());
    let no_open = changed(&w, &r2, &|b| {
        let roots = b.wraps[0].wrapped_data_key.clone();
        b.wraps.retain(|x| x.key_id == KeyId::ROOT);
        b.wraps.push(KeyWrapEntry {
            key_id: id(&a),
            wrapped_data_key: roots,
        });
    });
    let bad_ladder = changed(&w, &r2, &|b| b.ladder = ladder(&dk9, 2, &w.dk1));
    for r in [&own_confirm, &no_open, &bad_ladder] {
        w.add(r);
    }
    let unwrap_rotation = |keys: &FolderKeys, r: &SignedRecord| {
        keys.unwrap_rotation_data_key(&r.hash(), &id(&a), &a).err()
    };
    let ambiguous = Some(HolderError::EpochAmbiguous(2));
    // Blamed as usual: step 8 against the rotation's own confirm, an HPKE
    // open that fails, for a rotation and for a grant.
    assert_eq!(
        unwrap_rotation(&w.keys, &own_confirm),
        Some(HolderError::ConfirmMismatch {
            signer: KeyId::ROOT
        })
    );
    assert_eq!(
        unwrap_rotation(&w.keys, &no_open),
        Some(HolderError::Unwrap {
            signer: KeyId::ROOT
        })
    );
    assert_eq!(unwrap_grant(&w, &unopenable, 42), blame_a_unwrap);
    // No key, and nobody blamed: rotations right about themselves, whatever
    // their ladder holds, which is not climbed; grants judged against the
    // chain's confirm, the honest one and the one with the rival's key.
    for r in [&r2, &rival, &bad_ladder] {
        assert_eq!(unwrap_rotation(&w.keys, r), ambiguous);
    }
    for r in [&r2, &bad_ladder] {
        assert_eq!(w.keys.climb_ladder(&r.hash(), &dk2).err(), ambiguous);
    }
    assert_eq!(unwrap_grant(&w, &honest, 40), ambiguous);
    assert_eq!(unwrap_grant(&w, &rivals_key, 41), ambiguous);
    // Epoch 3 is clear, but its rung leads into epoch 2: the key it yields
    // would be judged against a confirm chosen among rivals, so nothing comes
    // down it and nobody is blamed, whichever key it holds; a ladder that does
    // not open under epoch 3's own key still blames its rotator.
    let r3 = w.rotation(&root, KeyId::ROOT, &dk3, &to_a, None, view, 3);
    let r3_rivals_key = changed(&w, &r3, &|b| b.ladder = ladder(&dk3, 3, &dk9));
    let r3_broken = changed(&w, &r3, &|b| b.ladder = ladder(&dk9, 3, &dk2));
    let with = |r: &SignedRecord| {
        let mut keys = w.keys.clone();
        assert!(matches!(keys.insert(r, NOW), Ok(Accepted::Stored { .. })));
        assert!(!keys.epoch_ambiguous(3));
        keys
    };
    let keys = with(&r3);
    assert_eq!(unwrap_rotation(&keys, &r3), ambiguous);
    assert_eq!(keys.climb_ladder(&r3.hash(), &dk3).err(), ambiguous);
    assert_eq!(
        with(&r3_rivals_key)
            .climb_ladder(&r3_rivals_key.hash(), &dk3)
            .err(),
        ambiguous
    );
    assert_eq!(
        with(&r3_broken).climb_ladder(&r3_broken.hash(), &dk3).err(),
        Some(HolderError::Unwrap {
            signer: KeyId::ROOT
        })
    );
}

#[test]
fn production_signatures_are_hedged_for_grants_and_records() {
    // Two hedged issues of one sealed grant (no wrap, so one body) carry
    // different signatures, both of which verify; the deterministic form
    // repeats itself.
    let w = world();
    let k = set(10);
    let request = GrantRequest {
        folder_id: w.folder_id(),
        recipient: &k,
        tier: Tier::Sealed,
        may_share: false,
        expires_at: 0,
        epoch: 1,
        data_key: None,
        issued_at: 1,
        issuer_device_id: None,
    };
    let (g1, _) = issue_grant(w.root(), KeyId::ROOT, &request, &mut fixed_rng(1)).unwrap();
    let (g2, _) = issue_grant(w.root(), KeyId::ROOT, &request, &mut fixed_rng(2)).unwrap();
    assert_eq!(g1.body, g2.body);
    assert_ne!(g1.signature, g2.signature);
    assert_ne!(g1.key_signature, g2.key_signature);
    for g in [&g1, &g2] {
        let mut v = world();
        v.add(g);
    }
    let (d1, _) =
        issue_grant_deterministic(w.root(), KeyId::ROOT, &request, &mut fixed_rng(1)).unwrap();
    let (d2, _) =
        issue_grant_deterministic(w.root(), KeyId::ROOT, &request, &mut fixed_rng(2)).unwrap();
    assert_eq!(d1, d2);
    // sign_record over one body.
    let body = w.revocation(w.root(), KeyId::ROOT, id(&k), vec![]).body;
    let r1 = sign_record(
        w.root(),
        RecordType::Revocation,
        body.clone(),
        &mut fixed_rng(3),
    )
    .unwrap();
    let r2 = sign_record(
        w.root(),
        RecordType::Revocation,
        body.clone(),
        &mut fixed_rng(4),
    )
    .unwrap();
    assert_ne!(r1.signature, r2.signature);
    let pk = &w.folder.body.root_signing_pk;
    for r in [&r1, &r2] {
        let sig = crate::keyset::HybridSignature::from_bytes(&r.signature).unwrap();
        assert!(pk.verify(labels::SIG_REVOCATION, &body, &sig).is_ok());
    }
    // Two hedged folders over one body: the wrap's 64 bytes of randomness
    // are the same, the signature's differ.
    let ms = crate::secret::MasterSecret::from_bytes([1; 32]);
    let dk = DataKey::from_bytes([2; 32]);
    let genesis = FolderGenesis {
        master: &ms,
        nonce: crate::derive::FolderNonce([3; 32]),
        data_key: &dk,
        created_at: 1_700_000_000,
        required_features: vec![],
    };
    let make = |signature_byte: u8| {
        let mut used = 0usize;
        let mut rng = move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = if used < 64 { 0x11 } else { signature_byte };
                used += 1;
            }
        };
        create_folder(&genesis, &mut rng).unwrap()
    };
    let (f1, f2) = (make(1), make(2));
    assert_eq!(f1.record.body, f2.record.body);
    assert_ne!(f1.record.signature, f2.record.signature);
    for f in [f1, f2] {
        assert!(FolderKeys::new(&f.body.folder_id, f.record).is_ok());
    }
}

#[test]
fn bulk_load_rebuilds_the_same_set_and_lists_what_does_not_store() {
    let mut w = world();
    let (a, b, c) = (set(10), set(11), set(12));
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Write, true, 0));
    w.add(&w.grant_from(&b, id(&b), &c, Tier::Read, false, 0));
    w.add(&w.suspension(&a, id(&a), id(&c), ActingTier::Read, 0));
    let root = root_set();
    w.add(&w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes([2; 32]),
        &[],
        None,
        vec![],
        2,
    ));
    let stored: Vec<SignedRecord> = w.keys.records().map(|(_, r)| r.clone()).collect();
    for threads in [1, 3] {
        let (loaded, failures) = FolderKeys::load(
            &w.folder_id(),
            &stored,
            NOW,
            NonZeroUsize::new(threads).unwrap(),
        )
        .unwrap();
        assert!(failures.is_empty());
        let a_hashes: Vec<_> = loaded.records().map(|(h, _)| *h).collect();
        let b_hashes: Vec<_> = w.keys.records().map(|(h, _)| *h).collect();
        assert_eq!(a_hashes, b_hashes);
        assert_eq!(loaded.current_epoch(), 2);
        assert!(loaded.validity(NOW).is_presentable(&id(&c)));
    }
    // A damaged signature is caught on the sequential pass and listed.
    let mut damaged = stored.clone();
    damaged[2].signature = damaged[1].signature.clone();
    let (loaded, failures) =
        FolderKeys::load(&w.folder_id(), &damaged, NOW, NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(failures.first().map(|(_, e)| *e), Some(Rejected::Forged));
    assert!(!loaded.contains(&damaged[2].hash()));
    // No records, or another folder's Folder record, is an error.
    assert!(FolderKeys::load(&w.folder_id(), &[], NOW, NonZeroUsize::MIN).is_err());
    assert_eq!(
        FolderKeys::load(&FolderId([0; 32]), &stored, NOW, NonZeroUsize::MIN).err(),
        Some(Rejected::Malformed(Malformed::OtherFolder))
    );
}

/// Quality review SF 2: the bulk load spawned a worker even for one thread,
/// and `Scope::spawn` panics where no thread can start (always on
/// WebAssembly, the browser client's target). One thread now verifies on the
/// calling thread, and a part whose worker cannot start is verified there
/// too, with the same set as the result.
#[test]
fn bulk_load_does_not_panic_where_threads_cannot_start() {
    use super::load::{REFUSE_SPAWN, VERIFIED_HERE};
    let mut w = world();
    let (a, b) = (set(10), set(11));
    w.add(&w.root_grant(&a, Tier::Write, true));
    w.add(&w.grant_from(&a, id(&a), &b, Tier::Read, false, 0));
    w.add(&w.suspension(&a, id(&a), id(&b), ActingTier::Read, 0));
    let stored: Vec<SignedRecord> = w.keys.records().map(|(_, r)| r.clone()).collect();
    let expected: Vec<RecordHash> = w.keys.records().map(|(h, _)| *h).collect();
    let verified_here = |threads: usize| {
        let before = VERIFIED_HERE.with(core::cell::Cell::get);
        let (loaded, failures) = FolderKeys::load(
            &w.folder_id(),
            &stored,
            NOW,
            NonZeroUsize::new(threads).unwrap(),
        )
        .unwrap();
        assert!(failures.is_empty(), "{threads} threads");
        assert_eq!(
            loaded.records().map(|(h, _)| *h).collect::<Vec<_>>(),
            expected
        );
        assert!(loaded.validity(NOW).is_presentable(&id(&b)));
        VERIFIED_HERE.with(core::cell::Cell::get) - before
    };
    let after_the_folder = stored.len() - 1;
    assert_eq!(
        verified_here(1),
        after_the_folder,
        "no worker for one thread"
    );
    assert_eq!(verified_here(3), 0, "every part on a worker");
    REFUSE_SPAWN.with(|r| r.set(true));
    assert_eq!(
        verified_here(3),
        after_the_folder,
        "no worker could start: every part on the calling thread"
    );
    REFUSE_SPAWN.with(|r| r.set(false));
}

#[test]
fn holder_helpers_pick_the_governing_grant_and_derive_hk_from_dk_1_only() {
    let mut w = world();
    let k = set(10);
    let sealed = w.root_grant(&k, Tier::Sealed, false);
    let read = w.root_grant(&k, Tier::Read, false);
    w.add(&sealed);
    w.add(&read);
    let (epoch, dk) = w.keys.unwrap_governing_data_key(&id(&k), &k, NOW).unwrap();
    assert_eq!(epoch, 1);
    assert!(bool::from(dk.ct_eq(&w.dk1)));
    assert_eq!(
        w.keys
            .unwrap_governing_data_key(&id(&set(11)), &k, NOW)
            .err(),
        Some(HolderError::NotStored)
    );
    let hk = w.keys.chunk_hash_key(&w.dk1).unwrap();
    assert!(bool::from(hk.ct_eq(&w.dk1.chunk_hash_key())));
    assert!(w
        .keys
        .chunk_hash_key(&DataKey::from_bytes([9; 32]))
        .is_none());
    // The root key pair from the master secret, refused for another one.
    let folder = w.keys.folder();
    let ms = crate::secret::MasterSecret::from_bytes([1; 32]);
    let root = folder.root_key_pair(&ms).unwrap();
    assert_eq!(root.public().signing, folder.root_signing_pk);
    assert!(folder
        .root_key_pair(&crate::secret::MasterSecret::from_bytes([2; 32]))
        .is_none());
}

/// A grant body to clone for synthetic graphs: the search reads only the
/// key, issuer, tier, `may_share` and expiry.
fn template() -> &'static GrantBody {
    static T: OnceLock<GrantBody> = OnceLock::new();
    T.get_or_init(|| {
        let w = world();
        let mut g = GrantBody::parse(&w.root_grant(&set(10), Tier::Read, false).body).unwrap();
        g.wrapped_data_key = None;
        g
    })
}

fn kid(n: u32) -> KeyId {
    let mut b = [0x11u8; 16];
    b[..4].copy_from_slice(&n.to_be_bytes());
    KeyId(b)
}

fn rh(n: u64) -> RecordHash {
    let mut b = [0x22u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    RecordHash(b)
}

/// Stores a synthetic grant `n` of `key` from `issuer`.
fn fake(keys: &mut FolderKeys, n: u64, key: KeyId, issuer: KeyId, tier: Tier, may_share: bool) {
    fake_expiring(keys, n, key, issuer, tier, may_share, 0);
}

fn fake_expiring(
    keys: &mut FolderKeys,
    n: u64,
    key: KeyId,
    issuer: KeyId,
    tier: Tier,
    may_share: bool,
    expires_at: u64,
) {
    let mut g = template().clone();
    g.key_id = key;
    g.issuer_key_id = issuer;
    g.tier = tier;
    g.may_share = may_share;
    g.expires_at = expires_at;
    keys.store_grant_for_test(rh(n), g);
}

/// Every key on some authorizing walk of at most 16 grants from a grant of
/// `key` to root, by brute force over (grant, depth): the reference
/// [`super::validity`]'s two passes must agree with.
fn reference_ancestors(keys: &FolderKeys, key: KeyId) -> BTreeSet<KeyId> {
    let grants: Vec<(RecordHash, GrantBody)> = keys
        .grants_by_key
        .values()
        .flatten()
        .filter_map(|h| keys.grants_by_hash(h).map(|(h, g)| (*h, g.clone())))
        .collect();
    // reaches[(grant, d)]: from this grant, root within d more grants (d >= 1).
    let mut reaches: BTreeMap<(RecordHash, usize), bool> = BTreeMap::new();
    for d in 1..=MAX_CHAIN_DEPTH {
        for (h, g) in &grants {
            let r = g.issuer_key_id.is_root()
                || grants.iter().any(|(ph, p)| {
                    p.key_id == g.issuer_key_id
                        && p.may_share
                        && p.tier <= g.tier
                        && d > 1
                        && reaches[&(*ph, d - 1)]
                });
            reaches.insert((*h, d), r);
        }
    }
    // Forward from the key's grants: the grants at each position.
    let mut out = BTreeSet::new();
    let mut frontier: BTreeSet<RecordHash> = grants
        .iter()
        .filter(|(_, g)| g.key_id == key)
        .map(|(h, _)| *h)
        .collect();
    for position in 1..=MAX_CHAIN_DEPTH {
        let mut next = BTreeSet::new();
        for h in &frontier {
            let g = &grants.iter().find(|(x, _)| x == h).unwrap().1;
            if position > 1 && g.key_id != key && reaches[&(*h, MAX_CHAIN_DEPTH + 1 - position)] {
                out.insert(g.key_id);
            }
            for (ph, p) in &grants {
                if p.key_id == g.issuer_key_id && p.may_share && p.tier <= g.tier {
                    next.insert(*ph);
                }
            }
        }
        frontier = next;
    }
    out
}

/// Whether `grant` begins a chain (no key twice) of at most 16 grants, by
/// depth-first search over simple paths.
fn reference_begins_chain(keys: &FolderKeys, grant: &RecordHash) -> bool {
    fn go(keys: &FolderKeys, g: &GrantBody, seen: &mut Vec<KeyId>, depth: usize) -> bool {
        if depth > MAX_CHAIN_DEPTH {
            return false;
        }
        if g.issuer_key_id.is_root() {
            return true;
        }
        if seen.contains(&g.issuer_key_id) {
            return false;
        }
        seen.push(g.issuer_key_id);
        let found = keys
            .grants_for(&g.issuer_key_id)
            .any(|(_, p)| p.may_share && p.tier <= g.tier && go(keys, p, seen, depth + 1));
        seen.pop();
        found
    }
    let g = keys.grants_by_hash(grant).unwrap().1.clone();
    go(keys, &g, &mut vec![g.key_id], 1)
}

/// A random edge of a synthetic grant graph: key, issuer (`keys` stands for
/// root), tier number, `may_share`, and expiry (none, now, after now).
type Edge = (u32, u32, u8, bool, u8);

fn tier_of(n: u8) -> Tier {
    match n {
        1 => Tier::Write,
        2 => Tier::Read,
        _ => Tier::Sealed,
    }
}

/// Stores `edges` over the keys `kid(0..keys)`, from record number `first`;
/// indices wrap, and an edge from a key to itself is left out.
fn add_edges(store: &mut FolderKeys, edges: &[Edge], keys: u32, first: u64) {
    for (n, (key, issuer, tier, share, expiry)) in edges.iter().enumerate() {
        let key = kid(key % keys);
        let issuer = match issuer % (keys + 1) {
            i if i == keys => KeyId::ROOT,
            i => kid(i),
        };
        if issuer == key {
            continue;
        }
        let expires_at = match expiry {
            0 => 0,
            1 => NOW,
            _ => NOW + 1,
        };
        fake_expiring(
            store,
            first + n as u64,
            key,
            issuer,
            tier_of(*tier),
            *share,
            expires_at,
        );
    }
}

/// The properties of the brute-force tests over the keys `ids` of a
/// synthetic store: the stored-walk shortcuts and the full searches agree,
/// the forward ancestry, the backward "beneath" and `is_ancestor` agree with
/// a brute-force reference, and per-grant chain existence agrees with a
/// simple-path search.
fn searches_agree(keys: &FolderKeys, ids: &[KeyId]) -> Result<(), TestCaseError> {
    let v = keys.validity(NOW);
    // A held set with one unrelated grant turns the stored-walk shortcuts
    // off: the full searches must give the same answers.
    let mut held = HeldGrants::new(keys.folder_id());
    held.pad_for_test(template(), 1);
    let exact = keys.validity_with(&held, NOW);
    for k in ids {
        prop_assert_eq!(v.is_chain_valid(k), exact.is_chain_valid(k));
        prop_assert_eq!(
            v.governing_grant(k).map(|(h, _)| *h),
            exact.governing_grant(k).map(|(h, _)| *h)
        );
        prop_assert_eq!(
            grant_hashes(&v.canonical_chain(k)),
            grant_hashes(&exact.canonical_chain(k))
        );
        prop_assert_eq!(v.presentable_tier(k), exact.presentable_tier(k));
        prop_assert_eq!(
            grant_hashes(&v.presentable_chain(k)),
            grant_hashes(&exact.presentable_chain(k))
        );
        for tier in [Tier::Write, Tier::Read, Tier::Sealed] {
            prop_assert_eq!(v.may_issue(k, tier), exact.may_issue(k, tier));
        }
        prop_assert_eq!(v.ancestors(k), exact.ancestors(k));
        for (h, _) in keys.grants_for(k) {
            prop_assert_eq!(v.is_grant_valid(h), exact.is_grant_valid(h));
        }
    }
    let beneath: BTreeMap<KeyId, BTreeSet<KeyId>> = ids
        .iter()
        .map(|top| (*top, keys.stored_grants().beneath(top)))
        .collect();
    for key in ids {
        let ancestors = v.ancestors(key);
        prop_assert_eq!(&ancestors, &reference_ancestors(keys, *key));
        for top in ids {
            prop_assert_eq!(ancestors.contains(top), beneath[top].contains(key));
            prop_assert_eq!(
                ancestors.contains(top),
                keys.stored_grants().is_ancestor(top, key)
            );
        }
        for (h, _) in keys.grants_for(key) {
            prop_assert_eq!(v.is_grant_valid(h), reference_begins_chain(keys, h));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, .. ProptestConfig::default() })]

    /// Random grant graphs over eight keys.
    #[test]
    fn the_searches_agree_with_brute_force(
        edges in prop::collection::vec((0u32..8, 0u32..9, 1u8..=3, any::<bool>(), 0u8..3), 1..24)
    ) {
        let mut keys = world().keys;
        add_edges(&mut keys, &edges, 8, 0);
        searches_agree(&keys, &(0..8).map(kid).collect::<Vec<_>>())?;
    }

    /// Graphs whose walks reach 15 to 18 grants, on both sides of the
    /// 16-grant bound (quality review SF 1): a spine of `len` keys from root,
    /// each issued by the one above with `may_share` (the last perhaps
    /// without), at tiers that only become less privileged going down; a
    /// few random edges among the spine and three more keys, which add
    /// shortcuts, loops and branches; and perhaps, arriving last, a write
    /// grant with `may_share` from root to the spine's second, third or
    /// fourth key, which shortens every walk below it after its levels were
    /// kept.
    #[test]
    fn the_searches_agree_with_brute_force_near_the_depth_bound(
        len in 15u32..=18,
        tiers in prop::collection::vec(1u8..=3, 18),
        last_shares in any::<bool>(),
        edges in prop::collection::vec((0u32..21, 0u32..22, 1u8..=3, any::<bool>(), 0u8..3), 0..6),
        shortcut in prop::option::of(1u32..4),
    ) {
        let mut keys = world().keys;
        let mut spine: Vec<u8> = tiers[..len as usize].to_vec();
        spine.sort_unstable();
        for (i, tier) in (0..len).zip(spine) {
            let issuer = if i == 0 { KeyId::ROOT } else { kid(i - 1) };
            let share = i + 1 < len || last_shares;
            fake(&mut keys, u64::from(i), kid(i), issuer, tier_of(tier), share);
        }
        add_edges(&mut keys, &edges, len + 3, u64::from(len));
        if let Some(to) = shortcut {
            fake(&mut keys, 100, kid(to), KeyId::ROOT, Tier::Write, true);
        }
        searches_agree(&keys, &(0..len + 3).map(kid).collect::<Vec<_>>())?;
    }
}

/// The attacker shapes of the security review, at `scale` grants: a key with
/// many grants whose children each need it (fan-out), keys that loop through
/// their descendants, and a flat tree under root.
fn shapes(scale: usize) -> Vec<(&'static str, FolderKeys, KeyId)> {
    let w = world();
    let mut out = Vec::new();
    // Fan-out: I holds m grants from root, and c children each from I.
    let mut fan = w.keys.clone();
    let m = scale / 2;
    for j in 0..m {
        fake(&mut fan, j as u64, kid(1), KeyId::ROOT, Tier::Write, true);
    }
    for j in 0..scale - m {
        fake(
            &mut fan,
            (m + j) as u64,
            kid(1000 + j as u32),
            kid(1),
            Tier::Read,
            false,
        );
    }
    out.push(("multi-grant fan-out", fan, kid(1000)));
    // Looping keys: a chain of 16 keys from root, each key also re-granted
    // by every key below it.
    let mut looping = w.keys.clone();
    let mut n = 0u64;
    for depth in 0..16u32 {
        let issuer = if depth == 0 { KeyId::ROOT } else { kid(depth) };
        fake(&mut looping, n, kid(depth + 1), issuer, Tier::Write, true);
        n += 1;
    }
    'outer: loop {
        for from in 2..=16u32 {
            for to in 1..from {
                if n as usize >= scale {
                    break 'outer;
                }
                fake(&mut looping, n, kid(to), kid(from), Tier::Write, true);
                n += 1;
            }
        }
    }
    out.push(("looping keys", looping, kid(16)));
    // A dense mesh: k keys from root, each also granted by every other, so
    // every (key, issuer) pair is its own group: the shape grouping cannot
    // shrink.
    let mut mesh = w.keys.clone();
    let k = (1..=scale).find(|k: &usize| k * k >= scale).unwrap_or(1);
    let mut n = 0u64;
    'mesh: for key in 0..k as u32 {
        for issuer in 0..=k as u32 {
            if n as usize >= scale {
                break 'mesh;
            }
            if issuer == key {
                continue;
            }
            let from = if issuer == k as u32 {
                KeyId::ROOT
            } else {
                kid(issuer + 1)
            };
            fake(&mut mesh, n, kid(key + 1), from, Tier::Write, true);
            n += 1;
        }
    }
    out.push(("dense mesh", mesh, kid(1)));
    // A flat tree: every key straight from root.
    let mut flat = w.keys.clone();
    for j in 0..scale {
        fake(
            &mut flat,
            j as u64,
            kid(j as u32 + 1),
            KeyId::ROOT,
            Tier::Write,
            true,
        );
    }
    out.push(("flat tree", flat, kid(1)));
    out
}

/// Runs the questions an insertion asks of an issuer or signer `key` (its
/// governing grant and chain validity, step 9's check, entitlement through
/// ancestry, the canonical chain a push carries) and returns the grants
/// examined.
fn insert_cost(keys: &FolderKeys, key: KeyId) -> u64 {
    VISITS.with(|v| v.set(0));
    let v = keys.validity(NOW);
    let _ = v.governing_grant(&key);
    let _ = v.is_chain_valid(&key);
    let _ = keys.stored_grants().has_chain_avoiding(&key, &|_| false);
    let _ = keys.in_subtree(&key, &kid(2));
    let _ = v.canonical_chain(&key);
    VISITS.with(std::cell::Cell::get)
}

/// The questions a handshake asks of `key` (presentability, its tier and
/// chain, whether it may issue) and those of a revocation's scope.
fn handshake_cost(keys: &FolderKeys, key: KeyId) -> u64 {
    VISITS.with(|v| v.set(0));
    let v = keys.validity(NOW);
    let _ = v.is_presentable(&key);
    let _ = v.presentable_chain(&key);
    let _ = v.may_issue(&key, Tier::Read);
    let _ = keys.stored_grants().beneath(&key);
    VISITS.with(std::cell::Cell::get)
}

fn cost(keys: &FolderKeys, key: KeyId) -> u64 {
    insert_cost(keys, key) + handshake_cost(keys, key)
}

#[test]
fn the_searches_stay_linear_in_attacker_shapes() {
    // The work for one key's questions grows with the grants, not with their
    // square: doubling the store at most a little more than doubles it.
    for (name, small_keys, key) in shapes(1_000) {
        let small = cost(&small_keys, key);
        let large_keys = shapes(2_000)
            .into_iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, k, _)| k)
            .unwrap();
        let large = cost(&large_keys, key);
        assert!(
            large <= small.saturating_mul(3).max(64),
            "{name}: {small} grants examined at 1 000, {large} at 2 000"
        );
        // And the absolute bound: a few hundred passes over the grants.
        assert!(large <= 2_000 * 400, "{name}: {large}");
    }
}

/// The timings at the cap the reviews asked for, printed for the report;
/// `cargo test --release -p licketysync-keys -- --ignored --nocapture
/// timings_at_the_cap` runs it.
#[test]
#[ignore = "a measurement, run by hand in release"]
fn timings_at_the_cap() {
    use std::time::Instant;
    for (name, keys, key) in shapes(MAX_KEY_RECORDS_PER_FOLDER - 1) {
        let start = Instant::now();
        let visits = insert_cost(&keys, key);
        let insert = start.elapsed();
        let start = Instant::now();
        let handshake_visits = handshake_cost(&keys, key);
        let handshake = start.elapsed();
        println!(
            "{name} at {} grants: an insertion's questions {insert:?} ({visits} grants examined), a handshake's {handshake:?} ({handshake_visits})",
            keys.len() - 1,
        );
    }
    // Each insertion question on its own, in the widest shape.
    let (_, mesh, key) = shapes(MAX_KEY_RECORDS_PER_FOLDER - 1).remove(2);
    let v = mesh.validity(NOW);
    let each: [(&str, &dyn Fn()); 5] = [
        ("governing grant", &|| {
            let _ = v.governing_grant(&key);
        }),
        ("chain-valid", &|| {
            let _ = v.is_chain_valid(&key);
        }),
        ("step 9", &|| {
            let _ = mesh.stored_grants().has_chain_avoiding(&key, &|_| false);
        }),
        ("entitlement", &|| {
            let _ = mesh.in_subtree(&key, &kid(2));
        }),
        ("canonical chain", &|| {
            let _ = v.canonical_chain(&key);
        }),
    ];
    for (name, question) in each {
        VISITS.with(|c| c.set(0));
        let start = Instant::now();
        question();
        println!(
            "dense mesh, {name}: {:?} ({} grants examined)",
            start.elapsed(),
            VISITS.with(std::cell::Cell::get)
        );
    }
    // Building each shape grant by grant keeps the walk levels: the whole
    // rebuild's chain work, apart from signatures.
    for (name, keys, _) in shapes(MAX_KEY_RECORDS_PER_FOLDER - 1) {
        let grants: Vec<(RecordHash, GrantBody)> = keys
            .records()
            .skip(1)
            .filter_map(|(h, _)| keys.grants_by_hash(h).map(|(h, g)| (*h, g.clone())))
            .collect();
        let mut again = world().keys.clone();
        let start = Instant::now();
        for (h, g) in grants {
            again.store_grant_for_test(h, g);
        }
        println!(
            "{name}: storing every grant with its walk levels: {:?}",
            start.elapsed()
        );
    }
}

/// A rebuild of a store at the cap from real signed records, and one more
/// insertion: `cargo test --release -p licketysync-keys -- --ignored
/// --nocapture rebuild_at_the_cap`.
#[test]
#[ignore = "a measurement, run by hand in release"]
fn rebuild_at_the_cap() {
    use std::time::Instant;
    let w = world();
    let threads = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    // 255 may_share write keys from root, each issuing up to 256 read keys.
    let start = Instant::now();
    let issuers: Vec<KeyPairSet> = (0..255u32)
        .map(|i| KeyPairSet::from_seed(&crate::secret::Seed::from_bytes(seed(0, i))).unwrap())
        .collect();
    let mut records = vec![w.folder.record.clone()];
    for issuer in &issuers {
        records.push(w.root_grant(issuer, Tier::Write, true));
    }
    // The store's cap is whichever quota binds first: grants with two hybrid
    // signatures are about 10 KB, so the 512 MiB byte budget binds before
    // the 65 536-record count. Fill to one grant below it.
    let sample = w.grant_from(
        &issuers[0],
        id(&issuers[0]),
        &issuers[1],
        Tier::Sealed,
        false,
        0,
    );
    let size = prost::Message::encoded_len(&sample);
    let total = (MAX_KEY_RECORD_BYTES_PER_FOLDER / size).min(MAX_KEY_RECORDS_PER_FOLDER) - 1;
    println!("a sealed grant is {size} bytes; filling to {total} records");
    let per = (total - records.len()).div_ceil(issuers.len());
    let jobs: Vec<(usize, usize)> = (0..issuers.len())
        .flat_map(|i| (0..per).map(move |j| (i, j)))
        .take(total - records.len())
        .collect();
    let chunk = jobs.len().div_ceil(threads.get());
    let children: Vec<SignedRecord> = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|part| {
                let (issuers, w) = (&issuers, &w);
                scope.spawn(move || {
                    part.iter()
                        .map(|&(i, j)| {
                            let child = KeyPairSet::from_seed(&crate::secret::Seed::from_bytes(
                                seed(1 + i as u32, j as u32),
                            ))
                            .unwrap();
                            w.grant_from(
                                &issuers[i],
                                id(&issuers[i]),
                                &child,
                                Tier::Sealed,
                                false,
                                0,
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    records.extend(children);
    println!(
        "generated {} records in {:?}",
        records.len(),
        start.elapsed()
    );
    let start = Instant::now();
    for r in &records[1..] {
        let _ = GrantBody::parse(&r.body);
    }
    println!(
        "parsing every grant body once, on one thread: {:?}",
        start.elapsed()
    );
    let start = Instant::now();
    let (mut keys, failures) = FolderKeys::load(&w.folder_id(), &records, NOW, threads).unwrap();
    println!(
        "bulk load of {} records on {threads} threads: {:?} ({} failures)",
        keys.len(),
        start.elapsed(),
        failures.len()
    );
    if let Some(first) = failures.first() {
        println!("first failure: {first:?}");
    }
    assert!(failures.is_empty());
    let start = Instant::now();
    let (_, single) = FolderKeys::load(&w.folder_id(), &records, NOW, NonZeroUsize::MIN).unwrap();
    println!("the same on one thread: {:?}", start.elapsed());
    assert!(single.is_empty());
    let extra = KeyPairSet::from_seed(&crate::secret::Seed::from_bytes(seed(9_999, 0))).unwrap();
    let record = w.grant_from(&issuers[7], id(&issuers[7]), &extra, Tier::Sealed, false, 0);
    let start = Instant::now();
    keys.insert(&record, NOW).unwrap();
    println!(
        "one insertion at {} records: {:?}",
        keys.len(),
        start.elapsed()
    );
    let start = Instant::now();
    let v = keys.validity(NOW);
    assert!(v.is_presentable(&id(&extra)));
    let _ = v.ancestors(&id(&extra));
    println!(
        "one key's handshake questions at the cap: {:?}",
        start.elapsed()
    );
}

fn seed(a: u32, b: u32) -> [u8; 32] {
    let mut s = [0x33u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    s[4..8].copy_from_slice(&b.to_be_bytes());
    s
}
