// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Grant body (`keys.md` section 5.3) and issuing a key (section 4).
//! Verification against the folder's records (section 5.4) is
//! [`super::FolderKeys::insert`].

use core::fmt;

use prost::Message as _;

use super::{
    check_prefix, decode_bounded, issued_key_id_field, key_id_field, wire, Hedge, Malformed,
    RecordType, Rejected, Shape, SignedRecord,
};
use crate::derive;
use crate::ids::{DeviceId, FolderId, KeyId};
use crate::keyset::{HybridSignature, KemPublicKey, KeyPairSet, SignError, SigningPublicKey};
use crate::labels;
use crate::rng::RandomFill;
use crate::secret::DataKey;
use crate::suite::{Suite, Tier};
use crate::wrap::{wrap_data_key, WrapAad, WrapError, WrappedDataKey};

/// The longest chain of grants to root; a grant at the end of a longer one is
/// not chain-valid (sections 5.4 step 5 and 5.5, judged at use).
pub const MAX_CHAIN_DEPTH: usize = 16;

/// A parsed Grant body (section 5.3). Parsing checks every size and range of
/// section 5.4 step 1 except `suite >= minimum_suite`, which needs the folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantBody {
    /// Suite of the issued key and of this record.
    pub suite: Suite,
    /// The folder.
    pub folder_id: FolderId,
    /// `H("licketysync/v1/hash/id/key", be16(suite) || signing_pk || kem_pk)[0..16]`,
    /// recomputed at parse.
    pub key_id: KeyId,
    /// Write, read or sealed.
    pub tier: Tier,
    /// The holder may issue keys at or below its tier and revoke, suspend and lift them.
    pub may_share: bool,
    /// Unix seconds; `0` = never.
    pub expires_at: u64,
    /// [`KeyId::ROOT`], or the key ID of a `may_share` key.
    pub issuer_key_id: KeyId,
    /// Epoch of the wrapped data key, at least 1.
    pub epoch: u64,
    /// The issued key's hybrid signing public key.
    pub signing_pk: SigningPublicKey,
    /// The issued key's X-Wing public key.
    pub kem_pk: KemPublicKey,
    /// `dk_epoch` wrapped to `kem_pk`; `None` if and only if the tier is sealed.
    pub wrapped_data_key: Option<WrappedDataKey>,
    /// Informational.
    pub issued_at: u64,
    /// The device that issued, shown as "issued by".
    pub issuer_device_id: Option<DeviceId>,
}

impl GrantBody {
    /// Parses a body and runs section 5.4 step 1 (minus the minimum suite).
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`], or [`Rejected::ValidityOnly`] for a suite this
    /// release does not implement.
    pub fn parse(body: &[u8]) -> Result<GrantBody, Rejected> {
        let w: wire::Grant = decode_bounded(body, &Shape::new(14, &[1, 2, 5], &[]))?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Grant)?;
        let tier = Tier::from_grant_wire(w.tier).ok_or(Malformed::Range("tier"))?;
        if w.epoch == 0 {
            return Err(Malformed::Range("epoch").into());
        }
        let signing_pk = SigningPublicKey::parse(&w.signing_pk)
            .map_err(|_| Malformed::FieldSize("signing_pk"))?;
        let kem_pk = KemPublicKey::parse(&w.kem_pk).map_err(|_| Malformed::FieldSize("kem_pk"))?;
        let wrapped_data_key = match (tier, w.wrapped_data_key.is_empty()) {
            (Tier::Sealed, true) => None,
            (Tier::Sealed, false) | (_, true) => {
                return Err(Malformed::Range("wrapped_data_key").into())
            }
            (_, false) => Some(
                WrappedDataKey::from_slice(&w.wrapped_data_key)
                    .ok_or(Malformed::FieldSize("wrapped_data_key"))?,
            ),
        };
        let key_id = issued_key_id_field(&w.key_id, "key_id")?;
        if derive::key_id(suite, &signing_pk, &kem_pk) != key_id {
            return Err(Malformed::KeyIdMismatch.into());
        }
        let issuer_key_id = key_id_field(&w.issuer_key_id, "issuer_key_id")?;
        if issuer_key_id == key_id {
            return Err(Malformed::SelfIssued.into());
        }
        let issuer_device_id = match w.issuer_device_id.len() {
            0 => None,
            _ => Some(
                DeviceId::from_slice(&w.issuer_device_id)
                    .ok_or(Malformed::FieldSize("issuer_device_id"))?,
            ),
        };
        Ok(GrantBody {
            suite,
            folder_id: FolderId::from_slice(&w.folder_id)
                .ok_or(Malformed::FieldSize("folder_id"))?,
            key_id,
            tier,
            may_share: w.may_share,
            expires_at: w.expires_at,
            issuer_key_id,
            epoch: w.epoch,
            signing_pk,
            kem_pk,
            wrapped_data_key,
            issued_at: w.issued_at,
            issuer_device_id,
        })
    }

    /// Verifies the proof of possession (section 5.4 step 2): the envelope's
    /// `key_signature`, made by the issued key over the body as received, under
    /// the grant's own `signing_pk`. Only a holder of the key's private half
    /// can make it, so nobody can grant a key that is not theirs to grant.
    ///
    /// # Errors
    ///
    /// [`Rejected::Forged`] when it is missing or does not verify;
    /// [`Rejected::Malformed`] when it is not 3373 bytes.
    pub fn verify_possession(&self, record: &SignedRecord) -> Result<(), Rejected> {
        if record.key_signature.is_empty() {
            return Err(Rejected::Forged);
        }
        let signature = HybridSignature::from_bytes(&record.key_signature)
            .map_err(|_| Malformed::SignatureSize(record.key_signature.len()))?;
        self.signing_pk
            .verify(labels::SIG_GRANT_POP, &record.body, &signature)
            .map_err(|_| Rejected::Forged)
    }

    /// The canonical encoding (section 5.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::Grant {
            suite: self.suite.to_wire(),
            record_type: RecordType::Grant.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            key_id: self.key_id.0.to_vec(),
            tier: self.tier.to_wire(),
            may_share: self.may_share,
            expires_at: self.expires_at,
            issuer_key_id: self.issuer_key_id.0.to_vec(),
            epoch: self.epoch,
            signing_pk: self.signing_pk.as_bytes().to_vec(),
            kem_pk: self.kem_pk.as_bytes().to_vec(),
            wrapped_data_key: self
                .wrapped_data_key
                .as_ref()
                .map(|w| w.as_bytes().to_vec())
                .unwrap_or_default(),
            issued_at: self.issued_at,
            issuer_device_id: self
                .issuer_device_id
                .map(|d| d.0.to_vec())
                .unwrap_or_default(),
        }
        .encode_to_vec()
    }

    /// The associated data of this grant's wrap: `folder_id || key_id ||
    /// u8(tier) || be64(epoch)`, rebuilt from the grant's own fields.
    #[must_use]
    pub fn wrap_aad(&self) -> WrapAad {
        WrapAad {
            folder_id: self.folder_id,
            key_id: self.key_id,
            tier: self.tier,
            epoch: self.epoch,
        }
    }

    /// Whether the key may present at `now_unix` as far as this grant alone
    /// goes: `expires_at` is `0` or later than now.
    #[must_use]
    pub fn unexpired_at(&self, now_unix: u64) -> bool {
        self.expires_at == 0 || now_unix < self.expires_at
    }
}

/// What the issuer wants to grant.
#[derive(Debug)]
pub struct GrantRequest<'a> {
    /// The folder.
    pub folder_id: FolderId,
    /// The new key (`KeyPairSet::from_seed` on a fresh seed): its private
    /// half signs the proof of possession, so only the key's holder, or its
    /// issuer at mint time, can create a grant for it.
    pub recipient: &'a KeyPairSet,
    /// Write, read or sealed; never root.
    pub tier: Tier,
    /// Whether the new key may issue in turn.
    pub may_share: bool,
    /// Unix seconds, `0` = never.
    pub expires_at: u64,
    /// The epoch of `data_key`.
    pub epoch: u64,
    /// The data key of `epoch`, for write and read; `None` for sealed.
    pub data_key: Option<&'a DataKey>,
    /// Informational issue time, Unix seconds.
    pub issued_at: u64,
    /// The issuing device, shown as "issued by".
    pub issuer_device_id: Option<DeviceId>,
}

/// Why a grant could not be issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// Root never appears in a grant.
    RootTier,
    /// Epoch 0 never occurs.
    ZeroEpoch,
    /// A write or read grant needs the data key; a sealed one must not carry it.
    DataKey,
    /// The wrap failed.
    Wrap(WrapError),
    /// Signing failed.
    Sign(SignError),
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootTier => f.write_str("root is never granted"),
            Self::ZeroEpoch => f.write_str("epoch 0 never occurs"),
            Self::DataKey => {
                f.write_str("write and read grants carry the data key, sealed grants never do")
            }
            Self::Wrap(e) => write!(f, "{e}"),
            Self::Sign(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IssueError {}

/// Issues a grant (section 4): derives the key ID from the recipient's
/// public keys, wraps the data key to the recipient for write and read, has
/// the recipient sign the proof of possession, and signs with `issuer`, whose
/// key ID is `issuer_key_id` ([`KeyId::ROOT`] for root). Whether the issuer may issue this grant is the caller's question
/// to [`super::FolderKeys`] (`is_presentable` and the issuer's governing
/// grant); every verifier checks it again.
///
/// Both signatures are hedged.
///
/// # Errors
///
/// [`IssueError`].
pub fn issue_grant(
    issuer: &KeyPairSet,
    issuer_key_id: KeyId,
    request: &GrantRequest<'_>,
    rng: &mut RandomFill<'_>,
) -> Result<(SignedRecord, GrantBody), IssueError> {
    issue_grant_with(issuer, issuer_key_id, request, Hedge::Hedged, rng)
}

/// [`issue_grant`] with deterministic signatures, for test vectors only;
/// `rng` still supplies the wrap's encapsulation randomness.
///
/// # Errors
///
/// [`IssueError`].
#[cfg(any(test, feature = "test-vectors"))]
pub fn issue_grant_deterministic(
    issuer: &KeyPairSet,
    issuer_key_id: KeyId,
    request: &GrantRequest<'_>,
    rng: &mut RandomFill<'_>,
) -> Result<(SignedRecord, GrantBody), IssueError> {
    issue_grant_with(issuer, issuer_key_id, request, Hedge::Deterministic, rng)
}

fn issue_grant_with(
    issuer: &KeyPairSet,
    issuer_key_id: KeyId,
    request: &GrantRequest<'_>,
    hedge: Hedge,
    rng: &mut RandomFill<'_>,
) -> Result<(SignedRecord, GrantBody), IssueError> {
    if request.tier == Tier::Root {
        return Err(IssueError::RootTier);
    }
    if request.epoch == 0 {
        return Err(IssueError::ZeroEpoch);
    }
    let suite = Suite::ONE;
    let recipient = request.recipient.public();
    let key_id = recipient.key_id(suite);
    let aad = WrapAad {
        folder_id: request.folder_id,
        key_id,
        tier: request.tier,
        epoch: request.epoch,
    };
    let wrapped_data_key = match (request.tier.can_read(), request.data_key) {
        (true, Some(dk)) => {
            Some(wrap_data_key(&recipient.kem, &aad, dk, rng).map_err(IssueError::Wrap)?)
        }
        (false, None) => None,
        _ => return Err(IssueError::DataKey),
    };
    let body = GrantBody {
        suite,
        folder_id: request.folder_id,
        key_id,
        tier: request.tier,
        may_share: request.may_share,
        expires_at: request.expires_at,
        issuer_key_id,
        epoch: request.epoch,
        signing_pk: recipient.signing.clone(),
        kem_pk: recipient.kem.clone(),
        wrapped_data_key,
        issued_at: request.issued_at,
        issuer_device_id: request.issuer_device_id,
    };
    let bytes = body.encode();
    let key_signature = hedge
        .sign(request.recipient, labels::SIG_GRANT_POP, &bytes, rng)
        .map_err(IssueError::Sign)?;
    let signature = hedge
        .sign(issuer, RecordType::Grant.sig_label(), &bytes, rng)
        .map_err(IssueError::Sign)?;
    let record = SignedRecord {
        body: bytes,
        signature: signature.as_bytes().to_vec(),
        key_signature: key_signature.as_bytes().to_vec(),
    };
    Ok((record, body))
}

/// The public half of a grant as a proof verifier needs it before it
/// verifies the chain (`protocol.md` 3.5): the suite and the issued key's
/// hybrid signing key. The protocol crate's `GrantKey` is
/// `{ suite: suite.as_u16(), signing_public_key: signing_pk.as_bytes() }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantKey {
    /// The grant's suite.
    pub suite: Suite,
    /// The issued key's hybrid signing public key.
    pub signing_pk: SigningPublicKey,
}

/// Reads a grant record of `folder` without verifying or storing anything:
/// its key ID and signing key, so that a `FolderProof`'s signature can be
/// checked against the leaf grant before the chain is (round 4 ruling, nit
/// 11). The parse is section 5.4 step 1 (sizes, ranges, the key ID's
/// recomputation from both public keys); `None` for anything that is not a
/// well-formed grant of `folder` under an implemented suite. Nothing returned
/// here is trusted until [`super::FolderKeys::insert`] has verified the grant.
#[must_use]
pub fn leaf_grant(folder: &FolderId, record: &SignedRecord) -> Option<(KeyId, GrantKey)> {
    let grant = GrantBody::parse(&record.body).ok()?;
    (grant.folder_id == *folder).then_some((
        grant.key_id,
        GrantKey {
            suite: grant.suite,
            signing_pk: grant.signing_pk,
        },
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;
    use crate::records::folder::tests::fixed_rng;
    use crate::records::Validity;
    use crate::secret::Seed;

    fn recipient(byte: u8) -> KeyPairSet {
        KeyPairSet::from_seed(&Seed::from_bytes([byte; 32])).unwrap()
    }

    fn request<'a>(r: &'a KeyPairSet, tier: Tier, dk: Option<&'a DataKey>) -> GrantRequest<'a> {
        GrantRequest {
            folder_id: FolderId([1; 32]),
            recipient: r,
            tier,
            may_share: true,
            expires_at: 0,
            epoch: 1,
            data_key: dk,
            issued_at: 5,
            issuer_device_id: Some(DeviceId([4; 32])),
        }
    }

    #[test]
    fn issue_round_trips_through_parse() {
        let issuer = recipient(1);
        let r = recipient(2);
        let dk = DataKey::from_bytes([3; 32]);
        let (rec, body) = issue_grant_deterministic(
            &issuer,
            KeyId::ROOT,
            &request(&r, Tier::Write, Some(&dk)),
            &mut fixed_rng(1),
        )
        .unwrap();
        assert_eq!(GrantBody::parse(&rec.body).unwrap(), body);
        assert_eq!(body.encode(), rec.body);
        assert_eq!(body.key_id, r.public().key_id(Suite::ONE));
        assert_eq!(body.verify_possession(&rec), Ok(()));
        let opened = crate::wrap::unwrap_data_key(
            &r,
            &body.wrap_aad(),
            body.wrapped_data_key.as_ref().unwrap(),
        )
        .unwrap();
        assert!(bool::from(opened.ct_eq(&dk)));
        let (sealed, sbody) = issue_grant_deterministic(
            &issuer,
            KeyId::ROOT,
            &request(&r, Tier::Sealed, None),
            &mut fixed_rng(1),
        )
        .unwrap();
        assert!(sbody.wrapped_data_key.is_none());
        assert_eq!(GrantBody::parse(&sealed.body).unwrap(), sbody);
        assert!(body.unexpired_at(u64::MAX));
    }

    #[test]
    fn tm_9_a_grant_needs_its_holders_proof_of_possession() {
        let issuer = recipient(1);
        let victim = recipient(2);
        let dk = DataKey::from_bytes([3; 32]);
        let (rec, body) = issue_grant_deterministic(
            &issuer,
            KeyId::ROOT,
            &request(&victim, Tier::Write, Some(&dk)),
            &mut fixed_rng(1),
        )
        .unwrap();
        assert_eq!(body.verify_possession(&rec), Ok(()));
        // Missing: forged.
        let bare = SignedRecord {
            key_signature: Vec::new(),
            ..rec.clone()
        };
        assert_eq!(body.verify_possession(&bare), Err(Rejected::Forged));
        // Made by another key (an attacker granting the victim's public key): forged.
        let attacker = recipient(4);
        let squat = SignedRecord {
            key_signature: attacker
                .sign_deterministic(labels::SIG_GRANT_POP, &rec.body)
                .unwrap()
                .as_bytes()
                .to_vec(),
            ..rec.clone()
        };
        assert_eq!(body.verify_possession(&squat), Err(Rejected::Forged));
        // Over another body: forged.
        let other = SignedRecord {
            key_signature: victim
                .sign_deterministic(labels::SIG_GRANT_POP, b"another body")
                .unwrap()
                .as_bytes()
                .to_vec(),
            ..rec.clone()
        };
        assert_eq!(body.verify_possession(&other), Err(Rejected::Forged));
        // Under the issuer's label instead of the proof's: forged, the labels never stand in for each other.
        let wrong_label = SignedRecord {
            key_signature: victim
                .sign_deterministic(labels::SIG_GRANT, &rec.body)
                .unwrap()
                .as_bytes()
                .to_vec(),
            ..rec.clone()
        };
        assert_eq!(body.verify_possession(&wrong_label), Err(Rejected::Forged));
        let short = SignedRecord {
            key_signature: vec![0; 100],
            ..rec.clone()
        };
        assert_eq!(
            body.verify_possession(&short),
            Err(Rejected::Malformed(Malformed::SignatureSize(100)))
        );
    }

    #[test]
    fn leaf_grant_reads_without_verifying() {
        let issuer = recipient(1);
        let r = recipient(2);
        let dk = DataKey::from_bytes([3; 32]);
        let (rec, body) = issue_grant_deterministic(
            &issuer,
            KeyId::ROOT,
            &request(&r, Tier::Write, Some(&dk)),
            &mut fixed_rng(1),
        )
        .unwrap();
        let (id, key) = leaf_grant(&FolderId([1; 32]), &rec).unwrap();
        assert_eq!(id, body.key_id);
        assert_eq!(
            key,
            GrantKey {
                suite: Suite::ONE,
                signing_pk: r.public().signing.clone()
            }
        );
        // Not verified: a garbage signature does not matter here.
        let unsigned = SignedRecord {
            body: rec.body.clone(),
            ..SignedRecord::default()
        };
        assert!(leaf_grant(&FolderId([1; 32]), &unsigned).is_some());
        assert!(
            leaf_grant(&FolderId([2; 32]), &rec).is_none(),
            "another folder"
        );
        assert!(leaf_grant(
            &FolderId([1; 32]),
            &SignedRecord {
                body: vec![0xff],
                ..SignedRecord::default()
            }
        )
        .is_none());
    }

    #[test]
    fn issue_refuses_root_zero_epoch_and_mismatched_data_key() {
        let issuer = recipient(1);
        let r = recipient(2);
        let dk = DataKey::from_bytes([3; 32]);
        let mut rng = fixed_rng(1);
        assert_eq!(
            issue_grant_deterministic(
                &issuer,
                KeyId::ROOT,
                &request(&r, Tier::Root, Some(&dk)),
                &mut rng
            )
            .unwrap_err(),
            IssueError::RootTier
        );
        let mut zero = request(&r, Tier::Read, Some(&dk));
        zero.epoch = 0;
        assert_eq!(
            issue_grant_deterministic(&issuer, KeyId::ROOT, &zero, &mut rng).unwrap_err(),
            IssueError::ZeroEpoch
        );
        assert_eq!(
            issue_grant_deterministic(
                &issuer,
                KeyId::ROOT,
                &request(&r, Tier::Read, None),
                &mut rng
            )
            .unwrap_err(),
            IssueError::DataKey
        );
        assert_eq!(
            issue_grant_deterministic(
                &issuer,
                KeyId::ROOT,
                &request(&r, Tier::Sealed, Some(&dk)),
                &mut rng
            )
            .unwrap_err(),
            IssueError::DataKey
        );
        for e in [
            IssueError::RootTier,
            IssueError::ZeroEpoch,
            IssueError::DataKey,
            IssueError::Wrap(WrapError::Seal),
            IssueError::Sign(SignError),
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    fn mutate(change: impl FnOnce(&mut wire::Grant)) -> Result<GrantBody, Rejected> {
        let issuer = recipient(1);
        let r = recipient(2);
        let dk = DataKey::from_bytes([3; 32]);
        let (rec, _) = issue_grant_deterministic(
            &issuer,
            KeyId::ROOT,
            &request(&r, Tier::Write, Some(&dk)),
            &mut fixed_rng(1),
        )
        .unwrap();
        let mut w = wire::Grant::decode(rec.body.as_slice()).unwrap();
        change(&mut w);
        GrantBody::parse(&w.encode_to_vec())
    }

    #[test]
    fn parse_rejects_every_step_one_failure() {
        let m = |x| Rejected::Malformed(x);
        assert_eq!(
            mutate(|w| w.record_type = 1).unwrap_err(),
            m(Malformed::WrongType {
                expected: RecordType::Grant,
                found: 1
            })
        );
        assert_eq!(
            mutate(|w| w.suite = 3).unwrap_err(),
            Rejected::ValidityOnly(Validity::UnimplementedSuite(3))
        );
        assert_eq!(
            mutate(|w| w.tier = 0).unwrap_err(),
            m(Malformed::Range("tier"))
        );
        assert_eq!(
            mutate(|w| w.tier = 4).unwrap_err(),
            m(Malformed::Range("tier"))
        );
        assert_eq!(
            mutate(|w| w.epoch = 0).unwrap_err(),
            m(Malformed::Range("epoch"))
        );
        assert_eq!(
            mutate(|w| w.signing_pk.truncate(1983)).unwrap_err(),
            m(Malformed::FieldSize("signing_pk"))
        );
        assert_eq!(
            mutate(|w| w.kem_pk.truncate(1215)).unwrap_err(),
            m(Malformed::FieldSize("kem_pk"))
        );
        // A sealed grant with a wrap, and a write grant without one.
        assert_eq!(
            mutate(|w| w.tier = 3).unwrap_err(),
            m(Malformed::Range("wrapped_data_key"))
        );
        assert_eq!(
            mutate(|w| w.wrapped_data_key.clear()).unwrap_err(),
            m(Malformed::Range("wrapped_data_key"))
        );
        assert_eq!(
            mutate(|w| w.wrapped_data_key.truncate(1167)).unwrap_err(),
            m(Malformed::FieldSize("wrapped_data_key"))
        );
        // A key ID that does not recompute, and the root ID.
        assert_eq!(
            mutate(|w| w.key_id[0] ^= 1).unwrap_err(),
            m(Malformed::KeyIdMismatch)
        );
        assert_eq!(
            mutate(|w| w.key_id = vec![0; 16]).unwrap_err(),
            m(Malformed::RootKeyId)
        );
        assert_eq!(
            mutate(|w| w.key_id.truncate(15)).unwrap_err(),
            m(Malformed::FieldSize("key_id"))
        );
        assert_eq!(
            mutate(|w| w.issuer_key_id.truncate(15)).unwrap_err(),
            m(Malformed::FieldSize("issuer_key_id"))
        );
        assert_eq!(
            mutate(|w| w.folder_id.truncate(31)).unwrap_err(),
            m(Malformed::FieldSize("folder_id"))
        );
        assert_eq!(
            mutate(|w| w.issuer_device_id.truncate(31)).unwrap_err(),
            m(Malformed::FieldSize("issuer_device_id"))
        );
        assert!(mutate(|w| w.issuer_device_id.clear())
            .unwrap()
            .issuer_device_id
            .is_none());
        // A self-grant: the key named as its own issuer.
        assert_eq!(
            mutate(|w| w.issuer_key_id = w.key_id.clone()).unwrap_err(),
            m(Malformed::SelfIssued)
        );
    }
}
