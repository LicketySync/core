// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Folder record (`keys.md` section 2.2): the genesis record, signed by
//! root, that publishes the root's public keys, the folder nonce, the root's
//! wrap of `dk_1` and epoch 1's key-confirmation value.

use prost::Message as _;

use super::{
    check_prefix, decode_bounded, sign_record_with, signature_of, wire, Bound, Hedge, Malformed,
    RecordType, Rejected, Shape, SignedRecord,
};
use crate::derive::{self, FolderNonce};
use crate::epoch::Confirm;
use crate::ids::{FolderId, KeyId};
use crate::keyset::{KemPublicKey, KeyError, KeyPairSet, SignError, SigningPublicKey};
use crate::rng::RandomFill;
use crate::secret::{DataKey, MasterSecret};
use crate::suite::{Suite, Tier};
use crate::wrap::{wrap_data_key, WrapAad, WrapError, WrappedDataKey};

/// The most `required_features` a Folder record may list.
pub const MAX_FEATURES: usize = 32;

/// A parsed Folder record body. Every field has been size- and range-checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderBody {
    /// Suite of the root key and of this record; the folder's current suite.
    pub suite: Suite,
    /// `H("licketysync/v1/hash/id/folder", be16(suite) || root_signing_pk)`.
    pub folder_id: FolderId,
    /// The root's hybrid signing public key.
    pub root_signing_pk: SigningPublicKey,
    /// The root's X-Wing public key.
    pub root_kem_pk: KemPublicKey,
    /// The nonce under which the phrase derives this folder's root (section 1.2).
    pub folder_nonce: FolderNonce,
    /// `dk_1` wrapped to the root with aad `folder_id || root_key_id || 0x00 || be64(1)`.
    pub root_wrapped_data_key: WrappedDataKey,
    /// Informational.
    pub created_at: u64,
    /// Peers whose keys or records use a lower suite are refused.
    pub minimum_suite: Suite,
    /// Feature names a peer's feature set must contain to open the folder.
    pub required_features: Vec<String>,
    /// `derive_key("licketysync/v1/epoch/confirm", dk_1)`.
    pub confirm: Confirm,
}

/// The feature grammar `[a-z0-9:-]{1,32}` (`protocol.md` section 5).
fn feature_ok(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b':' || b == b'-')
}

impl FolderBody {
    /// The root's key pair set from the master secret (section 1.2): the
    /// root seed of `ms` and this folder's nonce, accepted only when its
    /// public keys are the ones this Folder record names. `None` when `ms` is
    /// not this folder's master secret.
    #[must_use]
    pub fn root_key_pair(&self, ms: &MasterSecret) -> Option<KeyPairSet> {
        KeyPairSet::from_seed(&derive::root_seed(ms, &self.folder_nonce))
            .ok()
            .filter(|root| {
                root.public().signing == self.root_signing_pk
                    && root.public().kem == self.root_kem_pk
            })
    }

    /// Parses and checks a body (section 2.2, "parse"): sizes, the suite,
    /// `1 <= minimum_suite <= suite` and the feature grammar. The signature
    /// and the folder ID's recomputation are checked by [`FolderBody::verify`].
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`], or [`Rejected::ValidityOnly`] for a suite this
    /// release does not implement.
    pub fn parse(body: &[u8]) -> Result<FolderBody, Rejected> {
        let w: wire::Folder = decode_bounded(
            body,
            &Shape::new(
                11,
                &[1, 2, 9],
                &[Bound {
                    field: 10,
                    max: MAX_FEATURES,
                    name: "required_features",
                    entry_fields: 0,
                }],
            ),
        )?;
        let suite = check_prefix(w.suite, w.record_type, RecordType::Folder)?;
        let minimum_suite =
            Suite::from_wire(w.minimum_suite).map_err(|_| Malformed::Range("minimum_suite"))?;
        if minimum_suite > suite {
            return Err(Malformed::Range("minimum_suite").into());
        }
        if !w.required_features.iter().all(|f| feature_ok(f)) {
            return Err(Malformed::FeatureGrammar.into());
        }
        Ok(FolderBody {
            suite,
            folder_id: FolderId::from_slice(&w.folder_id)
                .ok_or(Malformed::FieldSize("folder_id"))?,
            root_signing_pk: SigningPublicKey::parse(&w.root_signing_pk)
                .map_err(|_| Malformed::FieldSize("root_signing_pk"))?,
            root_kem_pk: KemPublicKey::parse(&w.root_kem_pk)
                .map_err(|_| Malformed::FieldSize("root_kem_pk"))?,
            folder_nonce: FolderNonce::from_slice(&w.folder_nonce)
                .ok_or(Malformed::FieldSize("folder_nonce"))?,
            root_wrapped_data_key: WrappedDataKey::from_slice(&w.root_wrapped_data_key)
                .ok_or(Malformed::FieldSize("root_wrapped_data_key"))?,
            created_at: w.created_at,
            minimum_suite,
            required_features: w.required_features,
            confirm: Confirm::from_slice(&w.confirm).ok_or(Malformed::FieldSize("confirm"))?,
        })
    }

    /// Verifies a Folder record in the order of section 2.2: parse, the root's
    /// signature, then that `folder_id` recomputes from the suite and the root
    /// signing key. A forger can sign with a root of its own, so the
    /// recomputation is what ties the record to the folder ID.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`], [`Rejected::Forged`] or
    /// [`Rejected::ValidityOnly`] (unimplemented suite).
    pub fn verify(record: &SignedRecord) -> Result<FolderBody, Rejected> {
        let body = FolderBody::parse(&record.body)?;
        let signature = signature_of(record)?;
        body.root_signing_pk
            .verify(RecordType::Folder.sig_label(), &record.body, &signature)
            .map_err(|_| Rejected::Forged)?;
        if derive::folder_id(body.suite, &body.root_signing_pk) != body.folder_id {
            return Err(Malformed::FolderIdMismatch.into());
        }
        Ok(body)
    }

    /// The associated data of the root's wrap of `dk_1`.
    #[must_use]
    pub fn root_wrap_aad(&self) -> WrapAad {
        WrapAad {
            folder_id: self.folder_id,
            key_id: KeyId::ROOT,
            tier: Tier::Root,
            epoch: 1,
        }
    }

    /// The canonical encoding (section 5.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::Folder {
            suite: self.suite.to_wire(),
            record_type: RecordType::Folder.to_wire(),
            folder_id: self.folder_id.0.to_vec(),
            root_signing_pk: self.root_signing_pk.as_bytes().to_vec(),
            root_kem_pk: self.root_kem_pk.as_bytes().to_vec(),
            folder_nonce: self.folder_nonce.0.to_vec(),
            root_wrapped_data_key: self.root_wrapped_data_key.as_bytes().to_vec(),
            created_at: self.created_at,
            minimum_suite: self.minimum_suite.to_wire(),
            required_features: self.required_features.clone(),
            confirm: self.confirm.0.to_vec(),
        }
        .encode_to_vec()
    }
}

/// What a root holder needs to create a folder.
#[derive(Debug)]
pub struct FolderGenesis<'a> {
    /// The owner's master secret.
    pub master: &'a MasterSecret,
    /// The folder nonce, fresh from the caller's randomness ([`FolderNonce::generate`]).
    pub nonce: FolderNonce,
    /// The epoch 1 data key, fresh from the caller's randomness ([`DataKey::generate`]).
    pub data_key: &'a DataKey,
    /// Informational creation time, Unix seconds.
    pub created_at: u64,
    /// Feature names every member must support.
    pub required_features: Vec<String>,
}

/// A newly created folder.
#[derive(Debug)]
pub struct NewFolder {
    /// The signed Folder record.
    pub record: SignedRecord,
    /// Its parsed body.
    pub body: FolderBody,
    /// The root key pair set, derived from the phrase and the nonce.
    pub root: KeyPairSet,
}

/// Why a folder could not be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateError {
    /// A key could not be derived.
    Key(KeyError),
    /// The root wrap failed.
    Wrap(WrapError),
    /// Signing failed.
    Sign(SignError),
    /// A required feature breaks the grammar, or there are more than 32.
    Features,
}

impl core::fmt::Display for CreateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Key(e) => write!(f, "{e}"),
            Self::Wrap(e) => write!(f, "{e}"),
            Self::Sign(e) => write!(f, "{e}"),
            Self::Features => f.write_str("required features are invalid"),
        }
    }
}

impl std::error::Error for CreateError {}

/// Creates a folder (sections 1.2 and 2.2): derives the root from the master
/// secret and the nonce, wraps `dk_1` to the root, publishes `confirm`, and
/// signs the record with the root, hedged. `rng` supplies the wrap's
/// encapsulation randomness and the signature's.
///
/// # Errors
///
/// [`CreateError`].
pub fn create_folder(
    genesis: &FolderGenesis<'_>,
    rng: &mut RandomFill<'_>,
) -> Result<NewFolder, CreateError> {
    create_folder_with(genesis, Hedge::Hedged, rng)
}

/// [`create_folder`] with a deterministic signature, for test vectors only.
///
/// # Errors
///
/// [`CreateError`].
#[cfg(any(test, feature = "test-vectors"))]
pub fn create_folder_deterministic(
    genesis: &FolderGenesis<'_>,
    rng: &mut RandomFill<'_>,
) -> Result<NewFolder, CreateError> {
    create_folder_with(genesis, Hedge::Deterministic, rng)
}

fn create_folder_with(
    genesis: &FolderGenesis<'_>,
    hedge: Hedge,
    rng: &mut RandomFill<'_>,
) -> Result<NewFolder, CreateError> {
    if genesis.required_features.len() > MAX_FEATURES
        || !genesis.required_features.iter().all(|f| feature_ok(f))
    {
        return Err(CreateError::Features);
    }
    let root = KeyPairSet::from_seed(&derive::root_seed(genesis.master, &genesis.nonce))
        .map_err(CreateError::Key)?;
    let suite = Suite::ONE;
    let folder_id = derive::folder_id(suite, &root.public().signing);
    let aad = WrapAad {
        folder_id,
        key_id: KeyId::ROOT,
        tier: Tier::Root,
        epoch: 1,
    };
    let root_wrapped_data_key = wrap_data_key(&root.public().kem, &aad, genesis.data_key, rng)
        .map_err(CreateError::Wrap)?;
    let body = FolderBody {
        suite,
        folder_id,
        root_signing_pk: root.public().signing.clone(),
        root_kem_pk: root.public().kem.clone(),
        folder_nonce: genesis.nonce,
        root_wrapped_data_key,
        created_at: genesis.created_at,
        minimum_suite: suite,
        required_features: genesis.required_features.clone(),
        confirm: genesis.data_key.confirm(),
    };
    let record = sign_record_with(&root, RecordType::Folder, body.encode(), hedge, rng)
        .map_err(CreateError::Sign)?;
    Ok(NewFolder { record, body, root })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
pub(crate) mod tests {
    use super::*;
    use crate::records::sign_record_deterministic;

    pub(crate) fn fixed_rng(byte: u8) -> impl FnMut(&mut [u8]) {
        move |buf: &mut [u8]| buf.fill(byte)
    }

    pub(crate) fn new_folder(byte: u8) -> (NewFolder, DataKey) {
        let ms = MasterSecret::from_bytes([byte; 32]);
        let dk = DataKey::from_bytes([byte.wrapping_add(1); 32]);
        let genesis = FolderGenesis {
            master: &ms,
            nonce: FolderNonce([byte.wrapping_add(2); 32]),
            data_key: &dk,
            created_at: 1_700_000_000,
            required_features: vec![],
        };
        let f = create_folder_deterministic(&genesis, &mut fixed_rng(3)).unwrap();
        (f, dk)
    }

    #[test]
    fn create_then_verify() {
        let (f, dk) = new_folder(1);
        let body = FolderBody::verify(&f.record).unwrap();
        assert_eq!(body, f.body);
        assert_eq!(body.encode(), f.record.body);
        assert_eq!(body.confirm, dk.confirm());
        assert_eq!(body.minimum_suite, Suite::ONE);
        assert_eq!(body.root_wrap_aad().to_bytes()[48], 0);
        let opened = crate::wrap::unwrap_data_key(
            &f.root,
            &body.root_wrap_aad(),
            &body.root_wrapped_data_key,
        )
        .unwrap();
        assert!(bool::from(opened.ct_eq(&dk)));
    }

    fn resign(body: &FolderBody, signer: &KeyPairSet) -> SignedRecord {
        sign_record_deterministic(signer, RecordType::Folder, body.encode()).unwrap()
    }

    #[test]
    fn verification_order_and_failures() {
        let (f, _) = new_folder(1);
        // Forged: another key signed these bytes.
        let (other, _) = new_folder(9);
        let forged = SignedRecord {
            body: f.record.body.clone(),
            signature: other.record.signature.clone(),
            key_signature: Vec::new(),
        };
        assert_eq!(FolderBody::verify(&forged).unwrap_err(), Rejected::Forged);
        // A forger signing with a root of its own under our folder ID: the signature verifies, the ID does not recompute.
        let mut squat = other.body.clone();
        squat.folder_id = f.body.folder_id;
        assert_eq!(
            FolderBody::verify(&resign(&squat, &other.root)).unwrap_err(),
            Rejected::Malformed(Malformed::FolderIdMismatch)
        );
        // Signature size is checked before verification.
        let short = SignedRecord {
            body: f.record.body.clone(),
            signature: vec![0; 3372],
            key_signature: Vec::new(),
        };
        assert_eq!(
            FolderBody::verify(&short).unwrap_err(),
            Rejected::Malformed(Malformed::SignatureSize(3372))
        );
        // A malformed body that would also be forged: the parse is judged first.
        let mut bad = wire::Folder::decode(f.record.body.as_slice()).unwrap();
        bad.confirm = vec![0; 31];
        let bad = SignedRecord {
            body: bad.encode_to_vec(),
            signature: f.record.signature.clone(),
            key_signature: Vec::new(),
        };
        assert_eq!(
            FolderBody::verify(&bad).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("confirm"))
        );
    }

    fn mutate(
        f: &NewFolder,
        change: impl FnOnce(&mut wire::Folder),
    ) -> Result<FolderBody, Rejected> {
        let mut w = wire::Folder::decode(f.record.body.as_slice()).unwrap();
        change(&mut w);
        FolderBody::parse(&w.encode_to_vec())
    }

    #[test]
    fn parse_rejects_every_bad_field() {
        let (f, _) = new_folder(1);
        assert_eq!(
            mutate(&f, |w| w.record_type = 2).unwrap_err(),
            Rejected::Malformed(Malformed::WrongType {
                expected: RecordType::Folder,
                found: 2
            })
        );
        assert_eq!(
            mutate(&f, |w| w.suite = 2).unwrap_err(),
            Rejected::ValidityOnly(super::super::Validity::UnimplementedSuite(2))
        );
        assert_eq!(
            mutate(&f, |w| w.minimum_suite = 0).unwrap_err(),
            Rejected::Malformed(Malformed::Range("minimum_suite"))
        );
        assert_eq!(
            mutate(&f, |w| w.minimum_suite = 2).unwrap_err(),
            Rejected::Malformed(Malformed::Range("minimum_suite"))
        );
        assert_eq!(
            mutate(&f, |w| w.folder_id.pop().map_or((), |_| ())).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("folder_id"))
        );
        assert_eq!(
            mutate(&f, |w| w.root_signing_pk.truncate(10)).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("root_signing_pk"))
        );
        assert_eq!(
            mutate(&f, |w| w.root_kem_pk.truncate(10)).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("root_kem_pk"))
        );
        assert_eq!(
            mutate(&f, |w| w.folder_nonce.truncate(10)).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("folder_nonce"))
        );
        assert_eq!(
            mutate(&f, |w| w.root_wrapped_data_key.truncate(10)).unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("root_wrapped_data_key"))
        );
        assert_eq!(
            mutate(&f, |w| w.required_features = vec!["Upper".into()]).unwrap_err(),
            Rejected::Malformed(Malformed::FeatureGrammar)
        );
        assert_eq!(
            mutate(&f, |w| w.required_features = vec![String::new()]).unwrap_err(),
            Rejected::Malformed(Malformed::FeatureGrammar)
        );
        assert_eq!(
            mutate(&f, |w| w.required_features = vec!["a".repeat(33)]).unwrap_err(),
            Rejected::Malformed(Malformed::FeatureGrammar)
        );
        assert_eq!(
            mutate(&f, |w| w.required_features = vec!["x".into(); 33]).unwrap_err(),
            Rejected::Malformed(Malformed::TooMany("required_features"))
        );
        let ok = mutate(&f, |w| {
            w.required_features = vec!["compression:zstd".into(), "hash:blake3".into()];
        })
        .unwrap();
        assert_eq!(ok.required_features.len(), 2);
        assert_eq!(
            FolderBody::parse(&[0xff]).unwrap_err(),
            Rejected::Malformed(Malformed::Decode)
        );
    }

    #[test]
    fn create_refuses_bad_features() {
        let ms = MasterSecret::from_bytes([1; 32]);
        let dk = DataKey::from_bytes([2; 32]);
        for features in [vec!["BAD".to_string()], vec!["ok".to_string(); 33]] {
            let g = FolderGenesis {
                master: &ms,
                nonce: FolderNonce([3; 32]),
                data_key: &dk,
                created_at: 0,
                required_features: features,
            };
            assert_eq!(
                create_folder_deterministic(&g, &mut fixed_rng(0)).unwrap_err(),
                CreateError::Features
            );
        }
        assert_ne!(CreateError::Features.to_string(), "");
        assert_ne!(CreateError::Sign(SignError).to_string(), "");
        assert_ne!(CreateError::Key(KeyError::Internal).to_string(), "");
        assert_ne!(CreateError::Wrap(WrapError::Seal).to_string(), "");
    }
}
