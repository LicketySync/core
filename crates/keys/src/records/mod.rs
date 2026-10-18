// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The folder's key records (`keys.md` sections 2.2, 5 and 7): the signed
//! envelope, the canonical bodies, their verification in the order the spec
//! fixes, and [`FolderKeys`], the verified set of one folder's key records with
//! the validity predicates of section 5.5.
//!
//! Every procedure here verifies the signature immediately after the signer is
//! resolved and before any step whose failure is charged to a signer, issuer or
//! writer ("no blame before a signature", `protocol.md` section 5). Every
//! failure is a typed [`Rejected`] whose variant is the cause in
//! `protocol.md`'s rules table, so the caller maps it to close, reject-and-keep
//! or flag without guessing (TM-10).

pub(crate) mod folder;
mod grant;
mod groups;
mod held;
mod holder;
mod load;
mod phase7;
mod refused;
mod rotation;
#[cfg(test)]
mod ruling_tests;
mod store;
#[cfg(test)]
pub(crate) mod store_tests;
mod validity;
pub(crate) mod wire;

use core::fmt;

use prost::bytes::Buf;
use prost::Message as _;

#[cfg(any(test, feature = "test-vectors"))]
pub use folder::create_folder_deterministic;
pub use folder::{create_folder, CreateError, FolderBody, FolderGenesis, NewFolder, MAX_FEATURES};
#[cfg(any(test, feature = "test-vectors"))]
pub use grant::issue_grant_deterministic;
pub use grant::{
    issue_grant, leaf_grant, GrantBody, GrantKey, GrantRequest, IssueError, MAX_CHAIN_DEPTH,
};
pub use held::{HeldGrants, MAX_HELD_GRANTS};
pub use holder::HolderError;
pub use load::LoadFailures;
pub use phase7::{
    ActingTier, Cutoff, KeyWrapEntry, LiftBody, RevocationBody, RotationBody, SuspensionBody,
    WrapBody, MAX_CUTOFFS, MAX_VIEW, MAX_WRAPS,
};
pub use refused::MAX_REFUSED_REMEMBERED;
pub use store::{
    FolderKeys, Quota, MAX_KEY_RECORDS_PER_FOLDER, MAX_KEY_RECORDS_PER_SIGNER,
    MAX_KEY_RECORD_BYTES_PER_FOLDER,
};
pub use validity::{EffectiveTier, KeyValidity};

use crate::ids::{FolderId, KeyId, RecordHash};
use crate::keyset::{HybridSignature, KeyPairSet, SignError};
use crate::labels::{self, labelled_hash, SigLabel};
use crate::rng::RandomFill;
use crate::suite::{Suite, SuiteError};

/// The largest encoded [`SignedRecord`] carrying a key record (Folder, Grant,
/// Rotation, Wrap, Revocation, Suspension, Lift): `protocol.md`'s
/// `MAX_KEY_RECORD_BYTES` (ruling 16). A Rotation at its bounds of 4096 wraps
/// and 8192 view entries stays below it.
pub const MAX_KEY_RECORD_LEN: usize = 6_000_000;

/// The largest encoded [`SignedRecord`] carrying an index record:
/// `protocol.md`'s `MAX_INDEX_RECORD_BYTES` (ruling 16).
pub const MAX_INDEX_RECORD_LEN: usize = 4_000_000;

/// The signed envelope (section 5.1): a canonical body and the hybrid
/// signature over it. Verifiers keep `body` exactly as received; it is what is
/// hashed, verified, stored and forwarded, never re-encoded. Protocol messages
/// embed this type directly (`KeyRecords`, `ProofPayload`, `IndexRecords`).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct SignedRecord {
    /// The canonical bytes of one record body.
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
    /// `HybridSign(signer, "licketysync/v1/sig/<type>", body)`, 3373 bytes.
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    /// Grants only: the issued key's proof of possession,
    /// `HybridSign(issued key, "licketysync/v1/sig/grant-pop", body)`, 3373
    /// bytes (section 5.3); empty in every other record.
    #[prost(bytes = "vec", tag = "3")]
    pub key_signature: Vec<u8>,
}

impl SignedRecord {
    /// `record_hash = H("licketysync/v1/hash/record", body)`. Two records with
    /// equal bodies are the same record whatever their signatures.
    #[must_use]
    pub fn hash(&self) -> RecordHash {
        record_hash(&self.body)
    }

    /// The envelope's wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Decodes an envelope of at most [`MAX_KEY_RECORD_LEN`] bytes, or
    /// [`MAX_INDEX_RECORD_LEN`] when its body's prefix names an index record,
    /// each of its three fields at most once (ruling 16).
    ///
    /// # Errors
    ///
    /// [`Malformed::Decode`], [`Malformed::DuplicateField`] or
    /// [`Malformed::TooLarge`].
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedRecord, Malformed> {
        if bytes.len() > MAX_KEY_RECORD_LEN {
            return Err(Malformed::TooLarge(bytes.len()));
        }
        let record: SignedRecord = decode_bounded(bytes, &Shape::new(3, &[], &[]))?;
        let index = wire::Prefix::decode(record.body.as_slice())
            .is_ok_and(|p| p.record_type == RecordType::Index.to_wire());
        if index && bytes.len() > MAX_INDEX_RECORD_LEN {
            return Err(Malformed::TooLarge(bytes.len()));
        }
        Ok(record)
    }

    /// Reads the common prefix (suite, type, folder) of the body before
    /// anything else (section 5.1).
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] for a body that does not parse, a zero or
    /// out-of-range suite, an unknown type number or a folder ID of the wrong
    /// size; [`Rejected::ValidityOnly`] for a suite this release does not
    /// implement (`keys.md` 0.1: the sender may be a newer release).
    pub fn prefix(&self) -> Result<RecordPrefix, Rejected> {
        let prefix = wire::Prefix::decode(self.body.as_slice()).map_err(|_| Malformed::Decode)?;
        let suite = suite_of(prefix.suite)?;
        let record_type = RecordType::from_wire(prefix.record_type).ok_or(
            Rejected::ValidityOnly(Validity::UnsupportedRecordType(prefix.record_type)),
        )?;
        let folder_id =
            FolderId::from_slice(&prefix.folder_id).ok_or(Malformed::FieldSize("folder_id"))?;
        Ok(RecordPrefix {
            suite,
            record_type,
            folder_id,
        })
    }
}

/// `H("licketysync/v1/hash/record", body)`.
#[must_use]
pub fn record_hash(body: &[u8]) -> RecordHash {
    RecordHash(labelled_hash(labels::HASH_RECORD, &[body]))
}

/// The fields every body starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPrefix {
    /// The record's suite (implemented by this release).
    pub suite: Suite,
    /// The record type.
    pub record_type: RecordType,
    /// The folder.
    pub folder_id: FolderId,
}

/// Record types (section 5.1). The signature label is chosen from the body's
/// own type, so a body cannot be presented as another type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordType {
    /// The genesis record.
    Folder,
    /// An issued key's grant.
    Grant,
    /// A new epoch (phase 7).
    Rotation,
    /// One key's share of an epoch (phase 7).
    Wrap,
    /// A key revoked for ever (phase 7).
    Revocation,
    /// A key lowered for a time (phase 7).
    Suspension,
    /// A suspension ended early (phase 7).
    Lift,
    /// Reserved: a new root (phase 7, undesigned).
    RootRotation,
    /// An index record (`protocol.md` 4.4), not a key record.
    Index,
}

impl RecordType {
    /// The type's wire number.
    #[must_use]
    pub fn to_wire(self) -> u32 {
        match self {
            RecordType::Folder => 1,
            RecordType::Grant => 2,
            RecordType::Rotation => 3,
            RecordType::Wrap => 4,
            RecordType::Revocation => 5,
            RecordType::Suspension => 6,
            RecordType::Lift => 7,
            RecordType::RootRotation => 8,
            RecordType::Index => 16,
        }
    }

    /// The type a wire number names, if any.
    #[must_use]
    pub fn from_wire(value: u32) -> Option<RecordType> {
        Some(match value {
            1 => RecordType::Folder,
            2 => RecordType::Grant,
            3 => RecordType::Rotation,
            4 => RecordType::Wrap,
            5 => RecordType::Revocation,
            6 => RecordType::Suspension,
            7 => RecordType::Lift,
            8 => RecordType::RootRotation,
            16 => RecordType::Index,
            _ => return None,
        })
    }

    /// The signature label of the type.
    #[must_use]
    pub fn sig_label(self) -> SigLabel {
        match self {
            RecordType::Folder => labels::SIG_FOLDER,
            RecordType::Grant => labels::SIG_GRANT,
            RecordType::Rotation => labels::SIG_ROTATION,
            RecordType::Wrap => labels::SIG_WRAP,
            RecordType::Revocation => labels::SIG_REVOCATION,
            RecordType::Suspension => labels::SIG_SUSPENSION,
            RecordType::Lift => labels::SIG_LIFT,
            RecordType::RootRotation => labels::SIG_ROOT_ROTATION,
            RecordType::Index => labels::SIG_INDEX,
        }
    }
}

/// How a record is signed. Production signs hedged (`suites.md` 2.2,
/// "Signing variant"); test vectors sign deterministically so they reproduce,
/// and that form exists only in tests and under the `test-vectors` feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hedge {
    /// ML-DSA-65 with 32 fresh bytes from the caller's randomness.
    Hedged,
    /// ML-DSA-65 with `rnd` = 32 zero bytes.
    #[cfg(any(test, feature = "test-vectors"))]
    Deterministic,
}

impl Hedge {
    /// Signs `body` under `label` with `key` in this form.
    pub(crate) fn sign(
        self,
        key: &KeyPairSet,
        label: SigLabel,
        body: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<HybridSignature, SignError> {
        match self {
            Hedge::Hedged => key.sign(label, body, rng),
            #[cfg(any(test, feature = "test-vectors"))]
            Hedge::Deterministic => key.sign_deterministic(label, body),
        }
    }
}

/// Signs `body` as a record of `record_type` with `signer`, hedged.
///
/// # Errors
///
/// [`SignError`] only if the signature library refuses.
pub fn sign_record(
    signer: &KeyPairSet,
    record_type: RecordType,
    body: Vec<u8>,
    rng: &mut RandomFill<'_>,
) -> Result<SignedRecord, SignError> {
    sign_record_with(signer, record_type, body, Hedge::Hedged, rng)
}

/// [`sign_record`] with deterministic signing, for test vectors only.
///
/// # Errors
///
/// [`SignError`] only if the signature library refuses.
#[cfg(any(test, feature = "test-vectors"))]
pub fn sign_record_deterministic(
    signer: &KeyPairSet,
    record_type: RecordType,
    body: Vec<u8>,
) -> Result<SignedRecord, SignError> {
    sign_record_with(signer, record_type, body, Hedge::Deterministic, &mut |_| {})
}

pub(crate) fn sign_record_with(
    signer: &KeyPairSet,
    record_type: RecordType,
    body: Vec<u8>,
    hedge: Hedge,
    rng: &mut RandomFill<'_>,
) -> Result<SignedRecord, SignError> {
    let signature = hedge.sign(signer, record_type.sig_label(), &body, rng)?;
    Ok(SignedRecord {
        body,
        signature: signature.as_bytes().to_vec(),
        key_signature: Vec::new(),
    })
}

/// Why a record is malformed: the sender's fault, `Close(PROTOCOL_ERROR)` on
/// the connection that delivered it (`protocol.md` section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The bytes do not parse as the expected Protocol Buffers message.
    Decode,
    /// The envelope is larger than any key record can be.
    TooLarge(usize),
    /// The suite number is zero or does not fit 16 bits.
    Suite(SuiteError),
    /// The body's type is not the one this procedure verifies.
    WrongType {
        /// The type this procedure verifies.
        expected: RecordType,
        /// The wire number found.
        found: u32,
    },
    /// A bytes field has the wrong size, or a key in it does not decode.
    FieldSize(&'static str),
    /// A value is outside its stated range.
    Range(&'static str),
    /// A repeated field has more entries than its bound.
    TooMany(&'static str),
    /// A field that is not repeated occurs more than once (ruling 16; proto3
    /// would keep the last occurrence).
    DuplicateField(u32),
    /// A `uint32` field's varint does not fit 32 bits (prost would keep its
    /// low 32 bits).
    VarintRange(u32),
    /// A list the spec calls sorted is not sorted or has duplicates.
    NotSorted(&'static str),
    /// The signature is not 3373 bytes.
    SignatureSize(usize),
    /// The record names another folder.
    OtherFolder,
    /// The Folder record's `folder_id` does not recompute from its root key.
    FolderIdMismatch,
    /// The grant's `key_id` does not recompute from its `signing_pk` and
    /// `kem_pk`.
    KeyIdMismatch,
    /// A key ID is the reserved all-zero root ID where an issued key is meant.
    RootKeyId,
    /// The grant's suite is below the folder's `minimum_suite`.
    BelowMinimumSuite,
    /// A grant names its own key as its issuer.
    SelfIssued,
    /// A feature name breaks the grammar `[a-z0-9:-]{1,32}`.
    FeatureGrammar,
    /// A record type that never travels as a key record (an index record).
    NotAKeyRecord,
    /// A `key_signature` on a record that is not a grant (section 5.1).
    UnexpectedKeySignature,
    /// A link's bundle ends with a grant for a key other than the link's
    /// own (section 6.2).
    ForeignLeaf,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode => f.write_str("does not parse"),
            Self::TooLarge(n) => write!(f, "record of {n} bytes is too large"),
            Self::Suite(e) => write!(f, "{e}"),
            Self::WrongType { expected, found } => {
                write!(f, "record type {found} where {expected:?} was expected")
            }
            Self::FieldSize(field) => {
                write!(f, "field {field} has the wrong size or does not decode")
            }
            Self::Range(field) => write!(f, "field {field} is out of range"),
            Self::TooMany(field) => write!(f, "field {field} has too many entries"),
            Self::DuplicateField(n) => write!(f, "field number {n} occurs more than once"),
            Self::VarintRange(n) => write!(f, "field number {n} does not fit 32 bits"),
            Self::NotSorted(field) => write!(f, "field {field} is not sorted and unique"),
            Self::SignatureSize(n) => write!(f, "signature is {n} bytes"),
            Self::OtherFolder => f.write_str("record names another folder"),
            Self::FolderIdMismatch => f.write_str("folder ID does not match the root key"),
            Self::KeyIdMismatch => f.write_str("key ID does not match the public key"),
            Self::RootKeyId => f.write_str("the reserved root key ID names an issued key"),
            Self::BelowMinimumSuite => f.write_str("suite below the folder's minimum"),
            Self::SelfIssued => f.write_str("a grant issued by its own key"),
            Self::FeatureGrammar => f.write_str("feature name breaks the grammar"),
            Self::NotAKeyRecord => f.write_str("not a key record"),
            Self::UnexpectedKeySignature => {
                f.write_str("a key signature on a record that is not a grant")
            }
            Self::ForeignLeaf => f.write_str("a link's bundle ends with another key's grant"),
        }
    }
}

impl std::error::Error for Malformed {}

/// What a record needs that this verifier does not hold yet: reject without
/// storing, keep the connection, re-request (`protocol.md` 4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    /// The grant of the issuer or signer with this key ID.
    Grant(KeyId),
    /// The rotation that created this epoch.
    Epoch(u64),
    /// The record with this hash (a rotation's `cause` or `view`, a Lift's
    /// Suspension).
    Record(RecordHash),
}

/// A difference in what the peers know, not a fault: reject, keep the
/// connection, push the explaining records (`protocol.md` section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    /// A suite this release does not implement.
    UnimplementedSuite(u16),
    /// A record type this release does not know.
    UnsupportedRecordType(u32),
    /// A Wrap for a key none of whose grants at the Wrap's tier begins a
    /// valid chain (section 7.1, Wrap record, judged per grant, ruling 19).
    /// In phases 0 to 6 no Revocation or Suspension excludes a key (ruling
    /// 21), so this means no such grant has a chain within 16 grants: the key
    /// is out of reach, not excluded. Phase 7, which applies those records,
    /// adds the excluded case.
    WrapToKeyWithoutChain(KeyId),
    /// A grant for a key ID already granted with another public key: a 128-bit
    /// hash collision, refused rather than believed (ruling of 2026-10-17).
    KeyIdCollision {
        /// The key ID both grants name.
        key_id: KeyId,
        /// The issuer of the stored grant.
        stored_issuer: KeyId,
        /// The issuer of the refused grant.
        new_issuer: KeyId,
    },
    /// A rival or stale rotation (an epoch this verifier already reached) by
    /// a signer that already has one stored as evidence for that epoch: one
    /// per (epoch, signer) is kept (ruling 22).
    RivalAlreadyStored {
        /// The epoch both rotations name.
        epoch: u64,
        /// Their signer.
        signer: KeyId,
    },
    /// A record past one of ruling 23's quotas: a local bound, judged once
    /// the record verified, raised as an issue naming the signer, never a
    /// fault of the sender and never a close (rulings 21 and 23). Root-signed
    /// records are never refused so.
    QuotaExceeded {
        /// The record's signer (a grant's issuer), whose signature verified.
        signer: KeyId,
        /// The quota it would have passed.
        quota: Quota,
    },
    /// A grant offered to a connection's held set that already holds
    /// [`MAX_HELD_GRANTS`]: a bound of the connection, judged before either
    /// signature, so it names no key, not even the issuer the grant claims
    /// (ruling 29), and is no fault of the sender. The proof that carried the
    /// grant is answered REJECTED (`protocol.md` 3.5 step 6).
    HeldSetFull,
    /// A record that needs one this store refused under a quota, directly or
    /// through a record that needs one (rulings 24 and 25): the dependency
    /// will not be stored here, so it is not re-requested, and the record is
    /// remembered in turn ([`FolderKeys::refused_under_quota`]).
    DependencyRefused(Missing),
    /// What would be a signer fault if this verifier held every grant, which
    /// no peer can know it does (TM-10; rulings 24 and 25): a failure that
    /// rests only on a grant not being stored blames nobody, whatever the
    /// order records arrived in, and names the signer in an issue. A key
    /// that issues beyond its authority is refused here and not flagged.
    /// The faults it covers: the issuer's authority under its governing
    /// grant ([`SignerFault::NoMayShare`], [`SignerFault::TierTooHigh`]), a
    /// rotator's tier 1 or 2 grant ([`SignerFault::SealedRotator`]), a Wrap's
    /// tier ([`SignerFault::WrapTier`]) and entitlement as issuer or ancestor
    /// ([`SignerFault::NotEntitled`]). A Rotation's view is its own
    /// declaration, so [`SignerFault::ViewNotClosed`] keeps its blame (ruling
    /// 26).
    UnprovableFault {
        /// The record's signer.
        signer: KeyId,
        /// The fault it would have been.
        fault: SignerFault,
        /// The key whose grant, not held here, would make the record valid:
        /// the issuer or rotator itself, the key a Wrap serves, the key a
        /// Revocation or Suspension targets, the suspender a Lift answers.
        absent_grant_of: KeyId,
    },
}

/// A fault of the key that signed a well-signed record: flag that key, reject
/// the record, keep the connection (`protocol.md` section 5, "Signer fault").
/// The faults that rest only on a grant not being stored are never blamed
/// and travel inside [`Validity::UnprovableFault`] (rulings 25 and 26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerFault {
    /// A second root-signed Folder record for the folder (section 2.2).
    SecondFolderRecord,
    /// The issuer's governing grant lacks `may_share` (section 5.4 step 8).
    NoMayShare,
    /// The issuer's tier is above the tier it grants (section 5.4 step 8).
    TierTooHigh,
    /// The signer is not root, the key's issuer or an ancestor of it.
    NotEntitled,
    /// A rotation's `cause` names a record of another type, or a suspension
    /// that is not to `none`.
    CauseWrongType,
    /// A rotation's `cause` was signed by another key.
    CauseOtherSigner,
    /// A rotation with an empty `cause` signed by a key that is not root.
    EmptyCauseNotRoot,
    /// A Wrap's `tier` is not a tier of the key's grants, or the key is
    /// granted only at tier 3.
    WrapTier,
    /// A Lift names a stored record that is not a Suspension.
    LiftTarget,
    /// A rotation signed by a key that holds no stored grant of tier 1 or 2:
    /// a key granted only sealed cannot choose a folder's data key (ruling
    /// 21; validity is not consulted).
    SealedRotator,
    /// A rotation's `view` names a record of a type it may not hold.
    ViewWrongType,
    /// A rotation's `view` holds a grant without its issuer's grant.
    ViewNotClosed,
    /// A rotation omits a key it must keep (a lockout attempt).
    Lockout(KeyId),
    /// A rotation wraps a key it may not (a leak attempt).
    ForbiddenWrap(KeyId),
}

/// Why a record was not stored. The variant is the cause of `protocol.md`'s
/// rules table; the caller maps it to the action that table gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// The sender's fault: close with `PROTOCOL_ERROR`.
    Malformed(Malformed),
    /// The signature does not verify: close with `VERIFICATION_FAILED`.
    Forged,
    /// A dependency is not held: keep, re-request.
    Missing(Missing),
    /// A difference in knowledge: keep, push the explaining records.
    ValidityOnly(Validity),
    /// The signer's fault on a well-signed record: flag `signer`, keep.
    SignerFault {
        /// The key to flag; [`KeyId::ROOT`] for root.
        signer: KeyId,
        /// What it did.
        fault: SignerFault,
    },
}

impl Rejected {
    /// The rejection for a failure that rests only on a grant of
    /// `absent_grant_of` not being stored: validity-only, naming the signer
    /// and what the fault would be (rulings 24 to 26).
    pub(crate) fn unprovable(
        signer: KeyId,
        fault: SignerFault,
        absent_grant_of: KeyId,
    ) -> Rejected {
        Rejected::ValidityOnly(Validity::UnprovableFault {
            signer,
            fault,
            absent_grant_of,
        })
    }
}

impl From<Malformed> for Rejected {
    fn from(m: Malformed) -> Self {
        Rejected::Malformed(m)
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed: {m}"),
            Self::Forged => f.write_str("forged: the signature does not verify"),
            Self::Missing(m) => write!(f, "missing dependency: {m:?}"),
            Self::ValidityOnly(v) => write!(f, "not valid here: {v:?}"),
            Self::SignerFault { signer, fault } => write!(f, "signer {signer} at fault: {fault:?}"),
        }
    }
}

impl std::error::Error for Rejected {}

/// Something stored that the owner should see under Issues. None of these is
/// a rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    /// A key now holds two grants (section 5.4 step 7): nobody's fault, but
    /// worth the owner's eye.
    SeveralGrants {
        /// The key.
        key_id: KeyId,
        /// The earlier grant and its issuer.
        earlier: (RecordHash, KeyId),
        /// The new grant and its issuer.
        new: (RecordHash, KeyId),
    },
    /// A record of a type this release stores and forwards but whose effects
    /// beyond key validity are phase 7 (section 7).
    NotApplied(RecordType),
    /// An entitled signer this verifier knows to be revoked or suspended
    /// (section 7, introduction).
    SignerNotValid(KeyId),
    /// A grant whose issuer is revoked, or none of whose issuer's chains
    /// avoids a revoked key, stored and forwarded all the same (section 5.4
    /// step 9, ruling 20): its effect waits for phase 7.
    BeneathRevocation {
        /// The grant's key.
        key_id: KeyId,
        /// A Revocation of the issuer or of a key on its chains: the smallest
        /// record hash among them.
        revocation: RecordHash,
    },
    /// A cutoff names a writer outside the revoked or suspended key's subtree
    /// and is ignored (section 7, scope).
    CutoffOutsideSubtree {
        /// The revoker or suspender.
        signer: KeyId,
        /// The writer the cutoff names.
        writer: KeyId,
    },
    /// A rotation's wrap reaches a key this verifier knows revoked or
    /// suspended to `none` by a record outside the rotation's view (section
    /// 7.1 step 6): rotate again.
    EpochReachedExcludedKey {
        /// The rotation's signer.
        rotator: KeyId,
        /// The key.
        key_id: KeyId,
    },
    /// A rotation to an epoch this verifier has already reached by another
    /// rotation, or to an earlier one: stored as evidence after its signature
    /// verified, and never used (round 4 ruling, SF 9).
    RivalRotation {
        /// The epoch it names.
        epoch: u64,
    },
    /// A chain-valid write or read key this verifier holds was left outside a
    /// rotation's view and awaits a Wrap (section 7.1 step 6).
    AwaitsWrap {
        /// The rotation's signer.
        rotator: KeyId,
        /// The key.
        key_id: KeyId,
    },
}

/// The outcome of storing a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// Verified and stored.
    Stored {
        /// Its record hash.
        hash: RecordHash,
        /// Its type.
        record_type: RecordType,
        /// What the owner should see.
        issues: Vec<Issue>,
    },
    /// Already held (same `record_hash`): ignored.
    Duplicate(RecordHash),
}

/// Reads a suite number and requires that this release implements it.
fn suite_of(wire: u32) -> Result<Suite, Rejected> {
    let suite = Suite::from_wire(wire).map_err(Malformed::Suite)?;
    if suite.is_implemented() {
        Ok(suite)
    } else {
        Err(Rejected::ValidityOnly(Validity::UnimplementedSuite(
            suite.as_u16(),
        )))
    }
}

/// Checks the common prefix of a body that must be of type `expected`:
/// suite, type, then folder. Returns the suite.
fn check_prefix(suite: u32, record_type: u32, expected: RecordType) -> Result<Suite, Rejected> {
    let suite = suite_of(suite)?;
    if record_type != expected.to_wire() {
        return Err(Malformed::WrongType {
            expected,
            found: record_type,
        }
        .into());
    }
    Ok(suite)
}

/// A repeated top-level field, the most entries it may hold, and for a
/// repeated message the number of its entry's fields (`1..=entry_fields`,
/// every one singular and none `uint32`; 0 for repeated bytes and strings).
pub(crate) struct Bound {
    field: u32,
    max: usize,
    name: &'static str,
    entry_fields: u32,
}

/// The shape [`decode_bounded`] checks a message against before prost decodes
/// it: fields numbered `1..=fields`, every one singular except those in
/// `repeated`, and the varint fields in `u32_fields` declared `uint32`.
pub(crate) struct Shape<'b> {
    fields: u32,
    u32_fields: &'b [u32],
    repeated: &'b [Bound],
}

impl<'b> Shape<'b> {
    pub(crate) const fn new(fields: u32, u32_fields: &'b [u32], repeated: &'b [Bound]) -> Self {
        Shape {
            fields,
            u32_fields,
            repeated,
        }
    }
}

/// Every key-record body starts with `suite` and `record_type`, both `uint32`.
pub(crate) const PREFIX_U32: [u32; 2] = [1, 2];

/// Decodes `body` as `M` after a scan against `shape` that allocates nothing
/// beyond one counter per bounded field:
///
/// - each repeated field holds at most its bound, so that a peer cannot make
///   the decoder allocate millions of empty entries from a few megabytes
///   (TM-2);
/// - each other field of the message, and each field of a bounded repeated
///   message's entries, occurs at most once (ruling 16: proto3 keeps the last
///   occurrence, and a grant with tier 3 and then tier 1 must mean nothing);
/// - a `uint32` field's varint fits 32 bits (prost would keep its low 32
///   bits, so `2^32 + 1` would read as 1).
///
/// Unknown fields may repeat, since a newer release may have added them as
/// repeated.
fn decode_bounded<M: prost::Message + Default>(
    body: &[u8],
    shape: &Shape<'_>,
) -> Result<M, Malformed> {
    scan_fields(body, shape)?;
    M::decode(body).map_err(|_| Malformed::Decode)
}

fn scan_fields(body: &[u8], shape: &Shape<'_>) -> Result<(), Malformed> {
    let mut counts = vec![0usize; shape.repeated.len()];
    let mut seen: u64 = 0;
    let mut buf = body;
    while buf.has_remaining() {
        let (field, wire_type) =
            prost::encoding::decode_key(&mut buf).map_err(|_| Malformed::Decode)?;
        let value = take_value(&mut buf, wire_type)?;
        if let Value::Varint(v) = value {
            if shape.u32_fields.contains(&field) && u32::try_from(v).is_err() {
                return Err(Malformed::VarintRange(field));
            }
        }
        if let Some((i, bound)) = shape
            .repeated
            .iter()
            .enumerate()
            .find(|(_, b)| b.field == field)
        {
            let count = counts.get_mut(i).ok_or(Malformed::Decode)?;
            *count += 1;
            if *count > bound.max {
                return Err(Malformed::TooMany(bound.name));
            }
            if let (Value::Bytes(entry), true) = (value, bound.entry_fields > 0) {
                scan_fields(entry, &Shape::new(bound.entry_fields, &[], &[]))?;
            }
        } else if (1..=shape.fields).contains(&field) {
            let bit = 1u64.checked_shl(field).ok_or(Malformed::Decode)?;
            if seen & bit != 0 {
                return Err(Malformed::DuplicateField(field));
            }
            seen |= bit;
        }
    }
    Ok(())
}

/// One field value as the scan sees it.
#[derive(Clone, Copy)]
enum Value<'b> {
    Varint(u64),
    Bytes(&'b [u8]),
    Fixed,
}

/// Takes one value of `wire_type` off the front of `buf`.
fn take_value<'b>(
    buf: &mut &'b [u8],
    wire_type: prost::encoding::WireType,
) -> Result<Value<'b>, Malformed> {
    use prost::encoding::WireType;
    let len = match wire_type {
        WireType::Varint => {
            let v = prost::encoding::decode_varint(buf).map_err(|_| Malformed::Decode)?;
            return Ok(Value::Varint(v));
        }
        WireType::SixtyFourBit => 8,
        WireType::ThirtyTwoBit => 4,
        WireType::LengthDelimited => {
            let len = prost::encoding::decode_varint(buf).map_err(|_| Malformed::Decode)?;
            usize::try_from(len).map_err(|_| Malformed::Decode)?
        }
        WireType::StartGroup | WireType::EndGroup => return Err(Malformed::Decode),
    };
    let (value, rest) = buf.split_at_checked(len).ok_or(Malformed::Decode)?;
    *buf = rest;
    Ok(if wire_type == WireType::LengthDelimited {
        Value::Bytes(value)
    } else {
        Value::Fixed
    })
}

/// A list the spec calls sorted: strictly ascending (so also unique).
fn strictly_ascending<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| matches!(w, [a, b] if a < b))
}

/// Reads a 16-byte key ID from a field.
fn key_id_field(bytes: &[u8], name: &'static str) -> Result<KeyId, Malformed> {
    KeyId::from_slice(bytes).ok_or(Malformed::FieldSize(name))
}

/// Reads a 16-byte key ID that must name an issued key, never root.
fn issued_key_id_field(bytes: &[u8], name: &'static str) -> Result<KeyId, Malformed> {
    let id = key_id_field(bytes, name)?;
    if id.is_root() {
        Err(Malformed::RootKeyId)
    } else {
        Ok(id)
    }
}

/// Reads a 32-byte record hash from a field.
fn hash_field(bytes: &[u8], name: &'static str) -> Result<RecordHash, Malformed> {
    RecordHash::from_slice(bytes).ok_or(Malformed::FieldSize(name))
}

/// The bundle a link carries (section 6.2).
pub(crate) fn wire_key_bundle(records: &[SignedRecord]) -> wire::KeyBundle {
    wire::KeyBundle {
        records: records.to_vec(),
    }
}

/// Decodes a link's `KeyBundle`, counting its records against `max` before
/// decoding them.
pub(crate) fn decode_key_bundle(bytes: &[u8], max: usize) -> Result<Vec<SignedRecord>, Malformed> {
    let bundle: wire::KeyBundle = decode_bounded(
        bytes,
        &Shape::new(
            1,
            &[],
            &[Bound {
                field: 1,
                max,
                name: "records",
                entry_fields: 3,
            }],
        ),
    )?;
    Ok(bundle.records)
}

/// The signature of an envelope, sized before any verification runs.
fn signature_of(record: &SignedRecord) -> Result<HybridSignature, Malformed> {
    HybridSignature::from_bytes(&record.signature)
        .map_err(|_| Malformed::SignatureSize(record.signature.len()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn record_types_round_trip_and_labels_are_distinct() {
        let all = [
            RecordType::Folder,
            RecordType::Grant,
            RecordType::Rotation,
            RecordType::Wrap,
            RecordType::Revocation,
            RecordType::Suspension,
            RecordType::Lift,
            RecordType::RootRotation,
            RecordType::Index,
        ];
        let mut labels = std::collections::BTreeSet::new();
        for t in all {
            assert_eq!(RecordType::from_wire(t.to_wire()), Some(t));
            assert!(labels.insert(t.sig_label().as_str()));
        }
        assert_eq!(RecordType::from_wire(0), None);
        assert_eq!(RecordType::from_wire(9), None);
    }

    #[test]
    fn envelope_round_trips_and_is_bounded() {
        let r = SignedRecord {
            body: vec![1, 2, 3],
            signature: vec![4; 10],
            key_signature: vec![5; 3],
        };
        let bytes = r.to_bytes();
        assert_eq!(SignedRecord::from_bytes(&bytes).unwrap(), r);
        assert_eq!(
            SignedRecord::from_bytes(&[0xff]).unwrap_err(),
            Malformed::Decode
        );
        let huge = vec![0u8; MAX_KEY_RECORD_LEN + 1];
        assert_eq!(
            SignedRecord::from_bytes(&huge).unwrap_err(),
            Malformed::TooLarge(MAX_KEY_RECORD_LEN + 1)
        );
        assert_eq!(r.hash(), record_hash(&[1, 2, 3]));
        assert_eq!(
            r.hash().0,
            labelled_hash(labels::HASH_RECORD, &[&[1, 2, 3]])
        );
    }

    fn prefix_body(suite: u32, record_type: u32, folder: &[u8]) -> SignedRecord {
        let body = wire::Prefix {
            suite,
            record_type,
            folder_id: folder.to_vec(),
        }
        .encode_to_vec();
        SignedRecord {
            body,
            signature: Vec::new(),
            key_signature: Vec::new(),
        }
    }

    #[test]
    fn prefix_reads_suite_type_and_folder() {
        let p = prefix_body(1, 2, &[7; 32]).prefix().unwrap();
        assert_eq!(
            p,
            RecordPrefix {
                suite: Suite::ONE,
                record_type: RecordType::Grant,
                folder_id: FolderId([7; 32])
            }
        );
        assert_eq!(
            prefix_body(0, 2, &[7; 32]).prefix().unwrap_err(),
            Rejected::Malformed(Malformed::Suite(SuiteError::Zero))
        );
        assert_eq!(
            prefix_body(70_000, 2, &[7; 32]).prefix().unwrap_err(),
            Rejected::Malformed(Malformed::Suite(SuiteError::OutOfRange(70_000)))
        );
        assert_eq!(
            prefix_body(2, 2, &[7; 32]).prefix().unwrap_err(),
            Rejected::ValidityOnly(Validity::UnimplementedSuite(2))
        );
        assert_eq!(
            prefix_body(1, 99, &[7; 32]).prefix().unwrap_err(),
            Rejected::ValidityOnly(Validity::UnsupportedRecordType(99))
        );
        assert_eq!(
            prefix_body(1, 2, &[7; 31]).prefix().unwrap_err(),
            Rejected::Malformed(Malformed::FieldSize("folder_id"))
        );
        let garbage = SignedRecord {
            body: vec![0xff, 0xff],
            signature: Vec::new(),
            key_signature: Vec::new(),
        };
        assert_eq!(
            garbage.prefix().unwrap_err(),
            Rejected::Malformed(Malformed::Decode)
        );
        assert_eq!(
            check_prefix(1, 3, RecordType::Grant).unwrap_err(),
            Rejected::Malformed(Malformed::WrongType {
                expected: RecordType::Grant,
                found: 3
            })
        );
    }

    #[test]
    fn tm_2_repeated_fields_are_counted_before_decoding() {
        // 10 000 empty entries of field 6 (wraps): two bytes each.
        let mut body = Vec::new();
        for _ in 0..10_000 {
            body.extend_from_slice(&[0x32, 0x00]);
        }
        let bounds = [Bound {
            field: 6,
            max: 4096,
            name: "wraps",
            entry_fields: 2,
        }];
        assert_eq!(
            decode_bounded::<wire::Rotation>(&body, &Shape::new(11, &PREFIX_U32, &bounds))
                .unwrap_err(),
            Malformed::TooMany("wraps")
        );
        let ok: wire::Rotation =
            decode_bounded(&body[..8192], &Shape::new(11, &PREFIX_U32, &bounds)).unwrap();
        assert_eq!(ok.wraps.len(), 4096);
        // Every wire type is skipped correctly, and groups and truncation are refused.
        let mixed = [
            0x08, 0x96, 0x01, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0x35, 0, 0, 0, 0,
        ];
        assert!(
            decode_bounded::<wire::Prefix>(&mixed, &Shape::new(3, &PREFIX_U32, &bounds)).is_ok()
        );
        assert_eq!(
            decode_bounded::<wire::Prefix>(&[0x0b], &Shape::new(3, &PREFIX_U32, &bounds))
                .unwrap_err(),
            Malformed::Decode
        );
        assert_eq!(
            decode_bounded::<wire::Prefix>(&[0x0c], &Shape::new(3, &PREFIX_U32, &bounds))
                .unwrap_err(),
            Malformed::Decode
        );
        assert_eq!(
            decode_bounded::<wire::Prefix>(
                &[0x1a, 0x05, 0x00],
                &Shape::new(3, &PREFIX_U32, &bounds)
            )
            .unwrap_err(),
            Malformed::Decode
        );
        assert_eq!(
            decode_bounded::<wire::Prefix>(&[0x08], &Shape::new(3, &PREFIX_U32, &bounds))
                .unwrap_err(),
            Malformed::Decode
        );
        assert_eq!(
            decode_bounded::<wire::Prefix>(&[0x1a, 0xff], &Shape::new(3, &PREFIX_U32, &bounds))
                .unwrap_err(),
            Malformed::Decode
        );
        assert_eq!(
            decode_bounded::<wire::Prefix>(&[0x80], &Shape::new(3, &PREFIX_U32, &bounds))
                .unwrap_err(),
            Malformed::Decode
        );
    }

    #[test]
    fn ruling_16_a_singular_field_twice_is_malformed_and_unknown_fields_may_repeat() {
        // Field 1 (suite) twice: proto3 would keep the second.
        assert_eq!(
            decode_bounded::<wire::Prefix>(
                &[0x08, 0x01, 0x08, 0x02],
                &Shape::new(3, &PREFIX_U32, &[])
            )
            .unwrap_err(),
            Malformed::DuplicateField(1)
        );
        // A bytes field twice, and the last field of the message twice.
        assert_eq!(
            decode_bounded::<wire::Prefix>(
                &[0x1a, 0x00, 0x1a, 0x01, 0x07],
                &Shape::new(3, &PREFIX_U32, &[])
            )
            .unwrap_err(),
            Malformed::DuplicateField(3)
        );
        // Each field once, in any order, is fine; so is an unknown field
        // (number 4 or above, here 5 as a varint) any number of times.
        let ok: wire::Prefix = decode_bounded(
            &[0x10, 0x02, 0x08, 0x01, 0x28, 0x00, 0x28, 0x01],
            &Shape::new(3, &PREFIX_U32, &[]),
        )
        .unwrap();
        assert_eq!((ok.suite, ok.record_type), (1, 2));
        // Inside a bounded repeated message, each entry's own fields once.
        let wrap = |fields: &[u8]| {
            let mut body = vec![0x32, u8::try_from(fields.len()).unwrap()];
            body.extend_from_slice(fields);
            body
        };
        let bounds = [Bound {
            field: 6,
            max: 4096,
            name: "wraps",
            entry_fields: 2,
        }];
        let mut two_entries = wrap(&[0x0a, 0x00, 0x12, 0x00]);
        two_entries.extend(wrap(&[0x0a, 0x00]));
        assert!(decode_bounded::<wire::Rotation>(
            &two_entries,
            &Shape::new(11, &PREFIX_U32, &bounds)
        )
        .is_ok());
        assert_eq!(
            decode_bounded::<wire::Rotation>(
                &wrap(&[0x0a, 0x00, 0x0a, 0x00]),
                &Shape::new(11, &PREFIX_U32, &bounds)
            )
            .unwrap_err(),
            Malformed::DuplicateField(1)
        );
        // A damaged entry is refused by the scan, not only by prost.
        assert_eq!(
            decode_bounded::<wire::Rotation>(
                &wrap(&[0x0a, 0x05]),
                &Shape::new(11, &PREFIX_U32, &bounds)
            )
            .unwrap_err(),
            Malformed::Decode
        );
        // The envelope: `signature` twice.
        let r = SignedRecord {
            body: vec![1],
            signature: vec![2],
            key_signature: Vec::new(),
        };
        let mut bytes = r.to_bytes();
        bytes.extend_from_slice(&[0x12, 0x01, 0x03]);
        assert_eq!(
            SignedRecord::from_bytes(&bytes).unwrap_err(),
            Malformed::DuplicateField(2)
        );
        assert_eq!(
            Malformed::DuplicateField(2).to_string(),
            "field number 2 occurs more than once"
        );
        // A uint32 field whose varint does not fit 32 bits: prost would read
        // 2^32 + 1 as 1.
        let mut over = vec![0x08];
        prost::encoding::encode_varint((1u64 << 32) + 1, &mut over);
        assert_eq!(
            decode_bounded::<wire::Prefix>(&over, &Shape::new(3, &PREFIX_U32, &[])).unwrap_err(),
            Malformed::VarintRange(1)
        );
        let mut fits = vec![0x08];
        prost::encoding::encode_varint(u64::from(u32::MAX), &mut fits);
        assert!(decode_bounded::<wire::Prefix>(&fits, &Shape::new(3, &PREFIX_U32, &[])).is_ok());
        // A u64 field may use all 64 bits; only the declared uint32 fields are held to 32.
        let mut wide = vec![0x08, 0x01, 0x20];
        prost::encoding::encode_varint(u64::MAX, &mut wide);
        assert!(decode_bounded::<wire::Prefix>(&wide, &Shape::new(3, &PREFIX_U32, &[])).is_ok());
        assert_eq!(
            Malformed::VarintRange(5).to_string(),
            "field number 5 does not fit 32 bits"
        );
    }

    #[test]
    fn ruling_16_an_index_record_is_capped_lower_than_a_key_record() {
        // A body of the given type padded by an unknown field (number 15) of
        // `pad` bytes: the envelope is `pad` plus a few dozen bytes.
        let record = |record_type: RecordType, pad: usize| {
            let mut body = wire::Prefix {
                suite: 1,
                record_type: record_type.to_wire(),
                folder_id: vec![0; 32],
            }
            .encode_to_vec();
            prost::encoding::bytes::encode(15, &vec![0u8; pad], &mut body);
            SignedRecord {
                body,
                signature: Vec::new(),
                key_signature: Vec::new(),
            }
            .to_bytes()
        };
        let index_ok = record(RecordType::Index, MAX_INDEX_RECORD_LEN - 100);
        assert!(index_ok.len() <= MAX_INDEX_RECORD_LEN);
        assert!(SignedRecord::from_bytes(&index_ok).is_ok());
        let index_big = record(RecordType::Index, MAX_INDEX_RECORD_LEN);
        assert!(index_big.len() > MAX_INDEX_RECORD_LEN);
        assert_eq!(
            SignedRecord::from_bytes(&index_big).unwrap_err(),
            Malformed::TooLarge(index_big.len())
        );
        // The same length is fine for a key record, up to its own cap.
        let key_ok = record(RecordType::Rotation, MAX_INDEX_RECORD_LEN);
        assert!(SignedRecord::from_bytes(&key_ok).is_ok());
        let key_big = record(RecordType::Rotation, MAX_KEY_RECORD_LEN);
        assert!(key_big.len() > MAX_KEY_RECORD_LEN);
        assert_eq!(
            SignedRecord::from_bytes(&key_big).unwrap_err(),
            Malformed::TooLarge(key_big.len())
        );
    }

    #[test]
    fn a_rotation_at_its_bounds_fits_the_key_record_cap() {
        let rotation = wire::Rotation {
            suite: 1,
            record_type: RecordType::Rotation.to_wire(),
            folder_id: vec![0xff; 32],
            new_epoch: u64::MAX,
            signer_key_id: vec![0xff; 16],
            wraps: (0..MAX_WRAPS)
                .map(|_| wire::KeyWrap {
                    key_id: vec![0xff; 16],
                    wrapped_data_key: vec![0xff; crate::suite::sizes::WRAPPED_KEY],
                })
                .collect(),
            ladder: vec![0xff; crate::suite::sizes::LADDER_LINK],
            cause: vec![0xff; 32],
            issued_at: u64::MAX,
            view: (0..MAX_VIEW).map(|_| vec![0xff; 32]).collect(),
            confirm: vec![0xff; 32],
        };
        let record = SignedRecord {
            body: rotation.encode_to_vec(),
            signature: vec![0xff; crate::suite::sizes::HYBRID_SIG],
            key_signature: Vec::new(),
        };
        assert!(
            record.encoded_len() < MAX_KEY_RECORD_LEN,
            "{}",
            record.encoded_len()
        );
    }

    #[test]
    fn helpers() {
        assert!(strictly_ascending::<u8>(&[]));
        assert!(strictly_ascending(&[1, 2, 3]));
        assert!(!strictly_ascending(&[1, 1]));
        assert!(!strictly_ascending(&[2, 1]));
        assert_eq!(
            issued_key_id_field(&[0; 16], "k").unwrap_err(),
            Malformed::RootKeyId
        );
        assert_eq!(
            key_id_field(&[0; 15], "k").unwrap_err(),
            Malformed::FieldSize("k")
        );
        assert_eq!(
            hash_field(&[0; 31], "h").unwrap_err(),
            Malformed::FieldSize("h")
        );
        let bad_sig = SignedRecord {
            body: Vec::new(),
            signature: vec![0; 5],
            key_signature: Vec::new(),
        };
        assert_eq!(
            signature_of(&bad_sig).unwrap_err(),
            Malformed::SignatureSize(5)
        );
        for m in [
            Malformed::Decode,
            Malformed::TooLarge(1),
            Malformed::Suite(SuiteError::Zero),
            Malformed::WrongType {
                expected: RecordType::Grant,
                found: 1,
            },
            Malformed::FieldSize("x"),
            Malformed::Range("x"),
            Malformed::TooMany("x"),
            Malformed::NotSorted("x"),
            Malformed::SignatureSize(1),
            Malformed::OtherFolder,
            Malformed::FolderIdMismatch,
            Malformed::KeyIdMismatch,
            Malformed::RootKeyId,
            Malformed::BelowMinimumSuite,
            Malformed::SelfIssued,
            Malformed::FeatureGrammar,
            Malformed::NotAKeyRecord,
            Malformed::UnexpectedKeySignature,
        ] {
            assert_ne!(m.to_string(), "");
            assert!(Rejected::from(m).to_string().starts_with("malformed"));
        }
        for r in [
            Rejected::Forged,
            Rejected::Missing(Missing::Epoch(2)),
            Rejected::ValidityOnly(Validity::UnimplementedSuite(2)),
            Rejected::SignerFault {
                signer: KeyId::ROOT,
                fault: SignerFault::NotEntitled,
            },
            Rejected::ValidityOnly(Validity::QuotaExceeded {
                signer: KeyId([1; 16]),
                quota: Quota::FolderBytes,
            }),
            Rejected::ValidityOnly(Validity::HeldSetFull),
            Rejected::ValidityOnly(Validity::DependencyRefused(Missing::Epoch(3))),
            Rejected::ValidityOnly(Validity::UnprovableFault {
                signer: KeyId::ROOT,
                fault: SignerFault::WrapTier,
                absent_grant_of: KeyId([1; 16]),
            }),
        ] {
            assert_ne!(r.to_string(), "");
        }
    }
}
