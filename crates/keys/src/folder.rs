// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Folder keys (`keys.md` sections 1, 2.1 and 8.2): the write secret and its
//! derivation tree, the three tiers, the folder's verification key and ID, and
//! the stored form of a folder key.
//!
//! A folder is its write secret. Everything else derives from it in one
//! direction only, so each tier's key holds exactly what that tier may do:
//!
//! - a [`WriteKey`] holds `ws` and derives the folder's Ed25519 signing key,
//!   its data key and through it every other key;
//! - a [`ReadKey`] holds `folder_vk` and `dk`: it verifies and decrypts but
//!   cannot sign;
//! - a [`SealedKey`] holds `folder_vk` and `ak`: it verifies and relays
//!   ciphertext it cannot open.
//!
//! Every tier carries the verification key, so every holder verifies every
//! update and computes the folder ID ([`FolderVerifier`]). There is no owner,
//! no per-person key and no record of who holds which key: holding a key is
//! the access. A holder derives the lower keys from its own
//! ([`FolderKey::lowered`]). A read or sealed key is made only from a write
//! key or from a payload (a key string, the stored form), never from loose
//! halves: the chunk and handshake keys of [`crate::chunk`] and
//! [`crate::handshake`] are built from these keys, so they always pair a key
//! with the folder ID it belongs to.

use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::ids::{hex, FolderId};
use crate::labels::{self, derive_key, labelled_hash};
use crate::rng::RandomFill;
use crate::secret::{AccessKey, DataKey, SecretBytes, WriteSecret};
use crate::suite::{sizes, Suite, SuiteError, Tier};

/// Why key material could not be read: a key string's payload, a stored key,
/// or a link code's payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// A stored key with no bytes at all.
    Empty,
    /// The payload is not the length its tier has under its suite (for suite
    /// 1, 34 for write and 66 for read and sealed), or is too short to hold a
    /// suite.
    Length {
        /// The tier's length under suite 1.
        expected: usize,
        /// The length found.
        found: usize,
    },
    /// The suite is 0.
    Suite(SuiteError),
    /// A suite this release does not implement: "this key needs a newer
    /// release of Lickety-Sync" (`keys.md` 0.1, 6.1).
    UnimplementedSuite(u16),
    /// The verification key is not the canonical encoding of an Ed25519
    /// point, or the point is of small order (`keys.md` 0.3).
    VerifyingKey,
    /// A stored key's tier byte is not 1, 2 or 3.
    Tier(u8),
    /// A key cannot be lowered to a tier above its own.
    NotLower {
        /// The key's own tier.
        own: Tier,
        /// The tier asked for.
        wanted: Tier,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the stored key is empty"),
            Self::Length { expected, found } => {
                let unit = if *found == 1 { "byte" } else { "bytes" };
                write!(f, "key material is {found} {unit}, not {expected}")
            }
            Self::Suite(e) => write!(f, "{e}"),
            Self::UnimplementedSuite(_) => {
                f.write_str("this key needs a newer release of Lickety-Sync")
            }
            Self::VerifyingKey => f.write_str(
                "the folder's verification key is not a canonical Ed25519 point of large order",
            ),
            Self::Tier(t) => write!(f, "tier {t} is not a key tier"),
            Self::NotLower { own, wanted } => {
                write!(f, "a {own:?} key cannot give a {wanted:?} key")
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// Requires that this release implements `suite`.
fn implemented(suite: Suite) -> Result<Suite, KeyError> {
    if suite.is_implemented() {
        Ok(suite)
    } else {
        Err(KeyError::UnimplementedSuite(suite.as_u16()))
    }
}

/// The folder's Ed25519 verification key `folder_vk`, validated on
/// construction: the canonical encoding of a point that is not of small order
/// (`keys.md` 0.3), so one folder has one verification key and one ID.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FolderVerifyingKey(VerifyingKey);

impl fmt::Debug for FolderVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FolderVerifyingKey({})", hex(self.0.as_bytes()))
    }
}

impl FolderVerifyingKey {
    /// Reads a verification key from its 32 bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError::VerifyingKey`] when the bytes are not a point, not the
    /// point's canonical encoding, or the point is of small order (`keys.md`
    /// 0.3, 6.1).
    pub fn from_bytes(bytes: &[u8; sizes::ED25519_PK]) -> Result<Self, KeyError> {
        crate::sig::canonical_public_key(bytes)
            .map(FolderVerifyingKey)
            .ok_or(KeyError::VerifyingKey)
    }

    /// The 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::ED25519_PK] {
        self.0.as_bytes()
    }

    pub(crate) fn key(&self) -> &VerifyingKey {
        &self.0
    }
}

/// What every key of a folder carries in public: the suite, the verification
/// key and the folder ID derived from them,
/// `H("licketysync/v1/hash/id/folder", be16(suite) || folder_vk)`. It
/// verifies the folder's index records
/// ([`FolderVerifier::verify_index_record`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FolderVerifier {
    suite: Suite,
    vk: FolderVerifyingKey,
    folder_id: FolderId,
}

impl fmt::Debug for FolderVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FolderVerifier(suite {}, {})",
            self.suite.as_u16(),
            self.folder_id
        )
    }
}

impl FolderVerifier {
    /// The verifier of the folder whose verification key is `vk` under an
    /// implemented `suite`.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnimplementedSuite`] for a suite this release does not
    /// implement.
    pub fn new(suite: Suite, vk: FolderVerifyingKey) -> Result<FolderVerifier, KeyError> {
        Ok(FolderVerifier::of(implemented(suite)?, vk))
    }

    /// The verifier under a suite already known to be implemented.
    fn of(suite: Suite, vk: FolderVerifyingKey) -> FolderVerifier {
        let folder_id = FolderId(labelled_hash(
            labels::HASH_ID_FOLDER,
            &[&suite.be16(), vk.as_bytes()],
        ));
        FolderVerifier {
            suite,
            vk,
            folder_id,
        }
    }

    /// The folder's suite.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The folder's verification key.
    #[must_use]
    pub fn verifying_key(&self) -> &FolderVerifyingKey {
        &self.vk
    }

    /// The folder ID (`keys.md` 0.3, 2.1).
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }
}

/// The write key (`keys.md` 1.1, 1.3): the write secret and what it derives.
/// It signs index records and can give out every tier.
/// Zeroized on drop; its `Debug` names only the folder.
pub struct WriteKey {
    secret: WriteSecret,
    signing: SigningKey,
    verifier: FolderVerifier,
    data_key: DataKey,
}

impl fmt::Debug for WriteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WriteKey({}, [redacted])", self.verifier.folder_id)
    }
}

impl WriteKey {
    /// A new folder (`keys.md` 7.1): 32 fresh bytes from the caller's
    /// randomness, drawn straight into the write secret, under suite 1.
    #[must_use]
    pub fn generate(rng: &mut RandomFill<'_>) -> WriteKey {
        WriteKey::derive(Suite::ONE, WriteSecret::generate(rng))
    }

    /// The write key of `secret` under `suite` (a key the caller holds as
    /// bytes). The derivations are those of `keys.md` 1.2: the signing seed
    /// `derive_key("licketysync/v1/folder/signing-key", ws)` loaded with
    /// `SigningKey::from_bytes`, and `dk = derive_key("licketysync/v1/folder/data-key", ws)`.
    ///
    /// # Errors
    ///
    /// [`KeyError::UnimplementedSuite`] for a suite this release does not
    /// implement.
    pub fn from_secret(suite: Suite, secret: WriteSecret) -> Result<WriteKey, KeyError> {
        Ok(WriteKey::derive(implemented(suite)?, secret))
    }

    /// The derivation, for an implemented suite.
    pub(crate) fn derive(suite: Suite, secret: WriteSecret) -> WriteKey {
        let signing =
            SigningKey::from_bytes(&derive_key(labels::FOLDER_SIGNING_KEY, secret.expose()));
        // A key derived here is canonical by construction (`keys.md` 0.3) and,
        // from a clamped scalar, never of small order, so the checks of
        // `FolderVerifyingKey::from_bytes` have nothing to refuse.
        let verifier = FolderVerifier::of(suite, FolderVerifyingKey(signing.verifying_key()));
        WriteKey {
            data_key: secret.data_key(),
            secret,
            signing,
            verifier,
        }
    }

    /// The write secret. It leaves a device only as the write key string or
    /// words, the stored form, or over a linked-device channel (`keys.md`
    /// 1.1); outside this crate it only compares in constant time.
    #[must_use]
    pub fn secret(&self) -> &WriteSecret {
        &self.secret
    }

    /// The suite, verification key and folder ID.
    #[must_use]
    pub fn verifier(&self) -> &FolderVerifier {
        &self.verifier
    }

    /// The data key.
    #[must_use]
    pub fn data_key(&self) -> &DataKey {
        &self.data_key
    }

    /// The folder's Ed25519 signing key, for this crate's signing functions.
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The Ed25519 seed of the signing key, for a test that pins the
    /// derivation.
    #[cfg(test)]
    pub(crate) fn signing_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// The read key this write key gives.
    #[must_use]
    pub fn read_key(&self) -> ReadKey {
        ReadKey {
            verifier: self.verifier,
            data_key: self.secret.data_key(),
        }
    }

    /// The sealed key this write key gives.
    #[must_use]
    pub fn sealed_key(&self) -> SealedKey {
        SealedKey {
            verifier: self.verifier,
            access_key: self.data_key.access_key(),
        }
    }
}

/// The read key (`keys.md` 1.3): the verification key and the data key. It
/// verifies every record and decrypts contents, names and structure, and
/// cannot sign. Zeroized on drop; its `Debug` names only the folder.
pub struct ReadKey {
    verifier: FolderVerifier,
    data_key: DataKey,
}

impl fmt::Debug for ReadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReadKey({}, [redacted])", self.verifier.folder_id)
    }
}

impl ReadKey {
    /// The suite, verification key and folder ID.
    #[must_use]
    pub fn verifier(&self) -> &FolderVerifier {
        &self.verifier
    }

    /// The data key.
    #[must_use]
    pub fn data_key(&self) -> &DataKey {
        &self.data_key
    }

    /// The sealed key this read key gives.
    #[must_use]
    pub fn sealed_key(&self) -> SealedKey {
        SealedKey {
            verifier: self.verifier,
            access_key: self.data_key.access_key(),
        }
    }
}

/// The sealed key (`keys.md` 1.3): the verification key and the access key.
/// It verifies every record and every chunk against the hashes the signed
/// records name, and stores, serves and relays ciphertext it cannot open.
/// Zeroized on drop; its `Debug` names only the folder.
pub struct SealedKey {
    verifier: FolderVerifier,
    access_key: AccessKey,
}

impl fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedKey({}, [redacted])", self.verifier.folder_id)
    }
}

impl SealedKey {
    /// The suite, verification key and folder ID.
    #[must_use]
    pub fn verifier(&self) -> &FolderVerifier {
        &self.verifier
    }

    /// The access key, for the handshake keys.
    pub(crate) fn access_key(&self) -> &AccessKey {
        &self.access_key
    }
}

/// The one key a device holds for a folder, at its tier. A device holds one
/// key per folder (`keys.md` 8.2).
#[derive(Debug)]
pub enum FolderKey {
    /// The write key, boxed: it is twice the size of the others.
    Write(Box<WriteKey>),
    /// The read key.
    Read(ReadKey),
    /// The sealed key.
    Sealed(SealedKey),
}

impl From<WriteKey> for FolderKey {
    fn from(key: WriteKey) -> Self {
        FolderKey::Write(Box::new(key))
    }
}

impl From<ReadKey> for FolderKey {
    fn from(key: ReadKey) -> Self {
        FolderKey::Read(key)
    }
}

impl From<SealedKey> for FolderKey {
    fn from(key: SealedKey) -> Self {
        FolderKey::Sealed(key)
    }
}

/// The payload length of each tier under suite 1, the one suite this release
/// implements (`keys.md` 6.1).
pub(crate) fn payload_len(tier: Tier) -> usize {
    match tier {
        Tier::Write => sizes::WRITE_PAYLOAD,
        Tier::Read => sizes::READ_PAYLOAD,
        Tier::Sealed => sizes::SEALED_PAYLOAD,
    }
}

/// A read or sealed payload after its suite: the verification key and the
/// 32-byte secret, if `rest` is exactly that long.
fn vk_and_secret(rest: &[u8]) -> Option<(&[u8; sizes::ED25519_PK], &[u8; sizes::KEY])> {
    let (vk, secret) = rest.split_first_chunk::<{ sizes::ED25519_PK }>()?;
    Some((vk, secret.try_into().ok()?))
}

impl FolderKey {
    /// The key's tier.
    #[must_use]
    pub fn tier(&self) -> Tier {
        match self {
            FolderKey::Write(_) => Tier::Write,
            FolderKey::Read(_) => Tier::Read,
            FolderKey::Sealed(_) => Tier::Sealed,
        }
    }

    /// The suite, verification key and folder ID.
    #[must_use]
    pub fn verifier(&self) -> &FolderVerifier {
        match self {
            FolderKey::Write(k) => &k.verifier,
            FolderKey::Read(k) => &k.verifier,
            FolderKey::Sealed(k) => &k.verifier,
        }
    }

    /// The folder ID.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.verifier().folder_id
    }

    /// The data key, for the write and read tiers.
    #[must_use]
    pub fn data_key(&self) -> Option<&DataKey> {
        match self {
            FolderKey::Write(k) => Some(&k.data_key),
            FolderKey::Read(k) => Some(&k.data_key),
            FolderKey::Sealed(_) => None,
        }
    }

    /// The write key, for the write tier.
    #[must_use]
    pub fn write_key(&self) -> Option<&WriteKey> {
        match self {
            FolderKey::Write(k) => Some(k),
            FolderKey::Read(_) | FolderKey::Sealed(_) => None,
        }
    }

    /// The key this one gives at `tier`, its own or a lower one (`keys.md`
    /// 1.3: any holder can hand out its own tier or a lower one). A key at
    /// its own tier is a second copy, made in place.
    ///
    /// # Errors
    ///
    /// [`KeyError::NotLower`] for a tier above the key's own.
    pub fn lowered(&self, tier: Tier) -> Result<FolderKey, KeyError> {
        match (self, tier) {
            (FolderKey::Write(k), Tier::Write) => Ok(FolderKey::from(WriteKey::derive(
                k.verifier.suite,
                WriteSecret::fill_with(|out| *out = *k.secret.expose()),
            ))),
            (FolderKey::Write(k), Tier::Read) => Ok(FolderKey::Read(k.read_key())),
            (FolderKey::Write(k), Tier::Sealed) => Ok(FolderKey::Sealed(k.sealed_key())),
            (FolderKey::Read(k), Tier::Read) => Ok(FolderKey::Read(ReadKey {
                verifier: k.verifier,
                data_key: DataKey::fill_with(|out| *out = *k.data_key.expose()),
            })),
            (FolderKey::Read(k), Tier::Sealed) => Ok(FolderKey::Sealed(k.sealed_key())),
            (FolderKey::Sealed(k), Tier::Sealed) => Ok(FolderKey::Sealed(SealedKey {
                verifier: k.verifier,
                access_key: AccessKey::fill_with(|out| *out = *k.access_key.expose()),
            })),
            (FolderKey::Read(_) | FolderKey::Sealed(_), Tier::Write)
            | (FolderKey::Sealed(_), Tier::Read) => Err(KeyError::NotLower {
                own: self.tier(),
                wanted: tier,
            }),
        }
    }

    /// The key string payload (`keys.md` 6.1): `be16(suite) || ws` for write,
    /// `be16(suite) || folder_vk || dk` for read, `be16(suite) || folder_vk ||
    /// ak` for sealed, in a buffer sized once and zeroized on drop.
    #[must_use]
    pub fn payload(&self) -> SecretBytes {
        let v = self.verifier();
        let mut out = Zeroizing::new(Vec::with_capacity(payload_len(self.tier())));
        out.extend_from_slice(&v.suite.be16());
        match self {
            FolderKey::Write(k) => out.extend_from_slice(k.secret.expose()),
            FolderKey::Read(k) => {
                out.extend_from_slice(v.vk.as_bytes());
                out.extend_from_slice(k.data_key.expose());
            }
            FolderKey::Sealed(k) => {
                out.extend_from_slice(v.vk.as_bytes());
                out.extend_from_slice(k.access_key.expose());
            }
        }
        out
    }

    /// Reads a tier's payload, checking in the order of `keys.md` 6.1: a
    /// payload shorter than its 2-byte suite is malformed; then the suite (0
    /// is malformed; one this release does not implement needs a newer
    /// release, whatever the payload's length, since a later suite's payloads
    /// may have other lengths); then the length under that suite; then, for
    /// read and sealed, the verification key. The secret is copied straight
    /// from `payload` into its zeroizing type.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn from_payload(tier: Tier, payload: &[u8]) -> Result<FolderKey, KeyError> {
        let length = KeyError::Length {
            expected: payload_len(tier),
            found: payload.len(),
        };
        let (suite, rest) = payload
            .split_first_chunk::<{ sizes::SUITE }>()
            .ok_or(length)?;
        let suite = implemented(Suite::from_be16(*suite).map_err(KeyError::Suite)?)?;
        if tier == Tier::Write {
            let ws: &[u8; sizes::KEY] = rest.try_into().map_err(|_| length)?;
            return Ok(FolderKey::from(WriteKey::derive(
                suite,
                WriteSecret::fill_with(|out| *out = *ws),
            )));
        }
        let (vk, secret) = vk_and_secret(rest).ok_or(length)?;
        let verifier = FolderVerifier::of(suite, FolderVerifyingKey::from_bytes(vk)?);
        Ok(if tier == Tier::Read {
            FolderKey::Read(ReadKey {
                verifier,
                data_key: DataKey::fill_with(|out| *out = *secret),
            })
        } else {
            FolderKey::Sealed(SealedKey {
                verifier,
                access_key: AccessKey::fill_with(|out| *out = *secret),
            })
        })
    }

    /// The key as the local key store keeps it (`keys.md` 8.2): its tier
    /// byte and its payload, `u8(tier) || payload`. Nothing derived is
    /// stored. The store's file layout around it is the phase 1 change's.
    #[must_use]
    pub fn to_stored(&self) -> SecretBytes {
        let payload = self.payload();
        let mut out = Zeroizing::new(Vec::with_capacity(1 + payload.len()));
        out.push(self.tier().as_u8());
        out.extend_from_slice(&payload);
        out
    }

    /// Reads a key from its stored form.
    ///
    /// # Errors
    ///
    /// [`KeyError::Empty`] for an empty input, [`KeyError::Tier`] for an
    /// unknown tier byte, then as [`FolderKey::from_payload`].
    pub fn from_stored(bytes: &[u8]) -> Result<FolderKey, KeyError> {
        let (&tier, payload) = bytes.split_first().ok_or(KeyError::Empty)?;
        let tier = Tier::from_wire(u32::from(tier)).ok_or(KeyError::Tier(tier))?;
        FolderKey::from_payload(tier, payload)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;

    pub(crate) fn write_key(byte: u8) -> WriteKey {
        WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes([byte; 32])).unwrap()
    }

    /// The access key a folder key holds or derives.
    pub(crate) fn access_key_of(key: &FolderKey) -> [u8; 32] {
        match key {
            FolderKey::Write(k) => *k.data_key.access_key().expose(),
            FolderKey::Read(k) => *k.data_key.access_key().expose(),
            FolderKey::Sealed(k) => *k.access_key.expose(),
        }
    }

    #[test]
    fn the_derivation_tree_of_keys_md_1_2() {
        let w = write_key(1);
        let ws = w.secret().expose();
        assert_eq!(
            &*w.signing_seed(),
            &*derive_key(labels::FOLDER_SIGNING_KEY, ws)
        );
        assert_eq!(
            w.data_key().expose(),
            &*derive_key(labels::FOLDER_DATA_KEY, ws)
        );
        let vk = SigningKey::from_bytes(&derive_key(labels::FOLDER_SIGNING_KEY, ws))
            .verifying_key()
            .to_bytes();
        assert_eq!(w.verifier().verifying_key().as_bytes(), &vk);
        assert_eq!(
            w.verifier().folder_id().0,
            labelled_hash(labels::HASH_ID_FOLDER, &[&[0, 1], &vk])
        );
        assert_eq!(w.verifier().suite(), Suite::ONE);
        // Deterministic, and another secret is another folder.
        assert_eq!(write_key(1).verifier(), w.verifier());
        assert_ne!(
            write_key(2).verifier().folder_id(),
            w.verifier().folder_id()
        );
        let mut fill = |b: &mut [u8]| b.fill(1);
        assert_eq!(WriteKey::generate(&mut fill).verifier(), w.verifier());
    }

    #[test]
    fn every_tier_derives_the_same_folder_id_access_key_and_verifier() {
        let w = write_key(3);
        let r = w.read_key();
        let s = w.sealed_key();
        assert_eq!(r.verifier(), w.verifier());
        assert_eq!(s.verifier(), w.verifier());
        assert!(bool::from(r.data_key().ct_eq(w.data_key())));
        let keys = [
            FolderKey::from(write_key(3)),
            FolderKey::from(r),
            FolderKey::from(s),
        ];
        for k in &keys {
            assert_eq!(k.folder_id(), w.verifier().folder_id());
            assert_eq!(access_key_of(k), *w.data_key().access_key().expose());
        }
        assert!(keys[0].data_key().is_some() && keys[1].data_key().is_some());
        assert!(keys[2].data_key().is_none());
        assert!(keys[0].write_key().is_some());
        assert!(keys[1].write_key().is_none() && keys[2].write_key().is_none());
        assert_eq!(
            keys.iter().map(FolderKey::tier).collect::<Vec<_>>(),
            Tier::ALL
        );
        // A read key lowered to sealed is the write key's sealed key.
        let from_read = keys[1].lowered(Tier::Sealed).unwrap();
        assert_eq!(*from_read.payload(), *keys[2].payload());
    }

    #[test]
    fn lowering_gives_own_or_lower_tiers_only() {
        let w = FolderKey::from(write_key(4));
        for (from, to, ok) in [
            (Tier::Write, Tier::Write, true),
            (Tier::Write, Tier::Read, true),
            (Tier::Write, Tier::Sealed, true),
            (Tier::Read, Tier::Write, false),
            (Tier::Read, Tier::Read, true),
            (Tier::Read, Tier::Sealed, true),
            (Tier::Sealed, Tier::Write, false),
            (Tier::Sealed, Tier::Read, false),
            (Tier::Sealed, Tier::Sealed, true),
        ] {
            let key = w.lowered(from).unwrap();
            match key.lowered(to) {
                Ok(lower) => {
                    assert!(ok, "{from:?} gave {to:?}");
                    assert_eq!(lower.tier(), to);
                    assert_eq!(*lower.payload(), *w.lowered(to).unwrap().payload());
                    assert_eq!(lower.verifier(), w.verifier());
                }
                Err(e) => {
                    assert!(!ok, "{from:?} refused {to:?}");
                    assert_eq!(
                        e,
                        KeyError::NotLower {
                            own: from,
                            wanted: to
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn payloads_and_stored_forms_round_trip() {
        let w = write_key(5);
        let keys = [
            FolderKey::from(write_key(5)),
            FolderKey::from(w.read_key()),
            FolderKey::from(w.sealed_key()),
        ];
        for key in &keys {
            let payload = key.payload();
            assert_eq!(payload.len(), payload_len(key.tier()));
            assert_eq!(&payload[..2], &[0, 1]);
            assert_eq!(payload.capacity(), payload.len(), "sized once");
            let back = FolderKey::from_payload(key.tier(), &payload).unwrap();
            assert_eq!(back.verifier(), key.verifier());
            assert_eq!(*back.payload(), *payload);
            let stored = key.to_stored();
            assert_eq!(stored[0], key.tier().as_u8());
            assert_eq!(&stored[1..], &payload[..]);
            assert_eq!(
                *FolderKey::from_stored(&stored).unwrap().payload(),
                *payload
            );
        }
        assert_eq!(&keys[0].payload()[2..], w.secret().expose());
        assert_eq!(
            &keys[1].payload()[2..34],
            w.verifier().verifying_key().as_bytes()
        );
        assert_eq!(&keys[1].payload()[34..], w.data_key().expose());
        assert_eq!(&keys[2].payload()[34..], w.data_key().access_key().expose());
    }

    /// `keys.md` 6.1's order: a payload too short for its suite, then the
    /// suite whatever the length, then the length, then the verification key.
    #[test]
    fn payload_rejections_in_the_order_of_keys_md_6_1() {
        let w = write_key(6);
        let read = FolderKey::from(w.read_key()).payload();
        let length = |tier: Tier, found: usize| KeyError::Length {
            expected: payload_len(tier),
            found,
        };
        // Too short to hold a suite.
        for tier in Tier::ALL {
            assert_eq!(
                FolderKey::from_payload(tier, &[]).unwrap_err(),
                length(tier, 0)
            );
            assert_eq!(
                FolderKey::from_payload(tier, &[0]).unwrap_err(),
                length(tier, 1)
            );
        }
        // Suite 1, the wrong length.
        assert_eq!(
            FolderKey::from_payload(Tier::Read, &read[..65]).unwrap_err(),
            length(Tier::Read, 65)
        );
        assert_eq!(
            FolderKey::from_payload(Tier::Write, &read).unwrap_err(),
            length(Tier::Write, 66)
        );
        assert_eq!(
            FolderKey::from_payload(Tier::Write, &[0, 1]).unwrap_err(),
            length(Tier::Write, 2)
        );
        // Suite 0 and suite 2 are judged before the length, at every tier.
        for tier in Tier::ALL {
            for len in [2, payload_len(tier), 70] {
                let mut p = vec![7u8; len];
                p[0] = 0;
                p[1] = 0;
                assert_eq!(
                    FolderKey::from_payload(tier, &p).unwrap_err(),
                    KeyError::Suite(SuiteError::Zero),
                    "{tier:?} {len}"
                );
                p[1] = 2;
                let e = FolderKey::from_payload(tier, &p).unwrap_err();
                assert_eq!(e, KeyError::UnimplementedSuite(2), "{tier:?} {len}");
                assert_eq!(
                    e.to_string(),
                    "this key needs a newer release of Lickety-Sync"
                );
            }
        }
        // Some repeated-byte y coordinates have no square root for x and so
        // decode to no point; the first such byte is fixed by the curve.
        let undecodable = (0u8..=255)
            .find(|&b| VerifyingKey::from_bytes(&[b; 32]).is_err())
            .expect("some encoding is not a point");
        let mut not_a_point = read.to_vec();
        not_a_point[2..34].fill(undecodable);
        assert_eq!(
            FolderKey::from_payload(Tier::Read, &not_a_point).unwrap_err(),
            KeyError::VerifyingKey
        );
        // A non-canonical encoding of a valid point.
        let mut non_canonical = read.to_vec();
        non_canonical[2..34].copy_from_slice(&crate::sig::tests::non_canonical_point());
        assert_eq!(
            FolderKey::from_payload(Tier::Read, &non_canonical).unwrap_err(),
            KeyError::VerifyingKey
        );
        // The identity point is of small order.
        let mut small = read.to_vec();
        small[2..34].fill(0);
        small[2] = 1;
        assert_eq!(
            FolderKey::from_payload(Tier::Sealed, &small).unwrap_err(),
            KeyError::VerifyingKey
        );
        // The stored form: empty, an unknown tier, then the payload's checks.
        assert_eq!(FolderKey::from_stored(&[]).unwrap_err(), KeyError::Empty);
        assert_eq!(
            FolderKey::from_stored(&[0, 0, 1]).unwrap_err(),
            KeyError::Tier(0)
        );
        assert_eq!(
            FolderKey::from_stored(&[4, 0, 1]).unwrap_err(),
            KeyError::Tier(4)
        );
        assert_eq!(
            FolderKey::from_stored(&[1, 0, 1]).unwrap_err(),
            length(Tier::Write, 2)
        );
        assert_eq!(
            FolderKey::from_stored(&[3, 0, 2]).unwrap_err(),
            KeyError::UnimplementedSuite(2)
        );
        for e in [
            KeyError::Empty,
            length(Tier::Read, 2),
            KeyError::Suite(SuiteError::Zero),
            KeyError::VerifyingKey,
            KeyError::Tier(7),
            KeyError::NotLower {
                own: Tier::Sealed,
                wanted: Tier::Write,
            },
        ] {
            assert_ne!(e.to_string(), "");
        }
        assert_eq!(KeyError::Empty.to_string(), "the stored key is empty");
        assert_eq!(
            length(Tier::Read, 1).to_string(),
            "key material is 1 byte, not 66"
        );
        assert_eq!(
            length(Tier::Write, 2).to_string(),
            "key material is 2 bytes, not 34"
        );
    }

    /// Every constructor that takes a suite refuses one this release does not
    /// implement.
    #[test]
    fn suite_2_is_refused_by_every_constructor() {
        let two = Suite::from_wire(2).unwrap();
        let w = write_key(8);
        let vk = *w.verifier().verifying_key();
        assert_eq!(
            FolderVerifier::new(two, vk).unwrap_err(),
            KeyError::UnimplementedSuite(2)
        );
        assert_eq!(FolderVerifier::new(Suite::ONE, vk).unwrap(), *w.verifier());
        assert_eq!(
            WriteKey::from_secret(two, WriteSecret::from_bytes([0; 32])).unwrap_err(),
            KeyError::UnimplementedSuite(2)
        );
        assert_eq!(
            WriteKey::from_secret(
                Suite::from_wire(9).unwrap(),
                WriteSecret::from_bytes([0; 32])
            )
            .unwrap_err(),
            KeyError::UnimplementedSuite(9)
        );
        assert_eq!(
            FolderVerifyingKey::from_bytes(vk.as_bytes()).unwrap(),
            vk,
            "a derived key passes the received-key checks"
        );
    }

    #[test]
    fn debug_output_names_the_folder_and_nothing_secret() {
        let w = write_key(7);
        let id = w.verifier().folder_id().to_string();
        let secret_hex = hex(w.secret().expose());
        let dk_hex = hex(w.data_key().expose());
        let outputs = [
            format!("{w:?}"),
            format!("{:?}", w.read_key()),
            format!("{:?}", w.sealed_key()),
            format!("{:?}", FolderKey::from(write_key(7))),
            format!("{:?}", w.verifier()),
        ];
        for out in &outputs {
            assert!(out.contains(&id), "{out}");
            assert!(
                !out.contains(&secret_hex) && !out.contains(&dk_hex),
                "{out}"
            );
        }
        assert!(outputs[0].starts_with("WriteKey(") && outputs[0].ends_with("[redacted])"));
        assert!(format!("{:?}", w.verifier().verifying_key()).starts_with("FolderVerifyingKey("));
    }

    fn tier_strategy() -> impl Strategy<Value = Tier> {
        prop::sample::select(Tier::ALL.to_vec())
    }

    proptest! {
        /// The stored form of any key at any tier reads back to the same key.
        #[test]
        fn stored_forms_round_trip(ws in any::<[u8; 32]>(), tier in tier_strategy()) {
            let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).unwrap();
            let key = FolderKey::from(w).lowered(tier).unwrap();
            let stored = key.to_stored();
            let back = FolderKey::from_stored(&stored).unwrap();
            prop_assert_eq!(back.tier(), tier);
            prop_assert_eq!(back.verifier(), key.verifier());
            prop_assert_eq!(&*back.to_stored(), &*stored);
            let payload = key.payload();
            prop_assert_eq!(&*FolderKey::from_payload(tier, &payload).unwrap().payload(), &*payload);
        }

        /// Any bytes into the stored-form parser: no panic, and what it accepts
        /// it writes back byte for byte.
        #[test]
        fn any_bytes_into_the_stored_form(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            if let Ok(key) = FolderKey::from_stored(&bytes) {
                prop_assert_eq!(&*key.to_stored(), &bytes[..]);
            }
        }

        /// The same with a valid tier and suite in front, so that the length
        /// and verification-key checks are reached.
        #[test]
        fn any_payload_after_a_valid_suite(tier in tier_strategy(), rest in proptest::collection::vec(any::<u8>(), 0..70)) {
            let mut payload = vec![0, 1];
            payload.extend(&rest);
            match FolderKey::from_payload(tier, &payload) {
                Ok(key) => prop_assert_eq!(&*key.payload(), &payload[..]),
                Err(KeyError::Length { expected, found }) => {
                    prop_assert_eq!(expected, payload_len(tier));
                    prop_assert_eq!(found, payload.len());
                    prop_assert_ne!(found, expected);
                }
                Err(e) => prop_assert_eq!(e, KeyError::VerifyingKey),
            }
        }
    }
}
