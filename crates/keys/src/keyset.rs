// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key pair sets (`keys.md` section 0.3) and hybrid signatures (section 0.2,
//! `suites.md` section 2.2).
//!
//! Every key in the system is a [`KeyPairSet`] derived from one 32-byte seed
//! under three labels: an Ed25519 signing key, an ML-DSA-65 signing key and an
//! X-Wing KEM key. A hybrid signature is both signatures over
//! `M = label || 0x00 || body`, Ed25519 first, 3373 bytes; verification runs
//! both and reports one error that does not say which half failed (TM-33).

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use hpke::{kem::XWing, Deserializable, Kem, Serializable};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as MlSignature};
use zeroize::Zeroize;

use crate::ids::hex;
use crate::labels::{self, derive_key, SigLabel};
use crate::rng::{Adapter, RandomFill};
use crate::secret::Seed;
use crate::suite::{sizes, Suite, SuiteError};

pub(crate) type XWingPrivateKey = <XWing as Kem>::PrivateKey;
pub(crate) type XWingPublicKey = <XWing as Kem>::PublicKey;
type MlSigningKey = ml_dsa::SigningKey<MlDsa65>;
type MlVerifyingKey = ml_dsa::VerifyingKey<MlDsa65>;

/// Why public key material or a signature could not be read. Every variant is
/// "malformed" to the verifier that meets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// A hybrid signing public key must be exactly 1984 bytes.
    SigningKeySize(usize),
    /// The Ed25519 half is not a valid point.
    InvalidEd25519,
    /// An X-Wing public key must be exactly 1216 bytes and decode.
    InvalidKemKey(usize),
    /// A hybrid signature must be exactly 3373 bytes.
    SignatureSize(usize),
    /// The public key bytes `be16(suite) || signing_pk` must be 1986 bytes.
    PublicKeyBytesSize(usize),
    /// The suite in the public key bytes is not a suite number.
    Suite(SuiteError),
    /// The underlying crate refused material of the right size, which does
    /// not happen; kept so that no `unwrap` is needed.
    Internal,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningKeySize(n) => write!(
                f,
                "signing public key is {n} bytes, not {}",
                sizes::SIGNING_PK
            ),
            Self::InvalidEd25519 => f.write_str("the Ed25519 public key is not a valid point"),
            Self::InvalidKemKey(n) => write!(f, "X-Wing public key of {n} bytes is invalid"),
            Self::SignatureSize(n) => {
                write!(f, "signature is {n} bytes, not {}", sizes::HYBRID_SIG)
            }
            Self::PublicKeyBytesSize(n) => write!(
                f,
                "public key bytes are {n} bytes, not {}",
                sizes::PUBLIC_KEY_BYTES
            ),
            Self::Suite(e) => write!(f, "{e}"),
            Self::Internal => f.write_str("the cryptographic library refused well-sized input"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A hybrid signature did not verify. One error for both halves, on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureError;

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("hybrid signature did not verify")
    }
}

impl std::error::Error for SignatureError {}

/// Signing failed inside the ML-DSA crate, which with an empty context does
/// not happen; kept so that no `unwrap` is needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignError;

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signing failed")
    }
}

impl std::error::Error for SignError {}

/// A hybrid signing public key, `ed25519_pk (32) || mldsa65_pk (1952)`,
/// validated on construction (the Ed25519 half decodes to a point).
#[derive(Clone, PartialEq, Eq)]
pub struct SigningPublicKey {
    bytes: [u8; sizes::SIGNING_PK],
}

impl fmt::Debug for SigningPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningPublicKey({}..)",
            hex(self.bytes.get(..8).unwrap_or_default())
        )
    }
}

impl SigningPublicKey {
    /// Reads a key from exactly 1984 bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError::SigningKeySize`] or [`KeyError::InvalidEd25519`].
    pub fn parse(bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; sizes::SIGNING_PK] = bytes
            .try_into()
            .map_err(|_| KeyError::SigningKeySize(bytes.len()))?;
        let key = SigningPublicKey { bytes };
        key.ed25519_key()?;
        Ok(key)
    }

    /// The 1984 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::SIGNING_PK] {
        &self.bytes
    }

    /// The Ed25519 half, which the handshake's role rule compares
    /// (`protocol.md` 3.2).
    #[must_use]
    pub fn ed25519_bytes(&self) -> &[u8] {
        self.bytes.get(..sizes::ED25519_PK).unwrap_or(&[])
    }

    /// The public key bytes `be16(suite) || signing_pk` (section 0.3): what
    /// Hello carries and what every identity hash is taken over.
    #[must_use]
    pub fn wire_form(&self, suite: Suite) -> Vec<u8> {
        let mut out = Vec::with_capacity(sizes::PUBLIC_KEY_BYTES);
        out.extend_from_slice(&suite.be16());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Reads `be16(suite) || signing_pk` as Hello carries it.
    ///
    /// # Errors
    ///
    /// Wrong length, an invalid suite number, or an invalid key.
    pub fn from_wire(bytes: &[u8]) -> Result<(Suite, Self), KeyError> {
        if bytes.len() != sizes::PUBLIC_KEY_BYTES {
            return Err(KeyError::PublicKeyBytesSize(bytes.len()));
        }
        let (suite, key) = bytes
            .split_first_chunk::<2>()
            .ok_or(KeyError::PublicKeyBytesSize(bytes.len()))?;
        let suite =
            Suite::from_wire(u32::from(u16::from_be_bytes(*suite))).map_err(KeyError::Suite)?;
        Ok((suite, Self::parse(key)?))
    }

    fn ed25519_key(&self) -> Result<EdVerifyingKey, KeyError> {
        let bytes: [u8; 32] = self
            .bytes
            .get(..sizes::ED25519_PK)
            .and_then(|b| b.try_into().ok())
            .ok_or(KeyError::Internal)?;
        EdVerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidEd25519)
    }

    fn mldsa_key(&self) -> Result<MlVerifyingKey, KeyError> {
        let encoded = self
            .bytes
            .get(sizes::ED25519_PK..)
            .and_then(|b| EncodedVerifyingKey::<MlDsa65>::try_from(b).ok())
            .ok_or(KeyError::Internal)?;
        Ok(MlVerifyingKey::decode(&encoded))
    }

    /// `HybridVerify(pk, label, body, sig)`: both halves over
    /// `M = label || 0x00 || body`, Ed25519 by `verify_strict`, ML-DSA-65 with
    /// an empty context. Both are always run.
    ///
    /// # Errors
    ///
    /// One [`SignatureError`] whichever half failed.
    pub fn verify(
        &self,
        label: SigLabel,
        body: &[u8],
        sig: &HybridSignature,
    ) -> Result<(), SignatureError> {
        let m = labels::signed_message(label, body);
        let (ed_sig, ml_sig) = sig.bytes.split_at(sizes::ED25519_SIG);
        let ed_ok = match (self.ed25519_key(), <[u8; 64]>::try_from(ed_sig)) {
            (Ok(pk), Ok(bytes)) => pk
                .verify_strict(&m, &ed25519_dalek::Signature::from_bytes(&bytes))
                .is_ok(),
            _ => false,
        };
        let ml_ok = match (
            self.mldsa_key(),
            EncodedSignature::<MlDsa65>::try_from(ml_sig),
        ) {
            (Ok(pk), Ok(encoded)) => MlSignature::<MlDsa65>::decode(&encoded)
                .is_some_and(|s| pk.verify_with_context(&m, b"", &s)),
            _ => false,
        };
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(SignatureError)
        }
    }
}

/// An X-Wing public (encapsulation) key, 1216 bytes, validated on construction.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey {
    bytes: [u8; sizes::XWING_PK],
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KemPublicKey({}..)",
            hex(self.bytes.get(..8).unwrap_or_default())
        )
    }
}

impl KemPublicKey {
    /// Reads a key from exactly 1216 bytes that X-Wing accepts.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidKemKey`].
    pub fn parse(bytes: &[u8]) -> Result<Self, KeyError> {
        let key =
            XWingPublicKey::from_bytes(bytes).map_err(|_| KeyError::InvalidKemKey(bytes.len()))?;
        Ok(KemPublicKey {
            bytes: key.to_bytes().into(),
        })
    }

    /// The 1216 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::XWING_PK] {
        &self.bytes
    }

    pub(crate) fn to_hpke(&self) -> Result<XWingPublicKey, KeyError> {
        XWingPublicKey::from_bytes(&self.bytes).map_err(|_| KeyError::Internal)
    }
}

/// The public halves of a key pair set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeySet {
    /// `ed25519_pk || mldsa_pk`, 1984 bytes.
    pub signing: SigningPublicKey,
    /// The X-Wing public key, 1216 bytes.
    pub kem: KemPublicKey,
}

impl PublicKeySet {
    /// The key ID an issued key with these public halves has under `suite`.
    #[must_use]
    pub fn key_id(&self, suite: Suite) -> crate::ids::KeyId {
        crate::derive::key_id(suite, &self.signing, &self.kem)
    }
}

/// A hybrid signature, `ed25519_sig (64) || mldsa65_sig (3309)`.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    bytes: [u8; sizes::HYBRID_SIG],
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridSignature({}..)",
            hex(self.bytes.get(..8).unwrap_or_default())
        )
    }
}

impl HybridSignature {
    /// Reads a signature from exactly 3373 bytes. Validity is judged by
    /// [`SigningPublicKey::verify`], never here.
    ///
    /// # Errors
    ///
    /// [`KeyError::SignatureSize`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| KeyError::SignatureSize(bytes.len()))?;
        Ok(HybridSignature { bytes })
    }

    /// The 3373 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::HYBRID_SIG] {
        &self.bytes
    }
}

/// A key pair set: the three private keys derived from one seed, and their
/// public halves. Zeroized on drop; `Debug` is redacted. The ML-DSA-65 key,
/// 64 KiB expanded, lives on the heap so that the set can be moved freely.
pub struct KeyPairSet {
    ed: EdSigningKey,
    mldsa: Box<MlSigningKey>,
    kem: XWingPrivateKey,
    public: PublicKeySet,
}

impl fmt::Debug for KeyPairSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyPairSet([redacted])")
    }
}

impl KeyPairSet {
    /// `KeyPairSet(seed)` (section 0.3): the Ed25519 key from
    /// `derive_key("licketysync/v1/key/ed25519", seed)`, the ML-DSA-65 key
    /// from `KeyGen_internal(derive_key("licketysync/v1/key/ml-dsa-65", seed))`,
    /// and the X-Wing key from its decapsulation seed
    /// `derive_key("licketysync/v1/key/x-wing", seed)` loaded as such, never
    /// through HPKE's `derive_keypair` (`suites.md` 2.1).
    ///
    /// # Errors
    ///
    /// [`KeyError::Internal`] only if a crate refused 32 well-formed bytes,
    /// which does not happen.
    pub fn from_seed(seed: &Seed) -> Result<KeyPairSet, KeyError> {
        let ed_seed = derive_key(labels::KEY_ED25519, seed.expose());
        let ed = EdSigningKey::from_bytes(&ed_seed);

        let xi = derive_key(labels::KEY_ML_DSA_65, seed.expose());
        let mut xi_array = ml_dsa::B32::from(*xi);
        let mldsa = Box::new(MlSigningKey::from_seed(&xi_array));
        xi_array.zeroize();

        let kem_seed = derive_key(labels::KEY_X_WING, seed.expose());
        let kem = XWingPrivateKey::from_bytes(&*kem_seed).map_err(|_| KeyError::Internal)?;

        let mut signing = [0u8; sizes::SIGNING_PK];
        signing
            .get_mut(..sizes::ED25519_PK)
            .ok_or(KeyError::Internal)?
            .copy_from_slice(ed.verifying_key().as_bytes());
        signing
            .get_mut(sizes::ED25519_PK..)
            .ok_or(KeyError::Internal)?
            .copy_from_slice(&mldsa.expanded_key().verifying_key().encode());
        let kem_pk = XWing::sk_to_pk(&kem).to_bytes();
        Ok(KeyPairSet {
            ed,
            mldsa,
            kem,
            public: PublicKeySet {
                signing: SigningPublicKey { bytes: signing },
                kem: KemPublicKey {
                    bytes: kem_pk.into(),
                },
            },
        })
    }

    /// The public halves.
    #[must_use]
    pub fn public(&self) -> &PublicKeySet {
        &self.public
    }

    /// `HybridSign(sk, label, body)` with the deterministic ML-DSA variant:
    /// Ed25519 (RFC 8032, pure) and ML-DSA-65 (FIPS 204, `rnd` = 32 zero
    /// bytes, empty context) over `M = label || 0x00 || body`. Test vectors
    /// use this form, so it exists only in tests and under the
    /// `test-vectors` feature; production signs with [`KeyPairSet::sign`].
    ///
    /// # Errors
    ///
    /// [`SignError`] only if the ML-DSA crate refuses, which with an empty
    /// context it does not.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn sign_deterministic(
        &self,
        label: SigLabel,
        body: &[u8],
    ) -> Result<HybridSignature, SignError> {
        let m = labels::signed_message(label, body);
        let ml = self
            .mldsa
            .expanded_key()
            .sign_deterministic(&m, b"")
            .map_err(|_| SignError)?;
        self.assemble(&m, &ml)
    }

    /// `HybridSign(sk, label, body)` with the hedged ML-DSA variant
    /// (`suites.md` 2.2, "Signing variant"): Ed25519 (RFC 8032, pure) and
    /// ML-DSA-65 (FIPS 204, empty context) over `M = label || 0x00 || body`,
    /// with 32 fresh bytes from the caller's randomness entering the ML-DSA
    /// signature, which resists fault attacks on the signing device. The only
    /// signing form outside tests; a verifier cannot tell it from the
    /// deterministic one.
    ///
    /// # Errors
    ///
    /// [`SignError`] only if the ML-DSA crate refuses.
    pub fn sign(
        &self,
        label: SigLabel,
        body: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<HybridSignature, SignError> {
        let m = labels::signed_message(label, body);
        let ml = self
            .mldsa
            .expanded_key()
            .sign_randomized(&m, b"", &mut Adapter(rng))
            .map_err(|_| SignError)?;
        self.assemble(&m, &ml)
    }

    fn assemble(&self, m: &[u8], ml: &MlSignature<MlDsa65>) -> Result<HybridSignature, SignError> {
        let mut bytes = [0u8; sizes::HYBRID_SIG];
        bytes
            .get_mut(..sizes::ED25519_SIG)
            .ok_or(SignError)?
            .copy_from_slice(&self.ed.sign(m).to_bytes());
        bytes
            .get_mut(sizes::ED25519_SIG..)
            .ok_or(SignError)?
            .copy_from_slice(&ml.encode());
        Ok(HybridSignature { bytes })
    }

    pub(crate) fn kem_private(&self) -> &XWingPrivateKey {
        &self.kem
    }

    /// The Ed25519 seed as a zeroizing buffer, for a test that pins the
    /// derivation; not used by the crate itself.
    #[cfg(test)]
    pub(crate) fn ed25519_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.ed.to_bytes())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;

    fn set(byte: u8) -> KeyPairSet {
        KeyPairSet::from_seed(&Seed::from_bytes([byte; 32])).unwrap()
    }

    #[test]
    fn derivation_is_deterministic_and_seed_specific() {
        let a = set(1);
        let b = set(1);
        let c = set(2);
        assert_eq!(a.public(), b.public());
        assert_ne!(a.public(), c.public());
        assert_eq!(a.public().signing.as_bytes().len(), 1984);
        assert_eq!(a.public().kem.as_bytes().len(), 1216);
        assert_eq!(format!("{a:?}"), "KeyPairSet([redacted])");
        assert_eq!(
            &*a.ed25519_seed(),
            &*derive_key(labels::KEY_ED25519, &[1u8; 32])
        );
        assert!(format!("{:?}", a.public().signing).starts_with("SigningPublicKey("));
        assert!(format!("{:?}", a.public().kem).starts_with("KemPublicKey("));
    }

    #[test]
    fn sign_and_verify_both_halves() {
        let a = set(3);
        let sig = a.sign_deterministic(labels::SIG_GRANT, b"body").unwrap();
        assert_eq!(sig.as_bytes().len(), 3373);
        assert!(format!("{sig:?}").starts_with("HybridSignature("));
        let pk = &a.public().signing;
        assert_eq!(pk.verify(labels::SIG_GRANT, b"body", &sig), Ok(()));
        // Deterministic: the same body signs to the same bytes.
        assert_eq!(
            a.sign_deterministic(labels::SIG_GRANT, b"body").unwrap(),
            sig
        );
        // Another label, another body, another key: all fail with one error.
        assert_eq!(
            pk.verify(labels::SIG_REVOCATION, b"body", &sig),
            Err(SignatureError)
        );
        assert_eq!(
            pk.verify(labels::SIG_GRANT, b"bodz", &sig),
            Err(SignatureError)
        );
        assert_eq!(
            set(4)
                .public()
                .signing
                .verify(labels::SIG_GRANT, b"body", &sig),
            Err(SignatureError)
        );
        // Corrupting either half alone fails: both are required (TM-33).
        let mut ed_broken = *sig.as_bytes();
        ed_broken[0] ^= 1;
        let ed_broken = HybridSignature::from_bytes(&ed_broken).unwrap();
        assert_eq!(
            pk.verify(labels::SIG_GRANT, b"body", &ed_broken),
            Err(SignatureError)
        );
        let mut ml_broken = *sig.as_bytes();
        ml_broken[3372] ^= 1;
        let ml_broken = HybridSignature::from_bytes(&ml_broken).unwrap();
        assert_eq!(
            pk.verify(labels::SIG_GRANT, b"body", &ml_broken),
            Err(SignatureError)
        );
        // An ML-DSA half that does not even decode fails too.
        let mut ml_garbage = *sig.as_bytes();
        for b in &mut ml_garbage[64..] {
            *b = 0xff;
        }
        let ml_garbage = HybridSignature::from_bytes(&ml_garbage).unwrap();
        assert_eq!(
            pk.verify(labels::SIG_GRANT, b"body", &ml_garbage),
            Err(SignatureError)
        );
        assert_eq!(
            SignatureError.to_string(),
            "hybrid signature did not verify"
        );
        assert_eq!(SignError.to_string(), "signing failed");
    }

    /// A small-order Ed25519 public key (the identity point) with the
    /// signature `R = identity, s = 0` verifies under RFC 8032's cofactorless
    /// equation for every message, so `verify` accepts it; `verify_strict`
    /// refuses the weak key, and so does the hybrid verification, though its
    /// ML-DSA half is a real signature over the same message.
    #[test]
    fn a_weak_ed25519_key_passes_verify_but_not_verify_strict_or_the_hybrid() {
        use ed25519_dalek::Verifier as _;
        let kp = KeyPairSet::from_seed(&Seed::from_bytes([5; 32])).unwrap();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut pk_bytes = kp.public().signing.as_bytes().to_vec();
        pk_bytes[..32].copy_from_slice(&identity);
        let weak = SigningPublicKey::parse(&pk_bytes).unwrap();
        let body = b"any body";
        let m = labels::signed_message(labels::SIG_INDEX, body);
        let mut weak_sig = [0u8; 64];
        weak_sig[0] = 1;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&weak_sig);
        let ed_pk = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
        assert!(
            ed_pk.verify(&m, &ed_sig).is_ok(),
            "the cofactorless check accepts it"
        );
        assert!(ed_pk.verify_strict(&m, &ed_sig).is_err());
        let real = kp.sign_deterministic(labels::SIG_INDEX, body).unwrap();
        let mut hybrid = real.as_bytes().to_vec();
        hybrid[..64].copy_from_slice(&weak_sig);
        let hybrid = HybridSignature::from_bytes(&hybrid).unwrap();
        assert_eq!(
            weak.verify(labels::SIG_INDEX, body, &hybrid),
            Err(SignatureError)
        );
    }

    #[test]
    fn hedged_signatures_verify_and_differ_by_randomness() {
        let a = set(5);
        let mut r1 = |buf: &mut [u8]| buf.fill(1);
        let mut r2 = |buf: &mut [u8]| buf.fill(2);
        let s1 = a.sign(labels::SIG_INDEX, b"x", &mut r1).unwrap();
        let s2 = a.sign(labels::SIG_INDEX, b"x", &mut r2).unwrap();
        let s3 = a.sign_deterministic(labels::SIG_INDEX, b"x").unwrap();
        assert_eq!(
            a.public().signing.verify(labels::SIG_INDEX, b"x", &s1),
            Ok(())
        );
        assert_eq!(
            a.public().signing.verify(labels::SIG_INDEX, b"x", &s2),
            Ok(())
        );
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        // The Ed25519 half is deterministic whatever the variant.
        assert_eq!(s1.as_bytes()[..64], s3.as_bytes()[..64]);
    }

    #[test]
    fn parsing_checks_sizes_and_points() {
        assert_eq!(
            SigningPublicKey::parse(&[0u8; 10]),
            Err(KeyError::SigningKeySize(10))
        );
        // Some repeated-byte y coordinates have no square root for x and so
        // decode to no point; the first such byte is fixed by the curve.
        let undecodable = (0u8..=255)
            .find(|&b| EdVerifyingKey::from_bytes(&[b; 32]).is_err())
            .expect("some encoding is not a point");
        let mut bad = [0u8; 1984];
        bad[..32].fill(undecodable);
        assert_eq!(
            SigningPublicKey::parse(&bad).err(),
            Some(KeyError::InvalidEd25519)
        );
        assert_eq!(
            KemPublicKey::parse(&[0u8; 5]),
            Err(KeyError::InvalidKemKey(5))
        );
        assert_eq!(
            HybridSignature::from_bytes(&[0u8; 3372]),
            Err(KeyError::SignatureSize(3372))
        );
        assert!(HybridSignature::from_bytes(&[0u8; 3373]).is_ok());
        let a = set(6);
        let wire = a.public().signing.wire_form(Suite::ONE);
        assert_eq!(wire.len(), 1986);
        assert_eq!(&wire[..2], &[0, 1]);
        let (suite, pk) = SigningPublicKey::from_wire(&wire).unwrap();
        assert_eq!(suite, Suite::ONE);
        assert_eq!(&pk, &a.public().signing);
        assert_eq!(pk.ed25519_bytes(), &a.public().signing.as_bytes()[..32]);
        assert_eq!(
            SigningPublicKey::from_wire(&wire[1..]),
            Err(KeyError::PublicKeyBytesSize(1985))
        );
        let mut zero_suite = wire.clone();
        zero_suite[1] = 0;
        assert_eq!(
            SigningPublicKey::from_wire(&zero_suite),
            Err(KeyError::Suite(SuiteError::Zero))
        );
        let kem = KemPublicKey::parse(a.public().kem.as_bytes()).unwrap();
        assert_eq!(&kem, &a.public().kem);
        for e in [
            KeyError::SigningKeySize(1),
            KeyError::InvalidEd25519,
            KeyError::InvalidKemKey(2),
            KeyError::SignatureSize(3),
            KeyError::PublicKeyBytesSize(4),
            KeyError::Suite(SuiteError::Zero),
            KeyError::Internal,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }
}
