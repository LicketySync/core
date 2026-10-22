// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ed25519 over labelled messages (`keys.md` 0.2, `suites.md` 2.2): every
//! signature in Lickety-Sync is pure Ed25519 (RFC 8032, no prehash, no
//! context) over `M = label || 0x00 || body`, verified with `verify_strict`,
//! which rejects small-order and non-canonical components. Signing is
//! deterministic, so the same key and body always give the same signature and
//! the test vectors reproduce through this, the production signing path.
//!
//! The keys that sign are [`crate::folder::WriteKey`] (index records) and
//! [`crate::device::DeviceKey`] (the device proof); this module holds the
//! signature type, the two operations they share, and the check every public
//! key received from anywhere passes before it is used (`keys.md` 0.3).

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::ids::hex;
use crate::labels::{signed_message, SigLabel};
use crate::suite::sizes;

/// An Ed25519 signature, exactly 64 bytes. Validity is judged by the
/// verifier, never here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; sizes::ED25519_SIG]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature({}..)",
            hex(self.0.get(..8).unwrap_or_default())
        )
    }
}

impl Signature {
    /// Reads a signature from exactly 64 bytes; any other length is
    /// malformed, judged before any verification runs.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Signature> {
        <[u8; sizes::ED25519_SIG]>::try_from(bytes)
            .ok()
            .map(Signature)
    }

    /// Wraps 64 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; sizes::ED25519_SIG]) -> Signature {
        Signature(bytes)
    }

    /// The 64 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; sizes::ED25519_SIG] {
        &self.0
    }
}

/// A signature did not verify: wrong key, wrong label, wrong body, a weak key
/// or a non-canonical component. One error on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureError;

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature did not verify")
    }
}

impl std::error::Error for SignatureError {}

/// Reads an Ed25519 public key received from anywhere (a key string, a
/// Hello): it must be the canonical encoding of a point, so that decoding it
/// and encoding the point again gives back the same 32 bytes, and the point
/// must not be of small order (`keys.md` 0.3, `suites.md` 2.2). One key
/// therefore has exactly one encoding and one ID. `ed25519-dalek` decodes by
/// ZIP-215's rules, which accept non-canonical encodings, hence the
/// re-encoding.
pub(crate) fn canonical_public_key(bytes: &[u8; sizes::ED25519_PK]) -> Option<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes).ok()?;
    (key.to_edwards().compress().as_bytes() == bytes && !key.is_weak()).then_some(key)
}

/// `Sign(sk, label, body) = Ed25519.Sign(sk, label || 0x00 || body)`.
pub(crate) fn sign(key: &SigningKey, label: SigLabel, body: &[u8]) -> Signature {
    Signature(key.sign(&signed_message(label, body)).to_bytes())
}

/// `Verify(pk, label, body, sig) = Ed25519.VerifyStrict(pk, label || 0x00 ||
/// body, sig)`; the 64-byte length is the [`Signature`] type's.
pub(crate) fn verify(
    key: &VerifyingKey,
    label: SigLabel,
    body: &[u8],
    sig: &Signature,
) -> Result<(), SignatureError> {
    key.verify_strict(
        &signed_message(label, body),
        &ed25519_dalek::Signature::from_bytes(&sig.0),
    )
    .map_err(|_| SignatureError)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]
pub(crate) mod tests {
    use super::*;
    use crate::labels::{SIG_DEVICE_PROOF, SIG_INDEX};

    #[test]
    fn signatures_bind_label_body_and_key_and_are_deterministic() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let vk = key.verifying_key();
        let sig = sign(&key, SIG_INDEX, b"body");
        assert_eq!(sign(&key, SIG_INDEX, b"body"), sig, "deterministic");
        assert_eq!(verify(&vk, SIG_INDEX, b"body", &sig), Ok(()));
        assert_eq!(
            verify(&vk, SIG_DEVICE_PROOF, b"body", &sig),
            Err(SignatureError)
        );
        assert_eq!(verify(&vk, SIG_INDEX, b"bodz", &sig), Err(SignatureError));
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert_eq!(
            verify(&other, SIG_INDEX, b"body", &sig),
            Err(SignatureError)
        );
        // The message is the label, a zero byte and the body: plain Ed25519.
        assert!(vk
            .verify_strict(
                b"licketysync/v1/sig/index\0body",
                &ed25519_dalek::Signature::from_bytes(sig.as_bytes())
            )
            .is_ok());
        assert!(Signature::from_slice(&[0u8; 63]).is_none());
        assert!(Signature::from_slice(&[0u8; 65]).is_none());
        assert_eq!(
            Signature::from_slice(sig.as_bytes()),
            Some(Signature::from_bytes(*sig.as_bytes()))
        );
        assert!(format!("{sig:?}").starts_with("Signature("));
        assert_eq!(SignatureError.to_string(), "signature did not verify");
    }

    /// A non-canonical encoding of a valid point that is not of small order:
    /// `y + p` for a small `y`, with either sign bit. The first such encoding
    /// is found by search, as the curve fixes it.
    pub(crate) fn non_canonical_point() -> [u8; 32] {
        for k in 0u8..19 {
            for sign in [0u8, 0x80] {
                // p + k = 2^255 - 19 + k, little-endian.
                let mut bytes = [0xffu8; 32];
                bytes[0] = 0xed + k;
                bytes[31] = 0x7f | sign;
                if let Ok(key) = VerifyingKey::from_bytes(&bytes) {
                    if !key.is_weak() {
                        return bytes;
                    }
                }
            }
        }
        panic!("no non-canonical encoding of a large-order point below p + 19")
    }

    #[test]
    fn public_keys_must_be_canonical_and_not_of_small_order() {
        let good = SigningKey::from_bytes(&[3u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            canonical_public_key(&good).map(|k| k.to_bytes()),
            Some(good)
        );
        // Decodes (ZIP-215) but is not canonical.
        let nc = non_canonical_point();
        let lax = VerifyingKey::from_bytes(&nc).unwrap();
        assert_ne!(lax.to_edwards().compress().as_bytes(), &nc);
        assert!(canonical_public_key(&nc).is_none());
        // The identity point: canonical and of small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(VerifyingKey::from_bytes(&identity).unwrap().is_weak());
        assert!(canonical_public_key(&identity).is_none());
        // Not a point at all.
        let undecodable = (0u8..=255)
            .find(|&b| VerifyingKey::from_bytes(&[b; 32]).is_err())
            .unwrap();
        assert!(canonical_public_key(&[undecodable; 32]).is_none());
    }

    /// A small-order public key (the identity point) with the signature
    /// `R = identity, s = 0` verifies under RFC 8032's cofactorless equation
    /// for every message, so the lax `verify` accepts it; the strict check
    /// this crate uses refuses it.
    #[test]
    fn a_weak_key_passes_lax_verify_but_not_verify_strict() {
        use ed25519_dalek::Verifier as _;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(weak.is_weak());
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let m = signed_message(SIG_INDEX, b"any body");
        assert!(
            weak.verify(&m, &ed25519_dalek::Signature::from_bytes(&forged))
                .is_ok(),
            "the cofactorless check accepts it"
        );
        assert_eq!(
            verify(
                &weak,
                SIG_INDEX,
                b"any body",
                &Signature::from_bytes(forged)
            ),
            Err(SignatureError)
        );
    }
}
