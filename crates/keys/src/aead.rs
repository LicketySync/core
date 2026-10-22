// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! XChaCha20-Poly1305 (`suites.md` section 2.3) under a key, nonce and
//! associated data the caller names: the one AEAD of suite 1, and private to
//! this crate. Chunks ([`crate::chunk`]), sealed metadata
//! ([`crate::sealed_meta`]) and the handshake's `FolderProof` payload
//! ([`crate::handshake::HandshakeKeys::seal_proof`]) seal through these
//! functions, each under its own derived key and with its nonce chosen inside
//! this crate: convergent for chunks, fresh from the caller's randomness for
//! metadata and proofs. A nonce must never repeat under one key; these
//! functions cannot check that, which is why no caller outside the crate
//! reaches them.

use core::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::suite::sizes;

/// An XChaCha20-Poly1305 open failed: a wrong key, nonce or associated data
/// or a damaged ciphertext, one error on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authenticated decryption failed")
    }
}

impl std::error::Error for AeadError {}

/// An XChaCha20-Poly1305 seal failed, which happens only for a plaintext
/// beyond the cipher's limit of about 256 GiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealError;

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the plaintext is beyond the cipher's limit")
    }
}

impl std::error::Error for SealError {}

/// Seals `plaintext` under `key` and `nonce`, binding `aad`; returns
/// `ciphertext || tag`, [`sizes::TAG`] bytes longer than the plaintext.
///
/// # Errors
///
/// [`SealError`] only for a plaintext beyond the cipher's limit.
pub(crate) fn xchacha_seal(
    key: &[u8; sizes::KEY],
    nonce: &[u8; sizes::NONCE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealError)
}

/// Opens `ciphertext || tag` sealed under `key`, `nonce` and `aad`. The
/// plaintext comes back in a buffer that is zeroed when dropped; nothing is
/// returned unless the tag verifies.
///
/// # Errors
///
/// [`AeadError`] for any failure, a ciphertext shorter than the tag included.
pub(crate) fn xchacha_open(
    key: &[u8; sizes::KEY],
    nonce: &[u8; sizes::NONCE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, AeadError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| AeadError)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trips_and_binds_key_nonce_aad_and_every_byte() {
        let key = [7u8; 32];
        let nonce = [9u8; sizes::NONCE];
        let sealed = xchacha_seal(&key, &nonce, b"hint", b"payload").unwrap();
        assert_eq!(sealed.len(), b"payload".len() + sizes::TAG);
        assert_eq!(
            xchacha_open(&key, &nonce, b"hint", &sealed)
                .unwrap()
                .as_slice(),
            b"payload"
        );
        // The same inputs seal to the same bytes; another nonce to others.
        assert_eq!(
            xchacha_seal(&key, &nonce, b"hint", b"payload").unwrap(),
            sealed
        );
        assert_ne!(
            xchacha_seal(&key, &[8; sizes::NONCE], b"hint", b"payload").unwrap(),
            sealed
        );
        assert_eq!(
            xchacha_open(&[6; 32], &nonce, b"hint", &sealed),
            Err(AeadError)
        );
        assert_eq!(
            xchacha_open(&key, &[8; sizes::NONCE], b"hint", &sealed),
            Err(AeadError)
        );
        assert_eq!(xchacha_open(&key, &nonce, b"hinT", &sealed), Err(AeadError));
        for i in 0..sealed.len() {
            let mut damaged = sealed.clone();
            damaged[i] ^= 0x01;
            assert_eq!(
                xchacha_open(&key, &nonce, b"hint", &damaged),
                Err(AeadError)
            );
        }
        // Shorter than the tag, or the tag alone of another message.
        assert_eq!(
            xchacha_open(&key, &nonce, b"hint", &sealed[..15]),
            Err(AeadError)
        );
        assert_eq!(xchacha_open(&key, &nonce, b"hint", &[]), Err(AeadError));
        // An empty plaintext seals to the tag alone and opens to nothing.
        let empty = xchacha_seal(&key, &nonce, b"", b"").unwrap();
        assert_eq!(empty.len(), sizes::TAG);
        assert!(xchacha_open(&key, &nonce, b"", &empty).unwrap().is_empty());
        assert_eq!(AeadError.to_string(), "authenticated decryption failed");
        assert_eq!(
            SealError.to_string(),
            "the plaintext is beyond the cipher's limit"
        );
    }

    /// The draft-irtf-cfrg-xchacha-03 Appendix A vector (`suites.md` 4.4),
    /// through the crate's own seal and open, the functions every AEAD use of
    /// the crate goes through.
    #[test]
    fn vector_xchacha20poly1305_draft() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/vectors/xchacha20poly1305_draft03.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
        let key: [u8; 32] = bytes("key").try_into().unwrap();
        let nonce: [u8; 24] = bytes("nonce").try_into().unwrap();
        let out = xchacha_seal(&key, &nonce, &bytes("aad"), &bytes("plaintext")).unwrap();
        let mut expected = bytes("ciphertext");
        expected.extend(bytes("tag"));
        assert_eq!(out, expected);
        let back = xchacha_open(&key, &nonce, &bytes("aad"), &out).unwrap();
        assert_eq!(*back, bytes("plaintext"));
    }
}
