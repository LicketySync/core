// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! XChaCha20-Poly1305 (`suites.md` section 2.3) under a key, nonce and
//! associated data the caller names: the one AEAD of suite 1. The record key,
//! the chunk key and the ladder seal through these functions, and so does the
//! handshake's `FolderProof` payload (`protocol.md` 3.5), whose construction
//! stays in the protocol crate: the key is the proof key
//! ([`crate::secret::ProofKey`], whose `seal` and `open` call these), the
//! associated data the hint ([`crate::labels::folder_hint`]), and the 24-byte
//! nonce fresh from the caller's randomness for every seal. A nonce must never
//! repeat under one key; these functions cannot check that.

use core::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;

/// The Poly1305 tag's length: a ciphertext is this much longer than its
/// plaintext.
pub const TAG_LEN: usize = crate::suite::sizes::TAG;

/// The `XChaCha20` nonce's length.
pub const NONCE_LEN: usize = crate::suite::sizes::NONCE;

/// An XChaCha20-Poly1305 seal or open failed: on open, a wrong key, nonce or
/// associated data or a damaged ciphertext, one error on purpose; on seal,
/// only a plaintext beyond the cipher's limit of about 256 GiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authenticated decryption failed")
    }
}

impl std::error::Error for AeadError {}

/// Seals `plaintext` under `key` and `nonce`, binding `aad`; returns
/// `ciphertext || tag`, [`TAG_LEN`] bytes longer than the plaintext.
///
/// # Errors
///
/// [`AeadError`] only for a plaintext beyond the cipher's limit.
pub fn xchacha_seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError)
}

/// Opens `ciphertext || tag` sealed under `key`, `nonce` and `aad`. The
/// plaintext comes back in a buffer that is zeroed when dropped; nothing is
/// returned unless the tag verifies.
///
/// # Errors
///
/// [`AeadError`] for any failure, a ciphertext shorter than the tag included.
pub fn xchacha_open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
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
        let nonce = [9u8; NONCE_LEN];
        let sealed = xchacha_seal(&key, &nonce, b"hint", b"payload").unwrap();
        assert_eq!(sealed.len(), b"payload".len() + TAG_LEN);
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
            xchacha_seal(&key, &[8; NONCE_LEN], b"hint", b"payload").unwrap(),
            sealed
        );
        assert_eq!(
            xchacha_open(&[6; 32], &nonce, b"hint", &sealed),
            Err(AeadError)
        );
        assert_eq!(
            xchacha_open(&key, &[8; NONCE_LEN], b"hint", &sealed),
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
        assert_eq!(empty.len(), TAG_LEN);
        assert!(xchacha_open(&key, &nonce, b"", &empty).unwrap().is_empty());
        assert_eq!(AeadError.to_string(), "authenticated decryption failed");
    }

    /// The `FolderProof` seal as `protocol.md` 3.5 builds it from these
    /// primitives: the proof key and hint from the folder ID and the
    /// transcript hash, the hint as associated data. Another transcript, role
    /// or folder gives a seal that does not open.
    #[test]
    fn the_folder_proof_construction_opens_only_for_the_same_folder_and_transcript() {
        use crate::ids::FolderId;
        use crate::labels::folder_hint;
        use crate::secret::ProofKey;
        let folder = FolderId([3u8; 32]);
        let th = [4u8; 32];
        let parts = |folder: &FolderId, th: &[u8; 32], role: u8| {
            (folder_hint(folder, th, role), ProofKey::derive(folder, th))
        };
        let (hint, key) = parts(&folder, &th, 0);
        let nonce = [5u8; NONCE_LEN];
        let sealed = key.seal(&nonce, &hint, b"ProofPayload").unwrap();
        assert_eq!(
            sealed,
            xchacha_seal(key.expose(), &nonce, &hint, b"ProofPayload").unwrap()
        );
        let (hint_b, key_b) = parts(&folder, &th, 0);
        assert_eq!(
            key_b.open(&nonce, &hint_b, &sealed).unwrap().as_slice(),
            b"ProofPayload"
        );
        let (other_hint, _) = parts(&folder, &th, 1);
        assert_ne!(other_hint, hint);
        assert_eq!(key.open(&nonce, &other_hint, &sealed), Err(AeadError));
        let (_, other_key) = parts(&folder, &[6; 32], 0);
        assert_eq!(other_key.open(&nonce, &hint, &sealed), Err(AeadError));
        let (_, other_folder) = parts(&FolderId([7; 32]), &th, 0);
        assert_eq!(other_folder.open(&nonce, &hint, &sealed), Err(AeadError));
    }
}
