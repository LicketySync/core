// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Secret types (`suites.md` section 4.1, TM-6). Every 32-byte secret in the
//! system has its own type here so that a seed cannot be passed where a data key
//! is expected. Each type zeroizes on drop, prints `[redacted]`, has no
//! `Display`, no `Serialize` and no `==`; comparison is [`ct_eq`](Seed::ct_eq)
//! through `subtle`. The bytes are reachable through `expose`, named so that a
//! reviewer can find every place a secret leaves its type.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::{self, AeadError};
use crate::ids::FolderId;
use crate::labels;
use crate::rng::RandomFill;

macro_rules! secret32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wraps 32 bytes the caller already holds (from a key store, a
            /// decoded key string, a derivation).
            #[must_use]
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Draws 32 fresh bytes from the caller's randomness
            /// (`suites.md` section 4.3: the operating system's generator in
            /// production, the simulator's seeded one in tests).
            #[must_use]
            pub fn generate(rng: &mut RandomFill<'_>) -> Self {
                let mut bytes = [0u8; 32];
                rng(&mut bytes);
                Self(bytes)
            }

            /// The secret bytes. Every call site is a place the secret leaves
            /// its zeroizing type; keep them few.
            #[must_use]
            pub fn expose(&self) -> &[u8; 32] {
                &self.0
            }

            /// Constant-time equality (`suites.md` section 4.2).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}([redacted])", stringify!($name))
            }
        }
    };
}

secret32! {
    /// The 256-bit master secret the 24-word recovery phrase encodes
    /// (section 1.1). Stored on root-holder devices only.
    MasterSecret
}

secret32! {
    /// A 32-byte seed from which a key pair set derives (section 0.3): an
    /// issued key's seed, a device seed, the identity seed or a folder's root
    /// seed. Holding the seed is holding the key.
    Seed
}

secret32! {
    /// An epoch's data key `dk_e` (section 3.1).
    DataKey
}

secret32! {
    /// `ck_e`, the `XChaCha` key for chunk ciphertext (section 3.2).
    ChunkKey
}

secret32! {
    /// `nk_e`, the keyed-BLAKE3 key for convergent chunk nonces (section 3.2).
    ChunkNonceKey
}

secret32! {
    /// `rk_e`, the `XChaCha` key for the sealed part of index records
    /// (section 3.2, `protocol.md` 4.4).
    RecordKey
}

secret32! {
    /// The key that encrypts `dk_{e-1}` in the epoch ladder (section 3.1).
    LadderKey
}

secret32! {
    /// `hk`, the folder-lifetime keyed-BLAKE3 key over plaintext chunks
    /// (section 3.2, TM-14).
    ChunkHashKey
}

secret32! {
    /// The `XChaCha` key for the linked-device catalogue (section 1.2, phase 5).
    CatalogueKey
}

secret32! {
    /// A link secret: the 32 fresh bytes in a link code (section 8.1, phase 5).
    LinkSecret
}

secret32! {
    /// The keyed-BLAKE3 key for the link proof (section 8.1).
    LinkConfirmKey
}

secret32! {
    /// The handshake's proof key (`protocol.md` 3.5): `BLAKE3_keyed(folder_id,
    /// "licketysync/v1/handshake/proof-key" || 0x00 || th)`, which seals the
    /// `FolderProof` payload ([`ProofKey::derive`], [`ProofKey::seal`]).
    ProofKey
}

impl ProofKey {
    /// Derives the proof key of `folder_id` for the transcript hash `th`.
    #[must_use]
    pub fn derive(folder_id: &FolderId, th: &[u8; 32]) -> ProofKey {
        ProofKey(labels::keyed_hash_labelled(
            folder_id.as_bytes(),
            labels::HANDSHAKE_PROOF_KEY,
            &[th],
        ))
    }

    /// `XChaCha(proof_key, nonce, aad, plaintext)`: the sealed `FolderProof`
    /// payload, `aad` being the folder hint and `nonce` 24 fresh bytes.
    ///
    /// # Errors
    ///
    /// [`AeadError`] only for a plaintext beyond the cipher's limit.
    pub fn seal(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        aead::xchacha_seal(&self.0, nonce, aad, plaintext)
    }

    /// Opens a sealed `FolderProof` payload.
    ///
    /// # Errors
    ///
    /// [`AeadError`] for any failure; the error says nothing more.
    pub fn open(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<SecretBytes, AeadError> {
        aead::xchacha_open(&self.0, nonce, aad, sealed)
    }
}

/// A plaintext buffer that is zeroized on drop: decrypted chunks, decoded
/// phrases, anything that held secret bytes on its way through.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Compile-time guards (TM-6): every type in this crate or its dependencies
/// that holds secret material wipes it on drop. Building fails if a feature
/// change (such as `chacha20poly1305` without `zeroize`) removes one.
const _: () = {
    const fn zeroize_on_drop<T: ZeroizeOnDrop + ?Sized>() {}
    zeroize_on_drop::<MasterSecret>();
    zeroize_on_drop::<Seed>();
    zeroize_on_drop::<DataKey>();
    zeroize_on_drop::<ChunkKey>();
    zeroize_on_drop::<ChunkNonceKey>();
    zeroize_on_drop::<RecordKey>();
    zeroize_on_drop::<LadderKey>();
    zeroize_on_drop::<ChunkHashKey>();
    zeroize_on_drop::<CatalogueKey>();
    zeroize_on_drop::<LinkSecret>();
    zeroize_on_drop::<LinkConfirmKey>();
    zeroize_on_drop::<ProofKey>();
    zeroize_on_drop::<SecretBytes>();
    zeroize_on_drop::<Zeroizing<[u8; 32]>>();
    // The ciphers and private keys the crate holds secrets in.
    zeroize_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
    zeroize_on_drop::<ed25519_dalek::SigningKey>();
    zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
    zeroize_on_drop::<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>>();
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_bytes_round_trip() {
        let s = Seed::from_bytes([7u8; 32]);
        assert_eq!(format!("{s:?}"), "Seed([redacted])");
        assert_eq!(
            format!("{:?}", MasterSecret::from_bytes([1; 32])),
            "MasterSecret([redacted])"
        );
        assert_eq!(
            format!("{:?}", DataKey::from_bytes([1; 32])),
            "DataKey([redacted])"
        );
        assert_eq!(s.expose(), &[7u8; 32]);
        assert!(bool::from(s.ct_eq(&s.clone())));
        assert!(!bool::from(s.ct_eq(&Seed::from_bytes([8u8; 32]))));
    }

    #[test]
    fn generate_draws_from_the_caller() {
        let mut calls = 0usize;
        let mut fill = |buf: &mut [u8]| {
            calls += 1;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = u8::try_from(i).unwrap_or(0);
            }
        };
        let k = DataKey::generate(&mut fill);
        assert_eq!(calls, 1);
        assert_eq!(k.expose()[31], 31);
    }
}
