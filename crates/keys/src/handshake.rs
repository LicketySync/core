// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The handshake's folder proof (`keys.md` section 4, `protocol.md` 3.5):
//! each side shows that it holds a key to the folder, without sending the key
//! and bound to the one connection. There is one proof for all three tiers:
//! possession of the access key `ak`, which every tier holds. Every value the
//! proof needs is computed here, so that the protocol crate computes none
//! itself:
//!
//! ```text
//! hint_key    = derive_key("licketysync/v1/handshake/hint-key", ak)      # once per folder
//! payload_key = derive_key("licketysync/v1/handshake/payload-key", ak)   # once per folder
//! hint        = BLAKE3_keyed(hint_key, folder_id || th || u8(role))
//! proof_key   = BLAKE3_keyed(payload_key, folder_id || th)
//! nonce       = 24 bytes from the caller's randomness, fresh for every proof
//! sealed      = XChaCha(proof_key, nonce, aad = hint, payload)
//! ```
//!
//! The prover seals its `ProofPayload` (the protocol crate's message, which
//! carries only the tier it reports) with [`HandshakeKeys::seal_proof`], which
//! draws the nonce itself, so that no caller can reuse one; the verifier opens
//! it with [`HandshakeKeys::open_proof`]. A payload that opens proves that its
//! sender holds `ak`. `th` is the transcript hash, which the protocol crate
//! builds with [`crate::labels::labelled_hash`] under
//! [`crate::labels::HASH_TRANSCRIPT`]; `role` is the prover's. The handshake
//! keys are built only from a folder key ([`FolderKey::handshake_keys`]), so
//! the folder ID inside both values is always the key's own; it binds a key's
//! halves: a read or sealed key made from two folders' halves yields hints no
//! holder of either folder computes.

use core::fmt;

use crate::aead::{xchacha_open, xchacha_seal, AeadError, SealError};
use crate::folder::FolderKey;
use crate::ids::FolderId;
use crate::labels::{keyed_hash, keyed_hash_into};
use crate::rng::RandomFill;
use crate::secret::{AccessKey, HintKey, PayloadKey, ProofKey, SecretBytes};
use crate::suite::sizes;

/// A side's role in the handshake (`protocol.md` 3.2): the side whose device
/// key is byte-wise smaller is A.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Role {
    /// Role byte `0x01`.
    A = 0x01,
    /// Role byte `0x02`.
    B = 0x02,
}

impl Role {
    /// The role byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The other side's role.
    #[must_use]
    pub fn peer(self) -> Role {
        match self {
            Role::A => Role::B,
            Role::B => Role::A,
        }
    }
}

/// The two keys of one folder's proofs, derived once per folder from its
/// access key, with the folder ID they bind: what a device caches to compute
/// the hints of its folders on every connection. Zeroized on drop; its
/// `Debug` names only the folder.
pub struct HandshakeKeys {
    folder_id: FolderId,
    hint_key: HintKey,
    payload_key: PayloadKey,
}

impl fmt::Debug for HandshakeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HandshakeKeys({}, [redacted])", self.folder_id)
    }
}

impl HandshakeKeys {
    /// The handshake keys of the folder `folder_id` whose access key is `ak`.
    fn new(folder_id: FolderId, ak: &AccessKey) -> HandshakeKeys {
        HandshakeKeys {
            folder_id,
            hint_key: ak.hint_key(),
            payload_key: ak.payload_key(),
        }
    }

    /// The folder these keys prove.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }

    /// `hint = BLAKE3_keyed(hint_key, folder_id || th || u8(role))`: the hint
    /// of the folder for the transcript hash `th` and the prover's `role`. It
    /// is the associated data of the sealed payload and the value a verifier
    /// matches its folders against, computed with the peer's role.
    #[must_use]
    pub fn hint(&self, th: &[u8; 32], role: Role) -> [u8; 32] {
        keyed_hash(
            self.hint_key.expose(),
            &[self.folder_id.as_bytes(), th, &[role.as_u8()]],
        )
    }

    /// `proof_key = BLAKE3_keyed(payload_key, folder_id || th)`: the `XChaCha`
    /// key of the payload for the transcript hash `th`, built in place.
    pub(crate) fn proof_key(&self, th: &[u8; 32]) -> ProofKey {
        ProofKey::fill_with(|out| {
            keyed_hash_into(
                self.payload_key.expose(),
                &[self.folder_id.as_bytes(), th],
                out,
            );
        })
    }

    /// This side's proof of the folder on the connection whose transcript
    /// hash is `th`, as the side with `role`: 24 fresh bytes from `rng` as the
    /// nonce, and `payload` (the protocol crate's encoded `ProofPayload`)
    /// sealed under the proof key with this side's hint as associated data.
    /// Returns the nonce and the sealed payload, which `FolderProof` carries
    /// with the hint.
    ///
    /// # Errors
    ///
    /// [`SealError`] only for a payload beyond the cipher's limit of about
    /// 256 GiB.
    pub fn seal_proof(
        &self,
        th: &[u8; 32],
        role: Role,
        payload: &[u8],
        rng: &mut RandomFill<'_>,
    ) -> Result<([u8; sizes::NONCE], Vec<u8>), SealError> {
        let mut nonce = [0u8; sizes::NONCE];
        rng(&mut nonce);
        let sealed = xchacha_seal(
            self.proof_key(th).expose(),
            &nonce,
            &self.hint(th, role),
            payload,
        )?;
        Ok((nonce, sealed))
    }

    /// Opens a peer's proof on the connection whose transcript hash is `th`:
    /// `peer_role` is the prover's role, so the associated data is the hint
    /// this folder has for the peer, and `nonce` and `sealed` are the
    /// `FolderProof`'s. The payload comes back in a buffer zeroized on drop.
    ///
    /// # Errors
    ///
    /// [`AeadError`] for any failure: another folder, transcript, role or
    /// nonce, or a damaged seal.
    pub fn open_proof(
        &self,
        th: &[u8; 32],
        peer_role: Role,
        nonce: &[u8; sizes::NONCE],
        sealed: &[u8],
    ) -> Result<SecretBytes, AeadError> {
        xchacha_open(
            self.proof_key(th).expose(),
            nonce,
            &self.hint(th, peer_role),
            sealed,
        )
    }
}

impl FolderKey {
    /// This folder's handshake keys, at any tier.
    #[must_use]
    pub fn handshake_keys(&self) -> HandshakeKeys {
        let folder_id = self.folder_id();
        match self {
            FolderKey::Write(k) => HandshakeKeys::new(folder_id, &k.data_key().access_key()),
            FolderKey::Read(k) => HandshakeKeys::new(folder_id, &k.data_key().access_key()),
            FolderKey::Sealed(k) => HandshakeKeys::new(folder_id, k.access_key()),
        }
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
    use crate::folder::tests::write_key;
    use crate::labels;
    use crate::suite::Tier;

    fn tiers(byte: u8) -> [FolderKey; 3] {
        let w = write_key(byte);
        let r = w.read_key();
        let s = w.sealed_key();
        [w.into(), r.into(), s.into()]
    }

    /// A sealed key made by hand from folder `a`'s verification key and
    /// folder `b`'s access key, as a key string could carry it.
    pub(crate) fn mixed_sealed_key(a: &crate::WriteKey, b: &crate::WriteKey) -> FolderKey {
        let payload = [
            &a.verifier().suite().be16()[..],
            a.verifier().verifying_key().as_bytes(),
            b.data_key().access_key().expose(),
        ]
        .concat();
        FolderKey::from_payload(Tier::Sealed, &payload).unwrap()
    }

    #[test]
    fn roles() {
        assert_eq!((Role::A.as_u8(), Role::B.as_u8()), (1, 2));
        assert_eq!(Role::A.peer(), Role::B);
        assert_eq!(Role::B.peer(), Role::A);
    }

    #[test]
    fn every_tier_computes_the_same_hint_and_proof_key() {
        let th = [4u8; 32];
        let keys = tiers(1);
        let hs = keys[0].handshake_keys();
        let hint = hs.hint(&th, Role::A);
        let pk = *hs.proof_key(&th).expose();
        for k in &keys {
            let h = k.handshake_keys();
            assert_eq!(h.folder_id(), keys[0].folder_id());
            assert_eq!(h.hint(&th, Role::A), hint);
            assert_eq!(*h.proof_key(&th).expose(), pk);
        }
        assert_ne!(hs.hint(&th, Role::B), hint, "the role is bound");
        assert_ne!(hs.hint(&[5; 32], Role::A), hint, "so is th");
        assert_ne!(
            tiers(2)[0].handshake_keys().hint(&th, Role::A),
            hint,
            "and the folder"
        );
        assert_ne!(*hs.proof_key(&[5; 32]).expose(), pk);
        // The construction of keys.md 4: two keys derived from ak, each keying
        // its own input.
        let w = write_key(1);
        let ak = w.data_key().access_key();
        let folder = keys[0].folder_id();
        let hint_key = labels::derive_key(labels::HANDSHAKE_HINT_KEY, ak.expose());
        let payload_key = labels::derive_key(labels::HANDSHAKE_PAYLOAD_KEY, ak.expose());
        assert_eq!(
            hint,
            keyed_hash(&hint_key, &[folder.as_bytes().as_slice(), &th, &[1u8]])
        );
        assert_eq!(pk, keyed_hash(&payload_key, &[folder.as_bytes(), &th]));
        // ak itself keys nothing: neither value is keyed with it.
        assert_ne!(
            hint,
            keyed_hash(ak.expose(), &[folder.as_bytes().as_slice(), &th, &[1u8]])
        );
        assert!(format!("{hs:?}").starts_with("HandshakeKeys("));
        assert!(format!("{hs:?}").ends_with("[redacted])"));
    }

    #[test]
    fn a_key_made_of_two_folders_halves_matches_neither_folders_hint() {
        let (a, b) = (write_key(1), write_key(2));
        let th = [6u8; 32];
        let mixed = mixed_sealed_key(&a, &b);
        assert_eq!(mixed.folder_id(), a.verifier().folder_id());
        let hint = mixed.handshake_keys().hint(&th, Role::A);
        for folder in [write_key(1), write_key(2)] {
            assert_ne!(
                hint,
                FolderKey::from(folder).handshake_keys().hint(&th, Role::A)
            );
        }
    }

    #[test]
    fn a_proof_opens_only_for_the_same_folder_transcript_and_role() {
        let th = [7u8; 32];
        let keys = tiers(3);
        let sealed_side = keys[2].handshake_keys();
        let mut calls = 0;
        let mut fill = |b: &mut [u8]| {
            calls += 1;
            b.fill(5);
        };
        let (nonce, sealed) = sealed_side
            .seal_proof(&th, Role::A, b"payload", &mut fill)
            .unwrap();
        assert_eq!((calls, nonce), (1, [5u8; 24]), "the nonce is drawn inside");
        assert_eq!(sealed.len(), b"payload".len() + sizes::TAG);
        // Exactly XChaCha(proof_key, nonce, aad = hint, payload).
        assert_eq!(
            sealed,
            xchacha_seal(
                sealed_side.proof_key(&th).expose(),
                &nonce,
                &sealed_side.hint(&th, Role::A),
                b"payload"
            )
            .unwrap()
        );
        // Every tier opens it, with the prover's role.
        for k in &keys {
            let opened = k
                .handshake_keys()
                .open_proof(&th, Role::A, &nonce, &sealed)
                .unwrap();
            assert_eq!(opened.as_slice(), b"payload");
        }
        let writer = keys[0].handshake_keys();
        // The other role (a proof reflected back), another transcript,
        // another nonce, another folder, a damaged seal: none opens.
        assert_eq!(
            writer.open_proof(&th, Role::B, &nonce, &sealed),
            Err(AeadError)
        );
        assert_eq!(
            writer.open_proof(&[8; 32], Role::A, &nonce, &sealed),
            Err(AeadError)
        );
        assert_eq!(
            writer.open_proof(&th, Role::A, &[6; 24], &sealed),
            Err(AeadError)
        );
        assert_eq!(
            tiers(4)[0]
                .handshake_keys()
                .open_proof(&th, Role::A, &nonce, &sealed),
            Err(AeadError)
        );
        let mut damaged = sealed.clone();
        damaged[0] ^= 1;
        assert_eq!(
            writer.open_proof(&th, Role::A, &nonce, &damaged),
            Err(AeadError)
        );
        // Two proofs draw two nonces and seal differently.
        let mut counter = 0u8;
        let mut fresh = |b: &mut [u8]| {
            counter += 1;
            b.fill(counter);
        };
        let first = writer.seal_proof(&th, Role::B, b"p", &mut fresh).unwrap();
        let second = writer.seal_proof(&th, Role::B, b"p", &mut fresh).unwrap();
        assert_ne!(first.0, second.0);
        assert_ne!(first.1, second.1);
    }
}
