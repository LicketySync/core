// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The derivation tree (`keys.md` section 1), the identity hashes (section
//! 0.4) and the device's single-purpose Ed25519 keys (section 1.3).
//!
//! One phrase derives the identity seed and, with each folder's public nonce,
//! that folder's root seed; nothing derives the phrase back (TM-36). Device
//! seeds are generated per device, never derived from the phrase.

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use zeroize::Zeroizing;

use crate::ids::{hex, DeviceId, FolderId, IdentityId, KeyId};
use crate::keyset::{KemPublicKey, SigningPublicKey};
use crate::labels::{self, derive_key, labelled_hash};
use crate::rng::RandomFill;
use crate::secret::{CatalogueKey, MasterSecret, Seed};
use crate::suite::Suite;

/// A folder's nonce: 32 random bytes created with the folder and published in
/// its Folder record, so that a root holder can re-derive the root (section 1.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FolderNonce(pub [u8; 32]);

impl fmt::Debug for FolderNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FolderNonce({})", hex(&self.0))
    }
}

impl FolderNonce {
    /// A fresh nonce from the caller's randomness.
    #[must_use]
    pub fn generate(rng: &mut RandomFill<'_>) -> Self {
        let mut bytes = [0u8; 32];
        rng(&mut bytes);
        FolderNonce(bytes)
    }

    /// Reads a nonce from exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }
}

/// `identity_seed = derive_key("licketysync/v1/identity/seed", ms)` (section 1.2).
#[must_use]
pub fn identity_seed(ms: &MasterSecret) -> Seed {
    Seed::from_bytes(*derive_key(labels::IDENTITY_SEED, ms.expose()))
}

/// The catalogue key from the identity seed (section 1.2, phase 5).
#[must_use]
pub fn catalogue_key(identity_seed: &Seed) -> CatalogueKey {
    CatalogueKey::from_bytes(*derive_key(
        labels::IDENTITY_CATALOGUE_KEY,
        identity_seed.expose(),
    ))
}

/// `root_seed = derive_key("licketysync/v1/folder/root-seed", ms || folder_nonce)`
/// (section 1.2): the same phrase and nonce always give the same root.
#[must_use]
pub fn root_seed(ms: &MasterSecret, nonce: &FolderNonce) -> Seed {
    let material = Zeroizing::new(crate::bytes::fill::<64>(&[ms.expose(), &nonce.0]));
    Seed::from_bytes(*labels::derive_key_64(labels::FOLDER_ROOT_SEED, &material))
}

/// `folder_id = H("licketysync/v1/hash/id/folder", be16(suite) || root_signing_pk)` (section 2.1).
#[must_use]
pub fn folder_id(suite: Suite, root_signing_pk: &SigningPublicKey) -> FolderId {
    FolderId(labelled_hash(
        labels::HASH_ID_FOLDER,
        &[&suite.be16(), root_signing_pk.as_bytes()],
    ))
}

/// `device_id = H("licketysync/v1/hash/id/device", be16(suite) || device_signing_pk)` (section 1.3).
#[must_use]
pub fn device_id(suite: Suite, device_signing_pk: &SigningPublicKey) -> DeviceId {
    DeviceId(labelled_hash(
        labels::HASH_ID_DEVICE,
        &[&suite.be16(), device_signing_pk.as_bytes()],
    ))
}

/// `identity_id = H("licketysync/v1/hash/id/identity", be16(suite) || identity_signing_pk)` (section 1.2).
#[must_use]
pub fn identity_id(suite: Suite, identity_signing_pk: &SigningPublicKey) -> IdentityId {
    IdentityId(labelled_hash(
        labels::HASH_ID_IDENTITY,
        &[&suite.be16(), identity_signing_pk.as_bytes()],
    ))
}

/// `key_id = H("licketysync/v1/hash/id/key", be16(suite) || signing_pk || kem_pk)[0..16]`:
/// an issued key's ID, which every verifier recomputes from the grant's own
/// public keys and compares with the grant's `key_id` field (decisions of
/// 2026-10-15 and 2026-10-17: the ID covers both halves, so a key ID names one
/// signing key and one KEM key for ever). It cannot be the reserved all-zero
/// root ID except by a 2^-128 accident, which the grant parse still refuses.
#[must_use]
pub fn key_id(suite: Suite, signing_pk: &SigningPublicKey, kem_pk: &KemPublicKey) -> KeyId {
    KeyId(crate::bytes::fill::<16>(&[&labelled_hash(
        labels::HASH_ID_KEY,
        &[&suite.be16(), signing_pk.as_bytes(), kem_pk.as_bytes()],
    )]))
}

/// The device's libp2p identity: a separate Ed25519 key derived from the device
/// seed under `licketysync/v1/key/libp2p-identity`, used for nothing but the
/// transport (section 1.3, `suites.md` 2.6). This type exposes the seed for the
/// `net` crate to hand to `libp2p-identity` and the public key for Hello; it
/// signs nothing here.
pub struct Libp2pIdentity {
    key: EdSigningKey,
}

impl fmt::Debug for Libp2pIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Libp2pIdentity([redacted])")
    }
}

impl Libp2pIdentity {
    /// Derives the identity from the device seed.
    #[must_use]
    pub fn from_device_seed(device_seed: &Seed) -> Self {
        let seed = derive_key(labels::KEY_LIBP2P_IDENTITY, device_seed.expose());
        Libp2pIdentity {
            key: EdSigningKey::from_bytes(&seed),
        }
    }

    /// The 32-byte Ed25519 public key that Hello carries as `libp2p_identity`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The 32-byte Ed25519 seed, for the transport layer's key type only.
    #[must_use]
    pub fn expose_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }
}

/// The device's DHT key: a third Ed25519 key from the device seed under
/// `licketysync/v1/key/dht-bep44`, which signs nothing but the BEP 44 mutable
/// items the device publishes (section 1.3, phase 2).
pub struct DhtKey {
    key: EdSigningKey,
}

impl fmt::Debug for DhtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DhtKey([redacted])")
    }
}

impl DhtKey {
    /// Derives the key from the device seed.
    #[must_use]
    pub fn from_device_seed(device_seed: &Seed) -> Self {
        let seed = derive_key(labels::KEY_DHT_BEP44, device_seed.expose());
        DhtKey {
            key: EdSigningKey::from_bytes(&seed),
        }
    }

    /// The 32-byte Ed25519 public key under which the device's items are stored.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Signs a BEP 44 mutable item's signing buffer (phase 2 builds it).
    #[must_use]
    pub fn sign_bep44(&self, item: &[u8]) -> [u8; 64] {
        self.key.sign(item).to_bytes()
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
    use crate::keyset::KeyPairSet;

    #[test]
    fn tree_is_deterministic_and_labels_separate() {
        let ms = MasterSecret::from_bytes([1u8; 32]);
        let id = identity_seed(&ms);
        assert!(bool::from(id.ct_eq(&identity_seed(&ms))));
        let nonce = FolderNonce([2u8; 32]);
        let r1 = root_seed(&ms, &nonce);
        let r2 = root_seed(&ms, &FolderNonce([3u8; 32]));
        assert!(!bool::from(r1.ct_eq(&r2)));
        assert!(!bool::from(r1.ct_eq(&id)));
        let cat = catalogue_key(&id);
        assert!(!bool::from(
            cat.ct_eq(&CatalogueKey::from_bytes(*id.expose()))
        ));
        assert_eq!(
            format!("{nonce:?}"),
            format!("FolderNonce({})", "02".repeat(32))
        );
        assert!(FolderNonce::from_slice(&[0; 31]).is_none());
        let mut fill = |buf: &mut [u8]| buf.fill(9);
        assert_eq!(FolderNonce::generate(&mut fill), FolderNonce([9u8; 32]));
    }

    #[test]
    fn identity_hashes_differ_by_kind_and_suite() {
        let set = KeyPairSet::from_seed(&Seed::from_bytes([4u8; 32])).unwrap();
        let pk = &set.public().signing;
        let f = folder_id(Suite::ONE, pk);
        let d = device_id(Suite::ONE, pk);
        let i = identity_id(Suite::ONE, pk);
        assert_ne!(f.0, d.0);
        assert_ne!(d.0, i.0);
        assert_ne!(f.0, i.0);
        assert_ne!(folder_id(Suite::from_wire(2).unwrap(), pk), f);
        assert_eq!(
            f.0,
            labelled_hash(labels::HASH_ID_FOLDER, &[&pk.wire_form(Suite::ONE)])
        );
        let kem = &set.public().kem;
        let k = key_id(Suite::ONE, pk, kem);
        assert!(!k.is_root());
        assert_eq!(
            k.0,
            labelled_hash(
                labels::HASH_ID_KEY,
                &[&pk.wire_form(Suite::ONE), kem.as_bytes()]
            )[..16]
        );
        assert_ne!(key_id(Suite::from_wire(2).unwrap(), pk, kem), k);
        let other = KeyPairSet::from_seed(&Seed::from_bytes([5u8; 32])).unwrap();
        assert_ne!(
            key_id(Suite::ONE, pk, &other.public().kem),
            k,
            "the ID covers the KEM key"
        );
    }

    #[test]
    fn device_keys_are_distinct_single_purpose_ed25519_keys() {
        let seed = Seed::from_bytes([5u8; 32]);
        let set = KeyPairSet::from_seed(&seed).unwrap();
        let identity = Libp2pIdentity::from_device_seed(&seed);
        let dht = DhtKey::from_device_seed(&seed);
        assert_ne!(identity.public_key(), dht.public_key());
        assert_ne!(
            &identity.public_key()[..],
            set.public().signing.ed25519_bytes()
        );
        assert_eq!(
            &*identity.expose_seed(),
            &*derive_key(labels::KEY_LIBP2P_IDENTITY, seed.expose())
        );
        assert_eq!(format!("{identity:?}"), "Libp2pIdentity([redacted])");
        assert_eq!(format!("{dht:?}"), "DhtKey([redacted])");
        let sig = dht.sign_bep44(b"item");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&dht.public_key()).unwrap();
        assert!(vk
            .verify_strict(b"item", &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok());
    }
}
