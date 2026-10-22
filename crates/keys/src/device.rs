// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Device keys (`keys.md` 8.1): the device seed and the three single-purpose
//! Ed25519 keys derived from it, the device ID, and the handshake's device
//! proof (`protocol.md` 3.4).
//!
//! - The **device key**, seed `derive_key("licketysync/v1/key/ed25519",
//!   device_seed)`, signs only the device proof; its public key is what Hello
//!   carries as `be16(suite) || device_pk` and what the device ID hashes.
//! - The **libp2p identity**, seed `derive_key("licketysync/v1/key/libp2p-identity",
//!   device_seed)`, is used for nothing but the transport.
//! - The **DHT key** (phase 2), seed `derive_key("licketysync/v1/key/dht-bep44",
//!   device_seed)`, signs nothing but the BEP 44 items the device publishes.
//!
//! A device ID is proven only at the handshake; inside a folder it is only a sync key
//! (section 5.3).

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::handshake::Role;
use crate::ids::{hex, DeviceId};
use crate::labels::{self, derive_key, labelled_hash};
use crate::secret::DeviceSeed;
use crate::sig::{self, Signature, SignatureError};
use crate::suite::{sizes, Suite, SuiteError};

/// Why the device public key in a Hello is refused (`protocol.md` 3.2:
/// `Close(PROTOCOL_ERROR)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKeyError {
    /// Not exactly `be16(suite) || ed25519_pk`, 34 bytes under suite 1.
    Length(usize),
    /// The suite is 0.
    Suite(SuiteError),
    /// A suite this release does not implement.
    UnimplementedSuite(u16),
    /// The Ed25519 key is not the canonical encoding of a point, or the point
    /// is of small order (`keys.md` 0.3).
    Key,
}

impl fmt::Display for DeviceKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(n) => write!(
                f,
                "device public key is {n} bytes, not {}",
                sizes::DEVICE_PUBLIC_KEY
            ),
            Self::Suite(e) => write!(f, "{e}"),
            Self::UnimplementedSuite(n) => write!(f, "device key of unimplemented suite {n}"),
            Self::Key => f.write_str("device key is not a canonical Ed25519 point of large order"),
        }
    }
}

impl std::error::Error for DeviceKeyError {}

/// A device's public key as Hello carries it, `be16(suite) || ed25519_pk`,
/// validated as `protocol.md` 3.2 checks it: the length, an implemented
/// suite, and an Ed25519 key that is canonical and not of small order
/// (`keys.md` 0.3), so that one device has one device ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePublicKey {
    suite: Suite,
    key: VerifyingKey,
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DevicePublicKey(suite {}, {})",
            self.suite.as_u16(),
            hex(self.key.as_bytes())
        )
    }
}

impl DevicePublicKey {
    /// Reads the 34 bytes of Hello's `device_public_key`.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError`], each a `Close(PROTOCOL_ERROR)`: the length, suite 0,
    /// a suite this release does not implement, or a key that is not
    /// canonical or is of small order.
    pub fn from_hello(bytes: &[u8]) -> Result<DevicePublicKey, DeviceKeyError> {
        let (suite, ed25519) = bytes
            .split_first_chunk::<{ sizes::SUITE }>()
            .and_then(|(s, k)| Some((s, <&[u8; sizes::ED25519_PK]>::try_from(k).ok()?)))
            .ok_or(DeviceKeyError::Length(bytes.len()))?;
        let suite = Suite::from_be16(*suite).map_err(DeviceKeyError::Suite)?;
        if !suite.is_implemented() {
            return Err(DeviceKeyError::UnimplementedSuite(suite.as_u16()));
        }
        let key = crate::sig::canonical_public_key(ed25519).ok_or(DeviceKeyError::Key)?;
        Ok(DevicePublicKey { suite, key })
    }

    /// The 34 bytes Hello carries.
    #[must_use]
    pub fn to_hello(&self) -> [u8; sizes::DEVICE_PUBLIC_KEY] {
        crate::bytes::join(&self.suite.be16(), self.key.as_bytes())
    }

    /// The suite.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The Ed25519 key, which the handshake's role rule compares
    /// (`protocol.md` 3.2: the byte-wise smaller key is A).
    #[must_use]
    pub fn ed25519_bytes(&self) -> &[u8; sizes::ED25519_PK] {
        self.key.as_bytes()
    }

    /// `device_id = H("licketysync/v1/hash/id/device", be16(suite) || device_pk)`.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId(labelled_hash(
            labels::HASH_ID_DEVICE,
            &[&self.suite.be16(), self.key.as_bytes()],
        ))
    }

    /// Verifies a peer's device proof (`protocol.md` 3.4):
    /// `Verify(device_pk, "licketysync/v1/sig/device-proof", th || u8(role), sig)`
    /// with `verify_strict`, `role` being the peer's.
    ///
    /// # Errors
    ///
    /// [`SignatureError`] for any failure (`Close(PROOF_REJECTED)`).
    pub fn verify_device_proof(
        &self,
        th: &[u8; 32],
        role: Role,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        sig::verify(
            &self.key,
            labels::SIG_DEVICE_PROOF,
            &device_proof_message(th, role),
            signature,
        )
    }
}

/// The body of a device proof, `th || u8(role)`.
fn device_proof_message(th: &[u8; 32], role: Role) -> [u8; 33] {
    crate::bytes::join(th, &[role.as_u8()])
}

/// The device key: the Ed25519 key that signs only the device proof.
/// Zeroized on drop; its `Debug` names only the device.
pub struct DeviceKey {
    key: SigningKey,
    public: DevicePublicKey,
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({}, [redacted])", self.public.device_id())
    }
}

impl DeviceKey {
    /// Derives the device key from the device seed, under suite 1.
    #[must_use]
    pub fn from_device_seed(seed: &DeviceSeed) -> DeviceKey {
        let key = SigningKey::from_bytes(&derive_key(labels::KEY_ED25519, seed.expose()));
        DeviceKey {
            public: DevicePublicKey {
                suite: Suite::ONE,
                key: key.verifying_key(),
            },
            key,
        }
    }

    /// The public key, as Hello carries it.
    #[must_use]
    pub fn public(&self) -> &DevicePublicKey {
        &self.public
    }

    /// The device ID.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.public.device_id()
    }

    /// This device's proof for the transcript hash `th` and its own `role`:
    /// `Sign(device_sk, "licketysync/v1/sig/device-proof", th || u8(role))`.
    #[must_use]
    pub fn sign_device_proof(&self, th: &[u8; 32], role: Role) -> Signature {
        sig::sign(
            &self.key,
            labels::SIG_DEVICE_PROOF,
            &device_proof_message(th, role),
        )
    }
}

/// The device's libp2p identity: a separate Ed25519 key, used for nothing but
/// the transport (`suites.md` 2.6). This type gives the `net` crate the seed
/// to hand to `libp2p-identity` and the public key for Hello; it signs
/// nothing here.
pub struct Libp2pIdentity {
    key: SigningKey,
}

impl fmt::Debug for Libp2pIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Libp2pIdentity([redacted])")
    }
}

impl Libp2pIdentity {
    /// Derives the identity from the device seed.
    #[must_use]
    pub fn from_device_seed(seed: &DeviceSeed) -> Self {
        Libp2pIdentity {
            key: SigningKey::from_bytes(&derive_key(labels::KEY_LIBP2P_IDENTITY, seed.expose())),
        }
    }

    /// The 32-byte Ed25519 public key that Hello carries as `libp2p_identity`.
    #[must_use]
    pub fn public_key(&self) -> [u8; sizes::ED25519_PK] {
        self.key.verifying_key().to_bytes()
    }

    /// The 32-byte Ed25519 seed, for the transport layer's key type only.
    #[must_use]
    pub fn expose_seed(&self) -> Zeroizing<[u8; sizes::KEY]> {
        Zeroizing::new(self.key.to_bytes())
    }
}

/// The device's DHT key (phase 2): a third Ed25519 key, which signs nothing
/// but the BEP 44 mutable items the device publishes (`keys.md` 2.2, 8.1).
pub struct DhtKey {
    key: SigningKey,
}

impl fmt::Debug for DhtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DhtKey([redacted])")
    }
}

impl DhtKey {
    /// Derives the key from the device seed.
    #[must_use]
    pub fn from_device_seed(seed: &DeviceSeed) -> Self {
        DhtKey {
            key: SigningKey::from_bytes(&derive_key(labels::KEY_DHT_BEP44, seed.expose())),
        }
    }

    /// The 32-byte Ed25519 public key under which the device's items are stored.
    #[must_use]
    pub fn public_key(&self) -> [u8; sizes::ED25519_PK] {
        self.key.verifying_key().to_bytes()
    }

    /// Signs a BEP 44 mutable item's signing buffer (phase 2 builds it; BEP
    /// 44 fixes the message, so it carries no label of ours).
    #[must_use]
    pub fn sign_bep44(&self, item: &[u8]) -> [u8; sizes::ED25519_SIG] {
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

    fn seed(byte: u8) -> DeviceSeed {
        DeviceSeed::from_bytes([byte; 32])
    }

    #[test]
    fn device_keys_are_distinct_single_purpose_ed25519_keys() {
        let s = seed(5);
        let device = DeviceKey::from_device_seed(&s);
        let identity = Libp2pIdentity::from_device_seed(&s);
        let dht = DhtKey::from_device_seed(&s);
        let keys = [
            *device.public().ed25519_bytes(),
            identity.public_key(),
            dht.public_key(),
        ];
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
        assert_eq!(
            device.public().ed25519_bytes(),
            &SigningKey::from_bytes(&derive_key(labels::KEY_ED25519, s.expose()))
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(
            &*identity.expose_seed(),
            &*derive_key(labels::KEY_LIBP2P_IDENTITY, s.expose())
        );
        assert_eq!(format!("{identity:?}"), "Libp2pIdentity([redacted])");
        assert_eq!(format!("{dht:?}"), "DhtKey([redacted])");
        assert_eq!(
            format!("{device:?}"),
            format!("DeviceKey({}, [redacted])", device.device_id())
        );
        let sig = dht.sign_bep44(b"item");
        let vk = VerifyingKey::from_bytes(&dht.public_key()).unwrap();
        assert!(vk
            .verify_strict(b"item", &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok());
    }

    #[test]
    fn hello_form_and_device_id() {
        let device = DeviceKey::from_device_seed(&seed(6));
        let hello = device.public().to_hello();
        assert_eq!(hello.len(), 34);
        assert_eq!(&hello[..2], &[0, 1]);
        let back = DevicePublicKey::from_hello(&hello).unwrap();
        assert_eq!(&back, device.public());
        assert_eq!(back.suite(), Suite::ONE);
        assert_eq!(
            back.device_id().0,
            labelled_hash(labels::HASH_ID_DEVICE, &[&hello])
        );
        assert_eq!(
            DevicePublicKey::from_hello(&hello[..33]),
            Err(DeviceKeyError::Length(33))
        );
        assert_eq!(
            DevicePublicKey::from_hello(&[0u8; 35]),
            Err(DeviceKeyError::Length(35))
        );
        let mut zero = hello;
        zero[1] = 0;
        assert_eq!(
            DevicePublicKey::from_hello(&zero),
            Err(DeviceKeyError::Suite(SuiteError::Zero))
        );
        let mut two = hello;
        two[1] = 2;
        assert_eq!(
            DevicePublicKey::from_hello(&two),
            Err(DeviceKeyError::UnimplementedSuite(2))
        );
        assert!(format!("{back:?}").starts_with("DevicePublicKey(suite 1, "));
        // keys.md 0.3: not a point, a non-canonical encoding, small order.
        let undecodable = (0u8..=255)
            .find(|&b| VerifyingKey::from_bytes(&[b; 32]).is_err())
            .unwrap();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        for bad in [
            [undecodable; 32],
            crate::sig::tests::non_canonical_point(),
            identity,
        ] {
            let mut hello = [0u8; 34];
            hello[1] = 1;
            hello[2..].copy_from_slice(&bad);
            assert_eq!(
                DevicePublicKey::from_hello(&hello),
                Err(DeviceKeyError::Key)
            );
        }
        for e in [
            DeviceKeyError::Length(1),
            DeviceKeyError::Suite(SuiteError::Zero),
            DeviceKeyError::UnimplementedSuite(2),
            DeviceKeyError::Key,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    #[test]
    fn the_device_proof_binds_the_transcript_and_the_role() {
        let device = DeviceKey::from_device_seed(&seed(7));
        let th = [9u8; 32];
        let proof = device.sign_device_proof(&th, Role::A);
        let pk = device.public();
        assert_eq!(pk.verify_device_proof(&th, Role::A, &proof), Ok(()));
        assert_eq!(device.sign_device_proof(&th, Role::A), proof);
        assert_eq!(
            pk.verify_device_proof(&th, Role::B, &proof),
            Err(SignatureError)
        );
        assert_eq!(
            pk.verify_device_proof(&[8u8; 32], Role::A, &proof),
            Err(SignatureError)
        );
        let other = DeviceKey::from_device_seed(&seed(8));
        assert_eq!(
            other.public().verify_device_proof(&th, Role::A, &proof),
            Err(SignatureError)
        );
        // The message is `th || role` under the device-proof label.
        let vk = VerifyingKey::from_bytes(pk.ed25519_bytes()).unwrap();
        assert!(sig::verify(
            &vk,
            labels::SIG_DEVICE_PROOF,
            &[&th[..], &[0x01]].concat(),
            &proof
        )
        .is_ok());
    }
}
