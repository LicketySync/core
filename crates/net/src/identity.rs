// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The device's libp2p identity as libp2p sees it (`suites.md` 2.6, `keys.md`
//! 8.1): an Ed25519 keypair whose 32-byte seed is
//! `derive_key("licketysync/v1/key/libp2p-identity", device_seed)`, derived in
//! the keys crate, and the peer ID that names it.
//!
//! The identity is never generated from randomness here: it is always the
//! derived seed, so a device has one peer ID for the life of its device seed.
//! The seed reaches `libp2p-identity` through
//! [`Libp2pIdentity::expose_seed`], whose zeroizing buffer
//! `ed25519::SecretKey::try_from_bytes` wipes in place. What `libp2p-identity`
//! 0.3.1 does with it afterwards is upstream's: its `SecretKey` is a plain
//! array that is not wiped on drop, and the keypair is cloned into the QUIC
//! and TLS configurations (a deviation recorded in TM-6 and `suites.md` 4.1,
//! to raise upstream).

use core::fmt;

use libp2p_identity::{ed25519, DecodingError, Keypair, PeerId};
use licketysync_keys::device::{check_peer_identity_key, Libp2pIdentity};

/// The libp2p keypair of `identity`.
///
/// # Errors
///
/// `libp2p-identity` refuses a seed that is not 32 bytes. The keys crate's
/// seed always is, so this does not fail; the error is passed on rather
/// than unwrapped (TM-23).
pub fn keypair(identity: &Libp2pIdentity) -> Result<Keypair, DecodingError> {
    let mut seed = identity.expose_seed();
    let secret = ed25519::SecretKey::try_from_bytes(&mut *seed)?;
    Ok(Keypair::from(ed25519::Keypair::from(secret)))
}

/// The peer ID of `identity`: the identity multihash of the protobuf encoding
/// of its Ed25519 public key (libp2p peer-ids specification), `12D3KooW…` in
/// text. Computed from the public key alone, so the seed is not exposed.
///
/// # Errors
///
/// `libp2p-identity` refuses bytes that are not an Ed25519 point. A key
/// derived by the keys crate always is one, so this does not fail.
pub fn peer_id(identity: &Libp2pIdentity) -> Result<PeerId, DecodingError> {
    let public = ed25519::PublicKey::try_from_bytes(&identity.public_key())?;
    Ok(libp2p_identity::PublicKey::from(public).to_peer_id())
}

/// Why a peer's authenticated identity is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerKeyError {
    /// The peer ID is not an inline Ed25519 key: a hashed (long) key, or
    /// another key type. A Lickety-Sync device's identity is always Ed25519.
    NotEd25519,
    /// The Ed25519 key is not the canonical encoding of a point, or the point
    /// is of small order (`keys.md` 0.3).
    WeakKey,
}

impl fmt::Display for PeerKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEd25519 => f.write_str("the peer's identity is not an Ed25519 key"),
            Self::WeakKey => {
                f.write_str("the peer's identity is not a canonical Ed25519 key of large order")
            }
        }
    }
}

impl std::error::Error for PeerKeyError {}

/// Checks the identity a peer proved in the transport handshake; the sync
/// behaviour refuses a connection whose peer fails it before the connection
/// is established, so before any stream (`suites.md` 2.2 and 3.1). The peer ID
/// carries the key itself (an identity multihash of its protobuf encoding),
/// and the key must be one the keys crate accepts: canonical and not of
/// small order. `libp2p-identity` accepts small-order keys and
/// verifies the certificate's extension non-strictly, so without this check a
/// peer could present the peer ID of the identity point, `12D3KooW9tGa…`,
/// with a forged signature and no secret at all.
///
/// # Errors
///
/// [`PeerKeyError`].
pub fn check_peer(peer: &PeerId) -> Result<(), PeerKeyError> {
    /// The multihash code of an inline (identity) multihash.
    const IDENTITY_MULTIHASH: u64 = 0;
    let multihash = peer.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH {
        return Err(PeerKeyError::NotEd25519);
    }
    let public = libp2p_identity::PublicKey::try_decode_protobuf(multihash.digest())
        .map_err(|_| PeerKeyError::NotEd25519)?
        .try_into_ed25519()
        .map_err(|_| PeerKeyError::NotEd25519)?;
    check_peer_identity_key(&public.to_bytes()).map_err(|_| PeerKeyError::WeakKey)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use licketysync_keys::secret::DeviceSeed;

    use super::*;

    /// The peer ID of the Ed25519 identity point, `01 00 … 00`, a key of
    /// small order (the security review's case, SA-S3).
    const IDENTITY_POINT_PEER: &str = "12D3KooW9tGaPdJo5jmCpadQ971nfiq4kLcQjeBPYTfutBTtckPH";

    #[test]
    fn a_small_order_identity_is_refused() {
        let mut point = [0u8; 32];
        point[0] = 1;
        // libp2p-identity itself accepts the key and gives it a peer ID.
        let public = ed25519::PublicKey::try_from_bytes(&point).unwrap();
        let peer = libp2p_identity::PublicKey::from(public).to_peer_id();
        assert_eq!(peer.to_base58(), IDENTITY_POINT_PEER);
        assert_eq!(check_peer(&peer), Err(PeerKeyError::WeakKey));
        assert_eq!(
            check_peer(&IDENTITY_POINT_PEER.parse().unwrap()),
            Err(PeerKeyError::WeakKey)
        );
    }

    #[test]
    fn a_derived_identity_passes_and_a_hashed_peer_id_does_not() {
        let identity = Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes([3; 32]));
        assert_eq!(check_peer(&peer_id(&identity).unwrap()), Ok(()));
        // A SHA-256 multihash (code 0x12), as a long key's peer ID is.
        let mut hashed = vec![0x12, 0x20];
        hashed.extend_from_slice(&[7; 32]);
        let hashed = PeerId::from_bytes(&hashed).unwrap();
        assert_eq!(check_peer(&hashed), Err(PeerKeyError::NotEd25519));
        for e in [PeerKeyError::NotEd25519, PeerKeyError::WeakKey] {
            assert_ne!(e.to_string(), "");
        }
    }
}
