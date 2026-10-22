// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Step 3 of the handshake (`protocol.md` 3.2 to 3.4): the Hello checks, the
//! role rule, the transcript hash, and the bytes a `DeviceProof` signs. Every
//! key and hash is the keys crate's: the device key is read with
//! [`DevicePublicKey::from_hello`] (canonical and not of small order, so one
//! device has one device ID), the transcript is
//! [`licketysync_keys::labels::labelled_hash`] under
//! `licketysync/v1/hash/transcript`, and the proof is
//! [`licketysync_keys::device::DeviceKey::sign_device_proof`] and
//! [`DevicePublicKey::verify_device_proof`].

use std::collections::BTreeSet;

use core::fmt;

use licketysync_keys::device::DevicePublicKey;
use licketysync_keys::labels::{labelled_hash, HASH_TRANSCRIPT};
use licketysync_keys::{DeviceId, Role, Suite};

use crate::features::{COMPRESSION_NONE, HASH_BLAKE3};
use crate::frame::Frame;
use crate::limits::{HELLO_NONCE_LEN, LIBP2P_IDENTITY_LEN, MAX_MESSAGE_SIZE, MIN_MESSAGE_SIZE};
use crate::messages::{CloseReason, Hello};

/// The transcript hash `th` of one connection (3.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TranscriptHash(pub [u8; 32]);

impl fmt::Debug for TranscriptHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TranscriptHash(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl TranscriptHash {
    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `th = H("licketysync/v1/hash/transcript", be32(len(protocol_id)) ||
/// protocol_id || be32(32) || libp2p_identity_A || be32(32) ||
/// libp2p_identity_B || be32(len(hello_A)) || hello_A || be32(len(hello_B)) ||
/// hello_B)` (3.3), each Hello its frame's `type || body` exactly as sent.
#[must_use]
pub fn transcript_hash(
    protocol_id: &str,
    libp2p_a: &[u8; 32],
    libp2p_b: &[u8; 32],
    hello_a: &[u8],
    hello_b: &[u8],
) -> TranscriptHash {
    let len = |b: &[u8]| u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes();
    let id = protocol_id.as_bytes();
    TranscriptHash(labelled_hash(
        HASH_TRANSCRIPT,
        &[
            &len(id),
            id,
            &len(libp2p_a),
            libp2p_a,
            &len(libp2p_b),
            libp2p_b,
            &len(hello_a),
            hello_a,
            &len(hello_b),
            hello_b,
        ],
    ))
}

/// The role rule (3.2): the side whose Ed25519 device key is byte-wise
/// smaller is A; `None` when the keys are equal (a device connected to
/// itself: `Close(PROTOCOL_ERROR)`).
#[must_use]
pub fn role_of(own: &DevicePublicKey, peer: &DevicePublicKey) -> Option<Role> {
    match own.ed25519_bytes().cmp(peer.ed25519_bytes()) {
        core::cmp::Ordering::Less => Some(Role::A),
        core::cmp::Ordering::Greater => Some(Role::B),
        core::cmp::Ordering::Equal => None,
    }
}

/// A peer's Hello that passed every check of 3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHello {
    /// The Hello as received.
    pub hello: Hello,
    /// Its frame's `type || body`, exactly as received: the transcript input.
    pub bytes: Vec<u8>,
    /// The peer's device key.
    pub device: DevicePublicKey,
    /// `H("licketysync/v1/hash/id/device", device_public_key)`.
    pub device_id: DeviceId,
    /// The peer's libp2p identity key as its Hello carries it.
    pub libp2p_identity: [u8; 32],
    /// The peer's `max_message_size`, treated as `MAX_MESSAGE_SIZE` when larger.
    pub max_message_size: u32,
    /// The suites the peer lists.
    pub suites: BTreeSet<u32>,
}

/// Checks a peer's Hello against 3.2, in the spec's order: the device key
/// (exactly `be16(suite) || ed25519_pk` of an implemented suite, canonical and
/// not of small order), the libp2p identity (32 bytes, and equal to the
/// transport-authenticated key when one is known), the suite list (non-empty,
/// no duplicates, sharing an implemented suite with `ours`, else
/// `NO_COMMON_SUITE`), `none` and `blake3`, the message-size floor (else
/// `LIMIT_TOO_SMALL`), `max_requests_in_flight ≥ 1` and the 32-byte nonce.
/// The list bounds, entry ranges and the feature grammar were judged when the
/// body was parsed, so a Hello with several faults is refused for the first
/// one found in that order (decision). `frame` is the frame it came in.
///
/// # Errors
/// The close reason: `PROTOCOL_ERROR` unless noted above.
pub fn check_peer_hello(
    hello: Hello,
    frame: &Frame,
    ours: &[Suite],
    transport_identity: Option<&[u8; 32]>,
) -> Result<PeerHello, CloseReason> {
    let device = DevicePublicKey::from_hello(&hello.device_public_key)
        .map_err(|_| CloseReason::ProtocolError)?;
    let libp2p_identity = <[u8; LIBP2P_IDENTITY_LEN]>::try_from(hello.libp2p_identity.as_slice())
        .map_err(|_| CloseReason::ProtocolError)?;
    if transport_identity.is_some_and(|t| *t != libp2p_identity) {
        return Err(CloseReason::ProtocolError);
    }
    let suites: BTreeSet<u32> = hello.suites.iter().copied().collect();
    if suites.is_empty() || suites.len() != hello.suites.len() {
        return Err(CloseReason::ProtocolError);
    }
    if !ours
        .iter()
        .any(|s| s.is_implemented() && suites.contains(&s.to_wire()))
    {
        return Err(CloseReason::NoCommonSuite);
    }
    if !hello.compressions.iter().any(|c| c == COMPRESSION_NONE)
        || !hello.hashes.iter().any(|h| h == HASH_BLAKE3)
    {
        return Err(CloseReason::ProtocolError);
    }
    if hello.max_message_size < MIN_MESSAGE_SIZE {
        return Err(CloseReason::LimitTooSmall);
    }
    if hello.max_requests_in_flight < 1 || hello.nonce.len() != HELLO_NONCE_LEN {
        return Err(CloseReason::ProtocolError);
    }
    Ok(PeerHello {
        device_id: device.device_id(),
        device,
        libp2p_identity,
        max_message_size: hello.max_message_size.min(MAX_MESSAGE_SIZE),
        suites,
        bytes: frame.type_and_body(),
        hello,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use licketysync_keys::device::DeviceKey;
    use licketysync_keys::secret::DeviceSeed;
    use prost::Message as _;

    use super::*;
    use crate::frame::MessageType;

    fn device(byte: u8) -> DeviceKey {
        DeviceKey::from_device_seed(&DeviceSeed::from_bytes([byte; 32]))
    }

    fn hello(key: &DeviceKey) -> Hello {
        Hello {
            device_public_key: key.public().to_hello().to_vec(),
            suites: vec![1],
            compressions: vec!["none".into()],
            hashes: vec!["blake3".into()],
            features: vec![],
            max_message_size: MIN_MESSAGE_SIZE,
            max_requests_in_flight: 1,
            nonce: vec![7; 32],
            libp2p_identity: vec![9; 32],
        }
    }

    fn check(h: Hello, transport: Option<&[u8; 32]>) -> Result<PeerHello, CloseReason> {
        let frame = Frame::new(MessageType::Hello.as_u16(), h.encode_to_vec()).unwrap();
        check_peer_hello(h, &frame, &[Suite::ONE], transport)
    }

    #[test]
    fn a_good_hello_passes_and_is_kept_byte_for_byte() {
        let key = device(1);
        let h = Hello {
            max_message_size: u32::MAX,
            ..hello(&key)
        };
        let frame = Frame::new(MessageType::Hello.as_u16(), h.encode_to_vec()).unwrap();
        let peer = check_peer_hello(h.clone(), &frame, &[Suite::ONE], Some(&[9; 32])).unwrap();
        assert_eq!(peer.device_id, key.device_id());
        assert_eq!(
            peer.max_message_size, MAX_MESSAGE_SIZE,
            "larger is treated as the max"
        );
        assert_eq!(peer.bytes, frame.type_and_body());
        assert_eq!(peer.hello, h);
        assert_eq!(peer.libp2p_identity, [9; 32]);
        assert!(peer.suites.contains(&1));
    }

    #[test]
    fn each_failing_check_has_its_reason() {
        let key = device(1);
        let bad = |f: &dyn Fn(&mut Hello)| {
            let mut h = hello(&key);
            f(&mut h);
            check(h, None).err()
        };
        let pe = Some(CloseReason::ProtocolError);
        assert_eq!(bad(&|h| h.device_public_key.truncate(33)), pe);
        assert_eq!(
            bad(&|h| h.device_public_key = vec![0; 1986]),
            pe,
            "the drafts' form"
        );
        assert_eq!(
            bad(&|h| h.device_public_key[1] = 2),
            pe,
            "suite 2 is not implemented"
        );
        assert_eq!(bad(&|h| h.libp2p_identity.truncate(31)), pe);
        assert_eq!(bad(&|h| h.suites.clear()), pe);
        assert_eq!(bad(&|h| h.suites = vec![1, 1]), pe);
        assert_eq!(
            bad(&|h| h.suites = vec![2]),
            Some(CloseReason::NoCommonSuite)
        );
        assert_eq!(bad(&|h| h.compressions = vec!["zstd".into()]), pe);
        assert_eq!(bad(&|h| h.hashes.clear()), pe);
        assert_eq!(
            bad(&|h| h.max_message_size = MIN_MESSAGE_SIZE - 1),
            Some(CloseReason::LimitTooSmall)
        );
        assert_eq!(bad(&|h| h.max_requests_in_flight = 0), pe);
        assert_eq!(bad(&|h| h.nonce.truncate(31)), pe);
        // From phase 1 the transport's key must equal the Hello's.
        assert_eq!(check(hello(&key), Some(&[8; 32])).err(), pe);
    }

    #[test]
    fn non_canonical_and_small_order_device_keys_are_refused() {
        let key = device(1);
        // The identity point encoded with y = p + 1 (non-canonical), and the
        // canonical identity (small order).
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        for pk in [non_canonical, identity] {
            let mut h = hello(&key);
            h.device_public_key = [&[0, 1][..], &pk].concat();
            assert_eq!(check(h, None).err(), Some(CloseReason::ProtocolError));
        }
    }

    #[test]
    fn roles_and_the_transcript() {
        let (a, b) = (device(1), device(2));
        let (ra, rb) = (
            role_of(a.public(), b.public()).unwrap(),
            role_of(b.public(), a.public()).unwrap(),
        );
        assert_eq!(ra.peer(), rb, "the rule gives the two sides the two roles");
        assert_eq!(role_of(a.public(), a.public()), None);
        let th = transcript_hash("/licketysync/sync/1", &[1; 32], &[2; 32], b"ha", b"hb");
        assert_ne!(
            th,
            transcript_hash("/licketysync/sync/1", &[2; 32], &[1; 32], b"ha", b"hb")
        );
        assert_ne!(
            th,
            transcript_hash("/licketysync/sync/2", &[1; 32], &[2; 32], b"ha", b"hb")
        );
        // Length prefixes keep boundaries: moving a byte between the Hellos
        // changes the hash.
        assert_ne!(
            th,
            transcript_hash("/licketysync/sync/1", &[1; 32], &[2; 32], b"h", b"ahb")
        );
        let manual = labelled_hash(
            HASH_TRANSCRIPT,
            &[
                &19u32.to_be_bytes(),
                b"/licketysync/sync/1",
                &32u32.to_be_bytes(),
                &[1; 32],
                &32u32.to_be_bytes(),
                &[2; 32],
                &2u32.to_be_bytes(),
                b"ha",
                &2u32.to_be_bytes(),
                b"hb",
            ],
        );
        assert_eq!(th.0, manual);
        assert_eq!(th.as_bytes(), &manual);
        assert_eq!(format!("{th:?}").len(), "TranscriptHash()".len() + 64);
        // The device proof signs th || role and verifies only for that role.
        let sig = a.sign_device_proof(&th.0, Role::A);
        assert!(a.public().verify_device_proof(&th.0, Role::A, &sig).is_ok());
        assert!(a
            .public()
            .verify_device_proof(&th.0, Role::B, &sig)
            .is_err());
    }
}
