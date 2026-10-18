// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Linking a device (`keys.md` section 8.1, phase 5): the link code a new
//! device shows, and the beacon ID and link proof derived from its link
//! secret. The formats are fixed now so that the labels have vectors; the
//! channel itself is phase 5.

use core::fmt;

use zeroize::Zeroizing;

use subtle::ConstantTimeEq;

use crate::ids::DeviceId;
use crate::keystring::{bech32m_decode, bech32m_encode, Bech32Error};
use crate::labels::{self, derive_key, keyed_hash};
use crate::secret::{LinkConfirmKey, LinkSecret};

/// A link code: `Bech32m(hrp = "lsl", device_id (32) || link_secret (32))`,
/// 113 characters, shown by the device that is joining.
pub struct LinkCode {
    /// The new device's ID.
    pub device_id: DeviceId,
    /// 32 fresh random bytes.
    pub secret: LinkSecret,
}

impl fmt::Debug for LinkCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkCode({}, [redacted])", self.device_id)
    }
}

impl LinkCode {
    /// The code as text, lower case, or upper case for a QR code.
    ///
    /// # Errors
    ///
    /// Only if the encoder refuses 64 bytes, which it does not.
    pub fn to_text(&self, upper: bool) -> Result<Zeroizing<String>, Bech32Error> {
        let p = Zeroizing::new(crate::bytes::fill::<64>(&[
            self.device_id.as_bytes(),
            self.secret.expose(),
        ]));
        bech32m_encode("lsl", &p, upper)
    }

    /// Parses a link code under the same rules as a key string.
    ///
    /// # Errors
    ///
    /// [`Bech32Error`].
    pub fn parse(s: &str) -> Result<LinkCode, Bech32Error> {
        let p = bech32m_decode("lsl", s)?;
        let (device, secret) = crate::bytes::halves(&p);
        Ok(LinkCode {
            device_id: DeviceId(device),
            secret: LinkSecret::from_bytes(secret),
        })
    }
}

/// `derive_key("licketysync/v1/link/discovery", link_secret)[0..16]`: the LAN
/// beacon ID an existing device announces while linking.
#[must_use]
pub fn link_beacon_id(secret: &LinkSecret) -> [u8; 16] {
    crate::bytes::fill::<16>(&[&*derive_key(labels::LINK_DISCOVERY, secret.expose())])
}

/// `derive_key("licketysync/v1/link/confirm", link_secret)`: the keyed-BLAKE3
/// key of the link proof.
#[must_use]
pub fn link_confirm_key(secret: &LinkSecret) -> LinkConfirmKey {
    LinkConfirmKey::from_bytes(*derive_key(labels::LINK_CONFIRM, secret.expose()))
}

/// `BLAKE3_keyed(link_confirm_key, th || role)`: each side's link proof over
/// the handshake transcript hash `th` (computed by the protocol crate) and its
/// role byte. A received proof is checked with [`verify_link_proof`].
#[must_use]
pub fn link_proof(key: &LinkConfirmKey, th: &[u8; 32], role: u8) -> [u8; 32] {
    keyed_hash(key.expose(), &[th, &[role]])
}

/// Whether `proof` is the link proof for `th` and `role` under `key`, compared
/// in constant time.
#[must_use]
pub fn verify_link_proof(key: &LinkConfirmKey, th: &[u8; 32], role: u8, proof: &[u8; 32]) -> bool {
    bool::from(link_proof(key, th, role).ct_eq(proof))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn link_code_round_trips_and_refuses_a_key_string() {
        let code = LinkCode {
            device_id: DeviceId([3; 32]),
            secret: LinkSecret::from_bytes([4; 32]),
        };
        let text = code.to_text(false).unwrap();
        assert_eq!(text.len(), 113);
        assert!(text.starts_with("lsl1"));
        let back = LinkCode::parse(&code.to_text(true).unwrap()).unwrap();
        assert_eq!(back.device_id, code.device_id);
        assert!(bool::from(back.secret.ct_eq(&code.secret)));
        assert!(format!("{code:?}").ends_with("[redacted])"));
        let key = crate::keystring::KeyString::new(
            crate::ids::FolderId([3; 32]),
            crate::secret::Seed::from_bytes([4; 32]),
        );
        assert_eq!(
            LinkCode::parse(&key.to_text().unwrap()).unwrap_err(),
            Bech32Error::Prefix
        );
    }

    #[test]
    fn link_values_are_separate_and_bound() {
        let secret = LinkSecret::from_bytes([1; 32]);
        let beacon = link_beacon_id(&secret);
        let key = link_confirm_key(&secret);
        assert_ne!(&beacon[..], &key.expose()[..16]);
        assert_ne!(beacon, link_beacon_id(&LinkSecret::from_bytes([2; 32])));
        let th = [3u8; 32];
        let a = link_proof(&key, &th, 1);
        assert_ne!(a, link_proof(&key, &th, 2));
        assert_ne!(a, link_proof(&key, &[4u8; 32], 1));
        assert_ne!(
            a,
            link_proof(&link_confirm_key(&LinkSecret::from_bytes([2; 32])), &th, 1)
        );
        assert!(verify_link_proof(&key, &th, 1, &a));
        assert!(!verify_link_proof(&key, &th, 2, &a));
        let mut flipped = a;
        flipped[31] ^= 1;
        assert!(!verify_link_proof(&key, &th, 1, &flipped));
    }
}
