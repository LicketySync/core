// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Linking a device (`keys.md` section 8.3, phase 5): the link code a new
//! device shows, and the beacon ID and link proof derived from its link
//! secret. The formats are fixed now so that the labels have vectors; the
//! channel itself, and the folder keys passed over it as key strings, are
//! phase 5.

use core::fmt;

use bech32::Hrp;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::folder::KeyError;
use crate::handshake::Role;
use crate::ids::DeviceId;
use crate::keystring::{bech32m_decode, bech32m_encode, KeyStringError};
use crate::labels::{self, derive_key, derive_key_into, keyed_hash};
use crate::secret::{LinkConfirmKey, LinkSecret};
use crate::suite::sizes;

/// The link code's prefix.
pub const HRP_LINK: &str = "lsl";

const HRP: Hrp = Hrp::parse_unchecked(HRP_LINK);

/// The link code's payload, `device_id (32) || link_secret (32)`.
const PAYLOAD: usize = sizes::ID + sizes::KEY;

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
    #[must_use]
    pub fn to_text(&self, upper: bool) -> Zeroizing<String> {
        let mut payload = Zeroizing::new([0u8; PAYLOAD]);
        crate::bytes::join_into(
            &mut payload,
            self.device_id.as_bytes(),
            self.secret.expose(),
        );
        bech32m_encode(&HRP, &*payload, upper)
    }

    /// Parses a link code under the same rules as a key string. The secret
    /// half is copied straight from the decoded buffer, which is zeroized,
    /// into its zeroizing type.
    ///
    /// # Errors
    ///
    /// [`KeyStringError`]; a payload that is not 64 bytes is
    /// [`KeyStringError::Key`] with [`KeyError::Length`].
    pub fn parse(s: &str) -> Result<LinkCode, KeyStringError> {
        let ((), payload) = bech32m_decode(s, &[(&HRP, ())])?;
        let (device, secret) = payload
            .split_first_chunk::<{ sizes::ID }>()
            .and_then(|(device, rest)| Some((device, <&[u8; sizes::KEY]>::try_from(rest).ok()?)))
            .ok_or(KeyStringError::Key(KeyError::Length {
                expected: PAYLOAD,
                found: payload.len(),
            }))?;
        Ok(LinkCode {
            device_id: DeviceId(*device),
            secret: LinkSecret::fill_with(|out| *out = *secret),
        })
    }
}

/// `derive_key("licketysync/v1/link/discovery", link_secret)[0..16]`: the LAN
/// beacon ID an existing device announces while linking.
#[must_use]
pub fn link_beacon_id(secret: &LinkSecret) -> [u8; 16] {
    crate::bytes::first(&derive_key(labels::LINK_DISCOVERY, secret.expose()))
}

/// `derive_key("licketysync/v1/link/confirm", link_secret)`: the keyed-BLAKE3
/// key of the link proof, built in place.
#[must_use]
pub fn link_confirm_key(secret: &LinkSecret) -> LinkConfirmKey {
    LinkConfirmKey::fill_with(|out| derive_key_into(labels::LINK_CONFIRM, secret.expose(), out))
}

/// `BLAKE3_keyed(link_confirm_key, th || u8(role))`: each side's link proof
/// over the handshake transcript hash `th` and its role. A received proof is
/// checked with [`verify_link_proof`].
#[must_use]
pub fn link_proof(key: &LinkConfirmKey, th: &[u8; 32], role: Role) -> [u8; 32] {
    keyed_hash(key.expose(), &[th, &[role.as_u8()]])
}

/// Whether `proof` is the link proof for `th` and `role` under `key`, compared
/// in constant time.
#[must_use]
pub fn verify_link_proof(
    key: &LinkConfirmKey,
    th: &[u8; 32],
    role: Role,
    proof: &[u8; 32],
) -> bool {
    bool::from(link_proof(key, th, role).ct_eq(proof))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;
    use crate::folder::tests::write_key;
    use crate::folder::FolderKey;

    #[test]
    fn link_code_round_trips_and_refuses_a_key_string() {
        let code = LinkCode {
            device_id: DeviceId([3; 32]),
            secret: LinkSecret::from_bytes([4; 32]),
        };
        let text = code.to_text(false);
        assert_eq!(text.len(), 113);
        assert_eq!(text.capacity(), 113);
        assert!(text.starts_with("lsl1"));
        let back = LinkCode::parse(&code.to_text(true)).unwrap();
        assert_eq!(back.device_id, code.device_id);
        assert!(bool::from(back.secret.ct_eq(&code.secret)));
        assert!(format!("{code:?}").ends_with("[redacted])"));
        let key = FolderKey::from(write_key(1).read_key());
        assert_eq!(
            LinkCode::parse(&key.to_key_string()).unwrap_err(),
            KeyStringError::Prefix
        );
        assert_eq!(
            FolderKey::from_key_string(&text).unwrap_err(),
            KeyStringError::Prefix
        );
        for len in [0, 31, 32, 63, 65] {
            let wrong = bech32m_encode(&HRP, &vec![0u8; len], false);
            assert_eq!(
                LinkCode::parse(&wrong).unwrap_err(),
                KeyStringError::Key(KeyError::Length {
                    expected: 64,
                    found: len
                }),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn link_values_are_separate_and_bound() {
        let secret = LinkSecret::from_bytes([1; 32]);
        let beacon = link_beacon_id(&secret);
        let key = link_confirm_key(&secret);
        assert_ne!(&beacon[..], &key.expose()[..16]);
        assert_ne!(beacon, link_beacon_id(&LinkSecret::from_bytes([2; 32])));
        let th = [3u8; 32];
        let a = link_proof(&key, &th, Role::A);
        assert_ne!(a, link_proof(&key, &th, Role::B));
        assert_ne!(a, link_proof(&key, &[4u8; 32], Role::A));
        assert_ne!(
            a,
            link_proof(
                &link_confirm_key(&LinkSecret::from_bytes([2; 32])),
                &th,
                Role::A
            )
        );
        assert!(verify_link_proof(&key, &th, Role::A, &a));
        assert!(!verify_link_proof(&key, &th, Role::B, &a));
        let mut flipped = a;
        flipped[31] ^= 1;
        assert!(!verify_link_proof(&key, &th, Role::A, &flipped));
    }

    use proptest::prelude::*;

    proptest! {
        /// Any link code reads back to the same device ID and secret, in
        /// either case.
        #[test]
        fn link_codes_round_trip(device in any::<[u8; 32]>(), secret in any::<[u8; 32]>(), upper in any::<bool>()) {
            let code = LinkCode { device_id: DeviceId(device), secret: LinkSecret::from_bytes(secret) };
            let back = LinkCode::parse(&code.to_text(upper)).unwrap();
            prop_assert_eq!(back.device_id, code.device_id);
            prop_assert!(bool::from(back.secret.ct_eq(&code.secret)));
        }

        /// Any text into the link-code parser: no panic, and what it accepts
        /// is its own text, in one case.
        #[test]
        fn any_text_into_the_link_code_parser(text in "\\PC{0,130}") {
            if let Ok(code) = LinkCode::parse(&text) {
                prop_assert_eq!(code.to_text(false).to_string(), text.to_ascii_lowercase());
            }
        }
    }
}
