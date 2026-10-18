// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Public identifiers: folder, device and identity IDs, record and chunk hashes
//! (32 bytes), and key IDs (16 bytes). All are public data and compare with `==`.
//! The derivations themselves (labelled hashes over public keys) are in
//! [`crate::derive`].

use core::fmt;

/// Lowercase hex of some bytes, for identifiers in diagnostics.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let digit = |n: u8| char::from_digit(u32::from(n), 16).unwrap_or('0');
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(digit(b >> 4));
        s.push(digit(b & 15));
    }
    s
}

macro_rules! id32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Reads the identifier from a slice of exactly 32 bytes.
            #[must_use]
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                <[u8; 32]>::try_from(bytes).ok().map(Self)
            }

            /// The bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex(&self.0))
            }
        }
    };
}

id32! {
    /// A folder's ID: `H("licketysync/v1/hash/id/folder", be16(suite) || root signing pk)` (section 2.1).
    FolderId
}
id32! {
    /// A device's ID: the labelled hash of its device signing public key (section 1.3).
    DeviceId
}
id32! {
    /// A person's identity ID (section 1.2, phase 5).
    IdentityId
}
id32! {
    /// A record's hash: `H("licketysync/v1/hash/record", body)` (section 5.1).
    RecordHash
}
id32! {
    /// A stored chunk's hash: `H("licketysync/v1/hash/chunk", stored)` (section 3.3).
    CipherHash
}

/// A key ID: the first 16 bytes of
/// `H("licketysync/v1/hash/id/key", be16(suite) || signing_pk || kem_pk)` of
/// an issued key ([`crate::derive::key_id`], `keys.md` section 0.4), so that
/// every verifier can recompute it from the grant's own two public keys and
/// one ID never names two key pairs. The all-zero ID names root, which has no
/// grant, and is never derived for an issued key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub [u8; 16]);

impl KeyId {
    /// The reserved root key ID: 16 zero bytes (section 2.1).
    pub const ROOT: KeyId = KeyId([0u8; 16]);

    /// Reads a key ID from a slice of exactly 16 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 16]>::try_from(bytes).ok().map(Self)
    }

    /// Whether this is the reserved root key ID.
    #[must_use]
    pub fn is_root(&self) -> bool {
        *self == KeyId::ROOT
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", hex(&self.0))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
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

    #[test]
    fn ids_parse_exact_sizes_and_print_hex() {
        assert!(FolderId::from_slice(&[0u8; 31]).is_none());
        assert!(FolderId::from_slice(&[0u8; 33]).is_none());
        let id = FolderId::from_slice(&[0xab; 32]).unwrap();
        assert_eq!(id.as_bytes(), &[0xab; 32]);
        assert_eq!(format!("{id:?}"), format!("FolderId({})", "ab".repeat(32)));
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert!(KeyId::from_slice(&[0u8; 15]).is_none());
        let k = KeyId::from_slice(&[1u8; 16]).unwrap();
        assert_eq!(format!("{k:?}"), format!("KeyId({})", "01".repeat(16)));
        assert_eq!(k.to_string(), "01".repeat(16));
        assert!(!k.is_root());
        assert!(KeyId::ROOT.is_root());
        assert_eq!(KeyId::ROOT.as_bytes(), &[0u8; 16]);
        assert_eq!(hex(&[0x0f, 0xf0]), "0ff0");
        assert_eq!(
            format!("{:?}", DeviceId([0; 32])).len(),
            "DeviceId()".len() + 64
        );
        assert_eq!(
            format!("{:?}", IdentityId([0; 32])).len(),
            "IdentityId()".len() + 64
        );
        assert_eq!(
            format!("{:?}", RecordHash([0; 32])).len(),
            "RecordHash()".len() + 64
        );
        assert_eq!(
            format!("{:?}", CipherHash([0; 32])).len(),
            "CipherHash()".len() + 64
        );
    }
}
