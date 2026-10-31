// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Public identifiers: folder and device IDs, record and chunk hashes, path
//! tags (file IDs) and set digests, 32 bytes each. All are public values and
//! compare with `==` (`suites.md` 4.2: path tags and set digests included).
//! The derivations themselves are with the keys they come from:
//! [`crate::folder::FolderVerifier::folder_id`],
//! [`crate::device::DevicePublicKey::device_id`],
//! [`crate::records::SignedRecord::hash`], [`crate::chunk::cipher_hash`],
//! [`crate::sealed_meta::RecordKeys::path_tag`] and [`crate::set_digest`].

use core::fmt;

use crate::suite::sizes;

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
        pub struct $name(pub [u8; sizes::ID]);

        impl $name {
            /// Reads the identifier from a slice of exactly 32 bytes.
            #[must_use]
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                <[u8; sizes::ID]>::try_from(bytes).ok().map(Self)
            }

            /// The bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; sizes::ID] {
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
    /// A folder's ID: `H("licketysync/v1/hash/id/folder", be16(suite) || folder_vk)`
    /// (`keys.md` 0.3, 2.1).
    FolderId
}
id32! {
    /// A device's ID: `H("licketysync/v1/hash/id/device", be16(suite) || device_pk)`
    /// (`keys.md` 0.3, 8.1). Inside a folder it is only a sync key: the
    /// sequence a device's records belong to (section 5.3), never shown as an
    /// author.
    DeviceId
}
id32! {
    /// A record's hash: `H("licketysync/v1/hash/record", body)` (section 5.1).
    RecordHash
}
id32! {
    /// A stored chunk's hash: `H("licketysync/v1/hash/chunk", stored)` (section 3.2).
    CipherHash
}
id32! {
    /// A path tag, the file ID (section 3.5): `BLAKE3_keyed(tk, path)` over
    /// the path's UTF-8 bytes exactly as `SealedMeta.path` holds them, with no
    /// normalisation. Only read and write holders compute one
    /// ([`crate::sealed_meta::RecordKeys::path_tag`]); every tier reads it in a
    /// record's clear fields. Without `tk` it names no path (TM-14).
    PathTag
}
id32! {
    /// The set digest of a subtree of a folder's records (`protocol.md` 4.5):
    /// 32 zero bytes for an empty subtree, else its leaf or node form
    /// ([`crate::set_digest`]).
    SetDigest
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
        assert_eq!(hex(&[0x0f, 0xf0]), "0ff0");
        assert_eq!(
            format!("{:?}", DeviceId([0; 32])).len(),
            "DeviceId()".len() + 64
        );
        assert_eq!(
            format!("{:?}", RecordHash([0; 32])).len(),
            "RecordHash()".len() + 64
        );
        assert_eq!(
            format!("{:?}", CipherHash([0; 32])).len(),
            "CipherHash()".len() + 64
        );
        assert_eq!(
            format!("{:?}", SetDigest([0; 32])).len(),
            "SetDigest()".len() + 64
        );
        assert_eq!(
            format!("{:?}", PathTag([0xcd; 32])),
            format!("PathTag({})", "cd".repeat(32))
        );
        assert_eq!(SetDigest([1; 32]).to_string(), "01".repeat(32));
    }
}
