// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Public identifiers: folder and device IDs, record and chunk hashes and
//! writer digests, 32 bytes each. All are public data and compare with `==`.
//! The derivations themselves are with the keys they come from:
//! [`crate::folder::FolderVerifier::folder_id`],
//! [`crate::device::DevicePublicKey::device_id`],
//! [`crate::records::SignedRecord::hash`] and [`crate::chunk::cipher_hash`].

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
    /// A writer's cursor digest (`protocol.md` 4.4): 32 zero bytes, then
    /// `H("licketysync/v1/hash/writer-digest", D || record_hash)` for each of
    /// the writer's records in canonical order ([`WriterDigest::then`]).
    WriterDigest
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
            format!("{:?}", WriterDigest([0; 32])).len(),
            "WriterDigest()".len() + 64
        );
    }
}
