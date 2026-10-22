// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Suite numbers, tiers and the fixed sizes of suite 1 (`keys.md` section 0,
//! `suites.md` section 1).

use core::fmt;

/// A suite number: one whole set of algorithms (`suites.md` section 1). It is a
/// 16-bit integer from 1 to 65 535; Protocol Buffers carries it as `uint32` and
/// any value outside that range is malformed. A folder's suite is the suite of
/// its keys, fixed when the folder is made (`keys.md` 0, 1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Suite(u16);

/// Why a wire value is not a suite number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiteError {
    /// The value was `0`, which never appears on the wire or on disk.
    Zero,
    /// The value does not fit in 16 bits.
    OutOfRange(u32),
}

impl fmt::Display for SuiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(f, "suite 0 is invalid"),
            Self::OutOfRange(v) => write!(f, "suite {v} does not fit in 16 bits"),
        }
    }
}

impl std::error::Error for SuiteError {}

impl Suite {
    /// Suite 1: Ed25519 signatures, XChaCha20-Poly1305, BLAKE3 and Argon2id
    /// (`suites.md` section 2). The suite this release creates folders under.
    pub const ONE: Suite = Suite(1);

    /// Reads a suite number from its `uint32` wire form.
    ///
    /// # Errors
    ///
    /// `0` and values above 65 535 are malformed.
    pub fn from_wire(value: u32) -> Result<Suite, SuiteError> {
        match u16::try_from(value) {
            Ok(0) => Err(SuiteError::Zero),
            Ok(n) => Ok(Suite(n)),
            Err(_) => Err(SuiteError::OutOfRange(value)),
        }
    }

    /// Reads `be16(suite)`, the two bytes that lead key-string payloads and
    /// the device public key in Hello.
    ///
    /// # Errors
    ///
    /// [`SuiteError::Zero`] for `0`.
    pub fn from_be16(bytes: [u8; 2]) -> Result<Suite, SuiteError> {
        Suite::from_wire(u32::from(u16::from_be_bytes(bytes)))
    }

    /// Whether this release implements the suite. Only suite 1 exists.
    #[must_use]
    pub fn is_implemented(self) -> bool {
        self == Suite::ONE
    }

    /// The number itself.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0
    }

    /// The number as Protocol Buffers carries it.
    #[must_use]
    pub fn to_wire(self) -> u32 {
        u32::from(self.0)
    }

    /// `be16(suite)`: the two big-endian bytes that lead key-string payloads,
    /// the Hello device key and identity-hash preimages.
    #[must_use]
    pub fn be16(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// A folder key's tier (`keys.md` 0, 1.3): one byte, lower numbers can do
/// more. `0` was the drafts' root tier and is never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Tier {
    /// The write secret: derives every key, signs records, decrypts.
    Write = 1,
    /// The verification key and the data key: verifies and decrypts.
    Read = 2,
    /// The verification key and the access key: verifies, stores and relays
    /// ciphertext it cannot open.
    Sealed = 3,
}

impl Tier {
    /// Every tier, highest first.
    pub const ALL: [Tier; 3] = [Tier::Write, Tier::Read, Tier::Sealed];

    /// The tier's byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The tier as Protocol Buffers carries it (`ProofPayload.tier`).
    #[must_use]
    pub fn to_wire(self) -> u32 {
        u32::from(self as u8)
    }

    /// The tier a wire value names: `1`, `2` or `3` only.
    #[must_use]
    pub fn from_wire(value: u32) -> Option<Tier> {
        match value {
            1 => Some(Tier::Write),
            2 => Some(Tier::Read),
            3 => Some(Tier::Sealed),
            _ => None,
        }
    }

    /// Whether a key of this tier holds the data key (write and read do;
    /// sealed does not).
    #[must_use]
    pub fn can_read(self) -> bool {
        matches!(self, Tier::Write | Tier::Read)
    }
}

/// Sizes the keys crate checks on every parse under suite 1 (`keys.md` 0.1).
pub mod sizes {
    /// `be16(suite)`, the two bytes that lead key-string payloads and the
    /// device public key in Hello.
    pub const SUITE: usize = 2;
    /// Ed25519 public key.
    pub const ED25519_PK: usize = 32;
    /// Ed25519 signature.
    pub const ED25519_SIG: usize = 64;
    /// A write secret, data key, access key and every key derived from them.
    pub const KEY: usize = 32;
    /// Folder ID, device ID, record hash, ciphertext hash.
    pub const ID: usize = 32;
    /// The device public key as Hello carries it, `be16(suite) || ed25519_pk`.
    pub const DEVICE_PUBLIC_KEY: usize = SUITE + ED25519_PK;
    /// The write key string's payload, `be16(suite) || ws`.
    pub const WRITE_PAYLOAD: usize = SUITE + KEY;
    /// The read key string's payload, `be16(suite) || folder_vk || dk`.
    pub const READ_PAYLOAD: usize = SUITE + ED25519_PK + KEY;
    /// The sealed key string's payload, `be16(suite) || folder_vk || ak`.
    pub const SEALED_PAYLOAD: usize = SUITE + ED25519_PK + KEY;
    /// The write key string, in characters.
    pub const WRITE_KEY_STRING: usize = 65;
    /// The read key string, in characters.
    pub const READ_KEY_STRING: usize = 116;
    /// The sealed key string, in characters.
    pub const SEALED_KEY_STRING: usize = 116;
    /// XChaCha20-Poly1305 nonce.
    pub const NONCE: usize = 24;
    /// Poly1305 tag.
    pub const TAG: usize = 16;
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
    fn suite_wire_range() {
        assert_eq!(Suite::from_wire(0), Err(SuiteError::Zero));
        assert_eq!(Suite::from_wire(1), Ok(Suite::ONE));
        assert_eq!(Suite::from_wire(65_535).map(Suite::as_u16), Ok(65_535));
        assert_eq!(
            Suite::from_wire(65_536),
            Err(SuiteError::OutOfRange(65_536))
        );
        assert_eq!(Suite::from_be16([0, 0]), Err(SuiteError::Zero));
        assert_eq!(Suite::from_be16([0, 1]), Ok(Suite::ONE));
        assert_eq!(Suite::from_be16([1, 0]).map(Suite::as_u16), Ok(256));
        assert!(Suite::ONE.is_implemented());
        assert!(!Suite(2).is_implemented());
        assert_eq!(Suite::ONE.be16(), [0, 1]);
        assert_eq!(Suite::ONE.to_wire(), 1);
        assert_eq!(SuiteError::Zero.to_string(), "suite 0 is invalid");
        assert_eq!(
            SuiteError::OutOfRange(70_000).to_string(),
            "suite 70000 does not fit in 16 bits"
        );
    }

    #[test]
    fn tiers() {
        assert_eq!(Tier::from_wire(0), None);
        assert_eq!(Tier::from_wire(1), Some(Tier::Write));
        assert_eq!(Tier::from_wire(2), Some(Tier::Read));
        assert_eq!(Tier::from_wire(3), Some(Tier::Sealed));
        assert_eq!(Tier::from_wire(4), None);
        assert_eq!(Tier::Sealed.as_u8(), 3);
        assert_eq!(Tier::Read.to_wire(), 2);
        assert!(Tier::Write.can_read() && Tier::Read.can_read());
        assert!(!Tier::Sealed.can_read());
        assert!(Tier::Write < Tier::Read && Tier::Read < Tier::Sealed);
        assert_eq!(Tier::ALL, [Tier::Write, Tier::Read, Tier::Sealed]);
    }

    #[test]
    fn sizes_add_up() {
        assert_eq!(sizes::SUITE, Suite::ONE.be16().len());
        assert_eq!(sizes::DEVICE_PUBLIC_KEY, 34);
        assert_eq!(sizes::WRITE_PAYLOAD, 34);
        assert_eq!(sizes::READ_PAYLOAD, 66);
        assert_eq!(sizes::SEALED_PAYLOAD, 66);
        // 3-character prefix, the separator, ceil(8 * payload / 5) data
        // characters and the 6-character checksum (keys.md 6.1).
        let chars = |payload: usize| 3 + 1 + (8 * payload).div_ceil(5) + 6;
        assert_eq!(chars(sizes::WRITE_PAYLOAD), sizes::WRITE_KEY_STRING);
        assert_eq!(chars(sizes::READ_PAYLOAD), sizes::READ_KEY_STRING);
        assert_eq!(chars(sizes::SEALED_PAYLOAD), sizes::SEALED_KEY_STRING);
    }
}
