// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Suite numbers, tiers and the fixed sizes of suite 1 (`keys.md` section 0,
//! `suites.md` section 1).

use core::fmt;

/// A suite number: one whole set of algorithms (`suites.md` section 1). It is a
/// 16-bit integer from 1 to 65 535; Protocol Buffers carries it as `uint32` and
/// any value outside that range is malformed.
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
    /// Suite 1: X-Wing through HPKE, Ed25519 + ML-DSA-65, XChaCha20-Poly1305,
    /// BLAKE3, Argon2id (`suites.md` section 2).
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

    /// `be16(suite)`: the two big-endian bytes that prefix public keys and
    /// identity-hash preimages.
    #[must_use]
    pub fn be16(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// A key's tier (`keys.md` section 4.1): one byte, lower numbers have more
/// authority. Root never appears in a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Tier {
    /// Issues and revokes at any tier, rotates; derived from the phrase; never in
    /// a grant and never presents.
    Root = 0,
    /// Changes files (signs index records); receives and decrypts.
    Write = 1,
    /// Receives and decrypts; its index records are ignored.
    Read = 2,
    /// Holds, verifies, serves and relays ciphertext it cannot open.
    Sealed = 3,
}

impl Tier {
    /// The tier's byte, as it appears in associated data.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The tier as Protocol Buffers carries it.
    #[must_use]
    pub fn to_wire(self) -> u32 {
        u32::from(self as u8)
    }

    /// A grant's tier from its wire value: `1`, `2` or `3` only (section 5.3).
    #[must_use]
    pub fn from_grant_wire(value: u32) -> Option<Tier> {
        match value {
            1 => Some(Tier::Write),
            2 => Some(Tier::Read),
            3 => Some(Tier::Sealed),
            _ => None,
        }
    }

    /// Whether a key of this tier receives the data key (write and read do;
    /// sealed does not; root has the Folder record's own wrap).
    #[must_use]
    pub fn can_read(self) -> bool {
        matches!(self, Tier::Root | Tier::Write | Tier::Read)
    }
}

/// Sizes the keys crate checks on every parse under suite 1 (`keys.md` 0.1).
pub mod sizes {
    /// Ed25519 public key.
    pub const ED25519_PK: usize = 32;
    /// Ed25519 signature.
    pub const ED25519_SIG: usize = 64;
    /// ML-DSA-65 public key.
    pub const MLDSA65_PK: usize = 1952;
    /// ML-DSA-65 signature.
    pub const MLDSA65_SIG: usize = 3309;
    /// Hybrid signing public key `ed25519_pk || mldsa_pk`.
    pub const SIGNING_PK: usize = ED25519_PK + MLDSA65_PK;
    /// Hybrid signature `ed25519_sig || mldsa_sig`.
    pub const HYBRID_SIG: usize = ED25519_SIG + MLDSA65_SIG;
    /// The public key bytes of a key pair set, `be16(suite) || signing_pk`
    /// (section 0.3); what Hello carries.
    pub const PUBLIC_KEY_BYTES: usize = 2 + SIGNING_PK;
    /// X-Wing public (encapsulation) key.
    pub const XWING_PK: usize = 1216;
    /// X-Wing ciphertext (HPKE `enc`).
    pub const XWING_CT: usize = 1120;
    /// X-Wing private seed.
    pub const XWING_SEED: usize = 32;
    /// HPKE wrap of a 32-byte key: `enc (1120) || ct (32 + 16)`.
    pub const WRAPPED_KEY: usize = XWING_CT + 32 + 16;
    /// Folder ID, device ID, record hash, data key, seed.
    pub const ID: usize = 32;
    /// Key ID.
    pub const KEY_ID: usize = 16;
    /// The epoch ladder link: `nonce (24) || XChaCha(dk_prev) (32 + 16)`.
    pub const LADDER_LINK: usize = 24 + 32 + 16;
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
        assert_eq!(Tier::from_grant_wire(0), None);
        assert_eq!(Tier::from_grant_wire(1), Some(Tier::Write));
        assert_eq!(Tier::from_grant_wire(2), Some(Tier::Read));
        assert_eq!(Tier::from_grant_wire(3), Some(Tier::Sealed));
        assert_eq!(Tier::from_grant_wire(4), None);
        assert_eq!(Tier::Sealed.as_u8(), 3);
        assert_eq!(Tier::Read.to_wire(), 2);
        assert!(Tier::Root.can_read() && Tier::Write.can_read() && Tier::Read.can_read());
        assert!(!Tier::Sealed.can_read());
        assert!(Tier::Root < Tier::Write && Tier::Write < Tier::Read && Tier::Read < Tier::Sealed);
    }

    #[test]
    fn sizes_add_up() {
        assert_eq!(sizes::SIGNING_PK, 1984);
        assert_eq!(sizes::HYBRID_SIG, 3373);
        assert_eq!(sizes::PUBLIC_KEY_BYTES, 1986);
        assert_eq!(sizes::WRAPPED_KEY, 1168);
        assert_eq!(sizes::LADDER_LINK, 72);
    }
}
