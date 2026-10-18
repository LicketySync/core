// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key material for Lickety-Sync: the recovery phrase, seed-derived key pair
//! sets, hybrid signatures (Ed25519 + ML-DSA-65), hybrid key wrapping (X-Wing
//! through HPKE), the folder's key records (Folder, Grant, Rotation, Wrap,
//! Revocation, Suspension, Lift) with their verification, data keys and the
//! epoch ladder, chunk sealing, key strings and discovery hashes. Under ruling
//! 13b this crate owns every cryptographic primitive, label, identifier and
//! [`records::SignedRecord`]; `licketysync-protocol` depends on it and builds
//! the handshake (transcript hash, folder hint, proof key, sealed proof) from
//! [`labels`] (with [`labels::folder_hint`]), [`secret::ProofKey`] and
//! [`aead`], and this crate never depends on the protocol crate.
//!
//! This crate implements `spec/keys.md` under the algorithms of `spec/suites.md`
//! and the requirements of `spec/threat-model.md`; section numbers in the docs
//! below refer to `keys.md` unless another file is named. Every byte that reaches
//! a parser here may have come from a peer and is untrusted: sizes are checked
//! before anything is interpreted, every rejection is a typed error, and nothing
//! is defaulted (TM-2, TM-10).
//!
//! # Where randomness comes from
//!
//! The crate never reads a random source of its own. Every operation that needs
//! randomness (seeds, data keys, nonces, salts, HPKE encapsulations, hedged
//! signatures; key IDs are derived, never drawn) takes a [`rng::RandomFill`], a
//! `&mut dyn FnMut(&mut [u8])` that
//! fills a buffer. The daemon passes the operating system's generator; the
//! simulator passes its seeded one; the engine passes
//! `|buf| cx.fill_random(buf)` from its runtime's `Randomness` trait. See
//! [`rng`] for the mapping.
//!
//! # Where time comes from
//!
//! Nothing here reads a clock. The predicates that depend on the wall clock
//! (expiry, a suspension's `until`) take `now_unix: u64`, which the caller reads
//! from its runtime's `Clock::wall_time()`.
//!
//! # Secrets
//!
//! Seeds, the master secret, data keys and every derived key live in the types of
//! [`secret`], which zeroize on drop, print `[redacted]` and compare in constant
//! time (`suites.md` section 4, TM-6).

pub mod aead;
mod bytes;
pub mod chunk;
pub mod derive;
pub mod discovery;
pub mod epoch;
pub mod ids;
pub mod keyset;
pub mod keystring;
pub mod labels;
pub mod linking;
pub mod phrase;
pub mod records;
pub mod rng;
pub mod secret;
pub mod suite;
#[cfg(test)]
mod test_vectors;
pub mod wrap;

pub use ids::{CipherHash, DeviceId, FolderId, IdentityId, KeyId, RecordHash};
pub use keyset::{HybridSignature, KemPublicKey, KeyPairSet, PublicKeySet, SigningPublicKey};
pub use rng::RandomFill;
pub use secret::{DataKey, MasterSecret, Seed};
pub use suite::{Suite, Tier};

// The integration tests' dev-dependencies, which the unit-test build of the
// library does not use.
#[cfg(test)]
use {hex as _, serde_json as _};

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-keys";

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-keys");
    }
}
