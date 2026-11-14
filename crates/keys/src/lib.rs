// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key material for LicketySync's shared folder keys: each folder has three
//! shared secret keys, as in Resilio Sync, and holding a key is the access.
//!
//! - [`folder`]: the 32-byte write secret and everything it derives (the
//!   folder's Ed25519 signing key, its data key, its folder ID), the read and
//!   sealed keys, and the stored form of a folder key.
//! - [`records`]: the signed envelope that every update travels in, index
//!   records and cleanups, signed with the folder's write key under the label
//!   of the record type and verified by every peer, and the record hash.
//! - [`chunk`] and [`sealed_meta`]: chunk encryption (XChaCha20-Poly1305,
//!   Padmé padding) with keyed BLAKE3 chunk hashes and the chunker's keyed
//!   gear table; sealed metadata, padded to a power of two, under the
//!   associated data of its index record or cleanup, and path tags, the file
//!   IDs, both through a folder's [`sealed_meta::RecordKeys`].
//! - [`set_digest`]: the set digests that reconcile index records.
//! - [`handshake`] and [`device`]: the hint and the sealed payload of the
//!   folder proof (one for every tier), the device key and its proof, the
//!   libp2p identity and the DHT key.
//! - [`keystring`] and [`words`]: key strings (Bech32m, `lsw`, `lsr`, `lss`),
//!   links and files, and the write key's 24 words (BIP39).
//! - [`discovery`] and [`linking`]: discovery hashes and the linked-device
//!   code and proof.
//! - [`labels`]: the label registry and the only calls into BLAKE3.
//!
//! This crate owns every cryptographic primitive, label and identifier of the
//! workspace; `licketysync-protocol` depends on it and builds the handshake
//! from [`handshake`], [`device`] and [`labels`], and this crate never depends
//! on the protocol crate. Its public surface is kept to what a caller needs:
//! the AEAD itself, `derive_key`, the signed-message prefix and every key
//! below a folder key are private to the crate, and the chunk and handshake
//! keys are built only from a folder key, so that no caller can pair a key
//! with the wrong folder ID or choose a nonce. It implements `spec/keys.md` under the algorithms of
//! `spec/suites.md` and the requirements of `spec/threat-model.md`; section
//! numbers in the docs below refer to `keys.md` unless another file is named.
//! Every byte that reaches a parser here may have come from a peer and is
//! untrusted: sizes are checked before anything is interpreted, every
//! rejection is a typed error, and nothing is defaulted (TM-2, TM-10).
//!
//! # Where randomness comes from
//!
//! The crate never reads a random source of its own. The few operations that
//! need randomness (a write secret, a device seed, a link secret, the nonce of
//! sealed metadata or of a folder proof) take a [`rng::RandomFill`], a
//! `&mut dyn FnMut(&mut [u8])` that fills a buffer. The daemon passes the operating system's generator;
//! the simulator passes its seeded one. Ed25519 signing and chunk encryption
//! are deterministic.
//!
//! # Time
//!
//! Nothing here reads a clock, and no key expires. The discovery hashes take
//! the time from the caller; a record's counter is inside its seal, which this
//! crate seals and opens without reading it.
//!
//! # Secrets
//!
//! Write secrets, data keys and every derived key live in the types of
//! [`secret`] and [`folder`], which zeroize on drop, print `[redacted]` and
//! compare in constant time (`suites.md` section 4, TM-6); each is built in
//! place, and no error value carries a secret or a length read from inside a
//! ciphertext.

mod aead;
mod bytes;
pub mod chunk;
pub mod device;
pub mod discovery;
pub mod folder;
pub mod handshake;
pub mod ids;
pub mod keystring;
pub mod labels;
pub mod linking;
pub mod records;
pub mod rng;
pub mod sealed_meta;
pub mod secret;
pub mod set_digest;
pub mod sig;
pub mod suite;
#[cfg(test)]
mod test_vectors;
pub mod words;

pub use aead::{AeadError, SealError};
pub use folder::{FolderKey, FolderVerifier, ReadKey, SealedKey, WriteKey};
pub use handshake::Role;
pub use ids::{CipherHash, DeviceId, FolderId, PathTag, RecordHash, SetDigest};
pub use records::{RecordType, SignedRecord};
pub use rng::RandomFill;
pub use secret::{DataKey, WriteSecret};
pub use sig::Signature;
pub use suite::{Suite, Tier};

// The integration tests' dev-dependencies, which the unit-test build of the
// library does not use.
#[cfg(test)]
use {hex as _, serde_json as _};

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-keys";

/// The fixed seed every property test of this crate runs from in the gate,
/// so that the gate is deterministic; the protocol and index crates' tests
/// run from the same one.
#[cfg(test)]
pub(crate) const PROPTEST_SEED: u64 = 0x6c69_636b_6574_7379;

/// The proptest configuration of every property test of this crate:
/// `cases` cases, or `PROPTEST_CASES` when it is set, from the fixed
/// [`PROPTEST_SEED`], or from the seed `LICKETYSYNC_PROPTEST_SEED` names:
/// `random` for a random one (a long run outside the gate), or a number.
#[cfg(test)]
#[allow(clippy::panic, reason = "test code")]
pub(crate) fn proptest_config(cases: u32) -> proptest::test_runner::Config {
    use proptest::test_runner::{Config, RngSeed};
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cases);
    let rng_seed = match std::env::var("LICKETYSYNC_PROPTEST_SEED") {
        Ok(v) if v == "random" => RngSeed::Random,
        Ok(v) => RngSeed::Fixed(
            v.parse()
                .unwrap_or_else(|_| panic!("LICKETYSYNC_PROPTEST_SEED={v}: random or a u64")),
        ),
        Err(_) => RngSeed::Fixed(PROPTEST_SEED),
    };
    Config {
        cases,
        rng_seed,
        ..Config::default()
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
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-keys");
    }
}
