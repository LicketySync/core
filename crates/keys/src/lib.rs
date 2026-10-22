// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key material for Lickety-Sync's shared folder keys: each folder has three
//! shared secret keys, as in Resilio Sync, and holding a key is the access.
//!
//! - [`folder`]: the 32-byte write secret and everything it derives (the
//!   folder's Ed25519 signing key, its data key, its folder ID), the read and
//!   sealed keys, and the stored form of a folder key.
//! - [`records`]: the signed envelope that every update travels in, signed
//!   with the folder's write key and verified by every peer, the record hash
//!   and the writer digest.
//! - [`chunk`] and [`sealed_meta`]: chunk and sealed-metadata encryption
//!   (XChaCha20-Poly1305, Padmé), keyed BLAKE3 chunk hashes.
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
//! Nothing here reads a clock, and no key or record expires. The discovery
//! hashes take the time from the caller.
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
pub mod sig;
pub mod suite;
#[cfg(test)]
mod test_vectors;
pub mod words;

pub use aead::{AeadError, SealError};
pub use folder::{FolderKey, FolderVerifier, ReadKey, SealedKey, WriteKey};
pub use handshake::Role;
pub use ids::{CipherHash, DeviceId, FolderId, RecordHash, WriterDigest};
pub use records::SignedRecord;
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
