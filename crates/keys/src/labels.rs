// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The label registry (`keys.md` section 10, `suites.md` section 2.4) and the
//! four labelled uses of BLAKE3.
//!
//! Every label is a typed constant here and nowhere else: a derive-key label
//! cannot be passed where a hash label is expected, and no call site can supply
//! a string. Only [`labelled_hash`], over public data, is public: the protocol
//! crate builds the transcript hash with it. The four uses are
//! domain-separated by construction:
//!
//! - `derive_key` (crate-private): BLAKE3 derive-key mode, from 32 bytes of
//!   uniformly random key material only (a write secret, a data key, an access
//!   key, a device seed, a link secret). Every purpose key comes from its
//!   parent this way, so no key serves two purposes (TM-11).
//! - [`labelled_hash`]: `H(label, x) = BLAKE3(label || 0x00 || x)`, for every
//!   identifier and link over public data. Plain `BLAKE3(x)` appears nowhere.
//! - `keyed_hash` (crate-private): keyed BLAKE3 under a key that a `derive_key`
//!   label made for that one use (`hk`, `nk`, the hint key, the payload key,
//!   the link-confirm key), so its input carries no label of its own.
//! - `signed_message` (crate-private): the signature prefix `M = label || 0x00
//!   || body`.
//!
//! [`REGISTRY`] lists every label with its mode and its input; tests check
//! that it has no duplicates, that every label matches the grammar, that every
//! `derive_key` label has a test vector, and that its labels, modes and inputs
//! equal `keys.md` section 10's and `suites.md` section 2.4's
//! (`tests/registry.rs`, which reads the specs from the repository).

use zeroize::{Zeroize, Zeroizing};

/// A BLAKE3 derive-key context string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeriveLabel(&'static str);

/// A label for the labelled hash `H`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashLabel(&'static str);

/// A signature-prefix label, one per signed layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigLabel(&'static str);

macro_rules! as_str {
    ($($t:ident),*) => {$(
        impl $t {
            /// The label text.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                self.0
            }
        }
    )*};
}
as_str!(DeriveLabel, HashLabel, SigLabel);

/// Which BLAKE3 use a label belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// BLAKE3 derive-key context.
    DeriveKey,
    /// The labelled hash `H`.
    Hash,
    /// Prefix of the signed message `M`.
    SigPrefix,
}

/// One registry row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The label.
    pub label: &'static str,
    /// Its mode.
    pub mode: Mode,
    /// What it is applied to, as `keys.md` section 10's "Material / input"
    /// column states it (the registry test compares the two).
    pub input: &'static str,
}

const fn d(label: &'static str) -> DeriveLabel {
    DeriveLabel(label)
}
const fn h(label: &'static str) -> HashLabel {
    HashLabel(label)
}
const fn s(label: &'static str) -> SigLabel {
    SigLabel(label)
}

/// The Ed25519 seed of the folder signing key, from the write secret (section 1.2).
pub const FOLDER_SIGNING_KEY: DeriveLabel = d("licketysync/v1/folder/signing-key");
/// The data key `dk`, from the write secret (section 1.2).
pub const FOLDER_DATA_KEY: DeriveLabel = d("licketysync/v1/folder/data-key");
/// The access key `ak`, from the data key (section 3.1).
pub const DATA_ACCESS_KEY: DeriveLabel = d("licketysync/v1/data/access-key");
/// The chunk key `ck`, from the data key (section 3.1).
pub const DATA_CHUNK_KEY: DeriveLabel = d("licketysync/v1/data/chunk-key");
/// The chunk nonce key `nk`, from the data key (section 3.1).
pub const DATA_CHUNK_NONCE_KEY: DeriveLabel = d("licketysync/v1/data/chunk-nonce-key");
/// The chunk hash key `hk`, from the data key (section 3.1).
pub const DATA_CHUNK_HASH_KEY: DeriveLabel = d("licketysync/v1/data/chunk-hash-key");
/// The record key `rk`, from the data key (section 3.1).
pub const DATA_RECORD_KEY: DeriveLabel = d("licketysync/v1/data/record-key");
/// The handshake's hint key, from the access key (section 4).
pub const HANDSHAKE_HINT_KEY: DeriveLabel = d("licketysync/v1/handshake/hint-key");
/// The handshake's payload key, from the access key (section 4).
pub const HANDSHAKE_PAYLOAD_KEY: DeriveLabel = d("licketysync/v1/handshake/payload-key");
/// The Ed25519 seed of the device key, from the device seed (section 8.1).
pub const KEY_ED25519: DeriveLabel = d("licketysync/v1/key/ed25519");
/// The Ed25519 seed of the libp2p identity, from the device seed (section 8.1).
pub const KEY_LIBP2P_IDENTITY: DeriveLabel = d("licketysync/v1/key/libp2p-identity");
/// The Ed25519 seed of the BEP 44 DHT key, from the device seed (section 8.1).
pub const KEY_DHT_BEP44: DeriveLabel = d("licketysync/v1/key/dht-bep44");
/// The link beacon ID, from the link secret (section 8.3).
pub const LINK_DISCOVERY: DeriveLabel = d("licketysync/v1/link/discovery");
/// The link proof's keyed-BLAKE3 key, from the link secret (section 8.3).
pub const LINK_CONFIRM: DeriveLabel = d("licketysync/v1/link/confirm");

/// Folder ID over `be16(suite) || folder_vk` (section 0.3).
pub const HASH_ID_FOLDER: HashLabel = h("licketysync/v1/hash/id/folder");
/// Device ID over `be16(suite) || device_pk` (section 0.3).
pub const HASH_ID_DEVICE: HashLabel = h("licketysync/v1/hash/id/device");
/// Record hash over a record body (section 5.1).
pub const HASH_RECORD: HashLabel = h("licketysync/v1/hash/record");
/// `cipher_hash` over a stored chunk blob (section 3.2).
pub const HASH_CHUNK: HashLabel = h("licketysync/v1/hash/chunk");
/// A writer's cursor digest step (`protocol.md` 4.4, 4.5).
pub const HASH_WRITER_DIGEST: HashLabel = h("licketysync/v1/hash/writer-digest");
/// The LAN beacon's peer tag (section 2.2).
pub const HASH_DISCOVERY_PEER: HashLabel = h("licketysync/v1/hash/discovery-peer");
/// The LAN beacon ID (section 2.2).
pub const HASH_DISCOVERY_LAN: HashLabel = h("licketysync/v1/hash/discovery-lan");
/// The DHT ID (section 2.2).
pub const HASH_DISCOVERY_DHT: HashLabel = h("licketysync/v1/hash/discovery-dht");
/// The handshake transcript hash (`protocol.md` 3.3), which the protocol
/// crate builds with [`labelled_hash`].
pub const HASH_TRANSCRIPT: HashLabel = h("licketysync/v1/hash/transcript");

/// Signature prefix of an index record (type 16, section 5).
pub const SIG_INDEX: SigLabel = s("licketysync/v1/sig/index");
/// Signature prefix of the handshake's device proof (`protocol.md` 3.4).
pub const SIG_DEVICE_PROOF: SigLabel = s("licketysync/v1/sig/device-proof");

macro_rules! entry {
    ($c:expr, $m:ident, $input:expr) => {
        Entry {
            label: $c.0,
            mode: Mode::$m,
            input: $input,
        }
    };
}

/// Every label in use, with its mode. Adding a label is a change to
/// `keys.md` section 10 first.
pub const REGISTRY: &[Entry] = &[
    entry!(FOLDER_SIGNING_KEY, DeriveKey, "write secret"),
    entry!(FOLDER_DATA_KEY, DeriveKey, "write secret"),
    entry!(DATA_ACCESS_KEY, DeriveKey, "data key"),
    entry!(DATA_CHUNK_KEY, DeriveKey, "data key"),
    entry!(DATA_CHUNK_NONCE_KEY, DeriveKey, "data key"),
    entry!(DATA_CHUNK_HASH_KEY, DeriveKey, "data key"),
    entry!(DATA_RECORD_KEY, DeriveKey, "data key"),
    entry!(HANDSHAKE_HINT_KEY, DeriveKey, "access key"),
    entry!(HANDSHAKE_PAYLOAD_KEY, DeriveKey, "access key"),
    entry!(KEY_ED25519, DeriveKey, "device seed"),
    entry!(KEY_LIBP2P_IDENTITY, DeriveKey, "device seed"),
    entry!(KEY_DHT_BEP44, DeriveKey, "device seed"),
    entry!(LINK_DISCOVERY, DeriveKey, "link secret"),
    entry!(LINK_CONFIRM, DeriveKey, "link secret"),
    entry!(
        HASH_ID_FOLDER,
        Hash,
        "be16(suite) || folder verification key"
    ),
    entry!(HASH_ID_DEVICE, Hash, "be16(suite) || device public key"),
    entry!(HASH_RECORD, Hash, "record body"),
    entry!(HASH_CHUNK, Hash, "stored chunk blob"),
    entry!(
        HASH_WRITER_DIGEST,
        Hash,
        "previous digest (32) || record hash (32)"
    ),
    entry!(
        HASH_DISCOVERY_PEER,
        Hash,
        "salt (16) || announcer libp2p identity key (32)"
    ),
    entry!(
        HASH_DISCOVERY_LAN,
        Hash,
        "salt || folder ID || peer tag || be64(minute)"
    ),
    entry!(HASH_DISCOVERY_DHT, Hash, "folder ID || be64(day)"),
    entry!(
        HASH_TRANSCRIPT,
        Hash,
        "protocol ID, both libp2p identity keys, both Hellos"
    ),
    entry!(SIG_INDEX, SigPrefix, "record body"),
    entry!(SIG_DEVICE_PROOF, SigPrefix, "transcript hash || role"),
];

/// The label grammar of `suites.md` section 2.4: ASCII lowercase from `a-z`,
/// `0-9`, `-` and `/`, reading `licketysync/v1/<area>/<purpose>`.
#[must_use]
pub fn is_well_formed(label: &str) -> bool {
    let Some(rest) = label.strip_prefix("licketysync/v1/") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    segments.len() >= 2
        && segments.iter().all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// BLAKE3 derive-key mode under a registered label (`suites.md` 2.4) over 32
/// bytes of uniformly random key material: a write secret, a data key, an
/// access key, a device seed, a link secret. Never public data and never a
/// passphrase; the type fixes the length. The output is written straight into
/// `out`, the storage of the secret type it becomes, and the hasher and the
/// `blake3::Hash` it returns are wiped, since both hold key material.
pub(crate) fn derive_key_into(label: DeriveLabel, material: &[u8; 32], out: &mut [u8; 32]) {
    let mut hasher = blake3::Hasher::new_derive_key(label.0);
    hasher.update(material);
    finish_into(hasher, out);
}

/// [`derive_key_into`] for a key that is used at once (an Ed25519 seed, a
/// beacon ID), in a buffer that is wiped when dropped.
#[must_use]
pub(crate) fn derive_key(label: DeriveLabel, material: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    derive_key_into(label, material, &mut out);
    out
}

/// Finishes a hasher whose state holds key material into `out`, then wipes
/// the hasher and the `blake3::Hash` it returned, so that no copy of the
/// output or of the key is left behind in either.
fn finish_into(mut hasher: blake3::Hasher, out: &mut [u8; 32]) {
    let mut hash = hasher.finalize();
    *out = *hash.as_bytes();
    hash.zeroize();
    hasher.zeroize();
}

/// The labelled hash `H(label, x) = BLAKE3(label || 0x00 || x)` over public
/// data, with `x` given as parts that are concatenated.
#[must_use]
pub fn labelled_hash(label: HashLabel, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.0.as_bytes());
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Keyed BLAKE3 under a key that a `derive_key` label made for that one use
/// (`hk`, `nk`, the hint key, the payload key, the link-confirm key): no label
/// in the input (`keys.md` 0). The output is written into `out`; the hasher,
/// whose state holds the key, and its `blake3::Hash` are wiped.
pub(crate) fn keyed_hash_into(key: &[u8; 32], parts: &[&[u8]], out: &mut [u8; 32]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(part);
    }
    finish_into(hasher, out);
}

/// [`keyed_hash_into`] for an output that is not itself a secret (a hint, a
/// chunk nonce, a plaintext hash, a link proof).
#[must_use]
pub(crate) fn keyed_hash(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    keyed_hash_into(key, parts, &mut out);
    out
}

/// The bytes an Ed25519 signature signs: `M = label || 0x00 || body`
/// (`keys.md` 0.2, `suites.md` 2.2).
#[must_use]
pub(crate) fn signed_message(label: SigLabel, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(label.0.len() + 1 + body.len());
    m.extend_from_slice(label.0.as_bytes());
    m.push(0);
    m.extend_from_slice(body);
    m
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
    use std::collections::BTreeSet;

    /// The official BLAKE3 test vectors, all three modes, outputs at 32
    /// bytes: the primitive under the helpers this module wraps.
    #[test]
    fn vector_blake3_official() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/blake3_official.json")).unwrap();
        let key: [u8; 32] = v["key"].as_str().unwrap().as_bytes().try_into().unwrap();
        let context = v["context_string"].as_str().unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 35);
        for case in cases {
            let len = usize::try_from(case["input_len"].as_u64().unwrap()).unwrap();
            let input: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let hex = |b: &[u8; 32]| crate::ids::hex(b);
            assert_eq!(
                hex(blake3::hash(&input).as_bytes()),
                case["hash"].as_str().unwrap(),
                "hash {len}"
            );
            assert_eq!(
                hex(blake3::keyed_hash(&key, &input).as_bytes()),
                case["keyed_hash"].as_str().unwrap(),
                "keyed {len}"
            );
            assert_eq!(
                hex(&blake3::derive_key(context, &input)),
                case["derive_key"].as_str().unwrap(),
                "derive {len}"
            );
        }
    }

    #[test]
    fn registry_has_no_duplicates_and_every_label_is_well_formed() {
        let mut seen = BTreeSet::new();
        for e in REGISTRY {
            assert!(
                is_well_formed(e.label),
                "{} breaks the label grammar",
                e.label
            );
            assert!(seen.insert(e.label), "{} is registered twice", e.label);
        }
        assert_eq!(REGISTRY.len(), 25);
        let count = |m: Mode| REGISTRY.iter().filter(|e| e.mode == m).count();
        assert_eq!(
            (
                count(Mode::DeriveKey),
                count(Mode::Hash),
                count(Mode::SigPrefix)
            ),
            (14, 9, 2)
        );
    }

    #[test]
    fn grammar() {
        assert!(is_well_formed("licketysync/v1/key/ed25519"));
        assert!(is_well_formed("licketysync/v1/hash/id/folder"));
        assert!(!is_well_formed("licketysync/v2/key/ed25519"));
        assert!(!is_well_formed("licketysync/v1/key"));
        assert!(!is_well_formed("licketysync/v1/key/"));
        assert!(!is_well_formed("licketysync/v1//ed25519"));
        assert!(!is_well_formed("licketysync/v1/Key/ed25519"));
        assert!(!is_well_formed("licketysync/v1/key/ed25519 "));
        assert!(!is_well_formed("other/v1/key/ed25519"));
    }

    #[test]
    fn labelled_hash_is_label_then_zero_then_input() {
        let a = labelled_hash(HASH_RECORD, &[b"ab", b"c"]);
        let b = labelled_hash(HASH_RECORD, &[b"abc"]);
        assert_eq!(a, b);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"licketysync/v1/hash/record\0abc");
        assert_eq!(a, *hasher.finalize().as_bytes());
        assert_ne!(a, labelled_hash(HASH_CHUNK, &[b"abc"]));
    }

    /// `suites.md` 3.2: the words' list is the BIP39 English list the `bip39`
    /// crate embeds, pinned by its BLAKE3 hash in the form of BIP39's
    /// `english.txt` (one word per line, a final line ending), so a change to
    /// the list in a dependency update fails here.
    #[test]
    fn the_bip39_english_word_list_is_pinned() {
        let list = bip39::Language::English.word_list();
        assert_eq!(list.len(), 2048);
        assert_eq!((list[0], list[2047]), ("abandon", "zoo"));
        let mut text = list.join("\n");
        text.push('\n');
        assert_eq!(
            ::hex::encode(blake3::hash(text.as_bytes()).as_bytes()),
            "43afe08c75f902534cfd2a694bef11db381f4804cd3ef76cd05a8ad0d7199122"
        );
    }

    #[test]
    fn keyed_hashes_and_signed_message() {
        let key = [9u8; 32];
        assert_ne!(
            keyed_hash(&key, &[b"xy"]),
            keyed_hash(&[8u8; 32], &[b"xy"]),
            "the key is bound"
        );
        assert_eq!(
            keyed_hash(&key, &[b"x", b"y"]),
            *blake3::keyed_hash(&key, b"xy").as_bytes()
        );
        assert_eq!(
            signed_message(SIG_INDEX, b"body"),
            b"licketysync/v1/sig/index\0body"
        );
        assert_eq!(
            &*derive_key(KEY_ED25519, &[1u8; 32]),
            &blake3::derive_key("licketysync/v1/key/ed25519", &[1u8; 32])
        );
        assert_eq!(KEY_ED25519.as_str(), "licketysync/v1/key/ed25519");
        assert_eq!(HASH_CHUNK.as_str(), "licketysync/v1/hash/chunk");
        assert_eq!(
            HANDSHAKE_PAYLOAD_KEY.as_str(),
            "licketysync/v1/handshake/payload-key"
        );
        assert_eq!(SIG_INDEX.as_str(), "licketysync/v1/sig/index");
    }
}
