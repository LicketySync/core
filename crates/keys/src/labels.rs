// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The label registry (`keys.md` section 10, `suites.md` section 2.4) and the
//! four labelled uses of BLAKE3.
//!
//! Every label is a typed constant here and nowhere else: a derive-key label
//! cannot be passed where a hash label is expected, and no call site can supply
//! a string. The four modes are domain-separated by construction:
//!
//! - [`derive_key`]: BLAKE3 derive-key mode, from uniformly random key material
//!   only (32 or 64 bytes). Every purpose key comes from its parent this way, so
//!   no key serves two purposes (TM-11).
//! - [`labelled_hash`]: `H(label, x) = BLAKE3(label || 0x00 || x)`, for every
//!   identifier and link over public data. Plain `BLAKE3(x)` appears nowhere.
//! - `keyed_hash_labelled` (crate-private): keyed BLAKE3 over `label || 0x00
//!   || x` where the key is itself a public identifier, the folder ID. Outside
//!   the crate it is reachable only as its two uses, the handshake's
//!   [`folder_hint`] and [`crate::secret::ProofKey::derive`], so the proof key
//!   is never a bare array; the protocol crate builds the handshake from these
//!   (ruling 13b). The keyed hashes under a *derived* key (`hk`, `nk_e`, the
//!   link-confirm key) carry no label in the input, because the key's own
//!   derivation label already separates them; they use the crate-private
//!   `keyed_hash`.
//! - [`signed_message`]: the signature prefix `M = label || 0x00 || body`.
//!
//! [`REGISTRY`] lists every label with its mode; tests check that it has no
//! duplicates, that every label matches the grammar, that every label has a
//! test vector, and that its labels and modes equal `keys.md` section 10's and
//! cover `suites.md` section 2.4's (`tests/registry.rs`, which reads the specs
//! from the repository).

use zeroize::{Zeroize, Zeroizing};

use crate::ids::FolderId;

/// A BLAKE3 derive-key context string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeriveLabel(&'static str);

/// A label for the labelled hash `H`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashLabel(&'static str);

/// A label prefixed inside the input of a keyed hash whose key is public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyedLabel(&'static str);

/// A signature-prefix label, one per record or proof type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigLabel(&'static str);

/// An HPKE `info` string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapInfo(&'static str);

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
as_str!(DeriveLabel, HashLabel, KeyedLabel, SigLabel, WrapInfo);

/// Which BLAKE3 (or HPKE) use a label belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// BLAKE3 derive-key context.
    DeriveKey,
    /// The labelled hash `H`.
    Hash,
    /// Keyed BLAKE3 with the label inside the input (key = folder ID).
    Keyed,
    /// Prefix of the signed message `M`.
    SigPrefix,
    /// HPKE `info`.
    HpkeInfo,
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
const fn k(label: &'static str) -> KeyedLabel {
    KeyedLabel(label)
}
const fn s(label: &'static str) -> SigLabel {
    SigLabel(label)
}

/// Identity seed from the master secret (section 1.2).
pub const IDENTITY_SEED: DeriveLabel = d("licketysync/v1/identity/seed");
/// The catalogue's `XChaCha` key from the identity seed (section 1.2, phase 5).
pub const IDENTITY_CATALOGUE_KEY: DeriveLabel = d("licketysync/v1/identity/catalogue-key");
/// Folder root seed from `ms || folder_nonce` (section 1.2).
pub const FOLDER_ROOT_SEED: DeriveLabel = d("licketysync/v1/folder/root-seed");
/// `hk` from `dk_1` (section 3.2).
pub const FOLDER_CHUNK_HASH_KEY: DeriveLabel = d("licketysync/v1/folder/chunk-hash-key");
/// Ed25519 seed from any key seed (section 0.3).
pub const KEY_ED25519: DeriveLabel = d("licketysync/v1/key/ed25519");
/// ML-DSA-65 ξ from any key seed (section 0.3).
pub const KEY_ML_DSA_65: DeriveLabel = d("licketysync/v1/key/ml-dsa-65");
/// X-Wing decapsulation seed from any key seed (section 0.3).
pub const KEY_X_WING: DeriveLabel = d("licketysync/v1/key/x-wing");
/// The libp2p identity's Ed25519 seed from the device seed (section 1.3).
pub const KEY_LIBP2P_IDENTITY: DeriveLabel = d("licketysync/v1/key/libp2p-identity");
/// The BEP 44 DHT signing key's Ed25519 seed from the device seed (section 1.3).
pub const KEY_DHT_BEP44: DeriveLabel = d("licketysync/v1/key/dht-bep44");
/// `ck_e` from `dk_e` (section 3.2).
pub const EPOCH_CHUNK_KEY: DeriveLabel = d("licketysync/v1/epoch/chunk-key");
/// `nk_e` from `dk_e` (section 3.2).
pub const EPOCH_CHUNK_NONCE_KEY: DeriveLabel = d("licketysync/v1/epoch/chunk-nonce-key");
/// `rk_e` from `dk_e` (section 3.2).
pub const EPOCH_RECORD_KEY: DeriveLabel = d("licketysync/v1/epoch/record-key");
/// The ladder key from `dk_e` (section 3.1).
pub const EPOCH_LADDER_KEY: DeriveLabel = d("licketysync/v1/epoch/ladder-key");
/// The rotation's key-confirmation value from `dk_e` (section 7.1).
pub const EPOCH_CONFIRM: DeriveLabel = d("licketysync/v1/epoch/confirm");
/// The link beacon ID from the link secret (section 8.1).
pub const LINK_DISCOVERY: DeriveLabel = d("licketysync/v1/link/discovery");
/// The link proof's keyed-BLAKE3 key from the link secret (section 8.1).
pub const LINK_CONFIRM: DeriveLabel = d("licketysync/v1/link/confirm");

/// Folder ID over `be16(suite) || root signing pk` (section 0.4).
pub const HASH_ID_FOLDER: HashLabel = h("licketysync/v1/hash/id/folder");
/// Device ID over `be16(suite) || device signing pk`.
pub const HASH_ID_DEVICE: HashLabel = h("licketysync/v1/hash/id/device");
/// Identity ID over `be16(suite) || identity signing pk`.
pub const HASH_ID_IDENTITY: HashLabel = h("licketysync/v1/hash/id/identity");
/// Key ID over `be16(suite) || issued signing pk || issued kem_pk`, truncated
/// to 16 bytes (section 0.4; coordinator decision 2026-10-15: key IDs are
/// derived, not random).
pub const HASH_ID_KEY: HashLabel = h("licketysync/v1/hash/id/key");
/// Record hash over a record body (section 5.1).
pub const HASH_RECORD: HashLabel = h("licketysync/v1/hash/record");
/// `cipher_hash` over a stored chunk blob (section 3.3).
pub const HASH_CHUNK: HashLabel = h("licketysync/v1/hash/chunk");
/// The LAN beacon's peer tag (section 2.3).
pub const HASH_DISCOVERY_PEER: HashLabel = h("licketysync/v1/hash/discovery-peer");
/// The LAN beacon ID (section 2.3).
pub const HASH_DISCOVERY_LAN: HashLabel = h("licketysync/v1/hash/discovery-lan");
/// The DHT ID (section 2.3).
pub const HASH_DISCOVERY_DHT: HashLabel = h("licketysync/v1/hash/discovery-dht");
/// The handshake transcript hash (`protocol.md` 3.3).
pub const HASH_TRANSCRIPT: HashLabel = h("licketysync/v1/hash/transcript");

/// The folder hint, keyed with the folder ID (`protocol.md` 3.5).
pub const HANDSHAKE_FOLDER_HINT: KeyedLabel = k("licketysync/v1/handshake/folder-hint");
/// The proof key, keyed with the folder ID (`protocol.md` 3.5).
pub const HANDSHAKE_PROOF_KEY: KeyedLabel = k("licketysync/v1/handshake/proof-key");

/// Signature prefix of the Folder record (type 1).
pub const SIG_FOLDER: SigLabel = s("licketysync/v1/sig/folder");
/// Signature prefix of a Grant (type 2).
pub const SIG_GRANT: SigLabel = s("licketysync/v1/sig/grant");
/// Signature prefix of a grant's proof of possession, signed by the issued
/// key itself over the grant body without its `key_signature` (round 4
/// ruling, BLOCKER 1).
pub const SIG_GRANT_POP: SigLabel = s("licketysync/v1/sig/grant-pop");
/// Signature prefix of a Rotation (type 3).
pub const SIG_ROTATION: SigLabel = s("licketysync/v1/sig/rotation");
/// Signature prefix of a Wrap (type 4).
pub const SIG_WRAP: SigLabel = s("licketysync/v1/sig/wrap");
/// Signature prefix of a Revocation (type 5).
pub const SIG_REVOCATION: SigLabel = s("licketysync/v1/sig/revocation");
/// Signature prefix of a Suspension (type 6).
pub const SIG_SUSPENSION: SigLabel = s("licketysync/v1/sig/suspension");
/// Signature prefix of a Lift (type 7).
pub const SIG_LIFT: SigLabel = s("licketysync/v1/sig/lift");
/// Signature prefix of a root rotation (type 8, reserved).
pub const SIG_ROOT_ROTATION: SigLabel = s("licketysync/v1/sig/root-rotation");
/// Signature prefix of an index record (type 16).
pub const SIG_INDEX: SigLabel = s("licketysync/v1/sig/index");
/// Signature prefix of the handshake's folder proof (`protocol.md` 3.5).
pub const SIG_FOLDER_PROOF: SigLabel = s("licketysync/v1/sig/folder-proof");
/// Signature prefix of the handshake's device proof (`protocol.md` 3.4).
pub const SIG_DEVICE_PROOF: SigLabel = s("licketysync/v1/sig/device-proof");

/// HPKE `info` of the data-key wrap (section 5.3).
pub const WRAP_DATA_KEY: WrapInfo = WrapInfo("licketysync/v1/wrap/data-key");

impl SigLabel {
    /// The registered signature label with this text, for callers whose
    /// interface carries labels as text (the protocol crate's signing and
    /// verifying traits). Only labels of the registry are returned, so no
    /// call site can sign under a label of its own invention.
    #[must_use]
    pub fn from_registered(text: &str) -> Option<SigLabel> {
        REGISTRY
            .iter()
            .find(|e| e.mode == Mode::SigPrefix && e.label == text)
            .map(|e| SigLabel(e.label))
    }
}

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
    entry!(IDENTITY_SEED, DeriveKey, "master secret"),
    entry!(IDENTITY_CATALOGUE_KEY, DeriveKey, "identity seed"),
    entry!(
        FOLDER_ROOT_SEED,
        DeriveKey,
        "master secret || folder nonce (64 bytes)"
    ),
    entry!(FOLDER_CHUNK_HASH_KEY, DeriveKey, "`dk_1`"),
    entry!(KEY_ED25519, DeriveKey, "any key seed"),
    entry!(KEY_ML_DSA_65, DeriveKey, "any key seed"),
    entry!(KEY_X_WING, DeriveKey, "any key seed"),
    entry!(KEY_LIBP2P_IDENTITY, DeriveKey, "device seed"),
    entry!(KEY_DHT_BEP44, DeriveKey, "device seed"),
    entry!(EPOCH_CHUNK_KEY, DeriveKey, "`dk_e`"),
    entry!(EPOCH_CHUNK_NONCE_KEY, DeriveKey, "`dk_e`"),
    entry!(EPOCH_RECORD_KEY, DeriveKey, "`dk_e`"),
    entry!(EPOCH_LADDER_KEY, DeriveKey, "`dk_e`"),
    entry!(EPOCH_CONFIRM, DeriveKey, "`dk_e`"),
    entry!(LINK_DISCOVERY, DeriveKey, "link secret"),
    entry!(LINK_CONFIRM, DeriveKey, "link secret"),
    entry!(
        HASH_ID_FOLDER,
        Hash,
        "be16(suite) || root signing public key"
    ),
    entry!(
        HASH_ID_DEVICE,
        Hash,
        "be16(suite) || device signing public key"
    ),
    entry!(
        HASH_ID_IDENTITY,
        Hash,
        "be16(suite) || identity signing public key"
    ),
    entry!(
        HASH_ID_KEY,
        Hash,
        "be16(suite) || issued signing public key || issued KEM public key"
    ),
    entry!(HASH_RECORD, Hash, "record body"),
    entry!(HASH_CHUNK, Hash, "stored chunk blob"),
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
    entry!(
        HANDSHAKE_FOLDER_HINT,
        Keyed,
        "label || 0x00 || transcript hash || role"
    ),
    entry!(
        HANDSHAKE_PROOF_KEY,
        Keyed,
        "label || 0x00 || transcript hash"
    ),
    entry!(SIG_FOLDER, SigPrefix, "record body"),
    entry!(SIG_GRANT, SigPrefix, "record body"),
    entry!(SIG_GRANT_POP, SigPrefix, "grant body"),
    entry!(SIG_ROTATION, SigPrefix, "record body"),
    entry!(SIG_WRAP, SigPrefix, "record body"),
    entry!(SIG_REVOCATION, SigPrefix, "record body"),
    entry!(SIG_SUSPENSION, SigPrefix, "record body"),
    entry!(SIG_LIFT, SigPrefix, "record body"),
    entry!(SIG_ROOT_ROTATION, SigPrefix, "record body"),
    entry!(SIG_INDEX, SigPrefix, "record body"),
    entry!(
        SIG_FOLDER_PROOF,
        SigPrefix,
        "folder ID || key ID || transcript hash || role"
    ),
    entry!(SIG_DEVICE_PROOF, SigPrefix, "transcript hash || role"),
    entry!(WRAP_DATA_KEY, HpkeInfo, "—"),
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
/// bytes of uniformly random key material: a seed, the master secret, a data
/// key, a link secret. Never public data and never a passphrase; the type
/// fixes the length.
#[must_use]
pub fn derive_key(label: DeriveLabel, material: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(label, material)
}

/// [`derive_key`] over 64 bytes of key material: the master secret followed
/// by the folder nonce, for the folder's root seed (section 1.2).
#[must_use]
pub fn derive_key_64(label: DeriveLabel, material: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    derive(label, material)
}

/// The derive-key hasher, wiped once the key is out: its state holds the
/// key material (SF 7).
fn derive(label: DeriveLabel, material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(label.0);
    hasher.update(material);
    let out = Zeroizing::new(*hasher.finalize().as_bytes());
    hasher.zeroize();
    out
}

/// Finishes a keyed hasher and wipes it: a keyed hasher's state holds its key.
fn finish_keyed(mut hasher: blake3::Hasher) -> [u8; 32] {
    let out = *hasher.finalize().as_bytes();
    hasher.zeroize();
    out
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

/// Keyed BLAKE3 with the label inside the input: `BLAKE3_keyed(key, label ||
/// 0x00 || parts...)`, the parts concatenated. Crate-private (quality review
/// NIT 3): other crates get [`folder_hint`] and
/// [`crate::secret::ProofKey::derive`], whose type zeroes the proof key when
/// dropped, and no other way to compute it.
#[must_use]
pub(crate) fn keyed_hash_labelled(key: &[u8; 32], label: KeyedLabel, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(label.0.as_bytes());
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    finish_keyed(hasher)
}

/// The handshake's folder hint (`protocol.md` 3.5): `BLAKE3_keyed(folder_id,
/// "licketysync/v1/handshake/folder-hint" || 0x00 || th || u8(role))`, for the
/// transcript hash `th` and the role byte of the side that proves (`0x01` for
/// A, `0x02` for B, `protocol.md` 3.2). It is public data: the associated data
/// of the sealed `FolderProof` and the value a verifier matches its folders
/// against.
#[must_use]
pub fn folder_hint(folder_id: &FolderId, th: &[u8; 32], role: u8) -> [u8; 32] {
    keyed_hash_labelled(folder_id.as_bytes(), HANDSHAKE_FOLDER_HINT, &[th, &[role]])
}

/// Keyed BLAKE3 under a key that was itself derived under a label (`hk`, `nk_e`,
/// the link-confirm key): no label in the input.
#[must_use]
pub(crate) fn keyed_hash(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(part);
    }
    finish_keyed(hasher)
}

/// The bytes both halves of a hybrid signature sign: `M = label || 0x00 ||
/// body` (`suites.md` 2.2).
#[must_use]
pub fn signed_message(label: SigLabel, body: &[u8]) -> Vec<u8> {
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
    /// bytes: the primitive under the three helpers this module wraps.
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
        assert_eq!(REGISTRY.len(), 41);
    }

    #[test]
    fn sig_labels_resolve_only_when_registered() {
        assert_eq!(
            SigLabel::from_registered("licketysync/v1/sig/device-proof"),
            Some(SIG_DEVICE_PROOF)
        );
        assert_eq!(
            SigLabel::from_registered("licketysync/v1/sig/grant-pop"),
            Some(SIG_GRANT_POP)
        );
        assert_eq!(
            SigLabel::from_registered("licketysync/v1/hash/record"),
            None,
            "not a signature label"
        );
        assert_eq!(
            SigLabel::from_registered("licketysync/v1/sig/anything"),
            None
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

    /// `suites.md` 3.2: the phrase's word list is the BIP39 English list the
    /// `bip39` crate embeds, pinned by its BLAKE3 hash in the form of
    /// BIP39's `english.txt` (one word per line, a final line ending), so a
    /// change to the list in a dependency update fails here.
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
        let a = keyed_hash_labelled(&key, HANDSHAKE_FOLDER_HINT, &[b"x", b"y"]);
        let b = blake3::keyed_hash(&key, b"licketysync/v1/handshake/folder-hint\0xy");
        assert_eq!(a, *b.as_bytes());
        assert_ne!(a, keyed_hash_labelled(&key, HANDSHAKE_PROOF_KEY, &[b"xy"]));
        let th = [4u8; 32];
        let folder = FolderId(key);
        let hint = folder_hint(&folder, &th, 0x01);
        assert_eq!(
            hint,
            *blake3::keyed_hash(
                &key,
                &[
                    b"licketysync/v1/handshake/folder-hint\0".as_slice(),
                    &th,
                    &[0x01]
                ]
                .concat()
            )
            .as_bytes()
        );
        assert_eq!(
            hint,
            keyed_hash_labelled(&key, HANDSHAKE_FOLDER_HINT, &[&th, &[0x01]])
        );
        assert_ne!(hint, folder_hint(&folder, &th, 0x02), "the role is bound");
        assert_ne!(hint, folder_hint(&folder, &[5; 32], 0x01), "so is th");
        assert_ne!(
            hint,
            folder_hint(&FolderId([8; 32]), &th, 0x01),
            "and the folder"
        );
        let proof_key = crate::secret::ProofKey::derive(&folder, &th);
        assert_eq!(
            proof_key.expose(),
            blake3::keyed_hash(
                &key,
                &[b"licketysync/v1/handshake/proof-key\0".as_slice(), &th].concat()
            )
            .as_bytes()
        );
        assert_eq!(
            keyed_hash(&key, &[b"x", b"y"]),
            *blake3::keyed_hash(&key, b"xy").as_bytes()
        );
        assert_eq!(
            signed_message(SIG_GRANT, b"body"),
            b"licketysync/v1/sig/grant\0body"
        );
        assert_eq!(
            &*derive_key(KEY_ED25519, &[1u8; 32]),
            &blake3::derive_key("licketysync/v1/key/ed25519", &[1u8; 32])
        );
        assert_eq!(KEY_ED25519.as_str(), "licketysync/v1/key/ed25519");
        assert_eq!(HASH_CHUNK.as_str(), "licketysync/v1/hash/chunk");
        assert_eq!(
            HANDSHAKE_PROOF_KEY.as_str(),
            "licketysync/v1/handshake/proof-key"
        );
        assert_eq!(SIG_INDEX.as_str(), "licketysync/v1/sig/index");
        assert_eq!(WRAP_DATA_KEY.as_str(), "licketysync/v1/wrap/data-key");
    }
}
