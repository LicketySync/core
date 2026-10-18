// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The test vectors of `keys.md` section 9 and `suites.md` section 4.4.
//!
//! Each `vector_*` test computes its vectors with this crate and compares
//! them with the committed data file under `tests/vectors/`; a change of one
//! bit in any output fails the test that names it. Every registered label has
//! its own test, named after the label. To regenerate the files after a
//! reviewed change of format, run
//! `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-keys vector_`
//! and review the diff. Signatures use the deterministic ML-DSA variant and
//! every random input is a fixed byte, so the files reproduce exactly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names,
    reason = "test code: short key names mirror the spec's examples"
)]

use serde_json::{json, Value};

use crate::chunk::{self, open_chunk, padme, seal_chunk, ChunkKeys, PlainHash, MAX_STORED_LEN};
use crate::derive::{self, DhtKey, FolderNonce, Libp2pIdentity};
use crate::discovery;
use crate::epoch::LadderLink;
use crate::ids::{DeviceId, FolderId, KeyId, RecordHash};
use crate::keyset::KeyPairSet;
use crate::keystring::{bech32m_encode, KeyString, Link};
use crate::labels::{
    self, derive_key, keyed_hash_labelled, labelled_hash, signed_message, REGISTRY,
};
use crate::linking;
use crate::phrase::{Phrase, PhraseError};
use crate::records::folder::tests::fixed_rng;
use crate::records::store_tests::{id, resigned, root_set, set, world, World, NOW};
use crate::records::{
    wire, ActingTier, Cutoff, EffectiveTier, GrantBody, RecordType, RotationBody, SignedRecord,
};
use crate::secret::{DataKey, LinkSecret, MasterSecret, Seed};
use crate::suite::{Suite, Tier};
use crate::wrap::{unwrap_data_key, wrap_data_key, WrapAad};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");

fn regenerating() -> bool {
    std::env::var_os("LICKETYSYNC_REGENERATE_VECTORS").is_some()
}

fn h(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn fixed32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

fn dbg<T: core::fmt::Debug>(v: &T) -> Value {
    Value::String(format!("{v:?}"))
}

fn record(r: &SignedRecord) -> Value {
    json!({ "body": h(&r.body), "signature": h(&r.signature), "key_signature": h(&r.key_signature), "record_hash": h(&r.hash().0) })
}

/// Compares `generated` with the committed `name.json`, or writes it when
/// regenerating.
fn check(name: &str, generated: &Value) {
    let path = format!("{DIR}{name}.json");
    if regenerating() {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(generated).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}; regenerate the vectors"));
    let committed: Value = serde_json::from_str(&text).unwrap();
    if let (Some(a), Some(b)) = (committed.as_object(), generated.as_object()) {
        for key in a.keys().chain(b.keys()) {
            assert_eq!(a.get(key), b.get(key), "{name}.json: entry {key:?} changed");
        }
    }
    assert_eq!(&committed, generated, "{name}.json changed");
}

fn seed_set(start: u8) -> (Seed, KeyPairSet) {
    let seed = Seed::from_bytes(fixed32(start));
    let set = KeyPairSet::from_seed(&seed).unwrap();
    (seed, set)
}

/// Section 9 item 1.
#[test]
fn vector_phrase() {
    let ms = MasterSecret::from_bytes(fixed32(0x00));
    let phrase = Phrase::from_master(&ms).unwrap();
    let text = phrase.to_text().to_string();
    let words: Vec<&str> = text.split(' ').collect();
    let list = bip39::Language::English.word_list();
    let last = list.iter().position(|w| *w == words[23]).unwrap();
    let mut bad_checksum = words.clone();
    bad_checksum[23] = list[(last + 1) % 2048];
    let mut unknown = words.clone();
    unknown[5] = "notaword";
    let rejected: Vec<Value> = [
        ("bad checksum", bad_checksum.join(" ")),
        ("23 words", words[..23].join(" ")),
        ("word not in the list", unknown.join(" ")),
    ]
    .iter()
    .map(|(name, p)| json!({ "name": name, "phrase": p, "error": dbg(&Phrase::parse(p).err()) }))
    .collect();
    assert_eq!(
        Phrase::parse(&bad_checksum.join(" ")).err(),
        Some(PhraseError::Checksum)
    );
    assert!(bool::from(
        Phrase::parse(&text).unwrap().master_secret().ct_eq(&ms)
    ));
    check(
        "phrase",
        &json!({ "master_secret": h(ms.expose()), "words": text, "rejected": rejected }),
    );
}

/// Section 9 item 2.
#[test]
fn vector_master_derivations() {
    let ms = MasterSecret::from_bytes(fixed32(0x00));
    let identity_seed = derive::identity_seed(&ms);
    let identity = KeyPairSet::from_seed(&identity_seed).unwrap();
    let nonce = FolderNonce(fixed32(0x40));
    let root_seed = derive::root_seed(&ms, &nonce);
    let root = KeyPairSet::from_seed(&root_seed).unwrap();
    check(
        "master",
        &json!({
            "master_secret": h(ms.expose()),
            "identity_seed": h(identity_seed.expose()),
            "identity_signing_pk": h(identity.public().signing.as_bytes()),
            "identity_kem_pk": h(identity.public().kem.as_bytes()),
            "identity_id": h(&derive::identity_id(Suite::ONE, &identity.public().signing).0),
            "catalogue_key": h(derive::catalogue_key(&identity_seed).expose()),
            "folder_nonce": h(&nonce.0),
            "root_seed": h(root_seed.expose()),
            "root_signing_pk": h(root.public().signing.as_bytes()),
            "root_kem_pk": h(root.public().kem.as_bytes()),
            "folder_id": h(&derive::folder_id(Suite::ONE, &root.public().signing).0),
        }),
    );
}

/// Section 9 item 3, and `suites.md` 4.4's encodings: the public keys, the
/// derived key ID, the Hello wire form and a full hybrid signature.
#[test]
fn vector_key_pair_set() {
    let (seed, set) = seed_set(0x80);
    let pk = set.public();
    let body = b"licketysync test vector body";
    let sig = set.sign_deterministic(labels::SIG_GRANT, body).unwrap();
    assert!(pk.signing.verify(labels::SIG_GRANT, body, &sig).is_ok());
    check(
        "key_pair_set",
        &json!({
            "seed": h(seed.expose()),
            "ed25519_seed": h(&*derive_key(labels::KEY_ED25519, seed.expose())),
            "ml_dsa_65_xi": h(&*derive_key(labels::KEY_ML_DSA_65, seed.expose())),
            "x_wing_seed": h(&*derive_key(labels::KEY_X_WING, seed.expose())),
            "ed25519_pk": h(&pk.signing.as_bytes()[..32]),
            "ml_dsa_65_pk": h(&pk.signing.as_bytes()[32..]),
            "x_wing_pk": h(pk.kem.as_bytes()),
            "key_id": h(&pk.key_id(Suite::ONE).0),
            "key_id_if_only_signing_pk_were_hashed": h(&labelled_hash(labels::HASH_ID_KEY, &[&Suite::ONE.be16(), pk.signing.as_bytes()])[..16]),
            "hello_public_key": h(&pk.signing.wire_form(Suite::ONE)),
            "signed_body": h(body),
            "signature_label": labels::SIG_GRANT.as_str(),
            "hybrid_signature": h(sig.as_bytes()),
        }),
    );
}

/// Base58btc, for the libp2p peer ID's text form.
fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u32> = Vec::new();
    for &b in bytes {
        let mut carry = u32::from(b);
        for d in &mut digits {
            carry += *d << 8;
            *d = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut s = "1".repeat(zeros);
    s.extend(
        digits
            .iter()
            .rev()
            .map(|d| char::from(ALPHABET[usize::try_from(*d).unwrap()])),
    );
    s
}

/// Section 9 item 4. The peer ID is the identity multihash of the protobuf
/// encoding of the Ed25519 public key (libp2p peer-ids specification); the
/// `net` crate's test checks it against `libp2p-identity` when that lands.
#[test]
fn vector_device() {
    let (seed, set) = seed_set(0xa0);
    let identity = Libp2pIdentity::from_device_seed(&seed);
    let dht = DhtKey::from_device_seed(&seed);
    let mut peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    peer_id.extend_from_slice(&identity.public_key());
    let text = base58(&peer_id);
    assert!(text.starts_with("12D3KooW"), "{text}");
    let item = b"bep44 test item";
    check(
        "device",
        &json!({
            "device_seed": h(seed.expose()),
            "device_id": h(&derive::device_id(Suite::ONE, &set.public().signing).0),
            "libp2p_identity_seed": h(&*identity.expose_seed()),
            "libp2p_identity_pk": h(&identity.public_key()),
            "libp2p_peer_id": h(&peer_id),
            "libp2p_peer_id_text": text,
            "dht_pk": h(&dht.public_key()),
            "dht_signed_item": h(item),
            "dht_signature": h(&dht.sign_bep44(item)),
        }),
    );
}

/// Section 9 item 5.
#[test]
fn vector_discovery() {
    let salt: [u8; 16] = core::array::from_fn(|i| 0x51 + u8::try_from(i).unwrap());
    let folder = FolderId(fixed32(0xc0));
    let announcer = Libp2pIdentity::from_device_seed(&Seed::from_bytes(fixed32(0xa0))).public_key();
    let other = Libp2pIdentity::from_device_seed(&Seed::from_bytes(fixed32(0xb0))).public_key();
    let now = 1_800_000_000u64;
    let minute = discovery::unix_minute(now);
    let tag = discovery::peer_tag(&salt, &announcer);
    assert_ne!(
        discovery::peer_tag(&salt, &other),
        tag,
        "a peer tag that does not match the authenticated identity is refused"
    );
    assert!(
        discovery::minute_in_window(minute, minute + 5)
            && discovery::minute_in_window(minute, minute - 5)
    );
    assert!(
        !discovery::minute_in_window(minute, minute + 6)
            && !discovery::minute_in_window(minute, minute - 6)
    );
    let day = discovery::unix_day(now);
    let ids = discovery::dht_lookup_ids(&folder, day);
    check(
        "discovery",
        &json!({
            "salt": h(&salt),
            "folder_id": h(&folder.0),
            "announcer_libp2p_pk": h(&announcer),
            "unix_seconds": now,
            "minute": minute,
            "peer_tag": h(&tag),
            "lan_id": h(&discovery::lan_id(&salt, &folder, &tag, minute)),
            "window": { "accepted": [minute - 5, minute + 5], "refused": [minute - 6, minute + 6] },
            "mismatched_identity": h(&other),
            "mismatched_peer_tag": h(&discovery::peer_tag(&salt, &other)),
            "day": day,
            "dht_id_yesterday": h(&ids[0]),
            "dht_id_today": h(&ids[1]),
            "dht_id_tomorrow": h(&ids[2]),
            "link_secret": h(&fixed32(0xd0)),
            "link_beacon_id": h(&linking::link_beacon_id(&LinkSecret::from_bytes(fixed32(0xd0)))),
        }),
    );
}

fn epoch_keys(dk: &DataKey) -> Value {
    json!({
        "data_key": h(dk.expose()),
        "chunk_key": h(dk.chunk_key().expose()),
        "chunk_nonce_key": h(dk.chunk_nonce_key().expose()),
        "record_key": h(dk.record_key().expose()),
        "ladder_key": h(dk.ladder_key().expose()),
        "confirm": h(&dk.confirm().0),
    })
}

/// Section 9 item 6.
#[test]
fn vector_epoch_keys() {
    let folder = FolderId(fixed32(0xc0));
    let dk1 = DataKey::from_bytes(fixed32(0x11));
    let dk2 = DataKey::from_bytes(fixed32(0x22));
    let link = LadderLink::seal(&dk2, 2, &folder, &dk1, &mut fixed_rng(0x5a)).unwrap();
    assert!(bool::from(link.open(&dk2, 2, &folder).unwrap().ct_eq(&dk1)));
    check(
        "epoch",
        &json!({
            "folder_id": h(&folder.0),
            "epoch_1": epoch_keys(&dk1),
            "epoch_2": epoch_keys(&dk2),
            "chunk_hash_key": h(dk1.chunk_hash_key().expose()),
            "ladder_2": { "nonce_byte": 0x5a, "link": h(link.as_bytes()), "recovers": h(dk1.expose()) },
        }),
    );
}

/// Section 9 item 7.
#[test]
fn vector_chunk() {
    let folder = FolderId(fixed32(0xc0));
    let dk1 = DataKey::from_bytes(fixed32(0x11));
    let keys = ChunkKeys::new(&dk1, &folder, 1);
    let hk = dk1.chunk_hash_key();
    let raw: Vec<u8> = (0..300u32)
        .map(|i| u8::try_from(i * 7 % 256).unwrap())
        .collect();
    let sealed = seal_chunk(&keys, &raw).unwrap();
    let plain = PlainHash::of(&hk, &raw);
    assert_eq!(
        &*open_chunk(&keys, &hk, &sealed.stored, &plain).unwrap(),
        &raw[..]
    );
    let mut bad_tag = sealed.stored.clone();
    *bad_tag.last_mut().unwrap() ^= 1;
    let forged = |pt: &[u8]| chunk::seal_plaintext_for_test(&keys, pt);
    let variants: Vec<(&str, Vec<u8>, PlainHash)> = vec![
        ("bad tag", bad_tag, plain),
        (
            "non-zero padding",
            forged(&[0, 0, 0, 0, 3, 1, 2, 3, 0, 1]),
            plain,
        ),
        (
            "payload length over L' - 5",
            forged(&[0, 0, 0, 0, 6, 1, 2, 3, 0, 0]),
            plain,
        ),
        ("empty payload", forged(&[0; 10]), plain),
        (
            "unsupported compression code",
            forged(&[2, 0, 0, 0, 3, 1, 2, 3, 0, 0]),
            plain,
        ),
        ("stored length not a Padme length", vec![0; 49], plain),
        (
            "bad plain hash",
            sealed.stored.clone(),
            PlainHash::of(&hk, b"another chunk"),
        ),
    ];
    let mut corrupt: Vec<Value> = variants
        .iter()
        .map(|(name, stored, expected)| {
            json!({ "name": name, "stored": h(stored), "expected_plain_hash": h(&expected.0), "error": dbg(&open_chunk(&keys, &hk, stored, expected).err()) })
        })
        .collect();
    let over = vec![0u8; MAX_STORED_LEN + 1];
    corrupt.push(json!({ "name": "stored length over the bound", "stored_len": over.len(), "error": dbg(&open_chunk(&keys, &hk, &over, &plain).err()) }));
    check(
        "chunk",
        &json!({
            "folder_id": h(&folder.0),
            "epoch": 1,
            "data_key": h(dk1.expose()),
            "raw": h(&raw),
            "plain_hash": h(&plain.0),
            "padded_length": padme(305).unwrap(),
            "nonce": h(&sealed.stored[..24]),
            "stored": h(&sealed.stored),
            "cipher_hash": h(&sealed.cipher_hash.0),
            "corrupt": corrupt,
        }),
    );
}

/// An independent Padmé: the highest set bit and its bit length by loops,
/// rounding up by division.
fn padme_reference(l: u64) -> u64 {
    if l < 2 {
        return l;
    }
    let mut e = 0u32;
    while (l >> (e + 1)) != 0 {
        e += 1;
    }
    let mut s = 0u32;
    while (e >> s) != 0 {
        s += 1;
    }
    let step = 1u64 << (e - s);
    l.div_ceil(step) * step
}

/// Section 9 item 8.
#[test]
fn vector_padme() {
    let examples: Vec<[u64; 2]> = [5u64, 9, 100, 1000, 65_537, 1_048_577]
        .iter()
        .map(|l| [*l, padme(*l).unwrap_or(0)])
        .collect();
    assert_eq!(
        examples.iter().map(|p| p[1]).collect::<Vec<_>>(),
        vec![5, 10, 104, 1024, 67_584, 1_081_344]
    );
    // SplitMix64, seeded: 1000 lengths spread over 1 byte to 2^40.
    let mut state = 0x6c69_636b_6574_7973u64;
    let mut next = || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let random: Vec<[u64; 2]> = (0..1000)
        .map(|_| {
            let bits = next() % 40 + 1;
            let l = next() % (1u64 << bits) + 1;
            assert_eq!(padme(l), Some(padme_reference(l)), "padme({l})");
            [l, padme(l).unwrap_or(0)]
        })
        .collect();
    check("padme", &json!({ "examples": examples, "random": random }));
}

fn genesis_inputs() -> Value {
    json!({ "master_secret": h(&[1; 32]), "folder_nonce": h(&[3; 32]), "data_key": h(&[2; 32]), "created_at": 1_700_000_000u64, "hpke_randomness_byte": 3 })
}

/// Section 9 item 9.
#[test]
fn vector_folder_record() {
    let mut w = world();
    let dk = w.keys.unwrap_root_data_key(w.root()).unwrap();
    assert!(bool::from(dk.ct_eq(&w.dk1)));
    let mut second = w.folder.body.clone();
    second.created_at += 1;
    let second = w.sign(w.root(), RecordType::Folder, second.encode());
    check(
        "folder",
        &json!({
            "inputs": genesis_inputs(),
            "record": record(&w.folder.record),
            "folder_id": h(&w.folder_id().0),
            "confirm": h(&w.folder.body.confirm.0),
            "root_wrap_unwraps_to": h(dk.expose()),
            "second_record": record(&second),
            "second_record_outcome": dbg(&w.keys.insert(&second, NOW)),
            "other_folders_record": record(&crate::records::folder::tests::new_folder(9).0.record),
            "other_folders_record_outcome": dbg(&w.keys.insert(&crate::records::folder::tests::new_folder(9).0.record, NOW)),
        }),
    );
}

/// A grant changed by `change`, with its holder's proof of possession redone
/// so that the change, not the proof, is what verification judges.
fn mutated(
    base: &SignedRecord,
    holder: &KeyPairSet,
    signer: &KeyPairSet,
    change: impl FnOnce(&mut wire::Grant),
) -> SignedRecord {
    resigned(base, holder, signer, change)
}

/// `base`'s body with `extra` bytes appended, signed again by both keys: a
/// body prost would accept and this crate must refuse.
fn appended(
    base: &SignedRecord,
    holder: &KeyPairSet,
    signer: &KeyPairSet,
    extra: &[u8],
) -> SignedRecord {
    let mut body = base.body.clone();
    body.extend_from_slice(extra);
    SignedRecord {
        key_signature: holder
            .sign_deterministic(labels::SIG_GRANT_POP, &body)
            .unwrap()
            .as_bytes()
            .to_vec(),
        signature: signer
            .sign_deterministic(labels::SIG_GRANT, &body)
            .unwrap()
            .as_bytes()
            .to_vec(),
        body,
    }
}

/// Vector helpers on the test world, as methods so that a record built from
/// the world can be passed straight back to it.
trait Cases {
    fn case(&mut self, name: &str, r: &SignedRecord) -> Value;
}

impl Cases for World {
    fn case(&mut self, name: &str, r: &SignedRecord) -> Value {
        json!({ "name": name, "record": record(r), "outcome": dbg(&self.keys.insert(r, NOW)) })
    }
}

/// Section 9 item 10: one grant per tier from root, one from a `may_share`
/// write key, and a rejected variant for every numbered step of 5.4.
#[test]
fn vector_grants() {
    let mut w = world();
    let (a_seed, a) = seed_set(0x61);
    let (r_seed, r) = seed_set(0x62);
    let (s_seed, s) = seed_set(0x63);
    let (wk_seed, wk) = seed_set(0x64);
    let ga = w.root_grant(&a, Tier::Write, true);
    let gr = w.root_grant(&r, Tier::Read, false);
    let gs = w.root_grant(&s, Tier::Sealed, false);
    let gw = w.grant_from(&a, id(&a), &wk, Tier::Write, false, 0);
    let mut stored = Vec::new();
    for (name, seed, key, g) in [
        ("write from root", &a_seed, &a, &ga),
        ("read from root", &r_seed, &r, &gr),
        ("sealed from root", &s_seed, &s, &gs),
        ("write from a may_share write key", &wk_seed, &wk, &gw),
    ] {
        w.add(g);
        let body = GrantBody::parse(&g.body).unwrap();
        let unwrapped = w
            .keys
            .unwrap_grant_data_key(&g.hash(), key)
            .map(|(_, dk)| hex::encode(dk.expose()));
        stored.push(json!({ "name": name, "seed": h(seed.expose()), "key_id": h(&body.key_id.0), "record": record(g), "unwraps_to": dbg(&unwrapped) }));
    }
    let root = root_set();
    let n = set(0x70);
    let rm = set(0x71);
    w.add(&w.root_grant(&n, Tier::Write, false));
    w.add(&w.root_grant(&rm, Tier::Read, true));
    let child = set(0x72);
    // A grant not yet stored, for the proof-of-possession cases (a stored body is a duplicate, ignored).
    let fresh_key = set(0x79);
    let fresh = w.root_grant(&fresh_key, Tier::Read, false);
    let mut rejected = vec![
        w.case(
            "wrong size",
            &mutated(&gr, &r, &root, |g| g.kem_pk.truncate(1215)),
        ),
        w.case(
            "missing key_signature",
            &SignedRecord {
                key_signature: Vec::new(),
                ..fresh.clone()
            },
        ),
        w.case(
            "key_signature made by another key",
            &SignedRecord {
                key_signature: child
                    .sign_deterministic(labels::SIG_GRANT_POP, &fresh.body)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                ..fresh.clone()
            },
        ),
        w.case(
            "key_signature over another body",
            &SignedRecord {
                key_signature: fresh_key
                    .sign_deterministic(labels::SIG_GRANT_POP, &ga.body)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                ..fresh.clone()
            },
        ),
        w.case(
            "kem_pk alone swapped",
            &mutated(&gr, &r, &root, |g| {
                g.kem_pk = s.public().kem.as_bytes().to_vec();
            }),
        ),
        w.case(
            "a non-grant record carrying a key_signature",
            &SignedRecord {
                key_signature: gr.key_signature.clone(),
                ..w.revocation(&root, KeyId::ROOT, id(&a), vec![])
            },
        ),
        w.case(
            "folder ID of another folder",
            &mutated(&gr, &r, &root, |g| g.folder_id = vec![0x5f; 32]),
        ),
        // Only suite 1 exists, so "below minimum_suite" cannot be built; an unimplemented suite stands in.
        w.case(
            "suite this release does not implement",
            &mutated(&gr, &r, &root, |g| g.suite = 2),
        ),
        w.case(
            "epoch beyond the current one",
            &mutated(&gr, &r, &root, |g| g.epoch = 2),
        ),
        w.case(
            "key_id that does not recompute",
            &mutated(&gr, &r, &root, |g| g.key_id[0] ^= 1),
        ),
        w.case(
            "all-zero key_id",
            &mutated(&gr, &r, &root, |g| g.key_id = vec![0; 16]),
        ),
        w.case(
            "issuer lacking may_share",
            &w.grant_from(&n, id(&n), &child, Tier::Read, false, 0),
        ),
        w.case(
            "issuer tier too low",
            &w.grant_from(&rm, id(&rm), &child, Tier::Write, false, 0),
        ),
        w.case(
            "sealed grant with a wrap",
            &mutated(&gr, &r, &root, |g| g.tier = 3),
        ),
        w.case(
            "write grant without one",
            &mutated(&ga, &a, &root, |g| g.wrapped_data_key.clear()),
        ),
        // Ruling 16: a singular field twice (tier 2, then tier 1), and a
        // uint32 tier whose varint is 2^32 + 1 (prost would read it as 1).
        w.case(
            "a body that repeats the singular tier field",
            &appended(&fresh, &fresh_key, &root, &[0x28, 0x01]),
        ),
        w.case(
            "a uint32 tier past 32 bits",
            &appended(
                &mutated(&fresh, &fresh_key, &root, |g| g.tier = 0),
                &fresh_key,
                &root,
                &[0x28, 0x81, 0x80, 0x80, 0x80, 0x10],
            ),
        ),
    ];
    let mut bad_sig = w.root_grant(&child, Tier::Read, false);
    bad_sig.signature = a
        .sign_deterministic(labels::SIG_GRANT, &bad_sig.body)
        .unwrap()
        .as_bytes()
        .to_vec();
    rejected.push(w.case("bad signature", &bad_sig));
    let mut bad_sig_bad_tier = w.grant_from(&rm, id(&rm), &child, Tier::Write, false, 0);
    bad_sig_bad_tier.signature = a
        .sign_deterministic(labels::SIG_GRANT, &bad_sig_bad_tier.body)
        .unwrap()
        .as_bytes()
        .to_vec();
    rejected.push(w.case(
        "bad signature that would also be a tier fault: the signature is judged first",
        &bad_sig_bad_tier,
    ));
    // A chain of 16, and a 17th.
    let mut issuer = root_set();
    let mut issuer_id = KeyId::ROOT;
    let mut chain = Vec::new();
    for i in 0..16u8 {
        let next = set(0x90 + i);
        let g = w.grant_from(&issuer, issuer_id, &next, Tier::Write, true, 0);
        w.add(&g);
        chain.push(record(&g));
        issuer_id = id(&next);
        issuer = next;
    }
    let deep = w.grant_from(&issuer, issuer_id, &set(0xb0), Tier::Read, false, 0);
    let deep_outcome = dbg(&w.keys.insert(&deep, NOW));
    let deep_valid = w.keys.validity(NOW).is_grant_valid(&deep.hash());
    assert!(!deep_valid);
    let sixteenth_valid = w.keys.validity(NOW).is_chain_valid(&issuer_id);
    assert!(sixteenth_valid);
    rejected.push(json!({ "name": "a chain of exactly 16 is chain-valid; the 17th grant is stored and is not", "chain": chain, "chain_of_16_valid": sixteenth_valid, "record": record(&deep), "outcome": deep_outcome, "chain_valid": deep_valid }));
    rejected.push(w.case(
        "self-issued grant",
        &w.grant_from(&a, id(&a), &a, Tier::Write, false, 0),
    ));
    // Beneath a known revocation: stored with an issue (ruling 20).
    let rev = w.revocation(&root, KeyId::ROOT, id(&rm), vec![]);
    w.add(&rev);
    let beneath = w.grant_from(&rm, id(&rm), &child, Tier::Read, false, 0);
    rejected.push(json!({ "name": "grant beneath a known revocation: stored and forwarded with an issue (ruling 20)", "revocation": record(&rev), "record": record(&beneath), "outcome": dbg(&w.keys.insert(&beneath, NOW)) }));
    // A second grant for one key at another tier.
    let gr2 = w.root_grant(&r, Tier::Write, false);
    let second = json!({ "record": record(&gr2), "outcome": dbg(&w.keys.insert(&gr2, NOW)), "governing": h(&w.keys.validity(NOW).governing_grant(&id(&r)).unwrap().0 .0) });
    // A tie between two grants equal in tier, may_share and expiry: the smaller record hash governs.
    let (t, tie_a) = (set(0x73), w.root_grant(&set(0x73), Tier::Read, false));
    let tie_b = mutated(&tie_a, &t, &root, |g| g.issued_at = 8);
    w.add(&tie_a);
    w.add(&tie_b);
    let tie = json!({ "a": record(&tie_a), "b": record(&tie_b), "governing": h(&w.keys.validity(NOW).governing_grant(&id(&t)).unwrap().0 .0) });
    // A descendant re-grant: A issues B, B issues a further grant to A.
    let (da, db) = (set(0x74), set(0x75));
    w.add(&w.root_grant(&da, Tier::Write, true));
    w.add(&w.grant_from(&da, id(&da), &db, Tier::Write, true, 0));
    let regrant = w.grant_from(&db, id(&db), &da, Tier::Write, true, 0);
    let regrant_outcome = dbg(&w.keys.insert(&regrant, NOW));
    let v = w.keys.validity(NOW);
    let descendant = json!({
        "record": record(&regrant),
        "outcome": regrant_outcome,
        "begins_a_chain": v.is_grant_valid(&regrant.hash()),
        "governing": h(&v.governing_grant(&id(&da)).unwrap().0 .0),
    });
    assert!(!v.is_grant_valid(&regrant.hash()));
    // A key on two chains survives the revocation of a key on one.
    let (x, two) = (set(0x76), set(0x77));
    w.add(&w.root_grant(&x, Tier::Write, true));
    let via_root = w.root_grant(&two, Tier::Read, false);
    let via_x = w.grant_from(&x, id(&x), &two, Tier::Write, false, 0);
    w.add(&via_root);
    w.add(&via_x);
    let rev_x = w.revocation(&root, KeyId::ROOT, id(&x), vec![]);
    w.add(&rev_x);
    // Phases 0 to 6 store the Revocation without applying it (ruling 21);
    // phase 7 will apply it, leaving the key on its other chain.
    let v = w.keys.validity(NOW);
    let v7 = w.keys.validity_applying_phase_7(NOW);
    let two_chains = json!({
        "grants": [record(&via_root), record(&via_x)],
        "revocation": record(&rev_x),
        "chain_valid": v.is_chain_valid(&id(&two)),
        "governing": h(&v.governing_grant(&id(&two)).unwrap().0 .0),
        "phase_7": {
            "chain_valid": v7.is_chain_valid(&id(&two)),
            "governing": h(&v7.governing_grant(&id(&two)).unwrap().0 .0),
        },
    });
    assert!(v.is_chain_valid(&id(&two)) && v7.is_chain_valid(&id(&two)));
    // Ruling 17: a key issued at write under its issuer's temporary write
    // grant presents at write until that grant expires, and not after: the
    // issuer's permanent read grant cannot authorize a write link.
    let (ti, tk) = (set(0x7a), set(0x7b));
    let temp = w.grant_from(&root, KeyId::ROOT, &ti, Tier::Write, true, NOW + 100);
    let perm = w.root_grant(&ti, Tier::Read, false);
    w.add(&temp);
    w.add(&perm);
    let gtk = w.grant_from(&ti, id(&ti), &tk, Tier::Write, false, 0);
    w.add(&gtk);
    let before = w.keys.validity(NOW);
    let after = w.keys.validity(NOW + 100);
    let temporary_raise = json!({
        "issuer_grants": [record(&temp), record(&perm)],
        "record": record(&gtk),
        "now": NOW,
        "expiry": NOW + 100,
        "before": { "presentable_tier": dbg(&before.presentable_tier(&id(&tk))), "issuer_may_issue_write": before.may_issue(&id(&ti), Tier::Write) },
        "after": { "presentable_tier": dbg(&after.presentable_tier(&id(&tk))), "chain_valid": after.is_chain_valid(&id(&tk)), "effective_tier": dbg(&after.effective_tier(&id(&tk))), "issuer_may_issue_write": after.may_issue(&id(&ti), Tier::Write) },
    });
    assert!(before.is_presentable(&id(&tk)) && !after.is_presentable(&id(&tk)));
    // A key whose canonical chain holds an expired grant presents through
    // another, unexpired chain at that chain's lower tier, while its index
    // records are judged under the governing grant.
    let (ek, ey) = (set(0x7c), set(0x7d));
    let short = w.grant_from(&root, KeyId::ROOT, &ek, Tier::Write, false, NOW + 100);
    let gey = w.root_grant(&ey, Tier::Read, true);
    let long = w.grant_from(&ey, id(&ey), &ek, Tier::Read, false, 0);
    for g in [&short, &gey, &long] {
        w.add(g);
    }
    let later = w.keys.validity(NOW + 100);
    let chain_hashes =
        |c: Vec<(&RecordHash, &GrantBody)>| c.iter().map(|(x, _)| h(&x.0)).collect::<Vec<_>>();
    let expired_canonical = json!({
        "grants": [record(&short), record(&gey), record(&long)],
        "now": NOW + 100,
        "canonical_chain": chain_hashes(later.canonical_chain(&id(&ek))),
        "governing": h(&later.governing_grant(&id(&ek)).unwrap().0 .0),
        "effective_tier": dbg(&later.effective_tier(&id(&ek))),
        "presentable_tier": dbg(&later.presentable_tier(&id(&ek))),
        "presentable_chain": chain_hashes(later.presentable_chain(&id(&ek))),
    });
    assert_eq!(later.presentable_tier(&id(&ek)), EffectiveTier::Read);
    assert_eq!(later.effective_tier(&id(&ek)), EffectiveTier::Write);
    // Two equally short chains: the canonical one is the smaller by record
    // hashes read from the key; the ancestors are every key on an
    // authorizing walk to root (ruling 18), both issuers here.
    let (c1, c2, ck) = (set(0x7e), set(0x7f), set(0x80));
    let gc1 = w.root_grant(&c1, Tier::Write, true);
    let gc2 = w.root_grant(&c2, Tier::Write, true);
    let k1 = w.grant_from(&c1, id(&c1), &ck, Tier::Read, false, 0);
    let k2 = w.grant_from(&c2, id(&c2), &ck, Tier::Read, false, 0);
    for g in [&gc1, &gc2, &k1, &k2] {
        w.add(g);
    }
    let v = w.keys.validity(NOW);
    let ancestors: Vec<Value> = v.ancestors(&id(&ck)).iter().map(|k| h(&k.0)).collect();
    let equal_chains = json!({
        "grants": [record(&gc1), record(&gc2), record(&k1), record(&k2)],
        "canonical_chain": chain_hashes(v.canonical_chain(&id(&ck))),
        "ancestors": ancestors,
    });
    assert_eq!(v.ancestors(&id(&ck)).len(), 2);
    // A wrap that opens to a key failing epoch 1's confirmation (a signer fault the holder finds).
    let (bad_holder, wrong_dk) = (set(0x78), DataKey::from_bytes(fixed32(0xee)));
    let request = crate::records::GrantRequest {
        folder_id: w.folder_id(),
        recipient: &bad_holder,
        tier: Tier::Read,
        may_share: false,
        expires_at: 0,
        epoch: 1,
        data_key: Some(&wrong_dk),
        issued_at: 1,
        issuer_device_id: None,
    };
    let (unconfirmed, _) =
        crate::records::issue_grant_deterministic(&root, KeyId::ROOT, &request, &mut fixed_rng(5))
            .unwrap();
    w.add(&unconfirmed);
    let confirm_case = json!({ "record": record(&unconfirmed), "holder_seed": h(&[0x78; 32]), "unwrap": dbg(&w.keys.unwrap_grant_data_key(&unconfirmed.hash(), &bad_holder).err()) });
    // The read grant's wrap under an aad with one field changed.
    let body = GrantBody::parse(&gr.body).unwrap();
    let wrapped = body.wrapped_data_key.clone().unwrap();
    let aad = body.wrap_aad();
    let aads = [
        (
            "folder_id",
            WrapAad {
                folder_id: FolderId([0x5f; 32]),
                ..aad
            },
        ),
        (
            "key_id",
            WrapAad {
                key_id: KeyId([0x5f; 16]),
                ..aad
            },
        ),
        (
            "tier",
            WrapAad {
                tier: Tier::Write,
                ..aad
            },
        ),
        ("epoch", WrapAad { epoch: 2, ..aad }),
    ];
    let aad_cases: Vec<Value> = aads.iter().map(|(f, x)| json!({ "changed": f, "aad": h(&x.to_bytes()), "outcome": dbg(&unwrap_data_key(&r, x, &wrapped).err()) })).collect();
    check(
        "grant",
        &json!({
            "folder": genesis_inputs(),
            "stored": stored,
            "rejected": rejected,
            "second_grant_same_key": second,
            "tie_by_record_hash": tie,
            "descendant_regrant": descendant,
            "key_on_two_chains": two_chains,
            "temporary_raise": temporary_raise,
            "expired_canonical_chain": expired_canonical,
            "equally_short_chains": equal_chains,
            "wrap_aad_changed": aad_cases,
            "wrap_fails_confirm": confirm_case,
        }),
    );
}

/// Section 9 item 11.
#[test]
fn vector_key_string() {
    let w = world();
    let (seed, _) = seed_set(0x62);
    let key = KeyString::new(w.folder_id(), seed);
    let lower = key.to_text().unwrap().to_string();
    let upper = key.to_qr_text().unwrap().to_string();
    let mut mixed = lower.clone();
    mixed.replace_range(10..11, &lower[10..11].to_ascii_uppercase());
    let flip = |c: char| if c == 'q' { "p" } else { "q" };
    let mut flipped = lower.clone();
    flipped.replace_range(20..21, flip(lower.as_bytes()[20] as char));
    let payload = crate::bytes::fill::<64>(&[w.folder_id().as_bytes(), key.seed().expose()]);
    let hrp = bech32::Hrp::parse_unchecked("lsk");
    let rejected: Vec<Value> = [
        ("mixed case", mixed),
        ("one flipped character", flipped),
        (
            "wrong prefix",
            bech32m_encode("lsl", &payload, false).unwrap().to_string(),
        ),
        (
            "Bech32 checksum",
            bech32::encode::<bech32::Bech32>(hrp, &payload).unwrap(),
        ),
        (
            "63-byte payload",
            bech32::encode::<bech32::Bech32m>(hrp, &payload[..63]).unwrap(),
        ),
        (
            "65-byte payload",
            bech32::encode::<bech32::Bech32m>(hrp, &[&payload[..], &[0]].concat()).unwrap(),
        ),
    ]
    .iter()
    .map(|(name, s)| json!({ "name": name, "string": s, "error": dbg(&KeyString::parse(s).err()) }))
    .collect();
    let bare = Link::bare(KeyString::parse(&lower).unwrap())
        .to_text()
        .unwrap()
        .to_string();
    let (mut v, a, wk) = (world(), set(0x61), set(0x64));
    let wk_seed = Seed::from_bytes([0x64; 32]);
    let ga = v.root_grant(&a, Tier::Write, true);
    let gw = v.grant_from(&a, id(&a), &wk, Tier::Write, false, 0);
    // The bundle's leaf is the grant of the link's own key.
    let full = Link {
        key: KeyString::new(w.folder_id(), wk_seed),
        bundle: vec![v.folder.record.clone(), ga.clone(), gw.clone()],
        addresses: vec!["/ip4/192.0.2.7/udp/4001/quic-v1".into()],
        cert_hash: Some(vec![0x12, 0x20, 0xaa, 0xbb]),
    };
    let full_text = full.to_text().unwrap().to_string();
    assert_eq!(full.to_text().unwrap().capacity(), full_text.len());
    let parsed = Link::parse(&full_text).unwrap();
    let verified = parsed.verify_bundle(NOW).unwrap().unwrap();
    assert_eq!(verified.len(), 3);
    // Another key's chain under this link's key string is refused.
    let foreign = Link {
        key: KeyString::parse(&lower).unwrap(),
        bundle: full.bundle.clone(),
        addresses: Vec::new(),
        cert_hash: None,
    };
    let foreign_text = foreign.to_text().unwrap().to_string();
    let foreign_outcome = dbg(&Link::parse(&foreign_text)
        .unwrap()
        .verify_bundle(NOW)
        .unwrap()
        .err());
    v.add(&ga);
    check(
        "key_string",
        &json!({
            "folder_id": h(&w.folder_id().0),
            "seed": h(key.seed().expose()),
            "lower": lower,
            "upper": upper,
            "rejected": rejected,
            "bare_link": bare,
            "link_with_bundle": full_text,
            "file": full.to_file().unwrap().to_string(),
            "link_with_another_keys_bundle": { "link": foreign_text, "outcome": foreign_outcome },
        }),
    );
}

/// Section 9 item 12, the keys crate's share: the device and folder proof
/// signatures (`protocol.md` 3.4 and 3.5) over a fixed transcript hash, and
/// the folder hint, proof key and sealed proof built from this crate's
/// primitives for that transcript hash and a fixed nonce. The transcript hash
/// itself is the protocol crate's construction (ruling 13b), whose vectors
/// feed real Hellos through these primitives.
#[test]
fn vector_handshake() {
    let (_, dev_a) = seed_set(0xa0);
    let (_, dev_b) = seed_set(0xb0);
    // Role A is the side whose Ed25519 half is byte-wise smaller (protocol.md 3.2).
    let (a, b, seed_a, seed_b) =
        if dev_a.public().signing.ed25519_bytes() < dev_b.public().signing.ed25519_bytes() {
            (&dev_a, &dev_b, 0xa0, 0xb0)
        } else {
            (&dev_b, &dev_a, 0xb0, 0xa0)
        };
    let th = fixed32(0x70);
    let folder = world().folder_id();
    let (_, issued) = seed_set(0x62);
    let key_id = issued.public().key_id(Suite::ONE);
    let device_proof = |set: &KeyPairSet, role: u8| {
        set.sign_deterministic(
            labels::SIG_DEVICE_PROOF,
            &crate::bytes::fill::<33>(&[&th, &[role]]),
        )
        .unwrap()
    };
    let dp_a = device_proof(a, 0x01);
    let dp_b = device_proof(b, 0x02);
    let folder_message =
        crate::bytes::fill::<81>(&[folder.as_bytes(), key_id.as_bytes(), &th, &[0x01]]);
    let fp = issued
        .sign_deterministic(labels::SIG_FOLDER_PROOF, &folder_message)
        .unwrap();
    assert!(issued
        .public()
        .signing
        .verify(labels::SIG_FOLDER_PROOF, &folder_message, &fp)
        .is_ok());
    assert!(a
        .public()
        .signing
        .verify(
            labels::SIG_DEVICE_PROOF,
            &crate::bytes::fill::<33>(&[&th, &[0x01]]),
            &dp_a
        )
        .is_ok());
    assert!(
        a.public()
            .signing
            .verify(
                labels::SIG_DEVICE_PROOF,
                &crate::bytes::fill::<33>(&[&th, &[0x02]]),
                &dp_a
            )
            .is_err(),
        "the role is bound"
    );
    let link_key = linking::link_confirm_key(&LinkSecret::from_bytes(fixed32(0xd0)));
    // The FolderProof envelope from this crate's primitives (protocol.md
    // 3.5): hint and proof key from the folder ID and th, the payload sealed
    // under a fixed nonce with the hint as associated data.
    let hint = labels::folder_hint(&folder, &th, 0x01);
    let proof_key = crate::secret::ProofKey::derive(&folder, &th);
    let nonce = [0x71u8; 24];
    let payload = b"ProofPayload bytes for the vector";
    let sealed = proof_key.seal(&nonce, &hint, payload).unwrap();
    assert_eq!(
        proof_key.open(&nonce, &hint, &sealed).unwrap().as_slice(),
        payload
    );
    check(
        "handshake",
        &json!({
            "transcript_hash": h(&th),
            "device_a_seed": h(&fixed32(seed_a)),
            "device_b_seed": h(&fixed32(seed_b)),
            "device_public_key_a": h(&a.public().signing.wire_form(Suite::ONE)),
            "device_public_key_b": h(&b.public().signing.wire_form(Suite::ONE)),
            "device_proof_a": h(dp_a.as_bytes()),
            "device_proof_b": h(dp_b.as_bytes()),
            "folder_id": h(&folder.0),
            "issued_key_seed": h(&fixed32(0x62)),
            "issued_key_id": h(&key_id.0),
            "folder_proof_message_a": h(&folder_message),
            "folder_proof_a": h(fp.as_bytes()),
            "link_secret": h(&fixed32(0xd0)),
            "link_proof_a": h(&linking::link_proof(&link_key, &th, 0x01)),
            "folder_hint_a": h(&hint),
            "proof_key": h(proof_key.expose()),
            "proof_nonce": h(&nonce),
            "proof_payload": h(payload),
            "sealed_proof": h(&sealed),
        }),
    );
}

/// Section 9 item 13: the phase 7 formats, the outcomes phase 0 gives them,
/// and the cases phase 7's verifier must judge. The restart records that name
/// a Suspension are index records (`protocol.md` 4.4) and belong to the
/// index crate's vectors.
#[test]
fn vector_phase_7() {
    let mut w = world();
    let root = root_set();
    let (a, b, s, c) = (set(0x61), set(0x65), set(0x63), set(0x66));
    let ga = w.root_grant(&a, Tier::Write, true);
    let gb = w.grant_from(&a, id(&a), &b, Tier::Read, false, 0);
    let gs = w.root_grant(&s, Tier::Sealed, false);
    let gc = w.root_grant(&c, Tier::Write, false);
    for g in [&ga, &gb, &gs, &gc] {
        w.add(g);
    }
    let dk2 = DataKey::from_bytes(fixed32(0x22));
    let cutoff = Cutoff {
        key_id: id(&b),
        device_id: DeviceId(fixed32(0xe0)),
        seq: 3,
        head_hash: Some(RecordHash(fixed32(0xe3))),
    };
    let rev = w.revocation(&a, id(&a), id(&b), vec![cutoff]);
    let rev_out = dbg(&w.keys.insert(&rev, NOW));
    // Each coverage case is the first rotation to epoch 2 in a copy of this
    // world: in one world they would be rivals, one per signer (ruling 22).
    let base = w.keys.clone();
    let cover = |name: &str, r: &SignedRecord| {
        let mut keys = base.clone();
        let stored = dbg(&keys.insert(r, NOW));
        json!({ "name": name, "record": record(r), "phase_0": stored, "phase_7_coverage": dbg(&keys.check_rotation_coverage(&r.hash(), NOW)) })
    };
    let view = vec![ga.hash(), gb.hash(), gs.hash()];
    let rot = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[(KeyId::ROOT, &root, Tier::Root), (id(&a), &a, Tier::Write)],
        Some(rev.hash()),
        view.clone(),
        2,
    );
    let rot_out = dbg(&w.keys.insert(&rot, NOW));
    let wrap = w.wrap_record(&root, KeyId::ROOT, &a, Tier::Write, 1);
    let wrap_out = dbg(&w.keys.insert(&wrap, NOW));
    let susp = {
        let body = crate::records::SuspensionBody {
            suite: Suite::ONE,
            folder_id: w.folder_id(),
            key_id: id(&c),
            acting_tier: ActingTier::Read,
            until: 0,
            signer_key_id: KeyId::ROOT,
            issued_at: 3,
            cutoffs: vec![Cutoff {
                key_id: id(&c),
                device_id: DeviceId(fixed32(0xe0)),
                seq: 7,
                head_hash: Some(RecordHash(fixed32(0xe7))),
            }],
        };
        w.sign(&root, RecordType::Suspension, body.encode())
    };
    let susp_out = dbg(&w.keys.insert(&susp, NOW));
    let lift = w.lift(&root, KeyId::ROOT, susp.hash());
    let lift_out = dbg(&w.keys.insert(&lift, NOW));
    let cases = vec![
        cover("valid; C, granted outside the view, awaits a wrap", &rot),
        cover(
            "omits a key in kept",
            &w.rotation(
                &a,
                id(&a),
                &dk2,
                &[(KeyId::ROOT, &root, Tier::Root)],
                Some(rev.hash()),
                view.clone(),
                2,
            ),
        ),
        cover(
            "wraps a key outside its view",
            &w.rotation(
                &a,
                id(&a),
                &dk2,
                &[
                    (KeyId::ROOT, &root, Tier::Root),
                    (id(&a), &a, Tier::Write),
                    (id(&c), &c, Tier::Write),
                ],
                Some(rev.hash()),
                view.clone(),
                2,
            ),
        ),
        cover(
            "wraps the key its cause revokes",
            &w.rotation(
                &a,
                id(&a),
                &dk2,
                &[
                    (KeyId::ROOT, &root, Tier::Root),
                    (id(&a), &a, Tier::Write),
                    (id(&b), &b, Tier::Read),
                ],
                Some(rev.hash()),
                view.clone(),
                2,
            ),
        ),
        cover(
            "a wrap reaches a key revoked outside its view; C awaits a wrap",
            &w.rotation(
                &root,
                KeyId::ROOT,
                &dk2,
                &[
                    (KeyId::ROOT, &root, Tier::Root),
                    (id(&a), &a, Tier::Write),
                    (id(&b), &b, Tier::Read),
                ],
                None,
                view.clone(),
                2,
            ),
        ),
    ];
    // Concurrent rotations: by cause, then by hash.
    let d = set(0x67);
    let gd = w.grant_from(&a, id(&a), &d, Tier::Write, true, 0);
    w.add(&gd);
    let e = set(0x68);
    w.add(&w.grant_from(&d, id(&d), &e, Tier::Read, false, 0));
    let rev_e = w.revocation(&d, id(&d), id(&e), vec![]);
    w.add(&rev_e);
    let rev_d = w.revocation(&a, id(&a), id(&d), vec![]);
    w.add(&rev_d);
    let by_a = w.rotation(
        &a,
        id(&a),
        &dk2,
        &[],
        Some(rev_d.hash()),
        vec![ga.hash()],
        2,
    );
    let by_d = w.rotation(
        &d,
        id(&d),
        &DataKey::from_bytes(fixed32(0x23)),
        &[],
        Some(rev_e.hash()),
        vec![ga.hash()],
        2,
    );
    let r1 = w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes(fixed32(0x24)),
        &[],
        None,
        vec![ga.hash()],
        2,
    );
    let r2 = w.rotation(
        &root,
        KeyId::ROOT,
        &DataKey::from_bytes(fixed32(0x25)),
        &[],
        None,
        vec![ga.hash()],
        2,
    );
    for r in [&by_a, &by_d, &r1, &r2] {
        w.add(r);
    }
    let concurrent = json!({
        "by_cause": { "a": record(&by_a), "b": record(&by_d), "winner": dbg(&w.keys.rotation_winner(&by_a.hash(), &by_d.hash())) },
        "by_hash": { "a": record(&r1), "b": record(&r2), "winner": dbg(&w.keys.rotation_winner(&r1.hash(), &r2.hash())) },
    });
    // A ladder whose recovered key fails the previous epoch's confirmation.
    let mut body = RotationBody::parse(&rot.body).unwrap();
    body.ladder = LadderLink::seal(
        &dk2,
        2,
        &w.folder_id(),
        &DataKey::from_bytes(fixed32(0x99)),
        &mut fixed_rng(6),
    )
    .unwrap();
    let bad_ladder = w.sign(&a, RecordType::Rotation, body.encode());
    let mut ladder_keys = base.clone();
    ladder_keys.insert(&bad_ladder, NOW).unwrap();
    // The holder's own wrap opens and confirms, but the ladder fails: the
    // rotator is at fault and nothing from the rotation is adopted (ruling 19).
    let ladder = json!({
        "record": record(&bad_ladder),
        "climb": dbg(&ladder_keys.climb_ladder(&bad_ladder.hash(), &dk2).err()),
        "unwrap_by_a": dbg(&ladder_keys.unwrap_rotation_data_key(&bad_ladder.hash(), &id(&a), &a).err()),
    });
    // A Wrap for a key this verifier knows revoked: stored in phases 0 to 6,
    // which apply no Revocation (ruling 21).
    let late_wrap = w.wrap_record(&root, KeyId::ROOT, &b, Tier::Read, 1);
    let late =
        json!({ "record": record(&late_wrap), "outcome": dbg(&w.keys.insert(&late_wrap, NOW)) });
    // A Lift by the suspended key's issuer for a Suspension root signed: a
    // signer fault, since no grant makes a key root's ancestor.
    let (e2, f2) = (set(0x69), set(0x6a));
    w.add(&w.grant_from(&a, id(&a), &e2, Tier::Write, true, 0));
    w.add(&w.grant_from(&e2, id(&e2), &f2, Tier::Read, false, 0));
    let root_susp = w.suspension(&root, KeyId::ROOT, id(&f2), ActingTier::Sealed, 0);
    w.add(&root_susp);
    let issuer_lift = w.lift(&e2, id(&e2), root_susp.hash());
    let lift_by_issuer = json!({ "suspension": record(&root_susp), "lift": record(&issuer_lift), "outcome": dbg(&w.keys.insert(&issuer_lift, NOW)) });
    // Phases 0 to 6: a dense chain of rotations to epoch 3 lets a grant at epoch 3 be stored.
    let dk3 = DataKey::from_bytes(fixed32(0x33));
    let folder_id = w.folder_id();
    let to3 = RotationBody {
        suite: Suite::ONE,
        folder_id,
        new_epoch: 3,
        signer_key_id: KeyId::ROOT,
        wraps: vec![crate::records::KeyWrapEntry {
            key_id: KeyId::ROOT,
            wrapped_data_key: wrap_data_key(
                &root.public().kem,
                &WrapAad {
                    folder_id,
                    key_id: KeyId::ROOT,
                    tier: Tier::Root,
                    epoch: 3,
                },
                &dk3,
                &mut fixed_rng(4),
            )
            .unwrap(),
        }],
        ladder: LadderLink::seal(&dk3, 3, &folder_id, &dk2, &mut fixed_rng(6)).unwrap(),
        cause: None,
        issued_at: 9,
        view: vec![],
        confirm: dk3.confirm(),
    };
    let to3 = w.sign(&root, RecordType::Rotation, to3.encode());
    let to3_outcome = dbg(&w.keys.insert(&to3, NOW));
    assert_eq!(w.keys.current_epoch(), 3);
    let late_key = set(0x6b);
    let request = crate::records::GrantRequest {
        folder_id,
        recipient: &late_key,
        tier: Tier::Read,
        may_share: false,
        expires_at: 0,
        epoch: 3,
        data_key: Some(&dk3),
        issued_at: 10,
        issuer_device_id: None,
    };
    let (at3, _) =
        crate::records::issue_grant_deterministic(&root, KeyId::ROOT, &request, &mut fixed_rng(5))
            .unwrap();
    let at3_outcome = dbg(&w.keys.insert(&at3, NOW));
    let at3_unwrap = w
        .keys
        .unwrap_grant_data_key(&at3.hash(), &late_key)
        .map(|(e, dk)| (e, hex::encode(dk.expose())));
    // This world holds rival rotations to epoch 2, so epoch 2 is ambiguous
    // and no key of it is judged (SF 4); in a world with one rotation to
    // epoch 2 the ladder recovers it.
    let ambiguous = w
        .keys
        .climb_ladder(&to3.hash(), &dk3)
        .map(|dk| hex::encode(dk.expose()));
    let mut clean = base.clone();
    clean.insert(&rot, NOW).unwrap();
    clean.insert(&to3, NOW).unwrap();
    let recovered_dk2 = clean
        .climb_ladder(&to3.hash(), &dk3)
        .map(|dk| hex::encode(dk.expose()));
    assert_eq!(
        recovered_dk2.as_deref().ok(),
        Some(hex::encode(dk2.expose()).as_str())
    );
    let dense = json!({
        "rotation_to_3": record(&to3),
        "rotation_outcome": to3_outcome,
        "current_epoch": w.keys.current_epoch(),
        "grant_at_epoch_3": record(&at3),
        "grant_outcome": at3_outcome,
        "unwraps_to": dbg(&at3_unwrap),
        "ladder_3_while_epoch_2_is_ambiguous": dbg(&ambiguous),
        "ladder_3_recovers": dbg(&recovered_dk2),
    });
    check(
        "phase7",
        &json!({
            "folder": genesis_inputs(),
            "grants": [record(&ga), record(&gb), record(&gs), record(&gc)],
            "revocation": { "record": record(&rev), "phase_0": rev_out },
            "rotation": { "record": record(&rot), "phase_0": rot_out, "data_key": h(dk2.expose()), "confirm": h(&dk2.confirm().0) },
            "wrap": { "record": record(&wrap), "phase_0": wrap_out },
            "suspension": { "record": record(&susp), "phase_0": susp_out },
            "lift": { "record": record(&lift), "names_suspension": h(&susp.hash().0), "phase_0": lift_out },
            "coverage": cases,
            "concurrent": concurrent,
            "ladder_fails_previous_confirm": ladder,
            "wrap_for_revoked_key": late,
            "lift_by_the_suspended_keys_issuer": lift_by_issuer,
            "dense_chain_to_epoch_3": dense,
        }),
    );
}

const LABEL_INPUT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

macro_rules! label_value {
    (derive, $l:expr) => {
        json!({ "mode": "derive_key", "input": h(&LABEL_INPUT), "output": h(&*derive_key($l, &LABEL_INPUT)) })
    };
    (hash, $l:expr) => {
        json!({ "mode": "H", "input": h(&LABEL_INPUT), "output": h(&labelled_hash($l, &[&LABEL_INPUT])) })
    };
    (keyed, $l:expr) => {
        json!({ "mode": "keyed", "key": h(&LABEL_INPUT), "input": h(&LABEL_INPUT), "output": h(&keyed_hash_labelled(&LABEL_INPUT, $l, &[&LABEL_INPUT])) })
    };
    (sig, $l:expr) => {{
        let (_, signer) = seed_set(0x80);
        json!({
            "mode": "prefix of M",
            "signer_seed": h(&fixed32(0x80)),
            "body": h(&LABEL_INPUT),
            "message": h(&signed_message($l, &LABEL_INPUT)),
            "signature": h(signer.sign_deterministic($l, &LABEL_INPUT).unwrap().as_bytes()),
        })
    }};
    (wrap, $l:expr) => {{
        let (_, recipient) = seed_set(0x80);
        let aad = WrapAad { folder_id: FolderId(LABEL_INPUT), key_id: KeyId([0x10; 16]), tier: Tier::Read, epoch: 1 };
        let wrapped = wrap_data_key(&recipient.public().kem, &aad, &DataKey::from_bytes(LABEL_INPUT), &mut fixed_rng(0x33)).unwrap();
        json!({
            "mode": "HPKE info",
            "info": $l.as_str(),
            "recipient_seed": h(&fixed32(0x80)),
            "aad": h(&aad.to_bytes()),
            "data_key": h(&LABEL_INPUT),
            "hpke_randomness_byte": 0x33,
            "wrapped_data_key": h(wrapped.as_bytes()),
        })
    }};
}

macro_rules! label_vectors {
    ($($test:ident: $mode:ident $label:ident;)*) => {
        fn label_entries() -> Vec<(&'static str, Value)> {
            vec![$((labels::$label.as_str(), label_value!($mode, labels::$label))),*]
        }
        $(
            #[test]
            fn $test() {
                check_label(labels::$label.as_str(), &label_value!($mode, labels::$label));
            }
        )*
    };
}

label_vectors! {
    vector_derive_key_identity_seed: derive IDENTITY_SEED;
    vector_derive_key_identity_catalogue_key: derive IDENTITY_CATALOGUE_KEY;
    vector_derive_key_folder_root_seed: derive FOLDER_ROOT_SEED;
    vector_derive_key_folder_chunk_hash_key: derive FOLDER_CHUNK_HASH_KEY;
    vector_derive_key_ed25519: derive KEY_ED25519;
    vector_derive_key_ml_dsa_65: derive KEY_ML_DSA_65;
    vector_derive_key_x_wing: derive KEY_X_WING;
    vector_derive_key_libp2p_identity: derive KEY_LIBP2P_IDENTITY;
    vector_derive_key_dht_bep44: derive KEY_DHT_BEP44;
    vector_derive_key_epoch_chunk_key: derive EPOCH_CHUNK_KEY;
    vector_derive_key_epoch_chunk_nonce_key: derive EPOCH_CHUNK_NONCE_KEY;
    vector_derive_key_epoch_record_key: derive EPOCH_RECORD_KEY;
    vector_derive_key_epoch_ladder_key: derive EPOCH_LADDER_KEY;
    vector_derive_key_epoch_confirm: derive EPOCH_CONFIRM;
    vector_derive_key_link_discovery: derive LINK_DISCOVERY;
    vector_derive_key_link_confirm: derive LINK_CONFIRM;
    vector_hash_id_folder: hash HASH_ID_FOLDER;
    vector_hash_id_device: hash HASH_ID_DEVICE;
    vector_hash_id_identity: hash HASH_ID_IDENTITY;
    vector_hash_id_key: hash HASH_ID_KEY;
    vector_hash_record: hash HASH_RECORD;
    vector_hash_chunk: hash HASH_CHUNK;
    vector_hash_discovery_peer: hash HASH_DISCOVERY_PEER;
    vector_hash_discovery_lan: hash HASH_DISCOVERY_LAN;
    vector_hash_discovery_dht: hash HASH_DISCOVERY_DHT;
    vector_hash_transcript: hash HASH_TRANSCRIPT;
    vector_keyed_handshake_folder_hint: keyed HANDSHAKE_FOLDER_HINT;
    vector_keyed_handshake_proof_key: keyed HANDSHAKE_PROOF_KEY;
    vector_sig_folder: sig SIG_FOLDER;
    vector_sig_grant: sig SIG_GRANT;
    vector_sig_grant_pop: sig SIG_GRANT_POP;
    vector_sig_rotation: sig SIG_ROTATION;
    vector_sig_wrap: sig SIG_WRAP;
    vector_sig_revocation: sig SIG_REVOCATION;
    vector_sig_suspension: sig SIG_SUSPENSION;
    vector_sig_lift: sig SIG_LIFT;
    vector_sig_root_rotation: sig SIG_ROOT_ROTATION;
    vector_sig_index: sig SIG_INDEX;
    vector_sig_folder_proof: sig SIG_FOLDER_PROOF;
    vector_sig_device_proof: sig SIG_DEVICE_PROOF;
    vector_wrap_data_key: wrap WRAP_DATA_KEY;
}

fn check_label(label: &str, generated: &Value) {
    if regenerating() {
        return;
    }
    let text = std::fs::read_to_string(format!("{DIR}labels.json")).unwrap();
    let committed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        committed.get(label),
        Some(generated),
        "the vector of {label} changed"
    );
}

/// The labels file holds exactly one vector per registered label.
#[test]
fn vector_labels_file() {
    let entries = label_entries();
    let mut file = serde_json::Map::new();
    for (label, value) in &entries {
        assert!(
            file.insert((*label).to_string(), value.clone()).is_none(),
            "{label} twice"
        );
    }
    let registered: std::collections::BTreeSet<&str> = REGISTRY.iter().map(|e| e.label).collect();
    let covered: std::collections::BTreeSet<&str> = entries.iter().map(|(l, _)| *l).collect();
    assert_eq!(
        registered, covered,
        "every registered label has a vector, and only those"
    );
    check("labels", &Value::Object(file));
}
