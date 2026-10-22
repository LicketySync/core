// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The test vectors of `keys.md` section 9 and `suites.md` section 4.4.
//!
//! Each `vector_*` test computes its vectors with this crate, checks what they
//! must show (round trips, refusals and their causes), and compares them with
//! the committed data file under `tests/vectors/` byte for byte: the file must
//! be exactly the pretty-printed JSON of what the test computes, so a change
//! of one bit in any output, or in the file, fails the test that names it.
//! Every `derive_key` label has its own test, named after the label; the
//! labels of the other modes are covered by the vectors that use them. To
//! regenerate the files after a reviewed change of format, run
//! `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-keys vector_`
//! and review the diff. Ed25519 signing is deterministic and every random
//! input is a fixed byte, so the files reproduce exactly through the
//! production signing path (`keys.md` 0.2).

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

use prost::Message as _;
use serde_json::{json, Value};

use crate::chunk::{self, cipher_hash, open_chunk, padme, seal_chunk, MAX_STORED_LEN};
use crate::device::{DeviceKey, DhtKey, Libp2pIdentity};
use crate::discovery;
use crate::folder::{FolderKey, WriteKey};
use crate::handshake::Role;
use crate::ids::{DeviceId, FolderId, RecordHash, WriterDigest};
use crate::keystring::{bech32m_encode, Link, HRP_READ, HRP_SEALED, HRP_WRITE};
use crate::labels::{self, derive_key, REGISTRY};
use crate::linking::{self, LinkCode};
use crate::records::SignedRecord;
use crate::sealed_meta::{self, open_meta, seal_meta, MAX_SEALED_BYTES};
use crate::secret::{DeviceSeed, LinkSecret, WriteSecret};
use crate::suite::{Suite, Tier};

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
    json!({ "body": h(r.body()), "signature": h(r.signature().as_bytes()), "record_hash": h(&r.hash().0) })
}

fn file_text(generated: &Value) -> String {
    serde_json::to_string_pretty(generated).unwrap() + "\n"
}

/// Compares `generated` with the committed `name.json`, entry by entry for a
/// readable failure and then byte for byte, or writes it when regenerating.
fn check(name: &str, generated: &Value) {
    let path = format!("{DIR}{name}.json");
    if regenerating() {
        std::fs::write(&path, file_text(generated)).unwrap();
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
    assert_eq!(
        text,
        file_text(generated),
        "{name}.json is not byte for byte"
    );
}

/// The vectors' folder: the write secret `00 01 .. 1f` plus `0x10`.
fn folder_key() -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(0x10))).unwrap()
}

/// A second folder, for "another folder's key".
fn other_folder_key() -> WriteKey {
    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(fixed32(0x20))).unwrap()
}

/// Section 9 item 1.
#[test]
fn vector_folder_derivations() {
    let w = folder_key();
    let dk = w.data_key();
    let r = FolderKey::from(w.read_key());
    let s = FolderKey::from(w.sealed_key());
    // One direction only: every tier derives the folder ID and the access key.
    for k in [&r, &s] {
        assert_eq!(k.folder_id(), w.verifier().folder_id());
        assert_eq!(
            crate::folder::tests::access_key_of(k),
            *dk.access_key().expose()
        );
    }
    check(
        "folder",
        &json!({
            "suite": 1,
            "write_secret": h(w.secret().expose()),
            "folder_signing_seed": h(&*derive_key(labels::FOLDER_SIGNING_KEY, w.secret().expose())),
            "folder_vk": h(w.verifier().verifying_key().as_bytes()),
            "folder_id": h(&w.verifier().folder_id().0),
            "data_key": h(dk.expose()),
            "access_key": h(dk.access_key().expose()),
            "chunk_key": h(dk.chunk_key().expose()),
            "chunk_nonce_key": h(dk.chunk_nonce_key().expose()),
            "chunk_hash_key": h(dk.chunk_hash_key().expose()),
            "record_key": h(dk.record_key().expose()),
            "hint_key": h(dk.access_key().hint_key().expose()),
            "payload_key": h(dk.access_key().payload_key().expose()),
            "write_payload": h(&FolderKey::from(folder_key()).payload()),
            "read_payload": h(&r.payload()),
            "sealed_payload": h(&s.payload()),
            "stored_read_key": h(&r.to_stored()),
        }),
    );
}

/// Section 9 item 2.
#[test]
fn vector_key_string() {
    let w = FolderKey::from(folder_key());
    let r = w.lowered(Tier::Read).unwrap();
    let s = w.lowered(Tier::Sealed).unwrap();
    let strings: Vec<Value> = [&w, &r, &s]
        .iter()
        .map(|k| {
            let lower = k.to_key_string().to_string();
            let upper = k.to_qr_string().to_string();
            for text in [&lower, &upper] {
                let back = FolderKey::from_key_string(text).unwrap();
                assert_eq!(back.tier(), k.tier());
                assert_eq!(*back.payload(), *k.payload());
            }
            json!({ "tier": k.tier().as_u8(), "lower": lower, "upper": upper, "payload": h(&k.payload()) })
        })
        .collect();
    let enc = |hrp: &str, payload: &[u8]| {
        bech32m_encode(&bech32::Hrp::parse_unchecked(hrp), payload, false).to_string()
    };
    let read_payload = r.payload().to_vec();
    let write_payload = w.payload().to_vec();
    let read_string = r.to_key_string().to_string();
    let mut mixed = read_string.clone();
    mixed.replace_range(10..11, &read_string[10..11].to_ascii_uppercase());
    let flip = |c: char| if c == 'q' { "p" } else { "q" };
    let mut flipped = read_string.clone();
    flipped.replace_range(20..21, flip(read_string.as_bytes()[20] as char));
    let mut padding: Vec<bech32::Fe32> = {
        use bech32::ByteIterExt as _;
        write_payload.iter().copied().bytes_to_fes().collect()
    };
    *padding.last_mut().unwrap() = bech32::Fe32::try_from(1u8).unwrap();
    let padding: String = {
        use bech32::Fe32IterExt as _;
        padding
            .into_iter()
            .with_checksum::<bech32::Bech32m>(&bech32::Hrp::parse_unchecked(HRP_WRITE))
            .chars()
            .collect()
    };
    let with_suite = |payload: &[u8], suite: u8| {
        let mut p = payload.to_vec();
        p[0] = 0;
        p[1] = suite;
        p
    };
    let undecodable = (0u8..=255)
        .find(|&b| ed25519_dalek::VerifyingKey::from_bytes(&[b; 32]).is_err())
        .unwrap();
    let mut not_a_point = read_payload.clone();
    not_a_point[2..34].fill(undecodable);
    let mut non_canonical = read_payload.clone();
    non_canonical[2..34].copy_from_slice(&crate::sig::tests::non_canonical_point());
    let mut small_order = read_payload.clone();
    small_order[2..34].fill(0);
    small_order[2] = 1;
    let rejected: Vec<Value> = [
        ("mixed case", mixed),
        ("one flipped character", flipped),
        (
            "prefix other than lsw, lsr and lss",
            enc("lsx", &read_payload),
        ),
        (
            "Bech32 (non-m) checksum",
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked(HRP_READ), &read_payload)
                .unwrap(),
        ),
        ("write payload under lsr", enc(HRP_READ, &write_payload)),
        ("read payload under lsw", enc(HRP_WRITE, &read_payload)),
        (
            "read payload one byte short",
            enc(HRP_READ, &read_payload[..65]),
        ),
        (
            "read payload one byte long (118 characters, over the 116 a decoder takes)",
            enc(HRP_READ, &[&read_payload[..], &[0]].concat()),
        ),
        (
            "write payload one byte short",
            enc(HRP_WRITE, &write_payload[..33]),
        ),
        (
            "write payload one byte long",
            enc(HRP_WRITE, &[&write_payload[..], &[0]].concat()),
        ),
        ("payload of 1 byte", enc(HRP_SEALED, &[1])),
        ("non-zero padding bit", padding),
        ("suite 0", enc(HRP_READ, &with_suite(&read_payload, 0))),
        (
            "suite 2, not implemented",
            enc(HRP_WRITE, &with_suite(&write_payload, 2)),
        ),
        (
            "suite 2, not implemented, with a length other than suite 1's",
            enc(HRP_WRITE, &with_suite(&read_payload, 2)),
        ),
        ("folder_vk not a point", enc(HRP_READ, &not_a_point)),
        (
            "folder_vk a non-canonical encoding of a valid point",
            enc(HRP_READ, &non_canonical),
        ),
        ("folder_vk of small order", enc(HRP_SEALED, &small_order)),
    ]
    .iter()
    .map(|(name, s)| {
        let e = FolderKey::from_key_string(s).unwrap_err();
        json!({ "name": name, "string": s, "error": dbg(&e), "message": e.to_string() })
    })
    .collect();
    // Both suite-2 strings are refused for their suite, whatever their length.
    for newer in rejected
        .iter()
        .filter(|r| r["name"].as_str().unwrap().starts_with("suite 2"))
    {
        assert_eq!(
            newer["message"],
            "this key needs a newer release of Lickety-Sync"
        );
    }
    check(
        "key_string",
        &json!({ "write_secret": h(&fixed32(0x10)), "strings": strings, "rejected": rejected }),
    );
}

/// Section 9 item 3.
#[test]
fn vector_words() {
    let w = folder_key();
    let text = w.to_words().unwrap().to_string();
    let words: Vec<&str> = text.split(' ').collect();
    assert_eq!(words.len(), 24);
    assert_eq!(text, text.to_lowercase(), "shown in lower case");
    let prefixes: Vec<&str> = words.iter().map(|w| &w[..w.len().min(4)]).collect();
    // Words in title, upper and lower case by turns (letter by letter
    // alternation would read to the spelling checker as typos).
    let mixed: String = words
        .iter()
        .enumerate()
        .map(|(i, w)| match i % 3 {
            0 => w[..1].to_ascii_uppercase() + &w[1..],
            1 => w.to_ascii_uppercase(),
            _ => (*w).to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ");
    let spaced = format!(
        "  {}\t{}\n{}   {}\r\n{} ",
        words[..5].join(" "),
        words[5..10].join("\t"),
        words[10..15].join("  "),
        words[15..20].join("\n"),
        words[20..].join(" \t ")
    );
    let accepted: Vec<Value> = [
        ("upper case", text.to_uppercase()),
        ("mixed case", mixed),
        ("tabs, line breaks and repeated spaces", spaced),
        ("four-letter prefixes", prefixes.join(" ")),
    ]
    .iter()
    .map(|(name, entry)| {
        let back = WriteKey::from_words(entry).unwrap();
        assert!(bool::from(back.secret().ct_eq(w.secret())), "{name}");
        json!({ "name": name, "words": entry })
    })
    .collect();
    let list = bip39::Language::English.word_list();
    let last = list.iter().position(|w| *w == words[23]).unwrap();
    let mut bad_checksum = words.clone();
    bad_checksum[23] = list[(last + 1) % 2048];
    let mut twenty_five = words.clone();
    twenty_five.push(words[0]);
    let mut no_word = words.clone();
    no_word[5] = "notaword";
    // A three-letter prefix of a longer word that is not itself a word.
    let (at, three) = words
        .iter()
        .enumerate()
        .find_map(|(i, w)| {
            let p = &w[..3];
            (w.len() > 3 && !list.contains(&p)).then_some((i, p))
        })
        .unwrap();
    let mut short_prefix = words.clone();
    short_prefix[at] = three;
    let refused: Vec<Value> = [
        ("23 tokens", words[..23].join(" ")),
        ("25 tokens", twenty_five.join(" ")),
        ("a token in the alphabet that is no word", no_word.join(" ")),
        (
            "a three-letter prefix of a longer word",
            short_prefix.join(" "),
        ),
        ("24 valid words with a bad checksum", bad_checksum.join(" ")),
    ]
    .iter()
    .map(|(name, p)| {
        let e = WriteKey::from_words(p).unwrap_err();
        json!({ "name": name, "words": p, "error": dbg(&e), "message": e.to_string() })
    })
    .collect();
    assert_eq!(refused[0]["message"], "23 words; a write key has 24");
    assert_eq!(refused[1]["message"], "25 words; a write key has 24");
    check(
        "words",
        &json!({
            "write_secret": h(w.secret().expose()),
            "words": text,
            "accepted": accepted,
            "refused": refused,
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

fn device_seed(start: u8) -> DeviceSeed {
    DeviceSeed::from_bytes(fixed32(start))
}

/// Section 9 item 4. The peer ID is the identity multihash of the protobuf
/// encoding of the Ed25519 public key (libp2p peer-ids specification); the
/// `net` crate's test checks it against `libp2p-identity` when that lands.
#[test]
fn vector_device() {
    let seed = device_seed(0xa0);
    let device = DeviceKey::from_device_seed(&seed);
    let identity = Libp2pIdentity::from_device_seed(&seed);
    let dht = DhtKey::from_device_seed(&seed);
    let mut peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    peer_id.extend_from_slice(&identity.public_key());
    let text = base58(&peer_id);
    assert!(text.starts_with("12D3KooW"), "{text}");
    let item = b"bep44 test item";
    let th = fixed32(0x70);
    let proof_a = device.sign_device_proof(&th, Role::A);
    let proof_b = device.sign_device_proof(&th, Role::B);
    for (role, proof) in [(Role::A, &proof_a), (Role::B, &proof_b)] {
        assert_eq!(
            device.public().verify_device_proof(&th, role, proof),
            Ok(())
        );
        assert!(device
            .public()
            .verify_device_proof(&th, role.peer(), proof)
            .is_err());
    }
    check(
        "device",
        &json!({
            "device_seed": h(seed.expose()),
            "device_key_seed": h(&*derive_key(labels::KEY_ED25519, seed.expose())),
            "device_pk": h(device.public().ed25519_bytes()),
            "hello_device_public_key": h(&device.public().to_hello()),
            "device_id": h(&device.device_id().0),
            "libp2p_identity_seed": h(&*identity.expose_seed()),
            "libp2p_identity_pk": h(&identity.public_key()),
            "libp2p_peer_id": h(&peer_id),
            "libp2p_peer_id_text": text,
            "dht_key_seed": h(&*derive_key(labels::KEY_DHT_BEP44, seed.expose())),
            "dht_pk": h(&dht.public_key()),
            "dht_signed_item": h(item),
            "dht_signature": h(&dht.sign_bep44(item)),
            "transcript_hash": h(&th),
            "device_proof_role_a": h(proof_a.as_bytes()),
            "device_proof_role_b": h(proof_b.as_bytes()),
        }),
    );
}

/// Section 9 item 5.
#[test]
fn vector_discovery() {
    let salt: [u8; 16] = core::array::from_fn(|i| 0x51 + u8::try_from(i).unwrap());
    let folder = folder_key().verifier().folder_id();
    let announcer = Libp2pIdentity::from_device_seed(&device_seed(0xa0)).public_key();
    let other = Libp2pIdentity::from_device_seed(&device_seed(0xb0)).public_key();
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
        }),
    );
}

/// The vectors' raw chunk: 300 bytes.
fn raw_chunk() -> Vec<u8> {
    (0..300u32)
        .map(|i| u8::try_from(i * 7 % 256).unwrap())
        .collect()
}

/// Section 9 item 6.
#[test]
fn vector_chunk() {
    let w = folder_key();
    let folder = w.verifier().folder_id();
    let keys = w.chunk_keys();
    let raw = raw_chunk();
    let sealed = seal_chunk(&keys, &raw).unwrap();
    let plain = sealed.plain_hash;
    assert!(bool::from(plain.ct_eq(&keys.plain_hash(&raw))));
    assert_eq!(
        &*open_chunk(&keys, &sealed.stored, &plain).unwrap(),
        &raw[..]
    );
    let mut bad_tag = sealed.stored.clone();
    *bad_tag.last_mut().unwrap() ^= 1;
    let forged = |pt: &[u8]| chunk::seal_plaintext_for_test(&keys, pt);
    let variants: Vec<(&str, Vec<u8>, chunk::PlainHash)> = vec![
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
            keys.plain_hash(b"another chunk"),
        ),
    ];
    let mut corrupt: Vec<Value> = variants
        .iter()
        .map(|(name, stored, expected)| {
            json!({ "name": name, "stored": h(stored), "expected_plain_hash": h(&expected.0), "error": dbg(&open_chunk(&keys, stored, expected).err()) })
        })
        .collect();
    let over = vec![0u8; MAX_STORED_LEN + 1];
    corrupt.push(json!({ "name": "stored length over the bound", "stored_len": over.len(), "error": dbg(&open_chunk(&keys, &over, &plain).err()) }));
    // Compression 0 with a payload one byte over MAX_CHUNK_PLAINTEXT, in a
    // plaintext long enough to hold it. Its 4 325 416 stored bytes are given
    // by their plaintext's header, padded length, nonce and ciphertext hash
    // rather than in full: the plaintext is the header and zeros, the nonce is
    // the convergent one, so they rebuild exactly.
    let over_plaintext = chunk::over_the_bound_plaintext();
    let over_stored = forged(&over_plaintext);
    assert_eq!(over_stored.len(), MAX_STORED_LEN);
    corrupt.push(json!({
        "name": "compression 0 payload over MAX_CHUNK_PLAINTEXT",
        "plaintext_header": h(&over_plaintext[..chunk::HEADER_LEN]),
        "padded_length": over_plaintext.len(),
        "nonce": h(&over_stored[..24]),
        "stored_len": over_stored.len(),
        "stored_cipher_hash": h(&cipher_hash(&over_stored).0),
        "error": dbg(&open_chunk(&keys, &over_stored, &plain).err()),
    }));
    let other = other_folder_key();
    let other_keys = other.chunk_keys();
    let elsewhere = seal_chunk(&other_keys, &raw).unwrap();
    assert_ne!(elsewhere.stored, sealed.stored);
    check(
        "chunk",
        &json!({
            "write_secret": h(w.secret().expose()),
            "folder_id": h(&folder.0),
            "raw": h(&raw),
            "plain_hash": h(&plain.0),
            "padded_length": padme(305).unwrap(),
            "nonce": h(&sealed.stored[..24]),
            "stored": h(&sealed.stored),
            "cipher_hash": h(&sealed.cipher_hash.0),
            "corrupt": corrupt,
            "under_another_folder": {
                "write_secret": h(other.secret().expose()),
                "stored": h(&elsewhere.stored),
                "cipher_hash": h(&elsewhere.cipher_hash.0),
                "error_under_this_folder": dbg(&open_chunk(&keys, &elsewhere.stored, &plain).err()),
            },
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

/// Section 9 item 7.
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

/// The index record of `protocol.md` 4.4, mirrored here for the vectors only;
/// the protocol crate owns the schema.
#[derive(Clone, PartialEq, prost::Message)]
struct IndexRecord {
    #[prost(uint32, tag = "1")]
    suite: u32,
    #[prost(uint32, tag = "2")]
    record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    device_id: Vec<u8>,
    #[prost(uint64, tag = "6")]
    seq: u64,
    #[prost(bytes = "vec", repeated, tag = "8")]
    supersedes: Vec<Vec<u8>>,
    #[prost(bool, tag = "11")]
    deleted: bool,
    #[prost(message, repeated, tag = "12")]
    chunks: Vec<ChunkRef>,
    #[prost(bytes = "vec", tag = "13")]
    sealed: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ChunkRef {
    #[prost(bytes = "vec", tag = "1")]
    cipher_hash: Vec<u8>,
    #[prost(uint32, tag = "2")]
    stored_len: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SealedMeta {
    #[prost(string, tag = "1")]
    path: String,
    #[prost(uint32, tag = "2")]
    kind: u32,
    #[prost(uint64, tag = "3")]
    size: u64,
    #[prost(int64, tag = "4")]
    mtime_ns: i64,
    #[prost(uint32, tag = "5")]
    mode: u32,
    #[prost(bytes = "vec", repeated, tag = "6")]
    plain_hashes: Vec<Vec<u8>>,
    #[prost(uint64, tag = "7")]
    written_at: u64,
}

/// Section 9 item 8.
#[test]
fn vector_index_record() {
    let w = folder_key();
    let v = *w.verifier();
    let folder = v.folder_id();
    let device = DeviceKey::from_device_seed(&device_seed(0xa0)).device_id();
    let rk = w.data_key().record_key();
    let keys = w.chunk_keys();
    let raw = raw_chunk();
    let chunk = seal_chunk(&keys, &raw).unwrap();
    let meta_of = |path: &str| SealedMeta {
        path: path.into(),
        kind: 1,
        size: 300,
        mtime_ns: 1_800_000_000_000_000_000,
        mode: 0o644,
        plain_hashes: vec![chunk.plain_hash.0.to_vec()],
        written_at: 1_800_000_000,
    };
    // A set: written sorted ascending (keys.md 5.2).
    let mut supersedes = vec![fixed32(0x90).to_vec(), fixed32(0x30).to_vec()];
    supersedes.sort();
    let body_of = |seq: u64, sealed: Vec<u8>| IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: folder.0.to_vec(),
        device_id: device.0.to_vec(),
        seq,
        supersedes: supersedes.clone(),
        deleted: false,
        chunks: vec![ChunkRef {
            cipher_hash: chunk.cipher_hash.0.to_vec(),
            stored_len: u32::try_from(chunk.stored.len()).unwrap(),
        }],
        sealed,
    };
    let meta = meta_of("docs/report.txt").encode_to_vec();
    let nonce = [0x5au8; 24];
    let sealed = seal_meta(&rk, &folder, &device, 1, &meta, &mut |b| {
        b.copy_from_slice(&nonce);
    })
    .unwrap();
    let body = body_of(1, sealed.clone()).encode_to_vec();
    let r = w.sign_index_record(body.clone());
    assert_eq!(v.verify_index_record(&r), Ok(()));
    assert_eq!(SignedRecord::from_bytes(&r.to_bytes()), Ok(r.clone()));
    // Opened with the aad rebuilt from the record's clear fields.
    let parsed = IndexRecord::decode(r.body()).unwrap();
    let opened = open_meta(
        &rk,
        &FolderId::from_slice(&parsed.folder_id).unwrap(),
        &DeviceId::from_slice(&parsed.device_id).unwrap(),
        parsed.seq,
        &parsed.sealed,
    )
    .unwrap();
    assert_eq!(*opened, meta);
    let other_device = DeviceKey::from_device_seed(&device_seed(0xb0)).device_id();
    let other = other_folder_key();
    let other_folder = other.verifier().folder_id();
    let moved = json!({
        "to_seq_2": dbg(&open_meta(&rk, &folder, &device, 2, &sealed).err()),
        "to_another_device_id": dbg(&open_meta(&rk, &folder, &other_device, 1, &sealed).err()),
        "to_another_folder": dbg(&open_meta(&rk, &other_folder, &device, 1, &sealed).err()),
    });
    // A seal whose padding is not zero, sealed by hand.
    let mut plain = (u32::try_from(meta.len()).unwrap()).to_be_bytes().to_vec();
    plain.extend(&meta);
    plain.resize(
        usize::try_from(padme(plain.len() as u64).unwrap()).unwrap(),
        0,
    );
    *plain.last_mut().unwrap() = 1;
    assert!(plain.len() > meta.len() + 4, "there is padding to spoil");
    let bad_padding = sealed_meta::seal_plain_for_test(&rk, &folder, &device, 1, &nonce, &plain);
    // Sealed parts of 39 and of 1 572 865 bytes: malformed, judged on length.
    let lengths = json!({
        "39": dbg(&open_meta(&rk, &folder, &device, 1, &[0u8; 39]).err()),
        "1572865": dbg(&open_meta(&rk, &folder, &device, 1, &vec![0u8; MAX_SEALED_BYTES + 1]).err()),
    });
    // One bit flipped inside a bytes field (the device ID), so that the body
    // still parses, then a signature by another folder's key.
    let mut flipped_bytes = r.to_bytes();
    let at = flipped_bytes
        .windows(32)
        .position(|win| win == device.0)
        .unwrap();
    flipped_bytes[at + 5] ^= 0x01;
    let flipped = SignedRecord::from_bytes(&flipped_bytes).unwrap();
    assert!(IndexRecord::decode(flipped.body()).is_ok());
    assert_ne!(flipped.body(), r.body());
    let by_other = other.sign_index_record(body.clone());
    // Two records of one device at one seq: both verify.
    let meta2 = meta_of("docs/report (2).txt").encode_to_vec();
    let sealed2 = seal_meta(&rk, &folder, &device, 1, &meta2, &mut |b| b.fill(0x5b)).unwrap();
    let r2 = w.sign_index_record(body_of(1, sealed2).encode_to_vec());
    assert_eq!(v.verify_index_record(&r2), Ok(()));
    let mut canonical = [r.hash(), r2.hash()];
    canonical.sort();
    // The writer digests after each of three fixed record hashes.
    let fixed = [
        RecordHash(fixed32(0x01)),
        RecordHash(fixed32(0x41)),
        RecordHash(fixed32(0x81)),
    ];
    let mut d = WriterDigest::ZERO;
    let digests: Vec<Value> = fixed
        .iter()
        .map(|rh| {
            d = d.then(rh);
            json!({ "record_hash": h(&rh.0), "digest": h(&d.0) })
        })
        .collect();
    check(
        "index_record",
        &json!({
            "write_secret": h(w.secret().expose()),
            "folder_id": h(&folder.0),
            "device_id": h(&device.0),
            "record_key": h(rk.expose()),
            "sealed_meta": h(&meta),
            "seal_nonce": h(&nonce),
            "aad": h(&[&folder.0[..], &device.0[..], &1u64.to_be_bytes()].concat()),
            "sealed": h(&sealed),
            "record": record(&r),
            "envelope": h(&r.to_bytes()),
            "opened_meta": h(&opened),
            "moved_seal": moved,
            "non_zero_padding": { "sealed": h(&bad_padding), "error": dbg(&open_meta(&rk, &folder, &device, 1, &bad_padding).err()) },
            "sealed_lengths": lengths,
            "bit_flipped_in_the_device_id": { "record": record(&flipped), "error": dbg(&v.verify_index_record(&flipped).err()) },
            "signed_by_another_folder": { "record": record(&by_other), "error": dbg(&v.verify_index_record(&by_other).err()) },
            "concurrent_version_at_seq_1": {
                "record": record(&r2),
                "verifies": v.verify_index_record(&r2).is_ok(),
                "canonical_order": canonical.iter().map(|h2| h(&h2.0)).collect::<Vec<_>>(),
            },
            "writer_digests": digests,
        }),
    );
}

/// `ProofPayload` of `protocol.md` 4.3, mirrored here for the vectors only:
/// the tier the prover reports.
#[derive(Clone, PartialEq, prost::Message)]
struct ProofPayload {
    #[prost(uint32, tag = "4")]
    tier: u32,
}

/// Section 9 item 9, shared with the protocol crate's vectors: for a fixed
/// transcript hash (the protocol crate's vectors build it from fixed Hellos
/// and feed it here) and the fixed folder, the hints for both roles, the proof
/// key, and the sealed payload for each reported tier in both roles under
/// fixed nonces, opened again; the same payload failing under another `th` and
/// under the other role's hint; and a sealed key made of two folders' halves.
#[test]
fn vector_handshake() {
    let th = fixed32(0x70);
    let other_th = fixed32(0x71);
    let w = folder_key();
    let keys = [
        FolderKey::from(folder_key()),
        FolderKey::from(w.read_key()),
        FolderKey::from(w.sealed_key()),
    ];
    let hs = keys[2].handshake_keys();
    for k in &keys {
        let other = k.handshake_keys();
        assert_eq!(other.hint(&th, Role::A), hs.hint(&th, Role::A));
        assert_eq!(other.proof_key(&th).expose(), hs.proof_key(&th).expose());
    }
    let proof_key = hs.proof_key(&th);
    let mut payloads = Vec::new();
    for (r, role) in [Role::A, Role::B].into_iter().enumerate() {
        let hint = hs.hint(&th, role);
        for (t, tier) in Tier::ALL.into_iter().enumerate() {
            let payload = ProofPayload {
                tier: tier.to_wire(),
            }
            .encode_to_vec();
            // A fixed nonce, through the production sealing path: the
            // closure stands in for the caller's randomness.
            let fixed = 0x71 + u8::try_from(r * 3 + t).unwrap();
            let (nonce, sealed) = hs
                .seal_proof(&th, role, &payload, &mut |b| b.fill(fixed))
                .unwrap();
            assert_eq!(nonce, [fixed; 24]);
            assert_eq!(
                sealed,
                crate::aead::xchacha_seal(proof_key.expose(), &nonce, &hint, &payload).unwrap()
            );
            // Opened again by any tier; refused under another th or the other
            // role's hint.
            for k in &keys {
                let opened = k
                    .handshake_keys()
                    .open_proof(&th, role, &nonce, &sealed)
                    .unwrap();
                assert_eq!(opened.as_slice(), payload.as_slice());
            }
            let under_other_th = hs.open_proof(&other_th, role, &nonce, &sealed);
            let under_other_role = hs.open_proof(&th, role.peer(), &nonce, &sealed);
            payloads.push(json!({
                "role": role.as_u8(),
                "reported_tier": tier.as_u8(),
                "payload": h(&payload),
                "nonce": h(&nonce),
                "sealed": h(&sealed),
                "under_another_th": dbg(&under_other_th.err()),
                "under_the_other_roles_hint": dbg(&under_other_role.err()),
            }));
        }
    }
    let other = other_folder_key();
    let mixed = crate::handshake::tests::mixed_sealed_key(&w, &other);
    let mixed_hint = mixed.handshake_keys().hint(&th, Role::A);
    let other_hint = FolderKey::from(other_folder_key())
        .handshake_keys()
        .hint(&th, Role::A);
    assert_ne!(mixed_hint, hs.hint(&th, Role::A));
    assert_ne!(mixed_hint, other_hint);
    let ak = w.data_key().access_key();
    check(
        "handshake",
        &json!({
            "transcript_hash": h(&th),
            "other_transcript_hash": h(&other_th),
            "write_secret": h(w.secret().expose()),
            "folder_id": h(&w.verifier().folder_id().0),
            "access_key": h(ak.expose()),
            "hint_key": h(ak.hint_key().expose()),
            "payload_key": h(ak.payload_key().expose()),
            "hint_role_a": h(&hs.hint(&th, Role::A)),
            "hint_role_b": h(&hs.hint(&th, Role::B)),
            "proof_key": h(proof_key.expose()),
            "payloads": payloads,
            "sealed_key_of_two_folders": {
                "folder_vk_of": h(&w.verifier().folder_id().0),
                "access_key_of": h(&other.verifier().folder_id().0),
                "hint_role_a": h(&mixed_hint),
                "matches_this_folder": mixed_hint == hs.hint(&th, Role::A),
                "matches_the_other_folder": mixed_hint == other_hint,
            },
        }),
    );
}

/// Section 9 item 11 (phase 1).
#[test]
fn vector_link() {
    let w = FolderKey::from(folder_key());
    let link = Link {
        key: w.lowered(Tier::Read).unwrap(),
        addresses: vec![
            "/ip4/192.0.2.7/udp/4001/quic-v1".into(),
            "/ip4/192.0.2.7/tcp/4001".into(),
        ],
        cert_hash: Some(vec![0x12, 0x20, 0xaa, 0xbb]),
    };
    let text = link.to_text().unwrap().to_string();
    let file = link.to_file().unwrap().to_string();
    let back = Link::parse_file(&file).unwrap();
    assert_eq!(back.addresses, link.addresses);
    assert_eq!(*back.key.payload(), *link.key.payload());
    let in_query = format!(
        "https://licketysync.dev/join?k={}",
        link.key.to_key_string().as_str()
    );
    check(
        "link",
        &json!({
            "key_string": link.key.to_key_string().as_str(),
            "link": text,
            "lskey_file": file,
            "key_string_in_the_query": { "link": in_query, "error": dbg(&Link::parse(&in_query).err()) },
        }),
    );
}

/// Section 9 item 12 (phase 5).
#[test]
fn vector_linking() {
    let device = DeviceKey::from_device_seed(&device_seed(0xa0)).device_id();
    let secret = LinkSecret::from_bytes(fixed32(0xd0));
    let code = LinkCode {
        device_id: device,
        secret: LinkSecret::from_bytes(fixed32(0xd0)),
    };
    let lower = code.to_text(false).to_string();
    let back = LinkCode::parse(&lower).unwrap();
    assert_eq!(back.device_id, device);
    let key = linking::link_confirm_key(&secret);
    let th = fixed32(0x70);
    check(
        "linking",
        &json!({
            "device_id": h(&device.0),
            "link_secret": h(secret.expose()),
            "link_code": lower,
            "link_code_upper": code.to_text(true).as_str(),
            "beacon_id": h(&linking::link_beacon_id(&secret)),
            "transcript_hash": h(&th),
            "link_proof_a": h(&linking::link_proof(&key, &th, Role::A)),
            "link_proof_b": h(&linking::link_proof(&key, &th, Role::B)),
        }),
    );
}

const LABEL_INPUT: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// The `derive_key` vector of one label (section 9 item 10): the labels of
/// the other modes are covered by the vectors of what they compute.
fn label_value(label: labels::DeriveLabel) -> Value {
    json!({ "input": h(&LABEL_INPUT), "output": h(&*derive_key(label, &LABEL_INPUT)) })
}

macro_rules! label_vectors {
    ($($test:ident: $label:ident;)*) => {
        fn label_entries() -> Vec<(&'static str, Value)> {
            vec![$((labels::$label.as_str(), label_value(labels::$label))),*]
        }
        $(
            #[test]
            fn $test() {
                check_label(labels::$label.as_str(), &label_value(labels::$label));
            }
        )*
    };
}

label_vectors! {
    vector_derive_key_folder_signing_key: FOLDER_SIGNING_KEY;
    vector_derive_key_folder_data_key: FOLDER_DATA_KEY;
    vector_derive_key_data_access_key: DATA_ACCESS_KEY;
    vector_derive_key_data_chunk_key: DATA_CHUNK_KEY;
    vector_derive_key_data_chunk_nonce_key: DATA_CHUNK_NONCE_KEY;
    vector_derive_key_data_chunk_hash_key: DATA_CHUNK_HASH_KEY;
    vector_derive_key_data_record_key: DATA_RECORD_KEY;
    vector_derive_key_handshake_hint_key: HANDSHAKE_HINT_KEY;
    vector_derive_key_handshake_payload_key: HANDSHAKE_PAYLOAD_KEY;
    vector_derive_key_ed25519: KEY_ED25519;
    vector_derive_key_libp2p_identity: KEY_LIBP2P_IDENTITY;
    vector_derive_key_dht_bep44: KEY_DHT_BEP44;
    vector_derive_key_link_discovery: LINK_DISCOVERY;
    vector_derive_key_link_confirm: LINK_CONFIRM;
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

/// The labels file holds exactly one vector per registered `derive_key` label.
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
    let registered: std::collections::BTreeSet<&str> = REGISTRY
        .iter()
        .filter(|e| e.mode == labels::Mode::DeriveKey)
        .map(|e| e.label)
        .collect();
    let covered: std::collections::BTreeSet<&str> = entries.iter().map(|(l, _)| *l).collect();
    assert_eq!(
        registered, covered,
        "every registered derive_key label has a vector, and only those"
    );
    assert_eq!(entries.len(), 14);
    check("labels", &Value::Object(file));
}
