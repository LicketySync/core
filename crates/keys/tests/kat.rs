// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Known-answer tests of the primitives as this crate uses them (`suites.md`
//! section 4.4): RFC 8032 Ed25519 and the BIP39 Trezor vectors through this
//! crate's words API. The BLAKE3 official vectors are tested in the labels
//! module, the one place this crate calls BLAKE3, and the XChaCha20-Poly1305
//! draft's AEAD vector in the aead module, whose functions are private to the
//! crate. The vectors are the published ones, copied into `tests/vectors/` as
//! data. (Argon2id's RFC 9106 vectors arrive with the phase 1 key store, the
//! first user of Argon2id.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
#![allow(
    unused_crate_dependencies,
    reason = "an integration test sees every dependency of the crate"
)]

use ed25519_dalek::Signer as _;
use licketysync_keys::{Suite, WriteKey, WriteSecret};
use serde_json::Value;

fn load(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn vector_ed25519_rfc8032() {
    let v = load(include_str!("vectors/ed25519_rfc8032.json"));
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let sk: [u8; 32] = bytes(&case["secret_key"]).try_into().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&sk);
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            bytes(&case["public_key"])
        );
        let msg = bytes(&case["message"]);
        let sig = key.sign(&msg);
        assert_eq!(sig.to_bytes().to_vec(), bytes(&case["signature"]));
        assert!(key.verifying_key().verify_strict(&msg, &sig).is_ok());
    }
}

#[test]
fn vector_bip39_trezor_english() {
    let v = load(include_str!("vectors/bip39_trezor.json"));
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 8, "every 256-bit entry of the Trezor list");
    for case in cases {
        let entropy: [u8; 32] = bytes(&case["entropy"]).try_into().unwrap();
        let key = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(entropy)).unwrap();
        assert_eq!(
            key.to_words().unwrap().as_str(),
            case["mnemonic"].as_str().unwrap()
        );
        let back = WriteKey::from_words(case["mnemonic"].as_str().unwrap()).unwrap();
        assert!(bool::from(back.secret().ct_eq(key.secret())));
    }
}
