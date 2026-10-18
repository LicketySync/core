// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Known-answer tests of the primitives as this crate uses them (`suites.md`
//! section 4.4): RFC 8032 Ed25519, ML-DSA-65 key generation from a seed
//! (IETF LAMPS example), the X-Wing draft's vectors through `hpke`'s KEM,
//! the XChaCha20-Poly1305 draft's AEAD vector, and the BIP39 Trezor vectors
//! through this crate's phrase API. The BLAKE3 official vectors are tested in
//! the labels module, the one place this crate calls BLAKE3. The vectors are
//! the published ones, copied into `tests/vectors/` as data.

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
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, Serializable};
use licketysync_keys::aead;
use licketysync_keys::phrase::Phrase;
use licketysync_keys::MasterSecret;
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
fn vector_ml_dsa_65_seed_keygen() {
    let v = load(include_str!("vectors/mldsa65_lamps_example.json"));
    let seed: [u8; 32] = bytes(&v["seed"]).try_into().unwrap();
    let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed.into());
    assert_eq!(
        key.expanded_key().verifying_key().encode().to_vec(),
        bytes(&v["verifying_key"])
    );
}

/// Hands out the draft's encapsulation seed as the generator's output.
struct Fixed(Vec<u8>);

impl hpke::rand_core::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("X-Wing draws whole buffers")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("X-Wing draws whole buffers")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.0[..dst.len()]);
        self.0.drain(..dst.len());
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for Fixed {}

#[test]
fn vector_x_wing_draft_through_hpke() {
    let v = load(include_str!("vectors/xwing_draft.json"));
    let cases = v.as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        // The decapsulation key is the 32-byte seed, loaded as such.
        let sk = <XWing as Kem>::PrivateKey::from_bytes(&bytes(&case["sk"])).unwrap();
        assert_eq!(bytes(&case["sk"]), bytes(&case["seed"]));
        let pk = XWing::sk_to_pk(&sk);
        assert_eq!(pk.to_bytes().to_vec(), bytes(&case["pk"]));
        let ct = <XWing as Kem>::EncappedKey::from_bytes(&bytes(&case["ct"])).unwrap();
        let ss = XWing::decap(&sk, None, &ct).unwrap();
        assert_eq!(ss.0.to_vec(), bytes(&case["ss"]));
        let (ss2, ct2) =
            XWing::encap_with_rng(&pk, None, &mut Fixed(bytes(&case["eseed"]))).unwrap();
        assert_eq!(ss2.0.to_vec(), bytes(&case["ss"]));
        assert_eq!(ct2.to_bytes().to_vec(), bytes(&case["ct"]));
    }
}

#[test]
fn vector_xchacha20poly1305_draft() {
    // Through the crate's own AEAD functions, the ones the record layer and
    // the handshake's FolderProof use.
    let v = load(include_str!("vectors/xchacha20poly1305_draft03.json"));
    let key: [u8; 32] = bytes(&v["key"]).try_into().unwrap();
    let nonce: [u8; 24] = bytes(&v["nonce"]).try_into().unwrap();
    let out = aead::xchacha_seal(&key, &nonce, &bytes(&v["aad"]), &bytes(&v["plaintext"])).unwrap();
    let mut expected = bytes(&v["ciphertext"]);
    expected.extend(bytes(&v["tag"]));
    assert_eq!(out, expected);
    let back = aead::xchacha_open(&key, &nonce, &bytes(&v["aad"]), &out).unwrap();
    assert_eq!(*back, bytes(&v["plaintext"]));
}

#[test]
fn vector_bip39_trezor_english() {
    let v = load(include_str!("vectors/bip39_trezor.json"));
    for case in v["vectors"].as_array().unwrap() {
        let entropy: [u8; 32] = bytes(&case["entropy"]).try_into().unwrap();
        let ms = MasterSecret::from_bytes(entropy);
        let phrase = Phrase::from_master(&ms).unwrap();
        assert_eq!(
            phrase.to_text().as_str(),
            case["mnemonic"].as_str().unwrap()
        );
        let back = Phrase::parse(case["mnemonic"].as_str().unwrap()).unwrap();
        assert!(bool::from(back.master_secret().ct_eq(&ms)));
    }
}
