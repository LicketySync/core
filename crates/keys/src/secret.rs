// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Secret types (`suites.md` section 4.1, TM-6). Every 32-byte secret in the
//! system has its own type here so that a data key cannot be passed where a
//! chunk key is expected. Each type zeroizes on drop, prints `[redacted]`, has
//! no `Display`, no `Serialize`, no `Clone` and no `==`.
//!
//! Outside this crate a secret can be made only where a caller owns its
//! source: a [`WriteSecret`], a [`DeviceSeed`] and a [`LinkSecret`] are drawn
//! from the caller's randomness or read from bytes the caller holds (a key
//! store). Every other key is derived here and never built from bytes outside
//! the crate. No secret's bytes leave the crate except through the explicit
//! export paths (key strings, words, the stored form, the libp2p seed), and
//! the public secret types compare only in constant time, through `ct_eq`
//! (`suites.md` 4.2). Inside the crate, `expose` names every place the bytes
//! leave their type, so that a reviewer can find them.
//!
//! Every secret is built in place: its bytes are written straight into the
//! zeroizing type ([`WriteSecret::generate`], the derivations), so no
//! unwiped copy is left on the way in.
//!
//! The derivations of `keys.md` sections 1.2, 3.1 and 4 below the write
//! secret are methods here, one label each: the data key of the write secret,
//! the five keys of [`DataKey`] and the two of the access key. The folder
//! signing key is [`crate::folder::WriteKey`]'s.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::labels::{self, derive_key_into};
use crate::rng::RandomFill;
use crate::suite::sizes;

macro_rules! secret32 {
    ($(#[$doc:meta])* $vis:vis $name:ident) => {
        $(#[$doc])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        $vis struct $name([u8; sizes::KEY]);

        impl $name {
            /// Builds the secret in place: `fill` writes its bytes straight
            /// into the zeroizing type, so that no copy is left behind.
            pub(crate) fn fill_with(fill: impl FnOnce(&mut [u8; sizes::KEY])) -> Self {
                let mut secret = Self([0; sizes::KEY]);
                fill(&mut secret.0);
                secret
            }

            /// The secret bytes, inside this crate only. Every call site is a
            /// place the secret leaves its zeroizing type; keep them few.
            pub(crate) fn expose(&self) -> &[u8; sizes::KEY] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}([redacted])", stringify!($name))
            }
        }
    };
}

/// Constant-time equality for the secret types that are public.
macro_rules! public_ct_eq {
    ($($name:ident),*) => {$(
        impl $name {
            /// Constant-time equality (`suites.md` section 4.2).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }
    )*};
}

/// Construction from bytes the caller holds and from the caller's randomness,
/// for the secrets that are drawn rather than derived.
macro_rules! drawn {
    ($($name:ident),*) => {$(
        impl $name {
            /// Wraps 32 bytes the caller already holds (from a key store, a
            /// decoded key string). The caller's copy, which this function
            /// received by value, is wiped before it returns.
            #[must_use]
            pub fn from_bytes(mut bytes: [u8; sizes::KEY]) -> Self {
                let secret = Self::fill_with(|out| *out = bytes);
                bytes.zeroize();
                secret
            }

            /// Draws 32 fresh bytes from the caller's randomness straight into
            /// the secret (`suites.md` section 4.3: the operating system's
            /// generator in production, the simulator's seeded one in
            /// simulator runs).
            #[must_use]
            pub fn generate(rng: &mut RandomFill<'_>) -> Self {
                Self::fill_with(|out| rng(out))
            }
        }
    )*};
}

secret32! {
    /// The write secret `ws` (`keys.md` 1.1): 32 random bytes, the folder's
    /// write key. Everything else of the folder derives from it.
    pub WriteSecret
}

secret32! {
    /// The data key `dk` (section 1.2), the folder's for its whole life;
    /// the read key carries it.
    pub DataKey
}

secret32! {
    /// The access key `ak` (section 3.1): the sealed key's secret, which every
    /// tier holds. It keys nothing itself: it is the parent of the
    /// handshake's hint key and payload key (section 4).
    pub(crate) AccessKey
}

secret32! {
    /// The hint key (section 4): the keyed-BLAKE3 key of the folder hint.
    pub(crate) HintKey
}

secret32! {
    /// The payload key (section 4): the keyed-BLAKE3 key that gives each
    /// connection's proof key.
    pub(crate) PayloadKey
}

secret32! {
    /// `ck`, the `XChaCha` key for chunk ciphertext (section 3.2).
    pub(crate) ChunkKey
}

secret32! {
    /// `nk`, the keyed-BLAKE3 key for convergent chunk nonces (section 3.2).
    pub(crate) ChunkNonceKey
}

secret32! {
    /// `hk`, the keyed-BLAKE3 key over plaintext chunks (section 3.2, TM-14).
    pub(crate) ChunkHashKey
}

secret32! {
    /// `rk`, the `XChaCha` key for the sealed metadata of index records
    /// (section 3.4).
    pub RecordKey
}

secret32! {
    /// A device seed (section 8.1): 32 random bytes drawn at first run, from
    /// which the device key, the libp2p identity and the DHT key derive.
    pub DeviceSeed
}

secret32! {
    /// A link secret: the 32 fresh bytes in a link code (section 8.3, phase 5).
    pub LinkSecret
}

secret32! {
    /// The keyed-BLAKE3 key for the link proof (section 8.3).
    pub LinkConfirmKey
}

secret32! {
    /// The handshake's proof key (section 4): `BLAKE3_keyed(payload_key,
    /// folder_id || th)`, the `XChaCha` key of one connection's `FolderProof`
    /// payload ([`crate::handshake::HandshakeKeys::seal_proof`]).
    pub(crate) ProofKey
}

public_ct_eq!(
    WriteSecret,
    DataKey,
    RecordKey,
    DeviceSeed,
    LinkSecret,
    LinkConfirmKey
);
drawn!(WriteSecret, DeviceSeed, LinkSecret);

impl WriteSecret {
    /// `dk = derive_key("licketysync/v1/folder/data-key", ws)` (section 1.2).
    pub(crate) fn data_key(&self) -> DataKey {
        DataKey::fill_with(|out| derive_key_into(labels::FOLDER_DATA_KEY, &self.0, out))
    }
}

impl DataKey {
    /// `ak = derive_key("licketysync/v1/data/access-key", dk)`.
    pub(crate) fn access_key(&self) -> AccessKey {
        AccessKey::fill_with(|out| derive_key_into(labels::DATA_ACCESS_KEY, &self.0, out))
    }

    /// `ck = derive_key("licketysync/v1/data/chunk-key", dk)`.
    pub(crate) fn chunk_key(&self) -> ChunkKey {
        ChunkKey::fill_with(|out| derive_key_into(labels::DATA_CHUNK_KEY, &self.0, out))
    }

    /// `nk = derive_key("licketysync/v1/data/chunk-nonce-key", dk)`.
    pub(crate) fn chunk_nonce_key(&self) -> ChunkNonceKey {
        ChunkNonceKey::fill_with(|out| derive_key_into(labels::DATA_CHUNK_NONCE_KEY, &self.0, out))
    }

    /// `hk = derive_key("licketysync/v1/data/chunk-hash-key", dk)`.
    pub(crate) fn chunk_hash_key(&self) -> ChunkHashKey {
        ChunkHashKey::fill_with(|out| derive_key_into(labels::DATA_CHUNK_HASH_KEY, &self.0, out))
    }

    /// `rk = derive_key("licketysync/v1/data/record-key", dk)`: the key that
    /// [`crate::sealed_meta`] seals and opens index records' metadata under.
    #[must_use]
    pub fn record_key(&self) -> RecordKey {
        RecordKey::fill_with(|out| derive_key_into(labels::DATA_RECORD_KEY, &self.0, out))
    }
}

impl AccessKey {
    /// `hint_key = derive_key("licketysync/v1/handshake/hint-key", ak)`.
    pub(crate) fn hint_key(&self) -> HintKey {
        HintKey::fill_with(|out| derive_key_into(labels::HANDSHAKE_HINT_KEY, &self.0, out))
    }

    /// `payload_key = derive_key("licketysync/v1/handshake/payload-key", ak)`.
    pub(crate) fn payload_key(&self) -> PayloadKey {
        PayloadKey::fill_with(|out| derive_key_into(labels::HANDSHAKE_PAYLOAD_KEY, &self.0, out))
    }
}

/// A plaintext buffer that is zeroized on drop: decrypted chunks and
/// metadata, encoded key strings and words, anything that held secret bytes on
/// its way through.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Compile-time guards (TM-6): every type in this crate or its dependencies
/// that holds secret material wipes it on drop. Building fails if a feature
/// change (such as `chacha20poly1305` without `zeroize`) removes one.
const _: () = {
    const fn zeroize_on_drop<T: ZeroizeOnDrop + ?Sized>() {}
    zeroize_on_drop::<WriteSecret>();
    zeroize_on_drop::<DataKey>();
    zeroize_on_drop::<AccessKey>();
    zeroize_on_drop::<ChunkKey>();
    zeroize_on_drop::<ChunkNonceKey>();
    zeroize_on_drop::<ChunkHashKey>();
    zeroize_on_drop::<RecordKey>();
    zeroize_on_drop::<HintKey>();
    zeroize_on_drop::<PayloadKey>();
    zeroize_on_drop::<DeviceSeed>();
    zeroize_on_drop::<LinkSecret>();
    zeroize_on_drop::<LinkConfirmKey>();
    zeroize_on_drop::<ProofKey>();
    zeroize_on_drop::<SecretBytes>();
    zeroize_on_drop::<Zeroizing<[u8; 32]>>();
    zeroize_on_drop::<Zeroizing<String>>();
    // The cipher, the private keys and the word list the crate holds secrets in.
    zeroize_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
    zeroize_on_drop::<ed25519_dalek::SigningKey>();
    zeroize_on_drop::<bip39::Mnemonic>();
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;
    use crate::labels::derive_key;

    #[test]
    fn debug_is_redacted_and_bytes_round_trip() {
        let s = WriteSecret::from_bytes([7u8; 32]);
        assert_eq!(format!("{s:?}"), "WriteSecret([redacted])");
        assert_eq!(
            format!("{:?}", DataKey::fill_with(|o| *o = [1; 32])),
            "DataKey([redacted])"
        );
        assert_eq!(
            format!("{:?}", ProofKey::fill_with(|o| *o = [1; 32])),
            "ProofKey([redacted])"
        );
        assert_eq!(s.expose(), &[7u8; 32]);
        assert!(bool::from(s.ct_eq(&WriteSecret::from_bytes([7u8; 32]))));
        assert!(!bool::from(s.ct_eq(&WriteSecret::from_bytes([8u8; 32]))));
        let seed = DeviceSeed::from_bytes([2; 32]);
        assert!(bool::from(seed.ct_eq(&DeviceSeed::from_bytes([2; 32]))));
        assert!(!bool::from(seed.ct_eq(&DeviceSeed::from_bytes([3; 32]))));
        let link = LinkSecret::from_bytes([4; 32]);
        assert_eq!(link.expose(), &[4; 32]);
    }

    #[test]
    fn generate_draws_from_the_caller_straight_into_the_secret() {
        let mut calls = 0usize;
        let mut fill = |buf: &mut [u8]| {
            calls += 1;
            assert_eq!(buf.len(), 32);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = u8::try_from(i).unwrap_or(0);
            }
        };
        let k = WriteSecret::generate(&mut fill);
        assert_eq!(calls, 1);
        assert_eq!(k.expose()[31], 31);
        let mut ones = |buf: &mut [u8]| buf.fill(1);
        assert_eq!(DeviceSeed::generate(&mut ones).expose(), &[1; 32]);
        assert_eq!(LinkSecret::generate(&mut ones).expose(), &[1; 32]);
    }

    /// Each derived key is `derive_key` under its own label from its own
    /// parent (`keys.md` 1.2): no two are equal, and none equals its parent.
    #[test]
    fn derivations_use_one_label_each() {
        let ws = WriteSecret::from_bytes([3u8; 32]);
        let dk = ws.data_key();
        assert_eq!(
            dk.expose(),
            &*derive_key(labels::FOLDER_DATA_KEY, ws.expose())
        );
        let derived = [
            (*dk.access_key().expose(), labels::DATA_ACCESS_KEY),
            (*dk.chunk_key().expose(), labels::DATA_CHUNK_KEY),
            (*dk.chunk_nonce_key().expose(), labels::DATA_CHUNK_NONCE_KEY),
            (*dk.chunk_hash_key().expose(), labels::DATA_CHUNK_HASH_KEY),
            (*dk.record_key().expose(), labels::DATA_RECORD_KEY),
        ];
        let mut all = vec![*ws.expose(), *dk.expose()];
        for (key, label) in derived {
            assert_eq!(key, *derive_key(label, dk.expose()), "{}", label.as_str());
            assert!(!all.contains(&key), "{} repeats a key", label.as_str());
            all.push(key);
        }
        let ak = dk.access_key();
        for (key, label) in [
            (*ak.hint_key().expose(), labels::HANDSHAKE_HINT_KEY),
            (*ak.payload_key().expose(), labels::HANDSHAKE_PAYLOAD_KEY),
        ] {
            assert_eq!(key, *derive_key(label, ak.expose()), "{}", label.as_str());
            assert!(!all.contains(&key), "{} repeats a key", label.as_str());
            all.push(key);
        }
        let rk = dk.record_key();
        assert!(bool::from(rk.ct_eq(&dk.record_key())));
        assert!(!bool::from(
            rk.ct_eq(&RecordKey::fill_with(|o| *o = [0; 32]))
        ));
    }
}
