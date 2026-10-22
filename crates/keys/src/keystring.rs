// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key strings, links and files (`keys.md` section 6): what one person hands
//! another. A key string is Bech32m (BIP-350) over one tier's payload, with
//! one prefix per tier:
//!
//! ```text
//! payload_write  = be16(suite) || ws                     # 34 bytes, "lsw", 65 characters
//! payload_read   = be16(suite) || folder_vk || dk        # 66 bytes, "lsr", 116 characters
//! payload_sealed = be16(suite) || folder_vk || ak        # 66 bytes, "lss", 116 characters
//! ```
//!
//! The link carries a key string after `#`, where browsers never send it
//! (TM-18), optionally with dialling addresses and a certificate hash; the
//! `.lskey` file is the link on one line (phase 1). A key string carries only
//! the suite, the tier's key material and a checksum (TM-37).

use core::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bech32::primitives::decode::{
    CharError, CheckedHrpstring, CheckedHrpstringError, UncheckedHrpstringError,
};
use bech32::{Bech32m, ByteIterExt as _, Fe32IterExt as _, Hrp};
use zeroize::Zeroizing;

use crate::folder::{FolderKey, KeyError};
use crate::secret::SecretBytes;
use crate::suite::{sizes, Tier};

/// The write key string's prefix.
pub const HRP_WRITE: &str = "lsw";
/// The read key string's prefix.
pub const HRP_READ: &str = "lsr";
/// The sealed key string's prefix.
pub const HRP_SEALED: &str = "lss";
/// The longest Bech32m string decoded: a read or sealed key string. The
/// `bech32` crate's 90-character segwit limit does not apply (`keys.md` 6.1).
pub const MAX_KEY_STRING_LEN: usize = sizes::READ_KEY_STRING;

const _: () = assert!(
    MAX_KEY_STRING_LEN >= sizes::WRITE_KEY_STRING && MAX_KEY_STRING_LEN >= sizes::SEALED_KEY_STRING
);

/// The prefix of a tier's key string.
fn hrp_of(tier: Tier) -> &'static Hrp {
    const WRITE: Hrp = Hrp::parse_unchecked(HRP_WRITE);
    const READ: Hrp = Hrp::parse_unchecked(HRP_READ);
    const SEALED: Hrp = Hrp::parse_unchecked(HRP_SEALED);
    match tier {
        Tier::Write => &WRITE,
        Tier::Read => &READ,
        Tier::Sealed => &SEALED,
    }
}

/// Why a Bech32m string was refused (`keys.md` 6.1). All are malformed but
/// [`KeyError::UnimplementedSuite`] inside [`KeyStringError::Key`], which says
/// the key needs a newer release of Lickety-Sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStringError {
    /// Longer than any key string.
    TooLong,
    /// Upper and lower case mixed.
    MixedCase,
    /// A character outside the alphabet, or no separator.
    Character,
    /// The Bech32m checksum fails (a Bech32 checksum included).
    Checksum,
    /// A prefix this decoder does not take.
    Prefix,
    /// The bits after the last whole byte are five or more, or one of them
    /// is not zero (BIP-173).
    Padding,
    /// The payload is refused, in the order of `keys.md` 6.1: shorter than
    /// its suite, suite 0, a suite this release does not implement, a length
    /// that is not its prefix's under that suite, or a verification key that
    /// is not canonical or is of small order.
    Key(KeyError),
}

impl fmt::Display for KeyStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("too long"),
            Self::MixedCase => f.write_str("mixed case"),
            Self::Character => f.write_str("invalid character"),
            Self::Checksum => f.write_str("checksum does not match"),
            Self::Prefix => f.write_str("wrong prefix"),
            Self::Padding => f.write_str("invalid padding"),
            Self::Key(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KeyStringError {}

/// Encodes `payload` as a Bech32m string under `hrp`, lower or upper case,
/// into a buffer of the final length so that no reallocation leaves a copy
/// of the secret behind.
pub(crate) fn bech32m_encode(hrp: &Hrp, payload: &[u8], upper: bool) -> Zeroizing<String> {
    let len = hrp.len() + 1 + (8 * payload.len()).div_ceil(5) + 6;
    let mut s = Zeroizing::new(String::with_capacity(len));
    for c in payload
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(hrp)
        .chars()
    {
        s.push(if upper { c.to_ascii_uppercase() } else { c });
    }
    s
}

/// Decodes a Bech32m string whose prefix is one of `prefixes` to the value
/// paired with that prefix and the payload, of whatever length the string
/// carries: the payload's length is judged by the caller, after the suite
/// (`keys.md` 6.1). Refuses, in this order: a string over
/// [`MAX_KEY_STRING_LEN`], mixed case, a character outside the alphabet, a
/// bad or Bech32 (non-m) checksum, another prefix, and padding that is five
/// bits or more or not zero.
pub(crate) fn bech32m_decode<T: Copy>(
    s: &str,
    prefixes: &[(&Hrp, T)],
) -> Result<(T, SecretBytes), KeyStringError> {
    if s.len() > MAX_KEY_STRING_LEN {
        return Err(KeyStringError::TooLong);
    }
    let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|e| match e {
        CheckedHrpstringError::Parse(UncheckedHrpstringError::Char(CharError::MixedCase)) => {
            KeyStringError::MixedCase
        }
        CheckedHrpstringError::Checksum(_) => KeyStringError::Checksum,
        _ => KeyStringError::Character,
    })?;
    let value = prefixes
        .iter()
        .find(|(hrp, _)| checked.hrp() == **hrp)
        .map(|(_, value)| *value)
        .ok_or(KeyStringError::Prefix)?;
    // The bits after the last whole byte: fewer than five, and all zero.
    let bits = 5 * checked.data_part_ascii_no_checksum().len();
    let pad_bits = bits % 8;
    let last = checked.fe32_iter().last().map_or(0, bech32::Fe32::to_u8);
    if pad_bits >= 5 || last & ((1u8 << pad_bits) - 1) != 0 {
        return Err(KeyStringError::Padding);
    }
    // Sized once for the whole payload, so that no reallocation leaves a copy.
    let mut out = Zeroizing::new(Vec::with_capacity(bits / 8));
    out.extend(checked.byte_iter());
    Ok((value, out))
}

impl FolderKey {
    /// The key string in lower case, for text and links.
    #[must_use]
    pub fn to_key_string(&self) -> Zeroizing<String> {
        bech32m_encode(hrp_of(self.tier()), &self.payload(), false)
    }

    /// The key string in upper case, for QR codes (alphanumeric mode).
    #[must_use]
    pub fn to_qr_string(&self) -> Zeroizing<String> {
        bech32m_encode(hrp_of(self.tier()), &self.payload(), true)
    }

    /// Parses a key string, all lower or all upper case, of any tier, in the
    /// order of `keys.md` 6.1: the Bech32m string, then the payload
    /// ([`FolderKey::from_payload`]: its suite before its length). The
    /// decoded payload is zeroized as soon as the key is built.
    ///
    /// # Errors
    ///
    /// [`KeyStringError`]; a suite this release does not implement is
    /// [`KeyStringError::Key`] with [`KeyError::UnimplementedSuite`].
    pub fn from_key_string(s: &str) -> Result<FolderKey, KeyStringError> {
        let (tier, payload) = bech32m_decode(s, &Tier::ALL.map(|t| (hrp_of(t), t)))?;
        FolderKey::from_payload(tier, &payload).map_err(KeyStringError::Key)
    }
}

/// The link prefix: the browser client's join page, with the secret after `#`.
pub const LINK_PREFIX: &str = "https://licketysync.dev/join#";
/// The longest link or key file accepted.
pub const MAX_LINK_LEN: usize = 8_192;
/// The most addresses a link carries.
pub const MAX_LINK_ADDRESSES: usize = 16;
/// The longest address or certificate hash in a link, in bytes.
pub const MAX_LINK_ITEM: usize = 256;

/// Why a link or key file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Longer than [`MAX_LINK_LEN`].
    TooLong,
    /// Not `https://licketysync.dev/join#...`: the secret must sit after `#`.
    Prefix,
    /// A parameter that is not `k`, `a` or `c`, or one without `=`.
    Parameter,
    /// `k` missing or repeated, `c` repeated, or more than 16 `a`.
    Count,
    /// The key string is invalid.
    Key(KeyStringError),
    /// `c` is not base64url.
    Encoding,
    /// An address or certificate hash is empty, too long, or holds a
    /// character a link cannot carry.
    Item,
    /// A key file is not one line.
    NotOneLine,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("link too long"),
            Self::Prefix => f.write_str("not a join link"),
            Self::Parameter => f.write_str("unknown link parameter"),
            Self::Count => f.write_str("link parameters repeated or missing"),
            Self::Key(e) => write!(f, "key string: {e}"),
            Self::Encoding => f.write_str("link data does not decode"),
            Self::Item => f.write_str("invalid address or certificate hash"),
            Self::NotOneLine => f.write_str("a key file is one line"),
        }
    }
}

impl std::error::Error for LinkError {}

/// A join link (`keys.md` 6.3, phase 1): the key string after `#`, and,
/// only by the sender's choice, dialling hints (`a`) and a certificate hash
/// (`c`). The folder is the one the key names; an address is a hint for
/// dialling, never an identity.
#[derive(Debug)]
pub struct Link {
    /// The key.
    pub key: FolderKey,
    /// Multiaddresses to dial, as text.
    pub addresses: Vec<String>,
    /// A certificate hash for browser transports.
    pub cert_hash: Option<Vec<u8>>,
}

/// An address may hold printable ASCII except the link's own delimiters.
fn item_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LINK_ITEM
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'&' | b'#' | b'='))
}

impl Link {
    /// A bare link: the key string and nothing else, as invites are by
    /// default (TM-37).
    #[must_use]
    pub fn bare(key: FolderKey) -> Self {
        Link {
            key,
            addresses: Vec::new(),
            cert_hash: None,
        }
    }

    /// The link text.
    ///
    /// # Errors
    ///
    /// [`LinkError::Item`] for an address a link cannot carry or a
    /// certificate hash of the wrong size; [`LinkError::Count`] for too many
    /// addresses.
    pub fn to_text(&self) -> Result<Zeroizing<String>, LinkError> {
        self.text_with_room(0)
    }

    /// The link text in a buffer sized up front for the whole link and
    /// `extra` more bytes, so that no reallocation leaves a copy of the key
    /// behind. The public parts are encoded first, the key last.
    fn text_with_room(&self, extra: usize) -> Result<Zeroizing<String>, LinkError> {
        if self.addresses.len() > MAX_LINK_ADDRESSES {
            return Err(LinkError::Count);
        }
        if !self.addresses.iter().all(|a| item_ok(a)) {
            return Err(LinkError::Item);
        }
        if self
            .cert_hash
            .as_ref()
            .is_some_and(|c| c.is_empty() || c.len() > MAX_LINK_ITEM)
        {
            return Err(LinkError::Item);
        }
        let cert = self.cert_hash.as_ref().map(|c| URL_SAFE_NO_PAD.encode(c));
        let key = self.key.to_key_string();
        let len = LINK_PREFIX.len()
            + 2
            + key.len()
            + self.addresses.iter().map(|a| 3 + a.len()).sum::<usize>()
            + cert.as_ref().map_or(0, |c| 3 + c.len())
            + extra;
        let mut s = Zeroizing::new(String::with_capacity(len));
        s.push_str(LINK_PREFIX);
        s.push_str("k=");
        s.push_str(&key);
        for a in &self.addresses {
            s.push_str("&a=");
            s.push_str(a);
        }
        if let Some(c) = &cert {
            s.push_str("&c=");
            s.push_str(c);
        }
        Ok(s)
    }

    /// Parses a link. Only the exact prefix [`LINK_PREFIX`] is accepted, so
    /// the secret is always in the fragment and never in a path or query.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    pub fn parse(text: &str) -> Result<Link, LinkError> {
        if text.len() > MAX_LINK_LEN {
            return Err(LinkError::TooLong);
        }
        let fragment = text.strip_prefix(LINK_PREFIX).ok_or(LinkError::Prefix)?;
        let (mut key, mut addresses, mut cert_hash) = (None, Vec::new(), None);
        for param in fragment.split('&') {
            let (name, value) = param.split_once('=').ok_or(LinkError::Parameter)?;
            match name {
                "k" if key.is_none() => {
                    key = Some(FolderKey::from_key_string(value).map_err(LinkError::Key)?);
                }
                "a" if addresses.len() < MAX_LINK_ADDRESSES => {
                    if !item_ok(value) {
                        return Err(LinkError::Item);
                    }
                    addresses.push(value.to_string());
                }
                "c" if cert_hash.is_none() => {
                    let c = URL_SAFE_NO_PAD
                        .decode(value)
                        .map_err(|_| LinkError::Encoding)?;
                    if c.is_empty() || c.len() > MAX_LINK_ITEM {
                        return Err(LinkError::Item);
                    }
                    cert_hash = Some(c);
                }
                "k" | "a" | "c" => return Err(LinkError::Count),
                _ => return Err(LinkError::Parameter),
            }
        }
        Ok(Link {
            key: key.ok_or(LinkError::Count)?,
            addresses,
            cert_hash,
        })
    }

    /// The `.lskey` file form (`keys.md` 6.4): the link text on one line.
    ///
    /// # Errors
    ///
    /// As [`Link::to_text`].
    pub fn to_file(&self) -> Result<Zeroizing<String>, LinkError> {
        let mut s = self.text_with_room(1)?;
        s.push('\n');
        Ok(s)
    }

    /// Parses a `.lskey` file: one line of UTF-8, with at most one trailing
    /// line ending (`\n` or `\r\n`).
    ///
    /// # Errors
    ///
    /// [`LinkError::NotOneLine`] or as [`Link::parse`].
    pub fn parse_file(text: &str) -> Result<Link, LinkError> {
        let line = text
            .strip_suffix('\n')
            .map_or(text, |t| t.strip_suffix('\r').unwrap_or(t));
        if line.contains(['\n', '\r']) {
            return Err(LinkError::NotOneLine);
        }
        Link::parse(line)
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
    use super::*;
    use crate::folder::tests::write_key;
    use crate::suite::SuiteError;
    use bech32::Fe32;

    fn tiers(byte: u8) -> [FolderKey; 3] {
        let w = write_key(byte);
        let r = w.read_key();
        let s = w.sealed_key();
        [w.into(), r.into(), s.into()]
    }

    #[test]
    fn key_strings_round_trip_in_both_cases() {
        for (key, (hrp, len)) in tiers(1)
            .iter()
            .zip([("lsw1", 65), ("lsr1", 116), ("lss1", 116)])
        {
            let lower = key.to_key_string();
            let upper = key.to_qr_string();
            assert_eq!(lower.len(), len);
            assert_eq!(lower.capacity(), len, "written into a buffer of its length");
            assert_eq!(upper.capacity(), len);
            assert!(lower.starts_with(hrp));
            assert_eq!(*upper, lower.to_ascii_uppercase());
            // The iterator encoder agrees with the crate's own.
            let reference = bech32::encode::<Bech32m>(*hrp_of(key.tier()), &key.payload()).unwrap();
            assert_eq!(*lower, reference);
            for s in [&*lower, &*upper] {
                let back = FolderKey::from_key_string(s).unwrap();
                assert_eq!(back.tier(), key.tier());
                assert_eq!(*back.payload(), *key.payload());
            }
        }
    }

    #[test]
    fn key_string_rejections() {
        let [w, r, _] = tiers(2);
        let s = r.to_key_string().to_string();
        // Mixed case.
        let mut mixed = s.clone();
        mixed.replace_range(5..6, &mixed[5..6].to_ascii_uppercase());
        assert_eq!(
            FolderKey::from_key_string(&mixed).unwrap_err(),
            KeyStringError::MixedCase
        );
        // Every single changed character in the data is caught.
        let alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for i in 4..s.len() {
            let c = s.as_bytes()[i] as char;
            let other = alphabet.chars().find(|&x| x != c).unwrap();
            let mut flipped = s.clone();
            flipped.replace_range(i..=i, &other.to_string());
            assert!(FolderKey::from_key_string(&flipped).is_err(), "flip at {i}");
        }
        let payload = r.payload();
        let lsl = bech32m_encode(&Hrp::parse_unchecked("lsl"), &payload, false);
        assert_eq!(
            FolderKey::from_key_string(&lsl).unwrap_err(),
            KeyStringError::Prefix
        );
        let bech32 = bech32::encode::<bech32::Bech32>(*hrp_of(Tier::Read), &payload).unwrap();
        assert_eq!(
            FolderKey::from_key_string(&bech32).unwrap_err(),
            KeyStringError::Checksum
        );
        // A read payload under lsw and a write payload under lsr: suite 1,
        // then the wrong length for the prefix.
        let length = |tier: Tier, found: usize| {
            KeyStringError::Key(KeyError::Length {
                expected: crate::folder::payload_len(tier),
                found,
            })
        };
        let read_as_write = bech32m_encode(hrp_of(Tier::Write), &payload, false);
        assert_eq!(
            FolderKey::from_key_string(&read_as_write).unwrap_err(),
            length(Tier::Write, 66)
        );
        let write_as_read = bech32m_encode(hrp_of(Tier::Read), &w.payload(), false);
        assert_eq!(
            FolderKey::from_key_string(&write_as_read).unwrap_err(),
            length(Tier::Read, 34)
        );
        // One byte short and one long; one byte and none at all.
        let short = bech32m_encode(hrp_of(Tier::Read), &payload[..65], false);
        assert_eq!(
            FolderKey::from_key_string(&short).unwrap_err(),
            length(Tier::Read, 65)
        );
        let long = bech32m_encode(
            hrp_of(Tier::Write),
            &[&w.payload()[..], &[0]].concat(),
            false,
        );
        assert_eq!(
            FolderKey::from_key_string(&long).unwrap_err(),
            length(Tier::Write, 35)
        );
        for (tier, p) in [(Tier::Sealed, &[1u8][..]), (Tier::Write, &[][..])] {
            assert_eq!(
                FolderKey::from_key_string(&bech32m_encode(hrp_of(tier), p, false)).unwrap_err(),
                length(tier, p.len())
            );
        }
        // Suite 0 and an unimplemented suite, at suite 1's length and at
        // another: the suite is judged first.
        let mut zero = payload.to_vec();
        zero[1] = 0;
        assert_eq!(
            FolderKey::from_key_string(&bech32m_encode(hrp_of(Tier::Read), &zero, false))
                .unwrap_err(),
            KeyStringError::Key(KeyError::Suite(SuiteError::Zero))
        );
        let mut newer = w.payload().to_vec();
        newer[1] = 2;
        for p in [&newer[..], &newer[..2], &[&newer[..], &[9; 20]].concat()] {
            let e = FolderKey::from_key_string(&bech32m_encode(hrp_of(Tier::Write), p, false))
                .unwrap_err();
            assert_eq!(e, KeyStringError::Key(KeyError::UnimplementedSuite(2)));
            assert_eq!(
                e.to_string(),
                "this key needs a newer release of Lickety-Sync"
            );
        }
        // A verification key of small order.
        let mut small = payload.to_vec();
        small[2..34].fill(0);
        small[2] = 1;
        assert_eq!(
            FolderKey::from_key_string(&bech32m_encode(hrp_of(Tier::Sealed), &small, false))
                .unwrap_err(),
            KeyStringError::Key(KeyError::VerifyingKey)
        );
        assert_eq!(
            FolderKey::from_key_string("lsw1").unwrap_err(),
            KeyStringError::Checksum
        );
        assert_eq!(
            FolderKey::from_key_string("lsw1\u{e9}").unwrap_err(),
            KeyStringError::Character
        );
        assert_eq!(
            FolderKey::from_key_string("no separator").unwrap_err(),
            KeyStringError::Character
        );
        assert_eq!(
            FolderKey::from_key_string(&"q".repeat(117)).unwrap_err(),
            KeyStringError::TooLong
        );
        // Exactly at the cap is decoded: a 116-character string is no TooLong.
        assert_eq!(
            FolderKey::from_key_string(&"q".repeat(MAX_KEY_STRING_LEN)).unwrap_err(),
            KeyStringError::Character
        );
        for e in [
            KeyStringError::TooLong,
            KeyStringError::MixedCase,
            KeyStringError::Character,
            KeyStringError::Checksum,
            KeyStringError::Prefix,
            KeyStringError::Padding,
            KeyStringError::Key(KeyError::VerifyingKey),
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    /// The field elements of `payload` with the last one replaced by `last`,
    /// as a Bech32m string under `tier`'s prefix.
    fn with_last_fe(tier: Tier, payload: &[u8], last: u8) -> String {
        let mut fes: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
        *fes.last_mut().unwrap() = Fe32::try_from(last).unwrap();
        fes.iter()
            .copied()
            .with_checksum::<Bech32m>(hrp_of(tier))
            .chars()
            .collect()
    }

    #[test]
    fn non_zero_padding_is_rejected() {
        // 34 bytes are 272 bits: 55 characters, the last 3 bits padding; 66
        // bytes are 106 characters with 2 padding bits.
        for (tier, chars, pad) in [(Tier::Write, 55, 3u8), (Tier::Read, 106, 2)] {
            let mut payload = vec![0u8; crate::folder::payload_len(tier)];
            payload[1] = 1;
            assert_eq!(payload.iter().copied().bytes_to_fes().count(), chars);
            for bit in 0..pad {
                assert_eq!(
                    FolderKey::from_key_string(&with_last_fe(tier, &payload, 1 << bit))
                        .unwrap_err(),
                    KeyStringError::Padding,
                    "{tier:?} bit {bit}"
                );
            }
        }
        // A data part that ends in five padding bits or more is not the
        // encoding of whole bytes: 1, 3 or 6 characters past a multiple of 8.
        for chars in [1usize, 3, 6, 9, 11] {
            let fes = vec![Fe32::Q; chars];
            let s: String = fes
                .iter()
                .copied()
                .with_checksum::<Bech32m>(hrp_of(Tier::Write))
                .chars()
                .collect();
            assert_eq!(
                FolderKey::from_key_string(&s).unwrap_err(),
                KeyStringError::Padding,
                "{chars} characters"
            );
        }
    }

    #[test]
    fn tm_18_link_and_file_forms() {
        let [_, r, _] = tiers(3);
        let link = Link {
            key: r,
            addresses: vec![
                "/ip4/192.0.2.1/udp/4001/quic-v1".into(),
                "/dns/peer.example/tcp/4001".into(),
            ],
            cert_hash: Some(vec![1, 2, 3]),
        };
        let text = link.to_text().unwrap();
        assert_eq!(text.capacity(), text.len(), "sized once");
        assert!(text.starts_with("https://licketysync.dev/join#k=lsr1"));
        let (before, after) = text.split_once('#').unwrap();
        assert!(!before.contains("lsr1"), "the secret is only after #");
        assert!(after.contains("&a=/ip4/192.0.2.1"));
        let back = Link::parse(&text).unwrap();
        assert_eq!(back.addresses, link.addresses);
        assert_eq!(back.cert_hash, link.cert_hash);
        assert_eq!(*back.key.payload(), *link.key.payload());
        let file = link.to_file().unwrap();
        assert!(file.ends_with('\n'));
        assert_eq!(file.capacity(), file.len());
        assert_eq!(Link::parse_file(&file).unwrap().addresses.len(), 2);
        assert_eq!(
            Link::parse_file(&format!("{}\r\n", text.as_str()))
                .unwrap()
                .addresses
                .len(),
            2
        );
        assert_eq!(Link::parse_file(&text).unwrap().addresses.len(), 2);
        assert_eq!(
            Link::parse_file(&format!("{}\n\n", text.as_str())).unwrap_err(),
            LinkError::NotOneLine
        );
        let [w, _, _] = tiers(3);
        let bare = Link::bare(w).to_text().unwrap();
        assert_eq!(bare.len(), LINK_PREFIX.len() + 2 + 65);
    }

    #[test]
    fn link_rejections() {
        let [w, _, _] = tiers(4);
        let k = w.to_key_string().to_string();
        let p = LINK_PREFIX;
        assert_eq!(
            Link::parse(&format!("https://licketysync.dev/join?k={k}")).unwrap_err(),
            LinkError::Prefix
        );
        assert_eq!(
            Link::parse(&format!("https://other.example/join#k={k}")).unwrap_err(),
            LinkError::Prefix
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&k={k}")).unwrap_err(),
            LinkError::Count
        );
        assert_eq!(
            Link::parse(&format!("{p}a=x")).unwrap_err(),
            LinkError::Count
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&z=1")).unwrap_err(),
            LinkError::Parameter
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&g=AQID")).unwrap_err(),
            LinkError::Parameter,
            "the drafts' grant chain is gone"
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&a")).unwrap_err(),
            LinkError::Parameter
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&c=!!")).unwrap_err(),
            LinkError::Encoding
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&c=")).unwrap_err(),
            LinkError::Item
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&c=AQ&c=AQ")).unwrap_err(),
            LinkError::Count
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&a=")).unwrap_err(),
            LinkError::Item
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&a=has space")).unwrap_err(),
            LinkError::Item
        );
        let seventeen = (0..17)
            .map(|i| format!("&a=/x/{i}"))
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(
            Link::parse(&format!("{p}k={k}{seventeen}")).unwrap_err(),
            LinkError::Count
        );
        assert_eq!(
            Link::parse(&format!("{p}k=lsw1bad")).unwrap_err(),
            LinkError::Key(KeyStringError::Character)
        );
        assert_eq!(
            Link::parse(&"x".repeat(MAX_LINK_LEN + 1)).unwrap_err(),
            LinkError::TooLong
        );
        // Exactly at the cap the text is read, and refused for what it says.
        assert_eq!(
            Link::parse(&"x".repeat(MAX_LINK_LEN)).unwrap_err(),
            LinkError::Prefix
        );
        let mut l = Link::bare(w);
        l.addresses = vec!["a&b".into()];
        assert_eq!(l.to_text().unwrap_err(), LinkError::Item);
        l.addresses = vec!["/x".into(); 17];
        assert_eq!(l.to_text().unwrap_err(), LinkError::Count);
        l.addresses.clear();
        l.cert_hash = Some(vec![]);
        assert_eq!(l.to_text().unwrap_err(), LinkError::Item);
        l.cert_hash = Some(vec![0; MAX_LINK_ITEM + 1]);
        assert_eq!(l.to_file().unwrap_err(), LinkError::Item);
        // The longest link a sender can make parses.
        l.cert_hash = Some(vec![0; MAX_LINK_ITEM]);
        l.addresses = vec!["/".repeat(MAX_LINK_ITEM); MAX_LINK_ADDRESSES];
        let longest = l.to_text().unwrap();
        assert!(longest.len() <= MAX_LINK_LEN, "{}", longest.len());
        assert!(Link::parse(&longest).is_ok());
        for e in [
            LinkError::TooLong,
            LinkError::Prefix,
            LinkError::Parameter,
            LinkError::Count,
            LinkError::Key(KeyStringError::Padding),
            LinkError::Encoding,
            LinkError::Item,
            LinkError::NotOneLine,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    use proptest::prelude::*;

    fn key_strategy() -> impl Strategy<Value = FolderKey> {
        (any::<[u8; 32]>(), prop::sample::select(Tier::ALL.to_vec())).prop_map(|(ws, tier)| {
            FolderKey::from(
                crate::WriteKey::from_secret(crate::Suite::ONE, crate::WriteSecret::from_bytes(ws))
                    .unwrap(),
            )
            .lowered(tier)
            .unwrap()
        })
    }

    /// An address a link can carry: printable ASCII but `&`, `#` and `=`.
    fn address() -> impl Strategy<Value = String> {
        "[!-~&&[^&#=]]{1,40}"
    }

    proptest! {
        /// Every key string, in either case, reads back to the same key.
        #[test]
        fn key_strings_round_trip(key in key_strategy(), upper in any::<bool>()) {
            let text = if upper { key.to_qr_string() } else { key.to_key_string() };
            let back = FolderKey::from_key_string(&text).unwrap();
            prop_assert_eq!(back.tier(), key.tier());
            prop_assert_eq!(&*back.payload(), &*key.payload());
            prop_assert_eq!(&*back.to_key_string(), &*key.to_key_string());
        }

        /// Any text into the key-string parser: no panic, and what it accepts
        /// is its own key string, in one case.
        #[test]
        fn any_text_into_the_key_string_parser(text in "\\PC{0,120}") {
            if let Ok(key) = FolderKey::from_key_string(&text) {
                prop_assert_eq!(key.to_key_string().to_string(), text.to_ascii_lowercase());
            }
        }

        /// A valid key string with one character changed, inserted or removed
        /// is refused or, when the change is only of case throughout, the
        /// same key.
        #[test]
        fn edited_key_strings(key in key_strategy(), at in 0usize..116, c in "[a-z0-9]", edit in 0u8..3) {
            let mut text = key.to_key_string().to_string();
            let at = at % text.len();
            match edit {
                0 => text.replace_range(at..=at, &c),
                1 => text.insert_str(at, &c),
                _ => { text.remove(at); }
            }
            if let Ok(back) = FolderKey::from_key_string(&text) {
                prop_assert_eq!(&*back.to_key_string(), text.as_str());
                prop_assert_eq!(&*back.payload(), &*key.payload());
            }
        }

        /// A link with any addresses and certificate hash a sender may give
        /// reads back the same, as text and as a file.
        #[test]
        fn links_round_trip(
            key in key_strategy(),
            addresses in proptest::collection::vec(address(), 0..=MAX_LINK_ADDRESSES),
            cert_hash in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..=64)),
        ) {
            let link = Link { key, addresses, cert_hash };
            for back in [Link::parse(&link.to_text().unwrap()), Link::parse_file(&link.to_file().unwrap())] {
                let back = back.unwrap();
                prop_assert_eq!(&back.addresses, &link.addresses);
                prop_assert_eq!(&back.cert_hash, &link.cert_hash);
                prop_assert_eq!(&*back.key.payload(), &*link.key.payload());
            }
        }

        /// Any text into the link parsers: no panic, and what they accept
        /// writes back to a link that reads as the same.
        #[test]
        fn any_text_into_the_link_parsers(text in "\\PC{0,200}", tail in "\\PC{0,40}") {
            let k = FolderKey::from(crate::folder::tests::write_key(1)).to_key_string();
            for input in [text.clone(), format!("{LINK_PREFIX}k={}{tail}", k.as_str())] {
                for link in [Link::parse(&input), Link::parse_file(&input)].into_iter().flatten() {
                    let again = Link::parse(&link.to_text().unwrap()).unwrap();
                    prop_assert_eq!(&again.addresses, &link.addresses);
                    prop_assert_eq!(&again.cert_hash, &link.cert_hash);
                    prop_assert_eq!(&*again.key.payload(), &*link.key.payload());
                }
            }
        }
    }
}
