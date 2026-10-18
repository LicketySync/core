// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The key string, link and file (`keys.md` section 6): what one person hands
//! another. The key string is Bech32m (BIP-350) with the prefix `lsk` over
//! `folder_id (32) || seed (32)`, 113 characters; the link carries it after
//! `#`, where browsers never send it (TM-18), optionally with the grant chain,
//! addresses and a certificate hash; the `.lskey` file is the link on one line.
//! Key strings carry only the folder ID, the seed and a checksum (TM-37).

use core::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bech32::primitives::decode::{
    CharError, CheckedHrpstring, CheckedHrpstringError, UncheckedHrpstringError,
};
use bech32::{Bech32m, Fe32, Hrp};
use prost::Message as _;
use zeroize::Zeroizing;

use crate::ids::FolderId;
use crate::keyset::KeyPairSet;
use crate::records::{
    wire_key_bundle, FolderKeys, GrantBody, Malformed, RecordType, Rejected, SignedRecord,
};
use crate::secret::Seed;

/// The length of every key string and link code.
pub const KEY_STRING_LEN: usize = 113;
/// The link prefix: the browser client's join page, with the secret after `#`.
pub const LINK_PREFIX: &str = "https://licketysync.dev/join#";
/// The longest link or key file accepted.
pub const MAX_LINK_LEN: usize = 262_144;
/// The most records a link's bundle carries: the Folder record and 16 grants.
pub const MAX_BUNDLE_RECORDS: usize = 17;
/// The most addresses a link carries.
pub const MAX_LINK_ADDRESSES: usize = 16;
/// The longest address or certificate hash in a link, in bytes.
pub const MAX_LINK_ITEM: usize = 256;

/// Why a Bech32m string was refused (section 6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bech32Error {
    /// Longer than any key string.
    TooLong,
    /// Upper and lower case mixed.
    MixedCase,
    /// A character outside the alphabet, or no separator.
    Character,
    /// The Bech32m checksum fails (a Bech32 checksum included).
    Checksum,
    /// Another prefix.
    Prefix,
    /// The data does not decode to exactly 64 bytes.
    Length,
    /// A padding bit is not zero.
    Padding,
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "too long",
            Self::MixedCase => "mixed case",
            Self::Character => "invalid character",
            Self::Checksum => "checksum does not match",
            Self::Prefix => "wrong prefix",
            Self::Length => "wrong length",
            Self::Padding => "non-zero padding",
        })
    }
}

impl std::error::Error for Bech32Error {}

/// Encodes 64 bytes as a 113-character Bech32m string under `hrp`, lower or
/// upper case. The `bech32` crate's Bech32m code length is 1023, so its
/// encoder carries no 90-character limit.
pub(crate) fn bech32m_encode(
    hrp: &'static str,
    payload: &[u8; 64],
    upper: bool,
) -> Result<Zeroizing<String>, Bech32Error> {
    let hrp = Hrp::parse_unchecked(hrp);
    // Written into a buffer of the final length, so that no reallocation
    // leaves a copy of the secret behind (security review, BLOCKER 3).
    let len = bech32::encoded_length::<Bech32m>(hrp, payload).map_err(|_| Bech32Error::TooLong)?;
    let mut s = Zeroizing::new(String::with_capacity(len));
    let written = if upper {
        bech32::encode_upper_to_fmt::<Bech32m, String>(&mut s, hrp, payload)
    } else {
        bech32::encode_lower_to_fmt::<Bech32m, String>(&mut s, hrp, payload)
    };
    written.map_err(|_| Bech32Error::TooLong)?;
    Ok(s)
}

/// Decodes a 113-character Bech32m string under `hrp` to its 64 bytes,
/// rejecting mixed case, a bad or Bech32 (non-m) checksum, another prefix,
/// another length and a non-zero padding bit.
pub(crate) fn bech32m_decode(
    hrp: &'static str,
    s: &str,
) -> Result<Zeroizing<[u8; 64]>, Bech32Error> {
    if s.len() > 1023 {
        return Err(Bech32Error::TooLong);
    }
    let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|e| match e {
        CheckedHrpstringError::Parse(UncheckedHrpstringError::Char(CharError::MixedCase)) => {
            Bech32Error::MixedCase
        }
        CheckedHrpstringError::Checksum(_) => Bech32Error::Checksum,
        _ => Bech32Error::Character,
    })?;
    if checked.hrp() != Hrp::parse_unchecked(hrp) {
        return Err(Bech32Error::Prefix);
    }
    let data = checked.data_part_ascii_no_checksum();
    // 64 bytes are 512 bits: 103 characters of 5 bits, the last 3 bits padding.
    if data.len() != 103 {
        return Err(Bech32Error::Length);
    }
    let last = data
        .last()
        .and_then(|c| Fe32::from_char(char::from(*c)).ok())
        .ok_or(Bech32Error::Character)?;
    if last.to_u8() & 0b111 != 0 {
        return Err(Bech32Error::Padding);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    let mut n = 0usize;
    for (slot, byte) in out.iter_mut().zip(checked.byte_iter()) {
        *slot = byte;
        n += 1;
    }
    if n == 64 {
        Ok(out)
    } else {
        Err(Bech32Error::Length)
    }
}

/// A key string: a folder ID and an issued key's seed (section 6.1).
pub struct KeyString {
    folder_id: FolderId,
    seed: Seed,
}

impl fmt::Debug for KeyString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyString({}, [redacted])", self.folder_id)
    }
}

impl KeyString {
    /// A key string for `seed` in `folder_id`.
    #[must_use]
    pub fn new(folder_id: FolderId, seed: Seed) -> Self {
        KeyString { folder_id, seed }
    }

    /// The folder.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.folder_id
    }

    /// The seed. Derive the key pair set and drop this as soon as it is stored.
    #[must_use]
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    fn payload(&self) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(crate::bytes::fill::<64>(&[
            self.folder_id.as_bytes(),
            self.seed.expose(),
        ]))
    }

    /// The lower-case string for text and links.
    ///
    /// # Errors
    ///
    /// Only if the encoder refuses 64 bytes, which it does not.
    pub fn to_text(&self) -> Result<Zeroizing<String>, Bech32Error> {
        bech32m_encode("lsk", &self.payload(), false)
    }

    /// The upper-case string for QR codes (alphanumeric mode).
    ///
    /// # Errors
    ///
    /// Only if the encoder refuses 64 bytes, which it does not.
    pub fn to_qr_text(&self) -> Result<Zeroizing<String>, Bech32Error> {
        bech32m_encode("lsk", &self.payload(), true)
    }

    /// Parses a key string, all lower or all upper case.
    ///
    /// # Errors
    ///
    /// [`Bech32Error`].
    pub fn parse(s: &str) -> Result<KeyString, Bech32Error> {
        let p = bech32m_decode("lsk", s)?;
        let (folder, seed) = crate::bytes::halves(&p);
        Ok(KeyString {
            folder_id: FolderId(folder),
            seed: Seed::from_bytes(seed),
        })
    }
}

/// Why a link or key file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Longer than [`MAX_LINK_LEN`].
    TooLong,
    /// Not `https://licketysync.dev/join#...`: the secret must sit after `#`.
    Prefix,
    /// A parameter that is not `k`, `g`, `a` or `c`, or one without `=`.
    Parameter,
    /// `k` missing or repeated, `g` or `c` repeated, or more than 16 `a`.
    Count,
    /// The key string is invalid.
    Key(Bech32Error),
    /// `g` or `c` is not base64url, or the bundle does not parse or is too big.
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

/// A join link (section 6.2): the key string after `#`, and optionally the
/// Folder record and grant chain (`g`), dialling hints (`a`) and a
/// certificate hash (`c`). Nothing in a link is trusted until the Folder
/// record's ID matches the key string's and the chain verifies
/// ([`Link::verify_bundle`]); an address is a hint, never an identity.
#[derive(Debug)]
pub struct Link {
    /// The key string.
    pub key: KeyString,
    /// The Folder record, then the grant chain parent-first.
    pub bundle: Vec<SignedRecord>,
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
    /// A bare link: the key string and nothing else, as invites are by default (TM-37).
    #[must_use]
    pub fn bare(key: KeyString) -> Self {
        Link {
            key,
            bundle: Vec::new(),
            addresses: Vec::new(),
            cert_hash: None,
        }
    }

    /// The link text.
    ///
    /// # Errors
    ///
    /// [`LinkError::Item`] for an address a link cannot carry or a certificate
    /// hash of the wrong size; [`LinkError::Count`] for too many addresses or
    /// bundle records.
    pub fn to_text(&self) -> Result<Zeroizing<String>, LinkError> {
        self.text_with_room(0)
    }

    /// The link text in a buffer sized up front for the whole link and
    /// `extra` more bytes, so that no reallocation leaves a copy of the key
    /// behind (security review, BLOCKER 3). The public parts are encoded
    /// first, the key last.
    fn text_with_room(&self, extra: usize) -> Result<Zeroizing<String>, LinkError> {
        if self.addresses.len() > MAX_LINK_ADDRESSES || self.bundle.len() > MAX_BUNDLE_RECORDS {
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
        let bundle = (!self.bundle.is_empty())
            .then(|| URL_SAFE_NO_PAD.encode(wire_key_bundle(&self.bundle).encode_to_vec()));
        let cert = self.cert_hash.as_ref().map(|c| URL_SAFE_NO_PAD.encode(c));
        let len = LINK_PREFIX.len()
            + 2
            + KEY_STRING_LEN
            + bundle.as_ref().map_or(0, |b| 3 + b.len())
            + self.addresses.iter().map(|a| 3 + a.len()).sum::<usize>()
            + cert.as_ref().map_or(0, |c| 3 + c.len())
            + extra;
        let mut s = Zeroizing::new(String::with_capacity(len));
        s.push_str(LINK_PREFIX);
        s.push_str("k=");
        s.push_str(&self.key.to_text().map_err(LinkError::Key)?);
        if let Some(b) = &bundle {
            s.push_str("&g=");
            s.push_str(b);
        }
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
        let (mut key, mut bundle, mut addresses, mut cert_hash) = (None, None, Vec::new(), None);
        for param in fragment.split('&') {
            let (name, value) = param.split_once('=').ok_or(LinkError::Parameter)?;
            match name {
                "k" if key.is_none() => {
                    key = Some(KeyString::parse(value).map_err(LinkError::Key)?);
                }
                "g" if bundle.is_none() => bundle = Some(decode_bundle(value)?),
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
                "k" | "g" | "a" | "c" => return Err(LinkError::Count),
                _ => return Err(LinkError::Parameter),
            }
        }
        Ok(Link {
            key: key.ok_or(LinkError::Count)?,
            bundle: bundle.unwrap_or_default(),
            addresses,
            cert_hash,
        })
    }

    /// The `.lskey` file form (section 6.3): the link text on one line.
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

    /// Verifies the bundle: its first record must be the Folder record of the
    /// key string's folder, each later one a grant that verifies against the
    /// records before it, and the last grant, when there is one, a grant of
    /// the key string's own key (its key ID derived from the seed), so that a
    /// link cannot hand its holder another key's chain. `None` when the link
    /// carries no bundle.
    #[must_use]
    pub fn verify_bundle(&self, now_unix: u64) -> Option<Result<FolderKeys, Rejected>> {
        let (first, rest) = self.bundle.split_first()?;
        Some(
            FolderKeys::new(&self.key.folder_id(), first.clone()).and_then(|mut keys| {
                for record in rest {
                    if record.prefix()?.record_type != RecordType::Grant {
                        return Err(Malformed::NotAKeyRecord.into());
                    }
                    keys.insert(record, now_unix)?;
                }
                if let Some(leaf) = rest.last() {
                    let leaf = GrantBody::parse(&leaf.body)?;
                    let own = KeyPairSet::from_seed(self.key.seed())
                        .map_err(|_| Rejected::Malformed(Malformed::ForeignLeaf))?
                        .public()
                        .key_id(leaf.suite);
                    if leaf.key_id != own {
                        return Err(Malformed::ForeignLeaf.into());
                    }
                }
                Ok(keys)
            }),
        )
    }
}

fn decode_bundle(value: &str) -> Result<Vec<SignedRecord>, LinkError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| LinkError::Encoding)?;
    crate::records::decode_key_bundle(&bytes, MAX_BUNDLE_RECORDS).map_err(|_| LinkError::Encoding)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    fn sample() -> KeyString {
        KeyString::new(FolderId([0x11; 32]), Seed::from_bytes([0x22; 32]))
    }

    #[test]
    fn key_string_round_trips_in_both_cases() {
        let k = sample();
        let lower = k.to_text().unwrap();
        let upper = k.to_qr_text().unwrap();
        assert_eq!(lower.len(), KEY_STRING_LEN);
        // Written into a buffer of exactly the final length.
        assert_eq!(lower.capacity(), KEY_STRING_LEN);
        assert_eq!(upper.capacity(), KEY_STRING_LEN);
        assert!(lower.starts_with("lsk1"));
        assert_eq!(*upper, lower.to_ascii_uppercase());
        for s in [&*lower, &*upper] {
            let back = KeyString::parse(s).unwrap();
            assert_eq!(back.folder_id(), k.folder_id());
            assert!(bool::from(back.seed().ct_eq(k.seed())));
        }
        assert_eq!(
            format!("{k:?}"),
            format!("KeyString({}, [redacted])", k.folder_id())
        );
    }

    #[test]
    fn key_string_rejections() {
        let s = sample().to_text().unwrap().to_string();
        // Mixed case.
        let mut mixed = s.clone();
        mixed.replace_range(5..6, &mixed[5..6].to_ascii_uppercase());
        assert_eq!(
            KeyString::parse(&mixed).unwrap_err(),
            Bech32Error::MixedCase
        );
        // Every single flipped character in the data is caught.
        let alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for i in 4..s.len() {
            let c = s.as_bytes()[i] as char;
            let other = alphabet.chars().find(|&x| x != c).unwrap();
            let mut flipped = s.clone();
            flipped.replace_range(i..=i, &other.to_string());
            assert!(KeyString::parse(&flipped).is_err(), "flip at {i}");
        }
        // Another prefix with a valid checksum.
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&[0x11; 32]);
        let lsl = bech32m_encode("lsl", &payload, false).unwrap();
        assert_eq!(KeyString::parse(&lsl).unwrap_err(), Bech32Error::Prefix);
        // A Bech32 (non-m) checksum.
        let bech32 =
            bech32::encode::<bech32::Bech32>(Hrp::parse_unchecked("lsk"), &payload).unwrap();
        assert_eq!(
            KeyString::parse(&bech32).unwrap_err(),
            Bech32Error::Checksum
        );
        // 63- and 65-byte payloads with valid checksums.
        for n in [63usize, 65] {
            let e = bech32::encode::<Bech32m>(Hrp::parse_unchecked("lsk"), &vec![1u8; n]).unwrap();
            assert_eq!(KeyString::parse(&e).unwrap_err(), Bech32Error::Length);
        }
        assert_eq!(KeyString::parse("lsk1").unwrap_err(), Bech32Error::Checksum);
        assert_eq!(
            KeyString::parse("lsk1\u{e9}").unwrap_err(),
            Bech32Error::Character
        );
        assert_eq!(
            KeyString::parse("no separator").unwrap_err(),
            Bech32Error::Character
        );
        assert_eq!(
            KeyString::parse(&"q".repeat(1024)).unwrap_err(),
            Bech32Error::TooLong
        );
        for e in [
            Bech32Error::TooLong,
            Bech32Error::MixedCase,
            Bech32Error::Character,
            Bech32Error::Checksum,
            Bech32Error::Prefix,
            Bech32Error::Length,
            Bech32Error::Padding,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }

    #[test]
    fn non_zero_padding_is_rejected() {
        // Build 103 data characters whose last one has a padding bit set, with a valid checksum.
        use bech32::{ByteIterExt as _, Fe32IterExt as _};
        let hrp = Hrp::parse_unchecked("lsk");
        let mut fes: Vec<Fe32> = [0u8; 64].iter().copied().bytes_to_fes().collect();
        assert_eq!(fes.len(), 103);
        *fes.last_mut().unwrap() = Fe32::try_from(1u8).unwrap();
        let s: String = fes
            .into_iter()
            .with_checksum::<Bech32m>(&hrp)
            .chars()
            .collect();
        assert_eq!(KeyString::parse(&s).unwrap_err(), Bech32Error::Padding);
    }

    #[test]
    fn tm_18_link_and_file_forms() {
        let link = Link {
            key: sample(),
            bundle: vec![],
            addresses: vec![
                "/ip4/192.0.2.1/udp/4001/quic-v1".into(),
                "/dns/peer.example/tcp/4001".into(),
            ],
            cert_hash: Some(vec![1, 2, 3]),
        };
        let text = link.to_text().unwrap();
        assert!(text.starts_with("https://licketysync.dev/join#k=lsk1"));
        let (before, after) = text.split_once('#').unwrap();
        assert!(!before.contains("lsk1"), "the secret is only after #");
        assert!(after.contains("&a=/ip4/192.0.2.1"));
        let back = Link::parse(&text).unwrap();
        assert_eq!(back.addresses, link.addresses);
        assert_eq!(back.cert_hash, link.cert_hash);
        assert_eq!(back.bundle.len(), 0);
        assert!(back.verify_bundle(0).is_none());
        let file = link.to_file().unwrap();
        assert!(file.ends_with('\n'));
        assert_eq!(Link::parse_file(&file).unwrap().addresses.len(), 2);
        assert_eq!(
            Link::parse_file(&format!("{}\r\n", text.as_str()))
                .unwrap()
                .addresses
                .len(),
            2
        );
        assert_eq!(
            Link::parse_file(&format!("{}\n\n", text.as_str())).unwrap_err(),
            LinkError::NotOneLine
        );
        let bare = Link::bare(sample()).to_text().unwrap();
        assert_eq!(bare.len(), LINK_PREFIX.len() + 2 + KEY_STRING_LEN);
    }

    #[test]
    fn link_rejections() {
        let k = sample().to_text().unwrap().to_string();
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
            Link::parse(&format!("{p}k={k}&a")).unwrap_err(),
            LinkError::Parameter
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&g=!!")).unwrap_err(),
            LinkError::Encoding
        );
        assert_eq!(
            Link::parse(&format!("{p}k={k}&g=AQID")).unwrap_err(),
            LinkError::Encoding
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
            Link::parse(&format!("{p}k=lsk1bad")).unwrap_err(),
            LinkError::Key(Bech32Error::Character)
        );
        assert_eq!(
            Link::parse(&"x".repeat(MAX_LINK_LEN + 1)).unwrap_err(),
            LinkError::TooLong
        );
        let mut l = Link::bare(sample());
        l.addresses = vec!["a&b".into()];
        assert_eq!(l.to_text().unwrap_err(), LinkError::Item);
        l.addresses = vec!["/x".into(); 17];
        assert_eq!(l.to_text().unwrap_err(), LinkError::Count);
        l.addresses.clear();
        l.cert_hash = Some(vec![]);
        assert_eq!(l.to_text().unwrap_err(), LinkError::Item);
        for e in [
            LinkError::TooLong,
            LinkError::Prefix,
            LinkError::Parameter,
            LinkError::Count,
            LinkError::Key(Bech32Error::Padding),
            LinkError::Encoding,
            LinkError::Item,
            LinkError::NotOneLine,
        ] {
            assert_ne!(e.to_string(), "");
        }
    }
}
