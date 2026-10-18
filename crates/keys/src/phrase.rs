// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The recovery phrase (`keys.md` section 1.1): the BIP39 English encoding of
//! the 32-byte master secret, 24 words with an 8-bit SHA-256 checksum. BIP39's
//! PBKDF2 seed step is not used; the master secret is the entropy itself
//! (`suites.md`, "The recovery phrase").

use core::fmt;

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize as _, Zeroizing};

use crate::secret::MasterSecret;

/// The number of words in a phrase.
pub const WORDS: usize = 24;

/// Why a phrase was refused. Positions are 1-based, as the words are numbered
/// on paper. The phrase is never corrected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseError {
    /// The phrase does not have 24 words.
    WordCount(usize),
    /// The word at this position is not in the English list and is not a
    /// unique prefix of one.
    UnknownWord {
        /// 1-based position of the first word that is not in the list.
        position: usize,
    },
    /// The checksum does not match.
    Checksum,
    /// The BIP39 library refused 32 bytes of entropy, which it does not do;
    /// kept apart from [`PhraseError::Checksum`] so that nothing reads as a
    /// typing mistake.
    Entropy,
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WordCount(n) => write!(f, "a recovery phrase has {WORDS} words, this has {n}"),
            Self::UnknownWord { position } => write!(f, "word {position} is not in the word list"),
            Self::Checksum => f.write_str("the phrase's checksum does not match"),
            Self::Entropy => f.write_str("the BIP39 library refused the master secret"),
        }
    }
}

impl std::error::Error for PhraseError {}

/// A 24-word recovery phrase and the master secret it encodes. Zeroized on
/// drop; its `Debug` is redacted.
pub struct Phrase {
    mnemonic: Mnemonic,
    ms: MasterSecret,
}

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Phrase([redacted])")
    }
}

impl Phrase {
    /// The phrase that encodes `ms`.
    ///
    /// # Errors
    ///
    /// [`PhraseError::Entropy`] only if the BIP39 crate refuses 32 bytes of
    /// entropy, which it does not; the result type exists so that no `unwrap`
    /// is needed here.
    pub fn from_master(ms: &MasterSecret) -> Result<Phrase, PhraseError> {
        Mnemonic::from_entropy_in(Language::English, ms.expose())
            .map(|mnemonic| Phrase {
                mnemonic,
                ms: ms.clone(),
            })
            .map_err(|_| PhraseError::Entropy)
    }

    /// Parses a phrase as a person typed it: words separated by any
    /// whitespace, any case, and a word may be given by a prefix of four or
    /// more letters when that prefix names exactly one word (the English list's
    /// first four letters are unique). The checksum is validated and a failing
    /// phrase is refused, never corrected.
    ///
    /// # Errors
    ///
    /// [`PhraseError`]: the word count, the position of the first unknown
    /// word, or the checksum.
    pub fn parse(text: &str) -> Result<Phrase, PhraseError> {
        let count = text.split_whitespace().count();
        if count != WORDS {
            return Err(PhraseError::WordCount(count));
        }
        // The full words can be longer than the prefixes typed: sized for the
        // longest phrase so that no reallocation leaves a copy behind.
        let mut normalized = Zeroizing::new(String::with_capacity(WORDS * 9));
        for (i, raw) in text.split_whitespace().enumerate() {
            let lower = Zeroizing::new(raw.to_ascii_lowercase());
            let word = resolve_word(&lower).ok_or(PhraseError::UnknownWord { position: i + 1 })?;
            if i > 0 {
                normalized.push(' ');
            }
            normalized.push_str(word);
        }
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|e| match e {
                bip39::Error::UnknownWord(i) => PhraseError::UnknownWord { position: i + 1 },
                bip39::Error::BadWordCount(n) => PhraseError::WordCount(n),
                _ => PhraseError::Checksum,
            })?;
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let ms =
            (len == 32).then(|| MasterSecret::from_bytes(crate::bytes::fill::<32>(&[&entropy])));
        entropy.zeroize();
        Ok(Phrase {
            mnemonic,
            ms: ms.ok_or(PhraseError::WordCount(count))?,
        })
    }

    /// The master secret the phrase encodes.
    #[must_use]
    pub fn master_secret(&self) -> &MasterSecret {
        &self.ms
    }

    /// The words, in order, from the English list.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.mnemonic.words()
    }

    /// The phrase as one line of space-separated words, in a buffer that is
    /// zeroized on drop.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        // Sized for the longest phrase (24 words of at most 8 letters and
        // their separators), so that no reallocation leaves a copy behind.
        let mut s = Zeroizing::new(String::with_capacity(WORDS * 9));
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(w);
        }
        s
    }
}

/// A word from the list, exactly or by a unique prefix of at least four letters.
fn resolve_word(word: &str) -> Option<&'static str> {
    let list = Language::English;
    if let Some(index) = list.find_word(word) {
        return list.word_list().get(usize::from(index)).copied();
    }
    if word.len() < 4 {
        return None;
    }
    let mut matches = list.words_by_prefix_iter(word);
    match (matches.next(), matches.next()) {
        (Some(single), None) => Some(single),
        _ => None,
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

    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn zero_entropy_round_trips_through_the_trezor_vector() {
        let ms = MasterSecret::from_bytes([0u8; 32]);
        let phrase = Phrase::from_master(&ms).unwrap();
        assert_eq!(&*phrase.to_text(), ZERO_PHRASE);
        assert_eq!(phrase.words().count(), WORDS);
        assert_eq!(format!("{phrase:?}"), "Phrase([redacted])");
        let back = Phrase::parse(ZERO_PHRASE).unwrap();
        assert!(bool::from(back.master_secret().ct_eq(&ms)));
        assert!(bool::from(phrase.master_secret().ct_eq(&ms)));
        // Sized once for the longest phrase: no reallocation left a copy.
        assert_eq!(phrase.to_text().capacity(), WORDS * 9);
        assert_eq!(
            PhraseError::Entropy.to_string(),
            "the BIP39 library refused the master secret"
        );
    }

    #[test]
    fn parse_accepts_case_whitespace_and_unique_prefixes() {
        let typed = "  Abandon ABANDON aban abandon abandon abandon abandon abandon abandon abandon abandon abandon\n abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ART ";
        // "aban" is a 4-letter prefix shared by "abandon" only.
        let p = Phrase::parse(typed).unwrap();
        assert_eq!(&*p.to_text(), ZERO_PHRASE);
    }

    #[test]
    fn parse_refuses_bad_count_unknown_word_and_checksum() {
        let words: Vec<&str> = ZERO_PHRASE.split(' ').collect();
        let twenty_three = words[..23].join(" ");
        assert_eq!(
            Phrase::parse(&twenty_three).err(),
            Some(PhraseError::WordCount(23))
        );
        assert_eq!(Phrase::parse("").err(), Some(PhraseError::WordCount(0)));
        let mut bad = words.clone();
        bad[4] = "zzzz";
        assert_eq!(
            Phrase::parse(&bad.join(" ")).err(),
            Some(PhraseError::UnknownWord { position: 5 })
        );
        let mut short = words.clone();
        short[0] = "aba"; // too short to be a prefix
        assert_eq!(
            Phrase::parse(&short.join(" ")).err(),
            Some(PhraseError::UnknownWord { position: 1 })
        );
        // Four-letter prefixes are unique in the English list, so "ange" is "anger" alone
        // and only a prefix that names no word fails.
        let mut no_such = words.clone();
        no_such[1] = "angez";
        assert_eq!(
            Phrase::parse(&no_such.join(" ")).err(),
            Some(PhraseError::UnknownWord { position: 2 })
        );
        let mut prefixed = words.clone();
        prefixed[1] = "aband";
        assert_eq!(
            &*Phrase::parse(&prefixed.join(" ")).unwrap().to_text(),
            ZERO_PHRASE
        );
        let mut checksum = words.clone();
        checksum[23] = "abandon";
        assert_eq!(
            Phrase::parse(&checksum.join(" ")).err(),
            Some(PhraseError::Checksum)
        );
        assert_eq!(
            PhraseError::WordCount(3).to_string(),
            "a recovery phrase has 24 words, this has 3"
        );
        assert_eq!(
            PhraseError::UnknownWord { position: 2 }.to_string(),
            "word 2 is not in the word list"
        );
        assert_eq!(
            PhraseError::Checksum.to_string(),
            "the phrase's checksum does not match"
        );
    }
}
