// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The write key as words (`keys.md` 6.2): the BIP39 English encoding of the
//! 32-byte write secret, 24 words with an 8-bit SHA-256 checksum. BIP39's
//! PBKDF2 seed step is not used: the words are the secret itself
//! (`suites.md` 3.2). They are another encoding of the same secret, not an
//! owner key: whoever has them has the write key of that one folder and
//! nothing else. The words carry no suite: 24 words always mean a suite 1
//! write secret. Only the write key has words.
//!
//! Entry first refuses a text longer than [`MAX_WORDS_TEXT`] bytes, before
//! anything is split, so that a pasted file cannot make the parser walk it.
//! It then splits the text at runs of whitespace into tokens and compares
//! letters without regard to case, and refuses, at the first check that
//! fails: a count other than 24 (naming the count); a token that is neither a
//! word of the list nor a prefix of at least four letters of exactly one word
//! (naming the position of the first such token); a checksum that does not
//! match (naming no position, since any word may be the wrong one). Nothing
//! is ever corrected or guessed.

use core::fmt;

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize as _, Zeroizing};

use crate::folder::WriteKey;
use crate::secret::WriteSecret;
use crate::suite::Suite;

/// The number of words.
pub const WORD_COUNT: usize = 24;

/// The longest text word entry reads, in bytes: far more than 24 words and
/// any whitespace a person would type between them.
pub const MAX_WORDS_TEXT: usize = 4096;

/// Why words were refused, in the order the checks run (`keys.md` 6.2).
/// Positions are 1-based, as the words are numbered. The words are never
/// corrected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordsError {
    /// The text is longer than [`MAX_WORDS_TEXT`] bytes; it was not read.
    TooLong,
    /// Not 24 tokens; the count found.
    WordCount(usize),
    /// The token at this position is not a word of the English list and not a
    /// prefix of at least four letters of exactly one word.
    UnknownWord {
        /// 1-based position of the first word that is not in the list.
        position: usize,
    },
    /// The checksum does not match; no position is named, since any word may
    /// be the wrong one.
    Checksum,
    /// The BIP39 library refused 32 bytes of entropy, which it does not do;
    /// kept apart from [`WordsError::Checksum`] so that nothing reads as a
    /// typing mistake.
    Entropy,
}

impl fmt::Display for WordsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "more than {MAX_WORDS_TEXT} bytes; a write key is 24 words"
            ),
            Self::WordCount(n) => write!(f, "{n} words; a write key has {WORD_COUNT}"),
            Self::UnknownWord { position } => write!(f, "word {position} is not in the word list"),
            Self::Checksum => {
                f.write_str("the words' checksum does not match; one of them is wrong")
            }
            Self::Entropy => f.write_str("the BIP39 library refused the write secret"),
        }
    }
}

impl std::error::Error for WordsError {}

/// The longest text of 24 words: words of at most 8 letters and their
/// separators. Buffers are sized for it once, so that no reallocation leaves
/// a copy behind.
const MAX_TEXT: usize = WORD_COUNT * 9;

impl WriteKey {
    /// The write key as 24 words, one line of space-separated lower-case words
    /// from the English list, in a buffer that is zeroized on drop. The app
    /// numbers them 1 to 24 when it shows them.
    ///
    /// # Errors
    ///
    /// [`WordsError::Entropy`] only if the BIP39 crate refuses 32 bytes of
    /// entropy, which it does not; the result type exists so that no `unwrap`
    /// is needed here.
    pub fn to_words(&self) -> Result<Zeroizing<String>, WordsError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, self.secret().expose())
            .map_err(|_| WordsError::Entropy)?;
        let mut s = Zeroizing::new(String::with_capacity(MAX_TEXT));
        for (i, w) in mnemonic.words().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(w);
        }
        Ok(s)
    }

    /// Reads the write key from words as a person typed them: at most
    /// [`MAX_WORDS_TEXT`] bytes of tokens separated by runs of whitespace
    /// (leading and trailing whitespace ignored), letters in any case, and a
    /// word may be given by a prefix of four or more letters when that prefix
    /// names exactly one word (the English list's first four letters are
    /// unique). The checks run in the order of `keys.md` 6.2 and the first
    /// that fails refuses the words. The key is a suite 1 key.
    ///
    /// # Errors
    ///
    /// [`WordsError`]: the text's length, the token count, the position of the
    /// first token that is no word, or the checksum.
    pub fn from_words(text: &str) -> Result<WriteKey, WordsError> {
        if text.len() > MAX_WORDS_TEXT {
            return Err(WordsError::TooLong);
        }
        let count = text.split_whitespace().count();
        if count != WORD_COUNT {
            return Err(WordsError::WordCount(count));
        }
        let mut normalized = Zeroizing::new(String::with_capacity(MAX_TEXT));
        for (i, raw) in text.split_whitespace().enumerate() {
            let lower = Zeroizing::new(raw.to_ascii_lowercase());
            let word = resolve_word(&lower).ok_or(WordsError::UnknownWord { position: i + 1 })?;
            if i > 0 {
                normalized.push(' ');
            }
            normalized.push_str(word);
        }
        // Every token is a word of the list and there are 24 of them, so the
        // checksum is all that can fail here.
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|_| WordsError::Checksum)?;
        // 24 words are 32 bytes of entropy; the array has room for 33.
        let (mut entropy, _) = mnemonic.to_entropy_array();
        let secret = WriteSecret::fill_with(|out| crate::bytes::first_into(out, &entropy));
        entropy.zeroize();
        Ok(WriteKey::derive(Suite::ONE, secret))
    }
}

/// A word from the list, exactly (the lower-case token itself) or by a unique
/// prefix of at least four letters.
fn resolve_word(word: &str) -> Option<&str> {
    let list = Language::English;
    if list.find_word(word).is_some() {
        return Some(word);
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

    const ZERO_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn zero_key() -> WriteKey {
        WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes([0u8; 32])).unwrap()
    }

    #[test]
    fn zero_entropy_round_trips_through_the_trezor_vector() {
        let key = zero_key();
        let words = key.to_words().unwrap();
        assert_eq!(&*words, ZERO_WORDS);
        assert_eq!(words.capacity(), MAX_TEXT, "sized once");
        let back = WriteKey::from_words(ZERO_WORDS).unwrap();
        assert!(bool::from(back.secret().ct_eq(key.secret())));
        assert_eq!(back.verifier(), key.verifier());
        assert_eq!(
            WordsError::Entropy.to_string(),
            "the BIP39 library refused the write secret"
        );
    }

    #[test]
    fn parse_accepts_case_whitespace_and_unique_prefixes() {
        let typed = "  Abandon ABANDON aban abandon abandon abandon abandon abandon abandon abandon abandon abandon\n abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ART ";
        let k = WriteKey::from_words(typed).unwrap();
        assert_eq!(&*k.to_words().unwrap(), ZERO_WORDS);
    }

    #[test]
    fn parse_refuses_bad_count_unknown_word_and_checksum() {
        let words: Vec<&str> = ZERO_WORDS.split(' ').collect();
        assert_eq!(
            WriteKey::from_words(&words[..23].join(" ")).unwrap_err(),
            WordsError::WordCount(23)
        );
        let mut twenty_five = words.clone();
        twenty_five.push("abandon");
        assert_eq!(
            WriteKey::from_words(&twenty_five.join(" ")).unwrap_err(),
            WordsError::WordCount(25)
        );
        assert_eq!(
            WriteKey::from_words("").unwrap_err(),
            WordsError::WordCount(0)
        );
        // The length cap comes before tokenising: at the cap the text is read
        // (and these are not 24 words), one byte over it is not.
        let padded = |n: usize| format!("{ZERO_WORDS}{}", " ".repeat(n - ZERO_WORDS.len()));
        assert!(WriteKey::from_words(&padded(MAX_WORDS_TEXT)).is_ok());
        assert_eq!(
            WriteKey::from_words(&padded(MAX_WORDS_TEXT + 1)).unwrap_err(),
            WordsError::TooLong
        );
        assert_eq!(
            WriteKey::from_words(&"x ".repeat(MAX_WORDS_TEXT / 2)).unwrap_err(),
            WordsError::WordCount(MAX_WORDS_TEXT / 2)
        );
        assert_eq!(
            WriteKey::from_words(&"x".repeat(MAX_WORDS_TEXT + 1)).unwrap_err(),
            WordsError::TooLong
        );
        assert_eq!(
            WordsError::TooLong.to_string(),
            "more than 4096 bytes; a write key is 24 words"
        );
        let mut bad = words.clone();
        bad[4] = "zzzz";
        assert_eq!(
            WriteKey::from_words(&bad.join(" ")).unwrap_err(),
            WordsError::UnknownWord { position: 5 }
        );
        let mut short = words.clone();
        short[0] = "aba"; // too short to be a prefix
        assert_eq!(
            WriteKey::from_words(&short.join(" ")).unwrap_err(),
            WordsError::UnknownWord { position: 1 }
        );
        let mut no_such = words.clone();
        no_such[1] = "angez";
        assert_eq!(
            WriteKey::from_words(&no_such.join(" ")).unwrap_err(),
            WordsError::UnknownWord { position: 2 }
        );
        let mut prefixed = words.clone();
        prefixed[1] = "aband";
        assert_eq!(
            &*WriteKey::from_words(&prefixed.join(" "))
                .unwrap()
                .to_words()
                .unwrap(),
            ZERO_WORDS
        );
        let mut checksum = words.clone();
        checksum[23] = "abandon";
        assert_eq!(
            WriteKey::from_words(&checksum.join(" ")).unwrap_err(),
            WordsError::Checksum
        );
        assert_eq!(
            WordsError::WordCount(23).to_string(),
            "23 words; a write key has 24"
        );
        assert_eq!(
            WordsError::UnknownWord { position: 2 }.to_string(),
            "word 2 is not in the word list"
        );
        assert_eq!(
            WordsError::Checksum.to_string(),
            "the words' checksum does not match; one of them is wrong"
        );
        // The order: the count before any word, a word before the checksum.
        let mut both = words.clone();
        both[3] = "zzzz";
        both.pop();
        assert_eq!(
            WriteKey::from_words(&both.join(" ")).unwrap_err(),
            WordsError::WordCount(23)
        );
        let mut word_and_checksum = checksum.clone();
        word_and_checksum[10] = "qqqq";
        assert_eq!(
            WriteKey::from_words(&word_and_checksum.join(" ")).unwrap_err(),
            WordsError::UnknownWord { position: 11 }
        );
        // Two unknown tokens: the first is named.
        let mut two = words.clone();
        two[6] = "nope";
        two[2] = "zzzz";
        assert_eq!(
            WriteKey::from_words(&two.join(" ")).unwrap_err(),
            WordsError::UnknownWord { position: 3 }
        );
    }

    use proptest::prelude::*;

    /// One way a person may type a word: its letters in any case and, for a
    /// word of four letters or more, cut to a prefix of at least four.
    fn typed(word: &str, cut: usize, case: &[bool]) -> String {
        let len = if word.len() > 4 {
            4 + cut % (word.len() - 3)
        } else {
            word.len()
        };
        word.chars()
            .take(len)
            .zip(case.iter().cycle())
            .map(|(c, &up)| if up { c.to_ascii_uppercase() } else { c })
            .collect()
    }

    proptest! {
        /// Any write secret's words read back to it, typed in any case, cut to
        /// any unique prefix of four letters or more, and separated by any
        /// runs of whitespace.
        #[test]
        fn words_round_trip_as_typed(
            ws in any::<[u8; 32]>(),
            cuts in proptest::collection::vec(any::<usize>(), 24),
            cases in proptest::collection::vec(proptest::collection::vec(any::<bool>(), 1..9), 24),
            gaps in proptest::collection::vec(proptest::collection::vec(prop::sample::select(vec![" ", "\t", "\n", "\r\n", "\u{a0}"]), 1..4), 25),
        ) {
            let key = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).unwrap();
            let words = key.to_words().unwrap();
            prop_assert_eq!(words.split(' ').count(), 24);
            prop_assert_eq!(words.to_ascii_lowercase(), words.as_str());
            let mut text = String::new();
            for (i, w) in words.split(' ').enumerate() {
                text.push_str(&gaps[i].concat());
                text.push_str(&typed(w, cuts[i], &cases[i]));
            }
            text.push_str(&gaps[24].concat());
            let back = WriteKey::from_words(&text).unwrap();
            prop_assert!(bool::from(back.secret().ct_eq(key.secret())));
            prop_assert_eq!(&*back.to_words().unwrap(), &*words);
        }

        /// Any text into the words parser: no panic, and what it accepts
        /// writes back to 24 words that read as the same key.
        #[test]
        fn any_text_into_the_words_parser(text in "\\PC{0,300}") {
            if let Ok(key) = WriteKey::from_words(&text) {
                let again = WriteKey::from_words(&key.to_words().unwrap()).unwrap();
                prop_assert!(bool::from(again.secret().ct_eq(key.secret())));
            }
        }

        /// 24 tokens drawn from the list and its four-letter prefixes are
        /// refused only for the checksum, never for a word.
        #[test]
        fn listed_words_fail_only_the_checksum(picks in proptest::collection::vec((0usize..2048, any::<bool>()), 24)) {
            let list = Language::English.word_list();
            let text: Vec<&str> = picks
                .iter()
                .map(|&(i, short)| {
                    let w = list[i];
                    if short && w.len() > 4 { &w[..4] } else { w }
                })
                .collect();
            match WriteKey::from_words(&text.join(" ")) {
                Ok(_) | Err(WordsError::Checksum) => {}
                Err(e) => prop_assert!(false, "{e:?}"),
            }
        }
    }
}
