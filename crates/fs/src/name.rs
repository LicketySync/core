// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Which names a folder's disk may hold (TM-4).
//!
//! An index path is UTF-8, `/`-separated, and passes `check_path`
//! (`protocol.md` §4.4); its writer gives every component in NFC (§4.4 step
//! 7). A [`NamePolicy`] says, for one platform, which such paths this device
//! can store, and turns a name read from the disk into a component of one. A
//! name it refuses "cannot be stored here": the file stays on the disk and is
//! never read as deleted, and a record for it is kept without being written.
//!
//! Refused everywhere:
//! - a component that a file system that folds names could take for
//!   `.licketysync`, at any depth: the folder's hidden directory
//!   ([`HIDDEN_DIR`]) at the root, another folder's beneath it. That is a
//!   component that, once every `Default_Ignorable_Code_Point` is removed
//!   (Linux's casefold directories and HFS+ ignore them) and trailing dots
//!   and spaces are trimmed (vfat and exFAT drop them), has `.LICKETYSYNC` or
//!   `.licketysync` as its Unicode upper or lower case (`.licketyſync`, with
//!   the long s, is one), or is Windows' short name for it, `LICKET~` and
//!   digits, in any case (git's `is_hfs_dotgit` and `is_ntfs_dotgit` refuse
//!   `.git`'s aliases alike);
//! - a path `check_path` refuses, and a disk name that is not UTF-8, holds a
//!   `/`, or that `check_path` refuses (empty, `.`, `..`, a NUL, a backslash);
//! - a component not in NFC. On macOS, whose file systems take every Unicode
//!   form of a name for the same name and may list it decomposed, a disk name
//!   is normalised to NFC instead; on Linux and Windows the NFC form of such a
//!   name would be another file, so the name is refused;
//! - a component longer than [`MAX_NAME_BYTES`]: bytes on Linux and macOS
//!   (APFS counts UTF-8 bytes, which is stricter than HFS+'s UTF-16 units),
//!   UTF-16 code units on Windows. A file system with a lower limit refuses
//!   the name itself. On macOS the limit holds after normalising, and a disk
//!   name over three times it is refused before.
//!
//! Refused on Windows also: `<`, `>`, `:`, `"`, `\`, `|`, `?` and `*` (`:`
//! covers alternate data streams); the control characters U+0001 to U+001F;
//! a trailing dot or space; and the device names `CON`, `PRN`, `AUX`, `NUL`,
//! `COM0` to `COM9`, `LPT0` to `LPT9` (with the superscript digits `¹`, `²`
//! and `³` too), `CONIN$` and `CONOUT$`, in any case, with any extension, and
//! with spaces before the extension (`nul .txt`).
//!
//! Other aliases the file system makes (case for any other name, Windows'
//! other short names) are not modelled here: the resolver refuses a component
//! that is the hidden directory by its file ID, and every create is
//! no-replace, so an alias fails as the name already taken.

use std::fmt;

use licketysync_protocol::limits::{MAX_NAME_BYTES, MAX_PATH_BYTES};
use licketysync_protocol::record::{PathError, check_path};
use unicode_normalization::{UnicodeNormalization, is_nfc};

#[cfg(test)]
mod tests;

/// The folder's hidden directory at its root: the marker, temporary
/// downloads, the archive. Never synced, and no index path may name it.
pub const HIDDEN_DIR: &str = ".licketysync";

/// The names one platform's file systems can store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NamePolicy {
    /// Any name `check_path` admits, in NFC, of at most 255 bytes.
    Linux,
    /// As Linux, and a disk name normalised to NFC.
    Macos,
    /// As Linux, but at most 255 UTF-16 code units, and none of Windows'
    /// reserved characters, trailing dots or spaces, or device names.
    Windows,
}

impl NamePolicy {
    /// The policy of the platform this build is for: Apple's systems take
    /// macOS's, Windows its own, and every other system Linux's.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_vendor = "apple") {
            Self::Macos
        } else {
            Self::Linux
        }
    }

    /// Whether this platform's file systems take every Unicode form of a name
    /// for one name, so that a disk name is normalised to NFC rather than
    /// refused.
    const fn folds_unicode_forms(self) -> bool {
        matches!(self, Self::Macos)
    }

    /// A path the index holds, as this platform can store it.
    ///
    /// # Errors
    /// [`NameError::Path`] when `check_path` refuses the path, else the first
    /// component's refusal, as [`NamePolicy::name`] gives it.
    pub fn index_path(self, path: &str) -> Result<IndexPath, NameError> {
        check_path(path).map_err(NameError::Path)?;
        for component in path.split('/') {
            self.name(component)?;
        }
        Ok(IndexPath {
            text: path.to_owned(),
            policy: self,
        })
    }

    /// One component of an index path, as this platform can store it: the
    /// name exactly as given, which must already be in NFC.
    ///
    /// # Errors
    /// The rule it breaks, in this order: [`NameError::Separator`],
    /// [`NameError::Path`], [`NameError::NotNfc`], [`NameError::TooLong`],
    /// [`NameError::Hidden`], then Windows' rules.
    pub fn name(self, component: &str) -> Result<Name, NameError> {
        if component.contains('/') {
            return Err(NameError::Separator);
        }
        check_path(component).map_err(NameError::Path)?;
        if !is_nfc(component) {
            return Err(NameError::NotNfc);
        }
        self.check(component)?;
        Ok(Name {
            text: component.to_owned(),
            policy: self,
        })
    }

    /// A name as a directory listing gives it, as a component of an index
    /// path: UTF-8, then in NFC (normalised on macOS, else required), then
    /// as [`NamePolicy::name`] judges it.
    ///
    /// # Errors
    /// [`NameError::NotUtf8`], [`NameError::NotNfc`], [`NameError::TooLong`]
    /// (on macOS, also before normalising, for a name too long to fit after),
    /// or what [`NamePolicy::name`] refuses.
    pub fn from_disk(self, raw: &[u8]) -> Result<Name, NameError> {
        let text = std::str::from_utf8(raw).map_err(|_| NameError::NotUtf8)?;
        if is_nfc(text) || !self.folds_unicode_forms() {
            return self.name(text);
        }
        // Bounds the work of normalising: decomposed, a name is at most three
        // times as long in UTF-8 as composed (a Hangul syllable is three
        // jamo), so one longer than this cannot fit. name() judges the
        // normalised length, which NFC can also lengthen.
        if raw.len() > 3 * MAX_NAME_BYTES {
            return Err(NameError::TooLong);
        }
        let normalised: String = text.nfc().collect();
        self.name(&normalised)
    }

    /// The rules after the grammar and NFC: length, the hidden directory,
    /// and Windows' own.
    fn check(self, name: &str) -> Result<(), NameError> {
        let length = match self {
            Self::Linux | Self::Macos => name.len(),
            Self::Windows => name.encode_utf16().count(),
        };
        if length > MAX_NAME_BYTES {
            return Err(NameError::TooLong);
        }
        if is_hidden(name) {
            return Err(NameError::Hidden);
        }
        if self == Self::Windows {
            check_windows(name)?;
        }
        Ok(())
    }
}

/// Whether a file system that folds names could take `name` for
/// [`HIDDEN_DIR`]: without its default-ignorable characters and its trailing
/// dots and spaces, it is [`HIDDEN_DIR`] in some case, upper or lower case
/// taken character by character as Unicode defines them, or Windows' short
/// name for it.
fn is_hidden(name: &str) -> bool {
    let visible: String = name.chars().filter(|c| !is_default_ignorable(*c)).collect();
    let folded = visible.trim_end_matches(['.', ' ']);
    folded
        .chars()
        .flat_map(char::to_uppercase)
        .eq(".LICKETYSYNC".chars())
        || folded
            .chars()
            .flat_map(char::to_lowercase)
            .eq(HIDDEN_DIR.chars())
        || is_short_name(folded)
}

/// Whether `name` is Windows' 8.3 short name for [`HIDDEN_DIR`]: `LICKET~`
/// and one or more digits, in any case.
fn is_short_name(name: &str) -> bool {
    match (name.get(..7), name.get(7..)) {
        (Some(head), Some(digits)) => {
            head.eq_ignore_ascii_case("licket~")
                && !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// Unicode's `Default_Ignorable_Code_Point` property: the Unicode Character
/// Database 16.0.0, `DerivedCoreProperties.txt`, its ranges with adjacent
/// ones merged. Checked against the table `ucd-generate property-bool
/// ucd-16.0.0` wrote for regex-syntax 0.8.11
/// (`src/unicode_tables/property_bool.rs`, `DEFAULT_IGNORABLE_CODE_POINT`),
/// which it equals. Characters a renderer shows nothing for, which some file
/// systems drop when they fold a name.
const DEFAULT_IGNORABLE: [(char, char); 17] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{034F}', '\u{034F}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{115F}', '\u{1160}'),
    ('\u{17B4}', '\u{17B5}'),
    ('\u{180B}', '\u{180F}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{206F}'),
    ('\u{3164}', '\u{3164}'),
    ('\u{FE00}', '\u{FE0F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFA0}', '\u{FFA0}'),
    ('\u{FFF0}', '\u{FFF8}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0000}', '\u{E0FFF}'),
];

/// Whether `c` has Unicode's `Default_Ignorable_Code_Point` property.
#[must_use]
pub fn is_default_ignorable(c: char) -> bool {
    DEFAULT_IGNORABLE
        .iter()
        .any(|&(first, last)| first <= c && c <= last)
}

/// Windows' rules for a name that has passed the others.
fn check_windows(name: &str) -> Result<(), NameError> {
    // A backslash never gets here: check_path refuses it everywhere.
    if let Some(c) = name
        .chars()
        .find(|c| matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
    {
        return Err(NameError::Reserved(c));
    }
    // NUL never gets here either.
    if name.chars().any(|c| c < '\u{20}') {
        return Err(NameError::Control);
    }
    if name.ends_with(['.', ' ']) {
        return Err(NameError::TrailingDotOrSpace);
    }
    if is_device(name) {
        return Err(NameError::Device);
    }
    Ok(())
}

/// Whether Windows takes a name for a device: the part before the first dot,
/// without the spaces that end it, is a device name in any case.
fn is_device(name: &str) -> bool {
    let stem = name
        .split_once('.')
        .map_or(name, |(stem, _)| stem)
        .trim_end_matches(' ');
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
    {
        return true;
    }
    let mut chars = stem.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let numbered = prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT");
    numbered
        && matches!(
            (chars.next(), chars.next()),
            (Some('0'..='9' | '¹' | '²' | '³'), None)
        )
}

/// A component of an index path that a [`NamePolicy`] admitted, and that
/// policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    text: String,
    policy: NamePolicy,
}

impl Name {
    /// The name, in NFC.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The policy that admitted it.
    #[must_use]
    pub const fn policy(&self) -> NamePolicy {
        self.policy
    }
}

/// A path the index holds that a [`NamePolicy`] admitted: it passes
/// `check_path`, and the policy admits each of its components.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IndexPath {
    text: String,
    policy: NamePolicy,
}

impl IndexPath {
    /// The path, `/`-separated.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Its components, the first at the folder's root: at least one, each
    /// admitted by the policy.
    pub fn names(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.text.split('/')
    }

    /// Its last component.
    #[must_use]
    pub fn file_name(&self) -> Name {
        Name {
            text: self
                .text
                .rsplit('/')
                .next()
                .unwrap_or(&self.text)
                .to_owned(),
            policy: self.policy,
        }
    }

    /// The policy that admitted it.
    #[must_use]
    pub const fn policy(&self) -> NamePolicy {
        self.policy
    }

    /// The path of `name` in this directory, judged by this path's policy.
    ///
    /// # Errors
    /// What the policy refuses in `name`, or [`NameError::Path`] when the
    /// path would be longer than `check_path` admits.
    pub fn join(&self, name: &Name) -> Result<Self, NameError> {
        let name = self.policy.name(name.as_str())?;
        let length = self.text.len() + 1 + name.as_str().len();
        if length > MAX_PATH_BYTES {
            return Err(NameError::Path(PathError::TooLong(length)));
        }
        Ok(Self {
            text: format!("{}/{}", self.text, name.as_str()),
            policy: self.policy,
        })
    }
}

/// Why a name cannot be stored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// `check_path` refuses the path, or the name as a path.
    Path(PathError),
    /// A disk name holds a `/`.
    Separator,
    /// A disk name is not UTF-8.
    NotUtf8,
    /// The name is not in NFC (on macOS, only an index path's).
    NotNfc,
    /// Longer than [`MAX_NAME_BYTES`]: bytes, or UTF-16 units on Windows.
    TooLong,
    /// A name a file system could take for [`HIDDEN_DIR`].
    Hidden,
    /// Windows: one of `< > : " \ | ? *`.
    Reserved(char),
    /// Windows: a control character, U+0001 to U+001F.
    Control,
    /// Windows: the name ends with a dot or a space.
    TrailingDotOrSpace,
    /// Windows: a device name, such as `CON` or `com1.txt`.
    Device,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(e) => write!(f, "{e}"),
            Self::Separator => f.write_str("the name holds a /"),
            Self::NotUtf8 => f.write_str("the name is not UTF-8"),
            Self::NotNfc => f.write_str("the name is not in Unicode's NFC form"),
            Self::TooLong => write!(
                f,
                "the name is longer than {MAX_NAME_BYTES} bytes (UTF-16 units on Windows)"
            ),
            Self::Hidden => write!(f, "the name could be {HIDDEN_DIR}, which is reserved"),
            Self::Reserved(c) => write!(f, "the name holds {c:?}, which Windows reserves"),
            Self::Control => f.write_str("the name holds a control character"),
            Self::TrailingDotOrSpace => f.write_str("the name ends with a dot or a space"),
            Self::Device => f.write_str("the name is a Windows device name"),
        }
    }
}

impl std::error::Error for NameError {}
