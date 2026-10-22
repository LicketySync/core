// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Feature names and the feature set (`protocol.md` section 5). A feature name
//! is `[a-z0-9:-]{1,32}`. A device's feature set is its Hello `features` plus
//! `compression:<c>` for every entry of `compressions` and `hash:<h>` for every
//! entry of `hashes`, so every set contains `compression:none` and
//! `hash:blake3`. Features are negotiated per connection, in the Hello, and
//! nothing folder-wide requires one (ruling S-2); major 1 defines none beyond
//! the compression and hash names.

use crate::limits::{MAX_FEATURE_NAME_BYTES, MAX_LIST_ENTRY_BYTES};

/// The compression every device can decode.
pub const COMPRESSION_NONE: &str = "none";
/// The hash every major-1 device must list.
pub const HASH_BLAKE3: &str = "blake3";

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b':' || b == b'-'
}

/// Whether `name` matches the feature grammar `[a-z0-9:-]{1,32}`.
#[must_use]
pub fn is_feature_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_FEATURE_NAME_BYTES && name.bytes().all(is_name_byte)
}

/// Whether `name` is a valid `compressions` or `hashes` entry,
/// `[a-z0-9-]{1,20}`, so that `compression:<c>` and `hash:<h>` fit the
/// feature grammar.
#[must_use]
pub fn is_list_entry(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_LIST_ENTRY_BYTES
        && name.bytes().all(|b| b != b':' && is_name_byte(b))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn grammars() {
        assert!(is_feature_name("compression:zstd"));
        assert!(is_feature_name(&"a".repeat(32)));
        assert!(!is_feature_name(&"a".repeat(33)));
        assert!(!is_feature_name(""));
        assert!(!is_feature_name("Upper"));
        assert!(!is_feature_name("space here"));
        assert!(is_list_entry("blake3"));
        assert!(is_list_entry(&"a".repeat(20)));
        assert!(!is_list_entry(&"a".repeat(21)));
        assert!(
            !is_list_entry("hash:x"),
            "a colon would break the feature set"
        );
        assert!(!is_list_entry(""));
    }
}
