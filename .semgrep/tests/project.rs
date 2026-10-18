// Cases for the rules in .semgrep/project.yml, run in CI and by gate.sh with
//   semgrep --test --metrics=off --config .semgrep/project.yml .semgrep/tests/project.rs
// Each case is a comment that holds the word ruleid or ok, a colon and a rule
// id, on the line before the code: with ruleid that line must be flagged by the
// rule, with ok it must not be. semgrep --test reads that form wherever a line
// holds it, prose included, so this header never writes it out; and it fails
// unless every rule id the file names has at least one finding here, so every
// rule in project.yml needs a ruleid case in this file. This file is not
// compiled; it only has to parse as Rust. The scan excludes .semgrep/, so these
// lines never count as findings there. The blake3 rules exempt
// crates/keys/src/labels.rs and crates/protocol/src/hash.rs by path, which no
// case here can show; the scan of those two files does.

// no-blake3-imports: every way of importing or aliasing the crate.

// ruleid: no-blake3-imports
use blake3::hash;
// ruleid: no-blake3-imports
use blake3::Hasher;
// ruleid: no-blake3-imports
use blake3::*;
// ruleid: no-blake3-imports
use blake3::{Hasher as Blake, hash as blake_hash};
// ruleid: no-blake3-imports
use blake3 as b3;
// ruleid: no-blake3-imports
use ::blake3::Hasher as AnotherHasher;
// ruleid: no-blake3-imports
pub(crate) use blake3::keyed_hash;
// ruleid: no-blake3-imports
use {
    blake3::Hasher as Grouped,
};
// ruleid: no-blake3-imports
extern crate blake3 as renamed_blake3;
// ok: no-blake3-imports
use crate::labels::labelled_hash;
// ok: no-blake3-imports
use zeroize::Zeroizing;

// blake3-only-in-hash-modules: outside the two hash modules every way into the
// crate is flagged, whatever the function is called, the helpers' own names
// included.
pub fn labelled_hash(label: &str, parts: &[&[u8]]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub fn keyed_hash(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub fn derive_key(label: &str, material: &[u8]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    blake3::derive_key(label, material)
}

pub fn keyed_once(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    *blake3::keyed_hash(key, data).as_bytes()
}

// The plaintext chunk hash without its key: the confirmation-of-a-file mistake.
pub fn plain_hash(chunk: &[u8]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    *blake3::hash(chunk).as_bytes()
}

// The ciphertext hash without its label: a hash of one kind that can equal another.
pub fn cipher_hash(stored: &[u8]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    let mut hasher = blake3::Hasher::new();
    hasher.update(stored);
    *hasher.finalize().as_bytes()
}

pub fn record_hash(body: &[u8]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    let mut hasher = blake3::Hasher::default();
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

pub fn streamed_derive(context: &str, material: &[u8]) -> [u8; 32] {
    // ruleid: blake3-only-in-hash-modules
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

pub fn fingerprint(data: &[u8]) -> bool {
    // ruleid: blake3-only-in-hash-modules
    blake3::hash(data).as_bytes()[0] == 0
}

// What the crates do instead: call the hash modules' helpers, and use blake3's
// types without building a hash.
pub fn through_the_helper(body: &[u8]) -> [u8; 32] {
    // ok: blake3-only-in-hash-modules
    crate::hash::labelled(crate::labels::RECORD, &[body])
}

pub fn compare(a: [u8; 32], b: [u8; 32]) -> bool {
    // ok: blake3-only-in-hash-modules
    blake3::Hash::from_bytes(a) == blake3::Hash::from_bytes(b)
}

// no-follow-symlinks: the resolver opens with no-follow semantics instead.
pub fn resolve(path: &std::path::Path) {
    // ruleid: no-follow-symlinks
    let _ = std::fs::canonicalize(path);
    // ruleid: no-follow-symlinks
    let _ = std::fs::read_link(path);
    // ok: no-follow-symlinks
    let _ = std::fs::symlink_metadata(path);
}

// no-expect-on-remote-data: in crates/protocol and crates/net (and here) every
// `expect` is flagged, since what it unwraps may come from a peer (TM-23).
pub fn decode_hello(bytes: &[u8]) -> Hello {
    // ruleid: no-expect-on-remote-data
    Hello::decode(bytes).expect("the peer sent a valid Hello")
}

pub fn first_byte(bytes: &[u8]) -> u8 {
    // ruleid: no-expect-on-remote-data
    *bytes.first().expect("the frame is not empty")
}

// What the crates do instead: return the decode error, or bound the input.
pub fn decode_hello_checked(bytes: &[u8]) -> Result<Hello, DecodeError> {
    // ok: no-expect-on-remote-data
    Hello::decode(bytes).map_err(DecodeError::from)
}

pub fn decode_len(bytes: &[u8]) -> usize {
    // ok: no-expect-on-remote-data
    bytes.first().map_or(0, |b| usize::from(*b))
}

// Test modules compare against the crate directly, and may import it.
#[cfg(test)]
mod tests {
    // ok: no-blake3-imports
    use blake3::Hasher;

    #[test]
    fn labelled_hash_matches_the_reference() {
        // ok: blake3-only-in-hash-modules
        let mut reference = blake3::Hasher::new();
        reference.update(b"licketysync/v1/hash/record\0x");
        // ok: blake3-only-in-hash-modules
        let plain = blake3::hash(b"x");
        assert_ne!(plain, reference.finalize());
        // ok: blake3-only-in-hash-modules
        let _keyed = blake3::keyed_hash(&[0; 32], b"x");
        let _unused = Hasher::new_keyed(&[0; 32]);
    }
}
