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
// crates/keys/src/labels.rs by path, which no case here can show; the scan of
// that file does.

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
// ruleid: no-blake3-imports, extern_keyword-only-in-ffi-crates
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

// The same through an import, and Path's methods (the gate review's finding
// S3: the method forms were not flagged).
use std::fs;
use std::path::{Path, PathBuf};

pub fn resolve_by_method(path: &Path, owned: PathBuf) {
    // ruleid: no-follow-symlinks
    let _ = fs::canonicalize(path);
    // ruleid: no-follow-symlinks
    let _ = fs::read_link(path);
    // ruleid: no-follow-symlinks
    let _ = path.canonicalize();
    // ruleid: no-follow-symlinks
    let _ = path.read_link();
    // ruleid: no-follow-symlinks
    let _ = owned.canonicalize();
    // ruleid: no-follow-symlinks
    let _ = path.join("sub").canonicalize();
    // ruleid: no-follow-symlinks
    let _ = Path::canonicalize(path);
    // ruleid: no-follow-symlinks
    let _ = std::path::Path::read_link(path);
    // ruleid: no-follow-symlinks
    let _ = PathBuf::canonicalize(&owned);
    // ok: no-follow-symlinks
    let _ = path.symlink_metadata();
}

// The same passed as function values, not called.
pub fn resolve_as_values(paths: &[PathBuf]) {
    // ruleid: no-follow-symlinks
    let _ = paths.iter().map(fs::canonicalize).count();
    // ruleid: no-follow-symlinks
    let _ = paths.iter().map(Path::read_link).count();
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

// unsafe_code-only-in-ffi-crates: the banned words, whole, anywhere. These
// comments never spell one; that would be a finding on a line no case names.
// The gap (TM-7): a crate defines sneak!, which reads through a raw pointer,
// and another crate that forbids unsafe_code compiles a::sneak!(p) with no
// lint, and cargo-geiger counts neither. The definition is flagged; the call,
// which shows nothing, is not.
#[macro_export]
macro_rules! sneak {
    // ruleid: unsafe_code-only-in-ffi-crates
    ($p:expr) => { unsafe { *$p } };
}

pub fn read_through(p: *const u8) -> u8 {
    // ok: unsafe_code-only-in-ffi-crates
    sneak!(p)
}

// The constructs the lint forbids that need no such block in edition 2021,
// each from another crate's macro: a symbol exported under its own name or
// another (a caller's malloc, say), a linker section, and assembly.
#[macro_export]
macro_rules! export_as {
    ($f:ident) => {
        // ruleid: unsafe_code-only-in-ffi-crates
        #[no_mangle]
        // ruleid: extern_keyword-only-in-ffi-crates
        pub extern "C" fn $f() {}
    };
    ($f:ident, $name:literal) => {
        // ruleid: unsafe_code-only-in-ffi-crates
        #[export_name = $name]
        // ruleid: extern_keyword-only-in-ffi-crates
        pub extern "C" fn $f() {}
    };
}

#[macro_export]
macro_rules! placed {
    ($v:ident) => {
        // ruleid: unsafe_code-only-in-ffi-crates
        #[link_section = ".init_array"]
        // ruleid: extern_keyword-only-in-ffi-crates
        pub static $v: extern "C" fn() = run;
    };
}

#[macro_export]
macro_rules! asm_block {
    () => {
        // ruleid: unsafe_code-only-in-ffi-crates
        core::arch::global_asm!("nop");
    };
}

// Code outside macros, a comment, a string and a raw identifier, alike.
// ruleid: unsafe_code-only-in-ffi-crates
pub unsafe fn read_raw(p: *const u8) -> u8 {
    *p
}

pub struct Raw(*const u8);
// ruleid: unsafe_code-only-in-ffi-crates
unsafe impl Send for Raw {}

// ruleid: unsafe_code-only-in-ffi-crates
// SAFETY: an unsafe block needs this comment.
// ruleid: unsafe_code-only-in-ffi-crates
pub const WORD: &str = "unsafe";
// ruleid: unsafe_code-only-in-ffi-crates
pub fn r#unsafe() {}

// The lint's name, other lints' names and other words that hold one pass,
// before it (not_) as after it (_code).
// ok: unsafe_code-only-in-ffi-crates
#[forbid(unsafe_code)]
pub mod forbidding {}
// ok: unsafe_code-only-in-ffi-crates
#[deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]
pub fn is_unsafe_free(cell: &std::cell::UnsafeCell<u8>) -> bool {
    let _ = cell;
    true
}
// ok: unsafe_code-only-in-ffi-crates
pub fn not_unsafe() {}

// extern_keyword-only-in-ffi-crates: the keyword, in every form: blocks, linking or empty, a
// nested comment, the forms that name a crate or declare Rust, and the
// keyword passed to a macro that builds a block with it.
pub mod blocks {
    #[link(name = "../notes.o", kind = "static", modifiers = "+verbatim")]
    // ruleid: extern_keyword-only-in-ffi-crates
    extern "C" {}
    // ruleid: extern_keyword-only-in-ffi-crates
    extern {}
    // ruleid: extern_keyword-only-in-ffi-crates
    extern /* a comment */ "system" {
        fn f();
    }
    // ruleid: unsafe_code-only-in-ffi-crates, extern_keyword-only-in-ffi-crates
    unsafe extern "C" {}
    // ruleid: extern_keyword-only-in-ffi-crates
    extern /* /* */ fn */ "C" {}
    // ruleid: extern_keyword-only-in-ffi-crates
    extern crate alloc;
    // ruleid: extern_keyword-only-in-ffi-crates
    pub extern "C" fn callable() {}
    // ruleid: extern_keyword-only-in-ffi-crates
    pub extern fn plain() {}
    // ruleid: extern_keyword-only-in-ffi-crates
    pub type Callback = extern /* c */ "C" /* d */ fn();

    // A matcher that takes the keyword where it would have passed, and a
    // block built from it.
    macro_rules! relocate {
        ($e:tt fn) => {
            #[link(name = "notes")]
            $e "C" {}
        };
    }
    // ruleid: extern_keyword-only-in-ffi-crates
    relocate!(extern fn);

    // ok: extern_keyword-only-in-ffi-crates
    pub fn externally() {}
    // ok: extern_keyword-only-in-ffi-crates
    pub fn not_extern_here() {}
}

// other_files-only-as-data: every way to compile in another file, and what
// may stay. These comments never spell a banned form.
pub mod compiled_in {
    // ruleid: other_files-only-as-data
    include!("notes.txt");
    // ruleid: other_files-only-as-data
    include ! ("../../../outside.rs");
    // ruleid: other_files-only-as-data
    std::include!("notes.txt");
    // ruleid: other_files-only-as-data
    use std::include as bring;
    // ruleid: other_files-only-as-data
    pass_name!(include);
    // Another crate's macros that compile files in, by name.
    // ruleid: other_files-only-as-data
    include_proto!("notes");
    // ruleid: other_files-only-as-data
    static NOTES_DIR: Dir = include_dir!("notes");
    // ruleid: other_files-only-as-data
    include_str_compressed!("notes.txt");

    // ruleid: other_files-only-as-data
    #[path = "notes.txt"]
    pub mod notes;
    // ruleid: other_files-only-as-data
    # [ path= "notes.txt" ]
    pub mod spaced;
    // ruleid: other_files-only-as-data
    #[path /* a comment */ = "notes.txt"]
    pub mod commented;
    // ruleid: other_files-only-as-data
    #[cfg_attr(all(), path = "notes.txt")]
    pub mod conditional;
    pub mod inner {
        // ruleid: other_files-only-as-data
        #![path = "notes"]
    }
    // The attribute's name alone, whatever follows it.
    // ruleid: other_files-only-as-data
    #[path]
    pub mod named_alone;

    // An attribute a macro builds from parts its callers pass.
    macro_rules! at {
        ($a:ident, $f:literal) => {
            // ruleid: other_files-only-as-data
            #[$a = $f]
            pub mod built;
        };
        // ruleid: other_files-only-as-data
        ($c:meta, $a:ident, $f:literal) => {
            // ruleid: other_files-only-as-data
            #[cfg_attr(all($c), $a = $f)]
            pub mod built_if;
        };
    }
    // A name passed through one macro into another's meta fragment.
    macro_rules! outer {
        // ruleid: other_files-only-as-data
        ($doc:meta) => {
            // ruleid: other_files-only-as-data
            #[$doc]
            pub mod hidden;
        };
    }
    macro_rules! relay {
        ($k:ident) => {
            outer!($k = "notes.txt");
        };
    }
    relay!(path);
    // The name written out, its = and value passed in.
    macro_rules! spelled {
        ($e:tt, $f:tt) => {
            // ruleid: other_files-only-as-data
            #[path $e $f]
            pub mod spelled_out;
        };
    }
    spelled!(=, "notes.txt");
    // The # passed in, the name written out.
    macro_rules! hashed {
        ($h:tt, $e:tt, $f:tt) => {
            // ruleid: other_files-only-as-data
            $h[path $e $f]
            pub mod hashed_out;
        };
    }

    // The harness's two copies, by their exact text, and data.
    pub mod harness {
        // ok: other_files-only-as-data
        include!("handshake_harness.rs");
    }
    // ok: other_files-only-as-data
    include!("../../crates/protocol/src/vectors/handshake_harness.rs");
    // ruleid: other_files-only-as-data
    include!("handshake_harness.txt");
    // ok: other_files-only-as-data
    pub const NOTES: &str = include_str!("notes.txt");
    // ok: other_files-only-as-data
    pub const SEEDS: &[u8] = include_bytes!("seeds.bin");
    // ok: other_files-only-as-data
    pub fn included_already() {}

    // Fields, bindings and comparisons named path, longer names, and the
    // doc comments the keys crate's macros pass on.
    pub fn named(mut m: Meta, other: &str) -> bool {
        // ok: other_files-only-as-data
        let path = "a/b";
        // ok: other_files-only-as-data
        let mut path = String::new();
        // ok: other_files-only-as-data
        m.path = path.clone();
        // ok: other_files-only-as-data
        path == other
    }
    // ok: other_files-only-as-data
    #[pathfinder]
    pub mod found {}
    // ok: other_files-only-as-data
    pass_tokens!($x: metrics);
    macro_rules! documented {
        // ok: other_files-only-as-data
        ($(#[doc = $doc:expr])* $name:ident, $path:expr) => {
            // ok: other_files-only-as-data
            $(#[doc = $doc])*
            pub struct $name;
        };
    }
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
