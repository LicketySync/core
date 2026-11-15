#![no_main]
//! Names as a directory listing gives them, and paths as a record gives
//! them, judged by each platform's name policy (TM-3, TM-4).
//!
//! - The input split at `/` into one name per directory level, each read as
//!   a disk name and joined into an index path. Each name admitted is one
//!   component that `check_path` admits, in NFC, with none of Windows'
//!   reserved characters on Windows, and no name a file system could take
//!   for the hidden directory, which the policy admits again unchanged; each
//!   path built is one `check_path` admits and the policy reads back as
//!   itself (checked once, at the end, so that a deep path costs time linear
//!   in its length).
//! - The input whole, when it is UTF-8, as an index path: one the policy
//!   admits is one `check_path` admits, and none of its components could be
//!   taken for the hidden directory.
//!
//! The oracle for the hidden directory is written here apart from the
//! policy's: without its default-ignorable characters and its trailing dots
//! and spaces, a component is `.licketysync` in any case, or `licket~` and
//! digits.
use libfuzzer_sys::fuzz_target;
use licketysync_fs::name::is_default_ignorable;
use licketysync_fs::{IndexPath, NamePolicy};
use licketysync_protocol::record::check_path;

/// The levels followed: each join copies the path so far, so a path of
/// thousands of levels would cost each run quadratic time, and deeper levels
/// reach nothing that 64 do not (a path too long needs only long names).
const LEVELS: usize = 64;

const POLICIES: [NamePolicy; 3] = [NamePolicy::Linux, NamePolicy::Macos, NamePolicy::Windows];

/// Whether a file system that folds names could take `name` for the hidden
/// directory.
fn folds_to_hidden(name: &str) -> bool {
    let visible: String = name.chars().filter(|c| !is_default_ignorable(*c)).collect();
    let folded = visible.trim_end_matches(|c| c == '.' || c == ' ');
    let lower: String = folded.chars().flat_map(char::to_lowercase).collect();
    let upper: String = folded.chars().flat_map(char::to_uppercase).collect();
    let short = folded.len() > 7
        && folded.is_char_boundary(7)
        && folded[..7].eq_ignore_ascii_case("licket~")
        && folded[7..].bytes().all(|b| b.is_ascii_digit());
    lower == ".licketysync" || upper == ".LICKETYSYNC" || short
}

fuzz_target!(|data: &[u8]| {
    for policy in POLICIES {
        let mut built: Option<IndexPath> = None;
        for raw in data.split(|b| *b == b'/').take(LEVELS) {
            let Ok(name) = policy.from_disk(raw) else {
                break;
            };
            let text = name.as_str();
            assert!(check_path(text).is_ok());
            assert!(!text.contains('/'));
            assert_eq!(policy.from_disk(text.as_bytes()).as_ref(), Ok(&name));
            assert_eq!(policy.name(text).as_ref(), Ok(&name));
            assert!(!folds_to_hidden(text), "{text:?}");
            if policy == NamePolicy::Windows {
                assert!(!text.chars().any(|c| "<>:\"\\|?*".contains(c) || c < ' '));
                assert!(!text.ends_with(['.', ' ']));
            }
            let next = match &built {
                None => policy.index_path(text).expect("one name is a path"),
                Some(parent) => match parent.join(&name) {
                    Ok(next) => next,
                    Err(_) => break,
                },
            };
            assert_eq!(next.file_name(), name);
            built = Some(next);
        }
        if let Some(built) = built {
            assert!(check_path(built.as_str()).is_ok());
            assert_eq!(policy.index_path(built.as_str()).as_ref(), Ok(&built));
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        for policy in POLICIES {
            if let Ok(path) = policy.index_path(text) {
                assert!(check_path(path.as_str()).is_ok());
                for component in path.names() {
                    assert!(!folds_to_hidden(component), "{component:?}");
                }
            }
        }
    }
});
