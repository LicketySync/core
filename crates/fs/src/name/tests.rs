// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The name policy, one test per rule, on every platform: each policy is a
//! value, so Linux's, macOS's and Windows' rules are all tested wherever the
//! tests run.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use super::*;
use proptest::prelude::*;

use NamePolicy::{Linux, Macos, Windows};

const ALL: [NamePolicy; 3] = [Linux, Macos, Windows];

fn name(policy: NamePolicy, s: &str) -> Result<Name, NameError> {
    policy.name(s)
}

#[test]
fn ordinary_names_and_paths_pass_everywhere() {
    for policy in ALL {
        for s in [
            "a", "file.txt", ".hidden", "x..y", "名前", "café", "a b", "-", "~",
        ] {
            let admitted = name(policy, s).unwrap();
            assert_eq!(admitted.as_str(), s, "{policy:?}");
            assert_eq!(admitted.policy(), policy);
            assert_eq!(policy.from_disk(s.as_bytes()), name(policy, s));
        }
        let p = policy.index_path("dir/sub/file.txt").unwrap();
        assert_eq!(p.as_str(), "dir/sub/file.txt");
        assert_eq!(p.names().collect::<Vec<_>>(), ["dir", "sub", "file.txt"]);
        assert_eq!(p.file_name().as_str(), "file.txt");
        assert_eq!(
            policy.index_path("top").unwrap().file_name().as_str(),
            "top"
        );
        assert_eq!(p.policy(), policy);
    }
}

#[test]
fn the_hidden_directory_is_refused_in_any_case_at_any_depth() {
    for policy in ALL {
        for s in [
            ".licketysync",
            ".LICKETYSYNC",
            ".LicketySync",
            ".lickeTysYnc",
            // The long s, whose upper case is S: a case-insensitive file
            // system folds it to s.
            ".licketyſync",
            // The dotless i, whose upper case is I.
            ".lıcketysync",
        ] {
            assert_eq!(name(policy, s), Err(NameError::Hidden), "{policy:?} {s}");
            assert_eq!(policy.from_disk(s.as_bytes()), Err(NameError::Hidden));
        }
        for p in [
            ".licketysync",
            "a/.licketysync",
            "a/.LicketySync/b",
            "a/b/.LICKETYSYNC",
        ] {
            assert_eq!(
                policy.index_path(p),
                Err(NameError::Hidden),
                "{policy:?} {p}"
            );
        }
        for s in [
            "licketysync",
            ".licketysync2",
            "..licketysync",
            ".licketysyn",
            ".licketysync.txt",
        ] {
            assert!(name(policy, s).is_ok(), "{policy:?} {s}");
        }
    }
    // The Kelvin sign is not NFC: its NFC form is K, so on macOS the disk
    // name becomes the hidden directory's, and elsewhere it is refused.
    // (Each alias class has a test of its own below.)
    let kelvin = ".lic\u{212A}etysync";
    assert_eq!(Macos.from_disk(kelvin.as_bytes()), Err(NameError::Hidden));
    assert_eq!(Linux.from_disk(kelvin.as_bytes()), Err(NameError::NotNfc));
    assert_eq!(Windows.from_disk(kelvin.as_bytes()), Err(NameError::NotNfc));
}

/// One character of each range of `Default_Ignorable_Code_Point`, which
/// Linux's casefold directories and HFS+ drop when they fold a name.
const IGNORABLE: [char; 17] = [
    '\u{00AD}',
    '\u{034F}',
    '\u{061C}',
    '\u{115F}',
    '\u{17B4}',
    '\u{180B}',
    '\u{200C}',
    '\u{202A}',
    '\u{2060}',
    '\u{3164}',
    '\u{FE0F}',
    '\u{FEFF}',
    '\u{FFA0}',
    '\u{FFF0}',
    '\u{1BCA0}',
    '\u{1D173}',
    '\u{E0001}',
];

#[test]
fn the_hidden_directory_with_ignorable_characters_is_refused() {
    for policy in ALL {
        for c in IGNORABLE {
            for s in [
                format!(".lick{c}etysync"),
                format!("{c}.licketysync"),
                format!(".licketysync{c}"),
                format!(".L{c}{c}ICKETYSYNC"),
            ] {
                assert_eq!(name(policy, &s), Err(NameError::Hidden), "{policy:?} {c:?}");
                assert_eq!(
                    policy.index_path(&format!("a/{s}/b")),
                    Err(NameError::Hidden)
                );
            }
        }
        // A character that is not ignorable makes another name.
        assert!(name(policy, ".lick\u{200A}etysync").is_ok());
    }
}

#[test]
fn the_hidden_directory_with_trailing_dots_or_spaces_is_refused() {
    for policy in ALL {
        for s in [
            ".licketysync.",
            ".licketysync ",
            ".LicketySync. .",
            ".licketysync\u{200B}.",
        ] {
            assert_eq!(name(policy, s), Err(NameError::Hidden), "{policy:?} {s:?}");
        }
        // Dots elsewhere make another name.
        for s in ["..licketysync", ".licketysync.d", ".lickety.sync"] {
            assert!(name(policy, s).is_ok(), "{policy:?} {s}");
        }
    }
}

#[test]
fn windows_short_names_of_the_hidden_directory_are_refused() {
    for policy in ALL {
        for s in [
            "LICKET~1",
            "licket~1",
            "Licket~12",
            "LICKET~1.",
            "licket~9 ",
        ] {
            assert_eq!(name(policy, s), Err(NameError::Hidden), "{policy:?} {s}");
        }
        for s in [
            "LICKET~",
            "LICKET~1A",
            "LICKETY~1",
            "LICKET1",
            "LICKE~1",
            "LICKET~¹",
        ] {
            assert!(name(policy, s).is_ok(), "{policy:?} {s}");
        }
    }
}

#[test]
fn the_default_ignorable_table_is_unicodes() {
    for (first, last) in DEFAULT_IGNORABLE {
        assert!(is_default_ignorable(first), "{first:?}");
        assert!(is_default_ignorable(last), "{last:?}");
        for outside in [u32::from(first) - 1, u32::from(last) + 1] {
            let c = char::from_u32(outside).unwrap();
            assert!(!is_default_ignorable(c), "{c:?}");
        }
    }
    for c in ['a', '.', ' ', '\u{200A}', '\u{2010}', '\u{E1000}'] {
        assert!(!is_default_ignorable(c), "{c:?}");
    }
}

#[test]
fn a_disk_name_that_is_not_utf8_is_refused() {
    for policy in ALL {
        for raw in [&b"\xff"[..], b"na\xefve", b"a\xc3", b"\xed\xa0\x80"] {
            assert_eq!(
                policy.from_disk(raw),
                Err(NameError::NotUtf8),
                "{policy:?} {raw:?}"
            );
        }
    }
}

#[test]
fn what_check_path_refuses_is_refused() {
    for policy in ALL {
        let refused = [
            ("", PathError::Empty),
            ("/a", PathError::Absolute),
            ("a//b", PathError::EmptyComponent),
            ("a/", PathError::EmptyComponent),
            ("a/./b", PathError::DotComponent),
            ("a/..", PathError::DotComponent),
            ("../a", PathError::DotComponent),
            ("a\0b", PathError::Nul),
            ("a\\b", PathError::Backslash),
        ];
        for (p, e) in refused {
            assert_eq!(
                policy.index_path(p),
                Err(NameError::Path(e)),
                "{policy:?} {p:?}"
            );
        }
        let long = "a/".repeat(MAX_PATH_BYTES / 2) + "a";
        assert_eq!(
            policy.index_path(&long),
            Err(NameError::Path(PathError::TooLong(MAX_PATH_BYTES + 1)))
        );
        // As disk names.
        for (raw, e) in [
            (&b""[..], PathError::Empty),
            (b".", PathError::DotComponent),
            (b"..", PathError::DotComponent),
            (b"a\0", PathError::Nul),
            (b"a\\b", PathError::Backslash),
        ] {
            assert_eq!(
                policy.from_disk(raw),
                Err(NameError::Path(e)),
                "{policy:?} {raw:?}"
            );
        }
        for raw in [&b"a/b"[..], b"/", b"/etc", b"../x"] {
            assert_eq!(
                policy.from_disk(raw),
                Err(NameError::Separator),
                "{policy:?} {raw:?}"
            );
        }
    }
}

#[test]
fn a_name_not_in_nfc_is_refused_or_on_macos_normalised() {
    let decomposed = "re\u{301}sume\u{301}";
    let composed = "r\u{e9}sum\u{e9}";
    for policy in ALL {
        // An index path is written in NFC (protocol.md 4.4 step 7); one that
        // is not would read back from the disk as another path.
        assert_eq!(name(policy, decomposed), Err(NameError::NotNfc));
        assert_eq!(
            policy.index_path(&format!("a/{decomposed}")),
            Err(NameError::NotNfc)
        );
        assert_eq!(
            policy.from_disk(composed.as_bytes()).unwrap().as_str(),
            composed
        );
    }
    assert_eq!(
        Macos.from_disk(decomposed.as_bytes()).unwrap().as_str(),
        composed
    );
    // The Ohm sign's NFC form is the Greek capital omega.
    assert_eq!(
        Macos.from_disk("\u{2126}".as_bytes()).unwrap().as_str(),
        "\u{3a9}"
    );
    for policy in [Linux, Windows] {
        assert_eq!(
            policy.from_disk(decomposed.as_bytes()),
            Err(NameError::NotNfc)
        );
    }
}

#[test]
fn macos_judges_the_length_before_and_after_normalising() {
    // 86 decomposed letters are 258 bytes, normalised 172: admitted.
    let fits = "e\u{301}".repeat(86);
    assert_eq!(fits.len(), 258);
    assert_eq!(
        Macos.from_disk(fits.as_bytes()).unwrap().as_str(),
        "\u{e9}".repeat(86)
    );
    // 85 Hangul syllables written as three jamo each are 765 bytes, three
    // times the limit, and normalise to 255: admitted, at the bound.
    let jamo = "\u{1100}\u{1161}\u{11A8}".repeat(85);
    assert_eq!(jamo.len(), 3 * MAX_NAME_BYTES);
    assert_eq!(
        Macos.from_disk(jamo.as_bytes()).unwrap().as_str(),
        "\u{AC01}".repeat(85)
    );
    // One more is over three times the limit: refused before normalising.
    let over = jamo + "\u{1100}\u{1161}\u{11A8}";
    assert_eq!(Macos.from_disk(over.as_bytes()), Err(NameError::TooLong));
    // Within the bound but too long once normalised: refused after.
    let long = "e\u{301}".repeat(MAX_NAME_BYTES);
    assert_eq!(Macos.from_disk(long.as_bytes()), Err(NameError::TooLong));
    // NFC can lengthen a name: U+0344 (2 bytes) is U+0308 U+0301 (4).
    let grows = "\u{344}".repeat(127);
    assert_eq!(grows.len(), 254);
    assert_eq!(Macos.from_disk(grows.as_bytes()), Err(NameError::TooLong));
    // A disk name whose NFC form breaks another rule is refused for it.
    let kelvin = ".lic\u{212A}etysync";
    assert_eq!(Macos.from_disk(kelvin.as_bytes()), Err(NameError::Hidden));
}

#[test]
fn a_name_longer_than_the_platform_counts_is_refused() {
    let most = "a".repeat(MAX_NAME_BYTES);
    let over = "a".repeat(MAX_NAME_BYTES + 1);
    for policy in ALL {
        assert!(name(policy, &most).is_ok());
        assert_eq!(name(policy, &over), Err(NameError::TooLong));
        assert_eq!(policy.from_disk(over.as_bytes()), Err(NameError::TooLong));
    }
    // 255 two-byte characters: 510 bytes, 255 UTF-16 units. APFS counts
    // bytes, so macOS takes Linux's limit, the stricter of the two.
    let accents = "\u{e9}".repeat(MAX_NAME_BYTES);
    assert_eq!(name(Linux, &accents), Err(NameError::TooLong));
    assert_eq!(name(Macos, &accents), Err(NameError::TooLong));
    assert!(name(Windows, &accents).is_ok());
    // 127 of them and one byte are 255 bytes; one byte more is too many.
    let boundary = "\u{e9}".repeat(127) + "a";
    assert_eq!(boundary.len(), MAX_NAME_BYTES);
    assert!(name(Macos, &boundary).is_ok());
    assert_eq!(name(Macos, &(boundary + "a")), Err(NameError::TooLong));
    // A character beyond the BMP is two UTF-16 units.
    let wide = "😀".repeat(MAX_NAME_BYTES / 2) + "a";
    assert!(name(Windows, &wide).is_ok());
    let wider = "😀".repeat(MAX_NAME_BYTES / 2 + 1);
    assert_eq!(name(Windows, &wider), Err(NameError::TooLong));
    assert_eq!(name(Macos, &wider), Err(NameError::TooLong));
    // 85 three-byte characters are 255 bytes; one more is too many on Linux.
    let cjk = "名".repeat(85);
    assert!(name(Linux, &cjk).is_ok());
    assert_eq!(name(Linux, &(cjk + "a")), Err(NameError::TooLong));
}

#[test]
fn windows_reserved_characters_are_refused_there_only() {
    for c in ['<', '>', ':', '"', '|', '?', '*'] {
        for s in [format!("a{c}b"), format!("{c}"), format!("x{c}")] {
            assert_eq!(name(Windows, &s), Err(NameError::Reserved(c)), "{s}");
            assert!(name(Linux, &s).is_ok(), "{s}");
            assert!(name(Macos, &s).is_ok(), "{s}");
        }
    }
    // An alternate data stream.
    assert_eq!(
        name(Windows, "file.txt:secret"),
        Err(NameError::Reserved(':'))
    );
}

#[test]
fn windows_control_characters_are_refused_there_only() {
    for c in 1..0x20_u8 {
        let s = format!("a{}b", char::from(c));
        assert_eq!(name(Windows, &s), Err(NameError::Control), "{c}");
        assert!(name(Linux, &s).is_ok(), "{c}");
        assert!(name(Macos, &s).is_ok(), "{c}");
    }
    assert!(name(Windows, "a\u{7f}b").is_ok());
    assert!(name(Windows, "a\u{20}b").is_ok());
}

#[test]
fn windows_trailing_dots_and_spaces_are_refused_there_only() {
    for s in ["a.", "a ", "a. ", "a..", ". .", "x .", "名 "] {
        assert_eq!(name(Windows, s), Err(NameError::TrailingDotOrSpace), "{s}");
        assert!(name(Linux, s).is_ok(), "{s}");
        assert!(name(Macos, s).is_ok(), "{s}");
    }
    for s in [" a", ".a", "a.b", "a b"] {
        assert!(name(Windows, s).is_ok(), "{s}");
    }
}

#[test]
fn windows_device_names_are_refused_there_only() {
    let mut devices = vec![
        "CON", "con", "Con", "PRN", "prn", "AUX", "aux", "NUL", "nul", "CONIN$", "conin$",
        "CONOUT$", "ConOut$",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    for prefix in ["COM", "com", "Com", "LPT", "lpt", "lPt"] {
        for digit in ['0', '1', '5', '9', '¹', '²', '³'] {
            devices.push(format!("{prefix}{digit}"));
        }
    }
    for device in devices {
        for s in [
            device.clone(),
            format!("{device}.txt"),
            format!("{device}.tar.gz"),
            format!("{device} .txt"),
            format!("{device}  .x"),
        ] {
            assert_eq!(name(Windows, &s), Err(NameError::Device), "{s}");
            assert!(name(Linux, &s).is_ok(), "{s}");
            assert!(name(Macos, &s).is_ok(), "{s}");
        }
    }
    for s in [
        "CONSOLE", "COM10", "LPT", "COM", "COMA", "LPT⁴", "xCON", "CON_", "NULL", "AUXX", "con-x",
        "a.CON", "CONIN", "CONOUT", "CON$", " CON", "CO", "COM¹0", "COMx.txt",
    ] {
        assert!(name(Windows, s).is_ok(), "{s}");
    }
}

#[test]
fn a_path_takes_the_policy_rules_at_every_depth() {
    assert_eq!(Windows.index_path("a/CON/b"), Err(NameError::Device));
    assert_eq!(Windows.index_path("a/b/c?"), Err(NameError::Reserved('?')));
    assert!(Linux.index_path("a/CON/b").is_ok());
}

#[test]
fn join_judges_the_name_by_the_paths_policy_and_the_path_by_check_path() {
    let dir = Linux.index_path("dir").unwrap();
    let file = Linux.name("CON").unwrap();
    let joined = dir.join(&file).unwrap();
    assert_eq!(joined.as_str(), "dir/CON");
    assert_eq!(joined.names().count(), 2);
    assert_eq!(joined.file_name(), file);
    assert_eq!(joined, Linux.index_path("dir/CON").unwrap());
    // The same name, made by Linux's policy, joined to a Windows path.
    let windows = Windows.index_path("dir").unwrap();
    assert_eq!(windows.join(&file), Err(NameError::Device));
    // Too long a path.
    let mut deep = Linux.index_path(&"a".repeat(MAX_NAME_BYTES)).unwrap();
    let part = Linux.name(&"b".repeat(MAX_NAME_BYTES)).unwrap();
    while deep.as_str().len() + 1 + MAX_NAME_BYTES <= MAX_PATH_BYTES {
        deep = deep.join(&part).unwrap();
    }
    let over = deep.as_str().len() + 1 + MAX_NAME_BYTES;
    assert_eq!(
        deep.join(&part),
        Err(NameError::Path(PathError::TooLong(over)))
    );
    // The longest path joins; one byte more does not.
    let base = Linux.index_path(&("a/".repeat(2046) + "aa")).unwrap();
    assert_eq!(base.as_str().len(), MAX_PATH_BYTES - 2);
    let longest = base.join(&Linux.name("b").unwrap()).unwrap();
    assert_eq!(longest.as_str().len(), MAX_PATH_BYTES);
    assert_eq!(longest, Linux.index_path(longest.as_str()).unwrap());
    assert_eq!(
        base.join(&Linux.name("bc").unwrap()),
        Err(NameError::Path(PathError::TooLong(MAX_PATH_BYTES + 1)))
    );
}

#[test]
fn the_native_policy_is_the_platforms() {
    let expected = if cfg!(windows) {
        Windows
    } else if cfg!(target_vendor = "apple") {
        Macos
    } else {
        Linux
    };
    assert_eq!(NamePolicy::native(), expected);
}

#[test]
fn every_refusal_says_why() {
    let errors = [
        NameError::Path(PathError::Empty),
        NameError::Separator,
        NameError::NotUtf8,
        NameError::NotNfc,
        NameError::TooLong,
        NameError::Hidden,
        NameError::Reserved('?'),
        NameError::Control,
        NameError::TrailingDotOrSpace,
        NameError::Device,
    ];
    let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
    for (e, text) in errors.iter().zip(&texts) {
        assert!(!text.is_empty(), "{e:?}");
    }
    let distinct: std::collections::BTreeSet<&String> = texts.iter().collect();
    assert_eq!(distinct.len(), texts.len());
    assert_eq!(
        NameError::Path(PathError::Empty).to_string(),
        PathError::Empty.to_string()
    );
    assert!(NameError::Reserved('?').to_string().contains("'?'"));
    assert!(NameError::Hidden.to_string().contains(HIDDEN_DIR));
    assert!(NameError::TooLong.to_string().contains("bytes"));
}

/// Characters that make every rule fire: the separator, dots, the backslash,
/// NUL, Windows' reserved and control characters, spaces, letters of the
/// hidden directory's name in both cases with the long s and dotless i,
/// ignorable characters, the tilde and digits of a short name, a combining
/// accent and a precomposed letter, and characters beyond the BMP.
fn tricky() -> impl Strategy<Value = String> {
    let chars = prop::sample::select(vec![
        '/', '.', '\\', '\0', '<', ':', '*', '\u{1}', '\u{1f}', ' ', 'a', 'l', 'i', 'c', 'k', 'e',
        't', 'y', 's', 'n', 'L', 'I', 'C', 'K', 'E', 'T', 'Y', 'S', 'N', 'O', 'P', 'R', 'U', 'X',
        'M', '1', '¹', '$', 'ſ', 'ı', '\u{212A}', '\u{301}', '\u{e9}', '名', '😀', '~', '9',
        '\u{200C}', '\u{FEFF}', '\u{AD}',
    ]);
    prop::collection::vec(chars, 0..40).prop_map(|v| v.into_iter().collect())
}

proptest! {
    /// The policy admits no path that check_path refuses, and refuses each
    /// such path with check_path's own reason.
    #[test]
    fn the_policy_admits_only_what_check_path_admits(s in prop_oneof![tricky(), any::<String>()]) {
        for policy in ALL {
            match check_path(&s) {
                Err(e) => prop_assert_eq!(policy.index_path(&s), Err(NameError::Path(e))),
                Ok(()) => {
                    if let Ok(p) = policy.index_path(&s) {
                        prop_assert_eq!(p.as_str(), s.as_str());
                        prop_assert!(p.names().eq(s.split('/')));
                    }
                }
            }
        }
    }

    /// A disk name the policy admits is a one-component path check_path
    /// admits, in NFC, which the policy admits again unchanged, from the
    /// disk and from the index.
    #[test]
    fn a_disk_name_admitted_is_a_component_check_path_admits(
        raw in prop_oneof![
            tricky().prop_map(String::into_bytes),
            prop::collection::vec(any::<u8>(), 0..300),
        ]
    ) {
        for policy in ALL {
            if let Ok(n) = policy.from_disk(&raw) {
                prop_assert!(check_path(n.as_str()).is_ok());
                prop_assert!(!n.as_str().contains('/'));
                prop_assert!(is_nfc(n.as_str()));
                prop_assert_eq!(policy.from_disk(n.as_str().as_bytes()), Ok(n.clone()));
                prop_assert_eq!(policy.name(n.as_str()), Ok(n.clone()));
                let p = policy.index_path(n.as_str()).unwrap();
                prop_assert_eq!(p.file_name(), n.clone());
                prop_assert!(p.names().eq([n.as_str()]));
                if !policy.folds_unicode_forms() {
                    prop_assert_eq!(n.as_str().as_bytes(), &raw[..]);
                }
            }
        }
    }
}
