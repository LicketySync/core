// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The crate's label registry against the specs' tables, read from the
//! repository at test time so that drift on either side fails here: every
//! label in `spec/keys.md` section 10 is in the crate with the same mode and
//! input and the crate has no other, and `spec/suites.md` section 2.4's copy
//! of that registry is identical to it, row for row.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]
#![allow(
    unused_crate_dependencies,
    reason = "an integration test sees every dependency of the crate"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use licketysync_keys::labels::{Mode, REGISTRY};

fn spec(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "spec", name]
        .iter()
        .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn mode_of(cell: &str) -> Mode {
    let cell = cell.trim();
    if cell == "derive_key" {
        Mode::DeriveKey
    } else if cell.starts_with("`H`") {
        Mode::Hash
    } else if cell.starts_with("prefix of `M`") {
        Mode::SigPrefix
    } else {
        panic!("unknown mode cell {cell:?}")
    }
}

/// The label rows of the first table after `heading`, up to the next heading:
/// each row's backticked labels (a row may list one full label and then
/// further purposes under the same area) with the row's mode and, when the
/// table has one, its "Material / input" cell (Markdown's `\|` read as `|`).
fn table(text: &str, heading: &str) -> BTreeMap<String, Mode> {
    rows(text, heading)
        .into_iter()
        .map(|(l, (m, _))| (l, m))
        .collect()
}

fn rows(text: &str, heading: &str) -> BTreeMap<String, (Mode, String)> {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("no heading {heading:?}"));
    let mut out = BTreeMap::new();
    let mut in_table = false;
    for line in text[start + heading.len()..].lines() {
        if line.starts_with('#') {
            break;
        }
        if !line.starts_with("| `licketysync/") {
            if in_table && !line.starts_with('|') {
                break;
            }
            continue;
        }
        in_table = true;
        let cells: Vec<&str> = line.split(" | ").collect();
        let labels = cells[0].trim_start_matches("| ");
        let mode = mode_of(cells[1]);
        let input = cells
            .get(2)
            .map_or(String::new(), |c| c.trim().replace("\\|", "|"));
        let mut parts = labels.split('`').skip(1).step_by(2);
        let first = parts.next().unwrap().to_string();
        let area = &first[..=first.rfind('/').unwrap()];
        out.insert(first.clone(), (mode, input.clone()));
        for suffix in parts {
            out.insert(format!("{area}{suffix}"), (mode, input.clone()));
        }
    }
    assert!(!out.is_empty(), "no rows under {heading:?}");
    out
}

fn crate_registry() -> BTreeMap<String, Mode> {
    REGISTRY
        .iter()
        .map(|e| (e.label.to_string(), e.mode))
        .collect()
}

#[test]
fn registry_matches_keys_md_section_10_exactly() {
    let spec = table(&spec("keys.md"), "## 10. Label registry");
    let ours = crate_registry();
    for (label, mode) in &spec {
        assert_eq!(
            ours.get(label),
            Some(mode),
            "keys.md registers {label} as {mode:?}"
        );
    }
    for (label, mode) in &ours {
        assert_eq!(
            spec.get(label),
            Some(mode),
            "the crate has {label} ({mode:?}), keys.md does not"
        );
    }
    assert_eq!(spec.len(), 25);
}

#[test]
fn registry_inputs_match_keys_md_section_10() {
    let spec = rows(&spec("keys.md"), "## 10. Label registry");
    for entry in REGISTRY {
        let (_, input) = &spec[entry.label];
        assert_eq!(
            entry.input, input,
            "keys.md applies {} to {input:?}",
            entry.label
        );
    }
}

#[test]
fn registry_covers_suites_md_section_2_4() {
    let spec = table(&spec("suites.md"), "### 2.4");
    let ours = crate_registry();
    for (label, mode) in &spec {
        assert_eq!(
            ours.get(label),
            Some(mode),
            "suites.md lists {label} as {mode:?}"
        );
    }
    assert_eq!(spec.len(), 25);
}

/// `suites.md` 2.4 says its table is `keys.md`'s registry "copied row for row
/// and byte for byte so that the two can be compared mechanically".
#[test]
fn suites_md_section_2_4_copies_keys_md_section_10_row_for_row() {
    let rows_of = |text: &str, heading: &str| -> Vec<String> {
        let start = text.find(heading).unwrap();
        text[start..]
            .lines()
            .skip_while(|l| !l.starts_with("| `licketysync/"))
            .take_while(|l| l.starts_with('|'))
            .map(str::to_string)
            .collect()
    };
    let keys = rows_of(&spec("keys.md"), "## 10. Label registry");
    let suites = rows_of(&spec("suites.md"), "### 2.4");
    assert_eq!(keys.len(), 25, "one label per row");
    assert_eq!(keys, suites);
}
