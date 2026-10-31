// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index crate's test vectors (`protocol.md` section 8), committed as
//! JSON under `crates/index/tests/vectors/`: `outcomes.json` (item 6),
//! `heads.json` (item 7), `digests.json` (item 8) and `cleanups.json` (item
//! 12). Every record is built from the keys crate's fixed folder (write secret
//! `10 11 .. 2f`) with fixed nonces and fixed clocks, so each file reproduces
//! byte for byte. Each case runs against real indexes, asserts what the spec
//! says it must show, and records its records, outcomes and section 5 rows;
//! every name is spelled out by the tests, never taken from a `Debug` form.
//!
//! Regenerate after a reviewed change with
//! `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-index vector_`
//! and review the diff.

use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");

fn regenerating() -> bool {
    std::env::var_os("LICKETYSYNC_REGENERATE_VECTORS").is_some()
}

/// Hex of `bytes`.
pub(crate) fn h(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn file_text(generated: &Value) -> String {
    serde_json::to_string_pretty(generated).unwrap() + "\n"
}

/// Compares `generated` with the committed `name.json`, entry by entry for a
/// readable failure and then byte for byte, or writes it when regenerating.
pub(crate) fn check(name: &str, generated: &Value) {
    let path = format!("{DIR}{name}.json");
    if regenerating() {
        std::fs::create_dir_all(DIR).unwrap();
        std::fs::write(&path, file_text(generated)).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{path} is missing; regenerate the vectors"));
    let parsed: Value = serde_json::from_str(&committed).unwrap();
    if let (Some(a), Some(b)) = (generated.as_object(), parsed.as_object()) {
        for (k, v) in a {
            assert_eq!(Some(v), b.get(k), "{name}.json: entry {k} differs");
        }
    }
    assert_eq!(committed, file_text(generated), "{name}.json differs");
}
