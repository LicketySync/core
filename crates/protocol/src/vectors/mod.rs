// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The test vectors of `protocol.md` section 8, committed as JSON under
//! `crates/protocol/tests/vectors/`. Each `vector_*` test computes its file
//! with this crate (over the keys crate's fixed folder, write secret
//! `10 11 .. 2f`, and fixed devices), checks what every vector must show by
//! feeding it to the decoder or to a connection and asserting the section 5
//! row it reaches, and compares the result with the committed file byte for
//! byte. A **decoder vector** is bytes and the outcome a decoder or a
//! connection in a named state gives them; a **connection vector** is a
//! scenario between two connections, recorded as every frame each side handed
//! to the transport with its time, the rows reached and the end state.
//!
//! Regenerate after a reviewed change of format with
//! `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-protocol vector_`,
//! which also rewrites the fuzz seeds under `fuzz/seeds/`, and review the
//! diff. Item 7 (heads) and the cached-digest vectors of item 8 are the index
//! crate's (coordinator ruling of 2026-10-22).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::many_single_char_names,
    reason = "test code"
)]

mod chunks;
mod exchange;
mod frames;
mod handshake;
mod index_record;
mod status;

use core::time::Duration;

use serde_json::{json, Value};

use crate::connection::{Event, Side as Who};
use crate::testkit::{Pair, Side};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");
const SEEDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/");

fn regenerating() -> bool {
    std::env::var_os("LICKETYSYNC_REGENERATE_VECTORS").is_some()
}

pub(crate) fn h(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

/// An input as a vector records it: in full up to 4 KiB, otherwise its
/// length and first 64 bytes (the test that writes it feeds the whole).
pub(crate) fn input(bytes: &[u8]) -> Value {
    if bytes.len() <= 4096 {
        h(bytes)
    } else {
        json!({ "len": bytes.len(), "prefix": h(&bytes[..64]) })
    }
}

fn file_text(generated: &Value) -> String {
    serde_json::to_string_pretty(generated).unwrap() + "\n"
}

/// Compares `generated` with the committed `name.json`, entry by entry for a
/// readable failure and then byte for byte, or writes it when regenerating.
pub(crate) fn check(name: &str, generated: &Value) {
    let path = format!("{DIR}{name}.json");
    if regenerating() {
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

/// Writes a fuzz seed when regenerating.
pub(crate) fn seed(target: &str, name: &str, bytes: &[u8]) {
    // Fuzz inputs past 64 KiB help no fuzzer (its default bound is 4 KiB).
    if regenerating() && bytes.len() <= 65_536 {
        let dir = format!("{SEEDS}{target}");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/{name}"), bytes).unwrap();
    }
}

/// How a side's connection ended, as a vector names it.
pub(crate) fn ending(side: &Side) -> Value {
    side.events
        .iter()
        .find_map(|e| match e {
            Event::Closed {
                reason, by, cause, ..
            } => Some(json!({
                "closed": reason.name(),
                "by": if *by == Who::Local { "self" } else { "peer" },
                "row": cause.map(|c| format!("{c:?}")),
            })),
            _ => None,
        })
        .unwrap_or_else(|| json!("open"))
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap()
}

/// Every frame a side handed over, with its time in milliseconds.
pub(crate) fn sent(side: &Side) -> Value {
    Value::Array(
        side.sent
            .iter()
            .map(|(t, f)| json!([ms(*t), h(f)]))
            .collect(),
    )
}

/// A connection vector: the scenario's frames both ways, its rows and the
/// end state of each side.
pub(crate) fn scenario(p: &Pair, rows: &[&str], extra: Value) -> Value {
    json!({
        "rows": rows,
        "a_sent": sent(&p.a),
        "b_sent": sent(&p.b),
        "a_end": ending(&p.a),
        "b_end": ending(&p.b),
        "a_records": p.a.store.len(),
        "b_records": p.b.store.len(),
        "notes": extra,
    })
}

/// The outcome a connection in `state` gives `bytes` from the peer: closed
/// with a reason and row, answered `Unsupported`, or accepted.
pub(crate) fn feed(state: &str, bytes: &[u8]) -> String {
    let mut p = match state {
        "first" => Pair::new(0xa0, 0xb0, &[key()], &[key()]),
        "before-device-proof" => {
            let mut p = Pair::new(0xa0, 0xb0, &[key()], &[key()]);
            let hello = core::mem::take(&mut p.b.outbox);
            p.a.receive(p.now, &hello);
            p
        }
        "established" => Pair::open(),
        _ => panic!("state {state}"),
    };
    p.b.auto = false;
    let before = p.a.sent.len();
    p.a.receive(p.now, bytes);
    if let Some(Event::Closed {
        reason, cause, by, ..
    }) =
        p.a.events
            .iter()
            .find(|e| matches!(e, Event::Closed { .. }))
    {
        if *by == Who::Peer {
            return format!("closed by the peer: {}", reason.name());
        }
        return format!(
            "close {} ({})",
            reason.name(),
            cause.map_or("-".into(), |c| format!("{c:?}"))
        );
    }
    let unsupported = p.a.sent[before..]
        .iter()
        .filter(|(_, f)| f[4..6] == [0x00, 0x02])
        .count();
    if unsupported > 0 {
        return format!("unsupported x{unsupported}");
    }
    "accepted".into()
}

pub(crate) fn key() -> licketysync_keys::folder::FolderKey {
    licketysync_keys::folder::FolderKey::from(crate::testkit::folder(0x10))
}
