// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the engine's integration tests share: a convergence predicate for
//! the honest members among scripted peers, and the scripted peers of the
//! adversary and outsider tests ([`peers`]).

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test code; each test binary uses part of this module"
)]

pub(crate) mod peers;

use std::collections::BTreeMap;

use licketysync_engine::{Engine, FolderState};
use licketysync_keys::FolderId;
use licketysync_sim::scenario::Sim;

use peers::TestPeer;

/// Everything `engine` holds of `folder` that converged members agree on.
pub(crate) fn fingerprint(engine: &Engine, folder: &FolderId) -> Vec<u8> {
    let mut out = Vec::new();
    engine.fingerprint(folder, &mut |b: &[u8]| {
        out.extend_from_slice(&(b.len() as u64).to_le_bytes());
        out.extend_from_slice(b);
    });
    out
}

/// What every member of `folder` agrees on whatever its tier: the part of
/// [`fingerprint`] before the heads, which a sealed holder computes none of.
pub(crate) fn records_print(engine: &Engine, folder: &FolderId) -> Vec<u8> {
    let mut out = Vec::new();
    let mut heads = false;
    engine.fingerprint(folder, &mut |b: &[u8]| {
        heads |= b == b"heads";
        if !heads {
            out.extend_from_slice(&(b.len() as u64).to_le_bytes());
            out.extend_from_slice(b);
        }
    });
    out
}

/// Converged when every member (an outsider's included) has finished its
/// workload, has no staged writes and every folder Up to date with nothing
/// lacking, and every member of a folder holds the same records as the
/// others (the heads follow from the records at every read and write
/// holder).
pub(crate) fn honest_converged(sim: &Sim<TestPeer>) -> bool {
    let mut seen: BTreeMap<FolderId, Vec<u8>> = BTreeMap::new();
    let mut any = false;
    for (id, p) in sim.peers() {
        let Some(m) = p.member() else {
            continue;
        };
        let Some(e) = m.engine() else {
            return false;
        };
        any = true;
        if !m.done() || sim.storage(id).is_none_or(|s| s.staged_len() != 0) {
            return false;
        }
        for folder in e.folder_ids() {
            let v = e.folder(&folder).unwrap();
            if v.state != FolderState::UpToDate || !v.lacking.is_empty() {
                return false;
            }
            let print = records_print(e, &folder);
            if seen.entry(folder).or_insert_with(|| print.clone()) != &print {
                return false;
            }
        }
    }
    any
}
