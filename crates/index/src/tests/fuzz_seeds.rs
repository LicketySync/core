// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The seeds of the `index_ops` fuzz target (`fuzz/fuzz_targets/index_ops.rs`,
//! the index security review's NIT 9), written in that target's input format:
//! a header (the tier, then this device's ID), then operations, each an
//! opcode byte and its operands, in the order the target reads them. Each
//! seed starts the fuzzer inside a case worth exploring: a history at each
//! tier, broken stored local sequence numbers and metadata, a base at another
//! path, tree deletes over records beneath them, cleanup groups that wait
//! and apply, forged and garbage signatures, a store that crashes between a
//! change's records and its removals, and a clock set back.
//!
//! Regenerate with
//! `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-index vector_`;
//! otherwise the test checks that the committed seeds are exactly these.

const SEEDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/index_ops/");

/// The target's opcodes.
mod op {
    pub(super) const INDEX: u8 = 0;
    pub(super) const CLEANUP: u8 = 1;
    pub(super) const STORE: u8 = 2;
    pub(super) const STORE_BASE_ONLY: u8 = 3;
    pub(super) const STORE_BASE: u8 = 4;
    pub(super) const STORE_META: u8 = 5;
    pub(super) const OPEN: u8 = 7;
    pub(super) const DELIVER: u8 = 8;
    pub(super) const WRITE: u8 = 9;
    pub(super) const SET_BASE: u8 = 10;
    pub(super) const END_ROUND: u8 = 11;
    pub(super) const ROUND_ENDED: u8 = 12;
    pub(super) const CLOCK: u8 = 13;
    pub(super) const CRASH: u8 = 14;
    pub(super) const REOPEN: u8 = 15;
}

/// The target's path pool: "a", "b", "d", "d/x", "d/y", "d/x/z", "d-x", "e".
mod path {
    pub(super) const A: u8 = 0;
    pub(super) const B: u8 = 1;
    pub(super) const D: u8 = 2;
    pub(super) const DX: u8 = 3;
    pub(super) const DY: u8 = 4;
}

/// The target's device pool: 1, 2, 3, 4 and 9, by index.
const DEV1: u8 = 0;
const DEV2: u8 = 1;
const DEV3: u8 = 2;

/// Tiers.
const WRITE: u8 = 0;
const READ: u8 = 1;
const SEALED: u8 = 2;

/// A counter `secs` seconds after the target's clock.
fn at(secs: u16) -> Vec<u8> {
    let [hi, lo] = secs.to_be_bytes();
    vec![5, hi, lo]
}

/// An index record as the target builds it.
#[derive(Clone)]
struct Rec {
    path: u8,
    kind: u8,
    deleted: bool,
    tree: bool,
    chunks: u8,
    device: u8,
    counter: Vec<u8>,
    vector: Vec<(u8, u8)>,
    names: Vec<u8>,
    /// 0 genuine, 1 forged, 2 a garbage signature.
    variant: u8,
}

fn file(path: u8, device: u8, secs: u16) -> Rec {
    Rec {
        path,
        kind: 1,
        deleted: false,
        tree: false,
        chunks: 1,
        device,
        counter: at(secs),
        vector: Vec::new(),
        names: Vec::new(),
        variant: 0,
    }
}

fn index(r: &Rec) -> Vec<u8> {
    let mut out = vec![op::INDEX, r.path, 0, r.kind];
    let flags = u8::from(r.deleted) | u8::from(r.tree) << 1 | (r.chunks & 3) << 2;
    out.push(flags);
    out.push(7); // the size byte
    out.push(r.device);
    out.extend(&r.counter);
    out.push(u8::try_from(r.vector.len()).unwrap());
    for (d, secs) in &r.vector {
        out.extend([*d, *secs]);
    }
    out.push(u8::try_from(r.names.len()).unwrap());
    out.extend(&r.names);
    out.extend(core::iter::repeat_n(0x33, usize::from(r.chunks & 3)));
    out.push(r.variant);
    out
}

/// A cleanup: per group, its `because` (0 for none, else a pool index) and
/// its names (pool indexes).
fn cleanup(device: u8, secs: u16, groups: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![op::CLEANUP, device];
    out.extend(at(secs));
    out.push(u8::try_from(groups.len() - 1).unwrap());
    for (because, names) in groups {
        out.push(*because);
        out.push(u8::try_from(names.len() - 1).unwrap());
        out.extend(*names);
    }
    out.push(0);
    out
}

fn deliver(r: u8, peer: u8) -> Vec<u8> {
    vec![op::DELIVER, r, peer, 1]
}

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    // A write holder's history: a peer's version, its own writes, a rename,
    // a tree delete, a round's end, a reopen.
    let mut s = vec![WRITE, DEV1];
    s.extend(index(&file(path::A, DEV2, 10)));
    s.extend(index(&file(path::DX, DEV3, 11)));
    s.extend([op::OPEN]);
    s.extend(deliver(0, DEV2));
    s.extend(deliver(1, DEV3));
    s.extend([op::SET_BASE, path::A, 0, 1]);
    s.extend([op::WRITE, 0, path::A, path::B, 9, 1]);
    s.extend([op::WRITE, 3, path::A, path::B, 9, 1]);
    s.extend([op::WRITE, 2, path::A, path::A, 2, 1]);
    s.extend([op::END_ROUND, 1, op::ROUND_ENDED, DEV2, 1, 5, 1, op::REOPEN]);
    out.push(("write-holder-history", s));
    // Stored local sequence numbers repeated, 0 and past MAX_LOCAL_SEQ.
    let mut s = vec![READ, DEV1];
    s.extend(index(&file(path::A, DEV2, 1)));
    s.extend(index(&file(path::B, DEV2, 2)));
    s.extend(index(&file(path::DX, DEV3, 3)));
    s.extend([op::STORE, 0, 4, op::STORE, 1, 1, op::STORE, 2, 0]);
    s.extend([op::OPEN, op::REOPEN]);
    out.push(("stored-seqs-repeated-and-zero", s));
    let mut s = vec![WRITE, DEV1];
    s.extend(index(&file(path::A, DEV1, 1)));
    s.extend([op::STORE, 0, 3, op::STORE_META]);
    s.extend(at(1));
    s.extend([
        3,
        7,
        op::OPEN,
        op::WRITE,
        0,
        path::B,
        path::B,
        1,
        1,
        op::REOPEN,
    ]);
    out.push(("stored-next-seq-past-max", s));
    // A base slot whose record lies at another path, and one kept only as a
    // base.
    let mut s = vec![WRITE, DEV1];
    s.extend(index(&file(path::A, DEV2, 1)));
    s.extend(index(&file(path::B, DEV2, 2)));
    s.extend([
        op::STORE,
        0,
        4,
        op::STORE_BASE_ONLY,
        1,
        op::STORE_BASE,
        path::B,
        0,
        0,
    ]);
    s.extend([op::OPEN, op::WRITE, 0, path::B, path::B, 3, 1, op::REOPEN]);
    out.push(("a-base-at-another-path", s));
    // Records beneath a directory, a tree delete that covers some, a nested
    // one, at a read holder.
    let mut s = vec![READ, DEV1];
    s.extend(index(&file(path::DX, DEV2, 1)));
    s.extend(index(&file(path::DY, DEV3, 2)));
    let mut td = file(path::D, DEV2, 5);
    td.kind = 2;
    td.deleted = true;
    td.tree = true;
    td.chunks = 0;
    td.vector = vec![(DEV2, 1)];
    s.extend(index(&td));
    let mut later = td.clone();
    later.counter = at(9);
    later.vector = vec![(DEV2, 5), (DEV3, 2)];
    s.extend(index(&later));
    s.extend([op::OPEN]);
    for r in [0, 1, 2, 3, 2, 0] {
        s.extend(deliver(r, DEV2));
    }
    s.extend([op::REOPEN]);
    out.push(("tree-deletes-over-records-beneath", s));
    // Cleanup groups at a sealed peer: one that waits for its because, then
    // applies when it arrives; a replay.
    let mut s = vec![SEALED, DEV1];
    s.extend(index(&file(path::A, DEV2, 1)));
    s.extend(index(&file(path::B, DEV2, 2)));
    s.extend(cleanup(DEV2, 3, &[(1, &[0])]));
    s.extend([op::OPEN]);
    for r in [0, 2, 1, 2, 0] {
        s.extend(deliver(r, DEV3));
    }
    s.extend([op::REOPEN]);
    out.push(("cleanup-groups-at-a-sealed-peer", s));
    // Forged and garbage signatures, offered as new and as stale copies.
    let mut s = vec![WRITE, DEV1];
    let mut forged = file(path::A, DEV2, 1);
    forged.variant = 1;
    s.extend(index(&forged));
    let mut garbage = file(path::A, DEV3, 2);
    garbage.variant = 2;
    s.extend(index(&garbage));
    s.extend(index(&file(path::A, DEV2, 3)));
    s.extend([op::OPEN]);
    for r in [0, 1, 2, 1, 0] {
        s.extend(deliver(r, DEV2));
    }
    s.extend([op::END_ROUND, 1]);
    out.push(("forged-and-garbage-signatures", s));
    // A store that crashes between a change's records and its removals.
    let mut s = vec![WRITE, DEV1];
    s.extend([op::OPEN, op::WRITE, 0, path::A, path::A, 1, 1]);
    s.extend([op::CRASH, op::WRITE, 0, path::A, path::A, 2, 1]);
    s.extend([op::CRASH, op::WRITE, 2, path::A, path::A, 0, 1, op::REOPEN]);
    out.push(("a-crash-between-records-and-removals", s));
    // Deletions forgotten by the folder's time, then a clock set back.
    let mut s = vec![READ, DEV1];
    let mut tomb = file(path::B, DEV2, 1);
    tomb.deleted = true;
    tomb.chunks = 0;
    s.extend(index(&tomb));
    let mut late = file(path::A, DEV3, 1);
    late.counter = vec![3];
    s.extend(index(&late));
    s.extend([op::OPEN]);
    s.extend(deliver(0, DEV2));
    s.extend([op::CLOCK, 0]);
    s.extend(deliver(1, DEV3));
    s.extend(deliver(0, DEV2));
    s.extend([op::CLOCK, 1, op::REOPEN]);
    out.push(("expiry-and-a-clock-set-back", s));
    out
}

#[test]
fn vector_index_ops_fuzz_seeds() {
    let seeds = seeds();
    if std::env::var_os("LICKETYSYNC_REGENERATE_VECTORS").is_some() {
        let _ = std::fs::remove_dir_all(SEEDS);
        std::fs::create_dir_all(SEEDS).unwrap();
        for (name, bytes) in &seeds {
            std::fs::write(format!("{SEEDS}{name}"), bytes).unwrap();
        }
        return;
    }
    let mut committed: Vec<String> = std::fs::read_dir(SEEDS)
        .unwrap_or_else(|_| panic!("{SEEDS} is missing; regenerate the vectors"))
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    committed.sort();
    let mut names: Vec<String> = seeds.iter().map(|(n, _)| (*n).to_string()).collect();
    names.sort();
    assert_eq!(committed, names, "the committed seeds are exactly these");
    for (name, bytes) in &seeds {
        let on_disk = std::fs::read(format!("{SEEDS}{name}")).unwrap();
        assert_eq!(&on_disk, bytes, "{name} differs; regenerate the vectors");
    }
}
