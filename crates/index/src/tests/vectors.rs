// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The test vectors of `protocol.md` section 8 that are the index crate's,
//! committed as JSON under `crates/index/tests/vectors/`: in item 6 each
//! record's outcome against its writer's records (`outcomes.json`), item 7
//! whole (`heads.json`), and in item 8 the digests, the cached digests and
//! the serving cases (a) to (d) (`digests.json`). Every record is built from
//! the keys crate's fixed folder (write secret `10 11 .. 2f`) with a fixed
//! nonce, so each file reproduces byte for byte. Each `vector_*` test runs
//! its scenarios against a real index, asserts what the spec says each must
//! show, names the section 5 row of every outcome (the rows a case lists are
//! the ones its outcomes reached), and compares the result with the
//! committed file. Every name in the files is spelled out here, never taken
//! from a `Debug` form. Item 7 runs on a write holder, whose writes some
//! cases need, and every step is checked against a read holder given the
//! same records, which shows the same state (the spec's "on a read holder").
//!
//! Regenerate after a reviewed change with
//! `LICKETYSYNC_REGENERATE_VECTORS=1 cargo test -p licketysync-index vector_`
//! and review the diff.

use std::collections::BTreeMap;

use licketysync_keys::{DeviceId, FolderKey, RecordHash, WriterDigest};
use licketysync_protocol::exchange::{Scope, ServeRequest, WriterCursor};
use licketysync_protocol::limits::DEFAULT_MESSAGE_SIZE;
use licketysync_protocol::record::{writer_digests, Arrival, Judgement, Kind, Record, WriterFault};
use licketysync_protocol::Cause;
use serde_json::{json, Map, Value};

use super::kit::{
    converge, dev, flipped_signature, garbage_signature, index, index_as, push, snapshot, verifier,
    write_key, Fault, Spec, OWN,
};
use crate::{AcceptError, Index, MemoryStore, Outcome, Reply};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");

fn regenerating() -> bool {
    std::env::var_os("LICKETYSYNC_REGENERATE_VECTORS").is_some()
}

fn h(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn file_text(generated: &Value) -> String {
    serde_json::to_string_pretty(generated).unwrap() + "\n"
}

/// Compares `generated` with the committed `name.json`, entry by entry for a
/// readable failure and then byte for byte, or writes it when regenerating.
fn check(name: &str, generated: &Value) {
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

/// The section 5 row an index record's outcome reaches, as the files name it.
fn row(cause: Cause) -> &'static str {
    match cause {
        Cause::Duplicate => "duplicate",
        Cause::PushGap => "push_gap",
        Cause::ConcurrentVersion => "concurrent_version",
        Cause::Waiting => "waiting",
        Cause::WriterFault => "writer_fault",
        Cause::OwnSequenceAhead => "own_sequence_ahead",
        Cause::SenderViolation => "sender_violation",
        Cause::Forged => "forged",
        other => panic!("no index record reaches {other:?}"),
    }
}

fn judgement(j: Judgement) -> &'static str {
    match j {
        Judgement::Duplicate => "duplicate",
        Judgement::PushGap => "push_gap",
        Judgement::Next => "next",
        Judgement::Concurrent => "concurrent_version",
    }
}

fn writer_fault(f: &WriterFault) -> &'static str {
    match f {
        WriterFault::Seal(_) => "seal",
        WriterFault::Meta(_) => "metadata",
        WriterFault::Path(_) => "path",
        WriterFault::Kind(_) => "kind",
        WriterFault::HashCount { .. } => "hash_count",
        WriterFault::DirectoryWithChunks => "directory_with_chunks",
        WriterFault::FileWithoutChunks => "file_without_chunks",
        other => panic!("a writer fault the vectors do not name: {other:?}"),
    }
}

/// How a record was built to be a writer fault.
fn built_fault(f: Fault) -> &'static str {
    match f {
        Fault::Seal => "seal",
        Fault::DirectoryWithChunk => "directory_with_chunk",
        Fault::FileWithoutChunks => "file_without_chunks",
    }
}

fn header(description: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("description".into(), json!(description));
    m.insert("folder_id".into(), h(&write_key().verifier().folder_id().0));
    m.insert("own_device".into(), h(&OWN.0));
    m
}

/// One scenario against one index: records by label, what each delivery did,
/// and the state after it; and a read holder given the same records, which
/// must show the same state at every step.
struct Case {
    name: String,
    index: Index<MemoryStore>,
    reader: Index<MemoryStore>,
    labels: BTreeMap<RecordHash, String>,
    records: Vec<Value>,
    steps: Vec<Value>,
    /// The section 5 rows the outcomes reached, in the order first reached.
    rows: Vec<&'static str>,
}

impl Case {
    fn new(name: &str) -> Self {
        Self::with(name, index())
    }

    /// A case over `index`, with a read holder that holds what it holds.
    fn with(name: &str, index: Index<MemoryStore>) -> Self {
        let reader = Index::open(
            FolderKey::from(write_key().read_key()),
            OWN,
            index.store().clone(),
        )
        .unwrap();
        Self {
            name: name.into(),
            index,
            reader,
            labels: BTreeMap::new(),
            records: Vec::new(),
            steps: Vec::new(),
            rows: Vec::new(),
        }
    }

    fn reached(&mut self, cause: Cause) {
        let name = row(cause);
        if !self.rows.contains(&name) {
            self.rows.push(name);
        }
    }

    /// The read holder shows what the write holder shows.
    fn check_reader(&self) {
        assert_eq!(
            snapshot(&self.reader),
            snapshot(&self.index),
            "{}",
            self.name
        );
    }

    fn label(&self, hash: &RecordHash) -> Value {
        self.labels
            .get(hash)
            .map_or_else(|| h(&hash.0), |l| json!(l))
    }

    fn labels(&self, hashes: &[RecordHash]) -> Value {
        Value::Array(hashes.iter().map(|x| self.label(x)).collect())
    }

    /// Registers `spec`'s record under `label`.
    fn add(&mut self, label: &str, spec: &Spec) -> Record {
        let record = spec.record();
        self.register(label, &record, spec);
        record
    }

    fn register(&mut self, label: &str, record: &Record, spec: &Spec) {
        self.labels.insert(record.hash(), label.into());
        self.records.push(json!({
            "label": label,
            "hash": h(&record.hash().0),
            "record": h(&record.signed().to_bytes()),
            "writer": h(&record.device_id().0),
            "seq": record.seq(),
            "path": spec.path,
            "kind": if spec.kind == Kind::Directory { "directory" } else { "file" },
            "deleted": spec.deleted,
            "mtime_ns": spec.mtime,
            "mode": spec.mode,
            "content": spec.content,
            "fault": spec.fault.map(built_fault),
            "supersedes": self.labels(record.supersedes()),
        }));
    }

    /// Knows a record another case registered, by the same label.
    fn learn(&mut self, label: &str, record: &Record) {
        self.labels.insert(record.hash(), label.into());
    }

    fn outcome(&self, o: &Outcome) -> Value {
        json!({
            "judgement": judgement(o.judgement),
            "rows": o.rows().into_iter().map(row).collect::<Vec<_>>(),
            "fault": o.fault.as_ref().map(writer_fault),
            "own_ahead": o.own_ahead,
            "waits": o.waits,
            "released": self.labels(&o.released),
            "changed": o.changed,
        })
    }

    /// One path's heads in display order, the version at the path,
    /// deletion, conflict and conflict copies.
    fn path_state(&self, path: &str) -> Value {
        let heads = self.index.heads(path);
        let hashes: Vec<RecordHash> = heads.versions().map(|v| v.hash()).collect();
        let copies: Vec<RecordHash> = heads.conflict_copies().map(|v| v.hash()).collect();
        json!({
            "heads": self.labels(&hashes),
            "current": heads.current().map(|v| self.label(&v.hash())),
            "deleted": heads.is_deleted(),
            "conflict": heads.is_conflict(),
            "copies": self.labels(&copies),
        })
    }

    /// After one step: the paths it changed, and the waiting records.
    fn step_state(&self, changed: &[String]) -> Value {
        let paths: Map<String, Value> = changed
            .iter()
            .map(|p| (p.clone(), self.path_state(p)))
            .collect();
        let waiting: Vec<RecordHash> = self.index.waiting().collect();
        json!({ "paths": paths, "waiting": self.labels(&waiting) })
    }

    /// At the end: every path, the waiting records, the cursors and the next
    /// seq.
    fn end_state(&self) -> Value {
        let paths: Map<String, Value> = self
            .index
            .paths()
            .map(|p| (p.to_string(), self.path_state(p)))
            .collect();
        let waiting: Vec<RecordHash> = self.index.waiting().collect();
        json!({
            "paths": paths,
            "waiting": self.labels(&waiting),
            "cursors": self.index.cursors(None).map(|c| json!([h(&c.writer.0), c.seq])).collect::<Vec<_>>(),
            "next_seq": self.index.next_seq(),
        })
    }

    /// Delivers `record` (registered as `label`, perhaps with another
    /// signature) as `arrival`, and records what happened.
    fn deliver_as(
        &mut self,
        label: &str,
        variant: &str,
        record: Record,
        arrival: Arrival,
    ) -> Result<Outcome, AcceptError> {
        let result = self.index.accept(record.clone(), arrival);
        let mirrored = self.reader.accept(record, arrival);
        assert_eq!(mirrored.is_ok(), result.is_ok(), "{}", self.name);
        self.check_reader();
        let what = match &result {
            Ok(o) => {
                o.rows().into_iter().for_each(|c| self.reached(c));
                self.outcome(o)
            }
            Err(AcceptError::Refused(cause)) => {
                self.reached(*cause);
                json!({ "refused": row(*cause) })
            }
            Err(e) => panic!("{}: {e}", self.name),
        };
        let arrival = match arrival {
            Arrival::Push => json!("push"),
            Arrival::Reply { in_scope } => json!({ "reply": { "in_scope": in_scope } }),
        };
        let state = self.step_state(result.as_ref().map_or(&[], |o| &o.changed[..]));
        self.steps.push(json!({
            "deliver": label,
            "variant": variant,
            "as": arrival,
            "outcome": what,
            "after": state,
        }));
        result
    }

    fn deliver(&mut self, label: &str, record: &Record) -> Outcome {
        self.deliver_as(label, "as signed", record.clone(), Arrival::Push)
            .unwrap()
    }

    /// This device writes `spec`'s path (or renames `from` to it) through
    /// the index, and the record is registered as `label`.
    fn write(&mut self, label: &str, spec: &Spec, from: Option<&str>) -> Record {
        let chunks = spec.chunks();
        let draft = match from {
            None => self.index.draft(spec.meta(), chunks, spec.deleted).unwrap(),
            Some(old) => self.index.draft_rename(old, spec.meta(), chunks).unwrap(),
        };
        let salt = spec.salt;
        let o = self
            .index
            .write(&draft, &mut |b: &mut [u8]| b.fill(salt))
            .unwrap();
        let record = self.index.record(&o.hash).unwrap().clone();
        self.reader.accept(record.clone(), Arrival::Push).unwrap();
        self.check_reader();
        o.rows().into_iter().for_each(|c| self.reached(c));
        let mut shown = spec.clone();
        shown.writer = self.index.own();
        shown.seq = record.seq();
        self.register(label, &record, &shown);
        let what = self.outcome(&o);
        let state = self.step_state(&o.changed);
        self.steps.push(json!({
            "write": label,
            "renamed_from": from,
            "outcome": what,
            "after": state,
        }));
        record
    }

    fn heads(&self, path: &str) -> Vec<String> {
        self.index
            .heads(path)
            .versions()
            .map(|v| self.labels[&v.hash()].clone())
            .collect()
    }

    fn json(&self) -> Value {
        self.check_reader();
        json!({
            "name": self.name,
            "rows": self.rows,
            "records": self.records,
            "steps": self.steps,
            "end": self.end_state(),
        })
    }
}

fn labels(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

/// `protocol.md` 8 item 6, the index's part: each record's outcome against
/// its writer's records.
#[test]
fn vector_outcomes() {
    let w = dev(1);
    let mut c = Case::new("outcomes of one writer's records");
    let r1 = c.add("R1", &Spec::file(w, 1, "a").salt(1));
    let r2 = c.add("R2", &Spec::file(w, 2, "b").salt(1));
    let r3 = c.add("R3", &Spec::file(w, 3, "c").salt(1));
    let next = c.deliver("R1", &r1);
    assert_eq!(next.rows(), vec![]);
    // A gap on a push, signed and forged: ignored, unverified.
    let gap = c
        .deliver_as("R3", "as signed", r3.clone(), Arrival::Push)
        .unwrap();
    assert_eq!(gap.judgement, Judgement::PushGap);
    let gap = c
        .deliver_as(
            "R3",
            "signature bit flipped",
            flipped_signature(&r3),
            Arrival::Push,
        )
        .unwrap();
    assert!(!gap.stored());
    // A gap in a reply, signed and forged: a sender violation.
    for (variant, r) in [
        ("as signed", r3.clone()),
        ("signature bit flipped", flipped_signature(&r3)),
    ] {
        assert_eq!(
            c.deliver_as("R3", variant, r, Arrival::Reply { in_scope: true }),
            Err(AcceptError::Refused(Cause::SenderViolation))
        );
    }
    // A writer outside the request's scope: a sender violation.
    assert!(c
        .deliver_as(
            "R2",
            "as signed",
            r2.clone(),
            Arrival::Reply { in_scope: false }
        )
        .is_err());
    // Forged at the cursor plus one.
    assert_eq!(
        c.deliver_as(
            "R2",
            "signature bit flipped",
            flipped_signature(&r2),
            Arrival::Push
        ),
        Err(AcceptError::Refused(Cause::Forged))
    );
    c.deliver("R2", &r2);
    c.deliver("R3", &r3);
    // An exact duplicate with garbage for a signature: ignored, unverified.
    let dup = c
        .deliver_as(
            "R2",
            "garbage signature",
            garbage_signature(&r2),
            Arrival::Push,
        )
        .unwrap();
    assert_eq!(dup.judgement, Judgement::Duplicate);
    // Concurrent versions below the cursor and at it.
    let before = c.index.digest_at(&w, 3);
    let low = c.add("C2", &Spec::file(w, 2, "b2").salt(2));
    assert_eq!(c.deliver("C2", &low).rows(), vec![Cause::ConcurrentVersion]);
    assert_ne!(c.index.digest_at(&w, 3), before);
    let top = c.add("C3", &Spec::file(w, 3, "c3").salt(2));
    c.deliver("C3", &top);
    // Writer faults: the seal, a directory with a chunk, a non-empty file
    // without chunks; each opaque and counted in the cursor and digest.
    let mut dir = Spec::file(w, 5, "d").fault(Fault::DirectoryWithChunk);
    dir.kind = Kind::Directory;
    for (label, spec) in [
        ("F4", Spec::file(w, 4, "s").fault(Fault::Seal).salt(4)),
        ("F5", dir),
        ("F6", Spec::file(w, 6, "e").fault(Fault::FileWithoutChunks)),
    ] {
        let r = c.add(label, &spec);
        let o = c.deliver(label, &r);
        assert_eq!(o.rows(), vec![Cause::WriterFault]);
        assert_eq!(c.index.writer_cursor(&w).seq, spec.seq);
    }
    // A forged record that would also be a writer fault: forged wins.
    let both = c.add("F7", &Spec::file(w, 7, "s").fault(Fault::Seal).salt(7));
    assert_eq!(
        c.deliver_as(
            "F7",
            "signature bit flipped",
            flipped_signature(&both),
            Arrival::Push
        ),
        Err(AcceptError::Refused(Cause::Forged))
    );
    // A path that is not NFC: applied, a distinct path.
    let nfd = c.add("N7", &Spec::file(w, 7, "cafe\u{301}"));
    assert!(c.deliver("N7", &nfd).fault.is_none());
    // A record under this device's own ID above its counter.
    let own = c.add("O1", &Spec::file(OWN, 1, "o"));
    assert!(c.deliver("O1", &own).own_ahead);
    assert_eq!(c.index.next_seq(), Some(2));
    let digests: Vec<Value> = (1..=c.index.writer_cursor(&w).seq)
        .map(|s| h(&c.index.digest_at(&w, s).unwrap().0))
        .collect();
    let reference: Vec<Value> = writer_digests(c.index.records_of(&w).map(|r| (r.seq(), r.hash())))
        .values()
        .map(|d| h(&d.0))
        .collect();
    assert_eq!(digests, reference);
    let mut out = header(
        "protocol.md 8 item 6, the index's part: each record's outcome against its writer's records (next, push gap, reply gap, out of scope, forged, duplicate, concurrent versions below and at the cursor, writer faults, a path that is not NFC, a record under the device's own ID), with the section 5 rows reached, and the writer's cached digests at the end.",
    );
    assert_eq!(
        c.rows,
        [
            "push_gap",
            "sender_violation",
            "forged",
            "duplicate",
            "concurrent_version",
            "writer_fault",
            "own_sequence_ahead"
        ]
    );
    out.insert("case".into(), c.json());
    out.insert("digests".into(), Value::Array(digests));
    check("outcomes", &Value::Object(out));
}

/// `protocol.md` 8 item 7: heads.
#[test]
fn vector_heads() {
    let mut cases = Vec::new();
    let (a, b, c3, d) = (dev(1), dev(2), dev(3), dev(4));

    // A version superseding the one head; two versions superseding it; a
    // record naming both.
    let mut c = Case::new("supersede, conflict, resolve");
    let r0 = c.add("R0", &Spec::file(a, 1, "p"));
    let r1 = c.add(
        "R1",
        &Spec::file(a, 2, "p")
            .names(&[r0.hash()])
            .mtime(200)
            .content(2),
    );
    let r2 = c.add(
        "R2",
        &Spec::file(b, 1, "p")
            .names(&[r0.hash()])
            .mtime(100)
            .content(3),
    );
    c.deliver("R0", &r0);
    c.deliver("R1", &r1);
    assert_eq!(c.heads("p"), labels(&["R1"]));
    c.deliver("R2", &r2);
    assert_eq!(
        c.heads("p"),
        labels(&["R1", "R2"]),
        "the greater mtime first"
    );
    assert!(c.index.heads("p").is_conflict());
    let r3 = c.add("R3", &Spec::file(a, 3, "p").names(&[r1.hash(), r2.hash()]));
    c.deliver("R3", &r3);
    assert_eq!(c.heads("p"), labels(&["R3"]));
    cases.push(c.json());

    // Equal mtime: the smaller record hash first.
    let mut c = Case::new("equal mtime");
    let e1 = c.add("E1", &Spec::file(a, 1, "p").content(2));
    let e2 = c.add("E2", &Spec::file(b, 1, "p").content(3));
    c.deliver("E1", &e1);
    c.deliver("E2", &e2);
    let first = if e1.hash() < e2.hash() { "E1" } else { "E2" };
    assert_eq!(c.heads("p")[0], first);
    cases.push(c.json());

    // Each case of the display order and of "content differs".
    let pairs: [(&str, Spec, Spec, usize, bool); 6] = [
        (
            "a file and a tombstone: the file shown, no copy",
            Spec::file(a, 1, "p").mtime(1),
            Spec::tombstone(b, 1, "p").mtime(9),
            0,
            false,
        ),
        (
            "a file and a directory: the directory shown, the file a copy",
            Spec::file(a, 1, "p").mtime(9),
            Spec::dir(b, 1, "p").mtime(1),
            1,
            false,
        ),
        (
            "two files with different content: one copy",
            Spec::file(a, 1, "p").content(2),
            Spec::file(b, 1, "p").content(3).mtime(2_000),
            1,
            false,
        ),
        (
            "two files with the same content, other modes and times: no copy",
            Spec::file(a, 1, "p").content(2).mode(0o600),
            Spec::file(b, 1, "p").content(2).mode(0o755).mtime(5),
            0,
            false,
        ),
        (
            "two directories: no copy",
            Spec::dir(a, 1, "p"),
            Spec::dir(b, 1, "p").mtime(5),
            0,
            false,
        ),
        (
            "only tombstones: the path deleted",
            Spec::tombstone(a, 1, "p"),
            Spec::tombstone(b, 1, "p").mtime(5),
            0,
            true,
        ),
    ];
    for (name, x, y, copies, deleted) in pairs {
        let mut c = Case::new(name);
        let rx = c.add("X", &x);
        let ry = c.add("Y", &y);
        c.deliver("X", &rx);
        c.deliver("Y", &ry);
        let heads = c.index.heads("p");
        assert_eq!(heads.len(), 2, "{name}");
        assert_eq!(heads.conflict_copies().count(), copies, "{name}");
        assert_eq!(heads.is_deleted(), deleted, "{name}");
        match name {
            n if n.starts_with("a file and a tombstone") => assert_eq!(c.heads("p")[0], "X"),
            n if n.starts_with("a file and a directory") => assert_eq!(c.heads("p")[0], "Y"),
            _ => {}
        }
        cases.push(c.json());
    }

    // R2 superseding R1 arriving before R1: R2 waits, no conflict.
    let mut c = Case::new("out of order: R2 before R1");
    let r0 = c.add("R0", &Spec::file(a, 1, "p"));
    let r1 = c.add("R1", &Spec::file(b, 1, "p").names(&[r0.hash()]).content(2));
    let r2 = c.add("R2", &Spec::file(c3, 1, "p").names(&[r1.hash()]).content(3));
    c.deliver("R0", &r0);
    assert!(c.deliver("R2", &r2).waits);
    assert_eq!(
        c.heads("p"),
        labels(&["R0"]),
        "the old head stays, no conflict"
    );
    let o = c.deliver("R1", &r1);
    assert_eq!(c.labels(&o.released), json!(["R2"]));
    assert_eq!(c.heads("p"), labels(&["R2"]));
    assert_eq!(c.rows, ["waiting"]);
    cases.push(c.json());

    // A chain arriving as R3, R2, R1.
    let mut c = Case::new("out of order: a chain R3, R2, R1");
    let r1 = c.add("R1", &Spec::file(a, 1, "p"));
    let r2 = c.add("R2", &Spec::file(b, 1, "p").names(&[r1.hash()]).content(2));
    let r3 = c.add("R3", &Spec::file(c3, 1, "p").names(&[r2.hash()]).content(3));
    assert!(c.deliver("R3", &r3).waits);
    assert!(c.deliver("R2", &r2).waits, "R2 waits for R1");
    assert!(c.index.heads("p").is_empty());
    let o = c.deliver("R1", &r1);
    assert_eq!(c.labels(&o.released), json!(["R2", "R3"]));
    assert_eq!(c.heads("p"), labels(&["R3"]));
    assert_eq!(c.rows, ["waiting"]);
    cases.push(c.json());

    // A record naming a hash no peer holds: it waits for good, stored and
    // served (forwarded).
    let mut c = Case::new("a record naming a hash no peer holds");
    let ghost = RecordHash([0xee; 32]);
    let r0 = c.add("R0", &Spec::file(a, 1, "p"));
    let rg = c.add(
        "RG",
        &Spec::file(b, 1, "p").names(&[r0.hash(), ghost]).content(2),
    );
    c.deliver("R0", &r0);
    assert!(c.deliver("RG", &rg).waits);
    assert_eq!(c.heads("p"), labels(&["R0"]));
    let mut served = Reply::new(serve_all());
    let page = served
        .next_page(&c.index, DEFAULT_MESSAGE_SIZE)
        .unwrap()
        .unwrap();
    assert_eq!(
        page.page.records.len(),
        2,
        "the waiting record is forwarded"
    );
    assert_eq!(c.rows, ["waiting"]);
    cases.push(c.json());

    // A restored device. D writes R0, is backed up, writes R1 (naming R0)
    // and RQ; its peer P holds all three. D's index is restored from the
    // backup, and D edits the path, naming R0, at its reused seq 2.
    let mut orig = Case::with("a restored device: before the restore", index_as(d));
    let r0 = orig.write("R0", &Spec::file(d, 1, "p"), None);
    let backup = orig.index.store().clone();
    let r1 = orig.write("R1", &Spec::file(d, 2, "p").content(2).salt(1), None);
    let rq = orig.write("RQ", &Spec::file(d, 3, "q").content(4).salt(1), None);
    assert_eq!(r1.supersedes(), &[r0.hash()]);
    let mut p = Case::with("a restored device: its peer", index_as(dev(0xb0)));
    for (label, r) in [("R0", &r0), ("R1", &r1), ("RQ", &rq)] {
        p.learn(label, r);
        p.deliver(label, r);
    }
    let restored = Index::open(FolderKey::from(write_key()), d, backup).unwrap();
    let mut dd = Case::with("a restored device: after the restore", restored);
    for (label, r) in [("R0", &r0), ("R1", &r1), ("RQ", &rq)] {
        dd.learn(label, r);
    }
    assert_eq!(dd.index.next_seq(), Some(2), "the backup's counter");
    let r2 = dd.write("R2", &Spec::file(d, 2, "p").content(3).salt(2), None);
    assert_eq!(r2.seq(), 2);
    assert_eq!(r2.supersedes(), &[r0.hash()]);
    p.learn("R2", &r2);
    let o = p.deliver("R2", &r2);
    assert_eq!(o.judgement, Judgement::Concurrent);
    assert_eq!(p.heads("p").len(), 2, "a conflict, nothing lost");
    let o = dd.deliver("R1", &r1);
    assert_eq!(o.judgement, Judgement::Concurrent);
    assert!(!o.own_ahead);
    let o = dd.deliver("RQ", &rq);
    assert!(
        o.own_ahead,
        "a record under D's own ID at or above its counter"
    );
    assert_eq!(
        dd.index.next_seq(),
        Some(4),
        "the counter moved past the reused seqs"
    );
    assert_eq!(dd.heads("p"), p.heads("p"));
    assert!(dd.index.heads("p").is_conflict());
    assert_eq!(snapshot(&dd.index), snapshot(&p.index));
    assert_eq!(orig.rows, Vec::<&str>::new());
    assert_eq!(p.rows, ["concurrent_version"]);
    assert_eq!(dd.rows, ["concurrent_version", "own_sequence_ahead"]);
    cases.push(orig.json());
    cases.push(p.json());
    cases.push(dd.json());

    // A rename: the old path has no head, the new one.
    let mut c = Case::new("a rename");
    let old = c.add("R0", &Spec::file(a, 1, "old"));
    c.deliver("R0", &old);
    let renamed = c.write("R1", &Spec::file(OWN, 1, "new"), Some("old"));
    assert_eq!(renamed.supersedes(), &[old.hash()]);
    assert!(c.index.heads("old").is_empty());
    assert_eq!(c.heads("new"), labels(&["R1"]));
    cases.push(c.json());

    // A rename away, then a new file at the old path (ruling of 2026-10-22):
    // the new record names the version the rename superseded, so a peer
    // that holds it and the new file but not the rename shows one head at
    // the old path at every step.
    let mut c = Case::new("a new file at a path renamed away");
    let r0 = c.add("R0", &Spec::file(a, 1, "old"));
    let r1 = c.add("R1", &Spec::file(b, 1, "new").names(&[r0.hash()]));
    c.deliver("R0", &r0);
    c.deliver("R1", &r1);
    assert!(c.index.heads("old").is_empty());
    let r2 = c.write("R2", &Spec::file(OWN, 1, "old").content(2), None);
    assert_eq!(r2.supersedes(), &[r0.hash()], "the renamed version");
    assert_eq!(c.heads("old"), labels(&["R2"]));
    cases.push(c.json());
    let mut peer = Case::with(
        "a new file at a path renamed away: a peer that has it before the rename",
        index_as(dev(0xb0)),
    );
    for (label, r) in [("R0", &r0), ("R2", &r2), ("R1", &r1)] {
        peer.learn(label, r);
        peer.deliver(label, r);
        assert!(peer.index.heads("old").len() <= 1, "no false conflict");
    }
    assert_eq!(peer.heads("old"), labels(&["R2"]));
    assert_eq!(peer.heads("new"), labels(&["R1"]));
    assert_eq!(snapshot(&peer.index), snapshot(&c.index));
    cases.push(peer.json());

    // 17 heads and a write naming 16: two heads remain (the new record and
    // the one left unnamed).
    let mut c = Case::new("17 heads and a write naming 16");
    for i in 0..17u8 {
        let r = c.add(
            &format!("H{i:02}"),
            &Spec::file(dev(10 + i), 1, "p").mtime(i64::from(i)),
        );
        c.deliver(&format!("H{i:02}"), &r);
    }
    let before = c.heads("p");
    let w = c.write("W", &Spec::file(OWN, 1, "p").content(9), None);
    assert_eq!(w.supersedes().len(), 16);
    assert_eq!(c.heads("p"), vec!["W".to_string(), before[16].clone()]);
    cases.push(c.json());

    // A rename whose old and new paths have 10 heads each: the old path's
    // 10 named first, then 6 of the new path's in display order; 4 of the
    // new path's heads remain beside the rename record.
    let mut c = Case::new("a rename over 10 and 10 heads");
    for i in 0..10u8 {
        let r = c.add(
            &format!("O{i}"),
            &Spec::file(dev(30 + i), 1, "old").mtime(i64::from(i)),
        );
        c.deliver(&format!("O{i}"), &r);
        let r = c.add(
            &format!("N{i}"),
            &Spec::file(dev(50 + i), 1, "new").mtime(i64::from(i)),
        );
        c.deliver(&format!("N{i}"), &r);
    }
    let old_heads = c.heads("old");
    let new_heads = c.heads("new");
    let w = c.write("W", &Spec::file(OWN, 1, "new").content(9), Some("old"));
    let mut named: Vec<String> = w.supersedes().iter().map(|x| c.labels[x].clone()).collect();
    named.sort();
    let mut expected: Vec<String> = old_heads.iter().chain(&new_heads[..6]).cloned().collect();
    expected.sort();
    assert_eq!(named, expected);
    assert!(c.index.heads("old").is_empty());
    let mut remaining = c.heads("new");
    remaining.retain(|l| l != "W");
    assert_eq!(remaining, new_heads[6..].to_vec());
    assert_eq!(c.index.heads("new").len(), 5);
    cases.push(c.json());

    // A record naming an opaque record does not wait; an opaque record
    // naming the one head leaves it the head.
    let mut c = Case::new("opaque records");
    let r0 = c.add("R0", &Spec::file(a, 1, "p"));
    let op = c.add(
        "OP",
        &Spec::file(b, 1, "p")
            .names(&[r0.hash()])
            .fault(Fault::Seal)
            .salt(3),
    );
    let rn = c.add("RN", &Spec::file(c3, 1, "q").names(&[op.hash()]));
    c.deliver("R0", &r0);
    assert!(c.deliver("OP", &op).fault.is_some());
    assert_eq!(c.heads("p"), labels(&["R0"]), "the head stays");
    assert!(
        !c.deliver("RN", &rn).waits,
        "naming an opaque record does not wait"
    );
    assert_eq!(c.heads("q"), labels(&["RN"]));
    // An opaque record never waits, even for a record no peer holds.
    let og = c.add(
        "OG",
        &Spec::file(d, 1, "p")
            .names(&[RecordHash([0xee; 32])])
            .fault(Fault::Seal)
            .salt(4),
    );
    let o = c.deliver("OG", &og);
    assert!(o.fault.is_some() && !o.waits && o.stored());
    assert_eq!(o.rows(), vec![Cause::WriterFault]);
    assert_eq!(c.index.waiting().count(), 0);
    assert_eq!(c.heads("p"), labels(&["R0"]));
    assert_eq!(c.rows, ["writer_fault"]);
    cases.push(c.json());

    let mut out = header(
        "protocol.md 8 item 7: heads (one path each unless named), on a write holder, whose writes some cases need, with a read holder given the same records checked to show the same state at every step. Each case lists its records (labels, hashes, signed bytes, what they say) and every delivery or write with its outcome and the state after it: every path's heads in display order, the version at the path, deletion, conflict and conflict copies, the waiting records, the cursors and the next seq.",
    );
    out.insert("cases".into(), Value::Array(cases));
    check("heads", &Value::Object(out));
}

fn serve_all() -> ServeRequest {
    ServeRequest {
        request_id: 1,
        scope: Scope::ALL,
        cursors: BTreeMap::new(),
        page_limit: 64,
    }
}

fn digest_list(index: &Index<MemoryStore>, w: &DeviceId) -> Vec<Value> {
    (1..=index.writer_cursor(w).seq)
        .map(|s| json!([s, h(&index.digest_at(w, s).unwrap().0)]))
        .collect()
}

/// Serves `cursors` (scope `scope`) and names what each page holds.
fn served(
    index: &Index<MemoryStore>,
    names: &BTreeMap<RecordHash, String>,
    scope: Scope,
    cursors: &[WriterCursor],
) -> Value {
    let request = ServeRequest {
        request_id: 1,
        scope,
        cursors: cursors.iter().map(|c| (c.writer, *c)).collect(),
        page_limit: 64,
    };
    let mut reply = Reply::new(request);
    let mut pages = Vec::new();
    while let Some(p) = reply.next_page(index, DEFAULT_MESSAGE_SIZE).unwrap() {
        let records: Vec<String> = p
            .page
            .records
            .iter()
            .map(|b| names[&Record::from_bytes(b, &verifier()).unwrap().hash()].clone())
            .collect();
        pages.push(json!({
            "records": records,
            "more": p.page.more,
            "marks": p.marks.iter().map(|m| h(&m.0)).collect::<Vec<_>>(),
        }));
    }
    Value::Array(pages)
}

fn cursor_json(c: &WriterCursor) -> Value {
    json!({ "writer": h(&c.writer.0), "seq": c.seq, "digest": c.digest.map(|d| h(&d.0)) })
}

/// `protocol.md` 8 item 8, the index's part: digests, cached digests and the
/// serving cases.
#[test]
fn vector_digests() {
    let w = dev(1);
    let mut ix = index();
    let mut names = BTreeMap::new();
    let mut add = |ix: &mut Index<MemoryStore>, label: &str, spec: Spec| {
        let r = spec.record();
        names.insert(r.hash(), label.to_string());
        push(ix, &r);
        r
    };
    let r1 = add(&mut ix, "R1", Spec::file(w, 1, "a").salt(1));
    let r2 = add(&mut ix, "R2", Spec::file(w, 2, "a").salt(1));
    let r3 = add(&mut ix, "R3", Spec::file(w, 3, "a").salt(1));
    let one_per_seq = digest_list(&ix, &w);
    let reference = writer_digests([(1, r1.hash()), (2, r2.hash()), (3, r3.hash())]);
    assert_eq!(ix.digest_at(&w, 3), reference.get(&3).copied());
    // A concurrent version lands below the cursor.
    let c2 = add(&mut ix, "C2", Spec::file(w, 2, "b").salt(2));
    let after = digest_list(&ix, &w);
    let reference2 = writer_digests([
        (1, r1.hash()),
        (2, r2.hash()),
        (2, c2.hash()),
        (3, r3.hash()),
    ]);
    for s in 1..=3 {
        assert_eq!(ix.digest_at(&w, s), reference2.get(&s).copied());
    }
    assert_eq!(after[0], one_per_seq[0]);
    assert_ne!(after[1], one_per_seq[1]);
    assert_ne!(after[2], one_per_seq[2]);
    let mut first_two = [r2.hash(), c2.hash()];
    first_two.sort();
    let manual = WriterDigest::ZERO
        .then(&r1.hash())
        .then(&first_two[0])
        .then(&first_two[1]);
    assert_eq!(
        ix.digest_at(&w, 2),
        Some(manual),
        "two records at one seq, canonical order"
    );

    // The serving cases against this index (records R1, R2 and C2, R3).
    let at = |s: u64| WriterCursor {
        writer: w,
        seq: s,
        digest: ix.digest_at(&w, s),
    };
    let differing = WriterCursor {
        writer: w,
        seq: 2,
        digest: Some(WriterDigest([0x99; 32])),
    };
    let ahead = WriterCursor {
        writer: w,
        seq: 5,
        digest: Some(WriterDigest([0x11; 32])),
    };
    let cases = [
        ("(a) absent from have: every record", Scope::ALL, vec![]),
        (
            "(b) equal digest at 1: the records above 1",
            Scope::ALL,
            vec![at(1)],
        ),
        (
            "(c) different digest at 2: every record, the writer marked",
            Scope::ALL,
            vec![differing],
        ),
        (
            "(d) a cursor above this side's: nothing",
            Scope::ALL,
            vec![ahead],
        ),
        (
            "equal cursors and digests: nothing",
            Scope::ALL,
            vec![at(3)],
        ),
        (
            "a listed request",
            Scope::Listed([w, dev(2)].into_iter().collect()),
            vec![at(1), WriterCursor::none(dev(2))],
        ),
        (
            "a range that excludes the writer",
            Scope::Range {
                after: Some(w),
                through: None,
            },
            vec![],
        ),
    ];
    // What each case's one page must hold, in canonical order, and whether
    // it marks the writer.
    let (first, second) = if r2.hash() < c2.hash() {
        ("R2", "C2")
    } else {
        ("C2", "R2")
    };
    let every = json!(["R1", first, second, "R3"]);
    let above_one = json!([first, second, "R3"]);
    let expected = [
        (every.clone(), false),
        (above_one.clone(), false),
        (every, true),
        (json!([]), false),
        (json!([]), false),
        (above_one, false),
        (json!([]), false),
    ];
    let mut serving = Vec::new();
    for ((name, scope, cursors), (records, marked)) in cases.into_iter().zip(expected) {
        let pages = served(&ix, &names, scope, &cursors);
        assert_eq!(pages.as_array().map(Vec::len), Some(1), "{name}");
        assert_eq!(pages[0]["records"], records, "{name}");
        assert_eq!(pages[0]["more"], json!(false), "{name}");
        let marks = if marked { json!([h(&w.0)]) } else { json!([]) };
        assert_eq!(pages[0]["marks"], marks, "{name}");
        serving.push(json!({
            "name": name,
            "have": cursors.iter().map(cursor_json).collect::<Vec<_>>(),
            "pages": pages,
        }));
    }

    // Convergence: a concurrent version the responder lacks at equal
    // cursors, and one it lacks behind a lower cursor.
    let mut convergence = Vec::new();
    for (name, a_has, b_has) in [
        ("equal cursors", vec![0usize, 1, 2, 3], vec![0usize, 1, 3]),
        ("behind a lower cursor", vec![0, 2], vec![0, 1, 3]),
    ] {
        let all = [&r1, &r2, &c2, &r3];
        let mut a = index_as(dev(0xa1));
        let mut b = index_as(dev(0xb1));
        for i in &a_has {
            push(&mut a, all[*i]);
        }
        for i in &b_has {
            push(&mut b, all[*i]);
        }
        let start = json!({
            "a": a_has.iter().map(|i| names[&all[*i].hash()].clone()).collect::<Vec<_>>(),
            "b": b_has.iter().map(|i| names[&all[*i].hash()].clone()).collect::<Vec<_>>(),
            "a_cursor": cursor_json(&a.writer_cursor(&w)),
            "b_cursor": cursor_json(&b.writer_cursor(&w)),
        });
        converge(&mut a, &mut b);
        assert_eq!(snapshot(&a), snapshot(&b), "{name}");
        assert_eq!(a.len(), 4, "{name}");
        convergence.push(json!({
            "name": name,
            "start": start,
            "end_cursor": cursor_json(&a.writer_cursor(&w)),
            "end_digests": digest_list(&a, &w),
        }));
    }
    let mut out = header(
        "protocol.md 8 item 8, the index's part: the cached digests of a writer with one record per seq and after a concurrent version lands below the cursor (two records at seq 2, in canonical order), equal to the reference computation; the serving cases (a) to (d), equal cursors, a listed request and a range that excludes the writer, as the pages a reply holds and the writers it marks; and two indexes converging through rounds of range and listed requests.",
    );
    out.insert(
        "records".into(),
        json!([r1, r2, c2, r3]
            .iter()
            .map(|r| json!({
                "label": names[&r.hash()],
                "hash": h(&r.hash().0),
                "seq": r.seq(),
                "record": h(&r.signed().to_bytes()),
            }))
            .collect::<Vec<_>>()),
    );
    out.insert("writer".into(), h(&w.0));
    out.insert("digests_one_per_seq".into(), Value::Array(one_per_seq));
    out.insert(
        "digests_after_concurrent_at_seq_2".into(),
        Value::Array(after),
    );
    out.insert("serving".into(), Value::Array(serving));
    out.insert("convergence".into(), Value::Array(convergence));
    check("digests", &Value::Object(out));
}
