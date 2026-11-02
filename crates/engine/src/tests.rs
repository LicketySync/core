// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The engine's unit tests over fake contexts (`testkit::Net`): each names the
//! rule it shows, with its spec section or TM number. They exercise what does
//! not depend on how the index syncs: the handshake and folder proofs, the
//! commit discipline, the store-failure pause, opening and its report, local
//! writes, chunks and their passes, pacing, closes and issues.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

use core::time::Duration;

use licketysync_keys::FolderId;
use licketysync_protocol::frame::Frame;
use licketysync_protocol::{Cause, CloseReason};

use crate::issues::{IssueKind, StoreFailureCause, Subject};
use crate::runtime::{Peer, PeerId, Storage, TimerId, MAX_SEND_QUEUE};
use crate::store::{record_key, stage_changes};
use crate::testkit::{config, folder_key, records_of, with_signature, FakeStorage, Net};
use crate::{FolderState, WriteFailure, HARNESS_TIMERS};

pub(crate) fn folder() -> FolderId {
    folder_key(1, 1).folder_id()
}

/// Stores `records` of folder 1's ID as the index would, numbered 1 up.
pub(crate) fn store_records(
    storage: &mut FakeStorage,
    records: Vec<licketysync_keys::records::SignedRecord>,
) {
    let changes = licketysync_index::ChangeSet {
        put: records.into_iter().zip(1..).collect(),
        ..licketysync_index::ChangeSet::default()
    };
    stage_changes(storage, &folder(), &changes).unwrap();
    storage.commit().unwrap();
}

/// Two write holders of folder 1, connected.
pub(crate) fn pair() -> Net {
    let mut net = Net::new(vec![
        config(0, vec![folder_key(1, 1)]),
        config(1, vec![folder_key(1, 1)]),
    ]);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    net
}

pub(crate) fn state(net: &Net, i: usize) -> FolderState {
    net.nodes[i].engine.folder(&folder()).unwrap().state
}

pub(crate) fn write(
    net: &mut Net,
    i: usize,
    path: &str,
    content: &[u8],
) -> Result<licketysync_keys::RecordHash, WriteFailure> {
    let f = folder();
    net.with(i, |e, cx| e.write_file(cx, f, path, content, 0))
}

#[test]
fn crate_name_is_set() {
    assert_eq!(crate::CRATE, "licketysync-engine");
}

#[test]
fn two_holders_open_the_folder_by_proof_and_are_up_to_date() {
    // protocol.md 3.5: each side proves the folder; it opens when both
    // accepted; the engine's state is Up to date once the first round ran.
    let net = pair();
    for i in 0..2 {
        assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
        let t = net.nodes[i].engine.folder(&folder()).unwrap().transitions;
        assert_eq!(t.first().map(|(_, s)| *s), Some(FolderState::Checking));
    }
    let entries = net.nodes[0].engine.status_entries(PeerId::new(1));
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (
            entries[0].index_records,
            entries[0].bytes_needed,
            entries[0].paused,
            entries[0].free_disk_bytes
        ),
        (0, 0, false, 0)
    );
    assert_eq!(entries[0].folder_id, folder().0.to_vec());
}

#[test]
fn a_write_reaches_the_peer_and_its_chunks_read_back_there() {
    let mut net = pair();
    let content: Vec<u8> = (0..3500u32).map(|i| (i % 251) as u8).collect();
    let hash = write(&mut net, 0, "docs/a.bin", &content).unwrap();
    net.advance(Duration::from_secs(3));
    let n = &net.nodes[1];
    assert_eq!(
        n.engine.read_file(&n.cx.storage, &folder(), &hash),
        Ok(content)
    );
    assert_eq!(state(&net, 1), FolderState::UpToDate);
    let v = n.engine.folder(&folder()).unwrap();
    assert_eq!(v.stored_chunks.len(), 4, "3500 bytes in 1 KiB chunks");
    assert!(v.lacking.is_empty() && v.bytes_needed == 0);
}

#[test]
fn a_failed_commit_sends_nothing_and_pauses_the_folder() {
    // protocol.md 4.5, "Durability before transmission", and section 5,
    // "Store failure": memory never runs ahead of disk and nothing is sent.
    let mut net = pair();
    let f = folder();
    net.nodes[0].cx.storage.full = true;
    let n = &mut net.nodes[0];
    let commits = n.cx.storage.commits;
    let result = n.engine.write_file(&mut n.cx, f, "x.txt", b"hello", 0);
    assert_eq!(result, Err(WriteFailure::Store(StoreFailureCause::Full)));
    assert!(n.cx.outbox.is_empty(), "nothing sent");
    assert!(
        n.cx.storage.staged.is_empty() && n.cx.storage.commits == commits,
        "rolled back"
    );
    assert!(
        n.engine.files(&f).is_empty(),
        "the index was rebuilt from what is committed"
    );
    assert_eq!(state(&net, 0), FolderState::Paused(StoreFailureCause::Full));
    let issue = net.nodes[0]
        .engine
        .issues()
        .list()
        .iter()
        .any(|i| i.kind == IssueKind::StoreFailure(StoreFailureCause::Full));
    assert!(issue);
    assert!(net.nodes[0].engine.status_entries(PeerId::new(1))[0].paused);
    // Paused: writes are refused up front, the probe keeps failing.
    assert_eq!(write(&mut net, 0, "y.txt", b"y"), Err(WriteFailure::Paused));
    net.advance(Duration::from_secs(3));
    assert_eq!(state(&net, 0), FolderState::Paused(StoreFailureCause::Full));
    // The disk frees: the probe commits, the pause ends, a round is owed.
    net.nodes[0].cx.storage.full = false;
    net.advance(Duration::from_secs(2));
    assert_eq!(state(&net, 0), FolderState::UpToDate);
    assert!(net.nodes[0].engine.counters().rounds_owed >= 1);
    let hash = write(&mut net, 0, "x.txt", b"hello").unwrap();
    net.advance(Duration::from_secs(2));
    assert_eq!(
        net.nodes[1]
            .engine
            .read_file(&net.nodes[1].cx.storage, &f, &hash),
        Ok(b"hello".to_vec())
    );
}

#[test]
fn what_a_paused_folder_skipped_comes_back_once_it_resumes() {
    let mut net = pair();
    net.nodes[1].cx.storage.full = true;
    let hash = write(&mut net, 0, "late.txt", b"late").unwrap();
    net.advance(Duration::from_secs(2));
    assert_eq!(state(&net, 1), FolderState::Paused(StoreFailureCause::Full));
    let e = &net.nodes[1].engine;
    assert!(e.counters().store_failures >= 1);
    net.nodes[1].cx.storage.full = false;
    net.advance(Duration::from_secs(15));
    let n = &net.nodes[1];
    assert_eq!(
        n.engine.read_file(&n.cx.storage, &folder(), &hash),
        Ok(b"late".to_vec())
    );
    assert!(n.engine.counters().rounds_owed >= 1);
    assert_eq!(state(&net, 1), FolderState::UpToDate);
    assert_eq!(
        n.engine.counters().blaming_closes(),
        0,
        "a local disk never closes a connection"
    );
}

pub(crate) fn engine_over(storage: FakeStorage) -> Net {
    let mut net = Net::new(vec![]);
    let mut n = crate::testkit::Node {
        engine: crate::Engine::new(config(0, vec![folder_key(1, 1)])).unwrap(),
        cx: crate::testkit::FakeCx {
            storage,
            ..crate::testkit::FakeCx::default()
        },
    };
    n.engine.on_start(&mut n.cx);
    net.nodes.push(n);
    net
}

#[test]
fn misconfigured_when_every_stored_record_is_another_folders_and_never_proven() {
    // protocol.md 4.4, "Opening a folder": a store in which nothing passes
    // means a misconfigured folder; it is never proven to a peer.
    let mut storage = FakeStorage::default();
    store_records(&mut storage, records_of(2, 1, 3));
    let mut net = engine_over(storage);
    let e = &mut net.nodes[0].engine;
    let v = e.folder(&folder()).unwrap();
    assert_eq!(
        v.state,
        FolderState::Misconfigured {
            dropped: 3,
            undecodable: 0
        }
    );
    assert!(!v.credentialed);
    let kinds: Vec<IssueKind> = e.issues().list().iter().map(|i| i.kind).collect();
    assert_eq!(kinds, vec![IssueKind::OpenReport, IssueKind::Misconfigured]);
    assert_eq!(
        e.write_file(
            &mut crate::testkit::FakeCx::default(),
            folder(),
            "a",
            b"a",
            0
        ),
        Err(WriteFailure::NotUsable)
    );
}

#[test]
fn a_misconfigured_folder_never_opens_on_a_connection() {
    let mut storage = FakeStorage::default();
    store_records(&mut storage, records_of(2, 1, 1));
    let mut net = engine_over(storage);
    let mut peer = Net::new(vec![config(1, vec![folder_key(1, 1)])]);
    net.nodes.push(peer.nodes.remove(0));
    net.nodes[1].cx.id = 1;
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    assert!(matches!(state(&net, 0), FolderState::Misconfigured { .. }));
    assert_eq!(
        state(&net, 1),
        FolderState::Syncing {
            lacking_chunks: 0,
            bytes_needed: 0,
            rounds_pending: 0,
            open_on: 0
        },
        "its peer is left waiting for peers"
    );
    assert!(net.nodes[1].engine.counters().proofs_rejected >= 1);
}

#[test]
fn undecodable_stored_bytes_are_counted_and_alone_make_the_folder_misconfigured() {
    let mut storage = FakeStorage::default();
    storage
        .put(
            &record_key(&folder(), &licketysync_keys::RecordHash([1; 32])),
            b"\xff not a record",
        )
        .unwrap();
    storage.commit().unwrap();
    let net = engine_over(storage);
    let e = &net.nodes[0].engine;
    let v = e.folder(&folder()).unwrap();
    assert_eq!(
        v.state,
        FolderState::Misconfigured {
            dropped: 0,
            undecodable: 1
        }
    );
    assert_eq!(v.open.undecodable, 1);
    let open = e
        .issues()
        .entries()
        .map(|entry| &entry.issue)
        .find(|i| i.kind == IssueKind::OpenReport)
        .unwrap();
    assert!(matches!(
        open.subject,
        Subject::Open {
            undecodable: 1,
            dropped: 0,
            ..
        }
    ));
}

#[test]
fn the_open_issue_gives_the_counts_and_at_most_sixteen_hashes() {
    // protocol.md section 5, "Stored record fails its check": one issue, the
    // counts, at most 16 record hashes (a fixed engine constant, ruling F4).
    let mut storage = FakeStorage::default();
    let mut stored = records_of(1, 1, 1);
    stored.extend(
        records_of(1, 2, 20)
            .iter()
            .map(|r| with_signature(r, [7; 64])),
    );
    store_records(&mut storage, stored);
    let net = engine_over(storage);
    let e = &net.nodes[0].engine;
    let open = e
        .issues()
        .entries()
        .map(|entry| &entry.issue)
        .find(|i| i.kind == IssueKind::OpenReport)
        .unwrap();
    let Subject::Open {
        dropped, hashes, ..
    } = &open.subject
    else {
        unreachable!("the open issue's subject is Open");
    };
    assert_eq!((*dropped, hashes.len()), (20, 16));
    let v = e.folder(&folder()).unwrap();
    assert_eq!(v.open.dropped, 20);
    assert_eq!(v.records.len(), 1, "the good record is held");
    assert!(!matches!(v.state, FolderState::Misconfigured { .. }));
}

#[test]
fn writes_are_refused_for_the_read_and_sealed_tiers_and_record_nothing() {
    // keys.md 1.3: a read or sealed key cannot sign.
    for tier in [2, 3] {
        let mut net = Net::new(vec![config(0, vec![folder_key(1, tier)])]);
        let commits = net.nodes[0].cx.storage.commits;
        assert_eq!(
            write(&mut net, 0, "a.txt", b"a"),
            Err(WriteFailure::NotWriteKey),
            "tier {tier}"
        );
        let f = folder();
        assert_eq!(
            net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)),
            Err(WriteFailure::NotWriteKey)
        );
        let n = &net.nodes[0];
        assert_eq!(n.cx.storage.commits, commits);
        assert!(n.cx.storage.staged.is_empty());
        assert_eq!(n.engine.counters().writes_refused, 2);
    }
}

#[test]
fn tombstones_take_the_deleted_kind_and_a_directory_goes_by_one_tree_delete() {
    // protocol.md 4.7 item 6: a file deleted is a tombstone of its kind; a
    // directory deleted with what lies beneath it is one tree delete.
    let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
    let f = folder();
    write(&mut net, 0, "a.txt", b"some text").unwrap();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    write(&mut net, 0, "d/in.txt", b"inside").unwrap();
    let d = net.with(0, |e, cx| e.mkdir(cx, f, "d", 1)).unwrap();
    let files = net.nodes[0].engine.files(&f);
    let dir = files.iter().find(|v| v.path == "d").unwrap();
    assert_eq!(
        (dir.heads[0].hash, dir.heads[0].kind, dir.heads[0].size),
        (d, licketysync_protocol::record::Kind::Directory, 0)
    );
    net.with(0, |e, cx| e.delete(cx, f, "a.txt", 5)).unwrap();
    let before = net.nodes[0].engine.folder(&f).unwrap().records.len();
    net.with(0, |e, cx| e.delete(cx, f, "d", 6)).unwrap();
    let files = net.nodes[0].engine.files(&f);
    let a = files.iter().find(|v| v.path == "a.txt").unwrap();
    assert!(a.deleted);
    assert_eq!(
        (a.heads[0].tombstone, a.heads[0].kind, a.heads[0].size),
        (true, licketysync_protocol::record::Kind::File, 0)
    );
    assert!(
        files.iter().all(|v| !v.path.starts_with('d')),
        "nothing left at or beneath the directory"
    );
    let after = net.nodes[0].engine.folder(&f).unwrap().records;
    assert_eq!(
        (after.len(), after.iter().filter(|r| r.cleanup).count()),
        (before, 1),
        "the tree delete and its cleanup replaced the directory and its file"
    );
    assert_eq!(
        net.with(0, |e, cx| e.delete(cx, f, "d", 7)),
        Err(WriteFailure::NoSuchPath),
        "deleted already"
    );
    assert_eq!(
        net.with(0, |e, cx| e.delete(cx, f, "a.txt", 7)),
        Err(WriteFailure::NoSuchPath),
        "deleted already"
    );
    assert_eq!(
        net.with(0, |e, cx| e.delete(cx, f, "never", 7)),
        Err(WriteFailure::NoSuchPath)
    );
    assert!(matches!(
        write(&mut net, 0, "/abs", b"x"),
        Err(WriteFailure::Path(_))
    ));
    assert!(matches!(
        net.with(0, |e, cx| e.rename(cx, f, "a/../b", "c", 0)),
        Err(WriteFailure::Path(_))
    ));
    let empty = write(&mut net, 0, "empty.txt", b"").unwrap();
    let n = &net.nodes[0];
    assert_eq!(
        n.engine.read_file(&n.cx.storage, &f, &empty),
        Ok(Vec::new()),
        "an empty file has no chunks"
    );
}

#[test]
fn a_rename_reuses_the_stored_chunks() {
    let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
    let f = folder();
    let content = vec![3u8; 2500];
    write(&mut net, 0, "old.bin", &content).unwrap();
    let stored = net.nodes[0].engine.folder(&f).unwrap().stored_chunks;
    let renamed = net
        .with(0, |e, cx| e.rename(cx, f, "old.bin", "new.bin", 0))
        .unwrap();
    let n = &net.nodes[0];
    assert_eq!(
        n.engine.folder(&f).unwrap().stored_chunks,
        stored,
        "no new blob"
    );
    assert_eq!(n.engine.read_file(&n.cx.storage, &f, &renamed), Ok(content));
    assert_eq!(
        net.with(0, |e, cx| e.rename(cx, f, "gone", "x", 0)),
        Err(WriteFailure::NoSuchPath)
    );
}

#[test]
fn a_restart_rebuilds_an_equal_view_and_shows_checking() {
    let mut net = pair();
    write(&mut net, 0, "a.txt", b"a").unwrap();
    write(&mut net, 1, "b.bin", &[9u8; 3000]).unwrap();
    net.advance(Duration::from_secs(3));
    let before = net.nodes[0].engine.folder(&folder()).unwrap();
    let files = net.nodes[0].engine.files(&folder());
    net.restart(0, config(0, vec![folder_key(1, 1)]));
    let after = net.nodes[0].engine.folder(&folder()).unwrap();
    assert_eq!(
        (after.records, after.stored_chunks),
        (before.records, before.stored_chunks)
    );
    assert_eq!(net.nodes[0].engine.files(&folder()), files);
    assert_eq!(
        after.transitions.first().map(|(_, s)| *s),
        Some(FolderState::Checking)
    );
    assert!(matches!(
        after.transitions.get(1),
        Some((_, FolderState::Syncing { .. }))
    ));
}

#[test]
fn a_crash_just_after_a_write_keeps_the_committed_record_as_its_base() {
    let mut net = pair();
    let first = write(&mut net, 0, "a.txt", b"first").unwrap();
    // The process dies before anything else runs: staged writes are gone,
    // committed ones stay, the base included.
    net.restart(0, config(0, vec![folder_key(1, 1)]));
    let held = |net: &Net| -> Vec<_> {
        net.nodes[0]
            .engine
            .folder(&folder())
            .unwrap()
            .records
            .iter()
            .map(|r| r.hash)
            .collect()
    };
    assert_eq!(held(&net), vec![first]);
    let second = write(&mut net, 0, "a.txt", b"second").unwrap();
    assert_ne!(first, second);
    assert_eq!(
        held(&net),
        vec![second],
        "built from the base: it replaces it"
    );
}

#[test]
fn the_budget_defers_frames_and_the_poll_sends_them() {
    // runtime.rs, MAX_SEND_QUEUE: the engine hands over its next CHUNK_OK only
    // while unsent plus the frame stays within its budget; an empty queue
    // always takes one.
    let mut a = config(0, vec![folder_key(1, 1)]);
    a.send_budget = 2_000;
    let mut net = Net::new(vec![a, config(1, vec![folder_key(1, 1)])]);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    let content: Vec<u8> = (0..10 * 1024u32).map(|i| (i % 251) as u8).collect();
    let hash = write(&mut net, 0, "big.bin", &content).unwrap();
    net.advance(Duration::from_secs(5));
    assert!(
        net.nodes[0].engine.counters().deferrals >= 5,
        "{:?}",
        net.nodes[0].engine.counters()
    );
    let n = &net.nodes[1];
    assert_eq!(
        n.engine.read_file(&n.cx.storage, &folder(), &hash),
        Ok(content)
    );
}

#[test]
fn chunk_stored_reaches_every_connection_where_the_folder_is_open() {
    // protocol.md 4.6: each chunk this device stores is counted on every
    // connection where the folder is open, feeding each peer's pass trigger.
    let mut net = Net::new(vec![
        config(0, vec![folder_key(1, 1)]),
        config(1, vec![folder_key(1, 1)]),
        config(2, vec![folder_key(1, 1)]),
    ]);
    net.connect(0, 1);
    net.connect(0, 2);
    net.advance(Duration::from_secs(2));
    let content: Vec<u8> = (0..3000u32).map(|i| (i % 253) as u8).collect();
    write(&mut net, 0, "three.bin", &content).unwrap();
    net.advance(Duration::from_secs(3));
    for peer in [1, 2] {
        let last = net.statuses(0, peer).pop().unwrap();
        assert_eq!(
            last.folders[0].chunks_stored, 3,
            "the Status to node {peer}"
        );
    }
}

#[test]
fn harness_timer_ids_are_the_harness_and_ignored() {
    let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
    let n = &mut net.nodes[0];
    let timers = n.cx.timers.clone();
    n.engine.on_timer(&mut n.cx, TimerId::new(HARNESS_TIMERS));
    n.engine.on_timer(&mut n.cx, TimerId::new(12_345));
    assert_eq!(n.cx.timers, timers);
    assert!(n.cx.outbox.is_empty());
}

#[test]
fn a_close_for_the_peers_fault_names_it_and_a_clean_stop_only_logs() {
    // rules.rs, Cause::report: a close for the sender's fault raises an issue
    // naming the peer; a peer's orderly Close is a log line (TM-10).
    let mut net = Net::new(vec![
        config(0, vec![folder_key(1, 1)]),
        config(1, vec![folder_key(1, 1)]),
        config(2, vec![folder_key(1, 1)]),
    ]);
    net.connect(0, 1);
    net.connect(0, 2);
    net.advance(Duration::from_secs(2));
    let unknown_critical = Frame::new(0xfff0, vec![]).unwrap().encode();
    net.nodes[1]
        .cx
        .outbox
        .entry(PeerId::new(0))
        .or_default()
        .extend(unknown_critical);
    net.settle();
    let e = &net.nodes[0].engine;
    let named = e.issues().list().iter().any(|i| {
        i.kind == IssueKind::PeerFault(Cause::UnknownCriticalType)
            && matches!(i.subject, Subject::Peer { peer, device: Some(_), holder: true } if peer == PeerId::new(1))
    });
    assert!(named, "{:?}", e.issues().list());
    assert_eq!(
        e.counters()
            .closes_sent
            .of(CloseReason::UnsupportedCriticalType),
        1
    );
    let n = &mut net.nodes[2];
    n.engine.on_stop(&mut n.cx);
    net.settle();
    let e = &net.nodes[0].engine;
    assert_eq!(e.counters().closes_received.of(CloseReason::Shutdown), 1);
    assert_eq!(e.issues().list().len(), 1, "the clean stop raised nothing");
}

#[test]
fn chunk_busy_is_an_ordinary_answer_and_the_chunk_comes_after_the_backoff() {
    // protocol.md 4.6, "Busy": a holder with half of MAX_SEND_QUEUE unsent
    // answers CHUNK_BUSY; the requester waits and asks again, keeping the
    // connection.
    let mut net = pair();
    net.nodes[0]
        .cx
        .extra_unsent
        .insert(PeerId::new(1), MAX_SEND_QUEUE / 2);
    let hash = write(&mut net, 0, "busy.bin", &[4u8; 3000]).unwrap();
    net.advance(Duration::from_millis(500));
    assert!(net.nodes[1].engine.counters().of(Cause::ChunkBusy) >= 1);
    net.nodes[0].cx.extra_unsent.clear();
    net.advance(Duration::from_secs(5));
    let n = &net.nodes[1];
    assert_eq!(
        n.engine.read_file(&n.cx.storage, &folder(), &hash),
        Ok(vec![4u8; 3000])
    );
    assert_eq!(n.engine.counters().blaming_closes(), 0);
}

#[test]
fn no_debug_output_carries_a_path_or_a_secret() {
    // TM-6.
    let mut net = pair();
    write(&mut net, 0, "secret-plans/q3.txt", b"x").unwrap();
    net.advance(Duration::from_secs(2));
    let e = &net.nodes[1].engine;
    let text = format!(
        "{e:?} {:?} {:?} {:?} {:?}",
        e.files(&folder()),
        e.folder(&folder()),
        e.issues(),
        config(1, vec![folder_key(1, 1)])
    );
    assert!(
        !text.contains("secret-plans") && !text.contains("q3"),
        "{text}"
    );
    // Neither the device seed nor the folder's write secret, in either way
    // `Debug` or a hex dump would print the bytes.
    for secret in [[0x41u8; 32], [1u8; 32]] {
        // Each secret repeats one byte.
        let hex = format!("{:02x}", secret[0]).repeat(32);
        assert!(!text.contains(&format!("{secret:?}")), "{text}");
        assert!(!text.contains(&hex), "{text}");
    }
    assert!(
        e.files(&folder())
            .iter()
            .any(|f| f.path == "secret-plans/q3.txt"),
        "the path is there for display"
    );
}

#[test]
fn a_version_received_becomes_its_paths_base_once_its_chunks_are_on_disk() {
    let mut net = pair();
    let h = write(&mut net, 0, "p.txt", b"hello there").unwrap();
    net.advance(Duration::from_secs(3));
    let files = net.nodes[1].engine.files(&folder());
    let p = files.iter().find(|f| f.path == "p.txt").unwrap();
    assert_eq!(p.bases, vec![(crate::inspect::Place::Path, h)]);
    let f = net.nodes[1].engine.folders.get(&folder()).unwrap();
    assert!(f.unapplied.is_empty(), "nothing left to apply");
}
