// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Regression tests, each named after the bug it pins: what the reviews of
//! the engine and their confirm rounds found that the latest-only index has
//! not made impossible. Each fails without its fix.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::assert_is_empty,
    reason = "test code"
)]

use core::time::Duration;

use licketysync_keys::chunk::seal_chunk;
use licketysync_keys::{CipherHash, FolderId, RecordHash};
use licketysync_protocol::connection::Timing;
use licketysync_protocol::frame::{Frame, FrameKind, MessageType};

use crate::config::EngineConfig;
use crate::inspect::Place;
use crate::issues::{IssueClass, IssueKind, StoreFailureCause, Subject};
use crate::rules::{conflict, file};
use crate::runtime::{Instant, Peer, PeerId, Storage};
use crate::store::{chunk_key, held_key};
use crate::sync::disk::copy_name;
use crate::testkit::{chunk_hash, config, folder_key, write_key, Hold, Net};
use crate::tests::{folder, pair, state, write};
use crate::timers::Purpose;
use crate::{FolderState, WriteFailure};

fn key_config(n: u8) -> EngineConfig {
    config(n, vec![folder_key(1, 1)])
}

/// The first chunk `record` names, as node `i` holds the record.
fn first_chunk(net: &Net, i: usize, record: RecordHash) -> CipherHash {
    let view = net.nodes[i].engine.folder(&folder()).unwrap();
    let r = view.records.iter().find(|r| r.hash == record).unwrap();
    r.chunks[0].cipher_hash
}

/// Whether node `i` raised an issue naming a record, or a peer.
fn blames_anyone(net: &Net, i: usize) -> bool {
    net.nodes[i]
        .engine
        .issues()
        .list()
        .iter()
        .any(crate::issues::Issue::blames)
}

/// Whether node `i` raised the local issue naming `chunk`.
fn named_changed_at_rest(net: &Net, i: usize, chunk: CipherHash) -> bool {
    net.nodes[i]
        .engine
        .issues()
        .list()
        .iter()
        .any(|x| x.kind == IssueKind::LocalChunkCorrupt && x.subject == Subject::Chunk(chunk))
}

fn read(net: &Net, i: usize, record: RecordHash) -> Result<Vec<u8>, crate::inspect::ReadError> {
    let n = &net.nodes[i];
    n.engine.read_file(&n.cx.storage, &folder(), &record)
}

/// Node `from` sends node `to` a frame of a critical type nobody knows: a
/// fault only the sender can be blamed for.
fn misbehave(net: &mut Net, from: usize, to: usize) {
    let unknown_critical = Frame::new(0xfff0, vec![]).unwrap().encode();
    net.nodes[from]
        .cx
        .outbox
        .entry(PeerId::new(to as u64))
        .or_default()
        .extend(unknown_critical);
    net.settle();
}

#[test]
fn a_blob_changed_at_rest_is_fetched_again_after_a_restart_and_blames_no_record() {
    // E1, the restart path: a restart judges every wanted stored chunk again,
    // and a blob that changed in this device's storage is no record's fault.
    let mut net = pair();
    let content = vec![5u8; 2500];
    let hash = write(&mut net, 0, "a.bin", &content).unwrap();
    net.advance(Duration::from_secs(3));
    let chunk = first_chunk(&net, 1, hash);
    net.nodes[1].cx.storage.flip(&chunk_key(&folder(), &chunk));
    net.restart(1, key_config(1));
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    assert_eq!(read(&net, 1, hash), Ok(content), "the peer's copy came");
    assert!(
        !blames_anyone(&net, 1),
        "{:?}",
        net.nodes[1].engine.issues()
    );
    assert!(named_changed_at_rest(&net, 1, chunk));
    assert_eq!(state(&net, 1), FolderState::UpToDate);
}

/// Node 1 holds a file from node 0 and is cut from it; the file's first
/// chunk at node 1 is flipped at rest (or its reads fail), and node 2,
/// connected to node 1 alone, asks node 1 for it. Returns the record, the
/// chunk and node 1's commits before node 2 asked.
fn serve_a_bad_blob(net: &mut Net, flip: bool) -> (RecordHash, CipherHash, u64) {
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    let hash = write(net, 0, "b.bin", &[6u8; 1500]).unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 1);
    let chunk = first_chunk(net, 1, hash);
    if flip {
        net.nodes[1].cx.storage.flip(&chunk_key(&folder(), &chunk));
    } else {
        net.nodes[1].cx.storage.get_fails = true;
    }
    let commits = net.nodes[1].cx.storage.commits;
    net.connect(1, 2);
    net.advance(Duration::from_secs(2));
    net.nodes[1].cx.storage.get_fails = false;
    (hash, chunk, commits)
}

fn three() -> Net {
    Net::new(vec![key_config(0), key_config(1), key_config(2)])
}

#[test]
fn a_blob_changed_at_rest_while_serving_is_deleted_with_its_marker_and_fetched_again() {
    // E1, the serving path (TM-10): answered not found, forgotten, lacking,
    // deleted with its marker at node 1's next commit, and fetched again;
    // no record blamed.
    let mut net = three();
    let (hash, chunk, _) = serve_a_bad_blob(&mut net, true);
    let view = net.nodes[1].engine.folder(&folder()).unwrap();
    assert!(view.lacking.contains(&chunk) && !view.stored_chunks.contains(&chunk));
    assert!(named_changed_at_rest(&net, 1, chunk));
    assert!(read(&net, 2, hash).is_err(), "nobody had a good copy yet");
    write(&mut net, 1, "other.txt", b"other").unwrap();
    let s = &net.nodes[1].cx.storage;
    assert_eq!(s.get(&chunk_key(&folder(), &chunk)), Ok(None));
    assert_eq!(s.get(&held_key(&folder(), &chunk)), Ok(None), "the marker");
    net.connect(0, 1);
    net.advance(Duration::from_secs(10));
    for i in [1, 2] {
        assert_eq!(read(&net, i, hash), Ok(vec![6u8; 1500]), "node {i}");
        assert!(!blames_anyone(&net, i), "node {i}");
    }
}

#[test]
fn deleting_a_blob_changed_at_rest_takes_no_commit_of_its_own() {
    // C-G (brief section 7: at most one commit per handler): the deletion
    // rides the next commit node 1 makes anyway.
    let mut net = three();
    let (_, chunk, _) = serve_a_bad_blob(&mut net, true);
    write(&mut net, 1, "other.txt", b"other").unwrap();
    let s = &net.nodes[1].cx.storage;
    assert!(!s.committed.contains_key(&chunk_key(&folder(), &chunk)));
    assert!(!s.committed.contains_key(&held_key(&folder(), &chunk)));
    let carried = s
        .commit_log
        .iter()
        .find(|keys| keys.contains(&chunk_key(&folder(), &chunk)))
        .unwrap();
    assert!(
        carried.len() > 2,
        "the deletion rode a commit made anyway, not one of its own"
    );
}

#[test]
fn a_storage_read_error_while_serving_never_deletes_the_blob_or_raises_an_issue() {
    // C-B: a failed read is no sign the blob changed.
    let mut net = three();
    let (hash, chunk, _) = serve_a_bad_blob(&mut net, false);
    assert!(net.nodes[1].engine.counters().read_errors >= 1);
    assert!(!named_changed_at_rest(&net, 1, chunk));
    write(&mut net, 1, "other.txt", b"other").unwrap();
    let s = &net.nodes[1].cx.storage;
    assert!(s.committed.contains_key(&chunk_key(&folder(), &chunk)));
    assert!(s.committed.contains_key(&held_key(&folder(), &chunk)));
    net.connect(0, 1);
    net.advance(Duration::from_secs(10));
    for i in [1, 2] {
        assert_eq!(read(&net, i, hash), Ok(vec![6u8; 1500]), "node {i}");
        assert!(net.nodes[i].engine.issues().list().is_empty(), "node {i}");
    }
}

#[test]
fn a_storage_read_error_during_a_rewrite_raises_no_issue() {
    // C-B, the write path: the blob is staged again, counted, no issue.
    let mut net = Net::new(vec![key_config(0)]);
    let content = vec![9u8; 1500];
    let first = write(&mut net, 0, "a.bin", &content).unwrap();
    net.nodes[0].cx.storage.get_fails = true;
    let second = write(&mut net, 0, "b.bin", &content).unwrap();
    net.nodes[0].cx.storage.get_fails = false;
    // Two for the write's chunks, and the refresh after it reads them too.
    assert!(net.nodes[0].engine.counters().read_errors >= 2);
    assert!(net.nodes[0].engine.issues().list().is_empty());
    for record in [first, second] {
        assert_eq!(read(&net, 0, record), Ok(content.clone()));
    }
}

#[test]
fn a_failed_refetch_commit_never_counts_a_blob_changed_at_rest_as_stored_and_good() {
    // C-H (R1's probe): node 0 finds its blob changed at rest after a
    // restart and asks node 1 again; only the handler that stages the good
    // copy fails its commit. The rollback leaves the bad blob and its
    // marker on disk, and re-reading the markers must not count it as
    // stored again with its positions still verified.
    let mut net = pair();
    let content = vec![4u8; 2500];
    let hash = write(&mut net, 1, "r.bin", &content).unwrap();
    net.advance(Duration::from_secs(3));
    let chunk = first_chunk(&net, 0, hash);
    net.nodes[0].cx.storage.flip(&chunk_key(&folder(), &chunk));
    net.restart(0, key_config(0));
    assert!(named_changed_at_rest(&net, 0, chunk));
    net.hold = Some(Hold::new(1, 0, MessageType::ChunkReply));
    net.connect(0, 1);
    net.nodes[0].cx.storage.commit_fails = true;
    net.release();
    assert!(matches!(state(&net, 0), FolderState::Paused(_)));
    let view = net.nodes[0].engine.folder(&folder()).unwrap();
    assert!(
        !view.stored_chunks.contains(&chunk) && view.lacking.contains(&chunk),
        "the bad blob is counted as stored"
    );
    net.nodes[0].cx.storage.commit_fails = false;
    net.advance(Duration::from_secs(15));
    assert_eq!(read(&net, 0, hash), Ok(content));
    assert_eq!(state(&net, 0), FolderState::UpToDate);
}

#[test]
fn a_rewrite_of_the_same_content_stages_a_blob_changed_at_rest_again() {
    // E1, the local-rewrite path: the book still counts the blob as stored,
    // and a new record naming it must not name a blob that changed.
    let mut net = Net::new(vec![key_config(0)]);
    let content = vec![7u8; 1500];
    let first = write(&mut net, 0, "a.bin", &content).unwrap();
    let chunk = first_chunk(&net, 0, first);
    net.nodes[0].cx.storage.flip(&chunk_key(&folder(), &chunk));
    let second = write(&mut net, 0, "b.bin", &content).unwrap();
    for record in [first, second] {
        assert_eq!(read(&net, 0, record), Ok(content.clone()));
    }
    assert!(named_changed_at_rest(&net, 0, chunk));
}

#[test]
fn a_chunk_that_arrives_for_a_hash_stored_already_is_dropped_and_counted() {
    // E2: once the chunk patience lets a second connection ask, the slower
    // answer finds the hash stored.
    let mut net = Net::new(vec![key_config(0)]);
    let hash = write(&mut net, 0, "c.bin", &[8u8; 500]).unwrap();
    let chunk = first_chunk(&net, 0, hash);
    let n = &mut net.nodes[0];
    let blob =
        n.cx.storage
            .get(&chunk_key(&folder(), &chunk))
            .unwrap()
            .unwrap();
    let commits = n.cx.storage.commits;
    let f = folder();
    n.engine.run(&mut n.cx, |e, cx, w| {
        e.on_chunk(cx, w, f, PeerId::new(9), chunk, &blob);
    });
    assert_eq!(n.engine.counters().late_chunks, 1);
    assert_eq!(n.cx.storage.commits, commits, "nothing staged");
}

#[test]
fn outsiders_with_fresh_device_keys_never_evict_an_issue_naming_a_key_holder() {
    // E4 (TM-22): a device ID is anyone's to mint, so a peer that proved no
    // key of a folder this device holds counts in the unproven class.
    let mut configs = vec![key_config(0), key_config(1)];
    for n in 2..19 {
        configs.push(config(n, vec![folder_key(2, 1)]));
    }
    let mut net = Net::new(configs);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    misbehave(&mut net, 1, 0);
    for n in 2..19 {
        net.connect(0, n);
        misbehave(&mut net, n, 0);
    }
    let issues = net.nodes[0].engine.issues();
    let proven = issues.of(IssueClass::ProvenPeer);
    assert_eq!(proven.len(), 1, "{issues:?}");
    assert!(matches!(
        proven[0].issue.subject,
        Subject::Peer { peer, holder: true, device: Some(_) } if peer == PeerId::new(1)
    ));
    let unproven = issues.of(IssueClass::UnprovenPeer);
    assert_eq!(unproven.len(), 1);
    assert_eq!(unproven[0].count, 17);
    assert_eq!(issues.overflow_total(), 0);
}

/// `n` directories written on node `i`.
fn mkdirs(net: &mut Net, i: usize, from: usize, n: usize) {
    let f = folder();
    for d in from..from + n {
        net.with(i, |e, cx| e.mkdir(cx, f, &format!("d{d}"), 0))
            .unwrap();
    }
}

/// Node 1 met node 0 (and `others`), so each holds the other's cursor, and
/// is cut from them; node 0 then writes `n` directories, which `others`
/// take. Node 0 (and every other) paces its replies one page per send poll;
/// node 1 asks for pages of 64 and probes its store every `probe`. When node
/// 1 reconnects, its round's Since reply brings the `n` records in pages.
fn met_then_apart(n: usize, others: &[usize], probe: Duration) -> Net {
    let mut configs = Vec::new();
    for i in 0..=others.iter().copied().max().unwrap_or(1).max(1) {
        let mut c = key_config(i as u8);
        if i == 1 {
            c.max_records = 64;
            c.resume_probe = probe;
        } else {
            c.send_budget = 1;
        }
        configs.push(c);
    }
    let mut net = Net::new(configs);
    mkdirs(&mut net, 0, 0, 1);
    net.connect(0, 1);
    for &o in others {
        net.connect(1, o);
        net.connect(0, o);
    }
    net.advance(Duration::from_secs(15));
    assert_eq!(state(&net, 1), FolderState::UpToDate);
    net.disconnect(0, 1);
    for &o in others {
        net.disconnect(1, o);
    }
    mkdirs(&mut net, 0, 1, n);
    net.advance(Duration::from_secs(15));
    net
}

#[test]
fn a_pause_that_ends_during_a_reply_voids_the_reply_and_blames_nobody() {
    // E5 (R1's probe), on the new exchange: 200 records in a Since reply of
    // pages of 64, one page every send poll; the first page fails to store,
    // the pause ends 75 ms later, mid-reply. The reply's later pages are
    // reported skipped, unjudged, up to its last, and the round owed brings
    // them; nobody is blamed.
    let mut net = met_then_apart(200, &[], Duration::from_millis(75));
    net.nodes[1].cx.storage.fail_prefix = Some((b"e/r/".to_vec(), 1));
    net.connect(0, 1);
    net.advance(Duration::from_secs(30));
    for i in [0, 1] {
        let e = &net.nodes[i].engine;
        assert_eq!(e.counters().blaming_closes(), 0, "node {i}");
        assert!(!blames_anyone(&net, i), "node {i}: {:?}", e.issues());
    }
    let e = &net.nodes[1].engine;
    assert!(
        e.counters().void_reply_pages >= 1,
        "a page came after the resume: {:?}",
        e.counters()
    );
    assert_eq!(e.folder(&folder()).unwrap().records.len(), 201);
    assert_eq!(state(&net, 1), FolderState::UpToDate);
}

#[test]
fn void_pages_after_a_resume_never_keep_another_connections_owed_round_from_counting() {
    // R1's two-peer probe (C-D), on the new exchange: node 1 comes back to
    // node 2 and node 0 at once; node 0's Since reply is paced and its first
    // page fails to store; the pause ends 75 ms later and the round owed to
    // node 2 begins, held by node 2 a second (INDEX_REQUEST_MIN_INTERVAL)
    // while node 0's void pages arrive. A void page moves nothing: node 2's
    // round ends caught up, and the folder is Up to date.
    let mut net = met_then_apart(200, &[2], Duration::from_millis(75));
    net.nodes[1].cx.storage.fail_prefix = Some((b"e/r/".to_vec(), 1));
    net.connect(1, 2);
    net.connect(0, 1);
    net.advance(Duration::from_secs(30));
    let e = &net.nodes[1].engine;
    assert!(e.counters().void_reply_pages >= 1, "{:?}", e.counters());
    assert_eq!(e.folder(&folder()).unwrap().records.len(), 201);
    assert_eq!(state(&net, 1), FolderState::UpToDate);
}

#[test]
fn void_pages_from_one_server_never_keep_the_folder_syncing_with_three_nodes() {
    // R2's three-node probe (C-D), on the new exchange: nodes 0 and 2 hold
    // the same 300 new records, and node 1 comes back to both, in Since
    // pages of 64 paced one per send poll; its first put fails and the pause
    // ends mid-reply.
    let mut net = met_then_apart(300, &[2], Duration::from_millis(75));
    assert_eq!(state(&net, 2), FolderState::UpToDate);
    net.nodes[1].cx.storage.fail_prefix = Some((b"e/r/".to_vec(), 1));
    net.connect(0, 1);
    net.connect(1, 2);
    net.advance(Duration::from_secs(60));
    for i in 0..3 {
        let e = &net.nodes[i].engine;
        assert_eq!(e.counters().blaming_closes(), 0, "node {i}");
        assert_eq!(e.folder(&folder()).unwrap().records.len(), 301, "node {i}");
        assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
    }
    assert!(net.nodes[1].engine.counters().void_reply_pages >= 1);
}

#[test]
fn a_failed_handler_owes_a_round_to_every_folder_whose_records_it_skipped() {
    // E6: one handler brings pages of two folders; the first page's put
    // fails, so the other folder's page is not judged. That folder staged
    // nothing and is not paused, so nothing else would bring its records
    // back.
    let keys = || vec![folder_key(1, 1), folder_key(2, 1)];
    let (fa, fb) = (folder_key(1, 1).folder_id(), folder_key(2, 1).folder_id());
    let mut net = Net::new(vec![config(0, keys()), config(1, keys())]);
    for f in [fa, fb] {
        for i in 0..3 {
            net.with(0, |e, cx| e.mkdir(cx, f, &format!("d{i}"), 0))
                .unwrap();
        }
    }
    net.nodes[1].cx.storage.fail_prefix = Some((b"e/r/".to_vec(), 1));
    net.connect(0, 1);
    let view = |net: &Net, f: &FolderId| net.nodes[1].engine.folder(f).unwrap();
    let paused: Vec<FolderId> = [fa, fb]
        .into_iter()
        .filter(|f| matches!(view(&net, f).state, FolderState::Paused(_)))
        .collect();
    assert_eq!(paused.len(), 1, "both pages came in one handler");
    let other = if paused[0] == fa { fb } else { fa };
    assert!(
        view(&net, &other).records.is_empty(),
        "its page was skipped"
    );
    assert!(
        matches!(view(&net, &other).state, FolderState::Syncing { .. }),
        "not caught up: {:?}",
        view(&net, &other).state
    );
    assert_eq!(
        net.nodes[1].engine.counters().rounds_owed,
        1,
        "a round owed to the skipped folder, before any resume"
    );
    net.advance(Duration::from_secs(15));
    for f in [fa, fb] {
        let v = view(&net, &f);
        assert_eq!((v.records.len(), v.state), (3, FolderState::UpToDate));
    }
}

#[test]
fn a_pause_clears_caught_up_so_a_resumed_folder_reads_syncing_until_its_owed_round() {
    // E6: Up to date only once a round that began after the pause completes.
    let mut net = pair();
    assert_eq!(state(&net, 1), FolderState::UpToDate);
    net.nodes[1].cx.storage.full = true;
    write(&mut net, 0, "p.txt", b"p").unwrap();
    assert_eq!(state(&net, 1), FolderState::Paused(StoreFailureCause::Full));
    net.nodes[1].cx.storage.full = false;
    // The probe resumes the folder; nothing is delivered yet, so the round
    // owed has not completed.
    let n = &mut net.nodes[1];
    n.engine.run(&mut n.cx, |e, cx, w| e.probe(cx, w));
    assert!(
        matches!(
            state(&net, 1),
            FolderState::Syncing {
                rounds_pending: 1,
                ..
            }
        ),
        "{:?}",
        state(&net, 1)
    );
    net.advance(Duration::from_secs(15));
    assert_eq!(state(&net, 1), FolderState::UpToDate);
}

#[test]
fn a_round_that_completes_while_paused_does_not_count_as_caught_up() {
    // E5 and E6, on the new exchange: a Since reply that began before the
    // pause and ends during it brought pages the folder did not judge; its
    // round is never caught up (the connection's rule for a round that
    // skipped a record), and the resumed folder reads Syncing until the
    // round owed ends caught up.
    let mut net = met_then_apart(200, &[], Duration::from_secs(5));
    net.nodes[1].cx.storage.fail_prefix = Some((b"e/r/".to_vec(), 1));
    net.connect(0, 1);
    net.advance(Duration::from_secs(1));
    assert!(matches!(state(&net, 1), FolderState::Paused(_)));
    assert_eq!(
        net.nodes[1].engine.counters().void_reply_pages,
        3,
        "the three pages after the one whose put failed"
    );
    // The probe resumes the folder; nothing is delivered yet.
    let n = &mut net.nodes[1];
    n.engine.run(&mut n.cx, |e, cx, w| e.probe(cx, w));
    assert!(
        matches!(
            state(&net, 1),
            FolderState::Syncing {
                rounds_pending: 1,
                ..
            }
        ),
        "{:?}",
        state(&net, 1)
    );
    net.advance(Duration::from_secs(20));
    assert_eq!(state(&net, 1), FolderState::UpToDate);
    assert_eq!(
        net.nodes[1].engine.folder(&folder()).unwrap().records.len(),
        201
    );
}

#[test]
fn a_commit_that_fails_after_its_puts_leaves_no_record_in_memory_ahead_of_disk() {
    // E8: after a failed commit, memory holds nothing the disk lost (the
    // index's transaction is dropped, which undoes it).
    let mut net = pair();
    net.nodes[1].cx.storage.commit_fails = true;
    let hash = write(&mut net, 0, "x.txt", b"x").unwrap();
    let held = |net: &Net| {
        net.nodes[1]
            .engine
            .folder(&folder())
            .unwrap()
            .records
            .iter()
            .any(|r| r.hash == hash)
    };
    assert!(
        matches!(state(&net, 1), FolderState::Paused(StoreFailureCause::Io)),
        "{:?}",
        state(&net, 1)
    );
    assert!(!held(&net), "memory dropped what the failed commit lost");
    net.nodes[1].cx.storage.commit_fails = false;
    net.advance(Duration::from_secs(15));
    assert!(held(&net), "the round owed brought it back");
    net.restart(1, key_config(1));
    assert!(held(&net), "and this time it is on disk");
}

#[test]
fn a_folder_past_the_open_limit_of_a_connection_is_counted_and_named() {
    // C-E: a peer refuses a proof once 64 folders are open on the
    // connection (protocol.md 3.5 step 6), so a device sharing 65 folders
    // with one peer syncs 64 of them with it; the 65th must not go unseen.
    let keys = || -> Vec<_> { (1..=65u8).map(|n| folder_key(n, 1)).collect() };
    let mut net = Net::new(vec![config(0, keys()), config(1, keys())]);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    for i in [0, 1] {
        let e = &net.nodes[i].engine;
        assert_eq!(e.counters().open_limit_refusals, 1, "node {i}");
        let named: Vec<FolderId> = e
            .issues()
            .list()
            .iter()
            .filter(|x| x.kind == IssueKind::OpenLimit)
            .filter_map(|x| x.folder)
            .collect();
        assert_eq!(named.len(), 1, "node {i}");
        let left_out = e.folder(&named[0]).unwrap().state;
        assert!(
            matches!(left_out, FolderState::Syncing { open_on: 0, .. }),
            "{left_out:?}"
        );
        let up_to_date = e
            .folder_ids()
            .filter(|f| e.folder(f).unwrap().state == FolderState::UpToDate)
            .count();
        assert_eq!(up_to_date, 64, "node {i}");
    }
}

/// What runs at a chunk request's patience deadline besides its timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtDeadline {
    /// Nothing: the patience timer alone.
    Alone,
    /// The Status ticks of the connections node 2 opened as it asked, which
    /// fall on that instant. The test net fires the timers due at one
    /// instant in node order, so node 1's Status reaches node 2 before any
    /// of node 2's own timers fires.
    StatusTick,
    /// A handler with nothing to do, this many nanoseconds after the
    /// deadline, before the timer fires (late, as a runtime may fire it).
    Idle(u64),
    /// Node 0's second frame of an unknown non-critical type, which is only
    /// counted (protocol.md 5), this many nanoseconds after the deadline.
    Frame(u64),
}

/// A frame of a type nobody knows that a receiver may ignore.
fn unknown_non_critical() -> Vec<u8> {
    Frame::new(0x7ff0, vec![]).unwrap().encode()
}

/// The deadline node `i`'s timer for `purpose` is armed at, if it is.
fn armed_at(net: &Net, i: usize, purpose: Purpose) -> Option<u64> {
    let n = &net.nodes[i];
    let id = n.engine.timers.id_of(purpose)?;
    n.cx.timers.get(&id).map(|at| at.as_nanos())
}

/// Fires node `i`'s timers due at `at`, where the net's clock is, lowest id
/// first, settling after each: what `Net::advance` does at that instant
/// for node `i` before any node after it.
fn fire_due(net: &mut Net, i: usize, at: u64) {
    loop {
        let n = &mut net.nodes[i];
        let due = n.cx.timers.iter().filter(|(_, t)| t.as_nanos() == at);
        let Some(id) = due.map(|(id, _)| *id).min() else {
            return;
        };
        n.cx.timers.remove(&id);
        n.engine.on_timer(&mut n.cx, id);
        net.settle();
    }
}

/// Nodes 0 and 1 hold the one chunk of a file, and node 2 has asked node 0
/// for it; node 0's answer, and all it sends node 2 after it, is held back
/// for good, and node 2 may not ask node 1 yet. For
/// [`AtDeadline::StatusTick`] node 2 asked as it met node 0; otherwise the
/// three met 2 s before node 0 wrote the file, so that no other timer falls
/// on the deadline. Returns the net, the record, its content and the
/// deadline.
fn asked_of_a_silent_peer(case: AtDeadline) -> (Net, RecordHash, Vec<u8>, u64) {
    let mut net = three();
    let content = vec![5u8; 500];
    net.connect(0, 1);
    let record = if case == AtDeadline::StatusTick {
        net.advance(Duration::from_secs(2));
        let record = write(&mut net, 0, "p.bin", &content).unwrap();
        net.advance(Duration::from_secs(3));
        net.hold = Some(Hold::new(0, 2, MessageType::ChunkReply));
        net.connect(0, 2);
        net.connect(1, 2);
        record
    } else {
        net.connect(0, 2);
        net.connect(1, 2);
        net.advance(Duration::from_secs(2));
        net.hold = Some(Hold::new(0, 2, MessageType::ChunkReply));
        write(&mut net, 0, "p.bin", &content).unwrap()
    };
    assert_eq!(
        read(&net, 1, record),
        Ok(content.clone()),
        "node 1 holds it"
    );
    assert!(read(&net, 2, record).is_err(), "node 1 is not asked yet");
    let asked = Instant::from_nanos(net.now);
    let wait = crate::inflight::patience(&Timing::SPEC);
    assert_eq!(wait, Duration::from_secs(60));
    let deadline = asked.saturating_add(wait);
    assert_eq!(
        net.nodes[2].engine.in_flight.next_expiry(wait, asked),
        Some(deadline),
        "node 2 asked node 0 now"
    );
    (net, record, content, deadline.as_nanos())
}

#[test]
fn a_chunk_whose_patience_runs_out_while_another_handler_runs_is_offered_elsewhere() {
    // Node 0 takes node 2's request and never answers while it stays
    // connected, so once the request's patience runs out node 2 must ask
    // node 1 (`inflight`; TM-22). The patience timer was disarmed, the
    // passes never driven, whenever a handler other than its own ran at or
    // after the deadline before it fired: `InFlight::next_expiry` leaves out
    // an expiry at `now`, and `settle_states` cancelled the timer. So a
    // peer that never answers could keep the hash from the others by
    // sending frames that cost it nothing. `Alone` shows the timer is armed
    // at all.
    let cases = [
        AtDeadline::Alone,
        AtDeadline::StatusTick,
        AtDeadline::Idle(0),
        AtDeadline::Idle(1_000_000),
        AtDeadline::Frame(0),
        AtDeadline::Frame(1_000_000),
    ];
    let fetched: Vec<(AtDeadline, bool)> = cases
        .into_iter()
        .map(|case| {
            let (mut net, record, content, deadline) = asked_of_a_silent_peer(case);
            let from_0 = PeerId::new(0);
            if let AtDeadline::Frame(_) = case {
                // The first is answered Unsupported.
                let n = &mut net.nodes[2];
                n.engine
                    .on_message(&mut n.cx, from_0, &unknown_non_critical());
                net.settle();
            }
            net.advance(Duration::from_nanos(deadline - 1 - net.now));
            assert_eq!(
                armed_at(&net, 2, Purpose::ChunkPatience),
                Some(deadline),
                "{case:?}"
            );
            let due: usize = net
                .nodes
                .iter()
                .map(|n| {
                    n.cx.timers
                        .values()
                        .filter(|at| at.as_nanos() == deadline)
                        .count()
                })
                .sum();
            if case == AtDeadline::StatusTick {
                let own = |net: &Net| {
                    [PeerId::new(0), PeerId::new(1)].map(|p| armed_at(net, 2, Purpose::Wake(p)))
                };
                assert_eq!(own(&net), [Some(deadline); 2], "node 2's Status ticks");
                let heard = net.statuses(1, 2).len();
                net.now = deadline;
                for n in &mut net.nodes {
                    n.cx.now = deadline;
                }
                fire_due(&mut net, 0, deadline);
                fire_due(&mut net, 1, deadline);
                assert_eq!(
                    net.statuses(1, 2).len(),
                    heard + 1,
                    "node 1's Status reached node 2"
                );
                assert_eq!(
                    own(&net),
                    [Some(deadline); 2],
                    "before node 2's own timers fired"
                );
            } else {
                assert_eq!(due, 1, "{case:?}: the patience timer alone is due");
            }
            if let AtDeadline::Idle(late) | AtDeadline::Frame(late) = case {
                net.now = deadline + late;
                for n in &mut net.nodes {
                    n.cx.now = deadline + late;
                }
                let n = &mut net.nodes[2];
                let counted = n.engine.counters().unsupported;
                if let AtDeadline::Frame(_) = case {
                    n.engine
                        .on_message(&mut n.cx, from_0, &unknown_non_critical());
                    assert_eq!(n.engine.counters().unsupported, counted + 1, "{case:?}");
                } else {
                    n.engine.run(&mut n.cx, |_, _, _| ());
                }
                net.settle();
            }
            net.advance(Duration::from_secs(65));
            assert!(net.nodes[2].cx.connected.contains(&from_0), "{case:?}");
            assert!(
                !net.nodes[2].engine.timers.is_armed(Purpose::ChunkPatience),
                "{case:?}: nothing is left to wait for"
            );
            (case, read(&net, 2, record) == Ok(content))
        })
        .collect();
    assert!(fetched.iter().all(|(_, ok)| *ok), "{fetched:?}");
}

/// What node 1 of [`withheld_by_two`], which lacks the chunk, does a second
/// after each minute to be asked for it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejoin {
    /// Nothing: after its refusal its pass waits for a trigger.
    Nothing,
    /// It reconnects, which starts its pass afresh.
    Reconnect,
    /// It reports one more chunk stored in its next Status, a count a peer
    /// may raise at will, which triggers its next pass.
    MoreStored,
}

/// The hashes node `from` asked node `to` for, across every connection
/// between them, in order.
fn requested(net: &Net, from: usize, to: usize) -> Vec<CipherHash> {
    use licketysync_protocol::frame::FrameDecoder;
    let bytes = net.streams.get(&(from, to)).cloned().unwrap_or_default();
    let mut decoder = FrameDecoder::new(licketysync_protocol::limits::MAX_MESSAGE_SIZE);
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    while let Ok(Some(frame)) = decoder.next_frame(&mut input) {
        if frame.kind() == FrameKind::Known(MessageType::ChunkRequest) {
            out.extend(chunk_hash(&frame));
        }
    }
    out
}

/// The chunk requests node `from` sent node `to`, across every connection
/// between them.
fn chunk_requests(net: &Net, from: usize, to: usize) -> usize {
    requested(net, from, to).len()
}

/// Node 0 holds the one chunk of a file and never answers node 2's request
/// for it; node 1 lacks it and answers `CHUNK_NOT_FOUND`; node 3 holds it
/// and is honest. Node 2 meets them in that order, so node 1 is offered the
/// hash before node 3 whenever both may ask. Node 1 does `rejoin` a second
/// after each minute since node 2 asked node 0, for five minutes. Returns
/// whether node 2 held the file a second after the patience first ran out
/// and at the end, and the chunk requests it sent node 1 and node 3.
fn withheld_by_two(rejoin: Rejoin) -> (bool, bool, usize, usize) {
    let mut net = Net::new((0..4).map(key_config).collect());
    let content = vec![5u8; 500];
    net.connect(0, 3);
    for i in [0, 1, 3] {
        net.connect(i, 2);
    }
    net.advance(Duration::from_secs(2));
    net.hold = Some(Hold::new(0, 2, MessageType::ChunkReply));
    let record = write(&mut net, 0, "p.bin", &content).unwrap();
    assert_eq!(
        read(&net, 3, record),
        Ok(content.clone()),
        "node 3 holds it"
    );
    assert!(read(&net, 1, record).is_err(), "node 1 lacks it");
    assert!(chunk_requests(&net, 1, 2) > 0, "node 2 refused node 1");
    assert_eq!(
        net.nodes[1].engine.in_flight.entries(),
        0,
        "a request refused goes once its handler ends"
    );
    let asked = net.now;
    let wait = crate::inflight::patience(&Timing::SPEC);
    assert_eq!(
        net.nodes[2]
            .engine
            .in_flight
            .next_expiry(wait, Instant::from_nanos(asked)),
        Some(Instant::from_nanos(asked).saturating_add(wait)),
        "node 2 asked node 0 now"
    );
    let mut first = false;
    for minute in 1..=5 {
        let at = asked + minute * wait.as_nanos() as u64 + 1_000_000_000;
        net.advance(Duration::from_nanos(at - net.now));
        if minute == 1 {
            first = read(&net, 2, record) == Ok(content.clone());
        }
        match rejoin {
            Rejoin::Nothing => {}
            Rejoin::Reconnect => {
                net.disconnect(1, 2);
                net.connect(1, 2);
            }
            Rejoin::MoreStored => {
                net.with(1, |e, cx| {
                    e.run(cx, |e, cx, w| e.notify_stored(cx, w, folder(), 1))
                });
            }
        }
    }
    assert!(
        net.nodes[2].cx.connected.contains(&PeerId::new(0)),
        "node 0 stayed connected"
    );
    let last = read(&net, 2, record) == Ok(content);
    (
        first,
        last,
        chunk_requests(&net, 2, 1),
        chunk_requests(&net, 2, 3),
    )
}

#[test]
fn a_chunk_one_peer_withholds_is_asked_of_an_honest_holder_once_another_refuses_it() {
    // The control for the two below: node 1 refuses once and does nothing
    // more. Its refusal dropped its request but left its ask time as the
    // whole hash's (`inflight`), so node 3 was asked only a second patience
    // later.
    let (first, last, to_1, to_3) = withheld_by_two(Rejoin::Nothing);
    assert!(
        first,
        "fetched as node 1 refused; at the end {last}; asked node 1 {to_1}, node 3 {to_3}"
    );
    assert_eq!((to_1, to_3), (1, 1));
}

#[test]
fn two_peers_never_keep_a_chunk_from_an_honest_holder_by_reconnecting() {
    // Node 0 takes the request and stays silent; node 1, which sorts before
    // node 3, is asked first at each expiry, refuses, and reconnects so that
    // its pass may ask again before node 3's. Each ask of node 1 restarted
    // the patience for every connection (`inflight`), so node 3 was never
    // asked: two key holders of any tier (ruling S-3) kept the hash from an
    // honest holder for as long as they liked.
    let (first, last, to_1, to_3) = withheld_by_two(Rejoin::Reconnect);
    assert!(first && last, "fetched; asked node 1 {to_1}, node 3 {to_3}");
    assert_eq!((to_1, to_3), (1, 1), "node 3 asked as node 1 refused");
}

#[test]
fn two_peers_never_keep_a_chunk_from_an_honest_holder_by_raising_chunks_stored() {
    // As above, but node 1 stays connected and triggers its next pass with
    // a Status that reports one more chunk stored (`protocol.md` 4.6,
    // "Passes").
    let (first, last, to_1, to_3) = withheld_by_two(Rejoin::MoreStored);
    assert!(first && last, "fetched; asked node 1 {to_1}, node 3 {to_3}");
    assert_eq!((to_1, to_3), (1, 1), "node 3 asked as node 1 refused");
}

/// How each of nodes 0 and 1 of [`taking_turns`] ends its turn holding the
/// hash, so that the other is asked next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndTurn {
    /// It reconnects, which drops its request and starts its pass afresh.
    Reconnect,
    /// It answers `CHUNK_NOT_FOUND`, then reports one more chunk stored so
    /// that its pass may ask again.
    Refuse,
}

/// Node 3 writes a file of one chunk; nodes 0 and 1 lack it and take turns
/// holding node 2's request for it without answering, each ending its turn
/// (`end`) every 30 s, before its patience runs out, so that the other is
/// asked next. Node 2 met them in the order 0, 1, 3. Returns the turn after
/// which node 2 first held the file, if it did within five minutes, and the
/// chunk requests it sent each of nodes 0, 1 and 3.
fn taking_turns(end: EndTurn) -> (Option<u32>, [usize; 3]) {
    let mut net = Net::new((0..4).map(key_config).collect());
    let content = vec![6u8; 500];
    for i in [0, 1, 3] {
        net.connect(i, 2);
    }
    net.advance(Duration::from_secs(2));
    net.hold = Some(Hold::new(0, 2, MessageType::ChunkReply));
    let record = write(&mut net, 3, "q.bin", &content).unwrap();
    let asked = |net: &Net| [0, 1, 3].map(|to| chunk_requests(net, 2, to));
    assert_eq!(asked(&net), [1, 0, 0], "node 0 asked first");
    let mut held = None;
    for turn in 1..=10 {
        net.advance(Duration::from_secs(30));
        let (holder, other) = if turn % 2 == 1 { (0, 1) } else { (1, 0) };
        match end {
            EndTurn::Reconnect => {
                net.hold = Some(Hold::new(other, 2, MessageType::ChunkReply));
                net.disconnect(holder, 2);
                net.connect(holder, 2);
            }
            EndTurn::Refuse => {
                net.release_unsettled();
                net.hold = Some(Hold::new(other, 2, MessageType::ChunkReply));
                net.settle();
                net.with(holder, |e, cx| {
                    e.run(cx, |e, cx, w| e.notify_stored(cx, w, folder(), 1))
                });
            }
        }
        if held.is_none() && read(&net, 2, record) == Ok(content.clone()) {
            held = Some(turn);
        }
    }
    (held, asked(&net))
}

#[test]
fn two_peers_never_keep_a_chunk_from_an_honest_holder_by_taking_turns_reconnecting() {
    // Nodes 0 and 1, which node 2 met before node 3, hand the request back
    // and forth by reconnecting, each before its patience runs out: the
    // hash went to the first connection free to ask whenever the other's
    // request ended, so node 3 was never asked.
    let (held, asked) = taking_turns(EndTurn::Reconnect);
    assert_eq!(held, Some(2), "node 3 asked at the second turn: {asked:?}");
    assert_eq!(asked[2], 1, "{asked:?}");
}

#[test]
fn two_peers_never_keep_a_chunk_from_an_honest_holder_by_taking_turns_refusing() {
    // As above, each ending its turn with `CHUNK_NOT_FOUND` and a Status
    // that triggers its next pass.
    let (held, asked) = taking_turns(EndTurn::Refuse);
    assert_eq!(held, Some(2), "node 3 asked at the second turn: {asked:?}");
    assert_eq!(asked[2], 1, "{asked:?}");
}

/// What node `i` lacks of the folder.
fn lacking(net: &Net, i: usize) -> usize {
    net.nodes[i].engine.folder(&folder()).unwrap().lacking.len()
}

/// Node 3 writes a file of eight chunks, which node 1 fetches; then node 2
/// meets nodes 0, 1 and 3, in that order. Node 0 takes every request and
/// never answers. Node 1 advertises `max_requests_in_flight` 1 and, when
/// `slow`, answers each request 59 s after it was asked, inside the
/// patience. Returns, at 60 s and every 59 s after, until 296 s: the
/// seconds since node 2 met them, the chunk requests it sent nodes 0, 1 and
/// 3, and what it lacks.
fn one_slot_ahead(slow: bool) -> Vec<(u64, [usize; 3], usize)> {
    let mut configs: Vec<EngineConfig> = (0..4).map(key_config).collect();
    configs[1].max_requests_in_flight = 1;
    let mut net = Net::new(configs);
    net.connect(1, 3);
    net.advance(Duration::from_secs(2));
    let eight: Vec<u8> = (0..8 * 1024usize)
        .map(|i| (i.wrapping_mul(7) + i / 1024) as u8)
        .collect();
    write(&mut net, 3, "eight.bin", &eight).unwrap();
    net.advance(Duration::from_secs(2));
    assert_eq!(lacking(&net, 1), 0, "node 1 holds it");
    net.gate.rules.push((0, 2, MessageType::ChunkReply, None));
    if slow {
        net.gate.rules.push((1, 2, MessageType::ChunkReply, None));
    }
    for i in [0, 1, 3] {
        net.connect(i, 2);
    }
    let start = net.now;
    let step = |net: &Net| {
        let asked = [0, 1, 3].map(|to| chunk_requests(net, 2, to));
        ((net.now - start) / 1_000_000_000, asked, lacking(net, 2))
    };
    assert_eq!(step(&net), (0, [8, 0, 0], 8), "node 0 holds them all");
    net.advance(Duration::from_secs(60));
    let mut log = vec![step(&net)];
    for _ in 0..4 {
        net.advance(Duration::from_secs(59));
        net.deliver(1, 2, |_| true);
        log.push(step(&net));
    }
    assert_eq!(net.nodes[2].engine.counters().internal_errors, 0);
    log
}

#[test]
fn a_one_slot_peer_that_serves_slowly_keeps_no_batch_from_the_honest_holder() {
    // Review R1's probe C. Once node 0's patience ran out, node 1 was first
    // in line for all eight hashes. Counted as able to ask while its one
    // slot was taken, it kept the turn at the seven it could not ask for:
    // node 3 was never asked, and node 2 got one chunk every 59 s.
    let log = one_slot_ahead(true);
    assert!(log[0].1[2] > 0, "node 3 asked at 60 s: {log:?}");
    assert_eq!((log[1].0, log[1].2), (119, 0), "all held by 119 s: {log:?}");
}

#[test]
fn a_one_slot_peer_next_in_line_leaves_the_rest_of_a_batch_to_the_honest_holder() {
    // Review R1's probe B: as above with node 1 answering at once. It took
    // the hashes one at a time while node 3, with room for all, was asked
    // for none.
    let log = one_slot_ahead(false);
    assert!(log[0].1[2] > 0, "node 3 asked at 60 s: {log:?}");
    assert_eq!((log[0].0, log[0].2), (60, 0), "all held at 60 s: {log:?}");
}

#[test]
fn a_turn_passes_on_when_a_pass_past_the_hash_comes_to_wait() {
    // Review R2's probe. Node 1's passes in folder one were driven while
    // node 3, first in line for h, still counted as able to ask; its pass,
    // past h after an earlier `CHUNK_NOT_FOUND`, came to wait without asking
    // for it, and nothing drove the passes again, so node 4, the honest
    // holder after it, was never asked. Node 3's pass got past h because
    // folder two's passes ran first in the handler that brought its refusal
    // and filled its room, and later handlers drove folder two alone.
    let ids = [1u8, 2].map(|s| folder_key(s, 1).folder_id());
    let (s1, s2) = if ids[0] > ids[1] { (1u8, 2u8) } else { (2, 1) };
    let (f1, f2) = (folder_key(s1, 1).folder_id(), folder_key(s2, 1).folder_id());
    assert!(f2 < f1, "folder two's passes run first");
    // Three one-chunk files of folder one, by cipher hash: h < j < p.
    let keys = write_key(s1).chunk_keys();
    let hash = |c: &Vec<u8>| seal_chunk(&keys, c).unwrap().cipher_hash;
    let mut contents: Vec<Vec<u8>> = (0u8..12).map(|i| vec![i; 600]).collect();
    contents.sort_by_key(hash);
    let (hc, jc, pc) = (
        contents[0].clone(),
        contents[1].clone(),
        contents[2].clone(),
    );
    let (h, j, p) = (hash(&hc), hash(&jc), hash(&pc));
    // The writer, the requester, a holder that never answers it, a peer
    // that lacks j, and an honest holder.
    let (writer, asker, silent, partial, honest) = (0, 1, 2, 3, 4);
    let both = |n: u8| config(n, vec![folder_key(s1, 1), folder_key(s2, 1)]);
    let mut configs = vec![
        config(0, vec![folder_key(s1, 1)]),
        both(1),
        config(2, vec![folder_key(s1, 1)]),
        both(3),
        config(4, vec![folder_key(s1, 1)]),
    ];
    configs[silent].max_requests_in_flight = 1;
    configs[partial].max_requests_in_flight = 2;
    let mut net = Net::new(configs);
    let write_in = |net: &mut Net, i: usize, f: FolderId, path: &str, content: &[u8]| {
        net.with(i, |eng, cx| eng.write_file(cx, f, path, content, 0))
            .unwrap();
    };
    let holds = |net: &Net, i: usize, f: FolderId, c: CipherHash| {
        let view = net.nodes[i].engine.folder(&f).unwrap();
        view.stored_chunks.contains(&c)
    };
    for i in [silent, partial, honest] {
        net.connect(writer, i);
    }
    net.advance(Duration::from_secs(2));
    write_in(&mut net, writer, f1, "h.bin", &hc);
    write_in(&mut net, writer, f1, "p.bin", &pc);
    net.advance(Duration::from_secs(5));
    net.disconnect(writer, partial);
    write_in(&mut net, writer, f1, "j.bin", &jc);
    net.advance(Duration::from_secs(5));
    net.disconnect(writer, silent);
    net.disconnect(writer, honest);
    assert!(
        holds(&net, partial, f1, h) && holds(&net, partial, f1, p) && !holds(&net, partial, f1, j)
    );
    assert!([h, j, p]
        .iter()
        .all(|c| holds(&net, silent, f1, *c) && holds(&net, honest, f1, *c)));
    // Node 2 never answers node 1; node 3's chunk replies to node 1 wait,
    // and its chunk requests never arrive.
    net.gate.rules.extend([
        (silent, asker, MessageType::ChunkReply, None),
        (partial, asker, MessageType::ChunkReply, None),
        (partial, asker, MessageType::ChunkRequest, None),
    ]);
    net.connect(asker, silent);
    let t0 = net.now;
    assert_eq!(requested(&net, asker, silent), vec![h], "node 2 holds h");
    net.connect(asker, partial);
    assert_eq!(
        requested(&net, asker, partial),
        vec![j, p],
        "node 3 holds j and p"
    );
    net.connect(asker, honest);
    assert!(
        requested(&net, asker, honest).is_empty(),
        "nothing free for node 4"
    );
    // Node 3 writes eight chunks in folder two; its push of the records
    // waits too.
    net.gate
        .rules
        .push((partial, asker, MessageType::IndexRecords, None));
    let eight: Vec<u8> = (0..8 * 1024usize).map(|b| (b * 7 % 251) as u8).collect();
    write_in(&mut net, partial, f2, "q.bin", &eight);
    // Its `CHUNK_NOT_FOUND` for j and the records, in one message: folder
    // two's passes run first and fill its room.
    let refusal_and_records = |f: &Frame| {
        f.kind() == FrameKind::Known(MessageType::IndexRecords) || chunk_hash(f) == Some(j)
    };
    assert!(net.deliver(partial, asker, refusal_and_records) >= 2);
    net.gate.rules.retain(|r| r.2 != MessageType::IndexRecords);
    // Its other answers, as they come: each drives one folder's passes.
    for _ in 0..20 {
        let is_reply = |f: &Frame| f.kind() == FrameKind::Known(MessageType::ChunkReply);
        if net.deliver(partial, asker, is_reply) == 0 {
            break;
        }
    }
    // From here node 3 answers as it is asked.
    net.gate
        .rules
        .retain(|r| (r.0, r.2) != (partial, MessageType::ChunkReply));
    assert!(!holds(&net, asker, f1, h));
    let wait = crate::inflight::patience(&Timing::SPEC);
    let deadline = t0 + 2 * wait.as_nanos() as u64;
    net.advance(Duration::from_nanos(deadline - net.now));
    assert!(
        holds(&net, asker, f1, h),
        "fetched within two patiences; asked node 4 for {:?}",
        requested(&net, asker, honest)
    );
    assert_eq!(net.nodes[asker].engine.counters().internal_errors, 0);
}

/// Node 3 writes x.bin, and node 2, which met node 1 first, asks node 1 for
/// its chunk; node 1, a read holder, never answers for it when `silent`
/// and answers everything else. Node 0 then writes y.bin and goes before
/// anyone fetched its chunk, so node 2 asks node 3 for y, which node 3 lacks
/// too, and node 3's pass waits for a trigger. Returns whether node 2 holds
/// x.bin `minutes` later, and the requests for x it sent nodes 1 and 3.
fn behind_a_waiting_pass(minutes: u64, silent: bool) -> (bool, usize, usize) {
    let (x_content, y_content) = (vec![7u8; 500], vec![8u8; 500]);
    let x = seal_chunk(&write_key(1).chunk_keys(), &x_content)
        .unwrap()
        .cipher_hash;
    let tier = |n: u8, t: u8| config(n, vec![folder_key(1, t)]);
    let mut net = Net::new(vec![tier(0, 1), tier(1, 2), tier(2, 1), tier(3, 1)]);
    if silent {
        net.gate
            .rules
            .push((1, 2, MessageType::ChunkReply, Some(x)));
    }
    net.connect(1, 2);
    net.connect(3, 2);
    net.advance(Duration::from_secs(2));
    let x_record = write(&mut net, 3, "x.bin", &x_content).unwrap();
    assert_eq!(first_chunk(&net, 3, x_record), x);
    net.advance(Duration::from_secs(10));
    net.gate.rules.extend([
        (0, 2, MessageType::ChunkReply, None),
        (0, 3, MessageType::ChunkReply, None),
    ]);
    net.connect(0, 2);
    net.connect(0, 3);
    net.advance(Duration::from_secs(2));
    let y_record = write(&mut net, 0, "y.bin", &y_content).unwrap();
    net.advance(Duration::from_secs(1));
    net.disconnect(0, 2);
    net.disconnect(0, 3);
    assert!(read(&net, 2, y_record).is_err() && read(&net, 3, y_record).is_err());
    net.advance(Duration::from_secs(minutes * 60));
    assert!([1, 3]
        .map(PeerId::new)
        .iter()
        .all(|p| net.nodes[2].cx.connected.contains(p)));
    let asked = |to| requested(&net, 2, to).iter().filter(|c| **c == x).count();
    (read(&net, 2, x_record) == Ok(x_content), asked(1), asked(3))
}

#[test]
fn a_chunk_comes_from_an_honest_holder_whose_pass_waits_when_nobody_withholds_it() {
    // The control for the residual below.
    let (fetched, to_1, to_3) = behind_a_waiting_pass(5, false);
    assert!(fetched, "asked node 1 {to_1}, node 3 {to_3}");
}

#[test]
#[ignore = "residual (TM-22): a holder whose pass waits for a trigger is never asked, so one silent \
            peer keeps the chunk from it in a quiet folder; a third pass trigger closes it next"]
fn one_silent_peer_keeps_a_chunk_from_an_honest_holder_whose_pass_waits() {
    // The security review's probe P1: in an hour node 2 asks node 3 for x
    // not once, its pass waiting after node 3's `CHUNK_NOT_FOUND` for y.
    let (fetched, to_1, to_3) = behind_a_waiting_pass(60, true);
    assert!(fetched, "asked node 1 {to_1}, node 3 {to_3}");
}

/// The bases on node `i`'s disk at `path`, and the records it holds.
fn disk_and_records(
    net: &Net,
    i: usize,
    path: &str,
) -> (Vec<(Place, RecordHash)>, Vec<RecordHash>) {
    let n = &net.nodes[i].engine;
    let bases = file(net, i, path).map(|v| v.bases).unwrap_or_default();
    let records = n
        .folder(&folder())
        .unwrap()
        .records
        .iter()
        .map(|r| r.hash)
        .collect();
    (bases, records)
}

#[test]
fn a_rename_of_a_path_to_itself_counts_no_engine_bug() {
    // Engine mutants batch 1 reviews, the bug: a rename onto its own path
    // built a version and a tombstone at that one path, which the index
    // refuses as one path twice in a batch (`WriteError::DuplicatePath`), so
    // the caller's mistake came back as `Internal` and counted an engine bug.
    // It is refused up front, as the caller's, and writes nothing.
    let mut net = Net::new(vec![key_config(0)]);
    let f = folder();
    let a = write(&mut net, 0, "a.txt", b"a").unwrap();
    let before = disk_and_records(&net, 0, "a.txt");
    assert_eq!(before.0, vec![(Place::Path, a)]);
    assert_eq!(
        net.with(0, |e, cx| e.rename(cx, f, "a.txt", "a.txt", 1)),
        Err(WriteFailure::RenameOntoItself)
    );
    assert_eq!(net.nodes[0].engine.counters().internal_errors, 0);
    assert_eq!(
        disk_and_records(&net, 0, "a.txt"),
        before,
        "nothing written"
    );
}

#[test]
fn a_rename_between_a_path_and_one_of_its_conflict_copies_counts_no_engine_bug() {
    // The same bug, found by reading. A rename writes each of its paths over
    // the heads on the disk there, so it first writes each conflict copy
    // beside either path as a version at the copy's name (4.4, "What becomes
    // of a conflict copy"). Renamed onto one of its copies' names, the path's
    // version and the copy's met at that name; a file written at a copy's
    // name and renamed onto the copy's path met the copy's version with its
    // tombstone. Each was `Internal`, an engine bug counted; each is refused
    // up front, as the caller's, and writes nothing.
    let (mut net, _, _) = conflict();
    let f = folder();
    let copy = file(&net, 0, "f.txt").unwrap().conflict_copies[0];
    let name = copy_name("f.txt", &copy);
    let before = disk_and_records(&net, 0, "f.txt");
    assert!(
        before.0.contains(&(Place::Copy(name.clone()), copy)),
        "the copy is on node 0's disk"
    );
    assert_eq!(
        net.with(0, |e, cx| e.rename(cx, f, "f.txt", &name, 9)),
        Err(WriteFailure::RenameOntoItself),
        "onto the copy's name"
    );
    assert_eq!(
        disk_and_records(&net, 0, "f.txt"),
        before,
        "nothing written"
    );
    assert_eq!(
        net.with(0, |e, cx| e.rename(cx, f, &name, "f.txt", 9)),
        Err(WriteFailure::RenameOntoItself),
        "from the copy's name onto its path, with nothing written at the name: checked before \
         NoSuchPath, since the copy is no file of its own until a write over the path"
    );
    assert_eq!(
        disk_and_records(&net, 0, "f.txt"),
        before,
        "nothing written"
    );
    write(&mut net, 0, &name, b"named as the copy").unwrap();
    let before = disk_and_records(&net, 0, "f.txt");
    assert_eq!(
        net.with(0, |e, cx| e.rename(cx, f, &name, "f.txt", 9)),
        Err(WriteFailure::RenameOntoItself),
        "from the copy's name onto its path"
    );
    assert_eq!(
        disk_and_records(&net, 0, "f.txt"),
        before,
        "nothing written"
    );
    assert_eq!(net.nodes[0].engine.counters().internal_errors, 0);
}

#[test]
fn a_rename_between_two_paths_whose_conflict_copies_share_a_name_counts_no_engine_bug() {
    // The security review of the rename fix: a rename first writes each
    // conflict copy beside either of its paths as a version at the copy's
    // name, so a copy beside each path under one name met at that name
    // (`WriteError::DuplicatePath`): `Internal`, an engine bug counted.
    // Phase 0's copy names hold the whole path, so no two paths' copies
    // share one; a shortened name could. The slot beside `g.txt` is planted.
    let (mut net, _, _) = conflict();
    let f = folder();
    let copy = file(&net, 0, "f.txt").unwrap().conflict_copies[0];
    let name = copy_name("f.txt", &copy);
    let g = write(&mut net, 0, "g.txt", b"g").unwrap();
    let index = &mut net.nodes[0].engine.folders.get_mut(&f).unwrap().index;
    let mut txn = index.begin();
    txn.set_base("g.txt", Place::Copy(name.clone()), Some(g))
        .unwrap();
    let (_, pending) = txn.finish();
    pending.commit();
    let before = [
        disk_and_records(&net, 0, "f.txt"),
        disk_and_records(&net, 0, "g.txt"),
    ];
    assert!(before[0].0.contains(&(Place::Copy(name.clone()), copy)));
    assert!(
        before[1].0.contains(&(Place::Copy(name), g)),
        "the planted slot"
    );
    assert_eq!(
        net.with(0, |e, cx| e.rename(cx, f, "f.txt", "g.txt", 9)),
        Err(WriteFailure::RenameOntoItself)
    );
    assert_eq!(net.nodes[0].engine.counters().internal_errors, 0);
    let after = [
        disk_and_records(&net, 0, "f.txt"),
        disk_and_records(&net, 0, "g.txt"),
    ];
    assert_eq!(after, before, "nothing written");
}
