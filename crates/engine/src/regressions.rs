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

use licketysync_keys::{CipherHash, FolderId, RecordHash};
use licketysync_protocol::frame::{Frame, MessageType};

use crate::config::EngineConfig;
use crate::issues::{IssueClass, IssueKind, StoreFailureCause, Subject};
use crate::runtime::{PeerId, Storage};
use crate::store::{chunk_key, held_key};
use crate::testkit::{config, folder_key, Hold, Net};
use crate::tests::{folder, pair, state, write};
use crate::FolderState;

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
