// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The rules of `protocol.md` 4.7 ("What the engine needs") and section 5
//! that the other tests do not pin, one test each, named by the rule: the
//! pending-free list, the chunk book and the bases of what arrives (item 1),
//! the store-failure pause and the failed commit (item 4, section 5, "Store
//! failure"), the bases and conflicts of a write (item 6), and phase 0's
//! clock rule, which the code keeps until phase 1 removes it.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code"
)]

use core::time::Duration;

use licketysync_keys::{CipherHash, RecordHash};
use licketysync_protocol::frame::MessageType;

use crate::inspect::{FileView, Place};
use crate::issues::IssueKind;
use crate::runtime::Peer as _;
use crate::sync::disk::copy_name;
use crate::testkit::{config, folder_key, FakeStorage, Hold, Net};
use crate::tests::{engine_over, folder, pair, state, write};
use crate::{FolderState, WriteFailure};

fn chunks_of(net: &Net, i: usize, record: &RecordHash) -> Vec<CipherHash> {
    net.nodes[i]
        .engine
        .folder(&folder())
        .unwrap()
        .records
        .iter()
        .find(|r| r.hash == *record)
        .map(|r| r.chunks.iter().map(|c| c.cipher_hash).collect())
        .unwrap_or_default()
}

fn stored(net: &Net, i: usize, hash: &CipherHash) -> bool {
    let v = net.nodes[i].engine.folder(&folder()).unwrap();
    v.stored_chunks.contains(hash)
}

fn pending(net: &Net, i: usize, hash: &CipherHash) -> bool {
    let v = net.nodes[i].engine.folder(&folder()).unwrap();
    v.pending_free.contains(hash)
}

fn file(net: &Net, i: usize, path: &str) -> Option<FileView> {
    net.nodes[i]
        .engine
        .files(&folder())
        .into_iter()
        .find(|f| f.path == path)
}

fn heads(f: &FileView) -> Vec<RecordHash> {
    let mut h: Vec<RecordHash> = f.heads.iter().map(|h| h.hash).collect();
    h.sort_unstable();
    h
}

/// A pair over which node 0 wrote `a.bin` twice: the first version's chunk
/// is left unnamed on both.
fn dropped_version() -> (Net, CipherHash) {
    let mut net = pair();
    let v1 = write(&mut net, 0, "a.bin", &[1u8; 3000]).unwrap();
    net.advance(Duration::from_secs(3));
    let c1 = chunks_of(&net, 1, &v1)[0];
    assert!(stored(&net, 1, &c1));
    write(&mut net, 0, "a.bin", &[2u8; 3000]).unwrap();
    net.advance(Duration::from_secs(3));
    for i in 0..2 {
        assert!(
            pending(&net, i, &c1),
            "node {i}: listed in the dropping commit"
        );
        assert!(stored(&net, i, &c1), "node {i}: and still stored");
    }
    (net, c1)
}

#[test]
fn a_chunk_left_unnamed_waits_on_the_pending_free_list_until_a_round_ends() {
    // Item 1: freed at the end of the next round on a connection where the
    // folder is open. Rounds start at open and when owed (4.5), so a quiet
    // connection ends none: the chunk stays listed until the rounds of a
    // reconnect end.
    let (mut net, c1) = dropped_version();
    net.advance(Duration::from_secs(120));
    assert!(
        pending(&net, 1, &c1),
        "no round ended, so nothing was freed"
    );
    net.disconnect(0, 1);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    for i in 0..2 {
        assert!(!pending(&net, i, &c1) && !stored(&net, i, &c1), "node {i}");
    }
}

#[test]
fn with_no_connection_open_the_pending_free_list_goes_within_a_minute() {
    // Item 1: "or, when no connection is open, once a minute".
    let (mut net, c1) = dropped_version();
    net.disconnect(0, 1);
    assert!(pending(&net, 1, &c1));
    net.advance(Duration::from_secs(61));
    for i in 0..2 {
        assert!(!pending(&net, i, &c1) && !stored(&net, i, &c1), "node {i}");
    }
}

#[test]
fn a_chunk_named_again_before_its_free_stays() {
    // Item 1: "one whose count rose again stays", and need not travel
    // twice.
    let (mut net, c1) = dropped_version();
    let v3 = write(&mut net, 0, "b.bin", &[1u8; 3000]).unwrap();
    net.advance(Duration::from_secs(3));
    assert!(
        chunks_of(&net, 1, &v3).contains(&c1),
        "the same content, the same chunk"
    );
    net.disconnect(0, 1);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    for i in 0..2 {
        assert!(stored(&net, i, &c1) && !pending(&net, i, &c1), "node {i}");
        let n = &net.nodes[i];
        let bytes = n.engine.read_file(&n.cx.storage, &folder(), &v3).unwrap();
        assert_eq!(bytes, vec![1u8; 3000]);
    }
}

#[test]
fn an_open_finishes_the_pending_free_list_before_the_folder_syncs() {
    // Item 1: "an open finishes whatever it lists before the folder syncs".
    let (mut net, c1) = dropped_version();
    net.restart(1, config(1, vec![folder_key(1, 1)]));
    assert!(!pending(&net, 1, &c1) && !stored(&net, 1, &c1));
}

/// A pair in conflict at `f.txt`: node 0 wrote V1, then V2, whose chunk node
/// 1 had not yet when it wrote its own edit over V1, its base. Returns V2 and
/// the edit, once both are on both disks.
fn conflict() -> (Net, RecordHash, RecordHash) {
    let mut net = pair();
    let v1 = write(&mut net, 0, "f.txt", &[1u8; 2000]).unwrap();
    net.advance(Duration::from_secs(3));
    net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
    let v2 = write(&mut net, 0, "f.txt", &[2u8; 2000]).unwrap();
    net.advance(Duration::from_secs(3));
    let f = file(&net, 1, "f.txt").unwrap();
    assert_eq!(heads(&f), vec![v2], "node 1 holds V2, which covers V1");
    assert_eq!(
        f.bases,
        vec![(Place::Path, v1)],
        "V2 is not on node 1's disk: the old file stays, V1 its base"
    );
    let mine = write(&mut net, 1, "f.txt", &[3u8; 2000]).unwrap();
    net.release();
    net.advance(Duration::from_secs(5));
    (net, v2, mine)
}

#[test]
fn a_version_still_arriving_stays_a_head_beside_a_local_write_and_the_old_file_stays() {
    // Item 6, Bases, and item 1: until V2's content is on node 1's disk, V1
    // stays the base at the path and the file there as it was; node 1's own
    // edit is built from V1 and its twins, of which V2 is none, whatever its
    // content: it covers V1, a later version (4.4, "Bases"). So V2 and the
    // edit are both heads, a conflict, never one written over the other
    // (4.4, "Why it is safe" 9).
    let (net, v2, mine) = conflict();
    let mut want = vec![v2, mine];
    want.sort_unstable();
    for i in 0..2 {
        let f = file(&net, i, "f.txt").unwrap();
        assert_eq!(heads(&f), want, "node {i}: both heads");
        assert_eq!(f.conflict_copies.len(), 1, "node {i}");
        let copy = f.conflict_copies[0];
        assert!(
            f.bases
                .contains(&(Place::Copy(copy_name("f.txt", &copy)), copy)),
            "node {i}: the copy is on the disk beside the path"
        );
    }
}

#[test]
fn a_write_over_a_conflict_turns_each_copy_into_an_ordinary_file() {
    // Item 6, Conflicts: the write first writes each conflict copy on the
    // disk as a version at its own path, in the same commit, and covers both
    // heads (4.4, "What becomes of a conflict copy").
    let (mut net, v2, _) = conflict();
    let copy = file(&net, 0, "f.txt").unwrap().conflict_copies[0];
    let name = copy_name("f.txt", &copy);
    let content = if copy == v2 { [2u8; 2000] } else { [3u8; 2000] };
    let v4 = write(&mut net, 0, "f.txt", &[4u8; 2000]).unwrap();
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        assert_eq!(
            heads(&file(&net, i, "f.txt").unwrap()),
            vec![v4],
            "node {i}"
        );
        let c = file(&net, i, &name).unwrap();
        assert_eq!(c.heads.len(), 1, "node {i}: an ordinary file");
        let n = &net.nodes[i];
        let bytes = n
            .engine
            .read_file(&n.cx.storage, &folder(), &c.heads[0].hash)
            .unwrap();
        assert_eq!(bytes, content.to_vec(), "node {i}: the copy's content");
    }
}

/// Seconds in 400 days: past the one-year clock rule.
const PAST_THE_RULE: u64 = 400 * 86_400;

#[test]
fn the_clock_rule_issue_is_raised_though_the_close_comes_with_it() {
    // Item 6, the clock rule: the two Hellos are compared when the first
    // folder opens, and a peer out of range is refused with the issue. The
    // bug: the event came in the output that closed the connection, and the
    // engine dropped it with the connection's other events.
    let mut net = Net::new(vec![
        config(0, vec![folder_key(1, 1)]),
        config(1, vec![folder_key(1, 1)]),
    ]);
    net.nodes[1].cx.wall += PAST_THE_RULE;
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    for i in 0..2 {
        let e = &net.nodes[i].engine;
        assert!(
            e.issues()
                .list()
                .iter()
                .any(|x| x.kind == IssueKind::ClockOutOfRange),
            "node {i}: {:?}",
            e.issues()
        );
        assert_ne!(state(&net, i), FolderState::UpToDate, "node {i}");
    }
}

#[test]
fn a_stranger_out_of_the_clock_rule_is_only_counted() {
    // 3.2: a connection that ends with no folder opened and clocks out of
    // range is counted, with no issue (the same bug as above, at the close).
    let mut net = Net::new(vec![
        config(0, vec![folder_key(1, 1)]),
        config(1, vec![folder_key(2, 1)]),
    ]);
    net.nodes[1].cx.wall += PAST_THE_RULE;
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    net.disconnect(0, 1);
    for i in 0..2 {
        let e = &net.nodes[i].engine;
        assert_eq!(e.counters().stranger_clocks, 1, "node {i}");
        assert!(
            e.issues()
                .list()
                .iter()
                .all(|x| x.kind != IssueKind::ClockOutOfRange),
            "node {i}"
        );
    }
}

#[test]
fn a_record_from_the_future_is_refused_with_the_issue_naming_its_device() {
    // Item 2, "from the future (verified, refused, the clock-rule issue)":
    // node 0's clock jumps past the rule after the handshake.
    let mut net = pair();
    net.nodes[0].cx.wall += PAST_THE_RULE;
    let r = write(&mut net, 0, "f.txt", b"later").unwrap();
    net.advance(Duration::from_secs(3));
    let e = &net.nodes[1].engine;
    let v = e.folder(&folder()).unwrap();
    assert!(v.records.iter().all(|x| x.hash != r), "refused");
    assert!(
        e.issues()
            .list()
            .iter()
            .any(|x| x.kind == IssueKind::FromTheFuture
                && matches!(x.subject, crate::issues::Subject::Device(_))),
        "{:?}",
        e.issues()
    );
}

/// A node whose folder holds a record dated 400 days ahead of its clock,
/// restarted with its clock back: kept closed for 35 days. Node `i` of a
/// net of `n`, the others' clocks `ahead` seconds ahead of it.
fn closed_net(n: usize, ahead: u64) -> Net {
    let configs = (0..n)
        .map(|i| config(u8::try_from(i).unwrap(), vec![folder_key(1, 1)]))
        .collect();
    let mut net = Net::new(configs);
    for i in 1..n {
        net.nodes[i].cx.wall += ahead;
    }
    net.nodes[0].cx.wall += PAST_THE_RULE;
    write(&mut net, 0, "f.txt", b"ahead").unwrap();
    net.nodes[0].cx.wall -= PAST_THE_RULE;
    net.restart(0, config(0, vec![folder_key(1, 1)]));
    net
}

/// Days of the lead past a year that `closed_net` leaves, plus one.
const STEP: u64 = 36 * 86_400;

#[test]
fn a_folder_whose_records_lie_more_than_a_year_ahead_stays_closed_and_opens_by_itself() {
    // Item 8 and 4.4, "A clock set back": kept closed while its records lie
    // more than a year ahead of the clock, held paused meanwhile (no write,
    // no round), with the clock-rule issue and the open report saying so,
    // and opened once the clock reaches the time the open gave.
    let mut net = closed_net(1, 0);
    let FolderState::Closed { opens_at_us } = state(&net, 0) else {
        panic!("not closed: {:?}", state(&net, 0));
    };
    let now_us = net.nodes[0].cx.wall * 1_000_000;
    let days = (opens_at_us - now_us) / 86_400_000_000;
    assert_eq!(days, 35, "the record's lead past a year");
    let e = &net.nodes[0].engine;
    assert!(
        e.folder(&folder()).unwrap().open.kept_closed,
        "the open report says so"
    );
    assert!(
        e.issues()
            .list()
            .iter()
            .any(|i| i.kind == IssueKind::KeptClosed && i.folder == Some(folder())),
        "{:?}",
        e.issues()
    );
    assert_eq!(write(&mut net, 0, "g.txt", b"g"), Err(WriteFailure::Paused));
    net.nodes[0].cx.wall += STEP;
    net.advance(Duration::from_secs(STEP));
    assert!(
        !matches!(state(&net, 0), FolderState::Closed { .. }),
        "{:?}",
        state(&net, 0)
    );
    assert!(write(&mut net, 0, "g.txt", b"g").is_ok());
}

#[test]
fn a_closed_folder_opens_when_its_wall_clock_steps_forward_without_monotonic_time() {
    // EP-1, the bug: the open's time was turned into a monotonic delay, so a
    // clock set right by stepping it forward kept the folder closed until
    // that delay ran out. The wall clock is compared every handler, and the
    // timer looks at least once a minute.
    let mut net = closed_net(1, 0);
    net.nodes[0].cx.wall += STEP;
    net.advance(Duration::from_secs(61));
    assert!(
        !matches!(state(&net, 0), FolderState::Closed { .. }),
        "still closed a minute after the clock passed its time: {:?}",
        state(&net, 0)
    );
    // And at once in any handler, here a write.
    let mut net = closed_net(1, 0);
    net.nodes[0].cx.wall += STEP;
    assert!(write(&mut net, 0, "g.txt", b"g").is_ok());
}

#[test]
fn a_closed_folder_is_not_proven_to_peers_and_is_proven_once_it_opens() {
    // EP-2, 4.4: while kept closed the folder counts as paused for folder
    // proofs: not proven, the peer's proof answered REJECTED, nothing
    // received. Once it opens, its credential is back; a peer that proved it
    // on the connection already does not prove it again there (3.5), so it
    // syncs on the next one. Node 1's clock runs 36 days ahead, so that the
    // records are within its year.
    let mut net = closed_net(2, STEP);
    assert!(!net.nodes[0].engine.folder(&folder()).unwrap().credentialed);
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    assert!(net.nodes[1].engine.counters().proofs_rejected >= 1);
    let one = net.nodes[1].engine.folder(&folder()).unwrap();
    assert_eq!(one.records.len(), 0, "nothing crossed while closed");
    assert!(!matches!(one.state, FolderState::UpToDate));
    net.nodes[0].cx.wall += STEP;
    net.advance(Duration::from_secs(61));
    assert!(net.nodes[0].engine.folder(&folder()).unwrap().credentialed);
    net.disconnect(0, 1);
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
    }
    assert_eq!(
        net.nodes[1].engine.folder(&folder()).unwrap().records.len(),
        1
    );
}

#[test]
fn a_tree_delete_received_clears_the_bases_beneath_its_directory() {
    // Item 6, Tree deletes: a tree delete received removes every file
    // beneath its directory with no live version left from the disk, and
    // becomes the directory's base.
    let mut net = pair();
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    let a = write(&mut net, 0, "d/a.txt", b"a").unwrap();
    let b = write(&mut net, 0, "d/b.txt", b"b").unwrap();
    net.advance(Duration::from_secs(3));
    let bases = |net: &Net, path: &str| net.nodes[1].engine.bases(&folder(), path);
    assert_eq!(bases(&net, "d/a.txt"), vec![(Place::Path, a)]);
    assert_eq!(bases(&net, "d/b.txt"), vec![(Place::Path, b)]);
    let deleted = net.with(0, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(3));
    assert_eq!(bases(&net, "d/a.txt"), vec![], "the file's base went");
    assert_eq!(bases(&net, "d/b.txt"), vec![]);
    assert_eq!(bases(&net, "d"), vec![(Place::Path, deleted)]);
}

#[test]
fn a_failed_commit_reports_held_records_skipped_and_its_round_is_not_caught_up() {
    // Item 4: a record this side could not keep is reported skipped, so the
    // round that brought it is not caught up and moves no cursor; the round
    // the resume owes brings it back.
    let mut net = pair();
    net.disconnect(0, 1);
    for i in 0..3u8 {
        write(&mut net, 0, &format!("f{i}.txt"), &[i; 10]).unwrap();
    }
    let device = net.nodes[0].engine.own;
    let cursor = |net: &Net| {
        let f = net.nodes[1].engine.folders.get(&folder()).unwrap();
        f.index.peer(&device).map(|p| p.cursor)
    };
    let before = cursor(&net);
    net.nodes[1].cx.storage.commit_fails = true;
    net.connect(0, 1);
    let one = &net.nodes[1].engine;
    let judged: Vec<_> = one
        .judged_log
        .iter()
        .flat_map(|(_, results)| results.iter())
        .collect();
    assert!(!judged.is_empty(), "pages were judged");
    assert!(
        judged.iter().all(|r| !matches!(r, Ok(j) if j.held())),
        "a record the failed commit lost was reported held: {judged:?}"
    );
    let conn = one.conns.get(&crate::runtime::PeerId::new(0)).unwrap();
    assert!(
        !conn.sync.caught_up(&folder()),
        "a round that skipped records"
    );
    assert_eq!(cursor(&net), before, "no cursor moved");
    assert!(matches!(state(&net, 1), FolderState::Paused(_)));
    net.nodes[1].cx.storage.commit_fails = false;
    net.advance(Duration::from_secs(15));
    assert_eq!(state(&net, 1), FolderState::UpToDate);
    assert_eq!(
        net.nodes[1].engine.folder(&folder()).unwrap().records.len(),
        3
    );
}

#[test]
fn a_failed_first_commit_pauses_the_folder_and_its_probe_handler_commits_once() {
    // R1's NITs b and c, the bugs: a failure staging what the open changed
    // paused no folder, so it synced with the open's work undone; and the
    // resume probe committed on its own, then phase B again in the same
    // handler. Now the folder pauses, the probe's commit is the handler's
    // one, and the open's changes commit in a handler of their own after.
    let storage = FakeStorage {
        fail_prefix: Some((b"e/m".to_vec(), 1)),
        ..FakeStorage::default()
    };
    let mut net = engine_over(storage);
    assert!(
        matches!(state(&net, 0), FolderState::Paused(_)),
        "{:?}",
        state(&net, 0)
    );
    let meta = |net: &Net| {
        net.nodes[0]
            .cx
            .storage
            .committed
            .keys()
            .any(|k| k.starts_with(b"e/m/"))
    };
    assert!(!meta(&net));
    let n = &mut net.nodes[0];
    let probe = *n.cx.timers.keys().next().unwrap();
    n.cx.timers.remove(&probe);
    let before = n.cx.storage.commits;
    n.engine.on_timer(&mut n.cx, probe);
    assert_eq!(
        n.cx.storage.commits - before,
        1,
        "one commit in the probe's handler"
    );
    net.advance(Duration::from_millis(10));
    assert!(meta(&net), "the open's changes committed after the resume");
    assert!(!matches!(state(&net, 0), FolderState::Paused(_)));
}

#[test]
fn a_blob_forgotten_after_a_read_error_is_read_again_and_served() {
    // The security review's NIT 4, the bug (probe P8): a blob that could not
    // be read was forgotten, and nothing read it again before a restart, so
    // its only holder could not serve it. It is read again, hash-checked, on
    // the free tick.
    let mut net = pair();
    net.nodes[0].cx.storage.get_fails = true;
    let r = write(&mut net, 0, "a.bin", &[7u8; 2000]).unwrap();
    net.nodes[0].cx.storage.get_fails = false;
    net.advance(Duration::from_secs(1));
    let read = |net: &Net| {
        let n = &net.nodes[1];
        n.engine.read_file(&n.cx.storage, &folder(), &r)
    };
    assert!(read(&net).is_err(), "node 0 could not serve it");
    net.advance(Duration::from_secs(120));
    assert_eq!(read(&net), Ok(vec![7u8; 2000]));
}

#[test]
fn holding_a_tree_delete_reads_what_it_drops_not_the_twenty_thousand_files_left_beneath_it() {
    // The security review's EP-S1 and CS-1 (TM-22), the bug: holding a tree
    // delete walked every path of the folder, then (EP-S1's first fix) every
    // path and base slot beneath its directory, 260 ms a tree delete at
    // 20 000 files it does not cover. It reads now only the paths where it
    // dropped records, and their slots. Node 1 holds 20 000 files beneath
    // `w3` that node 0 never saw; node 0 makes `w3` and deletes it, so its
    // tree delete drops node 0's one directory record there and nothing else.
    let mut storage = FakeStorage::default();
    crate::tests::store_records(&mut storage, crate::testkit::records_of(1, 3, 20_000));
    let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
    let mut n = crate::testkit::Node {
        engine: crate::Engine::new(config(1, vec![folder_key(1, 1)])).unwrap(),
        cx: crate::testkit::FakeCx {
            id: 1,
            wall: 1_767_225_600,
            rng: 1,
            storage,
            ..crate::testkit::FakeCx::default()
        },
    };
    n.engine.on_start(&mut n.cx);
    net.nodes.push(n);
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "w3", 0)).unwrap();
    net.with(0, |e, cx| e.delete(cx, f, "w3", 0)).unwrap();
    // Node 0 never takes node 1's 20 000 records.
    net.hold = Some(Hold::new(1, 0, MessageType::IndexRecords));
    let before = net.nodes[1].engine.counters.paths_applied;
    net.connect(0, 1);
    net.advance(Duration::from_secs(3));
    let one = &net.nodes[1].engine;
    assert!(one.files(&f).len() >= 20_000, "the files beneath survive");
    let read = one.counters.paths_applied - before;
    assert!(read > 0, "the tree delete was held");
    assert!(
        read <= 4,
        "{read} paths and slots read for a tree delete that dropped one"
    );
}

#[test]
fn a_tree_delete_leaves_the_disk_of_a_concurrent_edit_beneath_it_and_its_next_edit_covers_it() {
    // EP-6, the bug: holding a tree delete cleared every base beneath its
    // directory, the base of a file it does not cover too. Node 2 has V1 of
    // d/x on its disk and holds node 1's concurrent edit E, whose content
    // has not arrived, when node 0's tree delete of d (which covers V1, not
    // E) arrives: the old file stays until E's content is there, and node
    // 2's next edit of d/x then covers E, with no conflict.
    let mut net = Net::new((0..3).map(|i| config(i, vec![folder_key(1, 1)])).collect());
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        net.connect(a, b);
    }
    net.advance(Duration::from_secs(2));
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    let v1 = write(&mut net, 0, "d/x.txt", &[1u8; 1500]).unwrap();
    net.advance(Duration::from_secs(3));
    assert_eq!(
        net.nodes[2].engine.bases(&f, "d/x.txt"),
        vec![(Place::Path, v1)]
    );
    net.disconnect(0, 1);
    net.disconnect(0, 2);
    net.disconnect(1, 2);
    let e = write(&mut net, 1, "d/x.txt", &[2u8; 1500]).unwrap();
    net.with(0, |eng, cx| eng.delete(cx, f, "d", 0)).unwrap();
    // E's record, then the tree delete, reach node 2; E's content does not.
    net.hold = Some(Hold::new(1, 2, MessageType::ChunkReply));
    net.connect(1, 2);
    net.advance(Duration::from_secs(2));
    net.connect(0, 2);
    net.advance(Duration::from_secs(2));
    let two = |net: &Net| net.nodes[2].engine.bases(&f, "d/x.txt");
    assert!(
        net.nodes[2]
            .engine
            .files(&f)
            .iter()
            .any(|v| v.path == "d/x.txt" && v.heads.iter().any(|h| h.hash == e)),
        "E survives the tree delete"
    );
    assert_eq!(
        two(&net),
        vec![(Place::Path, v1)],
        "the old file stays until E's content is there"
    );
    net.release();
    net.advance(Duration::from_secs(40));
    assert_eq!(two(&net), vec![(Place::Path, e)]);
    let later = write(&mut net, 2, "d/x.txt", &[3u8; 1500]).unwrap();
    net.advance(Duration::from_secs(3));
    let heads = file(&net, 2, "d/x.txt").unwrap().heads;
    assert_eq!(
        heads.iter().map(|h| h.hash).collect::<Vec<_>>(),
        vec![later],
        "no conflict"
    );
}

#[test]
fn nested_tree_deletes_made_at_once_leave_the_same_disk_in_either_order() {
    // CF-4, the bug: holding a tree delete of `d` cleared every slot
    // beneath it left with no head, the slot of a tree delete of `d/e`
    // still held among them, so a device that held `d/e`'s first kept no
    // base there and one that held `d`'s first kept `d/e`'s: two disks for
    // the same records. Node 0 deletes `d/e` while node 1 deletes `d`; each
    // receives the other's.
    let mut net = pair();
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    net.with(0, |e, cx| e.mkdir(cx, f, "d/e", 0)).unwrap();
    write(&mut net, 0, "d/e/f.txt", b"f").unwrap();
    write(&mut net, 0, "d/g.txt", b"g").unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 1);
    let inner = net.with(0, |e, cx| e.delete(cx, f, "d/e", 0)).unwrap();
    let outer = net.with(1, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    let disk = |i: usize| net.nodes[i].engine.bases_beneath(&f, "");
    assert_eq!(disk(0), disk(1), "the same disk on both");
    assert!(disk(0).contains(&("d/e".to_owned(), Place::Path, inner)));
    assert!(disk(0).contains(&("d".to_owned(), Place::Path, outer)));
}

/// A pair where node 1 holds V1 of `f.txt` on its disk and V2's record,
/// whose chunk is held back from it. Returns V1 and V2.
fn second_version_held_back() -> (Net, RecordHash, RecordHash) {
    let mut net = pair();
    let v1 = write(&mut net, 0, "f.txt", &[1u8; 1500]).unwrap();
    net.advance(Duration::from_secs(3));
    net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
    let v2 = write(&mut net, 0, "f.txt", &[2u8; 1500]).unwrap();
    net.advance(Duration::from_secs(3));
    assert_eq!(
        net.nodes[1].engine.bases(&folder(), "f.txt"),
        vec![(Place::Path, v1)]
    );
    (net, v1, v2)
}

#[test]
fn a_failed_commit_never_leaves_a_paths_base_old_for_good() {
    // CS-3, the bug (probe P3b): V2's chunk arrived in a handler whose
    // commit failed; its transaction had taken `f.txt` off the paths still
    // to apply, and the rollback did not put it back, so once the store
    // recovered and the chunk came again the base stayed V1 for good and
    // the next edit was a spurious conflict with V2.
    let (mut net, _, v2) = second_version_held_back();
    net.nodes[1].cx.storage.commit_fails = true;
    net.release();
    assert!(matches!(state(&net, 1), FolderState::Paused(_)));
    net.nodes[1].cx.storage.commit_fails = false;
    net.advance(Duration::from_secs(40));
    assert_eq!(
        net.nodes[1].engine.bases(&folder(), "f.txt"),
        vec![(Place::Path, v2)]
    );
    let v3 = write(&mut net, 1, "f.txt", &[3u8; 1500]).unwrap();
    net.advance(Duration::from_secs(3));
    for i in 0..2 {
        assert_eq!(
            heads(&file(&net, i, "f.txt").unwrap()),
            vec![v3],
            "node {i}: no conflict"
        );
    }
}

#[test]
fn a_version_whose_chunk_a_failed_commit_rolled_back_is_not_on_the_disk() {
    // CS-2: a position that verified stays verified after its chunk is
    // forgotten (rolled back with a failed commit, here), so the version
    // counted as on the disk with its chunk gone. It counts only while its
    // chunks are stored too: node 1's base stays V1 until V2's chunk comes
    // again.
    let (mut net, v1, v2) = second_version_held_back();
    net.nodes[1].cx.storage.commit_fails = true;
    net.release();
    net.nodes[1].cx.storage.commit_fails = false;
    // The chunk is held back again, so that the resume and the commits
    // after it run without it.
    net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
    net.advance(Duration::from_secs(5));
    assert!(!matches!(state(&net, 1), FolderState::Paused(_)), "resumed");
    assert_eq!(
        net.nodes[1].engine.bases(&folder(), "f.txt"),
        vec![(Place::Path, v1)],
        "V2 is not on the disk without its chunk"
    );
    net.release();
    net.advance(Duration::from_secs(40));
    assert_eq!(
        net.nodes[1].engine.bases(&folder(), "f.txt"),
        vec![(Place::Path, v2)]
    );
}

#[test]
fn a_blob_found_changed_when_read_again_raises_the_local_issue_and_is_deleted() {
    // The security review's CS-N2 (probe P4b): a blob that could not be
    // read, and is found changed when it is read again, is changed at rest:
    // the local issue, and its blob and marker deleted with the next commit
    // (no peer holds it here, so it is not fetched back). Without the
    // re-read's hash check it would count as stored.
    let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
    let r = write(&mut net, 0, "a.bin", &[5u8; 900]).unwrap();
    let chunk = chunks_of(&net, 0, &r)[0];
    let key = crate::store::chunk_key(&folder(), &chunk);
    // The restart judges every stored chunk again; this one's blob cannot
    // be read then.
    net.nodes[0].cx.storage.get_fail_prefix = Some(key.clone());
    net.restart(0, config(0, vec![folder_key(1, 1)]));
    assert!(!stored(&net, 0, &chunk), "forgotten after the read error");
    net.nodes[0].cx.storage.get_fail_prefix = None;
    net.nodes[0].cx.storage.flip(&key);
    net.advance(Duration::from_secs(61));
    let e = &net.nodes[0].engine;
    assert!(
        e.issues()
            .list()
            .iter()
            .any(|i| i.kind == IssueKind::LocalChunkCorrupt
                && i.subject == crate::issues::Subject::Chunk(chunk)),
        "{:?}",
        e.issues()
    );
    assert!(!stored(&net, 0, &chunk));
    write(&mut net, 0, "b.txt", b"another commit").unwrap();
    let committed = &net.nodes[0].cx.storage.committed;
    assert!(!committed.contains_key(&key), "the blob went");
    assert!(
        !committed.contains_key(&crate::store::held_key(&folder(), &chunk)),
        "and its marker"
    );
}

#[test]
fn a_page_of_duplicates_commits_nothing() {
    // The security review's NIT 5 (CS-N3): a handler whose change sets are
    // all empty makes no storage commit. Three nodes, settled, then one more
    // directory from node 0: node 1 relays it to node 2, which has it from
    // node 0 already, a page of one duplicate (its push counted, the cursor
    // that raises commits in a handler of its own after).
    let mut net = Net::new((0..3).map(|i| config(i, vec![folder_key(1, 1)])).collect());
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        net.connect(a, b);
    }
    net.advance(Duration::from_secs(2));
    let duplicates = |net: &Net| {
        net.nodes[2]
            .engine
            .counters
            .of(licketysync_protocol::Cause::Duplicate)
    };
    let before = duplicates(&net);
    for n in &mut net.nodes {
        n.cx.storage.commit_log.clear();
    }
    // Node 1's relay is held back until node 2 has committed all else, so
    // that the page of one duplicate is all its handler does.
    net.hold = Some(Hold::new(1, 2, MessageType::IndexRecords));
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "x", 0)).unwrap();
    net.advance(Duration::from_secs(2));
    let commits = net.nodes[2].cx.storage.commits;
    let refreshes = |net: &Net| {
        net.nodes[2]
            .engine
            .folders
            .get(&folder())
            .unwrap()
            .book
            .refreshes
    };
    let book_before = refreshes(&net);
    net.release();
    assert_eq!(
        refreshes(&net),
        book_before,
        "RS-N1: no chunk-book refresh for a page that held or dropped nothing"
    );
    assert!(
        duplicates(&net) > before,
        "the relay was a duplicate at node 2"
    );
    assert_eq!(
        net.nodes[2].cx.storage.commits, commits,
        "no commit for the page of duplicates"
    );
    for (i, n) in net.nodes.iter().enumerate() {
        assert!(
            n.cx.storage.commit_log.iter().all(|keys| !keys.is_empty()),
            "node {i} made an empty commit"
        );
    }
}

#[test]
fn a_paused_folder_serving_a_reset_claims_no_redraw() {
    // R1's NIT (a), CF-3 (a), the bug: a Since request whose `since` lies
    // above this side's local sequence under its own epoch is answered with
    // a reset that draws a new epoch; for a folder held paused that draw was
    // dropped with its transaction, yet the reset claimed it, spending the
    // connection's one redraw on nothing. Node 0 comes back from an older
    // copy of its store (the same epoch, fewer records) with its folder
    // paused.
    let mut net = pair();
    let snapshot = net.nodes[0].cx.storage.clone();
    write(&mut net, 0, "a.txt", b"a").unwrap();
    write(&mut net, 0, "b.txt", b"b").unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 1);
    net.nodes[0].cx.storage = snapshot;
    net.restart(0, config(0, vec![folder_key(1, 1)]));
    net.nodes[0].cx.storage.commit_fails = true;
    assert!(write(&mut net, 0, "c.txt", b"c").is_err());
    assert!(matches!(state(&net, 0), FolderState::Paused(_)));
    net.connect(0, 1);
    net.advance(Duration::from_millis(500));
    let resets = &net.nodes[0].engine.resets_log;
    assert!(!resets.is_empty(), "a reset was served");
    assert!(resets.iter().all(|(_, redrew)| !redrew), "{resets:?}");
}

#[test]
fn a_closed_folder_that_opens_before_the_peers_proof_arrives_syncs_without_a_reconnect() {
    // CF-3 (b): node 1's proof is in flight while node 0's folder is kept
    // closed; node 0 opens before it arrives and proves it on every
    // connection (`prove_everywhere`), and accepts the late proof with the
    // credential it now holds (3.5 step 6): the folder opens on that
    // connection and syncs with no reconnect. Either alone opens it here;
    // the case only `prove_everywhere` opens, both sides closed, is
    // `a_folder_both_devices_kept_closed_opens_when_the_second_proves_it`.
    let mut net = closed_net(2, STEP);
    net.hold = Some(Hold::new(1, 0, MessageType::FolderProof));
    net.connect(0, 1);
    net.advance(Duration::from_secs(1));
    // The clock is set right; node 0's next handler (a write) opens the
    // folder first, well inside the proof timeout.
    net.nodes[0].cx.wall += STEP;
    write(&mut net, 0, "g.txt", b"g").unwrap();
    assert!(net.nodes[0].engine.folder(&folder()).unwrap().credentialed);
    net.release();
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
        assert_eq!(net.nodes[i].engine.counters.internal_errors, 0, "node {i}");
    }
    assert_eq!(
        net.nodes[1].engine.folder(&folder()).unwrap().records.len(),
        2
    );
}

/// Every node's disk: its base slots, all of them.
fn disks(net: &Net) -> Vec<Vec<(String, Place, RecordHash)>> {
    (0..net.nodes.len())
        .map(|i| net.nodes[i].engine.bases_beneath(&folder(), ""))
        .collect()
}

#[test]
fn two_devices_deleting_one_directory_apart_keep_the_same_disk() {
    // RC-1, the bug (probe P1, the security review's case (a)): each device
    // named its own tree delete of `d` as `d`'s base and kept it beside the
    // other's, so two devices with the same records kept different disks.
    // At a path with no heads the base is the greatest tree delete held
    // there.
    let mut net = pair();
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    write(&mut net, 0, "d/g.txt", b"g").unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 1);
    let a = net.with(0, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    let b = net.with(1, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    let d = disks(&net);
    assert_eq!(d[0], d[1], "the same disk");
    assert!(d[0].contains(&("d".to_owned(), Place::Path, a.max(b))));
}

#[test]
fn three_devices_holding_nested_tree_deletes_keep_the_same_disk() {
    // RC-1 (probe P3): node 0 deletes d/p (TD_x); node 1 makes d/p, then
    // deletes d (TD_y, covering its d/p, not TD_x); node 2 has TD_x, then
    // node 1's d/p alone, then TD_y. All three hold the same records and
    // keep the same disk: d/p's base is TD_x, d's is TD_y.
    let mut net = Net::new((0..3).map(|i| config(i, vec![folder_key(1, 1)])).collect());
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        net.connect(a, b);
    }
    net.advance(Duration::from_secs(2));
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(3));
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        net.disconnect(a, b);
    }
    net.with(0, |e, cx| e.mkdir(cx, f, "d/p", 0)).unwrap();
    let tdx = net.with(0, |e, cx| e.delete(cx, f, "d/p", 0)).unwrap();
    net.connect(0, 2);
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 2);
    net.with(1, |e, cx| e.mkdir(cx, f, "d/p", 0)).unwrap();
    net.connect(1, 2);
    net.advance(Duration::from_secs(3));
    let tdy = net.with(1, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(3));
    net.connect(0, 1);
    net.connect(0, 2);
    net.advance(Duration::from_secs(40));
    let d = disks(&net);
    assert!(d[0] == d[1] && d[1] == d[2], "the same disk on all three");
    assert!(d[0].contains(&("d/p".to_owned(), Place::Path, tdx)));
    assert!(d[0].contains(&("d".to_owned(), Place::Path, tdy)));
}

#[test]
fn a_tree_delete_that_drops_a_record_at_a_nested_tree_deletes_path_keeps_the_disk_the_same() {
    // RC-1 (probe P5): node 0 deletes d/p (TD_x); node 1, never seeing it,
    // writes a file at d/p (R) and deletes d (TD_y, covering R, not TD_x).
    // Node 0 holds R (its content never arrives) when TD_y drops it; node 1
    // gets TD_x only after TD_y. Both keep TD_x as d/p's base.
    let mut net = pair();
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 1);
    net.with(0, |e, cx| e.mkdir(cx, f, "d/p", 0)).unwrap();
    let tdx = net.with(0, |e, cx| e.delete(cx, f, "d/p", 0)).unwrap();
    write(&mut net, 1, "d/p", &[7u8; 1500]).unwrap();
    net.hold = Some(Hold::new(0, 1, MessageType::IndexRecords));
    net.connect(0, 1);
    net.advance(Duration::from_secs(3));
    net.with(1, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(3));
    assert!(
        disks(&net)[0].contains(&("d/p".to_owned(), Place::Path, tdx)),
        "node 0 keeps TD_x at d/p after TD_y dropped R there"
    );
    net.release();
    net.advance(Duration::from_secs(40));
    let d = disks(&net);
    assert_eq!(d[0], d[1], "the same disk");
}

#[test]
fn nested_tree_deletes_arriving_in_one_handler_count_no_internal_error() {
    // RC-3, the bug (probe P8): node 0 deletes d/e, then d, which covers the
    // first; node 1 takes both in one handler, holds d/e's only until d's
    // drops it, and named it d/e's base after that, an internal error. Only
    // a tree delete still held is ever a base.
    let mut net = pair();
    let f = folder();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    net.with(0, |e, cx| e.mkdir(cx, f, "d/e", 0)).unwrap();
    write(&mut net, 0, "d/e/f.txt", b"f").unwrap();
    net.advance(Duration::from_secs(3));
    net.hold = Some(Hold::new(0, 1, MessageType::IndexRecords));
    net.with(0, |e, cx| e.delete(cx, f, "d/e", 0)).unwrap();
    net.with(0, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.release();
    net.advance(Duration::from_secs(5));
    assert_eq!(net.nodes[1].engine.counters.internal_errors, 0);
    let d = disks(&net);
    assert_eq!(d[0], d[1], "the same disk");
}

/// The security review's cases (b) and (c): A (node 0) makes the directory
/// d/e while C (node 1) writes a file d/e; D (node 2), holding both, deletes
/// d (T, covering both), and A deletes d/e (T', covering only its own). X
/// (node 3) receives C's file, its content only if `whole`, then T', then
/// T; Y (node 4) receives the file whole, then T, then T'. Returns the net,
/// T and T'.
fn file_and_nested_deletes(whole: bool) -> (Net, RecordHash, RecordHash) {
    let mut net = Net::new((0..5).map(|i| config(i, vec![folder_key(1, 1)])).collect());
    let f = folder();
    let pairs = [
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 4),
        (1, 2),
        (1, 3),
        (1, 4),
        (2, 3),
        (2, 4),
        (3, 4),
    ];
    for (a, b) in pairs {
        net.connect(a, b);
    }
    net.advance(Duration::from_secs(2));
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(3));
    for (a, b) in pairs {
        net.disconnect(a, b);
    }
    net.with(0, |e, cx| e.mkdir(cx, f, "d/e", 0)).unwrap();
    write(&mut net, 1, "d/e", &[8u8; 1500]).unwrap();
    let meet = |net: &mut Net, a: usize, b: usize, secs: u64| {
        net.connect(a, b);
        net.advance(Duration::from_secs(secs));
        net.disconnect(a, b);
    };
    meet(&mut net, 0, 2, 3);
    meet(&mut net, 1, 2, 40);
    let t = net.with(2, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    let t2 = net.with(0, |e, cx| e.delete(cx, f, "d/e", 0)).unwrap();
    if !whole {
        net.hold = Some(Hold::new(1, 3, MessageType::ChunkReply));
    }
    meet(&mut net, 1, 3, 40);
    net.hold = None;
    meet(&mut net, 0, 3, 3);
    meet(&mut net, 2, 3, 3);
    meet(&mut net, 1, 4, 40);
    meet(&mut net, 2, 4, 3);
    meet(&mut net, 0, 4, 3);
    (net, t, t2)
}

#[test]
fn a_file_and_two_nested_tree_deletes_in_either_order_leave_the_same_disk() {
    // RC-1 (the security review's cases (b) and (c)): X and Y hold the same
    // records whatever order they came in, the file's content or not, and
    // keep the same disk: d/e's base is T', d's is T.
    for whole in [false, true] {
        let (net, t, t2) = file_and_nested_deletes(whole);
        let d = disks(&net);
        let rec = |i: usize| -> Vec<RecordHash> {
            let mut r: Vec<RecordHash> = net.nodes[i]
                .engine
                .folder(&folder())
                .unwrap()
                .records
                .iter()
                .map(|r| r.hash)
                .collect();
            r.sort_unstable();
            r
        };
        assert_eq!(rec(3), rec(4), "whole {whole}: the same records");
        assert_eq!(d[3], d[4], "whole {whole}: the same disk");
        assert!(
            d[3].contains(&("d/e".to_owned(), Place::Path, t2)),
            "whole {whole}"
        );
        assert!(
            d[3].contains(&("d".to_owned(), Place::Path, t)),
            "whole {whole}"
        );
    }
}

#[test]
fn a_folder_both_devices_kept_closed_opens_when_the_second_proves_it() {
    // RC-N1 (probe P6): both nodes keep the folder closed by the clock rule,
    // so neither proves it at connect. Node 0's clock is set right first and
    // its folder opens; node 1's is set right before anything node 0 sent
    // for the folder arrives. Each side proves it when it opens
    // (`prove_everywhere`): without that, neither would ever prove it on
    // this connection.
    let mut net = Net::new((0..2).map(|i| config(i, vec![folder_key(1, 1)])).collect());
    for i in 0..2u8 {
        let n = usize::from(i);
        net.nodes[n].cx.wall += PAST_THE_RULE;
        write(&mut net, n, &format!("f{i}.txt"), b"ahead").unwrap();
        net.nodes[n].cx.wall -= PAST_THE_RULE;
        net.restart(n, config(i, vec![folder_key(1, 1)]));
        assert!(!net.nodes[n].engine.folder(&folder()).unwrap().credentialed);
    }
    net.hold = Some(Hold::new(0, 1, MessageType::FolderProof));
    net.connect(0, 1);
    net.advance(Duration::from_secs(1));
    net.nodes[0].cx.wall += STEP;
    write(&mut net, 0, "g.txt", b"g").unwrap();
    net.nodes[1].cx.wall += STEP;
    write(&mut net, 1, "h.txt", b"h").unwrap();
    net.release();
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
    }
}

#[test]
fn a_blob_this_device_freed_after_a_read_error_raises_no_corruption() {
    // RC-2 (probe P7), the bug: node 1 could not read a blob at a restart
    // and kept it to read again; it then freed that chunk itself (the
    // version naming it was replaced), and the free tick, finding it gone,
    // took it for a blob changed at rest. A blob this device freed is no
    // longer one to read again.
    let mut net = pair();
    let r1 = write(&mut net, 0, "a.bin", &[5u8; 900]).unwrap();
    net.advance(Duration::from_secs(3));
    let c1 = chunks_of(&net, 1, &r1)[0];
    let key = crate::store::chunk_key(&folder(), &c1);
    net.disconnect(0, 1);
    write(&mut net, 0, "a.bin", &[6u8; 900]).unwrap();
    net.advance(Duration::from_secs(61));
    net.nodes[1].cx.storage.get_fail_prefix = Some(key.clone());
    net.restart(1, config(1, vec![folder_key(1, 1)]));
    net.nodes[1].cx.storage.get_fail_prefix = None;
    assert!(!stored(&net, 1, &c1));
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    assert!(
        !net.nodes[1].cx.storage.committed.contains_key(&key),
        "node 1 freed it"
    );
    net.advance(Duration::from_secs(61));
    let e = &net.nodes[1].engine;
    assert!(
        e.issues()
            .list()
            .iter()
            .all(|i| i.kind != IssueKind::LocalChunkCorrupt),
        "{:?}",
        e.issues()
    );
}

#[test]
fn a_conflict_copy_keeps_its_place_on_the_disk_while_its_chunk_is_forgotten() {
    // RS-2, the bug: a copy slot was cleared whenever its record was not on
    // the disk at that moment, so a copy whose chunk could not be read at a
    // restart lost its slot, and the next write over the conflict did not
    // turn it into a file. A copy slot goes only once its record is no
    // conflict copy any more.
    let (mut net, v2, _) = conflict();
    let copy = file(&net, 0, "f.txt").unwrap().conflict_copies[0];
    let name = copy_name("f.txt", &copy);
    let content = if copy == v2 { [2u8; 2000] } else { [3u8; 2000] };
    let chunk = chunks_of(&net, 0, &copy)[0];
    let key = crate::store::chunk_key(&folder(), &chunk);
    net.nodes[0].cx.storage.get_fail_prefix = Some(key);
    net.restart(0, config(0, vec![folder_key(1, 1)]));
    net.nodes[0].cx.storage.get_fail_prefix = None;
    assert!(!stored(&net, 0, &chunk), "the copy's chunk is forgotten");
    let f0 = file(&net, 0, "f.txt").unwrap();
    assert!(
        f0.bases.contains(&(Place::Copy(name.clone()), copy)),
        "the copy keeps its slot"
    );
    write(&mut net, 0, "f.txt", &[4u8; 2000]).unwrap();
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        let c = file(&net, i, &name).unwrap_or_else(|| panic!("node {i}: no file for the copy"));
        let n = &net.nodes[i];
        let bytes = n
            .engine
            .read_file(&n.cx.storage, &folder(), &c.heads[0].hash)
            .unwrap();
        assert_eq!(bytes, content.to_vec(), "node {i}: the copy's content");
    }
}

#[test]
fn a_local_tree_delete_with_a_pruned_vector_keeps_the_disk_of_a_tree_delete_it_leaves() {
    // R3-1, the bug (probe P9): 34 devices. Node 33 deletes d/sub first (B,
    // the lowest counter beneath d); 32 others then write a file each
    // beneath d; node 0, which wrote nothing there, deletes d. Its vector
    // keeps the 32 greatest counters, so B is not covered and stays held,
    // but the write cleared B's slot at d/sub without reporting the path,
    // so node 0's disk lost B there while every other device kept it.
    let n = 34usize;
    let mut net = Net::new(
        (0..n)
            .map(|i| config(u8::try_from(i).unwrap(), vec![folder_key(1, 1)]))
            .collect(),
    );
    for i in 1..n {
        net.connect(0, i);
    }
    net.advance(Duration::from_secs(2));
    let f = folder();
    net.with(1, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(2));
    net.with(33, |e, cx| e.mkdir(cx, f, "d/sub", 0)).unwrap();
    net.advance(Duration::from_secs(2));
    let b = net.with(33, |e, cx| e.delete(cx, f, "d/sub", 0)).unwrap();
    net.advance(Duration::from_secs(2));
    for i in 1..=32usize {
        write(&mut net, i, &format!("d/f{i:02}"), b"x").unwrap();
        net.advance(Duration::from_secs(1));
    }
    net.with(0, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    net.advance(Duration::from_secs(10));
    let held = net.nodes[0]
        .engine
        .folder(&f)
        .unwrap()
        .records
        .iter()
        .any(|r| r.hash == b);
    assert!(held, "B is not covered by node 0's pruned vector");
    let d = disks(&net);
    assert!(
        d[0].contains(&("d/sub".to_owned(), Place::Path, b)),
        "node 0 keeps B at d/sub"
    );
    for (i, disk) in d.iter().enumerate() {
        assert_eq!(*disk, d[0], "node {i} has node 0's disk");
    }
}

/// Seconds in 200 days.
const TWO_HUNDRED_DAYS: u64 = 200 * 86_400;

/// Every node's wall clock `secs` on.
fn step_clocks(net: &mut Net, secs: u64) {
    for n in &mut net.nodes {
        n.cx.wall += secs;
    }
}

/// Three writers: node 2 holds V1 of g.txt alone; nodes 0 and 1 hold V3,
/// which covers V1 without naming it (it names V2), and two tree deletes of
/// d made apart, node 1's 200 days before node 0's (`mtime` is node 0's
/// delete's). Returns the net and the older and newer delete.
fn two_tree_deletes_apart(mtime: i64) -> (Net, RecordHash, RecordHash) {
    let mut net = Net::new((0..3).map(|i| config(i, vec![folder_key(1, 1)])).collect());
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        net.connect(a, b);
    }
    net.advance(Duration::from_secs(2));
    let f = folder();
    write(&mut net, 0, "g.txt", b"one").unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 2);
    net.disconnect(1, 2);
    write(&mut net, 0, "g.txt", b"two").unwrap();
    write(&mut net, 0, "g.txt", b"three").unwrap();
    net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
    write(&mut net, 0, "d/x", b"x").unwrap();
    net.advance(Duration::from_secs(3));
    net.disconnect(0, 1);
    let old = net.with(1, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
    step_clocks(&mut net, TWO_HUNDRED_DAYS);
    let new = net.with(0, |e, cx| e.delete(cx, f, "d", mtime)).unwrap();
    net.connect(0, 1);
    net.advance(Duration::from_secs(5));
    (net, old, new)
}

#[test]
fn a_rounds_end_cleanup_that_expires_the_greater_tree_delete_leaves_the_other_as_the_base() {
    // S3-C, the bug: node 0 and node 1 hold two tree deletes of d, d's base
    // the greater, which is also the older. 200 days later node 2, back
    // with V1, offers it; node 0 notes it (V3 covers it, nothing held names
    // it) and names it at the round's end
    // in a cleanup whose counter raises the folder's time past the older
    // delete's horizon, which expires it. The round's end reported no
    // paths, so node 0 left d with no base, while node 1, expiring it as it
    // accepted that cleanup, made the newer delete d's base.
    // The first of node 0's deletes, by its mtime, that sorts below node 1's.
    let (mut net, old, new) = (0..64)
        .map(two_tree_deletes_apart)
        .find(|(_, old, new)| old > new)
        .unwrap();
    for i in 0..2 {
        assert!(disks(&net)[i].contains(&("d".to_owned(), Place::Path, old)));
    }
    step_clocks(&mut net, TWO_HUNDRED_DAYS);
    net.connect(0, 2);
    net.advance(Duration::from_secs(40));
    let d = disks(&net);
    for (i, disk) in d.iter().enumerate() {
        let held: Vec<RecordHash> = net.nodes[i]
            .engine
            .folder(&folder())
            .unwrap()
            .records
            .iter()
            .map(|r| r.hash)
            .collect();
        assert!(!held.contains(&old), "node {i}: the older delete expired");
        assert!(held.contains(&new), "node {i}");
        assert!(
            disk.contains(&("d".to_owned(), Place::Path, new)),
            "node {i}: the newer delete is d's base"
        );
        assert_eq!(*disk, d[0], "node {i} has node 0's disk");
    }
}

#[test]
fn a_write_that_stages_no_blob_has_its_version_judged_in_its_own_handler() {
    // S3-B, the write's mark on the chunk book: a rename stages no blob
    // (its content is stored already) and drops the old version, so only
    // the write's own mark has the book judge the new version's stored
    // chunks in the handler that wrote it.
    let mut net = pair();
    write(&mut net, 0, "f.txt", &[6u8; 1500]).unwrap();
    let f = folder();
    let renamed = net
        .with(0, |e, cx| e.rename(cx, f, "f.txt", "g.txt", 0))
        .unwrap();
    let book = &net.nodes[0].engine.folders.get(&f).unwrap().book;
    assert!(book.ready(&renamed), "judged in the rename's handler");
}

/// A record of folder 1 by device `[writer; 32]` at `counter` over
/// `vector` (device byte and counter, ascending), signed with its write
/// key: a file naming chunk `[n; 32]` (nobody holds it), or, with `None`, a
/// tree delete.
fn crafted(
    path: &str,
    writer: u8,
    counter: u64,
    vector: &[(u8, u64)],
    chunk: Option<u8>,
) -> licketysync_keys::records::SignedRecord {
    use licketysync_keys::chunk::PlainHash;
    use licketysync_keys::DeviceId;
    use licketysync_protocol::record::{Chunk, Dot, IndexDraft, Kind, Meta, Vector};
    let key = crate::testkit::write_key(1);
    let dot = |d: u8, counter: u64| Dot {
        device: DeviceId([d; 32]),
        counter,
    };
    let chunks: Vec<Chunk> = chunk
        .map(|n| Chunk {
            cipher_hash: CipherHash([n; 32]),
            stored_len: 200,
        })
        .into_iter()
        .collect();
    let tree = chunk.is_none();
    IndexDraft {
        meta: Meta {
            path: path.to_owned(),
            kind: if tree { Kind::Directory } else { Kind::File },
            size: if tree { 0 } else { 100 },
            mtime_ns: 0,
            mode: 0,
            plain_hashes: chunks.iter().map(|_| PlainHash([3; 32])).collect(),
            written_at: 0,
            dot: dot(writer, counter),
            vector: Vector::from_sorted(vector.iter().map(|(d, c)| dot(*d, *c)).collect()).unwrap(),
            deleted: tree,
            tree,
        },
        chunks,
        replaces: Vec::new(),
    }
    .sign(&key, &key.record_keys(), &mut |b: &mut [u8]| b.fill(0x5a))
    .unwrap()
}

/// Puts `records` in node `i`'s committed store, as held there, and
/// restarts it over them as a read holder.
fn plant(net: &mut Net, i: usize, records: &[licketysync_keys::records::SignedRecord]) {
    let tier_2 = config(u8::try_from(i).unwrap(), vec![folder_key(1, 2)]);
    plant_and_restart(net, i, records, tier_2);
}

/// Puts `records` in node `i`'s committed store, as held there in folder 1,
/// and restarts it over them with `config`.
fn plant_and_restart(
    net: &mut Net,
    i: usize,
    records: &[licketysync_keys::records::SignedRecord],
    config: crate::config::EngineConfig,
) {
    for (seq, r) in (1u64..).zip(records) {
        let mut value = seq.to_be_bytes().to_vec();
        value.extend_from_slice(&r.to_bytes());
        net.nodes[i]
            .cx
            .storage
            .committed
            .insert(crate::store::record_key(&folder(), &r.hash()), value);
    }
    net.restart(i, config);
}

#[test]
fn a_page_that_only_drops_a_record_stops_wanting_its_chunks() {
    // S3-B, a page's mark on the chunk book when it only drops: node 0
    // holds R1 at d/x (its chunk nobody has, so lacking) and a tree delete
    // T of d that does not cover it. Node 1 sends R2, which replaces R1 but
    // which T covers: R1 is dropped and R2 not held, so the page held
    // nothing, and only its drop marks the book, which then stops lacking
    // R1's chunk in that handler. (Freeing R1's chunk at a later round's end
    // marks the book too, so the state is read before anything node 0
    // answers goes out.)
    let us = 1_767_225_600_000_000;
    let r1 = crafted("d/x", 0x91, us + 1_000, &[], Some(0xc1));
    let r2 = crafted("d/x", 0x92, us + 2_000, &[(0x91, us + 1_000)], Some(0xc2));
    let t = crafted("d", 0x93, us + 3_000, &[(0x92, us + 2_000)], None);
    let mut net = Net::new((0..2).map(|i| config(i, vec![folder_key(1, 2)])).collect());
    plant(&mut net, 0, &[r1.clone(), t.clone()]);
    plant(&mut net, 1, &[r2]);
    let lacking = |net: &Net| net.nodes[0].engine.folder(&folder()).unwrap().lacking;
    assert_eq!(lacking(&net), vec![CipherHash([0xc1; 32])]);
    net.hold = Some(Hold::new(1, 0, MessageType::IndexRecords));
    net.connect(0, 1);
    net.release_unsettled();
    let v = net.nodes[0].engine.folder(&folder()).unwrap();
    let held: Vec<RecordHash> = v.records.iter().map(|r| r.hash).collect();
    assert_eq!(held, vec![t.hash()], "R1 dropped, R2 not held");
    assert!(v.lacking.is_empty(), "R1's chunk no longer wanted");
    assert_eq!(v.bytes_needed, 0);
    net.settle();
    assert!(lacking(&net).is_empty(), "nor once node 0 answered");
}

#[test]
fn a_resolved_conflict_leaves_no_copy_slot_beside_its_path_on_any_disk() {
    // Item 6, Bases, and the `disk` module: a copy slot goes once its record
    // is no conflict copy any more. Once node 0's write over the conflict
    // reaches node 1, the copy's version lies at its own path on both disks
    // and the path's one base is the write.
    let (mut net, _, _) = conflict();
    let copy = file(&net, 0, "f.txt").unwrap().conflict_copies[0];
    let name = copy_name("f.txt", &copy);
    let v4 = write(&mut net, 0, "f.txt", &[4u8; 2000]).unwrap();
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        assert_eq!(
            file(&net, i, "f.txt").unwrap().bases,
            vec![(Place::Path, v4)],
            "node {i}: no copy slot beside the path"
        );
        let c = file(&net, i, &name).unwrap();
        assert_eq!(c.bases, vec![(Place::Path, c.heads[0].hash)], "node {i}");
    }
}

#[test]
fn a_write_over_a_conflict_writes_each_copy_with_its_own_size_and_time() {
    // 4.4, "What becomes of a conflict copy": the copy is written at its own
    // path as the version it was, its chunks and so its size, its kind and
    // its modification time, never the shown version's. Node 1's edit is
    // later by `mtime_ns`, so it is shown first and V2 is the copy (4.4,
    // display order).
    let mut net = pair();
    let f = folder();
    write(&mut net, 0, "f.txt", &[1u8; 2000]).unwrap();
    net.advance(Duration::from_secs(3));
    net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
    let v2 = write(&mut net, 0, "f.txt", &[2u8; 2000]).unwrap();
    net.advance(Duration::from_secs(3));
    let mine = net
        .with(1, |e, cx| e.write_file(cx, f, "f.txt", &[3u8; 1500], 7))
        .unwrap();
    net.release();
    net.advance(Duration::from_secs(5));
    let view = file(&net, 0, "f.txt").unwrap();
    assert_eq!(view.current, Some(mine), "the later edit is shown");
    assert_eq!(view.conflict_copies, vec![v2]);
    write(&mut net, 0, "f.txt", &[4u8; 100]).unwrap();
    net.advance(Duration::from_secs(5));
    let name = copy_name("f.txt", &v2);
    for i in 0..2 {
        let c = file(&net, i, &name).unwrap();
        assert_eq!(c.heads.len(), 1, "node {i}: an ordinary file");
        let head = c.heads[0];
        assert_eq!(
            (head.kind, head.size, head.mtime_ns),
            (licketysync_protocol::record::Kind::File, 2000, 0),
            "node {i}: V2's own"
        );
        let n = &net.nodes[i];
        let bytes = n.engine.read_file(&n.cx.storage, &f, &head.hash).unwrap();
        assert_eq!(bytes, vec![2u8; 2000], "node {i}");
    }
}

#[test]
fn a_rename_over_a_conflict_turns_each_copy_into_an_ordinary_file() {
    // Item 6, Conflicts, for a rename: its tombstone writes the old path
    // over every head on the disk there, so each conflict copy beside it is
    // first written as a version at its own path, in the same commit, and
    // is never lost with the path (4.4, "What becomes of a conflict copy").
    let (mut net, v2, _) = conflict();
    let copy = file(&net, 0, "f.txt").unwrap().conflict_copies[0];
    let name = copy_name("f.txt", &copy);
    let (shown, copied) = if copy == v2 {
        ([3u8; 2000], [2u8; 2000])
    } else {
        ([2u8; 2000], [3u8; 2000])
    };
    let f = folder();
    net.with(0, |e, cx| e.rename(cx, f, "f.txt", "g.txt", 0))
        .unwrap();
    net.advance(Duration::from_secs(5));
    for i in 0..2 {
        let old = file(&net, i, "f.txt").unwrap();
        assert!(old.deleted, "node {i}: the old path is deleted");
        assert_eq!(old.heads.len(), 1, "node {i}: its conflict covered");
        let n = &net.nodes[i];
        let read = |path: &str| {
            let v = file(&net, i, path).unwrap();
            assert_eq!(v.heads.len(), 1, "node {i}: {path} is an ordinary file");
            n.engine
                .read_file(&n.cx.storage, &f, &v.heads[0].hash)
                .unwrap()
        };
        assert_eq!(read("g.txt"), shown.to_vec(), "node {i}: the file renamed");
        assert_eq!(read(&name), copied.to_vec(), "node {i}: the copy's content");
    }
}

#[test]
fn a_folder_paused_for_a_store_failure_frees_no_chunk_until_it_resumes() {
    // Item 1 and section 5, "Store failure": a folder held paused takes no
    // change into its store until it resumes, the chunk frees the free tick
    // makes due included. They wait, and go once it has resumed.
    let (mut net, c1) = dropped_version();
    net.disconnect(0, 1);
    net.nodes[0].cx.storage.full = true;
    assert!(write(&mut net, 0, "x.txt", b"x").is_err());
    // The store takes puts again, but not the probe's: the folder stays
    // paused.
    net.nodes[0].cx.storage.full = false;
    net.nodes[0].cx.storage.fail_prefix = Some((crate::store::PROBE.to_vec(), u64::MAX));
    let commits = net.nodes[0].cx.storage.commits;
    net.advance(Duration::from_secs(61));
    assert!(matches!(state(&net, 0), FolderState::Paused(_)));
    assert!(
        net.nodes[0].engine.folders.get(&folder()).unwrap().free_due,
        "the free tick made the free due"
    );
    assert!(
        pending(&net, 0, &c1) && stored(&net, 0, &c1),
        "nothing freed while paused"
    );
    assert_eq!(
        net.nodes[0].cx.storage.commits, commits,
        "nothing committed"
    );
    net.nodes[0].cx.storage.fail_prefix = None;
    net.advance(Duration::from_secs(5));
    assert!(!matches!(state(&net, 0), FolderState::Paused(_)));
    assert!(
        !pending(&net, 0, &c1) && !stored(&net, 0, &c1),
        "freed once it resumed"
    );
}

#[test]
fn a_failed_commit_pauses_only_the_folders_it_meant_to_change() {
    // Section 5, "Store failure", and item 4: a failed commit pauses every
    // folder its handler meant to change, and no other. At this start
    // folder 2 is new, so its creation is staged and lost with the commit;
    // folder 1's store opens as it was, with nothing to change, and stays
    // usable.
    let (f1, f2) = (folder_key(1, 1).folder_id(), folder_key(2, 1).folder_id());
    let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
    write(&mut net, 0, "a.txt", b"a").unwrap();
    net.nodes[0].cx.storage.commit_fails = true;
    net.restart(0, config(0, vec![folder_key(1, 1), folder_key(2, 1)]));
    let state_of = |f: &licketysync_keys::FolderId| net.nodes[0].engine.folder(f).unwrap().state;
    assert!(
        matches!(state_of(&f2), FolderState::Paused(_)),
        "{:?}",
        state_of(&f2)
    );
    assert!(
        !matches!(state_of(&f1), FolderState::Paused(_)),
        "{:?}",
        state_of(&f1)
    );
}

#[test]
fn the_frees_an_open_finishes_are_committed_at_that_open() {
    // Item 1: "an open finishes whatever it lists before the folder syncs",
    // in on-start's one commit: the blob, its marker and its entry on the
    // list are gone from what is committed, so the next start finds nothing
    // left to free.
    let (mut net, c1) = dropped_version();
    net.restart(1, config(1, vec![folder_key(1, 1)]));
    let f = folder();
    let committed = &net.nodes[1].cx.storage.committed;
    for key in [
        crate::store::chunk_key(&f, &c1),
        crate::store::held_key(&f, &c1),
        crate::store::free_key(&f, &c1),
    ] {
        assert!(!committed.contains_key(&key), "{key:?}");
    }
    net.restart(1, config(1, vec![folder_key(1, 1)]));
    assert!(!pending(&net, 1, &c1) && !stored(&net, 1, &c1));
}

#[test]
fn a_rounds_end_that_drops_nothing_recomputes_no_chunk_state() {
    // The chunk book is computed again only when the index changed what it
    // is computed from, a round's end included. A reconnect's rounds end
    // with no cleanup to write and nothing dropped, so they change nothing
    // of it.
    let mut net = pair();
    write(&mut net, 0, "a.bin", &[1u8; 3000]).unwrap();
    net.advance(Duration::from_secs(3));
    let devices = [net.nodes[1].engine.own, net.nodes[0].engine.own];
    let look = |net: &Net| -> Vec<(u64, Option<u64>)> {
        (0..2)
            .map(|i| {
                let f = net.nodes[i].engine.folders.get(&folder()).unwrap();
                let ended = f.index.peer(&devices[i]).map(|p| p.round_ended_us);
                (f.book.refreshes, ended)
            })
            .collect()
    };
    let before = look(&net);
    net.disconnect(0, 1);
    net.connect(0, 1);
    net.advance(Duration::from_secs(3));
    let after = look(&net);
    for i in 0..2 {
        assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
        assert!(after[i].1 > before[i].1, "node {i}: a round ended");
        assert_eq!(after[i].0, before[i].0, "node {i}: no refresh");
    }
}

#[test]
fn a_write_the_index_refuses_reports_its_refusal_though_its_handlers_commit_failed() {
    // Section 5, "Store failure", and the `write` module: a write that made
    // no record says why, and a failed commit in its handler is not the
    // reason. Node 1 holds a record of folder 1 at `MAX_COUNTER`, so its
    // next counter there would pass it and the index refuses the write (4.4,
    // "The counter ceiling"; section 5, a device's next counter would pass
    // `MAX_COUNTER`); the same handler commits folder 2's cursor that node
    // 0's counted push raised, which waited for the next commit, and that
    // commit fails.
    //
    // The clocks are set just below `MAX_COUNTER` only for phase 0's clock
    // rule, which the code keeps: it keeps a store more than a year ahead of
    // the clock closed (the index's open, `CLOCK_RULE_LIMIT`) and compares
    // the Hellos' clocks. 4.4, "Opening a folder", opens such a store
    // whatever the clock; phase 1 removes the rule, and these lines with it.
    let max = licketysync_protocol::limits::MAX_COUNTER;
    let (f1, f2) = (folder(), folder_key(2, 1).folder_id());
    let both = || config(1, vec![folder_key(1, 1), folder_key(2, 1)]);
    let mut net = Net::new(vec![config(0, vec![folder_key(2, 1)]), both()]);
    for n in &mut net.nodes {
        n.cx.wall = max / 1_000_000;
    }
    plant_and_restart(&mut net, 1, &[crafted("z", 0x99, max, &[], None)], both());
    assert_eq!(net.nodes[1].engine.high_water(&f1), Some(max));
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    net.with(0, |e, cx| e.mkdir(cx, f2, "d", 0)).unwrap();
    assert!(
        !net.nodes[1].engine.deferred.is_empty(),
        "the push's cursor waits for the next commit"
    );
    net.nodes[1].cx.storage.commit_fails = true;
    let n = &mut net.nodes[1];
    let written = n.engine.write_file(&mut n.cx, f1, "a.txt", b"a", 0);
    assert_eq!(written, Err(WriteFailure::CounterExhausted));
    let state_of = |f: &licketysync_keys::FolderId| net.nodes[1].engine.folder(f).unwrap().state;
    assert!(
        matches!(state_of(&f2), FolderState::Paused(_)),
        "the commit failed: {:?}",
        state_of(&f2)
    );
}

#[test]
fn a_version_becomes_its_paths_base_in_the_handler_that_stores_its_last_chunk() {
    // The `disk` module and item 1: a path whose heads are not all on the
    // disk is applied again as their chunks arrive, so a version received
    // is its path's base, its file in place, in the handler that stores and
    // verifies its last chunk.
    let mut net = pair();
    net.hold = Some(Hold::new(0, 1, MessageType::ChunkReply));
    let h = write(&mut net, 0, "p.txt", b"hello there").unwrap();
    net.advance(Duration::from_secs(3));
    assert_eq!(
        file(&net, 1, "p.txt").unwrap().bases,
        vec![],
        "its chunk is held back"
    );
    net.release_unsettled();
    assert!(stored(&net, 1, &chunks_of(&net, 1, &h)[0]));
    assert_eq!(
        file(&net, 1, "p.txt").unwrap().bases,
        vec![(Place::Path, h)]
    );
}
