// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Adversaries on a real protocol connection with real keys (the brief's
//! 13.5, items 3, 8 and 9 as the port brief changes them, and its three new
//! attacks): two honest members run the default workload beside one
//! adversary.
//! In every case the honest members converge on the honest records and
//! blame only the adversary, by the outcome section 5 gives its fault: a
//! close and an issue naming the peer for what only the sender can be blamed
//! for (TM-10), an issue naming the record and the connection kept for what
//! a valid signature covers (ruling S-4).

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::assert_is_empty,
    reason = "integration tests link every dev-dependency; test code"
)]

mod support;

use core::cell::RefCell;
use core::time::Duration;
use std::collections::BTreeSet;
use std::rc::Rc;

use licketysync_engine::inspect::RecordState;
use licketysync_engine::runtime::{Instant, PeerId};
use licketysync_engine::{Engine, EngineConfig, Issue, IssueKind, Subject};
use licketysync_keys::{CipherHash, FolderId, FolderKey, RecordHash, Tier};
use licketysync_protocol::{Cause, CloseReason};
use licketysync_sim::member::{default_workload, Ledger, Member};
use licketysync_sim::network::Partition;
use licketysync_sim::scenario::{Fault, Scenario, Sim};
use licketysync_sim::scenarios::engine::SMALL_CHUNK;
use licketysync_sim::world::{World, MAIN};
use support::peers::{write_key, Adversary, AdversaryLog, Attack, TestPeer, FOLDER_A};

const ADVERSARY: PeerId = PeerId::new(2);

struct Setup {
    sim: Sim<TestPeer>,
    ledger: Rc<RefCell<Ledger>>,
    log: Rc<RefCell<AdversaryLog>>,
    folder: FolderId,
}

fn engine(sim: &Sim<TestPeer>, id: u64) -> &Engine {
    sim.peer(PeerId::new(id))
        .and_then(TestPeer::member)
        .and_then(Member::engine)
        .unwrap()
}

/// Members 0 and 1 (write key, default workload) and the adversary 2.
fn setup(
    attack: Attack,
    adversary_key: FolderKey,
    seed: u64,
    tweak: fn(&mut EngineConfig),
    scene: fn(Scenario<TestPeer>) -> Scenario<TestPeer>,
) -> Setup {
    setup_in(World::new(2), attack, adversary_key, seed, tweak, scene)
}

/// As [`setup`], with the members' keys from `world`.
fn setup_in(
    world: World,
    attack: Attack,
    adversary_key: FolderKey,
    seed: u64,
    tweak: fn(&mut EngineConfig),
    scene: fn(Scenario<TestPeer>) -> Scenario<TestPeer>,
) -> Setup {
    let folder = world.folder_id(MAIN).unwrap();
    let ledger = Rc::new(RefCell::new(Ledger::default()));
    let log = Rc::new(RefCell::new(AdversaryLog::default()));
    let (l, a) = (Rc::clone(&ledger), Rc::clone(&log));
    let key = RefCell::new(Some(adversary_key));
    let factory = move |id: PeerId| {
        if id == ADVERSARY {
            let k = key.borrow_mut().take().unwrap();
            return TestPeer::Adversary(Adversary::new(0x99, &k, attack, Rc::clone(&a)));
        }
        let mut config = EngineConfig::new(world.device_seed(id), world.keys_of(id));
        config.chunk_size = SMALL_CHUNK;
        tweak(&mut config);
        let steps = default_workload(
            id,
            SMALL_CHUNK,
            Duration::from_secs(1),
            Duration::from_millis(300),
        );
        TestPeer::Member(Member::new(
            config,
            id,
            Some(folder),
            steps,
            BTreeSet::new(),
            Rc::clone(&l),
        ))
    };
    let scenario = Scenario::new(seed, 3, factory).converged_when(support::honest_converged);
    Setup {
        sim: scene(scenario).build(),
        ledger,
        log,
        folder,
    }
}

fn run(attack: Attack, adversary_key: FolderKey) -> Setup {
    run_with(attack, adversary_key, |_| {}, |s| s)
}

fn run_with(
    attack: Attack,
    adversary_key: FolderKey,
    tweak: fn(&mut EngineConfig),
    scene: fn(Scenario<TestPeer>) -> Scenario<TestPeer>,
) -> Setup {
    let mut s = setup(attack, adversary_key, 3, tweak, scene);
    let o = s.sim.run_until_quiescent(Instant::from_secs(600));
    assert!(
        o.converged && o.quiescent && !o.exhausted,
        "{attack:?}: the honest members did not converge: {o}"
    );
    s
}

fn a_write() -> FolderKey {
    FolderKey::from(write_key(FOLDER_A))
}

/// No issue blames either honest member, and none names a record unless the
/// attack's own record.
fn blames_only_the_adversary(s: &Setup) {
    let ours: BTreeSet<RecordHash> = s.log.borrow().records.iter().copied().collect();
    for (peer, issue) in &s.ledger.borrow().issues {
        match &issue.subject {
            Subject::Peer { peer: p, .. } => assert_eq!(*p, ADVERSARY, "{peer}: {issue:?}"),
            Subject::Record(r) => assert!(
                ours.contains(r),
                "{peer}: an honest record blamed: {issue:?}"
            ),
            _ => {}
        }
    }
    assert_eq!(s.ledger.borrow().internal_errors, 0);
}

/// Each member closed the adversary with `reason` and raised an issue naming
/// it for `cause`.
fn closed_for(s: &Setup, cause: Cause, reason: CloseReason) {
    for id in [0, 1] {
        let e = engine(&s.sim, id);
        let named = e.issues().list().iter().any(|i: &Issue| {
            i.kind == IssueKind::PeerFault(cause)
                // Proven or not: a fault before the folder opened on the
                // member's side counts the adversary unproven (E4).
                && matches!(i.subject, Subject::Peer { peer, device: Some(_), .. } if peer == ADVERSARY)
        });
        assert!(
            named,
            "member {id} raised no issue naming the adversary for {cause:?}"
        );
        assert!(
            e.counters().closes_sent.of(reason) >= 1,
            "member {id} sent no {reason:?}"
        );
        assert!(
            !e.connections().any(|p| p == ADVERSARY),
            "member {id} kept the connection"
        );
    }
    blames_only_the_adversary(s);
}

/// Each member keeps the connection, holds the adversary's record and raised
/// `kind` naming it.
fn record_blamed(s: &Setup, kind: IssueKind, state: RecordState) {
    let record = s.log.borrow().records[0];
    for id in [0, 1] {
        let e = engine(&s.sim, id);
        let view = e.folder(&s.folder).unwrap();
        let held = view
            .records
            .iter()
            .find(|r| r.hash == record)
            .map(|r| r.state);
        assert_eq!(held, Some(state), "member {id}");
        let named = e
            .issues()
            .list()
            .iter()
            .any(|i| i.kind == kind && i.subject == Subject::Record(record));
        assert!(named, "member {id} raised no {kind:?} naming the record");
        assert_eq!(
            e.counters().blaming_closes(),
            0,
            "member {id} closed a connection"
        );
    }
    blames_only_the_adversary(s);
}

#[test]
fn a_bit_flipped_inside_a_pushed_body_is_forged_and_closes() {
    let s = run(Attack::FlippedBody, a_write());
    closed_for(&s, Cause::Forged, CloseReason::VerificationFailed);
    let record = s.log.borrow().records[0];
    assert!(engine(&s.sim, 0)
        .folder(&s.folder)
        .unwrap()
        .records
        .iter()
        .all(|r| r.hash != record));
}

#[test]
fn a_body_signed_with_another_folders_key_is_forged() {
    let read = FolderKey::from(write_key(FOLDER_A).read_key());
    let s = run(Attack::OtherFolderKey, read);
    closed_for(&s, Cause::Forged, CloseReason::VerificationFailed);
}

#[test]
fn a_garbage_seal_is_stored_opaque_everywhere_and_names_the_record() {
    let s = run(Attack::GarbageSeal, a_write());
    // The seal will not open: a fault every release finds, which saving the
    // file again clears.
    record_blamed(
        &s,
        IssueKind::WriterFault { shared: true },
        RecordState::Opaque,
    );
    // Key holders keep the chunks of opaque records too, to serve them to a
    // release that reads them (4.7 item 5).
    let blob = s.log.borrow().blobs[0];
    for id in [0, 1] {
        let view = engine(&s.sim, id).folder(&s.folder).unwrap();
        assert!(view.stored_chunks.contains(&blob), "member {id}");
    }
}

#[test]
fn a_chunk_whose_seal_will_not_open_is_corrupt_for_its_record_and_never_fetched_again() {
    let mut s = run(Attack::CorruptChunk, a_write());
    record_blamed(&s, IssueKind::ChunkCorrupt, RecordState::Applied);
    let hash = s.log.borrow().blobs[0];
    let asked = |s: &Setup| {
        s.log
            .borrow()
            .chunk_requests
            .get(&hash)
            .copied()
            .unwrap_or(0)
    };
    let before = asked(&s);
    assert!((1..=2).contains(&before), "asked {before} times");
    s.sim
        .run_until(s.sim.now().saturating_add(Duration::from_secs(600)));
    assert_eq!(asked(&s), before, "fetched again");
}

#[test]
fn a_version_whose_chunk_fails_for_it_is_never_on_the_disk_though_another_record_keeps_the_chunk() {
    // The security review's NIT 3, the bug (probe N3): a version counted as
    // on the disk once each chunk it names was stored, so a chunk that an
    // opaque record kept, and that does not open for the version, made the
    // version the base at its path. A version is on the disk only when every
    // chunk has verified for it.
    let s = run(Attack::CorruptBesideOpaque, a_write());
    let (version, blob) = (s.log.borrow().records[0], s.log.borrow().blobs[0]);
    for id in [0, 1] {
        let e = engine(&s.sim, id);
        let view = e.folder(&s.folder).unwrap();
        assert!(
            view.stored_chunks.contains(&blob),
            "member {id}: kept for the opaque one"
        );
        let file = e
            .files(&s.folder)
            .into_iter()
            .find(|f| f.heads.iter().any(|h| h.hash == version))
            .unwrap();
        assert_eq!(file.current, Some(version), "member {id}");
        assert!(
            file.bases.is_empty(),
            "member {id}: on the disk: {:?}",
            file.bases
        );
    }
    blames_only_the_adversary(&s);
}

#[test]
fn a_version_whose_chunks_do_not_add_up_to_its_size_is_never_on_the_disk() {
    // The security review's CS-N1: every chunk opens for the version, but
    // their plaintext lengths do not sum to its size: a writer fault naming
    // the record, and the version is never put on the disk.
    let s = run(Attack::WrongSize, a_write());
    record_blamed(&s, IssueKind::SizeMismatch, RecordState::Applied);
    let version = s.log.borrow().records[0];
    for id in [0, 1] {
        let file = engine(&s.sim, id)
            .files(&s.folder)
            .into_iter()
            .find(|f| f.heads.iter().any(|h| h.hash == version))
            .unwrap();
        assert!(
            file.bases.is_empty(),
            "member {id}: on the disk: {:?}",
            file.bases
        );
    }
}

#[test]
fn a_stored_length_other_than_the_blobs_is_a_writer_fault() {
    let s = run(Attack::StoredLenMismatch, a_write());
    record_blamed(&s, IssueKind::ChunkCorrupt, RecordState::Applied);
}

#[test]
fn an_unsolicited_chunk_reply_closes_with_protocol_error() {
    let s = run(Attack::UnsolicitedReply, a_write());
    closed_for(&s, Cause::Malformed, CloseReason::ProtocolError);
}

#[test]
fn more_chunk_requests_than_advertised_close_with_protocol_error() {
    let s = run_with(
        Attack::TooManyRequests,
        a_write(),
        |c| c.max_requests_in_flight = 1,
        |s| s,
    );
    closed_for(&s, Cause::Malformed, CloseReason::ProtocolError);
}

#[test]
fn a_peer_that_takes_chunk_requests_and_never_answers_pins_no_hash_for_ever() {
    // E2: any key holder may be asked for any hash (ruling S-3), and a
    // chunk request has no reply deadline. The honest members advertise
    // one request in flight each, so that every other hash they lack is
    // asked of the adversary first; after the chunk patience (60 s) the
    // other member is asked too.
    let sealed = FolderKey::from(write_key(FOLDER_A).sealed_key());
    let s = run_with(
        Attack::Silent,
        sealed,
        |c| c.max_requests_in_flight = 1,
        |s| s,
    );
    assert!(
        !s.log.borrow().chunk_requests.is_empty(),
        "the adversary was asked, so the patience was what got the chunks"
    );
    for id in [0, 1] {
        let e = engine(&s.sim, id);
        assert!(
            e.issues().list().is_empty(),
            "member {id}: {:?}",
            e.issues()
        );
        assert_eq!(e.counters().blaming_closes(), 0, "member {id}");
    }
    blames_only_the_adversary(&s);
}

/// Runs the members of `world` beside an adversary until they converge.
fn run_in(world: World, attack: Attack, adversary_key: FolderKey) -> Setup {
    let mut s = setup_in(world, attack, adversary_key, 3, |_| {}, |s| s);
    let o = s.sim.run_until_quiescent(Instant::from_secs(600));
    assert!(
        o.converged && o.quiescent && !o.exhausted,
        "{attack:?}: the honest members did not converge: {o}"
    );
    s
}

/// Member 0 holds the write key and member 1 `tier`.
fn writer_and(tier: Tier) -> World {
    World::new(2).holds(PeerId::new(1), MAIN, Some(tier))
}

/// No issue names a peer or a record, and nobody closed a connection for a
/// fault.
fn nobody_blamed(s: &Setup) {
    for (peer, issue) in &s.ledger.borrow().issues {
        assert!(
            !matches!(issue.subject, Subject::Peer { .. } | Subject::Record(_)),
            "{peer}: {issue:?}"
        );
    }
    for id in [0, 1] {
        assert_eq!(
            engine(&s.sim, id).counters().blaming_closes(),
            0,
            "member {id}"
        );
    }
    assert_eq!(s.ledger.borrow().internal_errors, 0);
}

fn held(s: &Setup, id: u64, record: &RecordHash) -> Option<RecordState> {
    engine(&s.sim, id)
        .folder(&s.folder)
        .unwrap()
        .records
        .iter()
        .find(|r| r.hash == *record)
        .map(|r| r.state)
}

#[test]
fn records_whose_counters_jump_are_held_with_no_gap_to_blame() {
    // Item 3: with per-writer sequences gone, a jump in a writer's counters
    // is no gap; the later record is held first, the earlier one too.
    let s = run(Attack::CounterJump, a_write());
    let records = s.log.borrow().records.clone();
    assert_eq!(records.len(), 2);
    for id in [0, 1] {
        for r in &records {
            assert_eq!(held(&s, id, r), Some(RecordState::Applied), "member {id}");
        }
    }
    nobody_blamed(&s);
}

#[test]
fn a_write_holder_under_an_honest_devices_id_is_equivocation_and_blames_nobody() {
    // Item 8: a twin under the dot of member 0's first record (two records,
    // one dot: concurrent heads, protocol proof 13) and a record under
    // member 0's ID above its high-water mark (the own-ID hint).
    let mut s = setup(Attack::HonestId, a_write(), 3, |_| {}, |s| s);
    s.sim.run_until(Instant::from_millis(1_500));
    let (twin, ahead) = {
        let log = s.log.borrow();
        (log.records[0], log.records[1])
    };
    for id in [0, 1] {
        let files = engine(&s.sim, id).files(&s.folder);
        let at = files
            .iter()
            .find(|f| f.heads.iter().any(|h| h.hash == twin))
            .unwrap_or_else(|| panic!("member {id} holds no twin head"));
        assert_eq!(
            at.heads.len(),
            2,
            "member {id}: the twin beside the genuine record"
        );
    }
    let o = s.sim.run_until_quiescent(Instant::from_secs(600));
    assert!(o.converged && o.quiescent && !o.exhausted, "{o}");
    let zero = engine(&s.sim, 0);
    assert!(
        zero.issues()
            .list()
            .iter()
            .any(|i| i.kind == IssueKind::OwnCounterAhead && i.subject == Subject::None),
        "{:?}",
        zero.issues()
    );
    let ahead_counter = zero.dot(&s.folder, &ahead).unwrap().counter;
    assert!(
        zero.high_water(&s.folder).unwrap() > ahead_counter,
        "member 0 wrote on above it"
    );
    for id in [0, 1] {
        assert_eq!(
            held(&s, id, &ahead),
            Some(RecordState::Applied),
            "member {id}"
        );
        assert_eq!(
            held(&s, id, &twin),
            None,
            "member {id}: a later write covered the twin"
        );
    }
    assert!(s.ledger.borrow().counters_reused.is_empty());
    nobody_blamed(&s);
}

#[test]
fn a_record_naming_a_chunk_nobody_holds_is_held_and_waits_with_no_issue() {
    // Item 9: held like any record; its chunk stays lacking for good and
    // nothing is raised about it.
    let mut s = setup(Attack::UnknownHash, a_write(), 3, |_| {}, |s| s);
    s.sim.run_until(Instant::from_secs(300));
    let record = s.log.borrow().records[0];
    let mut prints = Vec::new();
    for id in [0, 1] {
        let e = engine(&s.sim, id);
        assert_eq!(
            held(&s, id, &record),
            Some(RecordState::Applied),
            "member {id}"
        );
        let view = e.folder(&s.folder).unwrap();
        assert_eq!(view.lacking, vec![CipherHash([0xee; 32])], "member {id}");
        assert!(
            e.issues().list().is_empty(),
            "member {id}: {:?}",
            e.issues()
        );
        prints.push(support::fingerprint(e, &s.folder));
    }
    assert_eq!(prints[0], prints[1], "the members agree");
    nobody_blamed(&s);
}

#[test]
fn a_forged_deep_path_record_at_a_read_holder_costs_one_bounded_check_and_closes() {
    // A page of records at the deepest path the grammar allows, each forged:
    // a read holder opens the first one's seal and looks up its ancestors
    // (O(L) work), verifies it, finds it forged and closes; the rest of the
    // page is never judged.
    let s = run_in(writer_and(Tier::Read), Attack::DeepPath, a_write());
    closed_for(&s, Cause::Forged, CloseReason::VerificationFailed);
    for id in [0, 1] {
        let e = engine(&s.sim, id);
        // One log line for the first record's judgement and one for the
        // close it causes: a second record judged would add a third.
        assert_eq!(
            e.counters().of(Cause::Forged),
            2,
            "member {id} judged more than the first record"
        );
        let deep = e.files(&s.folder).iter().any(|f| f.path.len() > 4_000);
        assert!(!deep, "member {id} holds a deep record");
    }
}

#[test]
fn a_replayed_expired_tree_delete_is_ignored_and_the_write_holder_names_it() {
    // A genuine tree delete of `p0` a horizon and ten days old, replayed:
    // expired at both, so `p0` stays; the write holder verifies it and notes
    // it as a forgotten record, to name in a cleanup at its round's end.
    let s = run_in(
        writer_and(Tier::Read),
        Attack::ExpiredTreeDelete { forged: false },
        a_write(),
    );
    let record = s.log.borrow().records[0];
    for id in [0, 1] {
        assert_eq!(held(&s, id, &record), None, "member {id}");
        let live = engine(&s.sim, id)
            .files(&s.folder)
            .iter()
            .filter(|f| f.path.starts_with("p0/") && f.current.is_some())
            .count();
        assert!(live > 0, "member {id}: p0 was deleted");
    }
    assert!(engine(&s.sim, 0).counters().stale_noted >= 1);
    nobody_blamed(&s);
}

#[test]
fn a_forged_expired_tree_delete_is_ignored_unverified_at_a_read_holder() {
    // The same record with a forged signature: the read holder ignores it
    // without verifying it, so it keeps the connection; the write holder,
    // which would note it, verifies it first and closes.
    let s = run_in(
        writer_and(Tier::Read),
        Attack::ExpiredTreeDelete { forged: true },
        a_write(),
    );
    let read = engine(&s.sim, 1);
    assert_eq!(read.counters().blaming_closes(), 0);
    assert!(
        read.connections().any(|p| p == ADVERSARY),
        "the read holder kept it"
    );
    let write = engine(&s.sim, 0);
    assert!(
        write
            .counters()
            .closes_sent
            .of(CloseReason::VerificationFailed)
            >= 1
    );
    assert!(!write.connections().any(|p| p == ADVERSARY));
    blames_only_the_adversary(&s);
}

#[test]
fn a_sealed_peer_replaying_history_grows_another_only_by_genuine_records() {
    // The adversary holds the sealed key, keeps every record pushed to it
    // and replays them all at 10 s. The honest sealed member holds a
    // replayed version only while nothing it holds names it; it never holds
    // anything member 0 did not sign. The write holder notes the stale
    // copies offered to it and names them at its next round's end: member 0
    // is cut off from 12 s to 14 s, so that its rounds at the reconnect end
    // and its cleanup reaches the sealed member.
    let sealed = FolderKey::from(write_key(FOLDER_A).sealed_key());
    let mut s = setup_in(
        writer_and(Tier::Sealed),
        Attack::ReplayHistory,
        sealed,
        3,
        |_| {},
        |s| {
            s.fault(Fault::Partition {
                partition: Partition::isolate(PeerId::new(0), [PeerId::new(1), ADVERSARY]),
                from: Instant::from_secs(12),
                until: Instant::from_secs(14),
            })
        },
    );
    let o = s.sim.run_until_quiescent(Instant::from_secs(600));
    assert!(o.converged && o.quiescent && !o.exhausted, "{o}");
    let replayed = s.log.borrow().replayed.clone();
    assert!(!replayed.is_empty(), "nothing replayed");
    // What member 0 wrote: each write's record (the ledger) and what it
    // holds of its own (a rename's tombstone beside its new version).
    let mut genuine: BTreeSet<RecordHash> = s
        .ledger
        .borrow()
        .written
        .iter()
        .filter(|(w, _, _)| *w == PeerId::new(0))
        .map(|(_, _, h)| *h)
        .collect();
    genuine.extend(
        engine(&s.sim, 0)
            .folder(&s.folder)
            .unwrap()
            .records
            .iter()
            .filter(|r| !r.cleanup)
            .map(|r| r.hash),
    );
    let view = engine(&s.sim, 1).folder(&s.folder).unwrap();
    for r in &view.records {
        assert!(
            r.cleanup || genuine.contains(&r.hash),
            "the sealed member holds {} that nobody genuine wrote",
            r.hash
        );
    }
    assert!(
        engine(&s.sim, 0).counters().stale_noted >= 1,
        "no stale copy noted"
    );
    assert!(
        view.records.iter().any(|r| r.cleanup),
        "the write holder's cleanup did not reach the sealed member"
    );
    nobody_blamed(&s);
}
