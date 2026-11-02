// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Outsiders (the brief's 13.5): members 0 to 2 hold folder A, and member 0
//! also folder B; peer 3 holds no key, and peer 4 holds only B. Each outsider
//! gets REJECTED for every proof where it shares nothing (`protocol.md` 3.5:
//! the uniform answer, TM-32), the connection closes with `NO_COMMON_FOLDER`
//! once `PROOF_TIMEOUT` passes, and no `IndexRecords` page or `ChunkReply` of
//! folder A ever reaches either. Folder B syncs between member 0 and peer 4
//! over the same connection that refuses A: messages route by folder ID.

#![allow(
    unused_crate_dependencies,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::indexing_slicing,
    reason = "integration tests link every dev-dependency; test code"
)]

mod support;

use core::cell::RefCell;
use core::time::Duration;
use std::collections::BTreeSet;
use std::rc::Rc;

use licketysync_engine::runtime::{Instant, PeerId};
use licketysync_engine::{Engine, EngineConfig};
use licketysync_keys::Tier;
use licketysync_protocol::CloseReason;
use licketysync_sim::member::{default_workload, Action, Ledger, Member, Step};
use licketysync_sim::scenario::{Scenario, Sim};
use licketysync_sim::scenarios::engine::SMALL_CHUNK;
use licketysync_sim::world::{World, MAIN};
use support::peers::{Sniffed, Sniffer, TestPeer};

const NO_KEY: PeerId = PeerId::new(3);
const ONLY_B: PeerId = PeerId::new(4);

fn engine(sim: &Sim<TestPeer>, id: PeerId) -> &Engine {
    sim.peer(id)
        .and_then(TestPeer::member)
        .and_then(Member::engine)
        .unwrap()
}

fn closes(e: &Engine, reason: CloseReason) -> u64 {
    e.counters().closes(reason)
}

#[test]
fn outsiders_are_refused_and_see_nothing_of_a_folder_they_do_not_hold() {
    let mut world = World::new(5);
    let b = world.add_folder();
    let world = world
        .holds(PeerId::new(0), b, Some(Tier::Write))
        .holds(NO_KEY, MAIN, None)
        .holds(ONLY_B, MAIN, None)
        .holds(ONLY_B, b, Some(Tier::Write));
    let (a_id, b_id) = (world.folder_id(MAIN).unwrap(), world.folder_id(b).unwrap());
    let ledger = Rc::new(RefCell::new(Ledger::default()));
    let seen: Vec<Rc<RefCell<Sniffed>>> = (0..2)
        .map(|_| Rc::new(RefCell::new(Sniffed::default())))
        .collect();
    let (l, w, s) = (Rc::clone(&ledger), world.clone(), seen.clone());
    let factory = move |id: PeerId| {
        let mut config = EngineConfig::new(w.device_seed(id), w.keys_of(id));
        config.chunk_size = SMALL_CHUNK;
        let first = Duration::from_secs(1);
        match id {
            NO_KEY => TestPeer::Outsider(Sniffer::new(
                Member::new(config, id, None, Vec::new(), BTreeSet::new(), Rc::clone(&l)),
                Rc::clone(&s[0]),
            )),
            ONLY_B => {
                let steps = vec![Step {
                    delay: first,
                    action: Action::Write {
                        path: "b/notes.txt".to_owned(),
                        content: vec![0x42; 3000],
                    },
                }];
                TestPeer::Outsider(Sniffer::new(
                    Member::new(
                        config,
                        id,
                        Some(b_id),
                        steps,
                        BTreeSet::new(),
                        Rc::clone(&l),
                    ),
                    Rc::clone(&s[1]),
                ))
            }
            _ => {
                let steps = default_workload(id, SMALL_CHUNK, first, Duration::from_millis(300));
                TestPeer::Member(Member::new(
                    config,
                    id,
                    Some(a_id),
                    steps,
                    BTreeSet::new(),
                    Rc::clone(&l),
                ))
            }
        }
    };
    let mut sim = Scenario::new(5, 5, factory)
        .converged_when(support::honest_converged)
        .build();
    let o = sim.run_until_quiescent(Instant::from_secs(600));
    assert!(o.converged && o.quiescent, "{o}");
    // Past PROOF_TIMEOUT for every connection that opened nothing.
    let o = sim.run_until(sim.now().saturating_add(Duration::from_secs(40)));
    assert!(o.converged, "{o}");

    // Nothing of A crossed to either outsider.
    let no_key = seen[0].borrow().clone();
    assert!(
        no_key.index_records.is_empty() && no_key.chunk_replies.is_empty(),
        "{no_key:?}"
    );
    let only_b = seen[1].borrow().clone();
    // B's only file is the outsider's own, pushed to member 0, which has
    // nothing of B to send back: what the outsider got, if anything, is B's.
    assert!(
        only_b
            .index_records
            .iter()
            .chain(&only_b.chunk_replies)
            .all(|f| *f == b_id),
        "{only_b:?}"
    );

    // Every proof that met no key was REJECTED, and the connections that
    // opened nothing closed with NO_COMMON_FOLDER.
    for id in [1, 2] {
        let e = engine(&sim, PeerId::new(id));
        assert!(
            e.counters().proofs_rejected >= 2,
            "member {id}'s proofs of A to both outsiders"
        );
        assert!(closes(e, CloseReason::NoCommonFolder) >= 2, "member {id}");
        assert!(!e.connections().any(|p| p == NO_KEY || p == ONLY_B));
    }
    let e0 = engine(&sim, PeerId::new(0));
    assert!(
        e0.connections().any(|p| p == ONLY_B),
        "member 0 keeps B open with peer 4"
    );
    assert!(
        engine(&sim, ONLY_B).counters().proofs_rejected >= 3,
        "peer 4's proofs of B"
    );
    assert!(closes(engine(&sim, NO_KEY), CloseReason::NoCommonFolder) >= 4);

    // B is the same on member 0 and peer 4, and its file reads back.
    let (p0, p4) = (
        support::fingerprint(e0, &b_id),
        support::fingerprint(engine(&sim, ONLY_B), &b_id),
    );
    assert_eq!(p0, p4);
    let storage = sim.storage(PeerId::new(0)).unwrap();
    let file = e0
        .files(&b_id)
        .into_iter()
        .find(|f| f.path == "b/notes.txt")
        .unwrap();
    assert_eq!(
        e0.read_file(storage, &b_id, &file.current.unwrap()),
        Ok(vec![0x42; 3000])
    );
    assert!(e0.folder(&a_id).is_some() && engine(&sim, ONLY_B).folder(&a_id).is_none());
    assert!(
        ledger.borrow().issues.is_empty(),
        "{:?}",
        ledger.borrow().issues
    );
}
