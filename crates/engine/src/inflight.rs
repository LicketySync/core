// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The chunk requests outstanding across every connection (`protocol.md`
//! 4.6, "Passes": a hash already asked of one connection is skipped on the
//! others), the patience after which another connection may ask too, and
//! the order in which the connections take their turns.
//!
//! A peer holding any key of the folder may be asked for any hash (ruling
//! S-3), and the protocol gives a chunk request no reply deadline, so a peer
//! that takes requests and never answers would otherwise keep each hash it
//! was asked for from every other connection for as long as it stays
//! connected. So each connection a hash is outstanding on notes when it was
//! asked there, and once every one of them was asked at least [`patience`]
//! ago, twice the Status interval with no answer (60 s at the spec's
//! timing), the other connections where the folder is open may ask for it
//! as well. A refusal or a disconnect ends only its own connection's wait.
//! The slow request stays outstanding on its own connection; the first chunk
//! that arrives for the hash wins, and one that arrives once the hash is
//! stored is dropped and counted (`Counters::late_chunks`). Once a chunk has
//! arrived for the hash, the next connection in line that holds no request
//! for it may ask at once (the chunk may have been corrupt for its records),
//! and no connection is asked twice.
//!
//! **Turns.** Whenever the hash is free again, it goes round the connections
//! that could ask for it now, in the order this device made them, starting
//! after the one asked last; a connection made since the round began, or
//! asked already in it, waits for the next round. [`InFlight::turns`] names
//! whose turn each hash is once per run of the passes, and a connection that
//! can no longer ask (its room filled, or its pass past the hash came to
//! wait) is passed over when the passes run again in the same handler
//! (`Engine::drive_passes`). So peers that refuse the hash, reconnect, or
//! report more chunks stored to be asked again, even two or more taking
//! turns to hold it, are asked again only after every other connection had
//! its turn: an honest holder that can be asked when its turn comes is asked
//! within one round, after at most one turn of each connection ahead of it,
//! each turn at most about the patience (TM-22). One whose pass waits for a
//! trigger cannot be asked until the trigger comes, the residual TM-22
//! states.
//!
//! Bounded (TM-22): an entry names only connections that hold the request
//! open under their peer's `max_requests_in_flight`, one time each, and a
//! connection's names go when it ends; the entry's place in the round is
//! two numbers. An entry whose requests have all ended stays until the end
//! of the handler ([`InFlight::sweep`]), so that the passes that handler
//! drives keep the round.

use core::time::Duration;
use std::collections::BTreeMap;

use licketysync_keys::{CipherHash, FolderId};
use licketysync_protocol::connection::Timing;

use crate::runtime::{Instant, PeerId};

/// How long a hash asked of one connection waits for its answer before the
/// other connections may ask for it too: two Status intervals.
pub(crate) fn patience(timing: &Timing) -> Duration {
    timing.status.saturating_mul(2)
}

/// A connection as the turns see it: its handle, and its place in the
/// order this device made its connections ([`InFlight::connected`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Asker {
    pub(crate) peer: PeerId,
    pub(crate) made: u64,
}

/// One hash's outstanding requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Asked {
    /// The connections it is outstanding on, each with when it was asked
    /// there.
    by: BTreeMap<PeerId, Instant>,
    /// A chunk arrived for it from one of them: the others are not waited
    /// for.
    answered: bool,
    /// The place of the connection asked last.
    last: u64,
    /// The round goes through the connections made up to this place.
    round: u64,
}

impl Asked {
    /// Where the connection made at `made` stands in line: first those the
    /// round has still to reach, then the others, who start the next round,
    /// each part in the order the connections were made.
    fn place(&self, made: u64) -> (bool, u64) {
        (made <= self.last || made > self.round, made)
    }
}

/// Every chunk request outstanding, by folder and hash (module
/// documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InFlight {
    asked: BTreeMap<(FolderId, CipherHash), Asked>,
    /// The connections made so far.
    made: u64,
}

impl InFlight {
    /// A connection was made: its place in the order.
    pub(crate) fn connected(&mut self) -> u64 {
        self.made = self.made.saturating_add(1);
        self.made
    }

    /// Whose turn each hash of `folder` with requests is among `ready`, the
    /// connections that could ask now: the first of them in line that holds
    /// no request for it. Worked out once per run of the passes, so that
    /// [`InFlight::free`] looks it up.
    pub(crate) fn turns(&self, folder: FolderId, ready: &[Asker]) -> BTreeMap<CipherHash, PeerId> {
        let all = (folder, CipherHash([0; 32]))..=(folder, CipherHash([u8::MAX; 32]));
        self.asked
            .range(all)
            .filter_map(|((_, hash), a)| {
                let next = ready
                    .iter()
                    .filter(|q| !a.by.contains_key(&q.peer))
                    .min_by_key(|q| a.place(q.made))?;
                Some((*hash, next.peer))
            })
            .collect()
    }

    /// Whether `peer` may ask for `hash` now: nobody has asked for it; or
    /// `peer` holds no request for it, every connection that does was asked
    /// at least `patience` ago (or a chunk for it arrived), and it is
    /// `peer`'s turn (`turns`, from [`InFlight::turns`]).
    pub(crate) fn free(
        &self,
        folder: FolderId,
        hash: &CipherHash,
        peer: PeerId,
        now: Instant,
        patience: Duration,
        turns: &BTreeMap<CipherHash, PeerId>,
    ) -> bool {
        self.asked.get(&(folder, *hash)).is_none_or(|a| {
            !a.by.contains_key(&peer)
                && (a.answered || a.by.values().all(|at| now >= at.saturating_add(patience)))
                && turns.get(hash) == Some(&peer)
        })
    }

    /// `hash` was asked of `me` at `now`; if the round had passed `me`, a
    /// new round begins with it.
    pub(crate) fn asked(&mut self, folder: FolderId, hash: CipherHash, me: Asker, now: Instant) {
        let entry = self.asked.entry((folder, hash)).or_default();
        if entry.place(me.made).0 {
            entry.round = self.made;
        }
        entry.last = me.made;
        entry.answered = false;
        entry.by.insert(me.peer, now);
    }

    /// `peer` answered a chunk for `hash`: the other connections' requests
    /// for it stay outstanding, their answers late, and nobody is waited
    /// for any more.
    pub(crate) fn answered(&mut self, folder: FolderId, hash: &CipherHash, peer: PeerId) {
        if let Some(a) = self.asked.get_mut(&(folder, *hash)) {
            a.answered = true;
        }
        self.refused(folder, hash, peer);
    }

    /// `peer` answered `CHUNK_NOT_FOUND` or `CHUNK_BUSY` for `hash`, or a
    /// chunk: its request is no longer outstanding, and the others wait
    /// only on their own.
    pub(crate) fn refused(&mut self, folder: FolderId, hash: &CipherHash, peer: PeerId) {
        if let Some(a) = self.asked.get_mut(&(folder, *hash)) {
            a.by.remove(&peer);
        }
    }

    /// `peer`'s connection ended: its requests are gone with it.
    pub(crate) fn forget_peer(&mut self, peer: PeerId) {
        for a in self.asked.values_mut() {
            a.by.remove(&peer);
        }
    }

    /// The end of a handler: the entries whose requests have all ended go.
    pub(crate) fn sweep(&mut self) {
        self.asked.retain(|_, a| !a.by.is_empty());
    }

    /// When the next outstanding hash runs out of patience after `now`, if
    /// any does: `patience` after the latest ask still outstanding for it.
    /// A hash whose patience ran out already was offered to the passes when
    /// the patience timer fired (the engine leaves a timer that is due armed
    /// until it does), or, when a refusal or a disconnect ended its latest
    /// ask, by the passes that handler drives; and every later pass may take
    /// it.
    pub(crate) fn next_expiry(&self, patience: Duration, now: Instant) -> Option<Instant> {
        self.asked
            .values()
            .filter(|a| !a.answered)
            .filter_map(|a| a.by.values().max())
            .map(|at| at.saturating_add(patience))
            .filter(|at| *at > now)
            .min()
    }
}

#[cfg(test)]
impl InFlight {
    /// How many hashes have an entry, ended or not.
    pub(crate) fn entries(&self) -> usize {
        self.asked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOLDER: FolderId = FolderId([1; 32]);
    const HASH: CipherHash = CipherHash([2; 32]);

    fn at(secs: u64) -> Instant {
        Instant::from_secs(secs)
    }

    /// Whether `me` may ask for [`HASH`] at `secs` when the connections
    /// that could ask now are `ready`.
    fn may_at(f: &InFlight, me: Asker, secs: u64, ready: &[Asker]) -> bool {
        let turns = f.turns(FOLDER, ready);
        f.free(
            FOLDER,
            &HASH,
            me.peer,
            at(secs),
            patience(&Timing::SPEC),
            &turns,
        )
    }

    /// Whether `me` may ask for [`HASH`] at `secs`, the one connection that
    /// could ask now.
    fn alone(f: &InFlight, me: Asker, secs: u64) -> bool {
        may_at(f, me, secs, &[me])
    }

    #[test]
    fn a_hash_asked_of_one_connection_is_free_for_the_others_only_after_the_patience() {
        let mut f = InFlight::default();
        let (folder, hash) = (FOLDER, HASH);
        let a = Asker {
            peer: PeerId::new(1),
            made: 1,
        };
        let b = Asker {
            peer: PeerId::new(2),
            made: 2,
        };
        let wait = patience(&Timing::SPEC);
        assert_eq!(wait, Duration::from_secs(60));
        let t0 = at(10);
        assert!(alone(&f, a, 10));
        f.asked(folder, hash, a, t0);
        assert!(!alone(&f, b, 10));
        assert!(!alone(&f, b, 69));
        assert!(alone(&f, b, 70));
        assert!(!alone(&f, a, 700), "never twice on one connection");
        assert_eq!(f.next_expiry(wait, t0), Some(at(70)));
        assert_eq!(f.next_expiry(wait, at(70)), None, "run out already");
        f.sweep();
        assert!(!alone(&f, b, 69), "a sweep keeps a request outstanding");
        // Asked of b too: both hold it, and the patience starts again.
        f.asked(folder, hash, b, at(70));
        assert_eq!(f.next_expiry(wait, t0), Some(at(130)));
        f.refused(folder, &hash, a.peer);
        assert!(!alone(&f, a, 71));
        f.forget_peer(b.peer);
        assert!(alone(&f, a, 71));
        assert_eq!(f.next_expiry(wait, t0), None);
        f.asked(folder, hash, a, at(80));
        f.asked(folder, hash, b, at(80));
        f.answered(folder, &hash, b.peer);
        let c = Asker {
            peer: PeerId::new(3),
            made: 3,
        };
        assert!(alone(&f, c, 81), "answered: nobody is waited for");
        assert!(!alone(&f, a, 81), "a's request stays outstanding");
        assert_eq!(f.next_expiry(wait, t0), None);
        f.answered(folder, &hash, a.peer);
        assert_ne!(f, InFlight::default(), "kept until the handler ends");
        f.sweep();
        assert_eq!(f, InFlight::default());
        f.asked(folder, hash, a, t0);
        f.refused(folder, &hash, a.peer);
        f.sweep();
        assert_eq!(f, InFlight::default(), "the last refusal frees it");
    }

    #[test]
    fn a_refusal_or_a_disconnect_leaves_the_others_waiting_on_their_own_asks_only() {
        // `regressions::two_peers_never_keep_a_chunk_from_an_honest_holder_*`:
        // the hash had one ask time, the latest, which a refusal or a
        // disconnect left in place, so a connection that refused it held it
        // from the others for a whole patience after its ask.
        let mut f = InFlight::default();
        let [a, b, c] = [1, 2, 3].map(|n| Asker {
            peer: PeerId::new(n),
            made: n,
        });
        let wait = patience(&Timing::SPEC);
        f.asked(FOLDER, HASH, a, at(10));
        f.asked(FOLDER, HASH, b, at(70));
        assert!(!alone(&f, c, 129), "b was asked 59 s ago");
        assert!(alone(&f, c, 130));
        assert_eq!(f.next_expiry(wait, at(70)), Some(at(130)), "the latest ask");
        f.refused(FOLDER, &HASH, b.peer);
        assert!(alone(&f, c, 71), "a was asked 61 s ago");
        assert!(alone(&f, b, 71), "b may be asked again");
        assert_eq!(f.next_expiry(wait, at(69)), Some(at(70)), "a's alone");
        assert_eq!(f.next_expiry(wait, at(71)), None);
        f.asked(FOLDER, HASH, b, at(71));
        f.forget_peer(b.peer);
        assert!(alone(&f, c, 72), "b disconnected");
        // The latest ask sets the expiry, whichever connection sorts first.
        f.asked(FOLDER, HASH, b, at(80));
        f.refused(FOLDER, &HASH, a.peer);
        f.asked(FOLDER, HASH, a, at(90));
        assert_eq!(f.next_expiry(wait, at(90)), Some(at(150)));
        assert!(!alone(&f, c, 149), "a was asked 59 s ago");
        assert!(alone(&f, c, 150));
    }

    #[test]
    fn a_free_hash_goes_round_the_connections_that_could_ask_in_the_order_they_were_made() {
        // `regressions::two_peers_never_keep_a_chunk_from_an_honest_holder_by_taking_turns_*`:
        // the first connection free to ask took the hash whenever it was
        // free, so two peers that met this device before an honest holder
        // could hand it back and forth for good. The handles run against
        // the order the connections were made, which alone counts.
        let mut flight = InFlight::default();
        let made: Vec<u64> = (0..4).map(|_| flight.connected()).collect();
        assert_eq!(made, [1, 2, 3, 4]);
        let [one, two, three, four] = [1, 2, 3, 4].map(|n| Asker {
            peer: PeerId::new(10 - n),
            made: n,
        });
        let may = |f: &InFlight, me: Asker, ready: &[Asker]| may_at(f, me, 100, ready);
        let all = [one, two, three, four];
        assert!(
            all.iter().all(|&q| may(&flight, q, &all)),
            "nobody asked yet"
        );
        flight.asked(FOLDER, HASH, one, at(0));
        // One's patience ran out: the round goes on after it.
        assert!(may(&flight, two, &all));
        assert!(
            !may(&flight, three, &all) && !may(&flight, four, &all),
            "two first"
        );
        assert!(
            may(&flight, three, &[one, three, four]),
            "two cannot ask now"
        );
        assert!(!may(&flight, one, &all), "one holds it");
        // A connection made since the round began waits for the next one,
        // and one that holds the hash stands in nobody's way.
        let late = Asker {
            peer: PeerId::new(1),
            made: flight.connected(),
        };
        assert!(!may(&flight, late, &[two, late]));
        assert!(may(&flight, late, &[one, late]));
        flight.asked(FOLDER, HASH, two, at(100));
        flight.refused(FOLDER, &HASH, two.peer);
        let everyone = [one, two, three, four, late];
        let turn = |f: &InFlight| everyone.map(|q| may(f, q, &everyone));
        assert_eq!(turn(&flight), [false, false, true, false, false]);
        flight.asked(FOLDER, HASH, three, at(100));
        flight.refused(FOLDER, &HASH, three.peer);
        assert_eq!(turn(&flight), [false, false, false, true, false]);
        // Four cannot ask: the next round begins, with two first (one holds
        // the hash) and the late one last.
        assert!(may(&flight, two, &[two, late]) && !may(&flight, late, &[two, late]));
        flight.asked(FOLDER, HASH, two, at(100));
        flight.refused(FOLDER, &HASH, two.peer);
        assert_eq!(turn(&flight), [false, false, true, false, false]);
        assert!(
            may(&flight, four, &[four, late, two]) && !may(&flight, late, &[four, late, two]),
            "three cannot ask: four, then the late one"
        );
        assert!(
            may(&flight, late, &[late, two]),
            "the late one is in this round, two in the next"
        );
        flight.refused(FOLDER, &HASH, one.peer);
        flight.sweep();
        assert_eq!(flight.entries(), 0);
    }

    #[test]
    fn whose_turn_each_hash_is_is_worked_out_per_folder_among_those_that_could_ask() {
        let mut flight = InFlight::default();
        for _ in 0..3 {
            flight.connected();
        }
        let [one, two, three] = [1, 2, 3].map(|n| Asker {
            peer: PeerId::new(n),
            made: n,
        });
        let (low, high, other) = (
            CipherHash([0; 32]),
            CipherHash([u8::MAX; 32]),
            FolderId([9; 32]),
        );
        flight.asked(FOLDER, low, one, at(0));
        flight.asked(FOLDER, high, two, at(0));
        flight.asked(other, HASH, one, at(0));
        assert_eq!(
            flight.turns(FOLDER, &[one, two, three]),
            BTreeMap::from([(low, two.peer), (high, three.peer)]),
            "the next in line that holds no request, this folder's only"
        );
        assert_eq!(
            flight.turns(FOLDER, &[one]),
            BTreeMap::from([(high, one.peer)]),
            "nobody that could ask is free to ask for low"
        );
        assert_eq!(
            flight.turns(other, &[two, three]),
            BTreeMap::from([(HASH, two.peer)])
        );
    }
}
