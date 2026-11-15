// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The chunk requests outstanding across every connection, the patience
//! after which another connection may ask too, the order in which the
//! connections take their turns, and the hashes kept for a connection whose
//! pass waits (`protocol.md` 4.6, "Several connections").
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
//! asked already in it, waits for the next round. [`InFlight::ask`] works
//! out whose turn a hash is as a pass looks at it, and a connection that can
//! no longer ask (its room filled, or its pass, past the hash, came to wait)
//! is passed over when the passes run again in the same handler
//! (`Engine::drive_passes`). So peers that refuse the hash, reconnect, or
//! report more chunks stored to be asked again, even two or more taking
//! turns to hold it, are asked again only after every other connection had
//! its turn: an honest holder that can be asked when its turn comes is asked
//! within one round, after at most one turn of each connection ahead of it,
//! each turn at most about the patience (TM-22).
//!
//! **Kept for a waiting connection.** A connection whose pass waits for a
//! trigger, its latest pass having skipped a hash for another connection's
//! request or turn (`Connection::skipped`), counts in line with those that
//! may ask. When it stands first for a free hash the folder lacks, last
//! asked of another connection, the hash is kept for it
//! ([`InFlight::reserve`]), as many such hashes, in hash order, as it may
//! send requests once its trigger acts; the rest go on to the next in line,
//! as past a connection whose room is full. Nobody else may ask for a kept
//! hash until the connection does, its connection ends, or [`hold`] passes,
//! and it gets the freed-hash trigger, again whenever the passes run
//! meanwhile, which acts within that time unless the connection keeps it
//! from acting. Once the hold has passed, the connection counts as having
//! had its turn; if it asks, its request's patience counts from when the
//! hash was kept, so a turn lasts at most the patience either way.
//!
//! Bounded (TM-22): an entry names only connections that hold the request
//! open under their peer's `max_requests_in_flight`, one time each, and a
//! connection's names go when it ends; with the hash's place in the round,
//! two numbers, and the connection it is kept for, with two times. A hash
//! the folder still lacks keeps its place, two numbers, once its requests
//! have ended ([`InFlight::sweep`]), until it is stored or no longer wanted
//! ([`InFlight::keep_lacking`]): at most one entry per hash lacking.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::{CipherHash, FolderId};
use licketysync_protocol::connection::Timing;

use crate::runtime::{Instant, PeerId};

/// How long a hash asked of one connection waits for its answer before the
/// other connections may ask for it too: two Status intervals.
pub(crate) fn patience(timing: &Timing) -> Duration {
    timing.status.saturating_mul(2)
}

/// How long a hash is kept for a waiting connection: a Status interval and
/// `CHUNK_BUSY_BACKOFF`'s minimum, the longest the freed-hash trigger waits
/// to act unless the connection keeps it from acting (a `CHUNK_NOT_FOUND`
/// restarts its 1 s).
pub(crate) fn hold(timing: &Timing) -> Duration {
    timing.status.saturating_add(timing.busy_backoff)
}

/// A connection as the turns see it: its handle, and its place in the
/// order this device made its connections ([`InFlight::connected`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Asker {
    pub(crate) peer: PeerId,
    pub(crate) made: u64,
}

/// A connection whose pass waits for a trigger, and the requests it may send
/// once the trigger acts (`Connection::requests_free`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Waiting {
    pub(crate) asker: Asker,
    pub(crate) room: usize,
}

/// What a connection's pass may do with a hash ([`InFlight::ask`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ask {
    /// Ask for it.
    Free,
    /// Leave it: the connection holds a request for it.
    Own,
    /// Leave it: another connection holds a request for it or has the turn.
    /// The pass skipped it (`Connection::pass_skipped`).
    Elsewhere,
}

/// Where a hash stands in its round.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Place {
    /// The place of the connection asked last.
    last: u64,
    /// The round goes through the connections made up to this place.
    round: u64,
}

impl Place {
    /// `made` takes a turn, starting a new round, of the connections made
    /// so far (`made_so_far`), if the round had passed it.
    fn turn_of(&mut self, made: u64, made_so_far: u64) {
        if made <= self.last || made > self.round {
            self.round = made_so_far;
        }
        self.last = made;
    }

    /// The connections of `ready`, sorted by `made`, in line: first those
    /// the round has still to reach (made after the connection asked last,
    /// up to the round's end), then the others, who start the next round,
    /// each part in the order the connections were made. A binary search
    /// finds where the round stands, so the work is the connections passed,
    /// not every connection that could ask.
    fn in_line<'a>(&self, ready: &'a [Asker]) -> impl Iterator<Item = &'a Asker> {
        let after = ready.partition_point(|q| q.made <= self.last);
        let end = ready.partition_point(|q| q.made <= self.round).max(after);
        let (passed, rest) = ready.split_at(after);
        let (round, later) = rest.split_at(end - after);
        round.iter().chain(passed).chain(later)
    }
}

/// A hash kept for a waiting connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Kept {
    /// The connection.
    conn: Asker,
    /// When it was kept for it: its turn began then.
    since: Instant,
    /// When it is kept no longer: [`hold`] after `since`.
    until: Instant,
}

/// One hash's outstanding requests, or the connection it is kept for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Asked {
    /// The connections it is outstanding on, each with when it was asked
    /// there (for the connection it was kept for, when it was kept).
    by: BTreeMap<PeerId, Instant>,
    /// A chunk arrived for it from one of them: the others are not waited
    /// for.
    answered: bool,
    place: Place,
    kept_for: Option<Kept>,
}

impl Asked {
    /// Whether every connection that holds the request was asked at least
    /// `patience` before `now`, or a chunk for it arrived: another may ask.
    fn free(&self, now: Instant, patience: Duration) -> bool {
        self.answered
            || self
                .by
                .values()
                .all(|at| now >= at.saturating_add(patience))
    }

    /// Its place, the connection it was kept for counted as having had its
    /// turn once the hold has passed (`made_so_far`, the connections made).
    fn place_at(&self, now: Instant, made_so_far: u64) -> Place {
        let mut place = self.place;
        if let Some(k) = self.kept_for
            && now >= k.until
        {
            place.turn_of(k.conn.made, made_so_far);
        }
        place
    }

    /// What it is kept for now, if anything.
    fn kept(&self, now: Instant) -> Option<Kept> {
        self.kept_for.filter(|k| now < k.until)
    }

    /// The first of `line` that holds no request for it.
    fn next_of<'a>(&self, mut line: impl Iterator<Item = &'a Asker>) -> Option<Asker> {
        line.find(|q| !self.by.contains_key(&q.peer)).copied()
    }
}

/// Every chunk request outstanding, by folder and hash, and the place in
/// line of each hash still lacking whose requests have ended (module
/// documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InFlight {
    /// The hashes with a request outstanding or a connection they are kept
    /// for.
    asked: BTreeMap<(FolderId, CipherHash), Asked>,
    /// The place of each hash still lacking that has neither.
    kept: BTreeMap<(FolderId, CipherHash), Place>,
    /// The connections made so far.
    made: u64,
}

/// Every key of `folder`.
fn all_of(folder: FolderId) -> core::ops::RangeInclusive<(FolderId, CipherHash)> {
    (folder, CipherHash([0; 32]))..=(folder, CipherHash([u8::MAX; 32]))
}

impl InFlight {
    /// A connection was made: its place in the order.
    pub(crate) fn connected(&mut self) -> u64 {
        self.made = self.made.saturating_add(1);
        self.made
    }

    /// What `peer`'s pass may do with `hash` now: ask, when nobody has asked
    /// for it, or it is free and it is `peer`'s turn among `ready`, the
    /// connections that may ask now, sorted by `made`, or it is kept for
    /// `peer`; otherwise leave it, for its own request or another
    /// connection's. Costs a binary search and the connections passed.
    pub(crate) fn ask(
        &self,
        folder: FolderId,
        hash: &CipherHash,
        peer: PeerId,
        ready: &[Asker],
        now: Instant,
        patience: Duration,
    ) -> Ask {
        let key = (folder, *hash);
        let turn = if let Some(a) = self.asked.get(&key) {
            if a.by.contains_key(&peer) {
                return Ask::Own;
            }
            match a.kept(now) {
                Some(k) => Some(k.conn),
                None if a.free(now, patience) => {
                    a.next_of(a.place_at(now, self.made).in_line(ready))
                }
                None => None,
            }
        } else if let Some(place) = self.kept.get(&key) {
            place.in_line(ready).next().copied()
        } else {
            return Ask::Free;
        };
        if turn.is_some_and(|q| q.peer == peer) {
            Ask::Free
        } else {
            Ask::Elsewhere
        }
    }

    /// Keeps each hash of `folder` that is free, still `lacking` and kept
    /// for nobody, in hash order, for its next in line among `ready` and
    /// `waiting` counted together, when that is one of `waiting`, not the
    /// last asked, with room left: until `hold` after `now`. `ready` are the
    /// connections that may ask now, sorted by `made`; `waiting`, sorted
    /// likewise, those whose pass waits for a trigger, its latest pass having
    /// skipped a hash for another connection's request or turn, each with the
    /// requests it may send once its trigger acts. Each is kept no more
    /// hashes than that, counting those kept for it already; one with no
    /// room left is passed over, as a connection whose room is full is.
    /// Returns the connections of `waiting` a `lacking` hash of `folder` is
    /// kept for now, newly or still: each is owed the freed-hash trigger.
    /// Costs a look at each hash of the folder with an entry or a place, and
    /// a binary search for each free one.
    #[allow(
        clippy::too_many_arguments,
        reason = "the one call site passes what the passes already hold"
    )]
    pub(crate) fn reserve(
        &mut self,
        folder: FolderId,
        ready: &[Asker],
        waiting: &[Waiting],
        now: Instant,
        patience: Duration,
        hold: Duration,
        lacking: impl Fn(&CipherHash) -> bool,
    ) -> BTreeSet<PeerId> {
        let mut all: Vec<Asker> = ready
            .iter()
            .copied()
            .chain(waiting.iter().map(|w| w.asker))
            .collect();
        all.sort_unstable_by_key(|q| q.made);
        // The room each waiting connection has left, by `made`.
        let mut left: BTreeMap<u64, usize> =
            waiting.iter().map(|w| (w.asker.made, w.room)).collect();
        let mut owed = BTreeSet::new();
        for ((kept_folder, hash), a) in &self.asked {
            let Some(k) = a.kept(now) else {
                continue;
            };
            if let Some(n) = left.get_mut(&k.conn.made) {
                *n = n.saturating_sub(1);
                if *kept_folder == folder && lacking(hash) {
                    owed.insert(k.conn.peer);
                }
            }
        }
        let made = self.made;
        let mut free: Vec<((FolderId, CipherHash), Place)> = self
            .asked
            .range(all_of(folder))
            .filter(|((_, hash), a)| {
                a.kept(now).is_none() && a.free(now, patience) && lacking(hash)
            })
            .map(|(key, a)| (*key, a.place_at(now, made)))
            .chain(
                self.kept
                    .range(all_of(folder))
                    .filter(|((_, hash), _)| lacking(hash))
                    .map(|(key, place)| (*key, *place)),
            )
            .collect();
        free.sort_unstable_by_key(|(key, _)| *key);
        for (key, place) in free {
            let next = {
                let holds = |q: &Asker| {
                    self.asked
                        .get(&key)
                        .is_some_and(|a| a.by.contains_key(&q.peer))
                };
                place
                    .in_line(&all)
                    .find(|q| !holds(q) && left.get(&q.made).is_none_or(|n| *n > 0))
                    .copied()
            };
            let Some(w) = next.filter(|q| q.made != place.last) else {
                continue;
            };
            let Some(n) = left.get_mut(&w.made) else {
                continue;
            };
            *n = n.saturating_sub(1);
            let entry = self.asked.entry(key).or_default();
            self.kept.remove(&key);
            entry.place = place;
            entry.kept_for = Some(Kept {
                conn: w,
                since: now,
                until: now.saturating_add(hold),
            });
            owed.insert(w.peer);
        }
        owed
    }

    /// `hash` was asked of `me` at `now`; if the round had passed `me`, a
    /// new round begins with it. A hash kept for `me` is kept no longer, and
    /// its patience counts from when it was kept: a turn lasts at most the
    /// patience, whether the connection asked at once or was waited for.
    pub(crate) fn asked(&mut self, folder: FolderId, hash: CipherHash, me: Asker, now: Instant) {
        let key = (folder, hash);
        let place = self.kept.remove(&key);
        let made = self.made;
        let entry = self.asked.entry(key).or_insert_with(|| Asked {
            place: place.unwrap_or_default(),
            ..Asked::default()
        });
        let since = entry
            .kept(now)
            .filter(|k| k.conn.peer == me.peer)
            .map_or(now, |k| k.since);
        entry.place = entry.place_at(now, made);
        entry.place.turn_of(me.made, made);
        entry.kept_for = None;
        entry.answered = false;
        entry.by.insert(me.peer, since);
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

    /// `peer`'s connection ended: its requests go with it, and so does what
    /// was kept for it.
    pub(crate) fn forget_peer(&mut self, peer: PeerId) {
        for a in self.asked.values_mut() {
            a.by.remove(&peer);
            if a.kept_for.is_some_and(|k| k.conn.peer == peer) {
                a.kept_for = None;
            }
        }
    }

    /// The end of a handler, at `now`: a hash whose requests have all ended
    /// and that is kept for nobody keeps only its place if its folder still
    /// lacks it (`lacking`), and goes otherwise.
    pub(crate) fn sweep(&mut self, now: Instant, lacking: impl Fn(&FolderId, &CipherHash) -> bool) {
        let made = self.made;
        let ended: Vec<(FolderId, CipherHash)> = self
            .asked
            .iter()
            .filter(|(_, a)| a.by.is_empty() && a.kept(now).is_none())
            .map(|(key, _)| *key)
            .collect();
        for key in ended {
            if let Some(a) = self.asked.remove(&key)
                && lacking(&key.0, &key.1)
            {
                self.kept.insert(key, a.place_at(now, made));
            }
        }
    }

    /// The folder's chunks were worked out again: a place is kept only for
    /// a hash it still lacks (`lacking`).
    pub(crate) fn keep_lacking(&mut self, folder: FolderId, lacking: impl Fn(&CipherHash) -> bool) {
        let gone: Vec<(FolderId, CipherHash)> = self
            .kept
            .range(all_of(folder))
            .filter(|((_, hash), _)| !lacking(hash))
            .map(|(key, _)| *key)
            .collect();
        for key in gone {
            self.kept.remove(&key);
        }
    }

    /// When the next outstanding hash runs out of patience after `now`, if
    /// any does (`patience` after the latest ask still outstanding for it),
    /// or the next hash kept for a waiting connection is kept no longer. A
    /// hash whose patience ran out already was offered to the passes when
    /// the patience timer fired (the engine leaves a timer that is due armed
    /// until it does), or, when a refusal or a disconnect ended its latest
    /// ask, by the passes that handler drives; and every later pass may take
    /// it.
    pub(crate) fn next_expiry(&self, patience: Duration, now: Instant) -> Option<Instant> {
        let ran_out = self
            .asked
            .values()
            .filter(|a| !a.answered)
            .filter_map(|a| a.by.values().max())
            .map(|at| at.saturating_add(patience));
        let kept = self
            .asked
            .values()
            .filter_map(|a| a.kept_for.map(|k| k.until));
        ran_out.chain(kept).filter(|at| *at > now).min()
    }
}

#[cfg(test)]
impl InFlight {
    /// How many hashes have a request outstanding or are kept for a
    /// connection, and how many keep only their place.
    pub(crate) fn entries(&self) -> (usize, usize) {
        (self.asked.len(), self.kept.len())
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

    fn asker(n: u64) -> Asker {
        Asker {
            peer: PeerId::new(n),
            made: n,
        }
    }

    /// What `me` may do with `hash` at `secs` when the connections that may
    /// ask now are `ready`.
    fn ask_at(f: &InFlight, hash: CipherHash, me: Asker, secs: u64, ready: &[Asker]) -> Ask {
        let mut sorted = ready.to_vec();
        sorted.sort_unstable_by_key(|q| q.made);
        f.ask(
            FOLDER,
            &hash,
            me.peer,
            &sorted,
            at(secs),
            patience(&Timing::SPEC),
        )
    }

    /// Whether `me` may ask for [`HASH`] at `secs` when the connections
    /// that may ask now are `ready`.
    fn may_at(f: &InFlight, me: Asker, secs: u64, ready: &[Asker]) -> bool {
        ask_at(f, HASH, me, secs, ready) == Ask::Free
    }

    /// Whether `me` may ask for [`HASH`] at `secs`, the one connection that
    /// may ask now.
    fn alone(f: &InFlight, me: Asker, secs: u64) -> bool {
        may_at(f, me, secs, &[me])
    }

    /// `waiting`, each with room for 64 requests.
    fn roomy(waiting: &[Asker]) -> Vec<Waiting> {
        waiting
            .iter()
            .map(|&asker| Waiting { asker, room: 64 })
            .collect()
    }

    /// A hash its folder still lacks.
    fn lacks(_: &FolderId, _: &CipherHash) -> bool {
        true
    }

    /// A hash its folder no longer lacks.
    fn stored(_: &FolderId, _: &CipherHash) -> bool {
        false
    }

    #[test]
    fn a_hash_asked_of_one_connection_is_free_for_the_others_only_after_the_patience() {
        let mut f = InFlight::default();
        let (folder, hash) = (FOLDER, HASH);
        let (a, b) = (asker(1), asker(2));
        let wait = patience(&Timing::SPEC);
        assert_eq!(wait, Duration::from_secs(60));
        let t0 = at(10);
        assert!(alone(&f, a, 10));
        f.asked(folder, hash, a, t0);
        assert!(!alone(&f, b, 10));
        assert!(!alone(&f, b, 69));
        assert_eq!(ask_at(&f, hash, a, 69, &[a, b]), Ask::Own);
        assert_eq!(ask_at(&f, hash, b, 69, &[a, b]), Ask::Elsewhere);
        assert!(alone(&f, b, 70));
        assert!(!alone(&f, a, 700), "never twice on one connection");
        assert_eq!(f.next_expiry(wait, t0), Some(at(70)));
        assert_eq!(f.next_expiry(wait, at(70)), None, "run out already");
        f.sweep(at(11), stored);
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
        let c = asker(3);
        assert!(alone(&f, c, 81), "answered: nobody is waited for");
        assert!(!alone(&f, a, 81), "a's request stays outstanding");
        assert_eq!(f.next_expiry(wait, t0), None);
        f.answered(folder, &hash, a.peer);
        assert_ne!(f, InFlight::default(), "kept until the handler ends");
        let mut lacking = f.clone();
        f.sweep(at(81), stored);
        assert_eq!(f, InFlight::default(), "stored: nothing is kept");
        lacking.sweep(at(81), lacks);
        assert_eq!(
            lacking.entries(),
            (0, 1),
            "a chunk came and left it lacking: its place is kept"
        );
    }

    #[test]
    fn a_hash_still_lacking_keeps_its_place_in_line_once_its_requests_end() {
        // The requester forgot who was asked last for a hash once its last
        // request ended, so a hash refused, or let go by a disconnect, while
        // a waiting connection could not ask yet started its round again
        // from the first connection, and the freed-hash trigger had nothing
        // to go on.
        let mut f = InFlight::default();
        for _ in 0..3 {
            f.connected();
        }
        let [a, b, c] = [1, 2, 3].map(asker);
        f.asked(FOLDER, HASH, b, at(0));
        f.refused(FOLDER, &HASH, b.peer);
        f.sweep(at(1), lacks);
        assert_eq!(f.entries(), (0, 1), "its place kept");
        assert!(
            may_at(&f, c, 1, &[a, b, c]) && !may_at(&f, a, 1, &[a, b, c]),
            "the round goes on after b"
        );
        f.keep_lacking(FolderId([9; 32]), |_| false);
        assert_eq!(f.entries(), (0, 1), "another folder's refresh");
        f.keep_lacking(FOLDER, |_| true);
        assert_eq!(f.entries(), (0, 1), "still lacking");
        // Asked again, the place goes on from where it stood: a connection
        // made since the round began waits for the next one.
        let late = asker(f.connected());
        f.asked(FOLDER, HASH, c, at(2));
        assert_eq!(f.entries(), (1, 0));
        f.refused(FOLDER, &HASH, c.peer);
        f.sweep(at(3), lacks);
        let all = [a, b, c, late];
        assert!(
            may_at(&f, a, 3, &all) && !may_at(&f, late, 3, &all),
            "a, in the next round, before the late one"
        );
        f.keep_lacking(FOLDER, |_| false);
        assert_eq!(f, {
            let mut made = InFlight::default();
            for _ in 0..4 {
                made.connected();
            }
            made
        });
    }

    #[test]
    fn a_refusal_or_a_disconnect_leaves_the_others_waiting_on_their_own_asks_only() {
        // `regressions::two_peers_never_keep_a_chunk_from_an_honest_holder_*`:
        // the hash had one ask time, the latest, which a refusal or a
        // disconnect left in place, so a connection that refused it held it
        // from the others for a whole patience after its ask.
        let mut f = InFlight::default();
        let [a, b, c] = [1, 2, 3].map(asker);
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
        // Asked of four, the last of the round: the next round begins with
        // two (one holds the hash), and the late one comes last in it.
        let mut ended = flight.clone();
        ended.asked(FOLDER, HASH, four, at(100));
        ended.refused(FOLDER, &HASH, four.peer);
        assert_eq!(turn(&ended), [false, true, false, false, false]);
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
    }

    #[test]
    fn whose_turn_a_hash_is_is_worked_out_per_folder_and_hash_among_those_that_may_ask() {
        use Ask::{Elsewhere, Free, Own};
        let mut flight = InFlight::default();
        for _ in 0..3 {
            flight.connected();
        }
        let [one, two, three] = [1, 2, 3].map(asker);
        let (low, high, other) = (
            CipherHash([0; 32]),
            CipherHash([u8::MAX; 32]),
            FolderId([9; 32]),
        );
        let wait = patience(&Timing::SPEC);
        flight.asked(FOLDER, low, one, at(0));
        flight.asked(FOLDER, high, two, at(0));
        flight.asked(other, HASH, one, at(0));
        let all = [one, two, three];
        let turn = |hash, secs| all.map(|q| ask_at(&flight, hash, q, secs, &all));
        assert_eq!(turn(low, 59), [Own, Elsewhere, Elsewhere], "not free yet");
        assert_eq!(turn(low, 60), [Own, Free, Elsewhere]);
        assert_eq!(turn(high, 60), [Elsewhere, Own, Free]);
        assert_eq!(
            ask_at(&flight, low, two, 60, &[one]),
            Elsewhere,
            "not ready"
        );
        assert_eq!(
            flight.ask(other, &HASH, two.peer, &[two, three], at(60), wait),
            Free,
            "another folder's"
        );
    }

    #[test]
    fn whose_turn_a_hash_is_costs_a_search_and_the_connections_passed_not_every_connection() {
        // Working out the turns once looked at every connection that could
        // ask, for every hash, again on each run of the passes: about 143 ms
        // a run and 8 s a cascade at 65 536 hashes and 128 connections.
        /// Those that hold the hash, where the round stands (`last`,
        /// `round`), the next in line, and how many were looked at.
        type Case = (&'static [u64], u64, u64, Option<u64>, usize);
        let ready: Vec<Asker> = (1..=1024).map(asker).collect();
        let cases: [Case; 5] = [
            // The round goes on after 500: 501 is next.
            (&[], 500, 1024, Some(501), 1),
            // 501 to 503 hold it: passed, 504 is next.
            (&[501, 502, 503], 500, 1024, Some(504), 4),
            // The round has reached its end, at 600: the next round, from 1.
            (&[], 600, 600, Some(1), 1),
            // Connections made since the round began wait for the next.
            (&[600], 599, 600, Some(1), 2),
            // Nobody that may ask is free to.
            (&[1, 2], 1, 2, None, 2),
        ];
        for (held, last, round, next, looked) in cases {
            let some = if round == 2 {
                ready.split_at(2).0
            } else {
                &ready
            };
            let place = Place { last, round };
            let seen = core::cell::Cell::new(0);
            let found = place
                .in_line(some)
                .inspect(|_| seen.set(seen.get() + 1))
                .find(|q| !held.contains(&q.made));
            assert_eq!(
                (found.map(|q| q.made), seen.get()),
                (next, looked),
                "{place:?}"
            );
        }
    }

    #[test]
    fn a_hash_freed_for_a_waiting_connection_first_in_line_is_kept_for_it_until_the_hold() {
        // A waiting connection owed the freed-hash trigger was passed over
        // while its trigger could not act yet (inside its Status interval,
        // or within 1 s of its latest CHUNK_NOT_FOUND): the hash went to the
        // connection behind it, and a peer that took turns let it go only
        // then.
        let mut flight = InFlight::default();
        for _ in 0..4 {
            flight.connected();
        }
        let [one, two, three, four] = [1, 2, 3, 4].map(asker);
        let (wait, keep) = (patience(&Timing::SPEC), hold(&Timing::SPEC));
        assert_eq!(keep, Duration::from_secs(31));
        flight.asked(FOLDER, HASH, one, at(0));
        let reserve = |f: &mut InFlight, ready: &[Asker], waiting: &[Asker], secs: u64| {
            f.reserve(FOLDER, ready, &roomy(waiting), at(secs), wait, keep, |_| {
                true
            })
        };
        let mut f = flight.clone();
        assert!(
            reserve(&mut f, &[three], &[two], 59).is_empty(),
            "not yet free"
        );
        assert!(
            reserve(&mut f, &[two], &[three], 60).is_empty(),
            "one that may ask is first"
        );
        assert!(
            f.reserve(FOLDER, &[], &roomy(&[two]), at(60), wait, keep, |_| false)
                .is_empty(),
            "a hash no longer lacking"
        );
        assert_eq!(
            reserve(&mut f, &[three, four], &[two], 60),
            BTreeSet::from([two.peer])
        );
        assert_eq!(
            reserve(&mut f, &[three], &[two], 61),
            BTreeSet::from([two.peer]),
            "kept still: told again, kept no longer than before"
        );
        assert!(
            reserve(&mut f, &[two, three], &[four], 61).is_empty(),
            "told only while its pass waits"
        );
        assert!(
            f.reserve(FOLDER, &[], &roomy(&[two]), at(61), wait, keep, |_| false)
                .is_empty(),
            "told only while the hash lacks"
        );
        // Kept for two: three, behind it, may not ask until 91.
        assert_eq!(ask_at(&f, HASH, three, 90, &[three, four]), Ask::Elsewhere);
        assert_eq!(ask_at(&f, HASH, two, 90, &[two, three]), Ask::Free);
        assert_eq!(f.next_expiry(wait, at(60)), Some(at(91)));
        // Once the hold has passed, two counts as having had its turn.
        assert_eq!(ask_at(&f, HASH, three, 91, &[two, three, four]), Ask::Free);
        assert_eq!(
            ask_at(&f, HASH, two, 91, &[two, three, four]),
            Ask::Elsewhere
        );
        let mut after = f.clone();
        assert!(
            reserve(&mut after, &[], &[two], 91).is_empty(),
            "two had its turn"
        );
        assert_eq!(
            reserve(&mut f, &[], &[two, three], 91),
            BTreeSet::from([three.peer]),
            "kept for the next"
        );
        assert_eq!(f.next_expiry(wait, at(91)), Some(at(122)));
        // Asked of two, or two's connection ended, it is kept no longer.
        // Asked, its patience counts from when it was kept for two.
        let mut asked = flight.clone();
        reserve(&mut asked, &[], &[two], 60);
        asked.asked(FOLDER, HASH, two, at(70));
        assert_eq!(ask_at(&asked, HASH, two, 70, &[two]), Ask::Own);
        assert_eq!(ask_at(&asked, HASH, three, 70, &[three]), Ask::Elsewhere);
        assert_eq!(asked.next_expiry(wait, at(70)), Some(at(120)));
        assert_eq!(ask_at(&asked, HASH, three, 120, &[three]), Ask::Free);
        let mut gone = flight.clone();
        reserve(&mut gone, &[], &[two], 60);
        gone.forget_peer(two.peer);
        assert_eq!(ask_at(&gone, HASH, three, 61, &[three]), Ask::Free);
        // A connection is never kept a hash it was the last to refuse.
        let mut refused = flight.clone();
        refused.refused(FOLDER, &HASH, one.peer);
        refused.sweep(at(1), lacks);
        assert!(reserve(&mut refused, &[], &[one], 2).is_empty());
        assert_eq!(
            reserve(&mut refused, &[], &[one, two], 2),
            BTreeSet::from([two.peer]),
            "a hash that keeps only its place is kept for the next"
        );
        assert_eq!(refused.entries(), (1, 0));
        refused.sweep(at(3), lacks);
        assert_eq!(refused.entries(), (1, 0), "kept through the sweep");
        // A connection made meanwhile waits for the next round still.
        let late = asker(refused.connected());
        refused.sweep(at(33), lacks);
        assert_eq!(refused.entries(), (0, 1), "its place once the hold passed");
        assert_eq!(
            ask_at(&refused, HASH, three, 33, &[one, two, three]),
            Ask::Free,
            "two had its turn"
        );
        assert_eq!(
            ask_at(&refused, HASH, one, 33, &[one, late]),
            Ask::Free,
            "the next round, before the late one"
        );
    }

    #[test]
    fn a_waiting_connection_is_kept_no_more_hashes_than_it_could_ask() {
        use Ask::{Elsewhere, Free};
        // Every free hash a waiting connection stood first for was kept for
        // it, whatever its room: two waiting peers that kept their triggers
        // from acting held a whole batch from the holder by turns, which
        // then got only its room's worth each round. Kept in hash order up
        // to its room, counting those kept for it already, the rest go on
        // to the next in line.
        let mut f = InFlight::default();
        for _ in 0..4 {
            f.connected();
        }
        let [one, two, three, four] = [1, 2, 3, 4].map(asker);
        let (wait, keep) = (patience(&Timing::SPEC), hold(&Timing::SPEC));
        let hashes = [1, 2, 3, 4, 5, 6].map(|n| CipherHash([n; 32]));
        for &h in &hashes {
            f.asked(FOLDER, h, one, at(0));
        }
        let waiting = [
            Waiting {
                asker: two,
                room: 2,
            },
            Waiting {
                asker: three,
                room: 3,
            },
        ];
        let owed = f.reserve(FOLDER, &[four], &waiting, at(60), wait, keep, |_| true);
        assert_eq!(owed, BTreeSet::from([two.peer, three.peer]));
        let turns: Vec<Ask> = hashes
            .iter()
            .map(|h| ask_at(&f, *h, four, 60, &[four]))
            .collect();
        assert_eq!(
            turns,
            [Elsewhere, Elsewhere, Elsewhere, Elsewhere, Elsewhere, Free],
            "two kept the first two, three the next three, four's turn for the last"
        );
        assert_eq!(ask_at(&f, hashes[1], two, 60, &[two]), Free);
        assert_eq!(ask_at(&f, hashes[2], three, 60, &[three]), Free);
        // Counting what is kept for it already: nothing more for two or
        // three, though they are still told.
        let more = CipherHash([9; 32]);
        f.asked(FOLDER, more, one, at(1));
        let owed = f.reserve(FOLDER, &[four], &waiting, at(61), wait, keep, |_| true);
        assert_eq!(owed, BTreeSet::from([two.peer, three.peer]));
        assert_eq!(ask_at(&f, more, four, 61, &[four]), Free, "four's turn");
        // Or kept for a connection's room in another folder.
        let mut other = InFlight::default();
        for _ in 0..4 {
            other.connected();
        }
        let elsewhere = FolderId([9; 32]);
        other.asked(elsewhere, HASH, one, at(0));
        other.asked(FOLDER, more, one, at(0));
        let alone = [Waiting {
            asker: two,
            room: 1,
        }];
        other.reserve(elsewhere, &[], &alone, at(60), wait, keep, |_| true);
        let owed = other.reserve(FOLDER, &[four], &alone, at(60), wait, keep, |_| true);
        assert!(owed.is_empty(), "two's room went to the other folder");
        assert_eq!(ask_at(&other, more, four, 60, &[four]), Free);
    }
}
