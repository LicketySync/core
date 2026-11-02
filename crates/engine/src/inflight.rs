// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The chunk requests outstanding across every connection (`protocol.md`
//! 4.6, "Passes": a hash already asked of one connection is skipped on the
//! others), and the patience after which another connection may ask too.
//!
//! A peer holding any key of the folder may be asked for any hash (ruling
//! S-3), and the protocol gives a chunk request no reply deadline, so a peer
//! that takes requests and never answers would otherwise keep each hash it
//! was asked for from every other connection for as long as it stays
//! connected. So each hash notes when it was last asked: after
//! [`patience`], twice the Status interval with no answer (decision: 60 s at
//! the spec's timing), every other connection where the folder is open may
//! ask for it as well. The slow request stays outstanding on its own
//! connection; the first chunk that arrives for the hash wins, and one that
//! arrives once the hash is stored is dropped and counted
//! (`Counters::late_chunks`). Once a chunk has arrived for the hash, any
//! connection that holds no request for it may ask at once (the chunk may
//! have been corrupt for its records), and no connection is asked twice.
//!
//! Bounded (TM-22): an entry names only connections that hold the request
//! open under their peer's `max_requests_in_flight`, and a connection's
//! names go when it ends.

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

/// One hash's outstanding requests.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Asked {
    /// When it was last asked.
    at: Instant,
    /// The connections it is outstanding on.
    by: BTreeSet<PeerId>,
    /// A chunk arrived for it from one of them: the others are not waited
    /// for.
    answered: bool,
}

/// Every chunk request outstanding, by folder and hash (module
/// documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InFlight {
    asked: BTreeMap<(FolderId, CipherHash), Asked>,
}

impl InFlight {
    /// Whether `peer` may ask for `hash` now: nobody has asked for it, or
    /// it has waited `patience` since it was last asked and `peer` holds no
    /// request for it.
    pub(crate) fn free(
        &self,
        folder: FolderId,
        hash: &CipherHash,
        peer: PeerId,
        now: Instant,
        patience: Duration,
    ) -> bool {
        self.asked.get(&(folder, *hash)).is_none_or(|a| {
            !a.by.contains(&peer) && (a.answered || now >= a.at.saturating_add(patience))
        })
    }

    /// `hash` was asked of `peer` at `now`.
    pub(crate) fn asked(&mut self, folder: FolderId, hash: CipherHash, peer: PeerId, now: Instant) {
        let entry = self.asked.entry((folder, hash)).or_insert_with(|| Asked {
            at: now,
            by: BTreeSet::new(),
            answered: false,
        });
        entry.at = now;
        entry.answered = false;
        entry.by.insert(peer);
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
    /// chunk: its request is no longer outstanding.
    pub(crate) fn refused(&mut self, folder: FolderId, hash: &CipherHash, peer: PeerId) {
        if let Some(a) = self.asked.get_mut(&(folder, *hash)) {
            a.by.remove(&peer);
            if a.by.is_empty() {
                self.asked.remove(&(folder, *hash));
            }
        }
    }

    /// `peer`'s connection ended: its requests are gone with it.
    pub(crate) fn forget_peer(&mut self, peer: PeerId) {
        self.asked.retain(|_, a| {
            a.by.remove(&peer);
            !a.by.is_empty()
        });
    }

    /// When the next outstanding hash runs out of patience after `now`, if
    /// any does. A hash whose patience ran out already was offered to the
    /// passes then, and every later pass may take it.
    pub(crate) fn next_expiry(&self, patience: Duration, now: Instant) -> Option<Instant> {
        self.asked
            .values()
            .filter(|a| !a.answered)
            .map(|a| a.at.saturating_add(patience))
            .filter(|at| *at > now)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_asked_of_one_connection_is_free_for_the_others_only_after_the_patience() {
        let mut f = InFlight::default();
        let (folder, hash) = (FolderId([1; 32]), CipherHash([2; 32]));
        let (a, b) = (PeerId::new(1), PeerId::new(2));
        let wait = patience(&Timing::SPEC);
        assert_eq!(wait, Duration::from_secs(60));
        let t0 = Instant::from_secs(10);
        assert!(f.free(folder, &hash, a, t0, wait));
        f.asked(folder, hash, a, t0);
        assert!(!f.free(folder, &hash, b, t0, wait));
        assert!(!f.free(folder, &hash, b, Instant::from_secs(69), wait));
        assert!(f.free(folder, &hash, b, Instant::from_secs(70), wait));
        assert!(
            !f.free(folder, &hash, a, Instant::from_secs(700), wait),
            "never twice on one connection"
        );
        assert_eq!(f.next_expiry(wait, t0), Some(Instant::from_secs(70)));
        assert_eq!(
            f.next_expiry(wait, Instant::from_secs(70)),
            None,
            "run out already"
        );
        // Asked of b too: both hold it, and the patience starts again.
        f.asked(folder, hash, b, Instant::from_secs(70));
        assert_eq!(f.next_expiry(wait, t0), Some(Instant::from_secs(130)));
        f.refused(folder, &hash, a);
        assert!(!f.free(folder, &hash, a, Instant::from_secs(71), wait));
        f.forget_peer(b);
        assert!(f.free(folder, &hash, a, Instant::from_secs(71), wait));
        assert_eq!(f.next_expiry(wait, t0), None);
        f.asked(folder, hash, a, t0);
        f.asked(folder, hash, b, Instant::from_secs(80));
        f.answered(folder, &hash, b);
        assert!(
            f.free(folder, &hash, PeerId::new(3), Instant::from_secs(81), wait),
            "answered: nobody is waited for"
        );
        assert!(
            !f.free(folder, &hash, a, Instant::from_secs(81), wait),
            "a's request stays outstanding"
        );
        assert_eq!(f.next_expiry(wait, t0), None);
        f.answered(folder, &hash, a);
        assert_eq!(f, InFlight::default());
        f.asked(folder, hash, a, t0);
        f.refused(folder, &hash, a);
        assert_eq!(f, InFlight::default(), "the last refusal frees it");
    }
}
