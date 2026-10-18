// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a folder's store refused under ruling 23's quotas (rulings 24 and
//! 25). A refused record is gone for good from this verifier (the counters
//! only grow), so a record that needs it is not missing a dependency that
//! will arrive: it is validity-only ([`Validity::DependencyRefused`]), and is
//! remembered in turn, so that what needs it is validity-only as well; so is
//! a record refused for a grant not stored ([`Validity::UnprovableFault`])
//! of a key with a remembered refusal (ruling 26). Every dependency kind is
//! matched: an issuer's or signer's grant, the key a Wrap serves, a
//! Revocation's or Suspension's target, by the key ID granted; a cause, a
//! view entry or a Lift's Suspension, by hash; an epoch, by the epoch a
//! rotation refused under a quota creates. Each entry keeps the record's
//! hash and what the record would have given the store: the key a grant
//! grants, and the epoch a rotation creates when that rotation verified in
//! full before a quota refused it (ruling 29). A record remembered because
//! it needs a remembered one did not verify to the end: a grant among them
//! still provides its key, which its verified proof of possession binds,
//! and any other record provides only its hash, so an unsigned or
//! unentitled Rotation claims no epoch here. Dependencies are matched on
//! those. No other refusal is remembered. The memory is the store's own,
//! per folder, bounded, oldest forgotten first, and not persisted: after a
//! restart a peer may send a refused record once more, and it is judged
//! again, as any remembered record that arrives again is; one that is then
//! stored is forgotten. A peer with no key can push every genuine entry out
//! with [`MAX_REFUSED_REMEMBERED`] unsigned records that need a remembered
//! one, with the same result: refused records are sent again and judged
//! again.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::store::{Body, FolderKeys};
use super::{GrantBody, Missing, RecordType, Rejected, Validity};
use crate::ids::{KeyId, RecordHash};

/// The most refused records one folder's store remembers (rulings 24 and
/// 25): past this many, the oldest is forgotten.
pub const MAX_REFUSED_REMEMBERED: usize = 16_384;

/// What a refused record would have given the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provides {
    /// A grant: a stored grant for this key.
    Grant(KeyId),
    /// A rotation that verified in full before a quota refused it: this
    /// epoch.
    Epoch(u64),
    /// Nothing but itself, by its hash.
    Itself,
}

impl Provides {
    fn of(body: &Body) -> Provides {
        match body {
            Body::Grant(g) => Provides::Grant(g.key_id),
            Body::Rotation(r) => Provides::Epoch(r.new_epoch),
            _ => Provides::Itself,
        }
    }

    /// What a record not verified to the end would provide, from its body
    /// alone (ruling 29). A grant reaches a missing dependency only after its
    /// proof of possession verified, so the key it names is its holder's own
    /// and it provides that key. Any other record provides only itself, by
    /// its hash: a Rotation's epoch is judged before its signature and its
    /// entitlement, so the epoch an unverified one names is anyone's claim.
    /// Only a rotation refused under a quota once it verified in full
    /// provides an epoch.
    fn of_unverified(record_type: RecordType, body: &[u8]) -> Provides {
        match record_type {
            RecordType::Grant => {
                GrantBody::parse(body).map_or(Provides::Itself, |g| Provides::Grant(g.key_id))
            }
            _ => Provides::Itself,
        }
    }
}

/// The refused records, oldest first, with indexes by hash, granted key and
/// created epoch (counts, since two refused grants may name one key).
#[derive(Clone, Debug, Default)]
pub(crate) struct Refused {
    order: VecDeque<(RecordHash, Provides)>,
    hashes: BTreeSet<RecordHash>,
    keys: BTreeMap<KeyId, usize>,
    epochs: BTreeMap<u64, usize>,
}

impl Refused {
    /// Remembers a record refused under a quota.
    pub(crate) fn remember_refused(&mut self, hash: RecordHash, body: &Body) {
        self.remember(hash, Provides::of(body));
    }

    /// Remembers a record refused because it needs a remembered one: a
    /// grant with the key it grants, any other record by its hash alone
    /// (ruling 29).
    pub(crate) fn remember_dependent(
        &mut self,
        hash: RecordHash,
        record_type: RecordType,
        body: &[u8],
    ) {
        self.remember(hash, Provides::of_unverified(record_type, body));
    }

    /// Remembers `hash`, forgetting the oldest past
    /// [`MAX_REFUSED_REMEMBERED`]. A record refused twice is remembered once.
    fn remember(&mut self, hash: RecordHash, provides: Provides) {
        if !self.hashes.insert(hash) {
            return;
        }
        match provides {
            Provides::Grant(key) => *self.keys.entry(key).or_default() += 1,
            Provides::Epoch(epoch) => *self.epochs.entry(epoch).or_default() += 1,
            Provides::Itself => {}
        }
        self.order.push_back((hash, provides));
        while self.order.len() > MAX_REFUSED_REMEMBERED {
            if let Some((old, provided)) = self.order.pop_front() {
                self.unindex(&old, provided);
            }
        }
    }

    /// Forgets `hash`, when it is remembered: the record is stored after all.
    pub(crate) fn forget(&mut self, hash: &RecordHash) {
        if !self.hashes.contains(hash) {
            return;
        }
        if let Some(at) = self.order.iter().position(|(h, _)| h == hash) {
            if let Some((old, provided)) = self.order.remove(at) {
                self.unindex(&old, provided);
            }
        }
    }

    fn unindex(&mut self, hash: &RecordHash, provided: Provides) {
        self.hashes.remove(hash);
        match provided {
            Provides::Grant(key) => forget_one(&mut self.keys, &key),
            Provides::Epoch(epoch) => forget_one(&mut self.epochs, &epoch),
            Provides::Itself => {}
        }
    }

    /// Whether a remembered refusal grants `key`.
    pub(crate) fn grants(&self, key: &KeyId) -> bool {
        self.keys.contains_key(key)
    }

    /// The remembered hashes, oldest first.
    pub(crate) fn hashes(&self) -> impl Iterator<Item = &RecordHash> + '_ {
        self.order.iter().map(|(h, _)| h)
    }

    /// Whether a remembered refusal is what `missing` waits for, with the
    /// store at `current_epoch`: a refused grant of the key, the refused
    /// record itself, or a refused rotation to one of the epochs from
    /// `current_epoch + 1` up to the missing one.
    fn covers(&self, missing: &Missing, current_epoch: u64) -> bool {
        match missing {
            Missing::Grant(key) => self.grants(key),
            Missing::Record(hash) => self.hashes.contains(hash),
            Missing::Epoch(epoch) => {
                // An empty range is checked first: `range` panics on one
                // whose start is past its end.
                let next = current_epoch.saturating_add(1);
                next <= *epoch && self.epochs.range(next..=*epoch).next().is_some()
            }
        }
    }
}

fn forget_one<K: Ord>(counts: &mut BTreeMap<K, usize>, key: &K) {
    if let Some(n) = counts.get_mut(key) {
        *n -= 1;
        if *n == 0 {
            counts.remove(key);
        }
    }
}

impl FolderKeys {
    /// The records this store refused under a quota, or because they need
    /// one it refused so, by record hash, oldest first, at most
    /// [`MAX_REFUSED_REMEMBERED`]: the protocol crate lists them in
    /// `KeyRecordsRequest.have`, so that a peer does not send them again.
    pub fn refused_under_quota(&self) -> impl Iterator<Item = &RecordHash> + '_ {
        self.refused.hashes()
    }

    /// A missing dependency this store refused under a quota, directly or
    /// through a record that needs one, is [`Validity::DependencyRefused`]
    /// (rulings 24 and 25); anything else is returned as it is.
    pub(crate) fn after_refusals(&self, rejected: Rejected) -> Rejected {
        match rejected {
            Rejected::Missing(missing) if self.refused.covers(&missing, self.current_epoch()) => {
                Rejected::ValidityOnly(Validity::DependencyRefused(missing))
            }
            other => other,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;
    use crate::records::store_tests::{root_set, set, world};
    use crate::records::{GrantBody, LiftBody, RotationBody};
    use crate::secret::DataKey;
    use crate::suite::{Suite, Tier};

    fn hash(n: usize) -> RecordHash {
        let mut b = [0x5au8; 32];
        b[..8].copy_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
        RecordHash(b)
    }

    #[test]
    fn the_memory_is_bounded_and_forgets_the_oldest_first() {
        let w = world();
        let grant = GrantBody::parse(&w.root_grant(&set(10), Tier::Read, false).body).unwrap();
        let key = grant.key_id;
        let rotation = RotationBody::parse(
            &w.rotation(
                &root_set(),
                KeyId::ROOT,
                &DataKey::from_bytes([2; 32]),
                &[],
                None,
                vec![],
                3,
            )
            .body,
        )
        .unwrap();
        let lift = |n: usize| {
            Body::Lift(LiftBody {
                suite: Suite::ONE,
                folder_id: w.folder_id(),
                suspension: hash(n),
                signer_key_id: KeyId::ROOT,
                issued_at: 0,
            })
        };
        let mut r = Refused::default();
        r.remember_refused(hash(0), &Body::Grant(Box::new(grant.clone())));
        r.remember_refused(hash(0), &Body::Grant(Box::new(grant)));
        r.remember_refused(hash(1), &Body::Rotation(Box::new(rotation)));
        assert_eq!(r.hashes().count(), 2, "a record refused twice counts once");
        assert!(r.covers(&Missing::Grant(key), 1));
        assert!(r.covers(&Missing::Record(hash(1)), 1));
        // A refused rotation to epoch 3 is what epochs 3 and above wait for
        // from epoch 2 on, and not epoch 2, nor anything once epoch 3 is here.
        assert!(r.covers(&Missing::Epoch(3), 2) && r.covers(&Missing::Epoch(5), 1));
        assert!(!r.covers(&Missing::Epoch(2), 1));
        assert!(!r.covers(&Missing::Epoch(4), 3));
        assert!(
            !r.covers(&Missing::Epoch(3), u64::MAX),
            "no range past the end"
        );
        assert!(!r.covers(&Missing::Grant(KeyId([7; 16])), 1));
        for n in 2..MAX_REFUSED_REMEMBERED {
            r.remember_refused(hash(n), &lift(n));
        }
        assert_eq!(r.hashes().count(), MAX_REFUSED_REMEMBERED);
        assert!(r.covers(&Missing::Grant(key), 1));
        // One more forgets the grant, the next the rotation, oldest first.
        r.remember_refused(hash(MAX_REFUSED_REMEMBERED), &lift(0));
        assert_eq!(r.hashes().count(), MAX_REFUSED_REMEMBERED);
        assert_eq!(r.hashes().next(), Some(&hash(1)));
        assert!(!r.covers(&Missing::Grant(key), 1));
        assert!(!r.covers(&Missing::Record(hash(0)), 1));
        assert!(r.covers(&Missing::Epoch(3), 2));
        r.remember_refused(hash(MAX_REFUSED_REMEMBERED + 1), &lift(0));
        assert!(!r.covers(&Missing::Epoch(3), 2));
        assert_eq!(r.hashes().last(), Some(&hash(MAX_REFUSED_REMEMBERED + 1)));
        assert!(r.keys.is_empty() && r.epochs.is_empty());
    }
}
