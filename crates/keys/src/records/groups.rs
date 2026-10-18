// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The grant index the chain searches run over (security review, BLOCKER 2).
//! Grants of one key from one issuer at one tier with the same `may_share`
//! are interchangeable for every authorizing link: they authorize the same
//! children and are authorized by the same parents. A **group** gathers
//! them; a search visits groups, and reaches into a group's members only to
//! pick the representative a question asks for (the smallest record hash
//! that passes its filter, or the best by the governing order). The index is
//! updated as each grant is stored, so no question ever rebuilds it, and a
//! key re-granted thousands of times by one issuer costs a search one group.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use super::GrantBody;
use crate::ids::{KeyId, RecordHash};
use crate::suite::Tier;

/// The grants of `key` issued by `issuer` at `tier` with `may_share`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Group {
    pub(crate) key: KeyId,
    pub(crate) issuer: KeyId,
    pub(crate) tier: Tier,
    pub(crate) may_share: bool,
}

impl Group {
    pub(crate) fn of(grant: &GrantBody) -> Group {
        Group {
            key: grant.key_id,
            issuer: grant.issuer_key_id,
            tier: grant.tier,
            may_share: grant.may_share,
        }
    }
}

/// How the governing order ranks a member within its group, where tier and
/// `may_share` are equal: the later or absent expiry, then the smaller hash.
pub(crate) type MemberRank = (Reverse<u64>, RecordHash);

pub(crate) fn member_rank(hash: &RecordHash, grant: &GrantBody) -> MemberRank {
    let expiry = if grant.expires_at == 0 {
        u64::MAX
    } else {
        grant.expires_at
    };
    (Reverse(expiry), *hash)
}

#[derive(Clone, Debug)]
struct Members {
    /// Every member, ascending.
    hashes: BTreeSet<RecordHash>,
    /// Each member's rank, kept so that the best is the first.
    ranked: BTreeSet<MemberRank>,
}

/// Groups by key and by issuer.
#[derive(Clone, Debug, Default)]
pub(crate) struct GroupIndex {
    members: BTreeMap<Group, Members>,
    of_key: BTreeMap<KeyId, BTreeSet<Group>>,
    by_issuer: BTreeMap<KeyId, BTreeSet<Group>>,
}

impl GroupIndex {
    pub(crate) fn insert(&mut self, hash: RecordHash, grant: &GrantBody) {
        let group = Group::of(grant);
        let members = self.members.entry(group).or_insert_with(|| Members {
            hashes: BTreeSet::new(),
            ranked: BTreeSet::new(),
        });
        members.hashes.insert(hash);
        members.ranked.insert(member_rank(&hash, grant));
        self.of_key.entry(group.key).or_default().insert(group);
        self.by_issuer
            .entry(group.issuer)
            .or_default()
            .insert(group);
    }

    pub(crate) fn remove(&mut self, hash: &RecordHash, grant: &GrantBody) {
        let group = Group::of(grant);
        let empty = self.members.get_mut(&group).is_some_and(|m| {
            m.hashes.remove(hash);
            m.ranked.remove(&member_rank(hash, grant));
            m.hashes.is_empty()
        });
        if empty {
            self.members.remove(&group);
            for index in [
                self.of_key.get_mut(&group.key),
                self.by_issuer.get_mut(&group.issuer),
            ]
            .into_iter()
            .flatten()
            {
                index.remove(&group);
            }
            self.of_key.retain(|_, g| !g.is_empty());
            self.by_issuer.retain(|_, g| !g.is_empty());
        }
    }

    pub(crate) fn groups_of(&self, key: &KeyId) -> impl Iterator<Item = &Group> + '_ {
        self.of_key.get(key).into_iter().flatten()
    }

    pub(crate) fn issued_by(&self, issuer: &KeyId) -> impl Iterator<Item = &Group> + '_ {
        self.by_issuer.get(issuer).into_iter().flatten()
    }

    /// The group's members, ascending.
    pub(crate) fn members(&self, group: &Group) -> impl Iterator<Item = &RecordHash> + '_ {
        self.members
            .get(group)
            .into_iter()
            .flat_map(|m| m.hashes.iter())
    }

    /// The group's member the governing order prefers.
    pub(crate) fn best(&self, group: &Group) -> Option<&MemberRank> {
        self.members.get(group).and_then(|m| m.ranked.first())
    }
}

/// The walk levels of phases 0 to 6, kept as grants are stored (correctness
/// review SF 3, security review BLOCKER 2): for each stored group, the number
/// of grants in its shortest authorizing walk to root, at most 16, repeats
/// allowed and nothing excluded, since phases 0 to 6 apply no Revocation or
/// Suspension and validity ignores expiry. A group's level depends only on
/// its issuer's `may_share` groups that authorize its tier, so a stored
/// group lowers its children's levels and nothing else; a key's best level
/// per tier only falls, at most 16 times, so keeping the levels costs each
/// key's children a bounded number of passes over the store's lifetime. For
/// each key and child tier the best parent (least level, then smallest
/// representative) is kept too, so a shortest walk is read in 16 steps.
#[derive(Clone, Debug, Default)]
pub(crate) struct WalkLevels {
    level: BTreeMap<Group, usize>,
    /// Per key, per tier a child may have (by tier number), the key's
    /// `may_share` group that authorizes such a child with the least level,
    /// then the smallest representative: (level, representative, group).
    share: BTreeMap<KeyId, [Option<Parent>; 4]>,
}

/// A best parent: its level, its representative, its group.
pub(crate) type Parent = (usize, RecordHash, Group);

impl WalkLevels {
    /// The group's level, if it has a walk within 16 grants.
    pub(crate) fn level(&self, group: &Group) -> Option<usize> {
        self.level.get(group).copied()
    }

    /// The best parent for a child of `tier` issued by `key`: its level, its
    /// representative and its group.
    pub(crate) fn parent(&self, key: &KeyId, tier: Tier) -> Option<&Parent> {
        self.share
            .get(key)
            .and_then(|s| s.get(usize::from(tier.as_u8())))
            .and_then(Option::as_ref)
    }

    /// Offers `group` at `level` with representative `rep` as a parent for
    /// its key's children; true when some tier's least level fell.
    fn offer(&mut self, group: Group, level: usize, rep: RecordHash) -> bool {
        let share = self.share.entry(group.key).or_insert([None; 4]);
        let mut fell = false;
        for s in share.iter_mut().skip(usize::from(group.tier.as_u8())) {
            if s.is_none_or(|(l, r, _)| (level, rep) < (l, r)) {
                fell |= s.is_none_or(|(l, _, _)| level < l);
                *s = Some((level, rep, group));
            }
        }
        fell
    }

    /// Takes in a grant just stored in `index` under `hash`: a new group's
    /// level lowers every level its walk shortens; a new member of a known
    /// group may give it a smaller representative.
    pub(crate) fn add(&mut self, group: Group, hash: RecordHash, index: &GroupIndex) {
        if let Some(level) = self.level(&group) {
            if group.may_share {
                self.offer(group, level, hash);
            }
            return;
        }
        let candidate = if group.issuer.is_root() {
            Some(1)
        } else {
            self.parent(&group.issuer, group.tier)
                .map(|(l, _, _)| l + 1)
        };
        let Some(first) = candidate.filter(|l| *l <= super::MAX_CHAIN_DEPTH) else {
            return;
        };
        // Least level first, so each group is settled at its final level once
        // per arrival.
        let mut work: BTreeSet<(usize, Group)> = BTreeSet::from([(first, group)]);
        while let Some((l, g)) = work.pop_first() {
            if self.level(&g).is_some_and(|x| x <= l) {
                continue;
            }
            self.level.insert(g, l);
            if !g.may_share {
                continue;
            }
            let Some(rep) = index.members(&g).next().copied() else {
                continue;
            };
            if !self.offer(g, l, rep) {
                continue;
            }
            for child in index.issued_by(&g.key) {
                let Some(&(parent, _, _)) = self.parent(&g.key, child.tier) else {
                    continue;
                };
                let cl = parent + 1;
                if cl <= super::MAX_CHAIN_DEPTH && self.level(child).is_none_or(|x| cl < x) {
                    work.insert((cl, *child));
                }
            }
        }
    }
}
