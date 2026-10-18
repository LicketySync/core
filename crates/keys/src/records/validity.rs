// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Chains, ancestry, validity, presentability and effective tier (`keys.md`
//! section 5.5, rulings 17 and 18).
//!
//! An **authorizing link** joins a grant `g` to a grant `p` of `g`'s issuer
//! when `p` has `may_share` and a tier at least as privileged as `g`'s (ruling
//! 17). A **chain** of a key is a sequence of at most 16 grants joined by
//! authorizing links, from a grant for the key to one root issued, visiting
//! no key ID twice; a **walk** may repeat keys. At the handshake, grants held
//! for the connection count as stored ([`super::HeldGrants`]).
//!
//! - **Ancestors** (ruling 18): the keys on some authorizing walk of at most
//!   16 grants from a grant of the key to root, validity and expiry ignored.
//!   This only grows as grants arrive, so a Revocation, Suspension or Lift
//!   entitled when it was stored stays entitled whatever arrives later. "An
//!   ancestor", "beneath", "descends from" and entitlement use it.
//! - The **canonical chain**: the key's shortest chain, valid or not, then the
//!   bytewise smallest by record hashes read from the key. It is used only
//!   where one chain must be picked: what pushes carry, and the suspensions
//!   that weigh on the tier for record entitlement.
//! - **Valid**: no key on the chain is revoked or under an active suspension
//!   to `none`. A key is **chain-valid** when some grant of it begins a valid
//!   chain; its **governing grant** is the best such grant by tier, then
//!   `may_share`, then the later or absent expiry, then the smaller record
//!   hash (by the same order over all its grants when none is valid).
//! - **Presentable chain**: a valid chain whose every grant is unexpired and
//!   along which the effective tier is not `none`. The **best** is the one
//!   with the most privileged effective tier, then the governing order of its
//!   first grant, then the shortest, then the smallest by hashes.
//!
//! Computing them. The searches run over groups ([`super::groups`]): grants
//! of one key from one issuer at one tier with the same `may_share`, which
//! are interchangeable for every link. A question about one key's own chains
//! first walks forward from the key along authorizing issuer links, which
//! names the keys any of its walks can use (its region), then searches
//! breadth-first from root over that region's groups only. An issuer is
//! expanded only when its most privileged `may_share` tier reached so far
//! improves, at most three times, and a child group takes the parent of the
//! smallest record hash among those of its level, so each grant's path read
//! from it is the bytewise smallest of its shortest walks. The queried key is
//! never a parent, so a path never returns through it (a grant to a key from
//! its own descendant begins no chain). Any other repeated key can be
//! shortcut: the grant below its first visit links straight to its second,
//! which has `may_share` and, since tiers only become more privileged towards
//! root along authorizing links, a tier that authorizes it, so the shortcut is
//! an authorizing walk through a subset of the same grants and no worse for
//! any question here; a shortest walk is therefore a chain. Ancestry is the
//! forward pass and a second breadth-first pass for each group's distance to
//! root; "beneath a key" runs the same relation backwards. Each pass reads
//! each group of its region a bounded number of times, and every result
//! depends on the set of grants only, never on the order they arrived in.

use std::collections::{BTreeMap, BTreeSet};

use super::groups::{member_rank, Group, GroupIndex, WalkLevels};
use super::held::HeldGrants;
use super::phase7::ActingTier;
use super::store::FolderKeys;
use super::{GrantBody, MAX_CHAIN_DEPTH};
use crate::ids::{KeyId, RecordHash};
use crate::keyset::SigningPublicKey;
use crate::suite::Tier;

#[cfg(test)]
thread_local! {
    /// Grants examined by the searches on this thread: the cost measure the
    /// complexity tests bound.
    pub(crate) static VISITS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Counts one grant examined (tests only).
#[inline]
fn visit() {
    #[cfg(test)]
    VISITS.with(|v| v.set(v.get().saturating_add(1)));
}

/// The tier a key acts at (section 5.5): a grant's tier lowered by every
/// active suspension on the key or on its chain. Ordered from most to least
/// privileged; [`EffectiveTier::Nothing`] (acting tier `none`, 255) is
/// greater than every tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectiveTier {
    /// Signs index records that peers apply.
    Write,
    /// Reads.
    Read,
    /// Holds ciphertext.
    Sealed,
    /// Not at all: not chain-valid or not presentable, or suspended to `none`.
    Nothing,
}

impl From<Tier> for EffectiveTier {
    fn from(t: Tier) -> Self {
        match t {
            Tier::Root | Tier::Write => EffectiveTier::Write,
            Tier::Read => EffectiveTier::Read,
            Tier::Sealed => EffectiveTier::Sealed,
        }
    }
}

impl From<ActingTier> for EffectiveTier {
    fn from(t: ActingTier) -> Self {
        match t {
            ActingTier::Read => EffectiveTier::Read,
            ActingTier::Sealed => EffectiveTier::Sealed,
            ActingTier::Nothing => EffectiveTier::Nothing,
        }
    }
}

/// The effective tiers a presentable chain can have, most privileged first.
const PRESENTABLE_TIERS: [EffectiveTier; 3] = [
    EffectiveTier::Write,
    EffectiveTier::Read,
    EffectiveTier::Sealed,
];

/// Each grant a top-down search reached, with its path to root, itself
/// first.
pub(crate) type Reach = BTreeMap<RecordHash, Vec<RecordHash>>;

/// Each group a breadth-first search reached: its level (1 for grants root
/// issued), its representative (the smallest member the search's filter
/// passes) and its parent group one level nearer root.
type Levels<'a> = BTreeMap<Group, (usize, &'a RecordHash, Option<Group>)>;

/// Each group's distance to root, from the stored levels or a search.
enum ToRoot<'a> {
    Stored(&'a WalkLevels),
    Searched(Levels<'a>),
}

impl ToRoot<'_> {
    fn get(&self, group: &Group) -> Option<usize> {
        match self {
            ToRoot::Stored(walks) => walks.level(group),
            ToRoot::Searched(levels) => levels.get(group).map(|&(d, _, _)| d),
        }
    }
}

/// A filter on the grants a search may use.
type Admit<'f> = &'f dyn Fn(&RecordHash, &GrantBody) -> bool;

/// The filter that passes every grant.
fn every(_: &RecordHash, _: &GrantBody) -> bool {
    true
}

/// The grants a search runs over: a folder's stored grants and, at the
/// handshake, the grants held for the connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Grants<'a> {
    pub(crate) keys: &'a FolderKeys,
    held: Option<&'a HeldGrants>,
}

impl<'a> Grants<'a> {
    pub(crate) fn stored(keys: &'a FolderKeys) -> Self {
        Grants { keys, held: None }
    }

    pub(crate) fn with_held(keys: &'a FolderKeys, held: &'a HeldGrants) -> Self {
        Grants {
            keys,
            held: Some(held),
        }
    }

    /// A grant by record hash, stored or held.
    pub(crate) fn get(self, hash: &RecordHash) -> Option<(&'a RecordHash, &'a GrantBody)> {
        self.keys
            .grants_by_hash(hash)
            .or_else(|| self.held.and_then(|h| h.get(hash)))
    }

    pub(crate) fn grant(self, hash: &RecordHash) -> Option<&'a GrantBody> {
        self.get(hash).map(|(_, g)| g)
    }

    /// Every grant for `key`, stored ones first, each in the order kept.
    pub(crate) fn of(self, key: &KeyId) -> Vec<(&'a RecordHash, &'a GrantBody)> {
        let mut all: Vec<_> = self.keys.grants_for(key).collect();
        if let Some(h) = self.held {
            all.extend(h.grants_for(key));
        }
        all
    }

    /// The hybrid signing key of root or of a key with a stored or held
    /// grant.
    pub(crate) fn signing_key(self, key: &KeyId) -> Option<&'a SigningPublicKey> {
        if key.is_root() {
            Some(&self.keys.folder().root_signing_pk)
        } else {
            self.of(key).first().map(|(_, g)| &g.signing_pk)
        }
    }

    fn indexes(self) -> impl Iterator<Item = &'a GroupIndex> {
        core::iter::once(&self.keys.groups).chain(self.held.map(|h| &h.groups))
    }

    /// The groups of `key`, stored and held.
    pub(crate) fn groups_of(self, key: &KeyId) -> BTreeSet<Group> {
        self.indexes()
            .flat_map(|i| i.groups_of(key).copied())
            .collect()
    }

    /// The groups `issuer` issued, stored and held.
    fn groups_issued_by(self, issuer: &KeyId) -> BTreeSet<Group> {
        self.indexes()
            .flat_map(|i| i.issued_by(issuer).copied())
            .collect()
    }

    /// The group's smallest member that `admit` passes.
    fn first_member(self, group: &Group, admit: Admit<'_>) -> Option<&'a RecordHash> {
        self.indexes()
            .filter_map(|i| {
                i.members(group).find(|h| {
                    visit();
                    self.grant(h).is_some_and(|g| admit(h, g))
                })
            })
            .min()
    }

    /// The group's members that `admit` passes.
    fn members(self, group: &Group, admit: Admit<'_>) -> Vec<(&'a RecordHash, &'a GrantBody)> {
        self.indexes()
            .flat_map(|i| i.members(group))
            .filter_map(|h| self.get(h))
            .filter(|(h, g)| admit(h, g))
            .collect()
    }

    /// The group's member the governing order prefers.
    fn best_member(self, group: &Group) -> Option<&'a RecordHash> {
        self.indexes()
            .filter_map(|i| i.best(group))
            .min()
            .and_then(|(_, h)| self.get(h).map(|(h, _)| h))
    }

    /// The stored walk levels, when this view holds no grant they leave out
    /// (a non-empty held set is not in them).
    fn walks(self) -> Option<&'a WalkLevels> {
        self.held
            .is_none_or(HeldGrants::is_empty)
            .then_some(&self.keys.walks)
    }

    /// The shortest walk of `group` from its member `hash`, by the stored
    /// levels: each step the parent group one level down with the smallest
    /// representative, so the walk read from `hash` is the bytewise smallest
    /// of the shortest. `None` when the group has no level.
    fn walk(
        self,
        walks: &WalkLevels,
        hash: &'a RecordHash,
        group: &Group,
    ) -> Option<Vec<&'a RecordHash>> {
        walks.level(group)?;
        let mut path = vec![hash];
        let mut current = *group;
        while !current.issuer.is_root() {
            visit();
            let (_, rep, parent) = walks.parent(&current.issuer, current.tier)?;
            path.push(self.get(rep)?.0);
            current = *parent;
        }
        Some(path)
    }

    /// Whether `group` has an authorizing walk to root within 16 grants
    /// through no key `avoid` names (the group's own key aside), by the
    /// stored levels: they bound every walk from below, so a parent whose
    /// shortest walk is too long is skipped, and a parent whose shortest walk
    /// already avoids those keys ends the search. Each (issuer, tier) state
    /// is revisited only with more grants to spare, at most 16 times.
    fn avoiding(self, walks: &WalkLevels, group: &Group, avoid: &dyn Fn(&KeyId) -> bool) -> bool {
        if group.issuer.is_root() {
            return true;
        }
        let mut memo: BTreeMap<(KeyId, Tier), usize> = BTreeMap::new();
        self.reaches(
            walks,
            (group.issuer, group.tier),
            MAX_CHAIN_DEPTH - 1,
            avoid,
            &mut memo,
        )
    }

    fn reaches(
        self,
        walks: &WalkLevels,
        (issuer, bound): (KeyId, Tier),
        budget: usize,
        avoid: &dyn Fn(&KeyId) -> bool,
        memo: &mut BTreeMap<(KeyId, Tier), usize>,
    ) -> bool {
        if budget == 0 || avoid(&issuer) {
            return false;
        }
        if memo.get(&(issuer, bound)).is_some_and(|b| *b >= budget) {
            return false;
        }
        memo.insert((issuer, bound), budget);
        for parent in self.groups_of(&issuer) {
            visit();
            if !parent.may_share || parent.tier > bound {
                continue;
            }
            if walks.level(&parent).is_none_or(|l| l > budget) {
                continue;
            }
            if parent.issuer.is_root() {
                return true;
            }
            let clear = self
                .first_member(&parent, &every)
                .and_then(|rep| self.walk(walks, rep, &parent))
                .is_some_and(|path| {
                    path.iter()
                        .all(|h| self.grant(h).is_some_and(|g| !avoid(&g.key_id)))
                });
            if clear || self.reaches(walks, (parent.issuer, parent.tier), budget - 1, avoid, memo) {
                return true;
            }
        }
        false
    }

    /// Whether `group` begins a chain, by its stored walk: `Some(true)` when
    /// its shortest walk avoids its own key (so is a chain), `Some(false)`
    /// when it has no walk within 16 grants (so no chain), `None` when the
    /// walk returns through the key and only a search without the key can
    /// tell.
    fn chain_by_walk(self, walks: &WalkLevels, group: &Group) -> Option<bool> {
        let Some(rep) = self.first_member(group, &every) else {
            return Some(false);
        };
        let Some(path) = self.walk(walks, rep, group) else {
            return Some(false);
        };
        let returns = path
            .iter()
            .skip(1)
            .any(|h| self.grant(h).is_some_and(|g| g.key_id == group.key));
        (!returns).then_some(true)
    }

    /// The forward pass from `key`: every key reachable from it along
    /// authorizing issuer links within 16 grants (`key` included), and the
    /// least position (1 for a group of `key`) at which each group is reached.
    /// A state is an issuer and the tier its grant must authorize; each is
    /// expanded once, so the pass reads each group at most three times.
    fn forward(self, key: &KeyId) -> (BTreeSet<KeyId>, BTreeMap<Group, usize>) {
        let mut region = BTreeSet::from([*key]);
        let mut position: BTreeMap<Group, usize> = BTreeMap::new();
        let mut seen: BTreeSet<(KeyId, Tier)> = BTreeSet::new();
        let mut frontier: Vec<(KeyId, Tier)> = Vec::new();
        for group in self.groups_of(key) {
            position.insert(group, 1);
            if !group.issuer.is_root() {
                frontier.push((group.issuer, group.tier));
            }
        }
        for depth in 2..=MAX_CHAIN_DEPTH {
            let mut next = Vec::new();
            for state in frontier {
                if !seen.insert(state) {
                    continue;
                }
                let (issuer, bound) = state;
                for group in self.groups_of(&issuer) {
                    visit();
                    if !group.may_share || group.tier > bound {
                        continue;
                    }
                    region.insert(issuer);
                    position.entry(group).or_insert(depth);
                    if !group.issuer.is_root() {
                        next.push((group.issuer, group.tier));
                    }
                }
            }
            frontier = next;
        }
        (region, position)
    }

    /// Breadth-first from root, along authorizing links, over the groups
    /// whose key is in `within` (every group when `None`) with a member that
    /// `admit` passes, to at most 16 levels. A group of `leaf` is reached but
    /// never a parent, so no walk passes through that key. See the module
    /// documentation for the expansion and tie-break rules.
    fn settle(
        self,
        within: Option<&BTreeSet<KeyId>>,
        admit: Admit<'_>,
        leaf: Option<KeyId>,
    ) -> Levels<'a> {
        // The groups searched, by issuer: within a region, only the region's
        // own, so the work follows the region and not the store.
        let scoped: Option<BTreeMap<KeyId, Vec<Group>>> = within.map(|w| {
            let mut by_issuer: BTreeMap<KeyId, Vec<Group>> = BTreeMap::new();
            for key in w {
                for group in self.groups_of(key) {
                    visit();
                    by_issuer.entry(group.issuer).or_default().push(group);
                }
            }
            by_issuer
        });
        let children = |issuer: &KeyId| -> Vec<Group> {
            match &scoped {
                Some(by_issuer) => by_issuer.get(issuer).cloned().unwrap_or_default(),
                None => self.groups_issued_by(issuer).into_iter().collect(),
            }
        };
        let mut levels = Levels::new();
        let mut frontier: Vec<Group> = Vec::new();
        for group in children(&KeyId::ROOT) {
            if let Some(rep) = self.first_member(&group, admit) {
                levels.insert(group, (1, rep, None));
                frontier.push(group);
            }
        }
        let mut expanded: BTreeMap<KeyId, Tier> = BTreeMap::new();
        for level in 2..=MAX_CHAIN_DEPTH {
            // Per issuer that improves, per tier its children may have, the
            // frontier's `may_share` group of smallest representative that
            // authorizes it.
            let mut slots: BTreeMap<KeyId, [Option<(&'a RecordHash, Group)>; 4]> = BTreeMap::new();
            for group in &frontier {
                let Some(&(_, rep, _)) = levels.get(group) else {
                    continue;
                };
                if !group.may_share
                    || leaf == Some(group.key)
                    || expanded.get(&group.key).is_some_and(|t| *t <= group.tier)
                {
                    continue;
                }
                let slot = slots.entry(group.key).or_insert([None; 4]);
                for (tier, s) in slot.iter_mut().enumerate() {
                    if usize::from(group.tier.as_u8()) <= tier && s.is_none_or(|(x, _)| rep < x) {
                        *s = Some((rep, *group));
                    }
                }
            }
            let mut next = Vec::new();
            for (issuer, slot) in &slots {
                for child in children(issuer) {
                    visit();
                    if levels.contains_key(&child) {
                        continue;
                    }
                    let Some(Some((_, parent))) = slot.get(usize::from(child.tier.as_u8())) else {
                        continue;
                    };
                    if let Some(rep) = self.first_member(&child, admit) {
                        levels.insert(child, (level, rep, Some(*parent)));
                        next.push(child);
                    }
                }
                let best = [Tier::Write, Tier::Read, Tier::Sealed]
                    .into_iter()
                    .find(|t| {
                        slot.get(usize::from(t.as_u8()))
                            .is_some_and(Option::is_some)
                    });
                if let Some(best) = best {
                    let entry = expanded.entry(*issuer).or_insert(best);
                    *entry = (*entry).min(best);
                }
            }
            frontier = next;
        }
        levels
    }

    /// The path from the grant `hash` of the reached group `group` to root,
    /// `hash` first and the parents' representatives after it.
    fn path(levels: &Levels<'a>, hash: &'a RecordHash, group: &Group) -> Vec<&'a RecordHash> {
        let mut path = vec![hash];
        let mut current = levels.get(group).and_then(|(_, _, p)| *p);
        while let Some(p) = current {
            let Some(&(_, rep, parent)) = levels.get(&p) else {
                break;
            };
            path.push(rep);
            current = parent;
        }
        path
    }

    /// The search for one key's own chains: over the key's forward region,
    /// with the key never a parent, so every path found is a chain.
    fn levels_for(self, key: &KeyId, admit: Admit<'_>) -> Levels<'a> {
        let (region, _) = self.forward(key);
        self.settle(Some(&region), admit, Some(*key))
    }

    /// The shortest chain beginning with each grant of `key` that `admit`
    /// passes everywhere along it, the grant first.
    #[cfg(test)]
    pub(crate) fn chains_of(self, key: &KeyId, admit: Admit<'_>) -> Vec<Vec<&'a RecordHash>> {
        let levels = self.levels_for(key, admit);
        self.groups_of(key)
            .iter()
            .filter(|g| levels.contains_key(g))
            .flat_map(|g| {
                self.members(g, admit)
                    .into_iter()
                    .map(|(h, _)| Self::path(&levels, h, g))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Whether the grant `hash` begins a chain whose every grant `admit`
    /// passes.
    pub(crate) fn begins_chain(self, hash: &RecordHash, admit: Admit<'_>) -> bool {
        self.get(hash).is_some_and(|(h, g)| {
            admit(h, g)
                && self
                    .levels_for(&g.key_id, admit)
                    .contains_key(&Group::of(g))
        })
    }

    /// Whether some grant of `key` begins a chain through no key `avoid`
    /// names. The stored shortest walks answer when one of them avoids those
    /// keys and the key itself; otherwise one search over the key's region
    /// decides.
    pub(crate) fn has_chain_avoiding(self, key: &KeyId, avoid: &dyn Fn(&KeyId) -> bool) -> bool {
        if avoid(key) {
            return false;
        }
        if let Some(walks) = self.walks() {
            let avoided = |k: &KeyId| k == key || avoid(k);
            return self
                .groups_of(key)
                .iter()
                .any(|g| self.avoiding(walks, g, &avoided));
        }
        let levels = self.levels_for(key, &|_, g| !avoid(&g.key_id));
        self.groups_of(key).iter().any(|g| levels.contains_key(g))
    }

    /// The key's canonical chain: the shortest of its chains, validity and
    /// expiry aside, then the bytewise smallest read from the key. Within a
    /// group the representative, the smallest member, starts the smallest.
    pub(crate) fn canonical(self, key: &KeyId) -> Option<Vec<&'a RecordHash>> {
        if let Some(walks) = self.walks() {
            // Each group's shortest walk from its smallest member; a walk that
            // returns through the key is no chain, and only matters when it
            // is no longer than the best chain found.
            let mut best: Option<Vec<&'a RecordHash>> = None;
            let mut looping = usize::MAX;
            for group in self.groups_of(key) {
                let Some(rep) = self.first_member(&group, &every) else {
                    continue;
                };
                let Some(path) = self.walk(walks, rep, &group) else {
                    continue;
                };
                if path
                    .iter()
                    .skip(1)
                    .any(|h| self.grant(h).is_some_and(|g| g.key_id == *key))
                {
                    looping = looping.min(path.len());
                } else if best
                    .as_ref()
                    .is_none_or(|b| (path.len(), &path) < (b.len(), b))
                {
                    best = Some(path);
                }
            }
            if best.as_ref().is_some_and(|b| b.len() < looping) || looping == usize::MAX {
                return best;
            }
        }
        let levels = self.levels_for(key, &every);
        self.groups_of(key)
            .iter()
            .filter_map(|g| {
                levels
                    .get(g)
                    .map(|&(_, rep, _)| Self::path(&levels, rep, g))
            })
            .min_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)))
    }

    /// Each group's distance to root, repeats allowed and nothing excluded:
    /// the stored walk levels, or a search over `region` when the view holds
    /// grants they leave out.
    fn to_root(self, region: &BTreeSet<KeyId>) -> ToRoot<'a> {
        self.walks().map_or_else(
            || ToRoot::Searched(self.settle(Some(region), &every, None)),
            ToRoot::Stored,
        )
    }

    /// The ancestors of `key` (ruling 18): the keys other than `key` on some
    /// authorizing walk of at most 16 grants from a grant of `key` to root,
    /// validity and expiry ignored. Root, the ancestor of every key, is not
    /// listed. Two breadth-first passes: each group's position on walks from
    /// the key ([`Grants::forward`]), then each group's distance to root over
    /// the same region, repeats allowed; a group at position `p` whose walk to
    /// root takes `d` grants lies on a walk of `p + d - 1`.
    pub(crate) fn ancestors(self, key: &KeyId) -> BTreeSet<KeyId> {
        let (region, position) = self.forward(key);
        let to_root = self.to_root(&region);
        position
            .into_iter()
            .filter_map(|(group, at)| {
                let d = to_root.get(&group)?;
                (at >= 2 && at + d - 1 <= MAX_CHAIN_DEPTH && group.key != *key).then_some(group.key)
            })
            .collect()
    }

    /// Whether `ancestor` is an ancestor of `key` ([`Grants::ancestors`]),
    /// stopping at the first walk that shows it: the forward pass from `key`
    /// in order of position, each group of `ancestor` it reaches checked
    /// against its distance to root. Entitlement asks this of one signer.
    pub(crate) fn is_ancestor(self, ancestor: &KeyId, key: &KeyId) -> bool {
        if ancestor == key {
            return false;
        }
        let walks = self.walks();
        let mut seen: BTreeSet<(KeyId, Tier)> = BTreeSet::new();
        let mut frontier: Vec<(KeyId, Tier)> = self
            .groups_of(key)
            .into_iter()
            .filter(|g| !g.issuer.is_root())
            .map(|g| (g.issuer, g.tier))
            .collect();
        let mut region: Option<BTreeSet<KeyId>> = None;
        for depth in 2..=MAX_CHAIN_DEPTH {
            let mut next = Vec::new();
            for state in frontier {
                if !seen.insert(state) {
                    continue;
                }
                let (issuer, bound) = state;
                for group in self.groups_of(&issuer) {
                    visit();
                    if !group.may_share || group.tier > bound {
                        continue;
                    }
                    if group.key == *ancestor {
                        let to_root = walks.map_or_else(
                            || {
                                let region = region.get_or_insert_with(|| self.forward(key).0);
                                self.settle(Some(region), &every, None)
                                    .get(&group)
                                    .map(|&(d, _, _)| d)
                            },
                            |w| w.level(&group),
                        );
                        if to_root.is_some_and(|d| depth + d - 1 <= MAX_CHAIN_DEPTH) {
                            return true;
                        }
                    }
                    if !group.issuer.is_root() {
                        next.push((group.issuer, group.tier));
                    }
                }
            }
            frontier = next;
        }
        false
    }

    /// The keys beneath `top`: every key other than `top` of which `top` is
    /// an ancestor ([`Grants::ancestors`]), found by running the same walks
    /// backwards. Each group of `top` that reaches root starts at its
    /// distance to root; a group issued by a key whose reached group
    /// authorizes it is one further; a group whose walk is at most 16 grants
    /// long makes its key one beneath `top`.
    pub(crate) fn beneath(self, top: &KeyId) -> BTreeSet<KeyId> {
        let (region, _) = self.forward(top);
        let to_root = self.to_root(&region);
        let mut level: BTreeSet<Group> = BTreeSet::new();
        let mut at_level: Vec<Vec<Group>> = vec![Vec::new(); MAX_CHAIN_DEPTH + 1];
        for group in self.groups_of(top) {
            if let Some(d) = to_root.get(&group) {
                if let Some(slot) = at_level.get_mut(d) {
                    level.insert(group);
                    slot.push(group);
                }
            }
        }
        // The most privileged `may_share` tier among each key's reached groups.
        let mut share: BTreeMap<KeyId, Tier> = BTreeMap::new();
        let mut out = BTreeSet::new();
        for l in 1..=MAX_CHAIN_DEPTH {
            let here = at_level.get_mut(l).map(core::mem::take).unwrap_or_default();
            let mut improved: BTreeMap<KeyId, Tier> = BTreeMap::new();
            for group in here {
                out.insert(group.key);
                let better = share.get(&group.key).is_none_or(|t| group.tier < *t)
                    && improved.get(&group.key).is_none_or(|t| group.tier < *t);
                if group.may_share && better {
                    improved.insert(group.key, group.tier);
                }
            }
            for (issuer, tier) in improved {
                share.insert(issuer, tier);
                if l == MAX_CHAIN_DEPTH {
                    continue;
                }
                for child in self.groups_issued_by(&issuer) {
                    visit();
                    if child.tier >= tier && level.insert(child) {
                        if let Some(slot) = at_level.get_mut(l + 1) {
                            slot.push(child);
                        }
                    }
                }
            }
        }
        out.remove(top);
        out
    }

    /// Every grant `allowed` admits that begins an authorizing walk to root,
    /// of at most 16 grants, through keys for which `dead` does not hold, with
    /// its shortest such walk (the bytewise smallest among equally short
    /// ones), itself first: the top-down form over every grant, for the phase
    /// 7 rotation checks, which ask it of every grant in a view at once. The
    /// rotation checks ask whether a key has a chain (some grant of it begins
    /// one) and what its most privileged such grant is, and a walk from a
    /// grant `g` that returns through another grant `g'` of the same key
    /// contains the walk from `g'`, a grant at least as privileged as `g` with
    /// a shorter walk, so both answers are the same as over chains.
    pub(crate) fn propagate(
        self,
        dead: &dyn Fn(&KeyId) -> bool,
        allowed: &dyn Fn(&RecordHash) -> bool,
    ) -> Reach {
        let admit = |h: &RecordHash, g: &GrantBody| allowed(h) && !dead(&g.key_id);
        let levels = self.settle(None, &admit, None);
        let mut reach = Reach::new();
        for group in levels.keys() {
            for (h, _) in self.members(group, &admit) {
                let path = Self::path(&levels, h, group).into_iter().copied().collect();
                reach.insert(*h, path);
            }
        }
        reach
    }
}

impl FolderKeys {
    /// Whether a stored Revocation names `key`.
    pub(crate) fn revoked(&self, key: &KeyId) -> bool {
        self.revocations_by_key
            .get(key)
            .is_some_and(|r| !r.is_empty())
    }

    /// The acting tiers of the suspensions on `key` that are active at
    /// `now_unix`: within their window and not lifted.
    pub(crate) fn active_suspensions(
        &self,
        key: &KeyId,
        now_unix: u64,
    ) -> impl Iterator<Item = ActingTier> + '_ {
        self.suspensions_by_key
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(move |h| match self.entries.get(h).map(|e| &e.body) {
                Some(super::store::Body::Suspension(s))
                    if s.in_window(now_unix) && !self.is_lifted(h) =>
                {
                    Some(s.acting_tier)
                }
                _ => None,
            })
    }

    /// Revoked, or under an active suspension to `none`.
    pub(crate) fn dead(&self, key: &KeyId, now_unix: u64) -> bool {
        self.revoked(key)
            || self
                .active_suspensions(key, now_unix)
                .any(|t| t == ActingTier::Nothing)
    }

    /// The stored grants as a search sees them.
    pub(crate) fn stored_grants(&self) -> Grants<'_> {
        Grants::stored(self)
    }

    /// [`Grants::propagate`] over the stored grants.
    pub(crate) fn propagate(
        &self,
        dead: &dyn Fn(&KeyId) -> bool,
        allowed: &dyn Fn(&RecordHash) -> bool,
    ) -> Reach {
        self.stored_grants().propagate(dead, allowed)
    }

    pub(crate) fn grants_by_hash(&self, hash: &RecordHash) -> Option<(&RecordHash, &GrantBody)> {
        self.entries
            .get_key_value(hash)
            .and_then(|(h, e)| match &e.body {
                super::store::Body::Grant(g) => Some((h, g.as_ref())),
                _ => None,
            })
    }
}

/// The section 5.5 predicates for one folder at one wall-clock instant, over
/// its stored grants ([`FolderKeys::validity`]) or its stored and held ones
/// ([`FolderKeys::validity_with`]). Every question runs its own search over
/// the grants above (or below) the key it names; nothing is computed for the
/// whole folder.
///
/// In phases 0 to 6 stored Revocations, Suspensions and Lifts are stored,
/// forwarded and checked but never applied (ruling 21): a chain is valid when
/// it exists, and the effective tier is the governing grant's. The crate's
/// own phase 7 checks, and the issues that report what a verifier knows of a
/// signer, build the predicates with those records applied.
#[derive(Clone, Copy, Debug)]
pub struct KeyValidity<'a> {
    grants: Grants<'a>,
    now_unix: u64,
    /// Whether stored Revocations, Suspensions and Lifts count (phase 7).
    applied: bool,
}

impl<'a> KeyValidity<'a> {
    pub(crate) fn over(grants: Grants<'a>, now_unix: u64, applied: bool) -> Self {
        KeyValidity {
            grants,
            now_unix,
            applied,
        }
    }

    fn live(&self, grant: &GrantBody) -> bool {
        !self.applied || !self.grants.keys.dead(&grant.key_id, self.now_unix)
    }

    /// The acting tiers of the active suspensions on `key` that count.
    fn suspensions(&self, key: &KeyId) -> Vec<ActingTier> {
        if self.applied {
            self.grants
                .keys
                .active_suspensions(key, self.now_unix)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// The least privileged acting tier of the active suspensions on `key`
    /// that count ([`EffectiveTier::Write`] when there are none).
    fn suspension_level(&self, key: &KeyId) -> EffectiveTier {
        self.suspensions(key)
            .into_iter()
            .map(EffectiveTier::from)
            .fold(EffectiveTier::Write, Ord::max)
    }

    /// The groups of `key` whose grants begin a valid chain (validity is a
    /// property of keys, so a group's members are valid together).
    fn valid_groups(&self, key: &KeyId) -> Vec<Group> {
        let groups = self.grants.groups_of(key);
        let walks = self.grants.walks().filter(|_| !self.applied);
        let mut exact: Option<Levels<'a>> = None;
        groups
            .into_iter()
            .filter(|g| {
                if let Some(answer) = walks.and_then(|w| self.grants.chain_by_walk(w, g)) {
                    return answer;
                }
                // Phase 0 to 6 validity is the existence of a chain: a walk
                // that avoids the key, which the stored levels find quickly.
                if let Some(w) = walks {
                    return self.grants.avoiding(w, g, &|k| k == key);
                }
                exact
                    .get_or_insert_with(|| self.grants.levels_for(key, &|_, b| self.live(b)))
                    .contains_key(g)
            })
            .collect()
    }

    /// The governing order over groups, by each group's best member.
    fn best_of(
        &self,
        groups: impl Iterator<Item = Group>,
    ) -> Option<(&'a RecordHash, &'a GrantBody)> {
        groups
            .filter_map(|g| {
                let hash = self.grants.best_member(&g)?;
                let (h, body) = self.grants.get(hash)?;
                Some(((g.tier, !g.may_share, member_rank(h, body)), (h, body)))
            })
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, best)| best)
    }

    /// Whether this grant (by record hash) begins a valid chain.
    #[must_use]
    pub fn is_grant_valid(&self, grant: &RecordHash) -> bool {
        let Some(body) = self.grants.grant(grant) else {
            return false;
        };
        if let Some(w) = self.grants.walks().filter(|_| !self.applied) {
            let group = Group::of(body);
            return self
                .grants
                .chain_by_walk(w, &group)
                .unwrap_or_else(|| self.grants.avoiding(w, &group, &|k| *k == group.key));
        }
        self.grants.begins_chain(grant, &|_, g| self.live(g))
    }

    /// Chain-valid (section 5.5): used when accepting records the key signs.
    /// Root is always valid. Expiry plays no part.
    #[must_use]
    pub fn is_chain_valid(&self, key: &KeyId) -> bool {
        key.is_root() || !self.valid_groups(key).is_empty()
    }

    /// The key's governing grant: its chain-valid grant with the most
    /// privileged tier (then `may_share`, then later or absent expiry, then
    /// the smaller hash), or the most privileged grant when none is
    /// chain-valid. `None` when no grant is known, and for root.
    #[must_use]
    pub fn governing_grant(&self, key: &KeyId) -> Option<(&'a RecordHash, &'a GrantBody)> {
        self.best_of(self.valid_groups(key).into_iter())
            .or_else(|| self.best_of(self.grants.groups_of(key).into_iter()))
    }

    /// The key's canonical chain (section 5.5): its shortest chain, valid or
    /// not and expired or not, then the bytewise smallest by record hashes
    /// read from the key; the key's grant first and the grant root issued
    /// last. The chain pushes carry. Empty for root and for a key with no
    /// chain within 16 grants.
    #[must_use]
    pub fn canonical_chain(&self, key: &KeyId) -> Vec<(&'a RecordHash, &'a GrantBody)> {
        self.grants
            .canonical(key)
            .map(|path| {
                path.into_iter()
                    .filter_map(|p| self.grants.get(p))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The key's ancestors (ruling 18): the keys on some authorizing walk of
    /// at most 16 grants from a grant of the key to root, validity and expiry
    /// ignored, the key itself excluded. Root, the ancestor of every key, is
    /// not listed.
    #[must_use]
    pub fn ancestors(&self, key: &KeyId) -> BTreeSet<KeyId> {
        self.grants.ancestors(key)
    }

    /// Whether any active suspension that counts, at any acting tier, is on
    /// the key or on an ancestor: such a key may not issue, revoke, suspend,
    /// lift or rotate. Always false in phases 0 to 6 (ruling 21).
    #[must_use]
    pub fn under_suspension(&self, key: &KeyId) -> bool {
        self.applied
            && (!self.suspensions(key).is_empty()
                || self
                    .ancestors(key)
                    .iter()
                    .any(|a| !self.suspensions(a).is_empty()))
    }

    /// The effective tier for record entitlement (section 5.5): the least
    /// privileged of the governing grant's tier and every active suspension's
    /// acting tier on the key or on a key of its canonical chain, insensitive
    /// to expiry; [`EffectiveTier::Nothing`] for a key that is not
    /// chain-valid. Root acts at write.
    #[must_use]
    pub fn effective_tier(&self, key: &KeyId) -> EffectiveTier {
        if key.is_root() {
            return EffectiveTier::Write;
        }
        if !self.is_chain_valid(key) {
            return EffectiveTier::Nothing;
        }
        let own = self
            .governing_grant(key)
            .map_or(EffectiveTier::Nothing, |(_, g)| g.tier.into());
        let mut on_chain: BTreeSet<KeyId> = self
            .canonical_chain(key)
            .iter()
            .map(|(_, g)| g.key_id)
            .collect();
        on_chain.insert(*key);
        on_chain
            .iter()
            .map(|k| self.suspension_level(k))
            .fold(own, Ord::max)
    }

    /// The best presentable chain's effective tier and path, first grant
    /// first, the suite aside. A chain is presentable at a tier when every
    /// grant on it is unexpired, every key on it live and suspended no lower
    /// than that tier, and its first grant's tier is at least that tier.
    fn best_presentable(&self, key: &KeyId) -> Option<(EffectiveTier, Vec<&'a RecordHash>)> {
        if key.is_root() {
            return None;
        }
        if let Some(found) = self.presentable_by_walk(key) {
            return found;
        }
        PRESENTABLE_TIERS.iter().find_map(|level| {
            let admit = |_: &RecordHash, g: &GrantBody| {
                g.unexpired_at(self.now_unix)
                    && self.live(g)
                    && self.suspension_level(&g.key_id) <= *level
            };
            let levels = self.grants.levels_for(key, &admit);
            self.grants
                .groups_of(key)
                .into_iter()
                .filter(|g| EffectiveTier::from(g.tier) <= *level && levels.contains_key(g))
                .filter_map(|g| {
                    // The group's best member that is itself unexpired.
                    let (h, body) = self
                        .grants
                        .members(&g, &admit)
                        .into_iter()
                        .min_by_key(|(h, body)| member_rank(h, body))?;
                    let rank = (g.tier, !g.may_share, member_rank(h, body));
                    Some((rank, Grants::path(&levels, h, &g)))
                })
                .min_by(|a, b| a.0.cmp(&b.0))
                .map(|(_, path)| (*level, path))
        })
    }

    /// The phase 0 to 6 shortcut for [`KeyValidity::best_presentable`]: with
    /// nothing suspended, a chain's effective tier is its first grant's, so
    /// the best presentable chain starts with the best-ranked unexpired grant
    /// of the key that has an unexpired chain. Candidates are taken in that
    /// order; a candidate whose stored shortest walk is unexpired and avoids
    /// the key wins with that walk (also its shortest presentable chain), one
    /// without any walk is passed over, and any other case is left to the
    /// search (`None`).
    #[allow(
        clippy::option_option,
        reason = "None defers to the search; Some(None) is a final no"
    )]
    fn presentable_by_walk(
        &self,
        key: &KeyId,
    ) -> Option<Option<(EffectiveTier, Vec<&'a RecordHash>)>> {
        let walks = self.grants.walks().filter(|_| !self.applied)?;
        let unexpired = |_: &RecordHash, g: &GrantBody| g.unexpired_at(self.now_unix);
        let mut candidates: Vec<_> = self
            .grants
            .groups_of(key)
            .into_iter()
            .flat_map(|g| {
                self.grants
                    .members(&g, &unexpired)
                    .into_iter()
                    .map(move |(h, b)| ((g.tier, !g.may_share, member_rank(h, b)), h, g))
            })
            .collect();
        candidates.sort_by_key(|c| c.0);
        for (_, hash, group) in candidates {
            let Some(path) = self.grants.walk(walks, hash, &group) else {
                continue;
            };
            let clean = path.iter().skip(1).all(|h| {
                self.grants
                    .grant(h)
                    .is_some_and(|g| g.key_id != *key && g.unexpired_at(self.now_unix))
            });
            if !clean {
                return None;
            }
            return Some(Some((EffectiveTier::from(group.tier), path)));
        }
        Some(None)
    }

    /// The phase 0 to 6 shortcut for [`KeyValidity::may_issue`]'s chain: an
    /// unexpired `may_share` grant of the issuer at `tier` or above whose
    /// stored shortest walk is unexpired and avoids the issuer. `None` leaves
    /// a walk that does not settle it to the search.
    fn issuing_by_walk(&self, issuer: &KeyId, tier: Tier) -> Option<bool> {
        let walks = self.grants.walks().filter(|_| !self.applied)?;
        let unexpired = |_: &RecordHash, g: &GrantBody| g.unexpired_at(self.now_unix);
        let mut unsure = false;
        for group in self.grants.groups_of(issuer) {
            if !group.may_share || group.tier > tier {
                continue;
            }
            for (hash, _) in self.grants.members(&group, &unexpired) {
                let Some(path) = self.grants.walk(walks, hash, &group) else {
                    continue;
                };
                let clean = path.iter().skip(1).all(|h| {
                    self.grants
                        .grant(h)
                        .is_some_and(|g| g.key_id != *issuer && g.unexpired_at(self.now_unix))
                });
                if clean {
                    return Some(true);
                }
                unsure = true;
            }
        }
        (!unsure).then_some(false)
    }

    /// Whether the key's suite is at or above the folder's minimum (every
    /// grant of one key carries the same suite, which its ID binds).
    fn suite_allowed(&self, key: &KeyId) -> bool {
        self.grants
            .of(key)
            .first()
            .is_some_and(|(_, g)| g.suite >= self.grants.keys.folder().minimum_suite)
    }

    /// Presentable (section 5.5): some grant of the key begins a presentable
    /// chain, a valid chain whose every grant is unexpired at the wall clock
    /// and along which the effective tier is not `none`, and the key's suite
    /// is at or above the folder's minimum. Used at the handshake and before
    /// a key issues, revokes, suspends, lifts or rotates. Root never presents.
    #[must_use]
    pub fn is_presentable(&self, key: &KeyId) -> bool {
        self.suite_allowed(key) && self.best_presentable(key).is_some()
    }

    /// The tier the key presents at: its best presentable chain's effective
    /// tier, the most privileged any presentable chain gives it;
    /// [`EffectiveTier::Nothing`] for a key that is not presentable.
    #[must_use]
    pub fn presentable_tier(&self, key: &KeyId) -> EffectiveTier {
        match self.best_presentable(key) {
            Some((tier, _)) if self.suite_allowed(key) => tier,
            _ => EffectiveTier::Nothing,
        }
    }

    /// The key's best presentable chain, the key's grant first and the grant
    /// root issued last (a `FolderProof` and a link's bundle carry it parent
    /// first, so reversed). Empty for a key that is not presentable.
    #[must_use]
    pub fn presentable_chain(&self, key: &KeyId) -> Vec<(&'a RecordHash, &'a GrantBody)> {
        if !self.suite_allowed(key) {
            return Vec::new();
        }
        self.best_presentable(key)
            .map(|(_, path)| {
                path.into_iter()
                    .filter_map(|p| self.grants.get(p))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether `issuer` may issue a grant at `tier` now: root always; another
    /// key when presentable and under no active suspension, when its governing
    /// grant has `may_share` and a tier at or above `tier` (the authority
    /// peers check, section 5.4 step 8), and when some grant of it with
    /// `may_share` and such a tier begins a presentable chain with no key on
    /// it suspended at all, so that the issued key could present through it
    /// (ruling 17: an issuer whose temporary raise expired cannot hand out
    /// keys under it).
    #[must_use]
    pub fn may_issue(&self, issuer: &KeyId, tier: Tier) -> bool {
        if issuer.is_root() {
            return true;
        }
        let authority = self
            .governing_grant(issuer)
            .is_some_and(|(_, g)| g.may_share && g.tier <= tier);
        let unsuspended = |_: &RecordHash, g: &GrantBody| {
            g.unexpired_at(self.now_unix)
                && self.live(g)
                && self.suspension_level(&g.key_id) == EffectiveTier::Write
        };
        let through = self.issuing_by_walk(issuer, tier).unwrap_or_else(|| {
            let levels = self.grants.levels_for(issuer, &unsuspended);
            self.grants
                .groups_of(issuer)
                .iter()
                .any(|g| g.may_share && g.tier <= tier && levels.contains_key(g))
        });
        authority && through && self.is_presentable(issuer) && !self.under_suspension(issuer)
    }
}
