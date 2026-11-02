// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Who holds what in an engine scenario: each peer's device seed and, per
//! folder, the tier of the key it holds, all from fixed bytes, so that a seed
//! replays the same run.
//!
//! The engine stores no key (`keys.md` 8.2: phase 0), so the factory builds
//! every secret afresh from here at each start and restart. Two peers may be
//! given one device seed, as if one had been restored from a backup of the
//! other (the `engine-clones` scenario).

use std::collections::BTreeMap;

use licketysync_engine::runtime::PeerId;
use licketysync_keys::secret::{DeviceSeed, WriteSecret};
use licketysync_keys::{FolderId, FolderKey, Suite, Tier, WriteKey};

/// The folder every workload writes to.
pub const MAIN: usize = 0;

/// The world of one scenario.
#[derive(Clone, Debug)]
pub struct World {
    peers: u32,
    seeds: BTreeMap<PeerId, [u8; 32]>,
    /// Each folder's write secret, by index.
    folders: Vec<[u8; 32]>,
    /// The tier each peer holds of each folder; absent: not a member.
    tiers: BTreeMap<(PeerId, usize), Tier>,
}

impl World {
    /// `peers` peers, each with a seed of its own, all holding the write key
    /// of one folder ([`MAIN`]).
    #[must_use]
    pub fn new(peers: u32) -> Self {
        let mut w = Self {
            peers,
            seeds: BTreeMap::new(),
            folders: vec![[0x10; 32]],
            tiers: BTreeMap::new(),
        };
        for p in w.ids() {
            let byte = u8::try_from(0x40 + p.as_u64()).unwrap_or(0xff);
            w.seeds.insert(p, [byte; 32]);
            w.tiers.insert((p, MAIN), Tier::Write);
        }
        w
    }

    /// The peers, `0..peers`.
    #[must_use]
    pub fn ids(&self) -> Vec<PeerId> {
        (0..u64::from(self.peers)).map(PeerId::new).collect()
    }

    /// Adds a folder nobody holds yet; its index.
    pub fn add_folder(&mut self) -> usize {
        let byte = u8::try_from(0x10 + self.folders.len()).unwrap_or(0xff);
        self.folders.push([byte; 32]);
        self.folders.len() - 1
    }

    /// `peer` holds `folder` at `tier`, or not at all for `None`.
    #[must_use]
    pub fn holds(mut self, peer: PeerId, folder: usize, tier: Option<Tier>) -> Self {
        match tier {
            Some(t) => self.tiers.insert((peer, folder), t),
            None => self.tiers.remove(&(peer, folder)),
        };
        self
    }

    /// `b` gets `a`'s device seed: a clone of `a`.
    #[must_use]
    pub fn clone_device(mut self, a: PeerId, b: PeerId) -> Self {
        if let Some(seed) = self.seeds.get(&a).copied() {
            self.seeds.insert(b, seed);
        }
        self
    }

    /// `peer`'s device seed, built afresh.
    #[must_use]
    pub fn device_seed(&self, peer: PeerId) -> DeviceSeed {
        DeviceSeed::from_bytes(self.seeds.get(&peer).copied().unwrap_or([0; 32]))
    }

    fn write_key(&self, folder: usize) -> Option<WriteKey> {
        let secret = WriteSecret::from_bytes(*self.folders.get(folder)?);
        WriteKey::from_secret(Suite::ONE, secret).ok()
    }

    /// `folder`'s key at `tier`, built afresh.
    #[must_use]
    pub fn key(&self, folder: usize, tier: Tier) -> Option<FolderKey> {
        let w = self.write_key(folder)?;
        Some(match tier {
            Tier::Write => FolderKey::from(w),
            Tier::Read => FolderKey::from(w.read_key()),
            Tier::Sealed => FolderKey::from(w.sealed_key()),
        })
    }

    /// Every key `peer` holds.
    #[must_use]
    pub fn keys_of(&self, peer: PeerId) -> Vec<FolderKey> {
        self.tiers
            .iter()
            .filter(|((p, _), _)| *p == peer)
            .filter_map(|((_, f), t)| self.key(*f, *t))
            .collect()
    }

    /// The tier `peer` holds of `folder`.
    #[must_use]
    pub fn tier(&self, peer: PeerId, folder: usize) -> Option<Tier> {
        self.tiers.get(&(peer, folder)).copied()
    }

    /// The ID of `folder`.
    #[must_use]
    pub fn folder_id(&self, folder: usize) -> Option<FolderId> {
        Some(self.write_key(folder)?.verifier().folder_id())
    }

    /// The folders, by index.
    #[must_use]
    pub fn folders(&self) -> usize {
        self.folders.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_peer_holds_the_main_folder_unless_told_otherwise() {
        let w = World::new(3).holds(PeerId::new(2), MAIN, Some(Tier::Sealed));
        assert_eq!(w.tier(PeerId::new(0), MAIN), Some(Tier::Write));
        assert_eq!(w.tier(PeerId::new(2), MAIN), Some(Tier::Sealed));
        assert_eq!(w.keys_of(PeerId::new(2)).len(), 1);
        let w = w.holds(PeerId::new(1), MAIN, None);
        assert!(w.keys_of(PeerId::new(1)).is_empty());
        assert!(w.folder_id(MAIN).is_some());
        assert!(w.folder_id(5).is_none());
    }

    #[test]
    fn clones_share_a_device_seed_and_others_do_not() {
        let mut w = World::new(3).clone_device(PeerId::new(0), PeerId::new(2));
        let b = w.add_folder();
        assert_eq!(b, 1);
        assert_eq!(w.folders(), 2);
        assert_ne!(w.folder_id(MAIN), w.folder_id(b));
        let same = |a: u64, b: u64| {
            bool::from(
                w.device_seed(PeerId::new(a))
                    .ct_eq(&w.device_seed(PeerId::new(b))),
            )
        };
        assert!(same(0, 2));
        assert!(!same(0, 1));
    }
}
