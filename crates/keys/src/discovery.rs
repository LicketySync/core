// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Discovery hashes (`keys.md` section 2.2): the LAN beacon's peer tag and
//! beacon ID under a fresh salt and the current Unix minute, and the daily
//! DHT ID. The caller supplies the time (`Clock::wall_time()`); nothing here
//! reads a clock.

use crate::ids::FolderId;
use crate::labels::{self, labelled_hash};

/// A beacon's `minute` may differ from the listener's own by this much.
pub const LAN_MINUTE_WINDOW: u64 = 5;

/// `floor(unix_seconds / 60)`.
#[must_use]
pub fn unix_minute(unix_seconds: u64) -> u64 {
    unix_seconds / 60
}

/// `floor(unix_seconds / 86400)`.
#[must_use]
pub fn unix_day(unix_seconds: u64) -> u64 {
    unix_seconds / 86_400
}

/// `peer_tag = H("licketysync/v1/hash/discovery-peer", salt || peer)[0..16]`
/// where `peer` is the announcer's 32-byte libp2p identity key.
#[must_use]
pub fn peer_tag(salt: &[u8; 16], peer: &[u8; 32]) -> [u8; 16] {
    crate::bytes::first(&labelled_hash(labels::HASH_DISCOVERY_PEER, &[salt, peer]))
}

/// `lan_id = H("licketysync/v1/hash/discovery-lan", salt || folder_id || peer_tag || be64(minute))[0..16]`.
#[must_use]
pub fn lan_id(salt: &[u8; 16], folder_id: &FolderId, peer_tag: &[u8; 16], minute: u64) -> [u8; 16] {
    crate::bytes::first(&labelled_hash(
        labels::HASH_DISCOVERY_LAN,
        &[salt, folder_id.as_bytes(), peer_tag, &minute.to_be_bytes()],
    ))
}

/// Whether a beacon's `minute` is within ±5 minutes of the listener's own.
#[must_use]
pub fn minute_in_window(ours: u64, theirs: u64) -> bool {
    ours.abs_diff(theirs) <= LAN_MINUTE_WINDOW
}

/// `dht_id(day) = H("licketysync/v1/hash/discovery-dht", folder_id || be64(day))[0..20]`.
#[must_use]
pub fn dht_id(folder_id: &FolderId, day: u64) -> [u8; 20] {
    crate::bytes::first(&labelled_hash(
        labels::HASH_DISCOVERY_DHT,
        &[folder_id.as_bytes(), &day.to_be_bytes()],
    ))
}

/// The IDs a device looks up: yesterday, today and tomorrow, which covers
/// clock disagreement of up to a day. Day 0 has no yesterday; its entry is
/// today's.
#[must_use]
pub fn dht_lookup_ids(folder_id: &FolderId, today: u64) -> [[u8; 20]; 3] {
    [
        dht_id(folder_id, today.saturating_sub(1)),
        dht_id(folder_id, today),
        dht_id(folder_id, today.saturating_add(1)),
    ]
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn time_helpers_and_window() {
        assert_eq!(unix_minute(119), 1);
        assert_eq!(unix_minute(120), 2);
        assert_eq!(unix_day(86_399), 0);
        assert_eq!(unix_day(86_400), 1);
        assert!(minute_in_window(100, 105));
        assert!(minute_in_window(105, 100));
        assert!(!minute_in_window(100, 106));
        assert!(!minute_in_window(106, 100));
    }

    #[test]
    fn hashes_depend_on_every_input() {
        let salt = [1u8; 16];
        let peer = [2u8; 32];
        let folder = FolderId([3u8; 32]);
        let tag = peer_tag(&salt, &peer);
        assert_ne!(tag, peer_tag(&[9u8; 16], &peer));
        assert_ne!(tag, peer_tag(&salt, &[9u8; 32]));
        let id = lan_id(&salt, &folder, &tag, 7);
        assert_ne!(id, lan_id(&[9u8; 16], &folder, &tag, 7));
        assert_ne!(id, lan_id(&salt, &FolderId([9u8; 32]), &tag, 7));
        assert_ne!(id, lan_id(&salt, &folder, &[9u8; 16], 7));
        assert_ne!(id, lan_id(&salt, &folder, &tag, 8));
        let d = dht_id(&folder, 20_000);
        assert_ne!(d, dht_id(&folder, 20_001));
        assert_ne!(d, dht_id(&FolderId([9u8; 32]), 20_000));
        assert_eq!(
            dht_lookup_ids(&folder, 20_000),
            [dht_id(&folder, 19_999), d, dht_id(&folder, 20_001)]
        );
        assert_eq!(dht_lookup_ids(&folder, 0)[0], dht_id(&folder, 0));
    }
}
