// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the engine keeps in the runtime's [`Storage`]: the key layout, the
//! index's stored state loaded for [`licketysync_index::Index::open`], each
//! handler's [`ChangeSet`] staged for its one commit, and the chunk blobs
//! with their markers and the pending-free list (`protocol.md` 4.7 item 1).
//!
//! # Key layout
//!
//! `<f>` is the folder's 32-byte ID, so a folder under a new write key, which
//! is a new folder ID, starts with a fresh store (`protocol.md` 4.4,
//! "Opening a folder"). Every number is big-endian.
//!
//! | Key | Value |
//! | --- | --- |
//! | `e/r/<f>/<record hash>` | a record held: its local sequence number (8 bytes), then its envelope exactly as received |
//! | `e/b/<f>/<record hash>` | a record kept only as a base: its envelope |
//! | `e/s/<f>/<path tag><place>` | a base slot: the record hash there; `<place>` is `0` for the path itself, or `1` and the copy's name |
//! | `e/m/<f>` | the folder's metadata: high-water mark, next local sequence number, index epoch (8 bytes each) |
//! | `e/p/<f>/<device ID>` | the per-peer state: epoch, cursor, when the last round ended, the names window and its count (8 bytes each), caught up (1 byte) |
//! | `e/c/<f>/<cipher hash>` | a stored chunk blob (`nonce \|\| ciphertext`) |
//! | `e/h/<f>/<cipher hash>` | empty: marks a stored chunk, so a start scans these keys and not the blobs |
//! | `e/f/<f>/<cipher hash>` | empty: a chunk no held record named when its record went, freed at the end of the next round |
//! | `e/probe` | the resume probe's last write (empty) |
//! | `w/…` | the harness's, never the engine's |
//!
//! No key is stored (`keys.md` 8.2: phase 0 stores no key): the device seed
//! and the folder keys come from the config at every start. The store is
//! trusted to keep what it is given, not for its authenticity: every record
//! and base it returns is checked again when the folder opens (TM-9), and an
//! entry that does not decode is counted, never a panic.
//!
//! # Durability comes at the handler's commit
//!
//! What a handler stages here becomes durable at its one commit, before it
//! sends anything that carries a record or a chunk (`protocol.md` 4.5,
//! "Durability before transmission"; the `work` module). The runtime's
//! storage stages atomically, so a failed commit leaves nothing of the
//! handler, and the index undoes its own changes ([`licketysync_index::Pending`]).

use std::collections::BTreeSet;

use licketysync_index::{ChangeSet, PeerState, Place, Stored, StoredMeta};
use licketysync_keys::records::SignedRecord;
use licketysync_keys::{CipherHash, DeviceId, FolderId, PathTag, RecordHash};

use crate::runtime::{Storage, StorageError};

/// The prefix of every record held.
const RECORDS: &[u8] = b"e/r/";
/// The prefix of every record kept only as a base.
const BASE_ONLY: &[u8] = b"e/b/";
/// The prefix of every base slot.
const SLOTS: &[u8] = b"e/s/";
/// The prefix of every folder's metadata.
const META: &[u8] = b"e/m/";
/// The prefix of every per-peer state.
const PEERS: &[u8] = b"e/p/";
/// The prefix of every stored chunk blob.
const CHUNKS: &[u8] = b"e/c/";
/// The prefix of every stored-chunk marker.
const HELD: &[u8] = b"e/h/";
/// The prefix of every pending free.
const FREES: &[u8] = b"e/f/";
/// The resume probe's key.
pub(crate) const PROBE: &[u8] = b"e/probe";

fn prefix(kind: &[u8], folder: &FolderId) -> Vec<u8> {
    let mut key = Vec::with_capacity(kind.len() + 33 + 64);
    key.extend_from_slice(kind);
    key.extend_from_slice(folder.as_bytes());
    key.push(b'/');
    key
}

fn key_of(kind: &[u8], folder: &FolderId, id: &[u8]) -> Vec<u8> {
    let mut key = prefix(kind, folder);
    key.extend_from_slice(id);
    key
}

/// `e/r/<f>/<record hash>`.
pub(crate) fn record_key(folder: &FolderId, hash: &RecordHash) -> Vec<u8> {
    key_of(RECORDS, folder, hash.as_bytes())
}

/// `e/c/<f>/<cipher hash>`.
pub(crate) fn chunk_key(folder: &FolderId, hash: &CipherHash) -> Vec<u8> {
    key_of(CHUNKS, folder, hash.as_bytes())
}

/// `e/h/<f>/<cipher hash>`.
pub(crate) fn held_key(folder: &FolderId, hash: &CipherHash) -> Vec<u8> {
    key_of(HELD, folder, hash.as_bytes())
}

/// `e/f/<f>/<cipher hash>`.
pub(crate) fn free_key(folder: &FolderId, hash: &CipherHash) -> Vec<u8> {
    key_of(FREES, folder, hash.as_bytes())
}

fn slot_key(folder: &FolderId, tag: &PathTag, place: &Place) -> Vec<u8> {
    let mut id = tag.as_bytes().to_vec();
    match place {
        Place::Path => id.push(0),
        Place::Copy(name) => {
            id.push(1);
            id.extend_from_slice(name.as_bytes());
        }
    }
    key_of(SLOTS, folder, &id)
}

fn meta_key(folder: &FolderId) -> Vec<u8> {
    let mut key = META.to_vec();
    key.extend_from_slice(folder.as_bytes());
    key
}

fn u64_at(bytes: &[u8], i: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(i * 8..i * 8 + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(raw))
}

fn encode_meta(m: &StoredMeta) -> Vec<u8> {
    [m.hw, m.next_seq, m.epoch]
        .iter()
        .flat_map(|n| n.to_be_bytes())
        .collect()
}

fn decode_meta(bytes: &[u8]) -> Option<StoredMeta> {
    (bytes.len() == 24).then_some(())?;
    Some(StoredMeta {
        hw: u64_at(bytes, 0)?,
        next_seq: u64_at(bytes, 1)?,
        epoch: u64_at(bytes, 2)?,
    })
}

fn encode_peer(p: &PeerState) -> Vec<u8> {
    let mut out: Vec<u8> = [
        p.epoch,
        p.cursor,
        p.round_ended_us,
        p.names_window_us,
        p.names,
    ]
    .iter()
    .flat_map(|n| n.to_be_bytes())
    .collect();
    out.push(u8::from(p.caught_up));
    out
}

fn decode_peer(bytes: &[u8]) -> Option<PeerState> {
    (bytes.len() == 41).then_some(())?;
    Some(PeerState {
        epoch: u64_at(bytes, 0)?,
        cursor: u64_at(bytes, 1)?,
        round_ended_us: u64_at(bytes, 2)?,
        names_window_us: u64_at(bytes, 3)?,
        names: u64_at(bytes, 4)?,
        caught_up: match bytes.get(40)? {
            0 => false,
            1 => true,
            _ => return None,
        },
    })
}

/// What a start reads of one folder: the index's stored state, the chunks
/// pending a free, and whether anything was stored at all.
#[derive(Debug, Default)]
pub(crate) struct Loaded {
    pub(crate) stored: Stored,
    pub(crate) pending_free: BTreeSet<CipherHash>,
    /// Some key of the folder's index was found: it was created before.
    pub(crate) existed: bool,
}

/// The suffix of `key` after `start`, if `key` has it.
fn suffix<'a>(key: &'a [u8], start: &[u8]) -> Option<&'a [u8]> {
    key.get(start.len()..)
}

/// Everything committed (and staged) under the folder's prefixes, for
/// [`licketysync_index::Index::open`]. An entry that does not decode, a
/// record whose key is not its hash included, is counted in
/// `Stored::undecodable` and left out (gap G6).
///
/// # Errors
/// The storage's own error when it cannot be read.
pub(crate) fn load(storage: &dyn Storage, folder: &FolderId) -> Result<Loaded, StorageError> {
    let mut out = Loaded::default();
    let mut bad = 0usize;
    let start = prefix(RECORDS, folder);
    for (key, value) in storage.scan(&start)? {
        out.existed = true;
        let record = value
            .get(8..)
            .and_then(|env| SignedRecord::from_bytes(env).ok())
            .filter(|r| suffix(&key, &start) == Some(r.hash().as_bytes().as_slice()));
        match (record, u64_at(&value, 0)) {
            (Some(r), Some(seq)) => out.stored.records.push((r, seq)),
            _ => bad += 1,
        }
    }
    let start = prefix(BASE_ONLY, folder);
    for (key, value) in storage.scan(&start)? {
        out.existed = true;
        match SignedRecord::from_bytes(&value)
            .ok()
            .filter(|r| suffix(&key, &start) == Some(r.hash().as_bytes().as_slice()))
        {
            Some(r) => out.stored.base_only.push(r),
            None => bad += 1,
        }
    }
    let start = prefix(SLOTS, folder);
    for (key, value) in storage.scan(&start)? {
        out.existed = true;
        let slot = suffix(&key, &start).and_then(|id| {
            let tag = PathTag::from_slice(id.get(..32)?)?;
            let place = match id.get(32..)? {
                [0] => Place::Path,
                [1, name @ ..] => Place::Copy(String::from_utf8(name.to_vec()).ok()?),
                _ => return None,
            };
            Some((tag, place))
        });
        match (slot, RecordHash::from_slice(&value)) {
            (Some(slot), Some(h)) => out.stored.bases.push((slot, h)),
            _ => bad += 1,
        }
    }
    if let Some(bytes) = storage.get(&meta_key(folder))? {
        out.existed = true;
        match decode_meta(&bytes) {
            Some(m) => out.stored.meta = Some(m),
            None => bad += 1,
        }
    }
    let start = prefix(PEERS, folder);
    for (key, value) in storage.scan(&start)? {
        out.existed = true;
        let device = suffix(&key, &start).and_then(DeviceId::from_slice);
        match (device, decode_peer(&value)) {
            (Some(d), Some(p)) => out.stored.peers.push((d, p)),
            _ => bad += 1,
        }
    }
    let start = prefix(FREES, folder);
    for (key, _) in storage.scan(&start)? {
        match suffix(&key, &start).and_then(CipherHash::from_slice) {
            Some(h) => {
                out.pending_free.insert(h);
            }
            None => bad += 1,
        }
    }
    out.stored.undecodable = bad;
    Ok(out)
}

/// The cipher hashes of every chunk marked stored for the folder. A marker
/// key whose suffix is not 32 bytes is no chunk of this layout and is left
/// out (it counts as not stored, so the chunk is fetched again).
///
/// # Errors
/// The storage's own error when it cannot be read.
pub(crate) fn load_stored_chunks(
    storage: &dyn Storage,
    folder: &FolderId,
) -> Result<BTreeSet<CipherHash>, StorageError> {
    let start = prefix(HELD, folder);
    Ok(storage
        .scan(&start)?
        .into_iter()
        .filter_map(|(key, _)| CipherHash::from_slice(suffix(&key, &start)?))
        .collect())
}

/// Stages one transaction's change set, and the chunks it left unnamed onto
/// the pending-free list, in the store's order (the records, then the
/// metadata with the base slots and the per-peer state, then the removals),
/// although the runtime's store stages atomically and the order matters only
/// to one that does not (`protocol.md` 4.7 item 1).
///
/// # Errors
/// The storage's error: nothing more is staged then, and the handler rolls
/// back.
pub(crate) fn stage_changes(
    storage: &mut dyn Storage,
    folder: &FolderId,
    changes: &ChangeSet,
) -> Result<(), StorageError> {
    for (record, seq) in &changes.put {
        let mut value = seq.to_be_bytes().to_vec();
        value.extend_from_slice(&record.to_bytes());
        storage.put(&record_key(folder, &record.hash()), &value)?;
    }
    for record in &changes.base_only_put {
        storage.put(
            &key_of(BASE_ONLY, folder, record.hash().as_bytes()),
            &record.to_bytes(),
        )?;
    }
    if let Some(meta) = &changes.meta {
        storage.put(&meta_key(folder), &encode_meta(meta))?;
    }
    for ((tag, place), record) in &changes.bases {
        let key = slot_key(folder, tag, place);
        match record {
            Some(h) => storage.put(&key, h.as_bytes())?,
            None => storage.delete(&key)?,
        }
    }
    for (device, state) in &changes.peers {
        let key = key_of(PEERS, folder, device.as_bytes());
        match state {
            Some(p) => storage.put(&key, &encode_peer(p))?,
            None => storage.delete(&key)?,
        }
    }
    for hash in &changes.freed {
        storage.put(&free_key(folder, hash), &[])?;
    }
    for hash in &changes.remove {
        storage.delete(&record_key(folder, hash))?;
    }
    for hash in &changes.base_only_remove {
        storage.delete(&key_of(BASE_ONLY, folder, hash.as_bytes()))?;
    }
    Ok(())
}

/// Stages one chunk blob and its marker.
///
/// # Errors
/// The storage's error: nothing more is staged then.
pub(crate) fn stage_chunk(
    storage: &mut dyn Storage,
    folder: &FolderId,
    hash: &CipherHash,
    blob: &[u8],
) -> Result<(), StorageError> {
    storage.put(&chunk_key(folder, hash), blob)?;
    storage.put(&held_key(folder, hash), &[])
}

/// Stages the deletion of one chunk blob and its marker.
///
/// # Errors
/// The storage's error.
pub(crate) fn stage_chunk_delete(
    storage: &mut dyn Storage,
    folder: &FolderId,
    hash: &CipherHash,
) -> Result<(), StorageError> {
    storage.delete(&chunk_key(folder, hash))?;
    storage.delete(&held_key(folder, hash))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::assert_is_empty,
    reason = "test code"
)]
mod tests {
    use super::*;
    use crate::testkit::{signed_record, FakeStorage};

    fn changes() -> ChangeSet {
        let r1 = signed_record(1);
        let r2 = signed_record(2);
        let tag = PathTag([4; 32]);
        ChangeSet {
            put: vec![(r1.clone(), 1), (r2.clone(), 2)],
            base_only_put: vec![signed_record(3)],
            bases: vec![
                ((tag, Place::Path), Some(r1.hash())),
                ((tag, Place::Copy("a (1)".into())), Some(r2.hash())),
            ],
            meta: Some(StoredMeta {
                hw: 7,
                next_seq: 3,
                epoch: 9,
            }),
            peers: vec![(
                DeviceId([5; 32]),
                Some(PeerState {
                    epoch: 1,
                    cursor: 2,
                    round_ended_us: 3,
                    caught_up: true,
                    names_window_us: 4,
                    names: 5,
                }),
            )],
            freed: vec![CipherHash([6; 32])],
            ..ChangeSet::default()
        }
    }

    #[test]
    fn a_change_set_loads_back_as_the_stored_state() {
        let f = FolderId([9; 32]);
        let mut s = FakeStorage::default();
        let c = changes();
        stage_changes(&mut s, &f, &c).unwrap();
        s.commit().unwrap();
        let loaded = load(&s, &f).unwrap();
        assert!(loaded.existed);
        let mut records = loaded.stored.records.clone();
        records.sort_by_key(|(_, seq)| *seq);
        assert_eq!(records, c.put);
        assert_eq!(loaded.stored.base_only, c.base_only_put);
        let mut bases = loaded.stored.bases.clone();
        bases.sort();
        let mut want: Vec<_> = c
            .bases
            .iter()
            .map(|(s, h)| (s.clone(), h.unwrap()))
            .collect();
        want.sort();
        assert_eq!(bases, want);
        assert_eq!(loaded.stored.meta, c.meta);
        assert_eq!(
            loaded.stored.peers,
            vec![(c.peers[0].0, c.peers[0].1.unwrap())]
        );
        assert_eq!(loaded.pending_free.len(), 1);
        assert_eq!(loaded.stored.undecodable, 0);
        assert!(!load(&s, &FolderId([8; 32])).unwrap().existed);
    }

    #[test]
    fn removals_and_cleared_slots_go_and_bad_entries_are_counted() {
        let f = FolderId([9; 32]);
        let mut s = FakeStorage::default();
        let c = changes();
        stage_changes(&mut s, &f, &c).unwrap();
        let later = ChangeSet {
            remove: vec![c.put[0].0.hash()],
            base_only_remove: vec![c.base_only_put[0].hash()],
            bases: vec![(c.bases[1].0.clone(), None)],
            peers: vec![(c.peers[0].0, None)],
            ..ChangeSet::default()
        };
        stage_changes(&mut s, &f, &later).unwrap();
        // A record under another hash's key, a short value, garbage.
        let r = signed_record(4);
        let mut v = 1u64.to_be_bytes().to_vec();
        v.extend_from_slice(&r.to_bytes());
        s.put(&record_key(&f, &RecordHash([0; 32])), &v).unwrap();
        s.put(&record_key(&f, &RecordHash([1; 32])), b"x").unwrap();
        s.put(&meta_key(&FolderId([7; 32])), b"short").unwrap();
        s.commit().unwrap();
        let loaded = load(&s, &f).unwrap();
        assert_eq!(loaded.stored.records.len(), 1);
        assert!(loaded.stored.base_only.is_empty());
        assert_eq!(loaded.stored.bases.len(), 1);
        assert!(loaded.stored.peers.is_empty());
        assert_eq!(loaded.stored.undecodable, 2);
        assert_eq!(load(&s, &FolderId([7; 32])).unwrap().stored.undecodable, 1);
    }

    #[test]
    fn a_peer_state_loads_back_whether_or_not_its_last_round_was_caught_up() {
        // The layout: the per-peer state ends with "caught up (1 byte)",
        // either value of which loads back as staged.
        let f = FolderId([9; 32]);
        for caught_up in [false, true] {
            let state = PeerState {
                epoch: 1,
                cursor: 2,
                round_ended_us: 3,
                caught_up,
                names_window_us: 4,
                names: 5,
            };
            let mut s = FakeStorage::default();
            let c = ChangeSet {
                peers: vec![(DeviceId([5; 32]), Some(state))],
                ..ChangeSet::default()
            };
            stage_changes(&mut s, &f, &c).unwrap();
            s.commit().unwrap();
            let loaded = load(&s, &f).unwrap();
            assert_eq!(
                loaded.stored.peers,
                vec![(DeviceId([5; 32]), state)],
                "caught up: {caught_up}"
            );
            assert_eq!(loaded.stored.undecodable, 0, "caught up: {caught_up}");
        }
    }

    #[test]
    fn every_kind_of_entry_that_does_not_decode_is_counted_once() {
        // Gap G6: an entry that does not decode is counted in
        // `Stored::undecodable` and left out, whatever its kind; one of each
        // kind counts one each, alone or all together.
        let f = FolderId([9; 32]);
        let mut slot = [4u8; 32].to_vec();
        slot.push(2); // a place that is neither the path (0) nor a copy (1)
        let mut peer = vec![0u8; 40];
        peer.push(2); // caught up neither 0 nor 1
        let bad: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (record_key(&f, &RecordHash([1; 32])), b"x".to_vec()),
            (key_of(BASE_ONLY, &f, &[2; 32]), signed_record(1).to_bytes()),
            (key_of(SLOTS, &f, &slot), [3; 32].to_vec()),
            (meta_key(&f), b"short".to_vec()),
            (key_of(PEERS, &f, &[5; 32]), peer),
            (key_of(FREES, &f, b"short"), Vec::new()),
        ];
        let load_of = |entries: &[(Vec<u8>, Vec<u8>)]| {
            let mut s = FakeStorage::default();
            for (key, value) in entries {
                s.put(key, value).unwrap();
            }
            s.commit().unwrap();
            load(&s, &f).unwrap()
        };
        for entry in &bad {
            let loaded = load_of(core::slice::from_ref(entry));
            assert_eq!(loaded.stored.undecodable, 1, "{:?}", entry.0);
            assert!(loaded.stored.records.is_empty() && loaded.stored.base_only.is_empty());
            assert!(loaded.stored.bases.is_empty() && loaded.stored.peers.is_empty());
            assert!(loaded.stored.meta.is_none() && loaded.pending_free.is_empty());
        }
        assert_eq!(load_of(&bad).stored.undecodable, bad.len());
    }

    #[test]
    fn the_layout_keeps_folders_and_kinds_apart() {
        let (f, g) = (FolderId([1; 32]), FolderId([2; 32]));
        let c = CipherHash([3; 32]);
        assert_ne!(chunk_key(&f, &c), held_key(&f, &c));
        assert_ne!(chunk_key(&f, &c), chunk_key(&g, &c));
        assert_ne!(free_key(&f, &c), held_key(&f, &c));
        assert!(!PROBE.starts_with(b"w/"));
        let mut s = FakeStorage::default();
        stage_chunk(&mut s, &f, &c, b"blob").unwrap();
        s.put(b"e/h/short", &[]).unwrap();
        s.commit().unwrap();
        assert_eq!(load_stored_chunks(&s, &f).unwrap().len(), 1);
        stage_chunk_delete(&mut s, &f, &c).unwrap();
        s.commit().unwrap();
        assert!(load_stored_chunks(&s, &f).unwrap().is_empty());
    }
}
