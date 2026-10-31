// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Opening a folder's index from its stored state (`protocol.md` 4.4,
//! "Opening a folder"; 4.7 item 8; TM-9).

use std::collections::{BTreeMap, BTreeSet};

use licketysync_keys::{RandomFill, RecordHash};
use licketysync_protocol::limits::{
    CLOCK_AHEAD_WARNING, CLOCK_FLOOR_MAX, CLOCK_RULE_LIMIT, MAX_COUNTER, MAX_LOCAL_SEQ,
    MAX_PEER_STATES, PEER_STATE_HORIZON,
};
use licketysync_protocol::record::Record;

use crate::index::{draw_epoch, Accepted, Index, OpenReport, Seq};
use crate::state::BaseRecord;
use crate::store::{BaseSlot, ChangeSet, Stored, StoredMeta};
use crate::verify;

/// What a stored envelope was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kept {
    /// A record held, with its local sequence number.
    Held(u64),
    /// A record kept only as a base.
    Base,
}

/// The open of [`Index::open`] (its documentation says what it does).
pub(crate) fn open(
    mut ix: Index,
    stored: Stored,
    clock_us: u64,
    rng: &mut RandomFill<'_>,
    threads: usize,
) -> (Index, OpenReport) {
    let mut report = OpenReport {
        undecodable: stored.undecodable,
        ..OpenReport::default()
    };
    let stored_meta = stored.meta;
    let stored_bases = stored.bases;
    let stored_peers = stored.peers;
    let mut items: Vec<(_, Kept)> = stored
        .records
        .into_iter()
        .map(|(r, seq)| (r, Kept::Held(seq)))
        .collect();
    items.extend(stored.base_only.into_iter().map(|r| (r, Kept::Base)));
    let (passing, failed) = verify::authentic(items, &ix.verifier, threads);
    // A failing copy beside a passing one of the same hash is dropped
    // without a report: the record itself is there.
    let passed: BTreeSet<RecordHash> = passing.iter().map(|(r, _)| r.hash()).collect();
    let mut dropped: Vec<RecordHash> = failed.into_iter().filter(|h| !passed.contains(h)).collect();
    dropped.sort_unstable();
    dropped.dedup();
    let mut held_stored: Vec<(u64, Record)> = Vec::new();
    let mut base_stored: BTreeMap<RecordHash, Record> = BTreeMap::new();
    for (r, kept) in passing {
        match kept {
            Kept::Held(seq) => held_stored.push((seq, r)),
            Kept::Base => {
                base_stored.insert(r.hash(), r);
            }
        }
    }
    held_stored.sort_by_key(|(seq, r)| (*seq, r.hash()));
    // Two stored copies of one record (a store not keyed by hash that kept
    // a row twice) are one record, at the first of their numbers, so that a
    // copy is not taken for a repeated number below.
    let mut copies = BTreeSet::new();
    held_stored.retain(|(_, r)| copies.insert(r.hash()));
    let stored_held: BTreeSet<RecordHash> = held_stored.iter().map(|(_, r)| r.hash()).collect();
    // Stored local sequence numbers are not signed: one of 0, one above
    // MAX_LOCAL_SEQ, one two records share, or a next number past
    // MAX_LOCAL_SEQ + 1, and every record held is numbered afresh from 1 in
    // stored order under a new epoch, the spec's rule for passing
    // MAX_LOCAL_SEQ (4.5).
    let mut numbers = BTreeSet::new();
    report.renumbered = stored_meta.is_some_and(|m| m.next_seq > MAX_LOCAL_SEQ + 1)
        || held_stored
            .iter()
            .any(|(seq, _)| *seq == 0 || *seq > MAX_LOCAL_SEQ || !numbers.insert(*seq));
    if report.renumbered {
        for (n, (seq, _)) in (1..).zip(held_stored.iter_mut()) {
            *seq = n;
        }
    }
    let greatest_seq = held_stored.iter().map(|(s, _)| *s).max().unwrap_or(0);
    ix.s.meta = StoredMeta {
        hw: 0,
        next_seq: if report.renumbered {
            greatest_seq.saturating_add(1)
        } else {
            stored_meta
                .map_or(1, |m| m.next_seq)
                .max(greatest_seq.saturating_add(1))
                .max(1)
        },
        epoch: stored_meta.map_or(0, |m| m.epoch),
    };
    let (silent, misplaced) = replay(
        &mut ix,
        &stored_bases,
        &base_stored,
        held_stored,
        &dropped,
        clock_us,
    );
    report.misplaced_bases = misplaced;
    // The high-water mark (read and write holders; a sealed holder keeps
    // none).
    let greatest = ix.s.greatest_counter();
    if ix.key_holder() {
        let floor = clock_us.min(CLOCK_FLOOR_MAX);
        let justified = greatest.max(floor);
        let stored_hw = stored_meta.map_or(0, |m| m.hw);
        let hw = if stored_hw >= MAX_COUNTER
            || stored_hw > justified.saturating_add(CLOCK_AHEAD_WARNING)
        {
            report.hw_corrupt = true;
            justified
        } else {
            stored_hw.max(greatest)
        };
        ix.s.meta.hw = hw;
        if greatest > clock_us.saturating_add(CLOCK_RULE_LIMIT) {
            report.opens_at = Some(greatest - CLOCK_RULE_LIMIT);
        }
    }
    // The epoch: as stored, redrawn once when the open dropped anything or
    // numbered the records afresh.
    if ix.s.meta.epoch == 0 {
        ix.s.meta.epoch = draw_epoch(rng);
    } else if silent || report.renumbered || !dropped.is_empty() {
        ix.s.meta.epoch = draw_epoch(rng);
        report.epoch_redrawn = true;
    }
    let mut changes = ChangeSet::default();
    peers_at_open(&mut ix, stored_peers, clock_us, &mut changes);
    if report.renumbered {
        changes.put =
            ix.s.by_seq
                .iter()
                .filter_map(|(seq, h)| Some((ix.s.held.get(h)?.record.signed().clone(), *seq)))
                .collect();
    }
    stored_changes(
        &ix,
        &mut changes,
        &stored_held,
        &base_stored,
        &stored_bases,
        stored_meta,
    );
    report.dropped = dropped;
    report.changes = changes;
    (ix, report)
}

/// The stored per-peer state (4.5, "Per-peer state"): each entry's times
/// are clamped to the clock, so that a time ahead of it can neither keep an
/// entry for ever nor keep its names window from ending; an entry past
/// `PEER_STATE_HORIZON` without a round goes; and at most `MAX_PEER_STATES`
/// are kept, the ones longest without a round going first (the index
/// security review's NIT 4). What changed is staged.
fn peers_at_open(
    ix: &mut Index,
    stored_peers: Vec<(licketysync_keys::DeviceId, crate::PeerState)>,
    clock_us: u64,
    changes: &mut ChangeSet,
) {
    let mut kept: Vec<(licketysync_keys::DeviceId, crate::PeerState)> = Vec::new();
    for (peer, stored) in stored_peers {
        let state = crate::PeerState {
            round_ended_us: stored.round_ended_us.min(clock_us),
            names_window_us: stored.names_window_us.min(clock_us),
            ..stored
        };
        if clock_us.saturating_sub(state.round_ended_us) > PEER_STATE_HORIZON {
            changes.peers.push((peer, None));
        } else {
            if state != stored {
                changes.peers.push((peer, Some(state)));
            }
            kept.push((peer, state));
        }
    }
    kept.sort_by_key(|(d, p)| (core::cmp::Reverse(p.round_ended_us), *d));
    for (i, (peer, state)) in kept.into_iter().enumerate() {
        if i < MAX_PEER_STATES {
            ix.s.peers.insert(peer, state);
        } else {
            changes.peers.retain(|(d, _)| *d != peer);
            changes.peers.push((peer, None));
        }
    }
}

/// The base slots, then the replay of the records held in stored
/// local-sequence order with their numbers, then expiry. Returns whether
/// anything stored went silently (a base slot whose record is not there, or
/// a record a stored one replaces), for the epoch, and the base slots
/// dropped because their record lies at another file ID (the index security
/// review's NIT 5: `Txn::set_base` refuses such a base).
fn replay(
    ix: &mut Index,
    stored_bases: &[(BaseSlot, RecordHash)],
    base_stored: &BTreeMap<RecordHash, Record>,
    held_stored: Vec<(u64, Record)>,
    dropped: &[RecordHash],
    clock_us: u64,
) -> (bool, Vec<BaseSlot>) {
    let mut misplaced = Vec::new();
    let by_hash: BTreeMap<RecordHash, &Record> =
        held_stored.iter().map(|(_, r)| (r.hash(), r)).collect();
    let mut silent = false;
    let mut txn = ix.begin();
    // The base slots first, so that a record replaced in the replay below
    // stays, kept only as a base, where it is one.
    if txn.index().key_holder() {
        for (slot, hash) in stored_bases {
            let record = base_stored.get(hash).or_else(|| by_hash.get(hash).copied());
            if record.is_some_and(|r| r.path_tag() != Some(slot.0)) {
                misplaced.push(slot.clone());
                continue;
            }
            let base = record.and_then(|r| {
                let meta = txn.index().verdict(r)?.ok()?.meta()?.clone();
                Some(BaseRecord {
                    record: r.clone(),
                    meta,
                })
            });
            match base {
                Some(b) => txn.ix.s.set_base(slot.clone(), Some(*hash), Some(b), None),
                None => {
                    if !dropped.contains(hash) {
                        silent = true;
                    }
                }
            }
        }
    }
    // The replay, in stored local-sequence order, with the stored numbers.
    let mut scratch = Accepted::scratch();
    let mut seen = BTreeSet::new();
    for (seq, record) in held_stored {
        if !seen.insert(record.hash()) {
            continue;
        }
        let verdict = txn.index().verdict(&record);
        let applied = verdict.as_ref().and_then(|v| v.as_ref().ok()).cloned();
        let replaces = txn.ix.s.replaced_by(&record, applied.as_ref());
        if txn
            .store(
                record,
                verdict,
                &replaces,
                Seq::Stored(seq),
                clock_us,
                &mut scratch,
            )
            .is_err()
        {
            silent = true;
        }
    }
    txn.expire(&mut scratch);
    txn.keep();
    (silent || !scratch.dropped.is_empty(), misplaced)
}

/// What the store is to keep of this open: the records it no longer holds,
/// the records kept only as bases that came or went, the base slots cleared,
/// and the metadata when it changed.
fn stored_changes(
    ix: &Index,
    changes: &mut ChangeSet,
    stored_held: &BTreeSet<RecordHash>,
    base_stored: &BTreeMap<RecordHash, Record>,
    stored_bases: &[(BaseSlot, RecordHash)],
    stored_meta: Option<StoredMeta>,
) {
    changes.remove = stored_held
        .iter()
        .filter(|h| !ix.s.is_held(h))
        .copied()
        .collect();
    changes.base_only_put =
        ix.s.base_only
            .iter()
            .filter(|(h, _)| !base_stored.contains_key(h))
            .map(|(_, b)| b.record.signed().clone())
            .collect();
    changes.base_only_remove = base_stored
        .keys()
        .filter(|h| !ix.s.base_only.contains_key(h))
        .copied()
        .collect();
    changes.bases = stored_bases
        .iter()
        .filter(|(slot, _)| !ix.s.bases.contains_key(slot))
        .map(|(slot, _)| (slot.clone(), None))
        .collect();
    if stored_meta != Some(ix.s.meta) {
        changes.meta = Some(ix.s.meta);
    }
}
