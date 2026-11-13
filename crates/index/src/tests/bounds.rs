// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The bounds on a write holder's notes and names, each reached, with the
//! caps lowered through `Bounds` where the real one is too large to reach in
//! a test (the coordinator's ruling Q7; the R2 review's I-4): the notes kept
//! (`MAX_STALE_KNOWN`, the oldest dropped first), the names per peer and
//! window (`MAX_PEER_NAMES`, in a note, a write and a round's end), the
//! verifications for notes per connection and window
//! (`MAX_NOTE_VERIFICATIONS`, at its real value), and the paging of a
//! round's cleanups (`MAX_CLEANUP_GROUPS`, `MAX_CLEANUP_ENTRIES`).

use licketysync_keys::RecordHash;
use licketysync_protocol::connection::Judgement;
use licketysync_protocol::limits::{CLEANUP_HORIZON, MAX_NOTE_VERIFICATIONS};

use super::kit::{dev, garbage, Dev, DAY};
use crate::{Change, NotNoted};

/// A writer `d` with three versions at each of `paths`, and a write holder
/// that holds the newest of each: the oldest ones are stale copies to it,
/// covered and not named (the newest names the second).
fn stale_copies(paths: &[&str]) -> (Dev, Dev, Vec<RecordHash>) {
    let mut d = Dev::writer(0xd0);
    let mut old = Vec::new();
    let mut new = Vec::new();
    for p in paths {
        old.push(d.put(p, 1));
        d.put(p, 2);
        new.push(d.put(p, 3));
    }
    let mut w = Dev::writer(0xb0);
    w.take(&d, &new);
    (d, w, old)
}

#[test]
fn the_oldest_note_goes_first_past_max_stale_known() {
    let (d, mut w, old) = stale_copies(&["a", "b", "c"]);
    w.ix.bounds.stale_known = 2;
    for h in &old {
        let a = w.accept(d.signed(h)).unwrap();
        assert!(a.noted);
    }
    assert_eq!(w.ix.s.notes.len(), 2, "two notes kept");
    assert!(!w.ix.s.notes.contains_key(&old[0]), "the oldest went");
    assert!(w.ix.s.notes.contains_key(&old[1]) && w.ix.s.notes.contains_key(&old[2]));
}

#[test]
fn a_peer_at_max_peer_names_is_not_noted_until_its_window_ends() {
    let (d, mut w, old) = stale_copies(&["a", "b"]);
    w.ix.bounds.peer_names = 1;
    // One note named at a round's end fills the peer's window.
    assert!(w.accept(d.signed(&old[0])).unwrap().noted);
    assert!(w.end_round().cleanup);
    assert_eq!(w.ix.peer(&dev(0xee)).unwrap().names, 1);
    // The next copy that peer offers is neither verified nor noted, and the
    // index says why: a garbage signature is never looked at.
    let a = w.accept(&garbage(d.signed(&old[1]))).unwrap();
    assert_eq!(a.judgement, Judgement::Obsolete);
    assert!(!a.noted);
    assert_eq!(a.not_noted, Some(NotNoted::PeerNames));
    // Another peer's copy is noted.
    let b = w.accept_from(dev(0xef), d.signed(&old[1])).unwrap();
    assert!(b.noted && b.not_noted.is_none());
    // Once the window of CLEANUP_HORIZON has passed, the first peer's names
    // count afresh.
    let (d2, mut w2, old2) = stale_copies(&["a", "b"]);
    w2.ix.bounds.peer_names = 1;
    assert!(w2.accept(d2.signed(&old2[0])).unwrap().noted);
    assert!(w2.end_round().cleanup);
    w2.clock += CLEANUP_HORIZON + 1;
    let c = w2.accept(d2.signed(&old2[1])).unwrap();
    assert!(c.noted, "a new window");
}

/// The window of `MAX_PEER_NAMES` is `PEER_NAMES_WINDOW`, 30 days by the
/// write holder's wall clock (4.5, "Stale copies"), from the first name
/// counted in it: a microsecond before it ends the peer is still at its
/// bound, and when it ends the peer's names count afresh, alike when a
/// copy it offers is judged and when its names are counted at a round's
/// end.
#[test]
fn a_peers_names_window_ends_exactly_30_days_after_it_began() {
    const PEER_NAMES_WINDOW: u64 = 30 * DAY;
    let (d, mut w, old) = stale_copies(&["a", "b"]);
    w.ix.bounds.peer_names = 1;
    assert!(w.accept(d.signed(&old[0])).unwrap().noted);
    assert!(w.end_round().cleanup);
    let began = w.ix.peer(&dev(0xee)).unwrap().names_window_us;
    w.clock = began + PEER_NAMES_WINDOW - 1;
    let a = w.accept(&garbage(d.signed(&old[1]))).unwrap();
    assert_eq!(a.not_noted, Some(NotNoted::PeerNames), "still the window");
    w.clock = began + PEER_NAMES_WINDOW;
    let b = w.accept(d.signed(&old[1])).unwrap();
    assert!(b.noted && b.not_noted.is_none(), "a new window");
    assert!(w.end_round().cleanup);
    let p = w.ix.peer(&dev(0xee)).unwrap();
    assert_eq!(
        (p.names_window_us, p.names),
        (began + PEER_NAMES_WINDOW, 1),
        "counted in the new window"
    );
}

#[test]
fn a_round_names_at_most_max_peer_names_of_one_peers_notes() {
    let (d, mut w, old) = stale_copies(&["a", "b", "c"]);
    w.ix.bounds.peer_names = 2;
    for h in &old {
        assert!(w.accept(d.signed(h)).unwrap().noted);
    }
    let written = w.end_round();
    assert!(written.cleanup);
    let named: usize = written
        .records
        .iter()
        .filter_map(|(h, _)| w.ix.s.held.get(h))
        .map(|c| {
            c.record
                .groups()
                .iter()
                .map(|g| g.forget.len())
                .sum::<usize>()
        })
        .sum();
    assert_eq!(named, 2, "two of the peer's three notes named");
    assert_eq!(w.ix.s.notes.len(), 1, "the third waits for the next window");
    assert_eq!(w.ix.peer(&dev(0xee)).unwrap().names, 2);
}

#[test]
fn a_write_names_a_peers_notes_only_within_its_window_n10() {
    // Two stale copies at one path from one peer, the peer's window at one
    // name: the write names one and leaves the other noted, counted with the
    // cleanups' names ("in writes and cleanups together"; the R2 review's
    // N10).
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("a", 1);
    let v2 = d.put("a", 2);
    d.put("a", 3);
    let v4 = d.put("a", 4);
    let mut w = Dev::writer(0xb0);
    w.take(&d, &[v4]);
    w.ix.bounds.peer_names = 1;
    assert!(w.accept(d.signed(&v1)).unwrap().noted);
    assert!(w.accept(d.signed(&v2)).unwrap().noted);
    w.apply("a");
    let written = w
        .write(&[Change::Put(super::kit::file("a", 5, 99))])
        .unwrap();
    let names = w.ix.s.held[&written.records[0].0]
        .record
        .replaces()
        .to_vec();
    let noted_named = [v1, v2].iter().filter(|h| names.contains(h)).count();
    assert_eq!(noted_named, 1, "one of the two notes named");
    assert_eq!(w.ix.s.notes.len(), 1, "the other stays noted");
    assert_eq!(
        w.ix.peer(&dev(0xee)).unwrap().names,
        1,
        "counted against the peer"
    );
}

#[test]
fn a_connection_past_max_note_verifications_notes_nothing_more_this_window() {
    let (d, mut w, old) = stale_copies(&["a"]);
    for _ in 0..MAX_NOTE_VERIFICATIONS {
        assert!(w.notes.may_verify());
        w.notes.verified();
    }
    let a = w.accept(&garbage(d.signed(&old[0]))).unwrap();
    assert_eq!(a.judgement, Judgement::Obsolete, "not verified: no Forged");
    assert!(!a.noted);
    assert_eq!(a.not_noted, Some(NotNoted::Verifications));
    assert!(w.ix.s.notes.is_empty());
}

#[test]
fn a_rounds_cleanups_are_paged_by_groups_and_names() {
    // Five stale copies at five paths, each `because` its own path's newer
    // version: five groups, paged two groups and two names a record.
    let (d, mut w, old) = stale_copies(&["a", "b", "c", "d", "e"]);
    w.ix.bounds.cleanup_groups = 2;
    w.ix.bounds.cleanup_entries = 2;
    for h in &old {
        assert!(w.accept(d.signed(h)).unwrap().noted);
    }
    let written = w.end_round();
    let cleanups: Vec<_> = written
        .records
        .iter()
        .filter_map(|(h, _)| w.ix.s.held.get(h))
        .filter(|c| c.record.is_cleanup())
        .collect();
    assert_eq!(cleanups.len(), 3, "five groups of one name, two a record");
    let mut named = Vec::new();
    for c in &cleanups {
        let groups = c.record.groups();
        assert!(groups.len() <= 2);
        assert!(groups.iter().map(|g| g.forget.len()).sum::<usize>() <= 2);
        named.extend(groups.iter().flat_map(|g| g.forget.iter().copied()));
    }
    named.sort();
    let mut want = old.clone();
    want.sort();
    assert_eq!(named, want, "every note named once");
    assert!(w.ix.s.notes.is_empty());
}

#[test]
fn a_rounds_cleanups_are_paged_by_groups_alone() {
    // Five stale copies, each `because` its own path's newer version, with
    // room for any number of names but two groups a record: three records,
    // of two, two and one group (the R1 review's N16, `page_groups`).
    let (d, mut w, old) = stale_copies(&["a", "b", "c", "d", "e"]);
    w.ix.bounds.cleanup_groups = 2;
    w.ix.bounds.cleanup_entries = 1_000;
    for h in &old {
        assert!(w.accept(d.signed(h)).unwrap().noted);
    }
    let written = w.end_round();
    let groups: Vec<usize> = written
        .records
        .iter()
        .filter_map(|(h, _)| w.ix.s.held.get(h))
        .filter(|c| c.record.is_cleanup())
        .map(|c| c.record.groups().len())
        .collect();
    assert_eq!(groups, vec![2, 2, 1], "three records of at most two groups");
    assert!(w.ix.s.notes.is_empty());
}
