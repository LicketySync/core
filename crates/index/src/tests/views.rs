// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The views the engine reads (R10 and R11; the review's I-2), at every
//! tier: the chunks the folder wants, a file version's content, Status's
//! `extra_versions` (`protocol.md` 8 item 11), a record's writer fault, the
//! bases and their refusals, and what a change reports of itself: the chunk
//! hashes it freed, the paths it touched and whether the folder's wants
//! changed.

use licketysync_keys::{CipherHash, RecordHash, Tier};
use licketysync_protocol::record::WriterFault;

use super::kit::{chunk, dev, forge, sealed_file, Dev, T0};
use crate::{BaseError, Change, Place, Store};

const TIERS: [Tier; 3] = [Tier::Write, Tier::Read, Tier::Sealed];

/// A writer fault the next write at its path names: a tree delete without
/// `deleted` (`TreeWithoutDeleted`), with one chunk, by another device.
fn opaque_at(path: &str, n: u8) -> licketysync_keys::records::SignedRecord {
    let mut m = sealed_file(path, dev(0xe0), T0 + 5);
    m.tree = true;
    forge(path, &[chunk(n)], &m, &[])
}

/// Two concurrent versions of `f` by two devices (a real conflict, contents
/// 1 and 2), and an opaque record at `g`.
fn conflict_and_opaque() -> (
    Dev,
    Dev,
    RecordHash,
    RecordHash,
    licketysync_keys::records::SignedRecord,
) {
    let mut d = Dev::writer(0xd0);
    let mut e = Dev::writer(0xd1);
    let v1 = d.put("f", 1);
    let v2 = e.put("f", 2);
    (d, e, v1, v2, opaque_at("g", 7))
}

#[test]
fn wanted_lists_every_head_and_opaque_record_with_chunks_i2() {
    let (d, e, v1, v2, bad) = conflict_and_opaque();
    for tier in TIERS {
        let mut x = Dev::new(tier, 0xa0);
        x.take(&d, &[v1]);
        x.take(&e, &[v2]);
        x.accept(&bad).unwrap();
        // A directory has no chunks: not wanted.
        let mut w = Dev::writer(0xd2);
        let dir = w.mkdir("h");
        x.take(&w, &[dir]);
        let wanted = x.ix.wanted();
        let records: Vec<RecordHash> = wanted.iter().map(|w| w.record).collect();
        assert_eq!(
            records,
            vec![v1, v2, bad.hash()],
            "{tier:?}: in local-sequence order"
        );
        for want in &wanted {
            assert_eq!(want.chunks.len(), 1);
            assert_eq!(want.chunks[0].stored_len, 46);
        }
        let key = tier != Tier::Sealed;
        assert_eq!(wanted[0].chunks[0].hash, CipherHash([1; 32]));
        assert_eq!(wanted[1].chunks[0].hash, CipherHash([2; 32]));
        assert_eq!(wanted[2].chunks[0].hash, CipherHash([7; 32]));
        let plain = |i: usize| wanted[i].chunks[0].plain.map(|p| p.0);
        assert_eq!(
            plain(0),
            key.then_some([1; 32]),
            "{tier:?}: the plain hash at a key holder only"
        );
        assert_eq!(plain(1), key.then_some([2; 32]));
        assert_eq!(wanted[0].size, key.then_some(1));
        assert_eq!(plain(2), None, "an opaque record's are not trusted");
        assert_eq!(wanted[2].size, None);
        for (h, n) in [(v1, 1u8), (v2, 2), (bad.hash(), 7)] {
            assert!(x.ix.names_chunk(&CipherHash([n; 32])), "{h:?}");
        }
        assert!(!x.ix.names_chunk(&CipherHash([9; 32])));
    }
}

#[test]
fn file_gives_the_content_of_any_applied_file_head_i2() {
    let (d, e, v1, v2, bad) = conflict_and_opaque();
    let mut w = Dev::writer(0xd2);
    let dir = w.mkdir("h");
    let mut t = Dev::writer(0xd3);
    t.put("gone", 4);
    let tomb = t.delete("gone");
    for tier in TIERS {
        let mut x = Dev::new(tier, 0xa0);
        x.take(&d, &[v1]);
        x.take(&e, &[v2]);
        x.accept(&bad).unwrap();
        x.take(&w, &[dir]);
        x.take(&t, &[tomb]);
        if tier == Tier::Sealed {
            assert!(x.ix.file(&v1).is_none(), "a sealed holder reads no content");
            continue;
        }
        for (h, n) in [(v1, 1u8), (v2, 2)] {
            let f = x.ix.file(&h).unwrap();
            assert_eq!(f.chunks, vec![chunk(n)], "{tier:?}: each conflict head");
            let plain: Vec<[u8; 32]> = f.plain_hashes.iter().map(|p| p.0).collect();
            assert_eq!(plain, vec![[n; 32]]);
            assert_eq!(f.size, 1);
        }
        assert!(x.ix.file(&bad.hash()).is_none(), "opaque");
        assert!(x.ix.file(&dir).is_none(), "a directory");
        assert!(x.ix.file(&tomb).is_none(), "a tombstone");
        assert!(x.ix.file(&RecordHash([3; 32])).is_none(), "not held");
    }
}

/// `protocol.md` 8 item 11: a sealed holder with two stale copies and one
/// real conflict counts 3, a read holder with that conflict 1.
#[test]
fn extra_versions_at_a_sealed_and_a_key_holder_i2() {
    let mut d = Dev::writer(0xd0);
    let [a1, _, a3] = [d.put("a", 1), d.put("a", 2), d.put("a", 3)];
    let [b1, _, b3] = [d.put("b", 1), d.put("b", 2), d.put("b", 3)];
    let c1 = d.put("c", 1);
    let mut e = Dev::writer(0xd1);
    let c2 = e.put("c", 2);
    let mut s = Dev::sealed(0xa2);
    let mut r = Dev::reader(0xa1);
    for x in [&mut s, &mut r] {
        // The newest first, then the oldest, which nothing held names.
        x.take(&d, &[a3, a1, b3, b1, c1]);
        x.take(&e, &[c2]);
    }
    assert!(
        s.holds(&a1) && s.holds(&b1),
        "two stale copies at the sealed peer"
    );
    assert_eq!(
        s.ix.extra_versions(),
        3,
        "two stale copies and one conflict"
    );
    assert!(!r.holds(&a1) && !r.holds(&b1), "covered at the read holder");
    assert_eq!(r.heads("c").len(), 2, "a real conflict");
    assert_eq!(r.ix.extra_versions(), 1, "the conflict's extra head");
    let mut w = Dev::writer(0xa3);
    w.take(&d, &[c1]);
    assert_eq!(w.ix.extra_versions(), 0, "one head");
}

#[test]
fn fault_names_the_writer_fault_of_an_opaque_record_i2() {
    let (d, _, v1, _, bad) = conflict_and_opaque();
    for tier in TIERS {
        let mut x = Dev::new(tier, 0xa0);
        x.take(&d, &[v1]);
        x.accept(&bad).unwrap();
        match tier {
            Tier::Sealed => assert_eq!(
                x.ix.fault(&bad.hash()),
                None,
                "a sealed holder opens nothing"
            ),
            _ => assert_eq!(
                x.ix.fault(&bad.hash()),
                Some(&WriterFault::TreeWithoutDeleted),
                "{tier:?}"
            ),
        }
        assert_eq!(x.ix.fault(&v1), None, "applied");
        assert_eq!(x.ix.fault(&RecordHash([3; 32])), None, "not held");
    }
}

#[test]
fn clear_bases_beneath_clears_every_slot_but_the_directory_itself_i2() {
    let mut d = Dev::writer(0xd0);
    let dv = d.mkdir("dir");
    d.put("dir/a", 1);
    d.put("dir/b/c", 2);
    let dash = d.put("dir-x", 3);
    let other = d.put("other", 4);
    for p in ["dir", "dir/a", "dir/b/c", "dir-x", "other"] {
        assert_eq!(d.ix.bases(p).len(), 1, "{p}: each write is its path's base");
    }
    let mut txn = d.ix.begin();
    txn.clear_bases_beneath("dir");
    let (changes, pending) = txn.finish();
    let cleared: Vec<_> = changes.bases.iter().filter(|(_, h)| h.is_none()).collect();
    assert_eq!(cleared.len(), 2, "dir/a and dir/b/c");
    d.store.commit(&changes).unwrap();
    pending.commit();
    assert_eq!(
        d.ix.bases("dir"),
        vec![(Place::Path, dv)],
        "its own slot stays"
    );
    assert!(d.ix.bases("dir/a").is_empty() && d.ix.bases("dir/b/c").is_empty());
    assert_eq!(
        d.ix.bases("dir-x"),
        vec![(Place::Path, dash)],
        "not beneath"
    );
    assert_eq!(d.ix.bases("other"), vec![(Place::Path, other)]);
    // A sealed holder keeps no bases: nothing to clear, nothing staged.
    let mut s = Dev::sealed(0xa2);
    let mut txn = s.ix.begin();
    txn.clear_bases_beneath("dir");
    assert!(txn.finish().0.is_empty());
}

/// `Index::bases_beneath` lists the base slots at or beneath a directory in
/// path order, a path's own slot first, from the path-ordered index of the
/// slots, whether or not the path has heads: the engine's oracle checks
/// with it that nothing beneath a held tree delete keeps a base unless it is
/// live, which no other view showed for a slot without a head. The root,
/// `""`, lists every slot; a sealed holder keeps none.
#[test]
fn bases_beneath_lists_the_slots_there_with_heads_or_without() {
    let slots = |d: &Dev, dir: &str| -> Vec<(String, Place, RecordHash)> {
        d.ix.bases_beneath(dir)
            .map(|(p, place, h)| (p.to_string(), place.clone(), *h))
            .collect()
    };
    let at = |p: &str, place: Place, h: RecordHash| (p.to_string(), place, h);
    let mut d = Dev::writer(0xd0);
    let dv = d.mkdir("dir");
    let a = d.put("dir/a", 1);
    let c = d.put("dir/b/c", 2);
    let dash = d.put("dir-x", 3);
    let other = d.put("other", 4);
    let copy = Place::Copy("a (1)".into());
    let mut txn = d.ix.begin();
    txn.set_base("dir/a", copy.clone(), Some(a)).unwrap();
    let (changes, pending) = txn.finish();
    d.store.commit(&changes).unwrap();
    pending.commit();
    let beneath = vec![
        at("dir", Place::Path, dv),
        at("dir/a", Place::Path, a),
        at("dir/a", copy.clone(), a),
        at("dir/b/c", Place::Path, c),
    ];
    assert_eq!(slots(&d, "dir"), beneath, "path order, not dir-x");
    assert_eq!(
        slots(&d, ""),
        vec![
            at("dir", Place::Path, dv),
            at("dir-x", Place::Path, dash),
            at("dir/a", Place::Path, a),
            at("dir/a", copy.clone(), a),
            at("dir/b/c", Place::Path, c),
            at("other", Place::Path, other),
        ],
        "the root: every slot"
    );
    assert_eq!(slots(&d, "dir/a").len(), 2);
    assert!(slots(&d, "di").is_empty() && slots(&d, "nothing").is_empty());
    // Another writer's tree delete of `dir`, from what it took and applied:
    // here it drops `dir/a` and `dir/b/c`, whose slots stay, kept only as
    // bases, until the engine clears them; only this view shows them.
    let mut e = Dev::writer(0xe0);
    e.take_all(&d);
    e.apply_all();
    let t = e.tree_delete("dir");
    let hashes: Vec<RecordHash> = t.records.iter().map(|(h, _)| *h).collect();
    d.take(&e, &hashes);
    assert!(
        !d.ix.paths().any(|p| p.starts_with("dir/")),
        "no heads beneath dir"
    );
    let left = slots(&d, "dir");
    for s in &beneath[1..] {
        assert!(left.contains(s), "{s:?} kept as a base, without a head");
    }
    // A sealed holder keeps no bases.
    let mut s = Dev::sealed(0xa2);
    s.take_all(&d);
    assert_eq!(s.ix.bases_beneath("").count(), 0);
}

#[test]
fn set_base_refuses_what_it_cannot_name_i2() {
    let (d, _, v1, _, bad) = conflict_and_opaque();
    let mut x = Dev::reader(0xa0);
    x.take(&d, &[v1]);
    x.accept(&bad).unwrap();
    let mut txn = x.ix.begin();
    assert_eq!(
        txn.set_base("f", Place::Path, Some(RecordHash([3; 32]))),
        Err(BaseError::Unknown)
    );
    assert_eq!(
        txn.set_base("g", Place::Path, Some(bad.hash())),
        Err(BaseError::NotApplied)
    );
    assert_eq!(
        txn.set_base("elsewhere", Place::Path, Some(v1)),
        Err(BaseError::OtherPath)
    );
    assert!(txn.finish().0.is_empty(), "every refusal staged nothing");
    let mut txn = x.ix.begin();
    txn.set_base("f", Place::Copy("f (1)".into()), Some(v1))
        .unwrap();
    let (changes, _) = txn.finish();
    assert_eq!(changes.bases.len(), 1, "a copy's slot");
    let mut s = Dev::sealed(0xa2);
    s.take(&d, &[v1]);
    let mut txn = s.ix.begin();
    assert_eq!(
        txn.set_base("f", Place::Path, Some(v1)),
        Err(BaseError::Sealed)
    );
    assert_eq!(txn.set_base("f", Place::Path, None), Err(BaseError::Sealed));
    assert!(txn.finish().0.is_empty());
    for e in [
        BaseError::Sealed,
        BaseError::Unknown,
        BaseError::NotApplied,
        BaseError::OtherPath,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

/// The pending-free input (4.7 item 1, "Chunks"): a change reports the chunk
/// hashes no held record names any more, and only those.
#[test]
fn the_change_set_frees_the_chunks_no_record_names_any_more_i2() {
    // A write replaces a version: its chunk goes, unless another record
    // names it.
    let mut d = Dev::writer(0xd0);
    d.put("f", 1);
    d.put("g", 5);
    d.put("h", 5);
    let mut txn = d.ix.begin();
    let m = 99;
    txn.write(
        &[
            Change::Put(super::kit::file("f", 2, m)),
            Change::Put(super::kit::file("g", 6, m)),
        ],
        d.clock,
        &mut |b| b.fill(3),
    )
    .unwrap();
    let (changes, _) = txn.finish();
    assert_eq!(
        changes.freed,
        vec![CipherHash([1; 32])],
        "f's old chunk; g's is still named at h"
    );
    // A read and a sealed holder accepting a version that replaces another.
    let v1 = d.put("k", 8);
    let v2 = d.put("k", 9);
    for tier in [Tier::Read, Tier::Sealed] {
        let mut x = Dev::new(tier, 0xa0);
        x.take(&d, &[v1]);
        let record = licketysync_protocol::record::Record::parse(
            d.signed(&v2).clone(),
            d.ix.key().verifier(),
        )
        .unwrap();
        let mut txn = x.ix.begin();
        let mut fill = |b: &mut [u8]| b.fill(1);
        let mut arrival = crate::Arrival {
            peer: dev(0xd0),
            memory: &mut x.memory,
            notes: &mut x.notes,
            clock_us: T0,
            rng: &mut fill,
        };
        let a = txn.accept(record, &mut arrival).unwrap();
        assert_eq!(a.dropped, vec![v1]);
        let (changes, _) = txn.finish();
        assert_eq!(changes.freed, vec![CipherHash([8; 32])], "{tier:?}");
    }
}

/// What an accepted record reports for the engine (R3): the paths whose
/// heads changed (key holders) and whether the folder's wants of chunks
/// changed.
#[test]
fn accepted_reports_the_paths_and_chunks_it_changed_i2() {
    let mut d = Dev::writer(0xd0);
    let v1 = d.put("f", 1);
    let v2 = d.put("f", 2);
    let x1 = d.mkdir("dir");
    let x2 = d.mkdir("dir");
    let inner = d.put("d/x", 3);
    d.apply_all();
    let td = d.tree_delete("d").records[0].0;
    for tier in TIERS {
        let key = tier != Tier::Sealed;
        let mut x = Dev::new(tier, 0xa0);
        let a = x.accept_from(d.id(), d.signed(&v1)).unwrap();
        assert_eq!(
            a.paths,
            if key { vec!["f".to_string()] } else { vec![] },
            "{tier:?}"
        );
        assert!(a.chunks_changed, "a version with a chunk");
        let a = x.accept_from(d.id(), d.signed(&v2)).unwrap();
        assert_eq!(key, a.paths.contains(&"f".to_string()));
        assert!(a.chunks_changed);
        x.take(&d, &[x1]);
        let a = x.accept_from(d.id(), d.signed(&x2)).unwrap();
        assert!(
            !a.chunks_changed,
            "a directory replacing a directory: no chunk"
        );
        x.take(&d, &[inner]);
        let a = x.accept_from(d.id(), d.signed(&td)).unwrap();
        if key {
            assert!(a.paths.contains(&"d".to_string()) && a.paths.contains(&"d/x".to_string()));
            assert!(a.chunks_changed, "the file beneath it dropped");
            assert!(a.dropped.contains(&inner));
        } else {
            assert!(!a.chunks_changed, "a sealed peer drops nothing by coverage");
        }
    }
}

/// What a write reports (R8): the paths its records touched, sorted, each
/// once.
#[test]
fn written_reports_the_paths_its_records_touched_i2() {
    let mut d = Dev::writer(0xd0);
    d.put("a", 1);
    let w = d.rename("a", "b");
    assert_eq!(w.paths, vec!["a".to_string(), "b".to_string()]);
    d.put("d/x", 2);
    d.put("d/y", 3);
    d.apply_all();
    let w = d.tree_delete("d");
    for p in ["d", "d/x", "d/y"] {
        assert!(w.paths.contains(&p.to_string()), "{p}: {:?}", w.paths);
    }
    let mut sorted = w.paths.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(w.paths, sorted, "sorted, each once");
}
