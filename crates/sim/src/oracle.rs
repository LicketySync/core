// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What "converged" means for engine members (the phase 0 gate; the brief's
//! 13.3), as a cheap predicate the scheduler evaluates whenever nothing is in
//! flight, and as the full oracle a run applies once at its end.
//!
//! **The predicate** ([`converged`]) holds when at least one member runs and
//! every running member has finished its workload, has no staged writes, and
//! has every folder Up to date with nothing lacking; and when, per folder,
//! every member that holds it agrees on its records (the root set digest),
//! and every read or write holder on its heads. Agreement is compared by
//! digest (FNV through [`TraceHasher`]) over the engine's
//! [`Engine::fingerprint`]. The stored chunks are per member (a writer keeps
//! the chunks of versions others never fetched), so they are not compared:
//! "nothing lacking" is the per-member check that each stores every chunk
//! its tier wants.
//!
//! **The full oracle** ([`check`]) adds, per folder: (a) the same set of
//! record hashes on every member (TM-41); (b) for read and write holders the
//! same paths and heads in display order, and no record opaque (no scenario
//! plants one); (b′) what each has on its disk, its bases, matching its heads
//! (each path's base its first head, each conflict copy in its copy slot, no
//! base at a path without heads but a tree delete's own) and the same on
//! every read and write holder, every path checked: (b) refuses opaque
//! records in every gate scenario, so (b′) needs no carve-out (a future
//! scenario that plants them must make (b′) skip each path with no heads and
//! an opaque record, the `protocol.md` 4.4 residual, where the engine leaves
//! such a path's disk as it is); (c) every head that is not a tombstone
//! reassembled by every key holder to exactly the ledger's bytes, every
//! stored blob named by a held record or on the pending-free list, and, for a
//! sealed holder, every record kept sealed and every named blob matching its
//! ciphertext hash and the stored length a record names; (d) no issue naming
//! a peer or a record and only the issues the scenario expects, no close
//! blaming a peer, no overflowed connection, no internal error, every start
//! shown as Checking, and, over every instance of each member, no high-water
//! mark that fell and no counter given to two records (no counter reuse
//! within one device, the brief's engine-crash criterion, checked
//! everywhere).

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use licketysync_engine::inspect::{
    conflict_copy_name, stored_blob, FolderView, Place, RecordState,
};
use licketysync_engine::runtime::PeerId;
use licketysync_engine::{Engine, FolderState, Issue, IssueKind};
use licketysync_keys::chunk::cipher_hash;
use licketysync_keys::{CipherHash, FolderId, RecordHash, Tier};

use crate::member::{Ledger, Member};
use crate::scenario::Sim;
use crate::trace::TraceHasher;

/// The digest of what `engine` holds of `folder`, its heads included or not.
fn digest(engine: &Engine, folder: &FolderId, heads: bool) -> u64 {
    let mut h = TraceHasher::default();
    let mut part = 0u8;
    engine.fingerprint(folder, &mut |bytes: &[u8]| {
        if bytes == b"heads" {
            part = 1;
        }
        if heads || part == 0 {
            h.write_bytes(bytes);
        }
    });
    h.finish()
}

/// Whether every folder of `engine` is Up to date with nothing lacking.
fn settled(engine: &Engine) -> bool {
    engine.folder_ids().all(|id| {
        engine
            .folder(&id)
            .is_some_and(|v| v.state == FolderState::UpToDate && v.lacking.is_empty())
    })
}

/// The cheap convergence predicate (module documentation).
#[must_use]
pub fn converged(sim: &Sim<Member>) -> bool {
    let mut any = false;
    let mut records: BTreeMap<FolderId, u64> = BTreeMap::new();
    let mut heads: BTreeMap<FolderId, u64> = BTreeMap::new();
    for (id, m) in sim.peers() {
        any = true;
        let Some(e) = m.engine() else {
            return false;
        };
        if !m.done() || sim.storage(id).is_none_or(|s| s.staged_len() != 0) || !settled(e) {
            return false;
        }
        for folder in e.folder_ids() {
            let r = digest(e, &folder, false);
            if *records.entry(folder).or_insert(r) != r {
                return false;
            }
            if e.folder(&folder).is_some_and(|v| v.tier != Tier::Sealed) {
                let full = digest(e, &folder, true);
                if *heads.entry(folder).or_insert(full) != full {
                    return false;
                }
            }
        }
    }
    any
}

/// A digest of every running member's final state, records, heads and
/// stored chunks included: two runs of one seed give the same.
#[must_use]
pub fn state_digest(sim: &Sim<Member>) -> u64 {
    let mut h = TraceHasher::default();
    for (id, e) in sim.peers().filter_map(|(id, m)| Some((id, m.engine()?))) {
        h.write_u64(id.as_u64());
        for folder in e.folder_ids() {
            h.write_u64(digest(e, &folder, true));
            // A stored chunk no held record names is on the pending-free
            // list, on its way out at the next round's end, whenever that
            // comes: not part of the state. One named again stays listed
            // until then, and is part of it from the start.
            if let Some(v) = e.folder(&folder) {
                let named = named(&v);
                for c in v.stored_chunks.iter().filter(|c| named.contains(c)) {
                    h.write(c.as_bytes());
                }
            }
        }
    }
    h.finish()
}

/// The chunks the records `v` holds name.
fn named(v: &FolderView) -> BTreeSet<CipherHash> {
    v.records
        .iter()
        .flat_map(|r| r.chunks.iter().map(|c| c.cipher_hash))
        .collect()
}

/// What a scenario expects beyond the common criteria.
#[derive(Clone, Copy, Debug, Default)]
pub struct Expect {
    /// The own-ID hint (a restored or cloned device) is expected.
    pub own_counter_ahead: bool,
    /// A store failure is expected.
    pub store_failure: bool,
    /// The warning that the folder's time is more than a day ahead of a
    /// device's clock is expected.
    pub clock_ahead: bool,
}

impl Expect {
    fn allows(self, issue: &Issue) -> bool {
        match issue.kind {
            IssueKind::OwnCounterAhead => self.own_counter_ahead,
            IssueKind::StoreFailure(_) => self.store_failure,
            IssueKind::ClockAhead => self.clock_ahead,
            _ => false,
        }
    }
}

/// The full oracle (module documentation). The first difference found, as
/// text, on failure.
///
/// # Errors
/// What differs.
pub fn check(
    sim: &Sim<Member>,
    ledger: &Rc<RefCell<Ledger>>,
    expect: Expect,
) -> Result<(), String> {
    check_ledger(sim, &ledger.borrow(), expect)?;
    let mut by_folder: BTreeMap<FolderId, Vec<(PeerId, FolderView)>> = BTreeMap::new();
    for (id, m) in sim.peers() {
        let e = m
            .engine()
            .ok_or_else(|| format!("{id}: its config was refused"))?;
        if !m.done() {
            return Err(format!("{id}: workload not done"));
        }
        if sim.storage(id).is_none_or(|s| s.staged_len() != 0) {
            return Err(format!("{id}: staged writes left"));
        }
        for folder in e.folder_ids() {
            let view = e.folder(&folder).ok_or_else(|| format!("{id}: no view"))?;
            if view.state != FolderState::UpToDate {
                return Err(format!("{id}: folder {folder} is {:?}", view.state));
            }
            if !view.lacking.is_empty() {
                return Err(format!("{id}: lacks {} chunks", view.lacking.len()));
            }
            by_folder.entry(folder).or_default().push((id, view));
        }
    }
    if by_folder.is_empty() {
        return Err("no member runs".to_owned());
    }
    for (folder, views) in &by_folder {
        check_records(folder, views)?;
        check_heads(sim, folder, views)?;
        check_bases(sim, folder, views)?;
        check_chunks(sim, ledger, folder, views)?;
    }
    Ok(())
}

fn check_ledger(sim: &Sim<Member>, ledger: &Ledger, expect: Expect) -> Result<(), String> {
    if let Some((peer, e)) = ledger.configs_refused.first() {
        return Err(format!("{peer}: config refused: {e}"));
    }
    if let Some((peer, issue)) = ledger
        .issues
        .iter()
        .find(|(_, i)| i.blames() || !expect.allows(i))
    {
        return Err(format!("{peer}: unexpected issue {issue:?}"));
    }
    if ledger.bad_closes > 0 {
        return Err(format!("{} closes blamed a peer", ledger.bad_closes));
    }
    if ledger.internal_errors > 0 {
        return Err(format!("{} internal errors", ledger.internal_errors));
    }
    if let Some((peer, before, after)) = ledger.hw_fell.first() {
        return Err(format!(
            "{peer}: its high-water mark fell from {before} to {after}"
        ));
    }
    if let Some((peer, counter)) = ledger.counters_reused.first() {
        return Err(format!("{peer}: counter {counter} given to two records"));
    }
    if sim.stats().overflowed > 0 {
        return Err(format!("{} connections overflowed", sim.stats().overflowed));
    }
    if let Some((peer, _)) = ledger.starts.iter().find(|(_, ok)| !ok) {
        return Err(format!(
            "{peer}: a start did not show Checking, then Syncing or Up to date"
        ));
    }
    Ok(())
}

/// (a), and (b)'s no opaque record (no scenario plants one; the adversary
/// tests do, outside the oracle).
fn check_records(folder: &FolderId, views: &[(PeerId, FolderView)]) -> Result<(), String> {
    let Some((first_peer, first)) = views.first() else {
        return Ok(());
    };
    let hashes = |v: &FolderView| v.records.iter().map(|r| r.hash).collect::<BTreeSet<_>>();
    let want = hashes(first);
    for (peer, v) in views {
        if hashes(v) != want {
            return Err(format!(
                "{peer} and {first_peer} hold different records of {folder}"
            ));
        }
        let sealed = v.tier == Tier::Sealed;
        for r in &v.records {
            let ok = if sealed {
                r.state == RecordState::Sealed
            } else {
                r.state == RecordState::Applied
            };
            if !ok {
                return Err(format!("{peer}: record {} is {:?}", r.hash, r.state));
            }
        }
    }
    Ok(())
}

/// (b): the same heads in display order on every read and write holder.
fn check_heads(
    sim: &Sim<Member>,
    folder: &FolderId,
    views: &[(PeerId, FolderView)],
) -> Result<(), String> {
    let mut want: Option<(PeerId, Vec<(String, Vec<_>)>)> = None;
    for (peer, v) in views {
        if v.tier == Tier::Sealed {
            continue;
        }
        let Some(e) = sim.peer(*peer).and_then(Member::engine) else {
            continue;
        };
        let files: Vec<(String, Vec<_>)> = e
            .files(folder)
            .into_iter()
            .map(|f| (f.path, f.heads.iter().map(|h| h.hash).collect()))
            .collect();
        match &want {
            None => want = Some((*peer, files)),
            Some((p, w)) if *w != files => {
                return Err(format!("{peer} and {p} differ in the heads of {folder}"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// A holder's disk: each path with heads, and its bases.
type Disk = Vec<(String, Vec<(Place, RecordHash)>)>;

/// (b′): what each read and write holder has on its disk (its bases)
/// matches its heads: each path's `Place::Path` base is its first head, each
/// conflict copy sits in its `Place::Copy` slot and no other copy does; at a
/// path with no heads the only base is a held tree delete's at its own
/// directory, so that nothing beneath a tree delete keeps a base unless it
/// is live; and every read and write holder has the same slots. Every path
/// is checked, since (b) refuses opaque records in every gate scenario
/// (module documentation).
fn check_bases(
    sim: &Sim<Member>,
    folder: &FolderId,
    views: &[(PeerId, FolderView)],
) -> Result<(), String> {
    let mut want: Option<(PeerId, Disk)> = None;
    for (peer, v) in views {
        if v.tier == Tier::Sealed {
            continue;
        }
        let Some(e) = sim.peer(*peer).and_then(Member::engine) else {
            continue;
        };
        let mut disk = Vec::new();
        for f in e.files(folder) {
            let mut expected: Vec<(Place, RecordHash)> = f
                .heads
                .first()
                .map(|h| (Place::Path, h.hash))
                .into_iter()
                .chain(
                    f.conflict_copies
                        .iter()
                        .map(|c| (Place::Copy(conflict_copy_name(&f.path, c)), *c)),
                )
                .collect();
            let mut bases = f.bases.clone();
            expected.sort();
            bases.sort();
            if bases != expected {
                let (have, want) = (bases.len(), expected.len());
                return Err(format!(
                    "{peer}: the disk at a path of {folder} is not its heads \
                     ({have} bases, {want} expected)"
                ));
            }
            disk.push((f.path, bases));
        }
        let headed: BTreeSet<String> = disk.iter().map(|(p, _)| p.clone()).collect();
        let heads: BTreeSet<RecordHash> = e
            .files(folder)
            .iter()
            .flat_map(|f| f.heads.iter().map(|h| h.hash))
            .collect();
        // Held records that are no head and no cleanup: the tree deletes.
        let trees: BTreeSet<RecordHash> = v
            .records
            .iter()
            .filter(|r| !r.cleanup && !heads.contains(&r.hash))
            .map(|r| r.hash)
            .collect();
        for (path, place, hash) in e.bases_beneath(folder, "") {
            if headed.contains(&path) {
                continue;
            }
            if place != Place::Path || !trees.contains(&hash) {
                return Err(format!(
                    "{peer}: a base of {folder} lies at a path with no heads \
                     and is no tree delete's"
                ));
            }
            disk.push((path, vec![(place, hash)]));
        }
        disk.sort();
        match &want {
            None => want = Some((*peer, disk)),
            Some((p, w)) if *w != disk => {
                return Err(format!(
                    "{peer} and {p} differ in what is on the disk of {folder}"
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// (c): reassembly on key holders, blobs on sealed holders.
fn check_chunks(
    sim: &Sim<Member>,
    ledger: &Rc<RefCell<Ledger>>,
    folder: &FolderId,
    views: &[(PeerId, FolderView)],
) -> Result<(), String> {
    for (peer, v) in views {
        let (Some(e), Some(storage)) =
            (sim.peer(*peer).and_then(Member::engine), sim.storage(*peer))
        else {
            continue;
        };
        let named = named(v);
        if let Some(c) = v
            .stored_chunks
            .iter()
            .find(|c| !named.contains(c) && !v.pending_free.contains(c))
        {
            return Err(format!(
                "{peer}: blob {c} is kept with no record naming it and no free pending"
            ));
        }
        if v.tier == Tier::Sealed {
            check_sealed_blobs(*peer, v, storage)?;
            continue;
        }
        for f in e.files(folder) {
            for head in f.heads.iter().filter(|h| h.is_file()) {
                let bytes = e
                    .read_file(storage, folder, &head.hash)
                    .map_err(|e| format!("{peer}: head {} does not read back: {e:?}", head.hash))?;
                let expected = ledger.borrow().bytes.get(&head.hash).cloned();
                if expected.as_ref() != Some(&bytes) {
                    return Err(format!(
                        "{peer}: head {} reads other bytes than were written",
                        head.hash
                    ));
                }
            }
        }
    }
    Ok(())
}

fn check_sealed_blobs(
    peer: PeerId,
    v: &FolderView,
    storage: &crate::storage::SimStorage,
) -> Result<(), String> {
    let named = named(v);
    for hash in v.stored_chunks.iter().filter(|c| named.contains(c)) {
        let blob = stored_blob(storage, &v.folder, hash)
            .ok()
            .flatten()
            .ok_or_else(|| format!("{peer}: blob {hash} missing"))?;
        if cipher_hash(&blob) != *hash {
            return Err(format!("{peer}: blob {hash} does not hash to its name"));
        }
        let named = v.records.iter().flat_map(|r| r.chunks.iter()).any(|c| {
            c.cipher_hash == *hash && usize::try_from(c.stored_len).ok() == Some(blob.len())
        });
        if !named {
            return Err(format!(
                "{peer}: blob {hash} has no record naming its length"
            ));
        }
    }
    Ok(())
}
