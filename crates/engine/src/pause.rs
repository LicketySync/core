// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What follows a store failure (`protocol.md` section 5, "Store failure"),
//! and the folders held paused.
//!
//! A put or a commit that fails rolls the whole handler back: the storage
//! stages atomically, so nothing of the handler was persisted, and the
//! index's transactions are dropped, which undoes their changes exactly with
//! nothing rebuilt (`crate::sync`). Every folder the handler meant to change
//! is **paused**: it judges no record (its pages are answered skipped, TM-22:
//! no peer can make it verify the same record again and again), stores no
//! chunk, asks for none, and refuses local writes, while it stays proven to
//! its peers, serves what it holds and answers chunk requests (decision for
//! gap G4). An issue names the cause, the Status says `paused`, and every
//! connection where the folder is open holds it paused
//! (`Connection::set_paused`: no round of this side's starts for it, and the
//! peer's pushes are not counted, so no cursor passes a record that was
//! refused), so it reads Syncing once it resumes until a round ends caught
//! up. A resume probe stages `e/probe` every `resume_probe`, and the
//! handler's one commit carries it; once one commits, the pause ends and
//! each of those connections takes the folder again, which owes a round
//! there and brings back what the folder skipped. A pause closes no
//! connection.

use licketysync_keys::FolderId;

use crate::engine::Engine;
use crate::issues::{Issue, IssueKind, StoreFailureCause, Subject, bump};
use crate::runtime::{Context, StorageError};
use crate::store::PROBE;
use crate::work::Work;

impl Engine {
    /// Pauses `folder` for a store failure (module documentation).
    pub(crate) fn pause(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
        cause: StoreFailureCause,
    ) {
        self.lost_rounds(&folder);
        let Some(f) = self.folders.get_mut(&folder) else {
            return;
        };
        let was_held = f.held_paused();
        if f.paused.replace(cause).is_none() {
            self.issues.raise(Issue {
                folder: Some(folder),
                kind: IssueKind::StoreFailure(cause),
                subject: Subject::None,
            });
        }
        if !was_held {
            self.hold_paused(cx, work, folder, true);
        }
    }

    /// Tells every connection where `folder` is open that it is held paused,
    /// or taken again (which owes a round on each).
    pub(crate) fn hold_paused(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
        paused: bool,
    ) {
        for peer in self.open_on(&folder) {
            if let Some(out) = self.with_conn(cx, peer, |c, t| c.set_paused(t, folder, paused)) {
                if !paused {
                    bump(&mut self.counters.rounds_owed);
                }
                self.apply(cx, work, peer, out);
            }
        }
    }

    /// The resume probe: stages `e/probe` for the handler's one commit,
    /// whose success resumes every folder paused for a store failure
    /// ([`Self::resume`]).
    pub(crate) fn probe(&mut self, cx: &mut dyn Context, work: &mut Work) {
        if self.folders.values().all(|f| f.paused.is_none()) {
            return;
        }
        let tried: Result<(), StorageError> = cx.storage().put(PROBE, &[]);
        match tried {
            Ok(()) => {
                work.staged = true;
                work.sync.probing = true;
            }
            Err(e) => work.failed = Some(e),
        }
    }

    /// The probe's commit succeeded: every folder paused for a store failure
    /// resumes, and each connection where it is open takes it again.
    pub(crate) fn resume(&mut self, cx: &mut dyn Context, work: &mut Work) {
        let resumed: Vec<FolderId> = self
            .folders
            .iter_mut()
            .filter_map(|(id, f)| {
                f.paused.take()?;
                f.book.dirty = true;
                f.recheck_disk = true;
                (!f.held_paused()).then_some(*id)
            })
            .collect();
        for folder in resumed {
            work.passes.insert(folder);
            // What waited while it was paused (its bases, the open's
            // changes, chunk frees) commits in a handler of its own at once.
            self.deferred.entry(folder).or_default();
            self.hold_paused(cx, work, folder, false);
        }
    }
}
