// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Opening every folder at start (`protocol.md` 4.4, "Opening a folder";
//! 4.7 item 8; TM-9).
//!
//! For each folder the engine shows **Checking**, reads its stored state
//! (counting the entries that do not decode, gap G6) and its stored-chunk
//! markers, and opens the index, which checks every stored record and every
//! base kept only as a base again on every core (gap G2: the verdicts are
//! joined in input order, so nothing about threads reaches the run). A
//! folder with no stored state is created afresh (`Index::create`, its first
//! epoch drawn). What the open changed (records another replaces or that
//! expired, a new epoch, a repaired high-water mark, records numbered
//! afresh, per-peer state past its horizon) is staged with the folder's
//! first transaction, on-start's one commit, and kept until a commit carries
//! it (`Folder::open_changes`); so are the frees the pending-free list still
//! holds ("an open finishes whatever it lists before the folder syncs"). A
//! failure there pauses the folder, which stages it all again once it
//! resumes. Phase 0 opens
//! synchronously inside `on_start`: the runtime connects no peer before it
//! returns, so no peer's folder proof can arrive while a folder is being
//! checked (gap G5).
//!
//! Then: one issue for what the open found (records dropped, entries that
//! did not decode, a corrupt high-water mark, records numbered afresh,
//! misplaced bases), with the counts and at most 16 record hashes;
//! **Misconfigured** when the store returned something and nothing passed,
//! in which case the folder is never proven to a peer and an error issue is
//! raised, so the engine never fills an empty index from a store of another
//! folder or key; and **Closed** while the records stored lie more than a
//! year ahead of this device's clock (the clock rule, 4.4 "A clock set
//! back"): not proven to peers, with the clock-rule issue
//! (`IssueKind::KeptClosed`), the open report saying so
//! (`OpenCounts::kept_closed`).

use licketysync_index::Index;
use licketysync_keys::FolderId;
use licketysync_keys::FolderKey;
use licketysync_protocol::connection::{Keys, ProveError};
use licketysync_protocol::proof::FolderCredential;

use crate::chunks::ChunkBook;
use crate::engine::Engine;
use crate::folder::{Folder, FolderState, Health, OpenCounts, Transitions};
use crate::issues::{open_subject, Issue, IssueKind, Subject};
use crate::runtime::{Context, PeerId};
use crate::store::{load, load_stored_chunks, Loaded};
use crate::work::Work;

impl Engine {
    /// `on_start`'s work: every folder of the config opened, then the
    /// credentials of those that may be proven.
    pub(crate) fn open_folders(&mut self, cx: &mut dyn Context, work: &mut Work) {
        for key in core::mem::take(&mut self.to_open) {
            self.open_one(cx, key);
        }
        self.refresh_credentials();
        work.passes.extend(self.folders.keys().copied());
        self.arm_opens_at(cx);
    }

    /// The credentials of every folder that may be proven now
    /// (`Folder::credentialed`): what a new connection proves, and what a
    /// peer's proof is checked against.
    pub(crate) fn refresh_credentials(&mut self) {
        self.credentials = self
            .folders
            .values()
            .filter(|f| f.credentialed())
            .map(|f| FolderCredential::new(f.index.key()))
            .collect();
    }

    /// Proves `folder` on every connection the engine still acts on: a
    /// folder that could not be proven before (kept closed by the clock rule)
    /// and now may be. A peer whose own folder was kept closed too, and opens
    /// later, proves nothing on its own, so without this the folder would
    /// open on no connection that was there while both were closed. Where the
    /// peer proved it earlier and this side answered REJECTED, the peer does
    /// not prove it again on that connection (3.5), so the folder opens there
    /// only on the next connection.
    pub(crate) fn prove_everywhere(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
    ) {
        let peers: Vec<PeerId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.reacts())
            .map(|(p, _)| *p)
            .collect();
        for peer in peers {
            let t = crate::engine::tick(cx, peer);
            let Some(c) = self.conns.get_mut(&peer) else {
                continue;
            };
            let keys = Keys {
                device: &self.device,
                folders: &self.credentials,
            };
            let proved = c
                .protocol
                .prove(&keys, &mut |b: &mut [u8]| cx.fill_random(b), t, folder);
            match proved {
                Ok(out) => self.apply(cx, work, peer, out),
                // At the bound of proofs on that connection, or closing.
                Err(ProveError::TooMany | ProveError::Closed) => {}
                Err(_) => self.counters.bug(),
            }
        }
    }

    fn open_one(&mut self, cx: &mut dyn Context, key: FolderKey) {
        let id = key.folder_id();
        let tier = key.tier();
        let chunk_keys = key.chunk_keys();
        let record_keys = key.record_keys();
        let mut transitions = Transitions::default();
        transitions.record(cx.now(), FolderState::Checking);
        let clock_us = cx.wall_time_us();
        let storage = cx.storage();
        let read = load(storage, &id).and_then(|l| Ok((l, load_stored_chunks(storage, &id)?)));
        let mut health = Health::Usable;
        let (loaded, stored_chunks) = read.unwrap_or_else(|_| {
            health = Health::Unreadable;
            (Loaded::default(), std::collections::BTreeSet::default())
        });
        let returned =
            loaded.stored.records.len() + loaded.stored.base_only.len() + loaded.stored.undecodable;
        let mut open = OpenCounts::default();
        let mut closed_until = None;
        let pending_free = loaded.pending_free;
        let fill = &mut |b: &mut [u8]| cx.fill_random(b);
        let (index, changes) = if loaded.existed {
            let (index, report) = Index::open(key, self.own, loaded.stored, clock_us, fill);
            open = OpenCounts {
                dropped: report.dropped.len() as u64,
                undecodable: report.undecodable as u64,
                hw_corrupt: report.hw_corrupt,
                renumbered: report.renumbered,
                misplaced_bases: report.misplaced_bases.len() as u64,
                kept_closed: report.opens_at.is_some(),
            };
            if let Some(subject) = open_subject(&report) {
                self.issues.raise(Issue {
                    folder: Some(id),
                    kind: IssueKind::OpenReport,
                    subject,
                });
            }
            closed_until = report.opens_at;
            (index, report.changes)
        } else {
            Index::create(key, self.own, fill)
        };
        if health == Health::Usable && returned > 0 && index.is_empty() {
            health = Health::Misconfigured {
                dropped: open.dropped,
                undecodable: open.undecodable,
            };
        }
        match health {
            Health::Misconfigured { .. } => self.raise_error(id, IssueKind::Misconfigured),
            Health::Unreadable => self.raise_error(id, IssueKind::Unreadable),
            Health::Usable => {
                if closed_until.is_some() {
                    self.issues.raise(Issue {
                        folder: Some(id),
                        kind: IssueKind::KeptClosed,
                        subject: Subject::None,
                    });
                }
            }
        }
        let unapplied = index.paths().map(str::to_owned).collect();
        let open_changes = (health == Health::Usable
            && (!changes.is_empty() || !changes.freed.is_empty()))
        .then_some(changes);
        self.folders.insert(
            id,
            Folder {
                id,
                tier,
                index,
                chunk_keys,
                record_keys,
                book: ChunkBook::new(stored_chunks),
                health,
                paused: None,
                closed_until,
                open,
                state: FolderState::Checking,
                transitions,
                unapplied,
                free_due: !pending_free.is_empty(),
                pending_free,
                recheck_disk: true,
                open_changes,
            },
        );
    }

    fn raise_error(&mut self, folder: licketysync_keys::FolderId, kind: IssueKind) {
        self.issues.raise(Issue {
            folder: Some(folder),
            kind,
            subject: Subject::None,
        });
    }
}
