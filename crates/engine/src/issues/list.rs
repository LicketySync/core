// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Issues list, bounded per source: issues fall into classes by where
//! they come from, each class has a bound of its own, and no class ever
//! evicts another's entries, so no peer and no record a peer forwards can
//! crowd this device's own folder-health issues out of the list (TM-22:
//! every table a peer can grow is bounded per source). An issue raised again
//! is merged into its entry, whose count grows, and whatever a bound keeps
//! out is counted in its class's overflow, never dropped without trace
//! (TM-10).
//!
//! | Class | Kinds | Merged per | Bound | When full |
//! | --- | --- | --- | --- | --- |
//! | [`IssueClass::Local`] | store failure, misconfigured, unreadable, open report, local chunk corrupt, own counter ahead, open limit, the clock rule's four | folder and kind | one entry per folder and kind | never, for an engine (below) |
//! | [`IssueClass::Record`] | writer fault, chunk corrupt, size mismatch | folder, kind and record | [`MAX_RECORD_ISSUES_PER_FOLDER`] per folder | the folder's oldest record entry is evicted |
//! | [`IssueClass::ProvenPeer`] | a fault of a peer that proved a key of a folder this device holds | device and cause | [`MAX_PEER_ISSUES`] | the oldest proven-peer entry is evicted |
//! | [`IssueClass::UnprovenPeer`] | a fault of any other peer, its device ID proven or not | cause | one entry per cause | never more |
//!
//! The local class holds one entry per folder and kind, and a config holds at
//! most [`crate::MAX_FOLDERS`] folders, so an engine's local issues never
//! reach [`MAX_LOCAL_ISSUES`], the product of the two: a store failure is
//! always stored, never only counted. The bound keeps the list bounded on its
//! own; a newcomer past it would only be counted. Local entries stay until
//! this instance ends.
//!
//! A device ID proves only that the peer holds some device key, which anyone
//! can mint, so a peer counts as proven only once it has proven a key of a
//! folder this device holds (a folder opened on the connection). Every other
//! peer shares one entry per cause, whatever device IDs it shows. A merged
//! proven-peer entry moves to the newest place, so a peer that keeps failing
//! stays listed while one that stopped ages out.
//!
//! The residual: a key holder can mint fresh device IDs and, faulting under
//! each, evict other proven-peer entries, oldest first, each eviction counted
//! in the class's overflow. It holds a folder key already, so it is one of
//! the people the folder is shared with, and removing it is a re-key.

use super::{Issue, IssueKind, Subject};
use crate::issues::bump;

/// How many local kinds one folder can raise: a store failure for each of
/// its two causes, Misconfigured, Unreadable, the open report, a local chunk
/// corrupt, its own counter ahead, the open limit, and the clock rule's four
/// (out of range, from the future, the folder's time ahead, kept closed).
const LOCAL_KINDS: usize = 12;

/// The most local and folder-health entries the list holds: one per local
/// kind for each of the most folders a config holds.
pub const MAX_LOCAL_ISSUES: usize = crate::config::MAX_FOLDERS * LOCAL_KINDS;

/// The most entries about remote records the list holds per folder.
pub const MAX_RECORD_ISSUES_PER_FOLDER: usize = 16;

/// The most entries about peers whose device ID is proven.
pub const MAX_PEER_ISSUES: usize = 16;

/// Where an issue comes from, which decides its bound (module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueClass {
    /// This device's own folder health.
    Local,
    /// What a valid signature covers: a record or a chunk a writer made.
    Record,
    /// A fault of a peer that proved a key of a folder this device holds.
    ProvenPeer,
    /// A fault of any other peer.
    UnprovenPeer,
}

impl IssueClass {
    const ALL: [Self; 4] = [
        Self::Local,
        Self::Record,
        Self::ProvenPeer,
        Self::UnprovenPeer,
    ];

    const fn slot(self) -> usize {
        match self {
            Self::Local => 0,
            Self::Record => 1,
            Self::ProvenPeer => 2,
            Self::UnprovenPeer => 3,
        }
    }
}

impl Issue {
    /// The class the issue counts in.
    #[must_use]
    pub fn class(&self) -> IssueClass {
        match self.kind {
            IssueKind::PeerFault(_) => match self.subject {
                Subject::Peer {
                    device: Some(_),
                    holder: true,
                    ..
                } => IssueClass::ProvenPeer,
                _ => IssueClass::UnprovenPeer,
            },
            IssueKind::WriterFault { .. } | IssueKind::ChunkCorrupt | IssueKind::SizeMismatch => {
                IssueClass::Record
            }
            IssueKind::OwnCounterAhead
            | IssueKind::ClockOutOfRange
            | IssueKind::FromTheFuture
            | IssueKind::ClockAhead
            | IssueKind::KeptClosed
            | IssueKind::OpenReport
            | IssueKind::StoreFailure(_)
            | IssueKind::Misconfigured
            | IssueKind::Unreadable
            | IssueKind::LocalChunkCorrupt
            | IssueKind::OpenLimit => IssueClass::Local,
        }
    }

    /// Whether `other` is this issue raised again, by its class's merge key.
    fn same(&self, other: &Self) -> bool {
        if self.kind != other.kind {
            return false;
        }
        match self.class() {
            IssueClass::Local => self.folder == other.folder,
            IssueClass::Record => self.folder == other.folder && self.subject == other.subject,
            IssueClass::ProvenPeer => device(self) == device(other),
            IssueClass::UnprovenPeer => true,
        }
    }
}

fn device(issue: &Issue) -> Option<licketysync_keys::DeviceId> {
    match issue.subject {
        Subject::Peer { device, .. } => device,
        _ => None,
    }
}

/// One entry of the list: the issue as last raised, and how many times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueEntry {
    /// The issue, as raised the latest time (its peer handle, say).
    pub issue: Issue,
    /// How many times it was raised.
    pub count: u64,
}

/// The Issues list (module documentation).
#[derive(Clone, Debug, Default)]
pub struct Issues {
    /// One list per class, each oldest first.
    classes: [Vec<IssueEntry>; 4],
    /// Per class, the newcomers not stored and the entries evicted.
    overflow: [u64; 4],
}

impl Issues {
    /// Raises `issue` into its class (module documentation).
    pub(crate) fn raise(&mut self, issue: Issue) {
        let class = issue.class();
        let slot = class.slot();
        let Some(list) = self.classes.get_mut(slot) else {
            return;
        };
        if let Some(i) = list.iter().position(|e| e.issue.same(&issue)) {
            let mut entry = list.remove(i);
            entry.count = entry.count.saturating_add(1);
            entry.issue = issue;
            // A proven peer's entry moves to the newest place; the others
            // keep theirs.
            let at = if class == IssueClass::ProvenPeer {
                list.len()
            } else {
                i
            };
            list.insert(at, entry);
            return;
        }
        let Some(overflow) = self.overflow.get_mut(slot) else {
            return;
        };
        match class {
            // One entry per cause, and a newcomer is a cause not listed yet.
            IssueClass::UnprovenPeer => {}
            IssueClass::Local => {
                if list.len() >= MAX_LOCAL_ISSUES {
                    bump(overflow);
                    return;
                }
            }
            IssueClass::Record => {
                let mine = |e: &IssueEntry| e.issue.folder == issue.folder;
                if list.iter().filter(|e| mine(e)).count() >= MAX_RECORD_ISSUES_PER_FOLDER {
                    if let Some(oldest) = list.iter().position(mine) {
                        list.remove(oldest);
                    }
                    bump(overflow);
                }
            }
            IssueClass::ProvenPeer => {
                if list.len() >= MAX_PEER_ISSUES {
                    // At least MAX_PEER_ISSUES entries: the oldest is there.
                    list.remove(0);
                    bump(overflow);
                }
            }
        }
        list.push(IssueEntry { issue, count: 1 });
    }

    /// Every entry, class by class (local, record, proven peer, unproven
    /// peer), each class oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &IssueEntry> + '_ {
        self.classes.iter().flatten()
    }

    /// The entries of one class, oldest first.
    #[must_use]
    pub fn of(&self, class: IssueClass) -> &[IssueEntry] {
        self.classes.get(class.slot()).map_or(&[], Vec::as_slice)
    }

    /// Every issue, in the order of [`Issues::entries`], each once however
    /// often it was raised.
    #[must_use]
    pub fn list(&self) -> Vec<Issue> {
        self.entries().map(|e| e.issue.clone()).collect()
    }

    /// The newcomers `class` did not store and the entries it evicted.
    #[must_use]
    pub fn overflow(&self, class: IssueClass) -> u64 {
        self.overflow.get(class.slot()).copied().unwrap_or(0)
    }

    /// Overflow over every class.
    #[must_use]
    pub fn overflow_total(&self) -> u64 {
        IssueClass::ALL
            .iter()
            .map(|c| self.overflow(*c))
            .fold(0, u64::saturating_add)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;
    use crate::issues::StoreFailureCause;
    use crate::runtime::PeerId;
    use licketysync_keys::{CipherHash, DeviceId, FolderId, RecordHash};
    use licketysync_protocol::Cause;

    fn id32(n: u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_be_bytes());
        b
    }

    fn record_issue(folder: u8, n: u32) -> Issue {
        Issue {
            folder: Some(FolderId([folder; 32])),
            kind: IssueKind::WriterFault { shared: true },
            subject: Subject::Record(RecordHash(id32(n))),
        }
    }

    fn proven(n: u32, cause: Cause) -> Issue {
        Issue {
            folder: None,
            kind: IssueKind::PeerFault(cause),
            subject: Subject::Peer {
                peer: PeerId::new(u64::from(n)),
                device: Some(DeviceId(id32(n))),
                holder: true,
            },
        }
    }

    fn unproven(n: u32, cause: Cause) -> Issue {
        Issue {
            folder: None,
            kind: IssueKind::PeerFault(cause),
            subject: Subject::Peer {
                peer: PeerId::new(u64::from(n)),
                device: None,
                holder: false,
            },
        }
    }

    fn local(folder: u8, kind: IssueKind) -> Issue {
        Issue {
            folder: Some(FolderId([folder; 32])),
            kind,
            subject: Subject::None,
        }
    }

    /// One issue of every class, raised before a flood.
    fn seeded() -> Issues {
        let mut issues = Issues::default();
        issues.raise(local(1, IssueKind::StoreFailure(StoreFailureCause::Full)));
        issues.raise(record_issue(1, 0));
        issues.raise(proven(0, Cause::Forged));
        issues.raise(unproven(0, Cause::Malformed));
        issues
    }

    fn snapshot(issues: &Issues, class: IssueClass) -> Vec<IssueEntry> {
        issues.of(class).to_vec()
    }

    /// Every class but `flooded` is exactly as before, and has no overflow.
    fn untouched(before: &Issues, after: &Issues, flooded: IssueClass) {
        for class in IssueClass::ALL {
            if class != flooded {
                assert_eq!(
                    snapshot(after, class),
                    snapshot(before, class),
                    "{class:?} changed"
                );
                assert_eq!(after.overflow(class), 0, "{class:?} overflow");
            }
        }
    }

    #[test]
    fn issues_fall_into_their_classes() {
        let issues = seeded();
        assert_eq!(issues.list().len(), 4);
        for class in IssueClass::ALL {
            assert_eq!(issues.of(class).len(), 1, "{class:?}");
        }
        assert_eq!(
            issues.list().first(),
            Some(&local(1, IssueKind::StoreFailure(StoreFailureCause::Full)))
        );
        assert_eq!(issues.overflow_total(), 0);
    }

    #[test]
    fn a_flood_of_proven_peers_evicts_only_proven_peers_oldest_first() {
        let before = seeded();
        let mut issues = before.clone();
        for n in 1..=1_000 {
            issues.raise(proven(n, Cause::Forged));
        }
        untouched(&before, &issues, IssueClass::ProvenPeer);
        let peers = issues.of(IssueClass::ProvenPeer);
        assert_eq!(peers.len(), MAX_PEER_ISSUES);
        assert_eq!(
            peers.last().map(|e| &e.issue),
            Some(&proven(1_000, Cause::Forged))
        );
        assert_eq!(
            issues.overflow(IssueClass::ProvenPeer),
            1_000 + 1 - MAX_PEER_ISSUES as u64
        );
    }

    #[test]
    fn a_merged_proven_peer_moves_to_the_newest_place_and_counts() {
        let mut issues = Issues::default();
        for n in 0..3 {
            issues.raise(proven(n, Cause::Forged));
        }
        // The same device under a new handle (a reconnection).
        let mut again = proven(0, Cause::Forged);
        if let Subject::Peer { peer, .. } = &mut again.subject {
            *peer = PeerId::new(77);
        }
        issues.raise(again.clone());
        let peers = issues.of(IssueClass::ProvenPeer);
        assert_eq!(peers.len(), 3);
        assert_eq!(
            peers.last(),
            Some(&IssueEntry {
                issue: again,
                count: 2
            })
        );
        issues.raise(proven(0, Cause::Malformed));
        assert_eq!(
            issues.of(IssueClass::ProvenPeer).len(),
            4,
            "another cause, another entry"
        );
    }

    #[test]
    fn unproven_peers_make_one_entry_per_cause_and_evict_nothing() {
        let before = seeded();
        let mut issues = before.clone();
        for n in 1..=1_000 {
            issues.raise(unproven(n, Cause::Malformed));
            issues.raise(unproven(n, Cause::FrameOverLimit));
        }
        untouched(&before, &issues, IssueClass::UnprovenPeer);
        let entries = issues.of(IssueClass::UnprovenPeer);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.first().map(|e| e.count), Some(1_001));
        assert_eq!(entries.last().map(|e| e.count), Some(1_000));
        assert_eq!(issues.overflow(IssueClass::UnprovenPeer), 0);
    }

    #[test]
    fn a_flood_of_record_issues_evicts_only_that_folders_oldest() {
        let before = seeded();
        let mut issues = before.clone();
        issues.raise(record_issue(2, 0));
        let other_folder = issues.of(IssueClass::Record).last().cloned();
        for n in 1..=1_000 {
            issues.raise(record_issue(1, n));
        }
        for class in [
            IssueClass::Local,
            IssueClass::ProvenPeer,
            IssueClass::UnprovenPeer,
        ] {
            assert_eq!(
                snapshot(&issues, class),
                snapshot(&before, class),
                "{class:?}"
            );
        }
        let records = issues.of(IssueClass::Record);
        let of = |f: u8| {
            records
                .iter()
                .filter(|e| e.issue.folder == Some(FolderId([f; 32])))
                .count()
        };
        assert_eq!(of(1), MAX_RECORD_ISSUES_PER_FOLDER);
        assert_eq!(of(2), 1, "the other folder's entry stays");
        assert!(other_folder.is_some_and(|e| records.contains(&e)));
        assert!(
            !records.iter().any(|e| e.issue == record_issue(1, 0)),
            "folder 1's oldest went"
        );
        assert_eq!(
            issues.overflow(IssueClass::Record),
            1_001 - MAX_RECORD_ISSUES_PER_FOLDER as u64
        );
        // The same record raised again is one entry, counted.
        issues.raise(record_issue(1, 1_000));
        assert_eq!(
            issues.of(IssueClass::Record).last().map(|e| e.count),
            Some(2)
        );
    }

    #[test]
    fn local_issues_merge_per_folder_and_kind_and_every_folder_of_a_config_is_stored() {
        let before = seeded();
        let mut issues = before.clone();
        // Repeats merge: a store failure each pause, a corrupt blob each time.
        for _ in 0..100 {
            issues.raise(local(1, IssueKind::StoreFailure(StoreFailureCause::Full)));
        }
        for n in 0..100 {
            issues.raise(Issue {
                folder: Some(FolderId([1; 32])),
                kind: IssueKind::LocalChunkCorrupt,
                subject: Subject::Chunk(CipherHash(id32(n))),
            });
        }
        assert_eq!(issues.of(IssueClass::Local).len(), 2);
        assert_eq!(
            issues.of(IssueClass::Local).first().map(|e| e.count),
            Some(101)
        );
        // Every local kind of as many folders as a config holds is stored:
        // a store failure is never only counted.
        let kinds = [
            IssueKind::StoreFailure(StoreFailureCause::Full),
            IssueKind::StoreFailure(StoreFailureCause::Io),
            IssueKind::Misconfigured,
            IssueKind::Unreadable,
            IssueKind::OpenReport,
            IssueKind::LocalChunkCorrupt,
            IssueKind::OwnCounterAhead,
            IssueKind::OpenLimit,
            IssueKind::ClockOutOfRange,
            IssueKind::FromTheFuture,
            IssueKind::ClockAhead,
            IssueKind::KeptClosed,
        ];
        assert_eq!(kinds.len(), LOCAL_KINDS);
        let folders: Vec<FolderId> = core::iter::once(FolderId([1; 32]))
            .chain(
                (1..crate::config::MAX_FOLDERS).map(|n| FolderId(id32(u32::try_from(n).unwrap()))),
            )
            .collect();
        for folder in &folders {
            for kind in kinds {
                issues.raise(Issue {
                    folder: Some(*folder),
                    kind,
                    subject: Subject::None,
                });
            }
        }
        assert_eq!(issues.of(IssueClass::Local).len(), MAX_LOCAL_ISSUES);
        assert_eq!(issues.overflow(IssueClass::Local), 0);
        assert_eq!(
            issues.of(IssueClass::Local).first().map(|e| e.count),
            Some(102),
            "merged in its place"
        );
        // A folder past what a config holds would only be counted.
        issues.raise(local(0xee, IssueKind::Misconfigured));
        assert_eq!(issues.of(IssueClass::Local).len(), MAX_LOCAL_ISSUES);
        assert_eq!(issues.overflow(IssueClass::Local), 1);
        for class in [
            IssueClass::Record,
            IssueClass::ProvenPeer,
            IssueClass::UnprovenPeer,
        ] {
            assert_eq!(
                snapshot(&issues, class),
                snapshot(&before, class),
                "{class:?}"
            );
            assert_eq!(issues.overflow(class), 0);
        }
    }

    #[test]
    fn floods_of_every_peer_and_record_class_leave_a_store_failure_stored() {
        // The security finding: nothing a peer causes keeps a folder's own
        // issue out (TM-22).
        let mut issues = Issues::default();
        for n in 0..500 {
            issues.raise(proven(n, Cause::Forged));
            issues.raise(unproven(n, Cause::Malformed));
            issues.raise(record_issue(1, n));
        }
        let failure = local(1, IssueKind::StoreFailure(StoreFailureCause::Full));
        issues.raise(failure.clone());
        assert!(issues.list().contains(&failure));
        assert_eq!(issues.overflow(IssueClass::Local), 0);
    }
}
