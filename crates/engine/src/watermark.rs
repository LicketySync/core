// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A write holder's watermark (`protocol.md` 4.4, "Expiry by the watermark";
//! 4.7 item 6) and the rounds a change of the greatest watermark owes (4.5,
//! "Round owed").
//!
//! # When a write holder checks
//!
//! Each folder this device writes owes a check ([`crate::folder::Folder`]'s
//! `check_due`) when it opens, once the open is done; when the device resumes
//! from sleep ([`crate::runtime::Peer::on_resumed`]); and at least once per
//! `WATERMARK_CHECK_INTERVAL` of monotonic time while it stays open (the
//! `WatermarkCheck` timer, re-armed at each). The check runs in phase B, last
//! in the folder's transaction, so that it sees every record its commit
//! holds; in a transaction that signed a cleanup already it waits for the
//! next commit, made by a handler of its own at once, so that a watermark
//! goes in a cleanup with no group only when no other cleanup goes in its
//! commit (case (d)). The index computes the candidate and signs it when the
//! interval since the last signing has passed: within this opening by the
//! monotonic time since the signing this module keeps (`signed_at`), the
//! runtime's monotonic clock counting time asleep (`runtime::Clock::now`);
//! across openings by the wall-clock reading the index keeps with the
//! folder's metadata. The cleanup it signs is pushed like any record.
//!
//! # Rounds owed
//!
//! A commit that raised the greatest watermark held and expired a record, or
//! lowered it (`licketysync_index::Txn::watermark_moved`), owes a round on
//! every connection where the folder is open, once it has committed: at once
//! toward a peer that reports the read or write tier, and toward one that
//! reports the sealed tier at most once per `WATERMARK_INTERVAL`, which the
//! connection keeps (`Connection::watermark_moved`).

use licketysync_keys::FolderId;

use crate::engine::Engine;
use crate::issues::bump;
use crate::runtime::Context;
use crate::timers::Purpose;
use crate::work::Work;

impl Engine {
    /// Arms the periodic check `WATERMARK_CHECK_INTERVAL` (as the timing
    /// scales it) from now, while a folder this device signs in is open.
    pub(crate) fn arm_watermark_checks(&mut self, cx: &mut dyn Context) {
        if self.folders.values().any(crate::folder::Folder::signs) {
            let at = cx
                .now()
                .saturating_add(self.settings.timing.watermark_check);
            if !self.timers.arm(cx, Purpose::WatermarkCheck, at) {
                self.counters.bug();
            }
        }
    }

    /// Every folder this device signs in owes a check: the periodic timer
    /// fired, or the device resumed from sleep. The timer is armed afresh.
    pub(crate) fn watermark_checks_due(&mut self, cx: &mut dyn Context) {
        for f in self.folders.values_mut() {
            if f.signs() {
                f.check_due = true;
            }
        }
        self.arm_watermark_checks(cx);
    }

    /// Phase C: a committed change of `folder`'s greatest watermark owes a
    /// round on every connection where the folder is open (module
    /// documentation).
    pub(crate) fn watermark_moved(
        &mut self,
        cx: &mut dyn Context,
        work: &mut Work,
        folder: FolderId,
    ) {
        for peer in self.open_on(&folder) {
            if let Some(out) = self.with_conn(cx, peer, |c, t| c.watermark_moved(t, folder)) {
                bump(&mut self.counters.watermark_rounds);
                self.apply(cx, work, peer, out);
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use core::cell::Cell;
    use core::time::Duration;

    use licketysync_keys::records::SignedRecord;
    use licketysync_keys::{CipherHash, DeviceId, RecordHash};
    use licketysync_protocol::Cause;
    use licketysync_protocol::frame::MessageType;
    use licketysync_protocol::limits::{
        TOMBSTONE_HORIZON, WATERMARK_CHECK_INTERVAL, WATERMARK_INTERVAL,
    };
    use licketysync_protocol::record::{
        Chunk, CleanupDraft, Dot, Group, IndexDraft, Kind, Meta, Vector,
    };

    use crate::FolderState;
    use crate::rules::plant_and_restart;
    use crate::runtime::Peer as _;
    use crate::testkit::{Net, config, folder_key, write_key};
    use crate::tests::{folder, state, write};

    /// A year and a day of the wall clock, in seconds: past the horizon.
    const YEAR: u64 = TOMBSTONE_HORIZON / 1_000_000 + 86_400;

    /// Node `i`'s greatest watermark held, and the watermarks it signed.
    fn watermark(net: &Net, i: usize) -> (u64, u64) {
        let e = &net.nodes[i].engine;
        (
            e.folder(&folder()).unwrap().watermark,
            e.counters().watermarks_signed,
        )
    }

    fn holds(net: &Net, i: usize, r: &RecordHash) -> bool {
        net.nodes[i]
            .engine
            .folder(&folder())
            .unwrap()
            .records
            .iter()
            .any(|x| x.hash == *r)
    }

    /// A write holder alone that wrote and deleted `f.txt`: the tombstone.
    fn deleted_alone(net: &mut Net, i: usize) -> RecordHash {
        let f = folder();
        write(net, i, "f.txt", b"f").unwrap();
        net.with(i, |e, cx| e.delete(cx, f, "f.txt", 0)).unwrap()
    }

    #[test]
    fn a_write_holder_checks_hourly_and_signs_once_the_deletion_is_a_year_old() {
        // 4.4, "When a write holder signs one": at least once per
        // WATERMARK_CHECK_INTERVAL of monotonic time while the folder is
        // open; a deletion held a year by the wall clock is passed by the
        // watermark signed at the next check, which expires it.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let t = deleted_alone(&mut net, 0);
        net.advance(WATERMARK_CHECK_INTERVAL);
        assert_eq!(watermark(&net, 0), (0, 0), "a check: nothing old");
        net.nodes[0].cx.wall += YEAR;
        assert_eq!(watermark(&net, 0), (0, 0), "no check until the timer");
        write(&mut net, 0, "g.txt", b"g").unwrap();
        assert_eq!(watermark(&net, 0), (0, 0), "a write's commit makes none");
        net.advance(WATERMARK_CHECK_INTERVAL);
        assert_eq!(watermark(&net, 0).1, 1, "the hourly check signed");
        assert!(watermark(&net, 0).0 > 0);
        assert!(!holds(&net, 0, &t), "the tombstone expired");
    }

    #[test]
    fn a_resume_from_sleep_checks_at_once() {
        // 4.4: a write holder checks when the device resumes from sleep
        // (`Peer::on_resumed`), not only on the hour.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let t = deleted_alone(&mut net, 0);
        net.nodes[0].cx.wall += YEAR;
        net.with(0, |e, cx| e.on_resumed(cx));
        assert_eq!(watermark(&net, 0).1, 1, "signed in the resume's handler");
        assert!(!holds(&net, 0, &t));
        // A read holder resumes and signs nothing.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 2)])]);
        net.with(0, |e, cx| e.on_resumed(cx));
        assert_eq!(watermark(&net, 0), (0, 0));
    }

    #[test]
    fn a_write_holder_checks_when_the_folder_opens() {
        // 4.4: a write holder checks when the folder opens, once the open is
        // done: here a year after its deletion, offline meanwhile; and the
        // arrival it kept in its store is what it counts from.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let t = deleted_alone(&mut net, 0);
        net.nodes[0].cx.wall += YEAR;
        net.restart(0, config(0, vec![folder_key(1, 1)]));
        assert_eq!(watermark(&net, 0).1, 1, "signed at the open");
        assert!(!holds(&net, 0, &t));
        assert_ne!(state(&net, 0), FolderState::Checking);
        // Restarted a day less than a year after the deletion: the stored
        // arrival is a day young, and nothing is signed.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let t = deleted_alone(&mut net, 0);
        net.nodes[0].cx.wall += YEAR - 2 * 86_400;
        net.restart(0, config(0, vec![folder_key(1, 1)]));
        assert_eq!(watermark(&net, 0), (0, 0));
        assert!(
            holds(&net, 0, &t),
            "held: its arrival came back from the store"
        );
    }

    #[test]
    fn a_write_holder_signs_at_most_once_a_day_within_an_opening_whatever_the_wall_clock() {
        // 4.4 and section 5, WATERMARK_INTERVAL: within one opening the
        // interval is counted by the monotonic clock alone; a wall clock
        // that jumps a year between two checks signs no second watermark
        // until a day of monotonic time has passed.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        deleted_alone(&mut net, 0);
        net.nodes[0].cx.wall += YEAR;
        net.with(0, |e, cx| e.on_resumed(cx));
        assert_eq!(watermark(&net, 0).1, 1);
        // A second deletion, then the wall clock a year further on.
        let f = folder();
        write(&mut net, 0, "g.txt", b"g").unwrap();
        let u = net.with(0, |e, cx| e.delete(cx, f, "g.txt", 0)).unwrap();
        net.nodes[0].cx.wall += YEAR;
        net.with(0, |e, cx| e.on_resumed(cx));
        net.advance(Duration::from_secs(23 * 3_600));
        assert_eq!(watermark(&net, 0).1, 1, "within a day of monotonic time");
        assert!(holds(&net, 0, &u));
        net.advance(Duration::from_secs(3_600));
        assert_eq!(watermark(&net, 0).1, 2, "a day on, at the hourly check");
        assert!(!holds(&net, 0, &u));
    }

    #[test]
    fn across_openings_the_interval_is_counted_by_the_wall_clock() {
        // 4.4: across openings, from the wall-clock reading kept with the
        // folder's metadata. Two deletions two days apart; the first is
        // signed past once it is a year old, the second still young. A
        // restart a fifth of a day later, the second now old, signs
        // nothing: a day has not passed since the stored signing. A restart
        // a day after that signing signs.
        const DAY: u64 = 86_400;
        let horizon = TOMBSTONE_HORIZON / 1_000_000;
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let t = deleted_alone(&mut net, 0);
        let start = net.nodes[0].cx.wall;
        net.nodes[0].cx.wall += 2 * DAY;
        let f = folder();
        write(&mut net, 0, "g.txt", b"g").unwrap();
        let u = net.with(0, |e, cx| e.delete(cx, f, "g.txt", 0)).unwrap();
        net.nodes[0].cx.wall = start + horizon + 19 * DAY / 10;
        net.with(0, |e, cx| e.on_resumed(cx));
        assert_eq!(watermark(&net, 0).1, 1, "past the first");
        assert!(!holds(&net, 0, &t) && holds(&net, 0, &u));
        let signed_at = net.nodes[0]
            .engine
            .folder(&folder())
            .unwrap()
            .last_signed_us;
        assert_eq!(signed_at, Some(net.nodes[0].cx.wall * 1_000_000));
        net.nodes[0].cx.wall += DAY / 5;
        net.restart(0, config(0, vec![folder_key(1, 1)]));
        assert_eq!(watermark(&net, 0).1, 0, "a fifth of a day after it signed");
        assert!(holds(&net, 0, &u));
        net.nodes[0].cx.wall += DAY;
        net.restart(0, config(0, vec![folder_key(1, 1)]));
        assert_eq!(watermark(&net, 0).1, 1, "a day after: the open signs");
        assert!(!holds(&net, 0, &u));
    }

    #[test]
    fn a_check_waits_for_a_commit_with_no_other_cleanup_of_its_own() {
        // 4.4, "Cleanup", case (d): a watermark goes in a cleanup with no
        // group only when no other cleanup goes in its commit. A check owed
        // in the handler of a tree delete, whose cleanup goes in that
        // commit, waits for a commit of its own, made at once: the tree
        // delete's cleanup carries the greatest watermark held then (none),
        // and the watermark goes in a cleanup of its own after.
        let mut net = Net::new(vec![config(0, vec![folder_key(1, 1)])]);
        let f = folder();
        net.with(0, |e, cx| e.mkdir(cx, f, "d", 0)).unwrap();
        write(&mut net, 0, "d/x", b"x").unwrap();
        let t = deleted_alone(&mut net, 0);
        net.nodes[0].cx.wall += YEAR;
        net.nodes[0].engine.folders.get_mut(&f).unwrap().check_due = true;
        net.with(0, |e, cx| e.delete(cx, f, "d", 0)).unwrap();
        assert_eq!(watermark(&net, 0), (0, 0), "the check waited");
        assert!(holds(&net, 0, &t));
        assert!(net.nodes[0].engine.folders[&f].check_due);
        net.advance(Duration::ZERO);
        assert_eq!(watermark(&net, 0).1, 1, "in a commit of its own");
        assert!(!holds(&net, 0, &t));
        assert!(!net.nodes[0].engine.folders[&f].check_due);
        let cleanups: Vec<u64> = net.nodes[0]
            .engine
            .folder(&f)
            .unwrap()
            .records
            .iter()
            .filter(|r| r.cleanup)
            .map(|r| r.forget_before)
            .collect();
        assert_eq!(cleanups.len(), 2, "the tree delete's and the watermark's");
        assert!(cleanups.contains(&0), "the tree delete's carries none");
    }

    #[test]
    fn a_rise_that_expires_a_record_owes_a_round_on_every_connection() {
        // 4.5, "Round owed": a commit that raises the greatest watermark and
        // expires a record owes a round on every connection where the
        // folder is open (the connection then owes it at once toward a read
        // or write holder, and toward a peer that reports the sealed tier at
        // most once per WATERMARK_INTERVAL: the protocol crate's test). The
        // sealed peer keeps the tombstone until that round names it in a
        // case-(c) cleanup.
        let mut net = Net::new(vec![
            config(0, vec![folder_key(1, 1)]),
            config(1, vec![folder_key(1, 1)]),
            config(2, vec![folder_key(1, 3)]),
        ]);
        net.connect(0, 1);
        net.connect(0, 2);
        net.advance(Duration::from_secs(2));
        let t = deleted_alone(&mut net, 0);
        net.advance(Duration::from_secs(3));
        assert!(holds(&net, 2, &t), "the sealed peer holds the tombstone");
        for n in &mut net.nodes {
            n.cx.wall += YEAR;
        }
        net.with(0, |e, cx| e.on_resumed(cx));
        net.advance(Duration::from_secs(30));
        let e = &net.nodes[0].engine;
        assert_eq!(e.counters().watermarks_signed, 1);
        assert_eq!(e.counters().watermark_rounds, 2, "one per connection");
        for i in 0..3 {
            assert!(!holds(&net, i, &t), "node {i}: gone");
        }
        for i in 0..3 {
            assert_eq!(state(&net, i), FolderState::UpToDate, "node {i}");
        }
    }

    /// A wall-clock reading in microseconds, for crafted counters.
    const US: u64 = 1_767_225_600_000_000;

    fn dot(device: u8, counter: u64) -> Dot {
        Dot {
            device: DeviceId([device; 32]),
            counter,
        }
    }

    /// A record of folder 1 at `path` by device `[writer; 32]` at `counter`
    /// over `vector`, signed with its write key: a file naming a chunk that
    /// nobody holds, or a tombstone.
    fn version(
        path: &str,
        writer: u8,
        counter: u64,
        vector: &[(u8, u64)],
        deleted: bool,
    ) -> SignedRecord {
        let key = write_key(1);
        let chunks: Vec<Chunk> = if deleted {
            Vec::new()
        } else {
            vec![Chunk {
                cipher_hash: CipherHash([0xc1; 32]),
                stored_len: 200,
            }]
        };
        IndexDraft {
            meta: Meta {
                path: path.to_owned(),
                kind: Kind::File,
                size: if deleted { 0 } else { 100 },
                mtime_ns: 0,
                mode: 0,
                plain_hashes: chunks
                    .iter()
                    .map(|_| licketysync_keys::chunk::PlainHash([3; 32]))
                    .collect(),
                written_at: 0,
                dot: dot(writer, counter),
                vector: Vector::from_sorted(vector.iter().map(|(d, c)| dot(*d, *c)).collect())
                    .unwrap(),
                deleted,
                tree: false,
            },
            chunks,
            replaces: Vec::new(),
        }
        .sign(&key, &key.record_keys(), &mut |b: &mut [u8]| b.fill(0x5a))
        .unwrap()
    }

    /// A cleanup of folder 1 by device `[writer; 32]` at `counter`, carrying
    /// `forget_before`, with one group forgetting `forget`, or none.
    fn cleanup(
        writer: u8,
        counter: u64,
        forget_before: u64,
        forget: &[RecordHash],
    ) -> SignedRecord {
        let key = write_key(1);
        let groups = if forget.is_empty() {
            Vec::new()
        } else {
            vec![Group {
                because: None,
                forget: forget.to_vec(),
            }]
        };
        CleanupDraft {
            dot: dot(writer, counter),
            forget_before,
            groups,
        }
        .sign(&key, &key.record_keys(), &mut |b: &mut [u8]| b.fill(0x5a))
        .unwrap()
    }

    /// Five nodes in folder 1 at `tier`, nodes 0 and 1 connected and done
    /// with their first rounds, and `sources` planted at nodes 2 and on,
    /// one record each, connected to nobody.
    fn crossing(tier: u8, sources: &[&SignedRecord]) -> Net {
        let node = |i: u8| config(i, vec![folder_key(1, tier)]);
        let mut net = Net::new((0..5).map(node).collect());
        net.connect(0, 1);
        net.advance(Duration::from_secs(2));
        for (i, r) in (2u8..).zip(sources) {
            plant_and_restart(&mut net, usize::from(i), &[(*r).clone()], node(i));
        }
        net
    }

    #[test]
    fn a_rise_that_expires_a_deletion_owes_the_round_that_brings_back_its_version() {
        // Section 8 item 8, "a rise of the greatest watermark" (4.5, "Round
        // owed"), on a write holder and on a read holder: Q (0) and Z (1)
        // count each other's pushes. Q holds a version V and then a
        // watermark W above the counter of a tombstone T that covers V; Z
        // holds T; their pushes cross. Q ignores T as expired; Z ignores V
        // as obsolete, then holds W, which expires T and owes a round
        // toward Q, which brings V: without that round V never comes again.
        for tier in [1, 2] {
            let v = version("p", 0x91, US + 1_000, &[], false);
            let t = version("p", 0x94, US + 2_000, &[(0x91, US + 1_000)], true);
            let w = cleanup(0x92, US + 3_000, US + 2_000, &[]);
            let mut net = crossing(tier, &[&v, &w, &t]);
            net.gate.rules.push((0, 1, MessageType::IndexRecords, None));
            net.connect(0, 2);
            net.advance(Duration::from_secs(2));
            net.connect(0, 3);
            net.advance(Duration::from_secs(2));
            assert!(holds(&net, 0, &v.hash()) && holds(&net, 0, &w.hash()));
            net.connect(1, 4);
            net.advance(Duration::from_secs(2));
            assert!(holds(&net, 1, &t.hash()), "tier {tier}");
            assert!(!holds(&net, 0, &t.hash()), "tier {tier}: expired at Q");
            // Q's pushes reach Z in order: V's, then W's.
            net.gate.rules.clear();
            let obsolete = net.nodes[1].engine.counters().of(Cause::Obsolete);
            let first = Cell::new(true);
            assert_eq!(net.deliver(0, 1, |_| first.replace(false)), 1);
            assert!(!holds(&net, 1, &v.hash()), "tier {tier}");
            assert_eq!(
                net.nodes[1].engine.counters().of(Cause::Obsolete),
                obsolete + 1,
                "tier {tier}: V obsolete while Z holds T"
            );
            net.deliver(0, 1, |_| true);
            net.advance(Duration::from_secs(15));
            for i in 0..2 {
                let held = (holds(&net, i, &v.hash()), holds(&net, i, &w.hash()));
                assert_eq!(held, (true, true), "tier {tier}, node {i}: V and W");
                assert!(!holds(&net, i, &t.hash()), "tier {tier}, node {i}");
            }
        }
    }

    #[test]
    fn a_fall_of_the_greatest_watermark_owes_the_round_that_brings_back_the_deletion() {
        // Section 8 item 8, "a fall of the greatest watermark" (4.4, "Expiry
        // by the watermark"; 4.5, "Round owed"), on a write holder and on a
        // read holder: Q (0) and Z (1) count each other's pushes. Z holds a
        // watermark W, Q a tombstone T dated below it, their pushes
        // crossing: Z ignores T as expired. Q then holds a cleanup C that a
        // dishonest write holder signed, naming the cleanup that carries W,
        // pushes it, and refuses W as obsolete when it arrives. Z holds C,
        // which lowers its greatest watermark below T's counter and owes a
        // round toward Q, which brings T: both end holding T and C, and
        // neither W.
        for tier in [1, 2] {
            let t = version("p", 0x91, US + 1_000, &[], true);
            let w = cleanup(0x92, US + 3_000, US + 2_000, &[]);
            let c = cleanup(0x93, US + 4_000, 0, &[w.hash()]);
            let mut net = crossing(tier, &[&t, &w, &c]);
            net.gate.rules.push((0, 1, MessageType::IndexRecords, None));
            net.gate.rules.push((1, 0, MessageType::IndexRecords, None));
            net.connect(1, 3);
            net.advance(Duration::from_secs(2));
            assert!(holds(&net, 1, &w.hash()), "tier {tier}");
            net.connect(0, 2);
            net.advance(Duration::from_secs(2));
            assert!(holds(&net, 0, &t.hash()), "tier {tier}");
            let expired = net.nodes[1].engine.counters().of(Cause::Expired);
            net.deliver(0, 1, |_| true);
            assert!(!holds(&net, 1, &t.hash()), "tier {tier}");
            assert_eq!(
                net.nodes[1].engine.counters().of(Cause::Expired),
                expired + 1,
                "tier {tier}: T expired at Z"
            );
            net.connect(0, 4);
            net.advance(Duration::from_secs(2));
            assert!(holds(&net, 0, &c.hash()), "tier {tier}");
            net.deliver(1, 0, |_| true);
            assert!(!holds(&net, 0, &w.hash()), "tier {tier}: W refused at Q");
            net.gate.rules.clear();
            net.deliver(0, 1, |_| true);
            net.advance(Duration::from_secs(15));
            for i in 0..2 {
                let held = (holds(&net, i, &t.hash()), holds(&net, i, &c.hash()));
                assert_eq!(held, (true, true), "tier {tier}, node {i}: T and C");
                assert!(!holds(&net, i, &w.hash()), "tier {tier}, node {i}");
                assert_eq!(watermark(&net, i).0, 0, "tier {tier}, node {i}");
            }
        }
    }

    #[test]
    fn toward_a_peer_reporting_the_sealed_tier_a_second_change_waits_for_the_interval() {
        // Section 8 item 8, "a false report", as far as the harness goes: a
        // peer cannot report a tier other than its key's here, so Q (0)
        // holds the sealed key; what Z (1) does depends only on the tier Q
        // reports. Z is a read holder, so that no case-(c) cleanup of its
        // owes a round of its own. Q holds a version V, which Z ignores as
        // obsolete while it holds the tombstone T that covers V. A watermark
        // W1 that expires another tombstone T1 owes a round toward Q at once;
        // a watermark W2 that expires T, within WATERMARK_INTERVAL of it,
        // owes none until that interval has passed; then V comes.
        let v = version("p", 0x91, US + 1_000, &[], false);
        let t = version("p", 0x94, US + 2_000, &[(0x91, US + 1_000)], true);
        let t1 = version("q", 0x95, US + 500, &[], true);
        let w1 = cleanup(0x92, US + 3_000, US + 500, &[]);
        let w2 = cleanup(0x92, US + 4_000, US + 2_000, &[]);
        let tier = |i: u8| if i == 0 { 3 } else { 2 };
        let node = |i: u8| config(i, vec![folder_key(1, tier(i))]);
        let mut net = Net::new((0..4).map(node).collect());
        plant_and_restart(&mut net, 0, core::slice::from_ref(&v), node(0));
        plant_and_restart(&mut net, 1, &[t.clone(), t1.clone()], node(1));
        plant_and_restart(&mut net, 2, core::slice::from_ref(&w1), node(2));
        plant_and_restart(&mut net, 3, core::slice::from_ref(&w2), node(3));
        net.connect(0, 1);
        net.advance(Duration::from_secs(2));
        assert!(!holds(&net, 1, &v.hash()), "obsolete while Z holds T");
        net.connect(1, 2);
        net.advance(Duration::from_secs(2));
        assert!(!holds(&net, 1, &t1.hash()), "W1 expired T1");
        net.connect(1, 3);
        net.advance(Duration::from_secs(2));
        assert!(!holds(&net, 1, &t.hash()), "W2 expired T");
        net.advance(Duration::from_secs(3_600));
        assert!(
            !holds(&net, 1, &v.hash()),
            "no round toward Q within the interval"
        );
        net.advance(WATERMARK_INTERVAL);
        assert!(
            holds(&net, 1, &v.hash()),
            "the round once the interval passed"
        );
    }
}
