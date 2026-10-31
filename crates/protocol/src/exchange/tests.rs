// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::assert_is_empty,
    reason = "test code"
)]

use proptest::prelude::*;
use prost::Message as _;

use licketysync_keys::RecordHash;

use super::*;
use crate::frame::MessageType;
use crate::limits::MAX_LOCAL_SEQ;
use crate::messages::Message;

const F: FolderId = FolderId([7; 32]);

#[test]
fn nibbles_are_read_high_first() {
    let mut key = [0u8; 64];
    key[0] = 0xab;
    key[31] = 0xcd;
    key[63] = 0xef;
    assert_eq!(nibble(&key, 0), 0xa);
    assert_eq!(nibble(&key, 1), 0xb);
    assert_eq!(nibble(&key, 2), 0);
    assert_eq!(nibble(&key, 62), 0xc);
    assert_eq!(nibble(&key, 63), 0xd);
    assert_eq!(nibble(&key, 126), 0xe);
    assert_eq!(nibble(&key, 127), 0xf);
    assert_eq!(nibble(&key, 128), 0, "past the key: no nibble");
}

#[test]
fn prefixes_on_the_wire() {
    // Every value 0 to 15, and every length 0 to 128.
    for len in [0usize, 1, 2, 63, 64, 65, 127, 128] {
        let wire: Vec<u8> = (0..len).map(|i| (i % 16) as u8).collect();
        let p = Prefix::from_wire(&wire).unwrap();
        assert_eq!(p.depth(), len);
        assert_eq!(p.to_wire(), wire);
        assert_eq!(p.nibbles().collect::<Vec<_>>(), wire);
        assert_eq!(p.nibbles().len(), len);
        assert_eq!(p.is_root(), len == 0);
        assert_eq!(p.is_full(), len == 128);
    }
    // 129 bytes, and a value of 16 (protocol.md 8 item 8: malformed).
    assert_eq!(Prefix::from_wire(&[0; 129]), None);
    assert_eq!(Prefix::from_wire(&[1, 16]), None);
    assert_eq!(Prefix::from_wire(&[0xff]), None);
    assert_eq!(Prefix::default(), Prefix::ROOT);
    assert_eq!(
        format!("{:?}", Prefix::from_wire(&[0xa, 3]).unwrap()),
        "Prefix(a3)"
    );
    assert_eq!(format!("{:?}", Prefix::ROOT), "Prefix()");
}

#[test]
fn children_keys_and_bounds() {
    let mut key = [0u8; 64];
    key[0] = 0x5c;
    key[1] = 0x30;
    key[40] = 0x77;
    let p = Prefix::of_key(&key, 3);
    assert_eq!(p.to_wire(), [5, 0xc, 3]);
    assert!(p.contains(&key));
    let mut other = key;
    other[1] = 0x40;
    assert!(!p.contains(&other));
    assert!(Prefix::ROOT.contains(&other));
    assert_eq!(p.child(15).unwrap().to_wire(), [5, 0xc, 3, 15]);
    assert_eq!(p.child(16), None);
    // Beneath the path tag, by the record-hash nibbles.
    let deep = Prefix::of_key(&key, 82);
    assert_eq!(deep.to_wire()[80..], [7, 7]);
    assert!(deep.contains(&key));
    let mut sibling = key;
    sibling[40] = 0x78;
    assert!(!deep.contains(&sibling) && Prefix::of_key(&key, 64).contains(&sibling));
    assert_eq!(
        Prefix::of_key(&key, 128).child(0),
        None,
        "a full key has none"
    );
    assert_eq!(
        Prefix::of_key(&key, 199).depth(),
        128,
        "clamped to a full key"
    );
    let (lo, hi) = p.bounds();
    assert_eq!(lo[..2], [0x5c, 0x30]);
    assert_eq!(hi[..2], [0x5c, 0x3f]);
    assert!(lo[2..].iter().all(|b| *b == 0) && hi[2..].iter().all(|b| *b == 0xff));
    assert_eq!(Prefix::ROOT.bounds(), ([0; 64], [0xff; 64]));
    let full = Prefix::of_key(&key, 128);
    assert_eq!(full.bounds(), (key, key));
}

#[test]
fn a_prefix_is_packed_two_nibbles_to_a_byte() {
    // 64 bytes of nibbles and its length: a pass's work list of 1 921
    // prefixes holds about 125 KB, not 250 KB.
    assert_eq!(core::mem::size_of::<Prefix>(), 65);
    // An odd length keeps only the high nibble of its last byte, so that a
    // prefix read from a key equals the same one from the wire, orders as
    // its nibbles do, and bounds only its own subtree.
    let mut key = [0u8; 64];
    key[..3].copy_from_slice(&[0x5c, 0x3f, 0xee]);
    let p = Prefix::of_key(&key, 3);
    assert_eq!(p, Prefix::from_wire(&[5, 0xc, 3]).unwrap());
    assert_eq!(p.child(0xf).unwrap(), Prefix::of_key(&key, 4));
    assert!(Prefix::from_wire(&[5, 0xc]).unwrap() < p);
    assert!(p < Prefix::from_wire(&[5, 0xc, 4]).unwrap());
    let (lo, hi) = p.bounds();
    assert_eq!(
        (lo[..2].to_vec(), hi[..2].to_vec()),
        (vec![0x5c, 0x30], vec![0x5c, 0x3f])
    );
    // Membership agrees with the nibbles, one by one, for every depth.
    let mut other = key;
    other[1] = 0x4f;
    for depth in 0..=128 {
        let p = Prefix::of_key(&key, depth);
        let by_nibbles = (0..depth).all(|i| nibble(&other, i) == nibble(&key, i));
        assert_eq!(p.contains(&other), by_nibbles, "depth {depth}");
        assert!(p.contains(&key));
        assert_eq!(
            p.nibbles().collect::<Vec<_>>(),
            (0..depth).map(|i| nibble(&key, i)).collect::<Vec<_>>()
        );
    }
}

fn digest(n: u8) -> SetDigest {
    SetDigest::leaf(&[RecordHash([n; 32])])
}

#[test]
fn the_three_reconcile_conditions() {
    let (a, b) = (digest(1), digest(2));
    // Equal digests: EQUAL, whatever else.
    assert_eq!(reconcile_outcome(0, &a, &a, 1000), ReconcileOutcome::Equal);
    assert_eq!(
        reconcile_outcome(0, &SetDigest::EMPTY, &SetDigest::EMPTY, 0),
        ReconcileOutcome::Equal
    );
    // The requester holds nothing there: RECORDS, however many.
    assert_eq!(
        reconcile_outcome(0, &SetDigest::EMPTY, &a, 1000),
        ReconcileOutcome::Records
    );
    // A full key: RECORDS, however many.
    assert_eq!(
        reconcile_outcome(128, &a, &b, 1000),
        ReconcileOutcome::Records
    );
    // Leaf form (at most 64) or empty: RECORDS; 65: CHILDREN.
    assert_eq!(reconcile_outcome(3, &a, &b, 64), ReconcileOutcome::Records);
    assert_eq!(
        reconcile_outcome(3, &a, &SetDigest::EMPTY, 0),
        ReconcileOutcome::Records
    );
    assert_eq!(reconcile_outcome(3, &a, &b, 65), ReconcileOutcome::Children);
    assert_eq!(
        reconcile_outcome(127, &a, &b, 65),
        ReconcileOutcome::Children
    );
    assert_eq!(
        reconcile_outcome(64, &a, &b, 65),
        ReconcileOutcome::Children,
        "beneath a path tag, by the record-hash nibbles"
    );
}

#[test]
fn page_limits() {
    assert_eq!(page_limit(0), 4096);
    assert_eq!(page_limit(5000), 4096);
    assert_eq!(page_limit(1), 64);
    assert_eq!(page_limit(63), 64);
    assert_eq!(page_limit(64), 64);
    assert_eq!(page_limit(100), 100);
    assert_eq!(page_limit(4096), 4096);
    assert_eq!(page_limit(4097), 4096);
}

/// A record whose body is the common prefix and `body_len` bytes of an
/// unknown field.
fn record(body_len: usize) -> SignedRecord {
    let mut body = crate::messages::IndexRecord {
        suite: 1,
        record_type: 16,
        folder_id: vec![1; 32],
        ..crate::messages::IndexRecord::default()
    }
    .encode_to_vec();
    prost::encoding::bytes::encode(99, &vec![1u8; body_len], &mut body);
    crate::testkit::record_of(&body, &[2; 64])
}

/// A record whose page entry is exactly `target` bytes, when one is.
fn sized(target: usize) -> Option<SignedRecord> {
    (target.saturating_sub(200)..target)
        .map(record)
        .find(|r| encoded_record_len(r) == target)
}

/// A page at its widest: `more`, the widest `request_id`, an `epoch`, the
/// widest `through` and `reset` (no real page sets both `more` and `reset`;
/// the overhead bounds every page).
fn widest(p: &mut Pager) -> Message {
    let mut page = p.page(&F, u32::MAX, true, u64::MAX, MAX_LOCAL_SEQ);
    page.reset = true;
    Message::IndexRecords(page)
}

#[test]
fn pages_hold_the_limit_and_fit_the_frame() {
    // The record-count limit, exactly: 64 go, the 65th waits.
    let mut p = Pager::new(page_limit(1), 16 << 20);
    for _ in 0..64 {
        assert_eq!(p.push(&record(10)), Ok(true));
    }
    assert_eq!(
        p.push(&record(10)),
        Ok(false),
        "a 65th waits for the next page"
    );
    assert_eq!(p.len(), 64);
    let page = p.page(&F, 3, true, 9, 5);
    assert_eq!(page.records.len(), 64);
    assert!(p.is_empty());
    assert_eq!(
        (
            page.request_id,
            page.more,
            page.epoch,
            page.through,
            page.reset
        ),
        (3, true, 9, 5, false)
    );
    assert_eq!(p.push(&record(10)), Ok(true), "an empty page takes it");
    assert_eq!(p.page(&F, 3, false, 9, 6).records.len(), 1);
    // The byte limit, exactly: a page whose frame at its widest is the peer's
    // limit to the byte; one byte more waits.
    let limit = 20_000u32;
    let room = limit as usize - PAGE_FIXED_OVERHEAD;
    let first = record(1000);
    let rest = room - encoded_record_len(&first);
    let exact = sized(rest).unwrap();
    let over = sized(rest + 1).unwrap();
    let mut p = Pager::new(4096, limit);
    assert_eq!(p.push(&first), Ok(true));
    assert_eq!(p.push(&exact), Ok(true));
    assert_eq!(p.push(&record(0)), Ok(false), "full to the byte");
    let frame = widest(&mut p).to_frame().unwrap();
    assert_eq!(frame.length(), limit, "exactly the peer's limit");
    let mut p = Pager::new(4096, limit);
    assert_eq!(p.push(&first), Ok(true));
    assert_eq!(p.push(&over), Ok(false), "one byte over waits");
    // A record that fills an empty page exactly fits; one byte more fits none.
    let mut p = Pager::new(4096, limit);
    assert_eq!(p.push(&sized(room).unwrap()), Ok(true));
    assert_eq!(widest(&mut p).to_frame().unwrap().length(), limit);
    assert_eq!(
        Pager::new(4096, limit).push(&sized(room + 1).unwrap()),
        Err(BuildError::DoesNotFit)
    );
    // A push holds at most MAX_PAGE_RECORDS.
    let mut push = Pager::new(MAX_PAGE_RECORDS + 10, 64 << 20);
    for _ in 0..MAX_PAGE_RECORDS {
        assert_eq!(push.push(&record(1)), Ok(true));
    }
    assert_eq!(push.push(&record(1)), Ok(false));
    assert_ne!(BuildError::DoesNotFit.to_string(), "");
}

#[test]
fn a_reset_is_one_empty_page() {
    let page = reset_page(&F, 4, 77);
    assert_eq!(
        page,
        IndexRecords {
            folder_id: F.0.to_vec(),
            records: vec![],
            more: false,
            request_id: 4,
            epoch: 77,
            through: 0,
            reset: true,
        }
    );
}

proptest! {
    #![proptest_config(crate::testkit::proptest_config(256))]

    /// Every page the pager closes fits the peer's limit at its widest, and
    /// was closed only because the next record would have taken it past that
    /// limit or past the page limit.
    #[test]
    fn pages_fit_the_limit(sizes in proptest::collection::vec(0usize..3000, 1..40), limit in 4000u32..20000) {
        let mut p = Pager::new(4096, limit);
        for n in sizes {
            let r = record(n);
            match p.push(&r) {
                Ok(true) => {}
                Err(BuildError::DoesNotFit) => {
                    prop_assert!(encoded_record_len(&r) + PAGE_FIXED_OVERHEAD > limit as usize);
                }
                Ok(false) => {
                    let Message::IndexRecords(mut with) = widest(&mut p) else {
                        unreachable!()
                    };
                    let frame = Message::IndexRecords(with.clone()).to_frame().unwrap();
                    prop_assert!(frame.fits(limit));
                    with.records.push(r.to_bytes());
                    let bigger = Message::IndexRecords(with).to_frame().unwrap();
                    prop_assert!(!bigger.fits(limit), "closed early");
                    prop_assert_eq!(p.push(&r), Ok(true));
                }
            }
        }
        let frame = widest(&mut p).to_frame().unwrap();
        prop_assert!(frame.fits(limit));
        prop_assert_eq!(
            MessageType::IndexRecords.as_u16(),
            frame.type_number()
        );
    }

    /// A prefix's bounds are its least and greatest key, and a key lies in
    /// the subtree exactly when it begins with the prefix's nibbles.
    #[test]
    fn bounds_are_the_subtree(key in proptest::array::uniform::<_, 64>(any::<u8>()), probe in proptest::array::uniform::<_, 64>(any::<u8>()), len in 0usize..=128) {
        let p = Prefix::of_key(&key, len);
        let (lo, hi) = p.bounds();
        prop_assert!(p.contains(&key) && p.contains(&lo) && p.contains(&hi));
        prop_assert_eq!(p.contains(&probe), lo <= probe && probe <= hi);
        prop_assert_eq!(Prefix::from_wire(&p.to_wire()), Some(p));
    }
}
