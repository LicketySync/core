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

use super::*;
use crate::frame::MessageType;
use crate::messages::Message;
use crate::parse::Parse;

fn dev(n: u32) -> DeviceId {
    let mut d = [0u8; 32];
    d[28..].copy_from_slice(&n.to_be_bytes());
    DeviceId(d)
}

fn cursor(n: u32, seq: u64) -> WriterCursor {
    WriterCursor {
        writer: dev(n),
        seq,
        digest: (seq > 0).then_some(WriterDigest([u8::try_from(n % 256).unwrap(); 32])),
    }
}

const F: FolderId = FolderId([7; 32]);

#[test]
fn cursors_to_and_from_the_wire() {
    for c in [
        cursor(1, 0),
        cursor(2, 5),
        cursor(3, crate::limits::MAX_SEQ),
    ] {
        let wire = c.to_wire().unwrap();
        assert_eq!(Cursor::parse(&wire.encode_to_vec()).unwrap(), wire);
        assert_eq!(WriterCursor::from_wire(&wire), Some(c));
    }
    let bad = [
        WriterCursor {
            writer: dev(1),
            seq: 1,
            digest: None,
        },
        WriterCursor {
            writer: dev(1),
            seq: 0,
            digest: Some(WriterDigest([0; 32])),
        },
        WriterCursor {
            writer: dev(1),
            seq: crate::limits::MAX_SEQ + 1,
            digest: Some(WriterDigest([0; 32])),
        },
    ];
    for c in bad {
        assert_eq!(c.to_wire(), Err(BuildError::Cursor));
    }
    assert_eq!(WriterCursor::none(dev(4)), cursor(4, 0));
    let wrong = Cursor {
        device_id: dev(1).0.to_vec(),
        seq: 0,
        digest: vec![1; 32],
    };
    assert_eq!(WriterCursor::from_wire(&wrong), None);
}

#[test]
fn scopes() {
    assert!(Scope::ALL.contains(&dev(0)));
    let range = Scope::Range {
        after: Some(dev(5)),
        through: Some(dev(9)),
    };
    assert!(!range.contains(&dev(5)), "after is exclusive");
    assert!(range.contains(&dev(6)));
    assert!(range.contains(&dev(9)), "through is inclusive");
    assert!(!range.contains(&dev(10)));
    let open_top = Scope::Range {
        after: Some(dev(5)),
        through: None,
    };
    assert!(open_top.contains(&dev(u32::MAX)));
    let listed = Scope::Listed([dev(2), dev(4)].into_iter().collect());
    assert!(listed.contains(&dev(4)) && !listed.contains(&dev(3)));
    let req = listed_request(&F, [cursor(2, 0), cursor(4, 1)], 0).unwrap();
    assert_eq!(Scope::of(&req), listed);
    let req = range_request(&F, Some(dev(5)), [cursor(6, 1)], 0).unwrap();
    assert_eq!(
        Scope::of(&req),
        Scope::Range {
            after: Some(dev(5)),
            through: None
        }
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
}

#[test]
fn the_round_split() {
    // No writers: one request with have empty and no range.
    let r = range_request(&F, None, [], 0).unwrap();
    assert!(r.have.is_empty() && r.after.is_empty() && r.through.is_empty());
    let all = |n: u32| (0..n).map(|i| cursor(i, u64::from(i % 3)));
    // 16 384 writers: one request, after and through empty.
    let r = range_request(&F, None, all(16_384), 4096).unwrap();
    assert_eq!(r.have.len(), 16_384);
    assert!(r.through.is_empty());
    assert_eq!(r.max_records, 4096);
    IndexRequest::parse(&IndexRequest { request_id: 1, ..r }.encode_to_vec()).unwrap();
    // 16 385: the first's through is the 16 384th writer, the second's after
    // that, through empty.
    let first = range_request(&F, None, all(16_385), 0).unwrap();
    assert_eq!(first.have.len(), 16_384);
    assert_eq!(first.through, dev(16_383).0.to_vec());
    let second = range_request(&F, Some(dev(16_383)), all(16_385), 0).unwrap();
    assert_eq!(second.have.len(), 1);
    assert_eq!(second.after, dev(16_383).0.to_vec());
    assert!(second.through.is_empty());
    for r in [first, second] {
        let r = IndexRequest { request_id: 9, ..r };
        assert_eq!(IndexRequest::parse(&r.encode_to_vec()).unwrap(), r);
    }
    assert_eq!(
        range_request(&F, None, [cursor(2, 0), cursor(1, 0)], 0),
        Err(BuildError::Unsorted)
    );
    assert_eq!(
        range_request(&F, None, [cursor(2, 0), cursor(2, 0)], 0),
        Err(BuildError::Unsorted)
    );
    let bad = WriterCursor {
        digest: None,
        ..cursor(1, 3)
    };
    assert_eq!(range_request(&F, None, [bad], 0), Err(BuildError::Cursor));
}

#[test]
fn listed_requests() {
    // Exactly MAX_CURSORS_PER_REQUEST writers are accepted, one more is not.
    let full = listed_request(&F, (0..16_384).map(|i| cursor(i, 0)), 0).unwrap();
    assert_eq!(full.have.len(), MAX_CURSORS_PER_REQUEST);
    IndexRequest::parse(
        &IndexRequest {
            request_id: 1,
            ..full
        }
        .encode_to_vec(),
    )
    .unwrap();
    let r = listed_request(&F, [cursor(1, 0), cursor(3, 2)], 0).unwrap();
    assert!(r.listed && r.after.is_empty() && r.through.is_empty());
    IndexRequest::parse(&IndexRequest { request_id: 1, ..r }.encode_to_vec()).unwrap();
    assert_eq!(listed_request(&F, [], 0), Err(BuildError::ListSize(0)));
    assert_eq!(
        listed_request(&F, [cursor(3, 0), cursor(1, 0)], 0),
        Err(BuildError::Unsorted)
    );
    assert_eq!(
        listed_request(&F, (0..16_385).map(|i| cursor(i, 0)), 0),
        Err(BuildError::ListSize(16_385))
    );
}

#[test]
fn the_four_serving_cases() {
    let d = |b| Some(WriterDigest([b; 32]));
    // (a) the requester holds none: everything.
    assert_eq!(serve((0, None), 5, None), Serve::All { mark: false });
    // (b) equal digests at s: the records above s.
    assert_eq!(serve((3, d(1)), 5, d(1)), Serve::After(3));
    assert_eq!(serve((5, d(1)), 5, d(1)), Serve::After(5), "equal cursors");
    // (c) different digests: a full resend and a mark.
    assert_eq!(serve((3, d(1)), 5, d(2)), Serve::All { mark: true });
    assert_eq!(serve((3, d(1)), 5, None), Serve::All { mark: true });
    // (d) the requester is ahead: nothing; this side's own request compares.
    assert_eq!(serve((6, d(1)), 5, None), Serve::Nothing);
    // A writer this side holds nothing of.
    assert_eq!(serve((0, None), 0, None), Serve::Nothing);
    assert_eq!(serve((2, d(1)), 0, None), Serve::Nothing);
}

#[test]
fn serve_requests_type_a_parsed_request() {
    let r = IndexRequest {
        request_id: 4,
        max_records: 10,
        ..range_request(&F, None, [cursor(1, 0), cursor(2, 3)], 10).unwrap()
    };
    let s = ServeRequest::of(&r);
    assert_eq!(s.request_id, 4);
    assert_eq!(s.page_limit, 64);
    assert_eq!(s.scope, Scope::ALL);
    assert_eq!(s.requester(&dev(2)), (3, cursor(2, 3).digest));
    assert_eq!(s.requester(&dev(9)), (0, None), "absent: cursor 0");
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
    let page = p.page(&F, 3, true);
    assert_eq!(page.records.len(), 64);
    assert_eq!(p.push(&record(10)), Ok(true), "an empty page takes it");
    assert_eq!(p.page(&F, 3, false).records.len(), 1);
    // The byte limit, exactly: a page whose frame, with `more` and the widest
    // request ID, is the peer's limit to the byte; one byte more waits.
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
    let frame = Message::IndexRecords(p.page(&F, u32::MAX, true))
        .to_frame()
        .unwrap();
    assert_eq!(frame.length(), limit, "exactly the peer's limit");
    let mut p = Pager::new(4096, limit);
    assert_eq!(p.push(&first), Ok(true));
    assert_eq!(p.push(&over), Ok(false), "one byte over waits");
    // A record that fills an empty page exactly fits; one byte more fits none.
    let mut p = Pager::new(4096, limit);
    assert_eq!(p.push(&sized(room).unwrap()), Ok(true));
    let frame = Message::IndexRecords(p.page(&F, u32::MAX, true))
        .to_frame()
        .unwrap();
    assert_eq!(frame.length(), limit);
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
    for e in [
        BuildError::Unsorted,
        BuildError::ListSize(0),
        BuildError::DoesNotFit,
        BuildError::Cursor,
    ] {
        assert_ne!(e.to_string(), "");
    }
}

#[test]
fn slices_of_cursors_are_cursors() {
    let held: Vec<WriterCursor> = [1, 3, 5].into_iter().map(|n| cursor(n, 2)).collect();
    let after = |a: Option<u32>| -> Vec<u32> {
        held[..]
            .cursors_after(a.map(dev))
            .map(|c| u32::from_be_bytes(c.writer.0[28..].try_into().unwrap()))
            .collect()
    };
    assert_eq!(after(None), vec![1, 3, 5]);
    assert_eq!(after(Some(1)), vec![3, 5], "strictly above");
    assert_eq!(after(Some(2)), vec![3, 5]);
    assert_eq!(after(Some(5)), Vec::<u32>::new());
    assert_eq!(held[..].cursor_of(&dev(3)), cursor(3, 2));
    assert_eq!(held[..].cursor_of(&dev(4)), WriterCursor::none(dev(4)));
}

proptest! {
    /// Every page the pager closes fits the peer's limit, with `more` set and
    /// the widest request ID, and was closed only because the next record
    /// would have taken it past that limit or past the page limit.
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
                    let mut with = p.page(&F, u32::MAX, true);
                    let frame = Message::IndexRecords(with.clone()).to_frame().unwrap();
                    prop_assert!(frame.fits(limit));
                    with.records.push(r.to_bytes());
                    let bigger = Message::IndexRecords(with).to_frame().unwrap();
                    prop_assert!(!bigger.fits(limit), "closed early");
                    prop_assert_eq!(p.push(&r), Ok(true));
                }
                Err(e) => prop_assert!(false, "{e}"),
            }
        }
        let frame = Message::IndexRecords(p.page(&F, u32::MAX, true)).to_frame().unwrap();
        prop_assert!(frame.fits(limit));
        prop_assert_eq!(
            MessageType::IndexRecords.as_u16(),
            frame.type_number()
        );
    }
}
