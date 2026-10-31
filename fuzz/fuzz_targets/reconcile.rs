#![no_main]
//! A `ReconcileRequest` or `ReconcileReply` body from a peer (`protocol.md`
//! 4.5), the first byte choosing which (even: request, odd: reply). What
//! parses keeps the rules of 4.5: a request's prefix is at most 128 nibbles of
//! 0 to 15 (a record's 64-byte key) and makes a `Prefix` that writes back to
//! the same bytes, whose bounds hold the keys it contains and whose children
//! extend it by one nibble; a reply's outcome is one of the three with 16
//! children on `CHILDREN` and none otherwise. The responder's three
//! conditions (`reconcile_outcome`) never answer `CHILDREN` for a zero
//! digest or a full key.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::SetDigest;
use licketysync_protocol::exchange::{reconcile_outcome, Prefix};
use licketysync_protocol::limits::{MAX_LOCAL_SEQ, MAX_PREFIX_NIBBLES};
use licketysync_protocol::messages::{ReconcileOutcome, ReconcileReply, ReconcileRequest};
use licketysync_protocol::Parse;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        let Ok(request) = ReconcileRequest::parse(body) else {
            return;
        };
        let prefix = Prefix::from_wire(&request.prefix).expect("a parsed prefix");
        assert_eq!(prefix.to_wire(), request.prefix);
        assert!(prefix.depth() <= MAX_PREFIX_NIBBLES);
        let (lo, hi) = prefix.bounds();
        assert!(prefix.contains(&lo) && prefix.contains(&hi));
        match prefix.child(selector / 2 % 16) {
            Some(child) => {
                assert!(!prefix.is_full() && child.depth() == prefix.depth() + 1);
                assert!(child.nibbles().take(prefix.depth()).eq(prefix.nibbles()));
            }
            None => assert!(prefix.is_full()),
        }
        let digest = SetDigest::from_slice(&request.digest).expect("32 bytes");
        let mut own = [0u8; 32];
        own[..body.len().min(32)].copy_from_slice(&body[..body.len().min(32)]);
        for records in [0, 1, 64, 65, usize::from(selector) * 1000] {
            let outcome = reconcile_outcome(prefix.depth(), &digest, &SetDigest(own), records);
            if outcome == ReconcileOutcome::Children {
                assert!(!digest.is_empty() && !prefix.is_full() && records > 64);
            }
        }
    } else {
        let Ok(reply) = ReconcileReply::parse(body) else {
            return;
        };
        let outcome = ReconcileOutcome::from_u32(reply.outcome).expect("1 to 3");
        let children = if outcome == ReconcileOutcome::Children { 16 } else { 0 };
        assert_eq!(reply.children.len(), children);
        assert!(reply.children.iter().all(|c| c.len() == 32));
        assert!(reply.epoch != 0 && reply.through <= MAX_LOCAL_SEQ);
    }
});
