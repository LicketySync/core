#![no_main]
//! Every bounded decoder of the protocol crate on a body from a peer. The
//! first byte selects the decoder: 0 to 12 the message types of
//! `protocol.md` 4.1 in the order of `MessageType::ALL`, then the embedded
//! and inner messages (13 ProofPayload, 14 ChunkRef, 15 FolderStatus, 16
//! SealedMeta, 17 IndexRecord, 18 CleanupRecord, 19 CleanupGroup, 20
//! CleanupMeta, 21 VectorEntry). A body that parses re-encodes canonically
//! to one that parses to the same value.
use libfuzzer_sys::fuzz_target;
use licketysync_protocol::messages::{
    ChunkRef, CleanupGroup, CleanupMeta, CleanupRecord, FolderStatus, IndexRecord, ProofPayload,
    SealedMeta, VectorEntry,
};
use licketysync_protocol::{Message, MessageType, Parse};

fn round_trip<M: Parse + prost::Message + PartialEq + core::fmt::Debug>(body: &[u8]) {
    if let Ok(m) = M::parse(body) {
        let again = M::parse(&m.encode_to_vec());
        assert_eq!(again.as_ref(), Ok(&m), "canonical re-encoding parses alike");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 22 {
        n @ 0..=12 => {
            let t = MessageType::ALL[usize::from(n)];
            if let Ok(m) = Message::parse(t, body) {
                let again = Message::parse(t, &m.encode_body());
                assert_eq!(again.as_ref(), Ok(&m), "canonical re-encoding parses alike");
            }
        }
        13 => round_trip::<ProofPayload>(body),
        14 => round_trip::<ChunkRef>(body),
        15 => round_trip::<FolderStatus>(body),
        16 => round_trip::<SealedMeta>(body),
        17 => round_trip::<IndexRecord>(body),
        18 => round_trip::<CleanupRecord>(body),
        19 => round_trip::<CleanupGroup>(body),
        20 => round_trip::<CleanupMeta>(body),
        _ => round_trip::<VectorEntry>(body),
    }
});
