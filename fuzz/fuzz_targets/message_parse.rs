#![no_main]
//! Every bounded decoder of the protocol crate on a body from a peer. The
//! first byte selects the decoder: 0 to 10 the message types of
//! `protocol.md` 4.1 in the order of `MessageType::ALL`, then the embedded
//! and inner messages (11 ProofPayload, 12 Cursor, 13 ChunkRef, 14
//! FolderStatus, 15 SealedMeta, 16 IndexRecord). A body that parses
//! re-encodes canonically to one that parses to the same value.
use libfuzzer_sys::fuzz_target;
use licketysync_protocol::messages::{ChunkRef, Cursor, FolderStatus, IndexRecord, ProofPayload, SealedMeta};
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
    match selector % 17 {
        n @ 0..=10 => {
            let t = MessageType::ALL[usize::from(n)];
            if let Ok(m) = Message::parse(t, body) {
                let again = Message::parse(t, &m.encode_body());
                assert_eq!(again.as_ref(), Ok(&m), "canonical re-encoding parses alike");
            }
        }
        11 => round_trip::<ProofPayload>(body),
        12 => round_trip::<Cursor>(body),
        13 => round_trip::<ChunkRef>(body),
        14 => round_trip::<FolderStatus>(body),
        15 => round_trip::<SealedMeta>(body),
        _ => round_trip::<IndexRecord>(body),
    }
});
