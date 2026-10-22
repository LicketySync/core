#![no_main]
//! The frame decoder over a byte stream from a peer, each frame dispatched
//! as it completes: a known type's body goes to its bounded decoder, and a
//! body that parses re-encodes canonically to one that parses to the same
//! value. Two limits are tried: `PRE_HELLO_LIMIT` and the default
//! `max_message_size`.
use libfuzzer_sys::fuzz_target;
use licketysync_protocol::limits::{DEFAULT_MESSAGE_SIZE, PRE_HELLO_LIMIT};
use licketysync_protocol::{FrameDecoder, FrameKind, Message};

fuzz_target!(|data: &[u8]| {
    for limit in [PRE_HELLO_LIMIT, DEFAULT_MESSAGE_SIZE] {
        let mut decoder = FrameDecoder::new(limit);
        // Feed in two pieces, split where the first byte says, so that frames
        // cross piece boundaries.
        let cut = data.first().map_or(0, |b| usize::from(*b) % (data.len() + 1));
        for piece in [&data[..cut], &data[cut..]] {
            let mut input = piece;
            while let Ok(Some(frame)) = decoder.next_frame(&mut input) {
                assert!(frame.length() <= limit);
                if let FrameKind::Known(t) = frame.kind() {
                    if let Ok(m) = Message::parse(t, frame.body()) {
                        let again = Message::parse(t, &m.encode_body());
                        assert_eq!(again.as_ref(), Ok(&m), "canonical re-encoding parses alike");
                    }
                }
            }
        }
        let _ = decoder.finish();
    }
});
