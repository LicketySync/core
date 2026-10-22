#![no_main]
//! A peer's Hello body: the bounded decoder, then every check of
//! `protocol.md` 3.2 against a side that implements suite 1, without and
//! with a transport-authenticated identity.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::Suite;
use licketysync_protocol::hello::check_peer_hello;
use licketysync_protocol::messages::Hello;
use licketysync_protocol::{Frame, MessageType, Parse};

fuzz_target!(|data: &[u8]| {
    let Ok(hello) = Hello::parse(data) else {
        return;
    };
    let Ok(frame) = Frame::new(MessageType::Hello.as_u16(), data.to_vec()) else {
        return;
    };
    for identity in [None, Some([7u8; 32])] {
        if let Ok(peer) = check_peer_hello(hello.clone(), &frame, &[Suite::ONE], identity.as_ref()) {
            assert_eq!(peer.device_id, peer.device.device_id());
            assert!(peer.max_message_size <= licketysync_protocol::limits::MAX_MESSAGE_SIZE);
        }
    }
});
