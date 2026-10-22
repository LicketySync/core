// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Item 1, frames (decoder vectors).

use prost::encoding::{encode_key, encode_varint, WireType};
use prost::Message as _;
use serde_json::{json, Value};

use super::{check, feed, seed};
use crate::frame::{Frame, MessageType};
use crate::limits::{DEFAULT_MESSAGE_SIZE, PRE_HELLO_LIMIT};
use crate::messages::{Close, Hello, IndexRequest, Message};

fn raw(t: u16, body: &[u8]) -> Vec<u8> {
    Frame::new(t, body.to_vec()).unwrap().encode()
}

/// The outcome of decoding `body` as `t`: accepted with the decoded value,
/// or malformed with why.
fn body_outcome(t: MessageType, body: &[u8]) -> String {
    match Message::parse(t, body) {
        Ok(m) => format!("accepted {}", hex::encode(m.encode_body())),
        Err(e) => format!("malformed: {e}"),
    }
}

#[test]
fn vector_frames() {
    let mut stream = Vec::new();
    // The `handshake` fuzz target's seeds: mode 0 is a fresh connection fed
    // the peer's stream (the peer's Hello first where the state needs it),
    // mode 1 one with the folder open.
    let hello_b = crate::testkit::Pair::new(0xa0, 0xb0, &[super::key()], &[super::key()])
        .b
        .outbox;
    let mut add = |name: &str, state: &str, bytes: Vec<u8>, want: &str| {
        let got = feed(state, &bytes);
        assert_eq!(got, want, "{name}");
        seed("frame_decode", name, &bytes);
        let fuzz = match state {
            "first" => [&[0u8][..], &bytes].concat(),
            "before-device-proof" => [&[0u8][..], &hello_b, &bytes].concat(),
            _ => [&[1u8][..], &bytes].concat(),
        };
        seed("handshake", name, &fuzz);
        stream.push(
            json!({ "name": name, "state": state, "input": super::input(&bytes), "outcome": got }),
        );
    };
    let close = raw(
        0x8002,
        &Close {
            reason: 1,
            detail: String::new(),
        }
        .encode_to_vec(),
    );
    add(
        "valid-close",
        "first",
        close,
        "closed by the peer: SHUTDOWN",
    );
    add(
        "length-0",
        "first",
        0u32.to_be_bytes().to_vec(),
        "close PROTOCOL_ERROR (Malformed)",
    );
    add(
        "length-1",
        "first",
        1u32.to_be_bytes().to_vec(),
        "close PROTOCOL_ERROR (Malformed)",
    );
    add(
        "over-pre-hello-limit",
        "first",
        (PRE_HELLO_LIMIT + 1).to_be_bytes().to_vec(),
        "close MESSAGE_TOO_LARGE (FrameOverLimit)",
    );
    add(
        "over-pre-hello-limit-between-hello-and-device-proof",
        "before-device-proof",
        (PRE_HELLO_LIMIT + 1).to_be_bytes().to_vec(),
        "close MESSAGE_TOO_LARGE (FrameOverLimit)",
    );
    add(
        "over-max-message-size",
        "established",
        (DEFAULT_MESSAGE_SIZE + 1).to_be_bytes().to_vec(),
        "close MESSAGE_TOO_LARGE (FrameOverLimit)",
    );
    add(
        "at-max-message-size-not-yet-whole",
        "established",
        DEFAULT_MESSAGE_SIZE.to_be_bytes().to_vec(),
        "accepted",
    );
    add(
        "unknown-critical",
        "established",
        raw(0x800c, b""),
        "close UNSUPPORTED_CRITICAL_TYPE (UnknownCriticalType)",
    );
    add(
        "reserved-key-records-type",
        "established",
        raw(0x8006, b""),
        "close UNSUPPORTED_CRITICAL_TYPE (UnknownCriticalType)",
    );
    add(
        "unknown-non-critical",
        "established",
        raw(0x0003, b""),
        "unsupported x1",
    );
    add(
        "two-frames-of-one-unknown-non-critical-type",
        "established",
        [raw(0x0003, b"a"), raw(0x0003, b"b")].concat(),
        "unsupported x1",
    );
    add(
        "first-frame-not-hello",
        "first",
        raw(0x8003, &[0x0a, 0]),
        "close PROTOCOL_ERROR (Malformed)",
    );
    add(
        "unknown-non-critical-before-device-proof",
        "before-device-proof",
        raw(0x0003, b""),
        "close PROTOCOL_ERROR (Malformed)",
    );

    // Body-level rules, on the bodies alone.
    let mut bodies = Vec::new();
    let mut body = |name: &str, t: MessageType, b: Vec<u8>, accepted: bool| {
        let got = body_outcome(t, &b);
        assert_eq!(got.starts_with("accepted"), accepted, "{name}: {got}");
        let mut framed = vec![0u8; 0];
        framed.extend_from_slice(&t.as_u16().to_be_bytes());
        framed.extend_from_slice(&b);
        seed("message_parse", name, &[&[selector(t)], &b[..]].concat());
        bodies.push(
            json!({ "name": name, "type": t.name(), "body": super::input(&b), "outcome": got }),
        );
    };
    let mut fieldnum = Vec::new();
    encode_varint(u64::from(1u32 << 29) << 3, &mut fieldnum);
    fieldnum.push(0);
    body("field-number-2^29", MessageType::Close, fieldnum, false);
    let mut last = Vec::new();
    encode_varint(u64::from((1u32 << 29) - 1) << 3, &mut last);
    last.push(0);
    body(
        "field-number-2^29-1-skipped",
        MessageType::Close,
        last,
        true,
    );
    body(
        "group-wire-type",
        MessageType::Close,
        vec![0x0b, 0x0c],
        false,
    );
    body(
        "fixed-size-field-absent",
        MessageType::DeviceProof,
        vec![],
        false,
    );
    let request = IndexRequest {
        folder_id: vec![1; 32],
        request_id: 1,
        ..IndexRequest::default()
    };
    body(
        "empty-able-fields-absent",
        MessageType::IndexRequest,
        request.encode_to_vec(),
        true,
    );
    let mut twice = Vec::new();
    for v in [1, 2] {
        encode_key(1, WireType::Varint, &mut twice);
        encode_varint(v, &mut twice);
    }
    body("singular-field-twice", MessageType::Close, twice, false);
    let hello = Hello {
        suites: vec![],
        ..Hello::default()
    }
    .encode_to_vec();
    let mut packed = hello.clone();
    encode_key(3, WireType::LengthDelimited, &mut packed);
    encode_varint(3, &mut packed);
    packed.extend_from_slice(&[1, 2, 3]);
    let mut unpacked = hello.clone();
    for s in [1, 2, 3] {
        encode_key(3, WireType::Varint, &mut unpacked);
        encode_varint(s, &mut unpacked);
    }
    let mut mixed = hello;
    encode_key(3, WireType::Varint, &mut mixed);
    encode_varint(1, &mut mixed);
    encode_key(3, WireType::LengthDelimited, &mut mixed);
    encode_varint(2, &mut mixed);
    mixed.extend_from_slice(&[2, 3]);
    let same: Vec<String> = [&packed, &unpacked, &mixed]
        .iter()
        .map(|b| body_outcome(MessageType::Hello, b))
        .collect();
    assert!(
        same.windows(2).all(|w| w[0] == w[1]),
        "packed, unpacked and mixed mean the same"
    );
    body("repeated-scalar-packed", MessageType::Hello, packed, true);
    body(
        "repeated-scalar-unpacked",
        MessageType::Hello,
        unpacked,
        true,
    );
    body("repeated-scalar-mixed", MessageType::Hello, mixed, true);
    let mut bool2 = request.encode_to_vec();
    encode_key(7, WireType::Varint, &mut bool2);
    encode_varint(2, &mut bool2);
    body("bool-2", MessageType::IndexRequest, bool2, false);
    let mut wide = Vec::new();
    encode_key(1, WireType::Varint, &mut wide);
    encode_varint(1 << 32, &mut wide);
    body("uint32-2^32", MessageType::Close, wide, false);
    let mut reserved = Vec::new();
    encode_key(2, WireType::LengthDelimited, &mut reserved);
    encode_varint(4, &mut reserved);
    reserved.extend_from_slice(b"name");
    body("reserved-field-skipped", MessageType::Hello, reserved, true);

    let value: Value = json!({
        "description": "protocol.md 8 item 1: frames fed to a connection in the named state (first frame; after the peer's Hello, before its DeviceProof; established with the folder open), and bodies fed to their type's decoder. The outcome is the close and its section 5 row, Unsupported, or accepted.",
        "stream": stream,
        "bodies": bodies,
    });
    check("frames", &value);
}

/// The `message_parse` fuzz target's selector byte for a type.
pub(crate) fn selector(t: MessageType) -> u8 {
    u8::try_from(MessageType::ALL.iter().position(|x| *x == t).unwrap()).unwrap()
}
