// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Items 10 and 11: Close and Status.

use prost::Message as _;
use serde_json::{json, Value};

use super::{check, ending, feed, h, scenario, seed};
use crate::connection::{Event, Tick};
use crate::messages::{Close, CloseReason, FolderStatus, Message, Status};
use crate::parse::{close_without_detail, Parse};
use crate::testkit::{s, Pair};

#[test]
fn vector_close_and_status() {
    let mut closes = Vec::new();
    for reason in CloseReason::ALL {
        for detail in ["", "goodbye"] {
            let c = Close {
                reason: reason.as_u32(),
                detail: detail.into(),
            };
            let body = c.encode_to_vec();
            assert_eq!(Close::parse(&body).unwrap(), c);
            let name = format!(
                "{}{}",
                reason.name().to_lowercase(),
                if detail.is_empty() { "" } else { "-detail" }
            );
            seed(
                "message_parse",
                &format!("close-{name}"),
                &[&[1u8], &body[..]].concat(),
            );
            closes.push(
                json!({ "reason": reason.name(), "detail": detail, "body": super::input(&body) }),
            );
        }
    }
    let control = Close {
        reason: 1,
        detail: "a\u{7}b".into(),
    }
    .encode_to_vec();
    assert!(Close::parse(&control).is_err());
    assert_eq!(close_without_detail(&control).reason, 1);
    let got = feed(
        "established",
        &crate::frame::Frame::new(0x8002, control.clone())
            .unwrap()
            .encode(),
    );
    assert_eq!(
        got, "closed by the peer: SHUTDOWN",
        "the reason kept, the detail dropped"
    );

    // Status: the first after the open carries the name and chunks_stored 0;
    // a chunk stored later counts; fifty within a second are one Status.
    let mut p = Pair::open();
    let f = p.a.folder_id();
    p.advance(s(2));
    for _ in 0..50 {
        let out = p.a.conn.chunk_stored(Tick::at(p.now), f);
        p.a.apply(p.now, out);
    }
    p.advance(s(2));
    let sent: Vec<Status> =
        p.a.sent
            .iter()
            .filter(|(_, fr)| fr[4..6] == [0x00, 0x01])
            .map(|(_, fr)| Status::parse(&fr[6..]).unwrap())
            .collect();
    assert_eq!(sent[0].device_name, "device-a0");
    assert_eq!(sent[0].folders[0].chunks_stored, 0);
    assert_eq!(sent.last().unwrap().folders[0].chunks_stored, 50);
    assert_eq!(sent.len(), 2, "one Status for the fifty chunks");
    for (i, st) in sent.iter().enumerate() {
        seed(
            "message_parse",
            &format!("status-{i}"),
            &[&[9u8], &st.encode_to_vec()[..]].concat(),
        );
    }
    let mut bad = Pair::open();
    bad.b.auto = false;
    let mut body = Vec::new();
    prost::encoding::string::encode(2, &"name\u{1}".to_string(), &mut body);
    bad.b.receive(
        bad.now,
        &crate::frame::Frame::new(0x0001, body.clone())
            .unwrap()
            .encode(),
    );
    assert_eq!(ending(&bad.b)["closed"], "PROTOCOL_ERROR");
    let named = Status {
        folders: vec![FolderStatus {
            folder_id: f.0.to_vec(),
            ..FolderStatus::default()
        }],
        device_name: "phone".into(),
    };
    let mut q = Pair::open();
    q.b.auto = false;
    q.b.receive(
        q.now,
        &Message::Status(named.clone()).to_frame().unwrap().encode(),
    );
    assert!(q
        .b
        .saw(|e| matches!(e, Event::PeerNamed { device_name } if device_name == "phone")));

    let value: Value = json!({
        "description": "protocol.md 8 items 10 and 11: Close for every reason with and without detail, one whose detail holds a control character (not shown; its reason kept), and Status: the first after the open with the device name and chunks_stored 0, fifty chunks stored within a second reported by one Status, and a name with a control character (PROTOCOL_ERROR).",
        "closes": closes,
        "close_with_control_detail": h(&control),
        "status_scenario": scenario(&p, &[], json!("A stores fifty chunks within one second after the open")),
        "status_bad_name": h(&body),
    });
    check("status", &value);
}
