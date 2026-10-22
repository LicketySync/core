// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::panic,
    clippy::unchecked_time_subtraction,
    clippy::doc_markdown,
    clippy::type_complexity,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

use licketysync_keys::folder::FolderKey;
use licketysync_keys::{Role, Tier};
use prost::Message as _;

use crate::connection::{
    Config, ConfigError, Connection, Event, Keys, ProveError, SendError, Side, State, Tick,
};
use crate::frame::Frame;
use crate::limits::{MAX_PROOFS_PER_CONNECTION, MAX_REQUESTS_IN_FLIGHT, PRE_HELLO_LIMIT};
use crate::messages::{
    Close, CloseReason, DeviceProof, FolderProof, Hello, Message, ProofResult, Status, Unsupported,
};
use crate::proof::FolderCredential;
use crate::rules::Cause;
use crate::testkit::{device, folder, s, Pair, Rng};

fn frame(m: &Message) -> Vec<u8> {
    m.to_frame().unwrap().encode()
}

fn raw(type_number: u16, body: &[u8]) -> Vec<u8> {
    Frame::new(type_number, body.to_vec()).unwrap().encode()
}

fn closed(side: &crate::testkit::Side) -> Option<(CloseReason, Option<Cause>)> {
    side.events.iter().find_map(|e| match e {
        Event::Closed {
            reason,
            by: Side::Local,
            cause,
            ..
        } => Some((*reason, *cause)),
        _ => None,
    })
}

fn write() -> FolderKey {
    FolderKey::from(folder(0x10))
}

/// A pair where A has received B's Hello (and sent its DeviceProof) and
/// nothing else has moved; B is scripted by hand.
fn half_open() -> Pair {
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    p.b.auto = false;
    let hello_b = core::mem::take(&mut p.b.outbox);
    p.a.receive(p.now, &hello_b);
    assert_eq!(p.a.conn.state(), State::AwaitingDeviceProof);
    p
}

#[test]
fn two_write_holders_open_the_folder() {
    let p = Pair::open();
    let (ra, rb) = (p.a.conn.role().unwrap(), p.b.conn.role().unwrap());
    assert_eq!(ra.peer(), rb);
    assert_eq!(p.a.conn.transcript_hash(), p.b.conn.transcript_hash());
    for (me, other) in [(&p.a, &p.b), (&p.b, &p.a)] {
        assert!(me.saw(|e| matches!(e, Event::Authenticated { device_id, .. } if *device_id == other.key.device_id())));
        assert!(me.saw(|e| matches!(
            e,
            Event::FolderOpened {
                peer_tier: Tier::Write,
                ..
            }
        )));
        assert_eq!(me.conn.state(), State::Established);
        assert_eq!(
            me.conn.receive_limit(),
            me.conn.local_hello().max_message_size
        );
        assert_eq!(me.conn.open_folders().count(), 1);
        assert!(me.saw(|e| matches!(e, Event::StatusDue)));
        assert!(
            me.saw(|e| matches!(e, Event::RoundCompleted { .. })),
            "the round on open"
        );
    }
    assert_eq!(p.a.conn.peer().unwrap().device_id, p.b.key.device_id());
}

#[test]
fn every_tier_proves_to_every_tier_and_reports_its_own() {
    for (ta, tb) in [
        (Tier::Write, Tier::Read),
        (Tier::Read, Tier::Sealed),
        (Tier::Sealed, Tier::Sealed),
        (Tier::Sealed, Tier::Write),
    ] {
        let key = |t: Tier| FolderKey::from(folder(0x10)).lowered(t).unwrap();
        let mut p = Pair::new(0xa0, 0xb0, &[key(ta)], &[key(tb)]);
        p.settle();
        p.b.prove_all(p.now);
        p.settle();
        assert!(p
            .a
            .saw(|e| matches!(e, Event::FolderOpened { peer_tier, .. } if *peer_tier == tb)));
        assert!(p
            .b
            .saw(|e| matches!(e, Event::FolderOpened { peer_tier, .. } if *peer_tier == ta)));
    }
}

#[test]
fn a_folder_the_peer_lacks_is_rejected_and_proof_timeout_closes() {
    // TM-32, TM-10: the uniform REJECTED; then PROOF_TIMEOUT.
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[FolderKey::from(folder(0x20))]);
    p.settle();
    p.a.prove_all(p.now);
    p.b.prove_all(p.now);
    p.settle();
    assert!(p.a.saw(|e| matches!(e, Event::ProofRejected { .. })));
    assert!(p.b.saw(|e| matches!(e, Event::ProofRejected { .. })));
    assert!(!p.a.saw(|e| matches!(e, Event::FolderOpened { .. })));
    p.advance(s(29));
    assert_eq!(p.a.conn.state(), State::Established);
    p.advance(s(1));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::NoCommonFolder, Some(Cause::ProofTimeout)))
    );
    // The Close goes out and the transport closes after the flush.
    p.advance(s(1));
    assert!(p.a.transport_closed);
}

#[test]
fn hello_timeout_closes() {
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    p.b.outbox.clear();
    p.b.auto = false;
    p.a.outbox.clear();
    p.advance(s(9));
    assert_eq!(p.a.conn.state(), State::AwaitingHello);
    p.advance(s(1));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::Timeout, Some(Cause::HelloTimeout)))
    );
}

#[test]
fn the_first_frame_must_be_hello_or_close() {
    for first in [
        frame(&Message::DeviceProof(DeviceProof {
            signature: vec![0; 64],
        })),
        raw(0x0003, b""),
        raw(0x800c, b""),
        frame(&Message::Status(Status::default())),
    ] {
        let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
        p.a.receive(p.now, &first);
        assert_eq!(
            closed(&p.a),
            Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
        );
    }
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    p.a.receive(
        p.now,
        &frame(&Message::Close(Close {
            reason: 1,
            detail: "bye".into(),
        })),
    );
    assert!(p.a.saw(|e| matches!(e, Event::Closed { reason: CloseReason::Shutdown, by: Side::Peer, detail, .. } if detail == "bye")));
    assert!(p.a.transport_closed, "a received Close closes at once");
}

#[test]
fn before_the_device_proof_only_it_or_close_is_accepted() {
    // An unknown non-critical type: PROTOCOL_ERROR, not Unsupported (3.2).
    let mut p = half_open();
    p.a.receive(p.now, &raw(0x0003, b""));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // A second Hello.
    let mut p = half_open();
    let hello = frame(&Message::Hello(Box::new(p.a.conn.local_hello().clone())));
    p.a.receive(p.now, &hello);
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
    // A FolderProof before the DeviceProof.
    let mut p = half_open();
    p.a.receive(
        p.now,
        &frame(&Message::FolderProof(FolderProof {
            hint: vec![1; 32],
            sealed: vec![0; 18],
            nonce: vec![0; 24],
        })),
    );
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
    // A frame one byte over PRE_HELLO_LIMIT: refused before anything is read.
    let mut p = half_open();
    p.a.receive(p.now, &(PRE_HELLO_LIMIT + 1).to_be_bytes());
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::MessageTooLarge, Some(Cause::FrameOverLimit)))
    );
    // A DeviceProof of 63 bytes: malformed.
    let mut p = half_open();
    let mut body = Vec::new();
    prost::encoding::bytes::encode(1, &vec![0u8; 63], &mut body);
    p.a.receive(p.now, &raw(0x8003, &body));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // A DeviceProof that does not verify: PROOF_REJECTED.
    let mut p = half_open();
    p.a.receive(
        p.now,
        &frame(&Message::DeviceProof(DeviceProof {
            signature: vec![7; 64],
        })),
    );
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProofRejected, Some(Cause::DeviceProofRejected)))
    );
    // HELLO_TIMEOUT after the peer's Hello with no DeviceProof.
    let mut p = half_open();
    p.advance(s(10));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::Timeout, Some(Cause::HelloTimeout)))
    );
}

#[test]
fn a_second_device_proof_closes() {
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    p.settle();
    let proof =
        p.b.sent
            .iter()
            .find(|(_, f)| f[4..6] == [0x80, 0x03])
            .unwrap()
            .1
            .clone();
    p.a.receive(p.now, &proof);
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
}

#[test]
fn hello_check_failures_close_with_their_reasons() {
    let base = |p: &Pair| p.b.conn.local_hello().clone();
    let cases: Vec<(Box<dyn Fn(&mut Hello)>, CloseReason)> = vec![
        (Box::new(|h| h.suites = vec![2]), CloseReason::NoCommonSuite),
        (
            Box::new(|h| h.max_message_size = 1 << 20),
            CloseReason::LimitTooSmall,
        ),
        (
            Box::new(|h| h.compressions = vec!["zstd".into()]),
            CloseReason::ProtocolError,
        ),
        (
            Box::new(|h| h.device_public_key.truncate(33)),
            CloseReason::ProtocolError,
        ),
        (
            Box::new(|h| h.libp2p_identity = vec![1; 31]),
            CloseReason::ProtocolError,
        ),
    ];
    for (change, reason) in cases {
        let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
        let mut h = base(&p);
        change(&mut h);
        p.a.receive(p.now, &frame(&Message::Hello(Box::new(h))));
        assert_eq!(closed(&p.a).map(|c| c.0), Some(reason));
    }
    // Equal device keys: a device connected to itself.
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    let own = p.a.conn.local_hello().clone();
    p.a.receive(
        p.now,
        &frame(&Message::Hello(Box::new(Hello {
            nonce: vec![3; 32],
            ..own
        }))),
    );
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
    // From phase 1, a transport identity that differs from the Hello's.
    let mut p = Pair::with(
        0xa0,
        0xb0,
        &[write()],
        &[write()],
        |c| c.transport_identity = Some([9; 32]),
        |_| {},
    );
    p.settle();
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
}

/// A FolderProof from B for the folder, under the established transcript.
fn proof_from_b(p: &Pair, role: Role) -> FolderProof {
    let th = *p.a.conn.transcript_hash().unwrap();
    let cred = FolderCredential::new(&write());
    let mut rng = Rng(5);
    cred.prove(&th, role, &mut |b| rng.fill(b)).unwrap()
}

/// A pair where both device proofs verified and no folder proof moved; B
/// is scripted by hand.
fn established() -> Pair {
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    p.b.auto = false;
    p.settle();
    assert_eq!(p.a.conn.state(), State::Established);
    p.b.outbox.clear();
    p
}

fn results(side: &crate::testkit::Side) -> Vec<ProofResult> {
    side.sent
        .iter()
        .filter(|(_, f)| f[4..6] == [0x80, 0x05])
        .map(|(_, f)| crate::parse::Parse::parse(&f[6..]).unwrap())
        .collect()
}

#[test]
fn folder_proof_verification_steps() {
    // Accepted, and A answers with its own proof (3.5 step 6).
    let mut p = established();
    let role_b = p.b.conn.role().unwrap();
    let proof = proof_from_b(&p, role_b);
    p.a.receive(p.now, &frame(&Message::FolderProof(proof.clone())));
    assert_eq!(results(&p.a)[0].status, 1);
    assert!(
        p.a.sent.iter().any(|(_, f)| f[4..6] == [0x80, 0x04]),
        "A sends its proof"
    );
    // The same hint again: PROTOCOL_ERROR.
    p.a.receive(p.now, &frame(&Message::FolderProof(proof)));
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );

    // Reflected: A's own role's hint matches no folder for B's role.
    let mut p = established();
    let reflected = proof_from_b(&p, p.a.conn.role().unwrap());
    p.a.receive(p.now, &frame(&Message::FolderProof(reflected)));
    assert_eq!(results(&p.a)[0].status, 2);
    // Replayed from another connection: another transcript.
    let other = established();
    let replayed = proof_from_b(&other, other.b.conn.role().unwrap());
    let mut p = Pair::new(0xa0, 0xb1, &[write()], &[write()]);
    p.b.auto = false;
    p.settle();
    p.a.receive(p.now, &frame(&Message::FolderProof(replayed)));
    assert_eq!(results(&p.a)[0].status, 2);
    // A seal that does not open, tier 0 and tier 4.
    for tier_byte in [None, Some(0u8), Some(4)] {
        let mut p = established();
        let th = *p.a.conn.transcript_hash().unwrap();
        let role_b = p.b.conn.role().unwrap();
        let keys = write().handshake_keys();
        let hint = keys.hint(&th.0, role_b);
        let (nonce, sealed) = match tier_byte {
            None => ([4u8; 24], vec![0; 18]),
            Some(t) => keys
                .seal_proof(&th.0, role_b, &[0x20, t], &mut |b: &mut [u8]| b.fill(4))
                .unwrap(),
        };
        p.a.receive(
            p.now,
            &frame(&Message::FolderProof(FolderProof {
                hint: hint.to_vec(),
                sealed,
                nonce: nonce.to_vec(),
            })),
        );
        assert_eq!(results(&p.a)[0].status, 2, "{tier_byte:?}");
        assert_eq!(
            p.a.conn.state(),
            State::Established,
            "REJECTED keeps the connection"
        );
    }
    // A folder held but paused (absent from the credentials): REJECTED.
    let mut p = established();
    p.a.credentials.clear();
    p.a.conn.refresh_folders();
    let proof = proof_from_b(&p, p.b.conn.role().unwrap());
    p.a.receive(p.now, &frame(&Message::FolderProof(proof)));
    assert_eq!(results(&p.a)[0].status, 2);
}

#[test]
fn proof_envelopes_and_results_that_close() {
    let bad = [
        FolderProof {
            hint: vec![1; 32],
            sealed: vec![0; 15],
            nonce: vec![0; 24],
        },
        FolderProof {
            hint: vec![1; 32],
            sealed: vec![0; 1025],
            nonce: vec![0; 24],
        },
        FolderProof {
            hint: vec![1; 32],
            sealed: vec![0; 18],
            nonce: vec![0; 23],
        },
    ];
    for proof in bad {
        let mut p = established();
        p.a.receive(p.now, &frame(&Message::FolderProof(proof)));
        assert_eq!(
            closed(&p.a),
            Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
        );
    }
    // The 257th proof.
    let mut p = established();
    for i in 0..=MAX_PROOFS_PER_CONNECTION {
        let mut hint = [0u8; 32];
        hint[..8].copy_from_slice(&(i as u64).to_be_bytes());
        p.a.receive(
            p.now,
            &frame(&Message::FolderProof(FolderProof {
                hint: hint.to_vec(),
                sealed: vec![0; 18],
                nonce: vec![0; 24],
            })),
        );
    }
    assert_eq!(results(&p.a).len(), MAX_PROOFS_PER_CONNECTION);
    assert_eq!(
        closed(&p.a),
        Some((CloseReason::ProtocolError, Some(Cause::Malformed)))
    );
    // A stray ProofResult, a second one, and one with status 3.
    let mut p = established();
    p.a.receive(
        p.now,
        &frame(&Message::ProofResult(ProofResult {
            hint: vec![1; 32],
            status: 1,
        })),
    );
    assert_eq!(closed(&p.a).map(|c| c.0), Some(CloseReason::ProtocolError));
    let mut p = established();
    p.a.prove_all(p.now);
    let ours: FolderProof = crate::parse::Parse::parse(&p.a.sent.last().unwrap().1[6..]).unwrap();
    let answer = frame(&Message::ProofResult(ProofResult {
        hint: ours.hint.clone(),
        status: 2,
    }));
    p.a.receive(p.now, &answer);
    assert!(p.a.saw(|e| matches!(e, Event::ProofRejected { .. })));
    assert_eq!(p.a.conn.state(), State::Established);
    p.a.receive(p.now, &answer);
    assert_eq!(
        closed(&p.a).map(|c| c.0),
        Some(CloseReason::ProtocolError),
        "a second result"
    );
    let mut p = established();
    p.a.prove_all(p.now);
    let ours: FolderProof = crate::parse::Parse::parse(&p.a.sent.last().unwrap().1[6..]).unwrap();
    let mut body = ProofResult {
        hint: ours.hint,
        status: 3,
    }
    .encode_to_vec();
    body.truncate(body.len());
    p.a.receive(p.now, &raw(0x8005, &body));
    assert_eq!(
        closed(&p.a).map(|c| c.0),
        Some(CloseReason::ProtocolError),
        "status 3"
    );
}

#[test]
fn the_open_folder_bound_rejects_the_65th() {
    let keys: Vec<FolderKey> = (0..65u8)
        .map(|i| FolderKey::from(folder(0x40 + i)))
        .collect();
    let mut p = Pair::new(0xa0, 0xb0, &keys, &keys);
    p.settle();
    p.b.prove_all(p.now);
    p.settle();
    let opened =
        p.a.events
            .iter()
            .filter(|e| matches!(e, Event::FolderOpened { .. }))
            .count();
    assert_eq!(opened, 64);
    assert_eq!(results(&p.a).iter().filter(|r| r.status == 2).count(), 1);
    assert_eq!(p.a.conn.state(), State::Established);
}

#[test]
fn unknown_types_once_established() {
    let mut p = Pair::open();
    p.a.receive(p.now, &raw(0x0007, b"x"));
    p.a.receive(p.now, &raw(0x0007, b"y"));
    let unsupported: Vec<Unsupported> =
        p.a.sent
            .iter()
            .filter(|(_, f)| f[4..6] == [0x00, 0x02])
            .map(|(_, f)| crate::parse::Parse::parse(&f[6..]).unwrap())
            .collect();
    assert_eq!(
        unsupported,
        vec![Unsupported { message_type: 7 }],
        "once per type"
    );
    assert!(p.a.saw(|e| matches!(e, Event::Ignored { message_type: 7 })));
    p.settle();
    assert!(p
        .b
        .saw(|e| matches!(e, Event::PeerUnsupported { message_type: 7 })));
    // 0x0000 is never used, so unknown: answered too.
    p.a.receive(p.now, &raw(0x0000, b""));
    assert_eq!(p.a.conn.state(), State::Established);
    // 0x8006, the drafts' key records, is an unknown critical type.
    p.a.receive(p.now, &raw(0x8006, b""));
    assert_eq!(
        closed(&p.a),
        Some((
            CloseReason::UnsupportedCriticalType,
            Some(Cause::UnknownCriticalType)
        ))
    );
}

#[test]
fn closing_and_the_flush() {
    let mut p = Pair::open();
    let tick = Tick::at(p.now);
    let out = p.a.conn.close(tick, CloseReason::Shutdown);
    assert_eq!(out.frames.len(), 1);
    assert_eq!(out.wake_at, Some(p.now + s(1)));
    p.a.apply(p.now, out);
    p.settle();
    assert!(p.b.saw(|e| matches!(
        e,
        Event::Closed {
            reason: CloseReason::Shutdown,
            by: Side::Peer,
            ..
        }
    )));
    assert_eq!(p.a.conn.state(), State::Closed);
    // Nothing is processed after a Close.
    let before = p.a.events.len();
    p.a.receive(p.now, &raw(0x0003, b""));
    assert_eq!(p.a.events.len(), before);
    assert_eq!(
        p.a.conn.send_status(Tick::at(p.now), &[]).err(),
        Some(SendError::Closed)
    );
    p.advance(s(1));
    assert!(p.a.transport_closed);
    // A Close whose detail breaks its grammar: the reason is still reported.
    let mut p = Pair::open();
    let bad = Close {
        reason: 1,
        detail: "a\nb".into(),
    };
    p.a.receive(p.now, &frame(&Message::Close(bad)));
    assert!(p.a.saw(|e| matches!(e, Event::Closed { reason: CloseReason::Shutdown, by: Side::Peer, detail, .. } if detail.is_empty())));
}

#[test]
fn configuration_errors_and_proving_errors() {
    let (key, libp2p) = device(0xa0);
    let mut rng = Rng(1);
    let mut bad = Config::new(libp2p);
    bad.max_message_size = 1;
    assert_eq!(
        Connection::new(&key, bad, &mut |b| rng.fill(b), Tick::default()).err(),
        Some(ConfigError::Limits)
    );
    // max_requests_in_flight: 1 ..= MAX_REQUESTS_IN_FLIGHT (SEC-B1).
    for (n, ok) in [
        (0, false),
        (1, true),
        (MAX_REQUESTS_IN_FLIGHT, true),
        (MAX_REQUESTS_IN_FLIGHT + 1, false),
    ] {
        let mut c = Config::new(libp2p);
        c.max_requests_in_flight = n;
        let made = Connection::new(&key, c, &mut |b| rng.fill(b), Tick::default());
        assert_eq!(made.is_ok(), ok, "max_requests_in_flight {n}");
        if !ok {
            assert_eq!(made.err(), Some(ConfigError::Limits));
        }
    }
    let mut bad = Config::new(libp2p);
    bad.compressions.clear();
    assert!(matches!(
        Connection::new(&key, bad, &mut |b| rng.fill(b), Tick::default()),
        Err(ConfigError::Hello(_))
    ));
    let mut bad = Config::new(libp2p);
    bad.device_name = "a\u{7}".into();
    assert!(Connection::new(&key, bad, &mut |b| rng.fill(b), Tick::default()).is_err());
    let mut bad = Config::new(libp2p);
    bad.features = vec!["f".repeat(32); 32];
    bad.compressions = (0..32).map(|i| format!("c{i:0>19}")).collect();
    bad.hashes = std::iter::once("blake3".to_string())
        .chain((0..31).map(|i| format!("h{i:0>19}")))
        .collect();
    bad.compressions[0] = "none".into();
    assert!(
        Connection::new(&key, bad, &mut |b| rng.fill(b), Tick::default()).is_ok(),
        "the largest Hello fits"
    );
    for e in [
        ConfigError::Limits,
        ConfigError::Hello(CloseReason::ProtocolError),
        ConfigError::HelloTooLarge,
    ] {
        assert_ne!(e.to_string(), "");
    }
    let mut p = Pair::open();
    let keys = Keys {
        device: &p.a.key,
        folders: &p.a.credentials,
    };
    let other = folder(0x77).verifier().folder_id();
    assert_eq!(
        p.a.conn
            .prove(&keys, &mut |b| b.fill(0), Tick::at(p.now), other)
            .err(),
        Some(ProveError::UnknownFolder)
    );
    let mut name = p.a.conn.set_device_name("x\n".into());
    assert!(name.is_err());
    name = p.a.conn.set_device_name("renamed".into());
    assert!(name.is_ok());
    let out = p.a.conn.close(Tick::at(p.now), CloseReason::Shutdown);
    p.a.apply(p.now, out);
    let keys = Keys {
        device: &p.a.key,
        folders: &p.a.credentials,
    };
    let id = p.a.folder_id();
    assert_eq!(
        p.a.conn
            .prove(&keys, &mut |b| b.fill(0), Tick::at(p.now), id)
            .err(),
        Some(ProveError::Closed)
    );
    for e in [
        ProveError::Closed,
        ProveError::UnknownFolder,
        ProveError::TooMany,
    ] {
        assert_ne!(e.to_string(), "");
    }
}

#[test]
fn this_sides_own_proofs_are_bounded() {
    // R2-SF4: at most MAX_PROOFS_PER_CONNECTION proofs sent or waiting, both
    // before the handshake ends (kept) and after (sent).
    let keys: Vec<FolderKey> = (0..=MAX_PROOFS_PER_CONNECTION)
        .map(|i| {
            let mut ws = [0u8; 32];
            ws[..8].copy_from_slice(&(i as u64).to_be_bytes());
            ws[31] = 0x5a;
            FolderKey::from(
                licketysync_keys::WriteKey::from_secret(
                    licketysync_keys::Suite::ONE,
                    licketysync_keys::secret::WriteSecret::from_bytes(ws),
                )
                .unwrap(),
            )
        })
        .collect();
    for established in [false, true] {
        let mut p = Pair::new(0xa0, 0xb0, &keys, &[write()]);
        if established {
            p.b.auto = false;
            p.settle();
            assert_eq!(p.a.conn.state(), State::Established);
        }
        let ids: Vec<_> =
            p.a.credentials
                .iter()
                .map(FolderCredential::folder_id)
                .collect();
        let mut rng = Rng(9);
        for (i, id) in ids.iter().enumerate() {
            let k = Keys {
                device: &p.a.key,
                folders: &p.a.credentials,
            };
            let got =
                p.a.conn
                    .prove(&k, &mut |b| rng.fill(b), Tick::at(p.now), *id);
            if i < MAX_PROOFS_PER_CONNECTION {
                let out = got.unwrap();
                p.a.apply(p.now, out);
            } else {
                assert_eq!(
                    got.err(),
                    Some(ProveError::TooMany),
                    "established {established}"
                );
            }
        }
        if established {
            let proofs =
                p.a.sent
                    .iter()
                    .filter(|(_, f)| f[4..6] == [0x80, 0x04])
                    .count();
            assert_eq!(proofs, MAX_PROOFS_PER_CONNECTION);
        }
    }
}

#[test]
fn folders_proved_before_the_handshake_ends_wait_for_it() {
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    // Before anything is delivered: the proof is kept, nothing about the
    // folder leaves.
    p.a.prove_all(p.now);
    p.a.prove_all(p.now);
    assert!(!p.a.sent.iter().any(|(_, f)| f[4..6] == [0x80, 0x04]));
    p.settle();
    assert!(p.a.conn.is_open(&p.a.folder_id()));
    let proofs =
        p.a.sent
            .iter()
            .filter(|(_, f)| f[4..6] == [0x80, 0x04])
            .count();
    assert_eq!(proofs, 1, "one proof per folder per connection");
    // Proving an open folder again does nothing.
    p.a.prove_all(p.now);
    assert_eq!(
        p.a.sent
            .iter()
            .filter(|(_, f)| f[4..6] == [0x80, 0x04])
            .count(),
        1
    );
}

#[test]
fn another_device_key_than_the_hellos_is_a_local_error() {
    let mut p = Pair::new(0xa0, 0xb0, &[write()], &[write()]);
    let hello_b = core::mem::take(&mut p.b.outbox);
    let (other, _) = device(0xc0);
    let keys = Keys {
        device: &other,
        folders: &p.a.credentials,
    };
    let out =
        p.a.conn
            .receive(&keys, &mut |b| b.fill(0), Tick::at(p.now), &hello_b);
    p.a.apply(p.now, out);
    assert_eq!(closed(&p.a), Some((CloseReason::Unspecified, None)));
}
