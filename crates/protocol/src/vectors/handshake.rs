// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Items 2 to 5: Hello, the transcript, the device proof and the folder
//! proof.

use licketysync_keys::folder::FolderKey;
use licketysync_keys::{Role, Suite, Tier};
use prost::Message as _;
use serde_json::{json, Value};

use super::{check, ending, feed, h, key, scenario, seed};
use crate::connection::{Config, Connection, Event, State, Tick};
use crate::frame::Frame;
use crate::hello::TranscriptHash;
use crate::limits::{MAX_PROOFS_PER_CONNECTION, PRE_HELLO_LIMIT};
use crate::messages::{DeviceProof, FolderProof, Hello, Message, ProofResult};
use crate::parse::Parse;
use crate::proof::{seal_proof, FolderCredential};
use crate::testkit::{device, fixed32, folder, s, Pair, Rng};

fn frame(m: &Message) -> Vec<u8> {
    m.to_frame().unwrap().encode()
}

fn hello_of(p: &Pair, a: bool) -> Vec<u8> {
    let side = if a { &p.a } else { &p.b };
    side.sent[0].1.clone()
}

/// The largest Hello major 1 sends: every list at its bound, every entry at
/// its longest, the widest varints.
fn largest_config(libp2p: [u8; 32]) -> Config {
    let mut c = Config::new(libp2p);
    c.suites = vec![Suite::ONE];
    c.compressions = std::iter::once("none".to_string())
        .chain((1..32).map(|i| format!("c{i:0>19}")))
        .collect();
    c.hashes = std::iter::once("blake3".to_string())
        .chain((1..32).map(|i| format!("h{i:0>19}")))
        .collect();
    c.features = (0..32).map(|i| format!("f{i:0>31}")).collect();
    c.max_message_size = crate::limits::MAX_MESSAGE_SIZE;
    c.max_requests_in_flight = crate::limits::MAX_REQUESTS_IN_FLIGHT;
    c
}

#[test]
fn vector_hello_transcript_and_device_proof() {
    let p = Pair::open();
    let (ha, hb) = (hello_of(&p, true), hello_of(&p, false));
    let ra = p.a.conn.role().unwrap();
    let th = *p.a.conn.transcript_hash().unwrap();
    assert_eq!(Some(&th), p.b.conn.transcript_hash());
    let proof_of = |side: &crate::testkit::Side| {
        side.sent
            .iter()
            .find(|(_, f)| f[4..6] == [0x80, 0x03])
            .unwrap()
            .1
            .clone()
    };
    let (pa, pb) = (proof_of(&p.a), proof_of(&p.b));
    seed("hello_check", "hello-a", &ha[6..]);
    seed("hello_check", "hello-b", &hb[6..]);
    // The same two devices with the other one created first: the roles
    // depend only on the keys.
    let q = Pair::new(0xb0, 0xa0, &[key()], &[key()]);
    let mut q = q;
    q.settle();
    assert_eq!(
        q.b.conn.role(),
        Some(ra),
        "device 0xa0 has the same role either way"
    );

    // The largest Hello.
    let (dk, libp2p) = device(0xa0);
    let (big, out) = Connection::new(
        &dk,
        largest_config(libp2p),
        &mut |b| b.fill(7),
        Tick::default(),
    )
    .unwrap();
    let largest = out.frames[0].clone();
    assert!(largest.len() - 4 <= PRE_HELLO_LIMIT as usize);
    assert_eq!(big.state(), State::AwaitingHello);
    seed("hello_check", "largest", &largest[6..]);

    // Failing variants, each fed to a connection as the first frame.
    let base: Hello = Hello::parse(&hb[6..]).unwrap();
    let mut refused = Vec::new();
    let mut variant = |name: &str, change: &dyn Fn(&mut Hello), want: &str| {
        let mut v = base.clone();
        change(&mut v);
        let bytes = frame(&Message::Hello(Box::new(v)));
        let got = feed("first", &bytes);
        assert_eq!(got, want, "{name}");
        seed("hello_check", name, &bytes[6..]);
        refused.push(json!({ "name": name, "input": super::input(&bytes), "outcome": got }));
    };
    let pe = "close PROTOCOL_ERROR (Malformed)";
    variant(
        "device-key-1986-bytes-the-drafts-hybrid-form",
        &|v| v.device_public_key = [&[0, 1][..], &[7; 1984][..]].concat(),
        pe,
    );
    variant(
        "device-key-33-bytes",
        &|v| v.device_public_key.truncate(33),
        pe,
    );
    let mut non_canonical = [0xffu8; 32];
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;
    variant(
        "device-key-non-canonical",
        &|v| v.device_public_key = [&[0, 1][..], &non_canonical[..]].concat(),
        pe,
    );
    let mut small = [0u8; 32];
    small[0] = 1;
    variant(
        "device-key-small-order",
        &|v| v.device_public_key = [&[0, 1][..], &small[..]].concat(),
        pe,
    );
    variant(
        "missing-none",
        &|v| v.compressions = vec!["zstd".into()],
        pe,
    );
    variant("missing-blake3", &|v| v.hashes = vec!["sha3".into()], pe);
    variant(
        "limit-below-floor",
        &|v| v.max_message_size = (8 << 20) - 1,
        "close LIMIT_TOO_SMALL (LimitTooSmall)",
    );
    variant(
        "no-common-suite",
        &|v| v.suites = vec![2],
        "close NO_COMMON_SUITE (NoCommonSuite)",
    );
    variant("suite-0", &|v| v.suites = vec![0], pe);
    variant("suite-65536", &|v| v.suites = vec![65_536], pe);
    variant("17-suites", &|v| v.suites = (1..=17).collect(), pe);
    variant("duplicate-suites", &|v| v.suites = vec![1, 1], pe);
    variant("identity-31-bytes", &|v| v.libp2p_identity.truncate(31), pe);
    variant(
        "feature-grammar",
        &|v| v.features = vec!["Upper".into()],
        pe,
    );
    variant("nonce-31-bytes", &|v| v.nonce.truncate(31), pe);
    variant(
        "max-requests-in-flight-0",
        &|v| v.max_requests_in_flight = 0,
        pe,
    );
    let own = Hello::parse(&ha[6..]).unwrap();
    variant(
        "equal-device-keys",
        &|v| v.device_public_key = own.device_public_key.clone(),
        pe,
    );

    // The device proof: both roles from the scenario; a bad one, a short
    // one, a second one; HELLO_TIMEOUT.
    let mut proofs = Vec::new();
    let mut proof = |name: &str, state: &str, bytes: Vec<u8>, want: &str| {
        let got = feed(state, &bytes);
        assert_eq!(got, want, "{name}");
        proofs.push(
            json!({ "name": name, "state": state, "input": super::input(&bytes), "outcome": got }),
        );
    };
    proof(
        "does-not-verify",
        "before-device-proof",
        frame(&Message::DeviceProof(DeviceProof {
            signature: vec![7; 64],
        })),
        "close PROOF_REJECTED (DeviceProofRejected)",
    );
    let mut short = Vec::new();
    prost::encoding::bytes::encode(1, &vec![7u8; 63], &mut short);
    proof(
        "63-bytes",
        "before-device-proof",
        Frame::new(0x8003, short).unwrap().encode(),
        pe,
    );
    proof("second-device-proof", "established", pb.clone(), pe);
    proof("second-hello", "established", hb.clone(), pe);
    let mut t = Pair::new(0xa0, 0xb0, &[key()], &[key()]);
    t.b.auto = false;
    let hello = core::mem::take(&mut t.b.outbox);
    t.a.receive(t.now, &hello);
    t.b.outbox.clear();
    t.a.outbox.clear();
    t.advance(s(10));
    assert_eq!(ending(&t.a)["row"], "HelloTimeout");

    let value: Value = json!({
        "description": "protocol.md 8 items 2 to 4: the Hellos of devices a0 and b0 (device seeds a0.. and b0..; the role depends only on the keys), the largest Hello, refused variants fed as a first frame, the transcript hash, the device proofs and the device-proof failures.",
        "hello_a": h(&ha),
        "hello_b": h(&hb),
        "role_of_a": ra.as_u8(),
        "transcript_hash": h(th.as_bytes()),
        "device_proof_a": h(&pa),
        "device_proof_b": h(&pb),
        "largest_hello": h(&largest),
        "largest_hello_length_field": largest.len() - 4,
        "refused_hellos": refused,
        "device_proofs": proofs,
        "hello_timeout": scenario(&t, &["HelloTimeout"], json!("B's Hello arrives, its DeviceProof never")),
    });
    check("hello", &value);
}

/// The proofs `prover` sends `verifier` on a pair of the given tiers.
fn opened(prover: Tier, verifier: Tier) -> Pair {
    let k = |t: Tier| key().lowered(t).unwrap();
    let mut p = Pair::new(0xa0, 0xb0, &[k(prover)], &[k(verifier)]);
    p.settle();
    p.a.prove_all(p.now);
    p.settle();
    p
}

fn results(side: &crate::testkit::Side) -> Vec<u32> {
    side.sent
        .iter()
        .filter(|(_, f)| f[4..6] == [0x80, 0x05])
        .map(|(_, f)| ProofResult::parse(&f[6..]).unwrap().status)
        .collect()
}

#[test]
fn vector_folder_proof() {
    // The construction under the keys crate's inputs of keys.md 9 item 9:
    // the fixed folder and th = 70 71 .. 8f; the sealed payloads equal the
    // keys crate's committed ones.
    let th = TranscriptHash(fixed32(0x70));
    let keys_file: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../keys/tests/vectors/handshake.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let cred = FolderCredential::new(&key());
    let hk = key().handshake_keys();
    let mut sealed = Vec::new();
    for (r, role) in [Role::A, Role::B].into_iter().enumerate() {
        for (t, tier) in Tier::ALL.into_iter().enumerate() {
            let n = 0x71 + u8::try_from(r * 3 + t).unwrap();
            let proof = seal_proof(&hk, &th, role, tier, &mut |b: &mut [u8]| b.fill(n)).unwrap();
            let theirs = &keys_file["payloads"][r * 3 + t];
            assert_eq!(
                theirs["sealed"],
                h(&proof.sealed),
                "role {role:?} tier {tier:?}"
            );
            assert_eq!(theirs["nonce"], h(&proof.nonce));
            assert_eq!(cred.open(&th, role, &proof), Ok(tier));
            seed(
                "folder_proof",
                &format!("role{}-tier{}", role.as_u8(), tier.as_u8()),
                &proof.encode_to_vec(),
            );
            sealed.push(json!({ "role": role.as_u8(), "tier": tier.as_u8(), "folder_proof": h(&proof.encode_to_vec()) }));
        }
    }
    assert_eq!(keys_file["hint_role_a"], h(&cred.hint(&th, Role::A)));
    assert_eq!(keys_file["hint_role_b"], h(&cred.hint(&th, Role::B)));

    // ACCEPTED between every pair of tiers, the reported tier recorded as sent.
    let mut accepted = Vec::new();
    for prover in Tier::ALL {
        for verifier in Tier::ALL {
            let p = opened(prover, verifier);
            assert!(p.b.saw(
                |e| matches!(e, Event::FolderOpened { peer_tier, .. } if *peer_tier == prover)
            ));
            assert!(p.a.saw(
                |e| matches!(e, Event::FolderOpened { peer_tier, .. } if *peer_tier == verifier)
            ));
            accepted.push(json!({
                "prover": prover.as_u8(), "verifier": verifier.as_u8(),
                "scenario": scenario(&p, &[], json!("both open; each records the tier the other reported")),
            }));
        }
    }

    // REJECTED for each failure of 3.5, the connection kept.
    let established = || {
        let mut p = Pair::new(0xa0, 0xb0, &[key()], &[key()]);
        p.b.auto = false;
        p.settle();
        p.b.outbox.clear();
        p
    };
    let mut rejected = Vec::new();
    let mut reject = |name: &str, p: &mut Pair, proof: FolderProof| {
        let bytes = frame(&Message::FolderProof(proof.clone()));
        p.a.receive(p.now, &bytes);
        assert_eq!(results(&p.a), vec![2], "{name}");
        assert_eq!(p.a.conn.state(), State::Established, "{name}");
        seed("folder_proof", name, &proof.encode_to_vec());
        rejected.push(json!({ "name": name, "input": super::input(&bytes), "proof_result": h(&p.a.sent.last().unwrap().1) }));
    };
    let mut p = established();
    let th = *p.a.conn.transcript_hash().unwrap();
    let role_b = p.b.conn.role().unwrap();
    let mut rng = Rng(3);
    let other = FolderCredential::new(&FolderKey::from(folder(0x20)));
    reject(
        "hint-matches-no-folder",
        &mut p,
        other.prove(&th, role_b, &mut |b| rng.fill(b)).unwrap(),
    );
    let mut p = established();
    p.a.credentials.clear();
    p.a.conn.refresh_folders();
    reject(
        "folder-held-but-paused",
        &mut p,
        cred.prove(&th, role_b, &mut |b| rng.fill(b)).unwrap(),
    );
    let mut p = established();
    let mut bad_seal = cred.prove(&th, role_b, &mut |b| rng.fill(b)).unwrap();
    bad_seal.sealed[0] ^= 1;
    reject("seal-does-not-open", &mut p, bad_seal);
    for t in [0u8, 4] {
        let mut p = established();
        let hint = hk.hint(&th.0, role_b);
        let (nonce, sealed) = hk
            .seal_proof(&th.0, role_b, &[0x20, t], &mut |b: &mut [u8]| b.fill(9))
            .unwrap();
        reject(
            &format!("tier-{t}"),
            &mut p,
            FolderProof {
                hint: hint.to_vec(),
                sealed,
                nonce: nonce.to_vec(),
            },
        );
    }
    let mut p = established();
    let role_a = p.a.conn.role().unwrap();
    reject(
        "reflected",
        &mut p,
        cred.prove(&th, role_a, &mut |b| rng.fill(b)).unwrap(),
    );
    let mut p = established();
    reject(
        "replayed-from-another-connection",
        &mut p,
        cred.prove(&TranscriptHash([1; 32]), role_b, &mut |b| rng.fill(b))
            .unwrap(),
    );
    // A sealed key made of this folder's verification key and the other
    // folder's access key.
    let w = folder(0x10);
    let o_payload = FolderKey::from(folder(0x20).sealed_key()).payload();
    let mut mixed = o_payload.to_vec();
    mixed[2..34].copy_from_slice(w.verifier().verifying_key().as_bytes());
    let halves = FolderKey::from_payload(Tier::Sealed, &mixed).unwrap();
    let mut p = established();
    reject(
        "key-of-two-folders-halves",
        &mut p,
        FolderCredential::new(&halves)
            .prove(&th, role_b, &mut |b| rng.fill(b))
            .unwrap(),
    );
    // The open-folder bound: 65 folders, one REJECTED.
    let many: Vec<FolderKey> = (0..65u8)
        .map(|i| FolderKey::from(folder(0x40 + i)))
        .collect();
    let mut b65 = Pair::new(0xa0, 0xb0, &many, &many);
    b65.settle();
    b65.b.prove_all(b65.now);
    b65.settle();
    let statuses = results(&b65.a);
    assert_eq!(statuses.iter().filter(|s| **s == 2).count(), 1);
    assert_eq!(statuses.len(), 65);
    // The peer's Hello not listing the folder's suite cannot be reached while
    // suite 1 is the only one: a peer without it has no common suite.

    // Envelopes and results that close.
    let mut closing = Vec::new();
    let mut close = |name: &str, bytes: Vec<u8>| {
        let got = feed("established", &bytes);
        assert_eq!(got, "close PROTOCOL_ERROR (Malformed)", "{name}");
        seed("folder_proof", name, &bytes[6..]);
        closing.push(json!({ "name": name, "input": super::input(&bytes), "outcome": got }));
    };
    let good = cred.prove(&th, role_b, &mut |b| rng.fill(b)).unwrap();
    close(
        "nonce-23-bytes",
        frame(&Message::FolderProof(FolderProof {
            nonce: vec![0; 23],
            ..good.clone()
        })),
    );
    close(
        "sealed-15-bytes",
        frame(&Message::FolderProof(FolderProof {
            sealed: vec![0; 15],
            ..good.clone()
        })),
    );
    close(
        "sealed-1025-bytes",
        frame(&Message::FolderProof(FolderProof {
            sealed: vec![0; 1025],
            ..good.clone()
        })),
    );
    close(
        "stray-proof-result",
        frame(&Message::ProofResult(ProofResult {
            hint: vec![1; 32],
            status: 1,
        })),
    );
    let mut status3 = Vec::new();
    prost::encoding::bytes::encode(1, &vec![1u8; 32], &mut status3);
    prost::encoding::uint32::encode(2, &3, &mut status3);
    close(
        "proof-result-status-3",
        Frame::new(0x8005, status3).unwrap().encode(),
    );
    // A second proof with the same hint, and the 257th.
    let mut p = established();
    let proof = frame(&Message::FolderProof(
        cred.prove(&th, role_b, &mut |b| rng.fill(b)).unwrap(),
    ));
    p.a.receive(p.now, &proof);
    p.a.receive(p.now, &proof);
    assert_eq!(ending(&p.a)["closed"], "PROTOCOL_ERROR");
    let mut p = established();
    for i in 0..=MAX_PROOFS_PER_CONNECTION {
        let mut hint = [0u8; 32];
        hint[..8].copy_from_slice(&(i as u64).to_be_bytes());
        p.a.receive(
            p.now,
            &frame(&Message::FolderProof(FolderProof {
                hint: hint.to_vec(),
                ..good.clone()
            })),
        );
    }
    assert_eq!(results(&p.a).len(), MAX_PROOFS_PER_CONNECTION);
    assert_eq!(ending(&p.a)["closed"], "PROTOCOL_ERROR");
    // A second result for the same proof.
    let mut p = established();
    p.a.prove_all(p.now);
    let ours = FolderProof::parse(&p.a.sent.last().unwrap().1[6..]).unwrap();
    let answer = frame(&Message::ProofResult(ProofResult {
        hint: ours.hint,
        status: 2,
    }));
    p.a.receive(p.now, &answer);
    assert_eq!(p.a.conn.state(), State::Established);
    p.a.receive(p.now, &answer);
    assert_eq!(ending(&p.a)["closed"], "PROTOCOL_ERROR");
    // PROOF_TIMEOUT with nothing open.
    let mut t = Pair::new(0xa0, 0xb0, &[key()], &[FolderKey::from(folder(0x20))]);
    t.settle();
    t.a.prove_all(t.now);
    t.b.prove_all(t.now);
    t.settle();
    t.advance(s(31));
    assert_eq!(ending(&t.a)["row"], "ProofTimeout");

    let value: Value = json!({
        "description": "protocol.md 8 item 5: the folder proof for the keys crate's fixed folder and th = 70 71 .. 8f (equal to its handshake.json), ACCEPTED between holders of each tier, REJECTED for every failure of 3.5 with the connection kept (but step 5, the folder's suite missing from the peer's Hello, which no peer can reach while suite 1 is the only suite: a Hello without it has no suite in common and is closed NO_COMMON_SUITE), the envelopes and results that close, a second proof and a second result, and PROOF_TIMEOUT. The open-folder bound: of 65 folders proved, 64 open and one is REJECTED.",
        "sealed_payloads": sealed,
        "accepted": accepted,
        "rejected": rejected,
        "open_folder_bound_results": statuses,
        "closing": closing,
        "proof_timeout": scenario(&t, &["FolderProofRejected", "ProofTimeout"], json!("each holds a folder the other lacks")),
    });
    check("folder_proof", &value);
}
