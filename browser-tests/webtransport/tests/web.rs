// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Spike B, browser half: headless Chrome dials the native listeners
//! (`crates/net/examples/webtransport_listen.rs`) with
//! `libp2p-webtransport-websys`, given only each listener's multiaddr
//! (address, certhash, peer ID). The addresses come in at build time from the
//! listener's output (`ci/webtransport-chrome.sh`). Identities are fixed
//! public test seeds.
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::poll_fn;
use std::pin::Pin;

use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use libp2p_core::multiaddr::Protocol;
use libp2p_core::multihash::Multihash;
use libp2p_core::muxing::StreamMuxer;
use libp2p_core::transport::{DialOpts, PortUse, Transport as _};
use libp2p_core::{Endpoint, Multiaddr};
use libp2p_identity::{Keypair, PeerId};
use libp2p_webtransport_websys::{Config, Connection, Error, Transport};
use wasm_bindgen_test::{console_log, wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const PROTOCOL: &str = "/licketysync/sync/1";
const MIB: usize = 1024 * 1024;
const PIECE: usize = 64 * 1024;
const BROWSER_SEED: u8 = 2;
const LISTENER_SEED: u8 = 1;

fn addr(value: Option<&'static str>, name: &str) -> Multiaddr {
    value
        .unwrap_or_else(|| panic!("WT_PROBE_{name} was not set at build time"))
        .parse()
        .unwrap()
}

fn ok_addr() -> Multiaddr {
    addr(option_env!("WT_PROBE_OK"), "OK")
}

fn keypair(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn listener_peer() -> PeerId {
    keypair(LISTENER_SEED).public().to_peer_id()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap_or(0))
        .collect()
}

async fn dial(addr: Multiaddr) -> Result<(PeerId, Connection), Error> {
    let mut transport = Transport::new(Config::new(&keypair(BROWSER_SEED)));
    let opts = DialOpts {
        role: Endpoint::Dialer,
        port_use: PortUse::New,
    };
    match transport.dial(addr, opts) {
        Ok(fut) => fut.await,
        Err(e) => panic!("dial refused the address: {e}"),
    }
}

async fn echo(conn: &mut Connection, len: usize) -> Result<usize, String> {
    let stream = poll_fn(|cx| Pin::new(&mut *conn).poll_outbound(cx))
        .await
        .map_err(|e| format!("open stream: {e}"))?;
    let (protocol, io) = multistream_select::dialer_select_proto(
        stream,
        [PROTOCOL],
        multistream_select::Version::V1,
    )
    .await
    .map_err(|e| format!("multistream-select: {e}"))?;
    assert_eq!(protocol, PROTOCOL);
    let payload = pattern(len);
    let (mut reader, mut writer) = io.split();
    let write = async {
        for piece in payload.chunks(PIECE) {
            writer.write_all(piece).await?;
        }
        writer.close().await
    };
    let read = async {
        let mut got = Vec::with_capacity(len);
        reader.read_to_end(&mut got).await.map(|_| got)
    };
    let (w, r) = futures::join!(write, read);
    w.map_err(|e| format!("write: {e}"))?;
    let got = r.map_err(|e| format!("read: {e}"))?;
    if got != payload {
        return Err(format!("echo differs: sent {len}, got {}", got.len()));
    }
    Ok(got.len())
}

fn with_certhashes(addr: &Multiaddr, hashes: &[Multihash<64>], peer: Option<PeerId>) -> Multiaddr {
    let mut out = Multiaddr::empty();
    for p in addr {
        match p {
            Protocol::Certhash(_) | Protocol::P2p(_) => {}
            other => out.push(other),
        }
    }
    for h in hashes {
        out.push(Protocol::Certhash(*h));
    }
    if let Some(peer) = peer {
        out.push(Protocol::P2p(peer));
    }
    out
}

fn certhash_of(addr: &Multiaddr) -> Multihash<64> {
    addr.iter()
        .find_map(|p| match p {
            Protocol::Certhash(h) => Some(h),
            _ => None,
        })
        .unwrap()
}

fn other_hash() -> Multihash<64> {
    Multihash::wrap(0x12, &[0xAB; 32]).unwrap()
}

async fn expect_echo(name: &str, a: Multiaddr) {
    console_log!("{name}: dialing {a}");
    let (peer, mut conn) = dial(a)
        .await
        .unwrap_or_else(|e| panic!("{name}: dial failed: {e:?}"));
    assert_eq!(peer, listener_peer());
    let n = echo(&mut conn, MIB)
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(n, MIB);
    console_log!("{name}: listener proved {peer}; {n} bytes echoed in order over {PROTOCOL}");
}

#[wasm_bindgen_test]
async fn b2_one_mib_echoes_with_only_address_and_certhash() {
    expect_echo("OK", ok_addr()).await;
}

#[wasm_bindgen_test]
async fn b1_pq_only_listener_accepts_chrome() {
    expect_echo("PQ", addr(option_env!("WT_PROBE_PQ"), "PQ")).await;
}

#[wasm_bindgen_test]
async fn b1_classical_only_listener_accepts_chrome() {
    expect_echo(
        "CLASSICAL",
        addr(option_env!("WT_PROBE_CLASSICAL"), "CLASSICAL"),
    )
    .await;
}

#[wasm_bindgen_test]
async fn neg_wrong_certhash_is_refused() {
    let a = with_certhashes(&ok_addr(), &[other_hash()], Some(listener_peer()));
    let r = dial(a).await;
    console_log!("wrong certhash: {:?}", r.as_ref().err());
    assert!(
        matches!(r, Err(Error::JsError(_))),
        "{:?}",
        r.map(|(p, _)| p)
    );
}

#[wasm_bindgen_test]
async fn neg_listener_reporting_other_certhashes_in_noise_is_refused() {
    let r = dial(addr(option_env!("WT_PROBE_LIAR"), "LIAR")).await;
    console_log!("liar: {:?}", r.as_ref().err());
    assert!(
        matches!(
            r,
            Err(Error::Noise(
                libp2p_noise::Error::UnknownWebTransportCerthashes(..)
            ))
        ),
        "{:?}",
        r.map(|(p, _)| p)
    );
}

#[wasm_bindgen_test]
async fn neg_dialed_certhash_not_reported_in_noise_is_refused() {
    let ok = ok_addr();
    let a = with_certhashes(
        &ok,
        &[certhash_of(&ok), other_hash()],
        Some(listener_peer()),
    );
    let r = dial(a).await;
    console_log!("extra certhash: {:?}", r.as_ref().err());
    assert!(
        matches!(
            r,
            Err(Error::Noise(
                libp2p_noise::Error::UnknownWebTransportCerthashes(..)
            ))
        ),
        "{:?}",
        r.map(|(p, _)| p)
    );
}

#[wasm_bindgen_test]
async fn neg_listener_with_another_peer_id_is_refused() {
    let ok = ok_addr();
    let a = with_certhashes(
        &ok,
        &[certhash_of(&ok)],
        Some(keypair(9).public().to_peer_id()),
    );
    let r = dial(a).await;
    console_log!("wrong peer: {:?}", r.as_ref().err());
    assert!(
        matches!(r, Err(Error::UnknownRemotePeerId)),
        "{:?}",
        r.map(|(p, _)| p)
    );
}

#[wasm_bindgen_test]
async fn neg_certificate_valid_15_days_is_refused_by_chrome() {
    let r = dial(addr(option_env!("WT_PROBE_LONG"), "LONG")).await;
    console_log!("15-day certificate: {:?}", r.as_ref().err());
    assert!(
        matches!(r, Err(Error::JsError(_))),
        "{:?}",
        r.map(|(p, _)| p)
    );
}

#[wasm_bindgen_test]
async fn neg_listener_expecting_another_browser_refuses() {
    let (peer, mut conn) = dial(addr(option_env!("WT_PROBE_STRICT"), "STRICT"))
        .await
        .unwrap();
    assert_eq!(peer, listener_peer());
    let r = echo(&mut conn, MIB).await;
    console_log!("strict listener: {r:?}");
    assert!(r.is_err());
}
