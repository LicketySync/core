// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Spike A by hand (pass condition A1), on 127.0.0.1: every socket that stays
//! bound is on 127.0.0.1; quinn-udp's GSO and GRO checks open and close `[::]`
//! sockets without sending. In one terminal:
//!
//! ```text
//! cargo run -p licketysync-net --example spike -- listen
//! ```
//!
//! It prints its peer ID and two addresses, QUIC first, then TCP. In
//! another terminal, once for each address:
//!
//! ```text
//! cargo run -p licketysync-net --example spike -- dial <address>
//! ```
//!
//! Each side prints the peer ID the other side proved in its TLS handshake
//! (the one the other side printed for itself), the protocol both agreed
//! on, `/licketysync/sync/1`, and the dialer prints "1 MiB echoed in order"
//! once the listener has echoed a mebibyte back unchanged. Both identities
//! come from the keys crate's public test seeds (the listener's is its
//! vector seed, so its peer ID is the vector's `12D3KooWLbwY…`); never a real
//! key. The listener runs until Ctrl-C; the dialer exits 0 on success, 1 on
//! any failure, within 60 seconds.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    unused_crate_dependencies,
    reason = "the by-hand check prints what A1 asks to see; an example links every dev-dependency"
)]

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt as _};
use libp2p_core::multiaddr::Protocol;
use libp2p_core::{ConnectedPoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{Stream, SwarmEvent};
use licketysync_keys::device::Libp2pIdentity;
use licketysync_keys::secret::DeviceSeed;
use licketysync_net::limits::Limits;
use licketysync_net::node::{self, dial_opts::DialOpts, Event, Swarm};
use licketysync_net::pieces::{Delivery, Pieces};
use licketysync_net::sync;

const MIB: usize = 1 << 20;

/// The dialer gives up after this long.
const DEADLINE: Duration = Duration::from_secs(60);

/// The keys crate's fixed test seed `start, start + 1, …`: public, never a
/// real key.
fn identity_of(start: u8) -> Libp2pIdentity {
    let seed: [u8; 32] = core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap_or(0)));
    Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes(seed))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0) ^ u8::try_from((i >> 16) % 256).unwrap_or(0))
        .collect()
}

fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

fn transport_of(addr: &Multiaddr) -> &'static str {
    if is_quic(addr) {
        "QUIC"
    } else {
        "TCP"
    }
}

/// `/ip4/127.0.0.1/udp/0/quic-v1`: QUIC on loopback, any port.
fn loopback_quic() -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(0))
        .with(Protocol::QuicV1)
}

fn remote_of(endpoint: &ConnectedPoint) -> &Multiaddr {
    match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}

fn build(start: u8) -> Result<Swarm, String> {
    let swarm = node::build(&identity_of(start), &Limits::default()).map_err(|e| e.to_string())?;
    println!("peer ID (this side): {}", swarm.local_peer_id());
    Ok(swarm)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    // Semgrep's community rule flags every std::env::args(): argv[0], the
    // program name, can be set to anything by the caller. It is skipped here
    // and decides nothing; only the arguments after it are read.
    // nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.as_slice() {
        [command] if command == "listen" => listen().await,
        [command, address] if command == "dial" => {
            match tokio::time::timeout(DEADLINE, dial(address)).await {
                Ok(outcome) => outcome,
                Err(_) => Err(format!("not done within {DEADLINE:?}")),
            }
        }
        _ => {
            eprintln!("usage: spike listen | spike dial <address the listener printed>");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("failed: {why}");
            ExitCode::FAILURE
        }
    }
}

async fn listen() -> Result<(), String> {
    let mut swarm = build(0xa0)?;
    let tcp = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Tcp(0));
    for addr in [loopback_quic(), tcp] {
        swarm.listen_on(addr).map_err(|e| e.to_string())?;
    }
    let me = *swarm.local_peer_id();
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!(
                    "listening ({}): {}",
                    transport_of(&address),
                    address.with(Protocol::P2p(me))
                );
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => println!(
                "connected over {}: the dialer proved peer ID {peer_id}",
                transport_of(remote_of(&endpoint))
            ),
            SwarmEvent::Behaviour(Event::Sync(sync::Event::Accepted {
                protocol, stream, ..
            })) => {
                println!("protocol: {protocol}");
                tokio::spawn(echo(stream));
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                println!("refused an incoming connection: {error}");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                println!("connection with {peer_id} closed");
            }
            _ => {}
        }
    }
}

/// Echoes the stream back and says how much went through.
async fn echo(stream: Stream) {
    let (read, mut write) = stream.split();
    let mut pieces = Pieces::new(read);
    let mut total = 0usize;
    let end = loop {
        match pieces.next().await {
            Delivery::Bytes(bytes) => {
                total += bytes.len();
                if let Err(e) = write.write_all(bytes).await {
                    println!("echo stopped after {total} bytes: {e}");
                    return;
                }
            }
            Delivery::Ended(end) => break end,
        }
    };
    let _closed = write.close().await;
    println!("echoed {total} bytes, then the stream ended ({end:?})");
}

/// The address to dial and the peer ID it names, from exactly the two forms
/// the listener prints: `/ip4/127.0.0.1/tcp/<port>/p2p/<peer ID>` and
/// `/ip4/127.0.0.1/udp/<port>/quic-v1/p2p/<peer ID>`, the port not 0. This
/// tool contacts nothing else (TM-31).
fn loopback_address(text: &str) -> Result<(Multiaddr, PeerId), String> {
    const FORMS: &str = "/ip4/127.0.0.1/tcp/<port>/p2p/<peer ID> or \
                         /ip4/127.0.0.1/udp/<port>/quic-v1/p2p/<peer ID>";
    let address: Multiaddr = text
        .parse()
        .map_err(|e| format!("not an address ({e}); give {FORMS}"))?;
    let parts: Vec<Protocol<'_>> = address.iter().collect();
    let peer = match parts.as_slice() {
        [Protocol::Ip4(ip), Protocol::Tcp(port), Protocol::P2p(peer)]
        | [Protocol::Ip4(ip), Protocol::Udp(port), Protocol::QuicV1, Protocol::P2p(peer)]
            if *ip == Ipv4Addr::LOCALHOST && *port != 0 =>
        {
            *peer
        }
        _ => return Err(format!("only {FORMS} is dialed")),
    };
    Ok((address, peer))
}

async fn dial(text: &str) -> Result<(), String> {
    let (address, expected) = loopback_address(text)?;
    let mut swarm = build(0xb0)?;
    if is_quic(&address) {
        // libp2p-quic dials from a QUIC listener's endpoint when the swarm
        // has one, and otherwise binds a socket of its own on every address
        // (0.0.0.0, port 0); listening on loopback first keeps this tool on
        // 127.0.0.1 (TM-31).
        swarm
            .listen_on(loopback_quic())
            .map_err(|e| e.to_string())?;
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { .. } => break,
                SwarmEvent::ListenerError { error, .. } => return Err(error.to_string()),
                SwarmEvent::ListenerClosed { reason, .. } => {
                    return Err(format!("the loopback listener closed: {reason:?}"))
                }
                _ => {}
            }
        }
    }
    swarm
        .dial(
            DialOpts::peer_id(expected)
                .addresses(vec![address.clone()])
                .build(),
        )
        .map_err(|e| e.to_string())?;
    let stream = loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } => {
                println!(
                    "connected over {}: the listener proved peer ID {peer_id}{}",
                    transport_of(&address),
                    if peer_id == expected {
                        " (the one in the address)"
                    } else {
                        ""
                    }
                );
                swarm.behaviour_mut().sync().open(peer_id, connection_id);
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error.to_string()),
            SwarmEvent::Behaviour(Event::Sync(sync::Event::Opened {
                protocol, stream, ..
            })) => {
                println!("protocol: {protocol}");
                break stream;
            }
            SwarmEvent::Behaviour(Event::Sync(sync::Event::OpenFailed { error, .. })) => {
                return Err(error.to_string())
            }
            _ => {}
        }
    };
    let sent = pattern(MIB);
    let (read, mut write) = stream.split();
    let writing = async {
        write.write_all(&sent).await?;
        write.close().await
    };
    let receive = async {
        let mut pieces = Pieces::new(read);
        let mut got = Vec::with_capacity(MIB);
        while let Delivery::Bytes(bytes) = pieces.next().await {
            got.extend_from_slice(bytes);
        }
        got
    };
    // The swarm keeps being polled while the bytes go through.
    let transfer = async { futures::join!(writing, receive) };
    futures::pin_mut!(transfer);
    let (sent_ok, echoed) = loop {
        tokio::select! {
            done = &mut transfer => break done,
            _ = swarm.select_next_some() => {}
        }
    };
    sent_ok.map_err(|e| format!("sending failed: {e}"))?;
    if echoed == sent {
        println!("1 MiB echoed in order");
        Ok(())
    } else {
        Err(format!(
            "{} bytes came back, not the 1 MiB sent, in order",
            echoed.len()
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    const PEER: &str = "12D3KooWLbwYSoxYfCSHg726dZA3cCSdzeMG18brSyhACQ2mo24f";

    #[test]
    fn only_the_two_loopback_forms_are_dialed() {
        for good in [
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{PEER}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{PEER}"),
        ] {
            let (address, peer) = loopback_address(&good).unwrap();
            assert_eq!(address.to_string(), good);
            assert_eq!(peer.to_base58(), PEER);
        }
        for bad in [
            format!("/ip4/127.0.0.2/tcp/4001/p2p/{PEER}"),
            format!("/ip4/192.0.2.1/tcp/4001/p2p/{PEER}"),
            format!("/ip4/127.0.0.1/tcp/0/p2p/{PEER}"),
            format!("/ip6/::1/tcp/4001/p2p/{PEER}"),
            format!("/dns4/localhost/tcp/4001/p2p/{PEER}"),
            format!("/ip4/127.0.0.1/udp/4001/p2p/{PEER}"),
            format!("/ip4/127.0.0.1/tcp/4001/ws/p2p/{PEER}"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{PEER}/p2p-circuit"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{PEER}/p2p/{PEER}"),
            "/ip4/127.0.0.1/tcp/4001".to_owned(),
            "not an address".to_owned(),
        ] {
            assert!(loopback_address(&bad).is_err(), "{bad} was accepted");
        }
    }
}
