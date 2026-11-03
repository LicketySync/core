// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The stream behaviour of `/licketysync/sync/1`: open a stream to a
//! connected peer, accept the streams a peer opens, and nothing else.
//!
//! Negotiation is multistream-select on each new stream, after the
//! connection's TLS handshake has authenticated both sides: the opener lists
//! the protocol identifiers it speaks, newest first, and the other side
//! takes the first one it also speaks (`protocol.md` 3.1; TM-30's newest
//! common version). Today the list is [`PROTOCOL_ID`] alone.
//!
//! A connection whose peer's identity key is weak (not canonical, or of small
//! order) is refused before it is established ([`identity::check_peer`]).
//!
//! Bounds (TM-22): a connection accepts at most `max_inbound` streams of the
//! protocol over its whole life (the protocol runs one stream per
//! connection, so the node's default is one); once they are used up the
//! handler offers no protocol at all, so a further stream fails its
//! negotiation and is dropped by libp2p. The streams still negotiating are
//! bounded by the swarm's `max_negotiating_inbound_streams`, and the streams
//! open at once by the muxer's stream limit (both in
//! [`crate::limits::Limits`]). A stream's negotiation ends after 10 s,
//! `libp2p-swarm`'s `SubstreamProtocol` default, which is kept: it is not
//! taken from the limits (the commit and the CHANGELOG list it among the
//! library defaults). Requests to open a stream are this side's own
//! and are answered, one event each, when the stream opens, fails or its
//! connection closes.

use core::convert::Infallible;
use core::fmt;
use core::task::{Context, Poll};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use libp2p_core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_core::{transport::PortUse, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::handler::{
    ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
};
use libp2p_swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
    NetworkBehaviour, NotifyHandler, Stream, StreamProtocol, StreamUpgradeError, SubstreamProtocol,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};

use crate::{identity, PROTOCOL_ID};

/// The identifiers this build speaks, newest first.
pub const PROTOCOLS: &[StreamProtocol] = &[StreamProtocol::new(PROTOCOL_ID)];

/// This side's request to open a stream, answered by exactly one
/// [`Event::Opened`] or [`Event::OpenFailed`] with the same id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenId(u64);

/// Why a stream this side asked for did not open.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// The peer speaks none of [`PROTOCOLS`], or accepts no more streams of
    /// it on this connection.
    Unsupported,
    /// Negotiation did not finish in time.
    Timeout,
    /// The stream failed while it was being opened.
    Io(std::io::Error),
    /// The connection closed before the stream opened.
    ConnectionClosed,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("the peer accepts no stream of this protocol"),
            Self::Timeout => f.write_str("the stream's negotiation timed out"),
            Self::Io(e) => write!(f, "the stream failed while opening: {e}"),
            Self::ConnectionClosed => f.write_str("the connection closed before the stream opened"),
        }
    }
}

impl std::error::Error for OpenError {}

/// What the behaviour reports.
#[derive(Debug)]
pub enum Event {
    /// The peer opened a stream and both sides agreed on `protocol`.
    Accepted {
        /// The authenticated peer.
        peer: PeerId,
        /// The connection the stream belongs to.
        connection: ConnectionId,
        /// The identifier both sides agreed on.
        protocol: StreamProtocol,
        /// The stream: a reliable, ordered byte stream in each direction.
        stream: Stream,
    },
    /// A stream this side asked for opened and both sides agreed on
    /// `protocol`.
    Opened {
        /// The request.
        id: OpenId,
        /// The authenticated peer.
        peer: PeerId,
        /// The connection the stream belongs to.
        connection: ConnectionId,
        /// The identifier both sides agreed on.
        protocol: StreamProtocol,
        /// The stream.
        stream: Stream,
    },
    /// A stream this side asked for did not open.
    OpenFailed {
        /// The request.
        id: OpenId,
        /// The peer it was asked of.
        peer: PeerId,
        /// The connection it was asked on.
        connection: ConnectionId,
        /// Why.
        error: OpenError,
    },
}

/// The behaviour. One per swarm.
pub struct Behaviour {
    protocols: Arc<[StreamProtocol]>,
    max_inbound: u32,
    next_id: u64,
    /// Requests not yet answered, by connection, so that a connection that
    /// closes answers its own.
    pending: HashMap<ConnectionId, Vec<OpenId>>,
    /// The established connections and their peers, so that a request for
    /// any other connection is answered at once. At most the node's
    /// established-connection limit.
    connections: HashMap<ConnectionId, PeerId>,
    events: VecDeque<ToSwarm<Event, OpenId>>,
}

impl fmt::Debug for Behaviour {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Behaviour")
            .field("protocols", &self.protocols)
            .field("max_inbound", &self.max_inbound)
            .finish_non_exhaustive()
    }
}

impl Behaviour {
    /// A behaviour that speaks [`PROTOCOLS`] and accepts at most
    /// `max_inbound` streams over each connection's life.
    #[must_use]
    pub fn new(max_inbound: u32) -> Self {
        Self {
            protocols: PROTOCOLS.into(),
            max_inbound,
            next_id: 0,
            pending: HashMap::new(),
            connections: HashMap::new(),
            events: VecDeque::new(),
        }
    }

    /// Asks to open a stream to `peer` on `connection`. The answer is an
    /// [`Event::Opened`] or [`Event::OpenFailed`] with the returned id; for a
    /// connection that is not established to `peer` (closed, unknown, or
    /// another peer's), it is [`OpenError::ConnectionClosed`] at once.
    pub fn open(&mut self, peer: PeerId, connection: ConnectionId) -> OpenId {
        let id = OpenId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        if self.connections.get(&connection) != Some(&peer) {
            self.events
                .push_back(ToSwarm::GenerateEvent(Event::OpenFailed {
                    id,
                    peer,
                    connection,
                    error: OpenError::ConnectionClosed,
                }));
            return id;
        }
        self.pending.entry(connection).or_default().push(id);
        self.events.push_back(ToSwarm::NotifyHandler {
            peer_id: peer,
            handler: NotifyHandler::One(connection),
            event: id,
        });
        id
    }

    fn answered(&mut self, connection: ConnectionId, id: OpenId) {
        if let Some(ids) = self.pending.get_mut(&connection) {
            ids.retain(|pending| *pending != id);
            if ids.is_empty() {
                self.pending.remove(&connection);
            }
        }
    }

    fn handler(&self) -> Handler {
        Handler {
            protocols: Arc::clone(&self.protocols),
            accepted: 0,
            max_inbound: self.max_inbound,
            to_open: VecDeque::new(),
            events: VecDeque::new(),
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        identity::check_peer(&peer).map_err(ConnectionDenied::new)?;
        Ok(self.handler())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        identity::check_peer(&peer).map_err(ConnectionDenied::new)?;
        Ok(self.handler())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionEstablished(established) = event {
            self.connections
                .insert(established.connection_id, established.peer_id);
        }
        if let FromSwarm::ConnectionClosed(closed) = event {
            self.connections.remove(&closed.connection_id);
            for id in self
                .pending
                .remove(&closed.connection_id)
                .unwrap_or_default()
            {
                self.events
                    .push_back(ToSwarm::GenerateEvent(Event::OpenFailed {
                        id,
                        peer: closed.peer_id,
                        connection: closed.connection_id,
                        error: OpenError::ConnectionClosed,
                    }));
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        let event = match event {
            HandlerEvent::Accepted { protocol, stream } => Event::Accepted {
                peer,
                connection,
                protocol,
                stream,
            },
            HandlerEvent::Opened {
                id,
                protocol,
                stream,
            } => {
                self.answered(connection, id);
                Event::Opened {
                    id,
                    peer,
                    connection,
                    protocol,
                    stream,
                }
            }
            HandlerEvent::OpenFailed { id, error } => {
                self.answered(connection, id);
                Event::OpenFailed {
                    id,
                    peer,
                    connection,
                    error,
                }
            }
        };
        self.events.push_back(ToSwarm::GenerateEvent(event));
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Event, THandlerInEvent<Self>>> {
        match self.events.pop_front() {
            Some(event) => Poll::Ready(event),
            None => Poll::Pending,
        }
    }
}

/// What a connection's handler reports to the behaviour.
#[derive(Debug)]
pub enum HandlerEvent {
    /// See [`Event::Accepted`].
    Accepted {
        /// The identifier both sides agreed on.
        protocol: StreamProtocol,
        /// The stream.
        stream: Stream,
    },
    /// See [`Event::Opened`].
    Opened {
        /// The request.
        id: OpenId,
        /// The identifier both sides agreed on.
        protocol: StreamProtocol,
        /// The stream.
        stream: Stream,
    },
    /// See [`Event::OpenFailed`].
    OpenFailed {
        /// The request.
        id: OpenId,
        /// Why.
        error: OpenError,
    },
}

/// The handler of one connection.
pub struct Handler {
    protocols: Arc<[StreamProtocol]>,
    accepted: u32,
    max_inbound: u32,
    /// Requests from the behaviour not yet handed to the connection. Only
    /// this side's own requests are queued here.
    to_open: VecDeque<OpenId>,
    /// Events not yet handed to the behaviour: at most `max_inbound`
    /// accepted streams, and one per request of this side.
    events: VecDeque<HandlerEvent>,
}

impl fmt::Debug for Handler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handler")
            .field("accepted", &self.accepted)
            .field("max_inbound", &self.max_inbound)
            .finish_non_exhaustive()
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = OpenId;
    type ToBehaviour = HandlerEvent;
    type InboundProtocol = Upgrade;
    type OutboundProtocol = Upgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = OpenId;

    fn listen_protocol(&self) -> SubstreamProtocol<Upgrade, ()> {
        // Once the connection's streams are used up, nothing is offered, so
        // multistream-select answers `na` to every proposal.
        let protocols = if self.accepted < self.max_inbound {
            self.protocols.to_vec()
        } else {
            Vec::new()
        };
        SubstreamProtocol::new(Upgrade { protocols }, ())
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Upgrade, OpenId, HandlerEvent>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        if let Some(id) = self.to_open.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    Upgrade {
                        protocols: self.protocols.to_vec(),
                    },
                    id,
                ),
            });
        }
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, id: OpenId) {
        self.to_open.push_back(id);
    }

    fn on_connection_event(&mut self, event: ConnectionEvent<'_, Upgrade, Upgrade, (), OpenId>) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: (stream, protocol),
                info: (),
            }) => {
                // listen_protocol offers nothing past the bound, so this is
                // the backstop: a stream past it is dropped, which resets it.
                if self.accepted < self.max_inbound {
                    self.accepted += 1;
                    self.events
                        .push_back(HandlerEvent::Accepted { protocol, stream });
                }
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: (stream, protocol),
                info: id,
            }) => self.events.push_back(HandlerEvent::Opened {
                id,
                protocol,
                stream,
            }),
            ConnectionEvent::DialUpgradeError(DialUpgradeError { info: id, error }) => {
                let error = match error {
                    StreamUpgradeError::Timeout => OpenError::Timeout,
                    StreamUpgradeError::NegotiationFailed => OpenError::Unsupported,
                    StreamUpgradeError::Io(e) => OpenError::Io(e),
                    StreamUpgradeError::Apply(never) => match never {},
                };
                self.events
                    .push_back(HandlerEvent::OpenFailed { id, error });
            }
            _ => {}
        }
    }
}

/// The stream upgrade: multistream-select over `protocols`, newest first,
/// then the stream as it is.
#[derive(Clone, Debug)]
pub struct Upgrade {
    protocols: Vec<StreamProtocol>,
}

impl UpgradeInfo for Upgrade {
    type Info = StreamProtocol;
    type InfoIter = std::vec::IntoIter<StreamProtocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone().into_iter()
    }
}

impl InboundUpgrade<Stream> for Upgrade {
    type Output = (Stream, StreamProtocol);
    type Error = Infallible;
    type Future = core::future::Ready<Result<Self::Output, Infallible>>;

    fn upgrade_inbound(self, stream: Stream, protocol: StreamProtocol) -> Self::Future {
        core::future::ready(Ok((stream, protocol)))
    }
}

impl OutboundUpgrade<Stream> for Upgrade {
    type Output = (Stream, StreamProtocol);
    type Error = Infallible;
    type Future = core::future::Ready<Result<Self::Output, Infallible>>;

    fn upgrade_outbound(self, stream: Stream, protocol: StreamProtocol) -> Self::Future {
        core::future::ready(Ok((stream, protocol)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test code")]
mod tests {
    use licketysync_keys::device::Libp2pIdentity;
    use licketysync_keys::secret::DeviceSeed;

    use super::*;

    #[test]
    fn speaks_sync_1_only() {
        let names: Vec<&str> = PROTOCOLS.iter().map(StreamProtocol::as_ref).collect();
        assert_eq!(names, ["/licketysync/sync/1"]);
    }

    fn peer(byte: u8) -> PeerId {
        crate::identity::peer_id(&Libp2pIdentity::from_device_seed(&DeviceSeed::from_bytes(
            [byte; 32],
        )))
        .unwrap()
    }

    fn next_event(behaviour: &mut Behaviour) -> Option<ToSwarm<Event, OpenId>> {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        match behaviour.poll(&mut cx) {
            Poll::Ready(event) => Some(event),
            Poll::Pending => None,
        }
    }

    #[test]
    fn offers_nothing_once_the_streams_are_used_up() {
        let behaviour = Behaviour::new(1);
        let mut handler = behaviour.handler();
        let offered = |h: &Handler| h.listen_protocol().upgrade().protocol_info().count();
        assert_eq!(offered(&handler), 1);
        handler.accepted = 1;
        assert_eq!(offered(&handler), 0);
    }

    #[test]
    fn open_on_a_connection_not_established_answers_at_once() {
        let mut behaviour = Behaviour::new(1);
        let unknown = ConnectionId::new_unchecked(7);
        let id = behaviour.open(peer(1), unknown);
        assert!(behaviour.pending.is_empty(), "nothing waits for an answer");
        match next_event(&mut behaviour) {
            Some(ToSwarm::GenerateEvent(Event::OpenFailed {
                id: got,
                connection,
                error: OpenError::ConnectionClosed,
                ..
            })) => assert_eq!((got, connection), (id, unknown)),
            other => panic!("not answered at once: {:?}", other.is_some()),
        }
        assert!(next_event(&mut behaviour).is_none());
        // An established connection's request goes to its handler instead.
        behaviour.connections.insert(unknown, peer(1));
        let _ = behaviour.open(peer(1), unknown);
        assert_eq!(behaviour.pending.len(), 1);
        assert!(matches!(
            next_event(&mut behaviour),
            Some(ToSwarm::NotifyHandler { .. })
        ));
        // Another peer's connection is not this peer's.
        let _ = behaviour.open(peer(2), unknown);
        assert!(matches!(
            next_event(&mut behaviour),
            Some(ToSwarm::GenerateEvent(Event::OpenFailed {
                error: OpenError::ConnectionClosed,
                ..
            }))
        ));
    }

    #[test]
    fn a_peer_with_a_small_order_identity_is_refused_both_ways() {
        let mut point = [0u8; 32];
        point[0] = 1;
        let weak = libp2p_identity::PublicKey::from(
            libp2p_identity::ed25519::PublicKey::try_from_bytes(&point).unwrap(),
        )
        .to_peer_id();
        let addr = Multiaddr::empty();
        let connection = ConnectionId::new_unchecked(1);
        let mut behaviour = Behaviour::new(1);
        let inbound =
            behaviour.handle_established_inbound_connection(connection, weak, &addr, &addr);
        let outbound = behaviour.handle_established_outbound_connection(
            connection,
            weak,
            &addr,
            Endpoint::Dialer,
            PortUse::New,
        );
        for refused in [inbound.err(), outbound.err()] {
            let refused = refused.unwrap();
            assert_eq!(
                refused.downcast_ref::<crate::identity::PeerKeyError>(),
                Some(&crate::identity::PeerKeyError::WeakKey)
            );
        }
        assert!(behaviour
            .handle_established_inbound_connection(connection, peer(1), &addr, &addr)
            .is_ok());
    }
}
