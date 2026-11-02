// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One connection as the engine keeps it: the protocol's [`Connection`] and
//! the engine's own tables beside it.
//!
//! Every table here is bounded and dropped with the connection in
//! `on_disconnected` (TM-22): `open` holds at most
//! `MAX_OPEN_FOLDERS_PER_CONNECTION` folders (the protocol's bound); the
//! index exchange's state (`sync::ConnSync`) one reply per open folder; and
//! `chunk_requests` at most this side's `max_requests_in_flight`, which the
//! connection enforces before it hands a request over (4.6), each holding
//! only its hash until the chunk is read from storage as it is sent.

use std::collections::{BTreeSet, VecDeque};

use licketysync_keys::{CipherHash, DeviceId, FolderId};
use licketysync_protocol::connection::{Connection, State};

use crate::sync::ConnSync;

/// One connection.
#[derive(Debug)]
pub(crate) struct Conn {
    pub(crate) protocol: Connection,
    /// The peer's device ID once its `DeviceProof` verified: what an issue
    /// naming the peer names besides the handle.
    pub(crate) device: Option<DeviceId>,
    /// This side asked the runtime to close the transport: nothing more is
    /// sent, and `on_disconnected` follows.
    pub(crate) hung_up: bool,
    /// The folders open here.
    pub(crate) open: BTreeSet<FolderId>,
    /// The index exchange's state on this connection.
    pub(crate) sync: ConnSync,
    pub(crate) chunk_requests: VecDeque<(FolderId, CipherHash)>,
    /// The `Event::Closed` outcome was recorded.
    pub(crate) closed_noted: bool,
}

impl Conn {
    pub(crate) fn new(protocol: Connection) -> Self {
        Self {
            protocol,
            device: None,
            hung_up: false,
            open: BTreeSet::new(),
            sync: ConnSync::default(),
            chunk_requests: VecDeque::new(),
            closed_noted: false,
        }
    }

    /// Whether the engine still acts on the connection: once it is closed
    /// (a Close sent or received) or hung up, only its `Closed` outcome is
    /// recorded (the protocol test kit's rule, SEC N6).
    pub(crate) fn reacts(&self) -> bool {
        !self.hung_up && self.protocol.state() != State::Closed
    }

    /// Whether `folder` is open here and the engine acts on the connection.
    pub(crate) fn has_open(&self, folder: &FolderId) -> bool {
        self.reacts() && self.open.contains(folder)
    }
}
