// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One transport connection's protocol state (`protocol.md` sections 3 to 5),
//! as a pure state machine: no I/O, no clock, no randomness of its own.
//!
//! # Driving it
//!
//! | Runtime or engine event | Call |
//! | --- | --- |
//! | `on_connected(peer)` | [`Connection::new`]: sends Hello |
//! | `on_message(peer, bytes)` | [`Connection::receive`] |
//! | `on_timer` for this connection's one timer | [`Connection::wake`] |
//! | the engine wants a folder here | [`Connection::prove`] |
//! | [`Event::RequestDue`] | [`Connection::send_request`] with the index's [`Cursors`] |
//! | [`Event::Serve`], then [`Event::Room`] | [`Connection::send_page`], page by page |
//! | [`Event::Records`], once the index has judged each record | [`Connection::judged`] |
//! | the index accepted records that arrived elsewhere | [`Connection::push`] |
//! | the engine lacks chunks the peer may hold | [`Connection::chunk_position`], [`Connection::request_chunk`], and [`Connection::pass_done`] when no lacking hash lies above the position |
//! | [`Event::ChunkRequested`] | [`Connection::reply_chunk`] |
//! | the engine stored a chunk of an open folder | [`Connection::chunk_stored`] |
//! | [`Event::StatusDue`] | [`Connection::send_status`] |
//! | a send returned [`SendError::WouldBlock`] | [`Connection::want_room`], then wait for [`Event::Room`] |
//! | the device stops or pauses | [`Connection::close`] |
//! | `on_disconnected(peer)` | drop the `Connection` |
//!
//! Every call takes a [`Tick`]: the monotonic time, as a [`Duration`] since
//! the runtime's clock started, and the transport's unsent bytes for the
//! connection (`Transport::unsent`). Calls that sign or open take the device
//! key and the folder credentials ([`Keys`]) and the runtime's randomness;
//! nothing is kept between calls but the connection's own state. Each call
//! returns an [`Output`]: the frames to hand to `Transport::send`, in order
//! and all of them before the next call; the events, in the order they
//! happened; the one deadline for which the engine arms this connection's
//! timer (or cancels it, for `None`); and whether to close the transport. A
//! send that fails returns its [`SendError`] and changes nothing.
//!
//! # The send queue
//!
//! Three rules need the transport's unsent bytes (3.1, 4.5, 4.6): a push that
//! does not fit is dropped and owes an empty push, which waits and is never
//! dropped; a chunk request dispatched while half of `MAX_SEND_QUEUE` is
//! unsent, counting what waits here, is answered `CHUNK_BUSY`; and a request's
//! `REPLY_PAGE_TIMEOUT` starts only when it has left the send queue. So the
//! connection keeps a backlog of the frames it may not hand over yet: a frame
//! is handed over only while the unsent bytes plus the frame stay below
//! `MAX_SEND_QUEUE` (a Close is never held back). The backlog holds only the
//! connection's own small frames and this side's requests, each bounded by a
//! constant: what a peer can make this side send in volume (reply pages,
//! `CHUNK_OK`) and Status are refused with [`SendError::WouldBlock`] instead,
//! so the engine keeps them until [`Event::Room`] (or, for a Status, skips it:
//! the next is due within `STATUS_INTERVAL`). While it waits on the transport
//! the connection asks to be woken every `SEND_POLL_INTERVAL`, since the
//! transport drains between calls without telling anyone.
//!
//! # What it enforces
//!
//! Framing limits, frames dispatched one at a time, nothing after a Close;
//! Hello first, the Hello checks, roles, the transcript, the `DeviceProof`
//! both ways; the `FolderProof` steps with the uniform REJECTED, the proof and
//! open-folder bounds, the `ProofResult` rules; `HELLO_TIMEOUT`,
//! `PROOF_TIMEOUT`, `IDLE_TIMEOUT` and the delivery stall; unknown types and
//! `Unsupported` once per type; messages only for open folders; request IDs,
//! one `IndexRequest` per folder each way, the round and listed requests, the
//! marks and the round owed, the resync intervals, `INDEX_REQUEST_MIN_INTERVAL`,
//! `REPLY_PAGE_TIMEOUT` and its restarts, step 1 of every record and the scope
//! of every reply; chunk requests in flight (at most `MAX_REQUESTS_IN_FLIGHT`),
//! `CHUNK_BUSY` and the backoff, the chunk passes, unsolicited replies and the
//! ciphertext hash of every chunk both ways; Status only for open folders,
//! with `chunks_stored` and the device name. Steps 2 to 7 of a record are the
//! index's ([`crate::record::judge`]).

mod chunks;
mod handshake;
mod index;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use core::fmt;
use core::time::Duration;

use licketysync_keys::device::DeviceKey;
use licketysync_keys::{DeviceId, FolderId, Role, Suite, Tier};

use crate::exchange::ServeRequest;
use crate::features::{COMPRESSION_NONE, HASH_BLAKE3};
use crate::frame::{Frame, FrameDecoder, FrameError, FrameKind, MessageType};
use crate::hello::{check_peer_hello, PeerHello, TranscriptHash};
use crate::limits::{
    CHUNK_BUSY_BACKOFF, CLOSE_FLUSH, DEFAULT_MESSAGE_SIZE, DEFAULT_REQUESTS_IN_FLIGHT,
    HELLO_NONCE_LEN, HELLO_TIMEOUT, IDLE_TIMEOUT, INDEX_REQUEST_MIN_INTERVAL,
    INDEX_RESYNC_INTERVAL, MAX_CHUNK_BUSY_BACKOFF, MAX_MESSAGE_SIZE, MAX_REQUESTS_IN_FLIGHT,
    MAX_SEND_QUEUE, MAX_UNSUPPORTED_TYPES, MIN_MESSAGE_SIZE, PRE_HELLO_LIMIT, PROOF_TIMEOUT,
    REPLY_PAGE_TIMEOUT, SEND_POLL_INTERVAL, STATUS_CHUNKS_INTERVAL, STATUS_INTERVAL,
};
use crate::messages::{
    ChunkReply, ChunkRequest, Close, CloseReason, DeviceProof, FolderProof, FolderStatus, Hello,
    IndexRequest, Message, ProofResult, Status, Unsupported,
};
use crate::parse::{close_without_detail, is_device_name, parse_records_page, Parse};
use crate::proof::FolderCredential;
use crate::record::{Arrival, Judgement, Record};
use crate::rules::{Cause, Outcome};

#[cfg(doc)]
use crate::exchange::Cursors;

pub use index::{Due, MarkKind};

/// The intervals and timeouts a connection keeps. They are the spec's
/// constants ([`Timing::SPEC`]); the simulator may scale them, both sides
/// alike (`protocol.md` section 5, "Time").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// `HELLO_TIMEOUT`.
    pub hello: Duration,
    /// `PROOF_TIMEOUT`.
    pub proof: Duration,
    /// `IDLE_TIMEOUT`.
    pub idle: Duration,
    /// `STATUS_INTERVAL`.
    pub status: Duration,
    /// The least gap between two Statuses sent for a change in
    /// `chunks_stored` alone.
    pub status_chunks: Duration,
    /// `REPLY_PAGE_TIMEOUT`.
    pub reply_page: Duration,
    /// `INDEX_RESYNC_INTERVAL`.
    pub index_resync: Duration,
    /// `INDEX_REQUEST_MIN_INTERVAL`.
    pub index_request_min: Duration,
    /// `CHUNK_BUSY_BACKOFF` at first, and the least wait before the next
    /// chunk pass to a peer that answered `CHUNK_NOT_FOUND`.
    pub busy_backoff: Duration,
    /// The longest the backoff doubles to.
    pub max_busy_backoff: Duration,
    /// How long a sent Close may flush before the close is requested.
    pub close_flush: Duration,
    /// `SEND_POLL_INTERVAL`.
    pub send_poll: Duration,
}

impl Timing {
    /// The constants of `protocol.md`.
    pub const SPEC: Self = Self {
        hello: HELLO_TIMEOUT,
        proof: PROOF_TIMEOUT,
        idle: IDLE_TIMEOUT,
        status: STATUS_INTERVAL,
        status_chunks: STATUS_CHUNKS_INTERVAL,
        reply_page: REPLY_PAGE_TIMEOUT,
        index_resync: INDEX_RESYNC_INTERVAL,
        index_request_min: INDEX_REQUEST_MIN_INTERVAL,
        busy_backoff: CHUNK_BUSY_BACKOFF,
        max_busy_backoff: MAX_CHUNK_BUSY_BACKOFF,
        close_flush: CLOSE_FLUSH,
        send_poll: SEND_POLL_INTERVAL,
    };
}

/// What this side advertises and how it paces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Implemented suites, preferred first.
    pub suites: Vec<Suite>,
    /// Compressions this device can decode; must contain `none`.
    pub compressions: Vec<String>,
    /// Hash algorithms; must contain `blake3`.
    pub hashes: Vec<String>,
    /// Optional features.
    pub features: Vec<String>,
    /// Frames this side accepts, `MIN_MESSAGE_SIZE ..= MAX_MESSAGE_SIZE`.
    pub max_message_size: u32,
    /// Chunk requests this side will hold open, `1 ..= MAX_REQUESTS_IN_FLIGHT`.
    pub max_requests_in_flight: u32,
    /// The `max_records` of this side's own index requests.
    pub max_records: u32,
    /// The Ed25519 public key of this device's libp2p identity (`keys.md` 8.1).
    pub libp2p_identity: [u8; 32],
    /// From phase 1, the peer's transport-authenticated identity key, which
    /// its Hello's `libp2p_identity` must equal; `None` in phase 0 (3.1).
    pub transport_identity: Option<[u8; 32]>,
    /// Self-reported, at most 64 bytes, no control characters; sent in the
    /// first Status after the first folder opens.
    pub device_name: String,
    /// The intervals and timeouts.
    pub timing: Timing,
}

impl Config {
    /// The defaults of major 1 for a device whose libp2p identity key is
    /// `libp2p_identity`.
    #[must_use]
    pub fn new(libp2p_identity: [u8; 32]) -> Self {
        Self {
            suites: vec![Suite::ONE],
            compressions: vec![COMPRESSION_NONE.to_owned()],
            hashes: vec![HASH_BLAKE3.to_owned()],
            features: Vec::new(),
            max_message_size: DEFAULT_MESSAGE_SIZE,
            max_requests_in_flight: DEFAULT_REQUESTS_IN_FLIGHT,
            max_records: 0,
            libp2p_identity,
            transport_identity: None,
            device_name: String::new(),
            timing: Timing::SPEC,
        }
    }
}

/// Why a [`Config`] cannot start a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// `max_message_size` outside `MIN_MESSAGE_SIZE ..= MAX_MESSAGE_SIZE`, or
    /// `max_requests_in_flight` outside `1 ..= MAX_REQUESTS_IN_FLIGHT`.
    Limits,
    /// The Hello would break a check of 3.2 that a peer makes, a bound or a
    /// grammar (the device name's included).
    Hello(CloseReason),
    /// The Hello does not fit `PRE_HELLO_LIMIT`.
    HelloTooLarge,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits => f.write_str("a limit is out of range"),
            Self::Hello(r) => write!(f, "a peer would refuse this Hello ({})", r.name()),
            Self::HelloTooLarge => f.write_str("the Hello does not fit the pre-Hello limit"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The time and the transport's state at a call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tick {
    /// The monotonic time since the runtime's clock started.
    pub now: Duration,
    /// `Transport::unsent` for this connection: the bytes handed over and
    /// not yet put on the wire.
    pub unsent: usize,
}

impl Tick {
    /// A tick at `now` with an empty send queue.
    #[must_use]
    pub const fn at(now: Duration) -> Self {
        Self { now, unsent: 0 }
    }
}

/// The keys a call that signs or opens proofs needs: the device key, and one
/// credential per folder this device holds and has not paused.
#[derive(Clone, Copy, Debug)]
pub struct Keys<'a> {
    /// The device key, whose public key this side's Hello carries.
    pub device: &'a DeviceKey,
    /// The folders this device holds and has not paused.
    pub folders: &'a [FolderCredential],
}

impl Keys<'_> {
    fn folder(&self, id: &FolderId) -> Option<&FolderCredential> {
        self.folders.iter().find(|f| f.folder_id() == *id)
    }
}

/// Which side ended the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// This side sent `Close`.
    Local,
    /// The peer sent `Close`.
    Peer,
}

/// Where the handshake is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// This side's Hello is sent; the peer's has not arrived.
    AwaitingHello,
    /// This side's `DeviceProof` is sent; the peer's has not verified.
    AwaitingDeviceProof,
    /// Both device keys are proven; folders open by proof.
    Established,
    /// Closed (a sent Close may still be flushing); nothing more is processed.
    Closed,
}

/// One record of an `IndexRecords` page, past step 1, with how it came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// The record.
    pub record: Record,
    /// A push, or a reply with whether the writer is in the request's scope:
    /// what [`crate::record::judge`] takes.
    pub arrival: Arrival,
}

/// Which `IndexRecords` arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// An unsolicited page of newly accepted records.
    Push,
    /// A page of the reply to this side's request `request_id`; `last` when
    /// `more` was false.
    Reply {
        /// The request it answers.
        request_id: u32,
        /// The reply's last page.
        last: bool,
    },
}

/// What happened, for the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The peer's `DeviceProof` verified: its device ID is proven.
    Authenticated {
        /// The peer's device ID.
        device_id: DeviceId,
        /// The peer's role on this connection.
        role: Role,
    },
    /// Both sides accepted each other's proof: the folder is open.
    FolderOpened {
        /// The folder.
        folder: FolderId,
        /// The tier the peer reported: shown marked "reported", never relied on.
        peer_tier: Tier,
    },
    /// The peer answered this side's proof REJECTED; the folder is not tried
    /// again on this connection.
    ProofRejected {
        /// The folder.
        folder: FolderId,
    },
    /// An `IndexRequest` of this side is due: send it with
    /// [`Connection::send_request`], which builds it from the index's
    /// cursors.
    RequestDue {
        /// The folder.
        folder: FolderId,
        /// What to ask for.
        due: Due,
    },
    /// A round of this side's range requests with the peer completed.
    RoundCompleted {
        /// The folder.
        folder: FolderId,
    },
    /// The peer's `IndexRequest` may be served now: page by page with
    /// [`crate::exchange::Pager`] and [`crate::exchange::serve`], each page
    /// through [`Connection::send_page`]. It comes when the request arrives,
    /// or, for one that arrived within `INDEX_REQUEST_MIN_INTERVAL` of when
    /// serving the previous one began, from the wake-up at the end of that
    /// interval (delayed, never refused; the connection holds the request
    /// meanwhile).
    Serve {
        /// The folder.
        folder: FolderId,
        /// The request.
        request: ServeRequest,
    },
    /// Records arrived, each past step 1: the index judges them in order
    /// ([`crate::record::judge`]), stopping at the first that closes, and the
    /// engine hands the judgements to [`Connection::judged`].
    Records {
        /// The folder.
        folder: FolderId,
        /// The records.
        records: Vec<Received>,
        /// A push or which page of a reply.
        page: Page,
    },
    /// An empty push arrived: the peer dropped pushes for the folder, and
    /// this side owes itself a round.
    EmptyPush {
        /// The folder.
        folder: FolderId,
    },
    /// The peer asked for a chunk: answer through [`Connection::reply_chunk`]
    /// (the stored blob, or not found), reading the chunk only as it is sent.
    ChunkRequested {
        /// The folder.
        folder: FolderId,
        /// The chunk.
        cipher_hash: licketysync_keys::CipherHash,
    },
    /// A chunk arrived whose ciphertext hash matches; any later failure is
    /// the writer's fault, judged per record that names it.
    Chunk {
        /// The folder.
        folder: FolderId,
        /// The chunk.
        cipher_hash: licketysync_keys::CipherHash,
        /// The stored blob.
        data: Vec<u8>,
    },
    /// The peer does not hold the chunk: ask other peers.
    ChunkNotFound {
        /// The folder.
        folder: FolderId,
        /// The chunk.
        cipher_hash: licketysync_keys::CipherHash,
    },
    /// The peer was busy: no chunk request on this connection until
    /// [`Event::ChunksAllowed`]; ask other peers meanwhile.
    ChunkBusy {
        /// The folder.
        folder: FolderId,
        /// The chunk.
        cipher_hash: licketysync_keys::CipherHash,
    },
    /// The `CHUNK_BUSY_BACKOFF` ended.
    ChunksAllowed,
    /// The next chunk pass to this peer for the folder may start.
    PassAllowed {
        /// The folder.
        folder: FolderId,
    },
    /// A Status is due: send one for the open folders with
    /// [`Connection::send_status`], which fills in `chunks_stored` and the
    /// device name.
    StatusDue,
    /// The send queue has room for the frame the engine asked about with
    /// [`Connection::want_room`]: send what waited.
    Room,
    /// The peer's Status, advisory.
    PeerStatus {
        /// One entry per folder.
        folders: Vec<FolderStatus>,
    },
    /// The peer reported its device name: untrusted text, shown as text only,
    /// marked "reported" (TM-20).
    PeerNamed {
        /// The name.
        device_name: String,
    },
    /// The peer does not know a non-critical type this side sent.
    PeerUnsupported {
        /// The full 16-bit type.
        message_type: u16,
    },
    /// A second frame of an unknown non-critical type: ignored (a log line).
    Ignored {
        /// The full 16-bit type.
        message_type: u16,
    },
    /// The connection ended.
    Closed {
        /// The reason sent or received.
        reason: CloseReason,
        /// Who closed.
        by: Side,
        /// This side's cause, when it closed.
        cause: Option<Cause>,
        /// The peer's `detail`, when the peer closed: untrusted text.
        detail: String,
    },
}

/// What one call produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Encoded frames to hand to `Transport::send`, in order, before the
    /// next call.
    pub frames: Vec<Vec<u8>>,
    /// Events, in the order they happened.
    pub events: Vec<Event>,
    /// When to wake the connection ([`Connection::wake`]); `None`: no timer.
    pub wake_at: Option<Duration>,
    /// Close the transport after sending `frames`.
    pub close: bool,
}

/// Why a send was refused; nothing was sent and nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendError {
    /// The handshake has not finished.
    NotEstablished,
    /// The connection is closed.
    Closed,
    /// A folder it names is not open on this connection (a Status before any
    /// folder opened included).
    FolderNotOpen,
    /// A message a peer would refuse: a field of the wrong size, cursors out
    /// of order or without their digest, a push with `request_id` or `more`
    /// set or without records, a reply page with `more` and no records, more
    /// Status entries than a Status holds.
    Malformed,
    /// The frame would exceed the peer's `max_message_size`.
    TooLarge,
    /// The send queue has no room for this frame of `len` bytes now: keep it
    /// and ask for [`Event::Room`] with [`Connection::want_room`] (a Status
    /// may be skipped instead; the next is due within `STATUS_INTERVAL`).
    WouldBlock {
        /// The frame's length on the wire.
        len: usize,
    },
    /// No `IndexRequest` is due for the folder.
    NotDue,
    /// A reply page for no request of the peer's that may be served now.
    UnknownRequest,
    /// A page with more records than the request's page limit, or a push of
    /// more than `MAX_PAGE_RECORDS`.
    PageTooLong,
    /// The peer's `max_requests_in_flight` chunk requests (at most
    /// `MAX_REQUESTS_IN_FLIGHT`) are outstanding.
    InFlightFull,
    /// A request for this chunk of the folder is already outstanding.
    AlreadyRequested,
    /// Within the `CHUNK_BUSY_BACKOFF`.
    BackingOff,
    /// The chunk pass to this peer waits for its trigger.
    PassWaiting,
    /// A chunk request at or below the pass's position: passes go in
    /// ascending `cipher_hash` order.
    OutOfOrder,
    /// A chunk reply with no chunk request of the peer's to answer.
    Unrequested,
    /// A chunk to send that is not the one requested: its ciphertext hash
    /// differs, or it is empty or longer than the largest stored chunk. It is
    /// corrupt in this device's storage and is never sent (TM-10).
    Corrupt,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::WouldBlock { len } => {
                return write!(f, "the send queue has no room for a frame of {len} bytes");
            }
            Self::NotEstablished => "the handshake has not finished",
            Self::Closed => "the connection is closed",
            Self::FolderNotOpen => "the folder is not open on this connection",
            Self::Malformed => "a peer would refuse this message",
            Self::TooLarge => "the frame exceeds the peer's limit",
            Self::NotDue => "no index request is due",
            Self::UnknownRequest => "no such request may be served",
            Self::PageTooLong => "the page holds more than the page limit",
            Self::InFlightFull => "the peer's chunk-request limit is reached",
            Self::AlreadyRequested => "this chunk is already requested",
            Self::BackingOff => "chunk requests wait for the busy backoff",
            Self::PassWaiting => "the chunk pass waits for its trigger",
            Self::OutOfOrder => "chunk passes go in ascending hash order",
            Self::Unrequested => "no chunk request is waiting for a reply",
            Self::Corrupt => "the chunk is not the one requested",
        };
        f.write_str(text)
    }
}

impl std::error::Error for SendError {}

/// What this side answers a peer's chunk request with
/// ([`Connection::reply_chunk`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkAnswer<'a> {
    /// `CHUNK_OK` with the stored blob (`nonce || ciphertext`), read from
    /// storage as it is sent.
    Ok(&'a [u8]),
    /// `CHUNK_NOT_FOUND`: this device does not hold the chunk for the folder.
    NotFound,
}

/// Why [`Connection::prove`] did nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProveError {
    /// The connection is closed.
    Closed,
    /// The folder is not among the credentials given.
    UnknownFolder,
    /// `MAX_PROOFS_PER_CONNECTION` proofs are already sent or waiting.
    TooMany,
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "the connection is closed",
            Self::UnknownFolder => "no credential for the folder",
            Self::TooMany => "too many folder proofs",
        })
    }
}

impl std::error::Error for ProveError {}

/// A frame waiting in the backlog, and what handing it over means.
#[derive(Debug)]
struct Queued {
    bytes: Vec<u8>,
    tag: Tag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    None,
    /// This side's outstanding `IndexRequest` for the folder.
    Request(FolderId),
    /// The empty push owed for the folder.
    EmptyPush(FolderId),
    /// A reply to one of the peer's chunk requests.
    ChunkReply,
}

/// One folder's state on this connection.
#[derive(Debug, Default)]
struct Folder {
    /// This side sent its `FolderProof`.
    proof_sent: bool,
    /// The peer answered it ACCEPTED.
    ours_accepted: bool,
    /// This side answered the peer's proof ACCEPTED, with the tier reported.
    peer_tier: Option<Tier>,
    /// The folder's verifier, from the credential that proved or verified.
    verifier: Option<licketysync_keys::FolderVerifier>,
    /// Both accepted: the exchange state.
    open: Option<Box<index::Exchange>>,
}

/// One transport connection's protocol state. See the module documentation.
#[derive(Debug)]
pub struct Connection {
    config: Config,
    hello: Hello,
    hello_frame: Frame,
    device_public: licketysync_keys::device::DevicePublicKey,
    decoder: FrameDecoder,
    state: State,
    peer: Option<PeerHello>,
    role: Option<Role>,
    th: Option<TranscriptHash>,
    folders: BTreeMap<FolderId, Folder>,
    /// Folders the engine asked to prove before the handshake finished.
    pending: Vec<FolderId>,
    /// Hint (peer's role) to folder, for every folder held, built once.
    hint_cache: Option<BTreeMap<[u8; 32], FolderId>>,
    /// This side's proofs by hint, and whether each has been answered.
    our_hints: BTreeMap<[u8; 32], (FolderId, bool)>,
    /// Hints of the peer's proofs received.
    received_hints: BTreeSet<[u8; 32]>,
    proofs_sent: usize,
    accepted: usize,
    opened_any: bool,
    /// Non-critical types answered with Unsupported: a 4 KiB bitset.
    unsupported: Box<[u64; MAX_UNSUPPORTED_TYPES / 64]>,
    // Index exchange, connection-wide.
    next_request_id: u32,
    ours_by_id: BTreeMap<u32, FolderId>,
    theirs_by_id: BTreeMap<u32, FolderId>,
    last_progress: Duration,
    // Chunks, connection-wide.
    chunks: chunks::Chunks,
    // Status.
    name_sent: Option<String>,
    next_status: Option<Duration>,
    last_status_sent: Option<Duration>,
    status_chunks_due: Option<Duration>,
    // The send queue and the clocks.
    /// The engine waits for room for a frame of this many bytes
    /// ([`Connection::want_room`]): [`Event::Room`] once there is.
    want_room: Option<usize>,
    backlog: VecDeque<Queued>,
    backlog_bytes: usize,
    handed: u64,
    unsent: usize,
    /// Bytes handed over minus the transport's unsent bytes, as last seen.
    delivered: i128,
    last_growth: Duration,
    now: Duration,
    last_frame: Duration,
    hello_deadline: Option<Duration>,
    proof_deadline: Option<Duration>,
    flush_deadline: Option<Duration>,
}

const fn close_reason(cause: Cause) -> CloseReason {
    match cause.outcome() {
        Outcome::Close(reason) => reason,
        _ => CloseReason::ProtocolError,
    }
}

impl Connection {
    /// Starts a connection: builds this side's Hello with a fresh 32-byte
    /// nonce, checks that a peer would accept it, sends it, and arms
    /// `HELLO_TIMEOUT` and `IDLE_TIMEOUT`.
    ///
    /// # Errors
    /// [`ConfigError`] when the configuration could not produce a Hello a peer
    /// would accept.
    pub fn new(
        device: &DeviceKey,
        config: Config,
        rng: &mut licketysync_keys::RandomFill<'_>,
        tick: Tick,
    ) -> Result<(Self, Output), ConfigError> {
        if !(MIN_MESSAGE_SIZE..=MAX_MESSAGE_SIZE).contains(&config.max_message_size)
            || !(1..=MAX_REQUESTS_IN_FLIGHT).contains(&config.max_requests_in_flight)
        {
            return Err(ConfigError::Limits);
        }
        if !is_device_name(&config.device_name) {
            return Err(ConfigError::Hello(CloseReason::ProtocolError));
        }
        let mut nonce = [0u8; HELLO_NONCE_LEN];
        rng(&mut nonce);
        let hello = Hello {
            device_public_key: device.public().to_hello().to_vec(),
            suites: config.suites.iter().map(|s| s.to_wire()).collect(),
            compressions: config.compressions.clone(),
            hashes: config.hashes.clone(),
            features: config.features.clone(),
            max_message_size: config.max_message_size,
            max_requests_in_flight: config.max_requests_in_flight,
            nonce: nonce.to_vec(),
            libp2p_identity: config.libp2p_identity.to_vec(),
        };
        let hello_frame = Message::Hello(Box::new(hello.clone()))
            .to_frame()
            .map_err(|_| ConfigError::HelloTooLarge)?;
        if hello_frame.length() > PRE_HELLO_LIMIT {
            return Err(ConfigError::HelloTooLarge);
        }
        // This side never sends what it would refuse.
        let reparsed = Hello::parse(hello_frame.body())
            .map_err(|_| ConfigError::Hello(CloseReason::ProtocolError))?;
        check_peer_hello(reparsed, &hello_frame, &config.suites, None)
            .map_err(ConfigError::Hello)?;
        let now = tick.now;
        let mut connection = Self {
            decoder: FrameDecoder::new(PRE_HELLO_LIMIT),
            hello,
            device_public: *device.public(),
            state: State::AwaitingHello,
            peer: None,
            role: None,
            th: None,
            folders: BTreeMap::new(),
            pending: Vec::new(),
            hint_cache: None,
            our_hints: BTreeMap::new(),
            received_hints: BTreeSet::new(),
            proofs_sent: 0,
            accepted: 0,
            opened_any: false,
            unsupported: Box::new([0; MAX_UNSUPPORTED_TYPES / 64]),
            next_request_id: 0,
            ours_by_id: BTreeMap::new(),
            theirs_by_id: BTreeMap::new(),
            last_progress: now,
            chunks: chunks::Chunks::new(config.timing.busy_backoff),
            name_sent: None,
            next_status: None,
            last_status_sent: None,
            status_chunks_due: None,
            want_room: None,
            backlog: VecDeque::new(),
            backlog_bytes: 0,
            handed: 0,
            unsent: tick.unsent,
            delivered: 0 - i128::try_from(tick.unsent).unwrap_or(0),
            last_growth: now,
            now,
            last_frame: now,
            hello_deadline: Some(now.saturating_add(config.timing.hello)),
            proof_deadline: None,
            flush_deadline: None,
            hello_frame,
            config,
        };
        let mut out = Output::default();
        let frame = connection.hello_frame.encode();
        connection.enqueue(frame, Tag::None, &mut out);
        connection.finish(&mut out);
        Ok((connection, out))
    }

    /// Where the handshake is.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// This side's role, once the peer's Hello has arrived.
    #[must_use]
    pub const fn role(&self) -> Option<Role> {
        self.role
    }

    /// The transcript hash, once the peer's Hello has arrived.
    #[must_use]
    pub const fn transcript_hash(&self) -> Option<&TranscriptHash> {
        self.th.as_ref()
    }

    /// This side's Hello as sent.
    #[must_use]
    pub const fn local_hello(&self) -> &Hello {
        &self.hello
    }

    /// The peer's Hello, once it has passed the checks.
    #[must_use]
    pub const fn peer(&self) -> Option<&PeerHello> {
        self.peer.as_ref()
    }

    /// The frame limit in force for the next frame received.
    #[must_use]
    pub const fn receive_limit(&self) -> u32 {
        self.decoder.limit()
    }

    /// The largest frame this side may send: the peer's advertised
    /// `max_message_size` (at most `MAX_MESSAGE_SIZE`) once its Hello has
    /// arrived, `PRE_HELLO_LIMIT` before. Pagers take this.
    #[must_use]
    pub fn peer_max_message_size(&self) -> u32 {
        self.peer
            .as_ref()
            .map_or(PRE_HELLO_LIMIT, |p| p.max_message_size)
    }

    /// Whether `folder` is open on this connection.
    #[must_use]
    pub fn is_open(&self, folder: &FolderId) -> bool {
        self.folders.get(folder).is_some_and(|f| f.open.is_some())
    }

    /// The folders open on this connection.
    pub fn open_folders(&self) -> impl Iterator<Item = &FolderId> {
        self.folders
            .iter()
            .filter(|(_, f)| f.open.is_some())
            .map(|(id, _)| id)
    }

    /// The bytes waiting in this connection's backlog.
    #[must_use]
    pub const fn backlog(&self) -> usize {
        self.backlog_bytes
    }

    /// Whether a frame of `len` bytes would be handed to the transport at
    /// once: the unsent bytes (the larger of `tick.unsent` and what this side
    /// has handed over since, which the transport may not yet report), plus
    /// the backlog, plus the frame, stay below `MAX_SEND_QUEUE`. The sends
    /// that refuse with [`SendError::WouldBlock`] refuse exactly when this
    /// does not hold.
    #[must_use]
    pub fn has_room(&self, tick: Tick, len: usize) -> bool {
        tick.unsent
            .max(self.unsent)
            .saturating_add(self.backlog_bytes)
            .saturating_add(len)
            < MAX_SEND_QUEUE
    }

    /// Room for `len` bytes as of the last reading of the transport.
    fn room_for(&self, len: usize) -> bool {
        self.unsent
            .saturating_add(self.backlog_bytes)
            .saturating_add(len)
            < MAX_SEND_QUEUE
    }

    /// The engine waits to send a frame of `len` bytes (after
    /// [`SendError::WouldBlock`], or before it builds a big frame):
    /// [`Event::Room`] comes once a frame of that length would be handed over
    /// at once, in this call's output when it already would, and otherwise
    /// from a later call or wake-up (the connection asks to be woken every
    /// `SEND_POLL_INTERVAL` meanwhile). One wait at a time: several calls wait
    /// for the smallest length asked, and the engine retries everything that
    /// waits on the event. A length over the peer's frame limit waits for that
    /// limit, the largest frame a send can take.
    pub fn want_room(&mut self, tick: Tick, len: usize) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if self.state == State::Established {
            let limit = usize::try_from(self.peer_max_message_size())
                .unwrap_or(usize::MAX)
                .saturating_add(4);
            let len = len.min(limit);
            self.want_room = Some(self.want_room.map_or(len, |w| w.min(len)));
        }
        self.finish(&mut out);
        out
    }

    /// Forgets the per-connection hint table, so that a folder this device
    /// joined since the first `FolderProof` arrived can be matched.
    pub fn refresh_folders(&mut self) {
        self.hint_cache = None;
    }

    /// Changes the device name; the next Status this side sends carries it.
    ///
    /// # Errors
    /// [`ConfigError::Hello`] for more than 64 bytes or a control character.
    pub fn set_device_name(&mut self, name: String) -> Result<(), ConfigError> {
        if !is_device_name(&name) {
            return Err(ConfigError::Hello(CloseReason::ProtocolError));
        }
        self.config.device_name = name;
        Ok(())
    }

    /// Bytes arrived from the peer, in any chunk boundaries: frames are
    /// decoded and dispatched one at a time, and nothing after a Close is.
    pub fn receive(
        &mut self,
        keys: &Keys<'_>,
        rng: &mut licketysync_keys::RandomFill<'_>,
        tick: Tick,
        bytes: &[u8],
    ) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let mut input = bytes;
        while self.state != State::Closed && !input.is_empty() {
            match self.decoder.next_frame(&mut input) {
                Ok(Some(frame)) => {
                    self.last_frame = self.now;
                    self.on_frame(keys, rng, &frame, &mut out);
                }
                Ok(None) => break,
                Err(e) => {
                    let cause = match e {
                        FrameError::TooLarge { .. } => Cause::FrameOverLimit,
                        _ => Cause::Malformed,
                    };
                    self.close_with(e.close_reason(), Some(cause), &mut out);
                }
            }
        }
        self.finish(&mut out);
        out
    }

    fn on_frame(
        &mut self,
        keys: &Keys<'_>,
        rng: &mut licketysync_keys::RandomFill<'_>,
        frame: &Frame,
        out: &mut Output,
    ) {
        let established = self.state == State::Established;
        let message_type = match frame.kind() {
            FrameKind::Known(t) => t,
            FrameKind::UnknownCritical(_) if established => {
                return self.fail(Cause::UnknownCriticalType, out);
            }
            FrameKind::UnknownNonCritical(t) if established => {
                return self.on_unknown(t, out);
            }
            // Before the peer's DeviceProof verified, any other frame closes
            // (3.2 takes precedence over Unsupported).
            FrameKind::UnknownCritical(_) | FrameKind::UnknownNonCritical(_) => {
                return self.fail(Cause::Malformed, out);
            }
        };
        let allowed = match self.state {
            State::AwaitingHello => matches!(message_type, MessageType::Hello | MessageType::Close),
            State::AwaitingDeviceProof => {
                matches!(message_type, MessageType::DeviceProof | MessageType::Close)
            }
            State::Established => {
                !matches!(message_type, MessageType::Hello | MessageType::DeviceProof)
            }
            State::Closed => false,
        };
        if !allowed {
            return self.fail(Cause::Malformed, out);
        }
        let body = frame.body();
        match message_type {
            MessageType::Hello => {
                if let Some(m) = self.parsed::<Hello>(body, out) {
                    self.on_hello(keys, m, frame, out);
                }
            }
            // A Close whose detail breaks its grammar is not shown; its
            // reason is still reported, and the connection closes (4.2).
            MessageType::Close => {
                let close = Close::parse(body).unwrap_or_else(|_| close_without_detail(body));
                self.on_close(close, out);
            }
            MessageType::DeviceProof => {
                if let Some(m) = self.parsed::<DeviceProof>(body, out) {
                    self.on_device_proof(keys, rng, &m, out);
                }
            }
            MessageType::FolderProof => {
                if let Some(m) = self.parsed::<FolderProof>(body, out) {
                    self.on_folder_proof(keys, rng, &m, out);
                }
            }
            MessageType::ProofResult => {
                if let Some(m) = self.parsed::<ProofResult>(body, out) {
                    self.on_proof_result(&m, out);
                }
            }
            MessageType::Unsupported => {
                if let Some(u) = self.parsed::<Unsupported>(body, out) {
                    out.events.push(Event::PeerUnsupported {
                        message_type: u16::try_from(u.message_type).unwrap_or(u16::MAX),
                    });
                }
            }
            MessageType::IndexRequest => {
                if let Some(m) = self.parsed::<IndexRequest>(body, out) {
                    self.on_index_request(&m, out);
                }
            }
            // Each embedded record is decoded once, here (N13).
            MessageType::IndexRecords => match parse_records_page(body) {
                Ok(page) => self.on_index_records(page, out),
                Err(_) => self.fail(Cause::Malformed, out),
            },
            MessageType::ChunkRequest => {
                if let Some(m) = self.parsed::<ChunkRequest>(body, out) {
                    self.on_chunk_request(&m, out);
                }
            }
            MessageType::ChunkReply => {
                if let Some(m) = self.parsed::<ChunkReply>(body, out) {
                    self.on_chunk_reply(m, out);
                }
            }
            MessageType::Status => {
                if let Some(m) = self.parsed::<Status>(body, out) {
                    self.on_status(m, out);
                }
            }
        }
    }

    /// A body parsed under its bounds, or the connection closed as malformed.
    fn parsed<T: Parse>(&mut self, body: &[u8], out: &mut Output) -> Option<T> {
        let parsed = T::parse(body).ok();
        if parsed.is_none() {
            self.fail(Cause::Malformed, out);
        }
        parsed
    }

    /// An unknown non-critical type, once established: `Unsupported` the
    /// first time per type, then ignored with a log line.
    fn on_unknown(&mut self, message_type: u16, out: &mut Output) {
        let n = usize::from(message_type & 0x7fff);
        let (word, bit) = (n / 64, 1u64 << (n % 64));
        let Some(slot) = self.unsupported.get_mut(word) else {
            return;
        };
        if *slot & bit != 0 {
            out.events.push(Event::Ignored { message_type });
            return;
        }
        *slot |= bit;
        self.send_own(
            &Message::Unsupported(Unsupported {
                message_type: u32::from(message_type),
            }),
            out,
        );
    }

    /// One of this connection's deadlines may have passed; the engine calls
    /// this when the timer from [`Output::wake_at`] fires (early or late
    /// alike: each deadline is checked against `tick.now`).
    pub fn wake(&mut self, tick: Tick) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let now = self.now;
        if self.flush_deadline.is_some_and(|d| now >= d) {
            self.flush_deadline = None;
            out.close = true;
        }
        if self.state != State::Closed {
            self.check_timeouts(&mut out);
        }
        if self.state == State::Established {
            self.wake_exchange(&mut out);
            self.wake_chunks(&mut out);
            self.wake_status(&mut out);
        }
        self.finish(&mut out);
        out
    }

    /// The deadlines that close: Hello, proof, idle, the delivery stall and
    /// every reply page.
    fn check_timeouts(&mut self, out: &mut Output) {
        let now = self.now;
        let t = self.config.timing;
        let timeout = if self.hello_deadline.is_some_and(|d| now >= d) {
            Some(Cause::HelloTimeout)
        } else if self.proof_deadline.is_some_and(|d| now >= d) {
            Some(Cause::ProofTimeout)
        } else if now >= self.last_frame.saturating_add(t.idle)
            || (self.unsent > 0 && now >= self.last_growth.saturating_add(t.idle))
        {
            Some(Cause::IdleTimeout)
        } else if self.reply_deadline().is_some_and(|d| now >= d) {
            Some(Cause::ReplyPageTimeout)
        } else {
            None
        };
        if let Some(cause) = timeout {
            self.fail(cause, out);
        }
    }

    /// The index judged the records of one [`Event::Records`] page of
    /// `folder`, in order: for each, the writer's device ID and what
    /// [`crate::record::judge`] returned, up to and including the first
    /// error, after which the engine stores nothing more of the page. A gap on
    /// a push marks the writer for a listed request (4.5); a push that brought
    /// at least one record to store restarts `REPLY_PAGE_TIMEOUT` (a reply's
    /// pages restarted it as they arrived); and a cause whose outcome is a
    /// close (a forged record, a sender violation) closes the connection.
    pub fn judged(
        &mut self,
        tick: Tick,
        folder: FolderId,
        page: Page,
        results: &[(DeviceId, Result<Judgement, Cause>)],
    ) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        let mut stored = false;
        for (writer, result) in results {
            if self.state == State::Closed {
                break;
            }
            match result {
                Ok(Judgement::PushGap) => {
                    self.mark_writer(folder, *writer, MarkKind::Gap, &mut out);
                }
                Ok(judgement) => stored |= judgement.stores(),
                Err(cause) if cause.closes() => self.fail(*cause, &mut out),
                Err(_) => {}
            }
        }
        if stored && page == Page::Push && self.state == State::Established {
            self.last_progress = self.now;
        }
        self.finish(&mut out);
        out
    }

    /// Closes the connection from this side with `reason` (usually
    /// `SHUTDOWN`): the Close frame, then the flush deadline.
    pub fn close(&mut self, tick: Tick, reason: CloseReason) -> Output {
        let mut out = Output::default();
        self.observe(tick, &mut out);
        self.close_with(reason, None, &mut out);
        self.finish(&mut out);
        out
    }

    /// Reads the tick: the time, and how far the transport has drained,
    /// which starts the reply deadline of requests that left the queue and
    /// marks delivery progress; then hands over what now has room.
    fn observe(&mut self, tick: Tick, out: &mut Output) {
        self.now = self.now.max(tick.now);
        self.unsent = tick.unsent;
        let delivered = i128::from(self.handed) - i128::try_from(tick.unsent).unwrap_or(i128::MAX);
        if delivered > self.delivered || tick.unsent == 0 {
            self.last_growth = self.now;
        }
        self.delivered = delivered;
        self.note_departures();
        self.drain(out);
    }

    /// Queues a frame and hands over what fits.
    fn enqueue(&mut self, bytes: Vec<u8>, tag: Tag, out: &mut Output) {
        self.backlog_bytes = self.backlog_bytes.saturating_add(bytes.len());
        self.backlog.push_back(Queued { bytes, tag });
        self.drain(out);
    }

    /// Hands frames from the backlog to the transport, in order, while each
    /// keeps the unsent bytes below `MAX_SEND_QUEUE`.
    fn drain(&mut self, out: &mut Output) {
        while let Some(front) = self.backlog.front() {
            if self.unsent.saturating_add(front.bytes.len()) >= MAX_SEND_QUEUE {
                break;
            }
            let Some(q) = self.backlog.pop_front() else {
                break;
            };
            let len = q.bytes.len();
            self.backlog_bytes = self.backlog_bytes.saturating_sub(len);
            self.unsent = self.unsent.saturating_add(len);
            self.handed = self
                .handed
                .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
            self.last_frame = self.now;
            match q.tag {
                Tag::None => {}
                Tag::Request(folder) => self.request_handed(folder),
                Tag::EmptyPush(folder) => self.empty_push_handed(folder),
                Tag::ChunkReply => self.chunk_reply_handed(),
            }
            out.frames.push(q.bytes);
        }
    }

    /// Encodes and queues one of the connection's own messages, which always
    /// fit the peer's limit.
    fn send_own(&mut self, message: &Message, out: &mut Output) {
        if let Ok(frame) = message.to_frame() {
            if frame.fits(self.peer_max_message_size()) {
                self.enqueue(frame.encode(), Tag::None, out);
            }
        }
    }

    /// Hands over what fits, announces room the engine waits for, and sets
    /// the next wake-up.
    fn finish(&mut self, out: &mut Output) {
        self.drain(out);
        if self.want_room.is_some_and(|len| self.room_for(len)) {
            self.want_room = None;
            out.events.push(Event::Room);
        }
        out.wake_at = self.next_wake();
    }

    fn next_wake(&self) -> Option<Duration> {
        if self.state == State::Closed {
            return self.flush_deadline;
        }
        let t = self.config.timing;
        let polling =
            !self.backlog.is_empty() || self.want_room.is_some() || self.awaiting_departure();
        [
            self.hello_deadline,
            self.proof_deadline,
            Some(self.last_frame.saturating_add(t.idle)),
            (self.unsent > 0).then(|| self.last_growth.saturating_add(t.idle)),
            self.reply_deadline(),
            self.exchange_wake(),
            self.chunks_wake(),
            self.status_wake(),
            polling.then(|| self.now.saturating_add(t.send_poll)),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn fail(&mut self, cause: Cause, out: &mut Output) {
        self.close_with(close_reason(cause), Some(cause), out);
    }

    fn close_with(&mut self, reason: CloseReason, cause: Option<Cause>, out: &mut Output) {
        if self.state == State::Closed {
            return;
        }
        let close = Message::Close(Close {
            reason: reason.as_u32(),
            detail: String::new(),
        });
        self.finish_tables();
        // A Close is never held back by the send queue (3.1).
        if let Ok(frame) = close.to_frame() {
            out.frames.push(frame.encode());
        }
        self.flush_deadline = Some(self.now.saturating_add(self.config.timing.close_flush));
        out.events.push(Event::Closed {
            reason,
            by: Side::Local,
            cause,
            detail: String::new(),
        });
    }

    fn on_close(&mut self, close: Close, out: &mut Output) {
        self.finish_tables();
        out.close = true;
        out.events.push(Event::Closed {
            reason: CloseReason::from_u32(close.reason),
            by: Side::Peer,
            cause: None,
            detail: close.detail,
        });
    }

    /// Stops processing and frees every per-connection table (4.2).
    fn finish_tables(&mut self) {
        self.state = State::Closed;
        self.decoder.clear();
        self.folders.clear();
        self.pending.clear();
        self.hint_cache = None;
        self.our_hints.clear();
        self.received_hints.clear();
        self.ours_by_id.clear();
        self.theirs_by_id.clear();
        self.chunks = chunks::Chunks::new(self.config.timing.busy_backoff);
        self.backlog.clear();
        self.backlog_bytes = 0;
        self.want_room = None;
        self.hello_deadline = None;
        self.proof_deadline = None;
        self.next_status = None;
        self.status_chunks_due = None;
    }
}

/// Folders that are open, by ID, mutable.
fn open_mut<'a>(
    folders: &'a mut BTreeMap<FolderId, Folder>,
    id: &FolderId,
) -> Option<&'a mut index::Exchange> {
    folders.get_mut(id).and_then(|f| f.open.as_deref_mut())
}
