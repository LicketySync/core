// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The runtime surface the engine runs on: time, timers, transport, storage and
//! randomness as traits, and the event-driven [`Peer`] a runtime drives.
//!
//! Design. The engine never performs I/O and never reads a clock of its own. A
//! runtime (the daemon in production, `licketysync-sim` in tests) owns the
//! clocks, the network and the disk and calls the engine through the six
//! handlers of [`Peer`]: started, a message arrived, a timer fired, a peer
//! connected or disconnected, stopping. Each handler receives a [`Context`]
//! through which the peer reads the current [`Instant`] and the device's wall
//! clock, sends bytes, arms or cancels a timer, reads and writes its [`Storage`]
//! and draws randomness; it never holds a reference to the context between
//! calls. Everything the engine does is thus a function of the sequence of calls
//! it receives, which is what lets the simulator replay a run from its seed
//! alone (plan, Tests: "time and network go through traits"). Storage has
//! transaction semantics on purpose: writes are staged and become durable only
//! at [`Storage::commit`], so a crash mid-write is a precise, testable event
//! rather than an accident of timing. The transport is a reliable, ordered
//! byte stream per connection (protocol spec, 3.1): the engine frames its own
//! messages, and loss shows itself only as the connection ending, so the
//! engine's recovery logic lives in one place, [`Peer::on_disconnected`]. Every
//! promise here is about what one side sees; nothing orders what two machines
//! see against each other. There is no async and no threading here; the
//! runtime decides how handlers are scheduled and must call them one at a time.
//! Every byte that arrives in [`Peer::on_message`] came from another machine
//! and is untrusted.

use core::fmt;
use core::time::Duration;

/// A point on the runtime's monotonic clock, in nanoseconds since the clock
/// started. It is not wall time: it says how much time has passed, never the
/// date (that is [`Clock::wall_time`], with its own rules), and two runtimes'
/// instants are not comparable. An `Instant` never survives a restart: a
/// restarted process's clock starts afresh, so one kept from before (in
/// storage, say) means nothing after it; keep wall time or a duration instead.
/// `u64` nanoseconds last 584 years, so arithmetic that would overflow is a
/// bug, and the checked and saturating forms below make the caller say which
/// it wants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// The start of the clock.
    pub const ZERO: Self = Self { nanos: 0 };

    /// The instant `nanos` nanoseconds after the clock started.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// The instant `millis` milliseconds after the clock started, saturating.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self {
            nanos: millis.saturating_mul(1_000_000),
        }
    }

    /// The instant `secs` seconds after the clock started, saturating.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self {
            nanos: secs.saturating_mul(1_000_000_000),
        }
    }

    /// Nanoseconds since the clock started.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.nanos
    }

    /// Whole seconds since the clock started, rounded down.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.nanos / 1_000_000_000
    }

    /// `self + d`, or `None` when the sum does not fit (also when `d` alone does
    /// not fit in 64 bits of nanoseconds).
    #[must_use]
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        let d = u64::try_from(d.as_nanos()).ok()?;
        self.nanos.checked_add(d).map(Self::from_nanos)
    }

    /// `self + d`, clamped to the largest representable instant.
    #[must_use]
    pub fn saturating_add(self, d: Duration) -> Self {
        self.checked_add(d).unwrap_or(Self { nanos: u64::MAX })
    }

    /// `self - d`, or `None` when that would be before the clock started.
    #[must_use]
    pub fn checked_sub(self, d: Duration) -> Option<Self> {
        let d = u64::try_from(d.as_nanos()).ok()?;
        self.nanos.checked_sub(d).map(Self::from_nanos)
    }

    /// The time from `earlier` to `self`, or `None` when `earlier` is later.
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        self.nanos
            .checked_sub(earlier.nanos)
            .map(Duration::from_nanos)
    }

    /// The time from `earlier` to `self`, or zero when `earlier` is later.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.duration_since(earlier).unwrap_or(Duration::ZERO)
    }
}

impl fmt::Display for Instant {
    /// Seconds with all nine fractional digits, such as `1.250000000s`, so that
    /// two traces that differ by a nanosecond read differently.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.nanos / 1_000_000_000;
        let frac = self.nanos % 1_000_000_000;
        f.pad(&format!("{secs}.{frac:09}s"))
    }
}

/// A handle the runtime assigns to a remote peer for the life of this process.
/// It names where to send bytes; it is not an identity. Who is behind it is
/// established by the protocol's handshake, and the engine must not assume the
/// same number names the same device after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(u64);

impl PeerId {
    /// Wraps a runtime-chosen number.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The number the runtime chose.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PeerId {
    /// `p7`; honours width and alignment, so columns line up in traces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("p{}", self.0))
    }
}

/// A timer the peer chose a number for. Arming a timer that is already armed
/// replaces its deadline, so a peer can keep one id per purpose (a gossip tick,
/// a retry) without bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId(u64);

impl TimerId {
    /// Wraps a peer-chosen number.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The number the peer chose.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TimerId {
    /// `t3`; honours width and alignment.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("t{}", self.0))
    }
}

/// Why a storage operation did not happen. The store is unchanged after an
/// error: a failed `put` staged nothing and a failed `commit` left the staged
/// writes staged, so the peer may retry or roll back.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageError {
    /// The disk is full: the store cannot take the bytes.
    Full,
    /// Any other failure, described for the Issues list.
    Io(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("storage is full"),
            Self::Io(why) => write!(f, "storage failed: {why}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// The most bytes one [`Peer::on_message`] call hands over. A runtime may hand
/// over fewer, split anywhere: chunk boundaries carry no meaning.
pub const MAX_CHUNK: usize = 64 * 1024;

/// The most bytes a connection's unsent queue may hold: what this side has
/// written with [`Transport::send`] and the runtime has not yet handed to the
/// network ([`Transport::unsent`]). A runtime may end a connection whose
/// unsent queue would pass this, as if the network had cut it. It is only
/// where the runtime cuts, not a budget to fill: the engine paces to a budget
/// of its own, far below it, writing its next frame (a chunk reply, a page of
/// records) only while `unsent` plus that frame stays within that budget.
/// Nothing tells the engine that the queue has drained, so while it is over
/// budget the engine arms a timer and reads `unsent` again when it fires.
/// Every frame is itself bounded by the peer's `max_message_size` (protocol
/// spec, 2).
pub const MAX_SEND_QUEUE: usize = 128 * 1024 * 1024;

/// Why bytes were not handed to the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendError {
    /// This side has no open connection to that peer as far as it knows. The
    /// cases, all of them: it has not heard [`Peer::on_connected`] for the
    /// peer (always so for its own id); it has heard [`Peer::on_disconnected`]
    /// for it since; or the same handler has already called
    /// [`Transport::close`] for it. A peer learns of connections only through
    /// those calls, so this is a bug in the caller, never routine. Inside a
    /// connection as this side knows it, a send is never refused, even when
    /// the connection has in fact already ended.
    NotConnected,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConnected => f.write_str("peer is not connected"),
        }
    }
}

impl std::error::Error for SendError {}

/// The two clocks. The engine reads time only here.
pub trait Clock {
    /// The current instant on this runtime's monotonic clock: for timeouts,
    /// intervals and knowing how long ago something happened in this process.
    fn now(&self) -> Instant;

    /// The wall clock as this device believes it: seconds since the Unix epoch.
    /// It may be wrong by any amount, may jump forwards or backwards between two
    /// readings, and differs between devices. Its one use is expiry: whether a
    /// key, grant or proof is still within its validity window, and whether a
    /// suspension has ended, as this device sees the date (protocol spec, 3.5
    /// and section 5, "Time"). Beyond expiry, no conflict, ordering or
    /// acceptance decision may depend on it: an `mtime` or `written_at` in a
    /// record is data the writer supplied, not a reading of this clock, and
    /// nothing is ordered or compared by when this device thinks it happened.
    fn wall_time(&self) -> u64;
}

/// Wake-ups. A timer fires through [`Peer::on_timer`] at or after its deadline,
/// once; a timer whose deadline has already passed fires at the next
/// opportunity.
pub trait Timers {
    /// Arms `id` to fire at `at`, replacing any earlier deadline for `id`.
    fn set_timer(&mut self, id: TimerId, at: Instant);
    /// Disarms `id`; a no-op when it is not armed.
    fn cancel_timer(&mut self, id: TimerId);
}

/// Sending bytes to connected peers over one reliable, ordered byte stream per
/// connection (protocol spec, 3.1: a QUIC stream, a TCP connection or the
/// simulator's channel). The stream carries bytes, not messages: `send`
/// appends bytes, and [`Peer::on_message`] hands over the next bytes with
/// arbitrary chunk boundaries, at most [`MAX_CHUNK`] at a time, so the engine
/// frames its messages and enforces every size limit itself, through the
/// protocol crate's frame decoder (protocol spec, 2). While a connection
/// lasts, its bytes are never lost, duplicated or reordered. When it ends,
/// whatever the other side had not yet received may be lost, and this side
/// cannot tell which; loss shows itself only as [`Peer::on_disconnected`],
/// after which the next connection to the same peer is a new stream that
/// starts from nothing. Nothing is ordered across connections.
pub trait Transport {
    /// This peer's own id, as the runtime names it.
    fn local_id(&self) -> PeerId;

    /// Appends `bytes` to the stream to `to`. Accepted means queued, not
    /// delivered: if the connection ends before the other side has received
    /// them, they may be lost. A runtime may end a connection whose unsent
    /// queue this would take past [`MAX_SEND_QUEUE`]; see
    /// [`Transport::unsent`] for how to stay below it.
    ///
    /// # Errors
    /// [`SendError::NotConnected`] when this side has no open connection to
    /// `to` as far as it knows: before it has heard [`Peer::on_connected`] for
    /// `to` (always, for its own id), after it has heard
    /// [`Peer::on_disconnected`] for `to`, or after this same handler called
    /// [`Transport::close`] for `to`. Inside a connection as this side knows
    /// it, a send is never refused, even when the connection has in fact
    /// already ended.
    fn send(&mut self, to: PeerId, bytes: Vec<u8>) -> Result<(), SendError>;

    /// The bytes accepted by [`Transport::send`] on the connection to `to` and
    /// not yet handed to the network, this handler's own writes included: the
    /// queue [`MAX_SEND_QUEUE`] bounds. It drains as the runtime puts bytes on
    /// the wire, between handler calls, never during one, and no handler is
    /// called when it has: an engine waiting for room polls it on a timer of
    /// its own. The engine paces on it against its own budget, far below
    /// `MAX_SEND_QUEUE`, which is only where the runtime cuts. 0 when no
    /// connection to `to` is open as this side knows it.
    fn unsent(&self, to: PeerId) -> usize;

    /// Hangs up on `to`, abruptly: the connection ends once this handler
    /// returns, and this side hears [`Peer::on_disconnected`] after every
    /// other effect this handler asked for, before or after the close, has
    /// taken effect, receiving nothing more on it. What this side sent may or
    /// may not reach the other side, which learns of the end in its own time
    /// (at once, or only when its runtime times the connection out); nothing
    /// orders when it hears against when this side does. A further `send` to
    /// `to` from this handler is refused; a no-op when no connection to `to`
    /// is open. Whether a new connection follows is the runtime's business:
    /// the daemon's dialling policy, the simulator's scenario (a closed pair
    /// never reconnects on its own there). To say goodbye (protocol spec, 4.2)
    /// the engine sends its Close frame, arms its own timer for 1 s, and calls
    /// `close` when that timer fires or when it hears `on_disconnected`,
    /// whichever comes first; even so, the frame may be lost.
    fn close(&mut self, to: PeerId);
}

/// A key and its value, as [`Storage::scan`] returns them.
pub type Entry = (Vec<u8>, Vec<u8>);

/// The state a crash must not lose, as a key-value store with transactions.
/// `put` and `delete` stage writes that this process sees at once (a `get`
/// after a `put` returns the new value) but that survive a crash only after
/// `commit`, which makes everything staged durable at once or not at all.
pub trait Storage {
    /// The value at `key`, staged or committed, or `None`.
    ///
    /// # Errors
    /// [`StorageError::Io`] when the store cannot be read.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Every key-value pair whose key starts with `prefix`, in key order,
    /// staged writes included.
    ///
    /// # Errors
    /// [`StorageError::Io`] when the store cannot be read.
    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError>;

    /// Stages `value` at `key`.
    ///
    /// # Errors
    /// [`StorageError::Full`] when the disk has no room for it; nothing is staged then.
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Stages the removal of `key`.
    ///
    /// # Errors
    /// [`StorageError::Io`] when the store cannot be written.
    fn delete(&mut self, key: &[u8]) -> Result<(), StorageError>;

    /// Makes every staged write durable, atomically.
    ///
    /// # Errors
    /// [`StorageError::Full`] or [`StorageError::Io`]; the writes stay staged,
    /// so the peer may retry after the disk has room or call [`Storage::rollback`].
    fn commit(&mut self) -> Result<(), StorageError>;

    /// Discards every staged write.
    fn rollback(&mut self);
}

/// Random bytes. The daemon backs this with the operating system's generator
/// through the approved crates; the simulator with its seeded one, so that a
/// run replays. Key material is derived under the keys crate's rules; this is
/// for jitter, nonces the protocol spec allows to be random, and sampling.
pub trait Randomness {
    /// Fills `buf` with random bytes.
    fn fill_random(&mut self, buf: &mut [u8]);
}

/// Everything a handler may do, handed to each call of [`Peer`] and valid only
/// for that call.
pub trait Context: Clock + Timers + Transport + Randomness {
    /// This peer's persistent store.
    fn storage(&mut self) -> &mut dyn Storage;
}

/// An engine instance as the runtime drives it. All six handlers run to
/// completion before the next begins; none performs I/O except through `cx`.
///
/// For any one [`PeerId`], [`Peer::on_connected`] and
/// [`Peer::on_disconnected`] strictly alternate, starting with `on_connected`:
/// there is at most one logical connection per peer at a time, and
/// [`Peer::on_message`] for that peer arrives only between the two. A runtime
/// whose transport can hold several connections to the same peer at once
/// (libp2p does) must collapse them into one logical connection before it
/// calls these handlers; the engine never sees the multiplicity.
///
/// What a handler asks of its context (sends, timers, hang-ups) takes effect
/// in the order it asked, all of it before that peer's next handler runs, so a
/// cancel never overtakes the arming it cancels and bytes never overtake bytes
/// sent before them. Each side hears of its own connections' ends one at a
/// time, in the order its runtime learned of them, never in the middle of a
/// handler's effects; a hang-up this side asked for reaches this side after
/// that handler's effects. These are promises about one side only: nothing
/// orders what one side hears against what another side hears, or against
/// when the other side hung up (a crashed peer may be learned of only by a
/// timeout, a hang-up at once). Until a side has heard `on_disconnected`, the
/// connection is open as far as it is concerned: its sends are accepted, and
/// may be lost. When the runtime replaces the stream under a logical
/// connection (libp2p moving to a newer connection to the same peer, say), the
/// engine hears `on_disconnected` and then `on_connected`: a connection never
/// moves to a new stream silently, since what the engine has decoded so far
/// belongs to the old one.
pub trait Peer {
    /// The process started (or restarted after a crash). Load state from
    /// `cx.storage()`, arm the first timers. Connections are reported after this
    /// returns, one [`Peer::on_connected`] each. A restarted process's clock
    /// starts afresh: no [`Instant`] from before the restart means anything now.
    fn on_start(&mut self, cx: &mut dyn Context);

    /// The next `bytes` of the stream from `from`: between 1 and [`MAX_CHUNK`]
    /// of them, split wherever the transport chose, so a frame may span calls
    /// and one call may end several frames. Feed them to the frame decoder.
    /// They are untrusted: check every length before allocating, ignore what
    /// does not parse, never index with an offset they supplied.
    fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]);

    /// The timer `id` fired, at or after its deadline, once per arming.
    fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId);

    /// A connection to `peer` is open: a new stream that starts from nothing.
    /// [`Transport::send`] to it works from this call until
    /// [`Peer::on_disconnected`] says otherwise.
    fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId);

    /// The connection to `peer` ended, whether the peer went away, the network
    /// cut it or lost data, or either side called [`Transport::close`]. What
    /// either side sent and the other had not yet received may be lost, and
    /// this side cannot tell which; a partly received frame is discarded with
    /// the stream. A send to `peer` from this call on is refused until the next
    /// [`Peer::on_connected`] for it, which starts a new stream.
    fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId);

    /// The process is stopping cleanly. Commit what should survive. A crash
    /// does not call this; that is the difference between the two. It is the
    /// last call this instance gets. What it sends (a `Close(SHUTDOWN)`
    /// frame, say) the runtime flushes for up to 1 s and then closes each
    /// connection, so the other side may receive it or may see only the
    /// connection end. A hang-up made inside it ([`Transport::close`]) is
    /// abrupt and reaches only the other side, which hears
    /// [`Peer::on_disconnected`]; this side never does.
    fn on_stop(&mut self, cx: &mut dyn Context);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn instant_arithmetic_is_checked_and_saturating() {
        let t = Instant::from_nanos(1_500_000_000);
        assert_eq!(t.as_nanos(), 1_500_000_000);
        assert_eq!(
            t.checked_add(Duration::from_millis(500)),
            Some(Instant::from_nanos(2_000_000_000))
        );
        assert_eq!(t.checked_add(Duration::MAX), None);
        assert_eq!(
            Instant::from_nanos(u64::MAX - 1).checked_add(Duration::from_nanos(2)),
            None
        );
        assert_eq!(
            Instant::from_nanos(u64::MAX - 1).saturating_add(Duration::from_secs(7)),
            Instant::from_nanos(u64::MAX)
        );
        assert_eq!(
            t.checked_sub(Duration::from_secs(1)),
            Some(Instant::from_nanos(500_000_000))
        );
        assert_eq!(t.checked_sub(Duration::from_secs(2)), None);
        assert_eq!(t.checked_sub(Duration::MAX), None);
        assert_eq!(
            t.duration_since(Instant::ZERO),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(Instant::from_millis(1500), t);
        assert_eq!(t.as_secs(), 1, "rounded down");
        assert_eq!(Instant::from_nanos(u64::MAX).as_secs(), 18_446_744_073);
        assert_eq!(Instant::from_secs(2), Instant::from_nanos(2_000_000_000));
        assert_eq!(Instant::from_secs(u64::MAX), Instant::from_nanos(u64::MAX));
        assert_eq!(
            Instant::from_millis(u64::MAX),
            Instant::from_nanos(u64::MAX)
        );
        assert_eq!(Instant::ZERO.duration_since(t), None);
        assert_eq!(Instant::ZERO.saturating_duration_since(t), Duration::ZERO);
        assert_eq!(
            t.saturating_duration_since(Instant::from_nanos(1_000_000_000)),
            Duration::from_millis(500)
        );
        assert!(Instant::ZERO < t);
        assert_eq!(Instant::default(), Instant::ZERO);
    }

    #[test]
    fn instant_displays_every_nanosecond() {
        assert_eq!(Instant::ZERO.to_string(), "0.000000000s");
        assert_eq!(
            Instant::from_nanos(1_250_000_000).to_string(),
            "1.250000000s"
        );
        assert_eq!(
            Instant::from_nanos(1_250_000_001).to_string(),
            "1.250000001s"
        );
        assert_eq!(format!("{:>14}", Instant::ZERO), "  0.000000000s");
    }

    #[test]
    fn ids_round_trip_and_display() {
        let p = PeerId::new(7);
        assert_eq!(p.as_u64(), 7);
        assert_eq!(p.to_string(), "p7");
        assert_eq!(format!("{p:<4}|"), "p7  |", "width is honoured");
        assert!(PeerId::new(1) < PeerId::new(2));
        let t = TimerId::new(3);
        assert_eq!(t.as_u64(), 3);
        assert_eq!(t.to_string(), "t3");
        assert_eq!(format!("{t:>4}|"), "  t3|");
        assert!(TimerId::new(1) < TimerId::new(2));
    }

    #[test]
    fn the_transport_bounds_are_the_ones_the_protocol_spec_names() {
        assert_eq!(MAX_CHUNK, 65_536);
        assert_eq!(MAX_SEND_QUEUE, 134_217_728);
    }

    #[test]
    fn errors_display_and_are_std_errors() {
        let full: &dyn std::error::Error = &StorageError::Full;
        assert_eq!(full.to_string(), "storage is full");
        assert!(full.source().is_none());
        assert_eq!(
            StorageError::Io("disk vanished".into()).to_string(),
            "storage failed: disk vanished"
        );
        let send: &dyn std::error::Error = &SendError::NotConnected;
        assert_eq!(send.to_string(), "peer is not connected");
        assert!(send.source().is_none());
    }

    /// 2026-01-01T00:00:00Z: what the recorder's wall clock reads at its start.
    const WALL_EPOCH: u64 = 1_767_225_600;

    /// A context that records what a peer does, to show the traits compose
    /// behind `&mut dyn Context` and that a peer can be driven through it.
    #[derive(Default)]
    struct Recorder {
        now: u64,
        sent: Vec<(PeerId, Vec<u8>)>,
        closed: Vec<PeerId>,
        timers: BTreeMap<TimerId, Instant>,
        store: Store,
        connected: Vec<PeerId>,
    }

    #[derive(Default)]
    struct Store {
        committed: BTreeMap<Vec<u8>, Vec<u8>>,
        staged: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    }

    impl Storage for Store {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(match self.staged.get(key) {
                Some(v) => v.clone(),
                None => self.committed.get(key).cloned(),
            })
        }
        fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError> {
            let mut all = self.committed.clone();
            for (k, v) in &self.staged {
                match v {
                    Some(v) => all.insert(k.clone(), v.clone()),
                    None => all.remove(k),
                };
            }
            Ok(all
                .into_iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .collect())
        }
        fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            if key == b"too-big" {
                return Err(StorageError::Full);
            }
            self.staged.insert(key.to_vec(), Some(value.to_vec()));
            Ok(())
        }
        fn delete(&mut self, key: &[u8]) -> Result<(), StorageError> {
            self.staged.insert(key.to_vec(), None);
            Ok(())
        }
        fn commit(&mut self) -> Result<(), StorageError> {
            for (k, v) in std::mem::take(&mut self.staged) {
                match v {
                    Some(v) => self.committed.insert(k, v),
                    None => self.committed.remove(&k),
                };
            }
            Ok(())
        }
        fn rollback(&mut self) {
            self.staged.clear();
        }
    }

    impl Clock for Recorder {
        fn now(&self) -> Instant {
            Instant::from_nanos(self.now)
        }
        fn wall_time(&self) -> u64 {
            WALL_EPOCH + self.now / 1_000_000_000
        }
    }

    impl Timers for Recorder {
        fn set_timer(&mut self, id: TimerId, at: Instant) {
            self.timers.insert(id, at);
        }
        fn cancel_timer(&mut self, id: TimerId) {
            self.timers.remove(&id);
        }
    }
    impl Transport for Recorder {
        fn local_id(&self) -> PeerId {
            PeerId::new(0)
        }
        fn send(&mut self, to: PeerId, bytes: Vec<u8>) -> Result<(), SendError> {
            if !self.connected.contains(&to) {
                return Err(SendError::NotConnected);
            }
            self.sent.push((to, bytes));
            Ok(())
        }
        fn unsent(&self, to: PeerId) -> usize {
            if !self.connected.contains(&to) {
                return 0;
            }
            self.sent
                .iter()
                .filter(|(p, _)| *p == to)
                .map(|(_, b)| b.len())
                .sum()
        }
        fn close(&mut self, to: PeerId) {
            self.connected.retain(|p| *p != to);
            self.closed.push(to);
        }
    }
    impl Randomness for Recorder {
        fn fill_random(&mut self, buf: &mut [u8]) {
            buf.fill(0x5a);
        }
    }
    impl Context for Recorder {
        fn storage(&mut self) -> &mut dyn Storage {
            &mut self.store
        }
    }

    /// Echoes every message back (and hangs up on an empty one), counts timer
    /// ticks in storage, greets peers as they connect, and notes the date it
    /// last ticked.
    #[derive(Default)]
    struct Echo {
        ticks: u64,
        peers: Vec<PeerId>,
        last_tick_date: u64,
    }

    const TICK: TimerId = TimerId::new(1);

    impl Peer for Echo {
        fn on_start(&mut self, cx: &mut dyn Context) {
            self.ticks = cx
                .storage()
                .get(b"ticks")
                .ok()
                .flatten()
                .and_then(|v| v.as_slice().try_into().ok())
                .map_or(0, u64::from_le_bytes);
            let next = cx.now().saturating_add(Duration::from_secs(1));
            cx.set_timer(TICK, next);
        }
        fn on_message(&mut self, cx: &mut dyn Context, from: PeerId, bytes: &[u8]) {
            if bytes.is_empty() {
                cx.close(from);
                return;
            }
            let mut nonce = [0u8; 2];
            cx.fill_random(&mut nonce);
            let mut reply = bytes.to_vec();
            reply.extend_from_slice(&nonce);
            let _ = cx.send(from, reply);
        }
        fn on_timer(&mut self, cx: &mut dyn Context, id: TimerId) {
            assert_eq!(id, TICK);
            self.ticks += 1;
            self.last_tick_date = cx.wall_time();
            let _ = cx.storage().put(b"ticks", &self.ticks.to_le_bytes());
            let _ = cx.storage().commit();
            let next = cx.now().saturating_add(Duration::from_secs(1));
            cx.set_timer(TICK, next);
        }
        fn on_connected(&mut self, cx: &mut dyn Context, peer: PeerId) {
            self.peers.push(peer);
            let _ = cx.send(peer, b"hello".to_vec());
        }
        fn on_disconnected(&mut self, cx: &mut dyn Context, peer: PeerId) {
            self.peers.retain(|p| *p != peer);
            cx.cancel_timer(TimerId::new(99));
        }
        fn on_stop(&mut self, cx: &mut dyn Context) {
            let _ = cx.storage().put(b"stopped", b"clean");
            let _ = cx.storage().commit();
        }
    }

    #[test]
    fn a_peer_can_be_driven_through_a_dyn_context() {
        let mut cx = Recorder::default();
        let mut peer = Echo::default();
        let p1 = PeerId::new(1);

        peer.on_start(&mut cx);
        assert_eq!(
            cx.timers.get(&TICK),
            Some(&Instant::from_nanos(1_000_000_000))
        );

        // Not connected yet: the greeting on connect works, a stray send does not.
        cx.connected.push(p1);
        peer.on_connected(&mut cx, p1);
        assert_eq!(cx.sent, vec![(p1, b"hello".to_vec())]);
        assert_eq!(
            cx.send(PeerId::new(9), vec![]),
            Err(SendError::NotConnected)
        );

        assert_eq!(cx.unsent(p1), 5, "the recorder never drains: the greeting");
        peer.on_message(&mut cx, p1, b"ping");
        assert_eq!(cx.sent.get(1), Some(&(p1, b"ping\x5a\x5a".to_vec())));
        assert_eq!(cx.unsent(p1), 11);
        assert_eq!(
            cx.unsent(PeerId::new(9)),
            0,
            "nothing for a peer not connected"
        );
        peer.on_message(&mut cx, p1, b"");
        assert_eq!(cx.closed, vec![p1], "an empty message makes it hang up");
        assert_eq!(cx.send(p1, vec![]), Err(SendError::NotConnected));
        assert_eq!(cx.sent.len(), 2);
        assert_eq!(cx.unsent(p1), 0, "a closed connection has nothing unsent");

        cx.now = 1_000_000_000;
        peer.on_timer(&mut cx, TICK);
        assert_eq!(
            cx.timers.get(&TICK),
            Some(&Instant::from_nanos(2_000_000_000))
        );
        assert_eq!(
            peer.last_tick_date,
            WALL_EPOCH + 1,
            "the wall clock reaches the peer through the same context"
        );
        assert_eq!(
            cx.store.get(b"ticks").ok().flatten(),
            Some(1u64.to_le_bytes().to_vec())
        );

        cx.timers.insert(TimerId::new(99), Instant::ZERO);
        peer.on_disconnected(&mut cx, p1);
        assert_eq!(peer.peers, Vec::new());
        assert!(!cx.timers.contains_key(&TimerId::new(99)));

        peer.on_stop(&mut cx);
        assert_eq!(
            cx.store.get(b"stopped").ok().flatten(),
            Some(b"clean".to_vec())
        );

        // A restarted peer reloads its committed tick count through the same context.
        let mut again = Echo::default();
        again.on_start(&mut cx);
        assert_eq!(again.ticks, 1);
    }

    #[test]
    fn storage_double_sees_staged_writes_until_rollback() {
        let mut s = Store::default();
        assert!(s.put(b"a", b"1").is_ok());
        assert_eq!(s.get(b"a").ok().flatten(), Some(b"1".to_vec()));
        assert_eq!(s.scan(b"a").ok().map(|v| v.len()), Some(1));
        s.rollback();
        assert_eq!(s.get(b"a").ok().flatten(), None);
        assert!(s.put(b"a", b"1").is_ok());
        assert!(s.commit().is_ok());
        assert!(s.delete(b"a").is_ok());
        assert_eq!(s.get(b"a").ok().flatten(), None);
        assert!(s.commit().is_ok());
        assert!(s.scan(b"").is_ok_and(|v| v.is_empty()));
        assert_eq!(s.put(b"too-big", b""), Err(StorageError::Full));
    }
}
