// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What an engine instance is built from ([`EngineConfig`]), its defaults,
//! and the checks [`crate::Engine::new`] makes before anything runs.
//!
//! Every secret (the device seed, the folder keys) comes from the config at
//! every start and restart; phase 0 stores no key (`keys.md` 8.2, 8.4). The
//! config's `Debug` names no secret and no path (TM-6): the seed and the keys
//! print as the keys crate redacts them, and nothing else here is secret.

use core::fmt;
use core::time::Duration;
use std::collections::BTreeSet;

use licketysync_keys::secret::DeviceSeed;
use licketysync_keys::{FolderId, FolderKey};
use licketysync_protocol::connection::Timing;
use licketysync_protocol::limits::{
    DEFAULT_MESSAGE_SIZE, DEFAULT_REQUESTS_IN_FLIGHT, MAX_CHUNK_PLAINTEXT, MAX_MESSAGE_SIZE,
    MAX_PROOFS_PER_CONNECTION, MAX_REQUESTS_IN_FLIGHT, MIN_MESSAGE_SIZE,
};
use licketysync_protocol::parse::is_device_name;

/// The default send budget: the unsent bytes under which the engine hands
/// over its next reply page or `CHUNK_OK` (decision: 16 MiB, an eighth of
/// `MAX_SEND_QUEUE`, so that pacing never reaches where the runtime cuts).
pub const DEFAULT_SEND_BUDGET: usize = 16 << 20;
/// How often the engine reads `Transport::unsent` again while it is over its
/// budget (decision: 50 ms; nothing tells it when the queue drains).
pub const DEFAULT_SEND_POLL: Duration = Duration::from_millis(50);
/// How often a folder paused for a store failure tries its store again
/// (decision: 1 s; the `pause` module).
pub const DEFAULT_RESUME_PROBE: Duration = Duration::from_secs(1);
/// The most folders one config holds: each is proven on every connection,
/// and a connection carries at most `MAX_PROOFS_PER_CONNECTION` proofs
/// (`protocol.md` 3.5), so no proof goes unsent for their number.
///
/// A connection opens at most `MAX_OPEN_FOLDERS_PER_CONNECTION` (64)
/// folders, though: the peer answers REJECTED to a proof past them (3.5 step
/// 6), with no retry, and the engine keeps one connection per peer. So a
/// device that shares more than 64 folders with one peer syncs only 64 of
/// them with it (a recorded limitation). The engine counts each refusal
/// that comes while 64 folders are open, possibly the limit's
/// (`Counters::open_limit_refusals`), and raises `IssueKind::OpenLimit` for
/// the folder.
pub const MAX_FOLDERS: usize = MAX_PROOFS_PER_CONNECTION;
/// The default size of the fixed-size chunks a write cuts (decision: 1 MiB;
/// `FastCDC` is phase 1, a recorded deviation from `keys.md` 3.2).
pub const DEFAULT_CHUNK_SIZE: usize = 1 << 20;

/// Everything one engine instance runs with. The runtime's factory builds a
/// fresh one at every start and restart.
pub struct EngineConfig {
    /// The device seed (`keys.md` 8.1): the device key and the libp2p
    /// identity derive from it.
    pub device_seed: DeviceSeed,
    /// The name this device reports in Status, at most 64 bytes, no control
    /// characters (`protocol.md` 4.5).
    pub device_name: String,
    /// One key per folder this device holds, at its tier; a folder ID may
    /// appear once (`keys.md` 8.2), and at most [`MAX_FOLDERS`] of them.
    pub folders: Vec<FolderKey>,
    /// The protocol's intervals and timeouts, [`Timing::SPEC`] unless a
    /// simulation scales them, both sides alike (`protocol.md` 5, "Time").
    pub timing: Timing,
    /// The send budget (`runtime.rs`, `MAX_SEND_QUEUE`): see
    /// [`DEFAULT_SEND_BUDGET`].
    pub send_budget: usize,
    /// See [`DEFAULT_SEND_POLL`].
    pub send_poll: Duration,
    /// See [`DEFAULT_RESUME_PROBE`].
    pub resume_probe: Duration,
    /// The plaintext bytes of each chunk a write cuts, 1 to
    /// `MAX_CHUNK_PLAINTEXT`: see [`DEFAULT_CHUNK_SIZE`].
    pub chunk_size: usize,
    /// The `max_records` of this side's index requests: 0 means 4 096
    /// (`protocol.md` 4.5).
    pub max_records: u32,
    /// The chunk requests this side holds open for a peer, advertised in its
    /// Hello: 1 to `MAX_REQUESTS_IN_FLIGHT`.
    pub max_requests_in_flight: u32,
    /// The largest frame this side accepts, advertised in its Hello:
    /// `MIN_MESSAGE_SIZE` to `MAX_MESSAGE_SIZE`.
    pub max_message_size: u32,
}

impl EngineConfig {
    /// A device with these folders and every other setting at its default.
    #[must_use]
    pub fn new(device_seed: DeviceSeed, folders: Vec<FolderKey>) -> Self {
        Self {
            device_seed,
            device_name: String::new(),
            folders,
            timing: Timing::SPEC,
            send_budget: DEFAULT_SEND_BUDGET,
            send_poll: DEFAULT_SEND_POLL,
            resume_probe: DEFAULT_RESUME_PROBE,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_records: 0,
            max_requests_in_flight: DEFAULT_REQUESTS_IN_FLIGHT,
            max_message_size: DEFAULT_MESSAGE_SIZE,
        }
    }
}

impl fmt::Debug for EngineConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineConfig")
            .field("folders", &self.folders.len())
            .field("timing", &self.timing)
            .field("send_budget", &self.send_budget)
            .field("send_poll", &self.send_poll)
            .field("resume_probe", &self.resume_probe)
            .field("chunk_size", &self.chunk_size)
            .field("max_records", &self.max_records)
            .field("max_requests_in_flight", &self.max_requests_in_flight)
            .field("max_message_size", &self.max_message_size)
            .finish_non_exhaustive()
    }
}

/// Why [`crate::Engine::new`] refused a config. Nothing ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// Two keys for one folder: a device holds one key per folder
    /// (`keys.md` 8.2).
    DuplicateFolder(FolderId),
    /// More than [`MAX_FOLDERS`] folders.
    TooManyFolders(usize),
    /// `chunk_size` outside `1 ..= MAX_CHUNK_PLAINTEXT`.
    ChunkSize(usize),
    /// `send_budget` is 0, or `send_poll` or `resume_probe` is zero.
    Pacing,
    /// `max_message_size` or `max_requests_in_flight` outside its range.
    Limits,
    /// The device name breaks the Status grammar (`protocol.md` 4.5).
    DeviceName,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFolder(id) => write!(f, "two keys for folder {id}"),
            Self::TooManyFolders(n) => write!(f, "{n} folders, more than {MAX_FOLDERS}"),
            Self::ChunkSize(n) => write!(
                f,
                "a chunk size of {n} bytes is outside 1..={MAX_CHUNK_PLAINTEXT}"
            ),
            Self::Pacing => f.write_str("the send budget and both intervals must be above zero"),
            Self::Limits => f.write_str("a Hello limit is out of range"),
            Self::DeviceName => f.write_str("the device name breaks the Status grammar"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The settings an engine keeps from its config once the secrets have been
/// taken out of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) device_name: String,
    pub(crate) timing: Timing,
    pub(crate) send_budget: usize,
    pub(crate) send_poll: Duration,
    pub(crate) resume_probe: Duration,
    pub(crate) chunk_size: usize,
    pub(crate) max_records: u32,
    pub(crate) max_requests_in_flight: u32,
    pub(crate) max_message_size: u32,
}

/// Checks every setting a connection or a write depends on, so that nothing
/// fails later for a reason the config could have shown.
///
/// # Errors
/// [`ConfigError`].
pub(crate) fn check(config: &EngineConfig) -> Result<Settings, ConfigError> {
    if config.folders.len() > MAX_FOLDERS {
        return Err(ConfigError::TooManyFolders(config.folders.len()));
    }
    let mut seen = BTreeSet::new();
    for key in &config.folders {
        if !seen.insert(key.folder_id()) {
            return Err(ConfigError::DuplicateFolder(key.folder_id()));
        }
    }
    if !(1..=MAX_CHUNK_PLAINTEXT).contains(&config.chunk_size) {
        return Err(ConfigError::ChunkSize(config.chunk_size));
    }
    if config.send_budget == 0 || config.send_poll.is_zero() || config.resume_probe.is_zero() {
        return Err(ConfigError::Pacing);
    }
    if !(MIN_MESSAGE_SIZE..=MAX_MESSAGE_SIZE).contains(&config.max_message_size)
        || !(1..=MAX_REQUESTS_IN_FLIGHT).contains(&config.max_requests_in_flight)
    {
        return Err(ConfigError::Limits);
    }
    if !is_device_name(&config.device_name) {
        return Err(ConfigError::DeviceName);
    }
    Ok(Settings {
        device_name: config.device_name.clone(),
        timing: config.timing,
        send_budget: config.send_budget,
        send_poll: config.send_poll,
        resume_probe: config.resume_probe,
        chunk_size: config.chunk_size,
        max_records: config.max_records,
        max_requests_in_flight: config.max_requests_in_flight,
        max_message_size: config.max_message_size,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names,
    clippy::field_reassign_with_default,
    clippy::map_unwrap_or,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use super::*;
    use licketysync_keys::secret::WriteSecret;
    use licketysync_keys::{Suite, WriteKey};

    fn key(byte: u8) -> FolderKey {
        FolderKey::from(
            WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes([byte; 32])).unwrap(),
        )
    }

    fn config() -> EngineConfig {
        EngineConfig::new(DeviceSeed::from_bytes([1; 32]), vec![key(1), key(2)])
    }

    #[test]
    fn the_defaults_pass_and_keep_every_setting() {
        let s = check(&config()).unwrap();
        assert_eq!(s.send_budget, 16 << 20);
        assert_eq!(s.send_poll, Duration::from_millis(50));
        assert_eq!(s.resume_probe, Duration::from_secs(1));
        assert_eq!(s.chunk_size, 1 << 20);
        assert_eq!(s.max_records, 0);
        assert_eq!(s.max_requests_in_flight, 64);
        assert_eq!(s.max_message_size, 16 << 20);
        assert_eq!(s.timing, Timing::SPEC);
    }

    #[test]
    fn each_bad_setting_is_refused_with_its_reason() {
        let mut c = config();
        c.folders.push(key(1));
        assert_eq!(
            check(&c),
            Err(ConfigError::DuplicateFolder(key(1).folder_id()))
        );
        for (n, ok) in [
            (0, false),
            (1, true),
            (MAX_CHUNK_PLAINTEXT, true),
            (MAX_CHUNK_PLAINTEXT + 1, false),
        ] {
            let mut c = config();
            c.chunk_size = n;
            assert_eq!(check(&c).is_ok(), ok, "{n}");
            if !ok {
                assert_eq!(check(&c), Err(ConfigError::ChunkSize(n)));
            }
        }
        let mut c = config();
        c.send_budget = 0;
        assert_eq!(check(&c), Err(ConfigError::Pacing));
        let mut c = config();
        c.send_poll = Duration::ZERO;
        assert_eq!(check(&c), Err(ConfigError::Pacing));
        let mut c = config();
        c.resume_probe = Duration::ZERO;
        assert_eq!(check(&c), Err(ConfigError::Pacing));
        let mut c = config();
        c.max_message_size = MIN_MESSAGE_SIZE - 1;
        assert_eq!(check(&c), Err(ConfigError::Limits));
        let mut c = config();
        c.max_requests_in_flight = 0;
        assert_eq!(check(&c), Err(ConfigError::Limits));
        let mut c = config();
        c.device_name = "bell\u{7}".to_owned();
        assert_eq!(check(&c), Err(ConfigError::DeviceName));
        for e in [
            ConfigError::DuplicateFolder(key(1).folder_id()),
            ConfigError::TooManyFolders(MAX_FOLDERS + 1),
            ConfigError::ChunkSize(0),
            ConfigError::Pacing,
            ConfigError::Limits,
            ConfigError::DeviceName,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn more_folders_than_a_connection_can_prove_are_refused() {
        // protocol.md 3.5: a connection carries at most
        // MAX_PROOFS_PER_CONNECTION proofs, and the engine proves every
        // folder on every connection, so one more folder could never be
        // proven (it was an internal error at connect).
        let keys: Vec<FolderKey> = (0..=MAX_FOLDERS)
            .map(|i| {
                let mut secret = [0u8; 32];
                secret[..8].copy_from_slice(&(i as u64).to_le_bytes());
                FolderKey::from(
                    WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(secret)).unwrap(),
                )
            })
            .collect();
        let mut c = config();
        c.folders = keys;
        assert_eq!(check(&c), Err(ConfigError::TooManyFolders(MAX_FOLDERS + 1)));
        c.folders.pop();
        assert!(check(&c).is_ok());
    }

    #[test]
    fn debug_names_no_secret() {
        let text = format!("{:?}", config());
        assert!(text.contains("folders: 2"), "{text}");
        assert!(!text.contains("seed"), "{text}");
    }
}
