// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A folder's disk (`threat-model.md` TM-4).
//!
//! - [`name`]: which names a folder's disk may hold, and how a name read from
//!   the disk becomes part of an index path, for Linux, macOS and Windows
//!   alike ([`NamePolicy`]). Pure functions, tested on every platform. A name
//!   the policy refuses is one this device cannot store: it is kept on the
//!   disk and never read as deleted.
//! - [`resolver`]: the one way into a folder's disk. A [`Root`] holds the
//!   folder's root open, and its hidden directory, which it makes when it
//!   is missing; [`Root::parent`] reaches the [`Dir`] that holds a path's
//!   last component one directory at a time, never through a symbolic link,
//!   into another folder or into the hidden directory, nor across a mount
//!   point (by mount ID on Linux 5.8 and later, by device elsewhere). Linux
//!   and macOS; Windows in phase 3.
//!
//! Every name is untrusted, whether a peer's record or the disk supplied it:
//! nothing here panics on one, and what the policy admits is fuzzed against
//! `check_path` (`fuzz/fuzz_targets/disk_names.rs`, TM-3).

pub mod name;
pub mod resolver;

pub use name::{HIDDEN_DIR, IndexPath, Name, NameError, NamePolicy};
pub use resolver::{
    CROSSES_MOUNTS, Create, Dir, Entries, Entry, FileId, Kind, OpenError, ResolveError, Root, Time,
};
