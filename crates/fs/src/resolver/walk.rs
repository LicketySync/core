// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The resolver's parts on macOS (and every Unix but Linux), which has
//! neither `openat2` nor a mount ID: the walk alone, and `stat`, so that a
//! mount point is found by its device only.

use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::AtFlags;
use rustix::io::Errno;

use super::unix::{Meta, meta_from_stat, walk_open};

/// How one root opens the directories on the way: always by the walk.
#[derive(Debug)]
pub(super) struct Opener;

impl Opener {
    #[allow(clippy::unnecessary_wraps, reason = "the same call as Linux's opener")]
    pub(super) const fn new(_root: BorrowedFd<'_>) -> Result<Self, Errno> {
        Ok(Self)
    }

    /// The directory `name` in `at`, never through a symbolic link.
    #[allow(clippy::unused_self, reason = "the same call as Linux's opener")]
    pub(super) fn open_dir(&self, at: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
        walk_open(at, name)
    }
}

/// What is at `name` in `dir`, without following it.
pub(super) fn meta_at(dir: BorrowedFd<'_>, name: &str) -> Result<Meta, Errno> {
    meta_from_stat(&rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?)
}

/// What the descriptor `fd` is.
pub(super) fn meta_of(fd: BorrowedFd<'_>) -> Result<Meta, Errno> {
    meta_from_stat(&rustix::fs::fstat(fd)?)
}
