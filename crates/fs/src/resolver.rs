// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The one way into a folder's disk (TM-4).
//!
//! A [`Root`] holds the folder's root directory open, and its hidden
//! directory `.licketysync`, which [`Root::open`] makes (mode `0o700`)
//! wherever it is pointed when it is missing, and narrows to `0o700` when it
//! has a looser mode. The hidden directory must be this user's
//! ([`OpenError::HiddenNotOwned`]; this fails closed where a file system
//! invents or remaps owners, such as an NFS export's `nobody`, or CIFS or FUSE
//! mounted without `uid=`), and no one else may write it
//! ([`OpenError::HiddenWritable`]); the root itself has no owner rule, since a
//! folder a group shares is a person's choice. A root this user cannot write
//! does not open ([`OpenError::Io`]). Every path beneath the root is an
//! [`IndexPath`](crate::IndexPath), which the root's
//! [`NamePolicy`](crate::NamePolicy) admitted, so no component is empty,
//! `.`, `..`, absolute or a name a file system could take for the hidden
//! directory. [`Root::parent`] first checks that the hidden directory is the
//! one the root opened (one removed or replaced since makes the root refuse
//! until it is opened again, [`ResolveError::RootChanged`]; a [`Dir`] handed
//! out before keeps working), then opens the
//! directory that holds a path's last component, one component at a time,
//! each relative to the descriptor of the one before, and refuses, at every
//! component:
//! - a symbolic link, which is never followed ([`ResolveError::Symlink`]);
//! - a mount point: the walk stays on the root's mount
//!   ([`CROSSES_MOUNTS`], [`ResolveError::OtherFileSystem`]). On Linux 5.8
//!   and later it compares mount IDs (`statx`, `STATX_MNT_ID`), which tells a
//!   bind mount of the root's own file system apart; on macOS, and on Linux
//!   before 5.8, it compares devices only, so such a mount is not seen;
//! - a directory that holds `.licketysync`, another folder's root
//!   ([`ResolveError::NestedFolder`]);
//! - the folder's own hidden directory under another name, by its file ID
//!   ([`ResolveError::HiddenDirectory`]): a file system can give it one the
//!   name policy does not know.
//!
//! The last component is reached only through the parent's descriptor, by
//! [`Dir::stat`], which never follows it, and [`Dir::open_file`], which
//! never follows it either and must find what `stat` found, on the same
//! mount. A FIFO, a socket or a device is [`ResolveError::Special`], never
//! read. A [`Name`](crate::Name) admitted by another policy is judged again
//! by the root's, as a path is.
//!
//! On Linux each component is opened by `openat2` with `RESOLVE_BENEATH`,
//! `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_XDEV`, so
//! that the kernel refuses a link or a mount in the same call that opens the
//! directory. [`Root::open`] decides the way once, by one `openat2` of the
//! root itself: where the kernel lacks it (`ENOSYS`, before 5.6) or a seccomp
//! filter refuses it (`EPERM`), the root walks with `openat` and
//! `O_NOFOLLOW`, checking each directory's mount itself; a component that
//! meets `EAGAIN` three times is walked too. macOS always walks. One
//! component at a time on both, so that each directory on the way is
//! checked for a nested folder and for the hidden directory's file ID. A
//! directory missing on the way is made with `mkdirat` when the caller asks.
//!
//! What remains:
//! - a directory that a local process moves out of the root while its
//!   descriptor is held takes the next call on it along;
//! - between [`Dir::stat`] and [`Dir::open_file`], any local user who can
//!   write in that directory can swap in a FIFO, which is opened (without
//!   blocking or taking a terminal) before its `fstat` refuses it; a device
//!   needs `CAP_MKNOD` to make;
//! - a hard link to a file outside the root, made by a user who can write
//!   in the folder, is read like any file (its [`Entry::nlink`] says so;
//!   what the scanner does with it is the scanner's);
//! - naming an automount trigger beneath the root starts its mount before
//!   the resolver refuses it as another file system.
//!
//! Windows has no resolver yet: [`Root::open`] returns
//! [`OpenError::Unsupported`] there (phase 3, on a platform-FFI crate).

use std::fmt;
use std::io;

use crate::name::NameError;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(not(unix))]
mod other;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
mod walk;
// `cfg(test)` alone, so that cargo-mutants knows the tests for test code.
#[cfg(test)]
#[cfg(unix)]
mod tests;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
pub use other::{Dir, Entries, Root};
#[cfg(unix)]
pub use unix::{Dir, Entries, Root};

/// Whether resolution crosses a mount point beneath the root. It does not:
/// a place, a rename and a delete need one mount to be atomic, and a disk
/// that is unmounted must not read as everything beneath it deleted. A mount
/// point beneath the root is [`ResolveError::OtherFileSystem`], found by
/// mount ID where Linux reports one and by device elsewhere. The one switch
/// for that choice.
pub const CROSSES_MOUNTS: bool = false;

/// A file's identity on its device: the device and the inode, which a
/// rename keeps and a replacement changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    /// The device (`st_dev`).
    pub dev: u64,
    /// The inode (`st_ino`).
    pub ino: u64,
}

/// A time as the file system keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Time {
    /// Seconds since 1970-01-01 UTC.
    pub secs: i64,
    /// Nanoseconds within the second.
    pub nanos: u32,
}

/// What a name beneath the root is, of the kinds a folder holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// What [`Dir::stat`] found at a name, without following it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Entry {
    /// A file or a directory.
    pub kind: Kind,
    /// Its identity.
    pub id: FileId,
    /// Its size in bytes.
    pub size: u64,
    /// When its content last changed.
    pub mtime: Time,
    /// When its content or its metadata last changed.
    pub ctime: Time,
    /// Its permission bits, `0o7777` at most.
    pub mode: u32,
    /// Its hard links: more than one for a file means it has other names,
    /// perhaps outside the root.
    pub nlink: u64,
}

/// Whether [`Root::parent`] makes the directories missing on the way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Create {
    /// No: a missing directory is [`ResolveError::NotFound`].
    No,
    /// Yes, with `mkdirat`, mode `0o777` less the process's umask.
    Directories,
}

/// Why a path beneath the root cannot be used.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResolveError {
    /// The name cannot be stored here: the root's policy refuses it, or the
    /// file system finds it too long.
    Unstorable(NameError),
    /// A directory on the way, or the file to open, is missing.
    NotFound,
    /// A component is a symbolic link, which is never followed.
    Symlink,
    /// A component on the way is a file.
    NotADirectory,
    /// A component is on another file system: a mount point.
    OtherFileSystem,
    /// A component is a FIFO, a socket or a device.
    Special,
    /// A directory on the way is another folder's root: it holds
    /// `.licketysync`.
    NestedFolder,
    /// A component is the folder's own hidden directory by another name.
    HiddenDirectory,
    /// [`Dir::open_file`] found something other than the file its caller
    /// expected: it was replaced or changed since it was examined.
    Changed,
    /// The hidden directory the root opened was removed or replaced: the
    /// root refuses until it is opened again.
    RootChanged,
    /// The system refused for another reason.
    Io(io::Error),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unstorable(e) => write!(f, "cannot be stored here: {e}"),
            Self::NotFound => f.write_str("missing: a directory on the way, or the file"),
            Self::Symlink => f.write_str("a symbolic link, which is never followed"),
            Self::NotADirectory => f.write_str("a file where a directory was expected"),
            Self::OtherFileSystem => f.write_str("on another file system (a mount point)"),
            Self::Special => f.write_str("a FIFO, socket or device"),
            Self::NestedFolder => f.write_str("inside another folder"),
            Self::HiddenDirectory => f.write_str("the folder's hidden directory"),
            Self::Changed => f.write_str("changed since it was examined"),
            Self::RootChanged => f.write_str(
                "the folder's hidden directory was removed or replaced; open the folder again",
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unstorable(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ResolveError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Why a folder's root cannot be opened.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// This platform has no resolver yet.
    Unsupported,
    /// The root's `.licketysync` is not a directory on the root's mount: a
    /// symbolic link, a file, or a mount point.
    Hidden,
    /// The root's `.licketysync` belongs to another user, who could keep
    /// this folder's temporary and archived files there.
    HiddenNotOwned,
    /// Group or others can write the root's `.licketysync`, and it could not
    /// be narrowed (a file system whose modes come from its mount, such as
    /// vfat or exFAT, refuses).
    HiddenWritable,
    /// The root could not be opened or examined.
    Io(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("folders on this platform are not supported yet"),
            Self::Hidden => f.write_str("the folder's .licketysync is not a directory of its own"),
            Self::HiddenNotOwned => {
                f.write_str("the folder's .licketysync belongs to another user")
            }
            Self::HiddenWritable => {
                f.write_str("others can write the folder's .licketysync, and it cannot be narrowed")
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
