// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The resolver on Linux and macOS: descriptors and `*at` calls.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::fs::{FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::{CROSSES_MOUNTS, Create, Entry, FileId, Kind, OpenError, ResolveError, Time};
use crate::name::{HIDDEN_DIR, IndexPath, Name, NameError, NamePolicy};

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::linux::{Opener, meta_at, meta_of};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use super::walk::{Opener, meta_at, meta_of};

/// How a directory on the way is opened: read-only, never through a
/// symbolic link (`O_NOFOLLOW` makes one fail), never inherited by a child
/// process, and only if it is a directory.
pub(super) const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// How a file is opened for its content: as [`DIRECTORY`], but a file, and
/// without waiting (`O_NONBLOCK`: a FIFO swapped in is refused, not waited
/// on) or taking a terminal (`O_NOCTTY`).
const FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);

/// How the root itself is opened: as the person's path leads, links and all
/// (it is their choice of folder), but only if it is a directory.
const ROOT: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

/// The mode of a directory made on the way: `0o777`, less the umask.
const DIRECTORY_MODE: Mode = Mode::RWXU.union(Mode::RWXG).union(Mode::RWXO);

/// The mode of the hidden directory: its owner's alone.
const HIDDEN_MODE: Mode = Mode::RWXU;

/// The walk's way to open one directory on the way: `openat`.
pub(super) fn walk_open(at: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(at, name, DIRECTORY, Mode::empty())
}

/// What a no-follow look at a name, or at a descriptor, found.
pub(super) struct Meta {
    pub(super) file_type: FileType,
    pub(super) id: FileId,
    /// The mount's ID, where the system reports one (Linux 5.8 and later).
    pub(super) mount: Option<u64>,
    pub(super) size: u64,
    pub(super) mtime: Time,
    pub(super) ctime: Time,
    /// The permission bits, `0o7777` at most.
    pub(super) mode: u32,
    pub(super) nlink: u64,
    /// The owner's user ID.
    pub(super) uid: u32,
}

/// A `stat`'s fields as [`Meta`], with no mount ID.
pub(super) fn meta_from_stat(st: &Stat) -> Result<Meta, Errno> {
    let mode: u32 = number(st.st_mode)?;
    Ok(Meta {
        file_type: FileType::from_raw_mode(st.st_mode),
        id: FileId {
            dev: number(st.st_dev)?,
            ino: number(st.st_ino)?,
        },
        mount: None,
        size: number(st.st_size)?,
        mtime: Time {
            secs: number(st.st_mtime)?,
            nanos: number(st.st_mtime_nsec)?,
        },
        ctime: Time {
            secs: number(st.st_ctime)?,
            nanos: number(st.st_ctime_nsec)?,
        },
        mode: mode & 0o7777,
        nlink: number(st.st_nlink)?,
        uid: number(st.st_uid)?,
    })
}

/// A `stat` field as this crate keeps it. Generic, because the fields' types
/// differ by platform and architecture.
fn number<T: TryInto<U>, U>(value: T) -> Result<U, Errno> {
    value.try_into().map_err(|_| Errno::OVERFLOW)
}

/// What every component beneath a root is checked against.
#[derive(Clone, Copy, Debug)]
pub(super) struct Bounds {
    /// The root's device.
    pub(super) dev: u64,
    /// The root's mount, where the system reports one.
    pub(super) mount: Option<u64>,
    /// The hidden directory's identity.
    pub(super) hidden: Option<FileId>,
}

impl Bounds {
    /// Whether `meta` is on the root's mount, and is not the hidden
    /// directory.
    pub(super) fn check(&self, meta: &Meta) -> Result<(), ResolveError> {
        if !CROSSES_MOUNTS && (meta.id.dev != self.dev || meta.mount != self.mount) {
            return Err(ResolveError::OtherFileSystem);
        }
        if self.hidden == Some(meta.id) {
            return Err(ResolveError::HiddenDirectory);
        }
        Ok(())
    }

    /// What a no-follow look found, if it is a file or a directory that
    /// passes [`Bounds::check`].
    fn entry(&self, meta: &Meta) -> Result<Entry, ResolveError> {
        let kind = match meta.file_type {
            FileType::RegularFile => Kind::File,
            FileType::Directory => Kind::Directory,
            FileType::Symlink => return Err(ResolveError::Symlink),
            _ => return Err(ResolveError::Special),
        };
        self.check(meta)?;
        Ok(Entry {
            kind,
            id: meta.id,
            size: meta.size,
            mtime: meta.mtime,
            ctime: meta.ctime,
            mode: meta.mode,
            nlink: meta.nlink,
        })
    }
}

fn io_error(e: Errno) -> ResolveError {
    ResolveError::Io(e.into())
}

/// What a failed call on a last component, or the last refusal of a
/// directory on the way, means.
pub(super) fn classify(e: Errno) -> ResolveError {
    match e {
        Errno::LOOP => ResolveError::Symlink,
        Errno::NOENT => ResolveError::NotFound,
        Errno::XDEV => ResolveError::OtherFileSystem,
        Errno::NAMETOOLONG => ResolveError::Unstorable(NameError::TooLong),
        e => io_error(e),
    }
}

/// What a failed open of the directory `name` on the way means. `ENOTDIR`
/// covers a file, a special file and, on Linux, a symbolic link
/// (`O_DIRECTORY` is judged before `O_NOFOLLOW`), so the name is examined,
/// without following it, to say which.
fn on_the_way(at: BorrowedFd<'_>, name: &str, e: Errno) -> ResolveError {
    if e != Errno::NOTDIR {
        return classify(e);
    }
    match meta_at(at, name) {
        Ok(meta) => match meta.file_type {
            FileType::Symlink => ResolveError::Symlink,
            FileType::RegularFile | FileType::Directory => ResolveError::NotADirectory,
            _ => ResolveError::Special,
        },
        Err(_) => ResolveError::NotADirectory,
    }
}

/// Whether the user `euid` owns the hidden directory `meta` describes: one of
/// another user's is refused, since they could keep this folder's temporary
/// and archived files there. Where a file system invents or remaps owners (an
/// NFS export's `nobody`, CIFS or FUSE mounted without `uid=`), this fails
/// closed. The root itself has no owner rule: a folder shared by a group is
/// one a person may choose.
pub(super) fn owned_by(meta: &Meta, euid: u32) -> Result<(), OpenError> {
    if meta.uid == euid {
        Ok(())
    } else {
        Err(OpenError::HiddenNotOwned)
    }
}

/// Whether only its owner can write the hidden directory `meta` describes.
pub(super) fn private(meta: &Meta) -> Result<(), OpenError> {
    if meta.mode & 0o022 == 0 {
        Ok(())
    } else {
        Err(OpenError::HiddenWritable)
    }
}

/// Whether the file system of the directory `meta` describes counts its
/// links: a directory has at least one, but some FUSE and network file
/// systems report none.
pub(super) fn counts_links(meta: &Meta) -> bool {
    meta.nlink > 0
}

/// Whether the hidden directory is still the one a root holds: what its name
/// leads to (`None`: nothing) is a directory of the identity `id`, and the
/// directory held (`held`) is still linked, where its file system counted
/// links when the root opened (`links_counted`).
pub(super) fn still_held(
    named: Option<&Meta>,
    held: &Meta,
    id: FileId,
    links_counted: bool,
) -> bool {
    named.is_some_and(|named| named.file_type == FileType::Directory && named.id == id)
        && (!links_counted || held.nlink > 0)
}

/// A path admitted by another policy, judged again by `policy`.
fn check_policy(path: &IndexPath, policy: NamePolicy) -> Result<(), ResolveError> {
    if path.policy() != policy {
        for name in path.names() {
            policy.name(name).map_err(ResolveError::Unstorable)?;
        }
    }
    Ok(())
}

/// A folder's root, held open with its hidden directory, and the policy its
/// paths are judged by.
#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
    /// The hidden directory, held open (`None` only for a test's root at a
    /// system directory, where nothing may be made).
    hidden: Option<OwnedFd>,
    /// Whether the hidden directory's file system counted its links when the
    /// root opened (some FUSE and network file systems report none).
    links_counted: bool,
    bounds: Bounds,
    /// The hidden directory was found removed or replaced.
    changed: AtomicBool,
    policy: NamePolicy,
    opener: Opener,
}

impl Root {
    /// Opens the folder's root at `path`, which may lead through symbolic
    /// links: it is the person's choice of folder. Nothing beneath it is
    /// ever reached so. Its `.licketysync` is made (mode `0o700`) when it is
    /// missing, wherever the root is (an empty mount point with nothing
    /// mounted included: the marker that tells a folder apart is a later
    /// check's), then held open and noted by its file ID, so that no other
    /// name reaches it. It must be this user's; one with a looser mode (a
    /// copy's `0o755`, say) is narrowed to `0o700`, and one that group or
    /// others can still write after that is refused. The root itself has no
    /// owner rule.
    ///
    /// # Errors
    /// [`OpenError::Io`] when the root cannot be opened as a directory or
    /// examined, or its hidden directory cannot be made (a root this user
    /// cannot write); [`OpenError::Hidden`] when its `.licketysync` is a
    /// symbolic link, a file or a mount point; [`OpenError::HiddenNotOwned`]
    /// when another user owns it (this fails closed where a file system
    /// invents or remaps owners); [`OpenError::HiddenWritable`] when group or
    /// others can still write it after it was narrowed.
    pub fn open(path: &Path, policy: NamePolicy) -> Result<Self, OpenError> {
        let fd = Self::open_root(path)?;
        let bounds = Self::bounds_of(&fd)?;
        match rustix::fs::mkdirat(&fd, HIDDEN_DIR, HIDDEN_MODE) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(OpenError::Io(e.into())),
        }
        let hidden = walk_open(fd.as_fd(), HIDDEN_DIR).map_err(|e| match e {
            // O_DIRECTORY and O_NOFOLLOW refuse a link with either.
            Errno::LOOP | Errno::NOTDIR => OpenError::Hidden,
            e => OpenError::Io(e.into()),
        })?;
        let meta = meta_of(hidden.as_fd()).map_err(|e| OpenError::Io(e.into()))?;
        owned_by(&meta, rustix::process::geteuid().as_raw())?;
        if bounds.check(&meta).is_err() {
            return Err(OpenError::Hidden);
        }
        let meta = if meta.mode & 0o077 != 0 {
            match rustix::fs::fchmod(&hidden, HIDDEN_MODE) {
                // A file system whose modes come from its mount refuses: its
                // mode is judged as it is, below.
                Ok(()) | Err(Errno::PERM) => {}
                Err(e) => return Err(OpenError::Io(e.into())),
            }
            meta_of(hidden.as_fd()).map_err(|e| OpenError::Io(e.into()))?
        } else {
            meta
        };
        private(&meta)?;
        Ok(Self {
            opener: Opener::new(fd.as_fd()).map_err(|e| OpenError::Io(e.into()))?,
            fd,
            hidden: Some(hidden),
            links_counted: counts_links(&meta),
            bounds: Bounds {
                hidden: Some(meta.id),
                ..bounds
            },
            changed: AtomicBool::new(false),
            policy,
        })
    }

    fn open_root(path: &Path) -> Result<OwnedFd, OpenError> {
        rustix::fs::open(path, ROOT, Mode::empty()).map_err(|e| OpenError::Io(e.into()))
    }

    /// The root's device and mount.
    fn bounds_of(fd: &OwnedFd) -> Result<Bounds, OpenError> {
        let meta = meta_of(fd.as_fd()).map_err(|e| OpenError::Io(e.into()))?;
        Ok(Bounds {
            dev: meta.id.dev,
            mount: meta.mount,
            hidden: None,
        })
    }

    /// The policy this root judges paths by.
    #[must_use]
    pub const fn policy(&self) -> NamePolicy {
        self.policy
    }

    /// Whether the hidden directory is still the one this root opened: its
    /// name leads to a directory of the identity noted, and the directory
    /// held is still linked (a removed one, whose inode number a new
    /// directory took, is not). Once it is not, the root refuses for good: it
    /// must be opened again. A [`Dir`] handed out before keeps working; it
    /// was checked when it was resolved.
    fn verify(&self) -> Result<(), ResolveError> {
        let (Some(id), Some(held)) = (self.bounds.hidden, self.hidden.as_ref()) else {
            return Ok(());
        };
        if self.changed.load(Ordering::Relaxed) {
            return Err(ResolveError::RootChanged);
        }
        let named = match meta_at(self.fd.as_fd(), HIDDEN_DIR) {
            Ok(named) => Some(named),
            Err(Errno::NOENT) => None,
            Err(e) => return Err(io_error(e)),
        };
        let held = meta_of(held.as_fd()).map_err(io_error)?;
        if still_held(named.as_ref(), &held, id, self.links_counted) {
            Ok(())
        } else {
            self.changed.store(true, Ordering::Relaxed);
            Err(ResolveError::RootChanged)
        }
    }

    /// The hidden directory, through the descriptor this root holds.
    ///
    /// # Errors
    /// [`ResolveError::RootChanged`] when it was removed or replaced, or the
    /// system's refusal.
    pub fn hidden_dir(&self) -> Result<Dir, ResolveError> {
        self.verify()?;
        let held = self.hidden.as_ref().ok_or(ResolveError::NotFound)?;
        let fd = rustix::io::fcntl_dupfd_cloexec(held, 0).map_err(io_error)?;
        Ok(self.dir(fd))
    }

    fn dir(&self, fd: OwnedFd) -> Dir {
        Dir {
            fd,
            bounds: self.bounds,
            policy: self.policy,
        }
    }

    /// The directory that holds `path`'s last component, and that component.
    /// Each directory on the way is opened in the one before, never through
    /// a symbolic link, never across a mount point (by mount ID where Linux
    /// reports one, else by device, which misses a bind mount of the root's
    /// own file system), and never into another folder or the hidden
    /// directory; with [`Create::Directories`], one that is missing is made.
    /// A path admitted by another policy is judged again by this root's.
    ///
    /// # Errors
    /// [`ResolveError::RootChanged`] when the hidden directory was removed
    /// or replaced, else the first refusal on the way.
    pub fn parent(&self, path: &IndexPath, create: Create) -> Result<(Dir, Name), ResolveError> {
        check_policy(path, self.policy)?;
        self.verify()?;
        let mut on_the_way = path.names();
        let last = on_the_way.next_back().unwrap_or_default();
        let name = self.policy.name(last).map_err(ResolveError::Unstorable)?;
        let mut held: Option<OwnedFd> = None;
        for component in on_the_way {
            let at = held.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
            held = Some(self.step(at, component, create)?);
        }
        let fd = match held {
            Some(fd) => fd,
            None => rustix::io::fcntl_dupfd_cloexec(&self.fd, 0).map_err(io_error)?,
        };
        Ok((self.dir(fd), name))
    }

    /// One directory on the way: opened (made first when missing and asked
    /// for), then checked.
    fn step(
        &self,
        at: BorrowedFd<'_>,
        name: &str,
        create: Create,
    ) -> Result<OwnedFd, ResolveError> {
        let fd = match self.opener.open_dir(at, name) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if create == Create::Directories => {
                match rustix::fs::mkdirat(at, name, DIRECTORY_MODE) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(on_the_way(at, name, e)),
                }
                self.opener
                    .open_dir(at, name)
                    .map_err(|e| on_the_way(at, name, e))?
            }
            Err(e) => return Err(on_the_way(at, name, e)),
        };
        self.bounds.check(&meta_of(fd.as_fd()).map_err(io_error)?)?;
        match meta_at(fd.as_fd(), HIDDEN_DIR) {
            Ok(meta) if meta.file_type == FileType::Directory => Err(ResolveError::NestedFolder),
            Ok(_) | Err(Errno::NOENT) => Ok(fd),
            Err(e) => Err(io_error(e)),
        }
    }
}

/// A root that neither makes nor checks a hidden directory, for the tests of
/// mounts and devices at system directories (`/`, `/dev`), where nothing may
/// be made. Compiled only in this crate's own test build.
#[cfg(test)]
impl Root {
    pub(super) fn open_unmarked(path: &Path, policy: NamePolicy) -> Result<Self, OpenError> {
        let fd = Self::open_root(path)?;
        let bounds = Self::bounds_of(&fd)?;
        Ok(Self {
            opener: Opener::new(fd.as_fd()).map_err(|e| OpenError::Io(e.into()))?,
            fd,
            hidden: None,
            links_counted: false,
            bounds,
            changed: AtomicBool::new(false),
            policy,
        })
    }
}

/// The test-only switch to the walk: compiled only in this crate's own test
/// build (`cfg(test)`), so that no other build can reach it.
#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
impl Root {
    /// Makes this root walk with `openat`, as on a kernel without `openat2`.
    pub(super) fn force_walk(&mut self) {
        self.opener.force_walk();
    }

    /// Whether this root walks.
    pub(super) fn walks(&self) -> bool {
        self.opener.walks()
    }

    /// How many directories this root opened by `openat2`.
    pub(super) fn by_openat2(&self) -> usize {
        self.opener.by_openat2()
    }

    /// How many directories this root walked to after `openat2` gave up.
    pub(super) fn fell_back(&self) -> usize {
        self.opener.fell_back()
    }
}

/// A directory beneath (or at) a folder's root, held open; every name in it
/// is reached through it.
#[derive(Debug)]
pub struct Dir {
    fd: OwnedFd,
    bounds: Bounds,
    policy: NamePolicy,
}

impl Dir {
    /// A name admitted by another policy, judged again by this directory's.
    fn admit(&self, name: &Name) -> Result<(), ResolveError> {
        if name.policy() != self.policy {
            self.policy
                .name(name.as_str())
                .map_err(ResolveError::Unstorable)?;
        }
        Ok(())
    }

    /// What is at `name`, without following it: `None` when nothing is.
    ///
    /// # Errors
    /// [`ResolveError::Unstorable`] for a name this directory's policy
    /// refuses, [`ResolveError::Symlink`], [`ResolveError::Special`],
    /// [`ResolveError::OtherFileSystem`] (a mount point),
    /// [`ResolveError::HiddenDirectory`], or the system's refusal.
    pub fn stat(&self, name: &Name) -> Result<Option<Entry>, ResolveError> {
        self.admit(name)?;
        match meta_at(self.fd.as_fd(), name.as_str()) {
            Ok(meta) => self.bounds.entry(&meta).map(Some),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(classify(e)),
        }
    }

    /// Opens the file at `name` to read it, never following it, and only if
    /// it is still the regular file `expect` describes, on the root's mount:
    /// the same identity, size, times, mode and links.
    ///
    /// # Errors
    /// [`ResolveError::Changed`] when it is not, [`ResolveError::Symlink`]
    /// and [`ResolveError::Special`] for what is never read,
    /// [`ResolveError::OtherFileSystem`], [`ResolveError::NotFound`] when it
    /// is gone, [`ResolveError::Unstorable`] for a name this directory's
    /// policy refuses, or the system's refusal.
    pub fn open_file(&self, name: &Name, expect: &Entry) -> Result<File, ResolveError> {
        self.admit(name)?;
        let fd = rustix::fs::openat(&self.fd, name.as_str(), FILE, Mode::empty()).map_err(|e| {
            match e {
                // A socket: Linux says ENXIO, macOS EOPNOTSUPP.
                Errno::NXIO | Errno::OPNOTSUPP => ResolveError::Special,
                e => classify(e),
            }
        })?;
        let found = self.bounds.entry(&meta_of(fd.as_fd()).map_err(io_error)?)?;
        if found.kind != Kind::File || found != *expect {
            return Err(ResolveError::Changed);
        }
        Ok(File::from(fd))
    }

    /// The names in this directory, raw, as the file system lists them,
    /// without `.` and `..`; [`NamePolicy::from_disk`] reads them. An `Err`
    /// item means the listing could not go on, so it is incomplete: it never
    /// means that the names not listed were removed.
    ///
    /// # Errors
    /// The system's refusal to read the directory.
    pub fn entries(&self) -> Result<Entries, ResolveError> {
        rustix::fs::Dir::read_from(&self.fd)
            .map(|dir| Entries { dir })
            .map_err(io_error)
    }
}

/// The names in a directory ([`Dir::entries`]).
#[derive(Debug)]
pub struct Entries {
    dir: rustix::fs::Dir,
}

impl Iterator for Entries {
    type Item = Result<Vec<u8>, ResolveError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.dir.read()? {
                Ok(entry) => {
                    let name = entry.file_name().to_bytes();
                    if name != b"." && name != b".." {
                        return Some(Ok(name.to_vec()));
                    }
                }
                Err(e) => return Some(Err(io_error(e))),
            }
        }
    }
}
