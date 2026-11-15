// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Linux's parts of the resolver: opening one directory on the way by
//! `openat2`, which refuses a symbolic link, a magic link and a mount point
//! in the same call, where the kernel has it; and looking at a name or a
//! descriptor by `statx`, which reports the mount ID (5.8 and later).

use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU8, Ordering};

use rustix::fs::{AtFlags, FileType, Mode, ResolveFlags, StatxFlags, StatxTimestamp};
use rustix::io::Errno;

use super::unix::{DIRECTORY, Meta, meta_from_stat, walk_open};
use super::{CROSSES_MOUNTS, FileId, Time};

/// Tries of `openat2` on one component that `EAGAIN` allows before that
/// component is opened by the walk: the kernel returns `EAGAIN` when a rename
/// raced the lookup.
const OPENAT2_TRIES: usize = 3;

/// Whether `openat2` may be tried again after `e`: only after a race.
fn retries(e: Errno) -> bool {
    e == Errno::AGAIN
}

/// Whether a system call failed because this process cannot make it at all:
/// the kernel lacks it (`ENOSYS`), or a seccomp filter refuses it (`EPERM`).
fn unavailable(e: Errno) -> bool {
    matches!(e, Errno::NOSYS | Errno::PERM)
}

/// The resolution flags of every `openat2`: the component stays beneath its
/// directory, and neither a symbolic link, a magic link (`/proc/*/fd`) nor,
/// unless [`CROSSES_MOUNTS`], a mount point is crossed.
fn resolve_flags() -> ResolveFlags {
    let flags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);
    if CROSSES_MOUNTS {
        flags
    } else {
        flags.union(ResolveFlags::NO_XDEV)
    }
}

/// How one root opens the directories on the way.
#[derive(Debug)]
pub(super) struct Opener {
    /// The walk, for a root whose kernel refused `openat2` when it opened.
    walk: bool,
    /// Directories opened by `openat2`, and by the walk after `openat2`
    /// gave up on them, so that the tests can tell which way a root went.
    #[cfg(test)]
    by_openat2: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fell_back: std::sync::atomic::AtomicUsize,
}

impl Opener {
    /// The way for the root `root`, decided once: `openat2`, unless an
    /// `openat2` of the root itself shows the call unavailable (`ENOSYS`
    /// before 5.6, `EPERM` under a seccomp filter), and then the walk.
    ///
    /// # Errors
    /// Any other failure of that `openat2`, which is the open's.
    pub(super) fn new(root: BorrowedFd<'_>) -> Result<Self, Errno> {
        let walk = match rustix::fs::openat2(root, ".", DIRECTORY, Mode::empty(), resolve_flags()) {
            Ok(_) => false,
            Err(e) if unavailable(e) => true,
            Err(e) => return Err(e),
        };
        Ok(Self {
            walk,
            #[cfg(test)]
            by_openat2: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fell_back: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The directory `name` in `at`, never through a symbolic link. A
    /// refusal, `EPERM` included, is this directory's, not the root's.
    pub(super) fn open_dir(&self, at: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
        if !self.walk {
            for _ in 0..OPENAT2_TRIES {
                match rustix::fs::openat2(at, name, DIRECTORY, Mode::empty(), resolve_flags()) {
                    Ok(fd) => {
                        #[cfg(test)]
                        self.by_openat2
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(fd);
                    }
                    Err(e) => {
                        if !retries(e) {
                            return Err(e);
                        }
                    }
                }
            }
            #[cfg(test)]
            self.fell_back
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        walk_open(at, name)
    }
}

/// The test-only switch to the walk, and what the tests read: none of it is
/// compiled outside this crate's own test build (`cfg(test)`), so no other
/// build, a release, a dependent crate's tests or a fuzz target, can reach
/// it.
#[cfg(test)]
impl Opener {
    pub(super) fn force_walk(&mut self) {
        self.walk = true;
    }

    pub(super) fn walks(&self) -> bool {
        self.walk
    }

    pub(super) fn by_openat2(&self) -> usize {
        self.by_openat2.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn fell_back(&self) -> usize {
        self.fell_back.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Whether this process can use `statx`: decided by its first answer, as
/// Rust's std decides, and kept for the process. Until then [`UNKNOWN`].
static STATX: StatxSupport = StatxSupport(AtomicU8::new(UNKNOWN));

const UNKNOWN: u8 = 0;
const AVAILABLE: u8 = 1;
const UNAVAILABLE: u8 = 2;

/// Whether `statx` works here, once known.
struct StatxSupport(AtomicU8);

impl StatxSupport {
    /// One look: by `statx` while it is available or not yet known, else
    /// by `stat`. The first `statx` that succeeds makes it available for
    /// good. One that fails as [`unavailable`] before any succeeded is
    /// confirmed first by `confirm`, a `statx` of the same descriptor that
    /// asks the file system nothing (`AT_STATX_DONT_SYNC`), since a FUSE
    /// server can answer one look with `EPERM` or `ENOSYS`: if that succeeds,
    /// `statx` is available and the look's own answer stands; if it fails as
    /// unavailable too, `statx` is unavailable for good, unless another look
    /// found it available meanwhile, and the look is made by `stat`. Once
    /// `statx` is known to work, its `EPERM` is that look's refusal.
    fn look<T>(
        &self,
        statx: impl FnOnce() -> Result<T, Errno>,
        confirm: impl FnOnce() -> Result<(), Errno>,
        stat: impl FnOnce() -> Result<T, Errno>,
    ) -> Result<T, Errno> {
        let known = self.0.load(Ordering::Relaxed);
        if known == UNAVAILABLE {
            return stat();
        }
        match statx() {
            Ok(found) => {
                self.0.store(AVAILABLE, Ordering::Relaxed);
                Ok(found)
            }
            Err(e) if known == UNKNOWN && unavailable(e) => match confirm() {
                Ok(()) => {
                    self.0.store(AVAILABLE, Ordering::Relaxed);
                    Err(e)
                }
                Err(again) if unavailable(again) => {
                    let decided = self.0.compare_exchange(
                        UNKNOWN,
                        UNAVAILABLE,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                    match decided {
                        Ok(_) | Err(UNAVAILABLE) => stat(),
                        Err(_) => Err(e),
                    }
                }
                Err(_) => Err(e),
            },
            Err(e) => Err(e),
        }
    }
}

/// The flags of the confirming `statx`: the descriptor itself, without
/// asking the file system to sync.
#[cfg(target_os = "linux")]
const CONFIRM: AtFlags = AtFlags::EMPTY_PATH.union(AtFlags::STATX_DONT_SYNC);

/// On Android, whose C library rustix does not take `AT_STATX_DONT_SYNC`
/// from, the descriptor itself, as the file system answers.
#[cfg(target_os = "android")]
const CONFIRM: AtFlags = AtFlags::EMPTY_PATH;

/// The confirming `statx` of [`StatxSupport::look`]: what kind of file the
/// descriptor is.
fn confirm(fd: BorrowedFd<'_>) -> Result<FileType, Errno> {
    let st = rustix::fs::statx(fd, "", CONFIRM, StatxFlags::TYPE)?;
    Ok(FileType::from_raw_mode(u32::from(st.stx_mode)))
}

/// What is at `name` in `dir`, without following it or starting an
/// automount.
pub(super) fn meta_at(dir: BorrowedFd<'_>, name: &str) -> Result<Meta, Errno> {
    let flags = AtFlags::SYMLINK_NOFOLLOW.union(AtFlags::NO_AUTOMOUNT);
    STATX.look(
        || meta_from_statx(&rustix::fs::statx(dir, name, flags, wanted())?),
        || confirm(dir).map(|_| ()),
        || meta_from_stat(&rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?),
    )
}

/// What the descriptor `fd` is.
pub(super) fn meta_of(fd: BorrowedFd<'_>) -> Result<Meta, Errno> {
    let flags = AtFlags::EMPTY_PATH.union(AtFlags::NO_AUTOMOUNT);
    STATX.look(
        || meta_from_statx(&rustix::fs::statx(fd, "", flags, wanted())?),
        || confirm(fd).map(|_| ()),
        || meta_from_stat(&rustix::fs::fstat(fd)?),
    )
}

/// What every look asks `statx` for: the basic fields and the mount ID.
fn wanted() -> StatxFlags {
    StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID)
}

/// The fields a look needs `statx` to have filled in: its type, mode,
/// inode, link count, owner, size and two times. The mount ID is optional.
fn needed() -> StatxFlags {
    StatxFlags::TYPE
        .union(StatxFlags::MODE)
        .union(StatxFlags::INO)
        .union(StatxFlags::NLINK)
        .union(StatxFlags::UID)
        .union(StatxFlags::SIZE)
        .union(StatxFlags::MTIME)
        .union(StatxFlags::CTIME)
}

/// Whether a `statx` answer whose mask is `mask` filled in every field a
/// look needs: one that did not is refused (`ENODATA`), never read as zeros.
fn complete(mask: u32) -> Result<StatxFlags, Errno> {
    let reported = StatxFlags::from_bits_retain(mask);
    if reported.contains(needed()) {
        Ok(reported)
    } else {
        Err(Errno::NODATA)
    }
}

fn meta_from_statx(st: &rustix::fs::Statx) -> Result<Meta, Errno> {
    let reported = complete(st.stx_mask)?;
    let time = |t: StatxTimestamp| Time {
        secs: t.tv_sec,
        nanos: t.tv_nsec,
    };
    Ok(Meta {
        file_type: FileType::from_raw_mode(u32::from(st.stx_mode)),
        id: FileId {
            dev: rustix::fs::makedev(st.stx_dev_major, st.stx_dev_minor),
            ino: st.stx_ino,
        },
        mount: reported
            .contains(StatxFlags::MNT_ID)
            .then_some(st.stx_mnt_id),
        size: st.stx_size,
        mtime: time(st.stx_mtime),
        ctime: time(st.stx_ctime),
        mode: u32::from(st.stx_mode) & 0o7777,
        nlink: u64::from(st.stx_nlink),
        uid: st.stx_uid,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn only_a_race_is_tried_again() {
        assert!(retries(Errno::AGAIN));
        for e in [
            Errno::NOSYS,
            Errno::PERM,
            Errno::LOOP,
            Errno::XDEV,
            Errno::NOENT,
            Errno::NOTDIR,
            Errno::ACCESS,
        ] {
            assert!(!retries(e), "{e:?}");
        }
    }

    #[test]
    fn a_call_is_unavailable_only_when_the_kernel_lacks_it_or_a_filter_refuses_it() {
        assert!(unavailable(Errno::NOSYS));
        assert!(unavailable(Errno::PERM));
        for e in [
            Errno::AGAIN,
            Errno::ACCESS,
            Errno::NOENT,
            Errno::LOOP,
            Errno::INVAL,
        ] {
            assert!(!unavailable(e), "{e:?}");
        }
    }

    /// The statx decision, on stubs: the first answer decides for good, a
    /// refusal only once a look of the descriptor confirms it.
    #[test]
    fn statx_is_decided_once_and_stat_takes_over_only_if_it_is_unavailable() {
        let ok = || Ok(());
        for refusal in [Errno::NOSYS, Errno::PERM] {
            let refused = StatxSupport(AtomicU8::new(UNKNOWN));
            assert_eq!(
                refused.look(|| Err(refusal), || Err(refusal), || Ok(2)),
                Ok(2)
            );
            assert_eq!(refused.0.load(Ordering::Relaxed), UNAVAILABLE);
            // Decided: statx is not tried again.
            let again = refused.look(
                || -> Result<u8, Errno> { panic!("statx tried again") },
                || panic!("confirmed again"),
                || Ok(3),
            );
            assert_eq!(again, Ok(3));
        }
        // A FUSE server's EPERM for one look, while a look that asks it
        // nothing works: statx is available, and the look's EPERM stands.
        let fuse = StatxSupport(AtomicU8::new(UNKNOWN));
        assert_eq!(
            fuse.look(|| Err(Errno::PERM), ok, || Ok(2)),
            Err(Errno::PERM)
        );
        assert_eq!(fuse.0.load(Ordering::Relaxed), AVAILABLE);
        assert_eq!(fuse.look(|| Ok(1), ok, || Ok(2)), Ok(1));
        // The confirming look fails otherwise: nothing is decided.
        let unsure = StatxSupport(AtomicU8::new(UNKNOWN));
        let got = unsure.look(|| Err(Errno::PERM), || Err(Errno::IO), || Ok(2));
        assert_eq!(got, Err(Errno::PERM));
        assert_eq!(unsure.0.load(Ordering::Relaxed), UNKNOWN);
        // Another look found statx available meanwhile: not undone.
        let raced = StatxSupport(AtomicU8::new(UNKNOWN));
        let got = raced.look(
            || {
                raced.0.store(AVAILABLE, Ordering::Relaxed);
                Err(Errno::PERM)
            },
            || Err(Errno::PERM),
            || Ok(2),
        );
        assert_eq!(got, Err(Errno::PERM));
        assert_eq!(raced.0.load(Ordering::Relaxed), AVAILABLE);
        let working = StatxSupport(AtomicU8::new(UNKNOWN));
        assert_eq!(working.look(|| Ok(1), ok, || Ok(2)), Ok(1));
        // Once statx works, its EPERM is the look's refusal, not a fallback.
        assert_eq!(
            working.look(|| Err(Errno::PERM), ok, || Ok(2)),
            Err(Errno::PERM)
        );
        assert_eq!(
            working.look(|| Err(Errno::NOENT), ok, || Ok(2)),
            Err(Errno::NOENT)
        );
        // Another error before anything is decided decides nothing.
        let unknown = StatxSupport(AtomicU8::new(UNKNOWN));
        assert_eq!(
            unknown.look(|| Err(Errno::NOENT), ok, || Ok(2)),
            Err(Errno::NOENT)
        );
        assert_eq!(unknown.0.load(Ordering::Relaxed), UNKNOWN);
    }

    /// The confirming look works on this kernel, and sees the descriptor.
    #[test]
    fn the_confirming_look_works_here() {
        use std::os::fd::AsFd;
        let dir = rustix::fs::open(".", DIRECTORY, Mode::empty()).unwrap();
        assert_eq!(confirm(dir.as_fd()), Ok(FileType::Directory));
        let file =
            rustix::fs::open("Cargo.toml", rustix::fs::OFlags::RDONLY, Mode::empty()).unwrap();
        assert_eq!(confirm(file.as_fd()), Ok(FileType::RegularFile));
    }

    /// A statx answer missing a field a look needs is refused, never read
    /// as zeros.
    #[test]
    fn a_statx_answer_without_a_needed_field_is_refused() {
        let full = needed().bits();
        assert_eq!(complete(full), Ok(needed()));
        let with_mount = needed().union(StatxFlags::MNT_ID);
        assert_eq!(complete(with_mount.bits()), Ok(with_mount));
        for missing in [
            StatxFlags::TYPE,
            StatxFlags::MODE,
            StatxFlags::INO,
            StatxFlags::NLINK,
            StatxFlags::UID,
            StatxFlags::SIZE,
            StatxFlags::MTIME,
            StatxFlags::CTIME,
        ] {
            assert_eq!(
                complete(full & !missing.bits()),
                Err(Errno::NODATA),
                "{missing:?}"
            );
        }
        assert!(wanted().contains(needed()));
    }

    #[test]
    fn openat2_stays_beneath_and_crosses_no_link_and_no_mount() {
        assert_eq!(
            resolve_flags(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV
        );
    }

    #[test]
    fn statx_is_asked_for_the_mount_id() {
        assert!(wanted().contains(StatxFlags::MNT_ID));
        assert!(wanted().contains(StatxFlags::BASIC_STATS));
    }
}
