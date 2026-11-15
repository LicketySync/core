// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The store's files before SQLite opens them: its directories, the lock that
//! serialises opening, leftovers, a new store built and placed, and the
//! header's verdict on an existing one (the module above says why).

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::{APPLICATION_ID, FORMAT, Foreign, MAGIC, OpenError, SCHEMA, defend, flags, open_error};

/// The names a store at a path uses: the database and, beside it, SQLite's
/// log and journal, the hidden name a new store is built under, and the
/// hidden lock that serialises opening.
#[derive(Debug)]
pub(super) struct Names {
    pub(super) path: PathBuf,
    pub(super) wal: PathBuf,
    pub(super) journal: PathBuf,
    pub(super) temp: PathBuf,
    pub(super) lock: PathBuf,
}

impl Names {
    /// The names of a store at `path`, which is absolute.
    pub(super) fn of(path: &Path) -> Result<Self, OpenError> {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(OpenError::NotAFile);
        };
        let beside = |suffix: &str| {
            let mut n = path.as_os_str().to_owned();
            n.push(suffix);
            PathBuf::from(n)
        };
        let hidden = |suffix: &str| {
            let mut n = OsString::from(".");
            n.push(name);
            n.push(suffix);
            dir.join(n)
        };
        Ok(Self {
            path: path.to_path_buf(),
            wal: beside("-wal"),
            journal: beside("-journal"),
            temp: hidden(".new"),
            lock: hidden(".lock"),
        })
    }

    /// The store's directory.
    pub(super) fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(&self.path)
    }
}

/// A file's device and inode. On Windows, where stable std gives no file ID,
/// every file's is `(0, 0)`, so no check by it catches a file replaced there.
pub(super) type FileId = (u64, u64);

/// The device and inode of what is at `path`, not following a link there.
pub(super) fn file_id(path: &Path) -> Result<FileId, OpenError> {
    let meta = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Ok((0, 0))
    }
}

/// The effective user.
#[cfg(unix)]
fn user() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Whether anything, a link included, is at `path`.
pub(super) fn exists(path: &Path) -> Result<bool, OpenError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Prepares the store's directory `dir`. From the first directory that
/// exists on the way down to it, each must be the user's or root's and
/// closed to writes by group and others unless sticky; those missing are
/// created, mode 0700 (less what the umask removes, as `mkdir` does), each
/// made durable in its parent; and `dir` itself must be the user's and
/// closed to writes by group and others, whatever its sticky bit. Nothing is
/// created before the checks. A link found on the way must be the user's or
/// root's: in a sticky shared directory, such as `/tmp`, another user may
/// plant one, and keep it pointing where they like. A directory the store
/// creates must be one, not a link put in its place meanwhile. Otherwise the
/// directories may be reached through links. On Windows, only that `dir` is
/// a directory, created when absent.
pub(super) fn directories(dir: &Path) -> Result<(), OpenError> {
    let mut missing = Vec::new();
    let mut at = dir;
    let found = loop {
        match fs::metadata(at) {
            Ok(meta) => break meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing.push(at);
                at = at.parent().ok_or(e)?;
            }
            Err(e) => return Err(e.into()),
        }
    };
    if !found.is_dir() {
        return Err(OpenError::NotAFile);
    }
    trusted_link(at)?;
    if missing.is_empty() {
        return private(&found);
    }
    shared(&found)?;
    for (i, made) in missing.iter().rev().enumerate() {
        let meta = make_dir(made)?;
        if i + 1 == missing.len() {
            private(&meta)?;
        } else {
            shared(&meta)?;
        }
    }
    Ok(())
}

/// Refuses a link at `path` that is neither the user's nor root's. Unix
/// only.
fn trusted_link(path: &Path) -> Result<(), OpenError> {
    let meta = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    if meta.file_type().is_symlink() {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != user() && meta.uid() != 0 {
            return Err(OpenError::NotOwned);
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

/// The store's own directory: the user's, closed to group and others.
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "it checks only on Unix")
)]
fn private(meta: &fs::Metadata) -> Result<(), OpenError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != user() {
            return Err(OpenError::NotOwned);
        }
        if meta.mode() & 0o022 != 0 {
            return Err(OpenError::Exposed);
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

/// A directory above the store's: the user's or root's, closed to group and
/// others unless sticky (where none may rename or remove another's entry).
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "it checks only on Unix")
)]
fn shared(meta: &fs::Metadata) -> Result<(), OpenError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != user() && meta.uid() != 0 {
            return Err(OpenError::NotOwned);
        }
        if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return Err(OpenError::Exposed);
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

/// Creates one directory, mode 0700, and makes it durable in its parent; one
/// made meanwhile by another is taken as it is. Either way, what is there now
/// must be a directory, not a link: its metadata, not following a link, for
/// the caller's checks.
pub(super) fn make_dir(dir: &Path) -> Result<fs::Metadata, OpenError> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    match builder.create(dir) {
        Ok(()) => sync_parent(dir)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(OpenError::Symlink);
    }
    if !meta.is_dir() {
        return Err(OpenError::NotAFile);
    }
    Ok(meta)
}

/// Makes `path`'s entry in its directory durable (`fsync` on the directory).
/// Windows opens no directory as a file and its file systems journal names,
/// so there it does nothing.
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "it checks only on Unix")
)]
pub(super) fn sync_parent(path: &Path) -> Result<(), OpenError> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Opens `path` to read, not following a link there and not blocking on a
/// FIFO: `None` when nothing is there. On Linux and Android the name is
/// examined first (`O_PATH`, then `fstat`), so a device node or FIFO is never
/// opened, and the file opened must be the one examined. Elsewhere on Unix
/// the file is opened (`O_NONBLOCK`) and examined after; on Windows a link or
/// anything but a regular file is refused by a look first, which a race can
/// pass.
#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<Option<File>, OpenError> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;
    let errno = |e: Errno| match e {
        Errno::LOOP => OpenError::Symlink,
        Errno::NXIO => OpenError::NotAFile,
        e => OpenError::Io(io::Error::from(e).to_string()),
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let examined = {
        use rustix::fs::FileType;
        let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match rustix::fs::open(path, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(errno(e)),
        };
        let stat = rustix::fs::fstat(&fd).map_err(errno)?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => return Err(OpenError::Symlink),
            FileType::RegularFile => {}
            _ => return Err(OpenError::NotAFile),
        }
        (stat.st_dev, stat.st_ino)
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(errno(e)),
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let stat = rustix::fs::fstat(&fd).map_err(errno)?;
        if examined != (stat.st_dev, stat.st_ino) {
            return Err(OpenError::Io("a file was replaced as it was opened".into()));
        }
    }
    Ok(Some(File::from(fd)))
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> Result<Option<File>, OpenError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(OpenError::Symlink),
        // Windows opens no directory as a file: refused as what it is.
        Ok(meta) if !meta.is_file() => return Err(OpenError::NotAFile),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    Ok(Some(File::open(path)?))
}

/// Refuses a file that is not regular, not the user's (Unix), or, `one_name`,
/// that has another name besides.
fn own(meta: &fs::Metadata, one_name: bool) -> Result<(), OpenError> {
    if !meta.is_file() {
        return Err(OpenError::NotAFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != user() {
            return Err(OpenError::NotOwned);
        }
        if one_name && meta.nlink() != 1 {
            return Err(OpenError::NotAFile);
        }
    }
    #[cfg(not(unix))]
    let _ = one_name;
    Ok(())
}

/// Opens one of the store's files, `None` when absent, refusing a link, a
/// file that is not regular or has another name, and, on Unix, one that is
/// not the user's.
pub(super) fn open_own(path: &Path) -> Result<Option<File>, OpenError> {
    let Some(file) = open_nofollow(path)? else {
        return Ok(None);
    };
    named(file)
}

/// `file`, just opened at one of the store's names, refused by [`own`] or
/// kept; `None` when, on Unix, it has no name left: removed since it was
/// opened, it is absent, as one removed before is. Another process's SQLite
/// removes the store's journal and log as it opens and closes the store.
pub(super) fn named(file: File) -> Result<Option<File>, OpenError> {
    let meta = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() == 0 {
            return Ok(None);
        }
    }
    own(&meta, true)?;
    Ok(Some(file))
}

/// Takes the group and other bits from one of the store's own files: mode
/// 0600. Owner bits are left: a store its owner made read-only stays so.
/// Unix only.
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "it checks only on Unix")
)]
pub(super) fn tighten(file: &File) -> Result<(), OpenError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// The header's verdict on the file at `path`: this store, or what it is
/// instead. Reads the first 100 bytes of the main file only, not following a
/// link; the connection checks the IDs again through SQLite, which reads the
/// log too.
pub(super) fn judge(path: &Path) -> Result<(), OpenError> {
    let Some(file) = open_own(path)? else {
        return Err(OpenError::Io("the store vanished as it was opened".into()));
    };
    verdict(&header(&file)?)?;
    tighten(&file)
}

/// A first look at what is at `path`, before anything is made beside it:
/// nothing, or a file with this store's header; anything else is refused as
/// [`judge`] refuses it, so that nothing is made beside a file refused. A
/// second name, which a placement cut short leaves, is left to [`judge`],
/// once [`create`] has removed it.
pub(super) fn glance(path: &Path) -> Result<(), OpenError> {
    let Some(file) = open_nofollow(path)? else {
        return Ok(());
    };
    own(&file.metadata()?, false)?;
    verdict(&header(&file)?)
}

/// The first 100 bytes of `file`: the database header, or less.
fn header(file: &File) -> Result<Vec<u8>, OpenError> {
    let mut header = Vec::with_capacity(100);
    file.take(100).read_to_end(&mut header)?;
    Ok(header)
}

/// What a database header says: this store, or what the file is instead.
pub(super) fn verdict(header: &[u8]) -> Result<(), OpenError> {
    let field = |at: usize| -> Option<u32> {
        let bytes: [u8; 4] = header.get(at..at + 4)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    };
    if header.is_empty() {
        return Err(OpenError::NotAStore(Foreign::Empty));
    }
    let (Some(version), Some(id)) = (field(60), field(68)) else {
        return Err(OpenError::NotAStore(Foreign::NotSqlite));
    };
    if !header.starts_with(MAGIC) {
        return Err(OpenError::NotAStore(Foreign::NotSqlite));
    }
    if id.to_be_bytes() != APPLICATION_ID.to_be_bytes() {
        return Err(OpenError::NotAStore(Foreign::OtherProgram));
    }
    if version.to_be_bytes() != FORMAT.to_be_bytes() {
        return Err(OpenError::NotAStore(Foreign::OtherFormat(version)));
    }
    Ok(())
}

/// The open lock, held until dropped: an exclusive lock on the hidden
/// `.<name>.lock` beside the store, a file of its own, so that the database's
/// POSIX locks are never touched. It stays when released.
#[derive(Debug)]
pub(super) struct OpenLock(#[allow(dead_code, reason = "held for its lock")] File);

/// Takes the open lock at `lock`, waiting for another opener, in this process
/// or another, to have opened the store or failed. The name is opened without
/// following a link, created mode 0600, and must be a regular file of the
/// user's.
pub(super) fn lock_open(lock: &Path) -> Result<OpenLock, OpenError> {
    match fs::symlink_metadata(lock) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(OpenError::Symlink),
        Ok(meta) => own(&meta, false)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let file = open_lock(lock)?;
    own(&file.metadata()?, false)?;
    file.lock()?;
    Ok(OpenLock(file))
}

#[cfg(unix)]
fn open_lock(lock: &Path) -> Result<File, OpenError> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::open(lock, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::LOOP) => Err(OpenError::Symlink),
        Err(e) => Err(OpenError::Io(io::Error::from(e).to_string())),
    }
}

#[cfg(not(unix))]
fn open_lock(lock: &Path) -> Result<File, OpenError> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock)?)
}

/// Makes a new store at `names.path` unless one is there (module
/// documentation, "Opening"), under the open lock, `_held`. A temporary name
/// that is a second name of the store, which a placement by hard link can
/// leave when it stops between the link and the removal, is removed. A `-wal`
/// or `-journal` already at the path's names is refused, named and untouched:
/// it belongs to a store or database that is gone, and SQLite would read it
/// into the new one.
pub(super) fn create(names: &Names, _held: &OpenLock) -> Result<(), OpenError> {
    if exists(&names.path)? {
        if exists(&names.temp)? && file_id(&names.temp)? == file_id(&names.path)? {
            fs::remove_file(&names.temp)?;
        }
        return Ok(());
    }
    for side in [&names.wal, &names.journal] {
        if exists(side)? {
            return Err(OpenError::Leftover(side.clone()));
        }
    }
    remove_leftover(&names.temp)?;
    let (file, id) = new_file(&names.temp)?;
    let made = build(&names.temp)
        .and_then(|()| flush(file))
        .and_then(|()| place(&names.temp, id, &names.path));
    if made.is_err() {
        // Ours, under the lock; another program's file in its place is kept.
        if file_id(&names.temp).is_ok_and(|now| now == id) {
            let _ = fs::remove_file(&names.temp);
        }
    }
    made?;
    sync_parent(&names.path)
}

/// Removes, under the open lock, a temporary file a crash left: a regular
/// file of the user's that is empty or starts as an SQLite database does.
/// Anything else at that name is refused and left.
fn remove_leftover(temp: &Path) -> Result<(), OpenError> {
    let meta = match fs::symlink_metadata(temp) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(OpenError::Symlink);
    }
    own(&meta, false)?;
    let mut start = Vec::with_capacity(MAGIC.len());
    if let Some(file) = open_nofollow(temp)? {
        (&file).take(16).read_to_end(&mut start)?;
    }
    if !MAGIC.starts_with(&start) {
        return Err(OpenError::Leftover(temp.to_path_buf()));
    }
    fs::remove_file(temp)?;
    Ok(())
}

/// Creates the temporary file, mode 0600, never through a link
/// (`O_CREAT|O_EXCL`); returns it, open to write, and its device and inode.
fn new_file(temp: &Path) -> Result<(File, FileId), OpenError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The mode exactly, whatever the umask.
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let id = file_id(temp)?;
    Ok((file, id))
}

/// The new store's table and IDs, written with the journal in memory (a
/// crash leaves only the temporary file, which the next creation removes)
/// and closed, so that the header carries the IDs. `auto_vacuum` can only be
/// set before the first table.
pub(super) fn build(temp: &Path) -> Result<(), OpenError> {
    let conn = Connection::open_with_flags(temp, flags()).map_err(|e| open_error(&e))?;
    defend(&conn)?;
    conn.execute_batch(&format!(
        "PRAGMA journal_mode = MEMORY; PRAGMA auto_vacuum = INCREMENTAL; {SCHEMA}; \
         PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {FORMAT};"
    ))
    .map_err(|e| open_error(&e))?;
    conn.close().map_err(|(_, e)| open_error(&e))
}

/// Flushes the temporary file through the handle that created it, then
/// closes it: Windows flushes only a file open to write (`FlushFileBuffers`).
/// [`place`] then checks that the name still holds that file.
fn flush(file: File) -> Result<(), OpenError> {
    file.sync_all()?;
    drop(file);
    Ok(())
}

fn replaced(temp: &Path) -> OpenError {
    OpenError::Io(format!(
        "the new store's temporary file {} was replaced or removed",
        temp.display()
    ))
}

/// Gives the built store its name, only while `temp` is still the file built
/// (device and inode), and never over anything at `path`: a file another
/// program put there first is kept, and judged as any, and `temp` removed.
pub(super) fn place(temp: &Path, id: FileId, path: &Path) -> Result<(), OpenError> {
    if file_id(temp)? != id {
        return Err(replaced(temp));
    }
    match rename_noreplace(temp, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(temp)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Renames `from` to `to` unless something is at `to`: `renameat2`'s
/// `RENAME_NOREPLACE` on Linux and Android, `renameatx_np`'s `RENAME_EXCL` on
/// macOS and iOS. A file system that refuses the flag gets a hard link
/// instead.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(e) if refuses_flag(e) => link_noreplace(from, to),
        Err(e) => Err(e.into()),
    }
}

/// Whether a no-replace rename failed because the file system refuses the
/// flag: `EINVAL` on Linux and Android (some network and FUSE file systems),
/// `ENOTSUP` on macOS and iOS (a volume without `VOL_CAP_INT_RENAME_EXCL`).
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub(super) fn refuses_flag(e: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    matches!(e, Errno::INVAL | Errno::NOTSUP)
}

/// A hard link, then the old name removed: Windows, whose non-replacing
/// move (`MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`) needs a platform
/// crate that phase 3 brings.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    link_noreplace(from, to)
}

/// `to` made a second name of `from`, which fails rather than replace
/// anything, then `from` removed.
fn link_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}
