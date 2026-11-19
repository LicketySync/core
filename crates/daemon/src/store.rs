// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The device's store: the engine's [`Storage`] on SQLite, one key-value
//! table in one file whose path the caller gives.
//!
//! # On disk
//!
//! One table, `kv`, of binary keys and values, `WITHOUT ROWID`, so that the
//! table is the key's own B-tree and a scan by prefix is a range of it. The
//! header marks the file as this store: application ID `LkSy` (offset 68) and
//! user version 1 (offset 60), the format.
//!
//! Write-ahead logging with `synchronous = FULL`, and `fullfsync` and
//! `checkpoint_fullfsync` on macOS, whose plain `fsync` leaves the drive's
//! cache unflushed: a commit has reached the disk when [`Storage::commit`]
//! returns, so the engine sends nothing that a crash could take back
//! (`protocol.md` 4.5, "Durability before transmission"). Exclusive locking:
//! one connection holds the store, so a second one, in this process or
//! another, is refused with [`OpenError::Locked`], and SQLite keeps the log's
//! index in its own memory, never in a `-shm` file.
//!
//! # Opening
//!
//! [`SqliteStorage::open`] decides what the file is before SQLite sees it: it
//! reads the main file's first 100 bytes itself, not following a link, and
//! hands SQLite only a file that carries this store's header. Anything else
//! is refused as it is, unopened ([`Foreign`] says why), an empty file
//! included, so neither another program's database nor its log or journal is
//! ever recovered, checkpointed or written. Once SQLite has read the file, its
//! log included, the connection checks the IDs again and the schema, and that
//! the path is still the file judged (device and inode); a connection refused
//! then is closed without a checkpoint. SQLite may already have recovered the
//! file's own log or journal by then: a file with this store's header and
//! another schema ([`Foreign::OtherSchema`]) is judged after that.
//!
//! Every open holds an exclusive lock on a hidden `.<name>.lock` beside the
//! store (a file of its own, so the database's POSIX locks are never touched;
//! it stays) until SQLite holds the store, so openers, in this process and
//! others, open one at a time: one opens the store, and the rest are refused
//! while it stays open. (Two SQLite connections that each took the shared lock
//! before either took the exclusive one would both be refused.) A file already
//! at the path is judged by its header first, so nothing is made beside a file
//! refused. A new store never shows at the path half made, and only one is
//! made: a store another made meanwhile is opened instead. When nothing
//! is at the path: a `-wal` or `-journal` at the store's names is refused,
//! named and untouched ([`OpenError::Leftover`]), since SQLite would read it
//! into the new store, so starting over means removing them too; a temporary
//! file a crash left (`.<name>.new`, empty or starting as an SQLite database
//! does) is removed, and anything else there refused; the store is built under
//! that name (created exclusively, mode 0600), closed so that its header
//! carries the IDs, flushed, and renamed into place without replacing anything
//! (`renameat2`'s `RENAME_NOREPLACE` on Linux and Android, `renameatx_np`'s
//! `RENAME_EXCL` on macOS and iOS; a hard link, which fails rather than
//! replace, on Windows and on file systems that refuse the flag: `EINVAL` on
//! Linux, `ENOTSUP` on macOS), once its device and inode show it is still the
//! file built; and the directory is flushed.
//!
//! The directories the caller gives may be reached through links: where they
//! are is the person's or the platform's choice (iOS's `/var`, Fedora
//! Atomic's `/home`). From the first one that exists on the way down to the
//! store's, each must be the user's or root's and closed to writes by group
//! and others unless sticky, and the store's own directory must be the
//! user's and closed to group and others whatever its sticky bit, as one the
//! store creates is (mode 0700; under a user-private-group umask of 002 a
//! directory made otherwise is 0775, and refused). A link found on the way
//! must be the user's or root's (in a sticky shared directory, such as
//! `/tmp`, another user could plant one and re-point it later), and a
//! directory the store makes must be one, not a link put in its place
//! meanwhile. Nothing the store opens or
//! creates in its directory is followed: this module opens the database,
//! `-wal`, `-journal`, temporary file and lock with `O_NOFOLLOW` and refuses a
//! link at any of those names, its target untouched, and SQLite's Unix VFS
//! opens the log and journal with `O_NOFOLLOW`. SQLite would resolve a link at
//! the database's own name, which the device and inode check after it opens
//! catches. On Linux and Android a name is examined (`O_PATH`) before it is
//! opened to read, so a device node is never opened. On Unix the database,
//! `-wal` and `-journal`, when present, must be regular files of the user's
//! with no other name; their group and other bits are taken away (mode
//! 0600), and their owner bits left. A log or journal that has no name left
//! once opened is absent: another process's SQLite removes them as it opens
//! and closes the store. On Windows a file being removed keeps its name, and
//! refuses every open as access denied, until its last handle closes: a name
//! refused so is looked at again for about a second, and is absent if gone
//! by then; still refused, it fails the open. On Windows, SQLite follows
//! links and the store checks no owner, sets no access list and compares no
//! device and inode, which stable std does not give there (Windows comes
//! with phase 3).
//!
//! The SQLite linked must be the bundled one, built to sync: a different
//! runtime version, or a `NO_SYNC` or `DISABLE_DIRSYNC` build, fails the
//! open. The connection is defensive (`SQLITE_DBCONFIG_DEFENSIVE`,
//! `trusted_schema = OFF`, `cell_size_check = ON`) before it reads anything.
//!
//! # Staged writes
//!
//! A `put` or `delete` opens a transaction if none is open and writes into it,
//! so `get` and `scan` see staged writes at once, and past SQLite's page cache
//! they spill to the log, not to memory; `commit` commits it and `rollback`
//! rolls it back. As the [`Storage`] contract allows, an error may lose every
//! staged write: SQLite rolls the whole transaction back on a full disk, an
//! I/O error (a failed read inside the transaction included) or a failed
//! commit, and from then until [`Storage::rollback`] every call fails with
//! [`StorageError::Io`]. A commit whose log frames were written but whose
//! `fsync` failed reports failure with the batch in the log: the running
//! process does not see it, the next commit that writes overwrites it, and if
//! the process ends first, the next open replays it whole.
//!
//! # What stays on disk
//!
//! The store holds no key (`keys.md` 8.2: the device seed and folder keys come
//! from the configuration); were one ever to enter it, this must change.
//! `secure_delete = FAST` zeroes deleted content in the pages a write touches
//! anyway, and `auto_vacuum = INCREMENTAL` returns free pages to the file
//! system only when an incremental vacuum runs, which is the daemon's to run;
//! so a deleted record or chunk can stay on the disk, in free pages, in the
//! log until it is checkpointed and overwritten, and in the file system's own
//! copies.
//!
//! # Hazards
//!
//! POSIX locks belong to the process and go when any of its handles to the
//! file closes: while the store is open, nothing in the daemon may open and
//! close its database or log through another handle, a file-ID check
//! included, or the exclusive lock is silently lost. A second
//! [`SqliteStorage::open`] of a store open in this process is refused by its
//! device and inode before it opens any of the store's files. (Windows's
//! locks belong to the handle, and there SQLite refuses the second.) The
//! daemon never reopens the store beneath a live engine: a failed commit's
//! batch may be replayed by the reopening, under an engine that rolled it
//! back. A corrupt page fails the read that meets it (`Io`), so the folder
//! whose records lie there does not open: the engine's per-record check
//! (TM-17's recovery) is never reached, and nothing here repairs the file.
//!
//! The format is read from the main file's header before SQLite opens it, and
//! again through SQLite, the log included, after: a later format that changes
//! the user version must keep the second check.

#[cfg(unix)]
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Mutex;
use std::time::Duration;

use licketysync_engine::runtime::{Entry, Storage, StorageError};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, ffi};

mod files;
#[cfg(test)]
mod tests;

use files::{FileId, Names};

/// The table, exactly as `sqlite_schema` keeps it.
const SCHEMA: &str = "CREATE TABLE kv (k BLOB PRIMARY KEY NOT NULL, v BLOB NOT NULL) WITHOUT ROWID";

/// The first 16 bytes of every SQLite database.
const MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// The database header's application ID that marks this store: `LkSy` in ASCII.
const APPLICATION_ID: i32 = 0x4c6b_5379;

/// The store's format, in the header's user version.
const FORMAT: i32 = 1;

/// The log's size kept after a checkpoint: a large transaction grows it, and
/// without a limit it would keep that size until the store closes.
const LOG_SIZE_LIMIT: i64 = 64 << 20;

/// Why every call fails until a rollback.
const LOST: &str = "the staged writes were lost after an error; roll back first";

/// What a file at the store's path is instead of this store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Foreign {
    /// An empty file.
    Empty,
    /// Not an SQLite database: shorter than its header, or another header.
    NotSqlite,
    /// An SQLite database of another program: another application ID.
    OtherProgram,
    /// This store in another format: the user version it carries.
    OtherFormat(u32),
    /// This store's header over another schema. Judged once SQLite has opened
    /// the file, which may have recovered its log or journal by then.
    OtherSchema,
}

impl fmt::Display for Foreign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an empty file"),
            Self::NotSqlite => f.write_str("not an SQLite database"),
            Self::OtherProgram => f.write_str("another program's database"),
            Self::OtherFormat(v) => write!(f, "a LicketySync store of format {v}"),
            Self::OtherSchema => f.write_str("a LicketySync store with another schema"),
        }
    }
}

/// Why a store did not open.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenError {
    /// A symbolic link where the database, its log or journal, or the
    /// temporary file or lock of a new store goes.
    Symlink,
    /// Something other than a regular file there, or a file with another
    /// name besides.
    NotAFile,
    /// The file is not this store; it is left as it is, unopened, but for
    /// [`Foreign::OtherSchema`], which SQLite has opened.
    NotAStore(Foreign),
    /// A file left at one of the store's names stops a new store from being
    /// made: a `-wal` or `-journal` of a store or database that is gone, or a
    /// temporary file that is not one the store started. Starting over means
    /// removing it.
    Leftover(PathBuf),
    /// A directory or one of the store's files belongs to another user.
    NotOwned,
    /// Group or others may write to the store's directory, or to one above
    /// it that is not sticky.
    Exposed,
    /// The SQLite this build links is not the bundled one, or does not sync.
    Build(String),
    /// Another connection holds the store, in this process or another.
    Locked,
    /// The disk is full.
    Full,
    /// Any other failure, described.
    Io(String),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symlink => f.write_str("a symbolic link is where the store's files go"),
            Self::NotAFile => f.write_str("the store's path is not a file with one name"),
            Self::NotAStore(what) => write!(f, "the file is not a LicketySync store: {what}"),
            Self::Leftover(path) => write!(
                f,
                "{} is left from before; remove it to start a new store",
                path.display()
            ),
            Self::NotOwned => f.write_str("the store's directory or files belong to another user"),
            Self::Exposed => f.write_str("others may write to the store's directory"),
            Self::Build(why) => write!(f, "this build's SQLite is unfit: {why}"),
            Self::Locked => f.write_str("the store is open elsewhere"),
            Self::Full => f.write_str("the disk is full"),
            Self::Io(why) => write!(f, "the store did not open: {why}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// What SQLite's error means for opening.
fn open_error(e: &rusqlite::Error) -> OpenError {
    match e.sqlite_error_code() {
        Some(ErrorCode::NotADatabase) => OpenError::NotAStore(Foreign::NotSqlite),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => OpenError::Locked,
        Some(ErrorCode::DiskFull) => OpenError::Full,
        _ => OpenError::Io(e.to_string()),
    }
}

/// What SQLite's error means for a store call: `Full` for `SQLITE_FULL`,
/// which SQLite reports for the operating system's ENOSPC and for a short
/// write; anything else, an ENOSPC that SQLite reports as an I/O error (from
/// `fsync`, say) included, is `Io`.
fn storage_error(e: &rusqlite::Error) -> StorageError {
    match e.sqlite_error_code() {
        Some(ErrorCode::DiskFull) => StorageError::Full,
        _ => StorageError::Io(e.to_string()),
    }
}

/// The stores open in this process, by device and inode.
#[cfg(unix)]
static OPEN: Mutex<BTreeSet<FileId>> = Mutex::new(BTreeSet::new());

/// A store's place in the list of stores open in this process, given up
/// when dropped: after its connection, which is declared before it.
#[derive(Debug)]
struct Registered(FileId);

impl Registered {
    /// Registers the file at `path` (not following a link there), or refuses
    /// it, [`OpenError::Locked`], when a store of this process has it open.
    fn take(path: &Path) -> Result<Self, OpenError> {
        let id = files::file_id(path)?;
        #[cfg(unix)]
        {
            let mut open = OPEN
                .lock()
                .map_err(|_| OpenError::Io("the list of open stores was poisoned".into()))?;
            if !open.insert(id) {
                return Err(OpenError::Locked);
            }
        }
        Ok(Self(id))
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Ok(mut open) = OPEN.lock() {
            open.remove(&self.0);
        }
    }
}

/// The engine's store on SQLite. One per device: [`SqliteStorage::open`] is
/// refused while another holds the same file.
#[derive(Debug)]
pub struct SqliteStorage {
    conn: Connection,
    /// Dropped after `conn`.
    _registered: Registered,
    /// A write has been staged since the last commit or rollback. If SQLite
    /// has no transaction open while this is set, it rolled the writes back.
    staged: bool,
    /// A rollback failed and left the transaction open: its writes must not
    /// be committed, so every call fails until a rollback succeeds.
    stuck: bool,
}

impl SqliteStorage {
    /// Opens the store at `path`, creating it when absent (module
    /// documentation, "Opening"). Nothing here picks the path: the caller's
    /// configuration does. A relative path is taken against the working
    /// directory, and the directories may be reached through links; the
    /// store's own files never are.
    ///
    /// # Errors
    /// [`OpenError`]: a link or something not a file where the store's files
    /// go, a file that is not this store, a leftover at its names, a
    /// directory or file that is not the user's or that others may write to,
    /// an unfit SQLite, the store held by another connection, a full disk, or
    /// any other failure.
    pub fn open(path: &Path) -> Result<Self, OpenError> {
        // Absolute, so that SQLite, which reads URI file names whatever the
        // flags say (libsqlite3-sys builds it with SQLITE_USE_URI), never
        // takes the path for one: no absolute path starts with "file:".
        let names = Names::of(&std::path::absolute(path)?)?;
        files::directories(names.dir())?;
        // A file already at the path is registered, then judged by its
        // header, before anything is made beside it.
        let found = if files::exists(&names.path)? {
            let registered = Registered::take(&names.path)?;
            files::glance(&names.path)?;
            Some(registered)
        } else {
            None
        };
        let held = files::lock_open(&names.lock)?;
        files::create(&names, &held)?;
        let registered = match found {
            Some(registered) => registered,
            None => Registered::take(&names.path)?,
        };
        files::judge(&names.path)?;
        for side in [&names.wal, &names.journal] {
            if let Some(file) = files::open_own(side)? {
                files::tighten(&file)?;
            }
        }
        let conn = connect(&names.path, registered.0)?;
        drop(held);
        Ok(Self {
            conn,
            _registered: registered,
            staged: false,
            stuck: false,
        })
    }

    /// Fails while the staged writes are not what the caller staged.
    fn intact(&self) -> Result<(), StorageError> {
        if self.stuck || (self.staged && self.conn.is_autocommit()) {
            return Err(StorageError::Io(LOST.into()));
        }
        Ok(())
    }

    /// Stages one write: opens the transaction if none is open, then runs
    /// `sql` with `params`.
    fn write<P: rusqlite::Params>(&mut self, sql: &str, params: P) -> Result<(), StorageError> {
        self.intact()?;
        if self.conn.is_autocommit() {
            self.conn
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| storage_error(&e))?;
        }
        self.conn
            .prepare_cached(sql)
            .and_then(|mut statement| statement.execute(params))
            .map_err(|e| storage_error(&e))?;
        self.staged = true;
        Ok(())
    }
}

/// How SQLite opens the store: read and write, never creating (the store is
/// created here), never a URI, one thread at a time, extended result codes.
fn flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_EXRESCODE
}

/// Before the first read: a defensive connection, and a fit SQLite.
fn defend(conn: &Connection) -> Result<(), OpenError> {
    let fail = |e: rusqlite::Error| open_error(&e);
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(fail)?;
    conn.pragma_update(None, "trusted_schema", false)
        .map_err(fail)?;
    conn.pragma_update(None, "cell_size_check", true)
        .map_err(fail)?;
    let mut statement = conn.prepare("PRAGMA compile_options").map_err(fail)?;
    let options = statement
        .query_map([], |r| r.get::<_, String>(0))
        .and_then(Iterator::collect::<rusqlite::Result<Vec<String>>>)
        .map_err(fail)?;
    fit(
        rusqlite::version_number(),
        ffi::SQLITE_VERSION_NUMBER,
        &options,
    )
}

/// Whether the SQLite linked is the bundled one (`runtime` the bundled
/// header's `bundled`) and built to sync files and their directories.
fn fit(runtime: i32, bundled: i32, options: &[String]) -> Result<(), OpenError> {
    if runtime != bundled {
        return Err(OpenError::Build(format!(
            "SQLite {runtime} is linked, not the bundled {bundled}"
        )));
    }
    for unfit in ["NO_SYNC", "DISABLE_DIRSYNC"] {
        if options.iter().any(|o| o == unfit) {
            return Err(OpenError::Build(format!("SQLite is built with {unfit}")));
        }
    }
    Ok(())
}

/// Opens this store's file with SQLite and sets it up (module documentation).
/// Until every check has passed, the connection would close without a
/// checkpoint, so a refused file's log is never written into it.
fn connect(path: &Path, id: FileId) -> Result<Connection, OpenError> {
    let conn = Connection::open_with_flags(path, flags()).map_err(|e| open_error(&e))?;
    let fail = |e: rusqlite::Error| open_error(&e);
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .map_err(fail)?;
    defend(&conn)?;
    // rusqlite waits 5 s for a lock by default; a held store is refused at once.
    conn.busy_timeout(Duration::ZERO).map_err(fail)?;
    // Before the first read, so that no -shm file is ever made.
    let locking: String = conn
        .pragma_update_and_check(None, "locking_mode", "EXCLUSIVE", |r| r.get(0))
        .map_err(fail)?;
    identity(&conn)?;
    if files::file_id(path)? != id {
        return Err(OpenError::Io(
            "the store's path changed as it was opened".into(),
        ));
    }
    let journal: String = conn
        .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
        .map_err(fail)?;
    if !locking.eq_ignore_ascii_case("exclusive") || !journal.eq_ignore_ascii_case("wal") {
        return Err(OpenError::Io(format!(
            "SQLite kept locking mode {locking} and journal mode {journal}"
        )));
    }
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(fail)?;
    conn.pragma_update(None, "fullfsync", true).map_err(fail)?;
    conn.pragma_update(None, "checkpoint_fullfsync", true)
        .map_err(fail)?;
    conn.pragma_update(None, "secure_delete", "FAST")
        .map_err(fail)?;
    let _: i64 = conn
        .pragma_update_and_check(None, "journal_size_limit", LOG_SIZE_LIMIT, |r| r.get(0))
        .map_err(fail)?;
    // The write lock, held from now on (exclusive locking).
    conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")
        .map_err(fail)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)
        .map_err(fail)?;
    Ok(conn)
}

/// SQLite's first read: the IDs again, through SQLite and so the log too,
/// and nothing but the one table.
fn identity(conn: &Connection) -> Result<(), OpenError> {
    let fail = |e: rusqlite::Error| open_error(&e);
    let id: i32 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(fail)?;
    if id != APPLICATION_ID {
        return Err(OpenError::NotAStore(Foreign::OtherProgram));
    }
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(fail)?;
    if version != FORMAT {
        return Err(OpenError::NotAStore(Foreign::OtherFormat(
            u32::from_be_bytes(version.to_be_bytes()),
        )));
    }
    let mut statement = conn
        .prepare("SELECT type, name, sql FROM sqlite_schema")
        .map_err(fail)?;
    let found = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>)
        .map_err(fail)?;
    let ours = [("table".to_owned(), "kv".to_owned(), Some(SCHEMA.to_owned()))];
    if found != ours {
        return Err(OpenError::NotAStore(Foreign::OtherSchema));
    }
    Ok(())
}

/// The least key above every key that starts with `prefix`: `prefix` without
/// its trailing 0xff bytes, its last byte raised by one. `None` when every
/// byte is 0xff, or there are none, since no key bounds those from above.
fn successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let last = prefix.iter().rposition(|&b| b != 0xff)?;
    let mut bound = prefix.get(..=last)?.to_vec();
    let byte = bound.last_mut()?;
    *byte += 1;
    Some(bound)
}

impl Storage for SqliteStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.intact()?;
        self.conn
            .prepare_cached("SELECT v FROM kv WHERE k = ?1")
            .and_then(|mut statement| statement.query_row([key], |r| r.get(0)).optional())
            .map_err(|e| storage_error(&e))
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError> {
        self.intact()?;
        let entry =
            |r: &rusqlite::Row<'_>| -> rusqlite::Result<Entry> { Ok((r.get(0)?, r.get(1)?)) };
        // BLOBs compare as memcmp, then by length: the order of `Vec<u8>`.
        match successor(prefix) {
            Some(bound) => self
                .conn
                .prepare_cached("SELECT k, v FROM kv WHERE k >= ?1 AND k < ?2 ORDER BY k")
                .and_then(|mut statement| {
                    statement
                        .query_map([prefix, bound.as_slice()], entry)?
                        .collect::<rusqlite::Result<Vec<Entry>>>()
                }),
            None => self
                .conn
                .prepare_cached("SELECT k, v FROM kv WHERE k >= ?1 ORDER BY k")
                .and_then(|mut statement| {
                    statement
                        .query_map([prefix], entry)?
                        .collect::<rusqlite::Result<Vec<Entry>>>()
                }),
        }
        .map_err(|e| storage_error(&e))
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.write(
            "INSERT OR REPLACE INTO kv (k, v) VALUES (?1, ?2)",
            [key, value],
        )
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StorageError> {
        self.write("DELETE FROM kv WHERE k = ?1", [key])
    }

    fn commit(&mut self) -> Result<(), StorageError> {
        self.intact()?;
        if !self.conn.is_autocommit() {
            self.conn
                .execute_batch("COMMIT")
                .map_err(|e| storage_error(&e))?;
        }
        self.staged = false;
        Ok(())
    }

    fn rollback(&mut self) {
        if !self.conn.is_autocommit() {
            // The outcome shows in whether a transaction is still open.
            let _ = self.conn.execute_batch("ROLLBACK");
        }
        self.stuck = !self.conn.is_autocommit();
        if !self.stuck {
            self.staged = false;
        }
    }
}
