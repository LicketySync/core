// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The SQLite store's tests: the storage conformance suite and its model, the
//! settings, the files and modes it makes, what it refuses to open and leaves
//! untouched, a creation cut short, and failures. The `crash` module kills a
//! writer and holds the store from a second process.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

mod crash;

use std::fs;
use std::path::{Path, PathBuf};

use licketysync_engine::runtime::conformance::{self, LARGEST_VALUE, Subject, pattern};
use proptest::prelude::*;

use super::*;

/// The fixed seed of every property test here, as in the engine's.
const PROPTEST_SEED: u64 = 0x6c69_636b_6574_7379;

/// `cases` cases, or `PROPTEST_CASES`, from the fixed seed or the one
/// `LICKETYSYNC_PROPTEST_SEED` names (`random`, or a number), as the
/// engine's tests take them.
fn proptest_config(cases: u32) -> ProptestConfig {
    use proptest::test_runner::RngSeed;
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cases);
    let rng_seed = match std::env::var("LICKETYSYNC_PROPTEST_SEED") {
        Ok(v) if v == "random" => RngSeed::Random,
        Ok(v) => RngSeed::Fixed(
            v.parse()
                .expect("LICKETYSYNC_PROPTEST_SEED: random or a u64"),
        ),
        Err(_) => RngSeed::Fixed(PROPTEST_SEED),
    };
    ProptestConfig {
        cases,
        rng_seed,
        ..ProptestConfig::default()
    }
}

/// What every call returns once the staged writes are lost.
fn lost<T>() -> Result<T, StorageError> {
    Err(StorageError::Io(LOST.into()))
}

/// A new, empty directory for one test, mode 0700, in the target directory
/// beside this test binary.
fn scratch(name: &str) -> PathBuf {
    // Semgrep's community rule flags every std::env::current_exe(): whoever
    // runs a binary can change the path it gives. Here it only places this
    // test's own files.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let exe = std::env::current_exe().unwrap();
    let dir = exe
        .parent()
        .unwrap()
        .join("sqlite-store-tests")
        .join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o700);
    dir
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// `path` with `suffix` added to its name, as SQLite names a log.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The temporary name a new store at `path` is built under.
fn temp_of(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap());
    name.push(".new");
    path.with_file_name(name)
}

/// The open lock beside a store at `path`.
fn lock_of(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap());
    name.push(".lock");
    path.with_file_name(name)
}

/// Stores in one scratch directory, removed with it.
struct Sqlite {
    dir: PathBuf,
    stores: u32,
    /// `max_page_count` before the disk was filled.
    room: Option<i64>,
}

impl Sqlite {
    fn new(name: &str) -> Self {
        Self {
            dir: scratch(name),
            stores: 0,
            room: None,
        }
    }
}

impl Drop for Sqlite {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn path_of(store: &SqliteStorage) -> PathBuf {
    PathBuf::from(store.conn.path().unwrap())
}

impl Subject for Sqlite {
    type Store = SqliteStorage;

    fn fresh(&mut self) -> SqliteStorage {
        self.stores += 1;
        SqliteStorage::open(&self.dir.join(format!("{}.store", self.stores))).unwrap()
    }

    fn reopen(&mut self, store: SqliteStorage) -> SqliteStorage {
        let path = path_of(&store);
        drop(store);
        SqliteStorage::open(&path).unwrap()
    }

    /// The disk as full as SQLite can be made without root: no page beyond
    /// those the file has, so any write that needs a new one fails with
    /// `SQLITE_FULL`.
    fn set_full(&mut self, store: &mut SqliteStorage, full: bool) {
        let conn = &store.conn;
        let pages: i64 = if full {
            let room = conn
                .pragma_query_value(None, "max_page_count", |r| r.get(0))
                .unwrap();
            self.room = Some(room);
            conn.pragma_query_value(None, "page_count", |r| r.get(0))
                .unwrap()
        } else {
            self.room.take().unwrap()
        };
        let set: i64 = conn
            .pragma_update_and_check(None, "max_page_count", pages, |r| r.get(0))
            .unwrap();
        assert_eq!(set, pages);
    }

    /// A commit hook that turns every commit into a rollback, as SQLite does
    /// itself when a commit fails.
    fn set_commit_fails(&mut self, store: &mut SqliteStorage, fails: bool) {
        if fails {
            store.conn.commit_hook(Some(|| true)).unwrap();
        } else {
            store.conn.commit_hook(None::<fn() -> bool>).unwrap();
        }
    }
}

#[test]
fn the_store_conforms() {
    assert_eq!(conformance::run(&mut Sqlite::new("conforms")), Ok(()));
}

proptest! {
    #![proptest_config(proptest_config(24))]

    #[test]
    fn the_store_matches_the_model(script in proptest::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(conformance::model(&mut Sqlite::new("model"), &script), Ok(()));
    }
}

#[test]
fn open_sets_the_log_durability_exclusive_lock_and_defences() {
    let mut subject = Sqlite::new("settings");
    let store = subject.fresh();
    let conn = &store.conn;
    let text =
        |name: &str| -> String { conn.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
    let number = |name: &str| -> i64 { conn.pragma_query_value(None, name, |r| r.get(0)).unwrap() };
    assert_eq!(text("journal_mode"), "wal");
    assert_eq!(text("locking_mode"), "exclusive");
    assert_eq!(number("synchronous"), 2, "FULL");
    assert_eq!(number("fullfsync"), 1);
    assert_eq!(number("checkpoint_fullfsync"), 1);
    assert_eq!(number("journal_size_limit"), 67_108_864);
    assert_eq!(LOG_SIZE_LIMIT, 67_108_864);
    assert_eq!(number("application_id"), i64::from(APPLICATION_ID));
    assert_eq!(number("user_version"), i64::from(FORMAT));
    assert_eq!(number("busy_timeout"), 0, "a held store is refused at once");
    assert_eq!(number("trusted_schema"), 0);
    assert_eq!(number("cell_size_check"), 1);
    assert_eq!(number("secure_delete"), 2, "FAST");
    assert_eq!(number("auto_vacuum"), 2, "INCREMENTAL");
    assert_eq!(
        conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE),
        Ok(true)
    );
}

#[test]
fn only_the_bundled_sqlite_built_to_sync_is_fit() {
    let bundled = ffi::SQLITE_VERSION_NUMBER;
    assert_eq!(rusqlite::version_number(), bundled, "this build's own");
    let options = |o: &[&str]| -> Vec<String> { o.iter().map(|&s| s.to_owned()).collect() };
    assert_eq!(fit(bundled, bundled, &options(&["THREADSAFE=1"])), Ok(()));
    assert_eq!(
        fit(bundled - 1, bundled, &[]),
        Err(OpenError::Build(format!(
            "SQLite {} is linked, not the bundled {bundled}",
            bundled - 1
        )))
    );
    assert_eq!(
        fit(bundled, bundled, &options(&["THREADSAFE=1", "NO_SYNC"])),
        Err(OpenError::Build("SQLite is built with NO_SYNC".into()))
    );
    assert_eq!(
        fit(bundled, bundled, &options(&["DISABLE_DIRSYNC"])),
        Err(OpenError::Build(
            "SQLite is built with DISABLE_DIRSYNC".into()
        ))
    );
}

#[cfg(unix)]
#[test]
fn open_creates_the_file_0600_in_directories_0700_and_no_shared_memory_file() {
    let dir = scratch("modes");
    let path = dir.join("a").join("b").join("store");
    let mut store = SqliteStorage::open(&path).unwrap();
    store.put(b"k", b"v").unwrap();
    store.commit().unwrap();
    assert_eq!(mode(&dir.join("a")), 0o700);
    assert_eq!(mode(&dir.join("a").join("b")), 0o700);
    assert_eq!(mode(&path), 0o600);
    let log = beside(&path, "-wal");
    assert_eq!(mode(&log), 0o600, "the log takes the database's mode");
    assert!(!beside(&path, "-shm").exists());
    assert!(!temp_of(&path).exists());
    drop(store);
    assert!(!log.exists(), "the log goes when the store closes");
    // Group and other bits of an existing store are taken away.
    set_mode(&path, 0o644);
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    assert_eq!(mode(&path), 0o600);
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_second_open_is_refused_while_the_store_is_open() {
    let dir = scratch("locked");
    let path = dir.join("store");
    let first = SqliteStorage::open(&path).unwrap();
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::Locked));
    drop(first);
    let again = SqliteStorage::open(&path).unwrap();
    drop(again);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_directory_reached_through_a_link_holds_the_store() {
    use std::os::unix::fs::symlink;
    let dir = scratch("linked-dir");
    let real = dir.join("real");
    fs::create_dir(&real).unwrap();
    set_mode(&real, 0o700);
    symlink(&real, dir.join("via")).unwrap();
    let mut store = SqliteStorage::open(&dir.join("via").join("store")).unwrap();
    store.put(b"k", b"v").unwrap();
    store.commit().unwrap();
    drop(store);
    assert!(real.join("store").is_file());
    let store = SqliteStorage::open(&real.join("store")).unwrap();
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_link_at_any_of_the_stores_names_is_refused_and_its_target_untouched() {
    use std::os::unix::fs::symlink;
    let dir = scratch("links");
    let target = dir.join("target");
    fs::write(&target, b"not the store").unwrap();
    let store = dir.join("store");
    // The database itself, to a file and dangling; and the temporary name
    // of a new store.
    for (name, to) in [
        (store.clone(), target.clone()),
        (store.clone(), dir.join("absent")),
        (temp_of(&store), target.clone()),
        (temp_of(&store), dir.join("absent")),
    ] {
        symlink(&to, &name).unwrap();
        assert_eq!(
            SqliteStorage::open(&store).err(),
            Some(OpenError::Symlink),
            "{name:?}"
        );
        fs::remove_file(&name).unwrap();
        assert!(!store.exists(), "{name:?}");
    }
    // The log and the journal of a store that exists.
    drop(SqliteStorage::open(&store).unwrap());
    for suffix in ["-wal", "-journal"] {
        for to in [target.clone(), dir.join("absent")] {
            let side = beside(&store, suffix);
            symlink(&to, &side).unwrap();
            assert_eq!(
                SqliteStorage::open(&store).err(),
                Some(OpenError::Symlink),
                "{suffix}"
            );
            fs::remove_file(&side).unwrap();
        }
    }
    assert_eq!(fs::read(&target).unwrap(), b"not the store");
    assert!(!dir.join("absent").exists());
    drop(SqliteStorage::open(&store).unwrap());
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_directory_or_file_others_could_change_is_refused() {
    let dir = scratch("owners");
    // A directory group or others may write to; nothing is created in it.
    for exposed in [0o770, 0o702, 0o777] {
        set_mode(&dir, exposed);
        assert_eq!(
            SqliteStorage::open(&dir.join("store")).err(),
            Some(OpenError::Exposed)
        );
        assert!(!dir.join("store").exists());
    }
    set_mode(&dir, 0o755);
    let path = dir.join("store");
    drop(SqliteStorage::open(&path).unwrap());
    // A store with a second name.
    fs::hard_link(&path, dir.join("again")).unwrap();
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::NotAFile));
    fs::remove_file(dir.join("again")).unwrap();
    // A log that is a directory.
    fs::create_dir(beside(&path, "-wal")).unwrap();
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::NotAFile));
    fs::remove_dir(beside(&path, "-wal")).unwrap();
    // A store and its log left by a crash, both mode 0644: their group and
    // other bits go, and the log's commit is there.
    let mut live = SqliteStorage::open(&path).unwrap();
    live.put(b"k", b"v").unwrap();
    live.commit().unwrap();
    let copy = dir.join("copy");
    copy_live(&path, &copy);
    drop(live);
    set_mode(&copy, 0o644);
    set_mode(&beside(&copy, "-wal"), 0o644);
    let store = SqliteStorage::open(&copy).unwrap();
    assert_eq!(mode(&copy), 0o600);
    assert_eq!(mode(&beside(&copy, "-wal")), 0o600);
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    drop(store);
    // A directory of another user (the root's), unless this runs as root.
    if rustix::process::geteuid().as_raw() != 0 {
        let theirs = Path::new("/licketysync-store-test-never-made");
        assert_eq!(SqliteStorage::open(theirs).err(), Some(OpenError::NotOwned));
        assert!(!theirs.exists());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_fifo_where_the_store_goes_is_refused_without_waiting_for_a_writer() {
    let dir = scratch("fifo");
    let path = dir.join("store");
    let made = std::process::Command::new("mkfifo").arg(&path).status();
    assert!(made.unwrap().success());
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::NotAFile));
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_store_its_owner_made_read_only_is_not_made_writable() {
    // Root writes whatever the mode says.
    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }
    let dir = scratch("read-only");
    let path = dir.join("store");
    drop(SqliteStorage::open(&path).unwrap());
    set_mode(&path, 0o400);
    assert!(matches!(SqliteStorage::open(&path), Err(OpenError::Io(_))));
    assert_eq!(mode(&path), 0o400);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn a_link_put_where_the_store_makes_a_directory_is_refused_and_nothing_made_through_it() {
    use std::os::unix::fs::symlink;
    let dir = scratch("raced-dir");
    let target = dir.join("target");
    fs::create_dir(&target).unwrap();
    set_mode(&target, 0o700);
    // As if another user had put a link where a missing directory was about
    // to be made, between the look and the mkdir.
    let raced = dir.join("raced");
    symlink(&target, &raced).unwrap();
    assert_eq!(files::make_dir(&raced).err(), Some(OpenError::Symlink));
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    // A file there instead: not a directory.
    fs::write(dir.join("file"), b"x").unwrap();
    assert_eq!(
        files::make_dir(&dir.join("file")).err(),
        Some(OpenError::NotAFile)
    );
    // Made, or found made as a directory: its own metadata, not a link's.
    let made = files::make_dir(&dir.join("made")).unwrap();
    assert!(made.is_dir());
    assert_eq!(mode(&dir.join("made")), 0o700);
    assert!(files::make_dir(&dir.join("made")).unwrap().is_dir());
    fs::remove_dir_all(dir).unwrap();
}

/// Every file under `dir`, by name, with its bytes.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files: Vec<(PathBuf, Vec<u8>)> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            let bytes = fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    files.sort();
    files
}

/// A copy of `from`, its sidecars and its open lock at `to`, taken while
/// another connection holds them, as a crash would leave them.
fn copy_live(from: &Path, to: &Path) {
    fs::copy(from, to).unwrap();
    for suffix in ["-wal", "-journal"] {
        if beside(from, suffix).exists() {
            fs::copy(beside(from, suffix), beside(to, suffix)).unwrap();
        }
    }
    if lock_of(from).exists() {
        fs::copy(lock_of(from), lock_of(to)).unwrap();
    }
}

#[test]
fn another_programs_files_are_refused_unopened_and_left_byte_for_byte() {
    let dir = scratch("foreign");
    let live = dir.join("live");
    fs::create_dir(&live).unwrap();
    let refused = |path: &Path, why: Foreign| {
        let parent = path.parent().unwrap();
        let before = snapshot(parent);
        assert_eq!(
            SqliteStorage::open(path).err(),
            Some(OpenError::NotAStore(why)),
            "{path:?}"
        );
        assert_eq!(snapshot(parent), before, "{path:?} changed");
    };
    // (a) A WAL database whose frames are still in its log.
    let wal = live.join("wal.db");
    let conn = Connection::open(&wal).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;
         CREATE TABLE t (x); INSERT INTO t VALUES (randomblob(9000));",
    )
    .unwrap();
    copy_live(&wal, &dir.join("wal.db"));
    drop(conn);
    assert!(
        fs::metadata(beside(&dir.join("wal.db"), "-wal"))
            .unwrap()
            .len()
            > 0
    );
    refused(&dir.join("wal.db"), Foreign::OtherProgram);
    // (b) A database with a hot journal: a transaction half done.
    let hot = live.join("hot.db");
    let conn = Connection::open(&hot).unwrap();
    conn.execute_batch(
        "PRAGMA cache_size = 1; CREATE TABLE t (x);
         INSERT INTO t SELECT randomblob(3000) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3);
         BEGIN; UPDATE t SET x = randomblob(3000);",
    )
    .unwrap();
    copy_live(&hot, &dir.join("hot.db"));
    drop(conn);
    assert!(
        fs::metadata(beside(&dir.join("hot.db"), "-journal"))
            .unwrap()
            .len()
            > 0
    );
    refused(&dir.join("hot.db"), Foreign::OtherProgram);
    // (c) An empty file; a database with no table and IDs 0; one with a
    // table and no IDs; not a database at all.
    fs::write(dir.join("empty"), b"").unwrap();
    refused(&dir.join("empty"), Foreign::Empty);
    let bare = dir.join("bare.db");
    Connection::open(&bare)
        .unwrap()
        .execute_batch("VACUUM")
        .unwrap();
    refused(&bare, Foreign::OtherProgram);
    let table = dir.join("table.db");
    Connection::open(&table)
        .unwrap()
        .execute_batch("CREATE TABLE kv (k, v)")
        .unwrap();
    refused(&table, Foreign::OtherProgram);
    fs::write(dir.join("junk"), pattern(8_192, 1)).unwrap();
    refused(&dir.join("junk"), Foreign::NotSqlite);
    fs::write(dir.join("short"), &MAGIC[..]).unwrap();
    refused(&dir.join("short"), Foreign::NotSqlite);
    // This store in another format: refused before SQLite opens it.
    let other = dir.join("format.db");
    drop(SqliteStorage::open(&other).unwrap());
    Connection::open(&other)
        .unwrap()
        .execute_batch("PRAGMA user_version = 2")
        .unwrap();
    refused(&other, Foreign::OtherFormat(2));
    // This store's header over another schema: refused once SQLite reads it.
    let schema = dir.join("schema.db");
    drop(SqliteStorage::open(&schema).unwrap());
    Connection::open(&schema)
        .unwrap()
        .execute_batch("CREATE TABLE extra (x)")
        .unwrap();
    assert_eq!(
        SqliteStorage::open(&schema).err(),
        Some(OpenError::NotAStore(Foreign::OtherSchema))
    );
    // A directory where the store goes.
    fs::create_dir(dir.join("dir")).unwrap();
    assert_eq!(
        SqliteStorage::open(&dir.join("dir")).err(),
        Some(OpenError::NotAFile)
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn headers_say_what_a_file_is() {
    let mut header = MAGIC.to_vec();
    header.resize(100, 0);
    header[60..64].copy_from_slice(&1u32.to_be_bytes());
    header[68..72].copy_from_slice(b"LkSy");
    assert_eq!(files::verdict(&header), Ok(()));
    assert_eq!(
        files::verdict(&header[..72]),
        Ok(()),
        "the fields are all it reads"
    );
    let with = |at: usize, bytes: &[u8]| {
        let mut h = header.clone();
        h[at..at + bytes.len()].copy_from_slice(bytes);
        files::verdict(&h)
    };
    let not = |why| Err(OpenError::NotAStore(why));
    assert_eq!(files::verdict(&[]), not(Foreign::Empty));
    assert_eq!(files::verdict(&header[..71]), not(Foreign::NotSqlite));
    assert_eq!(with(0, b"SQLite format 4"), not(Foreign::NotSqlite));
    assert_eq!(with(15, &[1]), not(Foreign::NotSqlite));
    assert_eq!(with(68, b"LkSz"), not(Foreign::OtherProgram));
    assert_eq!(with(68, &[0; 4]), not(Foreign::OtherProgram));
    assert_eq!(with(60, &[0; 4]), not(Foreign::OtherFormat(0)));
    assert_eq!(with(60, &[0, 0, 1, 0]), not(Foreign::OtherFormat(256)));
}

#[test]
fn a_creation_cut_short_is_never_adopted() {
    let dir = scratch("cut-short");
    let path = dir.join("store");
    let temp = temp_of(&path);
    let complete = dir.join("complete");
    drop(SqliteStorage::open(&complete).unwrap());
    // Cut short before the store was placed: an empty file, a half-built
    // database, a built one. Each is removed and a new store made.
    let half = dir.join("half");
    Connection::open(&half)
        .unwrap()
        .execute_batch("CREATE TABLE kv (k, v)")
        .unwrap();
    for leftover in [
        Vec::new(),
        fs::read(&half).unwrap(),
        fs::read(&complete).unwrap(),
    ] {
        fs::write(&temp, &leftover).unwrap();
        let mut store = SqliteStorage::open(&path).unwrap();
        assert_eq!(store.scan(b""), Ok(Vec::new()));
        store.put(b"k", b"v").unwrap();
        store.commit().unwrap();
        drop(store);
        assert!(!temp.exists());
        fs::remove_file(&path).unwrap();
    }
    // A placement by hard link cut short between the link and the removal:
    // the temporary name is a second name of the store, which opens whole,
    // with one name.
    let mut store = SqliteStorage::open(&path).unwrap();
    store.put(b"k", b"v").unwrap();
    store.commit().unwrap();
    drop(store);
    fs::hard_link(&path, &temp).unwrap();
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    assert!(!temp.exists());
    drop(store);
    // With no store yet, anything at the temporary name but an empty file or
    // one that starts as an SQLite database is refused and left.
    fs::remove_file(&path).unwrap();
    fs::create_dir(&temp).unwrap();
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::NotAFile));
    fs::remove_dir(&temp).unwrap();
    fs::write(&temp, b"someone's notes").unwrap();
    assert_eq!(
        SqliteStorage::open(&path).err(),
        Some(OpenError::Leftover(temp.clone()))
    );
    assert_eq!(fs::read(&temp).unwrap(), b"someone's notes");
    assert!(!path.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_store_is_placed_only_where_nothing_is_and_only_as_built() {
    let dir = scratch("place");
    let temp = dir.join(".t");
    // Another program's file at the path first: kept, the built one removed.
    let path = dir.join("store");
    fs::write(&path, b"theirs").unwrap();
    fs::write(&temp, b"ours").unwrap();
    let id = files::file_id(&temp).unwrap();
    assert_eq!(files::place(&temp, id, &path), Ok(()));
    assert_eq!(fs::read(&path).unwrap(), b"theirs");
    assert!(!temp.exists());
    // Nothing there: placed.
    fs::write(&temp, b"ours").unwrap();
    let id = files::file_id(&temp).unwrap();
    assert_eq!(files::place(&temp, id, &dir.join("free")), Ok(()));
    assert_eq!(fs::read(dir.join("free")).unwrap(), b"ours");
    assert!(!temp.exists());
    // The temporary name holding another file by then: not placed. (Windows
    // gives no device and inode here, so there it would be.)
    #[cfg(unix)]
    {
        fs::write(&temp, b"ours").unwrap();
        let id = files::file_id(&temp).unwrap();
        fs::write(dir.join("swap"), b"swapped in").unwrap();
        fs::rename(dir.join("swap"), &temp).unwrap();
        assert!(matches!(
            files::place(&temp, id, &dir.join("third")),
            Err(OpenError::Io(_))
        ));
        assert!(!dir.join("third").exists());
        assert_eq!(fs::read(&temp).unwrap(), b"swapped in");
        fs::remove_file(&temp).unwrap();
    }
    // A creation whose placement fails leaves no temporary file.
    let names = files::Names {
        path: dir.join("absent").join("store"),
        wal: dir.join("absent").join("store-wal"),
        journal: dir.join("absent").join("store-journal"),
        temp: temp.clone(),
        lock: dir.join(".lock"),
    };
    let held = files::lock_open(&names.lock).unwrap();
    assert!(matches!(
        files::create(&names, &held),
        Err(OpenError::Io(_))
    ));
    drop(held);
    assert!(!temp.exists());
    fs::remove_dir_all(dir).unwrap();
}

/// Regression: a macOS or iOS volume without `RENAME_EXCL` answers the
/// no-replace rename with `ENOTSUP`, not `EINVAL`, and no store could be made
/// there. Either answer means a hard link instead; a store already at the
/// name does not.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[test]
fn a_macos_volume_without_rename_excl_gets_a_hard_link_not_an_error() {
    use rustix::io::Errno;
    assert!(files::refuses_flag(Errno::NOTSUP));
    assert!(files::refuses_flag(Errno::INVAL));
    assert!(!files::refuses_flag(Errno::EXIST));
    assert!(!files::refuses_flag(Errno::NOENT));
}

/// Regression: an opener that opened the store's journal or log as another
/// process's SQLite removed it looked at a file with no name left, and
/// refused the store as "not a file with one name" (six processes opening one
/// fresh path, on macOS). Such a file is absent; one with its name is kept,
/// and one with two names still refused.
#[cfg(unix)]
#[test]
fn a_log_or_journal_removed_as_it_is_opened_is_absent_not_a_file_with_two_names() {
    let dir = scratch("removed-as-opened");
    let journal = beside(&dir.join("store"), "-journal");
    fs::write(&journal, b"").unwrap();
    let opened = fs::File::open(&journal).unwrap();
    fs::remove_file(&journal).unwrap();
    assert!(matches!(files::named(opened), Ok(None)));
    fs::write(&journal, b"").unwrap();
    let opened = fs::File::open(&journal).unwrap();
    assert!(matches!(files::named(opened), Ok(Some(_))));
    fs::hard_link(&journal, dir.join("second")).unwrap();
    let opened = fs::File::open(&journal).unwrap();
    assert_eq!(files::named(opened).err(), Some(OpenError::NotAFile));
    fs::remove_dir_all(dir).unwrap();
}

/// Regression: openers of one path in several processes at once could each
/// be refused, none opening it (six processes, on Linux): each one's SQLite
/// took the shared lock before any took the exclusive one, which then none
/// could. Every open, of an existing store too, now holds the open lock until
/// SQLite holds the store, and lets it go then.
#[test]
fn openers_at_once_are_not_all_refused_since_each_open_holds_the_open_lock() {
    let dir = scratch("open-lock");
    let path = dir.join("store");
    let lock = lock_of(&path);
    drop(SqliteStorage::open(&path).unwrap());
    fs::remove_file(&lock).unwrap();
    let store = SqliteStorage::open(&path).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .expect("the open of an existing store took the open lock");
    assert!(file.try_lock().is_ok(), "and let it go");
    drop(file);
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::Locked));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

/// Regression: on Windows, an opener looked at the store's log, another
/// opener's SQLite removed it as it closed the store, and the open of it
/// failed: "The system cannot find the file specified" (eight threads
/// opening one fresh path). A log removed between the look and the open is
/// not there, as on Unix.
#[cfg(any(target_os = "linux", target_os = "android", windows))]
#[test]
fn a_log_removed_between_its_look_and_its_open_does_not_fail_the_open() {
    let dir = scratch("removed-after-look");
    let path = dir.join("store");
    let mut store = SqliteStorage::open(&path).unwrap();
    store.put(b"k", b"v").unwrap();
    store.commit().unwrap();
    drop(store);
    fs::write(beside(&path, "-wal"), b"").unwrap();
    let remove_log: fn(&Path) = |p| {
        if p.as_os_str().to_string_lossy().ends_with("-wal") {
            fs::remove_file(p).unwrap();
        }
    };
    files::BETWEEN.with(|between| between.set(Some(remove_log)));
    let opened = SqliteStorage::open(&path);
    files::BETWEEN.with(|between| between.set(None));
    let store = opened.unwrap();
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(windows)]
thread_local! {
    /// The last handle to a log whose removal is pending.
    static HELD: std::cell::RefCell<Option<fs::File>> = const { std::cell::RefCell::new(None) };
    /// The waits an open spent on a name refused as access denied.
    static WAITED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// A store with one record, closed, and beside it a log, empty, whose removal
/// is pending: a handle opened with `FILE_FLAG_DELETE_ON_CLOSE` and closed
/// while another, kept in `HELD`, is open leaves the file, its name kept,
/// until that last handle closes, and Windows refuses every open of it as
/// access denied meanwhile, as when another opener's SQLite removes the log
/// of a store it closes.
#[cfg(windows)]
fn store_with_a_log_pending_removal(name: &str) -> (PathBuf, PathBuf) {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    let dir = scratch(name);
    let path = dir.join("store");
    let mut store = SqliteStorage::open(&path).unwrap();
    store.put(b"k", b"v").unwrap();
    store.commit().unwrap();
    drop(store);
    let wal = beside(&path, "-wal");
    fs::write(&wal, b"").unwrap();
    let held = fs::File::open(&wal).unwrap();
    let remover = fs::OpenOptions::new()
        .access_mode(DELETE)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(&wal)
        .unwrap();
    drop(remover);
    HELD.with(|h| *h.borrow_mut() = Some(held));
    assert_eq!(
        fs::File::open(&wal).map(drop).map_err(|e| e.raw_os_error()),
        Err(Some(5)),
        "the log's removal is pending"
    );
    (dir, path)
}

/// Regression: on Windows, an opener opened the store's log while the opener
/// before it, closing the store, had SQLite remove it, and the open failed:
/// "Access is denied" (`openers_of_a_fresh_path_at_once_each_open_it_or_are_refused`).
/// Windows refuses every open of a file whose removal is pending; the opener
/// now looks again after a wait, and a log gone by then is not there.
#[cfg(windows)]
#[test]
fn a_log_whose_removal_is_pending_as_it_is_opened_does_not_fail_the_open() {
    let (dir, path) = store_with_a_log_pending_removal("removal-pending");
    // The removal ends during the first wait, as when the remover's handle
    // closes.
    let end_removal: fn() = || HELD.with(|h| drop(h.take()));
    files::DENIED.with(|denied| denied.set(Some(end_removal)));
    let opened = SqliteStorage::open(&path);
    files::DENIED.with(|denied| denied.set(None));
    let store = opened.unwrap();
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

/// On Windows, a store's file refused as access denied past every wait, as
/// one the user may not open is, fails the open: after exactly
/// `DENIED_WAITS` waits.
#[cfg(windows)]
#[test]
fn a_log_refused_as_access_denied_past_every_wait_fails_the_open() {
    let (dir, path) = store_with_a_log_pending_removal("denied-past-waits");
    WAITED.with(|w| w.set(0));
    let count: fn() = || WAITED.with(|w| w.set(w.get() + 1));
    files::DENIED.with(|denied| denied.set(Some(count)));
    let opened = SqliteStorage::open(&path);
    files::DENIED.with(|denied| denied.set(None));
    let denied = std::io::Error::from_raw_os_error(5).to_string();
    assert_eq!(opened.err(), Some(OpenError::Io(denied)));
    assert_eq!(WAITED.with(std::cell::Cell::get), files::DENIED_WAITS);
    // Its removal ended, the log is gone and the store opens.
    HELD.with(|h| drop(h.take()));
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(store.get(b"k"), Ok(Some(b"v".to_vec())));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

/// Regression: on Windows, which gives no file ID here, any file at a
/// store's temporary name counted as a second name of the store and was
/// removed, another program's included. Only a second name is.
#[test]
fn a_file_of_another_program_at_the_temporary_name_beside_a_store_is_kept() {
    let dir = scratch("theirs-beside");
    let path = dir.join("store");
    drop(SqliteStorage::open(&path).unwrap());
    let temp = temp_of(&path);
    fs::write(&temp, b"someone's notes").unwrap();
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(store.scan(b""), Ok(Vec::new()));
    assert_eq!(fs::read(&temp).unwrap(), b"someone's notes");
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

/// Regression: an open let the open lock go by closing its file, while a
/// child that another thread was spawning held a copy of the descriptor, as a
/// child does until it starts its program; the lock, which belongs to the open
/// file, stayed held through the copy, and a look at it just after the open
/// found it held (`cargo careful test`, every test in one process). A copy of
/// the descriptor no longer keeps the lock held once it is dropped.
#[test]
fn a_copy_of_the_open_lock_a_spawned_child_holds_does_not_keep_it_held() {
    let dir = scratch("lock-copy");
    let lock = lock_of(&dir.join("store"));
    let held = files::lock_open(&lock).unwrap();
    let copy = held.file().try_clone().unwrap();
    drop(held);
    let other = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .unwrap();
    assert!(other.try_lock().is_ok(), "let go while a copy is open");
    drop((copy, other));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn openers_of_a_fresh_path_at_once_each_open_it_or_are_refused() {
    let dir = scratch("together");
    for round in 0..8 {
        let path = dir.join(format!("store-{round}"));
        let start = std::sync::Barrier::new(8);
        let results: Vec<Result<(), OpenError>> = std::thread::scope(|s| {
            let openers: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        start.wait();
                        SqliteStorage::open(&path).map(drop)
                    })
                })
                .collect();
            openers.into_iter().map(|o| o.join().unwrap()).collect()
        });
        for r in &results {
            assert!(matches!(r, Ok(()) | Err(OpenError::Locked)), "{r:?}");
        }
        assert!(results.iter().any(Result::is_ok), "round {round}");
        let mut store = SqliteStorage::open(&path).unwrap();
        store.put(b"k", b"v").unwrap();
        store.commit().unwrap();
        assert!(!temp_of(&path).exists());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_log_or_journal_left_at_a_missing_stores_names_stops_a_new_store() {
    let dir = scratch("left-sides");
    let path = dir.join("store");
    // An old store's log, its database gone.
    let mut old = SqliteStorage::open(&path).unwrap();
    old.put(b"old", b"1").unwrap();
    old.commit().unwrap();
    let wal = beside(&path, "-wal");
    let kept = fs::read(&wal).unwrap();
    drop(old);
    fs::remove_file(&path).unwrap();
    fs::write(&wal, &kept).unwrap();
    assert_eq!(
        SqliteStorage::open(&path).err(),
        Some(OpenError::Leftover(wal.clone()))
    );
    assert_eq!(fs::read(&wal).unwrap(), kept);
    assert!(!path.exists());
    fs::remove_file(&wal).unwrap();
    // Another database's journal.
    let journal = beside(&path, "-journal");
    fs::write(&journal, pattern(600, 3)).unwrap();
    assert_eq!(
        SqliteStorage::open(&path).err(),
        Some(OpenError::Leftover(journal.clone()))
    );
    assert_eq!(fs::read(&journal).unwrap(), pattern(600, 3));
    assert!(!path.exists());
    // Removed, both: a new store.
    fs::remove_file(&journal).unwrap();
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(store.get(b"old"), Ok(None));
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_store_whose_log_says_otherwise_is_refused_and_its_log_kept() {
    let dir = scratch("log-says");
    for (change, why) in [
        ("CREATE TABLE extra (x)", Foreign::OtherSchema),
        ("PRAGMA user_version = 2", Foreign::OtherFormat(2)),
        ("PRAGMA application_id = 7", Foreign::OtherProgram),
    ] {
        let path = dir.join("store");
        drop(SqliteStorage::open(&path).unwrap());
        // The change in the log only: the main file's header still says
        // this store in this format.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!("PRAGMA wal_autocheckpoint = 0; {change};"))
            .unwrap();
        let copies = dir.join("copies");
        fs::create_dir(&copies).unwrap();
        set_mode(&copies, 0o700);
        let copy = copies.join("store");
        copy_live(&path, &copy);
        drop(conn);
        let before = snapshot(&copies);
        assert_eq!(
            SqliteStorage::open(&copy).err(),
            Some(OpenError::NotAStore(why)),
            "{change}"
        );
        assert_eq!(snapshot(&copies), before, "{change}: no checkpoint into it");
        fs::remove_dir_all(&copies).unwrap();
        fs::remove_file(&path).unwrap();
    }
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn directories_above_a_new_store_must_be_closed_to_others_unless_sticky() {
    let dir = scratch("parents");
    let above = dir.join("above");
    fs::create_dir(&above).unwrap();
    // Writable by others and not sticky: refused, nothing made.
    set_mode(&above, 0o777);
    let path = above.join("new").join("store");
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::Exposed));
    assert!(!above.join("new").exists());
    // Sticky, as /tmp is: the store's own directory is made 0700.
    set_mode(&above, 0o1777);
    drop(SqliteStorage::open(&path).unwrap());
    assert_eq!(mode(&above.join("new")), 0o700);
    // The store's own directory may not be shared, sticky or not.
    let own = dir.join("own");
    fs::create_dir(&own).unwrap();
    set_mode(&own, 0o1770);
    assert_eq!(
        SqliteStorage::open(&own.join("store")).err(),
        Some(OpenError::Exposed)
    );
    set_mode(&above, 0o700);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_failed_put_on_a_full_disk_drops_the_batch_and_fails_until_rolled_back() {
    let mut subject = Sqlite::new("full");
    let mut store = subject.fresh();
    store.put(b"k0", b"v0").unwrap();
    store.commit().unwrap();
    store.put(b"a", b"A").unwrap();
    subject.set_full(&mut store, true);
    assert_eq!(
        store.put(b"big", &pattern(LARGEST_VALUE, 1)),
        Err(StorageError::Full)
    );
    // SQLite rolled the whole transaction back: nothing reads as if the
    // staged write were not there, and nothing commits.
    assert!(store.conn.is_autocommit());
    assert_eq!(store.get(b"a"), lost());
    assert_eq!(store.scan(b""), lost());
    assert_eq!(store.put(b"b", b"B"), lost());
    assert_eq!(store.delete(b"b"), lost());
    assert_eq!(store.commit(), lost());
    subject.set_full(&mut store, false);
    store.rollback();
    assert_eq!(store.get(b"a"), Ok(None));
    assert_eq!(store.get(b"k0"), Ok(Some(b"v0".to_vec())));
    store.put(b"b", b"B").unwrap();
    store.commit().unwrap();
    let store = subject.reopen(store);
    assert_eq!(
        store.scan(b""),
        Ok(vec![
            (b"b".to_vec(), b"B".to_vec()),
            (b"k0".to_vec(), b"v0".to_vec())
        ])
    );
}

#[test]
fn a_failed_commit_drops_the_batch_and_fails_until_rolled_back() {
    let mut subject = Sqlite::new("failed-commit");
    let mut store = subject.fresh();
    store.put(b"a", b"A").unwrap();
    subject.set_commit_fails(&mut store, true);
    assert!(matches!(store.commit(), Err(StorageError::Io(_))));
    subject.set_commit_fails(&mut store, false);
    // A put now would be committed on its own if the store opened no
    // transaction for it (SQLite's autocommit): it is refused instead.
    assert_eq!(store.put(b"b", b"B"), lost());
    assert_eq!(store.commit(), lost());
    let mut store = subject.reopen(store);
    assert_eq!(store.scan(b""), Ok(Vec::new()));
    store.put(b"c", b"C").unwrap();
    subject.set_commit_fails(&mut store, true);
    assert!(store.commit().is_err());
    subject.set_commit_fails(&mut store, false);
    store.rollback();
    store.put(b"d", b"D").unwrap();
    store.commit().unwrap();
    let store = subject.reopen(store);
    assert_eq!(store.scan(b""), Ok(vec![(b"d".to_vec(), b"D".to_vec())]));
}

#[test]
fn a_rollback_that_leaves_the_transaction_open_keeps_the_store_refusing() {
    let mut subject = Sqlite::new("stuck");
    let mut store = subject.fresh();
    store.put(b"a", b"A").unwrap();
    // As if ROLLBACK had failed to run: the transaction is still open.
    store.stuck = true;
    assert_eq!(store.get(b"a"), lost());
    assert_eq!(store.commit(), lost());
    store.rollback();
    assert!(!store.stuck);
    assert_eq!(store.get(b"a"), Ok(None));
}

#[test]
fn successor_bounds_every_key_with_the_prefix() {
    let cases: [(&[u8], Option<&[u8]>); 9] = [
        (&[], None),
        (&[0xff], None),
        (&[0xff, 0xff], None),
        (&[0x00], Some(&[0x01])),
        (&[0x01], Some(&[0x02])),
        (&[0xfe], Some(&[0xff])),
        (&[0x01, 0xff], Some(&[0x02])),
        (&[0x01, 0xff, 0xff], Some(&[0x02])),
        (&[0x01, 0xff, 0x05], Some(&[0x01, 0xff, 0x06])),
    ];
    for (prefix, want) in cases {
        assert_eq!(successor(prefix).as_deref(), want, "{prefix:02x?}");
    }
}

#[test]
fn errors_map_as_the_engine_and_the_daemon_read_them() {
    let sqlite = |code| rusqlite::Error::SqliteFailure(ffi::Error::new(code), None);
    assert_eq!(storage_error(&sqlite(ffi::SQLITE_FULL)), StorageError::Full);
    assert!(matches!(
        storage_error(&sqlite(ffi::SQLITE_IOERR_FSYNC)),
        StorageError::Io(_)
    ));
    assert!(matches!(
        open_error(&sqlite(ffi::SQLITE_CANTOPEN)),
        OpenError::Io(_)
    ));
    assert_eq!(
        open_error(&sqlite(ffi::SQLITE_NOTADB)),
        OpenError::NotAStore(Foreign::NotSqlite)
    );
    assert_eq!(open_error(&sqlite(ffi::SQLITE_BUSY)), OpenError::Locked);
    assert_eq!(open_error(&sqlite(ffi::SQLITE_LOCKED)), OpenError::Locked);
    assert_eq!(open_error(&sqlite(ffi::SQLITE_FULL)), OpenError::Full);
    let shown: Vec<String> = [
        OpenError::Symlink,
        OpenError::NotAFile,
        OpenError::NotAStore(Foreign::Empty),
        OpenError::NotAStore(Foreign::NotSqlite),
        OpenError::NotAStore(Foreign::OtherProgram),
        OpenError::NotAStore(Foreign::OtherFormat(2)),
        OpenError::NotAStore(Foreign::OtherSchema),
        OpenError::Leftover(PathBuf::from("/d/store-wal")),
        OpenError::NotOwned,
        OpenError::Exposed,
        OpenError::Build("why".into()),
        OpenError::Locked,
        OpenError::Full,
        OpenError::Io("why".into()),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        shown,
        [
            "a symbolic link is where the store's files go",
            "the store's path is not a file with one name",
            "the file is not a LicketySync store: an empty file",
            "the file is not a LicketySync store: not an SQLite database",
            "the file is not a LicketySync store: another program's database",
            "the file is not a LicketySync store: a LicketySync store of format 2",
            "the file is not a LicketySync store: a LicketySync store with another schema",
            "/d/store-wal is left from before; remove it to start a new store",
            "the store's directory or files belong to another user",
            "others may write to the store's directory",
            "this build's SQLite is unfit: why",
            "the store is open elsewhere",
            "the disk is full",
            "the store did not open: why",
        ]
    );
    let io: OpenError = std::io::Error::other("gone").into();
    assert_eq!(io, OpenError::Io("gone".into()));
}
