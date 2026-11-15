// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Other processes: a writer killed at points that vary, one killed while a
//! batch larger than SQLite's page cache is staged, and a second process
//! refused while one holds the store. Each test starts its own binary again
//! as the other process, told by a variable, and talks to it through pipes.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use licketysync_engine::runtime::Storage;
use licketysync_engine::runtime::conformance::pattern;

use super::{OpenError, SqliteStorage, beside, scratch};

/// The variable that makes this test's binary the killed writer, naming the
/// store.
const WRITER: &str = "LICKETYSYNC_STORE_CRASH_CHILD";

/// Set beside [`WRITER`]: the writer's batches outgrow SQLite's page cache.
const LARGE: &str = "LICKETYSYNC_STORE_CRASH_LARGE";

/// The variable that makes this test's binary hold the store it names.
const HOLDER: &str = "LICKETYSYNC_STORE_HOLDER";

/// The variable that makes this test's binary try to open the store it
/// names, and say what happened.
const TRIER: &str = "LICKETYSYNC_STORE_TRIER";

/// The variable that makes this test's binary open the store it names once
/// a line arrives on its standard input, and say what happened.
const OPENER: &str = "LICKETYSYNC_STORE_OPENER";

/// The tests the children run, as libtest names them.
const CRASH_TEST: &str = "store::tests::crash::a_killed_writer_leaves_each_batch_whole_or_absent";
const LARGE_TEST: &str =
    "store::tests::crash::a_writer_killed_with_a_batch_past_the_page_cache_leaves_none_of_it";
const HOLD_TEST: &str =
    "store::tests::crash::a_second_process_is_refused_while_one_holds_the_store";
const TRY_TEST: &str = "store::tests::crash::a_second_open_in_this_process_leaves_the_lock_held";
const OPENERS_TEST: &str =
    "store::tests::crash::openers_in_other_processes_at_once_each_open_it_or_are_refused";

/// The keys each batch writes, under its own number and over the shared ones.
const BATCH_KEYS: u64 = 8;

/// Batch `n`'s value at key `i`: its number, then 100 bytes to 16 KiB, so
/// that a batch spans many pages and the log grows past a checkpoint; or,
/// `large`, 300 KiB, so that 16 of them (4.8 MB) outgrow SQLite's page cache
/// of about 2 MB and spill to the log before the commit.
fn batch_value(n: u64, i: u64, large: bool) -> Vec<u8> {
    let len = if large {
        300 << 10
    } else {
        100 + usize::try_from((n * 7_919 + i * 1_013) % 16_000).unwrap()
    };
    let mut v = n.to_be_bytes().to_vec();
    v.extend(pattern(len, u8::try_from(i).unwrap()));
    v
}

/// Says `line` on standard output at once (libtest captures `println!`, not
/// writes to the handle).
fn say(line: &str) {
    let mut out = std::io::stdout();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
}

/// Batch `n`: new keys of its own, the shared keys overwritten, the previous
/// batch's mark deleted and its own put, and the number of the last batch,
/// saying `staged n i` after each pair of puts.
fn write_batch(store: &mut SqliteStorage, n: u64, large: bool) {
    for i in 0..BATCH_KEYS {
        let value = batch_value(n, i, large);
        store
            .put(format!("n/{n:08}/{i}").as_bytes(), &value)
            .unwrap();
        store.put(format!("shared/{i}").as_bytes(), &value).unwrap();
        say(&format!("staged {n} {i}"));
    }
    store
        .delete(format!("mark/{:08}", n - 1).as_bytes())
        .unwrap();
    store.put(format!("mark/{n:08}").as_bytes(), b"").unwrap();
    store.put(b"last", &n.to_be_bytes()).unwrap();
}

fn last_batch(store: &SqliteStorage) -> u64 {
    store
        .get(b"last")
        .unwrap()
        .map_or(0, |v| u64::from_be_bytes(v.try_into().unwrap()))
}

/// The killed writer: stages and commits batch after batch, saying where it
/// is (`staged n i`, `committing n`, `committed n` once the commit returned),
/// until it is killed or, bounded, after 1 000 batches.
fn writer(path: &Path, large: bool) {
    let mut store = SqliteStorage::open(path).unwrap();
    let start = last_batch(&store) + 1;
    for n in start..start + 1_000 {
        write_batch(&mut store, n, large);
        say(&format!("committing {n}"));
        store.commit().unwrap();
        say(&format!("committed {n}"));
    }
}

/// Every batch up to the last committed is whole, and none after it is there
/// even in part. Returns the last.
fn check_batches(store: &SqliteStorage, acknowledged: u64, large: bool) -> u64 {
    let last = last_batch(store);
    assert!(
        last == acknowledged || last == acknowledged + 1,
        "batch {acknowledged} was acknowledged, and the store's last is {last}"
    );
    let numbered = store.scan(b"n/").unwrap();
    assert_eq!(
        numbered.len() as u64,
        last * BATCH_KEYS,
        "keys of batches after {last}"
    );
    for (k, v) in numbered {
        let key = String::from_utf8(k).unwrap();
        let (n, i) = key[2..].split_once('/').unwrap();
        let (n, i): (u64, u64) = (n.parse().unwrap(), i.parse().unwrap());
        assert!(n <= last, "{key}");
        assert!(v == batch_value(n, i, large), "{key} holds another value");
    }
    for i in 0..BATCH_KEYS {
        let shared = store.get(format!("shared/{i}").as_bytes()).unwrap();
        assert_eq!(
            shared,
            (last > 0).then(|| batch_value(last, i, large)),
            "shared/{i}"
        );
    }
    let marks: Vec<Vec<u8>> = store
        .scan(b"mark/")
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    let want: Vec<Vec<u8>> = (last > 0)
        .then(|| format!("mark/{last:08}").into_bytes())
        .into_iter()
        .collect();
    assert_eq!(marks, want);
    last
}

/// This test's binary again, running `test` with `variable` set to `path`.
fn start(test: &str, variable: &str, path: &Path, large: bool) -> Child {
    // Semgrep's community rule flags every std::env::current_exe(): whoever
    // runs a binary can change the path it gives. Here it only names this
    // test's own binary, to start again.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test])
        .env(variable, path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if large {
        command.env(LARGE, "1");
    }
    command.spawn().unwrap()
}

/// Runs a writer over `path` and kills it when it says `trigger` (SIGKILL on
/// Unix); the kill lands a little after, wherever the writer has got to.
/// Returns the last batch it said it committed, from `before`.
fn kill_at(test: &str, path: &Path, trigger: &str, before: u64, large: bool) -> u64 {
    let mut child = start(test, WRITER, path, large);
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut acknowledged = before;
    let mut heard = |line: &str| {
        if let Some(n) = line.strip_prefix("committed ") {
            acknowledged = n.parse().unwrap();
        }
    };
    let mut reached = false;
    let mut said = Vec::new();
    while let Some(Ok(line)) = lines.next() {
        heard(&line);
        reached = line == trigger;
        said.push(line);
        if reached {
            break;
        }
    }
    let _ = child.kill();
    let status = child.wait().unwrap();
    // What the writer said before it died, read after.
    for line in lines.map_while(Result::ok) {
        heard(&line);
        said.push(line);
    }
    let mut errors = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut errors)
        .unwrap();
    assert!(
        reached,
        "the writer ended ({status}) before {trigger:?}:\n{}\n{errors}",
        said.join("\n")
    );
    acknowledged
}

/// A writer killed when it says it has reached a point that varies by round:
/// in the first to the fourth batch it writes, at the start of staging, in
/// the middle of it, as it begins the commit, or once the commit returned.
/// Each time the store, reopened, holds every batch the writer said it
/// committed, whole, and nothing of any later one, even in part. This proves
/// atomicity across a process crash, where the operating system keeps what
/// was written; durability across a power loss rests on `synchronous = FULL`
/// and `fullfsync`, which no test here can cut the power under.
#[test]
fn a_killed_writer_leaves_each_batch_whole_or_absent() {
    if let Some(path) = std::env::var_os(WRITER) {
        writer(Path::new(&path), false);
        return;
    }
    let dir = scratch("crash");
    let path = dir.join("store");
    let mut last = 0;
    for round in 0..16u64 {
        let batch = last + 1 + round % 4;
        let trigger = match round / 4 {
            0 => format!("staged {batch} 0"),
            1 => format!("staged {batch} 5"),
            2 => format!("committing {batch}"),
            _ => format!("committed {batch}"),
        };
        let acknowledged = kill_at(CRASH_TEST, &path, &trigger, last, false);
        let store = SqliteStorage::open(&path).unwrap();
        last = check_batches(&store, acknowledged, false);
    }
    fs::remove_dir_all(dir).unwrap();
}

/// A writer killed with a whole batch of 4.8 MB staged, past SQLite's page
/// cache, so that its pages are already in the log, uncommitted: the store,
/// reopened, holds none of it, and after a batch committed first, only that.
#[test]
fn a_writer_killed_with_a_batch_past_the_page_cache_leaves_none_of_it() {
    if let Some(path) = std::env::var_os(WRITER) {
        writer(Path::new(&path), true);
        return;
    }
    let dir = scratch("crash-large");
    let path = dir.join("store");
    let acknowledged = kill_at(LARGE_TEST, &path, "staged 1 7", 0, true);
    let log = fs::metadata(beside(&path, "-wal")).unwrap().len();
    assert!(
        log > 1 << 20,
        "{log} bytes in the log: the batch did not spill"
    );
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(check_batches(&store, acknowledged, true), 0);
    drop(store);
    let acknowledged = kill_at(LARGE_TEST, &path, "staged 2 7", 0, true);
    let store = SqliteStorage::open(&path).unwrap();
    assert_eq!(check_batches(&store, acknowledged, true), 1);
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

/// The holder: opens the store, says so, and holds it until its standard
/// input closes.
fn holder(path: &Path) {
    let store = SqliteStorage::open(path).unwrap();
    say("open");
    let mut rest = Vec::new();
    std::io::stdin().read_to_end(&mut rest).unwrap();
    drop(store);
}

/// Another process holds the store: this one is refused, and opens it once
/// the other has gone.
#[test]
fn a_second_process_is_refused_while_one_holds_the_store() {
    if let Some(path) = std::env::var_os(HOLDER) {
        holder(Path::new(&path));
        return;
    }
    let dir = scratch("held");
    let path = dir.join("store");
    let mut child = start(HOLD_TEST, HOLDER, &path, false);
    let mut out = String::new();
    // libtest's own lines first, then ours.
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    while let Some(Ok(line)) = lines.next() {
        if line == "open" {
            out = line;
            break;
        }
    }
    assert_eq!(out, "open", "the holder never opened the store");
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::Locked));
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    drop(SqliteStorage::open(&path).unwrap());
    fs::remove_dir_all(dir).unwrap();
}

/// A second open in this process is refused before it opens any of the
/// store's files: closing a handle to one would drop the first connection's
/// POSIX lock, and another process could then open the store.
#[test]
fn a_second_open_in_this_process_leaves_the_lock_held() {
    if let Some(path) = std::env::var_os(TRIER) {
        say(match SqliteStorage::open(Path::new(&path)) {
            Err(OpenError::Locked) => "locked",
            Ok(_) => "opened",
            Err(_) => "failed",
        });
        return;
    }
    let dir = scratch("lock-held");
    let path = dir.join("store");
    let first = SqliteStorage::open(&path).unwrap();
    assert_eq!(SqliteStorage::open(&path).err(), Some(OpenError::Locked));
    let other = start(TRY_TEST, TRIER, &path, false)
        .wait_with_output()
        .unwrap();
    let said = String::from_utf8_lossy(&other.stdout);
    assert!(
        said.lines().any(|l| l == "locked"),
        "the other process:\n{said}"
    );
    drop(first);
    fs::remove_dir_all(dir).unwrap();
}

/// Processes that open one fresh path at once, each told to go when all have
/// started: each opens the store or is refused as `Locked`, and the path ends
/// as a store.
#[test]
fn openers_in_other_processes_at_once_each_open_it_or_are_refused() {
    if let Some(path) = std::env::var_os(OPENER) {
        let mut go = String::new();
        std::io::stdin().read_line(&mut go).unwrap();
        say(&match SqliteStorage::open(Path::new(&path)) {
            Ok(_) => "opened".to_owned(),
            Err(OpenError::Locked) => "locked".to_owned(),
            Err(e) => format!("failed: {e}"),
        });
        return;
    }
    let dir = scratch("together-processes");
    for round in 0..6 {
        let path = dir.join(format!("store-{round}"));
        let mut openers: Vec<Child> = (0..6)
            .map(|_| start(OPENERS_TEST, OPENER, &path, false))
            .collect();
        for opener in &mut openers {
            writeln!(opener.stdin.as_mut().unwrap(), "go").unwrap();
        }
        let mut opened = 0;
        for opener in openers {
            let out = opener.wait_with_output().unwrap();
            let said = String::from_utf8_lossy(&out.stdout);
            let verdict = said
                .lines()
                .find(|l| *l == "opened" || *l == "locked" || l.starts_with("failed"))
                .unwrap_or("nothing");
            assert!(
                verdict == "opened" || verdict == "locked",
                "round {round}:\n{said}"
            );
            opened += usize::from(verdict == "opened");
        }
        assert!(opened > 0, "round {round}: none opened");
        let mut store = SqliteStorage::open(&path).unwrap();
        store.put(b"k", b"v").unwrap();
        store.commit().unwrap();
    }
    fs::remove_dir_all(dir).unwrap();
}
