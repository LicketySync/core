// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The storage conformance suite: what every [`Storage`] the engine runs on
//! must do, checked the same way on each (the daemon's SQLite store, the
//! simulator's store and this crate's unit-test double). It is compiled for
//! this crate's tests and, with the `testkit` feature, for the tests of the
//! crates that implement a store; no shipped build has it.
//!
//! A store is reached through a [`Subject`], which opens a fresh one, restarts
//! it, and makes its disk full or its commits fail. [`run`] runs every check;
//! [`model`] replays a script of operations on the store and on a model of the
//! trait (a map of committed entries with an overlay of staged ones), for
//! property tests. Each returns the first difference from the contract, named,
//! as an `Err`.
//!
//! # After a failure
//!
//! [`Storage`] lets an error drop every staged write and refuse every call
//! until a rollback, and lets a failed commit's batch turn up whole at the
//! next open. Stores differ there: the simulator's keeps its staged writes by
//! default; SQLite drops them; and a commit whose log reached the disk before
//! its error leaves the batch for the next open. The checks hold every store
//! to what all of them keep: after a failed call a read shows the staged
//! writes or fails, never the committed state as if nothing had been staged;
//! a rollback leaves the committed state, and the store works again; a failed
//! batch is wholly absent or, after a restart that no later commit preceded,
//! wholly there, never in part; and a write staged after a failure is never
//! durable on its own. The engine rolls back after every storage error (its
//! `sync::commit` module), so it never retries a commit.

use std::collections::BTreeMap;

use licketysync_keys::chunk::MAX_STORED_LEN;

use super::{Entry, Storage, StorageError};

/// The largest value the engine stores: a chunk blob at its largest
/// ([`MAX_STORED_LEN`], 4 325 416 bytes). A held record's value, its local
/// sequence number and its envelope, is at most 4 000 008 bytes.
pub const LARGEST_VALUE: usize = MAX_STORED_LEN;

/// A store under test, as the checks reach it.
pub trait Subject {
    /// The store.
    type Store: Storage;

    /// A new, empty store.
    fn fresh(&mut self) -> Self::Store;

    /// `store` as a restart finds it: what was committed, and nothing staged.
    fn reopen(&mut self, store: Self::Store) -> Self::Store;

    /// Fills the store's disk (`true`), so that a `put` of a value of
    /// [`LARGEST_VALUE`] bytes fails with [`StorageError::Full`], or gives it
    /// room again (`false`).
    fn set_full(&mut self, store: &mut Self::Store, full: bool);

    /// Makes every `commit` fail (`true`), as a full disk or an I/O error at
    /// the commit does, or succeed again (`false`).
    fn set_commit_fails(&mut self, store: &mut Self::Store, fails: bool);
}

/// What a check found: `Err` names the first difference from the contract.
pub type Outcome = Result<(), String>;

/// Entries by key, as a scan of every key returns them.
type Map = BTreeMap<Vec<u8>, Vec<u8>>;

/// A check, as [`run`] lists them.
type Check<T> = fn(&mut T) -> Outcome;

/// Runs every check, each on fresh stores, and returns the first failure,
/// prefixed with the check's name.
///
/// # Errors
/// The first check that fails, as `name: what differed`.
pub fn run<T: Subject>(subject: &mut T) -> Outcome {
    let checks: [(&str, Check<T>); 11] = [
        ("get_and_overwrite", get_and_overwrite),
        ("staged_writes_are_visible", staged_writes_are_visible),
        ("rollback_discards", rollback_discards),
        ("commit_is_durable_and_atomic", commit_is_durable_and_atomic),
        ("scan_by_prefix_in_key_order", scan_by_prefix_in_key_order),
        ("empty_keys_and_values", empty_keys_and_values),
        ("binary_keys", binary_keys),
        ("prefix_edges", prefix_edges),
        ("large_values", large_values),
        ("full_disk", full_disk),
        ("put_after_failed_commit", put_after_failed_commit),
    ];
    for (name, check) in checks {
        check(subject).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

/// `len` bytes that depend on `seed` and on their position, with a period of
/// 251 bytes (a prime, so no page size divides it): a truncated, shifted or
/// swapped value does not compare equal.
#[must_use]
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i + usize::from(seed)) % 251).unwrap_or(0))
        .collect()
}

/// `bytes` for a message: whole up to 16 bytes, else its length and start.
fn show(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        format!("{bytes:02x?}")
    } else {
        let start: Vec<u8> = bytes.iter().take(8).copied().collect();
        format!("{} bytes from {start:02x?}", bytes.len())
    }
}

fn show_value(got: &Result<Option<Vec<u8>>, StorageError>) -> String {
    match got {
        Ok(Some(v)) => show(v),
        Ok(None) => "nothing".into(),
        Err(e) => format!("an error ({e})"),
    }
}

fn show_entries<'a>(entries: impl IntoIterator<Item = (&'a Vec<u8>, &'a Vec<u8>)>) -> String {
    let items: Vec<String> = entries
        .into_iter()
        .map(|(k, v)| format!("{}={}", show(k), show(v)))
        .collect();
    format!("[{}]", items.join(", "))
}

/// The entries of ASCII keys and values.
fn text(entries: &[(&str, &str)]) -> Map {
    entries
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

fn put<S: Storage>(s: &mut S, key: &[u8], value: &[u8]) -> Outcome {
    s.put(key, value)
        .map_err(|e| format!("put at {} failed: {e}", show(key)))
}

fn delete<S: Storage>(s: &mut S, key: &[u8]) -> Outcome {
    s.delete(key)
        .map_err(|e| format!("delete at {} failed: {e}", show(key)))
}

fn commit<S: Storage>(s: &mut S) -> Outcome {
    s.commit().map_err(|e| format!("commit failed: {e}"))
}

/// `get(key)` returns `want`.
fn has<S: Storage>(what: &str, s: &S, key: &[u8], want: Option<&[u8]>) -> Outcome {
    let got = s.get(key);
    if got.as_ref().is_ok_and(|v| v.as_deref() == want) {
        return Ok(());
    }
    Err(format!(
        "{what}: get at {} gave {}, want {}",
        show(key),
        show_value(&got),
        want.map_or_else(|| "nothing".into(), show)
    ))
}

/// The keys of `entries` rise strictly, as unsigned bytes.
fn in_order(entries: &[Entry]) -> Outcome {
    for pair in entries.windows(2) {
        if let [(a, _), (b, _)] = pair
            && a >= b
        {
            return Err(format!("a scan gave {} before {}", show(a), show(b)));
        }
    }
    Ok(())
}

/// `scan(prefix)` returns `want`, in key order.
fn scan_is<S: Storage>(what: &str, s: &S, prefix: &[u8], want: &[Entry]) -> Outcome {
    let got = s
        .scan(prefix)
        .map_err(|e| format!("{what}: scan of {} failed: {e}", show(prefix)))?;
    in_order(&got).map_err(|e| format!("{what}: {e}"))?;
    if got != want {
        return Err(format!(
            "{what}: scan of {} gave {}, want {}",
            show(prefix),
            show_entries(got.iter().map(|(k, v)| (k, v))),
            show_entries(want.iter().map(|(k, v)| (k, v)))
        ));
    }
    Ok(())
}

/// `store` holds exactly `want`, staged writes included: by one scan of every
/// key, in key order, and by `get` of each.
fn holds<S: Storage>(what: &str, s: &S, want: &Map) -> Outcome {
    let entries: Vec<Entry> = want.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    scan_is(what, s, &[], &entries)?;
    for (k, v) in want {
        has(what, s, k, Some(v))?;
    }
    Ok(())
}

/// `store` holds exactly one of `options`, as [`holds`] judges; returns it.
fn holds_one_of<'m, S: Storage>(what: &str, s: &S, options: &[&'m Map]) -> Result<&'m Map, String> {
    let entries = s
        .scan(&[])
        .map_err(|e| format!("{what}: scan of every key failed: {e}"))?;
    in_order(&entries).map_err(|e| format!("{what}: {e}"))?;
    let got: Map = entries.into_iter().collect();
    let Some(&found) = options.iter().find(|&&option| *option == got) else {
        let want: Vec<String> = options.iter().map(|o| show_entries(o.iter())).collect();
        return Err(format!(
            "{what}: holds {}, want one of {}",
            show_entries(got.iter()),
            want.join(" or ")
        ));
    };
    holds(what, s, found)?;
    Ok(found)
}

/// A read after a failure shows `want`, what was staged, or fails: it never
/// shows anything else, such as the committed state in place of staged writes.
fn reads_as(read: &Result<Option<Vec<u8>>, StorageError>, want: Option<&[u8]>) -> bool {
    match read {
        Ok(v) => v.as_deref() == want,
        Err(_) => true,
    }
}

/// Makes one commit fail, as the subject says how, and gives commits back.
fn fail_commit<T: Subject>(subject: &mut T, s: &mut T::Store) -> Outcome {
    subject.set_commit_fails(s, true);
    let failed = s.commit();
    subject.set_commit_fails(s, false);
    if failed.is_ok() {
        return Err("a commit succeeded while commits fail".into());
    }
    Ok(())
}

/// A key never written reads as nothing; a put reads back at once, an
/// overwrite replaces it, staged or committed, and both survive a restart.
///
/// # Errors
/// The first difference.
pub fn get_and_overwrite<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    has("a fresh store", &s, b"k", None)?;
    holds("a fresh store", &s, &Map::new())?;
    put(&mut s, b"k", b"one")?;
    has("after a put", &s, b"k", Some(b"one"))?;
    has("a key that extends one written", &s, b"k2", None)?;
    has("a key that one written extends", &s, b"", None)?;
    put(&mut s, b"k", b"two")?;
    has("after an overwrite", &s, b"k", Some(b"two"))?;
    commit(&mut s)?;
    has("after the commit", &s, b"k", Some(b"two"))?;
    put(&mut s, b"k", b"three")?;
    has(
        "after an overwrite of a committed value",
        &s,
        b"k",
        Some(b"three"),
    )?;
    commit(&mut s)?;
    let s = subject.reopen(s);
    holds("after a restart", &s, &text(&[("k", "three")]))
}

/// Staged puts, overwrites and deletes show at once in `get` and `scan`, over
/// what is committed, and commit as they were staged.
///
/// # Errors
/// The first difference.
pub fn staged_writes_are_visible<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    for (k, v) in [("a", "1"), ("b", "2"), ("c", "3")] {
        put(&mut s, k.as_bytes(), v.as_bytes())?;
    }
    commit(&mut s)?;
    put(&mut s, b"d", b"4")?;
    put(&mut s, b"b", b"22")?;
    delete(&mut s, b"c")?;
    delete(&mut s, b"never")?;
    has("a staged delete of a committed key", &s, b"c", None)?;
    has("a staged delete of a key never written", &s, b"never", None)?;
    holds(
        "staged over committed",
        &s,
        &text(&[("a", "1"), ("b", "22"), ("d", "4")]),
    )?;
    delete(&mut s, b"d")?;
    has("a staged put, then deleted", &s, b"d", None)?;
    put(&mut s, b"c", b"33")?;
    has("a staged delete, then put", &s, b"c", Some(b"33"))?;
    let want = text(&[("a", "1"), ("b", "22"), ("c", "33")]);
    holds("after more staged writes", &s, &want)?;
    commit(&mut s)?;
    holds("after the commit", &s, &want)?;
    let s = subject.reopen(s);
    holds("after a restart", &s, &want)
}

/// A rollback discards every staged write and keeps what is committed; the
/// store works after it, and a second rollback changes nothing.
///
/// # Errors
/// The first difference.
pub fn rollback_discards<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    put(&mut s, b"a", b"1")?;
    put(&mut s, b"b", b"2")?;
    commit(&mut s)?;
    put(&mut s, b"a", b"11")?;
    delete(&mut s, b"b")?;
    put(&mut s, b"c", b"3")?;
    s.rollback();
    let committed = text(&[("a", "1"), ("b", "2")]);
    holds("after a rollback", &s, &committed)?;
    s.rollback();
    holds("after a rollback with nothing staged", &s, &committed)?;
    put(&mut s, b"d", b"4")?;
    commit(&mut s)?;
    let s = subject.reopen(s);
    holds(
        "after a commit since the rollback and a restart",
        &s,
        &text(&[("a", "1"), ("b", "2"), ("d", "4")]),
    )?;
    let mut s = subject.fresh();
    put(&mut s, b"x", b"y")?;
    s.rollback();
    holds("a fresh store after a rollback", &s, &Map::new())?;
    let s = subject.reopen(s);
    holds(
        "a fresh store after a rollback and a restart",
        &s,
        &Map::new(),
    )
}

/// A commit makes its whole batch durable: puts, overwrites and deletes, of
/// values that span many pages of a database, survive a restart together. A
/// batch not committed leaves no trace after a restart, and a commit with
/// nothing staged changes nothing.
///
/// # Errors
/// The first difference.
pub fn commit_is_durable_and_atomic<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    let mut want = Map::new();
    for i in 0..8u8 {
        let (k, v) = (vec![b'k', i], pattern(3_000, i));
        put(&mut s, &k, &v)?;
        want.insert(k, v);
    }
    commit(&mut s)?;
    let mut s = subject.reopen(s);
    holds("the first batch after a restart", &s, &want)?;
    for i in 1..4u8 {
        let (k, v) = (vec![b'k', i], pattern(5_000, i));
        put(&mut s, &k, &v)?;
        want.insert(k, v);
    }
    for i in 4..6u8 {
        let k = vec![b'k', i];
        delete(&mut s, &k)?;
        want.remove(&k);
    }
    for i in 0..4u8 {
        let (k, v) = (vec![b'n', i], pattern(2_000, i));
        put(&mut s, &k, &v)?;
        want.insert(k, v);
    }
    commit(&mut s)?;
    let mut s = subject.reopen(s);
    holds("the second batch after a restart", &s, &want)?;
    for k in want.keys() {
        put(&mut s, k, &pattern(4_000, 200))?;
    }
    delete(&mut s, &[b'k', 0])?;
    put(&mut s, b"new", b"x")?;
    let mut s = subject.reopen(s);
    holds("a batch not committed, after a restart", &s, &want)?;
    commit(&mut s)?;
    let s = subject.reopen(s);
    holds("after a commit of nothing and a restart", &s, &want)
}

/// The scans [`scan_by_prefix_in_key_order`] checks, each key holding itself.
fn scans<S: Storage>(what: &str, s: &S) -> Outcome {
    let cases: [(&str, &[&str]); 7] = [
        ("p/", &["p/0", "p/1", "p/2", "p/25", "p/3"]),
        ("p", &["p", "p/0", "p/1", "p/2", "p/25", "p/3", "pz"]),
        (
            "",
            &["o", "p", "p/0", "p/1", "p/2", "p/25", "p/3", "pz", "q"],
        ),
        ("p/2", &["p/2", "p/25"]),
        ("p/22", &[]),
        ("r", &[]),
        ("p/1/deeper", &[]),
    ];
    for (prefix, keys) in cases {
        let want: Vec<Entry> = keys
            .iter()
            .map(|k| (k.as_bytes().to_vec(), k.as_bytes().to_vec()))
            .collect();
        scan_is(what, s, prefix.as_bytes(), &want)?;
    }
    Ok(())
}

/// A scan returns exactly the keys that start with its prefix, the prefix
/// itself included, in key order, merging staged writes over committed ones.
///
/// # Errors
/// The first difference.
pub fn scan_by_prefix_in_key_order<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    for k in ["p/3", "p/1", "q", "p", "p/22", "o", "p/2"] {
        put(&mut s, k.as_bytes(), k.as_bytes())?;
    }
    commit(&mut s)?;
    for k in ["p/25", "pz", "p/0"] {
        put(&mut s, k.as_bytes(), k.as_bytes())?;
    }
    delete(&mut s, b"p/22")?;
    scans("staged over committed", &s)?;
    commit(&mut s)?;
    scans("after the commit", &s)?;
    let s = subject.reopen(s);
    scans("after a restart", &s)
}

/// The empty key and the empty value are a key and a value like others: an
/// empty value reads as present, not as nothing.
///
/// # Errors
/// The first difference.
pub fn empty_keys_and_values<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    has("a fresh store's empty key", &s, b"", None)?;
    put(&mut s, b"", b"")?;
    has("the empty key holding the empty value", &s, b"", Some(b""))?;
    put(&mut s, b"e", b"")?;
    has("an empty value", &s, b"e", Some(b""))?;
    put(&mut s, b"v", b"x")?;
    let want = text(&[("", ""), ("e", ""), ("v", "x")]);
    holds("staged", &s, &want)?;
    scan_is("staged", &s, b"e", &[(b"e".to_vec(), Vec::new())])?;
    commit(&mut s)?;
    let mut s = subject.reopen(s);
    holds("after a restart", &s, &want)?;
    scan_is("after a restart", &s, b"e", &[(b"e".to_vec(), Vec::new())])?;
    put(&mut s, b"", b"now")?;
    has("the empty key overwritten", &s, b"", Some(b"now"))?;
    commit(&mut s)?;
    delete(&mut s, b"")?;
    has("the empty key deleted", &s, b"", None)?;
    commit(&mut s)?;
    let s = subject.reopen(s);
    holds(
        "after the empty key's delete and a restart",
        &s,
        &text(&[("e", ""), ("v", "x")]),
    )
}

/// Keys and values are bytes, not text: a 0x00 inside or at the end of a key
/// does not end it, and keys order as unsigned bytes (0x7f before 0x80, 0xff
/// last), staged, committed and after a restart.
///
/// # Errors
/// The first difference.
pub fn binary_keys<T: Subject>(subject: &mut T) -> Outcome {
    let sorted: [&[u8]; 12] = [
        &[0x00],
        &[0x00, 0x00],
        &[0x00, 0xff],
        &[0x01],
        &[0x61],
        &[0x61, 0x00],
        &[0x61, 0x00, 0x62],
        &[0x7f],
        &[0x80],
        &[0xff],
        &[0xff, 0x00],
        &[0xff, 0xff],
    ];
    let value = |k: &[u8]| -> Vec<u8> {
        let mut v = vec![0x00, 0xff];
        v.extend(k.iter().rev());
        v.push(0x00);
        v
    };
    let want: Map = sorted.iter().map(|k| (k.to_vec(), value(k))).collect();
    let (first, last) = sorted.split_at(6);
    let mut s = subject.fresh();
    for k in last.iter().rev() {
        put(&mut s, k, &value(k))?;
    }
    commit(&mut s)?;
    for k in first.iter().rev() {
        put(&mut s, k, &value(k))?;
    }
    holds("half committed, half staged", &s, &want)?;
    commit(&mut s)?;
    let s = subject.reopen(s);
    holds("after a restart", &s, &want)
}

/// The scans [`prefix_edges`] checks: of each prefix, the keys of `keys`
/// (which are in key order) that start with it.
fn edges<S: Storage>(what: &str, s: &S, keys: &[&[u8]], prefixes: &[&[u8]]) -> Outcome {
    for prefix in prefixes {
        let want: Vec<Entry> = keys
            .iter()
            .filter(|k| k.starts_with(prefix))
            .map(|k| (k.to_vec(), k.to_vec()))
            .collect();
        scan_is(what, s, prefix, &want)?;
    }
    Ok(())
}

/// Prefixes at the edges of the key space: 0xff ones, which no key bounds from
/// above, prefixes ending in 0xff, whose bound carries into the byte before,
/// 0x00 ones and the empty prefix, staged, committed and after a restart.
///
/// # Errors
/// The first difference.
pub fn prefix_edges<T: Subject>(subject: &mut T) -> Outcome {
    let keys: [&[u8]; 11] = [
        &[],
        &[0x00],
        &[0x01, 0xff],
        &[0x01, 0xff, 0xff],
        &[0x02],
        &[0xfe],
        &[0xfe, 0xff],
        &[0xff],
        &[0xff, 0x00],
        &[0xff, 0xff],
        &[0xff, 0xff, 0xff],
    ];
    let prefixes: [&[u8]; 11] = [
        &[0xff],
        &[0xff, 0xff],
        &[0xff, 0xff, 0xff],
        &[0xff, 0xff, 0xff, 0xff],
        &[0xff, 0x00],
        &[0xfe],
        &[0x01, 0xff],
        &[0x01],
        &[0x00],
        &[0x02, 0x00],
        &[],
    ];
    let mut s = subject.fresh();
    for k in keys {
        put(&mut s, k, k)?;
    }
    edges("staged", &s, &keys, &prefixes)?;
    commit(&mut s)?;
    edges("committed", &s, &keys, &prefixes)?;
    let s = subject.reopen(s);
    edges("after a restart", &s, &keys, &prefixes)
}

/// Values up to [`LARGEST_VALUE`] bytes read back whole, staged, committed
/// and after a restart, and a large value and a small one replace each other.
///
/// # Errors
/// The first difference.
pub fn large_values<T: Subject>(subject: &mut T) -> Outcome {
    let sizes = [
        LARGEST_VALUE,
        4_325_415,
        1_048_576,
        65_537,
        4_097,
        4_096,
        4_095,
        1_000,
    ];
    let mut want = Map::new();
    let mut s = subject.fresh();
    for (i, len) in sizes.into_iter().enumerate() {
        let k = format!("big/{i}").into_bytes();
        let v = pattern(len, u8::try_from(i).unwrap_or(0));
        put(&mut s, &k, &v)?;
        want.insert(k, v);
    }
    holds("staged", &s, &want)?;
    commit(&mut s)?;
    let mut s = subject.reopen(s);
    holds("after a restart", &s, &want)?;
    for (k, v) in [
        (b"big/0".to_vec(), b"small".to_vec()),
        (b"big/7".to_vec(), pattern(LARGEST_VALUE, 99)),
    ] {
        put(&mut s, &k, &v)?;
        want.insert(k, v);
    }
    commit(&mut s)?;
    let s = subject.reopen(s);
    holds("after swapping a large value and a small one", &s, &want)
}

/// A full disk fails a put with `Full`, and that put stages nothing; a write
/// staged before it reads back or the store refuses to read; a commit while
/// the disk is full makes the batch durable whole or not at all; and once the
/// disk has room, the store works again after a rollback.
///
/// # Errors
/// The first difference.
pub fn full_disk<T: Subject>(subject: &mut T) -> Outcome {
    let mut s = subject.fresh();
    put(&mut s, b"k0", b"v0")?;
    commit(&mut s)?;
    put(&mut s, b"a", b"A")?;
    subject.set_full(&mut s, true);
    let big = pattern(LARGEST_VALUE, 7);
    let tried = s.put(b"big", &big);
    if tried != Err(StorageError::Full) {
        return Err(format!("a put on a full disk gave {tried:?}, want Full"));
    }
    let read = s.get(b"big");
    if !reads_as(&read, None) {
        return Err(format!(
            "the put that failed reads as {}",
            show_value(&read)
        ));
    }
    let read = s.get(b"a");
    if !reads_as(&read, Some(b"A")) {
        return Err(format!(
            "after a failed put, a write staged before it read as {}",
            show_value(&read)
        ));
    }
    if let Ok(entries) = s.scan(&[]) {
        let staged = text(&[("a", "A"), ("k0", "v0")]);
        if !entries.iter().map(|(k, v)| (k, v)).eq(staged.iter()) {
            return Err(format!(
                "after a failed put, a scan gave {}",
                show_entries(entries.iter().map(|(k, v)| (k, v)))
            ));
        }
    }
    let committed = s.commit();
    subject.set_full(&mut s, false);
    s.rollback();
    let mut want = text(&[("k0", "v0")]);
    if committed.is_ok() {
        want.insert(b"a".to_vec(), b"A".to_vec());
    }
    holds("after the disk had room and a rollback", &s, &want)?;
    put(&mut s, b"big", &big)?;
    commit(&mut s)?;
    want.insert(b"big".to_vec(), big);
    let s = subject.reopen(s);
    holds("after a commit since and a restart", &s, &want)
}

/// The failed batch of [`put_after_failed_commit`]: `a` put and `k0`
/// deleted, staged over a store that holds `k0`.
fn stage_batch<S: Storage>(s: &mut S) -> Outcome {
    put(s, b"a", b"A")?;
    delete(s, b"k0")
}

/// After a commit that failed: a read shows the staged writes or fails; a
/// rollback leaves the committed state; a put that follows is not durable on
/// its own; a restart that no later commit preceded finds the failed batch
/// wholly absent or wholly there; and a later commit makes durable what is
/// staged then (the failed batch too, if the store kept it staged), or fails
/// and leaves the committed state.
///
/// # Errors
/// The first difference.
pub fn put_after_failed_commit<T: Subject>(subject: &mut T) -> Outcome {
    let base = text(&[("k0", "v0")]);
    let batch = text(&[("a", "A")]);
    let mut s = subject.fresh();
    put(&mut s, b"k0", b"v0")?;
    commit(&mut s)?;
    stage_batch(&mut s)?;
    fail_commit(subject, &mut s)?;
    // It may stage, or fail until a rollback; either way it is not durable.
    let _ = s.put(b"b", b"B");
    let s = subject.reopen(s);
    holds_one_of(
        "a restart after a failed commit and a put",
        &s,
        &[&base, &batch],
    )?;
    let mut s = subject.fresh();
    put(&mut s, b"k0", b"v0")?;
    commit(&mut s)?;
    stage_batch(&mut s)?;
    fail_commit(subject, &mut s)?;
    let read = s.get(b"a");
    if !reads_as(&read, Some(b"A")) {
        return Err(format!(
            "after a failed commit, a staged put read as {}",
            show_value(&read)
        ));
    }
    let read = s.get(b"k0");
    if !reads_as(&read, None) {
        return Err(format!(
            "after a failed commit, a staged delete read as {}",
            show_value(&read)
        ));
    }
    s.rollback();
    holds("a rollback after a failed commit", &s, &base)?;
    let mut s = subject.reopen(s);
    let start = holds_one_of("a restart after those", &s, &[&base, &batch])?.clone();
    stage_batch(&mut s)?;
    fail_commit(subject, &mut s)?;
    let committed = s.put(b"b", b"B").and_then(|()| s.commit()).is_ok();
    let mut want = if committed {
        text(&[("a", "A"), ("b", "B")])
    } else {
        s.rollback();
        start
    };
    holds(
        "after a put and a commit that followed a failed one",
        &s,
        &want,
    )?;
    let mut s = subject.reopen(s);
    if committed {
        holds("after those and a restart", &s, &want)?;
    } else {
        want = holds_one_of("after those and a restart", &s, &[&want, &batch])?.clone();
    }
    put(&mut s, b"c", b"C")?;
    commit(&mut s)?;
    want.insert(b"c".to_vec(), b"C".to_vec());
    let s = subject.reopen(s);
    holds("after a commit since and a restart", &s, &want)
}

/// The keys a [`model`] script picks from: the empty key, 0x00 and 0xff alone,
/// at the end and doubled, and keys that are prefixes of others.
const KEYS: [&[u8]; 16] = [
    &[],
    &[0x00],
    &[0x00, 0x00],
    &[0x00, 0xff],
    &[0x01],
    b"a",
    &[0x61, 0x00],
    b"ab",
    b"abc",
    &[0x7f],
    &[0x80],
    &[0xfe],
    &[0xfe, 0xff],
    &[0xff],
    &[0xff, 0x00],
    &[0xff, 0xff],
];

/// The lengths of the values a [`model`] script writes: empty, short, and
/// around a 4 KiB page.
const VALUE_LENS: [usize; 16] = [
    0, 1, 2, 3, 8, 64, 255, 256, 1_000, 2_048, 4_095, 4_096, 4_097, 8_192, 10_000, 20_000,
];

/// The trait's model: committed entries, and the staged writes over them (a
/// `None` is a staged delete).
#[derive(Default)]
struct Model {
    committed: Map,
    staged: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Model {
    fn view(&self) -> Map {
        let mut all = self.committed.clone();
        for (k, v) in &self.staged {
            match v {
                Some(v) => all.insert(k.clone(), v.clone()),
                None => all.remove(k),
            };
        }
        all
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.staged.get(key) {
            Some(v) => v.clone(),
            None => self.committed.get(key).cloned(),
        }
    }

    fn scan(&self, prefix: &[u8]) -> Vec<Entry> {
        self.view()
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect()
    }

    fn commit(&mut self) {
        self.committed = self.view();
        self.staged.clear();
    }
}

/// Replays `script` on a fresh store and on a model of the trait, comparing
/// every read, then what the store holds at the end and after a restart. Each
/// pair of bytes is one operation: the first byte's value modulo 8 picks it
/// (0 and 1 put, 2 delete, 3 get, 4 scan with the key as the prefix, 5
/// commit, 6 rollback, 7 restart), the second byte's low four bits the key
/// from 16 (the empty key, 0x00 and 0xff alone, at the end and doubled, and
/// keys that are prefixes of others) and its high four the length of the value
/// from 16 (empty, short, and around a 4 KiB page), whose content the first
/// byte seeds. No failure is injected.
///
/// # Errors
/// The first difference, with the step at which it showed.
pub fn model<T: Subject>(subject: &mut T, script: &[u8]) -> Outcome {
    let mut s = subject.fresh();
    let mut m = Model::default();
    for (step, pair) in script.chunks(2).enumerate() {
        let op = pair.first().copied().unwrap_or(0);
        let arg = pair.get(1).copied().unwrap_or(0);
        let key = KEYS.get(usize::from(arg & 0x0f)).copied().unwrap_or(&[]);
        let len = VALUE_LENS.get(usize::from(arg >> 4)).copied().unwrap_or(0);
        let what = format!("step {step}");
        match op % 8 {
            0 | 1 => {
                let v = pattern(len, op);
                put(&mut s, key, &v).map_err(|e| format!("{what}: {e}"))?;
                m.staged.insert(key.to_vec(), Some(v));
            }
            2 => {
                delete(&mut s, key).map_err(|e| format!("{what}: {e}"))?;
                m.staged.insert(key.to_vec(), None);
            }
            3 => has(&what, &s, key, m.get(key).as_deref())?,
            4 => scan_is(&what, &s, key, &m.scan(key))?,
            5 => {
                commit(&mut s).map_err(|e| format!("{what}: {e}"))?;
                m.commit();
            }
            6 => {
                s.rollback();
                m.staged.clear();
            }
            _ => {
                s = subject.reopen(s);
                m.staged.clear();
            }
        }
    }
    holds("at the end of the script", &s, &m.view())?;
    let s = subject.reopen(s);
    holds("after a restart at the end", &s, &m.committed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use proptest::prelude::*;

    use super::*;
    use crate::testkit::{FakeStorage, proptest_config};

    /// The engine's unit-test double, restarted by keeping what it committed.
    struct Fake;

    impl Subject for Fake {
        type Store = FakeStorage;
        fn fresh(&mut self) -> FakeStorage {
            FakeStorage::default()
        }
        fn reopen(&mut self, store: FakeStorage) -> FakeStorage {
            FakeStorage {
                committed: store.committed,
                ..FakeStorage::default()
            }
        }
        fn set_full(&mut self, store: &mut FakeStorage, full: bool) {
            store.full = full;
        }
        fn set_commit_fails(&mut self, store: &mut FakeStorage, fails: bool) {
            store.commit_fails = fails;
        }
    }

    #[test]
    fn the_unit_test_double_conforms() {
        assert_eq!(run(&mut Fake), Ok(()));
    }

    proptest! {
        #![proptest_config(proptest_config(64))]

        #[test]
        fn the_unit_test_double_matches_the_model(
            script in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            prop_assert_eq!(model(&mut Fake, &script), Ok(()));
        }
    }

    /// What a store without a flaw does after a failure: the contract allows
    /// each.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    enum Keeps {
        /// The staged writes stay staged (the simulator's default).
        #[default]
        Staged,
        /// Every staged write goes, and every call fails until a rollback
        /// (SQLite's).
        Nothing,
        /// As `Nothing`, and a failed commit's batch reached the disk: the
        /// next open finds it, unless a later commit that wrote succeeded
        /// first.
        Limbo,
    }

    /// One way a store can break the contract: the check that must catch it
    /// fails on a [`Flawed`] store with it and passes on one without.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    enum Flaw {
        #[default]
        None,
        GetIgnoresStaged,
        OverwriteIgnored,
        DeleteIgnored,
        ScanIgnoresStaged,
        ScanReversed,
        RollbackKeeps,
        RestartKeepsStaged,
        CommitKeepsFirstOnly,
        EmptyValueIsNothing,
        KeyEndsAtNul,
        SignedOrder,
        PrefixOfFfFindsNothing,
        ValuesCapped,
        FullIgnored,
        FailedPutForgets,
        /// After a failed put, `get` reads the committed state; `scan` is right.
        FailedPutReadsStale,
        FailedCommitAutocommits,
        FailedCommitForgets,
        /// A failed commit's batch is committed at once.
        FailedCommitVisible,
        /// The next open finds part of a failed commit's batch.
        FailedCommitPersistsPart,
    }

    /// The model as a store, with one flaw.
    #[derive(Default)]
    #[allow(clippy::struct_excessive_bools, reason = "test code: one switch each")]
    struct Flawed {
        flaw: Flaw,
        keeps: Keeps,
        model: Model,
        full: bool,
        commit_fails: bool,
        /// After a failed commit, writes go straight to the committed state.
        autocommit: bool,
        /// Every call fails until a rollback.
        refusing: bool,
        /// `get` reads the committed state until a rollback.
        stale: bool,
        /// A failed commit's batch, which the next open applies.
        limbo: Option<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    }

    impl Flawed {
        fn key(&self, key: &[u8]) -> Vec<u8> {
            if self.flaw == Flaw::KeyEndsAtNul {
                key.split(|&b| b == 0).next().unwrap_or_default().to_vec()
            } else {
                key.to_vec()
            }
        }

        fn refuse(&self) -> Result<(), StorageError> {
            if self.refusing {
                return Err(StorageError::Io("refusing until a rollback".into()));
            }
            Ok(())
        }

        /// What a failure does to the staged writes, as `keeps` says.
        fn fail(&mut self) {
            if self.keeps != Keeps::Staged {
                self.model.staged.clear();
                self.refusing = true;
            }
        }
    }

    impl Storage for Flawed {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.refuse()?;
            let key = self.key(key);
            let v = if self.flaw == Flaw::GetIgnoresStaged || self.stale {
                self.model.committed.get(&key).cloned()
            } else {
                self.model.get(&key)
            };
            Ok(v.filter(|v| !(v.is_empty() && self.flaw == Flaw::EmptyValueIsNothing)))
        }

        fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError> {
            self.refuse()?;
            let prefix = self.key(prefix);
            let mut out: Vec<Entry> = if self.flaw == Flaw::ScanIgnoresStaged {
                let committed = self.model.committed.clone().into_iter();
                committed.filter(|(k, _)| k.starts_with(&prefix)).collect()
            } else {
                self.model.scan(&prefix)
            };
            match self.flaw {
                Flaw::ScanReversed => out.reverse(),
                Flaw::SignedOrder => {
                    out.sort_by_key(|(k, _)| k.iter().map(|b| b ^ 0x80).collect::<Vec<u8>>());
                }
                Flaw::PrefixOfFfFindsNothing if prefix.last() == Some(&0xff) => out.clear(),
                _ => {}
            }
            Ok(out)
        }

        fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.refuse()?;
            if self.full && self.flaw != Flaw::FullIgnored {
                match self.flaw {
                    Flaw::FailedPutForgets => self.model.staged.clear(),
                    Flaw::FailedPutReadsStale => self.stale = true,
                    _ => self.fail(),
                }
                return Err(StorageError::Full);
            }
            let key = self.key(key);
            let mut value = value.to_vec();
            if self.flaw == Flaw::ValuesCapped {
                value.truncate(1 << 20);
            }
            if self.autocommit {
                self.model.committed.insert(key, value);
            } else if !(self.flaw == Flaw::OverwriteIgnored && self.model.get(&key).is_some()) {
                self.model.staged.insert(key, Some(value));
            }
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StorageError> {
            self.refuse()?;
            let key = self.key(key);
            if self.flaw == Flaw::DeleteIgnored {
                return Ok(());
            }
            if self.autocommit {
                self.model.committed.remove(&key);
            } else {
                self.model.staged.insert(key, None);
            }
            Ok(())
        }

        fn commit(&mut self) -> Result<(), StorageError> {
            self.refuse()?;
            if self.full || self.commit_fails {
                match self.flaw {
                    Flaw::FailedCommitAutocommits => {
                        self.model.staged.clear();
                        self.autocommit = true;
                    }
                    Flaw::FailedCommitForgets => self.model.staged.clear(),
                    Flaw::FailedCommitVisible => self.model.commit(),
                    Flaw::FailedCommitPersistsPart => {
                        self.limbo = Some(self.model.staged.pop_first().into_iter().collect());
                        self.model.staged.clear();
                        self.refusing = true;
                    }
                    _ => {
                        if self.keeps == Keeps::Limbo {
                            self.limbo = Some(self.model.staged.clone());
                        }
                        self.fail();
                    }
                }
                return Err(StorageError::Io("commit".into()));
            }
            if self.flaw == Flaw::CommitKeepsFirstOnly {
                let first = self.model.staged.pop_first();
                self.model.staged.clear();
                self.model.staged.extend(first);
            }
            if !self.model.staged.is_empty() {
                self.limbo = None;
            }
            self.model.commit();
            Ok(())
        }

        fn rollback(&mut self) {
            self.refusing = false;
            self.stale = false;
            if self.flaw != Flaw::RollbackKeeps {
                self.model.staged.clear();
            }
        }
    }

    struct WithFlaw(Flaw, Keeps);

    impl Subject for WithFlaw {
        type Store = Flawed;
        fn fresh(&mut self) -> Flawed {
            Flawed {
                flaw: self.0,
                keeps: self.1,
                ..Flawed::default()
            }
        }
        fn reopen(&mut self, mut store: Flawed) -> Flawed {
            if self.0 != Flaw::RestartKeepsStaged {
                store.model.staged.clear();
            }
            if let Some(batch) = store.limbo.take() {
                let staged = core::mem::replace(&mut store.model.staged, batch);
                store.model.commit();
                store.model.staged = staged;
            }
            store.autocommit = false;
            store.refusing = false;
            store.stale = false;
            store
        }
        fn set_full(&mut self, store: &mut Flawed, full: bool) {
            store.full = full;
        }
        fn set_commit_fails(&mut self, store: &mut Flawed, fails: bool) {
            store.commit_fails = fails;
        }
    }

    const ALL_KEEPS: [Keeps; 3] = [Keeps::Staged, Keeps::Nothing, Keeps::Limbo];

    /// Every operation, and an odd byte at the end.
    fn every_operation() -> Vec<u8> {
        (0..16u8)
            .flat_map(|op| [op, op.wrapping_mul(17)])
            .chain([1])
            .collect()
    }

    #[test]
    fn a_store_without_a_flaw_conforms_whatever_a_failure_keeps() {
        for keeps in ALL_KEEPS {
            assert_eq!(run(&mut WithFlaw(Flaw::None, keeps)), Ok(()), "{keeps:?}");
            let every = every_operation();
            assert_eq!(model(&mut WithFlaw(Flaw::None, keeps), &every), Ok(()));
        }
    }

    #[test]
    fn each_check_catches_its_flaw() {
        let cases: [(&str, Check<WithFlaw>, Flaw); 20] = [
            ("get", get_and_overwrite, Flaw::GetIgnoresStaged),
            ("overwrite", get_and_overwrite, Flaw::OverwriteIgnored),
            ("delete", staged_writes_are_visible, Flaw::DeleteIgnored),
            ("staged", staged_writes_are_visible, Flaw::ScanIgnoresStaged),
            (
                "staged get",
                staged_writes_are_visible,
                Flaw::GetIgnoresStaged,
            ),
            ("rollback", rollback_discards, Flaw::RollbackKeeps),
            (
                "restart",
                commit_is_durable_and_atomic,
                Flaw::RestartKeepsStaged,
            ),
            (
                "partial",
                commit_is_durable_and_atomic,
                Flaw::CommitKeepsFirstOnly,
            ),
            ("order", scan_by_prefix_in_key_order, Flaw::ScanReversed),
            ("empty", empty_keys_and_values, Flaw::EmptyValueIsNothing),
            ("nul", binary_keys, Flaw::KeyEndsAtNul),
            ("signed", binary_keys, Flaw::SignedOrder),
            ("ff", prefix_edges, Flaw::PrefixOfFfFindsNothing),
            ("large", large_values, Flaw::ValuesCapped),
            ("full", full_disk, Flaw::FullIgnored),
            ("forgets", full_disk, Flaw::FailedPutForgets),
            ("stale", full_disk, Flaw::FailedPutReadsStale),
            (
                "autocommit",
                put_after_failed_commit,
                Flaw::FailedCommitAutocommits,
            ),
            (
                "forgotten",
                put_after_failed_commit,
                Flaw::FailedCommitForgets,
            ),
            (
                "visible",
                put_after_failed_commit,
                Flaw::FailedCommitVisible,
            ),
        ];
        for (name, check, flaw) in cases {
            for keeps in ALL_KEEPS {
                assert_eq!(check(&mut WithFlaw(Flaw::None, keeps)), Ok(()), "{name}");
                assert!(
                    check(&mut WithFlaw(flaw, keeps)).is_err(),
                    "{name}: {flaw:?}, {keeps:?}"
                );
            }
        }
        // Part of a failed batch after a restart.
        let part =
            put_after_failed_commit(&mut WithFlaw(Flaw::FailedCommitPersistsPart, Keeps::Limbo));
        assert_eq!(
            part,
            Err(
                "a restart after a failed commit and a put: holds [[61]=[41], [6b, 30]=[76, 30]], \
                 want one of [[6b, 30]=[76, 30]] or [[61]=[41]]"
                    .into()
            )
        );
    }

    #[test]
    fn failures_show_what_was_found_and_what_was_wanted() {
        assert_eq!(
            prefix_edges(&mut WithFlaw(Flaw::PrefixOfFfFindsNothing, Keeps::Staged)),
            Err(
                "staged: scan of [ff] gave [], want [[ff]=[ff], [ff, 00]=[ff, 00], \
                 [ff, ff]=[ff, ff], [ff, ff, ff]=[ff, ff, ff]]"
                    .into()
            )
        );
        assert_eq!(
            put_after_failed_commit(&mut WithFlaw(Flaw::FailedCommitAutocommits, Keeps::Staged)),
            Err(
                "a restart after a failed commit and a put: holds [[62]=[42], [6b, 30]=[76, 30]], \
                 want one of [[6b, 30]=[76, 30]] or [[61]=[41]]"
                    .into()
            )
        );
    }

    #[test]
    fn run_names_the_check_that_failed() {
        let failed = run(&mut WithFlaw(Flaw::ValuesCapped, Keeps::Staged)).unwrap_err();
        assert!(failed.starts_with("large_values: staged: "), "{failed}");
        let failed = run(&mut WithFlaw(Flaw::FailedCommitForgets, Keeps::Staged)).unwrap_err();
        assert!(failed.starts_with("put_after_failed_commit: "), "{failed}");
    }

    /// A commit that never fails, on a store whose commits always fail.
    #[test]
    fn a_commit_that_does_not_fail_when_told_is_caught() {
        struct Stubborn;
        impl Subject for Stubborn {
            type Store = Flawed;
            fn fresh(&mut self) -> Flawed {
                Flawed::default()
            }
            fn reopen(&mut self, store: Flawed) -> Flawed {
                store
            }
            fn set_full(&mut self, _: &mut Flawed, _: bool) {}
            fn set_commit_fails(&mut self, _: &mut Flawed, _: bool) {}
        }
        let mut s = Flawed::default();
        assert_eq!(
            fail_commit(&mut Stubborn, &mut s),
            Err("a commit succeeded while commits fail".into())
        );
        assert!(put_after_failed_commit(&mut Stubborn).is_err());
        assert!(full_disk(&mut Stubborn).is_err());
    }

    #[test]
    fn the_model_catches_flaws_in_short_scripts() {
        // Each script: (op, arg) pairs; key 5 is "a", 7 is "ab", 13 is 0xff;
        // length 3 is 3 bytes, 0 is empty.
        let cases: [(Flaw, &[u8]); 10] = [
            (Flaw::GetIgnoresStaged, &[0, 0x35, 3, 0x05]),
            (Flaw::ScanIgnoresStaged, &[0, 0x35, 4, 0x05]),
            (Flaw::ScanReversed, &[0, 0x35, 0, 0x37, 4, 0x05]),
            (Flaw::RollbackKeeps, &[0, 0x35, 6, 0, 3, 0x05]),
            (Flaw::RestartKeepsStaged, &[0, 0x35, 7, 0, 3, 0x05]),
            (
                Flaw::CommitKeepsFirstOnly,
                &[0, 0x35, 0, 0x37, 5, 0, 3, 0x07],
            ),
            (Flaw::EmptyValueIsNothing, &[0, 0x05, 3, 0x05]),
            (Flaw::PrefixOfFfFindsNothing, &[0, 0x3d, 4, 0x0d]),
            (Flaw::OverwriteIgnored, &[0, 0x35, 1, 0x45, 3, 0x05]),
            (Flaw::DeleteIgnored, &[0, 0x35, 5, 0, 2, 0x05, 3, 0x05]),
        ];
        for (flaw, script) in cases {
            let without = model(&mut WithFlaw(Flaw::None, Keeps::Staged), script);
            assert_eq!(without, Ok(()), "{flaw:?}");
            let found = model(&mut WithFlaw(flaw, Keeps::Staged), script).unwrap_err();
            assert!(found.starts_with("step "), "{flaw:?}: {found}");
        }
        // A flaw that shows only in what is left at the end.
        let found = model(
            &mut WithFlaw(Flaw::RestartKeepsStaged, Keeps::Staged),
            &[0, 0x35],
        )
        .unwrap_err();
        assert!(found.starts_with("after a restart at the end"), "{found}");
        assert_eq!(model(&mut Fake, &every_operation()), Ok(()));
    }

    #[test]
    fn messages_show_long_values_by_length_and_start() {
        assert_eq!(show(b"ab"), "[61, 62]");
        assert_eq!(
            show(&pattern(20, 0)),
            "20 bytes from [00, 01, 02, 03, 04, 05, 06, 07]"
        );
        assert_eq!(show_value(&Ok(None)), "nothing");
        assert_eq!(
            show_value(&Err(StorageError::Full)),
            "an error (storage is full)"
        );
        assert_eq!(pattern(253, 3).get(247..), Some(&[250, 0, 1, 2, 3, 4][..]));
        assert_eq!(LARGEST_VALUE, 4_325_416);
        // The literal sizes `large_values` writes.
        assert_eq!(LARGEST_VALUE - 1, 4_325_415);
        assert_eq!(1 << 20, 1_048_576);
    }
}
