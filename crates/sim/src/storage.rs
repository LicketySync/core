// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A peer's simulated disk: an in-memory key-value store with the staged and
//! committed halves the engine's [`Storage`] trait describes, a capacity, and a
//! "disk full" switch for fault injection.

use std::collections::BTreeMap;

use licketysync_engine::runtime::{Entry, Storage, StorageError};

/// A peer's persistent store. `committed` is what survives a crash; `staged`
/// holds the writes since the last commit (a `None` value is a staged delete).
/// The two byte totals are kept up to date by every write, so checking a
/// capacity costs nothing per call however large the store grows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimStorage {
    committed: BTreeMap<Vec<u8>, Vec<u8>>,
    staged: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Bytes of keys plus values in `committed`.
    committed_size: u64,
    /// Bytes of keys plus values as this process sees them: `committed` with
    /// `staged` applied over it.
    projected_size: u64,
    capacity: Option<u64>,
    full: bool,
}

fn entry_size(key: &[u8], value: &[u8]) -> u64 {
    (key.len() as u64).saturating_add(value.len() as u64)
}

impl SimStorage {
    /// An empty, unbounded store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store that refuses to hold more than `bytes` of keys plus
    /// values.
    #[must_use]
    pub fn with_capacity(bytes: u64) -> Self {
        Self {
            capacity: Some(bytes),
            ..Self::default()
        }
    }

    /// Changes the capacity; `None` is unbounded.
    pub fn set_capacity(&mut self, bytes: Option<u64>) {
        self.capacity = bytes;
    }

    /// Switches the "disk full" fault on or off: while on, every `put` and
    /// `commit` fails with [`StorageError::Full`].
    pub fn set_full(&mut self, full: bool) {
        self.full = full;
    }

    /// Whether the "disk full" fault is on.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.full
    }

    /// Simulates a crash: staged writes are gone, committed ones remain.
    pub fn crash(&mut self) {
        self.staged.clear();
        self.projected_size = self.committed_size;
    }

    /// The committed entries, as a restart would find them.
    #[must_use]
    pub const fn committed(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.committed
    }

    /// Bytes of keys plus values that are committed.
    #[must_use]
    pub const fn committed_bytes(&self) -> u64 {
        self.committed_size
    }

    /// How many writes are staged and would be lost in a crash.
    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.staged.len()
    }

    /// The bytes `key` takes as this process sees the store: its staged value
    /// if any (a staged delete takes none), else its committed one, else none.
    fn projected_entry_size(&self, key: &[u8]) -> u64 {
        match self.staged.get(key) {
            Some(Some(v)) => entry_size(key, v),
            Some(None) => 0,
            None => self.committed.get(key).map_or(0, |v| entry_size(key, v)),
        }
    }

    /// Whether the store may hold `bytes` in all.
    fn check_room(&self, bytes: u64) -> Result<(), StorageError> {
        if self.full {
            return Err(StorageError::Full);
        }
        match self.capacity {
            Some(cap) if bytes > cap => Err(StorageError::Full),
            _ => Ok(()),
        }
    }
}

impl Storage for SimStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(match self.staged.get(key) {
            Some(staged) => staged.clone(),
            None => self.committed.get(key).cloned(),
        })
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<Entry>, StorageError> {
        let mut view: BTreeMap<Vec<u8>, Vec<u8>> = self
            .committed
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in self
            .staged
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
        {
            match v {
                Some(v) => view.insert(k.clone(), v.clone()),
                None => view.remove(k),
            };
        }
        Ok(view.into_iter().collect())
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let after = self
            .projected_size
            .saturating_sub(self.projected_entry_size(key))
            .saturating_add(entry_size(key, value));
        self.check_room(after)?;
        self.staged.insert(key.to_vec(), Some(value.to_vec()));
        self.projected_size = after;
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StorageError> {
        self.projected_size = self
            .projected_size
            .saturating_sub(self.projected_entry_size(key));
        self.staged.insert(key.to_vec(), None);
        Ok(())
    }

    fn commit(&mut self) -> Result<(), StorageError> {
        self.check_room(self.projected_size)?;
        for (k, v) in std::mem::take(&mut self.staged) {
            match v {
                Some(v) => self.committed.insert(k, v),
                None => self.committed.remove(&k),
            };
        }
        self.committed_size = self.projected_size;
        Ok(())
    }

    fn rollback(&mut self) {
        self.staged.clear();
        self.projected_size = self.committed_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_writes_are_visible_but_a_crash_loses_them() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"a", b"1"), Ok(()));
        assert_eq!(s.get(b"a"), Ok(Some(b"1".to_vec())));
        assert_eq!(s.staged_len(), 1);
        assert_eq!(s.committed_bytes(), 0);
        s.crash();
        assert_eq!(s.get(b"a"), Ok(None));
        assert_eq!(s.staged_len(), 0);
    }

    #[test]
    fn committed_writes_survive_a_crash() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"a", b"1"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.put(b"b", b"2"), Ok(()));
        s.crash();
        assert_eq!(s.get(b"a"), Ok(Some(b"1".to_vec())));
        assert_eq!(s.get(b"b"), Ok(None));
        assert_eq!(s.committed().len(), 1);
        assert_eq!(s.committed_bytes(), 2);
    }

    #[test]
    fn delete_is_staged_and_scan_sees_the_projection() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"item/1", b"x"), Ok(()));
        assert_eq!(s.put(b"item/2", b"y"), Ok(()));
        assert_eq!(s.put(b"other", b"z"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.delete(b"item/1"), Ok(()));
        assert_eq!(s.get(b"item/1"), Ok(None));
        assert_eq!(
            s.scan(b"item/"),
            Ok(vec![(b"item/2".to_vec(), b"y".to_vec())])
        );
        assert_eq!(s.scan(b"").map(|v| v.len()), Ok(2));
        s.rollback();
        assert_eq!(s.get(b"item/1"), Ok(Some(b"x".to_vec())));
        assert_eq!(s.delete(b"item/1"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed().len(), 2);
        assert_eq!(s.delete(b"never-there"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed().len(), 2);
    }

    #[test]
    fn capacity_refuses_a_put_that_would_not_fit_and_leaves_the_store_unchanged() {
        let mut s = SimStorage::with_capacity(4);
        assert_eq!(s.put(b"ab", b"cd"), Ok(()));
        assert_eq!(s.put(b"e", b""), Err(StorageError::Full));
        assert_eq!(s.get(b"e"), Ok(None));
        assert_eq!(s.staged_len(), 1);
        assert_eq!(s.commit(), Ok(()));
        // Overwriting in place with the same size still fits; growing does not.
        assert_eq!(s.put(b"ab", b"xy"), Ok(()));
        assert_eq!(s.put(b"ab", b"xyz"), Err(StorageError::Full));
        s.set_capacity(None);
        assert_eq!(s.put(b"ab", b"xyz"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed_bytes(), 5);
    }

    #[test]
    fn disk_full_fault_fails_put_and_commit_until_freed() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"a", b"1"), Ok(()));
        s.set_full(true);
        assert!(s.is_full());
        assert_eq!(s.put(b"b", b"2"), Err(StorageError::Full));
        assert_eq!(s.commit(), Err(StorageError::Full));
        assert_eq!(
            s.staged_len(),
            1,
            "a failed commit leaves the writes staged"
        );
        assert_eq!(s.get(b"a"), Ok(Some(b"1".to_vec())));
        s.set_full(false);
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed().len(), 1);
    }

    fn recount(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> u64 {
        entries.iter().map(|(k, v)| entry_size(k, v)).sum()
    }

    #[test]
    fn byte_totals_follow_every_write_without_a_recount() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"a", b"12345"), Ok(()));
        assert_eq!(s.put(b"a", b"1"), Ok(()), "overwriting shrinks");
        assert_eq!(s.put(b"bb", b"22"), Ok(()));
        assert_eq!(s.delete(b"bb"), Ok(()));
        assert_eq!(s.delete(b"never"), Ok(()), "deleting nothing costs nothing");
        assert_eq!(s.projected_size, 2);
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed_bytes(), 2);
        assert_eq!(s.committed_bytes(), recount(s.committed()));
        assert_eq!(s.put(b"ccc", b"333"), Ok(()));
        assert_eq!(s.delete(b"a"), Ok(()));
        assert_eq!(s.projected_size, 6);
        assert_eq!(s.put(b"a", b"x"), Ok(()), "re-adding a staged delete");
        assert_eq!(s.projected_size, 8);
        s.rollback();
        assert_eq!(s.projected_size, s.committed_bytes());
        assert_eq!(s.put(b"d", b"4"), Ok(()));
        s.crash();
        assert_eq!(s.projected_size, 2);
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed_bytes(), recount(s.committed()));
        assert_eq!(s.committed_bytes(), 2);
    }

    #[test]
    fn a_staged_delete_frees_room_for_a_put() {
        let mut s = SimStorage::with_capacity(4);
        assert_eq!(s.put(b"ab", b"cd"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.put(b"e", b"f"), Err(StorageError::Full));
        assert_eq!(s.delete(b"ab"), Ok(()));
        assert_eq!(s.put(b"e", b"f"), Ok(()));
        assert_eq!(s.put(b"g", b"h"), Ok(()));
        assert_eq!(s.put(b"i", b"j"), Err(StorageError::Full));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed_bytes(), 4);
        assert_eq!(s.scan(b"").map(|v| v.len()), Ok(2));
    }

    #[test]
    fn scan_merges_committed_and_staged_under_the_prefix_in_key_order() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"k/2", b"c"), Ok(()));
        assert_eq!(s.put(b"k/4", b"c"), Ok(()));
        assert_eq!(s.put(b"other", b"c"), Ok(()));
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.put(b"k/1", b"s"), Ok(()));
        assert_eq!(s.put(b"k/3", b"s"), Ok(()));
        assert_eq!(s.put(b"k/4", b"s"), Ok(()), "a staged value wins");
        assert_eq!(s.delete(b"k/2"), Ok(()));
        assert_eq!(
            s.put(b"kz", b"s"),
            Ok(()),
            "shares the prefix's first byte only"
        );
        let keys: Vec<Vec<u8>> = s
            .scan(b"k/")
            .unwrap_or_default()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            vec![b"k/1".to_vec(), b"k/3".to_vec(), b"k/4".to_vec()]
        );
        assert_eq!(s.scan(b"k/4"), Ok(vec![(b"k/4".to_vec(), b"s".to_vec())]));
        assert_eq!(s.scan(b"zzz"), Ok(vec![]));
    }

    #[test]
    fn a_commit_that_no_longer_fits_fails_and_keeps_the_writes_staged() {
        let mut s = SimStorage::new();
        assert_eq!(s.put(b"abcd", b"efgh"), Ok(()));
        s.set_capacity(Some(3));
        assert_eq!(s.commit(), Err(StorageError::Full));
        assert_eq!(s.staged_len(), 1);
        s.rollback();
        assert_eq!(s.commit(), Ok(()));
        assert_eq!(s.committed_bytes(), 0);
    }
}
