// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Rebuilding a folder's set from storage (correctness review, SF 3): every
//! signature is verified first, in parallel, and the records are then
//! inserted in their stored order by the same procedures as
//! [`FolderKeys::insert`], skipping only a signature the parallel pass
//! already verified under the very key the store resolves. Nothing else is
//! skipped, so a rebuilt set is the one inserting the records one by one
//! gives. Each insertion's chain checks search only the grants above (or
//! below) the keys it names, so the set holds no folder-wide chain state that
//! an insertion would have to recompute.
//!
//! The load never panics (quality review, SF 2): with one thread, and on
//! WebAssembly, where the browser client has no threads, the signatures are
//! verified on the calling thread; elsewhere each part goes to a worker
//! started with [`std::thread::Builder::spawn_scoped`], and a part whose
//! worker cannot be started is verified on the calling thread instead.

use std::collections::BTreeMap;
use std::io;
use std::num::NonZeroUsize;
use std::thread::{Builder, Scope, ScopedJoinHandle};

use super::store::FolderKeys;
use super::{
    signature_of, GrantBody, LiftBody, RecordHash, RecordType, Rejected, RevocationBody,
    RotationBody, SignedRecord, SuspensionBody, WrapBody,
};
use crate::ids::{FolderId, KeyId};
use crate::keyset::SigningPublicKey;

/// What a rebuild could not store again: each record's hash and why.
pub type LoadFailures = Vec<(RecordHash, Rejected)>;

impl FolderKeys {
    /// Rebuilds a folder's set from `records`, the Folder record first and
    /// the rest in the order [`FolderKeys::records`] yields them (a
    /// dependency order). Signatures are verified on up to `threads` threads
    /// before anything is stored.
    ///
    /// # Errors
    ///
    /// The Folder record's [`Rejected`] when it does not verify as
    /// `expected`'s; every later record that does not store again is listed
    /// in the [`LoadFailures`] instead.
    pub fn load(
        expected: &FolderId,
        records: &[SignedRecord],
        now_unix: u64,
        threads: NonZeroUsize,
    ) -> Result<(FolderKeys, LoadFailures), Rejected> {
        let Some((folder, rest)) = records.split_first() else {
            return Err(Rejected::Malformed(super::Malformed::Decode));
        };
        let mut keys = FolderKeys::new(expected, folder.clone())?;
        let signers = signing_keys(&keys, rest);
        let verified = verify_all(rest, &signers, threads);
        let mut failures = Vec::new();
        for (record, pk) in rest.iter().zip(verified) {
            keys.set_pre_verified(pk);
            let outcome = keys.insert(record, now_unix);
            keys.set_pre_verified(None);
            if let Err(e) = outcome {
                failures.push((record.hash(), e));
            }
        }
        Ok((keys, failures))
    }
}

/// Every signing key the records can name: root's, and each key's from the
/// first grant of it among `records`.
fn signing_keys(keys: &FolderKeys, records: &[SignedRecord]) -> BTreeMap<KeyId, SigningPublicKey> {
    let mut out = BTreeMap::new();
    out.insert(KeyId::ROOT, keys.folder().root_signing_pk.clone());
    for record in records {
        if let Ok(g) = GrantBody::parse(&record.body) {
            out.entry(g.key_id).or_insert(g.signing_pk);
        }
    }
    out
}

#[cfg(test)]
thread_local! {
    /// Records whose signatures were checked on this thread (tests only),
    /// to show where the load verified them.
    pub(crate) static VERIFIED_HERE: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    /// Whether starting a worker fails on this thread, as it does on a
    /// platform without threads (tests only).
    pub(crate) static REFUSE_SPAWN: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// For each record, the key under which its signature (and a grant's proof
/// of possession) verified, or `None`; split across up to `threads` threads.
fn verify_all(
    records: &[SignedRecord],
    signers: &BTreeMap<KeyId, SigningPublicKey>,
    threads: NonZeroUsize,
) -> Vec<Option<SigningPublicKey>> {
    let inline = |part: &[SignedRecord]| -> Vec<Option<SigningPublicKey>> {
        part.iter().map(|r| verified_under(r, signers)).collect()
    };
    if threads.get() == 1 || cfg!(target_family = "wasm") {
        return inline(records);
    }
    let chunk = records.len().div_ceil(threads.get()).max(1);
    std::thread::scope(|scope| {
        let workers: Vec<_> = records
            .chunks(chunk)
            .map(|part| (part, spawn(scope, move || inline(part))))
            .collect();
        workers
            .into_iter()
            .flat_map(|(part, worker)| match worker {
                // A worker that panicked (none can) leaves its records
                // unverified, so the sequential pass verifies them itself.
                Ok(handle) => handle.join().unwrap_or_else(|_| vec![None; part.len()]),
                Err(_) => inline(part),
            })
            .collect()
    })
}

/// Starts one verification worker in `scope`; an error, never a panic, when
/// the platform cannot start a thread.
fn spawn<'scope, T: Send + 'scope>(
    scope: &'scope Scope<'scope, '_>,
    work: impl FnOnce() -> T + Send + 'scope,
) -> io::Result<ScopedJoinHandle<'scope, T>> {
    #[cfg(test)]
    if REFUSE_SPAWN.with(core::cell::Cell::get) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    Builder::new().spawn_scoped(scope, work)
}

/// The key `record`'s signature verifies under, after a grant's proof of
/// possession verified; `None` for anything else.
fn verified_under(
    record: &SignedRecord,
    signers: &BTreeMap<KeyId, SigningPublicKey>,
) -> Option<SigningPublicKey> {
    #[cfg(test)]
    VERIFIED_HERE.with(|n| n.set(n.get() + 1));
    let record_type = record.prefix().ok()?.record_type;
    let signer = match record_type {
        RecordType::Grant => {
            let g = GrantBody::parse(&record.body).ok()?;
            g.verify_possession(record).ok()?;
            g.issuer_key_id
        }
        RecordType::Rotation => RotationBody::parse(&record.body).ok()?.signer_key_id,
        RecordType::Wrap => WrapBody::parse(&record.body).ok()?.signer_key_id,
        RecordType::Revocation => RevocationBody::parse(&record.body).ok()?.signer_key_id,
        RecordType::Suspension => SuspensionBody::parse(&record.body).ok()?.signer_key_id,
        RecordType::Lift => LiftBody::parse(&record.body).ok()?.signer_key_id,
        RecordType::Folder | RecordType::RootRotation | RecordType::Index => return None,
    };
    let pk = signers.get(&signer)?;
    let signature = signature_of(record).ok()?;
    pk.verify(record_type.sig_label(), &record.body, &signature)
        .ok()
        .map(|()| pk.clone())
}
