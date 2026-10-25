// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The authenticity checks a stored record gets when the index opens: step 1
//! and step 4 of `protocol.md` 4.4, the same functions a record from a peer
//! goes through ([`Record::parse`], which the connection's
//! [`Record::from_bytes`] calls, and [`Record::verify`], which
//! [`judge`](licketysync_protocol::record::judge) calls), spread across the
//! processor's cores.
//!
//! The signatures are the cost (one Ed25519 `verify_strict` a record), so
//! they are checked in parallel: the parsed records are split into one
//! contiguous slice per thread, each thread borrows its slice (nothing is
//! cloned), and the verdicts are joined back in input order, so the result
//! is the same on any number of threads. The calling thread checks the first
//! slice itself. A slice whose thread cannot be spawned (a platform without
//! threads, such as `wasm32-unknown-unknown`) is checked on the calling thread
//! instead; that fallback is for spawn failure, and it also takes a slice
//! whose thread panicked, though verification has no panic path.

use std::thread::Builder;

use licketysync_keys::records::SignedRecord;
use licketysync_keys::{FolderVerifier, RecordHash};
use licketysync_protocol::record::Record;

/// The stored records that pass step 1 against `folder` and whose signature
/// verifies under its verification key, in input order, and the hashes of the
/// others, of the body as stored: those failing step 1 first, then those
/// failing the signature, which the caller sorts. `threads` is how many
/// threads may verify, the calling thread included (0 counts as 1).
pub(crate) fn authentic(
    loaded: Vec<SignedRecord>,
    folder: &FolderVerifier,
    threads: usize,
) -> (Vec<Record>, Vec<RecordHash>) {
    let mut failed = Vec::new();
    let mut records: Vec<Record> = loaded
        .into_iter()
        .filter_map(|signed| {
            // Step 1 takes the envelope; its hash is kept for the report.
            let hash = signed.hash();
            Record::parse(signed, folder)
                .map_err(|_| failed.push(hash))
                .ok()
        })
        .collect();
    let mut verdicts = verified(&records, folder, threads).into_iter();
    records.retain(|record| {
        let ok = verdicts.next().unwrap_or(false);
        if !ok {
            failed.push(record.hash());
        }
        ok
    });
    (records, failed)
}

/// Whether each record's signature verifies under `folder`, in the records'
/// order, on up to `threads` threads.
fn verified(records: &[Record], folder: &FolderVerifier, threads: usize) -> Vec<bool> {
    let verify = |slice: &[Record]| -> Vec<bool> {
        slice.iter().map(|r| r.verify(folder).is_ok()).collect()
    };
    let per_thread = records.len().div_ceil(threads.max(1)).max(1);
    if per_thread >= records.len() {
        return verify(records);
    }
    std::thread::scope(|scope| {
        let mut slices = records.chunks(per_thread);
        let first = slices.next().unwrap_or_default();
        let others: Vec<_> = slices
            .map(|slice| {
                let worker = Builder::new().spawn_scoped(scope, move || verify(slice));
                (slice, worker.ok())
            })
            .collect();
        let mut out = verify(first);
        for (slice, worker) in others {
            match worker.and_then(|w| w.join().ok()) {
                Some(verdicts) => out.extend(verdicts),
                None => out.extend(verify(slice)),
            }
        }
        out
    })
}
