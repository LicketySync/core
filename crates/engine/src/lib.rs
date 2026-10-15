// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The sync engine: `FastCDC` chunking with keyed `BLAKE3`, Padme padding, scanning and change journals, conflict handling, versioning and archive, selective sync.
//!
//! Status: skeleton plus [`runtime`], the trait surface the engine runs on. The
//! plan ("Lickety-Sync: Project Plan") is the specification this crate
//! implements; `spec/` in this repository carries the protocol and the threat
//! model as they are written down.
//!
//! The engine performs no I/O of its own. Time, timers, the network, persistent
//! storage and randomness reach it only through the traits in [`runtime`], so the
//! same engine code runs under the daemon and under the deterministic simulator
//! (`licketysync-sim`), where a seed replays a whole run exactly.

pub mod runtime;

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-engine";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-engine");
    }
}
