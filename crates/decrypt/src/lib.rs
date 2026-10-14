// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Offline tool: turn a sealed copy and a key into plain files, and verify a sealed copy.
//!
//! Status: skeleton. The plan ("Lickety-Sync: Project Plan") is the specification
//! this crate implements; `spec/` in this repository carries the protocol and the
//! threat model as they are written down.

/// The crate's name as it appears in logs and diagnostics.
pub const CRATE: &str = "licketysync-decrypt";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_set() {
        assert_eq!(super::CRATE, "licketysync-decrypt");
    }
}
