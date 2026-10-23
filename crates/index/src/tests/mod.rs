// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index crate's tests: behaviour, properties over arrival orders, and
//! the test vectors of `protocol.md` 8 items 6 to 8 that are the index's.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::many_single_char_names,
    reason = "test code"
)]

mod behaviour;
mod kit;
mod properties;
mod vectors;

#[test]
fn crate_name_is_set() {
    assert_eq!(super::CRATE, "licketysync-index");
}
