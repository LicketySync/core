// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The index crate's tests: `protocol.md` section 8 items 6 (each record's
//! outcome), 7 (latest only, coverage, tree deletes, expiry, heads) whole, 8
//! (set digests, their cache and serving) and 12 (the sealed-peer rule and
//! every cleanup outcome), each a JSON vector under `tests/vectors/`; the
//! open, the store and the transaction overlay; the property tests (a) to
//! (m) of item 7 (`properties`; (l) also in `structures`, (m) in
//! `structures` and `digests`); the structures that judge a tree delete
//! without a walk and keep the digests (`structures`); and the regressions,
//! each named after the bug it pins.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_panics_doc,
    clippy::assert_is_empty,
    clippy::format_push_string,
    reason = "test code"
)]

mod bounds;
mod cleanups;
mod digests;
mod fuzz_seeds;
mod heads;
pub(crate) mod kit;
mod open;
mod outcomes;
mod properties;
mod rules;
mod structures;
mod vectors;
mod views;

/// The fixed seed every property test of this crate runs from in the gate,
/// so that the gate is deterministic; the keys and protocol crates' tests
/// run from the same one.
pub(crate) const PROPTEST_SEED: u64 = 0x6c69_636b_6574_7379;

/// The proptest configuration of every property test of this crate: `cases`
/// cases, or `PROPTEST_CASES` when it is set, from the fixed
/// [`PROPTEST_SEED`], or from the seed `LICKETYSYNC_PROPTEST_SEED` names:
/// `random` for a random one (a long run outside the gate), or a number.
pub(crate) fn proptest_config(cases: u32) -> proptest::test_runner::Config {
    use proptest::test_runner::{Config, RngSeed};
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cases);
    let rng_seed = match std::env::var("LICKETYSYNC_PROPTEST_SEED") {
        Ok(v) if v == "random" => RngSeed::Random,
        Ok(v) => RngSeed::Fixed(
            v.parse()
                .unwrap_or_else(|_| panic!("LICKETYSYNC_PROPTEST_SEED={v}: random or a u64")),
        ),
        Err(_) => RngSeed::Fixed(PROPTEST_SEED),
    };
    Config {
        cases,
        rng_seed,
        ..Config::default()
    }
}
