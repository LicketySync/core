// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! How randomness reaches this crate.
//!
//! Every function that needs random bytes (a write secret, a device seed, a
//! link secret, the nonce of a sealed metadata part) takes a [`RandomFill`]: a
//! closure that fills the buffer it is given. The crate never calls a
//! generator of its own (`suites.md` section 4.3), so the same code runs under
//! the operating system's generator in the daemon and under the simulator's
//! seeded one, where a run replays exactly from its seed. Ed25519 signing and
//! chunk encryption are deterministic and take no randomness at all.
//!
//! Mapping from the engine's runtime: the engine's `Randomness` trait has
//! `fn fill_random(&mut self, buf: &mut [u8])`; a handler with a context `cx`
//! passes `&mut |buf| cx.fill_random(buf)`. Every generator handed to this
//! crate is infallible (ruling 8 of 2026-10-17, as amended): the daemon's
//! `getrandom`-backed implementation is the one place a failure of the
//! operating system's generator is handled, and it ends the process with
//! `std::process::exit` and an exit code kept for that failure alone, never
//! with `std::process::abort()` (an abort can write a core dump holding key
//! material), never with a panic, and never by falling back to a weaker
//! source.

/// A source of random bytes supplied by the caller: fills the slice it is
/// given, every time, from the caller's generator.
pub type RandomFill<'a> = dyn FnMut(&mut [u8]) + 'a;
