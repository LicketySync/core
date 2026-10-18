// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! How randomness reaches this crate.
//!
//! Every function that needs random bytes takes a [`RandomFill`]: a closure
//! that fills the buffer it is given. The crate never calls a generator of its
//! own (`suites.md` section 4.3), so the same code runs under the operating
//! system's generator in the daemon and under the simulator's seeded one, where
//! a run replays exactly from its seed.
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
//!
//! The crates that take a `rand_core::CryptoRng` (`hpke` for the encapsulation
//! randomness, `ml-dsa` for hedged signing) see the closure through
//! the crate-private `Adapter`, which is the only `CryptoRng` implementation in this workspace
//! and draws from nothing but the closure.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// A source of random bytes supplied by the caller: fills the slice it is
/// given, every time, from the caller's generator.
pub type RandomFill<'a> = dyn FnMut(&mut [u8]) + 'a;

/// Presents a [`RandomFill`] to the crates that ask for a `rand_core`
/// generator.
pub(crate) struct Adapter<'a, 'b>(pub(crate) &'a mut RandomFill<'b>);

impl TryRng for Adapter<'_, '_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        (self.0)(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        (self.0)(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        (self.0)(dst);
        Ok(())
    }
}

// `rand_core` derives `Rng` and `CryptoRng` from the infallible `Try*` forms.
impl TryCryptoRng for Adapter<'_, '_> {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;
    use rand_core::Rng as _;

    #[test]
    fn adapter_draws_only_from_the_closure() {
        let mut counter = 0u8;
        let mut fill = |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
        };
        let mut a = Adapter(&mut fill);
        assert_eq!(a.next_u32(), u32::from_le_bytes([0, 1, 2, 3]));
        assert_eq!(a.next_u64(), u64::from_le_bytes([4, 5, 6, 7, 8, 9, 10, 11]));
        let mut out = [0u8; 3];
        a.fill_bytes(&mut out);
        assert_eq!(out, [12, 13, 14]);
        assert_eq!(a.try_next_u32(), Ok(u32::from_le_bytes([15, 16, 17, 18])));
        assert_eq!(
            a.try_next_u64(),
            Ok(u64::from_le_bytes([19, 20, 21, 22, 23, 24, 25, 26]))
        );
        assert_eq!(a.try_fill_bytes(&mut out), Ok(()));
        assert_eq!(out, [27, 28, 29]);
    }
}
