// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The simulator's seeded random source.
//!
//! `SplitMix64` (Steele, Lea and Flood, 2014; public domain; the generator
//! behind Java's `SplittableRandom`) in twenty lines: a 64-bit counter stepped
//! by the golden-ratio constant and mixed with two multiply-xorshift rounds. It
//! is a statistical generator, not a cryptographic one, and nothing here is
//! security-relevant: it decides latencies, losses and what a simulated peer
//! gets when it asks for random bytes. It is written here rather than taken
//! from `rand_chacha` because that crate brings `ppv-lite86`, `zerocopy` and
//! their build-time dependencies, none audited at current versions in the
//! Mozilla or Google sets the project imports, for no benefit a simulator needs.

use core::time::Duration;

use crate::network::Probability;

/// A seeded, deterministic generator. Two generators built from the same seed
/// produce the same sequence on every platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    /// A generator at the start of the sequence for `seed`.
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..n`, or 0 when `n` is 0. Taken by remainder: the bias of
    /// at most `n / 2^64` is invisible to a simulator.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    /// `true` with probability `p`.
    pub fn chance(&mut self, p: Probability) -> bool {
        self.below(Probability::ONE_MILLION) < u64::from(p.per_million())
    }

    /// A duration between `lo` and `hi` inclusive, uniformly in nanoseconds;
    /// the bounds may come in either order.
    pub fn duration_between(&mut self, lo: Duration, hi: Duration) -> Duration {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        let span = hi.saturating_sub(lo);
        let span_nanos = u64::try_from(span.as_nanos()).unwrap_or(u64::MAX);
        let extra = if span_nanos == u64::MAX {
            self.next_u64()
        } else {
            self.below(span_nanos + 1)
        };
        lo.saturating_add(Duration::from_nanos(extra))
    }

    /// Fills `buf` with random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(word.iter()) {
                *dst = *src;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference sequence for `SplitMix64`: the first outputs for seeds
    /// 0 and 1 (as published with the algorithm and in the `rand_xoshiro`
    /// test suite), checked here against an independent evaluation of the
    /// algorithm as well.
    #[test]
    fn matches_the_reference_vectors() {
        let mut r = SimRng::from_seed(0);
        assert_eq!(r.next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(r.next_u64(), 0x6e78_9e6a_a1b9_65f4);
        assert_eq!(r.next_u64(), 0x06c4_5d18_8009_454f);
        assert_eq!(r.next_u64(), 0xf88b_b8a8_724c_81ec);
        let mut r = SimRng::from_seed(1);
        assert_eq!(r.next_u64(), 0x910a_2dec_8902_5cc1);
        assert_eq!(r.next_u64(), 0xbeeb_8da1_658e_ec67);
        let mut r = SimRng::from_seed(0x1234_5678_9abc_def0);
        assert_eq!(r.next_u64(), 0x1619_22c6_45ce_50e8);
        assert_eq!(r.next_u64(), 0xad76_0caf_a169_7b60);
    }

    #[test]
    fn same_seed_same_sequence_and_seeds_differ() {
        let mut a = SimRng::from_seed(42);
        let mut b = SimRng::from_seed(42);
        let mut c = SimRng::from_seed(43);
        let xs: Vec<u64> = (0..16).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..16).map(|_| b.next_u64()).collect();
        let zs: Vec<u64> = (0..16).map(|_| c.next_u64()).collect();
        assert_eq!(xs, ys);
        assert_ne!(xs, zs);
    }

    #[test]
    fn below_stays_in_range_and_handles_zero() {
        let mut r = SimRng::from_seed(7);
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
    }

    #[test]
    fn chance_honours_the_extremes_and_roughly_the_middle() {
        let mut r = SimRng::from_seed(3);
        assert!((0..100).all(|_| !r.chance(Probability::NEVER)));
        assert!((0..100).all(|_| r.chance(Probability::ALWAYS)));
        let hits = (0..10_000)
            .filter(|_| r.chance(Probability::from_f64(0.25)))
            .count();
        assert!((2_200..2_800).contains(&hits), "hits = {hits}");
    }

    #[test]
    fn duration_between_respects_bounds_in_either_order() {
        let mut r = SimRng::from_seed(9);
        let lo = Duration::from_millis(10);
        let hi = Duration::from_millis(50);
        for _ in 0..1000 {
            let d = r.duration_between(lo, hi);
            assert!(d >= lo && d <= hi, "{d:?}");
            let d = r.duration_between(hi, lo);
            assert!(d >= lo && d <= hi, "{d:?}");
        }
        assert_eq!(r.duration_between(lo, lo), lo);
        let wide = r.duration_between(Duration::ZERO, Duration::MAX);
        assert!(wide <= Duration::MAX);
    }

    #[test]
    fn fill_bytes_fills_every_byte_deterministically() {
        let mut a = SimRng::from_seed(1);
        let mut b = SimRng::from_seed(1);
        let mut x = [0u8; 13];
        let mut y = [0u8; 13];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);
        assert!(x.iter().any(|&v| v != 0));
        let mut none = [];
        a.fill_bytes(&mut none);
    }
}
