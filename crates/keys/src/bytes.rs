// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fixed-size joins and splits without indexing, so that no slice operation
//! in this crate can panic (TM-23).

/// Fills an `N`-byte array from `parts` in order. Callers pass parts whose
/// lengths add up to `N`, which the tests of each call site check; a shorter
/// input leaves trailing zeros and a longer one is cut, never a panic.
pub(crate) fn fill<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut out = [0u8; N];
    for (o, i) in out.iter_mut().zip(parts.iter().flat_map(|p| p.iter())) {
        *o = *i;
    }
    out
}

/// The first `N` bytes of `bytes`, or `None` if it is shorter.
pub(crate) fn prefix<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.first_chunk::<N>().copied()
}

/// Splits 64 bytes into two halves.
pub(crate) fn halves(bytes: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for (o, i) in a.iter_mut().chain(b.iter_mut()).zip(bytes.iter()) {
        *o = *i;
    }
    (a, b)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn fill_prefix_and_halves() {
        assert_eq!(fill::<4>(&[&[1, 2], &[3], &[4, 5]]), [1, 2, 3, 4]);
        assert_eq!(fill::<4>(&[&[1]]), [1, 0, 0, 0]);
        assert_eq!(prefix::<2>(&[1, 2, 3]), Some([1, 2]));
        assert_eq!(prefix::<4>(&[1, 2, 3]), None);
        let mut x = [0u8; 64];
        x[0] = 1;
        x[63] = 2;
        let (a, b) = halves(&x);
        assert_eq!((a[0], b[31]), (1, 2));
    }
}
