// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fixed-size joins and truncations without indexing, so that no slice
//! operation in this crate can panic (TM-23). Every length is a const generic
//! and is checked when the crate is built: a call whose parts do not add up to
//! its output, or that takes more bytes than its input holds, does not compile
//! (an inline `const` assertion, evaluated for each instantiation).

/// Writes `a || b` into `out`.
pub(crate) fn join_into<const A: usize, const B: usize, const N: usize>(
    out: &mut [u8; N],
    a: &[u8; A],
    b: &[u8; B],
) {
    const { assert!(A + B == N, "the parts must fill the output exactly") };
    for (o, i) in out.iter_mut().zip(a.iter().chain(b)) {
        *o = *i;
    }
}

/// `a || b`.
pub(crate) fn join<const A: usize, const B: usize, const N: usize>(
    a: &[u8; A],
    b: &[u8; B],
) -> [u8; N] {
    let mut out = [0u8; N];
    join_into(&mut out, a, b);
    out
}

/// `a || b || c`.
pub(crate) fn join3<const A: usize, const B: usize, const C: usize, const N: usize>(
    a: &[u8; A],
    b: &[u8; B],
    c: &[u8; C],
) -> [u8; N] {
    const { assert!(A + B + C == N, "the parts must fill the output exactly") };
    let mut out = [0u8; N];
    for (o, i) in out.iter_mut().zip(a.iter().chain(b).chain(c)) {
        *o = *i;
    }
    out
}

/// Writes the first `N` bytes of `a` into `out`.
pub(crate) fn first_into<const M: usize, const N: usize>(out: &mut [u8; N], a: &[u8; M]) {
    const { assert!(N <= M, "cannot take more bytes than the input holds") };
    for (o, i) in out.iter_mut().zip(a) {
        *o = *i;
    }
}

/// The first `N` bytes of `a`.
pub(crate) fn first<const M: usize, const N: usize>(a: &[u8; M]) -> [u8; N] {
    let mut out = [0u8; N];
    first_into(&mut out, a);
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn joins_and_truncations() {
        assert_eq!(join::<2, 2, 4>(&[1, 2], &[3, 4]), [1, 2, 3, 4]);
        assert_eq!(join::<0, 3, 3>(&[], &[5, 6, 7]), [5, 6, 7]);
        assert_eq!(join3::<1, 2, 1, 4>(&[1], &[2, 3], &[4]), [1, 2, 3, 4]);
        let mut out = [9u8; 3];
        join_into(&mut out, &[1u8], &[2u8, 3]);
        assert_eq!(out, [1, 2, 3]);
        assert_eq!(first::<4, 2>(&[1, 2, 3, 4]), [1, 2]);
        assert_eq!(first::<2, 2>(&[1, 2]), [1, 2]);
        let mut out = [9u8; 1];
        first_into(&mut out, &[7u8, 8]);
        assert_eq!(out, [7]);
        let wide: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        assert_eq!(first::<64, 32>(&wide)[31], 31);
    }
}
