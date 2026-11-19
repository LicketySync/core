// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The keyed chunker (`keys.md` section 3.2, `suites.md` section 2.7): where
//! a file's chunks end.
//!
//! Whether a chunk ends after a byte depends only on the 64 bytes that end at
//! it, the window `b_0 .. b_63` (oldest first). Two tabulated Toeplitz hashes
//! under the folder's two secret tables compress the window to 128 bits,
//! AES-128 under the folder's chunk cut key encrypts them, and the chunk ends
//! there when the first 20 bits of the ciphertext are zero:
//!
//! ```text
//! P      = x^64 + x^4 + x^3 + x + 1                     irreducible over GF(2)
//! e_i    = BLAKE3_keyed(ctk, u8(i))                     i = 0 ..= 255
//! T0[i]  = le64(e_i[0..8]);  T1[i] = le64(e_i[8..16])
//! d_t    = XOR over j of x^(63-j) * T_t[b_j] mod P      t = 0, 1
//! c      = AES-128(cck[0..16], le64(d_0) || le64(d_1))
//! cut    = be32(c[0..4]) < 2^12
//! ```
//!
//! This is the construction of Truong, Merz, Scarlata, Günther and Paterson
//! (CCS 2025, ePrint 2025/558, Theorem 4.5) with a universal hash of
//! collision probability exactly 2^-128 in place of their polynomial hash
//! (their section 4.3). A party that asks for the cuts of `q` windows of its
//! choice tells them from coins of bias 2^-20 with an advantage (its chance
//! of guessing which it is shown, less 1/2) of at most AES-128's and BLAKE3's
//! advantages as PRFs (the tables and the AES key are BLAKE3 outputs) plus
//! `q^2 * 2^-149`. By their Theorem 4.3, a stream's chunk lengths, all but
//! the last, are then indistinguishable from [`MIN_CHUNK_LEN`] plus a
//! geometric length, capped at the longest chunk, as long as no window
//! evaluated repeats: identical windows always decide alike (`keys.md`
//! section 3.2).
//!
//! A chunk that a cut ends is at least [`MIN_CHUNK_LEN`] bytes long; every
//! chunk is at most `MAX_CHUNK_PLAINTEXT`; a file's last chunk may be shorter
//! than [`MIN_CHUNK_LEN`]. Windows are evaluated only where a chunk may end,
//! so each lies inside its chunk, about two bytes in three of a large file.
//! The digests roll, `d' = d*x + x^64*T[b_out] + T[b_in]`, and the digests of
//! up to 64 positions go to AES in one call, so that the processor's AES
//! instructions pipeline them.
//!
//! [`Chunker`] is streaming: it takes a stream's bytes in pieces of any size,
//! never holds more than the last 64 of them, and allocates once, when it is
//! made. No branch and no memory access depends on the tables, the digests or
//! the AES key. The table loads are indexed by the stream's bytes, unlike
//! anything else between reading a file and encrypting its chunks (with
//! compression off, the default; the coders of `keys.md` section 3.2 are
//! table-driven too): entries
//! are 16 bytes, about four to a cache line, so a process that shares the
//! core's cache can learn by prime and probe about the top six bits of the
//! bytes evaluated (`threat-model.md` section 5; another user of the machine
//! is a section 3.7 adversary). Whether a chunk ends is the one branch on a
//! ciphertext, and where chunks end is what chunk lengths show anyway.

use core::fmt;

use aes::Aes128Enc;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bytes::first;
use crate::chunk::MAX_CHUNK_PLAINTEXT;
use crate::labels::keyed_hash_into;
use crate::secret::{ChunkCutKey, ChunkTableKey};

/// The shortest chunk that a cut ends: 512 KiB. Only a file's last chunk is
/// shorter, and only when the file has fewer bytes left.
pub const MIN_CHUNK_LEN: usize = 512 * 1024;

/// The window: whether a chunk ends after a byte depends on the 64 bytes
/// that end at it.
pub(crate) const WINDOW: usize = 64;

/// A chunk ends after a byte when this many leading bits of its ciphertext
/// are zero: with probability 2^-20.
pub(crate) const CUT_BITS: u32 = 20;

/// `x^4 + x^3 + x + 1`, the low terms of `P = x^64 + x^4 + x^3 + x + 1`,
/// which is what `x^64` is modulo `P`. Bit `k` of a `u64` is the coefficient
/// of `x^k`.
pub(crate) const P_LOW: u64 = 0x1b;

/// The number of positions whose digests one AES call encrypts.
const BATCH: usize = 64;

/// The entries of each table: one per byte value.
const ENTRIES: usize = 256;

/// `d * x mod P`, with no branch on `d`'s top bit: the digests depend on the
/// secret tables.
#[must_use]
pub(crate) const fn times_x(d: u64) -> u64 {
    (d << 1) ^ (P_LOW & 0u64.wrapping_sub(d >> 63))
}

/// The bounds of a chunker: the shortest chunk a cut ends, the longest
/// chunk, and the value below which the first four bytes of a ciphertext,
/// read big-endian, make a cut. Fixed by the spec; tests shrink them so that
/// cuts come often.
///
/// Every window lies inside its chunk, `WINDOW <= min <= max`, which
/// [`Chunker::next_cut`] relies on: the fields are private, so the only
/// bounds outside this module's tests are [`Bounds::SPEC`], checked when the
/// crate is built, and a test's come from `Bounds::new`, which checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    min: usize,
    max: usize,
    threshold: u32,
}

impl Bounds {
    /// `keys.md` 3.2's: [`MIN_CHUNK_LEN`], `MAX_CHUNK_PLAINTEXT`, and 2^12, so
    /// that a cut needs 20 leading zero bits.
    pub(crate) const SPEC: Bounds = Bounds {
        min: MIN_CHUNK_LEN,
        max: MAX_CHUNK_PLAINTEXT,
        threshold: 1 << (u32::BITS - CUT_BITS),
    };

    /// A test's bounds. Panics unless every window lies inside its chunk.
    #[cfg(test)]
    pub(crate) const fn new(min: usize, max: usize, threshold: u32) -> Bounds {
        assert!(WINDOW <= min && min <= max, "a window must fit in a chunk");
        Bounds {
            min,
            max,
            threshold,
        }
    }
}

const _: () = assert!(WINDOW <= Bounds::SPEC.min && Bounds::SPEC.min <= Bounds::SPEC.max);

/// The AES-128 cipher of a 16-byte key, encryption only: the cut key's first
/// 16 bytes.
fn cipher(key: &[u8; 16]) -> Aes128Enc {
    Aes128Enc::new(Array::cast_from_core(key))
}

/// Encrypts each 16-byte block in place, in one call so that the backend can
/// run several at once.
fn encrypt(aes: &Aes128Enc, blocks: &mut [[u8; 16]]) {
    aes.encrypt_blocks(Array::cast_slice_from_core_mut(blocks));
}

/// What a chunker holds: the folder's tables and cipher, and the state of the
/// stream it is cutting. Wiped on drop (the cipher wipes its own round keys).
#[derive(Zeroize, ZeroizeOnDrop)]
struct Inner {
    /// `[T0[v], T1[v]]` for each byte value `v`: what a byte entering the
    /// window adds.
    tin: [[u64; 2]; ENTRIES],
    /// `[x^64 * T0[v] mod P, x^64 * T1[v] mod P]`: what a byte leaving the
    /// window takes out.
    tout: [[u64; 2]; ENTRIES],
    #[zeroize(skip)]
    aes: Aes128Enc,
    #[zeroize(skip)]
    bounds: Bounds,
    /// The bytes of the current chunk taken so far, below `bounds.max`.
    len: usize,
    /// `[d_0, d_1]` of the bytes of the current window taken so far: 0
    /// until the chunk's first window starts.
    d: [u64; 2],
    /// The bytes of the current window, each at its position in the chunk
    /// modulo 64, so that the byte 64 positions back is the one overwritten.
    ring: [u8; WINDOW],
    /// The blocks of a batch: digests, then their ciphertexts.
    batch: [[u8; 16]; BATCH],
}

/// What [`Chunker`]'s `ZeroizeOnDrop` stands on (TM-6): the boxed state wipes
/// its tables and the stream's bytes on drop, and the cipher it skips wipes
/// its own round keys. Building fails if either stops.
const _: () = {
    const fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    zeroize_on_drop::<Inner>();
    zeroize_on_drop::<Aes128Enc>();
};

impl Inner {
    /// Starts a chunk: no byte taken, and the digests of an empty window.
    fn restart(&mut self) {
        self.len = 0;
        self.d = [0; 2];
    }

    /// Takes byte `b` at position `self.len` of the chunk into the window,
    /// for a window that holds fewer than 64 bytes: `d = d*x + T[b]`.
    #[allow(
        clippy::indexing_slicing,
        reason = "a u8 indexes the 256 entries, and a position modulo 64 the 64-byte ring"
    )]
    fn absorb(&mut self, b: u8) {
        let t = self.tin[usize::from(b)];
        self.d = [times_x(self.d[0]) ^ t[0], times_x(self.d[1]) ^ t[1]];
        self.ring[self.len % WINDOW] = b;
        self.len += 1;
    }

    /// Takes `bytes`, at most a batch, at positions where a chunk may end,
    /// encrypts the digest of the window that ends at each, and returns the
    /// index of the first that cuts. `self.len` counts them all.
    #[allow(
        clippy::indexing_slicing,
        reason = "a u8 indexes the 256 entries, and a position modulo 64 the 64-byte ring"
    )]
    fn evaluate(&mut self, bytes: &[u8]) -> Option<usize> {
        let Inner {
            tin,
            tout,
            aes,
            bounds,
            len,
            d,
            ring,
            batch,
        } = self;
        let (blocks, _) = batch.split_at_mut(bytes.len().min(BATCH));
        let mut pairs = blocks.iter_mut().zip(bytes);
        // Position `min - 1` completes the chunk's first window, from which
        // no byte leaves yet.
        if *len < bounds.min
            && let Some((block, &b)) = pairs.next()
        {
            let t = tin[usize::from(b)];
            *d = [times_x(d[0]) ^ t[0], times_x(d[1]) ^ t[1]];
            ring[*len % WINDOW] = b;
            *len += 1;
            put(block, *d);
        }
        let (mut dd, mut at) = (*d, *len);
        for (block, &b) in pairs {
            let slot = at % WINDOW;
            let o = tout[usize::from(ring[slot])];
            let t = tin[usize::from(b)];
            dd = [
                times_x(dd[0]) ^ (o[0] ^ t[0]),
                times_x(dd[1]) ^ (o[1] ^ t[1]),
            ];
            ring[slot] = b;
            put(block, dd);
            at += 1;
        }
        (*d, *len) = (dd, at);
        encrypt(aes, blocks);
        let threshold = bounds.threshold;
        blocks
            .iter()
            .position(|c| u32::from_be_bytes(first(c)) < threshold)
    }
}

/// Writes `le64(d_0) || le64(d_1)`, the block that AES encrypts.
fn put(block: &mut [u8; 16], d: [u64; 2]) {
    let (d0, d1) = block.split_at_mut(8);
    d0.copy_from_slice(&d[0].to_le_bytes());
    d1.copy_from_slice(&d[1].to_le_bytes());
}

/// The folder's keyed chunker (`keys.md` section 3.2), from
/// [`crate::chunk::ChunkKeys::chunker`]: the same at every key holder of the
/// folder, so that identical files cut into identical chunks and deduplicate,
/// and unpredictable to anyone without the data key.
///
/// It cuts one stream at a time. Pass the stream's bytes in order, in pieces
/// of any size, to [`Chunker::next_cut`]; at the end, [`Chunker::finish`] gives
/// the last chunk and readies the chunker for the next stream.
/// [`Chunker::chunks`] cuts a whole stream held in memory. Pieces of at least
/// a few kilobytes keep AES's batches full.
pub struct Chunker {
    inner: Box<Inner>,
}

/// The boxed state wipes itself when the box drops it.
impl ZeroizeOnDrop for Chunker {}

impl fmt::Debug for Chunker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Chunker([redacted])")
    }
}

impl Chunker {
    /// A chunker under the table key and the cut key, with `bounds`: builds
    /// the tables (256 keyed hashes) and the cipher, wiping each hash and the
    /// AES key as soon as they are taken.
    pub(crate) fn new(ctk: &ChunkTableKey, cck: &ChunkCutKey, bounds: Bounds) -> Chunker {
        let key = Zeroizing::new(first::<32, 16>(cck.expose()));
        let mut inner = Box::new(Inner {
            tin: [[0; 2]; ENTRIES],
            tout: [[0; 2]; ENTRIES],
            aes: cipher(&key),
            bounds,
            len: 0,
            d: [0; 2],
            ring: [0; WINDOW],
            batch: [[0; 16]; BATCH],
        });
        let mut e = Zeroizing::new([0u8; 32]);
        let mut both = Zeroizing::new(0u128);
        let s = &mut *inner;
        for (i, (tin, tout)) in (0..=u8::MAX).zip(s.tin.iter_mut().zip(&mut s.tout)) {
            keyed_hash_into(ctk.expose(), &[&[i]], &mut e);
            *both = u128::from_le_bytes(first(&e));
            #[allow(
                clippy::cast_possible_truncation,
                reason = "T0 is the low half of the 16 bytes and T1 the high half, each truncated by definition"
            )]
            {
                *tin = [*both as u64, (*both >> 64) as u64];
            }
            *tout = *tin;
            for _ in 0..u64::BITS {
                *tout = [times_x(tout[0]), times_x(tout[1])];
            }
        }
        Chunker { inner }
    }

    /// Takes the stream's next bytes, up to the end of the current chunk.
    /// Returns `Some(n)` when that chunk ends after `data[..n]` (`n` is at
    /// least 1, and the next chunk starts at `data[n]`, which the caller
    /// passes next); `None` when it does not end in `data`, all of which it
    /// took.
    #[must_use]
    pub fn next_cut(&mut self, data: &[u8]) -> Option<usize> {
        let s = &mut *self.inner;
        let Bounds { min, max, .. } = s.bounds;
        // The first byte that any window of the chunk reads.
        let reads = min - WINDOW;
        let mut rest = data;
        loop {
            let skip = reads.saturating_sub(s.len).min(rest.len());
            s.len += skip;
            rest = rest.split_at(skip).1;
            if s.len < reads {
                return None;
            }
            while s.len < min - 1 {
                let (&b, after) = rest.split_first()?;
                s.absorb(b);
                rest = after;
            }
            // `s.len` is below `max`, so a batch never passes the longest chunk.
            let room = BATCH.min(max.saturating_sub(s.len)).min(rest.len());
            let (now, after) = rest.split_at(room);
            if now.is_empty() {
                return None;
            }
            let taken = data.len() - rest.len();
            rest = after;
            if let Some(j) = s.evaluate(now) {
                s.restart();
                return Some(taken + j + 1);
            }
            if s.len == max {
                s.restart();
                return Some(taken + now.len());
            }
        }
    }

    /// Ends the stream: the length of its last chunk, the bytes taken since
    /// the last cut, or `None` when there are none (an empty stream, or one
    /// whose last byte ended a chunk). The chunker is then at the start of a
    /// new stream.
    #[must_use]
    pub fn finish(&mut self) -> Option<usize> {
        let len = self.inner.len;
        self.inner.restart();
        (len > 0).then_some(len)
    }

    /// The chunks of a whole stream held in memory, in order. The chunker
    /// starts a new stream first, dropping what an unfinished one had taken,
    /// and is at the start of a new stream again once the last is returned.
    #[must_use]
    pub fn chunks<'c, 'd>(&'c mut self, data: &'d [u8]) -> Chunks<'c, 'd> {
        let _ = self.finish();
        Chunks {
            chunker: self,
            rest: data,
        }
    }
}

/// The chunks of a stream held in memory: [`Chunker::chunks`].
pub struct Chunks<'c, 'd> {
    chunker: &'c mut Chunker,
    rest: &'d [u8],
}

impl fmt::Debug for Chunks<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chunks({} bytes left)", self.rest.len())
    }
}

impl<'d> Iterator for Chunks<'_, 'd> {
    type Item = &'d [u8];

    fn next(&mut self) -> Option<&'d [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        let n = self.chunker.next_cut(self.rest).unwrap_or_else(|| {
            let _ = self.chunker.finish();
            self.rest.len()
        });
        let (chunk, rest) = self.rest.split_at(n);
        self.rest = rest;
        Some(chunk)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code"
)]
pub(crate) mod tests {
    use self::reference::{Reference, clmul, reduce, splitmix};
    use super::*;
    use crate::chunk::ChunkKeys;
    use crate::folder::tests::write_key;
    use proptest::prelude::*;

    /// An independent, straightforward reading of `keys.md` 3.2 for the tests:
    /// the keys derived from the data key by their label strings, the tables
    /// from BLAKE3 directly, each window's digests as the sum of its 64 terms,
    /// each product by carry-less multiplication and long division, and AES one
    /// block at a time. Nothing of the chunker above is used.
    pub(crate) mod reference {
        use aes::Aes128;
        use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

        /// `P`'s 65 bits.
        pub(crate) const P: u128 = (1 << 64) | 0b1_1011;

        /// The carry-less product of two polynomials of degree below 64.
        pub(crate) fn clmul(a: u64, b: u64) -> u128 {
            (0..64)
                .filter(|i| (b >> i) & 1 == 1)
                .fold(0, |acc, i| acc ^ (u128::from(a) << i))
        }

        /// The remainder of a polynomial of degree below 128, by long division
        /// by `P`.
        pub(crate) fn reduce(mut r: u128) -> u64 {
            for i in (64..128).rev() {
                if (r >> i) & 1 == 1 {
                    r ^= P << (i - 64);
                }
            }
            u64::try_from(r).unwrap()
        }

        /// One folder's keys and the products of every position and byte value.
        pub(crate) struct Reference {
            /// `terms[t][j][v] = x^(63-j) * T_t[v] mod P`.
            terms: Vec<Vec<[u64; 256]>>,
            tables: [[u64; 256]; 2],
            aes: Aes128,
        }

        impl Reference {
            /// From the folder's data key.
            pub(crate) fn new(dk: &[u8; 32]) -> Reference {
                let ctk = blake3::derive_key("licketysync/v1/data/chunk-table-key", dk);
                let cck = blake3::derive_key("licketysync/v1/data/chunk-cut-key", dk);
                let e: Vec<[u8; 32]> = (0..=u8::MAX)
                    .map(|i| *blake3::keyed_hash(&ctk, &[i]).as_bytes())
                    .collect();
                let tables: [[u64; 256]; 2] = core::array::from_fn(|t| {
                    core::array::from_fn(|i| {
                        u64::from_le_bytes(e[i][8 * t..8 * t + 8].try_into().unwrap())
                    })
                });
                let terms = tables
                    .iter()
                    .map(|t| {
                        (0..64)
                            .map(|j| core::array::from_fn(|v| reduce(clmul(1 << (63 - j), t[v]))))
                            .collect()
                    })
                    .collect();
                let key: [u8; 16] = cck[..16].try_into().unwrap();
                Reference {
                    terms,
                    tables,
                    aes: Aes128::new(&Array::from(key)),
                }
            }

            /// `T_t[v]`.
            pub(crate) fn table(&self, t: usize, v: u8) -> u64 {
                self.tables[t][usize::from(v)]
            }

            /// `[d_0, d_1]` of a window.
            pub(crate) fn digests(&self, w: &[u8]) -> [u64; 2] {
                assert_eq!(w.len(), 64);
                core::array::from_fn(|t| {
                    w.iter()
                        .enumerate()
                        .fold(0, |d, (j, &b)| d ^ self.terms[t][j][usize::from(b)])
                })
            }

            /// `le64(d_0) || le64(d_1)` of a window: what AES encrypts.
            pub(crate) fn block(&self, w: &[u8]) -> [u8; 16] {
                let [d0, d1] = self.digests(w);
                let mut block = [0u8; 16];
                block[..8].copy_from_slice(&d0.to_le_bytes());
                block[8..].copy_from_slice(&d1.to_le_bytes());
                block
            }

            /// `c` of a window.
            pub(crate) fn cipher(&self, w: &[u8]) -> [u8; 16] {
                let mut block = Array::from(self.block(w));
                self.aes.encrypt_block(&mut block);
                block.into()
            }

            /// Whether the first `bits` bits of `c` are zero.
            pub(crate) fn decides(&self, w: &[u8], bits: u32) -> bool {
                let c = self.cipher(w);
                u32::from_be_bytes(c[..4].try_into().unwrap()) >> (32 - bits) == 0
            }

            /// The end offsets of the chunks of `data` by the rule, with the
            /// window decision `cut` (called with the window's last position).
            pub(crate) fn cuts_by(
                n: usize,
                min: usize,
                max: usize,
                mut cut: impl FnMut(usize) -> bool,
            ) -> Vec<usize> {
                let mut ends = Vec::new();
                let mut s = 0;
                while s < n {
                    let end = (s + min - 1..(s + max).min(n))
                        .find(|&k| cut(k))
                        .map_or((s + max).min(n), |k| k + 1);
                    ends.push(end);
                    s = end;
                }
                ends
            }

            /// The end offsets of the chunks of `data`.
            pub(crate) fn cuts(
                &self,
                data: &[u8],
                min: usize,
                max: usize,
                bits: u32,
            ) -> Vec<usize> {
                Self::cuts_by(data.len(), min, max, |k| {
                    self.decides(&data[k + 1 - 64..=k], bits)
                })
            }
        }

        /// `SplitMix64` from `seed`, each word little-endian: the vectors' input.
        pub(crate) fn splitmix(seed: u64, len: usize) -> Vec<u8> {
            let mut state = seed;
            let mut out = Vec::with_capacity(len + 8);
            while out.len() < len {
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
            }
            out.truncate(len);
            out
        }
    }

    fn hex16(s: &str) -> [u8; 16] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// FIPS 197 Appendix C.1 and SP 800-38A F.1.1 (`suites.md` 4.4): AES-128
    /// as the chunker calls it, one block and a batch, and a batch longer
    /// than the chunker's.
    #[test]
    fn vector_aes128_fips197_and_sp800_38a() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/aes128.json")).unwrap();
        let c1 = &v["fips197_c1"];
        let mut block = [hex16(c1["plaintext"].as_str().unwrap())];
        encrypt(&cipher(&hex16(c1["key"].as_str().unwrap())), &mut block);
        assert_eq!(block[0], hex16(c1["ciphertext"].as_str().unwrap()));
        let f11 = &v["sp800_38a_f11"];
        let aes = cipher(&hex16(f11["key"].as_str().unwrap()));
        let all = |name: &str| -> Vec<[u8; 16]> {
            f11[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| hex16(b.as_str().unwrap()))
                .collect()
        };
        let (pt, ct) = (all("plaintext"), all("ciphertext"));
        assert_eq!(pt.len(), 4);
        let mut blocks = pt.clone();
        encrypt(&aes, &mut blocks);
        assert_eq!(blocks, ct);
        // One at a time and in a batch past the chunker's agree.
        let mut long: Vec<[u8; 16]> = pt.iter().cycle().take(BATCH + 3).copied().collect();
        encrypt(&aes, &mut long);
        for (i, c) in long.iter().enumerate() {
            let mut one = [pt[i % 4]];
            encrypt(&aes, &mut one);
            assert_eq!((one[0], *c), (ct[i % 4], ct[i % 4]), "block {i}");
        }
    }

    /// `P` is irreducible (Rabin's test for degree 64 = 2^6:
    /// `x^(2^64) = x mod P`, and `gcd(x^(2^32) - x, P) = 1`), so every
    /// nonzero coefficient of a window's difference is invertible and two
    /// different windows collide with probability 2^-64 per table. And
    /// [`times_x`] is multiplication by `x` modulo `P`.
    #[test]
    fn p_is_irreducible_and_times_x_multiplies_by_x() {
        let square = |a: u64| reduce(clmul(a, a));
        let mut a = 2u64; // x
        for _ in 0..32 {
            a = square(a);
        }
        let x_2_32 = a;
        for _ in 0..32 {
            a = square(a);
        }
        assert_eq!(a, 2, "x^(2^64) = x");
        // gcd over GF(2)[x] of P and x^(2^32) + x, by Euclid.
        let degree = |v: u128| v.ilog2();
        let (mut u, mut v) = (reference::P, u128::from(x_2_32 ^ 2));
        while v != 0 {
            while u != 0 && degree(u) >= degree(v) {
                u ^= v << (degree(u) - degree(v));
            }
            core::mem::swap(&mut u, &mut v);
        }
        assert_eq!(u, 1, "gcd(x^(2^32) - x, P) = 1");
        for d in [
            0u64,
            1,
            0x1b,
            1 << 63,
            (1 << 63) | 1,
            u64::MAX,
            0x0123_4567_89ab_cdef,
        ] {
            assert_eq!(times_x(d), reduce(clmul(d, 2)), "{d:#x}");
        }
        assert_eq!(Bounds::SPEC.threshold, 4096);
        assert_eq!(Bounds::SPEC.min, 524_288);
        assert_eq!(Bounds::SPEC.max, 4_194_304);
    }

    fn keys(n: u8) -> ChunkKeys {
        write_key(n).chunk_keys()
    }

    fn reference(n: u8) -> Reference {
        Reference::new(write_key(n).data_key().expose())
    }

    fn small(n: u8, min: usize, max: usize, bits: u32) -> Chunker {
        keys(n).chunker_with(Bounds::new(min, max, 1 << (32 - bits)))
    }

    /// Feeds `data` in pieces of the lengths `pieces` gives in turn (an
    /// empty piece included), and returns the chunk end offsets.
    fn cut_in_pieces(chunker: &mut Chunker, data: &[u8], pieces: &[usize]) -> Vec<usize> {
        let mut ends = Vec::new();
        let mut at = 0;
        let mut start = 0; // where the current chunk began
        for &p in pieces.iter().cycle() {
            if at >= data.len() {
                break;
            }
            // An empty piece takes nothing; the stream then moves on by one.
            let p = if p == 0 {
                assert_eq!(chunker.next_cut(&[]), None);
                1
            } else {
                p
            };
            let mut piece = &data[at..(at + p).min(data.len())];
            at += piece.len();
            let base = at - piece.len();
            let mut offset = 0;
            while let Some(n) = chunker.next_cut(piece) {
                assert!(n >= 1 && n <= piece.len());
                offset += n;
                ends.push(base + offset);
                start = base + offset;
                piece = &piece[n..];
            }
        }
        if let Some(last) = chunker.finish() {
            assert_eq!(start + last, data.len(), "the last chunk is what was left");
            ends.push(data.len());
        } else {
            assert_eq!(start, data.len());
        }
        ends
    }

    /// The lengths of the chunks [`Chunker::chunks`] gives for `data`,
    /// each checked as it comes against the chunker's bounds (1 to `max`
    /// bytes, and at least `min` unless it is the last), so that a broken
    /// chunker fails at its first wrong chunk rather than running on.
    pub(crate) fn lens(chunker: &mut Chunker, data: &[u8]) -> Vec<usize> {
        let Bounds { min, max, .. } = chunker.inner.bounds;
        let mut lens = Vec::new();
        let mut taken = 0;
        for chunk in chunker.chunks(data) {
            taken += chunk.len();
            assert!(
                (1..=max).contains(&chunk.len()) && (chunk.len() >= min || taken == data.len()),
                "chunk {} of {} bytes",
                lens.len(),
                chunk.len()
            );
            lens.push(chunk.len());
        }
        lens
    }

    /// The end offsets of those chunks.
    pub(crate) fn ends(chunker: &mut Chunker, data: &[u8]) -> Vec<usize> {
        lens(chunker, data)
            .iter()
            .scan(0, |s, l| {
                *s += l;
                Some(*s)
            })
            .collect()
    }

    /// Checks the chunk bounds of a list of end offsets of `n` bytes.
    fn assert_bounds(ends: &[usize], n: usize, min: usize, max: usize) {
        let mut s = 0;
        for (i, &e) in ends.iter().enumerate() {
            let len = e - s;
            assert!((1..=max).contains(&len), "chunk {i} of {len} bytes");
            if i + 1 < ends.len() {
                assert!(len >= min, "chunk {i} of {len} bytes is short and not last");
            }
            s = e;
        }
        assert_eq!(s, n, "the chunks cover the input");
    }

    proptest! {
        #![proptest_config(crate::proptest_config(64))]

        /// With bounds small enough for many cuts: the chunker cuts where
        /// the rule says (each window's digests and AES as the reference
        /// computes them), whatever pieces the stream comes in, and its
        /// chunks are within the bounds and cover the stream.
        #[test]
        fn cuts_follow_the_rule_in_any_pieces(
            data in proptest::collection::vec(any::<u8>(), 0..6000),
            min in 64usize..400,
            extra in 0usize..1500,
            bits in 2u32..7,
            pieces in proptest::collection::vec(0usize..700, 1..8),
        ) {
            let max = min + extra;
            let want = reference(3).cuts(&data, min, max, bits);
            let mut chunker = small(3, min, max, bits);
            let got = cut_in_pieces(&mut chunker, &data, &pieces);
            prop_assert_eq!(&got, &want);
            assert_bounds(&got, data.len(), min, max);
            // Once more on the same chunker, in one piece and through chunks.
            prop_assert_eq!(&ends(&mut chunker, &data), &want);
            prop_assert_eq!(chunker.finish(), None);
        }

        /// Shift resistance: bytes inserted at `at` leave every cut before
        /// it as it was, and once the two streams cut at the same byte of
        /// the content after the insertion, they cut alike from there on.
        #[test]
        fn an_insertion_changes_only_the_cuts_near_it(
            seed in any::<u64>(),
            len in 2000usize..8000,
            at in 0usize..8000,
            inserted in proptest::collection::vec(any::<u8>(), 1..100),
        ) {
            let (min, max, bits) = (100, 1200, 5);
            let data = splitmix(seed, len);
            let at = at % len;
            let mut edited = data[..at].to_vec();
            edited.extend_from_slice(&inserted);
            edited.extend_from_slice(&data[at..]);
            let mut chunker = small(4, min, max, bits);
            let before = cut_in_pieces(&mut chunker, &data, &[len]);
            let after = cut_in_pieces(&mut chunker, &edited, &[edited.len()]);
            let k = inserted.len();
            // Every cut before the insertion is kept.
            let kept = |ends: &[usize]| -> Vec<usize> { ends.iter().copied().filter(|&e| e <= at).collect() };
            prop_assert_eq!(kept(&before), kept(&after));
            // From the first common end past the insertion, all agree.
            let shifted: Vec<usize> = after.iter().filter(|&&e| e >= at + k).map(|&e| e - k).collect();
            if let Some(common) = before.iter().find(|e| **e > at && shifted.contains(e)) {
                let tail = |ends: &[usize]| -> Vec<usize> { ends.iter().copied().filter(|e| e >= common).collect() };
                prop_assert_eq!(tail(&before), tail(&shifted));
            }
        }

        /// Rolling a window through a stream gives, at every position, the
        /// digests the reference computes from that position's window alone.
        #[test]
        fn rolling_digests_equal_direct_ones(data in proptest::collection::vec(any::<u8>(), 64..400)) {
            let r = reference(5);
            let mut chunker = small(5, 64, 1 << 20, 32);
            let s = &mut *chunker.inner;
            for (k, &b) in data.iter().enumerate() {
                if k < 63 {
                    s.absorb(b);
                    continue;
                }
                prop_assert_eq!(s.evaluate(&[b]), None);
                prop_assert_eq!(s.d, r.digests(&data[k - 63..=k]), "at {}", k);
            }
        }
    }

    /// Byte by byte across every boundary, and pieces that end exactly at
    /// one: the same cuts.
    #[test]
    fn one_byte_at_a_time() {
        let data = splitmix(9, 5000);
        let (min, max, bits) = (64, 300, 3);
        let want = reference(6).cuts(&data, min, max, bits);
        assert!(want.len() > 10);
        let mut chunker = small(6, min, max, bits);
        assert_eq!(cut_in_pieces(&mut chunker, &data, &[1]), want);
        assert_eq!(cut_in_pieces(&mut chunker, &data, &[63, 1, 64, 0, 2]), want);
        assert_eq!(chunker.next_cut(&[]), None);
        assert_eq!(chunker.finish(), None);
    }

    /// The tables and the cipher come from the folder's keys alone: the
    /// write and read keys' chunkers cut alike, and another folder's
    /// elsewhere. The production bounds on 8 MiB.
    #[test]
    fn every_key_holder_cuts_alike_and_another_folder_does_not() {
        let data = splitmix(0, 8 << 20);
        let w = write_key(7);
        let cut = |c: &mut Chunker| ends(c, &data);
        let ours = cut(&mut w.chunk_keys().chunker());
        assert!(ours.len() >= 3, "{ours:?}");
        assert_bounds(&ours, data.len(), MIN_CHUNK_LEN, MAX_CHUNK_PLAINTEXT);
        assert_eq!(cut(&mut w.read_key().chunk_keys().chunker()), ours);
        let theirs = cut(&mut write_key(8).chunk_keys().chunker());
        assert_bounds(&theirs, data.len(), MIN_CHUNK_LEN, MAX_CHUNK_PLAINTEXT);
        assert!(
            ours[..ours.len() - 1].iter().all(|e| !theirs.contains(e)),
            "{ours:?} {theirs:?}"
        );
        let mut chunker = w.chunk_keys().chunker();
        assert_eq!(format!("{chunker:?}"), "Chunker([redacted])");
        assert_eq!(
            format!("{:?}", chunker.chunks(b"abc")),
            "Chunks(3 bytes left)"
        );
    }

    /// An insertion with the spec's bounds: one byte in the middle of a chunk
    /// of 8 MiB that a cut ended (not the first, and not the last) changes
    /// that chunk only; every other chunk is the same bytes.
    #[test]
    fn an_insertion_changes_only_its_chunk() {
        let data = splitmix(0, 8 << 20);
        let mut chunker = keys(7).chunker();
        let before = lens(&mut chunker, &data);
        let i = (1..before.len() - 1)
            .find(|&i| before[i] < MAX_CHUNK_PLAINTEXT)
            .unwrap();
        let at = before[..i].iter().sum::<usize>() + before[i] / 2;
        let mut edited = data.clone();
        edited.insert(at, 0x5a);
        let after = lens(&mut chunker, &edited);
        assert_eq!(after.len(), before.len());
        assert_eq!(after[..i], before[..i]);
        assert_eq!(after[i], before[i] + 1);
        assert_eq!(after[i + 1..], before[i + 1..]);
    }

    /// The batch path's edges: a stream whose windows all cut ends a chunk
    /// at every `min`, and one none of whose windows cut ends one at every
    /// `max`, whether the batch reaches `max` or the data runs out first.
    #[test]
    fn every_window_cuts_or_none_does() {
        let data = splitmix(1, 10_000);
        let all = |c: &mut Chunker| lens(c, &data);
        // Every ciphertext but one in 2^32 is below u32::MAX; none below 0.
        let mut always = keys(2).chunker_with(Bounds::new(70, 500, u32::MAX));
        let lens = all(&mut always);
        assert_eq!(lens, [vec![70; 142], vec![60]].concat());
        let mut never = keys(2).chunker_with(Bounds::new(70, 500, 0));
        let lens = all(&mut never);
        assert_eq!(lens, [vec![500; 20]].concat());
        let lens = cut_in_pieces(&mut never, &data, &[499, 1, 7]);
        assert_eq!(lens, (1..=20).map(|i| i * 500).collect::<Vec<_>>());
        let mut odd = keys(2).chunker_with(Bounds::new(70, 135, 0));
        assert!(odd.chunks(&data[..1000]).take(7).all(|c| c.len() == 135));
    }

    /// A ciphertext whose first four bytes equal the threshold does not cut;
    /// one below it does.
    #[test]
    fn only_a_ciphertext_below_the_threshold_cuts() {
        let data = splitmix(11, 200);
        let c = reference(2).cipher(&data[..64]);
        let t = u32::from_be_bytes(c[..4].try_into().unwrap());
        let with = |threshold| keys(2).chunker_with(Bounds::new(64, 1000, threshold));
        assert_eq!(with(t).next_cut(&data[..64]), None);
        assert_eq!(
            with(t.checked_add(1).unwrap()).next_cut(&data[..64]),
            Some(64)
        );
    }

    /// Bounds whose shortest chunk could not hold a window are refused.
    #[test]
    #[should_panic(expected = "a window must fit in a chunk")]
    fn bounds_shorter_than_a_window_are_refused() {
        let _ = Bounds::new(WINDOW - 1, 1000, 1);
    }

    /// The reference's own rule on a stream where the decision is given:
    /// the last chunk short, MAX enforced, an empty stream with no chunk.
    #[test]
    fn the_rule_on_given_decisions() {
        assert_eq!(Reference::cuts_by(0, 4, 10, |_| true), Vec::<usize>::new());
        assert_eq!(Reference::cuts_by(3, 4, 10, |_| true), vec![3]);
        assert_eq!(Reference::cuts_by(9, 4, 10, |_| true), vec![4, 8, 9]);
        assert_eq!(Reference::cuts_by(25, 4, 10, |_| false), vec![10, 20, 25]);
        assert_eq!(Reference::cuts_by(10, 4, 10, |k| k == 9), vec![10]);
    }
}
