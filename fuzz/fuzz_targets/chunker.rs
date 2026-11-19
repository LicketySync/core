#![no_main]
//! The keyed chunker (`keys.md` 3.2) under the test vectors' folder (write
//! secret `10 11 .. 2f`), on a stream the input describes, fed in pieces the
//! input chooses.
//!
//! The input: three bytes, big-endian, give a length modulo
//! `2 * MAX_CHUNK_PLAINTEXT + MIN_CHUNK_LEN + 1`; the next byte's top three
//! bits `s` shift it right by `s` bits to give the stream's length, and
//! its low five bits choose the piece sizes; the rest is a pattern of `p`
//! bytes, and byte `i` of the stream is `pattern[i % p] ^ (i / p)` (all zeros
//! for an empty pattern), so that short inputs make long streams, runs of one
//! value and repeats among them. One input in eight has the full range, up to
//! 8.5 MiB; the rest are 2 to 128 times shorter, since a stream of
//! megabytes takes most of a second under the sanitizer; the scales from 0 to
//! 4 can still pass `MIN_CHUNK_LEN`, so they reach the cut path.
//!
//! What must hold: the chunks cover the stream in order; every chunk is 1 to
//! `MAX_CHUNK_PLAINTEXT` bytes and every chunk but the last at least
//! `MIN_CHUNK_LEN`; the pieces give the cuts that one whole piece gives;
//! `next_cut` never claims more than its piece, and `finish` leaves the
//! chunker at the start of a stream.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use licketysync_keys::chunk::{ChunkKeys, MAX_CHUNK_PLAINTEXT};
use licketysync_keys::chunker::{Chunker, MIN_CHUNK_LEN};
use licketysync_keys::{Suite, WriteKey, WriteSecret};

fn keys() -> &'static ChunkKeys {
    static KEYS: OnceLock<ChunkKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + i as u8);
        let w = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)).expect("suite 1");
        w.chunk_keys()
    })
}

/// The piece sizes, chosen by one byte: from single bytes to more than a
/// chunk, and sizes around the window and the batch.
const PIECES: [usize; 12] = [1, 2, 63, 64, 65, 127, 4096, 65_536, 1 << 20, MIN_CHUNK_LEN, MAX_CHUNK_PLAINTEXT, 3];

fn ends_in_pieces(chunker: &mut Chunker, stream: &[u8], choice: u8) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut at = 0;
    let mut start = 0;
    let mut turn = usize::from(choice);
    while at < stream.len() {
        let size = PIECES[turn % PIECES.len()];
        turn = turn.wrapping_mul(31).wrapping_add(7);
        let mut piece = &stream[at..(at + size).min(stream.len())];
        let base = at;
        at += piece.len();
        let mut offset = 0;
        while let Some(n) = chunker.next_cut(piece) {
            assert!(n >= 1 && n <= piece.len(), "a cut inside its piece");
            offset += n;
            start = base + offset;
            ends.push(start);
            piece = &piece[n..];
        }
    }
    match chunker.finish() {
        Some(last) => {
            assert_eq!(start + last, stream.len());
            ends.push(stream.len());
        }
        None => assert_eq!(start, stream.len()),
    }
    assert_eq!(chunker.finish(), None, "finish starts a new stream");
    ends
}

fuzz_target!(|data: &[u8]| {
    let Some((&[a, b, c, choice], pattern)) = data.split_first_chunk::<4>() else {
        return;
    };
    let len = ((usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c))
        % (2 * MAX_CHUNK_PLAINTEXT + MIN_CHUNK_LEN + 1))
        >> (choice >> 5);
    let stream: Vec<u8> = (0..len)
        .map(|i| match pattern.len() {
            0 => 0,
            p => pattern[i % p] ^ (i / p) as u8,
        })
        .collect();
    let mut chunker = keys().chunker();
    let whole: Vec<&[u8]> = chunker.chunks(&stream).collect();
    let mut s = 0;
    let mut ends = Vec::new();
    for (i, chunk) in whole.iter().enumerate() {
        assert!((1..=MAX_CHUNK_PLAINTEXT).contains(&chunk.len()));
        if i + 1 < whole.len() {
            assert!(chunk.len() >= MIN_CHUNK_LEN);
        }
        assert_eq!(*chunk, &stream[s..s + chunk.len()]);
        s += chunk.len();
        ends.push(s);
    }
    assert_eq!(s, stream.len(), "the chunks cover the stream");
    assert_eq!(ends_in_pieces(&mut chunker, &stream, choice & 0x1f), ends);
});
