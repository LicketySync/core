// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! How fast the keyed chunker (`keys.md` 3.2) cuts on this machine: a
//! measurement that states a speed and checks none. It cuts 64 MiB of
//! `SplitMix64` output (or the MiB the first argument names) in 1 MiB pieces,
//! under the test vectors' folder key, three times, and prints the best:
//!
//! ```text
//! cargo run --release -p licketysync-keys --example chunker_speed
//! ```
//!
//! and as a device without AES instructions runs it, on the AES crate's
//! constant-time bitsliced code:
//!
//! ```text
//! RUSTFLAGS='--cfg aes_backend="soft"' cargo run --release -p licketysync-keys --example chunker_speed
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    unused_crate_dependencies,
    reason = "the measurement prints what it measured; an example links every dev-dependency"
)]

use std::process::ExitCode;
use std::time::Instant;

use licketysync_keys::chunker::Chunker;
use licketysync_keys::{Suite, WriteKey, WriteSecret};

/// `SplitMix64` from `seed`, each word little-endian.
fn splitmix(seed: u64, len: usize) -> Vec<u8> {
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

/// Cuts `data` in pieces of `piece` bytes; returns the number of chunks.
fn cut(chunker: &mut Chunker, data: &[u8], piece: usize) -> usize {
    let mut chunks = 0;
    for mut rest in data.chunks(piece) {
        while let Some(n) = chunker.next_cut(rest) {
            chunks += 1;
            rest = rest.split_at(n).1;
        }
    }
    chunks + usize::from(chunker.finish().is_some())
}

fn main() -> ExitCode {
    // Semgrep's community rule flags every std::env::args(): argv[0] is not
    // trustworthy. Only argument 1, the MiB to cut, is read, and it decides
    // nothing about security.
    // nosemgrep: rust.lang.security.args.args
    let mib = match std::env::args().nth(1).map(|a| a.parse::<usize>()) {
        None => 64,
        Some(Ok(n)) if n > 0 => n,
        Some(_) => {
            eprintln!("usage: chunker_speed [MiB, at least 1]");
            return ExitCode::FAILURE;
        }
    };
    // The test vectors' write secret, `10 11 .. 2f`: a public test key.
    let ws: [u8; 32] = core::array::from_fn(|i| 0x10 + u8::try_from(i).unwrap_or(0));
    let Ok(key) = WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes(ws)) else {
        eprintln!("suite 1 is not implemented");
        return ExitCode::FAILURE;
    };
    let mut chunker = key.chunk_keys().chunker();
    let data = splitmix(1, mib << 20);
    let mut best = f64::INFINITY;
    let mut chunks = 0;
    for _ in 0..3 {
        let start = Instant::now();
        chunks = cut(&mut chunker, &data, 1 << 20);
        best = best.min(start.elapsed().as_secs_f64());
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "a byte count far below 2^52 is exact as an f64"
    )]
    let bytes = data.len() as f64;
    println!(
        "AES instructions: {}; {mib} MiB in {chunks} chunks (mean {:.2} MiB): {:.0} MB/s, best of 3",
        if aes::hardware_accelerated() {
            "yes"
        } else {
            "no (bitsliced)"
        },
        bytes / 1_048_576.0 / f64::from(u32::try_from(chunks).unwrap_or(u32::MAX).max(1)),
        bytes / best / 1e6,
    );
    ExitCode::SUCCESS
}
