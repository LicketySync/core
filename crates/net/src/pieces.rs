// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reading a stream the way the engine's runtime contract hands bytes over
//! (`protocol.md` 3.1, "Transport contract"; the engine's `runtime` module):
//! the bytes in order, never more than [`MAX_PIECE`] at a time, split
//! anywhere, and then the end, reported once and for good.
//!
//! A stream's bytes come from another machine and are untrusted (TM-2): this
//! reader allocates one buffer of [`MAX_PIECE`] bytes and never sizes
//! anything to what the peer sends. Frames are the protocol crate's to
//! assemble.

use futures::{AsyncRead, AsyncReadExt as _};

/// The most bytes one piece holds: the engine runtime's `MAX_CHUNK`
/// (imported, not defined here), 64 KiB.
pub const MAX_PIECE: usize = licketysync_engine::runtime::MAX_CHUNK;

/// How a stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The stream reached its end without an error: the peer closed its
    /// side, or the connection under it closed in order. Like `Failed`, it
    /// promises nothing about bytes the peer had not yet sent: loss shows only
    /// as the end (`protocol.md` 3.1), and only the protocol's own `Close`
    /// says a conversation is complete.
    Closed,
    /// The stream or its connection failed.
    Failed(std::io::ErrorKind),
}

/// The next thing a stream hands over.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery<'a> {
    /// The next bytes, between 1 and [`MAX_PIECE`] of them.
    Bytes(&'a [u8]),
    /// The stream is over; every later call says so again.
    Ended(End),
}

/// A stream read in pieces.
pub struct Pieces<S> {
    stream: S,
    buf: Box<[u8]>,
    ended: Option<End>,
}

impl<S> core::fmt::Debug for Pieces<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pieces")
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + Unpin> Pieces<S> {
    /// Reads `stream` in pieces.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: vec![0; MAX_PIECE].into_boxed_slice(),
            ended: None,
        }
    }

    /// The next piece, or the end.
    pub async fn next(&mut self) -> Delivery<'_> {
        if let Some(end) = self.ended {
            return Delivery::Ended(end);
        }
        loop {
            match self.stream.read(&mut self.buf).await {
                Ok(0) => return self.end(End::Closed),
                Ok(n) => {
                    // `read` returns at most the buffer's length.
                    let piece = self.buf.get(..n).unwrap_or(&[]);
                    return Delivery::Bytes(piece);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return self.end(End::Failed(e.kind())),
            }
        }
    }

    fn end(&mut self, end: End) -> Delivery<'_> {
        self.ended = Some(end);
        Delivery::Ended(end)
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, reason = "test code: a byte pattern")]
mod tests {
    use super::*;

    #[test]
    fn piece_is_the_runtime_chunk() {
        assert_eq!(MAX_PIECE, 65_536);
    }

    #[test]
    fn hands_over_in_pieces_then_the_end_for_good() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut pieces = Pieces::new(futures::io::Cursor::new(data.clone()));
        let mut got = Vec::new();
        futures::executor::block_on(async {
            loop {
                match pieces.next().await {
                    Delivery::Bytes(b) => {
                        assert!(!b.is_empty() && b.len() <= MAX_PIECE);
                        got.extend_from_slice(b);
                    }
                    Delivery::Ended(end) => {
                        assert_eq!(end, End::Closed);
                        break;
                    }
                }
            }
            assert_eq!(pieces.next().await, Delivery::Ended(End::Closed));
        });
        assert_eq!(got, data);
    }
}
