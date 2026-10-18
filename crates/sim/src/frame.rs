// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A small length-prefixed framing for the simulator's own peers.
//!
//! The transport carries bytes, not messages, and hands them over in chunks
//! split anywhere (protocol spec, 3.1), so a peer that wants messages frames
//! them. The engine will use the protocol crate's frame decoder; the toy and
//! probing peers here, and the tests, use this one: a frame is a big-endian
//! `u32` payload length followed by the payload. [`Deframer`] reassembles
//! frames from chunks one stream at a time, and refuses a frame whose
//! announced length exceeds its limit before buffering any of it, as every
//! decoder of untrusted bytes must.

use core::fmt;

/// Bytes of the length header.
pub const HEADER: usize = 4;

/// `payload` as one frame, or `None` when it is too long for a `u32` length.
#[must_use]
pub fn frame(payload: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(payload.len()).ok()?;
    let mut out = Vec::with_capacity(HEADER.saturating_add(payload.len()));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// A frame announced a payload longer than the [`Deframer`]'s limit. The
/// stream is unusable from here on: the peer should hang up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameTooLarge {
    /// The announced payload length.
    pub announced: u64,
    /// The limit it exceeded.
    pub limit: usize,
}

impl fmt::Display for FrameTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a frame announced {} bytes, more than the limit of {}",
            self.announced, self.limit
        )
    }
}

impl std::error::Error for FrameTooLarge {}

/// Reassembles frames from one stream's chunks. It holds at most one partial
/// frame, and never more than `HEADER + limit` bytes of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deframer {
    limit: usize,
    header: Vec<u8>,
    /// The announced payload length, once the header is complete.
    want: Option<usize>,
    payload: Vec<u8>,
    broken: bool,
}

impl Deframer {
    /// A deframer that accepts payloads of at most `limit` bytes.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            header: Vec::new(),
            want: None,
            payload: Vec::new(),
            broken: false,
        }
    }

    /// Bytes of a partial frame held, header included.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.header.len().saturating_add(self.payload.len())
    }

    /// Feeds the next chunk of the stream and returns every frame it
    /// completes, in order.
    ///
    /// # Errors
    /// [`FrameTooLarge`] when a header announces more than the limit; it is
    /// returned again for every later chunk, since the stream cannot be
    /// resynchronised. Frames completed earlier in the same chunk are lost
    /// with it, as the stream is to be abandoned.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameTooLarge> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            if self.broken {
                return Err(self.too_large(u64::MAX));
            }
            let Some(want) = self.want else {
                let need = HEADER.saturating_sub(self.header.len());
                let (head, rest) = bytes.split_at(need.min(bytes.len()));
                self.header.extend_from_slice(head);
                bytes = rest;
                if let Ok(h) = <[u8; HEADER]>::try_from(self.header.as_slice()) {
                    let announced = u32::from_be_bytes(h);
                    let Some(len) = usize::try_from(announced).ok().filter(|n| *n <= self.limit)
                    else {
                        self.broken = true;
                        self.header.clear();
                        return Err(self.too_large(u64::from(announced)));
                    };
                    self.header.clear();
                    self.want = Some(len);
                    if len == 0 {
                        self.want = None;
                        frames.push(Vec::new());
                    }
                }
                continue;
            };
            let need = want.saturating_sub(self.payload.len());
            let (body, rest) = bytes.split_at(need.min(bytes.len()));
            self.payload.extend_from_slice(body);
            bytes = rest;
            if self.payload.len() == want {
                frames.push(core::mem::take(&mut self.payload));
                self.want = None;
            }
        }
        if self.broken {
            return Err(self.too_large(u64::MAX));
        }
        Ok(frames)
    }

    const fn too_large(&self, announced: u64) -> FrameTooLarge {
        FrameTooLarge {
            announced,
            limit: self.limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(d: &mut Deframer, chunks: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(c).unwrap_or_default());
        }
        out
    }

    #[test]
    fn frames_round_trip_whole_split_and_coalesced() {
        let hello = frame(b"hello").unwrap_or_default();
        let empty = frame(b"").unwrap_or_default();
        let long = frame(&[7; 300]).unwrap_or_default();
        assert_eq!(hello, b"\0\0\0\x05hello".to_vec());
        let mut stream = hello.clone();
        stream.extend_from_slice(&empty);
        stream.extend_from_slice(&long);
        let want = vec![b"hello".to_vec(), Vec::new(), vec![7; 300]];
        let mut whole = Deframer::new(1000);
        assert_eq!(all(&mut whole, &[&stream]), want, "coalesced in one chunk");
        for cut in 0..=stream.len() {
            let (x, y) = stream.split_at(cut);
            let mut d = Deframer::new(1000);
            assert_eq!(all(&mut d, &[x, y]), want, "split at {cut}");
            assert_eq!(d.pending(), 0);
        }
        let mut bytewise = Deframer::new(1000);
        let singles: Vec<&[u8]> = stream.chunks(1).collect();
        assert_eq!(all(&mut bytewise, &singles), want, "one byte at a time");
    }

    #[test]
    fn a_partial_frame_is_held_and_counted() {
        let mut d = Deframer::new(10);
        assert_eq!(d.push(b"\0\0"), Ok(vec![]));
        assert_eq!(d.pending(), 2);
        assert_eq!(d.push(b"\0\x03ab"), Ok(vec![]));
        assert_eq!(d.pending(), 2, "header consumed, two payload bytes held");
        assert_eq!(d.push(b"c\0"), Ok(vec![b"abc".to_vec()]));
        assert_eq!(d.pending(), 1);
    }

    #[test]
    fn an_oversized_frame_is_refused_before_it_is_buffered_and_the_stream_stays_broken() {
        let mut d = Deframer::new(4);
        assert_eq!(d.push(b"\0\0\0\x04abcd"), Ok(vec![b"abcd".to_vec()]));
        let err = d.push(b"\0\0\0\x05abcde");
        assert_eq!(
            err,
            Err(FrameTooLarge {
                announced: 5,
                limit: 4
            })
        );
        assert_eq!(d.pending(), 0, "nothing of the oversized payload was kept");
        assert!(
            d.push(b"\0\0\0\x01x").is_err(),
            "and the stream is abandoned"
        );
        assert!(d.push(b"").is_err());
        let huge = Deframer::new(usize::MAX).push(&[0xff; 4]);
        assert_eq!(huge.map(|v| v.len()), Ok(0), "u32::MAX fits a usize limit");
        assert_eq!(
            FrameTooLarge {
                announced: 5,
                limit: 4
            }
            .to_string(),
            "a frame announced 5 bytes, more than the limit of 4"
        );
    }

    #[test]
    fn an_empty_chunk_changes_nothing() {
        let mut d = Deframer::new(4);
        assert_eq!(d.push(b""), Ok(vec![]));
        assert_eq!(d.pending(), 0);
    }
}
