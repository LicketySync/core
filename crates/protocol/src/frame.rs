// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Framing (`protocol.md` section 2): a `u32` big-endian length, a `u16`
//! big-endian type with the critical bit, and the body.
//!
//! ```text
//! +----------------+----------------+------------------------+
//! | length  u32 BE | type  u16 BE   | body (length - 2 bytes)|
//! +----------------+----------------+------------------------+
//! ```
//!
//! [`FrameDecoder`] receives in the spec's order: it reads exactly four bytes,
//! checks the length against the current limit, and only then starts the body,
//! which grows as its bytes arrive. Nothing is allocated for a frame over the
//! limit, by construction: the body buffer does not exist until the check has
//! passed (TM-2). The connection keeps the limit at `PRE_HELLO_LIMIT` until the
//! peer's `DeviceProof` has verified, then raises it to its own advertised
//! `max_message_size`.

use core::fmt;

use crate::limits::MAX_MESSAGE_SIZE;
use crate::messages::CloseReason;

/// The critical bit of a type number: a receiver that does not know a type
/// with it set must close; without it, it answers `Unsupported` and continues.
pub const CRITICAL_BIT: u16 = 0x8000;
/// Bytes of the length prefix.
pub const LENGTH_LEN: usize = 4;
/// Bytes of the type field, counted in the length.
pub const TYPE_LEN: usize = 2;

/// The message types of major 1 (`protocol.md` section 4.1). 0x8006 and
/// 0x800B carried the drafts' key records and are reserved, so they read as
/// unknown critical types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum MessageType {
    /// Identity, capabilities, limits; both sides, first.
    Hello = 0x8001,
    /// Reason for closing; both sides, last.
    Close = 0x8002,
    /// Signature over the transcript with the device key.
    DeviceProof = 0x8003,
    /// Sealed proof of holding a key to one folder.
    FolderProof = 0x8004,
    /// Answer to one `FolderProof`.
    ProofResult = 0x8005,
    /// "Send what I lack", by range and cursor.
    IndexRequest = 0x8007,
    /// Signed index records, paged or pushed.
    IndexRecords = 0x8008,
    /// One chunk by ciphertext hash.
    ChunkRequest = 0x8009,
    /// The chunk, or why not.
    ChunkReply = 0x800A,
    /// Progress per open folder; non-critical.
    Status = 0x0001,
    /// "I do not know that non-critical type"; non-critical.
    Unsupported = 0x0002,
}

impl MessageType {
    /// Every type of major 1.
    pub const ALL: [Self; 11] = [
        Self::Hello,
        Self::Close,
        Self::DeviceProof,
        Self::FolderProof,
        Self::ProofResult,
        Self::IndexRequest,
        Self::IndexRecords,
        Self::ChunkRequest,
        Self::ChunkReply,
        Self::Status,
        Self::Unsupported,
    ];

    /// The type for a wire number, or `None` for one this release does not know.
    #[must_use]
    pub const fn from_u16(n: u16) -> Option<Self> {
        Some(match n {
            0x8001 => Self::Hello,
            0x8002 => Self::Close,
            0x8003 => Self::DeviceProof,
            0x8004 => Self::FolderProof,
            0x8005 => Self::ProofResult,
            0x8007 => Self::IndexRequest,
            0x8008 => Self::IndexRecords,
            0x8009 => Self::ChunkRequest,
            0x800A => Self::ChunkReply,
            0x0001 => Self::Status,
            0x0002 => Self::Unsupported,
            _ => return None,
        })
    }

    /// The wire number, critical bit included.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Whether the critical bit is set.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        self.as_u16() & CRITICAL_BIT != 0
    }

    /// The spec's name, for logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::Close => "Close",
            Self::DeviceProof => "DeviceProof",
            Self::FolderProof => "FolderProof",
            Self::ProofResult => "ProofResult",
            Self::IndexRequest => "IndexRequest",
            Self::IndexRecords => "IndexRecords",
            Self::ChunkRequest => "ChunkRequest",
            Self::ChunkReply => "ChunkReply",
            Self::Status => "Status",
            Self::Unsupported => "Unsupported",
        }
    }
}

/// How a received type number dispatches (section 2, step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// A type of this major: decode the body with its schema.
    Known(MessageType),
    /// Unknown with the critical bit set: `Close(UNSUPPORTED_CRITICAL_TYPE)`.
    UnknownCritical(u16),
    /// Unknown with the critical bit clear: send `Unsupported` and continue.
    UnknownNonCritical(u16),
}

/// One frame: a type number and a body. Its length field is `2 + body.len()`,
/// which [`Frame::new`] keeps at most `MAX_MESSAGE_SIZE`.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    type_number: u16,
    body: Vec<u8>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Frame({:#06x}, {} bytes)",
            self.type_number,
            self.body.len()
        )
    }
}

/// Why bytes are not a frame, or a frame cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// The length field is below 2: there is no room for the type.
    TooShort {
        /// The length field.
        length: u32,
    },
    /// The length field is above the limit; nothing was allocated.
    TooLarge {
        /// The length field, or the length a frame would need.
        length: u64,
        /// The limit in force.
        limit: u32,
    },
    /// The bytes end inside a frame (only reported on a stream's end).
    Truncated {
        /// Bytes still needed to complete the frame.
        needed: usize,
    },
    /// The decoder refused earlier input and takes no more.
    Poisoned,
}

impl FrameError {
    /// The close reason for this error: `MESSAGE_TOO_LARGE` for a frame over
    /// the limit, `PROTOCOL_ERROR` for everything else.
    #[must_use]
    pub const fn close_reason(&self) -> CloseReason {
        match self {
            Self::TooLarge { .. } => CloseReason::MessageTooLarge,
            Self::TooShort { .. } | Self::Truncated { .. } | Self::Poisoned => {
                CloseReason::ProtocolError
            }
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { length } => write!(f, "frame length {length} is below 2"),
            Self::TooLarge { length, limit } => {
                write!(f, "frame length {length} is over the limit {limit}")
            }
            Self::Truncated { needed } => write!(f, "stream ended {needed} bytes inside a frame"),
            Self::Poisoned => f.write_str("decoder refused earlier input"),
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// A frame, refused when `2 + body.len()` would exceed `MAX_MESSAGE_SIZE`.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] with `limit = MAX_MESSAGE_SIZE`.
    pub fn new(type_number: u16, body: Vec<u8>) -> Result<Self, FrameError> {
        let length = u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .saturating_add(TYPE_LEN as u64);
        if length > u64::from(MAX_MESSAGE_SIZE) {
            return Err(FrameError::TooLarge {
                length,
                limit: MAX_MESSAGE_SIZE,
            });
        }
        Ok(Self { type_number, body })
    }

    /// The full 16-bit type, critical bit included.
    #[must_use]
    pub const fn type_number(&self) -> u16 {
        self.type_number
    }

    /// The Protocol Buffers body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The value of the length field: `2 + body.len()`.
    #[must_use]
    pub fn length(&self) -> u32 {
        u32::try_from(self.body.len() + TYPE_LEN).unwrap_or(u32::MAX)
    }

    /// The bytes the whole frame takes on the wire, length field included.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        LENGTH_LEN + TYPE_LEN + self.body.len()
    }

    /// Whether the frame fits a limit (an advertised `max_message_size`).
    #[must_use]
    pub fn fits(&self, limit: u32) -> bool {
        self.length() <= limit
    }

    /// Whether the critical bit is set.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.type_number & CRITICAL_BIT != 0
    }

    /// How the type dispatches.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        match MessageType::from_u16(self.type_number) {
            Some(t) => FrameKind::Known(t),
            None if self.is_critical() => FrameKind::UnknownCritical(self.type_number),
            None => FrameKind::UnknownNonCritical(self.type_number),
        }
    }

    /// `type || body`: what the transcript hashes for a Hello (3.3).
    #[must_use]
    pub fn type_and_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TYPE_LEN + self.body.len());
        out.extend_from_slice(&self.type_number.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// The whole frame: length, type and body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.length().to_be_bytes());
        out.extend_from_slice(&self.type_number.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// A streaming frame decoder over a byte stream with arbitrary chunk
/// boundaries (`protocol.md` 3.1). [`FrameDecoder::next_frame`] yields one frame
/// at a time, so that the caller dispatches each before the next is decoded
/// and stops at a close (section 2, step 4). The limit is checked when the
/// four length bytes are complete, before the body buffer exists (TM-2); the
/// body buffer then grows as bytes arrive, never past the checked length, so a
/// peer that announces a large frame and sends little costs little.
/// [`FrameDecoder::set_limit`] changes the limit for frames whose length has
/// not yet been read.
#[derive(Debug)]
pub struct FrameDecoder {
    limit: u32,
    header: [u8; LENGTH_LEN],
    header_len: usize,
    body: Option<PartialBody>,
    poisoned: bool,
}

#[derive(Debug)]
struct PartialBody {
    buf: Vec<u8>,
    want: usize,
}

impl PartialBody {
    /// Appends `chunk`, growing the buffer geometrically but never past `want`.
    fn extend(&mut self, chunk: &[u8]) {
        let needed = self.buf.len() + chunk.len();
        if needed > self.buf.capacity() {
            let target = needed
                .max(self.buf.capacity().saturating_mul(2))
                .min(self.want);
            self.buf.reserve_exact(target - self.buf.len());
        }
        self.buf.extend_from_slice(chunk);
    }
}

impl FrameDecoder {
    /// A decoder whose frames are bounded by `limit`.
    #[must_use]
    pub const fn new(limit: u32) -> Self {
        Self {
            limit,
            header: [0; LENGTH_LEN],
            header_len: 0,
            body: None,
            poisoned: false,
        }
    }

    /// The limit for frames whose length has not been read yet.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Sets the limit for frames whose length has not been read yet (a frame
    /// already being read keeps the limit it was checked against).
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = limit;
    }

    /// Whether no partial frame is buffered.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.header_len == 0 && self.body.is_none()
    }

    /// Bytes allocated for the body being read: 0 until a length has passed
    /// the limit check, then at most the bytes that have arrived (rounded up
    /// geometrically) and never more than the checked length.
    #[must_use]
    pub fn body_capacity(&self) -> usize {
        self.body.as_ref().map_or(0, |b| b.buf.capacity())
    }

    /// Drops any partial frame and refuses further input: for a connection
    /// that has closed (`protocol.md` 4.2: every per-connection table is freed).
    pub fn clear(&mut self) {
        self.header_len = 0;
        self.body = None;
        self.poisoned = true;
    }

    /// Reads from the front of `input` until one frame is complete, and
    /// returns it, leaving the rest of `input` unread; `Ok(None)` when `input`
    /// ran out first (its bytes are kept for the next call). After an error
    /// the decoder is poisoned: the connection must close, and further input
    /// is refused.
    ///
    /// # Errors
    /// [`FrameError::TooShort`] (length below 2), [`FrameError::TooLarge`]
    /// (over the limit; nothing allocated) or [`FrameError::Poisoned`].
    pub fn next_frame(&mut self, input: &mut &[u8]) -> Result<Option<Frame>, FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }
        while !input.is_empty() {
            if let Some(partial) = &mut self.body {
                let take = (partial.want - partial.buf.len()).min(input.len());
                let (chunk, rest) = input.split_at(take);
                partial.extend(chunk);
                *input = rest;
                if partial.buf.len() == partial.want {
                    let mut buf = core::mem::take(&mut partial.buf);
                    self.body = None;
                    let type_number = buf
                        .first_chunk::<TYPE_LEN>()
                        .map_or(0, |t| u16::from_be_bytes(*t));
                    // `check_length` made `want` at least TYPE_LEN.
                    buf.drain(..TYPE_LEN.min(buf.len()));
                    return Ok(Some(Frame {
                        type_number,
                        body: buf,
                    }));
                }
            } else {
                let take = (LENGTH_LEN - self.header_len).min(input.len());
                let (head, rest) = input.split_at(take);
                for (slot, byte) in self.header.iter_mut().skip(self.header_len).zip(head) {
                    *slot = *byte;
                }
                self.header_len += take;
                *input = rest;
                if self.header_len == LENGTH_LEN {
                    let length = u32::from_be_bytes(self.header);
                    if let Err(e) = self.check_length(length) {
                        self.poisoned = true;
                        return Err(e);
                    }
                    self.body = Some(PartialBody {
                        buf: Vec::new(),
                        want: length as usize,
                    });
                    self.header_len = 0;
                }
            }
        }
        Ok(None)
    }

    fn check_length(&self, length: u32) -> Result<(), FrameError> {
        if (length as usize) < TYPE_LEN {
            return Err(FrameError::TooShort { length });
        }
        if length > self.limit {
            return Err(FrameError::TooLarge {
                length: u64::from(length),
                limit: self.limit,
            });
        }
        Ok(())
    }

    /// Called when the stream ends: an error if it ended inside a frame.
    ///
    /// # Errors
    /// [`FrameError::Truncated`] with the bytes still needed.
    pub fn finish(&self) -> Result<(), FrameError> {
        if let Some(partial) = &self.body {
            return Err(FrameError::Truncated {
                needed: partial.want - partial.buf.len(),
            });
        }
        if self.header_len > 0 {
            return Err(FrameError::Truncated {
                needed: LENGTH_LEN - self.header_len,
            });
        }
        Ok(())
    }

    /// Decodes exactly one whole frame from `bytes` under `limit`: for
    /// fuzzing, test vectors and tools that hold a frame in one buffer.
    ///
    /// # Errors
    /// As [`Self::next_frame`], plus [`FrameError::Truncated`] when `bytes`
    /// end early (the bytes still needed) or carry more than one frame
    /// (`needed = 0`).
    pub fn decode_one(bytes: &[u8], limit: u32) -> Result<Frame, FrameError> {
        let mut d = Self::new(limit);
        let mut input = bytes;
        let frame = d.next_frame(&mut input)?;
        d.finish()?;
        match frame {
            Some(frame) if input.is_empty() => Ok(frame),
            Some(_) => Err(FrameError::Truncated { needed: 0 }),
            None => Err(FrameError::Truncated { needed: LENGTH_LEN }),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::limits::PRE_HELLO_LIMIT;

    fn frame(t: u16, body: &[u8]) -> Frame {
        Frame::new(t, body.to_vec()).unwrap()
    }

    /// Feeds `input` and returns every frame, or the first error.
    fn all(d: &mut FrameDecoder, mut input: &[u8]) -> Result<Vec<Frame>, FrameError> {
        let mut out = Vec::new();
        while let Some(f) = d.next_frame(&mut input)? {
            out.push(f);
        }
        assert!(input.is_empty(), "None only once the input is used up");
        Ok(out)
    }

    #[test]
    fn types_have_their_numbers_and_critical_bits() {
        assert_eq!(MessageType::Hello.as_u16(), 0x8001);
        assert_eq!(MessageType::ChunkReply.as_u16(), 0x800A);
        assert_eq!(MessageType::Status.as_u16(), 0x0001);
        assert_eq!(MessageType::Unsupported.as_u16(), 0x0002);
        for t in MessageType::ALL {
            assert_eq!(MessageType::from_u16(t.as_u16()), Some(t));
            assert_eq!(
                t.is_critical(),
                !matches!(t, MessageType::Status | MessageType::Unsupported)
            );
            assert_ne!(t.name(), "");
        }
        // 0x8006 and 0x800B carried the drafts' key records: reserved now.
        for n in [0x0000, 0x8000, 0x8006, 0x800B, 0x800C, 0x0003] {
            assert_eq!(MessageType::from_u16(n), None);
        }
        assert_eq!(
            frame(0x8006, b"").kind(),
            FrameKind::UnknownCritical(0x8006)
        );
        assert_eq!(
            frame(0x0003, b"").kind(),
            FrameKind::UnknownNonCritical(0x0003)
        );
        assert_eq!(
            frame(0x8002, b"").kind(),
            FrameKind::Known(MessageType::Close)
        );
        assert!(frame(0x8002, b"").is_critical());
        assert!(!frame(0x0002, b"").is_critical());
        assert_eq!(
            format!("{:?}", frame(0x8002, b"ab")),
            "Frame(0x8002, 2 bytes)"
        );
    }

    #[test]
    fn encode_lays_out_length_type_body() {
        let f = frame(0x8001, b"abc");
        assert_eq!(f.length(), 5);
        assert_eq!(f.wire_len(), 9);
        assert_eq!(f.encode(), vec![0, 0, 0, 5, 0x80, 0x01, b'a', b'b', b'c']);
        assert_eq!(f.type_and_body(), vec![0x80, 0x01, b'a', b'b', b'c']);
        assert!(f.fits(5));
        assert!(!f.fits(4));
        assert_eq!(FrameDecoder::decode_one(&f.encode(), 5).unwrap(), f);
        assert_eq!(
            FrameDecoder::decode_one(&f.encode(), 4),
            Err(FrameError::TooLarge {
                length: 5,
                limit: 4
            })
        );
        assert!(matches!(
            Frame::new(1, vec![0; MAX_MESSAGE_SIZE as usize - 1]),
            Err(FrameError::TooLarge { .. })
        ));
        assert_eq!(
            Frame::new(1, vec![0; MAX_MESSAGE_SIZE as usize - 2])
                .unwrap()
                .length(),
            MAX_MESSAGE_SIZE
        );
    }

    #[test]
    fn one_frame_at_a_time_across_arbitrary_splits() {
        let a = frame(0x8001, b"hello").encode();
        let b = frame(0x0001, b"").encode();
        let c = frame(0x800A, &[9; 100]).encode();
        let joined: Vec<u8> = [a, b, c].concat();
        for split in 0..=joined.len() {
            let mut d = FrameDecoder::new(1000);
            let mut out = all(&mut d, &joined[..split]).unwrap();
            out.extend(all(&mut d, &joined[split..]).unwrap());
            assert_eq!(out.len(), 3, "split at {split}");
            assert_eq!(out[0].body(), b"hello");
            assert_eq!(out[1].type_number(), 0x0001);
            assert_eq!(out[2].body().len(), 100);
            assert!(d.is_idle());
            d.finish().unwrap();
        }
        let mut d = FrameDecoder::new(1000);
        let mut input = &joined[..];
        let first = d.next_frame(&mut input).unwrap().unwrap();
        assert_eq!(first.type_number(), 0x8001);
        assert_eq!(
            input.len(),
            joined.len() - 11,
            "the rest is left for the caller to dispatch later"
        );
    }

    #[test]
    fn oversize_length_allocates_nothing() {
        let mut d = FrameDecoder::new(100);
        let header = 101u32.to_be_bytes();
        assert_eq!(all(&mut d, &header[..3]), Ok(vec![]));
        assert_eq!(d.body_capacity(), 0, "nothing before the length is whole");
        assert_eq!(
            all(&mut d, &header[3..]),
            Err(FrameError::TooLarge {
                length: 101,
                limit: 100
            })
        );
        assert_eq!(d.body_capacity(), 0, "nothing after the check failed");
        assert_eq!(all(&mut d, &[0]), Err(FrameError::Poisoned));
        let mut d = FrameDecoder::new(100);
        assert_eq!(all(&mut d, &[0, 0]), Ok(vec![]));
        assert_eq!(d.finish(), Err(FrameError::Truncated { needed: 2 }));
    }

    #[test]
    fn the_body_buffer_grows_with_the_bytes_that_arrive() {
        let mut d = FrameDecoder::new(1 << 24);
        assert_eq!(all(&mut d, &(1u32 << 24).to_be_bytes()), Ok(vec![]));
        assert_eq!(d.body_capacity(), 0, "a 16 MiB length alone costs nothing");
        assert_eq!(all(&mut d, &[7; 10]), Ok(vec![]));
        assert!(d.body_capacity() < 1024, "ten bytes cost about ten bytes");
        assert_eq!(
            d.finish(),
            Err(FrameError::Truncated {
                needed: (1 << 24) - 10
            })
        );
        let mut d = FrameDecoder::new(100);
        let f = frame(1, &[5; 98]).encode();
        for byte in &f[..f.len() - 1] {
            assert_eq!(all(&mut d, core::slice::from_ref(byte)), Ok(vec![]));
            assert!(d.body_capacity() <= 100, "never past the checked length");
        }
        assert_eq!(all(&mut d, &f[f.len() - 1..]).unwrap().len(), 1);
    }

    #[test]
    fn the_limit_applies_to_frames_not_yet_started() {
        let mut d = FrameDecoder::new(PRE_HELLO_LIMIT);
        assert_eq!(d.limit(), PRE_HELLO_LIMIT);
        assert!(matches!(
            all(&mut d, &(PRE_HELLO_LIMIT + 1).to_be_bytes()),
            Err(FrameError::TooLarge { .. })
        ));
        let mut d = FrameDecoder::new(PRE_HELLO_LIMIT);
        assert_eq!(all(&mut d, &frame(0x8001, b"x").encode()).unwrap().len(), 1);
        d.set_limit(MAX_MESSAGE_SIZE);
        assert_eq!(
            all(&mut d, &(PRE_HELLO_LIMIT + 1).to_be_bytes()),
            Ok(vec![]),
            "raised once the peer is proven"
        );
        d.clear();
        assert_eq!(d.body_capacity(), 0);
        assert!(d.is_idle());
        assert_eq!(all(&mut d, &[0]), Err(FrameError::Poisoned));
    }

    #[test]
    fn lengths_below_two_are_refused() {
        assert_eq!(
            all(&mut FrameDecoder::new(100), &0u32.to_be_bytes()),
            Err(FrameError::TooShort { length: 0 })
        );
        assert_eq!(
            all(&mut FrameDecoder::new(100), &1u32.to_be_bytes()),
            Err(FrameError::TooShort { length: 1 })
        );
        assert_eq!(
            all(&mut FrameDecoder::new(100), &[0, 0, 0, 2, 0x80, 0x01]),
            Ok(vec![frame(0x8001, b"")])
        );
    }

    /// A frame completed before an error in the same input is yielded, and the
    /// error comes on the next call, so the connection handles the frame
    /// before it closes (found by the old `frame_decode` fuzz target).
    #[test]
    fn frames_before_an_error_in_one_feed_are_kept() {
        let mut d = FrameDecoder::new(100);
        let mut input: &[u8] = &[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(d.next_frame(&mut input), Ok(Some(frame(0x0000, &[0]))));
        assert_eq!(
            d.next_frame(&mut input),
            Err(FrameError::TooShort { length: 0 })
        );
    }

    #[test]
    fn decode_one_refuses_short_long_and_doubled_input() {
        let f = frame(1, b"ab").encode();
        assert_eq!(
            FrameDecoder::decode_one(&f[..5], 100),
            Err(FrameError::Truncated { needed: 3 })
        );
        assert_eq!(
            FrameDecoder::decode_one(&[], 100),
            Err(FrameError::Truncated { needed: 4 })
        );
        assert_eq!(
            FrameDecoder::decode_one(&[f.clone(), f.clone()].concat(), 100),
            Err(FrameError::Truncated { needed: 0 })
        );
        assert_eq!(
            FrameDecoder::decode_one(&[f, vec![0]].concat(), 100),
            Err(FrameError::Truncated { needed: 0 })
        );
    }

    #[test]
    fn errors_map_to_close_reasons_and_display() {
        let large = FrameError::TooLarge {
            length: 9,
            limit: 8,
        };
        assert_eq!(large.close_reason(), CloseReason::MessageTooLarge);
        for e in [
            FrameError::TooShort { length: 1 },
            FrameError::Truncated { needed: 1 },
            FrameError::Poisoned,
        ] {
            assert_eq!(e.close_reason(), CloseReason::ProtocolError);
        }
        assert_eq!(
            FrameError::TooShort { length: 1 }.to_string(),
            "frame length 1 is below 2"
        );
        assert_eq!(large.to_string(), "frame length 9 is over the limit 8");
        assert_eq!(
            FrameError::Truncated { needed: 3 }.to_string(),
            "stream ended 3 bytes inside a frame"
        );
        assert_eq!(
            FrameError::Poisoned.to_string(),
            "decoder refused earlier input"
        );
        let e: &dyn std::error::Error = &FrameError::Poisoned;
        assert!(e.source().is_none());
    }

    proptest! {
        #[test]
        fn any_frame_within_the_limit_round_trips(t in any::<u16>(), body in proptest::collection::vec(any::<u8>(), 0..=300)) {
            let f = Frame::new(t, body).unwrap();
            prop_assert_eq!(FrameDecoder::decode_one(&f.encode(), 302).unwrap(), f);
        }

        #[test]
        fn every_length_over_the_limit_is_refused_before_allocation(limit in 2u32..5000, over in 1u32..5000, tail in proptest::collection::vec(any::<u8>(), 0..=8)) {
            let length = limit.saturating_add(over);
            let input = [length.to_be_bytes().to_vec(), tail].concat();
            let mut d = FrameDecoder::new(limit);
            prop_assert_eq!(all(&mut d, &input), Err(FrameError::TooLarge { length: u64::from(length), limit }));
            prop_assert_eq!(d.body_capacity(), 0);
        }

        #[test]
        fn arbitrary_streams_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=64), limit in 0u32..300) {
            let mut d = FrameDecoder::new(limit);
            let mut input = &bytes[..];
            while let Ok(Some(_)) = d.next_frame(&mut input) {}
            let _ = d.finish();
            let _ = FrameDecoder::decode_one(&bytes, limit);
        }
    }
}
