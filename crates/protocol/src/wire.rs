// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A bounded reader of the Protocol Buffers wire format.
//!
//! Every message body that arrives from a peer is read here, field by field,
//! and never through prost's own decoder: a length is compared with its limit
//! and with the bytes that remain before anything is sliced or pushed, a count
//! is checked as each element is read, a fixed-size field is checked for its
//! exact size, and a value outside its stated range is refused. The frame
//! limit already bounds what one body can make this reader hold; the per-field
//! bounds keep a hostile body from turning a few bytes into a large table
//! (TM-2, TM-22). Unknown fields are skipped, as proto3 requires, so a newer
//! peer may add fields. Every decoder must judge a signed body alike, so the
//! things decoders disagree on are refused outright (`protocol.md` section 2,
//! "Every decoder judges a body the same way"): a field number above 2^29 − 1,
//! a group wire type (3 or 4) whether the field is known or not, a singular
//! field that occurs twice, a `bool` other than 0 or 1 and a `uint32` of 2^32
//! or more. A repeated scalar is read packed, unpacked or partly each.

use core::fmt;

use licketysync_keys::records::Malformed;

use crate::limits::MAX_FIELD_NUMBER;

/// Why bytes did not parse as a message under its bounds. Every variant is
/// malformed input: the sender is to blame (`protocol.md` section 5).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// The bytes end before the field they announce.
    Truncated,
    /// A varint longer than ten bytes or wider than 64 bits.
    BadVarint,
    /// A known field arrived with the wrong wire type.
    WrongWireType {
        /// The field number.
        field: u32,
    },
    /// A wire type proto3 does not use (3 and 4 are groups, 6 and 7 do not exist).
    UnknownWireType(u8),
    /// A field number of 0 or above 2^29 − 1.
    FieldNumber(u64),
    /// A field that is not repeated occurred more than once (proto3 would
    /// keep the last, so two decoders could read different values).
    Repeated {
        /// The field number.
        field: u32,
    },
    /// A peer-supplied count or length exceeds the limit for `what`.
    LimitExceeded {
        /// Which field.
        what: &'static str,
        /// The limit.
        limit: usize,
        /// What the peer offered (the count or length that broke it).
        offered: u64,
    },
    /// A fixed-size field arrived absent or with another length.
    WrongLength {
        /// Which field.
        what: &'static str,
        /// The required length.
        expected: usize,
        /// What arrived.
        got: usize,
    },
    /// A value outside its stated range (a `uint32` that does not fit, a
    /// `bool` other than 0 or 1, a suite of 0, a `seq` above `MAX_SEQ`).
    OutOfRange {
        /// Which field.
        what: &'static str,
    },
    /// A `string` field that is not UTF-8.
    NotUtf8 {
        /// Which field.
        what: &'static str,
    },
    /// A field that parses but breaks a grammar or ordering rule the spec
    /// states for it (a feature name, a control character in a device name, an
    /// unsorted list, a writer outside a request's range).
    Grammar {
        /// Which field and rule.
        what: &'static str,
    },
    /// A `SignedRecord` envelope the keys crate's strict decoder refused
    /// (`keys.md` 5.1: its size, its shape, its signature's size, its record
    /// type).
    Record(Malformed),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("bytes end before the field they announce"),
            Self::BadVarint => f.write_str("varint too long"),
            Self::WrongWireType { field } => write!(f, "field {field}: wrong wire type"),
            Self::UnknownWireType(t) => write!(f, "wire type {t} is not proto3"),
            Self::FieldNumber(n) => write!(f, "field number {n} is out of range"),
            Self::Repeated { field } => write!(f, "field {field} occurs more than once"),
            Self::LimitExceeded {
                what,
                limit,
                offered,
            } => write!(f, "{what}: {offered} offered, limit {limit}"),
            Self::WrongLength {
                what,
                expected,
                got,
            } => write!(f, "{what}: {got} bytes, must be {expected}"),
            Self::OutOfRange { what } => write!(f, "{what}: value out of range"),
            Self::NotUtf8 { what } => write!(f, "{what}: not UTF-8"),
            Self::Grammar { what } => write!(f, "{what}: grammar violated"),
            Self::Record(m) => write!(f, "record: {m}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<Malformed> for WireError {
    fn from(m: Malformed) -> Self {
        Self::Record(m)
    }
}

/// The known singular fields of one message already read: a second
/// occurrence of one is malformed. Unknown fields are skipped as often as
/// they come, since this release cannot tell whether they repeat.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Seen(u64);

impl Seen {
    /// Records `field` if it is one of `once` (the message's singular known
    /// fields, all below 64).
    ///
    /// # Errors
    /// [`WireError::Repeated`] when it was already read.
    pub(crate) fn check(&mut self, field: u32, once: &[u32]) -> Result<(), WireError> {
        if field >= 64 || !once.contains(&field) {
            return Ok(());
        }
        let bit = 1u64 << field;
        if self.0 & bit != 0 {
            return Err(WireError::Repeated { field });
        }
        self.0 |= bit;
        Ok(())
    }
}

/// A proto3 wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireType {
    /// 0: `int32`, `int64`, `uint32`, `uint64`, `bool`, enums.
    Varint,
    /// 1: `fixed64`, `sfixed64`, `double` (unused here, skipped).
    Fixed64,
    /// 2: `string`, `bytes`, messages, packed repeated scalars.
    LengthDelimited,
    /// 5: `fixed32`, `sfixed32`, `float` (unused here, skipped).
    Fixed32,
}

/// Reads one body, field by field.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over the whole of `buf`.
    #[must_use]
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet read.
    #[must_use]
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or(WireError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    /// Reads one varint of at most ten bytes.
    ///
    /// # Errors
    /// [`WireError::Truncated`] or [`WireError::BadVarint`].
    pub(crate) fn varint(&mut self) -> Result<u64, WireError> {
        let mut value: u64 = 0;
        for i in 0..10u32 {
            let b = self.byte()?;
            let shift = i * 7;
            let payload = u64::from(b & 0x7f);
            if shift == 63 && payload > 1 {
                return Err(WireError::BadVarint);
            }
            value |= payload << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(WireError::BadVarint)
    }

    /// The next field's number and wire type, or `None` at the end of the body.
    ///
    /// # Errors
    /// A truncated or malformed tag, a field number of 0 or above 2^29 − 1, or
    /// a wire type proto3 does not use (groups included).
    pub(crate) fn next_tag(&mut self) -> Result<Option<(u32, WireType)>, WireError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let number = key >> 3;
        let field = u32::try_from(number)
            .ok()
            .filter(|f| (1..=MAX_FIELD_NUMBER).contains(f))
            .ok_or(WireError::FieldNumber(number))?;
        let wire_type = match key & 7 {
            0 => WireType::Varint,
            1 => WireType::Fixed64,
            2 => WireType::LengthDelimited,
            5 => WireType::Fixed32,
            other => {
                return Err(WireError::UnknownWireType(
                    u8::try_from(other).unwrap_or(u8::MAX),
                ))
            }
        };
        Ok(Some((field, wire_type)))
    }

    /// Skips one field of `wire_type` (an unknown field, kept in the sender's
    /// bytes and never re-encoded).
    ///
    /// # Errors
    /// [`WireError::Truncated`] when the field runs past the body.
    pub(crate) fn skip(&mut self, wire_type: WireType) -> Result<(), WireError> {
        match wire_type {
            WireType::Varint => self.varint().map(|_| ()),
            WireType::Fixed64 => self.advance(8),
            WireType::Fixed32 => self.advance(4),
            WireType::LengthDelimited => {
                let len = self.length_prefix(usize::MAX, "skipped field")?;
                self.advance(len)
            }
        }
    }

    fn advance(&mut self, n: usize) -> Result<(), WireError> {
        if n > self.remaining() {
            return Err(WireError::Truncated);
        }
        self.pos += n;
        Ok(())
    }

    /// Reads a length prefix and checks it against `limit` and against the
    /// bytes remaining, in that order, before anything is sliced.
    fn length_prefix(&mut self, limit: usize, what: &'static str) -> Result<usize, WireError> {
        let len = self.varint()?;
        let exceeded = WireError::LimitExceeded {
            what,
            limit,
            offered: len,
        };
        let len = usize::try_from(len).map_err(|_| exceeded.clone())?;
        if len > limit {
            return Err(exceeded);
        }
        if len > self.remaining() {
            return Err(WireError::Truncated);
        }
        Ok(len)
    }

    fn want_type(wire_type: WireType, want: WireType, field: u32) -> Result<(), WireError> {
        if wire_type == want {
            Ok(())
        } else {
            Err(WireError::WrongWireType { field })
        }
    }

    /// A `uint32` field.
    ///
    /// # Errors
    /// Wrong wire type, truncated, or a value of 2^32 or more.
    pub(crate) fn uint32(
        &mut self,
        wire_type: WireType,
        field: u32,
        what: &'static str,
    ) -> Result<u32, WireError> {
        Self::want_type(wire_type, WireType::Varint, field)?;
        let v = self.varint()?;
        u32::try_from(v).map_err(|_| WireError::OutOfRange { what })
    }

    /// A `uint64` field.
    ///
    /// # Errors
    /// Wrong wire type or truncated.
    pub(crate) fn uint64(&mut self, wire_type: WireType, field: u32) -> Result<u64, WireError> {
        Self::want_type(wire_type, WireType::Varint, field)?;
        self.varint()
    }

    /// An `int64` field (two's complement varint).
    ///
    /// # Errors
    /// Wrong wire type or truncated.
    pub(crate) fn int64(&mut self, wire_type: WireType, field: u32) -> Result<i64, WireError> {
        Self::want_type(wire_type, WireType::Varint, field)?;
        self.varint().map(|v| i64::from_ne_bytes(v.to_ne_bytes()))
    }

    /// A `bool` field: 0 or 1, nothing else.
    ///
    /// # Errors
    /// Wrong wire type, truncated, or a value other than 0 or 1.
    pub(crate) fn boolean(
        &mut self,
        wire_type: WireType,
        field: u32,
        what: &'static str,
    ) -> Result<bool, WireError> {
        Self::want_type(wire_type, WireType::Varint, field)?;
        match self.varint()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::OutOfRange { what }),
        }
    }

    /// A `bytes` field of at most `limit` bytes, as a slice of the body.
    ///
    /// # Errors
    /// Wrong wire type, a length over `limit` or past the body.
    pub(crate) fn bytes(
        &mut self,
        wire_type: WireType,
        field: u32,
        what: &'static str,
        limit: usize,
    ) -> Result<&'a [u8], WireError> {
        Self::want_type(wire_type, WireType::LengthDelimited, field)?;
        let len = self.length_prefix(limit, what)?;
        let start = self.pos;
        self.pos += len;
        self.buf.get(start..self.pos).ok_or(WireError::Truncated)
    }

    /// A `string` field of at most `limit` bytes, valid UTF-8.
    ///
    /// # Errors
    /// As [`Self::bytes`], plus [`WireError::NotUtf8`].
    pub(crate) fn string(
        &mut self,
        wire_type: WireType,
        field: u32,
        what: &'static str,
        limit: usize,
    ) -> Result<String, WireError> {
        let b = self.bytes(wire_type, field, what, limit)?;
        core::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| WireError::NotUtf8 { what })
    }

    /// One occurrence of a `repeated uint32` field, packed or not, appended
    /// to `into` with the count checked before each push.
    ///
    /// # Errors
    /// Wrong wire type, truncated, a value of 2^32 or more, or more than
    /// `limit` entries in all.
    pub(crate) fn repeated_uint32(
        &mut self,
        wire_type: WireType,
        field: u32,
        what: &'static str,
        limit: usize,
        into: &mut Vec<u32>,
    ) -> Result<(), WireError> {
        let wide = |_| WireError::OutOfRange { what };
        match wire_type {
            WireType::Varint => {
                let v = u32::try_from(self.varint()?).map_err(wide)?;
                push_bounded(into, v, limit, what)
            }
            WireType::LengthDelimited => {
                let packed = self.bytes(wire_type, field, what, usize::MAX)?;
                let mut inner = Reader::new(packed);
                while inner.remaining() > 0 {
                    let v = u32::try_from(inner.varint()?).map_err(wide)?;
                    push_bounded(into, v, limit, what)?;
                }
                Ok(())
            }
            WireType::Fixed64 | WireType::Fixed32 => Err(WireError::WrongWireType { field }),
        }
    }
}

/// Pushes `item` unless `into` already holds `limit` items.
///
/// # Errors
/// [`WireError::LimitExceeded`] with `offered = limit + 1`.
pub(crate) fn push_bounded<T>(
    into: &mut Vec<T>,
    item: T,
    limit: usize,
    what: &'static str,
) -> Result<(), WireError> {
    room(into, limit, what)?;
    into.push(item);
    Ok(())
}

/// Whether `list` has room for one more item under `limit`.
///
/// # Errors
/// [`WireError::LimitExceeded`] with `offered = limit + 1`.
pub(crate) fn room<T>(list: &[T], limit: usize, what: &'static str) -> Result<(), WireError> {
    if list.len() >= limit {
        return Err(WireError::LimitExceeded {
            what,
            limit,
            offered: u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1),
        });
    }
    Ok(())
}

/// A fixed-size field must be present at exactly `len` bytes.
///
/// # Errors
/// [`WireError::WrongLength`].
pub(crate) fn exact(field: &[u8], len: usize, what: &'static str) -> Result<(), WireError> {
    if field.len() == len {
        Ok(())
    } else {
        Err(WireError::WrongLength {
            what,
            expected: len,
            got: field.len(),
        })
    }
}

/// A field that may be empty, or else is exactly `len` bytes.
///
/// # Errors
/// [`WireError::WrongLength`].
pub(crate) fn empty_or_exact(
    field: &[u8],
    len: usize,
    what: &'static str,
) -> Result<(), WireError> {
    if field.is_empty() {
        Ok(())
    } else {
        exact(field, len, what)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn varints_decode_minimal_and_non_minimal_forms() {
        let b = [0x96, 0x01, 0x80, 0x00, 0x7f];
        let mut r = Reader::new(&b);
        assert_eq!(r.varint(), Ok(150));
        assert_eq!(
            r.varint(),
            Ok(0),
            "non-minimal zero is accepted, as prost does"
        );
        assert_eq!(r.varint(), Ok(127));
        assert_eq!(r.varint(), Err(WireError::Truncated));
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(Reader::new(&max).varint(), Ok(u64::MAX));
        let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(Reader::new(&over).varint(), Err(WireError::BadVarint));
        assert_eq!(Reader::new(&[0x80; 11]).varint(), Err(WireError::BadVarint));
        assert_eq!(
            Reader::new(&[0x80, 0x80]).varint(),
            Err(WireError::Truncated)
        );
    }

    #[test]
    fn tags_and_skipping() {
        // field 1 varint 5; field 2 fixed64; field 3 fixed32; field 4 bytes "ab".
        let b = [
            0x08, 5, 0x11, 1, 2, 3, 4, 5, 6, 7, 8, 0x1d, 1, 2, 3, 4, 0x22, 2, b'a', b'b',
        ];
        let mut r = Reader::new(&b);
        assert_eq!(r.next_tag(), Ok(Some((1, WireType::Varint))));
        r.skip(WireType::Varint).unwrap();
        assert_eq!(r.next_tag(), Ok(Some((2, WireType::Fixed64))));
        r.skip(WireType::Fixed64).unwrap();
        assert_eq!(r.next_tag(), Ok(Some((3, WireType::Fixed32))));
        r.skip(WireType::Fixed32).unwrap();
        assert_eq!(r.next_tag(), Ok(Some((4, WireType::LengthDelimited))));
        r.skip(WireType::LengthDelimited).unwrap();
        assert_eq!(r.next_tag(), Ok(None));
        assert_eq!(r.remaining(), 0);
        assert_eq!(
            Reader::new(&[0x0b]).next_tag(),
            Err(WireError::UnknownWireType(3))
        );
        assert_eq!(
            Reader::new(&[0x0c]).next_tag(),
            Err(WireError::UnknownWireType(4))
        );
        assert_eq!(
            Reader::new(&[0x0e]).next_tag(),
            Err(WireError::UnknownWireType(6))
        );
        assert_eq!(
            Reader::new(&[0x00]).next_tag(),
            Err(WireError::FieldNumber(0))
        );
        // Field number 2^29 - 1 is the last one allowed; 2^29 is malformed.
        assert_eq!(
            Reader::new(&[0xf8, 0xff, 0xff, 0xff, 0x0f]).next_tag(),
            Ok(Some((536_870_911, WireType::Varint)))
        );
        assert_eq!(
            Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x10]).next_tag(),
            Err(WireError::FieldNumber(1 << 29))
        );
        let mut r = Reader::new(&[0x11, 1, 2]);
        r.next_tag().unwrap();
        assert_eq!(r.skip(WireType::Fixed64), Err(WireError::Truncated));
        let mut r = Reader::new(&[0x15, 1]);
        r.next_tag().unwrap();
        assert_eq!(r.skip(WireType::Fixed32), Err(WireError::Truncated));
        let mut r = Reader::new(&[0x22, 9, 1]);
        r.next_tag().unwrap();
        assert_eq!(r.skip(WireType::LengthDelimited), Err(WireError::Truncated));
    }

    #[test]
    fn scalars_check_wire_type_and_range() {
        let b = [0x80, 0x80, 0x80, 0x80, 0x10, 2, 1];
        let mut r = Reader::new(&b);
        assert_eq!(
            r.uint32(WireType::Varint, 1, "x"),
            Err(WireError::OutOfRange { what: "x" }),
            "2^32 is malformed, not truncated"
        );
        assert_eq!(
            r.boolean(WireType::Varint, 2, "b"),
            Err(WireError::OutOfRange { what: "b" }),
            "a bool of 2 is malformed"
        );
        assert_eq!(r.boolean(WireType::Varint, 2, "b"), Ok(true));
        assert_eq!(
            r.uint32(WireType::LengthDelimited, 3, "x"),
            Err(WireError::WrongWireType { field: 3 })
        );
        assert_eq!(
            r.uint64(WireType::Fixed32, 4),
            Err(WireError::WrongWireType { field: 4 })
        );
        assert_eq!(
            r.int64(WireType::Fixed64, 5),
            Err(WireError::WrongWireType { field: 5 })
        );
        assert_eq!(
            r.boolean(WireType::Fixed64, 5, "b"),
            Err(WireError::WrongWireType { field: 5 })
        );
        let neg = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x07, 0x00,
        ];
        let mut r = Reader::new(&neg);
        assert_eq!(r.int64(WireType::Varint, 1), Ok(-1));
        assert_eq!(r.uint64(WireType::Varint, 1), Ok(7));
        assert_eq!(r.boolean(WireType::Varint, 1, "b"), Ok(false));
        assert_eq!(
            r.boolean(WireType::Varint, 1, "b"),
            Err(WireError::Truncated)
        );
    }

    #[test]
    fn length_delimited_fields_check_limit_then_remaining_before_slicing() {
        let b = [3, b'a', b'b', b'c'];
        assert_eq!(
            Reader::new(&b).bytes(WireType::LengthDelimited, 1, "f", 2),
            Err(WireError::LimitExceeded {
                what: "f",
                limit: 2,
                offered: 3
            })
        );
        assert_eq!(
            Reader::new(&b).bytes(WireType::LengthDelimited, 1, "f", 3),
            Ok(&b"abc"[..])
        );
        assert_eq!(
            Reader::new(&[4, b'a']).bytes(WireType::LengthDelimited, 1, "f", 10),
            Err(WireError::Truncated)
        );
        assert_eq!(
            Reader::new(&b).bytes(WireType::Varint, 1, "f", 10),
            Err(WireError::WrongWireType { field: 1 })
        );
        assert_eq!(
            exact(b"abc", 4, "f"),
            Err(WireError::WrongLength {
                what: "f",
                expected: 4,
                got: 3
            })
        );
        assert_eq!(exact(b"abcd", 4, "f"), Ok(()));
        assert_eq!(empty_or_exact(b"", 4, "f"), Ok(()));
        assert_eq!(empty_or_exact(b"abcd", 4, "f"), Ok(()));
        assert!(empty_or_exact(b"abc", 4, "f").is_err());
        // A length that does not fit usize on 32-bit targets is refused, too:
        // a ten-byte varint of u64::MAX is never sliced.
        let huge = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert!(matches!(
            Reader::new(&huge).bytes(WireType::LengthDelimited, 1, "f", usize::MAX),
            Err(WireError::Truncated | WireError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn strings_must_be_utf8() {
        let b = [2, 0xff, 0xfe, 2, b'o', b'k'];
        let mut r = Reader::new(&b);
        assert_eq!(
            r.string(WireType::LengthDelimited, 1, "s", 9),
            Err(WireError::NotUtf8 { what: "s" })
        );
        assert_eq!(
            r.string(WireType::LengthDelimited, 1, "s", 9),
            Ok("ok".to_string())
        );
    }

    #[test]
    fn repeated_uint32_packed_unpacked_and_mixed_with_bound() {
        let mut out = Vec::new();
        let mut r = Reader::new(&[3, 1, 2, 3]);
        r.repeated_uint32(WireType::LengthDelimited, 1, "s", 4, &mut out)
            .unwrap();
        let mut r = Reader::new(&[4]);
        r.repeated_uint32(WireType::Varint, 1, "s", 4, &mut out)
            .unwrap();
        assert_eq!(out, vec![1, 2, 3, 4], "partly packed, partly not, in order");
        let mut r = Reader::new(&[4]);
        assert_eq!(
            r.repeated_uint32(WireType::Varint, 1, "s", 4, &mut out),
            Err(WireError::LimitExceeded {
                what: "s",
                limit: 4,
                offered: 5
            })
        );
        let mut out = Vec::new();
        let mut r = Reader::new(&[3, 1, 2, 3]);
        assert_eq!(
            r.repeated_uint32(WireType::LengthDelimited, 1, "s", 2, &mut out),
            Err(WireError::LimitExceeded {
                what: "s",
                limit: 2,
                offered: 3
            }),
            "the third element is refused as it is read"
        );
        assert_eq!(out.len(), 2);
        assert_eq!(
            Reader::new(&[3, 1, 2, 3]).repeated_uint32(WireType::Fixed32, 1, "s", 9, &mut out),
            Err(WireError::WrongWireType { field: 1 })
        );
        assert_eq!(
            Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x10]).repeated_uint32(
                WireType::Varint,
                1,
                "s",
                9,
                &mut out
            ),
            Err(WireError::OutOfRange { what: "s" })
        );
        assert_eq!(
            Reader::new(&[5, 0x80, 0x80, 0x80, 0x80, 0x10]).repeated_uint32(
                WireType::LengthDelimited,
                1,
                "s",
                9,
                &mut out
            ),
            Err(WireError::OutOfRange { what: "s" })
        );
        assert_eq!(
            Reader::new(&[5, 1]).repeated_uint32(WireType::LengthDelimited, 1, "s", 9, &mut out),
            Err(WireError::Truncated)
        );
        assert_eq!(
            Reader::new(&[1, 0x80]).repeated_uint32(WireType::LengthDelimited, 1, "s", 9, &mut out),
            Err(WireError::Truncated),
            "a packed run that ends inside a varint"
        );
    }

    #[test]
    fn singular_fields_may_occur_once() {
        let mut seen = Seen::default();
        assert_eq!(seen.check(1, &[1, 2]), Ok(()));
        assert_eq!(
            seen.check(3, &[1, 2]),
            Ok(()),
            "a repeated or unknown field"
        );
        assert_eq!(seen.check(3, &[1, 2]), Ok(()));
        assert_eq!(seen.check(2, &[1, 2]), Ok(()));
        assert_eq!(
            seen.check(1, &[1, 2]),
            Err(WireError::Repeated { field: 1 })
        );
        assert_eq!(
            seen.check(100, &[100]),
            Ok(()),
            "no known field is that high"
        );
    }

    #[test]
    fn errors_display() {
        for (e, text) in [
            (
                WireError::Truncated,
                "bytes end before the field they announce",
            ),
            (WireError::BadVarint, "varint too long"),
            (
                WireError::WrongWireType { field: 3 },
                "field 3: wrong wire type",
            ),
            (WireError::UnknownWireType(6), "wire type 6 is not proto3"),
            (WireError::FieldNumber(9), "field number 9 is out of range"),
            (
                WireError::Repeated { field: 4 },
                "field 4 occurs more than once",
            ),
            (
                WireError::LimitExceeded {
                    what: "x",
                    limit: 1,
                    offered: 2,
                },
                "x: 2 offered, limit 1",
            ),
            (
                WireError::WrongLength {
                    what: "x",
                    expected: 32,
                    got: 3,
                },
                "x: 3 bytes, must be 32",
            ),
            (WireError::OutOfRange { what: "x" }, "x: value out of range"),
            (WireError::NotUtf8 { what: "x" }, "x: not UTF-8"),
            (WireError::Grammar { what: "x" }, "x: grammar violated"),
            (
                WireError::from(Malformed::SignatureSize(3)),
                "record: signature is 3 bytes, not 64",
            ),
        ] {
            assert_eq!(e.to_string(), text);
        }
        let as_std: &dyn std::error::Error = &WireError::Truncated;
        assert!(as_std.source().is_none());
    }
}
