//! Bounds-checked wire-format reader and the recursive schemaless decoder.
//!
//! Every read is length-checked before it happens: a truncated or overlong
//! varint, or a length that exceeds the bytes remaining, yields an [`Error`],
//! never a panic or an out-of-bounds index. Recursion (submessages and groups)
//! is depth-capped so a hostile depth-bomb degrades gracefully instead of
//! overflowing the stack.

use crate::{Error, Field, FieldValue, LenInterp, LenValue, Limits, WireType};

/// The largest legal protobuf field number, `2^29 − 1`.
const MAX_FIELD_NUMBER: u64 = 536_870_911;

/// A bounds-checked forward cursor over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Remaining unread bytes.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Decode a base-128 varint (LSB-first, MSB is the continuation bit). A
    /// varint that runs off the end is [`Error::TruncatedVarint`]; one that
    /// exceeds ten bytes is [`Error::OverlongVarint`]; one whose tenth byte
    /// carries bits above bit 63 is [`Error::VarintOverflow`].
    fn read_varint(&mut self) -> Result<u64, Error> {
        let start = self.pos;
        let mut result: u64 = 0;
        let mut count: u32 = 0;
        loop {
            let byte = match self.buf.get(self.pos) {
                Some(b) => *b,
                None => return Err(Error::TruncatedVarint { offset: start }),
            };
            // The tenth byte (index 9) can only contribute bit 63; any higher
            // payload bit would not fit in a u64.
            if count == 9 && byte & 0x7f > 0x01 {
                return Err(Error::VarintOverflow { offset: start });
            }
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << (7 * count);
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            count += 1;
            if count == 10 {
                return Err(Error::OverlongVarint { offset: start });
            }
        }
    }

    /// Take exactly `n` bytes, advancing the cursor. Errors if fewer remain.
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof {
            what,
            offset: self.pos,
        })?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::UnexpectedEof {
            what,
            offset: self.pos,
        })?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u32_le(&mut self) -> Result<u32, Error> {
        let b = self.take(4, "fixed32")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, Error> {
        let b = self.take(8, "fixed64")?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a length-delimited payload: the length was already decoded; this
    /// caps it at the bytes remaining so a lying or oversized length errors
    /// with [`Error::LengthOutOfRange`] instead of over-allocating.
    fn take_len(&mut self, len: u64, offset: usize) -> Result<Vec<u8>, Error> {
        let available = self.remaining();
        // A length that does not fit in `usize` (only reachable on a 32-bit host)
        // is handled by the same out-of-range arm as an oversized length, so
        // there is no separate never-taken branch.
        match usize::try_from(len) {
            Ok(n) if n <= available => Ok(self.take(n, "length-delimited")?.to_vec()),
            _ => Err(Error::LengthOutOfRange {
                value: len,
                available,
                offset,
            }),
        }
    }
}

/// Decode a full message from `bytes`, consuming all of it.
pub(crate) fn decode_message(bytes: &[u8], limits: Limits) -> Result<Vec<Field>, Error> {
    let mut cur = Cursor::new(bytes);
    decode_fields(&mut cur, 0, limits, None)
}

/// Decode fields until the cursor is exhausted (`open == None`) or a matching
/// group-end tag is reached (`open == Some((field, offset))`).
fn decode_fields(
    cur: &mut Cursor<'_>,
    depth: usize,
    limits: Limits,
    open: Option<(u64, usize)>,
) -> Result<Vec<Field>, Error> {
    if depth > limits.max_depth {
        return Err(Error::DepthLimitExceeded {
            limit: limits.max_depth,
            offset: cur.pos(),
        });
    }
    let mut fields = Vec::new();
    loop {
        if cur.is_empty() {
            if let Some((field, offset)) = open {
                return Err(Error::UnterminatedGroup { field, offset });
            }
            return Ok(fields);
        }
        let tag_offset = cur.pos();
        let tag = cur.read_varint()?;
        let number = tag >> 3;
        let wire = WireType::from_u8((tag & 0x07) as u8, tag_offset)?;

        if wire == WireType::EndGroup {
            return match open {
                Some((field, _)) if field == number => Ok(fields),
                _ => Err(Error::UnexpectedEndGroup {
                    field: number,
                    offset: tag_offset,
                }),
            };
        }
        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(Error::InvalidFieldNumber {
                value: number,
                offset: tag_offset,
            });
        }

        let value = match wire {
            WireType::Varint => FieldValue::Varint(cur.read_varint()?),
            WireType::I64 => FieldValue::I64(cur.read_u64_le()?),
            WireType::I32 => FieldValue::I32(cur.read_u32_le()?),
            WireType::Len => {
                let len_offset = cur.pos();
                let len = cur.read_varint()?;
                let raw = cur.take_len(len, len_offset)?;
                let interp = resolve_len(&raw, depth, limits);
                FieldValue::Len(LenValue { raw, interp })
            }
            WireType::StartGroup => {
                let inner = decode_fields(cur, depth + 1, limits, Some((number, tag_offset)))?;
                FieldValue::Group(inner)
            }
            // cov:unreachable: EndGroup returns above; kept as a defensive,
            // non-panicking arm rather than `unreachable!()`.
            WireType::EndGroup => {
                return Err(Error::UnexpectedEndGroup {
                    field: number,
                    offset: tag_offset,
                })
            }
        };
        fields.push(Field {
            number,
            wire_type: wire,
            value,
        });
    }
}

/// Infer how to read a length-delimited payload: message-first (matching
/// `protoc --decode_raw`), then printable UTF-8 string, else opaque bytes.
fn resolve_len(raw: &[u8], depth: usize, limits: Limits) -> LenInterp {
    if raw.is_empty() {
        return LenInterp::Bytes;
    }
    // A clean submessage parse consumes exactly `raw` (decode_fields loops to
    // exhaustion) and yields ≥1 field for non-empty input, so success here is a
    // strong message signal. Depth-limit failures fall through to text/bytes.
    if let Ok(inner) = try_message(raw, depth + 1, limits) {
        return LenInterp::Message(inner);
    }
    if let Some(text) = printable_utf8(raw) {
        return LenInterp::Text(text);
    }
    LenInterp::Bytes
}

/// Attempt to decode `raw` as a self-contained message consuming all of it.
fn try_message(raw: &[u8], depth: usize, limits: Limits) -> Result<Vec<Field>, Error> {
    let mut cur = Cursor::new(raw);
    decode_fields(&mut cur, depth, limits, None)
}

/// `Some(string)` iff `raw` is valid UTF-8 with no control characters other than
/// tab / newline / carriage-return — the "printable-ish" test that keeps binary
/// blobs (which happen to be valid UTF-8) from being mislabelled as text.
fn printable_utf8(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?;
    if s.chars()
        .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
    {
        Some(s.to_string())
    } else {
        None
    }
}

/// Decode `raw` as a packed sequence of varints — `Some` iff it is a non-empty
/// whole number of varints consuming all bytes.
pub(crate) fn packed_varints(raw: &[u8]) -> Option<Vec<u64>> {
    if raw.is_empty() {
        return None;
    }
    let mut cur = Cursor::new(raw);
    let mut out = Vec::new();
    while !cur.is_empty() {
        out.push(cur.read_varint().ok()?);
    }
    Some(out)
}

/// Decode `raw` as packed fixed 4-byte little-endian values — `Some` iff the
/// length is a non-zero multiple of 4.
pub(crate) fn packed_i32(raw: &[u8]) -> Option<Vec<u32>> {
    if raw.is_empty() || raw.len() % 4 != 0 {
        return None;
    }
    Some(
        raw.chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    )
}

/// Decode `raw` as packed fixed 8-byte little-endian values — `Some` iff the
/// length is a non-zero multiple of 8.
pub(crate) fn packed_i64(raw: &[u8]) -> Option<Vec<u64>> {
    if raw.is_empty() || raw.len() % 8 != 0 {
        return None;
    }
    Some(
        raw.chunks_exact(8)
            .map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_overflow_on_big_tenth_byte() {
        // Ten bytes, all continuation set, tenth payload 0x7f > 1 → overflow.
        let mut cur = Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(
            cur.read_varint(),
            Err(Error::VarintOverflow { offset: 0 })
        ));
    }

    #[test]
    fn max_u64_varint_decodes() {
        // 0xffff_ffff_ffff_ffff = nine 0xff then 0x01.
        let mut cur = Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert_eq!(cur.read_varint().unwrap(), u64::MAX);
    }

    #[test]
    fn truncated_fixed32_errors() {
        let mut cur = Cursor::new(&[0x01, 0x02]);
        assert!(matches!(
            cur.read_u32_le(),
            Err(Error::UnexpectedEof {
                what: "fixed32",
                ..
            })
        ));
    }

    #[test]
    fn truncated_fixed64_errors() {
        let mut cur = Cursor::new(&[0x01, 0x02, 0x03]);
        assert!(matches!(
            cur.read_u64_le(),
            Err(Error::UnexpectedEof {
                what: "fixed64",
                ..
            })
        ));
    }

    #[test]
    fn take_len_rejects_oversized_length() {
        let mut cur = Cursor::new(&[0xaa, 0xbb]);
        assert!(matches!(
            cur.take_len(100, 0),
            Err(Error::LengthOutOfRange {
                value: 100,
                available: 2,
                offset: 0
            })
        ));
    }

    #[test]
    fn printable_utf8_rejects_embedded_nul() {
        assert!(printable_utf8(&[b'a', 0x00, b'b']).is_none());
        assert_eq!(printable_utf8(b"a\tb\n").as_deref(), Some("a\tb\n"));
    }

    #[test]
    fn packed_helpers_reject_ragged_lengths() {
        assert!(packed_i32(&[0x00, 0x00, 0x00]).is_none());
        assert!(packed_i64(&[0x00]).is_none());
        assert!(packed_varints(&[]).is_none());
        assert!(packed_i32(&[]).is_none());
        assert!(packed_i64(&[]).is_none());
        // A byte with the continuation bit set but no follower is not a clean
        // packed-varint sequence.
        assert!(packed_varints(&[0x80]).is_none());
    }
}
