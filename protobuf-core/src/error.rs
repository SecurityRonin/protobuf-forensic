//! Error type for the schemaless protobuf wire decoder.
//!
//! Every variant carries the offending value and its byte offset so an
//! "unknown / invalid X" is never a dead end — the raw datum and its location
//! travel with the error (fail-loud, show-the-value discipline). Decoding is
//! panic-free: every malformed input becomes one of these rather than a panic,
//! an out-of-bounds index, or an over-allocation.

use std::fmt;

/// Errors returned while decoding protobuf wire-format bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A varint ran off the end of the buffer before its final byte (the
    /// continuation bit was set on the last byte available).
    TruncatedVarint {
        /// Byte offset where the varint began.
        offset: usize,
    },
    /// A varint used more than the 10 bytes a 64-bit value can occupy — the
    /// continuation bit was still set after ten bytes.
    OverlongVarint {
        /// Byte offset where the varint began.
        offset: usize,
    },
    /// A varint's tenth byte carried payload bits above bit 63, so the value
    /// does not fit in a `u64`.
    VarintOverflow {
        /// Byte offset where the varint began.
        offset: usize,
    },
    /// Ran off the end of the buffer while reading a fixed-width field.
    UnexpectedEof {
        /// What was being read (e.g. `"fixed32"`).
        what: &'static str,
        /// Byte offset where the read began.
        offset: usize,
    },
    /// A length-delimited field's length exceeds the bytes remaining in the
    /// buffer — a lying or oversized length that would over-read/allocate.
    LengthOutOfRange {
        /// The offending length value.
        value: u64,
        /// The bytes actually available.
        available: usize,
        /// Byte offset where the length prefix was read.
        offset: usize,
    },
    /// A tag's wire type was 6 or 7, which the wire format does not define.
    InvalidWireType {
        /// The offending 3-bit wire-type value (6 or 7).
        value: u8,
        /// Byte offset of the tag.
        offset: usize,
    },
    /// A tag encoded field number 0, or a number above the protobuf maximum
    /// (`536_870_911`, i.e. 2^29 − 1). Field 0 is never valid.
    InvalidFieldNumber {
        /// The offending field number.
        value: u64,
        /// Byte offset of the tag.
        offset: usize,
    },
    /// An `EGROUP` (group-end) tag appeared with no matching open group, or with
    /// a field number that does not match the innermost open group.
    UnexpectedEndGroup {
        /// The field number carried by the `EGROUP` tag.
        field: u64,
        /// Byte offset of the tag.
        offset: usize,
    },
    /// An `SGROUP` (group-start) was never closed by a matching `EGROUP` before
    /// the buffer ended.
    UnterminatedGroup {
        /// The field number of the unterminated group.
        field: u64,
        /// Byte offset where the group opened.
        offset: usize,
    },
    /// Nesting (submessages and/or groups) exceeded the configured depth limit —
    /// a depth-bomb guard that prevents unbounded recursion.
    DepthLimitExceeded {
        /// The configured maximum depth.
        limit: usize,
        /// Byte offset where the limit was hit.
        offset: usize,
    },
}

impl Error {
    /// The byte offset associated with this error, for reporting.
    #[must_use]
    pub fn offset(&self) -> usize {
        match self {
            Error::TruncatedVarint { offset }
            | Error::OverlongVarint { offset }
            | Error::VarintOverflow { offset }
            | Error::UnexpectedEof { offset, .. }
            | Error::LengthOutOfRange { offset, .. }
            | Error::InvalidWireType { offset, .. }
            | Error::InvalidFieldNumber { offset, .. }
            | Error::UnexpectedEndGroup { offset, .. }
            | Error::UnterminatedGroup { offset, .. }
            | Error::DepthLimitExceeded { offset, .. } => *offset,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TruncatedVarint { offset } => {
                write!(f, "truncated varint at offset {offset}")
            }
            Error::OverlongVarint { offset } => {
                write!(f, "overlong varint (>10 bytes) at offset {offset}")
            }
            Error::VarintOverflow { offset } => {
                write!(f, "varint overflows u64 at offset {offset}")
            }
            Error::UnexpectedEof { what, offset } => {
                write!(
                    f,
                    "unexpected end of input reading {what} at offset {offset}"
                )
            }
            Error::LengthOutOfRange {
                value,
                available,
                offset,
            } => write!(
                f,
                "length-delimited field claims {value} bytes but only {available} remain \
                 (at offset {offset})"
            ),
            Error::InvalidWireType { value, offset } => {
                write!(f, "invalid wire type {value} at offset {offset}")
            }
            Error::InvalidFieldNumber { value, offset } => {
                write!(f, "invalid field number {value} at offset {offset}")
            }
            Error::UnexpectedEndGroup { field, offset } => write!(
                f,
                "unexpected group-end tag for field {field} at offset {offset}"
            ),
            Error::UnterminatedGroup { field, offset } => write!(
                f,
                "unterminated group for field {field} opened at offset {offset}"
            ),
            Error::DepthLimitExceeded { limit, offset } => {
                write!(f, "nesting depth limit {limit} exceeded at offset {offset}")
            }
        }
    }
}

impl std::error::Error for Error {}
