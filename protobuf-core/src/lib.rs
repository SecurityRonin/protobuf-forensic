//! Schemaless Protocol Buffers wire-format decoder for forensics.
//!
//! Hand a byte slice of protobuf with **no `.proto` schema** to [`decode`] and
//! get back a tree of [`Field`]s. For each field the wire format tells us the
//! field number and a wire type; a length-delimited (`LEN`) payload is then
//! *inferred* to be one of a nested [message](LenInterp::Message), a UTF-8
//! [string](LenInterp::Text), or raw [bytes](LenInterp::Bytes) — the same blind
//! decode `protoc --decode_raw` and Google's protoscope perform.
//!
//! The wire format (see the authoritative
//! [encoding spec](https://protobuf.dev/programming-guides/encoding/)):
//! `tag = (field_number << 3) | wire_type`, where wire type `0` is a varint,
//! `1` is fixed 8 bytes (`I64`), `2` is length-delimited (`LEN`), `3`/`4` are
//! the deprecated group markers, and `5` is fixed 4 bytes (`I32`).
//!
//! ```
//! // Field 1 = varint 150, then field 3 = submessage {1: 150}.
//! let bytes = [0x08, 0x96, 0x01, 0x1a, 0x03, 0x08, 0x96, 0x01];
//! let fields = protobuf_core::decode(&bytes).unwrap();
//! assert_eq!(fields.len(), 2);
//! assert_eq!(fields[0].number, 1);
//! ```
//!
//! Decoding is `#![forbid(unsafe_code)]` and panic-free: every varint and length
//! read is bounds-checked (a truncated or overlong varint, or a lying length,
//! yields an [`Error`], never a panic), recursion is depth-capped against
//! depth-bombs, and no length field can drive an over-allocation.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod reader;

pub use error::Error;

/// The default maximum nesting depth (submessages + groups) before
/// [`Error::DepthLimitExceeded`]. Deeper nesting is not treated as a message; it
/// degrades to [`LenInterp::Bytes`] rather than recursing without bound.
pub const DEFAULT_MAX_DEPTH: usize = 100;

/// The six protobuf wire types. The 3-bit value packed into the low bits of a
/// tag; values 6 and 7 are undefined and rejected as [`Error::InvalidWireType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// `0` — base-128 varint (int32/64, uint32/64, sint32/64, bool, enum).
    Varint,
    /// `1` — fixed 8 bytes, little-endian (fixed64, sfixed64, double).
    I64,
    /// `2` — length-delimited (string, bytes, embedded message, packed).
    Len,
    /// `3` — group start (deprecated).
    StartGroup,
    /// `4` — group end (deprecated).
    EndGroup,
    /// `5` — fixed 4 bytes, little-endian (fixed32, sfixed32, float).
    I32,
}

impl WireType {
    /// Map a raw 3-bit wire-type value to a [`WireType`]; `6`/`7` are undefined.
    ///
    /// # Errors
    /// Returns [`Error::InvalidWireType`] for values 6 or 7.
    pub fn from_u8(value: u8, offset: usize) -> Result<Self, Error> {
        match value {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::I64),
            2 => Ok(WireType::Len),
            3 => Ok(WireType::StartGroup),
            4 => Ok(WireType::EndGroup),
            5 => Ok(WireType::I32),
            other => Err(Error::InvalidWireType {
                value: other,
                offset,
            }),
        }
    }

    /// The raw 3-bit wire-type value.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            WireType::Varint => 0,
            WireType::I64 => 1,
            WireType::Len => 2,
            WireType::StartGroup => 3,
            WireType::EndGroup => 4,
            WireType::I32 => 5,
        }
    }
}

/// One decoded record: a field number, its wire type, and the decoded value.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// The field number (`tag >> 3`); always in `1..=536_870_911`.
    pub number: u64,
    /// The wire type carried by the tag.
    pub wire_type: WireType,
    /// The decoded value.
    pub value: FieldValue,
}

/// A decoded field value, keyed by wire type.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// A base-128 varint, stored as the raw unsigned 64-bit value. Signed
    /// (`sint`) fields are ZigZag-encoded; apply [`zigzag_decode`] to recover
    /// the signed value (the schema, which we do not have, decides which).
    Varint(u64),
    /// A fixed 8-byte little-endian value (`I64`), as raw `u64` bits.
    I64(u64),
    /// A fixed 4-byte little-endian value (`I32`), as raw `u32` bits.
    I32(u32),
    /// A length-delimited payload plus its inferred interpretation.
    Len(LenValue),
    /// A deprecated group, decoded as its sequence of inner fields.
    Group(Vec<Field>),
}

/// A length-delimited (`LEN`) field: the raw payload bytes plus the inferred
/// interpretation. The raw bytes are always retained so a forensic caller can
/// re-interpret an ambiguous payload (e.g. as a packed repeated field).
#[derive(Debug, Clone, PartialEq)]
pub struct LenValue {
    /// The raw payload bytes (length-prefix already stripped).
    pub raw: Vec<u8>,
    /// The inferred interpretation.
    pub interp: LenInterp,
}

/// The inferred interpretation of a length-delimited payload.
///
/// Resolution is message-first (mirroring `protoc --decode_raw`): a payload that
/// parses cleanly as a non-empty submessage consuming exactly its bytes is a
/// [`Message`](LenInterp::Message); otherwise a valid, printable UTF-8 payload
/// is [`Text`](LenInterp::Text); otherwise it is opaque [`Bytes`](LenInterp::Bytes).
#[derive(Debug, Clone, PartialEq)]
pub enum LenInterp {
    /// The payload decoded cleanly as a nested message.
    Message(Vec<Field>),
    /// The payload is valid, printable UTF-8.
    Text(String),
    /// The payload is opaque bytes (see [`LenValue::raw`]).
    Bytes,
}

/// Decoder limits that bound resource use on hostile input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting depth for submessages and groups.
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl LenValue {
    /// Reinterpret the raw payload as a packed repeated field of varints —
    /// `Some` iff the bytes decode as a whole number of varints consuming
    /// exactly the payload (and the payload is non-empty). Schemaless callers
    /// use this to surface a packed-repeated reading of an otherwise opaque
    /// payload; it is one *candidate* interpretation, not a certainty.
    #[must_use]
    pub fn as_packed_varints(&self) -> Option<Vec<u64>> {
        reader::packed_varints(&self.raw)
    }

    /// Reinterpret the raw payload as a packed repeated field of fixed 4-byte
    /// (`I32`) little-endian values — `Some` iff the length is a non-zero
    /// multiple of 4.
    #[must_use]
    pub fn as_packed_i32(&self) -> Option<Vec<u32>> {
        reader::packed_i32(&self.raw)
    }

    /// Reinterpret the raw payload as a packed repeated field of fixed 8-byte
    /// (`I64`) little-endian values — `Some` iff the length is a non-zero
    /// multiple of 8.
    #[must_use]
    pub fn as_packed_i64(&self) -> Option<Vec<u64>> {
        reader::packed_i64(&self.raw)
    }
}

/// Decode ZigZag-encoded `sint32`/`sint64` back to a signed value.
///
/// A schemaless decoder cannot know whether a varint field is `sint` (ZigZag) or
/// a plain `int`; this helper lets a caller offer the signed reading as an
/// alternative. `0 → 0`, `1 → -1`, `2 → 1`, `3 → -2`, …
#[must_use]
pub fn zigzag_decode(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

/// Decode protobuf wire-format bytes into a field tree with default [`Limits`].
///
/// # Errors
/// Returns an [`Error`] on any malformed input (truncated/overlong varint, lying
/// length, invalid wire type or field number, unbalanced group, or nesting past
/// the depth limit) rather than panicking.
pub fn decode(bytes: &[u8]) -> Result<Vec<Field>, Error> {
    decode_with_limits(bytes, &Limits::default())
}

/// Decode protobuf wire-format bytes into a field tree with explicit [`Limits`].
///
/// # Errors
/// See [`decode`].
pub fn decode_with_limits(bytes: &[u8], limits: &Limits) -> Result<Vec<Field>, Error> {
    reader::decode_message(bytes, limits)
}
