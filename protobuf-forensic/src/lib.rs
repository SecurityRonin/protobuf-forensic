//! Forensic layer over [`protobuf_core`].
//!
//! [`analyze`] decodes a schemaless protobuf blob into a path-addressed tree of
//! [`AnalyzedField`]s and adds two forensic value-adds the raw wire decode
//! cannot:
//!
//! 1. **Ambiguity scoring for length-delimited fields.** `protobuf-core` picks a
//!    single message-first interpretation; here each `LEN` field also carries a
//!    [`confidence`](AnalyzedField::confidence) and [`notes`](AnalyzedField::notes)
//!    naming the *other* plausible readings (a payload that parses as a message
//!    but is also printable text; opaque bytes that also decode as a packed
//!    repeated field). The scores are documented heuristics, not certainties.
//! 2. **Timestamp flagging.** Every integer-bearing field (varint, fixed32,
//!    fixed64 — the last read both as an integer and as an IEEE-754 double) is
//!    run through [`timeglyph`]; readings that land in a plausible civil-time
//!    window above a score threshold are attached as [`TimestampHit`]s. A field
//!    value is reported as *consistent with* a timestamp format, never as a
//!    confirmed time.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod timestamps;

use protobuf_core::{Error, Field, Limits, WireType};

pub use protobuf_core;
pub use timestamps::{TimeSource, TimestampHit};

/// Confidence that a `LEN` payload parsing cleanly as a structured message — and
/// *not* also being printable text — is indeed a message.
pub const MESSAGE_CONFIDENCE: f64 = 0.9;
/// Confidence in the message reading when the same bytes are *also* valid
/// printable UTF-8 (a genuinely ambiguous payload — short ASCII can parse as a
/// message). The text reading is surfaced as a note.
pub const MESSAGE_AMBIGUOUS_CONFIDENCE: f64 = 0.55;
/// Confidence that a `LEN` payload that did not parse as a message but is valid
/// printable UTF-8 is a string.
pub const TEXT_CONFIDENCE: f64 = 0.9;
/// Confidence that a `LEN` payload that is neither a clean message nor printable
/// text is opaque bytes.
pub const BYTES_CONFIDENCE: f64 = 0.6;
/// Confidence in the bytes reading when the payload *also* decodes as a packed
/// repeated field (so "bytes" is a weaker call); the packed reading is noted.
pub const BYTES_PACKABLE_CONFIDENCE: f64 = 0.5;

/// The result of analysing a protobuf blob: its top-level fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Analysis {
    /// The top-level fields, in wire order.
    pub fields: Vec<AnalyzedField>,
}

/// One field enriched with forensic classification.
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzedField {
    /// Dotted path from the root (e.g. `"3.1"` for field 1 of the submessage in
    /// top-level field 3).
    pub path: String,
    /// The field number.
    pub number: u64,
    /// The wire type carried by the tag.
    pub wire_type: WireType,
    /// The classified value.
    pub value: AnalyzedValue,
    /// Confidence in [`value`](AnalyzedField::value)'s interpretation, in
    /// `[0, 1]`. Unambiguous scalars are `1.0`; ambiguous length-delimited
    /// payloads carry one of the documented `*_CONFIDENCE` heuristics.
    pub confidence: f64,
    /// Human-readable notes: alternative interpretations and ambiguity flags.
    pub notes: Vec<String>,
    /// Timestamp readings consistent with this field's numeric value(s).
    pub timestamps: Vec<TimestampHit>,
}

/// A classified field value.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalyzedValue {
    /// A varint (raw unsigned value).
    Varint(u64),
    /// A fixed 8-byte value (raw bits).
    Fixed64(u64),
    /// A fixed 4-byte value (raw bits).
    Fixed32(u32),
    /// A length-delimited payload that resolved to a nested message.
    Message(Vec<AnalyzedField>),
    /// A deprecated group.
    Group(Vec<AnalyzedField>),
    /// A length-delimited payload that resolved to printable UTF-8 text.
    Text(String),
    /// A length-delimited payload left as opaque bytes.
    Bytes(Vec<u8>),
}

/// Tuning for [`analyze_with`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Options {
    /// Minimum timeglyph plausibility score (`[0, 1]`) for a timestamp reading
    /// to be attached. Higher = fewer, stronger candidates.
    pub timestamp_score_threshold: f64,
    /// Maximum timestamp readings retained per field (the highest-scoring).
    pub max_timestamp_candidates: usize,
    /// Wire-decoder limits (depth cap).
    pub limits: Limits,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timestamp_score_threshold: 0.5,
            max_timestamp_candidates: 3,
            limits: Limits::default(),
        }
    }
}

/// Decode and analyse a protobuf blob with default [`Options`].
///
/// # Errors
/// Propagates any [`protobuf_core::Error`] from the wire decode.
pub fn analyze(bytes: &[u8]) -> Result<Analysis, Error> {
    analyze_with(bytes, &Options::default())
}

/// Decode and analyse a protobuf blob with explicit [`Options`].
///
/// # Errors
/// Propagates any [`protobuf_core::Error`] from the wire decode.
pub fn analyze_with(bytes: &[u8], options: &Options) -> Result<Analysis, Error> {
    let fields = protobuf_core::decode_with_limits(bytes, options.limits)?;
    Ok(analyze_fields(&fields, options))
}

/// Analyse already-decoded [`Field`]s (no wire decode).
#[must_use]
pub fn analyze_fields(fields: &[Field], options: &Options) -> Analysis {
    let _ = (fields, options);
    unimplemented!("GREEN")
}
