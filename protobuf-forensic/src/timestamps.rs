//! Timestamp flagging via [`timeglyph`].
//!
//! RED skeleton — types plus unimplemented producers; behaviour lands in GREEN.

/// Where a timestamp reading came from — which numeric view of a field was fed
/// to [`timeglyph`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// A varint value, read as a signed integer.
    Varint,
    /// A fixed 8-byte value, its bits read as a signed integer.
    Fixed64AsInt,
    /// A fixed 8-byte value, its bits read as an IEEE-754 double.
    Fixed64AsFloat,
    /// A fixed 4-byte value, read as a signed integer.
    Fixed32AsInt,
}

/// One timestamp reading consistent with a field's numeric value.
///
/// A [`TimestampHit`] states that the value *is consistent with* the named
/// format rendering to [`rendered`](TimestampHit::rendered); it is a candidate,
/// carrying its plausibility [`score`](TimestampHit::score), never a confirmed
/// time.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampHit {
    /// Which numeric view produced this reading.
    pub source: TimeSource,
    /// timeglyph format id (e.g. `"unixtime"`, `"webkit"`).
    pub format_id: String,
    /// Human-readable format label.
    pub label: String,
    /// The RFC 3339 rendering of the decoded instant (UTC).
    pub rendered: String,
    /// timeglyph plausibility score in `[0, 1]`.
    pub score: f64,
    /// The score as a whole-number percentage.
    pub confidence_pct: u8,
    /// Spec citation for the assumed format.
    pub citation: String,
}

/// Collect timestamp readings for a varint value (read as a signed integer).
pub(crate) fn for_varint(_value: u64, _threshold: f64, _max: usize) -> Vec<TimestampHit> {
    unimplemented!("GREEN")
}

/// Collect timestamp readings for a fixed 8-byte value (as int and as double).
pub(crate) fn for_fixed64(_bits: u64, _threshold: f64, _max: usize) -> Vec<TimestampHit> {
    unimplemented!("GREEN")
}

/// Collect timestamp readings for a fixed 4-byte value (as a signed integer).
pub(crate) fn for_fixed32(_bits: u32, _threshold: f64, _max: usize) -> Vec<TimestampHit> {
    unimplemented!("GREEN")
}
