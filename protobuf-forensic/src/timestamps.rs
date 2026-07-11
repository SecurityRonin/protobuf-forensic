//! Timestamp flagging via [`timeglyph`].
//!
//! Each integer view of a field is run through `timeglyph`, which returns every
//! civil-renderable reading scored by plausibility-window membership. We keep
//! only non-sentinel readings at or above a score threshold and cap the count,
//! so a value that lands in a plausible modern window (a real timestamp) is
//! surfaced while an arbitrary small integer is not.

use std::cmp::Ordering;

use timeglyph::interpret::{interpret_float, interpret_int, Candidate};
use timeglyph::scan::confidence_pct;

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

/// Build a [`TimestampHit`] from a timeglyph [`Candidate`] — `None` if it does
/// not render to a civil date.
fn hit_from(candidate: Candidate, source: TimeSource) -> Option<TimestampHit> {
    let rendered = candidate.rendered?;
    Some(TimestampHit {
        source,
        format_id: candidate.format_id.to_string(),
        label: candidate.label.to_string(),
        rendered,
        score: candidate.score,
        confidence_pct: confidence_pct(candidate.score),
        citation: candidate.citation.to_string(),
    })
}

/// Filter timeglyph candidates to plausible, non-sentinel readings above the
/// score threshold and convert them to hits.
fn collect(candidates: Vec<Candidate>, source: TimeSource, threshold: f64) -> Vec<TimestampHit> {
    candidates
        .into_iter()
        .filter(|c| !c.sentinel && c.score >= threshold)
        .filter_map(|c| hit_from(c, source))
        .collect()
}

/// Sort by score (descending) and keep at most `max`.
fn finalize(mut hits: Vec<TimestampHit>, max: usize) -> Vec<TimestampHit> {
    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    hits.truncate(max);
    hits
}

/// Timestamp readings for a varint value, read as a signed integer. A value
/// above `i64::MAX` cannot be a plausible signed epoch and yields none.
pub(crate) fn for_varint(value: u64, threshold: f64, max: usize) -> Vec<TimestampHit> {
    let hits = match i64::try_from(value) {
        Ok(v) => collect(interpret_int(v), TimeSource::Varint, threshold),
        Err(_) => Vec::new(),
    };
    finalize(hits, max)
}

/// Timestamp readings for a fixed 8-byte value, read both as a signed integer
/// (fixed64/sfixed64) and as an IEEE-754 double (e.g. a Cocoa/Mac absolute time).
pub(crate) fn for_fixed64(bits: u64, threshold: f64, max: usize) -> Vec<TimestampHit> {
    let mut hits = collect(
        interpret_int(bits as i64),
        TimeSource::Fixed64AsInt,
        threshold,
    );
    hits.extend(collect(
        interpret_float(f64::from_bits(bits)),
        TimeSource::Fixed64AsFloat,
        threshold,
    ));
    finalize(hits, max)
}

/// Timestamp readings for a fixed 4-byte value, read as a signed integer (a
/// 32-bit Unix time fits here).
pub(crate) fn for_fixed32(bits: u32, threshold: f64, max: usize) -> Vec<TimestampHit> {
    let hits = collect(
        interpret_int(i64::from(bits)),
        TimeSource::Fixed32AsInt,
        threshold,
    );
    finalize(hits, max)
}
