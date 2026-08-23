//! `protobuf4n6` — a protoscope-style schemaless protobuf CLI (library half).
//!
//! Humble object: every decision lives here as testable functions; `main.rs` is
//! a thin shell that selects an input (file, `--hex`, or stdin), parses
//! arguments, and calls [`run`]. Dumps a decoded + forensically-analysed
//! protobuf blob as a human `text` field tree, machine-faithful `jsonl`, or a
//! protoscope-like format.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod render;

use std::fmt;
use std::io::{self, Write};

use clap::ValueEnum;
use protobuf_forensic::Options;

pub use protobuf_forensic::{self, Options as AnalysisOptions};

/// Output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable, indented field tree with confidence, notes, and timestamps.
    Text,
    /// One JSON object per field (pre-order, path-addressed) — machine-faithful.
    Jsonl,
    /// A protoscope-like `N: value` / `N: { … }` rendering.
    Protoscope,
}

/// Errors surfaced by the CLI.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The wire decode failed.
    Decode(protobuf_forensic_core::Error),
    /// A `--hex` argument was not valid hex. Carries the offending character and
    /// its position (fail-loud, show-the-value).
    Hex {
        /// A human description of the problem.
        reason: String,
    },
    /// An I/O error reading input or writing output.
    Io(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Decode(e) => write!(f, "protobuf decode error: {e}"),
            CliError::Hex { reason } => write!(f, "invalid hex input: {reason}"),
            CliError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<protobuf_forensic_core::Error> for CliError {
    fn from(e: protobuf_forensic_core::Error) -> Self {
        CliError::Decode(e)
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Io(e)
    }
}

/// Parse a hex string into bytes, tolerating a leading `0x`, ASCII whitespace,
/// and `:`/`-` separators. Odd length or a non-hex character is an error naming
/// the offending character and position.
///
/// # Errors
/// [`CliError::Hex`] on odd length or an invalid character.
pub fn parse_hex(input: &str) -> Result<Vec<u8>, CliError> {
    // Drop ASCII whitespace and common separators, then an optional 0x prefix.
    let mut cleaned = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_whitespace() || matches!(c, ':' | '-' | '_') {
            continue;
        }
        cleaned.push(c);
    }
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned.as_str());

    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return Err(CliError::Hex {
            reason: format!("odd number of hex digits ({})", digits.len()),
        });
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    let mut chunks = digits.chunks_exact(2);
    let mut position = 0;
    for pair in chunks.by_ref() {
        let hi = hex_nibble(pair[0], position)?;
        let lo = hex_nibble(pair[1], position + 1)?;
        out.push((hi << 4) | lo);
        position += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8, position: usize) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(CliError::Hex {
            reason: format!(
                "non-hex character {:?} at position {position}",
                char::from(other)
            ),
        }),
    }
}

/// Decode, analyse, and render `bytes` to `out`.
///
/// # Errors
/// [`CliError::Decode`] if the bytes are not valid protobuf; [`CliError::Io`] on
/// a write failure.
pub fn run(
    bytes: &[u8],
    format: Format,
    options: &Options,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let analysis = protobuf_forensic::analyze_with(bytes, options)?;
    render::render(&analysis, format, out)?;
    Ok(())
}
