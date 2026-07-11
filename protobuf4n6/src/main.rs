//! `protobuf4n6` CLI entry point (thin humble-object shell).
//!
//! Selects an input (a file, a `--hex` string, or stdin), parses arguments, and
//! delegates to [`protobuf4n6::run`]; all logic lives in the library so it is
//! unit-testable.
#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use protobuf4n6::{parse_hex, run, AnalysisOptions, CliError, Format};

/// Schemaless protobuf forensic decoder: dump a protobuf blob with no `.proto`.
#[derive(Parser)]
#[command(name = "protobuf4n6", version, about)]
struct Cli {
    /// Protobuf file to decode. Omit (or pass `-`) to read from standard input.
    file: Option<PathBuf>,

    /// Decode this hex string instead of a file (e.g. `0x089601` or `08 96 01`).
    #[arg(long, conflicts_with = "file")]
    hex: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Minimum timeglyph plausibility score for a timestamp candidate to show.
    #[arg(long, default_value_t = 0.5)]
    min_score: f64,

    /// Maximum timestamp candidates to show per field.
    #[arg(long, default_value_t = 3)]
    max_timestamps: usize,
}

fn read_input(cli: &Cli) -> Result<Vec<u8>, CliError> {
    if let Some(hex) = &cli.hex {
        return parse_hex(hex);
    }
    match &cli.file {
        Some(path) if path.as_os_str() != "-" => Ok(std::fs::read(path)?),
        _ => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let options = AnalysisOptions {
        timestamp_score_threshold: cli.min_score,
        max_timestamp_candidates: cli.max_timestamps,
        ..AnalysisOptions::default()
    };

    let bytes = match read_input(&cli) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = writeln!(io::stderr(), "protobuf4n6: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    match run(&bytes, cli.format, &options, &mut out) {
        Ok(()) => {
            let _ = out.flush();
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "protobuf4n6: {e}");
            ExitCode::FAILURE
        }
    }
}
