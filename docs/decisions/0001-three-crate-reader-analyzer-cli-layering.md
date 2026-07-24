# 1. Three-crate layering: core reader, forensic analyzer, front-end CLI

Date: 2026-07-24
Status: Accepted

## Context

The repository does two conceptually distinct jobs. First, it decodes the raw
Protocol Buffers wire format with **no `.proto`** into a recursive field tree —
pure, dependency-light, and useful to any third party who links it. Second, it
adds forensic value on top: ambiguity scoring for length-delimited fields and
timestamp flagging via `timeglyph`. Third, it presents both to an examiner as a
runnable command with human and machine output formats.

Folding all three into one crate would force the pure wire decoder to inherit the
analyzer's dependency (`timeglyph`) and its higher MSRV, and would bury a reusable
primitive inside an application. The fleet crate-structure standard
(`ronin-issen/CLAUDE.md`, "Crate-structure standard — reader/analyzer split")
mandates a `<x>-core` reader plus an `<x>-forensic` analyzer; a front-end binary
follows the `<x>4n6` convention.

## Decision

Split the workspace into three members with a strictly downward dependency
arrow (`Cargo.toml` `members = ["protobuf-forensic-core", "protobuf-forensic",
"protobuf4n6"]`):

1. **`protobuf-forensic-core`** — the schemaless wire decoder. `decode(&[u8]) ->
   Vec<Field>`, pure `std`, zero dependencies, low MSRV. No findings, no
   heuristics. (`protobuf-forensic-core/src/lib.rs`, `reader.rs`.)
2. **`protobuf-forensic`** — the analysis layer. Depends on the core crate plus
   `timeglyph`; adds `*_CONFIDENCE` ambiguity scoring and `TimestampHit`
   flagging (`protobuf-forensic/src/lib.rs`, `timestamps.rs`).
3. **`protobuf4n6`** — the CLI. Depends on both libraries plus `clap` /
   `serde_json`; a thin humble-object `main.rs` shell over a testable `lib.rs`
   (`protobuf4n6/src/main.rs`, `lib.rs`).

The core crate never imports the analyzer; the analyzer never imports the CLI.

## Consequences

- A third party can `cargo add protobuf-forensic-core` for the wire decoder alone
  without pulling `timeglyph`, `clap`, or the raised MSRV.
- The analyzer's forensic heuristics evolve without touching the audited decoder.
- Three crates mean three published SemVer surfaces to keep in step; the shared
  `[workspace.package]` version and `[workspace.dependencies]` path/registry pins
  keep the bump to one edit (`Cargo.toml`).
- The layering matches the fleet reader/analyzer split, so the repository reads
  the same as `ntfs-forensic`, `vmdk-forensic`, and the other Pattern-A repos.
