# protobuf-forensic — Product Requirements

*A reverse-written intent document. Every current-state claim below is grounded in a
same-session read of the workspace (`Cargo.toml` members, `protobuf-forensic-core/src/`,
`protobuf-forensic/src/`, `protobuf4n6/src/`, `docs/validation.md`, `README.md`) and the
git history (2026-07-24). The load-bearing decisions live as ADRs
[0001](decisions/0001-three-crate-reader-analyzer-cli-layering.md)–[0008](decisions/0008-timestamp-flagging-as-cited-candidates.md)
under [`docs/decisions/`](decisions/).*

## Executive Summary

**You have a Protocol Buffers blob and no `.proto`. protobuf-forensic decodes it
anyway.** In forensics the schema is almost never available — the blob comes out
of a LevelDB value, an app cache, a memory dump — so schema-driven libraries
(`prost`, `rust-protobuf`) are useless. This project decodes the protobuf **wire
format blind**, the way `protoc --decode_raw` and Google's protoscope do, into a
recursive, path-addressed field tree, and layers two forensic value-adds on top:
ambiguity scoring for length-delimited fields, and timestamp flagging for every
integer field via `timeglyph`.

The examiner-facing product is **`protobuf4n6`**, a CLI that takes a blob from a
file, stdin, or a `--hex` string and renders it as a human field tree, one JSON
object per field (`jsonl`), or a protoscope-like format — with the values that
look like timestamps flagged as *consistent with* specific epochs, never as a
verdict.

The decoder parses untrusted, attacker-influenceable evidence, so it holds the
fleet Paranoid Gatekeeper bar: `forbid(unsafe)`, panic-free by lint,
bounds-checked reads, depth-capped recursion, `cargo-fuzz` targets, and
validation against `protoc` as an independent oracle.

## Problem & Users

**Who runs this:** a DFIR analyst or reverse engineer who has extracted an opaque
binary blob and suspects it is Protocol Buffers, with no schema to decode it.

**Their pain:** protobuf is everywhere in application storage and IPC, but its
wire format discards field names and types. Without the `.proto`, standard
tooling gives nothing. `protoc --decode_raw` exists but is a raw dump with no
forensic lens — it does not flag timestamps, score ambiguous payloads, or emit a
machine-faithful stream for a pipeline. The analyst is left eyeballing hex.

**What they need right now:** point a tool at the blob and get back a readable
field tree — nested messages walked recursively, strings recovered,
length-delimited payloads classified, and any integer that could be a time
surfaced with candidate readings — fast enough to iterate, and honest enough to
put in a report.

## What It Does

- **Decodes every wire field schema-blind.** `tag = (field_number << 3) |
  wire_type`; wire type 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32, plus
  the deprecated group markers 3/4. Output is a recursive `Field` tree
  (`protobuf-forensic-core`).
- **Infers length-delimited payloads** message-first (matching
  `protoc --decode_raw`): a `LEN` payload resolves to a nested **message**
  (parses cleanly, consumes exactly its bytes), a UTF-8 **string**, or opaque
  **bytes** ([ADR 0007](decisions/0007-message-first-length-delimited-inference.md)).
- **Scores ambiguity.** The forensic layer attaches a confidence and notes naming
  the *other* plausible readings of an ambiguous payload (a message that is also
  printable text; bytes that also decode as a packed repeated field).
- **Flags timestamps.** Every integer view of a field (varint, fixed32, fixed64
  as int and as double) runs through `timeglyph`; plausible readings are attached
  as ranked, cited **candidates** — *consistent with* a format, never a confirmed
  time ([ADR 0008](decisions/0008-timestamp-flagging-as-cited-candidates.md)).
- **Reads from file, stdin, or `--hex`**, and renders as `text` (indented tree
  with confidence/notes/timestamps), `jsonl` (one machine-faithful JSON object
  per field, path-addressed), or `protoscope` (a protoscope-like `N: value`
  form). Selected with `--format`; timestamp output tuned with `--min-score` /
  `--max-timestamps` (`protobuf4n6/src/main.rs`, `lib.rs`).

## Scope

- Schemaless decode of the protobuf wire format, all wire types (0/1/2/5) plus
  groups (3/4), recursive submessages, packed repeated fields, zigzag decode.
- Forensic ambiguity scoring and `timeglyph` timestamp flagging over that decode.
- A CLI with text / JSONL / protoscope output and file / stdin / hex input.
- The two libraries are independently linkable: `protobuf-forensic-core` for the
  raw decoder, `protobuf-forensic` for the analyzed tree.

## Non-Goals

- **Schema-driven decoding.** No `.proto` compilation, no generated types — that
  is `prost` / `rust-protobuf`, and it is the case this tool exists *because*
  forensics lacks the schema ([ADR 0002](decisions/0002-build-our-own-schemaless-wire-decoder.md)).
- **Encoding / re-serialization.** The tool reads evidence; it does not produce
  protobuf bytes.
- **Confirming that a field *is* a timestamp.** Schema-blind, this is unknowable;
  the tool surfaces candidates and leaves the conclusion to the analyst
  ([ADR 0008](decisions/0008-timestamp-flagging-as-cited-candidates.md)).
- **Locating protobuf blobs inside a larger artifact.** Carving a `LEN` region
  out of a LevelDB value or a memory page is an upstream layer's job; this tool
  takes an already-isolated blob (`Path` / bytes / hex).
- **A GUI or MCP server.** The product surface is the `protobuf4n6` CLI.

## Artifact Family

Protocol Buffers wire-format blobs, wherever an examiner finds them without a
schema: LevelDB / IndexedDB values, application caches and preference stores,
serialized IPC captures, and protobuf regions recovered from memory dumps. The
decoder is medium-agnostic — it accepts a `Path`, a `&[u8]`, or a hex string and
knows nothing about where the bytes came from.

## Validation Approach

Correctness is proven against independent references, not self-authored fixtures
alone (`docs/validation.md`):

- **Tier-2 independent oracle for the decoder.** `protoc --encode` produces real
  wire bytes from a `.proto`, and `protoc --decode_raw` (the reference schemaless
  decoder this crate reimplements) is cross-checked field-by-field against our
  decode over a blob spanning every wire type, a submessage, a packed repeated
  field, a UTF-8 string, and non-UTF-8 bytes
  (`protobuf-forensic-core/tests/oracle.rs`, env-gated on `protoc`).
- **Tier-2 for timestamp flagging.** Known values (a Unix second → 2020-09-13; a
  `fixed64` double as a Cocoa/CFAbsoluteTime reading) whose civil rendering is
  derivable and confirmed by `timeglyph`'s own decode.
- **Tier-3 robustness + fuzz.** Property tests feed truncated/overlong varints,
  lying lengths, invalid wire types, unbalanced groups, and a depth bomb,
  asserting *returns `Err`, never panics* (`tests/wire.rs`); two `cargo-fuzz`
  "must not panic" targets (`decode`, `analyze`) back it at runtime.
- **Coverage gate.** 100 % function coverage across the workspace
  (`cargo llvm-cov --workspace --all-features --fail-under-functions 100`), with
  provably-unreachable defensive arms annotated `// cov:unreachable`.

## Security Posture

`forbid(unsafe)` workspace-wide; `clippy::unwrap_used`/`expect_used = deny` in
production; every varint/length bounds-checked; recursion depth-capped
(`DEFAULT_MAX_DEPTH = 100`) so a depth-bomb degrades to bytes rather than
overflowing the stack; no length field can drive an over-allocation
([ADR 0004](decisions/0004-forbid-unsafe-panic-free-by-lint.md),
[ADR 0003](decisions/0003-zero-dependency-bounds-checked-reader.md)). Supply chain
is gated by `cargo-deny` (license + advisory) and `cargo-vet`; releases are cut
by `release-plz`.
