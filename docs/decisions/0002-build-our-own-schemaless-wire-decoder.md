# 2. Build our own schemaless wire decoder rather than reuse an existing crate

Date: 2026-07-24
Status: Accepted

## Context

Before writing a parser the fleet requires a search for prior art
(`CLAUDE.core.md`, "Research-First"). Two classes of protobuf crate exist on
crates.io:

- **Schema-driven** — `prost`, `rust-protobuf`. Both generate types from a
  `.proto` and cannot decode without it. Forensics rarely has the schema (the
  blob comes out of a LevelDB value, an app cache, a memory dump), so these do
  not address the schemaless case at all.
- **Schemaless** — `protobuf-core` (an unrelated crate by `wada314`, version
  0.2.2) decodes arbitrary bytes into a field tree without a `.proto`.

`protobuf-core` was evaluated on the forensic-robustness bar (`docs/validation.md`,
"Build-vs-reuse"). It is **not written to the fleet panic-free bar**: it declares
neither `forbid(unsafe)` nor `deny(clippy::unwrap_used/expect_used)`, so no lint
enforces the "never panic on untrusted input" invariant; it ships no fuzz target;
and its MSRV is unspecified. Its behaviour on attacker-controlled evidence bytes is
therefore unproven — neither guaranteed by lint nor exercised by a fuzzer. (Its one
`unreachable!()`, `src/lib.rs:222`, is the never-constructible
`impl From<Infallible> for ProtobufError` arm — unreachable by type construction,
not a decode-path hazard; the read paths use `Result` / `thiserror`.)

## Decision

Implement the schemaless wire decoder ourselves in `protobuf-forensic-core`,
against the authoritative protobuf
[encoding spec](https://protobuf.dev/programming-guides/encoding/) cited at the
top of `src/lib.rs`. The wire format is small (`tag = (field_number << 3) |
wire_type`; wire types 0/1/2/5 plus the deprecated group markers 3/4), roughly
40 lines of real logic, so the reuse win is small and the robustness cost of
adopting an un-fuzzed, panic-capable dependency is real.

Correctness is not taken on faith: it is cross-validated against Google's
`protoc` as an independent oracle (`protobuf-forensic-core/tests/oracle.rs`, ADR
evidence in `docs/validation.md`), so building our own does not forfeit
third-party verification.

## Consequences

- The decoder meets the Paranoid Gatekeeper bar by construction: `forbid(unsafe)`,
  `deny(unwrap_used/expect_used)`, every varint/length bounds-checked, recursion
  depth-capped, backed by a `cargo-fuzz` "must not panic" target.
- We own and maintain ~40 lines of wire-format logic instead of a dependency.
- The correctness risk of a hand-rolled decoder is retired by the tier-2 `protoc`
  oracle (`protoc --decode_raw` is the reference schemaless decoder we reimplement),
  not by self-authored fixtures alone.
- If a maintained, fuzzed, panic-free schemaless crate later appears, the
  build-vs-reuse calculus should be revisited (fleet "prefer our own / reuse a
  correct maintained crate" policy).
