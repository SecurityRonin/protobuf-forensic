# Validation

How each layer is checked, and at what evidence tier (see the fleet
Evidence-Based Rigor scale: tier 1 = independent third-party artifact + answer
key or real-world data; tier 2 = real engine output whose ground truth is
derivable from the documented construction or an independent oracle; tier 3 =
fixtures we authored, legitimate for detection rules and robustness properties).

## Build-vs-reuse: why a hand-rolled wire decoder

A schemaless protobuf decoder does exist on crates.io — **`protobuf-core`** (an
unrelated crate by `wada314`) decodes arbitrary bytes into a field tree without a
`.proto`. We evaluated it and **rejected it for forensic use** on robustness
grounds, not because "nothing existed":

- It is **not written to the fleet panic-free bar** — it declares neither
  `forbid(unsafe)` nor `deny(clippy::unwrap_used/expect_used)`, so no lint enforces
  the "never panic on untrusted input" invariant. (Its one `unreachable!()`,
  `src/lib.rs:222`, is the never-constructible `impl From<Infallible> for
  ProtobufError` arm — unreachable by type construction, not a decode-path hazard;
  the read paths use `Result` / `thiserror`.)
- It ships **no fuzz target** — the untrusted-input codec has never been fuzzed,
  so its robustness on attacker-controlled bytes is unproven.
- MSRV is unspecified; download/maturity is low.

For a decoder on the forensic path — untrusted, attacker-influenced evidence
bytes — the fleet bar is *never panic, never read out of bounds* (Paranoid
Gatekeeper). `protobuf-forensic-core` meets it by construction: `forbid(unsafe)`,
`deny(unwrap_used/expect_used)`, every varint/length bounds-checked, recursion
depth-capped, and a `cargo-fuzz` target (`protobuf-forensic/fuzz`) that drives
malformed bytes through the decoder asserting no panic / bounded memory. The wire
format is ~40 lines, so the reuse win is small and the robustness cost of adopting
an un-fuzzed, panic-capable dependency is real. (`prost`/`rust-protobuf` are the
other alternatives — both schema-driven, requiring a `.proto`, so they don't
address the schemaless case at all.) The correctness of the decode itself is then
validated against `protoc` as an independent oracle, below.

## `protobuf-forensic-core` — the schemaless wire decoder (tier 2, independent oracle)

`protobuf-forensic-core/tests/oracle.rs` cross-validates against Google's `protoc`
(env-gated; skips cleanly when `protoc` is absent, set `PROTOC` to override):

- **Independent producer** — `protoc --encode=Test test.proto` turns a text
  message plus a `.proto` schema into real wire bytes. Neither the bytes nor the
  ground truth is a fixture we hand-authored; both come from Google's engine and
  the documented `.proto` construction.
- **Independent oracle** — `protoc --decode_raw` is the reference schemaless
  decoder this crate reimplements. The test asserts our decode agrees with it on
  the top-level field-number multiset and, field by field, on the discriminating
  classifications: field 3 is a nested **message** in both (protoc renders
  `3 {`), field 2 is the **string** `"testing"`, field 4 is opaque **bytes**
  (non-UTF-8), field 5 (packed `int32`) recovers `[1, 2, 3]` via the packed
  helper, and the varint / `fixed32` / `fixed64` scalars decode to the exact
  documented values.

The blob covers every wire type (0/1/2/5), a submessage, a packed repeated
field, a UTF-8 string, and non-UTF-8 bytes. Verified locally against
`libprotoc 25.3`.

### Robustness (tier 3, property tests + fuzz)

`protobuf-forensic-core/tests/wire.rs` feeds truncated and overlong varints, lying
lengths, invalid wire types, field number 0, unbalanced groups, a 200-deep
depth bomb, and a deterministic random-byte sweep to the public decoder and
asserts the property *"returns `Err` (or partial), never panics"*. These are
tier-3 property tests: the value-producing correctness is covered by the tier-2
oracle above; here the invariant is a property, not a value.

The runtime backstop is `cargo-fuzz` (`fuzz/`): two "must not panic" targets,
`decode` (the wire decoder) and `analyze` (the full forensic walk). Local smoke
runs on nightly executed **1.82 M** and **0.21 M** cases respectively with no
crashes and bounded memory (RSS ~ 0.5 GB); `fuzz.yml` runs them weekly.

## `protobuf-forensic` — analysis layer (tier 2 / tier 3)

- **Timestamp flagging (tier 2).** Integer values are run through
  [`timeglyph`](https://github.com/SecurityRonin/timeglyph); the tests use a
  known Unix second (`1_600_000_000` -> 2020-09-13) and a `fixed32`/`fixed64`
  double whose civil rendering is derivable and confirmed by timeglyph's own
  decode. The `fixed64` double path is validated as a Cocoa / CFAbsoluteTime
  reading (~2021).
- **Ambiguity scoring (tier 3, documented heuristic).** The confidence attached
  to a length-delimited field's message / string / bytes / packed reading is a
  *documented heuristic* (the `*_CONFIDENCE` constants), not an oracle-checked
  value. Correctness here is defined by the rule, which is specified by the
  tests (e.g. the payload `(1` = `0x28 0x31` parses as a message **and** is
  printable, so it is flagged ambiguous at `MESSAGE_AMBIGUOUS_CONFIDENCE`). This
  is the legitimate tier-3 zone: a scoring heuristic, not a codec value.

### Honest limitations of the scoring

- **Timestamp candidates are candidates, not confirmations.** A schemaless
  decoder cannot know that an integer field *is* a time. timeglyph legitimately
  scores small integers as in-window for recent-epoch formats (150 is "Cocoa
  2001-01-01 + 150 s"). We therefore surface **capped, ranked, cited**
  candidates and leave the judgement to the analyst, rather than pretending to
  suppress or confirm. Filter with `--min-score` / `--max-timestamps`.
- **Message-vs-string is inherently ambiguous.** Resolution is message-first,
  matching `protoc --decode_raw`. Short byte sequences that happen to parse as a
  valid message (e.g. `hi` = `0x68 0x69` decodes as field 13 = 105) are reported
  as a message with an ambiguity note pointing at the text reading. This
  message-vs-string-vs-packed disambiguation is a heuristic; treat the notes and
  confidence as guidance, not a verdict.

## `protobuf4n6` — the CLI (tier 2 via the oracle, plus shell tests)

The library renderers are exercised across text / JSONL / protoscope formats,
and the compiled binary is driven end-to-end via `CARGO_BIN_EXE` shell tests
(file, `--hex`, and stdin inputs; loud non-zero exit on bad input). Correctness
of the underlying decode rides on the `protobuf-forensic-core` oracle above.

## Coverage

The workspace enforces **100 % function coverage**
(`cargo llvm-cov --workspace --all-features --fail-under-functions 100`).
Provably-unreachable defensive arms (e.g. the `EGROUP` wire-type label, which no
field can carry) are annotated `// cov:unreachable` and left in place as
defense-in-depth rather than deleted to chase a line.
