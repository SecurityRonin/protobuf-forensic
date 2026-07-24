# 7. Message-first inference for length-delimited fields, with ambiguity scoring

Date: 2026-07-24
Status: Accepted

## Context

Protobuf wire type 2 (`LEN`) is a length-delimited payload whose *meaning* the
wire format does not record: the same bytes may be a nested message, a UTF-8
string, opaque bytes, or a packed repeated field. A schemaless decoder must
choose an interpretation with no `.proto` to consult. This ambiguity is inherent
— short byte sequences frequently parse as *both* a valid submessage and
printable text (e.g. `hi` = `0x68 0x69` decodes as field 13 = 105;
`(1` = `0x28 0x31` parses as a message and is printable).

The reference schemaless decoder, `protoc --decode_raw`, resolves this
**message-first**: a payload that parses cleanly and consumes exactly its bytes
is rendered as a nested message. Diverging from `protoc` would make the
tier-2 oracle cross-check (ADR 0002, `tests/oracle.rs`) meaningless.

## Decision

Split the concern across the two library layers:

1. **`protobuf-forensic-core` picks a single, `protoc`-compatible
   interpretation** (`LenInterp::Message` / `Text` / `Bytes`), message-first: a
   `LEN` payload that decodes as a well-formed message consuming exactly its
   length is a message; otherwise valid UTF-8 is a string; otherwise opaque
   bytes (`src/lib.rs`, `reader.rs`).
2. **`protobuf-forensic` adds ambiguity scoring on top** rather than overriding
   the choice. Each `LEN` field carries a `confidence` and `notes` naming the
   *other* plausible readings — a message that is also printable text scores
   `MESSAGE_AMBIGUOUS_CONFIDENCE` (0.55) with the text reading in a note; bytes
   that also decode as a packed repeated field score `BYTES_PACKABLE_CONFIDENCE`
   (`src/lib.rs`, `*_CONFIDENCE` constants).

The confidence values are documented heuristics defined by the analyzer's own
tests, not oracle-checked codec values — the legitimate tier-3 zone
(`docs/validation.md`).

## Consequences

- The raw decode stays byte-faithful and directly comparable to
  `protoc --decode_raw`, preserving the independent-oracle validation.
- The examiner is not handed a false certainty: a genuinely ambiguous payload
  surfaces its alternate readings with a score and a note, and the tool says a
  reading is *plausible*, never that it is the truth.
- The scoring is a heuristic; the README and `docs/validation.md` state plainly
  that the notes and confidence are guidance, not a verdict.
