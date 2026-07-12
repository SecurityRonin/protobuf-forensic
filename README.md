[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/protobuf-forensic/)
[![CI](https://github.com/SecurityRonin/protobuf-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/protobuf-forensic/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# protobuf-forensic

**You have a Protocol Buffers blob and no `.proto`. Decode it anyway — the wire
format into a field tree, with the values that look like timestamps flagged.**

In forensics you almost never have the schema. `prost` and `rust-protobuf` are
schema-*driven* and cannot help. protobuf-forensic decodes the wire format
**blind**, the way `protoc --decode_raw` and Google's protoscope do, and adds a
forensic layer on top.

## See it in 30 seconds

```console
$ protobuf4n6 --hex 0880a0f8fa05120a73657373696f6e2e64621a03089601
1 [field 1 varint] varint 1600000000
    time? 2027-10-30T02:00:00Z  exFAT packed timestamp (LOCAL time) (exfat, 100%, via varint)
    time? 2020-09-13T12:26:40Z  Unix time (seconds) (unix, 100%, via varint)
2 [field 2 len] string "session.db"
    conf 0.90
3 [field 3 len] message (1 field(s))
  3.1 [field 1 varint] varint 150
```

*(representative timestamp rows shown; values verbatim.)* No schema, no config:
field 1 is decoded as a varint and its value flagged as **consistent with**
several timestamp formats (Unix seconds -> 2020-09-13); field 2's length-delimited
payload is inferred to be the string `session.db`; field 3 is resolved to a
nested message and walked recursively with a dotted path (`3.1`).

Read from a file or stdin, and pick the output your pipeline wants:

```console
$ protobuf4n6 record.bin --format protoscope     # protoscope-like
$ protobuf4n6 record.bin --format jsonl          # one JSON object per field
$ cat record.bin | protobuf4n6 --format text     # from stdin
```

Install (from source, until published):

```console
$ cargo install --path protobuf4n6
```

## Why not just decode with a protobuf library?

`prost` / `rust-protobuf` need the `.proto` to generate types. Forensics rarely
has it — the blob comes out of a LevelDB value, an app cache, a memory dump. This
tool decodes the wire format directly:

- **Every field** — `tag = (field_number << 3) | wire_type`; wire type 0 varint,
  1 fixed64, 2 length-delimited, 5 fixed32, plus the deprecated groups.
- **Length-delimited inference** — a `LEN` payload is resolved to a nested
  **message** (parses cleanly and consumes exactly its bytes), a UTF-8 **string**,
  or opaque **bytes** — message-first, matching `protoc --decode_raw`. Ambiguous
  payloads (a message that is also printable, or bytes that also decode as a
  packed repeated field) are flagged with a confidence and a note.
- **Timestamp flagging** — every integer / fixed field is run through
  [`timeglyph`](https://github.com/SecurityRonin/timeglyph); plausible readings
  are surfaced as scored, cited **candidates** — never a verdict.

## Three crates

- **`protobuf-forensic-core`** — the schemaless wire decoder. `decode(&[u8]) -> Vec<Field>`.
  `#![forbid(unsafe_code)]`, panic-free, **zero dependencies**, low MSRV.
- **`protobuf-forensic`** — the analysis layer: ambiguity scoring + timeglyph
  timestamp flagging.
- **`protobuf4n6`** — the CLI (text / JSONL / protoscope).

## Trust, but verify

`protobuf-forensic-core` is validated against an **independent oracle**: `protoc --encode`
produces real wire bytes from a `.proto`, and `protoc --decode_raw` (the
reference schemaless decoder) is cross-checked field-by-field against our decode.
See [`docs/validation.md`](https://securityronin.github.io/protobuf-forensic/validation/).

Every read is bounds-checked and panic-free by lint
(`clippy::unwrap_used`/`expect_used = deny`): a truncated or overlong varint, a
lying length, or a depth-bomb yields an `Err`, never a panic or an
over-allocation. Both parsers have a `cargo-fuzz` "must not panic" target. The
workspace enforces 100 % function coverage.

The forensic layer is **honest by construction**: timestamp readings are ranked,
capped candidates carrying a score and a spec citation — the tool says a value is
*consistent with* a format, and leaves the conclusion to the analyst.

---

[Privacy Policy](https://securityronin.github.io/protobuf-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/protobuf-forensic/terms/) · © 2026 Security Ronin Ltd
