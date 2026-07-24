# 3. Zero-dependency, hand-rolled bounds-checked reader in the core crate

Date: 2026-07-24
Status: Accepted

## Context

The fleet default for reading integer fields out of untrusted images is the
published `safe-read` crate: `CLAUDE.core.md` / `ronin-issen/CLAUDE.md` ("Paranoid
Gatekeeper") say route fixed-width reads through `safe-read` and **never hand-roll
a per-crate `bytes.rs`**, because hand-rolled copies drift and some naive
`data.get(off..off+4)` variants can overflow `usize`.

`safe-read` covers *fixed-width integer fields only*. The protobuf wire format is
dominated by **variable-length LEB128 varints**, which `safe-read` does not
decode; only the `fixed32` / `fixed64` scalars are fixed-width. Pulling `safe-read`
would therefore cover a minority of the reads while adding the core crate's *only*
dependency, costing the "zero dependencies" property that
`protobuf-forensic-core` advertises (`README.md`, "Three crates";
`Cargo.toml` — no `[dependencies]` table) and complicating its deliberately low
`rust-version = "1.80"` floor (ADR 0006).

## Decision

Keep `protobuf-forensic-core` **zero-dependency** and implement a small,
self-contained bounds-checked forward cursor in-crate
(`protobuf-forensic-core/src/reader.rs`, `struct Cursor`). Every read is
length-checked before it happens — `read_varint` rejects truncated/overlong
varints, `take`/`take_len` reject a length that exceeds the bytes remaining, and
the fixed reads (`read_u32_le`/`read_u64_le`) index only after a checked `take`.
Recursion is depth-capped (`DEFAULT_MAX_DEPTH = 100`) so a depth-bomb degrades to
`LenInterp::Bytes` instead of overflowing the stack.

This consciously forgoes the `safe-read` default for this one crate, on the
grounds that a varint-centric ~40-line reader gains little from a fixed-width
integer helper and the zero-dependency + low-MSRV posture is worth preserving.

## Consequences

- `protobuf-forensic-core` stays dependency-free and buildable on Rust 1.80,
  a genuine compatibility signal for third-party reuse.
- The robustness guarantee the fleet standard exists to protect is met a
  different way: the cursor is exhaustively exercised by tier-3 property tests
  (`tests/wire.rs`: truncated/overlong varints, lying lengths, invalid wire
  types, unbalanced groups, a 200-deep depth bomb) and a `cargo-fuzz` "must not
  panic" target.
- The deviation is narrow and annotated here; it is not a licence to hand-roll
  byte readers elsewhere in the fleet, where fixed-width image parsing must still
  route through `safe-read`.
