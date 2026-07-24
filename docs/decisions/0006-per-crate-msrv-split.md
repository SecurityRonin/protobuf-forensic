# 6. Per-crate MSRV: low floor for the reader, pinned toolchain for the rest

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`CLAUDE.core.md`, "Rust MSRV & Toolchain Policy";
`CLAUDE.personal.md`, "fleet specifics") sets declared MSRV *by role*, not
uniformly: published libraries keep a low, CI-verified floor as a compatibility
signal and README trust marker; apps declare the pinned dev toolchain, since
nothing pins a library dependency against a binary. Raising a published crate's
floor narrows its crates.io audience, so it is treated as near-breaking.

The reader has no non-`std` dependencies (ADR 0003), so it *can* stay low. The
analyzer depends on `timeglyph`, whose MSRV is 1.96, and the batteries-included
rule (`ronin-issen/CLAUDE.md`) says take the MSRV bump a capability dependency
forces rather than feature-gate the capability away. The CLI is an application.

## Decision

Declare `rust-version` honestly per crate rather than pinning one number
fleet-wide:

- **`protobuf-forensic-core`** — `rust-version = "1.80"`. A deliberately low,
  CI-verified floor, distinct from the dev toolchain, justified by the crate's
  zero dependencies (`Cargo.toml` comment). Raise only when a newer-Rust feature
  is genuinely needed.
- **`protobuf-forensic`** — `rust-version = "1.96"`. Its floor follows the pinned
  toolchain because `timeglyph` (1.96) is a hard dependency; the low floor is not
  contorted to fit.
- **`protobuf4n6`** — `rust-version = "1.96"`. Application crate: declares the
  pinned dev toolchain (`rust-toolchain.toml` channel `1.96.0`), since nothing
  pins a library dependency against it.

## Consequences

- Third parties can link the pure wire decoder on Rust 1.80; the forensic layer
  and CLI require 1.96, and say so.
- The low `1.80` floor is a real guarantee only while the reader stays
  dependency-free — ADR 0003's zero-dependency decision is what keeps it
  honest, and a CI job must verify it.
- Bumping the pinned toolchain moves the analyzer/CLI floor in lockstep; the
  reader floor moves only on a deliberate, separately-justified decision.
