# 4. `forbid(unsafe)` and panic-free-by-lint across the whole workspace

Date: 2026-07-24
Status: Accepted

## Context

Every crate here touches attacker-influenceable input: the decoder parses raw
evidence bytes, the analyzer walks that decode, and the CLI reads a file, stdin,
or a `--hex` string. The fleet security law (`CLAUDE.core.md`, "Paranoid
Gatekeeper" / "unsafe is an avoidable cost-benefit exception") sets the bar for
such crates: never panic, never read out of bounds, and prefer a *provable*
`forbid(unsafe)` over `deny + allow`. `forbid(unsafe)` is only downgraded to
`deny` when a real benefit — e.g. an `mmap` reader (ewf) — justifies a bounded
`unsafe` site. This decoder does purely in-memory, index-checked slice work; it
needs no `mmap` and no FFI, so nothing justifies a downgrade.

## Decision

Set the strictest posture workspace-wide in `Cargo.toml`
(`[workspace.lints]`), inherited by every member via `[lints] workspace = true`:

- `unsafe_code = "forbid"` — no `unsafe` anywhere, unconditionally. Each crate's
  `lib.rs`/`main.rs` also carries `#![forbid(unsafe_code)]`.
- `clippy::correctness` / `suspicious = "deny"`, `all` / `pedantic = "warn"`.
- `clippy::unwrap_used` / `expect_used = "deny"` in production, with
  `allow-unwrap-in-tests`/`allow-expect-in-tests` in `clippy.toml` so tests may
  unwrap to fail loudly.

Empirical robustness is proven, not merely asserted: two `cargo-fuzz` "must not
panic" targets (`fuzz/fuzz_targets/decode.rs`, `analyze.rs`) exercise the
decoder and the full forensic walk (`docs/validation.md` records 1.82 M / 0.21 M
local executions with no crash and bounded RSS).

## Consequences

- The crate earns the `unsafe forbidden` badge honestly (`README.md`), and the
  README leads with the *measured* claim ("input-fuzzed") beside the *static*
  one ("panic-free by lint") per the fleet robustness-wording rule — never a bare
  "panic-free" absolute.
- A truncated/overlong varint, a lying length, an invalid wire type, or a
  depth-bomb yields an `Err`, never a panic or an over-allocation.
- `unwrap_used`/`expect_used = deny` forces every fallible read to be handled;
  the cost is more explicit `Result` plumbing, accepted as the price of the
  no-panic guarantee.
