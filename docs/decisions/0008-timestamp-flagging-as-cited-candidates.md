# 8. Timestamp flagging via timeglyph, as ranked cited candidates — never a verdict

Date: 2026-07-24
Status: Accepted

## Context

Protobuf stores times as bare integers with no type tag: a `varint`, a
`fixed32`, or a `fixed64` (which may itself be an integer *or* an IEEE-754
double) can each hold a timestamp in any of dozens of epoch/format conventions
(Unix seconds, Cocoa/CFAbsoluteTime, exFAT packed, WebKit, …). A schemaless
decoder cannot *know* an integer is a time — and small integers legitimately land
inside recent-epoch windows (150 renders as "Cocoa 2001-01-01 + 150 s"). The
fleet already owns the timestamp decipherer for exactly this problem,
`timeglyph`, and the "prefer our own crates" rule says use it. The forensic
epistemology discipline (`CLAUDE.core.md`, "consistent with, not proves";
`ronin-issen/CLAUDE.md`, findings are observations, never conclusions) forbids
presenting an inference as a fact.

## Decision

Run every integer-bearing field view through `timeglyph` in
`protobuf-forensic/src/timestamps.rs` (varint as signed int; `fixed32`/`fixed64`
as int; `fixed64` also as a double) and attach the results as `TimestampHit`s —
**capped, ranked, and cited**, never as a decoded value on the field:

- Keep only non-sentinel readings at or above a score threshold and cap the
  count (`Options::timestamp_score_threshold`, `max_timestamp_candidates`;
  CLI `--min-score` / `--max-timestamps`).
- Each hit carries the format id, a human label, the rendered civil time, a
  score, a confidence percentage, and a **spec citation** (`TimestampHit`).
- The output wording is *consistent with* / "time?" — the field is flagged as
  plausibly a timestamp, and the judgement is left to the analyst.

## Consequences

- An examiner sees which integer fields could be times, in which formats, ranked
  by plausibility, with a citation to check — without the tool committing to a
  reading it cannot justify schema-blind.
- False positives are inherent (a small integer in a recent-epoch window); the
  design surfaces them as low-scored candidates and lets the analyst filter,
  rather than silently suppressing or confirming (`docs/validation.md`, "Honest
  limitations of the scoring").
- The dependency on `timeglyph` raises the analyzer's MSRV to 1.96 (ADR 0006),
  an accepted cost of the batteries-included capability. `timeglyph` is consumed
  as the published registry crate `0.4`, having dropped an earlier path dependency
  (commit `c978e14`), per the fleet "prefer the published registry crate" rule.
