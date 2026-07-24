# 5. Crate naming: `protobuf-core` → `protobuf-forensic-core` (collision-driven)

Date: 2026-07-24
Status: Accepted

## Context

The reader crate was originally scaffolded as `protobuf-core`, following the
fleet's `<x>-core` reader convention. That bare name is already taken on
crates.io: **`protobuf-core` 0.2.2** is a pre-existing, unrelated crate. The
fleet naming grammar (`ronin-issen/CLAUDE.md`, "Crate naming grammar") has an
explicit rule for exactly this case: when `<x>-core` is taken by an unrelated
third party, the reader publishes under the **`<x>-forensic-core`** form —
self-describing on crates.io as "the core of the `<x>-forensic` suite" — with the
import path preserved via `[lib] name`. The precedent is `zfs-forensic-core`
(because `zfs-core` = the `libzfs_core` FFI bindings).

## Decision

Rename the reader crate `protobuf-core` → **`protobuf-forensic-core`**
(commit `ea35016`, "refactor: rename protobuf-core -> protobuf-forensic-core
(crates.io name collision)"). The analyzer stays `protobuf-forensic` and the CLI
`protobuf4n6`. The import path is kept ergonomic via `[lib] name =
"protobuf_forensic_core"` (`protobuf-forensic-core/Cargo.toml`), so consumers
write `use protobuf_forensic_core::…`.

## Consequences

- No crates.io collision at publish; the name is namespaced under the project and
  matches the fleet `*-forensic-core` convention.
- The rename landed before any publish, inside the window where a name is not yet
  claimed, avoiding an orphaned reserved name (fleet "crates.io rename window").
- All dependents (`protobuf-forensic`, `protobuf4n6`, `fuzz/`, `deny.toml`) and
  the `Cargo.lock` were swept to the new name in the same commit; a follow-up
  `rustfmt` pass (`d57bf2b`) and a validation-doc fix for the stale name
  (`c4a7294`) completed the migration.
