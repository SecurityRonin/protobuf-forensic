# protobuf-forensic-core

Schemaless Protocol Buffers wire-format decoder for forensics. Decodes raw
protobuf bytes with no `.proto` into a recursive field tree, resolving each
length-delimited payload to a nested message, a UTF-8 string, or raw bytes.
Pure-Rust, `#![forbid(unsafe_code)]`, input-fuzzed, panic-free by lint, dependency-free.

Part of [protobuf-forensic](https://github.com/SecurityRonin/protobuf-forensic).
