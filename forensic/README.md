# protobuf-forensic

Forensic layer over [`protobuf-forensic-core`](https://crates.io/crates/protobuf-forensic-core):
scores ambiguous length-delimited fields (message vs string vs bytes vs packed)
with confidence, and flags integer / fixed64 fields whose value decodes as a
plausible timestamp via [`timeglyph`](https://github.com/SecurityRonin/timeglyph).

Part of [protobuf-forensic](https://github.com/SecurityRonin/protobuf-forensic).
