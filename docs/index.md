# protobuf-forensic

**Decode a Protocol Buffers blob with no `.proto` schema — walk the raw wire format into a field tree and flag the values that look like timestamps.**

```rust
// Field 1 = varint 150, nested message in field 3.
let bytes = [0x08, 0x96, 0x01, 0x1a, 0x03, 0x08, 0x96, 0x01];
let fields = protobuf_core::decode(&bytes)?;
for f in &fields {
    println!("field {} wire {:?}", f.number, f.wire_type);
}
# Ok::<(), protobuf_core::Error>(())
```

In forensics you almost never have the `.proto`. Schema-driven decoders
(`prost`, `rust-protobuf`) cannot help. protobuf-forensic decodes the wire
format blind, the way `protoc --decode_raw` and Google's protoscope do, and adds
a forensic layer that scores ambiguous length-delimited fields and runs integer
values through [`timeglyph`](https://github.com/SecurityRonin/timeglyph) to
surface embedded timestamps.

**[GitHub Repository →](https://github.com/SecurityRonin/protobuf-forensic)**
