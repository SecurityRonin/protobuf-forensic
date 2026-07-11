//! Tier-2 cross-validation against `protoc` (env-gated).
//!
//! An independent third-party engine both *produces* and *checks* the data:
//! `protoc --encode` turns a text message + `.proto` into real wire bytes, and
//! `protoc --decode_raw` is the reference schemaless decoder. We assert our
//! schemaless decode agrees with `--decode_raw` on the field structure. The
//! ground truth is the documented `.proto` construction, not a fixture we
//! authored — so this is tier-2, not a self-referential round-trip.
//!
//! Skips cleanly (does not fail) when `protoc` is not installed, so CI without
//! `protoc` still passes. Set `PROTOC` to override the binary path.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use protobuf_core::{decode, Field, FieldValue, LenInterp};

fn protoc() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PROTOC") {
        return Some(PathBuf::from(p));
    }
    let out = Command::new("protoc").arg("--version").output().ok()?;
    out.status.success().then(|| PathBuf::from("protoc"))
}

const PROTO: &str = r#"
syntax = "proto3";
message Inner { int64 a = 1; }
message Test {
  int64 id = 1;
  string name = 2;
  Inner inner = 3;
  bytes blob = 4;
  repeated int32 nums = 5;
  fixed32 f32 = 6;
  fixed64 f64 = 7;
}
"#;

// Text-format message. `blob` carries non-UTF-8 bytes; `nums` is packed in proto3.
const MESSAGE: &str = r#"
id: 150
name: "testing"
inner { a: 150 }
blob: "\377\376"
nums: 1
nums: 2
nums: 3
f32: 305419896
f64: 72623859790382856
"#;

/// Encode `MESSAGE` to wire bytes with `protoc --encode`.
fn encode(protoc: &PathBuf, dir: &std::path::Path) -> Vec<u8> {
    let proto_path = dir.join("test.proto");
    std::fs::write(&proto_path, PROTO).unwrap();

    let mut child = Command::new(protoc)
        .arg(format!("-I{}", dir.display()))
        .arg("--encode=Test")
        .arg(&proto_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(MESSAGE.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "protoc --encode failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// `protoc --decode_raw` reference decode → its text output.
fn decode_raw(protoc: &PathBuf, bytes: &[u8]) -> String {
    let mut child = Command::new(protoc)
        .arg("--decode_raw")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

/// Top-level field numbers from `--decode_raw` text: a line with no leading
/// whitespace beginning `<number>:` (scalar/len) or `<number> {` (message).
fn protoc_top_level_numbers(text: &str) -> BTreeMap<u64, usize> {
    let mut counts = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let head: String = line.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = head.parse::<u64>() {
            *counts.entry(n).or_insert(0) += 1;
        }
    }
    counts
}

fn our_top_level_numbers(fields: &[Field]) -> BTreeMap<u64, usize> {
    let mut counts = BTreeMap::new();
    for f in fields {
        *counts.entry(f.number).or_insert(0) += 1;
    }
    counts
}

#[test]
fn field_structure_agrees_with_protoc_decode_raw() {
    let Some(protoc) = protoc() else {
        eprintln!("skipping: protoc not found (set PROTOC to enable)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pb4n6_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = encode(&protoc, &dir);
    let _ = std::fs::remove_dir_all(&dir);

    let ours = decode(&bytes).expect("our decoder handles protoc-encoded bytes");
    let raw = decode_raw(&protoc, &bytes);

    // Same top-level field numbers, same multiplicity.
    assert_eq!(
        our_top_level_numbers(&ours),
        protoc_top_level_numbers(&raw),
        "field-number multiset mismatch.\nprotoc:\n{raw}"
    );

    // Field-by-field kind agreement for the discriminating cases.
    let by_num: BTreeMap<u64, &FieldValue> = ours.iter().map(|f| (f.number, &f.value)).collect();

    // 1: int64 150 → varint.
    assert_eq!(by_num[&1], &FieldValue::Varint(150));
    // 2: string "testing" → Text (protoc renders `2: "testing"`).
    assert!(
        matches!(by_num[&2], FieldValue::Len(l) if l.interp == LenInterp::Text("testing".into()))
    );
    assert!(raw.contains("2: \"testing\""));
    // 3: submessage → Message (protoc renders `3 {`).
    assert!(matches!(by_num[&3], FieldValue::Len(l) if matches!(l.interp, LenInterp::Message(_))));
    assert!(raw.contains("3 {"));
    // 4: non-UTF-8 bytes → Bytes.
    assert!(matches!(by_num[&4], FieldValue::Len(l) if l.interp == LenInterp::Bytes));
    // 5: packed int32 → LEN; the packed varints must recover [1,2,3].
    assert!(
        matches!(by_num[&5], FieldValue::Len(l) if l.as_packed_varints() == Some(vec![1, 2, 3]))
    );
    // 6/7: fixed widths.
    assert_eq!(by_num[&6], &FieldValue::I32(305_419_896));
    assert_eq!(by_num[&7], &FieldValue::I64(72_623_859_790_382_856));
}
