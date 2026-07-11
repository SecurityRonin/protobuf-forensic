//! Behavioural tests for the `protobuf4n6` CLI library half.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use protobuf4n6::{parse_hex, run, AnalysisOptions, Format};

fn render(bytes: &[u8], format: Format) -> String {
    let mut out = Vec::new();
    run(bytes, format, &AnalysisOptions::default(), &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn parse_hex_plain() {
    assert_eq!(parse_hex("089601").unwrap(), vec![0x08, 0x96, 0x01]);
}

#[test]
fn parse_hex_tolerates_prefix_whitespace_and_separators() {
    assert_eq!(parse_hex("0x08 96 01").unwrap(), vec![0x08, 0x96, 0x01]);
    assert_eq!(parse_hex("08:96:01").unwrap(), vec![0x08, 0x96, 0x01]);
    assert_eq!(parse_hex("08-96-01").unwrap(), vec![0x08, 0x96, 0x01]);
}

#[test]
fn parse_hex_rejects_odd_length() {
    assert!(parse_hex("089").is_err());
}

#[test]
fn parse_hex_rejects_and_names_bad_character() {
    let err = parse_hex("08zz").unwrap_err();
    // The message names the offending character so the user can locate it.
    assert!(format!("{err}").contains('z'), "got: {err}");
}

#[test]
fn text_renders_field_and_value() {
    // field 1 = 150.
    let out = render(&[0x08, 0x96, 0x01], Format::Text);
    assert!(out.contains('1'), "should name the field number");
    assert!(out.contains("150"), "should render the value; got:\n{out}");
}

#[test]
fn text_shows_nested_paths() {
    // field 3 = { field 1 = 150 }.
    let out = render(&[0x1a, 0x03, 0x08, 0x96, 0x01], Format::Text);
    assert!(
        out.contains("3.1"),
        "should show the nested path; got:\n{out}"
    );
}

#[test]
fn jsonl_lines_are_valid_json_and_path_addressed() {
    // field 3 = { field 1 = 150 }: pre-order emits a line for path "3" then "3.1".
    let out = render(&[0x1a, 0x03, 0x08, 0x96, 0x01], Format::Jsonl);
    let paths: Vec<String> = out
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("each line is valid JSON");
            v["path"].as_str().unwrap().to_string()
        })
        .collect();
    assert!(paths.contains(&"3".to_string()));
    assert!(paths.contains(&"3.1".to_string()));
}

#[test]
fn jsonl_carries_varint_value() {
    let out = render(&[0x08, 0x96, 0x01], Format::Jsonl);
    let line = out.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["path"], "1");
    assert_eq!(v["value"], 150);
}

#[test]
fn protoscope_like_format() {
    let out = render(&[0x08, 0x96, 0x01], Format::Protoscope);
    assert!(out.contains("1: 150"), "got:\n{out}");
}

#[test]
fn protoscope_nests_submessages_in_braces() {
    let out = render(&[0x1a, 0x03, 0x08, 0x96, 0x01], Format::Protoscope);
    assert!(out.contains('{') && out.contains('}'), "got:\n{out}");
    assert!(
        out.contains("1: 150"),
        "inner field should render; got:\n{out}"
    );
}

#[test]
fn text_renders_string_field() {
    let bytes = [0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g'];
    let out = render(&bytes, Format::Text);
    assert!(out.contains("testing"), "got:\n{out}");
}

#[test]
fn run_propagates_decode_error() {
    let mut out = Vec::new();
    let err = run(
        &[0x08, 0x80],
        Format::Text,
        &AnalysisOptions::default(),
        &mut out,
    );
    assert!(err.is_err());
}

#[test]
fn text_flags_a_timestamp_field() {
    // field 6 fixed32 = 1_600_000_000 (2020) → a "time?" line is rendered.
    let mut bytes = vec![0x35];
    bytes.extend_from_slice(&1_600_000_000_u32.to_le_bytes());
    let out = render(&bytes, Format::Text);
    assert!(
        out.contains("time?"),
        "expected a timestamp line; got:\n{out}"
    );
    assert!(out.contains("fixed32"));
}

#[test]
fn jsonl_bytes_field_carries_hex_and_kind() {
    // field 5 packed {1,2,3} resolves to bytes.
    let out = render(&[0x2a, 0x03, 0x01, 0x02, 0x03], Format::Jsonl);
    let line = out.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["kind"], "bytes");
    assert_eq!(v["hex"], "010203");
    assert!(v["notes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n.as_str().unwrap().contains("packed")));
}

#[test]
fn jsonl_carries_timestamp_candidates() {
    let mut bytes = vec![0x35];
    bytes.extend_from_slice(&1_600_000_000_u32.to_le_bytes());
    let out = render(&bytes, Format::Jsonl);
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let ts = v["timestamps"].as_array().unwrap();
    assert!(!ts.is_empty());
    assert!(
        ts.iter()
            .any(|t| t["rendered"].as_str().unwrap().starts_with("2020")),
        "expected a 2020 candidate among {ts:?}"
    );
    assert!(ts
        .iter()
        .all(|t| t["source"].as_str().unwrap().contains("fixed32")));
}

#[test]
fn protoscope_renders_fixed_and_bytes() {
    // fixed32 + a bytes payload in one blob.
    let mut bytes = vec![0x35];
    bytes.extend_from_slice(&7_u32.to_le_bytes()); // field 6 fixed32 = 7
    bytes.extend_from_slice(&[0x22, 0x02, 0xff, 0xfe]); // field 4 bytes ff fe
    let out = render(&bytes, Format::Protoscope);
    assert!(out.contains("6: 7i32"), "got:\n{out}");
    assert!(out.contains("4: {`fffe`}"), "got:\n{out}");
}

#[test]
fn renders_string_bytes_note_and_float_time_in_all_formats() {
    // field 2 string "testing" (does not parse as a message, unlike "hi");
    // field 5 packed bytes {1,2,3} (a note); field 7 fixed64 holding a
    // Cocoa/CFAbsoluteTime double (~2021, a float timestamp).
    let mut bytes = vec![
        0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g', // field 2 = "testing"
        0x2a, 0x03, 0x01, 0x02, 0x03, // field 5 packed {1,2,3}
        0x39, // field 7 fixed64
    ];
    bytes.extend_from_slice(&640_000_000.0_f64.to_bits().to_le_bytes());

    let text = render(&bytes, Format::Text);
    assert!(text.contains("string \"testing\""), "got:\n{text}");
    assert!(text.contains("bytes["), "got:\n{text}");
    assert!(text.contains("note:"), "packed note; got:\n{text}");
    assert!(
        text.contains("via fixed64:double"),
        "float-source timestamp; got:\n{text}"
    );

    let jsonl = render(&bytes, Format::Jsonl);
    assert!(jsonl
        .lines()
        .any(|l| { serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"] == "string" }));

    let proto = render(&bytes, Format::Protoscope);
    assert!(proto.contains("2: {\"testing\"}"), "got:\n{proto}");
}

/// field 7 fixed64 = 1, then field 8 group { field 2 = 150 }.
const FIXED64_AND_GROUP: &[u8] = &[
    0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // field 7 fixed64 = 1
    0x43, 0x10, 0x96, 0x01, 0x44, // field 8 group { field 2 = 150 }
];

#[test]
fn text_renders_fixed64_and_group() {
    let out = render(FIXED64_AND_GROUP, Format::Text);
    assert!(out.contains("fixed64"), "got:\n{out}");
    assert!(out.contains("group"), "got:\n{out}");
    assert!(
        out.contains("sgroup"),
        "group field wire label; got:\n{out}"
    );
    assert!(out.contains("8.2"), "nested group path; got:\n{out}");
}

#[test]
fn jsonl_renders_fixed64_and_group() {
    let out = render(FIXED64_AND_GROUP, Format::Jsonl);
    let kinds: Vec<String> = out
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(kinds.contains(&"fixed64".to_string()));
    assert!(kinds.contains(&"group".to_string()));
}

#[test]
fn protoscope_renders_fixed64_and_group() {
    let out = render(FIXED64_AND_GROUP, Format::Protoscope);
    assert!(out.contains("7: 1i64"), "got:\n{out}");
    assert!(out.contains("8: {"), "group as braces; got:\n{out}");
    assert!(out.contains("2: 150"), "inner group field; got:\n{out}");
}

// ---- binary shell (covers `main` / input selection) -----------------------

fn bin() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_protobuf4n6"))
}

#[test]
fn binary_decodes_hex_and_exits_success() {
    let out = bin().args(["--hex", "089601"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("150"));
}

#[test]
fn binary_decodes_a_file() {
    let path = std::env::temp_dir().join(format!("pb4n6_{}.bin", std::process::id()));
    std::fs::write(&path, [0x08, 0x96, 0x01]).unwrap();
    let out = bin().arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("150"));
}

#[test]
fn binary_reads_stdin() {
    use std::io::Write as _;
    let mut child = bin()
        .args(["--format", "protoscope"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[0x08, 0x96, 0x01])
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("1: 150"));
}

#[test]
fn binary_missing_file_is_a_loud_failure() {
    let out = bin().arg("/no/such/protobuf/file").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("protobuf4n6:"));
}

#[test]
fn binary_bad_hex_is_a_loud_failure() {
    let out = bin().args(["--hex", "08zz"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid hex"));
}

#[test]
fn binary_malformed_protobuf_is_a_loud_failure() {
    let out = bin().args(["--hex", "0880"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("protobuf4n6:"));
}
