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
