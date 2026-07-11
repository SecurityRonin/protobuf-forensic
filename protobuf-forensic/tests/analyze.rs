//! Behavioural tests for the forensic analysis layer.
//!
//! Timestamp expectations are tier-2: the input integer is a known Unix epoch
//! second whose civil rendering is derivable (e.g. 1_600_000_000 → 2020-09-13),
//! cross-checked against timeglyph's own decode.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use protobuf_forensic::{analyze, analyze_with, AnalyzedValue, Options, TimeSource};

/// Encode a varint into `out` (test helper).
fn put_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// `field << 3 | wire` then a varint value.
fn varint_field(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint((field << 3) | 0, &mut out);
    put_varint(value, &mut out);
    out
}

#[test]
fn scalar_varint_is_unambiguous() {
    let a = analyze(&varint_field(1, 150)).unwrap();
    assert_eq!(a.fields.len(), 1);
    let f = &a.fields[0];
    assert_eq!(f.path, "1");
    assert_eq!(f.number, 1);
    assert_eq!(f.value, AnalyzedValue::Varint(150));
    assert_eq!(f.confidence, 1.0);
    assert!(f.notes.is_empty());
}

#[test]
fn nested_message_has_dotted_paths() {
    // field 3 = { field 1 = 150 } → `1a 03 08 96 01`.
    let a = analyze(&[0x1a, 0x03, 0x08, 0x96, 0x01]).unwrap();
    let outer = &a.fields[0];
    assert_eq!(outer.path, "3");
    match &outer.value {
        AnalyzedValue::Message(inner) => {
            assert_eq!(inner.len(), 1);
            assert_eq!(inner[0].path, "3.1");
            assert_eq!(inner[0].value, AnalyzedValue::Varint(150));
        }
        other => panic!("expected Message, got {other:?}"),
    }
    // A clean, non-printable message payload is high-confidence, no text note.
    assert!((outer.confidence - protobuf_forensic::MESSAGE_CONFIDENCE).abs() < 1e-9);
}

#[test]
fn ambiguous_message_that_is_also_text_is_flagged() {
    // LEN payload "(1" = [0x28, 0x31] parses as field 5 = varint 49 AND is
    // printable ASCII. field 2 LEN → `12 02 28 31`.
    let a = analyze(&[0x12, 0x02, 0x28, 0x31]).unwrap();
    let f = &a.fields[0];
    assert!(matches!(f.value, AnalyzedValue::Message(_)));
    assert!((f.confidence - protobuf_forensic::MESSAGE_AMBIGUOUS_CONFIDENCE).abs() < 1e-9);
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("text") && n.contains("(1")),
        "expected a note naming the text alternative, got {:?}",
        f.notes
    );
}

#[test]
fn printable_string_is_text_high_confidence() {
    // field 2 = "testing".
    let bytes = [0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g'];
    let a = analyze(&bytes).unwrap();
    let f = &a.fields[0];
    assert_eq!(f.value, AnalyzedValue::Text("testing".to_string()));
    assert!((f.confidence - protobuf_forensic::TEXT_CONFIDENCE).abs() < 1e-9);
}

#[test]
fn opaque_bytes_with_packed_reading_is_noted() {
    // field 5 packed {1,2,3} → `2a 03 01 02 03`: resolves to Bytes, packed
    // varints [1,2,3] are noted with reduced confidence.
    let a = analyze(&[0x2a, 0x03, 0x01, 0x02, 0x03]).unwrap();
    let f = &a.fields[0];
    assert!(matches!(f.value, AnalyzedValue::Bytes(_)));
    assert!((f.confidence - protobuf_forensic::BYTES_PACKABLE_CONFIDENCE).abs() < 1e-9);
    assert!(
        f.notes
            .iter()
            .any(|n| n.contains("packed") && n.contains("1")),
        "expected a packed note, got {:?}",
        f.notes
    );
}

#[test]
fn unix_timestamp_varint_is_flagged() {
    // 1_600_000_000 = 2020-09-13T12:26:40Z (Unix seconds).
    let a = analyze(&varint_field(1, 1_600_000_000)).unwrap();
    let f = &a.fields[0];
    assert!(
        !f.timestamps.is_empty(),
        "a plausible Unix second should be flagged as a timestamp candidate"
    );
    assert!(
        f.timestamps
            .iter()
            .any(|t| t.rendered.starts_with("2020") && t.source == TimeSource::Varint),
        "expected a 2020 reading, got {:?}",
        f.timestamps
    );
    // Confidence percentage tracks the score.
    let top = &f.timestamps[0];
    assert_eq!(
        top.confidence_pct,
        (top.score.clamp(0.0, 1.0) * 100.0).round() as u8
    );
}

#[test]
fn small_integer_is_not_over_flagged_as_timestamp() {
    // 150 seconds after the epoch (1970) is not a plausible modern timestamp; it
    // must not be reported above the default threshold.
    let a = analyze(&varint_field(1, 150)).unwrap();
    assert!(
        a.fields[0].timestamps.is_empty(),
        "150 should not be flagged as a timestamp at the default threshold, got {:?}",
        a.fields[0].timestamps
    );
}

#[test]
fn threshold_zero_surfaces_more_candidates() {
    // Lowering the threshold surfaces more (weaker) readings — proves the knob
    // works and that filtering is what suppresses them by default.
    let opts = Options {
        timestamp_score_threshold: 0.0,
        max_timestamp_candidates: 10,
        ..Options::default()
    };
    let a = analyze_with(&varint_field(1, 150), &opts).unwrap();
    assert!(!a.fields[0].timestamps.is_empty());
}

#[test]
fn malformed_input_errors_not_panics() {
    // Truncated varint value.
    assert!(analyze(&[0x08, 0x80]).is_err());
}
