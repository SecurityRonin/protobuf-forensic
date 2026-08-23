//! Behavioural tests for the forensic analysis layer.
//!
//! Timestamp expectations are tier-2: the input integer is a known Unix epoch
//! second whose civil rendering is derivable (e.g. `1_600_000_000` → 2020-09-13),
//! cross-checked against timeglyph's own decode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]

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
    put_varint(field << 3, &mut out); // wire type 0 (varint)
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
            .any(|n| n.contains("packed") && n.contains('1')),
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
fn timestamp_readings_are_capped_and_ranked_candidates() {
    // Honest behaviour: a schemaless decoder cannot confirm an integer is a
    // timestamp. Even 150 is "consistent with" recent-epoch formats (Cocoa =
    // 2001-01-01 + 150 s). We surface these as *candidates*, capped at
    // `max_timestamp_candidates` and ranked by score (descending) — the analyst
    // judges by magnitude and context. We do not pretend to suppress them.
    let opts = Options {
        max_timestamp_candidates: 2,
        ..Options::default()
    };
    let a = analyze_with(&varint_field(1, 150), &opts).unwrap();
    let hits = &a.fields[0].timestamps;
    assert!(hits.len() <= 2, "must respect the cap, got {}", hits.len());
    // Ranked by score, descending.
    for pair in hits.windows(2) {
        assert!(pair[0].score >= pair[1].score);
    }
    // Every hit carries a citation and a rendered instant — framed as evidence,
    // not a verdict.
    for hit in hits {
        assert!(!hit.citation.is_empty());
        assert!(!hit.rendered.is_empty());
    }
}

#[test]
fn max_candidates_zero_yields_none() {
    let opts = Options {
        max_timestamp_candidates: 0,
        ..Options::default()
    };
    let a = analyze_with(&varint_field(1, 1_600_000_000), &opts).unwrap();
    assert!(a.fields[0].timestamps.is_empty());
}

#[test]
fn fixed32_unix_second_is_flagged() {
    // field 6, wire 5 (tag 0x35), value 1_600_000_000 little-endian.
    let mut bytes = vec![0x35];
    bytes.extend_from_slice(&1_600_000_000_u32.to_le_bytes());
    let a = analyze(&bytes).unwrap();
    let f = &a.fields[0];
    assert_eq!(f.value, AnalyzedValue::Fixed32(1_600_000_000));
    assert!(
        f.timestamps
            .iter()
            .any(|t| t.source == TimeSource::Fixed32AsInt && t.rendered.starts_with("2020")),
        "expected a Fixed32AsInt 2020 reading, got {:?}",
        f.timestamps
    );
}

#[test]
fn fixed64_double_is_read_as_a_cocoa_time() {
    // A fixed64 holding an IEEE-754 double of ~2021 in Cocoa/CFAbsoluteTime
    // seconds (since 2001). field 7, wire 1 (tag 0x39).
    let cocoa_seconds = 640_000_000.0_f64; // 2001-01-01 + ~20.3 years ≈ 2021.
    let mut bytes = vec![0x39];
    bytes.extend_from_slice(&cocoa_seconds.to_bits().to_le_bytes());
    let a = analyze(&bytes).unwrap();
    let f = &a.fields[0];
    assert_eq!(f.value, AnalyzedValue::Fixed64(cocoa_seconds.to_bits()));
    assert!(
        f.timestamps
            .iter()
            .any(|t| t.source == TimeSource::Fixed64AsFloat),
        "expected the double to be read as a float-based timestamp, got {:?}",
        f.timestamps
    );
}

#[test]
fn packed_fixed32_payload_is_noted() {
    // field 5 LEN with two little-endian i32s (1, 2): not a clean message, not
    // text; the packed fixed32 reading is noted.
    let a = analyze(&[0x2a, 0x08, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]).unwrap();
    let f = &a.fields[0];
    assert!(matches!(f.value, AnalyzedValue::Bytes(_)));
    assert!(
        f.notes.iter().any(|n| n.contains("fixed32")),
        "expected a packed fixed32 note, got {:?}",
        f.notes
    );
}

#[test]
fn malformed_input_errors_not_panics() {
    // Truncated varint value.
    assert!(analyze(&[0x08, 0x80]).is_err());
}
