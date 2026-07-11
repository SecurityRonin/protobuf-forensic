//! Behavioural tests for the schemaless wire decoder.
//!
//! Byte sequences are taken from the protobuf encoding spec's worked examples
//! (<https://protobuf.dev/programming-guides/encoding/>) so the expected tree is
//! derivable from the documented construction (tier-2), not invented.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use protobuf_core::{
    decode, decode_with_limits, zigzag_decode, Error, FieldValue, LenInterp, Limits, WireType,
};

#[test]
fn empty_input_is_an_empty_message() {
    assert_eq!(decode(&[]).unwrap(), vec![]);
}

#[test]
fn single_varint_field_150() {
    // Spec's first example: field 1 = 150 → `08 96 01`.
    let fields = decode(&[0x08, 0x96, 0x01]).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].number, 1);
    assert_eq!(fields[0].wire_type, WireType::Varint);
    assert_eq!(fields[0].value, FieldValue::Varint(150));
}

#[test]
fn string_field_is_resolved_as_text() {
    // field 2 = "testing" → `12 07 74 65 73 74 69 6e 67`.
    let bytes = [0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g'];
    let fields = decode(&bytes).unwrap();
    assert_eq!(fields[0].number, 2);
    assert_eq!(fields[0].wire_type, WireType::Len);
    match &fields[0].value {
        FieldValue::Len(len) => {
            assert_eq!(len.interp, LenInterp::Text("testing".to_string()));
            assert_eq!(len.raw, b"testing");
        }
        other => panic!("expected Len, got {other:?}"),
    }
}

#[test]
fn submessage_is_resolved_as_nested_message() {
    // field 3 = { field 1 = 150 } → `1a 03 08 96 01`.
    let fields = decode(&[0x1a, 0x03, 0x08, 0x96, 0x01]).unwrap();
    assert_eq!(fields[0].number, 3);
    match &fields[0].value {
        FieldValue::Len(len) => match &len.interp {
            LenInterp::Message(inner) => {
                assert_eq!(inner.len(), 1);
                assert_eq!(inner[0].number, 1);
                assert_eq!(inner[0].value, FieldValue::Varint(150));
            }
            other => panic!("expected Message, got {other:?}"),
        },
        other => panic!("expected Len, got {other:?}"),
    }
}

#[test]
fn non_utf8_len_payload_is_bytes() {
    // field 4 = { 0xff, 0xfe } → `22 02 ff fe`. Not a valid message, not UTF-8.
    let fields = decode(&[0x22, 0x02, 0xff, 0xfe]).unwrap();
    match &fields[0].value {
        FieldValue::Len(len) => {
            assert_eq!(len.interp, LenInterp::Bytes);
            assert_eq!(len.raw, vec![0xff, 0xfe]);
        }
        other => panic!("expected Len bytes, got {other:?}"),
    }
}

#[test]
fn fixed32_field() {
    // field 6, wire 5 → tag 0x35; value 0x1234_5678 little-endian.
    let fields = decode(&[0x35, 0x78, 0x56, 0x34, 0x12]).unwrap();
    assert_eq!(fields[0].number, 6);
    assert_eq!(fields[0].wire_type, WireType::I32);
    assert_eq!(fields[0].value, FieldValue::I32(0x1234_5678));
}

#[test]
fn fixed64_field() {
    // field 7, wire 1 → tag 0x39; value 0x0102_0304_0506_0708 little-endian.
    let fields = decode(&[0x39, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]).unwrap();
    assert_eq!(fields[0].number, 7);
    assert_eq!(fields[0].wire_type, WireType::I64);
    assert_eq!(fields[0].value, FieldValue::I64(0x0102_0304_0506_0708));
}

#[test]
fn packed_repeated_varints_surface_via_helper() {
    // Spec: field 5 = {1 2 3} packed → `2a 03 01 02 03`. The payload 01 02 03 is
    // not a clean message (tag 0x01 → field 0) and not printable text, so it
    // resolves to Bytes; the packed reading is offered as a candidate.
    let fields = decode(&[0x2a, 0x03, 0x01, 0x02, 0x03]).unwrap();
    match &fields[0].value {
        FieldValue::Len(len) => {
            assert_eq!(len.interp, LenInterp::Bytes);
            assert_eq!(len.as_packed_varints(), Some(vec![1, 2, 3]));
        }
        other => panic!("expected Len, got {other:?}"),
    }
}

#[test]
fn packed_fixed32_helper() {
    // Two i32 values 1 and 2, little-endian: 8 bytes.
    let fields = decode(&[0x2a, 0x08, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]).unwrap();
    match &fields[0].value {
        FieldValue::Len(len) => assert_eq!(len.as_packed_i32(), Some(vec![1, 2])),
        other => panic!("expected Len, got {other:?}"),
    }
}

#[test]
fn packed_fixed64_helper() {
    // One i64 value 1, little-endian: 8 bytes → packed-i64 candidate.
    let fields = decode(&[0x2a, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    match &fields[0].value {
        FieldValue::Len(len) => assert_eq!(len.as_packed_i64(), Some(vec![1])),
        other => panic!("expected Len, got {other:?}"),
    }
}

#[test]
fn multiple_fields_in_order() {
    // field 1 = 150, then field 2 = "hi".
    let bytes = [0x08, 0x96, 0x01, 0x12, 0x02, b'h', b'i'];
    let fields = decode(&bytes).unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].number, 1);
    assert_eq!(fields[1].number, 2);
}

#[test]
fn group_is_decoded_into_inner_fields() {
    // field 1 SGROUP (tag 0x0b), inner field 2 = 150 (08? no: field2 varint tag
    // 0x10, value 0x96 0x01), then EGROUP for field 1 (tag 0x0c).
    let bytes = [0x0b, 0x10, 0x96, 0x01, 0x0c];
    let fields = decode(&bytes).unwrap();
    assert_eq!(fields[0].number, 1);
    assert_eq!(fields[0].wire_type, WireType::StartGroup);
    match &fields[0].value {
        FieldValue::Group(inner) => {
            assert_eq!(inner.len(), 1);
            assert_eq!(inner[0].number, 2);
            assert_eq!(inner[0].value, FieldValue::Varint(150));
        }
        other => panic!("expected Group, got {other:?}"),
    }
}

// ---- adversarial / robustness (tier-3 property tests) --------------------

#[test]
fn truncated_varint_errors() {
    // tag says field 1 varint, but the value varint never terminates.
    assert!(matches!(
        decode(&[0x08, 0x80]),
        Err(Error::TruncatedVarint { .. })
    ));
}

#[test]
fn overlong_varint_errors() {
    // tag 0x08 then ten continuation bytes → a varint longer than 10 bytes.
    let mut bytes = vec![0x08];
    bytes.extend_from_slice(&[0x80; 10]);
    assert!(matches!(decode(&bytes), Err(Error::OverlongVarint { .. })));
}

#[test]
fn length_exceeding_buffer_errors() {
    // field 2 LEN claims 5 bytes but only 2 follow.
    assert!(matches!(
        decode(&[0x12, 0x05, 0x61, 0x62]),
        Err(Error::LengthOutOfRange {
            value: 5,
            available: 2,
            ..
        })
    ));
}

#[test]
fn invalid_wire_type_errors() {
    // tag with wire type 6 (0b110): 0x0e = field 1, wire 6.
    assert!(matches!(
        decode(&[0x0e]),
        Err(Error::InvalidWireType { value: 6, .. })
    ));
}

#[test]
fn field_number_zero_errors() {
    // tag 0x00 → field 0, wire 0. Field 0 is never valid.
    assert!(matches!(
        decode(&[0x00, 0x00]),
        Err(Error::InvalidFieldNumber { value: 0, .. })
    ));
}

#[test]
fn unbalanced_group_end_errors() {
    // A bare EGROUP (tag 0x0c) with no open group.
    assert!(matches!(
        decode(&[0x0c]),
        Err(Error::UnexpectedEndGroup { field: 1, .. })
    ));
}

#[test]
fn unterminated_group_errors() {
    // SGROUP for field 1 (0x0b) then EOF.
    assert!(matches!(
        decode(&[0x0b]),
        Err(Error::UnterminatedGroup { field: 1, .. })
    ));
}

#[test]
fn depth_bomb_degrades_without_panicking() {
    // 200 nested single-field submessages. Parsing stops treating them as
    // messages at the depth limit and degrades the deepest level to Bytes;
    // the call returns Ok (partial), never overflowing the stack.
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
    let limits = Limits { max_depth: 16 };
    // Build from the inside out: innermost is field 1 = 1 (`08 01`), then wrap it
    // 200 times in a field-3 LEN submessage with a correctly encoded varint length.
    let mut payload = vec![0x08, 0x01];
    for _ in 0..200 {
        let mut next = vec![0x1a]; // field 3, LEN
        put_varint(payload.len() as u64, &mut next);
        next.extend_from_slice(&payload);
        payload = next;
    }
    let fields = decode_with_limits(&payload, limits).unwrap();
    assert_eq!(fields[0].number, 3);
}

#[test]
fn random_bytes_never_panic() {
    // A deterministic pseudo-random sweep: decode must return without panicking.
    let mut state = 0x1234_5678_u32;
    for _ in 0..2000 {
        let mut buf = Vec::new();
        let n = (state % 64) as usize;
        for _ in 0..n {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            buf.push((state >> 24) as u8);
        }
        let _ = decode(&buf); // Ok or Err, never a panic.
    }
}

#[test]
fn zigzag_decoding_matches_spec_table() {
    assert_eq!(zigzag_decode(0), 0);
    assert_eq!(zigzag_decode(1), -1);
    assert_eq!(zigzag_decode(2), 1);
    assert_eq!(zigzag_decode(3), -2);
    assert_eq!(zigzag_decode(0xffff_fffe), 0x7fff_ffff);
    assert_eq!(zigzag_decode(0xffff_ffff), -0x8000_0000);
}

#[test]
fn wire_type_roundtrips() {
    for v in 0u8..=5 {
        let wt = WireType::from_u8(v, 0).unwrap();
        assert_eq!(wt.as_u8(), v);
    }
    assert!(WireType::from_u8(7, 0).is_err());
}
