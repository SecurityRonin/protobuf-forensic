//! Output renderers: a human `text` field tree, machine-faithful `jsonl`, and a
//! protoscope-like format.

use std::fmt::Write as _;
use std::io::{self, Write};

use protobuf_forensic::{Analysis, AnalyzedField, AnalyzedValue, TimeSource, TimestampHit};
use protobuf_forensic_core::WireType;

use crate::Format;

/// Render `analysis` to `out` in `format`.
pub(crate) fn render(analysis: &Analysis, format: Format, out: &mut dyn Write) -> io::Result<()> {
    match format {
        Format::Text => render_text(analysis, out),
        Format::Jsonl => render_jsonl(analysis, out),
        Format::Protoscope => render_protoscope(analysis, out),
    }
}

fn wire_str(wire: WireType) -> &'static str {
    match wire {
        WireType::Varint => "varint",
        WireType::I64 => "i64",
        WireType::Len => "len",
        WireType::StartGroup => "sgroup",
        // cov:unreachable: an EGROUP tag is consumed by the decoder and never
        // becomes a field, so no `Field` carries this wire type.
        WireType::EndGroup => "egroup",
        WireType::I32 => "i32",
    }
}

fn source_str(source: TimeSource) -> &'static str {
    match source {
        TimeSource::Varint => "varint",
        TimeSource::Fixed64AsInt => "fixed64:int",
        TimeSource::Fixed64AsFloat => "fixed64:double",
        TimeSource::Fixed32AsInt => "fixed32:int",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---- text -----------------------------------------------------------------

fn render_text(analysis: &Analysis, out: &mut dyn Write) -> io::Result<()> {
    for field in &analysis.fields {
        text_field(field, 0, out)?;
    }
    Ok(())
}

fn text_field(field: &AnalyzedField, depth: usize, out: &mut dyn Write) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    let head = format!(
        "{indent}{path} [field {number} {wire}]",
        path = field.path,
        number = field.number,
        wire = wire_str(field.wire_type),
    );
    match &field.value {
        AnalyzedValue::Varint(v) => writeln!(out, "{head} varint {v}")?,
        AnalyzedValue::Fixed64(v) => writeln!(out, "{head} fixed64 {v} (0x{v:016x})")?,
        AnalyzedValue::Fixed32(v) => writeln!(out, "{head} fixed32 {v} (0x{v:08x})")?,
        AnalyzedValue::Text(s) => writeln!(out, "{head} string {s:?}")?,
        AnalyzedValue::Bytes(b) => writeln!(out, "{head} bytes[{}] {}", b.len(), hex(b))?,
        AnalyzedValue::Message(children) => {
            writeln!(out, "{head} message ({} field(s))", children.len())?;
            for child in children {
                text_field(child, depth + 1, out)?;
            }
        }
        AnalyzedValue::Group(children) => {
            writeln!(out, "{head} group ({} field(s))", children.len())?;
            for child in children {
                text_field(child, depth + 1, out)?;
            }
        }
    }
    if field.confidence < 1.0 {
        writeln!(out, "{indent}    conf {:.2}", field.confidence)?;
    }
    for note in &field.notes {
        writeln!(out, "{indent}    note: {note}")?;
    }
    for ts in &field.timestamps {
        text_timestamp(&indent, ts, out)?;
    }
    Ok(())
}

fn text_timestamp(indent: &str, ts: &TimestampHit, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "{indent}    time? {rendered}  {label} ({format_id}, {pct}%, via {source})",
        rendered = ts.rendered,
        label = ts.label,
        format_id = ts.format_id,
        pct = ts.confidence_pct,
        source = source_str(ts.source),
    )
}

// ---- jsonl ----------------------------------------------------------------

fn render_jsonl(analysis: &Analysis, out: &mut dyn Write) -> io::Result<()> {
    for field in &analysis.fields {
        jsonl_field(field, out)?;
    }
    Ok(())
}

fn jsonl_field(field: &AnalyzedField, out: &mut dyn Write) -> io::Result<()> {
    // `serde_json::Value` renders compact JSON via `Display` — no fallible
    // `to_string` (and thus no never-taken error branch) needed.
    writeln!(out, "{}", field_to_json(field))?;
    if let AnalyzedValue::Message(children) | AnalyzedValue::Group(children) = &field.value {
        for child in children {
            jsonl_field(child, out)?;
        }
    }
    Ok(())
}

fn field_to_json(field: &AnalyzedField) -> serde_json::Value {
    use serde_json::json;
    let (kind, value, extra): (&str, serde_json::Value, serde_json::Value) = match &field.value {
        AnalyzedValue::Varint(v) => ("varint", json!(v), json!({})),
        AnalyzedValue::Fixed64(v) => ("fixed64", json!(v), json!({})),
        AnalyzedValue::Fixed32(v) => ("fixed32", json!(v), json!({})),
        AnalyzedValue::Text(s) => ("string", json!(s), json!({})),
        AnalyzedValue::Bytes(b) => (
            "bytes",
            serde_json::Value::Null,
            json!({ "hex": hex(b), "len": b.len() }),
        ),
        AnalyzedValue::Message(children) => (
            "message",
            serde_json::Value::Null,
            json!({ "fields": children.len() }),
        ),
        AnalyzedValue::Group(children) => (
            "group",
            serde_json::Value::Null,
            json!({ "fields": children.len() }),
        ),
    };
    let timestamps: Vec<serde_json::Value> = field
        .timestamps
        .iter()
        .map(|ts| {
            json!({
                "source": source_str(ts.source),
                "format_id": ts.format_id,
                "label": ts.label,
                "rendered": ts.rendered,
                "score": ts.score,
                "confidence_pct": ts.confidence_pct,
                "citation": ts.citation,
            })
        })
        .collect();
    let mut obj = json!({
        "path": field.path,
        "number": field.number,
        "wire_type": wire_str(field.wire_type),
        "kind": kind,
        "value": value,
        "confidence": field.confidence,
        "notes": field.notes,
        "timestamps": timestamps,
    });
    if let (Some(map), Some(extra_map)) = (obj.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_map {
            map.insert(k.clone(), v.clone());
        }
    }
    obj
}

// ---- protoscope-like ------------------------------------------------------

fn render_protoscope(analysis: &Analysis, out: &mut dyn Write) -> io::Result<()> {
    for field in &analysis.fields {
        proto_field(field, 0, out)?;
    }
    Ok(())
}

fn proto_field(field: &AnalyzedField, depth: usize, out: &mut dyn Write) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    let n = field.number;
    match &field.value {
        AnalyzedValue::Varint(v) => writeln!(out, "{indent}{n}: {v}")?,
        AnalyzedValue::Fixed64(v) => writeln!(out, "{indent}{n}: {v}i64")?,
        AnalyzedValue::Fixed32(v) => writeln!(out, "{indent}{n}: {v}i32")?,
        AnalyzedValue::Text(s) => writeln!(out, "{indent}{n}: {{{s:?}}}")?,
        AnalyzedValue::Bytes(b) => writeln!(out, "{indent}{n}: {{`{}`}}", hex(b))?,
        AnalyzedValue::Message(children) | AnalyzedValue::Group(children) => {
            writeln!(out, "{indent}{n}: {{")?;
            for child in children {
                proto_field(child, depth + 1, out)?;
            }
            writeln!(out, "{indent}}}")?;
        }
    }
    Ok(())
}
