//! Fuzz the forensic analysis layer on arbitrary bytes.
//!
//! `analyze` decodes then walks the tree, classifying length-delimited fields
//! and running every integer value through timeglyph. It must never panic on
//! hostile input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = protobuf_forensic::analyze(data);
});
