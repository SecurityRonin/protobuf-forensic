//! Fuzz the schemaless wire decoder on arbitrary bytes.
//!
//! `decode` walks tags, varints, fixed32/64, length-delimited payloads (with
//! recursive message/string/bytes inference), and groups. On any input it must
//! return `Ok`/`Err` without panicking, aborting, or over-allocating.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = protobuf_core::decode(data);
});
