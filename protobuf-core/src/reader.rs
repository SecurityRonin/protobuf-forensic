//! Bounds-checked wire-format reader and the recursive schemaless decoder.
//!
//! RED skeleton — signatures only; behaviour lands in the GREEN commit.

use crate::{Error, Field, Limits};

pub(crate) fn decode_message(_bytes: &[u8], _limits: &Limits) -> Result<Vec<Field>, Error> {
    unimplemented!("GREEN")
}

pub(crate) fn packed_varints(_raw: &[u8]) -> Option<Vec<u64>> {
    unimplemented!("GREEN")
}

pub(crate) fn packed_i32(_raw: &[u8]) -> Option<Vec<u32>> {
    unimplemented!("GREEN")
}

pub(crate) fn packed_i64(_raw: &[u8]) -> Option<Vec<u64>> {
    unimplemented!("GREEN")
}
