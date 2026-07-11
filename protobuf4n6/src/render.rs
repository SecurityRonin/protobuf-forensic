//! Output renderers (RED skeleton).

use std::io::{self, Write};

use protobuf_forensic::Analysis;

use crate::Format;

pub(crate) fn render(
    _analysis: &Analysis,
    _format: Format,
    _out: &mut dyn Write,
) -> io::Result<()> {
    unimplemented!("GREEN")
}
