//! Shared helpers for operator-supplied boot files (lab / integration only).

use crate::ProtocolError;
use std::path::Path;

/// Read a boot input file; map I/O failure to [`ProtocolError::PqSigningUnavailable`].
pub fn read_boot_file(path: &Path, err_label: &'static str) -> Result<Vec<u8>, ProtocolError> {
    std::fs::read(path).map_err(|_| ProtocolError::PqSigningUnavailable(err_label))
}

/// Read a boot file and strip trailing `\n` / `\r` (text manifest convention).
pub fn read_boot_file_trim_trailing_newlines(
    path: &Path,
    err_label: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = read_boot_file(path, err_label)?;
    while bytes
        .last()
        .is_some_and(|b| *b == b'\n' || *b == b'\r')
    {
        bytes.pop();
    }
    Ok(bytes)
}