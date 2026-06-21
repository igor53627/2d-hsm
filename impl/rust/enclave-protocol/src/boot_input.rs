//! Shared helpers for operator-supplied boot files (lab / integration only).
//!
//! Every reader here is a FEATURE-CONDITIONAL boot helper: the producer (`ml-dsa-65` lab/provisioning) and
//! the agent (`lab-agent-keystore-from-file`) builds each compile only the subset they call, so the
//! dead-code lint would fire on the unused reader(s) per feature build — hence the per-fn `allow(dead_code)`.

use crate::ProtocolError;
use std::path::Path;

/// Read a boot input file; map I/O failure to [`ProtocolError::PqSigningUnavailable`].
#[allow(dead_code)]
pub fn read_boot_file(path: &Path, err_label: &'static str) -> Result<Vec<u8>, ProtocolError> {
    std::fs::read(path).map_err(|_| ProtocolError::PqSigningUnavailable(err_label))
}

/// Read a boot file but CAP the read at `max_bytes + 1` so a never-ending special file (e.g. `/dev/zero`)
/// or an oversize file cannot OOM / hang the boot path before the caller's length check. Returns up to
/// `max_bytes + 1` bytes — the caller still validates the exact length (a returned `len > max_bytes` means
/// "too large", deterministically, without having read the whole thing). Maps I/O failure fail-closed.
#[allow(dead_code)]
pub fn read_boot_file_capped(
    path: &Path,
    max_bytes: usize,
    err_label: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|_| ProtocolError::PqSigningUnavailable(err_label))?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProtocolError::PqSigningUnavailable(err_label))?;
    Ok(bytes)
}

/// Read a boot file and strip trailing `\n` / `\r` (text manifest convention).
#[allow(dead_code)]
pub fn read_boot_file_trim_trailing_newlines(
    path: &Path,
    err_label: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = read_boot_file(path, err_label)?;
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    Ok(bytes)
}
