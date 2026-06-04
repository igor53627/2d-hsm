//! Shared Unix domain socket bind helper (dev + staging servers).

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// Bind a UDS listener at `path` with socket mode `0600`.
///
/// Creates the parent directory when missing. Tightens the default `private_dir` to `0700`;
/// custom `TWOD_HSM_ENCLAVE_*_SOCKET` parents are created but not chmod'd (operator responsibility).
pub fn bind_unix_listener(
    path: &Path,
    private_dir: &Path,
) -> Result<UnixListener, io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        if path_parent_is_private_dir(parent, private_dir) {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn path_parent_is_private_dir(parent: &Path, private_dir: &Path) -> bool {
    if parent == private_dir {
        return true;
    }
    match (parent.canonicalize(), private_dir.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Default dev socket directory: `$HOME/.2d-hsm` (or `$TMPDIR/.2d-hsm` when `HOME` is unset).
pub fn default_dev_socket_dir() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    base.join(".2d-hsm")
}
