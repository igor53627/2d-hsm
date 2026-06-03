//! Shared Unix domain socket bind helper (dev + staging servers).

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// Bind a UDS listener at `path` with parent `0700` and socket `0600`.
///
/// When `path` is not under `default_parent`, the parent must already exist with mode `0700`
/// so other local users cannot connect during the brief window before socket chmod.
pub fn bind_unix_listener(
    path: &Path,
    private_dir: &Path,
) -> Result<UnixListener, io::Error> {
    if let Some(parent) = path.parent() {
        let is_default_parent = Some(parent) == Some(private_dir);
        if is_default_parent {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        } else {
            require_private_socket_parent(parent)?;
        }
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn require_private_socket_parent(parent: &Path) -> Result<(), io::Error> {
    let meta = fs::metadata(parent).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "socket parent {} must exist with mode 0700 before bind (custom socket path): {e}",
                parent.display()
            ),
        )
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket parent {} must be mode 0700 (got {mode:o}); use default ~/.2d-hsm path or fix permissions",
                parent.display()
            ),
        ));
    }
    Ok(())
}

/// Default dev socket directory: `$HOME/.2d-hsm`.
pub fn default_dev_socket_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join(".2d-hsm")
}