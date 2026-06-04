//! AF_VSOCK listener (Linux / Nitro / SEV-SNP reference transport).

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use std::io;
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use vsock::{VsockAddr, VsockListener};

/// Default Nitro-style enclave CID (many Nitro setups use CID 3 for the enclave listener).
/// On generic Linux dev hosts (e.g. SEV loopback on **aya**), use `TWOD_HSM_VSOCK_CID=1` or `4294967295`.
pub const DEFAULT_VSOCK_CID: u32 = 3;
/// Loopback-friendly CID (`VMADDR_CID_LOCAL`) for `vsock_loopback` on dev Linux.
pub const DEFAULT_VSOCK_CID_LOOPBACK: u32 = 1;
/// Default vsock service port (override via `TWOD_HSM_VSOCK_PORT`).
pub const DEFAULT_VSOCK_PORT: u32 = 5000;

/// Env keys for vsock bind (systemd-safe: no leading digit — use `TWOD_`, not `2D_`).
pub const ENV_VSOCK_CID: &[&str] = &["TWOD_HSM_VSOCK_CID", "HSM_VSOCK_CID", "2D_HSM_VSOCK_CID"];
pub const ENV_VSOCK_PORT: &[&str] = &["TWOD_HSM_VSOCK_PORT", "HSM_VSOCK_PORT", "2D_HSM_VSOCK_PORT"];

fn env_u32(names: &[&str], default: u32) -> Result<u32, String> {
    for name in names {
        if let Ok(s) = std::env::var(name) {
            return s
                .parse::<u32>()
                .map_err(|_| format!("{name} must be a u32"));
        }
    }
    Ok(default)
}

/// Resolve `(cid, port)` from env or defaults.
///
/// Canonical keys: `TWOD_HSM_VSOCK_CID` / `TWOD_HSM_VSOCK_PORT` (`2D` → `TWOD` for systemd/shell).
/// Legacy aliases `HSM_VSOCK_*` and `2D_HSM_VSOCK_*` are still accepted.
pub fn vsock_listen_addr_from_env() -> Result<(u32, u32), String> {
    let cid = env_u32(ENV_VSOCK_CID, DEFAULT_VSOCK_CID)?;
    let port = env_u32(ENV_VSOCK_PORT, DEFAULT_VSOCK_PORT)?;
    Ok((cid, port))
}

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub fn bind_vsock_listener(cid: u32, port: u32) -> Result<VsockListener, io::Error> {
    let addr = VsockAddr::new(cid, port);
    VsockListener::bind(&addr)
}

/// Apply the same session I/O timeouts as UDS staging (prevents slot exhaustion on idle peers).
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub fn configure_vsock_session_timeouts(
    stream: &mut vsock::VsockStream,
) -> Result<(), io::Error> {
    use crate::enclave_serve::{READ_TIMEOUT, WRITE_TIMEOUT};
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "vsock-transport")))]
pub fn bind_vsock_listener(_cid: u32, _port: u32) -> Result<(), String> {
    Err("AF_VSOCK requires Linux and feature vsock-transport (use staging-vsock)".to_string())
}