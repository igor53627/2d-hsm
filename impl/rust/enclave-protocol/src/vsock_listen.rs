//! AF_VSOCK listener (Linux / Nitro / SEV-SNP reference transport).

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use std::io;
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use vsock::{VsockAddr, VsockListener};

use crate::env_config::{
    var_twod, LEGACY_HSM_VSOCK_CID, LEGACY_HSM_VSOCK_PORT, TWOD_HSM_VSOCK_CID, TWOD_HSM_VSOCK_PORT,
};

/// Default Nitro-style enclave CID (many Nitro setups use CID 3 for the enclave listener).
/// On generic Linux dev hosts (e.g. SEV loopback on **aya**), use `TWOD_HSM_VSOCK_CID=1` or `4294967295`.
pub const DEFAULT_VSOCK_CID: u32 = 3;
/// Loopback-friendly CID (`VMADDR_CID_LOCAL`) for `vsock_loopback` on dev Linux.
pub const DEFAULT_VSOCK_CID_LOOPBACK: u32 = 1;
/// Default vsock service port (override via `TWOD_HSM_VSOCK_PORT`).
pub const DEFAULT_VSOCK_PORT: u32 = 5000;

fn env_u32_twod(primary: &str, legacy: &str, default: u32) -> Result<u32, String> {
    match var_twod(primary, legacy) {
        Ok(s) if s.is_empty() => Ok(default),
        Ok(s) => s
            .parse::<u32>()
            .map_err(|_| format!("{primary} (or legacy {legacy}) must be a u32")),
        Err(_) => Ok(default),
    }
}

/// Resolve `(cid, port)` from env or defaults.
///
/// Canonical: `TWOD_HSM_VSOCK_CID` / `TWOD_HSM_VSOCK_PORT`. Legacy `2D_HSM_VSOCK_*` still accepted.
pub fn vsock_listen_addr_from_env() -> Result<(u32, u32), String> {
    let cid = env_u32_twod(TWOD_HSM_VSOCK_CID, LEGACY_HSM_VSOCK_CID, DEFAULT_VSOCK_CID)?;
    let port = env_u32_twod(TWOD_HSM_VSOCK_PORT, LEGACY_HSM_VSOCK_PORT, DEFAULT_VSOCK_PORT)?;
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