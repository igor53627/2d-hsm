//! AF_VSOCK listener (Linux / Nitro / SEV-SNP reference transport).

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use vsock::{VsockAddr, VsockListener};

/// Default Nitro-style enclave CID (parent VM is typically CID 3 for the enclave side in many setups).
pub const DEFAULT_VSOCK_CID: u32 = 3;
/// Default vsock service port for the signing service (override via `2D_HSM_VSOCK_PORT`).
pub const DEFAULT_VSOCK_PORT: u32 = 5000;

/// Resolve `(cid, port)` from `2D_HSM_VSOCK_CID` / `2D_HSM_VSOCK_PORT` or defaults.
pub fn vsock_listen_addr_from_env() -> Result<(u32, u32), String> {
    let cid = std::env::var("2D_HSM_VSOCK_CID")
        .ok()
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|_| "2D_HSM_VSOCK_CID must be a u32")?
        .unwrap_or(DEFAULT_VSOCK_CID);
    let port = std::env::var("2D_HSM_VSOCK_PORT")
        .ok()
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|_| "2D_HSM_VSOCK_PORT must be a u32")?
        .unwrap_or(DEFAULT_VSOCK_PORT);
    Ok((cid, port))
}

#[cfg(target_os = "linux")]
pub fn bind_vsock_listener(cid: u32, port: u32) -> Result<VsockListener, io::Error> {
    let addr = VsockAddr::new(cid, port);
    VsockListener::bind(&addr)
}

#[cfg(not(target_os = "linux"))]
pub fn bind_vsock_listener(_cid: u32, _port: u32) -> Result<(), String> {
    Err("AF_VSOCK is only available on Linux".to_string())
}