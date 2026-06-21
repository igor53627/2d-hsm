//! AF_VSOCK listener **socket leaf** (Linux / Nitro / SEV-SNP reference transport).
//!
//! Only the socket-touching code lives here — it is gated `vsock-transport` (lib.rs) because it pulls the
//! Linux-only `vsock` crate. The pure address/port *resolution + validation* lives in the gate-free
//! [`crate::vsock_addr`] module so it is CI-tested in the default/`agent-gateway` builds (TASK-7.7 5b-2).

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use std::io;
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
use vsock::{VsockAddr, VsockListener};

// Re-export so the staging/production bins keep importing the resolver via this module
// (`use ...vsock_listen::{..., vsock_listen_addr_from_env}`); canonical home is `crate::vsock_addr`.
pub use crate::vsock_addr::vsock_listen_addr_from_env;

#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub fn bind_vsock_listener(cid: u32, port: u32) -> Result<VsockListener, io::Error> {
    let addr = VsockAddr::new(cid, port);
    VsockListener::bind(&addr)
}

/// Apply session I/O timeouts (per-read [`READ_TIMEOUT`]; inter-frame idle in `serve_framed_connection`).
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
pub fn configure_vsock_session_timeouts(stream: &mut vsock::VsockStream) -> Result<(), io::Error> {
    use crate::enclave_serve::{READ_TIMEOUT, WRITE_TIMEOUT};
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "vsock-transport")))]
pub fn bind_vsock_listener(_cid: u32, _port: u32) -> Result<(), String> {
    Err("AF_VSOCK requires Linux and feature vsock-transport (use staging-vsock)".to_string())
}
