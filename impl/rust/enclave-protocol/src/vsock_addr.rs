//! AF_VSOCK **address/port resolution + validation** — the pure, gate-free layer.
//!
//! Deliberately split out of [`crate::vsock_listen`] (which is gated `vsock-transport` because it pulls
//! the Linux-only `vsock` crate to actually `bind`/`connect`). This module touches no socket and no
//! optional dep, so it is compiled — and its tests run — in the DEFAULT/`agent-gateway` CI builds, not
//! only the deferred `vsock-transport` build. Keeping the relay/serve port contract here is what makes
//! TASK-7.7 5b-2's "the testable logic lives outside the un-compiled gate" thesis actually hold for the
//! port validation (the bind/socket leaf stays in `vsock_listen`).

use crate::env_config::{
    var_twod, LEGACY_HSM_ANCHOR_RELAY_PORT, LEGACY_HSM_VSOCK_CID, LEGACY_HSM_VSOCK_PORT,
    TWOD_HSM_ANCHOR_RELAY_PORT, TWOD_HSM_VSOCK_CID, TWOD_HSM_VSOCK_PORT,
};

/// Default bind CID: `VMADDR_CID_ANY` (guest accepts connections on any assigned guest CID).
pub const DEFAULT_VSOCK_CID: u32 = 4_294_967_295;
/// Loopback-friendly CID (`VMADDR_CID_LOCAL`) for `vsock_loopback` on dev Linux.
pub const DEFAULT_VSOCK_CID_LOOPBACK: u32 = 1;
/// Default vsock service port (override via `TWOD_HSM_VSOCK_PORT`).
pub const DEFAULT_VSOCK_PORT: u32 = 5000;
/// `VMADDR_CID_HOST` — the host the enclave dials for the anti-rollback boot relay (TASK-7.7 5b-2).
pub const VMADDR_CID_HOST: u32 = 2;
/// Default anti-rollback boot-relay port (override via `TWOD_HSM_ANCHOR_RELAY_PORT`). Deliberately one
/// above [`DEFAULT_VSOCK_PORT`] as an operator-ergonomics default (see [`validate_relay_port`] for why
/// the two are already distinct endpoints regardless of the number).
pub const DEFAULT_ANCHOR_RELAY_PORT: u32 = 5001;

fn env_u32_twod(primary: &str, legacy: &str, default: u32) -> Result<u32, String> {
    match var_twod(primary, legacy) {
        Ok(s) if s.is_empty() => Ok(default),
        Ok(s) => s
            .parse::<u32>()
            .map_err(|_| format!("{primary} (or legacy {legacy}) must be a u32")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(format!("{primary} (or legacy {legacy}): {e}")),
    }
}

fn validate_vsock_listen_addr(cid: u32, port: u32) -> Result<(u32, u32), String> {
    if cid == 0 {
        return Err(format!(
            "{TWOD_HSM_VSOCK_CID} must not be 0 (hypervisor reserved); set an explicit guest CID"
        ));
    }
    if port == 0 {
        return Err(format!(
            "{TWOD_HSM_VSOCK_PORT} must not be 0; set an explicit service port"
        ));
    }
    Ok((cid, port))
}

/// Resolve `(cid, port)` from env or defaults.
///
/// Canonical: `TWOD_HSM_VSOCK_CID` / `TWOD_HSM_VSOCK_PORT`. Legacy `2D_HSM_VSOCK_*` still accepted.
pub fn vsock_listen_addr_from_env() -> Result<(u32, u32), String> {
    let cid = env_u32_twod(TWOD_HSM_VSOCK_CID, LEGACY_HSM_VSOCK_CID, DEFAULT_VSOCK_CID)?;
    let port = serve_vsock_port_from_env()?;
    validate_vsock_listen_addr(cid, port)
}

/// Resolve the serve vsock port from env — the single source shared by [`vsock_listen_addr_from_env`]
/// and the relay-port collision check, so both decode it identically (one place to change).
fn serve_vsock_port_from_env() -> Result<u32, String> {
    env_u32_twod(TWOD_HSM_VSOCK_PORT, LEGACY_HSM_VSOCK_PORT, DEFAULT_VSOCK_PORT)
}

/// Pure validation of a resolved relay `port` against the `serve_port`: reject `0` (reserved) and a
/// value equal to the serve port. (The relay endpoint is `(VMADDR_CID_HOST, port)` and the serve
/// listener binds the *guest* CID, so they are already distinct endpoints even at the same port number;
/// this is an operator-ergonomics guard against setting the two to the same number by mistake, NOT a
/// CID-level collision check.) Pure so it is unit-tested without touching process-global env.
fn validate_relay_port(port: u32, serve_port: u32) -> Result<u32, String> {
    if port == 0 {
        return Err(format!("{TWOD_HSM_ANCHOR_RELAY_PORT} must not be 0"));
    }
    if port == serve_port {
        return Err(format!(
            "{TWOD_HSM_ANCHOR_RELAY_PORT} ({port}) must differ from the serve port {TWOD_HSM_VSOCK_PORT} ({serve_port})"
        ));
    }
    Ok(port)
}

/// Resolve the anti-rollback boot-relay port (TASK-7.7 5b-2): `TWOD_HSM_ANCHOR_RELAY_PORT` (legacy
/// `2D_HSM_ANCHOR_RELAY_PORT`) or [`DEFAULT_ANCHOR_RELAY_PORT`] (5001), validated by
/// [`validate_relay_port`]. The enclave dials `(VMADDR_CID_HOST, this port)`; the host relay daemon binds
/// the same. The const/env contract is shared with [`vsock_listen_addr_from_env`].
pub fn anchor_relay_port_from_env() -> Result<u32, String> {
    let port = env_u32_twod(
        TWOD_HSM_ANCHOR_RELAY_PORT,
        LEGACY_HSM_ANCHOR_RELAY_PORT,
        DEFAULT_ANCHOR_RELAY_PORT,
    )?;
    validate_relay_port(port, serve_vsock_port_from_env()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_relay_port_consts() {
        assert_eq!(DEFAULT_ANCHOR_RELAY_PORT, 5001);
        assert_ne!(DEFAULT_ANCHOR_RELAY_PORT, DEFAULT_VSOCK_PORT);
        assert_eq!(VMADDR_CID_HOST, 2);
    }

    #[test]
    fn validate_relay_port_accepts_distinct_rejects_zero_and_collision() {
        // The default vs serve default — accepted.
        assert_eq!(validate_relay_port(DEFAULT_ANCHOR_RELAY_PORT, DEFAULT_VSOCK_PORT).unwrap(), 5001);
        // 0 is reserved.
        assert!(validate_relay_port(0, DEFAULT_VSOCK_PORT).is_err());
        // same as the serve port — rejected (deterministic, no env needed).
        assert!(validate_relay_port(DEFAULT_VSOCK_PORT, DEFAULT_VSOCK_PORT).is_err());
        assert!(validate_relay_port(6000, 6000).is_err());
    }

    #[test]
    fn validate_vsock_listen_addr_rejects_zero_cid_and_port() {
        assert_eq!(validate_vsock_listen_addr(3, 5000).unwrap(), (3, 5000));
        assert!(validate_vsock_listen_addr(0, 5000).is_err());
        assert!(validate_vsock_listen_addr(3, 0).is_err());
    }
}
