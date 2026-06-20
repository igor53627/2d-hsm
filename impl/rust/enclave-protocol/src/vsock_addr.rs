//! AF_VSOCK **address/port resolution + validation** — the pure, gate-free layer.
//!
//! Deliberately split out of [`crate::vsock_listen`] (which is gated `vsock-transport` because it pulls
//! the Linux-only `vsock` crate to actually `bind`/`connect`). This module touches no socket and no
//! optional dep, so it is compiled — and its tests run — in the DEFAULT/`agent-gateway` CI builds, not
//! only the deferred `vsock-transport` build. Keeping the relay/serve port contract here is what makes
//! TASK-7.7 5b-2's "the testable logic lives outside the un-compiled gate" thesis actually hold for the
//! port validation (the bind/socket leaf stays in `vsock_listen`).

use crate::env_config::{
    var_twod, LEGACY_HSM_ANCHOR_ENDPOINT, LEGACY_HSM_ANCHOR_RELAY_PORT, LEGACY_HSM_VSOCK_CID,
    LEGACY_HSM_VSOCK_PORT, TWOD_HSM_ANCHOR_ENDPOINT, TWOD_HSM_ANCHOR_RELAY_PORT, TWOD_HSM_VSOCK_CID,
    TWOD_HSM_VSOCK_PORT,
};
use std::net::ToSocketAddrs;

/// Default bind CID: `VMADDR_CID_ANY` (guest accepts connections on any assigned guest CID).
pub const DEFAULT_VSOCK_CID: u32 = 4_294_967_295;
/// Default vsock service port (override via `TWOD_HSM_VSOCK_PORT`).
pub const DEFAULT_VSOCK_PORT: u32 = 5000;
/// `VMADDR_CID_HOST` — the host the enclave dials for the anti-rollback boot relay (TASK-7.7 5b-2).
pub const VMADDR_CID_HOST: u32 = 2;
/// Default anti-rollback boot-relay port (override via `TWOD_HSM_ANCHOR_RELAY_PORT`). Deliberately one
/// above [`DEFAULT_VSOCK_PORT`] as an operator-ergonomics default (see [`validate_relay_port`] for why
/// the two are already distinct endpoints regardless of the number).
pub const DEFAULT_ANCHOR_RELAY_PORT: u32 = 5001;
/// Default provisioning bootstrap vsock port (TASK-25 Q5). Distinct from serve (5000) + relay (5001).
pub const DEFAULT_PROVISIONING_VSOCK_PORT: u32 = 5002;

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

/// Resolve the provisioning bootstrap vsock port (TASK-25 Q5): `TWOD_HSM_PROVISIONING_VSOCK_PORT`
/// (legacy `2D_HSM_PROVISIONING_VSOCK_PORT`) or [`DEFAULT_PROVISIONING_VSOCK_PORT`] (5002), validated
/// against BOTH the serve port and the relay port (three distinct ports — Q5 structural invariant).
pub fn provisioning_vsock_port_from_env() -> Result<u32, String> {
    use crate::env_config::{
        LEGACY_HSM_PROVISIONING_VSOCK_PORT, TWOD_HSM_PROVISIONING_VSOCK_PORT,
    };
    let port = env_u32_twod(
        TWOD_HSM_PROVISIONING_VSOCK_PORT,
        LEGACY_HSM_PROVISIONING_VSOCK_PORT,
        DEFAULT_PROVISIONING_VSOCK_PORT,
    )?;
    let serve = serve_vsock_port_from_env()?;
    if port == serve {
        return Err(format!(
            "provisioning vsock port ({port}) must be distinct from the serve port ({serve})"
        ));
    }
    let relay = env_u32_twod(
        TWOD_HSM_ANCHOR_RELAY_PORT,
        LEGACY_HSM_ANCHOR_RELAY_PORT,
        DEFAULT_ANCHOR_RELAY_PORT,
    )?;
    if port == relay {
        return Err(format!(
            "provisioning vsock port ({port}) must be distinct from the anchor relay port ({relay})"
        ));
    }
    Ok(port)
}

/// Resolve the UNTRUSTED host relay's upstream anchor endpoint (TASK-7.7 5b-2b-ii(b)) from
/// `TWOD_HSM_ANCHOR_ENDPOINT` (legacy `2D_HSM_ANCHOR_ENDPOINT`). REQUIRED — no default; a missing or
/// empty value is a fail-closed boot error naming the var (never a silent localhost guess; §8
/// profile-uniformity). Resolves DNS via `to_socket_addrs`, returning the addr LIST so the dialer can
/// try each. Gate-free + std-only so it is CI-tested without the vsock dep (the pure-layer convention
/// this module exists for — same home + shape as [`anchor_relay_port_from_env`]). The connect-timeout
/// + per-pump socket budget are DERIVED daemon-side from the per-leg Duration, NOT a separate knob.
pub fn anchor_endpoint_from_env() -> Result<Vec<std::net::SocketAddr>, String> {
    let raw = match var_twod(TWOD_HSM_ANCHOR_ENDPOINT, LEGACY_HSM_ANCHOR_ENDPOINT) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return Err(format!(
                "{TWOD_HSM_ANCHOR_ENDPOINT} (or legacy {LEGACY_HSM_ANCHOR_ENDPOINT}) must be set to \
                 the external anchor host:port (no default — fail-closed)"
            ))
        }
    };
    let addrs = resolve_host_port_bounded(&raw, ANCHOR_RESOLVE_BUDGET)?;
    if addrs.is_empty() {
        return Err(format!("{TWOD_HSM_ANCHOR_ENDPOINT} ({raw}) resolved to zero addresses"));
    }
    Ok(addrs)
}

/// Hard wall-clock cap on the blocking `getaddrinfo` at daemon startup. A wedged / black-holing resolver
/// must NOT silently hang the daemon BEFORE it binds + logs `Listening` — that would defeat the whole
/// fail-closed startup contract (a clean non-zero exit, never an invisible stall). Generous against a
/// HEALTHY resolver (glibc's own resolv.conf timeout × attempts is already seconds); a hard ceiling
/// against a pathological / hung NSS source that `getaddrinfo` itself would never time out.
const ANCHOR_RESOLVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);

/// Resolve `host:port` via `to_socket_addrs` (blocking `getaddrinfo`) under a HARD wall-clock cap, so a
/// wedged resolver fails CLOSED (a named error → the bin prints it + exits 1) instead of hanging the
/// daemon forever before it ever binds. The resolve runs on a detached worker thread; if it overruns
/// `budget` we abandon it (a `getaddrinfo` that never returns dies with the process on the fail-closed
/// exit below — acceptable for a one-shot startup resolve) and return a timeout error. An IP literal
/// resolves synchronously, well within any budget — so the IP path is unaffected.
fn resolve_host_port_bounded(
    raw: &str,
    budget: std::time::Duration,
) -> Result<Vec<std::net::SocketAddr>, String> {
    let owned = raw.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("anchor-resolve".into())
        .spawn(move || {
            // Map the io::Error to a String so the Result crosses the channel (io::Error is not Send-
            // restricted, but a String keeps the worker self-contained + the receiver dependency-free).
            let _ = tx.send(
                owned
                    .to_socket_addrs()
                    .map(|it| it.collect::<Vec<_>>())
                    .map_err(|e| e.to_string()),
            );
        })
        .map_err(|e| format!("{TWOD_HSM_ANCHOR_ENDPOINT}: could not spawn resolver thread: {e}"))?;
    match rx.recv_timeout(budget) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(format!(
            "{TWOD_HSM_ANCHOR_ENDPOINT} ({raw}) is not a resolvable host:port: {e}"
        )),
        // Timeout OR the worker dropped the sender without sending (shouldn't happen) — both fail closed.
        Err(_) => Err(format!(
            "{TWOD_HSM_ANCHOR_ENDPOINT} ({raw}) did not resolve within {}s — failing closed (resolver \
             wedged?)",
            budget.as_secs()
        )),
    }
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

    // --- TASK-7.7 5b-2b-ii(b) test 10: anchor_endpoint_from_env (gate-free; runs in the DEFAULT /
    // agent-gateway CI build — no vsock dep). Serializes env mutation via a module-local lock: this
    // resolver is the SOLE consumer of TWOD_HSM_ANCHOR_ENDPOINT / 2D_HSM_ANCHOR_ENDPOINT, so a local
    // guard fully serializes access to those two vars (no cross-module env race). Regression: the
    // no-default fail-closed contract + the to_socket_addrs DNS resolution path.

    /// Serializes the env-mutating test below (the only one touching these two vars).
    static ANCHOR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Hold the lock, clear BOTH var names, run `body`, then clear again so no sibling inherits.
    fn with_anchor_env_cleared<R>(body: impl FnOnce() -> R) -> R {
        let _g = ANCHOR_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var(TWOD_HSM_ANCHOR_ENDPOINT);
        std::env::remove_var(LEGACY_HSM_ANCHOR_ENDPOINT);
        let r = body();
        std::env::remove_var(TWOD_HSM_ANCHOR_ENDPOINT);
        std::env::remove_var(LEGACY_HSM_ANCHOR_ENDPOINT);
        r
    }

    #[test]
    fn anchor_endpoint_from_env_fail_closed_unset_and_empty() {
        with_anchor_env_cleared(|| {
            // UNSET → fail-closed Err naming the var (no default, no silent localhost).
            let err = anchor_endpoint_from_env().unwrap_err();
            assert!(err.contains(TWOD_HSM_ANCHOR_ENDPOINT), "err must name the var: {err}");
            assert!(err.contains("fail-closed"), "err must state fail-closed: {err}");
            // EMPTY is treated as unset (same fail-closed branch) — never a localhost guess.
            std::env::set_var(TWOD_HSM_ANCHOR_ENDPOINT, "");
            assert!(anchor_endpoint_from_env().is_err());
        });
    }

    #[test]
    fn anchor_endpoint_from_env_resolves_ipv4_literal() {
        with_anchor_env_cleared(|| {
            std::env::set_var(TWOD_HSM_ANCHOR_ENDPOINT, "127.0.0.1:9999");
            let addrs = anchor_endpoint_from_env().expect("ip literal resolves");
            assert!(!addrs.is_empty());
            assert!(
                addrs.iter().any(|a| a.to_string() == "127.0.0.1:9999"),
                "must contain the literal addr: {addrs:?}"
            );
        });
    }

    #[test]
    fn anchor_endpoint_from_env_localhost_dns_resolves() {
        with_anchor_env_cleared(|| {
            // A DNS name resolves via to_socket_addrs (localhost is universally resolvable in CI).
            std::env::set_var(TWOD_HSM_ANCHOR_ENDPOINT, "localhost:9999");
            let addrs = anchor_endpoint_from_env().expect("localhost resolves via DNS");
            assert!(!addrs.is_empty(), "localhost must resolve to >=1 addr");
            assert!(addrs.iter().all(|a| a.port() == 9999));
        });
    }

    #[test]
    fn anchor_endpoint_from_env_rejects_unparseable() {
        with_anchor_env_cleared(|| {
            // No port → not a resolvable host:port → Err (NOT a silent default).
            std::env::set_var(TWOD_HSM_ANCHOR_ENDPOINT, "not-a-host-port");
            assert!(anchor_endpoint_from_env().is_err());
        });
    }

    #[test]
    fn anchor_endpoint_from_env_legacy_name_accepted() {
        with_anchor_env_cleared(|| {
            // Legacy 2D_HSM_ANCHOR_ENDPOINT is honored when the canonical name is unset.
            std::env::set_var(LEGACY_HSM_ANCHOR_ENDPOINT, "127.0.0.1:7000");
            let addrs = anchor_endpoint_from_env().expect("legacy name resolves");
            assert!(addrs.iter().any(|a| a.to_string() == "127.0.0.1:7000"));
        });
    }

    // --- TASK-7.7 5b-2b-ii(b) review-fix: the bounded resolver (no env — the IP path resolves
    // synchronously, well within the budget; a wedged real DNS can't be simulated deterministically, so
    // we pin the fast path + the budget-arg plumbing, which is what guards the fail-closed startup).

    #[test]
    fn resolve_host_port_bounded_ip_literal_within_budget() {
        // An IP literal does NO network DNS, so it returns immediately regardless of the (tiny) budget —
        // proving the bounded wrapper does not regress the IP path and threads the budget through.
        let addrs =
            resolve_host_port_bounded("127.0.0.1:7100", std::time::Duration::from_secs(5)).unwrap();
        assert!(addrs.iter().any(|a| a.to_string() == "127.0.0.1:7100"));
    }

    #[test]
    fn resolve_host_port_bounded_rejects_unparseable() {
        // A missing port is unresolvable → the worker's getaddrinfo errors fast → bounded Err (NOT a
        // timeout, NOT a hang) naming the var. Distinguishes the resolve-error arm from the timeout arm.
        let err = resolve_host_port_bounded("not-a-host-port", std::time::Duration::from_secs(5))
            .unwrap_err();
        assert!(err.contains(TWOD_HSM_ANCHOR_ENDPOINT), "err must name the var: {err}");
    }
}
