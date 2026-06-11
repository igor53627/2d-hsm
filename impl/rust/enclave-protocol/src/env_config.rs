//! Operator environment variable names (`TWOD_*` prefix).
//!
//! POSIX and **systemd** reject env keys that start with a digit, so use
//! `TWOD_HSM_*` instead of `2D_HSM_*` in unit files, cloud-init, and NixOS modules.
//! Reference binaries still accept deprecated `2D_HSM_*` names for one transition period.

/// Read `primary`, then deprecated `legacy` (`2D_HSM_*`).
///
/// Falls back to `legacy` only when `primary` is unset. A `primary` set to a
/// non-UTF-8 value is a misconfiguration and is surfaced (fail closed) rather
/// than masked by a stale legacy value.
pub fn var_twod(primary: &str, legacy: &str) -> Result<String, std::env::VarError> {
    match std::env::var(primary) {
        Ok(v) => Ok(v),
        Err(std::env::VarError::NotPresent) => std::env::var(legacy),
        Err(e) => Err(e),
    }
}

pub const TWOD_HSM_VSOCK_CID: &str = "TWOD_HSM_VSOCK_CID";
pub const LEGACY_HSM_VSOCK_CID: &str = "2D_HSM_VSOCK_CID";
pub const TWOD_HSM_VSOCK_PORT: &str = "TWOD_HSM_VSOCK_PORT";
pub const LEGACY_HSM_VSOCK_PORT: &str = "2D_HSM_VSOCK_PORT";

// TASK-7.7 5b-2: the enclave-initiated anti-rollback boot-relay endpoint port (distinct from the serve
// port above; the enclave dials host CID 2 on this to reach the anchor relay). Default 5001.
pub const TWOD_HSM_ANCHOR_RELAY_PORT: &str = "TWOD_HSM_ANCHOR_RELAY_PORT";
pub const LEGACY_HSM_ANCHOR_RELAY_PORT: &str = "2D_HSM_ANCHOR_RELAY_PORT";

// TASK-7.7 5b-2b-ii(b): the UNTRUSTED host relay's upstream anchor endpoint (host:port). NO default
// — a missing anchor is a fail-closed boot error, never a silent localhost guess. Host-side only.
pub const TWOD_HSM_ANCHOR_ENDPOINT: &str = "TWOD_HSM_ANCHOR_ENDPOINT";
pub const LEGACY_HSM_ANCHOR_ENDPOINT: &str = "2D_HSM_ANCHOR_ENDPOINT";

pub const TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE: &str = "TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE";
pub const LEGACY_HSM_PRODUCER_ATTESTATION_TRUST_FILE: &str = "2D_HSM_PRODUCER_ATTESTATION_TRUST_FILE";

pub const TWOD_HSM_PQ_SEAL_V1_ROOT_FILE: &str = "TWOD_HSM_PQ_SEAL_V1_ROOT_FILE";
pub const LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE: &str = "2D_HSM_PQ_SEAL_V1_ROOT_FILE";

pub const TWOD_HSM_ENCLAVE_SOCKET: &str = "TWOD_HSM_ENCLAVE_SOCKET";
pub const LEGACY_HSM_ENCLAVE_SOCKET: &str = "2D_HSM_ENCLAVE_SOCKET";

pub const TWOD_HSM_ENCLAVE_STAGING_SOCKET: &str = "TWOD_HSM_ENCLAVE_STAGING_SOCKET";
pub const LEGACY_HSM_ENCLAVE_STAGING_SOCKET: &str = "2D_HSM_ENCLAVE_STAGING_SOCKET";

pub const TWOD_HSM_PQ_SEALED_SIGNER_FILE: &str = "TWOD_HSM_PQ_SEALED_SIGNER_FILE";
pub const LEGACY_HSM_PQ_SEALED_SIGNER_FILE: &str = "2D_HSM_PQ_SEALED_SIGNER_FILE";

pub const TWOD_HSM_ENCLAVE_MEASUREMENT_FILE: &str = "TWOD_HSM_ENCLAVE_MEASUREMENT_FILE";
pub const LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE: &str = "2D_HSM_ENCLAVE_MEASUREMENT_FILE";

/// When `1`, allow boot without platform PQ root (transport-only smoke; NOT mainnet).
pub const TWOD_HSM_TRANSPORT_ONLY_MODE: &str = "TWOD_HSM_TRANSPORT_ONLY_MODE";
pub const LEGACY_HSM_TRANSPORT_ONLY_MODE: &str = "2D_HSM_TRANSPORT_ONLY_MODE";

pub fn transport_only_mode_enabled() -> bool {
    var_twod(TWOD_HSM_TRANSPORT_ONLY_MODE, LEGACY_HSM_TRANSPORT_ONLY_MODE)
        .ok()
        .as_deref()
        == Some("1")
}
