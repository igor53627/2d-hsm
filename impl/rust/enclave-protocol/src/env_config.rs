//! Operator environment variable names (`TWOD_*` prefix).
//!
//! POSIX and **systemd** reject env keys that start with a digit, so use
//! `TWOD_HSM_*` instead of `2D_HSM_*` in unit files, cloud-init, and NixOS modules.
//! Reference binaries still accept deprecated `2D_HSM_*` names for one transition period.

/// Read `primary`, then deprecated `legacy` (`2D_HSM_*`).
pub fn var_twod(primary: &str, legacy: &str) -> Result<String, std::env::VarError> {
    std::env::var(primary).or_else(|_| std::env::var(legacy))
}

pub const TWOD_HSM_VSOCK_CID: &str = "TWOD_HSM_VSOCK_CID";
pub const LEGACY_HSM_VSOCK_CID: &str = "2D_HSM_VSOCK_CID";
pub const TWOD_HSM_VSOCK_PORT: &str = "TWOD_HSM_VSOCK_PORT";
pub const LEGACY_HSM_VSOCK_PORT: &str = "2D_HSM_VSOCK_PORT";

pub const TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE: &str = "TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE";
pub const LEGACY_HSM_PRODUCER_ATTESTATION_TRUST_FILE: &str = "2D_HSM_PRODUCER_ATTESTATION_TRUST_FILE";

pub const TWOD_HSM_PQ_SEAL_V1_ROOT_FILE: &str = "TWOD_HSM_PQ_SEAL_V1_ROOT_FILE";
pub const LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE: &str = "2D_HSM_PQ_SEAL_V1_ROOT_FILE";

pub const TWOD_HSM_ENCLAVE_SOCKET: &str = "TWOD_HSM_ENCLAVE_SOCKET";
pub const LEGACY_HSM_ENCLAVE_SOCKET: &str = "2D_HSM_ENCLAVE_SOCKET";

pub const TWOD_HSM_ENCLAVE_STAGING_SOCKET: &str = "TWOD_HSM_ENCLAVE_STAGING_SOCKET";
pub const LEGACY_HSM_ENCLAVE_STAGING_SOCKET: &str = "2D_HSM_ENCLAVE_STAGING_SOCKET";