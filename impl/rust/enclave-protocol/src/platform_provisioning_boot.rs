//! Platform provisioning root at enclave boot (production path).
//!
//! Production images call [`set_pq_seal_v1_provisioning_root`] from vTPM / SNP / Nitro integration.
//! This module provides a single boot entrypoint and an optional file-based loader for local labs.

#[cfg(feature = "ml-dsa-65")]
use crate::seal_root::set_pq_seal_v1_provisioning_root;
use crate::ProtocolError;

/// Configure the PQ seal v1 provisioning root once at enclave boot (before `install_sealed_pq_signer`).
///
/// Production: link a platform hook or call [`set_pq_seal_v1_provisioning_root`] directly from
/// Nitro/SEV startup code. With feature `platform-provisioning-from-file`, reads
/// `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE` (32 raw bytes) for integration testing only.
#[cfg(feature = "ml-dsa-65")]
pub fn boot_configure_pq_seal_v1_platform_root() -> Result<(), ProtocolError> {
    let root = derive_platform_provisioning_root_v1()?;
    set_pq_seal_v1_provisioning_root(root)
}

#[cfg(feature = "ml-dsa-65")]
fn derive_platform_provisioning_root_v1() -> Result<[u8; 32], ProtocolError> {
    // Production: read from the FIXED path written by `snp-derive-root --out` at boot.
    // NOT a host-settable env var — the host cannot redirect to a known root.
    #[cfg(feature = "platform-root-from-boot-file")]
    {
        return read_provisioning_root_file(std::path::Path::new(
            "/run/twod-hsm/pq-seal-root.bin",
        ));
    }
    // Lab: read from a host-settable env var (lab feature, release-banned).
    #[cfg(feature = "platform-provisioning-from-file")]
    {
        use crate::env_config::{
            var_twod, LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE, TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
        };
        let path = var_twod(TWOD_HSM_PQ_SEAL_V1_ROOT_FILE, LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE)
            .map_err(|_| {
                ProtocolError::PqSigningUnavailable(
                    "TWOD_HSM_PQ_SEAL_V1_ROOT_FILE not set (expected path to 32-byte provisioning root)",
                )
            })?;
        return read_provisioning_root_file(path.as_ref());
    }
    #[cfg(not(any(feature = "platform-provisioning-from-file", feature = "platform-root-from-boot-file")))]
    {
        Err(ProtocolError::PqSigningUnavailable(
            "platform PQ seal v1 provisioning root hook not configured (integrate vTPM/SNP/Nitro, enable platform-root-from-boot-file for the snp-derive-root boot path, or platform-provisioning-from-file for labs)",
        ))
    }
}

#[cfg(feature = "ml-dsa-65")]
fn read_provisioning_root_file(path: &std::path::Path) -> Result<[u8; 32], ProtocolError> {
    let bytes = crate::boot_input::read_boot_file(
        path,
        "failed to read provisioning root file",
    )?;
    bytes.try_into().map_err(|_| {
        ProtocolError::PqSigningUnavailable("provisioning root file must be exactly 32 bytes")
    })
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[cfg(feature = "ml-dsa-65")]
    use crate::pq_signer::SealedSignerTestGuard;
    use crate::seal_root::is_platform_pq_seal_v1_provisioning_root_set;

    #[cfg(all(
        feature = "ml-dsa-65",
        not(feature = "platform-provisioning-from-file"),
        not(feature = "reference-seal-v1-root")
    ))]
    #[test]
    fn boot_configure_errors_without_platform_hook() {
        let _guard = SealedSignerTestGuard::acquire();
        assert!(boot_configure_pq_seal_v1_platform_root().is_err());
        assert!(!is_platform_pq_seal_v1_provisioning_root_set());
    }

    #[cfg(all(feature = "ml-dsa-65", feature = "platform-provisioning-from-file"))]
    #[test]
    fn read_provisioning_root_file_accepts_32_bytes() {
        let _guard = SealedSignerTestGuard::acquire();
        let root = include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform_root.bin");
        std::fs::write(&path, root).unwrap();
        let loaded = read_provisioning_root_file(&path).unwrap();
        assert_eq!(loaded, *root);
        set_pq_seal_v1_provisioning_root(loaded).unwrap();
        assert!(is_platform_pq_seal_v1_provisioning_root_set());
    }
}
