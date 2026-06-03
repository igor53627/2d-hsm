//! Platform provisioning root at enclave boot (production path).
//!
//! Production images call [`set_pq_seal_v1_provisioning_root`] from vTPM / SNP / Nitro integration.
//! This module provides a single boot entrypoint and an optional file-based loader for local labs.

use crate::pq_signer::set_pq_seal_v1_provisioning_root;
use crate::ProtocolError;

/// Configure the PQ seal v1 provisioning root once at enclave boot (before `install_sealed_pq_signer`).
///
/// Production: link a platform hook or call [`set_pq_seal_v1_provisioning_root`] directly from
/// Nitro/SEV startup code. With feature `platform-provisioning-from-file`, reads
/// `2D_HSM_PQ_SEAL_V1_ROOT_FILE` (32 raw bytes) for integration testing only.
#[cfg(feature = "ml-dsa-65")]
pub fn boot_configure_pq_seal_v1_platform_root() -> Result<(), ProtocolError> {
    let root = derive_platform_provisioning_root_v1()?;
    set_pq_seal_v1_provisioning_root(root)
}

#[cfg(feature = "ml-dsa-65")]
fn derive_platform_provisioning_root_v1() -> Result<[u8; 32], ProtocolError> {
    #[cfg(feature = "platform-provisioning-from-file")]
    {
        use std::env;
        let path = env::var("2D_HSM_PQ_SEAL_V1_ROOT_FILE").map_err(|_| {
            ProtocolError::PqSigningUnavailable(
                "2D_HSM_PQ_SEAL_V1_ROOT_FILE not set (expected path to 32-byte provisioning root)",
            )
        })?;
        return read_provisioning_root_file(path.as_ref());
    }
    #[cfg(not(feature = "platform-provisioning-from-file"))]
    {
        let _ = ();
        Err(ProtocolError::PqSigningUnavailable(
            "platform PQ seal v1 provisioning root hook not configured (integrate vTPM/SNP/Nitro or enable platform-provisioning-from-file for labs)",
        ))
    }
}

#[cfg(all(feature = "ml-dsa-65", feature = "platform-provisioning-from-file"))]
fn read_provisioning_root_file(path: &std::path::Path) -> Result<[u8; 32], ProtocolError> {
    let bytes = std::fs::read(path).map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "failed to read 2D_HSM_PQ_SEAL_V1_ROOT_FILE provisioning root",
        )
    })?;
    bytes.try_into().map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "provisioning root file must be exactly 32 bytes",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_signer::{
        is_platform_pq_seal_v1_provisioning_root_set, SealedSignerTestGuard,
    };

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
