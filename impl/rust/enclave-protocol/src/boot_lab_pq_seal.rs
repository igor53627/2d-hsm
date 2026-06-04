//! Lab-only: install sealed PQ signer from host-supplied files (never for mainnet).
//!
//! Requires `lab-pq-seal-from-file` + `platform-provisioning-from-file` and a **debug** build
//! (`platform-provisioning-from-file` is rejected in `release_build`).

/// Default measurement for lab prod guest (`GET_MEASUREMENT` production profile).
pub const LAB_PROD_MEASUREMENT: &[u8] = b"enclave-measurement-placeholder";

#[cfg(feature = "lab-pq-seal-from-file")]
pub fn boot_install_lab_sealed_signer_from_file() -> Result<(), crate::ProtocolError> {
    use crate::env_config::{
        var_twod, LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE, LEGACY_HSM_PQ_SEALED_SIGNER_FILE,
        TWOD_HSM_ENCLAVE_MEASUREMENT_FILE, TWOD_HSM_PQ_SEALED_SIGNER_FILE,
    };
    use crate::pq_signer::install_sealed_pq_signer;
    let blob_path = var_twod(TWOD_HSM_PQ_SEALED_SIGNER_FILE, LEGACY_HSM_PQ_SEALED_SIGNER_FILE)
        .map_err(|_| {
            crate::ProtocolError::PqSigningUnavailable(
                "TWOD_HSM_PQ_SEALED_SIGNER_FILE not set (lab prod guest)",
            )
        })?;
    let blob = std::fs::read(blob_path).map_err(|_| {
        crate::ProtocolError::PqSigningUnavailable("failed to read TWOD_HSM_PQ_SEALED_SIGNER_FILE")
    })?;
    let measurement = match var_twod(
        TWOD_HSM_ENCLAVE_MEASUREMENT_FILE,
        LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE,
    ) {
        Ok(path) => std::fs::read(path).map_err(|_| {
            crate::ProtocolError::PqSigningUnavailable(
                "failed to read TWOD_HSM_ENCLAVE_MEASUREMENT_FILE",
            )
        })?,
        Err(_) => LAB_PROD_MEASUREMENT.to_vec(),
    };
    if measurement.is_empty() {
        return Err(crate::ProtocolError::PqSigningUnavailable(
            "enclave measurement must be non-empty",
        ));
    }
    install_sealed_pq_signer(&blob, measurement.as_ref())
}