//! TASK-7.7 5b-2d integration: drive `unseal_agent_keystore_at_boot()` end-to-end from the COMMITTED
//! genesis golden blob on disk, via the real `TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE` env + the lab root-step.
//!
//! This keeps the (otherwise dead-code-until-5b-2c) loader CI-type-checked AND behaviorally exercised
//! through the actual public surface — mirrors `tests/host_anchor_relay_bin.rs`. As a separate crate the
//! library is compiled WITHOUT `cfg(test)`, so `resolve_provisioning_root` has no reference-root fallback;
//! the test sets the root explicitly via `boot_configure_agent_seal_root` (one test → no install-once /
//! process-global race; the integration crate can't call the `#[cfg(test)]` resets).
#![cfg(all(feature = "agent-gateway", feature = "lab-agent-keystore-from-file"))]

use enclave_protocol::env_config::{
    LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE, LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE,
    LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE, TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
    TWOD_HSM_ENCLAVE_MEASUREMENT_FILE, TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
};
use enclave_protocol::{
    boot_configure_agent_seal_root, unseal_agent_keystore_at_boot,
    AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
};

#[test]
fn deterministic_golden_loader_unseals_committed_blob() {
    // Clean slate: as a separate crate we can't call the lib's #[cfg(test)] env reset, and the measurement
    // var is SHARED with the producer flow — an AMBIENT TWOD_HSM_ENCLAVE_MEASUREMENT_FILE (or its legacy
    // alias) would override the placeholder fallback the golden was sealed under (-> MeasurementMismatch ->
    // a spurious failure). Scrub the measurement vars (relied-upon absence) + the vars we set.
    for k in [
        TWOD_HSM_ENCLAVE_MEASUREMENT_FILE,
        LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE,
        TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
        LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE,
        TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
        LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE,
    ] {
        std::env::remove_var(k);
    }
    // The committed genesis blob is sealed under the reference provisioning root + the agent placeholder
    // measurement (see boot_agent_keystore::tests). Set the root explicitly (no cfg(test) fallback here).
    let root: &[u8; 32] = include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
    let dir = tempfile::tempdir().unwrap();
    let rpath = dir.path().join("root.bin");
    std::fs::write(&rpath, root).unwrap();
    std::env::set_var(TWOD_HSM_PQ_SEAL_V1_ROOT_FILE, &rpath);
    boot_configure_agent_seal_root().expect("set the agent provisioning root before unseal");

    let blob_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testvectors/agent-gateway/agent_keystore_genesis_v2.sealed.bin"
    );
    std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, blob_path);
    // No measurement file is set → the placeholder fallback (the value the golden was sealed under).

    let (body, measurement) =
        unseal_agent_keystore_at_boot().expect("committed genesis golden unseals from disk");

    assert_eq!(measurement, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT);
    assert_eq!(body.config.twod_chain_id, 11565);
    assert_eq!(body.config.environment_identifier, "testnet");
    assert_eq!(body.config.backup_recovery_wrapping_pubkey.len(), 1568);
    assert_eq!(body.structural_version, 1, "genesis structural_version");
    assert_eq!(
        body.strict_recovery_counter, 0,
        "genesis strict_recovery_counter"
    );
    assert_eq!(body.freshness_epoch, 1);
    assert!(body.entries.is_empty(), "genesis has no key entries");
    assert!(body.counters.is_empty(), "genesis has no counter rows");
}
