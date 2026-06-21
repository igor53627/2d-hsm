//! AF_VSOCK server — **production** profile (`production-vsock`).
//!
//! Linux only. Requires a pinned producer attestation trust anchor at boot (32-byte
//! Ed25519 verifying key file). PQ seal provisioning and sealed signer install are
//! platform responsibilities (see `platform_provisioning_boot` and vsock spec §2.2).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("enclave-vsock: requires Linux (AF_VSOCK)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-vsock: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn load_attestation_trust(
) -> Result<enclave_protocol::ProducerAttestationTrust, Box<dyn std::error::Error>> {
    use enclave_protocol::ProducerAttestationTrust;
    use std::env;
    use std::fs;

    use enclave_protocol::env_config::{
        var_twod, LEGACY_HSM_PRODUCER_ATTESTATION_TRUST_FILE,
        TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE,
    };
    let path = var_twod(
        TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE,
        LEGACY_HSM_PRODUCER_ATTESTATION_TRUST_FILE,
    )
    .map_err(|_| {
        "TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE must point to a 32-byte Ed25519 verifying key"
    })?;
    let bytes = fs::read(path)?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "producer attestation trust file must be exactly 32 bytes")?;
    Ok(ProducerAttestationTrust::from_verifying_key_bytes(&key)?)
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use enclave_protocol::enclave_serve::{run_incoming_accept_loop, SharedEnclaveRuntime};
    use enclave_protocol::platform_provisioning_boot::boot_configure_pq_seal_v1_platform_root;
    use enclave_protocol::vsock_listen::{
        bind_vsock_listener, configure_vsock_session_timeouts, vsock_listen_addr_from_env,
    };
    use enclave_protocol::{is_sealed_signer_installed, pq_signing_ready, ProtocolError};
    use std::sync::Arc;

    #[cfg(feature = "lab-pq-seal-from-file")]
    {
        boot_configure_pq_seal_v1_platform_root()
            .map_err(|e| format!("PQ seal provisioning root: {e}"))?;
        enclave_protocol::boot_lab_pq_seal::boot_install_lab_sealed_signer_from_file()
            .map_err(|e| format!("lab sealed PQ signer: {e}"))?;
        eprintln!("enclave-vsock: lab PQ seal root + sealed signer configured");
    }
    #[cfg(all(not(feature = "lab-pq-seal-from-file"), release_build))]
    {
        boot_configure_pq_seal_v1_platform_root().map_err(|e| {
            format!("PQ platform provisioning root required in release builds: {e}")
        })?;
        eprintln!("enclave-vsock: PQ seal v1 provisioning root configured");
    }
    #[cfg(all(not(feature = "lab-pq-seal-from-file"), not(release_build)))]
    {
        use enclave_protocol::env_config::transport_only_mode_enabled;
        match boot_configure_pq_seal_v1_platform_root() {
            Ok(()) => eprintln!("enclave-vsock: PQ seal v1 provisioning root configured"),
            Err(e) if transport_only_mode_enabled() => {
                eprintln!(
                    "enclave-vsock: transport-only mode (TWOD_HSM_TRANSPORT_ONLY_MODE=1); \
                     PQ signing unavailable until platform hook: {e}"
                );
            }
            Err(e) => {
                return Err(format!(
                    "PQ platform provisioning root required (set TWOD_HSM_TRANSPORT_ONLY_MODE=1 only for non-release lab smoke): {e}"
                )
                .into());
            }
        }
    }

    // TASK-5 Phase 3 (AC#4): capture the real SNP launch measurement bound to the installed PQ key
    // so GET_MEASUREMENT reports it. Best-effort — on KVM/dev or without the sev-guest TSM provider
    // it logs and continues, and GET_MEASUREMENT keeps the placeholder (graceful fallback).
    let snp_captured = match enclave_protocol::boot_capture_snp_measurement() {
        Ok(()) => {
            eprintln!("enclave-vsock: SNP launch measurement captured (attested GET_MEASUREMENT)");
            true
        }
        Err(e) => {
            eprintln!("enclave-vsock: SNP measurement capture failed: {e}");
            false
        }
    };
    // Fail-closed in release builds: refuse to serve an operational PQ signer with a placeholder
    // measurement/attestation (a host could otherwise block SNP/configfs to fake attestation).
    // Dev/lab (debug) builds and the transport-only case continue with the placeholder.
    enclave_protocol::snp_attestation_boot_gate(
        cfg!(release_build),
        is_sealed_signer_installed(),
        snp_captured,
    )
    .map_err(|e| format!("enclave-vsock: {e}"))?;
    if !snp_captured {
        eprintln!(
            "enclave-vsock: continuing with placeholder GET_MEASUREMENT (non-release / no operational signer)"
        );
    }

    let (cid, port) = vsock_listen_addr_from_env()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listener = bind_vsock_listener(cid, port)?;
    let trust = load_attestation_trust()?;
    let runtime = Arc::new(SharedEnclaveRuntime::new(trust));

    eprintln!(
        "enclave-vsock listening on vsock cid={cid} port={port} (sealed_signer_installed={}, pq_signing_ready={})",
        is_sealed_signer_installed(),
        pq_signing_ready()
    );

    run_incoming_accept_loop(listener.incoming(), runtime, |stream| {
        configure_vsock_session_timeouts(stream).map_err(ProtocolError::from)
    });
    Ok(())
}
