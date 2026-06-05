//! Unix domain socket server — **staging** profile (TASK-1 slice).
//!
//! Like `enclave-uds-server` but built with `staging-host`: installs the reference ML-DSA-65
//! sealed signer at boot (fail-closed SIGN without seal). **Not for production.**

use enclave_protocol::enclave_serve::{
    configure_unix_session_timeouts, run_incoming_accept_loop, SharedEnclaveRuntime,
};
use enclave_protocol::{
    bind_unix_listener, default_dev_socket_dir, is_sealed_signer_installed, pq_signing_ready,
};
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-uds-staging: {e}");
        std::process::exit(1);
    }
}

fn default_socket_path() -> PathBuf {
    default_dev_socket_dir().join("enclave-staging.sock")
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    use enclave_protocol::env_config::{
        var_twod, LEGACY_HSM_ENCLAVE_STAGING_SOCKET, TWOD_HSM_ENCLAVE_STAGING_SOCKET,
    };
    let path = match var_twod(TWOD_HSM_ENCLAVE_STAGING_SOCKET, LEGACY_HSM_ENCLAVE_STAGING_SOCKET) {
        Ok(p) => PathBuf::from(p),
        Err(std::env::VarError::NotPresent) => default_socket_path(),
        Err(e) => return Err(e.into()),
    };
    let private_dir = default_dev_socket_dir();
    let listener = bind_unix_listener(&path, &private_dir)?;

    let runtime = SharedEnclaveRuntime::staging_with_reference_signer()?;
    eprintln!(
        "enclave-uds-staging listening on {} (ML-DSA sealed signer installed={}, pq_signing_ready={})",
        path.display(),
        is_sealed_signer_installed(),
        pq_signing_ready()
    );

    run_incoming_accept_loop(listener.incoming(), runtime, configure_unix_session_timeouts);
    Ok(())
}