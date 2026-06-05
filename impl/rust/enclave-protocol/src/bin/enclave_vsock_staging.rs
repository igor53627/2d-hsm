//! AF_VSOCK server — **staging** profile (TASK-1 / production transport slice).
//!
//! Linux only. Same framing and shared `EnclaveState` as `enclave-uds-staging`, on vsock.
//! **Not for production deployment** (`staging-host` embeds reference keys).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("enclave-vsock-staging: requires Linux (AF_VSOCK)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-vsock-staging: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use enclave_protocol::enclave_serve::{run_incoming_accept_loop, SharedEnclaveRuntime};
    use enclave_protocol::{
        install_reference_sealed_signer_staging, is_sealed_signer_installed, pq_signing_ready,
        reference_test_attestation_trust, ProtocolError,
    };
    use enclave_protocol::vsock_listen::{
        bind_vsock_listener, configure_vsock_session_timeouts, vsock_listen_addr_from_env,
    };
    use std::sync::Arc;

    let (cid, port) = vsock_listen_addr_from_env()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listener = bind_vsock_listener(cid, port)?;

    install_reference_sealed_signer_staging()?;
    let runtime = Arc::new(SharedEnclaveRuntime::new(reference_test_attestation_trust()));
    eprintln!(
        "enclave-vsock-staging listening on vsock cid={cid} port={port} (installed={}, pq_signing_ready={})",
        is_sealed_signer_installed(),
        pq_signing_ready()
    );

    run_incoming_accept_loop(listener.incoming(), runtime, |stream| {
        configure_vsock_session_timeouts(stream).map_err(ProtocolError::from)
    });
    Ok(())
}