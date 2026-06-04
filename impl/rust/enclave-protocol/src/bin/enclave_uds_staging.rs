//! Unix domain socket server — **staging** profile (TASK-1 slice).
//!
//! Like `enclave-uds-server` but built with `staging-host`: installs the reference ML-DSA-65
//! sealed signer at boot (fail-closed SIGN without seal). **Not for production.**

use enclave_protocol::enclave_serve::{serve_framed_connection, SharedEnclaveRuntime};
use enclave_protocol::{
    bind_unix_listener, default_dev_socket_dir, install_reference_sealed_signer_staging,
    is_sealed_signer_installed, pq_signing_ready, reference_test_attestation_trust,
};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct SessionSlotGuard(Arc<AtomicUsize>);

impl Drop for SessionSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

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
    let path = var_twod(TWOD_HSM_ENCLAVE_STAGING_SOCKET, LEGACY_HSM_ENCLAVE_STAGING_SOCKET)
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());
    let private_dir = default_dev_socket_dir();
    let listener = bind_unix_listener(&path, &private_dir)?;

    install_reference_sealed_signer_staging()?;
    let runtime = Arc::new(SharedEnclaveRuntime::new(reference_test_attestation_trust()));
    eprintln!(
        "enclave-uds-staging listening on {} (ML-DSA sealed signer installed={}, pq_signing_ready={})",
        path.display(),
        is_sealed_signer_installed(),
        pq_signing_ready()
    );

    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let prev = active.fetch_add(1, Ordering::Relaxed);
        if prev >= enclave_protocol::enclave_serve::MAX_CONCURRENT_SESSIONS {
            active.fetch_sub(1, Ordering::Relaxed);
            eprintln!("rejecting connection: at session cap");
            continue;
        }
        let active = Arc::clone(&active);
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || handle_client(stream, runtime, active));
    }
    Ok(())
}

fn handle_client(
    stream: UnixStream,
    runtime: Arc<SharedEnclaveRuntime>,
    active: Arc<AtomicUsize>,
) {
    let _guard = SessionSlotGuard(active);
    let mut stream = stream;
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(120))) {
        eprintln!("session error: {e}");
        return;
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(120))) {
        eprintln!("session error: {e}");
        return;
    }
    if let Err(e) = serve_framed_connection(&mut stream, &runtime) {
        eprintln!("session error: {e}");
    }
}