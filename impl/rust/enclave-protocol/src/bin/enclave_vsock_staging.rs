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
    use enclave_protocol::enclave_serve::{serve_framed_connection, SharedEnclaveRuntime};
    use enclave_protocol::{
        install_reference_sealed_signer_staging, is_sealed_signer_installed, pq_signing_ready,
        reference_test_attestation_trust,
    };
    use enclave_protocol::vsock_listen::{bind_vsock_listener, vsock_listen_addr_from_env};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

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

    struct SessionSlotGuard(Arc<AtomicUsize>);
    impl Drop for SessionSlotGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = match stream {
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
        thread::spawn(move || {
            let _guard = SessionSlotGuard(active);
            if let Err(e) = serve_framed_connection(&mut stream, &runtime) {
                eprintln!("session error: {e}");
            }
        });
    }
    Ok(())
}