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
fn load_attestation_trust() -> Result<enclave_protocol::ProducerAttestationTrust, Box<dyn std::error::Error>> {
    use enclave_protocol::ProducerAttestationTrust;
    use std::env;
    use std::fs;

    let path = env::var("2D_HSM_PRODUCER_ATTESTATION_TRUST_FILE").map_err(|_| {
        "2D_HSM_PRODUCER_ATTESTATION_TRUST_FILE must point to a 32-byte Ed25519 verifying key"
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
    use enclave_protocol::enclave_serve::{serve_framed_connection, SharedEnclaveRuntime};
    use enclave_protocol::platform_provisioning_boot::boot_configure_pq_seal_v1_platform_root;
    use enclave_protocol::vsock_listen::{bind_vsock_listener, vsock_listen_addr_from_env};
    use enclave_protocol::{is_sealed_signer_installed, pq_signing_ready};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    match boot_configure_pq_seal_v1_platform_root() {
        Ok(()) => eprintln!("enclave-vsock: PQ seal v1 provisioning root configured"),
        Err(e) => eprintln!("enclave-vsock: platform provisioning root not configured: {e}"),
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