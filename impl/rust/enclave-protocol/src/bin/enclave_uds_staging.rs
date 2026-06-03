//! Unix domain socket server — **staging** profile (TASK-1 slice).
//!
//! Like `enclave-uds-server` but built with `staging-host`: installs the reference ML-DSA-65
//! sealed signer at boot (fail-closed SIGN without seal). **Not for production.**

use enclave_protocol::{
    bind_unix_listener, default_dev_socket_dir, install_reference_sealed_signer_staging,
    is_sealed_signer_installed, process_framed_with_shared_state, pq_signing_ready,
    read_framed_message, reference_test_attestation_trust, write_framed_message, EnclaveState,
    ProducerAttestationTrust,
};
use std::env;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_CONCURRENT_SESSIONS: usize = 32;
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

struct SharedEnclaveRuntime {
    state: Arc<Mutex<EnclaveState>>,
    attestation_trust: ProducerAttestationTrust,
}

impl SharedEnclaveRuntime {
    fn staging() -> Result<Self, enclave_protocol::ProtocolError> {
        install_reference_sealed_signer_staging()?;
        Ok(Self {
            state: Arc::new(Mutex::new(EnclaveState::Unarmed)),
            attestation_trust: reference_test_attestation_trust(),
        })
    }
}

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
    // Separate from dev `2D_HSM_ENCLAVE_SOCKET` so staging cannot unlink the mock server's socket.
    let path = env::var("2D_HSM_ENCLAVE_STAGING_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());
    let private_dir = default_dev_socket_dir();
    let listener = bind_unix_listener(&path, &private_dir)?;

    let runtime = Arc::new(SharedEnclaveRuntime::staging()?);
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
        if prev >= MAX_CONCURRENT_SESSIONS {
            active.fetch_sub(1, Ordering::Relaxed);
            eprintln!("rejecting connection: at session cap");
            continue;
        }
        let active = Arc::clone(&active);
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || {
            let _guard = SessionSlotGuard(active);
            if let Err(e) = handle_client(stream, runtime) {
                eprintln!("session error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_client(
    mut stream: UnixStream,
    runtime: Arc<SharedEnclaveRuntime>,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    loop {
        let frame = match read_framed_message(&mut stream) {
            Ok(f) => f,
            Err(enclave_protocol::ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        };
        let mut state = runtime
            .state
            .lock()
            .map_err(|_| "shared enclave state mutex poisoned")?;
        let response = process_framed_with_shared_state(
            &frame,
            &mut state,
            runtime.attestation_trust,
        )?;
        drop(state);
        write_framed_message(&mut stream, &response)?;
    }
    Ok(())
}
