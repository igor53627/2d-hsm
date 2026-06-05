//! Shared connection loop for stateful enclave transports (UDS, vsock).
//!
//! Poisoned [`EnclaveState`] mutex: `process::exit(1)` for supervisor restart (fail-closed).
//! `exit` skips destructors; PQ secrets rely on TEE teardown, not `Drop` zeroization here.

use crate::{
    process_framed_with_shared_state, read_framed_message_with_idle_deadline, write_framed_message,
    EnclaveState, ProducerAttestationTrust, ProtocolError,
};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_CONCURRENT_SESSIONS: usize = 32;
/// Max idle time between complete frames on one connection (slowloris bound).
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Socket read timeout must be at least the inter-frame idle budget (see serve_framed_connection).
pub const READ_TIMEOUT: Duration = SESSION_IDLE_TIMEOUT;
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// One enclave process: shared authorization state across all transport connections.
pub struct SharedEnclaveRuntime {
    pub state: Arc<Mutex<EnclaveState>>,
    pub attestation_trust: ProducerAttestationTrust,
}

impl SharedEnclaveRuntime {
    pub fn new(attestation_trust: ProducerAttestationTrust) -> Self {
        Self {
            state: Arc::new(Mutex::new(EnclaveState::Unarmed)),
            attestation_trust,
        }
    }

    /// Dev / `test-support` UDS server: reference Ed25519 attestation trust anchor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reference_test() -> Self {
        Self::new(crate::reference_test_attestation_trust())
    }
}

struct SessionSlotGuard(Arc<AtomicUsize>);

impl Drop for SessionSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Blocking accept loop: one thread per connection, capped at [`MAX_CONCURRENT_SESSIONS`].
///
/// `prepare_connection` runs on the accept thread before spawn (e.g. socket I/O timeouts).
/// Rejected connections (cap or setup failure) are dropped explicitly.
pub fn run_incoming_accept_loop<I, S, F>(
    incoming: I,
    runtime: Arc<SharedEnclaveRuntime>,
    mut prepare_connection: F,
)
where
    I: Iterator<Item = Result<S, std::io::Error>>,
    S: Read + Write + Send + 'static,
    F: FnMut(&mut S) -> Result<(), ProtocolError>,
{
    let active = Arc::new(AtomicUsize::new(0));
    for stream in incoming {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        if let Err(e) = prepare_connection(&mut stream) {
            eprintln!("connection setup failed: {e}");
            continue;
        }
        let prev = active.fetch_add(1, Ordering::Relaxed);
        if prev >= MAX_CONCURRENT_SESSIONS {
            active.fetch_sub(1, Ordering::Relaxed);
            eprintln!("rejecting connection: at session cap");
            drop(stream);
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
}

/// Apply UDS session I/O timeouts (must be at least [`READ_TIMEOUT`] for idle framing).
#[cfg(unix)]
pub fn configure_unix_session_timeouts(stream: &mut std::os::unix::net::UnixStream) -> Result<(), ProtocolError> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(())
}

/// Serve framed host requests on one connection until EOF, timeout, or I/O error.
pub fn serve_framed_connection<S>(stream: &mut S, runtime: &SharedEnclaveRuntime) -> Result<(), ProtocolError>
where
    S: Read + Write,
{
    let mut idle_deadline = Instant::now() + SESSION_IDLE_TIMEOUT;
    loop {
        let frame = match read_framed_message_with_idle_deadline(stream, Some(idle_deadline)) {
            Ok(f) => f,
            Err(ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            }
            // Oversize length prefix: request type unknown; close without an application frame.
            Err(ProtocolError::MessageTooLarge(_)) => break,
            Err(e) => return Err(e),
        };
        idle_deadline = Instant::now() + SESSION_IDLE_TIMEOUT;
        let mut state = lock_enclave_state(&runtime.state)?;
        let response = process_framed_with_shared_state(
            &frame,
            &mut state,
            runtime.attestation_trust,
        )?;
        drop(state);
        write_framed_message(stream, &response)?;
    }
    Ok(())
}

/// Panic while holding this lock may leave [`EnclaveState`] inconsistent — fail closed via process exit.
fn lock_enclave_state(
    state: &Arc<Mutex<EnclaveState>>,
) -> Result<std::sync::MutexGuard<'_, EnclaveState>, ProtocolError> {
    match state.lock() {
        Ok(guard) => Ok(guard),
        Err(_) => {
            eprintln!(
                "FATAL: shared enclave state mutex poisoned — exiting for supervisor restart"
            );
            std::process::exit(1);
        }
    }
}