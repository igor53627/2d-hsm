//! Shared connection loop for stateful enclave transports (UDS, vsock).
//!
//! Poisoned [`EnclaveState`] mutex: `process::exit(1)` for supervisor restart (fail-closed).
//! `exit` skips destructors; PQ secrets rely on TEE teardown, not `Drop` zeroization here.

use crate::{
    decode_message, is_wire_error_payload, process_framed_with_shared_state,
    read_framed_message_with_idle_deadline, write_framed_message, EnclaveState,
    ProducerAttestationTrust, ProtocolError,
};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_CONCURRENT_SESSIONS: usize = 32;
/// Max idle time between **successful** application frames on one connection (slowloris bound).
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-syscall read timeout (shorter than session idle; `read_exact_with_idle_deadline` also checks the idle instant).
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Backoff after an `accept(2)` ERROR to cap an EMFILE/ENFILE busy-spin: under fd exhaustion the kernel
/// fails accept IMMEDIATELY without draining the backlog entry, so a bare log+continue would tight-spin a
/// core + flood stderr until fds free elsewhere. SINGLE SOURCE for every serial accept loop (the agent
/// serve loop AND the (b) host-anchor relay) so the anti-spin value can never silently diverge between
/// them. Accept errors are rare for AF_VSOCK, so this never delays the steady state.
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

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

    /// Staging vsock/UDS: install reference sealed signer + reference attestation trust.
    #[cfg(feature = "staging-host")]
    pub fn staging_with_reference_signer() -> Result<Arc<Self>, ProtocolError> {
        crate::install_reference_sealed_signer_staging()?;
        Ok(Arc::new(Self::new(crate::reference_test_attestation_trust())))
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
            Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            // Session idle exhausted (see read_exact_with_idle_deadline); per-read retries stay inner.
            Err(ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break
            }
            // Oversize length prefix: request type unknown; close without an application frame.
            Err(ProtocolError::MessageTooLarge(_)) => break,
            Err(e) => return Err(e),
        };
        let mut state = lock_enclave_state(&runtime.state)?;
        let response = process_framed_with_shared_state(
            &frame,
            &mut state,
            runtime.attestation_trust,
        )?;
        drop(state);
        write_framed_message(stream, &response)?;
        // Wire-error responses are still "complete frames" but must not extend the idle budget
        // (otherwise a peer can hold a slot by dribbling parseable garbage forever).
        let reset_idle = decode_message(&response)
            .map(|framed| !is_wire_error_payload(&framed.payload))
            .unwrap_or(false);
        if reset_idle {
            idle_deadline = Instant::now() + SESSION_IDLE_TIMEOUT;
        }
    }
    Ok(())
}

/// Generic per-connection framed-request PUMP (TASK-7.7 5b-2c-ii): the body of
/// [`serve_framed_connection`] EXTRACTED and parameterized over a frame handler — WITHOUT the producer's
/// `EnclaveState` lock, `ProducerAttestationTrust`, or `process::exit`-on-poison path. `handle_frame` does
/// the decode / type-guard / route / reframe and returns the framed reply; this kernel owns only the
/// inter-frame idle-deadline (slowloris bound), the break taxonomy (EOF / per-syscall timeout / oversize →
/// close), and the idle-reset-on-NON-error rule (a wire/agent-error reply must NOT extend the budget — else
/// a peer dribbles parseable-but-erroring frames forever; [`is_wire_error_payload`] is the predicate — NOT
/// the `#[cfg(test)]`-only `decode_agent_error_code`). NEVER panics, NEVER exits; the only non-break Err is a
/// handler/IO error → the caller closes this connection. Currently ONE caller (the agent serve loop, §8
/// 5b-2c-ii); the producer [`serve_framed_connection`] stays byte-identical this slice and converges onto
/// this kernel as a NAMED §8 follow-up (do not perturb the SNP-validated producer here).
pub fn serve_framed_pump<S, H>(
    stream: &mut S,
    mut handle_frame: H,
    idle_timeout: Duration,
) -> Result<(), ProtocolError>
where
    S: Read + Write,
    H: FnMut(&[u8]) -> Result<Vec<u8>, ProtocolError>,
{
    let mut idle_deadline = Instant::now() + idle_timeout;
    loop {
        let frame = match read_framed_message_with_idle_deadline(stream, Some(idle_deadline)) {
            Ok(f) => f,
            Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break
            }
            // Oversize length prefix: request type unknown; close without an application frame.
            Err(ProtocolError::MessageTooLarge(_)) => break,
            Err(e) => return Err(e),
        };
        let reply = handle_frame(&frame)?;
        write_framed_message(stream, &reply)?;
        // A NON-error reply extends the idle budget; a wire/agent-error reply must NOT (else a peer holds a
        // slot by dribbling parseable-but-erroring frames forever). See [`reply_resets_idle`].
        if reply_resets_idle(&reply) {
            idle_deadline = Instant::now() + idle_timeout;
        }
    }
    Ok(())
}

/// Does this self-encoded reply frame EXTEND the inter-frame idle budget? A reply extends it iff it is NOT
/// a wire/agent-error frame — a peer must not keep its slot alive by dribbling parseable-but-erroring
/// frames (the agent error band `0x40..=0x46` IS wire-error-shaped, so it correctly does NOT extend).
/// [`is_wire_error_payload`] is the predicate — NOT the `#[cfg(test)]`-only `decode_agent_error_code`
/// (which can't compile in prod). A decode failure or a sub-header reply conservatively does NOT extend
/// (treated like an error). EXTRACTED from the inline rule so the SUCCESS direction (extends) and the
/// ERROR direction (does not) are both directly, deterministically testable without driving a wall-clock
/// idle expiry. The producer [`serve_framed_connection`] keeps its byte-identical inline copy this slice
/// and converges onto this helper as the NAMED §8 follow-up (do not perturb the SNP-validated producer).
pub(crate) fn reply_resets_idle(reply: &[u8]) -> bool {
    decode_message(reply)
        .map(|framed| !is_wire_error_payload(&framed.payload))
        .unwrap_or(false)
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