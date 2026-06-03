//! Shared connection loop for stateful enclave transports (UDS, vsock, stdio-session).

use crate::{
    process_framed_with_shared_state, read_framed_message, write_framed_message, EnclaveState,
    ProducerAttestationTrust, ProtocolError,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MAX_CONCURRENT_SESSIONS: usize = 32;
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);
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
}

/// Serve framed host requests on one connection until EOF, timeout, or I/O error.
pub fn serve_framed_connection<S>(stream: &mut S, runtime: &SharedEnclaveRuntime) -> Result<(), ProtocolError>
where
    S: Read + Write,
{
    loop {
        let frame = match read_framed_message(stream) {
            Ok(f) => f,
            Err(ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            }
            Err(e) => return Err(e),
        };
        let mut state = runtime
            .state
            .lock()
            .map_err(|_| ProtocolError::PqSigningUnavailable("shared enclave state mutex poisoned"))?;
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