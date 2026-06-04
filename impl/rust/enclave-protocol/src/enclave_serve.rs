//! Shared connection loop for stateful enclave transports (UDS, vsock, stdio-session).

use crate::{
    process_framed_with_shared_state, read_framed_message, write_framed_message, EnclaveState,
    ProducerAttestationTrust, ProtocolError,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_CONCURRENT_SESSIONS: usize = 32;
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Wall-clock cap per connection (slowloris / byte-at-a-time idle reads).
pub const SESSION_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);

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
    let session_deadline = Instant::now() + SESSION_TOTAL_TIMEOUT;
    loop {
        let frame = match read_framed_message_before(stream, session_deadline) {
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

fn read_framed_message_before<R: Read>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Vec<u8>, ProtocolError> {
    use crate::ProtocolError;
    use std::io::{ErrorKind, Read};

    let mut len_buf = [0u8; 4];
    read_exact_before_deadline(reader, &mut len_buf, deadline)?;
    let total_len = u32::from_be_bytes(len_buf) as usize;
    if total_len > crate::MAX_MESSAGE_SIZE as usize {
        return Err(ProtocolError::MessageTooLarge(total_len as u32));
    }
    let mut body = vec![0u8; total_len];
    read_exact_before_deadline(reader, &mut body, deadline)?;
    let mut frame = Vec::with_capacity(4 + total_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn read_exact_before_deadline<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), ProtocolError> {
    use std::io::{ErrorKind, Read};

    let mut off = 0;
    while off < buf.len() {
        if Instant::now() >= deadline {
            return Err(ProtocolError::Io(std::io::Error::new(
                ErrorKind::TimedOut,
                "session total timeout exceeded",
            )));
        }
        match reader.read(&mut buf[off..]) {
            Ok(0) => {
                return Err(ProtocolError::Io(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "connection closed while reading frame",
                )));
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProtocolError::from(e)),
        }
    }
    Ok(())
}