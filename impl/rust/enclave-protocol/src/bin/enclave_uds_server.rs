//! Unix domain socket server — dev transport matching vsock framing (TASK-2 Phase 4).
//!
//! **Dev only:** socket under `~/.2d-hsm/` (parent dir `0700`), mode `0600`, session cap.
//! Not a production enclave entrypoint (no peer auth).

use enclave_protocol::{
    process_framed_with_session, read_framed_message, write_framed_message, HostSession,
};
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_CONCURRENT_SESSIONS: usize = 32;
const READ_TIMEOUT: Duration = Duration::from_secs(120);

struct SessionSlotGuard(Arc<AtomicUsize>);

impl Drop for SessionSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-uds-server: {e}");
        std::process::exit(1);
    }
}

fn default_socket_path() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join(".2d-hsm")
        .join("enclave.sock")
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::var("2D_HSM_ENCLAVE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_socket_path());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // Only harden permissions on the default app dir (~/.2d-hsm), not arbitrary env paths.
        if Some(parent) == default_socket_path().parent() {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    eprintln!(
        "enclave-uds-server listening on {} (mode 0600, max {} sessions)",
        path.display(),
        MAX_CONCURRENT_SESSIONS
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
        thread::spawn(move || {
            let _guard = SessionSlotGuard(active);
            if let Err(e) = handle_client(stream) {
                eprintln!("session error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut session = HostSession::reference_test();
    loop {
        let frame = match read_framed_message(&mut stream) {
            Ok(f) => f,
            Err(enclave_protocol::ProtocolError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        };
        let response = process_framed_with_session(&frame, &mut session)?;
        write_framed_message(&mut stream, &response)?;
    }
    Ok(())
}