//! Unix domain socket server — dev transport matching vsock framing (TASK-2 Phase 4).
//!
//! **Dev only:** one shared [`EnclaveState`] per server process (all connections), matching a
//! single enclave instance. Socket under `~/.2d-hsm/` (parent `0700`), mode `0600`.
//! Any same-UID process that can open the socket may issue ARM/SIGN — not a production auth boundary.

use enclave_protocol::enclave_serve::{
    configure_unix_session_timeouts, run_incoming_accept_loop, SharedEnclaveRuntime,
    MAX_CONCURRENT_SESSIONS,
};
use enclave_protocol::{bind_unix_listener, default_dev_socket_dir};
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    if let Err(e) = run() {
        eprintln!("enclave-uds-server: {e}");
        std::process::exit(1);
    }
}

fn default_socket_path() -> PathBuf {
    default_dev_socket_dir().join("enclave.sock")
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    use enclave_protocol::env_config::{
        var_twod, LEGACY_HSM_ENCLAVE_SOCKET, TWOD_HSM_ENCLAVE_SOCKET,
    };
    let path = match var_twod(TWOD_HSM_ENCLAVE_SOCKET, LEGACY_HSM_ENCLAVE_SOCKET) {
        Ok(p) => PathBuf::from(p),
        Err(std::env::VarError::NotPresent) => default_socket_path(),
        Err(e) => return Err(e.into()),
    };
    let private_dir = default_dev_socket_dir();
    let listener = bind_unix_listener(&path, &private_dir)?;
    eprintln!(
        "enclave-uds-server listening on {} (mode 0600, shared enclave state, max {} connections)",
        path.display(),
        MAX_CONCURRENT_SESSIONS
    );

    let runtime = Arc::new(SharedEnclaveRuntime::reference_test());
    run_incoming_accept_loop(listener.incoming(), runtime, configure_unix_session_timeouts);
    Ok(())
}