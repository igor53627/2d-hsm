//! `twod-hsm-agent-contract-server` (TASK-23) — a DEVICELESS, cross-platform 0x40 agent-gateway
//! contract-test server over AF_UNIX, so downstream 2d (Elixir/macOS) can live-contract-test the
//! protocol (PUBLIC_IDENTITY now; signing/capability/configure behind the preview features).
//!
//! **TEST/DEV ONLY — NEVER a production endpoint.** It installs a reference keystore with PUBLIC dev
//! keys, runs NO SNP attestation and NO anti-rollback durability; its trust boundary is local file
//! permissions (socket 0600 / parent dir 0700) only. The `agent-contract-server` feature it requires is
//! release-banned (`lib.rs` `compile_error!`), so this bin cannot compile in a release build. The
//! production serve path is the AF_VSOCK + SNP `twod-hsm-agent-gateway` bin.
//!
//! Invocation (how 2d CI starts it): set `TWOD_HSM_AGENT_CONTRACT_SOCKET` to the desired UDS path
//! (default `/tmp/twod-hsm-agent-contract/agent.sock`); the parent dir is created 0700. Build/run with
//! `--features agent-gateway,agent-contract-server` (+ the relevant `agent-*-preview` features to reach
//! the signing/capability lanes). The process serves serially and runs until killed.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::path::PathBuf;

    let socket = std::env::var("TWOD_HSM_AGENT_CONTRACT_SOCKET")
        .unwrap_or_else(|_| "/tmp/twod-hsm-agent-contract/agent.sock".to_string());
    let socket = PathBuf::from(socket);
    let private_dir = socket
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/twod-hsm-agent-contract"));

    match enclave_protocol::contract_server::run_contract_server(&socket, &private_dir) {
        Err(e) => {
            eprintln!("[fatal] twod-hsm-agent-contract-server: {e:?}");
            std::process::ExitCode::FAILURE
        }
        // run_contract_server returns Infallible on success (serves forever); this arm is unreachable.
        Ok(never) => match never {},
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("twod-hsm-agent-contract-server requires a Unix platform (AF_UNIX)");
    std::process::ExitCode::from(2)
}
