//! (5b-2c) agent-gateway AF_VSOCK serve bin (TASK-7.7 anti-rollback profile).
//!
//! The 2-statement dispatch-first shape (mirrors `twod_hsm_quote_smoke.rs`, which named itself the
//! future 5b-2c shape): the FIRST statement is the unconditional `agent_quote_child_dispatch()` re-exec
//! hook — a spawned quote child (the production `HardBoundedQuoteProducer` re-execs `/proc/self/exe`)
//! re-enters this main and NEVER returns from that line, so NOTHING may print before it (a stdout write
//! before dispatch, or moving dispatch down, would silently boot a SECOND full gateway in the child).
//! Then it forwards to the SOLE `pub` lib boot entrypoint `run_agent_gateway_boot`, which owns the whole
//! boot sequence + the stderr→journald logging + rendering the returned `ProtocolError` at err priority;
//! the bin only maps the exit code. `run_agent_gateway_boot` returns `Result<Infallible, _>` — `Ok` is
//! unconstructible (the serve loop diverges), so a clean return means the boot fail-closed and the bin
//! exits 1 (the library already rendered the cause). Dispatch-first + PROTOCOL-ONLY stdout are
//! CI-enforced by `tests/twod_hsm_agent_gateway_bin.rs`.

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("twod-hsm-agent-gateway: requires Linux (AF_VSOCK)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    // §8 dispatch-first contract: FIRST statement, unconditional. A spawned quote child re-enters this
    // main and never returns from this line. NOTHING may print before it.
    enclave_protocol::agent_quote_child_dispatch();
    match enclave_protocol::run_agent_gateway_boot() {
        // `Ok` is uninhabited (`Infallible`): the serve loop diverges, so this arm is unreachable.
        Ok(never) => match never {},
        // The library already rendered the cause at err priority (wrapper-internal sink) — exit 1.
        Err(_) => std::process::ExitCode::from(1),
    }
}
