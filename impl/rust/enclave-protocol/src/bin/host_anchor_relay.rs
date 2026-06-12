//! (b) host-relay daemon bin (TASK-7.7 5b-2b-ii(b)) — the UNTRUSTED host-side process that bridges the
//! SNP guest to the external anchor (notary) over TCP. Thin: resolve env config + call the library
//! `run_host_anchor_relay` (which binds AF_VSOCK CID_ANY, accepts serially, dials the anchor with a
//! bounded TCP connect, forwards verbatim via the existing `pub(crate)` relay core, closes-on-fault,
//! NEVER dies). `required-features = ["agent-gateway","vsock-transport"]` (NOT lab-quote-smoke, NOT
//! production-vsock/staging-vsock — role isolation: those pull ml-dsa-65 ⊕ agent-gateway).
//!
//! Non-linux: a stub `main` exits 2 (mirrors `twod_hsm_quote_smoke.rs`). Linux: `main`/`run` shape
//! mirrors `enclave_vsock.rs` — `run() -> Result<(), Box<dyn Error>>` prints the STARTUP error (config
//! parse / bind) and exits 1. The library `run_host_anchor_relay` returns `Result<Infallible, _>`: its
//! Ok arm is unconstructible (the serve loop never returns Ok — per-connection faults are logged +
//! skipped inside the library), so `run()` returns only the startup `Err`. The bin's pre-serve
//! `eprintln!` is permitted (short-lived startup, `enclave_vsock.rs:16` precedent); the LIBRARY
//! per-pump sink is the `let _ = writeln!` house rule.

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("twod-hsm-host-anchor-relay: requires Linux (AF_VSOCK)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        // STARTUP error only (config parse / bind). The serve loop never returns to here.
        eprintln!("twod-hsm-host-anchor-relay: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    // `run_host_anchor_relay` returns `Result<Infallible, _>`: the Ok arm is unconstructible (the serve
    // loop never returns Ok), so a successful bind never returns here — only a STARTUP `Err` does. The
    // `match` discharges the `Infallible` without an `unreachable!`/panic in the bin.
    match enclave_protocol::run_host_anchor_relay() {
        Ok(never) => match never {},
        Err(e) => Err(e),
    }
}
