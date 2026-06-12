//! 5b-2c-iii lab anchor stub bin (TASK-7.7) — **TEST KEYS ONLY, release-banned feature**. The TCP
//! endpoint `twod-hsm-host-anchor-relay` dials (`TWOD_HSM_ANCHOR_ENDPOINT`) during the aya SNP live
//! smoke's boot handshake. Thin: env config + the library `run_lab_anchor_stub` (fail-closed
//! startup: capped file reads, unseal, the seed↔anchor_root pairing assert; then a serial,
//! never-dying accept loop). TCP-only on purpose — NO vsock-transport in `required-features`
//! (darwin-buildable; the vsock leg belongs to the relay).
//!
//! Env: `TWOD_HSM_LAB_ANCHOR_LISTEN` (default `127.0.0.1:5003`),
//! `TWOD_HSM_LAB_ANCHOR_KEYSTORE_FILE` + `TWOD_HSM_LAB_ANCHOR_SEAL_ROOT_FILE` (REQUIRED, no
//! default, fail-closed). The startup `eprintln!` is permitted (short-lived; the
//! `host_anchor_relay.rs` bin precedent); the library per-pump sink is `let _ = writeln!`.

fn main() {
    if let Err(e) = run() {
        // STARTUP error only (env/file/unseal/pairing/bind). The serve loop never returns here.
        eprintln!("twod-hsm-lab-anchor: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // `Result<Infallible, _>`: the Ok arm is unconstructible (the serial loop never returns Ok),
    // so the `match` discharges it without an `unreachable!`/panic in the bin.
    match enclave_protocol::run_lab_anchor_stub() {
        Ok(never) => match never {},
        Err(e) => Err(Box::new(e)),
    }
}
