//! (b) bin-contract integration test (TASK-7.7 5b-2b-ii(b)): the `twod-hsm-host-anchor-relay` bin's
//! STRUCTURAL fail-closed shape, enforced in CI against the REAL bin via `CARGO_BIN_EXE_*` (Cargo sets
//! it only for integration tests/benches — and the bin only builds when its `required-features` are
//! on, hence the dedicated workflow step).
//!
//! STRUCTURAL only (NOT a live run): asserts that with `TWOD_HSM_ANCHOR_ENDPOINT` unset the bin exits
//! NON-ZERO with a fail-closed message NAMING the var (no panic, no listen) — the no-default
//! operator-ergonomics tax (Risk #9). It does NOT bind vsock or dial an anchor (CI has no vsock device
//! / no anchor). Unlike `twod-hsm-quote-smoke`, NO `lab-quote-smoke` feature is needed.
//!
//! NB: the relay's resolved port (`anchor_relay_port_from_env`) has a DEFAULT, so it does not fail the
//! config gate; `anchor_endpoint_from_env` is the no-default gate this test exercises. The bin clears
//! its env to make the unset-var assertion deterministic regardless of the CI host's environment.
#![cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]

use std::process::{Command, Stdio};

/// Transcribed literal == `env_config::TWOD_HSM_ANCHOR_ENDPOINT` (the fail-closed message must name
/// it). A rename that drops it from the message fails this test loudly.
const ANCHOR_ENDPOINT_ENV: &str = "TWOD_HSM_ANCHOR_ENDPOINT";
const LEGACY_ANCHOR_ENDPOINT_ENV: &str = "2D_HSM_ANCHOR_ENDPOINT";

fn relay_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_twod-hsm-host-anchor-relay"));
    // Clear env so the unset-var assertion is deterministic; null stdin so it never blocks on input.
    cmd.env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Regression: the no-default fail-closed boot error — unset `TWOD_HSM_ANCHOR_ENDPOINT` → exit
/// non-zero with a message naming the var. (Guards against a silent localhost guess sneaking in, and
/// against the var name drifting out of the error text.)
#[test]
fn bin_fails_closed_when_anchor_endpoint_unset() {
    // Belt-and-suspenders: env_clear() already drops these, but remove explicitly in case a future
    // change pre-seeds env for the child.
    let out = relay_bin()
        .env_remove(ANCHOR_ENDPOINT_ENV)
        .env_remove(LEGACY_ANCHOR_ENDPOINT_ENV)
        .output()
        .expect("spawn the host-anchor-relay bin");
    assert!(
        !out.status.success(),
        "unset {ANCHOR_ENDPOINT_ENV} must fail the daemon closed (non-zero exit); status={:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(ANCHOR_ENDPOINT_ENV),
        "the fail-closed message must NAME the var; got stderr: {stderr:?}"
    );
    // Fail-closed, never a localhost guess: the message states the no-default contract.
    assert!(
        stderr.contains("fail-closed"),
        "the message must state the no-default fail-closed contract; got stderr: {stderr:?}"
    );
}
