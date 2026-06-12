//! (5b-2c) bin-contract integration test for the `twod-hsm-agent-gateway` bin: the §8 dispatch-first +
//! PROTOCOL-ONLY-stdout acceptance item, RE-TARGETED to the agent bin (the quote-smoke test seeds the
//! harness but cannot discharge it — wrong binary), plus a fail-closed-startup assertion.
//!
//! CI-enforced against the REAL bin via `CARGO_BIN_EXE_*` (Cargo sets it only for integration tests, and
//! the bin only builds when its `required-features` are on — hence the dedicated workflow lane).
//! SURFACE-FREE: transcribes the crate-private quote-child marker + golden frame literals (a rename
//! breaks dispatch and the byte-exact asserts fail LOUDLY here rather than silently re-keying).
//!
//! Both arms are deterministic + deviceless (no vsock device / configfs needed): arm (a)'s child fails
//! at env parse BEFORE any device I/O; the fail-closed arm fails at the agent provisioning root BEFORE
//! any bind/connect.
#![cfg(all(target_os = "linux", feature = "vsock-transport", feature = "agent-gateway"))]

use std::process::{Command, Stdio};

/// Transcribed literal == `quote_subprocess::QUOTE_CHILD_ENV` (crate-private by §8 pin — a rename breaks
/// dispatch and the byte-exact assert below fails loudly).
const MARKER_ENV: &str = "TWOD_HSM_QUOTE_CHILD";
/// Golden ERR(1) frame (status `FRAME_STATUS_ERR=0xA2`, code 1 = bad-env); the in-crate golden-byte
/// tests pin the same encoding.
const ERR1_FRAME: [u8; 2] = [0xA2, 0x01];

fn agent_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_twod-hsm-agent-gateway"));
    cmd.env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Arm (a) — DISPATCH-FIRST: marker env set, report_data env ABSENT ⇒ the dispatched quote child's env
/// parse fails ⇒ stdout is FULL-BUFFER byte-equal to the ERR(1) frame (dispatch ran FIRST and nothing
/// else ever wrote stdout — a dispatch moved below any stdout write, or ANY stdout logging in the bin's
/// main/boot, fails this by construction), exit code 1, and the child's stderr breadcrumb is emitted.
/// THIS discharges the §8 5b-2c byte-exact-stdout acceptance item (re-targeted to the agent bin).
#[test]
fn agent_bin_dispatches_first_and_stdout_is_byte_exact_err1() {
    let out = agent_bin().env(MARKER_ENV, "1").output().expect("spawn the agent bin");
    assert_eq!(
        out.stdout.as_slice(),
        ERR1_FRAME,
        "stdout must be EXACTLY the 2-byte ERR(1) frame (full-buffer equality, not the parser)"
    );
    assert_eq!(out.status.code(), Some(1), "bad/missing report_data env exits 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("twod-hsm quote child: exit 1"),
        "the child's nonzero-exit breadcrumb must be emitted on stderr; got: {stderr:?}"
    );
}

/// Arm (b) — FAIL-CLOSED STARTUP: NO marker (a normal boot) under env_clear ⇒ the very first boot step,
/// `boot_configure_agent_seal_root`, fails closed (the production stub without `lab-agent-keystore-from-file`,
/// or "root file not set" with it) ⇒ exit 1 and the library renders a root-naming cause at err priority.
/// The agent NEVER serves without a configured provisioning root/source.
#[test]
fn agent_bin_fails_closed_on_unconfigured_root() {
    let out = agent_bin().output().expect("spawn the agent bin");
    assert_eq!(out.status.code(), Some(1), "an unconfigured-root boot exits 1 (fail-closed)");
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("boot failed") && stderr.contains("root"),
        "stderr must render the fail-closed boot cause naming the provisioning root; got: {stderr:?}"
    );
    // PROTOCOL-ONLY stdout: a fail-closed boot writes NOTHING to stdout (the journald channel is stderr).
    assert!(out.stdout.is_empty(), "fail-closed startup must not write to stdout; got {:?}", out.stdout);
}
