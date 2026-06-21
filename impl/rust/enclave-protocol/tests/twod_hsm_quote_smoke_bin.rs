//! (4c) bin-contract integration test: the `twod-hsm-quote-smoke` bin's dispatch-first +
//! PROTOCOL-ONLY-stdout contract, enforced in CI against the REAL bin via `CARGO_BIN_EXE_*`
//! (Cargo sets it only for integration tests/benches — and the bin only builds when its
//! `required-features` are on, hence the dedicated workflow step).
//!
//! SURFACE-FREE by design: the crate's env names + frame bytes stay crate-private (the §8 pin —
//! "the marker env stays crate-private so the dispatch condition cannot be re-keyed one-sided");
//! this test TRANSCRIBES the literals. Fail-loud by construction: if the crate consts are ever
//! renamed, the spawned child never dispatches, the byte-exact stdout asserts fail, and the drift
//! is caught HERE rather than silently re-keyed.
//!
//! Seeds the 5b-2c byte-exact harness but does NOT discharge the 5b-2c acceptance item — that test
//! must re-target `CARGO_BIN_EXE_<agent-bin>` (the wrong binary cannot discharge it).
//!
//! Both arms are deterministic + deviceless (ubuntu CI INVARIANT: no vsock device, no configfs-tsm
//! needed — the child fails BEFORE any device I/O in arm (a) and AT the configfs create in arm (b)).
#![cfg(all(
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway",
    feature = "lab-quote-smoke"
))]

use std::process::{Command, Stdio};

/// Transcribed literal == `quote_subprocess::QUOTE_CHILD_ENV` (crate-private by §8 pin — do NOT
/// re-export; a rename breaks dispatch and the byte-exact asserts below fail loudly).
const MARKER_ENV: &str = "TWOD_HSM_QUOTE_CHILD";
/// Transcribed literal == `quote_subprocess::QUOTE_CHILD_REPORT_DATA_ENV` (same rule).
const REPORT_DATA_ENV: &str = "TWOD_HSM_QUOTE_CHILD_REPORT_DATA";
/// Transcribed literal == `snp_report::TSM_REPORT_DIR` (the arm-(b) skip guard).
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
/// Golden ERR frames (stable wire constants; the in-crate golden-byte tests pin the same encoding):
/// status `FRAME_STATUS_ERR = 0xA2`, code 1 = bad-env, code 2 = entry create failed.
const ERR1_FRAME: [u8; 2] = [0xA2, 0x01];
const ERR2_FRAME: [u8; 2] = [0xA2, 0x02];

fn smoke_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_twod-hsm-quote-smoke"));
    cmd.env_clear()
        .env(MARKER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Arm (a) — marker env set, report_data env ABSENT: the dispatched child's env parse fails ⇒
/// stdout is FULL-BUFFER byte-equal to the ERR(1) frame (dispatch ran FIRST and nothing else ever
/// wrote to stdout — a dispatch moved below any stdout-writing statement, or any stdout logging
/// anywhere in the bin, fails this by construction), exit code 1, and the stderr breadcrumb is
/// EMITTED (the free deviceless half of pin (2)'s stderr leg; journald ARRIVAL stays the (4c)
/// in-guest `ExecStartPost` assert). Regression: dispatch-first + PROTOCOL-ONLY-stdout drift in
/// the smoke bin's main.
#[test]
fn bin_dispatches_first_and_stdout_is_byte_exact_err1() {
    let out = smoke_bin().output().expect("spawn the smoke bin");
    assert_eq!(
        out.stdout.as_slice(),
        ERR1_FRAME,
        "stdout must be EXACTLY the 2-byte ERR(1) frame (full-buffer equality, not the parser)"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "bad/missing report_data env exits 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("twod-hsm quote child: exit 1"),
        "the child's nonzero-exit breadcrumb must be emitted on stderr; got: {stderr:?}"
    );
}

/// Arm (b) — marker env + VALID 128-hex report_data on a configfs-less host: the child dispatches,
/// parses the env, then fails at the configfs entry CREATE ⇒ stdout == ERR(2) frame byte-exact,
/// exit code 2. GUARD: skipped (with a loud note) when the configfs-tsm report dir exists — on an
/// SNP guest / exotic dev box the create may SUCCEED and this arm would assert the wrong thing.
/// Regression: the dispatched child reaching real fetch logic with a clean stdout protocol stream.
#[test]
fn bin_child_emits_byte_exact_err2_on_configfs_less_host() {
    if std::path::Path::new(TSM_REPORT_DIR).exists() {
        eprintln!(
            "skipping bin_child_emits_byte_exact_err2_on_configfs_less_host: {TSM_REPORT_DIR} \
             exists (configfs-tsm-bearing host — the create arm is not deterministic here)"
        );
        return;
    }
    let out = smoke_bin()
        .env(REPORT_DATA_ENV, "ab".repeat(64)) // valid 128-hex
        .output()
        .expect("spawn the smoke bin");
    assert_eq!(
        out.stdout.as_slice(),
        ERR2_FRAME,
        "stdout must be EXACTLY the 2-byte ERR(2) frame (entry create fails first deviceless)"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "configfs create failure exits 2"
    );
}
