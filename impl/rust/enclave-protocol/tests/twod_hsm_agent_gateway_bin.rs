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

/// Arms (ii)/(iii) — the doc-pinned "bin logging acceptance split BY PATH" (one happy smoke is NOT
/// enough): (ii) validation-refusal and (iii) outcome-refusal, both DEVICELESS (no SNP, no vsock
/// device, no relay/anchor). They need the lab keystore FILE source to get past root+unseal, hence
/// the feature gate; env paths point at the committed reference root + the 5b-2c-iii smoke fixture.
#[cfg(feature = "lab-agent-keystore-from-file")]
mod refusal_arms {
    use super::agent_bin;
    use enclave_protocol::env_config::{
        TWOD_HSM_BOOT_MAX_ATTEMPTS, TWOD_HSM_BOOT_OVERALL_BUDGET_MS,
        TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS, TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
        TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
    };

    const ROOT_FILE: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/seal_v1_provisioning_root.bin");
    const SMOKE_BLOB: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin"
    );

    fn lab_boot_bin() -> std::process::Command {
        let mut cmd = agent_bin();
        cmd.env(TWOD_HSM_PQ_SEAL_V1_ROOT_FILE, ROOT_FILE)
            .env(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, SMOKE_BLOB);
        cmd
    }

    /// Arm (ii) — VALIDATION REFUSAL: a parseable-but-invalid budget (overall=1 ms ≪ the nominal
    /// `max_attempts·(2·per_leg+12)`) fails `ValidatedBootBudget::validate` deterministically AFTER
    /// the raw pre-validate event but BEFORE the validated event. Pins the two-phase logging
    /// contract: the RawBudgetConfig line + the err-render BOTH appear, `boot budget validated`
    /// does NOT, stdout stays protocol-only EMPTY, exit 1.
    #[test]
    fn arm_ii_validation_refusal_logs_raw_config_and_err_render() {
        let out = lab_boot_bin()
            .env(TWOD_HSM_BOOT_OVERALL_BUDGET_MS, "1")
            .output()
            .expect("spawn the agent bin");
        assert_eq!(out.status.code(), Some(1), "validation refusal exits 1");
        assert!(out.stdout.is_empty(), "stdout stays protocol-only; got {:?}", out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("boot budget config (raw, pre-validate)"),
            "the RAW pre-validate event is the operator's only copy on a refused budget; got: {stderr:?}"
        );
        assert!(
            stderr.contains("[err] agent-gateway boot failed:"),
            "the returned ProtocolError must be rendered at err priority; got: {stderr:?}"
        );
        assert!(
            !stderr.contains("boot budget validated"),
            "a refused budget must never emit the validated event; got: {stderr:?}"
        );
        assert!(!stderr.contains("serving on vsock"), "must never reach serve");
    }

    /// Arm (iii) — OUTCOME REFUSAL: a VALID budget (1 attempt, 200 ms per leg), then the handshake's
    /// quote child fails off-SNP (no configfs-tsm) BEFORE any vsock dial ⇒ retryable ⇒ exhausted ⇒
    /// a non-Ready outcome. Pins the byte-offset ORDER raw → validated → `[warn]` outcome →
    /// `[err]` render, stdout EMPTY, exit 1 (supervisor restart; NO in-process retry).
    ///
    /// CANNOT-HANG (why `.output()` is safe here, matching arms (a)/(b)): this is a HOST-side cargo
    /// test, and the boot's FIRST per-attempt step is the SNP quote fetch via configfs-tsm — which
    /// requires an SNP GUEST. On any test host (CI ubuntu, or aya's HOST userspace) `/sys/kernel/
    /// config/tsm/report` does not exist, so the quote fetch fails on the single attempt
    /// (MAX_ATTEMPTS=1) and the boot fail-closes and EXITS before the serve loop is ever reachable
    /// (reaching serve would additionally require a Ready outcome = a valid anchor-signed response,
    /// impossible without the matching lab stub on the relay path). So the child always terminates
    /// and `.output()` returns. (A general bounded-spawn wrapper for ALL bin-test arms — so a future
    /// arm that COULD serve can't wedge CI — is a named test-harness follow-up, applied uniformly,
    /// not bolted onto this one arm.)
    #[test]
    fn arm_iii_outcome_refusal_logs_warn_outcome_then_err_render_in_order() {
        let out = lab_boot_bin()
            .env(TWOD_HSM_BOOT_MAX_ATTEMPTS, "1")
            .env(TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS, "200")
            .output()
            .expect("spawn the agent bin");
        assert_eq!(out.status.code(), Some(1), "outcome refusal exits 1");
        assert!(out.stdout.is_empty(), "stdout stays protocol-only; got {:?}", out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let pos = |needle: &str| -> usize {
            stderr
                .find(needle)
                .unwrap_or_else(|| panic!("stderr must contain {needle:?}; got: {stderr:?}"))
        };
        let raw = pos("boot budget config (raw, pre-validate)");
        let validated = pos("boot budget validated:");
        let outcome = pos("[warn] boot handshake outcome:");
        let err_render = pos("[err] agent-gateway boot failed:");
        assert!(
            raw < validated && validated < outcome && outcome < err_render,
            "the canonical order raw({raw}) < validated({validated}) < warn-outcome({outcome}) < \
             err-render({err_render}) must hold; got: {stderr:?}"
        );
        assert!(!stderr.contains("serving on vsock"), "a refused outcome must never serve");
    }
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
