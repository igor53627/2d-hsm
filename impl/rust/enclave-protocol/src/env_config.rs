//! Operator environment variable names (`TWOD_*` prefix).
//!
//! POSIX and **systemd** reject env keys that start with a digit, so use
//! `TWOD_HSM_*` instead of `2D_HSM_*` in unit files, cloud-init, and NixOS modules.
//! Reference binaries still accept deprecated `2D_HSM_*` names for one transition period.

/// Read `primary`, then deprecated `legacy` (`2D_HSM_*`).
///
/// Falls back to `legacy` only when `primary` is unset. A `primary` set to a
/// non-UTF-8 value is a misconfiguration and is surfaced (fail closed) rather
/// than masked by a stale legacy value.
pub fn var_twod(primary: &str, legacy: &str) -> Result<String, std::env::VarError> {
    match std::env::var(primary) {
        Ok(v) => Ok(v),
        Err(std::env::VarError::NotPresent) => std::env::var(legacy),
        Err(e) => Err(e),
    }
}

pub const TWOD_HSM_VSOCK_CID: &str = "TWOD_HSM_VSOCK_CID";
pub const LEGACY_HSM_VSOCK_CID: &str = "2D_HSM_VSOCK_CID";
pub const TWOD_HSM_VSOCK_PORT: &str = "TWOD_HSM_VSOCK_PORT";
pub const LEGACY_HSM_VSOCK_PORT: &str = "2D_HSM_VSOCK_PORT";

// TASK-7.7 5b-2: the enclave-initiated anti-rollback boot-relay endpoint port (distinct from the serve
// port above; the enclave dials host CID 2 on this to reach the anchor relay). Default 5001.
pub const TWOD_HSM_ANCHOR_RELAY_PORT: &str = "TWOD_HSM_ANCHOR_RELAY_PORT";
pub const LEGACY_HSM_ANCHOR_RELAY_PORT: &str = "2D_HSM_ANCHOR_RELAY_PORT";

// TASK-7.7 5b-2b-ii(b): the UNTRUSTED host relay's upstream anchor endpoint (host:port). NO default
// — a missing anchor is a fail-closed boot error, never a silent localhost guess. Host-side only.
pub const TWOD_HSM_ANCHOR_ENDPOINT: &str = "TWOD_HSM_ANCHOR_ENDPOINT";
pub const LEGACY_HSM_ANCHOR_ENDPOINT: &str = "2D_HSM_ANCHOR_ENDPOINT";

pub const TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE: &str =
    "TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE";
pub const LEGACY_HSM_PRODUCER_ATTESTATION_TRUST_FILE: &str =
    "2D_HSM_PRODUCER_ATTESTATION_TRUST_FILE";

pub const TWOD_HSM_PQ_SEAL_V1_ROOT_FILE: &str = "TWOD_HSM_PQ_SEAL_V1_ROOT_FILE";
pub const LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE: &str = "2D_HSM_PQ_SEAL_V1_ROOT_FILE";

pub const TWOD_HSM_ENCLAVE_SOCKET: &str = "TWOD_HSM_ENCLAVE_SOCKET";
pub const LEGACY_HSM_ENCLAVE_SOCKET: &str = "2D_HSM_ENCLAVE_SOCKET";

pub const TWOD_HSM_ENCLAVE_STAGING_SOCKET: &str = "TWOD_HSM_ENCLAVE_STAGING_SOCKET";
pub const LEGACY_HSM_ENCLAVE_STAGING_SOCKET: &str = "2D_HSM_ENCLAVE_STAGING_SOCKET";

pub const TWOD_HSM_PQ_SEALED_SIGNER_FILE: &str = "TWOD_HSM_PQ_SEALED_SIGNER_FILE";
pub const LEGACY_HSM_PQ_SEALED_SIGNER_FILE: &str = "2D_HSM_PQ_SEALED_SIGNER_FILE";

pub const TWOD_HSM_ENCLAVE_MEASUREMENT_FILE: &str = "TWOD_HSM_ENCLAVE_MEASUREMENT_FILE";
pub const LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE: &str = "2D_HSM_ENCLAVE_MEASUREMENT_FILE";

// TASK-7.7 5b-2d: lab/integration source for the sealed AGENT keystore (pq-agent-keystore-v1). Read RAW
// (a sealed binary blob — never newline-trimmed). Behind `lab-agent-keystore-from-file` (debug only); the
// production host-vsock install/restore source is a deferred slice.
pub const TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE: &str = "TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE";
pub const LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE: &str = "2D_HSM_AGENT_SEALED_KEYSTORE_FILE";

// TASK-25 AC#2: the one-shot provisioning bootstrap vsock port (Q5 — SEPARATE from the serve port
// 5000 + the relay port 5001). The bootstrap listener accepts ONE connection, runs M1→M2→M3→M4,
// then tears down. Default 5002.
pub const TWOD_HSM_PROVISIONING_VSOCK_PORT: &str = "TWOD_HSM_PROVISIONING_VSOCK_PORT";
pub const LEGACY_HSM_PROVISIONING_VSOCK_PORT: &str = "2D_HSM_PROVISIONING_VSOCK_PORT";

// TASK-25 §7/AC#2: the pinned operator CA root Ed25519 public key (hex-encoded, 64 hex chars → 32
// bytes). LAB/DEV: read from this env var. PRODUCTION: compiled into the binary at build (the same
// binary-pinning discipline as the Q7 measurement allowlist). The provisioner cert chain verifies
// against this root.
pub const TWOD_HSM_OPERATOR_CA_ROOT_HEX: &str = "TWOD_HSM_OPERATOR_CA_ROOT_HEX";
pub const LEGACY_HSM_OPERATOR_CA_ROOT_HEX: &str = "2D_HSM_OPERATOR_CA_ROOT_HEX";

/// When `1`, allow boot without platform PQ root (transport-only smoke; NOT mainnet).
pub const TWOD_HSM_TRANSPORT_ONLY_MODE: &str = "TWOD_HSM_TRANSPORT_ONLY_MODE";
pub const LEGACY_HSM_TRANSPORT_ONLY_MODE: &str = "2D_HSM_TRANSPORT_ONLY_MODE";

pub fn transport_only_mode_enabled() -> bool {
    var_twod(TWOD_HSM_TRANSPORT_ONLY_MODE, LEGACY_HSM_TRANSPORT_ONLY_MODE)
        .ok()
        .as_deref()
        == Some("1")
}

/// TASK-18 AC#1: when `1`, the bin boots in provisioning mode — runs the attested install
/// handshake (M1→M2→M3→M4) instead of unsealing a pre-sealed keystore. First boot only.
pub const TWOD_HSM_PROVISIONING_MODE: &str = "TWOD_HSM_PROVISIONING_MODE";
pub const LEGACY_HSM_PROVISIONING_MODE: &str = "2D_HSM_PROVISIONING_MODE";

pub fn provisioning_mode_enabled() -> bool {
    var_twod(TWOD_HSM_PROVISIONING_MODE, LEGACY_HSM_PROVISIONING_MODE)
        .ok()
        .as_deref()
        == Some("1")
}

// TASK-7.7 5b-2c: the agent-gateway boot-budget triplet (max_attempts, per_leg_timeout,
// overall_boot_budget) the bin parses for `ValidatedBootBudget::validate`. The connect-timeout and the
// per-socket SO_*TIMEO are DERIVED from per_leg_timeout (§8: derived, not separate operator knobs) —
// only these three are operator-facing.
pub const TWOD_HSM_BOOT_MAX_ATTEMPTS: &str = "TWOD_HSM_BOOT_MAX_ATTEMPTS";
pub const LEGACY_HSM_BOOT_MAX_ATTEMPTS: &str = "2D_HSM_BOOT_MAX_ATTEMPTS";
pub const TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS: &str = "TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS";
pub const LEGACY_HSM_BOOT_PER_LEG_TIMEOUT_MS: &str = "2D_HSM_BOOT_PER_LEG_TIMEOUT_MS";
pub const TWOD_HSM_BOOT_OVERALL_BUDGET_MS: &str = "TWOD_HSM_BOOT_OVERALL_BUDGET_MS";
pub const LEGACY_HSM_BOOT_OVERALL_BUDGET_MS: &str = "2D_HSM_BOOT_OVERALL_BUDGET_MS";

const DEFAULT_BOOT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_BOOT_PER_LEG_TIMEOUT_MS: u64 = 5_000;
/// Per-attempt overhead margin folded into the DERIVED default overall budget — deliberately ≫ the
/// real per-attempt ε (`quote_subprocess::QUOTE_ATTEMPT_OVERHEAD` ≈ 12 ms), so a derive-by-default
/// overall always clears `validate()`'s `nominal = max_attempts·(3·per_leg + ε) ≤ overall` with
/// comfortable headroom WITHOUT this gate-free parser referencing the gated ε.
// pub(crate) so the gated `agent_gateway_boot` test can pin it ≥ the real per-attempt ε
// (`quote_subprocess::QUOTE_ATTEMPT_OVERHEAD`), which this gate-free parser cannot reference directly.
pub(crate) const BOOT_DERIVE_PER_ATTEMPT_MARGIN_MS: u64 = 1_000;
/// Flat slack added on top of the derived per-attempt sum.
const BOOT_DERIVE_SLACK_MS: u64 = 2_000;

fn env_u32_or(primary: &str, legacy: &str, default: u32) -> Result<u32, String> {
    match var_twod(primary, legacy) {
        // Name BOTH the canonical + legacy var (var_twod reads either) so an operator who set the
        // deprecated 2D_HSM_* alias gets a diagnostic naming the var they actually set.
        Ok(s) if !s.is_empty() => s
            .parse::<u32>()
            .map_err(|_| format!("{primary} (or legacy {legacy}) must be a u32")),
        // Unset or empty → default. A SET-but-non-UTF-8 value is a misconfiguration — surface it
        // (fail closed), matching var_twod's documented contract + the sibling env_u32_twod; never
        // silently default over a corrupt env value.
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!(
            "{primary} (or legacy {legacy}) must be valid UTF-8"
        )),
    }
}

fn env_u64_or(primary: &str, legacy: &str, default: u64) -> Result<u64, String> {
    match var_twod(primary, legacy) {
        Ok(s) if !s.is_empty() => s
            .parse::<u64>()
            .map_err(|_| format!("{primary} (or legacy {legacy}) must be a u64 (milliseconds)")),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!(
            "{primary} (or legacy {legacy}) must be valid UTF-8"
        )),
    }
}

/// Saturating derive of the default overall boot budget from the resolved `max_attempts`/`per_leg_ms`.
/// Saturating so an absurd operator `per_leg`/`attempts` can't overflow the derive — `validate()` then
/// rejects an over-ceiling value fail-closed. THREE per-leg multiples since 5b-2e: the worst-case
/// attempt runs quote + freshness + marks (the AdoptForward leg), matching `validate()`'s 3-leg nominal
/// (`quote_subprocess::per_attempt_nominal_cost`) so a derived-by-default overall still clears it.
fn derive_overall_budget_ms(max_attempts: u32, per_leg_ms: u64) -> u64 {
    let per_attempt = per_leg_ms
        .saturating_mul(3)
        .saturating_add(BOOT_DERIVE_PER_ATTEMPT_MARGIN_MS);
    u64::from(max_attempts)
        .saturating_mul(per_attempt)
        .saturating_add(BOOT_DERIVE_SLACK_MS)
}

/// Parse the agent boot-budget triplet from operator env, in `ValidatedBootBudget::validate`'s PARAM
/// ORDER `(max_attempts, per_leg_timeout, overall_boot_budget)` — positional discipline, no config
/// struct (so a transposed-but-valid config fails closed in `validate`). PARSE + DEFAULT ONLY: this
/// never pre-validates band-validity — `ValidatedBootBudget::validate` (inside the handshake) is the
/// sole fail-closed judge. `overall_boot_budget` is DERIVE-BY-DEFAULT (always-valid out of the box)
/// but an operator may widen it via `TWOD_HSM_BOOT_OVERALL_BUDGET_MS`. Gate-free + std-only so it is
/// CI-tested without the vsock/agent gates.
pub fn boot_budget_config_from_env(
) -> Result<(u32, std::time::Duration, std::time::Duration), String> {
    let max_attempts = env_u32_or(
        TWOD_HSM_BOOT_MAX_ATTEMPTS,
        LEGACY_HSM_BOOT_MAX_ATTEMPTS,
        DEFAULT_BOOT_MAX_ATTEMPTS,
    )?;
    let per_leg_ms = env_u64_or(
        TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS,
        LEGACY_HSM_BOOT_PER_LEG_TIMEOUT_MS,
        DEFAULT_BOOT_PER_LEG_TIMEOUT_MS,
    )?;
    let overall_ms = match var_twod(
        TWOD_HSM_BOOT_OVERALL_BUDGET_MS,
        LEGACY_HSM_BOOT_OVERALL_BUDGET_MS,
    ) {
        Ok(s) if !s.is_empty() => s.parse::<u64>().map_err(|_| {
            format!(
                "{TWOD_HSM_BOOT_OVERALL_BUDGET_MS} (or legacy {LEGACY_HSM_BOOT_OVERALL_BUDGET_MS}) \
                 must be a u64 (milliseconds)"
            )
        })?,
        // Unset or empty → derive-by-default; a set-but-non-UTF-8 value fails closed (see env_u*_or).
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            derive_overall_budget_ms(max_attempts, per_leg_ms)
        }
        Err(_) => {
            return Err(format!(
                "{TWOD_HSM_BOOT_OVERALL_BUDGET_MS} (or legacy {LEGACY_HSM_BOOT_OVERALL_BUDGET_MS}) \
                 must be valid UTF-8"
            ))
        }
    };
    Ok((
        max_attempts,
        std::time::Duration::from_millis(per_leg_ms),
        std::time::Duration::from_millis(overall_ms),
    ))
}

#[cfg(test)]
mod boot_budget_tests {
    use super::*;
    use std::time::Duration;

    // Serializes the env-mutating tests (these six vars are the sole consumers here).
    static BUDGET_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear() {
        for k in [
            TWOD_HSM_BOOT_MAX_ATTEMPTS,
            LEGACY_HSM_BOOT_MAX_ATTEMPTS,
            TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS,
            LEGACY_HSM_BOOT_PER_LEG_TIMEOUT_MS,
            TWOD_HSM_BOOT_OVERALL_BUDGET_MS,
            LEGACY_HSM_BOOT_OVERALL_BUDGET_MS,
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn defaults_when_unset_and_overall_is_derived_and_valid() {
        let _g = BUDGET_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        let (attempts, per_leg, overall) = boot_budget_config_from_env().unwrap();
        assert_eq!(attempts, 5);
        assert_eq!(per_leg, Duration::from_millis(5_000));
        // Derived overall comfortably exceeds the bare nominal 3·per_leg·attempts (3 legs since 5b-2e).
        let bare_nominal = per_leg.checked_mul(3 * attempts).unwrap();
        assert!(
            overall > bare_nominal,
            "derived overall {overall:?} must exceed bare nominal {bare_nominal:?}"
        );
        clear();
    }

    #[test]
    fn explicit_overall_overrides_the_derive() {
        let _g = BUDGET_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        std::env::set_var(TWOD_HSM_BOOT_OVERALL_BUDGET_MS, "123456");
        let (_, _, overall) = boot_budget_config_from_env().unwrap();
        assert_eq!(overall, Duration::from_millis(123_456));
        clear();
    }

    #[test]
    fn derive_recomputes_from_overridden_attempts_and_per_leg() {
        let _g = BUDGET_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        std::env::set_var(TWOD_HSM_BOOT_MAX_ATTEMPTS, "3");
        std::env::set_var(TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS, "1000");
        let (attempts, per_leg, overall) = boot_budget_config_from_env().unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(per_leg, Duration::from_millis(1_000));
        // 3·(3·1000 + 1000) + 2000 = 3·4000 + 2000 = 14000 (3 legs since 5b-2e).
        assert_eq!(overall, Duration::from_millis(14_000));
        clear();
    }

    #[test]
    fn legacy_aliases_resolve_for_all_three_vars() {
        let _g = BUDGET_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        // Exercise ALL THREE legacy aliases (not just max_attempts) so a typo/copy-paste error in any
        // legacy const name is caught by CI.
        std::env::set_var(LEGACY_HSM_BOOT_MAX_ATTEMPTS, "7");
        std::env::set_var(LEGACY_HSM_BOOT_PER_LEG_TIMEOUT_MS, "1234");
        std::env::set_var(LEGACY_HSM_BOOT_OVERALL_BUDGET_MS, "99999");
        let (attempts, per_leg, overall) = boot_budget_config_from_env().unwrap();
        assert_eq!(attempts, 7);
        assert_eq!(per_leg, Duration::from_millis(1234));
        assert_eq!(overall, Duration::from_millis(99999));
        clear();
    }

    #[test]
    fn non_integer_fails_closed_naming_the_var() {
        let _g = BUDGET_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        std::env::set_var(TWOD_HSM_BOOT_MAX_ATTEMPTS, "not-a-number");
        let err = boot_budget_config_from_env().unwrap_err();
        assert!(
            err.contains(TWOD_HSM_BOOT_MAX_ATTEMPTS),
            "err names the var: {err}"
        );
        clear();
        std::env::set_var(TWOD_HSM_BOOT_PER_LEG_TIMEOUT_MS, "x");
        assert!(boot_budget_config_from_env().is_err());
        clear();
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_value_fails_closed_not_silently_defaulted() {
        use std::os::unix::ffi::OsStrExt;
        let _g = BUDGET_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear();
        // A set-but-non-UTF-8 value (e.g. a mis-encoded systemd EnvironmentFile) must FAIL CLOSED naming
        // the var (var_twod's contract) — NOT silently fall back to the default budget.
        std::env::set_var(
            TWOD_HSM_BOOT_MAX_ATTEMPTS,
            std::ffi::OsStr::from_bytes(&[0xff, 0xfe]),
        );
        let err = boot_budget_config_from_env().unwrap_err();
        assert!(
            err.contains(TWOD_HSM_BOOT_MAX_ATTEMPTS) && err.contains("UTF-8"),
            "non-UTF-8 must fail closed naming the var: {err}"
        );
        clear();
        std::env::set_var(
            TWOD_HSM_BOOT_OVERALL_BUDGET_MS,
            std::ffi::OsStr::from_bytes(&[0xff]),
        );
        assert!(
            boot_budget_config_from_env().is_err(),
            "non-UTF-8 overall must fail closed"
        );
        clear();
    }
}
