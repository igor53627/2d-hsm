//! Agent Gateway anti-rollback **freshness-challenge (nonce) state machine** (TASK-7.7, slice 2).
//!
//! On every (re)start the enclave issues a fresh, unpredictable, **single-use** nonce, binds it into
//! its SNP handshake `report_data` (the value [`crate::agent_anchor::anchor_handshake_report_data`]
//! computes), and later verifies the anchor's signed response against that *same* nonce
//! ([`crate::agent_anchor::verify_anchor_response`] / `..._bytes`, whose `# Caller preconditions` doc
//! block says the slice supplying `expected_nonce` "owns the invariant" that the nonce is freshly
//! sampled, unpredictable, and single-use). **This module is that owner.** It draws the nonce, holds
//! it as the single outstanding challenge, hands the *same* value to both the `report_data` binding and
//! the verify echo-check, and retires it on consume.
//!
//! ## Load-bearing invariants
//! - **Volatile-only.** The outstanding challenge is volatile *process* state ONLY — a const-init
//!   `static` like `INSTALLED_KEYSTORE` / `PLATFORM_PROVISIONING_ROOT`. It MUST NOT be sealed,
//!   persisted, written to `KeystoreBody`, or relayed to/through the untrusted host except as the
//!   public nonce sent to the anchor. A restart MUST lose it and force a fresh CSPRNG draw — otherwise
//!   a host that rolls back sealed state (the whole TASK-7.7 threat model, design §1/§3) could replay a
//!   captured `(nonce, response)` across a forced restart. This is **enforced structurally**:
//!   [`Challenge`] derives neither `Serialize` nor `Deserialize`, so it cannot be added to a
//!   serde-CBOR sealed struct by accident. Do not add those derives.
//! - **Single-use.** [`consume_outstanding_challenge`] `take()`s the slot under the lock and returns
//!   what it took; the slot is emptied on the first consume regardless of outcome, so a replayed
//!   `(nonce, response)` finds no matching outstanding nonce.
//! - **Overwrite-on-reissue.** Unlike the install-once setters (`install_agent_keystore`,
//!   `set_pq_seal_v1_provisioning_root`), [`issue_challenge`] **overwrites** unconditionally: the
//!   challenge is a re-issuable per-restart token, not an install-once secret; a failed handshake MUST
//!   rotate to a fresh unpredictable nonce, never retry the same one.
//! - **Per-instance.** The slot gives single-use *within one process*; it does NOT fence a sibling
//!   clone running its own fresh nonce — anti-clone rests on the anchor's per-scope counter churn
//!   (design §3 Option A), an operator-procedural residual, not on this module.
//!
//! ## Safe usage + boot-slice obligations
//! The intended flow makes single-use structural: `let c = issue_challenge(chain_id, env)?;` → use
//! `c.report_data()` to drive the SNP quote → relay the nonce and receive the anchor response →
//! `verify_outstanding_response(&response, config)`. That primitive **takes the challenge before it
//! verifies**, so the nonce is retired on every outcome and there is no non-consuming peek to misuse.
//! - **Scope/ordering (deferred to boot).** `chain_id`/`environment_identifier` come from the
//!   *unsealed* `KeystoreConfig`, so [`issue_challenge`] runs **after** the keystore is unsealed (not
//!   before). Exact placement in the boot ceremony is the boot-wiring slice's decision.
//! - **Single handshake in flight.** `issue_challenge` is called once per (re)start; on a timeout /
//!   anchor-unavailable path with no response to verify, the boot caller retires the challenge via
//!   [`consume_outstanding_challenge`] and re-issues. A retry MUST `issue_challenge` afresh.
//!
//! Like the rest of the anchor path this is dead-code-gated until boot wiring calls it.

#![cfg_attr(not(test), allow(dead_code))]

use crate::agent_anchor::{
    anchor_handshake_report_data, verify_anchor_response_bytes, AnchorError, AnchorState,
    DIGEST_LEN,
};
use crate::agent_keystore::KeystoreConfig;
use std::sync::Mutex;

/// Why issuing a challenge failed. Coarse + fail-closed; the underlying `getrandom` detail is
/// discarded (no oracle), matching every other CSPRNG site in the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeError {
    /// The platform CSPRNG was unavailable when drawing the nonce.
    Csprng,
}

/// Why verifying a response against the outstanding challenge failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeVerifyError {
    /// No challenge was outstanding — never issued, or already consumed (a replay attempt).
    NoOutstandingChallenge,
    /// The anchor response failed verification against the challenge's nonce + the sealed config.
    Anchor(AnchorError),
}

/// One outstanding freshness challenge. **Volatile process state only** — deliberately NOT
/// `Serialize`/`Deserialize` (so it can't enter sealed/persisted state — the volatile-only invariant)
/// and NOT `Zeroizing` (the nonce is public: it is sent to the anchor and echoed back).
#[derive(Debug, Clone)]
pub(crate) struct Challenge {
    nonce: [u8; DIGEST_LEN],
    chain_id: u64,
    environment_identifier: String,
}

impl Challenge {
    /// The fresh per-(re)start nonce — the value the anchor must echo and `verify_anchor_response`'s
    /// `expected_nonce` must equal.
    pub(crate) fn nonce(&self) -> &[u8; DIGEST_LEN] {
        &self.nonce
    }

    /// The 64-byte SNP `report_data` the enclave's handshake attestation commits to, computed from the
    /// **stored** nonce so the quote's binding and verify's `expected_nonce` are provably the same draw.
    pub(crate) fn report_data(&self) -> [u8; 64] {
        anchor_handshake_report_data(self.chain_id, &self.environment_identifier, &self.nonce)
    }
}

/// The single outstanding challenge for this process. Const-init volatile state; lost on restart
/// (mirrors `INSTALLED_KEYSTORE` / `PLATFORM_PROVISIONING_ROOT`).
static OUTSTANDING_CHALLENGE: Mutex<Option<Challenge>> = Mutex::new(None);

/// Draw a fresh CSPRNG nonce for `(chain_id, environment_identifier)` and install it as the single
/// outstanding challenge, **overwriting** any prior one (per-restart re-issuable token, not
/// install-once). Returns a copy so the caller can compute [`Challenge::report_data`] and present the
/// nonce. Fails closed (`ChallengeError::Csprng`) if the platform CSPRNG is unavailable — never panics,
/// never installs a non-random nonce.
pub(crate) fn issue_challenge(
    chain_id: u64,
    environment_identifier: &str,
) -> Result<Challenge, ChallengeError> {
    // Draw first (verbatim getrandom idiom — agent_keygen.rs key_ref draw); discard getrandom detail.
    let mut nonce = [0u8; DIGEST_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| ChallengeError::Csprng)?;
    // Build the Challenge FULLY before taking the lock, then a single swap — so a panic can never leave
    // a torn `Some` and poison-recovery only ever reads a fully-formed prior challenge.
    let challenge = Challenge {
        nonce,
        chain_id,
        environment_identifier: environment_identifier.to_owned(),
    };
    let mut guard = OUTSTANDING_CHALLENGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(challenge.clone());
    Ok(challenge)
}

/// Retire the outstanding challenge (the single-use RETIRE primitive): `take()` the slot under the lock
/// and return what it took (`None` if there was none). After this, a replayed `(nonce, response)` finds
/// an empty (or rotated) slot. This is the LOWER-LEVEL retire, used by two callers: (1)
/// [`verify_outstanding_response`] — the safe consume-then-verify path the boot reconcile routes through,
/// which consumes via this and hands the verified nonce back; and (2) the driver's transport-error path,
/// which retires an un-answered challenge before re-issuing a fresh one. The nonce-handoff contract lives
/// on [`verify_outstanding_response`], not here.
pub(crate) fn consume_outstanding_challenge() -> Option<Challenge> {
    OUTSTANDING_CHALLENGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
}

/// Atomically RETIRE the outstanding challenge and verify `response_bytes` against its nonce — the
/// **safe verification primitive**. The challenge is consumed FIRST, so single-use is *structural*:
/// it is taken on EVERY outcome (success, anchor error, or no-challenge), making "forget to consume"
/// unrepresentable and a replayed `(nonce, response)` after a verify a `NoOutstandingChallenge`. There
/// is deliberately **no non-consuming peek** of the nonce — the only way to check a response retires
/// the challenge in the same step. On any failure the caller MUST [`issue_challenge`] afresh before
/// retrying (never reuse a nonce). `report_data` for the SNP quote comes from the [`Challenge`] that
/// [`issue_challenge`] returned, not from a peek.
///
/// Returns `(AnchorState, nonce)` on success: the consumed nonce VALUE is handed back so the boot
/// caller can bind a downstream message to the SAME single-use nonce (5b-2e `AdoptForward` binds its
/// raw-marks fetch to it) WITHOUT a separate non-consuming peek — the slot is genuinely retired in this
/// one step, and the nonce travels as an owned value, not a re-read of the (now-empty) slot.
pub(crate) fn verify_outstanding_response(
    response_bytes: &[u8],
    config: &KeystoreConfig,
) -> Result<(AnchorState, [u8; DIGEST_LEN]), ChallengeVerifyError> {
    let challenge =
        consume_outstanding_challenge().ok_or(ChallengeVerifyError::NoOutstandingChallenge)?;
    let nonce = *challenge.nonce();
    let state = verify_anchor_response_bytes(response_bytes, &nonce, config)
        .map_err(ChallengeVerifyError::Anchor)?;
    Ok((state, nonce))
}

/// Whether a challenge is currently outstanding (presence-only; poison-recovers like the mutators so
/// it can't disagree with `consume`/`issue` about lifecycle state on a poisoned lock).
pub(crate) fn has_outstanding_challenge() -> bool {
    OUTSTANDING_CHALLENGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

#[cfg(test)]
pub(crate) fn reset_outstanding_challenge_for_tests() {
    // Poison-recover (not `if let Ok`) so a test that panicked while the slot was non-empty can't leak
    // stale state into the next test via a poisoned lock.
    *OUTSTANDING_CHALLENGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ENV: &str = "testnet";
    const CHAIN: u64 = 11565;

    /// Serialize the tests that touch the `OUTSTANDING_CHALLENGE` process-global (cargo runs tests in
    /// parallel) and reset the slot. Hold the returned guard for the test body's duration. Delegates to
    /// the crate-wide [`crate::agent_dispatch::lock_and_reset_agent_process_globals`] (not a module-local
    /// mutex): `agent_boot` drives this global AND `ANTI_ROLLBACK_BINDING` together, so all touchers of
    /// either global serialize on one mutex (and reset the full global set) or they race.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::agent_dispatch::lock_and_reset_agent_process_globals()
    }

    fn test_config() -> KeystoreConfig {
        KeystoreConfig {
            twod_chain_id: CHAIN,
            environment_identifier: ENV.to_string(),
            admin_authority_pk: [0xa1; 32],
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: Vec::new(),
            monotonic_treasury_config_version: 1,
            authority_epoch: 0,
            anchor_root: [0u8; 32],
            enclave_scope_id: [0xe1; 32],
            fleet_scope_id: [0xf1; 32],
        }
    }

    #[test]
    fn issue_returns_ok_and_stores() {
        let _g = test_lock();
        let c = issue_challenge(CHAIN, ENV).unwrap();
        assert!(has_outstanding_challenge());
        assert_eq!(consume_outstanding_challenge().unwrap().nonce(), c.nonce());
    }

    #[test]
    fn two_issues_return_different_nonces() {
        let _g = test_lock();
        let a = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let b = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        assert_ne!(a, b, "each (re)issue draws a fresh nonce");
    }

    #[test]
    fn nonce_is_high_entropy() {
        // Cheap defence against a degraded/stub CSPRNG (a counter would pass plain assert_ne!):
        // many draws are all-distinct and not a low-entropy constant.
        let _g = test_lock();
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let n = *issue_challenge(CHAIN, ENV).unwrap().nonce();
            assert_ne!(n, [0u8; DIGEST_LEN], "nonce must not be all-zero");
            assert!(seen.insert(n), "draws must be unique");
        }
    }

    #[test]
    fn reissue_rotates_outstanding() {
        let _g = test_lock();
        let n1 = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let n2 = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        assert_ne!(n1, n2);
        assert!(has_outstanding_challenge());
    }

    #[test]
    fn verify_outstanding_with_no_challenge_errs() {
        let _g = test_lock();
        let cfg = test_config();
        assert_eq!(
            verify_outstanding_response(&[0xa1, 0x01, 0x00], &cfg),
            Err(ChallengeVerifyError::NoOutstandingChallenge)
        );
    }

    #[test]
    fn verify_outstanding_success_returns_state_and_consumes() {
        use ed25519_dalek::SigningKey;
        let _g = test_lock();
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut cfg = test_config();
        cfg.anchor_root = key.verifying_key().to_bytes();
        let c = issue_challenge(CHAIN, ENV).unwrap();
        let nonce = *c.nonce();
        // A valid anchor response echoing the issued nonce → Ok(AnchorState) AND the challenge is
        // retired (the same take()-before-verify path as the failure case).
        let resp = crate::agent_anchor::test_signed_response_bytes(
            &key, CHAIN, ENV, 7, 2, [0xab; 32], nonce,
        );
        let (st, ret_nonce) =
            verify_outstanding_response(&resp, &cfg).expect("a valid signed response verifies");
        assert_eq!(st.epoch, 7);
        assert_eq!(
            ret_nonce, nonce,
            "the primitive returns the consumed nonce VALUE it verified against"
        );
        assert!(
            !has_outstanding_challenge(),
            "challenge consumed on success"
        );
        // a replay of the (now-retired) valid response finds no outstanding challenge
        assert_eq!(
            verify_outstanding_response(&resp, &cfg),
            Err(ChallengeVerifyError::NoOutstandingChallenge)
        );
    }

    #[test]
    fn verify_outstanding_consumes_even_on_failure() {
        let _g = test_lock();
        let cfg = test_config();
        issue_challenge(CHAIN, ENV).unwrap();
        // Garbage bytes → anchor verify fails, BUT the challenge is taken first, so it is retired
        // regardless of the verify result (structural single-use).
        let r = verify_outstanding_response(&[0xff, 0xff, 0xff], &cfg);
        assert!(matches!(r, Err(ChallengeVerifyError::Anchor(_))));
        assert!(
            !has_outstanding_challenge(),
            "challenge consumed even on verify failure"
        );
        // a replay now finds no outstanding challenge
        assert_eq!(
            verify_outstanding_response(&[0xff, 0xff, 0xff], &cfg),
            Err(ChallengeVerifyError::NoOutstandingChallenge)
        );
    }

    #[test]
    fn consume_returns_issued_challenge() {
        let _g = test_lock();
        let n = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let taken = consume_outstanding_challenge().expect("a challenge was outstanding");
        assert_eq!(taken.nonce(), &n);
        assert_eq!(
            taken.report_data(),
            anchor_handshake_report_data(CHAIN, ENV, &n),
            "report_data binds the same stored draw"
        );
        assert!(!has_outstanding_challenge(), "consume retires the slot");
    }

    #[test]
    fn reissue_then_consume_takes_newest() {
        let _g = test_lock();
        let n1 = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let n2 = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let taken = consume_outstanding_challenge().unwrap();
        assert_eq!(
            taken.nonce(),
            &n2,
            "consume takes the newest (overwrite) challenge"
        );
        assert_ne!(taken.nonce(), &n1);
        assert!(!has_outstanding_challenge());
    }

    #[test]
    fn single_use_replay_after_consume_is_none() {
        let _g = test_lock();
        issue_challenge(CHAIN, ENV).unwrap();
        assert!(
            consume_outstanding_challenge().is_some(),
            "first consume retires it"
        );
        assert!(
            consume_outstanding_challenge().is_none(),
            "a replayed (nonce,response) finds an empty slot"
        );
    }

    #[test]
    fn consume_with_empty_slot_is_none() {
        let _g = test_lock();
        assert!(consume_outstanding_challenge().is_none());
        assert!(!has_outstanding_challenge());
    }

    #[test]
    fn report_data_binds_same_draw() {
        let _g = test_lock();
        let c = issue_challenge(CHAIN, ENV).unwrap();
        // The one stored draw flows to BOTH report_data (SNP quote) and (later) verify's expected_nonce.
        assert_eq!(
            c.report_data(),
            anchor_handshake_report_data(CHAIN, ENV, c.nonce())
        );
    }
}
