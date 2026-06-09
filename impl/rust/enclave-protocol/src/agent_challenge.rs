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
//! ## Boot-slice obligations (deferred; not satisfied by these primitives alone)
//! - **Scope/ordering.** `chain_id`/`environment_identifier` come from the *unsealed* `KeystoreConfig`,
//!   so [`issue_challenge`] runs **after** the keystore is unsealed (not before). Exact placement in
//!   the boot ceremony is the boot-wiring slice's decision.
//! - **Single handshake in flight.** `issue_challenge` is called once per (re)start and no second
//!   issue overlaps an outstanding verify (the boot ceremony is single-threaded). The boot caller must
//!   route **every** verify outcome (Ok, Err, and timeout/unavailable) through
//!   [`consume_outstanding_challenge`] and, on success, assert the returned `Challenge.nonce()` equals
//!   the nonce it verified against — the fail-closed backstop if the peek/verify/take sequence ever
//!   races a reissue. A retry MUST `issue_challenge` afresh, never re-use a peeked nonce.
//!
//! Like the rest of the anchor path this is dead-code-gated until boot wiring calls it.

#![cfg_attr(not(test), allow(dead_code))]

use crate::agent_anchor::{anchor_handshake_report_data, DIGEST_LEN};
use std::sync::Mutex;

/// Why issuing a challenge failed. Coarse + fail-closed; the underlying `getrandom` detail is
/// discarded (no oracle), matching every other CSPRNG site in the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeError {
    /// The platform CSPRNG was unavailable when drawing the nonce.
    Csprng,
}

/// One outstanding freshness challenge. **Volatile process state only** — deliberately NOT
/// `Serialize`/`Deserialize` (so it can't enter sealed/host-relayed state, see the module invariants)
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

/// Retire the outstanding challenge (the single-use primitive): `take()` the slot under the lock and
/// return what it took (`None` if there was none). The boot caller routes **every** verify outcome
/// through this, then on success asserts the returned `Challenge.nonce()` equals the nonce it verified
/// against. After this, a replayed `(nonce, response)` finds an empty (or rotated) slot.
pub(crate) fn consume_outstanding_challenge() -> Option<Challenge> {
    OUTSTANDING_CHALLENGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
}

/// Non-consuming peek at the outstanding nonce (copies the public nonce). The boot caller pulls this
/// **once** to drive the `report_data` binding + verify's `expected_nonce`. MUST NOT be used to drive a
/// retry of the same handshake — a retry MUST [`issue_challenge`] afresh.
pub(crate) fn outstanding_nonce() -> Option<[u8; DIGEST_LEN]> {
    OUTSTANDING_CHALLENGE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|c| c.nonce)
}

/// Whether a challenge is currently outstanding (presence-only).
pub(crate) fn has_outstanding_challenge() -> bool {
    OUTSTANDING_CHALLENGE
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false)
}

#[cfg(test)]
pub(crate) fn reset_outstanding_challenge_for_tests() {
    if let Ok(mut guard) = OUTSTANDING_CHALLENGE.lock() {
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ENV: &str = "testnet";
    const CHAIN: u64 = 11565;

    /// Serialize the tests that touch the `OUTSTANDING_CHALLENGE` process-global (cargo runs tests in
    /// parallel) and reset the slot. Hold the returned guard for the test body's duration. Mirrors the
    /// crate's "consolidate global-state tests to avoid cross-test interference" convention, but as a
    /// reusable lock so each behavior stays its own test.
    static TEST_GUARD: Mutex<()> = Mutex::new(());
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        reset_outstanding_challenge_for_tests();
        g
    }

    #[test]
    fn issue_returns_ok_and_stores() {
        let _g = test_lock();
        let c = issue_challenge(CHAIN, ENV).unwrap();
        assert!(has_outstanding_challenge());
        assert_eq!(outstanding_nonce(), Some(*c.nonce()));
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
        assert_eq!(outstanding_nonce(), Some(n2), "reissue overwrites with the newest nonce");
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
        assert_eq!(taken.nonce(), &n2, "consume takes the newest (overwrite) challenge");
        assert_ne!(taken.nonce(), &n1);
        assert!(!has_outstanding_challenge());
    }

    #[test]
    fn single_use_replay_after_consume_is_none() {
        let _g = test_lock();
        issue_challenge(CHAIN, ENV).unwrap();
        assert!(consume_outstanding_challenge().is_some(), "first consume retires it");
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
        assert_eq!(c.report_data(), anchor_handshake_report_data(CHAIN, ENV, c.nonce()));
    }
}
