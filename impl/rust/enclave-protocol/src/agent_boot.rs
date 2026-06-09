//! Agent Gateway anti-rollback **boot reconcile orchestration** (TASK-7.7, slice 5a).
//!
//! This is the pure, platform-free *glue* between the three anchor primitives already on `main`:
//! the freshness-challenge state machine ([`crate::agent_challenge`]), the signed-response verifier +
//! reconcile rules ([`crate::agent_anchor`]), and the runtime funding gate's binding
//! ([`crate::agent_dispatch::install_anti_rollback_binding`]). Given the host-relayed anchor response
//! bytes and the unsealed [`KeystoreBody`], it runs the one canonical sequence —
//!
//! 1. `verify_outstanding_response` (atomically RETIRE the outstanding challenge **then** Ed25519-verify
//!    the response against the sealed `anchor_root`, scope, and the issued nonce),
//! 2. `compute_local_marks_digest` over the sealed counters/spend,
//! 3. `reconcile` the local `(freshness_epoch, structural_version, marks)` against the verified
//!    [`AnchorState`],
//!
//! — and turns the [`ReconcileDecision`] into a single [`BootAntiRollbackOutcome`] the boot-wiring slice
//! (5b) acts on. **The live Layer-2b binding is installed ONLY on the `Fresh` arm.** `AdoptForward`
//! returns `AdoptForwardRequired` *without* installing (5b must seed the body from the anchor's marks +
//! re-seal forward, then install), and every fail path returns `FailClosed(..)` and installs nothing.
//!
//! ## Why no binding install off the `Fresh` path (the load-bearing guarantee)
//! Installing the runtime gate's binding is what *unblocks* fund custody for this boot. It must happen
//! exactly once, only after a reconcile that proves the sealed state is current. Four independent
//! properties enforce that here:
//! - **Construction-in-arm.** The `AntiRollbackBinding` value is *constructed inside the `Fresh` match
//!   arm only* — there is no binding literal anywhere else to install by mistake.
//! - **Exhaustive, wildcard-free match.** The `match decision { Fresh => .., AdoptForward { .. } => ..,
//!   FailClosed(_) => .. }` has no `_` arm, so a future `ReconcileDecision` variant is a compile error
//!   here rather than silently falling through to (or away from) an install.
//! - **Const-init fail-closed default.** `ANTI_ROLLBACK_BINDING` is const-init `None`; if this function
//!   is never reached, or returns any non-`Ready` outcome, the gate stays unconfigured ⇒ blocked.
//! - **Callee install-once + reject-inactive.** `install_anti_rollback_binding` itself refuses a second
//!   install and refuses an `!active` binding, so even a buggy double-call can't fail open.
//!
//! ## UNWIRED — 5b adds the only caller
//! Nothing calls [`boot_reconcile_anti_rollback`] yet: the SNP-quote fetch (the enclave's side of the
//! *mutual* handshake), the vsock host relay that delivers `response_bytes`, the `AdoptForward`
//! re-seed/re-seal, and the at-boot call sequencing (`issue_challenge` after unseal → relay → this) are
//! the **platform/host** slice 5b, validated on real SNP hardware. So the whole module is dead-code in
//! the non-test lib build (the inner attribute below); the test build still type- and use-checks it.
#![cfg_attr(not(test), allow(dead_code))]

/// The outcome of the boot anti-rollback ceremony, ready for slice 5b to act on. Carries the verified
/// [`crate::agent_anchor::AnchorState`] on the two non-fail arms so 5b can install / seed / audit from
/// the authoritative epoch + marks without re-verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootAntiRollbackOutcome {
    /// Sealed state is current (`reconcile` ⇒ `Fresh`) AND the runtime Layer-2b binding was installed.
    /// Fund custody is unblocked for this boot.
    Ready(crate::agent_anchor::AnchorState),
    /// Anchor is ahead by a counter/spend-only gap (`reconcile` ⇒ `AdoptForward`). **No binding
    /// installed** — 5b must seed the body from the anchor's marks (asserting adopted ≥ local), re-seal
    /// forward to `state.epoch`, then re-run the ceremony so the now-current state reconciles `Fresh`.
    /// The carried `AnchorState` gives 5b the authoritative `epoch` + `structural_version` to re-seal to;
    /// its `marks_digest` is a hash (decides the reconcile, not invertible), so the *actual* counter/
    /// spend marks to seed come from the boot-wiring channel that delivers them (per `agent_anchor`'s
    /// data model), NOT from this outcome.
    AdoptForwardRequired(crate::agent_anchor::AnchorState),
    /// This invocation did not newly configure custody — the caller MUST NOT proceed (abort / don't
    /// serve). No `FailClosed` arm constructs or installs a NEW binding. On a clean boot the gate
    /// therefore stays blocked (const-init `None`). **One nuance:** `BindingInstall` means a *prior*
    /// `Fresh` ceremony already (validly) installed the binding **this same process**, so
    /// `is_anti_rollback_configured()` may legitimately still read configured off that earlier, valid
    /// install — that is an internal sequencing defect (the ceremony ran twice), NOT this invocation
    /// leaving the gate open by a failure. Treat it as fatal/abort regardless (see `BindingInstall`).
    FailClosed(BootFailReason),
}

/// Why the boot anti-rollback ceremony failed closed. Flattens the verify-stage errors
/// ([`crate::agent_challenge::ChallengeVerifyError`] / [`crate::agent_anchor::AnchorError`]) and the
/// reconcile-stage fail reasons ([`crate::agent_anchor::FailReason`]) into one boot-time enum, plus the
/// install-step failure. Coarse + fail-closed (the handshake is a boot ceremony, not a host-probeable
/// per-request surface), so no anti-oracle band is needed — but each cause stays distinct for the boot
/// log / operator triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootFailReason {
    /// No challenge was outstanding when the response arrived (never issued, or already consumed — a
    /// replayed response after a prior verify).
    NoChallenge,
    /// Verify stage: the response was not strict-canonical CBOR / unknown version / wrong shape.
    VerifyMalformed,
    /// Verify stage: Ed25519 verification against the sealed `anchor_root` failed (or the root is not a
    /// valid key).
    VerifySignatureInvalid,
    /// Verify stage: the response was for a different `(chain_id, environment_identifier)` scope.
    VerifyScopeMismatch,
    /// Verify stage: the response did not echo this (re)start's challenge nonce (stale/replayed).
    VerifyNonceMismatch,
    /// Reconcile stage: anchor epoch < local epoch — the anchor itself was rolled back / is inconsistent.
    AnchorBehind,
    /// Reconcile stage: epoch ahead with a structural_version mismatch — a dropped structural mutation
    /// the anchor can't reconstruct ⇒ restore from backup (handled outside this ceremony).
    StructuralGap,
    /// Reconcile stage: same epoch but marks / structural_version disagree — corrupt/inconsistent state.
    Inconsistent,
    /// `Fresh` reconcile but the runtime binding could not be installed (already present this process —
    /// a boot-sequencing bug, since the slot is const-init `None` and install-once). **Unlike the
    /// host/anchor-driven reasons above, this signals an enclave-INTERNAL defect, not operator-
    /// recoverable state** — 5b triage should treat it as a code bug (the ceremony ran twice), not as an
    /// operator-action condition like `AnchorBehind`/`StructuralGap`. Still fail-closed, never `Ready`.
    BindingInstall,
}

/// Run the boot anti-rollback ceremony for a freshly unsealed keystore: verify the host-relayed anchor
/// `response_bytes` against the outstanding challenge + sealed `anchor_root`, reconcile the local sealed
/// `(freshness_epoch, structural_version, marks)` against the verified anchor state, and — only when the
/// reconcile is `Fresh` — install the runtime Layer-2b [`crate::agent_dispatch::AntiRollbackBinding`]
/// that unblocks fund custody for this boot.
///
/// Returns [`BootAntiRollbackOutcome`]. The caller (slice 5b) MUST NOT proceed (abort / don't serve
/// rollback-sensitive frames) on any variant other than `Ready`: `AdoptForwardRequired` needs a
/// seed/re-seal pass before a fresh-challenge retry, host/anchor `FailClosed` reasons need operator
/// intervention, and `FailClosed(BindingInstall)` is a fatal internal sequencing defect (the ceremony
/// ran twice). Note "don't proceed" is the caller's obligation, not a guarantee the gate slot reads
/// unconfigured — on the `BindingInstall` path a prior valid `Fresh` install legitimately remains (see
/// the `FailClosed` variant doc).
///
/// # Preconditions (owned by the boot-wiring caller, slice 5b)
/// - A challenge MUST have been issued this (re)start via [`crate::agent_challenge::issue_challenge`]
///   *after* the keystore was unsealed, and the SAME draw's `report_data` bound into the SNP quote — so
///   the nonce this verifies against is fresh, unpredictable, and single-use (the whole anti-replay
///   guarantee; see [`crate::agent_challenge`] module docs).
/// - `response_bytes` is the untrusted host-relayed anchor response; it is strict-canonical-decoded and
///   signature-checked inside, so no pre-validation is required (or trusted).
pub(crate) fn boot_reconcile_anti_rollback(
    response_bytes: &[u8],
    body: &crate::agent_keystore::KeystoreBody,
) -> BootAntiRollbackOutcome {
    // 1. Verify the response against the outstanding challenge (take-before-verify ⇒ the nonce is
    //    retired on every outcome) and the sealed config.
    let state = match crate::agent_challenge::verify_outstanding_response(response_bytes, &body.config)
    {
        Ok(s) => s,
        Err(crate::agent_challenge::ChallengeVerifyError::NoOutstandingChallenge) => {
            return BootAntiRollbackOutcome::FailClosed(BootFailReason::NoChallenge);
        }
        Err(crate::agent_challenge::ChallengeVerifyError::Anchor(e)) => {
            return BootAntiRollbackOutcome::FailClosed(map_anchor_error(e));
        }
    };

    // 2. Recompute the local counter/spend marks digest from the sealed body.
    let local_marks = body.compute_local_marks_digest();

    // 3. Reconcile local sealed state against the verified anchor state.
    let decision = crate::agent_anchor::reconcile(
        body.freshness_epoch,
        body.structural_version,
        &local_marks,
        &state,
    );

    // Exhaustive, wildcard-free: a new ReconcileDecision variant is a compile error here, not a silent
    // install/skip. The binding literal exists ONLY in the `Fresh` arm.
    match decision {
        crate::agent_anchor::ReconcileDecision::Fresh => {
            let binding =
                crate::agent_dispatch::AntiRollbackBinding { epoch: state.epoch, active: true };
            if crate::agent_dispatch::install_anti_rollback_binding(binding) {
                BootAntiRollbackOutcome::Ready(state)
            } else {
                BootAntiRollbackOutcome::FailClosed(BootFailReason::BindingInstall)
            }
        }
        crate::agent_anchor::ReconcileDecision::AdoptForward { .. } => {
            BootAntiRollbackOutcome::AdoptForwardRequired(state)
        }
        crate::agent_anchor::ReconcileDecision::FailClosed(r) => {
            BootAntiRollbackOutcome::FailClosed(map_fail_reason(r))
        }
    }
}

/// Flatten a verify-stage [`crate::agent_anchor::AnchorError`] into a [`BootFailReason`]. Wildcard-free
/// so a new `AnchorError` variant forces an explicit decision here.
fn map_anchor_error(e: crate::agent_anchor::AnchorError) -> BootFailReason {
    use crate::agent_anchor::AnchorError;
    match e {
        AnchorError::Malformed => BootFailReason::VerifyMalformed,
        AnchorError::SignatureInvalid => BootFailReason::VerifySignatureInvalid,
        AnchorError::ScopeMismatch => BootFailReason::VerifyScopeMismatch,
        AnchorError::NonceMismatch => BootFailReason::VerifyNonceMismatch,
    }
}

/// Flatten a reconcile-stage [`crate::agent_anchor::FailReason`] into a [`BootFailReason`]. Wildcard-free
/// so a new `FailReason` variant forces an explicit decision here.
fn map_fail_reason(r: crate::agent_anchor::FailReason) -> BootFailReason {
    use crate::agent_anchor::FailReason;
    match r {
        FailReason::AnchorBehind => BootFailReason::AnchorBehind,
        FailReason::StructuralGap => BootFailReason::StructuralGap,
        FailReason::Inconsistent => BootFailReason::Inconsistent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_challenge::issue_challenge;
    use crate::agent_dispatch::{
        install_anti_rollback_binding, is_anti_rollback_configured, AntiRollbackBinding,
    };
    use crate::agent_keystore::{AuditRing, FaucetState, KeystoreBody, KeystoreConfig};
    use ed25519_dalek::SigningKey;

    const ENV: &str = "testnet";
    const CHAIN: u64 = 11565;

    /// Serialize every test here: they all drive BOTH the `OUTSTANDING_CHALLENGE` and the
    /// `ANTI_ROLLBACK_BINDING` process-globals (cargo runs tests in parallel). Delegates to the
    /// crate-wide [`crate::agent_dispatch::lock_and_reset_agent_process_globals`] — the SAME mutex
    /// `agent_challenge` and `agent_dispatch` tests lock, which also resets every agent global on entry
    /// — so this module doesn't race them and no test inherits another's state.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::agent_dispatch::lock_and_reset_agent_process_globals()
    }

    /// The anchor's signing key; its verifying key is the body's sealed `anchor_root`.
    fn anchor_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    /// A `KeystoreBody` mirroring `agent_dispatch::base_body()`, with `anchor_root` set to the test
    /// anchor key and the local `(freshness_epoch, structural_version)` made tunable.
    fn test_body(freshness_epoch: u64, structural_version: u64) -> KeystoreBody {
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: CHAIN,
                environment_identifier: ENV.to_string(),
                admin_authority_pk: [0xa1; 32],
                recovery_authority_pk: [0xa2; 32],
                backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
                monotonic_treasury_config_version: 1,
                authority_epoch: 0,
                anchor_root: anchor_key().verifying_key().to_bytes(),
            },
            entries: vec![],
            counters: vec![],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 21000,
                max_effective_gas_fee_rate: 100,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
            },
            audit: AuditRing { records: vec![], capacity: 64, last_exported_seq: 0, next_seq: 1 },
            freshness_epoch,
            structural_version,
            strict_recovery_counter: 0,
        }
    }

    /// Issue a fresh challenge and build the canonically-signed anchor response bytes for
    /// `(epoch, structural_version, marks)` echoing the issued nonce, signed by `signer`. Returns the
    /// response bytes. (Use `anchor_key()` for a valid signature; a different key for the invalid case.)
    fn issue_and_sign(
        signer: &SigningKey,
        epoch: u64,
        structural_version: u64,
        marks: [u8; 32],
    ) -> Vec<u8> {
        let nonce = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        crate::agent_anchor::test_signed_response_bytes(
            signer,
            CHAIN,
            ENV,
            epoch,
            structural_version,
            marks,
            nonce,
        )
    }

    #[test]
    fn fresh_returns_ready_and_installs_binding() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        // Same epoch + structural + matching marks, valid signature, echoed nonce ⇒ Fresh ⇒ Ready.
        let resp = issue_and_sign(&anchor_key(), 7, 2, marks);
        match boot_reconcile_anti_rollback(&resp, &body) {
            BootAntiRollbackOutcome::Ready(st) => {
                assert_eq!(st.epoch, 7);
                assert_eq!(st.structural_version, 2);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
        assert!(is_anti_rollback_configured(), "binding installed on the Fresh arm");
    }

    #[test]
    fn adopt_forward_returns_required_no_install() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // Anchor epoch ahead, same structural_version ⇒ AdoptForward (counter/spend gap). Marks are not
        // compared on the Greater+same-structural arm.
        let resp = issue_and_sign(&anchor_key(), 6, 2, [0x00; 32]);
        match boot_reconcile_anti_rollback(&resp, &body) {
            BootAntiRollbackOutcome::AdoptForwardRequired(st) => {
                assert_eq!(st.epoch, 6);
                // structural_version is load-bearing: 5b re-seals forward to the carried state, so a
                // swapped/wrong value here would mis-seed the body.
                assert_eq!(st.structural_version, 2);
            }
            other => panic!("expected AdoptForwardRequired, got {other:?}"),
        }
        assert!(!is_anti_rollback_configured(), "AdoptForward must NOT install the binding");
    }

    #[test]
    fn anchor_behind_fails_closed() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // Anchor epoch < local ⇒ AnchorBehind.
        let resp = issue_and_sign(&anchor_key(), 4, 2, [0x00; 32]);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::AnchorBehind)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn structural_gap_fails_closed() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // Anchor epoch ahead AND structural_version ahead ⇒ StructuralGap (restore-from-backup).
        let resp = issue_and_sign(&anchor_key(), 7, 3, [0x00; 32]);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::StructuralGap)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn inconsistent_same_epoch_marks_mismatch() {
        let _g = test_lock();
        let body = test_body(5, 2);
        let local_marks = body.compute_local_marks_digest();
        // Same epoch + structural, but marks differ from local ⇒ Inconsistent. (SHA3-256 of the sealed
        // marks is never all-zero, so [0x00;32] is guaranteed to differ.)
        assert_ne!(local_marks, [0x00; 32]);
        let resp = issue_and_sign(&anchor_key(), 5, 2, [0x00; 32]);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::Inconsistent)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn inconsistent_same_epoch_structural_mismatch() {
        let _g = test_lock();
        let body = test_body(5, 2);
        let local_marks = body.compute_local_marks_digest();
        // Same epoch + matching marks, but structural_version differs ⇒ Inconsistent (the Equal arm's
        // `&&` fails closed on either divergence; this pins the structural-only sub-case).
        let resp = issue_and_sign(&anchor_key(), 5, 3, local_marks);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::Inconsistent)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn verify_signature_invalid_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        // Correct nonce + scope, but signed by the WRONG key vs the sealed anchor_root ⇒ SignatureInvalid.
        let resp = issue_and_sign(&SigningKey::from_bytes(&[9u8; 32]), 7, 2, marks);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::VerifySignatureInvalid)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn verify_nonce_mismatch_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        // Issue a challenge, then sign a response echoing a DIFFERENT nonce (valid signature + scope) ⇒
        // NonceMismatch (stale/replayed response).
        let nonce = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let mut wrong = nonce;
        wrong[0] ^= 0xff; // guaranteed != nonce
        let resp =
            crate::agent_anchor::test_signed_response_bytes(&anchor_key(), CHAIN, ENV, 7, 2, marks, wrong);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::VerifyNonceMismatch)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn verify_scope_mismatch_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        // Sign a valid response (right key + echoed nonce) but for a DIFFERENT chain_id ⇒ the signature
        // verifies over that scope's preimage, then the scope check fails ⇒ ScopeMismatch.
        let nonce = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let resp = crate::agent_anchor::test_signed_response_bytes(
            &anchor_key(),
            999, // wrong chain
            ENV,
            7,
            2,
            marks,
            nonce,
        );
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::VerifyScopeMismatch)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn verify_malformed_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        // A challenge IS outstanding (so it's not NoChallenge), but the bytes aren't strict-canonical
        // CBOR ⇒ the strict decoder rejects before any signature check ⇒ Malformed.
        let _ = issue_challenge(CHAIN, ENV).unwrap();
        assert_eq!(
            boot_reconcile_anti_rollback(&[0xff, 0xff, 0xff], &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::VerifyMalformed)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn no_challenge_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        // No challenge issued this (re)start ⇒ verify_outstanding_response retires nothing ⇒ NoChallenge.
        assert_eq!(
            boot_reconcile_anti_rollback(&[0xa1, 0x01, 0x00], &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::NoChallenge)
        );
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn binding_install_already_present_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        // Pre-install a binding (simulating a boot-sequencing bug), then a Fresh reconcile: the
        // install-once callee returns false ⇒ BindingInstall (NOT Ready), and the original binding stays.
        assert!(install_anti_rollback_binding(AntiRollbackBinding { epoch: 1, active: true }));
        let resp = issue_and_sign(&anchor_key(), 7, 2, marks);
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::BindingInstall)
        );
        // The pre-existing binding is left untouched (install-once never overwrites/clears), so the
        // gate stays configured — boot_reconcile neither swapped nor wiped the live slot on this path.
        assert!(is_anti_rollback_configured());
    }

    #[test]
    fn no_install_on_any_non_fresh_arm() {
        let _g = test_lock();
        // Sweep every non-Fresh outcome in sequence and assert the binding slot stays empty throughout —
        // a single guard against any future arm accidentally installing. Each step issues its own fresh
        // challenge (verify consumes it).
        let body = test_body(5, 2);
        let local_marks = body.compute_local_marks_digest();

        // AdoptForward
        let r = issue_and_sign(&anchor_key(), 6, 2, [0x00; 32]);
        assert!(matches!(
            boot_reconcile_anti_rollback(&r, &body),
            BootAntiRollbackOutcome::AdoptForwardRequired(_)
        ));
        assert!(!is_anti_rollback_configured());

        // StructuralGap
        let r = issue_and_sign(&anchor_key(), 7, 3, [0x00; 32]);
        assert!(matches!(
            boot_reconcile_anti_rollback(&r, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::StructuralGap)
        ));
        assert!(!is_anti_rollback_configured());

        // AnchorBehind
        let r = issue_and_sign(&anchor_key(), 4, 2, [0x00; 32]);
        assert!(matches!(
            boot_reconcile_anti_rollback(&r, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::AnchorBehind)
        ));
        assert!(!is_anti_rollback_configured());

        // Inconsistent (same epoch, marks differ)
        let r = issue_and_sign(&anchor_key(), 5, 2, [0x00; 32]);
        assert_ne!(local_marks, [0x00; 32]);
        assert!(matches!(
            boot_reconcile_anti_rollback(&r, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::Inconsistent)
        ));
        assert!(!is_anti_rollback_configured());

        // VerifyMalformed (challenge outstanding, garbage bytes)
        let _ = issue_challenge(CHAIN, ENV).unwrap();
        assert!(matches!(
            boot_reconcile_anti_rollback(&[0xff, 0xff, 0xff], &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::VerifyMalformed)
        ));
        assert!(!is_anti_rollback_configured(), "no non-Fresh arm ever installs the binding");
    }
}
