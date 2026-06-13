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
//! returns `AdoptForwardRequired` *without* installing — and 5b must NOT install directly on it: it has
//! to obtain the anchor's raw marks over a separate `anchor_root`-signed channel, assert
//! `hash(adopted_marks) == state.marks_digest` (digest equality, NOT only `adopted ≥ local`), re-seal
//! forward, then re-run the FULL ceremony (fresh challenge + response) so the now-current state
//! reconciles `Fresh` — the only arm that installs. Until that signed raw-marks channel exists,
//! `AdoptForward` is fail-closed (see the slice-5b contract in `agent-gateway-anti-rollback.md` §8).
//! Every fail path returns `FailClosed(..)` and installs nothing.
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
//! - **Const-init fail-closed default.** `ANTI_ROLLBACK_BINDING` is const-init `None`; no non-`Ready`
//!   outcome installs a NEW binding, so on a clean boot the gate stays unconfigured ⇒ blocked. (The one
//!   exception is `FailClosed(BindingInstall)` after a double-invoke, where a *prior* valid `Fresh`
//!   install legitimately remains — an internal sequencing defect the caller must abort on, not this
//!   call opening the gate; see the `FailClosed` variant doc.)
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
    /// installed, and 5b must NOT install directly on this arm.** 5b must obtain the anchor's raw marks
    /// over a separate `anchor_root`-signed channel, assert **`hash(adopted_marks) == state.marks_digest`**
    /// (digest equality authenticates the host-relayed raw marks — the weaker `adopted ≥ local` alone
    /// lets a host forge large-but-`≥-local` marks), re-seal forward to `state.epoch`, then re-run the
    /// FULL ceremony (fresh challenge + response) so the now-current state reconciles `Fresh` — the only
    /// arm that installs. The carried `AnchorState` gives 5b the authoritative `epoch` +
    /// `structural_version` to re-seal to; its `marks_digest` is a non-invertible hash (it decides the
    /// reconcile and authenticates the raw marks), so the *actual* marks to seed come from that signed
    /// channel, NOT from this outcome. The carried `nonce` is the SAME single-use freshness nonce this
    /// attempt consumed — 5b binds the raw-marks message to it (§E2/D4), so the slot is already retired
    /// (single-use preserved) yet the marks channel verifies against the exact nonce this attempt used.
    AdoptForwardRequired {
        state: crate::agent_anchor::AnchorState,
        nonce: [u8; crate::agent_anchor::DIGEST_LEN],
    },
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
    // 1. RETIRE-then-verify through the ONE safe primitive `verify_outstanding_response` (consume the
    //    challenge FIRST ⇒ the nonce is retired on every outcome, single-use is structural), which hands
    //    back the consumed nonce VALUE so the AdoptForward arm can bind the raw-marks message to the SAME
    //    nonce (§E2/D4) WITHOUT a separate non-consuming peek. Routing the boot path through the primitive
    //    (rather than re-inlining its consume→verify decomposition) keeps the verify logic single-sourced.
    //    The nonce is a fresh-per-restart CSPRNG draw the host cannot predict, and a replayed
    //    `(nonce, response)` after this attempt finds an empty slot (`NoOutstandingChallenge` → NoChallenge).
    let (state, nonce) = match crate::agent_challenge::verify_outstanding_response(
        response_bytes,
        &body.config,
    ) {
        Ok(sn) => sn,
        Err(crate::agent_challenge::ChallengeVerifyError::NoOutstandingChallenge) => {
            return BootAntiRollbackOutcome::FailClosed(BootFailReason::NoChallenge)
        }
        Err(crate::agent_challenge::ChallengeVerifyError::Anchor(e)) => {
            return BootAntiRollbackOutcome::FailClosed(map_anchor_error(e))
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
            // Carry the consumed nonce VALUE out so 5b's marks fetch binds to the SAME single-use nonce.
            BootAntiRollbackOutcome::AdoptForwardRequired { state, nonce }
        }
        crate::agent_anchor::ReconcileDecision::FailClosed(r) => {
            BootAntiRollbackOutcome::FailClosed(map_fail_reason(r))
        }
    }
}

/// Why executing an `AdoptForward` (the 5b-2e raw-marks adopt) failed closed. Each cause is a terminal
/// refusal of the adopt — the boot must NOT serve rollback-sensitive frames on any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdoptForwardFail {
    /// The raw-marks message did not verify (signature / scope / nonce / epoch) vs the sealed config.
    MarksVerify(crate::agent_anchor::MarksError),
    /// The authenticated marks payload was not strict-canonical / wrong shape / over-cap.
    MarksDecode,
    /// **THE security boundary:** the host-relayed raw marks, re-hashed via the production digest path,
    /// did NOT equal the anchor's signed `state.marks_digest`. A forged (large-but-`≥-local`) marks set
    /// fails here — the `≥`-belt would have admitted it.
    HashMismatch,
    /// Defense-in-depth belt (AFTER the hash gate): a surface that is `< local` (a non-monotone adopt).
    /// Unreachable for a genuine anchor high-water; a free tripwire if the hash path were ever weakened.
    BeltRegression,
    /// The seeded candidate body failed `validate()` (env-fold / caps / field lengths).
    Seed,
}

/// Execute an `AdoptForward`: verify the host-relayed `anchor_root`-signed raw-marks message, decode it
/// strictly, build a candidate body seeded from it, and — THE SECURITY GATE — require the candidate's
/// `compute_local_marks_digest()` (the EXACT production digest path) to equal the anchor's signed
/// `state.marks_digest` **byte-for-byte**. Returns the authenticated, epoch-advanced candidate body for
/// the driver to re-run reconcile against (it will reconcile `Fresh` and install). On ANY failure
/// returns `Err` and the caller seeds/installs NOTHING (the original body is untouched — `body` is
/// borrowed, the candidate is a local clone).
///
/// `nonce` is the SAME single-use freshness nonce this attempt consumed (carried out of
/// `boot_reconcile_anti_rollback`); the marks message must echo it (anti-splice). `state` is the
/// verified freshness `AnchorState` — its `epoch` is the re-seal target and its `marks_digest` is the
/// gate's authority.
///
/// **Why forgery is structurally dead & drift-proof:** the gate computes the digest via the *same*
/// `KeystoreBody::compute_local_marks_digest` the local body and the anchor co-sign use (no second
/// digest impl to drift); over a re-built candidate (clone + overwrite-4-surfaces → canonical
/// re-encode), so only the *canonical* form's digest can match. A non-canonical inner payload never
/// reaches the digest at all — step 2's `strict_decode_marks_payload` enforces strictly-ascending row
/// order + minimal-length integers and rejects any reorder/dup/slack as `MarksDecode`; the
/// canonical-only candidate re-encode is belt-and-suspenders BEHIND that decode gate, not the primary
/// guard. The `≥`-belt is *additional*, never the gate. A host supplying arbitrarily-large-but-`≥-local`
/// marks produces a candidate whose digest `≠ state.marks_digest` (the anchor signed the genuine digest)
/// → `HashMismatch`.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 4/8; the driver execute arm lands in commit 6
pub(crate) fn execute_adopt_forward(
    marks_bytes: &[u8],
    body: &crate::agent_keystore::KeystoreBody,
    state: &crate::agent_anchor::AnchorState,
    nonce: &[u8; crate::agent_anchor::DIGEST_LEN],
) -> Result<crate::agent_keystore::KeystoreBody, AdoptForwardFail> {
    // 1. Verify the marks message: Ed25519 vs sealed anchor_root, same scope + same nonce + same epoch.
    let marks_payload =
        crate::agent_anchor::verify_marks_response_bytes(marks_bytes, nonce, state.epoch, &body.config)
            .map_err(AdoptForwardFail::MarksVerify)?;
    // 2. Strict-decode the INNER marks payload (canonical, capped at MAX_COUNTER_ENTRIES, scope_class<=255,
    //    no depth-slack) — never trust the inner bstr's bytes, only its canonical decode.
    let decoded = crate::agent_cbor::strict_decode_marks_payload(
        &marks_payload,
        crate::agent_keystore::MAX_COUNTER_ENTRIES,
    )
    .map_err(|_| AdoptForwardFail::MarksDecode)?;
    // 3. Build a CANDIDATE = clone local + overwrite EXACTLY the 4 marks surfaces (env from config) +
    //    freshness_epoch = state.epoch; validate(). The original `body` is untouched.
    let mut candidate = body.clone();
    candidate.seed_marks_forward(&decoded, state.epoch).map_err(|_| AdoptForwardFail::Seed)?;
    // 4. THE GATE — recompute via the production digest path, CONSTANT-TIME byte-compare. Fail-closed,
    //    no install. Constant-time is defense-in-depth, NOT the load-bearing guard: the chosen-input
    //    timing attack a plain `!=` would expose is already foreclosed upstream — step 1's Ed25519
    //    `verify_strict` means a host cannot vary `candidate` without a valid anchor signature, so it
    //    cannot adaptively probe prefix-matches against `state.marks_digest`. We still compare in
    //    constant time because it is the house standard for every fund-custody digest comparison and
    //    removes the premise entirely (subtle's `ct_eq` over both 32-byte digests; no early exit).
    use subtle::ConstantTimeEq;
    let local_digest = candidate.compute_local_marks_digest();
    if !bool::from(local_digest.as_slice().ct_eq(state.marks_digest.as_slice())) {
        return Err(AdoptForwardFail::HashMismatch);
    }
    // 5. Defense-in-depth BELT — never the gate (the gate is the SHA3 equality above). Can never reject
    //    a genuine anchor high-water; a free tripwire if the hash path were ever weakened.
    if !marks_dominate_local(&decoded, body) {
        return Err(AdoptForwardFail::BeltRegression);
    }
    Ok(candidate)
}

/// Defense-in-depth: every adopted marks surface is `>= local`. Counter rows match by
/// `(authority, scope_class, scope_target)` — a local row absent from (or lowered by) the anchor's
/// authoritative high-water is a regression; both spends + the recovery counter must not decrease.
/// (`[u8; 32]` compares lexicographically == big-endian-u256 numeric order.) Belt-only — NEVER the gate.
///
/// ASSUMPTION (liveness, not security): this trips (`BeltRegression`, fail-closed) only if the anchor
/// signs a hash-matching snapshot that DROPS or LOWERS a row the local body still holds — which the
/// reconcile trust model rules out (the anchor records a MONOTONE, no-prune high-water,
/// `agent_anchor` reconcile doc). So it is unreachable for a genuine anchor under that model. If the
/// (not-yet-frozen) anchor data model ever allows a legitimate row prune, this belt would fail a valid
/// adopt closed (availability loss, NEVER a wrong-accept — the hash gate already authenticated the
/// state); revisit the assumption when the anchor data model freezes.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 4/8
fn marks_dominate_local(
    decoded: &crate::agent_cbor::DecodedMarks,
    body: &crate::agent_keystore::KeystoreBody,
) -> bool {
    for local in &body.counters {
        let adopted = decoded.rows.iter().find(|r| {
            r.authority == local.authority
                && r.scope_class == local.scope_class
                && r.scope_target == local.scope_target
        });
        match adopted {
            Some(r) if r.highest_accepted_counter >= local.highest_accepted_counter => {}
            _ => return false, // dropped or lowered a local counter row
        }
    }
    decoded.cumulative_native_spend >= body.faucet.cumulative_native_spend
        && decoded.lifetime_spend >= body.faucet.lifetime_spend
        && decoded.strict_recovery_counter >= body.strict_recovery_counter
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
            BootAntiRollbackOutcome::AdoptForwardRequired { state: st, .. } => {
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
            BootAntiRollbackOutcome::AdoptForwardRequired { .. }
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

    // ---- 5b-2e execute_adopt_forward: the hash-equality gate (commit 4/8) ----

    use sha3::{Digest as _, Sha3_256};

    const ADOPT_NONCE: [u8; 32] = [0x7c; 32];

    /// Hand-build a canonical (sorted) marks payload from sorted single rows + spends + recovery.
    fn marks_payload(
        rows: &[([u8; 32], u8, &[u8], u64)],
        cum: [u8; 32],
        life: [u8; 32],
        rec: u64,
    ) -> Vec<u8> {
        use crate::agent_capability::{put_bytes, put_uint};
        let mut o = Vec::new();
        put_uint(&mut o, 5, 4);
        put_uint(&mut o, 0, 1);
        put_uint(&mut o, 4, rows.len() as u64);
        for (auth, sc, tgt, ctr) in rows {
            put_uint(&mut o, 4, 4);
            put_bytes(&mut o, auth);
            put_uint(&mut o, 0, u64::from(*sc));
            put_bytes(&mut o, tgt);
            put_uint(&mut o, 0, *ctr);
        }
        put_uint(&mut o, 0, 2);
        put_bytes(&mut o, &cum);
        put_uint(&mut o, 0, 3);
        put_bytes(&mut o, &life);
        put_uint(&mut o, 0, 4);
        put_uint(&mut o, 0, rec);
        o
    }

    fn digest_of(payload: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(crate::agent_keystore::MARKS_DOMAIN);
        h.update(payload);
        h.finalize().into()
    }

    fn anchor_state(epoch: u64, structural_version: u64, marks_digest: [u8; 32]) -> crate::agent_anchor::AnchorState {
        crate::agent_anchor::AnchorState {
            epoch,
            structural_version,
            marks_digest,
            chain_height: None,
            chain_block_hash: None,
        }
    }

    fn signed_marks(epoch: u64, payload: Vec<u8>) -> Vec<u8> {
        crate::agent_anchor::test_signed_marks_response_bytes(
            &anchor_key(), CHAIN, ENV, epoch, ADOPT_NONCE, payload,
        )
    }

    #[test]
    fn execute_adopt_forward_accepts_genuine_marks() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // Genuine marks the anchor committed to: D = hash(P). The marks message carries P, signed by the
        // anchor, echoing the SAME nonce + the AnchorState epoch.
        let p = marks_payload(&[([0x11; 32], 0, b"x", 5)], [0xaa; 32], [0xbb; 32], 1);
        let state = anchor_state(6, 2, digest_of(&p));
        let marks = signed_marks(6, p.clone());
        let candidate = execute_adopt_forward(&marks, &body, &state, &ADOPT_NONCE)
            .expect("genuine marks adopt");
        assert_eq!(candidate.freshness_epoch, 6, "candidate advanced to the anchor epoch");
        assert_eq!(candidate.structural_version, 2, "structural_version unchanged");
        assert_eq!(
            candidate.compute_local_marks_digest(),
            state.marks_digest,
            "the seeded candidate now reconciles Fresh against the anchor digest"
        );
    }

    #[test]
    fn execute_adopt_forward_rejects_forged_marks_the_belt_would_admit() {
        // THE HEADLINE. The anchor committed to D = hash(GENUINE small marks). A malicious host relays a
        // VALIDLY-SIGNED marks message carrying FORGED marks — arbitrarily large counter + spend, every
        // surface >= local (so the >= belt would ADMIT it) — but hash(forged) != D. The hash-equality
        // gate fail-closes: NO seed, NO install. There is NO >= path that bypasses the gate.
        let _g = test_lock();
        let body = test_body(5, 2);
        let genuine = marks_payload(&[([0x11; 32], 0, b"x", 5)], [0x00; 32], [0x00; 32], 0);
        let state = anchor_state(6, 2, digest_of(&genuine)); // D = hash(genuine)
        // forged: counter 9_999_999, max spend, recovery huge — all >= local, but a DIFFERENT payload.
        let forged = marks_payload(
            &[([0x11; 32], 0, b"x", 9_999_999)],
            [0xff; 32],
            [0xff; 32],
            1_000_000,
        );
        assert_ne!(digest_of(&forged), state.marks_digest, "forged marks hash != the committed digest");
        let marks = signed_marks(6, forged); // validly anchor-signed, correct nonce + epoch
        assert_eq!(
            execute_adopt_forward(&marks, &body, &state, &ADOPT_NONCE),
            Err(AdoptForwardFail::HashMismatch),
            "the hash gate rejects forged-but->=-local marks the belt would have admitted"
        );
        assert!(!is_anti_rollback_configured(), "no binding installed on the forged-marks path");
    }

    #[test]
    fn execute_adopt_forward_belt_rejects_non_monotone_below_hash_gate() {
        // hash(P) == D (gate passes), but P lowers a local counter (5 < local 1000) → the belt trips.
        let _g = test_lock();
        let mut body = test_body(5, 2);
        body.counters = vec![crate::agent_keystore::CounterEntry {
            authority: [0x11; 32],
            environment_identifier: ENV.to_string(),
            scope_class: 0,
            scope_target: b"x".to_vec(),
            highest_accepted_counter: 1000,
        }];
        let p = marks_payload(&[([0x11; 32], 0, b"x", 5)], [0; 32], [0; 32], 0); // 5 < 1000
        let state = anchor_state(6, 2, digest_of(&p));
        let marks = signed_marks(6, p);
        assert_eq!(
            execute_adopt_forward(&marks, &body, &state, &ADOPT_NONCE),
            Err(AdoptForwardFail::BeltRegression)
        );
    }

    #[test]
    fn execute_adopt_forward_rejects_wrong_nonce_scope_epoch_and_signer() {
        let _g = test_lock();
        let body = test_body(5, 2);
        let p = marks_payload(&[([0x11; 32], 0, b"x", 5)], [0; 32], [0; 32], 0);
        let state = anchor_state(6, 2, digest_of(&p));
        let good = signed_marks(6, p.clone());
        // wrong nonce echo (the marks message was for ADOPT_NONCE; the gate is called with another)
        assert_eq!(
            execute_adopt_forward(&good, &body, &state, &[0x00; 32]),
            Err(AdoptForwardFail::MarksVerify(crate::agent_anchor::MarksError::NonceMismatch))
        );
        // wrong epoch: marks signed for epoch 99, but state.epoch is 6 → EpochMismatch
        let wrong_epoch = signed_marks(99, p.clone());
        assert_eq!(
            execute_adopt_forward(&wrong_epoch, &body, &state, &ADOPT_NONCE),
            Err(AdoptForwardFail::MarksVerify(crate::agent_anchor::MarksError::EpochMismatch))
        );
        // wrong signer
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let forged_sig = crate::agent_anchor::test_signed_marks_response_bytes(&other, CHAIN, ENV, 6, ADOPT_NONCE, p);
        assert_eq!(
            execute_adopt_forward(&forged_sig, &body, &state, &ADOPT_NONCE),
            Err(AdoptForwardFail::MarksVerify(crate::agent_anchor::MarksError::SignatureInvalid))
        );
    }

    #[test]
    fn boot_reconcile_carries_the_consumed_nonce_on_adopt_forward() {
        // The nonce threaded out of boot_reconcile is the SAME one the freshness leg consumed — pinned
        // so the marks-fetch (commit 6) binds to it. And single-use is preserved: a second reconcile with
        // no fresh challenge finds NoChallenge (the slot was retired).
        let _g = test_lock();
        let body = test_body(5, 2);
        let nonce = *issue_challenge(CHAIN, ENV).unwrap().nonce();
        let resp = crate::agent_anchor::test_signed_response_bytes(&anchor_key(), CHAIN, ENV, 6, 2, [0; 32], nonce);
        match boot_reconcile_anti_rollback(&resp, &body) {
            BootAntiRollbackOutcome::AdoptForwardRequired { state, nonce: out } => {
                assert_eq!(state.epoch, 6);
                assert_eq!(out, nonce, "the carried nonce is the consumed freshness nonce");
            }
            other => panic!("expected AdoptForwardRequired, got {other:?}"),
        }
        // single-use: the slot is empty now → a replay finds NoChallenge.
        assert_eq!(
            boot_reconcile_anti_rollback(&resp, &body),
            BootAntiRollbackOutcome::FailClosed(BootFailReason::NoChallenge)
        );
    }
}
