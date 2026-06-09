//! Agent Gateway anti-rollback **boot-handshake driver + serve-gate** (TASK-7.7, slice 5b-1).
//!
//! This is the bounded, retrying loop one layer ABOVE the pure single-shot
//! [`crate::agent_boot::boot_reconcile_anti_rollback`] (slice 5a). It owns the *full* boot ceremony
//! sequencing — issue a fresh freshness challenge, drive the one platform round-trip (SNP quote + host
//! relay to the anchor), feed the signed response to reconcile, classify the outcome, and retry only
//! genuine transport flakiness up to a hard bound — and a pure serve-gate the boot caller uses to
//! decide whether the agent may serve rollback-sensitive frames.
//!
//! ## The one platform dependency: [`AnchorBootTransport`]
//! The driver is generic over a single trait method, [`AnchorBootTransport::anchor_round_trip`], which
//! is the ONLY thing slice 5b-2 (real SNP / aya validation) must implement: given the public
//! [`AnchorBootRequest`] (sealed-config `(chain_id, env)`, the fresh `nonce`, and the `report_data`
//! commitment), fetch an SNP quote committing to `report_data` (via `snp_report::fetch_report`) THEN
//! relay it + the public challenge to the anchor over the *untrusted host* (an enclave-initiated vsock
//! round-trip — a genuinely new pre-serve exchange; today's transport is strictly host-initiated) and
//! return the anchor's signed response **bytes**. Those bytes are UNTRUSTED: the driver hands them
//! straight to `boot_reconcile_anti_rollback`, which strict-decodes + Ed25519-verifies them against the
//! sealed `anchor_root` and the issued nonce. **The seam is transport, never trust** — every value it
//! receives is public (the nonce/scope go to the anchor regardless) and a tampered response simply
//! fails verification downstream; it cannot choose the verify key, and the scope it carries is the
//! sealed config's (the anchor binds it via `report_data`), not a host override.
//!
//! ## Load-bearing invariants (all structural)
//! - **Never installs the binding.** There is no `AntiRollbackBinding` literal and no
//!   `install_anti_rollback_binding` call in this module — `boot_reconcile_anti_rollback` installs it
//!   ONLY on its `Fresh` arm. The driver only relays `Ready` up.
//! - **Never serves.** Serving (and calling [`agent_anti_rollback_serve_gate`]) is the boot caller's
//!   job (slice 5b-2's bin), not the driver's.
//! - **Scope from the sealed body.** `issue_challenge` is called with `(body.config.twod_chain_id,
//!   body.config.environment_identifier)` — never a host override.
//! - **Fresh challenge per attempt.** Every loop iteration issues a fresh CSPRNG nonce ⇒ fresh
//!   `report_data` ⇒ fresh quote. `verify_outstanding_response` consumes the challenge on *every*
//!   outcome, so a retry is a full new ceremony, never a replay.
//! - **Structurally bounded.** The loop is `for _ in 1..=max_attempts` — no `loop {}`, no
//!   host-controlled break ⇒ an infinite boot loop (e.g. a continuously-advancing or hostile anchor) is
//!   impossible. `max_attempts == 0` ⇒ `Unstartable` (never loops, never serves).
//! - **Fail-closed default.** Every non-`Ready` path returns `FailClosed(..)`; the caller must abort.
//!
//! ## Retry classification — anti-grind (load-bearing, fragile)
//! ONLY a transport error ([`AnchorTransportError`]) is retryable (transient liveness: configfs/
//! sev-guest hiccup, vsock blip, anchor briefly unreachable). **EVERY** [`crate::agent_boot::BootFailReason`]
//! and `AdoptForward` are TERMINAL. In particular the host-reachable verify verdicts —
//! `VerifyMalformed` / `VerifyScopeMismatch` / `VerifyNonceMismatch` / `VerifySignatureInvalid` — are
//! NOT retried: making them retryable would hand a malicious/buggy host a *grind lever* to stall boot
//! or fish for a serve decision across the attempt budget. A conformant anchor+relay always echoes the
//! issued nonce + scope and signs with the sealed `anchor_root`; a mismatch means substitution/replay/
//! corruption, and retrying rewards it. (A legitimately stale late response is already defeated — each
//! attempt issues a fresh nonce and the old slot is consumed.) `AnchorBehind`/`StructuralGap`/
//! `Inconsistent`/`BindingInstall`/`NoChallenge` are deterministic given this body, so retrying is
//! futile. `AdoptForward` is fail-closed per the §8 slice-5b contract: no `anchor_root`-signed
//! raw-marks channel exists yet, so any auto-adopt would risk seeding forged marks.
//!
//! ## UNWIRED — slice 5b-2 adds the only caller
//! Like 5a, this whole module is dead-code in the non-test lib build (the inner attribute below); the
//! test build type- and use-checks it against a mock transport. Slice 5b-2 (real SNP / aya) adds: the
//! concrete `impl AnchorBootTransport` (quote fetch + enclave-initiated vsock relay — which MUST
//! enforce a per-call timeout, correlate the reply to the current nonce, and cap the untrusted response
//! length), the agent-gateway bin + its in-crate boot module (set platform root → unseal the agent
//! keystore → `install_agent_keystore` → `run_boot_anti_rollback_handshake` →
//! `decide_serve(outcome, cfg!(release_build))?` → serve), the sealed-blob source + unseal sequencing,
//! and the `AdoptForward` signed raw-marks channel (which would eventually reclassify
//! `AdoptForwardUnsupported` from terminal to executable — only in 5b-2+). The handshake is
//! single-threaded over the challenge/binding process-globals — 5b-2 MUST NOT run it concurrently.
#![cfg_attr(not(test), allow(dead_code))]

/// The public per-attempt handshake values the driver hands the transport. All fields are PUBLIC: the
/// nonce and scope transit the untrusted host to reach the anchor anyway, and the anchor must **echo**
/// the nonce + scope in its signed response (`verify_anchor_response` checks `r.nonce`/`r.chain_id`/
/// `r.environment_identifier`). Because `report_data` is a non-invertible SHA3-512 commitment over
/// `(chain_id, env, nonce)`, the transport/anchor cannot recover those from it — so the driver supplies
/// them explicitly. `report_data` is provided too so the impl fetches the SNP quote without recomputing;
/// the anchor recomputes `report_data` from the public fields and checks it equals the quote's embedded
/// `report_data` before signing (binding the cleartext to the attestation).
pub(crate) struct AnchorBootRequest<'a> {
    /// 2D chain id from the SEALED `body.config` (never a host override).
    pub chain_id: u64,
    /// Environment identifier from the SEALED `body.config`.
    pub environment_identifier: &'a str,
    /// The fresh per-attempt CSPRNG nonce the anchor must echo in its signed response.
    pub nonce: [u8; 32],
    /// SHA3-512 commitment over `(chain_id, env, nonce)` the SNP quote must embed.
    pub report_data: [u8; 64],
}

/// The single platform dependency of the boot driver — slice 5b-2 implements it. One impl, one call
/// per attempt. The implementation fetches an SNP quote committing to `request.report_data`
/// (`snp_report::fetch_report`) then relays it — together with the public `(chain_id, env, nonce)` —
/// to the anchor over the untrusted host, and returns the anchor's **signed response bytes**. Those
/// bytes are UNTRUSTED and verified downstream (`boot_reconcile_anti_rollback` strict-decodes +
/// Ed25519-verifies them against the sealed `anchor_root` and the issued nonce); the seam is a dumb
/// transport pipe, never a trust boundary. It cannot choose the key or scope independently: the scope
/// is the sealed config (the anchor binds it via `report_data`), and a tampered response simply fails
/// verification downstream.
pub(crate) trait AnchorBootTransport {
    /// Perform the one enclave-initiated round-trip for this attempt: produce a quote bound to
    /// `request.report_data`, relay it + the public challenge to the anchor, return the anchor's signed
    /// response bytes. Any failure (quote fetch error, relay error, anchor-unavailable timeout) is a
    /// transient [`AnchorTransportError`], which the driver classifies as RETRYABLE.
    ///
    /// **5b-2 implementation obligation:** this method MUST enforce its own per-call deadline/timeout.
    /// The driver bounds the attempt COUNT (`max_attempts`), not wall-clock time — so a transport that
    /// blocks forever on a hung / black-holing host would stall boot indefinitely despite the count
    /// bound. A timed-out call MUST return [`AnchorTransportError`] (retryable) rather than block.
    fn anchor_round_trip(
        &mut self,
        request: &AnchorBootRequest,
    ) -> Result<Vec<u8>, AnchorTransportError>;
}

/// The ONLY error the seam can raise. Deliberately coarse + opaque — every transport error is
/// classified RETRYABLE by the driver, so the seam cannot smuggle a terminal / serve signal through a
/// host-chosen discriminant. The `&'static str` is log-only (boot triage), not a control value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnchorTransportError(pub &'static str);

/// Defensive upper bound on `max_attempts`, independent of the caller. The recommended operating value
/// is a small bin-side const (≈5); this ceiling exists only so a buggy or hostile caller cannot request
/// a pathological count (e.g. `u32::MAX`) that would turn the bounded loop into a soft boot-DoS (each
/// attempt is a full CSPRNG draw + SNP quote + vsock relay). A request above it is a config error
/// (`Unstartable`), NOT silently clamped — silent clamping would hide the caller bug. This makes the
/// "structurally bounded, infinite-loop impossible" property self-contained in this module rather than
/// dependent on a well-behaved caller.
pub(crate) const MAX_BOOT_ATTEMPTS_CEILING: u32 = 64;

/// The result of the bounded boot handshake, for the boot caller (5b-2 bin) to feed to the serve-gate.
/// `#[must_use]`: a `Ready` that is dropped would silently skip the serve decision.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootDriverOutcome {
    /// A `Fresh` reconcile occurred AND `boot_reconcile_anti_rollback` installed the runtime binding.
    /// Carries the verified [`AnchorState`](crate::agent_anchor::AnchorState). The ONLY arm that may
    /// lead to serving (after the serve-gate also passes).
    Ready(crate::agent_anchor::AnchorState),
    /// Terminal fail-closed; the caller MUST NOT serve. Carries the cause for the boot log / triage.
    FailClosed(BootDriverFail),
}

/// Why the boot handshake failed closed (terminal). Distinct causes for the boot log / operator triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootDriverFail {
    /// A terminal reconcile verdict from [`crate::agent_boot::boot_reconcile_anti_rollback`]
    /// (host-reachable verify verdict, operator condition, or internal defect — all terminal here).
    Reconcile(crate::agent_boot::BootFailReason),
    /// `AdoptForward` was required but is NOT executable in slice 5b-1 (no `anchor_root`-signed
    /// raw-marks channel yet). §8 fail-closed; carries the [`AnchorState`](crate::agent_anchor::AnchorState)
    /// for the operator log. Returned immediately (never retried).
    AdoptForwardUnsupported(crate::agent_anchor::AnchorState),
    /// `max_attempts` transport (retryable) failures in a row — the bound was hit. Carries the last
    /// transport cause string.
    RetriesExhausted(&'static str),
    /// The ceremony could not run at all: `max_attempts == 0`, or `issue_challenge` failed (CSPRNG
    /// unavailable — every attempt would fail identically).
    Unstartable(&'static str),
}

/// Run the bounded boot anti-rollback handshake against an already-unsealed keystore `body`.
///
/// Loops up to `max_attempts` times: issue a fresh challenge (scope from `body.config`), perform the
/// one platform [`AnchorBootTransport::anchor_round_trip`], and verify+reconcile via
/// [`crate::agent_boot::boot_reconcile_anti_rollback`]. Only transport errors are retried; every
/// reconcile verdict and `AdoptForward` are terminal (see the module-level anti-grind note). Returns a
/// [`BootDriverOutcome`] for the boot caller to feed to [`agent_anti_rollback_serve_gate`].
///
/// The driver installs nothing (reconcile installs the binding on its `Fresh` arm) and does not serve.
pub(crate) fn run_boot_anti_rollback_handshake(
    transport: &mut impl AnchorBootTransport,
    body: &crate::agent_keystore::KeystoreBody,
    max_attempts: u32,
) -> BootDriverOutcome {
    // Distinct messages per cause for operator triage (a misconfigured bound is not a runtime fault).
    if max_attempts == 0 {
        return BootDriverOutcome::FailClosed(BootDriverFail::Unstartable("max_attempts must be >= 1"));
    }
    if max_attempts > MAX_BOOT_ATTEMPTS_CEILING {
        // A pathological count is a caller config error (soft boot-DoS) — reject, don't clamp.
        return BootDriverOutcome::FailClosed(BootDriverFail::Unstartable(
            "max_attempts exceeds MAX_BOOT_ATTEMPTS_CEILING",
        ));
    }
    let chain = body.config.twod_chain_id;
    let env = body.config.environment_identifier.as_str();
    let mut last_transport: &'static str = "no attempt completed";

    for _attempt in 1..=max_attempts {
        // Fresh challenge per attempt: fresh CSPRNG nonce -> fresh report_data -> fresh quote. Scope is
        // the SEALED config, never a host override.
        let challenge = match crate::agent_challenge::issue_challenge(chain, env) {
            Ok(c) => c,
            // CSPRNG dead: every attempt would fail identically -> terminal, do not loop.
            Err(_) => {
                return BootDriverOutcome::FailClosed(BootDriverFail::Unstartable(
                    "CSPRNG unavailable to draw the freshness nonce",
                ));
            }
        };
        // The public per-attempt challenge for the transport: scope from the SEALED config, the fresh
        // nonce, and the report_data commitment. All public (they transit the host to the anchor).
        let request = AnchorBootRequest {
            chain_id: chain,
            environment_identifier: env,
            nonce: *challenge.nonce(),
            report_data: challenge.report_data(),
        };

        // One platform round-trip: quote(report_data) + public challenge -> host -> anchor -> signed bytes.
        let response = match transport.anchor_round_trip(&request) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Retire the un-answered challenge before re-issuing, so the slot is honest on exit
                // (boot_reconcile only consumes when it actually runs). The next iteration reissues.
                let _ = crate::agent_challenge::consume_outstanding_challenge();
                last_transport = e.0;
                continue;
            }
        };

        // Verify + reconcile. This take()s the challenge BEFORE verifying (so it is consumed on EVERY
        // outcome here) and installs the binding ONLY on its Fresh arm — the driver installs nothing.
        match crate::agent_boot::boot_reconcile_anti_rollback(&response, body) {
            crate::agent_boot::BootAntiRollbackOutcome::Ready(state) => {
                return BootDriverOutcome::Ready(state);
            }
            // §8: no anchor_root-signed raw-marks channel exists yet, so adopting forward would risk
            // seeding forged marks. Fail closed (terminal), returned immediately — never retried (a
            // continuously-advancing anchor must not spin the loop to exhaustion).
            crate::agent_boot::BootAntiRollbackOutcome::AdoptForwardRequired(state) => {
                return BootDriverOutcome::FailClosed(BootDriverFail::AdoptForwardUnsupported(state));
            }
            // Every reconcile fail reason is TERMINAL: host-reachable verify verdicts are NOT retried
            // (anti-grind), and operator/internal reasons are deterministic given this body.
            crate::agent_boot::BootAntiRollbackOutcome::FailClosed(reason) => {
                return BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(reason));
            }
        }
    }

    // Bound exhausted: only transport flaps reach here (every reconcile outcome returns above).
    BootDriverOutcome::FailClosed(BootDriverFail::RetriesExhausted(last_transport))
}

/// Pure boot-time fail-closed decision for whether the agent gateway may serve rollback-sensitive
/// frames. Follows the same fail-closed SHAPE as [`crate::snp_attestation_boot_gate`], but — unlike the
/// SNP gate (which has a "release + no operational signer ⇒ ok" transport-only allowance) — there is NO
/// production allowance: in release, anti-rollback is mandatory. Production (`require_real`, i.e. release
/// builds) refuses unless the runtime Layer-2b binding is installed (which `boot_reconcile_anti_rollback`
/// does ONLY on a verified `Fresh` reconcile). Dev/lab (debug, `require_real == false`) may continue with
/// the binding absent — fund custody stays independently blocked by the runtime binding check, so this
/// gate's dev allowance cannot move funds.
///
/// This gate is the SECOND, independent layer; the boot caller (5b-2) MUST also branch on the driver
/// outcome FIRST — only [`BootDriverOutcome::Ready`] proceeds to this gate; every `FailClosed` aborts
/// before it (so a `BindingInstall` double-run, which can leave a prior valid binding configured, cannot
/// reach a serve). Taking the INSTALLED-BINDING flag ([`crate::agent_dispatch::is_anti_rollback_configured`])
/// rather than the driver's outcome is the defense-in-depth: even a driver bug that wrongly returned
/// `Ready` cannot open the gate. The `Result` is already `#[must_use]`, so a dropped gate decision warns.
pub(crate) fn agent_anti_rollback_serve_gate(
    require_real: bool,
    anti_rollback_configured: bool,
) -> Result<(), crate::ProtocolError> {
    if require_real && !anti_rollback_configured {
        return Err(crate::ProtocolError::PqSigningUnavailable(
            "agent gateway anti-rollback binding not installed \
             (production refuses to serve rollback-sensitive frames)",
        ));
    }
    Ok(())
}

/// Fuse the driver outcome with the serve-gate into ONE fail-closed serve decision, so the boot
/// caller (5b-2) cannot get the ordering wrong. **This is the function 5b-2's bin calls** (not the gate
/// directly) once the handshake returns:
/// ```ignore
/// let state = decide_serve(outcome, cfg!(release_build))?; // Ok ⇒ serve; Err ⇒ abort (do NOT serve)
/// ```
/// It encodes the load-bearing ordering structurally: **every `FailClosed` is rejected unconditionally**
/// (in all builds — including `BindingInstall`, which can leave a *prior* valid binding configured so the
/// gate alone would wrongly pass), and ONLY `Ready` proceeds to the second, independent
/// [`agent_anti_rollback_serve_gate`] check (which reads the installed-binding flag, not this outcome, so
/// even a driver bug returning `Ready` without an installed binding fails closed in production). The
/// unsafe "handshake → gate → serve without an outcome branch" wiring is therefore unrepresentable.
/// Returns the verified [`AnchorState`](crate::agent_anchor::AnchorState) on success (for the boot log /
/// audit). (The standalone [`agent_anti_rollback_serve_gate`] remains for the deployment that never runs
/// the handshake at all — anti-rollback not wired — where there is no `BootDriverOutcome` to branch on.)
pub(crate) fn decide_serve(
    outcome: BootDriverOutcome,
    require_real: bool,
) -> Result<crate::agent_anchor::AnchorState, crate::ProtocolError> {
    match outcome {
        BootDriverOutcome::Ready(state) => {
            agent_anti_rollback_serve_gate(
                require_real,
                crate::agent_dispatch::is_anti_rollback_configured(),
            )?;
            Ok(state)
        }
        BootDriverOutcome::FailClosed(_) => Err(crate::ProtocolError::PqSigningUnavailable(
            "agent gateway boot anti-rollback handshake did not reach Ready (refusing to serve)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_anchor::{anchor_handshake_report_data, test_signed_response_bytes};
    use crate::agent_boot::BootFailReason;
    use crate::agent_challenge::has_outstanding_challenge;
    use crate::agent_dispatch::{
        install_anti_rollback_binding, is_anti_rollback_configured, AntiRollbackBinding,
    };
    use crate::agent_keystore::{AuditRing, FaucetState, KeystoreBody, KeystoreConfig};
    use ed25519_dalek::SigningKey;
    use std::collections::VecDeque;

    const ENV: &str = "testnet";
    const CHAIN: u64 = 11565;

    /// Serialize every test: the driver drives the `OUTSTANDING_CHALLENGE` + `ANTI_ROLLBACK_BINDING`
    /// process-globals — the same set 5a/agent_challenge serialize on. Delegates to the crate-wide
    /// helper (which resets the full global set on entry).
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::agent_dispatch::lock_and_reset_agent_process_globals()
    }

    /// The anchor's signing key; its verifying key is the body's sealed `anchor_root`.
    fn anchor_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    /// A `KeystoreBody` mirroring `agent_boot::test_body`, with `anchor_root` = the test anchor key and
    /// tunable local `(freshness_epoch, structural_version)`.
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

    /// One scripted per-attempt mock behaviour. `Sign*` variants peek the live issued nonce so the
    /// response echoes the actual fresh draw (a precomputed nonce can't match a CSPRNG draw).
    #[derive(Clone)]
    enum MockAction {
        /// Transient transport failure -> retryable.
        Transport,
        /// Correct anchor key + correct scope + echoed live nonce, signed for `(epoch, sv, marks)`.
        Sign { epoch: u64, sv: u64, marks: [u8; 32] },
        /// Wrong signing key -> SignatureInvalid.
        SignWrongKey { epoch: u64, sv: u64, marks: [u8; 32] },
        /// Correct key/scope but a different echoed nonce -> NonceMismatch.
        SignWrongNonce { epoch: u64, sv: u64, marks: [u8; 32] },
        /// Correct key but a different chain scope -> ScopeMismatch (signature still valid).
        SignWrongScope { epoch: u64, sv: u64, marks: [u8; 32] },
        /// Non-CBOR bytes -> Malformed.
        Garbage,
    }

    /// Mock [`AnchorBootTransport`] driven by a scripted action queue; records every `report_data` it
    /// is handed and the live nonce at that moment (always peeked, even on transport errors), so the
    /// tests can assert fresh-per-attempt + report_data↔nonce binding.
    struct TestTransport {
        actions: VecDeque<MockAction>,
        attempts: u32,
        seen_report_data: Vec<[u8; 64]>,
        seen_nonce: Vec<[u8; 32]>,
    }

    impl TestTransport {
        fn new(actions: Vec<MockAction>) -> Self {
            Self {
                actions: actions.into(),
                attempts: 0,
                seen_report_data: Vec::new(),
                seen_nonce: Vec::new(),
            }
        }
    }

    impl AnchorBootTransport for TestTransport {
        fn anchor_round_trip(
            &mut self,
            request: &AnchorBootRequest,
        ) -> Result<Vec<u8>, AnchorTransportError> {
            self.attempts += 1;
            self.seen_report_data.push(request.report_data);
            // The request carries the fresh issued nonce directly (it's public) — the mock signs against
            // THIS draw, no peek needed. Sanity-check the driver bound report_data to (scope, nonce).
            assert_eq!(
                request.report_data,
                anchor_handshake_report_data(request.chain_id, request.environment_identifier, &request.nonce),
                "driver must hand the transport a report_data that commits to the request's scope+nonce"
            );
            let nonce = request.nonce;
            self.seen_nonce.push(nonce);
            // If the driver attempts MORE round-trips than scripted, return a transport error instead
            // of panicking on an empty queue. A wrongful retry (e.g. a regression that retries a
            // terminal verdict, or an off-by-one in the bound) then surfaces as a clean
            // attempt-count / outcome assertion failure pointing at the driver — not a confusing mock
            // panic that hides the root cause.
            let action = match self.actions.pop_front() {
                Some(a) => a,
                None => return Err(AnchorTransportError("mock: driver over-attempted (no scripted action)")),
            };
            let r = match action {
                MockAction::Transport => return Err(AnchorTransportError("mock transport")),
                MockAction::Sign { epoch, sv, marks } => {
                    test_signed_response_bytes(&anchor_key(), CHAIN, ENV, epoch, sv, marks, nonce)
                }
                MockAction::SignWrongKey { epoch, sv, marks } => test_signed_response_bytes(
                    &SigningKey::from_bytes(&[9u8; 32]),
                    CHAIN,
                    ENV,
                    epoch,
                    sv,
                    marks,
                    nonce,
                ),
                MockAction::SignWrongNonce { epoch, sv, marks } => {
                    let mut wrong = nonce;
                    wrong[0] ^= 0xff; // guaranteed != the issued nonce
                    test_signed_response_bytes(&anchor_key(), CHAIN, ENV, epoch, sv, marks, wrong)
                }
                MockAction::SignWrongScope { epoch, sv, marks } => test_signed_response_bytes(
                    &anchor_key(),
                    CHAIN + 1, // wrong chain scope; signature valid over the wrong-scope preimage
                    ENV,
                    epoch,
                    sv,
                    marks,
                    nonce,
                ),
                MockAction::Garbage => vec![0xff, 0xff, 0xff],
            };
            Ok(r)
        }
    }

    /// A `Sign` action that reconciles `Fresh` against `body` (epoch + structural + marks all match).
    fn fresh(body: &KeystoreBody) -> MockAction {
        MockAction::Sign {
            epoch: body.freshness_epoch,
            sv: body.structural_version,
            marks: body.compute_local_marks_digest(),
        }
    }

    // ---- happy path + install provenance ----

    #[test]
    fn ready_first_attempt_installs_and_consumes() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let mut t = TestTransport::new(vec![fresh(&body)]);
        match run_boot_anti_rollback_handshake(&mut t, &body, 5) {
            BootDriverOutcome::Ready(st) => {
                assert_eq!(st.epoch, 7);
                assert_eq!(st.structural_version, 2);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
        assert_eq!(t.attempts, 1, "Fresh on the first attempt");
        // boot_reconcile's Fresh arm installed the binding (the driver has no install literal).
        assert!(is_anti_rollback_configured(), "binding installed via boot_reconcile Fresh arm");
        // boot_reconcile consumed the challenge (take-before-verify).
        assert!(!has_outstanding_challenge(), "challenge consumed on the Ready path");
    }

    // ---- AdoptForward + the no-install sweep ----

    #[test]
    fn adopt_forward_fail_closed_no_retry() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // Anchor epoch ahead, same structural ⇒ AdoptForward; 5b-1 returns it terminal, no retry.
        let mut t = TestTransport::new(vec![MockAction::Sign { epoch: 6, sv: 2, marks: [0x00; 32] }]);
        match run_boot_anti_rollback_handshake(&mut t, &body, 5) {
            BootDriverOutcome::FailClosed(BootDriverFail::AdoptForwardUnsupported(st)) => {
                assert_eq!(st.epoch, 6);
            }
            other => panic!("expected AdoptForwardUnsupported, got {other:?}"),
        }
        assert_eq!(t.attempts, 1, "AdoptForward is terminal, not retried");
        assert!(!is_anti_rollback_configured(), "AdoptForward installs nothing");
    }

    #[test]
    fn driver_never_installs_on_any_failclosed() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // Each scenario, run under the same lock, must leave the binding slot empty throughout.
        let scenarios: Vec<MockAction> = vec![
            MockAction::Sign { epoch: 6, sv: 2, marks: [0x00; 32] }, // AdoptForward
            MockAction::Sign { epoch: 4, sv: 2, marks: [0x00; 32] }, // AnchorBehind
            MockAction::Sign { epoch: 7, sv: 3, marks: [0x00; 32] }, // StructuralGap
            MockAction::Sign { epoch: 5, sv: 2, marks: [0x00; 32] }, // Inconsistent (marks differ)
            MockAction::SignWrongKey { epoch: 5, sv: 2, marks: [0x00; 32] }, // SignatureInvalid
            MockAction::SignWrongNonce { epoch: 5, sv: 2, marks: [0x00; 32] }, // NonceMismatch
            MockAction::SignWrongScope { epoch: 5, sv: 2, marks: [0x00; 32] }, // ScopeMismatch
            MockAction::Garbage,                                     // Malformed
            MockAction::Transport,                                   // RetriesExhausted (1 attempt)
        ];
        for action in scenarios {
            let mut t = TestTransport::new(vec![action]);
            let outcome = run_boot_anti_rollback_handshake(&mut t, &body, 1);
            assert!(
                matches!(outcome, BootDriverOutcome::FailClosed(_)),
                "expected FailClosed, got {outcome:?}"
            );
            assert!(!is_anti_rollback_configured(), "no FailClosed path installs the binding");
        }
    }

    // ---- transport retry + bound ----

    #[test]
    fn transport_retry_to_success() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let mut t = TestTransport::new(vec![MockAction::Transport, fresh(&body)]);
        assert!(matches!(
            run_boot_anti_rollback_handshake(&mut t, &body, 5),
            BootDriverOutcome::Ready(_)
        ));
        assert_eq!(t.attempts, 2, "one transport flap then success");
        assert_ne!(t.seen_nonce[0], t.seen_nonce[1], "a fresh nonce per attempt");
        assert!(is_anti_rollback_configured());
    }

    #[test]
    fn transport_exhaustion_fails_closed() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let mut t = TestTransport::new(vec![
            MockAction::Transport,
            MockAction::Transport,
            MockAction::Transport,
        ]);
        match run_boot_anti_rollback_handshake(&mut t, &body, 3) {
            BootDriverOutcome::FailClosed(BootDriverFail::RetriesExhausted(_)) => {}
            other => panic!("expected RetriesExhausted, got {other:?}"),
        }
        assert_eq!(t.attempts, 3, "exactly max_attempts transport attempts");
        // distinct nonces each attempt
        assert_ne!(t.seen_nonce[0], t.seen_nonce[1]);
        assert_ne!(t.seen_nonce[1], t.seen_nonce[2]);
        assert!(!has_outstanding_challenge(), "transport-error path retires the challenge");
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn bounded_never_infinite() {
        let _g = test_lock();
        let body = test_body(7, 2);
        for n in [1u32, 2, 5] {
            let actions: Vec<MockAction> = (0..n).map(|_| MockAction::Transport).collect();
            let mut t = TestTransport::new(actions);
            let outcome = run_boot_anti_rollback_handshake(&mut t, &body, n);
            assert!(matches!(
                outcome,
                BootDriverOutcome::FailClosed(BootDriverFail::RetriesExhausted(_))
            ));
            assert_eq!(t.attempts, n, "loop runs exactly max_attempts ({n}) times — no loop{{}}");
        }
    }

    #[test]
    fn advancing_anchor_terminates_immediately() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // A continuously-advancing anchor (always an AdoptForward) must NOT spin the loop: the first
        // AdoptForward is terminal.
        let mut t = TestTransport::new(vec![
            MockAction::Sign { epoch: 6, sv: 2, marks: [0x00; 32] },
            MockAction::Sign { epoch: 7, sv: 2, marks: [0x00; 32] },
            MockAction::Sign { epoch: 8, sv: 2, marks: [0x00; 32] },
        ]);
        assert!(matches!(
            run_boot_anti_rollback_handshake(&mut t, &body, 5),
            BootDriverOutcome::FailClosed(BootDriverFail::AdoptForwardUnsupported(_))
        ));
        assert_eq!(t.attempts, 1, "advancing anchor is fail-closed at attempt 1, not looped");
    }

    #[test]
    fn max_attempts_zero_unstartable() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let mut t = TestTransport::new(vec![]);
        match run_boot_anti_rollback_handshake(&mut t, &body, 0) {
            BootDriverOutcome::FailClosed(BootDriverFail::Unstartable(_)) => {}
            other => panic!("expected Unstartable, got {other:?}"),
        }
        assert_eq!(t.attempts, 0, "transport never called when unstartable");
        assert!(!is_anti_rollback_configured());
    }

    #[test]
    fn max_attempts_above_ceiling_unstartable() {
        let _g = test_lock();
        let body = test_body(7, 2);
        // A pathological count is a caller config error -> Unstartable BEFORE any challenge/transport,
        // so the loop bound is self-contained (not dependent on a well-behaved caller).
        let mut t = TestTransport::new(vec![]);
        match run_boot_anti_rollback_handshake(&mut t, &body, MAX_BOOT_ATTEMPTS_CEILING + 1) {
            BootDriverOutcome::FailClosed(BootDriverFail::Unstartable(_)) => {}
            other => panic!("expected Unstartable above the ceiling, got {other:?}"),
        }
        assert_eq!(t.attempts, 0, "transport never called above the attempts ceiling");
        assert!(!is_anti_rollback_configured());
        // The ceiling itself is still a valid (if large) bound: at the ceiling, a fresh-on-attempt-1
        // mock still succeeds (proves the boundary is inclusive, not off-by-one).
        let mut t2 = TestTransport::new(vec![fresh(&body)]);
        assert!(matches!(
            run_boot_anti_rollback_handshake(&mut t2, &body, MAX_BOOT_ATTEMPTS_CEILING),
            BootDriverOutcome::Ready(_)
        ));
        assert_eq!(t2.attempts, 1);
    }

    // ---- freshness + scope binding ----

    #[test]
    fn challenge_fresh_each_attempt_and_no_leak() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let mut t = TestTransport::new(vec![
            MockAction::Transport,
            MockAction::Transport,
            fresh(&body),
        ]);
        assert!(matches!(
            run_boot_anti_rollback_handshake(&mut t, &body, 5),
            BootDriverOutcome::Ready(_)
        ));
        // every report_data the seam saw is distinct (fresh nonce -> fresh report_data)
        let mut seen = t.seen_report_data.clone();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), t.seen_report_data.len(), "report_data distinct per attempt");
        assert!(!has_outstanding_challenge(), "no leaked challenge after the run");
    }

    #[test]
    fn report_data_binds_issued_nonce_and_body_scope() {
        let _g = test_lock();
        let body = test_body(7, 2);
        // Two transport flaps then success — three attempts to check.
        let mut t = TestTransport::new(vec![
            MockAction::Transport,
            MockAction::Transport,
            fresh(&body),
        ]);
        let _ = run_boot_anti_rollback_handshake(&mut t, &body, 5);
        assert_eq!(t.seen_report_data.len(), 3);
        for (rd, nonce) in t.seen_report_data.iter().zip(t.seen_nonce.iter()) {
            assert_eq!(
                *rd,
                anchor_handshake_report_data(CHAIN, ENV, nonce),
                "report_data commits to the issued nonce AND body.config scope"
            );
        }
    }

    #[test]
    fn scope_sourced_from_body_not_host() {
        let _g = test_lock();
        let body = test_body(7, 2);
        // A response signed for a DIFFERENT chain scope ⇒ ScopeMismatch (proves the driver issues +
        // verifies against body.config scope, not a host-chosen one).
        let mut t = TestTransport::new(vec![MockAction::SignWrongScope { epoch: 7, sv: 2, marks: [0u8; 32] }]);
        match run_boot_anti_rollback_handshake(&mut t, &body, 5) {
            BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(BootFailReason::VerifyScopeMismatch)) => {}
            other => panic!("expected VerifyScopeMismatch, got {other:?}"),
        }
        assert_eq!(t.attempts, 1, "scope mismatch is terminal");
    }

    // ---- terminal reconcile verdicts: each must be 1 attempt (anti-grind) ----

    fn assert_terminal_one_attempt(action: MockAction, body: &KeystoreBody, want: BootFailReason) {
        let mut t = TestTransport::new(vec![action]);
        match run_boot_anti_rollback_handshake(&mut t, body, 5) {
            BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(got)) => assert_eq!(got, want),
            other => panic!("expected Reconcile({want:?}), got {other:?}"),
        }
        assert_eq!(t.attempts, 1, "{want:?} is terminal — exactly one attempt, no grind retry");
    }

    #[test]
    fn terminal_signature_invalid_no_retry() {
        let _g = test_lock();
        let body = test_body(7, 2);
        assert_terminal_one_attempt(
            MockAction::SignWrongKey { epoch: 7, sv: 2, marks: body.compute_local_marks_digest() },
            &body,
            BootFailReason::VerifySignatureInvalid,
        );
    }

    #[test]
    fn terminal_nonce_mismatch_no_retry() {
        let _g = test_lock();
        let body = test_body(7, 2);
        assert_terminal_one_attempt(
            MockAction::SignWrongNonce { epoch: 7, sv: 2, marks: body.compute_local_marks_digest() },
            &body,
            BootFailReason::VerifyNonceMismatch,
        );
    }

    #[test]
    fn terminal_malformed_no_retry() {
        let _g = test_lock();
        let body = test_body(7, 2);
        assert_terminal_one_attempt(MockAction::Garbage, &body, BootFailReason::VerifyMalformed);
    }

    #[test]
    fn terminal_anchor_behind_no_retry() {
        let _g = test_lock();
        let body = test_body(5, 2);
        assert_terminal_one_attempt(
            MockAction::Sign { epoch: 4, sv: 2, marks: body.compute_local_marks_digest() },
            &body,
            BootFailReason::AnchorBehind,
        );
    }

    #[test]
    fn terminal_structural_gap_no_retry() {
        let _g = test_lock();
        let body = test_body(5, 2);
        assert_terminal_one_attempt(
            MockAction::Sign { epoch: 7, sv: 3, marks: [0x00; 32] },
            &body,
            BootFailReason::StructuralGap,
        );
    }

    #[test]
    fn terminal_inconsistent_no_retry() {
        let _g = test_lock();
        let body = test_body(5, 2);
        // same epoch + structural, marks differ from local ⇒ Inconsistent.
        assert_ne!(body.compute_local_marks_digest(), [0x00; 32]);
        assert_terminal_one_attempt(
            MockAction::Sign { epoch: 5, sv: 2, marks: [0x00; 32] },
            &body,
            BootFailReason::Inconsistent,
        );
    }

    #[test]
    fn terminal_binding_install_no_retry() {
        let _g = test_lock();
        let body = test_body(7, 2);
        // Pre-install a binding (sequencing-bug sim): a Fresh reconcile then hits install-once -> false
        // -> BindingInstall. Terminal, one attempt.
        assert!(install_anti_rollback_binding(AntiRollbackBinding { epoch: 1, active: true }));
        let mut t = TestTransport::new(vec![fresh(&body)]);
        match run_boot_anti_rollback_handshake(&mut t, &body, 5) {
            BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(BootFailReason::BindingInstall)) => {}
            other => panic!("expected BindingInstall, got {other:?}"),
        }
        assert_eq!(t.attempts, 1, "BindingInstall is terminal");
    }

    #[test]
    fn transport_error_single_attempt_retires_challenge() {
        let _g = test_lock();
        let body = test_body(7, 2);
        let mut t = TestTransport::new(vec![MockAction::Transport]);
        assert!(matches!(
            run_boot_anti_rollback_handshake(&mut t, &body, 1),
            BootDriverOutcome::FailClosed(BootDriverFail::RetriesExhausted(_))
        ));
        assert!(!has_outstanding_challenge(), "transport-error branch retires the challenge on exit");
    }

    // ---- pure serve-gate ----

    #[test]
    fn serve_gate_decision_table() {
        // (require_real, configured) -> serve/refuse
        assert!(agent_anti_rollback_serve_gate(true, true).is_ok(), "prod + configured => serve");
        assert!(
            agent_anti_rollback_serve_gate(true, false).is_err(),
            "prod + unconfigured => REFUSE (the only fail-closed cell)"
        );
        assert!(agent_anti_rollback_serve_gate(false, false).is_ok(), "dev + unconfigured => serve degraded");
        assert!(agent_anti_rollback_serve_gate(false, true).is_ok(), "dev + configured => serve");
    }

    #[test]
    fn serve_gate_refusal_is_pq_signing_unavailable() {
        match agent_anti_rollback_serve_gate(true, false) {
            Err(crate::ProtocolError::PqSigningUnavailable(_)) => {}
            other => panic!("expected PqSigningUnavailable, got {other:?}"),
        }
    }

    // ---- fused serve decision (decide_serve) ----

    fn an_state(epoch: u64) -> crate::agent_anchor::AnchorState {
        crate::agent_anchor::AnchorState {
            epoch,
            structural_version: 2,
            marks_digest: [0u8; 32],
            chain_height: None,
            chain_block_hash: None,
        }
    }

    #[test]
    fn decide_serve_ready_configured_serves() {
        let _g = test_lock();
        // Ready + an installed binding ⇒ serve (gate passes), returns the state.
        assert!(install_anti_rollback_binding(AntiRollbackBinding { epoch: 7, active: true }));
        let st = decide_serve(BootDriverOutcome::Ready(an_state(7)), true).expect("Ready+configured serves");
        assert_eq!(st.epoch, 7);
    }

    #[test]
    fn decide_serve_ready_unconfigured_prod_refuses_dev_serves() {
        let _g = test_lock();
        // Ready but NO installed binding (a driver-bug shape): prod refuses via the gate, dev serves
        // degraded (runtime binding still blocks funds). Proves the gate reads the flag, not the outcome.
        assert!(!is_anti_rollback_configured());
        assert!(decide_serve(BootDriverOutcome::Ready(an_state(7)), true).is_err(), "prod refuses");
        assert!(decide_serve(BootDriverOutcome::Ready(an_state(7)), false).is_ok(), "dev serves degraded");
    }

    #[test]
    fn decide_serve_failclosed_always_aborts() {
        let _g = test_lock();
        // EVERY FailClosed aborts in BOTH builds — never reaches a serve.
        let fails = [
            BootDriverFail::Reconcile(BootFailReason::AnchorBehind),
            BootDriverFail::Reconcile(BootFailReason::VerifySignatureInvalid),
            BootDriverFail::AdoptForwardUnsupported(an_state(9)),
            BootDriverFail::RetriesExhausted("flap"),
            BootDriverFail::Unstartable("zero"),
        ];
        for f in fails {
            assert!(decide_serve(BootDriverOutcome::FailClosed(f), true).is_err(), "{f:?} aborts in prod");
            assert!(decide_serve(BootDriverOutcome::FailClosed(f), false).is_err(), "{f:?} aborts in dev");
        }
    }

    #[test]
    fn decide_serve_binding_install_with_prior_binding_still_aborts() {
        let _g = test_lock();
        // The exact codex case: a prior valid Fresh install left the binding configured, then a second
        // ceremony returned FailClosed(BindingInstall). is_anti_rollback_configured() is TRUE, so the
        // gate ALONE would pass — but decide_serve branches on the outcome FIRST and aborts.
        assert!(install_anti_rollback_binding(AntiRollbackBinding { epoch: 1, active: true }));
        assert!(is_anti_rollback_configured(), "prior binding configured");
        let outcome = BootDriverOutcome::FailClosed(BootDriverFail::Reconcile(BootFailReason::BindingInstall));
        assert!(decide_serve(outcome, true).is_err(), "BindingInstall must abort despite a configured binding");
        assert!(decide_serve(outcome, false).is_err(), "...in dev too");
    }
}
