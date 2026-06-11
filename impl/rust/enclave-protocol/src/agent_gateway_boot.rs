//! Agent Gateway (4b) boot WIRING (TASK-7.7 5b-2b-ii (d-ii)/4b): the live composition of the
//! TWO-artifact serve gate into the boot path — `ValidatedBootBudget::validate` (gate #2) → the shared
//! producer+transport mint `transport_with_spawn` (gate #1: the CONCRETE `HardBoundedQuoteProducer`,
//! claim + witness by signature) → `run_boot_anti_rollback_handshake` with the count derived in-body
//! from the SAME witness → `decide_serve` — plus the typed boot-event seam
//! ([`AgentBootEvent`]/[`BootLogLevel`]) that discharges the §8 two-phase config-logging obligation in
//! the LIBRARY (content + severity; the 5b-2c bin only forwards Display lines to stderr→journald,
//! mapping [`AgentBootEvent::level`] to priority).
//!
//! (4b) ships the COMPOSITION, not a serving loop: nothing here is `pub`, there is no listener and no
//! bin, and live serve remains gated on the TWO-artifact gate — the (4c) in-guest aya smoke + 5b-2c
//! witness-construction-from-operator-config (§8). The module is consumer-free until the 5b-2c bin's
//! `pub` wrapper (`run_agent_gateway_boot`, §8) wraps [`run_boot_handshake_wired`] — the exact
//! precedent of `production_transport`/`production()` when (d-ii)/2+3 landed — hence the module-wide
//! allow below.
//!
//! Discharged HERE (the two §8 5b-2c preconditions named at (d-ii)/3): the DRIVER-COUNT BINDING (by
//! construction — no count parameter exists anywhere on this surface; `budget.max_attempts()` is
//! derived in-body from the same witness that minted the transport; test-backed by
//! `wired_driver_count_is_the_same_witness_max_attempts`) and the TWO-PHASE LOGGING content+severity
//! (raw triplet BEFORE validate, getters incl. slack after, zero-slack ⇒ Warn — library logic, each
//! half test-pinned). Never-generic-Q containment is structural: the generic composition body is
//! module-PRIVATE and the only crate-visible wired door is the concrete [`run_boot_handshake_wired`];
//! `<Q: BootQuoteProducer>` appears nowhere (§8).
//!
//! Cfg gate: this module names `ValidatedBootBudget` + `HardBoundedQuoteProducer` (triple-gated) — the
//! cfg intersection of its dependencies, never wider (the §8 hard rule); it CANNOT be
//! agent-gateway-only. CI covers it devicelessly: the Linux
//! `cargo test --features vsock-transport,agent-gateway` lane. Cross-file references in this file are
//! plain backticks (house rule: everything referenced is same-gate or wider, so a link could never
//! dangle here — the uniform rule keeps the next editor from copying a link into a wider-gated file).
#![cfg_attr(not(test), allow(dead_code))]

use crate::ProtocolError;
use std::time::Duration;

/// Severity for the 5b-2c bin's stderr→journald forwarding. The classification is LIBRARY logic
/// (testable here); the bin only maps it to journald priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootLogLevel {
    Info,
    Warn,
}

/// Structured boot-wiring events. The library NEVER writes to any fd (no stdout/stderr pollution by
/// construction — libtest hygiene, and the 5b-2c parent's stderr is the journald triage channel the
/// BIN owns; the wiring runs in the PARENT pre-spawn, where stdout is not protocol, but the bin
/// obligation is stderr-only). The bin forwards Display lines, mapping [`Self::level`] to priority.
/// Emission points are strictly OUTSIDE deadline-bounded fetch paths (pre-handshake + one
/// post-handshake line) — a constraint on future variants too (§8 reap-logging hazard: a blocking
/// write inside the fetch path is the wedge class (d) exists to kill). This sink is NOT the
/// reap-status carrier (an explicit 5b-2c design task); it is the carrier's intended EMISSION
/// surface once that carrier (a bounded non-blocking buffer drained between attempts) is designed.
/// 5b-2c promotion note: when this enum goes `pub` for the separate-crate bin, add
/// `#[non_exhaustive]` AT PROMOTION TIME (no effect in-crate today; the bin's match needs a
/// catch-all so a future reap-status variant cannot break the bin build).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentBootEvent {
    /// Phase (a): the RAW operator triplet, emitted BEFORE `ValidatedBootBudget::validate` — on Err
    /// there are no getters and the static error strings deliberately carry no numbers (house
    /// anti-oracle pattern), so this event is the operator's ONLY copy of the numbers in a
    /// fail-closed boot (§8 two-phase item (a)).
    RawBudgetConfig {
        max_attempts: u32,
        per_leg_timeout: Duration,
        overall_boot_budget: Duration,
    },
    /// Phase (b): the getter line incl. `nominal_boot_cost` AND the slack, emitted on Ok. Zero
    /// slack validates (`≤` passes) but is mis-sized by definition — [`Self::level`] says Warn (§8).
    ValidatedBudget {
        max_attempts: u32,
        per_leg_timeout: Duration,
        overall_boot_budget: Duration,
        nominal_boot_cost: Duration,
        slack: Duration,
    },
    /// The driver outcome BEFORE `decide_serve` folds it: `decide_serve` deliberately returns ONE
    /// uniform refusal string for every FailClosed, while the driver doc promises the
    /// `BootDriverFail` cause "for the boot log / triage" — without this event that cause is
    /// structurally unreachable by the operator. `line` is the Debug rendering (NOT a stable
    /// contract — tests pin prefix + substring only, never full content); pre-rendered String so a
    /// later `pub` promotion of this enum cannot drag the pub(crate) driver types with it.
    HandshakeOutcome { ready: bool, line: String },
}

impl AgentBootEvent {
    /// Built from the witness so the numbers are single-sourced from the getters incl. `slack()` —
    /// no second formula site.
    pub(crate) fn validated_from(b: &crate::quote_subprocess::ValidatedBootBudget) -> Self {
        Self::ValidatedBudget {
            max_attempts: b.max_attempts(),
            per_leg_timeout: b.per_leg_timeout(),
            overall_boot_budget: b.overall_boot_budget(),
            nominal_boot_cost: b.nominal_boot_cost(),
            slack: b.slack(),
        }
    }

    /// Library-owned severity: zero-slack ValidatedBudget → Warn (validates but mis-sized by
    /// definition, §8); a non-Ready HandshakeOutcome → Warn; everything else Info.
    pub(crate) fn level(&self) -> BootLogLevel {
        match self {
            Self::ValidatedBudget { slack, .. } if *slack == Duration::ZERO => BootLogLevel::Warn,
            Self::HandshakeOutcome { ready: false, .. } => BootLogLevel::Warn,
            _ => BootLogLevel::Info,
        }
    }
}

/// The operator boot-log lines (forwarded verbatim by the 5b-2c bin; test-pinned). Durations render
/// `{:?}` — NOT `as_millis()`: a sub-ms slack would print `slack_ms=0` WITHOUT the zero-slack WARN,
/// an operator-confusing line, while `{:?}` is lossless. These lines become a de-facto operator
/// interface — journald tooling built later is tracked at the 5b-2c smoke (§8).
impl std::fmt::Display for AgentBootEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawBudgetConfig {
                max_attempts,
                per_leg_timeout,
                overall_boot_budget,
            } => write!(
                f,
                "boot budget config (raw, pre-validate): max_attempts={max_attempts} \
                 per_leg_timeout={per_leg_timeout:?} overall_boot_budget={overall_boot_budget:?}"
            ),
            Self::ValidatedBudget {
                max_attempts,
                per_leg_timeout,
                overall_boot_budget,
                nominal_boot_cost,
                slack,
            } => {
                write!(
                    f,
                    "boot budget validated: max_attempts={max_attempts} \
                     per_leg_timeout={per_leg_timeout:?} \
                     overall_boot_budget={overall_boot_budget:?} \
                     nominal_boot_cost={nominal_boot_cost:?} slack={slack:?}"
                )?;
                if *slack == Duration::ZERO {
                    write!(
                        f,
                        " (ZERO SLACK: nominal boot cost equals overall_boot_budget - mis-sized \
                         by definition)"
                    )?;
                }
                Ok(())
            }
            Self::HandshakeOutcome { line, .. } => write!(f, "boot handshake outcome: {line}"),
        }
    }
}

/// THE shared composition body. MODULE-PRIVATE (the only crate-visible wired door is the concrete
/// [`run_boot_handshake_wired`] — never-generic-Q containment by construction, not by review grep).
/// `S` exists solely so the deviceless tests can drive the SAME body the production wrapper ships
/// (a cfg(test) twin would be a drift surface) — see `transport_with_spawn` for why generic-S is
/// inside the (4a)-closed class, not a reopening.
// 8 args: param order mirrors `ValidatedBootBudget::validate` + the two seams + the sink; a config
// struct is deliberately REJECTED (see the wrapper doc's transposition note) — the allow is cheaper
// than mechanism without a reachable failure.
#[allow(clippy::too_many_arguments)]
fn run_boot_handshake_core<S, C>(
    max_attempts: u32,
    per_leg_timeout: Duration,
    overall_boot_budget: Duration,
    spawn: S,
    channel: C,
    body: &crate::agent_keystore::KeystoreBody,
    require_real: bool,
    emit: &mut dyn FnMut(AgentBootEvent),
) -> Result<crate::agent_anchor::AnchorState, ProtocolError>
where
    S: crate::quote_subprocess::QuoteChildSpawn,
    C: crate::agent_boot_relay::BootRelayChannel,
{
    // TWO-PHASE LOGGING phase (a) (§8 5b-2c precondition (3), library-discharged here): the raw
    // triplet, ALWAYS, BEFORE validate — on Err there are no getters and the static error strings
    // carry no numbers; this event is the operator's only copy in a fail-closed boot.
    emit(AgentBootEvent::RawBudgetConfig {
        max_attempts,
        per_leg_timeout,
        overall_boot_budget,
    });

    // Gate #2: fail-closed; FATAL wiring config — `?`-propagated, NEVER folded into the retryable
    // fetch class (position is the discriminator, §8).
    let budget = crate::quote_subprocess::ValidatedBootBudget::validate(
        max_attempts,
        per_leg_timeout,
        overall_boot_budget,
    )?;

    // Phase (b): getters + slack from THE witness; zero slack ⇒ the event's level() is Warn.
    emit(AgentBootEvent::validated_from(&budget));

    // Gate #1 + gate #2 composition: claim + transport minted from the SAME witness's timeout, one
    // call. Claim refusal is FATAL wiring config (`?`), same position rule as validate above.
    let mut transport = budget.transport_with_spawn(spawn, channel)?;

    // DRIVER-COUNT BINDING (§8, the named TEST-BACKED (4b) item): the count is derived HERE from
    // the SAME `budget` local that minted the transport. This module's surface has NO driver-count
    // parameter anywhere — caller-side drift is unrepresentable; the in-body drift (a literal, a
    // second validate()) is what the named test refuses behaviorally.
    let outcome = crate::agent_boot_driver::run_boot_anti_rollback_handshake(
        &mut transport,
        body,
        budget.max_attempts(),
    );

    // Triage cause BEFORE decide_serve folds every FailClosed to its uniform refusal string —
    // emitted AFTER the driver returns, outside any deadline-bounded fetch path.
    emit(AgentBootEvent::HandshakeOutcome {
        ready: matches!(
            outcome,
            crate::agent_boot_driver::BootDriverOutcome::Ready(_)
        ),
        line: format!("{outcome:?}"),
    });

    crate::agent_boot_driver::decide_serve(outcome, require_real)
}

/// THE (4b) wired boot-handshake entry — the composition the 5b-2c bin's `pub` wrapper
/// (`run_agent_gateway_boot`, §8) forwards to. Producer is the CONCRETE
/// `HardBoundedQuoteProducer<ExecChildSpawn>` BY CONSTRUCTION (never-generic-Q: this fn has no
/// producer/spawn type parameter at all; the core is module-private). `C` stays the seam trait — a
/// real `VsockBootRelayChannel` cannot exist in CI; 5b-2c instantiates
/// `VsockBootRelayChannel::new(vsock_addr::VMADDR_CID_HOST, vsock_addr::anchor_relay_port_from_env()?)`.
/// ONE handshake per process: the producer claim is permanent — a second call refuses fail-closed
/// (test-pinned), which is §8 5b-2c precondition (2) (the bin runs ONE handshake and EXITS for
/// supervisor restart; no in-process retry). Ok(state) ⇒ the caller MAY proceed toward serving —
/// but (4b) ships no serving loop and no pub export; live serve stays gated on (4c) + 5b-2c.
/// Param order mirrors `ValidatedBootBudget::validate` exactly, so its documented transposition
/// analysis (any swapped valid config fails closed) transfers verbatim — why there is no
/// BootConfig struct; 5b-2c owns operator-config parsing. `require_real` stays parametric HERE for
/// both-polarity tests; the 5b-2c PUB wrapper hardcodes `cfg!(release_build)` (§8: no production
/// allowance — an operator override flag must be unrepresentable in the bin).
/// TEST RULE: tests MUST NOT drive this fn past validation/claim — `ExecChildSpawn::production()`
/// re-execs `/proc/self/exe`, which in a test process is the TEST BINARY with no argv filter (a
/// full-suite recursive child). Behavioral tests drive `run_boot_handshake_core` with echo fakes.
pub(crate) fn run_boot_handshake_wired<C: crate::agent_boot_relay::BootRelayChannel>(
    max_attempts: u32,
    per_leg_timeout: Duration,
    overall_boot_budget: Duration,
    channel: C,
    body: &crate::agent_keystore::KeystoreBody,
    require_real: bool,
    emit: &mut dyn FnMut(AgentBootEvent),
) -> Result<crate::agent_anchor::AnchorState, ProtocolError> {
    run_boot_handshake_core(
        max_attempts,
        per_leg_timeout,
        overall_boot_budget,
        crate::quote_subprocess::ExecChildSpawn::production(),
        channel,
        body,
        require_real,
        emit,
    )
}

// TEST RULE (restated from `HardBoundedQuoteProducer::new` — uniform here): EVERY test holds
// `crate::agent_dispatch::lock_and_reset_agent_process_globals()` for its WHOLE body (the reset
// clears claim + binding + challenge + keystore), and tests that re-claim leave the flag pristine
// via `reset_process_quote_ledger_claim_for_tests()` on exit (the claim-test hygiene pattern).
// Local fakes are module-private by house precedent (the agent_boot/driver/relay `test_body`
// triplication); factoring a shared cfg(test) fixture is a recorded separable cleanup. Zero real
// child processes are spawned here — the real-subprocess composition is already pinned by
// `producer_end_to_end_real_subprocess` + `driver_ready_through_real_response_framing`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{AuditRing, FaucetState, KeystoreBody, KeystoreConfig};
    use crate::quote_subprocess::{
        encode_ok_frame, reset_process_quote_ledger_claim_for_tests, ChildHandle,
        HardBoundedQuoteProducer, QuoteChildSpawn, ReapOutcome, ValidatedBootBudget,
        QUOTE_ATTEMPT_OVERHEAD,
    };
    use ed25519_dalek::SigningKey;
    use std::cell::Cell;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    const ENV: &str = "testnet";
    const CHAIN: u64 = 11565;

    /// The anchor's signing key; its verifying key is the body's sealed `anchor_root` (fourth local
    /// copy, mirroring the agent_boot/driver/relay fixtures — see the tests-module header).
    fn anchor_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn test_config() -> KeystoreConfig {
        KeystoreConfig {
            twod_chain_id: CHAIN,
            environment_identifier: ENV.to_string(),
            admin_authority_pk: [0xa1; 32],
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
            monotonic_treasury_config_version: 1,
            authority_epoch: 0,
            anchor_root: anchor_key().verifying_key().to_bytes(),
        }
    }

    fn test_body(freshness_epoch: u64, structural_version: u64) -> KeystoreBody {
        KeystoreBody {
            config: test_config(),
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
            audit: AuditRing {
                records: vec![],
                capacity: 64,
                last_exported_seq: 0,
                next_seq: 1,
            },
            freshness_epoch,
            structural_version,
            strict_recovery_counter: 0,
        }
    }

    /// Test-side nominal product `n·(t + t + ε)` — derived from `QUOTE_ATTEMPT_OVERHEAD`, never a
    /// transcribed ms literal (an ε retune moves expectation and production together). Expected
    /// Display strings below are LITERAL skeletons + `format!("{:?}", derived)` insertions: a wrong
    /// format string in the lib stays visible while the numbers stay const-derived.
    fn nominal_product(n: u32, t: Duration) -> Duration {
        t.checked_add(t)
            .and_then(|legs| legs.checked_add(QUOTE_ATTEMPT_OVERHEAD))
            .and_then(|p| p.checked_mul(n))
            .expect("test arithmetic fits")
    }

    /// Echo-correct spawn fake: builds the frame FROM the handed `report_data` — REQUIRED because
    /// the parent echo-verifies the report's embedded report_data against the driver's per-attempt
    /// RANDOM nonces, so a canned frame cannot pass the echo check. Trivially-reapable handle
    /// (`ReapOutcome::Exited`): no ledger growth, no kill bookkeeping needed here.
    struct EchoChildSpawn {
        spawns: Rc<Cell<u32>>,
    }
    impl EchoChildSpawn {
        fn new() -> Self {
            Self {
                spawns: Rc::new(Cell::new(0)),
            }
        }
    }
    struct EchoHandle;
    impl ChildHandle for EchoHandle {
        fn kill_best_effort(&mut self) {}
        fn try_reap(&mut self) -> ReapOutcome {
            ReapOutcome::Exited
        }
    }
    impl QuoteChildSpawn for EchoChildSpawn {
        type Pipe = UnixStream;
        type Handle = EchoHandle;
        fn spawn(&self, report_data: &[u8; 64]) -> Result<(UnixStream, EchoHandle), ProtocolError> {
            self.spawns.set(self.spawns.get() + 1);
            let mut report = vec![0u8; crate::snp_report::MIN_REPORT_LEN];
            report
                [crate::snp_report::REPORT_DATA_OFFSET..crate::snp_report::REPORT_DATA_OFFSET + 64]
                .copy_from_slice(report_data);
            let frame = encode_ok_frame(&report, &[0x01])?;
            let (reader, mut writer) = UnixStream::pair().expect("socketpair");
            // Small frame fits the default socket buffer — inline write never blocks.
            writer
                .write_all(&frame)
                .expect("test frame fits the socket buffer");
            drop(writer);
            Ok((reader, EchoHandle))
        }
    }

    /// Always-Err channel counting round-trips: with the echo-succeeding spawn it binds the attempt
    /// count through BOTH transport legs (the transport runs producer-then-channel per attempt).
    struct AlwaysErrChannel {
        round_trips: Rc<Cell<u32>>,
    }
    impl crate::agent_boot_relay::BootRelayChannel for AlwaysErrChannel {
        fn round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            self.round_trips.set(self.round_trips.get() + 1);
            Err(crate::agent_boot_driver::AnchorTransportError(
                "wired test channel error",
            ))
        }
    }

    /// Signing channel: decodes the request via `decode_anchor_boot_request` to recover the live
    /// per-attempt nonce, replies with a validly-signed Fresh response (the MockChannel SignFresh
    /// arm pattern from agent_boot_relay's tests).
    struct SigningChannel {
        epoch: u64,
        sv: u64,
        marks: [u8; 32],
        round_trips: Rc<Cell<u32>>,
    }
    impl crate::agent_boot_relay::BootRelayChannel for SigningChannel {
        fn round_trip(
            &mut self,
            request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            self.round_trips.set(self.round_trips.get() + 1);
            let decoded = crate::agent_boot_relay::decode_anchor_boot_request(request_frame)
                .expect("driver-encoded request must decode");
            Ok(crate::agent_anchor::test_signed_response_bytes(
                &anchor_key(),
                CHAIN,
                ENV,
                self.epoch,
                self.sv,
                self.marks,
                decoded.nonce,
            ))
        }
    }

    #[test]
    fn wired_boot_ready_installs_binding_and_serves_with_real_gate() {
        // Regression: the full (4b) composition order — a wiring that skips the driver, drops the
        // outcome, or decides serve off stale globals cannot return Ok under `require_real = true`
        // (install-on-Fresh provenance reaches the wired serve decision). Honesty: quote↔report_data
        // binding is producer/anchor-side coverage, not this test's.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let body = test_body(7, 2);
        let marks = body.compute_local_marks_digest();
        let spawn = EchoChildSpawn::new();
        let spawns = Rc::clone(&spawn.spawns);
        let round_trips = Rc::new(Cell::new(0));
        let channel = SigningChannel {
            epoch: 7,
            sv: 2,
            marks,
            round_trips: Rc::clone(&round_trips),
        };
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let state = run_boot_handshake_core(
            3,
            Duration::from_millis(200),
            Duration::from_secs(10),
            spawn,
            channel,
            &body,
            true,
            &mut |e| events.push(e),
        )
        .expect("Ready handshake must serve under require_real = true");
        assert_eq!(state.epoch, 7);
        assert_eq!(state.structural_version, 2);
        assert!(
            crate::agent_dispatch::is_anti_rollback_configured(),
            "install-on-Fresh provenance must reach the wired serve decision"
        );
        assert_eq!(spawns.get(), 1, "exactly one quote child spawn");
        assert_eq!(round_trips.get(), 1, "exactly one channel round-trip");
        assert_eq!(
            events.len(),
            3,
            "exactly the three wired events: {events:?}"
        );
        assert!(matches!(events[0], AgentBootEvent::RawBudgetConfig { .. }));
        assert!(matches!(events[1], AgentBootEvent::ValidatedBudget { .. }));
        assert!(matches!(
            events[2],
            AgentBootEvent::HandshakeOutcome { ready: true, .. }
        ));
        for e in &events {
            assert_eq!(e.level(), BootLogLevel::Info, "happy path is all-Info: {e}");
        }
        // Pristine claim on exit (this test claimed through the wired core) — claim-test hygiene.
        reset_process_quote_ledger_claim_for_tests();
    }

    #[test]
    fn wired_driver_count_is_the_same_witness_max_attempts() {
        // THE §8 named TEST-BACKED (4b) item (DRIVER-COUNT BINDING). Regression: a wiring that
        // validates one budget and hand-feeds the driver a literal/second-validate count changes
        // the observed attempt count. Honesty note: this refusal power is VALUE-level, not
        // instance-level — a wiring that validated a SECOND budget with identical numbers is
        // observationally identical (and harmless); the §8 drift class (different numbers) is what
        // the no-count-param signature eliminates and this test refuses. The count binds through
        // BOTH legs: the driver calls `anchor_round_trip` once per attempt and the transport runs
        // producer-then-channel, so echo-succeeding spawn + always-Err channel ⇒ spawns == N AND
        // round_trips == N.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let body = test_body(7, 2);
        // Distinctive count: ≠ the ceiling (64), ≠ any default.
        let spawn = EchoChildSpawn::new();
        let spawns = Rc::clone(&spawn.spawns);
        let round_trips = Rc::new(Cell::new(0));
        let channel = AlwaysErrChannel {
            round_trips: Rc::clone(&round_trips),
        };
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let err = run_boot_handshake_core(
            3,
            Duration::from_millis(200),
            Duration::from_secs(10),
            spawn,
            channel,
            &body,
            false,
            &mut |e| events.push(e),
        )
        .expect_err("always-Err channel must exhaust the bounded retries");
        assert!(
            matches!(
                err,
                ProtocolError::PqSigningUnavailable(
                    "agent gateway boot anti-rollback handshake did not reach Ready \
                     (refusing to serve)"
                )
            ),
            "got {err:?}"
        );
        assert_eq!(
            spawns.get(),
            3,
            "attempt count at the SPAWN seam == the config value"
        );
        assert_eq!(
            round_trips.get(),
            3,
            "attempt count at the CHANNEL seam == the config value"
        );
        match events.last().expect("HandshakeOutcome event") {
            e @ AgentBootEvent::HandshakeOutcome { ready, line } => {
                assert!(!ready, "exhausted retries are not Ready");
                assert_eq!(e.level(), BootLogLevel::Warn, "non-Ready outcome is Warn");
                // Prefix + substring only — Debug rendering is not a stable contract.
                assert!(
                    line.starts_with("FailClosed(RetriesExhausted"),
                    "got {line}"
                );
                assert!(line.contains("wired test channel error"), "got {line}");
            }
            other => panic!("expected HandshakeOutcome, got {other:?}"),
        }
        reset_process_quote_ledger_claim_for_tests();
    }

    #[test]
    fn boot_events_raw_triplet_before_validate_on_refusal() {
        // Regression: §8 two-phase (a) — a numberless fail-closed boot must still leave the
        // operator the numbers (the static error strings carry none by the house anti-oracle
        // pattern). Drives the WRAPPER — safe under the TEST RULE: validate fails before any spawn.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let body = test_body(7, 2);
        let t = Duration::from_millis(200);
        let overall = Duration::from_secs(10);
        let round_trips = Rc::new(Cell::new(0));
        let channel = AlwaysErrChannel {
            round_trips: Rc::clone(&round_trips),
        };
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let err =
            run_boot_handshake_wired(0, t, overall, channel, &body, true, &mut |e| events.push(e))
                .expect_err("max_attempts=0 must refuse at validate");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: max_attempts must be >= 1")
            ),
            "got {err:?}"
        );
        assert_eq!(
            events,
            vec![AgentBootEvent::RawBudgetConfig {
                max_attempts: 0,
                per_leg_timeout: t,
                overall_boot_budget: overall,
            }],
            "EXACTLY the raw triplet — nothing else emitted"
        );
        assert_eq!(
            events[0].to_string(),
            format!(
                "boot budget config (raw, pre-validate): max_attempts=0 per_leg_timeout={t:?} \
                 overall_boot_budget={overall:?}"
            ),
            "the exact pinned raw line"
        );
        assert_eq!(events[0].level(), BootLogLevel::Info);
        assert_eq!(round_trips.get(), 0, "no attempt ran");
    }

    #[test]
    fn wired_wrapper_emits_validated_getters_and_slack_before_the_claim() {
        // Regression: §8 two-phase (b) — the getter line incl. nominal_boot_cost AND slack. DOUBLES
        // as evidence the wrapper constructs the CONCRETE process-claiming producer (a generic-Q
        // shim claims nothing) and emits the numbers BEFORE the claim (the operator keeps them even
        // when wiring fails later). Safe under the TEST RULE: the pre-burned claim refuses before
        // any spawn.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let body = test_body(7, 2);
        let t = Duration::from_millis(200);
        let n = 3u32;
        let nominal = nominal_product(n, t);
        let slack = Duration::from_millis(7);
        let overall = nominal.checked_add(slack).expect("test arithmetic fits");
        // Pre-hold the claim under the lock.
        let budget = ValidatedBootBudget::validate(n, t, overall).expect("valid config");
        let _held = HardBoundedQuoteProducer::new(&budget, EchoChildSpawn::new())
            .expect("pre-hold claims first");
        let round_trips = Rc::new(Cell::new(0));
        let channel = AlwaysErrChannel {
            round_trips: Rc::clone(&round_trips),
        };
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let err =
            run_boot_handshake_wired(n, t, overall, channel, &body, true, &mut |e| events.push(e))
                .expect_err("burned claim must refuse the wired wrapper");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("quote producer: process quote ledger already claimed")
            ),
            "got {err:?}"
        );
        assert_eq!(
            events,
            vec![
                AgentBootEvent::RawBudgetConfig {
                    max_attempts: n,
                    per_leg_timeout: t,
                    overall_boot_budget: overall,
                },
                AgentBootEvent::ValidatedBudget {
                    max_attempts: n,
                    per_leg_timeout: t,
                    overall_boot_budget: overall,
                    nominal_boot_cost: nominal,
                    slack,
                },
            ],
            "raw THEN validated, in order; the claim refusal stops the wiring after both"
        );
        assert_eq!(
            events[1].level(),
            BootLogLevel::Info,
            "non-zero slack is Info"
        );
        assert_eq!(
            events[1].to_string(),
            format!(
                "boot budget validated: max_attempts={n} per_leg_timeout={t:?} \
                 overall_boot_budget={overall:?} nominal_boot_cost={nominal:?} slack={slack:?}"
            ),
            "the exact pinned validated line, WITHOUT the zero-slack suffix"
        );
        assert_eq!(round_trips.get(), 0, "no attempt ran");
        reset_process_quote_ledger_claim_for_tests();
    }

    #[test]
    fn boot_events_zero_slack_is_warn_and_still_boots() {
        // Regression: §8 — a zero-slack config VALIDATES (`≤` passes) but is mis-sized by
        // definition and deserves a WARN-level line; the classification is library-owned, not bin
        // prose.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let body = test_body(7, 2);
        let t = Duration::from_millis(200);
        let nominal = nominal_product(1, t);
        let overall = nominal; // EXACTLY the const-derived nominal: zero slack, still validates.
        let spawn = EchoChildSpawn::new();
        let spawns = Rc::clone(&spawn.spawns);
        let round_trips = Rc::new(Cell::new(0));
        let channel = AlwaysErrChannel {
            round_trips: Rc::clone(&round_trips),
        };
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let _ = run_boot_handshake_core(1, t, overall, spawn, channel, &body, false, &mut |e| {
            events.push(e)
        })
        .expect_err("always-Err channel fails closed — but zero slack must NOT refuse validation");
        assert_eq!(spawns.get(), 1, "validation PROCEEDED: the quote leg ran");
        assert_eq!(
            round_trips.get(),
            1,
            "validation PROCEEDED: the channel leg ran"
        );
        match &events[1] {
            AgentBootEvent::ValidatedBudget { slack, .. } => {
                assert_eq!(*slack, Duration::ZERO, "slack via the event == ZERO");
            }
            other => panic!("expected ValidatedBudget, got {other:?}"),
        }
        assert_eq!(
            events[1].level(),
            BootLogLevel::Warn,
            "zero slack is WARN — library-owned"
        );
        assert_eq!(
            events[1].to_string(),
            format!(
                "boot budget validated: max_attempts=1 per_leg_timeout={t:?} \
                 overall_boot_budget={overall:?} nominal_boot_cost={nominal:?} slack={:?} \
                 (ZERO SLACK: nominal boot cost equals overall_boot_budget - mis-sized by \
                 definition)",
                Duration::ZERO
            ),
            "the exact pinned validated line WITH the zero-slack suffix"
        );
        // Classification boundary: the raw triplet stays Info; the non-Ready outcome is Warn.
        assert_eq!(events[0].level(), BootLogLevel::Info);
        assert!(matches!(
            events[2],
            AgentBootEvent::HandshakeOutcome { ready: false, .. }
        ));
        assert_eq!(events[2].level(), BootLogLevel::Warn);
        reset_process_quote_ledger_claim_for_tests();
    }

    #[test]
    fn wired_second_call_refuses_via_permanent_claim_before_any_attempt() {
        // Regression: §8 5b-2c precondition (2) pinned AT THE WIRING — no in-process
        // whole-handshake retry; the claim error is FATAL position (`?`-propagated post-validate,
        // pre-driver), never folded into the retryable class (which would spin the attempt budget
        // on a permanent refusal).
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let body = test_body(7, 2);
        let t = Duration::from_millis(200);
        let overall = Duration::from_secs(10);
        let round_trips = Rc::new(Cell::new(0));
        let mut first_events: Vec<AgentBootEvent> = Vec::new();
        let _ = run_boot_handshake_core(
            1,
            t,
            overall,
            EchoChildSpawn::new(),
            AlwaysErrChannel {
                round_trips: Rc::clone(&round_trips),
            },
            &body,
            false,
            &mut |e| first_events.push(e),
        )
        .expect_err("first call fails closed (always-Err channel) but CLAIMS permanently");
        let after_first = round_trips.get();
        assert_eq!(
            after_first, 1,
            "precondition: the first call ran its one attempt"
        );
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let err = run_boot_handshake_core(
            1,
            t,
            overall,
            EchoChildSpawn::new(),
            AlwaysErrChannel {
                round_trips: Rc::clone(&round_trips),
            },
            &body,
            false,
            &mut |e| events.push(e),
        )
        .expect_err("second call must refuse via the permanent claim");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("quote producer: process quote ledger already claimed")
            ),
            "got {err:?}"
        );
        assert_eq!(
            round_trips.get(),
            after_first,
            "NO attempt ran on the second call"
        );
        assert_eq!(
            events,
            vec![
                AgentBootEvent::RawBudgetConfig {
                    max_attempts: 1,
                    per_leg_timeout: t,
                    overall_boot_budget: overall,
                },
                AgentBootEvent::validated_from(
                    &ValidatedBootBudget::validate(1, t, overall).expect("valid config"),
                ),
            ],
            "refusal is post-validation, pre-driver — the operator still gets the numbers"
        );
        reset_process_quote_ledger_claim_for_tests();
    }
}
