//! Agent Gateway (4b) boot WIRING (TASK-7.7 5b-2b-ii (d-ii)/4b): the live composition of the
//! TWO-artifact serve gate into the boot path — `ValidatedBootBudget::validate` (gate #2) → the shared
//! producer+transport mint `transport_with_spawn` (gate #1: the CONCRETE `HardBoundedQuoteProducer`,
//! claim + witness by signature) → `run_boot_anti_rollback_handshake` with the count derived in-body
//! from the SAME witness → `decide_serve` — plus the typed boot-event seam
//! ([`AgentBootEvent`]/[`BootLogLevel`]) that discharges the §8 two-phase config-logging obligation in
//! the LIBRARY (content + severity; the 5b-2c bin only forwards Display lines to stderr→journald,
//! mapping [`AgentBootEvent::level`] to priority). NB the fatal paths emit no DEDICATED ERROR event
//! (events emitted BEFORE the failure point still flow — they carry context, not the cause) — the
//! bin MUST also render the returned `ProtocolError` to stderr at err priority; the event seam alone
//! under-reports the most severe class (§8 (4b) re-scope item (d)). Event matrix per failure class:
//! validate `Err` ⇒ RawBudgetConfig only + the Err; claim refusal ⇒ RawBudgetConfig +
//! ValidatedBudget + the Err; driver FailClosed ⇒ all three events (HandshakeOutcome ready:false
//! carries the cause at Warn) + the folded Err; Ready-but-gate-refused (driver-bug corner) ⇒ all
//! three with ready:true + the DISTINCT gate-refusal Err — the one class where the event stream
//! reads success.
//!
//! (4b) ships the COMPOSITION, not a serving loop: nothing here is `pub`, there is no listener and no
//! bin, and live serve remains gated on the TWO-artifact gate — the (4c) in-guest aya smoke + 5b-2c
//! witness-construction-from-operator-config (§8). The module is consumer-free until the 5b-2c bin's
//! `pub` wrapper (`run_agent_gateway_boot`, §8) wraps [`run_boot_handshake_wired`] — the exact
//! precedent of `production_transport`/`production()` when (d-ii)/2+3 landed — hence the module-wide
//! allow below.
//!
//! Discharged HERE (the two §8 5b-2c preconditions named at (d-ii)/3): the DRIVER-COUNT BINDING (by
//! construction — no SEPARATE driver-count input exists; the ONE `max_attempts` input is the value
//! `validate()` blesses and the driver receives, so a second, divergent count is unrepresentable:
//! `budget.max_attempts()` is derived in-body from the same witness that minted the transport;
//! test-backed by
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
/// catch-all so a future reap-status variant cannot break the bin build). The SAME applies to
/// [`BootLogLevel`] — the two enums promote together; also decide AT PROMOTION whether a non-Ready
/// outcome (`ready: false`) deserves an `Error` level distinct from Warn.
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
    /// Secret-content audit: the Debug render carries protocol-PUBLIC anti-rollback state only
    /// (`AnchorState` = epoch/structural_version/marks digest — no key material by construction);
    /// any future field added to `AnchorState`/`BootDriverFail` must re-audit this render for
    /// secret content.
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

    /// THE zero-slack classification — the ONE predicate both [`Self::level`] and the Display
    /// suffix consult (single-source rule: two encodings of one classification would drift).
    fn is_zero_slack(&self) -> bool {
        matches!(self, Self::ValidatedBudget { slack, .. } if *slack == Duration::ZERO)
    }

    /// Library-owned severity: zero-slack ValidatedBudget → Warn (validates but mis-sized by
    /// definition, §8); a non-Ready HandshakeOutcome → Warn; everything else Info.
    pub(crate) fn level(&self) -> BootLogLevel {
        match self {
            Self::ValidatedBudget { .. } if self.is_zero_slack() => BootLogLevel::Warn,
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
                // Single-source rule: the suffix decision is the SAME predicate level() consults.
                if self.is_zero_slack() {
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
// SINK CONTRACT (§8 (4b) re-scope; compact 8473): `emit` is infallible-synchronous BY DESIGN — the
// library has no error channel for logging and must not gain one (classification stays CLOSED). The
// 5b-2c bin's closure MUST therefore be non-panicking bounded best-effort (the `let _ = writeln!`
// house pattern — NEVER eprintln!, which panics on broken stderr): a PANIC in the sink after the
// claim burns the process claim (fail-closed, supervisor restart heals), and a BLOCKING sink delays
// only the pre/post-handshake edges (the sink is never threaded into the deadline-bounded fetch).
fn run_boot_handshake_core<S, C>(
    max_attempts: u32,
    per_leg_timeout: Duration,
    overall_boot_budget: Duration,
    spawn: S,
    channel: C,
    body: &mut crate::agent_keystore::KeystoreBody,
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
/// allowance — an operator override flag must be unrepresentable in the bin). NB `release_build` is
/// THE CRATE's build.rs-defined custom cfg (set on `PROFILE == "release"` or
/// `TWOD_HSM_STRICT_RELEASE_GUARDS`, registered via `rustc-check-cfg`) — NOT a std flag; `[[bin]]`
/// targets share the crate build.rs, so it applies to the 5b-2c bin as-is (a literal copy into a
/// DIFFERENT crate would silently evaluate false — fail-open — without its own build.rs).
/// TEST RULE: tests MUST NOT drive this fn past validation/claim — `ExecChildSpawn::production()`
/// re-execs `/proc/self/exe`, which in a test process is the TEST BINARY with no argv filter (a
/// full-suite recursive child). Behavioral tests drive `run_boot_handshake_core` with echo fakes.
pub(crate) fn run_boot_handshake_wired<C: crate::agent_boot_relay::BootRelayChannel>(
    max_attempts: u32,
    per_leg_timeout: Duration,
    overall_boot_budget: Duration,
    channel: C,
    body: &mut crate::agent_keystore::KeystoreBody,
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

/// (5b-2c) The agent-gateway serve-bin boot entrypoint — the SOLE `pub` bridge across the bin/lib
/// boundary (every wired type it composes is `pub(crate)` in this crate-private module, unreachable
/// from a separate-crate `[[bin]]`). Sequences the §8 boot: agent provisioning root → unseal the agent
/// keystore (5b-2d) → parse the operator budget → construct the concrete `VsockBootRelayChannel` → ONE
/// wired handshake → install the keystore AFTER `Ready` → SERVE. `require_real` is HARDCODED
/// `cfg!(release_build)` (§8: no operator override; `release_build` is THIS crate's build.rs cfg — a
/// copy out-of-crate evaluates false ⇒ fail-OPEN). Returns `Result<Infallible, ProtocolError>`: `Ok` is
/// unconstructible (the serve loop diverges); `Err` is the FATAL boot/install/startup class. ONE
/// handshake per process — on any failure the bin EXITS for supervisor restart (the producer claim is
/// permanent; NO in-process retry). The emit sink is WRAPPER-INTERNAL (keeps `AgentBootEvent`
/// `pub(crate)`): best-effort `let _ = writeln!` (NEVER `eprintln!` — a sink panic after the claim burns
/// it), mapping `level()` to a journald priority tag; the returned `ProtocolError` is ALSO rendered at
/// err (the event seam emits no dedicated error event).
///
/// ERROR CARRIER (convention, not a precise type): all boot/config/install failures here are carried as
/// `ProtocolError::PqSigningUnavailable` — the established agent fail-closed variant since 5b-2d, an
/// intentional `&'static str` carrier. A dedicated `BootConfig`/`BootInstall` variant is deliberately NOT
/// added (it would widen the exhaustive `protocol_error_to_wire_body` mapper for zero caller benefit — the
/// bin renders the string and exits, it never branches on the variant). The rendered STRING is the operator
/// surface; do NOT semantically match on the variant for these boot errors.
pub fn run_agent_gateway_boot() -> Result<std::convert::Infallible, ProtocolError> {
    use std::io::Write as _;
    run_agent_gateway_boot_inner().inspect_err(|e| {
        let _ = writeln!(std::io::stderr(), "[err] agent-gateway boot failed: {e}");
    })
}

// ---------------------------------------------------------------------------------------------------
// TASK-18 AC#1: the production provisioning bootstrap driver (25-2b-iv Driver Contract).
// Listens on the provisioning vsock port, runs the M1→M2→M3→M4 attested install handshake,
// then returns the freshly-sealed keystore body + measurement for installation. One-connection
// only (Q5); a Failed session tears down the listener (the host must re-connect for any retry).
// The measurement passed to ProvisionSession::new is the SAME hardware measurement that appears
// in the M2 SNP report (fetched from the enclave's own configfs-tsm).
// ---------------------------------------------------------------------------------------------------

/// 4-byte big-endian length-prefixed frame read (matches the 0x40 serve framing).
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
fn recv_frame<R: std::io::Read>(stream: &mut R) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|_e| ProtocolError::PqSigningUnavailable(
        "provisioning: frame header read failed",
    ))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > crate::MAX_MESSAGE_SIZE as usize {
        return Err(ProtocolError::PqSigningUnavailable(
            "provisioning: frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).map_err(|_e| ProtocolError::PqSigningUnavailable(
        "provisioning: frame body read failed",
    ))?;
    Ok(buf)
}

/// 4-byte big-endian length-prefixed frame write.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
fn send_frame<W: std::io::Write>(stream: &mut W, data: &[u8]) -> Result<(), ProtocolError> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|_e| ProtocolError::PqSigningUnavailable(
        "provisioning: frame header write failed",
    ))?;
    stream.write_all(data).map_err(|_e| ProtocolError::PqSigningUnavailable(
        "provisioning: frame body write failed",
    ))?;
    stream.flush().map_err(|_e| ProtocolError::PqSigningUnavailable(
        "provisioning: frame flush failed",
    ))?;
    Ok(())
}

/// The production provisioning bootstrap driver. Returns the freshly-provisioned keystore body
/// + the enclave measurement. Called ONLY on first boot (no pre-sealed keystore); subsequent boots
/// unseal from the persisted blob via `unseal_agent_keystore_at_boot`.
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
fn run_provisioning_bootstrap(
    seal_root: &[u8; 32],
) -> Result<(crate::agent_keystore::KeystoreBody, Vec<u8>), ProtocolError> {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: fetching enclave measurement");
    // Get the hardware measurement from a zero-report_data SNP report (the measurement field
    // is hardware-signed and identical regardless of report_data — we verify it matches later
    // in the M2 report).
    let (dummy_report, _) = crate::snp_report::fetch_report(&[0u8; 64])?;
    let measurement = crate::snp_report::measurement_from_report(&dummy_report)?;

    // (2) Parse the pinned operator CA root (hex → Ed25519 VerifyingKey).
    let ca_root_hex = crate::env_config::var_twod(
        crate::env_config::TWOD_HSM_OPERATOR_CA_ROOT_HEX,
        crate::env_config::LEGACY_HSM_OPERATOR_CA_ROOT_HEX,
    ).map_err(|_| ProtocolError::PqSigningUnavailable(
        "provisioning: TWOD_HSM_OPERATOR_CA_ROOT_HEX not set",
    ))?;
    let ca_root_bytes = {
        let h = ca_root_hex.trim();
        if h.len() != 64 {
            return Err(ProtocolError::PqSigningUnavailable(
                "provisioning: operator CA root hex must be 64 chars (32 bytes)",
            ));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in h.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
                .map_err(|_| ProtocolError::PqSigningUnavailable(
                    "provisioning: operator CA root hex decode failed",
                ))?;
        }
        out.to_vec()
    };
    let ca_root_arr: [u8; 32] = ca_root_bytes.as_slice().try_into().map_err(|_| ProtocolError::PqSigningUnavailable(
        "provisioning: operator CA root must be exactly 32 bytes",
    ))?;
    let ca_root = ed25519_dalek::VerifyingKey::from_bytes(&ca_root_arr).map_err(|_| ProtocolError::PqSigningUnavailable(
        "provisioning: operator CA root is not a valid Ed25519 verifying key",
    ))?;

    // (3) Create the session.
    let mut session = crate::agent_provision::ProvisionSession::new(
        ca_root,
        *seal_root,
        measurement.to_vec(),
    );

    // (4) Bind the provisioning vsock listener (one connection — Q5).
    let port = crate::vsock_addr::provisioning_vsock_port_from_env().map_err(|msg| {
        let _ = writeln!(std::io::stderr(), "[err] provisioning: {msg}");
        ProtocolError::PqSigningUnavailable(
            "provisioning: invalid provisioning vsock port (see prior log line)",
        )
    })?;
    let listener = crate::vsock_listen::bind_vsock_listener(
        crate::vsock_addr::DEFAULT_VSOCK_CID,
        port,
    ).map_err(|e| {
        let _ = writeln!(std::io::stderr(), "[err] provisioning: vsock bind failed: {e}");
        ProtocolError::PqSigningUnavailable(
            "provisioning: vsock bind failed (see prior log line)",
        )
    })?;

    // (5) Accept ONE connection.
    let (mut stream, _peer) = listener.accept().map_err(|e| {
        let _ = writeln!(std::io::stderr(), "[err] provisioning: accept failed: {e}");
        ProtocolError::PqSigningUnavailable(
            "provisioning: accept failed (see prior log line)",
        )
    })?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: provisioner connected");

    // (6) M1: receive the provisioner's challenge.
    let m1_frame = recv_frame(&mut stream)?;

    let m1 = crate::agent_provision::decode_m1(&m1_frame).map_err(|e| {
        let _ = writeln!(std::io::stderr(), "[err] provisioning: M1 decode failed: {e:?}");
        ProtocolError::PqSigningUnavailable("provisioning: M1 decode failed")
    })?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: M1 received");

    // (7) on_m1: mint enclave nonce N_e + compute report_data.
    let (n_e, report_data) = session.on_m1(m1.n_p).map_err(|e| {
        let _ = writeln!(std::io::stderr(), "[err] provisioning: on_m1 failed: {e:?}");
        ProtocolError::PqSigningUnavailable("provisioning: on_m1 failed")
    })?;

    // (8) Fetch the M2 SNP attestation report (report_data binds N_p + N_e + measurement).
    let _ = writeln!(std::io::stderr(), "[info] provisioning: fetching SNP report");
    let (report, _cert_chain) = crate::snp_report::fetch_report(&report_data)
        .map_err(|e| {
            let _ = writeln!(std::io::stderr(), "[err] provisioning: SNP report fetch failed: {e}");
            ProtocolError::PqSigningUnavailable("provisioning: SNP report fetch failed")
        })?;

    // (9) M2: send N_e + report to the provisioner.
    let m2 = crate::agent_provision::encode_m2(&n_e, &report);
    send_frame(&mut stream, &m2)?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: M2 sent (report {}B)", report.len());

    // (10) M3: receive the provisioner's config + signature.
    let m3_frame = recv_frame(&mut stream)?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: M3 received");

    // (11) on_m3: verify provisioner cert + transcript + sig, mint enclave_scope_id (getrandom),
    //      seal the keystore. One-shot failure: ANY error consumes the session (Failed terminal).
    let (_config, sealed_blob) = session.on_m3(&m3_frame, &report).map_err(|e| {
        let _ = writeln!(std::io::stderr(), "[err] provisioning: on_m3 failed (session consumed): {e:?}");
        ProtocolError::PqSigningUnavailable("provisioning: on_m3 failed — session consumed (restart required)")
    })?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: keystore sealed ({}B)", sealed_blob.len());

    // (12) M4: send the sealed keystore blob to the provisioner (for the host to persist).
    let m4 = crate::agent_provision::encode_m4(&sealed_blob);
    send_frame(&mut stream, &m4)?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: M4 sent — handshake complete");

    // (13) Unseal the freshly-provisioned blob for in-enclave installation.
    let body = crate::agent_keystore::unseal_body(&sealed_blob, seal_root, &measurement)
        .map_err(|e| {
            let _ = writeln!(std::io::stderr(), "[err] provisioning: unseal of freshly-provisioned blob failed: {e:?}");
            ProtocolError::PqSigningUnavailable("provisioning: unseal of freshly-provisioned blob failed")
        })?;
    let _ = writeln!(std::io::stderr(), "[info] provisioning: keystore installed");

    Ok((body, measurement.to_vec()))
}

fn run_agent_gateway_boot_inner() -> Result<std::convert::Infallible, ProtocolError> {
    use std::io::Write as _;
    // (A) agent provisioning root FIRST (install-once).
    crate::boot_agent_keystore::boot_configure_agent_seal_root()?;
    // (B) Keystore source: provisioning mode (first boot — attested install handshake) or
    //     unseal mode (subsequent boots — pre-sealed blob from file). The provisioning driver
    //     is the runtime path that mints a getrandom enclave_scope_id (TASK-18 AC#1).
    #[cfg(all(target_os = "linux", feature = "vsock-transport"))]
    let (mut body, measurement) = if crate::env_config::provisioning_mode_enabled() {
        let root = crate::seal_root::resolve_provisioning_root()?;
        run_provisioning_bootstrap(&root)?
    } else {
        crate::boot_agent_keystore::unseal_agent_keystore_at_boot()?
    };
    #[cfg(not(all(target_os = "linux", feature = "vsock-transport")))]
    let (mut body, measurement) = crate::boot_agent_keystore::unseal_agent_keystore_at_boot()?;
    // (C) operator-config → budget triplet (validate() PARAM ORDER; parse + derive-by-default only —
    //     ValidatedBootBudget::validate inside the handshake is the sole fail-closed band judge).
    let (max_attempts, per_leg_timeout, overall_boot_budget) =
        crate::env_config::boot_budget_config_from_env().map_err(|msg| {
            // Render the parser's SPECIFIC per-var message (which var, why) at err — the static
            // ProtocolError can't carry the dynamic String (&'static str), so surface it here or the
            // operator gets a generic refusal naming all three vars.
            let _ = writeln!(std::io::stderr(), "[err] agent boot: {msg}");
            ProtocolError::PqSigningUnavailable(
                "agent boot: invalid boot-budget config (see prior log line)",
            )
        })?;
    // (D) construct the concrete channel internally (the bin can't reach VsockBootRelayChannel::new).
    //     The boot-relay DIAL target is host CID 2 on the anchor relay port (distinct from the serve
    //     listen port — anchor_relay_port_from_env validates relay != serve).
    let relay_port = crate::vsock_addr::anchor_relay_port_from_env().map_err(|msg| {
        // Surface the parser's SPECIFIC reason (a relay==serve PORT COLLISION names the conflicting
        // serve var + value; or port==0 / parse / non-UTF-8) before the static ProtocolError — same as
        // the budget path; a generic message would point the operator at the wrong var.
        let _ = writeln!(std::io::stderr(), "[err] agent boot: {msg}");
        ProtocolError::PqSigningUnavailable(
            "agent boot: invalid anchor relay port (see prior log line)",
        )
    })?;
    let channel = crate::agent_boot_relay::VsockBootRelayChannel::new(
        crate::vsock_addr::VMADDR_CID_HOST,
        relay_port,
    );
    // (E) wrapper-internal best-effort emit sink (decision: keeps AgentBootEvent pub(crate)). NEVER
    //     eprintln!; maps level() to a journald-style priority tag.
    let mut emit = |ev: AgentBootEvent| {
        let priority = match ev.level() {
            BootLogLevel::Info => "info",
            BootLogLevel::Warn => "warn",
        };
        let _ = writeln!(std::io::stderr(), "[{priority}] {ev}");
    };
    // (F) ONE wired handshake; decide_serve is INSIDE; &mut body is BORROWED here (5b-2e: an AdoptForward
    //     seeds body forward in place). require_real HARDCODED. The &mut borrow ends when this returns,
    //     so (G) can MOVE the now-(possibly-seeded) body into install.
    let _ready: crate::agent_anchor::AnchorState = run_boot_handshake_wired(
        max_attempts,
        per_leg_timeout,
        overall_boot_budget,
        channel,
        &mut body,
        cfg!(release_build),
        &mut emit,
    )?;
    // (G) install the keystore LAST (MOVES the post-handshake body — the SEEDED one on an adopt, the
    //     original on a plain Fresh; a non-Ready outcome aborts at the `?` above, never reaching here).
    //     false (overwrite / empty-measurement / poison) is FATAL — abort, never log-and-serve
    //     (install-AFTER-Ready: a stale-but-valid keystore is never process-global before the gate).
    if !crate::agent_dispatch::install_agent_keystore(body, &measurement) {
        return Err(ProtocolError::PqSigningUnavailable(
            "agent boot: install_agent_keystore returned false (already installed / empty \
             measurement) — fatal",
        ));
    }
    // (G') slice 6-4b: install the per-op anchor-COMMIT channel — a SECOND `VsockBootRelayChannel` to the
    //      SAME host relay (the boot handshake CONSUMED its own at step F; the channel opens a FRESH vsock
    //      connection per `round_trip` and stores no fd — stale-reply isolation — so the two instances
    //      share nothing). Gated under `agent-keygen-exec-preview` because the preview GENERATE_KEYS exec
    //      path is the channel's ONLY consumer: a non-preview build installs nothing and GENERATE_KEYS
    //      stays NotConfigured. Placed AFTER the keystore install and BEFORE serve, so no frame can race
    //      the two installs (the serve loop starts only after BOTH) and the KEYSTORE→COMMIT_CHANNEL lock
    //      order is respected. `false` ⇒ FATAL (already installed = double-boot / bug; see the helper).
    #[cfg(feature = "agent-keygen-exec-preview")]
    install_serve_time_commit_channel(Box::new(
        crate::agent_boot_relay::VsockBootRelayChannel::new(
            crate::vsock_addr::VMADDR_CID_HOST,
            relay_port,
        ),
    ))?;
    // (H) SERVE the agent 0x40 command loop. Diverges (Ok never constructed). 5b-2c-i ships a
    //     fail-closed stub; 5b-2c-ii implements the real bind+accept+pump.
    run_agent_serve_loop()
}

/// slice 6-4b: install the process-global per-op anchor-COMMIT channel — consumed by the preview-gated
/// GENERATE_KEYS seal-before-emit path — BEFORE the serve loop starts, so the first keygen can durably
/// commit its advanced `{epoch, structural, marks}` to the anchor. Takes the channel as an OWNED trait
/// object (the boot caller boxes the concrete [`crate::agent_boot_relay::VsockBootRelayChannel`]) so this
/// install-once + fail-closed logic stays deviceless-unit-testable with a `Send` mock — the real channel
/// is only constructed at the SNP-pinned call site. **Install-once:** a `false` return means a channel is
/// ALREADY installed (a double-boot / caller bug — structurally impossible on a clean single boot) ⇒
/// FATAL, fail closed (never serve the preview keygen path against a duplicate/unknown channel; mirrors
/// the `install_agent_keystore` false=FATAL contract). **SAFETY:** the channel is PURE TRANSPORT — the
/// trust anchor is the sealed `anchor_root` verified against the commit ACK signature
/// (`verify_commit_ack_bytes`), so a bad/host-controlled channel can only fail an op CLOSED, never cause a
/// wrong-accept.
#[cfg(feature = "agent-keygen-exec-preview")]
fn install_serve_time_commit_channel(
    channel: Box<dyn crate::agent_boot_relay::BootRelayChannel + Send>,
) -> Result<(), ProtocolError> {
    if !crate::agent_dispatch::install_commit_channel(channel) {
        return Err(ProtocolError::PqSigningUnavailable(
            "agent boot: install_commit_channel returned false (already installed) — fatal",
        ));
    }
    Ok(())
}

/// A pump `Err` that is a PROTOCOL-LEVEL reject of PEER input — every case an UNAUTHENTICATED peer can trip
/// at the DECODE/ROUTE layer BEFORE any keystore auth — vs a genuine local/transport fault. The former are
/// logged CALMLY (info) so a peer cannot turn malformed pre-auth frames into a WARN-flood lever (the producer
/// path folds these into an Ok error-reply and never warns); genuine faults stay at warn. The peer-reject
/// classes: a misrouted type (`WireProtocol`), a bad version byte (`InvalidVersion`), an unknown message-type
/// byte (`UnknownMessageType`), and a sub-header / too-short frame — `decode_message` surfaces the last as
/// `Io(UnexpectedEof)`; a MID-frame read EOF already breaks to `Ok` inside the pump (read taxonomy), so the
/// ONLY `UnexpectedEof` reaching this arm is a peer's short frame (write faults are `BrokenPipe`/`ConnectionReset`,
/// never `UnexpectedEof`). Read-side idle-timeout / oversize also break to `Ok` and never reach here.
fn is_peer_protocol_reject(e: &ProtocolError) -> bool {
    match e {
        ProtocolError::WireProtocol(_)
        | ProtocolError::InvalidVersion { .. }
        | ProtocolError::UnknownMessageType(_) => true,
        ProtocolError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}

/// THE agent serve port is 0x40-ONLY: decode the frame, REQUIRE `MessageType::AgentGateway`, route to the
/// reusable per-frame handler, and reframe the reply as 0x40. A NON-0x40 frame returns `Err` → the pump
/// closes the connection with ZERO bytes back (CLOSE-SILENTLY — strictly fail-closed; never synthesizes an
/// agent-band body for a misrouted type; [`handle_agent_gateway_frame`] is only ever called on a
/// verified-0x40 frame). A reply body that won't fit the wire (`MessageTooLarge` from `encode_message`) is
/// likewise a close-fault. `pub(crate)` (the `reply_resets_idle` precedent): the 5b-2c-iii lab smoke's
/// client↔serve cross-validation test drives the SHIPPED type-guard + reframe glue, not a replica.
pub(crate) fn agent_serve_one_frame(frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let decoded = crate::decode_message(frame)?;
    if decoded.msg_type != crate::MessageType::AgentGateway {
        return Err(ProtocolError::WireProtocol(
            "agent serve: non-0x40 frame on the agent listener",
        ));
    }
    // ALWAYS returns a body (errors already folded into the 0x40..=0x46 agent error band; the handler
    // poison-recovers the keystore/binding globals and never panics).
    let body = crate::agent_dispatch::handle_agent_gateway_frame(&decoded.payload);
    crate::encode_message(crate::MessageType::AgentGateway, &body)
}

/// THE one accepted-item body shared by the prod serial loop AND the `#[cfg(test)]` finite twin (no
/// `cfg(test)` drift). Three DISTINCT outcomes, never a fatal, never a panic:
/// - accept(2) itself failed (`Err`) → log "accept error" + bounded [`crate::enclave_serve::ACCEPT_ERROR_BACKOFF`]
///   (EMFILE/ENFILE anti-spin: accept fails WITHOUT draining the backlog, so a bare continue tight-spins).
/// - accept(2) succeeded but per-stream `prepare` (SO_*TIMEO arming) failed → log "stream setup failed" and
///   skip WITHOUT backoff (this is NOT fd pressure; mirrors the producer's `prepare_connection` seam so an
///   arm fault is never MISLABELED as an accept fault, and the seam is deviceless-testable).
/// - served: run the per-connection [`crate::enclave_serve::serve_framed_pump`]; a clean close / a CALM
///   peer-protocol reject ([`is_peer_protocol_reject`]) / a genuine fault are logged at info/info/warn.
/// RAII drops the connection on every path. `let _ = writeln!` NEVER `eprintln!` (a broken-stderr panic must
/// not kill serving).
fn handle_agent_accepted<S, P>(accepted: std::io::Result<S>, prepare: &mut P)
where
    S: std::io::Read + std::io::Write,
    P: FnMut(&mut S) -> Result<(), ProtocolError>,
{
    use std::io::Write as _;
    let mut conn = match accepted {
        Ok(conn) => conn,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "[warn] agent gateway: accept error ({}); skipping",
                e.kind()
            );
            std::thread::sleep(crate::enclave_serve::ACCEPT_ERROR_BACKOFF);
            return;
        }
    };
    if let Err(e) = prepare(&mut conn) {
        let _ = writeln!(
            std::io::stderr(),
            "[warn] agent gateway: stream setup failed ({e}); skipping"
        );
        return;
    }
    match crate::enclave_serve::serve_framed_pump(
        &mut conn,
        agent_serve_one_frame,
        crate::enclave_serve::SESSION_IDLE_TIMEOUT,
    ) {
        Ok(()) => {
            let _ = writeln!(
                std::io::stderr(),
                "[info] agent gateway: connection closed cleanly"
            );
        }
        Err(e) if is_peer_protocol_reject(&e) => {
            let _ = writeln!(
                std::io::stderr(),
                "[info] agent gateway: closed connection ({e})"
            );
        }
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "[warn] agent gateway: connection fault ({e}); closed"
            );
        }
    }
}

/// The agent SERIAL accept loop — one connection at a time, NO threads, NO `SharedEnclaveRuntime`, NO state
/// lock (mirrors `host_anchor_relay::serve_anchor_relay_loop` statement-for-statement). SERIAL is sufficient
/// AND strictly safer: every keystore mutation already serializes on the `INSTALLED_KEYSTORE` Mutex inside
/// [`handle_agent_gateway_frame`] regardless of thread count, and there is NO shared `EnclaveState` mutex, so
/// the producer's `process::exit(1)`-on-poison hazard is STRUCTURALLY ABSENT. Concurrent-capped is a NAMED §8
/// follow-up (triggered only if the upstream gateway ever multiplexes many independent slow clients).
/// `prepare` is the per-stream setup seam (prod arms SO_*TIMEO; the finite twin injects no-op / forced-fail).
/// Diverges: the prod `VsockListener::incoming()` is infinite so the `for` never exits; the finite
/// `#[cfg(test)]` twin loops the SAME `handle_agent_accepted` body and returns `()`.
fn serve_agent_loop<I, S, P>(incoming: I, mut prepare: P) -> std::convert::Infallible
where
    I: Iterator<Item = std::io::Result<S>>,
    S: std::io::Read + std::io::Write,
    P: FnMut(&mut S) -> Result<(), ProtocolError>,
{
    for accepted in incoming {
        handle_agent_accepted(accepted, &mut prepare);
    }
    unreachable!("VsockListener::incoming() never terminates")
}

/// (5b-2c-ii) The real agent 0x40 serve loop — bind the agent vsock listener (`vsock_listen_addr_from_env`,
/// a DISTINCT port from the boot-relay DIAL port; `anchor_relay_port_from_env` in boot step D already
/// validated relay != serve), then run the SERIAL accept loop. Reached ONLY after the boot wrapper succeeds
/// (root → unseal → handshake `Ready` → install_agent_keystore), so a serving agent always has a freshly
/// installed keystore + the anti-rollback binding the handler reads.
///
/// FAIL-CLOSED: addr-resolve / bind failures are the ONLY `Err` path — FATAL → `run_agent_gateway_boot`
/// renders at err → the bin exits → supervisor restart (an agent that cannot bind its serve port REFUSES to
/// serve, never a silent half-serve). The bind branch is NOT deviceless-testable (UnixStream pairs have no
/// CID) — it is aya/SNP-guest-pinned (like `host_anchor_relay`'s bind Risk #5); the deviceless suite covers
/// `serve_framed_pump` / `serve_agent_loop` / `agent_serve_one_frame` over in-memory pairs.
fn run_agent_serve_loop() -> Result<std::convert::Infallible, ProtocolError> {
    use std::io::Write as _;
    let (cid, port) = crate::vsock_addr::vsock_listen_addr_from_env().map_err(|msg| {
        let _ = writeln!(std::io::stderr(), "[err] agent gateway: {msg}");
        ProtocolError::PqSigningUnavailable(
            "agent serve: invalid vsock listen addr (see prior log line)",
        )
    })?;
    let listener = crate::vsock_listen::bind_vsock_listener(cid, port).map_err(|e| {
        let _ = writeln!(
            std::io::stderr(),
            "[err] agent gateway: vsock bind failed: {e}"
        );
        ProtocolError::PqSigningUnavailable("agent serve: vsock bind failed (see prior log line)")
    })?;
    let _ = writeln!(
        std::io::stderr(),
        "[info] agent gateway: serving on vsock CID {cid} port {port}"
    );
    // Per-stream setup seam: arm SO_RCVTIMEO/SO_SNDTIMEO (READ 30s / WRITE 120s) on each accepted stream
    // (the serve loop's idle bound, SESSION_IDLE_TIMEOUT 300s, is separate). A setup failure is logged as a
    // STREAM-SETUP fault (NOT an accept fault) and skipped per-connection by handle_agent_accepted, never
    // fatal — mirrors the producer's `run_incoming_accept_loop` prepare_connection seam.
    // Never returns Ok: the loop diverges (incoming() is infinite). The Ok wrapper documents at the type
    // level that serve never returns Ok; the divergence makes it unreachable.
    #[allow(unreachable_code)]
    Ok(serve_agent_loop(listener.incoming(), |s| {
        crate::vsock_listen::configure_vsock_session_timeouts(s).map_err(ProtocolError::from)
    }))
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
        encode_ok_frame, nominal_product, reset_process_quote_ledger_claim_for_tests, ChildHandle,
        HardBoundedQuoteProducer, QuoteChildSpawn, ReapOutcome, ValidatedBootBudget,
    };
    use ed25519_dalek::SigningKey;
    use std::cell::Cell;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    /// TRIPWIRE: the gate-free 5b-2c derive-by-default per-attempt margin MUST stay ≥ the real per-attempt
    /// ε (`QUOTE_ATTEMPT_OVERHEAD`) — else a DEFAULT-config boot derives an overall budget below the
    /// `nominal = max_attempts·(3·per_leg + ε)` floor `ValidatedBootBudget::validate` enforces, failing
    /// closed silently on the OUT-OF-BOX config. The parser is gate-free and can't reference the gated ε,
    /// so this pin lives here (mirrors the `QUOTE_ATTEMPT_OVERHEAD ≥ REAP_GRACE` pin in `quote_subprocess`).
    #[test]
    fn boot_derive_margin_covers_quote_attempt_overhead() {
        assert!(
            u128::from(crate::env_config::BOOT_DERIVE_PER_ATTEMPT_MARGIN_MS)
                >= crate::quote_subprocess::QUOTE_ATTEMPT_OVERHEAD.as_millis(),
            "derive-by-default margin must stay ≥ the per-attempt ε so the default budget clears validate()"
        );
    }

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
            enclave_scope_id: [0xe1; 32],
            fleet_scope_id: [0xf1; 32],
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
                cumulative_signing_budget: [0; 32],
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

    // Nominal-product derivation: the SHARED test-side helper `quote_subprocess::nominal_product`
    // (imported in the use-list above; single-source rule — an ε retune moves expectation and
    // production together). Expected Display strings below are LITERAL skeletons +
    // `format!("{:?}", derived)` insertions: a wrong format string in the lib stays visible while
    // the numbers stay const-derived.

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
        fn marks_round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            // These wired-boot tests exercise the FRESHNESS path only; the marks leg is unscripted.
            Err(crate::agent_boot_driver::AnchorTransportError(
                "wired test channel: marks not scripted",
            ))
        }
    }

    /// slice 6-4b: a `Send` commit-channel mock for the boot-time install test. The install-once test
    /// only INSTALLS it (never round-trips), so both transport legs are unreachable. (`AlwaysErrChannel`/
    /// `SigningChannel` hold `Rc`/`Cell` for test introspection and so are NOT `Send` — they cannot box
    /// into `Box<dyn BootRelayChannel + Send>`, which is what the process-global commit slot stores.)
    #[cfg(feature = "agent-keygen-exec-preview")]
    struct UnusedSendCommitChannel;
    #[cfg(feature = "agent-keygen-exec-preview")]
    impl crate::agent_boot_relay::BootRelayChannel for UnusedSendCommitChannel {
        fn round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            unreachable!("the 6-4b install-once test never round-trips the channel")
        }
        fn marks_round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            unreachable!("the 6-4b install-once test never round-trips the channel")
        }
    }

    /// slice 6-4b: the boot-time per-op commit-channel install is install-once + fail-closed. The FIRST
    /// install succeeds on the empty slot; a SECOND (a double-boot) returns the FATAL already-installed
    /// `ProtocolError` so boot aborts rather than serving the preview keygen path against a duplicate
    /// channel. (The real `VsockBootRelayChannel` construction at the boot call site is SNP-pinned; this
    /// pins the install-once + false=FATAL contract deviceless via a `Send` mock.)
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn serve_time_commit_channel_installs_once_then_fatal_on_double_install() {
        // The guard resets ALL agent process-globals (incl. the commit channel slot) for isolation.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(
            install_serve_time_commit_channel(Box::new(UnusedSendCommitChannel)).is_ok(),
            "first boot install succeeds on the empty slot"
        );
        let err = install_serve_time_commit_channel(Box::new(UnusedSendCommitChannel))
            .expect_err("a second install (double-boot) must fail closed, not silently overwrite");
        assert!(
            matches!(&err, ProtocolError::PqSigningUnavailable(s) if s.contains("install_commit_channel returned false")),
            "double-install is the fatal already-installed error, got {err:?}"
        );
        crate::agent_dispatch::reset_commit_channel_for_tests();
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
        fn marks_round_trip(
            &mut self,
            _request_frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            // These wired-boot tests exercise the FRESHNESS path only; the marks leg is unscripted.
            Err(crate::agent_boot_driver::AnchorTransportError(
                "wired test channel: marks not scripted",
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
        let mut body = test_body(7, 2);
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
            &mut body,
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
        // the no-SEPARATE-count-input signature eliminates (the ONE max_attempts input is the value
        // validate() blesses AND the driver receives) and this test refuses. The count binds through
        // BOTH legs: the driver calls `anchor_round_trip` once per attempt and the transport runs
        // producer-then-channel, so echo-succeeding spawn + always-Err channel ⇒ spawns == N AND
        // round_trips == N.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let mut body = test_body(7, 2);
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
            &mut body,
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
        let mut body = test_body(7, 2);
        let t = Duration::from_millis(200);
        let overall = Duration::from_secs(10);
        let round_trips = Rc::new(Cell::new(0));
        let channel = AlwaysErrChannel {
            round_trips: Rc::clone(&round_trips),
        };
        let mut events: Vec<AgentBootEvent> = Vec::new();
        let err = run_boot_handshake_wired(0, t, overall, channel, &mut body, true, &mut |e| {
            events.push(e)
        })
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
        let mut body = test_body(7, 2);
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
        let err = run_boot_handshake_wired(n, t, overall, channel, &mut body, true, &mut |e| {
            events.push(e)
        })
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
        let mut body = test_body(7, 2);
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
        let _ =
            run_boot_handshake_core(1, t, overall, spawn, channel, &mut body, false, &mut |e| {
                events.push(e)
            })
            .expect_err(
                "always-Err channel fails closed — but zero slack must NOT refuse validation",
            );
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
        let mut body = test_body(7, 2);
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
            &mut body,
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
            &mut body,
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

    // ===== 5b-2c-ii: the agent 0x40 serve loop (deviceless, over UnixStream pairs) =====
    // The real vsock bind branch in run_agent_serve_loop is aya/SNP-pinned (UnixStream pairs have no CID);
    // these drive serve_framed_pump / serve_agent_loop's body (drive_agent_serve_finite) / agent_serve_one_frame
    // over in-memory pairs. Each holds lock_and_reset_agent_process_globals() (resets all agent globals).

    /// Install a minimal agent keystore + active anti-rollback binding — the realistic post-boot state the
    /// serve loop runs in (the wrapper reaches run_agent_serve_loop only after install_agent_keystore).
    fn install_serving_state() {
        assert!(crate::agent_dispatch::install_agent_keystore(
            test_body(1, 1),
            b"agent-meas"
        ));
        assert!(crate::agent_dispatch::install_anti_rollback_binding(
            crate::agent_dispatch::AntiRollbackBinding {
                epoch: 1,
                active: true
            }
        ));
    }

    fn agent_frame(payload: &[u8]) -> Vec<u8> {
        crate::encode_message(crate::MessageType::AgentGateway, payload).unwrap()
    }

    fn read_reply(peer: &mut UnixStream) -> crate::FramedMessage {
        let frame = crate::read_framed_message(peer).expect("a framed reply");
        crate::decode_message(&frame).expect("decodable reply")
    }

    /// Finite twin (§3b): loops the SAME handle_agent_accepted body as serve_agent_loop but returns () when a
    /// FINITE iterator drains — so Infallible stays truthful WITHOUT unreachable! ever firing under test.
    /// Threads the SAME per-stream `prepare` seam serve_agent_loop runs (no `cfg(test)` drift).
    fn drive_agent_serve_finite<I, S, P>(incoming: I, mut prepare: P)
    where
        I: Iterator<Item = std::io::Result<S>>,
        S: std::io::Read + std::io::Write,
        P: FnMut(&mut S) -> Result<(), ProtocolError>,
    {
        for accepted in incoming {
            handle_agent_accepted(accepted, &mut prepare);
        }
    }

    /// No-op per-stream setup for the deviceless twin: the prod arm seam (`configure_vsock_session_timeouts`)
    /// is vsock-only, so most tests inject this; the setup-FAILURE path is covered explicitly by
    /// `serve_loop_stream_setup_failure_skips_and_continues`.
    fn no_prepare<S>(_: &mut S) -> Result<(), ProtocolError> {
        Ok(())
    }

    #[test]
    fn serve_0x40_frame_round_trips_to_a_0x40_reply_no_panic() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let (mut relay_side, mut peer) = UnixStream::pair().unwrap();
        // A 0x40 frame with a garbage envelope → handle_agent_gateway_frame returns a 0x40-BAND error body
        // (proves decode → 0x40 guard → handler → reframe → write WITHOUT panic). The SUCCESS-body compute
        // is covered by agent_dispatch's own PUBLIC_IDENTITY tests; the serve loop's job is transport+reframe.
        (&peer).write_all(&agent_frame(&[0xff, 0xff])).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        crate::enclave_serve::serve_framed_pump(
            &mut relay_side,
            agent_serve_one_frame,
            crate::enclave_serve::SESSION_IDLE_TIMEOUT,
        )
        .expect("clean close after the reply");
        let reply = read_reply(&mut peer);
        assert_eq!(
            reply.msg_type,
            crate::MessageType::AgentGateway,
            "reply must be 0x40-typed"
        );
        assert!(
            crate::agent_dispatch::decode_agent_error_code(&reply.payload).is_some(),
            "a garbage 0x40 frame must round-trip to an agent error body"
        );
    }

    #[test]
    fn serve_non_0x40_frame_closes_silently() {
        use std::io::Read as _;
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let (mut relay_side, mut peer) = UnixStream::pair().unwrap();
        // A GET_STATUS frame on the 0x40-only serve port → agent_serve_one_frame returns Err → the pump
        // faults → the connection closes with ZERO bytes back (never synthesizes an agent body).
        (&peer)
            .write_all(&crate::encode_message(crate::MessageType::GetStatus, &[0xa0]).unwrap())
            .unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let r = crate::enclave_serve::serve_framed_pump(
            &mut relay_side,
            agent_serve_one_frame,
            crate::enclave_serve::SESSION_IDLE_TIMEOUT,
        );
        assert!(
            r.is_err(),
            "a non-0x40 frame faults the pump (close-silently)"
        );
        let mut back = Vec::new();
        let _ = peer.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = peer.read_to_end(&mut back);
        assert!(
            back.is_empty(),
            "wrong-type frame: ZERO bytes written back; got {back:?}"
        );
    }

    #[test]
    fn serve_eof_closes_cleanly() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let (mut relay_side, peer) = UnixStream::pair().unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        crate::enclave_serve::serve_framed_pump(
            &mut relay_side,
            agent_serve_one_frame,
            crate::enclave_serve::SESSION_IDLE_TIMEOUT,
        )
        .expect("immediate EOF → Ok(())");
    }

    #[test]
    fn serve_oversize_prefix_closes_without_reply() {
        use std::io::Read as _;
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let (mut relay_side, mut peer) = UnixStream::pair().unwrap();
        // A 4-byte len prefix claiming > MAX_MESSAGE_SIZE, then nothing → MessageTooLarge → break → Ok(()).
        (&peer)
            .write_all(&(crate::MAX_MESSAGE_SIZE + 1).to_be_bytes())
            .unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        crate::enclave_serve::serve_framed_pump(
            &mut relay_side,
            agent_serve_one_frame,
            crate::enclave_serve::SESSION_IDLE_TIMEOUT,
        )
        .expect("oversize prefix → break → Ok(())");
        let mut back = Vec::new();
        let _ = peer.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = peer.read_to_end(&mut back);
        assert!(
            back.is_empty(),
            "oversize prefix: nothing written back; got {back:?}"
        );
    }

    #[test]
    fn serve_multi_frame_on_one_connection() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let (mut relay_side, mut peer) = UnixStream::pair().unwrap();
        (&peer).write_all(&agent_frame(&[0xff, 0xff])).unwrap();
        (&peer).write_all(&agent_frame(&[0xfe, 0xfe])).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        crate::enclave_serve::serve_framed_pump(
            &mut relay_side,
            agent_serve_one_frame,
            crate::enclave_serve::SESSION_IDLE_TIMEOUT,
        )
        .expect("clean close after two replies");
        assert_eq!(
            read_reply(&mut peer).msg_type,
            crate::MessageType::AgentGateway
        );
        assert_eq!(
            read_reply(&mut peer).msg_type,
            crate::MessageType::AgentGateway
        );
    }

    #[test]
    fn serve_loop_close_and_continue_resilience() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        // bad conn = a non-0x40 frame (faults + closes); good conn = a valid 0x40 (served). Pins that the
        // serial loop's handle_agent_accepted body keeps serving after a per-connection fault.
        let (bad, bad_peer) = UnixStream::pair().unwrap();
        (&bad_peer)
            .write_all(&crate::encode_message(crate::MessageType::GetStatus, &[0xa0]).unwrap())
            .unwrap();
        bad_peer.shutdown(std::net::Shutdown::Write).unwrap();
        let (good, mut good_peer) = UnixStream::pair().unwrap();
        (&good_peer).write_all(&agent_frame(&[0xff, 0xff])).unwrap();
        good_peer.shutdown(std::net::Shutdown::Write).unwrap();
        drive_agent_serve_finite(vec![Ok(bad), Ok(good)].into_iter(), no_prepare);
        assert_eq!(
            read_reply(&mut good_peer).msg_type,
            crate::MessageType::AgentGateway
        );
    }

    #[test]
    fn serve_loop_accept_error_backoff_does_not_escalate() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let (good, mut good_peer) = UnixStream::pair().unwrap();
        (&good_peer).write_all(&agent_frame(&[0xff, 0xff])).unwrap();
        good_peer.shutdown(std::net::Shutdown::Write).unwrap();
        // An accept Err (EMFILE) is logged + backed-off (ACCEPT_ERROR_BACKOFF), NEVER escalated; the next
        // accepted connection still serves.
        let incoming: Vec<std::io::Result<UnixStream>> =
            vec![Err(std::io::Error::from_raw_os_error(24)), Ok(good)];
        drive_agent_serve_finite(incoming.into_iter(), no_prepare);
        assert_eq!(
            read_reply(&mut good_peer).msg_type,
            crate::MessageType::AgentGateway
        );
    }

    #[test]
    fn agent_error_body_is_wire_error_classified_for_idle_reset() {
        // The kernel's idle-reset predicate (is_wire_error_payload) must classify an agent-error body as an
        // error so a dribbling error-er can't extend the 300s idle budget. A future agent SUCCESS body using
        // {1:Integer, 2:Text} would be misclassified — re-audit this if the success shape changes.
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let err_body = crate::agent_dispatch::handle_agent_gateway_frame(&[0xff, 0xff]);
        assert!(
            crate::is_wire_error_payload(&err_body),
            "an agent-error body must be wire-error-classified (no idle reset)"
        );
    }

    /// END-TO-END the pump's idle-reset DECISION (`reply_resets_idle`) in BOTH directions over real framed
    /// replies — the ERROR-only classifier test above pins one half; this pins that a SUCCESS reply EXTENDS
    /// the budget. Without the positive half, a regression that flipped/dropped the kernel's `!` (resetting
    /// idle on errors — re-opening the slowloris hole) would pass every other test. (A future agent SUCCESS
    /// body shaped `{1:Integer, 2:Text}` would now FAIL here loudly, not regress silently.)
    #[test]
    fn reply_extends_idle_on_success_not_on_error() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        // ERROR reply (a garbage 0x40 → the agent error band `{1:Integer, 2:Text}`) must NOT extend idle.
        let err_frame = agent_frame(&crate::agent_dispatch::handle_agent_gateway_frame(&[
            0xff, 0xff,
        ]));
        assert!(
            !crate::enclave_serve::reply_resets_idle(&err_frame),
            "an agent-error reply must NOT reset the idle deadline"
        );
        // SUCCESS reply (key 1 = Bytes, the PUBLIC_IDENTITY / PROVE_IDENTITY success shape) MUST extend it.
        let mut success_body = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Bytes(vec![0u8; 65]),
            )]),
            &mut success_body,
        )
        .unwrap();
        let success_frame = agent_frame(&success_body);
        assert!(
            crate::enclave_serve::reply_resets_idle(&success_frame),
            "a non-error reply (key 1 = Bytes) MUST reset the idle deadline"
        );
    }

    /// The pump CONSULTS the idle deadline: with a ZERO idle budget (already exhausted at entry) it breaks on
    /// the FIRST read — `Instant::now() >= deadline` — BEFORE processing the buffered 0x40 frame, returning
    /// `Ok(())` with ZERO bytes back. A regression that ignored the deadline would instead read + reply, so
    /// this guards the slowloris bound's enforcement (the deviceless suite cannot drive a real wall-clock
    /// expiry; the live 300s budget is exercised by the aya/SNP smoke).
    #[test]
    fn serve_pump_respects_expired_idle_deadline() {
        use std::io::Read as _;
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let (mut relay_side, mut peer) = UnixStream::pair().unwrap();
        (&peer).write_all(&agent_frame(&[0xff, 0xff])).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        crate::enclave_serve::serve_framed_pump(
            &mut relay_side,
            agent_serve_one_frame,
            Duration::ZERO,
        )
        .expect("an exhausted idle budget breaks before reading → Ok(())");
        let mut back = Vec::new();
        let _ = peer.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = peer.read_to_end(&mut back);
        assert!(
            back.is_empty(),
            "expired idle: nothing read or replied; got {back:?}"
        );
    }

    /// A per-stream `prepare` (SO_*TIMEO arming) failure on ONE accepted stream is logged as a stream-setup
    /// fault and SKIPPED — the loop keeps serving (the NEXT stream replies). Covers the prod arming seam
    /// (`configure_vsock_session_timeouts`) the device-bound `run_agent_serve_loop` owns but the deviceless
    /// suite otherwise never drives, AND that an arm fault is never mislabeled/escalated.
    #[test]
    fn serve_loop_stream_setup_failure_skips_and_continues() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        install_serving_state();
        let (first, _first_peer) = UnixStream::pair().unwrap();
        let (second, mut second_peer) = UnixStream::pair().unwrap();
        (&second_peer)
            .write_all(&agent_frame(&[0xff, 0xff]))
            .unwrap();
        second_peer.shutdown(std::net::Shutdown::Write).unwrap();
        // `prepare` fails for the FIRST accepted stream (a deviceless stand-in for a setsockopt arm failure),
        // then succeeds — the loop must skip the first and still serve the second.
        let mut first_seen = false;
        drive_agent_serve_finite(
            vec![Ok(first), Ok(second)].into_iter(),
            |_: &mut UnixStream| {
                if !first_seen {
                    first_seen = true;
                    return Err(ProtocolError::WireProtocol(
                        "test: forced stream setup failure",
                    ));
                }
                Ok(())
            },
        );
        assert_eq!(
            read_reply(&mut second_peer).msg_type,
            crate::MessageType::AgentGateway,
            "the serial loop keeps serving after a per-stream setup failure"
        );
    }

    /// Pin the calm-vs-warn boundary: EVERY decode/route reject a peer can trip pre-auth (misroute, bad
    /// version, unknown type, too-short frame) is classified calm (no [warn] flood lever); genuine
    /// transport/write faults and our own oversize stay warn.
    #[test]
    fn peer_protocol_rejects_are_calm_genuine_faults_are_not() {
        use std::io::{Error as IoError, ErrorKind};
        assert!(is_peer_protocol_reject(&ProtocolError::WireProtocol(
            "non-0x40"
        )));
        assert!(is_peer_protocol_reject(&ProtocolError::InvalidVersion {
            got: 9,
            expected: 1
        }));
        assert!(is_peer_protocol_reject(&ProtocolError::UnknownMessageType(
            0x77
        )));
        assert!(is_peer_protocol_reject(&ProtocolError::Io(IoError::new(
            ErrorKind::UnexpectedEof,
            "frame too short"
        ))));
        // Genuine transport/write faults and our own MessageTooLarge are NOT calm — they warrant [warn].
        assert!(!is_peer_protocol_reject(&ProtocolError::Io(IoError::new(
            ErrorKind::ConnectionReset,
            "reset"
        ))));
        assert!(!is_peer_protocol_reject(&ProtocolError::Io(IoError::new(
            ErrorKind::BrokenPipe,
            "epipe"
        ))));
        assert!(!is_peer_protocol_reject(&ProtocolError::MessageTooLarge(1)));
    }
}
