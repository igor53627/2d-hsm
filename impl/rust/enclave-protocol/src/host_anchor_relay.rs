//! (b) HOST-RELAY DAEMON (TASK-7.7 5b-2b-ii(b)) — the UNTRUSTED host-side process that bridges the
//! SNP guest to the external anchor (notary) over TCP.
//!
//! Triple-gated `all(target_os = "linux", feature = "vsock-transport", feature = "agent-gateway")`:
//! the cfg-INTERSECTION of the vsock leaf (`linux` + `vsock-transport`, for `vsock_listen::bind`)
//! and the agent-gateway cores (`relay_forward_once` lives in the agent-gateway-gated
//! [`crate::agent_boot_relay`]). NEVER wider (§8 hard rule) — same intersection-gate discipline as
//! `quote_subprocess` / `agent_gateway_boot`.
//!
//! ## What this is — transport ONLY
//! Binds AF_VSOCK (`VMADDR_CID_ANY`, the relay port), accepts enclave-initiated connections SERIALLY,
//! dials the anchor with a bounded TCP `connect_timeout`, forwards the boot-relay request VERBATIM via
//! the existing `pub(crate)` [`crate::agent_boot_relay::relay_forward_once`] core (ZERO codec
//! duplication), and CLOSES-ON-ANY-FAULT. It NEVER synthesizes or alters bytes, and NEVER dies in the
//! loop — every per-connection fault is `log + close + serve next`.
//!
//! ## Scope honesty (§12 — the #59-#63 lesson)
//! (b) carries NO ε, NO `HardBoundedQuoteProducer`, NO `ValidatedBootBudget`, NO budget arithmetic, NO
//! SNP quote, NO nonce/challenge issuance, NO Ed25519 verify, NO reconcile/AdoptForward, NO trust
//! boundary, NO concurrency (serial loop), NOT the 5b-2c bin/serve loop. The relay is in the threat
//! model as an attacker: it can drop/delay/corrupt bytes but cannot forge a Fresh — the enclave
//! strict-decodes + Ed25519-verifies the response against its sealed `anchor_root` + issued nonce. The
//! daemon's job is "transport, never trust + never a SILENT black hole (bounded + logged)".
//! `never-synth` is a BEHAVIORAL property (RAII close + the absence of any error-path write — tests 2,
//! 6, 9), NOT a type-level/structural guarantee. The [`AnchorDial`] seam advertises forward-compat the
//! code does NOT exercise (one TCP impl ships) — UDS is documented, NOT built. `relay ⊇ anchor` is a
//! cross-component sync OBLIGATION (Risk #1 in the design), not a present fact.

use crate::agent_boot_relay::{
    deadline_guarded_write, decode_anchor_boot_request, decode_anchor_marks_request,
    frame_response_cap, relay_round_trip_over_stream_cap, MAX_ANCHOR_RESPONSE_LEN,
    MAX_MARKS_RESPONSE_LEN,
};
use crate::enclave_serve::ACCEPT_ERROR_BACKOFF;
use crate::vsock_addr::{self, DEFAULT_VSOCK_CID};
use crate::vsock_listen;
use crate::ProtocolError;
use std::io::Write; // for `writeln!` into `std::io::stderr()` in `emit_log` + the enclave write-back
use std::time::Duration;

// ---------------------------------------------------------------------------------------------------
// Budget consts — single source, NO new operator knob (§8 L1443-1447 + design §5).
// ---------------------------------------------------------------------------------------------------

/// Per-pump HEAD-OF-LINE bound (NOT the boot bound — the enclave owns `max_attempts·(2·timeout+ε)`;
/// this daemon carries NO ε, NO producer, NO budget arithmetic). Prevents a wedged pump from blocking
/// the serial loop forever. One absolute `Instant` minted at PUMP ENTRY — i.e. BEFORE the enclave read
/// (the natural consequence of reading the request before connecting) — spans the whole framed pump
/// (enclave-read + connect + anchor-forward + write-back); the connect leg is ADDITIONALLY clamped to
/// `min(connect_budget(), remaining-deadline)`. Both legs' `SO_RCVTIMEO`/`SO_SNDTIMEO` are armed to this.
/// Sized to comfortably cover a single boot-relay round-trip to a LAN anchor.
const PUMP_BUDGET: Duration = Duration::from_secs(10);

/// Divisor deriving the connect budget from [`PUMP_BUDGET`] — the §8 "connect/socket budget DERIVED
/// from the per-leg Duration, not a separate knob" rule applied host-side. Connect is bounded by
/// NEITHER `SO_*TIMEO` NOR `relay_forward_once`'s in-fn deadline (which operates on already-connected
/// streams), so it needs its own explicit bound: the critical guard against a BLACK-HOLING anchor
/// wedging the whole daemon on `connect`.
const CONNECT_BUDGET_DIVISOR: u32 = 4;

/// Floor for the derived connect budget so a small `PUMP_BUDGET` can never derive a sub-millisecond
/// (effectively zero) connect timeout. Checked/saturating arithmetic only — no panics.
const CONNECT_BUDGET_MIN: Duration = Duration::from_millis(500);

/// Anchor-facing connect bound = `PUMP_BUDGET / CONNECT_BUDGET_DIVISOR`, floored at
/// [`CONNECT_BUDGET_MIN`]. `checked_div` guards the (compile-time-impossible-but-defensive) zero
/// divisor; `max` applies the floor. Pure const-fold; never panics.
fn connect_budget() -> Duration {
    let derived = PUMP_BUDGET
        .checked_div(CONNECT_BUDGET_DIVISOR)
        .unwrap_or(CONNECT_BUDGET_MIN);
    derived.max(CONNECT_BUDGET_MIN)
}

// Accept-error backoff (EMFILE/ENFILE anti-spin) is the SINGLE SHARED
// `crate::enclave_serve::ACCEPT_ERROR_BACKOFF` (imported above) — the SAME value the agent serve loop
// uses, so the two serial accept loops can never silently diverge. See its doc for the rationale.

// ---------------------------------------------------------------------------------------------------
// The AnchorDial seam — the transport quarantine (design §2).
// ---------------------------------------------------------------------------------------------------

/// Dial the external anchor with a HARD connect bound, returning a connected, BLOCKING-mode duplex
/// stream on which the daemon then arms `SO_RCVTIMEO`/`SO_SNDTIMEO` per pump. ONE method. The connect
/// bound is TRANSPORT-CONDITIONAL and lives ENTIRELY in the impl — the accept loop never sees connect
/// semantics, so a second transport drops in WITHOUT reopening the loop. (FORWARD-COMPAT the code does
/// NOT exercise: exactly one impl, [`TcpAnchorDial`], ships — the seam is a documented quarantine for a
/// FUTURE UDS impl, never a present structural claim. Collapse fallback if review prefers zero
/// abstraction: a bare `dial_anchor_tcp` free fn — low-cost either way, Risk #2.)
///
/// NEVER reuse `connect_bounded` (the vsock-only EINPROGRESS→poll(POLLOUT)→SO_ERROR→set_nonblocking
/// path): it is the WRONG shape off vsock.
///   - TCP (the only impl shipped): std `TcpStream::connect_timeout` does the whole
///     nonblock→poll→SO_ERROR→restore-blocking dance internally — no `nix`, no `unsafe`, clean under
///     `#![forbid(unsafe_code)]`.
///   - A FUTURE UDS impl (documented, NOT built): a would-block AF_UNIX connect returns `EAGAIN` (NOT
///     `EINPROGRESS`), so the `poll(POLLOUT)` finish sequence is wrong; treat `EAGAIN` as a retryable
///     per-pump fail-fast (= this pump failed → serve next; backlog pressure surfaces as a per-pump
///     retry, not a daemon-level failure). It MUST still do the `getsockopt(SO_ERROR)` +
///     `set_nonblocking(false)` restore a naive copy of `connect_bounded` drops — which is exactly why
///     UDS would be its OWN impl, never folded into the loop.
pub(crate) trait AnchorDial {
    type Stream: std::io::Read + std::io::Write;
    /// Connect with a HARD upper bound expressed as an ABSOLUTE `connect_deadline`: the impl tries each
    /// resolved address against the budget REMAINING until that instant, so the CUMULATIVE connect across
    /// ALL addresses is bounded by ONE connect budget (never N×budget for a multi-A/dual-stack name) and
    /// never overruns the caller's whole-pump deadline. The deadline is derived from a fraction of the
    /// per-pump budget (the §8 shared-source rule), never a separate operator knob.
    fn dial(&self, connect_deadline: std::time::Instant) -> std::io::Result<Self::Stream>;
    /// Operator-facing endpoint label for the startup log (no secrets — a host:port).
    fn endpoint_display(&self) -> String;
}

/// Arm `SO_RCVTIMEO`/`SO_SNDTIMEO` on an anchor stream after connect. Default impl is a no-op so the
/// deviceless `FakeAnchorDial` (whose fake stream has no socket options) is exercised without it; the
/// shipped [`TcpAnchorDial`] overrides it to arm the real `TcpStream`. Failure to arm folds into the
/// `AnchorConnect` fault class (logged + close).
pub(crate) trait ArmAnchorTimeouts {
    fn arm(&mut self, _budget: Duration) -> std::io::Result<()> {
        Ok(())
    }
}

/// The TCP anchor dialer — the ONE impl that ships. No `nix`, no `unsafe`, no poll-sequence copy.
pub(crate) struct TcpAnchorDial {
    /// Resolved ONCE at startup from [`vsock_addr::anchor_endpoint_from_env`] — no per-pump DNS.
    addrs: Vec<std::net::SocketAddr>,
}

impl AnchorDial for TcpAnchorDial {
    type Stream = std::net::TcpStream;

    fn dial(&self, connect_deadline: std::time::Instant) -> std::io::Result<std::net::TcpStream> {
        // Try each resolved addr against the budget REMAINING until the shared connect deadline — so the
        // CUMULATIVE connect across ALL addrs is bounded by ONE connect budget (a multi-A / dual-stack
        // black-holing anchor can NOT multiply the head-of-line bound to N×budget) and never overruns the
        // whole-pump deadline. std connect_timeout does the whole nonblock→poll→SO_ERROR→restore dance
        // internally and returns a BLOCKING stream. NO nix, NO unsafe, NO poll-sequence copy.
        let mut last: Option<std::io::Error> = None;
        for addr in &self.addrs {
            let remaining = connect_deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                // Connect budget spent across prior addrs (or the pump deadline already lapsed). Surface a
                // TimedOut so classify_close labels it "anchor-connect-timeout". (connect_timeout(0) itself
                // errors — we must never call it with a zero Duration, hence the break.)
                last.get_or_insert_with(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "anchor connect budget exhausted")
                });
                break;
            }
            // Floor the per-attempt timeout at 1ms: a sub-millisecond remainder must never round DOWN to a
            // zero/disabled connect timeout (the "zero-timeout trap" → infinite block). The <1ms slop on the
            // LAST attempt is negligible vs the connect budget. (is_zero() above already handled exact 0.)
            let attempt = remaining.max(Duration::from_millis(1));
            match std::net::TcpStream::connect_timeout(addr, attempt) {
                Ok(s) => {
                    s.set_nodelay(true)?; // one small frame each way — latency over throughput
                    return Ok(s);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no anchor addrs")
        }))
    }

    fn endpoint_display(&self) -> String {
        self.addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl ArmAnchorTimeouts for std::net::TcpStream {
    fn arm(&mut self, budget: Duration) -> std::io::Result<()> {
        // std TcpStream maps these to SO_RCVTIMEO/SO_SNDTIMEO — no `nix` on the anchor leg. (Contrast
        // the vsock leg, whose enclave-side timeouts use `vsock::VsockStream::set_*_timeout`.)
        self.set_read_timeout(Some(budget))?;
        self.set_write_timeout(Some(budget))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------
// Fault triage — RelayFault + classify_close (design §4). LOG-ONLY: every arm closes; the enum exists
// PURELY for the §8 operator-triage taxonomy, NEVER for behavioral branching or wire behavior.
// ---------------------------------------------------------------------------------------------------

/// Daemon-local fault enum. NOT for behavioral branching — EVERY arm closes the connection. It exists
/// PURELY for the §8-mandated operator triage taxonomy (the boot log MUST distinguish relay-timeout /
/// anchor-unavailable / oversized / malformed).
enum RelayFault {
    /// Dial / connect-timeout / SO_*TIMEO-arm failed → anchor-unavailable / anchor-connect-timeout.
    AnchorConnect(std::io::Error),
    /// `relay_forward_once` Err — classified for the log by [`classify_close`] (§4a). The core folds a
    /// deadline lapse into `WireProtocol(..)` too (its name "reads as malformed but is a timeout") —
    /// behavior is identical (close); only the LOG LABEL differs.
    Pump(ProtocolError),
}

impl RelayFault {
    /// The §8 operator-triage label for the log line. Pure; LOG-ONLY (never drives wire behavior).
    fn triage_label(&self) -> &'static str {
        classify_close(self)
    }
}

/// A log-ONLY classifier mapping a [`RelayFault`] to one of the §8 operator-triage buckets. CRITICAL:
/// it classifies for the LOG; it NEVER drives wire behavior (the wire behavior is uniform close).
/// Typed-first (variant-matched, robust), then substring ONLY for the `WireProtocol`-folded cases the
/// cores deliberately collapse (no distinct variant exists — the message text is the sole
/// discriminator). Substring buckets are PINNED by test 8 against core message wording drift (Risk #7).
fn classify_close(fault: &RelayFault) -> &'static str {
    match fault {
        RelayFault::AnchorConnect(e) => match e.kind() {
            std::io::ErrorKind::TimedOut => "anchor-connect-timeout",
            _ => "anchor-unavailable", // refused / unreachable / arm-failed
        },
        RelayFault::Pump(pe) => match pe {
            // Typed-first: an OVERSIZE ENCLAVE request frame surfaces as the TYPED
            // ProtocolError::MessageTooLarge(u32) from read_framed_message_with_idle_deadline (verified
            // lib.rs:291, 1732) — NOT a WireProtocol string. Match the variant directly.
            ProtocolError::MessageTooLarge(_) => "oversized-request-frame",
            ProtocolError::Io(e) => match e.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "socket-timeout",
                std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset => "peer-closed",
                _ => "io-error",
            },
            // Substring ONLY for the WireProtocol-folded cases (the cores deliberately fold timeout into
            // WireProtocol — no distinct variant; substring is the ONLY discriminator). Pinned by test 8.
            ProtocolError::WireProtocol(m) if m.contains("anchor response too large") => {
                "oversized-anchor-response"
            }
            ProtocolError::WireProtocol(m) if m.contains("deadline") => "pump-timeout",
            ProtocolError::WireProtocol(m) if m.contains("boot request") => "malformed-request",
            _ => "relay-error",
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Logging seam — RelayEvent + Display + emit_log. HARD house rule: `let _ = writeln!`, NEVER eprintln!
// (design §4b). Under the SERIAL loop, an eprintln! panic on broken stderr would KILL the daemon
// (contradicting "never die"). Verified house contract: agent_gateway_boot.rs:186-191.
// ---------------------------------------------------------------------------------------------------

/// One-line-per-connection, oracle-free operator log shape (mirrors `AgentBootEvent`'s `Display`).
/// There is NO serve API here; the daemon's only output is its own stderr log, so the labels carry the
/// §8 observability distinction WITHOUT leaking oracle-grade detail.
enum RelayEvent {
    /// Startup: the daemon bound the relay port and resolved the anchor endpoint.
    Listening { port: u32, anchor: String },
    /// `incoming()` yielded an accept error (rare for vsock; logged + skipped — NEVER fatal).
    AcceptError { kind: std::io::ErrorKind },
    /// A pump completed the full enclave↔anchor round-trip; the verbatim response was written back.
    PumpOk,
    /// A pump faulted; `label` is the §8 operator-triage bucket. Connection closed; loop continues.
    PumpFault { label: &'static str },
}

impl std::fmt::Display for RelayEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listening { port, anchor } => {
                write!(f, "host-anchor-relay: listening on vsock relay port {port}, anchor {anchor}")
            }
            Self::AcceptError { kind } => {
                write!(f, "host-anchor-relay: accept error ({kind:?}); skipping")
            }
            Self::PumpOk => write!(f, "host-anchor-relay: pump ok"),
            Self::PumpFault { label } => write!(f, "host-anchor-relay: pump fault ({label})"),
        }
    }
}

/// Best-effort, non-panicking log sink. A broken stderr must NEVER kill the serve loop — so this is
/// `let _ = writeln!`, NOT `eprintln!` (which panics on broken stderr). HARD house rule (§4b): this is
/// the LIBRARY per-pump sink; the BIN's pre-serve `run()` startup path MAY use `eprintln!`.
fn emit_log(ev: &RelayEvent) {
    let _ = writeln!(std::io::stderr(), "{ev}");
}

// ---------------------------------------------------------------------------------------------------
// The single pump (design §3c) — read+decode-BEFORE-dial → connect-bound → arm → forward verbatim →
// write back. Every Err = close + serve next. ZERO codec duplication: the request reader
// (`read_framed_message_with_idle_deadline`), the decoder (`decode_anchor_boot_request`), the
// anchor-side forward (`relay_round_trip_over_stream`), and the response framer (`frame_anchor_response`)
// are ALL reused verbatim from the `pub(crate)` cores; the daemon adds only the orchestration.
//
// DEVIATION FROM DESIGN §3c (justified — the design is internally inconsistent here): the design's §3c
// pump dials FIRST, then calls `relay_forward_once` (which reads+decodes the request internally). But
// deviceless test 2 (`malformed_enclave_request_rejects_before_dial`) ASSERTS `FakeAnchorDial::dial`
// is NEVER invoked (call-count == 0) for a malformed request — which the dial-first ordering cannot
// satisfy (the connect happens before the decode). `relay_forward_once`'s "reject-before-round-trip"
// means no anchor WRITE, NOT no connect. Resolving in favour of the explicit, stronger test contract:
// read+decode the request in the daemon FIRST (reusing the SAME core reader+decoder — not a codec
// dup), and only dial+forward on a valid request. This is strictly better (a malformed enclave frame
// never burns a TCP connect) AND keeps the distinct connect-fault classification tests 3/4 require (a
// dial failure stays an `AnchorConnect`, never folded into the forward's `Io`). The forward itself is
// the verbatim `relay_round_trip_over_stream` core (the anchor write+bounded-read), and the write-back
// uses the shared `frame_anchor_response` writer — so the request/response WIRE is wholly core-owned.
// ---------------------------------------------------------------------------------------------------

/// One enclave↔anchor pump. ONE absolute pump deadline spans enclave-read + connect + anchor-forward +
/// write-back; the connect leg is ADDITIONALLY capped by [`connect_budget`] AND clamped to the remaining
/// pump deadline (`min` of the two) — so connect is the head-of-line guard against a black-holing anchor
/// (§8: NOT covered by the cores' in-fn deadline, which operates on already-connected streams) yet can
/// never push the pump past PUMP_BUDGET, even for a MULTI-ADDRESS endpoint (the cumulative connect across
/// ALL resolved addrs is one connect_budget, never N×). Both legs' `SO_RCVTIMEO`/`SO_SNDTIMEO` are armed
/// to [`PUMP_BUDGET`] (the in-fn guards only bound *initiating* a write; an in-flight blocking write is
/// bounded only by `SO_SNDTIMEO` — the cores' docstring mandate). Once-per-pump arming is sufficient (the
/// pump is ONE round-trip; a syscall starting late overruns by at most one socket-timeout — Risk #3).
fn relay_one_pump<E, D>(enclave: &mut E, dial: &D) -> Result<(), RelayFault>
where
    E: std::io::Read + std::io::Write,
    D: AnchorDial,
    D::Stream: ArmAnchorTimeouts,
{
    // One absolute deadline for the WHOLE pump. Minting it up front (vs the design's "after connect") is
    // the natural consequence of reading the enclave frame before connecting — and is correct: the
    // connect below is clamped to BOTH connect_budget() AND this deadline, and the whole pump is
    // head-of-line-bounded by PUMP_BUDGET.
    relay_one_pump_until(enclave, dial, std::time::Instant::now() + PUMP_BUDGET)
}

/// [`relay_one_pump`] with the pump `deadline` INJECTED — the one piece of pump nondeterminism, factored
/// out so the deviceless suite can drive a GENUINELY-lapsed deadline (test `lapsed_deadline_pump_*`)
/// rather than only the EOF/empty-response path. Production always enters via [`relay_one_pump`]
/// (deadline = now + PUMP_BUDGET); nothing else constructs a deadline.
fn relay_one_pump_until<E, D>(
    enclave: &mut E,
    dial: &D,
    deadline: std::time::Instant,
) -> Result<(), RelayFault>
where
    E: std::io::Read + std::io::Write,
    D: AnchorDial,
    D::Stream: ArmAnchorTimeouts,
{
    // 1. Read the enclave request frame, then PEEK the type + DECODE-VALIDATE it BEFORE dialing —
    //    reject a malformed request before spending a TCP connect (defense-in-depth; test 2 pins
    //    dial-never-called). Both the reader and the decoders are the verbatim `pub(crate)` cores (no
    //    codec dup). 5b-2e: the relay now serves TWO enclave-initiated legs — 0x41 freshness (quote +
    //    cert) and 0x44 raw-marks (no quote) — each with its OWN decoder + response cap, so neither
    //    decoder straddles two grammars. An unknown/other type fails closed.
    let frame = crate::read_framed_message_with_idle_deadline(enclave, Some(deadline))
        .map_err(RelayFault::Pump)?;
    let response_cap = match crate::peek_msg_type_from_frame(&frame) {
        Some(crate::MessageType::AgentBootRelay) => {
            decode_anchor_boot_request(&frame).map_err(RelayFault::Pump)?;
            MAX_ANCHOR_RESPONSE_LEN
        }
        Some(crate::MessageType::AgentAnchorMarksRelay) => {
            decode_anchor_marks_request(&frame).map_err(RelayFault::Pump)?;
            MAX_MARKS_RESPONSE_LEN
        }
        _ => {
            return Err(RelayFault::Pump(ProtocolError::WireProtocol(
                "anchor relay: only AGENT_BOOT_RELAY (0x41) / AGENT_ANCHOR_MARKS_RELAY (0x44) are forwardable",
            )))
        }
    };

    // 2. Request is well-formed → dial the anchor under the hard connect bound (distinct AnchorConnect
    //    classification — tests 3/4). The connect leg shares ONE budget across ALL resolved addrs
    //    (connect_budget(), the §8 derived sub-budget) AND never overruns the pump deadline — min() of
    //    the two — so a black-holing anchor (even multi-A / dual-stack) is wedged-bounded HERE to
    //    ≤ connect_budget(), never on the loop and never past PUMP_BUDGET.
    let connect_deadline = (std::time::Instant::now() + connect_budget()).min(deadline);
    let mut anchor = dial.dial(connect_deadline).map_err(RelayFault::AnchorConnect)?;

    // 3. Arm SO_RCVTIMEO/SO_SNDTIMEO on the anchor leg (the enclave leg is armed at the concrete
    //    boundary in run_host_anchor_relay — design §3d). Arm failure folds into AnchorConnect (close).
    anchor.arm(PUMP_BUDGET).map_err(RelayFault::AnchorConnect)?;

    // 4. Forward the ALREADY-READ frame verbatim and read the bounded (4096 cap-before-alloc) response
    //    — the verbatim `relay_round_trip_over_stream` core (deadline-guarded anchor write +
    //    read_bounded_anchor_response). ZERO codec dup. `anchor` drops at fn return (fresh-conn-per-
    //    pump; stale-reply + cross-pump isolation — mirrors the enclave's documented fresh-conn-per-call).
    let response = relay_round_trip_over_stream_cap(&mut anchor, &frame, deadline, response_cap)
        .map_err(RelayFault::Pump)?;

    // 5. Frame the response with the SHARED `frame_anchor_response` writer (so writer↔reader can't drift
    //    on BE/prefix) and write it back to the enclave via the SAME `deadline_guarded_write` the reused
    //    `relay_forward_once` core uses for this identical leg — so a budget that lapsed during the
    //    round-trip never even INITIATES the enclave write (core-symmetric; the per-pump bound the rest of
    //    the function maintains now holds on the last leg too, not just SO_SNDTIMEO). This is the ONLY
    //    enclave write anywhere — on EVERY fault above the fn returned Err BEFORE reaching here, so the
    //    enclave stream received ZERO anchor-looking bytes (the never-synth behavioral invariant; tests
    //    2/5/6/9 + lapsed_deadline_pump_never_synth).
    let wire = frame_response_cap(&response, response_cap).map_err(RelayFault::Pump)?;
    deadline_guarded_write(enclave, &wire, deadline, "anchor relay: deadline before enclave write")
        .map_err(RelayFault::Pump)?;
    Ok(())
}

/// THE shared one-pump-and-log body — driven by BOTH the production `Infallible` loop and the
/// `#[cfg(test)]` finite twin, so the tested code path and the prod code path are the SAME statements
/// (no `cfg(test)` drift). RAII: `enclave` drops at the caller's loop edge — Err→close, fresh accept
/// starts a fresh frame (no desync; never-synth holds).
fn pump_one_and_log<E, D>(enclave: &mut E, dial: &D)
where
    E: std::io::Read + std::io::Write,
    D: AnchorDial,
    D::Stream: ArmAnchorTimeouts,
{
    match relay_one_pump(enclave, dial) {
        Ok(()) => emit_log(&RelayEvent::PumpOk),
        Err(fault) => emit_log(&RelayEvent::PumpFault { label: fault.triage_label() }),
    }
}

/// Handle ONE accepted item — the body BOTH the production `Infallible` loop and the `#[cfg(test)]`
/// finite twin share, so the accept-error backoff + the pump path are the SAME statements (no `cfg(test)`
/// drift, and the EMFILE/ENFILE anti-spin guard can't be added to one loop but forgotten in the other).
/// `Ok` → pump+log; `Err` → log + bounded [`ACCEPT_ERROR_BACKOFF`] (so a persistent immediate accept
/// error can't tight-spin a core). RAII: the accepted `enclave` (and the anchor inside the pump) drop at
/// this fn's return — Err→close, the next accept starts a fresh frame (no desync; never-synth holds).
fn handle_accepted<E, D>(accepted: std::io::Result<E>, dial: &D)
where
    E: std::io::Read + std::io::Write,
    D: AnchorDial,
    D::Stream: ArmAnchorTimeouts,
{
    match accepted {
        Ok(mut enclave) => pump_one_and_log(&mut enclave, dial),
        Err(e) => {
            emit_log(&RelayEvent::AcceptError { kind: e.kind() });
            // EMFILE/ENFILE fails accept(2) IMMEDIATELY without draining the backlog → a bare continue
            // would busy-loop. Back off to cap the retry rate; the daemon still NEVER dies.
            std::thread::sleep(ACCEPT_ERROR_BACKOFF);
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The serial accept loop (design §3b) + the cfg(test) finite twin. Both loop the SAME `handle_accepted`
// body — no drift. The pub loop's `Infallible` return documents AT THE TYPE LEVEL that it never
// returns Ok (per-connection faults never escape); the production VsockListener::incoming() is
// infinite so the `for` never exits.
// ---------------------------------------------------------------------------------------------------

/// Serial accept loop. Generic over the accepted stream type (`vsock::VsockStream` in prod, a
/// `UnixStream` half in deviceless tests — the cores are already generic over Read+Write) and the
/// dialer. NEVER returns: per-connection faults are logged + skipped (close + serve next). Iterator
/// exhaustion is NOT reachable for `VsockListener::incoming()` (it never yields None), so the closing
/// `unreachable!` is genuinely unreachable in production; the finite-test path uses
/// [`drive_relay_loop_finite`] instead (same body), so the `unreachable!` is never reached in tests.
fn serve_anchor_relay_loop<I, E, D>(incoming: I, dial: &D) -> std::convert::Infallible
where
    I: Iterator<Item = std::io::Result<E>>,
    E: std::io::Read + std::io::Write,
    D: AnchorDial,
    D::Stream: ArmAnchorTimeouts,
{
    for accepted in incoming {
        handle_accepted(accepted, dial);
    }
    // VsockListener::incoming() never yields None, so this is genuinely unreachable in production. The
    // finite-test driver (drive_relay_loop_finite) loops the SAME body and returns (), so the type-level
    // Infallible guarantee stays truthful WITHOUT an unreachable! ever being reached in tests.
    unreachable!("VsockListener::incoming() never terminates")
}

// ---------------------------------------------------------------------------------------------------
// The pub entrypoint (design §3a) — startup-fallible, then never returns Ok.
// ---------------------------------------------------------------------------------------------------

/// (b) host-relay daemon entrypoint (TASK-7.7 5b-2b-ii(b)). Resolves config, binds the AF_VSOCK relay
/// endpoint, resolves the anchor TCP endpoint, then runs a SERIAL accept loop: one deadline-bounded
/// enclave↔anchor pump at a time (§8 — concurrency is a NAMED follow-up). Per-connection faults are
/// logged + skipped (close + serve next); the loop NEVER returns Ok. Returns Err ONLY on a STARTUP
/// fault (config parse, bind) — the bin prints it and exits 1. The post-bind serve loop is
/// infallible-by-design (the `Ok` type is [`std::convert::Infallible`]).
///
/// BIND CID (Risk #5 — NOT deviceless-testable, aya-pinned): binds [`DEFAULT_VSOCK_CID`] (=
/// `VMADDR_CID_ANY` = 4294967295), NOT literal `VMADDR_CID_HOST=2` — a host process cannot bind literal
/// CID 2 under vhost-vsock; CID 2 is the DIAL TARGET the guest uses. The deviceless suite (UnixStream
/// pairs have no CID) does NOT cover the bind endpoint — that is the aya test A2.
pub fn run_host_anchor_relay() -> Result<std::convert::Infallible, Box<dyn std::error::Error>> {
    let relay_port = vsock_addr::anchor_relay_port_from_env()?; // fail-closed (== serve rejected)
    let addrs = vsock_addr::anchor_endpoint_from_env()?; // fail-closed (no default)
    let dial = TcpAnchorDial { addrs };
    // BIND CID_ANY (the host VsockListener accepts guest-initiated dials; the guest dials CID 2). NOT
    // deviceless-testable; aya-pinned (Risk #5).
    let listener = vsock_listen::bind_vsock_listener(DEFAULT_VSOCK_CID, relay_port)?;
    emit_log(&RelayEvent::Listening {
        port: relay_port,
        anchor: dial.endpoint_display(),
    });
    // §3d: arm the ENCLAVE leg's SO_*TIMEO at the CONCRETE boundary (NO SessionTimeouts seam — dropped
    // per the review-load grafts). The prod wrapper maps incoming() through a closure arming the vsock
    // stream's timeouts; the closure yields the SAME `Result<S, io::Error>` iterator the generic loop
    // expects, so the loop stays generic over `E: Read + Write` with no extra bound. The anchor leg is
    // armed inside relay_one_pump (in the tested path); the deviceless tests do not need real
    // SO_*TIMEO to exercise close-and-continue, so this enclave-arming branch being prod-only is fine.
    let armed = listener.incoming().map(|r| {
        r.and_then(|mut s| {
            configure_relay_session_timeouts(&mut s, PUMP_BUDGET)?;
            Ok(s)
        })
    });
    // Never returns Ok: per-conn faults are logged + skipped; the only exits above were startup. The
    // loop returns `Infallible` (uninhabited — it diverges), so the `Ok(..)` wrapper is technically
    // unreachable (the call never produces a value to wrap). We KEEP the `Result<Infallible, _>` shape
    // (it documents at the type level that the serve loop never returns Ok) and allow the one benign
    // unreachable-code lint that the divergence necessarily produces.
    #[allow(unreachable_code)]
    Ok(serve_anchor_relay_loop(armed, &dial))
}

/// Arm the enclave-facing vsock stream's `SO_RCVTIMEO`/`SO_SNDTIMEO` to `budget` (deadline-derived,
/// NOT the fixed 30s/120s of `configure_vsock_session_timeouts`). Concrete-boundary adapter for the
/// §3d enclave-leg arming — prod-only (the deviceless tests use a `UnixStream` pair).
#[cfg(all(target_os = "linux", feature = "vsock-transport"))]
fn configure_relay_session_timeouts(
    stream: &mut vsock::VsockStream,
    budget: Duration,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(budget))?;
    stream.set_write_timeout(Some(budget))?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Tests — DEVICELESS (CI, --features agent-gateway,vsock-transport). UnixStream::pair stands in for
// the accepted vsock stream + a FakeAnchorDial returns an in-memory scripted anchor. ZERO anchor-
// looking bytes on fault = the never-synth behavioral guard. The core (relay_forward_once) is ALREADY
// deviceless-tested in agent_boot_relay — these tests exercise the WRAPPER additions only.
// ---------------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_boot_relay::{
        frame_anchor_response, test_boot_relay_golden_frame, test_golden_request_frame,
    };
    use std::cell::Cell;
    // `Write` comes in via `use super::*` (the module-level `use std::io::Write`); only `Cursor`/`Read`
    // are additionally needed here.
    use std::io::{Cursor, Read};
    use std::os::unix::net::UnixStream;

    /// The finite-iterator test twin (§3b / §7): loops the SAME `handle_accepted` body as
    /// `serve_anchor_relay_loop` but returns `()` when a FINITE iterator drains — so `Infallible` stays
    /// truthful (the prod iterator is infinite) WITHOUT an `unreachable!` ever being reached in tests.
    fn drive_relay_loop_finite<I, E, D>(incoming: I, dial: &D)
    where
        I: Iterator<Item = std::io::Result<E>>,
        E: std::io::Read + std::io::Write,
        D: AnchorDial,
        D::Stream: ArmAnchorTimeouts,
    {
        for accepted in incoming {
            handle_accepted(accepted, dial);
        }
    }

    /// In-memory anchor stream: reads from a scripted `to_enclave` buffer (the canned anchor response),
    /// records EVERYTHING the relay wrote to it (the forwarded request) for the verbatim assertion.
    struct FakeAnchorStream {
        reads: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for FakeAnchorStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.read(buf)
        }
    }
    impl std::io::Write for FakeAnchorStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl ArmAnchorTimeouts for FakeAnchorStream {}

    /// Scripted dialer: each `dial` pops the next scripted outcome. Records the dial count (proving
    /// dial-never-called on a malformed request) +, on success, the bytes the relay forwarded.
    enum DialAct {
        /// Connect succeeds; the fake anchor will return these response bytes (already framed).
        Ok(Vec<u8>),
        /// Connect fails with this errorkind (refused / timed-out / unreachable).
        Err(std::io::ErrorKind),
    }
    struct FakeAnchorDial {
        acts: std::cell::RefCell<std::collections::VecDeque<DialAct>>,
        dials: Cell<u32>,
        /// The request bytes the most recent SUCCESSFUL pump forwarded to the anchor (verbatim check).
        last_forwarded: std::cell::RefCell<Vec<u8>>,
    }
    impl FakeAnchorDial {
        fn new(acts: Vec<DialAct>) -> Self {
            Self {
                acts: std::cell::RefCell::new(acts.into()),
                dials: Cell::new(0),
                last_forwarded: std::cell::RefCell::new(Vec::new()),
            }
        }
    }
    /// Anchor stream that records bytes forwarded to it LIVE inside `write` (via the `sink` reference —
    /// NOT on Drop; there is no Drop impl), so `dial.last_forwarded` updates as the relay writes.
    struct RecordingAnchorStream<'a> {
        inner: FakeAnchorStream,
        sink: &'a std::cell::RefCell<Vec<u8>>,
    }
    impl Read for RecordingAnchorStream<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }
    impl std::io::Write for RecordingAnchorStream<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // One unambiguous borrow_mut (no clone-per-write, no place/value borrow-ordering subtlety).
            self.sink.borrow_mut().extend_from_slice(buf);
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    impl ArmAnchorTimeouts for RecordingAnchorStream<'_> {}

    impl<'a> AnchorDial for &'a FakeAnchorDial {
        type Stream = RecordingAnchorStream<'a>;
        fn dial(&self, _deadline: std::time::Instant) -> std::io::Result<RecordingAnchorStream<'a>> {
            self.dials.set(self.dials.get() + 1);
            self.last_forwarded.borrow_mut().clear();
            match self.acts.borrow_mut().pop_front() {
                Some(DialAct::Ok(resp)) => Ok(RecordingAnchorStream {
                    inner: FakeAnchorStream { reads: Cursor::new(resp), written: Vec::new() },
                    sink: &self.last_forwarded,
                }),
                Some(DialAct::Err(k)) => Err(std::io::Error::new(k, "fake dial error")),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "no scripted dial",
                )),
            }
        }
        fn endpoint_display(&self) -> String {
            "fake-anchor:0".to_string()
        }
    }

    /// The OPAQUE anchor response payload the fake anchor returns. The relay NEVER parses/trusts the
    /// anchor response (verification is entirely in the enclave), so any bytes ≤ MAX_ANCHOR_RESPONSE_LEN
    /// model a conformant anchor for the daemon's purposes — the daemon's contract is "write the bytes
    /// back VERBATIM, framed by the shared writer".
    fn opaque_anchor_response() -> Vec<u8> {
        vec![0x5e; 96]
    }

    /// The canned framed anchor response a happy pump writes back — framed with the SHARED
    /// `frame_anchor_response` writer the enclave's reader pairs with (no BE/prefix drift).
    fn canned_framed_response() -> Vec<u8> {
        frame_anchor_response(&opaque_anchor_response()).expect("framable")
    }

    /// A UnixStream pair: returns the relay-facing half (the "accepted enclave" stream the loop drives)
    /// pre-loaded with `enclave_writes`, and the peer half kept alive so the relay can write back. The
    /// caller reads the relay's write-back off `peer`.
    fn enclave_pair_with(enclave_writes: &[u8]) -> (UnixStream, UnixStream) {
        let (relay_side, peer) = UnixStream::pair().unwrap();
        // The peer writes the request frame the enclave would send; the relay reads it off relay_side.
        (&peer).write_all(enclave_writes).unwrap();
        (relay_side, peer)
    }

    // 1. happy_path_one_pump — Regression: the accept→pump→write-back lifecycle + verbatim forward.
    #[test]
    fn happy_path_one_pump() {
        let req = test_golden_request_frame();
        let (relay_side, mut peer) = enclave_pair_with(&req);
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(canned_framed_response())]);
        drive_relay_loop_finite(vec![Ok(relay_side)].into_iter(), &&dial);
        // Anchor received the request frame VERBATIM.
        assert_eq!(*dial.last_forwarded.borrow(), req, "forwarded request must be byte-identical");
        // Enclave reads back EXACTLY the framed canned response.
        let mut got = Vec::new();
        let _ = peer.set_read_timeout(Some(Duration::from_secs(2)));
        // Read the 4-byte len then the body.
        let mut len_buf = [0u8; 4];
        peer.read_exact(&mut len_buf).unwrap();
        let n = u32::from_be_bytes(len_buf) as usize;
        got.resize(n, 0);
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, opaque_anchor_response(), "write-back must be the verbatim response");
        assert_eq!(dial.dials.get(), 1);
    }

    // 2. malformed_enclave_request_rejects_before_dial — Regression: decode-before-round-trip
    //    defense-in-depth; dial NEVER invoked; ZERO bytes written back.
    #[test]
    fn malformed_enclave_request_rejects_before_dial() {
        // A correctly-TYPED AgentBootRelay (0x41) frame whose payload is garbage CBOR — so the reject
        // is the `decode_anchor_boot_request` decode gate ("boot request: ..." → label
        // "malformed-request", pinned in test 8), NOT an earlier frame error. Mirrors the core's
        // `relay_forward_once_rejects_malformed_request_before_anchor`.
        let bad = crate::encode_message(crate::MessageType::AgentBootRelay, &[0xff, 0xff]).unwrap();
        let (relay_side, mut peer) = enclave_pair_with(&bad);
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(canned_framed_response())]);
        drive_relay_loop_finite(vec![Ok(relay_side)].into_iter(), &&dial);
        // dial was NEVER invoked (reject happened before the round-trip).
        assert_eq!(dial.dials.get(), 0, "anchor must NOT be dialed for a malformed request");
        // ZERO bytes written back to the enclave (never-synth).
        let mut got = Vec::new();
        let _ = peer.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = peer.read_to_end(&mut got);
        assert!(got.is_empty(), "no bytes may be written back on a malformed request; got {got:?}");
    }

    // 3. anchor_connect_refused_closes_and_continues — Regression: serial close-and-continue.
    #[test]
    fn anchor_connect_refused_closes_and_continues() {
        let req = test_golden_request_frame();
        let (e1, mut p1) = enclave_pair_with(&req);
        let (e2, mut p2) = enclave_pair_with(&req);
        let dial = FakeAnchorDial::new(vec![
            DialAct::Err(std::io::ErrorKind::ConnectionRefused), // first pump: anchor down
            DialAct::Ok(canned_framed_response()),               // second pump: succeeds
        ]);
        drive_relay_loop_finite(vec![Ok(e1), Ok(e2)].into_iter(), &&dial);
        // First conn closed with NO bytes back.
        let mut g1 = Vec::new();
        let _ = p1.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = p1.read_to_end(&mut g1);
        assert!(g1.is_empty(), "refused pump writes nothing back");
        // SECOND conn still served to success — the serial-continue property.
        let mut len_buf = [0u8; 4];
        let _ = p2.set_read_timeout(Some(Duration::from_secs(2)));
        p2.read_exact(&mut len_buf).unwrap();
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        p2.read_exact(&mut body).unwrap();
        assert_eq!(body, opaque_anchor_response());
        assert_eq!(dial.dials.get(), 2);
    }

    // 4. anchor_connect_timeout_label — Regression: TimedOut → "anchor-connect-timeout".
    #[test]
    fn anchor_connect_timeout_label() {
        let req = test_golden_request_frame();
        let (e1, _p1) = enclave_pair_with(&req);
        let dial = FakeAnchorDial::new(vec![DialAct::Err(std::io::ErrorKind::TimedOut)]);
        // The fault classifies as anchor-connect-timeout (asserted directly via classify_close below).
        drive_relay_loop_finite(vec![Ok(e1)].into_iter(), &&dial);
        assert_eq!(dial.dials.get(), 1, "dial attempted then timed out");
        // The label mapping is pinned exhaustively in test 8; here we confirm the daemon SURVIVED and
        // would serve the next conn (no panic, loop returned).
        let (e2, mut p2) = enclave_pair_with(&req);
        let dial2 = FakeAnchorDial::new(vec![DialAct::Ok(canned_framed_response())]);
        drive_relay_loop_finite(vec![Ok(e2)].into_iter(), &&dial2);
        let mut len_buf = [0u8; 4];
        let _ = p2.set_read_timeout(Some(Duration::from_secs(2)));
        p2.read_exact(&mut len_buf).unwrap();
    }

    // 5. oversized_anchor_response_closes — Regression: read_bounded_anchor_response rejects >4096
    //    before alloc; NO partial bytes to enclave; label "oversized-anchor-response".
    #[test]
    fn oversized_anchor_response_closes() {
        let req = test_golden_request_frame();
        let (e1, mut p1) = enclave_pair_with(&req);
        // A length prefix claiming > MAX_ANCHOR_RESPONSE_LEN (4096) — reader rejects before alloc.
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&(5000u32).to_be_bytes());
        oversized.extend_from_slice(&[0u8; 16]); // some body bytes; never fully read
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(oversized)]);
        drive_relay_loop_finite(vec![Ok(e1)].into_iter(), &&dial);
        // NO partial bytes written back to the enclave.
        let mut got = Vec::new();
        let _ = p1.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = p1.read_to_end(&mut got);
        assert!(got.is_empty(), "oversized anchor response: nothing written back; got {got:?}");
    }

    // 6. garbled_anchor_response_closes — Regression: truncated/garbage anchor frame (EOF mid-body) →
    //    close; ZERO anchor-looking bytes reach the enclave (the never-synth invariant).
    #[test]
    fn garbled_anchor_response_closes() {
        let req = test_golden_request_frame();
        let (e1, mut p1) = enclave_pair_with(&req);
        // Claims a 64-byte body but supplies only 10 → read_exact hits EOF mid-body → Err.
        let mut garbled = Vec::new();
        garbled.extend_from_slice(&(64u32).to_be_bytes());
        garbled.extend_from_slice(&[0xab; 10]);
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(garbled)]);
        drive_relay_loop_finite(vec![Ok(e1)].into_iter(), &&dial);
        let mut got = Vec::new();
        let _ = p1.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = p1.read_to_end(&mut got);
        assert!(got.is_empty(), "garbled anchor response: ZERO bytes reach the enclave; got {got:?}");
    }

    // 7. never_die_under_N_bad_connections — Regression: close-and-continue resilience end to end.
    #[test]
    fn never_die_under_n_bad_connections() {
        let req = test_golden_request_frame();
        // malformed (typed-but-bad-CBOR), anchor-down, timeout, garbled, then one GOOD.
        let bad_frame = crate::encode_message(crate::MessageType::AgentBootRelay, &[0xff, 0xff]).unwrap();
        let (e_mal, _pm) = enclave_pair_with(&bad_frame);
        let (e_down, _pd) = enclave_pair_with(&req);
        let (e_to, _pt) = enclave_pair_with(&req);
        let mut garbled = Vec::new();
        garbled.extend_from_slice(&(64u32).to_be_bytes());
        garbled.extend_from_slice(&[0xcd; 4]);
        let (e_garb, _pg) = enclave_pair_with(&req);
        let (e_good, mut p_good) = enclave_pair_with(&req);
        let dial = FakeAnchorDial::new(vec![
            // malformed never dials; the remaining acts line up with down/timeout/garbled/good.
            DialAct::Err(std::io::ErrorKind::ConnectionRefused),
            DialAct::Err(std::io::ErrorKind::TimedOut),
            DialAct::Ok(garbled),
            DialAct::Ok(canned_framed_response()),
        ]);
        drive_relay_loop_finite(
            vec![Ok(e_mal), Ok(e_down), Ok(e_to), Ok(e_garb), Ok(e_good)].into_iter(),
            &&dial,
        );
        // The FINAL good connection forwarded correctly.
        let mut len_buf = [0u8; 4];
        let _ = p_good.set_read_timeout(Some(Duration::from_secs(2)));
        p_good.read_exact(&mut len_buf).unwrap();
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        p_good.read_exact(&mut body).unwrap();
        assert_eq!(body, opaque_anchor_response(), "final good pump must succeed");
        // malformed did not dial; the other 4 each dialed exactly once.
        assert_eq!(dial.dials.get(), 4, "malformed never dials; the other four do");
    }

    // 8. classify_close_taxonomy_pin — Regression: the operator-triage taxonomy + core message-wording
    //    drift guard (Risk #7). Typed buckets are variant-matched; substring buckets pinned by content.
    #[test]
    fn classify_close_taxonomy_pin() {
        use std::io::{Error, ErrorKind};
        // AnchorConnect: kind-driven.
        assert_eq!(
            classify_close(&RelayFault::AnchorConnect(Error::new(ErrorKind::TimedOut, "x"))),
            "anchor-connect-timeout"
        );
        assert_eq!(
            classify_close(&RelayFault::AnchorConnect(Error::new(ErrorKind::ConnectionRefused, "x"))),
            "anchor-unavailable"
        );
        // Pump typed-first: MessageTooLarge → oversized-request-frame.
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::MessageTooLarge(99))),
            "oversized-request-frame"
        );
        // Pump Io kinds.
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::Io(Error::new(ErrorKind::TimedOut, "x")))),
            "socket-timeout"
        );
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::Io(Error::new(
                ErrorKind::UnexpectedEof,
                "x"
            )))),
            "peer-closed"
        );
        // WireProtocol-folded substring buckets — PINNED against the cores' actual messages.
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::WireProtocol("anchor response too large"))),
            "oversized-anchor-response"
        );
        // The reads-as-malformed-but-is-timeout case: a deadline-guarded write returns a WireProtocol
        // message containing "deadline" → pump-timeout (NOT malformed). The critical correctness pin —
        // and it pins the EXACT strings the DAEMON's production path (relay_one_pump_until) can emit, NOT
        // relay_forward_once's "...before anchor write" (which the daemon never calls): the anchor write
        // goes through relay_round_trip_over_stream ("...before write", agent_boot_relay.rs), and the
        // enclave write-back goes through deadline_guarded_write ("...before enclave write").
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::WireProtocol(
                "anchor relay: deadline before write"
            ))),
            "pump-timeout"
        );
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::WireProtocol(
                "anchor relay: deadline before enclave write"
            ))),
            "pump-timeout"
        );
        // A genuine malformed boot request → malformed-request (the cores prefix "boot request:").
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::WireProtocol("boot request: bad CBOR"))),
            "malformed-request"
        );
        // Anything else → relay-error.
        assert_eq!(
            classify_close(&RelayFault::Pump(ProtocolError::WireProtocol("something else"))),
            "relay-error"
        );
    }

    // 9. empty_anchor_response_closes_never_synth — Regression: a VALID request but an EMPTY anchor
    //    response → read_bounded_anchor_response hits immediate EOF on the 4-byte len prefix → pump errs,
    //    NO enclave bytes written, loop continues. (never-synth + survival on the peer-closed path. This
    //    does NOT exercise a deadline lapse — the genuine lapse is test 9b below.)
    #[test]
    fn empty_anchor_response_closes_never_synth() {
        // A valid request but the anchor returns zero bytes → read_exact of the 4-byte len prefix hits
        // immediate EOF → Err (close). The enclave sees ZERO bytes back.
        let req = test_golden_request_frame();
        let (e1, mut p1) = enclave_pair_with(&req);
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(Vec::new())]);
        drive_relay_loop_finite(vec![Ok(e1)].into_iter(), &&dial);
        let mut got = Vec::new();
        let _ = p1.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = p1.read_to_end(&mut got);
        assert!(got.is_empty(), "empty/failed anchor response writes nothing back; got {got:?}");
        assert_eq!(dial.dials.get(), 1);
    }

    // 9b. lapsed_deadline_pump_never_synth — Regression: a GENUINELY-lapsed pump deadline (injected via
    //     relay_one_pump_until — the prod deadline `now + PUMP_BUDGET` can't be coerced into the past
    //     inside a deviceless test) faults the pump with ZERO bytes written back, EVEN THOUGH the anchor
    //     is reachable and would return a perfectly-valid response. Pins never-synth on the deadline-lapse
    //     path: the budget guard (not a bad anchor) is the SOLE reason for the close.
    #[test]
    fn lapsed_deadline_pump_never_synth() {
        let req = test_golden_request_frame();
        let (mut relay_side, mut p1) = enclave_pair_with(&req);
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(canned_framed_response())]);
        // An already-past deadline → the enclave read / connect tripwire fires before any write-back.
        let past = std::time::Instant::now() - Duration::from_secs(1);
        let fault = relay_one_pump_until(&mut relay_side, &&dial, past);
        assert!(fault.is_err(), "a lapsed pump deadline must fault the pump");
        // never-synth on the lapse path: ZERO bytes reached the enclave.
        let mut got = Vec::new();
        let _ = p1.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = p1.read_to_end(&mut got);
        assert!(got.is_empty(), "lapsed-deadline pump writes nothing back (never-synth); got {got:?}");
    }

    // 11. golden_vector_reuse — Regression: the daemon forwards the CANONICAL frozen production request
    //     verbatim (no re-encode). The happy path drives the frozen golden vector as the enclave frame.
    #[test]
    fn golden_vector_reuse() {
        let golden = test_boot_relay_golden_frame();
        let (relay_side, _peer) = enclave_pair_with(golden);
        let dial = FakeAnchorDial::new(vec![DialAct::Ok(canned_framed_response())]);
        drive_relay_loop_finite(vec![Ok(relay_side)].into_iter(), &&dial);
        // The bytes forwarded to the anchor are the frozen golden vector, byte-for-byte.
        assert_eq!(
            dial.last_forwarded.borrow().as_slice(),
            golden,
            "the daemon must forward the canonical golden request VERBATIM"
        );
    }

    // Budget sanity: the derived connect budget is floored + a fraction of the pump budget.
    #[test]
    fn connect_budget_is_floored_fraction_of_pump_budget() {
        let cb = connect_budget();
        assert!(cb >= CONNECT_BUDGET_MIN, "connect budget floored");
        assert!(cb <= PUMP_BUDGET, "connect budget never exceeds the pump budget");
        assert_eq!(cb, PUMP_BUDGET / CONNECT_BUDGET_DIVISOR);
    }

    /// aya-only `#[ignore]` (needs the `vsock_loopback` module): the FULL guest→relay→anchor
    /// composition over a REAL AF_VSOCK leg — discharges the doc-pinned "real-vsock-loopback
    /// (bind-CID `CID_ANY` reality)" item that lands with the 5b-2c bring-up, AND seeds TASK-21's
    /// relay⊇anchor differential test with a MODELABLE anchor: the anchor side is the REAL 5b-2c-iii
    /// lab stub pump (`lab_agent_smoke::lab_anchor_pump_one`) on TCP loopback, exactly what the live
    /// smoke runs. Guest leg = the production `VsockBootRelayChannel` dialing loopback CID 1; relay
    /// leg = a REAL `CID_ANY` vsock bind + the SHIPPED `relay_one_pump` with the SHIPPED
    /// `TcpAnchorDial`. The returned bytes must pass the REAL guest verify path and reconcile Fresh.
    /// Run: `cargo test --features agent-gateway,vsock-transport \
    ///       relay_real_vsock_loopback_with_lab_anchor -- --ignored` (on aya).
    /// Triage: a FAILURE binding/accepting can mean `vsock_loopback` is not loaded (`modprobe
    /// vsock_loopback`) or a stray listener on port 5994 (`ss --vsock`).
    #[test]
    #[ignore]
    fn relay_real_vsock_loopback_with_lab_anchor() {
        use crate::agent_boot_relay::BootRelayChannel as _;
        /// vsock loopback CID (`VMADDR_CID_LOCAL`; requires the `vsock_loopback` module).
        const LOOPBACK_CID: u32 = 1;
        // The `agent_boot_relay` aya `#[ignore]` tests already bind/connect 5995–5999 on this CID
        // (5999/5996/5997 bind, 5998/5995 connect); libtest runs `--ignored` in PARALLEL, so pick a
        // DISTINCT port BELOW that band — a shared port EADDRINUSE-flakes the second binder. 5994 is
        // free; do not move into 5995–5999.
        const RELAY_TEST_PORT: u32 = 5994;
        let deadline = || std::time::Instant::now() + Duration::from_secs(5);

        // 1. The REAL lab anchor stub pump on TCP loopback (one connection, test thread).
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub TCP listener");
        let stub_addr = tcp.local_addr().expect("stub addr");
        let body = crate::lab_agent_smoke::smoke_body();
        let stub_body = body.clone();
        let stub = std::thread::spawn(move || {
            let (mut conn, _) = tcp.accept().expect("stub accept");
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            conn.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(
                &crate::lab_agent_smoke::LAB_ANCHOR_TEST_SEED,
            );
            crate::lab_agent_smoke::lab_anchor_pump_one(&mut conn, &stub_body, &key, deadline())
                .expect("the real stub pump signs the relayed request");
        });

        // 2. The relay leg: REAL CID_ANY bind (what production run_host_anchor_relay does) + the
        //    SHIPPED pump + SHIPPED TCP dialer pointed at the stub.
        let listener = vsock_listen::bind_vsock_listener(DEFAULT_VSOCK_CID, RELAY_TEST_PORT)
            .expect("relay binds CID_ANY on the loopback test port");
        let relay = std::thread::spawn(move || {
            let (mut enclave, _addr) = listener.accept().expect("relay accept");
            configure_relay_session_timeouts(&mut enclave, PUMP_BUDGET)
                .expect("arm enclave-leg timeouts");
            let dial = TcpAnchorDial { addrs: vec![stub_addr] };
            // RelayFault is LOG-ONLY (deliberately no Debug derive) — surface the triage label.
            if let Err(fault) = relay_one_pump(&mut enclave, &dial) {
                panic!("relay pump failed: {}", fault.triage_label());
            }
        });

        // 3. The guest leg: the PRODUCTION channel, a stub-conformant smoke request.
        let nonce = [0x6b_u8; 32];
        let frame = crate::lab_agent_smoke::smoke_request_frame(nonce);
        let mut ch = crate::agent_boot_relay::VsockBootRelayChannel::new(LOOPBACK_CID, RELAY_TEST_PORT);
        let raw = ch.round_trip(&frame, deadline()).expect("guest round trip over real vsock");

        // 4. The stub's bytes pass the REAL guest verify path and reconcile Fresh.
        let state = crate::agent_anchor::verify_anchor_response_bytes(&raw, &nonce, &body.config)
            .expect("stub response verifies against the smoke fixture's anchor_root");
        assert_eq!(
            crate::agent_anchor::reconcile(
                body.freshness_epoch,
                body.structural_version,
                &body.compute_local_marks_digest(),
                &state,
            ),
            crate::agent_anchor::ReconcileDecision::Fresh,
            "the composed guest→relay→anchor path must land reconcile == Fresh"
        );
        relay.join().expect("relay thread");
        stub.join().expect("stub thread");
    }
}
