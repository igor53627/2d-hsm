//! (4c) IN-GUEST quote smoke (TASK-7.7 5b-2b-ii (d-ii)/4c) — the diagnostic sequence the
//! `twod-hsm-quote-smoke` bin runs once per boot inside the SNP guest. Lab/debug images only
//! (`lab-quote-smoke`, release-banned in `lib.rs`).
//!
//! ## Scope pin (NOT the 5b-2c serve wrapper)
//! No handshake, no `decide_serve`, no listener, no anchor round-trip: `agent_gateway_boot` stays
//! crate-private and unexported, and live serve remains gated on 5b-2c. This module only drives the
//! already-shipped (d) artifacts — `connect_bounded` (via the smoke shim), `ValidatedBootBudget`,
//! `HardBoundedQuoteProducer` and the quote-child dispatch — against the REAL guest platform
//! (vsock device + configfs-tsm + journald), closing the zero-runtime-coverage set §8 names.
//!
//! ## Marker grammar (fixed prefix, `grep -a`-able from the host serial log)
//! ```text
//! twod-hsm-quote-smoke: START
//! twod-hsm-quote-smoke: PHASE <name> PASS <kv-detail>
//! twod-hsm-quote-smoke: PHASE <name> FAIL <detail incl. observed error string>
//! twod-hsm-quote-smoke: RESULT PASS phases=7 | RESULT FAIL phase=<first-failed>
//! ```
//! Parent-mode output goes to STDERR ONLY (the house `let _ = writeln!(stderr)` pattern) — stdout is
//! NEVER written in parent mode, forward-compat with the 5b-2c PROTOCOL-ONLY-stdout discipline (the
//! systemd unit routes stderr to journal+console so markers reach journald AND ttyS0).
//!
//! **SELF-MATCH GUARD (rule):** no marker, detail string, or launcher script may ever contain the
//! literal `twod-hsm quote child: exit` — the journald/serial breadcrumb greps must only ever match
//! the child's own stderr write (phase `breadcrumb` says `err1-frame+exit1` instead).
//!
//! ## Phase order is LOAD-BEARING
//! `vsock-lapse → gc-seed → budget-claim → quote-1 → gc-clean → quote-2 → breadcrumb`. The producer
//! claim (phase 3) is PERMANENT for the process — reordering a quote phase ahead of it (or re-running
//! `production()`) trips the claim by design. A phase FAIL records the verdict but later independent
//! phases still run (maximal triage per boot); the producer-dependent quote phases fail with a
//! `skipped:` detail when phase 3 left no producer.
//!
//! ## Honesty notes (recorded allowances/residuals)
//! - **Parent-side configfs I/O here is a SMOKE-ONLY allowance**: `gc-seed`'s `create_dir` and the
//!   `gc-clean`/`quote-2` `read_dir` asserts run in the parent process. The no-parent-configfs-I/O
//!   rule binds the PRODUCTION boot path (a wedged provider could block the unkillable parent); this
//!   is diagnostic staging in a disposable lab boot, bounded by the host launcher's BOOT_TIMEOUT.
//! - **The kill→orphan TRANSITION is not staged** (the healthy provider answers in ms; kill
//!   mechanics are (d-i)-pinned by `killed_wedged_child_shows_sigkill`); 4c adds GC behavior against
//!   the REAL dir with a REAL orphan-shaped entry (the synthetic `twod-hsm-q-stale-4c` seed).
//!
//! ## Black-hole mechanism (phase `vsock-lapse`, recorded facts)
//! IN-GUEST guest→nonexistent CID is the only self-contained black hole: the guest's virtio
//! transport queues the connect REQUEST unconditionally; host vhost_vsock silently FREES packets
//! whose `dst_cid != 2` — no RST, no RESPONSE. The guest kernel's own connect timer
//! (`VSOCK_DEFAULT_CONNECT_TIMEOUT` ≈ 2s) would fire via the VETO arm, so the 400ms probe deadline
//! makes OUR lapse arm the binding bound (the §8 "< ~2s" constraint; window CI-pinned by the
//! `cfg(test)` unit below). Host-side staging is impossible (`ENODEV`, see the shim's rustdoc).

use std::io::Write as _;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::agent_boot_relay::{
    connect_bounded_for_smoke, BootQuoteProducer as _, VSOCK_CONNECT_LAPSE_MSG,
};
use crate::quote_subprocess::{
    encode_err_frame, smoke_breadcrumb_arm, HardBoundedQuoteProducer, ValidatedBootBudget,
};
use crate::snp_report::{
    measurement_from_report, REPORT_DATA_OFFSET, TSM_QUOTE_ENTRY_PREFIX, TSM_REPORT_DIR,
};
use crate::ProtocolError;

/// No such guest CID: != 0/1/2 (hypervisor/loopback/host) and != 42 (the launcher's guest CID);
/// improbable as an operator-assigned CID. The host vhost silently drops packets to it (black hole).
const BLACK_HOLE_CID: u32 = 999_999_983;
/// Arbitrary non-privileged port for the black-hole probe (never bound anywhere).
const BLACK_HOLE_PORT: u32 = 5_994;
/// The vsock-lapse probe deadline. MUST stay well under the kernel's ~2s
/// `VSOCK_DEFAULT_CONNECT_TIMEOUT` or the kernel `ETIMEDOUT` fires first via the VETO arm and the
/// probe stops testing OUR bound (5x margin chosen; window pinned by the `cfg(test)` unit).
pub(crate) const LAPSE_PROBE_DEADLINE: Duration = Duration::from_millis(400);
/// Upper elapsed bound for the lapse arm — far below 2s so a kernel-timer preemption can never be
/// misread as a slow-but-passing lapse.
const LAPSE_ELAPSED_CEILING: Duration = Duration::from_millis(1_500);
/// Lower-bound slop below [`LAPSE_PROBE_DEADLINE`]: `poll(2)` takes a whole-millisecond timeout, so
/// `remaining_or_lapsed` truncates `399.x ms → 399 ms` and the kernel can wake up to one tick early —
/// a 400ms deadline legitimately lapses at 399ms (observed on the aya guest, 4c first run). 25ms is
/// generous against 2-vCPU-guest scheduler jitter yet still ~15× above a prompt-refusal (~0–1ms), so
/// the lapse stays unambiguously attributed to OUR deadline, never a kernel RST/ENODEV.
const LAPSE_ELAPSED_FLOOR_SLOP: Duration = Duration::from_millis(25);
/// SNP `ATTESTATION_REPORT` ABI floor (Milan/Genoa/Turin) for a REAL-quote claim.
/// `MIN_REPORT_LEN` (= 192, `snp_report`) is the PARSE floor — too weak for this assert.
const REAL_REPORT_MIN_LEN: usize = 1_184;
/// Distinct report_data for the two fetches so each echo assert is its own witness.
const RD_A: [u8; 64] = [0x41; 64];
const RD_B: [u8; 64] = [0x42; 64];

/// One stderr marker line (the house non-panicking pattern; stdout stays PROTOCOL-ONLY-silent).
fn emit(line: &str) {
    let _ = writeln!(std::io::stderr(), "twod-hsm-quote-smoke: {line}");
}

/// Lowercase hex (local 8-liner: the `hex` crate is not an `agent-gateway` dependency).
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The synthetic stale-entry path for `gc-seed`: `<TSM_REPORT_DIR>/<PREFIX>stale-4c`. Built from the
/// crate consts — zero path literals. The non-numeric suffix is unallocatable as a pid (can never
/// collide with a live child) AND proves the GC prefix-MATCHES rather than pid-parses.
fn synthetic_stale_entry_path() -> String {
    format!("{TSM_REPORT_DIR}/{TSM_QUOTE_ENTRY_PREFIX}stale-4c")
}

/// Names under [`TSM_REPORT_DIR`] starting with [`TSM_QUOTE_ENTRY_PREFIX`]. Deliberately NEVER
/// matches the bare `twod-hsm` entry (the concurrently booting enclave-vsock unit owns it;
/// strictly-longer-prefix discrimination is test-pinned in `snp_report`).
fn prefixed_residue() -> Result<Vec<String>, String> {
    let entries = std::fs::read_dir(TSM_REPORT_DIR)
        .map_err(|e| format!("read_dir {TSM_REPORT_DIR} failed: {e}"))?;
    let mut residue = Vec::new();
    for entry in entries {
        // Surface a read error, never skip it: a swallowed DirEntry fault could hide a stale
        // twod-hsm-q-* entry and turn gc-clean into a false residue=0 PASS (review finding).
        let entry =
            entry.map_err(|e| format!("read_dir entry under {TSM_REPORT_DIR} failed: {e}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!("non-UTF-8 entry name under {TSM_REPORT_DIR} (cannot rule out a stale prefix entry)"));
        };
        if name.starts_with(TSM_QUOTE_ENTRY_PREFIX) {
            residue.push(name.to_string());
        }
    }
    Ok(residue)
}

/// Phase 1 — `vsock-lapse` (goal v; the §8 black-hole checked residual): connect to the black-hole
/// CID under a 400ms deadline; PASS iff the error is the lapse-arm const EXACTLY (the veto string
/// means the kernel timer/RST preempted us = the staging assumption broke = FAIL printing the
/// observed string) AND elapsed lands in
/// `[LAPSE_PROBE_DEADLINE - LAPSE_ELAPSED_FLOOR_SLOP, LAPSE_ELAPSED_CEILING)` (the floor slop absorbs
/// the whole-millisecond `poll(2)` truncation + single-tick early wake — see the slop const).
fn phase_vsock_lapse() -> Result<String, String> {
    let start = Instant::now();
    let r = connect_bounded_for_smoke(
        BLACK_HOLE_CID,
        BLACK_HOLE_PORT,
        start + LAPSE_PROBE_DEADLINE,
    );
    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_millis();
    let floor = LAPSE_PROBE_DEADLINE - LAPSE_ELAPSED_FLOOR_SLOP;
    match r {
        Ok(_) => Err(format!(
            "connect to the black-hole CID unexpectedly SUCCEEDED elapsed_ms={elapsed_ms}"
        )),
        Err(ProtocolError::WireProtocol(msg)) if msg == VSOCK_CONNECT_LAPSE_MSG => {
            if elapsed < floor {
                return Err(format!(
                    "lapse arm fired implausibly early (< deadline - slop) elapsed_ms={elapsed_ms}"
                ));
            }
            if elapsed >= LAPSE_ELAPSED_CEILING {
                return Err(format!(
                    "lapse arm fired but past the elapsed ceiling elapsed_ms={elapsed_ms}"
                ));
            }
            Ok(format!("elapsed_ms={elapsed_ms}"))
        }
        // Covers the veto arm (kernel timer / unknown-CID RST preempted the lapse) and every other
        // arm: never a silent pass — the observed string is the triage.
        Err(e) => Err(format!(
            "expected the lapse arm, observed: {e} elapsed_ms={elapsed_ms}"
        )),
    }
}

/// Phase 2 — `gc-seed` (goal iii staging): mkdir the synthetic orphan-shaped entry. configfs mkdir
/// creates an inert entry (no inblob written → no report generation; rmdir-able), which the NEXT
/// quote child's leading prefix GC must sweep (asserted by `gc-clean`). Parent-side configfs I/O =
/// the recorded smoke-only allowance (module doc). The post-mkdir PRESENCE re-read makes the
/// seed→sweep coupling EXPLICIT: it forbids `gc-clean`'s residue==0 from degenerating to a trivial
/// pass on a boot where the orphan was never actually staged (review hardening — gc-clean alone is
/// residue-only and cannot tell "swept a real orphan" from "nothing was there").
fn phase_gc_seed() -> Result<String, String> {
    let path = synthetic_stale_entry_path();
    // AlreadyExists is FINE: a leftover from a prior run/restart (configfs is RAM-backed, so only a
    // same-boot re-run can hit this) is itself a valid foreign orphan for the next child's prefix GC
    // to sweep — the goal is "the entry is staged", reached either way.
    match std::fs::create_dir(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("mkdir {path} failed: {e}")),
    }
    if !std::path::Path::new(&path).is_dir() {
        return Err(format!(
            "seed {path} not present after mkdir (configfs lifecycle anomaly)"
        ));
    }
    Ok(format!("seeded={path}"))
}

/// Phase 3 — `budget-claim`: validate the boot budget (nominal 2·(3·10s+ε) ≈ 60.02s ≤ 70s; 10s ≥
/// `MIN_BOUNDARY_BUDGET`), claim THE process producer through the standalone claim+shape door
/// `HardBoundedQuoteProducer::production` (deliberately NOT a new `transport_with_spawn` caller —
/// that mint's any-new-caller-is-a-review-flag rule stays clean), then observe claim PERMANENCE
/// live: a second `production()` must refuse with the claim string (CI only ever sees the claim
/// under `cfg(test)` resets — this is the shipped-binary witness). Returns the producer + budget
/// for phases 4–6 (single-claim reuse). Never-generic-Q held: concrete type, no `<Q>` anywhere.
#[allow(clippy::type_complexity)]
fn phase_budget_claim() -> Result<(HardBoundedQuoteProducer, ValidatedBootBudget, String), String> {
    let budget = ValidatedBootBudget::validate(2, Duration::from_secs(10), Duration::from_secs(70))
        .map_err(|e| format!("budget validate refused: {e}"))?;
    let producer = HardBoundedQuoteProducer::production(&budget)
        .map_err(|e| format!("first production() refused: {e}"))?;
    match HardBoundedQuoteProducer::production(&budget) {
        Ok(_) => {
            return Err(
                "second production() unexpectedly SUCCEEDED (claim permanence broken)".to_string(),
            )
        }
        Err(e) => {
            let s = e.to_string();
            if !s.contains("quote producer: process quote ledger already claimed") {
                return Err(format!(
                    "second production() refused with the WRONG error: {e}"
                ));
            }
        }
    }
    Ok((
        producer,
        budget,
        "claim=permanent second-claim=refused".to_string(),
    ))
}

/// The shared quote-leg call for phases 4 (`quote-1`: goals i+ii+iii healthy path — §8 acceptance
/// arm (3) verbatim: "the shipped producer in its production spawn shape fetches a real quote
/// through configfs-tsm") and 6 (`quote-2`) — the IDENTICAL shape `run_boot_handshake_wired`
/// drives (`fetch(&mut p, report_data, Instant::now() + budget.per_leg_timeout())`, same
/// `ExecChildSpawn::production()` under the producer; the parent re-execs `/proc/self/exe` = THIS
/// bin, whose main's first statement is the dispatch — goal (ii) through the real re-exec, under
/// `clear_env` against the RPATH-linked Nix binary — the §8 loader validation for this build shape). Asserts: real-quote length floor + the
/// report_data echo at offset 0x50 (transcript-visible even though the fetch pipeline echo-verifies
/// internally). Detail carries `report_len` + the 96-hex launch measurement. `cert_chain_len` is
/// deliberately NOT printed/asserted: the child frame carries the outblob only, and aya's VCEK is
/// not KDS-resolvable anyway.
fn fetch_and_check(
    producer: &mut HardBoundedQuoteProducer,
    budget: &ValidatedBootBudget,
    rd: &[u8; 64],
) -> Result<String, String> {
    let deadline = Instant::now() + budget.per_leg_timeout();
    let (report, _cert_chain) = producer
        .fetch(rd, deadline)
        .map_err(|e| format!("fetch failed: {e}"))?;
    if report.len() < REAL_REPORT_MIN_LEN {
        return Err(format!(
            "report below the real-quote ABI floor: report_len={} min={REAL_REPORT_MIN_LEN}",
            report.len()
        ));
    }
    let echoed = report
        .get(REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64)
        .ok_or_else(|| {
            format!(
                "report shorter than the echo window: report_len={}",
                report.len()
            )
        })?;
    if echoed != rd.as_slice() {
        return Err("report_data echo mismatch at offset 0x50".to_string());
    }
    let measurement =
        measurement_from_report(&report).map_err(|e| format!("measurement extract failed: {e}"))?;
    Ok(format!(
        "report_len={} measurement={}",
        report.len(),
        hex(&measurement)
    ))
}

/// Phase 5 — `gc-clean` (goal iii GC half; §8 "no-stale-entry-after-kill via the child-side prefix
/// GC"): after `quote-1`, NO `twod-hsm-q-*` entry may remain — the seeded stale entry was swept by
/// the child's leading `gc_quote_entries_default()` and the child removed its own self-named entry
/// (cleanup-precedes-emit). Never asserts on the bare `twod-hsm` entry (see [`prefixed_residue`]).
/// This residue==0 is a FOREIGN-orphan-sweep witness ONLY because `gc-seed` (phase 2) PASSED and the
/// LOAD-BEARING phase order ran it before `quote-1` — the gc-seed presence re-read is what keeps this
/// assert from being a trivial residue-only pass (review hardening; the GC function itself is also
/// deviceless-pinned by `snp_report::gc_removes_prefix_only_spares_fixed_name`).
fn phase_gc_clean() -> Result<String, String> {
    let residue = prefixed_residue()?;
    if residue.is_empty() {
        Ok("residue=0".to_string())
    } else {
        Err(format!(
            "stale prefix entries survived the child GC: {}",
            residue.join(",")
        ))
    }
}

/// Phase 7 — `breadcrumb` (goal iv + the dispatch ERR path through the real re-exec): the staged
/// nonzero-exit child. Byte-exact `encode_err_frame(1)` on the piped stdout (full-buffer equality,
/// not the parser) + exit code 1; the child's breadcrumb rides the INHERITED stderr = the unit's
/// journald stream (arrival asserted by the unit's `ExecStartPost`, not here — the bin stays a
/// clean 5b-2c-shaped template with no journalctl shell-outs). Bypasses producer/ledger BY DESIGN:
/// the target is child-side dispatch + breadcrumb; parent custody is (d-i)-covered.
fn phase_breadcrumb() -> Result<String, String> {
    let (code, stdout) = smoke_breadcrumb_arm()?;
    let expected = encode_err_frame(1);
    if stdout.as_slice() != expected {
        return Err(format!(
            "child stdout is not the byte-exact ERR(1) frame: got {} bytes [{}]",
            stdout.len(),
            hex(&stdout)
        ));
    }
    if code != 1 {
        return Err(format!("child exit code {code}, expected 1"));
    }
    // Self-match guard: the detail must never contain the breadcrumb literal.
    Ok("err1-frame+exit1".to_string())
}

/// Run the seven (4c) smoke phases in their LOAD-BEARING order and emit the marker transcript.
/// TOTAL — never panics (mirrors the child rule: a missing RESULT line can only mean infra death).
/// Exit: success ⇔ `RESULT PASS phases=7`.
pub fn run_quote_smoke() -> ExitCode {
    emit("START");
    let mut first_failed: Option<&'static str> = None;
    let mut passes: u32 = 0;
    let mut phase = |name: &'static str, r: Result<String, String>| match r {
        Ok(detail) => {
            passes += 1;
            emit(&format!("PHASE {name} PASS {detail}"));
        }
        Err(detail) => {
            if first_failed.is_none() {
                first_failed = Some(name);
            }
            emit(&format!("PHASE {name} FAIL {detail}"));
        }
    };

    phase("vsock-lapse", phase_vsock_lapse());
    phase("gc-seed", phase_gc_seed());

    // Phase 3 also yields the producer/budget phases 4 and 6 reuse (the claim is permanent — this
    // is the ONE construction for the whole process).
    let mut claimed: Option<(HardBoundedQuoteProducer, ValidatedBootBudget)> = None;
    phase(
        "budget-claim",
        match phase_budget_claim() {
            Ok((producer, budget, detail)) => {
                claimed = Some((producer, budget));
                Ok(detail)
            }
            Err(detail) => Err(detail),
        },
    );

    phase(
        "quote-1",
        match claimed.as_mut() {
            Some((producer, budget)) => fetch_and_check(producer, budget, &RD_A),
            None => Err("skipped: no producer (budget-claim failed)".to_string()),
        },
    );
    phase("gc-clean", phase_gc_clean());
    phase(
        "quote-2",
        match claimed.as_mut() {
            Some((producer, budget)) => {
                fetch_and_check(producer, budget, &RD_B).and_then(|detail| {
                    // Single-claim reuse proven (second fetch, SAME producer, attempts=2 budget) —
                    // re-assert prefix-cleanliness after the second child exits.
                    let residue = prefixed_residue()?;
                    if residue.is_empty() {
                        Ok(format!("{detail} post-fetch-residue=0"))
                    } else {
                        Err(format!(
                            "prefix entries survived the second fetch: {}",
                            residue.join(",")
                        ))
                    }
                })
            }
            None => Err("skipped: no producer (budget-claim failed)".to_string()),
        },
    );
    phase("breadcrumb", phase_breadcrumb());

    drop(phase);
    match first_failed {
        None => {
            // passes == 7 by construction here (7 phase calls, none failed).
            emit(&format!("RESULT PASS phases={passes}"));
            ExitCode::SUCCESS
        }
        Some(name) => {
            emit(&format!("RESULT FAIL phase={name}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancellable_boundary::MIN_BOUNDARY_BUDGET;

    /// Pins the kernel-timer constraint as a CI fact (deviceless; runs in the (4c) CI step).
    /// Regression: someone retunes `LAPSE_PROBE_DEADLINE`/`LAPSE_ELAPSED_CEILING` past the ~2s
    /// `VSOCK_DEFAULT_CONNECT_TIMEOUT` — the in-guest probe would then silently test the kernel
    /// `ETIMEDOUT` veto arm instead of OUR lapse arm (the exact mis-test §8's residual warns about),
    /// or below the boundary floor (an instantly-lapsed probe tests nothing in-flight).
    #[test]
    fn lapse_probe_deadline_is_inside_binding_window() {
        assert!(
            MIN_BOUNDARY_BUDGET <= LAPSE_PROBE_DEADLINE,
            "probe deadline must clear the cancellable-boundary floor"
        );
        assert!(
            LAPSE_PROBE_DEADLINE < Duration::from_secs(2),
            "probe deadline must stay under the ~2s kernel connect timer (veto-arm preemption)"
        );
        assert!(
            LAPSE_ELAPSED_CEILING < Duration::from_secs(2),
            "elapsed ceiling must stay under the ~2s kernel connect timer"
        );
        // The floor slop must leave the floor comfortably ABOVE a prompt refusal (~0–1ms) yet not
        // exceed the deadline itself — so a real lapse is attributed to OUR deadline, never a kernel
        // RST/ENODEV.
        assert!(
            LAPSE_ELAPSED_FLOOR_SLOP < LAPSE_PROBE_DEADLINE,
            "floor slop must not swallow the whole deadline (a prompt refusal must still FAIL)"
        );
        assert!(
            LAPSE_PROBE_DEADLINE - LAPSE_ELAPSED_FLOOR_SLOP >= Duration::from_millis(100),
            "floor must stay well above a prompt-refusal (~0–1ms) so the lapse is unambiguous"
        );
    }
}
