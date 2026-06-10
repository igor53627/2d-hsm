//! Killable-subprocess HARD bound for the SNP quote fetch (TASK-7.7 5b-2b-ii(d), slice (d-i)).
//!
//! The cooperative deadline in `snp_report::fetch_report_with` cannot interrupt a wedged in-kernel
//! configfs `read(outblob)` (uninterruptible/D-state — the exact failure (d) exists for). The hard bound
//! moves the fetch into a KILLABLE CHILD PROCESS and makes the **pipe fd** the cancellable boundary: the
//! parent's only blocking wait is `cancellable_boundary::poll_with_deadline(POLLIN)` on the child's pipe,
//! and on a lapse the parent SIGKILLs the child and returns retryably. Two structural rules (judge-pinned,
//! design doc §8):
//! - **The parent performs NO configfs I/O of any kind** — including orphan-entry GC, which runs inside
//!   the NEXT killable child ((d-ii)): configfs-tsm serializes provider ops, so a parent-side
//!   readdir/rmdir against a wedged provider could itself block uninterruptibly (a permanent boot hang,
//!   strictly worse than fail-closed).
//! - **No blocking `wait()` exists in scope, by type**: SIGKILL only *pends* against a D-state child, so
//!   [`ChildHandle`] exposes only `kill_best_effort` + non-blocking `try_reap` (waitpid WNOHANG);
//!   unreapable children are ABANDONED to a bounded ledger (≤ [`ABANDONED_CHILD_BUDGET`] = the driver's
//!   `MAX_BOOT_ATTEMPTS_CEILING`), and the fetch REFUSES to spawn past the budget (fail-closed).
//!
//! (d-i) ships the entire deviceless-provable harness (this file) + the entry-path refactor in
//! `snp_report` + the §8 pin revision; (d-ii) adds the configfs child mode (`agent_quote_child_main`,
//! child-self-named `twod-hsm-q-<pid>` entries, child-side prefix GC) and `HardBoundedQuoteProducer` —
//! the structural type the 5b-2c serve path will require BY NAME. No `BootQuoteProducer` impl exists in
//! (d-i) ON PURPOSE: a skeleton delegating to the cooperative fetch would satisfy the 5b-2c by-signature
//! gate while the wedged-read hang remains (the gate-lie §8 forbids).
//!
//! Consumer-free until (d-ii)/5b-2c wire it — the module-wide allow is NOT transitional leftovers: under
//! the CI leaf combo (`vsock-transport,agent-gateway`) this compiles with its only consumer not yet
//! landed, and (like `cancellable_boundary`) it must stay warning-free there.
#![cfg_attr(not(test), allow(dead_code))]

use crate::cancellable_boundary::{
    classify_pipe_revents, poll_with_deadline, remaining_or_lapsed, PipeReadiness,
    DEADLINE_LAPSED_MSG,
};
use crate::ProtocolError;
use std::time::{Duration, Instant};

// The pipe-readiness predicate (`PipeReadiness` / `classify_pipe_revents`) lives NEXT TO the shared
// primitive in `cancellable_boundary`, beside its connect twin `connect_poll_succeeded` — both halves of
// poll_with_deadline's "caller MUST inspect revents" contract are one decision table in one place (and
// the predicate stays reachable for vsock-transport-only consumers, which this module is not).

// ---------------------------------------------------------------------------------------------------
// Frame codec — pure over bytes (no fd). One reply frame per child lifetime, child → parent.
// ---------------------------------------------------------------------------------------------------

/// Status bytes are non-trivial values: zeros, libtest banners, or shell garbage on the pipe parse as
/// malformed (retryable), never mis-accepted as a frame.
const FRAME_STATUS_OK: u8 = 0xA1;
const FRAME_STATUS_ERR: u8 = 0xA2;

/// Maximum legal frame: status + report_len + report + chain_len + chain. Derived, never a literal —
/// 1 + 4 + 8192 + 4 + 65536 = 73,737 bytes, which EXCEEDS the minimum legal pipe capacity (4 KiB) and
/// the common default (64 KiB): incremental draining in [`read_child_reply`] is therefore load-bearing,
/// not an optimization (a wait-for-EOF-then-read parent deadlocks against the child's blocked
/// `write_all` by construction).
pub(crate) const MAX_QUOTE_FRAME_LEN: usize =
    1 + 4 + crate::snp_report::MAX_OUTBLOB_LEN + 4 + crate::snp_report::MAX_CERT_CHAIN_LEN;

/// A decoded child reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildReply {
    /// Successful fetch: the raw SNP report (outblob) + best-effort cert chain (auxblob; may be empty).
    Quote { report: Vec<u8>, cert_chain: Vec<u8> },
    /// The child reported a step failure (fixed code table, mapped to static strings at parse time so
    /// the parent never invents triage text).
    ChildError(&'static str),
}

/// Incremental parse progress over the accumulated bytes so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FrameProgress {
    /// Not enough bytes yet — keep draining (header length fields are validated as soon as their bytes
    /// arrive; a lying prefix can never force an allocation).
    NeedMore,
    /// A complete frame was parsed — and the accumulator held EXACTLY the frame: the parser itself
    /// rejects trailing bytes (single-frame protocol; the invariant lives in ONE place). NB this is
    /// per-drain-window best-effort: junk the child writes AFTER the frame-completing chunk is never
    /// observed, because the drain deliberately returns at Complete without waiting for EOF (budget) —
    /// see `read_child_reply`'s doc.
    Complete { reply: ChildReply },
}

/// Map a child ERR code to the parent-side static triage string (fixed table; unknown codes fold to a
/// generic string rather than erroring the PARSE — the child already failed, triage must survive).
fn child_err_str(code: u8) -> &'static str {
    match code {
        1 => "quote child: bad env input",
        2 => "quote child: entry create failed",
        3 => "quote child: inblob write failed",
        4 => "quote child: outblob read failed",
        5 => "quote child: outblob oversize",
        6 => "quote child: outblob short",
        _ => "quote child: unknown error code",
    }
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Incremental, cap-before-alloc frame parser. Length fields are validated against the crate ABI bounds
/// (`MIN_REPORT_LEN ≤ report ≤ MAX_OUTBLOB_LEN`, `chain ≤ MAX_CERT_CHAIN_LEN`) the moment their header
/// bytes are available and BEFORE any allocation. Detect-and-error, never truncate.
pub(crate) fn parse_child_frame(accum: &[u8]) -> Result<FrameProgress, ProtocolError> {
    let Some(&status) = accum.first() else {
        return Ok(FrameProgress::NeedMore);
    };
    match status {
        FRAME_STATUS_ERR => {
            if accum.len() < 2 {
                return Ok(FrameProgress::NeedMore);
            }
            if accum.len() > 2 {
                return Err(ProtocolError::WireProtocol("quote child: trailing bytes after frame"));
            }
            Ok(FrameProgress::Complete { reply: ChildReply::ChildError(child_err_str(accum[1])) })
        }
        FRAME_STATUS_OK => {
            if accum.len() < 1 + 4 {
                return Ok(FrameProgress::NeedMore);
            }
            let report_len = be_u32(&accum[1..5]) as usize;
            if report_len < crate::snp_report::MIN_REPORT_LEN {
                return Err(ProtocolError::WireProtocol("quote child: report below ABI minimum"));
            }
            if report_len > crate::snp_report::MAX_OUTBLOB_LEN {
                return Err(ProtocolError::WireProtocol("quote child: report length over cap"));
            }
            let chain_at = 1 + 4 + report_len;
            if accum.len() < chain_at + 4 {
                return Ok(FrameProgress::NeedMore);
            }
            let chain_len = be_u32(&accum[chain_at..chain_at + 4]) as usize;
            if chain_len > crate::snp_report::MAX_CERT_CHAIN_LEN {
                return Err(ProtocolError::WireProtocol("quote child: cert chain length over cap"));
            }
            let total = chain_at + 4 + chain_len;
            if accum.len() < total {
                return Ok(FrameProgress::NeedMore);
            }
            if accum.len() > total {
                return Err(ProtocolError::WireProtocol("quote child: trailing bytes after frame"));
            }
            Ok(FrameProgress::Complete {
                reply: ChildReply::Quote {
                    report: accum[5..5 + report_len].to_vec(),
                    cert_chain: accum[chain_at + 4..total].to_vec(),
                },
            })
        }
        _ => Err(ProtocolError::WireProtocol("quote child: malformed frame status")),
    }
}

/// Encode the OK frame ((d-ii)'s child mode calls this; tests pin the golden bytes now so the two halves
/// living in different processes cannot drift).
pub(crate) fn encode_ok_frame(report: &[u8], cert_chain: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if report.len() < crate::snp_report::MIN_REPORT_LEN
        || report.len() > crate::snp_report::MAX_OUTBLOB_LEN
    {
        return Err(ProtocolError::WireProtocol("quote child: encode report length out of range"));
    }
    if cert_chain.len() > crate::snp_report::MAX_CERT_CHAIN_LEN {
        return Err(ProtocolError::WireProtocol("quote child: encode cert chain over cap"));
    }
    let mut out = Vec::with_capacity(1 + 4 + report.len() + 4 + cert_chain.len());
    out.push(FRAME_STATUS_OK);
    out.extend_from_slice(&(report.len() as u32).to_be_bytes());
    out.extend_from_slice(report);
    out.extend_from_slice(&(cert_chain.len() as u32).to_be_bytes());
    out.extend_from_slice(cert_chain);
    Ok(out)
}

/// Encode the ERR frame (2 bytes).
pub(crate) fn encode_err_frame(code: u8) -> [u8; 2] {
    [FRAME_STATUS_ERR, code]
}

// ---------------------------------------------------------------------------------------------------
// Deadline-bounded incremental drain.
// ---------------------------------------------------------------------------------------------------

/// Read one child reply frame off `pipe`, hard-bounded by the absolute `deadline`:
/// `poll_with_deadline(POLLIN, deadline)` → [`classify_pipe_revents`] → `read` ≤ 4096 B → incremental
/// [`parse_child_frame`], looping with the SAME absolute deadline throughout (partial data never extends
/// it). At `Complete` the fn returns WITHOUT waiting for EOF (no budget spent on a child that keeps
/// talking) — so the parser's trailing-byte rejection is **per-drain-window best-effort, not an
/// invariant**: junk the child writes AFTER the frame-completing chunk is never observed (the
/// echo-verify and downstream report verification bound the damage; a post-`Complete` extra read was
/// considered and rejected — it narrows the race by nanoseconds, needs a third readiness outcome, and
/// taxes every successful fetch). `read() == 0` before `Complete` ⇒ the writer
/// died mid-frame (retryable). A deadline lapse passes through as the helper's neutral
/// [`DEADLINE_LAPSED_MSG`] UNRELABELED — the orchestration applies the single connect-style relabel arm.
/// Generic over `AsFd + Read`: production drains a `ChildStdout`, the CI smokes a `ChildStderr`, and the
/// in-process tests a `UnixStream` — same code path.
pub(crate) fn read_child_reply<R: std::os::fd::AsFd + std::io::Read>(
    pipe: &mut R,
    deadline: Instant,
) -> Result<ChildReply, ProtocolError> {
    let mut accum: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let revents = poll_with_deadline(pipe, nix::poll::PollFlags::POLLIN, deadline)?;
        match classify_pipe_revents(revents) {
            PipeReadiness::BrokenFd => {
                return Err(ProtocolError::WireProtocol("quote child: pipe fd broken"));
            }
            PipeReadiness::ReadNow => {}
        }
        match pipe.read(&mut buf) {
            // EOF: legitimate only AFTER a complete frame (which returns below) — here it means the
            // writer died mid-frame.
            Ok(0) => return Err(ProtocolError::WireProtocol("quote child: pipe closed mid-frame")),
            Ok(n) => {
                accum.extend_from_slice(&buf[..n]);
                if let FrameProgress::Complete { reply } = parse_child_frame(&accum)? {
                    return Ok(reply);
                }
            }
            // The parent read end is O_NONBLOCK (belt-and-braces vs. spurious poll wakeups) and poll
            // can be interrupted — both re-poll under the same absolute deadline.
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ProtocolError::WireProtocol("quote child: pipe read failed")),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Spawn / kill / reap seams. NO blocking wait exists behind these types, by construction.
// ---------------------------------------------------------------------------------------------------

/// Result of a non-blocking reap attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReapOutcome {
    Exited,
    Running,
}

/// Parent-side child handle. Deliberately does NOT expose `wait()`/`wait_with_output()` — both are
/// unbounded against a D-state child (SIGKILL pends until the wedged syscall returns), and excluding
/// them BY TYPE is what makes "no blocking wait in the (d) path" a structural property instead of a
/// review rule.
pub(crate) trait ChildHandle {
    /// Best-effort SIGKILL. The `Result` is deliberately discarded — `Child::kill()`'s Ok-vs-Err after
    /// the child is already reaped is std-version-dependent; ALL reap/ledger logic keys off
    /// [`ChildHandle::try_reap`] exclusively.
    fn kill_best_effort(&mut self);
    /// Non-blocking reap (waitpid WNOHANG). An anomalous `try_wait` Err folds to `Running` — the handle
    /// is KEPT in the ledger (fail-closed: a pathological waitpid pins a slot toward the budget refuse,
    /// never silently forgets a possibly-live child).
    fn try_reap(&mut self) -> ReapOutcome;
}

/// Spawn seam: production execs `/proc/self/exe` in child mode ((d-ii)); the CI smokes spawn the test
/// binary's env-guarded helper tests. No entry-name parameter — the child SELF-NAMES its configfs entry
/// (`twod-hsm-q-<its own pid>`), which deletes the parent→child name plumbing and its validation surface.
pub(crate) trait QuoteChildSpawn {
    type Pipe: std::os::fd::AsFd + std::io::Read;
    type Handle: ChildHandle;
    fn spawn(&self, report_data: &[u8; 64]) -> Result<(Self::Pipe, Self::Handle), ProtocolError>;
}

/// Abandoned (killed-but-not-yet-reapable) children, bounded. Entries hold pid + status memory only —
/// the pipe fd is dropped before abandonment, so a ledger slot pins ZERO fds (a slot DOES pin a pid /
/// potential zombie until a later sweep or process exit — bounded by the budget; systemd reaps at exit).
///
/// **Lifecycle pins (the budget only binds if these hold):** there must be EXACTLY ONE ledger per
/// process, living as long as the boot path — (d-ii)'s `HardBoundedQuoteProducer` owns it; constructing
/// a fresh ledger per attempt would reset `is_full()` and void the cap (see §8). There is no terminal
/// sweep after the LAST fetch: children abandoned on late attempts stay zombies until process exit —
/// `Drop` below runs one final best-effort kill+reap pass to shrink that window, but a still-wedged
/// child is structurally unreapable and is left to pid-1.
pub(crate) struct AbandonedLedger<H: ChildHandle> {
    children: Vec<H>,
}

impl<H: ChildHandle> Drop for AbandonedLedger<H> {
    /// Final best-effort pass (non-blocking — one kill + one WNOHANG reap per child): reclaims every
    /// since-un-wedged child at end of life instead of leaving them zombies for the process lifetime.
    /// Cannot help a still-wedged child (nothing non-blocking can) — that one reparents to pid 1 at
    /// process exit.
    fn drop(&mut self) {
        for h in &mut self.children {
            h.kill_best_effort();
            let _ = h.try_reap();
        }
    }
}

/// Hard cap on abandoned children per process. DERIVED from the driver ceiling (≤ 1 child per fetch ×
/// ≤ `MAX_BOOT_ATTEMPTS_CEILING` attempts per handshake — the driver REJECTS larger `max_attempts`, it
/// does not clamp) and additionally pinned by an assert test so a future literal refactor cannot drift
/// them apart silently. Reaching the cap REFUSES further spawns (retryable error → the driver's bounded
/// retries → fail-closed `RetriesExhausted`): for a custody HSM, refusing to boot beats forgetting a
/// possibly-live child — and it closes the cross-run accumulation hole if a caller ever loops handshakes.
pub(crate) const ABANDONED_CHILD_BUDGET: usize =
    crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING as usize;

/// Bounded post-kill reap grace: `try_reap` is polled every ~1ms for at most this long before the child
/// is abandoned to the ledger. Empirically an S-state child is reapable ~1.3ms after SIGKILL — 10ms is
/// ~7× headroom, so a CLEANLY killed child is reaped on the spot (no success-path zombie, no ledger
/// churn), while a D-state child costs at most 10ms before abandonment. This grace is the dominant term
/// of the per-attempt overhead [`QUOTE_ATTEMPT_OVERHEAD`] (spawn + kill + grace + fd close), which lands
/// BETWEEN the quote and channel legs; 5b-2c's budget check carries it as the explicit
/// `max_attempts · ε` term.
pub(crate) const REAP_GRACE: Duration = Duration::from_millis(10);

/// ε — the per-attempt quote-subprocess overhead the 5b-2c budget check MUST carry as an explicit term:
/// `max_attempts · (2·timeout + ε) ≤ overall_boot_budget` (§8). DERIVED from its dominant term (the reap
/// grace) plus a ~2ms margin for spawn + SIGKILL + fd close, so a future `REAP_GRACE` retune cannot
/// silently strand a stale literal in the budget arithmetic — the same derive-don't-transcribe rule as
/// [`ABANDONED_CHILD_BUDGET`]. 5b-2c consumes THIS const, never a hand-copied number.
pub(crate) const QUOTE_ATTEMPT_OVERHEAD: Duration =
    REAP_GRACE.saturating_add(Duration::from_millis(2));

impl<H: ChildHandle> AbandonedLedger<H> {
    pub(crate) fn new() -> Self {
        Self { children: Vec::new() }
    }
    /// O(≤budget) WNOHANG sweep: drop every since-exited child, keep the rest. Run at every fetch start
    /// so un-wedged children are reclaimed promptly.
    pub(crate) fn sweep(&mut self) {
        self.children.retain_mut(|h| h.try_reap() == ReapOutcome::Running);
    }
    pub(crate) fn abandon(&mut self, h: H) {
        self.children.push(h);
    }
    pub(crate) fn is_full(&self) -> bool {
        self.children.len() >= ABANDONED_CHILD_BUDGET
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.children.len()
    }
}

/// RAII guard from spawn until disposition: if the parent panics (or any early `?` escapes) between
/// spawn and the normal disposition, Drop fires `kill_best_effort` + ONE best-effort `try_reap`.
/// **Honest contract: the KILL is guaranteed, the reap is best-effort** — a just-killed child is
/// typically reapable only ~1.3ms later, so the single zero-delay WNOHANG on the panic path usually
/// returns `Running` and the dead child stays an unledgered zombie until process exit (no LIVE orphan
/// survives, but the zombie is invisible to the budget — accepted: panics here are program bugs, not a
/// host-drivable path). Disarmed via [`KillOnDrop::into_inner`] on the normal path. (Drop does NOT run
/// under parent SIGKILL — systemd, pid 1 in the NixOS guest, reaps the ≤1 leaked child.)
pub(crate) struct KillOnDrop<H: ChildHandle>(Option<H>);

impl<H: ChildHandle> KillOnDrop<H> {
    pub(crate) fn new(h: H) -> Self {
        Self(Some(h))
    }
    pub(crate) fn into_inner(mut self) -> H {
        self.0.take().expect("KillOnDrop consumed twice")
    }
    /// Access the still-guarded handle (e.g. to take the pipe end or poll a test child) without
    /// disarming the kill-on-panic guarantee.
    pub(crate) fn get_mut(&mut self) -> &mut H {
        self.0.as_mut().expect("KillOnDrop consumed")
    }
}

impl<H: ChildHandle> Drop for KillOnDrop<H> {
    fn drop(&mut self) {
        if let Some(mut h) = self.0.take() {
            h.kill_best_effort();
            let _ = h.try_reap();
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Core orchestration — generic over the spawn seam so (d-i) ships AND fully tests it without configfs.
// ---------------------------------------------------------------------------------------------------

/// Uniform disposition — runs on EVERY path including success (a kill-free success path would let a
/// child that already wrote its frame linger if it wedges in its own cleanup): SIGKILL → bounded reap
/// (poll `try_reap` every ~1ms, ≤ [`REAP_GRACE`] total) → if still `Running`, abandon to the ledger.
fn dispose_child<H: ChildHandle>(mut h: H, ledger: &mut AbandonedLedger<H>) {
    h.kill_best_effort();
    let start = Instant::now();
    loop {
        if h.try_reap() == ReapOutcome::Exited {
            return;
        }
        if start.elapsed() >= REAP_GRACE {
            ledger.abandon(h);
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Fetch one SNP quote via a killable child, HARD-bounded by the absolute `deadline` (the exact
/// seam-minted `Instant` — never re-minted here, so the driver's budget arithmetic holds):
///
/// 0. fast-path: an already-lapsed deadline errs BEFORE any side effect (no sweep, no spawn);
/// 1. sweep the abandoned ledger (reclaim since-un-wedged children);
/// 2. refuse (retryable) if the ledger is full — BEFORE spawning;
/// 3. spawn the child (RAII [`KillOnDrop`] guard from this instant);
/// 4. [`read_child_reply`] on the pipe, same absolute deadline;
/// 5. drop the pipe (parent read fd closed — a ledger slot pins ZERO fds; an un-wedged orphan dies to
///    its pending SIGKILL before any userspace write, and if that kill somehow failed it exits at its
///    first FAILED write: Rust ignores SIGPIPE — std re-ignores it in the re-exec'd child — so EPIPE is
///    an `Err`, not a kernel kill; the (d-ii) child pins ANY write error ⇒ immediate nonzero exit);
/// 6. UNCONDITIONAL disposition (kill → bounded reap → abandon), success included;
/// 7. on `Quote`: re-check `len ≥ MIN_REPORT_LEN`, then ECHO-VERIFY the report's embedded report_data
///    against the requested one (a corrupted pipe or misrouted report must not enter the relay request);
/// 8. single relabel arm: the helper-neutral [`DEADLINE_LAPSED_MSG`] becomes
///    `"anchor relay: quote pipe deadline lapsed"` by exact-const match (the `connect_bounded` pattern) —
///    all other errors pass through with their own triage strings.
pub(crate) fn fetch_quote_via_child<S: QuoteChildSpawn>(
    spawn: &S,
    ledger: &mut AbandonedLedger<S::Handle>,
    report_data: &[u8; 64],
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    fetch_quote_via_child_inner(spawn, ledger, report_data, deadline).map_err(|e| match e {
        ProtocolError::WireProtocol(DEADLINE_LAPSED_MSG) => {
            ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")
        }
        other => other,
    })
}

fn fetch_quote_via_child_inner<S: QuoteChildSpawn>(
    spawn: &S,
    ledger: &mut AbandonedLedger<S::Handle>,
    report_data: &[u8; 64],
    deadline: Instant,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    // (0) Fast-path BEFORE any side effect (relabelled by the caller's single arm).
    remaining_or_lapsed(deadline)?;
    // (0b) Recursion brake at the POLICY level: inside a quote child the marker env is set — refuse to
    // fetch at all. ExecChildSpawn::spawn carries the same check for direct-seam use, but the seam
    // exists to permit other spawner impls, and a future impl that faithfully implements the trait
    // contract would otherwise lose the depth-1 guarantee (the orchestration owns the policy).
    if std::env::var_os(QUOTE_CHILD_ENV).is_some() {
        return Err(ProtocolError::WireProtocol("quote child: fetch refused inside child"));
    }
    // (1) Reclaim since-un-wedged children, then (2) enforce the budget BEFORE spawning.
    ledger.sweep();
    if ledger.is_full() {
        return Err(ProtocolError::WireProtocol("quote child: abandoned-child budget exhausted"));
    }
    // (3) Spawn under the RAII guard.
    let (mut pipe, handle) = spawn.spawn(report_data)?;
    let guard = KillOnDrop::new(handle);
    // (4) Drain one frame, hard-bounded.
    let reply = read_child_reply(&mut pipe, deadline);
    // (5) Close the parent read end BEFORE disposition: ledger slots must pin zero fds. (Orphan death
    // is owned by the pending SIGKILL on un-wedge; the closed pipe is the BACKSTOP — a surviving
    // orphan's next write returns Err(EPIPE), NOT a kernel kill (Rust ignores SIGPIPE), and the (d-ii)
    // child contract pins ANY write error ⇒ immediate nonzero exit. The test helper honors it via
    // unwrap-panic → libtest failure → nonzero exit.)
    drop(pipe);
    // (6) Uniform disposition on EVERY path, success included.
    dispose_child(guard.into_inner(), ledger);
    // (7) Post-disposition validation.
    match reply? {
        ChildReply::ChildError(msg) => Err(ProtocolError::WireProtocol(msg)),
        ChildReply::Quote { report, cert_chain } => {
            if report.len() < crate::snp_report::MIN_REPORT_LEN {
                return Err(ProtocolError::WireProtocol("quote child: report below ABI minimum"));
            }
            let echoed = crate::snp_report::report_data_from_report(&report)
                .map_err(|_| ProtocolError::WireProtocol("quote child: report_data echo unreadable"))?;
            if &echoed != report_data {
                return Err(ProtocolError::WireProtocol("quote child: report_data echo mismatch"));
            }
            Ok((report, cert_chain))
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The real-process leaf. CI-provable for S-state children; true D-state is only deterministically
// covered by the Fake seams above (stated honestly — see the test docs).
// ---------------------------------------------------------------------------------------------------

/// Marker env var: set in every spawned quote child. Doubles as the anti-fork-bomb brake — a spawner
/// REFUSES to spawn when the marker is already set in its OWN environment, capping accidental recursion
/// at depth 1 even if the 5b-2c bin forgets its child-mode dispatch.
pub(crate) const QUOTE_CHILD_ENV: &str = "TWOD_HSM_QUOTE_CHILD";
/// The 64-byte report_data, hex-encoded (128 chars). Env, not argv: the cargo-test child's argv is owned
/// by libtest, so ONE child contract serves both worlds. Non-secret (a domain-separated public-key hash
/// that appears verbatim in the report).
pub(crate) const QUOTE_CHILD_REPORT_DATA_ENV: &str = "TWOD_HSM_QUOTE_CHILD_REPORT_DATA";

/// Which std stream the child writes its protocol frame to. Production ((d-ii)) uses `Stdout`; the CI
/// smokes use `Stderr` because the spawned TEST binary's stdout carries the unstable libtest banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipeSource {
    /// Constructed by (d-ii)'s `ExecChildSpawn::production()` — until then only the test smokes build a
    /// `PipeSource` (always `Stderr`), so this variant is allowed dead in TEST builds too (the
    /// module-level allow covers only `not(test)`).
    #[allow(dead_code)]
    Stdout,
    Stderr,
}

/// The parent's read end, either way implementing `AsFd + Read` by delegation.
pub(crate) enum QuotePipe {
    Stdout(std::process::ChildStdout),
    Stderr(std::process::ChildStderr),
}

impl std::os::fd::AsFd for QuotePipe {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match self {
            QuotePipe::Stdout(s) => s.as_fd(),
            QuotePipe::Stderr(s) => s.as_fd(),
        }
    }
}

impl std::io::Read for QuotePipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            QuotePipe::Stdout(s) => s.read(buf),
            QuotePipe::Stderr(s) => s.read(buf),
        }
    }
}

/// [`ChildHandle`] over a real `std::process::Child`.
pub(crate) struct StdChildHandle(std::process::Child);

/// The `try_wait` → [`ReapOutcome`] fold, extracted pure so the fail-closed Err arm is unit-testable
/// (an anomalous waitpid Err cannot be staged on a real `Child`): `Err` folds to `Running` — the handle
/// is KEPT (a pathological waitpid pins a ledger slot toward the budget refuse; it never silently
/// forgets a possibly-live child).
fn fold_try_wait(r: std::io::Result<Option<std::process::ExitStatus>>) -> ReapOutcome {
    match r {
        Ok(Some(_)) => ReapOutcome::Exited,
        Ok(None) | Err(_) => ReapOutcome::Running,
    }
}

impl ChildHandle for StdChildHandle {
    fn kill_best_effort(&mut self) {
        // Result deliberately discarded — see the trait doc (Ok-vs-Err after reap is version-dependent).
        let _ = self.0.kill();
    }
    fn try_reap(&mut self) -> ReapOutcome {
        fold_try_wait(self.0.try_wait())
    }
}

#[cfg(test)]
impl StdChildHandle {
    /// Test-only: non-blocking poll of the exit status (for the SIGKILL-evidence smoke).
    fn try_status(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }
}

/// Hex-encode 64 bytes → 128 lowercase hex chars. Local helper on purpose: the `hex` crate is NOT an
/// `agent-gateway` dependency and 10 lines do not justify enabling it.
fn hex128(data: &[u8; 64]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(128);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// ONE spawner struct for production AND tests — the fields are the only difference between worlds, so
/// the aya smoke of (d-ii)'s shipped producer exercises the same code the production boot runs.
/// `spawn()`: brake-check → `Command { program, leading_args }` → optional `env_clear` → marker +
/// report_data + `extra_env` → `stdin = null` → pipe per [`PipeSource`] (the OTHER stream: production
/// `Stdout`-pipe inherits stderr → guest journald for kill-storm triage [user decision]; test
/// `Stderr`-pipe nulls stdout to suppress the libtest banner) → set the parent read end `O_NONBLOCK`
/// (belt-and-braces; the drain re-polls on `WouldBlock`).
pub(crate) struct ExecChildSpawn {
    pub(crate) program: std::path::PathBuf,
    pub(crate) leading_args: Vec<std::ffi::OsString>,
    pub(crate) extra_env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub(crate) pipe_source: PipeSource,
    pub(crate) clear_env: bool,
}

impl QuoteChildSpawn for ExecChildSpawn {
    type Pipe = QuotePipe;
    type Handle = StdChildHandle;

    fn spawn(&self, report_data: &[u8; 64]) -> Result<(Self::Pipe, Self::Handle), ProtocolError> {
        // Anti-fork-bomb brake: inside a quote child the marker is set — refuse to recurse.
        if std::env::var_os(QUOTE_CHILD_ENV).is_some() {
            return Err(ProtocolError::WireProtocol("quote child: spawn refused inside child"));
        }
        let mut cmd = std::process::Command::new(&self.program);
        cmd.args(&self.leading_args);
        if self.clear_env {
            cmd.env_clear();
        }
        // extra_env FIRST, reserved keys LAST: the spawner-computed marker + report_data always win —
        // a caller plumbing debug env through extra_env must not be able to override them (a stale
        // report_data override would surface as a misleading "echo mismatch" pointing at the pipe).
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }
        cmd.env(QUOTE_CHILD_ENV, "1");
        cmd.env(QUOTE_CHILD_REPORT_DATA_ENV, hex128(report_data));
        cmd.stdin(std::process::Stdio::null());
        match self.pipe_source {
            PipeSource::Stdout => {
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::inherit());
            }
            PipeSource::Stderr => {
                cmd.stderr(std::process::Stdio::piped());
                cmd.stdout(std::process::Stdio::null());
            }
        }
        let child = cmd
            .spawn()
            .map_err(|_| ProtocolError::WireProtocol("quote child: spawn failed"))?;
        // Guard the child from THE INSTANT it exists: the pipe-take and fcntl steps below are fallible,
        // and an early `?` would otherwise drop a LIVE child (std Child::Drop neither kills nor reaps)
        // outside both the kill discipline and the ledger budget — the exact custody leak this module
        // exists to prevent. On those error paths the guard's Drop fires kill + best-effort reap (the
        // child is milliseconds old and necessarily still S-state, so the kill lands).
        let mut guard = KillOnDrop::new(StdChildHandle(child));
        let pipe = match self.pipe_source {
            PipeSource::Stdout => guard.get_mut().0.stdout.take().map(QuotePipe::Stdout),
            PipeSource::Stderr => guard.get_mut().0.stderr.take().map(QuotePipe::Stderr),
        }
        .ok_or(ProtocolError::WireProtocol("quote child: pipe end missing after spawn"))?;
        // O_NONBLOCK on the parent read end (safe nix fcntl; `fs` feature). Belt-and-braces: poll says
        // readable before every read, but a spurious wakeup must re-poll, not block.
        {
            use nix::fcntl::{fcntl, FcntlArg, OFlag};
            let flags = fcntl(&pipe, FcntlArg::F_GETFL)
                .map_err(|_| ProtocolError::WireProtocol("quote child: F_GETFL failed"))?;
            let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
            fcntl(&pipe, FcntlArg::F_SETFL(flags))
                .map_err(|_| ProtocolError::WireProtocol("quote child: F_SETFL failed"))?;
        }
        Ok((pipe, guard.into_inner()))
    }
}

// ---------------------------------------------------------------------------------------------------
// Tests. Deviceless — run by the existing CI leaf step (`--features vsock-transport,agent-gateway`).
// Every test names the regression it discriminates. HONESTY NOTE (the discriminating-test rule): a true
// D-state child cannot be staged on demand in ANY environment (CI or aya) — the unreapable arm's only
// deterministic coverage is the Fake-handle ledger tests below; the real-subprocess smokes prove
// S-state behavior (sleeping children) and the plumbing.
// ---------------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    fn future() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// A structurally-valid report of `len` zeros with `rd` spliced at the ABI offset, so
    /// `report_data_from_report` reads back exactly `rd` — the ONE splice site for every fixture
    /// (a report-ABI change is a one-place edit, and all tests pin the same wire shape).
    fn test_report_of_len(len: usize, rd: &[u8; 64]) -> Vec<u8> {
        let mut r = vec![0u8; len];
        r[crate::snp_report::REPORT_DATA_OFFSET..crate::snp_report::REPORT_DATA_OFFSET + 64]
            .copy_from_slice(rd);
        r
    }

    /// The minimal valid report (MIN_REPORT_LEN).
    fn test_report(rd: &[u8; 64]) -> Vec<u8> {
        test_report_of_len(crate::snp_report::MIN_REPORT_LEN, rd)
    }

    // ---- frame codec (pure; the readiness-predicate tests live with the predicate in
    //      cancellable_boundary) ----

    #[test]
    fn frame_ok_roundtrip_golden_bytes() {
        // Regression: silent wire drift between the parent/child halves living in different processes
        // (and, after (d-ii), different PRs). Pin the exact header bytes + roundtrip identity.
        let rd = [0x11u8; 64];
        let report = test_report(&rd);
        let chain = vec![0xCC, 0xDD, 0xEE];
        let frame = encode_ok_frame(&report, &chain).expect("encode");
        // Golden header: status 0xA1, report_len = MIN_REPORT_LEN (192) as BE u32.
        assert_eq!(frame[0], 0xA1, "status byte is pinned wire ABI");
        assert_eq!(&frame[1..5], &(192u32).to_be_bytes(), "report_len BE header pinned");
        assert_eq!(frame.len(), 1 + 4 + 192 + 4 + 3);
        assert_eq!(&frame[1 + 4 + 192..1 + 4 + 192 + 4], &(3u32).to_be_bytes());
        match parse_child_frame(&frame).expect("parse") {
            FrameProgress::Complete { reply: ChildReply::Quote { report: r, cert_chain: c } } => {
                assert_eq!(r, report);
                assert_eq!(c, chain);
            }
            other => panic!("expected Complete/Quote, got {other:?}"),
        }
        // The parser OWNS the trailing-byte rejection (single-frame protocol, one place): the exact
        // frame parses, one extra byte errors.
        let mut with_junk = frame.clone();
        with_junk.push(0x00);
        assert!(
            matches!(
                parse_child_frame(&with_junk),
                Err(ProtocolError::WireProtocol("quote child: trailing bytes after frame"))
            ),
            "parser must reject trailing bytes itself"
        );
        // Empty cert_chain roundtrips (auxblob is best-effort).
        let frame2 = encode_ok_frame(&report, &[]).expect("encode empty chain");
        match parse_child_frame(&frame2).expect("parse") {
            FrameProgress::Complete { reply: ChildReply::Quote { cert_chain, .. }, .. } => {
                assert!(cert_chain.is_empty());
            }
            other => panic!("expected Complete/Quote, got {other:?}"),
        }
        // Max-size payloads roundtrip (the frame the >64KiB drain test depends on being legal).
        let max_report = test_report_of_len(crate::snp_report::MAX_OUTBLOB_LEN, &rd);
        let max_chain = vec![0xAB; crate::snp_report::MAX_CERT_CHAIN_LEN];
        let max_frame = encode_ok_frame(&max_report, &max_chain).expect("encode max");
        assert_eq!(max_frame.len(), MAX_QUOTE_FRAME_LEN, "derived max-frame const matches encoder");
        match parse_child_frame(&max_frame).expect("parse max") {
            FrameProgress::Complete { reply: ChildReply::Quote { report: r, cert_chain: c }, .. } => {
                assert_eq!(r.len(), crate::snp_report::MAX_OUTBLOB_LEN);
                assert_eq!(c.len(), crate::snp_report::MAX_CERT_CHAIN_LEN);
            }
            other => panic!("expected Complete/Quote, got {other:?}"),
        }
    }

    #[test]
    fn frame_report_len_over_max_rejected_at_header() {
        // Regression: cap-before-alloc bypass via a lying prefix — the parse must error the moment the
        // header bytes are available, never allocate toward the claimed length.
        let mut frame = vec![0xA1];
        frame.extend_from_slice(&((crate::snp_report::MAX_OUTBLOB_LEN as u32) + 1).to_be_bytes());
        assert!(parse_child_frame(&frame).is_err(), "oversize report_len must error at header time");
    }

    #[test]
    fn frame_chain_len_over_max_rejected_at_header() {
        // Regression: same bypass on the 64 KiB cert-chain cap.
        let rd = [0u8; 64];
        let report = test_report(&rd);
        let mut frame = vec![0xA1];
        frame.extend_from_slice(&(report.len() as u32).to_be_bytes());
        frame.extend_from_slice(&report);
        frame.extend_from_slice(&((crate::snp_report::MAX_CERT_CHAIN_LEN as u32) + 1).to_be_bytes());
        assert!(parse_child_frame(&frame).is_err(), "oversize chain_len must error at header time");
    }

    #[test]
    fn frame_report_len_below_abi_min_rejected() {
        // Regression: a garbled short report parsed as success (it could not even carry report_data).
        let mut frame = vec![0xA1];
        frame.extend_from_slice(&((crate::snp_report::MIN_REPORT_LEN as u32) - 1).to_be_bytes());
        assert!(parse_child_frame(&frame).is_err(), "below-ABI-min report_len must error");
    }

    #[test]
    fn frame_unknown_status_byte_malformed() {
        // Regression: banner/garbage-class first byte mis-parsed instead of erroring retryably —
        // 0x00 (zeros), ASCII (libtest banner "r" of "running"), etc.
        for status in [0x00u8, b'r', 0xFF, 0xA0] {
            assert!(parse_child_frame(&[status]).is_err(), "status {status:#x} must be malformed");
        }
    }

    #[test]
    fn frame_err_code_table_with_unknown_fallback() {
        // Regression: an unmapped child code losing triage or panicking the parse.
        for (code, expect) in [
            (1u8, "quote child: bad env input"),
            (4, "quote child: outblob read failed"),
            (200, "quote child: unknown error code"),
        ] {
            match parse_child_frame(&encode_err_frame(code)).expect("ERR frame parses") {
                FrameProgress::Complete { reply: ChildReply::ChildError(msg) } => {
                    assert_eq!(msg, expect);
                }
                other => panic!("expected Complete/ChildError, got {other:?}"),
            }
        }
    }

    #[test]
    fn frame_truncated_header_is_need_more() {
        // Regression: the incremental parser prematurely erroring on a legitimate partial read.
        assert_eq!(parse_child_frame(&[]).unwrap(), FrameProgress::NeedMore);
        assert_eq!(parse_child_frame(&[0xA1]).unwrap(), FrameProgress::NeedMore);
        assert_eq!(parse_child_frame(&[0xA1, 0x00, 0x00]).unwrap(), FrameProgress::NeedMore);
        assert_eq!(parse_child_frame(&[0xA2]).unwrap(), FrameProgress::NeedMore);
    }

    // ---- drain core (in-process: UnixStream::pair as the pipe; writer thread as the fake child) ----

    #[test]
    fn read_reply_final_chunk_with_eof_no_data_loss() {
        // Regression: EOF detection keyed off POLLHUP presence instead of read()==0 — the writer closes
        // immediately after the final chunk, so readiness arrives as data+closed together; every byte
        // must still be delivered.
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let rd = [0x22u8; 64];
        let frame = encode_ok_frame(&test_report(&rd), &[0x01, 0x02]).unwrap();
        let f = frame.clone();
        let w = std::thread::spawn(move || {
            b.write_all(&f).unwrap();
            // b drops here: writer closed right behind the data.
        });
        let reply = read_child_reply(&mut a, future()).expect("must parse the full frame");
        match reply {
            ChildReply::Quote { report, cert_chain } => {
                assert_eq!(report, test_report(&rd));
                assert_eq!(cert_chain, vec![0x01, 0x02]);
            }
            other => panic!("expected Quote, got {other:?}"),
        }
        w.join().unwrap();
    }

    #[test]
    fn read_reply_incremental_drain_unblocks_blocked_writer() {
        // Regression: a wait-for-EOF-then-parse parent. The max legal frame (73,737 B) EXCEEDS the
        // writer-side buffer, so the child's blocking write_all can only complete if the parent drains
        // INCREMENTALLY while the writer is still writing — a non-draining parent deadlocks here (the
        // test then fails by deadline, not by hanging CI). The buffer is shrunk to make the discriminator
        // bite far below the frame size (a <=buffer-sized "trickle" frame would discriminate NOTHING).
        let (mut a, b) = UnixStream::pair().unwrap();
        nix::sys::socket::setsockopt(&b, nix::sys::socket::sockopt::SndBuf, &4096)
            .expect("shrink writer SndBuf");
        let rd = [0x33u8; 64];
        let report = test_report_of_len(crate::snp_report::MAX_OUTBLOB_LEN, &rd);
        let chain = vec![0x77; crate::snp_report::MAX_CERT_CHAIN_LEN];
        let frame = encode_ok_frame(&report, &chain).unwrap();
        assert_eq!(frame.len(), MAX_QUOTE_FRAME_LEN, "must exercise the max frame");
        let mut bw = b;
        let w = std::thread::spawn(move || {
            bw.write_all(&frame).expect("writer completes ONLY if the parent drains incrementally");
        });
        let reply = read_child_reply(&mut a, Instant::now() + Duration::from_secs(10))
            .expect("incremental drain must reassemble the max frame");
        match reply {
            ChildReply::Quote { report: r, cert_chain: c } => {
                assert_eq!(r.len(), crate::snp_report::MAX_OUTBLOB_LEN);
                assert_eq!(c.len(), crate::snp_report::MAX_CERT_CHAIN_LEN);
            }
            other => panic!("expected Quote, got {other:?}"),
        }
        w.join().unwrap();
    }

    #[test]
    fn read_reply_trailing_bytes_after_frame_rejected() {
        // Regression: a corrupt/malicious child's trailing bytes silently tolerated when they land in
        // the drain window. PREMISE this test rests on (Linux-only module, deterministic there): the
        // single write_all below is one ≤16KiB skb on AF_UNIX, delivered whole by one read — so frame
        // and junk arrive in the SAME chunk. Junk written in a LATER chunk is deliberately out of scope
        // (the drain returns at Complete without waiting EOF — per-window best-effort, see the fn doc).
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let rd = [0x44u8; 64];
        let mut bytes = encode_ok_frame(&test_report(&rd), &[]).unwrap();
        bytes.extend_from_slice(b"junk");
        let w = std::thread::spawn(move || {
            b.write_all(&bytes).unwrap();
        });
        let err = read_child_reply(&mut a, future()).expect_err("trailing bytes must be rejected");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: trailing bytes after frame")),
            "got {err:?}"
        );
        w.join().unwrap();
    }

    #[test]
    fn read_reply_eof_mid_frame_is_retryable() {
        // Regression: a writer that died mid-frame accepted as a truncated quote — or hanging forever.
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let rd = [0x55u8; 64];
        let frame = encode_ok_frame(&test_report(&rd), &[0xAA; 8]).unwrap();
        let half = frame.len() / 2;
        let w = std::thread::spawn(move || {
            b.write_all(&frame[..half]).unwrap();
            // b drops: EOF mid-frame.
        });
        let err = read_child_reply(&mut a, future()).expect_err("mid-frame EOF must error");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: pipe closed mid-frame")),
            "got {err:?}"
        );
        w.join().unwrap();
    }

    #[test]
    fn read_reply_silent_writer_lapses_at_deadline() {
        // THE unbounded block (d) exists to kill: no bytes ever arrive; the drain must return the
        // helper-neutral lapse at ~the deadline (NOT hang) — and this pins the DEADLINE_LAPSED_MSG
        // const coupling the orchestration's relabel arm depends on.
        let (mut a, _b_keepalive) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let err = read_child_reply(&mut a, start + Duration::from_millis(100))
            .expect_err("silent writer must lapse");
        assert!(
            matches!(err, ProtocolError::WireProtocol(DEADLINE_LAPSED_MSG)),
            "must surface the UNRELABELED shared lapse const, got {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "must return at the deadline, not hang");
    }

    #[test]
    fn read_reply_partial_bytes_do_not_extend_deadline() {
        // Regression: per-read deadline re-minting — half a frame early must NOT buy the writer more
        // time; the lapse fires at the ORIGINAL absolute deadline.
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let rd = [0x66u8; 64];
        let frame = encode_ok_frame(&test_report(&rd), &[]).unwrap();
        b.write_all(&frame[..10]).unwrap(); // partial header immediately, then silence (b stays open)
        let start = Instant::now();
        let err = read_child_reply(&mut a, start + Duration::from_millis(200))
            .expect_err("partial frame + silence must lapse");
        assert!(matches!(err, ProtocolError::WireProtocol(DEADLINE_LAPSED_MSG)), "got {err:?}");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(2),
            "must lapse at the ORIGINAL deadline (~200ms), got {elapsed:?}"
        );
        drop(b);
    }
    // ---- orchestration (FakeSpawn / FakeHandle) ----
    // The fake whose `try_reap` returns Running forever is THE ONLY deterministic D-state stand-in
    // available anywhere (CI or aya) — a real D-state child cannot be staged on demand. Stated per the
    // discriminating-test rule; the real-subprocess smokes below cover S-state + plumbing.

    #[derive(Clone)]
    struct FakeHandle {
        kills: Rc<RefCell<u32>>,
        reaps: Rc<RefCell<u32>>,
        reapable: Rc<RefCell<bool>>,
    }

    impl FakeHandle {
        fn unreapable() -> Self {
            Self {
                kills: Rc::new(RefCell::new(0)),
                reaps: Rc::new(RefCell::new(0)),
                reapable: Rc::new(RefCell::new(false)),
            }
        }
    }

    impl ChildHandle for FakeHandle {
        fn kill_best_effort(&mut self) {
            *self.kills.borrow_mut() += 1;
        }
        fn try_reap(&mut self) -> ReapOutcome {
            *self.reaps.borrow_mut() += 1;
            if *self.reapable.borrow() {
                ReapOutcome::Exited
            } else {
                ReapOutcome::Running
            }
        }
    }

    /// What the fake child "writes": a complete frame (then writer closes) or nothing (writer held
    /// open — the deterministic wedge).
    enum FakePlan {
        FullFrame(Vec<u8>),
        Silent,
    }

    struct FakeSpawn {
        plan: FakePlan,
        reapable: bool,
        spawns: Rc<RefCell<u32>>,
        kills: Rc<RefCell<u32>>,
        // Writer ends held open for Silent plans (dropping one = EOF, which is NOT a wedge).
        keepalive: RefCell<Vec<UnixStream>>,
    }

    impl FakeSpawn {
        fn new(plan: FakePlan, reapable: bool) -> Self {
            Self {
                plan,
                reapable,
                spawns: Rc::new(RefCell::new(0)),
                kills: Rc::new(RefCell::new(0)),
                keepalive: RefCell::new(Vec::new()),
            }
        }
    }

    impl QuoteChildSpawn for FakeSpawn {
        type Pipe = UnixStream;
        type Handle = FakeHandle;
        fn spawn(&self, _report_data: &[u8; 64]) -> Result<(UnixStream, FakeHandle), ProtocolError> {
            *self.spawns.borrow_mut() += 1;
            let (reader, mut writer) = UnixStream::pair().unwrap();
            match &self.plan {
                FakePlan::FullFrame(f) => {
                    // Small frames fit the default socket buffer — inline write never blocks.
                    writer.write_all(f).unwrap();
                    drop(writer);
                }
                FakePlan::Silent => self.keepalive.borrow_mut().push(writer),
            }
            let h = FakeHandle {
                kills: Rc::clone(&self.kills),
                reaps: Rc::new(RefCell::new(0)),
                reapable: Rc::new(RefCell::new(self.reapable)),
            };
            Ok((reader, h))
        }
    }

    #[test]
    fn fetch_kills_and_ledgers_unreapable_child_promptly() {
        // Regression: any blocking-wait / unbounded-sleep reintroduction in the dispose path. A silent
        // pipe + an unreapable handle (the D-state stand-in): the fetch must return ~at the deadline,
        // kill exactly once, abandon to the ledger, and surface the relabelled retryable lapse. The
        // exact-string assert below ALSO pins the single relabel arm end-to-end via the shared const
        // (a reworded literal would dead-code the arm) — mirroring
        // `connect_bounded_entry_lapse_is_relabelled_deviceless`.
        let spawn = FakeSpawn::new(FakePlan::Silent, false);
        let mut ledger = AbandonedLedger::new();
        let start = Instant::now();
        let err = fetch_quote_via_child(&spawn, &mut ledger, &[0u8; 64], start + Duration::from_millis(200))
            .expect_err("silent child must lapse");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "got {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "must return at the deadline, not block");
        assert_eq!(*spawn.kills.borrow(), 1, "exactly one SIGKILL");
        assert_eq!(ledger.len(), 1, "unreapable child must be abandoned to the ledger");
    }

    #[test]
    fn fetch_unconditional_kill_on_success() {
        // Regression: a kill-free success path (a child that already wrote its frame but wedges in its
        // own cleanup would linger). Inverts the vetoed absence-pinning shape: kill MUST still fire.
        let rd = [0x77u8; 64];
        let frame = encode_ok_frame(&test_report(&rd), &[0x01]).unwrap();
        let spawn = FakeSpawn::new(FakePlan::FullFrame(frame), true);
        let mut ledger = AbandonedLedger::new();
        let (report, chain) =
            fetch_quote_via_child(&spawn, &mut ledger, &rd, future()).expect("fetch succeeds");
        assert_eq!(report, test_report(&rd));
        assert_eq!(chain, vec![0x01]);
        assert_eq!(*spawn.kills.borrow(), 1, "disposition (kill) runs on SUCCESS too");
        assert_eq!(ledger.len(), 0, "reapable child must not be abandoned");
    }

    #[test]
    fn fetch_child_error_frame_surfaces_triage_string() {
        // Regression: the child's step-failure code lost in transit — the fixed table must surface as
        // the parent error verbatim (and still dispose the child).
        let spawn = FakeSpawn::new(FakePlan::FullFrame(encode_err_frame(4).to_vec()), true);
        let mut ledger = AbandonedLedger::new();
        let err = fetch_quote_via_child(&spawn, &mut ledger, &[0u8; 64], future())
            .expect_err("ERR frame must fail the fetch");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: outblob read failed")),
            "got {err:?}"
        );
        assert_eq!(*spawn.kills.borrow(), 1);
    }

    #[test]
    fn fetch_sweeps_ledger_on_next_fetch() {
        // Regression: ledger leak — a previously-abandoned child that has since un-wedged (become
        // reapable) must be reclaimed by the NEXT fetch's sweep.
        let spawn = FakeSpawn::new(FakePlan::Silent, false);
        let mut ledger = AbandonedLedger::new();
        let _ = fetch_quote_via_child(&spawn, &mut ledger, &[0u8; 64], Instant::now() + Duration::from_millis(150));
        assert_eq!(ledger.len(), 1, "precondition: one abandoned child");
        // The wedged child "un-wedges": flip the abandoned handles' reapable flags via the ledger.
        for h in &ledger.children {
            *h.reapable.borrow_mut() = true;
        }
        let rd = [0x12u8; 64];
        let frame = encode_ok_frame(&test_report(&rd), &[]).unwrap();
        let spawn2 = FakeSpawn::new(FakePlan::FullFrame(frame), true);
        fetch_quote_via_child(&spawn2, &mut ledger, &rd, future()).expect("fetch 2 succeeds");
        assert_eq!(ledger.len(), 0, "sweep at fetch start must reclaim the un-wedged child");
    }

    #[test]
    fn fetch_refuses_past_budget_before_spawn() {
        // Regression: the cross-run accumulation hole — at the budget the fetch must refuse BEFORE
        // spawning (zero new children), fail-closed retryable.
        let mut ledger = AbandonedLedger::new();
        for _ in 0..ABANDONED_CHILD_BUDGET {
            ledger.abandon(FakeHandle::unreapable());
        }
        let spawn = FakeSpawn::new(FakePlan::Silent, false);
        let err = fetch_quote_via_child(&spawn, &mut ledger, &[0u8; 64], future())
            .expect_err("full ledger must refuse");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: abandoned-child budget exhausted")),
            "got {err:?}"
        );
        assert_eq!(*spawn.spawns.borrow(), 0, "must refuse BEFORE spawning");
    }

    #[test]
    fn attempt_overhead_dominated_by_reap_grace() {
        // Pins the eps derivation: QUOTE_ATTEMPT_OVERHEAD must track REAP_GRACE (its dominant term) —
        // a future REAP_GRACE retune must move eps WITH it, never strand a stale number for 5b-2c's
        // budget check to transcribe.
        assert!(QUOTE_ATTEMPT_OVERHEAD >= REAP_GRACE);
        assert!(QUOTE_ATTEMPT_OVERHEAD <= REAP_GRACE + Duration::from_millis(5));
    }

    #[test]
    fn budget_equals_driver_ceiling() {
        // Regression: silent drift between the ledger budget and the driver ceiling surviving a future
        // literal refactor (the const is derived; this pins the DERIVATION target too).
        assert_eq!(
            ABANDONED_CHILD_BUDGET as u32,
            crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING
        );
    }

    #[test]
    fn fetch_past_deadline_fast_path_no_side_effects() {
        // Deviceless-CI safety parity with the cooperative producer's fast-path pin (which (d-ii)
        // deletes): an already-lapsed deadline must error BEFORE any side effect — no spawn, no sweep.
        let mut ledger = AbandonedLedger::new();
        let sentinel = FakeHandle::unreapable();
        let reaps = Rc::clone(&sentinel.reaps);
        ledger.abandon(sentinel);
        let spawn = FakeSpawn::new(FakePlan::Silent, false);
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let err = fetch_quote_via_child(&spawn, &mut ledger, &[0u8; 64], past)
            .expect_err("past deadline must fast-path");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "fast-path lapse must carry the quote-leg triage label, got {err:?}"
        );
        assert_eq!(*spawn.spawns.borrow(), 0, "no spawn on the fast path");
        assert_eq!(*reaps.borrow(), 0, "no sweep on the fast path");
    }

    #[test]
    fn reap_err_keeps_handle_in_ledger() {
        // Pins the judges' FAIL-CLOSED choice on anomalous waitpid: Err folds to Running (handle kept,
        // pinning a budget slot) — never silently forgets a possibly-live child. Pure-fold test because
        // a real Child cannot be made to return Err from try_wait on demand.
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            fold_try_wait(Err(std::io::Error::other("anomalous waitpid"))),
            ReapOutcome::Running,
            "Err must fold fail-closed to Running"
        );
        assert_eq!(fold_try_wait(Ok(None)), ReapOutcome::Running);
        assert_eq!(
            fold_try_wait(Ok(Some(std::process::ExitStatus::from_raw(0)))),
            ReapOutcome::Exited
        );
    }

    #[test]
    fn kill_on_drop_guard_fires() {
        // Regression: the spawn→ledger panic window — an undisposed guard must kill + best-effort reap
        // exactly once on drop.
        let h = FakeHandle::unreapable();
        let (kills, reaps) = (Rc::clone(&h.kills), Rc::clone(&h.reaps));
        drop(KillOnDrop::new(h));
        assert_eq!(*kills.borrow(), 1, "guard drop must kill");
        assert_eq!(*reaps.borrow(), 1, "guard drop must attempt ONE best-effort reap");
    }

    #[test]
    fn fetch_echo_mismatch_is_retryable() {
        // Regression: a corrupted pipe / misrouted report accepted into the relay request — the report's
        // embedded report_data MUST equal the requested one.
        let requested = [0xAAu8; 64];
        let frame = encode_ok_frame(&test_report(&[0xBBu8; 64]), &[]).unwrap(); // echo of the WRONG rd
        let spawn = FakeSpawn::new(FakePlan::FullFrame(frame), true);
        let mut ledger = AbandonedLedger::new();
        let err = fetch_quote_via_child(&spawn, &mut ledger, &requested, future())
            .expect_err("echo mismatch must fail");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: report_data echo mismatch")),
            "got {err:?}"
        );
    }

    // ---- real-subprocess smokes (current_exe + env-guarded #[ignore] helper; protocol over STDERR
    //      because the spawned TEST binary's stdout carries the unstable libtest banner) ----
    // These prove S-state behavior + the real Child/pipe/env plumbing. They run DEVICELESS in CI.
    // Subprocess tests stay lib tests forever: a `tests/` integration target would lose both the
    // current_exe-helper reachability and the pub(crate) seams.

    const HELPER_GUARD_ENV: &str = "TWOD_HSM_QUOTE_CHILD_TEST";

    /// Hand-rolled ON PURPOSE (not the `hex` dev-dep the other test modules use): this is the
    /// PROTOTYPE of (d-ii)'s production `parse_report_data_env` — the production child cannot take the
    /// `hex` dep (not an agent-gateway dependency), so the decoder that ships there should be the one
    /// already exercised here, promoted with review, not rewritten. Lowercase-only by design (the
    /// encoder `hex128` emits lowercase; the env round-trip is closed).
    fn unhex128(s: &str) -> [u8; 64] {
        fn nib(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("bad hex"),
            }
        }
        let b = s.as_bytes();
        assert_eq!(b.len(), 128, "report_data env must be 128 hex chars");
        let mut out = [0u8; 64];
        for i in 0..64 {
            out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        }
        out
    }

    /// THE child for every smoke below. Dispatches on the guard env value; a bare invocation (guard
    /// unset — e.g. an aya `--include-ignored` sweep) is an instant no-op PASS. `exit()` (not return)
    /// on guarded paths suppresses the trailing libtest summary on the protocol stream's sibling.
    #[test]
    #[ignore = "subprocess helper: spawned by the smoke tests below; no-op without the guard env"]
    fn helper_quote_child() {
        // DOUBLE guard: dispatch requires BOTH the mode env AND the spawner's marker env. The real
        // spawner always sets the marker; an operator shell never does — so a stale
        // TWOD_HSM_QUOTE_CHILD_TEST export cannot hijack an unfiltered `cargo test -- --ignored` run
        // (single-guard would turn it into a wedge-loop or, worse, an exit(0) FALSE-GREEN that
        // silently skips the rest of the suite).
        if std::env::var_os(super::QUOTE_CHILD_ENV).is_none() {
            return; // not spawned by the harness: instant green no-op
        }
        let Some(mode) = std::env::var(HELPER_GUARD_ENV).ok() else {
            return; // guard unset: instant green no-op (protects --include-ignored sweeps)
        };
        let rd = std::env::var(super::QUOTE_CHILD_REPORT_DATA_ENV)
            .map(|h| unhex128(&h))
            .unwrap_or([0u8; 64]);
        let mut err = std::io::stderr();
        match mode.as_str() {
            "frame" => {
                let f = encode_ok_frame(&test_report(&rd), &[0xC1, 0xC2]).unwrap();
                err.write_all(&f).unwrap();
                std::process::exit(0);
            }
            "trailing" => {
                let mut f = encode_ok_frame(&test_report(&rd), &[]).unwrap();
                f.extend_from_slice(b"junk");
                err.write_all(&f).unwrap();
                std::process::exit(0);
            }
            "partial-wedge" => {
                let f = encode_ok_frame(&test_report(&rd), &[0xEE; 32]).unwrap();
                err.write_all(&f[..f.len() / 2]).unwrap();
                err.flush().unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
            "wedge" => loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
            "brake" => {
                // Inside a quote child the marker env is set — a nested spawn MUST refuse.
                let nested = smoke_spawn("frame").spawn(&[0u8; 64]);
                std::process::exit(if nested.is_err() { 0 } else { 7 });
            }
            _ => std::process::exit(9),
        }
    }

    fn smoke_spawn(mode: &str) -> ExecChildSpawn {
        ExecChildSpawn {
            program: std::env::current_exe().expect("current_exe"),
            leading_args: vec![
                "quote_subprocess::tests::helper_quote_child".into(),
                "--exact".into(),
                "--ignored".into(),
            ],
            extra_env: vec![(HELPER_GUARD_ENV.into(), mode.into())],
            pipe_source: PipeSource::Stderr,
            clear_env: false,
        }
    }

    /// Poll a real handle's exit status non-blockingly (test-side only — production has no wait at all).
    fn poll_status(h: &mut StdChildHandle, within: Duration) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(st) = h.try_status() {
                return st;
            }
            assert!(start.elapsed() < within, "child did not exit within {within:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// REAP_GRACE (10ms) is a PRODUCTION budget term, not a CI scheduling guarantee — on a loaded
    /// shared runner a SIGKILLed child's kill→reapable transition can exceed it, landing the handle in
    /// the ledger a few ms before it dies. The production-relevant property is "a subsequent sweep
    /// reclaims it" (exactly what every later fetch does), so the smokes assert THAT, bounded:
    /// retry-sweep ≤500ms, then require empty. Never "fix" a flake here by bumping REAP_GRACE — that
    /// silently inflates the doc-pinned ε term ([`QUOTE_ATTEMPT_OVERHEAD`]).
    fn assert_eventually_swept(ledger: &mut AbandonedLedger<StdChildHandle>) {
        let bound = Instant::now() + Duration::from_millis(500);
        while ledger.len() > 0 && Instant::now() < bound {
            std::thread::sleep(Duration::from_millis(10));
            ledger.sweep();
        }
        assert_eq!(ledger.len(), 0, "killed child must be reaped by a subsequent sweep");
    }

    #[test]
    fn exec_spawn_reads_helper_frame_to_eof() {
        // Regression: AsFd/pipe/env plumbing breakage in the REAL spawn path — end-to-end
        // fetch_quote_via_child over a real Child + ChildStderr, frame returned, child reaped.
        let rd = [0x5Au8; 64];
        let mut ledger = AbandonedLedger::new();
        let (report, chain) = fetch_quote_via_child(
            &smoke_spawn("frame"),
            &mut ledger,
            &rd,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("end-to-end fetch over a real subprocess");
        assert_eq!(report, test_report(&rd), "report delivered verbatim (incl. echo)");
        assert_eq!(chain, vec![0xC1, 0xC2]);
        assert_eventually_swept(&mut ledger);
    }

    #[test]
    fn exec_spawn_trailing_garbage_rejected() {
        // Regression: real-path counterpart of the trailing-bytes rejection (the in-process test could
        // pass while the real pipe path chunked differently).
        let mut ledger = AbandonedLedger::new();
        let err = fetch_quote_via_child(
            &smoke_spawn("trailing"),
            &mut ledger,
            &[0u8; 64],
            Instant::now() + Duration::from_secs(10),
        )
        .expect_err("trailing junk must be rejected");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: trailing bytes after frame")),
            "got {err:?}"
        );
    }

    #[test]
    fn wedged_child_returns_at_deadline_not_child_exit() {
        // THE hang (d) exists to kill, on a REAL child: a sleep-forever helper writes nothing; the
        // fetch must return at ~the deadline (hangs here if anyone reintroduces wait()/
        // wait_with_output — pinned by the ELAPSED bound; the no-wait rule is also structural via the
        // ChildHandle type), the relabelled lapse must surface, and the killed sleeper must be
        // reclaimed by a subsequent sweep (see assert_eventually_swept — NOT a 10ms-grace microbench).
        let mut ledger = AbandonedLedger::new();
        let start = Instant::now();
        let err = fetch_quote_via_child(
            &smoke_spawn("wedge"),
            &mut ledger,
            &[0u8; 64],
            start + Duration::from_millis(400),
        )
        .expect_err("wedged child must lapse");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "got {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(3), "must return at the deadline");
        assert_eventually_swept(&mut ledger);
    }

    #[test]
    fn killed_wedged_child_shows_sigkill() {
        // Regression: abandon-without-kill leaking a live sleeper. Direct spawn (not via fetch) so the
        // handle stays in OUR hands for after-the-fact evidence: kill, then the reaped status must show
        // signal 9. (Replaces the unsatisfiable "still Running at fetch-return" shape — a real S-state
        // sleeper dies to SIGKILL within the grace, so only the SIGNAL is assertable evidence.)
        use std::os::unix::process::ExitStatusExt;
        let (pipe, handle) = smoke_spawn("wedge").spawn(&[0u8; 64]).expect("spawn");
        // KillOnDrop: if poll_status's assert panics, the guard still kills the sleeper — a bare
        // handle would leak a LIVE child past the whole test run.
        let mut guard = KillOnDrop::new(handle);
        guard.get_mut().kill_best_effort();
        let status = poll_status(guard.get_mut(), Duration::from_secs(2));
        assert_eq!(status.signal(), Some(9), "the wedged child must die by SIGKILL, got {status:?}");
        drop(pipe);
    }

    #[test]
    fn partial_frame_then_wedge_lapses() {
        // Regression: a half-frame must neither parse (decode error) nor extend the deadline — the
        // result is the LAPSE, at the original deadline. (If a slow CI box delays the helper's half
        // write past the deadline the result is the same lapse — the decode-vs-lapse discrimination
        // engages whenever the half-frame lands in time, which is the overwhelmingly common case.)
        let mut ledger = AbandonedLedger::new();
        let start = Instant::now();
        let err = fetch_quote_via_child(
            &smoke_spawn("partial-wedge"),
            &mut ledger,
            &[0u8; 64],
            start + Duration::from_millis(800),
        )
        .expect_err("partial frame + wedge must lapse");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "must be the LAPSE, not a decode error: {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn helper_noop_passes_without_guard_env() {
        // Protects aya `--include-ignored` sweeps: WITHOUT the guard env every helper is an instant
        // green no-op (ExecChildSpawn sets only the marker + report_data envs — guard stays unset).
        let spawn = ExecChildSpawn {
            extra_env: vec![],
            ..smoke_spawn("unused")
        };
        let (pipe, handle) = spawn.spawn(&[0u8; 64]).expect("spawn");
        let mut guard = KillOnDrop::new(handle); // leak-proof if the poll assert panics
        let status = poll_status(guard.get_mut(), Duration::from_secs(10));
        assert!(status.success(), "guard-less helper must no-op PASS, got {status:?}");
        drop(pipe);
    }

    #[test]
    fn spawn_brake_refuses_inside_child() {
        // Regression: fork-bomb recursion — inside a child (marker env set) a nested spawn MUST refuse.
        // Tested in the CHILD's env (via the helper) so the test process's own env is never mutated.
        let (pipe, handle) = smoke_spawn("brake").spawn(&[0u8; 64]).expect("spawn");
        let mut guard = KillOnDrop::new(handle); // leak-proof if the poll assert panics
        let status = poll_status(guard.get_mut(), Duration::from_secs(10));
        assert_eq!(
            status.code(),
            Some(0),
            "helper exits 0 iff the nested spawn refused, got {status:?}"
        );
        drop(pipe);
    }
}
