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
//! (d-i) shipped the entire deviceless-provable harness (this file) + the entry-path refactor in
//! `snp_report` + the §8 pin revision; (d-ii)/1 added the configfs child mode (`agent_quote_child_main`,
//! child-self-named `twod-hsm-q-<pid>` entries, child-side prefix GC); (d-ii)/2 added
//! [`HardBoundedQuoteProducer`] — the structural type the 5b-2c serve path requires BY NAME, whose
//! [`crate::agent_boot_relay::BootQuoteProducer`] impl DELIVERS the bound (the (d-i) NO-skeleton rule is
//! SATISFIED, not waived: `fetch` delegates to the killable-subprocess orchestration
//! `fetch_quote_via_child`, so the wedged-read hang is killed at the deadline — no by-signature gate-lie
//! remains); (d-ii)/3 added [`ValidatedBootBudget`] — gate #2 of the TWO-artifact live-serve gate (the
//! fail-closed boot-budget check), taken by the producer's constructors as an ordering witness.
//! Still-open (d-ii): cooperative-path deletion (4a), live wiring (4b), the in-guest aya smoke (4c).
//!
//! Consumer-free until (4b)/5b-2c wire it — the module-wide allow is NOT transitional leftovers: under
//! the CI leaf combo (`vsock-transport,agent-gateway`) this compiles with its only consumer not yet
//! landed, and (like `cancellable_boundary`) it must stay warning-free there.
#![cfg_attr(not(test), allow(dead_code))]

use crate::cancellable_boundary::{
    classify_pipe_revents, poll_with_deadline, remaining_or_lapsed, PipeReadiness,
    DEADLINE_LAPSED_MSG, MIN_BOUNDARY_BUDGET,
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

/// Precondition: `b.len() >= 4` (every caller length-guards first — `from_be_bytes` over the
/// `try_into` makes the 4-byte intent explicit; a short slice still panics rather than misparses).
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().expect("be_u32 caller guarantees >= 4 bytes"))
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

/// Spawn seam: production execs `/proc/self/exe` in child mode — the shape [`ExecChildSpawn::production`]
/// constructs ((d-ii)/2); child mode itself landed in (d-ii)/1. The CI smokes spawn the test
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
/// process, living as long as the boot path — owned by [`HardBoundedQuoteProducer`] (landed,
/// (d-ii)/2, which enforces the one-per-process rule via its process claim); constructing
/// a fresh ledger per attempt would reset `is_full()` and void the cap (see §8). There is no terminal
/// sweep after the LAST fetch: children abandoned on late attempts stay zombies until process exit —
/// `Drop` below runs one final best-effort kill+reap pass to shrink that window, but a still-wedged
/// child is structurally unreapable and is left to pid-1.
struct AbandonedLedger<H: ChildHandle> {
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
/// BETWEEN the quote and channel legs; the boot-budget check ([`ValidatedBootBudget`], (d-ii)/3)
/// carries it as the explicit `max_attempts · ε` term.
pub(crate) const REAP_GRACE: Duration = Duration::from_millis(10);

/// ε — the per-attempt quote-subprocess overhead the boot-budget check carries as an explicit term:
/// `max_attempts · (2·timeout + ε) ≤ overall_boot_budget` (§8). DERIVED from its dominant term (the reap
/// grace) plus a ~2ms margin for spawn + SIGKILL + fd close, so a future `REAP_GRACE` retune cannot
/// silently strand a stale literal in the budget arithmetic — the same derive-don't-transcribe rule as
/// [`ABANDONED_CHILD_BUDGET`]. THE consumer is [`per_attempt_nominal_cost`] inside
/// [`ValidatedBootBudget::validate`] ((d-ii)/3) — never a hand-copied number, and never a SECOND
/// consumption site: 5b-2c's surviving step is constructing the witness from operator config, not
/// re-consuming ε.
pub(crate) const QUOTE_ATTEMPT_OVERHEAD: Duration =
    REAP_GRACE.saturating_add(Duration::from_millis(2));

impl<H: ChildHandle> AbandonedLedger<H> {
    fn new() -> Self {
        Self { children: Vec::new() }
    }
    /// O(≤budget) WNOHANG sweep: drop every since-exited child, keep the rest. Run at every fetch start
    /// so un-wedged children are reclaimed promptly.
    fn sweep(&mut self) {
        self.children.retain_mut(|h| h.try_reap() == ReapOutcome::Running);
    }
    fn abandon(&mut self, h: H) {
        self.children.push(h);
    }
    fn is_full(&self) -> bool {
        self.children.len() >= ABANDONED_CHILD_BUDGET
    }
    #[cfg(test)]
    fn len(&self) -> usize {
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

/// Set `O_NONBLOCK` on a pipe/stream read end (safe nix fcntl; the `fs` feature). Generic over `AsFd`
/// so the orchestration applies it uniformly to the real `QuotePipe` and the test fakes' streams.
fn set_nonblock<F: std::os::fd::AsFd>(fd: &F) -> Result<(), ProtocolError> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|_| ProtocolError::WireProtocol("quote child: F_GETFL failed"))?;
    let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags))
        .map_err(|_| ProtocolError::WireProtocol("quote child: F_SETFL failed"))?;
    Ok(())
}

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
fn fetch_quote_via_child<S: QuoteChildSpawn>(
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
    // (3b) O_NONBLOCK on the parent read end (belt-and-braces: poll says readable before every read,
    // but a spurious wakeup must re-poll, not block). HERE and not inside the spawner: this step is
    // fallible, and only the orchestration can route a failure through the bounded dispose/abandon
    // path — so even an exotic fcntl failure (seccomp policy) cannot leave a child outside the
    // ledger's custody accounting.
    if let Err(e) = set_nonblock(&pipe) {
        drop(pipe);
        dispose_child(guard.into_inner(), ledger);
        return Err(e);
    }
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
    /// Constructed by [`ExecChildSpawn::production`] ((d-ii)/2); shape-pinned by the CI test
    /// `production_spawner_shape_is_pinned`, runtime aya-only by §8 pin (2) (the (4c) in-guest smoke
    /// exercises it — the CI smokes pipe `Stderr` because the test binary's stdout carries the libtest
    /// banner).
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
/// `Stderr`-pipe nulls stdout to suppress the libtest banner). The parent read end's `O_NONBLOCK` is
/// set by the ORCHESTRATION, not here (custody: its failure must route through the ledger).
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
        // Preserve the OS error (ENOENT/EACCES/EMFILE…) — unlike the child-frame arms (a fixed static
        // table, anti-oracle), a parent-side spawn failure is pure operator triage and the errno is the
        // diagnosis; it still folds to the same retryable class at the seam.
        let child = cmd.spawn().map_err(ProtocolError::Io)?;
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
        // (That ok_or is DEFENSIVE-UNREACHABLE: std guarantees the Option is Some when the matching
        // Stdio::piped() was configured and spawn() returned Ok — kept because reaching it must still
        // kill the child via the guard rather than leak it. The O_NONBLOCK fcntl deliberately does NOT
        // happen here: the seam has no ledger, so a fallible step here could only kill+single-reap on
        // failure; the orchestration owns it — its failure path routes through the SAME bounded
        // dispose/abandon custody as every other error.)
        Ok((pipe, guard.into_inner()))
    }
}

impl ExecChildSpawn {
    /// The PRODUCTION spawn shape (§8 pin (2): this SHAPE has ZERO CI behavior coverage BY PIN — the
    /// (4c) in-guest aya smoke exercises it; CI pins construction only, see
    /// `production_spawner_shape_is_pinned`): re-exec the running binary via the literal
    /// `/proc/self/exe` — the magic link resolves AT EXEC TIME to the running parent's inode, so the
    /// parent and child frame halves are the SAME binary even if the on-disk path is replaced mid-boot
    /// (a `current_exe()` PATH would race that replacement into cross-version frame drift — the exact
    /// thing the golden-bytes frame tests exist to prevent), and the literal is infallible — no error
    /// arm to route (linux-only module by cfg, so /proc is guaranteed; the test `smoke_spawn` keeps
    /// `current_exe()` deliberately — it needs libtest argv targeting, a different world). No leading
    /// args (the 5b-2c bin's main calls [`agent_quote_child_dispatch`] first, unconditionally);
    /// `clear_env` (child env = exactly the marker + report_data the spawner sets AFTER `env_clear` —
    /// NB this also strips loader vars like `LD_LIBRARY_PATH`: fine for the NixOS guest binary, whose
    /// library paths are RPATH-linked by the Nix toolchain, and the (4c) in-guest smoke is the checked
    /// validation of exactly that); protocol pipe = `Stdout` (PROTOCOL-ONLY); stderr INHERITED → guest
    /// journald for kill-storm triage [user decision 2026-06-10].
    pub(crate) fn production() -> Self {
        Self {
            program: std::path::PathBuf::from("/proc/self/exe"),
            leading_args: Vec::new(),
            extra_env: Vec::new(),
            pipe_source: PipeSource::Stdout,
            clear_env: true,
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// (d-ii)/2 — HardBoundedQuoteProducer: the structural serve-gate type. Owns THE one AbandonedLedger.
// ---------------------------------------------------------------------------------------------------

/// Claim flag backing the "exactly ONE `AbandonedLedger` per process" pin (§8). Const-init false; set
/// once by [`HardBoundedQuoteProducer::new`] and deliberately NEVER cleared in a shipped binary — not
/// even on Drop (see the constructor doc) — only the cfg(test) reset below, called solely from
/// `lock_and_reset_agent_process_globals` (the crate's single reset site). SeqCst for clarity on a
/// never-hot one-shot boot flag (Relaxed would also be correct — the flag guards no associated memory).
static PROCESS_QUOTE_LEDGER_CLAIMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The production [`crate::agent_boot_relay::BootQuoteProducer`] — the (d) structural serve-gate type
/// (§8): the 5b-2c serving path takes THIS CONCRETE type by signature, so a build lacking the
/// killable-subprocess hard bound (this module's triple cfg gate) cannot construct a serving path.
/// `fetch` delegates to [`fetch_quote_via_child`] — the pipe-deadline hard bound (spawn → pipe poll →
/// SIGKILL at the lapse → bounded reap → ledger), NOT a skeleton: the wedged-read hang is killed at
/// the deadline, so the gate-lie §8 forbids is structurally absent (the delegate IS the bound). The
/// seam-minted absolute `deadline` is passed through UNTOUCHED — never re-minted here.
///
/// Owns **THE one [`AbandonedLedger`] for the process** (§8 pin): the abandoned-child budget binds only
/// if exactly one ledger outlives all fetches — a fresh ledger per attempt resets `is_full()` and voids
/// the cap. STRUCTURAL, not prose: (i) [`Self::new`] claims [`PROCESS_QUOTE_LEDGER_CLAIMED`]; a second
/// construction REFUSES fail-closed at boot wiring, before any handshake budget is spent, and the claim
/// is never released — including on Drop: a drop-and-reconstruct would forget every abandoned (possibly
/// live) child and reset the cap, the exact hole the pin names, and the claim also closes
/// [`ABANDONED_CHILD_BUDGET`]'s cross-handshake accumulation hole (a caller looping handshakes must
/// reuse this one producer or fail closed; ONE boot handshake per process is the design — a supervisor
/// restart is a new process and claims fresh); (ii) [`fetch_quote_via_child`] and [`AbandonedLedger`]
/// are module-PRIVATE, so outside this module the producer is the only quote-fetch door — NB the
/// door's SHAPE is not sealed: [`ExecChildSpawn`]'s fields stay pub(crate) (the smokes build test
/// shapes), so an in-crate caller could claim THE producer over a custom spawner; shape discipline
/// rests on (4b) wiring [`Self::production`] + the §8 concrete-type obligation, while the BOUND
/// itself stays intact for any spawner (every `S` routes through the same orchestration); (iii) the
/// `ledger` field is private, no method replaces it, and the type deliberately derives neither `Clone`
/// nor `Default` (a clone would mint a second ledger and fork the budget — treat any later derive as a
/// pin violation); (iv) `fetch(&mut self)` makes the single mutator a borrow-checker fact.
///
/// Budget-gate integration landed in (d-ii)/3: [`ValidatedBootBudget`] (below) is the fail-closed
/// `max_attempts·(2·timeout+ε)` constructor check consuming [`QUOTE_ATTEMPT_OVERHEAD`], and BOTH
/// constructors here take it as an ordering witness (validation strictly precedes the permanent
/// claim, by signature). The TWO-artifact live-serve gate stands: neither type landing opens live
/// serve — that waits for (4b) wiring + the (4c) in-guest smoke.
///
/// Generic over the spawn seam (default = the production [`ExecChildSpawn`]) so the deviceless
/// ledger-pin tests drive the SAME producer over fake handles (a real ledger cannot be filled: S-state
/// children die to SIGKILL and D-state cannot be staged — the (d-i) honesty note). The generics cannot
/// smuggle a softer bound: every `S` routes through the same hard-bounded orchestration, and in a
/// non-test build [`ExecChildSpawn`] is the only [`QuoteChildSpawn`] impl.
pub(crate) struct HardBoundedQuoteProducer<S: QuoteChildSpawn = ExecChildSpawn> {
    spawn: S,
    /// THE one ledger (see the type doc + [`AbandonedLedger`]'s own lifecycle pin).
    ledger: AbandonedLedger<S::Handle>,
}

impl<S: QuoteChildSpawn> HardBoundedQuoteProducer<S> {
    /// Claim the process quote ledger and construct. Errors iff a producer was EVER constructed in
    /// this process (the claim is permanent by design — see the type doc; for a custody HSM, refusing
    /// beats forgetting possibly-live children). TEST RULE: tests calling `new` MUST hold
    /// `crate::agent_dispatch::lock_and_reset_agent_process_globals()` for the whole test body (the
    /// reset clears the claim); behavior tests use `new_unclaimed_for_tests` instead.
    ///
    /// `_budget` is a pure ORDERING WITNESS, deliberately unread (underscore-named — no
    /// unused_variables lint): constructing a [`ValidatedBootBudget`] IS the budget validation (its
    /// only constructor validates), so this signature makes "§8: budget validation BEFORE the
    /// permanent process claim" a compile fact for the VALIDATION STEP — no claim can precede a
    /// successful validation. SCOPE HONESTY: the witness proves SOME budget validated; it does not
    /// bind THE SAME instance to the values the wiring later uses. That binding is
    /// `production_transport` for the timeout (structural — the transport is minted from the
    /// witness) and a recorded (4b) acceptance obligation for the driver count
    /// (`budget.max_attempts()` from the SAME instance) — a wiring that validates a throwaway
    /// budget and hand-feeds different numbers is a (4b)-review failure, not a compile error. The
    /// producer reads NOTHING from it (reading config here would duplicate the driver's config flow
    /// — a second source of truth).
    pub(crate) fn new(_budget: &ValidatedBootBudget, spawn: S) -> Result<Self, ProtocolError> {
        use std::sync::atomic::Ordering;
        if PROCESS_QUOTE_LEDGER_CLAIMED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ProtocolError::WireProtocol(
                "quote producer: process quote ledger already claimed",
            ));
        }
        Ok(Self::unclaimed(spawn))
    }

    /// The ONE construction literal (private, unconditional): `new()` reaches it only after winning
    /// the claim; the cfg(test) escape hatch reaches it directly.
    fn unclaimed(spawn: S) -> Self {
        Self { spawn, ledger: AbandonedLedger::new() }
    }

    /// Test-only escape hatch: bypasses the process claim so behavior tests parallelize (cfg(test) —
    /// cannot exist in a shipped binary; the claim pins a PRODUCTION-process invariant and has its own
    /// serialized discriminating test).
    #[cfg(test)]
    fn new_unclaimed_for_tests(spawn: S) -> Self {
        Self::unclaimed(spawn)
    }
}

impl HardBoundedQuoteProducer<ExecChildSpawn> {
    /// THE (4b)/5b-2c constructor: the production spawn shape ([`ExecChildSpawn::production`] — the
    /// `/proc/self/exe` rationale lives THERE, single source) + the process-ledger claim, one call.
    /// Budget-validation-before-claim is enforced BY SIGNATURE ((d-ii)/3 witness — see [`Self::new`]);
    /// the burned-claim WHY stays: only a supervisor restart heals a post-claim config mistake, which
    /// is why the witness exists. The infallible spawner leaves "constructed twice" as the ONLY error
    /// — FATAL wiring config, surfaced at boot wiring, never inside the retry loop; the wiring MUST
    /// `?`-propagate it (mapping it into the retryable `AnchorTransportError` class would spin the
    /// driver's whole attempt budget on a permanent refusal — position is the discriminator).
    pub(crate) fn production(budget: &ValidatedBootBudget) -> Result<Self, ProtocolError> {
        Self::new(budget, ExecChildSpawn::production())
    }
}

impl<S: QuoteChildSpawn> crate::agent_boot_relay::BootQuoteProducer for HardBoundedQuoteProducer<S> {
    /// Pure delegation to [`fetch_quote_via_child`] over the owned spawner + THE owned ledger (sweep →
    /// budget refuse → spawn → drain → unconditional dispose). All errors (child ERR frames, lapses,
    /// budget refusal) stay [`ProtocolError`] and fold to the retryable transport class at the
    /// `RelayAnchorTransport` seam — classification stays CLOSED (no terminal smuggling, §8).
    fn fetch(
        &mut self,
        report_data: &[u8; 64],
        deadline: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        fetch_quote_via_child(&self.spawn, &mut self.ledger, report_data, deadline)
    }
}

/// Test-only: clear the process-ledger claim. Called ONLY from
/// `crate::agent_dispatch::lock_and_reset_agent_process_globals` (the crate's single reset site, per
/// its own "a NEW agent process-global adds its reset HERE" pin) and the in-module SERIALIZED claim
/// tests (the claim test + the production_transport composition test), each restoring the pristine
/// flag on exit.
#[cfg(test)]
pub(crate) fn reset_process_quote_ledger_claim_for_tests() {
    PROCESS_QUOTE_LEDGER_CLAIMED.store(false, std::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------------------------------
// (d-ii)/3 — ValidatedBootBudget: the boot-budget validation artifact. Gate #2 of the TWO-artifact
// live-serve gate (§8 "Per-leg sizing floor"). Fail-closed constructor check, checked arithmetic,
// pure (no I/O, no process globals). Lives HERE for cohabitation with ε's definition (the formula's
// dominant term) and to avoid a second triple-gated mod declaration in lib.rs; a same-gated sibling
// module consuming `crate::quote_subprocess::QUOTE_ATTEMPT_OVERHEAD` by path would be equally
// transcription-free (cfg drift self-detects as a compile error) — the HARD requirement is only
// that the artifact's gate is never WIDER than the three consumed consts' intersection (ε: triple;
// MIN_BOUNDARY_BUDGET: linux+vsock; MAX_BOOT_ATTEMPTS_CEILING: agent-gateway = exactly this
// module's triple gate).
// ---------------------------------------------------------------------------------------------------

/// Shared by the add- and mul-overflow arms (two emit sites + the overflow tests — single-source
/// rule, cf. 73ddd5d). DISTINCT from the exceeds string so the overflow tests prove the CHECKED arm
/// fired rather than a saturate-then-compare accident slipping through the comparison.
const BOOT_BUDGET_OVERFLOW_MSG: &str = "boot budget: nominal boot cost arithmetic overflow";

/// Upper sanity ceiling on the per-leg timeout. Load-bearing, not just taste: every blessed value
/// flows into `Instant::now() + timeout` deadline mints (`RelayAnchorTransport::anchor_round_trip`),
/// where std's `Add` PANICS on overflow (linux `Instant` seconds are i64) — without this arm,
/// `validate()` would bless e.g. `Duration::from_secs(u64::MAX / 2)` (every other arm passes against
/// `overall = Duration::MAX`) and the gate's fail-closed contract would be voided by a downstream
/// abort on the FIRST round-trip. One hour is orders of magnitude above any sane boot leg and orders
/// below the i64-seconds overflow band — both failure classes stay far away; a per-leg value above
/// it is a config error by definition.
pub(crate) const MAX_PER_LEG_TIMEOUT: Duration = Duration::from_secs(3600);

/// Nominal per-attempt cost: quote leg + channel leg + ε ([`QUOTE_ATTEMPT_OVERHEAD`] — THE const,
/// never a transcribed number; a `REAP_GRACE` retune moves ε and this check with it). Written in the
/// GENERALIZED leg-sum shape (§8: "do NOT hardcode the 2· special case"):
/// [`ValidatedBootBudget::validate`] passes the ONE per-leg value for both legs (the single-budget
/// model, final for 5b-2b); the deferred distinct-timeout split changes the constructor INPUTS (the
/// two arguments), never this formula — the `2·` literal appears nowhere in code.
///
/// Checked Duration ops ONLY — never integer-millis conversion (the wrap hazard §8 names), and never
/// plain `+`/`*` (which PANIC on overflow: also wrong for a fail-closed constructor, which must
/// return `Err`, not abort boot).
fn per_attempt_nominal_cost(
    quote_leg: Duration,
    channel_leg: Duration,
) -> Result<Duration, ProtocolError> {
    quote_leg
        .checked_add(channel_leg)
        .and_then(|legs| legs.checked_add(QUOTE_ATTEMPT_OVERHEAD))
        .ok_or(ProtocolError::WireProtocol(BOOT_BUDGET_OVERFLOW_MSG))
}

/// Proof that `(max_attempts, per_leg_timeout)` fits `overall_boot_budget` under the §8 nominal
/// invariant `max_attempts · (quote_leg + channel_leg + ε) ≤ overall_boot_budget` (shipped form:
/// both legs = the one `per_leg_timeout`, i.e. `max_attempts · (2·timeout + ε)`). Gate #2 of the
/// TWO-artifact live-serve gate; gate #1 is [`HardBoundedQuoteProducer`], whose constructors take
/// this type as an ordering witness — in a shipped binary no producer (and transitively, via the §8
/// concrete-type obligation, no serve path) exists without a validated budget.
///
/// **ε is NOMINAL sizing arithmetic, not a runtime ceiling** (§8, verbatim obligation): only the
/// reap grace is code-bounded; `Command::spawn`, SIGKILL delivery and the ~1ms sleeps can stretch
/// under scheduler load. This check stops MIS-SIZED CONFIGS — the failure class that is actually
/// configurable; the runtime hard bounds remain the per-leg deadlines themselves.
///
/// **`≤` is the enforced comparison**: a budget EXACTLY equal to the nominal product passes but is
/// mis-sized by definition — operators MUST size `overall_boot_budget` with slack above the nominal
/// product (§8 decision: documented, deliberately NOT enforced). There is also deliberately NO upper
/// sanity bound on `overall_boot_budget` (`Duration::MAX` is accepted): the gate stops
/// under-budgeting; oversizing is operator slack.
///
/// **Hardening note (the one prose-only premise this gate rests on):** the two-leg accounting
/// assumes connect+I/O share ONE channel-leg deadline — wiring-enforced in
/// `agent_boot_relay::round_trip_inner` ONLY; re-verify on any refactor there. This artifact is
/// where the per-leg value ORIGINATES for 5b-2c: [`Self::production_transport`] threads
/// `per_leg_timeout` into `RelayAnchorTransport::new` itself, so the value the invariant was checked
/// against IS the value both leg deadlines are minted from. The transport cannot take this type BY
/// SIGNATURE — cfg-lattice fact: `agent_boot_relay` compiles in agent-gateway-without-vsock builds
/// where this type does not exist — so the Duration-typed seam there is the deliberate coupling
/// shape, not an oversight.
///
/// Clone/Copy are deliberate and SAFE here, in documented contrast to the producer: copying a
/// validated VALUE forks no state, while cloning the producer would fork the ledger budget (that
/// type's no-Clone pin stands untouched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatedBootBudget {
    max_attempts: u32,
    per_leg_timeout: Duration,
    overall_boot_budget: Duration,
    nominal_boot_cost: Duration,
}

impl ValidatedBootBudget {
    /// THE constructor — fail-closed, release-mode `Err` returns (NOT `debug_assert`: §8 requires
    /// the bound to hold in release). Errors are FATAL wiring-time config: `?`-propagate at boot
    /// wiring, NEVER fold into the fetch-path retryable class (construction-fatal and
    /// fetch-retryable deliberately share `ProtocolError`; POSITION is the discriminator — and the
    /// witness signature on the producer makes the wrong position unrepresentable).
    ///
    /// Validation chain, IN ORDER (each earlier arm wins; order is test-pinned):
    ///  1. `max_attempts == 0` → `"boot budget: max_attempts must be >= 1"`.
    ///  2. `max_attempts > MAX_BOOT_ATTEMPTS_CEILING` → the ceiling string — the bound DERIVED from
    ///     the const (never 64). The driver's own runtime range check (reject-don't-clamp) is
    ///     DELIBERATE duplication, not drift: the driver keeps its self-contained no-infinite-loop
    ///     property at a different error surface (`BootDriverFail::Unstartable`, runtime triage)
    ///     while this arm is the §8-mandated config-parse-time half (`ProtocolError`, wiring
    ///     triage); both derive from THE one const.
    ///  3. `per_leg_timeout < MIN_BOUNDARY_BUDGET` → the floor string — covers ZERO (a 0ms leg is
    ///     meaningless; `set_read_timeout(ZERO)` is an `Err` on vsock); floor INCLUSIVE (== MIN
    ///     passes), mirroring `remaining_or_lapsed`.
    ///  4. `per_leg_timeout > MAX_PER_LEG_TIMEOUT` → the ceiling string — the sanity arm that keeps
    ///     every blessed value safe for the downstream `Instant::now() + timeout` mints (std's `Add`
    ///     panics on overflow; see the const doc). Ceiling INCLUSIVE on the pass side (== MAX
    ///     passes).
    ///  5. nominal cost via [`per_attempt_nominal_cost`] then `.checked_mul(max_attempts)` →
    ///     [`BOOT_BUDGET_OVERFLOW_MSG`] on `None`. CHECKED, not saturating, by load-bearing choice:
    ///     a SATURATED `Duration::MAX` product would PASS the `≤` check against
    ///     `overall_boot_budget == Duration::MAX` — saturating arithmetic re-opens the exact
    ///     failure this arm exists to stop ("a wrapped product passing the check", §8). NB with
    ///     arm 4 in place these overflow arms are UNREACHABLE through `validate()` (64 · (2h + ε)
    ///     fits comfortably) — they are defense-in-depth against a ceiling retune/removal, and the
    ///     add arm stays directly pinned via the helper.
    ///  6. `nominal_boot_cost > overall_boot_budget` → the exceeds string; `≤` passes (equality
    ///     passes — see the type doc). No separate zero-budget arm: attempts ≥ 1 ∧ timeout ≥ 1ms ⇒
    ///     cost > 0 ⇒ a zero budget fails here.
    ///
    /// Transposition note: the two adjacent `Duration` params swapped at a call site always FAIL
    /// CLOSED for any valid config (nominal' = n·(2B+ε) > B > t), so no silent acceptance is
    /// reachable — a config-struct wrapper would be mechanism without a reachable failure.
    ///
    /// The static error strings deliberately carry no numbers (house pattern); the 5b-2c bin MUST
    /// log `(max_attempts, per_leg_timeout, overall_boot_budget, nominal_boot_cost)` at config
    /// parse — a named §8 obligation, served by the getters below.
    pub(crate) fn validate(
        max_attempts: u32,
        per_leg_timeout: Duration,
        overall_boot_budget: Duration,
    ) -> Result<Self, ProtocolError> {
        if max_attempts == 0 {
            return Err(ProtocolError::WireProtocol("boot budget: max_attempts must be >= 1"));
        }
        if max_attempts > crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING {
            return Err(ProtocolError::WireProtocol(
                "boot budget: max_attempts exceeds MAX_BOOT_ATTEMPTS_CEILING",
            ));
        }
        if per_leg_timeout < MIN_BOUNDARY_BUDGET {
            return Err(ProtocolError::WireProtocol(
                "boot budget: per-leg timeout below MIN_BOUNDARY_BUDGET",
            ));
        }
        if per_leg_timeout > MAX_PER_LEG_TIMEOUT {
            return Err(ProtocolError::WireProtocol(
                "boot budget: per-leg timeout exceeds MAX_PER_LEG_TIMEOUT",
            ));
        }
        let per_attempt = per_attempt_nominal_cost(per_leg_timeout, per_leg_timeout)?;
        let nominal_boot_cost = per_attempt
            .checked_mul(max_attempts)
            .ok_or(ProtocolError::WireProtocol(BOOT_BUDGET_OVERFLOW_MSG))?;
        if nominal_boot_cost > overall_boot_budget {
            return Err(ProtocolError::WireProtocol(
                "boot budget: nominal boot cost exceeds overall_boot_budget",
            ));
        }
        Ok(Self { max_attempts, per_leg_timeout, overall_boot_budget, nominal_boot_cost })
    }

    /// For `run_boot_anti_rollback_handshake` ((4b) wiring sources the driver's count from HERE).
    pub(crate) fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
    /// THE per-leg timeout origin for (4b)/5b-2c (`RelayAnchorTransport::new`'s `timeout`).
    pub(crate) fn per_leg_timeout(&self) -> Duration {
        self.per_leg_timeout
    }
    /// Boot-log triage ONLY — NEVER a runtime deadline source: ε is nominal sizing arithmetic and
    /// the runtime hard bounds remain the per-leg deadlines (§8 restated at the misuse site).
    pub(crate) fn overall_boot_budget(&self) -> Duration {
        self.overall_boot_budget
    }
    /// Boot-log triage ONLY (the "nominal X ≤ budget Y" slack line) — same warning as above. Stored
    /// at construction: no recompute path, no second formula site.
    pub(crate) fn nominal_boot_cost(&self) -> Duration {
        self.nominal_boot_cost
    }

    /// THE (4b)/5b-2c serve-path composition — both live-serve gates by signature, one call: claims
    /// the process producer (gate #1) and constructs the transport whose per-leg deadlines ORIGINATE
    /// from this validated value (gate #2 — the value the invariant was checked against IS the value
    /// both leg deadlines are minted from; the connect+I/O sharing of the channel leg stays
    /// wiring-enforced in `round_trip_inner`, see the type doc). The quote seam is the CONCRETE
    /// [`HardBoundedQuoteProducer`] (default `S = ExecChildSpawn`) per the §8 never-generic-Q
    /// obligation; `C` stays the seam trait because a real `VsockBootRelayChannel` cannot exist in
    /// CI — 5b-2c instantiates `C = VsockBootRelayChannel` (§8). ONLY error: the producer claim
    /// refusal — FATAL wiring config, `?`-propagate, never fold into the retryable fetch path.
    /// Consumer-free until (4b), exactly like `production()` was when (d-ii)/2 landed.
    pub(crate) fn production_transport<C: crate::agent_boot_relay::BootRelayChannel>(
        &self,
        channel: C,
    ) -> Result<
        crate::agent_boot_relay::RelayAnchorTransport<HardBoundedQuoteProducer, C>,
        ProtocolError,
    > {
        let producer = HardBoundedQuoteProducer::production(self)?;
        Ok(crate::agent_boot_relay::RelayAnchorTransport::new(
            producer,
            channel,
            self.per_leg_timeout,
        ))
    }
}

// ---------------------------------------------------------------------------------------------------
// (d-ii) CHILD MODE — the code that runs INSIDE the killable child. Everything here is testable
// deviceless over the TsmFs seam; only `agent_quote_child_main`'s RealTsmFs/GC binding needs the SNP
// guest (exercised by the disk-quote-test smoke, sub-slice 4).
// ---------------------------------------------------------------------------------------------------

/// Which configfs step the fetch last attempted — drives the ERR-frame code without string-matching
/// the fetch errors (the wrapper records the step; the two outblob POST-checks are refined by their
/// pinned in-crate literals below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchStep {
    None,
    CreateEntry,
    WriteInblob,
    ReadOutblob,
}

/// Forwarding [`crate::snp_report::TsmFs`] wrapper that records the last-attempted step, so a fetch
/// failure maps to its ERR code structurally (create→2, inblob→3, outblob→4) instead of by parsing
/// error text.
struct StepTracker<'a, F: crate::snp_report::TsmFs> {
    inner: &'a F,
    last: std::cell::Cell<FetchStep>,
}

impl<F: crate::snp_report::TsmFs> crate::snp_report::TsmFs for StepTracker<'_, F> {
    fn remove_entry(&self, entry: &str) {
        self.inner.remove_entry(entry);
    }
    fn create_entry(&self, entry: &str) -> Result<(), ProtocolError> {
        self.last.set(FetchStep::CreateEntry);
        self.inner.create_entry(entry)
    }
    fn write_inblob(&self, entry: &str, data: &[u8; 64]) -> Result<(), ProtocolError> {
        self.last.set(FetchStep::WriteInblob);
        self.inner.write_inblob(entry, data)
    }
    fn read_outblob(&self, entry: &str) -> Result<Vec<u8>, ProtocolError> {
        self.last.set(FetchStep::ReadOutblob);
        self.inner.read_outblob(entry)
    }
    fn read_auxblob(&self, entry: &str) -> Vec<u8> {
        self.inner.read_auxblob(entry)
    }
}

// The two outblob POST-check messages are snp_report's pub(crate) consts (single source — the emitter
// and this refinement CANNOT drift; the previous transcribed-copy + self-referential pin-test
// arrangement guaranteed nothing).
use crate::snp_report::{OUTBLOB_OVERSIZE_MSG, OUTBLOB_SHORT_MSG};

/// Map a failed fetch to its ERR-frame code (the parent's `child_err_str` table, (d-i)).
fn child_err_code(step: FetchStep, err: &ProtocolError) -> u8 {
    let msg = match err {
        ProtocolError::PqSigningUnavailable(m) | ProtocolError::WireProtocol(m) => *m,
        _ => "",
    };
    if msg == OUTBLOB_OVERSIZE_MSG {
        return 5;
    }
    if msg == OUTBLOB_SHORT_MSG {
        return 6;
    }
    match step {
        FetchStep::CreateEntry => 2,
        FetchStep::WriteInblob => 3,
        FetchStep::ReadOutblob => 4,
        // Pre-step failure: unreachable with the child's pinned `None` deadline (remove_entry is
        // infallible; check_deadline(None) never errors — create always records first). A TOTAL fold,
        // deliberately NOT `unreachable!()`: the child must never panic (a panic = exit 101 with no
        // frame — the exact undiagnosable ambiguity the frame protocol exists to prevent).
        FetchStep::None => {
            // debug_assert (compiled OUT of the release child — release keeps the total fold to 4,
            // preserving the never-panic rule) makes the prose guard above CHECKED in the deviceless
            // debug tests: it fires if a fallible pre-create op, a Some deadline, or a tracker
            // record-after-delegate reordering ever makes this arm reachable.
            debug_assert!(
                false,
                "fetch Err with no step recorded — pinned-None-deadline invariant broken; \
                 rework child_err_code's step mapping"
            );
            4
        }
    }
}

/// Exit code when the frame WRITE itself fails (EPIPE after the parent closed the pipe, etc.):
/// distinct from the fetch-step codes so triage can tell "child couldn't fetch" from "child fetched
/// but the parent was gone". The child contract pins ANY write error ⇒ immediate nonzero exit (Rust
/// ignores SIGPIPE — EPIPE is an `Err`, not a kernel kill; lingering instead of exiting is the
/// orphan-leak the §8 rules forbid).
pub(crate) const CHILD_EXIT_WRITE_FAILED: i32 = 10;

/// Write one frame + flush; map the result to the exit code — THE single write-failure policy site
/// (every frame path goes through here; a policy change cannot ship one-sided).
fn emit<W: std::io::Write>(out: &mut W, frame: &[u8], ok_code: i32) -> i32 {
    use std::io::Write as _; // for the stderr breadcrumb below
    if out.write_all(frame).and_then(|_| out.flush()).is_ok() {
        ok_code
    } else {
        // Best-effort journald breadcrumb: in production stderr is INHERITED (NOT the protocol pipe),
        // so this is the only observable evidence distinguishing "parent was gone" from "child could
        // not fetch" (the parent discards reaped exit statuses today — §8 records parent-side reap
        // logging as a named obligation). In the test smokes stderr IS the protocol pipe — but this
        // path only fires when that pipe is already dead, so the write is a harmless no-op Err.
        // ACCEPTED HAZARD (compact 8305, Low): this write is synchronous — a backpressured journald
        // could delay the child's exit here. Deliberate: by emit-time the configfs entry is already
        // cleaned (fetch cleanup precedes emit) so the child holds nothing; a parent-alive child is
        // SIGKILLed by the unconditional disposition regardless of where it blocks; only an ORPHAN
        // (parent died → that's what EPIPE here means) can linger, costing one pid until journald
        // drains. The alternative — fcntl(O_NONBLOCK) on inherited stderr — flips the SHARED open
        // file description non-blocking for every process holding it (incl. a still-alive parent's
        // own stderr), a strictly worse failure mode than a delayed orphan exit.
        let _ = writeln!(std::io::stderr(), "twod-hsm quote child: frame write failed (parent gone?)");
        CHILD_EXIT_WRITE_FAILED
    }
}

/// The testable CORE of the quote child: fetch at the SELF-NAMED unique entry
/// (`twod-hsm-q-<own pid>`, via [`crate::snp_report::fetch_report_with_at`] — UNBOUNDED `None`
/// deadline: the parent's pipe poll + SIGKILL is the bound, a cooperative timeout here would be the
/// exact best-effort theater (d) deletes) → encode ONE frame → single `write_all` → exit code.
/// Returns 0 on success; the ERR code (2..=6) when the fetch failed and the ERR frame was delivered;
/// [`CHILD_EXIT_WRITE_FAILED`] when any write failed. Generic over the seam + writer so the whole
/// thing is deviceless-testable (and the real-subprocess smokes drive it through a REAL child over a
/// fake fs — the full pipeline minus configfs).
pub(crate) fn quote_child_main_with<F: crate::snp_report::TsmFs, W: std::io::Write>(
    fs: &F,
    report_data: &[u8; 64],
    out: &mut W,
) -> i32 {
    let entry_path = crate::snp_report::quote_child_entry_path();
    let tracker = StepTracker { inner: fs, last: std::cell::Cell::new(FetchStep::None) };
    // NB the `None` deadline is pinned BY CONTRACT until the (d-ii)-4 parameter deletion makes it
    // structural: the parent's pipe poll + SIGKILL is the ONLY bound (a cooperative child-side timeout
    // is the best-effort theater §8 deleted). A Some-bearing variant must first rework
    // child_err_code's step mapping (a mid-sequence lapse would masquerade as the previous step).
    match crate::snp_report::fetch_report_with_at(&tracker, &entry_path, report_data, None) {
        Ok((report, mut cert_chain)) => {
            // Over-cap cert chain folds to EMPTY (auxblob is best-effort — mirror RealTsmFs's own
            // policy for seam impls that don't cap; failing the whole quote for a chain-size defect
            // would be the wrong severity AND the old fallback mislabeled it as an outblob error).
            if cert_chain.len() > crate::snp_report::MAX_CERT_CHAIN_LEN {
                cert_chain = Vec::new();
            }
            match encode_ok_frame(&report, &cert_chain) {
                Ok(frame) => emit(out, &frame, 0),
                // Structurally unreachable: fetch_report_inner_with enforces MIN ≤ report ≤ MAX for
                // EVERY TsmFs impl and the chain is folded above — kept as a total non-panicking fold
                // (never-panic child rule), labeled with the oversize code as the closest truth.
                Err(_) => emit(out, &encode_err_frame(5), 5),
            }
        }
        Err(e) => {
            let code = child_err_code(tracker.last.get(), &e);
            emit(out, &encode_err_frame(code), i32::from(code))
        }
    }
}

/// Parse the hex-encoded 64-byte report_data from the child's env. Lowercase-only BY DESIGN — the
/// only writer is the parent's `hex128` (lowercase emitter); this is never operator-typed input.
/// Returns `Err` (never panics) so a malformed/missing env folds to the ERR(1) frame + exit 1 — a
/// child must never die with an unexplained panic when it can still tell the parent why.
pub(crate) fn parse_report_data_env(val: &std::ffi::OsStr) -> Result<[u8; 64], ProtocolError> {
    let s = val
        .to_str()
        .ok_or(ProtocolError::WireProtocol("quote child: report_data env not UTF-8"))?;
    let b = s.as_bytes();
    if b.len() != 128 {
        return Err(ProtocolError::WireProtocol("quote child: report_data env wrong length"));
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        let hi = nib(b[2 * i]);
        let lo = nib(b[2 * i + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => out[i] = (h << 4) | l,
            _ => return Err(ProtocolError::WireProtocol("quote child: report_data env bad hex")),
        }
    }
    Ok(out)
}

/// The child-mode entrypoint proper (reached ONLY via [`agent_quote_child_dispatch`], the
/// crate-root-exported self-dispatching wrapper — bins are separate crates and this module is
/// private, so the wrapper is the entire public surface; the env names stay crate-private).
///
/// Sequence: parse [`QUOTE_CHILD_REPORT_DATA_ENV`] (bad/missing ⇒ ERR frame code 1 + exit 1, never a
/// panic) → best-effort orphan GC at the REAL configfs dir (child-side ONLY, per §8) → fetch at the
/// self-named entry over [`crate::snp_report::RealTsmFs`] → ONE frame to STDOUT (production pipes
/// stdout; stderr is inherited to journald for triage — stdout is PROTOCOL-ONLY, nothing else may
/// write to it) → exit. NEVER spawns anything (and the spawner-level + orchestration-level brakes
/// refuse even if it tried).
pub(crate) fn agent_quote_child_main() -> ! {
    /// Production-only exit: a BEST-EFFORT stderr breadcrumb per nonzero exit (`twod-hsm quote child:
    /// exit <code>`) toward journald via inherited stderr — best-effort because it is written AFTER
    /// the frame flush and the parent SIGKILLs on frame receipt, so it can lose the race; the reliable
    /// cause-carrier is the in-band ERR frame (parent-visible), and parent-side reap logging stays the
    /// named §8 obligation. Code 10 is skipped: `emit` already wrote its more specific write-failure
    /// line. Lives HERE and not in `emit`/`quote_child_main_with` BY DESIGN: in the real-subprocess CI
    /// smokes stderr IS the protocol pipe and the parser rejects trailing bytes — a breadcrumb in the
    /// shared core would corrupt the smoke protocol stream. This entrypoint has zero CI coverage (§8
    /// pin: production shape is aya-smoke-only); the (4c) aya smoke verifies it.
    fn exit_child(code: i32) -> ! {
        if code != 0 && code != CHILD_EXIT_WRITE_FAILED {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "twod-hsm quote child: exit {code}");
        }
        std::process::exit(code);
    }
    let mut out = std::io::stdout();
    let rd = std::env::var_os(QUOTE_CHILD_REPORT_DATA_ENV)
        .ok_or(ProtocolError::WireProtocol("quote child: report_data env missing"))
        .and_then(|v| parse_report_data_env(&v));
    let rd = match rd {
        Ok(rd) => rd,
        // ONE error arm for missing AND malformed env: ERR(1) frame, exit 1 — but a FAILED frame write
        // escalates to CHILD_EXIT_WRITE_FAILED like every other path (emit owns the policy), so
        // "bad env, frame delivered" and "parent was gone" stay distinguishable in the exit status.
        Err(_) => exit_child(emit(&mut out, &encode_err_frame(1), 1)),
    };
    crate::snp_report::gc_quote_entries_default();
    let code = quote_child_main_with(&crate::snp_report::RealTsmFs, &rd, &mut out);
    exit_child(code);
}

// ---------------------------------------------------------------------------------------------------
// Tests. Deviceless — run by the existing CI leaf step (`--features vsock-transport,agent-gateway`).
// Every test names the regression it discriminates. HONESTY NOTE (the discriminating-test rule): a true
// D-state child cannot be staged on demand in ANY environment (CI or aya) — the unreapable arm's only
// deterministic coverage is the Fake-handle ledger tests below; the real-subprocess smokes prove
// S-state behavior (sleeping children) and the plumbing.
// ---------------------------------------------------------------------------------------------------
/// THE quote-child dispatch — the ONE line the 5b-2c bin's `main` must call FIRST, unconditionally:
/// returns immediately in a normal (parent) process; never returns in a spawned quote child. Exported
/// at the crate root (this module is private), so the §8 "first statement of main" contract is
/// satisfiable by `enclave_protocol::agent_quote_child_dispatch();` — the dispatch CONDITION (the
/// marker env) stays crate-private and cannot be re-keyed one-sided. A forgotten dispatch fail-closes,
/// but the enforcement is the PARENT's kill bound, not the child failing fast: the dispatch-less child
/// runs the full boot logic against an env-cleared environment and may scribble boot-logic output onto
/// protocol stdout — or block and write nothing at all — until it is killed. Either way the parent's
/// only wait is the pipe deadline (`read_child_reply`'s `poll_with_deadline`): garbage fails frame
/// decode, silence lapses the deadline, both fold retryable → `RetriesExhausted`, and the unconditional
/// disposition SIGKILLs the child on every path — never a hang, never a serve, because the parent
/// bounds it, not because the child cooperates.
///
/// **NOT an authentication boundary (threat-model; §8 pin, matrix HIGH refuted 3-0):** dispatch
/// deliberately carries no parent-vs-external-launch check. The SNP signing oracle is configfs-tsm +
/// firmware — natively available to ANY equally-privileged in-guest process, and the report carries no
/// requesting-process identity — so an env-token/ppid/parent-capability check would be unfalsifiable
/// theater, and deriving report_data from key material inside the child would move secrets INTO the
/// SIGKILL-able child (which deliberately holds zero) for no oracle reduction. report_data trust comes
/// from the relying party's derive-and-compare rule + the measured-boot chain (TASK-16 must cover the
/// cmdline/env channel). Standing preconditions: the binary is never installed setuid nor wrapped by a
/// privileged env-forwarding service, and no relying path ascribes extra weight to "this binary
/// produced the quote".
///
/// **Child exit-code table (ops/journald triage):**
/// `0` ok (frame delivered) · `1` bad/missing report_data env (ERR(1) frame delivered) · `2..=6` fetch
/// failed at {2 create, 3 inblob, 4 outblob read, 5 outblob oversize, 6 outblob short} (ERR frame
/// delivered; same code) · `10` [`CHILD_EXIT_WRITE_FAILED`] — the frame write itself failed (parent
/// gone; one stderr breadcrumb is emitted) · `101` rust panic (must never happen — child-reachable
/// code MUST stay total: no `unwrap`/`expect`/`unreachable!()`/indexing/unchecked arithmetic on
/// external input (env, configfs blobs, frame bytes); unreachable cases fold to the nearest honest
/// code, guarded by `debug_assert!` so tests check what release must never hit). NB the PARENT
/// currently discards reaped exit statuses (parent-side reap-status logging is a named §8 obligation);
/// child-side, every nonzero exit emits a BEST-EFFORT stderr breadcrumb from the production entrypoint
/// (`twod-hsm quote child: exit <code>`, journald via inherited stderr — the code-10 write-failure
/// line subsumes its own). Best-effort because it races the parent: the breadcrumb is written AFTER
/// the frame flush, and the parent SIGKILLs the child as soon as it parses the frame — the reliable
/// cause-carrier is the in-band ERR frame itself (parent-visible as the retryable error string), not
/// journald; reap logging remains the obligation.
pub fn agent_quote_child_dispatch() {
    if std::env::var_os(QUOTE_CHILD_ENV).is_some() {
        agent_quote_child_main();
    }
}

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
        // checked_sub-with-now()-fallback is CORRECT here (and in cancellable_boundary) because the
        // lapse check is remaining_or_lapsed, whose MIN_BOUNDARY_BUDGET floor treats a bare now() as
        // already-lapsed — the fallback cannot turn this into a NON-past fluke. Contrast
        // snp_report::tests::past(), which deliberately uses direct subtraction: its consumer
        // (check_deadline) is a STRICT `now >= d` compare where a now()-fallback could race to a
        // not-yet-lapsed instant. Two patterns, two lapse semantics — not an inconsistency.
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

    // ---- (d-ii)/2 HardBoundedQuoteProducer (the structural serve-gate type) ----

    use crate::agent_boot_relay::BootQuoteProducer as _;

    #[test]
    fn producer_fetch_is_the_hard_bound_not_a_skeleton() {
        // Regression: the §8 gate-lie — a skeleton/cooperative delegate satisfying the 5b-2c
        // by-signature gate while the wedged-read hang (or a deadline re-mint) remains. Arm (a): a
        // silent (wedged) fake through the TRAIT path must lapse at ~the deadline, kill once, and
        // abandon to the producer's own ledger. Arm (b): an ALREADY-PAST deadline errs with the same
        // relabelled lapse and ZERO spawns — proving the seam-minted deadline is forwarded VERBATIM
        // (a re-minted `now()+x` inside fetch could never be already-lapsed).
        let spawn = FakeSpawn::new(FakePlan::Silent, false);
        let (kills, spawns) = (Rc::clone(&spawn.kills), Rc::clone(&spawn.spawns));
        let mut p = HardBoundedQuoteProducer::new_unclaimed_for_tests(spawn);
        let start = Instant::now();
        let err = p
            .fetch(&[0u8; 64], start + Duration::from_millis(100))
            .expect_err("wedged child must lapse through the trait path");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "got {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "must return at the deadline");
        assert_eq!(*kills.borrow(), 1, "exactly one SIGKILL through the wrapper");
        assert_eq!(p.ledger.len(), 1, "abandoned to THE producer-owned ledger");
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let err = p.fetch(&[0u8; 64], past).expect_err("past deadline must fast-path");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "got {err:?}"
        );
        assert_eq!(*spawns.borrow(), 1, "no spawn on the past-deadline arm (deadline not re-minted)");
    }

    #[test]
    fn producer_single_ledger_accumulates_across_fetches_no_cap_reset() {
        // THE pin-(1) test (§8 verbatim: "a fresh ledger per attempt resets is_full() and voids the
        // cap"): ONE producer across repeated lapsing fetches must accumulate 1, 2, 3 abandoned
        // children — a fresh-ledger-per-attempt impl can never exceed 1. Then a pre-filled ledger
        // (O(1), the fetch_refuses_past_budget_before_spawn precedent — not a 64-lapse loop) must
        // refuse the next TRAIT fetch BEFORE spawning.
        let spawn = FakeSpawn::new(FakePlan::Silent, false);
        let spawns = Rc::clone(&spawn.spawns);
        let mut p = HardBoundedQuoteProducer::new_unclaimed_for_tests(spawn);
        // 50ms deadlines: well above the MIN_BOUNDARY_BUDGET floor (1ms) yet 3x cheaper than the
        // 150ms first draft — the discriminated property is ledger accumulation, not lapse timing
        // (the lapse string/timing is pinned by producer_fetch_is_the_hard_bound_not_a_skeleton).
        for expected in 1..=3usize {
            let _ = p
                .fetch(&[0u8; 64], Instant::now() + Duration::from_millis(50))
                .expect_err("silent child must lapse");
            assert_eq!(p.ledger.len(), expected, "ledger must accumulate MONOTONE across fetches");
        }
        while p.ledger.len() < ABANDONED_CHILD_BUDGET {
            p.ledger.abandon(FakeHandle::unreapable());
        }
        let before = *spawns.borrow();
        let err = p.fetch(&[0u8; 64], future()).expect_err("full ledger must refuse via the trait");
        assert!(
            matches!(err, ProtocolError::WireProtocol("quote child: abandoned-child budget exhausted")),
            "got {err:?}"
        );
        assert_eq!(*spawns.borrow(), before, "budget refuse must come BEFORE spawn");
    }

    #[test]
    fn producer_success_path_delegates_and_disposes() {
        // Regression: a wrapper variant that bypasses the unconditional disposition on success (a
        // kill-free success path would linger a child that wedges in its own cleanup).
        let rd = [0x66u8; 64];
        let frame = encode_ok_frame(&test_report(&rd), &[0x01]).unwrap();
        let spawn = FakeSpawn::new(FakePlan::FullFrame(frame), true);
        let kills = Rc::clone(&spawn.kills);
        let mut p = HardBoundedQuoteProducer::new_unclaimed_for_tests(spawn);
        let (report, chain) = p.fetch(&rd, future()).expect("healthy fetch through the trait");
        assert_eq!(report, test_report(&rd));
        assert_eq!(chain, vec![0x01]);
        assert_eq!(*kills.borrow(), 1, "unconditional disposition must fire THROUGH the wrapper");
        assert_eq!(p.ledger.len(), 0, "reapable child must not be abandoned");
    }

    #[test]
    fn producer_new_claims_the_process_ledger_exactly_once() {
        // THE claim test (serialized; the OTHER claim site is the equally-serialized
        // production_transport_claims_once_and_threads_the_validated_timeout — no third caller of
        // new()/production() exists): (a) production()
        // claims; (b) a second construction refuses with the exact fail-closed string; (c) Drop must
        // NOT release (release-on-drop hands the next producer a fresh ledger — the §8 voided-cap
        // hole); (d) the crate reset site clears the claim (a forgotten hook in
        // lock_and_reset_agent_process_globals fails HERE — reset-site symmetry). NB ((d-ii)/3):
        // validation-before-claim has no runtime ordering arm because the witness SIGNATURE is the
        // artifact — `budget` below is constructed first or this test does not compile. test_budget()
        // construction inside the lock-held body is lock-order-safe: validate() is pure, no globals.
        let g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let budget = test_budget();
        let first =
            HardBoundedQuoteProducer::production(&budget).expect("first claim must succeed");
        // Composition pin: production() must wire EXACTLY the pinned production spawn shape (the
        // shape-pin test asserts ExecChildSpawn::production() directly; THIS assert closes the gap
        // where production()'s one-line body silently swaps in a different shape and every CI test
        // stays green until the expensive (4c) in-guest failure).
        assert_eq!(first.spawn.program, std::path::PathBuf::from("/proc/self/exe"));
        assert_eq!(first.spawn.pipe_source, PipeSource::Stdout);
        assert!(first.spawn.clear_env && first.spawn.leading_args.is_empty());
        assert!(first.spawn.extra_env.is_empty(), "production child env = marker + report_data ONLY");
        let err = HardBoundedQuoteProducer::new(&budget, FakeSpawn::new(FakePlan::Silent, false))
            .err()
            .expect("second construction must refuse");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("quote producer: process quote ledger already claimed")
            ),
            "got {err:?}"
        );
        drop(first);
        assert!(
            HardBoundedQuoteProducer::new(&budget, FakeSpawn::new(FakePlan::Silent, false)).is_err(),
            "Drop must NOT release the claim (release-on-drop re-opens the voided-cap hole)"
        );
        // Re-locking while holding g would deadlock (the guard Mutex is non-reentrant) — drop FIRST.
        drop(g);
        let _g2 = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(
            HardBoundedQuoteProducer::new(&budget, FakeSpawn::new(FakePlan::Silent, false)).is_ok(),
            "the crate reset site must clear the claim (reset-site symmetry)"
        );
        // Leave the flag PRISTINE on exit (the assert above re-claimed it): a future test that calls
        // new() without following the TEST RULE would otherwise inherit this test's leftover claim as
        // a scheduling-dependent flake far from its root cause. (Still hygiene, not a license — the
        // TEST RULE stands.)
        reset_process_quote_ledger_claim_for_tests();
    }

    #[test]
    fn production_spawner_shape_is_pinned() {
        // Pins CONSTRUCTION only — §8 pin (2): the shape's runtime behavior has ZERO CI coverage BY
        // PIN; the (4c) in-guest aya smoke is the checked discharge. Regression: silent drift of the
        // aya-only shape (flipped clear_env / Stderr pipe / sneaked leading args / a current_exe()
        // PATH replacing the exec-time-coherent /proc/self/exe LITERAL) shipping unnoticed until an
        // expensive in-guest failure.
        let s = ExecChildSpawn::production();
        assert_eq!(s.program, std::path::PathBuf::from("/proc/self/exe"), "the LITERAL, not a path");
        assert!(s.leading_args.is_empty(), "no leading args (dispatch-first bin contract)");
        assert!(s.extra_env.is_empty(), "no extra env (clear_env + marker + report_data only)");
        assert_eq!(s.pipe_source, PipeSource::Stdout, "protocol pipe = stdout (PROTOCOL-ONLY)");
        assert!(s.clear_env, "production child env must be cleared");
    }

    #[test]
    fn producer_end_to_end_real_subprocess() {
        // Regression: process-boundary drift against the SHIPPED producer type — one seam above
        // child_core_end_to_end_through_real_subprocess (which stays as the orchestration pin): the
        // REAL child core through THE HardBoundedQuoteProducer trait fetch.
        let rd = [0x5Bu8; 64];
        let mut p = HardBoundedQuoteProducer::new_unclaimed_for_tests(smoke_spawn("child-main-ok"));
        let (report, chain) =
            p.fetch(&rd, Instant::now() + Duration::from_secs(10)).expect("producer e2e fetch");
        assert_eq!(report, test_report(&rd), "report delivered verbatim (incl. echo)");
        assert_eq!(chain, vec![0xC1, 0xC2]);
        assert_eventually_swept(&mut p.ledger);
    }

    #[test]
    fn producer_wedged_child_lapses_at_deadline_real_subprocess() {
        // THE hang (d) exists to kill, asserted on the FINAL serve-gate type with a REAL child: a
        // wait()/blocking reintroduction one level up (the wrapper) hangs here.
        let mut p = HardBoundedQuoteProducer::new_unclaimed_for_tests(smoke_spawn("wedge"));
        let start = Instant::now();
        let err = p
            .fetch(&[0u8; 64], start + Duration::from_millis(400))
            .expect_err("wedged real child must lapse through the producer");
        assert!(
            matches!(err, ProtocolError::WireProtocol("anchor relay: quote pipe deadline lapsed")),
            "got {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(3), "must return ~at the deadline");
        assert_eventually_swept(&mut p.ledger);
    }

    #[test]
    fn producer_composes_into_relay_transport() {
        // Regression: composition drift at the exact (4b) mount point — the hard producer inside the
        // REAL RelayAnchorTransport must compile and flow bytes TODAY (quote↔nonce binding flowing
        // producer→request unmodified) so (4b) is zero-rework. Scope honesty: this pins BYTE FLOW
        // only — deadline-verbatim is pinned at the producer level by
        // producer_fetch_is_the_hard_bound_not_a_skeleton arm (b) and at the transport level by the
        // relay module's deadline_honoring FakeQuote tests; this test's channel discards its
        // deadline. ORDER MATTERS: report_data is DERIVED first — decode_anchor_boot_request
        // enforces report_data == anchor_handshake_report_data(chain, env, nonce), so a fixture-first
        // test fails confusingly.
        let nonce = [0x5Cu8; 32];
        let rd = crate::agent_anchor::anchor_handshake_report_data(7, "env-x", &nonce);
        let frame = encode_ok_frame(&test_report(&rd), &[0xC7; 8]).unwrap();
        let producer =
            HardBoundedQuoteProducer::new_unclaimed_for_tests(FakeSpawn::new(FakePlan::FullFrame(frame), true));
        // Minimal channel: records the request frame via a shared handle (the transport's fields are
        // private to agent_boot_relay, and its scripted mock lives in that module's tests), returns
        // canned bytes.
        struct CapturingChannel {
            seen: Rc<RefCell<Vec<Vec<u8>>>>,
            reply: Vec<u8>,
        }
        impl crate::agent_boot_relay::BootRelayChannel for CapturingChannel {
            fn round_trip(
                &mut self,
                request_frame: &[u8],
                _deadline: Instant,
            ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
                self.seen.borrow_mut().push(request_frame.to_vec());
                Ok(self.reply.clone())
            }
        }
        let seen = Rc::new(RefCell::new(Vec::new()));
        let channel = CapturingChannel { seen: Rc::clone(&seen), reply: vec![0xAB; 64] };
        let mut transport = crate::agent_boot_relay::RelayAnchorTransport::new(
            producer,
            channel,
            Duration::from_secs(5),
        );
        let req = crate::agent_boot_driver::AnchorBootRequest {
            chain_id: 7,
            environment_identifier: "env-x",
            nonce,
            report_data: rd,
        };
        use crate::agent_boot_driver::AnchorBootTransport as _;
        let reply = transport.anchor_round_trip(&req).expect("composed round-trip");
        assert_eq!(reply, vec![0xAB; 64], "anchor bytes returned VERBATIM");
        let captured = seen.borrow();
        assert_eq!(captured.len(), 1, "exactly one channel round-trip");
        let decoded =
            crate::agent_boot_relay::decode_anchor_boot_request(&captured[0]).expect("decodable");
        assert_eq!(decoded.quote_report, test_report(&rd), "producer report flowed into the frame");
        assert_eq!(decoded.report_data, rd, "report_data binding flowed unmodified");
    }

    // ---- (d-ii)/3 ValidatedBootBudget (pure; gate #2 of the TWO-artifact live-serve gate) ----

    fn generous() -> Duration {
        Duration::from_secs(3600)
    }

    /// The witness most tests need: ceiling attempts, a comfortable timeout, an hour of budget.
    fn test_budget() -> ValidatedBootBudget {
        ValidatedBootBudget::validate(
            crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING,
            Duration::from_millis(50),
            generous(),
        )
        .expect("helper budget must validate")
    }

    /// Test-side derivation of the nominal product `n·(t+t+ε)` — deliberately a SECOND derivation
    /// (not a call into the production `per_attempt_nominal_cost`) so the boundary tests stay an
    /// independent check of the formula, but single-sourced across them: a formula retune is one
    /// test-side edit, not three drifting copies (the third copy drifting LARGER would silently
    /// weaken the ε-pin's positive arm — `validate` accepts any overall ≥ nominal).
    fn nominal_product(n: u32, t: Duration) -> Duration {
        t.checked_add(t)
            .and_then(|legs| legs.checked_add(QUOTE_ATTEMPT_OVERHEAD))
            .and_then(|p| p.checked_mul(n))
            .expect("test arithmetic fits")
    }

    #[test]
    fn boot_budget_rejects_zero_max_attempts() {
        // Regression: the zero rejection must exist at CONFIG-parse time, not lean on the driver's
        // runtime Unstartable (different surface, §8-mandated config-parse half).
        let err = ValidatedBootBudget::validate(0, Duration::from_millis(50), generous())
            .expect_err("zero attempts must refuse");
        assert!(
            matches!(err, ProtocolError::WireProtocol("boot budget: max_attempts must be >= 1")),
            "got {err:?}"
        );
    }

    #[test]
    fn boot_budget_rejects_over_ceiling_max_attempts() {
        // Regression: reject-don't-clamp drift between the artifact and the driver. Bound DERIVED
        // from the const (no 64 literal anywhere in this test).
        let ceiling = crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING;
        let err = ValidatedBootBudget::validate(ceiling + 1, Duration::from_millis(50), generous())
            .expect_err("over-ceiling must refuse");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: max_attempts exceeds MAX_BOOT_ATTEMPTS_CEILING")
            ),
            "got {err:?}"
        );
        assert!(
            ValidatedBootBudget::validate(ceiling, Duration::from_millis(50), generous()).is_ok(),
            "the ceiling itself is valid (reject is strictly-greater)"
        );
    }

    #[test]
    fn boot_budget_range_error_wins_over_floor_and_budget() {
        // Regression: §8 "the check MUST run AFTER max_attempts range validation" silently
        // reordered — operator first-fix triage would point at the wrong knob. Three arms: with
        // EVERY arm violated, the range strings win; with valid attempts the floor wins next.
        let err = ValidatedBootBudget::validate(0, Duration::ZERO, Duration::ZERO)
            .expect_err("all-violated must refuse");
        assert!(
            matches!(err, ProtocolError::WireProtocol("boot budget: max_attempts must be >= 1")),
            "zero-attempts must win over floor/budget, got {err:?}"
        );
        let over = crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING + 1;
        let err = ValidatedBootBudget::validate(over, Duration::ZERO, Duration::ZERO)
            .expect_err("all-violated must refuse");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: max_attempts exceeds MAX_BOOT_ATTEMPTS_CEILING")
            ),
            "ceiling must win over floor/budget, got {err:?}"
        );
        let err = ValidatedBootBudget::validate(1, Duration::ZERO, Duration::ZERO)
            .expect_err("floor+budget violated must refuse");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: per-leg timeout below MIN_BOUNDARY_BUDGET")
            ),
            "floor must precede the budget arithmetic, got {err:?}"
        );
    }

    #[test]
    fn boot_budget_rejects_sub_floor_timeout() {
        // Regression: a 0ms/sub-floor leg reaching the platform (set_read_timeout(ZERO) is an Err
        // on vsock; sub-floor poll budgets are the MIN_BOUNDARY_BUDGET hazard). Consts only — a
        // floor retune moves this test with it. Floor INCLUSIVE: == MIN passes.
        for bad in [Duration::ZERO, MIN_BOUNDARY_BUDGET - Duration::from_nanos(1)] {
            let err = ValidatedBootBudget::validate(1, bad, generous())
                .expect_err("sub-floor timeout must refuse");
            assert!(
                matches!(
                    err,
                    ProtocolError::WireProtocol("boot budget: per-leg timeout below MIN_BOUNDARY_BUDGET")
                ),
                "got {err:?}"
            );
        }
        assert!(
            ValidatedBootBudget::validate(1, MIN_BOUNDARY_BUDGET, generous()).is_ok(),
            "the floor itself is valid (inclusive, mirroring remaining_or_lapsed)"
        );
    }

    #[test]
    fn boot_budget_exact_equality_passes_and_getters_echo() {
        // Regression: ≤ silently tightened to < (§8 pins ≤; operator slack stays prose), or getters
        // drifting from the validated values. Overall computed FROM the consts via checked ops.
        let n = crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING;
        let t = Duration::from_millis(50);
        let overall = nominal_product(n, t);
        let b = ValidatedBootBudget::validate(n, t, overall)
            .expect("budget exactly equal to the nominal product must pass (≤, not <)");
        assert_eq!(b.max_attempts(), n);
        assert_eq!(b.per_leg_timeout(), t);
        assert_eq!(b.overall_boot_budget(), overall);
        assert_eq!(b.nominal_boot_cost(), overall, "stored nominal == the computed product");
    }

    #[test]
    fn boot_budget_one_nanosecond_short_fails() {
        // Regression: hidden slack/rounding at the boundary — a mis-sized config constructing in
        // RELEASE is the exact fail-closed MUST this artifact exists for.
        let n = crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING;
        let t = Duration::from_millis(50);
        let overall = nominal_product(n, t);
        let err = ValidatedBootBudget::validate(n, t, overall - Duration::from_nanos(1))
            .expect_err("one nanosecond short must refuse");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: nominal boot cost exceeds overall_boot_budget")
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn boot_budget_epsilon_less_product_is_not_a_ceiling() {
        // THE ε-is-the-const pin (§8 verbatim: "the ε-less product is NOT a valid ceiling"): an
        // implementation that drops ε — or transcribes a stale number — passes the equality/boundary
        // tests trivially; THIS test fails it. Both sides computed from QUOTE_ATTEMPT_OVERHEAD, so a
        // REAP_GRACE retune moves the check and this test TOGETHER (chains to the
        // attempt_overhead_dominated_by_reap_grace derivation pin).
        let n = crate::agent_boot_driver::MAX_BOOT_ATTEMPTS_CEILING;
        let t = Duration::from_millis(50);
        let epsilon_less = t.checked_add(t).and_then(|l| l.checked_mul(n)).expect("fits");
        let err = ValidatedBootBudget::validate(n, t, epsilon_less)
            .expect_err("the ε-less product must NOT be accepted as a ceiling");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: nominal boot cost exceeds overall_boot_budget")
            ),
            "got {err:?}"
        );
        assert!(
            ValidatedBootBudget::validate(n, t, nominal_product(n, t)).is_ok(),
            "the ε-bearing product is the valid ceiling"
        );
    }

    #[test]
    fn boot_budget_sanity_ceiling_guards_the_instant_mints() {
        // Regression: validate() blessing a per-leg value that PANICS downstream — the transport
        // mints deadlines as `Instant::now() + timeout` (std Add panics on overflow; linux Instant
        // seconds are i64), so without the ceiling arm `u64::MAX / 2` secs passes every other arm
        // against overall == Duration::MAX and aborts boot on the FIRST round-trip instead of the
        // wiring-time Err the gate promises. TEST DISCIPLINE: huge values go STRAIGHT into validate.
        let err = ValidatedBootBudget::validate(1, Duration::from_secs(u64::MAX / 2), Duration::MAX)
            .expect_err("an Instant-overflow-capable timeout must refuse at the ceiling");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: per-leg timeout exceeds MAX_PER_LEG_TIMEOUT")
            ),
            "got {err:?}"
        );
        assert!(
            ValidatedBootBudget::validate(1, MAX_PER_LEG_TIMEOUT, Duration::MAX).is_ok(),
            "the ceiling itself is valid (inclusive on the pass side)"
        );
        let err =
            ValidatedBootBudget::validate(1, MAX_PER_LEG_TIMEOUT + Duration::from_nanos(1), Duration::MAX)
                .expect_err("one nanosecond over the ceiling must refuse");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("boot budget: per-leg timeout exceeds MAX_PER_LEG_TIMEOUT")
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn boot_budget_overflow_refuses_not_wraps() {
        // Regression: §8's named failure — "a wrapped product passing the check". CHECKED, not
        // saturating, is load-bearing: a SATURATED Duration::MAX product would PASS ≤ against
        // overall == Duration::MAX. With the MAX_PER_LEG_TIMEOUT arm in place the overflow arms are
        // UNREACHABLE through validate() (64 · (2h + ε) fits comfortably) — they are defense in
        // depth against a ceiling retune/removal, so the add arm is pinned DIRECTLY on the helper
        // (in-module, callable): the huge value goes STRAIGHT in (plain Duration ops on it in test
        // setup would panic, not refuse).
        let err = per_attempt_nominal_cost(Duration::from_secs(u64::MAX), Duration::from_secs(u64::MAX))
            .expect_err("add overflow must refuse, not wrap or pass");
        assert!(matches!(err, ProtocolError::WireProtocol(BOOT_BUDGET_OVERFLOW_MSG)), "got {err:?}");
    }

    #[test]
    fn production_transport_claims_once_and_threads_the_validated_timeout() {
        // Regression: a transport constructed with a timeout OTHER than the validated value (the
        // deadline-origination drift the §8 hardening note names), or a second producer door
        // bypassing the single claim. Serialized per the TEST RULE (holds the crate guard for the
        // whole body; the SECOND claim site, named by the claim test's pin).
        struct NeverChannel;
        impl crate::agent_boot_relay::BootRelayChannel for NeverChannel {
            fn round_trip(
                &mut self,
                _request_frame: &[u8],
                _deadline: Instant,
            ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
                panic!("composition test never round-trips");
            }
        }
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let budget = test_budget();
        let transport = budget
            .production_transport(NeverChannel)
            .expect("first composition must claim and construct");
        assert_eq!(
            transport.per_leg_timeout_for_tests(),
            budget.per_leg_timeout(),
            "the transport timeout MUST be the validated per-leg value (deadline origination)"
        );
        let err = budget
            .production_transport(NeverChannel)
            .err()
            .expect("second composition must refuse via the single claim");
        assert!(
            matches!(
                err,
                ProtocolError::WireProtocol("quote producer: process quote ledger already claimed")
            ),
            "got {err:?}"
        );
        // Pristine exit, same hygiene as the claim test.
        reset_process_quote_ledger_claim_for_tests();
    }

    // ---- (d-ii) child mode (deviceless over the TsmFs seam) ----

    /// Recording fake: a healthy provider that captures every entry path it is given.
    struct OkFs {
        outblob: Vec<u8>,
        auxblob: Vec<u8>,
        paths: RefCell<Vec<String>>,
        fail_step: Option<&'static str>,
    }

    impl OkFs {
        fn healthy(rd: &[u8; 64]) -> Self {
            Self {
                outblob: test_report(rd),
                auxblob: vec![0xC1, 0xC2],
                paths: RefCell::new(Vec::new()),
                fail_step: None,
            }
        }
        fn failing_at(step: &'static str) -> Self {
            Self {
                outblob: Vec::new(),
                auxblob: Vec::new(),
                paths: RefCell::new(Vec::new()),
                fail_step: Some(step),
            }
        }
    }

    impl crate::snp_report::TsmFs for OkFs {
        fn remove_entry(&self, entry: &str) {
            self.paths.borrow_mut().push(format!("remove:{entry}"));
        }
        fn create_entry(&self, entry: &str) -> Result<(), ProtocolError> {
            self.paths.borrow_mut().push(format!("create:{entry}"));
            if self.fail_step == Some("create") {
                return Err(ProtocolError::PqSigningUnavailable("fake create failure"));
            }
            Ok(())
        }
        fn write_inblob(&self, entry: &str, _data: &[u8; 64]) -> Result<(), ProtocolError> {
            self.paths.borrow_mut().push(format!("inblob:{entry}"));
            if self.fail_step == Some("inblob") {
                return Err(ProtocolError::PqSigningUnavailable("fake inblob failure"));
            }
            Ok(())
        }
        fn read_outblob(&self, entry: &str) -> Result<Vec<u8>, ProtocolError> {
            self.paths.borrow_mut().push(format!("outblob:{entry}"));
            match self.fail_step {
                Some("outblob") => Err(ProtocolError::PqSigningUnavailable("fake outblob failure")),
                // REAL-PATH arms (not injected error strings): the oversize/short refinements must be
                // exercised through the genuine snp_report post-checks, so a reword there fails HERE.
                Some("oversize") => Ok(vec![0u8; crate::snp_report::MAX_OUTBLOB_LEN + 1]),
                Some("short") => Ok(Vec::new()),
                _ => Ok(self.outblob.clone()),
            }
        }
        fn read_auxblob(&self, entry: &str) -> Vec<u8> {
            self.paths.borrow_mut().push(format!("auxblob:{entry}"));
            self.auxblob.clone()
        }
    }

    #[test]
    fn child_main_with_ok_frame_golden() {
        // Regression: the child/parent frame halves drifting (they live in different PROCESSES at
        // runtime) — the child core's output must be byte-equal to the codec the parent decodes.
        let rd = [0x71u8; 64];
        let fs = OkFs::healthy(&rd);
        let mut out = Vec::new();
        let code = quote_child_main_with(&fs, &rd, &mut out);
        assert_eq!(code, 0, "healthy fetch must exit 0");
        let expect = encode_ok_frame(&test_report(&rd), &[0xC1, 0xC2]).unwrap();
        assert_eq!(out, expect, "child output must be byte-equal to the canonical OK frame");
    }

    #[test]
    fn child_main_with_uses_self_named_entry_path() {
        // §8-obligated with the fetch_report_with_at promotion: prove the child fetch honors the
        // CUSTOM (self-named, pid-suffixed) entry path on every seam op — not the fixed producer name.
        let rd = [0x72u8; 64];
        let fs = OkFs::healthy(&rd);
        let mut out = Vec::new();
        assert_eq!(quote_child_main_with(&fs, &rd, &mut out), 0);
        let want = crate::snp_report::quote_child_entry_path();
        assert!(
            want.ends_with(&format!("twod-hsm-q-{}", std::process::id())),
            "self-named path must be prefix+own-pid, got {want}"
        );
        let paths = fs.paths.borrow();
        assert!(!paths.is_empty());
        for p in paths.iter() {
            let (_op, path) = p.split_once(':').unwrap();
            assert_eq!(path, want, "every seam op must target the self-named entry, got {p}");
        }
    }

    #[test]
    fn child_main_with_err_frame_on_fs_failure() {
        // Regression: a step failure crashing the child into an ambiguous parent error instead of the
        // coded ERR frame (+ the configfs sequence stopping at the failing step).
        for (step, code, expect_msg) in [
            ("create", 2u8, "quote child: entry create failed"),
            ("inblob", 3, "quote child: inblob write failed"),
            ("outblob", 4, "quote child: outblob read failed"),
        ] {
            let fs = OkFs::failing_at(step);
            let mut out = Vec::new();
            let exit = quote_child_main_with(&fs, &[0u8; 64], &mut out);
            assert_eq!(exit, i32::from(code), "step {step} must exit with its code");
            assert_eq!(out, encode_err_frame(code), "step {step} must emit ERR({code})");
            match parse_child_frame(&out).unwrap() {
                FrameProgress::Complete { reply: ChildReply::ChildError(msg) } => {
                    assert_eq!(msg, expect_msg);
                }
                other => panic!("expected ChildError, got {other:?}"),
            }
            // ...and the configfs SEQUENCE stops at the failing step (no post-failure I/O against a
            // possibly-wedged provider): the last recorded op is the failing one, save the trailing
            // unconditional cleanup remove.
            let paths = fs.paths.borrow();
            let ops: Vec<&str> = paths.iter().map(|p| p.split_once(':').unwrap().0).collect();
            let expect_ops: Vec<&str> = match step {
                "create" => vec!["remove", "create", "remove"],
                "inblob" => vec!["remove", "create", "inblob", "remove"],
                "outblob" => vec!["remove", "create", "inblob", "outblob", "remove"],
                _ => unreachable!(),
            };
            assert_eq!(ops, expect_ops, "step {step}: sequence must stop at the failure + cleanup");
        }
    }

    #[test]
    fn child_err_code_refines_outblob_postchecks() {
        // REAL-PATH refinement pin: the fake returns genuinely-oversize / genuinely-short outblobs, so
        // the errors come from snp_report's actual post-checks (single-source consts) — a reword or a
        // dropped check there fails HERE, end-to-end through child_err_code AND the parent string.
        for (step, code, parent_msg) in [
            ("oversize", 5u8, "quote child: outblob oversize"),
            ("short", 6, "quote child: outblob short"),
        ] {
            let fs = OkFs::failing_at(step);
            let mut out = Vec::new();
            let exit = quote_child_main_with(&fs, &[0u8; 64], &mut out);
            assert_eq!(exit, i32::from(code), "post-check {step} must refine to code {code}");
            match parse_child_frame(&out).unwrap() {
                FrameProgress::Complete { reply: ChildReply::ChildError(msg) } => {
                    assert_eq!(msg, parent_msg, "the PARENT half of the {code} row must decode");
                }
                other => panic!("expected ChildError, got {other:?}"),
            }
        }
    }

    #[test]
    fn child_err_table_every_emittable_code_decodes() {
        // Both-ways table pin: every code the child can put in an ERR frame (1 = env, 2..=6 = fetch)
        // must decode to a REAL parent triage string — a one-sided table addition fails here instead
        // of silently folding to "unknown error code" at the parent.
        for code in 1u8..=6 {
            match parse_child_frame(&encode_err_frame(code)).unwrap() {
                FrameProgress::Complete { reply: ChildReply::ChildError(msg) } => {
                    assert_ne!(
                        msg, "quote child: unknown error code",
                        "code {code} must have a real parent string"
                    );
                }
                other => panic!("expected ChildError for {code}, got {other:?}"),
            }
        }
    }

    #[test]
    fn child_main_with_folds_overcap_chain_to_empty() {
        // Best-effort auxblob policy for seam impls that don't cap: an over-cap chain must NOT fail
        // the quote — it folds to empty (mirroring RealTsmFs) and the report still ships.
        let rd = [0x74u8; 64];
        let mut fs = OkFs::healthy(&rd);
        fs.auxblob = vec![0xEE; crate::snp_report::MAX_CERT_CHAIN_LEN + 1];
        let mut out = Vec::new();
        assert_eq!(quote_child_main_with(&fs, &rd, &mut out), 0, "over-cap chain must not fail");
        match parse_child_frame(&out).unwrap() {
            FrameProgress::Complete { reply: ChildReply::Quote { report, cert_chain } } => {
                assert_eq!(report, test_report(&rd));
                assert!(cert_chain.is_empty(), "over-cap chain folds to empty");
            }
            other => panic!("expected Quote, got {other:?}"),
        }
    }

    #[test]
    fn parse_report_data_env_rejects_bad_hex_and_length() {
        // Regression: a malformed env crashing the child into an ambiguous parent error instead of the
        // ERR(1)+exit(1) contract.
        use std::ffi::OsStr;
        let good = hex128(&[0xABu8; 64]);
        assert_eq!(parse_report_data_env(OsStr::new(&good)).unwrap(), [0xABu8; 64]);
        assert!(parse_report_data_env(OsStr::new("")).is_err(), "empty");
        assert!(parse_report_data_env(OsStr::new(&good[..126])).is_err(), "short");
        let upper = good.to_uppercase();
        assert!(parse_report_data_env(OsStr::new(&upper)).is_err(), "uppercase (lowercase-only)");
        let mut bad = good.clone();
        bad.replace_range(0..1, "g");
        assert!(parse_report_data_env(OsStr::new(&bad)).is_err(), "non-hex char");
    }

    // ---- real-subprocess smokes (current_exe + env-guarded #[ignore] helper; protocol over STDERR
    //      because the spawned TEST binary's stdout carries the unstable libtest banner) ----
    // These prove S-state behavior + the real Child/pipe/env plumbing. They run DEVICELESS in CI.
    // Subprocess tests stay lib tests forever: a `tests/` integration target would lose both the
    // current_exe-helper reachability and the pub(crate) seams.

    const HELPER_GUARD_ENV: &str = "TWOD_HSM_QUOTE_CHILD_TEST";

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
        // Decode via the PRODUCTION parser — the e2e smokes must cross the real process boundary
        // through the same decode path agent_quote_child_main uses (a drift between hex128 and
        // parse_report_data_env fails HERE, not first in-guest).
        let rd = std::env::var_os(super::QUOTE_CHILD_REPORT_DATA_ENV)
            .map(|v| parse_report_data_env(&v).expect("smoke: spawner-set env must parse"))
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
            "child-main-ok" => {
                // Run the REAL child core (over a fake healthy fs) inside a REAL child process — the
                // full (d) pipeline minus configfs. Protocol over stderr (the smoke pipe).
                let fs = OkFs::healthy(&rd);
                let code = quote_child_main_with(&fs, &rd, &mut err);
                std::process::exit(code);
            }
            "child-main-epipe" => {
                // Parent drops its read end immediately; the child's frame write must FAIL and the
                // child must exit CHILD_EXIT_WRITE_FAILED — the lingering-orphan-after-un-wedge rule
                // (Rust ignores SIGPIPE: EPIPE is an Err, the EXIT is the child's obligation).
                // DETERMINISTIC, not a sleep-race: wait for read-end-closed EVIDENCE — poll on the
                // WRITE end reports POLLERR once the reader is gone (a fixed sleep would flake the
                // other way if the PARENT got descheduled past it).
                let stderr = std::io::stderr();
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let revents =
                        poll_with_deadline(&stderr, nix::poll::PollFlags::empty(), deadline)
                            .expect("poll for reader-gone evidence");
                    if revents.intersects(nix::poll::PollFlags::POLLERR) {
                        break;
                    }
                }
                let fs = OkFs::healthy(&rd);
                let code = quote_child_main_with(&fs, &rd, &mut err);
                std::process::exit(code);
            }
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
    fn child_core_end_to_end_through_real_subprocess() {
        // The strongest (d-ii)-1 pin: a REAL child process runs the REAL child core (fake fs) and the
        // REAL parent orchestration drains/verifies it — the full pipeline minus configfs. Catches
        // process-boundary drift no in-process test can (frame chunking, env plumbing, exit paths).
        let rd = [0x73u8; 64];
        let mut ledger = AbandonedLedger::new();
        let (report, chain) = fetch_quote_via_child(
            &smoke_spawn("child-main-ok"),
            &mut ledger,
            &rd,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("end-to-end child-core fetch");
        assert_eq!(report, test_report(&rd), "report verbatim incl. echo");
        assert_eq!(chain, vec![0xC1, 0xC2]);
        assert_eventually_swept(&mut ledger);
    }

    #[test]
    fn child_exits_nonzero_on_epipe() {
        // Regression: a child that lingers (or exits 0) after its frame write fails — the orphan-leak
        // rule. Drop the read end BEFORE the child writes; expect CHILD_EXIT_WRITE_FAILED.
        let (pipe, handle) = smoke_spawn("child-main-epipe").spawn(&[0u8; 64]).expect("spawn");
        drop(pipe); // close the read end while the child is still in its 300ms sleep
        let mut guard = KillOnDrop::new(handle);
        let status = poll_status(guard.get_mut(), Duration::from_secs(10));
        assert_eq!(
            status.code(),
            Some(CHILD_EXIT_WRITE_FAILED),
            "failed frame write must exit CHILD_EXIT_WRITE_FAILED, got {status:?}"
        );
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
