//! Shared cancellable-boundary primitives for the agent boot relay (TASK-7.7 5b-2b-ii, PR-A).
//!
//! Both hard bounds the live anti-rollback serve needs reduce to ONE kernel problem: *wait on an fd until
//! ready-or-deadline, under `#![forbid(unsafe_code)]`, with no thread/fd leak.*
//! - **(a')** the cancellable CONNECT bound — `poll(POLLOUT)` on a non-blocking vsock connect fd.
//! - **(d)** the cancellable QUOTE bound — `poll(POLLIN)` on a killable-subprocess pipe-read fd.
//!
//! `poll_with_deadline` (below) is that shared core. It is backed by `nix::poll` — whose `poll` wrapper is SAFE
//! (the `unsafe` `libc::poll` lives inside `nix`), so this stays within the crate's `forbid(unsafe_code)`
//! boundary — and `nix` is a direct, target-gated (`cfg(target_os = "linux")`), optional dep folded into
//! `vsock-transport`, declaring `poll`/`socket`/`fs` explicitly (vsock's transitive nix dep enables only
//! `ioctl`/`socket` — see Cargo.toml for why we don't rely on it and what each feature is for). Linux +
//! vsock-transport gated, mirroring the channel it serves.
//!
//! The (a') consumer is LIVE: `agent_boot_relay::connect_bounded` calls `poll_with_deadline` +
//! `connect_poll_succeeded`. The module-wide `allow(dead_code)` below is NOT transitional leftovers — it
//! is held for the **consumer-free feature combos**: the only consumer (`agent_boot_relay`) is gated on
//! `agent-gateway`, while this module compiles under plain `vsock-transport`; the `production-vsock` /
//! `staging-vsock` profiles (which can never enable `agent-gateway` — the `ml-dsa-65 ⊕ agent-gateway`
//! role-isolation compile_error forbids it) would otherwise emit dead_code warnings for the whole module.
#![cfg_attr(not(test), allow(dead_code))]

use crate::ProtocolError;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

/// Minimum socket/poll budget we will arm: a remaining budget below this is treated as a (retryable) lapse.
/// The binding reason for BOTH consumers is (b): a sub-millisecond residual cannot complete a real
/// connect/round-trip, so failing fast as retryable is correct, not a spurious failure. Additionally, for
/// the *socket-timeout* consumer only, (a) `set_read_timeout(Some(Duration::ZERO))` is an *error* on vsock
/// 0.5 (not "no timeout") and a sub-µs `Duration` could round to a 0 = infinite `timeval` — the floor
/// avoids both. ((a) is irrelevant to the `poll` consumer, where `PollTimeout::ZERO` is a valid
/// return-immediately; only (b) binds there.)
pub(crate) const MIN_BOUNDARY_BUDGET: Duration = Duration::from_millis(1);

/// The subsystem-neutral lapse message produced by [`remaining_or_lapsed`] (and therefore by
/// `poll_with_deadline`). A named const — not an inline literal — because callers that RELABEL a lapse for
/// triage (e.g. `connect_bounded`'s connect-leg attribution) pattern-match this exact string; a reworded
/// literal would silently turn their match arms into dead code, so the coupling is pinned here (and by the
/// deviceless entry-lapse test in `agent_boot_relay`).
pub(crate) const DEADLINE_LAPSED_MSG: &str = "deadline lapsed";

/// Remaining budget until `deadline`, or `Err` (retryable) if already lapsed / below [`MIN_BOUNDARY_BUDGET`].
/// Single `now` sample; `checked_duration_since` is `None` when `deadline < now`. Anything below the floor
/// folds to the retryable lapse error, so no caller ever arms a zero/sub-ms socket/poll timeout. The error
/// string is subsystem-neutral because this helper is shared by the boot-relay channel AND the generic
/// `poll_with_deadline` primitive (e.g. the 5b-2b-ii(d) quote-subprocess pipe).
pub(crate) fn remaining_or_lapsed(deadline: Instant) -> Result<Duration, ProtocolError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if d >= MIN_BOUNDARY_BUDGET => Ok(d),
        _ => Err(ProtocolError::WireProtocol(DEADLINE_LAPSED_MSG)),
    }
}

/// Wait until `fd` is ready for `events` (e.g. `POLLIN`/`POLLOUT`) or the `deadline` elapses — a true
/// CANCELLABLE bound (the `poll` simply returns at the deadline; nothing is left blocked, no thread/fd
/// leaks). Returns a retryable [`ProtocolError`] on deadline-lapse or poll error.
///
/// **`Ok(revents)` does NOT imply the requested `events` are set** — the caller MUST inspect `revents`.
/// `poll` reports `POLLERR`/`POLLHUP`/`POLLNVAL` regardless of `events`, so a readiness can be error-only —
/// never treat a bare `Ok(_)` as "ready for I/O". For the CONNECT/stream-write case use
/// [`connect_poll_succeeded`] (clean `POLLOUT`, error flags veto) — do not hand-roll the flag check. A pipe
/// READ caller (the future (d) quote pipe) must NOT use that predicate: on a pipe `POLLHUP` is a normal EOF
/// that can arrive WITH final data (`POLLIN|POLLHUP`); the (d) pipe predicate is
/// `quote_subprocess::classify_pipe_revents` (EOF-aware — landed in (d-i)).
///
/// The per-call timeout is re-derived from the budget *remaining to the absolute `deadline`* (via
/// [`remaining_or_lapsed`]) and shrinks across `EINTR` retries, so the absolute deadline is the true bound
/// no matter how many times `poll` is interrupted.
pub(crate) fn poll_with_deadline<Fd: AsFd>(
    fd: &Fd,
    events: nix::poll::PollFlags,
    deadline: Instant,
) -> Result<nix::poll::PollFlags, ProtocolError> {
    use nix::errno::Errno;
    use nix::poll::{poll, PollFd, PollTimeout};
    loop {
        let remaining = remaining_or_lapsed(deadline)?;
        // Duration -> PollTimeout (ms). try_from only errors for an absurdly-large duration (> i32::MAX
        // ms ≈ 24 days); clamp to MAX since `remaining` is deadline-bounded anyway. Never NONE (-1 =
        // infinite) — remaining_or_lapsed already guaranteed a positive, >=1ms budget.
        let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(fd.as_fd(), events)];
        match poll(&mut fds, timeout) {
            // Timeout fired with no fd ready: LOOP, don't error — `remaining_or_lapsed` re-checks the
            // ABSOLUTE deadline next iteration. For a normal deadline that returns the lapse error
            // immediately (the armed timeout == the remaining budget); for a deadline beyond ~24 days
            // (where the timeout was clamped to PollTimeout::MAX) the deadline is NOT yet up, so we re-arm.
            // Not a busy loop: each Ok(0) means a full timeout interval elapsed.
            Ok(0) => continue,
            Ok(_) => {
                return fds[0]
                    .revents()
                    .ok_or(ProtocolError::WireProtocol("poll: ready but no revents"));
            }
            // poll() (unlike some wrappers) does NOT retry EINTR — recompute the remaining budget and
            // retry, so a signal can't make us overrun the absolute deadline.
            Err(Errno::EINTR) => continue,
            Err(_) => return Err(ProtocolError::WireProtocol("poll: syscall error")),
        }
    }
}

/// True iff `revents` is a CLEAN connect/stream-write readiness: `POLLOUT` set AND no
/// `POLLERR`/`POLLHUP`/`POLLNVAL` (reported regardless of the requested events — an error-only readiness
/// must not pass). The concrete form of the `Ok(revents)` contract above for the (a') connect bound.
///
/// **Deliberately NOT parameterized over the wanted flag set** (the design doc's §8 (a') AC originally
/// specced exactly this connect-scoped shape): the unconditional `POLLHUP` veto is *connect-specific*
/// correctness — on AF_VSOCK a refused/timed-out connect surfaces `POLLERR|POLLOUT` (no `POLLHUP`; vsock
/// gates `EPOLLHUP` on *local* shutdown, unlike inet) and the veto fires on `POLLERR`. On a **pipe READ**
/// (the future (d) quote-subprocess fd) `POLLHUP` is instead a *normal EOF* that can arrive WITH final data
/// (`POLLIN|POLLHUP`) — a predicate like this one would drop the last quote bytes, so (d) must build its own
/// EOF-aware POLLIN check (now `quote_subprocess::classify_pipe_revents`, landed in (d-i));
/// hardcoding `POLLOUT` here makes that misuse impossible rather than
/// comment-guarded.
pub(crate) fn connect_poll_succeeded(revents: nix::poll::PollFlags) -> bool {
    use nix::poll::PollFlags;
    revents.contains(PollFlags::POLLOUT)
        && !revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::poll::PollFlags;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn past() -> Instant {
        // checked_sub: a bare `Instant::now()` is itself "lapsed" under the MIN_BOUNDARY_BUDGET floor, so
        // the fallback keeps the helper's meaning even if the monotonic clock reads < 1s (freshly-booted
        // microVM running tests as near-init) — where the naked `-` operator would panic.
        Instant::now().checked_sub(Duration::from_secs(1)).unwrap_or_else(Instant::now)
    }
    fn future() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn remaining_or_lapsed_past_future_subms() {
        assert!(remaining_or_lapsed(past()).is_err());
        assert!(remaining_or_lapsed(future()).is_ok());
        // sub-MIN_BOUNDARY_BUDGET (~0.5ms) folds to lapsed.
        let near = Instant::now() + Duration::from_micros(500);
        assert!(remaining_or_lapsed(near).is_err(), "sub-1ms residual must be treated as lapsed");
    }

    #[test]
    fn poll_returns_when_readable() {
        // a<->b connected; writing to b makes a readable. poll(a, POLLIN) returns POLLIN promptly.
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(b"x").unwrap();
        let rv = poll_with_deadline(&a, PollFlags::POLLIN, future()).expect("readable");
        assert!(rv.contains(PollFlags::POLLIN), "expected POLLIN, got {rv:?}");
    }

    #[test]
    fn poll_times_out_when_not_ready() {
        // Nothing written -> a never becomes readable -> a short deadline elapses -> retryable Err,
        // returned at ~the deadline (NOT a hang). 100ms budget; assert it returns well under 2s.
        let (a, _b) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let r = poll_with_deadline(&a, PollFlags::POLLIN, start + Duration::from_millis(100));
        assert!(r.is_err(), "no data -> must time out, not return ready");
        assert!(start.elapsed() < Duration::from_secs(2), "must return on its own deadline, not block");
    }

    #[test]
    fn poll_already_lapsed_is_immediate_err() {
        let (a, _b) = UnixStream::pair().unwrap();
        // A past deadline short-circuits in remaining_or_lapsed BEFORE poll is ever called, so the fd's
        // readiness/HUP state is irrelevant here — this only proves the pre-poll deadline check.
        assert!(poll_with_deadline(&a, PollFlags::POLLIN, past()).is_err());
    }

    #[test]
    fn poll_returns_pollout_when_writable() {
        // The (a') primary path: a fresh connected socket is immediately writable -> POLLOUT.
        let (a, _b) = UnixStream::pair().unwrap();
        let rv = poll_with_deadline(&a, PollFlags::POLLOUT, future()).expect("writable");
        assert!(rv.contains(PollFlags::POLLOUT), "expected POLLOUT, got {rv:?}");
    }

    #[test]
    fn poll_returns_ok_not_err_on_closed_peer() {
        // The pinned contract is Ok-PASS-THROUGH: a closed/error-readiness comes back as Ok(revents), NOT
        // converted to a poll-level Err — so the CALLER (not the primitive) inspects and decides.
        // poll_with_deadline returns `revents` verbatim (it never filters flags), so it cannot "drop" a
        // flag. Dropping the write end makes `a` poll-ready; the exact flag(s) vary by kernel/socket-type
        // (POLLHUP and/or POLLIN-for-EOF), so we assert Ok + a closed/readable signal, not one specific flag.
        let (a, b) = UnixStream::pair().unwrap();
        drop(b);
        let rv = poll_with_deadline(&a, PollFlags::POLLIN, future())
            .expect("closed peer must be Ok readiness, not an Err");
        assert!(
            rv.intersects(PollFlags::POLLHUP | PollFlags::POLLIN),
            "expected a closed/readable signal (POLLHUP and/or POLLIN), got {rv:?}"
        );
    }

    #[test]
    fn connect_poll_succeeded_requires_clean_pollout() {
        use PollFlags as P;
        // Primary use: a freshly-writable connect fd -> POLLOUT clean -> success.
        assert!(connect_poll_succeeded(P::POLLOUT), "bare POLLOUT must be success");
        // POLLOUT present but ALSO an error condition -> false. On AF_VSOCK the real refused/timed-out
        // connect shape is POLLERR|POLLOUT (kernel sets sk_err then wakes the poller; no POLLHUP — vsock
        // gates EPOLLHUP on LOCAL shutdown); POLLHUP/POLLNVAL are pinned too so the veto set can't shrink.
        assert!(!connect_poll_succeeded(P::POLLOUT | P::POLLERR), "POLLERR must veto (vsock refusal shape)");
        assert!(!connect_poll_succeeded(P::POLLOUT | P::POLLHUP), "POLLHUP must veto");
        assert!(!connect_poll_succeeded(P::POLLOUT | P::POLLNVAL), "POLLNVAL must veto");
        // POLLOUT absent -> false even on an otherwise-clean revents.
        assert!(!connect_poll_succeeded(P::POLLIN), "readable-without-writable is not connect success");
        assert!(!connect_poll_succeeded(P::empty()), "empty revents must not be success");
        // Why there is no `want` parameter: a pipe's EOF routinely arrives as POLLIN|POLLHUP (final data +
        // writer closed). A POLLHUP-vetoing predicate applied to a pipe read would reject that completed
        // read — the (d) quote pipe has its own EOF-aware check (quote_subprocess::
        // classify_pipe_revents), and the hardcoded-POLLOUT signature
        // makes reaching for this one a compile error rather than a prose warning.
        assert!(
            !connect_poll_succeeded(P::POLLIN | P::POLLHUP),
            "pipe EOF-with-data shape must never read as connect success"
        );
    }
}
