//! Shared cancellable-boundary primitives for the agent boot relay (TASK-7.7 5b-2b-ii, PR-A).
//!
//! Both hard bounds the live anti-rollback serve needs reduce to ONE kernel problem: *wait on an fd until
//! ready-or-deadline, under `#![forbid(unsafe_code)]`, with no thread/fd leak.*
//! - **(a')** the cancellable CONNECT bound — `poll(POLLOUT)` on a non-blocking vsock connect fd.
//! - **(d)** the cancellable QUOTE bound — `poll(POLLIN)` on a killable-subprocess pipe-read fd.
//!
//! [`poll_with_deadline`] is that shared core. It is backed by `nix::poll` — whose `poll` wrapper is SAFE
//! (the `unsafe` `libc::poll` lives inside `nix`), so this stays within the crate's `forbid(unsafe_code)`
//! boundary — and `nix` is a direct, target-gated (`cfg(target_os = "linux")`), optional dep folded into
//! `vsock-transport` (vsock pulls `nix` only for ioctl/socket, NOT `poll`). Linux + vsock-transport gated,
//! mirroring the channel it serves.
//!
//! `poll_with_deadline` is dead-code in the non-test lib build until its consumers land (5b-2b-ii (a') wires
//! POLLOUT on the connect fd; (d) wires POLLIN on the subprocess pipe) — allow it meanwhile (the tests
//! exercise it now).
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

/// Remaining budget until `deadline`, or `Err` (retryable) if already lapsed / below [`MIN_BOUNDARY_BUDGET`].
/// Single `now` sample; `checked_duration_since` is `None` when `deadline < now`. Anything below the floor
/// folds to the retryable lapse error, so no caller ever arms a zero/sub-ms socket/poll timeout. The error
/// string is subsystem-neutral because this helper is shared by the boot-relay channel AND the generic
/// `poll_with_deadline` primitive (e.g. the 5b-2b-ii(d) quote-subprocess pipe).
pub(crate) fn remaining_or_lapsed(deadline: Instant) -> Result<Duration, ProtocolError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if d >= MIN_BOUNDARY_BUDGET => Ok(d),
        _ => Err(ProtocolError::WireProtocol("deadline lapsed")),
    }
}

/// Wait until `fd` is ready for `events` (e.g. `POLLIN`/`POLLOUT`) or the `deadline` elapses — a true
/// CANCELLABLE bound (the `poll` simply returns at the deadline; nothing is left blocked, no thread/fd
/// leaks). Returns a retryable [`ProtocolError`] on deadline-lapse or poll error.
///
/// **`Ok(revents)` does NOT imply the requested `events` are set** — the caller MUST inspect `revents`.
/// `poll` reports `POLLERR`/`POLLHUP`/`POLLNVAL` regardless of `events`, so a readiness can be
/// error-only: e.g. a failed non-blocking connect returns `Ok(POLLERR)` WITHOUT `POLLOUT` (the caller then
/// reads `SO_ERROR`), and a closed peer returns `Ok(POLLHUP)` (possibly with `POLLIN`). A caller MUST do
/// `if revents.contains(POLLOUT) && !revents.intersects(POLLERR|POLLHUP|POLLNVAL)` (or equivalent) — never
/// treat a bare `Ok(_)` as "ready for I/O".
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

/// True iff `revents` is a CLEAN readiness for `want` (the requested event set AND no hangup/error
/// condition). The reusable form of the `Ok(revents)` contract above: `revents` containing `want` is NOT
/// enough — `POLLERR`/`POLLHUP`/`POLLNVAL` (reported regardless of `want`) mean the fd is broken/closed.
///
/// **Scope: CONNECT / stream-write readiness only** (the (a') `want = POLLOUT` case — a failed non-blocking
/// connect surfaces `POLLOUT|POLLERR|POLLHUP`, so vetoing the hangup/error flags is exactly right). It is the
/// only live caller today.
///
/// **Do NOT reuse this verbatim for a pipe READ (e.g. the future (d) quote-subprocess `POLLIN`).** On a pipe,
/// `POLLHUP` is a *normal EOF* (the writer closed) and can arrive **together with final readable data**
/// (`POLLIN|POLLHUP`); vetoing `POLLHUP` here would make (d) treat a completed quote read as a failure and
/// drop the last bytes. (d) must use its own EOF-aware read-readiness check — `poll_with_deadline` stays
/// shared (it returns raw `revents`; the caller decides), but this success predicate does not.
pub(crate) fn poll_ready_for(revents: nix::poll::PollFlags, want: nix::poll::PollFlags) -> bool {
    use nix::poll::PollFlags;
    revents.contains(want)
        && !revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::poll::PollFlags;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn past() -> Instant {
        Instant::now() - Duration::from_secs(1)
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
    fn poll_ready_for_requires_want_and_rejects_error_flags() {
        use PollFlags as P;
        // Primary use: a freshly-writable connect fd -> POLLOUT clean -> ready.
        assert!(poll_ready_for(P::POLLOUT, P::POLLOUT), "bare POLLOUT must be ready");
        // want present but ALSO carries an error condition -> false (the (a') connect-failure case:
        // a failed non-blocking connect can surface POLLOUT|POLLERR; treating it as ready would skip
        // the SO_ERROR check). Cover each error flag.
        assert!(!poll_ready_for(P::POLLOUT | P::POLLERR, P::POLLOUT), "POLLERR must veto readiness");
        assert!(!poll_ready_for(P::POLLOUT | P::POLLHUP, P::POLLOUT), "POLLHUP must veto readiness");
        assert!(!poll_ready_for(P::POLLOUT | P::POLLNVAL, P::POLLOUT), "POLLNVAL must veto readiness");
        // want absent -> false even on an otherwise-clean revents (e.g. POLLIN when we asked POLLOUT).
        assert!(!poll_ready_for(P::POLLIN, P::POLLOUT), "missing want must not be ready");
        assert!(!poll_ready_for(P::empty(), P::POLLOUT), "empty revents must not be ready");
    }

    #[test]
    fn poll_ready_for_is_wrong_for_pipe_reads_documents_why_d_must_not_reuse() {
        use PollFlags as P;
        // GUARD (not an endorsement): this asserts the EXACT failure that makes `poll_ready_for`
        // unsuitable for the future (d) quote-subprocess pipe READ. On a pipe, `POLLHUP` is a NORMAL
        // EOF (the writer closed) and routinely arrives WITH final readable data as `POLLIN|POLLHUP`.
        // `poll_ready_for` vetoes POLLHUP unconditionally, so it would reject that completed read and
        // (d) would drop the last quote bytes. Hence (d) must use its own EOF-aware predicate — this
        // helper is connect/stream-write readiness ONLY. The bare-POLLIN case is asserted too, purely to
        // show the helper is generic over `want`; it is NOT a sanction to reuse it for pipe reads.
        assert!(poll_ready_for(P::POLLIN, P::POLLIN), "generic over want: bare POLLIN matches want=POLLIN");
        assert!(
            !poll_ready_for(P::POLLIN | P::POLLHUP, P::POLLIN),
            "POLLIN|POLLHUP (a pipe's EOF-with-data) is REJECTED -> why (d) pipe reads must not reuse this"
        );
    }
}
