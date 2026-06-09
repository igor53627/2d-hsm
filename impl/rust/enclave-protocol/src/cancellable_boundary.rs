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
/// (a) `set_read_timeout(Some(Duration::ZERO))` is an *error* on vsock 0.5, not "no timeout", and a sub-µs
/// `Duration` could in theory round to a 0 = infinite `timeval`; (b) a sub-millisecond residual cannot
/// complete a real connect/round-trip, so failing fast as retryable is correct, not a spurious failure.
pub(crate) const MIN_SOCKET_BUDGET: Duration = Duration::from_millis(1);

/// Remaining budget until `deadline`, or `Err` (retryable) if already lapsed / below [`MIN_SOCKET_BUDGET`].
/// Single `now` sample; `checked_duration_since` is `None` when `deadline < now`. Anything below the floor
/// folds to the retryable lapse error, so no caller ever arms a zero/sub-ms socket timeout.
pub(crate) fn remaining_or_lapsed(deadline: Instant) -> Result<Duration, ProtocolError> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if d >= MIN_SOCKET_BUDGET => Ok(d),
        _ => Err(ProtocolError::WireProtocol("anchor relay: deadline lapsed")),
    }
}

/// Wait until `fd` is ready for `events` (e.g. `POLLIN`/`POLLOUT`) or the `deadline` elapses — a true
/// CANCELLABLE bound (the `poll` simply returns at the deadline; nothing is left blocked, no thread/fd
/// leaks). Returns the reported `revents` on readiness (the caller inspects — `POLLERR`/`POLLHUP` are
/// reported regardless of `events`, e.g. a failed connect sets `POLLERR` so the caller then reads
/// `SO_ERROR`). Returns a retryable [`ProtocolError`] on deadline-lapse or poll error.
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
            Ok(0) => return Err(ProtocolError::WireProtocol("poll: deadline elapsed before fd ready")),
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
        // sub-MIN_SOCKET_BUDGET (~0.5ms) folds to lapsed.
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
        // _b kept alive so a isn't HUP; past deadline -> remaining_or_lapsed errors before any poll.
        assert!(poll_with_deadline(&a, PollFlags::POLLIN, past()).is_err());
    }
}
