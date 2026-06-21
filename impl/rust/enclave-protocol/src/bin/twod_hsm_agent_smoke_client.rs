//! 5b-2c-iii host-side 0x40 smoke client bin (TASK-7.7) — **release-banned feature**. Dials the
//! guest agent serve port over AF_VSOCK from the aya host and drives the 5 checklisted phases
//! (public-identity / identity-unknown-keyref / non-agent-close / idle-expiry / post-expiry-
//! liveness); all expectations derive in-crate from the minted smoke fixture — zero env plumbing.
//!
//! Env: `TWOD_HSM_SMOKE_GUEST_CID` (default 42 — the run-guest-vm.sh `vhost-vsock` cid),
//! `TWOD_HSM_SMOKE_AGENT_PORT` (default 5002 — the agent unit's serve port; producer owns 5000,
//! relay 5001), `TWOD_HSM_AGENT_SMOKE_SKIP_IDLE` (`1` = drop the 300 s wall-clock phase; the
//! terminal token becomes `RESULT PASS-DEV phases=4`, structurally unmatchable by the official
//! `RESULT PASS phases=5` grep). Markers go to stderr (the quote-smoke precedent).
//!
//! Non-linux: exits 2 (AF_VSOCK is Linux-only; mirrors `twod_hsm_quote_smoke.rs`).

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("twod-hsm-agent-smoke-client: requires Linux (AF_VSOCK)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE, // RESULT FAIL already emitted by the core
        Err(e) => {
            eprintln!("twod-hsm-agent-smoke-client: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<bool, String> {
    // NotPresent → default; NotUnicode / parse failure → fail closed naming the var.
    let parse_u32 = |var: &str, default: u32| -> Result<u32, String> {
        match std::env::var(var) {
            Ok(s) => s
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("{var} must be a u32")),
            Err(std::env::VarError::NotPresent) => Ok(default),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{var} is not valid UTF-8")),
        }
    };
    let cid = parse_u32("TWOD_HSM_SMOKE_GUEST_CID", 42)?;
    let port = parse_u32("TWOD_HSM_SMOKE_AGENT_PORT", 5002)?;
    let skip_idle = match std::env::var("TWOD_HSM_AGENT_SMOKE_SKIP_IDLE") {
        Ok(s) if s == "1" => true,
        Ok(s) if s == "0" || s.is_empty() => false,
        Ok(s) => {
            return Err(format!(
                "TWOD_HSM_AGENT_SMOKE_SKIP_IDLE must be 0/1, got {s:?}"
            ))
        }
        Err(std::env::VarError::NotPresent) => false,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("TWOD_HSM_AGENT_SMOKE_SKIP_IDLE is not valid UTF-8".to_string())
        }
    };
    let connect = move || -> std::io::Result<vsock::VsockStream> {
        let stream = vsock::VsockStream::connect(&vsock::VsockAddr::new(cid, port))?;
        // The idle phase measures wall-clock to the server's close: the read timeout MUST clear
        // the acceptance-window ceiling or a socket timeout masquerades as the close (pinned by
        // idle_expiry_window_bounds_are_sane). Writes are immediate; 30 s is generous.
        stream.set_read_timeout(Some(enclave_protocol::SMOKE_CLIENT_IDLE_READ_TIMEOUT))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        Ok(stream)
    };
    Ok(enclave_protocol::run_agent_smoke_client(
        connect,
        skip_idle,
        &mut std::io::stderr(),
    ))
}
