//! TASK-15 host-side combined FAUCET write-path smoke client bin — **release-banned feature combo**
//! (`lab-agent-smoke` + `agent-keygen-exec-preview` + `agent-configure-treasury-preview` +
//! `agent-sign-faucet-preview`). Dials the guest agent serve port over AF_VSOCK from the aya host and
//! drives the full fund-custody flow that only became reachable once SIGN_FAUCET_DISPENSE (15-3b) AND
//! CONFIGURE_TREASURY (15-4) both landed: GENERATE_KEYS mints the treasury key at runtime →
//! CONFIGURE_TREASURY set_limits + refill_budget configure the caps + budget at runtime (no throwaway
//! sealed fixture — the production flow) → SIGN_FAUCET_DISPENSE pays a known transfer recipient and the
//! resealed blob shows the dual-counter debit → a fail-closed stranger-recipient gate (→ 0x42). All
//! inputs and expectations derive in-crate from the minted smoke fixture (the KNOWN admin seed +
//! anchor seed) — zero env plumbing for the protocol itself.
//!
//! Env: `TWOD_HSM_SMOKE_GUEST_CID` (default 42 — the run-guest-vm.sh `vhost-vsock` cid),
//! `TWOD_HSM_SMOKE_AGENT_PORT` (default 5002 — the agent unit's serve port; SHARED with the keygen
//! smoke, so the two are mutually exclusive on one host). Markers go to stderr
//! (`twod-hsm-agent-faucet-smoke: PHASE … PASS|FAIL`; terminal `RESULT PASS phases=5`).
//!
//! Non-linux: exits 2 (AF_VSOCK is Linux-only; mirrors `twod_hsm_agent_keygen_smoke_client.rs`).

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("twod-hsm-agent-faucet-smoke-client: requires Linux (AF_VSOCK)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE, // RESULT FAIL already emitted by the core
        Err(e) => {
            eprintln!("twod-hsm-agent-faucet-smoke-client: {e}");
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
    // Each phase opens a fresh connection; the committing phases (mint / set_limits / refill / dispense)
    // hold the keystore lock across the host-relayed anchor-commit round-trip, so allow a generous read
    // budget for the commit leg (matches the keygen smoke client).
    let connect = move || -> std::io::Result<vsock::VsockStream> {
        let stream = vsock::VsockStream::connect(&vsock::VsockAddr::new(cid, port))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        Ok(stream)
    };
    Ok(enclave_protocol::run_agent_faucet_smoke_client(
        connect,
        &mut std::io::stderr(),
    ))
}
