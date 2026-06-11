//! (4c) in-guest quote smoke bin (TASK-7.7 5b-2b-ii (d-ii)/4c) — lab/debug images only
//! (`required-features` includes the release-banned `lab-quote-smoke`; see Cargo.toml + lib.rs).
//!
//! This main SHAPE is the future 5b-2c agent bin's shape (5b-2c swaps the second statement for its
//! `pub` boot wrapper): dispatch-first + PROTOCOL-ONLY stdout are CI-enforced for THIS bin by
//! `tests/twod_hsm_quote_smoke_bin.rs` (the 5b-2c acceptance item is NOT discharged — it must
//! re-target `CARGO_BIN_EXE_<agent-bin>`).

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("twod-hsm-quote-smoke: requires Linux (vsock + configfs-tsm)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    // §8 dispatch-first contract: FIRST statement, unconditional. A spawned quote child re-enters
    // this main and never returns from this line. NOTHING may print before it.
    enclave_protocol::agent_quote_child_dispatch();
    enclave_protocol::run_quote_smoke()
}
