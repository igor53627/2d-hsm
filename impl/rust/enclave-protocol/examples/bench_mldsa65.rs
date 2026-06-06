//! ML-DSA-65 hot-path performance baseline (TASK-1 AC#7).
//!
//! Run on the **SNP host CPU** (AMD EPYC — the platform the enclave runs on), e.g. aya:
//!   cargo run --release --example bench_mldsa65 --features ml-dsa-65,pq-seal-provisioning [iters]
//!
//! Times sign + verify of a 32-byte ticket/block digest (the hot path: every ~2s block + every
//! ticket) and reports per-op latency, throughput, and the fraction of the ~2s block budget.
//! This is the CPU baseline — ML-DSA signing is not a GPU workload (see TASK-1 AC#7 / TASK-5
//! verifier-policy: the GPU "B200" path is the separate MAYO-iO slow path in theory-378).

use std::time::Instant;

fn main() {
    let iters: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);

    let signer = enclave_protocol::MlDsa65Signer::generate_keypair();
    let digest = [0x5au8; 32];

    // Warm up (page-in, branch predictor, etc.) before timing.
    let mut sig = signer.sign_ticket_hash(&digest).expect("warmup sign");
    for _ in 0..64 {
        sig = signer.sign_ticket_hash(&digest).expect("sign");
        signer.verify_ticket_hash(&digest, &sig).expect("verify");
    }

    // Sign throughput (hedged ML-DSA-65 — each signature is fresh).
    let t = Instant::now();
    for _ in 0..iters {
        sig = signer.sign_ticket_hash(&digest).expect("sign");
    }
    let sign = t.elapsed();

    // Verify throughput (verify the last signature repeatedly).
    let t = Instant::now();
    for _ in 0..iters {
        signer.verify_ticket_hash(&digest, &sig).expect("verify");
    }
    let verify = t.elapsed();

    let sign_us = sign.as_secs_f64() * 1e6 / f64::from(iters);
    let verify_us = verify.as_secs_f64() * 1e6 / f64::from(iters);
    let host = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|m| m.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".to_string());

    println!("ML-DSA-65 baseline on: {host}");
    println!("  iterations: {iters}   signature: {} bytes", sig.len());
    println!(
        "  sign:   {sign_us:8.1} us/op   ({:.0} ops/s)",
        1e6 / sign_us
    );
    println!(
        "  verify: {verify_us:8.1} us/op   ({:.0} ops/s)",
        1e6 / verify_us
    );
    println!(
        "  sign+verify per block: {:.1} us  =  {:.4}% of the ~2s block budget",
        sign_us + verify_us,
        (sign_us + verify_us) / 2e6 * 100.0
    );
}
