//! Validation / operator helper: fetch the live SEV-SNP launch measurement via configfs-tsm and
//! print it. Run **inside an SNP guest** with the `sev-guest` TSM provider loaded
//! (`/sys/kernel/config/tsm/report` present). Exercises the same `snp_report` path the production
//! enclave uses for GET_MEASUREMENT (TASK-5 Phase 3 / AC#4).
//!
//! Usage: `dump_snp_measurement [pubkey-bytes-for-report_data-binding]`

fn main() {
    let pq_pubkey = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "dump-snp-measurement".to_string());

    match enclave_protocol::snp_report::fetch_measurement_and_report(pq_pubkey.as_bytes()) {
        Ok((measurement, report)) => {
            println!("measurement={}", hex::encode(measurement));
            println!("report_len={}", report.len());
        }
        Err(e) => {
            eprintln!("snp report unavailable: {e}");
            std::process::exit(1);
        }
    }
}
