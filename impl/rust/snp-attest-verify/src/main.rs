//! Relying-party CLI for SEV-SNP attestation verification (policy §2).
//!
//! Verifies a `GET_MEASUREMENT` attestation end to end: structural prevalidate + the
//! VCEK→ASK→ARK cert chain to the pinned AMD root + the report's ECDSA-P384 signature.
//!
//!   snp-attest-verify \
//!     --report report.bin --vcek vcek.der --cert-chain ask_ark.pem \
//!     --measurement 3e39e33a... [--pq-pubkey pq.bin] [--pinned-ark-chain amd.pem]
//!
//! The VCEK + ASK/ARK chain come from the AMD KDS (auxblob is empty on current providers); fetch:
//!   curl 'https://kdsintf.amd.com/vcek/v1/Genoa/<chip_id_hex>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..' -o vcek.der
//!   curl 'https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain' -o ask_ark.pem

use clap::Parser;
use snp_attest_verify::{
    parse_cert_chain_pem, parse_cert_der, pinned_ark_spki, verify_attestation,
};
use std::path::PathBuf;
use std::process::ExitCode;

/// The committed AMD Genoa ARK/ASK — the default out-of-band pin (override with --pinned-ark-chain).
const EMBEDDED_AMD_GENOA_CHAIN: &[u8] = include_bytes!("../testvectors/amd_genoa_cert_chain.pem");

#[derive(Parser)]
#[command(
    name = "snp-attest-verify",
    about = "Relying-party SEV-SNP attestation verifier (policy §2)"
)]
struct Cli {
    /// Raw SEV-SNP ATTESTATION_REPORT (1184 bytes).
    #[arg(long)]
    report: PathBuf,
    /// VCEK certificate (DER), from the AMD KDS or the report's auxblob.
    #[arg(long)]
    vcek: PathBuf,
    /// VCEK→ASK→ARK chain (PEM; ASK + ARK), from the AMD KDS `cert_chain`.
    #[arg(long)]
    cert_chain: PathBuf,
    /// Out-of-band pinned AMD root chain (PEM containing the trusted ARK). Defaults to the embedded
    /// AMD Genoa ARK/ASK — override for a different product or to pin your own copy.
    #[arg(long)]
    pinned_ark_chain: Option<PathBuf>,
    /// Optional ML-DSA-65 producer public key to bind: requires
    /// report_data == SHA3-512("2d-hsm-snp-report-data-v1" || pq_pubkey).
    #[arg(long)]
    pq_pubkey: Option<PathBuf>,
    /// Allowed 48-byte launch measurement(s) as hex (repeatable). At least one is required.
    #[arg(long = "measurement", value_name = "HEX", required = true)]
    measurements: Vec<String>,
}

fn parse_measurement(hex_str: &str) -> Result<[u8; 48], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("measurement hex: {e}"))?;
    let arr: [u8; 48] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("measurement must be 48 bytes (got {})", bytes.len()))?;
    Ok(arr)
}

fn run(cli: &Cli) -> Result<[u8; 48], String> {
    let report = std::fs::read(&cli.report).map_err(|e| format!("read --report: {e}"))?;
    let vcek_der = std::fs::read(&cli.vcek).map_err(|e| format!("read --vcek: {e}"))?;
    let chain_pem =
        std::fs::read(&cli.cert_chain).map_err(|e| format!("read --cert-chain: {e}"))?;
    let pinned_pem = match &cli.pinned_ark_chain {
        Some(p) => std::fs::read(p).map_err(|e| format!("read --pinned-ark-chain: {e}"))?,
        None => EMBEDDED_AMD_GENOA_CHAIN.to_vec(),
    };
    let pq_pubkey = match &cli.pq_pubkey {
        Some(p) => Some(std::fs::read(p).map_err(|e| format!("read --pq-pubkey: {e}"))?),
        None => None,
    };
    let mut allow = Vec::with_capacity(cli.measurements.len());
    for m in &cli.measurements {
        allow.push(parse_measurement(m)?);
    }

    let vcek = parse_cert_der(&vcek_der).map_err(|e| e.to_string())?;
    let chain = parse_cert_chain_pem(&chain_pem).map_err(|e| e.to_string())?;
    let pinned = pinned_ark_spki(&pinned_pem).map_err(|e| format!("pinned ARK: {e}"))?;

    verify_attestation(
        &report,
        &vcek,
        &chain,
        &pinned,
        pq_pubkey.as_deref(),
        &allow,
    )
    .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(measurement) => {
            println!("VERIFIED measurement={}", hex::encode(measurement));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("snp-attest-verify: REJECTED: {e}");
            ExitCode::FAILURE
        }
    }
}
