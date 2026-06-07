//! Relying-party CLI for SEV-SNP attestation verification (policy §2).
//!
//! Verifies a `GET_MEASUREMENT` attestation end to end: structural prevalidate + the
//! VCEK→ASK→ARK cert chain to the pinned AMD root + the report's ECDSA-P384 signature.
//!
//!   snp-attest-verify \
//!     --report report.bin --vcek vcek.der --cert-chain ask_ark.pem \
//!     --measurement 3e39e33a... [--pq-pubkey pq.bin] [--pinned-ark-chain amd.pem]
//!
//! The VCEK + ASK/ARK chain come from the AMD KDS (auxblob is empty on current providers); pick the
//! product to match the CPU (lscpu family 25 = Genoa / 26 = Turin), then fetch:
//!   curl 'https://kdsintf.amd.com/vcek/v1/<Genoa|Turin>/<chip_id_hex>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..' -o vcek.der
//!   curl 'https://kdsintf.amd.com/vcek/v1/<Genoa|Turin>/cert_chain' -o ask_ark.pem

use clap::Parser;
use snp_attest_verify::{
    parse_cert_chain_pem, parse_cert_der, pinned_ark_spki, verify_attestation,
};
use std::path::PathBuf;
use std::process::ExitCode;

// Committed AMD product roots (the out-of-band pin). Pick the one matching the CPU family
// (`lscpu`: 25/0x19 = Genoa, 26/0x1A = Turin) via --product, or pass your own with --pinned-ark-chain.
const EMBEDDED_AMD_GENOA_CHAIN: &[u8] = include_bytes!("../testvectors/amd_genoa_cert_chain.pem");
const EMBEDDED_AMD_TURIN_CHAIN: &[u8] = include_bytes!("../testvectors/amd_turin_cert_chain.pem");

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
    /// AMD product whose bundled ARK/ASK to pin: `genoa` (CPU family 25) or `turin` (family 26).
    /// Required unless --pinned-ark-chain is given (no silent default — the pin must match the chip).
    #[arg(long, value_parser = ["genoa", "turin"])]
    product: Option<String>,
    /// Out-of-band pinned AMD root chain (PEM containing the trusted ARK) — use INSTEAD of --product
    /// (mutually exclusive) to pin your own copy or a product not bundled here.
    #[arg(long, conflicts_with = "product")]
    pinned_ark_chain: Option<PathBuf>,
    /// ML-DSA-65 producer public key to bind: requires
    /// report_data == SHA3-512("2d-hsm-snp-report-data-v1" || pq_pubkey). REQUIRED unless
    /// --allow-unbound — without it the attestation is not tied to a key (see --allow-unbound).
    #[arg(long)]
    pq_pubkey: Option<PathBuf>,
    /// Verify WITHOUT binding the report to a producer key. DANGEROUS: the launch measurement is
    /// OVMF-level and shared across guests, so an unbound report is replayable from a different
    /// enclave on the same firmware. Mutually exclusive with --pq-pubkey.
    #[arg(long)]
    allow_unbound: bool,
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
    let pinned_pem = match (&cli.pinned_ark_chain, cli.product.as_deref()) {
        (Some(_), Some(_)) => {
            return Err("specify only one of --pinned-ark-chain / --product".into())
        }
        (Some(p), None) => std::fs::read(p).map_err(|e| format!("read --pinned-ark-chain: {e}"))?,
        (None, Some("genoa")) => EMBEDDED_AMD_GENOA_CHAIN.to_vec(),
        (None, Some("turin")) => EMBEDDED_AMD_TURIN_CHAIN.to_vec(),
        (None, Some(other)) => return Err(format!("unknown --product '{other}' (genoa|turin)")),
        (None, None) => {
            return Err(
                "pin the AMD root: --product <genoa|turin> (match the CPU — lscpu family \
                        25=genoa, 26=turin) or --pinned-ark-chain <pem>"
                    .into(),
            )
        }
    };
    let pq_pubkey = match (&cli.pq_pubkey, cli.allow_unbound) {
        (Some(_), true) => {
            return Err("--pq-pubkey and --allow-unbound are mutually exclusive".into())
        }
        (Some(p), false) => Some(std::fs::read(p).map_err(|e| format!("read --pq-pubkey: {e}"))?),
        (None, true) => {
            eprintln!(
                "snp-attest-verify: WARNING: --allow-unbound: the report is NOT bound to a pq_pubkey. \
                 The launch measurement is OVMF-level and shared across guests, so this attestation \
                 is replayable from a different enclave on the same firmware."
            );
            None
        }
        (None, false) => {
            return Err(
                "--pq-pubkey is required to bind the report to a producer key (or pass \
                        --allow-unbound to verify without key binding — see policy §2 step 3)"
                    .into(),
            )
        }
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
