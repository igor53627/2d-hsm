//! Offline provisioning tool for PQ seal v1 blobs (see vsock spec §2.1).
//!
//! Run on a trusted workstation — not inside the untrusted host that launches the enclave.
//! The provisioning root must match what the enclave receives via `set_pq_seal_v1_provisioning_root`.

use clap::{Parser, Subcommand};
use enclave_protocol::{
    pq_seal_v1_expected_blob_len, pq_seal_v1_measurement_digest, seal_mldsa65_keypair_v1_with_root,
    verify_sealed_blob_v1_with_root, MlDsa65Signer, ML_DSA65_PUBKEY_LEN, ML_DSA65_SECRETKEY_LEN,
};
use zeroize::Zeroizing;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use thiserror::Error;

#[derive(Debug, Error)]
enum CliError {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] enclave_protocol::ProtocolError),
}

fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Seal(args) => cmd_seal(args),
        Command::Verify(args) => cmd_verify(args),
        Command::MeasDigest(args) => cmd_meas_digest(args),
        Command::GenerateKeypair(args) => cmd_generate_keypair(args),
    }
}

#[derive(Parser)]
#[command(
    name = "pq-seal-v1",
    about = "Offline seal v1 provisioning for 2d-hsm ML-DSA-65 producer keys"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a v1 sealed blob from SK/PK and enclave measurement.
    Seal(SealArgs),
    /// Verify a sealed blob decrypts (does not print key material).
    Verify(VerifyArgs),
    /// Print SHA3-256 measurement digest for an enclave measurement file.
    MeasDigest(MeasDigestArgs),
    /// Write fresh ML-DSA-65 keypair files (provisioning ceremony helper).
    GenerateKeypair(GenerateKeypairArgs),
}

#[derive(Parser)]
struct SealArgs {
    /// Raw enclave launch measurement (e.g. PCR/policy hash bytes).
    #[arg(long, group = "measurement")]
    measurement_file: Option<PathBuf>,
    #[arg(long, value_name = "HEX", group = "measurement")]
    measurement_hex: Option<String>,

    #[arg(long)]
    secret_key_file: PathBuf,
    #[arg(long)]
    public_key_file: PathBuf,

    /// 32-byte provisioning root file (must match enclave `set_pq_seal_v1_provisioning_root`).
    #[arg(long)]
    provisioning_root_file: PathBuf,

    #[arg(long, short = 'o')]
    output: PathBuf,
}

#[derive(Parser)]
struct VerifyArgs {
    #[arg(long)]
    sealed_blob_file: PathBuf,
    #[arg(long, group = "measurement")]
    measurement_file: Option<PathBuf>,
    #[arg(long, value_name = "HEX", group = "measurement")]
    measurement_hex: Option<String>,
    #[arg(long)]
    provisioning_root_file: PathBuf,
}

#[derive(Parser)]
struct MeasDigestArgs {
    #[arg(long, group = "measurement")]
    measurement_file: Option<PathBuf>,
    #[arg(long, value_name = "HEX", group = "measurement")]
    measurement_hex: Option<String>,
}

#[derive(Parser)]
struct GenerateKeypairArgs {
    #[arg(long)]
    secret_key_out: PathBuf,
    #[arg(long)]
    public_key_out: PathBuf,
}

fn read_measurement(args_file: &Option<PathBuf>, args_hex: &Option<String>) -> Result<Vec<u8>, CliError> {
    if let Some(path) = args_file {
        let bytes = fs::read(path)?;
        if bytes.is_empty() {
            return Err(CliError::Msg("measurement must be non-empty".into()));
        }
        return Ok(bytes);
    }
    if let Some(hex) = args_hex {
        let bytes = hex::decode(hex.trim()).map_err(|e| CliError::Msg(format!("measurement hex: {e}")))?;
        if bytes.is_empty() {
            return Err(CliError::Msg("measurement must be non-empty".into()));
        }
        return Ok(bytes);
    }
    Err(CliError::Msg(
        "provide --measurement-file or --measurement-hex".into(),
    ))
}

fn read_root_32(path: &PathBuf) -> Result<[u8; 32], CliError> {
    let bytes = fs::read(path)?;
    bytes
        .try_into()
        .map_err(|_| CliError::Msg("provisioning root must be exactly 32 bytes".into()))
}

/// Write high-value secret material with restrictive permissions (Unix 0o600).
fn write_secret_file(path: &PathBuf, data: &[u8]) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
        Ok(())
    }
}

fn cmd_seal(args: SealArgs) -> Result<(), CliError> {
    let measurement = read_measurement(&args.measurement_file, &args.measurement_hex)?;
    let root = read_root_32(&args.provisioning_root_file)?;
    let sk = Zeroizing::new(fs::read(&args.secret_key_file)?);
    let pk = Zeroizing::new(fs::read(&args.public_key_file)?);
    if sk.len() != ML_DSA65_SECRETKEY_LEN {
        return Err(CliError::Msg(format!(
            "secret key: expected {} bytes, got {}",
            ML_DSA65_SECRETKEY_LEN,
            sk.len()
        )));
    }
    if pk.len() != ML_DSA65_PUBKEY_LEN {
        return Err(CliError::Msg(format!(
            "public key: expected {} bytes, got {}",
            ML_DSA65_PUBKEY_LEN,
            pk.len()
        )));
    }
    let blob = seal_mldsa65_keypair_v1_with_root(sk.as_ref(), pk.as_ref(), &measurement, &root)?;
    if blob.len() != pq_seal_v1_expected_blob_len() {
        return Err(CliError::Msg("internal error: unexpected sealed blob length".into()));
    }
    write_secret_file(&args.output, &blob)?;
    eprintln!(
        "wrote {} bytes to {}",
        blob.len(),
        args.output.display()
    );
    eprintln!(
        "meas_digest={}",
        hex::encode(pq_seal_v1_measurement_digest(&measurement))
    );
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), CliError> {
    let measurement = read_measurement(&args.measurement_file, &args.measurement_hex)?;
    let root = read_root_32(&args.provisioning_root_file)?;
    let blob = fs::read(&args.sealed_blob_file)?;
    verify_sealed_blob_v1_with_root(&blob, &measurement, &root)?;
    eprintln!("ok: sealed blob verifies for measurement and provisioning root");
    Ok(())
}

fn cmd_meas_digest(args: MeasDigestArgs) -> Result<(), CliError> {
    let measurement = read_measurement(&args.measurement_file, &args.measurement_hex)?;
    let digest = pq_seal_v1_measurement_digest(&measurement);
    println!("{}", hex::encode(digest));
    Ok(())
}

fn cmd_generate_keypair(args: GenerateKeypairArgs) -> Result<(), CliError> {
    let signer = MlDsa65Signer::generate_keypair();
    write_secret_file(&args.secret_key_out, signer.secret_key_bytes())?;
    write_secret_file(&args.public_key_out, signer.public_key_bytes())?;
    eprintln!(
        "wrote sk={} pk={}",
        args.secret_key_out.display(),
        args.public_key_out.display()
    );
    Ok(())
}