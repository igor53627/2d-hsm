//! Offline provisioning tool for PQ seal v1 blobs (see vsock spec §2.1).
//!
//! Run on a trusted workstation — not inside the untrusted host that launches the enclave.
//! The provisioning root must match what the enclave receives via `set_pq_seal_v1_provisioning_root`.

use clap::{Parser, Subcommand};
use enclave_protocol::{
    pq_seal_v1_expected_blob_len, pq_seal_v1_measurement_digest, seal_mldsa65_keypair_v1_with_root,
    verify_sealed_blob_v1_with_root, MlDsa65Signer, ML_DSA65_PUBKEY_LEN, ML_DSA65_SECRETKEY_LEN,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use zeroize::Zeroizing;

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
        Command::Manifest(ManifestCmd::Build(args)) => cmd_manifest_build(args),
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
    /// Multi-host manifest operations: seal the producer key once per host root (see runbook §8).
    #[command(subcommand)]
    Manifest(ManifestCmd),
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Seal the producer key once per host provisioning root → `blobs/<label>.sealed` +
    /// `pq-seal-manifest.json` in the output dir. Each blob unseals only on its host.
    Build(ManifestBuildArgs),
}

#[derive(Parser)]
struct ManifestBuildArgs {
    #[arg(long, group = "measurement")]
    measurement_file: Option<PathBuf>,
    #[arg(long, value_name = "HEX", group = "measurement")]
    measurement_hex: Option<String>,

    #[arg(long)]
    secret_key_file: PathBuf,
    #[arg(long)]
    public_key_file: PathBuf,

    /// A host as `LABEL=ROOTFILE` (32-byte provisioning root from `snp-derive-root --out`/`--print`).
    /// Repeat once per host. LABEL is the blob filename stem; must be `[A-Za-z0-9._-]+`.
    #[arg(long = "host", value_name = "LABEL=ROOTFILE", required = true)]
    hosts: Vec<String>,

    /// Output directory (created fresh): writes `pq-seal-manifest.json` + `blobs/<label>.sealed`.
    #[arg(long)]
    out_dir: PathBuf,
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

fn read_measurement(
    args_file: &Option<PathBuf>,
    args_hex: &Option<String>,
) -> Result<Vec<u8>, CliError> {
    if let Some(path) = args_file {
        let bytes = fs::read(path)?;
        if bytes.is_empty() {
            return Err(CliError::Msg("measurement must be non-empty".into()));
        }
        return Ok(bytes);
    }
    if let Some(hex) = args_hex {
        let bytes =
            hex::decode(hex.trim()).map_err(|e| CliError::Msg(format!("measurement hex: {e}")))?;
        if bytes.is_empty() {
            return Err(CliError::Msg("measurement must be non-empty".into()));
        }
        return Ok(bytes);
    }
    Err(CliError::Msg(
        "provide --measurement-file or --measurement-hex".into(),
    ))
}

fn read_root_32(path: &PathBuf) -> Result<Zeroizing<[u8; 32]>, CliError> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut root = Zeroizing::new([0u8; 32]);
    file.read_exact(root.as_mut())
        .map_err(|_| CliError::Msg("provisioning root must be exactly 32 bytes".into()))?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(CliError::Msg(
            "provisioning root must be exactly 32 bytes".into(),
        ));
    }
    Ok(root)
}

/// Write high-value secret material with restrictive permissions (Unix 0o600).
fn write_secret_file(path: &PathBuf, data: &[u8]) -> Result<(), CliError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)?.write_all(data)?;
    Ok(())
}

/// An ML-DSA-65 secret/public keypair held in zeroizing buffers.
type ZeroizingKeypair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// Read + length-validate the ML-DSA-65 keypair files (shared by `seal` and `manifest build`).
fn read_validated_keypair(
    secret_key_file: &PathBuf,
    public_key_file: &PathBuf,
) -> Result<ZeroizingKeypair, CliError> {
    let sk = Zeroizing::new(fs::read(secret_key_file)?);
    let pk = Zeroizing::new(fs::read(public_key_file)?);
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
    Ok((sk, pk))
}

/// A host label becomes a `blobs/<label>.sealed` filename — keep it a safe, single path component.
fn validate_label(label: &str) -> Result<(), CliError> {
    let ok = !label.is_empty()
        && label != "."
        && label != ".."
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        return Err(CliError::Msg(format!(
            "host label '{label}' must be non-empty and match [A-Za-z0-9._-] (it becomes a filename)"
        )));
    }
    Ok(())
}

fn cmd_seal(args: SealArgs) -> Result<(), CliError> {
    let measurement = read_measurement(&args.measurement_file, &args.measurement_hex)?;
    let root = read_root_32(&args.provisioning_root_file)?;
    let (sk, pk) = read_validated_keypair(&args.secret_key_file, &args.public_key_file)?;
    let blob = seal_mldsa65_keypair_v1_with_root(sk.as_ref(), pk.as_ref(), &measurement, &root)?;
    if blob.len() != pq_seal_v1_expected_blob_len() {
        return Err(CliError::Msg(
            "internal error: unexpected sealed blob length".into(),
        ));
    }
    write_secret_file(&args.output, &blob)?;
    eprintln!("wrote {} bytes to {}", blob.len(), args.output.display());
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

fn cmd_manifest_build(args: ManifestBuildArgs) -> Result<(), CliError> {
    let measurement = read_measurement(&args.measurement_file, &args.measurement_hex)?;
    let (sk, pk) = read_validated_keypair(&args.secret_key_file, &args.public_key_file)?;

    // Parse + validate every host up front, so we fail before writing any output.
    let mut parsed: Vec<(String, PathBuf)> = Vec::with_capacity(args.hosts.len());
    let mut seen = std::collections::BTreeSet::new();
    for h in &args.hosts {
        let (label, path) = h
            .split_once('=')
            .ok_or_else(|| CliError::Msg(format!("--host '{h}' must be LABEL=ROOTFILE")))?;
        validate_label(label)?;
        if !seen.insert(label.to_string()) {
            return Err(CliError::Msg(format!("duplicate host label '{label}'")));
        }
        parsed.push((label.to_string(), PathBuf::from(path)));
    }

    // Create the output tree fresh — never clobber a prior ceremony's blobs.
    let blobs_dir = args.out_dir.join("blobs");
    fs::create_dir(&args.out_dir)
        .map_err(|e| CliError::Msg(format!("create --out-dir {}: {e}", args.out_dir.display())))?;
    fs::create_dir(&blobs_dir)?;

    let mut entries = Vec::with_capacity(parsed.len());
    for (label, root_path) in &parsed {
        let root = read_root_32(root_path)?;
        let blob =
            seal_mldsa65_keypair_v1_with_root(sk.as_ref(), pk.as_ref(), &measurement, &root)?;
        if blob.len() != pq_seal_v1_expected_blob_len() {
            return Err(CliError::Msg(
                "internal error: unexpected sealed blob length".into(),
            ));
        }
        let rel = format!("blobs/{label}.sealed");
        write_secret_file(&args.out_dir.join(&rel), &blob)?;
        entries.push(pq_seal_manifest::Entry {
            label: label.clone(),
            root_commitment: hex::encode(pq_seal_manifest::root_commitment(&root)),
            blob: rel,
        });
    }

    let manifest = pq_seal_manifest::Manifest {
        version: pq_seal_manifest::MANIFEST_VERSION,
        measurement: hex::encode(&measurement),
        entries,
    };
    let json = manifest
        .to_json_pretty()
        .map_err(|e| CliError::Msg(format!("serialize manifest: {e}")))?;
    fs::write(args.out_dir.join(pq_seal_manifest::MANIFEST_FILENAME), json)?;

    eprintln!(
        "wrote {} ({} host(s)) + blobs/ to {}",
        pq_seal_manifest::MANIFEST_FILENAME,
        manifest.entries.len(),
        args.out_dir.display()
    );
    eprintln!(
        "meas_digest={}",
        hex::encode(pq_seal_v1_measurement_digest(&measurement))
    );
    Ok(())
}

#[cfg(test)]
mod manifest_build_tests {
    use super::*;

    fn write(path: &std::path::Path, data: &[u8]) {
        fs::write(path, data).unwrap();
    }

    #[test]
    fn seals_per_host_and_selection_is_trustless() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let signer = MlDsa65Signer::generate_keypair();
        let sk = base.join("sk.bin");
        let pk = base.join("pk.bin");
        write(&sk, signer.secret_key_bytes());
        write(&pk, signer.public_key_bytes());

        let (r1, r2) = ([1u8; 32], [2u8; 32]);
        let (root1, root2) = (base.join("root1.bin"), base.join("root2.bin"));
        write(&root1, &r1);
        write(&root2, &r2);

        let out = base.join("manifest-out");
        let meas_hex = "aa".repeat(48);
        cmd_manifest_build(ManifestBuildArgs {
            measurement_file: None,
            measurement_hex: Some(meas_hex.clone()),
            secret_key_file: sk,
            public_key_file: pk,
            hosts: vec![
                format!("aya={}", root1.display()),
                format!("host2={}", root2.display()),
            ],
            out_dir: out.clone(),
        })
        .unwrap();

        // Manifest parses; selection (trustless, from the host's own root) picks the right blob.
        let mbytes = fs::read(out.join(pq_seal_manifest::MANIFEST_FILENAME)).unwrap();
        let manifest = pq_seal_manifest::Manifest::from_json(&mbytes).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(manifest.select(&r1).unwrap().label, "aya");
        assert_eq!(manifest.select(&r2).unwrap().label, "host2");
        assert!(manifest.select(&[9u8; 32]).is_err());

        // Each blob unseals against ITS root and not the other (the AEAD tag authenticates).
        let meas = hex::decode(&meas_hex).unwrap();
        let aya_blob = fs::read(out.join(&manifest.select(&r1).unwrap().blob)).unwrap();
        verify_sealed_blob_v1_with_root(&aya_blob, &meas, &r1).expect("aya blob unseals on aya");
        assert!(verify_sealed_blob_v1_with_root(&aya_blob, &meas, &r2).is_err());
    }

    #[test]
    fn rejects_bad_label_and_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let signer = MlDsa65Signer::generate_keypair();
        let (sk, pk, root) = (
            base.join("sk.bin"),
            base.join("pk.bin"),
            base.join("root.bin"),
        );
        write(&sk, signer.secret_key_bytes());
        write(&pk, signer.public_key_bytes());
        write(&root, &[7u8; 32]);
        let mk = |hosts: Vec<String>, out: PathBuf| ManifestBuildArgs {
            measurement_file: None,
            measurement_hex: Some("bb".repeat(48)),
            secret_key_file: sk.clone(),
            public_key_file: pk.clone(),
            hosts,
            out_dir: out,
        };
        // Path-traversal label rejected (the '/' is not in [A-Za-z0-9._-]).
        assert!(cmd_manifest_build(mk(
            vec![format!("../evil={}", root.display())],
            base.join("o1")
        ))
        .is_err());
        // Duplicate label rejected.
        assert!(cmd_manifest_build(mk(
            vec![
                format!("a={}", root.display()),
                format!("a={}", root.display())
            ],
            base.join("o2")
        ))
        .is_err());
    }
}
