//! `snp-derive-root` — derive the pq-seal v1 provisioning root from the SEV-SNP firmware.
//!
//! Boot use (the intended production wiring — a NixOS oneshot running before the enclave; only the
//! `--selftest` diagnostic is wired today, the `--out` oneshot is a follow-up, see runbook §7.1):
//!     snp-derive-root --out /run/twod-hsm/pq-seal-root.bin
//! Provisioning ceremony (run ONCE inside the target image to seal offline):
//!     snp-derive-root --print
//!
//! Options: --field-select <preset|u64|0xhex> (default: measurement), --root-key <vcek|vmrk>
//! (default vcek), --svn <n> (default 0). See snp_derive_root::FIELD_* for the mask bits.

use snp_derive_root::{
    provisioning_root, selftest, FIELD_FAMILY_ID, FIELD_GUEST_POLICY, FIELD_GUEST_SVN,
    FIELD_IMAGE_ID, FIELD_MEASUREMENT, FIELD_TCB_VERSION, ROOT_KEY_VCEK, ROOT_KEY_VMRK,
};
use zeroize::Zeroizing;

const USAGE: &str = "\
snp-derive-root — derive the pq-seal v1 provisioning root from SEV-SNP firmware

USAGE:
  snp-derive-root (--out <path> | --print | --selftest) [--field-select <v>] [--root-key vcek|vmrk] [--svn <n>]

MODES (at least one):
  --out <path>   write the 32-byte root to <path> (mode 0600) for TWOD_HSM_PQ_SEAL_V1_ROOT_FILE
  --print        print the root as hex (provisioning ceremony — run inside the target image)
  --selftest     validate the derived-key path in-guest; prints only a SHA3-256 commitment of the
                 root (no secret), PASS/FAIL + the measurement-binding check. exit 1 on FAIL.

OPTIONS:
  --field-select <v>   guest_field_select: a preset (measurement|policy|none|all|policy+measurement),
                       or a u64 / 0xHEX mask of FIELD_* bits (default: measurement)
  --root-key <k>       vcek (default) | vmrk
  --svn <n>            guest_svn (default 0); only binds when --field-select includes guest_svn (bit 4)
";

fn parse_field_select(v: &str) -> Result<u64, String> {
    match v {
        "measurement" => Ok(FIELD_MEASUREMENT),
        "policy" => Ok(FIELD_GUEST_POLICY),
        "policy+measurement" | "measurement+policy" => Ok(FIELD_GUEST_POLICY | FIELD_MEASUREMENT),
        "none" => Ok(0),
        "all" => Ok(FIELD_GUEST_POLICY
            | FIELD_IMAGE_ID
            | FIELD_FAMILY_ID
            | FIELD_MEASUREMENT
            | FIELD_GUEST_SVN
            | FIELD_TCB_VERSION),
        s => {
            let parsed = if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16)
            } else {
                s.parse::<u64>()
            };
            parsed.map_err(|_| format!("invalid --field-select '{s}' (preset, u64, or 0xHEX)"))
        }
    }
}

/// Parsed CLI arguments. Extracted from `run()` so the flag handling (the `--out` anti-flag guard,
/// missing values, presets) is unit-testable without touching `std::env`.
#[derive(Debug, Default)]
struct Args {
    out: Option<String>,
    print: bool,
    selftest: bool,
    field_select: u64,
    root_key: u32,
    svn: u32,
    help: bool,
}

fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Result<Args, String> {
    let mut a = Args {
        field_select: FIELD_MEASUREMENT,
        root_key: ROOT_KEY_VCEK,
        ..Default::default()
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let p = args.next().ok_or("--out needs a path")?;
                // Guard against eating the next flag as the path (e.g. `--out --print` writing the
                // secret root to a file literally named "--print"); paths don't start with "--".
                if p.starts_with("--") {
                    return Err(format!("--out needs a path, got flag '{p}'"));
                }
                a.out = Some(p);
            }
            "--print" => a.print = true,
            "--selftest" => a.selftest = true,
            "--field-select" => {
                a.field_select =
                    parse_field_select(&args.next().ok_or("--field-select needs a value")?)?
            }
            "--root-key" => {
                a.root_key = match args.next().as_deref() {
                    Some("vcek") => ROOT_KEY_VCEK,
                    Some("vmrk") => ROOT_KEY_VMRK,
                    other => return Err(format!("invalid --root-key {other:?} (vcek|vmrk)")),
                }
            }
            "--svn" => {
                a.svn = args
                    .next()
                    .ok_or("--svn needs a value")?
                    .parse()
                    .map_err(|_| "invalid --svn (u32)".to_string())?
            }
            "-h" | "--help" => {
                // Short-circuit: stop parsing so a following arg can't turn --help into an error.
                a.help = true;
                return Ok(a);
            }
            other => return Err(format!("unknown argument '{other}'\n\n{USAGE}")),
        }
    }
    Ok(a)
}

fn run() -> Result<(), String> {
    let a = parse_args(std::env::args().skip(1))?;
    if a.help {
        print!("{USAGE}");
        return Ok(());
    }

    if a.out.is_none() && !a.print && !a.selftest {
        return Err(format!(
            "need --out <path>, --print, or --selftest\n\n{USAGE}"
        ));
    }

    // --svn only mixes into the derivation when the field mask selects guest_svn (bit 4). Warn so an
    // operator doesn't believe an SVN was bound when it silently was not (and the --selftest path
    // ignores --svn entirely).
    if a.svn != 0 && (a.field_select & FIELD_GUEST_SVN) == 0 {
        eprintln!(
            "snp-derive-root: warning: --svn {} has no effect without --field-select including guest_svn (bit 4); the root will NOT be SVN-bound",
            a.svn
        );
    }

    if a.selftest {
        let st = selftest().map_err(|e| e.to_string())?;
        println!(
            "snp-derive-root selftest: {} (nonzero={}, binding_changes={}) measurement_root_commit={}",
            if st.pass { "PASS" } else { "FAIL" },
            st.nonzero,
            st.binding_changes,
            hex_lower(&st.measurement_root_commit),
        );
        if !st.pass {
            return Err("selftest FAILED (key zero or measurement binding ineffective — check DERIVED_KEY offset)".into());
        }
    }

    // selftest-only invocation (nothing to provision) — done.
    if a.out.is_none() && !a.print {
        return Ok(());
    }

    let root = provisioning_root(a.field_select, a.root_key, a.svn).map_err(|e| e.to_string())?;

    if let Some(path) = a.out.as_deref() {
        write_root_0600(path, &root).map_err(|e| format!("write {path}: {e}"))?;
        eprintln!(
            "snp-derive-root: wrote 32-byte provisioning root to {path} (field_select={:#x})",
            a.field_select
        );
    }
    if a.print {
        // Wrap the hex in Zeroizing so the heap copy of the secret is scrubbed after printing.
        let hex = Zeroizing::new(hex_lower(&root[..]));
        println!("{}", hex.as_str());
    }
    Ok(())
}

fn write_root_0600(path: &str, root: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;
    // Provision the parent dir (0700) so a documented target like /run/twod-hsm/pq-seal-root.bin
    // works without a separate tmpfiles/RuntimeDirectory step.
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(parent)?;
            }
        }
    }
    // Defeat a pre-existing file/symlink at the target: drop it, then create fresh with O_EXCL
    // (create_new). This never follows a planted symlink and never inherits loose perms — mode()
    // applies only at creation, so writing through an existing inode would otherwise keep its mode.
    let _ = std::fs::remove_file(path);
    let mut f = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?
        }
    };
    f.write_all(root)?;
    f.sync_all()
}

fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        // Into the preallocated String (no per-byte allocation, no transient secret fragments on
        // the heap); write! to a String is infallible.
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn main() {
    if let Err(e) = run() {
        eprintln!("snp-derive-root: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn out_rejects_flag_as_path() {
        let e = args(&["--out", "--print"]).unwrap_err();
        assert!(e.contains("--out needs a path"), "{e}");
    }

    #[test]
    fn out_takes_path() {
        assert_eq!(
            args(&["--out", "/run/x.bin"]).unwrap().out.as_deref(),
            Some("/run/x.bin")
        );
    }

    #[test]
    fn modes_and_defaults() {
        let a = args(&["--selftest"]).unwrap();
        assert!(a.selftest && a.out.is_none() && !a.print);
        assert_eq!(a.field_select, FIELD_MEASUREMENT);
        assert_eq!(a.root_key, ROOT_KEY_VCEK);
        assert_eq!(a.svn, 0);
    }

    #[test]
    fn missing_values_error() {
        assert!(args(&["--out"]).is_err());
        assert!(args(&["--field-select"]).is_err());
        assert!(args(&["--svn"]).is_err());
    }

    #[test]
    fn unknown_arg_errors() {
        assert!(args(&["--nope"]).unwrap_err().contains("unknown argument"));
    }

    #[test]
    fn help_short_circuits() {
        // --help stops parsing, so a following bad arg is ignored (preserves prior behavior).
        assert!(args(&["--help", "--nope"]).unwrap().help);
    }

    #[test]
    fn root_key_and_svn_parse() {
        let a = args(&["--root-key", "vmrk", "--svn", "7"]).unwrap();
        assert_eq!(a.root_key, ROOT_KEY_VMRK);
        assert_eq!(a.svn, 7);
        assert!(args(&["--root-key", "bogus"]).is_err());
        assert!(args(&["--svn", "x"]).is_err());
    }

    #[test]
    fn field_select_presets_and_numbers() {
        assert_eq!(
            parse_field_select("measurement").unwrap(),
            FIELD_MEASUREMENT
        );
        assert_eq!(parse_field_select("none").unwrap(), 0);
        assert_eq!(
            parse_field_select("policy+measurement").unwrap(),
            FIELD_GUEST_POLICY | FIELD_MEASUREMENT
        );
        assert_eq!(parse_field_select("0x8").unwrap(), 0x8);
        assert_eq!(parse_field_select("16").unwrap(), 16);
        assert!(parse_field_select("nope").is_err());
    }

    #[test]
    fn hex_lower_matches_expected() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex_lower(&[]), "");
    }

    #[cfg(unix)]
    fn unique_tmp(tag: &str) -> std::path::PathBuf {
        // Distinct per test (PID + tag); cargo runs tests as threads in one process, so the tag
        // avoids cross-test collisions on the shared temp dir.
        std::env::temp_dir().join(format!("snp-derive-root-{tag}-{}", std::process::id()))
    }

    #[cfg(unix)]
    #[test]
    fn write_root_0600_creates_parent_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_tmp("parent");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("root.bin");
        let root = [0xABu8; 32];
        write_root_0600(path.to_str().unwrap(), &root).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), root);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_root_0600_tightens_loose_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_tmp("loose");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("root.bin");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_root_0600(path.to_str().unwrap(), &[0x11u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "must tighten to 0600, got {mode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), [0x11u8; 32]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_root_0600_does_not_follow_symlink() {
        let dir = unique_tmp("link");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.bin");
        std::fs::write(&victim, b"untouched").unwrap();
        let link = dir.join("root.bin");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        // Writing the secret to the symlink path must replace the link, NOT write through to victim.
        write_root_0600(link.to_str().unwrap(), &[0x22u8; 32]).unwrap();
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"untouched",
            "victim must be untouched"
        );
        assert_eq!(
            std::fs::read(&link).unwrap(),
            [0x22u8; 32],
            "link path now holds the root"
        );
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
