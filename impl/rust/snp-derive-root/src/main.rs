//! `snp-derive-root` — derive the pq-seal v1 provisioning root from the SEV-SNP firmware.
//!
//! Boot use (NixOS oneshot, before the enclave):
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
  snp-derive-root (--out <path> | --print) [--field-select <v>] [--root-key vcek|vmrk] [--svn <n>]

MODES (at least one):
  --out <path>   write the 32-byte root to <path> (mode 0600) for TWOD_HSM_PQ_SEAL_V1_ROOT_FILE
  --print        print the root as hex (provisioning ceremony — run inside the target image)
  --selftest     validate the derived-key path in-guest; prints only a SHA3-256 commitment of the
                 root (no secret), PASS/FAIL + the measurement-binding check. exit 1 on FAIL.

OPTIONS:
  --field-select <v>   guest_field_select: a preset (measurement|policy|none), or a u64 / 0xHEX
                       mask of FIELD_* bits (default: measurement)
  --root-key <k>       vcek (default) | vmrk
  --svn <n>            guest_svn (default 0)
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

fn run() -> Result<(), String> {
    let mut out: Option<String> = None;
    let mut print = false;
    let mut do_selftest = false;
    let mut field_select = FIELD_MEASUREMENT;
    let mut root_key = ROOT_KEY_VCEK;
    let mut svn: u32 = 0;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => {
                let p = args.next().ok_or("--out needs a path")?;
                // Guard against eating the next flag as the path (e.g. `--out --print` writing the
                // secret root to a file literally named "--print"); paths don't start with "--".
                if p.starts_with("--") {
                    return Err(format!("--out needs a path, got flag '{p}'"));
                }
                out = Some(p);
            }
            "--print" => print = true,
            "--selftest" => do_selftest = true,
            "--field-select" => {
                field_select =
                    parse_field_select(&args.next().ok_or("--field-select needs a value")?)?
            }
            "--root-key" => {
                root_key = match args.next().as_deref() {
                    Some("vcek") => ROOT_KEY_VCEK,
                    Some("vmrk") => ROOT_KEY_VMRK,
                    other => return Err(format!("invalid --root-key {other:?} (vcek|vmrk)")),
                }
            }
            "--svn" => {
                svn = args
                    .next()
                    .ok_or("--svn needs a value")?
                    .parse()
                    .map_err(|_| "invalid --svn (u32)".to_string())?
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown argument '{other}'\n\n{USAGE}")),
        }
    }

    if do_selftest {
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
        if out.is_none() && !print {
            return Ok(());
        }
    }

    if out.is_none() && !print && !do_selftest {
        return Err(format!(
            "need --out <path>, --print, or --selftest\n\n{USAGE}"
        ));
    }
    if out.is_none() && !print {
        return Ok(());
    }

    let root = provisioning_root(field_select, root_key, svn).map_err(|e| e.to_string())?;

    if let Some(path) = out.as_deref() {
        write_root_0600(path, &root).map_err(|e| format!("write {path}: {e}"))?;
        eprintln!("snp-derive-root: wrote 32-byte provisioning root to {path} (field_select={field_select:#x})");
    }
    if print {
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
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn main() {
    if let Err(e) = run() {
        eprintln!("snp-derive-root: {e}");
        std::process::exit(1);
    }
}
