//! Derive the 2d-hsm **pq-seal v1 provisioning root** from the SEV-SNP firmware.
//!
//! The enclave (`enclave-protocol`) is `#![forbid(unsafe_code)]` and gets its 32-byte provisioning
//! root from a file (`TWOD_HSM_PQ_SEAL_V1_ROOT_FILE`). This boot helper owns the one ioctl that
//! crate cannot do — `SNP_GET_DERIVED_KEY` on the guest-only `/dev/sev-guest` — derives the root,
//! and (via the CLI) writes it to that file before the enclave starts. TASK-1.1.
//!
//! `root = SHA3-256("2d-hsm-pq-seal-v1-root" || snp_derived_key)` — domain-separated, so the raw
//! firmware key is never exposed and could feed other domains. Bind to MEASUREMENT by default so
//! the root is image-specific (matches the measurement-bound seal); configurable via the field mask.

// The ioctl request structs + constants are only used by the Linux ioctl path (and the ABI tests).
// On non-Linux dev builds (e.g. macOS) that path is cfg'd out, so allow the dead code there only —
// the lint stays active on Linux to catch genuinely-unused items.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use sha3::{Digest, Sha3_256};

/// configfs has no derived-key interface; this is the only path (guest-only device).
pub const DEV_SEV_GUEST: &str = "/dev/sev-guest";

// MSG_KEY_REQ.guest_field_select bits (AMD SEV-SNP ABI 56860).
pub const FIELD_GUEST_POLICY: u64 = 1 << 0;
pub const FIELD_IMAGE_ID: u64 = 1 << 1;
pub const FIELD_FAMILY_ID: u64 = 1 << 2;
pub const FIELD_MEASUREMENT: u64 = 1 << 3;
pub const FIELD_GUEST_SVN: u64 = 1 << 4;
pub const FIELD_TCB_VERSION: u64 = 1 << 5;

/// MSG_KEY_REQ.root_key_select: 0 = VCEK, 1 = VMRK.
pub const ROOT_KEY_VCEK: u32 = 0;
pub const ROOT_KEY_VMRK: u32 = 1;

/// MSG_KEY_RSP layout: STATUS@0x00 (4 B), reserved, **DERIVED_KEY@0x20 (32 B)** within the 64-byte
/// `snp_derived_key_resp.data`. Per AMD ABI 56860; the kernel copies the full payload verbatim.
const DERIVED_KEY_OFFSET: usize = 0x20;
const DERIVED_KEY_LEN: usize = 32;

/// Domain separation: the provisioning root is NOT the bare firmware key.
const ROOT_DOMAIN: &[u8] = b"2d-hsm-pq-seal-v1-root";

/// `root = SHA3-256(domain || snp_derived_key)`. Pure — the testable core.
pub fn derive_provisioning_root(snp_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ROOT_DOMAIN);
    h.update(snp_key);
    h.finalize().into()
}

#[derive(Debug)]
pub enum DeriveError {
    /// Not a Linux target (the SNP guest device + ioctl are Linux-only).
    Unsupported,
    /// `/dev/sev-guest` could not be opened (not an SNP guest, or sev-guest module not loaded).
    OpenDevice(std::io::Error),
    /// The SNP_GET_DERIVED_KEY ioctl failed (firmware/VMM error in exitinfo2).
    Ioctl {
        rc: i32,
        fw_error: u32,
        vmm_error: u32,
        errno: std::io::Error,
    },
}

impl std::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeriveError::Unsupported => write!(f, "SNP derived key is only available on Linux SEV-SNP guests"),
            DeriveError::OpenDevice(e) => write!(f, "cannot open {DEV_SEV_GUEST} (need an SEV-SNP guest with the sev-guest module): {e}"),
            DeriveError::Ioctl { rc, fw_error, vmm_error, errno } => write!(
                f,
                "SNP_GET_DERIVED_KEY ioctl failed (rc={rc}, fw_error={fw_error:#x}, vmm_error={vmm_error:#x}, errno={errno})"
            ),
        }
    }
}
impl std::error::Error for DeriveError {}

#[repr(C)]
struct SnpDerivedKeyReq {
    root_key_select: u32,
    rsvd: u32,
    guest_field_select: u64,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
}

#[repr(C)]
struct SnpDerivedKeyResp {
    data: [u8; 64],
}

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// `_IOWR(type, nr, size)` — dir(READ|WRITE)=3.
const fn iowr(ty: u32, nr: u32, size: usize) -> u64 {
    (((3u32) << 30) | ((size as u32) << 16) | (ty << 8) | nr) as u64
}
const SNP_GET_DERIVED_KEY: u64 =
    iowr(b'S' as u32, 0x1, core::mem::size_of::<SnpGuestRequestIoctl>());

/// Fetch the raw 32-byte SEV-SNP firmware-derived key (NOT domain-separated — use
/// [`provisioning_root`] for the value the enclave consumes).
#[cfg(target_os = "linux")]
pub fn fetch_snp_derived_key(
    field_select: u64,
    root_key_select: u32,
    guest_svn: u32,
) -> Result<[u8; 32], DeriveError> {
    use std::os::unix::io::AsRawFd;

    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEV_SEV_GUEST)
        .map_err(DeriveError::OpenDevice)?;

    let mut req = SnpDerivedKeyReq {
        root_key_select,
        rsvd: 0,
        guest_field_select: field_select,
        vmpl: 0,
        guest_svn,
        tcb_version: 0,
    };
    let mut resp = SnpDerivedKeyResp { data: [0u8; 64] };
    let mut ioc = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: (&mut req as *mut SnpDerivedKeyReq) as u64,
        resp_data: (&mut resp as *mut SnpDerivedKeyResp) as u64,
        exitinfo2: 0,
    };

    // SAFETY: `ioc`/`req`/`resp` outlive the call; the pointers in `ioc` are valid for the duration;
    // SNP_GET_DERIVED_KEY's encoded size matches `SnpGuestRequestIoctl`.
    let rc = unsafe {
        libc::ioctl(
            dev.as_raw_fd(),
            SNP_GET_DERIVED_KEY as libc::c_ulong,
            (&mut ioc as *mut SnpGuestRequestIoctl) as *mut libc::c_void,
        )
    };
    if rc != 0 {
        return Err(DeriveError::Ioctl {
            rc,
            fw_error: (ioc.exitinfo2 & 0xffff_ffff) as u32,
            vmm_error: (ioc.exitinfo2 >> 32) as u32,
            errno: std::io::Error::last_os_error(),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&resp.data[DERIVED_KEY_OFFSET..DERIVED_KEY_OFFSET + DERIVED_KEY_LEN]);
    resp.data.fill(0); // best-effort wipe of the response buffer
    Ok(key)
}

#[cfg(not(target_os = "linux"))]
pub fn fetch_snp_derived_key(
    _field_select: u64,
    _root_key_select: u32,
    _guest_svn: u32,
) -> Result<[u8; 32], DeriveError> {
    Err(DeriveError::Unsupported)
}

/// Fetch the firmware key and return the domain-separated provisioning root the enclave consumes.
pub fn provisioning_root(
    field_select: u64,
    root_key_select: u32,
    guest_svn: u32,
) -> Result<[u8; 32], DeriveError> {
    let key = fetch_snp_derived_key(field_select, root_key_select, guest_svn)?;
    Ok(derive_provisioning_root(&key))
}

/// In-guest self-test result. Carries only SHA3-256 **commitments** of the derived roots — never the
/// roots themselves — so it is safe to log/console-dump while validating on a real SNP host.
pub struct SelfTest {
    /// Both checks passed: the firmware key is non-trivial AND the MEASUREMENT binding changes it.
    pub pass: bool,
    /// The MEASUREMENT-bound key is not all-zero (catches a wrong DERIVED_KEY offset → status/zero).
    pub nonzero: bool,
    /// Selecting MEASUREMENT vs nothing yields different keys (the binding actually takes effect).
    pub binding_changes: bool,
    /// SHA3-256 of the MEASUREMENT-bound provisioning root — stable across reboots iff the firmware
    /// key is stable. Compare across two boots to prove stability without revealing the secret.
    pub measurement_root_commit: [u8; 32],
}

/// Validate the derived-key path in-guest without exposing secret material (see [`SelfTest`]).
#[cfg(target_os = "linux")]
pub fn selftest() -> Result<SelfTest, DeriveError> {
    let m_key = fetch_snp_derived_key(FIELD_MEASUREMENT, ROOT_KEY_VCEK, 0)?;
    let n_key = fetch_snp_derived_key(0, ROOT_KEY_VCEK, 0)?;
    let commit = |k: &[u8; 32]| -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"2d-hsm-snp-derive-root-selftest-commit");
        h.update(derive_provisioning_root(k));
        h.finalize().into()
    };
    let nonzero = m_key.iter().any(|b| *b != 0);
    let binding_changes = m_key != n_key;
    Ok(SelfTest {
        pass: nonzero && binding_changes,
        nonzero,
        binding_changes,
        measurement_root_commit: commit(&m_key),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn selftest() -> Result<SelfTest, DeriveError> {
    Err(DeriveError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_struct_sizes_match_uapi() {
        assert_eq!(core::mem::size_of::<SnpDerivedKeyReq>(), 32);
        assert_eq!(core::mem::size_of::<SnpDerivedKeyResp>(), 64);
        assert_eq!(core::mem::size_of::<SnpGuestRequestIoctl>(), 32);
    }

    #[test]
    fn ioctl_number_matches_iowr_s_1() {
        // _IOWR('S', 0x1, 32) = 0xC0205301
        assert_eq!(SNP_GET_DERIVED_KEY, 0xC020_5301);
    }

    #[test]
    fn field_and_root_constants() {
        assert_eq!(FIELD_MEASUREMENT, 0x8);
        assert_eq!(FIELD_GUEST_POLICY, 0x1);
        assert_eq!(ROOT_KEY_VCEK, 0);
        assert_eq!(ROOT_KEY_VMRK, 1);
    }

    #[test]
    fn root_is_domain_separated_and_deterministic() {
        let k = [0x5au8; 32];
        let r1 = derive_provisioning_root(&k);
        let r2 = derive_provisioning_root(&k);
        assert_eq!(r1, r2, "deterministic");
        assert_ne!(r1, k, "root must not be the bare firmware key");
        assert_ne!(r1, derive_provisioning_root(&[0x5bu8; 32]), "different key -> different root");
    }

    #[test]
    fn fetch_off_snp_errors_gracefully() {
        // No panic off-SNP: non-Linux -> Unsupported; Linux without the device -> OpenDevice.
        match fetch_snp_derived_key(FIELD_MEASUREMENT, ROOT_KEY_VCEK, 0) {
            Err(DeriveError::Unsupported) | Err(DeriveError::OpenDevice(_)) => {}
            other => panic!("expected Unsupported/OpenDevice off-SNP, got {other:?}"),
        }
    }
}
