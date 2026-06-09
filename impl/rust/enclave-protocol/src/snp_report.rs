//! SEV-SNP attestation report: fetch via configfs-tsm and extract the launch measurement.
//!
//! TASK-5 Phase 3 (AC#4): make `GET_MEASUREMENT` return the real TEE launch measurement for the
//! SNP production profile instead of a placeholder label.
//!
//! Field offsets are the AMD SEV-SNP `ATTESTATION_REPORT` ABI, verified against a live report
//! captured on aya (EPYC 9375F, AMD OVMF; report version 5). The report is obtained through
//! `configfs-tsm` (`/sys/kernel/config/tsm/report`) as plain file I/O — no ioctl — which keeps
//! this in the crate's `#![forbid(unsafe_code)]` boundary.

use crate::ProtocolError;

// ---- ATTESTATION_REPORT field layout (bytes) ----
// pub(crate) so the reference verifier (snp_verify) reuses the single source of truth for offsets.
pub(crate) const REPORT_DATA_OFFSET: usize = 0x50;
const REPORT_DATA_LEN: usize = 64;
pub(crate) const MEASUREMENT_OFFSET: usize = 0x90;
/// SNP launch measurement length (48 bytes, SHA-384-sized).
pub const SNP_MEASUREMENT_LEN: usize = 48;
/// Shortest report we accept: it must at least cover the measurement field.
pub(crate) const MIN_REPORT_LEN: usize = MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN;

/// configfs-tsm report directory (Linux >= 6.7 with the SNP guest TSM provider loaded).
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
/// Fixed configfs entry name for this enclave's one boot-time report.
const TSM_ENTRY_NAME: &str = "twod-hsm";
/// Domain separation for the `report_data` binding (so it is not a bare key hash).
const REPORT_DATA_DOMAIN: &[u8] = b"2d-hsm-snp-report-data-v1";

/// Upper bound on the configfs-tsm `auxblob` (VCEK→ASK→ARK chain) we will carry in
/// GET_MEASUREMENT. A real chain is a few KB; this is generous headroom while staying well under
/// `MAX_MESSAGE_SIZE` once the report + pq_pubkey are added.
// `pub(crate)` so the agent boot-relay request encoder (TASK-7.7 5b-2) bounds its outbound cert_chain
// against the single source of truth rather than re-declaring 64 KiB.
pub(crate) const MAX_CERT_CHAIN_LEN: usize = 64 * 1024;

/// Extract the 48-byte launch measurement from a raw SNP `ATTESTATION_REPORT`.
pub fn measurement_from_report(report: &[u8]) -> Result<[u8; SNP_MEASUREMENT_LEN], ProtocolError> {
    if report.len() < MIN_REPORT_LEN {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP report shorter than ABI minimum (measurement field)",
        ));
    }
    let mut m = [0u8; SNP_MEASUREMENT_LEN];
    m.copy_from_slice(&report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN]);
    Ok(m)
}

/// Read the 64-byte `report_data` field a report carries (the value the guest requested).
pub fn report_data_from_report(report: &[u8]) -> Result<[u8; REPORT_DATA_LEN], ProtocolError> {
    if report.len() < REPORT_DATA_OFFSET + REPORT_DATA_LEN {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP report shorter than ABI minimum (report_data field)",
        ));
    }
    let mut rd = [0u8; REPORT_DATA_LEN];
    rd.copy_from_slice(&report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN]);
    Ok(rd)
}

/// 64-byte `report_data` binding the producer PQ key into the attestation (domain-separated
/// SHA3-512 of the public key). Putting this in the report ties the signed measurement to the
/// exact `pq_pubkey` the enclave advertises, so a relying party cannot replay a report from a
/// different key.
pub fn report_data_for_pubkey(pq_pubkey: &[u8]) -> [u8; REPORT_DATA_LEN] {
    use sha3::{Digest, Sha3_512};
    let mut h = Sha3_512::new();
    h.update(REPORT_DATA_DOMAIN);
    h.update(pq_pubkey);
    h.finalize().into()
}

/// Fetch a fresh SNP `ATTESTATION_REPORT` via configfs-tsm, binding `report_data` (64 bytes).
///
/// Returns `(report, cert_chain)` where `cert_chain` is the configfs-tsm `auxblob` — the
/// VCEK→ASK→ARK certificate chain a relying party needs to verify the report's signature against
/// the AMD root (see `backlog/docs/snp-attestation-verifier-policy.md`). The chain is best-effort:
/// some providers / older kernels don't populate `auxblob`, so an absent/empty chain is returned as
/// an empty `Vec` (NOT an error) — the report itself is the required output. The error path includes
/// "interface absent", so callers on non-SNP/dev hosts can fall back to a placeholder.
pub fn fetch_report(report_data: &[u8; REPORT_DATA_LEN]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    use std::fs;

    let entry = format!("{TSM_REPORT_DIR}/{TSM_ENTRY_NAME}");
    // Clear any stale entry left by a previous crashed boot, then create ours.
    let _ = fs::remove_dir(&entry);
    fs::create_dir(&entry).map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "SNP attestation unavailable: cannot create configfs-tsm report entry \
             (needs kernel >= 6.7 and the sev-guest TSM provider)",
        )
    })?;

    let result = fetch_report_inner(&entry, report_data);
    // Best-effort cleanup of the configfs entry regardless of outcome.
    let _ = fs::remove_dir(&entry);
    result
}

fn fetch_report_inner(
    entry: &str,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    use std::fs;
    use std::io::Write;

    let mut inblob = fs::OpenOptions::new()
        .write(true)
        .open(format!("{entry}/inblob"))
        .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation: cannot open inblob"))?;
    inblob.write_all(report_data).map_err(|_| {
        ProtocolError::PqSigningUnavailable("SNP attestation: cannot write report_data")
    })?;
    drop(inblob);

    let report = fs::read(format!("{entry}/outblob"))
        .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation: cannot read outblob"))?;
    if report.len() < MIN_REPORT_LEN {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP attestation: outblob shorter than ABI minimum",
        ));
    }
    // VCEK→ASK→ARK cert chain. Best-effort: absent/unreadable auxblob is fine (the verifier can
    // fetch the chain from AMD KDS by VCEK serial). A real chain is a few KB; cap it so an
    // implausibly large auxblob can't push the GET_MEASUREMENT frame past MAX_MESSAGE_SIZE and
    // break the whole response — drop to empty in that case rather than fail the report.
    let cert_chain = match fs::read(format!("{entry}/auxblob")) {
        Ok(c) if c.len() <= MAX_CERT_CHAIN_LEN => c,
        _ => Vec::new(),
    };
    Ok((report, cert_chain))
}

/// Boot-captured SNP attestation: `(launch_measurement, raw_report, cert_chain)`.
/// `cert_chain` (configfs-tsm `auxblob`) may be empty when the provider didn't populate it.
pub type SnpAttestation = ([u8; SNP_MEASUREMENT_LEN], Vec<u8>, Vec<u8>);

/// Fetch the SNP report bound to `pq_pubkey` and return `(measurement, raw_report, cert_chain)`.
pub fn fetch_measurement_and_report(pq_pubkey: &[u8]) -> Result<SnpAttestation, ProtocolError> {
    let report_data = report_data_for_pubkey(pq_pubkey);
    let (report, cert_chain) = fetch_report(&report_data)?;
    let measurement = verify_and_extract_measurement(&report, &report_data)?;
    Ok((measurement, report, cert_chain))
}

/// Verify the report echoes the requested `report_data` (the key binding) before trusting its
/// measurement, then extract the measurement. Rejects a stale or misrouted report whose
/// `report_data` does not match what we asked for.
fn verify_and_extract_measurement(
    report: &[u8],
    expected_report_data: &[u8; REPORT_DATA_LEN],
) -> Result<[u8; SNP_MEASUREMENT_LEN], ProtocolError> {
    let echoed = report_data_from_report(report)?;
    if &echoed != expected_report_data {
        return Err(ProtocolError::PqSigningUnavailable(
            "SNP report_data does not echo the requested key binding",
        ));
    }
    measurement_from_report(report)
}

// ---- boot-time capture + cache ----

struct CachedAttestation {
    measurement: [u8; SNP_MEASUREMENT_LEN],
    report: Vec<u8>,
    cert_chain: Vec<u8>,
}

/// One SNP report captured at enclave boot (bound to the installed PQ key).
static SNP_ATTESTATION: std::sync::Mutex<Option<CachedAttestation>> =
    std::sync::Mutex::new(None);

/// Boot hook: fetch the SNP report bound to `pq_pubkey` once and cache
/// `(measurement, report, cert_chain)`. Propagates the fetch error (e.g. interface absent) so the
/// caller can log + fall back.
pub fn boot_fetch_and_cache(pq_pubkey: &[u8]) -> Result<(), ProtocolError> {
    let (measurement, report, cert_chain) = fetch_measurement_and_report(pq_pubkey)?;
    let mut guard = SNP_ATTESTATION
        .lock()
        .map_err(|_| ProtocolError::PqSigningUnavailable("SNP attestation cache poisoned"))?;
    *guard = Some(CachedAttestation {
        measurement,
        report,
        cert_chain,
    });
    Ok(())
}

/// The boot-captured `(measurement, raw_report, cert_chain)`, if an SNP report was obtained at
/// startup. `cert_chain` may be empty when the provider did not populate `auxblob`.
pub fn cached_attestation() -> Option<SnpAttestation> {
    let guard = SNP_ATTESTATION.lock().ok()?;
    guard
        .as_ref()
        .map(|c| (c.measurement, c.report.clone(), c.cert_chain.clone()))
}

#[cfg(test)]
pub(crate) fn set_cached_attestation_for_tests(
    measurement: [u8; SNP_MEASUREMENT_LEN],
    report: Vec<u8>,
    cert_chain: Vec<u8>,
) {
    if let Ok(mut g) = SNP_ATTESTATION.lock() {
        *g = Some(CachedAttestation {
            measurement,
            report,
            cert_chain,
        });
    }
}

#[cfg(test)]
pub(crate) fn reset_cached_attestation_for_tests() {
    if let Ok(mut g) = SNP_ATTESTATION.lock() {
        *g = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real SNP ATTESTATION_REPORT captured on aya (EPYC 9375F, AMD OVMF; report version 5),
    // requested with report_data = 0x00..0x3f. See backlog/tasks/task-5 Phase 3 notes.
    const GOLDEN: &[u8] = include_bytes!("../testvectors/snp_report_golden_v5.bin");
    const GOLDEN_MEASUREMENT_HEX: &str = "3e39e33ab71f37ec9391fb285620dc5e50b67dd7cb59447726138596f9c502ed971ae0d095ea2ab3f93a8b8f6016b488";

    #[test]
    fn golden_report_shape() {
        assert_eq!(GOLDEN.len(), 1184);
        // version field (u32 LE) at offset 0x00 is 5 for this capture.
        assert_eq!(u32::from_le_bytes(GOLDEN[0..4].try_into().unwrap()), 5);
    }

    #[test]
    fn measurement_from_golden_report() {
        let m = measurement_from_report(GOLDEN).unwrap();
        assert_eq!(m.len(), SNP_MEASUREMENT_LEN);
        assert_eq!(hex::encode(m), GOLDEN_MEASUREMENT_HEX);
    }

    #[test]
    fn report_data_field_matches_capture_anchor() {
        // The capture embedded report_data = 0x00..0x3f at offset 0x50 — proves the offset.
        let rd = report_data_from_report(GOLDEN).unwrap();
        let expected: Vec<u8> = (0u8..64).collect();
        assert_eq!(rd.as_slice(), expected.as_slice());
    }

    #[test]
    fn measurement_rejects_short_report() {
        assert!(measurement_from_report(&[0u8; MEASUREMENT_OFFSET]).is_err());
        assert!(measurement_from_report(&[]).is_err());
        // Exactly long enough succeeds.
        assert!(measurement_from_report(&[0u8; MIN_REPORT_LEN]).is_ok());
    }

    #[test]
    fn verify_and_extract_accepts_matching_report_data() {
        let expected: [u8; REPORT_DATA_LEN] = (0u8..64).collect::<Vec<_>>().try_into().unwrap();
        let m = verify_and_extract_measurement(GOLDEN, &expected).unwrap();
        assert_eq!(hex::encode(m), GOLDEN_MEASUREMENT_HEX);
    }

    #[test]
    fn verify_and_extract_rejects_mismatched_report_data() {
        let wrong = [0xFFu8; REPORT_DATA_LEN];
        assert!(verify_and_extract_measurement(GOLDEN, &wrong).is_err());
    }

    #[test]
    fn report_data_binding_is_deterministic_64_bytes_and_key_specific() {
        let a = report_data_for_pubkey(b"producer-pubkey-bytes");
        let b = report_data_for_pubkey(b"producer-pubkey-bytes");
        assert_eq!(a, b);
        assert_eq!(a.len(), REPORT_DATA_LEN);
        assert_ne!(a, report_data_for_pubkey(b"a-different-pubkey"));
        // Domain separation: not a bare hash of the key.
        use sha3::{Digest, Sha3_512};
        let bare: [u8; 64] = Sha3_512::digest(b"producer-pubkey-bytes").into();
        assert_ne!(a, bare);
    }
}
