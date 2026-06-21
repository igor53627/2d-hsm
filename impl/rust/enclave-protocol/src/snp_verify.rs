//! Reference relying-party **pre-validation** for the 2d-hsm SEV-SNP attestation (TASK-1 AC#3/#12).
//!
//! Implements the cheap, signature-independent checks of
//! `backlog/docs/snp-attestation-verifier-policy.md` (structure + key binding + measurement
//! allowlist + DEBUG-off posture). This is **relying-party** code (BP / on-chain consumer), **not**
//! the enclave signing path — it lives behind the off-by-default `snp-verify` feature so it is never
//! compiled into the production enclave binary.
//!
//! ## NOT sufficient on its own — this is the *pre-signature* step
//! [`prevalidate_report`] deliberately does **not** verify the report's VCEK→ASK→ARK signature
//! chain to the pinned AMD root (policy §2 step 2): that needs ECDSA-P384 + X.509 + AMD KDS and is
//! kept out of this `#![forbid(unsafe_code)]` crate. A `PrevalidatedReport` means "the claims look
//! right" — the caller **MUST** still verify the signature chain before trusting it. The name
//! signals this; do not treat a `PrevalidatedReport` as an attested report.

use crate::snp_report::{
    measurement_from_report, report_data_for_pubkey, report_data_from_report, SNP_MEASUREMENT_LEN,
};
use crate::ProtocolError;

// Field offsets snp_report does not expose (it reads report_data/measurement itself).
const VERSION_OFFSET: usize = 0x00; // u32 LE
const POLICY_OFFSET: usize = 0x08; // u64 LE guest policy
                                   // A SEV-SNP ATTESTATION_REPORT is a fixed 1184 bytes (ABI v2–v5). Require the whole structure: the
                                   // VCEK signature + other fields the caller's signature step needs live at the end, so a truncated
                                   // buffer must not pre-validate (security: reject short/forged reports up front).
const EXPECTED_REPORT_LEN: usize = 1184;
// GUEST_POLICY.DEBUG is bit 19 — a debuggable guest is never acceptable for production.
const POLICY_DEBUG_BIT: u64 = 1 << 19;
// The report_data (0x50) / measurement (0x90) / policy (0x08) offsets are stable for SEV-SNP
// ATTESTATION_REPORT ABI v2 and up (the committed golden is v5); reject older/garbage layouts.
const MIN_REPORT_VERSION: u32 = 2;

/// A report that passed the signature-independent checks. **Not** an attested report — the caller
/// must still verify the VCEK→ASK→ARK signature chain (see module docs).
#[derive(Debug, Clone)]
pub struct PrevalidatedReport {
    /// The 48-byte launch measurement that matched the allowlist.
    pub measurement: [u8; SNP_MEASUREMENT_LEN],
}

/// Pre-validate the signature-independent parts of the attestation policy.
///
/// Checks, in order:
/// 1. report length + ABI version (`>= MIN_REPORT_VERSION`, the version the offsets assume),
/// 2. guest policy `DEBUG` bit is **off**,
/// 3. when `expected_pq_pubkey` is `Some`, `report_data == SHA3-512("2d-hsm-snp-report-data-v1" ||
///    pq_pubkey)` (binds the producer key into the report); `None` skips binding for an
///    allowlist-only check — but note the launch measurement is OVMF-level and shared across
///    guests (policy §3), so without the binding this does **not** tie the report to any key,
/// 4. the launch `measurement` is in `allowed_measurements`.
///
/// Returns the verified measurement. **Does not** verify the VCEK signature / cert chain — the
/// caller MUST still do that against the pinned AMD root (see module docs).
pub fn prevalidate_report(
    report: &[u8],
    expected_pq_pubkey: Option<&[u8]>,
    allowed_measurements: &[[u8; SNP_MEASUREMENT_LEN]],
) -> Result<PrevalidatedReport, ProtocolError> {
    if report.len() < EXPECTED_REPORT_LEN {
        return Err(ProtocolError::WireProtocol(
            "SNP report shorter than the fixed 1184-byte ABI size (truncated)",
        ));
    }

    let version = u32::from_le_bytes(
        report[VERSION_OFFSET..VERSION_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if version < MIN_REPORT_VERSION {
        return Err(ProtocolError::WireProtocol(
            "SNP report version older than the assumed ABI layout (need v2+)",
        ));
    }

    let policy = u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());
    if policy & POLICY_DEBUG_BIT != 0 {
        return Err(ProtocolError::WireProtocol(
            "SNP guest policy has DEBUG enabled",
        ));
    }

    if let Some(pubkey) = expected_pq_pubkey {
        // Map snp_report's PqSigningUnavailable to WireProtocol — in a relying-party verifier the
        // failure is "malformed report", not "PQ signing unavailable".
        let echoed = report_data_from_report(report)
            .map_err(|_| ProtocolError::WireProtocol("malformed SNP report (report_data field)"))?;
        let expected = report_data_for_pubkey(pubkey);
        if echoed != expected {
            return Err(ProtocolError::WireProtocol(
                "report_data does not bind the expected pq_pubkey",
            ));
        }
    }

    let measurement = measurement_from_report(report)
        .map_err(|_| ProtocolError::WireProtocol("malformed SNP report (measurement field)"))?;
    if !allowed_measurements.iter().any(|m| *m == measurement) {
        return Err(ProtocolError::WireProtocol(
            "launch measurement not in allowlist",
        ));
    }

    Ok(PrevalidatedReport { measurement })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp_report::REPORT_DATA_OFFSET;

    const GOLDEN: &[u8] = include_bytes!("../testvectors/snp_report_golden_v5.bin");

    // Derived from the golden (its value is anchored by snp_report's own measurement test), so this
    // module tests prevalidate_report's logic without duplicating the measurement hex.
    fn golden_measurement() -> [u8; SNP_MEASUREMENT_LEN] {
        measurement_from_report(GOLDEN).unwrap()
    }

    #[test]
    fn golden_passes_allowlist_without_binding() {
        let v = prevalidate_report(GOLDEN, None, &[golden_measurement()]).unwrap();
        assert_eq!(v.measurement, golden_measurement());
    }

    #[test]
    fn rejects_measurement_not_in_allowlist() {
        let other = [0x11u8; SNP_MEASUREMENT_LEN];
        assert!(prevalidate_report(GOLDEN, None, &[other]).is_err());
    }

    #[test]
    fn rejects_empty_allowlist() {
        assert!(prevalidate_report(GOLDEN, None, &[]).is_err());
    }

    #[test]
    fn rejects_short_report() {
        // One byte short of the fixed 1184-byte report must be rejected as truncated.
        assert!(prevalidate_report(
            &GOLDEN[..EXPECTED_REPORT_LEN - 1],
            None,
            &[golden_measurement()]
        )
        .is_err());
    }

    #[test]
    fn binding_accepts_matching_pubkey_and_rejects_others() {
        let pubkey = b"reference-producer-pq-pubkey";
        // Patch a copy so report_data binds `pubkey`; keep the golden measurement.
        let mut report = GOLDEN.to_vec();
        let rd = report_data_for_pubkey(pubkey);
        report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + rd.len()].copy_from_slice(&rd);

        assert!(prevalidate_report(&report, Some(pubkey), &[golden_measurement()]).is_ok());
        assert!(
            prevalidate_report(&report, Some(b"a-different-key"), &[golden_measurement()]).is_err()
        );
    }

    #[test]
    fn rejects_debug_enabled_guest() {
        let mut report = GOLDEN.to_vec();
        let mut policy =
            u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());
        policy |= POLICY_DEBUG_BIT;
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());
        assert!(prevalidate_report(&report, None, &[golden_measurement()]).is_err());
    }

    #[test]
    fn rejects_pre_v2_version() {
        let mut report = GOLDEN.to_vec();
        report[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(prevalidate_report(&report, None, &[golden_measurement()]).is_err());
    }
}
