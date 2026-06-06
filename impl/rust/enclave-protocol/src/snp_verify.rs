//! Reference relying-party verifier for the 2d-hsm SEV-SNP attestation (TASK-1 AC#3/#12).
//!
//! Implements the structural + key-binding + allowlist + posture checks of
//! `backlog/docs/snp-attestation-verifier-policy.md`. This is **relying-party** code (BP /
//! on-chain consumer), **not** the enclave signing path — it lives behind the off-by-default
//! `snp-verify` feature so it is never compiled into the production enclave binary.
//!
//! Out of scope here (the relying party's remaining step, per the policy): verifying the report's
//! VCEK→ASK→ARK signature chain to the pinned AMD root. That needs ECDSA-P384 + X.509 + AMD KDS
//! and is intentionally kept out of this `#![forbid(unsafe_code)]` crate. A caller MUST still do
//! it; the checks here are necessary but not sufficient on their own.

use crate::snp_report::{
    measurement_from_report, report_data_for_pubkey, report_data_from_report, SNP_MEASUREMENT_LEN,
};
use crate::ProtocolError;

// SEV-SNP ATTESTATION_REPORT field offsets (ABI v2+; see AMD SEV-SNP ABI §7).
const VERSION_OFFSET: usize = 0x00; // u32 LE
const POLICY_OFFSET: usize = 0x08; // u64 LE guest policy
const MEASUREMENT_OFFSET: usize = 0x90;
const MIN_REPORT_LEN: usize = MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN;
// GUEST_POLICY.DEBUG is bit 19 — a debuggable guest is never acceptable for production.
const POLICY_DEBUG_BIT: u64 = 1 << 19;

/// Outcome of a successful structural verification.
#[derive(Debug, Clone)]
pub struct VerifiedReport {
    /// The 48-byte launch measurement that passed the allowlist.
    pub measurement: [u8; SNP_MEASUREMENT_LEN],
}

/// Verify the structural + binding + allowlist + posture parts of the attestation policy.
///
/// Checks, in order:
/// 1. report length + non-zero version (well-formed),
/// 2. guest policy `DEBUG` bit is **off**,
/// 3. when `expected_pq_pubkey` is `Some`, `report_data == SHA3-512("2d-hsm-snp-report-data-v1" ||
///    pq_pubkey)` (binds the producer key into the report),
/// 4. the launch `measurement` is in `allowed_measurements`.
///
/// Returns the verified measurement. **Does not** verify the VCEK signature / cert chain — the
/// caller must still do that against the pinned AMD root (see module docs).
pub fn verify_report(
    report: &[u8],
    expected_pq_pubkey: Option<&[u8]>,
    allowed_measurements: &[[u8; SNP_MEASUREMENT_LEN]],
) -> Result<VerifiedReport, ProtocolError> {
    if report.len() < MIN_REPORT_LEN {
        return Err(ProtocolError::WireProtocol(
            "SNP report shorter than ABI minimum",
        ));
    }

    let version = u32::from_le_bytes(report[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap());
    if version == 0 {
        return Err(ProtocolError::WireProtocol("SNP report version is 0"));
    }

    let policy = u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());
    if policy & POLICY_DEBUG_BIT != 0 {
        return Err(ProtocolError::WireProtocol(
            "SNP guest policy has DEBUG enabled",
        ));
    }

    if let Some(pubkey) = expected_pq_pubkey {
        let echoed = report_data_from_report(report)?;
        let expected = report_data_for_pubkey(pubkey);
        if echoed != expected {
            return Err(ProtocolError::WireProtocol(
                "report_data does not bind the expected pq_pubkey",
            ));
        }
    }

    let measurement = measurement_from_report(report)?;
    if !allowed_measurements.iter().any(|m| *m == measurement) {
        return Err(ProtocolError::WireProtocol(
            "launch measurement not in allowlist",
        ));
    }

    Ok(VerifiedReport { measurement })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &[u8] = include_bytes!("../testvectors/snp_report_golden_v5.bin");
    const GOLDEN_MEASUREMENT_HEX: &str = "3e39e33ab71f37ec9391fb285620dc5e50b67dd7cb59447726138596f9c502ed971ae0d095ea2ab3f93a8b8f6016b488";

    fn golden_measurement() -> [u8; SNP_MEASUREMENT_LEN] {
        hex::decode(GOLDEN_MEASUREMENT_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn golden_passes_allowlist_without_binding() {
        let v = verify_report(GOLDEN, None, &[golden_measurement()]).unwrap();
        assert_eq!(v.measurement, golden_measurement());
    }

    #[test]
    fn rejects_measurement_not_in_allowlist() {
        let other = [0x11u8; SNP_MEASUREMENT_LEN];
        assert!(verify_report(GOLDEN, None, &[other]).is_err());
    }

    #[test]
    fn rejects_empty_allowlist() {
        assert!(verify_report(GOLDEN, None, &[]).is_err());
    }

    #[test]
    fn rejects_short_report() {
        assert!(verify_report(&GOLDEN[..MIN_REPORT_LEN - 1], None, &[golden_measurement()]).is_err());
    }

    #[test]
    fn binding_accepts_matching_pubkey_and_rejects_others() {
        let pubkey = b"reference-producer-pq-pubkey";
        // Patch a copy so report_data binds `pubkey`; keep the golden measurement.
        let mut report = GOLDEN.to_vec();
        let rd = report_data_for_pubkey(pubkey);
        report[0x50..0x50 + rd.len()].copy_from_slice(&rd);

        // Right key binds; wrong key is rejected.
        assert!(verify_report(&report, Some(pubkey), &[golden_measurement()]).is_ok());
        assert!(verify_report(&report, Some(b"a-different-key"), &[golden_measurement()]).is_err());
    }

    #[test]
    fn rejects_debug_enabled_guest() {
        let mut report = GOLDEN.to_vec();
        let mut policy =
            u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());
        policy |= POLICY_DEBUG_BIT;
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());
        assert!(verify_report(&report, None, &[golden_measurement()]).is_err());
    }
}
