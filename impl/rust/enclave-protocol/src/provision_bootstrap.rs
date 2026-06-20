#![cfg_attr(not(test), allow(dead_code))]

//! Runtime driver for the one-shot provisioning bootstrap ceremony (TASK-25, runtime wiring).
//!
//! Connects [`crate::agent_provision::ProvisionSession`] to a real transport stream (AF_VSOCK on
//! Linux, or any `Read`+`Write` for testing) + a report-producer seam (SNP configfs-tsm in
//! production, mock on non-SNP hosts). The ceremony:
//!
//! ```text
//! M1 PROV_CHALLENGE ──►  on_m1 → mint N_e + report_data
//!                  ◄──  M2 PROV_ATTEST (N_e + report)
//! M3 PROV_CONFIG   ──►  on_m3 → verify + mint scope_id + seal
//!                  ◄──  M4 PROV_SEALED (sealed_blob)
//! ```
//!
//! On success, returns `(ProvisionConfig, sealed_blob)` — the boot path persists the blob to the
//! keystore path, then unseals it via the existing `unseal_agent_keystore_at_boot` path.
//!
//! **Platform scope.** The core [`run_provisioning_ceremony`] is pure (any `Read`+`Write` stream);
//! the vsock binding ([`vsock::run_vsock_provisioning_bootstrap`]) is Linux + `vsock-transport` gated;
//! the SNP report producer is behind a trait seam so it's testable without SNP hardware.

use crate::agent_provision::{
    self, decode_envelope, decode_m1, encode_envelope, encode_m2, encode_m4, ProvisionError,
    ProvisionSession, MSG_M1_CHALLENGE, MSG_M2_ATTEST, MSG_M4_SEALED,
};
use crate::read_framed_message_with_idle_deadline;
use crate::write_framed_message;

use ed25519_dalek::VerifyingKey;
use std::io::{Read, Write};
use std::time::Duration;

/// A seam for producing the M2 SNP attestation report (the 1184-byte VCEK-signed structure whose
/// `REPORT_DATA` field MUST equal `compute_report_data(N_p, N_e)`). Production: configfs-tsm fetch
/// via `snp_report`; tests: a mock returning a fixed report (the enclave does NOT verify the report —
/// the provisioner does; the enclave only emits it in M2 + binds its SHA3-256 into the transcript).
pub trait ProvisionReportProducer {
    /// Fetch the raw SNP report bytes (exactly `SNP_REPORT_LEN` = 1184) whose `REPORT_DATA` ==
    /// `report_data`. Fail-closed on any error (no report ⇒ no provisioning).
    fn fetch_report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, ProvisionError>;
}

/// Run the provisioning ceremony (M1→M2→M3→M4) over a connected stream. The stream is the AF_VSOCK
/// connection (or any `Read`+`Write` for testing). Messages are length-prefixed (the standard
/// `read_framed_message`/`write_framed_message` wrapping the provision envelope bytes).
///
/// **`pinned_root`** = the compiled-in operator CA root (verifies the provisioner cert).
/// **`seal_root` + `measurement`** = the keystore-seal inputs (MUST match the measurement in the SNP
/// report — the driver contract, slice iv). **`report_producer`** = the SNP report fetch seam.
///
/// **`idle_timeout`** = the per-read deadline (slowloris defense; the bootstrap is one-shot, so a
/// generous timeout is fine). Returns `(ProvisionConfig, sealed_blob)` on success.
/// Prepend a u32 BE length to a provision envelope + write via `write_framed_message` (the standard
/// length-prefixed framing wrapping the provision protocol's own envelope).
fn write_provision_envelope<W: Write>(writer: &mut W, envelope: &[u8]) -> Result<(), ProvisionError> {
    let mut frame = Vec::with_capacity(4 + envelope.len());
    frame.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    frame.extend_from_slice(envelope);
    write_framed_message(writer, &frame).map_err(|_| ProvisionError::Malformed)
}

pub fn run_provisioning_ceremony<S: Read + Write>(
    stream: &mut S,
    pinned_root: &VerifyingKey,
    seal_root: &[u8; 32],
    measurement: &[u8],
    report_producer: &dyn ProvisionReportProducer,
    idle_timeout: Duration,
) -> Result<(agent_provision::ProvisionConfig, Vec<u8>), ProvisionError> {
    let mut session = ProvisionSession::new(*pinned_root, *seal_root, measurement.to_vec());

    // ── M1: read PROV_CHALLENGE ───────────────────────────────────────────────
    let deadline = Some(std::time::Instant::now() + idle_timeout);
    let m1_frame = read_framed_message_with_idle_deadline(stream, deadline)
        .map_err(|_| ProvisionError::Malformed)?;
    // read_framed_message returns [u32 len][body]; strip the 4-byte prefix for the envelope.
    let (msg_type, m1_payload) = decode_envelope(&m1_frame[4..])?;
    if msg_type != MSG_M1_CHALLENGE {
        return Err(ProvisionError::Malformed);
    }
    let m1 = decode_m1(m1_payload)?;

    // on_m1: record N_p, mint N_e, compute report_data.
    let (n_e, report_data) = session.on_m1(m1.n_p)?;

    // Fetch the SNP report (embedding report_data in REPORT_DATA).
    let report = report_producer.fetch_report(&report_data)?;

    // ── M2: emit PROV_ATTEST (N_e + report) ───────────────────────────────────
    let m2_env = encode_envelope(MSG_M2_ATTEST, &encode_m2(&n_e, &report));
    write_provision_envelope(stream, &m2_env)?;

    // ── M3: read PROV_CONFIG ──────────────────────────────────────────────────
    let deadline = Some(std::time::Instant::now() + idle_timeout);
    let m3_frame = read_framed_message_with_idle_deadline(stream, deadline)
        .map_err(|_| ProvisionError::Malformed)?;
    // Strip the u32 prefix; pass the provision envelope to on_m3 (→ verify_m3_in_order).
    let (config, sealed_blob) = session.on_m3(&m3_frame[4..], &report)?;

    // ── M4: emit PROV_SEALED ──────────────────────────────────────────────────
    let m4_env = encode_envelope(MSG_M4_SEALED, &encode_m4(&sealed_blob));
    write_provision_envelope(stream, &m4_env)?;

    Ok((config, sealed_blob))
}

// ── vsock binding (Linux + vsock-transport) ─────────────────────────────────────

#[cfg(all(target_os = "linux", feature = "vsock-transport", feature = "agent-gateway"))]
pub mod vsock {
    use super::*;
    use crate::vsock_listen;

    /// Bind a one-shot AF_VSOCK listener on `cid:port`, accept ONE connection, run the provisioning
    /// ceremony, tear down the listener, and return `(ProvisionConfig, sealed_blob)`.
    ///
    /// **Q5 (25-1 design):** the provisioning listener is on a SEPARATE port from the runtime serve
    /// loop, and accepts exactly ONE connection (one-shot). On success OR failure, the listener is
    /// torn down — the host must re-connect + re-M1 for any retry.
    pub fn run_vsock_provisioning_bootstrap(
        cid: u32,
        port: u32,
        pinned_root: &VerifyingKey,
        seal_root: &[u8; 32],
        measurement: &[u8],
        report_producer: &dyn ProvisionReportProducer,
        idle_timeout: Duration,
    ) -> Result<(agent_provision::ProvisionConfig, Vec<u8>), ProvisionError> {
        let listener = vsock_listen::bind_vsock_listener(cid, port)
            .map_err(|_| ProvisionError::Malformed)?;
        let (mut stream, _peer_addr) = listener
            .accept()
            .map_err(|_| ProvisionError::Malformed)?;
        run_provisioning_ceremony(
            &mut stream,
            pinned_root,
            seal_root,
            measurement,
            report_producer,
            idle_timeout,
        )
    }
}
