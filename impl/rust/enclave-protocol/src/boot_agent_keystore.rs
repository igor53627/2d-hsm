//! Agent-keystore unseal-at-boot loader (TASK-7.7 5b-2d) — the agent twin of [`crate::boot_lab_pq_seal`].
//!
//! Sources the sealed `pq-agent-keystore-v1` blob + the agent provisioning root at boot, then unseals the
//! blob into a [`KeystoreBody`] via the shared [`crate::agent_keystore::unseal_body`] core — fail-closed at
//! every edge. This slice ships ONLY the lab/integration FILE source (behind `lab-agent-keystore-from-file`,
//! release-banned in `lib.rs`); the production host-vsock install/restore source is a deferred slice and the
//! non-lab arms are documented fail-closed stubs.
//!
//! ## What this is — a PURE source→unseal→return seam
//! [`unseal_agent_keystore_at_boot`] reads the blob + measurement, resolves the root, calls `unseal_body`,
//! and returns `(KeystoreBody, measurement)`. It DOES NOT install (the 5b-2c bin owns
//! [`crate::agent_dispatch::install_agent_keystore`] and the borrow-then-move ordering) and DOES NOT set the
//! root ([`boot_configure_agent_seal_root`] does, BEFORE the seam). So root-before-unseal,
//! borrow-before-move, and install-false-is-fatal cannot be wrong IN THIS SLICE — they live in 5b-2c, only
//! PINNED by tests here.
//!
//! ## Security boundary — structural invariant ONLY, NEVER the freshness decision
//! The seam enforces the STRUCTURAL/seal invariant by reusing `unseal_body` VERBATIM (length → magic
//! `2DAGTKS\0` → `format_version == 4` BEFORE decrypt → measurement-binding → strict whole-buffer CBOR →
//! `validate()` incl. `structural_version != 0`). It MUST NOT judge freshness/anti-rollback: a
//! rolled-back-but-structurally-valid blob UNSEALS fine (the seam does not judge freshness); the boot
//! handshake's `reconcile` (NOT this module) — which runs on the returned `&body` BEFORE the keystore is
//! installed (the canonical install-after-`Ready` order; §8 5b-2c) — compares
//! `freshness_epoch`/`structural_version`/marks against the anchor and fails closed for a stale blob, so a
//! stale keystore is NEVER installed/served. NO double-judging, NO re-seal-forward (AdoptForward stays
//! strictly 5b-2e). This
//! is enforced STRUCTURALLY: the use-list below imports NO `agent_anchor` / `agent_boot` / `reconcile` /
//! `marks` / `AdoptForward` / `AnchorState` symbol (grep-checkable).
//!
//! ## Guard classification
//! - COMPILE-TIME: the lab file source is release-banned (`lib.rs` `compile_error!`); the wildcard-free
//!   [`map_keystore_error`] makes a future 18th `KeystoreError` variant a build error, not a silent fold.
//! - RUNTIME (fail-closed): missing env / unreadable file / oversize blob / empty measurement / unset root
//!   (production) / every `KeystoreError` → a `ProtocolError::PqSigningUnavailable` with a distinct
//!   `agent keystore:`-prefixed label.
//! - TEST-ONLY: the move-vs-borrow + install-once contracts (5b-2c's) and the root-before-unseal ordering.

use crate::ProtocolError;

/// The lab/placeholder enclave measurement the seam binds when no measurement file is supplied. DISTINCT
/// from the producer's [`crate::PRODUCTION_PLACEHOLDER_MEASUREMENT`] (`b"enclave-measurement-placeholder"`)
/// so a dual-role lab cannot accidentally cross-bind a producer-sealed blob to an agent measurement. The
/// committed genesis golden vector is sealed under THIS exact value, single-sourced here so the generator
/// and the fallback cannot drift. The real attested 48-byte SNP launch measurement is a DEFERRED production
/// obligation (the production seam derives it from the configfs-tsm/SNP report; never a placeholder).
pub const AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT: &[u8] =
    b"agent-keystore-measurement-placeholder";

/// Configure the agent provisioning root once at boot, BEFORE [`unseal_agent_keystore_at_boot`].
///
/// The agent twin of the `ml-dsa-65`-only [`crate::platform_provisioning_boot::boot_configure_pq_seal_v1_platform_root`]
/// (the agent build gets neither it nor `platform-provisioning-from-file`). Derives a 32-byte root then
/// installs it via the SHARED [`crate::seal_root::set_pq_seal_v1_provisioning_root`] (compiled under
/// `any(ml-dsa-65, agent-gateway)`; install-once). Sharing the root mechanism does NOT weaken
/// producer↔agent isolation — they derive AEAD keys via distinct, domain-separated KDFs (see `seal_root`).
///
/// LAB: reads 32 raw bytes from `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE`. PRODUCTION: a documented fail-closed stub
/// (integrate the platform hook, or enable `lab-agent-keystore-from-file` for labs).
pub fn boot_configure_agent_seal_root() -> Result<(), ProtocolError> {
    let root = derive_agent_provisioning_root()?;
    crate::seal_root::set_pq_seal_v1_provisioning_root(root)
}

#[cfg(feature = "lab-agent-keystore-from-file")]
fn derive_agent_provisioning_root() -> Result<[u8; 32], ProtocolError> {
    use crate::env_config::{
        var_twod, LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE, TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
    };
    let path = var_twod(TWOD_HSM_PQ_SEAL_V1_ROOT_FILE, LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE).map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: TWOD_HSM_PQ_SEAL_V1_ROOT_FILE not set (expected path to a 32-byte provisioning root)",
        )
    })?;
    // CAPPED at 32+1: a 33rd byte (or /dev/zero) makes try_into::<[u8;32]> fail without OOM.
    let bytes = crate::boot_input::read_boot_file_capped(
        path.as_ref(),
        32,
        "agent keystore: failed to read TWOD_HSM_PQ_SEAL_V1_ROOT_FILE provisioning root",
    )?;
    bytes.try_into().map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: provisioning root file must be exactly 32 bytes",
        )
    })
}

#[cfg(all(
    feature = "platform-root-from-boot-file",
    not(feature = "lab-agent-keystore-from-file")
))]
fn derive_agent_provisioning_root() -> Result<[u8; 32], ProtocolError> {
    // Production: read from the FIXED path written by `snp-derive-root --out` at boot.
    // NOT a host-settable env var — the host cannot redirect to a known root.
    let bytes = crate::boot_input::read_boot_file_capped(
        std::path::Path::new("/run/twod-hsm/pq-seal-root.bin"),
        32,
        "agent keystore: failed to read /run/twod-hsm/pq-seal-root.bin (snp-derive-root oneshot)",
    )?;
    bytes.try_into().map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: provisioning root file must be exactly 32 bytes",
        )
    })
}

#[cfg(not(any(
    feature = "lab-agent-keystore-from-file",
    feature = "platform-root-from-boot-file"
)))]
fn derive_agent_provisioning_root() -> Result<[u8; 32], ProtocolError> {
    Err(ProtocolError::PqSigningUnavailable(
        "agent keystore: platform seal root hook not configured (integrate vTPM/SNP VMPL/Nitro \
         set_pq_seal_v1_provisioning_root at boot, or enable lab-agent-keystore-from-file for labs)",
    ))
}

/// Source + unseal the sealed agent keystore at boot, returning the unsealed [`KeystoreBody`] AND the
/// enclave measurement it was sealed under (5b-2c hands the measurement to `install_agent_keystore`, which
/// retains it for privileged re-seal). PURE: does NOT install and does NOT set the root.
///
/// Order (every edge fail-closed): (1) measurement (reject empty before unseal); (2) blob (RAW read,
/// size-capped to [`crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE`] so it stays re-installable); (3) root
/// (the caller ran [`boot_configure_agent_seal_root`] first); (4) [`crate::agent_keystore::unseal_body`]
/// VERBATIM; (5) map any `KeystoreError` to a coarse `agent keystore:`-labelled `PqSigningUnavailable`.
///
/// [`KeystoreBody`]: crate::agent_keystore::KeystoreBody
pub fn unseal_agent_keystore_at_boot(
) -> Result<(crate::agent_keystore::KeystoreBody, Vec<u8>), ProtocolError> {
    let measurement = agent_boot_measurement()?;
    let blob = agent_sealed_keystore_blob()?;
    // resolve_provisioning_root fails closed in a real build if no root was set; under cfg(test) /
    // reference-seal-v1-root it falls back to the committed reference root (a testing convenience the
    // negative ordering test pins via the production-stub path, not via a naive unset-root assertion).
    // Re-label its error so a missing-root failure stays `agent keystore:`-prefixed (operator-
    // distinguishable from a producer-signer failure) instead of leaking the shared producer message.
    let root = crate::seal_root::resolve_provisioning_root().map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: provisioning root not configured (run boot_configure_agent_seal_root at boot)",
        )
    })?;
    let body = crate::agent_keystore::unseal_body(&blob, &root, &measurement)
        .map_err(map_keystore_error)?;
    Ok((body, measurement))
}

/// Source the sealed agent keystore blob. LAB: `TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE`, read RAW (a sealed
/// binary blob's trailing `0x0a`/`0x0d` is significant — NEVER newline-trim), size-capped before unseal.
#[cfg(feature = "lab-agent-keystore-from-file")]
fn agent_sealed_keystore_blob() -> Result<Vec<u8>, ProtocolError> {
    use crate::env_config::{
        var_twod, LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE, TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
    };
    // Try the file path FIRST; if not found (first boot), fall back to the provisioning ceremony
    // (only available on Linux + vsock-transport + agent-gateway — otherwise fail closed).
    match var_twod(
        TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
        LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE,
    ) {
        Ok(path) => {
            // Check existence FIRST: read_boot_file_capped maps File::open errors to
            // PqSigningUnavailable (not Io), so a missing file wouldn't be distinguishable from
            // a read error. try_exists distinguishes Ok(false) = missing (first boot) from Err =
            // inaccessible (fail closed). Path::exists returns false on BOTH → would mis-route an
            // inaccessible path to provisioning.
            match std::path::Path::new(&path).try_exists() {
                Ok(false) => return agent_sealed_keystore_blob_from_provisioning_or_fail(),
                Ok(true) => {} // file exists → fall through to read
                Err(_) => {
                    return Err(ProtocolError::PqSigningUnavailable(
                        "agent keystore: cannot access TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE path",
                    ));
                }
            }
            // File exists → capped read.
            let blob = crate::boot_input::read_boot_file_capped(
                path.as_ref(),
                crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE,
                "agent keystore: failed to read TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE",
            )?;
            if blob.len() > crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE {
                return Err(ProtocolError::PqSigningUnavailable(
                    "agent keystore: sealed blob exceeds MAX_KEYSTORE_BLOB_SIZE",
                ));
            }
            Ok(blob)
        }
        Err(_) => {
            // Env var not set → first boot → provisioning (or fail closed).
            agent_sealed_keystore_blob_from_provisioning_or_fail()
        }
    }
}

/// Try the vsock provisioning ceremony (Linux + vsock-transport + agent-gateway only); otherwise
/// fail closed with a clear message.
fn agent_sealed_keystore_blob_from_provisioning_or_fail() -> Result<Vec<u8>, ProtocolError> {
    // Only the full lab + Linux + vsock + agent-gateway feature set has the provisioning ceremony.
    // Everything else (macOS CI, non-vsock, non-lab production) fails closed.
    #[cfg(all(
        target_os = "linux",
        feature = "vsock-transport",
        feature = "agent-gateway",
        feature = "lab-agent-keystore-from-file"
    ))]
    {
        agent_sealed_keystore_blob_from_provisioning()
    }
    #[cfg(not(all(
        target_os = "linux",
        feature = "vsock-transport",
        feature = "agent-gateway",
        feature = "lab-agent-keystore-from-file"
    )))]
    {
        Err(ProtocolError::PqSigningUnavailable(
            "agent keystore: no sealed keystore file and vsock provisioning unavailable \
             (needs Linux + vsock-transport + lab-agent-keystore-from-file)",
        ))
    }
}

// TASK-25 boot integration: the provisioning ceremony as the keystore source. LAB-GATED (the
// LabReportProducer returns a mock all-zero report — production needs the real configfs-tsm fetch,
// which is a TODO tracked in the function body). This means: on a LAB build (lab-agent-keystore-from-file
// + linux + vsock-transport + agent-gateway), the lab file path is tried FIRST; if not found, the
// provisioning ceremony runs. On a non-lab production build: the provisioning path does NOT compile
// (the non-lab `agent_sealed_keystore_blob` fails closed — production needs the real SNP report +
// compiled-in CA root, neither of which is wired yet).
#[cfg(all(
    feature = "lab-agent-keystore-from-file",
    target_os = "linux",
    feature = "vsock-transport",
    feature = "agent-gateway"
))]
fn agent_sealed_keystore_blob_from_provisioning() -> Result<Vec<u8>, ProtocolError> {
    use crate::env_config::{
        var_twod, LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE, LEGACY_HSM_OPERATOR_CA_ROOT_HEX,
        TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, TWOD_HSM_OPERATOR_CA_ROOT_HEX,
    };
    use crate::provision_bootstrap::ProvisionReportProducer;
    use std::io::Write as _;

    // Resolve the pinned operator CA root pubkey (hex → 32 bytes). LAB/DEV: from env var.
    // PRODUCTION: compiled in (a future build-time pin; this env path is for lab/dev testing).
    let ca_hex = var_twod(TWOD_HSM_OPERATOR_CA_ROOT_HEX, LEGACY_HSM_OPERATOR_CA_ROOT_HEX)
        .map_err(|_| ProtocolError::PqSigningUnavailable(
            "agent keystore: TWOD_HSM_OPERATOR_CA_ROOT_HEX not set (the pinned operator CA root pubkey)"
        ))?;
    // Decode hex → 32 bytes WITHOUT the `hex` crate (not pulled by agent-gateway in production).
    let ca_hex_trimmed = ca_hex.trim();
    if ca_hex_trimmed.len() != 64 {
        return Err(ProtocolError::PqSigningUnavailable(
            "agent keystore: TWOD_HSM_OPERATOR_CA_ROOT_HEX must be exactly 64 hex chars (32 bytes)",
        ));
    }
    let mut ca_arr = [0u8; 32];
    for (i, byte) in ca_arr.iter_mut().enumerate() {
        let pair = &ca_hex_trimmed[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            ProtocolError::PqSigningUnavailable(
                "agent keystore: TWOD_HSM_OPERATOR_CA_ROOT_HEX is not valid hex",
            )
        })?;
    }
    let pinned_root = ed25519_dalek::VerifyingKey::from_bytes(&ca_arr).map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: TWOD_HSM_OPERATOR_CA_ROOT_HEX is not a valid Ed25519 public key",
        )
    })?;

    // Resolve the provisioning vsock port (distinct from serve 5000 + relay 5001 — Q5).
    let prov_port = crate::vsock_addr::provisioning_vsock_port_from_env().map_err(|msg| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: invalid provisioning vsock port config (see prior log line)",
        )
    })?;

    // Resolve the seal root (set at step A) + measurement (the existing source).
    let seal_root = crate::seal_root::resolve_provisioning_root().map_err(|_| {
        ProtocolError::PqSigningUnavailable(
            "agent keystore: provisioning root not configured for the sealing ceremony",
        )
    })?;
    let measurement = agent_boot_measurement()?;

    // The SNP report producer: on a real SNP guest, configfs-tsm fetch. On aya (non-SNP),
    // a mock/stub is used — the report is opaque to the enclave (it only emits it in M2 + binds
    // its SHA3-256). For now, use the existing snp_report module if available; else a placeholder.
    // TODO(TASK-25): wire the real SNP report fetch (configfs-tsm) behind a trait impl; for the
    // lab/dev path on aya, a mock report is acceptable (the PROVISIONER verifies the report, not
    // the enclave).
    struct LabReportProducer;
    impl ProvisionReportProducer for LabReportProducer {
        fn fetch_report(
            &self,
            _report_data: &[u8; 64],
        ) -> Result<Vec<u8>, crate::agent_provision::ProvisionError> {
            // A fixed mock 1184-byte report. On a real SNP guest, this would call
            // snp_report::fetch_measurement_and_report with the report_data embedded in REPORT_DATA.
            Ok(vec![0u8; crate::agent_provision::SNP_REPORT_LEN])
        }
    }

    let idle_timeout = std::time::Duration::from_secs(60);

    // Run the one-shot ceremony (binds listener, accepts ONE connection, M1→M2→M3→M4, tears down).
    let (_config, sealed_blob) =
        crate::provision_bootstrap::vsock::run_vsock_provisioning_bootstrap(
            crate::vsock_addr::DEFAULT_VSOCK_CID,
            prov_port,
            &pinned_root,
            &seal_root,
            &measurement,
            &LabReportProducer,
            idle_timeout,
        )
        .map_err(|e| {
            ProtocolError::PqSigningUnavailable("agent keystore: provisioning ceremony failed")
        })?;

    // Persist the sealed blob to the keystore file path (the HOST would do this in a real TEE;
    // in the lab/dev host process, we write it directly so subsequent boots unseal it).
    if let Ok(path) = var_twod(
        TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
        LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE,
    ) {
        if let Ok(mut file) = std::fs::File::create(&path) {
            let _ = file.write_all(&sealed_blob);
        }
    }

    Ok(sealed_blob)
}

// Non-lab: fail closed. Covers BOTH non-vsock (macOS CI) AND vsock-but-no-lab (production is not
// ready — needs real SNP report + compiled-in CA root, both TODO). The provisioning ceremony is
// lab-gated; production wiring is a future TASK-25 slice.
#[cfg(not(feature = "lab-agent-keystore-from-file"))]
fn agent_sealed_keystore_blob() -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::PqSigningUnavailable(
        "agent keystore: sealed source not configured. LAB: set TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE \
         or enable lab-agent-keystore-from-file + vsock-transport for the provisioning ceremony. \
         PRODUCTION: the attested host-vsock install channel + SNP report fetch are not yet wired."
    ))
}

/// Source the enclave measurement. LAB: optional `TWOD_HSM_ENCLAVE_MEASUREMENT_FILE` (TEXT, newline-trimmed)
/// override, else the [`AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT`]. The measurement MUST equal the seal
/// measurement or `unseal_body` returns `MeasurementMismatch`; empty is rejected before unseal.
#[cfg(feature = "lab-agent-keystore-from-file")]
fn agent_boot_measurement() -> Result<Vec<u8>, ProtocolError> {
    use crate::env_config::{
        var_twod, LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE, TWOD_HSM_ENCLAVE_MEASUREMENT_FILE,
    };
    // A measurement is tiny (a 48-byte SNP launch measurement or a short placeholder); cap the read so a
    // /dev/zero / oversize file can't OOM the boot path, then trim trailing newlines (text manifest).
    const AGENT_MEASUREMENT_FILE_MAX_BYTES: usize = 4096;
    let measurement = match var_twod(
        TWOD_HSM_ENCLAVE_MEASUREMENT_FILE,
        LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE,
    ) {
        Ok(path) => {
            // CAPPED read (not read_boot_file_trim_trailing_newlines which uses uncapped std::fs::read):
            // a /dev/zero or oversize measurement file can't OOM the boot path. Trim locally.
            let mut bytes = crate::boot_input::read_boot_file_capped(
                path.as_ref(),
                AGENT_MEASUREMENT_FILE_MAX_BYTES,
                "agent keystore: failed to read TWOD_HSM_ENCLAVE_MEASUREMENT_FILE",
            )?;
            if bytes.len() > AGENT_MEASUREMENT_FILE_MAX_BYTES {
                return Err(ProtocolError::PqSigningUnavailable(
                    "agent keystore: enclave measurement file exceeds 4 KiB",
                ));
            }
            while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                bytes.pop();
            }
            bytes
        }
        Err(_) => AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT.to_vec(),
    };
    if measurement.is_empty() {
        return Err(ProtocolError::PqSigningUnavailable(
            "agent keystore: enclave measurement must be non-empty",
        ));
    }
    Ok(measurement)
}

#[cfg(not(feature = "lab-agent-keystore-from-file"))]
fn agent_boot_measurement() -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::PqSigningUnavailable(
        "agent keystore: enclave measurement source not configured (production derives the attested \
         48-byte SNP launch measurement; enable lab-agent-keystore-from-file for labs)",
    ))
}

/// Map every [`crate::agent_keystore::KeystoreError`] to a coarse, oracle-free `agent keystore:`-prefixed
/// [`ProtocolError::PqSigningUnavailable`]. WILDCARD-FREE (no `_ =>`) so a future 18th variant is a COMPILE
/// error, never a silent fail-open fold. Distinct labels for the known-risk cases (measurement mismatch,
/// unsupported version, structural_version, empty measurement) keep them operator-diagnosable without
/// leaking offsets/oracle detail; the labels survive into the wire reason (`protocol_error_to_wire_body`
/// code 2), reason-distinguishable from a producer-signer failure.
fn map_keystore_error(e: crate::agent_keystore::KeystoreError) -> ProtocolError {
    use crate::agent_keystore::KeystoreError as K;
    let label: &'static str = match e {
        K::EmptyMeasurement => "agent keystore: empty enclave measurement",
        K::TooShort | K::BadMagic => "agent keystore: malformed sealed blob",
        K::UnsupportedVersion => "agent keystore: unsupported sealed-keystore version",
        K::MeasurementMismatch => {
            "agent keystore: sealed measurement does not match enclave measurement"
        }
        K::AeadKey | K::Decrypt => "agent keystore: sealed blob authentication failed",
        K::Encrypt | K::Csprng => "agent keystore: seal-path crypto failure",
        K::InvalidStructuralVersion => "agent keystore: invalid structural_version (must be >= 1)",
        K::Cbor
        | K::InvalidEnvironmentId
        | K::InvalidScopeId
        | K::CapacityExceeded
        | K::CounterRegression
        | K::InvalidFieldLength
        | K::DuplicateKeyRef
        | K::DuplicateCounterTuple
        | K::AuditSeqDisorder
        | K::BlobTooLarge => "agent keystore: invalid keystore body",
        // A monotonic-counter overflow is a runtime capacity condition (epoch/structural at u64::MAX),
        // NOT structural body corruption — a distinct label so incident response looks at the counter,
        // not a malformed blob. (Unreachable via the boot UNSEAL path, which performs no bump — present
        // for match-exhaustiveness; the live surface is the 6-4 per-op commit dispatch mapping.)
        K::MonotonicOverflow => "agent keystore: monotonic counter overflow",
        // Audit-ring backpressure is a runtime capacity condition (un-exported records would be overwritten),
        // raised only by the per-op `record_audit` write path — NOT reachable via this boot UNSEAL path (no
        // append at boot); present for match-exhaustiveness. The live surface is the 4b/4c privileged-op
        // dispatch mapping (→ SealFailed/0x46).
        K::AuditBackpressure => "agent keystore: audit-ring backpressure",
    };
    ProtocolError::PqSigningUnavailable(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{
        seal_keystore_with_nonce, unseal_body, AuditRing, FaucetState, KeystoreBody,
        KeystoreConfig, MAX_KEYSTORE_BLOB_SIZE,
    };
    use crate::env_config::{
        LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE, LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE,
        LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE, TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
        TWOD_HSM_ENCLAVE_MEASUREMENT_FILE, TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
    };

    // The committed reference provisioning root — the genesis golden is sealed under it so a cfg(test)
    // unit run (resolve_provisioning_root's fallback returns this) unseals with NO root file, and the
    // root-step / integration tests point the root file at these same bytes.
    const GOLDEN_AGENT_ROOT: &[u8; 32] =
        include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
    /// Fixed nonce → byte-stable genesis golden blob (the only randomness in the seal).
    const GOLDEN_AGENT_NONCE: [u8; 24] = [0x5d; 24];

    /// Acquire the CRATE-WIDE agent process-globals lock (`lock_and_reset_agent_process_globals`) so this
    /// loader's tests serialize with — and reset the same INSTALLED_KEYSTORE / binding / challenge globals
    /// as — every other Agent Gateway test (agent_dispatch / agent_boot / quote), rather than racing them
    /// under a private lock. It does NOT cover the seal-root global or these env vars, so add those here.
    struct BootAgentTestGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl BootAgentTestGuard {
        fn acquire() -> Self {
            let g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
            clear_seal_root_and_env();
            BootAgentTestGuard(g)
        }
    }
    impl Drop for BootAgentTestGuard {
        fn drop(&mut self) {
            clear_seal_root_and_env();
        }
    }
    fn clear_seal_root_and_env() {
        for k in [
            TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE,
            LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE,
            TWOD_HSM_ENCLAVE_MEASUREMENT_FILE,
            LEGACY_HSM_ENCLAVE_MEASUREMENT_FILE,
            TWOD_HSM_PQ_SEAL_V1_ROOT_FILE,
            LEGACY_HSM_PQ_SEAL_V1_ROOT_FILE,
        ] {
            std::env::remove_var(k);
        }
        crate::seal_root::reset_pq_seal_v1_provisioning_root_for_tests();
    }

    /// A minimal valid v4 GENESIS keystore body: structural_version=1 (>=1, never 0),
    /// strict_recovery_counter=0, no entries, no counters, zeroed faucet, empty audit. All required fields
    /// present (no serde default — a body missing structural_version/strict_recovery_counter fails decode).
    fn genesis_body() -> KeystoreBody {
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "testnet".to_string(),
                admin_authority_pk: [0xa1; 32],
                recovery_authority_pk: [0xa2; 32],
                backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
                monotonic_treasury_config_version: 0,
                authority_epoch: 0,
                anchor_root: [0xa3; 32],
                enclave_scope_id: [0xe1; 32],
                fleet_scope_id: [0xf1; 32],
            },
            entries: vec![],
            counters: vec![],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 0,
                max_effective_gas_fee_rate: 0,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
                cumulative_signing_budget: [0; 32],
            },
            audit: AuditRing {
                records: vec![],
                capacity: 256,
                last_exported_seq: 0,
                next_seq: 1,
            },
            freshness_epoch: 1,
            structural_version: 1,
            strict_recovery_counter: 0,
        }
    }

    /// Deterministic CBOR of `body` — exactly what `seal_body` encodes internally, so `unseal_body`
    /// round-trips a blob sealed from this.
    fn cbor_of(body: &KeystoreBody) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(body, &mut buf).expect("genesis body encodes");
        buf
    }

    /// The byte-stable genesis golden blob: fixed root + placeholder measurement + fixed nonce.
    fn genesis_sealed_blob() -> Vec<u8> {
        seal_keystore_with_nonce(
            &cbor_of(&genesis_body()),
            GOLDEN_AGENT_ROOT,
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
            &GOLDEN_AGENT_NONCE,
        )
        .expect("genesis seals")
    }

    fn write_blob(blob: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent_keystore.sealed.bin");
        std::fs::write(&path, blob).unwrap();
        (dir, path)
    }

    // ---- lab-source seam tests (the file source compiles only under the lab feature) ----

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_happy_path_in_process() {
        let _g = BootAgentTestGuard::acquire();
        let (_dir, path) = write_blob(&genesis_sealed_blob());
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        // No measurement file → placeholder; no root set → cfg(test) reference-root fallback == GOLDEN root.
        let (body, meas) = unseal_agent_keystore_at_boot().expect("genesis unseals");
        assert_eq!(body, genesis_body());
        assert_eq!(meas, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT);
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_missing_env_fails_closed() {
        let _g = BootAgentTestGuard::acquire();
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        match err {
            ProtocolError::PqSigningUnavailable(s) => {
                assert!(
                    s.contains("TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE"),
                    "names the var: {s}"
                );
            }
            other => panic!("expected PqSigningUnavailable, got {other:?}"),
        }
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_legacy_alias_resolves() {
        let _g = BootAgentTestGuard::acquire();
        let (_dir, path) = write_blob(&genesis_sealed_blob());
        std::env::set_var(LEGACY_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        let (body, _) = unseal_agent_keystore_at_boot().expect("legacy alias resolves identically");
        assert_eq!(body, genesis_body());
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_measurement_mismatch_fails_closed() {
        let _g = BootAgentTestGuard::acquire();
        // Seal under a DIFFERENT measurement than the seam binds (placeholder) → MeasurementMismatch.
        let blob = seal_keystore_with_nonce(
            &cbor_of(&genesis_body()),
            GOLDEN_AGENT_ROOT,
            b"a-different-measurement",
            &GOLDEN_AGENT_NONCE,
        )
        .unwrap();
        let (_dir, path) = write_blob(&blob);
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(err, ProtocolError::PqSigningUnavailable(s) if s.contains("does not match")),
            "measurement mismatch label: {err:?}"
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_empty_measurement_fails_closed() {
        let _g = BootAgentTestGuard::acquire();
        let (_dir, path) = write_blob(&genesis_sealed_blob());
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        let mdir = tempfile::tempdir().unwrap();
        let mpath = mdir.path().join("measurement");
        std::fs::write(&mpath, b"\n").unwrap(); // trims to empty
        std::env::set_var(TWOD_HSM_ENCLAVE_MEASUREMENT_FILE, &mpath);
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(err, ProtocolError::PqSigningUnavailable(s) if s.contains("must be non-empty")),
            "empty measurement label: {err:?}"
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_oversize_blob_rejected_before_unseal() {
        let _g = BootAgentTestGuard::acquire();
        let (_dir, path) = write_blob(&vec![0u8; MAX_KEYSTORE_BLOB_SIZE + 1]);
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(err, ProtocolError::PqSigningUnavailable(s) if s.contains("MAX_KEYSTORE_BLOB_SIZE")),
            "oversize label: {err:?}"
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_neverending_file_capped_not_oom() {
        // A never-ending special file (/dev/zero) must be CAPPED (read_boot_file_capped) and rejected by
        // the size check — NOT read until OOM/hang. This test completing quickly is itself the assertion.
        let _g = BootAgentTestGuard::acquire();
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, "/dev/zero");
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(err, ProtocolError::PqSigningUnavailable(s) if s.contains("MAX_KEYSTORE_BLOB_SIZE")),
            "/dev/zero must be capped + rejected as oversize, got {err:?}"
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_unsupported_version_fails_closed() {
        let _g = BootAgentTestGuard::acquire();
        let mut blob = genesis_sealed_blob();
        blob[8] = 0x00; // version big-endian bytes [8],[9] : 4 -> 5 (5 is an unsupported FUTURE version;
        blob[9] = 0x05; // 4 is now the live KEYSTORE_FORMAT_VERSION, so injecting 4 would no longer reject)
        let (_dir, path) = write_blob(&blob);
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(err, ProtocolError::PqSigningUnavailable(s) if s.contains("unsupported sealed-keystore version")),
            "version label: {err:?}"
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_bad_magic_and_too_short_fail_closed() {
        let _g = BootAgentTestGuard::acquire();
        // Bad magic (a producer-shaped header): same length but wrong magic bytes.
        let mut bad_magic = genesis_sealed_blob();
        bad_magic[..8].copy_from_slice(b"2DHSMV1\0");
        let (_d1, p1) = write_blob(&bad_magic);
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &p1);
        let e1 = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(e1, ProtocolError::PqSigningUnavailable(s) if s.contains("malformed sealed blob"))
        );
        // Too short.
        let (_d2, p2) = write_blob(&[0x00u8; 4]);
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &p2);
        let e2 = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(e2, ProtocolError::PqSigningUnavailable(s) if s.contains("malformed sealed blob"))
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn seam_structural_version_zero_rejected() {
        let _g = BootAgentTestGuard::acquire();
        // Bypass seal_body's validate() by encoding a sv=0 body directly, then seal the raw CBOR.
        let mut body = genesis_body();
        body.structural_version = 0;
        let blob = seal_keystore_with_nonce(
            &cbor_of(&body),
            GOLDEN_AGENT_ROOT,
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
            &GOLDEN_AGENT_NONCE,
        )
        .unwrap();
        let (_dir, path) = write_blob(&blob);
        std::env::set_var(TWOD_HSM_AGENT_SEALED_KEYSTORE_FILE, &path);
        let err = unseal_agent_keystore_at_boot().unwrap_err();
        assert!(
            matches!(err, ProtocolError::PqSigningUnavailable(s) if s.contains("structural_version")),
            "structural_version label: {err:?}"
        );
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn boot_configure_agent_seal_root_sets_then_resolves() {
        let _g = BootAgentTestGuard::acquire();
        let dir = tempfile::tempdir().unwrap();
        let rpath = dir.path().join("root.bin");
        std::fs::write(&rpath, GOLDEN_AGENT_ROOT).unwrap();
        std::env::set_var(TWOD_HSM_PQ_SEAL_V1_ROOT_FILE, &rpath);
        boot_configure_agent_seal_root().expect("sets the root");
        assert!(crate::seal_root::is_platform_pq_seal_v1_provisioning_root_set());
        // Install-once: a second configure errors (does not clobber).
        assert!(boot_configure_agent_seal_root().is_err());
    }

    #[cfg(feature = "lab-agent-keystore-from-file")]
    #[test]
    fn boot_configure_agent_seal_root_rejects_wrong_length() {
        let _g = BootAgentTestGuard::acquire();
        let dir = tempfile::tempdir().unwrap();
        let rpath = dir.path().join("root31.bin");
        std::fs::write(&rpath, [0u8; 31]).unwrap();
        std::env::set_var(TWOD_HSM_PQ_SEAL_V1_ROOT_FILE, &rpath);
        assert!(boot_configure_agent_seal_root().is_err());
        assert!(!crate::seal_root::is_platform_pq_seal_v1_provisioning_root_set());
    }

    // ---- feature-independent tests (mapper, error-type, borrow-then-move, round-trip) ----

    #[test]
    fn map_keystore_error_total_and_coarse() {
        use crate::agent_keystore::KeystoreError as K;
        for e in [
            K::MeasurementMismatch,
            K::UnsupportedVersion,
            K::InvalidStructuralVersion,
            K::Cbor,
            K::Decrypt,
        ] {
            match map_keystore_error(e) {
                ProtocolError::PqSigningUnavailable(s) => {
                    assert!(s.starts_with("agent keystore:"), "prefixed: {s}");
                    assert!(!s.is_empty());
                }
                other => panic!("mapper must yield PqSigningUnavailable, got {other:?}"),
            }
        }
        // Pin the DISTINCT MonotonicOverflow label EXACTLY (it must not regress to the generic
        // "invalid keystore body" bucket — a runtime capacity condition reads differently in a log).
        // (ProtocolError has no PartialEq, so match + compare the &'static str.)
        match map_keystore_error(K::MonotonicOverflow) {
            ProtocolError::PqSigningUnavailable(s) => {
                assert_eq!(s, "agent keystore: monotonic counter overflow");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn error_type_is_pqsigningunavailable() {
        // The seam/root-step boundary type is ProtocolError, and every failure is PqSigningUnavailable —
        // no new public ProtocolError variant was minted for this slice.
        let _g = BootAgentTestGuard::acquire();
        // Production-stub measurement (no lab feature) OR missing env (lab feature) — either way the
        // failure must be PqSigningUnavailable.
        assert!(matches!(
            unseal_agent_keystore_at_boot(),
            Err(ProtocolError::PqSigningUnavailable(_))
        ));
    }

    #[cfg(not(feature = "lab-agent-keystore-from-file"))]
    #[test]
    fn production_stubs_fail_closed_without_lab_feature() {
        let _g = BootAgentTestGuard::acquire();
        // The root-step + the seam are documented fail-closed stubs in a non-lab agent build; the root
        // stays unset (the ordering is pinned through this path, which the cfg(test) root fallback can't
        // mask because measurement/blob sourcing Errs first).
        assert!(boot_configure_agent_seal_root().is_err());
        assert!(!crate::seal_root::is_platform_pq_seal_v1_provisioning_root_set());
        assert!(matches!(
            unseal_agent_keystore_at_boot(),
            Err(ProtocolError::PqSigningUnavailable(_))
        ));
    }

    #[test]
    fn borrow_then_move_install_order_and_install_once() {
        // Pins the 5b-2c ordering: the handshake BORROWS &body, then install MOVES body; a second install
        // returns false (install-once) — false is FATAL for the 5b-2c bin.
        let _g = BootAgentTestGuard::acquire();
        let body = genesis_body();
        let meas = AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT.to_vec();
        let _borrowed: &KeystoreBody = &body; // handshake borrow
        assert!(crate::agent_dispatch::install_agent_keystore(body, &meas)); // then move
        assert!(
            !crate::agent_dispatch::install_agent_keystore(genesis_body(), &meas),
            "install-once: a second install must return false (5b-2c treats false as FATAL)"
        );
    }

    #[test]
    fn genesis_body_seals_and_unseals_round_trip() {
        // The genesis fixture is a valid v4 body that round-trips through the seal envelope.
        let blob = genesis_sealed_blob();
        assert_eq!(
            &blob[8..10],
            &[0x00, 0x04],
            "format_version 4 in the header"
        );
        assert!(
            blob.len() <= MAX_KEYSTORE_BLOB_SIZE,
            "genesis blob is re-installable"
        );
        let body = unseal_body(
            &blob,
            GOLDEN_AGENT_ROOT,
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
        )
        .unwrap();
        assert_eq!(body, genesis_body());
    }

    #[test]
    fn agent_genesis_golden_blob_is_byte_exact() {
        // The in-source mint and the committed bytes must agree byte-for-byte — any deterministic-CBOR /
        // header / KeystoreBody-field drift flips this AND the from-disk loader integration test.
        let committed: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_genesis_v2.sealed.bin");
        assert_eq!(
            genesis_sealed_blob().as_slice(),
            committed,
            "genesis golden drifted; if the body layout/format_version changed intentionally, regen via \
             `regen_agent_genesis_golden_vector` and re-mint the .json sidecar in the same commit"
        );
        assert_eq!(
            &committed[8..10],
            &[0x00, 0x04],
            "format_version 4 (literal)"
        );
        assert!(
            committed.len() <= MAX_KEYSTORE_BLOB_SIZE,
            "golden blob is re-installable"
        );
        let body = unseal_body(
            committed,
            GOLDEN_AGENT_ROOT,
            AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
        )
        .expect("committed golden unseals");
        assert_eq!(body, genesis_body());
    }

    #[test]
    fn agent_genesis_golden_sidecar_matches_blob() {
        // The descriptive `.json` sidecar is documentation, consumed by no runtime path — so couple its
        // recorded sha256/len to the committed `.sealed.bin` HERE, else a future regen that updates the
        // blob but forgets the manual `.json` re-mint ships a stale, self-contradicting sidecar with green
        // CI. (The byte-exact freeze couples only the in-source mint to the blob, not the sidecar.)
        use sha2::{Digest, Sha256};
        let blob: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_genesis_v2.sealed.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/agent_keystore_genesis_v2.json");
        let hex = |bytes: &[u8]| -> String {
            let mut s = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        // Parse the sidecar (this ALSO asserts it is well-formed JSON), then compare SPECIFIC fields — not
        // substrings — so a value that drifted into the wrong field or a comment can't false-pass. Couples
        // BOTH the blob digest/len AND the descriptive seal_inputs (nonce / measurement / root hex) to the
        // source-of-truth constants, so a future regen that forgets the .json re-mint fails CI.
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("genesis sidecar must be valid JSON");
        let sha = hex(&Sha256::digest(blob));
        let nonce = hex(&GOLDEN_AGENT_NONCE);
        let meas = hex(AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT);
        let root = hex(GOLDEN_AGENT_ROOT);
        assert_eq!(
            v["blob_sha256"].as_str(),
            Some(sha.as_str()),
            "sidecar blob_sha256 drift — re-mint .json"
        );
        assert_eq!(
            v["blob_len_bytes"].as_u64(),
            Some(blob.len() as u64),
            "sidecar blob_len_bytes drift"
        );
        // Couple the documented format version to BOTH the const AND the actual header bytes [8],[9]
        // (big-endian) so a version bump that re-mints the blob but leaves the sidecar string stale fails CI.
        assert_eq!(
            v["envelope"]["keystore_format_version"].as_u64(),
            Some(u64::from(crate::agent_keystore::KEYSTORE_FORMAT_VERSION)),
            "sidecar keystore_format_version drift vs const"
        );
        assert_eq!(
            v["envelope"]["keystore_format_version"].as_u64(),
            Some(u64::from(u16::from_be_bytes([blob[8], blob[9]]))),
            "sidecar keystore_format_version drift vs blob header"
        );
        assert_eq!(
            v["envelope"]["nonce_hex"].as_str(),
            Some(nonce.as_str()),
            "sidecar nonce_hex drift"
        );
        assert_eq!(
            v["seal_inputs"]["enclave_measurement_hex"].as_str(),
            Some(meas.as_str()),
            "sidecar enclave_measurement_hex drift"
        );
        assert_eq!(
            v["seal_inputs"]["provisioning_root_hex"].as_str(),
            Some(root.as_str()),
            "sidecar provisioning_root_hex drift"
        );
    }

    /// REGEN (manual): `cargo test --features agent-gateway,lab-agent-keystore-from-file \
    /// regen_agent_genesis_golden_vector -- --ignored --nocapture`, then commit the `.sealed.bin`.
    /// Mirrors `agent_boot_relay::regen_boot_relay_golden_vector`. A deliberate `format_version` /
    /// body-layout change re-mints this AND the `.json` sidecar in the same commit.
    #[test]
    #[ignore]
    fn regen_agent_genesis_golden_vector() {
        let blob = genesis_sealed_blob();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testvectors/agent-gateway/agent_keystore_genesis_v2.sealed.bin"
        );
        std::fs::write(path, &blob).expect("write golden agent keystore blob");
        eprintln!("wrote {} bytes -> {path}", blob.len());
    }
}
