#![cfg_attr(not(test), allow(dead_code))]
// Slice 25-2b-i: the whole module is pure codec with no non-test caller yet (the cert-chain verify,
// transcript+Sig_PROV verify, mint+seal, and golden-regen land in slices ii–v). Per-item annotations
// would be noise across ~20 items; the module-level allow drops cleanly once slice iii/iv wires the
// inbound M3 path. Mirrors the staged-module convention (agent_boot / agent_boot_driver).

//! Agent Gateway provisioning channel — wire-format codec (TASK-25, slice 25-2b-i).
//!
//! Pure encode/decode of the **frozen** `provision_wire_version = 1` format defined in
//! `backlog/docs/agent-gateway-provisioning-wire-format.md` (25-2a). This slice implements ONLY the
//! structural codec + §2 DoS caps + per-state direction validation: it does NOT verify the provisioner
//! cert chain (slice ii), reconstruct/verify the transcript or `Sig_PROV` (slice iii), mint+seal
//! (slice iv), or regenerate the golden `Sig_PROV`/cert literals (slice v). The crypto arms of
//! [`ProvisionError`] are defined now so the error model is complete and stable for those slices.
//!
//! **Scope — untrusted provisioner→enclave wire input.** M1/M3 arrive over the AF_VSOCK bootstrap
//! listener from a provisioner the enclave has not yet authenticated. Every field is length-capped
//! (§2 DoS caps) BEFORE any expensive parse, and every parse is strict-canonical-CBOR
//! (RFC 8949 §4.2.1) via [`crate::agent_cbor`], so a non-canonical or oversized input fails closed
//! with a distinguishable [`ProvisionError`] rather than reaching the (deferred) crypto.

use crate::agent_cbor::{
    as_bytes, as_bytes32, as_bytes_n, as_u64, check_strict_keys, map_get, strict_decode_map,
    strict_decode_map_capped,
};
use crate::agent_capability::{put_bytes, put_text, put_uint};
use crate::agent_keystore::{
    is_valid_environment_identifier, MAX_KEYSTORE_BLOB_SIZE, ML_KEM_1024_ENCAPS_KEY_LEN,
};

// ════════════════════════════════════════════════════════════════════════════════
// Frozen constants (25-2a §10.1)
// ════════════════════════════════════════════════════════════════════════════════

/// 8-byte provision-family magic `b"2DAGPRV\0"` (follows the `2DAGxxx\0` convention: `2DAGTBK\0`
/// backup, `2DRIGV1\0` restore-ingress, `2DAGTKS\0` keystore).
pub(crate) const PROVISION_MAGIC: [u8; 8] = *b"2DAGPRV\0";

/// Frozen wire-format version. Any other value ⇒ [`ProvisionError::UnsupportedVersion`] (a future
/// bump is a new wire format, not a compatible extension).
pub(crate) const PROVISION_WIRE_VERSION: u8 = 1;

/// `Sig_PROV` domain (NUL-terminated, 26 bytes): `b"2d-hsm/agent-provision/v1\0"`. Matches the
/// `b"2d-hsm/agent-cap/v1\0"` / `b"2d-hsm/agent-anchor/v1\0"` family.
pub(crate) const PROVISION_DOMAIN: &[u8] = b"2d-hsm/agent-provision/v1\0";

/// `report_data` handshake domain (35 bytes, NO NUL): `b"2d-hsm-agent-provision-handshake-v1"`.
/// Mirrors the anchor handshake `b"2d-hsm-agent-anchor-handshake-v1"` style.
pub(crate) const HANDSHAKE_DOMAIN: &[u8] = b"2d-hsm-agent-provision-handshake-v1";

/// M1 PROV_CHALLENGE (provisioner → enclave).
pub(crate) const MSG_M1_CHALLENGE: u8 = 0x01;
/// M2 PROV_ATTEST (enclave → provisioner).
pub(crate) const MSG_M2_ATTEST: u8 = 0x02;
/// M3 PROV_CONFIG (provisioner → enclave).
pub(crate) const MSG_M3_CONFIG: u8 = 0x03;
/// M4 PROV_SEALED (enclave → provisioner).
pub(crate) const MSG_M4_SEALED: u8 = 0x04;

/// Envelope overhead: `magic(8) ‖ version(1) ‖ msg_type(1)`.
pub(crate) const ENVELOPE_OVERHEAD: usize = 10;

// ════════════════════════════════════════════════════════════════════════════════
// DoS caps (25-2a §2) — untrusted variable-length fields are bounded BEFORE the parse
// ════════════════════════════════════════════════════════════════════════════════

/// Overall M1/M3 CBOR payload cap (8 KiB; the largest legitimate M3 is ~1.8 KiB → 4× headroom).
pub(crate) const MAX_PROV_PAYLOAD_LEN: usize = 8192;
/// `config_map` (M3 key 1) cap (4 KiB; 7 fields, the 1568-byte ML-KEM key dominates → 2× headroom).
pub(crate) const MAX_CONFIG_MAP_LEN: usize = 4096;
/// `provisioner_cert` (M3 key 6) cap (2 KiB; a single-level DER X.509 Ed25519 leaf is ~300–500 B).
pub(crate) const MAX_PROV_CERT_LEN: usize = 2048;

// ════════════════════════════════════════════════════════════════════════════════
// Fixed field widths
// ════════════════════════════════════════════════════════════════════════════════

/// Fresh challenge / session nonce width (matches the anchor `DIGEST_LEN`).
pub(crate) const NONCE_LEN: usize = 32;
/// Ed25519 `Sig_PROV` width.
pub(crate) const SIG_PROV_LEN: usize = 64;
/// SEV-SNP attestation report (the fixed VCEK-signed structure).
pub(crate) const SNP_REPORT_LEN: usize = 1184;
/// Authority / anchor / fleet / report_hash width.
pub(crate) const DIGEST_LEN: usize = 32;

// ════════════════════════════════════════════════════════════════════════════════
// Error model (25-2a §9)
// ════════════════════════════════════════════════════════════════════════════════

/// Decoder / handshake errors for the provision channel. The structural arms are constructed in
/// THIS slice; the crypto arms are defined now (constructed by slices ii/iii) so a reviewer sees the
/// complete failure model and slice iii/iv do not reshape it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProvisionError {
    /// `magic ≠ b"2DAGPRV\0"` (§2/§9).
    BadMagic,
    /// `version ≠ 1` (§2/§9).
    UnsupportedVersion,
    /// Non-canonical CBOR, unknown `msg_type`, wrong key set / field type / length, trailing bytes,
    /// or a known `msg_type` received in the wrong handshake state (§9).
    Malformed,
    /// An untrusted variable-length field exceeded its §2 cap (overall payload / `config_map` /
    /// `provisioner_cert` / the fixed `report` length). Distinct from [`Self::Malformed`] so a DoS
    /// probe surfaces as a size violation, not a structural one.
    TooLarge,
    // ── crypto arms (constructed by slices ii/iii; defined for a stable error model) ──
    /// `report_data ≠ SHA3-512(HANDSHAKE_DOMAIN ‖ N_p ‖ N_e)` (§4/§9).
    AttestMismatch,
    /// M3 keys 2/3/4 did not byte-match the session's `(N_p, N_e, report_hash)` (§6/§9 — replay/MITM).
    TranscriptMismatch,
    /// `provisioner_cert` did not chain to the pinned operator CA root, or lacked the provisioning
    /// role EKU (§7/§9 — confused-deputy defense).
    UnauthorizedProvisioner,
    /// `Sig_PROV` did not verify under the provisioner cert's key (§6/§9).
    BadSignature,
}

// ════════════════════════════════════════════════════════════════════════════════
// Envelope framing (every message): magic ‖ version ‖ msg_type ‖ CBOR payload  (§2)
// ════════════════════════════════════════════════════════════════════════════════

/// Encode a provision envelope: `magic ‖ version ‖ msg_type ‖ payload`.
pub(crate) fn encode_envelope(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_OVERHEAD + payload.len());
    out.extend_from_slice(&PROVISION_MAGIC);
    out.push(PROVISION_WIRE_VERSION);
    out.push(msg_type);
    out.extend_from_slice(payload);
    out
}

/// Decode a provision envelope, returning the validated `(msg_type, payload_slice)`. Fails closed on
/// wrong magic ([`ProvisionError::BadMagic`]), wrong version ([`UnsupportedVersion`]), an unknown
/// `msg_type` or a too-short frame ([`Malformed`]). The payload is NOT capped here — each message
/// decoder applies its own §2 cap; the transport frame is already bounded by `MAX_MESSAGE_SIZE`.
pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<(u8, &[u8]), ProvisionError> {
    if bytes.len() < ENVELOPE_OVERHEAD {
        return Err(ProvisionError::Malformed);
    }
    if bytes[..8] != PROVISION_MAGIC {
        return Err(ProvisionError::BadMagic);
    }
    if bytes[8] != PROVISION_WIRE_VERSION {
        return Err(ProvisionError::UnsupportedVersion);
    }
    let msg_type = bytes[9];
    if !matches!(
        msg_type,
        MSG_M1_CHALLENGE | MSG_M2_ATTEST | MSG_M3_CONFIG | MSG_M4_SEALED
    ) {
        return Err(ProvisionError::Malformed);
    }
    Ok((msg_type, &bytes[ENVELOPE_OVERHEAD..]))
}

// ════════════════════════════════════════════════════════════════════════════════
// Per-state direction validation (25-2a-rev1 Low / §2 / §9)
// ════════════════════════════════════════════════════════════════════════════════

/// One step of the two-round-trip handshake that a *receiver* is currently waiting at. The step
/// name encodes BOTH the receiver role AND the expected inbound message (the enclave awaits M1 then
/// M3; the provisioner awaits M2 then M4), so direction validation is a pure total function of
/// `(step, msg_type)` — no separate role enum needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeStep {
    /// Enclave, bootstrap listener open — expects M1.
    AwaitingM1,
    /// Provisioner, after sending M1 — expects M2.
    AwaitingM2,
    /// Enclave, after emitting M2 — expects M3.
    AwaitingM3,
    /// Provisioner, after sending M3 — expects M4.
    AwaitingM4,
    /// Terminal — M4 sent/received; the enclave tears down the listener and starts the runtime loop.
    Done,
}

/// Validate that `incoming_msg_type` is the message expected at `step`, returning the next step.
/// A known `msg_type` received out-of-role/state ⇒ [`ProvisionError::Malformed`] (the §9 negative:
/// enclave receiving M2/M4 or M3-before-M1; provisioner receiving M1/M3 or M4-before-M2).
pub(crate) fn validate_inbound(
    step: HandshakeStep,
    incoming_msg_type: u8,
) -> Result<HandshakeStep, ProvisionError> {
    match (step, incoming_msg_type) {
        (HandshakeStep::AwaitingM1, MSG_M1_CHALLENGE) => Ok(HandshakeStep::AwaitingM3),
        (HandshakeStep::AwaitingM2, MSG_M2_ATTEST) => Ok(HandshakeStep::AwaitingM4),
        (HandshakeStep::AwaitingM3, MSG_M3_CONFIG) => Ok(HandshakeStep::Done),
        (HandshakeStep::AwaitingM4, MSG_M4_SEALED) => Ok(HandshakeStep::Done),
        _ => Err(ProvisionError::Malformed),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// M1 — PROV_CHALLENGE (provisioner → enclave): {1: N_p[32]}  (§3)
// ════════════════════════════════════════════════════════════════════════════════

/// Decoded M1 PROV_CHALLENGE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct M1Challenge {
    /// The provisioner's fresh challenge nonce.
    pub n_p: [u8; NONCE_LEN],
}

/// Encode the M1 payload (canonical-CBOR `{1: N_p}`).
pub(crate) fn encode_m1(n_p: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 + NONCE_LEN);
    put_uint(&mut out, 5, 1); // map(1)
    put_uint(&mut out, 0, 1); // key 1
    put_bytes(&mut out, n_p);
    out
}

/// Decode the M1 payload. Caps the payload at [`MAX_PROV_PAYLOAD_LEN`] before the parse.
pub(crate) fn decode_m1(payload: &[u8]) -> Result<M1Challenge, ProvisionError> {
    if payload.len() > MAX_PROV_PAYLOAD_LEN {
        return Err(ProvisionError::TooLarge);
    }
    let map = strict_decode_map(payload).map_err(|_| ProvisionError::Malformed)?;
    if !check_strict_keys(&map, |k| k == 1) {
        return Err(ProvisionError::Malformed);
    }
    let n_p = as_bytes_n::<NONCE_LEN>(map_get(&map, 1).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    Ok(M1Challenge { n_p })
}

// ════════════════════════════════════════════════════════════════════════════════
// M2 — PROV_ATTEST (enclave → provisioner): {1: N_e[32], 2: report[var]}  (§4)
// ════════════════════════════════════════════════════════════════════════════════

/// Decoded M2 PROV_ATTEST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct M2Attest {
    /// The enclave's fresh session nonce.
    pub n_e: [u8; NONCE_LEN],
    /// The raw SNP attestation report bytes (exactly [`SNP_REPORT_LEN`]).
    pub report: Vec<u8>,
}

/// Encode the M2 payload.
pub(crate) fn encode_m2(n_e: &[u8; NONCE_LEN], report: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_uint(&mut out, 5, 2); // map(2)
    put_uint(&mut out, 0, 1);
    put_bytes(&mut out, n_e);
    put_uint(&mut out, 0, 2);
    put_bytes(&mut out, report);
    out
}

/// Decode the M2 payload. The `report` MUST be exactly [`SNP_REPORT_LEN`] (a fixed VCEK-signed
/// structure); any other length ⇒ [`ProvisionError::TooLarge`] (the §9 fixed-equality check, reported
/// under the too-large family per §2). Parsed with the transport-bound bstr cap
/// ([`crate::MAX_MESSAGE_SIZE`], strictly wider than any field cap) so an over-length `report` of ANY
/// size reaches the explicit `!= SNP_REPORT_LEN` check as `TooLarge` rather than tripping a narrower
/// decode cap as `Malformed` — the same transport-bound-cap discipline as M4 (M2 is enclave-emitted and
/// carries no §2 overall-payload cap; the transport frame bounds the whole message).
pub(crate) fn decode_m2(payload: &[u8]) -> Result<M2Attest, ProvisionError> {
    let map = strict_decode_map_capped(payload, crate::MAX_MESSAGE_SIZE as u64)
        .map_err(|_| ProvisionError::Malformed)?;
    if !check_strict_keys(&map, |k| matches!(k, 1 | 2)) {
        return Err(ProvisionError::Malformed);
    }
    let n_e = as_bytes_n::<NONCE_LEN>(map_get(&map, 1).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let report = as_bytes(map_get(&map, 2).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    if report.len() != SNP_REPORT_LEN {
        return Err(ProvisionError::TooLarge);
    }
    Ok(M2Attest {
        n_e,
        report: report.to_vec(),
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// M3 — PROV_CONFIG (provisioner → enclave):  (§5/§6)
//   {1: config_map_bytes[var], 2: N_p[32], 3: N_e[32], 4: report_hash[32],
//    5: Sig_PROV[64], 6: provisioner_cert[var]}
// ════════════════════════════════════════════════════════════════════════════════

/// Decoded M3 PROV_CONFIG. The transcript fields (`N_p`/`N_e`/`report_hash`) and `Sig_PROV` are
/// structurally present at the right widths but are NOT cryptographically verified here — slice iii
/// re-derives `(N_p, N_e, report_hash)` from the live session, byte-compares, then verifies
/// `Sig_PROV` over `PROVISION_DOMAIN ‖ canonical-CBOR({1: config_map_bytes, 2: N_p, 3: N_e,
/// 4: report_hash})`. `config_map_bytes` is kept as the raw signed bytes (the config is decoded from
/// them by [`decode_config_map`] only AFTER the signature passes — §6 verify-order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct M3Config {
    /// M3 key 1 — pre-encoded canonical-CBOR of the §5.1 config map.
    pub config_map_bytes: Vec<u8>,
    /// M3 key 2 — echoed `N_p` (slice iii byte-compares to the session's M1 nonce).
    pub n_p: [u8; NONCE_LEN],
    /// M3 key 3 — echoed `N_e` (slice iii byte-compares to the session's M2 nonce).
    pub n_e: [u8; NONCE_LEN],
    /// M3 key 4 — `SHA3-256(report)` (slice iii byte-compares to the session's M2 report hash).
    pub report_hash: [u8; DIGEST_LEN],
    /// M3 key 5 — `Sig_PROV` (slice iii verifies under the provisioner cert's key).
    pub sig_prov: [u8; SIG_PROV_LEN],
    /// M3 key 6 — DER X.509 leaf cert chaining to the pinned operator CA (slice ii verifies).
    pub provisioner_cert: Vec<u8>,
}

/// Decode the M3 payload. Applies the §2 caps in order: overall payload, then (after a raised-cap
/// canonical parse) `config_map` and `provisioner_cert` — each distinguishable as
/// [`ProvisionError::TooLarge`]. The raised-cap parse ([`strict_decode_map_capped`]) is essential:
/// `config_map`'s cap (4096) equals the shared decoder's internal bstr cap, so without it an
/// over-cap `config_map` would collapse into a generic [`Malformed`] and the §9 `PROV_TOO_LARGE`
/// negative would be indistinguishable.
pub(crate) fn decode_m3(payload: &[u8]) -> Result<M3Config, ProvisionError> {
    if payload.len() > MAX_PROV_PAYLOAD_LEN {
        return Err(ProvisionError::TooLarge);
    }
    let map = strict_decode_map_capped(payload, MAX_PROV_PAYLOAD_LEN as u64)
        .map_err(|_| ProvisionError::Malformed)?;
    if !check_strict_keys(&map, |k| matches!(k, 1..=6)) {
        return Err(ProvisionError::Malformed);
    }
    let config_map_bytes = as_bytes(map_get(&map, 1).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    if config_map_bytes.len() > MAX_CONFIG_MAP_LEN {
        return Err(ProvisionError::TooLarge);
    }
    let n_p = as_bytes_n::<NONCE_LEN>(map_get(&map, 2).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let n_e = as_bytes_n::<NONCE_LEN>(map_get(&map, 3).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let report_hash = as_bytes32(map_get(&map, 4).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let sig_prov = as_bytes_n::<SIG_PROV_LEN>(map_get(&map, 5).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let provisioner_cert = as_bytes(map_get(&map, 6).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    if provisioner_cert.len() > MAX_PROV_CERT_LEN {
        return Err(ProvisionError::TooLarge);
    }
    Ok(M3Config {
        config_map_bytes: config_map_bytes.to_vec(),
        n_p,
        n_e,
        report_hash,
        sig_prov,
        provisioner_cert: provisioner_cert.to_vec(),
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// M4 — PROV_SEALED (enclave → provisioner): {1: sealed_blob[var]}  (§8)
// ════════════════════════════════════════════════════════════════════════════════

/// Decoded M4 PROV_SEALED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct M4Sealed {
    /// The freshly-minted + sealed keystore blob (magic `2DAGTKS\0`).
    pub sealed_blob: Vec<u8>,
}

/// Encode the M4 payload.
pub(crate) fn encode_m4(sealed_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_uint(&mut out, 5, 1); // map(1)
    put_uint(&mut out, 0, 1); // key 1
    put_bytes(&mut out, sealed_blob);
    out
}

/// Decode the M4 payload. The `sealed_blob` is capped at [`MAX_KEYSTORE_BLOB_SIZE`] — the SAME budget
/// `seal_body` enforces, so a blob that seals is always re-installable; a larger blob ⇒
/// [`ProvisionError::TooLarge`]. Parsed with the transport-bound bstr cap ([`crate::MAX_MESSAGE_SIZE`],
/// STRICTLY WIDER than the [`MAX_KEYSTORE_BLOB_SIZE`] field cap) so an over-keystore-cap blob reaches
/// the explicit `TooLarge` check rather than tripping the decode cap itself (which would collapse
/// into `Malformed`) — the same decode-cap > field-cap discipline as M3. The raised cap also lets a
/// realistic sealed keystore (the reference fixture is already ~4.2 KiB, above the shared decoder's
/// 4096 cap) through. This honors the keystore spec's "install/restore encoder MUST honor
/// `MAX_KEYSTORE_BLOB_SIZE`" obligation.
pub(crate) fn decode_m4(payload: &[u8]) -> Result<M4Sealed, ProvisionError> {
    let map = strict_decode_map_capped(payload, crate::MAX_MESSAGE_SIZE as u64)
        .map_err(|_| ProvisionError::Malformed)?;
    if !check_strict_keys(&map, |k| k == 1) {
        return Err(ProvisionError::Malformed);
    }
    let sealed_blob = as_bytes(map_get(&map, 1).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    if sealed_blob.len() > MAX_KEYSTORE_BLOB_SIZE {
        return Err(ProvisionError::TooLarge);
    }
    Ok(M4Sealed {
        sealed_blob: sealed_blob.to_vec(),
    })
}

// ════════════════════════════════════════════════════════════════════════════════
// The §5.1 config map (basket B) — 7 fields, NO enclave_scope_id  (I2 structural enforcement)
// ════════════════════════════════════════════════════════════════════════════════

/// The §5.1 provision config map — the 7 fields the provisioner delivers over the authenticated
/// channel. Deliberately a DISTINCT type from `KeystoreConfig`: it carries NO `enclave_scope_id`
/// (I2 — host-uncontrollable; minted in-TEE at seal time), and NO `monotonic_treasury_config_version`
/// / `authority_epoch` (enclave-init deterministic). Slice iv constructs a `KeystoreConfig` from
/// this + the enclave-minted scope id + the init constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvisionConfig {
    pub twod_chain_id: u64,
    pub environment_identifier: String,
    pub admin_authority_pk: [u8; DIGEST_LEN],
    pub recovery_authority_pk: [u8; DIGEST_LEN],
    /// ML-KEM-1024 encapsulation key (raw; exactly [`ML_KEM_1024_ENCAPS_KEY_LEN`] bytes).
    pub backup_recovery_wrapping_pubkey: Vec<u8>,
    pub anchor_root: [u8; DIGEST_LEN],
    pub fleet_scope_id: [u8; DIGEST_LEN],
}

/// Encode the config map (canonical-CBOR, keys `1..=7` ascending). The byte shape is the §5.2
/// encoder reference; the byte-exact literal (with concrete sentinels) is frozen by the slice-v
/// regen test.
pub(crate) fn encode_config_map(cfg: &ProvisionConfig) -> Vec<u8> {
    let mut out = Vec::new();
    put_uint(&mut out, 5, 7); // map(7)
    put_uint(&mut out, 0, 1);
    put_uint(&mut out, 0, cfg.twod_chain_id);
    put_uint(&mut out, 0, 2);
    put_text(&mut out, &cfg.environment_identifier);
    put_uint(&mut out, 0, 3);
    put_bytes(&mut out, &cfg.admin_authority_pk);
    put_uint(&mut out, 0, 4);
    put_bytes(&mut out, &cfg.recovery_authority_pk);
    put_uint(&mut out, 0, 5);
    put_bytes(&mut out, &cfg.backup_recovery_wrapping_pubkey);
    put_uint(&mut out, 0, 6);
    put_bytes(&mut out, &cfg.anchor_root);
    put_uint(&mut out, 0, 7);
    put_bytes(&mut out, &cfg.fleet_scope_id);
    out
}

/// Decode the config map. Strict-canonical-CBOR with keys EXACTLY `{1..=7}`: a host-injected key `8`
/// (an attempted `enclave_scope_id`) ⇒ [`ProvisionError::Malformed`] (the I2 structural enforcement
/// — the protocol does not carry the scope id). Field types + lengths are validated (32-byte keys,
/// 1568-byte ML-KEM key, the sealed-config `environment_identifier` charset).
pub(crate) fn decode_config_map(bytes: &[u8]) -> Result<ProvisionConfig, ProvisionError> {
    let map = strict_decode_map(bytes).map_err(|_| ProvisionError::Malformed)?;
    // Keys must be EXACTLY {1..=7}: check_strict_keys rejects any present key outside {1..=7}
    // (incl. a host-injected key 8); the count check rejects a subset (missing a required key).
    if !check_strict_keys(&map, |k| matches!(k, 1..=7)) || map.len() != 7 {
        return Err(ProvisionError::Malformed);
    }
    let twod_chain_id = as_u64(map_get(&map, 1).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let environment_identifier =
        match map_get(&map, 2).ok_or(ProvisionError::Malformed)? {
            ciborium::Value::Text(s) => s.clone(),
            _ => return Err(ProvisionError::Malformed),
        };
    if !is_valid_environment_identifier(&environment_identifier) {
        return Err(ProvisionError::Malformed);
    }
    let admin_authority_pk = as_bytes32(map_get(&map, 3).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let recovery_authority_pk = as_bytes32(map_get(&map, 4).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let backup_recovery_wrapping_pubkey =
        as_bytes(map_get(&map, 5).ok_or(ProvisionError::Malformed)?)
            .ok_or(ProvisionError::Malformed)?;
    if backup_recovery_wrapping_pubkey.len() != ML_KEM_1024_ENCAPS_KEY_LEN {
        return Err(ProvisionError::Malformed);
    }
    let anchor_root = as_bytes32(map_get(&map, 6).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    let fleet_scope_id = as_bytes32(map_get(&map, 7).ok_or(ProvisionError::Malformed)?)
        .ok_or(ProvisionError::Malformed)?;
    Ok(ProvisionConfig {
        twod_chain_id,
        environment_identifier,
        admin_authority_pk,
        recovery_authority_pk,
        backup_recovery_wrapping_pubkey: backup_recovery_wrapping_pubkey.to_vec(),
        anchor_root,
        fleet_scope_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §10.3 representative config (the slice-v regen test pins the exact sentinels; this is the
    /// shape reference reused across the golden + round-trip tests).
    fn sample_config() -> ProvisionConfig {
        ProvisionConfig {
            twod_chain_id: 11565,
            environment_identifier: "prod-0".to_string(),
            admin_authority_pk: [0xa1; 32],
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: vec![0xb0; ML_KEM_1024_ENCAPS_KEY_LEN],
            anchor_root: [0xa3; 32],
            fleet_scope_id: [0xf1; 32],
        }
    }

    // ── §10.1 frozen domains / magic ────────────────────────────────────────────

    #[test]
    fn frozen_domains_and_magic_literals() {
        assert_eq!(PROVISION_MAGIC, [0x32, 0x44, 0x41, 0x47, 0x50, 0x52, 0x56, 0x00]);
        assert_eq!(PROVISION_WIRE_VERSION, 1);
        assert_eq!(PROVISION_DOMAIN, b"2d-hsm/agent-provision/v1\0");
        assert_eq!(PROVISION_DOMAIN.len(), 26);
        assert_eq!(HANDSHAKE_DOMAIN, b"2d-hsm-agent-provision-handshake-v1");
        assert_eq!(HANDSHAKE_DOMAIN.len(), 35); // NO NUL (25-2a-rev1 Low)
    }

    // ── §10.2 M1 golden (byte-exact) ────────────────────────────────────────────

    #[test]
    fn m1_golden_byte_exact() {
        let n_p = [0x11u8; 32];
        let payload = encode_m1(&n_p);
        // payload = A1 01 58 20 <32×0x11>
        let mut expected = vec![0xA1, 0x01, 0x58, 0x20];
        expected.extend_from_slice(&[0x11; 32]);
        assert_eq!(payload, expected);

        let full = encode_envelope(MSG_M1_CHALLENGE, &payload);
        // 8 (magic) + 1 (ver) + 1 (type) + 4 (payload head) + 32 (nonce) = 46 (25-2a-rev2 HIGH fix)
        assert_eq!(full.len(), 46);
        assert_eq!(&full[..8], &PROVISION_MAGIC);
        assert_eq!(full[8], 0x01);
        assert_eq!(full[9], MSG_M1_CHALLENGE);

        // round-trips
        let dec = decode_m1(&payload).unwrap();
        assert_eq!(dec.n_p, n_p);
    }

    // ── §5.2 / §10.3 config_map golden shape ────────────────────────────────────
    //
    // NB: the §5.2 shape annotation says `65 "prod-0" # text(5)` but `"prod-0"` is 6 bytes — a
    // correct canonical encoder emits text(6)=0x66. This is a frozen-spec SHAPE typo (§10 defers the
    // byte-exact literal to the slice-v regen test, so the wire format is unaffected); flagged for a
    // doc rev, not honored in the encoder (honoring it would emit non-canonical/wrong-length CBOR).
    #[test]
    fn config_map_golden_shape() {
        let cfg = sample_config();
        let bytes = encode_config_map(&cfg);
        // A7 (map 7)
        assert_eq!(bytes[0], 0xA7);
        // key 1 = uint 11565 = 19 2D 2D  (25-2a-rev1 HIGH fix: 0x2D2D, NOT 0x2D0D)
        assert_eq!(&bytes[1..5], &[0x01, 0x19, 0x2D, 0x2D]);
        // key 2 = text "prod-0" = 02 66 "prod-0"  (6 bytes ⇒ text(6)=0x66, the §5.2 `text(5)` is a typo)
        assert_eq!(bytes[5], 0x02);
        assert_eq!(bytes[6], 0x66);
        assert_eq!(&bytes[7..13], b"prod-0");
        // key 3 = bytes(32): 03 58 20
        assert_eq!(&bytes[13..16], &[0x03, 0x58, 0x20]);
        // skip 32 admin bytes; key 4 = bytes(32): 04 58 20
        assert_eq!(&bytes[48..51], &[0x04, 0x58, 0x20]);
        // skip 32 recovery bytes; key 5 = bytes(1568): 05 59 06 20  (0x0620 = 1568)
        assert_eq!(&bytes[83..87], &[0x05, 0x59, 0x06, 0x20]);
        // skip 1568 backup bytes; key 6 = bytes(32): 06 58 20
        assert_eq!(&bytes[87 + 1568..87 + 1568 + 3], &[0x06, 0x58, 0x20]);
        // skip 32 anchor bytes; key 7 = bytes(32): 07 58 20
        assert_eq!(&bytes[87 + 1568 + 35..87 + 1568 + 35 + 3], &[0x07, 0x58, 0x20]);

        // round-trips
        let dec = decode_config_map(&bytes).unwrap();
        assert_eq!(dec, cfg);
    }

    // ── §2 envelope negatives ───────────────────────────────────────────────────

    #[test]
    fn envelope_wrong_magic() {
        let mut bad = encode_envelope(MSG_M1_CHALLENGE, &encode_m1(&[0x11; 32]));
        bad[3] = 0x58; // corrupt magic byte 4 (2DAG…→2DAx…)
        assert_eq!(decode_envelope(&bad), Err(ProvisionError::BadMagic));
    }

    #[test]
    fn envelope_unsupported_version() {
        for v in [0u8, 2, 0xFF] {
            let mut bad = encode_envelope(MSG_M1_CHALLENGE, &encode_m1(&[0x11; 32]));
            bad[8] = v;
            assert_eq!(decode_envelope(&bad), Err(ProvisionError::UnsupportedVersion), "v={v}");
        }
    }

    #[test]
    fn envelope_unknown_msg_type() {
        for t in [0u8, 5, 0xFF] {
            let mut bad = encode_envelope(MSG_M1_CHALLENGE, &encode_m1(&[0x11; 32]));
            bad[9] = t;
            assert_eq!(decode_envelope(&bad), Err(ProvisionError::Malformed), "t={t}");
        }
    }

    #[test]
    fn envelope_truncated() {
        // magic(8) + version(1) but no msg_type ⇒ 9 bytes < ENVELOPE_OVERHEAD(10)
        let mut truncated = Vec::from(&PROVISION_MAGIC[..]);
        truncated.push(PROVISION_WIRE_VERSION);
        assert_eq!(decode_envelope(&truncated), Err(ProvisionError::Malformed));
    }

    // ── §9 direction validation negatives ───────────────────────────────────────

    #[test]
    fn direction_happy_path() {
        // enclave side
        assert_eq!(
            validate_inbound(HandshakeStep::AwaitingM1, MSG_M1_CHALLENGE),
            Ok(HandshakeStep::AwaitingM3)
        );
        assert_eq!(
            validate_inbound(HandshakeStep::AwaitingM3, MSG_M3_CONFIG),
            Ok(HandshakeStep::Done)
        );
        // provisioner side
        assert_eq!(
            validate_inbound(HandshakeStep::AwaitingM2, MSG_M2_ATTEST),
            Ok(HandshakeStep::AwaitingM4)
        );
        assert_eq!(
            validate_inbound(HandshakeStep::AwaitingM4, MSG_M4_SEALED),
            Ok(HandshakeStep::Done)
        );
    }

    #[test]
    fn direction_wrong_role_or_state_is_malformed() {
        // enclave receiving M2/M4, or M3 before M1
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM1, MSG_M2_ATTEST), Err(ProvisionError::Malformed));
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM1, MSG_M4_SEALED), Err(ProvisionError::Malformed));
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM1, MSG_M3_CONFIG), Err(ProvisionError::Malformed));
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM3, MSG_M1_CHALLENGE), Err(ProvisionError::Malformed));
        // provisioner receiving M1/M3, or M4 before M2
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM2, MSG_M1_CHALLENGE), Err(ProvisionError::Malformed));
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM2, MSG_M3_CONFIG), Err(ProvisionError::Malformed));
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM2, MSG_M4_SEALED), Err(ProvisionError::Malformed));
        assert_eq!(validate_inbound(HandshakeStep::AwaitingM4, MSG_M2_ATTEST), Err(ProvisionError::Malformed));
        // terminal state rejects everything
        assert_eq!(validate_inbound(HandshakeStep::Done, MSG_M1_CHALLENGE), Err(ProvisionError::Malformed));
    }

    // ── §9 M1 structural negatives ──────────────────────────────────────────────

    #[test]
    fn m1_non_canonical_rejected() {
        // non-shortest int encoding for the key: 0x18 0x01 instead of 0x01
        let bad = vec![0xA1, 0x18, 0x01, 0x58, 0x20];
        assert_eq!(decode_m1(&bad), Err(ProvisionError::Malformed));
    }

    #[test]
    fn m1_wrong_key_rejected() {
        // key 2 instead of 1
        let mut bad = encode_m1(&[0x11; 32]);
        bad[1] = 0x02;
        assert_eq!(decode_m1(&bad), Err(ProvisionError::Malformed));
    }

    #[test]
    fn m1_extra_key_rejected() {
        // map(2) with keys 1 + 2 — strict keys {1} rejects key 2
        let mut bad = encode_m1(&[0x11; 32]);
        bad[0] = 0xA2; // map(2)
        bad.extend_from_slice(&[0x02, 0x58, 0x20]); // key 2 + bytes(32) head
        bad.extend_from_slice(&[0x99; 32]);
        assert_eq!(decode_m1(&bad), Err(ProvisionError::Malformed));
    }

    #[test]
    fn m1_payload_too_large() {
        let mut huge = vec![0xA1, 0x01, 0x59, 0x20, 0x00]; // bytes(8192)
        huge.extend(std::iter::repeat(0u8).take(MAX_PROV_PAYLOAD_LEN + 1));
        assert_eq!(decode_m1(&huge), Err(ProvisionError::TooLarge));
    }

    // ── §9 config_map negatives ─────────────────────────────────────────────────

    #[test]
    fn config_map_key8_injection_rejected() {
        // host attempts to inject enclave_scope_id as key 8
        let mut bytes = encode_config_map(&sample_config());
        // append key 8 + a 32-byte value; rewrite map header to 8 pairs
        bytes[0] = 0xA8; // map(8)
        bytes.extend_from_slice(&[0x08, 0x58, 0x20]);
        bytes.extend_from_slice(&[0xe1; 32]);
        assert_eq!(decode_config_map(&bytes), Err(ProvisionError::Malformed));
    }

    #[test]
    fn config_map_wrong_backup_length_rejected() {
        let mut cfg = sample_config();
        cfg.backup_recovery_wrapping_pubkey = vec![0xb0; 100]; // ≠ 1568
        let bytes = encode_config_map(&cfg);
        assert_eq!(decode_config_map(&bytes), Err(ProvisionError::Malformed));
    }

    #[test]
    fn config_map_bad_env_charset_rejected() {
        let mut cfg = sample_config();
        cfg.environment_identifier = "Main--net".to_string(); // uppercase + double hyphen
        let bytes = encode_config_map(&cfg);
        assert_eq!(decode_config_map(&bytes), Err(ProvisionError::Malformed));
    }

    #[test]
    fn config_map_missing_key_rejected() {
        // drop the last pair (key 7); rewrite map header to 6
        let mut bytes = encode_config_map(&sample_config());
        // truncate the trailing key-7 pair: 3-byte head + 32-byte value
        bytes.truncate(bytes.len() - 35);
        bytes[0] = 0xA6; // map(6)
        assert_eq!(decode_config_map(&bytes), Err(ProvisionError::Malformed));
    }

    #[test]
    fn config_map_header_count_mismatch_rejected() {
        // map(8) header but only 7 pairs follow ⇒ strict_decode_map rejects the head/count mismatch
        // (trailing bytes / under-filled map).
        let mut bytes = encode_config_map(&sample_config());
        bytes[0] = 0xA8; // map(8) claim over 7 pairs
        assert_eq!(decode_config_map(&bytes), Err(ProvisionError::Malformed));
    }

    #[test]
    fn config_map_duplicate_key_rejected() {
        // A literal duplicate of key 1: build a valid config_map, then splice in a second `01 <val>`
        // pair right after the first. strict_decode_map's canonical-ordering check (keys strictly
        // ascending by encoded bytes) rejects the equal-key repeat ⇒ Malformed.
        let cfg = sample_config();
        let mut first_val = Vec::new();
        put_uint(&mut first_val, 0, cfg.twod_chain_id); // the key-1 value (uint)
        let mut bytes = encode_config_map(&cfg);
        let insert_at = 1 + first_val.len() + 1; // after `A7 01 <uint>`
        let mut dup = Vec::with_capacity(bytes.len() + 1 + first_val.len());
        dup.extend_from_slice(&bytes[..insert_at]);
        dup.push(0x01); // duplicate key 1
        dup.extend_from_slice(&first_val);
        dup.extend_from_slice(&bytes[insert_at..]);
        dup[0] = 0xA8; // map(8) to keep the count consistent (7 + 1 dup = 8 pairs)
        assert_eq!(decode_config_map(&dup), Err(ProvisionError::Malformed));
    }

    #[test]
    fn config_map_out_of_order_keys_rejected() {
        // Keys in non-ascending order: swap key 6 and key 7's BYTE positions is hard (fixed widths
        // differ only by the key byte). Easier: emit key 7's pair BEFORE key 6's. Build by encoding
        // key 7 then key 6 — strict_decode_map rejects descending order ⇒ Malformed.
        let cfg = sample_config();
        let mut out = Vec::new();
        put_uint(&mut out, 5, 7); // map(7) claim
        put_uint(&mut out, 0, 1);
        put_uint(&mut out, 0, cfg.twod_chain_id);
        put_uint(&mut out, 0, 2);
        put_text(&mut out, &cfg.environment_identifier);
        put_uint(&mut out, 0, 3);
        put_bytes(&mut out, &cfg.admin_authority_pk);
        put_uint(&mut out, 0, 4);
        put_bytes(&mut out, &cfg.recovery_authority_pk);
        put_uint(&mut out, 0, 5);
        put_bytes(&mut out, &cfg.backup_recovery_wrapping_pubkey);
        // OUT-OF-ORDER: key 7 before key 6
        put_uint(&mut out, 0, 7);
        put_bytes(&mut out, &cfg.fleet_scope_id);
        put_uint(&mut out, 0, 6);
        put_bytes(&mut out, &cfg.anchor_root);
        assert_eq!(decode_config_map(&out), Err(ProvisionError::Malformed));
    }

    // ── §9 M2 negatives ─────────────────────────────────────────────────────────

    #[test]
    fn m2_round_trip_and_wrong_report_length() {
        let n_e = [0x22u8; 32];
        let report = vec![0x77u8; SNP_REPORT_LEN];
        let payload = encode_m2(&n_e, &report);
        let dec = decode_m2(&payload).unwrap();
        assert_eq!(dec.n_e, n_e);
        assert_eq!(dec.report, report);

        // wrong report length ⇒ TooLarge (the fixed-equality check, §9 too-large family)
        let bad = encode_m2(&n_e, &vec![0x77; SNP_REPORT_LEN - 1]);
        assert_eq!(decode_m2(&bad), Err(ProvisionError::TooLarge));
        let bad = encode_m2(&n_e, &vec![0x77; SNP_REPORT_LEN + 1]);
        assert_eq!(decode_m2(&bad), Err(ProvisionError::TooLarge));
        // report ABOVE the shared decoder's 4096 cap must STILL surface as TooLarge (not Malformed)
        // — the raised-cap (strict_decode_map_capped) fix.
        let bad = encode_m2(&n_e, &vec![0x77; 5000]);
        assert_eq!(decode_m2(&bad), Err(ProvisionError::TooLarge));
        // report ABOVE the MAX_PROV_PAYLOAD_LEN (8192) transport-framing-level cap must STILL be
        // TooLarge (the decode cap is MAX_MESSAGE_SIZE, not 8192) — compact job 9023 residual.
        let bad = encode_m2(&n_e, &vec![0x77; 9000]);
        assert_eq!(decode_m2(&bad), Err(ProvisionError::TooLarge));
    }

    // ── §9 M3 DoS caps (the load-bearing strict_decode_map_capped tests) ────────

    /// Build a structurally-valid M3 payload with arbitrary `config_map` and `cert` byte strings
    /// (used to exercise the field caps without needing a real signature/cert).
    fn m3_payload_with(config_map: &[u8], cert: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_uint(&mut out, 5, 6); // map(6)
        put_uint(&mut out, 0, 1);
        put_bytes(&mut out, config_map);
        put_uint(&mut out, 0, 2);
        put_bytes(&mut out, &[0x11; 32]); // N_p
        put_uint(&mut out, 0, 3);
        put_bytes(&mut out, &[0x22; 32]); // N_e
        put_uint(&mut out, 0, 4);
        put_bytes(&mut out, &[0x33; 32]); // report_hash
        put_uint(&mut out, 0, 5);
        put_bytes(&mut out, &[0x55; 64]); // Sig_PROV
        put_uint(&mut out, 0, 6);
        put_bytes(&mut out, cert);
        out
    }

    #[test]
    fn m3_config_map_over_cap_is_too_large_not_malformed() {
        // config_map of MAX_CONFIG_MAP_LEN+1. This MUST surface as TooLarge, NOT Malformed — the
        // whole reason strict_decode_map_capped exists (a >4096 bstr would otherwise hit the shared
        // decoder's internal cap and collapse into Malformed).
        let mut big_cfg = vec![0x59, 0x10, 0x01]; // bytes(4097) head
        big_cfg.extend(std::iter::repeat(0u8).take(MAX_CONFIG_MAP_LEN + 1));
        let payload = m3_payload_with(&big_cfg, &[0xc0; 64]);
        assert_eq!(decode_m3(&payload), Err(ProvisionError::TooLarge));
    }

    #[test]
    fn m3_provisioner_cert_over_cap_is_too_large() {
        let cert = vec![0xc0u8; MAX_PROV_CERT_LEN + 1];
        let cfg = encode_config_map(&sample_config());
        let payload = m3_payload_with(&cfg, &cert);
        assert_eq!(decode_m3(&payload), Err(ProvisionError::TooLarge));
    }

    #[test]
    fn m3_payload_over_cap_is_too_large() {
        // overall payload > MAX_PROV_PAYLOAD_LEN — a config_map bstr large enough to bust the cap,
        // checked before any CBOR parse.
        let mut big_cfg = vec![0x5A, 0x00, 0x20, 0x03]; // bytes(8195) head
        big_cfg.extend(std::iter::repeat(0u8).take(MAX_PROV_PAYLOAD_LEN + 50));
        let payload = m3_payload_with(&big_cfg, &[0xc0; 64]);
        assert_eq!(decode_m3(&payload), Err(ProvisionError::TooLarge));
    }

    #[test]
    fn m3_structural_round_trip() {
        let cfg = encode_config_map(&sample_config());
        let payload = m3_payload_with(&cfg, &[0xc0; 200]);
        let dec = decode_m3(&payload).unwrap();
        assert_eq!(dec.config_map_bytes, cfg);
        assert_eq!(dec.n_p, [0x11; 32]);
        assert_eq!(dec.n_e, [0x22; 32]);
        assert_eq!(dec.report_hash, [0x33; 32]);
        assert_eq!(dec.sig_prov, [0x55; 64]);
        assert_eq!(dec.provisioner_cert, vec![0xc0; 200]);
    }

    // ── §9 M4 round-trip ────────────────────────────────────────────────────────

    #[test]
    fn m4_round_trip() {
        let blob = vec![0xABu8; 500];
        let payload = encode_m4(&blob);
        let dec = decode_m4(&payload).unwrap();
        assert_eq!(dec.sealed_blob, blob);
    }

    /// Regression for the Medium finding: a realistic sealed keystore is ABOVE the shared decoder's
    /// 4096 cap (the reference fixture is ~4.2 KiB). Before the raised-cap fix, `decode_m4` rejected
    /// such a blob as a structural `Malformed`. It MUST round-trip.
    #[test]
    fn m4_realistic_oversized_sealed_blob_round_trips() {
        let blob = vec![0xABu8; 5000]; // > 4096, < MAX_KEYSTORE_BLOB_SIZE
        let payload = encode_m4(&blob);
        let dec = decode_m4(&payload).unwrap();
        assert_eq!(dec.sealed_blob, blob);
    }

    #[test]
    fn m4_sealed_blob_over_keystore_cap_is_too_large() {
        // A blob above MAX_KEYSTORE_BLOB_SIZE (the seal_body budget) ⇒ TooLarge, not Malformed.
        let blob = vec![0xABu8; MAX_KEYSTORE_BLOB_SIZE + 1];
        let payload = encode_m4(&blob);
        assert_eq!(decode_m4(&payload), Err(ProvisionError::TooLarge));
    }

    #[test]
    fn m4_wrong_key_rejected() {
        let mut bad = encode_m4(&[0xAB; 500]);
        bad[1] = 0x02; // key 2
        assert_eq!(decode_m4(&bad), Err(ProvisionError::Malformed));
    }
}
