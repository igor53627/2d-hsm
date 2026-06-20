#![cfg_attr(not(test), allow(dead_code))]
// Slices 25-2b-i..iii landed: codec + cert verify + verify-order integration. The module-level
// `allow(dead_code)` stays because the sole non-test caller — slice iv's stateful handshake driver
// (holds the session, calls verify_m3_in_order, mints+seals the keystore) — is not wired yet. Mirrors
// the staged-module convention (agent_boot / agent_boot_driver); drops once iv wires the inbound path.

//! Agent Gateway provisioning channel — wire format + M3 verify order (TASK-25, slices 25-2b-i..iii).
//!
//! Implements the **frozen** `provision_wire_version = 1` format defined in
//! `backlog/docs/agent-gateway-provisioning-wire-format.md` (25-2a):
//! - **i** — structural codec: envelope (magic/version/msg_type), per-state direction validation,
//!   M1-M4 encode/decode, §5.1 config_map, §2 DoS caps, the full §9 `ProvisionError` model.
//! - **ii** — provisioner-cert verify ([`verify_provisioner_cert`]): single-level X.509 leaf ← pinned
//!   operator CA root + the role EKU, via `x509-cert`.
//! - **iii** — the §6 verify-order integration ([`verify_m3_in_order`]): SHA3 session binding
//!   ([`compute_report_data`]/[`compute_report_hash`]), transcript reconstruction + `Sig_PROV`
//!   verify ([`verify_m3_transcript_and_sig`]) — binds the received M3 to THIS enclave session +
//!   the authenticated provisioner before config re-decode.
//!
//! Still deferred: **iv** mint+seal wiring (the in-TEE `enclave_scope_id` mint + `seal_body` that
//! produces M4) + the stateful handshake DRIVER that holds the session and calls
//! [`verify_m3_in_order`]; **v** golden-vector regen.
//!
//! **Scope — untrusted provisioner→enclave wire input.** M1/M3 arrive over the AF_VSOCK bootstrap
//! listener from a provisioner the enclave has not yet authenticated. Every field is length-capped
//! (§2 DoS caps) BEFORE any expensive parse, and every parse is strict-canonical-CBOR
//! (RFC 8949 §4.2.1) via [`crate::agent_cbor`], so a non-canonical or oversized input fails closed
//! with a distinguishable [`ProvisionError`] rather than reaching the crypto.

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
    // ── mint+seal arms (slice iv) ──
    /// The in-TEE CSPRNG (`getrandom`) failed — the `enclave_scope_id` mint or the seal nonce could
    /// not draw randomness — OR a successfully-drawn scope id was a rejected degenerate/fixture value
    /// (see [`mint_enclave_scope_id`]/[`validate_minted_scope_id`]: all-zero / [0xe1]/[0xf1] sentinels).
    /// Either way the AC#3/#4 host-uncontrollable provenance is unavailable; fail-closed.
    Csprng,
    /// `seal_body` rejected the freshly-constructed genesis body (a body this code just built should
    /// not fail `validate()`; a non-CSPRNG seal failure indicates an internal invariant break).
    SealFailed,
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
    // AC#7 provenance: fleet_scope_id must be a real fleet identity, not the zero id (which would
    // collapse fleet-scoped caps + misclassify as a SealFailed downstream via KeystoreBody::validate).
    if fleet_scope_id == [0u8; DIGEST_LEN] {
        return Err(ProvisionError::Malformed);
    }
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
// ════════════════════════════════════════════════════════════════════════════════
// provisioner_cert — DER X.509 leaf verify (single-level chain + role EKU)  (§7)
// ════════════════════════════════════════════════════════════════════════════════

use x509_cert::der::asn1::ObjectIdentifier;

/// Raw Ed25519 public-key / signature-key length (RFC 8032).
const ED25519_PUBKEY_LEN: usize = 32;

/// The dedicated **provisioner role EKU OID** (25-2b §7): `2.25.209175620`, under the private `2.25`
/// arc. A leaf under the operator CA MUST carry this OID in its Extended Key Usage extension; it is
/// the SOLE role marker (no Subject-string alternative — 25-2a-rev2 narrowing). A leaf issued for any
/// OTHER purpose (TLS client, code-signing, log-signing) lacks it ⇒ [`ProvisionError::UnauthorizedProvisioner`]
/// (confused-deputy defense — without it, ANY leaf under the operator CA is a valid provisioner).
///
/// **Arc value choice:** the spec's `2.25.<random>` is a private unregistered OID. `const-oid` (both
/// 0.9 and 0.10, used transitively by `x509-cert`) types its arc as `u32` AND caps each arc at
/// `ARC_MAX_BYTES = size_of::<u32> = 4` base-128 bytes (max value 268435455), so a full 128-bit
/// UUID-derived `2.25` value is unrepresentable. The frozen value is therefore an **arbitrary frozen
/// private OID under `2.25`**, seeded by the low 28 bits of candidate UUID
/// `6d847b22-9b6e-4c2f-8aa1-5f3e0c7b9d44`'s node id (`0x0C7B9D44` = 209175620), fitting the 4-byte-arc
/// limit (round-trip-verified). It is NOT the OID-encoding of that UUID (a `2.25` arc encodes the
/// integer itself; this is just a seed for an arbitrary value). Collision resistance is a non-issue:
/// the operator CA is the SOLE assigner, so the value space is far more than enough for one role marker.
pub(crate) const PROVISIONER_EKU_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.25.209175620");

/// The Ed25519 algorithm OID (RFC 8410: `id-Ed25519 = 1.3.101.112`). The provisioner leaf's SPKI
/// MUST use this algorithm with ABSENT parameters.
const ED25519_ALG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Read a DER tag+length head from `b`, returning `(header_len, content_len)`. A MINIMAL length
/// reader (short form + 1-4 byte long form) used ONLY to extract a sub-element's exact byte range
/// from an already-parsed cert — `x509-cert`/`der` do the structural parse + crypto. Rejects
/// indefinite length (minor 31), lengths >4 bytes, and truncation. Returns `Err(())` on any malformation.
fn der_head(b: &[u8]) -> Result<(usize, usize), ()> {
    let n = *b.get(1).ok_or(())?;
    let (hdr, content) = if n < 0x80 {
        (2, n as usize)
    } else {
        let k = (n & 0x7f) as usize;
        if k == 0 || k > 4 || b.len() < 2 + k {
            return Err(());
        }
        let mut len = 0usize;
        for i in 0..k {
            len = (len << 8) | b[2 + i] as usize;
        }
        (2 + k, len)
    };
    Ok((hdr, content))
}

/// Extract the EXACT `TBSCertificate` byte slice from a Certificate's DER (the first element of the
/// outer `SEQUENCE`). Used to verify the CA signature over the **original signed bytes** — NOT a
/// re-encoded TBS — so a cert whose TBS re-serializes differently under `x509-cert` still verifies iff
/// the CA actually signed those bytes (closes the re-encode availability hole: a legitimate non-canonical
/// cert is no longer falsely rejected). `cert_der` MUST already have been accepted by
/// `Certificate::from_der` (this fn is a byte-range slice, not a parser).
fn cert_tbs_bytes(cert_der: &[u8]) -> Result<&[u8], ()> {
    let (outer_hdr, _) = der_head(cert_der)?;
    let (tbs_hdr, tbs_len) = der_head(&cert_der[outer_hdr..])?;
    let end = outer_hdr
        .checked_add(tbs_hdr)
        .and_then(|s| s.checked_add(tbs_len))
        .ok_or(())?;
    if end > cert_der.len() {
        return Err(());
    }
    Ok(&cert_der[outer_hdr..end])
}

/// Verify the M3 `provisioner_cert` (§7) against the **pinned operator CA root** + the role EKU.
/// Returns the provisioner's Ed25519 verifying key (for slice iii's `Sig_PROV` verify).
///
/// **Single-level chain (MVP):** the leaf is signed DIRECTLY by the pinned root — no intermediate
/// CA, no path validation. This fn performs exactly five checks: (1) DER parse (strict — x509-cert/
/// der reject non-canonical input); (2) v3 + Ed25519 SPKI extraction (RFC 8410); (3) BOTH signature
/// `AlgorithmIdentifier`s (`tbs.signature` AND `cert.signature_algorithm`) MUST be Ed25519 with absent
/// params — algorithm agility is intentionally absent, the verifier fixes Ed25519; (4) one Ed25519
/// `verify_strict` of the cert signature over the **original TBS bytes** ([`cert_tbs_bytes`]) against
/// `operator_ca_root`; (5) the EKU extension MUST carry [`PROVISIONER_EKU_OID`].
///
/// **`operator_ca_root`** is the pinned root verifying key — compiled into the enclave binary at
/// build (the same binary-pinning discipline as the Q7 measurement allowlist); passed as a parameter
/// so the verify path is pure + testable, with the production pin wired by slice iv's install path.
/// Rotation = re-build with a new pin (the in-enclave clock-free epoch marker; §7 revocation).
///
/// **Signature is verified BEFORE the EKU check** (step 4 ≺ step 5): the EKU is only meaningful on an
/// AUTHENTICATED cert — a forgable cert's EKU is worthless, so authenticity is established first.
///
/// **Error taxonomy (§9):** malformed DER / non-v3 / non-Ed25519 SPKI OR signature algorithm / bad
/// signature encoding / non-canonical structure ⇒ [`ProvisionError::Malformed`]; signature not
/// verifying under the pinned root OR the role EKU missing/wrong ⇒
/// [`ProvisionError::UnauthorizedProvisioner`]. No wall-clock / `not_before`/`not_after` check (§7 —
/// the SNP TEE has no trusted clock; provisioner-cert lifecycle is CA-root rotation + optional
/// cert-serial denylist, NOT validity-window enforcement).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_provisioner_cert(
    cert_der: &[u8],
    operator_ca_root: &ed25519_dalek::VerifyingKey,
) -> Result<ed25519_dalek::VerifyingKey, ProvisionError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::Certificate;

    // 1. DER parse.
    let cert = Certificate::from_der(cert_der).map_err(|_| ProvisionError::Malformed)?;
    let tbs = &cert.tbs_certificate;

    // 2. v3 (extensions — incl. the role EKU — require v3); Ed25519 SPKI (RFC 8410: alg 1.3.101.112,
    //    parameters absent).
    if tbs.version != x509_cert::Version::V3 {
        return Err(ProvisionError::Malformed);
    }
    let spki = &tbs.subject_public_key_info;
    if spki.algorithm.oid != ED25519_ALG_OID || spki.algorithm.parameters.is_some() {
        return Err(ProvisionError::Malformed);
    }
    let prov_pub_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(ProvisionError::Malformed)?;
    if prov_pub_bytes.len() != ED25519_PUBKEY_LEN {
        return Err(ProvisionError::Malformed);
    }
    let prov_pub = VerifyingKey::from_bytes(
        prov_pub_bytes
            .try_into()
            .map_err(|_| ProvisionError::Malformed)?,
    )
    .map_err(|_| ProvisionError::Malformed)?;

    // 3. BOTH signature AlgorithmIdentifiers (RFC 5280 inner==outer) MUST be Ed25519 with absent
    //    parameters — algorithm agility is intentionally absent (the verifier fixes Ed25519), so a
    //    cert that advertises a different sig alg (even if its signature bits happen to verify) is
    //    rejected as Malformed before the crypto.
    let sig_alg_ok = |a: &x509_cert::spki::AlgorithmIdentifierOwned| {
        a.oid == ED25519_ALG_OID && a.parameters.is_none()
    };
    if !sig_alg_ok(&cert.signature_algorithm) || !sig_alg_ok(&tbs.signature) {
        return Err(ProvisionError::Malformed);
    }

    // 4. Cert signature over the ORIGINAL TBS bytes (not a re-encode), verified against the pinned
    //    operator CA root.
    let tbs_bytes = cert_tbs_bytes(cert_der).map_err(|_| ProvisionError::Malformed)?;
    let sig_bytes = cert.signature.as_bytes().ok_or(ProvisionError::Malformed)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| ProvisionError::Malformed)?;
    operator_ca_root
        .verify_strict(tbs_bytes, &sig)
        .map_err(|_| ProvisionError::UnauthorizedProvisioner)?;

    // 5. Role constraint: the dedicated EKU OID MUST be present (the sole role marker).
    let has_role = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| ProvisionError::Malformed)?
        .map(|(_, ExtendedKeyUsage(oids))| oids.contains(&PROVISIONER_EKU_OID))
        .unwrap_or(false);
    if !has_role {
        return Err(ProvisionError::UnauthorizedProvisioner);
    }

    Ok(prov_pub)
}
// ════════════════════════════════════════════════════════════════════════════════
// §6 verify-order integration: transcript reconstruction + Sig_PROV verify (slice 25-2b-iii)
// ════════════════════════════════════════════════════════════════════════════════

/// The 64-byte value the enclave commits to inside the M2 SNP report's `REPORT_DATA` field:
/// `SHA3-512(HANDSHAKE_DOMAIN ‖ N_p ‖ N_e)` (§4). Fits the 64-byte `REPORT_DATA` exactly. The
/// provisioner checks `SHA3-512(domain ‖ N_p ‖ N_e) == report.report_data` (mismatch ⇒
/// [`ProvisionError::AttestMismatch`] — the report is not for this challenge). Fixed-width nonces ⇒
/// no length-prefix needed (mirrors the anchor handshake).
///
/// **NB — provisioner-side check.** The ENCLAVE computes this to FILL the M2 `REPORT_DATA` (it does
/// NOT verify it); the `AttestMismatch` comparison is run by the PROVISIONER (the M2 receiver).
/// `verify_m3_in_order` (enclave side) binds the report only via `report_hash`
/// ([`compute_report_hash`]) in the transcript — it trusts the `session_report_hash` the driver
/// passes (slice iv guarantees that is SHA3-256 of the report THIS enclave emitted in M2).
pub(crate) fn compute_report_data(n_p: &[u8; NONCE_LEN], n_e: &[u8; NONCE_LEN]) -> [u8; 64] {
    use sha3::{Digest, Sha3_512};
    let mut h = Sha3_512::new();
    h.update(HANDSHAKE_DOMAIN);
    h.update(n_p);
    h.update(n_e);
    h.finalize().into()
}

/// `report_hash = SHA3-256(report)` — binds the WHOLE VCEK-signed report (measurement, TCB,
/// `report_data`, all auth fields) into the signed M3 transcript (§4, WF5 decision: strictly
/// stronger than hashing only `report_data`).
pub(crate) fn compute_report_hash(report: &[u8]) -> [u8; DIGEST_LEN] {
    use sha3::{Digest, Sha3_256};
    Sha3_256::digest(report).into()
}

/// `transcript_canonical = canonical-CBOR({1: config_map_bytes, 2: N_p, 3: N_e, 4: report_hash})`
/// (§5/§6). A flat 4-key map; key 1 is the SAME pre-encoded `config_map_bytes` bstr carried in M3 —
/// the transcript binds the EXACT config bytes the host sent, not a re-encoding.
///
/// **Provisioner identity = the authenticated Ed25519 PUBKEY, not the cert.** The transcript excludes
/// the cert by design: `Sig_PROV` (step 4) is verified under the pubkey step 2 authenticated FROM the
/// cert, so the binding is to the KEY. NB a **same-pubkey** cert substitution — a second valid leaf
/// under the pinned root + EKU, SAME key, different serial/subject — is NOT detected here (and is
/// HARMLESS: the same authenticated key signed). The cert BYTES / serial / subject / validity are NOT
/// cryptographically bound to M3; any future denylist / sealing / audit logic MUST key on the
/// authenticated PUBKEY, not the cert object (the cert is not stable across re-issuance).
pub(crate) fn transcript_canonical(
    config_map_bytes: &[u8],
    n_p: &[u8; NONCE_LEN],
    n_e: &[u8; NONCE_LEN],
    report_hash: &[u8; DIGEST_LEN],
) -> Vec<u8> {
    let mut out = Vec::new();
    put_uint(&mut out, 5, 4); // map(4)
    put_uint(&mut out, 0, 1);
    put_bytes(&mut out, config_map_bytes);
    put_uint(&mut out, 0, 2);
    put_bytes(&mut out, n_p);
    put_uint(&mut out, 0, 3);
    put_bytes(&mut out, n_e);
    put_uint(&mut out, 0, 4);
    put_bytes(&mut out, report_hash);
    out
}

/// `signed_bytes = PROVISION_DOMAIN ‖ transcript_canonical` — the message `Sig_PROV` covers (§6).
pub(crate) fn sig_prov_signed_bytes(
    config_map_bytes: &[u8],
    n_p: &[u8; NONCE_LEN],
    n_e: &[u8; NONCE_LEN],
    report_hash: &[u8; DIGEST_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROVISION_DOMAIN.len() + 4 * 4 + NONCE_LEN * 2 + DIGEST_LEN + config_map_bytes.len());
    out.extend_from_slice(PROVISION_DOMAIN);
    out.extend_from_slice(&transcript_canonical(config_map_bytes, n_p, n_e, report_hash));
    out
}

/// Steps 3 + 4 of the §6 verify order, against a provisioner pubkey already authenticated by step 2
/// ([`verify_provisioner_cert`]) and the live session's `(N_p, N_e, report_hash)`.
///
/// **Step 3 — transcript reconstruction:** byte-compare the M3 keys 2/3/4 to the session's
/// `(N_p, N_e, report_hash)`. Mismatch ⇒ [`ProvisionError::TranscriptMismatch`] (replay on a
/// different session / MITM — the load-bearing HIGH#1 test: a captured M3 replayed against a
/// DIFFERENT enclave session with a different `N_e` is rejected here).
///
/// **Step 4 — `Sig_PROV`:** re-compute `signed_bytes` from the M3 payload's key 1 + keys 2/3/4 +
/// `PROVISION_DOMAIN`, `verify_strict` against the provisioner cert's pubkey. Else
/// [`ProvisionError::BadSignature`]. (The signature binds the config bytes the host sent, so a host
/// cannot substitute config in transit — HIGH#1.)
///
/// Step 3 precedes step 4: the transcript compare validates the M3 keys 2/3/4 BEFORE they feed the
/// signed bytes, so a replayed M3 with wrong session nonces is rejected before the (more expensive)
/// signature verify.
pub(crate) fn verify_m3_transcript_and_sig(
    m3: &M3Config,
    prov_pub: &ed25519_dalek::VerifyingKey,
    session_n_p: &[u8; NONCE_LEN],
    session_n_e: &[u8; NONCE_LEN],
    session_report_hash: &[u8; DIGEST_LEN],
) -> Result<(), ProvisionError> {
    use ed25519_dalek::Signature;

    // Step 3: byte-exact transcript match against the live session.
    if &m3.n_p != session_n_p || &m3.n_e != session_n_e || &m3.report_hash != session_report_hash {
        return Err(ProvisionError::TranscriptMismatch);
    }

    // Step 4: Sig_PROV over PROVISION_DOMAIN ‖ canonical-CBOR({1: config_map_bytes, 2..=4 ...}).
    let signed = sig_prov_signed_bytes(
        &m3.config_map_bytes,
        &m3.n_p,
        &m3.n_e,
        &m3.report_hash,
    );
    let sig = Signature::from_bytes(&m3.sig_prov);
    prov_pub
        .verify_strict(&signed, &sig)
        .map_err(|_| ProvisionError::BadSignature)?;
    Ok(())
}

/// The FULL §6 verify order for an M3 message (the integration point — slice 25-2b-iii). Given the
/// raw M3 wire bytes (envelope + payload), the pinned operator CA root, and the live session's
/// `(N_p, N_e, report_hash)` (the `N_p` received in M1, the `N_e` + report the enclave emitted in
/// M2), run all five §6 steps in order and return the decoded config + the authenticated provisioner
/// pubkey (for slice iv's mint+seal).
///
/// **§6 steps (mapped to code):** (1) envelope + structural M3 decode — [`decode_envelope`] +
///   [`decode_m3`] (magic/version/msg_type=3, §2 DoS caps, canonical-CBOR payload; `decode_m3` is the
///   payload-structure part of §6 step 1, NOT a separate crypto step); (2) cert chain
///   [`verify_provisioner_cert`]; (3) transcript reconstruction (inside
///   [`verify_m3_transcript_and_sig`]); (4) `Sig_PROV` (inside `verify_m3_transcript_and_sig`);
///   (5) config re-decode [`decode_config_map`]. Only after all five pass does the caller mint+seal.
pub(crate) fn verify_m3_in_order(
    m3_message: &[u8],
    pinned_root: &ed25519_dalek::VerifyingKey,
    session_n_p: &[u8; NONCE_LEN],
    session_n_e: &[u8; NONCE_LEN],
    session_report_hash: &[u8; DIGEST_LEN],
) -> Result<(ProvisionConfig, ed25519_dalek::VerifyingKey), ProvisionError> {
    // §6 step 1: envelope (magic/version/msg_type=3) + the structural M3 decode that extracts the
    // cert/transcript/sig fields (§2 DoS caps + canonical-CBOR payload — NOT a separate crypto step).
    let (msg_type, payload) = decode_envelope(m3_message)?;
    if msg_type != MSG_M3_CONFIG {
        return Err(ProvisionError::Malformed);
    }
    let m3 = decode_m3(payload)?;
    // §6 step 2: cert chain (single-level leaf ← pinned root + role EKU).
    let prov_pub = verify_provisioner_cert(&m3.provisioner_cert, pinned_root)?;
    // §6 steps 3+4: transcript reconstruction (byte-compare to the live session) + Sig_PROV verify.
    verify_m3_transcript_and_sig(&m3, &prov_pub, session_n_p, session_n_e, session_report_hash)?;
    // §6 step 5: config re-decode (post-signature: the config bytes are now Sig_PROV-bound).
    let config = decode_config_map(&m3.config_map_bytes)?;
    Ok((config, prov_pub))
}
// ════════════════════════════════════════════════════════════════════════════════
// Mint + seal (slice 25-2b-iv) — the in-TEE enclave_scope_id provenance + the sealed M4 blob
// ════════════════════════════════════════════════════════════════════════════════

use crate::agent_keystore::{seal_body, AuditRing, FaucetState, KeystoreBody, KeystoreConfig, KeystoreError};

/// Mint the per-enclave `enclave_scope_id` (AC#3/#4 — the load-bearing host-uncontrollable
/// provenance): a RANDOM 32-byte id drawn from the platform CSPRNG (`getrandom`), in-TEE, exactly
/// once at provisioning. This is the SOLE field the host cannot supply (the §5.1 wire map has NO key
/// for it — I2). NEVER the `[0xe1;32]` / `[0xf1;32]` test sentinels (those are `#[cfg(test)]` /
/// lab-gated fixtures; a clone reproducing a known id would defeat the 18-2 byte-compare). An all-zero
/// id is rejected (a degenerate CSPRNG output / clone-replay vector; `KeystoreBody::validate` would
/// also reject it downstream — checked here for a clear provenance error).
pub(crate) fn mint_enclave_scope_id() -> Result<[u8; DIGEST_LEN], ProvisionError> {
    let mut id = [0u8; DIGEST_LEN];
    getrandom::getrandom(&mut id).map_err(|_| ProvisionError::Csprng)?;
    validate_minted_scope_id(&id)?;
    Ok(id)
}

/// Pure provenance guard on a drawn `enclave_scope_id` (AC#4): reject the degenerate / known-fixture
/// ids a clone could reproduce to defeat the 18-2 byte-compare — all-zero, and the `[0xe1;32]`/
/// `[0xf1;32]` test sentinels. A sound CSPRNG never returns these (2^-256 each); separated from the
/// `getrandom` draw so the rejection is deterministically testable. NB a faulty/faulted RNG that DID
/// draw one is caught here (not silently sealed) — defense-in-depth, not a substitute for a sound CSPRNG.
pub(crate) fn validate_minted_scope_id(id: &[u8; DIGEST_LEN]) -> Result<(), ProvisionError> {
    if id == &[0u8; DIGEST_LEN] || id == &[0xe1u8; 32] || id == &[0xf1u8; 32] {
        return Err(ProvisionError::Csprng);
    }
    Ok(())
}

/// Construct the production **provisioned** `KeystoreBody` (genesis-equivalent initial state) from the
/// verified provisioner config + the freshly-minted `enclave_scope_id` (25-1 Q2: the enclave seals its
/// OWN keystore — the provisioner sends only the public config; the plaintext never leaves the TEE).
///
/// **Basket mapping (25-1 Q4):** (A) enclave-minted → `enclave_scope_id` (the param); (B) provisioner-
/// supplied (the 7 fields from [`ProvisionConfig`]); (C) enclave-init deterministic →
/// `monotonic_treasury_config_version = 1`, `authority_epoch = 0` (§5.1). The faucet is genesis-ZERO
/// (`cumulative_signing_budget = [0;32]` ⇒ §2 fails closed until a CONFIGURE_TREASURY budget is sealed);
/// `entries`/`counters` are empty (keys/caps are minted later by GENERATE_KEYS). Mirrors the genesis
/// init of `boot_agent_keystore::genesis_body`, MINUS the test sentinels + with the basket-C version
/// pinned to the spec's `1` (the lab `genesis_body` uses `monotonic_treasury_config_version = 0`; prod
/// pins `1` per §5.1 — the divergence is intentional, §5.1 is authoritative for production).
///
/// **`enclave_scope_id` is NOT attested in M2 / the M3 transcript** — it is minted HERE (at seal time,
/// inside `on_m3` after the §6 verify), host-uncontrollable by construction (the §5.1 wire map has NO
/// field for it — I2; the host never sees it until it is sealed). AC#2's "mint before M2 / attested-
/// channel binding" was the 25-1 design-doc concept; the FROZEN 25-2a format binds only
/// `(config, N_p, N_e, report_hash)` and carries no scope id — so the id's provenance is STRUCTURAL
/// (host cannot supply it), not a per-field attestation.
pub(crate) fn build_provisioned_keystore_body(
    config: &ProvisionConfig,
    enclave_scope_id: [u8; DIGEST_LEN],
) -> KeystoreBody {
    KeystoreBody {
        config: KeystoreConfig {
            twod_chain_id: config.twod_chain_id,
            environment_identifier: config.environment_identifier.clone(),
            admin_authority_pk: config.admin_authority_pk,
            recovery_authority_pk: config.recovery_authority_pk,
            backup_recovery_wrapping_pubkey: config.backup_recovery_wrapping_pubkey.clone(),
            monotonic_treasury_config_version: 1, // basket C init (§5.1)
            authority_epoch: 0, // basket C init (§5.1)
            anchor_root: config.anchor_root,
            enclave_scope_id,
            fleet_scope_id: config.fleet_scope_id,
        },
        entries: Vec::new(),
        counters: Vec::new(),
        faucet: FaucetState {
            per_dispense_max_amount: [0; 32],
            max_gas_limit: 0,
            max_effective_gas_fee_rate: 0,
            cumulative_native_spend: [0; 32],
            lifetime_spend: [0; 32],
            circuit_breaker_threshold: None,
            cumulative_signing_budget: [0; 32], // §2: unconfigured ⇒ fails closed
        },
        audit: AuditRing {
            records: Vec::new(),
            capacity: 256,
            last_exported_seq: 0,
            next_seq: 1,
        },
        freshness_epoch: 1,
        structural_version: 1,
        strict_recovery_counter: 0,
    }
}

/// Build the provisioned body + `seal_body` it under the measurement-derived provisioning root → the
/// M4 `sealed_blob` (magic `2DAGTKS\0`). `provisioning_root` + `enclave_measurement` are runtime
/// values (the driver derives them from the SNP launch measurement); passed as params so the seal path
/// is pure/testable. A non-CSPRNG seal failure maps to [`ProvisionError::SealFailed`] (a body this code
/// just built should not fail `validate()` — indicates an internal invariant break).
pub(crate) fn seal_provisioned_keystore(
    config: &ProvisionConfig,
    enclave_scope_id: [u8; DIGEST_LEN],
    provisioning_root: &[u8; 32],
    enclave_measurement: &[u8],
) -> Result<Vec<u8>, ProvisionError> {
    let body = build_provisioned_keystore_body(config, enclave_scope_id);
    seal_body(&body, provisioning_root, enclave_measurement).map_err(|e| match e {
        KeystoreError::Csprng => ProvisionError::Csprng,
        _ => ProvisionError::SealFailed,
    })
}

/// The pure (transport-free) provisioning handshake session — the stateful caller of
/// [`verify_m3_in_order`] + [`mint_enclave_scope_id`] + [`seal_provisioned_keystore`]. The runtime
/// driver (the `twod-hsm-agent-gateway` bootstrap bin) owns the AF_VSOCK listener + the SNP report
/// fetch and calls [`ProvisionSession::on_m1`] / [`ProvisionSession::on_m3`]; this struct holds ONLY
/// the session state, so the handshake logic is CI-testable without SNP/transport.
#[derive(Debug)]
pub(crate) struct ProvisionSession {
    pinned_root: ed25519_dalek::VerifyingKey,
    seal_root: [u8; 32],
    measurement: Vec<u8>,
    n_p: Option<[u8; DIGEST_LEN]>,
    n_e: Option<[u8; DIGEST_LEN]>,
    state: SessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    /// Awaiting M1 (the provisioner's challenge).
    AwaitingM1,
    /// M1 received, N_e minted, M2 emitted; awaiting M3 (the report is fetched between, by the driver).
    AwaitingM3,
    /// M3 verified + keystore minted+sealed (M4 emitted). Terminal — the bootstrap listener tears down.
    Done,
    /// A verify/mint/seal error during `on_m3` — the session is CONSUMED (terminal). Any M3 attempt
    /// burns the session nonces, so the untrusted host cannot retry forged M3s against a fixed `N_e`
    /// (static-target / fault-injection / oracle defense — the host must restart from M1 = fresh N_e +
    /// fresh provisioner signature). One-shot failure semantics.
    Failed,
}

impl ProvisionSession {
    /// New session. `pinned_root` = the compiled-in operator CA root; `seal_root` + `measurement` =
    /// the runtime measurement-derived keystore-seal inputs.
    pub(crate) fn new(
        pinned_root: ed25519_dalek::VerifyingKey,
        seal_root: [u8; 32],
        measurement: Vec<u8>,
    ) -> Self {
        Self {
            pinned_root,
            seal_root,
            measurement,
            n_p: None,
            n_e: None,
            state: SessionState::AwaitingM1,
        }
    }

    /// M1 handling: record the provisioner's challenge nonce `N_p`, mint the enclave session nonce
    /// `N_e`, and compute `report_data` (§4) — the value the driver embeds in the M2 SNP report's
    /// `REPORT_DATA` field. Returns `(N_e, report_data)` so the driver can build + emit M2. The driver
    /// then fetches the SNP report and passes it back to [`on_m3`](Self::on_m3). Calling out of order
    /// (before M1, or after M3) ⇒ [`ProvisionError::Malformed`].
    pub(crate) fn on_m1(
        &mut self,
        n_p: [u8; DIGEST_LEN],
    ) -> Result<([u8; DIGEST_LEN], [u8; 64]), ProvisionError> {
        if self.state != SessionState::AwaitingM1 {
            return Err(ProvisionError::Malformed);
        }
        let mut n_e = [0u8; DIGEST_LEN];
        getrandom::getrandom(&mut n_e).map_err(|_| ProvisionError::Csprng)?;
        let report_data = compute_report_data(&n_p, &n_e);
        self.n_p = Some(n_p);
        self.n_e = Some(n_e);
        self.state = SessionState::AwaitingM3;
        Ok((n_e, report_data))
    }

    /// M3 handling: the full §6 verify order against THIS session, then mint `enclave_scope_id` +
    /// seal the keystore. `report` = the M2 SNP report the driver fetched (its SHA3-256 is the
    /// transcript's `report_hash`). Returns the decoded `ProvisionConfig` + the sealed M4 blob on
    /// success. Terminal on success (state → `Done`); a second `on_m3` ⇒ [`ProvisionError::Malformed`].
    /// Errors propagate the failing §6 step (e.g. [`TranscriptMismatch`](ProvisionError::TranscriptMismatch)
    /// if the M3 was replayed against this session, [`BadSignature`](ProvisionError::BadSignature),
    pub(crate) fn on_m3(
        &mut self,
        m3_message: &[u8],
        report: &[u8],
    ) -> Result<(ProvisionConfig, Vec<u8>), ProvisionError> {
        if self.state != SessionState::AwaitingM3 {
            return Err(ProvisionError::Malformed);
        }
        let n_p = self.n_p.expect("AwaitingM3 ⇒ n_p set");
        let n_e = self.n_e.expect("AwaitingM3 ⇒ n_e set");
        let report_hash = compute_report_hash(report);
        // One-shot failure semantics: ANY error (verify / mint / seal) CONSUMES the session —
        // transition to `Failed` regardless of outcome, so the untrusted host cannot retry forged M3s
        // against the same `N_e` (static-target / fault-injection / oracle defense; the host must
        // restart from M1 = a fresh N_e + fresh provisioner signature).
        let outcome = (|| {
            let (config, _prov_pub) =
                verify_m3_in_order(m3_message, &self.pinned_root, &n_p, &n_e, &report_hash)?;
            let scope_id = mint_enclave_scope_id()?;
            let sealed =
                seal_provisioned_keystore(&config, scope_id, &self.seal_root, &self.measurement)?;
            Ok((config, sealed))
        })();
        self.state = if outcome.is_ok() { SessionState::Done } else { SessionState::Failed };
        outcome
    }

    /// Current session state (for the driver / tests).
    pub(crate) fn state(&self) -> SessionState {
        self.state
    }
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
            fleet_scope_id: [0xf5; 32], // a provisioning-test fleet id, DISTINCT from the [0xf1;32] keystore test fixture (AC#7)
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
    // ── §7 provisioner_cert verify (slice 25-2b-ii) ──────────────────────────────

    use ed25519_dalek::{SigningKey, VerifyingKey};

    /// The frozen provisioner EKU OID (the const is `pub(crate)`; this re-exports it for test use).
    fn eku_oid() -> ObjectIdentifier {
        PROVISIONER_EKU_OID
    }
    /// Mint a v3 Ed25519 leaf cert signed by `ca_sk` (the operator CA root). `ekus` selects the
    /// Extended Key Usage extension: `Some(&[eku_oid()])` ⇒ a valid provisioner cert; `Some(&[other])`
    /// ⇒ wrong role; `None` ⇒ no EKU. TEST-ONLY scaffolding (direct `TbsCertificate` assembly — no
    /// x509-cert builder/signature-feature dependency; signs with the crate's direct Ed25519 sign).
    fn mint_cert(
        provisioner_pub: &VerifyingKey,
        ca_sk: &SigningKey,
        ekus: Option<&[x509_cert::der::asn1::ObjectIdentifier]>,
    ) -> Vec<u8> {
        mint_cert_malform(provisioner_pub, ca_sk, ekus, None)
    }

    /// A cert malformation for the [`mint_cert_malform`] negative fixtures (each exercises one
    /// `Malformed` branch of [`verify_provisioner_cert`]).
    enum Malform {
        V1,               // version 1 (no extensions) — exercises the v3 gate
        WrongSpkiAlg,     // SPKI algorithm = Ed448, not Ed25519
        SpkiParamsPresent, // SPKI algorithm carries NULL params (RFC 8410 forbids them)
        WrongPubkeyLen,   // SPKI subjectPublicKey = 31 bytes (not 32)
        WrongSigAlg,      // BOTH signature AlgorithmIdentifiers = Ed448 (SPKI stays Ed25519)
        WrongSigAlgInner, // only tbs.signature (inner) = Ed448; outer stays Ed25519
        WrongSigAlgOuter, // only cert.signature_algorithm (outer) = Ed448; inner stays Ed25519
    }

    /// `mint_cert` + an optional single [`Malform`]. Each malformation is applied independently and
    /// produces a structurally-valid DER cert (so it parses) that fails exactly one verify branch.
    fn mint_cert_malform(
        provisioner_pub: &VerifyingKey,
        ca_sk: &SigningKey,
        ekus: Option<&[x509_cert::der::asn1::ObjectIdentifier]>,
        malform: Option<Malform>,
    ) -> Vec<u8> {
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::der::asn1::{Any, BitString, OctetString};
        use x509_cert::der::{Encode, Tag};
        use x509_cert::ext::Extension;
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::time::Validity;
        use x509_cert::{Certificate, TbsCertificate, Version};
        use ed25519_dalek::Signer;

        let ed448 = || ObjectIdentifier::new_unwrap("1.3.101.113");
        let ed25519 = || AlgorithmIdentifierOwned {
            oid: ED25519_ALG_OID.clone(),
            parameters: None,
        };
        let spki_alg = match malform {
            Some(Malform::WrongSpkiAlg) => AlgorithmIdentifierOwned {
                oid: ed448(),
                parameters: None,
            },
            Some(Malform::SpkiParamsPresent) => AlgorithmIdentifierOwned {
                oid: ED25519_ALG_OID.clone(),
                parameters: Some(Any::new(Tag::Null, Vec::<u8>::new()).unwrap()),
            },
            _ => ed25519(),
        };
        // Inner (tbs.signature) and outer (cert.signature_algorithm) are set INDEPENDENTLY so the
        // wrong-inner-only / wrong-outer-only malforms pin that verify checks EACH (not just one).
        let ed448_alg = || AlgorithmIdentifierOwned {
            oid: ed448(),
            parameters: None,
        };
        let tbs_sig_alg = match malform {
            Some(Malform::WrongSigAlg) | Some(Malform::WrongSigAlgInner) => ed448_alg(),
            _ => ed25519(),
        };
        let cert_sig_alg = match malform {
            Some(Malform::WrongSigAlg) | Some(Malform::WrongSigAlgOuter) => ed448_alg(),
            _ => ed25519(),
        };
        let version = match malform {
            Some(Malform::V1) => Version::V1,
            _ => Version::V3,
        };
        let full_pub = provisioner_pub.to_bytes();
        let pubkey_bytes: &[u8] = match malform {
            Some(Malform::WrongPubkeyLen) => &full_pub[..31],
            _ => &full_pub,
        };

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_alg,
            subject_public_key: BitString::from_bytes(pubkey_bytes).unwrap(),
        };
        let validity = Validity::from_now(Duration::from_secs(86400)).unwrap();
        // v1 certs cannot carry extensions; force None there so the DER stays valid.
        let extensions = if version == Version::V1 {
            None
        } else {
            ekus.map(|oids| {
                let eku_der = ExtendedKeyUsage(oids.to_vec()).to_der().unwrap();
                vec![Extension {
                    extn_id: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37"),
                    critical: false,
                    extn_value: OctetString::new(eku_der).unwrap(),
                }]
            })
        };
        let tbs = TbsCertificate {
            version,
            serial_number: SerialNumber::from(1u32),
            signature: tbs_sig_alg.clone(),
            issuer: Name::from_str("CN=test-operator-ca").unwrap(),
            validity,
            subject: Name::from_str("CN=test-provisioner").unwrap(),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions,
        };
        let tbs_der = tbs.to_der().unwrap();
        let sig = ca_sk.sign(&tbs_der);
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: cert_sig_alg,
            signature: BitString::from_bytes(&sig.to_bytes()).unwrap(),
        };
        cert.to_der().unwrap()
    }

    /// Operator CA root keypair (deterministic test key).
    fn test_ca() -> SigningKey {
        SigningKey::from_bytes(&[0xC1; 32])
    }


    #[test]
    fn cert_valid_verifies_and_returns_provisioner_pubkey() {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let prov_vk = prov.verifying_key();
        let cert = mint_cert(&prov_vk, &ca, Some(&[eku_oid()]));
        // Verifies against the pinned CA root and returns the provisioner's pubkey.
        assert_eq!(verify_provisioner_cert(&cert, &ca.verifying_key()), Ok(prov_vk));
    }

    #[test]
    fn cert_signed_by_wrong_ca_is_unauthorized() {
        // A leaf signed by a DIFFERENT CA key does not verify under the pinned root.
        let rogue_ca = SigningKey::from_bytes(&[0xC2; 32]);
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert(&prov.verifying_key(), &rogue_ca, Some(&[eku_oid()]));
        assert_eq!(
            verify_provisioner_cert(&cert, &test_ca().verifying_key()),
            Err(ProvisionError::UnauthorizedProvisioner)
        );
    }

    #[test]
    fn cert_missing_eku_is_unauthorized() {
        // A leaf with NO Extended Key Usage at all — the role marker is absent.
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert(&prov.verifying_key(), &ca, None);
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::UnauthorizedProvisioner)
        );
    }

    #[test]
    fn cert_wrong_eku_is_unauthorized() {
        // A leaf whose EKU is a DIFFERENT OID (e.g. a TLS-client-usage cert under the same CA) —
        // it chains to the root but lacks the provisioning role marker.
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let other_oid =
            x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"); // id-kp-clientAuth
        let cert = mint_cert(&prov.verifying_key(), &ca, Some(&[other_oid]));
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::UnauthorizedProvisioner)
        );
    }

    #[test]
    fn cert_malformed_der_is_malformed() {
        let ca = test_ca();
        // Truncated / garbage DER.
        assert_eq!(
            verify_provisioner_cert(&[0x30, 0x05], &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
        assert_eq!(
            verify_provisioner_cert(&[0xDE, 0xAD, 0xBE, 0xEF], &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    // ── Medium finding: each Malformed branch must be exercised (not just garbage-DER) ─────

    #[test]
    fn cert_non_v3_is_malformed() {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::V1),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn cert_wrong_spki_alg_is_malformed() {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::WrongSpkiAlg),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn cert_spki_params_present_is_malformed() {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::SpkiParamsPresent),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn cert_wrong_pubkey_len_is_malformed() {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::WrongPubkeyLen),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn cert_wrong_sig_alg_is_malformed() {
        // SPKI stays Ed25519, but the signature AlgorithmIdentifiers advertise Ed448 — the
        // inner==outer alg check (RFC 5280) rejects it as Malformed before the crypto.
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::WrongSigAlg),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn cert_wrong_sig_alg_inner_only_is_malformed() {
        // Only the INNER tbs.signature advertises Ed448 (outer stays Ed25519) — pins that verify
        // checks the inner alg, not just the outer (compact 9051 residual).
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::WrongSigAlgInner),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn cert_wrong_sig_alg_outer_only_is_malformed() {
        // Only the OUTER cert.signature_algorithm advertises Ed448 (inner stays Ed25519) — pins that
        // verify checks the outer alg independently of the inner.
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert_malform(
            &prov.verifying_key(),
            &ca,
            Some(&[eku_oid()]),
            Some(Malform::WrongSigAlgOuter),
        );
        assert_eq!(
            verify_provisioner_cert(&cert, &ca.verifying_key()),
            Err(ProvisionError::Malformed)
        );
    }

    // ── §6 verify-order integration (slice 25-2b-iii) ────────────────────────────

    #[test]
    fn report_data_and_report_hash_golden() {
        // SHA3-512(HANDSHAKE_DOMAIN ‖ [0x11;32] ‖ [0x22;32]) and SHA3-256([0x77;1184]),
        // computed independently (Python hashlib) — pins the domain + hash construction.
        let rd = compute_report_data(&[0x11; 32], &[0x22; 32]);
        assert_eq!(
            hex::encode(rd),
            "313125647c6236d95a0acc96b662567d6f3809585c87530bad3ae4a8f3fe06b0\
             07e8ac42b399046cabd1273282b96c9f1dc6e85a49e40541f54b2fd8b9bc1bfb"
        );
        let rh = compute_report_hash(&vec![0x77u8; SNP_REPORT_LEN]);
        assert_eq!(
            hex::encode(rh),
            "d424c6a0944f583c6aefacebf0102898505a4cd07c8b01ccca1f1b271fe9034b"
        );
    }

    #[test]
    fn transcript_canonical_shape() {
        let cfg = vec![0xCDu8; 10]; // stand-in config bytes
        let t = transcript_canonical(&cfg, &[0x11; 32], &[0x22; 32], &[0x33; 32]);
        // map(4), keys 1..=4 ascending, each value a bstr.
        assert_eq!(t[0], 0xA4); // map(4)
        assert_eq!(&t[1..3], &[0x01, 0x4A]); // key 1 + bytes(10) (major 2 | 10)
        // (the rest is canonical bstr encoding of the fixed-width fields)
        // round-trip via strict_decode_map_capped to confirm it's canonical
        use crate::agent_cbor::strict_decode_map_capped;
        assert!(strict_decode_map_capped(&t, MAX_PROV_PAYLOAD_LEN as u64).is_ok());
    }

    /// Encode an M3 payload (map{1: config_map, 2: N_p, 3: N_e, 4: report_hash, 5: Sig_PROV, 6: cert})
    /// and wrap it in the M3 envelope. The signature is passed in (so a tampered sig can be supplied
    /// by the bad-signature test).
    fn build_m3_message(
        config_map: &[u8],
        n_p: &[u8; NONCE_LEN],
        n_e: &[u8; NONCE_LEN],
        report_hash: &[u8; DIGEST_LEN],
        sig_prov: &[u8; SIG_PROV_LEN],
        cert: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        put_uint(&mut payload, 5, 6); // map(6)
        put_uint(&mut payload, 0, 1);
        put_bytes(&mut payload, config_map);
        put_uint(&mut payload, 0, 2);
        put_bytes(&mut payload, n_p);
        put_uint(&mut payload, 0, 3);
        put_bytes(&mut payload, n_e);
        put_uint(&mut payload, 0, 4);
        put_bytes(&mut payload, report_hash);
        put_uint(&mut payload, 0, 5);
        put_bytes(&mut payload, sig_prov);
        put_uint(&mut payload, 0, 6);
        put_bytes(&mut payload, cert);
        encode_envelope(MSG_M3_CONFIG, &payload)
    }

    /// Build a fully-valid M3 message signed by `prov_sk` for the given session.
    fn mint_m3_message(
        prov_sk: &SigningKey,
        cert: &[u8],
        config_map: &[u8],
        n_p: &[u8; NONCE_LEN],
        n_e: &[u8; NONCE_LEN],
        report_hash: &[u8; DIGEST_LEN],
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = prov_sk
            .sign(&sig_prov_signed_bytes(config_map, n_p, n_e, report_hash))
            .to_bytes();
        build_m3_message(config_map, n_p, n_e, report_hash, &sig, cert)
    }

    /// A valid M3 + the session it was signed for + the provisioner keypair + the pinned root.
    fn valid_m3_and_session() -> (SigningKey, SigningKey, Vec<u8>, [u8; 32], [u8; 32], [u8; 32], Vec<u8>) {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert(&prov.verifying_key(), &ca, Some(&[eku_oid()]));
        let cfg = encode_config_map(&sample_config());
        let (n_p, n_e, report_hash) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        let m3 = mint_m3_message(&prov, &cert, &cfg, &n_p, &n_e, &report_hash);
        (ca, prov, m3, n_p, n_e, report_hash, cert)
    }

    #[test]
    fn verify_m3_in_order_full_happy_path() {
        let (ca, _prov, m3, n_p, n_e, report_hash, _cert) = valid_m3_and_session();
        let (config, prov_pub) =
            verify_m3_in_order(&m3, &ca.verifying_key(), &n_p, &n_e, &report_hash).unwrap();
        assert_eq!(config, sample_config());
        assert_eq!(prov_pub, _prov.verifying_key());
    }

    #[test]
    fn verify_m3_replay_against_different_session_is_transcript_mismatch() {
        // HIGH#1: a captured M3 replayed against a DIFFERENT enclave session (different N_e) ⇒
        // TranscriptMismatch (the session binding the signature cannot forge).
        let (ca, _prov, m3, n_p, _n_e, _report_hash, _cert) = valid_m3_and_session();
        let other_n_e = [0x99u8; 32];
        let other_report_hash = [0x88u8; 32];
        assert_eq!(
            verify_m3_in_order(&m3, &ca.verifying_key(), &n_p, &other_n_e, &other_report_hash),
            Err(ProvisionError::TranscriptMismatch)
        );
    }

    #[test]
    fn verify_m3_bad_signature_is_bad_signature() {
        // Tamper Sig_PROV (transcript matches, but the signature no longer verifies under prov_pub).
        let (ca, prov, _m3, n_p, n_e, report_hash, cert) = valid_m3_and_session();
        let cfg = encode_config_map(&sample_config());
        use ed25519_dalek::Signer;
        let mut sig = prov
            .sign(&sig_prov_signed_bytes(&cfg, &n_p, &n_e, &report_hash))
            .to_bytes();
        sig[0] ^= 0xFF; // flip a signature bit
        let tampered = build_m3_message(&cfg, &n_p, &n_e, &report_hash, &sig, &cert);
        assert_eq!(
            verify_m3_in_order(&tampered, &ca.verifying_key(), &n_p, &n_e, &report_hash),
            Err(ProvisionError::BadSignature)
        );
    }

    #[test]
    fn verify_m3_unauthorized_cert_is_unauthorized_provisioner() {
        // Step-2 failure: a cert signed by the wrong CA is caught before the transcript/sig steps.
        let rogue_ca = SigningKey::from_bytes(&[0xC2; 32]);
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert(&prov.verifying_key(), &rogue_ca, Some(&[eku_oid()]));
        let cfg = encode_config_map(&sample_config());
        let (n_p, n_e, report_hash) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        let m3 = mint_m3_message(&prov, &cert, &cfg, &n_p, &n_e, &report_hash);
        assert_eq!(
            verify_m3_in_order(&m3, &test_ca().verifying_key(), &n_p, &n_e, &report_hash),
            Err(ProvisionError::UnauthorizedProvisioner)
        );
    }

    #[test]
    fn verify_m3_bad_envelope_is_malformed() {
        let (ca, _prov, m3, n_p, n_e, report_hash, _cert) = valid_m3_and_session();
        let mut bad = m3.clone();
        bad[0] = 0x00; // corrupt magic
        assert_eq!(
            verify_m3_in_order(&bad, &ca.verifying_key(), &n_p, &n_e, &report_hash),
            Err(ProvisionError::BadMagic)
        );
    }

    #[test]
    fn verify_m3_wrong_msg_type_is_malformed() {
        // A well-formed envelope carrying a NON-M3 msg_type (e.g. M2) is rejected by the type gate
        // (exercises the `msg_type != MSG_M3_CONFIG` check, distinct from the magic-corruption case).
        let (ca, _prov, m3, n_p, n_e, report_hash, _cert) = valid_m3_and_session();
        // Rewrite the envelope's msg_type byte (offset 9) to M2.
        let mut wrong_type = m3.clone();
        wrong_type[9] = MSG_M2_ATTEST;
        assert_eq!(
            verify_m3_in_order(&wrong_type, &ca.verifying_key(), &n_p, &n_e, &report_hash),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn verify_m3_config_substitution_is_bad_signature() {
        // HIGH#1 direct: the host cannot swap config in transit. Sign config A, then ship config B
        // under config A's Sig_PROV (same session + cert) ⇒ BadSignature (the transcript binds the
        // EXACT config_map_bytes; a different config makes the signed_bytes mismatch the signature).
        let (ca, prov, _m3, n_p, n_e, report_hash, cert) = valid_m3_and_session();
        use ed25519_dalek::Signer;
        let cfg_a = encode_config_map(&sample_config());
        // config B: a DIFFERENT but valid config (different chain_id).
        let mut cfg_b = sample_config();
        cfg_b.twod_chain_id = 99999;
        let cfg_b = encode_config_map(&cfg_b);
        // Sign over config A's transcript, but ship config B bytes.
        let sig = prov
            .sign(&sig_prov_signed_bytes(&cfg_a, &n_p, &n_e, &report_hash))
            .to_bytes();
        let swapped = build_m3_message(&cfg_b, &n_p, &n_e, &report_hash, &sig, &cert);
        assert_eq!(
            verify_m3_in_order(&swapped, &ca.verifying_key(), &n_p, &n_e, &report_hash),
            Err(ProvisionError::BadSignature)
        );
    }

    #[test]
    fn verify_m3_replay_n_e_only_mismatch_is_transcript_mismatch() {
        // Isolate the N_e binding: only N_e differs (N_p + report_hash still match) ⇒
        // TranscriptMismatch. Pins that the guard keys on N_e, not just report_hash.
        let (ca, _prov, m3, n_p, n_e, report_hash, _cert) = valid_m3_and_session();
        let mut other_n_e = n_e;
        other_n_e[0] ^= 0xFF; // only N_e differs
        assert_eq!(
            verify_m3_in_order(&m3, &ca.verifying_key(), &n_p, &other_n_e, &report_hash),
            Err(ProvisionError::TranscriptMismatch)
        );
    }

    #[test]
    fn verify_m3_replay_report_hash_only_mismatch_is_transcript_mismatch() {
        // Isolate the report_hash binding: only report_hash differs ⇒ TranscriptMismatch.
        let (ca, _prov, m3, n_p, n_e, report_hash, _cert) = valid_m3_and_session();
        let mut other_rh = report_hash;
        other_rh[0] ^= 0xFF;
        assert_eq!(
            verify_m3_in_order(&m3, &ca.verifying_key(), &n_p, &n_e, &other_rh),
            Err(ProvisionError::TranscriptMismatch)
        );
    }

    #[test]
    fn verify_m3_replay_n_p_only_mismatch_is_transcript_mismatch() {
        // Isolate the N_p (challenge) binding: only N_p differs (N_e + report_hash match) ⇒
        // TranscriptMismatch — completes the keys-2/3/4 coverage (compact/codex residual).
        let (ca, _prov, m3, n_p, n_e, report_hash, _cert) = valid_m3_and_session();
        let mut other_np = n_p;
        other_np[0] ^= 0xFF;
        assert_eq!(
            verify_m3_in_order(&m3, &ca.verifying_key(), &other_np, &n_e, &report_hash),
            Err(ProvisionError::TranscriptMismatch)
        );
    }

    // ── mint + seal + session (slice 25-2b-iv) ─────────────────────────────────

    #[test]
    fn mint_enclave_scope_id_is_random_nonzero_distinct() {
        let a = mint_enclave_scope_id().unwrap();
        let b = mint_enclave_scope_id().unwrap();
        assert_ne!(a, [0u8; 32], "minted scope id must not be all-zero");
        assert_ne!(a, [0xe1u8; 32], "must NOT be the test sentinel");
        assert_ne!(a, b, "two mints must differ (host-uncontrollable randomness)");
    }

    #[test]
    fn build_provisioned_body_carries_config_and_genesis_state() {
        let cfg = sample_config();
        let scope_id = [0x5cu8; 32];
        let body = build_provisioned_keystore_body(&cfg, scope_id);
        // basket B (provisioner config) carried through.
        assert_eq!(body.config.twod_chain_id, cfg.twod_chain_id);
        assert_eq!(body.config.environment_identifier, cfg.environment_identifier);
        assert_eq!(body.config.admin_authority_pk, cfg.admin_authority_pk);
        assert_eq!(body.config.anchor_root, cfg.anchor_root);
        assert_eq!(body.config.fleet_scope_id, cfg.fleet_scope_id);
        // basket A (enclave-minted): the param, NOT a fixture.
        assert_eq!(body.config.enclave_scope_id, scope_id);
        assert_ne!(body.config.enclave_scope_id, [0xe1u8; 32]);
        // basket C (enclave-init deterministic).
        assert_eq!(body.config.monotonic_treasury_config_version, 1);
        assert_eq!(body.config.authority_epoch, 0);
        // genesis state: empty entries/counters, faucet unconfigured (§2 fails closed).
        assert!(body.entries.is_empty());
        assert!(body.counters.is_empty());
        assert_eq!(body.faucet.cumulative_signing_budget, [0u8; 32]);
        assert_eq!(body.structural_version, 1);
        assert_eq!(body.freshness_epoch, 1);
        // validate() accepts the production body (proves it is sealable).
        body.validate().unwrap();
    }

    #[test]
    fn seal_provisioned_keystore_round_trips() {
        let cfg = sample_config();
        let scope_id = mint_enclave_scope_id().unwrap();
        let root = [0x42u8; 32];
        let meas = b"test-measurement";
        let blob = seal_provisioned_keystore(&cfg, scope_id, &root, meas).unwrap();
        assert!(!blob.is_empty());
        // unseal round-trips to a body carrying the SAME config + minted scope_id.
        let body = crate::agent_keystore::unseal_body(&blob, &root, meas).unwrap();
        assert_eq!(body.config.enclave_scope_id, scope_id);
        assert_eq!(body.config.twod_chain_id, cfg.twod_chain_id);
    }

    /// Build a ProvisionSession driven against a minted-M3 happy path; returns (session, m3, report).
    /// `on_m1` is called, so the session is in AwaitingM3 with N_e set; the M3 is signed over that N_e.
    fn session_at_awaiting_m3(
        seal_root: [u8; 32],
        meas: &[u8],
    ) -> (ProvisionSession, SigningKey, Vec<u8>, Vec<u8>, [u8; 32]) {
        let ca = test_ca();
        let prov = SigningKey::from_bytes(&[0x70; 32]);
        let cert = mint_cert(&prov.verifying_key(), &ca, Some(&[eku_oid()]));
        let mut session = ProvisionSession::new(ca.verifying_key(), seal_root, meas.to_vec());
        let n_p = [0x11u8; 32];
        let (n_e, _report_data) = session.on_m1(n_p).unwrap();
        assert_eq!(session.state(), SessionState::AwaitingM3);
        let report = vec![0x77u8; SNP_REPORT_LEN];
        let report_hash = compute_report_hash(&report);
        let cfg = encode_config_map(&sample_config());
        let m3 = mint_m3_message(&prov, &cert, &cfg, &n_p, &n_e, &report_hash);
        (session, prov, m3, report, n_p)
    }

    #[test]
    fn session_happy_path_mints_and_seals() {
        let root = [0x42u8; 32];
        let meas = b"test-measurement";
        let (mut session, _prov, m3, report, _n_p) = session_at_awaiting_m3(root, meas);
        let (config, sealed) = session.on_m3(&m3, &report).unwrap();
        assert_eq!(session.state(), SessionState::Done);
        assert_eq!(config, sample_config());
        // The sealed blob unseals under the same root+measurement to a valid keystore whose
        // enclave_scope_id is a freshly-minted RANDOM id (NOT a fixture).
        let body = crate::agent_keystore::unseal_body(&sealed, &root, meas).unwrap();
        assert_ne!(body.config.enclave_scope_id, [0u8; 32]);
        assert_ne!(body.config.enclave_scope_id, [0xe1u8; 32]);
        assert_eq!(body.config.twod_chain_id, sample_config().twod_chain_id);
    }

    #[test]
    fn session_replay_different_n_e_is_transcript_mismatch() {
        // on_m1 mints the session's N_e; an M3 signed over a DIFFERENT N_e (a captured M3 replayed
        // against this session) ⇒ TranscriptMismatch at the §6 transcript step.
        let root = [0x42u8; 32];
        let meas = b"test-measurement";
        let (mut session, prov, _m3, report, n_p) = session_at_awaiting_m3(root, meas);
        // Build an M3 signed over a WRONG N_e (not the session's).
        let wrong_n_e = [0x99u8; 32];
        let report_hash = compute_report_hash(&report);
        let cert = mint_cert(&prov.verifying_key(), &test_ca(), Some(&[eku_oid()]));
        let cfg = encode_config_map(&sample_config());
        let replay_m3 = mint_m3_message(&prov, &cert, &cfg, &n_p, &wrong_n_e, &report_hash);
        assert_eq!(
            session.on_m3(&replay_m3, &report),
            Err(ProvisionError::TranscriptMismatch)
        );
        // One-shot failure semantics: the session is CONSUMED (→ Failed), so the host cannot retry
        // forged M3s against the same N_e (static-target/fault-injection defense).
        assert_eq!(session.state(), SessionState::Failed);
        // Failed is terminal — a subsequent on_m3 ⇒ Malformed (must restart from on_m1).
        assert_eq!(
            session.on_m3(&replay_m3, &report),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn session_out_of_order_is_malformed() {
        let root = [0x42u8; 32];
        let meas = b"test-measurement";
        let mut session = ProvisionSession::new(test_ca().verifying_key(), root, meas.to_vec());
        // on_m3 BEFORE on_m1 ⇒ Malformed (no session nonces yet).
        assert_eq!(
            session.on_m3(&[0x30, 0x00], &[0x77; SNP_REPORT_LEN]),
            Err(ProvisionError::Malformed)
        );
        // double on_m1 ⇒ Malformed.
        let _ = session.on_m1([0x11; 32]).unwrap();
        assert_eq!(
            session.on_m1([0x12; 32]),
            Err(ProvisionError::Malformed)
        );
    }

    #[test]
    fn session_double_on_m3_is_malformed() {
        let root = [0x42u8; 32];
        let meas = b"test-measurement";
        let (mut session, _prov, m3, report, _n_p) = session_at_awaiting_m3(root, meas);
        let _ = session.on_m3(&m3, &report).unwrap(); // → Done
        // A second on_m3 (re-provision attempt) ⇒ Malformed (terminal state).
        assert_eq!(session.on_m3(&m3, &report), Err(ProvisionError::Malformed));
    }

    #[test]
    fn validate_minted_scope_id_rejects_degenerate_and_sentinels() {
        // AC#4: the known reproducible ids a clone could use to defeat the 18-2 byte-compare.
        assert_eq!(validate_minted_scope_id(&[0u8; 32]), Err(ProvisionError::Csprng));
        assert_eq!(validate_minted_scope_id(&[0xe1u8; 32]), Err(ProvisionError::Csprng));
        assert_eq!(validate_minted_scope_id(&[0xf1u8; 32]), Err(ProvisionError::Csprng));
        // A genuine random id passes.
        assert_eq!(validate_minted_scope_id(&[0x5cu8; 32]), Ok(()));
    }

    #[test]
    fn config_map_zero_fleet_scope_id_is_malformed() {
        // AC#7: fleet_scope_id must be a real fleet identity, not zero (which would collapse
        // fleet-scoped caps and misclassify as SealFailed downstream via KeystoreBody::validate).
        let mut cfg = sample_config();
        cfg.fleet_scope_id = [0u8; 32];
        assert_eq!(decode_config_map(&encode_config_map(&cfg)), Err(ProvisionError::Malformed));
    }

}
