//! Agent Gateway **anti-rollback anchor** freshness verification + boot reconcile (TASK-7.7).
//!
//! The sealed keystore carries a `freshness_epoch` (and counter/spend high-water) that an untrusted
//! host can roll back to replay consumed capabilities / re-dispense funds. The defence is an external
//! **anchor** — an ordered, anti-rollback-durable service — that records the authoritative current
//! epoch + marks. On every (re)start the enclave issues a fresh nonce, the anchor returns an
//! **Ed25519-signed** freshness response, and the enclave verifies it against the **sealed
//! `anchor_root`** and reconciles its local sealed state forward (or fails closed).
//!
//! ## Variant C (hybrid, chosen)
//! The enclave is **anchor-agnostic**: it only verifies a signed response against `anchor_root`. WHO
//! signs — an operator HSM, a quorum, or a **chain-bridge** that reads 2D-chain state (recorded via
//! ordinary transactions to a normal contract) and signs the current mark — is a provisioning choice
//! that does not change this code. The optional `chain_height`/`chain_block_hash` fields let a
//! chain-backed anchor bind its attestation to a finalized block, so a direct merkle-read path can be
//! layered on later without changing the wire contract.
//!
//! ## This slice (verify-only — pure, testable with a mock anchor key)
//! [`verify_anchor_response`] parses + Ed25519-verifies the response and binds it to the sealed scope
//! and the enclave's fresh nonce; [`reconcile`] applies the counter/spend-bounded adopt-forward vs
//! fail-closed rules (reconciled in the design doc §3). The SNP-quote fetch (the enclave's side of the
//! *mutual* auth), the host relay, wiring into boot/install, and seeding the body from the anchor's
//! actual marks are the **next** slice (platform/host plumbing).

// This is the verify-only slice: `verify_anchor_response` / `reconcile` / `anchor_handshake_report_data`
// are exercised by the unit tests here but not yet called from `agent_dispatch`/boot — that wiring is
// the next slice. Suppress dead-code only in the non-test lib build so the slice stays warning-clean;
// the test build still type- and use-checks every item. Remove when the boot handshake wires them in.
#![cfg_attr(not(test), allow(dead_code))]

use crate::agent_keystore::KeystoreConfig;
use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use sha3::{Digest, Sha3_512};

/// Domain prefix for the anchor freshness-response signing preimage. Trailing NUL is part of the label.
const ANCHOR_DOMAIN: &[u8] = b"2d-hsm/agent-anchor/v1\0";
/// Only response-format version this build understands.
const ANCHOR_RESPONSE_VERSION: u64 = 1;
/// Domain prefix for the 5b-2e `AdoptForward` raw-marks-response signing preimage. DISTINCT from
/// [`ANCHOR_DOMAIN`] and `agent_keystore::MARKS_DOMAIN` (three labels, three purposes) so a signature
/// from one protocol leg can never substitute for another. Trailing NUL is part of the label.
const MARKS_RESP_DOMAIN: &[u8] = b"2d-hsm/agent-anchor-marks-resp/v1\0";
/// Only marks-response-format version this build understands.
const MARKS_RESP_VERSION: u64 = 1;
/// Domain for the anti-rollback per-op **commit ACK** (TASK-7.7 slice 6). A FOURTH distinct label
/// (alongside `ANCHOR_DOMAIN`/`MARKS_RESP_DOMAIN`/`MARKS_DOMAIN`) so a captured freshness- or
/// marks-response signature can NEVER be replayed as a commit ack (and vice-versa). Trailing NUL is
/// part of the label.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1; consumed by 6-4 dispatch wiring
const COMMIT_ACK_DOMAIN: &[u8] = b"2d-hsm/agent-anchor-commit-ack/v1\0";
/// Only commit-ack-format version this build understands.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1
const COMMIT_ACK_VERSION: u64 = 1;
/// Domain for the SNP `report_data` the enclave puts in its handshake attestation (the anchor verifies
/// the enclave's side; that verification is anchor-side, this is just the binding the enclave commits).
const HANDSHAKE_REPORT_DATA_DOMAIN: &[u8] = b"2d-hsm-agent-anchor-handshake-v1";
/// 32-byte fixed-length fields (marks digest, nonce, block hash). `pub(crate)` so the freshness-
/// challenge module ([`crate::agent_challenge`]) keeps the nonce width in lockstep with verify/report_data.
pub(crate) const DIGEST_LEN: usize = 32;

/// Why a freshness response was rejected. The handshake is a boot-time ceremony (not a per-request,
/// host-probeable surface), so these are coarse fail-closed reasons rather than an anti-oracle band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorError {
    /// Bad CBOR / unknown version / missing or wrong-typed field / wrong fixed length.
    Malformed,
    /// Ed25519 verification failed, or `anchor_root` is not a valid key.
    SignatureInvalid,
    /// `chain_id` / `environment_identifier` did not match the sealed config.
    ScopeMismatch,
    /// The response did not echo the enclave's fresh challenge nonce (stale/replayed response).
    NonceMismatch,
}

/// The verified authoritative state the anchor reports for this enclave's scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnchorState {
    /// Authoritative current freshness epoch.
    pub epoch: u64,
    /// Monotonic structural version (bumped by key/config mutations the anchor canNOT reconstruct);
    /// lets the enclave tell a counter/spend-only gap (adoptable) from a structural gap (restore).
    pub structural_version: u64,
    /// Digest of the authoritative counter/spend high-water marks (the enclave compares its local
    /// digest; the actual marks for seeding are delivered in the boot-wiring slice).
    pub marks_digest: [u8; DIGEST_LEN],
    /// Present iff the anchor bound its attestation to a finalized 2D block (chain-backed anchor).
    pub chain_height: Option<u64>,
    /// The finalized block hash the attestation was bound to (both-or-neither with `chain_height`).
    /// Surfaced so a later chain-policy / merkle-read path can bind to the exact signed block without
    /// re-parsing; `None` for a non-chain-backed anchor.
    pub chain_block_hash: Option<[u8; DIGEST_LEN]>,
}

/// What the enclave should do with its local sealed state after a verified anchor response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileDecision {
    /// Local epoch == anchor epoch and marks consistent — proceed on the sealed state as-is.
    Fresh,
    /// Anchor is ahead by a counter/spend-only gap — re-seal forward to `epoch` and adopt the
    /// anchor's marks (the dropped seal lost no key material; the debit lives at the anchor).
    AdoptForward { epoch: u64 },
    /// Operator intervention required; never run fund custody.
    FailClosed(FailReason),
}

/// Why reconciliation fails closed (design doc §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailReason {
    /// Anchor epoch < local epoch — the anchor itself was rolled back, or is inconsistent.
    AnchorBehind,
    /// Epoch ahead with **any** structural_version mismatch. Normal case: the anchor's
    /// structural_version is ahead too — a dropped GENERATE_KEYS/CONFIGURE_TREASURY whose key/config
    /// material the anchor never held ⇒ restore from backup. Defensive case: structural_version is
    /// *behind* while epoch is ahead — a contradictory/forged anchor — which also fails closed here.
    StructuralGap,
    /// Same epoch but the marks/structural version disagree — corrupt/inconsistent state.
    Inconsistent,
}

use crate::agent_cbor::{as_bytes32, as_bytes_n, as_u64, check_strict_keys, map_get};

/// Parsed, type-checked anchor response (keys `1..=7` always signed, `8/9` signed only when
/// chain-bound, key `13` = signature). `chain_height`/`chain_block_hash` are both-or-neither (a
/// chain-backed attestation binds to a block). Wire format is **v1-PROVISIONAL** (design doc §8):
/// `structural_version` (5) and `marks_digest` (6) constructions are pinned by later slices.
struct AnchorResponse {
    version: u64,
    chain_id: u64,
    environment_identifier: String,
    epoch: u64,
    structural_version: u64,
    marks_digest: [u8; DIGEST_LEN],
    nonce: [u8; DIGEST_LEN],
    chain_height: Option<u64>,
    chain_block_hash: Option<[u8; DIGEST_LEN]>,
    signature: [u8; 64],
}

/// Strict structural decode of the response map (keys ⊆ {1..=9, 13}, no dup, required present, the
/// chain-binding pair both-or-neither). Any shape error ⇒ [`AnchorError::Malformed`].
fn parse_response(map: &[(Value, Value)]) -> Result<AnchorResponse, AnchorError> {
    if !check_strict_keys(map, |n| (1..=9).contains(&n) || n == 13) {
        return Err(AnchorError::Malformed);
    }
    let req_u64 = |k: u64| {
        map_get(map, k)
            .and_then(as_u64)
            .ok_or(AnchorError::Malformed)
    };
    let req_digest = |k: u64| {
        map_get(map, k)
            .and_then(as_bytes32)
            .ok_or(AnchorError::Malformed)
    };

    let version = req_u64(1)?;
    let chain_id = req_u64(2)?;
    let environment_identifier = match map_get(map, 3) {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(AnchorError::Malformed),
    };
    let epoch = req_u64(4)?;
    let structural_version = req_u64(5)?;
    let marks_digest = req_digest(6)?;
    let nonce = req_digest(7)?;
    // chain binding (8 height, 9 block hash): both present or both absent. A present-but-wrong-typed
    // field is Malformed (not silently treated as absent).
    let chain_height = match map_get(map, 8) {
        Some(v) => Some(as_u64(v).ok_or(AnchorError::Malformed)?),
        None => None,
    };
    let chain_block_hash = match map_get(map, 9) {
        Some(v) => Some(as_bytes32(v).ok_or(AnchorError::Malformed)?),
        None => None,
    };
    if chain_height.is_some() != chain_block_hash.is_some() {
        return Err(AnchorError::Malformed);
    }
    let signature: [u8; 64] = map_get(map, 13)
        .and_then(as_bytes_n::<64>)
        .ok_or(AnchorError::Malformed)?;

    Ok(AnchorResponse {
        version,
        chain_id,
        environment_identifier,
        epoch,
        structural_version,
        marks_digest,
        nonce,
        chain_height,
        chain_block_hash,
        signature,
    })
}

/// `ANCHOR_DOMAIN ‖ canonical-CBOR({signed keys})` — keys `1..=9` present (8/9 only when chain-bound),
/// ascending, shortest-form (RFC 8949 §4.2.1), key 13 (the signature) excluded. Built with the same
/// canonical encoders the capability verifier uses, so a conformant anchor signer matches byte-for-byte.
fn signed_preimage(r: &AnchorResponse) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    // Derive the map-header pair count AND the optional 8/9 body from ONE predicate, so a
    // directly-constructed `AnchorResponse` can never announce a count that disagrees with the pairs
    // it emits (the verify path already gets both-or-neither from `parse_response`).
    let chain = match (r.chain_height, r.chain_block_hash) {
        (Some(h), Some(bh)) => Some((h, bh)),
        _ => None,
    };
    let mut out = Vec::with_capacity(ANCHOR_DOMAIN.len() + 128 + r.environment_identifier.len());
    out.extend_from_slice(ANCHOR_DOMAIN);
    let count: u64 = if chain.is_some() { 9 } else { 7 };
    put_uint(&mut out, 5, count); // map header
    put_uint(&mut out, 0, 1);
    put_uint(&mut out, 0, r.version);
    put_uint(&mut out, 0, 2);
    put_uint(&mut out, 0, r.chain_id);
    put_uint(&mut out, 0, 3);
    put_text(&mut out, &r.environment_identifier);
    put_uint(&mut out, 0, 4);
    put_uint(&mut out, 0, r.epoch);
    put_uint(&mut out, 0, 5);
    put_uint(&mut out, 0, r.structural_version);
    put_uint(&mut out, 0, 6);
    put_bytes(&mut out, &r.marks_digest);
    put_uint(&mut out, 0, 7);
    put_bytes(&mut out, &r.nonce);
    if let Some((h, bh)) = chain {
        put_uint(&mut out, 0, 8);
        put_uint(&mut out, 0, h);
        put_uint(&mut out, 0, 9);
        put_bytes(&mut out, &bh);
    }
    out
}

/// Verify an anchor freshness response: Ed25519 over `ANCHOR_DOMAIN ‖ canonical-CBOR({1..=7, plus 8/9
/// when chain-bound})` against the sealed `anchor_root`, bound to the sealed
/// `(chain_id, environment_identifier)` scope and the enclave's fresh `expected_nonce`. Returns the
/// authoritative [`AnchorState`] or a fail-closed error.
///
/// # Caller preconditions (load-bearing for the anti-replay guarantee)
/// - `expected_nonce` MUST be a freshly sampled, unpredictable, single-use challenge (a CSPRNG draw
///   per (re)start). The nonce echo is the **only** freshness binding, so if a nonce is ever reused a
///   host that captured a `(nonce, response)` pair can replay it. This function cannot enforce that —
///   the boot-wiring slice that supplies `expected_nonce` (and binds it into the SNP `report_data` via
///   [`anchor_handshake_report_data`], passing the *same* value to both) owns the invariant.
/// - `response_map` MUST come from a **strict/canonical** CBOR decode (reject non-shortest integers,
///   indefinite-length items, trailing bytes). The signature is checked over the *re-encoded* canonical
///   preimage of the parsed fields, not the received bytes, so a lenient upstream decoder would let a
///   non-canonical wire encoding of an otherwise-valid response verify (mirrors the `agent_capability`
///   convention).
pub(crate) fn verify_anchor_response(
    response_map: &[(Value, Value)],
    expected_nonce: &[u8; DIGEST_LEN],
    config: &KeystoreConfig,
) -> Result<AnchorState, AnchorError> {
    let r = parse_response(response_map)?;
    if r.version != ANCHOR_RESPONSE_VERSION {
        return Err(AnchorError::Malformed);
    }
    // Ed25519 verify against the pinned sealed anchor root.
    let key =
        VerifyingKey::from_bytes(&config.anchor_root).map_err(|_| AnchorError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&r.signature);
    key.verify_strict(&signed_preimage(&r), &sig)
        .map_err(|_| AnchorError::SignatureInvalid)?;
    // Scope binding: this response is for THIS keystore's chain + environment.
    if r.chain_id != config.twod_chain_id
        || r.environment_identifier != config.environment_identifier
    {
        return Err(AnchorError::ScopeMismatch);
    }
    // Freshness: the anchor must echo the nonce the enclave issued this (re)start.
    if &r.nonce != expected_nonce {
        return Err(AnchorError::NonceMismatch);
    }
    Ok(AnchorState {
        epoch: r.epoch,
        structural_version: r.structural_version,
        marks_digest: r.marks_digest,
        chain_height: r.chain_height,
        chain_block_hash: r.chain_block_hash,
    })
}

/// Strict-canonical-CBOR decode `bytes` (rejecting non-shortest integers, indefinite lengths,
/// duplicate / out-of-order keys, and trailing bytes), then verify as [`verify_anchor_response`].
/// This is the entrypoint the boot-wiring slice should call on host-supplied response bytes: it
/// closes the "binds values, not wire bytes" precondition documented on [`verify_anchor_response`]
/// by pinning the canonical wire encoding **before** the signature is checked over the re-encoded
/// preimage. (Until boot wiring lands, this is dead-code-gated like the rest of the module.)
pub(crate) fn verify_anchor_response_bytes(
    bytes: &[u8],
    expected_nonce: &[u8; DIGEST_LEN],
    config: &KeystoreConfig,
) -> Result<AnchorState, AnchorError> {
    let map = crate::agent_cbor::strict_decode_map(bytes).map_err(|_| AnchorError::Malformed)?;
    verify_anchor_response(&map, expected_nonce, config)
}

/// Reconcile the local sealed state against a verified [`AnchorState`] (design doc §3). The local
/// `marks_digest` is computed by the caller from its sealed counters/spend.
///
/// `marks_digest` is a hash, so this decides only the *action* (Fresh / AdoptForward / FailClosed)
/// from the epoch + structural_version ordering; it cannot compare mark *magnitudes*. The safety of
/// `AdoptForward` rests on the trusted anchor recording a **monotone** counter/spend high-water
/// (design §3). The boot-wiring slice that actually SEEDS the body from the anchor's marks MUST obtain
/// those raw marks over a separate `anchor_root`-signed channel and assert **`hash(adopted_marks) ==
/// state.marks_digest`** (digest equality — authenticates the host-relayed raw marks against this
/// verified digest; the weaker `adopted ≥ local` alone lets a host forge large-but-`≥-local` marks)
/// before re-sealing. Until that signed raw-marks channel exists, `AdoptForward` is treated as
/// fail-closed (slice-5b contract, `agent-gateway-anti-rollback.md` §8).
pub(crate) fn reconcile(
    local_epoch: u64,
    local_structural_version: u64,
    local_marks_digest: &[u8; DIGEST_LEN],
    anchor: &AnchorState,
) -> ReconcileDecision {
    use std::cmp::Ordering;
    match anchor.epoch.cmp(&local_epoch) {
        // Anchor behind the blob ⇒ the anchor was rolled back / inconsistent — never trust it.
        Ordering::Less => ReconcileDecision::FailClosed(FailReason::AnchorBehind),
        // Same epoch: state must be identical. Any divergence is corruption.
        Ordering::Equal => {
            if anchor.structural_version == local_structural_version
                && &anchor.marks_digest == local_marks_digest
            {
                ReconcileDecision::Fresh
            } else {
                ReconcileDecision::FailClosed(FailReason::Inconsistent)
            }
        }
        // Anchor ahead: a dropped seal. Adopt forward ONLY if the gap is counter/spend-only (the
        // anchor holds those marks); a structural mutation it never held ⇒ restore from backup.
        Ordering::Greater => {
            if anchor.structural_version == local_structural_version {
                ReconcileDecision::AdoptForward {
                    epoch: anchor.epoch,
                }
            } else {
                // structural_version ahead (or, defensively, behind while epoch is ahead) ⇒ a gap the
                // anchor cannot reconstruct.
                ReconcileDecision::FailClosed(FailReason::StructuralGap)
            }
        }
    }
}

/// The `report_data` the enclave binds into its fresh SNP attestation for the anchor handshake:
/// `SHA3-512("2d-hsm-agent-anchor-handshake-v1" ‖ chain_id(8B BE) ‖ len(env)(4B BE) ‖ env ‖ nonce)`.
/// Length-prefixing env keeps the binding unambiguous. (Fetching the actual SNP quote is the next
/// slice; this fixes the value the quote must commit to.)
pub(crate) fn anchor_handshake_report_data(
    chain_id: u64,
    environment_identifier: &str,
    nonce: &[u8; DIGEST_LEN],
) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(HANDSHAKE_REPORT_DATA_DOMAIN);
    h.update(chain_id.to_be_bytes());
    h.update((environment_identifier.len() as u32).to_be_bytes());
    h.update(environment_identifier.as_bytes());
    h.update(nonce);
    h.finalize().into()
}

/// Test-only: build the canonically-encoded, validly-signed (non-chain-bound) anchor freshness
/// response bytes a conformant anchor would send for `signing_key` + these fields. `pub(crate)` so the
/// freshness-challenge slice's tests can drive `verify_outstanding_response` end-to-end. Under the
/// release-banned `lab-agent-smoke` feature this is ALSO the 5b-2c-iii lab anchor stub's REFERENCE
/// response builder — the single source of the response wire shape, so the stub structurally cannot
/// drift from what [`verify_anchor_response`] accepts.
#[cfg(any(test, feature = "lab-agent-smoke"))]
pub(crate) fn test_signed_response_bytes(
    signing_key: &ed25519_dalek::SigningKey,
    chain_id: u64,
    environment_identifier: &str,
    epoch: u64,
    structural_version: u64,
    marks_digest: [u8; DIGEST_LEN],
    nonce: [u8; DIGEST_LEN],
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut r = AnchorResponse {
        version: ANCHOR_RESPONSE_VERSION,
        chain_id,
        environment_identifier: environment_identifier.to_string(),
        epoch,
        structural_version,
        marks_digest,
        nonce,
        chain_height: None,
        chain_block_hash: None,
        signature: [0u8; 64],
    };
    r.signature = signing_key.sign(&signed_preimage(&r)).to_bytes();
    let map: Vec<(Value, Value)> = vec![
        (Value::Integer(1.into()), Value::Integer(r.version.into())),
        (Value::Integer(2.into()), Value::Integer(r.chain_id.into())),
        (
            Value::Integer(3.into()),
            Value::Text(r.environment_identifier.clone()),
        ),
        (Value::Integer(4.into()), Value::Integer(r.epoch.into())),
        (
            Value::Integer(5.into()),
            Value::Integer(r.structural_version.into()),
        ),
        (
            Value::Integer(6.into()),
            Value::Bytes(r.marks_digest.to_vec()),
        ),
        (Value::Integer(7.into()), Value::Bytes(r.nonce.to_vec())),
        (
            Value::Integer(13.into()),
            Value::Bytes(r.signature.to_vec()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

// -------------------------------------------------------------------------------------------------
// 5b-2e AdoptForward raw-marks response — the SECOND anchor_root-signed channel (a deliberate mirror
// of the freshness response above). The freshness response commits the anchor's `marks_digest` (a
// SHA3 hash, non-invertible); on AdoptForward the enclave fetches the RAW marks here, re-hashes them,
// and requires byte-exact equality against that signed digest (the security boundary lives in
// `agent_boot::execute_adopt_forward`). This module owns the wire/crypto: domain-separated Ed25519
// verify vs the sealed `anchor_root`, same-scope + same-single-use-nonce + same-epoch binding.
// -------------------------------------------------------------------------------------------------

/// The genuine ceiling on a signed marks payload: a payload describes a body that itself must seal
/// under [`crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE`] (the plaintext marks are strictly smaller
/// than the sealed body, which also carries key material), so a payload whose body can't seal is
/// un-adoptable. The wire-transport cap ([`crate::agent_boot_relay`]) adds an envelope reserve on top.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 2/8
pub(crate) const MAX_MARKS_PAYLOAD_LEN: usize = crate::agent_keystore::MAX_KEYSTORE_BLOB_SIZE;

/// Why a marks response was rejected (coarse boot-ceremony band, like [`AnchorError`]).
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 2/8
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarksError {
    /// Bad CBOR / unknown version / wrong key-set / wrong field length.
    Malformed,
    /// Ed25519 verification failed, or `anchor_root` is not a valid key.
    SignatureInvalid,
    /// `chain_id` / `environment_identifier` did not match the sealed config.
    ScopeMismatch,
    /// The response did not echo the enclave's fresh challenge nonce (stale/replayed).
    NonceMismatch,
    /// The response epoch did not equal the verified freshness `state.epoch` (cross-epoch splice).
    EpochMismatch,
}

/// Why a per-op commit ACK was rejected (TASK-7.7 slice 6; coarse band like [`MarksError`]). The ack
/// confirms the anchor DURABLY RECORDED exactly what the enclave proposed; any mismatch fails the op
/// closed (discard the already-computed sealed blob, no swap, no signature/refs emitted).
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1; consumed by 6-4 dispatch wiring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitAckError {
    /// Bad CBOR / unknown version / wrong key-set / wrong field length.
    Malformed,
    /// Ed25519 verification failed, or `anchor_root` is not a valid key.
    SignatureInvalid,
    /// `chain_id` / `environment_identifier` did not match the sealed config.
    ScopeMismatch,
    /// The ack did not echo the enclave's fresh per-op nonce (stale/replayed ack).
    NonceMismatch,
    /// The ack epoch did not equal the proposed new `freshness_epoch`.
    EpochMismatch,
    /// The ack `structural_version` did not equal the proposed new structural version.
    StructuralMismatch,
    /// The ack `marks_digest` did not equal the proposed post-op marks digest (anchor recorded a
    /// DIFFERENT post-op state than the enclave is about to seal).
    MarksMismatch,
    /// The ack did not echo the op's `request_id` (the durable record is for a different op).
    RequestIdMismatch,
}

/// `MARKS_RESP_DOMAIN ‖ canonical-CBOR({1..=6})` — keys 1..=6 ascending, shortest-form, key 13 (the
/// signature) excluded. Built with the same canonical encoders the freshness preimage uses, so a
/// conformant anchor signer matches byte-for-byte. The marks payload (key 6) is an opaque bstr here.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 2/8
fn marks_resp_signed_preimage(f: &crate::agent_cbor::MarksRespFields) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    let mut out = Vec::with_capacity(
        MARKS_RESP_DOMAIN.len() + 96 + f.environment_identifier.len() + f.marks_payload.len(),
    );
    out.extend_from_slice(MARKS_RESP_DOMAIN);
    put_uint(&mut out, 5, 6); // map(6): keys 1..=6 (key 13 signature excluded)
    put_uint(&mut out, 0, 1);
    put_uint(&mut out, 0, f.version);
    put_uint(&mut out, 0, 2);
    put_uint(&mut out, 0, f.chain_id);
    put_uint(&mut out, 0, 3);
    put_text(&mut out, &f.environment_identifier);
    put_uint(&mut out, 0, 4);
    put_uint(&mut out, 0, f.epoch);
    put_uint(&mut out, 0, 5);
    put_bytes(&mut out, &f.nonce);
    put_uint(&mut out, 0, 6);
    put_bytes(&mut out, &f.marks_payload);
    out
}

/// Verify a raw-marks response and return the authenticated `marks_payload` bytes for the AdoptForward
/// hash-equality gate. Seven fail-closed checks (mirror of [`verify_anchor_response_bytes`] + the
/// epoch echo): strict-canonical OUTER decode (binds the wire bytes the signature covers) → version →
/// Ed25519 `verify_strict` vs the sealed `anchor_root` → scope (`chain_id`+`env`) → same single-use
/// `expected_nonce` → `expected_epoch` (== the freshness `state.epoch`). The returned `marks_payload`
/// is then strict-decoded + re-hashed by the caller (`execute_adopt_forward`) — the signature commits
/// these bytes, but the digest gate is what authenticates the *values*.
#[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 2/8
pub(crate) fn verify_marks_response_bytes(
    bytes: &[u8],
    expected_nonce: &[u8; DIGEST_LEN],
    expected_epoch: u64,
    config: &KeystoreConfig,
) -> Result<Vec<u8>, MarksError> {
    let f = crate::agent_cbor::strict_decode_marks_response(bytes, MAX_MARKS_PAYLOAD_LEN)
        .map_err(|_| MarksError::Malformed)?;
    if f.version != MARKS_RESP_VERSION {
        return Err(MarksError::Malformed);
    }
    // Ed25519 verify against the pinned sealed anchor root (verify_strict rejects torsion/small-order).
    let key =
        VerifyingKey::from_bytes(&config.anchor_root).map_err(|_| MarksError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&f.signature);
    key.verify_strict(&marks_resp_signed_preimage(&f), &sig)
        .map_err(|_| MarksError::SignatureInvalid)?;
    // Scope: this marks snapshot is for THIS keystore's chain + environment (the SEALED config).
    if f.chain_id != config.twod_chain_id
        || f.environment_identifier != config.environment_identifier
    {
        return Err(MarksError::ScopeMismatch);
    }
    // Freshness: the anchor must echo the SAME single-use nonce the freshness leg issued this attempt.
    if &f.nonce != expected_nonce {
        return Err(MarksError::NonceMismatch);
    }
    // Cross-epoch splice guard: the marks snapshot must be for the exact epoch the freshness AnchorState
    // reported, so the host cannot pair a valid (other-epoch) marks message under the same nonce window.
    if f.epoch != expected_epoch {
        return Err(MarksError::EpochMismatch);
    }
    Ok(f.marks_payload)
}

/// Test/lab-only: build the canonically-encoded, validly-signed raw-marks response bytes a conformant
/// anchor would send. The SINGLE source of the marks-response wire shape — the 5b-2e lab anchor stub
/// reuses it (anti-drift), exactly as [`test_signed_response_bytes`] is the freshness-response source.
#[cfg(any(test, feature = "lab-agent-smoke"))]
pub(crate) fn test_signed_marks_response_bytes(
    signing_key: &ed25519_dalek::SigningKey,
    chain_id: u64,
    environment_identifier: &str,
    epoch: u64,
    nonce: [u8; DIGEST_LEN],
    marks_payload: Vec<u8>,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut f = crate::agent_cbor::MarksRespFields {
        version: MARKS_RESP_VERSION,
        chain_id,
        environment_identifier: environment_identifier.to_string(),
        epoch,
        nonce,
        marks_payload,
        signature: [0u8; 64],
    };
    f.signature = signing_key.sign(&marks_resp_signed_preimage(&f)).to_bytes();
    let map: Vec<(Value, Value)> = vec![
        (Value::Integer(1.into()), Value::Integer(f.version.into())),
        (Value::Integer(2.into()), Value::Integer(f.chain_id.into())),
        (
            Value::Integer(3.into()),
            Value::Text(f.environment_identifier.clone()),
        ),
        (Value::Integer(4.into()), Value::Integer(f.epoch.into())),
        (Value::Integer(5.into()), Value::Bytes(f.nonce.to_vec())),
        (
            Value::Integer(6.into()),
            Value::Bytes(f.marks_payload.clone()),
        ),
        (
            Value::Integer(13.into()),
            Value::Bytes(f.signature.to_vec()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

/// `COMMIT_ACK_DOMAIN ‖ canonical-CBOR({1..=8})` — keys 1..=8 ascending, shortest-form, key 13 (the
/// signature) excluded. Built with the same canonical encoders the freshness/marks preimages use, so a
/// conformant anchor signer matches byte-for-byte.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1
fn commit_ack_signed_preimage(f: &crate::agent_cbor::CommitAckFields) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_text, put_uint};
    let mut out = Vec::with_capacity(
        COMMIT_ACK_DOMAIN.len() + 160 + f.environment_identifier.len() + f.request_id.len(),
    );
    out.extend_from_slice(COMMIT_ACK_DOMAIN);
    put_uint(&mut out, 5, 8); // map(8): keys 1..=8 (key 13 signature excluded)
    put_uint(&mut out, 0, 1);
    put_uint(&mut out, 0, f.version);
    put_uint(&mut out, 0, 2);
    put_uint(&mut out, 0, f.chain_id);
    put_uint(&mut out, 0, 3);
    put_text(&mut out, &f.environment_identifier);
    put_uint(&mut out, 0, 4);
    put_uint(&mut out, 0, f.epoch);
    put_uint(&mut out, 0, 5);
    put_uint(&mut out, 0, f.structural_version);
    put_uint(&mut out, 0, 6);
    put_bytes(&mut out, &f.marks_digest);
    put_uint(&mut out, 0, 7);
    put_bytes(&mut out, &f.nonce);
    put_uint(&mut out, 0, 8);
    put_bytes(&mut out, &f.request_id);
    out
}

/// The enclave-PROPOSED values a commit ACK must echo back — passed by NAME (not positionally) because
/// `epoch` and `structural_version` are both `u64` and a positional swap would be a silent forgery
/// hole. The verifier confirms the anchor durably recorded EXACTLY these.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1; consumed by 6-4 dispatch wiring
pub(crate) struct ExpectedCommitAck<'a> {
    /// The fresh per-op nonce the enclave drew for THIS commit (anti-replay).
    pub nonce: &'a [u8; DIGEST_LEN],
    /// The proposed new `freshness_epoch` (= local epoch + 1).
    pub epoch: u64,
    /// The proposed new `structural_version`.
    pub structural_version: u64,
    /// The post-op marks digest the enclave computed on the candidate body.
    pub marks_digest: &'a [u8; DIGEST_LEN],
    /// The op's deterministic `request_id` (idempotency key; a retry hits the same anchor record).
    pub request_id: &'a [u8],
}

/// Verify a per-op commit ACK against the values the enclave PROPOSED (TASK-7.7 slice 6). Eight
/// fail-closed checks: strict-canonical OUTER decode → version → Ed25519 `verify_strict` vs the sealed
/// `anchor_root` → scope (`chain_id`+`env`) → fresh per-op `nonce` echo → proposed `epoch` echo →
/// proposed `structural_version` echo → proposed `marks_digest` echo → `request_id` echo. The ACK is the
/// anchor's durable record that the proposed post-op state is committed; only on `Ok(())` may the enclave
/// seal the advanced epoch and emit the op's signature/refs (seal-before-emit). Any mismatch fails the op
/// CLOSED. The distinct [`COMMIT_ACK_DOMAIN`] makes a cross-leg signature substitution unrepresentable.
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-1; consumed by 6-4 dispatch wiring
pub(crate) fn verify_commit_ack_bytes(
    bytes: &[u8],
    expected: &ExpectedCommitAck,
    config: &KeystoreConfig,
) -> Result<(), CommitAckError> {
    let f = crate::agent_cbor::strict_decode_commit_ack(
        bytes,
        crate::agent_dispatch::MAX_REQUEST_ID_LEN,
    )
    .map_err(|_| CommitAckError::Malformed)?;
    if f.version != COMMIT_ACK_VERSION {
        return Err(CommitAckError::Malformed);
    }
    // Ed25519 verify against the pinned sealed anchor root (verify_strict rejects torsion/small-order).
    let key = VerifyingKey::from_bytes(&config.anchor_root)
        .map_err(|_| CommitAckError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&f.signature);
    key.verify_strict(&commit_ack_signed_preimage(&f), &sig)
        .map_err(|_| CommitAckError::SignatureInvalid)?;
    // Scope: this ack is for THIS keystore's chain + environment (the SEALED config).
    if f.chain_id != config.twod_chain_id
        || f.environment_identifier != config.environment_identifier
    {
        return Err(CommitAckError::ScopeMismatch);
    }
    // Anti-replay: the ack must echo the SAME fresh per-op nonce this commit drew.
    if &f.nonce != expected.nonce {
        return Err(CommitAckError::NonceMismatch);
    }
    // The anchor must have recorded EXACTLY the proposed post-op state (epoch, structural, marks): a
    // mismatch means the durable record diverges from what the enclave is about to seal → fail closed.
    if f.epoch != expected.epoch {
        return Err(CommitAckError::EpochMismatch);
    }
    if f.structural_version != expected.structural_version {
        return Err(CommitAckError::StructuralMismatch);
    }
    if &f.marks_digest != expected.marks_digest {
        return Err(CommitAckError::MarksMismatch);
    }
    // Idempotency / anti-cross-op-replay: the ack must be for THIS op's request_id.
    if f.request_id.as_slice() != expected.request_id {
        return Err(CommitAckError::RequestIdMismatch);
    }
    Ok(())
}

/// Test/lab-only: build the canonically-encoded, validly-signed commit-ACK bytes a conformant anchor
/// would return. The SINGLE source of the commit-ack wire shape — the slice-6 lab anchor stub reuses it
/// (anti-drift), exactly as [`test_signed_marks_response_bytes`] is the marks-response source. Also the
/// TASK-23 deviceless contract server's mock commit channel signs its acks through this one source — but
/// only when a MUTATING preview is on (the channel only exists then), so a PUBLIC_IDENTITY-only
/// contract-server build does not compile this as dead code.
#[cfg(any(
    test,
    feature = "lab-agent-smoke",
    all(
        feature = "agent-contract-server",
        any(
            feature = "agent-keygen-exec-preview",
            feature = "agent-configure-treasury-preview",
            feature = "agent-sign-faucet-preview"
        )
    )
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn test_signed_commit_ack_bytes(
    signing_key: &ed25519_dalek::SigningKey,
    chain_id: u64,
    environment_identifier: &str,
    epoch: u64,
    structural_version: u64,
    marks_digest: [u8; DIGEST_LEN],
    nonce: [u8; DIGEST_LEN],
    request_id: Vec<u8>,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let mut f = crate::agent_cbor::CommitAckFields {
        version: COMMIT_ACK_VERSION,
        chain_id,
        environment_identifier: environment_identifier.to_string(),
        epoch,
        structural_version,
        marks_digest,
        nonce,
        request_id,
        signature: [0u8; 64],
    };
    f.signature = signing_key.sign(&commit_ack_signed_preimage(&f)).to_bytes();
    let map: Vec<(Value, Value)> = vec![
        (Value::Integer(1.into()), Value::Integer(f.version.into())),
        (Value::Integer(2.into()), Value::Integer(f.chain_id.into())),
        (
            Value::Integer(3.into()),
            Value::Text(f.environment_identifier.clone()),
        ),
        (Value::Integer(4.into()), Value::Integer(f.epoch.into())),
        (
            Value::Integer(5.into()),
            Value::Integer(f.structural_version.into()),
        ),
        (
            Value::Integer(6.into()),
            Value::Bytes(f.marks_digest.to_vec()),
        ),
        (Value::Integer(7.into()), Value::Bytes(f.nonce.to_vec())),
        (Value::Integer(8.into()), Value::Bytes(f.request_id.clone())),
        (
            Value::Integer(13.into()),
            Value::Bytes(f.signature.to_vec()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_ENV: &str = "env-prod-0";
    const TEST_CHAIN: u64 = 11565;

    fn anchor_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn test_config() -> KeystoreConfig {
        KeystoreConfig {
            twod_chain_id: TEST_CHAIN,
            environment_identifier: TEST_ENV.to_string(),
            admin_authority_pk: [0xa1; 32],
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: Vec::new(),
            monotonic_treasury_config_version: 1,
            authority_epoch: 0,
            anchor_root: anchor_key().verifying_key().to_bytes(),
            enclave_scope_id: [0xe1; 32],
            fleet_scope_id: [0xf1; 32],
        }
    }

    /// Build a signed anchor response map for `(epoch, structural_version, marks_digest, nonce)`.
    fn signed_response(
        key: &SigningKey,
        chain_id: u64,
        env: &str,
        epoch: u64,
        structural_version: u64,
        marks_digest: [u8; 32],
        nonce: [u8; 32],
    ) -> Vec<(Value, Value)> {
        let mut r = AnchorResponse {
            version: 1,
            chain_id,
            environment_identifier: env.to_string(),
            epoch,
            structural_version,
            marks_digest,
            nonce,
            chain_height: None,
            chain_block_hash: None,
            signature: [0u8; 64],
        };
        r.signature = key.sign(&signed_preimage(&r)).to_bytes();
        cap_to_map(&r)
    }

    fn cap_to_map(r: &AnchorResponse) -> Vec<(Value, Value)> {
        let mut m: Vec<(Value, Value)> = vec![
            (Value::Integer(1.into()), Value::Integer(r.version.into())),
            (Value::Integer(2.into()), Value::Integer(r.chain_id.into())),
            (
                Value::Integer(3.into()),
                Value::Text(r.environment_identifier.clone()),
            ),
            (Value::Integer(4.into()), Value::Integer(r.epoch.into())),
            (
                Value::Integer(5.into()),
                Value::Integer(r.structural_version.into()),
            ),
            (
                Value::Integer(6.into()),
                Value::Bytes(r.marks_digest.to_vec()),
            ),
            (Value::Integer(7.into()), Value::Bytes(r.nonce.to_vec())),
        ];
        if let (Some(h), Some(bh)) = (r.chain_height, r.chain_block_hash) {
            m.push((Value::Integer(8.into()), Value::Integer(h.into())));
            m.push((Value::Integer(9.into()), Value::Bytes(bh.to_vec())));
        }
        m.push((
            Value::Integer(13.into()),
            Value::Bytes(r.signature.to_vec()),
        ));
        m
    }

    #[test]
    fn valid_response_verifies() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let resp = signed_response(&anchor_key(), TEST_CHAIN, TEST_ENV, 7, 2, [0xab; 32], nonce);
        let st = verify_anchor_response(&resp, &nonce, &cfg).unwrap();
        assert_eq!(st.epoch, 7);
        assert_eq!(st.structural_version, 2);
        assert!(st.chain_height.is_none());
    }

    #[test]
    fn wrong_anchor_key_rejected() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let resp = signed_response(
            &SigningKey::from_bytes(&[9u8; 32]),
            TEST_CHAIN,
            TEST_ENV,
            7,
            2,
            [0xab; 32],
            nonce,
        );
        assert_eq!(
            verify_anchor_response(&resp, &nonce, &cfg),
            Err(AnchorError::SignatureInvalid)
        );
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let mut resp =
            signed_response(&anchor_key(), TEST_CHAIN, TEST_ENV, 7, 2, [0xab; 32], nonce);
        // bump epoch (key 4) after signing ⇒ preimage no longer matches.
        for (k, v) in resp.iter_mut() {
            if matches!(k, Value::Integer(i) if u64::try_from(*i).ok() == Some(4)) {
                *v = Value::Integer(8.into());
            }
        }
        assert_eq!(
            verify_anchor_response(&resp, &nonce, &cfg),
            Err(AnchorError::SignatureInvalid)
        );
    }

    #[test]
    fn stale_nonce_rejected() {
        let cfg = test_config();
        let resp = signed_response(
            &anchor_key(),
            TEST_CHAIN,
            TEST_ENV,
            7,
            2,
            [0xab; 32],
            [0x11; 32],
        );
        assert_eq!(
            verify_anchor_response(&resp, &[0x22; 32], &cfg),
            Err(AnchorError::NonceMismatch)
        );
    }

    #[test]
    fn scope_mismatch_rejected() {
        let nonce = [0x33u8; 32];
        // Right key + nonce, but the signed response is for a different chain ⇒ ScopeMismatch.
        let resp = signed_response(&anchor_key(), 999, TEST_ENV, 7, 2, [0xab; 32], nonce);
        assert_eq!(
            verify_anchor_response(&resp, &nonce, &test_config()),
            Err(AnchorError::ScopeMismatch)
        );
        let resp2 = signed_response(
            &anchor_key(),
            TEST_CHAIN,
            "other-env",
            7,
            2,
            [0xab; 32],
            nonce,
        );
        assert_eq!(
            verify_anchor_response(&resp2, &nonce, &test_config()),
            Err(AnchorError::ScopeMismatch)
        );
    }

    #[test]
    fn unknown_version_is_malformed() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let mut r = AnchorResponse {
            version: 2,
            chain_id: TEST_CHAIN,
            environment_identifier: TEST_ENV.to_string(),
            epoch: 7,
            structural_version: 2,
            marks_digest: [0xab; 32],
            nonce,
            chain_height: None,
            chain_block_hash: None,
            signature: [0u8; 64],
        };
        r.signature = anchor_key().sign(&signed_preimage(&r)).to_bytes();
        assert_eq!(
            verify_anchor_response(&cap_to_map(&r), &nonce, &cfg),
            Err(AnchorError::Malformed)
        );
    }

    #[test]
    fn chain_bound_response_verifies_and_carries_height() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let mut r = AnchorResponse {
            version: 1,
            chain_id: TEST_CHAIN,
            environment_identifier: TEST_ENV.to_string(),
            epoch: 7,
            structural_version: 2,
            marks_digest: [0xab; 32],
            nonce,
            chain_height: Some(123_456),
            chain_block_hash: Some([0xcd; 32]),
            signature: [0u8; 64],
        };
        r.signature = anchor_key().sign(&signed_preimage(&r)).to_bytes();
        let st = verify_anchor_response(&cap_to_map(&r), &nonce, &cfg).unwrap();
        assert_eq!(st.chain_height, Some(123_456));
        assert_eq!(st.chain_block_hash, Some([0xcd; 32]));
    }

    #[test]
    fn chain_binding_must_be_both_or_neither() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        // height present without block hash ⇒ Malformed (build the map by hand, sign is irrelevant —
        // parse rejects before verify).
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer(TEST_CHAIN.into())),
            (Value::Integer(3.into()), Value::Text(TEST_ENV.to_string())),
            (Value::Integer(4.into()), Value::Integer(7.into())),
            (Value::Integer(5.into()), Value::Integer(2.into())),
            (Value::Integer(6.into()), Value::Bytes(vec![0xab; 32])),
            (Value::Integer(7.into()), Value::Bytes(nonce.to_vec())),
            (Value::Integer(8.into()), Value::Integer(123.into())), // height, no key 9
            (Value::Integer(13.into()), Value::Bytes(vec![0u8; 64])),
        ];
        assert_eq!(
            verify_anchor_response(&map, &nonce, &cfg),
            Err(AnchorError::Malformed)
        );
    }

    #[test]
    fn reconcile_fresh_adopt_and_failclosed() {
        let marks = [0xab; 32];
        let anchor = |epoch, sv, md| AnchorState {
            epoch,
            structural_version: sv,
            marks_digest: md,
            chain_height: None,
            chain_block_hash: None,
        };
        // Same epoch + matching marks/structural ⇒ Fresh.
        assert_eq!(
            reconcile(5, 2, &marks, &anchor(5, 2, marks)),
            ReconcileDecision::Fresh
        );
        // Same epoch but differing marks ⇒ Inconsistent.
        assert_eq!(
            reconcile(5, 2, &marks, &anchor(5, 2, [0x00; 32])),
            ReconcileDecision::FailClosed(FailReason::Inconsistent)
        );
        // Same epoch, SAME marks, but differing structural_version ⇒ also Inconsistent (the Equal-arm
        // `&&` means either divergence fails closed; this pins the structural-only sub-case).
        assert_eq!(
            reconcile(5, 3, &marks, &anchor(5, 2, marks)),
            ReconcileDecision::FailClosed(FailReason::Inconsistent)
        );
        // Anchor ahead, same structural ⇒ AdoptForward (counter/spend gap). This IS the slice-6-5
        // post-commit-crash EpochOnly case: a counter/spend op committed epoch N+1 to the anchor then
        // the enclave crashed before persist/swap, so on reboot sealed@N < anchor@(N+1) with the same
        // structural_version ⇒ adopt the anchor's marks forward (recoverable).
        assert_eq!(
            reconcile(5, 2, &marks, &anchor(6, 2, [0x00; 32])),
            ReconcileDecision::AdoptForward { epoch: 6 }
        );
        // Anchor ahead but structural ahead ⇒ StructuralGap (restore). This IS the slice-6-5
        // post-commit-crash STRUCTURAL case: a GENERATE_KEYS (structural) op committed N+1 then crashed
        // before swap ⇒ sealed@N < anchor@(N+1) with structural ahead ⇒ a gap the anchor can't supply
        // (key material) ⇒ fail closed → restore.
        assert_eq!(
            reconcile(5, 2, &marks, &anchor(7, 3, [0x00; 32])),
            ReconcileDecision::FailClosed(FailReason::StructuralGap)
        );
        // Anchor behind ⇒ AnchorBehind (rollback).
        assert_eq!(
            reconcile(5, 2, &marks, &anchor(4, 2, marks)),
            ReconcileDecision::FailClosed(FailReason::AnchorBehind)
        );
        // Anchor epoch ahead but structural_version BEHIND local — a contradictory/forged combination
        // (structural is monotone with epoch); the Greater else-branch must still fail closed.
        assert_eq!(
            reconcile(5, 2, &marks, &anchor(6, 1, marks)),
            ReconcileDecision::FailClosed(FailReason::StructuralGap)
        );
    }

    #[test]
    fn report_data_is_deterministic_and_domain_separated() {
        let n = [0x33u8; 32];
        let a = anchor_handshake_report_data(TEST_CHAIN, TEST_ENV, &n);
        let b = anchor_handshake_report_data(TEST_CHAIN, TEST_ENV, &n);
        assert_eq!(a, b);
        // A different nonce / chain / env changes the binding.
        assert_ne!(
            a,
            anchor_handshake_report_data(TEST_CHAIN, TEST_ENV, &[0x34; 32])
        );
        assert_ne!(
            a,
            anchor_handshake_report_data(TEST_CHAIN + 1, TEST_ENV, &n)
        );
        assert_ne!(a, anchor_handshake_report_data(TEST_CHAIN, "other", &n));
    }

    /// A canonical, well-typed 7-key map with a placeholder signature, for malformed-decode tests
    /// (these reject in `parse_response` before the signature is ever checked).
    fn base_map(nonce: [u8; 32]) -> Vec<(Value, Value)> {
        vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer(TEST_CHAIN.into())),
            (Value::Integer(3.into()), Value::Text(TEST_ENV.to_string())),
            (Value::Integer(4.into()), Value::Integer(7.into())),
            (Value::Integer(5.into()), Value::Integer(2.into())),
            (Value::Integer(6.into()), Value::Bytes(vec![0xab; 32])),
            (Value::Integer(7.into()), Value::Bytes(nonce.to_vec())),
            (Value::Integer(13.into()), Value::Bytes(vec![0u8; 64])),
        ]
    }

    fn has_key(k: &Value, want: u64) -> bool {
        matches!(k, Value::Integer(i) if u64::try_from(*i).ok() == Some(want))
    }

    #[test]
    fn malformed_maps_rejected() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let mal = |m: Vec<(Value, Value)>| verify_anchor_response(&m, &nonce, &cfg);

        // duplicate required key (two key-4 entries)
        let mut m = base_map(nonce);
        m.push((Value::Integer(4.into()), Value::Integer(9.into())));
        assert_eq!(mal(m), Err(AnchorError::Malformed));

        // unknown / out-of-range key (10 — outside {1..=9, 13})
        let mut m = base_map(nonce);
        m.push((Value::Integer(10.into()), Value::Integer(0.into())));
        assert_eq!(mal(m), Err(AnchorError::Malformed));

        // negative integer key
        let mut m = base_map(nonce);
        m.push((Value::Integer((-1i64).into()), Value::Integer(0.into())));
        assert_eq!(mal(m), Err(AnchorError::Malformed));

        // missing required key (drop key 4)
        let mut m = base_map(nonce);
        m.retain(|(k, _)| !has_key(k, 4));
        assert_eq!(mal(m), Err(AnchorError::Malformed));

        // wrong-typed required field (env, key 3, as integer)
        let mut m = base_map(nonce);
        for (k, v) in m.iter_mut() {
            if has_key(k, 3) {
                *v = Value::Integer(5.into());
            }
        }
        assert_eq!(mal(m), Err(AnchorError::Malformed));

        // marks (key 6) not exactly 32 bytes
        let mut m = base_map(nonce);
        for (k, v) in m.iter_mut() {
            if has_key(k, 6) {
                *v = Value::Bytes(vec![0xab; 31]);
            }
        }
        assert_eq!(mal(m), Err(AnchorError::Malformed));

        // signature (key 13) wrong length (63 bytes)
        let mut m = base_map(nonce);
        for (k, v) in m.iter_mut() {
            if has_key(k, 13) {
                *v = Value::Bytes(vec![0u8; 63]);
            }
        }
        assert_eq!(mal(m), Err(AnchorError::Malformed));
    }

    #[test]
    fn invalid_anchor_root_point_is_signature_invalid() {
        // Find a 32-byte value that is NOT a valid Ed25519 point encoding (≈half of candidates fail
        // decompression) so the `VerifyingKey::from_bytes` error path is exercised deterministically
        // without hand-picking a vector.
        let mut bad = [0u8; 32];
        let mut found = false;
        'outer: for a in 0u8..=255 {
            for b in 0u8..=255 {
                let mut cand = [0u8; 32];
                cand[0] = a;
                cand[1] = b;
                if VerifyingKey::from_bytes(&cand).is_err() {
                    bad = cand;
                    found = true;
                    break 'outer;
                }
            }
        }
        assert!(
            found,
            "expected at least one invalid Ed25519 point encoding"
        );
        let mut cfg = test_config();
        cfg.anchor_root = bad;
        let nonce = [0x33u8; 32];
        let resp = signed_response(&anchor_key(), TEST_CHAIN, TEST_ENV, 7, 2, [0xab; 32], nonce);
        assert_eq!(
            verify_anchor_response(&resp, &nonce, &cfg),
            Err(AnchorError::SignatureInvalid)
        );
    }

    #[test]
    fn chain_downgrade_strip_fails_signature() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        // Sign a chain-bound response (preimage announces 9 keys), then have the host strip keys 8/9.
        let mut r = AnchorResponse {
            version: 1,
            chain_id: TEST_CHAIN,
            environment_identifier: TEST_ENV.to_string(),
            epoch: 7,
            structural_version: 2,
            marks_digest: [0xab; 32],
            nonce,
            chain_height: Some(100),
            chain_block_hash: Some([0xcd; 32]),
            signature: [0u8; 64],
        };
        r.signature = anchor_key().sign(&signed_preimage(&r)).to_bytes();
        let mut map = cap_to_map(&r);
        // Downgrade: drop the chain binding. parse now rebuilds a 7-key preimage, so the signature
        // made over the 9-key preimage no longer matches.
        map.retain(|(k, _)| !has_key(k, 8) && !has_key(k, 9));
        assert_eq!(
            verify_anchor_response(&map, &nonce, &cfg),
            Err(AnchorError::SignatureInvalid)
        );
    }

    fn encode_map(m: &[(Value, Value)]) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(m.to_vec()), &mut out).unwrap();
        out
    }

    #[test]
    fn verify_bytes_accepts_canonical_rejects_noncanonical() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        let resp = signed_response(&anchor_key(), TEST_CHAIN, TEST_ENV, 7, 2, [0xab; 32], nonce);
        let bytes = encode_map(&resp);
        // Canonical wire bytes verify end-to-end through the strict-decode entrypoint.
        let st = verify_anchor_response_bytes(&bytes, &nonce, &cfg).unwrap();
        assert_eq!(st.epoch, 7);
        // Security-critical: re-encode the `version` value (byte index 2) in non-shortest long form.
        // The decoded VALUES are identical and the canonical preimage would `verify_strict`, but the
        // strict decoder rejects the non-canonical wire bytes BEFORE the signature is ever checked.
        let mut bad = bytes.clone();
        assert_eq!(bad[0], 0xa8); // map with 8 entries (keys 1..=7 + 13)
        assert_eq!(bad[1], 0x01); // key 1
        assert_eq!(bad[2], 0x01); // version value, shortest form
        bad.splice(2..3, [0x18u8, 0x01u8]); // 1 encoded as 0x18 0x01 (non-shortest)
        assert_eq!(
            verify_anchor_response_bytes(&bad, &nonce, &cfg),
            Err(AnchorError::Malformed)
        );
    }

    #[test]
    fn chain_upgrade_add_fails_signature() {
        let cfg = test_config();
        let nonce = [0x33u8; 32];
        // Sign a NON-chain response (7-key preimage), then have the host add spoofed keys 8/9.
        let resp = signed_response(&anchor_key(), TEST_CHAIN, TEST_ENV, 7, 2, [0xab; 32], nonce);
        let mut map = resp;
        map.push((Value::Integer(8.into()), Value::Integer(100.into())));
        map.push((Value::Integer(9.into()), Value::Bytes(vec![0xcd; 32])));
        // parse now sees a chain binding → rebuilds a 9-key preimage, so the 7-key signature fails.
        assert_eq!(
            verify_anchor_response(&map, &nonce, &cfg),
            Err(AnchorError::SignatureInvalid)
        );
    }

    // ---- 5b-2e raw-marks response verify (commit 2/8) ----

    const TEST_EPOCH: u64 = 7;
    const TEST_NONCE: [u8; 32] = [0x9a; 32];

    fn marks_payload_bytes() -> Vec<u8> {
        // A small but non-trivial canonical marks payload (1 row + non-zero spend), built via the
        // shared encoders so it matches the frozen grammar.
        use crate::agent_capability::{put_bytes, put_uint};
        let mut o = Vec::new();
        put_uint(&mut o, 5, 4);
        put_uint(&mut o, 0, 1);
        put_uint(&mut o, 4, 1);
        put_uint(&mut o, 4, 4);
        put_bytes(&mut o, &[0x11; 32]);
        put_uint(&mut o, 0, 0);
        put_bytes(&mut o, b"x");
        put_uint(&mut o, 0, 5);
        put_uint(&mut o, 0, 2);
        put_bytes(&mut o, &[0xaa; 32]);
        put_uint(&mut o, 0, 3);
        put_bytes(&mut o, &[0xbb; 32]);
        put_uint(&mut o, 0, 4);
        put_uint(&mut o, 0, 0);
        o
    }

    fn good_marks_response(payload: &[u8]) -> Vec<u8> {
        test_signed_marks_response_bytes(
            &anchor_key(),
            TEST_CHAIN,
            TEST_ENV,
            TEST_EPOCH,
            TEST_NONCE,
            payload.to_vec(),
        )
    }

    #[test]
    fn marks_response_verifies_and_returns_payload() {
        let payload = marks_payload_bytes();
        let bytes = good_marks_response(&payload);
        let got = verify_marks_response_bytes(&bytes, &TEST_NONCE, TEST_EPOCH, &test_config())
            .expect("conformant marks response verifies");
        assert_eq!(
            got, payload,
            "the authenticated marks_payload is returned verbatim"
        );
    }

    #[test]
    fn marks_response_rejects_wrong_signer() {
        // Signed by a key that is NOT the sealed anchor_root.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let payload = marks_payload_bytes();
        let bytes = test_signed_marks_response_bytes(
            &other, TEST_CHAIN, TEST_ENV, TEST_EPOCH, TEST_NONCE, payload,
        );
        assert_eq!(
            verify_marks_response_bytes(&bytes, &TEST_NONCE, TEST_EPOCH, &test_config()),
            Err(MarksError::SignatureInvalid)
        );
    }

    #[test]
    fn marks_response_rejects_scope_nonce_epoch_mismatch() {
        let payload = marks_payload_bytes();
        // wrong chain_id → ScopeMismatch
        let bad_chain = test_signed_marks_response_bytes(
            &anchor_key(),
            TEST_CHAIN + 1,
            TEST_ENV,
            TEST_EPOCH,
            TEST_NONCE,
            payload.clone(),
        );
        assert_eq!(
            verify_marks_response_bytes(&bad_chain, &TEST_NONCE, TEST_EPOCH, &test_config()),
            Err(MarksError::ScopeMismatch)
        );
        // wrong env → ScopeMismatch
        let bad_env = test_signed_marks_response_bytes(
            &anchor_key(),
            TEST_CHAIN,
            "other-env",
            TEST_EPOCH,
            TEST_NONCE,
            payload.clone(),
        );
        assert_eq!(
            verify_marks_response_bytes(&bad_env, &TEST_NONCE, TEST_EPOCH, &test_config()),
            Err(MarksError::ScopeMismatch)
        );
        // good signature but the verifier expects a DIFFERENT nonce → NonceMismatch
        let good = good_marks_response(&payload);
        assert_eq!(
            verify_marks_response_bytes(&good, &[0x00; 32], TEST_EPOCH, &test_config()),
            Err(MarksError::NonceMismatch)
        );
        // good signature but the verifier expects a DIFFERENT epoch → EpochMismatch (cross-epoch splice)
        assert_eq!(
            verify_marks_response_bytes(&good, &TEST_NONCE, TEST_EPOCH + 1, &test_config()),
            Err(MarksError::EpochMismatch)
        );
    }

    #[test]
    fn marks_response_rejects_noncanonical_outer_and_trailing() {
        let good = good_marks_response(&marks_payload_bytes());
        // canonical verifies
        assert!(
            verify_marks_response_bytes(&good, &TEST_NONCE, TEST_EPOCH, &test_config()).is_ok()
        );
        // trailing byte → Malformed (strict outer decode rejects)
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(
            verify_marks_response_bytes(&trailing, &TEST_NONCE, TEST_EPOCH, &test_config()),
            Err(MarksError::Malformed)
        );
    }

    #[test]
    fn marks_and_freshness_responses_are_domain_separated() {
        // A FRESHNESS response (ANCHOR_DOMAIN) must NOT verify as a marks response, and vice-versa —
        // the distinct MARKS_RESP_DOMAIN makes a cross-protocol signature substitution unrepresentable.
        let cfg = test_config();
        let freshness_map = signed_response(
            &anchor_key(),
            TEST_CHAIN,
            TEST_ENV,
            TEST_EPOCH,
            1,
            [0; 32],
            TEST_NONCE,
        );
        let mut freshness_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(freshness_map.clone()), &mut freshness_bytes)
            .unwrap();
        // freshness bytes decode to the wrong key-set/shape for the marks parser → never Ok.
        assert!(
            verify_marks_response_bytes(&freshness_bytes, &TEST_NONCE, TEST_EPOCH, &cfg).is_err()
        );
        // The freshness response itself still verifies through ITS own path (sanity — no collateral break).
        assert!(verify_anchor_response(&freshness_map, &TEST_NONCE, &cfg).is_ok());
        // A marks response must not verify through the freshness path either: its key 6 is a bstr (the
        // marks_payload), not a 32-byte digest → freshness parse rejects it.
        let marks = good_marks_response(&marks_payload_bytes());
        if let Ok(m) = crate::agent_cbor::strict_decode_map(&marks) {
            assert!(verify_anchor_response(&m, &TEST_NONCE, &cfg).is_err());
        }
    }

    // ---- slice-6 per-op commit-ACK verify ----

    const TEST_STRUCTURAL: u64 = 3;
    const TEST_MARKS_DIGEST: [u8; 32] = [0x5c; 32];
    const TEST_REQUEST_ID: &[u8] = b"op-req-1";

    fn good_commit_ack() -> Vec<u8> {
        test_signed_commit_ack_bytes(
            &anchor_key(),
            TEST_CHAIN,
            TEST_ENV,
            TEST_EPOCH,
            TEST_STRUCTURAL,
            TEST_MARKS_DIGEST,
            TEST_NONCE,
            TEST_REQUEST_ID.to_vec(),
        )
    }

    fn commit_expected() -> ExpectedCommitAck<'static> {
        ExpectedCommitAck {
            nonce: &TEST_NONCE,
            epoch: TEST_EPOCH,
            structural_version: TEST_STRUCTURAL,
            marks_digest: &TEST_MARKS_DIGEST,
            request_id: TEST_REQUEST_ID,
        }
    }

    #[test]
    fn commit_ack_verifies() {
        assert_eq!(
            verify_commit_ack_bytes(&good_commit_ack(), &commit_expected(), &test_config()),
            Ok(())
        );
    }

    #[test]
    fn commit_ack_rejects_wrong_signer() {
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let bytes = test_signed_commit_ack_bytes(
            &other,
            TEST_CHAIN,
            TEST_ENV,
            TEST_EPOCH,
            TEST_STRUCTURAL,
            TEST_MARKS_DIGEST,
            TEST_NONCE,
            TEST_REQUEST_ID.to_vec(),
        );
        assert_eq!(
            verify_commit_ack_bytes(&bytes, &commit_expected(), &test_config()),
            Err(CommitAckError::SignatureInvalid)
        );
    }

    #[test]
    fn commit_ack_rejects_scope_mismatch() {
        let bad_chain = test_signed_commit_ack_bytes(
            &anchor_key(),
            TEST_CHAIN + 1,
            TEST_ENV,
            TEST_EPOCH,
            TEST_STRUCTURAL,
            TEST_MARKS_DIGEST,
            TEST_NONCE,
            TEST_REQUEST_ID.to_vec(),
        );
        assert_eq!(
            verify_commit_ack_bytes(&bad_chain, &commit_expected(), &test_config()),
            Err(CommitAckError::ScopeMismatch)
        );
        let bad_env = test_signed_commit_ack_bytes(
            &anchor_key(),
            TEST_CHAIN,
            "other-env",
            TEST_EPOCH,
            TEST_STRUCTURAL,
            TEST_MARKS_DIGEST,
            TEST_NONCE,
            TEST_REQUEST_ID.to_vec(),
        );
        assert_eq!(
            verify_commit_ack_bytes(&bad_env, &commit_expected(), &test_config()),
            Err(CommitAckError::ScopeMismatch)
        );
    }

    #[test]
    fn commit_ack_rejects_each_proposed_field_mismatch() {
        // One validly-signed ack; vary ONE expected field per check. epoch and structural are BOTH u64 —
        // the named-field ExpectedCommitAck is exactly what makes a transposition impossible here.
        let cfg = test_config();
        let good = good_commit_ack();
        let zero = [0x00u8; 32];
        assert_eq!(
            verify_commit_ack_bytes(
                &good,
                &ExpectedCommitAck {
                    nonce: &zero,
                    ..commit_expected()
                },
                &cfg
            ),
            Err(CommitAckError::NonceMismatch)
        );
        assert_eq!(
            verify_commit_ack_bytes(
                &good,
                &ExpectedCommitAck {
                    epoch: TEST_EPOCH + 1,
                    ..commit_expected()
                },
                &cfg
            ),
            Err(CommitAckError::EpochMismatch)
        );
        assert_eq!(
            verify_commit_ack_bytes(
                &good,
                &ExpectedCommitAck {
                    structural_version: TEST_STRUCTURAL + 1,
                    ..commit_expected()
                },
                &cfg
            ),
            Err(CommitAckError::StructuralMismatch)
        );
        assert_eq!(
            verify_commit_ack_bytes(
                &good,
                &ExpectedCommitAck {
                    marks_digest: &zero,
                    ..commit_expected()
                },
                &cfg
            ),
            Err(CommitAckError::MarksMismatch)
        );
        assert_eq!(
            verify_commit_ack_bytes(
                &good,
                &ExpectedCommitAck {
                    request_id: b"other-op",
                    ..commit_expected()
                },
                &cfg
            ),
            Err(CommitAckError::RequestIdMismatch)
        );
    }

    #[test]
    fn commit_ack_rejects_noncanonical_trailing_and_over_cap_request_id() {
        let cfg = test_config();
        let good = good_commit_ack();
        assert_eq!(
            verify_commit_ack_bytes(&good, &commit_expected(), &cfg),
            Ok(())
        );
        // trailing byte → Malformed (strict outer decode rejects)
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(
            verify_commit_ack_bytes(&trailing, &commit_expected(), &cfg),
            Err(CommitAckError::Malformed)
        );
        // request_id over the 64-byte cap → Malformed at decode, BEFORE any field-echo check
        let big_id = vec![0x41u8; crate::agent_dispatch::MAX_REQUEST_ID_LEN + 1];
        let over = test_signed_commit_ack_bytes(
            &anchor_key(),
            TEST_CHAIN,
            TEST_ENV,
            TEST_EPOCH,
            TEST_STRUCTURAL,
            TEST_MARKS_DIGEST,
            TEST_NONCE,
            big_id,
        );
        assert_eq!(
            verify_commit_ack_bytes(&over, &commit_expected(), &cfg),
            Err(CommitAckError::Malformed)
        );
    }

    #[test]
    fn commit_ack_is_domain_separated_from_marks_and_freshness() {
        // The distinct COMMIT_ACK_DOMAIN + key-set make a cross-leg signature substitution
        // unrepresentable: a commit ack must not verify as a marks/freshness response, nor vice-versa.
        let cfg = test_config();
        let commit = good_commit_ack();
        assert!(verify_marks_response_bytes(&commit, &TEST_NONCE, TEST_EPOCH, &cfg).is_err());
        if let Ok(m) = crate::agent_cbor::strict_decode_map(&commit) {
            assert!(verify_anchor_response(&m, &TEST_NONCE, &cfg).is_err());
        }
        // a marks response does not verify as a commit ack
        let marks = good_marks_response(&marks_payload_bytes());
        assert!(verify_commit_ack_bytes(&marks, &commit_expected(), &cfg).is_err());
        // a freshness response does not verify as a commit ack
        let freshness_map = signed_response(
            &anchor_key(),
            TEST_CHAIN,
            TEST_ENV,
            TEST_EPOCH,
            1,
            [0; 32],
            TEST_NONCE,
        );
        let mut freshness_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(freshness_map), &mut freshness_bytes).unwrap();
        assert!(verify_commit_ack_bytes(&freshness_bytes, &commit_expected(), &cfg).is_err());
    }

    #[test]
    fn commit_request_payload_byte_matches_ack_preimage_body() {
        // INDEPENDENT anti-drift (compact 7184): the round-trip test reuses commit_ack_signed_preimage on
        // BOTH sign and verify, so it can't catch a COORDINATED encoder/preimage drift. The 0x45 request
        // payload (map(8) body) and the ack signed preimage (COMMIT_ACK_DOMAIN ‖ the SAME map(8) body)
        // MUST be byte-identical after the domain prefix — this asserts the two INDEPENDENT hand-rolled
        // emitters agree byte-for-byte, so a reorder/type-slip in either is caught here.
        // (Relies on COMMIT_REQUEST_VERSION == COMMIT_ACK_VERSION; if the version namespaces ever diverge
        // intentionally, this invariant + test must be revisited — the assert message says so.)
        let frame = crate::agent_boot_relay::encode_anchor_commit_request(
            &crate::agent_boot_relay::AnchorCommitRequest {
                chain_id: TEST_CHAIN,
                environment_identifier: TEST_ENV,
                new_epoch: TEST_EPOCH,
                new_structural_version: TEST_STRUCTURAL,
                marks_digest: TEST_MARKS_DIGEST,
                nonce: TEST_NONCE,
                request_id: TEST_REQUEST_ID,
            },
        )
        .unwrap();
        let payload = crate::decode_message(&frame).unwrap().payload;
        let f = crate::agent_cbor::CommitAckFields {
            version: COMMIT_ACK_VERSION,
            chain_id: TEST_CHAIN,
            environment_identifier: TEST_ENV.to_string(),
            epoch: TEST_EPOCH,
            structural_version: TEST_STRUCTURAL,
            marks_digest: TEST_MARKS_DIGEST,
            nonce: TEST_NONCE,
            request_id: TEST_REQUEST_ID.to_vec(),
            signature: [0u8; 64],
        };
        let preimage = commit_ack_signed_preimage(&f);
        assert_eq!(
            payload.as_slice(),
            &preimage[COMMIT_ACK_DOMAIN.len()..],
            "the 0x45 request payload body must byte-match the ack preimage's post-domain bytes — the two \
             independent map(8) emitters must agree; a divergence is an encoder/preimage drift (revisit \
             if COMMIT_REQUEST_VERSION and COMMIT_ACK_VERSION ever diverge)"
        );
    }
}
