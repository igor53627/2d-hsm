//! Enclave Protocol — canonical wire format for the 2D TEE signing service.
//!
//! This crate defines the length-prefixed CBOR protocol spoken over vsock
//! between the untrusted 2D host and the minimal PQ signing service inside
//! a TEE (Nitro Enclave / SEV-SNP).
//!
//! **High-risk component**: Any change here directly affects the ability
//! to sign AuthorizationTickets (including hard-fork announcements) and
//! to arm the enclave with correct network state.
//!
//! Review gate: Every non-trivial change must go through the 3:3 roborev
//! matrix + compact before being considered reviewed (see AGENTS.md).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// В Phase 1 мы оставляем часть публичных полей без документации,
// чтобы не раздувать скелет. На более поздних фазах документацию нужно будет довести до высокого уровня.
#![allow(missing_docs)]

mod chain_proof_crypto;
mod wire;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub use chain_proof_crypto::{
    build_proof_data_v1, build_signed_recent_chain_proof, compute_recovery_tail_digest,
    parse_proof_data_v1, sign_recent_chain_proof, verify_recent_chain_proof_crypto,
    ProducerAttestationTrust, ProofDataV1, PRODUCER_ATTESTATION_SIGNATURE_LEN,
    PROOF_DATA_FORMAT_V1, PROOF_DATA_V1_LEN,
};
#[cfg(any(test, feature = "test-support"))]
pub use chain_proof_crypto::{
    reference_test_attestation_signing_key, reference_test_attestation_trust,
};
pub use wire::{
    decode_arm_for_production_request, decode_get_status_request, decode_get_status_response,
    encode_arm_for_production_request, encode_get_status_request, encode_get_status_response,
};

/// Protocol version (bumped on breaking changes to the framing or core messages).
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowed message size (1 MiB).
/// 
/// Reduced from 64 MiB after Gemini security review on 2026-06-05:
/// In a TEE (Nitro Enclaves / SEV-SNP) memory is strictly limited.
/// A 64 MiB limit allows an untrusted host to force large allocations
/// via the length prefix, leading to resource exhaustion / OOM.
/// 1 MiB is more than sufficient for PQ signatures, attestations and tickets.
pub const MAX_MESSAGE_SIZE: u32 = 1 * 1024 * 1024;

/// Errors that can occur while (de)serializing or framing messages.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge(u32),

    #[error("invalid protocol version: got {got}, expected {expected}")]
    InvalidVersion { got: u8, expected: u8 },

    #[error("cbor decode error: {0}")]
    CborDecode(#[from] ciborium::de::Error<std::io::Error>),

    #[error("cbor encode error: {0}")]
    CborEncode(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unknown message type: {0}")]
    UnknownMessageType(u8),

    #[error("invalid ticket payload: {0}")]
    InvalidTicket(&'static str),

    /// Validation of the mandatory recent chain freshness proof failed.
    /// This error is security-critical: it prevents the enclave from arming
    /// under a stale, replayed, or attacker-supplied view of the chain.
    #[error("recent chain proof validation failed: {0}")]
    RecentChainProofValidation(&'static str),

    #[error("wire protocol error: {0}")]
    WireProtocol(&'static str),

    #[error("PQ signing unavailable: {0}")]
    PqSigningUnavailable(&'static str),
}

/// ML-DSA-65 wire sizes (FIPS 204, vsock spec §2.1).
pub const ML_DSA65_PUBKEY_LEN: usize = 1952;
pub const ML_DSA65_SIGNATURE_LEN: usize = 3309;

/// Wire message types (keep in sync with the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    GetMeasurement = 0x01,
    SignAuthorizationTicket = 0x10,
    ArmForProduction = 0x20,
    GetStatus = 0x30,
}

/// Простой диспетчер команд (скелет).
///
/// В реальном enclave здесь будет основная логика обработки входящих сообщений
/// от хоста. Пока оставлено как демонстрация структуры.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    GetMeasurement(GetMeasurementRequest),
    SignAuthorizationTicket(SignAuthorizationTicketRequest),
    ArmForProduction(ArmForProductionRequest),
    GetStatus(GetStatusRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    GetMeasurement(GetMeasurementResponse),
    SignAuthorizationTicket(SignAuthorizationTicketResponse),
    ArmForProduction(ArmForProductionResponse),
    GetStatus(GetStatusResponse),
    Error(String),
}

/// Top-level framed message.
///
/// This struct represents a single message on the wire after length-prefix decoding.
#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub version: u8,
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

/// Encode a message with length-prefixed framing.
///
/// Format (big-endian):
/// [u32 total_len] [u8 version] [u8 msg_type] [CBOR payload]
pub fn encode_message(msg_type: MessageType, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let total_len = 2 + payload.len(); // version + type + payload
    if total_len > MAX_MESSAGE_SIZE as usize {
        return Err(ProtocolError::MessageTooLarge(total_len as u32));
    }

    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_be_bytes());
    buf.push(PROTOCOL_VERSION);
    buf.push(msg_type as u8);
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Decode a length-prefixed framed message.
pub fn decode_message(data: &[u8]) -> Result<FramedMessage, ProtocolError> {
    if data.len() < 6 {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "frame too short",
        )));
    }

    let total_len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    if total_len > MAX_MESSAGE_SIZE as usize {
        return Err(ProtocolError::MessageTooLarge(total_len as u32));
    }
    if data.len() != 4 + total_len {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length mismatch",
        )));
    }

    let version = data[4];
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidVersion {
            got: version,
            expected: PROTOCOL_VERSION,
        });
    }

    let msg_type = match data[5] {
        0x01 => MessageType::GetMeasurement,
        0x10 => MessageType::SignAuthorizationTicket,
        0x20 => MessageType::ArmForProduction,
        0x30 => MessageType::GetStatus,
        other => return Err(ProtocolError::UnknownMessageType(other)),
    };

    let payload = data[6..].to_vec();

    Ok(FramedMessage {
        version,
        msg_type,
        payload,
    })
}

// -----------------------------------------------------------------------------
// Payload types (CBOR, using integer keys for compactness and determinism)
// -----------------------------------------------------------------------------

/// Request for GET_MEASUREMENT (empty for now).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMeasurementRequest {
    pub version: u8, // protocol version inside CBOR for extra safety
}

/// Response for GET_MEASUREMENT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMeasurementResponse {
    pub measurement: Vec<u8>,
    pub attestation: Vec<u8>,
    pub pq_pubkey: Vec<u8>,
    /// **Static capability list** — ticket types this enclave image can ever sign
    /// when all preconditions are met. Does not reflect current readiness
    /// (e.g. type=1 additionally requires armed state; see `GET_STATUS.armed`).
    pub supported_ticket_types: Vec<u8>,
    /// ML-DSA-65 signing operational in this build (false in release until TASK-1).
    pub pq_signing_ready: bool,
}

/// Whether this build can produce PQ signatures (mock/test vs production ML-DSA).
pub fn pq_signing_ready() -> bool {
    #[cfg(any(test, feature = "test-support"))]
    {
        true
    }
    #[cfg(not(any(test, feature = "test-support")))]
    {
        false
    }
}

// -----------------------------------------------------------------------------
// SignAuthorizationTicket (core for both recovery and hard forks)
// -----------------------------------------------------------------------------

/// Request to sign an AuthorizationTicket.
///
/// The enclave must:
/// - Verify it is currently armed as the authorized producer (for hard-fork tickets especially).
///
///   Hard-fork (type=1) requires `handle_sign_authorization_ticket_with_state`
///   after arming with a cryptographically verified `RecentChainProof` (TASK-3).
///   Stateless `handle_sign_authorization_ticket` still rejects type=1.
///
///   Recovery tickets (type 0) are currently allowed (bootstrap path).
///
/// - Compute the exact canonical `ticket_hash` (see below).
/// - Sign it with the PQ private key.
/// - Return the signature + the hash that was signed.
///
/// Recovery tickets (type 0) have a somewhat relaxed policy in early phases
/// (they are the bootstrap path), but even they benefit from the proof tail
/// checks inside `validate_recent_chain_proof` to limit replay windows.
///
/// **Important**: The actual state machine ("am I armed with a fresh-enough proof?")
/// and the exact gating logic live in the enclave implementation, **not** in this
/// protocol crate's request types. Do not add dispatch or handler code here
/// (that is Track A). This comment exists purely to make the security coupling
/// explicit for reviewers and future implementers.
///
/// This is the implementation of the canonical signed payload rules
/// fixed after the first roborev matrix (Codex HIGH + Claude confirmation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuthorizationTicketRequest {
    pub ticket: AuthorizationTicketPayload,
}

/// The payload that goes into the canonical hash for signing.
///
/// This must exactly match what the on-chain precompile will validate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationTicketPayload {
    pub ticket_type: u8,           // 0 = Recovery, 1 = HardFork
    pub nonce: u64,
    pub context_hash: [u8; 32],
    pub activation_height: u64,
    pub new_measurement: Vec<u8>,
    pub pq_pubkey: Vec<u8>,
    // For HARD_FORK_ACTIVATION these are mandatory in the signed preimage
    pub fork_spec_hash: Option<[u8; 32]>,
    pub new_header_version: Option<u32>,
}

/// Response after successful signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuthorizationTicketResponse {
    pub signature: Vec<u8>,
    pub ticket_hash: [u8; 32],   // The exact canonical hash that was signed
}

// -----------------------------------------------------------------------------
// ArmForProduction (with mandatory freshness proof) — Track B
// -----------------------------------------------------------------------------

/// Typed, verifiable structure carrying a recent chain freshness proof.
///
/// This replaces the previous opaque `Vec<u8>` for `recent_chain_proof`.
///
/// ## Security Rationale (critical for "network as second factor")
///
/// The host (block producer) is **untrusted**. A compromised or malicious host
/// must not be able to:
/// - Arm the enclave under a completely stale view of the chain.
/// - Replay an old `AuthorizationTicket` (especially RECOVERY) that was valid
///   at some past height but is no longer the live authorized producer.
/// - Convince the enclave that a hard-fork or recovery action is fresh when
///   the on-chain reality has moved on (long-range / replay attacks).
///
/// Therefore in a real implementation `ARM_FOR_PRODUCTION` should require a
/// cryptographically fresh proof that the claimed `AuthorizedProducerState`
/// is consistent with a recent finalized prefix of the canonical chain.
///
/// Cryptographic verification uses Producer Chain Attestation v1 in
/// `proof_data` plus `signature_from_recent_producer` (see `chain_proof_crypto`).
/// Full light-client proofs may extend or replace this format later.
///
/// Fields are intentionally minimal. A future light-client proof
/// (e.g. Tendermint/Beacon chain header + validator signatures, or 2D-specific
/// equivalent) will later live inside `proof_data` or replace parts of the
/// struct. We do **not** implement the full verifier here (explicitly out of
/// scope for this track).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentChainProof {
    /// Height of the most recent finalized block the proof attests to.
    /// Must be strictly monotonic and greater than or equal to the height at
    /// which the `authorized_state` was activated on-chain.
    pub finalized_height: u64,

    /// Hash of the finalized header (or state root, depending on final design).
    /// Non-zero value is a basic structural requirement.
    pub finalized_header_hash: [u8; 32],

    /// Hashes of the most recent RECOVERY and HARD_FORK_ACTIVATION tickets
    /// that were accepted on-chain and are visible in the recent history.
    ///
    /// Purpose: allow the enclave to detect whether the `source_ticket_hash`
    /// of the claimed `AuthorizedProducerState` is still part of the live
    /// tail, or whether a newer recovery/hard-fork has superseded it.
    /// This directly mitigates replay of old recovery tickets.
    pub recovery_history_tail: Vec<[u8; 32]>,

    /// Cryptographic proof material. **MVP (TASK-3):** Producer Chain
    /// Attestation v1 — see `chain_proof_crypto` (`0x01` || 32-byte tail digest).
    pub proof_data: Vec<u8>,

    /// Mandatory Ed25519 signature (64 bytes) over the domain-separated
    /// preimage defined in `chain_proof_crypto::recent_chain_proof_signing_preimage`.
    pub signature_from_recent_producer: Option<Vec<u8>>,
}

/// Request to arm the enclave for production under a specific authorized state.
///
/// Per review findings (Codex HIGH + Claude + Gemini, 5a0e3e2 matrix):
/// - `recent_chain_proof` is now **mandatory** and **typed** (not raw bytes).
/// - In the real enclave, `validate_recent_chain_proof` (or its future
///   cryptographic successor) **must** be called before arming.
///
///   Cryptographic verification of `RecentChainProof` is required (TASK-3).
///
/// After a successful arming the enclave records that it has seen a fresh proof.
/// Subsequent `SIGN_AUTHORIZATION_TICKET` for type=1 (HARD_FORK) **must** only
/// succeed if the enclave is currently armed under a proof whose
/// `finalized_height` is sufficiently recent relative to the ticket's
/// `activation_height` (exact policy to be enforced in the real enclave state
/// machine — see comments below; handler logic itself is Track A).
///
/// The previous raw `Vec<u8>` representation made it impossible for the type
/// system and reviewers to reason about the required fields and invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmForProductionRequest {
    pub authorized_state: AuthorizedProducerState,
    pub recent_chain_proof: RecentChainProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedProducerState {
    pub pq_pubkey: Vec<u8>,
    pub measurement: Vec<u8>,
    pub activated_at_height: u64,
    pub source_ticket_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmForProductionResponse {
    pub status: String,   // "armed" or "refused"
    pub reason: Option<String>,
}

// -----------------------------------------------------------------------------
// Enclave State (for AC #7 - ArmForProduction with actual state tracking)
// -----------------------------------------------------------------------------

/// Represents the state of the enclave after a successful `ARM_FOR_PRODUCTION`.
///
/// This is a minimal skeleton type used in Phase 1 to track authorization state.
/// In a real TEE implementation this information would be sealed inside the
/// enclave, protected by the TEE, and never exposed to the untrusted host
/// except through carefully controlled queries (e.g. `GET_STATUS`).
#[derive(Debug, Clone)]
pub struct EnclaveArmedState {
    /// The `RecentChainProof` that was successfully validated during arming.
    pub proof: RecentChainProof,

    /// Pinned producer attestation identity used to verify this session's proof.
    pub attestation_trust: ProducerAttestationTrust,

    /// On-chain activation height of the authorized producer (from
    /// `AuthorizedProducerState.activated_at_height` at arming time).
    /// Not the chain tip height at arming — see `proof.finalized_height` / GET_STATUS.
    pub authorized_activated_at_height: u64,

    /// The measurement that was authorized during this arming.
    /// Exposed via GET_STATUS so the host can know what code is considered active.
    pub authorized_measurement: Vec<u8>,

    /// The PQ pubkey that was authorized.
    pub authorized_pq_pubkey: Vec<u8>,

    /// The source ticket hash from the AuthorizedProducerState used at arming.
    /// Useful for auditing and future sign-time anti-replay checks.
    pub source_ticket_hash: [u8; 32],

    /// If a HARD_FORK_ACTIVATION ticket was signed while armed, records its
    /// `activation_height` for observability via `GET_STATUS`.
    pub pending_hard_fork_height: Option<u64>,
}

/// Current authorization state of the enclave.
///
/// This enum allows the skeleton (and future real enclave) to track whether
/// it has been successfully armed for production and with which proof.
#[derive(Debug, Clone, Default)]
pub enum EnclaveState {
    /// The enclave has not yet been armed (or has been reset).
    #[default]
    Unarmed,

    /// The enclave is currently armed with a validated proof.
    Armed(EnclaveArmedState),
}

/// Validates a `RecentChainProof` against the `AuthorizedProducerState` that
/// the caller wishes to arm the enclave with.
///
/// ## Security Invariants (MUST hold — fail closed on any violation)
///
/// 1. The proof must demonstrate that the chain has progressed at least to the
///    activation height of the authorized state (or beyond). This prevents
///    arming the enclave with an ancient "authorized producer" that has long
///    been replaced on-chain.
/// 2. Structural sanity: heights positive, header hash non-zero, etc.
/// 3. If `recovery_history_tail` is non-empty, the `source_ticket_hash` from
///    the authorized state **must** appear in it. Failure to contain it when
///    the tail is non-empty is now a hard error (see code below).
/// 4. `proof_data` and `signature_from_recent_producer` must pass Producer
///    Chain Attestation v1 verification (`verify_recent_chain_proof_crypto`).
///
/// Called at `ARM_FOR_PRODUCTION` and again at hard-fork sign time.
///
/// Returns `Ok(())` only when structural and cryptographic checks pass.
pub fn validate_recent_chain_proof(
    proof: &RecentChainProof,
    current_authorized: &AuthorizedProducerState,
    trust: &ProducerAttestationTrust,
) -> Result<(), ProtocolError> {
    if proof.finalized_header_hash == [0u8; 32] {
        return Err(ProtocolError::RecentChainProofValidation(
            "finalized_header_hash must not be zero",
        ));
    }

    if proof.finalized_height == 0 {
        return Err(ProtocolError::RecentChainProofValidation(
            "finalized_height must be positive",
        ));
    }

    if proof.finalized_height < current_authorized.activated_at_height {
        return Err(ProtocolError::RecentChainProofValidation(
            "finalized_height is older than the authorized state's activation height (stale/replay)",
        ));
    }

    // Basic anti-replay: if the tail is non-empty, the claimed source ticket
    // must be present in it. This is now a hard error (post-matrix fix).
    if !proof.recovery_history_tail.is_empty() {
        let source_in_tail = proof
            .recovery_history_tail
            .iter()
            .any(|h| h == &current_authorized.source_ticket_hash);
        if !source_in_tail {
            return Err(ProtocolError::RecentChainProofValidation(
                "recovery_history_tail is non-empty but does not contain the claimed source_ticket_hash (possible replay or superseded state)",
            ));
        }
    }

    // Reject obviously malformed tail entries
    for hash in &proof.recovery_history_tail {
        if *hash == [0u8; 32] {
            return Err(ProtocolError::RecentChainProofValidation(
                "recovery_history_tail contains zero hash",
            ));
        }
    }

    verify_recent_chain_proof_crypto(proof, current_authorized, trust)?;

    Ok(())
}

/// Attempts to arm (or re-arm) the enclave with the provided authorization.
///
/// This is the core pure function for AC #7. It:
/// - Validates the supplied `RecentChainProof` against the claimed `AuthorizedProducerState`
/// - On success, produces a new `EnclaveState::Armed(...)`
///
/// In a real enclave this function would be called by the vsock handler,
/// and the resulting state would be sealed inside the TEE.
///
pub fn arm_for_production(
    current_state: &EnclaveState,
    req: ArmForProductionRequest,
    trust: ProducerAttestationTrust,
) -> Result<EnclaveState, ProtocolError> {
    if let EnclaveState::Armed(ref armed) = current_state {
        if req.recent_chain_proof.finalized_height <= armed.proof.finalized_height {
            return Err(ProtocolError::RecentChainProofValidation(
                "re-arm requires strictly greater finalized_height than the current session proof",
            ));
        }
        if armed.attestation_trust.attestation_verifying_key.to_bytes()
            != trust.attestation_verifying_key.to_bytes()
        {
            return Err(ProtocolError::RecentChainProofValidation(
                "re-arm attestation trust must match the current session trust anchor",
            ));
        }
    }

    validate_recent_chain_proof(&req.recent_chain_proof, &req.authorized_state, &trust)?;

    let armed_state = EnclaveArmedState {
        proof: req.recent_chain_proof,
        attestation_trust: trust,
        authorized_activated_at_height: req.authorized_state.activated_at_height,
        authorized_measurement: req.authorized_state.measurement,
        authorized_pq_pubkey: req.authorized_state.pq_pubkey,
        source_ticket_hash: req.authorized_state.source_ticket_hash,
        pending_hard_fork_height: None,
    };

    Ok(EnclaveState::Armed(armed_state))
}

/// Reconstructs the `AuthorizedProducerState` that was used when the enclave armed.
fn authorized_state_from_armed(armed: &EnclaveArmedState) -> AuthorizedProducerState {
    AuthorizedProducerState {
        pq_pubkey: armed.authorized_pq_pubkey.clone(),
        measurement: armed.authorized_measurement.clone(),
        activated_at_height: armed.authorized_activated_at_height,
        source_ticket_hash: armed.source_ticket_hash,
    }
}

/// Sign-time checks for HARD_FORK_ACTIVATION (type=1).
///
/// Re-runs full `validate_recent_chain_proof` (structural + cryptographic) on the
/// armed proof snapshot and enforces activation-height ordering.
fn validate_hard_fork_sign_preconditions(
    ticket: &AuthorizationTicketPayload,
    armed: &EnclaveArmedState,
) -> Result<(), ProtocolError> {
    if armed.pending_hard_fork_height.is_some() {
        return Err(ProtocolError::InvalidTicket(
            "only one HARD_FORK_ACTIVATION ticket may be signed per armed session; re-arm to announce another fork",
        ));
    }

    if ticket.pq_pubkey != armed.authorized_pq_pubkey {
        return Err(ProtocolError::InvalidTicket(
            "pq_pubkey in hard-fork ticket must match the currently armed producer key",
        ));
    }

    let authorized = authorized_state_from_armed(armed);
    validate_recent_chain_proof(&armed.proof, &authorized, &armed.attestation_trust)?;

    if ticket.activation_height <= armed.proof.finalized_height {
        return Err(ProtocolError::InvalidTicket(
            "activation_height must be strictly greater than the finalized height from the armed RecentChainProof (stale chain view)",
        ));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// GetStatus
// -----------------------------------------------------------------------------

/// Пустой запрос на статус (пока не несёт полезной нагрузки).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatusRequest {
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStatusResponse {
    pub armed: bool,

    /// The measurement that was authorized when the enclave was armed.
    /// In Phase 1 this is the value captured at arming time.
    pub authorized_measurement: Vec<u8>,

    /// The PQ public key that was authorized when the enclave was armed.
    pub authorized_pq_pubkey: Vec<u8>,

    /// On-chain activation height of the authorized producer captured at arming.
    /// None when unarmed. Distinct from `proof_finalized_height` (chain view at arm).
    pub authorized_activated_at_height: Option<u64>,

    /// The finalized height from the proof that was used during arming.
    /// This gives the host visibility into how fresh the chain view was
    /// at the moment of arming.
    /// None when unarmed.
    pub proof_finalized_height: Option<u64>,

    /// The source ticket hash from the AuthorizedProducerState that was used
    /// during this arming. Useful for auditing and for future sign-time
    /// anti-replay checks (see AC #8).
    /// None when unarmed.
    pub source_ticket_hash: Option<[u8; 32]>,

    pub pending_hard_fork_height: Option<u64>,
    pub last_known_block: Option<u64>,
}

// -----------------------------------------------------------------------------
// Canonical hash computation (must be identical on enclave and precompile side)
// -----------------------------------------------------------------------------

/// Computes the **canonical** `ticketHash` that the enclave must sign,
/// using the **normative** preimage defined in the spec:
///
/// `keccak256(abi.encode(ticketType, nonce, contextHash, activationHeight,
///                       newMeasurement, pqPubkey, forkSpecHash, newHeaderVersion))`
///
/// This function now implements the exact layout that Solidity `abi.encode`
/// produces for the tuple `(uint8, uint64, bytes32, uint64, bytes, bytes, bytes32, uint32)`.
///
/// This is the implementation that must be used for all future ticket signing
/// (both in the enclave and eventually mirrored in the on-chain precompile verification).
pub fn compute_canonical_ticket_hash(payload: &AuthorizationTicketPayload) -> [u8; 32] {
    let mut hasher = Keccak256::new();

    // --- Head (static part, exactly 8 × 32 bytes for the 8-tuple) ---
    //
    // Tuple: (uint8, uint64, bytes32, uint64, bytes, bytes, bytes32, uint32)
    // This must produce bit-for-bit identical preimage to Solidity's
    // `abi.encode(...)` + `keccak256` as defined in the normative spec.
    //
    // Head layout (words 0-7):
    // 0: ticketType
    // 1: nonce
    // 2: contextHash
    // 3: activationHeight
    // 4: offset(newMeasurement) = 256
    // 5: offset(pqPubkey) = 256 + 32 + padded(newMeasurement)
    // 6: forkSpecHash (0 for recovery per script)
    // 7: newHeaderVersion (0 for recovery per script)

    // 0. ticketType as uint8 (right-padded to 32 bytes)
    let mut word = [0u8; 32];
    word[31] = payload.ticket_type;
    hasher.update(word);

    // 1. nonce as uint64
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&payload.nonce.to_be_bytes());
    hasher.update(word);

    // 2. contextHash (bytes32)
    hasher.update(payload.context_hash);

    // 3. activationHeight as uint64
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&payload.activation_height.to_be_bytes());
    hasher.update(word);

    // 4. offset for first dynamic (newMeasurement): always 256 (after 8-word head)
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&(256u64).to_be_bytes());
    hasher.update(word);

    // 5. offset for second dynamic (pqPubkey)
    // Data for newMeasurement starts at 256, consists of: 32-byte length word + actual data bytes + right-zero padding to 32
    let meas_len = payload.new_measurement.len() as u64;
    let meas_data_padded = 32 + meas_len + ((32 - (meas_len % 32)) % 32);
    let pq_offset: u64 = 256 + meas_data_padded;
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&pq_offset.to_be_bytes());
    hasher.update(word);

    // 6. forkSpecHash — for recovery (type 0) the canonical script forces bytes32(0)
    // even if the JSON had a value; for hard-fork use the provided value.
    let fork_hash = if payload.ticket_type == 0 {
        [0u8; 32]
    } else {
        payload.fork_spec_hash.unwrap_or([0u8; 32])
    };
    hasher.update(fork_hash);

    // 7. newHeaderVersion — same rule: 0 for recovery, real value for hard-fork.
    let ver = if payload.ticket_type == 0 {
        0u32
    } else {
        payload.new_header_version.unwrap_or(0)
    };
    let mut word = [0u8; 32];
    word[28..32].copy_from_slice(&ver.to_be_bytes());
    hasher.update(word);

    // --- Tail (dynamic data section, in declaration order) ---

    // newMeasurement (bytes): length word + data + right-zero padding to 32
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&meas_len.to_be_bytes());
    hasher.update(word);
    hasher.update(&payload.new_measurement);
    let padding = (32 - (meas_len % 32)) % 32;
    if padding > 0 {
        hasher.update(&[0u8; 32][..padding as usize]);
    }

    // pqPubkey (bytes): length word + data + padding
    let pq_len = payload.pq_pubkey.len() as u64;
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&pq_len.to_be_bytes());
    hasher.update(word);
    hasher.update(&payload.pq_pubkey);
    let padding = (32 - (pq_len % 32)) % 32;
    if padding > 0 {
        hasher.update(&[0u8; 32][..padding as usize]);
    }

    let result = hasher.finalize();
    result.into()
}

/// Validates that a ticket payload is well-formed before hashing/signing.
///
/// Returns error for hard-fork tickets that are missing required fields.
/// This was added to address the MEDIUM finding from the matrix.
pub fn validate_ticket_payload(payload: &AuthorizationTicketPayload) -> Result<(), ProtocolError> {
    match payload.ticket_type {
        0 => {
            // Recovery
            if payload.fork_spec_hash.is_some() || payload.new_header_version.is_some() {
                return Err(ProtocolError::InvalidTicket(
                    "Non-hard-fork tickets must not include hard-fork specific fields",
                ));
            }
        }
        1 => {
            // HARD_FORK_ACTIVATION (must match precompile skeleton §4 decoder table)
            let fork_spec = payload.fork_spec_hash.ok_or(ProtocolError::InvalidTicket(
                "Hard-fork tickets must include fork_spec_hash",
            ))?;
            if fork_spec == [0u8; 32] {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork fork_spec_hash must be non-zero",
                ));
            }
            let header_version = payload.new_header_version.ok_or(ProtocolError::InvalidTicket(
                "Hard-fork tickets must include new_header_version",
            ))?;
            if header_version == 0 {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork new_header_version must be non-zero",
                ));
            }
        }
        _ => {
            // Strict allow-list: only 0 and 1 are supported.
            // This addresses the Medium finding from the matrix on 402fdba
            // (default-allow for unknown ticket_type values creates a signing oracle risk).
            return Err(ProtocolError::InvalidTicket(
                "Unsupported ticket_type (only 0 = Recovery and 1 = HardFork are allowed)",
            ));
        }
    }
    Ok(())
}

/// High-level helper: validates the payload and returns the canonical hash
/// that should be signed.
///
/// This is the function the TEE signing service will most likely call
/// before producing a signature over an AuthorizationTicket.
pub fn prepare_ticket_for_signing(
    payload: &AuthorizationTicketPayload,
) -> Result<[u8; 32], ProtocolError> {
    validate_ticket_payload(payload)?;
    Ok(compute_canonical_ticket_hash(payload))
}

// =============================================================================
// Track A: Real command dispatch + SignAuthorizationTicket handler
// =============================================================================
//
// This is the first production-grade implementation of the vsock command
// handlers on top of the already-reviewed framing and canonical hash logic.
//
// Security notes (references to prior roborev work):
// - The only path that may produce a signature over an AuthorizationTicket
//   is `handle_sign_authorization_ticket` → `prepare_ticket_for_signing`.
// - For HARD_FORK_ACTIVATION tickets, the real enclave must additionally
//   check that it is currently armed under a *fresh* RecentChainProof
//   (see Track B coupling comments on SignAuthorizationTicketRequest).
// - The mock signature below is obviously fake and contains a clear
//   "DO-NOT-USE-IN-REAL-ENCLAVE" marker. It will be replaced by real
//   ML-DSA (or SLH-DSA) inside the TEE.
//
// All future changes to this module must go through the 3:3 process
// defined in AGENTS.md / .roborev.toml.
// =============================================================================

/// Production PQ signature (TASK-1: ML-DSA-65 via mldsa-native inside TEE).
#[cfg(not(any(test, feature = "test-support")))]
fn produce_pq_signature(
    _ticket_hash: &[u8; 32],
    _nonce: u64,
) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::PqSigningUnavailable(
        "ML-DSA-65 signing not implemented; enable feature test-support for mock-only demos or complete TASK-1",
    ))
}

/// Deterministic mock for a post-quantum signature (tests / `test-support` only).
#[cfg(any(test, feature = "test-support"))]
fn compute_mock_pq_signature(ticket_hash: &[u8; 32], nonce: u64) -> Vec<u8> {
    const MOCK_SECRET: &[u8] = b"2d-hsm-track-a-deterministic-mock-pq-sig-secret--DO-NOT-USE-IN-REAL-ENCLAVE--THIS-IS-ONLY-FOR-TESTING-THE-PROTOCOL-LAYER--";

    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(MOCK_SECRET);
    hasher.update(ticket_hash);
    hasher.update(nonce.to_be_bytes());
    let first = hasher.finalize();

    // Second round for "length"
    let mut hasher2 = Sha3_256::new();
    hasher2.update(&first);
    hasher2.update(b"second-round-for-64-byte-mock");
    let second = hasher2.finalize();

    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&first);
    sig.extend_from_slice(&second);
    sig
}

#[cfg(any(test, feature = "test-support"))]
fn produce_pq_signature(ticket_hash: &[u8; 32], nonce: u64) -> Result<Vec<u8>, ProtocolError> {
    Ok(compute_mock_pq_signature(ticket_hash, nonce))
}

/// Signs a PRODUCER_RECOVERY ticket (type=0) without requiring armed state.
///
/// HARD_FORK_ACTIVATION (type=1) must use `handle_sign_authorization_ticket_with_state`.
fn sign_recovery_ticket(
    ticket: &AuthorizationTicketPayload,
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    let ticket_hash = prepare_ticket_for_signing(ticket)?;
    let signature = produce_pq_signature(&ticket_hash, ticket.nonce)?;
    Ok(SignAuthorizationTicketResponse {
        signature,
        ticket_hash,
    })
}

/// The stateless signing entry point (legacy / host paths without enclave state).
///
/// Recovery tickets (type=0) are allowed. Hard-fork tickets (type=1) are rejected
/// here by design — they require `handle_sign_authorization_ticket_with_state`.
pub fn handle_sign_authorization_ticket(
    req: SignAuthorizationTicketRequest,
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    if req.ticket.ticket_type == 1 {
        return Err(ProtocolError::InvalidTicket(
            "Hard-fork (type=1) ticket signing requires armed enclave state. \
             Use dispatch_command_with_state after ARM_FOR_PRODUCTION with a validated RecentChainProof.",
        ));
    }

    sign_recovery_ticket(&req.ticket)
}

/// Stateful signing entry point — the recommended path for all ticket types.
///
/// - type=0 (recovery): allowed when armed or unarmed.
/// - type=1 (hard fork): requires `EnclaveState::Armed`, full proof validation
///   (structural + crypto), activation-height ordering, one hard-fork per session.
pub fn handle_sign_authorization_ticket_with_state(
    req: SignAuthorizationTicketRequest,
    state: &mut EnclaveState,
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    match req.ticket.ticket_type {
        0 => sign_recovery_ticket(&req.ticket),
        1 => {
            let EnclaveState::Armed(ref mut armed) = state else {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork signing requires the enclave to be armed via ARM_FOR_PRODUCTION with a validated RecentChainProof",
                ));
            };

            validate_hard_fork_sign_preconditions(&req.ticket, armed)?;

            let ticket_hash = prepare_ticket_for_signing(&req.ticket)?;
            let signature = produce_pq_signature(&ticket_hash, req.ticket.nonce)?;

            armed.pending_hard_fork_height = Some(req.ticket.activation_height);

            Ok(SignAuthorizationTicketResponse {
                signature,
                ticket_hash,
            })
        }
        _ => {
            validate_ticket_payload(&req.ticket)?;
            unreachable!("validate_ticket_payload only accepts ticket types 0 and 1");
        }
    }
}

/// Stateless dispatcher — **recovery tickets (type 0) and GET_MEASUREMENT only**.
///
/// Hard-fork signing, `ARM_FOR_PRODUCTION`, and `GET_STATUS` require
/// [`dispatch_command_with_state`] with an enclave-held [`ProducerAttestationTrust`]
/// (see §9.3 in the vsock spec — the host must not choose the trust anchor).
pub fn dispatch_command(cmd: Command) -> Response {
    match cmd {
        Command::SignAuthorizationTicket(req) => {
            match handle_sign_authorization_ticket(req) {
                Ok(resp) => Response::SignAuthorizationTicket(resp),
                Err(e) => Response::Error(format!("sign_authorization_ticket failed: {}", e)),
            }
        }
        Command::GetMeasurement(_req) => {
            // Minimal but useful response for now.
            // In a real enclave this would return the actual measurement
            // of the running image + supported operations.
            Response::GetMeasurement(GetMeasurementResponse {
                measurement: b"enclave-measurement-placeholder".to_vec(),
                attestation: b"attestation-placeholder".to_vec(),
                pq_pubkey: vec![0xDE, 0xAD, 0xBE, 0xEF],
                // Image capability: hard-fork is supported only via the stateful path.
                supported_ticket_types: vec![0, 1],
                pq_signing_ready: pq_signing_ready(),
            })
        }
        Command::ArmForProduction(_) => Response::Error(
            "ARM_FOR_PRODUCTION requires dispatch_command_with_state and an enclave-held ProducerAttestationTrust (host cannot supply the trust anchor)".to_string(),
        ),
        Command::GetStatus(_) => Response::Error(
            "GET_STATUS requires dispatch_command_with_state".to_string(),
        ),
    }
}

/// Stateful dispatcher — **required** for arming, status, and hard-fork signing.
///
/// `attestation_trust` must be loaded inside the TEE from sealed configuration or
/// an attested provisioning channel (PCR/policy-bound manifest). The untrusted
/// host must **never** pass the trust anchor over vsock; only the enclave binary
/// or attested bootstrapping code may call this with the pinned verifying key.
pub fn dispatch_command_with_state(
    cmd: Command,
    state: &mut EnclaveState,
    attestation_trust: ProducerAttestationTrust,
) -> Response {
    match cmd {
        Command::SignAuthorizationTicket(req) => {
            match handle_sign_authorization_ticket_with_state(req, state) {
                Ok(resp) => Response::SignAuthorizationTicket(resp),
                Err(e) => Response::Error(format!("sign_authorization_ticket failed: {}", e)),
            }
        }
        Command::GetMeasurement(_req) => {
            Response::GetMeasurement(GetMeasurementResponse {
                measurement: b"enclave-measurement-placeholder".to_vec(),
                attestation: b"attestation-placeholder".to_vec(),
                pq_pubkey: vec![0xDE, 0xAD, 0xBE, 0xEF],
                supported_ticket_types: vec![0, 1],
                pq_signing_ready: pq_signing_ready(),
            })
        }
        Command::ArmForProduction(req) => {
            match arm_for_production(state, req, attestation_trust) {
                Ok(new_state) => {
                    *state = new_state;
                    Response::ArmForProduction(ArmForProductionResponse {
                        status: "armed".to_string(),
                        reason: None,
                    })
                }
                Err(e) => Response::ArmForProduction(ArmForProductionResponse {
                    status: "refused".to_string(),
                    reason: Some(e.to_string()),
                }),
            }
        }
        Command::GetStatus(_req) => Response::GetStatus(build_get_status_response(state)),
    }
}

/// Builds the logical GET_STATUS payload (encode on the wire with [`encode_get_status_response`]).
pub fn build_get_status_response(state: &EnclaveState) -> GetStatusResponse {
    match state {
        EnclaveState::Armed(s) => GetStatusResponse {
            armed: true,
            authorized_measurement: s.authorized_measurement.clone(),
            authorized_pq_pubkey: s.authorized_pq_pubkey.clone(),
            authorized_activated_at_height: Some(s.authorized_activated_at_height),
            proof_finalized_height: Some(s.proof.finalized_height),
            source_ticket_hash: Some(s.source_ticket_hash),
            pending_hard_fork_height: s.pending_hard_fork_height,
            last_known_block: Some(s.proof.finalized_height),
        },
        EnclaveState::Unarmed => GetStatusResponse {
            armed: false,
            authorized_measurement: vec![],
            authorized_pq_pubkey: vec![],
            authorized_activated_at_height: None,
            proof_finalized_height: None,
            source_ticket_hash: None,
            pending_hard_fork_height: None,
            last_known_block: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attestation_signing_key() -> ed25519_dalek::SigningKey {
        crate::chain_proof_crypto::reference_test_attestation_signing_key()
    }

    fn test_attestation_trust() -> ProducerAttestationTrust {
        crate::chain_proof_crypto::reference_test_attestation_trust()
    }

    fn signed_recent_chain_proof(
        finalized_height: u64,
        finalized_header_hash: [u8; 32],
        recovery_history_tail: Vec<[u8; 32]>,
        authorized: &AuthorizedProducerState,
    ) -> RecentChainProof {
        build_signed_recent_chain_proof(
            finalized_height,
            finalized_header_hash,
            recovery_history_tail,
            authorized,
            &test_attestation_signing_key(),
        )
        .expect("test proof signing must succeed")
    }

    #[test]
    fn get_status_wire_roundtrip_matches_spec_integer_keys() {
        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![0x01; 48],
            measurement: b"m".to_vec(),
            activated_at_height: 5,
            source_ticket_hash: [0x02; 32],
        };
        let state = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: signed_recent_chain_proof(
                    10,
                    [0x03; 32],
                    vec![[0x02; 32]],
                    &authorized,
                ),
            },
            test_attestation_trust(),
        )
        .unwrap();
        let logical = build_get_status_response(&state);
        let wire = encode_get_status_response(&logical).unwrap();
        let decoded = decode_get_status_response(&wire).unwrap();
        assert!(decoded.armed);
        assert_eq!(decoded.proof_finalized_height, Some(10));
    }

    #[test]
    fn arm_request_wire_roundtrip_structured_recent_chain_proof() {
        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![7],
            measurement: b"meas".to_vec(),
            activated_at_height: 1,
            source_ticket_hash: [0x08; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(2, [0x09; 32], vec![], &authorized),
        };
        let wire = encode_arm_for_production_request(&req).unwrap();
        let decoded = decode_arm_for_production_request(&wire).unwrap();
        assert_eq!(decoded.recent_chain_proof.finalized_height, 2);
    }

    #[test]
    fn stateless_dispatch_rejects_arm_with_actionable_error() {
        let resp = dispatch_command(Command::ArmForProduction(ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: vec![],
                measurement: vec![],
                activated_at_height: 0,
                source_ticket_hash: [0; 32],
            },
            recent_chain_proof: RecentChainProof {
                finalized_height: 1,
                finalized_header_hash: [1; 32],
                recovery_history_tail: vec![],
                proof_data: vec![0x01],
                signature_from_recent_producer: None,
            },
        }));
        match resp {
            Response::Error(msg) => {
                assert!(msg.contains("dispatch_command_with_state"));
                assert!(msg.contains("ProducerAttestationTrust"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn roundtrip_get_measurement() {
        let req = GetMeasurementRequest { version: 1 };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&req, &mut payload).unwrap();

        let framed = encode_message(MessageType::GetMeasurement, &payload).unwrap();
        let decoded = decode_message(&framed).unwrap();

        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.msg_type, MessageType::GetMeasurement);

        let decoded_req: GetMeasurementRequest =
            ciborium::de::from_reader(&decoded.payload[..]).unwrap();
        assert_eq!(decoded_req.version, 1);
    }

    // ---------------------------------------------------------------------
    // TRACK B — RecentChainProof validation tests
    // ---------------------------------------------------------------------

    #[test]
    fn roundtrip_recent_chain_proof_cbor() {
        let proof = RecentChainProof {
            finalized_height: 1_234_567,
            finalized_header_hash: [0xAB; 32],
            recovery_history_tail: vec![[0x11; 32], [0x22; 32]],
            proof_data: vec![1, 2, 3, 4],
            signature_from_recent_producer: Some(vec![9; 64]),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&proof, &mut buf).unwrap();

        let decoded: RecentChainProof = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.finalized_height, 1_234_567);
        assert_eq!(decoded.recovery_history_tail.len(), 2);
    }

    #[test]
    fn validate_recent_chain_proof_accepts_valid_signed_proof() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let proof = signed_recent_chain_proof(150, [0xFE; 32], vec![[0xCA; 32]], &state);
        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_ok());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_empty_proof_data() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let proof = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0xCA; 32]],
            proof_data: vec![],
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_err());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_missing_signature() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let proof = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0xCA; 32]],
            proof_data: build_proof_data_v1(&[[0xCA; 32]]),
            signature_from_recent_producer: None,
        };

        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_err());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_forged_height_with_valid_signature() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        };

        let mut proof = signed_recent_chain_proof(150, [0xFE; 32], vec![[0xCA; 32]], &state);
        proof.finalized_height = 9999;
        assert!(validate_recent_chain_proof(&proof, &state, &test_attestation_trust()).is_err());
    }

    #[test]
    fn arm_and_hardfork_reject_unsigned_proof() {
        let pq = vec![0xAB; 48];
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq.clone(),
            measurement: b"m".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCC; 32],
        };

        let unsigned = RecentChainProof {
            finalized_height: 200,
            finalized_header_hash: [0xDD; 32],
            recovery_history_tail: vec![[0xCC; 32]],
            proof_data: vec![],
            signature_from_recent_producer: None,
        };

        let arm_err = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: unsigned.clone(),
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(
            arm_err,
            ProtocolError::RecentChainProofValidation(_)
        ));

        let mut state = EnclaveState::Unarmed;
        dispatch_command_with_state(
            Command::ArmForProduction(ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: signed_recent_chain_proof(
                    200,
                    [0xDD; 32],
                    vec![[0xCC; 32]],
                    &authorized,
                ),
            }),
            &mut state,
            test_attestation_trust(),
        );

        let ticket = sample_hardfork_ticket(pq, 300);
        let sign_resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state,
            test_attestation_trust(),
        );
        assert!(matches!(sign_resp, Response::SignAuthorizationTicket(_)));

        if let EnclaveState::Armed(ref armed) = state {
            let mut tampered = armed.proof.clone();
            tampered.proof_data.clear();
            tampered.signature_from_recent_producer = None;
            let mut bad_state = EnclaveState::Armed(EnclaveArmedState {
                proof: tampered,
                pending_hard_fork_height: None,
                ..armed.clone()
            });
            let ticket2 = sample_hardfork_ticket(vec![0xAB; 48], 400);
            let err = handle_sign_authorization_ticket_with_state(
                SignAuthorizationTicketRequest { ticket: ticket2 },
                &mut bad_state,
            )
            .unwrap_err();
            assert!(
                matches!(err, ProtocolError::RecentChainProofValidation(_)),
                "expected crypto proof failure at sign time, got {:?}",
                err
            );
        }
    }

    #[test]
    fn arm_rejects_measurement_mismatch_after_signing() {
        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![0xAB; 48],
            measurement: b"legit-meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCC; 32],
        };
        let proof = signed_recent_chain_proof(200, [0xDD; 32], vec![[0xCC; 32]], &authorized);
        let mut forged = authorized.clone();
        forged.measurement = b"evil-meas".to_vec();
        let err = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: forged,
                recent_chain_proof: proof,
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::RecentChainProofValidation(_)
        ));
    }

    #[test]
    fn re_arm_requires_strictly_fresher_finalized_height() {
        let pq = vec![0xEE; 48];
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq,
            measurement: b"m".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };

        let first = signed_recent_chain_proof(200, [0x11; 32], vec![[0xAA; 32]], &authorized);
        let armed = arm_for_production(
            &EnclaveState::Unarmed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: first,
            },
            test_attestation_trust(),
        )
        .unwrap();

        let stale_rearm = signed_recent_chain_proof(200, [0x22; 32], vec![[0xAA; 32]], &authorized);
        let err = arm_for_production(
            &armed,
            ArmForProductionRequest {
                authorized_state: authorized.clone(),
                recent_chain_proof: stale_rearm,
            },
            test_attestation_trust(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::RecentChainProofValidation(_)
        ));

        let fresher = signed_recent_chain_proof(250, [0x33; 32], vec![[0xAA; 32]], &authorized);
        assert!(arm_for_production(
            &armed,
            ArmForProductionRequest {
                authorized_state: authorized,
                recent_chain_proof: fresher,
            },
            test_attestation_trust(),
        )
        .is_ok());
    }

    #[test]
    fn validate_recent_chain_proof_rejects_non_empty_tail_without_source_ticket() {
        // This is the central anti-replay case that was made a hard error in 5369c3a
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };

        let bad = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0x11; 32]], // non-empty but does not contain source
            proof_data: build_proof_data_v1(&[[0x11; 32]]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&bad, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn arm_for_production_transitions_state_on_valid_proof() {
        // Basic test for the new arm_for_production function (AC #7)
        let initial = EnclaveState::Unarmed;

        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                150,
                [0xFE; 32],
                vec![[0xAA; 32]],
                &authorized,
            ),
        };

        let new_state = arm_for_production(&initial, req, test_attestation_trust()).expect("arming should succeed");

        match new_state {
            EnclaveState::Armed(s) => {
                assert_eq!(s.authorized_activated_at_height, 100);
            }
            EnclaveState::Unarmed => panic!("expected Armed state"),
        }
    }

    #[test]
    fn dispatch_arm_for_production_updates_state() {
        // Demonstrates using the stateful dispatcher (the new recommended path)
        let mut state = EnclaveState::Unarmed;

        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![1; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xAA; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                150,
                [0xFE; 32],
                vec![[0xAA; 32]],
                &authorized,
            ),
        };

        let cmd = Command::ArmForProduction(req);
        let resp = dispatch_command_with_state(cmd, &mut state, test_attestation_trust());

        match resp {
            Response::ArmForProduction(r) => {
                assert_eq!(r.status, "armed");
            }
            _ => panic!("expected ArmForProduction response"),
        }

        // State should now be armed
        assert!(matches!(state, EnclaveState::Armed(_)));

        // Also verify via GetStatus
        let status = match dispatch_command_with_state(Command::GetStatus(GetStatusRequest { version: 1 }), &mut state, test_attestation_trust()) {
            Response::GetStatus(r) => r,
            _ => panic!("expected GetStatus"),
        };
        assert!(status.armed);
        assert_eq!(status.authorized_activated_at_height, Some(100));
        assert_eq!(status.proof_finalized_height, Some(150));
        assert_eq!(status.source_ticket_hash, Some([0xAA; 32]));
    }

    #[test]
    fn get_status_reflects_armed_state() {
        let mut state = EnclaveState::Unarmed;

        let authorized = AuthorizedProducerState {
            pq_pubkey: vec![0xAA; 48],
            measurement: b"armed-measurement-v1".to_vec(),
            activated_at_height: 200,
            source_ticket_hash: [0xBB; 32],
        };
        let req = ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                250,
                [0xCC; 32],
                vec![[0xBB; 32]],
                &authorized,
            ),
        };

        let _ = dispatch_command_with_state(Command::ArmForProduction(req), &mut state, test_attestation_trust());

        let status_resp = match dispatch_command_with_state(Command::GetStatus(GetStatusRequest { version: 1 }), &mut state, test_attestation_trust()) {
            Response::GetStatus(r) => r,
            _ => panic!("expected GetStatus"),
        };

        assert!(status_resp.armed);
        assert_eq!(status_resp.authorized_measurement, b"armed-measurement-v1");
        assert_eq!(status_resp.authorized_pq_pubkey, vec![0xAA; 48]);
        assert_eq!(status_resp.authorized_activated_at_height, Some(200));
        assert_eq!(status_resp.proof_finalized_height, Some(250));
        assert_eq!(status_resp.source_ticket_hash, Some([0xBB; 32]));
    }

    #[test]
    fn arm_for_production_fails_with_invalid_proof() {
        let mut state = EnclaveState::Unarmed;

        let bad_req = ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: vec![1; 48],
                measurement: b"meas".to_vec(),
                activated_at_height: 100,
                source_ticket_hash: [0xAA; 32],
            },
            recent_chain_proof: {
                let authorized = AuthorizedProducerState {
                    pq_pubkey: vec![1; 48],
                    measurement: b"meas".to_vec(),
                    activated_at_height: 100,
                    source_ticket_hash: [0xAA; 32],
                };
                // Height 50 is stale; signing still uses a structurally valid proof blob.
                signed_recent_chain_proof(50, [0x11; 32], vec![[0xAA; 32]], &authorized)
            },
        };

        let resp = dispatch_command_with_state(Command::ArmForProduction(bad_req), &mut state, test_attestation_trust());

        match resp {
            Response::ArmForProduction(r) => {
                assert_eq!(r.status, "refused");
                let reason = r.reason.expect("expected refusal reason");
                assert!(
                    reason.contains("finalized_height is older"),
                    "expected stale-height refusal, got: {}",
                    reason
                );
            }
            _ => panic!("expected ArmForProduction response"),
        }

        assert!(matches!(state, EnclaveState::Unarmed));
    }

    #[test]
    fn stateful_sign_second_hardfork_while_armed_fails() {
        let pq = vec![0xDE; 48];
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state, test_attestation_trust());

        let first = sample_hardfork_ticket(pq.clone(), 10_000_100);
        let ok = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: first }),
            &mut state, test_attestation_trust());
        assert!(matches!(ok, Response::SignAuthorizationTicket(_)));

        let second = sample_hardfork_ticket(pq, 10_000_200);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: second }),
            &mut state, test_attestation_trust());
        match resp {
            Response::Error(msg) => assert!(msg.contains("only one HARD_FORK_ACTIVATION")),
            _ => panic!("expected refusal of second hard-fork sign"),
        }
    }

    #[test]
    fn validate_recent_chain_proof_rejects_zero_header_hash() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 10,
            source_ticket_hash: [0; 32],
        };

        let bad = RecentChainProof {
            finalized_height: 20,
            finalized_header_hash: [0; 32],
            recovery_history_tail: vec![],
            proof_data: build_proof_data_v1(&[]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&bad, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn validate_recent_chain_proof_rejects_stale_height() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 1000,
            source_ticket_hash: [0; 32],
        };

        let stale = RecentChainProof {
            finalized_height: 500, // older than activation
            finalized_header_hash: [0x11; 32],
            recovery_history_tail: vec![],
            proof_data: build_proof_data_v1(&[]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&stale, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn validate_recent_chain_proof_rejects_zero_in_recovery_tail() {
        let state = AuthorizedProducerState {
            pq_pubkey: vec![],
            measurement: vec![],
            activated_at_height: 10,
            source_ticket_hash: [0xAA; 32],
        };

        let bad = RecentChainProof {
            finalized_height: 50,
            finalized_header_hash: [0xBB; 32],
            recovery_history_tail: vec![[0; 32]], // zero hash in tail
            proof_data: build_proof_data_v1(&[[0; 32]]),
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };

        let err = validate_recent_chain_proof(&bad, &state, &test_attestation_trust()).unwrap_err();
        assert!(matches!(err, ProtocolError::RecentChainProofValidation(_)));
    }

    #[test]
    fn arm_request_now_carries_typed_proof() {
        // Compile-time + basic runtime check that the type change took effect
        let req = ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: vec![1; 48],
                measurement: b"m".to_vec(),
                activated_at_height: 1,
                source_ticket_hash: [0x01; 32],
            },
            recent_chain_proof: signed_recent_chain_proof(
                10,
                [0x02; 32],
                vec![],
                &AuthorizedProducerState {
                    pq_pubkey: vec![1; 48],
                    measurement: b"m".to_vec(),
                    activated_at_height: 1,
                    source_ticket_hash: [0x01; 32],
                },
            ),
        };

        assert_eq!(req.recent_chain_proof.finalized_height, 10);
    }

    // ---------------------------------------------------------------------
    // TRACK A — Sign via dispatch + framing roundtrips
    // ---------------------------------------------------------------------

    #[test]
    fn roundtrip_sign_via_framing_and_dispatch_recovery() {
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0x1111,
            context_hash: [0xAA; 32],
            activation_height: 1_000_000,
            new_measurement: b"recovery-dispatch".to_vec(),
            pq_pubkey: vec![0x11; 48],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: payload.clone() });

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut bytes).unwrap();

        let framed = encode_message(MessageType::SignAuthorizationTicket, &bytes).unwrap();
        let received = decode_message(&framed).unwrap();

        let received_cmd: Command = ciborium::de::from_reader(&received.payload[..]).unwrap();
        let resp = dispatch_command(received_cmd);

        match resp {
            Response::SignAuthorizationTicket(r) => {
                assert_eq!(r.ticket_hash, compute_canonical_ticket_hash(&payload));
                assert!(!r.signature.is_empty());
            }
            _ => panic!("expected SignAuthorizationTicket response"),
        }
    }

    fn sample_arm_request(
        pq_pubkey: Vec<u8>,
        activated_at_height: u64,
        finalized_height: u64,
    ) -> ArmForProductionRequest {
        let authorized = AuthorizedProducerState {
            pq_pubkey: pq_pubkey.clone(),
            measurement: b"prod-enclave-v1".to_vec(),
            activated_at_height,
            source_ticket_hash: [0xAA; 32],
        };
        ArmForProductionRequest {
            authorized_state: authorized.clone(),
            recent_chain_proof: signed_recent_chain_proof(
                finalized_height,
                [0x11; 32],
                vec![[0xAA; 32]],
                &authorized,
            ),
        }
    }

    fn sample_hardfork_ticket(pq_pubkey: Vec<u8>, activation_height: u64) -> AuthorizationTicketPayload {
        AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 42,
            context_hash: [0xAB; 32],
            activation_height,
            new_measurement: b"hardfork-v5".to_vec(),
            pq_pubkey,
            fork_spec_hash: Some([0xEF; 32]),
            new_header_version: Some(3),
        }
    }

    #[test]
    fn roundtrip_sign_via_framing_and_dispatch_hardfork() {
        // Stateless dispatch still rejects hard-fork (requires armed state).
        let payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 0x2222,
            context_hash: [0xBB; 32],
            activation_height: 2_000_000,
            new_measurement: b"hardfork-dispatch".to_vec(),
            pq_pubkey: vec![0x22; 48],
            fork_spec_hash: Some([0xCC; 32]),
            new_header_version: Some(3),
        };

        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: payload });

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut bytes).unwrap();

        let framed = encode_message(MessageType::SignAuthorizationTicket, &bytes).unwrap();
        let received = decode_message(&framed).unwrap();

        let received_cmd: Command = ciborium::de::from_reader(&received.payload[..]).unwrap();
        let resp = dispatch_command(received_cmd);

        match resp {
            Response::Error(msg) => {
                assert!(msg.contains("requires armed enclave state"));
            }
            _ => panic!("expected Error response for hard-fork without state"),
        }
    }

    #[test]
    fn stateful_arm_then_sign_hardfork_succeeds() {
        let pq = vec![0xDE; 48];
        let mut state = EnclaveState::Unarmed;

        let arm_resp = dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state, test_attestation_trust());
        match arm_resp {
            Response::ArmForProduction(r) => assert_eq!(r.status, "armed"),
            _ => panic!("expected arm success"),
        }

        let ticket = sample_hardfork_ticket(pq, 10_000_100);
        let sign_resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: ticket.clone() }),
            &mut state, test_attestation_trust());

        match sign_resp {
            Response::SignAuthorizationTicket(r) => {
                assert_eq!(r.ticket_hash, compute_canonical_ticket_hash(&ticket));
                assert_eq!(r.signature.len(), 64);
            }
            other => panic!("expected sign success, got {:?}", other),
        }

        let status = match dispatch_command_with_state(Command::GetStatus(GetStatusRequest { version: 1 }), &mut state, test_attestation_trust()) {
            Response::GetStatus(s) => s,
            _ => panic!("expected GetStatus"),
        };
        assert_eq!(status.pending_hard_fork_height, Some(10_000_100));
        assert_eq!(status.last_known_block, Some(10_000_050));
    }

    #[test]
    fn stateful_sign_hardfork_without_arming_fails() {
        let mut state = EnclaveState::Unarmed;
        let ticket = sample_hardfork_ticket(vec![0xCD; 48], 10_000_100);

        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state, test_attestation_trust());

        match resp {
            Response::Error(msg) => assert!(msg.contains("requires the enclave to be armed")),
            _ => panic!("expected error when signing hard-fork while unarmed"),
        }
    }

    #[test]
    fn stateful_sign_hardfork_wrong_pubkey_fails() {
        let pq = vec![0xDE; 48];
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq, 10_000_000, 10_000_050)),
            &mut state, test_attestation_trust());

        let ticket = sample_hardfork_ticket(vec![0xCD; 48], 10_000_100);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state, test_attestation_trust());

        match resp {
            Response::Error(msg) => assert!(msg.contains("pq_pubkey")),
            _ => panic!("expected pubkey mismatch error"),
        }
    }

    #[test]
    fn stateful_sign_hardfork_stale_activation_height_fails() {
        let pq = vec![0xDE; 48];
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 10_000_000, 10_000_050)),
            &mut state, test_attestation_trust());

        // activation_height not strictly above proof.finalized_height
        let ticket = sample_hardfork_ticket(pq, 10_000_050);
        let resp = dispatch_command_with_state(
            Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket }),
            &mut state, test_attestation_trust());

        match resp {
            Response::Error(msg) => assert!(msg.contains("activation_height must be strictly greater")),
            _ => panic!("expected stale activation_height error"),
        }
    }

    #[test]
    fn stateful_framing_roundtrip_hardfork_after_arm() {
        let pq = vec![0xEE; 48];
        let mut state = EnclaveState::Unarmed;

        dispatch_command_with_state(
            Command::ArmForProduction(sample_arm_request(pq.clone(), 100, 500)),
            &mut state, test_attestation_trust());

        let payload = sample_hardfork_ticket(pq, 600);
        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: payload.clone() });

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&cmd, &mut bytes).unwrap();
        let framed = encode_message(MessageType::SignAuthorizationTicket, &bytes).unwrap();
        let received = decode_message(&framed).unwrap();
        let received_cmd: Command = ciborium::de::from_reader(&received.payload[..]).unwrap();

        let resp = dispatch_command_with_state(received_cmd, &mut state, test_attestation_trust());
        match resp {
            Response::SignAuthorizationTicket(r) => {
                assert_eq!(r.ticket_hash, compute_canonical_ticket_hash(&payload));
            }
            _ => panic!("expected successful hard-fork sign after arm"),
        }
    }

    #[test]
    fn stateful_get_measurement_lists_hardfork_type() {
        let mut state = EnclaveState::Unarmed;
        let resp = dispatch_command_with_state(Command::GetMeasurement(GetMeasurementRequest { version: 1 }), &mut state, test_attestation_trust());
        match resp {
            Response::GetMeasurement(r) => {
                assert!(r.supported_ticket_types.contains(&0));
                assert!(r.supported_ticket_types.contains(&1));
            }
            _ => panic!("expected GetMeasurement"),
        }
    }

    #[test]
    fn dispatch_invalid_hardfork_ticket_yields_error_response() {
        let bad = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![],
            fork_spec_hash: None, // missing required fields
            new_header_version: None,
        };

        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: bad });
        let resp = dispatch_command(cmd);

        match resp {
            Response::Error(msg) => assert!(msg.contains("sign_authorization_ticket failed")),
            _ => panic!("expected Error response"),
        }
    }

    #[test]
    fn dispatch_recovery_ticket_with_hardfork_fields_yields_error() {
        let polluted = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 1,
            context_hash: [0; 32],
            activation_height: 10,
            new_measurement: vec![1],
            pq_pubkey: vec![2],
            fork_spec_hash: Some([3; 32]),
            new_header_version: Some(1),
        };

        let cmd = Command::SignAuthorizationTicket(SignAuthorizationTicketRequest { ticket: polluted });
        let resp = dispatch_command(cmd);

        match resp {
            Response::Error(msg) => assert!(msg.contains("sign_authorization_ticket failed")),
            _ => panic!("expected Error response"),
        }
    }

    #[test]
    fn dispatch_get_measurement_works() {
        let cmd = Command::GetMeasurement(GetMeasurementRequest { version: 1 });
        let resp = dispatch_command(cmd);

        match resp {
            Response::GetMeasurement(r) => {
                assert_eq!(r.supported_ticket_types, vec![0, 1]); // static capability; type=1 needs armed state
                assert!(r.pq_signing_ready); // cfg(test): mock signing available
                assert!(!r.measurement.is_empty());
            }
            _ => panic!("expected GetMeasurement response"),
        }
    }

    #[test]
    fn canonical_ticket_hash_is_deterministic_and_distinct() {
        let mut payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 42,
            context_hash: [0u8; 32],
            activation_height: 1_500_000,
            new_measurement: vec![1, 2, 3],
            pq_pubkey: vec![4, 5, 6],
            fork_spec_hash: Some([7u8; 32]),
            new_header_version: Some(2),
        };

        let h1 = compute_canonical_ticket_hash(&payload);

        // Changing any field must change the hash
        payload.nonce = 43;
        let h2 = compute_canonical_ticket_hash(&payload);
        assert_ne!(h1, h2);

        // Different hard-fork intent must produce different hash
        payload.fork_spec_hash = Some([8u8; 32]);
        let h3 = compute_canonical_ticket_hash(&payload);
        assert_ne!(h2, h3);
    }

    #[test]
    fn hard_fork_validation_rejects_missing_fields() {
        let bad_payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![],
            fork_spec_hash: None,           // missing!
            new_header_version: None,
        };

        assert!(validate_ticket_payload(&bad_payload).is_err());
    }

    #[test]
    fn hard_fork_validation_rejects_zero_fork_fields() {
        let zero_fork = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![1],
            fork_spec_hash: Some([0u8; 32]),
            new_header_version: Some(1),
        };
        assert!(validate_ticket_payload(&zero_fork).is_err());

        let zero_version = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![],
            pq_pubkey: vec![1],
            fork_spec_hash: Some([0xAB; 32]),
            new_header_version: Some(0),
        };
        assert!(validate_ticket_payload(&zero_version).is_err());
    }

    #[test]
    fn unknown_ticket_type_is_rejected() {
        let unknown = AuthorizationTicketPayload {
            ticket_type: 42,  // undefined type
            nonce: 1,
            context_hash: [0u8; 32],
            activation_height: 100,
            new_measurement: vec![1],
            pq_pubkey: vec![2],
            fork_spec_hash: None,
            new_header_version: None,
        };

        assert!(validate_ticket_payload(&unknown).is_err());
        assert!(prepare_ticket_for_signing(&unknown).is_err());
    }

    #[test]
    fn different_tickets_produce_different_hashes_even_with_similar_data() {
        let base = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 1,
            context_hash: [0x42; 32],
            activation_height: 10,
            new_measurement: vec![1, 2, 3],
            pq_pubkey: vec![4, 5, 6],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let h1 = compute_canonical_ticket_hash(&base);

        let mut modified = base.clone();
        modified.pq_pubkey = vec![4, 5, 7]; // меняем один байт

        let h2 = compute_canonical_ticket_hash(&modified);

        assert_ne!(h1, h2, "Changing even one byte in the payload must change the canonical hash");
    }

    #[test]
    fn hard_fork_ticket_without_required_fields_is_rejected() {
        let incomplete = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 99,
            context_hash: [0xAA; 32],
            activation_height: 5_000_000,
            new_measurement: vec![9, 9, 9],
            pq_pubkey: vec![8; 48],
            fork_spec_hash: None,           // deliberately missing
            new_header_version: None,
        };

        assert!(validate_ticket_payload(&incomplete).is_err());
        assert!(prepare_ticket_for_signing(&incomplete).is_err());
    }

    #[test]
    fn recovery_ticket_with_hard_fork_fields_is_rejected() {
        let polluted = AuthorizationTicketPayload {
            ticket_type: 0, // Recovery
            nonce: 100,
            context_hash: [0xBB; 32],
            activation_height: 5_000_001,
            new_measurement: vec![1],
            pq_pubkey: vec![2],
            fork_spec_hash: Some([3; 32]),  // should not be present
            new_header_version: Some(2),
        };

        assert!(validate_ticket_payload(&polluted).is_err());
    }

    #[test]
    fn hard_fork_and_recovery_with_same_base_data_produce_different_hashes() {
        let base = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 777,
            context_hash: [0x01; 32],
            activation_height: 3_000_000,
            new_measurement: vec![10, 20, 30],
            pq_pubkey: vec![40, 50, 60],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let recovery_hash = compute_canonical_ticket_hash(&base);

        let mut hardfork = base.clone();
        hardfork.ticket_type = 1;
        hardfork.fork_spec_hash = Some([0xAA; 32]);
        hardfork.new_header_version = Some(2);

        let hardfork_hash = compute_canonical_ticket_hash(&hardfork);

        assert_ne!(recovery_hash, hardfork_hash);
    }

    // =====================================================================
    // AUTOMATED CROSS-VERIFICATION WITH SOLIDITY (via Forge) — Track C
    //
    // These tests compare `compute_canonical_ticket_hash` against the *exact*
    // value produced by the on-chain `abi.encode(...) + keccak256` using the
    // normative Solidity script (`CanonicalTicketHash.s.sol`).
    //
    // This is the living contract between the TEE implementation and the
    // on-chain AuthorizationTickets precompile.
    //
    // The mechanism is intentionally graceful by default (so `cargo test`
    // works on machines without Foundry). In CI you can make it mandatory:
    //
    //     cargo test --features enforce-forge-crosscheck
    //
    // See Cargo.toml for the feature description.
    // =====================================================================

    /// Centralized helper for the automated Forge cross-check vectors.
    ///
    /// - If we got a Solidity hash → assert bit-for-bit equality with Rust.
    /// - If we could not run Forge (missing script or forge-std) → print a
    ///   very loud, actionable banner and either skip (default) or panic
    ///   (when `enforce-forge-crosscheck` feature is enabled).
    fn handle_forge_result(
        solidity_hash: Option<[u8; 32]>,
        rust_hash: [u8; 32],
        vector_label: &str,
    ) {
        if let Some(s) = solidity_hash {
            assert_eq!(
                rust_hash, s,
                "Rust canonical hash diverges from Solidity abi.encode + keccak256 for {}",
                vector_label
            );
            return;
        }

        // Skip / enforcement path
        let banner = format!(
            "\n\
            ============================================================\n\
            [LIVE CONTRACT] Automated canonical hash cross-check SKIPPED\n\
            Vector: {}\n\
            ============================================================\n\
            The Rust implementation of `compute_canonical_ticket_hash` must\n\
            stay bit-for-bit identical to the on-chain `abi.encode` used by\n\
            the AuthorizationTickets precompile.\n\n\
            One-time setup (run once):\n\
                cd impl/solidity && forge install foundry-rs/forge-std\n\n\
            To make this check mandatory in CI (fail on skip):\n\
                cargo test --features enforce-forge-crosscheck\n\
            ============================================================\n",
            vector_label
        );

        eprintln!("{}", banner);

        #[cfg(feature = "enforce-forge-crosscheck")]
        panic!(
            "Forge cross-check vector '{}' was skipped, but the feature 'enforce-forge-crosscheck' is enabled. \
             This is a hard failure in CI.",
            vector_label
        );
    }

    #[test]
    fn automated_cross_check_recovery_vector() {
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0x1234,
            context_hash: [0xAB; 32],
            activation_height: 10_000_000,
            new_measurement: b"recovery-v1".to_vec(),
            pq_pubkey: hex::decode("deadbeefcafebabe").unwrap(),
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "recovery ticket (original reference vector)");
    }

    #[test]
    fn automated_cross_check_hardfork_vector() {
        let payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 0x5678,
            context_hash: [0xCD; 32],
            activation_height: 12_000_000,
            new_measurement: b"hardfork-v2".to_vec(),
            pq_pubkey: hex::decode("feedface").unwrap(),
            fork_spec_hash: Some([0x11; 32]),
            new_header_version: Some(4),
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "hard-fork ticket (original reference vector)");
    }

    // ---------------------------------------------------------------------
    // NEW EDGE-CASE VECTORS (Track C)
    // ---------------------------------------------------------------------

    #[test]
    fn automated_cross_check_recovery_empty_measurement() {
        // 0-byte dynamic field — exercises length=0 + padding only.
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0xDEAD_BEEF,
            context_hash: [0x11; 32],
            activation_height: 42,
            new_measurement: vec![],
            pq_pubkey: b"pq-empty-meas".to_vec(),
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "recovery ticket — empty new_measurement (0 bytes)");
    }

    #[test]
    fn automated_cross_check_recovery_32byte_measurement() {
        // Exactly 32 bytes of data → clean single-word case.
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0x1234_5678,
            context_hash: [0x22; 32],
            activation_height: 7_000_000,
            new_measurement: [0xEE; 32].to_vec(),
            pq_pubkey: b"pq-32-byte".to_vec(),
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "recovery ticket — exactly 32-byte new_measurement");
    }

    #[test]
    fn automated_cross_check_hardfork_33byte_measurement() {
        // 33 bytes → crosses into next word, requires 31 bytes of padding.
        let payload = AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 0xCAFE,
            context_hash: [0x33; 32],
            activation_height: 1_000,
            new_measurement: vec![0xDE; 33],
            pq_pubkey: b"33-byte-boundary".to_vec(),
            fork_spec_hash: Some([0x22; 32]),
            new_header_version: Some(7),
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "hard-fork ticket — 33-byte new_measurement (padding boundary)");
    }

    #[test]
    fn automated_cross_check_recovery_large_measurement() {
        // 200 bytes → multi-word + non-trivial padding.
        let large_meas: Vec<u8> = (0u8..200).collect();
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 0xFEED_FACE_CAFE_BABE,
            context_hash: [0x44; 32],
            activation_height: 99_999_999,
            new_measurement: large_meas,
            pq_pubkey: vec![0xAB; 48],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "recovery ticket — large (200-byte) new_measurement");
    }

    #[test]
    fn automated_cross_check_recovery_zero_height_max_nonce() {
        // Extreme scalar values in the static head (activationHeight = 0, nonce = u64::MAX).
        let payload = AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: u64::MAX,
            context_hash: [0x99; 32],
            activation_height: 0,
            new_measurement: b"zero-height-max-nonce".to_vec(),
            pq_pubkey: vec![0xAB; 64],
            fork_spec_hash: None,
            new_header_version: None,
        };

        let solidity_hash = compute_hash_via_forge(&payload);
        let rust_hash = compute_canonical_ticket_hash(&payload);
        handle_forge_result(solidity_hash, rust_hash, "recovery ticket — activation_height=0 and nonce=u64::MAX");
    }

    /// Calls the Foundry script via JSON exchange to get the ground-truth hash
    /// from the *normative* Solidity implementation.
    ///
    /// This is the mechanism that makes the automated cross-checks actually
    /// compare against the on-chain encoding (the live contract).
    ///
    /// The script (`CanonicalTicketHash.s.sol`) reads `INPUT_JSON`, computes
    /// `keccak256(abi.encode(...))` using the real EVM rules (including the
    /// special casing for ticketType==0 vs 1), and writes the result to
    /// `OUTPUT_JSON`.
    ///
    /// If forge or the required files are missing, returns None (the caller
    /// then decides skip vs panic according to the policy in
    /// `handle_forge_result`).
    fn compute_hash_via_forge(
        payload: &AuthorizationTicketPayload,
    ) -> Option<[u8; 32]> {
        use std::fs;
        use std::path::PathBuf;
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};

        static FORGE_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

        // Locate repo root
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .ancestors()
            .nth(3)
            .unwrap_or(&manifest_dir);

        let solidity_dir = repo_root.join("impl/solidity");
        let script_path = solidity_dir.join("CanonicalTicketHash.s.sol");
        if !script_path.exists() {
            return None;
        }

        // Keep I/O inside impl/solidity so Forge fs_permissions (foundry.toml) allow read/write.
        let temp_dir = solidity_dir.join(".forge-crosscheck");
        fs::create_dir_all(&temp_dir).ok()?;
        let seq = FORGE_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let input_path = temp_dir.join(format!("input-{seq}.json"));
        let output_path = temp_dir.join(format!("output-{seq}.json"));

        // Build input JSON in the exact format the script expects
        let input_json = serde_json::json!({
            "ticketType": payload.ticket_type,
            "nonce": payload.nonce,
            "contextHash": format!("0x{}", hex::encode(payload.context_hash)),
            "activationHeight": payload.activation_height,
            "newMeasurement": format!("0x{}", hex::encode(&payload.new_measurement)),
            "pqPubkey": format!("0x{}", hex::encode(&payload.pq_pubkey)),
            "forkSpecHash": format!("0x{}", hex::encode(payload.fork_spec_hash.unwrap_or([0u8; 32]))),
            "newHeaderVersion": payload.new_header_version.unwrap_or(0),
        });

        fs::write(&input_path, serde_json::to_string_pretty(&input_json).ok()?).ok()?;

        // Run the script with environment variables (from the solidity dir so foundry.toml is found)
        let output = Command::new("forge")
            .current_dir(&solidity_dir)
            .env("INPUT_JSON", &input_path)
            .env("OUTPUT_JSON", &output_path)
            .args(["script", "CanonicalTicketHash.s.sol", "--silent"])
            .output()
            .ok()?;

        if !output.status.success() {
            eprintln!("Forge script failed while computing canonical hash for test vector.");
            eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            eprintln!("\nOne-time setup (run once):");
            eprintln!("    cd impl/solidity && forge install foundry-rs/forge-std --no-commit\n");
            return None;
        }

        let output_content = fs::read_to_string(&output_path).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&output_content).ok()?;
        let hash_hex = parsed["hash"].as_str()?;

        hex::decode(hash_hex.trim_start_matches("0x"))
            .ok()
            .and_then(|b| if b.len() == 32 { Some(b.try_into().unwrap()) } else { None })
    }
}
