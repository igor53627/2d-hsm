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

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

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
}

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
    pub supported_ticket_types: Vec<u8>,
}

// -----------------------------------------------------------------------------
// SignAuthorizationTicket (core for both recovery and hard forks)
// -----------------------------------------------------------------------------

/// Request to sign an AuthorizationTicket.
///
/// The enclave must:
/// - Verify it is currently armed as the authorized producer (for hard-fork tickets especially).
/// - Compute the exact canonical `ticket_hash` (see below).
/// - Sign it with the PQ private key.
/// - Return the signature + the hash that was signed.
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
// ArmForProduction (with mandatory freshness proof)
// -----------------------------------------------------------------------------

/// Request to arm the enclave for production under a specific authorized state.
///
/// Per review findings (Codex HIGH + Claude):
/// - `recent_chain_proof` is now **mandatory** (non-null).
/// - The enclave must verify the proof before arming.
/// - For hard-fork related operations later, the same strict rule applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmForProductionRequest {
    pub authorized_state: AuthorizedProducerState,
    pub recent_chain_proof: Vec<u8>,   // Mandatory verified freshness proof
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
    pub current_measurement: Vec<u8>,
    pub current_pq_pubkey: Vec<u8>,
    pub pending_hard_fork_height: Option<u64>,
    pub last_known_block: Option<u64>,
}

// -----------------------------------------------------------------------------
// Canonical hash computation (must be identical on enclave and precompile side)
// -----------------------------------------------------------------------------

/// Domain separation tag for all AuthorizationTicket signatures.
/// This prevents cross-protocol signature reuse.
const TICKET_DOMAIN_TAG: &[u8] = b"2D-AUTH-TICKET-v1";

/// Computes the **canonical** hash over an AuthorizationTicket that the
/// enclave will actually sign.
///
/// This implementation addresses the critical issues found in the roborev
/// matrix on commit 96d2022:
/// - Uses real Keccak256 instead of XOR placeholder.
/// - Uses length-prefixed encoding for all variable-length fields.
/// - Explicit presence byte for optional hard-fork fields.
/// - Domain separation tag.
///
/// The resulting 32-byte value is what must be signed with the PQ key.
pub fn compute_canonical_ticket_hash(payload: &AuthorizationTicketPayload) -> [u8; 32] {
    let mut hasher = Keccak256::new();

    // 1. Domain separation
    hasher.update(TICKET_DOMAIN_TAG);

    // 2. Fixed fields
    hasher.update([payload.ticket_type]);
    hasher.update(payload.nonce.to_be_bytes());
    hasher.update(payload.context_hash);
    hasher.update(payload.activation_height.to_be_bytes());

    // 3. Variable-length fields with length prefix (u32 BE)
    hasher.update((payload.new_measurement.len() as u32).to_be_bytes());
    hasher.update(&payload.new_measurement);

    hasher.update((payload.pq_pubkey.len() as u32).to_be_bytes());
    hasher.update(&payload.pq_pubkey);

    // 4. Hard-fork specific fields (with explicit presence)
    match payload.fork_spec_hash {
        Some(hash) => {
            hasher.update([1u8]); // present
            hasher.update(hash);
        }
        None => {
            hasher.update([0u8]); // absent
        }
    }

    match payload.new_header_version {
        Some(ver) => {
            hasher.update([1u8]); // present
            hasher.update(ver.to_be_bytes());
        }
        None => {
            hasher.update([0u8]); // absent
        }
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
            // HARD_FORK_ACTIVATION
            if payload.fork_spec_hash.is_none() || payload.new_header_version.is_none() {
                return Err(ProtocolError::InvalidTicket(
                    "Hard-fork tickets must include fork_spec_hash and new_header_version",
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
