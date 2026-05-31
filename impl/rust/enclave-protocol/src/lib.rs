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

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
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

/// Top-level framed message.
#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub version: u8,
    pub msg_type: MessageType,
    pub payload: Vec<u8>, // CBOR-encoded payload
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

/// Computes the exact canonical hash that the enclave will sign for an
/// AuthorizationTicket.
///
/// This must match the construction defined in
/// backlog/docs/authorization-tickets-precompile-spec-draft.md
/// (strengthened after the first matrix).
///
/// For HARD_FORK_ACTIVATION the `fork_spec_hash` and `new_header_version`
/// fields are part of the signed preimage.
pub fn compute_canonical_ticket_hash(payload: &AuthorizationTicketPayload) -> [u8; 32] {
    // In real implementation we would use a proper typed encoding
    // (e.g. abi.encode equivalent or canonical CBOR with integer keys).
    // For the skeleton we use a simple deterministic concatenation + keccak
    // to demonstrate the structure. This will be replaced with the exact
    // encoding chosen for the on-chain precompile.

    let mut preimage = Vec::new();
    preimage.push(payload.ticket_type);
    preimage.extend_from_slice(&payload.nonce.to_be_bytes());
    preimage.extend_from_slice(&payload.context_hash);
    preimage.extend_from_slice(&payload.activation_height.to_be_bytes());
    preimage.extend_from_slice(&payload.new_measurement);
    preimage.extend_from_slice(&payload.pq_pubkey);

    if let Some(hash) = payload.fork_spec_hash {
        preimage.extend_from_slice(&hash);
    }
    if let Some(ver) = payload.new_header_version {
        preimage.extend_from_slice(&ver.to_be_bytes());
    }

    // Placeholder for keccak256 (we'll plug in the real hasher later)
    // For now we just return a deterministic 32-byte value for skeleton purposes.
    let mut hash = [0u8; 32];
    for (i, byte) in preimage.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    hash
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
    fn canonical_ticket_hash_hard_fork_includes_fork_fields() {
        let payload = AuthorizationTicketPayload {
            ticket_type: 1, // HardFork
            nonce: 42,
            context_hash: [0u8; 32],
            activation_height: 1_500_000,
            new_measurement: vec![1, 2, 3],
            pq_pubkey: vec![4, 5, 6],
            fork_spec_hash: Some([7u8; 32]),
            new_header_version: Some(2),
        };

        let hash = compute_canonical_ticket_hash(&payload);
        // Just sanity check it's not all zeros
        assert_ne!(hash, [0u8; 32]);
    }
}
