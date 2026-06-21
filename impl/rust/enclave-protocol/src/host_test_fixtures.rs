//! Wire frames for host integration tests (requires `test-support`).

use crate::{build_signed_recent_chain_proof, reference_test_attestation_signing_key};
use crate::{
    encode_arm_for_production_request, encode_message, encode_sign_authorization_ticket_request,
    ArmForProductionRequest, AuthorizationTicketPayload, AuthorizedProducerState, MessageType,
    SignAuthorizationTicketRequest,
};

/// Pre-built `ARM_FOR_PRODUCTION` framed message for reference tests (placeholder 48-byte PQ).
pub fn sample_arm_for_production_frame() -> Vec<u8> {
    sample_arm_for_production_frame_with_pubkey(vec![0xDE; 48])
}

/// ARM frame with a specific `pq_pubkey` (use sealed signer key for ML-DSA staging tests).
pub fn sample_arm_for_production_frame_with_pubkey(pq_pubkey: Vec<u8>) -> Vec<u8> {
    let pq = pq_pubkey;
    let authorized = AuthorizedProducerState {
        pq_pubkey: pq.clone(),
        measurement: b"prod-enclave-v1".to_vec(),
        activated_at_height: 10_000_000,
        source_ticket_hash: [0xAA; 32],
    };
    let proof = build_signed_recent_chain_proof(
        10_000_050,
        [0x11; 32],
        vec![[0xAA; 32]],
        &authorized,
        &reference_test_attestation_signing_key(),
    )
    .expect("valid signed proof for test fixture");
    let req = ArmForProductionRequest {
        authorized_state: authorized,
        recent_chain_proof: proof,
    };
    let payload = encode_arm_for_production_request(&req).expect("encode arm request");
    encode_message(MessageType::ArmForProduction, &payload).expect("frame arm")
}

/// Pre-built hard-fork `SIGN_AUTHORIZATION_TICKET` framed message (reference PQ pubkey).
pub fn sample_hardfork_sign_frame() -> Vec<u8> {
    hardfork_sign_frame_at(10_000_100, 1, [0x01; 32])
}

/// Second hard-fork ticket (different activation height) for anti-equivocation tests.
pub fn sample_second_hardfork_sign_frame() -> Vec<u8> {
    hardfork_sign_frame_at(10_000_200, 2, [0x02; 32])
}

fn hardfork_sign_frame_at(activation_height: u64, nonce: u64, context_hash: [u8; 32]) -> Vec<u8> {
    let ticket = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce,
        context_hash,
        activation_height,
        new_measurement: b"hardfork-v5".to_vec(),
        pq_pubkey: vec![0xDE; 48],
        fork_spec_hash: Some([0xEF; 32]),
        new_header_version: Some(3),
    };
    let req = SignAuthorizationTicketRequest { ticket };
    let payload = encode_sign_authorization_ticket_request(&req).expect("encode sign request");
    encode_message(MessageType::SignAuthorizationTicket, &payload).expect("frame sign")
}

/// Pre-built recovery `SIGN_AUTHORIZATION_TICKET` framed message.
pub fn sample_recovery_sign_frame() -> Vec<u8> {
    let ticket = AuthorizationTicketPayload {
        ticket_type: 0,
        nonce: 7,
        context_hash: [0x11; 32],
        activation_height: 1_000_000,
        new_measurement: b"recovery-meas".to_vec(),
        pq_pubkey: vec![0xAA; 48],
        fork_spec_hash: None,
        new_header_version: None,
    };
    let req = SignAuthorizationTicketRequest { ticket };
    let payload = encode_sign_authorization_ticket_request(&req).expect("encode sign request");
    encode_message(MessageType::SignAuthorizationTicket, &payload).expect("frame sign")
}
