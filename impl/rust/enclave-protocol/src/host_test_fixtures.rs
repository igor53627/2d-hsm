//! Wire frames for host integration tests (requires `test-support`).

use crate::{
    encode_arm_for_production_request, encode_message, encode_sign_authorization_ticket_request,
    ArmForProductionRequest, AuthorizationTicketPayload, AuthorizedProducerState,
    MessageType, SignAuthorizationTicketRequest,
};
use crate::{build_signed_recent_chain_proof, reference_test_attestation_signing_key};

/// Pre-built `ARM_FOR_PRODUCTION` framed message for reference tests.
pub fn sample_arm_for_production_frame() -> Vec<u8> {
    let pq = vec![0xDE; 48];
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
    let payload =
        encode_sign_authorization_ticket_request(&req).expect("encode sign request");
    encode_message(MessageType::SignAuthorizationTicket, &payload).expect("frame sign")
}