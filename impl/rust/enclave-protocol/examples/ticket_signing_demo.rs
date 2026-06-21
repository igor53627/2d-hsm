//! Реалистичная симуляция взаимодействия хост ↔ enclave по vsock.
//!
//! Этот пример демонстрирует рекомендуемый flow с использованием состояния:
//! 1. Host выполняет ARM_FOR_PRODUCTION с валидным proof.
//! 2. Проверяет статус через GET_STATUS.
//! 3. Подписывает hard-fork тикет (только после arming + совпадающий pq_pubkey).
//!
//! Также показан негативный сценарий — попытка подписать hard-fork без arming.
//!
//! Запуск: cargo run --example ticket_signing_demo

use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use enclave_protocol::{
    build_signed_recent_chain_proof, decode_message, dispatch_command_with_state, encode_message,
    reference_test_attestation_signing_key, reference_test_attestation_trust,
    AuthorizationTicketPayload, AuthorizedProducerState, Command, EnclaveState, MessageType,
    Response,
};

fn main() {
    println!("=== Realistic Host ↔ Enclave Session Simulation (with state) ===\n");

    let producer_pubkey = vec![0xDE; 48];

    // =====================================================
    // Пример 1: Правильный flow — Arm → GetStatus → Sign hard-fork
    // =====================================================
    println!("=== Scenario: Proper flow (Arm first, then sign hard-fork) ===\n");

    let mut enclave_state = EnclaveState::Unarmed;

    let authorized = AuthorizedProducerState {
        pq_pubkey: producer_pubkey.clone(),
        measurement: b"prod-enclave-v1".to_vec(),
        activated_at_height: 10_000_000,
        source_ticket_hash: [0xAA; 32],
    };
    let arm_req = enclave_protocol::ArmForProductionRequest {
        authorized_state: authorized.clone(),
        recent_chain_proof: build_signed_recent_chain_proof(
            10_000_050,
            [0x11; 32],
            vec![[0xAA; 32]],
            &authorized,
            &reference_test_attestation_signing_key(),
        )
        .expect("valid signed proof for demo"),
    };

    let arm_cmd = Command::ArmForProduction(arm_req);
    let trust = reference_test_attestation_trust();
    let arm_resp = dispatch_command_with_state(arm_cmd, &mut enclave_state, trust);
    println!("Host → Enclave: ARM_FOR_PRODUCTION");
    match &arm_resp {
        Response::ArmForProduction(r) => println!("  Enclave: {}\n", r.status),
        Response::Error(e) => println!("  Error: {}\n", e),
        _ => {}
    }

    let status_cmd = Command::GetStatus(enclave_protocol::GetStatusRequest { version: 1 });
    let status_resp = dispatch_command_with_state(status_cmd, &mut enclave_state, trust);
    println!("Host → Enclave: GET_STATUS");
    if let Response::GetStatus(s) = &status_resp {
        println!("  armed: {}", s.armed);
        if s.armed {
            println!(
                "  authorized_measurement: {:?}",
                String::from_utf8_lossy(&s.authorized_measurement)
            );
            println!("  proof_finalized_height: {:?}", s.proof_finalized_height);
        }
    }
    println!();

    let hardfork_payload = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce: 42,
        context_hash: [0xAB; 32],
        activation_height: 10_500_000,
        new_measurement: b"hardfork-v5".to_vec(),
        pq_pubkey: producer_pubkey,
        fork_spec_hash: Some([0xEF; 32]),
        new_header_version: Some(3),
    };

    simulate_signing_flow(
        &hardfork_payload,
        &mut enclave_state,
        "Hard-Fork after proper arming",
    );

    if let Response::GetStatus(s) = dispatch_command_with_state(
        Command::GetStatus(enclave_protocol::GetStatusRequest { version: 1 }),
        &mut enclave_state,
        trust,
    ) {
        println!("After hard-fork sign — GET_STATUS:");
        println!(
            "  pending_hard_fork_height: {:?}",
            s.pending_hard_fork_height
        );
        println!();
    }

    // =====================================================
    // Пример 2: Негатив — hard-fork без arming
    // =====================================================
    println!("\n=== Scenario: Hard-fork signing WITHOUT prior arming (should fail) ===\n");

    let mut fresh_state = EnclaveState::Unarmed;

    let bad_hardfork = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce: 99,
        context_hash: [0xCD; 32],
        activation_height: 4_000_000,
        new_measurement: b"bad-hardfork".to_vec(),
        pq_pubkey: vec![0xEE; 48],
        fork_spec_hash: Some([0x11; 32]),
        new_header_version: Some(4),
    };

    simulate_signing_flow(
        &bad_hardfork,
        &mut fresh_state,
        "Hard-Fork without arming (expected to fail)",
    );

    // =====================================================
    // Пример 3: Негатив — armed, но activation_height не свежее proof
    // =====================================================
    println!("\n=== Scenario: Hard-fork with stale activation_height (should fail) ===\n");

    let mut stale_state = EnclaveState::Unarmed;
    let stale_authorized = AuthorizedProducerState {
        pq_pubkey: vec![0xFF; 48],
        measurement: b"v2".to_vec(),
        activated_at_height: 100,
        source_ticket_hash: [0xBB; 32],
    };
    let arm_for_stale = enclave_protocol::ArmForProductionRequest {
        authorized_state: stale_authorized.clone(),
        recent_chain_proof: build_signed_recent_chain_proof(
            200,
            [0x22; 32],
            vec![[0xBB; 32]],
            &stale_authorized,
            &reference_test_attestation_signing_key(),
        )
        .expect("valid signed proof for stale-height demo"),
    };
    dispatch_command_with_state(
        Command::ArmForProduction(arm_for_stale),
        &mut stale_state,
        reference_test_attestation_trust(),
    );

    let stale_ticket = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce: 7,
        context_hash: [0x33; 32],
        activation_height: 200,
        new_measurement: b"stale".to_vec(),
        pq_pubkey: vec![0xFF; 48],
        fork_spec_hash: Some([0x44; 32]),
        new_header_version: Some(2),
    };

    simulate_signing_flow(
        &stale_ticket,
        &mut stale_state,
        "Hard-Fork with activation_height <= proof.finalized_height",
    );

    println!("\n=== Simulation finished ===");
}

/// Симулирует отправку SignAuthorizationTicket через stateful dispatch
fn simulate_signing_flow(
    payload: &AuthorizationTicketPayload,
    state: &mut EnclaveState,
    label: &str,
) {
    println!("--- {} ---", label);

    let command =
        Command::SignAuthorizationTicket(enclave_protocol::SignAuthorizationTicketRequest {
            ticket: payload.clone(),
        });

    let mut cmd_bytes = Vec::new();
    into_writer(&command, &mut cmd_bytes).unwrap();

    let framed =
        encode_message(MessageType::SignAuthorizationTicket, &cmd_bytes).expect("encode failed");

    let received = decode_message(&framed).expect("decode failed");
    let received_command: Command = from_reader(&received.payload[..]).expect("deserialize failed");

    let response =
        dispatch_command_with_state(received_command, state, reference_test_attestation_trust());

    match &response {
        Response::SignAuthorizationTicket(r) => {
            println!("  SUCCESS: Ticket hash = {}", hex::encode(r.ticket_hash));
            println!("  Signature length: {}", r.signature.len());
        }
        Response::Error(e) => {
            println!("  REJECTED: {}", e);
        }
        _ => {}
    }

    println!();
}
