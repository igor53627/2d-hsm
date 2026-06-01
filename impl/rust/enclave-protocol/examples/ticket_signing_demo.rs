//! Реалистичная симуляция взаимодействия хост ↔ enclave по vsock.
//!
//! Этот пример демонстрирует рекомендуемый flow с использованием состояния:
//! 1. Host выполняет ARM_FOR_PRODUCTION с валидным proof.
//! 2. Проверяет статус через GET_STATUS.
//! 3. Пытается подписать hard-fork тикет (должно пройти только после успешного arming).
//!
//! Также показан негативный сценарий — попытка подписать hard-fork без arming.
//!
//! Запуск: cargo run --example ticket_signing_demo

use enclave_protocol::{
    AuthorizationTicketPayload, Command, EnclaveState, MessageType, Response,
    dispatch_command_with_state, encode_message, decode_message,
};
use ciborium::ser::into_writer;
use ciborium::de::from_reader;

fn main() {
    println!("=== Realistic Host ↔ Enclave Session Simulation (with state) ===\n");

    let mut enclave_state = EnclaveState::Unarmed;

    // =====================================================
    // Пример 1: Правильный flow — Arm → GetStatus → Sign hard-fork
    // =====================================================
    println!("=== Scenario: Proper flow (Arm first, then sign hard-fork) ===\n");

    // 1. Host выполняет ARM_FOR_PRODUCTION с валидным proof
    let arm_req = enclave_protocol::ArmForProductionRequest {
        authorized_state: enclave_protocol::AuthorizedProducerState {
            pq_pubkey: vec![0xDE; 48],
            measurement: b"prod-enclave-v1".to_vec(),
            activated_at_height: 10_000_000,
            source_ticket_hash: [0xAA; 32],
        },
        recent_chain_proof: enclave_protocol::RecentChainProof {
            finalized_height: 10_000_050,
            finalized_header_hash: [0x11; 32],
            recovery_history_tail: vec![[0xAA; 32]],
            proof_data: vec![],
            signature_from_recent_producer: None,
        },
    };

    let arm_cmd = Command::ArmForProduction(arm_req);
    let arm_resp = dispatch_command_with_state(arm_cmd, &mut enclave_state);
    println!("Host → Enclave: ARM_FOR_PRODUCTION");
    match &arm_resp {
        Response::ArmForProduction(r) => println!("  Enclave: {}\n", r.status),
        Response::Error(e) => println!("  Error: {}\n", e),
        _ => {}
    }

    // 2. Проверяем статус
    let status_cmd = Command::GetStatus(enclave_protocol::GetStatusRequest { version: 1 });
    let status_resp = dispatch_command_with_state(status_cmd, &mut enclave_state);
    println!("Host → Enclave: GET_STATUS");
    if let Response::GetStatus(s) = &status_resp {
        println!("  armed: {}", s.armed);
        if s.armed {
            println!("  authorized_measurement: {:?}", String::from_utf8_lossy(&s.authorized_measurement));
        }
    }
    println!();

    // 3. Теперь пытаемся подписать hard-fork тикет (должно пройти)
    let hardfork_payload = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce: 42,
        context_hash: [0xAB; 32],
        activation_height: 3_000_000,
        new_measurement: b"hardfork-v5".to_vec(),
        pq_pubkey: vec![0xCD; 48],
        fork_spec_hash: Some([0xEF; 32]),
        new_header_version: Some(3),
    };

    simulate_signing_flow(&hardfork_payload, &mut enclave_state, "Hard-Fork after proper arming");

    // =====================================================
    // Пример 2: Негатив — пытаемся подписать hard-fork без arming
    // =====================================================
    println!("\n=== Scenario: Hard-fork signing WITHOUT prior arming (should fail) ===\n");

    let mut fresh_state = EnclaveState::Unarmed; // новый "enclave" без arming

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

    simulate_signing_flow(&bad_hardfork, &mut fresh_state, "Hard-Fork without arming (expected to fail)");

    println!("\n=== Simulation finished ===");
}

/// Симулирует отправку SignAuthorizationTicket через stateful dispatch
fn simulate_signing_flow(
    payload: &AuthorizationTicketPayload,
    state: &mut EnclaveState,
    label: &str,
) {
    println!("--- {} ---", label);

    let command = Command::SignAuthorizationTicket(
        enclave_protocol::SignAuthorizationTicketRequest {
            ticket: payload.clone(),
        },
    );

    let mut cmd_bytes = Vec::new();
    into_writer(&command, &mut cmd_bytes).unwrap();

    let framed = encode_message(MessageType::SignAuthorizationTicket, &cmd_bytes)
        .expect("encode failed");

    let received = decode_message(&framed).expect("decode failed");
    let received_command: Command =
        from_reader(&received.payload[..]).expect("deserialize failed");

    let response = dispatch_command_with_state(received_command, state);

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