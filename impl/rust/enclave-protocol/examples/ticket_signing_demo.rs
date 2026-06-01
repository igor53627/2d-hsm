//! Реалистичная симуляция взаимодействия хост ↔ enclave по vsock.
//!
//! Этот пример показывает более близкий к реальности цикл:
//! - Хост создаёт `Command`
//! - Сериализует → упаковывает во фрейм
//! - "Отправляет" enclave
//! - Enclave: распаковывает фрейм → матч по MessageType → валидация + prepare hash
//! - Формирует `Response` → фреймит обратно
//!
//! Запуск: cargo run --example ticket_signing_demo

use enclave_protocol::{
    AuthorizationTicketPayload, Command, MessageType, Response,
    dispatch_command, encode_message, decode_message,
};
use ciborium::ser::into_writer;
use ciborium::de::from_reader;

fn main() {
    println!("=== Realistic Host ↔ Enclave Session Simulation ===\n");

    // === Hard-Fork тикет (успешный случай) ===
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

    simulate_signing_flow(&hardfork_payload, "Hard-Fork (valid)");

    // === Recovery тикет ===
    let recovery_payload = AuthorizationTicketPayload {
        ticket_type: 0,
        nonce: 777,
        context_hash: [0x12; 32],
        activation_height: 3_100_000,
        new_measurement: b"recovery-v3".to_vec(),
        pq_pubkey: vec![0x34; 48],
        fork_spec_hash: None,
        new_header_version: None,
    };

    simulate_signing_flow(&recovery_payload, "Recovery (valid)");

    println!("\n=== Simulation finished ===");
}

/// Симулирует полный цикл: хост → framed → enclave → dispatch → ответ
fn simulate_signing_flow(payload: &AuthorizationTicketPayload, label: &str) {
    println!("--- {} ---", label);

    // 1. Хост создаёт команду
    let command = Command::SignAuthorizationTicket(
        enclave_protocol::SignAuthorizationTicketRequest {
            ticket: payload.clone(),
        },
    );

    // 2. Сериализуем команду
    let mut cmd_bytes = Vec::new();
    into_writer(&command, &mut cmd_bytes).unwrap();

    // 3. Упаковываем во фрейм
    let framed = encode_message(MessageType::SignAuthorizationTicket, &cmd_bytes)
        .expect("encode failed");

    println!("Host → Enclave (framed, {} bytes)", framed.len());

    // 4. Enclave получает данные
    let received = decode_message(&framed).expect("decode failed");
    assert_eq!(received.msg_type, MessageType::SignAuthorizationTicket);

    // 5. Enclave десериализует команду
    let received_command: Command =
        from_reader(&received.payload[..]).expect("deserialize command failed");

    // 6. Enclave вызывает реальный диспетчер (Track A)
    let response = dispatch_command(received_command);

    // 7. Сериализуем и фреймим ответ обратно
    let mut resp_bytes = Vec::new();
    into_writer(&response, &mut resp_bytes).unwrap();

    let response_framed = encode_message(MessageType::SignAuthorizationTicket, &resp_bytes)
        .expect("encode response failed");

    println!("Enclave → Host (response framed, {} bytes)", response_framed.len());

    // 8. Печатаем полезную информацию
    match &response {
        Response::SignAuthorizationTicket(r) => {
            println!("  Ticket hash that was signed: {}", hex::encode(r.ticket_hash));
            println!("  Signature length: {}", r.signature.len());
        }
        Response::Error(e) => {
            println!("  Enclave returned error: {}", e);
        }
        _ => {}
    }

    println!();
}