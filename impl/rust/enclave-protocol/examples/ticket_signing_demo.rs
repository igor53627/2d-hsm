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
    AuthorizationTicketPayload, Command, FramedMessage, MessageType, Response,
    prepare_ticket_for_signing, encode_message, decode_message,
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

/// Симулирует полный цикл: хост → framed → enclave → обработка → ответ
fn simulate_signing_flow(payload: &AuthorizationTicketPayload, label: &str) {
    println!("--- {} ---", label);

    // 1. Хост создаёт команду
    let command = Command::SignAuthorizationTicket(
        enclave_protocol::SignAuthorizationTicketRequest {
            ticket: payload.clone(),
        },
    );

    // 2. Сериализуем payload команды (в реальности это будет часть Command)
    let mut payload_bytes = Vec::new();
    into_writer(&command, &mut payload_bytes).unwrap(); // упрощённо

    // 3. Упаковываем во фрейм
    let framed = encode_message(MessageType::SignAuthorizationTicket, &payload_bytes)
        .expect("encode failed");

    println!("Host → Enclave (framed, {} bytes)", framed.len());

    // 4. Enclave получает данные
    let received = decode_message(&framed).expect("decode failed");
    assert_eq!(received.msg_type, MessageType::SignAuthorizationTicket);

    // 5. Enclave десериализует команду
    let received_command: enclave_protocol::Command =
        from_reader(&received.payload[..]).expect("deserialize command failed");

    let received_ticket = match received_command {
        enclave_protocol::Command::SignAuthorizationTicket(req) => req,
        _ => panic!("Unexpected command type"),
    };

    // 6. Enclave выполняет валидацию + подготовку хэша
    match prepare_ticket_for_signing(&received_ticket.ticket) {
        Ok(ticket_hash) => {
            // 7. "Подписываем" (в скелете просто возвращаем хэш)
            let response = Response::SignAuthorizationTicket(
                enclave_protocol::SignAuthorizationTicketResponse {
                    signature: vec![0xEE; 64], // фейковая подпись
                    ticket_hash,
                },
            );

            // 8. Сериализуем и фреймим ответ обратно
            let mut resp_bytes = Vec::new();
            into_writer(&response, &mut resp_bytes).unwrap();

            let response_framed = encode_message(MessageType::SignAuthorizationTicket, &resp_bytes)
                .expect("encode response failed");

            println!("Enclave → Host (response framed, {} bytes)", response_framed.len());
            println!("  Ticket hash that would be signed: {}", hex::encode(ticket_hash));
        }
        Err(e) => {
            println!("Enclave rejected ticket: {}", e);
        }
    }

    println!();
}