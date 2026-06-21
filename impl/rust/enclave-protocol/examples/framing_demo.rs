//! Demo of the vsock protocol framing + canonical ticket preparation.
//!
//! Run with: cargo run --example framing_demo

use ciborium::ser::into_writer;
use enclave_protocol::{
    decode_message, encode_message, prepare_ticket_for_signing, AuthorizationTicketPayload,
    GetMeasurementRequest, MessageType,
};

fn main() {
    println!("=== Framing roundtrip demo ===\n");

    let req = GetMeasurementRequest { version: 1 };
    let mut payload = Vec::new();
    into_writer(&req, &mut payload).expect("CBOR encode");

    let framed = encode_message(MessageType::GetMeasurement, &payload).expect("framing failed");

    println!("Framed GET_MEASUREMENT ({} bytes)", framed.len());
    let decoded = decode_message(&framed).expect("decode failed");
    println!("  Decoded type: {:?}", decoded.msg_type);

    println!("\n=== Ticket preparation demo ===\n");

    // Recovery ticket
    let recovery = AuthorizationTicketPayload {
        ticket_type: 0,
        nonce: 123,
        context_hash: [0x11; 32],
        activation_height: 1_000_000,
        new_measurement: b"recovery-measurement-v1".to_vec(),
        pq_pubkey: vec![0xAA; 48],
        fork_spec_hash: None,
        new_header_version: None,
    };

    let recovery_hash = prepare_ticket_for_signing(&recovery).expect("valid recovery ticket");
    println!("Recovery ticket hash: {}", hex::encode(recovery_hash));

    // Hard-fork ticket (correct)
    let hardfork = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce: 456,
        context_hash: [0x22; 32],
        activation_height: 1_500_000,
        new_measurement: b"hardfork-measurement-v2".to_vec(),
        pq_pubkey: vec![0xBB; 48],
        fork_spec_hash: Some([0xCC; 32]),
        new_header_version: Some(2),
    };

    let hf_hash = prepare_ticket_for_signing(&hardfork).expect("valid hardfork ticket");
    println!("Hard-fork ticket hash:  {}", hex::encode(hf_hash));

    // Hard-fork ticket without required fields → should fail validation
    let bad_hf = AuthorizationTicketPayload {
        ticket_type: 1,
        nonce: 789,
        context_hash: [0x33; 32],
        activation_height: 1_600_000,
        new_measurement: b"bad".to_vec(),
        pq_pubkey: vec![0xDD; 48],
        fork_spec_hash: None, // missing!
        new_header_version: None,
    };

    match prepare_ticket_for_signing(&bad_hf) {
        Ok(_) => println!("ERROR: bad hard-fork ticket was accepted!"),
        Err(e) => println!("Correctly rejected bad hard-fork ticket: {}", e),
    }

    println!("\nDemo finished successfully.");
}
