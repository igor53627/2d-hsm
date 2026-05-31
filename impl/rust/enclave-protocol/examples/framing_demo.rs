//! Simple demo of the length-prefixed CBOR framing.
//!
//! Run with: cargo run --example framing_demo

use enclave_protocol::{encode_message, decode_message, MessageType, GetMeasurementRequest};
use ciborium::ser::into_writer;

fn main() {
    let req = GetMeasurementRequest { version: 1 };

    let mut payload = Vec::new();
    into_writer(&req, &mut payload).expect("CBOR encode");

    let framed = encode_message(MessageType::GetMeasurement, &payload)
        .expect("framing failed");

    println!("Framed message ({} bytes):", framed.len());
    println!("  hex: {}", hex::encode(&framed));

    let decoded = decode_message(&framed).expect("decode failed");
    println!("\nDecoded:");
    println!("  version: {}", decoded.version);
    println!("  type: {:?}", decoded.msg_type);

    let decoded_req: GetMeasurementRequest =
        ciborium::de::from_reader(&decoded.payload[..]).unwrap();
    println!("  payload.version: {}", decoded_req.version);

    println!("\nRoundtrip successful.");
}
