//! Producer wire-frame golden vector generator for the 2D producer vsock client
//! cross-check (TASK-122 AC#3 / Step 3).
//!
//! Emits frozen, byte-exact vsock request/response FRAMES (4-byte length prefix
//! + protocol_version + message_type + CBOR payload) for the four producer
//! commands in `vsock-api-wire-format-spec-draft.md` §8:
//!   - GET_MEASUREMENT             (message_type = 0x01)
//!   - SIGN_AUTHORIZATION_TICKET   (message_type = 0x10)
//!   - ARM_FOR_PRODUCTION          (message_type = 0x20)
//!   - GET_STATUS                  (message_type = 0x30)
//!
//! Unlike `gen_golden_vectors.rs` (which produces raw ML-DSA-65 signature/hash
//! triples for the AC#2 NIF cross-check), this generator produces the full
//! PRODUCER PROTOCOL FRAMES a 2D vsock client must speak and parse. The 2D
//! Elixir client cross-check asserts byte-identical encode + struct-equal
//! decode against these frames — preventing a self-referential 2D-only codec
//! from diverging from the reference Rust implementation (the same anti-self-
//! certification bar used for AC#2/#4).
//!
//! Wire layout (spec §7):
//!   [u32 total_length BE][u8 protocol_version = 1][u8 message_type][CBOR payload]
//! `total_length = 2 + payload.len()`, EXCLUDING the 4-byte length prefix.
//!
//! # Run
//! ```sh
//! cargo run --example gen_producer_vectors
//! ```
//! (No crypto features required — the producer wire layer is plain CBOR via
//! ciborium, available with default features.)

use enclave_protocol::{
    encode_arm_for_production_request, encode_arm_for_production_response,
    encode_get_measurement_request, encode_get_measurement_response, encode_get_status_request,
    encode_get_status_response, encode_message, encode_sign_authorization_ticket_request,
    encode_sign_authorization_ticket_response, encode_wire_error, ArmForProductionRequest,
    ArmForProductionResponse, AuthorizationTicketPayload, AuthorizedProducerState,
    GetMeasurementRequest, GetMeasurementResponse, GetStatusRequest, GetStatusResponse,
    MessageType, RecentChainProof, SignAuthorizationTicketRequest, SignAuthorizationTicketResponse,
};
use std::fs;
use std::path::Path;

/// Deterministic 1952-byte ML-DSA-65 pubkey placeholder (NOT a real key — pins
/// the wire size; cross-check against `mldsa65_crosscheck/` for real signatures).
const PQ_PUBKEY_1952: [u8; 1952] = [0x42; 1952];

fn main() {
    let out_dir = Path::new("testvectors/producer");
    fs::create_dir_all(out_dir).unwrap();

    let mut manifest: Vec<serde_json::Value> = Vec::new();

    // ----------------------------------------------------------------------
    // GET_MEASUREMENT (0x01)
    // ----------------------------------------------------------------------
    let gm_req = GetMeasurementRequest { version: 1 };
    let gm_req_payload = encode_get_measurement_request(&gm_req).unwrap();
    let gm_req_frame = encode_message(MessageType::GetMeasurement, &gm_req_payload).unwrap();
    write_bin(out_dir, "req_get_measurement_v1.bin", &gm_req_frame);
    record(
        &mut manifest,
        "req_get_measurement_v1.bin",
        "GET_MEASUREMENT request frame ({1:1}).",
        &gm_req_frame,
    );

    // Operational response: pq_signing_ready=true, full 1952-byte ML-DSA-65 pubkey,
    // 48-byte SEV-SNP launch measurement, cert chain present.
    let gm_resp_op = GetMeasurementResponse {
        measurement: vec![0x5A; 48],
        attestation: vec![0xA5; 32],
        pq_pubkey: PQ_PUBKEY_1952.to_vec(),
        supported_ticket_types: vec![0, 1],
        pq_signing_ready: true,
        cert_chain: vec![0xC7; 64],
    };
    let gm_resp_op_payload = encode_get_measurement_response(&gm_resp_op).unwrap();
    let gm_resp_op_frame =
        encode_message(MessageType::GetMeasurement, &gm_resp_op_payload).unwrap();
    write_bin(
        out_dir,
        "resp_get_measurement_operational_v1.bin",
        &gm_resp_op_frame,
    );
    record(
        &mut manifest,
        "resp_get_measurement_operational_v1.bin",
        "GET_MEASUREMENT response — operational (pq_signing_ready=true, 1952-byte pubkey, cert_chain present).",
        &gm_resp_op_frame,
    );

    // Transport-only response: pq_signing_ready=false, empty pq_pubkey, empty cert_chain.
    let gm_resp_tr = GetMeasurementResponse {
        measurement: vec![0x5A; 48],
        attestation: vec![0xA5; 32],
        pq_pubkey: Vec::new(),
        supported_ticket_types: vec![0, 1],
        pq_signing_ready: false,
        cert_chain: Vec::new(),
    };
    let gm_resp_tr_payload = encode_get_measurement_response(&gm_resp_tr).unwrap();
    let gm_resp_tr_frame =
        encode_message(MessageType::GetMeasurement, &gm_resp_tr_payload).unwrap();
    write_bin(
        out_dir,
        "resp_get_measurement_transport_v1.bin",
        &gm_resp_tr_frame,
    );
    record(
        &mut manifest,
        "resp_get_measurement_transport_v1.bin",
        "GET_MEASUREMENT response — transport-only (pq_signing_ready=false, empty pubkey/cert_chain). Hosts MUST NOT arm or treat as producer.",
        &gm_resp_tr_frame,
    );

    // ----------------------------------------------------------------------
    // SIGN_AUTHORIZATION_TICKET (0x10)
    // ----------------------------------------------------------------------
    // Recovery (type=0) request — fork_spec_hash + new_header_version are null.
    let sat_req_rec = SignAuthorizationTicketRequest {
        ticket: AuthorizationTicketPayload {
            ticket_type: 0,
            nonce: 1,
            context_hash: [0xAB; 32],
            activation_height: 1000,
            new_measurement: vec![0x55; 48],
            pq_pubkey: PQ_PUBKEY_1952.to_vec(),
            fork_spec_hash: None,
            new_header_version: None,
        },
    };
    let sat_req_rec_payload = encode_sign_authorization_ticket_request(&sat_req_rec).unwrap();
    let sat_req_rec_frame =
        encode_message(MessageType::SignAuthorizationTicket, &sat_req_rec_payload).unwrap();
    write_bin(
        out_dir,
        "req_sign_authorization_ticket_recovery_v1.bin",
        &sat_req_rec_frame,
    );
    record(
        &mut manifest,
        "req_sign_authorization_ticket_recovery_v1.bin",
        "SIGN_AUTHORIZATION_TICKET request — PRODUCER_RECOVERY (type=0, fork fields null).",
        &sat_req_rec_frame,
    );

    // Hard fork (type=1) request — fork_spec_hash + new_header_version present.
    let sat_req_hf = SignAuthorizationTicketRequest {
        ticket: AuthorizationTicketPayload {
            ticket_type: 1,
            nonce: 42,
            context_hash: [0xCD; 32],
            activation_height: 5_000_000,
            new_measurement: vec![0x77; 48],
            pq_pubkey: PQ_PUBKEY_1952.to_vec(),
            fork_spec_hash: Some([0xEE; 32]),
            new_header_version: Some(2),
        },
    };
    let sat_req_hf_payload = encode_sign_authorization_ticket_request(&sat_req_hf).unwrap();
    let sat_req_hf_frame =
        encode_message(MessageType::SignAuthorizationTicket, &sat_req_hf_payload).unwrap();
    write_bin(
        out_dir,
        "req_sign_authorization_ticket_hardfork_v1.bin",
        &sat_req_hf_frame,
    );
    record(
        &mut manifest,
        "req_sign_authorization_ticket_hardfork_v1.bin",
        "SIGN_AUTHORIZATION_TICKET request — HARD_FORK_ACTIVATION (type=1, fork fields bound).",
        &sat_req_hf_frame,
    );

    // Success response: 3309-byte ML-DSA-65 signature + 32-byte ticket_hash.
    let sat_resp_ok = SignAuthorizationTicketResponse {
        signature: vec![0x77; 3309],
        ticket_hash: [0x99; 32],
    };
    let sat_resp_ok_payload = encode_sign_authorization_ticket_response(&sat_resp_ok).unwrap();
    let sat_resp_ok_frame =
        encode_message(MessageType::SignAuthorizationTicket, &sat_resp_ok_payload).unwrap();
    write_bin(
        out_dir,
        "resp_sign_authorization_ticket_v1.bin",
        &sat_resp_ok_frame,
    );
    record(
        &mut manifest,
        "resp_sign_authorization_ticket_v1.bin",
        "SIGN_AUTHORIZATION_TICKET success response (3309-byte signature, 32-byte ticket_hash).",
        &sat_resp_ok_frame,
    );

    // Error response (PqSigningUnavailable) — wire error CBOR under the request type byte.
    let sat_resp_err_payload =
        encode_wire_error(2, "PqSigningUnavailable: no sealed signer").unwrap();
    let sat_resp_err_frame =
        encode_message(MessageType::SignAuthorizationTicket, &sat_resp_err_payload).unwrap();
    write_bin(
        out_dir,
        "resp_sign_authorization_ticket_error_v1.bin",
        &sat_resp_err_frame,
    );
    record(
        &mut manifest,
        "resp_sign_authorization_ticket_error_v1.bin",
        "SIGN_AUTHORIZATION_TICKET wire-error response (code=2 PqSigningUnavailable — matches protocol_error_to_wire_body in lib.rs). Frame echoes 0x10; CBOR body is the {1:int,2:tstr} error map.",
        &sat_resp_err_frame,
    );

    // ----------------------------------------------------------------------
    // ARM_FOR_PRODUCTION (0x20)
    // ----------------------------------------------------------------------
    let afp_req = ArmForProductionRequest {
        authorized_state: AuthorizedProducerState {
            pq_pubkey: PQ_PUBKEY_1952.to_vec(),
            measurement: vec![0x5A; 48],
            activated_at_height: 99,
            source_ticket_hash: [0xCC; 32],
        },
        recent_chain_proof: RecentChainProof {
            finalized_height: 100,
            finalized_header_hash: [0xDD; 32],
            recovery_history_tail: vec![[0xEE; 32]],
            proof_data: vec![0x01],
            signature_from_recent_producer: Some(vec![0xAA; 64]),
        },
    };
    let afp_req_payload = encode_arm_for_production_request(&afp_req).unwrap();
    let afp_req_frame = encode_message(MessageType::ArmForProduction, &afp_req_payload).unwrap();
    write_bin(out_dir, "req_arm_for_production_v1.bin", &afp_req_frame);
    record(
        &mut manifest,
        "req_arm_for_production_v1.bin",
        "ARM_FOR_PRODUCTION request (authorized_state + RecentChainProof with Ed25519 signature).",
        &afp_req_frame,
    );

    // Armed success response: {1:"armed"}.
    let afp_resp_armed = ArmForProductionResponse {
        status: "armed".to_string(),
        reason: None,
    };
    let afp_resp_armed_payload = encode_arm_for_production_response(&afp_resp_armed).unwrap();
    let afp_resp_armed_frame =
        encode_message(MessageType::ArmForProduction, &afp_resp_armed_payload).unwrap();
    write_bin(
        out_dir,
        "resp_arm_for_production_armed_v1.bin",
        &afp_resp_armed_frame,
    );
    record(
        &mut manifest,
        "resp_arm_for_production_armed_v1.bin",
        "ARM_FOR_PRODUCTION success response ({1:\"armed\"}).",
        &afp_resp_armed_frame,
    );

    // Refused response: wire error with reason.
    let afp_resp_refused = ArmForProductionResponse {
        status: "refused".to_string(),
        reason: Some("RecentChainProof stale".to_string()),
    };
    let afp_resp_refused_payload = encode_arm_for_production_response(&afp_resp_refused).unwrap();
    let afp_resp_refused_frame =
        encode_message(MessageType::ArmForProduction, &afp_resp_refused_payload).unwrap();
    write_bin(
        out_dir,
        "resp_arm_for_production_refused_v1.bin",
        &afp_resp_refused_frame,
    );
    record(
        &mut manifest,
        "resp_arm_for_production_refused_v1.bin",
        "ARM_FOR_PRODUCTION refuse response (wire error code=2, reason text).",
        &afp_resp_refused_frame,
    );

    // ----------------------------------------------------------------------
    // GET_STATUS (0x30)
    // ----------------------------------------------------------------------
    let gs_req = GetStatusRequest { version: 1 };
    let gs_req_payload = encode_get_status_request(&gs_req).unwrap();
    let gs_req_frame = encode_message(MessageType::GetStatus, &gs_req_payload).unwrap();
    write_bin(out_dir, "req_get_status_v1.bin", &gs_req_frame);
    record(
        &mut manifest,
        "req_get_status_v1.bin",
        "GET_STATUS request frame ({1:1}).",
        &gs_req_frame,
    );

    // Armed response — full fields populated.
    let gs_resp_armed = GetStatusResponse {
        armed: true,
        authorized_measurement: vec![0x5A; 48],
        authorized_pq_pubkey: PQ_PUBKEY_1952.to_vec(),
        authorized_activated_at_height: Some(99),
        proof_finalized_height: Some(100),
        source_ticket_hash: Some([0xCC; 32]),
        pending_hard_fork_height: None,
        last_known_block: Some(100),
    };
    let gs_resp_armed_payload = encode_get_status_response(&gs_resp_armed).unwrap();
    let gs_resp_armed_frame =
        encode_message(MessageType::GetStatus, &gs_resp_armed_payload).unwrap();
    write_bin(
        out_dir,
        "resp_get_status_armed_v1.bin",
        &gs_resp_armed_frame,
    );
    record(
        &mut manifest,
        "resp_get_status_armed_v1.bin",
        "GET_STATUS response — armed session (all fields populated).",
        &gs_resp_armed_frame,
    );

    // Disarmed response — armed=false, optional fields null, empty bytes.
    let gs_resp_disarmed = GetStatusResponse {
        armed: false,
        authorized_measurement: Vec::new(),
        authorized_pq_pubkey: Vec::new(),
        authorized_activated_at_height: None,
        proof_finalized_height: None,
        source_ticket_hash: None,
        pending_hard_fork_height: None,
        last_known_block: None,
    };
    let gs_resp_disarmed_payload = encode_get_status_response(&gs_resp_disarmed).unwrap();
    let gs_resp_disarmed_frame =
        encode_message(MessageType::GetStatus, &gs_resp_disarmed_payload).unwrap();
    write_bin(
        out_dir,
        "resp_get_status_disarmed_v1.bin",
        &gs_resp_disarmed_frame,
    );
    record(
        &mut manifest,
        "resp_get_status_disarmed_v1.bin",
        "GET_STATUS response — disarmed (armed=false, optional fields null, empty bytes).",
        &gs_resp_disarmed_frame,
    );

    // ----------------------------------------------------------------------
    // Negative framing vectors (no CBOR payload decode — frame-layer only).
    // ----------------------------------------------------------------------
    // Unknown message-type byte: valid frame structure, type byte 0x99.
    let unknown_type_frame = {
        let payload = vec![0x40u8]; // a map start as opaque payload
        let total_len = 2 + payload.len();
        let mut buf = Vec::with_capacity(4 + total_len);
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());
        buf.push(1); // protocol_version
        buf.push(0x99); // unknown message type
        buf.extend_from_slice(&payload);
        buf
    };
    write_bin(
        out_dir,
        "neg_unknown_message_type_v1.bin",
        &unknown_type_frame,
    );
    record(
        &mut manifest,
        "neg_unknown_message_type_v1.bin",
        "Negative: valid frame structure with an UNKNOWN message-type byte (0x99). Frame layer MUST reject as unknown_message_type_byte; never defaults to a producer type.",
        &unknown_type_frame,
    );

    // Wrong protocol_version byte: valid frame, version byte = 99.
    let wrong_version_frame = {
        let payload = vec![0x40u8];
        let total_len = 2 + payload.len();
        let mut buf = Vec::with_capacity(4 + total_len);
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());
        buf.push(99); // wrong protocol version
        buf.push(0x01); // GetMeasurement type byte
        buf.extend_from_slice(&payload);
        buf
    };
    write_bin(
        out_dir,
        "neg_wrong_protocol_version_v1.bin",
        &wrong_version_frame,
    );
    record(
        &mut manifest,
        "neg_wrong_protocol_version_v1.bin",
        "Negative: valid frame structure with WRONG protocol_version byte (99). MUST reject as unsupported_protocol_version.",
        &wrong_version_frame,
    );

    // Frame length mismatch: total_length says 100 but body is shorter.
    let length_mismatch_frame = {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&100u32.to_be_bytes()); // claims 100-byte body
        buf.extend_from_slice(&[0x01, 0x01, 0xA0]); // version + type + empty-map payload (3 bytes)
        buf
    };
    write_bin(
        out_dir,
        "neg_frame_length_mismatch_v1.bin",
        &length_mismatch_frame,
    );
    record(
        &mut manifest,
        "neg_frame_length_mismatch_v1.bin",
        "Negative: total_length prefix (100) does not match actual body size (3). MUST reject as frame_length_mismatch / Io error.",
        &length_mismatch_frame,
    );

    // ----------------------------------------------------------------------
    // Write manifest JSON
    // ----------------------------------------------------------------------
    let manifest_obj = serde_json::json!({
        "vectors_version": "1",
        "generated_by": "examples/gen_producer_vectors.rs",
        "spec": "backlog/docs/vsock-api-wire-format-spec-draft.md §7 (framing) + §8 (schemas)",
        "wire_layout": "[u32 total_length BE][u8 protocol_version=1][u8 message_type][CBOR payload]; total_length = 2 + payload.len(), excludes the 4-byte prefix",
        "protocol_version": 1,
        "message_types": {
            "0x01": "GET_MEASUREMENT",
            "0x10": "SIGN_AUTHORIZATION_TICKET",
            "0x20": "ARM_FOR_PRODUCTION",
            "0x30": "GET_STATUS"
        },
        "cbor_library": "ciborium 0.2 (default serialization; shortest-form definite-length, insertion-order map keys)",
        "provenance": "Emitted by the reference Rust encoder (enclave-protocol::wire). 2D Elixir client must produce/consume byte-identical frames.",
        "vectors": manifest,
    });
    let manifest_pretty = serde_json::to_string_pretty(&manifest_obj).unwrap();
    fs::write(out_dir.join("manifest.json"), manifest_pretty).unwrap();

    eprintln!(
        "\nDone. Wrote {} vectors + manifest.json to {}",
        manifest_obj["vectors"].as_array().unwrap().len(),
        out_dir.display()
    );
}

fn write_bin(dir: &Path, name: &str, bytes: &[u8]) {
    fs::write(dir.join(name), bytes).unwrap();
    eprintln!("  {name}: {} bytes", bytes.len());
}

fn record(manifest: &mut Vec<serde_json::Value>, name: &str, desc: &str, bytes: &[u8]) {
    manifest.push(serde_json::json!({
        "file": name,
        "description": desc,
        "byte_count": bytes.len(),
    }));
}
