//! Producer wire-frame golden-vector parity test (TASK-122 AC#3).
//!
//! Reads the frozen frames emitted by `examples/gen_producer_vectors.rs` and
//! verifies that:
//!   1. Each frame decodes via the public wire API (`decode_message` + the
//!      per-command decoder) to the documented struct values.
//!   2. Re-encoding the decoded struct produces BYTE-IDENTICAL bytes — pinning
//!      the canonical wire shape so a future encoder change is caught here
//!      before a 2D client sees a divergent frame.
//!   3. Negative frames are rejected at the appropriate layer (frame version
//!      check, message-type dispatch, or length-mismatch) with the documented
//!      error variant — never silently accepted.
//!
//! These vectors are also consumed cross-repo by the 2D Elixir producer signer
//! client cross-check (TASK-122 AC#3 Step 3); this test is the Rust-side oracle
//! that certifies the .bin files match the reference encoder.

use enclave_protocol::{
    decode_arm_for_production_request, decode_arm_for_production_response,
    decode_get_measurement_request, decode_get_measurement_response, decode_get_status_request,
    decode_get_status_response, decode_message, decode_sign_authorization_ticket_request,
    decode_sign_authorization_ticket_response, decode_sign_block_root_request,
    decode_sign_block_root_response, decode_wire_error, encode_arm_for_production_request,
    encode_arm_for_production_response, encode_get_measurement_request,
    encode_get_measurement_response, encode_get_status_request, encode_get_status_response,
    encode_sign_authorization_ticket_request, encode_sign_authorization_ticket_response,
    encode_sign_block_root_request, encode_sign_block_root_response, encode_wire_error,
    is_wire_error_payload, MessageType, ProtocolError,
};
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testvectors")
        .join("producer")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(vectors_dir().join(name)).unwrap_or_else(|e| panic!("read vector {name}: {e}"))
}

/// Decodes a happy-path frame and verifies the message_type, then returns the
/// CBOR payload bytes (for per-command decoding by the caller).
fn decode_happy(name: &str, expected_type: MessageType) -> Vec<u8> {
    let bytes = read(name);
    let framed =
        decode_message(&bytes).unwrap_or_else(|e| panic!("{name}: frame must decode: {e:?}"));
    assert_eq!(framed.version, 1, "{name}: protocol_version byte must be 1");
    assert_eq!(
        framed.msg_type, expected_type,
        "{name}: message_type byte mismatch"
    );
    framed.payload
}

/// Re-encodes a payload via `encode_message` and asserts the full frame is
/// byte-identical to the frozen .bin.
fn assert_frame_byte_identical(name: &str, msg_type: MessageType, payload: &[u8]) {
    let expected = read(name);
    let actual =
        enclave_protocol::encode_message(msg_type, payload).expect("re-encode must succeed");
    assert_eq!(
        expected, actual,
        "{name}: re-encoded frame diverges from frozen .bin (wire-canonical shape changed)"
    );
}

// =============================================================================
// GET_MEASUREMENT (0x01)
// =============================================================================

#[test]
fn req_get_measurement_roundtrips_byte_identical() {
    let payload = decode_happy("req_get_measurement_v1.bin", MessageType::GetMeasurement);
    let req = decode_get_measurement_request(&payload).unwrap();
    assert_eq!(req.version, 1);
    let re_enc = encode_get_measurement_request(&req).unwrap();
    assert_frame_byte_identical(
        "req_get_measurement_v1.bin",
        MessageType::GetMeasurement,
        &re_enc,
    );
}

#[test]
fn resp_get_measurement_operational_roundtrips_byte_identical() {
    let payload = decode_happy(
        "resp_get_measurement_operational_v1.bin",
        MessageType::GetMeasurement,
    );
    let resp = decode_get_measurement_response(&payload).unwrap();
    assert!(resp.pq_signing_ready);
    assert_eq!(resp.pq_pubkey.len(), 1952);
    assert_eq!(resp.measurement.len(), 48);
    assert_eq!(resp.supported_ticket_types, vec![0, 1]);
    assert_eq!(resp.cert_chain.len(), 64);
    let re_enc = encode_get_measurement_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_get_measurement_operational_v1.bin",
        MessageType::GetMeasurement,
        &re_enc,
    );
}

#[test]
fn resp_get_measurement_transport_roundtrips_byte_identical() {
    let payload = decode_happy(
        "resp_get_measurement_transport_v1.bin",
        MessageType::GetMeasurement,
    );
    let resp = decode_get_measurement_response(&payload).unwrap();
    assert!(!resp.pq_signing_ready);
    assert!(resp.pq_pubkey.is_empty());
    assert!(resp.cert_chain.is_empty());
    let re_enc = encode_get_measurement_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_get_measurement_transport_v1.bin",
        MessageType::GetMeasurement,
        &re_enc,
    );
}

// =============================================================================
// SIGN_AUTHORIZATION_TICKET (0x10)
// =============================================================================

#[test]
fn req_sign_authorization_ticket_recovery_roundtrips_byte_identical() {
    let payload = decode_happy(
        "req_sign_authorization_ticket_recovery_v1.bin",
        MessageType::SignAuthorizationTicket,
    );
    let req = decode_sign_authorization_ticket_request(&payload).unwrap();
    assert_eq!(req.ticket.ticket_type, 0);
    assert_eq!(req.ticket.nonce, 1);
    assert_eq!(req.ticket.activation_height, 1000);
    assert_eq!(req.ticket.pq_pubkey.len(), 1952);
    assert_eq!(req.ticket.new_measurement.len(), 48);
    assert!(req.ticket.fork_spec_hash.is_none());
    assert!(req.ticket.new_header_version.is_none());
    let re_enc = encode_sign_authorization_ticket_request(&req).unwrap();
    assert_frame_byte_identical(
        "req_sign_authorization_ticket_recovery_v1.bin",
        MessageType::SignAuthorizationTicket,
        &re_enc,
    );
}

#[test]
fn req_sign_authorization_ticket_hardfork_roundtrips_byte_identical() {
    let payload = decode_happy(
        "req_sign_authorization_ticket_hardfork_v1.bin",
        MessageType::SignAuthorizationTicket,
    );
    let req = decode_sign_authorization_ticket_request(&payload).unwrap();
    assert_eq!(req.ticket.ticket_type, 1);
    assert_eq!(req.ticket.nonce, 42);
    assert_eq!(req.ticket.activation_height, 5_000_000);
    assert_eq!(req.ticket.fork_spec_hash, Some([0xEE; 32]));
    assert_eq!(req.ticket.new_header_version, Some(2));
    let re_enc = encode_sign_authorization_ticket_request(&req).unwrap();
    assert_frame_byte_identical(
        "req_sign_authorization_ticket_hardfork_v1.bin",
        MessageType::SignAuthorizationTicket,
        &re_enc,
    );
}

#[test]
fn resp_sign_authorization_ticket_success_roundtrips_byte_identical() {
    let payload = decode_happy(
        "resp_sign_authorization_ticket_v1.bin",
        MessageType::SignAuthorizationTicket,
    );
    // Sanity: NOT a wire error.
    assert!(!is_wire_error_payload(&payload));
    let resp = decode_sign_authorization_ticket_response(&payload).unwrap();
    assert_eq!(resp.signature.len(), 3309);
    assert_eq!(resp.ticket_hash, [0x99; 32]);
    let re_enc = encode_sign_authorization_ticket_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_sign_authorization_ticket_v1.bin",
        MessageType::SignAuthorizationTicket,
        &re_enc,
    );
}

#[test]
fn resp_sign_authorization_ticket_error_decodes_as_wire_error() {
    let payload = decode_happy(
        "resp_sign_authorization_ticket_error_v1.bin",
        MessageType::SignAuthorizationTicket,
    );
    assert!(
        is_wire_error_payload(&payload),
        "must classify as wire error"
    );
    let (code, reason) = decode_wire_error(&payload).unwrap();
    assert_eq!(
        code, 2,
        "PqSigningUnavailable error code (protocol_error_to_wire_body maps it to 2)"
    );
    assert!(
        reason.contains("PqSigningUnavailable"),
        "reason text: {reason}"
    );
    // Decode via the response decoder must classify this as a refusal-shaped
    // status, not a success (the decoder falls through to wire-error parsing).
    let resp = decode_sign_authorization_ticket_response(&payload);
    assert!(
        resp.is_err(),
        "success response decoder must reject a wire-error body"
    );
    // Byte-identity: re-encoding the decoded wire error must reproduce the
    // frozen payload (roborev 10787 gap — every other response vector has
    // this assertion; the error vector now does too).
    let re_enc = encode_wire_error(code, &reason).unwrap();
    assert_eq!(
        payload, re_enc,
        "wire-error payload must round-trip byte-identical"
    );
    assert_frame_byte_identical(
        "resp_sign_authorization_ticket_error_v1.bin",
        MessageType::SignAuthorizationTicket,
        &re_enc,
    );
}

// =============================================================================
// ARM_FOR_PRODUCTION (0x20)
// =============================================================================

#[test]
fn req_arm_for_production_roundtrips_byte_identical() {
    let payload = decode_happy(
        "req_arm_for_production_v1.bin",
        MessageType::ArmForProduction,
    );
    let req = decode_arm_for_production_request(&payload).unwrap();
    assert_eq!(req.authorized_state.activated_at_height, 99);
    assert_eq!(req.authorized_state.pq_pubkey.len(), 1952);
    assert_eq!(req.authorized_state.source_ticket_hash, [0xCC; 32]);
    assert_eq!(req.recent_chain_proof.finalized_height, 100);
    assert_eq!(req.recent_chain_proof.recovery_history_tail.len(), 1);
    assert_eq!(
        req.recent_chain_proof
            .signature_from_recent_producer
            .as_ref()
            .unwrap()
            .len(),
        64
    );
    let re_enc = encode_arm_for_production_request(&req).unwrap();
    assert_frame_byte_identical(
        "req_arm_for_production_v1.bin",
        MessageType::ArmForProduction,
        &re_enc,
    );
}

#[test]
fn resp_arm_for_production_armed_roundtrips_byte_identical() {
    let payload = decode_happy(
        "resp_arm_for_production_armed_v1.bin",
        MessageType::ArmForProduction,
    );
    let resp = decode_arm_for_production_response(&payload).unwrap();
    assert_eq!(resp.status, "armed");
    assert!(resp.reason.is_none());
    let re_enc = encode_arm_for_production_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_arm_for_production_armed_v1.bin",
        MessageType::ArmForProduction,
        &re_enc,
    );
}

#[test]
fn resp_arm_for_production_refused_roundtrips_byte_identical() {
    let payload = decode_happy(
        "resp_arm_for_production_refused_v1.bin",
        MessageType::ArmForProduction,
    );
    let resp = decode_arm_for_production_response(&payload).unwrap();
    assert_eq!(resp.status, "refused");
    assert!(resp
        .reason
        .as_ref()
        .unwrap()
        .contains("RecentChainProof stale"));
    let re_enc = encode_arm_for_production_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_arm_for_production_refused_v1.bin",
        MessageType::ArmForProduction,
        &re_enc,
    );
}

// =============================================================================
// GET_STATUS (0x30)
// =============================================================================

#[test]
fn req_get_status_roundtrips_byte_identical() {
    let payload = decode_happy("req_get_status_v1.bin", MessageType::GetStatus);
    let req = decode_get_status_request(&payload).unwrap();
    assert_eq!(req.version, 1);
    let re_enc = encode_get_status_request(&req).unwrap();
    assert_frame_byte_identical("req_get_status_v1.bin", MessageType::GetStatus, &re_enc);
}

#[test]
fn resp_get_status_armed_roundtrips_byte_identical() {
    let payload = decode_happy("resp_get_status_armed_v1.bin", MessageType::GetStatus);
    let resp = decode_get_status_response(&payload).unwrap();
    assert!(resp.armed);
    assert_eq!(resp.authorized_pq_pubkey.len(), 1952);
    assert_eq!(resp.authorized_activated_at_height, Some(99));
    assert_eq!(resp.proof_finalized_height, Some(100));
    assert_eq!(resp.source_ticket_hash, Some([0xCC; 32]));
    assert!(resp.pending_hard_fork_height.is_none());
    assert_eq!(resp.last_known_block, Some(100));
    let re_enc = encode_get_status_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_get_status_armed_v1.bin",
        MessageType::GetStatus,
        &re_enc,
    );
}

#[test]
fn resp_get_status_disarmed_roundtrips_byte_identical() {
    let payload = decode_happy("resp_get_status_disarmed_v1.bin", MessageType::GetStatus);
    let resp = decode_get_status_response(&payload).unwrap();
    assert!(!resp.armed);
    assert!(resp.authorized_measurement.is_empty());
    assert!(resp.authorized_pq_pubkey.is_empty());
    assert_eq!(resp.authorized_activated_at_height, None);
    assert_eq!(resp.proof_finalized_height, None);
    assert_eq!(resp.source_ticket_hash, None);
    assert_eq!(resp.pending_hard_fork_height, None);
    assert_eq!(resp.last_known_block, None);
    let re_enc = encode_get_status_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_get_status_disarmed_v1.bin",
        MessageType::GetStatus,
        &re_enc,
    );
}

// =============================================================================
// SIGN_BLOCK_ROOT (0x50)
// =============================================================================

#[test]
fn req_sign_block_root_roundtrips_byte_identical() {
    let payload = decode_happy("req_sign_block_root_v1.bin", MessageType::SignBlockRoot);
    let req = decode_sign_block_root_request(&payload).unwrap();
    assert_eq!(req.block_hash, [0xB1; 32]);
    let re_enc = encode_sign_block_root_request(&req).unwrap();
    assert_frame_byte_identical(
        "req_sign_block_root_v1.bin",
        MessageType::SignBlockRoot,
        &re_enc,
    );
}

#[test]
fn resp_sign_block_root_roundtrips_byte_identical() {
    let payload = decode_happy("resp_sign_block_root_v1.bin", MessageType::SignBlockRoot);
    let resp = decode_sign_block_root_response(&payload).unwrap();
    assert_eq!(resp.signature.len(), 3309);
    // Domain-separated hash = keccak256("2D_BLOCK_ROOT_V1" || block_hash) — the binding the
    // 2D verifier MUST reproduce.
    assert_eq!(
        resp.signed_hash,
        enclave_protocol::compute_block_root_signing_hash(&[0xB1; 32])
    );
    let re_enc = encode_sign_block_root_response(&resp).unwrap();
    assert_frame_byte_identical(
        "resp_sign_block_root_v1.bin",
        MessageType::SignBlockRoot,
        &re_enc,
    );
}

// =============================================================================
// Negative frames
// =============================================================================

#[test]
fn neg_unknown_message_type_is_rejected_at_dispatch() {
    let bytes = read("neg_unknown_message_type_v1.bin");
    // decode_message parses the frame header; unknown type bytes yield an error
    // (fail-closed routing per TASK-7.1 AC#20 — never defaulted to a producer type).
    let err = decode_message(&bytes).unwrap_err();
    assert!(
        matches!(err, ProtocolError::UnknownMessageType(153)
            | ProtocolError::WireProtocol(_)),
        "unknown message-type byte must be rejected (not defaulted to a producer type), got {err:?}"
    );
}

#[test]
fn neg_wrong_protocol_version_is_rejected() {
    let bytes = read("neg_wrong_protocol_version_v1.bin");
    let err = decode_message(&bytes).unwrap_err();
    assert!(
        matches!(err, ProtocolError::InvalidVersion { .. }),
        "wrong protocol_version must be rejected as InvalidVersion, got {err:?}"
    );
}

#[test]
fn neg_frame_length_mismatch_is_rejected() {
    let bytes = read("neg_frame_length_mismatch_v1.bin");
    let err = decode_message(&bytes).unwrap_err();
    // Length mismatch surfaces as an Io error variant (frame_length_mismatch).
    assert!(
        matches!(err, ProtocolError::Io(_)),
        "total_length/body mismatch must be rejected, got {err:?}"
    );
}

// =============================================================================
// Manifest completeness — every .bin file is covered by this test file.
// =============================================================================

#[test]
fn manifest_vector_count_matches_emitted_files() {
    let manifest_text = std::fs::read_to_string(vectors_dir().join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
    let declared = manifest["vectors"].as_array().unwrap().len();

    // Count .bin files actually on disk (excluding manifest.json / README).
    let mut on_disk = 0usize;
    for entry in std::fs::read_dir(vectors_dir()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file()
            && entry.path().extension().and_then(|e| e.to_str()) == Some("bin")
        {
            on_disk += 1;
        }
    }
    assert_eq!(
        declared, on_disk,
        "manifest declares {declared} vectors but {on_disk} .bin files exist on disk"
    );
}
