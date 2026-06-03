//! Spec-aligned CBOR encoding (integer map keys per vsock-api-wire-format-spec-draft §8).
//!
//! The logical Rust structs in `lib.rs` use field names for in-process use; vsock
//! payloads for commands documented with integer keys must use the helpers here.

use crate::{
    ArmForProductionRequest, ArmForProductionResponse, AuthorizationTicketPayload,
    AuthorizedProducerState, GetMeasurementRequest, GetMeasurementResponse, GetStatusRequest,
    GetStatusResponse, ProtocolError, RecentChainProof, SignAuthorizationTicketRequest,
    SignAuthorizationTicketResponse, PROTOCOL_VERSION,
};

fn require_protocol_version(version: u64) -> Result<(), ProtocolError> {
    let v = u8::try_from(version).map_err(|_| ProtocolError::WireProtocol("version out of range"))?;
    if v != PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidVersion {
            got: v,
            expected: PROTOCOL_VERSION,
        });
    }
    Ok(())
}
use ciborium::value::Value;
use std::io::Cursor;

fn encode_value(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

fn decode_value(bytes: &[u8]) -> Result<Value, ProtocolError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor).map_err(ProtocolError::from)?;
    let consumed = cursor.position() as usize;
    if consumed != bytes.len() {
        return Err(ProtocolError::WireProtocol("trailing bytes after CBOR value"));
    }
    Ok(value)
}

fn map_get<'a>(map: &'a [(Value, Value)], key: u64) -> Result<&'a Value, ProtocolError> {
    map.iter()
        .find(|(k, _)| k == &Value::Integer(key.into()))
        .map(|(_, v)| v)
        .ok_or_else(|| {
            ProtocolError::RecentChainProofValidation("missing required CBOR map key")
        })
}

fn value_to_u64(v: &Value) -> Result<u64, ProtocolError> {
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| {
            ProtocolError::RecentChainProofValidation("integer field out of range")
        }),
        _ => Err(ProtocolError::RecentChainProofValidation(
            "expected unsigned integer",
        )),
    }
}

fn value_to_bool(v: &Value) -> Result<bool, ProtocolError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(ProtocolError::RecentChainProofValidation("expected bool")),
    }
}

fn value_to_bytes(v: &Value) -> Result<Vec<u8>, ProtocolError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ProtocolError::RecentChainProofValidation("expected bytes")),
    }
}

fn value_to_bytes32(v: &Value) -> Result<[u8; 32], ProtocolError> {
    let b = value_to_bytes(v)?;
    b.try_into()
        .map_err(|_| ProtocolError::RecentChainProofValidation("expected 32-byte hash"))
}

fn value_to_optional_u64(v: &Value) -> Result<Option<u64>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        other => Ok(Some(value_to_u64(other)?)),
    }
}

fn value_to_optional_bytes32(v: &Value) -> Result<Option<[u8; 32]>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        other => Ok(Some(value_to_bytes32(other)?)),
    }
}

fn encode_authorized_producer_state(state: &AuthorizedProducerState) -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Bytes(state.pq_pubkey.clone())),
        (Value::Integer(2.into()), Value::Bytes(state.measurement.clone())),
        (
            Value::Integer(3.into()),
            Value::Integer(state.activated_at_height.into()),
        ),
        (
            Value::Integer(4.into()),
            Value::Bytes(state.source_ticket_hash.to_vec()),
        ),
    ])
}

fn decode_authorized_producer_state(v: &Value) -> Result<AuthorizedProducerState, ProtocolError> {
    let Value::Map(map) = v else {
        return Err(ProtocolError::RecentChainProofValidation(
            "authorized_state must be a CBOR map",
        ));
    };
    Ok(AuthorizedProducerState {
        pq_pubkey: value_to_bytes(map_get(map, 1)?)?,
        measurement: value_to_bytes(map_get(map, 2)?)?,
        activated_at_height: value_to_u64(map_get(map, 3)?)?,
        source_ticket_hash: value_to_bytes32(map_get(map, 4)?)?,
    })
}

fn encode_recent_chain_proof(proof: &RecentChainProof) -> Value {
    let tail: Vec<Value> = proof
        .recovery_history_tail
        .iter()
        .map(|h| Value::Bytes(h.to_vec()))
        .collect();
    let sig = proof
        .signature_from_recent_producer
        .as_ref()
        .map(|s| Value::Bytes(s.clone()))
        .unwrap_or(Value::Null);
    Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Integer(proof.finalized_height.into()),
        ),
        (
            Value::Integer(2.into()),
            Value::Bytes(proof.finalized_header_hash.to_vec()),
        ),
        (Value::Integer(3.into()), Value::Array(tail)),
        (
            Value::Integer(4.into()),
            Value::Bytes(proof.proof_data.clone()),
        ),
        (Value::Integer(5.into()), sig),
    ])
}

fn decode_recent_chain_proof(v: &Value) -> Result<RecentChainProof, ProtocolError> {
    let Value::Map(map) = v else {
        return Err(ProtocolError::RecentChainProofValidation(
            "recent_chain_proof must be a CBOR map",
        ));
    };
    let tail_val = map_get(map, 3)?;
    let tail = match tail_val {
        Value::Array(items) => items
            .iter()
            .map(|item| value_to_bytes32(item))
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(ProtocolError::RecentChainProofValidation(
                "recovery_history_tail must be a CBOR array",
            ))
        }
    };
    let sig = match map_get(map, 5)? {
        Value::Null => None,
        other => Some(value_to_bytes(other)?),
    };
    Ok(RecentChainProof {
        finalized_height: value_to_u64(map_get(map, 1)?)?,
        finalized_header_hash: value_to_bytes32(map_get(map, 2)?)?,
        recovery_history_tail: tail,
        proof_data: value_to_bytes(map_get(map, 4)?)?,
        signature_from_recent_producer: sig,
    })
}

/// CBOR-encode wire error (`{ 1: error_code, 2: reason }`).
pub fn encode_wire_error(error_code: i64, reason: &str) -> Result<Vec<u8>, ProtocolError> {
    let value = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(error_code.into())),
        (Value::Integer(2.into()), Value::Text(reason.to_string())),
    ]);
    encode_value(&value)
}

/// Decode spec wire error body `{ 1: code, 2: reason }` (not a command success map).
pub fn decode_wire_error(bytes: &[u8]) -> Result<(i64, String), ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol("wire error must be a CBOR map"));
    };
    if is_success_response_map(&map) {
        return Err(ProtocolError::WireProtocol("payload is a success response, not a wire error"));
    }
    let code = value_to_u64(map_get(&map, 1)?)? as i64;
    let reason = value_to_text(map_get(&map, 2)?)?;
    Ok((code, reason))
}

/// True when `payload` is a wire error map (integer code + text reason, no success shape).
pub fn is_wire_error_payload(bytes: &[u8]) -> bool {
    decode_wire_error(bytes).is_ok()
}

fn is_success_response_map(map: &[(Value, Value)]) -> bool {
    if map_get(map, 3).is_ok() {
        return true;
    }
    if let Ok(v) = map_get(map, 1) {
        if matches!(v, Value::Text(s) if s == "armed") {
            return true;
        }
    }
    if let Ok(v) = map_get(map, 2) {
        if matches!(v, Value::Bool(_)) {
            return true;
        }
        if matches!(v, Value::Bytes(_)) {
            return true;
        }
    }
    false
}

fn value_to_u8(v: &Value) -> Result<u8, ProtocolError> {
    let n = value_to_u64(v)?;
    u8::try_from(n).map_err(|_| ProtocolError::InvalidTicket("ticket_type out of range"))
}

/// CBOR-encode `GET_MEASUREMENT` request (`{ 1: version }`).
pub fn encode_get_measurement_request(req: &GetMeasurementRequest) -> Result<Vec<u8>, ProtocolError> {
    let value = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer(req.version.into()),
    )]);
    encode_value(&value)
}

/// CBOR-decode `GET_MEASUREMENT` request.
pub fn decode_get_measurement_request(bytes: &[u8]) -> Result<GetMeasurementRequest, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol(
            "GET_MEASUREMENT request must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    Ok(GetMeasurementRequest {
        version: version as u8,
    })
}

/// CBOR-encode `GET_MEASUREMENT` response (spec keys 1–6).
pub fn encode_get_measurement_response(
    resp: &GetMeasurementResponse,
) -> Result<Vec<u8>, ProtocolError> {
    let ticket_types: Vec<Value> = resp
        .supported_ticket_types
        .iter()
        .map(|t| Value::Integer(u64::from(*t).into()))
        .collect();
    let value = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(PROTOCOL_VERSION.into())),
        (Value::Integer(2.into()), Value::Bytes(resp.measurement.clone())),
        (Value::Integer(3.into()), Value::Bytes(resp.attestation.clone())),
        (Value::Integer(4.into()), Value::Bytes(resp.pq_pubkey.clone())),
        (Value::Integer(5.into()), Value::Array(ticket_types)),
        (Value::Integer(6.into()), Value::Bool(resp.pq_signing_ready)),
    ]);
    encode_value(&value)
}

/// CBOR-decode `GET_MEASUREMENT` response.
pub fn decode_get_measurement_response(
    bytes: &[u8],
) -> Result<GetMeasurementResponse, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol(
            "GET_MEASUREMENT response must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    let supported = match map_get(&map, 5)? {
        Value::Array(items) => items
            .iter()
            .map(|v| {
                let n = value_to_u64(v)?;
                u8::try_from(n).map_err(|_| {
                    ProtocolError::WireProtocol("supported_ticket_types entry out of range")
                })
            })
            .collect::<Result<Vec<u8>, ProtocolError>>()?,
        _ => {
            return Err(ProtocolError::WireProtocol(
                "supported_ticket_types must be a CBOR array",
            ))
        }
    };
    Ok(GetMeasurementResponse {
        measurement: value_to_bytes(map_get(&map, 2)?)?,
        attestation: value_to_bytes(map_get(&map, 3)?)?,
        pq_pubkey: value_to_bytes(map_get(&map, 4)?)?,
        supported_ticket_types: supported,
        pq_signing_ready: value_to_bool(map_get(&map, 6)?)?,
    })
}

/// CBOR-encode `GET_STATUS` request (`{ 1: version }`).
pub fn encode_get_status_request(req: &GetStatusRequest) -> Result<Vec<u8>, ProtocolError> {
    let value = Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer(req.version.into()),
    )]);
    encode_value(&value)
}

/// CBOR-decode `GET_STATUS` request.
pub fn decode_get_status_request(bytes: &[u8]) -> Result<GetStatusRequest, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::RecentChainProofValidation(
            "GET_STATUS request must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    Ok(GetStatusRequest {
        version: version as u8,
    })
}

/// CBOR-encode `GET_STATUS` response (spec keys 1–9).
pub fn encode_get_status_response(resp: &GetStatusResponse) -> Result<Vec<u8>, ProtocolError> {
    let value = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(PROTOCOL_VERSION.into())),
        (Value::Integer(2.into()), Value::Bool(resp.armed)),
        (
            Value::Integer(3.into()),
            Value::Bytes(resp.authorized_measurement.clone()),
        ),
        (
            Value::Integer(4.into()),
            Value::Bytes(resp.authorized_pq_pubkey.clone()),
        ),
        (
            Value::Integer(5.into()),
            resp.authorized_activated_at_height
                .map(|h| Value::Integer(h.into()))
                .unwrap_or(Value::Null),
        ),
        (
            Value::Integer(6.into()),
            resp.proof_finalized_height
                .map(|h| Value::Integer(h.into()))
                .unwrap_or(Value::Null),
        ),
        (
            Value::Integer(7.into()),
            resp.source_ticket_hash
                .map(|h| Value::Bytes(h.to_vec()))
                .unwrap_or(Value::Null),
        ),
        (
            Value::Integer(8.into()),
            resp.pending_hard_fork_height
                .map(|h| Value::Integer(h.into()))
                .unwrap_or(Value::Null),
        ),
        (
            Value::Integer(9.into()),
            resp.last_known_block
                .map(|h| Value::Integer(h.into()))
                .unwrap_or(Value::Null),
        ),
    ]);
    encode_value(&value)
}

/// CBOR-decode `GET_STATUS` response.
pub fn decode_get_status_response(bytes: &[u8]) -> Result<GetStatusResponse, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::RecentChainProofValidation(
            "GET_STATUS response must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    Ok(GetStatusResponse {
        armed: value_to_bool(map_get(&map, 2)?)?,
        authorized_measurement: value_to_bytes(map_get(&map, 3)?)?,
        authorized_pq_pubkey: value_to_bytes(map_get(&map, 4)?)?,
        authorized_activated_at_height: value_to_optional_u64(map_get(&map, 5)?)?,
        proof_finalized_height: value_to_optional_u64(map_get(&map, 6)?)?,
        source_ticket_hash: value_to_optional_bytes32(map_get(&map, 7)?)?,
        pending_hard_fork_height: value_to_optional_u64(map_get(&map, 8)?)?,
        last_known_block: value_to_optional_u64(map_get(&map, 9)?)?,
    })
}

/// CBOR-encode `ARM_FOR_PRODUCTION` success (`{ 1: "armed" }`) or wire error on refuse.
pub fn encode_arm_for_production_response(
    resp: &ArmForProductionResponse,
) -> Result<Vec<u8>, ProtocolError> {
    if resp.status == "armed" {
        let value = Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Text("armed".to_string()),
        )]);
        return encode_value(&value);
    }
    let reason = resp
        .reason
        .as_deref()
        .unwrap_or("ARM_FOR_PRODUCTION refused");
    encode_wire_error(2, reason)
}

/// Decode `ARM_FOR_PRODUCTION` response (armed map or wire error).
pub fn decode_arm_for_production_response(
    bytes: &[u8],
) -> Result<ArmForProductionResponse, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::WireProtocol(
            "ARM_FOR_PRODUCTION response must be a CBOR map",
        ));
    };
    if let Ok(status) = map_get(&map, 1).and_then(value_to_text) {
        if status == "armed" {
            return Ok(ArmForProductionResponse {
                status: "armed".to_string(),
                reason: None,
            });
        }
    }
    let code = map_get(&map, 1).and_then(value_to_u64).unwrap_or(2);
    let reason = map_get(&map, 2)
        .and_then(value_to_text)
        .unwrap_or_else(|_| format!("arm refused (code {})", code));
    Ok(ArmForProductionResponse {
        status: "refused".to_string(),
        reason: Some(reason),
    })
}

fn value_to_text(v: &Value) -> Result<String, ProtocolError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(ProtocolError::WireProtocol("expected CBOR text")),
    }
}

/// CBOR-encode `ARM_FOR_PRODUCTION` request (spec keys 1–3).
pub fn encode_arm_for_production_request(
    req: &ArmForProductionRequest,
) -> Result<Vec<u8>, ProtocolError> {
    let value = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(PROTOCOL_VERSION.into())),
        (
            Value::Integer(2.into()),
            encode_authorized_producer_state(&req.authorized_state),
        ),
        (
            Value::Integer(3.into()),
            encode_recent_chain_proof(&req.recent_chain_proof),
        ),
    ]);
    encode_value(&value)
}

/// CBOR-decode `ARM_FOR_PRODUCTION` request.
pub fn decode_arm_for_production_request(
    bytes: &[u8],
) -> Result<ArmForProductionRequest, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::RecentChainProofValidation(
            "ARM_FOR_PRODUCTION request must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    Ok(ArmForProductionRequest {
        authorized_state: decode_authorized_producer_state(map_get(&map, 2)?)?,
        recent_chain_proof: decode_recent_chain_proof(map_get(&map, 3)?)?,
    })
}

fn value_to_optional_u32(v: &Value) -> Result<Option<u32>, ProtocolError> {
    match v {
        Value::Null => Ok(None),
        other => {
            let n = value_to_u64(other)?;
            u32::try_from(n).map_err(|_| {
                ProtocolError::RecentChainProofValidation("new_header_version out of range")
            })
            .map(Some)
        }
    }
}

fn decode_authorization_ticket_payload(v: &Value) -> Result<AuthorizationTicketPayload, ProtocolError> {
    let Value::Map(map) = v else {
        return Err(ProtocolError::RecentChainProofValidation(
            "ticket must be a CBOR map",
        ));
    };
    Ok(AuthorizationTicketPayload {
        ticket_type: value_to_u8(map_get(&map, 1)?)?,
        nonce: value_to_u64(map_get(&map, 2)?)?,
        context_hash: value_to_bytes32(map_get(&map, 3)?)?,
        activation_height: value_to_u64(map_get(&map, 4)?)?,
        new_measurement: value_to_bytes(map_get(&map, 5)?)?,
        pq_pubkey: value_to_bytes(map_get(&map, 6)?)?,
        fork_spec_hash: value_to_optional_bytes32(map_get(&map, 7)?)?,
        new_header_version: value_to_optional_u32(map_get(&map, 8)?)?,
    })
}

/// Encode SIGN_AUTHORIZATION_TICKET request (integer map keys, spec §8).
pub fn encode_sign_authorization_ticket_request(
    req: &SignAuthorizationTicketRequest,
) -> Result<Vec<u8>, ProtocolError> {
    let t = &req.ticket;
    let fork = t
        .fork_spec_hash
        .map(|h| Value::Bytes(h.to_vec()))
        .unwrap_or(Value::Null);
    let header_ver = t
        .new_header_version
        .map(|v| Value::Integer(v.into()))
        .unwrap_or(Value::Null);
    let ticket_map = vec![
        (Value::Integer(1.into()), Value::Integer(t.ticket_type.into())),
        (Value::Integer(2.into()), Value::Integer(t.nonce.into())),
        (Value::Integer(3.into()), Value::Bytes(t.context_hash.to_vec())),
        (Value::Integer(4.into()), Value::Integer(t.activation_height.into())),
        (Value::Integer(5.into()), Value::Bytes(t.new_measurement.clone())),
        (Value::Integer(6.into()), Value::Bytes(t.pq_pubkey.clone())),
        (Value::Integer(7.into()), fork),
        (Value::Integer(8.into()), header_ver),
        (Value::Integer(9.into()), Value::Null),
    ];
    let outer = vec![
        (Value::Integer(1.into()), Value::Integer(PROTOCOL_VERSION.into())),
        (Value::Integer(2.into()), Value::Map(ticket_map)),
    ];
    encode_value(&Value::Map(outer))
}

/// Decode SIGN_AUTHORIZATION_TICKET request (rejects trailing bytes and wrong version).
pub fn decode_sign_authorization_ticket_request(
    bytes: &[u8],
) -> Result<SignAuthorizationTicketRequest, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::RecentChainProofValidation(
            "SIGN_AUTHORIZATION_TICKET request must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    let ticket = decode_authorization_ticket_payload(map_get(&map, 2)?)?;
    Ok(SignAuthorizationTicketRequest { ticket })
}

/// Encode SIGN_AUTHORIZATION_TICKET success response (spec §8).
pub fn encode_sign_authorization_ticket_response(
    resp: &SignAuthorizationTicketResponse,
) -> Result<Vec<u8>, ProtocolError> {
    let map = vec![
        (Value::Integer(1.into()), Value::Integer(PROTOCOL_VERSION.into())),
        (Value::Integer(2.into()), Value::Bytes(resp.signature.clone())),
        (Value::Integer(3.into()), Value::Bytes(resp.ticket_hash.to_vec())),
    ];
    encode_value(&Value::Map(map))
}

/// Decode SIGN_AUTHORIZATION_TICKET success response.
pub fn decode_sign_authorization_ticket_response(
    bytes: &[u8],
) -> Result<SignAuthorizationTicketResponse, ProtocolError> {
    let value = decode_value(bytes)?;
    let Value::Map(map) = value else {
        return Err(ProtocolError::RecentChainProofValidation(
            "SIGN_AUTHORIZATION_TICKET response must be a CBOR map",
        ));
    };
    let version = value_to_u64(map_get(&map, 1)?)?;
    require_protocol_version(version)?;
    Ok(SignAuthorizationTicketResponse {
        signature: value_to_bytes(map_get(&map, 2)?)?,
        ticket_hash: value_to_bytes32(map_get(&map, 3)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GetMeasurementRequest, GetMeasurementResponse, GetStatusRequest};

    #[test]
    fn arm_response_wire_roundtrip() {
        let armed = ArmForProductionResponse {
            status: "armed".to_string(),
            reason: None,
        };
        let bytes = encode_arm_for_production_response(&armed).unwrap();
        assert_eq!(decode_arm_for_production_response(&bytes).unwrap().status, "armed");

        let refused = ArmForProductionResponse {
            status: "refused".to_string(),
            reason: Some("bad proof".to_string()),
        };
        let bytes = encode_arm_for_production_response(&refused).unwrap();
        let decoded = decode_arm_for_production_response(&bytes).unwrap();
        assert_eq!(decoded.status, "refused");
        assert!(decoded.reason.is_some());
    }

    #[test]
    fn get_measurement_wire_roundtrip() {
        let req = GetMeasurementRequest { version: 1 };
        let bytes = encode_get_measurement_request(&req).unwrap();
        assert_eq!(decode_get_measurement_request(&bytes).unwrap().version, 1);

        let resp = GetMeasurementResponse {
            measurement: b"meas".to_vec(),
            attestation: b"att".to_vec(),
            pq_pubkey: vec![0xDE, 0xAD],
            supported_ticket_types: vec![0, 1],
            pq_signing_ready: false,
        };
        let bytes = encode_get_measurement_response(&resp).unwrap();
        let Value::Map(map) = decode_value(&bytes).unwrap() else {
            panic!("expected map");
        };
        assert!(map.iter().all(|(k, _)| matches!(k, Value::Integer(_))));
        let decoded = decode_get_measurement_response(&bytes).unwrap();
        assert_eq!(decoded.measurement, b"meas");
        assert_eq!(decoded.supported_ticket_types, vec![0, 1]);
        assert!(!decoded.pq_signing_ready);
    }

    #[test]
    fn get_status_response_uses_integer_map_keys() {
        let resp = GetStatusResponse {
            armed: true,
            authorized_measurement: b"m".to_vec(),
            authorized_pq_pubkey: b"k".to_vec(),
            authorized_activated_at_height: Some(10),
            proof_finalized_height: Some(20),
            source_ticket_hash: Some([0xAB; 32]),
            pending_hard_fork_height: None,
            last_known_block: Some(20),
        };
        let bytes = encode_get_status_response(&resp).unwrap();
        let Value::Map(map) = decode_value(&bytes).unwrap() else {
            panic!("expected map");
        };
        assert!(map.iter().all(|(k, _)| matches!(k, Value::Integer(_))));
        let decoded = decode_get_status_response(&bytes).unwrap();
        assert!(decoded.armed);
        assert_eq!(decoded.proof_finalized_height, Some(20));
    }

    #[test]
    fn arm_request_roundtrip_structured_proof() {
        let req = ArmForProductionRequest {
            authorized_state: AuthorizedProducerState {
                pq_pubkey: vec![1, 2],
                measurement: b"meas".to_vec(),
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
        let bytes = encode_arm_for_production_request(&req).unwrap();
        let decoded = decode_arm_for_production_request(&bytes).unwrap();
        assert_eq!(decoded.authorized_state.activated_at_height, 99);
        assert_eq!(decoded.recent_chain_proof.finalized_height, 100);
    }

    #[test]
    fn get_status_request_roundtrip() {
        let req = GetStatusRequest { version: 1 };
        let bytes = encode_get_status_request(&req).unwrap();
        assert_eq!(decode_get_status_request(&bytes).unwrap().version, 1);
    }

    #[test]
    fn decode_rejects_trailing_cbor_bytes() {
        let mut bytes = encode_get_status_request(&GetStatusRequest { version: 1 }).unwrap();
        bytes.push(0xFF);
        let err = decode_get_status_request(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::WireProtocol("trailing bytes after CBOR value")
        ));
    }

    #[test]
    fn decode_rejects_wrong_protocol_version() {
        let value = Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer(99.into()),
        )]);
        let bytes = encode_value(&value).unwrap();
        let err = decode_get_status_request(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::InvalidVersion {
                got: 99,
                expected: PROTOCOL_VERSION
            }
        ));
    }

    #[test]
    fn sign_authorization_ticket_request_wire_roundtrip() {
        use crate::SignAuthorizationTicketRequest;

        let req = SignAuthorizationTicketRequest {
            ticket: AuthorizationTicketPayload {
                ticket_type: 1,
                nonce: 42,
                context_hash: [0x11; 32],
                activation_height: 9_000_000,
                new_measurement: b"meas".to_vec(),
                pq_pubkey: vec![0x22; 48],
                fork_spec_hash: Some([0x33; 32]),
                new_header_version: Some(3),
            },
        };
        let bytes = encode_sign_authorization_ticket_request(&req).unwrap();
        let decoded = decode_sign_authorization_ticket_request(&bytes).unwrap();
        assert_eq!(decoded.ticket.nonce, 42);
        assert_eq!(decoded.ticket.new_header_version, Some(3));
    }

    #[test]
    fn sign_request_rejects_ticket_type_out_of_range() {
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(256.into())),
            (Value::Integer(2.into()), Value::Integer(1.into())),
            (Value::Integer(3.into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer(4.into()), Value::Integer(1.into())),
            (Value::Integer(5.into()), Value::Bytes(b"m".to_vec())),
            (Value::Integer(6.into()), Value::Bytes(vec![0xAA; 48])),
            (Value::Integer(7.into()), Value::Null),
            (Value::Integer(8.into()), Value::Null),
        ];
        let ticket = Value::Map(map);
        let req_map = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), ticket),
        ];
        let bytes = encode_value(&Value::Map(req_map)).unwrap();
        assert!(decode_sign_authorization_ticket_request(&bytes).is_err());
    }

    #[test]
    fn sign_response_rejects_wrong_protocol_version() {
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Bytes(vec![1])),
            (Value::Integer(3.into()), Value::Bytes(vec![0u8; 32])),
        ];
        let bytes = encode_value(&Value::Map(map)).unwrap();
        assert!(decode_sign_authorization_ticket_response(&bytes).is_err());
    }

    #[test]
    fn get_status_response_rejects_wrong_version() {
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Bool(false)),
            (Value::Integer(3.into()), Value::Bytes(vec![])),
            (Value::Integer(4.into()), Value::Bytes(vec![])),
            (Value::Integer(5.into()), Value::Null),
            (Value::Integer(6.into()), Value::Null),
            (Value::Integer(7.into()), Value::Null),
            (Value::Integer(8.into()), Value::Null),
            (Value::Integer(9.into()), Value::Null),
        ];
        let bytes = encode_value(&Value::Map(map)).unwrap();
        assert!(decode_get_status_response(&bytes).is_err());
    }
}