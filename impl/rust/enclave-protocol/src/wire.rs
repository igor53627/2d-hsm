//! Spec-aligned CBOR encoding (integer map keys per vsock-api-wire-format-spec-draft §7).
//!
//! The logical Rust structs in `lib.rs` use field names for in-process use; vsock
//! payloads for commands documented with integer keys must use the helpers here.

use crate::{
    ArmForProductionRequest, AuthorizedProducerState, GetStatusRequest, GetStatusResponse,
    ProtocolError, RecentChainProof, PROTOCOL_VERSION,
};
use ciborium::value::Value;
use std::io::Cursor;

fn encode_value(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

fn decode_value(bytes: &[u8]) -> Result<Value, ProtocolError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(ProtocolError::from)
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
    Ok(GetStatusRequest {
        version: value_to_u64(map_get(&map, 1)?)? as u8,
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
    let _version = value_to_u64(map_get(&map, 1)?)? as u8;
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
    let _version = value_to_u64(map_get(&map, 1)?)? as u8;
    Ok(ArmForProductionRequest {
        authorized_state: decode_authorized_producer_state(map_get(&map, 2)?)?,
        recent_chain_proof: decode_recent_chain_proof(map_get(&map, 3)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GetStatusRequest;

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
}