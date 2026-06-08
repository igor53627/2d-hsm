//! Agent Gateway `0x40` dispatch router (TASK-7.6.3).
//!
//! Decodes the inner Agent Gateway envelope (protocol spec §10.2), applies the fail-closed gates in
//! order — profile (role isolation), `agent_version`, `command_domain`, opcode allow-list — then
//! classifies each opcode by privilege and routes it:
//!
//! - **Low-privilege reads** `PUBLIC_IDENTITY(2)` / `PROVE_IDENTITY(3)` (no capability) are handled
//!   here end-to-end against the unsealed keystore.
//! - **Privileged** opcodes `{GENERATE_KEYS(1), CONFIGURE_TREASURY(6), EXPORT_BACKUP(7),
//!   RESTORE_BACKUP(8)}` route through [`verify_capability`] — a **fail-closed seam**. The full
//!   Ed25519 capability verification + contiguous-counter advance + atomic seal land in a later
//!   slice (TASK-7.6.x / 7.2 / 7.4); until then the seam **rejects** (`AGENT_CAPABILITY_REJECTED`),
//!   so privileged opcodes are safely inert rather than open.
//! - **Runtime signing** `{SIGN_TRANSFER(4), SIGN_FAUCET_DISPENSE(5)}` is TASK-7.6.4; not in this
//!   slice → `AGENT_NOT_CONFIGURED`.
//!
//! All failures map to the §10.9 agent error band `0x40..=0x46` with the anti-oracle collapsing
//! rules (key-not-found and wrong-purpose both → `0x42`; every capability failure → `0x43`).
//!
//! Built only under the `agent-gateway` feature.

use crate::agent_identity::{
    public_identity_from_entry, sign_identity_proof, IdentityProof, PublicIdentity,
    AGENT_GATEWAY_VERSION,
};
use crate::agent_keystore::KeystoreBody;
use crate::secp256k1::Keypair;
use ciborium::value::Value;

/// Fixed command-domain string bound in the envelope (spec §10.2, key 3).
pub const COMMAND_DOMAIN: &str = "2d-hsm/agent-gateway/v1";

/// Agent error band (spec §10.9). Variants collapse distinct internal failures to a single
/// host-observable code (anti-oracle); the wire code is [`AgentError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentError {
    /// 0x40 — bad CBOR / unknown version / opcode / field / env-id format (syntax only).
    Malformed,
    /// 0x41 — command disabled in this role/profile.
    WrongProfile,
    /// 0x42 — collapses key-not-found AND wrong-purpose (never reveal which).
    KeyPurposeMismatch,
    /// 0x43 — collapses every capability failure (bad sig / wrong authority / scope / counter /
    /// payload-binding / retired authority / duplicate-treasury).
    CapabilityRejected,
    /// 0x44 — per-dispense/gas/budget/breaker exceeded or checked-overflow.
    CapExceeded,
    /// 0x45 — privileged/runtime op invoked before the supporting state is configured/implemented.
    NotConfigured,
    /// 0x46 — atomic sealed-commit failed; no signature/refs emitted.
    SealFailed,
}

impl AgentError {
    /// The §10.9 wire error code.
    pub fn code(self) -> u8 {
        match self {
            AgentError::Malformed => 0x40,
            AgentError::WrongProfile => 0x41,
            AgentError::KeyPurposeMismatch => 0x42,
            AgentError::CapabilityRejected => 0x43,
            AgentError::CapExceeded => 0x44,
            AgentError::NotConfigured => 0x45,
            AgentError::SealFailed => 0x46,
        }
    }
}

/// Agent Gateway opcodes (spec §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOpcode {
    GenerateKeys = 1,
    PublicIdentity = 2,
    ProveIdentity = 3,
    SignTransfer = 4,
    SignFaucetDispense = 5,
    ConfigureTreasury = 6,
    ExportBackup = 7,
    RestoreBackup = 8,
}

impl AgentOpcode {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::GenerateKeys,
            2 => Self::PublicIdentity,
            3 => Self::ProveIdentity,
            4 => Self::SignTransfer,
            5 => Self::SignFaucetDispense,
            6 => Self::ConfigureTreasury,
            7 => Self::ExportBackup,
            8 => Self::RestoreBackup,
            _ => return None,
        })
    }

    /// Privileged opcodes require an Ed25519 admin/recovery capability at envelope key 5.
    fn is_privileged(self) -> bool {
        matches!(
            self,
            Self::GenerateKeys | Self::ConfigureTreasury | Self::ExportBackup | Self::RestoreBackup
        )
    }
}

/// Which role this signer instance runs as (production role isolation, §10.2). A `Producer` signer
/// rejects every agent opcode; an `AgentGateway` signer rejects producer/AuthorizationTicket frames
/// (the latter is enforced at the frame layer, not here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Producer,
    AgentGateway,
}

/// Structured result of a dispatched agent command (CBOR encoding lives in the wire layer).
pub enum AgentResponse {
    PublicIdentity(PublicIdentity),
    /// A signed identity proof plus the `request_id` it answers.
    ProveIdentity(IdentityProof),
}

/// The decoded Agent Gateway envelope (§10.2). Capability (key 5) is captured only as *presence*
/// here; its verification is the [`verify_capability`] seam.
struct AgentEnvelope {
    agent_version: u8,
    opcode: u8,
    command_domain: String,
    #[allow(dead_code)] // bound into capability/audit by later slices; carried through now
    request_id: Vec<u8>,
    has_capability: bool,
    key_ref: Option<[u8; 32]>,
    payload: Option<Value>,
}

/// Look up an integer-keyed entry in a CBOR map.
fn map_get(map: &[(Value, Value)], key: u64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if u64::try_from(*i).ok() == Some(key)))
        .map(|(_, v)| v)
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

fn as_bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn as_bytes32(v: &Value) -> Option<[u8; 32]> {
    as_bytes(v).and_then(|b| b.try_into().ok())
}

/// Decode the inner Agent Gateway envelope. Any shape error → `Malformed` (0x40, syntax only).
fn decode_envelope(payload: &[u8]) -> Result<AgentEnvelope, AgentError> {
    let mut cursor = std::io::Cursor::new(payload);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| AgentError::Malformed)?;
    if cursor.position() != payload.len() as u64 {
        return Err(AgentError::Malformed); // trailing bytes
    }
    let Value::Map(map) = value else {
        return Err(AgentError::Malformed);
    };
    let agent_version = map_get(&map, 1)
        .and_then(as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(AgentError::Malformed)?;
    let opcode = map_get(&map, 2)
        .and_then(as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(AgentError::Malformed)?;
    let command_domain = match map_get(&map, 3) {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(AgentError::Malformed),
    };
    let request_id = map_get(&map, 4).and_then(as_bytes).map(|b| b.to_vec()).ok_or(AgentError::Malformed)?;
    let has_capability = map_get(&map, 5).is_some();
    // key_ref (envelope key 6) is required to be 32 bytes when present.
    let key_ref = match map_get(&map, 6) {
        None => None,
        Some(v) => Some(as_bytes32(v).ok_or(AgentError::Malformed)?),
    };
    let payload = map_get(&map, 7).cloned();
    Ok(AgentEnvelope {
        agent_version,
        opcode,
        command_domain,
        request_id,
        has_capability,
        key_ref,
        payload,
    })
}

/// Fail-closed capability seam for privileged opcodes. The full Ed25519 verification over capability
/// keys 1–12 against the sealed `admin_authority_pk`/`recovery_authority_pk`, the contiguous-counter
/// advance, and the payload-binding check land in a later slice (TASK-7.6.x; counter/seal are 7.2
/// territory). Until then this **rejects** every privileged request, collapsing to
/// `AGENT_CAPABILITY_REJECTED` (0x43) — privileged opcodes are inert, never open.
fn verify_capability(_envelope: &AgentEnvelope, _keystore: &KeystoreBody) -> Result<(), AgentError> {
    Err(AgentError::CapabilityRejected)
}

/// Dispatch one Agent Gateway request (`payload` = the inner envelope CBOR, frame body of a `0x40`
/// message) against the unsealed `keystore`. `profile` is this instance's role.
///
/// Read opcodes are served here; privileged opcodes route through the fail-closed capability seam;
/// runtime-signing opcodes are deferred (TASK-7.6.4). Errors carry the §10.9 collapsed code.
pub fn dispatch_agent(
    profile: Profile,
    payload: &[u8],
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    // Role/profile gate (0x41) — a producer signer rejects the whole 0x40 family before anything.
    if profile != Profile::AgentGateway {
        return Err(AgentError::WrongProfile);
    }
    let env = decode_envelope(payload)?;
    // Version + domain + opcode allow-list (0x40).
    if env.agent_version != AGENT_GATEWAY_VERSION || env.command_domain != COMMAND_DOMAIN {
        return Err(AgentError::Malformed);
    }
    let opcode = AgentOpcode::from_u8(env.opcode).ok_or(AgentError::Malformed)?;

    // Privilege routing: privileged opcodes MUST carry a capability and go through the seam;
    // read/runtime opcodes MUST NOT carry one.
    if opcode.is_privileged() {
        if !env.has_capability {
            return Err(AgentError::CapabilityRejected); // missing cap collapses to 0x43
        }
        verify_capability(&env, keystore)?; // fail-closed until the real verifier lands
        // Once verify_capability returns Ok (later slice), GENERATE_KEYS/CONFIGURE_TREASURY/...
        // execute here. For now the seam never returns Ok, so this is unreachable.
        return Err(AgentError::NotConfigured);
    }
    if env.has_capability {
        // A read/runtime opcode carrying a capability is malformed (cap only on privileged ops).
        return Err(AgentError::Malformed);
    }

    match opcode {
        AgentOpcode::PublicIdentity => handle_public_identity(&env, keystore),
        AgentOpcode::ProveIdentity => handle_prove_identity(&env, keystore),
        // Runtime signing (4/5) lands in TASK-7.6.4.
        AgentOpcode::SignTransfer | AgentOpcode::SignFaucetDispense => {
            Err(AgentError::NotConfigured)
        }
        // Privileged opcodes handled above; unreachable here.
        _ => Err(AgentError::Malformed),
    }
}

/// PUBLIC_IDENTITY(2): look up the key by `key_ref` and return its unified-account identity.
fn handle_public_identity(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    let key_ref = env.key_ref.ok_or(AgentError::Malformed)?;
    // not-found collapses with wrong-purpose to 0x42 (anti-oracle).
    let entry =
        crate::agent_identity::find_entry(keystore, &key_ref).ok_or(AgentError::KeyPurposeMismatch)?;
    let identity = public_identity_from_entry(entry).map_err(|_| AgentError::KeyPurposeMismatch)?;
    Ok(AgentResponse::PublicIdentity(identity))
}

/// PROVE_IDENTITY(3): sign the EIP-191 identity proof for `key_ref` over the verifier-supplied
/// nonce, binding the sealed chain_id/environment_identifier.
fn handle_prove_identity(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    let key_ref = env.key_ref.ok_or(AgentError::Malformed)?;
    // payload (envelope key 7) = { 1: verifier_nonce(32B) }.
    let verifier_nonce = match &env.payload {
        Some(Value::Map(m)) => map_get(m, 1).and_then(as_bytes32).ok_or(AgentError::Malformed)?,
        _ => return Err(AgentError::Malformed),
    };
    let entry =
        crate::agent_identity::find_entry(keystore, &key_ref).ok_or(AgentError::KeyPurposeMismatch)?;
    let secret: [u8; 32] = entry
        .secret_scalar
        .as_slice()
        .try_into()
        .map_err(|_| AgentError::KeyPurposeMismatch)?;
    let keypair = Keypair::from_secret_bytes(&secret).map_err(|_| AgentError::KeyPurposeMismatch)?;
    let proof = sign_identity_proof(
        &keypair,
        keystore.config.twod_chain_id,
        &keystore.config.environment_identifier,
        &key_ref,
        &verifier_nonce,
    )
    .map_err(|_| AgentError::SealFailed)?;
    Ok(AgentResponse::ProveIdentity(proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keygen::generate_keys;
    use crate::agent_keystore::{
        AuditRing, CreationMetadata, FaucetState, KeyPurpose, KeystoreConfig,
    };

    fn base_body() -> KeystoreBody {
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "testnet".to_string(),
                admin_authority_pk: [0xa1; 32],
                recovery_authority_pk: [0xa2; 32],
                backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
                monotonic_treasury_config_version: 1,
                authority_epoch: 0,
                anchor_root: [0xa3; 32],
            },
            entries: vec![],
            counters: vec![],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 21000,
                max_effective_gas_fee_rate: 100,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
            },
            audit: AuditRing { records: vec![], capacity: 64, last_exported_seq: 0, next_seq: 1 },
            freshness_epoch: 1,
        }
    }

    /// A body with one transfer key; returns (body, key_ref).
    fn body_with_key() -> (KeystoreBody, [u8; 32]) {
        let mut body = base_body();
        let creation = CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 };
        let gen = generate_keys(&mut body, KeyPurpose::AgentTransferK1, 1, creation).unwrap();
        let key_ref = gen[0].key_ref;
        (body, key_ref)
    }

    fn enc(value: Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        buf
    }

    fn envelope(opcode: u8, extra: Vec<(Value, Value)>) -> Vec<u8> {
        let mut m = vec![
            (Value::Integer(1.into()), Value::Integer((AGENT_GATEWAY_VERSION as u64).into())),
            (Value::Integer(2.into()), Value::Integer((opcode as u64).into())),
            (Value::Integer(3.into()), Value::Text(COMMAND_DOMAIN.to_string())),
            (Value::Integer(4.into()), Value::Bytes(vec![0x11; 16])), // request_id
        ];
        m.extend(extra);
        enc(Value::Map(m))
    }

    #[test]
    fn producer_profile_rejects_all_agent_opcodes() {
        let (body, key_ref) = body_with_key();
        let payload = envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))]);
        assert_eq!(
            dispatch_agent(Profile::Producer, &payload, &body).err(),
            Some(AgentError::WrongProfile)
        );
    }

    #[test]
    fn public_identity_returns_unified_identity() {
        let (body, key_ref) = body_with_key();
        let payload = envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))]);
        let resp = dispatch_agent(Profile::AgentGateway, &payload, &body).unwrap();
        match resp {
            AgentResponse::PublicIdentity(id) => {
                assert_eq!(id.key_ref, key_ref);
                assert_eq!(id.key_purpose, KeyPurpose::AgentTransferK1);
                assert_eq!(id.pubkey_uncompressed[0], 0x04);
                assert!(id.tron_address.starts_with('T'));
            }
            _ => panic!("expected PublicIdentity"),
        }
    }

    #[test]
    fn public_identity_unknown_key_ref_collapses_to_purpose_mismatch() {
        let (body, _) = body_with_key();
        let payload = envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(vec![0xff; 32]))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::KeyPurposeMismatch)
        );
    }

    #[test]
    fn prove_identity_signs_and_recovers() {
        let (body, key_ref) = body_with_key();
        let nonce = [0xab; 32];
        let payload = envelope(
            3,
            vec![
                (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                (
                    Value::Integer(7.into()),
                    Value::Map(vec![(Value::Integer(1.into()), Value::Bytes(nonce.to_vec()))]),
                ),
            ],
        );
        let resp = dispatch_agent(Profile::AgentGateway, &payload, &body).unwrap();
        match resp {
            AgentResponse::ProveIdentity(proof) => {
                let recovered = crate::secp256k1::recover_pubkey_uncompressed(
                    &proof.signing_hash,
                    &proof.signature,
                )
                .unwrap();
                assert_eq!(recovered, proof.pubkey_uncompressed, "recovered == bound pubkey");
                // bound address must equal the stored key's address.
                let entry = crate::agent_identity::find_entry(&body, &key_ref).unwrap();
                let id = public_identity_from_entry(entry).unwrap();
                assert_eq!(proof.address, id.eth_address);
            }
            _ => panic!("expected ProveIdentity"),
        }
    }

    #[test]
    fn privileged_generate_keys_fails_closed_with_capability() {
        let (body, _) = body_with_key();
        // GENERATE_KEYS(1) WITH a capability present still rejects (verifier is a fail-closed stub).
        let payload = envelope(1, vec![(Value::Integer(5.into()), Value::Map(vec![]))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn privileged_without_capability_rejected() {
        let (body, _) = body_with_key();
        let payload = envelope(1, vec![]); // no capability key 5
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn read_opcode_with_capability_is_malformed() {
        let (body, key_ref) = body_with_key();
        let payload = envelope(
            2,
            vec![
                (Value::Integer(5.into()), Value::Map(vec![])), // cap on a read op
                (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::Malformed)
        );
    }

    #[test]
    fn unknown_opcode_and_version_and_domain_are_malformed() {
        let (body, _) = body_with_key();
        // unknown opcode 9
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &envelope(9, vec![]), &body).err(),
            Some(AgentError::Malformed)
        );
        // wrong version
        let bad_ver = enc(Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Text(COMMAND_DOMAIN.to_string())),
            (Value::Integer(4.into()), Value::Bytes(vec![0x11; 16])),
        ]));
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &bad_ver, &body).err(),
            Some(AgentError::Malformed)
        );
        // wrong domain
        let bad_dom = enc(Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer((AGENT_GATEWAY_VERSION as u64).into())),
            (Value::Integer(2.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Text("wrong/domain".to_string())),
            (Value::Integer(4.into()), Value::Bytes(vec![0x11; 16])),
        ]));
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &bad_dom, &body).err(),
            Some(AgentError::Malformed)
        );
    }

    #[test]
    fn runtime_signing_opcodes_not_configured() {
        let (body, _) = body_with_key();
        for op in [4u8, 5u8] {
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &envelope(op, vec![]), &body).err(),
                Some(AgentError::NotConfigured)
            );
        }
    }

    #[test]
    fn trailing_bytes_and_non_map_rejected() {
        let (body, _) = body_with_key();
        let mut p = envelope(2, vec![]);
        p.push(0xff); // trailing garbage
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &p, &body).err(),
            Some(AgentError::Malformed)
        );
        let not_map = enc(Value::Integer(1.into()));
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &not_map, &body).err(),
            Some(AgentError::Malformed)
        );
    }

    #[test]
    fn error_codes_match_band() {
        assert_eq!(AgentError::Malformed.code(), 0x40);
        assert_eq!(AgentError::WrongProfile.code(), 0x41);
        assert_eq!(AgentError::KeyPurposeMismatch.code(), 0x42);
        assert_eq!(AgentError::CapabilityRejected.code(), 0x43);
        assert_eq!(AgentError::CapExceeded.code(), 0x44);
        assert_eq!(AgentError::NotConfigured.code(), 0x45);
        assert_eq!(AgentError::SealFailed.code(), 0x46);
    }
}
