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
    public_identity_from_entry, IdentityProof, PublicIdentity, AGENT_GATEWAY_VERSION,
};
use crate::agent_keystore::{KeyPurpose, KeystoreBody};
use ciborium::value::Value;
use std::sync::Mutex;

/// Fixed command-domain string bound in the envelope (spec §10.2, key 3).
pub const COMMAND_DOMAIN: &str = "2d-hsm/agent-gateway/v1";

/// Max `request_id` length — a small correlation/audit handle, not a payload.
const MAX_REQUEST_ID_LEN: usize = 64;

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
    /// A signed identity proof for the requested key. (The response body does not echo `request_id`;
    /// correlation is implicit at the synchronous 0x40 frame layer.)
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
    /// The PROVE_IDENTITY verifier nonce (payload key 7 → sub-map key 1), extracted directly so we
    /// never deep-clone the caller-controlled (up to ~1 MiB) payload subtree for opcodes that
    /// ignore it. Only read on the PROVE path (gated by `agent-prove-identity-preview`).
    #[cfg_attr(not(feature = "agent-prove-identity-preview"), allow(dead_code))]
    verifier_nonce: Option<[u8; 32]>,
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
    // Strict envelope: every key must be a known integer 1..=7, and none may repeat. Unknown or
    // duplicate keys ⇒ Malformed (no silent first-match resolution; the wire format stays
    // unambiguous for future capability/payload binding).
    let mut seen = 0u8; // bitmask of keys 1..=7
    for (k, _) in &map {
        let key = as_u64(k).filter(|n| (1..=7).contains(n)).ok_or(AgentError::Malformed)?;
        let bit = 1u8 << (key - 1);
        if seen & bit != 0 {
            return Err(AgentError::Malformed); // duplicate key
        }
        seen |= bit;
    }
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
    // request_id is a small correlation handle; cap it (an adversarial host could otherwise force a
    // large transient allocation per frame within the MAX_MESSAGE_SIZE budget).
    let request_id = match map_get(&map, 4).and_then(as_bytes) {
        Some(b) if b.len() <= MAX_REQUEST_ID_LEN => b.to_vec(),
        _ => return Err(AgentError::Malformed),
    };
    let has_capability = map_get(&map, 5).is_some();
    // key_ref (envelope key 6) is required to be 32 bytes when present.
    let key_ref = match map_get(&map, 6) {
        None => None,
        Some(v) => Some(as_bytes32(v).ok_or(AgentError::Malformed)?),
    };
    // Payload (key 7). Strict like the outer envelope (no parser ambiguity / audit-evasion): if
    // present it must be a map whose only key is 1 (the 32-byte verifier nonce), no duplicates/
    // unknowns. Extract just the nonce — never clone the (caller-controlled) payload subtree.
    let verifier_nonce = match map_get(&map, 7) {
        None => None,
        Some(Value::Map(inner)) => {
            let mut seen = false;
            for (k, _) in inner {
                if as_u64(k) != Some(1) || seen {
                    return Err(AgentError::Malformed); // unknown or duplicate inner key
                }
                seen = true;
            }
            match map_get(inner, 1) {
                Some(v) => Some(as_bytes32(v).ok_or(AgentError::Malformed)?),
                None => None, // empty payload map ({}) — PROVE then fails closed on the missing nonce
            }
        }
        Some(_) => return Err(AgentError::Malformed), // key 7 present but not a map
    };
    Ok(AgentEnvelope {
        agent_version,
        opcode,
        command_domain,
        request_id,
        has_capability,
        key_ref,
        verifier_nonce,
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
        AgentOpcode::ProveIdentity => {
            // PRODUCTION GATE (vsock spec §10.8): identity-proof signing stays disabled until the
            // 2D EIP-2718 type-0x19 reservation merges (2D PR #144). Enabled only via the
            // `agent-prove-identity-preview` feature; otherwise fail closed.
            #[cfg(feature = "agent-prove-identity-preview")]
            {
                handle_prove_identity(&env, keystore)
            }
            #[cfg(not(feature = "agent-prove-identity-preview"))]
            {
                let _ = &env;
                Err(AgentError::NotConfigured)
            }
        }
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
/// nonce, binding the sealed chain_id/environment_identifier. Gated by the production preview
/// feature (see the dispatch gate).
#[cfg(feature = "agent-prove-identity-preview")]
fn handle_prove_identity(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    use crate::agent_identity::sign_identity_proof;
    use crate::secp256k1::Keypair;
    let key_ref = env.key_ref.ok_or(AgentError::Malformed)?;
    // payload (envelope key 7) = { 1: verifier_nonce(32B) }, extracted in decode_envelope.
    let verifier_nonce = env.verifier_nonce.ok_or(AgentError::Malformed)?;
    let entry =
        crate::agent_identity::find_entry(keystore, &key_ref).ok_or(AgentError::KeyPurposeMismatch)?;
    // Hold the loaded scalar in Zeroizing so it is scrubbed on drop / early return (7.2 AC#15) —
    // a plain `[u8; 32]` would linger on the enclave stack.
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    if entry.secret_scalar.len() != 32 {
        return Err(AgentError::KeyPurposeMismatch);
    }
    secret.copy_from_slice(&entry.secret_scalar);
    let keypair = Keypair::from_secret_bytes(&secret).map_err(|_| AgentError::KeyPurposeMismatch)?;
    let proof = sign_identity_proof(
        &keypair,
        keystore.config.twod_chain_id,
        &keystore.config.environment_identifier,
        &key_ref,
        &verifier_nonce,
    )
    // PROVE_IDENTITY never seals — collapse a signing failure (e.g. the ~2^-128 x-reduced
    // recovery_id rejection) to the same per-key bucket the handler uses above, NOT SealFailed
    // (0x46 = atomic sealed-commit failed; reserved for the GENERATE_KEYS/CONFIGURE_TREASURY path).
    .map_err(|_| AgentError::KeyPurposeMismatch)?;
    Ok(AgentResponse::ProveIdentity(proof))
}

// ===========================================================================================
// Frame-layer integration: the installed-keystore slot + the entry point the lib.rs 0x40 dispatch
// arm calls. (Mirrors the pq_signer INSTALLED_SIGNER slot pattern.)
// ===========================================================================================

/// Process-global slot holding this enclave's unsealed Agent Gateway keystore. An agent-profile
/// instance installs it once at boot; a producer-profile instance never does, so an incoming `0x40`
/// frame on a producer instance is rejected as `WrongProfile` (profile derived from slot presence).
static INSTALLED_KEYSTORE: Mutex<Option<KeystoreBody>> = Mutex::new(None);

/// Install the unsealed keystore (agent-profile boot). **Install-once**: returns `false` (and does
/// NOT overwrite) if a keystore is already installed, so a second call (a boot race or caller
/// mistake) can't silently clobber the live store and dangle existing `key_ref` handles. The
/// mutating GENERATE_KEYS re-seal/swap path lands with the capability/seal slice.
#[must_use]
pub fn install_agent_keystore(body: KeystoreBody) -> bool {
    match INSTALLED_KEYSTORE.lock() {
        Ok(mut guard) if guard.is_none() => {
            *guard = Some(body);
            true
        }
        _ => false,
    }
}

/// Whether an agent keystore is installed (i.e. this instance runs the Agent Gateway profile).
pub fn is_agent_keystore_installed() -> bool {
    INSTALLED_KEYSTORE.lock().map(|g| g.is_some()).unwrap_or(false)
}

#[cfg(test)]
pub fn reset_agent_keystore_for_tests() {
    if let Ok(mut guard) = INSTALLED_KEYSTORE.lock() {
        *guard = None;
    }
}

/// Frame-layer entry point: dispatch a `0x40` inner-envelope `payload` against the installed
/// keystore and return the encoded response BODY — a per-opcode success map or a §10.9 error map.
/// Always returns a body (never errors out of band), so the wire layer just frames it. Profile is
/// derived from slot presence: no installed keystore ⇒ not an agent instance ⇒ `WrongProfile`.
pub fn handle_agent_gateway_frame(payload: &[u8]) -> Vec<u8> {
    let result = match INSTALLED_KEYSTORE.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(keystore) => dispatch_agent(Profile::AgentGateway, payload, keystore),
            None => Err(AgentError::WrongProfile),
        },
        Err(_) => Err(AgentError::SealFailed), // poisoned lock — fail closed
    };
    match result {
        Ok(resp) => encode_agent_response(&resp),
        Err(e) => encode_agent_error(e),
    }
}

fn key_purpose_code(p: KeyPurpose) -> u64 {
    match p {
        KeyPurpose::AgentTransferK1 => 1,
        KeyPurpose::AgentFaucetTreasuryK1 => 2,
    }
}

fn encode_body(map: Vec<(Value, Value)>) -> Vec<u8> {
    let mut buf = Vec::new();
    // into_writer is infallible for these owned in-memory Values; a serialize error can't occur.
    let _ = ciborium::ser::into_writer(&Value::Map(map), &mut buf);
    buf
}

/// Encode a success response body (per-opcode integer-key CBOR map).
fn encode_agent_response(resp: &AgentResponse) -> Vec<u8> {
    match resp {
        // PUBLIC_IDENTITY response (spec §10.4).
        AgentResponse::PublicIdentity(id) => encode_body(vec![
            (Value::Integer(1.into()), Value::Bytes(id.pubkey_uncompressed.to_vec())),
            (Value::Integer(2.into()), Value::Bytes(id.eth_address.to_vec())),
            (Value::Integer(3.into()), Value::Text(id.tron_address.clone())),
            (Value::Integer(4.into()), Value::Bytes(id.key_ref.to_vec())),
            (Value::Integer(5.into()), Value::Integer(key_purpose_code(id.key_purpose).into())),
            // §10.4 key 6 = backend_version. Currently the agent protocol version (=1); the
            // build/protocol-version component (keygen-identity doc) is a follow-up — no host keys
            // off a build component yet, and no vector pins it.
            (Value::Integer(6.into()), Value::Integer((id.agent_version as u64).into())),
        ]),
        // PROVE_IDENTITY response: low-S recoverable signature + the bound address/pubkey.
        AgentResponse::ProveIdentity(proof) => encode_body(vec![
            (Value::Integer(1.into()), Value::Bytes(proof.signature.r.to_vec())),
            (Value::Integer(2.into()), Value::Bytes(proof.signature.s.to_vec())),
            (Value::Integer(3.into()), Value::Integer((proof.signature.recovery_id as u64).into())),
            (Value::Integer(4.into()), Value::Bytes(proof.address.to_vec())),
            (Value::Integer(5.into()), Value::Bytes(proof.pubkey_uncompressed.to_vec())),
        ]),
    }
}

/// Encode a §10.9 agent error body `{1: code, 2: reason}`. Reasons are coarse (no secret detail).
fn encode_agent_error(e: AgentError) -> Vec<u8> {
    let reason = match e {
        AgentError::Malformed => "agent: malformed request",
        AgentError::WrongProfile => "agent: wrong profile",
        AgentError::KeyPurposeMismatch => "agent: key purpose mismatch",
        AgentError::CapabilityRejected => "agent: capability rejected",
        AgentError::CapExceeded => "agent: cap exceeded",
        AgentError::NotConfigured => "agent: not configured",
        AgentError::SealFailed => "agent: seal failed",
    };
    encode_body(vec![
        (Value::Integer(1.into()), Value::Integer((e.code() as u64).into())),
        (Value::Integer(2.into()), Value::Text(reason.to_string())),
    ])
}

/// Decode an agent response/error body to its `{code, reason}` or success-map for assertions.
#[cfg(test)]
pub fn decode_agent_error_code(body: &[u8]) -> Option<u8> {
    let v: Value = ciborium::de::from_reader(body).ok()?;
    let Value::Map(m) = v else { return None };
    // Error bodies carry an INTEGER code at key 1; success bodies carry BYTES at key 1 (a pubkey),
    // for which `as_u64` returns None — so a success body naturally yields None here.
    u8::try_from(map_get(&m, 1).and_then(as_u64)?).ok()
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

    #[cfg(feature = "agent-prove-identity-preview")]
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

    /// Without the production-preview feature, PROVE_IDENTITY is gated off (vsock §10.8) → 0x45.
    #[cfg(not(feature = "agent-prove-identity-preview"))]
    #[test]
    fn prove_identity_gated_off_when_preview_disabled() {
        let (body, key_ref) = body_with_key();
        let payload = envelope(
            3,
            vec![
                (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                (
                    Value::Integer(7.into()),
                    Value::Map(vec![(Value::Integer(1.into()), Value::Bytes(vec![0xab; 32]))]),
                ),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::NotConfigured)
        );
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
    fn payload_with_extra_inner_key_rejected() {
        // Inner payload map must be strict (only key 1) — an extra inner key ⇒ Malformed, before
        // routing (so it holds regardless of the PROVE preview feature).
        let (body, key_ref) = body_with_key();
        let payload = envelope(
            3,
            vec![
                (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                (
                    Value::Integer(7.into()),
                    Value::Map(vec![
                        (Value::Integer(1.into()), Value::Bytes(vec![0xab; 32])),
                        (Value::Integer(2.into()), Value::Integer(9.into())), // unknown inner key
                    ]),
                ),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
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

    /// Frame-layer path through the installed-keystore slot. Single test (the slot is process-global)
    /// to avoid cross-test interference; it covers the no-keystore (producer) and installed paths.
    #[test]
    fn frame_handler_via_installed_keystore_slot() {
        reset_agent_keystore_for_tests();
        let (body, key_ref) = body_with_key();

        // No keystore installed ⇒ producer/uninstalled ⇒ WrongProfile (0x41) error body.
        let pubid_env =
            envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))]);
        let err_body = handle_agent_gateway_frame(&pubid_env);
        assert_eq!(decode_agent_error_code(&err_body), Some(0x41));

        // Install the keystore ⇒ PUBLIC_IDENTITY returns a success body (key 1 = 65-byte pubkey).
        assert!(install_agent_keystore(body), "install-once succeeds on an empty slot");
        let ok_body = handle_agent_gateway_frame(&pubid_env);
        assert_eq!(decode_agent_error_code(&ok_body), None, "success body, not an error map");
        let v: Value = ciborium::de::from_reader(&ok_body[..]).unwrap();
        let Value::Map(m) = v else { panic!("response is a map") };
        assert_eq!(as_bytes(map_get(&m, 1).unwrap()).unwrap().len(), 65, "pubkey 65B");
        assert_eq!(as_bytes(map_get(&m, 4).unwrap()).unwrap(), key_ref, "key_ref echoed");

        // Unknown key_ref ⇒ collapsed 0x42 error body.
        let bad = envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(vec![0xfe; 32]))]);
        assert_eq!(decode_agent_error_code(&handle_agent_gateway_frame(&bad)), Some(0x42));

        reset_agent_keystore_for_tests();
    }
}
