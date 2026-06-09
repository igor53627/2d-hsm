//! Agent Gateway `0x40` dispatch router (TASK-7.6.3).
//!
//! Decodes the inner Agent Gateway envelope (protocol spec §10.2), applies the fail-closed gates in
//! order — profile (role isolation), `agent_version`, `command_domain`, opcode allow-list — then
//! classifies each opcode by privilege and routes it:
//!
//! - **Low-privilege reads** `PUBLIC_IDENTITY(2)` / `PROVE_IDENTITY(3)` (no capability) are handled
//!   here end-to-end against the unsealed keystore.
//! - **Privileged** opcodes `{GENERATE_KEYS(1), CONFIGURE_TREASURY(6), EXPORT_BACKUP(7),
//!   RESTORE_BACKUP(8)}` are verified by [`verify_capability`] (Ed25519 + authority tier + opcode/
//!   request binding + contiguous-counter CHECK, via [`crate::agent_capability`]). **GENERATE_KEYS
//!   executes** (key mint + counter advance + candidate re-seal/swap) ONLY under the off-by-default,
//!   release-banned `agent-keygen-exec-preview` feature — live, host-rollback-replayable key minting
//!   must wait for anti-rollback (TASK-7.7) + `scope_target`↔sealed-enclave-id binding + the AC#14
//!   audit record. Without that feature (and for CONFIGURE_TREASURY/EXPORT/RESTORE) a verified
//!   privileged request **fails closed** with `AGENT_NOT_CONFIGURED`. Capability *failures* collapse
//!   to `AGENT_CAPABILITY_REJECTED` (0x43).
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
use crate::agent_capability::VerifiedCapability;
use crate::agent_keygen::{generate_keys, GenerateKeysError, GeneratedKey};
use crate::agent_keystore::{seal_body, CreationMetadata, KeyPurpose, KeystoreBody};
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
    /// GENERATE_KEYS result: the generated public key material PLUS the mutated `candidate` keystore
    /// (counter advanced + new entries). The frame layer seals the candidate, returns the sealed blob
    /// for the host to persist, and swaps it into the live slot (clone→seal→persist→swap, §7.2).
    GenerateKeys {
        keys: Vec<GeneratedKey>,
        candidate: Box<KeystoreBody>,
    },
}

/// The decoded Agent Gateway envelope (§10.2). The capability (key 5) is captured as the raw CBOR
/// map for [`verify_capability`]; presence is derived from `capability.is_some()`.
struct AgentEnvelope {
    agent_version: u8,
    opcode: u8,
    command_domain: String,
    request_id: Vec<u8>,
    /// The administrative/recovery capability map (inner-envelope key 5) for privileged opcodes,
    /// `None` for reads/runtime. Verified by [`verify_capability`] (§10.5).
    capability: Option<Vec<(Value, Value)>>,
    key_ref: Option<[u8; 32]>,
    /// The command payload (inner-envelope key 7) as a raw CBOR map; parsed per-opcode by each
    /// handler: PROVE_IDENTITY = `{1: verifier_nonce(32B)}`, GENERATE_KEYS = `{1: purpose, 2: count}`.
    /// `None` if key 7 is absent.
    payload: Option<Vec<(Value, Value)>>,
}

use crate::agent_cbor::{as_bytes, as_bytes32, as_u64, check_strict_keys, map_get};

/// Decode the inner Agent Gateway envelope. Any shape error → `Malformed` (0x40, syntax only).
fn decode_envelope(payload: &[u8]) -> Result<AgentEnvelope, AgentError> {
    // Strict CANONICAL decode (rejects non-shortest integers, indefinite lengths, duplicate /
    // out-of-order keys, and trailing bytes) so the envelope AND its nested cap (key 5) / payload
    // (key 7) submaps bind the exact wire bytes — not a lenient ciborium re-encoding. This is what
    // makes the downstream capability Ed25519 check (which signs over a re-encoded canonical preimage)
    // sound against a host that submits a non-canonical encoding of otherwise-valid signed values.
    let map = crate::agent_cbor::strict_decode_map(payload).map_err(|_| AgentError::Malformed)?;
    // Strict envelope schema: every key must be a known integer 1..=7, and none may repeat. Unknown
    // or duplicate keys ⇒ Malformed (the canonical decode already rejected dup/out-of-order keys; this
    // is the schema allow-list on top).
    if !check_strict_keys(&map, |n| (1..=7).contains(&n)) {
        return Err(AgentError::Malformed);
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
    // Capability (envelope key 5): if present it MUST be a CBOR map (the §10.5 cap structure); its
    // full Ed25519 + binding + counter verification is the verify_capability seam.
    let capability = match map_get(&map, 5) {
        None => None,
        Some(Value::Map(m)) => Some(m.clone()),
        Some(_) => return Err(AgentError::Malformed),
    };
    // key_ref (envelope key 6) is required to be 32 bytes when present.
    let key_ref = match map_get(&map, 6) {
        None => None,
        Some(v) => Some(as_bytes32(v).ok_or(AgentError::Malformed)?),
    };
    // Payload (key 7): if present it must be a CBOR map (the per-opcode command params). Its exact
    // shape is validated by each opcode handler — PROVE_IDENTITY `{1: nonce}`, GENERATE_KEYS
    // `{1: purpose, 2: count}` — not here, so the envelope decode stays opcode-agnostic.
    let payload = match map_get(&map, 7) {
        None => None,
        Some(Value::Map(inner)) => Some(inner.clone()),
        Some(_) => return Err(AgentError::Malformed), // key 7 present but not a map
    };
    Ok(AgentEnvelope {
        agent_version,
        opcode,
        command_domain,
        request_id,
        capability,
        key_ref,
        payload,
    })
}

/// Capability seam for privileged opcodes — delegates to [`crate::agent_capability`] (§10.5/§10.6):
/// Ed25519 verify over canonical-CBOR(keys 1–12) vs the sealed `admin_authority_pk`/
/// `recovery_authority_pk`, opcode/`request_id` binding, chain/env match, and the contiguous-counter
/// CHECK. **Verify-only:** the `key_purpose` (0x42) and `payload_binding` checks plus the counter
/// ADVANCE + atomic re-seal land with the per-opcode handler / mutation slice (so a passing cap then
/// hits `AGENT_NOT_CONFIGURED` until execution is wired). Every failure collapses to
/// `AGENT_CAPABILITY_REJECTED` (0x43); structural/version errors surface as `AGENT_MALFORMED`.
fn verify_capability(
    envelope: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<VerifiedCapability, AgentError> {
    let cap = envelope
        .capability
        .as_deref()
        .ok_or(AgentError::CapabilityRejected)?;
    crate::agent_capability::verify_capability_extract(
        cap,
        envelope.opcode,
        &envelope.request_id,
        &keystore.config,
        &keystore.counters,
    )
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
        if env.capability.is_none() {
            return Err(AgentError::CapabilityRejected); // missing cap collapses to 0x43
        }
        // Full §10.5 capability verification (Ed25519 + tier + binding + contiguous counter CHECK);
        // failures collapse to 0x43 / 0x40. Returns the verified data the handler binds + advances.
        let verified = verify_capability(&env, keystore)?;
        return match opcode {
            // GENERATE_KEYS executes ONLY under the off-by-default `agent-keygen-exec-preview`
            // feature (release-banned): live key minting must wait for anti-rollback (TASK-7.7) +
            // scope_target-binding + the AC#14 audit record. Production verifies the cap then fails
            // closed (no mutation).
            #[cfg(feature = "agent-keygen-exec-preview")]
            AgentOpcode::GenerateKeys => handle_generate_keys(&env, keystore, &verified),
            // CONFIGURE_TREASURY / EXPORT_BACKUP / RESTORE_BACKUP (and GENERATE_KEYS without the
            // preview feature) verify here but their execution lands in later slices ⇒ fail closed.
            _ => {
                let _ = &verified;
                Err(AgentError::NotConfigured)
            }
        };
    }
    if env.capability.is_some() {
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
    // payload (envelope key 7) = strict `{ 1: verifier_nonce(32B) }` (no other/dup keys).
    let payload = env.payload.as_deref().ok_or(AgentError::Malformed)?;
    if payload.len() != 1 {
        return Err(AgentError::Malformed);
    }
    let verifier_nonce = match map_get(payload, 1) {
        Some(v) => as_bytes32(v).ok_or(AgentError::Malformed)?,
        None => return Err(AgentError::Malformed),
    };
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

/// Canonical CBOR of the GENERATE_KEYS command params `{1: purpose, 2: count}` (RFC 8949 shortest
/// form) — the exact bytes hashed into `payload_binding`. Shared by the handler and the tests so the
/// two cannot drift on the wire layout.
fn generate_keys_canonical_params(purpose_code: u64, count: u64) -> Vec<u8> {
    let mut out = Vec::new();
    crate::agent_capability::put_uint(&mut out, 5, 2); // 2-entry map header
    crate::agent_capability::put_uint(&mut out, 0, 1);
    crate::agent_capability::put_uint(&mut out, 0, purpose_code);
    crate::agent_capability::put_uint(&mut out, 0, 2);
    crate::agent_capability::put_uint(&mut out, 0, count);
    out
}

/// GENERATE_KEYS(1): after a verified admin capability, bind the request params to the cap, generate
/// `count` keys of `purpose` on a CANDIDATE clone, and advance the capability counter. Returns the
/// candidate for the frame layer to seal → persist → swap (no live mutation here).
///
/// Compiled always (so its imports/helpers stay "used") but only CALLED under the
/// `agent-keygen-exec-preview` feature — without it, dispatch routes GENERATE_KEYS to NotConfigured.
#[cfg_attr(not(feature = "agent-keygen-exec-preview"), allow(dead_code))]
fn handle_generate_keys(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
    verified: &VerifiedCapability,
) -> Result<AgentResponse, AgentError> {
    // payload (envelope key 7) = strict `{ 1: purpose, 2: count }` (no other/dup keys).
    let payload = env.payload.as_deref().ok_or(AgentError::Malformed)?;
    if payload.len() != 2 {
        return Err(AgentError::Malformed);
    }
    let purpose_code = map_get(payload, 1).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let count = map_get(payload, 2).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let purpose = match purpose_code {
        1 => KeyPurpose::AgentTransferK1,
        2 => KeyPurpose::AgentFaucetTreasuryK1,
        _ => return Err(AgentError::Malformed),
    };

    // key_purpose binding (§10.5): the cap's signed key_purpose (key 4) must match the request.
    // Collapses with key-not-found to 0x42 (anti-oracle, §10.9).
    if u64::from(verified.key_purpose) != purpose_code {
        return Err(AgentError::KeyPurposeMismatch);
    }

    // payload_binding (§10.5, last gate before mutation): recompute
    // keccak256(opcode ‖ request_id ‖ canonical-CBOR({1:purpose, 2:count})) and compare to the cap's
    // signed value, so the host cannot have altered purpose/count under a valid cap. → 0x43.
    let computed = crate::agent_capability::payload_binding(
        env.opcode,
        None,
        &env.request_id,
        &generate_keys_canonical_params(purpose_code, count),
    );
    if computed != verified.payload_binding {
        return Err(AgentError::CapabilityRejected);
    }

    // Financial scope policy (§10.5/§10.6 AC#12): faucet/treasury keys must be enclave-scoped
    // (scope_class == 0) so a fleet-scoped cap can't multiply a treasury across clones.
    if purpose == KeyPurpose::AgentFaucetTreasuryK1 && verified.scope_class != 0 {
        return Err(AgentError::CapabilityRejected);
    }

    let count_usize = usize::try_from(count).map_err(|_| AgentError::CapExceeded)?;

    // CANDIDATE: clone live → generate (all-or-nothing) → advance the counter, all on the candidate.
    let mut candidate = keystore.clone();
    let creation = CreationMetadata {
        config_version: keystore.config.monotonic_treasury_config_version,
        counter_snapshot: verified.counter,
        // batch_id = the capability counter: the per-(authority, scope_class, scope_target) batch
        // SEQUENCE number, not a global id — full provenance is (authority, scope, batch_id).
        batch_id: verified.counter,
    };
    // NOTE (deferred, AC#14): a privileged-op audit record (op, authority, counter, config_version)
    // into `candidate.audit` + the last_exported_seq backpressure is NOT written here yet — it lands
    // with the audit-ring slice (tracked as a TASK-7.6 follow-up).
    let keys =
        generate_keys(&mut candidate, purpose, count_usize, creation).map_err(map_keygen_error)?;
    candidate
        .advance_counter(
            &verified.authority,
            verified.scope_class,
            &verified.scope_target,
            verified.counter,
        )
        .map_err(|e| match e {
            // Counter table full → CapExceeded (0x44); a regression / anything else is an internal
            // invariant break → fail closed (0x46), no swap.
            crate::agent_keystore::KeystoreError::CapacityExceeded => AgentError::CapExceeded,
            _ => AgentError::SealFailed,
        })?;
    // Anti-rollback structural bump (TASK-7.7 key 5): GENERATE_KEYS is a structural mutation the anchor
    // cannot reconstruct, so bump structural_version per COMMITTED op (once, regardless of `count`).
    // `checked_add` → SealFailed (0x46) on overflow, never wrap (a wrapped counter would let a restore
    // masquerade as an adoptable gap). This is a LOCAL-ONLY bump and currently INERT: advancing
    // `freshness_epoch` + the anchor ack atomically with it (seal-before-emit) and the boot `reconcile`
    // that reads `structural_version` are the deferred co-slice — nothing reads it at boot yet. It rides
    // the candidate, so it ships only under `agent-keygen-exec-preview` like the rest of this handler.
    candidate.structural_version = candidate
        .structural_version
        .checked_add(1)
        .ok_or(AgentError::SealFailed)?;
    Ok(AgentResponse::GenerateKeys { keys, candidate: Box::new(candidate) })
}

/// Map a keygen failure to the anti-oracle §10.9 band.
fn map_keygen_error(e: GenerateKeysError) -> AgentError {
    match e {
        // Bad count for the purpose — a malformed request field.
        GenerateKeysError::InvalidCount => AgentError::Malformed,
        // A second treasury would reveal treasury presence — collapse to the generic cap rejection.
        GenerateKeysError::TreasuryExists => AgentError::CapabilityRejected,
        GenerateKeysError::CapacityExceeded => AgentError::CapExceeded,
        // RNG failure / key_ref-collision exhaustion: internal, fail-closed, no result emitted.
        GenerateKeysError::Csprng => AgentError::SealFailed,
    }
}

// ===========================================================================================
// Frame-layer integration: the installed-keystore slot + the entry point the lib.rs 0x40 dispatch
// arm calls. (Mirrors the pq_signer INSTALLED_SIGNER slot pattern.)
// ===========================================================================================

/// What the [`INSTALLED_KEYSTORE`] slot holds: the unsealed keystore body plus the
/// `enclave_measurement` it was sealed under, so a privileged mutation can RE-SEAL the candidate (the
/// provisioning root itself comes from [`crate::seal_root`]).
struct InstalledAgentKeystore {
    body: KeystoreBody,
    measurement: Vec<u8>,
}

/// Process-global slot holding this enclave's unsealed Agent Gateway keystore (+ its seal
/// measurement). An agent-profile instance installs it once at boot; a producer-profile instance
/// never does, so an incoming `0x40` frame on a producer instance is rejected as `WrongProfile`
/// (profile derived from slot presence).
static INSTALLED_KEYSTORE: Mutex<Option<InstalledAgentKeystore>> = Mutex::new(None);

/// Install the unsealed keystore + the `enclave_measurement` it was sealed under (agent-profile boot).
/// **Install-once**: returns `false` (and does NOT overwrite) if a keystore is already installed, so a
/// second call (a boot race or caller mistake) can't silently clobber the live store and dangle
/// existing `key_ref` handles. The measurement is retained so privileged mutations can re-seal.
#[must_use]
pub fn install_agent_keystore(body: KeystoreBody, enclave_measurement: &[u8]) -> bool {
    // An empty measurement would make every privileged re-seal fail (`EmptyMeasurement`) — reject the
    // install up front rather than brick keygen after boot.
    if enclave_measurement.is_empty() {
        return false;
    }
    match INSTALLED_KEYSTORE.lock() {
        Ok(mut guard) if guard.is_none() => {
            *guard = Some(InstalledAgentKeystore { body, measurement: enclave_measurement.to_vec() });
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
///
/// For a mutating opcode (GENERATE_KEYS) dispatch returns a CANDIDATE body; this layer **seals** it
/// (provisioning root from [`crate::seal_root`] + the stored measurement), returns the sealed blob in
/// the response for the host to persist, and **swaps** it into the live slot — only after a
/// successful seal (seal failure ⇒ `0x46`, live state untouched).
pub fn handle_agent_gateway_frame(payload: &[u8]) -> Vec<u8> {
    // Recover from a poisoned lock rather than bricking the agent permanently: the slot's only
    // mutation is the final swap below, performed AFTER every fallible step succeeds, so a panic in an
    // earlier step leaves the body intact and the next frame can safely continue. (Removes a
    // "one panic anywhere under dispatch → permanent 0x46 lockout" DoS.)
    let mut guard = INSTALLED_KEYSTORE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Borrow the installed body for dispatch and clone its measurement in one arm (no second
    // fallible unwrap). The borrow ends when dispatch returns its OWNED outcome, freeing `guard`.
    let (outcome, measurement) = match guard.as_ref() {
        Some(installed) => {
            let measurement = installed.measurement.clone();
            let outcome = dispatch_agent(Profile::AgentGateway, payload, &installed.body);
            (outcome, measurement)
        }
        None => return encode_agent_error(AgentError::WrongProfile),
    };
    match outcome {
        Ok(AgentResponse::GenerateKeys { keys, candidate }) => {
            // Seal the candidate (counter advanced + new entries) so the host can persist it.
            let sealed = match crate::seal_root::resolve_provisioning_root() {
                Ok(root) => match seal_body(&candidate, &root, &measurement) {
                    Ok(blob) => blob,
                    Err(_) => return encode_agent_error(AgentError::SealFailed),
                },
                Err(_) => return encode_agent_error(AgentError::SealFailed),
            };
            let body = encode_generate_keys_response(&keys, &sealed);
            // Swap the live in-memory slot so subsequent commands see the advanced counter + new
            // keys; durability is the host's job (it persists `sealed`, returned above).
            *guard = Some(InstalledAgentKeystore { body: *candidate, measurement });
            body
        }
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
        // GENERATE_KEYS MUST be encoded by the frame layer WITH its sealed blob
        // (`encode_generate_keys_response`). Reaching the generic encoder means a mis-routed mutation;
        // fail closed to an error body rather than fabricate a persist-less success the host can't
        // store. (No panic/`debug_assert` here — this runs under the INSTALLED_KEYSTORE lock.)
        AgentResponse::GenerateKeys { .. } => encode_agent_error(AgentError::SealFailed),
    }
}

/// Encode the GENERATE_KEYS response (§10.4): `{1: [per-key maps], 2: sealed_keystore_blob}`, each key
/// map = `{1: key_ref, 2: pubkey_uncompressed, 3: eth_address, 4: tron_address, 5: key_purpose}`. Key
/// 2 is the new sealed keystore the host MUST persist (the enclave has no durable storage).
fn encode_generate_keys_response(keys: &[GeneratedKey], sealed_blob: &[u8]) -> Vec<u8> {
    let key_list: Vec<Value> = keys
        .iter()
        .map(|k| {
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(k.key_ref.to_vec())),
                (Value::Integer(2.into()), Value::Bytes(k.pubkey_uncompressed.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(k.eth_address.to_vec())),
                (Value::Integer(4.into()), Value::Text(k.tron_address.clone())),
                (
                    Value::Integer(5.into()),
                    Value::Integer(key_purpose_code(k.key_purpose).into()),
                ),
            ])
        })
        .collect();
    encode_body(vec![
        (Value::Integer(1.into()), Value::Array(key_list)),
        (Value::Integer(2.into()), Value::Bytes(sealed_blob.to_vec())),
    ])
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
            structural_version: 1,
            strict_recovery_counter: 0,
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
    fn privileged_bogus_capability_is_malformed() {
        let (body, _) = body_with_key();
        // GENERATE_KEYS(1) with a structurally-invalid (empty) capability map → MALFORMED (0x40):
        // the verifier now parses the cap and rejects missing required keys.
        let payload = envelope(1, vec![(Value::Integer(5.into()), Value::Map(vec![]))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::Malformed)
        );
    }

    #[test]
    fn deferred_privileged_op_valid_cap_reaches_not_configured() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // EXPORT_BACKUP(7) is admin-tier but its handler is still deferred: a valid cap verifies,
        // then the request collapses to NotConfigured (0x45) — proves verify→handler routing.
        let cap = crate::agent_capability::test_signed_capability(
            &admin, 7, &[0x11; 16], 1, false, 11565, "testnet", 0, b"export_backup", 1, [0xab; 32],
        );
        let payload = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::NotConfigured)
        );
    }

    #[test]
    fn noncanonical_nested_capability_is_malformed_before_verify() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        let mut cap = crate::agent_capability::test_signed_capability(
            &admin, 7, &[0x11; 16], 1, false, 11565, "testnet", 0, b"export_backup", 1, [0xab; 32],
        );
        // Reverse the cap entries so the nested submap's keys are DESCENDING (non-canonical) while the
        // signed VALUES are unchanged. In ascending order this exact cap reaches NotConfigured (see
        // deferred_privileged_op_valid_cap_reaches_not_configured); the non-canonical wire bytes must
        // be rejected as Malformed by the strict decoder BEFORE verify_capability runs — proving the
        // nested cap submap (envelope key 5) is canonical-checked, not just the top-level envelope.
        cap.reverse();
        let payload = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body).err(),
            Some(AgentError::Malformed)
        );
    }

    /// Build a GENERATE_KEYS cap whose `payload_binding` correctly covers `{1:purpose, 2:count}`, plus
    /// the matching envelope-key-7 payload. Returns (cap_map, payload_map).
    #[allow(clippy::type_complexity)]
    fn generate_keys_cap_and_payload(
        admin: &ed25519_dalek::SigningKey,
        request_id: &[u8],
        counter: u64,
        purpose_code: u64,
        count: u64,
        scope_target: &[u8],
    ) -> (Vec<(Value, Value)>, Vec<(Value, Value)>) {
        let pb = crate::agent_capability::payload_binding(
            1,
            None,
            request_id,
            &generate_keys_canonical_params(purpose_code, count),
        );
        let cap = crate::agent_capability::test_signed_capability(
            admin, 1, request_id, counter, false, 11565, "testnet", 0, scope_target,
            purpose_code as u8, pb,
        );
        let payload = vec![
            (Value::Integer(1.into()), Value::Integer(purpose_code.into())),
            (Value::Integer(2.into()), Value::Integer(count.into())),
        ];
        (cap, payload)
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_executes_and_advances_counter() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        let (cap, pay) = generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body).unwrap() {
            AgentResponse::GenerateKeys { keys, candidate } => {
                assert_eq!(keys.len(), 3, "3 transfer keys generated");
                assert!(keys.iter().all(|k| k.key_purpose == KeyPurpose::AgentTransferK1));
                assert_eq!(candidate.entries.len(), 3, "candidate has the new entries");
                let c = candidate
                    .counters
                    .iter()
                    .find(|c| c.scope_target == b"generate_transfer")
                    .expect("counter row created");
                assert_eq!(c.highest_accepted_counter, 1, "counter advanced to 1");
                assert_eq!(c.authority, admin.verifying_key().to_bytes());
            }
            _ => panic!("expected GenerateKeys"),
        }
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_bumps_structural_version_per_op_local_only() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        assert_eq!(body.structural_version, 1);
        // count=3: three keys minted in ONE committed op.
        let (cap, pay) = generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body).unwrap() {
            AgentResponse::GenerateKeys { candidate, .. } => {
                // +1 per COMMITTED op, regardless of count (NOT +3).
                assert_eq!(candidate.structural_version, 2);
                // LOCAL-ONLY: freshness_epoch + strict_recovery_counter untouched (epoch advance + anchor
                // ack are the deferred seal-before-emit co-slice).
                assert_eq!(candidate.freshness_epoch, body.freshness_epoch);
                assert_eq!(candidate.strict_recovery_counter, body.strict_recovery_counter);
            }
            _ => panic!("expected GenerateKeys"),
        }
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_structural_overflow_fails_closed() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        body.structural_version = u64::MAX; // checked_add → None → SealFailed, no swap
        let (cap, pay) = generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 1, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::SealFailed)
        );
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_payload_binding_mismatch_rejected() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // Cap binds count=3, but the request payload says count=99 ⇒ payload_binding mismatch ⇒ 0x43.
        let (cap, _) = generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
        let tampered = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Integer(99.into())),
        ];
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(tampered)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_purpose_mismatch_is_key_purpose_mismatch() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // The cap (test helper) signs key_purpose=1 (transfer); request purpose=2 (faucet) ⇒ 0x42.
        // Build a cap+payload for purpose 2 but the cap's signed key_purpose is 1 → mismatch.
        let pb = crate::agent_capability::payload_binding(
            1,
            None,
            &[0x11; 16],
            &generate_keys_canonical_params(2, 1),
        );
        let cap = crate::agent_capability::test_signed_capability(
            &admin, 1, &[0x11; 16], 1, false, 11565, "testnet", 0, b"generate_faucet", 1, pb,
        );
        let pay = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())), // purpose 2 (faucet)
            (Value::Integer(2.into()), Value::Integer(1.into())),
        ];
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::KeyPurposeMismatch)
        );
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_treasury_enclave_scoped_succeeds() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // Faucet treasury (purpose 2), enclave scope (0), singleton count 1.
        let (cap, pay) = generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 2, 1, b"generate_faucet");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body).unwrap() {
            AgentResponse::GenerateKeys { keys, candidate } => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].key_purpose, KeyPurpose::AgentFaucetTreasuryK1);
                assert_eq!(candidate.entries.len(), 1);
            }
            _ => panic!("expected GenerateKeys"),
        }
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_fleet_scoped_treasury_rejected() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // Treasury keygen MUST be enclave-scoped (AC#12); a fleet-scoped (scope_class=1) cap is
        // rejected (0x43) so a treasury budget can't be multiplied across clones.
        let pb = crate::agent_capability::payload_binding(
            1,
            None,
            &[0x11; 16],
            &generate_keys_canonical_params(2, 1),
        );
        let cap = crate::agent_capability::test_signed_capability(
            &admin, 1, &[0x11; 16], 1, false, 11565, "testnet", 1, b"generate_faucet", 2, pb,
        );
        let pay = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(1.into())),
        ];
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn generate_keys_request_id_mismatch_rejected() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // Cap bound to request_id [0x22;16]; the envelope's request_id is [0x11;16] ⇒ 0x43 (a cap
        // for one request cannot authorize another).
        let (cap, pay) = generate_keys_cap_and_payload(&admin, &[0x22; 16], 1, 1, 1, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn privileged_badly_signed_capability_rejected() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let wrong = SigningKey::from_bytes(&[8u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // A well-formed cap signed by the wrong key ⇒ Ed25519 fails ⇒ CapabilityRejected (0x43).
        let cap = crate::agent_capability::test_signed_capability(
            &wrong, 1, &[0x11; 16], 1, false, 11565, "testnet", 0, b"generate_transfer", 1, [0xab; 32],
        );
        let payload = envelope(1, vec![(Value::Integer(5.into()), Value::Map(cap))]);
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

    #[cfg(feature = "agent-prove-identity-preview")]
    #[test]
    fn payload_with_extra_inner_key_rejected() {
        // The PROVE_IDENTITY payload must be strict `{1: nonce}` — an extra inner key ⇒ Malformed.
        // This strictness now lives in the (preview-gated) handler; without the preview feature
        // opcode 3 is gated off (NotConfigured) before the payload is parsed.
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
        use ed25519_dalek::SigningKey;
        reset_agent_keystore_for_tests();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // One transfer key so PUBLIC_IDENTITY has something to return.
        let creation = CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 };
        let key_ref =
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, 1, creation).unwrap()[0].key_ref;

        // No keystore installed ⇒ producer/uninstalled ⇒ WrongProfile (0x41) error body.
        let pubid_env =
            envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))]);
        assert_eq!(decode_agent_error_code(&handle_agent_gateway_frame(&pubid_env)), Some(0x41));

        // Install ⇒ PUBLIC_IDENTITY returns a success body (key 1 = 65-byte pubkey).
        assert!(install_agent_keystore(body, b"meas"), "install-once succeeds on an empty slot");
        let ok_body = handle_agent_gateway_frame(&pubid_env);
        assert_eq!(decode_agent_error_code(&ok_body), None, "success body, not an error map");
        let Value::Map(m) = ciborium::de::from_reader(&ok_body[..]).unwrap() else {
            panic!("response is a map")
        };
        assert_eq!(as_bytes(map_get(&m, 1).unwrap()).unwrap().len(), 65, "pubkey 65B");
        assert_eq!(as_bytes(map_get(&m, 4).unwrap()).unwrap(), key_ref, "key_ref echoed");

        // Unknown key_ref ⇒ collapsed 0x42 error body.
        let bad = envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(vec![0xfe; 32]))]);
        assert_eq!(decode_agent_error_code(&handle_agent_gateway_frame(&bad)), Some(0x42));

        // GENERATE_KEYS through the FRAME — live execution is preview-gated, so this whole section
        // only compiles/runs under `agent-keygen-exec-preview`. Success body carries the key list
        // (key 1) AND the new sealed keystore blob (key 2) for the host to persist.
        #[cfg(feature = "agent-keygen-exec-preview")]
        {
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 2, b"generate_transfer");
        let gen_env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        let gen_body = handle_agent_gateway_frame(&gen_env);
        assert_eq!(decode_agent_error_code(&gen_body), None, "GENERATE_KEYS success");
        let Value::Map(gm) = ciborium::de::from_reader(&gen_body[..]).unwrap() else { panic!() };
        match map_get(&gm, 1).unwrap() {
            Value::Array(a) => assert_eq!(a.len(), 2, "2 keys generated"),
            _ => panic!("key 1 is the key list"),
        }
        assert!(
            !as_bytes(map_get(&gm, 2).unwrap()).unwrap().is_empty(),
            "key 2 is the non-empty sealed keystore blob"
        );

        // Replay the SAME cap (counter 1) ⇒ now 0x43: the swap advanced the live counter to 1, so the
        // contiguity check expects 2. End-to-end replay rejection + proof the swap happened.
        let (cap_r, pay_r) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 2, b"generate_transfer");
        let replay_env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap_r)),
                (Value::Integer(7.into()), Value::Map(pay_r)),
            ],
        );
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&replay_env)),
            Some(0x43),
            "replay of the consumed counter is rejected after the swap"
        );

        // The next contiguous counter (2) succeeds against the swapped live slot.
        let (cap2, pay2) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 2, 1, 1, b"generate_transfer");
        let next_env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap2)),
                (Value::Integer(7.into()), Value::Map(pay2)),
            ],
        );
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&next_env)),
            None,
            "counter 2 accepted against the advanced live slot"
        );
        } // end #[cfg(agent-keygen-exec-preview)] GENERATE_KEYS frame section

        reset_agent_keystore_for_tests();
    }

    /// Production (preview OFF): a fully-valid GENERATE_KEYS request verifies the capability then
    /// FAILS CLOSED with NotConfigured (0x45) — no key minting until the safety controls land.
    #[cfg(not(feature = "agent-keygen-exec-preview"))]
    #[test]
    fn generate_keys_gated_off_reaches_not_configured() {
        use ed25519_dalek::SigningKey;
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 2, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::NotConfigured)
        );
    }
}
