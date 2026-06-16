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
use crate::agent_transfer::SignedTransfer;
use crate::agent_capability::VerifiedCapability;
use crate::agent_keygen::{generate_keys, GenerateKeysError, GeneratedKey};
use crate::agent_keystore::{seal_body, CreationMetadata, KeyPurpose, KeystoreBody};
use ciborium::value::Value;
use std::sync::Mutex;

/// Fixed command-domain string bound in the envelope (spec §10.2, key 3).
pub const COMMAND_DOMAIN: &str = "2d-hsm/agent-gateway/v1";

/// Max `request_id` length — a small correlation/audit handle, not a payload. `pub(crate)` so the
/// slice-6 commit-ack decoder caps the echoed `request_id` to the SAME bound (single source, no drift).
pub(crate) const MAX_REQUEST_ID_LEN: usize = 64;

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

    /// **Rollback-sensitive** opcodes (TASK-7.7 AC#5 Layer-2b): those that advance/debit sealed
    /// counters or spend, so they MUST be fail-closed-rejected when the anti-rollback mechanism is not
    /// configured. This is the privileged set {GENERATE_KEYS, CONFIGURE_TREASURY, EXPORT_BACKUP,
    /// RESTORE_BACKUP} PLUS the non-privileged SIGN_FAUCET_DISPENSE (which debits cumulative/lifetime
    /// spend). CONFIGURE_TREASURY is gated whole-opcode — every one of its sub-ops {0 set_limits,
    /// 1 refill_budget, 2 raise_lifetime_breaker, 3 reset_lifetime_breaker} is fund-custody, so no
    /// sub-op decode is needed. Exhaustive match (no wildcard) so a new opcode forces a classification.
    fn is_rollback_sensitive(self) -> bool {
        match self {
            Self::GenerateKeys
            | Self::SignFaucetDispense
            | Self::ConfigureTreasury
            | Self::ExportBackup
            | Self::RestoreBackup => true,
            // SIGN_TRANSFER is intentionally NOT gated — it carries no rollback-sensitive sealed state
            // (no spend/cap/counter; bounded by key-purpose + canonical EIP-155 + sealed chain_id per
            // §5). If TASK-7.6.4 transfer signing ever gains sealed spend/counter state, move it to true.
            Self::SignTransfer => false,
            // Read/attestation opcodes touch no rollback-sensitive state.
            Self::PublicIdentity | Self::ProveIdentity => false,
        }
    }

    /// The per-op COMMIT bump class (TASK-7.7 slice 6): which sealed-state fields a committed
    /// rollback-sensitive op advances at the anchor. SECURITY-LOAD-BEARING. Exhaustive/wildcard-free so a
    /// new opcode forces a classification; pinned consistent with [`Self::is_rollback_sensitive`] by
    /// `commit_bump_class_exhaustive_and_consistent_with_rollback_sensitive`.
    ///
    /// `Structural` mutates anchor-UNRECONSTRUCTABLE state NOT captured in the marks digest, so a dropped
    /// commit-seal reconciles `StructuralGap`→restore on next boot. `EpochOnly`'s full effect IS in the
    /// anchor's authenticated marks (or is re-presentable recovery material), so a dropped seal
    /// adopt-forwards. **UNDER-classifying a structural op as epoch-only is the DANGEROUS direction** (a
    /// dropped seal would silently adopt-forward and LOSE the structural change) — so when in doubt,
    /// `Structural` (fail-closed-safe).
    #[cfg_attr(not(test), allow(dead_code))] // staged slice-6-2; consumed by the 6-4 dispatch wiring
    fn commit_bump_class(self) -> CommitBumpClass {
        match self {
            // STRUCTURAL — mutate state NOT captured in the marks digest: GENERATE_KEYS mints new random
            // key material; CONFIGURE_TREASURY changes faucet CONFIG (limits/breaker — not a marks
            // surface). A dropped seal of either ⇒ StructuralGap⇒restore (design §3). [GENERATE_KEYS is
            // the only LIVE handler; CONFIGURE_TREASURY is deferred — its class is re-confirmed when its
            // handler lands, but Structural is the design-named AND fail-closed-safe value. CAVEAT for the
            // CONFIGURE handler: opcode-level granularity OVER-classifies the `reset_lifetime_breaker`
            // sub-op (marks-only: spend resets + strict_recovery_counter) as Structural — fail-closed-SAFE
            // (a dropped seal fails to restore rather than silently adopting), but the handler will need a
            // sub-op-level classifier (set_limits/refill/raise = Structural; reset = EpochOnly).]
            Self::GenerateKeys | Self::ConfigureTreasury => CommitBumpClass::Structural,
            // EPOCH-ONLY — full effect captured in the anchor's authenticated marks OR re-presentable:
            // SIGN_FAUCET_DISPENSE debits cumulative/lifetime spend (marks surfaces); EXPORT_BACKUP is a
            // freshness-gated read; RESTORE_BACKUP re-seeds from re-presentable recovery material +
            // advances the strict_recovery_counter (a marks surface). [All three handlers are deferred —
            // each class is CONFIRMED at its handler slice; EpochOnly per the current design.
            // CAVEAT for the EXPORT handler: EXPORT is specified to advance the AUDIT-ring backpressure
            // high-water `audit.last_exported_seq`, which is NEITHER a marks surface NOR structural_version
            // — so under EpochOnly a dropped EXPORT seal adopt-forwards and the seeder (which never touches
            // `audit`) silently rolls `last_exported_seq` back, re-enabling overwrite of already-exported
            // reviewable history (an AC#14 audit-completeness weakening, NOT a fund loss). The audit-ring
            // write path is itself a deferred follow-up for ALL privileged ops; before the EXPORT handler
            // lands, RESOLVE this: make `last_exported_seq` anti-rollback-covered, prove its rollback
            // acceptable, or class EXPORT Structural.]
            Self::SignFaucetDispense | Self::ExportBackup | Self::RestoreBackup => CommitBumpClass::EpochOnly,
            // NOT rollback-sensitive — no per-op commit (the commit path is gated on is_rollback_sensitive).
            Self::SignTransfer | Self::PublicIdentity | Self::ProveIdentity => CommitBumpClass::NotCommitted,
        }
    }
}

/// Which sealed-state a per-op anti-rollback COMMIT advances (TASK-7.7 slice 6). See
/// [`AgentOpcode::commit_bump_class`].
#[cfg_attr(not(test), allow(dead_code))] // staged slice-6-2; consumed by the 6-4 dispatch wiring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitBumpClass {
    /// Bump `structural_version` + `freshness_epoch` atomically (anchor-unreconstructable mutation).
    Structural,
    /// Bump `freshness_epoch` only (effect captured in the marks / re-presentable).
    EpochOnly,
    /// Not rollback-sensitive — no per-op commit.
    NotCommitted,
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
    /// SIGN_TRANSFER result: the broadcastable EIP-155 signed transaction + its `(r, s, recovery_id,
    /// v)` and the derived `from`. Non-mutating (NotCommitted) — no sealed-state change, so it does NOT
    /// go through the seal-before-emit seam; the frame layer encodes it directly.
    SignTransfer(SignedTransfer),
    /// GENERATE_KEYS result: the generated public key material PLUS the mutated `candidate` keystore
    /// (counter advanced + new entries + the atomic epoch/structural bump). The frame layer SEALS the
    /// candidate (side-effect-free compute), then COMMITS its post-op state to the anchor (TASK-7.7
    /// slice 6-4, seal-before-emit), then returns the sealed blob for the host to persist and swaps it
    /// into the live slot (enclave-local order clone→seal→commit→swap→emit; the host persists the
    /// returned blob AFTERWARD, §7.2 — seal precedes commit so a deterministic seal failure fails closed
    /// WITHOUT advancing the anchor). `request_id` is the op's
    /// envelope (key-4) request_id, carried here so the frame-layer commit can key the anchor record by
    /// it (idempotency).
    GenerateKeys {
        keys: Vec<GeneratedKey>,
        candidate: Box<KeystoreBody>,
        request_id: Vec<u8>,
    },
    /// SIGN_FAUCET_DISPENSE result: the broadcastable signed dispense transaction PLUS the mutated
    /// `candidate` keystore (faucet dual-counter debit + the atomic EpochOnly epoch bump). Like
    /// GENERATE_KEYS it is MUTATING — the frame layer SEALS the candidate, COMMITS the post-debit state to
    /// the anchor (seal-before-emit), then SWAPS it into the live slot and EMITS the signed tx + sealed
    /// blob; the signature is withheld until the debit is durably committed (§3 unbroadcast-burn).
    /// `request_id` is carried so the frame-layer commit can key the anchor record by it (idempotency).
    SignFaucetDispense {
        signed: SignedTransfer,
        candidate: Box<KeystoreBody>,
        request_id: Vec<u8>,
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

    // TASK-7.7 AC#5 Layer-2b — anti-rollback fund-custody gate. Rollback-sensitive opcodes are
    // rejected fail-closed ("anti-rollback mechanism not configured (TASK-7.7)" → NotConfigured/0x45)
    // when the boot-resolved anti-rollback binding is absent/unconfigured. Placed BEFORE privilege/cap
    // routing so a gated op is rejected REGARDLESS of capability validity — no bypass via a crafted or
    // valid cap, and no cap-state oracle for gated ops on an unconfigured instance. Covers both the
    // privileged ops {1,6,7,8} and the non-privileged SIGN_FAUCET_DISPENSE(5) in one place.
    if opcode.is_rollback_sensitive() && !anti_rollback_satisfied(keystore) {
        return Err(AgentError::NotConfigured);
    }

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
        // SIGN_TRANSFER(4): structured EIP-155 ordinary-transfer signing (TASK-7.6.4 / slice 15-1).
        // PRODUCTION-GATED as a fund-custody-readiness gate (it is NOT rollback-sensitive, so this is
        // NOT an anti-rollback gate): fund-moving signing stays fail-closed until the AC#5 funding
        // profile is provisioned and TASK-18 un-gates. Enabled only via `agent-sign-transfer-preview`;
        // otherwise fail closed.
        AgentOpcode::SignTransfer => {
            #[cfg(feature = "agent-sign-transfer-preview")]
            {
                handle_sign_transfer(&env, keystore)
            }
            #[cfg(not(feature = "agent-sign-transfer-preview"))]
            {
                let _ = &env;
                Err(AgentError::NotConfigured)
            }
        }
        // SIGN_FAUCET_DISPENSE(5): treasury→known-transfer-key native dispense (TASK-15 slice 15-3b). It
        // is ROLLBACK-SENSITIVE (debits sealed faucet counters), so the anti-rollback fund-custody gate
        // above ALREADY fails it closed (NotConfigured) when the boot binding is unconfigured — this arm
        // is reached only past that gate. PRODUCTION-GATED behind `agent-sign-faucet-preview` (fund-custody
        // readiness, on top of the runtime gate); otherwise fail closed. Mirrors the SIGN_TRANSFER arm.
        AgentOpcode::SignFaucetDispense => {
            #[cfg(feature = "agent-sign-faucet-preview")]
            {
                handle_sign_faucet_dispense(&env, keystore)
            }
            #[cfg(not(feature = "agent-sign-faucet-preview"))]
            {
                let _ = &env;
                Err(AgentError::NotConfigured)
            }
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

/// Load the signing `Keypair` for a sealed `KeyEntry`: copy its 32-byte secret scalar into a
/// `Zeroizing` buffer (scrubbed on drop / early return, AC#15 — a plain `[u8; 32]` would linger on the
/// enclave stack) and rebuild the keypair. A wrong-length or invalid scalar collapses to
/// `KeyPurposeMismatch` (0x42, the per-key anti-oracle bucket — never reveal loaded-key detail).
/// Shared by PROVE_IDENTITY and SIGN_TRANSFER (and slice 15-3 SIGN_FAUCET_DISPENSE) so the secret-scrub
/// and error-collapse discipline lives in ONE place. The `len() != 32` guard MUST precede the
/// `copy_from_slice` (which panics on a length mismatch); `secret_scalar` is a `Zeroizing<Vec<u8>>`.
#[cfg(any(
    feature = "agent-prove-identity-preview",
    feature = "agent-sign-transfer-preview",
    feature = "agent-sign-faucet-preview"
))]
fn load_keypair_for(
    entry: &crate::agent_keystore::KeyEntry,
) -> Result<crate::secp256k1::Keypair, AgentError> {
    if entry.secret_scalar.len() != 32 {
        return Err(AgentError::KeyPurposeMismatch);
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&entry.secret_scalar);
    crate::secp256k1::Keypair::from_secret_bytes(&secret).map_err(|_| AgentError::KeyPurposeMismatch)
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
    let keypair = load_keypair_for(entry)?;
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

/// SIGN_TRANSFER(4): structured EIP-155 ordinary-transfer signing for `key_ref` (an `agent_transfer_k1`
/// key only). Decodes the semantic-field payload, runs the §1 pre-build checks (sealed chain_id, `from`
/// == derived address, empty `data`) BEFORE building any preimage, then builds the canonical EIP-155
/// preimage internally (never a caller digest), signs low-S, and returns the broadcastable signed
/// transaction. Non-mutating: no seal, no anti-rollback commit. Gated by `agent-sign-transfer-preview`.
///
/// Capability absence is NOT re-checked here: the caller [`dispatch_agent`] rejects a runtime opcode
/// carrying an envelope capability (`env.capability.is_some()` → `Malformed`) and `decode_envelope`
/// strict-checks the outer keys `1..=7` — so a SIGN_TRANSFER frame with a capability or an unknown
/// outer key never reaches this handler (covered by `rejects_capability_on_runtime_op` /
/// `rejects_extra_outer_envelope_key`).
#[cfg(feature = "agent-sign-transfer-preview")]
fn handle_sign_transfer(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    use crate::agent_cbor::{as_bytes_n, as_u256_minimal_be};
    use crate::agent_transfer::{sign_transfer, EthTransferFields};
    let key_ref = env.key_ref.ok_or(AgentError::Malformed)?;
    // payload (envelope key 7) = strict EXACTLY
    // `{1: chain_id, 2: from(20B), 3: to(20B), 4: amount, 5: nonce, 6: gas_limit, 7: gas_price, 8: data}`.
    let payload = env.payload.as_deref().ok_or(AgentError::Malformed)?;
    if payload.len() != 8 || !check_strict_keys(payload, |n| (1..=8).contains(&n)) {
        return Err(AgentError::Malformed);
    }
    let req_chain_id = map_get(payload, 1).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let req_from = map_get(payload, 2).and_then(as_bytes_n::<20>).ok_or(AgentError::Malformed)?;
    let to = map_get(payload, 3).and_then(as_bytes_n::<20>).ok_or(AgentError::Malformed)?;
    let value_be = map_get(payload, 4).and_then(as_u256_minimal_be).ok_or(AgentError::Malformed)?;
    let nonce = map_get(payload, 5).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let gas_limit = map_get(payload, 6).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let gas_price_be = map_get(payload, 7).and_then(as_u256_minimal_be).ok_or(AgentError::Malformed)?;
    // data MUST be present and empty (MVP — non-empty calldata is a separate, semantically-parsed
    // command; §1). A precomputed-digest / arbitrary-bytes request can only land here as `data`, and a
    // non-empty `data` fails closed → there is no generic-digest signing path.
    let data = map_get(payload, 8).and_then(as_bytes).ok_or(AgentError::Malformed)?;
    if !data.is_empty() {
        return Err(AgentError::Malformed);
    }
    // §1 pre-build check 1: chain_id MUST equal the sealed 2D chain_id (never request-authoritative).
    if req_chain_id != keystore.config.twod_chain_id {
        return Err(AgentError::Malformed);
    }
    // Key-purpose: SIGN_TRANSFER accepts ONLY agent_transfer_k1. not-found ≡ wrong-purpose → 0x42
    // (anti-oracle, §4 / §10.9): an absent key and a faucet/treasury key are indistinguishable.
    let entry = crate::agent_identity::find_entry(keystore, &key_ref)
        .ok_or(AgentError::KeyPurposeMismatch)?;
    if entry.purpose != KeyPurpose::AgentTransferK1 {
        return Err(AgentError::KeyPurposeMismatch);
    }
    let keypair = load_keypair_for(entry)?;
    // §1 pre-build check 2: `from` MUST equal the selected key_ref's derived eth address. Collapse a
    // mismatch into the per-KEY bucket (0x42), NOT Malformed: reaching here means the key exists AND is
    // a transfer key, so a distinct code would be a key-existence/purpose oracle vs the 0x42 returned for
    // not-found / wrong-purpose. Request-SHAPE errors (chain_id, data, widths) stay 0x40; everything
    // key-related is uniformly 0x42 (anti-oracle, §10.9).
    if req_from != keypair.eth_address() {
        return Err(AgentError::KeyPurposeMismatch);
    }
    let fields = EthTransferFields { chain_id: req_chain_id, nonce, gas_limit, to, value_be, gas_price_be };
    // Collapse any signing failure (the ~2^-128 x-reduced recovery_id rejection, or the
    // recovery==from invariant) to the per-key bucket — SIGN_TRANSFER never seals, so NOT SealFailed
    // (0x46). ValueTooWide/ChainIdOverflow are unreachable here (caps pre-validated above).
    let signed = sign_transfer(&keypair, &fields).map_err(|_| AgentError::KeyPurposeMismatch)?;
    Ok(AgentResponse::SignTransfer(signed))
}

/// SIGN_FAUCET_DISPENSE(5): treasury→known-transfer-key native dispense (TASK-7.4 §2 / slice 15-3b). It
/// reuses the SAME machinery as SIGN_TRANSFER — the identical strict 8-field EIP-155 payload, the sealed
/// chain_id, the `from`-equals-derived-address check, and the canonical internal preimage — but with three
/// faucet-tier differences: (1) the signer is the singleton `agent_faucet_treasury_k1` key (not a transfer
/// key); (2) the recipient `to` MUST match an active `agent_transfer_k1` identity in the keystore (§2
/// recipient allowlist — blocks one-command faucet→external spend); and (3) the dispense passes the §2
/// accept-gate (per-field caps + worst-case cumulative budget + optional lifetime breaker) and ATOMICALLY
/// debits BOTH faucet spend counters.
///
/// MUTATING (EpochOnly, rollback-sensitive — the dispatch gate already fail-closed it when anti-rollback
/// is unconfigured): it returns a CANDIDATE body (debited faucet + the atomic epoch bump) for the frame
/// layer's seal-before-emit seam to seal → anchor-commit → swap → emit. The signature is computed here but
/// only EMITTED after the debit is durably committed (§3 unbroadcast-burn — the debit is permanent once a
/// signature leaves, never credited back). Gated by `agent-sign-faucet-preview`.
///
/// Error bands (anti-oracle §10.9), ordered so a less-privileged probe never reaches a higher band:
/// request-SHAPE (bad CBOR, chain_id ≠ sealed, non-empty `data`, over-width/non-minimal u256) → 0x40;
/// everything key/recipient-related (key absent, wrong purpose, `from` ≠ derived, `to` not a known
/// transfer identity, signing failure) → uniform 0x42 (so the host can't probe keystore contents); any §2
/// cap/budget/breaker/overflow rejection → 0x44; a candidate epoch-bump overflow → 0x46. The §2 checks run
/// only AFTER the key+recipient checks pass, so a 0x44 leaks no more than a valid dispense already would.
#[cfg(feature = "agent-sign-faucet-preview")]
fn handle_sign_faucet_dispense(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    use crate::agent_cbor::{as_bytes_n, as_u256_minimal_be};
    use crate::agent_transfer::{sign_transfer, EthTransferFields};
    let key_ref = env.key_ref.ok_or(AgentError::Malformed)?;
    // payload (envelope key 7) = the SAME strict 8-field map as SIGN_TRANSFER — a faucet dispense is a
    // pure native transfer (§2): `{1: chain_id, 2: from(20B), 3: to(20B), 4: amount, 5: nonce,
    // 6: gas_limit, 7: gas_price, 8: data}`.
    let payload = env.payload.as_deref().ok_or(AgentError::Malformed)?;
    if payload.len() != 8 || !check_strict_keys(payload, |n| (1..=8).contains(&n)) {
        return Err(AgentError::Malformed);
    }
    let req_chain_id = map_get(payload, 1).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let req_from = map_get(payload, 2).and_then(as_bytes_n::<20>).ok_or(AgentError::Malformed)?;
    let to = map_get(payload, 3).and_then(as_bytes_n::<20>).ok_or(AgentError::Malformed)?;
    let value_be = map_get(payload, 4).and_then(as_u256_minimal_be).ok_or(AgentError::Malformed)?;
    let nonce = map_get(payload, 5).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let gas_limit = map_get(payload, 6).and_then(as_u64).ok_or(AgentError::Malformed)?;
    let gas_price_be = map_get(payload, 7).and_then(as_u256_minimal_be).ok_or(AgentError::Malformed)?;
    // data MUST be present and empty (native dispenses only — no calldata/memo, §2).
    let data = map_get(payload, 8).and_then(as_bytes).ok_or(AgentError::Malformed)?;
    if !data.is_empty() {
        return Err(AgentError::Malformed);
    }
    // §1 pre-build check: chain_id MUST equal the sealed 2D chain_id (never request-authoritative).
    if req_chain_id != keystore.config.twod_chain_id {
        return Err(AgentError::Malformed);
    }
    // Key-purpose: SIGN_FAUCET_DISPENSE accepts ONLY the singleton agent_faucet_treasury_k1. not-found ≡
    // wrong-purpose → 0x42 (anti-oracle, §4 / §10.9).
    let entry = crate::agent_identity::find_entry(keystore, &key_ref)
        .ok_or(AgentError::KeyPurposeMismatch)?;
    if entry.purpose != KeyPurpose::AgentFaucetTreasuryK1 {
        return Err(AgentError::KeyPurposeMismatch);
    }
    let keypair = load_keypair_for(entry)?;
    // §1 pre-build check: `from` MUST equal the treasury key's derived eth address (per-KEY bucket 0x42).
    if req_from != keypair.eth_address() {
        return Err(AgentError::KeyPurposeMismatch);
    }
    // §2 recipient allowlist (AC#5): `to` MUST match an ACTIVE agent_transfer_k1 identity in the keystore.
    // Recipient-not-found collapses into the same per-key 0x42 bucket (anti-oracle: the host cannot probe
    // which addresses are known transfer keys, and cannot tell it from a missing/mis-purposed treasury
    // key). Each candidate address is derived straight from the entry's stored uncompressed public key —
    // NO secret load, and the tron form is deliberately not computed (only the eth address is compared) to
    // avoid wasted base58 work per scanned entry. All operands are public (host-known), so a plain compare
    // is safe (no secret-dependent timing).
    let recipient_known = keystore.entries.iter().any(|e| {
        e.purpose == KeyPurpose::AgentTransferK1
            && <[u8; 65]>::try_from(e.public_identity.as_slice())
                .ok()
                .and_then(|pk| crate::secp256k1::eth_address_from_uncompressed(&pk).ok())
                .is_some_and(|addr| addr == to)
    });
    if !recipient_known {
        return Err(AgentError::KeyPurposeMismatch);
    }
    // §2 accept-gate + atomic dual-counter debit. Lift the canonical minimal-BE wire `amount`/`gas_price`
    // into the right-aligned `[u8; 32]` arithmetic form (`as_u256_minimal_be` already bounded them to ≤32
    // bytes, so `from_minimal_be` cannot widen-reject — the guard stays as defense-in-depth). The faucet
    // gate caps worst_case = amount + gas_limit*gas_price and debits cumulative_native_spend +
    // lifetime_spend; ANY cap/overflow collapses to 0x44 (anti-oracle: the host can't tell WHICH cap
    // tripped). Runs only AFTER the key+recipient checks, so a 0x44 reveals nothing a valid dispense
    // wouldn't.
    let amount = crate::u256::from_minimal_be(&value_be).ok_or(AgentError::Malformed)?;
    let gas_price = crate::u256::from_minimal_be(&gas_price_be).ok_or(AgentError::Malformed)?;
    let new_faucet = keystore
        .faucet
        .accept_and_debit(&amount, gas_limit, &gas_price)
        .map_err(|_| AgentError::CapExceeded)?;
    // Sign the dispense (pure — the signature bytes do not leave the enclave until the frame layer's
    // seal-before-emit commit succeeds). Collapse a signing failure (the ~2^-128 x-reduced recovery_id
    // rejection / recovery==from invariant) to the per-key bucket (0x42) — NOT SealFailed (0x46 is
    // reserved for the frame layer's seal/anchor-commit failure).
    let fields = EthTransferFields { chain_id: req_chain_id, nonce, gas_limit, to, value_be, gas_price_be };
    let signed = sign_transfer(&keypair, &fields).map_err(|_| AgentError::KeyPurposeMismatch)?;
    // CANDIDATE: clone live → install the debited faucet → advance the EpochOnly commit (freshness_epoch
    // ONLY; the debit changed the marks surfaces cumulative_native_spend/lifetime_spend, which the
    // frame-layer commit's `compute_local_marks_digest` picks up). Derive the bump class from the
    // single-source classifier (EpochOnly — a faucet debit is anchor-reconstructable via AdoptForward)
    // rather than a hardcoded bool; an epoch overflow fails closed (0x46) with no swap.
    let mut candidate = keystore.clone();
    candidate.faucet = new_faucet;
    let bumps_structural =
        matches!(AgentOpcode::SignFaucetDispense.commit_bump_class(), CommitBumpClass::Structural);
    candidate
        .advance_commit_epoch(bumps_structural)
        .map_err(|_| AgentError::SealFailed)?;
    Ok(AgentResponse::SignFaucetDispense {
        signed,
        candidate: Box::new(candidate),
        request_id: env.request_id.clone(),
    })
}

/// Canonical CBOR of the GENERATE_KEYS command params `{1: purpose, 2: count}` (RFC 8949 shortest
/// form) — the exact bytes hashed into `payload_binding`. Shared by the handler and the tests so the
/// two cannot drift on the wire layout. `pub(crate)` so the release-banned `lab-agent-smoke` write-path
/// client (slice 6-7b) builds its cap's `payload_binding` from the SAME preimage the handler verifies.
pub(crate) fn generate_keys_canonical_params(purpose_code: u64, count: u64) -> Vec<u8> {
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
/// candidate for the frame layer to seal → anchor-commit → swap → emit (no live mutation here).
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
    // Anti-rollback ATOMIC bump (TASK-7.7 slice 6-2/6-4 key 5): GENERATE_KEYS is a STRUCTURAL op
    // (`commit_bump_class`), so advance `freshness_epoch` + `structural_version` TOGETHER as one checked
    // unit (overflow on either ⇒ SealFailed, never wrap — a wrapped counter would let a restore
    // masquerade as an adoptable gap). The advanced epoch is the post-op state the frame-layer anchor
    // commit RECORDS and the seal BINDS (seal-before-emit). The epoch advance was LOCAL-ONLY/INERT until
    // 6-4 — it is now LIVE alongside the commit (still only under `agent-keygen-exec-preview`).
    // This handler is GENERATE_KEYS-specific; derive its bump class from the single-source classifier
    // (Structural — key mint is anchor-unreconstructable) rather than a hardcoded bool.
    let bumps_structural =
        matches!(AgentOpcode::GenerateKeys.commit_bump_class(), CommitBumpClass::Structural);
    candidate
        .advance_commit_epoch(bumps_structural)
        .map_err(|_| AgentError::SealFailed)?;
    Ok(AgentResponse::GenerateKeys {
        keys,
        candidate: Box::new(candidate),
        request_id: env.request_id.clone(),
    })
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

// ---------------------------------------------------------------------------------------------------
// TASK-7.7 slice 6-4: the per-op anchor-commit channel + the seal-before-emit commit helper. The commit
// CODE compiles always but only RUNS under `agent-keygen-exec-preview` (the only path that produces a
// GENERATE_KEYS candidate; without the feature GENERATE_KEYS → NotConfigured, so the commit is never
// reached). The boot-time real-channel install is the 6-4b follow-up (`install_commit_channel`).
// ---------------------------------------------------------------------------------------------------

/// Per-op anchor-commit round-trip budget — the serve-time commit's wall-clock bound. A fixed const for
/// now (a budget-threaded/configurable value is a deferred follow-up); the commit fails closed on lapse
/// regardless, so this is a liveness bound, not a correctness param.
const COMMIT_ROUND_TRIP_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Process-global slot holding the boot-installed channel to the host anchor relay, used by the
/// seal-before-emit per-op commit. Installed once at boot AFTER the keystore (so a commit can never run
/// before a verified boot). `Send` so it can live in the static. The PER-OP COMMIT
/// ([`commit_candidate_to_anchor`]) acquires this lock while ALREADY holding `INSTALLED_KEYSTORE` (the
/// serial serve loop's lock), so per-op commits are serialized; `install_commit_channel` /
/// `reset_commit_channel_for_tests` acquire it STANDALONE (NOT under `INSTALLED_KEYSTORE`). No path ever
/// acquires COMMIT_CHANNEL and THEN `INSTALLED_KEYSTORE`, so the only nested order is
/// KEYSTORE→COMMIT_CHANNEL (never reversed → no deadlock).
static INSTALLED_COMMIT_CHANNEL: Mutex<
    Option<Box<dyn crate::agent_boot_relay::BootRelayChannel + Send>>,
> = Mutex::new(None);

/// Install the boot channel to the host anchor relay for per-op commits (agent-profile boot, slice 6-4b).
/// Install-once: returns `false` ONLY when a channel is already installed (boot race / caller mistake).
// Conditionally wired: the only NON-test caller is `agent_gateway_boot::install_serve_time_commit_channel`
// (needs `agent-keygen-exec-preview` + `vsock-transport` + linux); the only test callers are the 6-4a
// `agent-keygen-exec-preview` frame tests. So whether it is "used" depends on `test ∨ (preview ∧ vsock ∧
// linux)` — no single `cfg_attr` expresses that cleanly, and the prior `not(test)` mis-fired in the
// no-preview test build. An unconditional `allow(dead_code)` is the correct shape for this staged-then-
// conditionally-wired fn (harmless no-op wherever it IS used).
#[allow(dead_code)]
#[must_use]
pub(crate) fn install_commit_channel(
    channel: Box<dyn crate::agent_boot_relay::BootRelayChannel + Send>,
) -> bool {
    // Recover a poisoned lock (consistent with `commit_candidate_to_anchor` and the other global-state
    // installers) so a poison from an unrelated panic can't masquerade as a duplicate-install: `false`
    // means EXACTLY "already installed", never "lock was poisoned".
    let mut guard = INSTALLED_COMMIT_CHANNEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(channel);
        true
    } else {
        false
    }
}

#[cfg(test)]
pub(crate) fn reset_commit_channel_for_tests() {
    // Recover a poisoned lock so a poison from one test can't leak into the next (mirrors
    // `reset_anti_rollback_binding_for_tests`).
    *INSTALLED_COMMIT_CHANNEL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// Draw a fresh 32-byte CSPRNG nonce for ONE per-op commit. Anti-replay: a captured ACK cannot replay
/// for a LATER op, which draws a DIFFERENT nonce. `getrandom` failure ⇒ fail closed.
fn draw_commit_nonce() -> Result<[u8; 32], AgentError> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| AgentError::SealFailed)?;
    Ok(nonce)
}

/// TASK-7.7 slice 6-4 SEAL-BEFORE-EMIT: durably COMMIT the candidate's post-op state to the anchor
/// AFTER the frame layer has computed the sealed blob but BEFORE it swaps/emits. (The seal is a
/// side-effect-free computation, so the caller computes it FIRST — a deterministic seal failure then
/// fails closed without ever reaching this commit; see [`handle_agent_gateway_frame`].) Draws a fresh
/// per-op nonce, builds the [`crate::agent_boot_relay::AnchorCommit`] from the candidate's advanced
/// `(freshness_epoch, structural_version)` + post-op marks digest + the op's `request_id`, and runs the
/// round-trip + ack-verify. `Ok(())` is the GO signal (the anchor durably recorded EXACTLY the proposed
/// state); ANY failure — no channel installed, transport, ack mismatch, getrandom — ⇒ `Err(SealFailed)`,
/// and the caller MUST NOT swap / emit and MUST discard the already-computed sealed blob (no offline
/// window). The coarse fail-closed `SealFailed` keeps the anti-oracle surface minimal. Called under the
/// `INSTALLED_KEYSTORE` lock, so the commit-channel round-trip is serialized.
fn commit_candidate_to_anchor(candidate: &KeystoreBody, request_id: &[u8]) -> Result<(), AgentError> {
    let nonce = draw_commit_nonce()?;
    let commit = crate::agent_boot_relay::AnchorCommit {
        new_epoch: candidate.freshness_epoch,
        new_structural_version: candidate.structural_version,
        marks_digest: candidate.compute_local_marks_digest(),
        nonce,
        request_id,
    };
    let mut guard = INSTALLED_COMMIT_CHANNEL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let channel = guard.as_mut().ok_or(AgentError::SealFailed)?; // no channel installed ⇒ fail closed
    crate::agent_boot_relay::run_anchor_commit(
        &mut **channel,
        &commit,
        &candidate.config,
        std::time::Instant::now() + COMMIT_ROUND_TRIP_BUDGET,
    )
    .map_err(|_| AgentError::SealFailed)
}

/// The boot-resolved anti-rollback binding (TASK-7.7 AC#5). Opaque presence marker — the funding gate
/// only needs to know a successful anchor handshake + reconcile happened this (re)start, not the full
/// (v1-PROVISIONAL) `ReconcileDecision`. Installed by `agent_boot::boot_reconcile_anti_rollback` **only
/// on the `Fresh` arm** — NEVER directly on `AdoptForward` (that path must first seed the body from the
/// anchor's authenticated marks + re-seal forward, then re-run the full ceremony so the now-current
/// state reconciles `Fresh`). Do not install this from any other site: a binding installed on a stale
/// (un-re-sealed) `AdoptForward` body would unblock fund custody on rolled-back counters/spend.
#[derive(Debug, Clone, Copy)]
pub struct AntiRollbackBinding {
    /// The reconciled freshness epoch the instance is operating under (for observability/audit).
    pub epoch: u64,
    /// **Load-bearing:** the funding gate treats a binding with `active == false` as unconfigured
    /// (fail-closed) — not mere observability. Currently this means "a `Fresh` reconcile occurred this
    /// boot" (`boot_reconcile_anti_rollback` sets it `true` only on the `Fresh` arm); there is no
    /// anchor-reported per-instance liveness field in `AnchorState` yet (design §3 Option A has no clone
    /// fencing), so `active` is NOT yet a true liveness/fencing signal — a future Option-B upgrade that
    /// fences concurrent attestations would supply that and could set this `false`.
    pub active: bool,
}

/// Process-global anti-rollback binding. Const-init `None` ⇒ **fail-closed by default**: a real boot
/// where boot-wiring hasn't run, or a handshake that FAILED, leaves this `None` and the funding gate
/// rejects rollback-sensitive ops. Volatile — lost on restart, so a restart MUST re-run the handshake
/// (never trust a persisted "configured" flag, §3 threat model).
static ANTI_ROLLBACK_BINDING: Mutex<Option<AntiRollbackBinding>> = Mutex::new(None);

/// Install the boot-resolved anti-rollback binding (boot-wiring slice only, AFTER a successful
/// `reconcile`). **Install-once**: returns `false` without overwriting if one is already installed.
/// Like `install_agent_keystore`, production fail-closed rests on this being CALLED only post-reconcile
/// — it is not a host-settable input.
#[must_use]
pub fn install_anti_rollback_binding(binding: AntiRollbackBinding) -> bool {
    // Refuse to install an inactive binding: a binding is only ever installed after a SUCCESSFUL
    // reconcile (⇒ active), so `!active` is a caller bug — reject it rather than store a marker the
    // gate would treat as unconfigured anyway (defense-in-depth on top of the `active` gate check).
    if !binding.active {
        return false;
    }
    let mut guard = ANTI_ROLLBACK_BINDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_some() {
        return false;
    }
    *guard = Some(binding);
    true
}

/// Whether a boot-resolved anti-rollback binding is installed AND `active` (poison-recovers). Checks
/// `active` (not just presence) so a non-`active` binding fails closed rather than passing the gate.
/// Today `active` means "a `Fresh` reconcile occurred this boot" (set `true` only on the `Fresh` arm of
/// `boot_reconcile_anti_rollback`); a future Option-B clone-fencing upgrade is what would supply true
/// anchor-reported liveness and could set it `false` (see [`AntiRollbackBinding::active`]).
pub(crate) fn is_anti_rollback_configured() -> bool {
    ANTI_ROLLBACK_BINDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|b| b.active)
}

#[cfg(test)]
pub fn reset_anti_rollback_binding_for_tests() {
    *ANTI_ROLLBACK_BINDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// Test-only: the SINGLE guard serializing EVERY test across the crate that touches an agent
/// process-global. Private — all callers go through [`lock_and_reset_agent_process_globals`] so the
/// "lock + reset the FULL set of agent globals" invariant lives in exactly one place.
#[cfg(test)]
static AGENT_PROCESS_GLOBAL_TEST_GUARD: Mutex<()> = Mutex::new(());

/// Test-only: lock the crate-wide agent-process-global guard AND reset EVERY agent process-global to
/// its pristine state, returning the held guard (hold it for the whole test body). The crate's tests
/// run in one binary in parallel and `crate::agent_boot` drives BOTH `ANTI_ROLLBACK_BINDING` (this
/// module) and `OUTSTANDING_CHALLENGE` (`crate::agent_challenge`); the original per-module guards each
/// reset only "their" global, so once tests across modules shared one guard, stale state could leak
/// (a dispatch test inheriting a challenge a prior boot test left, etc.). This is the ONE place that
/// knows the full set: every global-touching test — here, in `agent_challenge`, and in `agent_boot` —
/// serializes + resets via this helper, and a NEW agent process-global adds its reset HERE so all
/// three modules stay symmetric by construction rather than by convention.
#[cfg(test)]
pub(crate) fn lock_and_reset_agent_process_globals() -> std::sync::MutexGuard<'static, ()> {
    let g = AGENT_PROCESS_GLOBAL_TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    // The FULL set: the installed keystore slot too (frame-path tests install into it), not just the
    // anti-rollback binding + freshness challenge — so the helper's "pristine state" claim actually holds
    // and no test inherits a keystore a prior frame test left installed.
    reset_agent_keystore_for_tests();
    reset_anti_rollback_binding_for_tests();
    reset_commit_channel_for_tests(); // slice 6-4: frame-path tests install a mock commit channel
    crate::agent_challenge::reset_outstanding_challenge_for_tests();
    // The quote-producer process-ledger claim ((d-ii)/2) — triple-gated like its module (the enclosing
    // module is already agent-gateway-gated; the inner cfg completes the gate so non-linux / non-vsock
    // agent-gateway test builds compile clean).
    #[cfg(all(target_os = "linux", feature = "vsock-transport"))]
    crate::quote_subprocess::reset_process_quote_ledger_claim_for_tests();
    g
}

/// AC#5 gate predicate: a rollback-sensitive op may proceed iff the anti-rollback mechanism is
/// configured for this boot OR the measured/sealed AC#10 opt-out is acknowledged in the sealed config.
fn anti_rollback_satisfied(keystore: &KeystoreBody) -> bool {
    is_anti_rollback_configured() || sealed_optout_acknowledged(keystore)
}

/// The measured/sealed AC#10 residual-risk opt-out (§5). **DEFERRED** to its own sub-slice: it needs a
/// sealed `KeystoreConfig` field carrying the verbatim TASK-7.2 AC#10 text + an operator (admin/
/// recovery) Ed25519 signature, verified against the canonical text — a sealed-format change. Until
/// then the gate hard-blocks when unconfigured (the design's safe default). **Contract for that slice:**
/// this MUST read ONLY the sealed body and verify the operator signature + canonical text — never a
/// host-supplied runtime input.
fn sealed_optout_acknowledged(_keystore: &KeystoreBody) -> bool {
    false
}

/// TASK-7.7 slice 6-7 shared SEAL-BEFORE-EMIT seam: the ONE audited seal → anchor-commit → swap → emit
/// ordering over a mutated CANDIDATE body, so every mutating opcode goes through it instead of
/// copy-pasting the order (GENERATE_KEYS today; the deferred CONFIGURE_TREASURY / EXPORT_BACKUP /
/// RESTORE_BACKUP handlers reuse it when they land). `encode_response` is the ONLY per-opcode part — it
/// builds the success body from the sealed blob and is called ONLY AFTER the commit succeeds, so nothing
/// op-specific is emitted before the anchor durably records the advance.
///
/// Order: SEAL (compute) → COMMIT (durable anchor advance) → SWAP → EMIT. The seal is computed FIRST
/// because it is SIDE-EFFECT-FREE — it validates + CBOR-encodes + AEADs into a local buffer, persisting
/// and emitting NOTHING. Doing it before the commit makes any DETERMINISTIC seal failure (`BlobTooLarge`
/// for an over-cap batch, or a `validate()` reject) fail closed (0x46) with NO anchor commit, so the
/// anchor can never advance to a structural state that was never sealed (which would force a spurious
/// next-boot StructuralGap→restore). The COMMIT still strictly precedes the SWAP/EMIT, so the anchor
/// never lags the emitted state — the anti-rollback invariant (anchor ≥ any sealed/emitted state) holds.
/// ANY commit failure (no channel, transport, ack mismatch) ⇒ fail closed: live state UNTOUCHED, NO swap,
/// NO signature/refs emitted (no offline window). Called UNDER the `INSTALLED_KEYSTORE` guard (serial) —
/// the two-lock order is KEYSTORE→COMMIT_CHANNEL. A crash AFTER the ack but BEFORE the swap leaves the
/// anchor ahead → next-boot reconcile StructuralGap→restore (the structural-op case), recoverable, never
/// a silent loss. INVARIANT: `candidate` is read by BOTH `seal_body` and `commit_candidate_to_anchor`;
/// the committed `{epoch, structural, marks}` MUST equal the sealed body's, so it is NOT mutated between
/// them here (and a future caller MUST pass a candidate already finalized).
fn commit_before_emit<F: FnOnce(&[u8]) -> Vec<u8>>(
    candidate: Box<KeystoreBody>,
    request_id: &[u8],
    measurement: Vec<u8>,
    guard: &mut Option<InstalledAgentKeystore>,
    encode_response: F,
) -> Vec<u8> {
    let sealed = match crate::seal_root::resolve_provisioning_root() {
        Ok(root) => match seal_body(&candidate, &root, &measurement) {
            Ok(blob) => blob,
            Err(_) => return encode_agent_error(AgentError::SealFailed),
        },
        Err(_) => return encode_agent_error(AgentError::SealFailed),
    };
    if let Err(e) = commit_candidate_to_anchor(&candidate, request_id) {
        return encode_agent_error(e);
    }
    let body = encode_response(&sealed);
    // Swap the live in-memory slot so subsequent commands see the advanced state; durability is the
    // host's job (it persists the sealed blob returned in `body`).
    *guard = Some(InstalledAgentKeystore { body: *candidate, measurement });
    body
}

/// Frame-layer entry point: dispatch a `0x40` inner-envelope `payload` against the installed
/// keystore and return the encoded response BODY — a per-opcode success map or a §10.9 error map.
/// Always returns a body (never errors out of band), so the wire layer just frames it. Profile is
/// derived from slot presence: no installed keystore ⇒ not an agent instance ⇒ `WrongProfile`.
///
/// For a mutating opcode (GENERATE_KEYS) dispatch returns a CANDIDATE body; this layer runs the
/// seal-before-emit order **seal → anchor-commit → swap → emit**: it **seals** the candidate
/// (provisioning root from [`crate::seal_root`] + the stored measurement, side-effect-free), **commits**
/// the candidate's advanced state to the anchor, **swaps** it into the live slot, and returns the sealed
/// blob in the response for the host to persist. ANY seal OR commit failure ⇒ `0x46` with the live state
/// untouched (no swap/emit) — the seal-failure path short-circuits before the commit, so a deterministic
/// seal failure never advances the anchor.
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
        Ok(AgentResponse::GenerateKeys { keys, candidate, request_id }) => {
            // GENERATE_KEYS (the only LIVE mutating opcode, agent-keygen-exec-preview) goes through the
            // shared seal-before-emit seam. The only op-specific part is the success-body encoder
            // (key list + the sealed blob), invoked by the seam ONLY after the anchor commit succeeds.
            commit_before_emit(candidate, &request_id, measurement, &mut guard, |sealed| {
                encode_generate_keys_response(&keys, sealed)
            })
        }
        Ok(AgentResponse::SignFaucetDispense { signed, candidate, request_id }) => {
            // SIGN_FAUCET_DISPENSE (rollback-sensitive, EpochOnly) goes through the SAME shared
            // seal-before-emit seam as GENERATE_KEYS — the only op-specific part is the success-body
            // encoder (the signed dispense tx + the sealed blob), invoked by the seam ONLY after the anchor
            // commit succeeds, so the signature never leaves before the debit is durably recorded.
            commit_before_emit(candidate, &request_id, measurement, &mut guard, |sealed| {
                encode_sign_faucet_dispense_response(&signed, sealed)
            })
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
        // SIGN_TRANSFER response (TASK-7.6.4 — the spec left the response map open): the broadcastable
        // signed transaction + its components. Key 1 = `signed_rlp` (BYTES), so a success body is
        // distinguishable from a `{1: code(int)}` error body (cf. `decode_agent_error_code`).
        AgentResponse::SignTransfer(t) => encode_body(vec![
            (Value::Integer(1.into()), Value::Bytes(t.signed_rlp.clone())),
            (Value::Integer(2.into()), Value::Bytes(t.signature.r.to_vec())),
            (Value::Integer(3.into()), Value::Bytes(t.signature.s.to_vec())),
            (Value::Integer(4.into()), Value::Integer((t.signature.recovery_id as u64).into())),
            (Value::Integer(5.into()), Value::Integer(t.v.into())),
            (Value::Integer(6.into()), Value::Bytes(t.signing_hash.to_vec())),
            (Value::Integer(7.into()), Value::Bytes(t.from.to_vec())),
        ]),
        // GENERATE_KEYS MUST be encoded by the frame layer WITH its sealed blob
        // (`encode_generate_keys_response`). Reaching the generic encoder means a mis-routed mutation;
        // fail closed to an error body rather than fabricate a persist-less success the host can't
        // store. (No panic/`debug_assert` here — this runs under the INSTALLED_KEYSTORE lock.)
        AgentResponse::GenerateKeys { .. } => encode_agent_error(AgentError::SealFailed),
        // SIGN_FAUCET_DISPENSE is likewise frame-layer-only (`encode_sign_faucet_dispense_response` needs
        // the sealed blob). Reaching the generic encoder is a mis-routed mutation ⇒ fail closed, same as
        // GENERATE_KEYS — never emit a signed dispense whose debit was not sealed/committed.
        AgentResponse::SignFaucetDispense { .. } => encode_agent_error(AgentError::SealFailed),
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

/// Encode the SIGN_FAUCET_DISPENSE response: the signed-tx 7-key map (BYTE-FOR-BYTE the SIGN_TRANSFER
/// layout — `{1: signed_rlp, 2: r, 3: s, 4: recovery_id, 5: v, 6: signing_hash, 7: from}`) PLUS key 8 =
/// the new sealed keystore blob the host MUST persist (the debited faucet state; mirrors GENERATE_KEYS
/// key 2 — the enclave has no durable storage). Key 1 is BYTES so a success body is distinguishable from a
/// `{1: code(int)}` error body (cf. `decode_agent_error_code`). Called by the frame layer ONLY after the
/// anchor commit succeeds, so the signature is emitted iff the debit is durably recorded.
fn encode_sign_faucet_dispense_response(signed: &SignedTransfer, sealed_blob: &[u8]) -> Vec<u8> {
    encode_body(vec![
        (Value::Integer(1.into()), Value::Bytes(signed.signed_rlp.clone())),
        (Value::Integer(2.into()), Value::Bytes(signed.signature.r.to_vec())),
        (Value::Integer(3.into()), Value::Bytes(signed.signature.s.to_vec())),
        (Value::Integer(4.into()), Value::Integer((signed.signature.recovery_id as u64).into())),
        (Value::Integer(5.into()), Value::Integer(signed.v.into())),
        (Value::Integer(6.into()), Value::Bytes(signed.signing_hash.to_vec())),
        (Value::Integer(7.into()), Value::Bytes(signed.from.to_vec())),
        (Value::Integer(8.into()), Value::Bytes(sealed_blob.to_vec())),
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
    // KeyEntry construction is shared by the keygen-exec and sign-transfer preview test blocks; the
    // `any(..)` gate avoids a duplicate import when both previews are enabled.
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-sign-transfer-preview",
        feature = "agent-sign-faucet-preview"
    ))]
    use crate::agent_keystore::{BackupExportMetadata, KeyAlgorithm, KeyEntry};
    #[cfg(feature = "agent-keygen-exec-preview")]
    use crate::agent_keystore::MAX_TOTAL_KEY_ENTRIES;

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
                cumulative_signing_budget: [0; 32],
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

    /// Lock the crate-wide agent-process-global guard (via `lock_and_reset_agent_process_globals`,
    /// which resets ALL agent globals) and hold it for the test body. The SAME guard serializes the
    /// `agent_challenge` and `agent_boot` tests, so this is NOT scoped to this module's binding global —
    /// do not reintroduce a module-local mutex. `gate_configured` then installs a test binding so the
    /// gated op proceeds to its real outcome; `gate_unconfigured` leaves the slot `None` so the gate
    /// fires. Read-only opcodes short-circuit the gate and need no guard.
    fn gate_configured() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        let _ = install_anti_rollback_binding(AntiRollbackBinding { epoch: 1, active: true });
        g
    }
    fn gate_unconfigured() -> std::sync::MutexGuard<'static, ()> {
        crate::agent_dispatch::lock_and_reset_agent_process_globals()
    }

    /// The lab anchor signing key the seal-before-emit tests use — a body whose `config.anchor_root` is
    /// this key's verifying key accepts an ACK this key signs.
    fn anchor_test_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32])
    }

    /// A scripted process-global commit channel for the 6-4 seal-before-emit tests: decode the 0x45
    /// request and answer per the action — a conformant anchor (signs the proposed state with
    /// `anchor_test_key`), a transport failure, or a forged signer (wrong key → ack fails verify).
    #[cfg(any(feature = "agent-keygen-exec-preview", feature = "agent-sign-faucet-preview"))]
    enum CommitChannelAct {
        Ok,
        Transport,
        WrongKey,
    }
    #[cfg(any(feature = "agent-keygen-exec-preview", feature = "agent-sign-faucet-preview"))]
    struct TestCommitChannel {
        act: CommitChannelAct,
        /// Bumped at the TOP of every `round_trip`, so a test can assert the commit was reached
        /// (`> 0`) or — for the seal-before-commit ordering proof — NEVER reached (`== 0`). Defaults
        /// to a throwaway counter the test ignores via [`TestCommitChannel::new`].
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    #[cfg(any(feature = "agent-keygen-exec-preview", feature = "agent-sign-faucet-preview"))]
    impl TestCommitChannel {
        fn new(act: CommitChannelAct) -> Self {
            Self { act, calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)) }
        }
        /// Share a caller-held counter so the test can read how many commits were attempted. Only the
        /// keygen-exec frame tests use the counted form (the over-size-candidate never-commit proof); the
        /// faucet-preview lane reuses `TestCommitChannel` via `new` only, so allow it dead there.
        #[cfg_attr(not(feature = "agent-keygen-exec-preview"), allow(dead_code))]
        fn counted(act: CommitChannelAct, calls: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
            Self { act, calls }
        }
    }
    #[cfg(any(feature = "agent-keygen-exec-preview", feature = "agent-sign-faucet-preview"))]
    impl crate::agent_boot_relay::BootRelayChannel for TestCommitChannel {
        fn round_trip(
            &mut self,
            frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let d = crate::agent_boot_relay::decode_anchor_commit_request(frame)
                .expect("a frame-layer commit must encode a decodable 0x45 request");
            let key = match self.act {
                CommitChannelAct::Transport => {
                    return Err(crate::agent_boot_driver::AnchorTransportError(
                        "test commit transport down",
                    ))
                }
                CommitChannelAct::Ok => anchor_test_key(),
                CommitChannelAct::WrongKey => ed25519_dalek::SigningKey::from_bytes(&[0x09; 32]),
            };
            Ok(crate::agent_anchor::test_signed_commit_ack_bytes(
                &key,
                d.chain_id,
                &d.environment_identifier,
                d.new_epoch,
                d.new_structural_version,
                d.marks_digest,
                d.nonce,
                d.request_id,
            ))
        }
        fn marks_round_trip(
            &mut self,
            _frame: &[u8],
            _deadline: std::time::Instant,
        ) -> Result<Vec<u8>, crate::agent_boot_driver::AnchorTransportError> {
            unreachable!("commit tests never call marks_round_trip")
        }
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
        let _g = gate_configured();
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
        let _g = gate_configured();
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
        let _g = gate_configured(); // op 7 is rollback-sensitive — serialize + bind (Malformed wins at decode)
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
        let _g = gate_configured();
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
            AgentResponse::GenerateKeys { keys, candidate, .. } => {
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
    fn generate_keys_atomically_advances_epoch_and_structural_per_op() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
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
                assert_eq!(candidate.structural_version, 2, "structural +1 per committed op");
                // 6-4: GENERATE_KEYS is Structural, so the ATOMIC bump advances freshness_epoch TOGETHER
                // with structural_version (was LOCAL-ONLY/INERT before 6-4). The anchor commit records this
                // advanced epoch and the seal binds it (the frame-layer seal-before-emit path).
                assert_eq!(candidate.freshness_epoch, body.freshness_epoch + 1, "epoch advances atomically");
                // strict_recovery_counter is a marks surface, NOT bumped by a structural op.
                assert_eq!(candidate.strict_recovery_counter, body.strict_recovery_counter);
            }
            _ => panic!("expected GenerateKeys"),
        }
    }

    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_structural_overflow_fails_closed() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
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
        let _g = gate_configured();
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
        let _g = gate_configured();
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
        let _g = gate_configured();
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
            AgentResponse::GenerateKeys { keys, candidate, .. } => {
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
        let _g = gate_configured();
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

    /// slice 6-5 VALIDATION PIN: the per-op commit reuses `env.request_id` VERBATIM as the anchor's
    /// `request_id` idempotency key (the LOGICAL-op identity — keyed ALONE, NOT `(request_id, epoch)`)
    /// with NO length check of its own — its SOLE guard is this
    /// envelope (key-4) decode bound, `MAX_REQUEST_ID_LEN`=64. Pin that dependency: a 65-byte request_id
    /// is rejected `Malformed` at decode (so it never reaches the commit); a 64-byte and an EMPTY (len 0)
    /// request_id decode fine (the op proceeds to its own outcome, not `Malformed`). An empty id is
    /// admin-signed-capability-bound (the key-10 echo + payload_binding), NOT a host-substitute attack —
    /// so the weakest legal id still requires admin authorship, never a host forgery.
    #[test]
    fn envelope_request_id_decode_bound_pins_the_anchor_idempotency_key() {
        let body = base_body();
        // A PUBLIC_IDENTITY (opcode 2) read envelope with a custom key-4 request_id and an unknown
        // key_ref — drives the decode without needing a signed capability.
        let read_env = |rid: Vec<u8>| {
            enc(Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer((AGENT_GATEWAY_VERSION as u64).into())),
                (Value::Integer(2.into()), Value::Integer(2u64.into())),
                (Value::Integer(3.into()), Value::Text(COMMAND_DOMAIN.to_string())),
                (Value::Integer(4.into()), Value::Bytes(rid)),
                (Value::Integer(6.into()), Value::Bytes(vec![0xfe; 32])),
            ]))
        };
        // 65 bytes ⇒ Malformed (the >64 reject the anchor keying depends on — never reaches the commit).
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &read_env(vec![0x41; MAX_REQUEST_ID_LEN + 1]), &body)
                .err(),
            Some(AgentError::Malformed),
            "a request_id over MAX_REQUEST_ID_LEN must fail closed at decode"
        );
        // 64-byte (boundary) and EMPTY both decode fine: the op proceeds to its own outcome (an unknown
        // key_ref ⇒ NOT Malformed). Confirms the bound admits exactly [0, 64], incl the empty id.
        for rid in [vec![0x41; MAX_REQUEST_ID_LEN], Vec::new()] {
            assert_ne!(
                dispatch_agent(Profile::AgentGateway, &read_env(rid.clone()), &body).err(),
                Some(AgentError::Malformed),
                "a request_id of len {} must decode (admin-cap-bound; not a Malformed reject)",
                rid.len()
            );
        }
    }

    #[test]
    fn generate_keys_request_id_mismatch_rejected() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
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
        let _g = gate_configured();
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
        let _g = gate_configured();
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
        let _g = gate_unconfigured(); // op 5 is rollback-sensitive — serialize the binding global
        let (body, _) = body_with_key();
        // SIGN_FAUCET_DISPENSE(5) is rollback-sensitive: the anti-rollback gate fail-closes it
        // (NotConfigured) when unconfigured — independent of any preview feature (until slice 15-3).
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &envelope(5, vec![]), &body).err(),
            Some(AgentError::NotConfigured)
        );
        // SIGN_TRANSFER(4): production fail-closed (NotConfigured) WITHOUT the preview feature; WITH it
        // the opcode is LIVE, so an empty payload reaches the handler and is rejected as Malformed (not
        // NotConfigured) — that distinction is exactly what proves the production gate opened.
        let err4 = dispatch_agent(Profile::AgentGateway, &envelope(4, vec![]), &body).err();
        #[cfg(not(feature = "agent-sign-transfer-preview"))]
        assert_eq!(err4, Some(AgentError::NotConfigured));
        #[cfg(feature = "agent-sign-transfer-preview")]
        assert_eq!(err4, Some(AgentError::Malformed));
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
        let _g = gate_configured(); // serialize + install the AC#5 binding (the frame drives a gated op)
        reset_agent_keystore_for_tests();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // 6-4: GENERATE_KEYS through the frame now COMMITS to the anchor (after computing the seal,
        // before swap/emit), so the body's anchor_root must be the key the test commit channel signs
        // with (PUBLIC_IDENTITY ignores it).
        body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
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
        // 6-4 seal-before-emit: install a conformant commit channel so the per-op anchor commit succeeds
        // and the frame proceeds to seal + swap.
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::Ok))));
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

    /// 6-4 SEAL-BEFORE-EMIT fail-closed: a per-op commit failure (no channel / transport / forged ACK)
    /// MUST fail the op closed (0x46) with NO seal and NO swap — the live slot is untouched, so the SAME
    /// cap is still accepted once a conformant channel is installed (the failed ops never advanced the
    /// counter). This is the load-bearing anti-rollback property: a signature/refs are emitted ONLY after
    /// the anchor durably recorded the advance.
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_commit_failure_fails_closed_no_swap() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
        assert!(install_agent_keystore(body, b"meas"));
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 2, b"generate_transfer");
        let gen_env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        // (a) NO commit channel installed → fail closed 0x46 (no offline window).
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            Some(0x46),
            "no commit channel ⇒ SealFailed"
        );
        // (b) a TRANSPORT failure on the commit → fail closed 0x46.
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::Transport))));
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            Some(0x46),
            "commit transport failure ⇒ SealFailed"
        );
        reset_commit_channel_for_tests();
        // (c) a FORGED ACK (wrong signer) → fail closed 0x46 (the durable record didn't verify).
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::WrongKey))));
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            Some(0x46),
            "forged commit ack ⇒ SealFailed"
        );
        reset_commit_channel_for_tests();
        // (d) PROOF OF NO SWAP across all three failures: the live counter never advanced, so the SAME cap
        //     (counter 1) is STILL accepted once a conformant channel is installed. If any failed op had
        //     swapped, the live counter would be 1 and this cap (contiguity expects 2) would be 0x43.
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::Ok))));
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            None,
            "the failed commits did NOT swap — the same cap now succeeds"
        );
        reset_agent_keystore_for_tests();
    }

    /// 6-4 SEAL-BEFORE-COMMIT ordering proof: a candidate that fails to SEAL deterministically
    /// (`BlobTooLarge` — an over-cap keygen batch, the exact host-triggerable case from the matrix
    /// review) MUST fail closed (0x46) WITHOUT ever reaching the anchor commit. The seal is computed
    /// before the commit, so the durable anchor is never advanced to a structural state that can never
    /// be sealed (which would otherwise force a spurious next-boot StructuralGap→restore). We pin the
    /// "no commit" half with a shared call-counter on the installed channel: it must be 0.
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_unsealable_candidate_never_commits() {
        use ed25519_dalek::SigningKey;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
        // Pre-load the live body to ONE under the count cap with unique, validate()-passing entries
        // (65-byte 0x04 pubkey, 32-byte scalar). Generating 1 key tips the candidate to exactly
        // MAX_TOTAL_KEY_ENTRIES — within the COUNT cap but past the SIZE cap, so `seal_body` rejects
        // it as `BlobTooLarge` (see agent_keystore::tests::oversized_blob_rejected).
        body.entries = (0..(MAX_TOTAL_KEY_ENTRIES - 1) as u64)
            .map(|i| {
                let mut key_ref = [0u8; 32];
                key_ref[..8].copy_from_slice(&i.to_le_bytes());
                KeyEntry {
                    key_ref,
                    purpose: KeyPurpose::AgentTransferK1,
                    algorithm: KeyAlgorithm::Secp256k1,
                    public_identity: {
                        let mut p = vec![0x04u8; 65];
                        p[1] = 0xcc;
                        p
                    },
                    secret_scalar: zeroize::Zeroizing::new(vec![0x11u8; 32]),
                    creation_metadata: CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 },
                    backup_export_metadata: BackupExportMetadata::default(),
                }
            })
            .collect();
        assert!(install_agent_keystore(body, b"meas"));
        // A CONFORMANT channel (would ACK happily) instrumented with a shared call-counter.
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(install_commit_channel(Box::new(TestCommitChannel::counted(
            CommitChannelAct::Ok,
            Arc::clone(&calls),
        ))));
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 1, b"generate_transfer");
        let gen_env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            Some(0x46),
            "an unsealable (over-size) candidate fails closed with SealFailed"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the anchor commit was NEVER reached — seal failure short-circuits before the durable commit"
        );
        reset_agent_keystore_for_tests();
    }

    /// Production (preview OFF): a fully-valid GENERATE_KEYS request verifies the capability then
    /// FAILS CLOSED with NotConfigured (0x45) — no key minting until the safety controls land.
    #[cfg(not(feature = "agent-keygen-exec-preview"))]
    #[test]
    fn generate_keys_gated_off_reaches_not_configured() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
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

    // ---- TASK-7.7 AC#5 Layer-2b funding-gate tests ----

    #[test]
    fn is_rollback_sensitive_exhaustive_classification() {
        for (op, expected) in [
            (AgentOpcode::GenerateKeys, true),
            (AgentOpcode::PublicIdentity, false),
            (AgentOpcode::ProveIdentity, false),
            (AgentOpcode::SignTransfer, false),
            (AgentOpcode::SignFaucetDispense, true),
            (AgentOpcode::ConfigureTreasury, true),
            (AgentOpcode::ExportBackup, true),
            (AgentOpcode::RestoreBackup, true),
        ] {
            assert_eq!(op.is_rollback_sensitive(), expected);
        }
    }

    #[test]
    fn commit_bump_class_exhaustive_and_consistent_with_rollback_sensitive() {
        for (op, expected) in [
            (AgentOpcode::GenerateKeys, CommitBumpClass::Structural),
            (AgentOpcode::ConfigureTreasury, CommitBumpClass::Structural),
            (AgentOpcode::SignFaucetDispense, CommitBumpClass::EpochOnly),
            (AgentOpcode::ExportBackup, CommitBumpClass::EpochOnly),
            (AgentOpcode::RestoreBackup, CommitBumpClass::EpochOnly),
            (AgentOpcode::SignTransfer, CommitBumpClass::NotCommitted),
            (AgentOpcode::PublicIdentity, CommitBumpClass::NotCommitted),
            (AgentOpcode::ProveIdentity, CommitBumpClass::NotCommitted),
        ] {
            assert_eq!(op.commit_bump_class(), expected, "{op:?}");
            // CONSISTENCY: an op is committed (Structural|EpochOnly) IFF it is rollback-sensitive — the
            // commit path is gated on is_rollback_sensitive, so a NotCommitted op must never commit and
            // every rollback-sensitive op must carry a bump class.
            let committed = op.commit_bump_class() != CommitBumpClass::NotCommitted;
            assert_eq!(committed, op.is_rollback_sensitive(), "{op:?}: committed-ness must match is_rollback_sensitive");
        }
    }

    #[test]
    fn configure_treasury_whole_opcode_gated() {
        // All CONFIGURE_TREASURY sub-ops {0..=3} are fund-custody, so the whole opcode is gated with no
        // sub-op decode needed.
        assert!(AgentOpcode::ConfigureTreasury.is_rollback_sensitive());
    }

    #[test]
    fn optout_stub_is_off() {
        // The AC#10 measured/sealed opt-out is DEFERRED; the stub MUST stay `false` so the gate
        // hard-blocks when unconfigured (the safe default). A premature `true` would open the gate.
        assert!(!sealed_optout_acknowledged(&base_body()));
    }

    #[test]
    fn install_binding_is_install_once_and_rejects_inactive() {
        let _g = gate_unconfigured(); // resets the slot to None + serializes
        // An inactive binding is refused (only a successful reconcile installs ⇒ active).
        assert!(!install_anti_rollback_binding(AntiRollbackBinding { epoch: 1, active: false }));
        assert!(!is_anti_rollback_configured());
        // First active install wins.
        assert!(install_anti_rollback_binding(AntiRollbackBinding { epoch: 5, active: true }));
        assert!(is_anti_rollback_configured());
        // Second install is refused (no overwrite) — a security-relevant property: a later call can't
        // swap in a different epoch over a live binding.
        assert!(!install_anti_rollback_binding(AntiRollbackBinding { epoch: 9, active: true }));
    }

    #[test]
    fn fail_closed_default_no_binding() {
        let _g = gate_unconfigured(); // resets the slot to None
        assert!(!is_anti_rollback_configured(), "const-init None ⇒ fail-closed default");
    }

    #[test]
    fn gate_blocks_generate_keys_when_unconfigured() {
        use ed25519_dalek::SigningKey;
        let _g = gate_unconfigured();
        let body = base_body();
        // A cap signed by a key that does NOT match the body's admin — would be CapabilityRejected if
        // verified. With the gate unconfigured it returns NotConfigured instead, proving the gate
        // short-circuits BEFORE verify_capability (no cap-state oracle). Removing the gate re-opens it.
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        let (cap, pay) =
            generate_keys_cap_and_payload(&wrong, &[0x11; 16], 1, 1, 3, b"generate_transfer");
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

    #[test]
    fn gate_blocks_configure_treasury_export_restore_when_unconfigured() {
        let _g = gate_unconfigured();
        let body = base_body();
        // The gate fires before privilege/cap routing, so no cap is needed to observe the block.
        for op in [6u8, 7, 8] {
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &envelope(op, vec![]), &body).err(),
                Some(AgentError::NotConfigured),
                "opcode {op} must be gated when anti-rollback is unconfigured"
            );
        }
    }

    #[test]
    fn sign_transfer_not_gated_but_faucet_is() {
        let _g = gate_unconfigured();
        let body = base_body();
        assert!(!AgentOpcode::SignTransfer.is_rollback_sensitive(), "transfer carries no rollback state");
        assert!(AgentOpcode::SignFaucetDispense.is_rollback_sensitive(), "faucet dispense debits spend");
        // SIGN_TRANSFER(4) is NOT anti-rollback-gated (the classification above is the lock). When the
        // gate is unconfigured it is therefore NOT blocked by the gate: without the preview it falls
        // through to the production fail-closed NotConfigured; WITH the preview it is live, so an empty
        // payload is Malformed — proving it passed the (unconfigured) gate rather than being blocked by it.
        let err4 = dispatch_agent(Profile::AgentGateway, &envelope(4, vec![]), &body).err();
        #[cfg(not(feature = "agent-sign-transfer-preview"))]
        assert_eq!(err4, Some(AgentError::NotConfigured));
        #[cfg(feature = "agent-sign-transfer-preview")]
        assert_eq!(err4, Some(AgentError::Malformed), "transfer is live — not gate-blocked");
        // SIGN_FAUCET_DISPENSE(5) IS gated → NotConfigured when the binding is unconfigured.
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &envelope(5, vec![]), &body).err(),
            Some(AgentError::NotConfigured)
        );
    }

    #[test]
    fn reads_allowed_when_unconfigured() {
        let _g = gate_unconfigured();
        let (body, key_ref) = body_with_key();
        // PUBLIC_IDENTITY(2) is not rollback-sensitive → allowed with no anti-rollback binding.
        // (PROVE_IDENTITY(3)'s gate-pass when unconfigured is covered by prove_identity_signs_and_recovers
        // under agent-prove-identity-preview, and op3==false is locked by the exhaustive classification.)
        let env = envelope(2, vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))]);
        assert!(
            dispatch_agent(Profile::AgentGateway, &env, &body).is_ok(),
            "PUBLIC_IDENTITY is not gated by anti-rollback"
        );
    }

    #[test]
    fn configured_lets_gated_op_reach_verify() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured(); // binding installed
        let body = base_body();
        // Same wrong-key cap as the block test, but the gate is now satisfied → the op proceeds to
        // verify_capability, which rejects the wrong key (0x43). Proves the binding unblocks the gate.
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        let cap = crate::agent_capability::test_signed_capability(
            &wrong, 7, &[0x11; 16], 1, false, 11565, "testnet", 0, b"export_backup", 1, [0xab; 32],
        );
        let env = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body).err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn frame_gated_op_unconfigured_returns_0x45() {
        use ed25519_dalek::SigningKey;
        let _g = gate_unconfigured(); // serialize + leave the binding None
        reset_agent_keystore_for_tests();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        assert!(install_agent_keystore(body, b"meas"));
        // EXPORT_BACKUP(7) with a valid cap, through the REAL frame handler, no anti-rollback binding ⇒
        // the gate fires ⇒ 0x45 (proves the gate is on the production frame path).
        let cap = crate::agent_capability::test_signed_capability(
            &admin, 7, &[0x11; 16], 1, false, 11565, "testnet", 0, b"export_backup", 1, [0xab; 32],
        );
        let env = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(decode_agent_error_code(&handle_agent_gateway_frame(&env)), Some(0x45));
        reset_agent_keystore_for_tests();
    }

    /// SIGN_TRANSFER(4) dispatch handler (TASK-15 slice 15-1) — golden reproduction + §6 rejections.
    #[cfg(feature = "agent-sign-transfer-preview")]
    mod sign_transfer_dispatch {
        use super::*;

        const KEYS: &str = include_str!("../testvectors/agent-gateway/keys.json");
        const ORD: &str = include_str!("../testvectors/agent-gateway/ordinary_tx_v1.json");

        fn unhex(s: &str) -> Vec<u8> {
            hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
        }
        fn arr20(s: &str) -> [u8; 20] {
            unhex(s).try_into().unwrap()
        }
        /// Minimal big-endian bytes of a u64 (the canonical u256 wire form for values that fit u64).
        fn min_be(x: u64) -> Vec<u8> {
            let b = x.to_be_bytes();
            let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
            b[i..].to_vec()
        }

        /// A keystore body carrying a specific secp256k1 key (golden test vectors) under `purpose`.
        /// Returns (body, key_ref, derived-from-address).
        fn body_with_key(name: &str, purpose: KeyPurpose) -> (KeystoreBody, [u8; 32], [u8; 20]) {
            let k: serde_json::Value = serde_json::from_str(KEYS).unwrap();
            let key_ref = [0x33u8; 32];
            let mut body = base_body();
            body.entries.push(KeyEntry {
                key_ref,
                purpose,
                algorithm: KeyAlgorithm::Secp256k1,
                public_identity: unhex(k[name]["pubkey_uncompressed_sec1"].as_str().unwrap()),
                secret_scalar: zeroize::Zeroizing::new(unhex(k[name]["privkey"].as_str().unwrap())),
                creation_metadata: CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 },
                backup_export_metadata: BackupExportMetadata::default(),
            });
            (body, key_ref, arr20(k[name]["eth_address"].as_str().unwrap()))
        }

        /// Build a SIGN_TRANSFER request envelope from explicit field values (each test perturbs one).
        /// `value`/`gas_price`/`data` are passed as raw `Value`s so a test can inject a non-`bstr` /
        /// non-minimal / over-width encoding.
        #[allow(clippy::too_many_arguments)]
        fn request(
            key_ref: &[u8; 32],
            chain_id: u64,
            from: &[u8; 20],
            to: &[u8; 20],
            value: Value,
            nonce: u64,
            gas_limit: u64,
            gas_price: Value,
            data: Value,
        ) -> Vec<u8> {
            let payload = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(chain_id.into())),
                (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                (Value::Integer(4.into()), value),
                (Value::Integer(5.into()), Value::Integer(nonce.into())),
                (Value::Integer(6.into()), Value::Integer(gas_limit.into())),
                (Value::Integer(7.into()), gas_price),
                (Value::Integer(8.into()), data),
            ]);
            envelope(
                4,
                vec![
                    (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                    (Value::Integer(7.into()), payload),
                ],
            )
        }

        /// The golden request reproducing `ordinary_tx_v1` for the given key.
        fn golden_request(key_ref: &[u8; 32], from: &[u8; 20]) -> Vec<u8> {
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let f = &o["fields"];
            request(
                key_ref,
                o["chain_id"].as_u64().unwrap(),
                from,
                &arr20(f["to"].as_str().unwrap()),
                Value::Bytes(min_be(f["value"].as_u64().unwrap())),
                f["nonce"].as_u64().unwrap(),
                f["gas_limit"].as_u64().unwrap(),
                Value::Bytes(min_be(f["gas_price"].as_u64().unwrap())),
                Value::Bytes(vec![]),
            )
        }

        fn resp_map(body: &[u8]) -> Vec<(Value, Value)> {
            match ciborium::de::from_reader::<Value, _>(body).unwrap() {
                Value::Map(m) => m,
                _ => panic!("response is not a CBOR map"),
            }
        }

        #[test]
        fn dispatch_matches_golden() {
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let resp = dispatch_agent(Profile::AgentGateway, &golden_request(&key_ref, &from), &body)
                .expect("golden SIGN_TRANSFER must succeed");
            let m = resp_map(&encode_agent_response(&resp));
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let bytes = |k: u64| as_bytes(map_get(&m, k).unwrap()).unwrap().to_vec();
            let uint = |k: u64| as_u64(map_get(&m, k).unwrap()).unwrap();
            assert_eq!(bytes(1), unhex(o["signed_rlp"].as_str().unwrap()), "signed_rlp");
            assert_eq!(bytes(2), unhex(o["signature"]["r"].as_str().unwrap()), "r");
            assert_eq!(bytes(3), unhex(o["signature"]["s"].as_str().unwrap()), "s");
            assert_eq!(uint(4), o["signature"]["recovery_id"].as_u64().unwrap(), "recovery_id");
            assert_eq!(uint(5), o["signature"]["v_eip155"].as_u64().unwrap(), "v");
            assert_eq!(bytes(6), unhex(o["signing_hash_keccak256"].as_str().unwrap()), "signing_hash");
            assert_eq!(bytes(7), from.to_vec(), "from");
        }

        /// The full wire path (frame layer + installed keystore) yields the same golden signed tx.
        #[test]
        fn frame_path_matches_golden() {
            let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            assert!(install_agent_keystore(body, b"meas"));
            let out = handle_agent_gateway_frame(&golden_request(&key_ref, &from));
            // A success body has BYTES at key 1 (signed_rlp), so the error-code decoder returns None.
            assert_eq!(decode_agent_error_code(&out), None, "must be a success body, not an error");
            let m = resp_map(&out);
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            assert_eq!(
                as_bytes(map_get(&m, 1).unwrap()).unwrap().to_vec(),
                unhex(o["signed_rlp"].as_str().unwrap()),
                "frame-path signed_rlp"
            );
            // Symmetric teardown: the guard's NEXT acquirer full-resets anyway, but reset here too so
            // this test leaves no installed keystore behind (mirrors the lock_and_reset entry).
            crate::agent_dispatch::reset_agent_keystore_for_tests();
        }

        #[test]
        fn rejects_invalid_requests() {
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let to = arr20(o["fields"]["to"].as_str().unwrap());
            let cid = o["chain_id"].as_u64().unwrap();
            let val = || Value::Bytes(min_be(o["fields"]["value"].as_u64().unwrap()));
            let gp = || Value::Bytes(min_be(o["fields"]["gas_price"].as_u64().unwrap()));
            let empty = || Value::Bytes(vec![]);
            let err = |req: &[u8]| dispatch_agent(Profile::AgentGateway, req, &body).err();

            // wrong chain_id (never request-authoritative) → Malformed
            assert_eq!(
                err(&request(&key_ref, cid + 1, &from, &to, val(), 0, 21000, gp(), empty())),
                Some(AgentError::Malformed),
                "wrong chain_id"
            );
            // `from` != the key's derived address → KeyPurposeMismatch (key-related → uniform 0x42,
            // anti-oracle: reaching the from-check means the key exists + is a transfer key).
            let mut bad_from = from;
            bad_from[0] ^= 0xff;
            assert_eq!(
                err(&request(&key_ref, cid, &bad_from, &to, val(), 0, 21000, gp(), empty())),
                Some(AgentError::KeyPurposeMismatch),
                "from != derived"
            );
            // non-empty `data` (no generic-digest / calldata path in MVP) → Malformed
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, val(), 0, 21000, gp(), Value::Bytes(vec![0xde, 0xad]))),
                Some(AgentError::Malformed),
                "non-empty data"
            );
            // over-width amount (33 bytes > u256) → Malformed (never truncated, §2 AC#8)
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, Value::Bytes(vec![0x01; 33]), 0, 21000, gp(), empty())),
                Some(AgentError::Malformed),
                "over-width amount"
            );
            // non-minimal amount (leading zero byte) → Malformed (canonical u256 wire form)
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, Value::Bytes(vec![0x00, 0x01]), 0, 21000, gp(), empty())),
                Some(AgentError::Malformed),
                "non-minimal amount"
            );
            // amount as a CBOR uint (not a byte string) → Malformed (u256 fields are byte strings)
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, Value::Integer(5.into()), 0, 21000, gp(), empty())),
                Some(AgentError::Malformed),
                "amount not a bstr"
            );
            // unknown key_ref → KeyPurposeMismatch (anti-oracle: not-found ≡ wrong-purpose)
            assert_eq!(
                err(&request(&[0x99; 32], cid, &from, &to, val(), 0, 21000, gp(), empty())),
                Some(AgentError::KeyPurposeMismatch),
                "unknown key_ref"
            );
            // the SAME malformed u256 encodings on `gas_price` (key 7) → Malformed — symmetric with
            // `amount` (key 4); both decode through `as_u256_minimal_be`, so this pins key 7's wiring.
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, val(), 0, 21000, Value::Bytes(vec![0x01; 33]), empty())),
                Some(AgentError::Malformed),
                "over-width gas_price"
            );
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, val(), 0, 21000, Value::Bytes(vec![0x00, 0x01]), empty())),
                Some(AgentError::Malformed),
                "non-minimal gas_price"
            );
            assert_eq!(
                err(&request(&key_ref, cid, &from, &to, val(), 0, 21000, Value::Integer(5.into()), empty())),
                Some(AgentError::Malformed),
                "gas_price not a bstr"
            );
        }

        #[test]
        fn rejects_wrong_key_purpose() {
            // A faucet-treasury key under SIGN_TRANSFER → KeyPurposeMismatch (cross-use, §4). Collapses
            // with key-not-found so the host cannot tell "wrong purpose" from "absent".
            let (body, key_ref, from) = body_with_key("treasury_key", KeyPurpose::AgentFaucetTreasuryK1);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &golden_request(&key_ref, &from), &body).err(),
                Some(AgentError::KeyPurposeMismatch)
            );
        }

        #[test]
        fn rejects_capability_on_runtime_op() {
            // SIGN_TRANSFER is a runtime op; a capability (envelope key 5) is forbidden → Malformed.
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let to = arr20(o["fields"]["to"].as_str().unwrap());
            let payload = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(o["chain_id"].as_u64().unwrap().into())),
                (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                (Value::Integer(4.into()), Value::Bytes(min_be(o["fields"]["value"].as_u64().unwrap()))),
                (Value::Integer(5.into()), Value::Integer(0.into())),
                (Value::Integer(6.into()), Value::Integer(21000.into())),
                (Value::Integer(7.into()), Value::Bytes(min_be(o["fields"]["gas_price"].as_u64().unwrap()))),
                (Value::Integer(8.into()), Value::Bytes(vec![])),
            ]);
            let req = envelope(
                4,
                vec![
                    (Value::Integer(5.into()), Value::Map(vec![(Value::Integer(1.into()), Value::Integer(1.into()))])),
                    (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                    (Value::Integer(7.into()), payload),
                ],
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &req, &body).err(),
                Some(AgentError::Malformed)
            );
        }

        #[test]
        fn rejects_missing_and_extra_payload_keys() {
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let to = arr20(o["fields"]["to"].as_str().unwrap());
            // Missing key 8 (data): only 7 keys → Malformed.
            let missing = envelope(
                4,
                vec![
                    (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                    (
                        Value::Integer(7.into()),
                        Value::Map(vec![
                            (Value::Integer(1.into()), Value::Integer(o["chain_id"].as_u64().unwrap().into())),
                            (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                            (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                            (Value::Integer(4.into()), Value::Bytes(min_be(1))),
                            (Value::Integer(5.into()), Value::Integer(0.into())),
                            (Value::Integer(6.into()), Value::Integer(21000.into())),
                            (Value::Integer(7.into()), Value::Bytes(min_be(1))),
                        ]),
                    ),
                ],
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &missing, &body).err(),
                Some(AgentError::Malformed),
                "missing data key"
            );
            // Extra key 9 → Malformed (strict allow-list 1..=8).
            let extra = envelope(
                4,
                vec![
                    (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                    (
                        Value::Integer(7.into()),
                        Value::Map(vec![
                            (Value::Integer(1.into()), Value::Integer(o["chain_id"].as_u64().unwrap().into())),
                            (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                            (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                            (Value::Integer(4.into()), Value::Bytes(min_be(1))),
                            (Value::Integer(5.into()), Value::Integer(0.into())),
                            (Value::Integer(6.into()), Value::Integer(21000.into())),
                            (Value::Integer(7.into()), Value::Bytes(min_be(1))),
                            (Value::Integer(8.into()), Value::Bytes(vec![])),
                            (Value::Integer(9.into()), Value::Integer(0.into())),
                        ]),
                    ),
                ],
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &extra, &body).err(),
                Some(AgentError::Malformed),
                "extra payload key"
            );
        }

        #[test]
        fn rejects_wrong_length_to_and_from() {
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let to = arr20(o["fields"]["to"].as_str().unwrap());
            let cid = o["chain_id"].as_u64().unwrap();
            let val = min_be(o["fields"]["value"].as_u64().unwrap());
            let gp = min_be(o["fields"]["gas_price"].as_u64().unwrap());
            // Build a request with arbitrary (possibly wrong-length) `from`/`to` byte strings.
            let build = |from_v: Value, to_v: Value| -> Vec<u8> {
                let payload = Value::Map(vec![
                    (Value::Integer(1.into()), Value::Integer(cid.into())),
                    (Value::Integer(2.into()), from_v),
                    (Value::Integer(3.into()), to_v),
                    (Value::Integer(4.into()), Value::Bytes(val.clone())),
                    (Value::Integer(5.into()), Value::Integer(0.into())),
                    (Value::Integer(6.into()), Value::Integer(21000.into())),
                    (Value::Integer(7.into()), Value::Bytes(gp.clone())),
                    (Value::Integer(8.into()), Value::Bytes(vec![])),
                ]);
                envelope(
                    4,
                    vec![
                        (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                        (Value::Integer(7.into()), payload),
                    ],
                )
            };
            // 19/21-byte `to` → Malformed (as_bytes_n::<20> rejects; never silently padded/truncated).
            for bad_to in [vec![0u8; 19], vec![0u8; 21]] {
                let req = build(Value::Bytes(from.to_vec()), Value::Bytes(bad_to));
                assert_eq!(
                    dispatch_agent(Profile::AgentGateway, &req, &body).err(),
                    Some(AgentError::Malformed),
                    "wrong-length to"
                );
            }
            // 19-byte `from` → Malformed (a SHAPE error caught at decode, before the semantic
            // from!=derived 0x42 check) — pins the shape-vs-key band split for `from`.
            let req = build(Value::Bytes(vec![0u8; 19]), Value::Bytes(to.to_vec()));
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &req, &body).err(),
                Some(AgentError::Malformed),
                "wrong-length from"
            );
        }

        #[test]
        fn signs_zero_value_and_gas_price() {
            // A zero-value, zero-gas_price transfer is a valid signed artifact (empty bstr = canonical
            // zero → RLP 0x80). Exercises the empty-bytes branch through the real dispatch + encoder.
            let (body, key_ref, from) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let to = arr20(o["fields"]["to"].as_str().unwrap());
            let cid = o["chain_id"].as_u64().unwrap();
            let req = request(
                &key_ref,
                cid,
                &from,
                &to,
                Value::Bytes(vec![]), // value = 0
                0,
                21000,
                Value::Bytes(vec![]), // gas_price = 0
                Value::Bytes(vec![]),
            );
            let resp = dispatch_agent(Profile::AgentGateway, &req, &body)
                .expect("zero-value transfer must sign");
            let m = resp_map(&encode_agent_response(&resp));
            assert_eq!(as_bytes(map_get(&m, 7).unwrap()).unwrap().to_vec(), from.to_vec(), "from");
            assert!(!as_bytes(map_get(&m, 1).unwrap()).unwrap().is_empty(), "signed_rlp present");
        }

        #[test]
        fn rejects_extra_outer_envelope_key() {
            // grok lock-in: decode_envelope strict-checks outer keys 1..=7, so an unknown OUTER key (8)
            // is Malformed before the handler — a SIGN_TRANSFER frame cannot smuggle extra outer fields
            // (the capability-at-key-5 case is covered by rejects_capability_on_runtime_op).
            let (body, _, _) = body_with_key("transfer_key", KeyPurpose::AgentTransferK1);
            let extra_outer = envelope(
                4,
                vec![
                    (Value::Integer(6.into()), Value::Bytes([0x33u8; 32].to_vec())),
                    (Value::Integer(7.into()), Value::Map(vec![])),
                    (Value::Integer(8.into()), Value::Integer(0.into())),
                ],
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &extra_outer, &body).err(),
                Some(AgentError::Malformed),
                "unknown outer envelope key"
            );
        }
    }

    /// SIGN_FAUCET_DISPENSE(5) dispatch handler (TASK-15 slice 15-3b) — the §2 recipient allowlist +
    /// accept-gate + dual-counter debit through the seal-before-emit seam.
    #[cfg(feature = "agent-sign-faucet-preview")]
    mod sign_faucet_dispatch {
        use super::*;

        const KEYS: &str = include_str!("../testvectors/agent-gateway/keys.json");

        fn unhex(s: &str) -> Vec<u8> {
            hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
        }
        fn arr20(s: &str) -> [u8; 20] {
            unhex(s).try_into().unwrap()
        }
        /// Minimal big-endian bytes of a u64 (the canonical u256 wire form for values that fit u64).
        fn min_be(x: u64) -> Vec<u8> {
            let b = x.to_be_bytes();
            let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
            b[i..].to_vec()
        }
        fn entry(name: &str, key_ref: [u8; 32], purpose: KeyPurpose, batch: u64) -> KeyEntry {
            let k: serde_json::Value = serde_json::from_str(KEYS).unwrap();
            KeyEntry {
                key_ref,
                purpose,
                algorithm: KeyAlgorithm::Secp256k1,
                public_identity: unhex(k[name]["pubkey_uncompressed_sec1"].as_str().unwrap()),
                secret_scalar: zeroize::Zeroizing::new(unhex(k[name]["privkey"].as_str().unwrap())),
                creation_metadata: CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: batch },
                backup_export_metadata: BackupExportMetadata::default(),
            }
        }
        fn addr(name: &str) -> [u8; 20] {
            let k: serde_json::Value = serde_json::from_str(KEYS).unwrap();
            arr20(k[name]["eth_address"].as_str().unwrap())
        }

        const TREASURY_REF: [u8; 32] = [0x55; 32];
        const TRANSFER_REF: [u8; 32] = [0x66; 32];
        // The dispense `to` + the test caps yield this worst_case = amount + gas_limit*gas_price.
        const DISP_AMOUNT: u64 = 1000;
        const DISP_GAS_LIMIT: u64 = 21000;
        const DISP_GAS_PRICE: u64 = 100;
        fn worst_case() -> u64 {
            DISP_AMOUNT + DISP_GAS_LIMIT * DISP_GAS_PRICE
        }

        /// A keystore body with the singleton faucet TREASURY key (the dispense signer) AND one TRANSFER
        /// key (the only allowlisted recipient), faucet caps set, and a `budget` budget ceiling. Returns
        /// (body, treasury_from, recipient_to).
        fn faucet_body(budget: u64) -> (KeystoreBody, [u8; 20], [u8; 20]) {
            let mut body = base_body();
            body.entries.push(entry("treasury_key", TREASURY_REF, KeyPurpose::AgentFaucetTreasuryK1, 1));
            body.entries.push(entry("transfer_key", TRANSFER_REF, KeyPurpose::AgentTransferK1, 2));
            body.faucet.per_dispense_max_amount = crate::u256::from_u64(1_000_000);
            body.faucet.max_gas_limit = 21_000;
            body.faucet.max_effective_gas_fee_rate = 1_000_000_000;
            body.faucet.cumulative_signing_budget = crate::u256::from_u64(budget);
            (body, addr("treasury_key"), addr("transfer_key"))
        }

        /// Build a SIGN_FAUCET_DISPENSE request envelope (the SAME strict 8-field map as SIGN_TRANSFER).
        #[allow(clippy::too_many_arguments)]
        fn request(
            key_ref: &[u8; 32],
            chain_id: u64,
            from: &[u8; 20],
            to: &[u8; 20],
            amount: Value,
            nonce: u64,
            gas_limit: u64,
            gas_price: Value,
            data: Value,
        ) -> Vec<u8> {
            let payload = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(chain_id.into())),
                (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                (Value::Integer(4.into()), amount),
                (Value::Integer(5.into()), Value::Integer(nonce.into())),
                (Value::Integer(6.into()), Value::Integer(gas_limit.into())),
                (Value::Integer(7.into()), gas_price),
                (Value::Integer(8.into()), data),
            ]);
            envelope(
                5,
                vec![
                    (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                    (Value::Integer(7.into()), payload),
                ],
            )
        }

        /// A canonical accepted dispense from the treasury to the allowlisted transfer key.
        fn good_request(from: &[u8; 20], to: &[u8; 20]) -> Vec<u8> {
            request(
                &TREASURY_REF,
                11565,
                from,
                to,
                Value::Bytes(min_be(DISP_AMOUNT)),
                0,
                DISP_GAS_LIMIT,
                Value::Bytes(min_be(DISP_GAS_PRICE)),
                Value::Bytes(vec![]),
            )
        }

        fn resp_map(body: &[u8]) -> Vec<(Value, Value)> {
            match ciborium::de::from_reader::<Value, _>(body).unwrap() {
                Value::Map(m) => m,
                _ => panic!("response is not a CBOR map"),
            }
        }

        #[test]
        fn dispatch_accepts_and_debits_dual_counters() {
            let _g = gate_configured(); // rollback-sensitive ⇒ the binding must be installed
            let (body, from, to) = faucet_body(10_000_000);
            let resp = dispatch_agent(Profile::AgentGateway, &good_request(&from, &to), &body)
                .expect("an in-cap dispense to a known transfer key must succeed");
            match resp {
                AgentResponse::SignFaucetDispense { signed, candidate, request_id } => {
                    // Signed FROM the treasury key (recovery==from invariant holds inside sign_transfer).
                    assert_eq!(signed.from, from, "dispense signed by the treasury key");
                    assert!(!signed.signed_rlp.is_empty(), "broadcastable signed tx present");
                    // The envelope's request_id is echoed verbatim — the frame layer keys the anchor
                    // commit record by it (idempotency).
                    assert_eq!(request_id, vec![0x11; 16], "request_id echoed from the envelope");
                    // BOTH spend counters advanced by worst_case; budget/caps untouched; EpochOnly bump.
                    let wc = crate::u256::from_u64(worst_case());
                    assert_eq!(candidate.faucet.cumulative_native_spend, wc, "cumulative debited");
                    assert_eq!(candidate.faucet.lifetime_spend, wc, "lifetime debited");
                    assert_eq!(candidate.faucet.cumulative_signing_budget, body.faucet.cumulative_signing_budget, "budget unchanged");
                    assert_eq!(candidate.freshness_epoch, body.freshness_epoch + 1, "EpochOnly: epoch advanced");
                    assert_eq!(candidate.structural_version, body.structural_version, "EpochOnly: structural untouched");
                }
                _ => panic!("expected SignFaucetDispense"),
            }
        }

        #[test]
        fn rejects_recipient_not_a_known_transfer_key() {
            let _g = gate_configured();
            let (body, from, _to) = faucet_body(10_000_000);
            // A `to` that is no transfer key in the keystore → 0x42 (anti-oracle: indistinguishable from a
            // missing/mis-purposed treasury key; the host cannot probe which addresses are known).
            let stranger = [0xab; 20];
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &good_request(&from, &stranger), &body).err(),
                Some(AgentError::KeyPurposeMismatch),
                "recipient not a known transfer identity"
            );
            // The treasury's OWN address is also not a transfer-key recipient → still 0x42 (no self-dispense
            // shortcut past the allowlist).
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &good_request(&from, &from), &body).err(),
                Some(AgentError::KeyPurposeMismatch),
                "treasury address is not an allowlisted recipient"
            );
        }

        #[test]
        fn rejects_wrong_signer_key_purpose_and_from() {
            let _g = gate_configured();
            let (body, from, to) = faucet_body(10_000_000);
            // The TRANSFER key as the signer (key_ref) → 0x42 (faucet accepts only the treasury purpose;
            // cross-use collapses with not-found).
            let transfer_signer = request(
                &TRANSFER_REF, 11565, &addr("transfer_key"), &to,
                Value::Bytes(min_be(DISP_AMOUNT)), 0, DISP_GAS_LIMIT, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &transfer_signer, &body).err(),
                Some(AgentError::KeyPurposeMismatch),
                "transfer key cannot sign a faucet dispense"
            );
            // unknown key_ref → 0x42.
            let unknown = request(
                &[0x99; 32], 11565, &from, &to,
                Value::Bytes(min_be(DISP_AMOUNT)), 0, DISP_GAS_LIMIT, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &unknown, &body).err(),
                Some(AgentError::KeyPurposeMismatch),
                "unknown signer key_ref"
            );
            // `from` != the treasury key's derived address → 0x42 (per-key bucket, key established).
            let mut bad_from = from;
            bad_from[0] ^= 0xff;
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &good_request(&bad_from, &to), &body).err(),
                Some(AgentError::KeyPurposeMismatch),
                "from != treasury derived address"
            );
        }

        #[test]
        fn rejects_shape_errors_as_malformed() {
            let _g = gate_configured();
            let (body, from, to) = faucet_body(10_000_000);
            let err = |req: &[u8]| dispatch_agent(Profile::AgentGateway, req, &body).err();
            // wrong chain_id (never request-authoritative) → 0x40.
            assert_eq!(
                err(&request(&TREASURY_REF, 11566, &from, &to, Value::Bytes(min_be(DISP_AMOUNT)), 0, DISP_GAS_LIMIT, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![]))),
                Some(AgentError::Malformed),
                "wrong chain_id"
            );
            // non-empty data (no calldata/memo) → 0x40.
            assert_eq!(
                err(&request(&TREASURY_REF, 11565, &from, &to, Value::Bytes(min_be(DISP_AMOUNT)), 0, DISP_GAS_LIMIT, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![0xde, 0xad]))),
                Some(AgentError::Malformed),
                "non-empty data"
            );
            // over-width amount (33 bytes) → 0x40 (never truncated, §2 AC#8) — a SHAPE error caught at
            // decode BEFORE the §2 cap gate (which would be 0x44), pinning the band split.
            assert_eq!(
                err(&request(&TREASURY_REF, 11565, &from, &to, Value::Bytes(vec![0x01; 33]), 0, DISP_GAS_LIMIT, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![]))),
                Some(AgentError::Malformed),
                "over-width amount"
            );
            // non-minimal gas_price (leading zero) → 0x40.
            assert_eq!(
                err(&request(&TREASURY_REF, 11565, &from, &to, Value::Bytes(min_be(DISP_AMOUNT)), 0, DISP_GAS_LIMIT, Value::Bytes(vec![0x00, 0x01]), Value::Bytes(vec![]))),
                Some(AgentError::Malformed),
                "non-minimal gas_price"
            );
        }

        #[test]
        fn rejects_cap_and_budget_as_cap_exceeded() {
            let _g = gate_configured();
            // amount over the per-dispense cap → 0x44 (key+recipient valid, so the §2 gate is reached).
            let (body, from, to) = faucet_body(10_000_000_000);
            let over_amount = request(
                &TREASURY_REF, 11565, &from, &to,
                Value::Bytes(min_be(2_000_000)), 0, DISP_GAS_LIMIT, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &over_amount, &body).err(),
                Some(AgentError::CapExceeded),
                "amount over per_dispense_max_amount"
            );
            // gas_limit over the cap → 0x44.
            let over_gas = request(
                &TREASURY_REF, 11565, &from, &to,
                Value::Bytes(min_be(DISP_AMOUNT)), 0, 21_001, Value::Bytes(min_be(DISP_GAS_PRICE)), Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &over_gas, &body).err(),
                Some(AgentError::CapExceeded),
                "gas_limit over max_gas_limit"
            );
            // worst_case over the cumulative budget → 0x44 (budget too small for one dispense).
            let (tiny, from2, to2) = faucet_body(worst_case() - 1);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &good_request(&from2, &to2), &tiny).err(),
                Some(AgentError::CapExceeded),
                "worst_case over cumulative_signing_budget"
            );
            // an UNCONFIGURED budget (==0) rejects every dispense, even an in-cap one → 0x44.
            let (unconf, from3, to3) = faucet_body(0);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &good_request(&from3, &to3), &unconf).err(),
                Some(AgentError::CapExceeded),
                "unconfigured budget fails closed"
            );
        }

        #[test]
        fn gated_off_when_anti_rollback_unconfigured() {
            // The dispatch anti-rollback gate fires BEFORE the handler: with NO binding installed, a
            // rollback-sensitive dispense is NotConfigured (0x45) regardless of the preview feature.
            let _g = gate_unconfigured();
            let (body, from, to) = faucet_body(10_000_000);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &good_request(&from, &to), &body).err(),
                Some(AgentError::NotConfigured),
                "anti-rollback unconfigured ⇒ NotConfigured"
            );
        }

        /// Full wire path: install keystore + commit channel, dispense through the frame, observe the
        /// sealed blob (key 8) AND the swap (the debit advanced the LIVE slot, so a second dispense that
        /// would exceed the budget is now rejected).
        #[test]
        fn frame_path_seals_commits_and_swaps_the_debit() {
            let _g = gate_configured();
            // Budget covers EXACTLY one worst_case so the swap is observable: the 2nd dispense exceeds it.
            let (mut body, from, to) = faucet_body(worst_case());
            body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
            assert!(install_agent_keystore(body, b"meas"));
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::Ok))));

            let out = handle_agent_gateway_frame(&good_request(&from, &to));
            assert_eq!(decode_agent_error_code(&out), None, "first dispense is a success body");
            let m = resp_map(&out);
            // signed-tx 7-key map + key 8 = the non-empty sealed keystore blob the host persists.
            assert_eq!(as_bytes(map_get(&m, 7).unwrap()).unwrap().to_vec(), from.to_vec(), "from = treasury");
            assert!(!as_bytes(map_get(&m, 1).unwrap()).unwrap().is_empty(), "key 1 = signed_rlp");
            assert!(!as_bytes(map_get(&m, 8).unwrap()).unwrap().is_empty(), "key 8 = sealed blob");

            // PROOF OF SWAP: the live slot now carries the debit, so the SAME dispense (cumulative would be
            // 2*worst_case > budget) is rejected 0x44. If the first hadn't swapped, this would succeed.
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                Some(0x44),
                "second dispense exceeds the budget after the first debit swapped into the live slot"
            );
            reset_agent_keystore_for_tests();
        }

        /// Seal-before-emit fail-closed: a commit failure (no channel / transport / forged ACK) fails the
        /// dispense closed (0x46) with NO debit — the live faucet is untouched, so the SAME dispense still
        /// succeeds once a conformant channel is installed. The signature is emitted ONLY after the anchor
        /// durably records the debit (§3 — no signed dispense without a committed spend).
        #[test]
        fn frame_path_commit_failure_fails_closed_no_debit() {
            let _g = gate_configured();
            let (mut body, from, to) = faucet_body(worst_case());
            body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
            assert!(install_agent_keystore(body, b"meas"));

            // (a) NO commit channel → 0x46.
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                Some(0x46),
                "no commit channel ⇒ SealFailed"
            );
            // (b) transport failure → 0x46.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::Transport))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                Some(0x46),
                "commit transport failure ⇒ SealFailed"
            );
            reset_commit_channel_for_tests();
            // (c) forged ACK (wrong signer) → 0x46.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::WrongKey))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                Some(0x46),
                "forged commit ack ⇒ SealFailed"
            );
            reset_commit_channel_for_tests();
            // (d) PROOF OF NO DEBIT: the live faucet never advanced across all three failures, so a
            // conformant channel now accepts the SAME single-worst_case dispense against the full budget.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(CommitChannelAct::Ok))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                None,
                "the failed dispenses never debited ⇒ the budget is intact and the dispense now succeeds"
            );
            reset_agent_keystore_for_tests();
        }
    }
}
