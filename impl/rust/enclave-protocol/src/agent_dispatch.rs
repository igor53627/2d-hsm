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

use crate::agent_capability::VerifiedCapability;
use crate::agent_identity::{
    public_identity_from_entry, IdentityProof, PublicIdentity, AGENT_GATEWAY_VERSION,
};
use crate::agent_keygen::{generate_keys, GenerateKeysError, GeneratedKey};
use crate::agent_keystore::{seal_body, CreationMetadata, KeyPurpose, KeystoreBody};
use crate::agent_transfer::SignedTransfer;
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
    /// GET_RESTORE_PUBKEY (TASK-24 Slice 2a-ii): generate + publish the destination TEE's attested
    /// ephemeral ML-KEM-1024 public key (the ceremony key the operator re-wraps the backup to). NOT
    /// privileged (no capability — the pubkey is public + attested), NOT rollback-sensitive (generates
    /// only a volatile process-global keypair, no sealed-state mutation), NotCommitted (no anchor commit).
    GetRestorePubkey = 9,
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
            9 => Self::GetRestorePubkey,
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
            // Read/attestation opcodes touch no rollback-sensitive state. GET_RESTORE_PUBKEY likewise —
            // it generates only a volatile process-global ephemeral keypair (no sealed-state mutation).
            Self::PublicIdentity | Self::ProveIdentity | Self::GetRestorePubkey => false,
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
            // STRUCTURAL — mutate state NOT captured in the marks digest (OR a marks surface that the op
            // DECREASES, which AdoptForward's monotone-up belt cannot reconstruct): GENERATE_KEYS mints new
            // random key material; CONFIGURE_TREASURY changes faucet CONFIG (limits / refillable budget /
            // breaker — not marks surfaces) AND, for `reset_lifetime_breaker`, LOWERS `lifetime_spend` (a
            // marks surface) + clears the breaker + bumps `config_version`. A dropped seal of either ⇒
            // StructuralGap⇒restore (design §3). The CONFIGURE handler uses a sub-op classifier
            // [`configure_treasury_sub_op_bump_class`] that re-confirms ALL FOUR sub-ops Structural — the
            // earlier note here (that `reset_lifetime_breaker` is "marks-only ⇒ EpochOnly") was WRONG
            // (TASK-15 15-4 review): reset LOWERS a marks surface, which `marks_dominate_local` rejects, so
            // EpochOnly would wedge the recovery op on a crash-before-swap. See that classifier's docs.
            // EXPORT_BACKUP (TASK-13b slice 2): once its handler lands (slice 4) it advances the AUDIT-ring
            // backpressure high-water `audit.last_exported_seq`, which is NEITHER a marks surface NOR
            // `structural_version`. Under EpochOnly a dropped/crashed EXPORT seal would adopt-forward and the
            // seeder (which never touches `audit`) silently roll `last_exported_seq` BACK, re-enabling
            // overwrite of already-exported reviewable history (an AC#14 audit-completeness hole — not a fund
            // loss). DETERMINED Structural (NOT a "when in doubt" default, and a DIFFERENT mechanism than
            // CONFIGURE `reset_lifetime_breaker`, which is Structural because it DECREASES a marks surface
            // that `marks_dominate_local` hard-rejects): `last_exported_seq` is durable non-marks/
            // non-structural state the adopt-forward seeder silently drops, so Structural is the resolution —
            // a dropped EXPORT seal ⇒ StructuralGap⇒restore re-presents the WHOLE body (incl.
            // `audit.last_exported_seq`), so the high-water can't silently regress. Why Structural and not
            // the "make `last_exported_seq` marks-covered" route (which would allow EpochOnly): the audit-ring
            // WRITE path is deferred for ALL privileged ops (agent_dispatch.rs ~913) — no marks surface for it
            // exists yet — so Structural is the conservative interim; revisit only if it ever becomes
            // marks-covered. ACCEPTED RESIDUAL: Structural means a dropped/crashed EXPORT seal forces a
            // next-boot StructuralGap⇒restore (an availability cost for a routinely-run op), traded for
            // audit completeness.
            // RESTORE_BACKUP (TASK-13b slice 2; handler deferred → TASK-24): wholesale-REPLACES the
            // keystore body — entries / config-identity / counters / faucet / audit RECORDS — from the
            // restore-ingress payload, and sets enclave-local `structural_version` + `freshness_epoch`
            // (the payload carries NEITHER — AC#4). Those replaced surfaces are non-marks,
            // non-AdoptForward-reconstructable (the seeder `seed_marks_forward` overwrites ONLY counters/
            // spend/strict_recovery_counter), so EpochOnly would be UNSAFE: a dropped/crashed RESTORE seal
            // would AdoptForward over a same-structural gap and SILENTLY LOSE the restore (the enclave stays
            // in the pre-restore body while the `strict_recovery_counter` already burned). Structural ⇒ a
            // dropped seal triggers StructuralGap⇒restore (re-attempt, never a silent rollback).
            // DECISION (TASK-24 AC#4/#5, the `local+1` structural_version strategy): RESTORE stays
            // `Structural` — it bumps `structural_version = local+1` via the ordinary
            // `advance_commit_epoch(true)` `++`, NOT a backup-seeded or strict_recovery_counter-seeded value
            // (the payload carries no structural_version; AC#4 sets it enclave-locally). The AC#5 invariant
            // — "a dropped/crashed RESTORE seal ⇒ StructuralGap→restore-retry, never a silent rollback" — is
            // SATISFIED by Structural + local+1: the anchor records structural+1 while a dropped seal leaves
            // the local body at the pre-restore structural, so next-boot reconcile sees anchor-structural >
            // local-structural ⇒ StructuralGap (AdoptForward fires ONLY on a same-structural_version gap —
            // `boot_reconcile_anti_rollback`; verified by the agent_boot reconcile tests). The wholesale body
            // replace touches non-marks surfaces (entries/config/audit) that AdoptForward can't reconstruct,
            // which is EXACTLY why Structural (not EpochOnly) is correct. A distinct
            // `CommitBumpClass::RestoreCeremony` is RESERVED as the extension point for a future non-local+1
            // structural_version (e.g. backup-seeded), where the reconcile would need to admit a restored
            // value != local+1; under local+1 that capability is unused, so the class is YAGNI for now. The
            // RESTORE handler's RECOVERY-SPECIFIC mutation (vs a normal Structural op) is the forward-only
            // `strict_recovery_counter` advance (AC#6, a marks surface) + the AC#11/#12 seeding gate — both
            // handler-side, before the commit; they do NOT require a distinct commit class.
            Self::GenerateKeys
            | Self::ConfigureTreasury
            | Self::ExportBackup
            | Self::RestoreBackup => CommitBumpClass::Structural,
            // EPOCH-ONLY — the op's FULL effect is captured in the anchor's authenticated marks (so
            // AdoptForward reconstructs it byte-for-byte): ONLY SIGN_FAUCET_DISPENSE. PINNED to its handler
            // (`handle_sign_faucet_dispense`): the sole candidate-body mutation is `candidate.faucet =
            // new_faucet`, which advances `cumulative_native_spend` + `lifetime_spend` (both marks surfaces)
            // and NOTHING else durable — so AdoptForward fully reconstructs it. INVARIANT: if the faucet
            // handler is ever changed to mutate any non-marks durable field, EpochOnly becomes unsafe and
            // this op must move to Structural (the same rule that put EXPORT/RESTORE there). Every other
            // committed op touches a non-marks surface ⇒ Structural.
            Self::SignFaucetDispense => CommitBumpClass::EpochOnly,
            // NOT rollback-sensitive — no per-op commit (the commit path is gated on is_rollback_sensitive).
            Self::SignTransfer
            | Self::PublicIdentity
            | Self::ProveIdentity
            | Self::GetRestorePubkey => CommitBumpClass::NotCommitted,
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

/// Slice 15-4: the SUB-OP-level commit-bump classifier for CONFIGURE_TREASURY. **ALL FOUR sub-ops are
/// `Structural`** — same as the opcode-level [`AgentOpcode::commit_bump_class`]. This fn is kept as the
/// per-sub-op extension point (and to single-source the handler's `bumps_structural`), but each sub-op is
/// re-confirmed Structural here:
/// - `{0 set_limits, 2 raise_lifetime_breaker}` mutate anchor-UNRECONSTRUCTABLE faucet CONFIG (the limit
///   triple / the breaker threshold — not marks surfaces), so a dropped seal must `StructuralGap`→restore.
/// - `1 refill_budget` mutates the budget ceiling (not a marks surface) AND resets the refillable
///   `cumulative_native_spend` → 0 — that IS a marks surface, and a DECREASE. That marks decrease is
///   exactly why it too must be Structural: `AdoptForward`'s monotone-up belt could not adopt a lowered
///   `cumulative_native_spend`, so a dropped seal must `StructuralGap`→restore (which fences it).
/// - `3 reset_lifetime_breaker` was INITIALLY thought EpochOnly ("its effect is in the marks"), but that
///   is **wrong** (TASK-15 15-4 review, all reviewers): it (a) LOWERS `lifetime_spend`, a marks surface —
///   and `AdoptForward`'s `marks_dominate_local` belt REQUIRES adopted marks ≥ local, so a lowered
///   `lifetime_spend` fails the belt (`BeltRegression`) and the op can NEVER adopt-forward; (b) CLEARS
///   `circuit_breaker_threshold` and (c) BUMPS `config_version` — neither a marks surface, so the
///   AdoptForward seeder (`seed_marks_forward`) silently drops them. So reset's full effect is NOT
///   marks-captured and NOT AdoptForward-reconstructable ⇒ it MUST be `Structural` (a dropped seal →
///   `StructuralGap`→restore re-presents the whole body from backup, incl. the lowered spend, cleared
///   breaker, and bumped version). EpochOnly is the DANGEROUS direction for EVERY sub-op here (a dropped
///   seal would adopt-forward and either wedge on the belt or silently lose state); the wildcard defaults
///   to the fail-closed-safe `Structural` (unreachable — the handler validates `sub_op ∈ 0..=3`).
#[cfg_attr(not(feature = "agent-configure-treasury-preview"), allow(dead_code))]
fn configure_treasury_sub_op_bump_class(sub_op: u8) -> CommitBumpClass {
    match sub_op {
        // ALL CONFIGURE_TREASURY sub-ops are Structural — none has an AdoptForward-safe effect (see the
        // doc above for why reset_lifetime_breaker(3), despite touching marks, is Structural not EpochOnly).
        0..=3 => CommitBumpClass::Structural,
        // Unreachable (sub_op validated to 0..=3 by the handler); default to fail-closed-safe Structural.
        _ => CommitBumpClass::Structural,
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
    /// CONFIGURE_TREASURY result (slice 15-4): the mutated `candidate` keystore after one faucet-config
    /// sub-op — `{set_limits, refill_budget, raise_lifetime_breaker, reset_lifetime_breaker}` — plus the
    /// monotonic `config_version` bump and the sub-op's commit-epoch bump (Structural for ALL FOUR
    /// sub-ops — see `configure_treasury_sub_op_bump_class`). Like GENERATE_KEYS it is MUTATING but emits NO
    /// secret/signature — a config op signs nothing. The frame layer SEALS the candidate, COMMITS the
    /// post-config state to the anchor (seal-before-emit), SWAPS it into the live slot and returns ONLY the
    /// sealed blob (the sole durable artifact). `request_id` is carried so the frame-layer commit can key
    /// the anchor record by it (idempotency).
    ConfigureTreasury {
        candidate: Box<KeystoreBody>,
        request_id: Vec<u8>,
    },
    /// EXPORT_BACKUP result (TASK-13b slice 4c-2b): the mutated `candidate` keystore (the appended EXPORT
    /// audit record + the FULL ring drain `last_exported_seq → next_seq-1` + the atomic Structural bump)
    /// PLUS the minted `pq-agent-backup-v1` DR blob (the KEM-DEM envelope wrapping the `restore-ingress-v1`
    /// payload, encapsulated to the operator's OFFLINE recovery key). Like the other mutating ops the frame
    /// layer SEALS the candidate, COMMITS the post-op state to the anchor (seal-before-emit), SWAPS it into
    /// the live slot, and EMITS the backup blob + the new sealed keystore blob. The backup blob is built in
    /// the handler from the post-append candidate (so it captures the export's own audit record); the drain
    /// high-water is enclave-local and deliberately NOT in the blob. `request_id` keys the anchor commit.
    ExportBackup {
        candidate: Box<KeystoreBody>,
        backup_blob: Vec<u8>,
        request_id: Vec<u8>,
    },
    /// RESTORE_BACKUP result (TASK-24): the wholesale-restored `candidate` keystore (entries/config-
    /// identity/counters/faucet/audit-records from the backup, AC#6-authenticated high-water counters/spend,
    /// reconstructed audit cursors, advanced strict_recovery_counter, + the enclave-local `local+1`
    /// structural bump via advance_commit_epoch). Like the other mutating Structural ops the frame layer
    /// SEALS the candidate, COMMITS the post-restore state to the anchor (seal-before-emit), SWAPS it into
    /// the live slot, EMITS the sealed blob, AND retires the restore-ephemeral key (single-use). `request_id`
    /// keys the anchor commit. The restore itself opens no key material in the response (the restored
    /// entries live in the sealed blob).
    RestoreBackup {
        candidate: Box<KeystoreBody>,
        request_id: Vec<u8>,
    },
    /// GET_RESTORE_PUBKEY result (TASK-24 Slice 2a-ii): the destination TEE's attested ephemeral ML-KEM-1024
    /// public key (`encaps_key`, 1568 bytes) + the `measurement` it was published under. Non-mutating
    /// (NotCommitted) — generates only a volatile process-global keypair, so it does NOT go through the
    /// seal-before-emit seam; the frame layer encodes it directly (like PUBLIC_IDENTITY / SIGN_TRANSFER).
    GetRestorePubkey {
        encaps_key: Vec<u8>,
        measurement: Vec<u8>,
        /// The fresh SNP attestation report binding the ephemeral key to this TEE (compact 9611 HIGH #2).
        /// The operator verifies report_data + measurement out-of-band BEFORE re-wrapping.
        attestation_report: Vec<u8>,
        /// The VCEK→ASK→ARK cert chain (best-effort; may be empty → operator fetches from AMD KDS).
        cert_chain: Vec<u8>,
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
///
/// **`pub(crate)`, NOT `pub`** (TASK-15 15-3b hardening): the mutating outcomes carry the to-be-emitted
/// artifact BEFORE the seal-before-emit commit — `SignFaucetDispense` carries the broadcastable `signed`
/// dispense tx and `GenerateKeys` carries the new key material — which is durable/emittable ONLY after
/// [`handle_agent_gateway_frame`] runs `commit_before_emit` (seal → anchor-commit → swap). Exposing this
/// as `pub` would let an out-of-crate caller extract a fund-moving signature (or minted keys) WITHOUT the
/// debit/counter being sealed and committed — a seal-before-emit bypass. The public frame entry point is
/// [`handle_agent_gateway_frame`]; `dispatch_agent` is an internal step reachable only in-crate (the frame
/// handler + tests).
pub(crate) fn dispatch_agent(
    profile: Profile,
    payload: &[u8],
    keystore: &KeystoreBody,
    measurement: &[u8],
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
            // CONFIGURE_TREASURY executes ONLY under the off-by-default `agent-configure-treasury-preview`
            // feature (release-banned): live faucet-config mutation must wait for the AC#5 funding profile,
            // the independent recovery-counter rule + AC#14 audit record, and TASK-18. Without the feature
            // it falls through to the privileged default arm below (verify cap, then fail closed).
            #[cfg(feature = "agent-configure-treasury-preview")]
            AgentOpcode::ConfigureTreasury => handle_configure_treasury(&env, keystore, &verified),
            // EXPORT_BACKUP executes ONLY under the off-by-default `agent-backup-export-preview` feature
            // (release-banned, pulls ml-kem): live DR-backup minting + the audit-ring drain wait for TASK-18.
            // Without the feature it falls through to the privileged default arm below (verify, fail closed).
            #[cfg(feature = "agent-backup-export-preview")]
            AgentOpcode::ExportBackup => handle_export_backup(&env, keystore, &verified),
            #[cfg(feature = "agent-backup-export-preview")]
            AgentOpcode::RestoreBackup => {
                handle_restore_backup(&env, keystore, &verified, measurement)
            }
            // CONFIGURE_TREASURY (without its preview) / EXPORT_BACKUP (without its preview) / RESTORE_BACKUP
            // (and GENERATE_KEYS without its preview) verify here but their execution lands in later slices /
            // is deferred ⇒ fail closed.
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
        // GET_RESTORE_PUBKEY (TASK-24 Slice 2a-ii): generate + publish the destination's attested
        // ephemeral ML-KEM pubkey. NOT privileged (no cap — the pubkey is public+attested), NOT
        // rollback-sensitive, NotCommitted — a ceremony-setup op. Enabled only under
        // `agent-backup-export-preview` (the handler uses the ml-kem-pulling ephemeral lifecycle);
        // otherwise fail closed (the opcode is known but the ceremony path is unconfigured).
        AgentOpcode::GetRestorePubkey => {
            #[cfg(feature = "agent-backup-export-preview")]
            {
                handle_get_restore_pubkey(&env, keystore, measurement)
            }
            #[cfg(not(feature = "agent-backup-export-preview"))]
            {
                let _ = (&env, keystore, measurement);
                Err(AgentError::NotConfigured)
            }
        }
        // Privileged opcodes handled above; unreachable here.
        _ => Err(AgentError::Malformed),
    }
}

/// GET_RESTORE_PUBKEY(9) handler (TASK-24 Slice 2a-ii): publish the destination TEE's attested ephemeral
/// ML-KEM-1024 public key (the ceremony key the operator re-wraps the backup to). IDEMPOTENT: if an
/// ephemeral is already published this boot, returns it unchanged (the operator may re-query before
/// re-wrapping — no key churn); else generates + installs a fresh one from the TEE CSPRNG. Single-use is
/// preserved across ceremonies by [`retire_restore_ephemeral`] (called by the RESTORE handler on success)
/// — a GET_RESTORE_PUBKEY after a completed restore finds nothing published + generates a NEW key. CSPRNG
/// failure ⇒ `SealFailed` (no half-publish). NotCommitted — no anchor commit (volatile process-global).
#[cfg(feature = "agent-backup-export-preview")]
fn handle_get_restore_pubkey(
    _env: &AgentEnvelope,
    keystore: &KeystoreBody,
    measurement: &[u8],
) -> Result<AgentResponse, AgentError> {
    let pub_info = published_restore_ephemeral()
        .or_else(|| {
            install_restore_ephemeral(
                measurement,
                keystore.config.twod_chain_id,
                keystore.config.environment_identifier.as_bytes(),
            )
        })
        .ok_or(AgentError::SealFailed)?;
    Ok(AgentResponse::GetRestorePubkey {
        encaps_key: pub_info.encaps_key,
        measurement: pub_info.measurement,
        attestation_report: pub_info.attestation_report,
        cert_chain: pub_info.cert_chain,
    })
}

/// PUBLIC_IDENTITY(2): look up the key by `key_ref` and return its unified-account identity.
fn handle_public_identity(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
) -> Result<AgentResponse, AgentError> {
    let key_ref = env.key_ref.ok_or(AgentError::Malformed)?;
    // not-found collapses with wrong-purpose to 0x42 (anti-oracle).
    let entry = crate::agent_identity::find_entry(keystore, &key_ref)
        .ok_or(AgentError::KeyPurposeMismatch)?;
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
    crate::secp256k1::Keypair::from_secret_bytes(&secret)
        .map_err(|_| AgentError::KeyPurposeMismatch)
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
    let entry = crate::agent_identity::find_entry(keystore, &key_ref)
        .ok_or(AgentError::KeyPurposeMismatch)?;
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
    let req_chain_id = map_get(payload, 1)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let req_from = map_get(payload, 2)
        .and_then(as_bytes_n::<20>)
        .ok_or(AgentError::Malformed)?;
    let to = map_get(payload, 3)
        .and_then(as_bytes_n::<20>)
        .ok_or(AgentError::Malformed)?;
    let value_be = map_get(payload, 4)
        .and_then(as_u256_minimal_be)
        .ok_or(AgentError::Malformed)?;
    let nonce = map_get(payload, 5)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let gas_limit = map_get(payload, 6)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let gas_price_be = map_get(payload, 7)
        .and_then(as_u256_minimal_be)
        .ok_or(AgentError::Malformed)?;
    // data MUST be present and empty (MVP — non-empty calldata is a separate, semantically-parsed
    // command; §1). A precomputed-digest / arbitrary-bytes request can only land here as `data`, and a
    // non-empty `data` fails closed → there is no generic-digest signing path.
    let data = map_get(payload, 8)
        .and_then(as_bytes)
        .ok_or(AgentError::Malformed)?;
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
    let fields = EthTransferFields {
        chain_id: req_chain_id,
        nonce,
        gas_limit,
        to,
        value_be,
        gas_price_be,
    };
    // Collapse any signing failure (the ~2^-128 x-reduced recovery_id rejection, or the
    // recovery==from invariant) to the per-key bucket — SIGN_TRANSFER never seals, so NOT SealFailed
    // (0x46). ValueTooWide/ChainIdOverflow are unreachable here (caps pre-validated above).
    let signed = sign_transfer(&keypair, &fields).map_err(|_| AgentError::KeyPurposeMismatch)?;
    Ok(AgentResponse::SignTransfer(signed))
}

/// §2 faucet recipient allowlist (AC#5): is `to` the derived eth address of SOME stored
/// `agent_transfer_k1` key? **"Allowlisted" == "present in the keystore as a transfer key"** — there is no
/// key-revocation/deactivation surface yet, so every stored transfer key is an eligible recipient (a
/// future revocation slice MUST revisit this predicate). Each candidate address is derived straight from
/// the entry's stored uncompressed public key — **no secret load** — and the tron form is deliberately not
/// computed (only the eth address is compared) to avoid wasted base58 work per scanned entry. The on-curve
/// re-validation inside `eth_address_from_uncompressed` is defense-in-depth (consistent with
/// `public_identity_from_entry`); a malformed stored entry simply never matches (fail-closed, never a
/// panic). All operands are public (host-derivable via PUBLIC_IDENTITY), so the plain compare leaks no
/// secret-dependent timing. A named helper (not an inline closure) so this custody gate is unit-tested in
/// isolation (`recipient_allowlist_matches_only_stored_transfer_keys`).
#[cfg(feature = "agent-sign-faucet-preview")]
fn is_known_transfer_recipient(keystore: &KeystoreBody, to: &[u8; 20]) -> bool {
    keystore.entries.iter().any(|e| {
        e.purpose == KeyPurpose::AgentTransferK1
            && <[u8; 65]>::try_from(e.public_identity.as_slice())
                .ok()
                .and_then(|pk| crate::secp256k1::eth_address_from_uncompressed(&pk).ok())
                .is_some_and(|addr| &addr == to)
    })
}

/// SIGN_FAUCET_DISPENSE(5): treasury→known-transfer-key native dispense (TASK-7.4 §2 / slice 15-3b). It
/// reuses the SAME machinery as SIGN_TRANSFER — the identical strict 8-field EIP-155 payload, the sealed
/// chain_id, the `from`-equals-derived-address check, and the canonical internal preimage — but with three
/// faucet-tier differences: (1) the signer is the singleton `agent_faucet_treasury_k1` key (not a transfer
/// key); (2) the recipient `to` MUST match a stored `agent_transfer_k1` identity in the keystore (§2
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
/// request-SHAPE (bad CBOR, an ABSENT `key_ref`, chain_id ≠ sealed, non-empty `data`, over-width/non-minimal
/// u256) → 0x40; everything key/recipient-related for a PRESENT `key_ref` (present-but-not-found, wrong
/// purpose, `from` ≠ derived, `to` not a known transfer identity, signing failure) → uniform 0x42 (so the
/// host can't probe keystore contents); any §2 cap/budget/breaker/overflow rejection → 0x44; a candidate
/// epoch-bump overflow → 0x46. The §2 checks run only AFTER the key+recipient checks pass, so a 0x44 leaks
/// no more than a valid dispense already would. (An absent `key_ref` is a structurally-incomplete request,
/// host-observable from its own bytes, so 0x40 leaks nothing — matches SIGN_TRANSFER; see §1 doc.)
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
    let req_chain_id = map_get(payload, 1)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let req_from = map_get(payload, 2)
        .and_then(as_bytes_n::<20>)
        .ok_or(AgentError::Malformed)?;
    let to = map_get(payload, 3)
        .and_then(as_bytes_n::<20>)
        .ok_or(AgentError::Malformed)?;
    let value_be = map_get(payload, 4)
        .and_then(as_u256_minimal_be)
        .ok_or(AgentError::Malformed)?;
    let nonce = map_get(payload, 5)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let gas_limit = map_get(payload, 6)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let gas_price_be = map_get(payload, 7)
        .and_then(as_u256_minimal_be)
        .ok_or(AgentError::Malformed)?;
    // data MUST be present and empty (native dispenses only — no calldata/memo, §2).
    let data = map_get(payload, 8)
        .and_then(as_bytes)
        .ok_or(AgentError::Malformed)?;
    if !data.is_empty() {
        return Err(AgentError::Malformed);
    }
    // §1 pre-build check: chain_id MUST equal the sealed 2D chain_id (never request-authoritative).
    if req_chain_id != keystore.config.twod_chain_id {
        return Err(AgentError::Malformed);
    }
    // Lift the canonical minimal-BE wire `amount`/`gas_price` into the right-aligned `[u8; 32]` arithmetic
    // form HERE — in the request-SHAPE (0x40) region, BEFORE the key/recipient (0x42) checks — so the
    // anti-oracle band ordering holds structurally: every shape error (incl. a u256-width reject) precedes
    // the key band, and no post-key path can emit a lower band. (`as_u256_minimal_be` already bounded these
    // to ≤32 bytes, so `from_minimal_be` cannot widen-reject — the `ok_or(Malformed)` is unreachable
    // defense-in-depth, and now correctly sits in the 0x40 region even if it ever became reachable.)
    let amount = crate::u256::from_minimal_be(&value_be).ok_or(AgentError::Malformed)?;
    let gas_price = crate::u256::from_minimal_be(&gas_price_be).ok_or(AgentError::Malformed)?;
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
    // §2 recipient allowlist (AC#5): `to` MUST match a stored agent_transfer_k1 identity (a named,
    // separately-unit-tested seam — `is_known_transfer_recipient` — so this fund-custody gate is a
    // reviewable unit, not an inline closure that a refactor could silently widen). Recipient-not-found
    // collapses into the same per-key 0x42 bucket (anti-oracle): a host WITHOUT valid treasury credentials
    // cannot distinguish recipient-not-found from a missing/mis-purposed treasury key (both 0x42). (A host
    // WITH valid treasury credentials can still distinguish 0x44=known-recipient-over-cap from 0x42 by
    // varying `to`, but every transfer address is already host-derivable via PUBLIC_IDENTITY — see the §2
    // doc — so this leaks nothing new.)
    if !is_known_transfer_recipient(keystore, &to) {
        return Err(AgentError::KeyPurposeMismatch);
    }
    // §2 accept-gate + atomic dual-counter debit, using the pre-lifted `amount`/`gas_price`. The faucet
    // gate caps worst_case = amount + gas_limit*gas_price and debits cumulative_native_spend +
    // lifetime_spend; ANY cap/overflow collapses to 0x44 (anti-oracle: the host can't tell WHICH cap
    // tripped). Runs only AFTER the key+recipient checks, so a 0x44 reveals nothing a valid dispense
    // wouldn't (and is strictly above the 0x40/0x42 bands those checks emit).
    let new_faucet = keystore
        .faucet
        .accept_and_debit(&amount, gas_limit, &gas_price)
        .map_err(|_| AgentError::CapExceeded)?;
    // Sign the dispense (pure — the signature bytes do not leave the enclave until the frame layer's
    // seal-before-emit commit succeeds). Collapse a signing failure (the ~2^-128 x-reduced recovery_id
    // rejection / recovery==from invariant) to the per-key bucket (0x42) — NOT SealFailed (0x46 is
    // reserved for the frame layer's seal/anchor-commit failure).
    let fields = EthTransferFields {
        chain_id: req_chain_id,
        nonce,
        gas_limit,
        to,
        value_be,
        gas_price_be,
    };
    let signed = sign_transfer(&keypair, &fields).map_err(|_| AgentError::KeyPurposeMismatch)?;
    // CANDIDATE: clone live → install the debited faucet → advance the EpochOnly commit (freshness_epoch
    // ONLY; the debit changed the marks surfaces cumulative_native_spend/lifetime_spend, which the
    // frame-layer commit's `compute_local_marks_digest` picks up). Derive the bump class from the
    // single-source classifier (EpochOnly — a faucet debit is anchor-reconstructable via AdoptForward)
    // rather than a hardcoded bool; an epoch overflow fails closed (0x46) with no swap.
    let mut candidate = keystore.clone();
    candidate.faucet = new_faucet;
    let bumps_structural = matches!(
        AgentOpcode::SignFaucetDispense.commit_bump_class(),
        CommitBumpClass::Structural
    );
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

/// Canonical CBOR of the CONFIGURE_TREASURY command params (slice 15-4) — the exact bytes hashed into
/// `payload_binding` (mirrors [`generate_keys_canonical_params`]). The map mirrors the request payload
/// (envelope key 7) 1:1: `{1: sub_op, 2: <field2 u256 minimal-BE>, [3: max_gas_limit, 4: max_fee_rate]}`,
/// keys 3,4 present iff `sub_op == 0 set_limits`. `field2_minimal_be` is the ON-THE-WIRE minimal
/// big-endian byte string (as validated by `agent_cbor::as_u256_minimal_be`), NOT the lifted `[u8; 32]`,
/// so a conformant cap issuer and this verifier produce byte-identical preimages. `pub(crate)` so the
/// handler + tests single-source the wire layout (no drift). `sub_op` is bound BOTH here (map key 1) and
/// as the `payload_binding` preimage's 2nd byte — intentional belt-and-suspenders; the caller passes the
/// same `sub_op` to both.
#[cfg_attr(not(feature = "agent-configure-treasury-preview"), allow(dead_code))]
pub(crate) fn configure_treasury_canonical_params(
    sub_op: u8,
    field2_minimal_be: &[u8],
    set_limits_gas_fields: Option<(u64, u64)>,
) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_uint};
    // set_limits(0) carries 4 keys {1,2,3,4}; every other sub-op carries 2 keys {1,2}.
    debug_assert_eq!(
        sub_op == 0,
        set_limits_gas_fields.is_some(),
        "set_limits(0) ⇔ gas fields present",
    );
    let n_keys: u64 = if set_limits_gas_fields.is_some() {
        4
    } else {
        2
    };
    let mut out = Vec::new();
    put_uint(&mut out, 5, n_keys); // definite-length map header (RFC 8949 shortest form)
    put_uint(&mut out, 0, 1);
    put_uint(&mut out, 0, u64::from(sub_op));
    put_uint(&mut out, 0, 2);
    put_bytes(&mut out, field2_minimal_be);
    if let Some((max_gas_limit, max_fee_rate)) = set_limits_gas_fields {
        put_uint(&mut out, 0, 3);
        put_uint(&mut out, 0, max_gas_limit);
        put_uint(&mut out, 0, 4);
        put_uint(&mut out, 0, max_fee_rate);
    }
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
    let purpose_code = map_get(payload, 1)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let count = map_get(payload, 2)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
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
    // AC#14 audit record is appended AFTER the candidate is fully finalized (entries + counter +
    // atomic epoch/structural bump) — see the `record_audit` call below at the post-bump site. The
    // `last_exported_seq` backpressure DRAIN (re-enabling appends once the ring fills) is the
    // EXPORT_BACKUP path and remains deferred to slice 4c; 4b only RESPECTS backpressure on append.
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
    let bumps_structural = matches!(
        AgentOpcode::GenerateKeys.commit_bump_class(),
        CommitBumpClass::Structural
    );
    candidate
        .advance_commit_epoch(bumps_structural)
        .map_err(|_| AgentError::SealFailed)?;
    // AC#14 audit record (slice 4b): append this privileged op's FULL provenance onto the CANDIDATE ring
    // BEFORE it leaves the handler. The seam (`commit_before_emit`) re-runs `validate()` at seal time and
    // forbids candidate mutation between seal and anchor-commit, so the record MUST already be in the body
    // here — never inside the seal/commit closure. Provenance:
    //   op                       = the wire opcode
    //   (authority, scope_class, scope_target) + counter = the accepted cap's full identity + its per-scope
    //                              batch sequence (counter is per-(authority,scope), so scope disambiguates)
    //   request_id               = the logical-op id (anchor idempotency key), ties the record to this call
    //   config_version           = the FINALIZED candidate's treasury config version. GENERATE_KEYS does not
    //                              bump it (so candidate == live here), but reading from `candidate` (the
    //                              state actually being sealed) is the robust default: a future handler that
    //                              copies this pattern AND bumps config before the audit append (e.g. 4c
    //                              CONFIGURE_TREASURY) records the post-bump version, not a stale live one.
    // Fail-closed: a full undrained ring (`AuditBackpressure`) or `next_seq` overflow (`MonotonicOverflow`)
    // collapses to `SealFailed` (0x46) — UNLIKE counter-table-full (`CapExceeded`/0x44): audit-ring fullness
    // is SEALED state on the untrusted host, so a distinct code would be an oracle; it folds to the generic
    // seal-class failure. The handler returns BEFORE the frame reaches `commit_before_emit` — no seal, no
    // anchor commit, no swap.
    candidate
        .record_audit(&crate::agent_keystore::AuditAppend {
            op: env.opcode,
            authority: &verified.authority,
            counter: verified.counter,
            config_version: candidate.config.monotonic_treasury_config_version,
            scope_class: verified.scope_class,
            scope_target: &verified.scope_target,
            request_id: &env.request_id,
        })
        .map_err(|_| AgentError::SealFailed)?;
    Ok(AgentResponse::GenerateKeys {
        keys,
        candidate: Box::new(candidate),
        request_id: env.request_id.clone(),
    })
}

/// CONFIGURE_TREASURY(6) (slice 15-4): after a verified admin/recovery capability, apply ONE faucet-config
/// sub-op to a CANDIDATE clone, bump the monotonic `config_version`, and advance the sub-op's commit
/// epoch. Returns the candidate for the frame layer to seal → anchor-commit → swap → emit (no live
/// mutation here; a config op signs nothing — the only emitted artifact is the sealed blob).
///
/// Compiled always (so its imports/helpers stay "used") but only CALLED under
/// `agent-configure-treasury-preview` — without it, dispatch routes CONFIGURE_TREASURY to NotConfigured.
///
/// Anti-oracle §10.9 band order: request shape/decode (0x40) → sub-op binding + payload_binding +
/// financial scope (0x43) → quantitative limits + counter table (0x44) → config_version / epoch / (frame
/// seam) seal+commit (0x46). There is NO 0x42 band — treasury config is the singleton `FaucetState`, with
/// no `key_ref` / key lookup.
#[cfg_attr(not(feature = "agent-configure-treasury-preview"), allow(dead_code))]
fn handle_configure_treasury(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
    verified: &VerifiedCapability,
) -> Result<AgentResponse, AgentError> {
    use crate::agent_cbor::as_u256_minimal_be;

    // ---- ORDER 3: request shape / payload decode (0x40 Malformed) ----
    // payload (envelope key 7) = strict `{1: sub_op, ...per-sub-op fields}`. Decode the selector first.
    let payload = env.payload.as_deref().ok_or(AgentError::Malformed)?;
    let sub_op_u64 = map_get(payload, 1)
        .and_then(as_u64)
        .ok_or(AgentError::Malformed)?;
    let sub_op = u8::try_from(sub_op_u64).map_err(|_| AgentError::Malformed)?;

    // Decoded + lifted per-sub-op fields, carried from the shape phase to the mutation phase so the
    // anti-oracle band order (decode 0x40 → bind 0x43 → limits 0x44) is preserved.
    enum Params {
        SetLimits {
            per_dispense_max: [u8; 32],
            max_gas_limit: u64,
            max_fee_rate: u64,
        },
        RefillBudget {
            new_budget: [u8; 32],
        },
        RaiseBreaker {
            new_threshold: [u8; 32],
        },
        ResetBreaker {
            target_lifetime_spend: [u8; 32],
        },
    }
    // Read a u256 field: BOTH the on-wire minimal-BE bytes (for the canonical_params preimage) and the
    // lifted `[u8; 32]` (for mutation/comparison). `as_u256_minimal_be` already bounds len ≤ 32, so
    // `from_minimal_be` cannot widen-reject — the `ok_or` is defense-in-depth (matches the faucet handler).
    let read_u256 = |key: u64| -> Result<(Vec<u8>, [u8; 32]), AgentError> {
        let minimal = map_get(payload, key)
            .and_then(as_u256_minimal_be)
            .ok_or(AgentError::Malformed)?;
        let lifted = crate::u256::from_minimal_be(&minimal).ok_or(AgentError::Malformed)?;
        Ok((minimal, lifted))
    };

    // A strict per-sub-op key count rejects extra/duplicate/unknown keys (anti-oracle 0x40). An unknown
    // sub-op (> 3) is a structural field error ⇒ 0x40.
    let (params, canonical_params) = match sub_op {
        0 => {
            // set_limits: {1: sub_op, 2: per_dispense_max(u256), 3: max_gas_limit(u64), 4: max_fee_rate(u64)}
            if payload.len() != 4 {
                return Err(AgentError::Malformed);
            }
            let (f2_min, per_dispense_max) = read_u256(2)?;
            let max_gas_limit = map_get(payload, 3)
                .and_then(as_u64)
                .ok_or(AgentError::Malformed)?;
            let max_fee_rate = map_get(payload, 4)
                .and_then(as_u64)
                .ok_or(AgentError::Malformed)?;
            let cp = configure_treasury_canonical_params(
                sub_op,
                &f2_min,
                Some((max_gas_limit, max_fee_rate)),
            );
            (
                Params::SetLimits {
                    per_dispense_max,
                    max_gas_limit,
                    max_fee_rate,
                },
                cp,
            )
        }
        1 => {
            // refill_budget: {1: sub_op, 2: new_cumulative_signing_budget(u256)}
            if payload.len() != 2 {
                return Err(AgentError::Malformed);
            }
            let (f2_min, new_budget) = read_u256(2)?;
            (
                Params::RefillBudget { new_budget },
                configure_treasury_canonical_params(sub_op, &f2_min, None),
            )
        }
        2 => {
            // raise_lifetime_breaker: {1: sub_op, 2: new_circuit_breaker_threshold(u256)}
            if payload.len() != 2 {
                return Err(AgentError::Malformed);
            }
            let (f2_min, new_threshold) = read_u256(2)?;
            (
                Params::RaiseBreaker { new_threshold },
                configure_treasury_canonical_params(sub_op, &f2_min, None),
            )
        }
        3 => {
            // reset_lifetime_breaker: {1: sub_op, 2: target_lifetime_spend(u256)}
            if payload.len() != 2 {
                return Err(AgentError::Malformed);
            }
            let (f2_min, target_lifetime_spend) = read_u256(2)?;
            (
                Params::ResetBreaker {
                    target_lifetime_spend,
                },
                configure_treasury_canonical_params(sub_op, &f2_min, None),
            )
        }
        _ => return Err(AgentError::Malformed), // unknown sub-op (§10.9 0x40)
    };

    // ---- ORDER 4: capability binding (0x43 CapabilityRejected) ----
    // (4a) Bind the request's sub-op to the cap's signed `treasury_sub_op` (§10.7). LOAD-BEARING for tier
    // separation: the verify-layer tier check (admin vs recovery) keys off the cap's sub-op, so without
    // this an admin cap (sub_op ∈ {0..2}) carrying a `payload_binding` baked for sub_op 3 could authorize
    // the recovery-tier reset. (`payload_binding` alone does not close it — see VerifiedCapability docs.)
    if verified.treasury_sub_op != Some(sub_op) {
        return Err(AgentError::CapabilityRejected);
    }
    // (4b) payload_binding: recompute keccak256(opcode ‖ sub_op ‖ request_id ‖ canonical_params) and
    // compare to the cap's signed value, so the host cannot have altered the sub-op fields under a valid
    // cap. → 0x43.
    let computed = crate::agent_capability::payload_binding(
        env.opcode,
        Some(sub_op),
        &env.request_id,
        &canonical_params,
    );
    if computed != verified.payload_binding {
        return Err(AgentError::CapabilityRejected);
    }
    // (4c) Financial scope policy (§10.5/§10.6 AC#12): treasury config MUST be enclave-scoped
    // (scope_class == 0) so a fleet-scoped cap can't reconfigure a treasury across clones. → 0x43.
    // DEFERRED (TASK-18 un-gate prereq, IDENTICAL to handle_generate_keys): this checks scope_class only;
    // it does NOT yet bind `verified.scope_target` to a sealed enclave id, so an enclave-scoped cap is not
    // yet pinned to ONE enclave (a clone with the same authority/chain/env/counter could accept it). The
    // `scope_target`↔sealed-enclave-id binding is a release-ban un-gate precondition (see lib.rs) shared by
    // ALL preview-gated privileged ops; CONFIGURE_TREASURY is preview-banned (non-production) until it lands.
    if verified.scope_class != 0 {
        return Err(AgentError::CapabilityRejected);
    }

    // ---- ORDER 5 + 6: quantitative checks (0x44) + mutation on the CANDIDATE clone ----
    // The CANDIDATE is mutated locally; nothing is live until the frame layer's seal-before-emit commit.
    // Each sub-op touches ONLY its own field(s) (`..` keeps the rest), so the spend/breaker carry-over over
    // treasury-key rotation (AC#17 — `FaucetState` is keyed independently of any `key_ref`) is preserved.
    let mut candidate = keystore.clone();
    match params {
        Params::SetLimits {
            per_dispense_max,
            max_gas_limit,
            max_fee_rate,
        } => {
            // Forward config — no ordering constraint vs current spend; touches ONLY the limit triple.
            candidate.faucet.per_dispense_max_amount = per_dispense_max;
            candidate.faucet.max_gas_limit = max_gas_limit;
            candidate.faucet.max_effective_gas_fee_rate = max_fee_rate;
        }
        Params::RefillBudget { new_budget } => {
            // A zero budget marks an UNCONFIGURED faucet (rejects every dispense); refilling to zero would
            // re-disable it — a regression, not a config ⇒ 0x44 (anti-oracle, collapses with the other
            // quantitative rejections). Refill RAISES/sets the ceiling AND resets the refillable spend
            // window; the genesis-from-zero `lifetime_spend` is left untouched (only reset_lifetime_breaker
            // lowers it).
            if new_budget == [0u8; 32] {
                return Err(AgentError::CapExceeded);
            }
            candidate.faucet.cumulative_signing_budget = new_budget;
            candidate.faucet.cumulative_native_spend = [0u8; 32];
        }
        Params::RaiseBreaker { new_threshold } => {
            // Anti-inversion: a breaker BELOW already-accumulated `lifetime_spend` would trip immediately
            // and is almost certainly an operator error — reject (⇒ 0x44) rather than instantly disable the
            // faucet. (`[u8; 32]` Ord is big-endian numeric.)
            if new_threshold < candidate.faucet.lifetime_spend {
                return Err(AgentError::CapExceeded);
            }
            candidate.faucet.circuit_breaker_threshold = Some(new_threshold);
        }
        Params::ResetBreaker {
            target_lifetime_spend,
        } => {
            // Recovery-tier: clears the breaker and LOWERS `lifetime_spend` to a recovery target. `target`
            // can only LOWER (≤ current) — raising `lifetime_spend` is not a reset (and would be a covert
            // spend deflation/inflation of the lifetime total) ⇒ 0x44 on target > current. Advances the
            // `strict_recovery_counter`. This op is STRUCTURAL (not EpochOnly): it LOWERS `lifetime_spend`
            // (a marks surface), which `AdoptForward`'s `marks_dominate_local` belt would reject, and it
            // also mutates non-marks state (the breaker + `config_version`) — so its effect is NOT
            // AdoptForward-reconstructable and a dropped seal must `StructuralGap`→restore (TASK-15 15-4
            // review; see `configure_treasury_sub_op_bump_class`).
            if target_lifetime_spend > candidate.faucet.lifetime_spend {
                return Err(AgentError::CapExceeded);
            }
            candidate.faucet.lifetime_spend = target_lifetime_spend;
            candidate.faucet.circuit_breaker_threshold = None;
            candidate.strict_recovery_counter = candidate
                .strict_recovery_counter
                .checked_add(1)
                .ok_or(AgentError::SealFailed)?;
        }
    }

    // Advance the capability counter on the candidate (table full ⇒ 0x44; any regression / invariant
    // break ⇒ 0x46, no swap) — mirrors handle_generate_keys.
    candidate
        .advance_counter(
            &verified.authority,
            verified.scope_class,
            &verified.scope_target,
            verified.counter,
        )
        .map_err(|e| match e {
            crate::agent_keystore::KeystoreError::CapacityExceeded => AgentError::CapExceeded,
            _ => AgentError::SealFailed,
        })?;

    // Monotonic config_version bump (EVERY sub-op): a SEPARATE checked bump from advance_commit_epoch.
    // Overflow ⇒ 0x46 (never wrap — `config_version` is a strictly-monotone audit/version stamp, NOT
    // itself a rollback control; wrapping would corrupt the audit trail / break monotonicity. The
    // anti-rollback fence is the Structural `freshness_epoch`+`structural_version` bump below, which
    // every CONFIGURE sub-op rides.)
    candidate
        .advance_treasury_config_version()
        .map_err(|_| AgentError::SealFailed)?;

    // Anti-rollback commit-epoch bump from the SUB-OP-level classifier. ALL FOUR sub-ops are Structural
    // (freshness_epoch + structural_version together) — including reset_lifetime_breaker, whose
    // marks-DECREASE + non-marks mutations are not AdoptForward-reconstructable (see the classifier docs).
    // A dropped seal therefore reconciles StructuralGap→restore for every sub-op. Overflow ⇒ 0x46, no swap.
    let bumps_structural = matches!(
        configure_treasury_sub_op_bump_class(sub_op),
        CommitBumpClass::Structural
    );
    candidate
        .advance_commit_epoch(bumps_structural)
        .map_err(|_| AgentError::SealFailed)?;

    // AC#14 audit record (slice 4c-1): append this privileged CONFIGURE op's full provenance onto the
    // finalized candidate ring — mirror of the 4b GENERATE_KEYS append. MUST be on the candidate BEFORE it
    // leaves the handler: `commit_before_emit` re-runs `validate()` at seal time and forbids candidate
    // mutation between seal and anchor-commit, so the record must already be in the body. The ONLY
    // difference from 4b is `config_version`: CONFIGURE bumped it via `advance_treasury_config_version`
    // above, so `candidate.config.monotonic_treasury_config_version` is the POST-bump value — exactly the
    // case the 4b comment anticipated by reading from the finalized candidate, not the pre-clone live body.
    // Fail-closed: `AuditBackpressure` / `MonotonicOverflow` → `SealFailed` (0x46), so the handler returns
    // BEFORE the frame reaches `commit_before_emit` — no seal, no anchor commit, no swap (anti-oracle:
    // ring fullness is sealed host-visible state, folds to the generic seal-class failure).
    candidate
        .record_audit(&crate::agent_keystore::AuditAppend {
            op: env.opcode,
            authority: &verified.authority,
            counter: verified.counter,
            config_version: candidate.config.monotonic_treasury_config_version,
            scope_class: verified.scope_class,
            scope_target: &verified.scope_target,
            request_id: &env.request_id,
        })
        .map_err(|_| AgentError::SealFailed)?;

    Ok(AgentResponse::ConfigureTreasury {
        candidate: Box::new(candidate),
        request_id: env.request_id.clone(),
    })
}

/// EXPORT_BACKUP(7) selector (envelope key 7): `{}` (ALL keys), `{1: [key_ref…]}` (explicit refs), or
/// `{2: batch_id}` (all keys minted under one capability batch). Exactly one form.
#[cfg(feature = "agent-backup-export-preview")]
enum ExportSelector {
    All,
    KeyRefs(Vec<[u8; 32]>),
    BatchId(u64),
}

/// Canonical CBOR of the EXPORT selector — the exact bytes hashed into `payload_binding` (mirrors
/// [`generate_keys_canonical_params`]); the map mirrors the request payload 1:1 so a conformant cap issuer
/// and this verifier produce byte-identical preimages.
#[cfg(feature = "agent-backup-export-preview")]
fn export_canonical_params(selector: &ExportSelector) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_uint};
    let mut out = Vec::new();
    match selector {
        ExportSelector::All => put_uint(&mut out, 5, 0), // empty map {}
        ExportSelector::KeyRefs(refs) => {
            put_uint(&mut out, 5, 1); // 1-key map {1: [..]}
            put_uint(&mut out, 0, 1);
            put_uint(&mut out, 4, refs.len() as u64); // array header
            for r in refs {
                put_bytes(&mut out, r);
            }
        }
        ExportSelector::BatchId(id) => {
            put_uint(&mut out, 5, 1); // 1-key map {2: id}
            put_uint(&mut out, 0, 2);
            put_uint(&mut out, 0, *id);
        }
    }
    out
}

/// Decode + strictly validate the EXPORT selector from the key-7 payload map. Both keys present, an empty
/// `key_refs` array, a non-32-byte ref, an over-cap array, or any stray key ⇒ Malformed.
#[cfg(feature = "agent-backup-export-preview")]
fn decode_export_selector(payload: &[(Value, Value)]) -> Result<ExportSelector, AgentError> {
    match (map_get(payload, 1), map_get(payload, 2)) {
        (None, None) if payload.is_empty() => Ok(ExportSelector::All),
        (Some(v), None) if payload.len() == 1 => {
            let items = match v {
                Value::Array(a) => a,
                _ => return Err(AgentError::Malformed),
            };
            if items.is_empty() || items.len() > crate::agent_keystore::MAX_TOTAL_KEY_ENTRIES {
                return Err(AgentError::Malformed);
            }
            let mut refs = Vec::with_capacity(items.len());
            for it in items {
                refs.push(crate::agent_cbor::as_bytes32(it).ok_or(AgentError::Malformed)?);
            }
            Ok(ExportSelector::KeyRefs(refs))
        }
        (None, Some(v)) if payload.len() == 1 => Ok(ExportSelector::BatchId(
            as_u64(v).ok_or(AgentError::Malformed)?,
        )),
        _ => Err(AgentError::Malformed), // both keys, or a stray key alongside one
    }
}

/// EXPORT_BACKUP(7) (TASK-13b slice 4c-2b): after a verified admin capability, mint a `pq-agent-backup-v1`
/// DR backup of the requested keys to the operator's OFFLINE recovery key, and DRAIN the audit ring (this
/// op IS the authenticated pull-export). On a CANDIDATE clone: append the EXPORT audit event → FULL drain
/// (append-then-drain, so the drain covers the export's own record — but EXPORT is subject to the SAME
/// backpressure on its append, so it is NOT a guaranteed escape hatch; see the drain-call note below) →
/// Structural bump → build the `restore-ingress-v1` payload from the post-append candidate → seal the
/// KEM-DEM backup blob. Returns the candidate (for the frame layer to seal→commit→swap) + the backup blob
/// (emitted alongside the new sealed keystore). EXPORT does NOT bump `config_version` (so the audit
/// `config_version` reads live==candidate). Any failure ⇒ `SealFailed` (0x46) before the seam — no commit.
///
/// Compiled + CALLED only under `agent-backup-export-preview` (release-banned); without it EXPORT routes to
/// NotConfigured (the deferred-stub path). `crate::agent_backup` itself only exists under this feature.
#[cfg(feature = "agent-backup-export-preview")]
fn handle_export_backup(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
    verified: &VerifiedCapability,
) -> Result<AgentResponse, AgentError> {
    let payload = env.payload.as_deref().ok_or(AgentError::Malformed)?;
    let selector = decode_export_selector(payload)?;

    // payload_binding (§10.5, last gate before mutation): recompute over the canonical selector + compare to
    // the cap's signed value, so the host cannot have altered the selector under a valid cap. → 0x43.
    let computed = crate::agent_capability::payload_binding(
        env.opcode,
        None,
        &env.request_id,
        &export_canonical_params(&selector),
    );
    if computed != verified.payload_binding {
        return Err(AgentError::CapabilityRejected);
    }

    // Resolve the selector → requested key refs (body order). An explicit ref not in the body, or a
    // selector matching ZERO keys, collapses to the key-not-found band (0x42, anti-oracle §10.9).
    let requested: Vec<[u8; 32]> = match &selector {
        ExportSelector::All => keystore.entries.iter().map(|e| e.key_ref).collect(),
        ExportSelector::KeyRefs(refs) => {
            for r in refs {
                if !keystore.entries.iter().any(|e| &e.key_ref == r) {
                    return Err(AgentError::KeyPurposeMismatch);
                }
            }
            refs.clone()
        }
        ExportSelector::BatchId(id) => keystore
            .entries
            .iter()
            .filter(|e| e.creation_metadata.batch_id == *id)
            .map(|e| e.key_ref)
            .collect(),
    };
    if requested.is_empty() {
        return Err(AgentError::KeyPurposeMismatch); // nothing matched the selector
    }

    // CANDIDATE: clone live → consume the cap counter (anti-replay) → append EXPORT audit event → FULL
    // drain → Structural bump. ALL mutation here, BEFORE the seam (commit_before_emit forbids mutation
    // between seal and commit).
    let mut candidate = keystore.clone();
    // Advance the capability counter (anti-replay), mirroring GENERATE_KEYS/CONFIGURE — a host cannot
    // replay an EXPORT cap to re-drain/re-export. Counter-table full → CapExceeded (0x44); any other
    // invariant break → SealFailed (0x46), no swap.
    candidate
        .advance_counter(
            &verified.authority,
            verified.scope_class,
            &verified.scope_target,
            verified.counter,
        )
        .map_err(|e| match e {
            crate::agent_keystore::KeystoreError::CapacityExceeded => AgentError::CapExceeded,
            _ => AgentError::SealFailed,
        })?;
    candidate
        .record_audit(&crate::agent_keystore::AuditAppend {
            op: env.opcode,
            authority: &verified.authority,
            counter: verified.counter,
            config_version: candidate.config.monotonic_treasury_config_version,
            scope_class: verified.scope_class,
            scope_target: &verified.scope_target,
            request_id: &env.request_id,
        })
        .map_err(|_| AgentError::SealFailed)?;
    // FULL drain AFTER the append, so `last_exported_seq → next_seq-1` covers the just-appended export
    // record ("this export IS the pull", no delta-export weakening). NOTE: because EXPORT appends FIRST, it
    // is subject to the SAME backpressure — a ring already saturated with un-exported records fails the
    // append above (0x46) and this drain never runs. EXPORT is NOT a guaranteed escape hatch; that is the
    // fail-closed-safe choice (drain-before-append would evict un-exported history). See the
    // keystore-backup-format §5 note + the `export_saturated_undrained_ring_fails_closed` test.
    candidate
        .advance_export_high_water()
        .map_err(|_| AgentError::SealFailed)?;
    let bumps_structural = matches!(
        AgentOpcode::ExportBackup.commit_bump_class(),
        CommitBumpClass::Structural
    );
    candidate
        .advance_commit_epoch(bumps_structural)
        .map_err(|_| AgentError::SealFailed)?;

    // Build the DR blob from the POST-append candidate (so it captures the export's own audit record). The
    // manifest is built from the SAME ordered refs as the payload entries (structural consistency).
    let ordered = crate::agent_backup::selected_key_refs(&candidate, &requested);
    let payload_bytes = crate::agent_backup::build_restore_ingress_payload(&candidate, &ordered)
        .map_err(|_| AgentError::SealFailed)?;
    let manifest = crate::agent_backup::build_key_refs_manifest(&ordered)
        .map_err(|_| AgentError::SealFailed)?;
    let recovery_key = &candidate.config.backup_recovery_wrapping_pubkey;
    let recovery_key_id = crate::agent_backup::derive_recovery_key_id(recovery_key);
    let backup_blob = crate::agent_backup::seal_backup_blob(
        recovery_key,
        &recovery_key_id,
        candidate.config.twod_chain_id,
        &candidate.config.environment_identifier,
        &manifest,
        &payload_bytes,
    )
    .map_err(|_| AgentError::SealFailed)?;

    Ok(AgentResponse::ExportBackup {
        candidate: Box::new(candidate),
        backup_blob,
        request_id: env.request_id.clone(),
    })
}

/// Canonical CBOR of the RESTORE_BACKUP request params — the exact bytes hashed into `payload_binding`
/// (HIGH #1, compact 9499). `{1: requested_refs(array<32B bstr>), 2: backup_digest(32B bstr)}` — binds
/// the cap to the key selector + the exact backup the recovery authority authorized.
#[cfg(feature = "agent-backup-export-preview")]
fn restore_canonical_params(requested_refs: &[[u8; 32]], backup_digest: &[u8; 32]) -> Vec<u8> {
    use crate::agent_capability::{put_bytes, put_uint};
    let mut out = Vec::new();
    put_uint(&mut out, 5, 2); // map(2) — major type 5 (NOT the composed byte 0xA0; put_uint shifts major<<5)
    put_uint(&mut out, 0, 1); // key 1: requested_refs
    put_uint(&mut out, 4, requested_refs.len() as u64); // array(n) — major type 4 (NOT 0x80)
    for r in requested_refs {
        put_bytes(&mut out, r);
    }
    put_uint(&mut out, 0, 2); // key 2: backup_digest
    put_bytes(&mut out, backup_digest);
    out
}

/// RESTORE_BACKUP(8) handler (TASK-24): the recovery ceremony — reconstitute the agent keystore inside
/// this enclave from an attested ingress envelope (the operator's re-wrap of a DR backup to this TEE's
/// ephemeral key), gated by the AC#6 authenticated high-water. Pure COMPOSITION of the tested primitives
/// (each AC is enforced at its step); EVERY error path ⇒ a §10.9 code with NO partial import + NO
/// counter/anchor/ephemeral advance (the frame layer retires the ephemeral + commits ONLY on success).
///
/// `verified` is the RECOVERY-tier capability (verify_capability already checked `is_recovery` — an
/// admin-signed restore is rejected at the tier check, AC#10). `measurement` is this enclave's own
/// attested measurement (the AAD' `dest_measurement == OWN` check).
#[cfg(feature = "agent-backup-export-preview")]
fn handle_restore_backup(
    env: &AgentEnvelope,
    keystore: &KeystoreBody,
    verified: &VerifiedCapability,
    measurement: &[u8],
) -> Result<AgentResponse, AgentError> {
    use crate::agent_backup::{
        adopt_ac6_high_water, apply_restore_to_body, decode_restore_request,
        open_restore_ingress_envelope, parse_restore_ingress, verify_ac6_high_water,
        verify_recovery_high_water, verify_restore_ingress,
    };
    use ml_kem::{DecapsulationKey, MlKem1024};
    use zeroize::Zeroize;

    // (1) Decode the request body: ingress envelope + original backup + key_refs selector + signed high-water.
    let req = decode_restore_request(env.payload.as_deref().ok_or(AgentError::Malformed)?)
        .map_err(|_| AgentError::Malformed)?;
    // (2) Snapshot the published ephemeral + reconstruct the decaps key. No ephemeral published (GET_RESTORE_PUBKEY
    //     not run / already retired) ⇒ the ceremony cannot proceed ⇒ fail closed (the operator must publish one first).
    let snap = snapshot_restore_ephemeral().ok_or(AgentError::NotConfigured)?;
    let mut seed_temp = *snap.decaps_seed; // copy out of Zeroizing for Seed::from (which takes by value)
    let dest_dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(seed_temp));
    seed_temp.zeroize(); // scrub the explicit copy (ml_kem's zeroize feature scrubs its internal copy on drop)
                         // (3) Open the attested ingress envelope (AC#1: decap with the ephemeral private key + AEAD-tag verify over AAD').
    let opened = open_restore_ingress_envelope(&dest_dk, &req.ingress_envelope)
        .map_err(|_| AgentError::SealFailed)?;
    // (4) Parse the restore-ingress payload (AC#2: magic/version/strict-CBOR).
    let data = parse_restore_ingress(&opened.payload).map_err(|_| AgentError::Malformed)?;
    // (5) AAD' semantic checks + AC#9 set-match (AC#1: measurement==OWN, chain/env==sealed, manifest/backup-digest match).
    verify_restore_ingress(
        &opened,
        &data,
        &req.original_backup,
        &req.requested_refs,
        measurement,
        keystore.config.twod_chain_id,
        keystore.config.environment_identifier.as_bytes(),
    )
    .map_err(|_| AgentError::SealFailed)?;
    // (5c) AC#10 wrapping-key separation (compact 9611 HIGH): the backup was sealed to the SAME recovery
    //      wrapping key this enclave holds. The AAD' `original_backup_digest` check above only confirms the
    //      operator re-wrapped the EXACT authorized backup; it does NOT confirm that backup was sealed to
    //      this enclave's `backup_recovery_wrapping_pubkey`. A backup sealed to a different ML-KEM key
    //      (e.g. authorized by the recovery authority but from a different fleet's wrapping key) would
    //      otherwise decrypt to garbage here; enforcing the header's `recovery_key_id` == the sealed key's
    //      derived id closes the AC#10 "distinct authority vs wrapping-key roles" invariant.
    let sealed_rid = crate::agent_backup::derive_recovery_key_id(
        &keystore.config.backup_recovery_wrapping_pubkey,
    );
    let backup_rid = crate::agent_backup::backup_recovery_key_id(&req.original_backup)
        .map_err(|_| AgentError::Malformed)?;
    if backup_rid != sealed_rid.as_slice() {
        return Err(AgentError::SealFailed);
    }
    // (5b) HIGH #1 (compact 9499): payload_binding — bind the cap to THIS restore's params (the key
    //      selector + the backup digest). A cap issued for one restore cannot authorize a different one.
    let canonical = restore_canonical_params(&req.requested_refs, &opened.original_backup_digest);
    let expected_binding =
        crate::agent_capability::payload_binding(8, None, &env.request_id, &canonical);
    if expected_binding != verified.payload_binding {
        return Err(AgentError::CapabilityRejected);
    }
    // (6) Verify the recovery-authority-signed high-water (AC#6 source (a): signature vs recovery_authority_pk
    //     + strict-decode the marks, bound to this ceremony's request_id).
    let authenticated = verify_recovery_high_water(
        &req.recovery_high_water,
        keystore.config.twod_chain_id,
        &keystore.config.environment_identifier,
        &env.request_id,
        &keystore.config.recovery_authority_pk,
    )
    .map_err(|_| AgentError::CapabilityRejected)?;
    // (7) AC#6 forward-only gate: authenticated >= backup (not stale) + >= destination-pre-restore (never lowers).
    verify_ac6_high_water(keystore, &data, &authenticated).map_err(|_| AgentError::SealFailed)?;
    // (8) Wholesale-replace the restorable state + reconstruct audit cursors + advance strict_recovery (AC#3/#7/#6).
    //     AC#7: capacity from the RESTORE-time policy (the destination's own `audit.capacity`, NOT the backup).
    let mut candidate = keystore.clone();
    apply_restore_to_body(&mut candidate, &data, keystore.audit.capacity)
        .map_err(|_| AgentError::SealFailed)?;
    // (9) AC#6 adopt: raise the candidate's counters/spend to the authenticated high-water (the current state).
    adopt_ac6_high_water(&mut candidate, &authenticated);
    // (9b) HIGH #2 (compact 9516): record the cap counter for anti-replay. advance_counter would REJECT
    //      (CounterRegression) if the backup/adopted marks already carry the recovery/"restore_backup"
    //      counter tuple at a higher value than the cap's counter. RESTORE must use max (not strict >):
    //      the candidate's counters were wholesale-replaced from the source + adopted from the authenticated
    //      marks, so a source-history row at a higher value is EXPECTED, not a replay.
    {
        let env_id = candidate.config.environment_identifier.clone();
        if let Some(c) = candidate.counters.iter_mut().find(|c| {
            &c.authority == &verified.authority
                && c.environment_identifier == env_id
                && c.scope_class == verified.scope_class
                && c.scope_target == verified.scope_target
        }) {
            c.highest_accepted_counter = c.highest_accepted_counter.max(verified.counter);
        } else if candidate.counters.len() >= crate::agent_keystore::MAX_COUNTER_ENTRIES {
            return Err(AgentError::CapExceeded);
        } else {
            candidate
                .counters
                .push(crate::agent_keystore::CounterEntry {
                    authority: verified.authority,
                    environment_identifier: env_id,
                    scope_class: verified.scope_class,
                    scope_target: verified.scope_target.clone(),
                    highest_accepted_counter: verified.counter,
                });
        }
    }
    // (10) Enclave-local structural_version = local+1 (AC#4, the `local+1` strategy; Structural commit class).
    candidate
        .advance_commit_epoch(true)
        .map_err(|_| AgentError::SealFailed)?;
    // (11) Return the candidate; the frame layer seals → commits → swaps → emits → retires the ephemeral.
    Ok(AgentResponse::RestoreBackup {
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
            *guard = Some(InstalledAgentKeystore {
                body,
                measurement: enclave_measurement.to_vec(),
            });
            true
        }
        _ => false,
    }
}

/// Whether an agent keystore is installed (i.e. this instance runs the Agent Gateway profile).
pub fn is_agent_keystore_installed() -> bool {
    INSTALLED_KEYSTORE
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false)
}

#[cfg(test)]
pub fn reset_agent_keystore_for_tests() {
    if let Ok(mut guard) = INSTALLED_KEYSTORE.lock() {
        *guard = None;
    }
}

// ---------------------------------------------------------------------------------------------------
// TASK-24 Slice 2a-i: the destination TEE's ATTESTED EPHEMERAL ML-KEM-1024 keypair lifecycle — the
// restore-ceremony key the operator re-wraps the backup to (the `dest_ephemeral_pubkey` of the
// `2d-hsm-agent-restore-ingress-v1` envelope, Slice 1). Generated on demand by the GET_RESTORE_PUBKEY
// opcode (Sub-slice 2a-ii); held in a process-global; SINGLE-USE (retired after one successful restore,
// so a second ceremony needs a fresh key + fresh attestation — claude-code AC#1 review: forbid reusing
// one attested ephemeral key across multiple restores). Gated by `agent-backup-export-preview` (pulls
// ml-kem), same as the whole DR-backup path.
// ---------------------------------------------------------------------------------------------------

/// The destination's attested restore-ephemeral keypair, held in [`INSTALLED_RESTORE_EPHEMERAL`] between
/// the GET_RESTORE_PUBKEY opcode (which generates + publishes the pubkey half) and the RESTORE_BACKUP
/// handler (which decapsulates with the private half via [`crate::agent_backup::open_restore_ingress_
/// envelope`]). The DECAPS key is stored as its 64-byte SEED (not the materialized `DecapsulationKey`) so
/// the slot is `Send` without depending on ml-kem's `Send` impls, AND so the private key is only
/// materialized briefly inside the restore decap (reconstructed via `DecapsulationKey::from_seed`, used,
/// dropped) — minimizing the window the decaps key exists in memory. The seed is `Zeroizing` (scrubbed on
/// drop / retire).
#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (held only by the fns below, wired in 2a-ii/2b)
struct InstalledRestoreEphemeral {
    /// The 1568-byte attested encapsulation (public) key the operator re-wraps to (the opcode returns it).
    encaps_key: Vec<u8>,
    /// The 64-byte ML-KEM keypair seed — reconstructs the decapsulation (private) key on demand. Sensitive
    /// (with the measurement + attestation it IS the ceremony private key); `Zeroizing`.
    decaps_seed: zeroize::Zeroizing<[u8; 64]>,
    /// The attestation measurement this ephemeral key was published under — IS the `dest_measurement`
    /// the RESTORE handler checks against the envelope's AAD' (`opened.dest_measurement == OWN`).
    measurement: Vec<u8>,
    /// The fresh SNP attestation report whose `report_data` binds the ephemeral key to this TEE (compact
    /// 9611 HIGH #2). Returned by GET_RESTORE_PUBKEY so the operator verifies — BEFORE re-wrapping — that
    /// the key came from the attested enclave (not a host-substituted key). The report echoes
    /// `report_data_for_restore_ephemeral(encaps_key, measurement, chain, env)` and carries the AMD-signed
    /// measurement; operator verification is out-of-band (AC#12) via the cert chain below.
    attestation_report: Vec<u8>,
    /// The VCEK→ASK→ARK cert chain for the attestation report (configfs-tsm `auxblob`; best-effort — may be
    /// empty, in which case the operator fetches the chain from AMD KDS by VCEK serial).
    cert_chain: Vec<u8>,
}

/// Process-global slot for the destination restore-ephemeral keypair. Const-init `None` ⇒ no ephemeral
/// published (GET_RESTORE_PUBKEY has not run this boot, or it was retired). Volatile — lost on restart, so
/// a restart forces the operator to re-fetch a fresh ephemeral pubkey + re-wrap (the ceremony never
/// trusts a persisted key).
#[cfg(feature = "agent-backup-export-preview")]
static INSTALLED_RESTORE_EPHEMERAL: Mutex<Option<InstalledRestoreEphemeral>> = Mutex::new(None);

/// The GET_RESTORE_PUBKEY opcode response: the attested ephemeral public key + the measurement it was
/// published under (the operator verifies the attestation binds the two out-of-band — AC#12 — then
pub(crate) struct RestoreEphemeralPub {
    pub encaps_key: Vec<u8>,
    pub measurement: Vec<u8>,
    /// The fresh SNP attestation report binding the ephemeral key to this TEE (compact 9611 HIGH #2).
    /// The operator verifies the report's `report_data` + measurement out-of-band BEFORE re-wrapping.
    pub attestation_report: Vec<u8>,
    /// The VCEK→ASK→ARK cert chain for the attestation report (best-effort; may be empty).
    pub cert_chain: Vec<u8>,
}

/// Generate + install a FRESH attested restore-ephemeral ML-KEM-1024 keypair (the GET_RESTORE_PUBKEY
/// opcode's action). **Install-once**: returns `None` if an ephemeral is already installed (a second
/// GET_RESTORE_PUBKEY this boot is a no-op — the operator re-uses the already-published key until it is
/// retired by a successful restore). `measurement` is the enclave's own attestation measurement (from
/// [`INSTALLED_KEYSTORE`]); returns `None` on an empty measurement or CSPRNG failure (fail-closed — the
/// opcode returns an error, no half-installed state). The keypair is drawn from the TEE CSPRNG
/// (`getrandom`), never host-supplied.
#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (Sub-slice 2a-ii opcode wires it)
pub(crate) fn install_restore_ephemeral(
    measurement: &[u8],
    chain_id: u64,
    environment_identifier: &[u8],
) -> Option<RestoreEphemeralPub> {
    use ml_kem::{DecapsulationKey, KeyExport as _, MlKem1024};
    // An empty measurement would make the AAD' `dest_measurement == OWN` check meaningless — reject up
    // front (mirrors `install_agent_keystore`'s empty-measurement guard).
    if measurement.is_empty() {
        return None;
    }
    // A fresh 64-byte seed from the TEE CSPRNG — the ceremony private key's root. CSPRNG failure ⇒ None
    // (fail-closed; no half-install).
    let mut seed = zeroize::Zeroizing::new([0u8; 64]);
    getrandom::getrandom(&mut seed[..]).ok()?;
    let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(*seed));
    let encaps_key = dk.encapsulation_key().to_bytes().as_slice().to_vec();
    // Compact 9611 HIGH #2 (AC#1 "attested ephemeral key"): fetch a FRESH SNP attestation whose
    // report_data binds the ephemeral key to THIS TEE (measurement + chain + env), so the operator can
    // verify — before re-wrapping — that the key came from the attested enclave (not a host-substituted
    // key). On a non-SNP host the fetch fails ⇒ None (fail-closed: no attestation ⇒ no ephemeral
    // published; the restore ceremony REQUIRES a real TEE). The fixed configfs entry is safe here: the
    // producer's boot-time fetch is long-complete by ceremony time, and fetch_report unconditionally
    // cleans up the entry.
    //
    // TODO(production-un-gate, compact-9611 Med codex+gemini): `fetch_report` is UNBOUNDED (the same
    // contract as the producer GET_MEASUREMENT boot path). Unlike GET_MEASUREMENT (boot-only, before the
    // serve loop), GET_RESTORE_PUBKEY runs IN the serial agent serve loop — a stuck configfs-tsm read
    // here blocks all later requests (DoS). The crate's accepted bound is the killable subprocess
    // (quote_subprocess::HardBoundedQuoteProducer); cooperative deadlines were deliberately removed
    // ((4a)). Routing this fetch through the bounded subprocess is tracked as TASK-27 — a HARD un-gate
    // blocker (the `agent-backup-export-preview` release-ban was removed in TASK-18 18-9 and the
    // `agent-gateway-release` Nix profile enables the feature, so this DoS ships the moment RESTORE is
    // un-gated unless TASK-27 gates it). The ceremony-setup op is low-frequency (operator-called, once
    // per restore), which limits but does not eliminate the vector.
    let report_data = crate::snp_report::report_data_for_restore_ephemeral(
        &encaps_key,
        measurement,
        chain_id,
        environment_identifier,
    );
    let (attestation_report, cert_chain) = crate::snp_report::fetch_report(&report_data).ok()?;
    let pub_info = RestoreEphemeralPub {
        encaps_key: encaps_key.clone(),
        measurement: measurement.to_vec(),
        attestation_report,
        cert_chain,
    };
    let mut guard = INSTALLED_RESTORE_EPHEMERAL.lock().ok()?;
    if guard.is_some() {
        return None; // install-once: a second GET_RESTORE_PUBKEY does not overwrite the published key
    }
    *guard = Some(InstalledRestoreEphemeral {
        encaps_key,
        decaps_seed: seed,
        measurement: measurement.to_vec(),
        attestation_report: pub_info.attestation_report.clone(),
        cert_chain: pub_info.cert_chain.clone(),
    });
    Some(pub_info)
}

/// Test-only: install a DETERMINISTIC restore-ephemeral keypair from an explicit 64-byte `seed` (the
/// production [`install_restore_ephemeral`] draws from the CSPRNG). Enables the end-to-end RESTORE_BACKUP
/// dispatch test to install the GOLDEN dest-ephemeral keypair (seed `[0x6c;64]`, matching the frozen
/// `restore_ingress_envelope_v1.bin`) so the test's ingress envelope — sealed to that known pubkey —
/// decapsulates inside the handler. Same install-once + empty-measurement-reject semantics.
#[cfg(all(test, feature = "agent-backup-export-preview"))]
#[allow(dead_code)] // forward enabler for the 2c end-to-end RESTORE_BACKUP dispatch test (lands next)
pub(crate) fn install_restore_ephemeral_with_seed(
    measurement: &[u8],
    seed: &[u8; 64],
    chain_id: u64,
    environment_identifier: &[u8],
) -> Option<RestoreEphemeralPub> {
    use ml_kem::{DecapsulationKey, KeyExport as _, MlKem1024};
    if measurement.is_empty() {
        return None;
    }
    let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(*seed));
    let encaps_key = dk.encapsulation_key().to_bytes().as_slice().to_vec();
    // Compact 9611 HIGH #2: build a STAND-IN attestation report (the production path fetches a real SNP
    // quote via fetch_report, unavailable in tests). The stand-in patches the binding into report_data +
    // the measurement so the operator-verification helper runs end-to-end; the AMD-signature half of
    // verification is out-of-crate (the operator verifies the cert chain against the AMD root offline).
    let report_data = crate::snp_report::report_data_for_restore_ephemeral(
        &encaps_key,
        measurement,
        chain_id,
        environment_identifier,
    );
    let mut attestation_report = vec![0u8; crate::snp_report::MIN_REPORT_LEN];
    let rd_off = crate::snp_report::REPORT_DATA_OFFSET;
    attestation_report[rd_off..rd_off + 64].copy_from_slice(&report_data);
    let m_off = crate::snp_report::MEASUREMENT_OFFSET;
    let m_len = measurement
        .len()
        .min(crate::snp_report::SNP_MEASUREMENT_LEN);
    attestation_report[m_off..m_off + m_len].copy_from_slice(&measurement[..m_len]);
    let pub_info = RestoreEphemeralPub {
        encaps_key: encaps_key.clone(),
        measurement: measurement.to_vec(),
        attestation_report: attestation_report.clone(),
        cert_chain: Vec::new(), // stand-in: no cert chain (operator fetches from AMD KDS in production)
    };
    let mut guard = INSTALLED_RESTORE_EPHEMERAL.lock().ok()?;
    if guard.is_some() {
        return None;
    }
    *guard = Some(InstalledRestoreEphemeral {
        encaps_key,
        decaps_seed: zeroize::Zeroizing::new(*seed),
        measurement: measurement.to_vec(),
        attestation_report,
        cert_chain: Vec::new(),
    });
    Some(pub_info)
}

/// Whether a restore-ephemeral keypair is currently published (GET_RESTORE_PUBKEY ran, not yet retired).
/// Poison-recovers (consistent with the other agent process-globals).
#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (Sub-slice 2a-ii opcode wires it)
pub(crate) fn is_restore_ephemeral_installed() -> bool {
    INSTALLED_RESTORE_EPHEMERAL
        .lock()
        .map(|g| g.is_some())
        .unwrap_or(false)
}

/// Idempotent read of the published ephemeral pubkey + measurement (the GET_RESTORE_PUBKEY handler's
/// "already published" path): returns the published `RestoreEphemeralPub` if an ephemeral is installed,
/// so a second GET_RESTORE_PUBKEY this boot returns the SAME key the operator already re-wrapped to
/// (idempotent), rather than generating a new one. Single-use is preserved by [`retire_restore_ephemeral`]
/// (after a successful restore) — a GET_RESTORE_PUBKEY post-retire finds None here + generates a FRESH key.
#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (Sub-slice 2a-ii opcode wires it)
pub(crate) fn published_restore_ephemeral() -> Option<RestoreEphemeralPub> {
    let guard = INSTALLED_RESTORE_EPHEMERAL.lock().ok()?;
    guard.as_ref().map(|e| RestoreEphemeralPub {
        encaps_key: e.encaps_key.clone(),
        measurement: e.measurement.clone(),
        attestation_report: e.attestation_report.clone(),
        cert_chain: e.cert_chain.clone(),
    })
}

/// The restore handler's read of the published ephemeral: a SNAPSHOT (decaps seed + the measurement)
/// cloned out under a brief lock, so the handler does NOT hold the ephemeral slot lock across the restore
/// (it already holds [`INSTALLED_KEYSTORE`). The handler reconstructs the `DecapsulationKey` from the seed
/// via `DecapsulationKey::from_seed`, passes it to [`crate::agent_backup::open_restore_ingress_envelope`],
/// and checks `snapshot.measurement == opened.dest_measurement` (the AAD' `== OWN` check). Returns `None`
/// if no ephemeral is published (the opcode hasn't run / was retired) — the handler fails the restore
/// closed. Does NOT consume the slot (a FAILED restore keeps the key for retry; only a SUCCESS retires it
/// via [`retire_restore_ephemeral`]).
#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (Sub-slice 2b handler wires it)
pub(crate) struct RestoreEphemeralSnapshot {
    pub decaps_seed: zeroize::Zeroizing<[u8; 64]>,
    pub measurement: Vec<u8>,
}

#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (Sub-slice 2b handler wires it)
pub(crate) fn snapshot_restore_ephemeral() -> Option<RestoreEphemeralSnapshot> {
    let guard = INSTALLED_RESTORE_EPHEMERAL.lock().ok()?;
    guard.as_ref().map(|e| RestoreEphemeralSnapshot {
        decaps_seed: zeroize::Zeroizing::new(*e.decaps_seed),
        measurement: e.measurement.clone(),
    })
}

/// Retire the restore-ephemeral keypair — SINGLE-USE enforcement (claude-code AC#1 review). Called by the
/// RESTORE handler ONLY after a successful restore commit (the operator-authorized ceremony consumed the
/// key). A second restore this boot then finds no ephemeral (`is_restore_ephemeral_installed()` == false)
/// and must re-fetch a fresh GET_RESTORE_PUBKEY + fresh attestation + fresh re-wrap — forbidding one
/// attested ephemeral key from authenticating two distinct recoveries. The `Zeroizing` decaps seed is
/// scrubbed on drop. No-op (idempotent) if already retired.
#[cfg(feature = "agent-backup-export-preview")]
#[allow(dead_code)] // primitive ahead of consumer (Sub-slice 2a-ii opcode + 2b handler wire it)
pub(crate) fn retire_restore_ephemeral() {
    if let Ok(mut guard) = INSTALLED_RESTORE_EPHEMERAL.lock() {
        *guard = None; // Zeroizing decaps_seed scrubbed on drop
    }
}

#[cfg(all(test, feature = "agent-backup-export-preview"))]
fn reset_restore_ephemeral_for_tests() {
    if let Ok(mut guard) = INSTALLED_RESTORE_EPHEMERAL.lock() {
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
fn commit_candidate_to_anchor(
    candidate: &KeystoreBody,
    request_id: &[u8],
) -> Result<(), AgentError> {
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
    let g = AGENT_PROCESS_GLOBAL_TEST_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    // The FULL set: the installed keystore slot too (frame-path tests install into it), not just the
    // anti-rollback binding + freshness challenge — so the helper's "pristine state" claim actually holds
    // and no test inherits a keystore a prior frame test left installed.
    reset_agent_keystore_for_tests();
    reset_anti_rollback_binding_for_tests();
    reset_commit_channel_for_tests(); // slice 6-4: frame-path tests install a mock commit channel
                                      // TASK-24 Slice 2a-i: the restore-ephemeral slot (only under the backup-export preview — pulls ml-kem).
    #[cfg(feature = "agent-backup-export-preview")]
    reset_restore_ephemeral_for_tests();
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
    *guard = Some(InstalledAgentKeystore {
        body: *candidate,
        measurement,
    });
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
            let outcome = dispatch_agent(
                Profile::AgentGateway,
                payload,
                &installed.body,
                &measurement,
            );
            (outcome, measurement)
        }
        None => return encode_agent_error(AgentError::WrongProfile),
    };
    match outcome {
        Ok(AgentResponse::GenerateKeys {
            keys,
            candidate,
            request_id,
        }) => {
            // GENERATE_KEYS (the only LIVE mutating opcode, agent-keygen-exec-preview) goes through the
            // shared seal-before-emit seam. The only op-specific part is the success-body encoder
            // (key list + the sealed blob), invoked by the seam ONLY after the anchor commit succeeds.
            commit_before_emit(candidate, &request_id, measurement, &mut guard, |sealed| {
                encode_generate_keys_response(&keys, sealed)
            })
        }
        Ok(AgentResponse::SignFaucetDispense {
            signed,
            candidate,
            request_id,
        }) => {
            // SIGN_FAUCET_DISPENSE (rollback-sensitive, EpochOnly) goes through the SAME shared
            // seal-before-emit seam as GENERATE_KEYS — the only op-specific part is the success-body
            // encoder (the signed dispense tx + the sealed blob), invoked by the seam ONLY after the anchor
            // commit succeeds, so the signature never leaves before the debit is durably recorded.
            commit_before_emit(
                candidate,
                &request_id,
                measurement,
                &mut guard,
                move |sealed| encode_sign_faucet_dispense_response(signed, sealed),
            )
        }
        Ok(AgentResponse::ConfigureTreasury {
            candidate,
            request_id,
        }) => {
            // CONFIGURE_TREASURY (rollback-sensitive; Structural for ALL FOUR sub-ops) goes through the SAME shared
            // seal-before-emit seam. A config op signs nothing — the only op-specific part is the
            // success-body encoder (just the sealed blob), invoked by the seam ONLY after the anchor commit
            // succeeds, so the new config is durably recorded before the host sees success.
            commit_before_emit(candidate, &request_id, measurement, &mut guard, |sealed| {
                encode_configure_treasury_response(sealed)
            })
        }
        Ok(AgentResponse::ExportBackup {
            candidate,
            backup_blob,
            request_id,
        }) => {
            // EXPORT_BACKUP (rollback-sensitive; Structural — advances last_exported_seq) goes through the
            // SAME shared seal-before-emit seam. The backup blob was minted in the handler from the
            // post-append candidate; the encoder (invoked by the seam ONLY after the anchor commit succeeds)
            // emits the backup blob + the new sealed keystore, so the host receives the DR artifact iff the
            // drain/advance is durably committed.
            commit_before_emit(
                candidate,
                &request_id,
                measurement,
                &mut guard,
                move |sealed| encode_export_backup_response(&backup_blob, sealed),
            )
        }
        Ok(AgentResponse::RestoreBackup {
            candidate,
            request_id,
        }) => {
            // RESTORE_BACKUP (rollback-sensitive; Structural — wholesale-replaced body + local+1 structural
            // bump) goes through the SAME shared seal-before-emit seam. After the commit succeeds the
            // restore-ephemeral key is RETIRED (single-use: a second restore must re-fetch GET_RESTORE_PUBKEY
            // + fresh attestation + fresh re-wrap). NB: commit_before_emit returns an error BODY on a
            // commit failure (not an Err) — the retire below is EAGER (per-attempt single-use): a failed
            // commit still burns this ephemeral, forcing a fresh ceremony for the retry. That is the
            // conservative single-use choice (the ephemeral is NEVER reused); the retry-cost (re-fetch +
            // re-wrap) is the accepted tradeoff vs threading a success signal out of the seam.
            #[cfg(feature = "agent-backup-export-preview")]
            let body = {
                // TASK-28 / compact-9651 HIGH: extract the restored-key identity evidence from the
                // PLAINTEXT candidate BEFORE the move into commit_before_emit — the sealed blob is
                // XChaCha20Poly1305 AEAD-encrypted, so the host cannot read it. Capture the identity set
                // + the request_id echo into the seam closure (the seam calls it after the commit, with
                // the sealed blob); 2D derives restored_identity_set_sha256 + verifies the request_id
                // echo from the response ALONE.
                let identity_set: Vec<RestoredKeyIdentity> = candidate
                    .entries
                    .iter()
                    .map(|e| RestoredKeyIdentity {
                        key_ref: e.key_ref,
                        public_identity: e.public_identity.clone(),
                        key_purpose: key_purpose_code(e.purpose),
                    })
                    .collect();
                let rid_echo = request_id.clone();
                commit_before_emit(
                    candidate,
                    &request_id,
                    measurement,
                    &mut guard,
                    move |sealed| encode_restore_backup_response(sealed, &rid_echo, &identity_set),
                )
            };
            #[cfg(feature = "agent-backup-export-preview")]
            retire_restore_ephemeral();
            #[cfg(not(feature = "agent-backup-export-preview"))]
            let body = encode_agent_error(AgentError::NotConfigured); // unreachable: dispatch gates the arm
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
            (
                Value::Integer(1.into()),
                Value::Bytes(id.pubkey_uncompressed.to_vec()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(id.eth_address.to_vec()),
            ),
            (
                Value::Integer(3.into()),
                Value::Text(id.tron_address.clone()),
            ),
            (Value::Integer(4.into()), Value::Bytes(id.key_ref.to_vec())),
            (
                Value::Integer(5.into()),
                Value::Integer(key_purpose_code(id.key_purpose).into()),
            ),
            // §10.4 key 6 = backend_version. Currently the agent protocol version (=1); the
            // build/protocol-version component (keygen-identity doc) is a follow-up — no host keys
            // off a build component yet, and no vector pins it.
            (
                Value::Integer(6.into()),
                Value::Integer((id.agent_version as u64).into()),
            ),
        ]),
        // PROVE_IDENTITY response: low-S recoverable signature + the bound address/pubkey.
        AgentResponse::ProveIdentity(proof) => encode_body(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(proof.signature.r.to_vec()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(proof.signature.s.to_vec()),
            ),
            (
                Value::Integer(3.into()),
                Value::Integer((proof.signature.recovery_id as u64).into()),
            ),
            (
                Value::Integer(4.into()),
                Value::Bytes(proof.address.to_vec()),
            ),
            (
                Value::Integer(5.into()),
                Value::Bytes(proof.pubkey_uncompressed.to_vec()),
            ),
        ]),
        // SIGN_TRANSFER response (TASK-7.6.4 — the spec left the response map open): the broadcastable
        // signed transaction + its components. Key 1 = `signed_rlp` (BYTES), so a success body is
        // distinguishable from a `{1: code(int)}` error body (cf. `decode_agent_error_code`).
        AgentResponse::SignTransfer(t) => encode_body(vec![
            (Value::Integer(1.into()), Value::Bytes(t.signed_rlp.clone())),
            (
                Value::Integer(2.into()),
                Value::Bytes(t.signature.r.to_vec()),
            ),
            (
                Value::Integer(3.into()),
                Value::Bytes(t.signature.s.to_vec()),
            ),
            (
                Value::Integer(4.into()),
                Value::Integer((t.signature.recovery_id as u64).into()),
            ),
            (Value::Integer(5.into()), Value::Integer(t.v.into())),
            (
                Value::Integer(6.into()),
                Value::Bytes(t.signing_hash.to_vec()),
            ),
            (Value::Integer(7.into()), Value::Bytes(t.from.to_vec())),
        ]),
        // GET_RESTORE_PUBKEY response (TASK-24 Slice 2a-ii + compact 9611 HIGH #2): the attested ephemeral
        // pubkey + its measurement + the fresh SNP attestation report + cert chain. Key 1 = encaps_key
        // (BYTES, 1568), key 2 = measurement (BYTES), key 3 = attestation_report (BYTES), key 4 =
        // cert_chain (BYTES, may be empty). Non-mutating (NotCommitted) so it IS encoded here. The report's
        // report_data binds the ephemeral key to this TEE (operator verifies out-of-band before re-wrap).
        AgentResponse::GetRestorePubkey {
            encaps_key,
            measurement,
            attestation_report,
            cert_chain,
        } => encode_body(vec![
            (Value::Integer(1.into()), Value::Bytes(encaps_key.clone())),
            (Value::Integer(2.into()), Value::Bytes(measurement.clone())),
            (
                Value::Integer(3.into()),
                Value::Bytes(attestation_report.clone()),
            ),
            (Value::Integer(4.into()), Value::Bytes(cert_chain.clone())),
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
        // CONFIGURE_TREASURY is likewise frame-layer-only (`encode_configure_treasury_response` needs the
        // sealed blob). Reaching the generic encoder is a mis-routed mutation ⇒ fail closed — never report
        // a config success the host can't persist (and whose anchor commit never ran).
        AgentResponse::ConfigureTreasury { .. } => encode_agent_error(AgentError::SealFailed),
        // EXPORT_BACKUP is likewise frame-layer-only (`encode_export_backup_response` needs the sealed blob).
        // Reaching the generic encoder is a mis-routed mutation ⇒ fail closed — never emit a DR backup whose
        // drain/advance was not sealed/committed.
        AgentResponse::ExportBackup { .. } => encode_agent_error(AgentError::SealFailed),
        // RESTORE_BACKUP is frame-layer-only (`encode_restore_backup_response` needs the sealed blob).
        // Reaching the generic encoder is a mis-routed mutation ⇒ fail closed — never report a restore
        // success whose state was not sealed/committed.
        AgentResponse::RestoreBackup { .. } => encode_agent_error(AgentError::SealFailed),
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
                (
                    Value::Integer(2.into()),
                    Value::Bytes(k.pubkey_uncompressed.to_vec()),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Bytes(k.eth_address.to_vec()),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Text(k.tron_address.clone()),
                ),
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
fn encode_sign_faucet_dispense_response(signed: SignedTransfer, sealed_blob: &[u8]) -> Vec<u8> {
    encode_body(vec![
        // `signed` is owned (moved out of the frame outcome), so move `signed_rlp` instead of cloning it.
        (Value::Integer(1.into()), Value::Bytes(signed.signed_rlp)),
        (
            Value::Integer(2.into()),
            Value::Bytes(signed.signature.r.to_vec()),
        ),
        (
            Value::Integer(3.into()),
            Value::Bytes(signed.signature.s.to_vec()),
        ),
        (
            Value::Integer(4.into()),
            Value::Integer((signed.signature.recovery_id as u64).into()),
        ),
        (Value::Integer(5.into()), Value::Integer(signed.v.into())),
        (
            Value::Integer(6.into()),
            Value::Bytes(signed.signing_hash.to_vec()),
        ),
        (Value::Integer(7.into()), Value::Bytes(signed.from.to_vec())),
        (Value::Integer(8.into()), Value::Bytes(sealed_blob.to_vec())),
    ])
}

/// Encode the CONFIGURE_TREASURY response (slice 15-4): `{1: sealed_keystore_blob}` — the new sealed
/// keystore the host MUST persist (the mutated faucet config + bumped `config_version`; the enclave has no
/// durable storage). A config op signs nothing, so there is no echoed result data. Key 1 is BYTES so a
/// success body is distinguishable from a `{1: code(int)}` error body (cf. `decode_agent_error_code`).
/// Called by the frame layer ONLY after the anchor commit succeeds.
fn encode_configure_treasury_response(sealed_blob: &[u8]) -> Vec<u8> {
    encode_body(vec![(
        Value::Integer(1.into()),
        Value::Bytes(sealed_blob.to_vec()),
    )])
}

/// Encode the EXPORT_BACKUP response: `{1: backup_blob, 2: sealed_keystore_blob}`. Key 1 = the
/// `pq-agent-backup-v1` DR blob the operator stores OFFLINE; key 2 = the new sealed keystore the host MUST
/// persist (the drained-ring + advanced state). Key 1 is BYTES so a success body is distinguishable from a
/// `{1: code(int)}` error body (cf. `decode_agent_error_code`). Called by the frame layer ONLY after the
/// anchor commit succeeds, so the DR blob is emitted iff the drain/advance is durably recorded.
fn encode_export_backup_response(backup_blob: &[u8], sealed_blob: &[u8]) -> Vec<u8> {
    encode_body(vec![
        (Value::Integer(1.into()), Value::Bytes(backup_blob.to_vec())),
        (Value::Integer(2.into()), Value::Bytes(sealed_blob.to_vec())),
    ])
}

/// One restored key's identity evidence — the subset of [`KeyEntry`] the host/2D needs to verify the
/// restore restored the EXPECTED keys. The sealed keystore is XChaCha20Poly1305 AEAD-encrypted, so the
/// host CANNOT read these from the sealed blob; the enclave-side frame layer extracts them from the
/// plaintext candidate and emits them here (TASK-28 / compact-9651 HIGH). `secret_scalar` is NEVER
/// emitted (confidential — lives only in the sealed blob).
#[cfg(feature = "agent-backup-export-preview")]
struct RestoredKeyIdentity {
    key_ref: [u8; 32],
    /// Uncompressed SEC1 (`0x04‖X‖Y`, 65 bytes) — 2D derives the Ethereum address + binds public-key
    /// evidence (address-only is insufficient, per TASK-26 AC#4).
    public_identity: Vec<u8>,
    /// 1 = agent_transfer_k1, 2 = agent_faucet_treasury_k1 (maps to 2D `source_table`).
    key_purpose: u64,
}

#[cfg(feature = "agent-backup-export-preview")]
/// Encode the RESTORE_BACKUP success body (TASK-24 + TASK-28): `{1: sealed_keystore_blob,
/// 2: request_id_echo, 3: restored_identity_set}`. Key 2 is the `request_id` echo — the SOLE replay token
/// (nonce-model resolution, TASK-26 §2: `decode_restore_request` denies unknown fields, so the ceremony
/// against a fresh attempt fails at BOTH signature verifies. `attempt_started.id` MUST be high-entropy).
/// ⚠️ UNAUTHENTICATED (compact-9675 HIGH, codex+gemini+claude-code): keys 2 + 3 are PLAINTEXT — a
/// compromised host can FORGE the response (fresh request_id + old sealed blob + expected identities),
/// so 2D MUST NOT trust these fields until an enclave-verifiable signature/attestation over them lands
/// (the core remaining TASK-28 work). The fields are the necessary SUBSTRATE for that authenticated
/// evidence (the binding signs OVER them), not deliverable evidence on their own.
/// Key 3 is the array of restored-key identity evidence (each `{1: key_ref(32B), 2: public_identity, 3: key_purpose}`) the host needs to
/// compute `restored_identity_set_sha256` WITHOUT unsealing (the blob is AEAD-encrypted/host-opaque).
/// Invoked by the frame-layer seam ONLY after the anchor commit succeeds.
fn encode_restore_backup_response(
    sealed_blob: &[u8],
    request_id_echo: &[u8],
    identity_set: &[RestoredKeyIdentity],
) -> Vec<u8> {
    let entries: Vec<Value> = identity_set
        .iter()
        .map(|e| {
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(e.key_ref.to_vec())),
                (
                    Value::Integer(2.into()),
                    Value::Bytes(e.public_identity.clone()),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Integer(e.key_purpose.into()),
                ),
            ])
        })
        .collect();
    encode_body(vec![
        (Value::Integer(1.into()), Value::Bytes(sealed_blob.to_vec())),
        (
            Value::Integer(2.into()),
            Value::Bytes(request_id_echo.to_vec()),
        ),
        (Value::Integer(3.into()), Value::Array(entries)),
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
        (
            Value::Integer(1.into()),
            Value::Integer((e.code() as u64).into()),
        ),
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
    #[cfg(feature = "agent-keygen-exec-preview")]
    use crate::agent_keystore::MAX_TOTAL_KEY_ENTRIES;
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-sign-transfer-preview",
        feature = "agent-sign-faucet-preview"
    ))]
    use crate::agent_keystore::{BackupExportMetadata, KeyAlgorithm, KeyEntry};

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
                enclave_scope_id: [0xe1; 32],
                fleet_scope_id: [0xf1; 32],
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
            audit: AuditRing {
                records: vec![],
                capacity: 64,
                last_exported_seq: 0,
                next_seq: 1,
            },
            freshness_epoch: 1,
            structural_version: 1,
            strict_recovery_counter: 0,
        }
    }

    /// A body with one transfer key; returns (body, key_ref).
    fn body_with_key() -> (KeystoreBody, [u8; 32]) {
        let mut body = base_body();
        let creation = CreationMetadata {
            config_version: 1,
            counter_snapshot: 0,
            batch_id: 1,
        };
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
        envelope_rid(opcode, &[0x11; 16], extra)
    }

    /// Like [`envelope`] but with a caller-chosen `request_id` — for multi-op tests where each logical op
    /// must carry a DISTINCT request_id (the per-op-unique admin precondition; see the audit-ring contract).
    fn envelope_rid(opcode: u8, request_id: &[u8], extra: Vec<(Value, Value)>) -> Vec<u8> {
        let mut m = vec![
            (
                Value::Integer(1.into()),
                Value::Integer((AGENT_GATEWAY_VERSION as u64).into()),
            ),
            (
                Value::Integer(2.into()),
                Value::Integer((opcode as u64).into()),
            ),
            (
                Value::Integer(3.into()),
                Value::Text(COMMAND_DOMAIN.to_string()),
            ),
            (Value::Integer(4.into()), Value::Bytes(request_id.to_vec())),
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
        let _ = install_anti_rollback_binding(AntiRollbackBinding {
            epoch: 1,
            active: true,
        });
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
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-sign-faucet-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-backup-export-preview"
    ))]
    enum CommitChannelAct {
        Ok,
        Transport,
        WrongKey,
    }
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-sign-faucet-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-backup-export-preview"
    ))]
    struct TestCommitChannel {
        act: CommitChannelAct,
        /// Bumped at the TOP of every `round_trip`, so a test can assert the commit was reached
        /// (`> 0`) or — for the seal-before-commit ordering proof — NEVER reached (`== 0`). Defaults
        /// to a throwaway counter the test ignores via [`TestCommitChannel::new`].
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-sign-faucet-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-backup-export-preview"
    ))]
    impl TestCommitChannel {
        fn new(act: CommitChannelAct) -> Self {
            Self {
                act,
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
        /// Share a caller-held counter so the test can read how many commits were attempted. Only the
        /// keygen-exec frame tests use the counted form (the over-size-candidate never-commit proof); the
        /// faucet-preview lane reuses `TestCommitChannel` via `new` only, so allow it dead there.
        #[cfg_attr(not(feature = "agent-keygen-exec-preview"), allow(dead_code))]
        fn counted(
            act: CommitChannelAct,
            calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ) -> Self {
            Self { act, calls }
        }
    }
    #[cfg(any(
        feature = "agent-keygen-exec-preview",
        feature = "agent-sign-faucet-preview",
        feature = "agent-configure-treasury-preview",
        feature = "agent-backup-export-preview"
    ))]
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
        let payload = envelope(
            2,
            vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))],
        );
        assert_eq!(
            dispatch_agent(Profile::Producer, &payload, &body, b"test-measurement").err(),
            Some(AgentError::WrongProfile)
        );
    }

    #[test]
    fn public_identity_returns_unified_identity() {
        let (body, key_ref) = body_with_key();
        let payload = envelope(
            2,
            vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))],
        );
        let resp =
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").unwrap();
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
        let payload = envelope(
            2,
            vec![(Value::Integer(6.into()), Value::Bytes(vec![0xff; 32]))],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
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
                    Value::Map(vec![(
                        Value::Integer(1.into()),
                        Value::Bytes(nonce.to_vec()),
                    )]),
                ),
            ],
        );
        let resp =
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").unwrap();
        match resp {
            AgentResponse::ProveIdentity(proof) => {
                let recovered = crate::secp256k1::recover_pubkey_uncompressed(
                    &proof.signing_hash,
                    &proof.signature,
                )
                .unwrap();
                assert_eq!(
                    recovered, proof.pubkey_uncompressed,
                    "recovered == bound pubkey"
                );
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
                    Value::Map(vec![(
                        Value::Integer(1.into()),
                        Value::Bytes(vec![0xab; 32]),
                    )]),
                ),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
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
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
            Some(AgentError::Malformed)
        );
    }

    // EXPORT_BACKUP is the deferred-stub case ONLY without `agent-backup-export-preview`; with the feature
    // it is LIVE (handle_export_backup) and this fixture's no-key-7 request would be Malformed, not
    // NotConfigured. The live path is covered by the `export_backup` test module; RESTORE_BACKUP has its own
    // always-deferred test below.
    #[cfg(not(feature = "agent-backup-export-preview"))]
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
            &admin,
            7,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            0,
            b"export_backup",
            1,
            [0xab; 32],
            [0xe1; 32],
        );
        let payload = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
            Some(AgentError::NotConfigured)
        );
    }

    // Under `agent-backup-export-preview` RESTORE_BACKUP is LIVE (handle_restore_backup) — this stub
    // contract (verify cap → NotConfigured) holds only WITHOUT the preview (mirrors the EXPORT stub test).
    #[cfg(not(feature = "agent-backup-export-preview"))]
    #[test]
    fn deferred_restore_backup_recovery_cap_reaches_not_configured() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
        let recovery = SigningKey::from_bytes(&[9u8; 32]);
        let mut body = base_body();
        body.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
        // RESTORE_BACKUP(8) is RECOVERY-tier (agent_capability.rs: `8 => cap.is_recovery`); its handler is a
        // FAIL-CLOSED RESERVED STUB — the full attested-ingress restore ceremony (the separate
        // `2d-hsm-agent-restore-ingress-v1` envelope + counter-seeding AC#11/#12) is a non-goal of 13b. A
        // valid recovery cap verifies (recovery_authority_pk + recovery-tier), then the request collapses to
        // NotConfigured (0x45) — pinning the verify→fail-closed contract so the stub can't silently become a
        // no-op handler. (An ADMIN-signed restore is separately rejected at the tier check, 0x43.)
        let cap = crate::agent_capability::test_signed_capability(
            &recovery,
            8,
            &[0x11; 16],
            1,
            true,
            11565,
            "testnet",
            0,
            b"restore_backup",
            1,
            [0xab; 32],
            [0xe1; 32],
        );
        let payload = envelope(8, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
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
            &admin,
            7,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            0,
            b"export_backup",
            1,
            [0xab; 32],
            [0xe1; 32],
        );
        // Reverse the cap entries so the nested submap's keys are DESCENDING (non-canonical) while the
        // signed VALUES are unchanged. In ascending order this exact cap reaches NotConfigured (see
        // deferred_privileged_op_valid_cap_reaches_not_configured); the non-canonical wire bytes must
        // be rejected as Malformed by the strict decoder BEFORE verify_capability runs — proving the
        // nested cap submap (envelope key 5) is canonical-checked, not just the top-level envelope.
        cap.reverse();
        let payload = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
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
            admin,
            1,
            request_id,
            counter,
            false,
            11565,
            "testnet",
            0,
            scope_target,
            purpose_code as u8,
            pb,
            [0xe1; 32],
        );
        let payload = vec![
            (
                Value::Integer(1.into()),
                Value::Integer(purpose_code.into()),
            ),
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
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").unwrap() {
            AgentResponse::GenerateKeys {
                keys, candidate, ..
            } => {
                assert_eq!(keys.len(), 3, "3 transfer keys generated");
                assert!(keys
                    .iter()
                    .all(|k| k.key_purpose == KeyPurpose::AgentTransferK1));
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
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").unwrap() {
            AgentResponse::GenerateKeys { candidate, .. } => {
                // +1 per COMMITTED op, regardless of count (NOT +3).
                assert_eq!(
                    candidate.structural_version, 2,
                    "structural +1 per committed op"
                );
                // 6-4: GENERATE_KEYS is Structural, so the ATOMIC bump advances freshness_epoch TOGETHER
                // with structural_version (was LOCAL-ONLY/INERT before 6-4). The anchor commit records this
                // advanced epoch and the seal binds it (the frame-layer seal-before-emit path).
                assert_eq!(
                    candidate.freshness_epoch,
                    body.freshness_epoch + 1,
                    "epoch advances atomically"
                );
                // strict_recovery_counter is a marks surface, NOT bumped by a structural op.
                assert_eq!(
                    candidate.strict_recovery_counter,
                    body.strict_recovery_counter
                );
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
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 1, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
        let (cap, _) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
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
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
            &admin,
            1,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            0,
            b"generate_faucet",
            1,
            pb,
            [0xe1; 32],
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
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 2, 1, b"generate_faucet");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").unwrap() {
            AgentResponse::GenerateKeys {
                keys, candidate, ..
            } => {
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
            &admin,
            1,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            1,
            b"generate_faucet",
            2,
            pb,
            [0xf1; 32],
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
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    /// TASK-18 18-5 — the NEGATIVE CONTROL for `generate_keys_fleet_scoped_treasury_rejected` (above):
    /// a fleet-scoped (`scope_class=1`) GENERATE_KEYS cap for purpose=1 (transfer pool) IS accepted
    /// (§10.3 "transfer pool: fleet allowed"), proving the AC#12 enclave-only rule is scoped to the
    /// FAUCET TREASURY keygen (purpose=2) and does NOT accidentally reject transfer-pool keygen. Without
    /// this control, someone could tighten the handler to reject fleet scope on ALL generate_keys
    /// (incl. transfer) and the suite would stay green — a false-confidence gap the 18-5 completeness
    /// audit explicitly calls out. Transfer keys are NOT spend-authority: a clone minting its own
    /// transfer pool does not multiply a treasury budget (design doc "Financial budget mutations"), so
    /// fleet-scoped transfer keygen is the one permitted fleet-scoped GENERATE_KEYS variant.
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_fleet_scoped_transfer_accepted() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // Fleet-scoped (scope_class=1) cap binding to fleet_scope_id [0xf1;32]; purpose=1 (transfer).
        let pb = crate::agent_capability::payload_binding(
            1,
            None,
            &[0x11; 16],
            &generate_keys_canonical_params(1, 1),
        );
        let cap = crate::agent_capability::test_signed_capability(
            &admin,
            1,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            1,
            b"generate_transfer",
            1,
            pb,
            [0xf1; 32],
        );
        let pay = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())), // purpose 1 (transfer)
            (Value::Integer(2.into()), Value::Integer(1.into())),
        ];
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        // Accepted (Success) — NOT CapabilityRejected. Transfer-pool keygen is the fleet-allowed case.
        assert!(
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").is_ok(),
            "fleet-scoped transfer-pool keygen (purpose=1) MUST be accepted (§10.3 transfer pool: fleet allowed); \
             only faucet-treasury keygen (purpose=2) is enclave-only (AC#12)"
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
                (
                    Value::Integer(1.into()),
                    Value::Integer((AGENT_GATEWAY_VERSION as u64).into()),
                ),
                (Value::Integer(2.into()), Value::Integer(2u64.into())),
                (
                    Value::Integer(3.into()),
                    Value::Text(COMMAND_DOMAIN.to_string()),
                ),
                (Value::Integer(4.into()), Value::Bytes(rid)),
                (Value::Integer(6.into()), Value::Bytes(vec![0xfe; 32])),
            ]))
        };
        // 65 bytes ⇒ Malformed (the >64 reject the anchor keying depends on — never reaches the commit).
        assert_eq!(
            dispatch_agent(
                Profile::AgentGateway,
                &read_env(vec![0x41; MAX_REQUEST_ID_LEN + 1]),
                &body,
                b"test-measurement"
            )
            .err(),
            Some(AgentError::Malformed),
            "a request_id over MAX_REQUEST_ID_LEN must fail closed at decode"
        );
        // 64-byte (boundary) and EMPTY both decode fine: the op proceeds to its own outcome (an unknown
        // key_ref ⇒ NOT Malformed). Confirms the bound admits exactly [0, 64], incl the empty id.
        for rid in [vec![0x41; MAX_REQUEST_ID_LEN], Vec::new()] {
            assert_ne!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &read_env(rid.clone()),
                    &body,
                    b"test-measurement"
                )
                .err(),
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
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x22; 16], 1, 1, 1, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
            &wrong,
            1,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            0,
            b"generate_transfer",
            1,
            [0xab; 32],
            [0xe1; 32],
        );
        let payload = envelope(1, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
            Some(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn privileged_without_capability_rejected() {
        let _g = gate_configured();
        let (body, _) = body_with_key();
        let payload = envelope(1, vec![]); // no capability key 5
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
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
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
            Some(AgentError::Malformed)
        );
    }

    #[test]
    fn unknown_opcode_and_version_and_domain_are_malformed() {
        let (body, _) = body_with_key();
        // unknown opcode 10 (9 is now GET_RESTORE_PUBKEY, TASK-24 Slice 2a-ii)
        assert_eq!(
            dispatch_agent(
                Profile::AgentGateway,
                &envelope(10, vec![]),
                &body,
                b"test-measurement"
            )
            .err(),
            Some(AgentError::Malformed)
        );
        // wrong version
        let bad_ver = enc(Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(2.into())),
            (
                Value::Integer(3.into()),
                Value::Text(COMMAND_DOMAIN.to_string()),
            ),
            (Value::Integer(4.into()), Value::Bytes(vec![0x11; 16])),
        ]));
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &bad_ver, &body, b"test-measurement").err(),
            Some(AgentError::Malformed)
        );
        // wrong domain
        let bad_dom = enc(Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Integer((AGENT_GATEWAY_VERSION as u64).into()),
            ),
            (Value::Integer(2.into()), Value::Integer(2.into())),
            (
                Value::Integer(3.into()),
                Value::Text("wrong/domain".to_string()),
            ),
            (Value::Integer(4.into()), Value::Bytes(vec![0x11; 16])),
        ]));
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &bad_dom, &body, b"test-measurement").err(),
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
            dispatch_agent(
                Profile::AgentGateway,
                &envelope(5, vec![]),
                &body,
                b"test-measurement"
            )
            .err(),
            Some(AgentError::NotConfigured)
        );
        // SIGN_TRANSFER(4): production fail-closed (NotConfigured) WITHOUT the preview feature; WITH it
        // the opcode is LIVE, so an empty payload reaches the handler and is rejected as Malformed (not
        // NotConfigured) — that distinction is exactly what proves the production gate opened.
        let err4 = dispatch_agent(
            Profile::AgentGateway,
            &envelope(4, vec![]),
            &body,
            b"test-measurement",
        )
        .err();
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
            dispatch_agent(Profile::AgentGateway, &p, &body, b"test-measurement").err(),
            Some(AgentError::Malformed)
        );
        let not_map = enc(Value::Integer(1.into()));
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &not_map, &body, b"test-measurement").err(),
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
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
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
        let creation = CreationMetadata {
            config_version: 1,
            counter_snapshot: 0,
            batch_id: 1,
        };
        let key_ref =
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, 1, creation).unwrap()[0].key_ref;

        // No keystore installed ⇒ producer/uninstalled ⇒ WrongProfile (0x41) error body.
        let pubid_env = envelope(
            2,
            vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))],
        );
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&pubid_env)),
            Some(0x41)
        );

        // Install ⇒ PUBLIC_IDENTITY returns a success body (key 1 = 65-byte pubkey).
        assert!(
            install_agent_keystore(body, b"meas"),
            "install-once succeeds on an empty slot"
        );
        let ok_body = handle_agent_gateway_frame(&pubid_env);
        assert_eq!(
            decode_agent_error_code(&ok_body),
            None,
            "success body, not an error map"
        );
        let Value::Map(m) = ciborium::de::from_reader(&ok_body[..]).unwrap() else {
            panic!("response is a map")
        };
        assert_eq!(
            as_bytes(map_get(&m, 1).unwrap()).unwrap().len(),
            65,
            "pubkey 65B"
        );
        assert_eq!(
            as_bytes(map_get(&m, 4).unwrap()).unwrap(),
            key_ref,
            "key_ref echoed"
        );

        // Unknown key_ref ⇒ collapsed 0x42 error body.
        let bad = envelope(
            2,
            vec![(Value::Integer(6.into()), Value::Bytes(vec![0xfe; 32]))],
        );
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&bad)),
            Some(0x42)
        );

        // GENERATE_KEYS through the FRAME — live execution is preview-gated, so this whole section
        // only compiles/runs under `agent-keygen-exec-preview`. Success body carries the key list
        // (key 1) AND the new sealed keystore blob (key 2) for the host to persist.
        #[cfg(feature = "agent-keygen-exec-preview")]
        {
            // 6-4 seal-before-emit: install a conformant commit channel so the per-op anchor commit succeeds
            // and the frame proceeds to seal + swap.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Ok
            ))));
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
            assert_eq!(
                decode_agent_error_code(&gen_body),
                None,
                "GENERATE_KEYS success"
            );
            let Value::Map(gm) = ciborium::de::from_reader(&gen_body[..]).unwrap() else {
                panic!()
            };
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
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(
            CommitChannelAct::Transport
        ))));
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            Some(0x46),
            "commit transport failure ⇒ SealFailed"
        );
        reset_commit_channel_for_tests();
        // (c) a FORGED ACK (wrong signer) → fail closed 0x46 (the durable record didn't verify).
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(
            CommitChannelAct::WrongKey
        ))));
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&gen_env)),
            Some(0x46),
            "forged commit ack ⇒ SealFailed"
        );
        reset_commit_channel_for_tests();
        // (d) PROOF OF NO SWAP across all three failures: the live counter never advanced, so the SAME cap
        //     (counter 1) is STILL accepted once a conformant channel is installed. If any failed op had
        //     swapped, the live counter would be 1 and this cap (contiguity expects 2) would be 0x43.
        assert!(install_commit_channel(Box::new(TestCommitChannel::new(
            CommitChannelAct::Ok
        ))));
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
                    creation_metadata: CreationMetadata {
                        config_version: 1,
                        counter_snapshot: 0,
                        batch_id: 1,
                    },
                    backup_export_metadata: BackupExportMetadata::default(),
                }
            })
            .collect();
        assert!(install_agent_keystore(body, b"meas"));
        // A CONFORMANT channel (would ACK happily) instrumented with a shared call-counter.
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(install_commit_channel(Box::new(
            TestCommitChannel::counted(CommitChannelAct::Ok, Arc::clone(&calls),)
        )));
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

    /// 4b AC#14 audit append (dispatch level): a successful GENERATE_KEYS writes EXACTLY ONE audit record
    /// onto the candidate ring (one per committed op, regardless of `count`), carrying full provenance —
    /// op = wire opcode, (authority, scope_class, scope_target) + counter = the accepted cap's identity +
    /// per-scope batch seq, request_id = the logical-op id, config_version = the live treasury config
    /// version. This checks the record CONTENTS at dispatch level; the seal-survives-`validate()` property
    /// is proven by the frame-level tests below (which actually seal the audited candidate).
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_appends_one_audit_record_to_candidate() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        // Distinctive config_version (7, not the structural_version/freshness_epoch value of 1) so the
        // config_version assertion can't pass by field-confusion with a same-valued field.
        body.config.monotonic_treasury_config_version = 7;
        // count=3 keys in ONE op ⇒ still exactly ONE audit record (record-per-op, not per-key).
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 3, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        match dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").unwrap() {
            AgentResponse::GenerateKeys { candidate, .. } => {
                assert_eq!(
                    candidate.audit.records.len(),
                    1,
                    "exactly one audit record per committed op"
                );
                assert_eq!(
                    candidate.audit.next_seq, 2,
                    "next_seq advanced 1→2 (base next_seq was 1)"
                );
                let r = &candidate.audit.records[0];
                assert_eq!(r.seq, 1, "first record gets seq 1");
                assert_eq!(r.op, 1, "op = the GENERATE_KEYS wire opcode");
                assert_eq!(
                    r.authority,
                    admin.verifying_key().to_bytes(),
                    "authority = the cap authority"
                );
                assert_eq!(r.counter, 1, "counter = the accepted cap batch sequence");
                assert_eq!(
                    r.config_version, 7,
                    "config_version = the live treasury config version (==7)"
                );
                // Full provenance (the 4b schema widening): scope + request_id disambiguate the op.
                assert_eq!(r.scope_class, 0, "scope_class = the cap scope_class");
                assert_eq!(
                    r.scope_target,
                    b"generate_transfer".to_vec(),
                    "scope_target = the cap scope"
                );
                assert_eq!(
                    r.request_id,
                    vec![0x11u8; 16],
                    "request_id = the envelope request_id"
                );
            }
            _ => panic!("expected GenerateKeys"),
        }
    }

    /// 4b AC#14 persistence-through-swap (frame level): successful frame ops ACCUMULATE audit records on
    /// the swapped live state — proven via the backpressure oracle. With a small ring (capacity 2), two
    /// contiguous ops succeed (each seals a GROWING ring through `validate()` and swaps), then the third
    /// hits a full-undrained ring and fails closed (0x46) WITHOUT a third commit. If the records had not
    /// persisted across the swap the ring would never fill and the third op would succeed. (The drain that
    /// re-enables appends is EXPORT_BACKUP — slice 4c; 4b only respects backpressure.)
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_audit_records_accumulate_across_swaps_then_backpressure() {
        use ed25519_dalek::SigningKey;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
        body.audit.capacity = 2; // room for exactly two un-exported records
        assert!(install_agent_keystore(body, b"meas"));
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(install_commit_channel(Box::new(
            TestCommitChannel::counted(CommitChannelAct::Ok, Arc::clone(&calls),)
        )));
        // Each logical op carries a DISTINCT request_id (the per-op-unique admin precondition) — reusing one
        // would model a sequence a real anchor treats as an idempotent replay, not three distinct ops.
        let op = |counter: u64, request_id: &[u8]| {
            let (cap, pay) = generate_keys_cap_and_payload(
                &admin,
                request_id,
                counter,
                1,
                1,
                b"generate_transfer",
            );
            envelope_rid(
                1,
                request_id,
                vec![
                    (Value::Integer(5.into()), Value::Map(cap)),
                    (Value::Integer(7.into()), Value::Map(pay)),
                ],
            )
        };
        // Two contiguous ops fill the ring to capacity; each seals a growing audit ring + swaps.
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&op(1, &[0x21; 16]))),
            None,
            "op 1 (record 1) succeeds"
        );
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&op(2, &[0x22; 16]))),
            None,
            "op 2 (record 2) succeeds"
        );
        // Third op: the swapped live ring is now full AND undrained ⇒ backpressure ⇒ fail closed, no swap.
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&op(3, &[0x23; 16]))),
            Some(0x46),
            "third op hits a full undrained ring ⇒ SealFailed (proves records persisted across swaps)"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "only the two successful ops committed — the backpressured third never reached the anchor"
        );
        reset_agent_keystore_for_tests();
    }

    /// 4b AC#14 backpressure fail-closed ordering (frame level, mirror `unsealable_candidate_never_commits`):
    /// a GENERATE_KEYS against a body whose audit ring is ALREADY full+undrained fails closed (0x46) in
    /// Phase A — `record_audit` returns `AuditBackpressure`, mapped to `SealFailed`, BEFORE the frame layer
    /// reaches `commit_before_emit`. Pinned with a shared call-counter that must be 0 (no anchor commit).
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_audit_backpressure_fails_closed_never_commits() {
        use ed25519_dalek::SigningKey;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
        // Saturate the ring (capacity 1, one un-exported record) via record_audit so the state is
        // guaranteed validate()-consistent: records=[seq1], next_seq=2, last_exported_seq=0.
        body.audit.capacity = 1;
        body.record_audit(&crate::agent_keystore::AuditAppend {
            op: 1,
            authority: &[0u8; 32],
            counter: 0,
            config_version: 0,
            scope_class: 0,
            scope_target: b"seed",
            request_id: b"seed",
        })
        .expect("first append fills the cap-1 ring");
        assert!(install_agent_keystore(body, b"meas"));
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(install_commit_channel(Box::new(
            TestCommitChannel::counted(CommitChannelAct::Ok, Arc::clone(&calls),)
        )));
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
            "a full undrained audit ring fails the op closed with SealFailed"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "audit backpressure short-circuits in Phase A — the anchor commit was NEVER reached"
        );
        reset_agent_keystore_for_tests();
    }

    /// 4b AC#14 overflow fail-closed (dispatch level, mirror `structural_overflow_fails_closed`): a body
    /// whose `audit.next_seq == u64::MAX` makes `record_audit`'s checked `next_seq` increment overflow →
    /// `MonotonicOverflow` → `SealFailed`. Confirms the SECOND `record_audit` error variant also fails
    /// closed (empty ring, so backpressure does not pre-empt the overflow path).
    #[cfg(feature = "agent-keygen-exec-preview")]
    #[test]
    fn generate_keys_audit_next_seq_overflow_fails_closed() {
        use ed25519_dalek::SigningKey;
        let _g = gate_configured();
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let mut body = base_body();
        body.config.admin_authority_pk = admin.verifying_key().to_bytes();
        body.audit.next_seq = u64::MAX; // checked_add(1) → None → MonotonicOverflow → SealFailed
        let (cap, pay) =
            generate_keys_cap_and_payload(&admin, &[0x11; 16], 1, 1, 1, b"generate_transfer");
        let env = envelope(
            1,
            vec![
                (Value::Integer(5.into()), Value::Map(cap)),
                (Value::Integer(7.into()), Value::Map(pay)),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
            Some(AgentError::SealFailed)
        );
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
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
            (AgentOpcode::GetRestorePubkey, false), // volatile ephemeral keypair, no sealed-state mutation
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
            // EXPORT_BACKUP is Structural (TASK-13b slice 2): it advances `audit.last_exported_seq`, which
            // is not a marks surface / structural_version, so a dropped seal must trigger StructuralGap⇒
            // restore rather than silently roll the audit high-water back.
            (AgentOpcode::ExportBackup, CommitBumpClass::Structural),
            // RESTORE_BACKUP is Structural (TASK-13b slice 2): it wholesale-replaces the keystore body
            // (entries/config/audit/structural_version) — non-marks state AdoptForward can't reconstruct —
            // so a dropped seal must StructuralGap⇒restore, never silently lose the restore (gemini PR #93).
            (AgentOpcode::RestoreBackup, CommitBumpClass::Structural),
            (AgentOpcode::SignTransfer, CommitBumpClass::NotCommitted),
            (AgentOpcode::PublicIdentity, CommitBumpClass::NotCommitted),
            (AgentOpcode::ProveIdentity, CommitBumpClass::NotCommitted),
            // GET_RESTORE_PUBKEY (TASK-24 Slice 2a-ii): NotCommitted — generates a volatile ephemeral
            // keypair (process-global), no sealed-state mutation, no anchor commit.
            (AgentOpcode::GetRestorePubkey, CommitBumpClass::NotCommitted),
        ] {
            assert_eq!(op.commit_bump_class(), expected, "{op:?}");
            // CONSISTENCY: an op is committed (Structural|EpochOnly) IFF it is rollback-sensitive — the
            // commit path is gated on is_rollback_sensitive, so a NotCommitted op must never commit and
            // every rollback-sensitive op must carry a bump class.
            let committed = op.commit_bump_class() != CommitBumpClass::NotCommitted;
            assert_eq!(
                committed,
                op.is_rollback_sensitive(),
                "{op:?}: committed-ness must match is_rollback_sensitive"
            );
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
        assert!(!install_anti_rollback_binding(AntiRollbackBinding {
            epoch: 1,
            active: false
        }));
        assert!(!is_anti_rollback_configured());
        // First active install wins.
        assert!(install_anti_rollback_binding(AntiRollbackBinding {
            epoch: 5,
            active: true
        }));
        assert!(is_anti_rollback_configured());
        // Second install is refused (no overwrite) — a security-relevant property: a later call can't
        // swap in a different epoch over a live binding.
        assert!(!install_anti_rollback_binding(AntiRollbackBinding {
            epoch: 9,
            active: true
        }));
    }

    #[test]
    fn fail_closed_default_no_binding() {
        let _g = gate_unconfigured(); // resets the slot to None
        assert!(
            !is_anti_rollback_configured(),
            "const-init None ⇒ fail-closed default"
        );
    }

    // ---- TASK-24 Slice 2a-i: restore-ephemeral keypair lifecycle ----

    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn restore_ephemeral_install_once_and_basic_access() {
        let _g = lock_and_reset_agent_process_globals();
        assert!(
            !is_restore_ephemeral_installed(),
            "const-init None ⇒ fail-closed default"
        );
        let pub1 = install_restore_ephemeral_with_seed(
            b"dest-measurement-v1",
            &[0x6c; 64],
            11565,
            b"testnet",
        )
        .expect("first install succeeds");
        assert_eq!(pub1.measurement, b"dest-measurement-v1");
        assert_eq!(
            pub1.encaps_key.len(),
            crate::agent_keystore::ML_KEM_1024_ENCAPS_KEY_LEN,
            "1568-byte ML-KEM-1024 encaps key"
        );
        assert!(is_restore_ephemeral_installed());
        // Install-once: a second call returns None + does NOT overwrite the published key.
        assert!(
            install_restore_ephemeral_with_seed(b"other", &[0x6c; 64], 11565, b"testnet").is_none(),
            "install-once refuses overwrite"
        );
        let still = snapshot_restore_ephemeral().unwrap();
        assert_eq!(
            still.measurement, b"dest-measurement-v1",
            "first key retained, not overwritten"
        );
    }

    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn restore_ephemeral_rejects_empty_measurement() {
        let _g = lock_and_reset_agent_process_globals();
        assert!(
            install_restore_ephemeral_with_seed(b"", &[0x6c; 64], 11565, b"testnet").is_none(),
            "empty measurement rejected"
        );
        assert!(
            !is_restore_ephemeral_installed(),
            "no half-install on empty measurement"
        );
    }

    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn restore_ephemeral_snapshot_reconstructs_the_published_encaps_key() {
        // The snapshot's decaps seed MUST reconstruct a DecapsulationKey whose encaps key == the one
        // GET_RESTORE_PUBKEY published (the operator re-wrapped to that pubkey; the handler decapsulates
        // with the matching private half). Pins the seed↔pubkey consistency the ceremony round-trip needs.
        use ml_kem::{DecapsulationKey, KeyExport as _, MlKem1024};
        let _g = lock_and_reset_agent_process_globals();
        let pub_info = install_restore_ephemeral_with_seed(
            b"dest-measurement-v1",
            &[0x6c; 64],
            11565,
            b"testnet",
        )
        .unwrap();
        let snap = snapshot_restore_ephemeral().expect("snapshot after install");
        assert_eq!(snap.measurement, b"dest-measurement-v1");
        let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(*snap.decaps_seed));
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            pub_info.encaps_key.as_slice(),
            "snapshot seed reconstructs the published encaps key"
        );
    }

    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn restore_ephemeral_retire_is_single_use() {
        // SINGLE-USE enforcement (claude-code AC#1 review): after retire, no ephemeral is published — a
        // second restore must re-fetch GET_RESTORE_PUBKEY + fresh attestation + fresh re-wrap.
        let _g = lock_and_reset_agent_process_globals();
        install_restore_ephemeral_with_seed(b"dest-measurement-v1", &[0x6c; 64], 11565, b"testnet")
            .unwrap();
        assert!(is_restore_ephemeral_installed());
        retire_restore_ephemeral();
        assert!(
            !is_restore_ephemeral_installed(),
            "retire clears (single-use)"
        );
        assert!(
            snapshot_restore_ephemeral().is_none(),
            "no snapshot after retire"
        );
        retire_restore_ephemeral(); // idempotent
                                    // After retire a FRESH install is allowed (the next ceremony's key).
        assert!(
            install_restore_ephemeral_with_seed(
                b"dest-measurement-v2",
                &[0x6c; 64],
                11565,
                b"testnet"
            )
            .is_some(),
            "fresh install allowed after retire"
        );
    }

    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn restore_ephemeral_snapshot_keeps_the_key_for_retry() {
        // A snapshot (a FAILED restore attempt) does NOT retire — the operator can retry the ceremony
        // with a corrected envelope to the SAME published key. Only a SUCCESSFUL restore retires.
        let _g = lock_and_reset_agent_process_globals();
        install_restore_ephemeral_with_seed(b"dest-measurement-v1", &[0x6c; 64], 11565, b"testnet")
            .unwrap();
        let _snap = snapshot_restore_ephemeral().unwrap();
        assert!(
            is_restore_ephemeral_installed(),
            "snapshot keeps the key for retry"
        );
        assert!(
            snapshot_restore_ephemeral().is_some(),
            "still snapshottable after a failed-attempt snapshot"
        );
    }

    /// GET_RESTORE_PUBKEY(9) via the full dispatch path (TASK-24 Slice 2a-ii): publishes an attested
    /// ephemeral pubkey, is IDEMPOTENT (a second call returns the SAME key), and generates a FRESH key
    /// after a retire. Non-privileged (no capability at envelope key 5), NotCommitted (no anchor commit).
    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn get_restore_pubkey_dispatch_is_idempotent_and_single_use() {
        use crate::agent_keystore::ML_KEM_1024_ENCAPS_KEY_LEN;
        let _g = lock_and_reset_agent_process_globals();
        let (body, _) = body_with_key();
        let env = envelope(9, vec![]); // opcode 9, no cap, no payload
                                       // The production handler path fetches a real SNP quote in
                                       // install_restore_ephemeral (unavailable devicelessly), so
                                       // pre-publish via the test variant — the handler's read path
                                       // (published_restore_ephemeral) returns it. The production
                                       // install-on-dispatch is verified on SNP hardware (like the
                                       // producer fetch_measurement_and_report path).
        let pub0 = install_restore_ephemeral_with_seed(
            b"dest-measurement",
            &[0x6c; 64],
            body.config.twod_chain_id,
            body.config.environment_identifier.as_bytes(),
        )
        .expect("pre-install the published ephemeral");
        // First dispatch returns the published key (read path) + its attestation report.
        let resp1 =
            dispatch_agent(Profile::AgentGateway, &env, &body, b"dest-measurement").unwrap();
        let (ek1, meas1, report1) = match resp1 {
            AgentResponse::GetRestorePubkey {
                encaps_key,
                measurement,
                attestation_report,
                ..
            } => (encaps_key, measurement, attestation_report),
            _ => panic!("expected GetRestorePubkey, got a different AgentResponse variant"),
        };
        assert_eq!(
            ek1.len(),
            ML_KEM_1024_ENCAPS_KEY_LEN,
            "1568-byte ML-KEM-1024 encaps key"
        );
        assert_eq!(
            meas1, b"dest-measurement",
            "the enclave's own measurement is returned"
        );
        // Compact 9611 HIGH #2: the response carries the attestation report whose report_data binds the
        // ephemeral key to this TEE — the operator verifies this BEFORE re-wrapping. Assert the binding
        // the stand-in report carries matches the recomputed one (pins the handler→install→response chain
        // passes chain/env through to the binding).
        let expected_rd = crate::snp_report::report_data_for_restore_ephemeral(
            &ek1,
            &meas1,
            body.config.twod_chain_id,
            body.config.environment_identifier.as_bytes(),
        );
        let echoed_rd =
            crate::snp_report::report_data_from_report(&report1).expect("report_data readable");
        assert_eq!(
            echoed_rd[..],
            expected_rd[..],
            "the attestation report's report_data binds the ephemeral key + measurement + chain + env"
        );
        assert_eq!(
            report1.len(),
            pub0.attestation_report.len(),
            "response carries the published attestation report unchanged"
        );
        assert!(is_restore_ephemeral_installed());
        // Idempotent: a second call returns the SAME published key (no churn).
        let resp2 =
            dispatch_agent(Profile::AgentGateway, &env, &body, b"dest-measurement").unwrap();
        let ek2 = match resp2 {
            AgentResponse::GetRestorePubkey { encaps_key, .. } => encaps_key,
            _ => panic!("expected GetRestorePubkey"),
        };
        assert_eq!(ek1, ek2, "idempotent — same published key on re-query");
        // After retire (a completed restore), a fresh key is published (the next ceremony's key).
        retire_restore_ephemeral();
        let _pub1 = install_restore_ephemeral_with_seed(
            b"dest-measurement",
            &[0x77; 64], // DISTINCT seed ⇒ a different ephemeral key
            body.config.twod_chain_id,
            body.config.environment_identifier.as_bytes(),
        )
        .expect("pre-install a fresh key after retire");
        let resp3 =
            dispatch_agent(Profile::AgentGateway, &env, &body, b"dest-measurement").unwrap();
        let ek3 = match resp3 {
            AgentResponse::GetRestorePubkey { encaps_key, .. } => encaps_key,
            _ => panic!("expected GetRestorePubkey"),
        };
        assert_ne!(
            ek1, ek3,
            "fresh key after retire (single-use across ceremonies)"
        );
    }

    /// GET_RESTORE_PUBKEY is non-privileged: a request carrying a capability (envelope key 5) is Malformed
    /// (caps are only for privileged ops). Mirrors the read-opcode cap-rejection rule.
    #[cfg(feature = "agent-backup-export-preview")]
    #[test]
    fn get_restore_pubkey_with_capability_is_malformed() {
        let _g = lock_and_reset_agent_process_globals();
        let (body, key_ref) = body_with_key();
        let payload = envelope(
            9,
            vec![
                (Value::Integer(5.into()), Value::Map(vec![])), // a cap on a non-privileged op
                (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
            ],
        );
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &payload, &body, b"test-measurement").err(),
            Some(AgentError::Malformed)
        );
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
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
                dispatch_agent(
                    Profile::AgentGateway,
                    &envelope(op, vec![]),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::NotConfigured),
                "opcode {op} must be gated when anti-rollback is unconfigured"
            );
        }
    }

    #[test]
    fn sign_transfer_not_gated_but_faucet_is() {
        let _g = gate_unconfigured();
        let body = base_body();
        assert!(
            !AgentOpcode::SignTransfer.is_rollback_sensitive(),
            "transfer carries no rollback state"
        );
        assert!(
            AgentOpcode::SignFaucetDispense.is_rollback_sensitive(),
            "faucet dispense debits spend"
        );
        // SIGN_TRANSFER(4) is NOT anti-rollback-gated (the classification above is the lock). When the
        // gate is unconfigured it is therefore NOT blocked by the gate: without the preview it falls
        // through to the production fail-closed NotConfigured; WITH the preview it is live, so an empty
        // payload is Malformed — proving it passed the (unconfigured) gate rather than being blocked by it.
        let err4 = dispatch_agent(
            Profile::AgentGateway,
            &envelope(4, vec![]),
            &body,
            b"test-measurement",
        )
        .err();
        #[cfg(not(feature = "agent-sign-transfer-preview"))]
        assert_eq!(err4, Some(AgentError::NotConfigured));
        #[cfg(feature = "agent-sign-transfer-preview")]
        assert_eq!(
            err4,
            Some(AgentError::Malformed),
            "transfer is live — not gate-blocked"
        );
        // SIGN_FAUCET_DISPENSE(5) IS gated → NotConfigured when the binding is unconfigured.
        assert_eq!(
            dispatch_agent(
                Profile::AgentGateway,
                &envelope(5, vec![]),
                &body,
                b"test-measurement"
            )
            .err(),
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
        let env = envelope(
            2,
            vec![(Value::Integer(6.into()), Value::Bytes(key_ref.to_vec()))],
        );
        assert!(
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").is_ok(),
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
            &wrong,
            7,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            0,
            b"export_backup",
            1,
            [0xab; 32],
            [0xe1; 32],
        );
        let env = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
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
            &admin,
            7,
            &[0x11; 16],
            1,
            false,
            11565,
            "testnet",
            0,
            b"export_backup",
            1,
            [0xab; 32],
            [0xe1; 32],
        );
        let env = envelope(7, vec![(Value::Integer(5.into()), Value::Map(cap))]);
        assert_eq!(
            decode_agent_error_code(&handle_agent_gateway_frame(&env)),
            Some(0x45)
        );
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
                creation_metadata: CreationMetadata {
                    config_version: 1,
                    counter_snapshot: 0,
                    batch_id: 1,
                },
                backup_export_metadata: BackupExportMetadata::default(),
            });
            (
                body,
                key_ref,
                arr20(k[name]["eth_address"].as_str().unwrap()),
            )
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
            let resp = dispatch_agent(
                Profile::AgentGateway,
                &golden_request(&key_ref, &from),
                &body,
                b"test-measurement",
            )
            .expect("golden SIGN_TRANSFER must succeed");
            let m = resp_map(&encode_agent_response(&resp));
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            let bytes = |k: u64| as_bytes(map_get(&m, k).unwrap()).unwrap().to_vec();
            let uint = |k: u64| as_u64(map_get(&m, k).unwrap()).unwrap();
            assert_eq!(
                bytes(1),
                unhex(o["signed_rlp"].as_str().unwrap()),
                "signed_rlp"
            );
            assert_eq!(bytes(2), unhex(o["signature"]["r"].as_str().unwrap()), "r");
            assert_eq!(bytes(3), unhex(o["signature"]["s"].as_str().unwrap()), "s");
            assert_eq!(
                uint(4),
                o["signature"]["recovery_id"].as_u64().unwrap(),
                "recovery_id"
            );
            assert_eq!(uint(5), o["signature"]["v_eip155"].as_u64().unwrap(), "v");
            assert_eq!(
                bytes(6),
                unhex(o["signing_hash_keccak256"].as_str().unwrap()),
                "signing_hash"
            );
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
            assert_eq!(
                decode_agent_error_code(&out),
                None,
                "must be a success body, not an error"
            );
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
            let err = |req: &[u8]| {
                dispatch_agent(Profile::AgentGateway, req, &body, b"test-measurement").err()
            };

            // wrong chain_id (never request-authoritative) → Malformed
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid + 1,
                    &from,
                    &to,
                    val(),
                    0,
                    21000,
                    gp(),
                    empty()
                )),
                Some(AgentError::Malformed),
                "wrong chain_id"
            );
            // `from` != the key's derived address → KeyPurposeMismatch (key-related → uniform 0x42,
            // anti-oracle: reaching the from-check means the key exists + is a transfer key).
            let mut bad_from = from;
            bad_from[0] ^= 0xff;
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &bad_from,
                    &to,
                    val(),
                    0,
                    21000,
                    gp(),
                    empty()
                )),
                Some(AgentError::KeyPurposeMismatch),
                "from != derived"
            );
            // non-empty `data` (no generic-digest / calldata path in MVP) → Malformed
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    val(),
                    0,
                    21000,
                    gp(),
                    Value::Bytes(vec![0xde, 0xad])
                )),
                Some(AgentError::Malformed),
                "non-empty data"
            );
            // over-width amount (33 bytes > u256) → Malformed (never truncated, §2 AC#8)
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    Value::Bytes(vec![0x01; 33]),
                    0,
                    21000,
                    gp(),
                    empty()
                )),
                Some(AgentError::Malformed),
                "over-width amount"
            );
            // non-minimal amount (leading zero byte) → Malformed (canonical u256 wire form)
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    Value::Bytes(vec![0x00, 0x01]),
                    0,
                    21000,
                    gp(),
                    empty()
                )),
                Some(AgentError::Malformed),
                "non-minimal amount"
            );
            // amount as a CBOR uint (not a byte string) → Malformed (u256 fields are byte strings)
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    Value::Integer(5.into()),
                    0,
                    21000,
                    gp(),
                    empty()
                )),
                Some(AgentError::Malformed),
                "amount not a bstr"
            );
            // unknown key_ref → KeyPurposeMismatch (anti-oracle: not-found ≡ wrong-purpose)
            assert_eq!(
                err(&request(
                    &[0x99; 32],
                    cid,
                    &from,
                    &to,
                    val(),
                    0,
                    21000,
                    gp(),
                    empty()
                )),
                Some(AgentError::KeyPurposeMismatch),
                "unknown key_ref"
            );
            // the SAME malformed u256 encodings on `gas_price` (key 7) → Malformed — symmetric with
            // `amount` (key 4); both decode through `as_u256_minimal_be`, so this pins key 7's wiring.
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    val(),
                    0,
                    21000,
                    Value::Bytes(vec![0x01; 33]),
                    empty()
                )),
                Some(AgentError::Malformed),
                "over-width gas_price"
            );
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    val(),
                    0,
                    21000,
                    Value::Bytes(vec![0x00, 0x01]),
                    empty()
                )),
                Some(AgentError::Malformed),
                "non-minimal gas_price"
            );
            assert_eq!(
                err(&request(
                    &key_ref,
                    cid,
                    &from,
                    &to,
                    val(),
                    0,
                    21000,
                    Value::Integer(5.into()),
                    empty()
                )),
                Some(AgentError::Malformed),
                "gas_price not a bstr"
            );
        }

        #[test]
        fn rejects_wrong_key_purpose() {
            // A faucet-treasury key under SIGN_TRANSFER → KeyPurposeMismatch (cross-use, §4). Collapses
            // with key-not-found so the host cannot tell "wrong purpose" from "absent".
            let (body, key_ref, from) =
                body_with_key("treasury_key", KeyPurpose::AgentFaucetTreasuryK1);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &golden_request(&key_ref, &from),
                    &body,
                    b"test-measurement"
                )
                .err(),
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
                (
                    Value::Integer(1.into()),
                    Value::Integer(o["chain_id"].as_u64().unwrap().into()),
                ),
                (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                (
                    Value::Integer(4.into()),
                    Value::Bytes(min_be(o["fields"]["value"].as_u64().unwrap())),
                ),
                (Value::Integer(5.into()), Value::Integer(0.into())),
                (Value::Integer(6.into()), Value::Integer(21000.into())),
                (
                    Value::Integer(7.into()),
                    Value::Bytes(min_be(o["fields"]["gas_price"].as_u64().unwrap())),
                ),
                (Value::Integer(8.into()), Value::Bytes(vec![])),
            ]);
            let req = envelope(
                4,
                vec![
                    (
                        Value::Integer(5.into()),
                        Value::Map(vec![(Value::Integer(1.into()), Value::Integer(1.into()))]),
                    ),
                    (Value::Integer(6.into()), Value::Bytes(key_ref.to_vec())),
                    (Value::Integer(7.into()), payload),
                ],
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &req, &body, b"test-measurement").err(),
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
                            (
                                Value::Integer(1.into()),
                                Value::Integer(o["chain_id"].as_u64().unwrap().into()),
                            ),
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
                dispatch_agent(Profile::AgentGateway, &missing, &body, b"test-measurement").err(),
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
                            (
                                Value::Integer(1.into()),
                                Value::Integer(o["chain_id"].as_u64().unwrap().into()),
                            ),
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
                dispatch_agent(Profile::AgentGateway, &extra, &body, b"test-measurement").err(),
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
                    dispatch_agent(Profile::AgentGateway, &req, &body, b"test-measurement").err(),
                    Some(AgentError::Malformed),
                    "wrong-length to"
                );
            }
            // 19-byte `from` → Malformed (a SHAPE error caught at decode, before the semantic
            // from!=derived 0x42 check) — pins the shape-vs-key band split for `from`.
            let req = build(Value::Bytes(vec![0u8; 19]), Value::Bytes(to.to_vec()));
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &req, &body, b"test-measurement").err(),
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
            let resp = dispatch_agent(Profile::AgentGateway, &req, &body, b"test-measurement")
                .expect("zero-value transfer must sign");
            let m = resp_map(&encode_agent_response(&resp));
            assert_eq!(
                as_bytes(map_get(&m, 7).unwrap()).unwrap().to_vec(),
                from.to_vec(),
                "from"
            );
            assert!(
                !as_bytes(map_get(&m, 1).unwrap()).unwrap().is_empty(),
                "signed_rlp present"
            );
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
                    (
                        Value::Integer(6.into()),
                        Value::Bytes([0x33u8; 32].to_vec()),
                    ),
                    (Value::Integer(7.into()), Value::Map(vec![])),
                    (Value::Integer(8.into()), Value::Integer(0.into())),
                ],
            );
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &extra_outer,
                    &body,
                    b"test-measurement"
                )
                .err(),
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
                creation_metadata: CreationMetadata {
                    config_version: 1,
                    counter_snapshot: 0,
                    batch_id: batch,
                },
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
            body.entries.push(entry(
                "treasury_key",
                TREASURY_REF,
                KeyPurpose::AgentFaucetTreasuryK1,
                1,
            ));
            body.entries.push(entry(
                "transfer_key",
                TRANSFER_REF,
                KeyPurpose::AgentTransferK1,
                2,
            ));
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
            let resp = dispatch_agent(
                Profile::AgentGateway,
                &good_request(&from, &to),
                &body,
                b"test-measurement",
            )
            .expect("an in-cap dispense to a known transfer key must succeed");
            match resp {
                AgentResponse::SignFaucetDispense {
                    signed,
                    candidate,
                    request_id,
                } => {
                    // Signed FROM the treasury key (recovery==from invariant holds inside sign_transfer).
                    assert_eq!(signed.from, from, "dispense signed by the treasury key");
                    assert!(
                        !signed.signed_rlp.is_empty(),
                        "broadcastable signed tx present"
                    );
                    // The envelope's request_id is echoed verbatim — the frame layer keys the anchor
                    // commit record by it (idempotency).
                    assert_eq!(
                        request_id,
                        vec![0x11; 16],
                        "request_id echoed from the envelope"
                    );
                    // BOTH spend counters advanced by worst_case; budget/caps untouched; EpochOnly bump.
                    let wc = crate::u256::from_u64(worst_case());
                    assert_eq!(
                        candidate.faucet.cumulative_native_spend, wc,
                        "cumulative debited"
                    );
                    assert_eq!(candidate.faucet.lifetime_spend, wc, "lifetime debited");
                    assert_eq!(
                        candidate.faucet.cumulative_signing_budget,
                        body.faucet.cumulative_signing_budget,
                        "budget unchanged"
                    );
                    assert_eq!(
                        candidate.freshness_epoch,
                        body.freshness_epoch + 1,
                        "EpochOnly: epoch advanced"
                    );
                    assert_eq!(
                        candidate.structural_version, body.structural_version,
                        "EpochOnly: structural untouched"
                    );
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
                dispatch_agent(
                    Profile::AgentGateway,
                    &good_request(&from, &stranger),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::KeyPurposeMismatch),
                "recipient not a known transfer identity"
            );
            // The treasury's OWN address is also not a transfer-key recipient → still 0x42 (no self-dispense
            // shortcut past the allowlist).
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &good_request(&from, &from),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::KeyPurposeMismatch),
                "treasury address is not an allowlisted recipient"
            );
        }

        #[test]
        fn recipient_allowlist_matches_only_stored_transfer_keys() {
            // Unit-test the custody gate in isolation (the inline-vs-named-helper altitude fix).
            let (body, treasury_from, transfer_to) = faucet_body(10_000_000);
            // The stored transfer key's address matches; the treasury's own address does NOT (only
            // AgentTransferK1 entries are recipients); a stranger does not.
            assert!(
                is_known_transfer_recipient(&body, &transfer_to),
                "stored transfer key is a recipient"
            );
            assert!(
                !is_known_transfer_recipient(&body, &treasury_from),
                "treasury address is not a recipient"
            );
            assert!(
                !is_known_transfer_recipient(&body, &[0xab; 20]),
                "stranger is not a recipient"
            );
            // A malformed transfer entry (wrong-length public_identity) never matches — fail-closed, no
            // panic (defense-in-depth on a trusted-but-validated sealed entry).
            let mut malformed = body.clone();
            malformed.entries.push(KeyEntry {
                key_ref: [0x77; 32],
                purpose: KeyPurpose::AgentTransferK1,
                algorithm: KeyAlgorithm::Secp256k1,
                public_identity: vec![0x04; 64], // 64 bytes, not the 65-byte SEC1 form
                secret_scalar: zeroize::Zeroizing::new(vec![0x01; 32]),
                creation_metadata: CreationMetadata {
                    config_version: 1,
                    counter_snapshot: 0,
                    batch_id: 9,
                },
                backup_export_metadata: BackupExportMetadata::default(),
            });
            assert!(
                !is_known_transfer_recipient(&malformed, &[0x00; 20]),
                "malformed entry never matches"
            );
            // and the GOOD transfer key still matches alongside the malformed one.
            assert!(
                is_known_transfer_recipient(&malformed, &transfer_to),
                "good entry still matches"
            );
        }

        #[test]
        fn rejects_wrong_signer_key_purpose_and_from() {
            let _g = gate_configured();
            let (body, from, to) = faucet_body(10_000_000);
            // The TRANSFER key as the signer (key_ref) → 0x42 (faucet accepts only the treasury purpose;
            // cross-use collapses with not-found).
            let transfer_signer = request(
                &TRANSFER_REF,
                11565,
                &addr("transfer_key"),
                &to,
                Value::Bytes(min_be(DISP_AMOUNT)),
                0,
                DISP_GAS_LIMIT,
                Value::Bytes(min_be(DISP_GAS_PRICE)),
                Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &transfer_signer,
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::KeyPurposeMismatch),
                "transfer key cannot sign a faucet dispense"
            );
            // unknown key_ref → 0x42.
            let unknown = request(
                &[0x99; 32],
                11565,
                &from,
                &to,
                Value::Bytes(min_be(DISP_AMOUNT)),
                0,
                DISP_GAS_LIMIT,
                Value::Bytes(min_be(DISP_GAS_PRICE)),
                Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &unknown, &body, b"test-measurement").err(),
                Some(AgentError::KeyPurposeMismatch),
                "unknown signer key_ref"
            );
            // `from` != the treasury key's derived address → 0x42 (per-key bucket, key established).
            let mut bad_from = from;
            bad_from[0] ^= 0xff;
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &good_request(&bad_from, &to),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::KeyPurposeMismatch),
                "from != treasury derived address"
            );
        }

        #[test]
        fn rejects_shape_errors_as_malformed() {
            let _g = gate_configured();
            let (body, from, to) = faucet_body(10_000_000);
            let err = |req: &[u8]| {
                dispatch_agent(Profile::AgentGateway, req, &body, b"test-measurement").err()
            };
            // wrong chain_id (never request-authoritative) → 0x40.
            assert_eq!(
                err(&request(
                    &TREASURY_REF,
                    11566,
                    &from,
                    &to,
                    Value::Bytes(min_be(DISP_AMOUNT)),
                    0,
                    DISP_GAS_LIMIT,
                    Value::Bytes(min_be(DISP_GAS_PRICE)),
                    Value::Bytes(vec![])
                )),
                Some(AgentError::Malformed),
                "wrong chain_id"
            );
            // non-empty data (no calldata/memo) → 0x40.
            assert_eq!(
                err(&request(
                    &TREASURY_REF,
                    11565,
                    &from,
                    &to,
                    Value::Bytes(min_be(DISP_AMOUNT)),
                    0,
                    DISP_GAS_LIMIT,
                    Value::Bytes(min_be(DISP_GAS_PRICE)),
                    Value::Bytes(vec![0xde, 0xad])
                )),
                Some(AgentError::Malformed),
                "non-empty data"
            );
            // over-width amount (33 bytes) → 0x40 (never truncated, §2 AC#8) — a SHAPE error caught at
            // decode BEFORE the §2 cap gate (which would be 0x44), pinning the band split.
            assert_eq!(
                err(&request(
                    &TREASURY_REF,
                    11565,
                    &from,
                    &to,
                    Value::Bytes(vec![0x01; 33]),
                    0,
                    DISP_GAS_LIMIT,
                    Value::Bytes(min_be(DISP_GAS_PRICE)),
                    Value::Bytes(vec![])
                )),
                Some(AgentError::Malformed),
                "over-width amount"
            );
            // non-minimal gas_price (leading zero) → 0x40.
            assert_eq!(
                err(&request(
                    &TREASURY_REF,
                    11565,
                    &from,
                    &to,
                    Value::Bytes(min_be(DISP_AMOUNT)),
                    0,
                    DISP_GAS_LIMIT,
                    Value::Bytes(vec![0x00, 0x01]),
                    Value::Bytes(vec![])
                )),
                Some(AgentError::Malformed),
                "non-minimal gas_price"
            );
        }

        #[test]
        fn absent_key_ref_is_malformed_not_key_band() {
            // An ABSENT envelope key_ref (key 6 omitted) is a structurally-incomplete request → 0x40
            // (shape), NOT the 0x42 key-band — pins the chosen band (matches SIGN_TRANSFER; a present-but-
            // unknown key_ref is the 0x42 case, covered by rejects_wrong_signer_key_purpose_and_from).
            let _g = gate_configured();
            let (body, from, to) = faucet_body(10_000_000);
            // A valid 8-field payload, but the envelope carries NO key_ref.
            let payload = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(11565.into())),
                (Value::Integer(2.into()), Value::Bytes(from.to_vec())),
                (Value::Integer(3.into()), Value::Bytes(to.to_vec())),
                (Value::Integer(4.into()), Value::Bytes(min_be(DISP_AMOUNT))),
                (Value::Integer(5.into()), Value::Integer(0.into())),
                (
                    Value::Integer(6.into()),
                    Value::Integer(DISP_GAS_LIMIT.into()),
                ),
                (
                    Value::Integer(7.into()),
                    Value::Bytes(min_be(DISP_GAS_PRICE)),
                ),
                (Value::Integer(8.into()), Value::Bytes(vec![])),
            ]);
            let no_key_ref = envelope(5, vec![(Value::Integer(7.into()), payload)]);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &no_key_ref,
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::Malformed),
                "absent key_ref → shape error (0x40), not the key band"
            );
        }

        #[test]
        fn rejects_cap_and_budget_as_cap_exceeded() {
            let _g = gate_configured();
            // amount over the per-dispense cap → 0x44 (key+recipient valid, so the §2 gate is reached).
            let (body, from, to) = faucet_body(10_000_000_000);
            let over_amount = request(
                &TREASURY_REF,
                11565,
                &from,
                &to,
                Value::Bytes(min_be(2_000_000)),
                0,
                DISP_GAS_LIMIT,
                Value::Bytes(min_be(DISP_GAS_PRICE)),
                Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &over_amount,
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapExceeded),
                "amount over per_dispense_max_amount"
            );
            // gas_limit over the cap → 0x44.
            let over_gas = request(
                &TREASURY_REF,
                11565,
                &from,
                &to,
                Value::Bytes(min_be(DISP_AMOUNT)),
                0,
                21_001,
                Value::Bytes(min_be(DISP_GAS_PRICE)),
                Value::Bytes(vec![]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &over_gas, &body, b"test-measurement").err(),
                Some(AgentError::CapExceeded),
                "gas_limit over max_gas_limit"
            );
            // worst_case over the cumulative budget → 0x44 (budget too small for one dispense).
            let (tiny, from2, to2) = faucet_body(worst_case() - 1);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &good_request(&from2, &to2),
                    &tiny,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapExceeded),
                "worst_case over cumulative_signing_budget"
            );
            // an UNCONFIGURED budget (==0) rejects every dispense, even an in-cap one → 0x44.
            let (unconf, from3, to3) = faucet_body(0);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &good_request(&from3, &to3),
                    &unconf,
                    b"test-measurement"
                )
                .err(),
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
                dispatch_agent(
                    Profile::AgentGateway,
                    &good_request(&from, &to),
                    &body,
                    b"test-measurement"
                )
                .err(),
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
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Ok
            ))));

            let out = handle_agent_gateway_frame(&good_request(&from, &to));
            assert_eq!(
                decode_agent_error_code(&out),
                None,
                "first dispense is a success body"
            );
            let m = resp_map(&out);
            // signed-tx 7-key map + key 8 = the non-empty sealed keystore blob the host persists.
            assert_eq!(
                as_bytes(map_get(&m, 7).unwrap()).unwrap().to_vec(),
                from.to_vec(),
                "from = treasury"
            );
            assert!(
                !as_bytes(map_get(&m, 1).unwrap()).unwrap().is_empty(),
                "key 1 = signed_rlp"
            );
            assert!(
                !as_bytes(map_get(&m, 8).unwrap()).unwrap().is_empty(),
                "key 8 = sealed blob"
            );

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
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Transport
            ))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                Some(0x46),
                "commit transport failure ⇒ SealFailed"
            );
            reset_commit_channel_for_tests();
            // (c) forged ACK (wrong signer) → 0x46.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::WrongKey
            ))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                Some(0x46),
                "forged commit ack ⇒ SealFailed"
            );
            reset_commit_channel_for_tests();
            // (d) PROOF OF NO DEBIT: the live faucet never advanced across all three failures, so a
            // conformant channel now accepts the SAME single-worst_case dispense against the full budget.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Ok
            ))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&good_request(&from, &to))),
                None,
                "the failed dispenses never debited ⇒ the budget is intact and the dispense now succeeds"
            );
            reset_agent_keystore_for_tests();
        }
    }

    // ===================== slice 15-4: CONFIGURE_TREASURY =====================

    /// Pure classifier test (no feature needed): ALL FOUR CONFIGURE_TREASURY sub-ops are Structural,
    /// matching the opcode-level class. reset_lifetime_breaker(3) is Structural — NOT EpochOnly — because
    /// it LOWERS `lifetime_spend` (a marks surface the AdoptForward `marks_dominate_local` belt would
    /// reject) and mutates non-marks state (breaker + config_version); its effect is not
    /// AdoptForward-reconstructable, so a dropped seal must `StructuralGap`→restore (TASK-15 15-4 review).
    #[test]
    fn configure_treasury_sub_op_bump_class_all_structural() {
        for sub_op in 0u8..=3 {
            assert_eq!(
                configure_treasury_sub_op_bump_class(sub_op),
                CommitBumpClass::Structural,
                "sub_op={sub_op} must be Structural (no CONFIGURE sub-op is AdoptForward-safe)"
            );
        }
        // Consistent with the opcode-level class (Structural for the whole opcode).
        assert_eq!(
            AgentOpcode::ConfigureTreasury.commit_bump_class(),
            CommitBumpClass::Structural
        );
    }

    #[cfg(feature = "agent-configure-treasury-preview")]
    mod configure_treasury {
        use super::*;
        use ed25519_dalek::SigningKey;

        const SCOPE: &[u8] = b"configure_treasury";

        fn min_be(x: u64) -> Vec<u8> {
            let b = x.to_be_bytes();
            let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
            b[i..].to_vec()
        }

        fn resp_map(body: &[u8]) -> Vec<(Value, Value)> {
            match ciborium::de::from_reader::<Value, _>(body).unwrap() {
                Value::Map(m) => m,
                _ => panic!("response is not a CBOR map"),
            }
        }

        /// Build a CONFIGURE_TREASURY cap (covering sub_op + canonical params) + the matching
        /// envelope-key-7 payload. `authority`/`is_recovery` must match the sub-op's tier (admin for 0..=2,
        /// recovery for 3); pass them mismatched to exercise the verify-layer tier rejection.
        #[allow(clippy::type_complexity)]
        fn cap_and_payload(
            authority: &SigningKey,
            is_recovery: bool,
            sub_op: u8,
            request_id: &[u8],
            counter: u64,
            field2_min: &[u8],
            set_limits_gas: Option<(u64, u64)>,
        ) -> (Vec<(Value, Value)>, Vec<(Value, Value)>) {
            let cp = configure_treasury_canonical_params(sub_op, field2_min, set_limits_gas);
            let pb = crate::agent_capability::payload_binding(6, Some(sub_op), request_id, &cp);
            let cap = crate::agent_capability::test_signed_capability_with_sub_op(
                authority,
                6,
                Some(sub_op),
                request_id,
                counter,
                is_recovery,
                11565,
                "testnet",
                0,
                SCOPE,
                2,
                pb,
                [0xe1; 32],
            );
            let mut payload = vec![
                (
                    Value::Integer(1.into()),
                    Value::Integer(u64::from(sub_op).into()),
                ),
                (Value::Integer(2.into()), Value::Bytes(field2_min.to_vec())),
            ];
            if let Some((gl, fr)) = set_limits_gas {
                payload.push((Value::Integer(3.into()), Value::Integer(gl.into())));
                payload.push((Value::Integer(4.into()), Value::Integer(fr.into())));
            }
            (cap, payload)
        }

        fn env_for(cap: Vec<(Value, Value)>, payload: Vec<(Value, Value)>) -> Vec<u8> {
            envelope(
                6,
                vec![
                    (Value::Integer(5.into()), Value::Map(cap)),
                    (Value::Integer(7.into()), Value::Map(payload)),
                ],
            )
        }

        fn body_with_authorities(admin: &SigningKey, recovery: &SigningKey) -> KeystoreBody {
            let mut body = base_body();
            body.config.admin_authority_pk = admin.verifying_key().to_bytes();
            body.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
            body
        }

        fn admin_key() -> SigningKey {
            SigningKey::from_bytes(&[7u8; 32])
        }
        fn recovery_key() -> SigningKey {
            SigningKey::from_bytes(&[8u8; 32])
        }

        #[test]
        fn set_limits_bumps_config_and_structural() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            let (cap, pay) = cap_and_payload(
                &admin,
                false,
                0,
                &[0x11; 16],
                1,
                &min_be(1_000_000),
                Some((30_000, 250)),
            );
            match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury {
                    candidate,
                    request_id,
                } => {
                    assert_eq!(request_id, vec![0x11; 16], "request_id echoed");
                    assert_eq!(
                        candidate.faucet.per_dispense_max_amount,
                        crate::u256::from_u64(1_000_000)
                    );
                    assert_eq!(candidate.faucet.max_gas_limit, 30_000);
                    assert_eq!(candidate.faucet.max_effective_gas_fee_rate, 250);
                    // spend/budget untouched.
                    assert_eq!(
                        candidate.faucet.cumulative_native_spend,
                        body.faucet.cumulative_native_spend
                    );
                    assert_eq!(candidate.faucet.lifetime_spend, body.faucet.lifetime_spend);
                    assert_eq!(
                        candidate.faucet.cumulative_signing_budget,
                        body.faucet.cumulative_signing_budget
                    );
                    // Structural: config_version + structural + epoch all advance.
                    assert_eq!(
                        candidate.config.monotonic_treasury_config_version,
                        body.config.monotonic_treasury_config_version + 1
                    );
                    assert_eq!(candidate.structural_version, body.structural_version + 1);
                    assert_eq!(candidate.freshness_epoch, body.freshness_epoch + 1);
                }
                _ => panic!("expected ConfigureTreasury"),
            }
        }

        /// 4c-1 AC#14: a successful CONFIGURE appends EXACTLY ONE audit record with full provenance. The
        /// CONFIGURE-specific property vs 4b GENERATE_KEYS: `config_version` is the POST-bump value
        /// (CONFIGURE bumps it via `advance_treasury_config_version`), pinned by asserting it equals
        /// base+1 — a pre-bump read would record the stale base value.
        #[test]
        fn configure_audit_record_appended_with_post_bump_provenance() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            let (cap, pay) = cap_and_payload(
                &admin,
                false,
                0,
                &[0x11; 16],
                1,
                &min_be(1_000_000),
                Some((30_000, 250)),
            );
            match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury { candidate, .. } => {
                    assert_eq!(
                        candidate.audit.records.len(),
                        1,
                        "exactly one audit record per committed op"
                    );
                    assert_eq!(
                        candidate.audit.next_seq,
                        body.audit.next_seq + 1,
                        "next_seq advanced by 1"
                    );
                    let r = &candidate.audit.records[0];
                    assert_eq!(r.seq, body.audit.next_seq, "record seq = the old next_seq");
                    assert_eq!(r.op, 6, "op = CONFIGURE_TREASURY wire opcode");
                    assert_eq!(
                        r.authority,
                        admin.verifying_key().to_bytes(),
                        "authority = cap authority"
                    );
                    assert_eq!(r.counter, 1, "counter = the accepted cap batch sequence");
                    assert_eq!(
                        r.config_version,
                        body.config.monotonic_treasury_config_version + 1,
                        "config_version is the POST-bump value (CONFIGURE bumps it — a pre-bump read would be stale)"
                    );
                    assert_eq!(
                        r.config_version, candidate.config.monotonic_treasury_config_version,
                        "and it equals the finalized candidate's config_version"
                    );
                    assert_eq!(r.scope_class, 0, "scope_class = cap scope_class");
                    assert_eq!(r.scope_target, SCOPE.to_vec(), "scope_target = cap scope");
                    assert_eq!(
                        r.request_id,
                        vec![0x11u8; 16],
                        "request_id = envelope request_id"
                    );
                }
                _ => panic!("expected ConfigureTreasury"),
            }
        }

        /// 4c-1 AC#14: a CONFIGURE against a full+undrained audit ring fails closed (0x46) in Phase A —
        /// `record_audit` returns `AuditBackpressure` → `SealFailed` BEFORE the frame reaches
        /// `commit_before_emit` (commit-counter == 0, no anchor commit, no swap). Mirrors the 4b proof.
        #[test]
        fn configure_audit_backpressure_fails_closed_never_commits() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::sync::Arc;
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
            // Saturate the ring (capacity 1, one undrained record) via record_audit so the state is
            // guaranteed validate()-consistent (records=[seq1], next_seq=2, last_exported_seq=0).
            body.audit.capacity = 1;
            body.record_audit(&crate::agent_keystore::AuditAppend {
                op: 6,
                authority: &[0u8; 32],
                counter: 0,
                config_version: 0,
                scope_class: 0,
                scope_target: b"seed",
                request_id: b"seed",
            })
            .expect("first append fills the cap-1 ring");
            assert!(install_agent_keystore(body, b"meas"));
            let calls = Arc::new(AtomicUsize::new(0));
            assert!(install_commit_channel(Box::new(
                TestCommitChannel::counted(CommitChannelAct::Ok, Arc::clone(&calls),)
            )));
            let (cap, pay) = cap_and_payload(
                &admin,
                false,
                0,
                &[0x11; 16],
                1,
                &min_be(1_000_000),
                Some((30_000, 250)),
            );
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&env_for(cap, pay))),
                Some(0x46),
                "a full undrained audit ring fails the CONFIGURE op closed with SealFailed"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "audit backpressure short-circuits in Phase A — the anchor commit was NEVER reached"
            );
            reset_agent_keystore_for_tests();
            reset_commit_channel_for_tests();
        }

        #[test]
        fn refill_budget_raises_and_resets_native_spend() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.faucet.cumulative_native_spend = crate::u256::from_u64(123);
            body.faucet.lifetime_spend = crate::u256::from_u64(456);
            let (cap, pay) =
                cap_and_payload(&admin, false, 1, &[0x11; 16], 1, &min_be(9_000_000), None);
            match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury { candidate, .. } => {
                    assert_eq!(
                        candidate.faucet.cumulative_signing_budget,
                        crate::u256::from_u64(9_000_000)
                    );
                    assert_eq!(
                        candidate.faucet.cumulative_native_spend, [0u8; 32],
                        "refill resets native spend"
                    );
                    assert_eq!(
                        candidate.faucet.lifetime_spend,
                        crate::u256::from_u64(456),
                        "lifetime untouched"
                    );
                    assert_eq!(
                        candidate.structural_version,
                        body.structural_version + 1,
                        "Structural"
                    );
                    assert_eq!(
                        candidate.config.monotonic_treasury_config_version,
                        body.config.monotonic_treasury_config_version + 1
                    );
                }
                _ => panic!("expected ConfigureTreasury"),
            }
        }

        #[test]
        fn refill_zero_budget_rejected_0x44() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            let (cap, pay) = cap_and_payload(&admin, false, 1, &[0x11; 16], 1, &min_be(0), None);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapExceeded),
                "refill to zero re-disables the faucet ⇒ 0x44"
            );
        }

        #[test]
        fn raise_breaker_sets_threshold_and_rejects_below_spend() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.faucet.lifetime_spend = crate::u256::from_u64(1_000);
            // threshold >= lifetime_spend: accepted.
            let (cap, pay) =
                cap_and_payload(&admin, false, 2, &[0x11; 16], 1, &min_be(5_000), None);
            match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury { candidate, .. } => {
                    assert_eq!(
                        candidate.faucet.circuit_breaker_threshold,
                        Some(crate::u256::from_u64(5_000))
                    );
                    assert_eq!(
                        candidate.structural_version,
                        body.structural_version + 1,
                        "Structural"
                    );
                }
                _ => panic!("expected ConfigureTreasury"),
            }
            // threshold < lifetime_spend: 0x44 (anti-inversion — would trip immediately).
            let (cap2, pay2) =
                cap_and_payload(&admin, false, 2, &[0x11; 16], 1, &min_be(999), None);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap2, pay2),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapExceeded),
                "breaker below accumulated lifetime_spend ⇒ 0x44"
            );
        }

        #[test]
        fn reset_breaker_is_structural_recovery_tier() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.faucet.lifetime_spend = crate::u256::from_u64(10_000);
            body.faucet.circuit_breaker_threshold = Some(crate::u256::from_u64(12_000));
            // reset to a lower target with a RECOVERY cap.
            let (cap, pay) =
                cap_and_payload(&recovery, true, 3, &[0x11; 16], 1, &min_be(2_000), None);
            match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury { candidate, .. } => {
                    assert_eq!(
                        candidate.faucet.lifetime_spend,
                        crate::u256::from_u64(2_000),
                        "lifetime lowered"
                    );
                    assert_eq!(
                        candidate.faucet.circuit_breaker_threshold, None,
                        "breaker cleared"
                    );
                    assert_eq!(
                        candidate.strict_recovery_counter,
                        body.strict_recovery_counter + 1,
                        "recovery counter advanced"
                    );
                    assert_eq!(
                        candidate.config.monotonic_treasury_config_version,
                        body.config.monotonic_treasury_config_version + 1,
                        "config_version still bumps"
                    );
                    // STRUCTURAL (not EpochOnly): reset LOWERS lifetime_spend (a marks surface the
                    // AdoptForward belt rejects) + clears the breaker + bumps config_version, so a dropped
                    // seal must StructuralGap→restore — structural_version MUST advance.
                    assert_eq!(
                        candidate.structural_version,
                        body.structural_version + 1,
                        "Structural: structural_version advances (TASK-15 15-4 review fix)"
                    );
                    assert_eq!(
                        candidate.freshness_epoch,
                        body.freshness_epoch + 1,
                        "epoch advanced"
                    );
                }
                _ => panic!("expected ConfigureTreasury"),
            }
            // target ABOVE current lifetime_spend → 0x44 (reset can only lower).
            let (cap2, pay2) =
                cap_and_payload(&recovery, true, 3, &[0x11; 16], 1, &min_be(20_000), None);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap2, pay2),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapExceeded),
                "reset target above current lifetime_spend ⇒ 0x44"
            );
        }

        /// 4c-1 AC#14: the audit append is sub-op-INDEPENDENT — it fires for the recovery-tier
        /// `reset_lifetime_breaker` (sub_op 3) too, recording op=6 with the RECOVERY cap's authority
        /// (not the admin's) and the post-bump config_version. Pins that the append sits after the
        /// `match params` block, not inside an admin-only arm.
        #[test]
        fn configure_audit_appended_for_recovery_tier_reset_breaker() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.faucet.lifetime_spend = crate::u256::from_u64(10_000);
            body.faucet.circuit_breaker_threshold = Some(crate::u256::from_u64(12_000));
            let (cap, pay) =
                cap_and_payload(&recovery, true, 3, &[0x11; 16], 1, &min_be(2_000), None);
            match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury { candidate, .. } => {
                    assert_eq!(
                        candidate.audit.records.len(),
                        1,
                        "one record even for the recovery-tier sub-op"
                    );
                    let r = &candidate.audit.records[0];
                    assert_eq!(r.op, 6, "op = CONFIGURE_TREASURY");
                    assert_eq!(
                        r.authority,
                        recovery.verifying_key().to_bytes(),
                        "authority = the RECOVERY cap authority (sub_op 3 is recovery-tier)"
                    );
                    assert_eq!(
                        r.config_version,
                        body.config.monotonic_treasury_config_version + 1,
                        "post-bump config_version"
                    );
                    assert_eq!(r.scope_target, SCOPE.to_vec());
                    assert_eq!(r.request_id, vec![0x11u8; 16]);
                }
                _ => panic!("expected ConfigureTreasury"),
            }
        }

        /// CRASH-RECONCILE PROOF (the TASK-15 15-4 review's missing test): a dropped reset_lifetime_breaker
        /// seal (committed to the anchor, crash before swap) must reconcile **StructuralGap → restore**, NOT
        /// the AdoptForward path whose `marks_dominate_local` belt would WEDGE on the LOWERED `lifetime_spend`.
        /// This is the load-bearing reason reset is Structural (not EpochOnly): because it advances
        /// `structural_version`, reconcile routes epoch+structural-ahead → StructuralGap, never the belt.
        #[test]
        fn reset_dropped_seal_reconciles_structural_gap_not_adopt_forward_wedge() {
            use crate::agent_anchor::{reconcile, AnchorState, FailReason, ReconcileDecision};
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.faucet.lifetime_spend = crate::u256::from_u64(10_000);
            body.faucet.circuit_breaker_threshold = Some(crate::u256::from_u64(12_000));
            let (le, ls) = (body.freshness_epoch, body.structural_version);
            let lmarks = body.compute_local_marks_digest();

            // Drive the REAL handler to get the post-reset candidate (lifetime lowered to 2000).
            let (cap, pay) =
                cap_and_payload(&recovery, true, 3, &[0x11; 16], 1, &min_be(2_000), None);
            let candidate = match dispatch_agent(
                Profile::AgentGateway,
                &env_for(cap, pay),
                &body,
                b"test-measurement",
            )
            .unwrap()
            {
                AgentResponse::ConfigureTreasury { candidate, .. } => candidate,
                _ => panic!("expected ConfigureTreasury"),
            };
            assert_eq!(
                candidate.structural_version,
                ls + 1,
                "reset is Structural — structural advanced"
            );
            assert!(
                candidate.faucet.lifetime_spend < body.faucet.lifetime_spend,
                "reset LOWERED lifetime_spend (the marks decrease)"
            );

            let anchor_of = |b: &KeystoreBody| AnchorState {
                epoch: b.freshness_epoch,
                structural_version: b.structural_version,
                marks_digest: b.compute_local_marks_digest(),
                chain_height: None,
                chain_block_hash: None,
            };
            // THE FIX: anchor ahead by epoch AND structural ⇒ StructuralGap ⇒ restore-from-backup
            // re-presents the lowered spend + cleared breaker + bumped config_version. No belt, no wedge.
            assert_eq!(
                reconcile(le, ls, &lmarks, &anchor_of(&candidate)),
                ReconcileDecision::FailClosed(FailReason::StructuralGap),
                "dropped reset seal ⇒ StructuralGap (restore), the safe recovery path"
            );

            // COUNTERFACTUAL — why EpochOnly was wrong: simulate the rejected EpochOnly class by presenting
            // the candidate's LOWERED marks at the OLD structural_version. reconcile then routes to
            // AdoptForward (epoch-ahead, structural-equal) — where `execute_adopt_forward`'s
            // `marks_dominate_local` belt REJECTS the lowered lifetime_spend (`BeltRegression`), wedging the
            // recovery op fail-closed. (The belt rejection itself is pinned by
            // `execute_adopt_forward_belt_rejects_non_monotone_below_hash_gate` in agent_boot.) Reaching
            // AdoptForward at all with a marks DECREASE is the bug; Structural avoids it.
            let epoch_only_anchor = AnchorState {
                epoch: candidate.freshness_epoch,
                structural_version: ls, // EpochOnly would have left structural untouched
                marks_digest: candidate.compute_local_marks_digest(),
                chain_height: None,
                chain_block_hash: None,
            };
            assert_eq!(
                reconcile(le, ls, &lmarks, &epoch_only_anchor),
                ReconcileDecision::AdoptForward { epoch: candidate.freshness_epoch },
                "an EpochOnly reset would route to AdoptForward — where the belt wedges on the lowered spend"
            );
        }

        #[test]
        fn tier_mismatch_rejected_0x43() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            // reset(3) with an ADMIN cap (is_recovery=false) → 0x43 (verify-layer tier).
            let (cap, pay) = cap_and_payload(&admin, false, 3, &[0x11; 16], 1, &min_be(0), None);
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapabilityRejected),
                "reset with admin tier ⇒ 0x43"
            );
            // set_limits(0) with a RECOVERY cap → 0x43.
            let (cap2, pay2) =
                cap_and_payload(&recovery, true, 0, &[0x11; 16], 1, &min_be(1), Some((1, 1)));
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap2, pay2),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapabilityRejected),
                "set_limits with recovery tier ⇒ 0x43"
            );
        }

        #[test]
        fn sub_op_substitution_blocked_by_direct_binding() {
            // ADMIN cap legitimately for set_limits(0), but the REQUEST claims reset(3): the direct
            // `request.sub_op == cap.treasury_sub_op` check rejects it (0x43). This is the tier-separation
            // guard — without it an admin could authorize the recovery-tier reset.
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            let (cap, _pay0) =
                cap_and_payload(&admin, false, 0, &[0x11; 16], 1, &min_be(1), Some((1, 1)));
            let pay3 = vec![
                (Value::Integer(1.into()), Value::Integer(3u64.into())),
                (Value::Integer(2.into()), Value::Bytes(min_be(0))),
            ];
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay3),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapabilityRejected),
                "request sub_op != cap sub_op ⇒ 0x43"
            );
        }

        #[test]
        fn payload_binding_mismatch_0x43() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            // valid cap for set_limits, but the request alters max_gas_limit under it.
            let (cap, _pay) = cap_and_payload(
                &admin,
                false,
                0,
                &[0x11; 16],
                1,
                &min_be(1_000_000),
                Some((30_000, 250)),
            );
            let altered = vec![
                (Value::Integer(1.into()), Value::Integer(0u64.into())),
                (Value::Integer(2.into()), Value::Bytes(min_be(1_000_000))),
                (Value::Integer(3.into()), Value::Integer(99_999u64.into())), // altered
                (Value::Integer(4.into()), Value::Integer(250u64.into())),
            ];
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, altered),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapabilityRejected),
                "altered params under a valid cap ⇒ payload_binding mismatch 0x43"
            );
        }

        #[test]
        fn fleet_scope_rejected_0x43() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            // scope_class=1 (fleet) cap — handler re-asserts enclave-only (AC#12).
            let cp = configure_treasury_canonical_params(0, &min_be(1), Some((1, 1)));
            let pb = crate::agent_capability::payload_binding(6, Some(0), &[0x11; 16], &cp);
            let cap = crate::agent_capability::test_signed_capability_with_sub_op(
                &admin,
                6,
                Some(0),
                &[0x11; 16],
                1,
                false,
                11565,
                "testnet",
                1,
                SCOPE,
                2,
                pb,
                [0xf1; 32],
            );
            let pay = vec![
                (Value::Integer(1.into()), Value::Integer(0u64.into())),
                (Value::Integer(2.into()), Value::Bytes(min_be(1))),
                (Value::Integer(3.into()), Value::Integer(1u64.into())),
                (Value::Integer(4.into()), Value::Integer(1u64.into())),
            ];
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::CapabilityRejected),
                "fleet-scoped treasury cap ⇒ 0x43 (financial must be enclave, AC#12)"
            );
        }

        #[test]
        fn unknown_sub_op_in_request_0x40() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            // cap for valid sub_op 1; request payload sub_op = 4 → handler decode rejects ⇒ 0x40.
            let (cap, _pay) = cap_and_payload(&admin, false, 1, &[0x11; 16], 1, &min_be(1), None);
            let pay4 = vec![
                (Value::Integer(1.into()), Value::Integer(4u64.into())),
                (Value::Integer(2.into()), Value::Bytes(min_be(1))),
            ];
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay4),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::Malformed),
                "unknown sub_op in the request ⇒ 0x40"
            );
        }

        #[test]
        fn overwidth_u256_0x40() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            let (cap, _pay) = cap_and_payload(&admin, false, 1, &[0x11; 16], 1, &min_be(1), None);
            let pay = vec![
                (Value::Integer(1.into()), Value::Integer(1u64.into())),
                (Value::Integer(2.into()), Value::Bytes(vec![0x01; 33])), // 33 bytes → over-width
            ];
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::Malformed),
                "over-width u256 ⇒ 0x40"
            );
        }

        #[test]
        fn wrong_key_count_0x40() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            // refill(1) expects exactly 2 keys; send an extra key 3 → 0x40.
            let (cap, _pay) =
                cap_and_payload(&admin, false, 1, &[0x11; 16], 1, &min_be(9_000_000), None);
            let pay = vec![
                (Value::Integer(1.into()), Value::Integer(1u64.into())),
                (Value::Integer(2.into()), Value::Bytes(min_be(9_000_000))),
                (Value::Integer(3.into()), Value::Integer(7u64.into())), // unexpected extra key
            ];
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::Malformed),
                "extra key for refill ⇒ 0x40"
            );
        }

        #[test]
        fn gated_off_when_anti_rollback_unconfigured() {
            let _g = gate_unconfigured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let body = body_with_authorities(&admin, &recovery);
            let (cap, pay) =
                cap_and_payload(&admin, false, 0, &[0x11; 16], 1, &min_be(1), Some((1, 1)));
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &env_for(cap, pay),
                    &body,
                    b"test-measurement"
                )
                .err(),
                Some(AgentError::NotConfigured),
                "rollback-sensitive ⇒ NotConfigured when the binding is absent"
            );
        }

        #[test]
        fn frame_path_seals_commits_and_swaps_config_version() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
            assert!(install_agent_keystore(body, b"meas"));
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Ok
            ))));

            let (cap, pay) = cap_and_payload(
                &admin,
                false,
                0,
                &[0x11; 16],
                1,
                &min_be(1_000_000),
                Some((30_000, 250)),
            );
            let out = handle_agent_gateway_frame(&env_for(cap, pay));
            assert_eq!(
                decode_agent_error_code(&out),
                None,
                "first config is a success body"
            );
            let m = resp_map(&out);
            assert!(
                !as_bytes(map_get(&m, 1).unwrap()).unwrap().is_empty(),
                "key 1 = sealed blob"
            );

            // PROOF OF SWAP: the live slot's counter advanced to 1, so a second request reusing counter 1 is
            // now non-contiguous ⇒ 0x43. (If the first hadn't swapped, counter 1 would still be expected.)
            let (cap2, pay2) = cap_and_payload(
                &admin,
                false,
                0,
                &[0x11; 16],
                1,
                &min_be(2_000_000),
                Some((30_000, 250)),
            );
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&env_for(cap2, pay2))),
                Some(0x43),
                "reused counter after the swap ⇒ 0x43 (proves the candidate swapped into the live slot)"
            );
            reset_agent_keystore_for_tests();
            reset_commit_channel_for_tests();
        }

        #[test]
        fn frame_path_commit_failure_fails_closed_no_config_bump() {
            let _g = gate_configured();
            let (admin, recovery) = (admin_key(), recovery_key());
            let mut body = body_with_authorities(&admin, &recovery);
            body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
            assert!(install_agent_keystore(body, b"meas"));

            let mk = || {
                let (cap, pay) = cap_and_payload(
                    &admin,
                    false,
                    0,
                    &[0x11; 16],
                    1,
                    &min_be(1_000_000),
                    Some((30_000, 250)),
                );
                env_for(cap, pay)
            };
            // (a) no channel → 0x46.
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&mk())),
                Some(0x46),
                "no channel ⇒ 0x46"
            );
            // (b) transport failure → 0x46.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Transport
            ))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&mk())),
                Some(0x46),
                "transport ⇒ 0x46"
            );
            reset_commit_channel_for_tests();
            // (c) forged ACK → 0x46.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::WrongKey
            ))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&mk())),
                Some(0x46),
                "forged ack ⇒ 0x46"
            );
            reset_commit_channel_for_tests();
            // (d) PROOF OF NO MUTATION: the live config never advanced across the 3 failures, so the SAME
            // request (counter 1) now SUCCEEDS once a conformant channel is installed.
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Ok
            ))));
            assert_eq!(
                decode_agent_error_code(&handle_agent_gateway_frame(&mk())),
                None,
                "no prior bump ⇒ counter 1 still valid ⇒ succeeds"
            );
            reset_agent_keystore_for_tests();
            reset_commit_channel_for_tests();
        }
    }

    #[cfg(feature = "agent-backup-export-preview")]
    mod export_backup {
        use super::*;
        use ed25519_dalek::SigningKey;

        const ESCOPE: &[u8] = b"export_backup";

        fn admin_key() -> SigningKey {
            SigningKey::from_bytes(&[7u8; 32])
        }

        /// A valid ML-KEM-1024 recovery ENCAPS (public) key from a fixed seed — TEST ONLY.
        fn valid_recovery_encaps_key() -> Vec<u8> {
            use ml_kem::{DecapsulationKey, KeyExport as _, MlKem1024};
            let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from([0x42u8; 64]));
            dk.encapsulation_key().to_bytes().as_slice().to_vec()
        }

        /// A body with `n` transfer keys (batch_id 7) + `anchor_root` set + 2 pre-seeded UN-exported audit
        /// records (so the EXPORT drain has history to advance). `valid_recovery=false` keeps base_body's
        /// non-ML-KEM recovery key so the seal fails closed.
        fn export_body(admin: &SigningKey, n: usize, valid_recovery: bool) -> KeystoreBody {
            let mut body = base_body();
            body.config.admin_authority_pk = admin.verifying_key().to_bytes();
            body.config.anchor_root = anchor_test_key().verifying_key().to_bytes();
            body.config.backup_recovery_wrapping_pubkey = if valid_recovery {
                valid_recovery_encaps_key()
            } else {
                vec![0xb0; 100] // wrong length ⇒ seal_backup_blob InvalidEncapsKeyLen ⇒ SealFailed
            };
            let creation = CreationMetadata {
                config_version: 1,
                counter_snapshot: 0,
                batch_id: 7,
            };
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, n, creation).unwrap();
            for i in 0..2u64 {
                body.record_audit(&crate::agent_keystore::AuditAppend {
                    op: 1,
                    authority: &[0xa1; 32],
                    counter: i,
                    config_version: 1,
                    scope_class: 0,
                    scope_target: b"seed",
                    request_id: b"seed",
                })
                .unwrap();
            }
            body
        }

        fn export_env(
            admin: &SigningKey,
            request_id: &[u8],
            counter: u64,
            selector: &ExportSelector,
        ) -> Vec<u8> {
            let pb = crate::agent_capability::payload_binding(
                7,
                None,
                request_id,
                &export_canonical_params(selector),
            );
            let cap = crate::agent_capability::test_signed_capability(
                admin, 7, request_id, counter, false, 11565, "testnet", 0, ESCOPE, 1, pb,
                [0xe1; 32],
            );
            let payload = match selector {
                ExportSelector::All => vec![],
                ExportSelector::KeyRefs(refs) => vec![(
                    Value::Integer(1.into()),
                    Value::Array(refs.iter().map(|r| Value::Bytes(r.to_vec())).collect()),
                )],
                ExportSelector::BatchId(id) => {
                    vec![(Value::Integer(2.into()), Value::Integer((*id).into()))]
                }
            };
            envelope_rid(
                7,
                request_id,
                vec![
                    (Value::Integer(5.into()), Value::Map(cap)),
                    (Value::Integer(7.into()), Value::Map(payload)),
                ],
            )
        }

        /// Dispatch-level: EXPORT (all) appends the op=7 audit event, FULL-drains the ring, Structural-bumps,
        /// and mints a pq-agent-backup-v1 blob.
        #[test]
        fn export_all_appends_audit_drains_and_mints_blob() {
            let _g = gate_configured();
            let admin = admin_key();
            let body = export_body(&admin, 2, true);
            let pre_next = body.audit.next_seq;
            let env = export_env(&admin, &[0x11; 16], 1, &ExportSelector::All);
            match dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").unwrap() {
                AgentResponse::ExportBackup {
                    candidate,
                    backup_blob,
                    request_id,
                } => {
                    assert_eq!(request_id, vec![0x11; 16]);
                    assert_eq!(&backup_blob[..8], b"2DAGTBK\0", "backup envelope magic");
                    assert_eq!(
                        candidate.audit.next_seq,
                        pre_next + 1,
                        "one EXPORT audit record appended"
                    );
                    let last = candidate.audit.records.last().unwrap();
                    assert_eq!(last.op, 7, "the appended record is the EXPORT event");
                    assert_eq!(last.authority, admin.verifying_key().to_bytes());
                    assert_eq!(
                        candidate.audit.last_exported_seq,
                        candidate.audit.next_seq - 1,
                        "FULL drain covers the export's own record"
                    );
                    assert_eq!(
                        candidate.structural_version,
                        body.structural_version + 1,
                        "Structural bump"
                    );
                    // cap counter consumed (anti-replay).
                    let c = candidate
                        .counters
                        .iter()
                        .find(|c| c.scope_target == ESCOPE)
                        .unwrap();
                    assert_eq!(c.highest_accepted_counter, 1);
                }
                _ => panic!("expected ExportBackup"),
            }
        }

        /// Frame-level: the seam seals→commits→swaps and emits {1: backup_blob, 2: sealed_keystore}.
        #[test]
        fn export_frame_seals_commits_swaps_and_emits() {
            let _g = gate_configured();
            let admin = admin_key();
            let body = export_body(&admin, 2, true);
            assert!(install_agent_keystore(body, b"meas"));
            assert!(install_commit_channel(Box::new(TestCommitChannel::new(
                CommitChannelAct::Ok
            ))));
            let env = export_env(&admin, &[0x11; 16], 1, &ExportSelector::All);
            let out = handle_agent_gateway_frame(&env);
            assert_eq!(decode_agent_error_code(&out), None, "EXPORT success body");
            let m = match ciborium::de::from_reader::<Value, _>(&out[..]).unwrap() {
                Value::Map(m) => m,
                _ => panic!("response is a map"),
            };
            assert_eq!(
                &as_bytes(map_get(&m, 1).unwrap()).unwrap()[..8],
                b"2DAGTBK\0",
                "key 1 = backup blob"
            );
            assert!(
                !as_bytes(map_get(&m, 2).unwrap()).unwrap().is_empty(),
                "key 2 = sealed keystore blob"
            );
            reset_agent_keystore_for_tests();
            reset_commit_channel_for_tests();
        }

        /// §10.5 payload_binding gate: a cap bound to one selector but a request carrying another ⇒ 0x43.
        #[test]
        fn export_payload_binding_mismatch_rejected() {
            let _g = gate_configured();
            let admin = admin_key();
            let body = export_body(&admin, 2, true);
            let pb = crate::agent_capability::payload_binding(
                7,
                None,
                &[0x11; 16],
                &export_canonical_params(&ExportSelector::All),
            );
            let cap = crate::agent_capability::test_signed_capability(
                &admin,
                7,
                &[0x11; 16],
                1,
                false,
                11565,
                "testnet",
                0,
                ESCOPE,
                1,
                pb,
                [0xe1; 32],
            );
            // Cap signed for ALL, but the request carries a batch_id selector.
            let env = envelope(
                7,
                vec![
                    (Value::Integer(5.into()), Value::Map(cap)),
                    (
                        Value::Integer(7.into()),
                        Value::Map(vec![(Value::Integer(2.into()), Value::Integer(7.into()))]),
                    ),
                ],
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
                Some(AgentError::CapabilityRejected)
            );
        }

        /// An explicit key_ref not in the body collapses to the key-not-found band (0x42, anti-oracle).
        #[test]
        fn export_unknown_key_ref_is_key_not_found() {
            let _g = gate_configured();
            let admin = admin_key();
            let body = export_body(&admin, 2, true);
            let env = export_env(
                &admin,
                &[0x11; 16],
                1,
                &ExportSelector::KeyRefs(vec![[0xfe; 32]]),
            );
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
                Some(AgentError::KeyPurposeMismatch)
            );
        }

        /// An invalid (non-ML-KEM) recovery key fails the seal closed (0x46) — no commit.
        #[test]
        fn export_invalid_recovery_key_fails_closed() {
            let _g = gate_configured();
            let admin = admin_key();
            let body = export_body(&admin, 2, false); // export_body substitutes a wrong-LENGTH recovery key
            let env = export_env(&admin, &[0x11; 16], 1, &ExportSelector::All);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
                Some(AgentError::SealFailed)
            );
        }

        /// A ring SATURATED with un-exported records fails the EXPORT append closed (0x46): EXPORT appends
        /// its own op=7 record BEFORE draining, so it is subject to the SAME backpressure as the other
        /// privileged writes — it is NOT a guaranteed escape hatch, and a saturated ring cannot be rescued
        /// (a drain-before-append would evict un-exported history). Pins the true brick semantics +
        /// discharges TASK-20 obligation (iii) for EXPORT.
        #[test]
        fn export_saturated_undrained_ring_fails_closed() {
            let _g = gate_configured();
            let admin = admin_key();
            let mut body = export_body(&admin, 2, true);
            // Saturate: capacity == the pre-seeded un-exported record count (last_exported_seq == 0).
            body.audit.capacity = body.audit.records.len() as u32;
            let env = export_env(&admin, &[0x11; 16], 1, &ExportSelector::All);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").err(),
                Some(AgentError::SealFailed),
                "EXPORT append on a saturated undrained ring fails closed — no drain, no commit"
            );
        }

        /// A batch_id selector exports only that batch's keys (a valid blob, not 0x42).
        #[test]
        fn export_by_batch_id_selects_only_that_batch() {
            let _g = gate_configured();
            let admin = admin_key();
            let mut body = export_body(&admin, 2, true); // 2 keys, batch 7
            let creation = CreationMetadata {
                config_version: 1,
                counter_snapshot: 0,
                batch_id: 99,
            };
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, 1, creation).unwrap();
            let env = export_env(&admin, &[0x11; 16], 1, &ExportSelector::BatchId(7));
            match dispatch_agent(Profile::AgentGateway, &env, &body, b"test-measurement").unwrap() {
                AgentResponse::ExportBackup { backup_blob, .. } => {
                    assert_eq!(&backup_blob[..8], b"2DAGTBK\0");
                }
                _ => panic!("expected ExportBackup"),
            }
            // A batch_id matching NO key ⇒ 0x42.
            let env2 = export_env(&admin, &[0x12; 16], 1, &ExportSelector::BatchId(123));
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env2, &body, b"test-measurement").err(),
                Some(AgentError::KeyPurposeMismatch)
            );
        }
    }

    #[cfg(feature = "agent-backup-export-preview")]
    mod restore_backup {
        use super::*;
        use crate::agent_backup::{
            build_key_refs_manifest, build_restore_ingress_payload, compute_manifest_hash,
            compute_original_backup_digest, derive_recovery_key_id, seal_backup_blob,
            seal_restore_ingress_envelope_with_m, RecoveryHighWater, RECOVERY_HIGH_WATER_DOMAIN,
        };
        use ed25519_dalek::{Signer, SigningKey};
        use ml_kem::{DecapsulationKey, KeyExport as _, MlKem1024};

        const RSCOPE: &[u8] = b"restore_backup";
        const DEST_MEAS: &[u8] = b"dest-tee-measurement-v1";
        const DEST_SEED: [u8; 64] = [0x6c; 64];
        const WRAP_SEED: [u8; 64] = [0xd7; 64]; // distinct from DEST_SEED (ceremony role separation)
        const INGRESS_M: [u8; 32] = [0x43; 32];

        /// The recovery wrapping encapsulation pubkey for WRAP_SEED — the ML-KEM key the original
        /// `pq-agent-backup-v1` is sealed to. AC#10: the destination enclave's sealed
        /// `backup_recovery_wrapping_pubkey` MUST equal this (or restore fails closed at the
        /// `recovery_key_id` binding). Returns ONLY the pubkey (the decaps key is the operator's
        /// offline secret — never in the enclave).
        fn wrapping_encaps_pubkey() -> Vec<u8> {
            let dk = DecapsulationKey::<MlKem1024>::from_seed(ml_kem::Seed::from(WRAP_SEED));
            dk.encapsulation_key().to_bytes().as_slice().to_vec()
        }

        fn recovery_key() -> SigningKey {
            SigningKey::from_bytes(&[0xa2; 32])
        }

        /// A source body with `n` transfer keys (the backup origin) — its payload + marks get restored.
        fn source_body(n: usize) -> KeystoreBody {
            let mut body = base_body();
            let creation = CreationMetadata {
                config_version: 1,
                counter_snapshot: 0,
                batch_id: 1,
            };
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, n, creation).unwrap();
            body
        }

        /// Sign the recovery-authority high-water using the SAME self-delimiting scoped preimage
        /// verify_recovery_high_water expects (via recovery_high_water_preimage — single source).
        fn signed_high_water(
            recovery: &SigningKey,
            request_id: &[u8],
            marks_payload: &[u8],
        ) -> RecoveryHighWater {
            let preimage = crate::agent_backup::recovery_high_water_preimage(
                11565,
                "testnet",
                request_id,
                marks_payload,
            );
            RecoveryHighWater {
                marks_payload: marks_payload.to_vec(),
                signature: recovery.sign(&preimage).to_bytes(),
            }
        }

        /// The full dispatch envelope for a RESTORE_BACKUP request: a recovery-tier cap (key 5) + the
        /// key-7 restore-request map {1: ingress envelope, 2: original backup, 3: refs, 4: high-water}.
        fn restore_env(
            cap_signer: &SigningKey,
            is_recovery: bool,
            hw_signer: &SigningKey,
            request_id: &[u8],
            counter: u64,
            n_keys: usize,
        ) -> (Vec<u8>, KeystoreBody) {
            // Publish the destination ephemeral (deterministic seed ⇒ the test knows the decaps key).
            let dest_pub = crate::agent_dispatch::install_restore_ephemeral_with_seed(
                &DEST_MEAS, &DEST_SEED, 11565, b"testnet",
            )
            .unwrap();
            // Source body → restore-ingress payload + manifest.
            let mut src = source_body(n_keys);
            let refs: Vec<[u8; 32]> = src.entries.iter().map(|e| e.key_ref).collect();
            let payload = build_restore_ingress_payload(&src, &refs).unwrap().to_vec();
            let manifest = build_key_refs_manifest(&refs).unwrap();
            let manifest_hash = compute_manifest_hash(&manifest);
            // Original backup blob (compact 9611 HIGH AC#10): a REAL `pq-agent-backup-v1` sealed to the
            // recovery wrapping key (WRAP_SEED) — NOT a placeholder. The handler parses this header's
            // `recovery_key_id` and binds it to the destination's sealed wrapping pubkey. The source
            // body carries the matching wrapping pubkey so the success-path test can copy it onto dest.
            let wrap_pub = wrapping_encaps_pubkey();
            let wrap_rid = derive_recovery_key_id(&wrap_pub);
            let original_backup = seal_backup_blob(
                &wrap_pub,
                &wrap_rid,
                src.config.twod_chain_id,
                &src.config.environment_identifier,
                &manifest,
                &payload,
            )
            .unwrap();
            // The source body carries the wrapping pubkey the backup was sealed to (callers that reach
            // the AC#10 check copy this onto the destination's sealed config).
            src.config.backup_recovery_wrapping_pubkey = wrap_pub;
            let backup_digest = compute_original_backup_digest(&original_backup);
            // Seal the ingress envelope to the dest ephemeral (AAD' = measurement/chain/env/manifest/digest).
            let envelope_blob = seal_restore_ingress_envelope_with_m(
                &dest_pub.encaps_key,
                DEST_MEAS,
                11565,
                "testnet",
                &manifest_hash,
                &backup_digest,
                &payload,
                &INGRESS_M,
            )
            .unwrap();
            // Signed high-water over the source's marks_payload.
            let hwm = signed_high_water(hw_signer, request_id, &src.encode_marks_payload());
            // Key-7 restore-request map.
            let req_map = vec![
                (Value::Integer(1.into()), Value::Bytes(envelope_blob)),
                (Value::Integer(2.into()), Value::Bytes(original_backup)),
                (
                    Value::Integer(3.into()),
                    Value::Array(refs.iter().map(|r| Value::Bytes(r.to_vec())).collect()),
                ),
                (
                    Value::Integer(4.into()),
                    Value::Map(vec![
                        (
                            Value::Integer(1.into()),
                            Value::Bytes(hwm.marks_payload.clone()),
                        ),
                        (
                            Value::Integer(2.into()),
                            Value::Bytes(hwm.signature.to_vec()),
                        ),
                    ]),
                ),
            ];
            // Compute the REAL payload_binding (HIGH #1) — the cap is bound to THIS restore's key
            // selector + the backup digest, not a placeholder.
            let pb = crate::agent_capability::payload_binding(
                8,
                None,
                request_id,
                &restore_canonical_params(&refs, &backup_digest),
            );
            let cap = crate::agent_capability::test_signed_capability(
                cap_signer,
                8,
                request_id,
                counter,
                is_recovery,
                11565,
                "testnet",
                0,
                RSCOPE,
                1,
                pb,
                [0xe1; 32],
            );
            (
                envelope_rid(
                    8,
                    request_id,
                    vec![
                        (Value::Integer(5.into()), Value::Map(cap)),
                        (Value::Integer(7.into()), Value::Map(req_map)),
                    ],
                ),
                src,
            )
        }

        /// Compact 9611 MEDIUM (restore_canonical_params): pin the EXACT RFC 8949 bytes so a conformant
        /// EXTERNAL cap issuer (computing the payload_binding preimage per the spec, not via this crate)
        /// produces byte-identical bytes. Before this the map/array headers passed the composed byte
        /// (0xA0/0x80) to put_uint, which expects a major-TYPE number (0-7) and shifts it `<<5`; the
        /// result was malformed CBOR that only this crate's own (symmetric) issuer/verifier pair agreed on.
        #[test]
        fn restore_canonical_params_pins_rfc_8949_bytes() {
            let refs = [[0xAA; 32], [0xBB; 32]];
            let digest = [0xCC; 32];
            let out = restore_canonical_params(&refs, &digest);
            // map(2)=0xA2, key1=0x01, array(2)=0x82, bstr(32)=0x58 0x20 +32B, key2=0x02, bstr(32)=0x58 0x20 +32B.
            let mut expect = vec![0xA2, 0x01, 0x82];
            expect.push(0x58);
            expect.push(0x20);
            expect.extend_from_slice(&[0xAA; 32]);
            expect.push(0x58);
            expect.push(0x20);
            expect.extend_from_slice(&[0xBB; 32]);
            expect.push(0x02);
            expect.push(0x58);
            expect.push(0x20);
            expect.extend_from_slice(&[0xCC; 32]);
            assert_eq!(
                out, expect,
                "restore_canonical_params MUST emit RFC 8949 shortest-form CBOR so an external cap \
                 issuer interoperates; a drift here silently rejects compliant externally-signed caps"
            );
        }

        /// End-to-end: a recovery-tier RESTORE_BACKUP through dispatch_agent reconstitutes the source
        /// keystore's entries into a fresh destination TEE + advances strict_recovery (AC#6) + structural
        /// (local+1, AC#4). The full ceremony path — ephemeral decap, AAD' verify, signed-high-water
        /// verify, AC#6 forward-only gate, wholesale-replace — runs inside the one dispatch call.
        #[test]
        fn restore_backup_restores_entries_end_to_end() {
            let _g = gate_configured();
            let recovery = recovery_key();
            let mut dest = base_body(); // fresh TEE: empty entries
                                        // The cap + high-water signatures both verify against the sealed recovery_authority_pk — set it
                                        // to the recovery key's DERIVED pubkey (base_body's [0xa2;32] is a seed, not a pubkey).
            dest.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
            let (env, src) = restore_env(&recovery, true, &recovery, &[0x11; 16], 1, 2);
            // AC#10: the destination's sealed wrapping pubkey MUST match the backup's (the handler's
            // recovery_key_id binding, compact 9611 HIGH). restore_env sealed the backup to WRAP_SEED
            // and set src's wrapping pubkey; copy it onto dest so the success path verifies.
            dest.config.backup_recovery_wrapping_pubkey =
                src.config.backup_recovery_wrapping_pubkey.clone();
            let resp = dispatch_agent(Profile::AgentGateway, &env, &dest, DEST_MEAS).unwrap();
            match resp {
                AgentResponse::RestoreBackup { candidate, .. } => {
                    // Exact-match the restored state against the SOURCE body (not just counts).
                    assert_eq!(candidate.entries.len(), src.entries.len());
                    for (i, (c, s)) in candidate.entries.iter().zip(src.entries.iter()).enumerate()
                    {
                        assert_eq!(c.key_ref, s.key_ref, "entry {i}: key_ref");
                        assert_eq!(c.public_identity, s.public_identity, "entry {i}: pubkey");
                        assert_eq!(c.secret_scalar, s.secret_scalar, "entry {i}: secret scalar");
                        assert_eq!(c.purpose, s.purpose, "entry {i}: purpose");
                    }
                    assert_eq!(
                        candidate.config.twod_chain_id, src.config.twod_chain_id,
                        "chain"
                    );
                    assert_eq!(
                        candidate.config.environment_identifier, src.config.environment_identifier,
                        "env"
                    );
                    assert_eq!(
                        candidate.config.admin_authority_pk, src.config.admin_authority_pk,
                        "admin pk"
                    );
                    // EXCLUDED surfaces preserved (the destination's own).
                    assert_eq!(
                        candidate.config.anchor_root, dest.config.anchor_root,
                        "anchor preserved"
                    );
                    assert_eq!(
                        candidate.config.enclave_scope_id, dest.config.enclave_scope_id,
                        "scope_id preserved"
                    );
                    // Anti-rollback advances.
                    assert_eq!(candidate.strict_recovery_counter, 1, "strict_recovery");
                    assert_eq!(candidate.structural_version, 2, "local+1");
                }
                _ => panic!("expected RestoreBackup"),
            }
        }

        /// AC#11 fail-closed: no ephemeral published (GET_RESTORE_PUBKEY not run / retired) ⇒ the
        /// handler cannot decap ⇒ NotConfigured (the operator must publish one first). No partial import.
        #[test]
        fn restore_backup_no_ephemeral_fails_closed() {
            let _g = gate_configured();
            let recovery = recovery_key();
            let mut dest = base_body();
            dest.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
            let (env, _) = restore_env(&recovery, true, &recovery, &[0x11; 16], 1, 2); // builds + installs the ephemeral
            retire_restore_ephemeral(); // …then retire it ⇒ the handler finds no ephemeral
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &dest, DEST_MEAS).err(),
                Some(AgentError::NotConfigured),
                "no published ephemeral ⇒ fail closed (NotConfigured)"
            );
        }

        /// AC#11 fail-closed: the envelope's AAD' `dest_measurement` != THIS enclave's measurement (a
        /// re-wrap for a DIFFERENT TEE) ⇒ the AAD' semantic check rejects ⇒ SealFailed. No partial import.
        #[test]
        fn restore_backup_measurement_mismatch_fails_closed() {
            let _g = gate_configured();
            let recovery = recovery_key();
            let mut dest = base_body();
            dest.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
            let (env, _) = restore_env(&recovery, true, &recovery, &[0x11; 16], 1, 2); // envelope AAD' measurement = DEST_MEAS
                                                                                       // Dispatch claiming a DIFFERENT measurement ⇒ opened.dest_measurement != OWN ⇒ SealFailed.
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &dest, b"OTHER-tee-measurement").err(),
                Some(AgentError::SealFailed),
                "dest_measurement mismatch ⇒ fail closed (SealFailed)"
            );
        }

        /// AC#10 fail-closed (compact 9611 HIGH): the backup was sealed to a recovery wrapping key
        /// whose `recovery_key_id` != the destination's sealed `backup_recovery_wrapping_pubkey`'s
        /// derived id. The handler parses the backup header + binds it to the sealed key; a mismatch
        /// (authorized by the recovery authority but re-wrapped to a DIFFERENT ML-KEM key) ⇒
        /// SealFailed. No partial import. Exercises the `backup_recovery_key_id` parse + compare.
        #[test]
        fn restore_backup_wrong_wrapping_key_fails_closed() {
            let _g = gate_configured();
            let recovery = recovery_key();
            let mut dest = base_body();
            dest.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
            let (env, _) = restore_env(&recovery, true, &recovery, &[0x11; 16], 1, 2);
            // restore_env sealed the backup to WRAP_SEED; leave dest's wrapping key as base_body's
            // placeholder (a DIFFERENT key) ⇒ recovery_key_id mismatch ⇒ fail closed at step 5c.
            // (base_body's `vec![0xb0; 1568]` is intentionally not WRAP_SEED's key.)
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &dest, DEST_MEAS).err(),
                Some(AgentError::SealFailed),
                "backup sealed to a different wrapping key than the destination's sealed pubkey ⇒ \
                 fail closed (SealFailed) — AC#10 wrapping-key separation"
            );
        }

        /// TASK-28 / compact-9651 HIGH: the RESTORE_BACKUP success body carries the restored-key
        /// identity set (key 3) + the request_id echo (key 2) as PLAINTEXT — the host/2D derives
        /// `restored_identity_set_sha256` + verifies the replay-protecting echo from the response ALONE,
        /// WITHOUT unsealing the AEAD-encrypted keystore blob (key 1). Pins the {1,2,3} wire shape.
        #[test]
        fn restore_backup_response_carries_identity_set_and_echo_without_unsealing() {
            let sealed_blob = b"opaque-aead-sealed-keystore-blob".to_vec();
            let rid = b"req-restore-task28";
            let identity = vec![
                RestoredKeyIdentity {
                    key_ref: [0xAA; 32],
                    public_identity: vec![0x04; 65],
                    key_purpose: 1, // agent_transfer_k1
                },
                RestoredKeyIdentity {
                    key_ref: [0xBB; 32],
                    public_identity: vec![0x04; 65],
                    key_purpose: 2, // agent_faucet_treasury_k1
                },
            ];
            let body = encode_restore_backup_response(&sealed_blob, rid, &identity);
            // Decode the success body map.
            let v = ciborium::de::from_reader::<Value, _>(body.as_slice()).unwrap();
            let Value::Map(top) = v else {
                panic!("response body is a CBOR map");
            };
            // Key 1: the sealed blob (opaque, host persists — NOT read for identities).
            let k1 = top
                .iter()
                .find(|(k, _)| *k == Value::Integer(1.into()))
                .map(|(_, v)| v.clone())
                .unwrap();
            assert_eq!(k1, Value::Bytes(sealed_blob.clone()), "key 1 = sealed blob");
            // Key 2: the request_id echo (2D replay prevention — verifies ceremony consumed live nonce).
            let k2 = top
                .iter()
                .find(|(k, _)| *k == Value::Integer(2.into()))
                .map(|(_, v)| v.clone())
                .unwrap();
            assert_eq!(
                k2,
                Value::Bytes(rid.to_vec()),
                "key 2 = request_id echo (plaintext, no unsealing)"
            );
            // Key 3: the restored identity set (array of {1: key_ref, 2: public_identity, 3: key_purpose}).
            // The host reads this PLAINTEXT — the AEAD-sealed blob (key 1) is never unsealed to derive it.
            let k3 = top
                .iter()
                .find(|(k, _)| *k == Value::Integer(3.into()))
                .map(|(_, v)| v.clone())
                .unwrap();
            let Value::Array(entries) = k3 else {
                panic!("key 3 = restored identity-set array");
            };
            assert_eq!(entries.len(), 2, "two restored keys");
            for (entry, expected) in entries.iter().zip(identity.iter()) {
                let Value::Map(fields) = entry else {
                    panic!("each identity entry is a map");
                };
                let key_ref = fields
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(1.into()))
                    .map(|(_, v)| v.clone())
                    .unwrap();
                let pub_id = fields
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(2.into()))
                    .map(|(_, v)| v.clone())
                    .unwrap();
                let purpose = fields
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(3.into()))
                    .map(|(_, v)| v.clone())
                    .unwrap();
                assert_eq!(
                    key_ref,
                    Value::Bytes(expected.key_ref.to_vec()),
                    "key_ref plaintext"
                );
                assert_eq!(
                    pub_id,
                    Value::Bytes(expected.public_identity.clone()),
                    "public_identity plaintext (address-only is insufficient; TASK-26 AC#4)"
                );
                assert_eq!(
                    purpose,
                    Value::Integer(expected.key_purpose.into()),
                    "key_purpose plaintext (maps to 2D source_table)"
                );
            }
        }

        /// AC#11 fail-closed: an ADMIN-tier cap (is_recovery=false) on a RESTORE_BACKUP opcode ⇒ the
        /// capability tier check rejects (AC#10: an admin authority cannot authorize a restore) ⇒
        /// CapabilityRejected, BEFORE any handler logic runs. No partial import.
        #[test]
        fn restore_backup_admin_cap_rejected() {
            let _g = gate_configured();
            let admin = ed25519_dalek::SigningKey::from_bytes(&[0xa1; 32]);
            let recovery = recovery_key();
            let mut dest = base_body();
            dest.config.admin_authority_pk = admin.verifying_key().to_bytes();
            dest.config.recovery_authority_pk = recovery.verifying_key().to_bytes();
            // An ADMIN-signed cap (is_recovery=false) for opcode 8 — the tier check rejects BEFORE the
            // handler. The high-water is correctly recovery-signed, so if the tier check regressed, the
            // handler would proceed + succeed (the test would FAIL, catching the regression).
            let (env, _) = restore_env(&admin, false, &recovery, &[0x11; 16], 1, 2);
            assert_eq!(
                dispatch_agent(Profile::AgentGateway, &env, &dest, DEST_MEAS).err(),
                Some(AgentError::CapabilityRejected),
                "an admin cap on RESTORE_BACKUP ⇒ tier-rejected (AC#10)"
            );
        }
    }

    /// TASK-22 — byte-exact `0x40` REQUEST-ENVELOPE golden vectors (AC#1).
    ///
    /// Frozen wire bytes of the canonical int-keyed CBOR request envelope (keys 1..=7: agent_version,
    /// opcode, command_domain, request_id, capability, key_ref, payload) for each NON-privileged opcode
    /// (no capability — the cap-bearing GENERATE_KEYS / CONFIGURE_TREASURY envelopes are frozen in the
    /// capability slice alongside their §10.5 cap vector). These let the downstream 2d Elixir codec
    /// (`Chain.AgentGateway.SignerProtocol`) byte-validate its CBOR encoder against the enclave's
    /// strict-canonical [`decode_envelope`], catching map-ordering / minimal-int / bstr-vs-uint drift
    /// BEFORE a live capability is rejected `0x40` after a monotonic counter slot is already burned.
    ///
    /// Each vector is (a) byte-exact vs the committed `.bin`, (b) ACCEPTED by the real `decode_envelope`
    /// (so an encoder/decoder drift breaks CI), and (c) canonical-header hand-audited. The `.json` index
    /// couples each blob's sha256/len + decoded fields to the source of truth. **TEST VALUES ONLY** — the
    /// addresses mirror `ordinary_tx_v1.json` (well-known dev accounts).
    mod golden_request_envelopes {
        use super::*;
        use sha2::{Digest, Sha256};

        // Addresses mirror ordinary_tx_v1.json (transfer-key `from`, treasury-key `to`).
        const TRANSFER_FROM: [u8; 20] = [
            0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce, 0x6a, 0xb8, 0x82, 0x72,
            0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
        ];
        const TREASURY_TO: [u8; 20] = [
            0x70, 0x99, 0x79, 0x70, 0xc5, 0x18, 0x12, 0xdc, 0x3a, 0x01, 0x0c, 0x7d, 0x01, 0xb5,
            0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xc8,
        ];
        const GOLDEN_KEY_REF: [u8; 32] = [0x11; 32];
        const GOLDEN_PROVE_NONCE: [u8; 32] = [0x22; 32];

        // Reuse the `hex` crate (already a dev-dependency, used by the sibling dispatch tests) rather
        // than a hand-rolled per-byte format loop.
        fn hex(b: &[u8]) -> String {
            hex::encode(b)
        }
        /// Minimal big-endian bytes of a u64 (the canonical u256 wire form for values that fit u64).
        /// Mirrors the per-mod test convention; the production source of truth for "minimal-BE" is
        /// `crate::agent_cbor::as_u256_minimal_be` — `golden_eip155_payload_is_production_minimal_be`
        /// couples this output to it. (Promoting the 4+ copies to one shared helper = a TASK-20 cleanup.)
        fn min_be(x: u64) -> Vec<u8> {
            let b = x.to_be_bytes();
            let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
            b[i..].to_vec()
        }
        fn enc(map: Vec<(Value, Value)>) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&Value::Map(map), &mut buf)
                .expect("canonical envelope encodes");
            buf
        }
        fn k(n: u64) -> Value {
            Value::Integer(n.into())
        }
        fn b(v: &[u8]) -> Value {
            Value::Bytes(v.to_vec())
        }

        /// The shared 8-field EIP-155 transfer/dispense payload (envelope key 7) — mirrors
        /// `ordinary_tx_v1.json`. Keys 1..=8: chain_id, from, to, value(u256-min-BE), nonce, gas_limit,
        /// gas_price(u256-min-BE), data.
        fn eip155_payload() -> Value {
            Value::Map(vec![
                (k(1), Value::Integer(11565u64.into())),
                (k(2), b(&TRANSFER_FROM)),
                (k(3), b(&TREASURY_TO)),
                (k(4), b(&min_be(1_000_000_000_000_000_000))),
                (k(5), Value::Integer(0u64.into())),
                (k(6), Value::Integer(21_000u64.into())),
                (k(7), b(&min_be(1_000_000_000))),
                (k(8), b(&[])),
            ])
        }

        fn base(opcode: u8, request_id: &[u8]) -> Vec<(Value, Value)> {
            vec![
                (k(1), Value::Integer((AGENT_GATEWAY_VERSION as u64).into())),
                (k(2), Value::Integer((opcode as u64).into())),
                (k(3), Value::Text(COMMAND_DOMAIN.to_string())),
                (k(4), b(request_id)),
            ]
        }

        // The 4 frozen NON-cap envelopes. request_id is human-readable + <= MAX_REQUEST_ID_LEN (64).
        const RID_PUBLIC_IDENTITY: &[u8] = b"0x40-golden:public-identity:v1";
        const RID_PROVE_IDENTITY: &[u8] = b"0x40-golden:prove-identity:v1";
        const RID_SIGN_TRANSFER: &[u8] = b"0x40-golden:sign-transfer:v1";
        const RID_SIGN_FAUCET: &[u8] = b"0x40-golden:sign-faucet-dispense:v1";

        fn req_public_identity() -> Vec<u8> {
            let mut m = base(2, RID_PUBLIC_IDENTITY);
            m.push((k(6), b(&GOLDEN_KEY_REF)));
            enc(m)
        }
        fn req_prove_identity() -> Vec<u8> {
            let mut m = base(3, RID_PROVE_IDENTITY);
            m.push((k(6), b(&GOLDEN_KEY_REF)));
            m.push((k(7), Value::Map(vec![(k(1), b(&GOLDEN_PROVE_NONCE))])));
            enc(m)
        }
        fn req_sign_transfer() -> Vec<u8> {
            let mut m = base(4, RID_SIGN_TRANSFER);
            m.push((k(6), b(&GOLDEN_KEY_REF)));
            m.push((k(7), eip155_payload()));
            enc(m)
        }
        fn req_sign_faucet() -> Vec<u8> {
            let mut m = base(5, RID_SIGN_FAUCET);
            m.push((k(6), b(&GOLDEN_KEY_REF)));
            m.push((k(7), eip155_payload()));
            enc(m)
        }

        /// (filename, built bytes, opcode, request_id, payload-present). Ordered ALPHABETICALLY by
        /// filename so the regen's outer-index insertion order is alphabetical too — the serialized
        /// `.json` bytes are then stable whether serde_json sorts keys (default) or preserves insertion
        /// order. The frozen/decode tests are order-independent (they `.find()` / loop), so the order is
        /// purely for deterministic regen.
        fn vectors() -> Vec<(&'static str, Vec<u8>, u8, &'static [u8], bool)> {
            vec![
                (
                    "req_prove_identity_v1.bin",
                    req_prove_identity(),
                    3,
                    RID_PROVE_IDENTITY,
                    true,
                ),
                (
                    "req_public_identity_v1.bin",
                    req_public_identity(),
                    2,
                    RID_PUBLIC_IDENTITY,
                    false,
                ),
                (
                    "req_sign_faucet_dispense_v1.bin",
                    req_sign_faucet(),
                    5,
                    RID_SIGN_FAUCET,
                    true,
                ),
                (
                    "req_sign_transfer_v1.bin",
                    req_sign_transfer(),
                    4,
                    RID_SIGN_TRANSFER,
                    true,
                ),
            ]
        }

        #[test]
        fn golden_request_envelopes_are_byte_exact() {
            // The in-source canonical mint and the committed bytes must agree byte-for-byte — any
            // map-ordering / minimal-int / bstr drift in the encoder flips this. Regen via
            // `regen_golden_request_envelopes` (-- --ignored) and re-mint the .json in the same commit.
            let committed: &[(&str, &[u8])] = &[
                (
                    "req_public_identity_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/req_public_identity_v1.bin"),
                ),
                (
                    "req_prove_identity_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/req_prove_identity_v1.bin"),
                ),
                (
                    "req_sign_transfer_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/req_sign_transfer_v1.bin"),
                ),
                (
                    "req_sign_faucet_dispense_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/req_sign_faucet_dispense_v1.bin"),
                ),
            ];
            for (name, built, ..) in vectors() {
                let c = committed
                    .iter()
                    .find(|(n, _)| *n == name)
                    .expect("committed vector present")
                    .1;
                assert_eq!(
                    built.as_slice(),
                    c,
                    "{name} golden drifted; regen + re-mint .json in the same commit"
                );
            }
        }

        #[test]
        fn golden_request_envelopes_decode_canonically() {
            // Each vector is a VALID wire envelope the enclave's strict-canonical decoder ACCEPTS, decoding
            // to the intended fields — couples the frozen bytes to the real `decode_envelope` so an
            // encoder/decoder divergence (the exact cross-language drift these vectors guard) breaks CI.
            for (name, bytes, opcode, request_id, has_payload) in vectors() {
                let env = decode_envelope(&bytes)
                    .unwrap_or_else(|_| panic!("{name} must decode canonically"));
                assert_eq!(
                    env.agent_version, AGENT_GATEWAY_VERSION,
                    "{name} agent_version"
                );
                assert_eq!(env.command_domain, COMMAND_DOMAIN, "{name} command_domain");
                assert_eq!(env.opcode, opcode, "{name} opcode");
                assert_eq!(env.request_id.as_slice(), request_id, "{name} request_id");
                assert_eq!(env.key_ref, Some(GOLDEN_KEY_REF), "{name} key_ref");
                assert!(
                    env.capability.is_none(),
                    "{name} non-privileged ⇒ no capability"
                );
                assert_eq!(
                    env.payload.is_some(),
                    has_payload,
                    "{name} payload presence"
                );
            }
        }

        #[test]
        fn golden_request_envelope_canonical_headers() {
            // Hand-audited canonical CBOR markers (RFC 8949 §4.2.1) a lenient re-encoder would mask: the
            // map-pair count in the head byte, and key 3 = text(23) "2d-hsm/agent-gateway/v1".
            assert_eq!(
                req_public_identity()[0],
                0xA5,
                "public-identity = 5-pair map {{1,2,3,4,6}}"
            );
            assert_eq!(
                req_prove_identity()[0],
                0xA6,
                "prove-identity = 6-pair map {{1,2,3,4,6,7}}"
            );
            assert_eq!(
                req_sign_transfer()[0],
                0xA6,
                "sign-transfer = 6-pair map {{1,2,3,4,6,7}}"
            );
            assert_eq!(
                req_sign_faucet()[0],
                0xA6,
                "sign-faucet = 6-pair map {{1,2,3,4,6,7}}"
            );
            // command_domain at key 3: int-key 0x03, then text(23) head 0x77 (major 3 | len 23) ‖ the bytes.
            assert_eq!(COMMAND_DOMAIN.len(), 23, "0x77 text head assumes len 23");
            let needle = [&[0x03u8, 0x77][..], COMMAND_DOMAIN.as_bytes()].concat();
            for (name, bytes, ..) in vectors() {
                assert!(
                    bytes.windows(needle.len()).any(|w| w == needle),
                    "{name} missing canonical text(23) command_domain marker"
                );
            }
        }

        #[test]
        fn golden_request_envelope_sidecar_matches() {
            // Couple the descriptive `.json` index (consumed by no runtime path) to the committed `.bin`s
            // and the source constants, so a regen that forgets the manual `.json` re-mint fails CI.
            let sidecar = include_str!("../testvectors/agent-gateway/request_envelopes_v1.json");
            let v: serde_json::Value =
                serde_json::from_str(sidecar).expect("request-envelope index is valid JSON");
            assert_eq!(
                v["command_domain"].as_str(),
                Some(COMMAND_DOMAIN),
                "index command_domain"
            );
            assert_eq!(
                v["agent_version"].as_u64(),
                Some(AGENT_GATEWAY_VERSION as u64),
                "index agent_version"
            );
            // No STALE/extra vector keys: the index must hold EXACTLY the current vectors, else a renamed
            // or dropped vector would leave a lingering entry the per-vector loop below never visits.
            assert_eq!(
                v["vectors"].as_object().map(|o| o.len()),
                Some(vectors().len()),
                "index has a stale/extra vector entry"
            );
            for (name, bytes, opcode, request_id, has_payload) in vectors() {
                let e = &v["vectors"][name];
                assert_eq!(
                    e["blob_sha256"].as_str(),
                    Some(hex(&Sha256::digest(&bytes)).as_str()),
                    "{name} sha256"
                );
                assert_eq!(
                    e["blob_len_bytes"].as_u64(),
                    Some(bytes.len() as u64),
                    "{name} len"
                );
                assert_eq!(e["opcode"].as_u64(), Some(opcode as u64), "{name} opcode");
                assert_eq!(
                    e["request_id_hex"].as_str(),
                    Some(hex(request_id).as_str()),
                    "{name} request_id"
                );
                assert_eq!(
                    e["has_payload"].as_bool(),
                    Some(has_payload),
                    "{name} has_payload"
                );
                // Couple the full bytes (blob_hex) + key_ref_hex too — the README advertises blob_hex as a
                // decode source, so a hand-edit/merge that corrupts ONLY blob_hex must fail CI.
                assert_eq!(
                    e["blob_hex"].as_str(),
                    Some(hex(&bytes).as_str()),
                    "{name} blob_hex"
                );
                assert_eq!(
                    e["key_ref_hex"].as_str(),
                    Some(hex(&GOLDEN_KEY_REF).as_str()),
                    "{name} key_ref_hex"
                );
            }
        }

        #[test]
        fn golden_eip155_payload_is_production_minimal_be() {
            // Couple this mod's local `min_be` to the PRODUCTION canonical u256 wire form: the value (key 4)
            // and gas_price (key 7) of the frozen EIP-155 payload must be accepted by the real
            // `as_u256_minimal_be` (which REJECTS non-minimal / over-width). So a `min_be` bug that froze a
            // non-canonical vector (e.g. a leading zero) is caught here, not silently shipped to 2d.
            let payload = eip155_payload();
            let m = match payload {
                Value::Map(m) => m,
                _ => panic!("payload is a map"),
            };
            for key in [4u64, 7u64] {
                let v = m
                    .iter()
                    .find(|(kk, _)| matches!(kk, Value::Integer(i) if u64::try_from(*i).ok() == Some(key)))
                    .map(|(_, vv)| vv)
                    .unwrap_or_else(|| panic!("payload key {key} present"));
                assert!(
                    crate::agent_cbor::as_u256_minimal_be(v).is_some(),
                    "payload key {key} is not production-canonical minimal-BE",
                );
            }
        }

        /// REGEN (manual): `cargo test --features agent-gateway golden_request_envelopes::regen_golden_request_envelopes -- --ignored --nocapture`,
        /// then commit the `.bin`s + the re-minted `request_envelopes_v1.json`. Mirrors
        /// `boot_agent_keystore::regen_agent_genesis_golden_vector`.
        #[test]
        #[ignore]
        fn regen_golden_request_envelopes() {
            let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
            let mut index = serde_json::Map::new();
            for (name, bytes, opcode, request_id, has_payload) in vectors() {
                std::fs::write(format!("{dir}{name}"), &bytes).expect("write envelope .bin");
                // Insert in ALPHABETICAL key order so the serialized bytes are stable regardless of whether
                // serde_json sorts keys (default BTreeMap) or preserves insertion order (preserve_order, if
                // a future workspace dep ever unifies it on) — no spurious regen churn either way.
                let mut e = serde_json::Map::new();
                e.insert("blob_hex".into(), hex(&bytes).into());
                e.insert("blob_len_bytes".into(), (bytes.len() as u64).into());
                e.insert("blob_sha256".into(), hex(&Sha256::digest(&bytes)).into());
                e.insert("has_payload".into(), has_payload.into());
                e.insert("key_ref_hex".into(), hex(&GOLDEN_KEY_REF).into());
                e.insert("opcode".into(), (opcode as u64).into());
                e.insert("request_id_hex".into(), hex(request_id).into());
                index.insert(name.into(), serde_json::Value::Object(e));
            }
            let doc = serde_json::json!({
                "_comment": "TASK-22 AC#1 — byte-exact 0x40 request-envelope golden vectors (non-privileged opcodes). Minted from the enclave canonical CBOR encoder; each is ACCEPTED by the strict-canonical decode_envelope. TEST VALUES ONLY (addresses mirror ordinary_tx_v1.json). Regen: cargo test --features agent-gateway golden_request_envelopes::regen_golden_request_envelopes -- --ignored --nocapture",
                "agent_version": AGENT_GATEWAY_VERSION,
                "command_domain": COMMAND_DOMAIN,
                "vectors": serde_json::Value::Object(index),
            });
            std::fs::write(
                format!("{dir}request_envelopes_v1.json"),
                serde_json::to_string_pretty(&doc).unwrap() + "\n",
            )
            .expect("write request-envelope index");
            eprintln!("wrote 4 envelope vectors + request_envelopes_v1.json -> {dir}");
        }
    }

    /// TASK-22 — byte-exact `0x40` CAP-BEARING request-envelope golden vectors (rest of AC#1).
    ///
    /// The privileged opcodes GENERATE_KEYS(1) / CONFIGURE_TREASURY(6) carry a §10.5 capability at envelope
    /// key 5 (and NO key_ref). Frozen here (next to `decode_envelope`) rather than with the non-cap
    /// envelopes because their shape differs (key 5 present, key 6 absent) and the embedded cap is the same
    /// one frozen by the capability vectors (AC#2, `agent_capability::tests`). Each vector: (a) byte-exact
    /// vs the committed `.bin`; (b) ACCEPTED by `decode_envelope` with the documented fields; (c) its
    /// embedded cap (key 5), re-encoded, EQUALS the corresponding `cap_full_*_v1.bin` — cross-referencing
    /// the already-verifier-accepted cap vector, so the envelope provably embeds a valid capability whose
    /// `payload_binding` matches this envelope's payload. **TEST KEYS ONLY** (admin Ed25519 `[7;32]`,
    /// recovery `[9;32]`; env `env-prod-0`, chain 11565 — matching the cap vectors).
    mod golden_cap_envelopes {
        use super::*;
        use sha2::{Digest, Sha256};

        const ENV_ID: &str = "env-prod-0";
        const CHAIN: u64 = 11565;
        const SCOPE_GENERATE: &[u8] = b"golden-scope-generate";
        const SCOPE_CONFIGURE: &[u8] = b"golden-scope-configure";
        const RID_GENERATE: &[u8] = b"0x40-golden:cap:generate-keys:v1";
        const RID_SET_LIMITS: &[u8] = b"0x40-golden:cap:configure-set-limits:v1";

        fn hex(b: &[u8]) -> String {
            hex::encode(b)
        }
        fn min_be(x: u64) -> Vec<u8> {
            let b = x.to_be_bytes();
            let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
            b[i..].to_vec()
        }
        fn enc(map: Vec<(Value, Value)>) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&Value::Map(map), &mut buf)
                .expect("canonical envelope encodes");
            buf
        }
        fn k(n: u64) -> Value {
            Value::Integer(n.into())
        }

        /// GENERATE_KEYS(1) envelope: cap(key5, no key_ref) + payload {1:purpose, 2:count}. The cap's
        /// payload_binding is over `generate_keys_canonical_params(1, 1)` so it matches THIS payload.
        fn req_generate_keys() -> Vec<u8> {
            let admin = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let pb = crate::agent_capability::payload_binding(
                1,
                None,
                RID_GENERATE,
                &generate_keys_canonical_params(1, 1),
            );
            let cap = crate::agent_capability::test_signed_capability(
                &admin,
                1,
                RID_GENERATE,
                1,
                false,
                CHAIN,
                ENV_ID,
                0,
                SCOPE_GENERATE,
                1,
                pb,
                [0xe1; 32],
            );
            enc(vec![
                (k(1), Value::Integer((AGENT_GATEWAY_VERSION as u64).into())),
                (k(2), Value::Integer(1u64.into())),
                (k(3), Value::Text(COMMAND_DOMAIN.to_string())),
                (k(4), Value::Bytes(RID_GENERATE.to_vec())),
                (k(5), Value::Map(cap)),
                (
                    k(7),
                    Value::Map(vec![
                        (k(1), Value::Integer(1u64.into())),
                        (k(2), Value::Integer(1u64.into())),
                    ]),
                ),
            ])
        }

        /// CONFIGURE_TREASURY(6) set_limits envelope: cap(key5, sub_op 0) + payload {1:0, 2:per_dispense_max,
        /// 3:max_gas_limit, 4:max_fee_rate}. The cap's payload_binding is over
        /// `configure_treasury_canonical_params(0, min_be(1e6), Some((21000, 1e9)))` to match THIS payload.
        fn req_configure_set_limits() -> Vec<u8> {
            let admin = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let params = configure_treasury_canonical_params(
                0,
                &min_be(1_000_000),
                Some((21_000, 1_000_000_000)),
            );
            let pb = crate::agent_capability::payload_binding(6, Some(0), RID_SET_LIMITS, &params);
            let cap = crate::agent_capability::test_signed_capability_with_sub_op(
                &admin,
                6,
                Some(0),
                RID_SET_LIMITS,
                1,
                false,
                CHAIN,
                ENV_ID,
                0,
                SCOPE_CONFIGURE,
                2,
                pb,
                [0xe1; 32],
            );
            enc(vec![
                (k(1), Value::Integer((AGENT_GATEWAY_VERSION as u64).into())),
                (k(2), Value::Integer(6u64.into())),
                (k(3), Value::Text(COMMAND_DOMAIN.to_string())),
                (k(4), Value::Bytes(RID_SET_LIMITS.to_vec())),
                (k(5), Value::Map(cap)),
                (
                    k(7),
                    Value::Map(vec![
                        (k(1), Value::Integer(0u64.into())),
                        (k(2), Value::Bytes(min_be(1_000_000))),
                        (k(3), Value::Integer(21_000u64.into())),
                        (k(4), Value::Integer(1_000_000_000u64.into())),
                    ]),
                ),
            ])
        }

        /// (filename, bytes, opcode, request_id, cap_full filename to cross-reference).
        fn vectors() -> Vec<(&'static str, Vec<u8>, u8, &'static [u8], &'static str)> {
            vec![
                (
                    "req_configure_set_limits_v1.bin",
                    req_configure_set_limits(),
                    6,
                    RID_SET_LIMITS,
                    "cap_full_configure_set_limits_v1.bin",
                ),
                (
                    "req_generate_keys_v1.bin",
                    req_generate_keys(),
                    1,
                    RID_GENERATE,
                    "cap_full_generate_keys_v1.bin",
                ),
            ]
        }

        #[test]
        fn golden_cap_envelopes_are_byte_exact() {
            let committed: &[(&str, &[u8])] = &[
                (
                    "req_configure_set_limits_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/req_configure_set_limits_v1.bin"),
                ),
                (
                    "req_generate_keys_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/req_generate_keys_v1.bin"),
                ),
            ];
            for (name, built, ..) in vectors() {
                let c = committed.iter().find(|(n, _)| *n == name).unwrap().1;
                assert_eq!(
                    built.as_slice(),
                    c,
                    "{name} golden drifted; regen + re-mint .json in the same commit"
                );
            }
        }

        #[test]
        fn golden_cap_envelopes_decode_and_embed_the_verified_cap() {
            // Decode via the real decoder; the cap-bearing envelope has key 5 (capability) + NO key 6
            // (key_ref). Cross-reference: the embedded cap (key 5), re-encoded canonically, EQUALS the
            // frozen cap_full_*_v1.bin (AC#2) — which the capability slice proved is accepted by the live
            // verify_capability. So the envelope provably carries a valid, verifier-accepted capability.
            let cap_full: &[(&str, &[u8])] = &[
                (
                    "cap_full_generate_keys_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/cap_full_generate_keys_v1.bin"),
                ),
                (
                    "cap_full_configure_set_limits_v1.bin",
                    include_bytes!(
                        "../testvectors/agent-gateway/cap_full_configure_set_limits_v1.bin"
                    ),
                ),
            ];
            for (name, bytes, opcode, request_id, cap_file) in vectors() {
                let env = decode_envelope(&bytes).unwrap_or_else(|_| panic!("{name} must decode"));
                assert_eq!(env.agent_version, AGENT_GATEWAY_VERSION, "{name} version");
                assert_eq!(env.command_domain, COMMAND_DOMAIN, "{name} domain");
                assert_eq!(env.opcode, opcode, "{name} opcode");
                assert_eq!(env.request_id.as_slice(), request_id, "{name} request_id");
                assert!(
                    env.key_ref.is_none(),
                    "{name} privileged op carries NO key_ref"
                );
                assert!(env.payload.is_some(), "{name} has a payload");
                let cap = env
                    .capability
                    .unwrap_or_else(|| panic!("{name} has a capability (key 5)"));
                let cap_bytes = enc(cap);
                let expected = cap_full.iter().find(|(n, _)| *n == cap_file).unwrap().1;
                assert_eq!(
                    cap_bytes.as_slice(),
                    expected,
                    "{name} embedded cap must equal {cap_file}"
                );
            }
        }

        #[test]
        fn golden_cap_envelope_binding_covers_its_payload() {
            // The cap's payload_binding (key 11) must equal the binding RECOMPUTED from THIS envelope's own
            // payload (key 7) — proving the cap binds the payload it travels with (the exact recompute-and-
            // compare the live handler does before mutating). Parses params back from the decoded payload, so
            // a future edit that changed the payload without updating the cap's binding source would fail.
            for (name, bytes, opcode, request_id, _cap_file) in vectors() {
                let env = decode_envelope(&bytes).unwrap_or_else(|_| panic!("{name} decode"));
                let cap = env.capability.unwrap_or_else(|| panic!("{name} cap"));
                let cap_pb = match map_get(&cap, 11) {
                    Some(Value::Bytes(b)) => b.clone(),
                    other => panic!("{name}: cap key 11 (payload_binding) not bytes: {other:?}"),
                };
                let payload = env.payload.unwrap_or_else(|| panic!("{name} payload"));
                let recomputed = match opcode {
                    1 => {
                        let purpose = map_get(&payload, 1).and_then(as_u64).unwrap();
                        let count = map_get(&payload, 2).and_then(as_u64).unwrap();
                        crate::agent_capability::payload_binding(
                            1,
                            None,
                            request_id,
                            &generate_keys_canonical_params(purpose, count),
                        )
                    }
                    6 => {
                        // Mirror handle_configure_treasury's payload SHAPE checks exactly, so a malformed
                        // regenerated payload that production would reject before binding cannot pass this
                        // recompute: sub_op via u8::try_from + range 0..=3; field2 via the production
                        // `as_u256_minimal_be` (rejects non-minimal/over-width); EXACT per-sub-op key counts
                        // (set_limits(0) = 4 keys reading 3/4; sub-ops 1..=3 = 2 keys, no gas fields).
                        let sub_op = u8::try_from(map_get(&payload, 1).and_then(as_u64).unwrap())
                            .unwrap_or_else(|_| panic!("{name}: sub_op fits u8"));
                        assert!(sub_op <= 3, "{name}: sub_op in 0..=3");
                        let field2 = crate::agent_cbor::as_u256_minimal_be(
                            map_get(&payload, 2).unwrap_or_else(|| panic!("{name}: payload key 2")),
                        )
                        .unwrap_or_else(|| panic!("{name}: field2 is canonical minimal-BE u256"));
                        let set_limits = if sub_op == 0 {
                            assert_eq!(
                                payload.len(),
                                4,
                                "{name}: set_limits(0) payload has exactly keys 1..=4"
                            );
                            let g = map_get(&payload, 3)
                                .and_then(as_u64)
                                .unwrap_or_else(|| panic!("{name}: gas_limit"));
                            let f = map_get(&payload, 4)
                                .and_then(as_u64)
                                .unwrap_or_else(|| panic!("{name}: fee_rate"));
                            Some((g, f))
                        } else {
                            assert_eq!(
                                payload.len(),
                                2,
                                "{name}: sub-op {sub_op} payload has exactly keys 1..=2 (no gas)"
                            );
                            None
                        };
                        crate::agent_capability::payload_binding(
                            6,
                            Some(sub_op),
                            request_id,
                            &configure_treasury_canonical_params(sub_op, &field2, set_limits),
                        )
                    }
                    other => panic!("{name}: unexpected opcode {other}"),
                };
                assert_eq!(
                    cap_pb.as_slice(),
                    recomputed.as_slice(),
                    "{name}: cap payload_binding must cover its own payload"
                );
            }
        }

        #[test]
        fn golden_cap_envelope_canonical_headers() {
            // Both are 6-pair maps {1,2,3,4,5,7} → 0xA6; key 5 (capability) is a map, key 6 absent.
            for (name, bytes, ..) in vectors() {
                assert_eq!(bytes[0], 0xA6, "{name} = 6-pair map {{1,2,3,4,5,7}}");
            }
        }

        #[test]
        fn golden_cap_envelope_sidecar_matches() {
            let sidecar = include_str!("../testvectors/agent-gateway/cap_envelopes_v1.json");
            let v: serde_json::Value =
                serde_json::from_str(sidecar).expect("cap-envelope index is valid JSON");
            assert_eq!(
                v["command_domain"].as_str(),
                Some(COMMAND_DOMAIN),
                "index command_domain"
            );
            assert_eq!(
                v["agent_version"].as_u64(),
                Some(AGENT_GATEWAY_VERSION as u64),
                "index agent_version"
            );
            assert_eq!(
                v["vectors"].as_object().map(|o| o.len()),
                Some(vectors().len()),
                "index has a stale/extra vector entry"
            );
            for (name, bytes, opcode, request_id, cap_file) in vectors() {
                let e = &v["vectors"][name];
                assert_eq!(
                    e["blob_sha256"].as_str(),
                    Some(hex(&Sha256::digest(&bytes)).as_str()),
                    "{name} sha256"
                );
                assert_eq!(
                    e["blob_len_bytes"].as_u64(),
                    Some(bytes.len() as u64),
                    "{name} len"
                );
                assert_eq!(
                    e["blob_hex"].as_str(),
                    Some(hex(&bytes).as_str()),
                    "{name} blob_hex"
                );
                assert_eq!(e["opcode"].as_u64(), Some(opcode as u64), "{name} opcode");
                assert_eq!(
                    e["request_id_hex"].as_str(),
                    Some(hex(request_id).as_str()),
                    "{name} request_id"
                );
                assert_eq!(
                    e["embedded_cap_file"].as_str(),
                    Some(cap_file),
                    "{name} cap cross-ref"
                );
            }
        }

        /// REGEN (manual): `cargo test --features agent-gateway golden_cap_envelopes::regen_golden_cap_envelopes -- --ignored --nocapture`.
        #[test]
        #[ignore]
        fn regen_golden_cap_envelopes() {
            let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
            let mut index = serde_json::Map::new();
            for (name, bytes, opcode, request_id, cap_file) in vectors() {
                std::fs::write(format!("{dir}{name}"), &bytes).expect("write cap-envelope .bin");
                let mut e = serde_json::Map::new();
                e.insert("blob_hex".into(), hex(&bytes).into());
                e.insert("blob_len_bytes".into(), (bytes.len() as u64).into());
                e.insert("blob_sha256".into(), hex(&Sha256::digest(&bytes)).into());
                e.insert("embedded_cap_file".into(), cap_file.into());
                e.insert("opcode".into(), (opcode as u64).into());
                e.insert("request_id_hex".into(), hex(request_id).into());
                index.insert(name.into(), serde_json::Value::Object(e));
            }
            let doc = serde_json::json!({
                "_comment": "TASK-22 AC#1 (cap-bearing) — byte-exact 0x40 request envelopes for GENERATE_KEYS / CONFIGURE_TREASURY. Cap at key 5 (no key_ref); the embedded cap equals the cap_full_*_v1.bin frozen by AC#2 (accepted by the live verify_capability). TEST KEYS ONLY (admin [7;32]; env env-prod-0, chain 11565). Regen: cargo test --features agent-gateway golden_cap_envelopes::regen_golden_cap_envelopes -- --ignored --nocapture",
                "agent_version": AGENT_GATEWAY_VERSION,
                "command_domain": COMMAND_DOMAIN,
                "vectors": serde_json::Value::Object(index),
            });
            std::fs::write(
                format!("{dir}cap_envelopes_v1.json"),
                serde_json::to_string_pretty(&doc).unwrap() + "\n",
            )
            .expect("write cap-envelope index");
            eprintln!("wrote 2 cap-envelope vectors + cap_envelopes_v1.json -> {dir}");
        }
    }

    /// TASK-22 — byte-exact `0x40` RESPONSE-BODY golden vectors (AC#3).
    ///
    /// Freezes the response bodies the enclave emits: PUBLIC_IDENTITY (6-key), SIGN_TRANSFER (7-key),
    /// SIGN_FAUCET_DISPENSE (8-key, incl. sealed_keystore_blob), GENERATE_KEYS ({1:[key maps],2:blob}),
    /// CONFIGURE_TREASURY ({1:blob}), and the §10.9 AgentError body {1:code,2:reason} for all 7 codes.
    ///
    /// Minted from the REAL encoders (`encode_agent_response` / `encode_*_response` / `encode_agent_error`)
    /// over FIXED inputs — NOT the live (preview-gated) dispatch path — so every vector builds in the base
    /// CI lane and the sealed-blob bytes are deterministic: the signed-tx fields come from `ordinary_tx_v1`
    /// (RFC6979/low-S), the identity from `public_identity_from_entry` on a `keys.json` key (the real eth/tron
    /// derivation), and the sealed blob is the already-frozen `agent_keystore_genesis_v2.sealed.bin` (a valid,
    /// byte-stable sealed keystore — opaque AEAD, so a representative blob is the right thing to pin a response
    /// SHAPE). TEST KEYS ONLY.
    mod golden_response_bodies {
        use super::*;
        use crate::agent_identity::public_identity_from_entry;
        use crate::agent_keygen::GeneratedKey;
        use crate::agent_keystore::{BackupExportMetadata, KeyAlgorithm, KeyEntry};
        use crate::agent_transfer::SignedTransfer;
        use crate::secp256k1::RecoverableSignature;
        use sha2::{Digest, Sha256};

        const KEYS: &str = include_str!("../testvectors/agent-gateway/keys.json");
        const ORD: &str = include_str!("../testvectors/agent-gateway/ordinary_tx_v1.json");
        /// A valid, byte-stable sealed keystore used as the representative sealed blob in the mutating
        /// responses (the blob is opaque AEAD; the response vector pins the SHAPE around it).
        const GENESIS_BLOB: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_genesis_v2.sealed.bin");
        const GOLDEN_KEY_REF: [u8; 32] = [0x33; 32];

        fn hx(b: &[u8]) -> String {
            hex::encode(b)
        }
        fn unhex(s: &str) -> Vec<u8> {
            hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
        }
        fn arr<const N: usize>(s: &str) -> [u8; N] {
            unhex(s).try_into().unwrap()
        }

        /// The seeded transfer KeyEntry (from keys.json) — `public_identity_from_entry` derives eth/tron.
        fn transfer_entry() -> KeyEntry {
            let k: serde_json::Value = serde_json::from_str(KEYS).unwrap();
            KeyEntry {
                key_ref: GOLDEN_KEY_REF,
                purpose: KeyPurpose::AgentTransferK1,
                algorithm: KeyAlgorithm::Secp256k1,
                public_identity: unhex(
                    k["transfer_key"]["pubkey_uncompressed_sec1"]
                        .as_str()
                        .unwrap(),
                ),
                secret_scalar: zeroize::Zeroizing::new(unhex(
                    k["transfer_key"]["privkey"].as_str().unwrap(),
                )),
                creation_metadata: CreationMetadata {
                    config_version: 1,
                    counter_snapshot: 0,
                    batch_id: 1,
                },
                backup_export_metadata: BackupExportMetadata::default(),
            }
        }

        /// A SignedTransfer reconstructed from the frozen `ordinary_tx_v1` golden (cross-references it).
        fn golden_signed_transfer() -> SignedTransfer {
            let o: serde_json::Value = serde_json::from_str(ORD).unwrap();
            SignedTransfer {
                signature: RecoverableSignature {
                    r: arr::<32>(o["signature"]["r"].as_str().unwrap()),
                    s: arr::<32>(o["signature"]["s"].as_str().unwrap()),
                    recovery_id: u8::try_from(o["signature"]["recovery_id"].as_u64().unwrap())
                        .expect("recovery_id fits u8"),
                },
                v: o["signature"]["v_eip155"].as_u64().unwrap(),
                signing_hash: arr::<32>(o["signing_hash_keccak256"].as_str().unwrap()),
                signed_rlp: unhex(o["signed_rlp"].as_str().unwrap()),
                from: arr::<20>(o["recovered_from"].as_str().unwrap()),
            }
        }

        fn resp_public_identity() -> Vec<u8> {
            let id = public_identity_from_entry(&transfer_entry()).expect("derive identity");
            encode_agent_response(&AgentResponse::PublicIdentity(id))
        }
        fn resp_sign_transfer() -> Vec<u8> {
            encode_agent_response(&AgentResponse::SignTransfer(golden_signed_transfer()))
        }
        fn resp_sign_faucet_dispense() -> Vec<u8> {
            encode_sign_faucet_dispense_response(golden_signed_transfer(), GENESIS_BLOB)
        }
        fn resp_generate_keys() -> Vec<u8> {
            let id = public_identity_from_entry(&transfer_entry()).expect("derive identity");
            let gk = GeneratedKey {
                key_ref: id.key_ref,
                pubkey_uncompressed: id.pubkey_uncompressed,
                eth_address: id.eth_address,
                tron_address: id.tron_address.clone(),
                key_purpose: id.key_purpose,
            };
            encode_generate_keys_response(&[gk], GENESIS_BLOB)
        }
        fn resp_configure_treasury() -> Vec<u8> {
            encode_configure_treasury_response(GENESIS_BLOB)
        }

        /// The 7 §10.9 AgentError codes → encoded body.
        fn agent_errors() -> Vec<(u8, Vec<u8>)> {
            [
                AgentError::Malformed,
                AgentError::WrongProfile,
                AgentError::KeyPurposeMismatch,
                AgentError::CapabilityRejected,
                AgentError::CapExceeded,
                AgentError::NotConfigured,
                AgentError::SealFailed,
            ]
            .into_iter()
            .map(|e| (e.code(), encode_agent_error(e)))
            .collect()
        }

        /// (filename, bytes, top-level key-1 is bytes? [success] — for the decode-shape assert).
        fn vectors() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                ("resp_configure_treasury_v1.bin", resp_configure_treasury()),
                ("resp_generate_keys_v1.bin", resp_generate_keys()),
                ("resp_public_identity_v1.bin", resp_public_identity()),
                (
                    "resp_sign_faucet_dispense_v1.bin",
                    resp_sign_faucet_dispense(),
                ),
                ("resp_sign_transfer_v1.bin", resp_sign_transfer()),
            ]
        }

        #[test]
        fn golden_response_bodies_are_byte_exact() {
            let committed: &[(&str, &[u8])] = &[
                (
                    "resp_configure_treasury_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/resp_configure_treasury_v1.bin"),
                ),
                (
                    "resp_generate_keys_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/resp_generate_keys_v1.bin"),
                ),
                (
                    "resp_public_identity_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/resp_public_identity_v1.bin"),
                ),
                (
                    "resp_sign_faucet_dispense_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/resp_sign_faucet_dispense_v1.bin"),
                ),
                (
                    "resp_sign_transfer_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/resp_sign_transfer_v1.bin"),
                ),
            ];
            for (name, built) in vectors() {
                let c = committed.iter().find(|(n, _)| *n == name).unwrap().1;
                assert_eq!(
                    built.as_slice(),
                    c,
                    "{name} drifted; regen + re-mint .json in the same commit"
                );
            }
        }

        #[test]
        fn golden_response_bodies_decode_to_expected_shape() {
            // Every success body decodes to a CBOR map; the mutating ones carry the sealed blob at their
            // documented key (GENERATE_KEYS key 2, SIGN_FAUCET_DISPENSE key 8, CONFIGURE_TREASURY key 1),
            // and key 1 of every SUCCESS body is NOT a bare integer code (so decode_agent_error_code → None
            // distinguishes success from a {1:code} error body).
            let get = |b: &[u8], k: u64| -> Option<Value> {
                match ciborium::de::from_reader::<Value, _>(b).unwrap() {
                    Value::Map(m) => map_get(&m, k).cloned(),
                    _ => None,
                }
            };
            assert_eq!(
                get(&resp_configure_treasury(), 1),
                Some(Value::Bytes(GENESIS_BLOB.to_vec())),
                "configure key1=blob"
            );
            assert_eq!(
                get(&resp_generate_keys(), 2),
                Some(Value::Bytes(GENESIS_BLOB.to_vec())),
                "generate key2=blob"
            );
            assert_eq!(
                get(&resp_sign_faucet_dispense(), 8),
                Some(Value::Bytes(GENESIS_BLOB.to_vec())),
                "faucet key8=blob"
            );
            for (name, bytes) in vectors() {
                assert_eq!(
                    decode_agent_error_code(&bytes),
                    None,
                    "{name} must be a SUCCESS body, not an error"
                );
            }
            // The §10.9 error bodies, conversely, ARE decodable as {1:code,2:reason}.
            for (code, body) in agent_errors() {
                assert_eq!(
                    decode_agent_error_code(&body),
                    Some(code),
                    "error body code {code:#x}"
                );
            }
        }

        #[test]
        fn golden_response_sidecar_matches() {
            let sidecar = include_str!("../testvectors/agent-gateway/response_bodies_v1.json");
            let v: serde_json::Value =
                serde_json::from_str(sidecar).expect("response index is valid JSON");
            assert_eq!(
                v["responses"].as_object().map(|o| o.len()),
                Some(vectors().len()),
                "index has a stale/extra response entry"
            );
            for (name, bytes) in vectors() {
                let e = &v["responses"][name];
                assert_eq!(
                    e["blob_sha256"].as_str(),
                    Some(hx(&Sha256::digest(&bytes)).as_str()),
                    "{name} sha"
                );
                assert_eq!(
                    e["blob_len_bytes"].as_u64(),
                    Some(bytes.len() as u64),
                    "{name} len"
                );
                assert_eq!(
                    e["blob_hex"].as_str(),
                    Some(hx(&bytes).as_str()),
                    "{name} hex"
                );
            }
            // The 7 error bodies, keyed by code hex — exactly 7, no stale/extra entry.
            assert_eq!(
                v["agent_errors"].as_object().map(|o| o.len()),
                Some(agent_errors().len()),
                "index has a stale/extra agent_error entry"
            );
            for (code, body) in agent_errors() {
                let e = &v["agent_errors"][format!("{code:#04x}")];
                assert_eq!(
                    e["body_hex"].as_str(),
                    Some(hx(&body).as_str()),
                    "error {code:#x} hex"
                );
                assert_eq!(
                    e["body_len_bytes"].as_u64(),
                    Some(body.len() as u64),
                    "error {code:#x} len"
                );
            }
        }

        /// REGEN (manual): `cargo test --features agent-gateway golden_response_bodies::regen_golden_response_bodies -- --ignored --nocapture`.
        #[test]
        #[ignore]
        fn regen_golden_response_bodies() {
            let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
            let mut responses = serde_json::Map::new();
            for (name, bytes) in vectors() {
                std::fs::write(format!("{dir}{name}"), &bytes).expect("write response .bin");
                let mut e = serde_json::Map::new();
                e.insert("blob_hex".into(), hx(&bytes).into());
                e.insert("blob_len_bytes".into(), (bytes.len() as u64).into());
                e.insert("blob_sha256".into(), hx(&Sha256::digest(&bytes)).into());
                responses.insert(name.into(), serde_json::Value::Object(e));
            }
            let mut errors = serde_json::Map::new();
            for (code, body) in agent_errors() {
                let mut e = serde_json::Map::new();
                e.insert("body_hex".into(), hx(&body).into());
                e.insert("body_len_bytes".into(), (body.len() as u64).into());
                errors.insert(format!("{code:#04x}"), serde_json::Value::Object(e));
            }
            let doc = serde_json::json!({
                "_comment": "TASK-22 AC#3 — byte-exact 0x40 response-body golden vectors. Minted from the real encoders over fixed inputs (ordinary_tx_v1 signed-tx fields, keys.json identity, the genesis sealed blob as the representative AEAD blob). The sealed blob is opaque; the vector pins the response SHAPE around it. TEST KEYS ONLY. Regen: cargo test --features agent-gateway golden_response_bodies::regen_golden_response_bodies -- --ignored --nocapture",
                "sealed_blob_file": "agent_keystore_genesis_v2.sealed.bin",
                "responses": serde_json::Value::Object(responses),
                "agent_errors": serde_json::Value::Object(errors),
            });
            std::fs::write(
                format!("{dir}response_bodies_v1.json"),
                serde_json::to_string_pretty(&doc).unwrap() + "\n",
            )
            .expect("write response index");
            eprintln!(
                "wrote 5 response vectors + 7 error bodies + response_bodies_v1.json -> {dir}"
            );
        }
    }

    /// TASK-22 — byte-exact `0x40` NEGATIVE (rejection) golden vectors (AC#4).
    ///
    /// Freezes `{malformed request bytes → expected §10.9 error code}` pairs so the downstream 2d codec can
    /// assert the enclave's anti-oracle band classification. Each request is deterministic; the band is
    /// asserted by driving the REAL `dispatch_agent` (the cap/not-configured bands need the process-global
    /// anti-rollback binding set/cleared, via the shared `gate_configured`/`gate_unconfigured` guards). The
    /// `0x44`(CapExceeded)/`0x46`(SealFailed) bands are handler/preview-level (not reachable deviceless
    /// without the preview features) — documented as deferred, not frozen here. **TEST KEYS ONLY.**
    mod golden_negative_vectors {
        use super::*;
        use sha2::{Digest, Sha256};

        const ENV_ID: &str = "env-prod-0";
        const CHAIN: u64 = 11565;
        /// `super::envelope()` stamps request_id `[0x11; 16]`; the cap negatives bind to the same id.
        const RID: &[u8] = &[0x11; 16];
        const ABSENT_KEY_REF: [u8; 32] = [0x99; 32];

        fn hx(b: &[u8]) -> String {
            hex::encode(b)
        }
        fn k(n: u64) -> Value {
            Value::Integer(n.into())
        }
        fn admin() -> ed25519_dalek::SigningKey {
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        }
        /// A body whose sealed config matches the cap conventions (admin authority [7;32], env-prod-0) so a
        /// cap negative reaches the SPECIFIC rejection (bad sig / counter gap), not an env/chain mismatch.
        fn cap_body() -> KeystoreBody {
            let mut b = base_body();
            b.config.admin_authority_pk = admin().verifying_key().to_bytes();
            b.config.environment_identifier = ENV_ID.to_string();
            b
        }
        fn genkeys_payload() -> Value {
            Value::Map(vec![
                (k(1), Value::Integer(1u64.into())),
                (k(2), Value::Integer(1u64.into())),
            ])
        }
        /// A GENERATE_KEYS cap on the admin lane; `pb` is unchecked by the verify layer (handler-only), so a
        /// placeholder is fine for verify-band negatives.
        fn genkeys_cap(signer: &ed25519_dalek::SigningKey, counter: u64) -> Vec<(Value, Value)> {
            crate::agent_capability::test_signed_capability(
                signer,
                1,
                RID,
                counter,
                false,
                CHAIN,
                ENV_ID,
                0,
                b"golden-scope-generate",
                1,
                [0xbb; 32],
                [0xe1; 32],
            )
        }

        // ---- the frozen negative request envelopes (deterministic; the code is asserted separately) ----
        fn neg_unknown_envelope_key() -> Vec<u8> {
            // Extra key 8 — decode_envelope's strict allow-list (keys 1..=7) rejects ⇒ 0x40.
            envelope(
                2,
                vec![
                    (k(6), Value::Bytes(vec![0x33; 32])),
                    (k(8), Value::Integer(0u64.into())),
                ],
            )
        }
        fn neg_runtime_op_with_capability() -> Vec<u8> {
            // SIGN_TRANSFER(4) is a runtime op; a capability at key 5 is structurally invalid ⇒ 0x40.
            envelope(
                4,
                vec![
                    (k(5), Value::Map(genkeys_cap(&admin(), 1))),
                    (k(6), Value::Bytes(vec![0x33; 32])),
                ],
            )
        }
        fn neg_wrong_profile_env() -> Vec<u8> {
            // A well-formed PUBLIC_IDENTITY env — the negative is dispatching it on Profile::Producer ⇒ 0x41.
            envelope(2, vec![(k(6), Value::Bytes(vec![0x33; 32]))])
        }
        fn neg_key_not_found() -> Vec<u8> {
            // PUBLIC_IDENTITY for a key_ref absent from the body ⇒ 0x42 (the anti-oracle key band).
            envelope(2, vec![(k(6), Value::Bytes(ABSENT_KEY_REF.to_vec()))])
        }
        fn neg_cap_wrong_signature() -> Vec<u8> {
            // GENERATE_KEYS cap signed by a NON-admin key ⇒ Ed25519 verify fails ⇒ 0x43.
            let wrong = ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]);
            envelope(
                1,
                vec![
                    (k(5), Value::Map(genkeys_cap(&wrong, 1))),
                    (k(7), genkeys_payload()),
                ],
            )
        }
        fn neg_cap_counter_gap() -> Vec<u8> {
            // Valid admin cap but counter=5 with an empty counter table (expected 1) ⇒ non-contiguous ⇒ 0x43.
            envelope(
                1,
                vec![
                    (k(5), Value::Map(genkeys_cap(&admin(), 5))),
                    (k(7), genkeys_payload()),
                ],
            )
        }
        fn neg_generate_keys_not_configured() -> Vec<u8> {
            // A well-formed, validly-capped GENERATE_KEYS — the negative is the anti-rollback binding being
            // ABSENT, so the fund-custody gate fires ⇒ 0x45 (before cap routing).
            envelope(
                1,
                vec![
                    (k(5), Value::Map(genkeys_cap(&admin(), 1))),
                    (k(7), genkeys_payload()),
                ],
            )
        }

        /// (filename, bytes, expected code, short cause). The code is asserted in the *_codes tests below.
        /// (filename, bytes, expected code, cause, PRECONDITION). The precondition is the enclave/dispatch
        /// state a consumer must reproduce to observe `expected_code` (e.g. the anti-rollback binding state
        /// for the gated bands) — without it, a state-dependent negative would yield a DIFFERENT code.
        fn vectors() -> Vec<(&'static str, Vec<u8>, u8, &'static str, &'static str)> {
            vec![
                ("neg_cap_counter_gap_v1.bin", neg_cap_counter_gap(), 0x43, "non-contiguous capability counter", "anti-rollback binding configured (so dispatch reaches cap verify, not the 0x45 gate); keystore admin authority = the cap signer, empty counter table"),
                ("neg_cap_wrong_signature_v1.bin", neg_cap_wrong_signature(), 0x43, "capability signature verify failed", "anti-rollback binding configured (so dispatch reaches cap verify, not the 0x45 gate); keystore admin authority = the EXPECTED admin key"),
                ("neg_generate_keys_not_configured_v1.bin", neg_generate_keys_not_configured(), 0x45, "anti-rollback binding not configured", "anti-rollback binding ABSENT (the fund-custody gate fires before cap routing)"),
                ("neg_key_not_found_v1.bin", neg_key_not_found(), 0x42, "key_ref not found / wrong purpose", "keystore has no entry for the requested key_ref"),
                ("neg_runtime_op_with_capability_v1.bin", neg_runtime_op_with_capability(), 0x40, "runtime opcode carrying a capability", "none (rejected at decode/allow-list, before any state)"),
                ("neg_unknown_envelope_key_v1.bin", neg_unknown_envelope_key(), 0x40, "unknown envelope key (strict 1..=7)", "none (rejected at decode, before any state)"),
                ("neg_wrong_profile_v1.bin", neg_wrong_profile_env(), 0x41, "agent opcode on the producer profile", "dispatched on Profile::Producer (non-agent-gateway)"),
            ]
        }

        #[test]
        fn golden_negative_vectors_are_byte_exact() {
            let committed: &[(&str, &[u8])] = &[
                (
                    "neg_cap_counter_gap_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/neg_cap_counter_gap_v1.bin"),
                ),
                (
                    "neg_cap_wrong_signature_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/neg_cap_wrong_signature_v1.bin"),
                ),
                (
                    "neg_generate_keys_not_configured_v1.bin",
                    include_bytes!(
                        "../testvectors/agent-gateway/neg_generate_keys_not_configured_v1.bin"
                    ),
                ),
                (
                    "neg_key_not_found_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/neg_key_not_found_v1.bin"),
                ),
                (
                    "neg_runtime_op_with_capability_v1.bin",
                    include_bytes!(
                        "../testvectors/agent-gateway/neg_runtime_op_with_capability_v1.bin"
                    ),
                ),
                (
                    "neg_unknown_envelope_key_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/neg_unknown_envelope_key_v1.bin"),
                ),
                (
                    "neg_wrong_profile_v1.bin",
                    include_bytes!("../testvectors/agent-gateway/neg_wrong_profile_v1.bin"),
                ),
            ];
            for (name, built, ..) in vectors() {
                let c = committed.iter().find(|(n, _)| *n == name).unwrap().1;
                assert_eq!(
                    built.as_slice(),
                    c,
                    "{name} drifted; regen + re-mint .json in the same commit"
                );
            }
        }

        #[test]
        fn golden_negative_shape_and_key_codes() {
            // Shape (0x40) + profile (0x41) + key (0x42) bands — all reached BEFORE the anti-rollback gate /
            // any process global, so no guard is needed. Driven through the real dispatch_agent.
            let b = base_body();
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &neg_unknown_envelope_key(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x40
            );
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &neg_runtime_op_with_capability(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x40
            );
            assert_eq!(
                dispatch_agent(
                    Profile::Producer,
                    &neg_wrong_profile_env(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x41
            );
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &neg_key_not_found(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x42
            );
        }

        #[test]
        fn golden_negative_capability_codes() {
            // 0x43 band: the anti-rollback binding must be INSTALLED so dispatch reaches cap verify (else the
            // gate would return 0x45 first). gate_configured installs it + holds the process-global guard.
            let _g = gate_configured();
            let b = cap_body();
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &neg_cap_wrong_signature(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x43
            );
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &neg_cap_counter_gap(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x43
            );
        }

        #[test]
        fn golden_negative_not_configured_code() {
            // 0x45 band: binding ABSENT ⇒ the fund-custody gate fires for the rollback-sensitive GENERATE_KEYS
            // even with an otherwise-valid cap. gate_unconfigured clears the binding + holds the guard.
            let _g = gate_unconfigured();
            let b = cap_body();
            assert_eq!(
                dispatch_agent(
                    Profile::AgentGateway,
                    &neg_generate_keys_not_configured(),
                    &b,
                    b"test-measurement"
                )
                .err()
                .unwrap()
                .code(),
                0x45
            );
        }

        #[test]
        fn configure_treasury_stray_key_ref_is_accepted_and_ignored() {
            // DOCUMENTED current behavior (TASK-20 residual, document-the-ignore): §10.7 says CONFIGURE has
            // no key_ref, but decode_envelope ACCEPTS a stray key 6 on ANY envelope (it is a valid envelope
            // key) and the CONFIGURE handler simply ignores it — benign, since the capability binding (not the
            // key_ref) carries integrity. A future strict-shape tightening (reject env.key_ref.is_some() for
            // CONFIGURE) would turn this into a 0x40 negative; until then this pins the accepted-but-ignored
            // shape so the frozen negative set stays consistent with actual behavior.
            let env = envelope(6, vec![(k(6), Value::Bytes(vec![0x33; 32]))]);
            let decoded =
                decode_envelope(&env).expect("stray key_ref on CONFIGURE is currently accepted");
            assert_eq!(decoded.opcode, 6, "opcode preserved");
            assert!(
                decoded.key_ref.is_some(),
                "the stray key_ref is present (decoded) but unused by the handler"
            );
        }

        #[test]
        fn golden_negative_sidecar_matches() {
            let sidecar = include_str!("../testvectors/agent-gateway/negative_vectors_v1.json");
            let v: serde_json::Value =
                serde_json::from_str(sidecar).expect("negative index is valid JSON");
            assert_eq!(
                v["negatives"].as_object().map(|o| o.len()),
                Some(vectors().len()),
                "index has a stale/extra negative entry"
            );
            for (name, bytes, code, cause, precondition) in vectors() {
                let e = &v["negatives"][name];
                assert_eq!(
                    e["expected_code"].as_u64(),
                    Some(code as u64),
                    "{name} code"
                );
                assert_eq!(e["cause"].as_str(), Some(cause), "{name} cause");
                assert_eq!(
                    e["precondition"].as_str(),
                    Some(precondition),
                    "{name} precondition"
                );
                assert_eq!(
                    e["blob_sha256"].as_str(),
                    Some(hx(&Sha256::digest(&bytes)).as_str()),
                    "{name} sha"
                );
                assert_eq!(
                    e["blob_len_bytes"].as_u64(),
                    Some(bytes.len() as u64),
                    "{name} len"
                );
                assert_eq!(
                    e["blob_hex"].as_str(),
                    Some(hx(&bytes).as_str()),
                    "{name} hex"
                );
            }
        }

        /// REGEN (manual): `cargo test --features agent-gateway golden_negative_vectors::regen_golden_negative_vectors -- --ignored --nocapture`.
        #[test]
        #[ignore]
        fn regen_golden_negative_vectors() {
            let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
            let mut negatives = serde_json::Map::new();
            for (name, bytes, code, cause, precondition) in vectors() {
                std::fs::write(format!("{dir}{name}"), &bytes).expect("write negative .bin");
                let mut e = serde_json::Map::new();
                e.insert("blob_hex".into(), hx(&bytes).into());
                e.insert("blob_len_bytes".into(), (bytes.len() as u64).into());
                e.insert("blob_sha256".into(), hx(&Sha256::digest(&bytes)).into());
                e.insert("cause".into(), cause.into());
                e.insert("expected_code".into(), (code as u64).into());
                e.insert("precondition".into(), precondition.into());
                negatives.insert(name.into(), serde_json::Value::Object(e));
            }
            let doc = serde_json::json!({
                "_comment": "TASK-22 AC#4 — byte-exact 0x40 NEGATIVE vectors: {request bytes → expected §10.9 code}, asserted via the real dispatch_agent. 0x40 shape / 0x41 profile / 0x42 key / 0x43 capability / 0x45 not-configured. 0x44 (CapExceeded) and 0x46 (SealFailed) are handler/preview-level — deferred. CONFIGURE stray key_ref is accepted+ignored today (TASK-20 document-the-ignore). TEST KEYS ONLY. Regen: cargo test --features agent-gateway golden_negative_vectors::regen_golden_negative_vectors -- --ignored --nocapture",
                "negatives": serde_json::Value::Object(negatives),
            });
            std::fs::write(
                format!("{dir}negative_vectors_v1.json"),
                serde_json::to_string_pretty(&doc).unwrap() + "\n",
            )
            .expect("write negative index");
            eprintln!("wrote 7 negative vectors + negative_vectors_v1.json -> {dir}");
        }
    }
}
