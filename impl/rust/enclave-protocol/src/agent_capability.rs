//! Agent Gateway administrative / recovery **capability verification** (vsock spec §10.5/§10.6).
//!
//! A capability is the TEE-verified, signed, parameter-binding token carried at inner-envelope key
//! `5` for the privileged opcodes `{GENERATE_KEYS(1), CONFIGURE_TREASURY(6), EXPORT_BACKUP(7),
//! RESTORE_BACKUP(8)}`. Host-side Vault/OPA authorization is **never** sufficient (AC#6); the enclave
//! independently verifies an Ed25519 signature against a **sealed** trust root.
//!
//! ## What this slice implements (verify-only)
//! [`verify_capability`] performs the read-only half of the §10.5 verify order:
//! 1. strict structural decode of the capability map (keys `1..=14`, no unknown/dup, required keys
//!    present, key `3` present iff `command_opcode == 6`) — any shape error ⇒ `0x40 MALFORMED`;
//! 2. `cap_format_version == 2` (unknown version ⇒ `0x40`; v1 caps fail closed — TASK-18 18-2a);
//! 3. **Ed25519 verify** of key `14` over `CAP_DOMAIN ‖ canonical-CBOR({1..13})`
//!    against the `is_recovery`-selected sealed authority (`admin_authority_pk` /
//!    `recovery_authority_pk`). Key `13` is the signed `scope_identity` (18-2a); it is INSIDE the
//!    signed bytes, key `14` (the signature) is excluded.
//! 4. `command_opcode == request.opcode` and `request_id(key 10) == envelope.request_id`;
//! 5. `chain_id` and `environment_identifier` equal the sealed config (byte-exact);
//! 5b. **`scope_identity` byte-bound** (TASK-18 18-2 / AC#1): `scope_class==0` ⇒ equals the sealed
//!    `enclave_scope_id`; `scope_class==1` ⇒ equals `fleet_scope_id`. This is the clone-replay guard
//!    (a cap minted for enclave A cannot replay on clone B). NB: this holds ONLY if `enclave_scope_id`
//!    is host-uncontrollable — TASK-25 AC#3 (in-TEE RNG provenance) is the un-gate precondition.
//! 6. **contiguous counter CHECK** (§10.6): `counter == highest_accepted_counter + 1` for the tuple
//!    `(authority, environment_identifier, scope_class, scope_target)` — read-only, no advance.
//!
//! Every semantic failure collapses to `0x43 AGENT_CAPABILITY_REJECTED` (anti-oracle, §10.9); only
//! structural/format errors surface as `0x40 AGENT_MALFORMED`.
//!
//! ## Domain string vs format version
//! `CAP_DOMAIN` is the fixed domain-separation label `"2d-hsm/agent-cap/v1\0"`; the `v1` there is
//! the DOMAIN label, NOT the capability format version. The wire-format version authority is
//! `cap_format_version` (cap key 1, currently `2`). They intentionally diverge: the domain string
//! pins the Ed25519 domain-separation prefix (stable across format bumps unless the signing domain
//! itself changes), while `cap_format_version` gates the signed-shape evolution (18-2a added the
//! signed `scope_identity` at key 13 and moved the signature 13 → 14). No production cap has ever
//! been minted, so the v1 → v2 bump is a clean break (a future bump after G3/TASK-25 ships a real
//! provisioned keystore is NOT clean and needs a migration plan).
//!
//! ## Deferred to the per-opcode handler / mutation slices (NOT done here)
//! - **`treasury_sub_op == request.sub_op` binding** (§10.5, opcode 6): the cap's signed sub-op is
//!   range-checked to `{0..=3}` (§10.3) at decode, and its per-sub-op tier is enforced
//!   (`reset_lifetime_breaker(3)` → recovery, `0..=2` → admin). Only binding the cap's sub-op to the
//!   *request's* sub-op is deferred — the envelope does not yet decode a request sub-op (that lands
//!   with the `CONFIGURE_TREASURY` handler; transitively also covered by `payload_binding`).
//! - **`key_purpose` ↔ key-entry** check (`0x42`, collapses key-not-found + wrong-purpose): needs the
//!   `key_ref` lookup performed inside each opcode handler.
//! - **`payload_binding`** (`keccak256(opcode ‖ sub_op ‖ request_id ‖ canonical params)`): needs the
//!   per-opcode canonical command-param encoding, which lands with the handlers.
//! - **`scope_class` "financial MUST be enclave" policy** (§10.5/§10.6, AC#12): the structural range
//!   `{0,1}` is enforced here, and the per-opcode rule (faucet/treasury keygen + treasury config
//!   require `scope_class == 0`) is ALREADY enforced at the live handlers
//!   (`agent_dispatch.rs` GENERATE_KEYS treasury-keygen + CONFIGURE_TREASURY reject `scope_class != 0`,
//!   with a paired `fleet-scoped treasury cap ⇒ 0x43` test). TASK-18 slice 18-5 owns the COMPLETENESS
//!   audit — enumerate EVERY budget-/rollback-sensitive opcode (incl. the still-preview-banned
//!   sign-faucet / export-backup) and prove none is fleet-scoped — plus the paired
//!   fleet-financial-reject test; it is NOT re-adding the two already-live checks.
//! - **recovery-tier counter semantics** (§10.6, AC#11): a recovery (`is_recovery`) capability is
//!   sequenced by an **independent strict recovery counter** and resyncs a wedged scope
//!   **forward-only** (`counter > highest`, not `== highest+1`); `RESTORE_BACKUP` +
//!   `reset_lifetime_breaker` share it. This slice applies the uniform admin contiguity rule to all
//!   caps (`is_recovery` only selects the verifying authority) — the distinct recovery-counter rule
//!   lands with the mutation slice.
//! - **counter ADVANCE + atomic re-seal** (`highest := counter`, clone→seal→anchor-commit→swap→emit):
//!   part of the GENERATE_KEYS-execution / candidate-swap mutation slice (7.2/7.6.x territory).
//!
//! A capability that passes this verify therefore reaches the handler, which today returns
//! `0x45 AGENT_NOT_CONFIGURED` (execution not yet wired). Only a holder of the sealed authority's
//! private key can produce a passing capability, so the `0x45`-vs-`0x43` distinction is not a useful
//! oracle (an attacker without the key cannot reach it).

use crate::agent_dispatch::AgentError;
use crate::agent_keystore::{CounterEntry, KeystoreConfig};
use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};

/// Domain prefix for the capability signing preimage (§10.5). The trailing NUL is part of the label.
const CAP_DOMAIN: &[u8] = b"2d-hsm/agent-cap/v1\0";
/// Only version understood by this build.
// v2 (TASK-18 18-2a): adds the signed `scope_identity` field at key 13 (the enclave/fleet id this
// cap binds to, byte-compared against the sealed `enclave_scope_id`/`fleet_scope_id` in 18-2b). The
// Ed25519 signature moved from key 13 → key 14. A v1 cap (no scope_identity) fails closed here as
// 0x40 before any state touch. No production cap has ever been minted, so this is a clean break (no
// migration story needed) — a future bump after G3 ships a real provisioned keystore is NOT (see
// TASK-25 AC#5).
const CAP_FORMAT_VERSION: u64 = 2;
/// `treasury_sub_op` (cap key 3) is present iff the capability authorizes `CONFIGURE_TREASURY`.
const OPCODE_CONFIGURE_TREASURY: u8 = 6;
/// Opcodes a capability may authorize — the privileged set (§10.3/§10.5):
/// `GENERATE_KEYS(1)`, `CONFIGURE_TREASURY(6)`, `EXPORT_BACKUP(7)`, `RESTORE_BACKUP(8)`.
const PRIVILEGED_OPCODES: [u8; 4] = [1, OPCODE_CONFIGURE_TREASURY, 7, 8];
/// Treasury sub-ops (§10.3): `0 set_limits, 1 refill_budget, 2 raise_lifetime_breaker,
/// 3 reset_lifetime_breaker`. `reset_lifetime_breaker` is recovery-tier; `0..=2` are admin-tier.
const MAX_TREASURY_SUB_OP: u8 = 3;
const TREASURY_SUB_OP_RESET_LIFETIME_BREAKER: u8 = 3;
/// Upper bound on `scope_target` bytes — a defensive read-side cap (the field is host-influenced and
/// later lands in sealed state; keep it small here so a malformed cap is rejected cheaply). `pub(crate)`
/// so the sealed-body audit ring (whose `scope_target` ORIGINATES from a verified capability) can bound
/// its records by the same true-origin cap in [`crate::agent_keystore::KeystoreBody::validate`].
pub(crate) const MAX_SCOPE_TARGET_LEN: usize = 64;
/// TASK-18 18-3 — `scope_target` well-formedness (the field is a command-class counter-lane LABEL, not
/// an opcode/purpose the enclave dispatches on; dispatch is by `command_opcode` + `key_purpose`, both
/// signed). Format: non-empty, ≤ [`MAX_SCOPE_TARGET_LEN`] bytes, `[a-z0-9_-]+` (lowercase ASCII
/// alphanumeric + underscore + hyphen). This is NOT a strict whitelist — the canonical command-class
/// lanes (`generate_transfer` / `generate_faucet` / `configure_treasury` / `export_backup` /
/// `restore_backup`, §10.6) are an ISSUANCE convention, and AC#18 explicitly permits the issuer to
/// narrow further (sub-lanes); the enclave fails closed only on a malformed (unset/garbage) label, not
/// on a non-canonical one. Defense-in-depth: `scope_target` is not a security boundary after 18-2
/// (replay is caught by the counter contiguity + the signed `scope_identity`), so this guard rejects
/// the degenerate cases (empty, non-canonical-charset, host garbage) rather than enumerate lanes.
/// NB it does NOT mirror [`crate::agent_keystore::is_valid_environment_identifier`] exactly — it uses
/// the same small-helper SHAPE but DIFFERENT rules: `scope_target` allows `_` (required by the
/// canonical `generate_transfer` lanes) and has NO positional-hyphen constraints (no leading/trailing/
/// double-hyphen ban), because the field is not a security boundary and canonical labels use `_`.
/// Do not "harden" this to match env-identifier rules — it would break the canonical lanes.
pub(crate) fn is_valid_scope_target(b: &[u8]) -> bool {
    if b.is_empty() || b.len() > MAX_SCOPE_TARGET_LEN {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}
/// Upper bound on `request_id` bytes — mirrors the envelope's `MAX_REQUEST_ID_LEN`.
const MAX_CAP_REQUEST_ID_LEN: usize = 64;

/// Parsed, type-checked capability (keys `1..=14`; key 14 = Ed25519 signature, key 13 =
/// `scope_identity`). Field types follow §10.5; `treasury_sub_op` is `Some` iff `command_opcode == 6`.
struct Capability {
    cap_format_version: u64,
    command_opcode: u8,
    treasury_sub_op: Option<u8>,
    key_purpose: u8,
    chain_id: u64,
    environment_identifier: String,
    scope_class: u8,
    scope_target: Vec<u8>,
    counter: u64,
    request_id: Vec<u8>,
    payload_binding: [u8; 32],
    is_recovery: bool,
    /// The signed scope identity this cap binds to (cap key 13, TASK-18 18-2a): for `scope_class==0`
    /// it is the target enclave id (byte-compared vs the sealed `enclave_scope_id`); for
    /// `scope_class==1` it is the fleet id (vs `fleet_scope_id`). Signed so a host cannot alter it
    /// under a valid cap — this is the field that makes AC#1's clone-replay guard enforceable.
    /// 18-2a added the field (parsed + signed + emitted); 18-2b ENFORCES it in
    /// `verify_capability_extract_inner` (step 5b) + the `KeystoreBody::validate()` value-level guards
    /// (reject all-zero / `enclave == fleet`).
    scope_identity: [u8; 32],
    signature: [u8; 64],
}

/// The verified-capability data a privileged handler needs after [`verify_capability`] passes: the
/// counter tuple (to advance the counter), the signed `payload_binding` (to bind the request params),
/// and `key_purpose` (to bind the op's key purpose). `environment_identifier` is the sealed config's
/// (the cap's was checked byte-exact), so it is not duplicated here.
pub(crate) struct VerifiedCapability {
    /// The sealed authority pubkey that verified this cap (admin or recovery) — counter-tuple key.
    pub authority: [u8; 32],
    pub scope_class: u8,
    pub scope_target: Vec<u8>,
    /// The accepted counter value (== highest_accepted_counter + 1); the handler advances to this.
    pub counter: u64,
    /// keccak256(opcode ‖ [sub_op] ‖ request_id ‖ canonical-CBOR(params)) — the handler recomputes
    /// from the actual request payload and compares (the last gate before mutation).
    pub payload_binding: [u8; 32],
    pub key_purpose: u8,
    /// The cap's signed `treasury_sub_op` (cap key 3), `Some` iff `command_opcode == 6`. The
    /// CONFIGURE_TREASURY handler MUST assert `request.sub_op == Some(this)` (§10.7) — the tier check
    /// above (admin vs recovery) keys off THIS field, so without the direct equality an admin cap
    /// (`treasury_sub_op` ∈ {0..2}) carrying a `payload_binding` baked for sub_op 3 would let an admin
    /// authorize the recovery-tier `reset_lifetime_breaker` (a tier-separation bypass). `payload_binding`
    /// alone does not close this — the issuer signs `payload_binding` as an opaque value, so it must be
    /// cross-checked against the independently-signed sub-op.
    pub treasury_sub_op: Option<u8>,
}

use crate::agent_cbor::{as_bytes, as_bytes32, as_bytes_n, as_u64, check_strict_keys, map_get};

/// Strict structural decode of the capability map → typed [`Capability`]. Any shape/type/range
/// violation ⇒ [`AgentError::Malformed`] (`0x40`, syntax only).
fn parse_capability(map: &[(Value, Value)]) -> Result<Capability, AgentError> {
    // Strict keys: every key is an integer in 1..=14, none repeats.
    // 18-2a: key 13 is `scope_identity` (signed); key 14 is the Ed25519 signature (NOT signed). A v2
    // cap MUST carry both.
    if !check_strict_keys(map, |n| (1..=14).contains(&n)) {
        return Err(AgentError::Malformed);
    }

    let req_u64 = |key: u64| {
        map_get(map, key)
            .and_then(as_u64)
            .ok_or(AgentError::Malformed)
    };
    let req_u8 = |key: u64| {
        map_get(map, key)
            .and_then(as_u64)
            .and_then(|v| u8::try_from(v).ok())
            .ok_or(AgentError::Malformed)
    };

    let cap_format_version = req_u64(1)?;
    let command_opcode = req_u8(2)?;
    // Capabilities only ever authorize privileged opcodes (§10.3/§10.5); a cap for a read/runtime or
    // out-of-range opcode is structurally invalid. (The dispatch seam also binds command_opcode to
    // the request opcode, but reject it here too — defense in depth, not caller-dependent.)
    if !PRIVILEGED_OPCODES.contains(&command_opcode) {
        return Err(AgentError::Malformed);
    }
    // key 3 present iff opcode is CONFIGURE_TREASURY.
    let treasury_sub_op = match map_get(map, 3) {
        Some(v) => {
            if command_opcode != OPCODE_CONFIGURE_TREASURY {
                return Err(AgentError::Malformed); // sub-op on a non-treasury cap
            }
            let sub = u8::try_from(as_u64(v).ok_or(AgentError::Malformed)?)
                .map_err(|_| AgentError::Malformed)?;
            // §10.3: sub-op ∈ {0..=3}; an unknown sub-op is a structural field error (§10.9 0x40).
            if sub > MAX_TREASURY_SUB_OP {
                return Err(AgentError::Malformed);
            }
            Some(sub)
        }
        None => {
            if command_opcode == OPCODE_CONFIGURE_TREASURY {
                return Err(AgentError::Malformed); // treasury cap missing its sub-op
            }
            None
        }
    };
    let key_purpose = req_u8(4)?;
    if !(1..=2).contains(&key_purpose) {
        return Err(AgentError::Malformed);
    }
    let chain_id = req_u64(5)?;
    // §10.6: environment_identifier is UTF-8, 1..=64, [a-z0-9-], no leading/trailing/double hyphen.
    // Reuse the keystore validator so a malformed env fails closed AT DECODE (0x40), consistent with
    // the sealed config's own validation (the later byte-exact compare then only sees a valid value).
    let environment_identifier = match map_get(map, 6) {
        Some(Value::Text(s)) if crate::agent_keystore::is_valid_environment_identifier(s) => {
            s.clone()
        }
        _ => return Err(AgentError::Malformed),
    };
    let scope_class = req_u8(7)?;
    // §10.5: scope_class ∈ {0=enclave, 1=fleet}. Out-of-range is a structural field error (the
    // "financial MUST be enclave" *policy* is per-opcode and deferred to the handler — see docs).
    if scope_class > 1 {
        return Err(AgentError::Malformed);
    }
    let scope_target = match map_get(map, 8).and_then(as_bytes) {
        Some(b) if is_valid_scope_target(b) => b.to_vec(),
        _ => return Err(AgentError::Malformed),
    };
    let counter = req_u64(9)?;
    let request_id = match map_get(map, 10).and_then(as_bytes) {
        Some(b) if b.len() <= MAX_CAP_REQUEST_ID_LEN => b.to_vec(),
        _ => return Err(AgentError::Malformed),
    };
    let payload_binding: [u8; 32] = map_get(map, 11)
        .and_then(as_bytes32)
        .ok_or(AgentError::Malformed)?;
    let is_recovery = match map_get(map, 12) {
        Some(Value::Bool(b)) => *b,
        _ => return Err(AgentError::Malformed),
    };
    // 18-2a: signed scope identity (enclave/fleet id this cap binds to). Required on every v2 cap.
    let scope_identity: [u8; 32] = map_get(map, 13)
        .and_then(as_bytes32)
        .ok_or(AgentError::Malformed)?;
    // 18-2a: signature moved key 13 → 14.
    let signature: [u8; 64] = map_get(map, 14)
        .and_then(as_bytes_n::<64>)
        .ok_or(AgentError::Malformed)?;

    Ok(Capability {
        cap_format_version,
        command_opcode,
        treasury_sub_op,
        key_purpose,
        chain_id,
        environment_identifier,
        scope_class,
        scope_target,
        counter,
        request_id,
        payload_binding,
        is_recovery,
        scope_identity,
        signature,
    })
}

/// Append a CBOR unsigned head/value (major type `major`, argument `val`) in **shortest form**
/// (RFC 8949 §4.2.1 deterministic encoding). Used for both map/key headers and integer values.
pub(crate) fn put_uint(out: &mut Vec<u8>, major: u8, val: u64) {
    let mt = major << 5;
    if val < 24 {
        out.push(mt | val as u8);
    } else if val <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(val as u8);
    } else if val <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

pub(crate) fn put_text(out: &mut Vec<u8>, s: &str) {
    put_uint(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_uint(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

/// The Ed25519-signed message: `CAP_DOMAIN ‖ canonical-CBOR({keys 1..13})`.
///
/// Keys are emitted in ascending order with shortest-form integer keys and a definite-length map
/// header — RFC 8949 §4.2.1 core deterministic encoding — so a conformant host signer and this
/// verifier produce byte-identical preimages. Key `14` (the signature) is excluded; keys `1..=13`
/// are signed (key 13 = `scope_identity`, added 18-2a).
fn signed_preimage(cap: &Capability) -> Vec<u8> {
    let mut out = Vec::with_capacity(CAP_DOMAIN.len() + 96 + cap.environment_identifier.len());
    out.extend_from_slice(CAP_DOMAIN);
    let count: u64 = if cap.treasury_sub_op.is_some() {
        13
    } else {
        12
    };
    put_uint(&mut out, 5, count); // map header
    put_uint(&mut out, 0, 1);
    put_uint(&mut out, 0, cap.cap_format_version);
    put_uint(&mut out, 0, 2);
    put_uint(&mut out, 0, u64::from(cap.command_opcode));
    if let Some(sub) = cap.treasury_sub_op {
        put_uint(&mut out, 0, 3);
        put_uint(&mut out, 0, u64::from(sub));
    }
    put_uint(&mut out, 0, 4);
    put_uint(&mut out, 0, u64::from(cap.key_purpose));
    put_uint(&mut out, 0, 5);
    put_uint(&mut out, 0, cap.chain_id);
    put_uint(&mut out, 0, 6);
    put_text(&mut out, &cap.environment_identifier);
    put_uint(&mut out, 0, 7);
    put_uint(&mut out, 0, u64::from(cap.scope_class));
    put_uint(&mut out, 0, 8);
    put_bytes(&mut out, &cap.scope_target);
    put_uint(&mut out, 0, 9);
    put_uint(&mut out, 0, cap.counter);
    put_uint(&mut out, 0, 10);
    put_bytes(&mut out, &cap.request_id);
    put_uint(&mut out, 0, 11);
    put_bytes(&mut out, &cap.payload_binding);
    put_uint(&mut out, 0, 12);
    out.push(if cap.is_recovery { 0xf5 } else { 0xf4 });
    put_uint(&mut out, 0, 13);
    put_bytes(&mut out, &cap.scope_identity);
    out
}

/// Verify a capability for a privileged opcode against the sealed config + counters, returning the
/// [`VerifiedCapability`] data the handler binds (`payload_binding`) + advances (the counter tuple).
///
/// `cap_map` is the raw inner-envelope key-`5` map; `request_opcode`/`request_id` come from the outer
/// envelope. `Ok(VerifiedCapability)` if the capability is authentic and authorized for this request
/// and its counter is the expected next value; otherwise an anti-oracle [`AgentError`].
pub(crate) fn verify_capability_extract(
    cap_map: &[(Value, Value)],
    request_opcode: u8,
    request_id: &[u8],
    config: &KeystoreConfig,
    counters: &[CounterEntry],
) -> Result<VerifiedCapability, AgentError> {
    verify_capability_extract_inner(cap_map, request_opcode, request_id, config, counters)
}

/// Verify-only predicate: `Ok(())` if the capability is authentic + authorized for this request and
/// counter-contiguous, else the anti-oracle [`AgentError`]. Test-only — the live seam calls
/// [`verify_capability_extract`] (handlers need the verified data to bind `payload_binding` + advance).
#[cfg(test)]
pub(crate) fn verify_capability(
    cap_map: &[(Value, Value)],
    request_opcode: u8,
    request_id: &[u8],
    config: &KeystoreConfig,
    counters: &[CounterEntry],
) -> Result<(), AgentError> {
    verify_capability_extract_inner(cap_map, request_opcode, request_id, config, counters)
        .map(|_| ())
}

fn verify_capability_extract_inner(
    cap_map: &[(Value, Value)],
    request_opcode: u8,
    request_id: &[u8],
    config: &KeystoreConfig,
    counters: &[CounterEntry],
) -> Result<VerifiedCapability, AgentError> {
    let cap = parse_capability(cap_map)?;

    // (2) format version (unknown ⇒ MALFORMED, not an oracle).
    if cap.cap_format_version != CAP_FORMAT_VERSION {
        return Err(AgentError::Malformed);
    }

    // (2b) Authority TIER per opcode (design doc "Capability tiers"): GENERATE_KEYS(1) +
    // EXPORT_BACKUP(7) are admin-tier; RESTORE_BACKUP(8) is recovery-tier; CONFIGURE_TREASURY(6) is
    // tier-checked per sub-op here (reset_lifetime_breaker → recovery; set_limits/refill/raise →
    // admin) — only binding the cap's sub-op to the *request's* sub-op is deferred to the handler.
    // Enforcing this here stops an admin authority from authorizing a restore and a recovery
    // authority from authorizing keygen/export. A tier mismatch is an authorization failure
    // (0x43, anti-oracle), not a structural error. From here on EVERY failure collapses to 0x43.
    let tier_ok = match cap.command_opcode {
        1 | 7 => !cap.is_recovery, // admin-only
        8 => cap.is_recovery,      // recovery-only
        OPCODE_CONFIGURE_TREASURY => match cap.treasury_sub_op {
            // §10.3/§10.7: reset_lifetime_breaker(3) = recovery; set_limits/refill/raise (0..=2) = admin.
            Some(TREASURY_SUB_OP_RESET_LIFETIME_BREAKER) => cap.is_recovery,
            Some(_) => !cap.is_recovery,
            None => false, // unreachable: opcode 6 ⇒ sub_op present (parse presence rule)
        },
        _ => false, // unreachable: opcode ∈ PRIVILEGED_OPCODES
    };
    if !tier_ok {
        return Err(AgentError::CapabilityRejected);
    }

    // (3) Ed25519 verify over canonical CBOR(1..13), against the is_recovery-selected sealed
    // authority (now tier-validated above). Key 14 (the signature itself) is excluded from the signed bytes.
    let authority = if cap.is_recovery {
        &config.recovery_authority_pk
    } else {
        &config.admin_authority_pk
    };
    let verifying_key =
        VerifyingKey::from_bytes(authority).map_err(|_| AgentError::CapabilityRejected)?;
    let signature = Signature::from_bytes(&cap.signature);
    verifying_key
        .verify_strict(&signed_preimage(&cap), &signature)
        .map_err(|_| AgentError::CapabilityRejected)?;

    // (4) opcode + request_id binding (a cap issued for one opcode/request cannot authorize another).
    if cap.command_opcode != request_opcode {
        return Err(AgentError::CapabilityRejected);
    }
    if cap.request_id != request_id {
        return Err(AgentError::CapabilityRejected);
    }

    // (5) chain + environment bound to sealed values (byte-exact).
    if cap.chain_id != config.twod_chain_id {
        return Err(AgentError::CapabilityRejected);
    }
    if cap.environment_identifier != config.environment_identifier {
        return Err(AgentError::CapabilityRejected);
    }

    // (5b) scope_identity byte-bound to the sealed scope id selected by scope_class (TASK-18 18-2 / AC#1).
    // This is the clone-replay guard: a cap minted for enclave A (carrying A's `enclave_scope_id` in its
    // signed `scope_identity`) cannot be replayed on a fresh clone B, because B's sealed `enclave_scope_id`
    // differs and this byte-compare fails (0x43) BEFORE the empty-counter-row check at (6) would otherwise
    // accept `incoming==1`. `scope_class==0` (enclave) pins to the per-enclave `enclave_scope_id`;
    // `scope_class==1` (fleet) pins to the shared `fleet_scope_id` (legitimately equal across one fleet's
    // clones). The signed `scope_identity` field (cap key 13, 18-2a) makes this host-unalterable under a
    // valid cap. NB: this guard holds ONLY if `enclave_scope_id` was minted in-TEE and is not host-selectable
    // — see TASK-25 AC#3 (G3 provenance precondition). The `financial ⇒ scope_class==0` policy that makes
    // this guard non-bypassable for budget-sensitive ops is enforced at the handler (18-5).
    let sealed_scope_id = if cap.scope_class == 0 {
        &config.enclave_scope_id
    } else {
        &config.fleet_scope_id
    };
    use subtle::ConstantTimeEq;
    if !bool::from(
        cap.scope_identity
            .as_slice()
            .ct_eq(sealed_scope_id.as_slice()),
    ) {
        return Err(AgentError::CapabilityRejected);
    }

    // (6) strict contiguous counter CHECK (§10.6) for the tuple
    // (authority, environment_identifier, scope_class, scope_target). No entry yet ⇒ highest = 0, so
    // the first accepted counter is 1. Read-only: the advance + re-seal lands with the mutation slice.
    // NOTE: recovery caps (is_recovery) get the same uniform contiguity here; their independent
    // strict-recovery-counter + forward-only resync rule (§10.6 AC#11) lands with the mutation slice.
    let highest = counters
        .iter()
        .find(|c| {
            &c.authority == authority
                && c.environment_identifier == cap.environment_identifier
                && c.scope_class == cap.scope_class
                && c.scope_target == cap.scope_target
        })
        .map(|c| c.highest_accepted_counter)
        .unwrap_or(0);
    let expected = highest
        .checked_add(1)
        .ok_or(AgentError::CapabilityRejected)?;
    if cap.counter != expected {
        return Err(AgentError::CapabilityRejected);
    }

    Ok(VerifiedCapability {
        authority: *authority,
        scope_class: cap.scope_class,
        scope_target: cap.scope_target,
        counter: cap.counter,
        payload_binding: cap.payload_binding,
        key_purpose: cap.key_purpose,
        treasury_sub_op: cap.treasury_sub_op,
    })
}

/// Recompute a capability's `payload_binding` preimage hash from the actual request:
/// `keccak256(opcode ‖ [sub_op] ‖ request_id ‖ canonical_params)`. The handler compares this to the
/// signed [`VerifiedCapability::payload_binding`] (the last gate before mutation). `canonical_params`
/// is the RFC 8949 canonical CBOR of the per-opcode payload map (built with [`put_uint`] et al.).
pub(crate) fn payload_binding(
    opcode: u8,
    sub_op: Option<u8>,
    request_id: &[u8],
    canonical_params: &[u8],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(2 + request_id.len() + canonical_params.len());
    pre.push(opcode);
    if let Some(s) = sub_op {
        pre.push(s);
    }
    pre.extend_from_slice(request_id);
    pre.extend_from_slice(canonical_params);
    crate::secp256k1::keccak256(&pre)
}

/// Encode a parsed [`Capability`] back to its inner-envelope key-5 CBOR map (keys 1..13).
/// Same gate as its sole caller [`test_signed_capability`] (slice 6-7b): `test` OR the write-path
/// smoke combo `lab-agent-smoke ∧ agent-keygen-exec-preview` — so the read-path lab-bin lane does not
/// compile it as dead code.
#[cfg(any(
    test,
    all(feature = "lab-agent-smoke", feature = "agent-keygen-exec-preview")
))]
fn cap_to_map(c: &Capability) -> Vec<(Value, Value)> {
    let mut m: Vec<(Value, Value)> = vec![
        (
            Value::Integer(1.into()),
            Value::Integer(c.cap_format_version.into()),
        ),
        (
            Value::Integer(2.into()),
            Value::Integer(u64::from(c.command_opcode).into()),
        ),
    ];
    if let Some(sub) = c.treasury_sub_op {
        m.push((
            Value::Integer(3.into()),
            Value::Integer(u64::from(sub).into()),
        ));
    }
    m.push((
        Value::Integer(4.into()),
        Value::Integer(u64::from(c.key_purpose).into()),
    ));
    m.push((Value::Integer(5.into()), Value::Integer(c.chain_id.into())));
    m.push((
        Value::Integer(6.into()),
        Value::Text(c.environment_identifier.clone()),
    ));
    m.push((
        Value::Integer(7.into()),
        Value::Integer(u64::from(c.scope_class).into()),
    ));
    m.push((
        Value::Integer(8.into()),
        Value::Bytes(c.scope_target.clone()),
    ));
    m.push((Value::Integer(9.into()), Value::Integer(c.counter.into())));
    m.push((
        Value::Integer(10.into()),
        Value::Bytes(c.request_id.clone()),
    ));
    m.push((
        Value::Integer(11.into()),
        Value::Bytes(c.payload_binding.to_vec()),
    ));
    m.push((Value::Integer(12.into()), Value::Bool(c.is_recovery)));
    m.push((
        Value::Integer(13.into()),
        Value::Bytes(c.scope_identity.to_vec()),
    ));
    m.push((
        Value::Integer(14.into()),
        Value::Bytes(c.signature.to_vec()),
    ));
    m
}

/// Build a fully-valid signed capability map for tests (other modules' integration tests use this to
/// exercise the wired dispatch seam). `key_purpose` and `payload_binding` are caller-supplied: callers
/// that only exercise the verify-only path may pass placeholders, but the GENERATE_KEYS exec path
/// (`handle_generate_keys`) DOES check both (purpose → 0x42, payload_binding → 0x43 on mismatch), so the
/// 6-7b lab write-path client passes the genuine purpose + the matching `payload_binding`.
///
/// Also reachable under the release-banned `lab-agent-smoke` + `agent-keygen-exec-preview` combo
/// (slice 6-7b): the lab write-path smoke client mints a valid GENERATE_KEYS cap against the smoke
/// keystore's known admin seed through this exact builder, so the smoke's cap and the enclave's
/// verifier are single-sourced. The gate matches that lone consumer (`smoke_generate_keys_envelope`,
/// itself preview-gated) — NOT plain `lab-agent-smoke` — so the read-path lab-bin lane (smoke without
/// preview) does not compile this as dead code.
#[cfg(any(
    test,
    all(feature = "lab-agent-smoke", feature = "agent-keygen-exec-preview")
))]
#[allow(clippy::too_many_arguments)] // a test fixture mirroring the §10.5 capability fields
pub(crate) fn test_signed_capability(
    signing_key: &ed25519_dalek::SigningKey,
    opcode: u8,
    request_id: &[u8],
    counter: u64,
    is_recovery: bool,
    chain_id: u64,
    environment_identifier: &str,
    scope_class: u8,
    scope_target: &[u8],
    key_purpose: u8,
    payload_binding: [u8; 32],
    scope_identity: [u8; 32],
) -> Vec<(Value, Value)> {
    // Default treasury sub-op for opcode 6 = `refill_budget`(1) (admin-tier) — back-compat for the
    // existing callers (none of which exercise sub-ops 0/2/3). Treasury tests that need a specific
    // sub-op call [`test_signed_capability_with_sub_op`] directly.
    let treasury_sub_op = if opcode == OPCODE_CONFIGURE_TREASURY {
        Some(1u8)
    } else {
        None
    };
    test_signed_capability_with_sub_op(
        signing_key,
        opcode,
        treasury_sub_op,
        request_id,
        counter,
        is_recovery,
        chain_id,
        environment_identifier,
        scope_class,
        scope_target,
        key_purpose,
        payload_binding,
        scope_identity,
    )
}

/// As [`test_signed_capability`] but with an explicit `treasury_sub_op` (slice 15-4): treasury tests
/// build caps for sub-ops `0 set_limits` / `2 raise_lifetime_breaker` (admin) and `3 reset_lifetime_breaker`
/// (recovery) — the caller is responsible for pairing `treasury_sub_op` with the right `is_recovery` tier
/// (reset ⇒ recovery; 0..=2 ⇒ admin), exactly as `verify_capability` enforces.
#[cfg(any(
    test,
    all(feature = "lab-agent-smoke", feature = "agent-keygen-exec-preview")
))]
#[allow(clippy::too_many_arguments)] // a test fixture mirroring the §10.5 capability fields
pub(crate) fn test_signed_capability_with_sub_op(
    signing_key: &ed25519_dalek::SigningKey,
    opcode: u8,
    treasury_sub_op: Option<u8>,
    request_id: &[u8],
    counter: u64,
    is_recovery: bool,
    chain_id: u64,
    environment_identifier: &str,
    scope_class: u8,
    scope_target: &[u8],
    key_purpose: u8,
    payload_binding: [u8; 32],
    scope_identity: [u8; 32],
) -> Vec<(Value, Value)> {
    use ed25519_dalek::Signer;
    let mut cap = Capability {
        cap_format_version: CAP_FORMAT_VERSION,
        command_opcode: opcode,
        treasury_sub_op,
        key_purpose,
        chain_id,
        environment_identifier: environment_identifier.to_string(),
        scope_class,
        scope_target: scope_target.to_vec(),
        counter,
        request_id: request_id.to_vec(),
        payload_binding,
        is_recovery,
        scope_identity,
        signature: [0u8; 64],
    };
    cap.signature = signing_key.sign(&signed_preimage(&cap)).to_bytes();
    cap_to_map(&cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{CounterEntry, KeystoreConfig};
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_ENV: &str = "env-prod-0";
    const TEST_CHAIN: u64 = 11565;
    /// Test enclave/fleet scope identities — mirror the genesis/reference fixture sentinels
    /// (`[0xe1;32]` / `[0xf1;32]` in `agent_keystore.rs`). TEST FIXTURES ONLY: a production
    /// provisioning path mints a RANDOM `enclave_scope_id` in-TEE (TASK-25 AC#3/#4) and never
    /// reuses these predictable sentinels. The two are DISTINCT so `scope_class` 0-vs-1 does not
    /// collapse (the 18-2b `KeystoreBody::validate()` distinctness invariant).
    const TEST_ENCLAVE_SCOPE_ID: [u8; 32] = [0xe1; 32];
    const TEST_FLEET_SCOPE_ID: [u8; 32] = [0xf1; 32];

    fn admin_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn recovery_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn test_config() -> KeystoreConfig {
        KeystoreConfig {
            twod_chain_id: TEST_CHAIN,
            environment_identifier: TEST_ENV.to_string(),
            admin_authority_pk: admin_signing_key().verifying_key().to_bytes(),
            recovery_authority_pk: recovery_signing_key().verifying_key().to_bytes(),
            // verify_capability never calls KeystoreBody::validate(), so this field is unused here.
            backup_recovery_wrapping_pubkey: Vec::new(),
            monotonic_treasury_config_version: 1,
            authority_epoch: 0,
            anchor_root: [0u8; 32],
            enclave_scope_id: [0xe1; 32],
            fleet_scope_id: [0xf1; 32],
        }
    }

    /// A capability builder mirroring §10.5; signs with `key` over the canonical preimage.
    struct CapBuilder {
        cap: Capability,
    }
    impl CapBuilder {
        fn new(opcode: u8, request_id: &[u8], counter: u64) -> Self {
            let sub = if opcode == OPCODE_CONFIGURE_TREASURY {
                Some(1u8)
            } else {
                None
            };
            CapBuilder {
                cap: Capability {
                    cap_format_version: CAP_FORMAT_VERSION,
                    command_opcode: opcode,
                    treasury_sub_op: sub,
                    key_purpose: 1,
                    chain_id: TEST_CHAIN,
                    environment_identifier: TEST_ENV.to_string(),
                    scope_class: 0,
                    scope_target: b"generate_transfer".to_vec(),
                    counter,
                    request_id: request_id.to_vec(),
                    payload_binding: [0xab; 32],
                    is_recovery: false,
                    scope_identity: TEST_ENCLAVE_SCOPE_ID,
                    signature: [0u8; 64],
                },
            }
        }

        /// Encode to the inner-envelope key-5 CBOR map, signing keys 1..13 with `key`.
        fn build(mut self, key: &SigningKey) -> Vec<(Value, Value)> {
            let sig = key.sign(&signed_preimage(&self.cap));
            self.cap.signature = sig.to_bytes();
            self.into_map()
        }

        /// Encode without re-signing (for tamper tests — caller sets a bad signature first).
        fn into_map(self) -> Vec<(Value, Value)> {
            super::cap_to_map(&self.cap)
        }
    }

    #[test]
    fn valid_admin_capability_accepted() {
        let cfg = test_config();
        let rid = b"req-1";
        let cap = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        assert_eq!(verify_capability(&cap, 1, rid, &cfg, &[]), Ok(()));
    }

    /// TASK-18 18-2b / AC#1 — the clone-replay guard. A cap minted for enclave A (signed with A's
    /// `enclave_scope_id` in `scope_identity`) is presented against clone B, whose sealed
    /// `enclave_scope_id` DIFFERS and whose counter row for this tuple is EMPTY (so without this guard
    /// `incoming==1` would be accepted at step 6). The 18-2b scope_identity byte-compare (step 5b) must
    /// fire FIRST ⇒ 0x43. This is the core anti-replay test; it MUST be paired with the
    /// `fleet_scoped_cap_binds_to_fleet_id` + `financial_must_be_enclave_scoped` tests (else the suite
    /// gives false confidence — see TASK-18 18-5 carry-in).
    #[test]
    fn enclave_scoped_cap_rejected_on_clone_with_different_enclave_id() {
        // Cap carries A's enclave_scope_id (CapBuilder defaults scope_identity = TEST_ENCLAVE_SCOPE_ID).
        let rid = b"req-clone";
        let cap = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        // Clone B: identical config EXCEPT enclave_scope_id is B's own (distinct, non-zero).
        let mut clone_b = test_config();
        clone_b.enclave_scope_id = [0xe2; 32];
        // Empty counter table ⇒ without the scope guard, highest=0 + incoming=1 ⇒ accepted.
        // The scope_identity byte-compare (cap has [0xe1;32], config has [0xe2;32]) ⇒ 0x43.
        assert_eq!(
            verify_capability(&cap, 1, rid, &clone_b, &[]),
            Err(AgentError::CapabilityRejected),
            "enclave-scoped cap for A must NOT replay on clone B (different enclave_scope_id)",
        );
        // Sanity: the SAME cap against A's config (matching enclave_scope_id) IS accepted.
        assert_eq!(
            verify_capability(&cap, 1, rid, &test_config(), &[]),
            Ok(()),
            "enclave-scoped cap accepted against the matching enclave config",
        );
    }

    /// TASK-18 18-2b — `scope_class` selects which sealed id the cap binds to. A fleet-scoped cap
    /// (scope_class==1) binds to `fleet_scope_id` (shared across one fleet's clones by design), NOT to
    /// `enclave_scope_id`. This documents WHY the enclave byte-compare alone does not protect
    /// fleet-scoped caps — motivating the 18-5 `financial ⇒ scope_class==0` policy that prevents an
    /// attacker from minting a fleet-scoped keygen/treasury cap to bypass the enclave compare.
    #[test]
    fn fleet_scoped_cap_binds_to_fleet_id_not_enclave_id() {
        let cfg = test_config(); // enclave_scope_id=[0xe1;32], fleet_scope_id=[0xf1;32]
        let rid = b"req-fleet";
        // Fleet cap: scope_class=1, scope_identity = fleet_scope_id ⇒ accepted.
        let mut b = CapBuilder::new(1, rid, 1);
        b.cap.scope_class = 1;
        b.cap.scope_identity = TEST_FLEET_SCOPE_ID;
        let fleet_cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&fleet_cap, 1, rid, &cfg, &[]),
            Ok(()),
            "fleet-scoped cap with the matching fleet_scope_id is accepted",
        );
        // A cap that claims scope_class=1 but carries the ENCLAVE id must fail (binds to fleet id).
        let mut b2 = CapBuilder::new(1, rid, 1);
        b2.cap.scope_class = 1;
        b2.cap.scope_identity = TEST_ENCLAVE_SCOPE_ID; // wrong: enclave id, not fleet id
        let wrong = b2.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&wrong, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected),
            "scope_class==1 binds to fleet_scope_id, not enclave_scope_id",
        );
    }

    /// TASK-18 18-3 — `scope_target` well-formedness. The field is a command-class counter-lane label
    /// (NOT a dispatch key — handlers route on `command_opcode` + `key_purpose`), so the verifier fails
    /// closed (0x40, structural) only on a MALFORMED label (empty / non-`[a-z0-9_-]` / over-long), not on
    /// a non-canonical one. The canonical 5 lanes (`generate_transfer` / `generate_faucet` /
    /// `configure_treasury` / `export_backup` / `restore_backup`) are an issuance convention; AC#18
    /// permits the issuer to narrow further (sub-lanes like `golden-scope-generate`), which this guard
    /// must NOT reject. (Replay itself is caught by counter contiguity + signed `scope_identity`, 18-2.)
    #[test]
    fn malformed_scope_target_is_rejected_canonical_and_sublanes_accepted() {
        let cfg = test_config();
        let rid = b"req-1";
        // Canonical lanes accepted.
        for ok in [
            b"generate_transfer".as_slice(),
            b"generate_faucet",
            b"configure_treasury",
            b"export_backup",
            b"restore_backup",
        ] {
            let mut b = CapBuilder::new(1, rid, 1);
            b.cap.scope_target = ok.to_vec();
            assert_eq!(
                verify_capability(&b.build(&admin_signing_key()), 1, rid, &cfg, &[]),
                Ok(()),
                "canonical scope_target {:?} accepted",
                String::from_utf8_lossy(ok),
            );
        }
        // AC#18 sub-lanes (issuer-narrowed) accepted — the guard is NOT a strict whitelist.
        for ok in [
            b"golden-scope-generate".as_slice(),
            b"smoke-c1",
            b"faucet-smoke-f1",
        ] {
            let mut b = CapBuilder::new(1, rid, 1);
            b.cap.scope_target = ok.to_vec();
            assert_eq!(
                verify_capability(&b.build(&admin_signing_key()), 1, rid, &cfg, &[]),
                Ok(()),
                "AC#18 sub-lane {:?} accepted (guard is charset+length, not a strict set)",
                String::from_utf8_lossy(ok),
            );
        }
        // Malformed labels fail closed at decode (0x40) — empty, over-long, non-charset.
        let overlong = vec![b'a'; MAX_SCOPE_TARGET_LEN + 1];
        for bad in [
            b"".as_slice(),
            &overlong,
            b"Generate_Transfer",   // uppercase
            b"generate transfer",   // space
            b"generate.transfer",   // dot
            b"generate_transfer#1", // `#`
            b"\0generate",          // NUL / control
        ] {
            // Drive the malformed label through the FULL production path: sign it (build) then verify.
            // parse_capability runs FIRST in verify_capability_extract_inner (before the Ed25519
            // check), so a malformed label fails closed at decode (0x40) regardless of whether the
            // signature is valid. Below asserts BOTH directions:
            //   (a) VALID signature  — proves a remote issued cap (always signed) still fails at parse;
            //   (b) TAMPERED signature — proves parse precedes the sig check (a reorder that verified
            //       the signature first would surface 0x43 CapabilityRejected for the bad sig here,
            //       NOT 0x40 Malformed; so the tampered assertion pins the order). Together they close
            // the test-vacuity gap a `.into_map()`-only OR valid-sig-only path would leave.
            let mut bld = CapBuilder::new(1, rid, 1);
            bld.cap.scope_target = bad.to_vec();
            let signed = bld.build(&admin_signing_key());
            // (a) valid signature
            assert_eq!(
                verify_capability(&signed, 1, rid, &cfg, &[]),
                Err(AgentError::Malformed),
                "malformed scope_target {:?} rejected as Malformed (0x40) even with a valid signature",
                String::from_utf8_lossy(bad),
            );
            // (b) tampered signature (flip one byte in the signature field, key 14) — must STILL be
            // Malformed (0x40), proving parse_capability ran first; if the order were reversed, this
            // would surface 0x43 (bad signature) and the assertion would fail, catching the regression.
            let mut tampered = signed.clone();
            // Find the signature bytes within the map (key 14) and flip the first one. The map is
            // Vec<(Value,Value)>; locate key 14 (the signature). Track whether we actually mutated it
            // so the test cannot pass through silently if the map shape changes (key 14 absent / not
            // Bytes) — without this guard the tampered variant could equal the signed one and the
            // assertion would prove nothing about the parse-before-sig-check order.
            let mut signature_tampered = false;
            for (k, v) in tampered.iter_mut() {
                if matches!(k, Value::Integer(i) if u64::try_from(*i).ok() == Some(14)) {
                    if let Value::Bytes(bytes) = v {
                        bytes[0] ^= 0xff;
                        signature_tampered = true;
                    }
                    break;
                }
            }
            assert!(signature_tampered, "key 14 (signature) must be present and Bytes for the tampered-sig assertion to be meaningful");
            assert_eq!(
                verify_capability(&tampered, 1, rid, &cfg, &[]),
                Err(AgentError::Malformed),
                "malformed scope_target {:?} with TAMPERED sig is still Malformed (parse precedes sig check)",
                String::from_utf8_lossy(bad),
            );
        }
    }

    /// TASK-18 18-3 — `scope_target` field-independence pin (NOT a runtime dispatch guard). This
    /// test asserts only that the VERIFIED-capability fields a handler routes on (`key_purpose`,
    /// `payload_binding`, `counter`) are structurally independent of `scope_target` — i.e. changing
    /// the lane label does not perturb them. It does NOT mechanically prevent a future handler in
    /// `agent_dispatch.rs` from introducing `match scope_target { ... }`; the no-dispatch contract is
    /// a STATIC, source-level invariant, enforced by review (this test pins field independence so a
    /// future refactor doesn't accidentally thread `scope_target` into a routing field). If a handler
    /// needs a signed discriminator, add a SIGNED cap field (as 18-2a did for `scope_identity`) — do
    /// NOT overload this label. NB: there is currently NO mechanical dispatch-invariance test in
    /// `agent_dispatch.rs` — the no-dispatch contract is enforced by review of handler routing code, not
    /// by a runtime assertion; this verifier-side test covers only field independence.
    #[test]
    fn scope_target_is_independent_of_verified_routing_fields() {
        // Two caps identical except for scope_target both verify and return VerifiedCapability with
        // the SAME routing fields (opcode/purpose/binding/counter) — scope_target carries no routing
        // authority at the verifier boundary, only an opaque counter-tuple key + audit provenance.
        let cfg = test_config();
        let rid = b"req-1";
        let mut a = CapBuilder::new(1, rid, 1);
        a.cap.scope_target = b"generate_transfer".to_vec();
        let mut b_ = CapBuilder::new(1, rid, 1);
        b_.cap.scope_target = b"generate_transfer-v2-pool".to_vec(); // a sub-lane label
        let va = verify_capability_extract(&a.build(&admin_signing_key()), 1, rid, &cfg, &[])
            .expect("cap a verifies");
        let vb = verify_capability_extract(&b_.build(&admin_signing_key()), 1, rid, &cfg, &[])
            .expect("cap b verifies");
        // Routing fields are IDENTICAL regardless of the lane label.
        assert_eq!(va.key_purpose, vb.key_purpose);
        assert_eq!(va.payload_binding, vb.payload_binding);
        assert_eq!(va.counter, vb.counter);
        // Only the opaque lane label (counter-tuple key + audit provenance) differs — by construction.
        assert_ne!(va.scope_target, vb.scope_target);
    }

    #[test]
    fn first_counter_must_be_one() {
        let cfg = test_config();
        let rid = b"req-1";
        // counter 2 with no prior entry (highest=0) ⇒ gap ⇒ rejected.
        let cap = CapBuilder::new(1, rid, 2).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn contiguous_counter_accept_and_replay_reject() {
        let cfg = test_config();
        let rid = b"req-7";
        // NOTE: this CHECKS the contiguity rule against an injected high-water (highest=5). The
        // counter is never ADVANCED in the verify-only slice, so end-to-end "accept then its replay
        // rejected" (§10.10) only becomes exercisable once the advance + re-seal lands.
        let entry = CounterEntry {
            authority: cfg.admin_authority_pk,
            environment_identifier: TEST_ENV.to_string(),
            scope_class: 0,
            scope_target: b"generate_transfer".to_vec(),
            highest_accepted_counter: 5,
        };
        // highest=5 ⇒ accept 6, reject 5 (replay) and 7 (gap).
        let ok = CapBuilder::new(1, rid, 6).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&ok, 1, rid, &cfg, std::slice::from_ref(&entry)),
            Ok(())
        );
        let replay = CapBuilder::new(1, rid, 5).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&replay, 1, rid, &cfg, std::slice::from_ref(&entry)),
            Err(AgentError::CapabilityRejected)
        );
        let gap = CapBuilder::new(1, rid, 7).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&gap, 1, rid, &cfg, std::slice::from_ref(&entry)),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn wrong_authority_rejected() {
        let cfg = test_config();
        let rid = b"req-1";
        // is_recovery=false but signed by the recovery key ⇒ verified vs admin_pk ⇒ fails.
        let cap = CapBuilder::new(1, rid, 1).build(&recovery_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn admin_tier_opcode_rejects_recovery_flag() {
        // GENERATE_KEYS(1) is admin-tier; a cap with is_recovery=true is a tier mismatch and is
        // rejected even when correctly signed by the recovery key.
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(1, rid, 1);
        b.cap.is_recovery = true;
        let cap = b.build(&recovery_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn restore_backup_requires_recovery_tier() {
        // RESTORE_BACKUP(8) is recovery-tier; is_recovery=false is a tier mismatch, rejected even
        // when correctly signed by the admin key (an admin authority cannot authorize a restore).
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(8, rid, 1);
        b.cap.is_recovery = false;
        b.cap.scope_target = b"restore_backup".to_vec();
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 8, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn export_backup_is_admin_tier() {
        let cfg = test_config();
        let rid = b"req-1";
        // EXPORT_BACKUP(7) admin-tier: admin accepted...
        let mut ok = CapBuilder::new(7, rid, 1);
        ok.cap.scope_target = b"export_backup".to_vec();
        assert_eq!(
            verify_capability(&ok.build(&admin_signing_key()), 7, rid, &cfg, &[]),
            Ok(())
        );
        // ...recovery flag rejected (tier mismatch).
        let mut bad = CapBuilder::new(7, rid, 1);
        bad.cap.is_recovery = true;
        bad.cap.scope_target = b"export_backup".to_vec();
        assert_eq!(
            verify_capability(&bad.build(&recovery_signing_key()), 7, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn recovery_flag_selects_recovery_authority() {
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(8, rid, 1); // RESTORE_BACKUP, recovery tier
        b.cap.is_recovery = true;
        b.cap.scope_target = b"restore_backup".to_vec();
        let cap = b.build(&recovery_signing_key());
        assert_eq!(verify_capability(&cap, 8, rid, &cfg, &[]), Ok(()));
    }

    #[test]
    fn tampered_signature_rejected() {
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(1, rid, 1);
        b.cap.signature = [0u8; 64]; // invalid sig, not re-signed
        let cap = b.into_map();
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let cfg = test_config();
        let rid = b"req-1";
        // Sign a valid cap, then mutate a signed field post-signing ⇒ preimage no longer matches ⇒
        // reject.
        let mut b = CapBuilder::new(1, rid, 1);
        let sig = admin_signing_key().sign(&signed_preimage(&b.cap));
        b.cap.signature = sig.to_bytes();
        b.cap.scope_target = b"generate_faucet".to_vec(); // changed AFTER signing
        let cap = b.into_map();
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn opcode_mismatch_rejected() {
        let cfg = test_config();
        let rid = b"req-1";
        // cap authorizes opcode 1, request is opcode 7.
        let cap = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 7, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn request_id_mismatch_rejected() {
        let cfg = test_config();
        let cap = CapBuilder::new(1, b"req-A", 1).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, b"req-B", &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn chain_and_env_mismatch_rejected() {
        let rid = b"req-1";
        let mut cfg = test_config();
        cfg.twod_chain_id = 99; // sealed chain differs from cap's 11565
        let cap = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );

        let mut cfg2 = test_config();
        cfg2.environment_identifier = "other-env".to_string();
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg2, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn unknown_format_version_is_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(1, rid, 1);
        // v2 is current (18-2a); an unknown FUTURE version (3) must fail closed as Malformed.
        b.cap.cap_format_version = 3;
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn structural_errors_are_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        // Missing required key 11 (payload_binding).
        let mut cap = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        cap.retain(|(k, _)| !matches!(k, Value::Integer(i) if u64::try_from(*i).ok() == Some(11)));
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );

        // Duplicate key 9.
        let mut cap2 = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        cap2.push((Value::Integer(9.into()), Value::Integer(1.into())));
        assert_eq!(
            verify_capability(&cap2, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );

        // Unknown key 14.
        let mut cap3 = CapBuilder::new(1, rid, 1).build(&admin_signing_key());
        cap3.push((Value::Integer(14.into()), Value::Integer(0.into())));
        assert_eq!(
            verify_capability(&cap3, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn treasury_sub_op_presence_rule_enforced() {
        let cfg = test_config();
        let rid = b"req-1";
        // Non-treasury opcode carrying a sub-op (key 3) ⇒ malformed.
        let mut b = CapBuilder::new(1, rid, 1);
        b.cap.treasury_sub_op = Some(1);
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );

        // Treasury opcode (6) missing its sub-op ⇒ malformed.
        let mut b2 = CapBuilder::new(6, rid, 1);
        b2.cap.treasury_sub_op = None;
        let cap2 = b2.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap2, 6, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn canonical_preimage_is_deterministic_and_excludes_signature() {
        // Two builds of the same cap produce identical preimages; key 14 (the signature) is not in the
        // preimage. Key 13 (scope_identity, 18-2a) IS signed.
        let a = CapBuilder::new(1, b"req-1", 1).cap;
        let b = CapBuilder::new(1, b"req-1", 1).cap;
        let pa = signed_preimage(&a);
        let pb = signed_preimage(&b);
        assert_eq!(pa, pb);
        assert!(pa.starts_with(CAP_DOMAIN));
        // map header for 12 entries (no sub-op) = 0xA0 | 12 = 0xAC, right after the domain.
        assert_eq!(pa[CAP_DOMAIN.len()], 0xAC);
    }

    #[test]
    fn counter_overflow_rejected() {
        let cfg = test_config();
        let rid = b"req-1";
        let entry = CounterEntry {
            authority: cfg.admin_authority_pk,
            environment_identifier: TEST_ENV.to_string(),
            scope_class: 0,
            scope_target: b"generate_transfer".to_vec(),
            highest_accepted_counter: u64::MAX,
        };
        // highest == u64::MAX ⇒ expected = MAX+1 overflows ⇒ reject (no wrap to 0).
        let cap = CapBuilder::new(1, rid, u64::MAX).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, std::slice::from_ref(&entry)),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn recovery_cap_signed_by_admin_rejected() {
        let cfg = test_config();
        let rid = b"req-1";
        // is_recovery=true ⇒ verified vs recovery_pk; signed by the ADMIN key ⇒ fails. (The other
        // direction of the cross-authority check — guards against an inverted authority selector.)
        let mut b = CapBuilder::new(8, rid, 1);
        b.cap.is_recovery = true;
        b.cap.scope_target = b"restore_backup".to_vec();
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 8, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    #[test]
    fn is_recovery_wrong_cbor_type_is_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        // is_recovery encoded as Integer 0 instead of Bool ⇒ structural type error (0x40), so it can
        // never silently route to the wrong authority.
        let cap: Vec<(Value, Value)> = CapBuilder::new(1, rid, 1)
            .build(&admin_signing_key())
            .into_iter()
            .map(|(k, v)| {
                if matches!(&k, Value::Integer(i) if u64::try_from(*i).ok() == Some(12)) {
                    (k, Value::Integer(0.into()))
                } else {
                    (k, v)
                }
            })
            .collect();
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn scope_mismatch_misses_counter_stream() {
        let cfg = test_config();
        let rid = b"req-1";
        let entry = CounterEntry {
            authority: cfg.admin_authority_pk,
            environment_identifier: TEST_ENV.to_string(),
            scope_class: 0,
            scope_target: b"generate_transfer".to_vec(),
            highest_accepted_counter: 5,
        };
        // A different scope_target is a different tuple ⇒ highest=0 ⇒ counter 6 is a gap (reject),
        // counter 1 is the fresh stream's first (accept). Proves the tuple keys on scope_target.
        let mut gap = CapBuilder::new(1, rid, 6);
        gap.cap.scope_target = b"generate_faucet".to_vec();
        assert_eq!(
            verify_capability(
                &gap.build(&admin_signing_key()),
                1,
                rid,
                &cfg,
                std::slice::from_ref(&entry)
            ),
            Err(AgentError::CapabilityRejected)
        );
        let mut fresh = CapBuilder::new(1, rid, 1);
        fresh.cap.scope_target = b"generate_faucet".to_vec();
        assert_eq!(
            verify_capability(
                &fresh.build(&admin_signing_key()),
                1,
                rid,
                &cfg,
                std::slice::from_ref(&entry)
            ),
            Ok(())
        );
    }

    #[test]
    fn scope_class_out_of_range_is_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(1, rid, 1);
        b.cap.scope_class = 2; // only {0,1} are valid
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn nonprivileged_opcode_capability_is_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        // opcode 2 (PUBLIC_IDENTITY, a read) is not in the privileged set ⇒ parse rejects.
        let cap = CapBuilder::new(2, rid, 1).build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 2, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn invalid_environment_identifier_is_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(1, rid, 1);
        b.cap.environment_identifier = "Bad_Env".to_string(); // uppercase + underscore: not [a-z0-9-]
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 1, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn valid_treasury_capability_accepted_with_13_entry_preimage() {
        let cfg = test_config();
        let rid = b"req-1";
        let b = CapBuilder::new(6, rid, 1); // CONFIGURE_TREASURY ⇒ sub_op present (13-entry preimage)
                                            // 13 entries ⇒ map header 0xA0 | 13 = 0xAD right after the domain.
        let pre = signed_preimage(&b.cap);
        assert_eq!(pre[CAP_DOMAIN.len()], 0xAD);
        let cap = b.build(&admin_signing_key());
        assert_eq!(verify_capability(&cap, 6, rid, &cfg, &[]), Ok(()));
    }

    #[test]
    fn treasury_sub_op_out_of_range_is_malformed() {
        let cfg = test_config();
        let rid = b"req-1";
        let mut b = CapBuilder::new(6, rid, 1);
        b.cap.treasury_sub_op = Some(4); // §10.3 pins sub-op ∈ {0..=3}
        let cap = b.build(&admin_signing_key());
        assert_eq!(
            verify_capability(&cap, 6, rid, &cfg, &[]),
            Err(AgentError::Malformed)
        );
    }

    #[test]
    fn reset_lifetime_breaker_requires_recovery_tier() {
        let cfg = test_config();
        let rid = b"req-1";
        // sub_op 3 (reset_lifetime_breaker) is recovery-tier: admin flag rejected...
        let mut admin_tier = CapBuilder::new(6, rid, 1);
        admin_tier.cap.treasury_sub_op = Some(3);
        admin_tier.cap.is_recovery = false;
        assert_eq!(
            verify_capability(&admin_tier.build(&admin_signing_key()), 6, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
        // ...recovery flag (signed by recovery key) accepted.
        let mut rec = CapBuilder::new(6, rid, 1);
        rec.cap.treasury_sub_op = Some(3);
        rec.cap.is_recovery = true;
        assert_eq!(
            verify_capability(&rec.build(&recovery_signing_key()), 6, rid, &cfg, &[]),
            Ok(())
        );
    }

    #[test]
    fn admin_treasury_sub_op_rejects_recovery_flag() {
        let cfg = test_config();
        let rid = b"req-1";
        // sub_op 0 (set_limits) is admin-tier; is_recovery=true ⇒ tier mismatch ⇒ 0x43.
        let mut b = CapBuilder::new(6, rid, 1);
        b.cap.treasury_sub_op = Some(0);
        b.cap.is_recovery = true;
        assert_eq!(
            verify_capability(&b.build(&recovery_signing_key()), 6, rid, &cfg, &[]),
            Err(AgentError::CapabilityRejected)
        );
    }

    /// TASK-22 — byte-exact §10.5 CAPABILITY golden vectors (AC#2).
    ///
    /// Freezes, for the cap-bearing opcodes, the Ed25519-signed PREIMAGE (`CAP_DOMAIN ‖
    /// canonical-CBOR(keys 1..13)`) AND the full capability map (keys 1..14, incl. the signature at key 14), plus the
    /// `payload_binding` derivation (`keccak256(opcode ‖ [sub_op] ‖ request_id ‖ canonical-CBOR(params))`).
    /// These pin the two facts most likely to drift an external (2d Elixir) reimplementer: the **12-vs-13
    /// entry preimage header** (`0xAC` no-sub_op vs `0xAD` CONFIGURE; 18-2a added the signed `scope_identity`
    /// key 13) and the **sub_op byte folded into the binding**. Each is byte-exact vs the committed `.bin` AND the full map is ACCEPTED by the real
    /// `verify_capability` against `test_config()` (so a signer/encoder drift breaks CI). Ed25519 (RFC 8032)
    /// is deterministic, so the signed bytes are reproducible. **TEST KEYS ONLY** — admin Ed25519 `[7;32]`,
    /// recovery `[9;32]`; env `env-prod-0`, chain 11565 (the agent_capability test fixtures).
    mod golden_capability_vectors {
        use super::*;
        use sha2::{Digest, Sha256};

        const SCOPE_GENERATE: &[u8] = b"golden-scope-generate";
        const SCOPE_CONFIGURE: &[u8] = b"golden-scope-configure";
        const RID_GENERATE: &[u8] = b"0x40-golden:cap:generate-keys:v1";
        const RID_SET_LIMITS: &[u8] = b"0x40-golden:cap:configure-set-limits:v1";
        const RID_RESET: &[u8] = b"0x40-golden:cap:configure-reset:v1";

        fn hx(b: &[u8]) -> String {
            hex::encode(b)
        }
        fn min_be(x: u64) -> Vec<u8> {
            let b = x.to_be_bytes();
            let i = b.iter().position(|&y| y != 0).unwrap_or(b.len());
            b[i..].to_vec()
        }
        fn enc(map: &[(Value, Value)]) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&Value::Map(map.to_vec()), &mut buf)
                .expect("cap map encodes");
            buf
        }

        /// Build a golden cap → (signed preimage, full-map CBOR bytes, the map). Constructs the Capability
        /// directly so BOTH the preimage (keys 1..13) and the signed full map (keys 1..14) come from ONE cap.
        #[allow(clippy::too_many_arguments)]
        fn build_cap(
            key: &SigningKey,
            opcode: u8,
            sub_op: Option<u8>,
            key_purpose: u8,
            scope_target: &[u8],
            counter: u64,
            request_id: &[u8],
            payload_binding: [u8; 32],
            is_recovery: bool,
            scope_identity: [u8; 32],
        ) -> (Vec<u8>, Vec<u8>, Vec<(Value, Value)>) {
            let mut cap = Capability {
                cap_format_version: CAP_FORMAT_VERSION,
                command_opcode: opcode,
                treasury_sub_op: sub_op,
                key_purpose,
                chain_id: TEST_CHAIN,
                environment_identifier: TEST_ENV.to_string(),
                scope_class: 0,
                scope_target: scope_target.to_vec(),
                counter,
                request_id: request_id.to_vec(),
                payload_binding,
                is_recovery,
                scope_identity,
                signature: [0u8; 64],
            };
            let preimage = signed_preimage(&cap);
            cap.signature = key.sign(&preimage).to_bytes();
            let map = cap_to_map(&cap);
            let full = enc(&map);
            (preimage, full, map)
        }

        // The two payload_bindings (also embedded in the caps so the vectors are internally consistent).
        fn pb_generate() -> [u8; 32] {
            payload_binding(
                1,
                None,
                RID_GENERATE,
                &crate::agent_dispatch::generate_keys_canonical_params(1, 1),
            )
        }
        fn pb_set_limits() -> [u8; 32] {
            payload_binding(
                6,
                Some(0),
                RID_SET_LIMITS,
                &crate::agent_dispatch::configure_treasury_canonical_params(
                    0,
                    &min_be(1_000_000),
                    Some((21_000, 1_000_000_000)),
                ),
            )
        }
        fn pb_reset() -> [u8; 32] {
            payload_binding(
                6,
                Some(3),
                RID_RESET,
                &crate::agent_dispatch::configure_treasury_canonical_params(3, &min_be(500), None),
            )
        }

        /// The standalone `payload_binding_*.bin` vectors, FULLY self-describing so a consumer can
        /// RECOMPUTE `keccak256(opcode ‖ [sub_op] ‖ request_id ‖ canonical_params)` end-to-end (the binding
        /// is otherwise just a 32-byte hash with no recoverable inputs). Returns
        /// (file, opcode, sub_op, request_id, canonical_params bytes, binding). The binding value reuses
        /// `pb_generate`/`pb_set_limits` so it can't drift from the caps that embed it.
        fn payload_binding_entries() -> Vec<(
            &'static str,
            u8,
            Option<u8>,
            &'static [u8],
            Vec<u8>,
            [u8; 32],
        )> {
            let gen_params = crate::agent_dispatch::generate_keys_canonical_params(1, 1);
            let set_params = crate::agent_dispatch::configure_treasury_canonical_params(
                0,
                &min_be(1_000_000),
                Some((21_000, 1_000_000_000)),
            );
            vec![
                (
                    "payload_binding_generate_keys_v1.bin",
                    1,
                    None,
                    RID_GENERATE,
                    gen_params,
                    pb_generate(),
                ),
                (
                    "payload_binding_configure_set_limits_v1.bin",
                    6,
                    Some(0),
                    RID_SET_LIMITS,
                    set_params,
                    pb_set_limits(),
                ),
            ]
        }

        /// (name, preimage, full-map bytes, opcode, sub_op, is_recovery, request_id, expected header byte).
        fn caps() -> Vec<(
            &'static str,
            Vec<u8>,
            Vec<u8>,
            u8,
            Option<u8>,
            bool,
            &'static [u8],
            u8,
        )> {
            let admin = SigningKey::from_bytes(&[7u8; 32]);
            let recovery = SigningKey::from_bytes(&[9u8; 32]);
            let (p_g, f_g, _) = build_cap(
                &admin,
                1,
                None,
                1,
                SCOPE_GENERATE,
                1,
                RID_GENERATE,
                pb_generate(),
                false,
                TEST_ENCLAVE_SCOPE_ID,
            );
            let (p_s, f_s, _) = build_cap(
                &admin,
                6,
                Some(0),
                2,
                SCOPE_CONFIGURE,
                1,
                RID_SET_LIMITS,
                pb_set_limits(),
                false,
                TEST_ENCLAVE_SCOPE_ID,
            );
            let (p_r, f_r, _) = build_cap(
                &recovery,
                6,
                Some(3),
                2,
                SCOPE_CONFIGURE,
                1,
                RID_RESET,
                pb_reset(),
                true,
                TEST_ENCLAVE_SCOPE_ID,
            );
            vec![
                (
                    "generate_keys",
                    p_g,
                    f_g,
                    1,
                    None,
                    false,
                    RID_GENERATE,
                    0xAC,
                ),
                (
                    "configure_reset",
                    p_r,
                    f_r,
                    6,
                    Some(3),
                    true,
                    RID_RESET,
                    0xAD,
                ),
                (
                    "configure_set_limits",
                    p_s,
                    f_s,
                    6,
                    Some(0),
                    false,
                    RID_SET_LIMITS,
                    0xAD,
                ),
            ]
        }

        #[test]
        fn cap_vectors_are_byte_exact() {
            let pre: &[(&str, &[u8])] = &[
                (
                    "generate_keys",
                    include_bytes!(
                        "../testvectors/agent-gateway/cap_preimage_generate_keys_v1.bin"
                    ),
                ),
                (
                    "configure_reset",
                    include_bytes!(
                        "../testvectors/agent-gateway/cap_preimage_configure_reset_v1.bin"
                    ),
                ),
                (
                    "configure_set_limits",
                    include_bytes!(
                        "../testvectors/agent-gateway/cap_preimage_configure_set_limits_v1.bin"
                    ),
                ),
            ];
            let full: &[(&str, &[u8])] = &[
                (
                    "generate_keys",
                    include_bytes!("../testvectors/agent-gateway/cap_full_generate_keys_v1.bin"),
                ),
                (
                    "configure_reset",
                    include_bytes!("../testvectors/agent-gateway/cap_full_configure_reset_v1.bin"),
                ),
                (
                    "configure_set_limits",
                    include_bytes!(
                        "../testvectors/agent-gateway/cap_full_configure_set_limits_v1.bin"
                    ),
                ),
            ];
            for (name, preimage, fullmap, ..) in caps() {
                let p = pre.iter().find(|(n, _)| *n == name).unwrap().1;
                let f = full.iter().find(|(n, _)| *n == name).unwrap().1;
                assert_eq!(
                    preimage.as_slice(),
                    p,
                    "cap {name} preimage drifted; regen + re-mint .json"
                );
                assert_eq!(
                    fullmap.as_slice(),
                    f,
                    "cap {name} full-map drifted; regen + re-mint .json"
                );
            }
            // payload_binding derivation vectors (32-byte keccak outputs).
            assert_eq!(
                pb_generate().as_slice(),
                include_bytes!("../testvectors/agent-gateway/payload_binding_generate_keys_v1.bin"),
                "pb generate_keys drifted"
            );
            assert_eq!(
                pb_set_limits().as_slice(),
                include_bytes!(
                    "../testvectors/agent-gateway/payload_binding_configure_set_limits_v1.bin"
                ),
                "pb configure_set_limits drifted"
            );
        }

        #[test]
        fn cap_preimages_have_domain_and_canonical_header() {
            // CAP_DOMAIN prefix + the map-header byte that distinguishes the 12-entry (no sub_op) preimage
            // from the 13-entry CONFIGURE preimage — the asymmetry an external reimplementer is most likely
            // to get wrong.
            for (name, preimage, _full, _op, _sub, _rec, _rid, header) in caps() {
                assert!(
                    preimage.starts_with(CAP_DOMAIN),
                    "cap {name} preimage missing CAP_DOMAIN prefix"
                );
                assert_eq!(
                    preimage[CAP_DOMAIN.len()],
                    header,
                    "cap {name} preimage map-header byte"
                );
            }
        }

        #[test]
        fn cap_full_maps_are_accepted_by_the_real_verifier() {
            // The strongest coupling: each frozen full map is ACCEPTED by the live `verify_capability`
            // against `test_config()` with an empty counter table (counter 1 == highest 0 + 1). A signer /
            // canonical-encoder / authority-tier drift would make the real verifier REJECT and break CI.
            for (name, _preimage, fullmap, opcode, _sub, _rec, request_id, _h) in caps() {
                let map = match ciborium::de::from_reader::<Value, _>(fullmap.as_slice()).unwrap() {
                    Value::Map(m) => m,
                    _ => panic!("cap {name} full map is not a CBOR map"),
                };
                assert_eq!(
                    verify_capability(&map, opcode, request_id, &test_config(), &[]),
                    Ok(()),
                    "cap {name} must be accepted by the real verifier"
                );
            }
        }

        #[test]
        fn admin_and_recovery_lanes_accept_counter_1_independently() {
            // The §10.6 counter lanes are keyed by (authority, env, scope_class, scope_target) and are
            // INDEPENDENT: a counter-1 cap on one authority's lane is accepted even when the OTHER lane is
            // already populated (highest 1). Drives the live `verify_capability` with a non-empty counter
            // table to exercise that (the byte-exact acceptance test above only uses an empty table).
            let admin = SigningKey::from_bytes(&[7u8; 32]);
            let recovery = SigningKey::from_bytes(&[9u8; 32]);
            let lane = |authority: [u8; 32], scope: &[u8]| CounterEntry {
                authority,
                environment_identifier: TEST_ENV.to_string(),
                scope_class: 0,
                scope_target: scope.to_vec(),
                highest_accepted_counter: 1,
            };
            // Isolate the AUTHORITY dimension: the populated "other lane" shares the SAME
            // env/scope_class/scope_target as the cap under test and differs ONLY in authority. So the
            // cap's counter 1 is accepted iff `authority` is part of the lane key — a verifier that keyed
            // by (env, scope_class, scope_target) but ignored authority would see that scope already at
            // highest 1, expect 2, and REJECT counter 1 (this test would then fail, catching the regression).
            // Admin GENERATE_KEYS counter 1, with a RECOVERY lane on the SAME scope already at highest 1.
            let (_p, _f, admin_map) = build_cap(
                &admin,
                1,
                None,
                1,
                SCOPE_GENERATE,
                1,
                RID_GENERATE,
                pb_generate(),
                false,
                TEST_ENCLAVE_SCOPE_ID,
            );
            let recovery_same_scope = lane(recovery.verifying_key().to_bytes(), SCOPE_GENERATE);
            assert_eq!(
                verify_capability(&admin_map, 1, RID_GENERATE, &test_config(), std::slice::from_ref(&recovery_same_scope)),
                Ok(()),
                "admin counter 1 accepted despite a recovery lane on the SAME scope (authority is in the lane key)",
            );
            // Symmetric: recovery RESET counter 1, with an ADMIN lane on the SAME scope already at highest 1.
            let (_p2, _f2, reset_map) = build_cap(
                &recovery,
                6,
                Some(3),
                2,
                SCOPE_CONFIGURE,
                1,
                RID_RESET,
                pb_reset(),
                true,
                TEST_ENCLAVE_SCOPE_ID,
            );
            let admin_same_scope = lane(admin.verifying_key().to_bytes(), SCOPE_CONFIGURE);
            assert_eq!(
                verify_capability(&reset_map, 6, RID_RESET, &test_config(), std::slice::from_ref(&admin_same_scope)),
                Ok(()),
                "recovery counter 1 accepted despite an admin lane on the SAME scope (authority is in the lane key)",
            );
        }

        #[test]
        fn payload_binding_sub_op_asymmetry() {
            // GENERATE_KEYS binds keccak256(opcode ‖ request_id ‖ params) — NO sub_op byte; CONFIGURE folds
            // the sub_op as the 2nd preimage byte. Pin that the two derivations differ in that one byte by
            // recomputing with/without and asserting they diverge (a reimplementer that omitted the sub_op
            // byte would collide the two).
            let with_sub = payload_binding(6, Some(0), RID_SET_LIMITS, b"params");
            let without_sub = payload_binding(6, None, RID_SET_LIMITS, b"params");
            assert_ne!(
                with_sub, without_sub,
                "sub_op byte must change the payload_binding"
            );
        }

        #[test]
        fn cap_vector_sidecar_matches() {
            let sidecar = include_str!("../testvectors/agent-gateway/capability_vectors_v1.json");
            let v: serde_json::Value =
                serde_json::from_str(sidecar).expect("capability index is valid JSON");
            assert_eq!(
                v["cap_domain_hex"].as_str(),
                Some(hx(CAP_DOMAIN).as_str()),
                "index cap_domain"
            );
            assert_eq!(
                v["environment_identifier"].as_str(),
                Some(TEST_ENV),
                "index env"
            );
            assert_eq!(v["chain_id"].as_u64(), Some(TEST_CHAIN), "index chain_id");
            assert_eq!(
                v["caps"].as_object().map(|o| o.len()),
                Some(caps().len()),
                "index has a stale/extra cap entry"
            );
            for (name, preimage, fullmap, opcode, sub, is_recovery, request_id, header) in caps() {
                let e = &v["caps"][name];
                assert_eq!(e["opcode"].as_u64(), Some(opcode as u64), "{name} opcode");
                assert_eq!(
                    e["treasury_sub_op"].as_u64(),
                    sub.map(u64::from),
                    "{name} sub_op"
                );
                assert_eq!(
                    e["is_recovery"].as_bool(),
                    Some(is_recovery),
                    "{name} is_recovery"
                );
                assert_eq!(
                    e["request_id_hex"].as_str(),
                    Some(hx(request_id).as_str()),
                    "{name} request_id"
                );
                assert_eq!(
                    e["preimage_header_byte"].as_u64(),
                    Some(header as u64),
                    "{name} header"
                );
                assert_eq!(
                    e["preimage_sha256"].as_str(),
                    Some(hx(&Sha256::digest(&preimage)).as_str()),
                    "{name} pre sha"
                );
                assert_eq!(
                    e["preimage_len_bytes"].as_u64(),
                    Some(preimage.len() as u64),
                    "{name} pre len"
                );
                assert_eq!(
                    e["preimage_hex"].as_str(),
                    Some(hx(&preimage).as_str()),
                    "{name} pre hex"
                );
                assert_eq!(
                    e["full_map_sha256"].as_str(),
                    Some(hx(&Sha256::digest(&fullmap)).as_str()),
                    "{name} full sha"
                );
                assert_eq!(
                    e["full_map_len_bytes"].as_u64(),
                    Some(fullmap.len() as u64),
                    "{name} full len"
                );
                assert_eq!(
                    e["full_map_hex"].as_str(),
                    Some(hx(&fullmap).as_str()),
                    "{name} full hex"
                );
            }
            // payload_binding index: each entry carries the full recompute inputs (canonical_params_hex)
            // so a consumer can reproduce the keccak — and we self-check that the indexed params DO produce
            // the indexed binding (no stale/uncomputable hash).
            assert_eq!(
                v["payload_bindings"].as_object().map(|o| o.len()),
                Some(payload_binding_entries().len()),
                "stale/extra payload_binding entry",
            );
            for (name, opcode, sub_op, request_id, canonical_params, binding) in
                payload_binding_entries()
            {
                assert_eq!(
                    payload_binding(opcode, sub_op, request_id, &canonical_params),
                    binding,
                    "{name}: indexed canonical_params must recompute the indexed binding",
                );
                let pe = &v["payload_bindings"][name];
                assert_eq!(
                    pe["opcode"].as_u64(),
                    Some(opcode as u64),
                    "{name} pb opcode"
                );
                assert_eq!(
                    pe["treasury_sub_op"].as_u64(),
                    sub_op.map(u64::from),
                    "{name} pb sub_op"
                );
                assert_eq!(
                    pe["request_id_hex"].as_str(),
                    Some(hx(request_id).as_str()),
                    "{name} pb request_id"
                );
                assert_eq!(
                    pe["canonical_params_hex"].as_str(),
                    Some(hx(&canonical_params).as_str()),
                    "{name} pb params"
                );
                assert_eq!(
                    pe["binding_hex"].as_str(),
                    Some(hx(&binding).as_str()),
                    "{name} pb binding"
                );
            }
        }

        /// REGEN (manual): `cargo test --features agent-gateway golden_capability_vectors::regen_golden_capability_vectors -- --ignored --nocapture`,
        /// then commit the `.bin`s + the re-minted `capability_vectors_v1.json`.
        #[test]
        #[ignore]
        fn regen_golden_capability_vectors() {
            let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testvectors/agent-gateway/");
            let write = |name: &str, bytes: &[u8]| {
                std::fs::write(format!("{dir}{name}"), bytes).expect("write .bin")
            };
            let mut index = serde_json::Map::new();
            for (name, preimage, fullmap, opcode, sub, is_recovery, request_id, header) in caps() {
                write(&format!("cap_preimage_{name}_v1.bin"), &preimage);
                write(&format!("cap_full_{name}_v1.bin"), &fullmap);
                // Alphabetical insertion → stable .json bytes regardless of serde_json map impl.
                let mut e = serde_json::Map::new();
                e.insert("full_map_hex".into(), hx(&fullmap).into());
                e.insert("full_map_len_bytes".into(), (fullmap.len() as u64).into());
                e.insert(
                    "full_map_sha256".into(),
                    hx(&Sha256::digest(&fullmap)).into(),
                );
                e.insert("is_recovery".into(), is_recovery.into());
                e.insert("opcode".into(), (opcode as u64).into());
                e.insert("preimage_header_byte".into(), (header as u64).into());
                e.insert("preimage_hex".into(), hx(&preimage).into());
                e.insert("preimage_len_bytes".into(), (preimage.len() as u64).into());
                e.insert(
                    "preimage_sha256".into(),
                    hx(&Sha256::digest(&preimage)).into(),
                );
                e.insert("request_id_hex".into(), hx(request_id).into());
                e.insert(
                    "treasury_sub_op".into(),
                    sub.map(|s| serde_json::Value::from(s as u64))
                        .unwrap_or(serde_json::Value::Null),
                );
                index.insert(name.into(), serde_json::Value::Object(e));
            }
            let _ = pb_reset(); // reset binding is embedded in the reset cap; not frozen standalone
                                // payload_binding vectors + a SELF-DESCRIBING index (opcode/sub_op/request_id/canonical_params/
                                // binding) so a consumer can recompute the keccak without reading the Rust source.
            let mut pb_index = serde_json::Map::new();
            for (name, opcode, sub_op, request_id, canonical_params, binding) in
                payload_binding_entries()
            {
                write(name, &binding);
                let mut e = serde_json::Map::new();
                e.insert("binding_hex".into(), hx(&binding).into());
                e.insert("canonical_params_hex".into(), hx(&canonical_params).into());
                e.insert("opcode".into(), (opcode as u64).into());
                e.insert("request_id_hex".into(), hx(request_id).into());
                e.insert(
                    "treasury_sub_op".into(),
                    sub_op
                        .map(|s| serde_json::Value::from(s as u64))
                        .unwrap_or(serde_json::Value::Null),
                );
                pb_index.insert(name.into(), serde_json::Value::Object(e));
            }
            let doc = serde_json::json!({
                "_comment": "TASK-22 AC#2 — byte-exact §10.5 capability golden vectors (cap_format_version 2, TASK-18 18-2a). preimage = CAP_DOMAIN || canonical-CBOR(keys 1..13); full map = keys 1..14 (incl. Ed25519 signature at key 14; key 13 = scope_identity). Each full map is ACCEPTED by the live verify_capability against the test config. payload_binding = keccak256(opcode || [sub_op] || request_id || canonical_params) — the payload_bindings entries carry canonical_params_hex so it is recomputable. TEST KEYS ONLY (admin [7;32], recovery [9;32]); environment_identifier 'env-prod-0' is a TEST value, NOT a production environment.",
                "_versioning_note": "THREE distinct version counters, do not conflate: (1) cap_format_version = 2 (cap key 1, the WIRE-FORMAT authority — 18-2a bumped 1→2 adding signed scope_identity at key 13, signature moved 13→14); (2) CAP_DOMAIN label = '2d-hsm/agent-cap/v1' (the Ed25519 domain-separation PREFIX, intentionally NOT bumped — it pins the signing domain, not the format; the format version lives in cap key 1); (3) the FILENAME suffix _v1 = the agent-gateway ENVELOPE/TESTVECTOR-SCHEMA version (retained to avoid churning include_bytes! paths, same precedent as agent_keystore_genesis_v2). A v1-shaped cap (no scope_identity, signature at key 13) FAILS CLOSED at the cap_format_version check.",
                "cap_format_version": CAP_FORMAT_VERSION,
                "cap_domain_hex": hx(CAP_DOMAIN),
                "environment_identifier": TEST_ENV,
                "chain_id": TEST_CHAIN,
                "caps": serde_json::Value::Object(index),
                "payload_bindings": serde_json::Value::Object(pb_index),
            });
            std::fs::write(
                format!("{dir}capability_vectors_v1.json"),
                serde_json::to_string_pretty(&doc).unwrap() + "\n",
            )
            .expect("write capability index");
            eprintln!(
                "wrote 6 cap vectors + 2 payload_binding + capability_vectors_v1.json -> {dir}"
            );
        }
    }
}
