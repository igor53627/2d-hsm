//! Agent Gateway administrative / recovery **capability verification** (vsock spec §10.5/§10.6).
//!
//! A capability is the TEE-verified, signed, parameter-binding token carried at inner-envelope key
//! `5` for the privileged opcodes `{GENERATE_KEYS(1), CONFIGURE_TREASURY(6), EXPORT_BACKUP(7),
//! RESTORE_BACKUP(8)}`. Host-side Vault/OPA authorization is **never** sufficient (AC#6); the enclave
//! independently verifies an Ed25519 signature against a **sealed** trust root.
//!
//! ## What this slice implements (verify-only)
//! [`verify_capability`] performs the read-only half of the §10.5 verify order:
//! 1. strict structural decode of the capability map (keys `1..=13`, no unknown/dup, required keys
//!    present, key `3` present iff `command_opcode == 6`) — any shape error ⇒ `0x40 MALFORMED`;
//! 2. `cap_format_version == 1` (unknown version ⇒ `0x40`);
//! 3. **Ed25519 verify** of key `13` over `"2d-hsm/agent-cap/v1\0" ‖ canonical-CBOR({1..12})`
//!    against the `is_recovery`-selected sealed authority (`admin_authority_pk` /
//!    `recovery_authority_pk`);
//! 4. `command_opcode == request.opcode` and `request_id(key 10) == envelope.request_id`;
//! 5. `chain_id` and `environment_identifier` equal the sealed config (byte-exact);
//! 6. **contiguous counter CHECK** (§10.6): `counter == highest_accepted_counter + 1` for the tuple
//!    `(authority, environment_identifier, scope_class, scope_target)` — read-only, no advance.
//!
//! Every semantic failure collapses to `0x43 AGENT_CAPABILITY_REJECTED` (anti-oracle, §10.9); only
//! structural/format errors surface as `0x40 AGENT_MALFORMED`.
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
//!   `{0,1}` is enforced here, but the per-opcode rule (faucet keygen + all treasury config require
//!   `scope_class == 0`) is a handler concern.
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
const CAP_FORMAT_VERSION: u64 = 1;
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
/// later lands in sealed state; keep it small here so a malformed cap is rejected cheaply).
const MAX_SCOPE_TARGET_LEN: usize = 64;
/// Upper bound on `request_id` bytes — mirrors the envelope's `MAX_REQUEST_ID_LEN`.
const MAX_CAP_REQUEST_ID_LEN: usize = 64;

/// Parsed, type-checked capability (keys `1..=13`). Field types follow §10.5; `treasury_sub_op` is
/// `Some` iff `command_opcode == 6`.
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
    // Strict keys: every key is an integer in 1..=13, none repeats.
    if !check_strict_keys(map, |n| (1..=13).contains(&n)) {
        return Err(AgentError::Malformed);
    }

    let req_u64 = |key: u64| map_get(map, key).and_then(as_u64).ok_or(AgentError::Malformed);
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
        Some(Value::Text(s)) if crate::agent_keystore::is_valid_environment_identifier(s) => s.clone(),
        _ => return Err(AgentError::Malformed),
    };
    let scope_class = req_u8(7)?;
    // §10.5: scope_class ∈ {0=enclave, 1=fleet}. Out-of-range is a structural field error (the
    // "financial MUST be enclave" *policy* is per-opcode and deferred to the handler — see docs).
    if scope_class > 1 {
        return Err(AgentError::Malformed);
    }
    let scope_target = match map_get(map, 8).and_then(as_bytes) {
        Some(b) if b.len() <= MAX_SCOPE_TARGET_LEN => b.to_vec(),
        _ => return Err(AgentError::Malformed),
    };
    let counter = req_u64(9)?;
    let request_id = match map_get(map, 10).and_then(as_bytes) {
        Some(b) if b.len() <= MAX_CAP_REQUEST_ID_LEN => b.to_vec(),
        _ => return Err(AgentError::Malformed),
    };
    let payload_binding: [u8; 32] =
        map_get(map, 11).and_then(as_bytes32).ok_or(AgentError::Malformed)?;
    let is_recovery = match map_get(map, 12) {
        Some(Value::Bool(b)) => *b,
        _ => return Err(AgentError::Malformed),
    };
    let signature: [u8; 64] =
        map_get(map, 13).and_then(as_bytes_n::<64>).ok_or(AgentError::Malformed)?;

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

/// The Ed25519-signed message: `CAP_DOMAIN ‖ canonical-CBOR({keys 1..12})`.
///
/// Keys are emitted in ascending order with shortest-form integer keys and a definite-length map
/// header — RFC 8949 §4.2.1 core deterministic encoding — so a conformant host signer and this
/// verifier produce byte-identical preimages. Key `13` (the signature) is excluded.
fn signed_preimage(cap: &Capability) -> Vec<u8> {
    let mut out = Vec::with_capacity(CAP_DOMAIN.len() + 96 + cap.environment_identifier.len());
    out.extend_from_slice(CAP_DOMAIN);
    let count: u64 = if cap.treasury_sub_op.is_some() { 12 } else { 11 };
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

    // (3) Ed25519 verify over canonical CBOR(1..12), against the is_recovery-selected sealed
    // authority (now tier-validated above).
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
    let expected = highest.checked_add(1).ok_or(AgentError::CapabilityRejected)?;
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
#[cfg(any(test, all(feature = "lab-agent-smoke", feature = "agent-keygen-exec-preview")))]
fn cap_to_map(c: &Capability) -> Vec<(Value, Value)> {
    let mut m: Vec<(Value, Value)> = vec![
        (Value::Integer(1.into()), Value::Integer(c.cap_format_version.into())),
        (Value::Integer(2.into()), Value::Integer(u64::from(c.command_opcode).into())),
    ];
    if let Some(sub) = c.treasury_sub_op {
        m.push((Value::Integer(3.into()), Value::Integer(u64::from(sub).into())));
    }
    m.push((Value::Integer(4.into()), Value::Integer(u64::from(c.key_purpose).into())));
    m.push((Value::Integer(5.into()), Value::Integer(c.chain_id.into())));
    m.push((Value::Integer(6.into()), Value::Text(c.environment_identifier.clone())));
    m.push((Value::Integer(7.into()), Value::Integer(u64::from(c.scope_class).into())));
    m.push((Value::Integer(8.into()), Value::Bytes(c.scope_target.clone())));
    m.push((Value::Integer(9.into()), Value::Integer(c.counter.into())));
    m.push((Value::Integer(10.into()), Value::Bytes(c.request_id.clone())));
    m.push((Value::Integer(11.into()), Value::Bytes(c.payload_binding.to_vec())));
    m.push((Value::Integer(12.into()), Value::Bool(c.is_recovery)));
    m.push((Value::Integer(13.into()), Value::Bytes(c.signature.to_vec())));
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
#[cfg(any(test, all(feature = "lab-agent-smoke", feature = "agent-keygen-exec-preview")))]
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
) -> Vec<(Value, Value)> {
    // Default treasury sub-op for opcode 6 = `refill_budget`(1) (admin-tier) — back-compat for the
    // existing callers (none of which exercise sub-ops 0/2/3). Treasury tests that need a specific
    // sub-op call [`test_signed_capability_with_sub_op`] directly.
    let treasury_sub_op = if opcode == OPCODE_CONFIGURE_TREASURY { Some(1u8) } else { None };
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
    )
}

/// As [`test_signed_capability`] but with an explicit `treasury_sub_op` (slice 15-4): treasury tests
/// build caps for sub-ops `0 set_limits` / `2 raise_lifetime_breaker` (admin) and `3 reset_lifetime_breaker`
/// (recovery) — the caller is responsible for pairing `treasury_sub_op` with the right `is_recovery` tier
/// (reset ⇒ recovery; 0..=2 ⇒ admin), exactly as `verify_capability` enforces.
#[cfg(any(test, all(feature = "lab-agent-smoke", feature = "agent-keygen-exec-preview")))]
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
) -> Vec<(Value, Value)> {
    use ed25519_dalek::Signer;
    let mut cap = Capability {
        cap_format_version: 1,
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
                    cap_format_version: 1,
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
                    signature: [0u8; 64],
                },
            }
        }

        /// Encode to the inner-envelope key-5 CBOR map, signing keys 1..12 with `key`.
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
        assert_eq!(verify_capability(&ok, 1, rid, &cfg, std::slice::from_ref(&entry)), Ok(()));
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
        assert_eq!(verify_capability(&ok.build(&admin_signing_key()), 7, rid, &cfg, &[]), Ok(()));
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
        b.cap.cap_format_version = 2;
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
        // Two builds of the same cap produce identical preimages; key 13 is not in the preimage.
        let a = CapBuilder::new(1, b"req-1", 1).cap;
        let b = CapBuilder::new(1, b"req-1", 1).cap;
        let pa = signed_preimage(&a);
        let pb = signed_preimage(&b);
        assert_eq!(pa, pb);
        assert!(pa.starts_with(CAP_DOMAIN));
        // map header for 11 entries (no sub-op) = 0xA0 | 11 = 0xAB, right after the domain.
        assert_eq!(pa[CAP_DOMAIN.len()], 0xAB);
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
            verify_capability(&gap.build(&admin_signing_key()), 1, rid, &cfg, std::slice::from_ref(&entry)),
            Err(AgentError::CapabilityRejected)
        );
        let mut fresh = CapBuilder::new(1, rid, 1);
        fresh.cap.scope_target = b"generate_faucet".to_vec();
        assert_eq!(
            verify_capability(&fresh.build(&admin_signing_key()), 1, rid, &cfg, std::slice::from_ref(&entry)),
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
    fn valid_treasury_capability_accepted_with_12_entry_preimage() {
        let cfg = test_config();
        let rid = b"req-1";
        let b = CapBuilder::new(6, rid, 1); // CONFIGURE_TREASURY ⇒ sub_op present (12-entry preimage)
        // 12 entries ⇒ map header 0xA0 | 12 = 0xAC right after the domain.
        let pre = signed_preimage(&b.cap);
        assert_eq!(pre[CAP_DOMAIN.len()], 0xAC);
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
}
