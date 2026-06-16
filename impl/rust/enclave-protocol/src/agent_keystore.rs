//! Sealed keystore envelope for the Agent Gateway signer (TASK-7.6.2 / TASK-7.2 format).
//!
//! This module is the **`pq-agent-keystore-v1` seal/unseal envelope**: the AEAD wrapping layer
//! that binds the keystore body to the per-enclave seal root + measurement, reusing the producer
//! `pq-seal-v1` *conventions* in `pq_signer.rs` (`SHA3-256(domain ‖ root ‖ meas_digest)` KDF,
//! `magic ‖ version ‖ meas_digest ‖ nonce` header with `AAD = header − nonce`,
//! fail-closed-on-unknown-version-before-decrypt, `Zeroizing` plaintext).
//!
//! **AEAD choice — XChaCha20Poly1305 (192-bit nonce), unlike the producer's ChaCha20Poly1305.**
//! The producer blob is sealed *once* at provisioning (one nonce per key), so a 96-bit random
//! nonce is safe there. The keystore is instead **re-sealed on every privileged mutation** under a
//! *fixed* per-enclave key, so a 96-bit random nonce would accrue a birthday-bound collision risk;
//! XChaCha20Poly1305's extended nonce removes it. `format_version = 1` denotes this XChaCha
//! envelope from inception — the module has never shipped, so no 96-bit-nonce `v1` blob exists.
//!
//! It deliberately uses **distinct magic and KDF/measurement domains** so a producer blob can never
//! be parsed as a keystore and the keystore AEAD key can never collide with the producer key
//! derived from the same SNP root (format-/key-level role isolation — see
//! `backlog/docs/agent-gateway-keystore-backup-format.md`).
//!
//! The plaintext here is opaque bytes: the deterministic-CBOR keystore body (config/identity, key
//! entries, counter high-water table, faucet state, audit ring) is (de)serialized and sealed/
//! unsealed through this envelope. Multi-byte header integers are big-endian.
//!
//! Built only under the `agent-gateway` feature, alongside the secp256k1 backend.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};
use zeroize::{Zeroize as _, Zeroizing};

/// `b"2DAGTKS\0"` — distinct from the producer `b"2DHSMV1\0"` so the two blob families can never
/// be cross-parsed (format-level role separation, AC#2).
pub const KEYSTORE_MAGIC: &[u8; 8] = b"2DAGTKS\0";
/// Current sealed-keystore format version (`u16`, big-endian on the wire). `3` denotes the
/// XChaCha20Poly1305 envelope + deterministic-CBOR body defined here. `2` added the TASK-7.7
/// anti-rollback body fields `structural_version` + `strict_recovery_counter`; **`3` (TASK-15 slice
/// 15-2b) adds `FaucetState::cumulative_signing_budget`** — the mandatory refillable signing-budget
/// CEILING the §2 faucet gate checks `cumulative_native_spend + worst_case ≤ cumulative_signing_budget`
/// against (a STRUCTURAL config cap set by CONFIGURE_TREASURY `refill_budget`, **not** a marks/spend
/// surface). **MIGRATION SAFETY: NEITHER `1` NOR `2` ever sealed a deployed/production blob** — the only
/// seal sites are the release-banned `agent-keygen-exec-preview` GENERATE_KEYS path and the lab test
/// fixtures (the whole agent-gateway serving + keygen path stays preview-gated until TASK-18), so there
/// is **no fielded keystore to migrate** and the v2→v3 bump cannot lose keys/counters/audit/spend state.
/// Each bump is therefore a HARD one with **no reader for the prior version**: the pre-decrypt
/// `UnsupportedVersion` rejection (version is AAD-bound) is the entire "migration" — a fresh provision,
/// never an in-place upgrade. (When production keygen un-gates at TASK-18, any future bump MUST first
/// define a real migration/reprovision path, since v3 will then be a fielded format.) Any further
/// incompatible on-disk layout/encoding change bumps this again. Note: the `KeystoreBody` fields are
/// feature-invariant (never `#[cfg]`-gated) so the sealed layout/golden is single-valued across all
/// feature combinations.
pub const KEYSTORE_FORMAT_VERSION: u16 = 3;

const MEAS_DIGEST_DOMAIN: &[u8] = b"2d-hsm-agent-keystore-v1-meas";
const AEAD_KEY_DOMAIN: &[u8] = b"2d-hsm-agent-keystore-v1-key";
/// Domain prefix for the TASK-7.7 anti-rollback marks digest (anchor response key 6). Trailing NUL is
/// part of the label. `marks_digest = SHA3-256(MARKS_DOMAIN ‖ canonical-CBOR(marks_payload))`.
pub(crate) const MARKS_DOMAIN: &[u8] = b"2d-hsm/agent-anchor-marks/v1\0";

const MEAS_DIGEST_LEN: usize = 32;
/// 24-byte (192-bit) XChaCha20Poly1305 nonce. Unlike the producer's one-shot `pq-seal-v1` blob,
/// the keystore is **re-sealed on every privileged mutation** under a *fixed* per-enclave key
/// (derived from the stable root+measurement). A 96-bit random nonce has a birthday-bound
/// collision risk over many re-seals (NIST caps random-96-bit nonces at ~2^32 messages/key); the
/// extended 192-bit nonce makes random-nonce collision infeasible regardless of re-seal count.
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// `magic(8) + format_version(2) + meas_digest(32) + nonce(24)`.
const HEADER_LEN: usize = 8 + 2 + MEAS_DIGEST_LEN + NONCE_LEN;
/// `magic(8) + format_version(2) + meas_digest(32)` — the header minus the nonce.
const AAD_LEN: usize = 8 + 2 + MEAS_DIGEST_LEN;

/// Errors from the keystore seal envelope. Deliberately coarse (no decrypt/parse oracle detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreError {
    /// Enclave measurement was empty (refused before any derivation).
    EmptyMeasurement,
    /// Blob shorter than a well-formed header + tag.
    TooShort,
    /// Magic bytes are not `KEYSTORE_MAGIC` (e.g. a producer `pq-seal-v1` blob).
    BadMagic,
    /// `format_version` is not a supported version (rejected BEFORE any decrypt).
    UnsupportedVersion,
    /// Sealed measurement digest does not match this enclave's measurement.
    MeasurementMismatch,
    /// AEAD key construction failed.
    AeadKey,
    /// Ciphertext authentication/decryption failed (wrong root/meas, or tampered blob/tag).
    Decrypt,
    /// AEAD encryption failed on the seal path.
    Encrypt,
    /// CSPRNG unavailable when generating a seal nonce.
    Csprng,
    /// Canonical-CBOR (de)serialization of the keystore body failed (incl. deny-unknown-fields).
    Cbor,
    /// `environment_identifier` failed the TASK-7.1 §10.6 rules (1..=64, `[a-z0-9-]`, no
    /// leading/trailing/double hyphen).
    InvalidEnvironmentId,
    /// `structural_version` violated the frozen v2 invariant: it must be `>= 1` (init 1, never 0 —
    /// a 0 would fail the same-epoch `reconcile` Fresh-equality vs a forged 0-anchor).
    InvalidStructuralVersion,
    /// Key-entry count over `MAX_TOTAL_KEY_ENTRIES`, or counter table over `MAX_COUNTER_ENTRIES`
    /// (AC#5 capacity guard).
    CapacityExceeded,
    /// A counter advance tried to set a high-water mark `<=` the existing one (anti-rollback
    /// defense-in-depth: a high-water counter must only move forward).
    CounterRegression,
    /// A fixed-length byte field (public identity 65 B, secret scalar 32 B) had the wrong length
    /// or a malformed SEC1 prefix.
    InvalidFieldLength,
    /// Two key entries share the same `key_ref` (the opaque handle must be unique).
    DuplicateKeyRef,
    /// Two counter rows share the same `(authority, scope_class, scope_target)` tuple. The marks
    /// grammar is one row per tuple (the strict decoder rejects duplicates); a duplicate here would make
    /// the monotonicity belt and counter updates order-dependent and would not round-trip through
    /// `strict_decode_marks_payload` on the AdoptForward path.
    DuplicateCounterTuple,
    /// The sealed blob would exceed the vsock `MAX_MESSAGE_SIZE` budget (entries/counters/audit too
    /// large to transmit to the host — Nitro has no persistent enclave storage).
    BlobTooLarge,
    /// A forward-only monotonic field (`freshness_epoch` or `structural_version`) would overflow `u64`
    /// on a per-op commit bump (TASK-7.7 slice 6). CHECKED, never wrapping — a wrapped counter would let
    /// a rolled-back blob masquerade as an adoptable forward gap. Unreachable in practice (one bump per
    /// op); fail-closed by contract.
    MonotonicOverflow,
}

/// `SHA3-256(domain ‖ enclave_measurement)` — the measurement digest bound into the header + AAD.
fn measurement_digest(enclave_measurement: &[u8]) -> [u8; MEAS_DIGEST_LEN] {
    let mut h = Sha3_256::new();
    h.update(MEAS_DIGEST_DOMAIN);
    h.update(enclave_measurement);
    h.finalize().into()
}

/// Keystore AEAD key = `SHA3-256(AEAD_KEY_DOMAIN ‖ provisioning_root ‖ meas_digest)`.
///
/// Same shape as the producer KDF but a **distinct domain label**, so for an identical
/// `(root, meas_digest)` the keystore key and the producer `pq-seal-v1` key differ — a producer
/// blob cannot be decrypted with the keystore key and vice-versa (AC#19). Returned in `Zeroizing`:
/// it directly en/decrypts agent private scalars and must not linger on the stack.
fn derive_aead_key(
    provisioning_root: &[u8; 32],
    meas_digest: &[u8; MEAS_DIGEST_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(AEAD_KEY_DOMAIN);
    h.update(provisioning_root);
    h.update(meas_digest);
    // Copy into a pre-zeroed Zeroizing buffer rather than `Zeroizing::new(finalize().into())`:
    // the latter materializes a bare `[u8; 32]` (a `Copy` type, no `Drop`) on the stack that is
    // never scrubbed (repo zeroize rule; cf. `pq_signer.rs` resolve_provisioning_root).
    let mut digest = h.finalize(); // GenericArray holding the raw key bytes
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(digest.as_slice());
    digest.as_mut_slice().zeroize(); // scrub the hasher-output temporary too
    key
}

/// Seal an opaque keystore body with a caller-supplied nonce (deterministic — for golden vectors).
///
/// Production callers should use [`seal_keystore`] (platform CSPRNG nonce). The body is the
/// deterministic-CBOR keystore plaintext; this function does not interpret it.
pub fn seal_keystore_with_nonce(
    body: &[u8],
    provisioning_root: &[u8; 32],
    enclave_measurement: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, KeystoreError> {
    if enclave_measurement.is_empty() {
        return Err(KeystoreError::EmptyMeasurement);
    }
    let meas_digest = measurement_digest(enclave_measurement);
    let key = derive_aead_key(provisioning_root, &meas_digest);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| KeystoreError::AeadKey)?;

    let mut out = Vec::with_capacity(HEADER_LEN + body.len() + TAG_LEN);
    out.extend_from_slice(KEYSTORE_MAGIC);
    out.extend_from_slice(&KEYSTORE_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&meas_digest);
    out.extend_from_slice(nonce);
    // AAD = header minus nonce (magic ‖ version ‖ meas_digest); binds them to the ciphertext.
    let ct = {
        let aad = &out[..AAD_LEN];
        cipher
            .encrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
            .map_err(|_| KeystoreError::Encrypt)?
    };
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Seal an opaque keystore body, drawing the 24-byte XChaCha nonce from the platform CSPRNG.
pub fn seal_keystore(
    body: &[u8],
    provisioning_root: &[u8; 32],
    enclave_measurement: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| KeystoreError::Csprng)?;
    seal_keystore_with_nonce(body, provisioning_root, enclave_measurement, &nonce)
}

/// Unseal a `pq-agent-keystore-v1` blob: returns the opaque keystore body in `Zeroizing`.
///
/// Fail-closed ordering mirrors `pq_signer.rs`: length, magic, then **`format_version` BEFORE any
/// decrypt** (no silent downgrade / best-effort parse), then measurement binding, then AEAD.
pub fn unseal_keystore(
    blob: &[u8],
    provisioning_root: &[u8; 32],
    enclave_measurement: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if enclave_measurement.is_empty() {
        return Err(KeystoreError::EmptyMeasurement);
    }
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(KeystoreError::TooShort);
    }
    if &blob[..8] != KEYSTORE_MAGIC.as_slice() {
        return Err(KeystoreError::BadMagic);
    }
    let version = u16::from_be_bytes([blob[8], blob[9]]);
    if version != KEYSTORE_FORMAT_VERSION {
        // Fail closed on unknown version BEFORE deriving keys or decrypting.
        return Err(KeystoreError::UnsupportedVersion);
    }
    let expected_meas = measurement_digest(enclave_measurement);
    let stored_meas = &blob[10..10 + MEAS_DIGEST_LEN];
    if stored_meas != expected_meas.as_slice() {
        return Err(KeystoreError::MeasurementMismatch);
    }
    let key = derive_aead_key(provisioning_root, &expected_meas);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| KeystoreError::AeadKey)?;
    let nonce = XNonce::from_slice(&blob[AAD_LEN..HEADER_LEN]);
    let aad = &blob[..AAD_LEN];
    let plain = cipher
        .decrypt(nonce, Payload { msg: &blob[HEADER_LEN..], aad })
        .map_err(|_| KeystoreError::Decrypt)?;
    Ok(Zeroizing::new(plain))
}

// ===========================================================================================
// Keystore body — the CBOR plaintext sealed by the envelope above.
// (`agent-gateway-keystore-backup-format.md` §Plaintext: config/identity, entry list, counter
// high-water table, faucet state, audit ring.) All structs are `deny_unknown_fields` so an
// unexpected field fails closed rather than being silently dropped on a forward-migration read.
//
// Encoding note (sealed-body format, current format_version 3): this uses **deterministic** CBOR — serde emits struct fields
// in declaration order and every collection is a `Vec` (no map/HashMap), so a given body always
// encodes to the same bytes (the golden vector locks this). It is NOT RFC 8949 *canonical* CBOR,
// and byte fields (`[u8; N]`, `Vec<u8>`) serialize as CBOR integer-arrays, not byte strings.
// Switching to byte-string encoding (smaller) or strict canonical ordering would change the bytes
// and is therefore a deliberate `format_version` bump + golden-vector update, never a silent edit.
// ===========================================================================================

/// Coarse upper backstop on key-entry count (AC#5). NOTE: this is **not** the binding capacity —
/// the authoritative limit is the [`MAX_KEYSTORE_BLOB_SIZE`] seal check, which (with v1's CBOR
/// integer-array byte encoding) rejects a full 4096-entry keystore well before this count is hit.
/// So the *effective* capacity is size-derived and smaller; this constant only fail-closes a
/// pathologically long entry list before serialization. A byte-string body encoding (a future
/// `format_version`) would raise the effective capacity toward this count.
pub const MAX_TOTAL_KEY_ENTRIES: usize = 4096;
/// Max entries minted in a single `AGENT_K1_GENERATE_KEYS` batch (AC#5). NOTE: per-batch
/// enforcement lands with the keygen mutation path (TASK-7.6.3); this slice only seals/validates
/// the at-rest store, so the constant is the shared limit those callers will check.
pub const MAX_BATCH_SIZE: usize = 256;
/// Bound on the counter high-water table (defense-in-depth; the table is one row per active
/// `(authority, environment, scope)` and should never approach this).
pub const MAX_COUNTER_ENTRIES: usize = 65_536;
/// Bound on the audit ring capacity (and therefore the materialized record vector).
pub const MAX_AUDIT_CAPACITY: u32 = 65_536;

/// Headroom reserved below `MAX_MESSAGE_SIZE` for the framing that wraps a sealed keystore when it
/// is transmitted back into the enclave: the 2-byte frame header (version+type, `lib.rs:261`), the
/// wire length prefix, and the install/restore CBOR envelope around the blob. **Provisional** — the
/// install/restore wire envelope is not yet defined (the current runtime install is an in-enclave
/// `INSTALLED_KEYSTORE` slot; the host-side install/restore framing is a later slice). 1 KiB is a
/// generous over-reserve until that slice owns and pins the exact envelope; the install/restore
/// encoder MUST then honor [`MAX_KEYSTORE_BLOB_SIZE`] so a sealed blob is always re-installable.
const KEYSTORE_FRAMING_RESERVE: usize = 1024;
/// Max sealed keystore blob size. A larger blob could seal but be impossible to send back into the
/// enclave over vsock (frame + envelope would exceed `MAX_MESSAGE_SIZE`) → permanent lockout, since
/// Nitro persists the sealed blob via the untrusted host and re-installs it on boot.
pub const MAX_KEYSTORE_BLOB_SIZE: usize =
    (crate::MAX_MESSAGE_SIZE as usize) - KEYSTORE_FRAMING_RESERVE;

const SECP256K1_UNCOMPRESSED_LEN: usize = 65;
const SECRET_SCALAR_LEN: usize = 32;
/// ML-KEM-1024 encapsulation (public) key length, FIPS 203 (the DR-backup wrapping key). v1 wraps
/// to a single ML-KEM-1024 key; a future `X25519+ML-KEM` hybrid would be a `format_version` bump.
const ML_KEM_1024_ENCAPS_KEY_LEN: usize = 1568;

/// Purpose of a stored key — singleton treasury/faucet source vs batch transfer-signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    AgentFaucetTreasuryK1,
    AgentTransferK1,
}

/// Signing algorithm for a stored key (secp256k1 only in this slice).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Secp256k1,
}

/// Config-version + counter snapshot + batch id captured at key creation (AC#18 atomic keygen).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationMetadata {
    pub config_version: u64,
    pub counter_snapshot: u64,
    pub batch_id: u64,
}

/// Per-entry DR-backup bookkeeping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupExportMetadata {
    /// Monotonic export sequence at which this entry was last included in a backup (0 = never).
    pub last_exported_seq: u64,
}

/// One stored agent key. The 32-byte secret scalar is **sealed here** (same-enclave restart
/// material) and held in `Zeroizing` in memory; `Debug` redacts it so it never reaches a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// Opaque random handle returned to the host (never the secret or a guessable index).
    pub key_ref: [u8; 32],
    pub purpose: KeyPurpose,
    pub algorithm: KeyAlgorithm,
    /// Uncompressed SEC1 public identity (`0x04 || X || Y`, 65 bytes).
    pub public_identity: Vec<u8>,
    /// 32-byte secret scalar — confidential; zeroized on drop.
    pub secret_scalar: Zeroizing<Vec<u8>>,
    pub creation_metadata: CreationMetadata,
    #[serde(default)]
    pub backup_export_metadata: BackupExportMetadata,
}

impl core::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the secret scalar.
        f.debug_struct("KeyEntry")
            .field("key_ref", &self.key_ref)
            .field("purpose", &self.purpose)
            .field("algorithm", &self.algorithm)
            .field("public_identity", &self.public_identity)
            .field("secret_scalar", &"<redacted>")
            .field("creation_metadata", &self.creation_metadata)
            .field("backup_export_metadata", &self.backup_export_metadata)
            .finish()
    }
}

/// One row of the counter high-water table (AC#8/#11): the highest accepted capability counter for
/// a `(authority, environment, scope)` tuple. Acceptance rule (TASK-7.1): `incoming == highest+1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterEntry {
    pub authority: [u8; 32],
    pub environment_identifier: String,
    pub scope_class: u8,
    pub scope_target: Vec<u8>,
    pub highest_accepted_counter: u64,
}

/// Faucet caps + spend state (AC#8/#17). Amounts are big-endian `u256` (2D native token, per
/// TASK-7.4). Spend counters are keyed independently of the treasury `key_ref`, so they survive
/// treasury-key rotation (AC#17 — never reset on key replacement; arithmetic lives in TASK-7.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetState {
    pub per_dispense_max_amount: [u8; 32],
    pub max_gas_limit: u64,
    pub max_effective_gas_fee_rate: u64,
    /// Refillable cumulative spend (resettable by treasury config).
    pub cumulative_native_spend: [u8; 32],
    /// Lifetime spend from genesis — never reset, even on treasury-key rotation.
    pub lifetime_spend: [u8; 32],
    /// Optional lifetime circuit-breaker threshold (TASK-7.4 §2).
    pub circuit_breaker_threshold: Option<[u8; 32]>,
    /// Mandatory refillable cumulative signing-budget CEILING (TASK-7.4 §2, format_version 3). The §2
    /// faucet gate accepts a dispense iff `cumulative_native_spend + worst_case ≤ cumulative_signing_budget`
    /// (big-endian `u256`). A STRUCTURAL config cap (raised by `CONFIGURE_TREASURY refill_budget`), NOT a
    /// marks/spend surface — so it is deliberately **absent** from `encode_marks_payload`; a dropped seal
    /// of a budget change fails closed (StructuralGap→restore), never adopt-forwarded. Genesis = `[0; 32]`
    /// (a fresh keystore cannot dispense until a budget is configured — §2 "fails closed until a cumulative
    /// budget is sealed"). Appended LAST so the audited marks-surface field order above is untouched.
    /// **Slice 15-2b ships this field INERT/frozen-ahead** (like v2's `structural_version` did): no code
    /// reads or writes it yet — the §2 gate that CHECKS it lands in slice 15-3 (SIGN_FAUCET_DISPENSE) and
    /// the `refill_budget` mutator that RAISES it in slice 15-4 (CONFIGURE_TREASURY). The field is sealed
    /// now so the format/golden settle before those mutators exist.
    pub cumulative_signing_budget: [u8; 32],
}

/// One privileged-op audit record (AC#14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub seq: u64,
    pub op: u8,
    pub authority: [u8; 32],
    pub counter: u64,
    pub config_version: u64,
}

/// Bounded audit ring + `last_exported_seq` backpressure (AC#14): privileged ops must fail closed
/// rather than overwrite un-exported entries (enforcement lives with the mutation path, later).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRing {
    pub records: Vec<AuditRecord>,
    pub capacity: u32,
    pub last_exported_seq: u64,
    pub next_seq: u64,
}

/// Config / identity block (AC#8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreConfig {
    pub twod_chain_id: u64,
    pub environment_identifier: String,
    pub admin_authority_pk: [u8; 32],
    pub recovery_authority_pk: [u8; 32],
    /// Operator recovery **public** key for DR wrapping (ML-KEM-1024; private side stays offline).
    pub backup_recovery_wrapping_pubkey: Vec<u8>,
    pub monotonic_treasury_config_version: u64,
    /// Reserved for a future authority-rotation task (no format bump needed).
    pub authority_epoch: u64,
    /// Pinned anti-rollback **anchor** identity — the Ed25519 public key the enclave verifies the
    /// anchor's freshness responses against (TASK-7.7). 7.2 only **stores** it; 7.7 owns the
    /// mechanism. Installed at provisioning. Rotating this value is a reviewed reprovision/reseal
    /// transition (a new sealed config), **not** a `format_version` bump — `format_version` changes
    /// only for incompatible on-disk layout/encoding changes.
    pub anchor_root: [u8; 32],
}

/// The full keystore plaintext: everything sealed inside one `pq-agent-keystore-v1` commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreBody {
    pub config: KeystoreConfig,
    pub entries: Vec<KeyEntry>,
    pub counters: Vec<CounterEntry>,
    pub faucet: FaucetState,
    pub audit: AuditRing,
    /// Anti-rollback freshness epoch (TASK-7.7). Lives in the encrypted body alongside the
    /// counter/spend state, so the keystore AEAD integrity-binds it. 7.2 **stores** it (sealed,
    /// authenticated); 7.7 advances it against the pinned [`KeystoreConfig::anchor_root`] and never
    /// trusts a behind-epoch blob's own marks — it adopts the anchor's authenticated counter/spend
    /// marks when they fully resolve the gap (bounded crash-reconcile), and fails closed for a blob
    /// ahead of the anchor, a structural key/config gap the anchor never held, or an
    /// unavailable/unresolvable anchor.
    pub freshness_epoch: u64,
    /// Anti-rollback **structural version** (TASK-7.7, anchor response key 5). **Required** (no
    /// `serde(default)` — a v2 body missing it fails closed as a CBOR decode error, never a silent 0).
    /// Init **1**, never 0 (a 0 would fail the same-epoch `reconcile` Fresh-equality vs a forged
    /// 0-anchor). Forward-only, never reset. Bumped by **exactly**: each committed GENERATE_KEYS, and
    /// each key/config-changing CONFIGURE_TREASURY sub-op (that handler is deferred). MUST NOT bump on
    /// counter/spend advances, `freshness_epoch`, `authority_epoch`, or a pure-config-version change,
    /// and MUST NOT be aliased onto [`KeystoreConfig::monotonic_treasury_config_version`]. Overflow:
    /// `checked_add` → fail closed (never wrap). The GENERATE_KEYS bump is **LIVE** (TASK-7.7 slice
    /// 6-4a): `advance_commit_epoch` advances `freshness_epoch` + `structural_version` atomically; the
    /// frame layer then computes the sealed blob FIRST (side-effect-free) and commits exactly that
    /// `{epoch, structural, marks}` through the anchor BEFORE the swap/emit (the "seal-before-emit" order
    /// is seal→commit→swap→emit); boot `reconcile` already reads this field (structural-ahead →
    /// `StructuralGap`).
    /// Still gated behind the off-by-default `agent-keygen-exec-preview` until the boot channel install
    /// (6-4b) + the request_id idempotency/crash-reconcile proof (6-5) land and TASK-18 un-gates
    /// production keygen.
    pub structural_version: u64,
    /// Strict recovery counter (TASK-7.7 §1 item 5, anchor marks key 4). **Required** (no
    /// `serde(default)`). Init **0** (genuine genesis: zero recoveries performed; anchor baseline 0).
    /// Forward-only `u64`, encoded as a CBOR major-0 unsigned int at marks key 4. Advanced (never
    /// decreased) by RESTORE_BACKUP + `reset_lifetime_breaker` — those **mutators are deferred**; the
    /// field + its marks encoding are frozen now so `marks_digest` is complete and stable.
    pub strict_recovery_counter: u64,
}

impl KeystoreBody {
    /// Canonical-CBOR encoding of the authoritative counter/spend high-water **marks** — the preimage
    /// (after [`MARKS_DOMAIN`]) of the anchor response key-6 digest. FROZEN v1 grammar (design doc §8):
    /// a 4-key map `{1: [rows…], 2: cumulative_native_spend(32B), 3: lifetime_spend(32B),
    /// 4: strict_recovery_counter(uint)}`, keys ascending, shortest-form. Each counter row is a CBOR
    /// **array(4)** `[authority(32B bstr), scope_class(uint), scope_target(bstr),
    /// highest_accepted_counter(uint)]`, so the whole payload is a genuinely **decodable** canonical
    /// CBOR document (the seeding slice reconstructs rows from it). Rows are **sorted** byte-lex by
    /// `(authority, scope_class, scope_target)` — `environment_identifier` is folded out (it equals
    /// `config.environment_identifier` for every row, `validate()`-enforced). Built with the shared
    /// canonical encoders, **not** serde (the sealed body serializes `[u8;N]` as CBOR int-arrays, which
    /// must not be reused here).
    // TODO(agent_cbor): the canonical ENCODER has 3 consumers now (capability/anchor/here); agent_cbor
    // is decode-only today, so reuse agent_capability's encoders in place until they move there.
    // `pub(crate)` (5b-2e): the lab anchor stub serves this verbatim as the 0x44 raw-marks response so
    // it self-consistently hashes to the `compute_local_marks_digest` it also commits on the 0x41 leg.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn encode_marks_payload(&self) -> Vec<u8> {
        use crate::agent_capability::{put_bytes, put_uint};
        // The digest's determinism + injectivity rest on every row's environment_identifier equalling
        // config.environment_identifier (validate() enforces this at every seal/unseal boundary), which
        // is why env is folded out of the encoding. Self-document + catch a future mutator that lands a
        // differing-env row without re-validating.
        debug_assert!(
            self.counters
                .iter()
                .all(|r| r.environment_identifier == self.config.environment_identifier),
            "marks env-fold precondition: every counter row's environment_identifier must equal config",
        );
        // Counters are stored in arrival order (see advance_counter); sort references for a canonical,
        // enclave-independent digest. The encoded sort key is (authority, scope_class, scope_target);
        // environment_identifier is appended as a final tiebreaker so the order stays TOTAL (and the
        // digest reproducible) even if the env-fold precondition above is ever violated — for a valid
        // body (env constant) it never changes the order, so the frozen vectors are unaffected.
        let mut rows: Vec<&CounterEntry> = self.counters.iter().collect();
        rows.sort_by(|a, b| {
            a.authority
                .cmp(&b.authority)
                .then(a.scope_class.cmp(&b.scope_class))
                .then(a.scope_target.as_slice().cmp(b.scope_target.as_slice()))
                .then(a.environment_identifier.cmp(&b.environment_identifier))
        });
        let mut out = Vec::new();
        put_uint(&mut out, 5, 4); // map header: 4 pairs
        put_uint(&mut out, 0, 1); // key 1 -> counter rows
        put_uint(&mut out, 4, rows.len() as u64); // outer array: one element PER ROW
        for r in &rows {
            // Each row is a 4-element CBOR array so the payload is a genuinely DECODABLE canonical CBOR
            // document (the seeding slice reconstructs rows from it), not just a hash preimage.
            put_uint(&mut out, 4, 4); // array(4): [authority, scope_class, scope_target, counter]
            put_bytes(&mut out, &r.authority);
            put_uint(&mut out, 0, u64::from(r.scope_class));
            put_bytes(&mut out, &r.scope_target);
            put_uint(&mut out, 0, r.highest_accepted_counter);
        }
        put_uint(&mut out, 0, 2); // key 2 -> cumulative_native_spend (32B u256-BE byte string)
        put_bytes(&mut out, &self.faucet.cumulative_native_spend);
        put_uint(&mut out, 0, 3); // key 3 -> lifetime_spend
        put_bytes(&mut out, &self.faucet.lifetime_spend);
        put_uint(&mut out, 0, 4); // key 4 -> strict_recovery_counter (CBOR uint)
        put_uint(&mut out, 0, self.strict_recovery_counter);
        out
    }

    /// `marks_digest = SHA3-256(MARKS_DOMAIN ‖ encode_marks_payload())` — the local high-water digest
    /// the boot `reconcile` compares against the anchor's authoritative key-6 (design doc §8). Pure,
    /// total, panic-free over `&self`. (Dead-code-allowed until boot wiring calls it.)
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn compute_local_marks_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(MARKS_DOMAIN);
        h.update(self.encode_marks_payload());
        h.finalize().into()
    }

    /// 5b-2e `AdoptForward` seed: overwrite EXACTLY the four marks surfaces — `counters`,
    /// `faucet.cumulative_native_spend`, `faucet.lifetime_spend`, `strict_recovery_counter` — from
    /// the authenticated decoded marks, set `freshness_epoch = epoch`, and leave `structural_version`
    /// UNCHANGED (AdoptForward fires only on a counter/spend-only gap; a structural bump would itself
    /// look like a structural mutation on the next reconcile). Each row's `environment_identifier` is
    /// reconstructed from `config` (the wire folds env out), then [`validate`] re-asserts the env-fold
    /// + caps + field lengths. `config`/`entries`/`audit`/faucet-policy fields are UNTOUCHED.
    ///
    /// Writes rows **absolutely** — it does NOT route through [`advance_counter`], whose forward-only
    /// `incoming <= highest` guard would reject an absolute re-write. Monotonicity (`adopted >= local`)
    /// is NOT enforced here; that is the caller's defense-in-depth belt AFTER the hash-equality gate
    /// (the gate against the anchor's signed digest is the security boundary, not this seeder).
    #[cfg_attr(not(test), allow(dead_code))] // staged 5b-2e commit 3/8; the caller lands in commit 4
    pub(crate) fn seed_marks_forward(
        &mut self,
        m: &crate::agent_cbor::DecodedMarks,
        epoch: u64,
    ) -> Result<(), KeystoreError> {
        let env = self.config.environment_identifier.clone();
        self.counters = m
            .rows
            .iter()
            .map(|r| CounterEntry {
                authority: r.authority,
                environment_identifier: env.clone(), // env-fold inverse, from config (never host-chosen)
                scope_class: r.scope_class,
                scope_target: r.scope_target.clone(),
                highest_accepted_counter: r.highest_accepted_counter,
            })
            .collect();
        self.faucet.cumulative_native_spend = m.cumulative_native_spend;
        self.faucet.lifetime_spend = m.lifetime_spend;
        self.strict_recovery_counter = m.strict_recovery_counter;
        self.freshness_epoch = epoch;
        // structural_version DELIBERATELY UNCHANGED (counter/spend-only gap).
        self.validate()
    }

    /// slice 6-2: advance the body forward for a per-op COMMIT — `freshness_epoch += 1` ALWAYS, and
    /// (for a STRUCTURAL op) `structural_version += 1`, as ONE atomic checked unit. This is the WRITE-side
    /// counterpart to `seed_marks_forward`'s read-side advance: it makes `structural_version`
    /// load-bearing by moving it in lockstep with `freshness_epoch`.
    ///
    /// **Atomic, no partial mutation:** BOTH increments are `checked_add(1)` and BOTH are computed
    /// BEFORE EITHER field is written, so an overflow on either leaves the body UNCHANGED (`Err`). The
    /// caller runs this on a CANDIDATE clone; the seal (6-4) binds the advanced `freshness_epoch` into
    /// the AEAD, and the anchor commit records `(new freshness_epoch, new structural_version, post-op
    /// marks_digest)`. `bumps_structural` comes from [`crate::agent_dispatch::AgentOpcode`]'s
    /// `commit_bump_class` (Structural ⇒ `true`, EpochOnly ⇒ `false`).
    ///
    /// **Why checked, never wrapping:** a wrapped epoch/structural would let a rolled-back blob
    /// masquerade as an adoptable forward gap — the exact anti-rollback failure. `u64` overflow is
    /// unreachable in practice (one bump per op), but fail-closed (`MonotonicOverflow`) is the contract.
    /// Does NOT touch the marks surfaces (counters/spend/recovery) — those are advanced by the op's own
    /// handler (`advance_counter` etc.) BEFORE the marks digest is computed; epoch/structural are not
    /// marks surfaces, so this bump leaves `compute_local_marks_digest()` unchanged.
    #[cfg_attr(not(test), allow(dead_code))] // staged slice-6-2; consumed by the 6-4 dispatch wiring
    pub(crate) fn advance_commit_epoch(&mut self, bumps_structural: bool) -> Result<(), KeystoreError> {
        let new_epoch = self.freshness_epoch.checked_add(1).ok_or(KeystoreError::MonotonicOverflow)?;
        let new_structural = if bumps_structural {
            Some(
                self.structural_version
                    .checked_add(1)
                    .ok_or(KeystoreError::MonotonicOverflow)?,
            )
        } else {
            None
        };
        // Commit BOTH only after both checks passed — no partial mutation on overflow.
        self.freshness_epoch = new_epoch;
        if let Some(s) = new_structural {
            self.structural_version = s;
        }
        Ok(())
    }
}

/// `environment_identifier` rules (TASK-7.1 §10.6): UTF-8, length `1..=64`, `[a-z0-9-]`, no
/// leading/trailing hyphen, no doubled hyphen. Shared so other Agent Gateway slices (e.g. the
/// identity-proof preimage builder) enforce the same rule rather than re-deriving it.
pub(crate) fn is_valid_environment_identifier(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if b[0] == b'-' || b[b.len() - 1] == b'-' {
        return false;
    }
    let mut prev_hyphen = false;
    for &c in b {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return false;
        }
        if c == b'-' && prev_hyphen {
            return false;
        }
        prev_hyphen = c == b'-';
    }
    true
}

fn validate_environment_identifier(s: &str) -> Result<(), KeystoreError> {
    if is_valid_environment_identifier(s) {
        Ok(())
    } else {
        Err(KeystoreError::InvalidEnvironmentId)
    }
}

impl KeystoreBody {
    /// Advance the contiguous capability counter for the tuple `(authority, environment_identifier,
    /// scope_class, scope_target)` to `incoming` (the verified `highest + 1`): update the existing
    /// row, or insert a new one (first counter) if none exists. The caller mutates a CANDIDATE body
    /// then seals it. New rows are bounded by [`MAX_COUNTER_ENTRIES`] (fail-closed on overflow).
    pub(crate) fn advance_counter(
        &mut self,
        authority: &[u8; 32],
        scope_class: u8,
        scope_target: &[u8],
        incoming: u64,
    ) -> Result<(), KeystoreError> {
        let env = self.config.environment_identifier.clone();
        if let Some(c) = self.counters.iter_mut().find(|c| {
            &c.authority == authority
                && c.environment_identifier == env
                && c.scope_class == scope_class
                && c.scope_target == scope_target
        }) {
            // Forward-only: the caller verified `incoming == highest + 1`, but guard here too so a
            // future caller that skipped that check cannot silently roll the high-water backward.
            if incoming <= c.highest_accepted_counter {
                return Err(KeystoreError::CounterRegression);
            }
            c.highest_accepted_counter = incoming;
            return Ok(());
        }
        if self.counters.len() >= MAX_COUNTER_ENTRIES {
            return Err(KeystoreError::CapacityExceeded);
        }
        self.counters.push(CounterEntry {
            authority: *authority,
            environment_identifier: env,
            scope_class,
            scope_target: scope_target.to_vec(),
            highest_accepted_counter: incoming,
        });
        Ok(())
    }


    /// Structural validation enforced on both seal (before commit) and unseal (after decrypt):
    /// environment-id rules, total-capacity (AC#5), and fixed byte-field lengths.
    pub fn validate(&self) -> Result<(), KeystoreError> {
        // Frozen v2 invariant: structural_version is init 1 and never 0 (enforced, not just documented),
        // so a 0 fails closed on both seal and unseal rather than silently producing a forge-equal mark.
        if self.structural_version == 0 {
            return Err(KeystoreError::InvalidStructuralVersion);
        }
        validate_environment_identifier(&self.config.environment_identifier)?;
        // The DR-backup wrapping key must be a well-formed ML-KEM-1024 encapsulation key.
        if self.config.backup_recovery_wrapping_pubkey.len() != ML_KEM_1024_ENCAPS_KEY_LEN {
            return Err(KeystoreError::InvalidFieldLength);
        }
        if self.entries.len() > MAX_TOTAL_KEY_ENTRIES
            || self.counters.len() > MAX_COUNTER_ENTRIES
        {
            return Err(KeystoreError::CapacityExceeded);
        }
        let mut seen_refs = std::collections::HashSet::with_capacity(self.entries.len());
        for e in &self.entries {
            // Uncompressed SEC1: exactly 65 bytes AND the 0x04 prefix (full on-curve validation is
            // done by `secp256k1.rs` at use time; this is the storage-layer structural check).
            if e.public_identity.len() != SECP256K1_UNCOMPRESSED_LEN || e.public_identity[0] != 0x04
            {
                return Err(KeystoreError::InvalidFieldLength);
            }
            if e.secret_scalar.len() != SECRET_SCALAR_LEN {
                return Err(KeystoreError::InvalidFieldLength);
            }
            // key_ref is an opaque handle returned to the host — it must be unique across entries.
            if !seen_refs.insert(e.key_ref) {
                return Err(KeystoreError::DuplicateKeyRef);
            }
        }
        // The marks-payload grammar (the AdoptForward digest path) is one row per
        // `(authority, scope_class, scope_target)` tuple with `scope_target` bounded by the strict
        // decoder's cap. Enforce BOTH here so the encode↔decode inverse is a validated invariant: any
        // body `validate()` accepts round-trips through `encode_marks_payload` →
        // `strict_decode_marks_payload`. `advance_counter` already dedups (find-or-insert), so a
        // duplicate or over-cap row only arises from a corrupt/forged sealed blob (AEAD-authenticated,
        // so unreachable in practice) or a future caller that skips the dedup — this gate makes both
        // fail closed at the seal/unseal boundary rather than producing a non-adoptable sealed state.
        let mut seen_tuples =
            std::collections::HashSet::<(&[u8; 32], u8, &[u8])>::with_capacity(self.counters.len());
        for c in &self.counters {
            // One sealed keystore is one environment: every counter row must carry the keystore's
            // own environment_identifier (format-valid AND equal to config), not just a well-formed
            // one. A mismatch is a structural invariant break (enclave bug / migration error).
            validate_environment_identifier(&c.environment_identifier)?;
            if c.environment_identifier != self.config.environment_identifier {
                return Err(KeystoreError::InvalidEnvironmentId);
            }
            if c.scope_target.len() > crate::agent_cbor::MARKS_SCOPE_TARGET_MAX_LEN {
                return Err(KeystoreError::InvalidFieldLength);
            }
            if !seen_tuples.insert((&c.authority, c.scope_class, c.scope_target.as_slice())) {
                return Err(KeystoreError::DuplicateCounterTuple);
            }
        }
        // Audit ring: capacity bounded, and the materialized record vector cannot exceed it.
        if self.audit.capacity > MAX_AUDIT_CAPACITY
            || self.audit.records.len() as u64 > self.audit.capacity as u64
        {
            return Err(KeystoreError::CapacityExceeded);
        }
        Ok(())
    }
}

/// A `std::io::Write` sink that counts bytes without retaining them — used to size the secret
/// CBOR buffer in one pass so the real serialization never reallocates (see [`seal_body`]).
struct CountingWriter(usize);

impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Validate + deterministically CBOR-encode the body, then seal it (CSPRNG nonce). The transient
/// CBOR buffer holds plaintext secrets and is zeroized on drop.
///
/// The buffer is **pre-sized** (a first counting pass that retains no bytes, then a single exact-
/// capacity `Zeroizing` allocation): a growing `Zeroizing<Vec>` would reallocate mid-serialization,
/// and `realloc` frees the old allocation **without** zeroizing it — leaking already-written secret
/// bytes to the allocator. With exact capacity, serialization never reallocates, so the only copy
/// of the plaintext lives in the one `Zeroizing` buffer that is scrubbed on drop.
pub fn seal_body(
    body: &KeystoreBody,
    provisioning_root: &[u8; 32],
    enclave_measurement: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    body.validate()?;
    // Pass 1: count the exact encoded length (the CountingWriter discards bytes — no secret retained).
    let mut counter = CountingWriter(0);
    ciborium::ser::into_writer(body, &mut counter).map_err(|_| KeystoreError::Cbor)?;
    // The sealed blob is persisted by the (untrusted) host and re-installed over vsock on boot —
    // Nitro enclaves have no persistent storage. Reject any body whose sealed size would exceed the
    // install budget (MAX_MESSAGE_SIZE minus frame + CBOR-envelope headroom), so a too-large
    // keystore fails closed at seal time rather than becoming an un-loadable blob (lockout) when it
    // is framed and sent back at install time.
    if HEADER_LEN + counter.0 + TAG_LEN > MAX_KEYSTORE_BLOB_SIZE {
        return Err(KeystoreError::BlobTooLarge);
    }
    // Pass 2: serialize into an exact-capacity Zeroizing buffer (no reallocation → no leaked copy).
    let mut cbor = Zeroizing::new(Vec::with_capacity(counter.0));
    ciborium::ser::into_writer(body, &mut *cbor).map_err(|_| KeystoreError::Cbor)?;
    // Both passes must encode the same length; if not, pass 2 exceeded the reserved capacity and
    // reallocated (leaking a copy), or encoding is non-deterministic — either way a bug.
    debug_assert_eq!(cbor.len(), counter.0, "seal_body CBOR length mismatch between passes");
    seal_keystore(&cbor, provisioning_root, enclave_measurement)
}

/// Unseal + CBOR-decode + validate the keystore body. `deny_unknown_fields` + the post-decode
/// `validate()` make an unexpected field or malformed entry fail closed (no best-effort parse).
pub fn unseal_body(
    blob: &[u8],
    provisioning_root: &[u8; 32],
    enclave_measurement: &[u8],
) -> Result<KeystoreBody, KeystoreError> {
    let cbor = unseal_keystore(blob, provisioning_root, enclave_measurement)?;
    // Decode through a cursor and require the WHOLE plaintext to be consumed: a valid body prefix
    // followed by trailing bytes must fail closed (strict format contract, no best-effort parse).
    let mut cursor = std::io::Cursor::new(&cbor[..]);
    let body: KeystoreBody =
        ciborium::de::from_reader(&mut cursor).map_err(|_| KeystoreError::Cbor)?;
    if cursor.position() != cbor.len() as u64 {
        return Err(KeystoreError::Cbor);
    }
    body.validate()?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [0x11; 32];
    const MEAS_A: &[u8] = b"enclave-measurement-A";
    const MEAS_B: &[u8] = b"enclave-measurement-B";
    const NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

    fn body() -> Vec<u8> {
        // Stand-in for the deterministic-CBOR keystore body (opaque to this layer).
        b"agent-keystore-body: config + entries + counters + faucet + audit".to_vec()
    }

    #[test]
    fn seal_unseal_round_trip() {
        let blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        assert_eq!(&blob[..8], KEYSTORE_MAGIC.as_slice());
        assert_eq!(u16::from_be_bytes([blob[8], blob[9]]), KEYSTORE_FORMAT_VERSION);
        let out = unseal_keystore(&blob, &ROOT, MEAS_A).unwrap();
        assert_eq!(out.as_slice(), body().as_slice());
    }

    #[test]
    fn random_nonce_round_trips_and_differs() {
        let a = seal_keystore(&body(), &ROOT, MEAS_A).unwrap();
        let b = seal_keystore(&body(), &ROOT, MEAS_A).unwrap();
        assert_ne!(a, b, "random nonce ⇒ distinct sealed blobs");
        assert_eq!(unseal_keystore(&a, &ROOT, MEAS_A).unwrap().as_slice(), body().as_slice());
        assert_eq!(unseal_keystore(&b, &ROOT, MEAS_A).unwrap().as_slice(), body().as_slice());
    }

    #[test]
    fn unsupported_version_fails_closed_before_decrypt() {
        // An unknown FUTURE version (4 — the current version is 3) is rejected pre-decrypt (version is
        // AAD-bound). NB: must be 0x04, not 0x03 — 3 is now the live KEYSTORE_FORMAT_VERSION.
        let mut blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        blob[8] = 0x00;
        blob[9] = 0x04;
        assert_eq!(unseal_keystore(&blob, &ROOT, MEAS_A), Err(KeystoreError::UnsupportedVersion));
    }

    #[test]
    fn legacy_versions_rejected_after_bump() {
        // Both pre-bump versions are now legacy with no reader: v1 never shipped a real blob, and v2 is
        // superseded by v3 (which added cumulative_signing_budget). Each is a hard bump — a v1- or
        // v2-stamped blob fails closed before decrypt (the version is AAD-bound, so this is the entire
        // migration story). The live version (3) is exercised by the round-trip tests; 4 by
        // unsupported_version_fails_closed_before_decrypt.
        for legacy in [0x01u8, 0x02u8] {
            let mut blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
            blob[8] = 0x00;
            blob[9] = legacy;
            assert_eq!(
                unseal_keystore(&blob, &ROOT, MEAS_A),
                Err(KeystoreError::UnsupportedVersion),
                "legacy version {legacy} must be rejected pre-decrypt"
            );
        }
    }

    #[test]
    fn wrong_magic_rejected() {
        // A producer-style `2DHSMV1\0` blob (or any non-keystore magic) must fail on magic.
        let mut blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        blob[..8].copy_from_slice(b"2DHSMV1\0");
        assert_eq!(unseal_keystore(&blob, &ROOT, MEAS_A), Err(KeystoreError::BadMagic));
    }

    #[test]
    fn measurement_binding_rejects_other_enclave() {
        let blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        // Sealed under measurement A; a different measurement B must not unseal.
        assert_eq!(unseal_keystore(&blob, &ROOT, MEAS_B), Err(KeystoreError::MeasurementMismatch));
    }

    #[test]
    fn wrong_root_fails_decrypt() {
        let blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        let other_root = [0x99; 32];
        assert_eq!(unseal_keystore(&blob, &other_root, MEAS_A), Err(KeystoreError::Decrypt));
    }

    #[test]
    fn tampered_ciphertext_and_tag_fail() {
        let base = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        // Flip a ciphertext byte.
        let mut ct = base.clone();
        let i = HEADER_LEN + 1;
        ct[i] ^= 0xff;
        assert_eq!(unseal_keystore(&ct, &ROOT, MEAS_A), Err(KeystoreError::Decrypt));
        // Flip a tag byte (last byte).
        let mut tag = base.clone();
        let last = tag.len() - 1;
        tag[last] ^= 0xff;
        assert_eq!(unseal_keystore(&tag, &ROOT, MEAS_A), Err(KeystoreError::Decrypt));
    }

    #[test]
    fn truncated_blob_too_short() {
        let blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        // Below the header+tag floor ⇒ TooShort (rejected before any magic/version check).
        assert_eq!(unseal_keystore(&blob[..HEADER_LEN + TAG_LEN - 1], &ROOT, MEAS_A), Err(KeystoreError::TooShort));
        assert_eq!(unseal_keystore(&blob[..10], &ROOT, MEAS_A), Err(KeystoreError::TooShort));
        // Above the floor but with a truncated body ⇒ passes length/magic/version, fails AEAD.
        assert_eq!(unseal_keystore(&blob[..HEADER_LEN + TAG_LEN + 2], &ROOT, MEAS_A), Err(KeystoreError::Decrypt));
    }

    #[test]
    fn empty_measurement_refused() {
        assert_eq!(seal_keystore_with_nonce(&body(), &ROOT, b"", &NONCE), Err(KeystoreError::EmptyMeasurement));
        let blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        assert_eq!(unseal_keystore(&blob, &ROOT, b""), Err(KeystoreError::EmptyMeasurement));
    }

    #[test]
    fn kdf_domain_non_collision_with_producer() {
        // The keystore KDF (…agent-keystore-v1-key) must not collide with the producer KDF
        // (…pq-seal-v1-key) for identical (root, meas_digest): a blob sealed with the keystore key
        // must not decrypt under the producer key. We model the producer key derivation inline.
        let meas_digest = measurement_digest(MEAS_A);
        let keystore_key = derive_aead_key(&ROOT, &meas_digest);
        let producer_key: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"2d-hsm-pq-seal-v1-key");
            h.update(ROOT);
            h.update(meas_digest);
            h.finalize().into()
        };
        assert_ne!(&keystore_key[..], &producer_key[..], "keystore vs producer AEAD key must differ");
    }

    // --- keystore body (CBOR plaintext) ---

    fn sample_entry(purpose: KeyPurpose, secret_fill: u8, pub_fill: u8, key_ref_fill: u8) -> KeyEntry {
        let mut public_identity = vec![0x04u8; SECP256K1_UNCOMPRESSED_LEN];
        for b in public_identity[1..].iter_mut() {
            *b = pub_fill;
        }
        KeyEntry {
            key_ref: [key_ref_fill; 32],
            purpose,
            algorithm: KeyAlgorithm::Secp256k1,
            public_identity,
            secret_scalar: Zeroizing::new(vec![secret_fill; SECRET_SCALAR_LEN]),
            creation_metadata: CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 7 },
            backup_export_metadata: BackupExportMetadata::default(),
        }
    }

    fn sample_body() -> KeystoreBody {
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "mainnet".to_string(),
                admin_authority_pk: [0xa1; 32],
                recovery_authority_pk: [0xa2; 32],
                backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
                monotonic_treasury_config_version: 3,
                authority_epoch: 0,
                anchor_root: [0xa3; 32],
            },
            entries: vec![
                sample_entry(KeyPurpose::AgentFaucetTreasuryK1, 0x77, 0x33, 0x01),
                sample_entry(KeyPurpose::AgentTransferK1, 0x88, 0x44, 0x02),
            ],
            counters: vec![CounterEntry {
                authority: [0xa1; 32],
                environment_identifier: "mainnet".to_string(),
                scope_class: 1,
                scope_target: vec![0x10, 0x20, 0x30],
                highest_accepted_counter: 42,
            }],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 21000,
                max_effective_gas_fee_rate: 100,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
                cumulative_signing_budget: [0; 32],
            },
            audit: AuditRing { records: vec![], capacity: 256, last_exported_seq: 0, next_seq: 1 },
            freshness_epoch: 1,
            structural_version: 2,
            strict_recovery_counter: 0,
        }
    }

    #[test]
    fn body_round_trip() {
        let body = sample_body();
        let blob = seal_body(&body, &ROOT, MEAS_A).unwrap();
        let out = unseal_body(&blob, &ROOT, MEAS_A).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn advance_counter_inserts_updates_and_is_forward_only() {
        let mut body = sample_body();
        body.counters.clear();
        let auth = [0x11u8; 32];
        // First advance on an absent tuple inserts the row.
        body.advance_counter(&auth, 0, b"generate_transfer", 1).unwrap();
        assert_eq!(body.counters.len(), 1);
        assert_eq!(body.counters[0].highest_accepted_counter, 1);
        // A forward advance updates in place.
        body.advance_counter(&auth, 0, b"generate_transfer", 2).unwrap();
        assert_eq!(body.counters.len(), 1);
        assert_eq!(body.counters[0].highest_accepted_counter, 2);
        // A replay (==) or rollback (<) is refused — high-water is forward-only.
        assert_eq!(
            body.advance_counter(&auth, 0, b"generate_transfer", 2),
            Err(KeystoreError::CounterRegression)
        );
        assert_eq!(
            body.advance_counter(&auth, 0, b"generate_transfer", 1),
            Err(KeystoreError::CounterRegression)
        );
        // A different scope_target is a different tuple ⇒ a fresh row.
        body.advance_counter(&auth, 0, b"generate_faucet", 1).unwrap();
        assert_eq!(body.counters.len(), 2);
    }

    #[test]
    fn body_no_plaintext_secret_leak() {
        // The secret scalar is a CBOR byte value `0x<fill>` per element; for fill > 0x17 ciborium
        // emits the two-byte head+value pair `0x18 <fill>`, so the on-wire run of a 32-byte secret
        // of `fill` bytes is `(0x18 fill) × 32`. Search for THAT pattern (not a raw `[fill;32]`,
        // which never appears in the CBOR encoding and would make this test vacuous).
        let secret_pattern = |fill: u8| -> Vec<u8> {
            [0x18u8, fill].iter().copied().cycle().take(2 * SECRET_SCALAR_LEN).collect()
        };
        let body = sample_body(); // treasury secret 0x77×32, transfer secret 0x88×32

        // Sanity: the pattern IS present in the unencrypted CBOR plaintext — so a match in the
        // sealed blob below would be a real leak, and an absence is meaningful (not by construction).
        let mut plaintext = Vec::new();
        ciborium::ser::into_writer(&body, &mut plaintext).unwrap();
        for fill in [0x77u8, 0x88] {
            let p = secret_pattern(fill);
            assert!(
                plaintext.windows(p.len()).any(|w| w == p.as_slice()),
                "sanity: secret 0x{fill:02x} must be present in the plaintext CBOR"
            );
        }

        // The sealed (encrypted) blob must NOT contain either secret's on-wire encoding.
        let blob = seal_body(&body, &ROOT, MEAS_A).unwrap();
        for fill in [0x77u8, 0x88] {
            let p = secret_pattern(fill);
            assert!(
                !blob.windows(p.len()).any(|w| w == p.as_slice()),
                "secret 0x{fill:02x} must not appear in the sealed blob"
            );
        }
    }

    #[test]
    fn environment_identifier_rules() {
        for ok in ["mainnet", "test-net-2", "a", "x9", "2d"] {
            assert!(validate_environment_identifier(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", "-x", "x-", "a--b", "Main", "x_y", "под"] {
            assert_eq!(
                validate_environment_identifier(bad),
                Err(KeystoreError::InvalidEnvironmentId),
                "{bad:?} should be rejected"
            );
        }
        assert!(validate_environment_identifier(&"a".repeat(64)).is_ok());
        assert_eq!(
            validate_environment_identifier(&"a".repeat(65)),
            Err(KeystoreError::InvalidEnvironmentId)
        );
    }

    #[test]
    fn capacity_exceeded_rejected() {
        let mut body = sample_body();
        body.entries = (0..(MAX_TOTAL_KEY_ENTRIES + 1))
            .map(|_| sample_entry(KeyPurpose::AgentTransferK1, 0x01, 0x02, 0x03))
            .collect();
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::CapacityExceeded));
    }

    #[test]
    fn invalid_field_length_rejected() {
        let mut body = sample_body();
        body.entries[0].secret_scalar = Zeroizing::new(vec![0x77; SECRET_SCALAR_LEN - 1]);
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::InvalidFieldLength));

        let mut body2 = sample_body();
        body2.entries[0].public_identity = vec![0x04; SECP256K1_UNCOMPRESSED_LEN - 1];
        assert_eq!(seal_body(&body2, &ROOT, MEAS_A), Err(KeystoreError::InvalidFieldLength));
    }

    #[test]
    fn invalid_environment_id_rejected_on_seal() {
        let mut body = sample_body();
        body.config.environment_identifier = "Main--net".to_string();
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::InvalidEnvironmentId));
    }

    #[test]
    fn deny_unknown_fields_rejected() {
        use ciborium::value::Value;
        // A CreationMetadata map carrying an extra, unmodeled field must fail to decode.
        let with_extra = Value::Map(vec![
            (Value::from("config_version"), Value::from(1u64)),
            (Value::from("counter_snapshot"), Value::from(2u64)),
            (Value::from("batch_id"), Value::from(3u64)),
            (Value::from("bogus"), Value::from(9u64)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&with_extra, &mut buf).unwrap();
        let r: Result<CreationMetadata, _> = ciborium::de::from_reader(&buf[..]);
        assert!(r.is_err(), "deny_unknown_fields must reject the extra 'bogus' key");

        // Sanity: the same map without the extra key decodes.
        let clean = Value::Map(vec![
            (Value::from("config_version"), Value::from(1u64)),
            (Value::from("counter_snapshot"), Value::from(2u64)),
            (Value::from("batch_id"), Value::from(3u64)),
        ]);
        let mut buf2 = Vec::new();
        ciborium::ser::into_writer(&clean, &mut buf2).unwrap();
        let cm: CreationMetadata = ciborium::de::from_reader(&buf2[..]).unwrap();
        assert_eq!(cm, CreationMetadata { config_version: 1, counter_snapshot: 2, batch_id: 3 });
    }

    #[test]
    fn body_measurement_binding() {
        let body = sample_body();
        let blob = seal_body(&body, &ROOT, MEAS_A).unwrap();
        assert_eq!(unseal_body(&blob, &ROOT, MEAS_B), Err(KeystoreError::MeasurementMismatch));
    }

    #[test]
    fn counter_environment_must_match_config() {
        let mut body = sample_body();
        body.counters[0].environment_identifier = "testnet".to_string(); // valid format, wrong env
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::InvalidEnvironmentId));
    }

    #[test]
    fn wrapping_pubkey_length_enforced() {
        let mut body = sample_body();
        body.config.backup_recovery_wrapping_pubkey = vec![0xb0; 32]; // not ML-KEM-1024 size
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::InvalidFieldLength));
    }

    #[test]
    fn audit_records_cannot_exceed_capacity() {
        let mut body = sample_body();
        body.audit.capacity = 2;
        body.audit.records = vec![
            AuditRecord { seq: 1, op: 1, authority: [0; 32], counter: 1, config_version: 1 };
            3
        ];
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::CapacityExceeded));
    }

    #[test]
    fn audit_capacity_bounded() {
        let mut body = sample_body();
        body.audit.capacity = MAX_AUDIT_CAPACITY + 1;
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::CapacityExceeded));
    }

    #[test]
    fn duplicate_key_ref_rejected() {
        let mut body = sample_body();
        let r = body.entries[0].key_ref;
        body.entries[1].key_ref = r; // collide the two entries' opaque handles
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::DuplicateKeyRef));
    }

    #[test]
    fn public_identity_prefix_enforced() {
        let mut body = sample_body();
        body.entries[0].public_identity[0] = 0x02; // valid length, wrong SEC1 prefix
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::InvalidFieldLength));
    }

    #[test]
    fn duplicate_counter_tuple_rejected() {
        // 5b-2e marks-grammar invariant: one row per (authority, scope_class, scope_target). A duplicate
        // would make the monotonicity belt + counter updates order-dependent and would not round-trip
        // through `strict_decode_marks_payload` on the AdoptForward path. Enforced at the seal/unseal
        // boundary so a forged/corrupt blob (or a future caller that skips advance_counter's dedup) fails
        // closed. (advance_counter already dedups, so this is unreachable in normal operation.)
        let mut body = sample_body();
        let base = body.counters[0].clone();
        body.counters.push(base); // identical tuple — a second row with the same (auth, class, target)
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::DuplicateCounterTuple));
    }

    #[test]
    fn over_cap_scope_target_rejected() {
        // The marks decoder caps scope_target at MARKS_SCOPE_TARGET_MAX_LEN; validate() enforces the same
        // cap so the encode↔decode inverse holds (a body validate() accepts always round-trips through
        // encode_marks_payload → strict_decode_marks_payload). One byte over the cap fails closed.
        let cap = crate::agent_cbor::MARKS_SCOPE_TARGET_MAX_LEN;
        let mut body = sample_body();
        body.counters[0].scope_target = vec![0x01u8; cap + 1];
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::InvalidFieldLength));
        // The cap itself is accepted (inclusive), and the round-trip holds at the boundary.
        body.counters[0].scope_target = vec![0x01u8; cap];
        assert!(body.validate().is_ok(), "a scope_target exactly at the cap is valid");
        let decoded = crate::agent_cbor::strict_decode_marks_payload(
            &body.encode_marks_payload(),
            MAX_COUNTER_ENTRIES,
        )
        .expect("a validate()-accepted body round-trips through the strict marks decoder");
        assert_eq!(decoded.rows.len(), body.counters.len(), "every counter row survives the round-trip");
    }

    #[test]
    fn oversized_blob_rejected() {
        // MAX_TOTAL_KEY_ENTRIES entries (each with a unique key_ref) is within the count cap but
        // serializes past MAX_MESSAGE_SIZE, so seal_body must reject it as BlobTooLarge.
        let mut body = sample_body();
        body.entries = (0..MAX_TOTAL_KEY_ENTRIES)
            .map(|i| {
                let mut e = sample_entry(KeyPurpose::AgentTransferK1, 0x01, 0x02, 0x00);
                e.key_ref[..8].copy_from_slice(&(i as u64).to_le_bytes());
                e
            })
            .collect();
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::BlobTooLarge));
    }

    #[test]
    fn unseal_body_rejects_trailing_bytes() {
        // Seal a body's CBOR with extra trailing bytes through the raw envelope; unseal_body must
        // reject it (strict full-consumption parse), not accept the valid prefix.
        let body = sample_body();
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&body, &mut cbor).unwrap();
        cbor.extend_from_slice(b"trailing-garbage");
        let blob = seal_keystore(&cbor, &ROOT, MEAS_A).unwrap();
        assert_eq!(unseal_body(&blob, &ROOT, MEAS_A), Err(KeystoreError::Cbor));
    }

    #[test]
    fn blob_size_budget_boundary() {
        // A body whose sealed size lands ABOVE MAX_KEYSTORE_BLOB_SIZE but still WITHIN
        // MAX_MESSAGE_SIZE must be rejected — guards against a regression that checks
        // MAX_MESSAGE_SIZE (which the far-oversized test above would not catch).
        let sealed_size = |b: &KeystoreBody| -> usize {
            let mut v = Vec::new();
            ciborium::ser::into_writer(b, &mut v).unwrap();
            HEADER_LEN + v.len() + TAG_LEN
        };
        let target = MAX_KEYSTORE_BLOB_SIZE + 1; // smallest over-limit sealed size
        let cap = crate::agent_cbor::MARKS_SCOPE_TARGET_MAX_LEN; // validate() caps each scope_target here
        let mut body = sample_body();
        body.counters.clear();
        // Pad to ~1 MiB with MANY counter rows (distinct authority ⇒ unique tuples; each scope_target ≤
        // the per-row cap) — `validate()` now rejects a single over-cap scope_target before the blob-size
        // budget, so the old one-giant-row padding can't reach this gate. A half-cap padding length keeps
        // each row's increment < cap, so a final tuning row can land the sealed size on the exact byte.
        let pad_len = cap / 2;
        let make_row = |idx: u32, len: usize| {
            let mut authority = [0u8; 32];
            authority[..4].copy_from_slice(&idx.to_be_bytes());
            CounterEntry {
                authority,
                environment_identifier: "mainnet".to_string(),
                scope_class: 1,
                scope_target: vec![0x01u8; len],
                highest_accepted_counter: 1,
            }
        };
        let mut idx = 0u32;
        while sealed_size(&body) + cap < target {
            body.counters.push(make_row(idx, pad_len));
            idx += 1;
        }
        // Final row: linear-correct its scope_target length so the sealed size lands exactly on `target`
        // (the bstr length header is constant across this range, so sealed size is 1:1 in the length).
        body.counters.push(make_row(idx, pad_len));
        let s0 = sealed_size(&body);
        let last_len = (pad_len as isize + (target as isize - s0 as isize)) as usize;
        assert!(last_len >= 1 && last_len <= cap, "tuning length {last_len} must be within [1, cap]");
        body.counters.last_mut().unwrap().scope_target = vec![0x01u8; last_len];
        let s1 = sealed_size(&body);
        assert!(
            s1 > MAX_KEYSTORE_BLOB_SIZE && s1 <= crate::MAX_MESSAGE_SIZE as usize,
            "boundary blob sealed={s1} not in (MAX_KEYSTORE_BLOB_SIZE, MAX_MESSAGE_SIZE]"
        );
        // validate() PASSES (capped scope_targets, unique tuples) so seal reaches the blob-size budget.
        assert!(body.validate().is_ok(), "the padded body must pass validate() to reach the size budget");
        assert_eq!(seal_body(&body, &ROOT, MEAS_A), Err(KeystoreError::BlobTooLarge));
    }

    // --- frozen golden vector (format-drift guard) ---

    const GOLDEN_ROOT: [u8; 32] = [0x3c; 32];
    const GOLDEN_MEAS: &[u8] = b"golden-keystore-measurement-v1";
    const GOLDEN_NONCE: [u8; NONCE_LEN] = [0x5a; NONCE_LEN];

    fn golden_body() -> KeystoreBody {
        let mut public_identity = vec![0x04u8; SECP256K1_UNCOMPRESSED_LEN];
        for (i, b) in public_identity[1..].iter_mut().enumerate() {
            *b = i as u8;
        }
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "mainnet".to_string(),
                admin_authority_pk: [0x01; 32],
                recovery_authority_pk: [0x02; 32],
                backup_recovery_wrapping_pubkey: vec![0xab; ML_KEM_1024_ENCAPS_KEY_LEN],
                monotonic_treasury_config_version: 1,
                authority_epoch: 0,
                anchor_root: [0x03; 32],
            },
            entries: vec![KeyEntry {
                key_ref: [0x07; 32],
                purpose: KeyPurpose::AgentFaucetTreasuryK1,
                algorithm: KeyAlgorithm::Secp256k1,
                public_identity,
                secret_scalar: Zeroizing::new(vec![0x09; SECRET_SCALAR_LEN]),
                creation_metadata: CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 },
                backup_export_metadata: BackupExportMetadata::default(),
            }],
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

    /// Frozen `pq-agent-keystore-v1` golden vector: a fixed body sealed under fixed
    /// root/measurement/nonce yields a byte-stable blob. Any change to the sealed layout, the
    /// deterministic-CBOR body encoding, or a struct field flips this hash — if intentional, that is a
    /// `format_version` bump + a reviewed vector update (mirrors the producer `pq-seal-v1` fixture).
    #[test]
    fn golden_keystore_blob_is_frozen() {
        let body = golden_body();
        body.validate().unwrap();
        let mut cbor = Zeroizing::new(Vec::new());
        ciborium::ser::into_writer(&body, &mut *cbor).unwrap();
        let blob = seal_keystore_with_nonce(&cbor, &GOLDEN_ROOT, GOLDEN_MEAS, &GOLDEN_NONCE).unwrap();
        // Independently pin the on-wire format-version byte to the literal 3 (not just the const), so a
        // stealth const edit can't pass on the hash alone.
        assert_eq!(u16::from_be_bytes([blob[8], blob[9]]), 3, "sealed format_version must be 3");

        let digest: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&blob);
            h.finalize().into()
        };
        // format_version 3 (adds FaucetState::cumulative_signing_budget on top of v2's structural_version
        // + strict_recovery_counter); supersedes the v2 vector 4278 / 0e8e0df5… and the never-shipped v1
        // (4233 / c55edc09…) — see KEYSTORE_FORMAT_VERSION.
        assert_eq!(
            (blob.len(), hex::encode(digest)),
            (4339usize, "1f24fdafbecb85c8a0d9a56a27f4a4a2ff6363090315b39f654510a8dcac636d".to_string()),
            "keystore golden blob changed — if intentional, bump format_version + update this vector"
        );

        // Round-trip from the frozen inputs.
        let out = unseal_body(&blob, &GOLDEN_ROOT, GOLDEN_MEAS).unwrap();
        assert_eq!(out, body);
    }

    // ---- TASK-7.7 marks_digest (anchor key 6) frozen-grammar tests ----

    fn ctr(authority: u8, scope_class: u8, scope_target: &[u8], counter: u64) -> CounterEntry {
        CounterEntry {
            authority: [authority; 32],
            environment_identifier: "testnet".to_string(),
            scope_class,
            scope_target: scope_target.to_vec(),
            highest_accepted_counter: counter,
        }
    }

    /// A body reset to marks-genesis (empty counters, zero spends, zero recovery counter). Config env
    /// is pinned to "testnet" to match [`ctr`] so the env-fold precondition (row env == config env)
    /// holds for the rows the tests add.
    fn marks_body() -> KeystoreBody {
        let mut b = golden_body();
        b.config.environment_identifier = "testnet".to_string();
        b.counters.clear();
        b.faucet.cumulative_native_spend = [0; 32];
        b.faucet.lifetime_spend = [0; 32];
        b.strict_recovery_counter = 0;
        b
    }

    #[test]
    fn marks_payload_genesis_is_hand_derived() {
        // FROZEN grammar, hand-derived (anti-self-certification): map(4)
        //   A4 | k1 01 array(0) 80 | k2 02 bstr32 5820 00*32 | k3 03 bstr32 5820 00*32 | k4 04 uint 00
        let mut expected = vec![0xA4, 0x01, 0x80, 0x02, 0x58, 0x20];
        expected.extend([0u8; 32]);
        expected.extend([0x03, 0x58, 0x20]);
        expected.extend([0u8; 32]);
        expected.extend([0x04, 0x00]);
        assert_eq!(marks_body().encode_marks_payload(), expected);
    }

    #[test]
    fn marks_payload_strict_decoder_is_the_inverse_of_the_encoder() {
        // ANTI-SELF-CERTIFICATION (5b-2e): the new strict decoder must reconstruct EXACTLY the marks
        // surfaces the FROZEN encoder emitted — on the genesis golden AND a multi-row body — so the
        // AdoptForward hash-equality gate (re-hash of a candidate seeded from the decode) is sound.
        // This freezes the decoder against the encoder via a round-trip, NOT a hand vector.
        for body in [marks_body(), {
            let mut b = marks_body();
            b.counters = vec![ctr(1, 200, b"target-a", 5), ctr(2, 0, b"", 9_000_000_000)];
            b.faucet.cumulative_native_spend = [0xaa; 32];
            b.faucet.lifetime_spend = [0xbb; 32];
            b.strict_recovery_counter = 42;
            b
        }] {
            let payload = body.encode_marks_payload();
            let decoded =
                crate::agent_cbor::strict_decode_marks_payload(&payload, MAX_COUNTER_ENTRIES)
                    .expect("frozen encoder output strict-decodes");
            // Rows: env is folded out of the wire, so compare the non-env fields; the encoder sorts
            // rows by (authority, scope_class, scope_target), so compare against that same order.
            let mut sorted = body.counters.clone();
            sorted.sort_by(|a, b| {
                a.authority
                    .cmp(&b.authority)
                    .then(a.scope_class.cmp(&b.scope_class))
                    .then(a.scope_target.as_slice().cmp(b.scope_target.as_slice()))
            });
            assert_eq!(decoded.rows.len(), sorted.len());
            for (d, c) in decoded.rows.iter().zip(sorted.iter()) {
                assert_eq!(d.authority, c.authority);
                assert_eq!(d.scope_class, c.scope_class);
                assert_eq!(d.scope_target, c.scope_target);
                assert_eq!(d.highest_accepted_counter, c.highest_accepted_counter);
            }
            assert_eq!(decoded.cumulative_native_spend, body.faucet.cumulative_native_spend);
            assert_eq!(decoded.lifetime_spend, body.faucet.lifetime_spend);
            assert_eq!(decoded.strict_recovery_counter, body.strict_recovery_counter);
        }
    }

    #[test]
    fn seed_marks_forward_round_trips_the_digest_and_preserves_structural_version() {
        // THE property the AdoptForward hash gate (commit 4) relies on: a body SEEDED from the decode
        // of a payload P has compute_local_marks_digest() == SHA3(MARKS_DOMAIN ‖ P) == the source
        // body's digest. So re-hashing a candidate seeded from the host-relayed marks recovers the
        // anchor's signed digest IFF the marks are genuine.
        let mut source = marks_body();
        source.counters = vec![ctr(1, 200, b"target-a", 5), ctr(2, 0, b"", 9_000_000_000)];
        source.faucet.cumulative_native_spend = [0xaa; 32];
        source.faucet.lifetime_spend = [0xbb; 32];
        source.strict_recovery_counter = 42;
        let payload = source.encode_marks_payload();
        let decoded =
            crate::agent_cbor::strict_decode_marks_payload(&payload, MAX_COUNTER_ENTRIES).unwrap();

        // A fresh candidate: same config (so env-fold reconstructs identically) but cleared marks +
        // a DIFFERENT epoch and a DISTINCT structural_version we expect to survive untouched.
        let mut candidate = marks_body();
        candidate.freshness_epoch = 1;
        candidate.structural_version = 5;
        candidate.seed_marks_forward(&decoded, 99).expect("seed validates");

        assert_eq!(candidate.freshness_epoch, 99, "freshness_epoch bumped to the adopted epoch");
        assert_eq!(candidate.structural_version, 5, "structural_version UNCHANGED (counter/spend gap)");
        assert!(candidate.counters.iter().all(|c| c.environment_identifier == candidate.config.environment_identifier),
            "every reconstructed row carries the config env (env-fold inverse)");
        assert_eq!(
            candidate.compute_local_marks_digest(),
            source.compute_local_marks_digest(),
            "seeded candidate digest == source digest (the gate recovers the signed digest)"
        );
        let mut h = Sha3_256::new();
        h.update(MARKS_DOMAIN);
        h.update(&payload);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(candidate.compute_local_marks_digest(), expected);
    }

    #[test]
    fn seed_marks_forward_writes_absolutely_and_re_seals() {
        // Absolute write: seeding can LOWER a counter that advance_counter's forward-only guard would
        // reject — the seeder writes the authenticated marks verbatim (monotonicity is the caller's
        // belt, not the seeder's job).
        let mut body = marks_body();
        body.counters = vec![ctr(1, 0, b"x", 1_000)]; // local high-water 1000
        let lower = {
            let mut b = marks_body();
            b.counters = vec![ctr(1, 0, b"x", 5)]; // an absolute re-write to 5 (< 1000)
            let p = b.encode_marks_payload();
            crate::agent_cbor::strict_decode_marks_payload(&p, MAX_COUNTER_ENTRIES).unwrap()
        };
        body.seed_marks_forward(&lower, 2).expect("absolute seed validates");
        assert_eq!(body.counters[0].highest_accepted_counter, 5, "absolute write, not forward-only");

        // The seeded body re-seals + unseals (re-installable on the re-run). seal_body validates +
        // honors MAX_KEYSTORE_BLOB_SIZE; unseal recovers the exact body.
        let root = [0x42u8; 32];
        let meas = b"meas-xyz";
        let blob = seal_body(&body, &root, meas).expect("seeded body seals");
        assert!(blob.len() <= MAX_KEYSTORE_BLOB_SIZE);
        let unsealed = unseal_body(&blob, &root, meas).unwrap();
        assert_eq!(unsealed, body);
    }

    #[test]
    fn marks_digest_is_sha3_of_domain_then_payload() {
        // Pin the digest = SHA3-256(MARKS_DOMAIN ‖ payload) relationship (payload hand-verified above),
        // so no captured hex is needed.
        let b = marks_body();
        let mut h = Sha3_256::new();
        h.update(MARKS_DOMAIN);
        h.update(b.encode_marks_payload());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(b.compute_local_marks_digest(), expected);
    }

    #[test]
    fn marks_digest_is_sort_invariant() {
        let mut a = marks_body();
        a.counters = vec![ctr(1, 0, b"x", 5), ctr(2, 0, b"y", 7)];
        let mut b = marks_body();
        b.counters = vec![ctr(2, 0, b"y", 7), ctr(1, 0, b"x", 5)]; // reversed arrival order
        assert_eq!(a.compute_local_marks_digest(), b.compute_local_marks_digest());
    }

    #[test]
    fn marks_scope_class_encoded_as_cbor_uint_not_raw_byte() {
        let mut b = marks_body();
        b.counters = vec![ctr(1, 200, b"x", 5)];
        // 200 must appear as the CBOR major-0 1-byte head `0x18 0xC8`, NOT a raw 0xC8.
        let payload = b.encode_marks_payload();
        assert!(payload.windows(2).any(|w| w == [0x18, 0xC8]));
        let mut b0 = marks_body();
        b0.counters = vec![ctr(1, 0, b"x", 5)];
        assert_ne!(b.compute_local_marks_digest(), b0.compute_local_marks_digest());
    }

    #[test]
    fn marks_spend_is_fixed_width_bytes_distinct_from_recovery_uint() {
        let mut spend = marks_body();
        spend.faucet.cumulative_native_spend = {
            let mut a = [0u8; 32];
            a[31] = 1;
            a
        };
        let mut rec = marks_body();
        rec.strict_recovery_counter = 1;
        // spend=1 (a 32-byte string) and strict_recovery_counter=1 (a uint) are different contributions.
        assert_ne!(spend.compute_local_marks_digest(), rec.compute_local_marks_digest());
    }

    #[test]
    fn marks_scope_target_length_framing_is_injective() {
        // prefix-distinct scope_targets must not collide (length-prefixed byte strings).
        let mut a = marks_body();
        a.counters = vec![ctr(1, 0, &[0x10], 5)];
        let mut b = marks_body();
        b.counters = vec![ctr(1, 0, &[0x10, 0x00], 5)];
        assert_ne!(a.compute_local_marks_digest(), b.compute_local_marks_digest());
    }

    #[test]
    fn marks_environment_identifier_is_folded_out() {
        // Two bodies that differ ONLY in their (internally-consistent) environment — each body's row
        // env equals its own config env, satisfying the fold precondition. Since env is not encoded,
        // the digests are equal.
        let body_for = |env: &str| {
            let mut b = marks_body();
            b.config.environment_identifier = env.to_string();
            let mut row = ctr(1, 0, b"x", 5);
            row.environment_identifier = env.to_string();
            b.counters = vec![row];
            b
        };
        assert_eq!(
            body_for("env-aaa").compute_local_marks_digest(),
            body_for("env-bbb").compute_local_marks_digest()
        );
    }

    #[test]
    fn marks_digest_is_deterministic() {
        let b = marks_body();
        assert_eq!(b.compute_local_marks_digest(), b.compute_local_marks_digest());
    }

    #[test]
    fn marks_payload_is_decodable_canonical_cbor() {
        // The payload must be a genuinely decodable CBOR document (the seeding slice reconstructs rows
        // from it) — not just a hash preimage. Parse it back with ciborium and check the structure.
        let mut b = marks_body();
        b.counters = vec![ctr(1, 0, b"x", 5), ctr(2, 7, b"yy", 9)];
        b.faucet.cumulative_native_spend = {
            let mut a = [0u8; 32];
            a[31] = 3;
            a
        };
        b.strict_recovery_counter = 4;
        let payload = b.encode_marks_payload();
        let v: ciborium::value::Value = ciborium::de::from_reader(&payload[..]).unwrap();
        let ciborium::value::Value::Map(m) = v else {
            panic!("marks_payload must decode as a CBOR map");
        };
        assert_eq!(m.len(), 4, "exactly 4 keys (no spilled row items)");
        let mut key1 = None;
        for (k, val) in &m {
            if matches!(k, ciborium::value::Value::Integer(i) if u64::try_from(*i).ok() == Some(1)) {
                key1 = Some(val);
            }
        }
        let ciborium::value::Value::Array(rows) = key1.expect("key 1 present") else {
            panic!("key 1 must be an array of rows");
        };
        assert_eq!(rows.len(), 2, "two counter rows");
        for row in rows {
            let ciborium::value::Value::Array(fields) = row else {
                panic!("each row must be a CBOR array(4)");
            };
            assert_eq!(fields.len(), 4, "row = [authority, scope_class, scope_target, counter]");
        }
    }

    #[test]
    fn structural_version_zero_fails_validation() {
        let mut b = sample_body();
        b.structural_version = 0;
        assert_eq!(b.validate(), Err(KeystoreError::InvalidStructuralVersion));
        // and it fails closed through the seal/unseal path too (validate is called on both).
        b.structural_version = 1;
        assert!(b.validate().is_ok());
    }

    #[test]
    fn advance_counter_does_not_change_structural_version() {
        // A counter advance is an adoptable (anchor-reconstructable) gap — it MUST NOT bump
        // structural_version (else a benign spend would masquerade as a structural mutation).
        let mut b = sample_body();
        let sv = b.structural_version;
        b.advance_counter(&[9u8; 32], 0, b"scope-x", 1).unwrap();
        assert_eq!(b.structural_version, sv);
    }

    // ---- slice 6-2: atomic per-op commit bump ----

    #[test]
    fn advance_commit_epoch_structural_co_advances_both() {
        let mut b = sample_body();
        let (e, s) = (b.freshness_epoch, b.structural_version);
        b.advance_commit_epoch(true).unwrap();
        assert_eq!(b.freshness_epoch, e + 1, "structural op advances freshness_epoch");
        assert_eq!(b.structural_version, s + 1, "... AND structural_version, as one unit");
    }

    #[test]
    fn advance_commit_epoch_epoch_only_leaves_structural() {
        let mut b = sample_body();
        let (e, s) = (b.freshness_epoch, b.structural_version);
        b.advance_commit_epoch(false).unwrap();
        assert_eq!(b.freshness_epoch, e + 1, "epoch-only op advances freshness_epoch");
        assert_eq!(b.structural_version, s, "... and MUST NOT touch structural_version");
    }

    /// slice 6-6: the co-advance invariant pinned END-TO-END to `reconcile`'s asymmetry (this is what
    /// 6-6 delivers — the invariant + asymmetry tests; the gate itself was already live). The 6-2 atomic
    /// `advance_commit_epoch` advances epoch+structural TOGETHER (structural op) or epoch ALONE
    /// (epoch-only), NEVER structural alone. The invariant is scoped to ONE authoritative committed
    /// history: within it `structural_version` never advances without `freshness_epoch`, so the anchor
    /// and the local blob (the SAME history) at the SAME epoch MUST share structural — a divergence is
    /// corruption. (It is NOT "any two states at epoch N share structural": an epoch-only vs a structural
    /// op from the same start both reach epoch N+1 with DIFFERENT structural — which is exactly why
    /// `reconcile` compares structural EXPLICITLY rather than inferring it from epoch.) A state advanced
    /// from `local` therefore reconciles strictly by its op CLASS: EpochOnly keeps `local`'s structural ⇒
    /// `AdoptForward` (NO false StructuralGap — pre-6-4 a structural-ONLY bump could move structural
    /// without epoch and mis-fire); a structural advance moves structural ⇒ `StructuralGap` ⇒
    /// fail-closed/restore. Marks are held constant (asserted `== lmarks` before each reconcile, since
    /// `reconcile` IGNORES marks in the epoch-ahead arm) so the cases isolate the STRUCTURAL asymmetry.
    #[test]
    fn co_advance_invariant_drives_reconcile_asymmetry() {
        use crate::agent_anchor::{reconcile, AnchorState, FailReason, ReconcileDecision};
        let local = sample_body();
        let (le, ls) = (local.freshness_epoch, local.structural_version);
        let lmarks = local.compute_local_marks_digest();
        let anchor_of = |b: &KeystoreBody| AnchorState {
            epoch: b.freshness_epoch,
            structural_version: b.structural_version,
            marks_digest: b.compute_local_marks_digest(),
            chain_height: None,
            chain_block_hash: None,
        };

        // EPOCH-ONLY (counter/spend) advance + dropped seal ⇒ anchor ahead by epoch, SAME structural ⇒
        // AdoptForward. The co-advance guarantees structural stayed put, so this never mis-fires.
        let mut epoch_only = local.clone();
        epoch_only.advance_commit_epoch(false).unwrap();
        assert_eq!(epoch_only.structural_version, ls, "epoch-only kept structural (co-advance invariant)");
        assert_eq!(epoch_only.compute_local_marks_digest(), lmarks, "the bump leaves marks untouched (isolates the structural asymmetry; reconcile ignores marks in the epoch-ahead arm)");
        assert_eq!(
            reconcile(le, ls, &lmarks, &anchor_of(&epoch_only)),
            ReconcileDecision::AdoptForward { epoch: le + 1 },
            "epoch-only advance ⇒ AdoptForward, never a false StructuralGap"
        );

        // A RUN of epoch-only advances: epoch climbs, structural never moves ⇒ still AdoptForward (a run
        // of counter/spend ops cannot accumulate into a structural gap).
        let mut many = local.clone();
        for _ in 0..5 {
            many.advance_commit_epoch(false).unwrap();
        }
        assert_eq!(many.structural_version, ls, "5 epoch-only advances still keep structural");
        assert_eq!(many.compute_local_marks_digest(), lmarks, "5 bumps still leave marks untouched");
        assert_eq!(
            reconcile(le, ls, &lmarks, &anchor_of(&many)),
            ReconcileDecision::AdoptForward { epoch: le + 5 },
            "a run of epoch-only advances stays adopt-forwardable"
        );

        // STRUCTURAL (GENERATE_KEYS/CONFIGURE) advance ⇒ epoch AND structural move ⇒ the anchor can't
        // supply the new key/config material ⇒ StructuralGap ⇒ fail-closed/restore. THIS is the asymmetry.
        let mut structural = local.clone();
        structural.advance_commit_epoch(true).unwrap();
        assert_eq!(structural.structural_version, ls + 1, "structural op co-advanced structural");
        assert_eq!(structural.compute_local_marks_digest(), lmarks, "the bump leaves marks untouched — the gap is purely structural");
        assert_eq!(
            reconcile(le, ls, &lmarks, &anchor_of(&structural)),
            ReconcileDecision::FailClosed(FailReason::StructuralGap),
            "structural advance ⇒ StructuralGap ⇒ restore (asymmetric vs epoch-only)"
        );

        // The invariant's contrapositive WITHIN ONE history: the anchor and local (same committed history)
        // at the SAME epoch must share structural — so a structural divergence at equal epoch (a structural
        // bump WITHOUT the matching epoch bump — impossible under the atomic co-advance) is corruption ⇒
        // `reconcile`'s same-epoch arm fails closed `Inconsistent` by EXPLICIT comparison, never inferred
        // away. Marks held equal so the divergence is purely structural.
        let mut diverged = local.clone();
        diverged.structural_version = ls + 1;
        assert_eq!(diverged.compute_local_marks_digest(), lmarks, "marks held equal — the divergence is purely structural");
        assert_eq!(
            reconcile(le, ls, &lmarks, &anchor_of(&diverged)),
            ReconcileDecision::FailClosed(FailReason::Inconsistent),
            "same epoch + diverged structural ⇒ Inconsistent"
        );
    }

    #[test]
    fn advance_commit_epoch_overflow_on_either_aborts_both() {
        // epoch at u64::MAX → epoch overflow aborts; structural untouched (no partial mutation).
        let mut b = sample_body();
        b.freshness_epoch = u64::MAX;
        let s = b.structural_version;
        assert_eq!(b.advance_commit_epoch(true), Err(KeystoreError::MonotonicOverflow));
        assert_eq!(b.freshness_epoch, u64::MAX, "epoch unchanged on overflow");
        assert_eq!(b.structural_version, s, "structural untouched when epoch overflows");
        // structural at u64::MAX (epoch fine) → structural overflow aborts; epoch untouched BECAUSE both
        // increments are computed BEFORE either is written.
        let mut b = sample_body();
        b.structural_version = u64::MAX;
        let e = b.freshness_epoch;
        assert_eq!(b.advance_commit_epoch(true), Err(KeystoreError::MonotonicOverflow));
        assert_eq!(b.freshness_epoch, e, "epoch untouched when structural overflows (computed-before-assign)");
        assert_eq!(b.structural_version, u64::MAX, "no partial mutation");
        // EPOCH-ONLY path: the epoch check is UNCONDITIONAL (runs regardless of bumps_structural), so an
        // epoch at u64::MAX must overflow even when bumps_structural=false. Pins the unconditional-epoch
        // contract against a future refactor that gated the epoch check on bumps_structural.
        let mut b = sample_body();
        b.freshness_epoch = u64::MAX;
        let s = b.structural_version;
        assert_eq!(b.advance_commit_epoch(false), Err(KeystoreError::MonotonicOverflow));
        assert_eq!(b.freshness_epoch, u64::MAX, "epoch-only overflow leaves epoch unchanged");
        assert_eq!(b.structural_version, s, "epoch-only never touches structural");
    }

    #[test]
    fn advance_commit_epoch_leaves_marks_digest_unchanged() {
        // epoch/structural are NOT marks surfaces — the per-op commit records the marks digest (over
        // counter/spend/recovery, advanced by the op's handler) SEPARATELY from the epoch/structural
        // bump. A pure bump must therefore leave compute_local_marks_digest() unchanged.
        let mut b = sample_body();
        let before = b.compute_local_marks_digest();
        b.advance_commit_epoch(true).unwrap();
        assert_eq!(b.compute_local_marks_digest(), before, "epoch/structural are not marks surfaces");
    }

    #[test]
    fn body_differing_only_in_structural_version_serializes_differently() {
        let mut a = sample_body();
        let mut b = sample_body();
        a.structural_version = 5;
        b.structural_version = 6;
        let enc = |body: &KeystoreBody| {
            let mut v = Vec::new();
            ciborium::ser::into_writer(body, &mut v).unwrap();
            v
        };
        assert_ne!(enc(&a), enc(&b), "structural_version is actually encoded in the sealed body");
    }

    #[test]
    fn v2_body_missing_required_field_fails_closed() {
        // Removing a required v2 field from the body CBOR must FAIL to decode (no serde(default)
        // silent-zero of a security counter). Guards against a future `#[serde(default)]`.
        let body = sample_body();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let val: ciborium::value::Value = ciborium::de::from_reader(&buf[..]).unwrap();
        let ciborium::value::Value::Map(entries) = val else {
            panic!("KeystoreBody should serialize as a CBOR map");
        };
        for field in ["structural_version", "strict_recovery_counter"] {
            let mut shortened_entries = entries.clone();
            let before = shortened_entries.len();
            shortened_entries.retain(
                |(k, _)| !matches!(k, ciborium::value::Value::Text(s) if s == field),
            );
            assert_eq!(shortened_entries.len(), before - 1, "removed {field}");
            let mut shortened = Vec::new();
            ciborium::ser::into_writer(&ciborium::value::Value::Map(shortened_entries), &mut shortened)
                .unwrap();
            let res: Result<KeystoreBody, _> = ciborium::de::from_reader(&shortened[..]);
            assert!(res.is_err(), "body missing {field} must fail closed, not default");
        }
    }

    #[test]
    fn v3_body_missing_nested_faucet_budget_fails_closed() {
        // The format_version-3 `cumulative_signing_budget` lives INSIDE the nested `faucet` map, which
        // the top-level strip above cannot reach. FaucetState is `deny_unknown_fields` + has no
        // `serde(default)`, so a v3 body whose faucet map OMITS the budget must FAIL to decode — never
        // silently zero a (future §2 §-gate) spend ceiling. Guards against a `#[serde(default)]`
        // regression on the nested field specifically.
        let body = sample_body();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let mut entries = match ciborium::de::from_reader(&buf[..]).unwrap() {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("KeystoreBody should serialize as a CBOR map"),
        };
        let faucet_idx = entries
            .iter()
            .position(|(k, _)| matches!(k, ciborium::value::Value::Text(s) if s == "faucet"))
            .expect("body has a faucet field");
        let faucet_entries = match &mut entries[faucet_idx].1 {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("FaucetState should serialize as a CBOR map"),
        };
        let before = faucet_entries.len();
        faucet_entries.retain(
            |(k, _)| !matches!(k, ciborium::value::Value::Text(s) if s == "cumulative_signing_budget"),
        );
        assert_eq!(faucet_entries.len(), before - 1, "removed faucet.cumulative_signing_budget");
        let mut shortened = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut shortened).unwrap();
        assert!(
            ciborium::de::from_reader::<KeystoreBody, _>(&shortened[..]).is_err(),
            "v3 body missing faucet.cumulative_signing_budget must fail closed, not default"
        );
    }

    #[test]
    fn cumulative_signing_budget_is_not_a_marks_surface() {
        // Load-bearing anti-rollback invariant (design §3): the budget is STRUCTURAL config (raised by a
        // CONFIGURE_TREASURY refill_budget — a Structural op), deliberately EXCLUDED from the marks
        // payload. If it were a marks surface, a host that dropped the seal of a budget RAISE could have
        // it adopt-forwarded instead of StructuralGap→restored. Pin it DIRECTLY (not just via the frozen
        // marks goldens): mutating ONLY cumulative_signing_budget must leave the marks payload + digest
        // byte-identical.
        let base = sample_body();
        let mut bumped = base.clone();
        bumped.faucet.cumulative_signing_budget = [0xff; 32];
        assert_ne!(base.faucet, bumped.faucet, "precondition: the budget field actually differs");
        assert_eq!(
            base.encode_marks_payload(),
            bumped.encode_marks_payload(),
            "cumulative_signing_budget must NOT appear in the marks payload (structural cap, not a marks surface)"
        );
        assert_eq!(
            base.compute_local_marks_digest(),
            bumped.compute_local_marks_digest(),
            "cumulative_signing_budget must NOT affect marks_digest"
        );
    }
}
