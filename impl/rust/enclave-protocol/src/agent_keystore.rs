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
/// Current sealed-keystore format version (`u16`, big-endian on the wire). `2` denotes the
/// XChaCha20Poly1305 envelope + deterministic-CBOR body defined here **with the TASK-7.7
/// anti-rollback body fields** `structural_version` + `strict_recovery_counter` (added in v2). `1`
/// (the same envelope without those fields) **never shipped a real blob** — the only seal site is the
/// `agent-keygen-exec-preview`-gated GENERATE_KEYS path — so v2 is a hard bump with **no v1 reader**:
/// the pre-decrypt `UnsupportedVersion` rejection (version is AAD-bound) is the entire migration. Any
/// further incompatible on-disk layout/encoding change bumps this again. Note: the `KeystoreBody`
/// fields are feature-invariant (never `#[cfg]`-gated) so the sealed layout/golden is single-valued
/// across all feature combinations.
pub const KEYSTORE_FORMAT_VERSION: u16 = 2;

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
    /// The sealed blob would exceed the vsock `MAX_MESSAGE_SIZE` budget (entries/counters/audit too
    /// large to transmit to the host — Nitro has no persistent enclave storage).
    BlobTooLarge,
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
// Encoding note (sealed-body format, current format_version 2): this uses **deterministic** CBOR — serde emits struct fields
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
    /// `checked_add` → fail closed (never wrap). The GENERATE_KEYS bump is **LOCAL-ONLY and currently
    /// INERT**: advancing `freshness_epoch` + the anchor ack atomically with this bump (seal-before-emit)
    /// and the boot `reconcile` that reads this field are the deferred co-slice — nothing reads
    /// `structural_version` at boot yet.
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
    fn encode_marks_payload(&self) -> Vec<u8> {
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
        for c in &self.counters {
            // One sealed keystore is one environment: every counter row must carry the keystore's
            // own environment_identifier (format-valid AND equal to config), not just a well-formed
            // one. A mismatch is a structural invariant break (enclave bug / migration error).
            validate_environment_identifier(&c.environment_identifier)?;
            if c.environment_identifier != self.config.environment_identifier {
                return Err(KeystoreError::InvalidEnvironmentId);
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
        // An unknown FUTURE version (3) is rejected pre-decrypt (version is AAD-bound).
        let mut blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        blob[8] = 0x00;
        blob[9] = 0x03;
        assert_eq!(unseal_keystore(&blob, &ROOT, MEAS_A), Err(KeystoreError::UnsupportedVersion));
    }

    #[test]
    fn legacy_v1_version_rejected_after_bump() {
        // The pre-bump format_version 1 (never shipped a real blob) is now rejected: v2 is a hard bump
        // with no v1 reader, so a v1-stamped blob fails closed before decrypt.
        let mut blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        blob[8] = 0x00;
        blob[9] = 0x01;
        assert_eq!(unseal_keystore(&blob, &ROOT, MEAS_A), Err(KeystoreError::UnsupportedVersion));
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
        let mut body = sample_body();
        // scope_target bytes <= 0x17 encode as 1 CBOR byte each, and at ~1 MiB the CBOR array
        // header size is constant, so sealed size is linear in the padding length — one correction
        // pass lands it exactly on `target`.
        body.counters[0].scope_target = vec![0x01u8; target];
        let s0 = sealed_size(&body);
        let len1 = (target as isize + (target as isize - s0 as isize)) as usize;
        body.counters[0].scope_target = vec![0x01u8; len1];
        let s1 = sealed_size(&body);
        assert!(
            s1 > MAX_KEYSTORE_BLOB_SIZE && s1 <= crate::MAX_MESSAGE_SIZE as usize,
            "boundary blob sealed={s1} not in (MAX_KEYSTORE_BLOB_SIZE, MAX_MESSAGE_SIZE]"
        );
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
        // Independently pin the on-wire format-version byte to the literal 2 (not just the const), so a
        // stealth const edit can't pass on the hash alone.
        assert_eq!(u16::from_be_bytes([blob[8], blob[9]]), 2, "sealed format_version must be 2");

        let digest: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&blob);
            h.finalize().into()
        };
        // format_version 2 (adds structural_version + strict_recovery_counter); supersedes the v1
        // vector 4233 / c55edc09… (v1 never shipped a real blob — see KEYSTORE_FORMAT_VERSION).
        assert_eq!(
            (blob.len(), hex::encode(digest)),
            (4278usize, "0e8e0df50b19ecb34faf0d09a51d5224e3c044ad3e07ef961814f4dfd1382edc".to_string()),
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
            assert!(res.is_err(), "v2 body missing {field} must fail closed, not default");
        }
    }
}
