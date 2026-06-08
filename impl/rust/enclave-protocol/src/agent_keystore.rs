//! Sealed keystore envelope for the Agent Gateway signer (TASK-7.6.2 / TASK-7.2 format).
//!
//! This module is the **`pq-agent-keystore-v1` seal/unseal envelope**: the AEAD wrapping layer
//! that binds the keystore body to the per-enclave seal root + measurement, exactly mirroring the
//! producer `pq-seal-v1` primitives in `pq_signer.rs` (ChaCha20Poly1305 + `SHA3-256(domain ‖ root
//! ‖ meas_digest)` KDF, `magic ‖ version ‖ meas_digest ‖ nonce` header with `AAD = header − nonce`,
//! fail-closed-on-unknown-version-before-decrypt, `Zeroizing` plaintext). It deliberately uses a
//! **distinct magic and KDF/measurement domains** so a producer blob can never be parsed as a
//! keystore and the keystore AEAD key can never collide with the producer key derived from the
//! same SNP root (format-/key-level role isolation — see
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
use zeroize::Zeroizing;

/// `b"2DAGTKS\0"` — distinct from the producer `b"2DHSMV1\0"` so the two blob families can never
/// be cross-parsed (format-level role separation, AC#2).
pub const KEYSTORE_MAGIC: &[u8; 8] = b"2DAGTKS\0";
/// Current sealed-keystore format version (`u16`, big-endian on the wire).
pub const KEYSTORE_FORMAT_VERSION: u16 = 1;

const MEAS_DIGEST_DOMAIN: &[u8] = b"2d-hsm-agent-keystore-v1-meas";
const AEAD_KEY_DOMAIN: &[u8] = b"2d-hsm-agent-keystore-v1-key";

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
    /// CSPRNG unavailable when generating a seal nonce.
    Csprng,
    /// Canonical-CBOR (de)serialization of the keystore body failed (incl. deny-unknown-fields).
    Cbor,
    /// `environment_identifier` failed the TASK-7.1 §10.6 rules (1..=64, `[a-z0-9-]`, no
    /// leading/trailing/double hyphen).
    InvalidEnvironmentId,
    /// Key-entry count over `MAX_TOTAL_KEY_ENTRIES` (AC#5 capacity guard).
    CapacityExceeded,
    /// A fixed-length byte field (public identity 65 B, secret scalar 32 B) had the wrong length.
    InvalidFieldLength,
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
    Zeroizing::new(h.finalize().into())
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
            .map_err(|_| KeystoreError::Decrypt)?
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
// Encoding note (format_version 1): this uses **deterministic** CBOR — serde emits struct fields
// in declaration order and every collection is a `Vec` (no map/HashMap), so a given body always
// encodes to the same bytes (the golden vector locks this). It is NOT RFC 8949 *canonical* CBOR,
// and byte fields (`[u8; N]`, `Vec<u8>`) serialize as CBOR integer-arrays, not byte strings.
// Switching to byte-string encoding (smaller) or strict canonical ordering would change the bytes
// and is therefore a deliberate `format_version` bump + golden-vector update, never a silent edit.
// ===========================================================================================

/// Max key entries sealed in one keystore (AC#5 total-capacity guard, enforced before seal).
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

const SECP256K1_UNCOMPRESSED_LEN: usize = 65;
const SECRET_SCALAR_LEN: usize = 32;

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
    /// mechanism. Installed at provisioning; changing it is a reviewed `format_version` bump.
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
    /// authenticated); 7.7 advances it against the pinned [`KeystoreConfig::anchor_root`] and
    /// rejects any unsealed blob whose epoch is behind the authenticated anchor-current.
    pub freshness_epoch: u64,
}

/// `environment_identifier` rules (TASK-7.1 §10.6): UTF-8, length `1..=64`, `[a-z0-9-]`, no
/// leading/trailing hyphen, no doubled hyphen.
fn validate_environment_identifier(s: &str) -> Result<(), KeystoreError> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return Err(KeystoreError::InvalidEnvironmentId);
    }
    if b[0] == b'-' || b[b.len() - 1] == b'-' {
        return Err(KeystoreError::InvalidEnvironmentId);
    }
    let mut prev_hyphen = false;
    for &c in b {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-';
        if !ok {
            return Err(KeystoreError::InvalidEnvironmentId);
        }
        if c == b'-' && prev_hyphen {
            return Err(KeystoreError::InvalidEnvironmentId);
        }
        prev_hyphen = c == b'-';
    }
    Ok(())
}

impl KeystoreBody {
    /// Structural validation enforced on both seal (before commit) and unseal (after decrypt):
    /// environment-id rules, total-capacity (AC#5), and fixed byte-field lengths.
    pub fn validate(&self) -> Result<(), KeystoreError> {
        validate_environment_identifier(&self.config.environment_identifier)?;
        if self.entries.len() > MAX_TOTAL_KEY_ENTRIES
            || self.counters.len() > MAX_COUNTER_ENTRIES
        {
            return Err(KeystoreError::CapacityExceeded);
        }
        for e in &self.entries {
            if e.public_identity.len() != SECP256K1_UNCOMPRESSED_LEN {
                return Err(KeystoreError::InvalidFieldLength);
            }
            if e.secret_scalar.len() != SECRET_SCALAR_LEN {
                return Err(KeystoreError::InvalidFieldLength);
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
    let body: KeystoreBody =
        ciborium::de::from_reader(&cbor[..]).map_err(|_| KeystoreError::Cbor)?;
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
        let mut blob = seal_keystore_with_nonce(&body(), &ROOT, MEAS_A, &NONCE).unwrap();
        blob[8] = 0x00;
        blob[9] = 0x02; // version 2 (unknown)
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
                backup_recovery_wrapping_pubkey: vec![0xab, 0xcd, 0xef, 0x10],
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

        let digest: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&blob);
            h.finalize().into()
        };
        assert_eq!(
            (blob.len(), hex::encode(digest)),
            (1102usize, "18700ccb7c446e93bc4798997e440fc74f72383f86d90e8ed749305fc408afdc".to_string()),
            "keystore golden blob changed — if intentional, bump format_version + update this vector"
        );

        // Round-trip from the frozen inputs.
        let out = unseal_body(&blob, &GOLDEN_ROOT, GOLDEN_MEAS).unwrap();
        assert_eq!(out, body);
    }
}
