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
//! The plaintext here is opaque bytes: the canonical-CBOR keystore body (config/identity, key
//! entries, counter high-water table, faucet state, audit ring) is (de)serialized in a later
//! slice and sealed/unsealed through this envelope. Multi-byte header integers are big-endian.
//!
//! Built only under the `agent-gateway` feature, alongside the secp256k1 backend.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
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
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `magic(8) + format_version(2) + meas_digest(32) + nonce(12)`.
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
/// canonical-CBOR keystore plaintext; this function does not interpret it.
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
        ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| KeystoreError::AeadKey)?;

    let mut out = Vec::with_capacity(HEADER_LEN + body.len() + TAG_LEN);
    out.extend_from_slice(KEYSTORE_MAGIC);
    out.extend_from_slice(&KEYSTORE_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&meas_digest);
    out.extend_from_slice(nonce);
    // AAD = header minus nonce (magic ‖ version ‖ meas_digest); binds them to the ciphertext.
    let ct = {
        let aad = &out[..AAD_LEN];
        cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: body, aad })
            .map_err(|_| KeystoreError::Decrypt)?
    };
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Seal an opaque keystore body, drawing the 12-byte nonce from the platform CSPRNG.
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
        ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| KeystoreError::AeadKey)?;
    let nonce = Nonce::from_slice(&blob[AAD_LEN..HEADER_LEN]);
    let aad = &blob[..AAD_LEN];
    let plain = cipher
        .decrypt(nonce, Payload { msg: &blob[HEADER_LEN..], aad })
        .map_err(|_| KeystoreError::Decrypt)?;
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [0x11; 32];
    const MEAS_A: &[u8] = b"enclave-measurement-A";
    const MEAS_B: &[u8] = b"enclave-measurement-B";
    const NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

    fn body() -> Vec<u8> {
        // Stand-in for the canonical-CBOR keystore body (opaque to this layer).
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
}
