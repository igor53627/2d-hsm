//! PQ signing identity for the enclave (TASK-1 sealed-key provisioning).
//!
//! - **v1** (production reference): AEAD + measurement digest + provisioning root (see vsock spec §2.1).
//! - **v0** (test-only): XOR sketch; compiles only under `cargo test`.

use crate::ProtocolError;
use std::sync::Mutex;

#[cfg(feature = "ml-dsa-65")]
use crate::mldsa65::MlDsa65Signer;

/// ML-DSA-65 secret key length (FIPS 204 / pqcrypto-mldsa).
pub const ML_DSA65_SECRETKEY_LEN: usize = 4032;

/// Sealed blob format version 0 (test-only XOR sketch).
pub const SEALED_BLOB_V0_VERSION: u8 = 0;

/// Sealed blob format version 1 (AEAD + measurement binding).
pub const SEALED_BLOB_V1_VERSION: u8 = 1;

/// v1 sealed PQ blob magic (`2DHSMV1\0`).
#[cfg(feature = "ml-dsa-65")]
pub const SEALED_BLOB_V1_MAGIC: &[u8; 8] = b"2DHSMV1\0";

/// Runtime provisioning root from platform integration (vTPM / SNP VMPL / Nitro hook).
/// Set once at enclave boot before `install_sealed_pq_signer` when not using `reference-seal-v1-root`.
#[cfg(feature = "ml-dsa-65")]
static PLATFORM_PROVISIONING_ROOT: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// Install the v1 provisioning root once at enclave boot (production path).
///
/// The root must match the secret used by the offline provisioning tool that produced the
/// sealed blob. Do not accept this value from the untrusted host over vsock.
#[cfg(feature = "ml-dsa-65")]
pub fn set_pq_seal_v1_provisioning_root(root: [u8; 32]) -> Result<(), ProtocolError> {
    let mut guard = PLATFORM_PROVISIONING_ROOT
        .lock()
        .map_err(|_| ProtocolError::PqSigningUnavailable("pq seal platform root mutex poisoned"))?;
    if guard.is_some() {
        return Err(ProtocolError::PqSigningUnavailable(
            "PQ seal v1 provisioning root already configured",
        ));
    }
    *guard = Some(root);
    Ok(())
}

#[cfg(all(feature = "ml-dsa-65", test))]
pub(crate) fn reset_pq_seal_v1_provisioning_root_for_tests() {
    if let Ok(mut guard) = PLATFORM_PROVISIONING_ROOT.lock() {
        *guard = None;
    }
}
#[cfg(feature = "ml-dsa-65")]
const SEALED_BLOB_V0_MAGIC: &[u8; 8] = b"2DHSMV0\0";

static INSTALLED_SIGNER: Mutex<Option<InstalledSigner>> = Mutex::new(None);

#[cfg(test)]
#[allow(dead_code)]
static SEALED_SIGNER_TEST_SESSIONS: Mutex<usize> = Mutex::new(0);

#[cfg(test)]
pub fn begin_sealed_signer_test_session() {
    *SEALED_SIGNER_TEST_SESSIONS
        .lock()
        .expect("sealed test session mutex poisoned") += 1;
}

#[cfg(test)]
pub fn end_sealed_signer_test_session() {
    let mut count = SEALED_SIGNER_TEST_SESSIONS
        .lock()
        .expect("sealed test session mutex poisoned");
    *count = count.saturating_sub(1);
    if *count == 0 {
        reset_installed_pq_signer_for_tests();
    }
}

#[cfg(test)]
static SEALED_SIGNER_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Holds the global sealed-signer test lock for the whole test (prevents parallel leakage).
#[cfg(test)]
pub struct SealedSignerTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl SealedSignerTestGuard {
    pub fn acquire() -> Self {
        Self {
            _lock: SEALED_SIGNER_TEST_LOCK
                .lock()
                .expect("sealed signer test lock poisoned"),
        }
    }
}

#[cfg(test)]
impl Drop for SealedSignerTestGuard {
    fn drop(&mut self) {
        reset_installed_pq_signer_for_tests();
    }
}

enum InstalledSigner {
    #[cfg(feature = "ml-dsa-65")]
    MlDsa65(MlDsa65Signer),
}

#[cfg(feature = "ml-dsa-65")]
fn lock_installed_signer(
) -> Result<std::sync::MutexGuard<'static, Option<InstalledSigner>>, ProtocolError> {
    INSTALLED_SIGNER
        .lock()
        .map_err(|_| ProtocolError::PqSigningUnavailable("pq signer mutex poisoned"))
}

/// Whether an operational ML-DSA-65 signer is installed (sealed path).
pub fn is_sealed_signer_installed() -> bool {
    #[cfg(feature = "ml-dsa-65")]
    {
        return lock_installed_signer()
            .ok()
            .and_then(|g| g.as_ref().map(|_| ()))
            .is_some();
    }
    #[cfg(not(feature = "ml-dsa-65"))]
    false
}

/// Public key bytes of the installed sealed signer, if any.
#[cfg(feature = "ml-dsa-65")]
pub fn sealed_signer_public_key_bytes() -> Option<Vec<u8>> {
    let guard = lock_installed_signer().ok()?;
    guard.as_ref().map(|s| match s {
        InstalledSigner::MlDsa65(signer) => signer.public_key_bytes_owned(),
    })
}

#[cfg(not(feature = "ml-dsa-65"))]
pub fn sealed_signer_public_key_bytes() -> Option<Vec<u8>> {
    None
}

#[cfg(feature = "ml-dsa-65")]
fn install_signer_from_key_material(
    sk_bytes: &mut Vec<u8>,
    pk_bytes: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    // Hold the install mutex across verify+install to prevent concurrent overwrite (runbook invariant).
    let mut guard = lock_installed_signer()?;
    if guard.is_some() {
        zeroize_vec(sk_bytes);
        zeroize_vec(pk_bytes);
        return Err(ProtocolError::PqSigningUnavailable(
            "PQ signer already installed; enclave restart required to reprovision",
        ));
    }
    let signer = match MlDsa65Signer::from_verified_key_bytes(sk_bytes, pk_bytes) {
        Ok(signer) => signer,
        Err(e) => {
            zeroize_vec(sk_bytes);
            zeroize_vec(pk_bytes);
            return Err(e);
        }
    };
    zeroize_vec(sk_bytes);
    zeroize_vec(pk_bytes);
    *guard = Some(InstalledSigner::MlDsa65(signer));
    Ok(())
}

#[cfg(feature = "ml-dsa-65")]
fn unseal_sealed_keypair(
    sealed_blob: &[u8],
    enclave_measurement: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    if sealed_blob.len() >= 8 && &sealed_blob[..8] == SEALED_BLOB_V1_MAGIC {
        return v1_seal::unseal_mldsa65_keypair_v1(sealed_blob, enclave_measurement);
    }
    if sealed_blob.len() >= 8 && &sealed_blob[..8] == SEALED_BLOB_V0_MAGIC {
        #[cfg(test)]
        return v0_seal::unseal_mldsa65_keypair_v0(sealed_blob, enclave_measurement);
        #[cfg(not(test))]
        {
            let _ = enclave_measurement;
            return Err(ProtocolError::PqSigningUnavailable(
                "v0 XOR sealed PQ blobs are test-only",
            ));
        }
    }
    Err(ProtocolError::PqSigningUnavailable("unknown sealed PQ blob magic"))
}

/// Install the PQ signer from a sealed blob bound to `enclave_measurement`.
///
/// Must be called once during enclave boot before production signing. The host must
/// not be able to call this over vsock with arbitrary measurement — only the enclave
/// entrypoint supplies the attested measurement.
#[cfg(feature = "ml-dsa-65")]
pub fn install_sealed_pq_signer(
    sealed_blob: &[u8],
    enclave_measurement: &[u8],
) -> Result<(), ProtocolError> {
    use zeroize::Zeroizing;
    let (sk_bytes, pk_bytes) = unseal_sealed_keypair(sealed_blob, enclave_measurement)?;
    let mut sk_bytes = Zeroizing::new(sk_bytes);
    let mut pk_bytes = Zeroizing::new(pk_bytes);
    install_signer_from_key_material(sk_bytes.as_mut(), pk_bytes.as_mut())
}

#[cfg(not(feature = "ml-dsa-65"))]
pub fn install_sealed_pq_signer(
    _sealed_blob: &[u8],
    _enclave_measurement: &[u8],
) -> Result<(), ProtocolError> {
    Err(ProtocolError::PqSigningUnavailable(
        "sealed PQ signer requires ML-DSA-65 support (enable feature ml-dsa-65)",
    ))
}

/// Sign with the installed sealed signer.
#[cfg(feature = "ml-dsa-65")]
pub fn sign_ticket_hash_sealed(ticket_hash: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
    let guard = lock_installed_signer()?;
    let InstalledSigner::MlDsa65(signer) = guard.as_ref().ok_or(
        ProtocolError::PqSigningUnavailable("no sealed PQ signer installed"),
    )?;
    signer.sign_ticket_hash(ticket_hash)
}

/// Clears the installed signer (unit tests only).
#[cfg(test)]
pub fn reset_installed_pq_signer_for_tests() {
    if let Ok(mut guard) = INSTALLED_SIGNER.lock() {
        *guard = None;
    }
}

#[cfg(feature = "ml-dsa-65")]
fn zeroize_vec(buf: &mut Vec<u8>) {
    use zeroize::Zeroize;
    buf.zeroize();
}

#[cfg(feature = "ml-dsa-65")]
mod v1_seal {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use sha3::{Digest, Sha3_256};


    const MEAS_DIGEST_DOMAIN: &[u8] = b"2d-hsm-pq-seal-v1-meas";
    const AEAD_KEY_DOMAIN: &[u8] = b"2d-hsm-pq-seal-v1-key";
    const V1_NONCE_LEN: usize = 12;
    const V1_MEAS_DIGEST_LEN: usize = 32;
    /// `magic(8) + version(1) + meas_digest(32) + nonce(12)`
    pub const SEALED_BLOB_V1_HEADER_LEN: usize = 8 + 1 + V1_MEAS_DIGEST_LEN + V1_NONCE_LEN;
    const PLAINTEXT_LEN: usize = ML_DSA65_SECRETKEY_LEN + crate::ML_DSA65_PUBKEY_LEN;

    pub fn measurement_digest_v1(enclave_measurement: &[u8]) -> [u8; V1_MEAS_DIGEST_LEN] {
        let mut h = Sha3_256::new();
        h.update(MEAS_DIGEST_DOMAIN);
        h.update(enclave_measurement);
        h.finalize().into()
    }

    pub(crate) fn resolve_provisioning_root() -> Result<[u8; 32], ProtocolError> {
        let guard = super::PLATFORM_PROVISIONING_ROOT
            .lock()
            .map_err(|_| ProtocolError::PqSigningUnavailable("pq seal platform root mutex poisoned"))?;
        if let Some(root) = *guard {
            return Ok(root);
        }
        drop(guard);
        #[cfg(any(test, feature = "reference-seal-v1-root"))]
        {
            return Ok(*include_bytes!("../testvectors/seal_v1_provisioning_root.bin"));
        }
        #[cfg(not(any(test, feature = "reference-seal-v1-root")))]
        {
            Err(ProtocolError::PqSigningUnavailable(
                "PQ seal v1 provisioning root not configured (call set_pq_seal_v1_provisioning_root at enclave boot)",
            ))
        }
    }

    pub fn pq_seal_v1_expected_blob_len() -> usize {
        SEALED_BLOB_V1_HEADER_LEN + PLAINTEXT_LEN + 16
    }

    fn derive_aead_key(
        root: &[u8; 32],
        meas_digest: &[u8; V1_MEAS_DIGEST_LEN],
    ) -> Result<[u8; 32], ProtocolError> {
        let mut h = Sha3_256::new();
        h.update(AEAD_KEY_DOMAIN);
        h.update(root);
        h.update(meas_digest);
        Ok(h.finalize().into())
    }

    pub fn unseal_mldsa65_keypair_v1(
        sealed_blob: &[u8],
        enclave_measurement: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        use zeroize::Zeroizing;
        let root = Zeroizing::new(resolve_provisioning_root()?);
        unseal_mldsa65_keypair_v1_with_root(sealed_blob, enclave_measurement, &root)
    }

    pub fn unseal_mldsa65_keypair_v1_with_root(
        sealed_blob: &[u8],
        enclave_measurement: &[u8],
        provisioning_root: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        if enclave_measurement.is_empty() {
            return Err(ProtocolError::PqSigningUnavailable(
                "enclave measurement must be non-empty for v1 seal",
            ));
        }
        let expected_meas = measurement_digest_v1(enclave_measurement);
        if sealed_blob.len() != pq_seal_v1_expected_blob_len() {
            return Err(ProtocolError::PqSigningUnavailable("v1 sealed blob length mismatch"));
        }
        if sealed_blob.get(..8) != Some(super::SEALED_BLOB_V1_MAGIC) {
            return Err(ProtocolError::PqSigningUnavailable("invalid v1 sealed blob magic"));
        }
        if sealed_blob[8] != SEALED_BLOB_V1_VERSION {
            return Err(ProtocolError::PqSigningUnavailable(
                "unsupported v1 sealed blob version",
            ));
        }
        let stored_meas = &sealed_blob[9..9 + V1_MEAS_DIGEST_LEN];
        if stored_meas != expected_meas.as_slice() {
            return Err(ProtocolError::PqSigningUnavailable(
                "v1 sealed blob measurement digest does not match enclave measurement",
            ));
        }
        let key = derive_aead_key(provisioning_root, &expected_meas)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| ProtocolError::PqSigningUnavailable("v1 AEAD key invalid"))?;
        let nonce = Nonce::from_slice(&sealed_blob[41..SEALED_BLOB_V1_HEADER_LEN]);
        let aad = &sealed_blob[..9 + V1_MEAS_DIGEST_LEN];
        let mut plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed_blob[SEALED_BLOB_V1_HEADER_LEN..],
                    aad,
                },
            )
            .map_err(|_| ProtocolError::PqSigningUnavailable("v1 sealed blob decrypt failed"))?;
        if plain.len() != PLAINTEXT_LEN {
            zeroize_vec(&mut plain);
            return Err(ProtocolError::PqSigningUnavailable(
                "v1 sealed blob plaintext length mismatch",
            ));
        }
        let sk = plain[..ML_DSA65_SECRETKEY_LEN].to_vec();
        let pk = plain[ML_DSA65_SECRETKEY_LEN..].to_vec();
        zeroize_vec(&mut plain);
        Ok((sk, pk))
    }

    /// Seal ML-DSA-65 key material (offline provisioning). Caller supplies the provisioning root.
    #[cfg(any(test, feature = "pq-seal-provisioning"))]
    pub fn seal_mldsa65_keypair_v1_with_root(
        secret_key: &[u8],
        public_key: &[u8],
        enclave_measurement: &[u8],
        provisioning_root: &[u8; 32],
    ) -> Result<Vec<u8>, ProtocolError> {
        if secret_key.len() != ML_DSA65_SECRETKEY_LEN {
            return Err(ProtocolError::PqSigningUnavailable(
                "invalid ML-DSA-65 secret key length for v1 sealing",
            ));
        }
        if public_key.len() != crate::ML_DSA65_PUBKEY_LEN {
            return Err(ProtocolError::PqSigningUnavailable(
                "invalid ML-DSA-65 public key length for v1 sealing",
            ));
        }
        if enclave_measurement.is_empty() {
            return Err(ProtocolError::PqSigningUnavailable(
                "enclave measurement must be non-empty for v1 sealing",
            ));
        }
        MlDsa65Signer::from_verified_key_bytes(secret_key, public_key)?;
        let meas_digest = measurement_digest_v1(enclave_measurement);
        let key = derive_aead_key(provisioning_root, &meas_digest)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| ProtocolError::PqSigningUnavailable("v1 AEAD key invalid"))?;

        use zeroize::Zeroizing;
        let mut plain = Zeroizing::new(Vec::with_capacity(
            ML_DSA65_SECRETKEY_LEN + crate::ML_DSA65_PUBKEY_LEN,
        ));
        plain.extend_from_slice(secret_key);
        plain.extend_from_slice(public_key);

        let mut nonce = [0u8; V1_NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| {
            ProtocolError::PqSigningUnavailable("CSPRNG unavailable for v1 seal nonce")
        })?;

        let mut out = Vec::with_capacity(pq_seal_v1_expected_blob_len());
        out.extend_from_slice(super::SEALED_BLOB_V1_MAGIC);
        out.push(SEALED_BLOB_V1_VERSION);
        out.extend_from_slice(&meas_digest);
        out.extend_from_slice(&nonce);
        let aad = &out[..9 + V1_MEAS_DIGEST_LEN];
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain.as_ref(),
                    aad,
                },
            )
            .map_err(|_| ProtocolError::PqSigningUnavailable("v1 sealed blob encrypt failed"))?;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Seal using the configured provisioning root (platform, reference feature, or `cargo test`).
    #[cfg(any(test, feature = "pq-seal-provisioning"))]
    pub fn seal_mldsa65_keypair_v1(
        secret_key: &[u8],
        public_key: &[u8],
        enclave_measurement: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let root = resolve_provisioning_root()?;
        seal_mldsa65_keypair_v1_with_root(secret_key, public_key, enclave_measurement, &root)
    }

    /// Check that a sealed blob decrypts for the given measurement and root (does not return key material).
    #[cfg(any(test, feature = "pq-seal-provisioning"))]
    pub fn verify_sealed_blob_v1_with_root(
        sealed_blob: &[u8],
        enclave_measurement: &[u8],
        provisioning_root: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        use zeroize::Zeroizing;
        let (sk, pk) =
            unseal_mldsa65_keypair_v1_with_root(sealed_blob, enclave_measurement, provisioning_root)?;
        let sk = Zeroizing::new(sk);
        let pk = Zeroizing::new(pk);
        MlDsa65Signer::from_verified_key_bytes(sk.as_ref(), pk.as_ref())?;
        Ok(())
    }
}

#[cfg(feature = "ml-dsa-65")]
pub use v1_seal::{
    measurement_digest_v1 as pq_seal_v1_measurement_digest, pq_seal_v1_expected_blob_len,
    SEALED_BLOB_V1_HEADER_LEN,
};
#[cfg(all(feature = "ml-dsa-65", any(test, feature = "pq-seal-provisioning")))]
pub use v1_seal::{
    seal_mldsa65_keypair_v1, seal_mldsa65_keypair_v1_with_root,
    verify_sealed_blob_v1_with_root,
};

/// Whether a platform or reference provisioning root is available for v1 unseal.
#[cfg(feature = "ml-dsa-65")]
pub fn is_pq_seal_v1_provisioning_root_configured() -> bool {
    v1_seal::resolve_provisioning_root().is_ok()
}

#[cfg(all(feature = "ml-dsa-65", test))]
mod v0_seal {
    use super::*;
    use sha3::{Digest, Keccak256};

    pub const SEALED_BLOB_V0_MAGIC: &[u8; 8] = b"2DHSMV0\0";
    const SEAL_DOMAIN_V0: &[u8] = b"2d-hsm-pq-seal-v0";
    pub const SEALED_BLOB_V0_HEADER_LEN: usize = 11;

    fn xor_stream_v0(data: &[u8], enclave_measurement: &[u8]) -> Vec<u8> {
        let mut stream = Vec::with_capacity(data.len());
        let mut counter: u64 = 0;
        while stream.len() < data.len() {
            let mut h = Keccak256::new();
            h.update(SEAL_DOMAIN_V0);
            h.update(enclave_measurement);
            h.update(counter.to_be_bytes());
            stream.extend_from_slice(&h.finalize());
            counter += 1;
        }
        stream.truncate(data.len());
        data.iter()
            .zip(stream.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    pub fn seal_mldsa65_keypair_v0(
        secret_key: &[u8],
        public_key: &[u8],
        enclave_measurement: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if secret_key.len() != ML_DSA65_SECRETKEY_LEN {
            return Err(ProtocolError::PqSigningUnavailable(
                "invalid ML-DSA-65 secret key length for sealing",
            ));
        }
        if public_key.len() != crate::ML_DSA65_PUBKEY_LEN {
            return Err(ProtocolError::PqSigningUnavailable(
                "invalid ML-DSA-65 public key length for sealing",
            ));
        }
        if enclave_measurement.is_empty() {
            return Err(ProtocolError::PqSigningUnavailable(
                "enclave measurement must be non-empty for sealing",
            ));
        }
        let meas_len: u16 = enclave_measurement.len().try_into().map_err(|_| {
            ProtocolError::PqSigningUnavailable("enclave measurement too large for v0 blob")
        })?;
        let mut material = Vec::with_capacity(ML_DSA65_SECRETKEY_LEN + crate::ML_DSA65_PUBKEY_LEN);
        material.extend_from_slice(secret_key);
        material.extend_from_slice(public_key);
        let cipher = xor_stream_v0(&material, enclave_measurement);
        let mut out =
            Vec::with_capacity(SEALED_BLOB_V0_HEADER_LEN + enclave_measurement.len() + cipher.len());
        out.extend_from_slice(SEALED_BLOB_V0_MAGIC);
        out.push(SEALED_BLOB_V0_VERSION);
        out.extend_from_slice(&meas_len.to_be_bytes());
        out.extend_from_slice(enclave_measurement);
        out.extend_from_slice(&cipher);
        Ok(out)
    }

    pub fn unseal_mldsa65_keypair_v0(
        sealed_blob: &[u8],
        enclave_measurement: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        let payload_len = ML_DSA65_SECRETKEY_LEN + crate::ML_DSA65_PUBKEY_LEN;
        if sealed_blob.len() < SEALED_BLOB_V0_HEADER_LEN + payload_len {
            return Err(ProtocolError::PqSigningUnavailable("sealed blob too short"));
        }
        if sealed_blob.get(..8) != Some(SEALED_BLOB_V0_MAGIC) {
            return Err(ProtocolError::PqSigningUnavailable("invalid sealed blob magic"));
        }
        if sealed_blob[8] != SEALED_BLOB_V0_VERSION {
            return Err(ProtocolError::PqSigningUnavailable(
                "unsupported sealed blob version",
            ));
        }
        let meas_len = u16::from_be_bytes([sealed_blob[9], sealed_blob[10]]) as usize;
        let header = SEALED_BLOB_V0_HEADER_LEN + meas_len;
        if sealed_blob.len() != header + payload_len {
            return Err(ProtocolError::PqSigningUnavailable("sealed blob length mismatch"));
        }
        let stored_meas = &sealed_blob[11..header];
        if stored_meas != enclave_measurement {
            return Err(ProtocolError::PqSigningUnavailable(
                "sealed blob measurement does not match enclave measurement",
            ));
        }
        let mut plain = xor_stream_v0(&sealed_blob[header..], enclave_measurement);
        let sk = plain[..ML_DSA65_SECRETKEY_LEN].to_vec();
        let pk = plain[ML_DSA65_SECRETKEY_LEN..].to_vec();
        super::zeroize_vec(&mut plain);
        Ok((sk, pk))
    }
}

#[cfg(all(feature = "ml-dsa-65", test))]
pub use v0_seal::{seal_mldsa65_keypair_v0, unseal_mldsa65_keypair_v0};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "ml-dsa-65", any(test, feature = "reference-seal-v1-root")))]
    #[test]
    fn v1_seal_unseal_roundtrip_and_tamper_fails() {
        let _guard = SealedSignerTestGuard::acquire();
        let sk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testvectors/mldsa65_reference_sk.bin"),
        )
        .unwrap();
        let pk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testvectors/mldsa65_reference_pk.bin"),
        )
        .unwrap();
        let measurement = b"enclave-measurement-placeholder";
        let blob = seal_mldsa65_keypair_v1(&sk, &pk, measurement).unwrap();
        let (back_sk, back_pk) = v1_seal::unseal_mldsa65_keypair_v1(&blob, measurement).unwrap();
        assert_eq!(back_sk, sk);
        assert_eq!(back_pk, pk);
        assert!(v1_seal::unseal_mldsa65_keypair_v1(&blob, b"wrong-meas").is_err());
        let mut tampered = blob.clone();
        tampered[v1_seal::SEALED_BLOB_V1_HEADER_LEN] ^= 0xFF;
        assert!(v1_seal::unseal_mldsa65_keypair_v1(&tampered, measurement).is_err());
    }

    #[cfg(feature = "ml-dsa-65")]
    #[test]
    fn v1_install_enables_signing_and_get_measurement() {
        let _guard = SealedSignerTestGuard::acquire();
        reset_installed_pq_signer_for_tests();
        let measurement = b"enclave-measurement-placeholder";
        let sk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/mldsa65_reference_sk.bin"),
        )
        .unwrap();
        let pk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/mldsa65_reference_pk.bin"),
        )
        .unwrap();
        let blob = seal_mldsa65_keypair_v1(&sk, &pk, measurement).unwrap();
        install_sealed_pq_signer(&blob, measurement).unwrap();
        assert!(is_sealed_signer_installed());
        assert_eq!(
            sealed_signer_public_key_bytes().as_deref(),
            Some(pk.as_slice())
        );
        let hash = [2u8; 32];
        let sig = sign_ticket_hash_sealed(&hash).unwrap();
        assert_eq!(sig.len(), crate::ML_DSA65_SIGNATURE_LEN);
    }

    #[cfg(all(feature = "ml-dsa-65", test))]
    #[test]
    fn seal_unseal_roundtrip_wrong_measurement_fails_v0() {
        let _guard = SealedSignerTestGuard::acquire();
        let sk = vec![0xABu8; ML_DSA65_SECRETKEY_LEN];
        let pk = vec![0xCDu8; crate::ML_DSA65_PUBKEY_LEN];
        let measurement = b"enclave-measurement-placeholder";
        let blob = seal_mldsa65_keypair_v0(&sk, &pk, measurement).unwrap();
        let (back_sk, back_pk) = unseal_mldsa65_keypair_v0(&blob, measurement).unwrap();
        assert_eq!(back_sk, sk);
        assert_eq!(back_pk, pk);
        assert!(unseal_mldsa65_keypair_v0(&blob, b"wrong").is_err());
    }

    #[cfg(feature = "ml-dsa-65")]
    #[test]
    fn platform_provisioning_root_install_and_sign() {
        let _guard = SealedSignerTestGuard::acquire();
        reset_installed_pq_signer_for_tests();
        reset_pq_seal_v1_provisioning_root_for_tests();
        let root: [u8; 32] =
            *include_bytes!("../testvectors/seal_v1_provisioning_root.bin");
        set_pq_seal_v1_provisioning_root(root).unwrap();
        assert!(set_pq_seal_v1_provisioning_root(root).is_err());
        assert!(is_pq_seal_v1_provisioning_root_configured());

        let measurement = b"enclave-measurement-placeholder";
        let sk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testvectors/mldsa65_reference_sk.bin"),
        )
        .unwrap();
        let pk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("testvectors/mldsa65_reference_pk.bin"),
        )
        .unwrap();
        let blob =
            seal_mldsa65_keypair_v1_with_root(&sk, &pk, measurement, &root).unwrap();
        verify_sealed_blob_v1_with_root(&blob, measurement, &root).unwrap();
        install_sealed_pq_signer(&blob, measurement).unwrap();
        let hash = [9u8; 32];
        let sig = sign_ticket_hash_sealed(&hash).unwrap();
        assert_eq!(sig.len(), crate::ML_DSA65_SIGNATURE_LEN);
    }

    #[cfg(feature = "ml-dsa-65")]
    #[test]
    fn install_rejects_second_install_without_reset() {
        let _guard = SealedSignerTestGuard::acquire();
        reset_installed_pq_signer_for_tests();
        let measurement = b"enclave-measurement-placeholder";
        let sk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/mldsa65_reference_sk.bin"),
        )
        .unwrap();
        let pk = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testvectors/mldsa65_reference_pk.bin"),
        )
        .unwrap();
        let blob = seal_mldsa65_keypair_v1(&sk, &pk, measurement).unwrap();
        install_sealed_pq_signer(&blob, measurement).unwrap();
        assert!(install_sealed_pq_signer(&blob, measurement).is_err());
    }
}