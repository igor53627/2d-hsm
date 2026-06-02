//! PQ signing identity for the enclave (TASK-1 sealed-key sketch).
//!
//! Production TEE replaces v0 XOR helpers with platform sealing (vTPM, SNP VMPL, etc.).
//! v0 is **reference-only** and compiles only under `cargo test`.

use crate::ProtocolError;
use std::sync::Mutex;

#[cfg(feature = "ml-dsa-65")]
use crate::mldsa65::MlDsa65Signer;

/// ML-DSA-65 secret key length (FIPS 204 / pqcrypto-mldsa).
pub const ML_DSA65_SECRETKEY_LEN: usize = 4032;

/// Sealed blob format version 0 (test-only XOR sketch).
pub const SEALED_BLOB_V0_VERSION: u8 = 0;

/// Sealed blob format version 1 (production — not implemented yet).
pub const SEALED_BLOB_V1_VERSION: u8 = 1;

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
    lock_installed_signer()
        .ok()
        .and_then(|g| g.as_ref().map(|_| ()))
        .is_some()
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
    #[cfg(not(test))]
    {
        let _ = (sealed_blob, enclave_measurement);
        if sealed_blob.first() == Some(&SEALED_BLOB_V1_VERSION) {
            return Err(ProtocolError::PqSigningUnavailable(
                "production PQ seal format (v1) not implemented",
            ));
        }
        return Err(ProtocolError::PqSigningUnavailable(
            "v0 XOR sealed PQ blobs are test-only; production seal format not implemented",
        ));
    }
    #[cfg(test)]
    {
        let (mut sk_bytes, mut pk_bytes) =
            unseal_mldsa65_keypair_v0(sealed_blob, enclave_measurement)?;
        let signer = MlDsa65Signer::from_verified_key_bytes(&sk_bytes, &pk_bytes)?;
        zeroize_vec(&mut sk_bytes);
        zeroize_vec(&mut pk_bytes);
        let mut guard = lock_installed_signer()?;
        if guard.is_some() {
            return Err(ProtocolError::PqSigningUnavailable(
                "PQ signer already installed; call reset_installed_pq_signer_for_tests first",
            ));
        }
        *guard = Some(InstalledSigner::MlDsa65(signer));
        Ok(())
    }
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

#[cfg(all(feature = "ml-dsa-65", test))]
mod v0_seal {
    use super::*;
    use sha3::{Digest, Keccak256};

    const SEALED_BLOB_V0_MAGIC: &[u8; 8] = b"2DHSMV0\0";
    const SEAL_DOMAIN_V0: &[u8] = b"2d-hsm-pq-seal-v0";
    /// `magic(8) + version(1) + meas_len_be(2) + measurement`
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

    fn zeroize_vec(buf: &mut Vec<u8>) {
        use zeroize::Zeroize;
        buf.zeroize();
    }

    /// Reference-only: seal ML-DSA-65 keypair material to a TEE measurement (v0 sketch).
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
        let mut out = Vec::with_capacity(SEALED_BLOB_V0_HEADER_LEN + enclave_measurement.len() + cipher.len());
        out.extend_from_slice(SEALED_BLOB_V0_MAGIC);
        out.push(SEALED_BLOB_V0_VERSION);
        out.extend_from_slice(&meas_len.to_be_bytes());
        out.extend_from_slice(enclave_measurement);
        out.extend_from_slice(&cipher);
        Ok(out)
    }

    /// Reference-only: unseal v0 blob with the enclave's attested measurement.
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
        zeroize_vec(&mut plain);
        Ok((sk, pk))
    }
}

#[cfg(all(feature = "ml-dsa-65", test))]
pub use v0_seal::{seal_mldsa65_keypair_v0, unseal_mldsa65_keypair_v0};

#[cfg(all(feature = "ml-dsa-65", test))]
fn zeroize_vec(buf: &mut Vec<u8>) {
    use zeroize::Zeroize;
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ml-dsa-65")]
    #[test]
    fn seal_unseal_roundtrip_wrong_measurement_fails() {
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
    fn install_sealed_signer_enables_signing() {
        let _guard = SealedSignerTestGuard::acquire();
        begin_sealed_signer_test_session();
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
        let blob = seal_mldsa65_keypair_v0(&sk, &pk, measurement).unwrap();
        install_sealed_pq_signer(&blob, measurement).unwrap();
        assert!(is_sealed_signer_installed());
        let hash = [1u8; 32];
        let sig = sign_ticket_hash_sealed(&hash).unwrap();
        assert_eq!(sig.len(), crate::ML_DSA65_SIGNATURE_LEN);
        end_sealed_signer_test_session();
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
        let blob = seal_mldsa65_keypair_v0(&sk, &pk, measurement).unwrap();
        install_sealed_pq_signer(&blob, measurement).unwrap();
        assert!(install_sealed_pq_signer(&blob, measurement).is_err());
    }
}