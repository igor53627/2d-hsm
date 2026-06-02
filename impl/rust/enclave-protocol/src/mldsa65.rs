//! ML-DSA-65 (FIPS 204) signing inside the enclave boundary.

use crate::{ProtocolError, ML_DSA65_SIGNATURE_LEN};
use pqcrypto_mldsa::mldsa65::{detached_sign, keypair, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
#[cfg(all(test, feature = "reference-test-key"))]
use std::sync::OnceLock;

/// Domain-separated message for install-time keypair self-test (not a ticket hash).
const INSTALL_SELF_TEST_MSG: [u8; 32] = *b"2d-hsm-pq-install-self-test!!!!!";

#[cfg(all(test, feature = "reference-test-key"))]
static REFERENCE_SIGNER: OnceLock<MlDsa65Signer> = OnceLock::new();

/// ML-DSA-65 signing key held inside the enclave (sealed or reference test vector).
pub struct MlDsa65Signer {
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl Drop for MlDsa65Signer {
    fn drop(&mut self) {
        #[cfg(feature = "ml-dsa-65")]
        {
            use zeroize::Zeroize;
            let mut scratch = self.secret_key.as_bytes().to_vec();
            scratch.zeroize();
        }
    }
}

impl MlDsa65Signer {
    #[cfg(all(test, feature = "reference-test-key"))]
    pub fn reference_test_vector() -> &'static Self {
        REFERENCE_SIGNER.get_or_init(|| {
            let sk_bytes = include_bytes!("../testvectors/mldsa65_reference_sk.bin");
            let pk_bytes = include_bytes!("../testvectors/mldsa65_reference_pk.bin");
            Self::from_verified_key_bytes(sk_bytes, pk_bytes).expect("valid reference ML-DSA-65 keypair")
        })
    }

    pub fn from_key_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self, ProtocolError> {
        let sk = SecretKey::from_bytes(sk_bytes)
            .map_err(|_| ProtocolError::PqSigningUnavailable("invalid ML-DSA-65 secret key"))?;
        let pk = PublicKey::from_bytes(pk_bytes)
            .map_err(|_| ProtocolError::PqSigningUnavailable("invalid ML-DSA-65 public key"))?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Parse keys and verify they form a matching pair (mandatory before accepting a provisioned signer).
    pub fn from_verified_key_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self, ProtocolError> {
        let signer = Self::from_key_bytes(sk_bytes, pk_bytes)?;
        signer.self_test_keypair()?;
        Ok(signer)
    }

    fn self_test_keypair(&self) -> Result<(), ProtocolError> {
        let sig = self.sign_ticket_hash(&INSTALL_SELF_TEST_MSG)?;
        self.verify_ticket_hash(&INSTALL_SELF_TEST_MSG, &sig)
    }

    /// Generate a fresh ML-DSA-65 keypair (provisioning / tests only).
    pub fn generate_keypair() -> Self {
        let (pk, sk) = keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    pub fn public_key_bytes_owned(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Pure ML-DSA-65 over the 32-byte `ticketHash` (no pre-hash; empty `ctx` in FIPS terms).
    pub fn sign_ticket_hash(&self, ticket_hash: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
        let sig = detached_sign(ticket_hash, &self.secret_key);
        let bytes = sig.as_bytes().to_vec();
        if bytes.len() != ML_DSA65_SIGNATURE_LEN {
            return Err(ProtocolError::PqSigningUnavailable(
                "ML-DSA-65 signature length mismatch vs wire spec",
            ));
        }
        Ok(bytes)
    }

    pub fn verify_ticket_hash(
        &self,
        ticket_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ProtocolError> {
        if signature.len() != ML_DSA65_SIGNATURE_LEN {
            return Err(ProtocolError::PqSignatureInvalid("invalid signature length"));
        }
        let sig = DetachedSignature::from_bytes(signature)
            .map_err(|_| ProtocolError::PqSignatureInvalid("invalid signature encoding"))?;
        pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, ticket_hash, &self.public_key)
            .map_err(|_| {
                ProtocolError::PqSignatureInvalid("ML-DSA-65 signature verification failed")
            })
    }
}

/// NIST test-vector signer — unit tests with `reference-test-key` only.
#[cfg(all(test, feature = "reference-test-key"))]
pub struct ReferenceMlDsa65Signer;

#[cfg(all(test, feature = "reference-test-key"))]
impl ReferenceMlDsa65Signer {
    pub fn global() -> &'static MlDsa65Signer {
        MlDsa65Signer::reference_test_vector()
    }
}

#[cfg(all(test, feature = "reference-test-key"))]
mod tests {
    use super::*;
    use crate::ML_DSA65_PUBKEY_LEN;

    #[test]
    fn sign_and_verify_ticket_hash_roundtrip() {
        let signer = MlDsa65Signer::reference_test_vector();
        assert_eq!(signer.public_key_bytes().len(), ML_DSA65_PUBKEY_LEN);
        let hash = [0x42u8; 32];
        let sig = signer.sign_ticket_hash(&hash).unwrap();
        assert_eq!(sig.len(), ML_DSA65_SIGNATURE_LEN);
        signer.verify_ticket_hash(&hash, &sig).unwrap();
    }

    #[test]
    fn mismatched_keypair_fails_self_test() {
        let sk = include_bytes!("../testvectors/mldsa65_reference_sk.bin");
        let mut bad_pk = include_bytes!("../testvectors/mldsa65_reference_pk.bin").to_vec();
        bad_pk[0] ^= 0xFF;
        assert!(MlDsa65Signer::from_verified_key_bytes(sk, &bad_pk).is_err());
    }
}