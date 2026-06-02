//! ML-DSA-65 (FIPS 204) signing for protocol tests (TASK-1 MVP slice).
//!
//! Compiled only with the explicit `ml-dsa-65` / `reference-test-key` feature.
//! Embeds a **public NIST test-vector secret key** — must never ship in default or
//! production enclave builds. Production TEE loads the key from sealed storage.

use crate::{ProtocolError, ML_DSA65_PUBKEY_LEN, ML_DSA65_SIGNATURE_LEN};
use pqcrypto_mldsa::mldsa65::{detached_sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use std::sync::OnceLock;

static REFERENCE_SIGNER: OnceLock<ReferenceMlDsa65Signer> = OnceLock::new();

/// Process-wide ML-DSA-65 identity for the reference enclave image.
pub struct ReferenceMlDsa65Signer {
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl ReferenceMlDsa65Signer {
    pub fn global() -> &'static Self {
        REFERENCE_SIGNER.get_or_init(Self::from_test_vector)
    }

    fn from_test_vector() -> Self {
        let sk_bytes = include_bytes!("../testvectors/mldsa65_reference_sk.bin");
        let pk_bytes = include_bytes!("../testvectors/mldsa65_reference_pk.bin");
        let sk = SecretKey::from_bytes(sk_bytes).expect("valid reference ML-DSA-65 secret key");
        let pk = PublicKey::from_bytes(pk_bytes).expect("valid reference ML-DSA-65 public key");
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
            return Err(ProtocolError::PqSigningUnavailable("invalid signature length"));
        }
        let sig = DetachedSignature::from_bytes(signature)
            .map_err(|_| ProtocolError::PqSigningUnavailable("invalid signature encoding"))?;
        pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, ticket_hash, &self.public_key)
            .map_err(|_| ProtocolError::PqSigningUnavailable("ML-DSA-65 verify failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_ticket_hash_roundtrip() {
        let signer = ReferenceMlDsa65Signer::global();
        assert_eq!(signer.public_key_bytes().len(), ML_DSA65_PUBKEY_LEN);
        let hash = [0x42u8; 32];
        let sig = signer.sign_ticket_hash(&hash).unwrap();
        assert_eq!(sig.len(), ML_DSA65_SIGNATURE_LEN);
        signer.verify_ticket_hash(&hash, &sig).unwrap();
    }
}