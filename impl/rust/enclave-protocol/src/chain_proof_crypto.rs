//! Cryptographic verification for `RecentChainProof` (TASK-3).
//!
//! ## MVP format: Producer Chain Attestation v1
//!
//! `proof_data` (minimum 33 bytes):
//! ```text
//! [0]     format_id = 0x01
//! [1..32] recovery_tail_digest = keccak256(concat recovery_history_tail hashes in order)
//! ```
//!
//! `signature_from_recent_producer` (mandatory, 64 bytes):
//! Ed25519 signature over the domain-separated preimage from
//! [`recent_chain_proof_signing_preimage`].
//!
//! The verifying key is **not** derived from public `pq_pubkey` (that would let
//! any host forge proofs). It must come from [`ProducerAttestationTrust`]:
//! a producer attestation Ed25519 key provisioned to the enclave via an
//! attested / sealed channel (separate from the PQ block-signing key until TASK-1).

use crate::{AuthorizedProducerState, ProtocolError, RecentChainProof};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Trusted producer attestation identity for RecentChainProof verification.
///
/// In production this key is pinned in the enclave image or loaded from sealed
/// storage after remote attestation — never computed from public `pq_pubkey`.
#[derive(Debug, Clone, Copy)]
pub struct ProducerAttestationTrust {
    pub attestation_verifying_key: VerifyingKey,
}

impl ProducerAttestationTrust {
    /// Builds trust from a 32-byte Ed25519 verifying key (e.g. sealed config).
    pub fn from_verifying_key_bytes(bytes: &[u8; 32]) -> Result<Self, ProtocolError> {
        let attestation_verifying_key = VerifyingKey::from_bytes(bytes).map_err(|_| {
            ProtocolError::RecentChainProofValidation("invalid attestation Ed25519 public key")
        })?;
        Ok(Self {
            attestation_verifying_key,
        })
    }
}

/// Reference attestation keypair for tests, demos, and local development only.
///
/// **Do not use in production enclaves.** Enabled with `cfg(test)` or the
/// `test-support` crate feature only.
#[cfg(any(test, feature = "test-support"))]
pub fn reference_test_attestation_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[
        0x3d, 0x40, 0x4b, 0x52, 0x36, 0x7b, 0x5b, 0x8f, 0x86, 0x3c, 0x1f, 0x2e, 0x9a, 0x0d,
        0x44, 0x8b, 0x6e, 0x2c, 0x4a, 0x1f, 0x9b, 0x5e, 0x7c, 0x3a, 0x8d, 0x2f, 0x1c, 0x6b,
        0x9e, 0x4a, 0x7d, 0x2c,
    ])
}

/// Trust anchor matching [`reference_test_attestation_signing_key`].
#[cfg(any(test, feature = "test-support"))]
pub fn reference_test_attestation_trust() -> ProducerAttestationTrust {
    ProducerAttestationTrust {
        attestation_verifying_key: reference_test_attestation_signing_key().verifying_key(),
    }
}

/// Format tag for [`PROOF_DATA_V1_LEN`] byte `proof_data` payloads.
pub const PROOF_DATA_FORMAT_V1: u8 = 0x01;

/// Minimum `proof_data` length for format v1.
pub const PROOF_DATA_V1_LEN: usize = 33;

/// Required length of `signature_from_recent_producer`.
pub const PRODUCER_ATTESTATION_SIGNATURE_LEN: usize = 64;

const SIGNING_DOMAIN: &[u8] = b"2d-hsm/RecentChainProof/v1\0";

/// Parsed contents of a v1 `proof_data` blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofDataV1 {
    pub recovery_tail_digest: [u8; 32],
}

/// Keccak256 digest of the ordered recovery tail (32-byte hashes concatenated).
pub fn compute_recovery_tail_digest(recovery_history_tail: &[[u8; 32]]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    for hash in recovery_history_tail {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

/// Builds the canonical v1 `proof_data` blob for a tail.
pub fn build_proof_data_v1(recovery_history_tail: &[[u8; 32]]) -> Vec<u8> {
    let digest = compute_recovery_tail_digest(recovery_history_tail);
    let mut out = Vec::with_capacity(PROOF_DATA_V1_LEN);
    out.push(PROOF_DATA_FORMAT_V1);
    out.extend_from_slice(&digest);
    out
}

/// Domain-separated signing preimage binding proof fields + authorized producer.
pub fn recent_chain_proof_signing_preimage(
    proof: &RecentChainProof,
    authorized: &AuthorizedProducerState,
    recovery_tail_digest: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SIGNING_DOMAIN.len()
            + 8
            + 32
            + 8
            + 32
            + 32
            + 4
            + authorized.pq_pubkey.len()
            + 4
            + authorized.measurement.len(),
    );
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(&proof.finalized_height.to_be_bytes());
    out.extend_from_slice(&proof.finalized_header_hash);
    out.extend_from_slice(&authorized.activated_at_height.to_be_bytes());
    out.extend_from_slice(&authorized.source_ticket_hash);
    out.extend_from_slice(&recovery_tail_digest);
    let pq_len = authorized.pq_pubkey.len() as u32;
    out.extend_from_slice(&pq_len.to_be_bytes());
    out.extend_from_slice(&authorized.pq_pubkey);
    let meas_len = authorized.measurement.len() as u32;
    out.extend_from_slice(&meas_len.to_be_bytes());
    out.extend_from_slice(&authorized.measurement);
    out
}

/// Parses and validates the v1 `proof_data` envelope.
pub fn parse_proof_data_v1(proof_data: &[u8]) -> Result<ProofDataV1, ProtocolError> {
    if proof_data.len() != PROOF_DATA_V1_LEN {
        return Err(ProtocolError::RecentChainProofValidation(
            "proof_data must be exactly 33 bytes for Producer Chain Attestation v1",
        ));
    }
    if proof_data[0] != PROOF_DATA_FORMAT_V1 {
        return Err(ProtocolError::RecentChainProofValidation(
            "unsupported proof_data format (expected 0x01)",
        ));
    }
    let mut recovery_tail_digest = [0u8; 32];
    recovery_tail_digest.copy_from_slice(&proof_data[1..33]);
    Ok(ProofDataV1 {
        recovery_tail_digest,
    })
}

/// Signs a proof using the producer attestation **secret** (host-side / test helper).
///
/// Production hosts must hold this key only on the block producer side, never
/// derive it from public `pq_pubkey`.
pub fn sign_recent_chain_proof(
    proof: &RecentChainProof,
    authorized: &AuthorizedProducerState,
    attestation_signing_key: &SigningKey,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let proof_data = build_proof_data_v1(&proof.recovery_history_tail);
    let parsed = parse_proof_data_v1(&proof_data)?;
    let expected_digest = compute_recovery_tail_digest(&proof.recovery_history_tail);
    if parsed.recovery_tail_digest != expected_digest {
        return Err(ProtocolError::RecentChainProofValidation(
            "internal tail digest mismatch while signing",
        ));
    }
    let preimage = recent_chain_proof_signing_preimage(proof, authorized, expected_digest);
    let signature = attestation_signing_key.sign(&preimage);
    Ok((proof_data, signature.to_bytes().to_vec()))
}

/// Constructs a fully signed `RecentChainProof` (tests / reference host client).
pub fn build_signed_recent_chain_proof(
    finalized_height: u64,
    finalized_header_hash: [u8; 32],
    recovery_history_tail: Vec<[u8; 32]>,
    authorized: &AuthorizedProducerState,
    attestation_signing_key: &SigningKey,
) -> Result<RecentChainProof, ProtocolError> {
    let mut proof = RecentChainProof {
        finalized_height,
        finalized_header_hash,
        recovery_history_tail,
        proof_data: vec![],
        signature_from_recent_producer: None,
    };
    let (proof_data, signature) =
        sign_recent_chain_proof(&proof, authorized, attestation_signing_key)?;
    proof.proof_data = proof_data;
    proof.signature_from_recent_producer = Some(signature);
    Ok(proof)
}

/// Cryptographic verification of `RecentChainProof` (fail closed).
pub fn verify_recent_chain_proof_crypto(
    proof: &RecentChainProof,
    authorized: &AuthorizedProducerState,
    trust: &ProducerAttestationTrust,
) -> Result<(), ProtocolError> {
    if proof.proof_data.is_empty() {
        return Err(ProtocolError::RecentChainProofValidation(
            "proof_data must not be empty (Producer Chain Attestation v1 required)",
        ));
    }

    let parsed = parse_proof_data_v1(&proof.proof_data)?;

    let expected_digest = compute_recovery_tail_digest(&proof.recovery_history_tail);
    if parsed.recovery_tail_digest != expected_digest {
        return Err(ProtocolError::RecentChainProofValidation(
            "proof_data recovery_tail_digest does not match recovery_history_tail",
        ));
    }

    let signature_bytes = proof.signature_from_recent_producer.as_deref().ok_or(
        ProtocolError::RecentChainProofValidation(
            "signature_from_recent_producer is required",
        ),
    )?;

    if signature_bytes.len() != PRODUCER_ATTESTATION_SIGNATURE_LEN {
        return Err(ProtocolError::RecentChainProofValidation(
            "signature_from_recent_producer must be 64 bytes (Ed25519)",
        ));
    }

    let signature = Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| {
                ProtocolError::RecentChainProofValidation(
                    "invalid Ed25519 signature encoding",
                )
            })?,
    );

    let preimage =
        recent_chain_proof_signing_preimage(proof, authorized, parsed.recovery_tail_digest);

    trust
        .attestation_verifying_key
        .verify(&preimage, &signature)
        .map_err(|_| {
            ProtocolError::RecentChainProofValidation(
                "Ed25519 signature over RecentChainProof preimage is invalid for the trusted attestation key",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_authorized() -> AuthorizedProducerState {
        AuthorizedProducerState {
            pq_pubkey: vec![0xDE; 48],
            measurement: b"meas".to_vec(),
            activated_at_height: 100,
            source_ticket_hash: [0xCA; 32],
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let authorized = sample_authorized();
        let sk = reference_test_attestation_signing_key();
        let trust = reference_test_attestation_trust();
        let proof = build_signed_recent_chain_proof(
            150,
            [0xFE; 32],
            vec![[0xCA; 32]],
            &authorized,
            &sk,
        )
        .unwrap();

        verify_recent_chain_proof_crypto(&proof, &authorized, &trust).unwrap();
    }

    #[test]
    fn pq_pubkey_derived_key_cannot_verify_without_trusted_secret() {
        let authorized = sample_authorized();
        let trust = reference_test_attestation_trust();
        // Attacker knows pq_pubkey but not the reference attestation secret.
        let mut hasher = sha3::Sha3_256::new();
        use sha3::Digest;
        hasher.update(authorized.pq_pubkey.as_slice());
        let fake_seed: [u8; 32] = hasher.finalize().into();
        let fake_signing = SigningKey::from_bytes(&fake_seed);
        let proof = build_signed_recent_chain_proof(
            150,
            [0xFE; 32],
            vec![[0xCA; 32]],
            &authorized,
            &fake_signing,
        )
        .unwrap();
        assert!(verify_recent_chain_proof_crypto(&proof, &authorized, &trust).is_err());
    }

    #[test]
    fn tampered_measurement_fails_verification() {
        let authorized = sample_authorized();
        let sk = reference_test_attestation_signing_key();
        let trust = reference_test_attestation_trust();
        let proof = build_signed_recent_chain_proof(
            150,
            [0xFE; 32],
            vec![[0xCA; 32]],
            &authorized,
            &sk,
        )
        .unwrap();
        let mut bad_arm = authorized.clone();
        bad_arm.measurement = b"attacker-measurement".to_vec();
        assert!(verify_recent_chain_proof_crypto(&proof, &bad_arm, &trust).is_err());
    }

    #[test]
    fn tampered_height_fails_verification() {
        let authorized = sample_authorized();
        let sk = reference_test_attestation_signing_key();
        let trust = reference_test_attestation_trust();
        let mut proof = build_signed_recent_chain_proof(
            150,
            [0xFE; 32],
            vec![[0xCA; 32]],
            &authorized,
            &sk,
        )
        .unwrap();
        proof.finalized_height = 999;
        assert!(verify_recent_chain_proof_crypto(&proof, &authorized, &trust).is_err());
    }

    #[test]
    fn proof_data_extra_trailing_bytes_rejected() {
        let authorized = sample_authorized();
        let sk = reference_test_attestation_signing_key();
        let trust = reference_test_attestation_trust();
        let mut proof = build_signed_recent_chain_proof(
            150,
            [0xFE; 32],
            vec![[0xCA; 32]],
            &authorized,
            &sk,
        )
        .unwrap();
        proof.proof_data.push(0xFF);
        assert!(verify_recent_chain_proof_crypto(&proof, &authorized, &trust).is_err());
    }

    #[test]
    fn empty_proof_data_rejected() {
        let authorized = sample_authorized();
        let trust = reference_test_attestation_trust();
        let proof = RecentChainProof {
            finalized_height: 150,
            finalized_header_hash: [0xFE; 32],
            recovery_history_tail: vec![[0xCA; 32]],
            proof_data: vec![],
            signature_from_recent_producer: Some(vec![0u8; 64]),
        };
        assert!(verify_recent_chain_proof_crypto(&proof, &authorized, &trust).is_err());
    }
}