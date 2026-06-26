//! ML-DSA-65 (FIPS 204) signing inside the enclave boundary.
//!
//! ## Side-channels — constant-time posture (accepted risk)
//!
//! Producer signing here is **not constant-time** — and not merely in wall-clock terms: the chosen
//! library offers no constant-time guarantee at all. `detached_sign` comes from PQClean's *clean*
//! ML-DSA-65 (Dilithium) reference via `pqcrypto-mldsa`. PQClean's own README lists "No branching on
//! secret data" and "No access to secret memory locations" as **unchecked, still-in-development**
//! goals, so the clean implementation may branch on — and index memory with — secret-derived values.
//! Separately, ML-DSA signing is Fiat-Shamir-with-aborts, so the number of rejection-sampling
//! iterations (hence the signing time) is data-dependent. The enclave threat model assumes the
//! untrusted host observes request→response latency over vsock, so this variance is observable.
//!
//! This is an **accepted risk**, not a defect fixable in this module. The ML-DSA/Dilithium design
//! argument is only that the *published signature distribution* is independent of the secret key
//! (zero-knowledge); it bounds, but does not eliminate, the wall-clock / micro-architectural timing
//! exposure of a non-hardened reference implementation. No code path relies on signing latency being
//! uniform. Eliminating this needs a constant-time-hardened ML-DSA — a library swap, not a local
//! change. Migration path: PQClean is deprecated (archived read-only ~July 2026); its successor is
//! the PQ Code Package (PQCA). Revisit this waiver when migrating off `pqcrypto-mldsa` (tracked: TASK-34).
//!
//! Everything *around* signing is constant-time where it matters: sealed-key AEAD open
//! (ChaCha20Poly1305 / XChaCha20Poly1305 — the Poly1305 tag check is `subtle`-backed), and the
//! secret-adjacent equality gates use `subtle::ct_eq` (the capability `payload_binding` /
//! `scope_identity` checks in `agent_dispatch`/`agent_capability` and the fund-custody digest gate in
//! `agent_boot`). The Agent Gateway secp256k1 signer (`k256`, RFC 6979) is constant-time with a
//! deterministic nonce. Signature *verification* here (`verify_ticket_hash`) operates only on public
//! inputs, so its timing carries no secret.

use crate::{ProtocolError, ML_DSA65_SECRETKEY_LEN, ML_DSA65_SIGNATURE_LEN};
use pqcrypto_mldsa::mldsa65::{detached_sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
#[cfg(all(test, feature = "reference-test-key"))]
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// Domain-separated message for install-time keypair self-test (not a ticket hash).
const INSTALL_SELF_TEST_MSG: [u8; 32] = *b"2d-hsm-pq-install-self-test!!!!!";

#[cfg(all(test, feature = "reference-test-key"))]
static REFERENCE_SIGNER: OnceLock<MlDsa65Signer> = OnceLock::new();

/// ML-DSA-65 signing key held inside the enclave (sealed or reference test vector).
///
/// The long-term secret key is stored as raw bytes in a [`Zeroizing`] buffer that is scrubbed
/// on drop. Dropping any `MlDsa65Signer` — including the short-lived ones built only to validate
/// a keypair during sealing/provisioning (the `pq_signer` `seal_*` / `verify_sealed_blob_*`
/// helpers) — therefore releases the secret material instead of leaving a parsed copy in heap
/// memory (TASK-6).
///
/// `pqcrypto`'s `SecretKey` is `Copy` with no `Drop`/`Zeroize`, so it cannot self-scrub. It is only
/// ever materialized transiently — per signature in [`MlDsa65Signer::sign_ticket_hash`], and (in
/// provisioning/test builds only) per keypair in `generate_keypair` — and never retained. Those
/// ephemeral copies are the residual upstream limitation; the stored long-term key is always held
/// in the `Zeroizing` buffer and scrubbed on drop.
pub struct MlDsa65Signer {
    public_key: PublicKey,
    secret_key: Zeroizing<Vec<u8>>,
}

impl MlDsa65Signer {
    #[cfg(all(test, feature = "reference-test-key"))]
    pub fn reference_test_vector() -> &'static Self {
        REFERENCE_SIGNER.get_or_init(|| {
            let sk_bytes = include_bytes!("../testvectors/mldsa65_reference_sk.bin");
            let pk_bytes = include_bytes!("../testvectors/mldsa65_reference_pk.bin");
            Self::from_verified_key_bytes(sk_bytes, pk_bytes)
                .expect("valid reference ML-DSA-65 keypair")
        })
    }

    /// Low-level constructor: checks the secret-key length and parses the public key, then stores
    /// the secret. It does **not** verify that `sk_bytes` and `pk_bytes` form a matching pair —
    /// callers that require keypair validation must use [`MlDsa65Signer::from_verified_key_bytes`].
    pub(crate) fn from_key_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self, ProtocolError> {
        if sk_bytes.len() != ML_DSA65_SECRETKEY_LEN {
            return Err(ProtocolError::PqSigningUnavailable(
                "invalid ML-DSA-65 secret key",
            ));
        }
        let pk = PublicKey::from_bytes(pk_bytes)
            .map_err(|_| ProtocolError::PqSigningUnavailable("invalid ML-DSA-65 public key"))?;
        // Store the secret as raw bytes in a Zeroizing buffer (scrubbed on drop) rather than a
        // non-zeroizing pqcrypto SecretKey. The cryptographic sk<->pk match is enforced by
        // `from_verified_key_bytes` via `self_test_keypair`.
        Ok(Self {
            public_key: pk,
            secret_key: Zeroizing::new(sk_bytes.to_vec()),
        })
    }

    /// Parse keys and verify they form a matching pair (mandatory before accepting a provisioned signer).
    pub fn from_verified_key_bytes(
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<Self, ProtocolError> {
        let signer = Self::from_key_bytes(sk_bytes, pk_bytes)?;
        signer.self_test_keypair()?;
        Ok(signer)
    }

    fn self_test_keypair(&self) -> Result<(), ProtocolError> {
        let sig = self.sign_ticket_hash(&INSTALL_SELF_TEST_MSG)?;
        self.verify_ticket_hash(&INSTALL_SELF_TEST_MSG, &sig)
    }

    /// Generate a fresh ML-DSA-65 keypair. Provisioning / tests only — gated out of production
    /// builds so it is never part of the deployed signing API. `pqcrypto`'s `keypair()` returns a
    /// `Copy`/non-zeroizing `SecretKey`, leaving one transient stack copy for the duration of this
    /// call (upstream limitation); the stored secret is held in a `Zeroizing` buffer as elsewhere.
    #[cfg(any(test, feature = "pq-seal-provisioning"))]
    pub fn generate_keypair() -> Self {
        let (pk, sk) = pqcrypto_mldsa::mldsa65::keypair();
        Self {
            public_key: pk,
            secret_key: Zeroizing::new(sk.as_bytes().to_vec()),
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    pub fn public_key_bytes_owned(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Secret key bytes (offline provisioning only — requires `pq-seal-provisioning`).
    #[cfg(feature = "pq-seal-provisioning")]
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_slice()
    }

    /// Pure ML-DSA-65 over the 32-byte `ticketHash` (no pre-hash; empty `ctx` in FIPS terms).
    pub fn sign_ticket_hash(&self, ticket_hash: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
        // Materialize the pqcrypto SecretKey transiently for this one signature; it is dropped at
        // the end of the call and never stored (the stored secret lives in a Zeroizing buffer).
        let secret_key = SecretKey::from_bytes(self.secret_key.as_slice()).map_err(|_| {
            ProtocolError::PqSigningUnavailable("stored ML-DSA-65 secret key invalid")
        })?;
        let sig = detached_sign(ticket_hash, &secret_key);
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
            return Err(ProtocolError::PqSignatureInvalid(
                "invalid signature length",
            ));
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

    /// TASK-6 regression guard. Asserts that the actual `MlDsa65Signer::secret_key` field type
    /// implements `ZeroizeOnDrop` (it is `Zeroizing<Vec<u8>>`). This is a compile-time *type* check
    /// — it does not inspect heap contents — but it ensures the field cannot be regressed to a
    /// non-scrubbing container without failing to build, which is what makes the runtime scrub on
    /// drop hold (so the short-lived validation signers do not retain secret-key copies).
    #[test]
    fn secret_key_storage_is_zeroize_on_drop() {
        // Bind the assertion to the *actual* `MlDsa65Signer::secret_key` field by inference (the
        // child module can read the private field), so regressing that field to a non-scrubbing
        // type fails to compile rather than silently passing this test (TASK-6).
        fn assert_field_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let signer = MlDsa65Signer::reference_test_vector();
        assert_field_zeroize_on_drop(&signer.secret_key);
    }

    /// Refactor regression: storing the secret as raw `Zeroizing` bytes and rebuilding the
    /// transient `SecretKey` per signature preserves the key exactly and still signs/verifies.
    #[test]
    fn zeroizing_secret_storage_roundtrips_and_signs() {
        let sk = include_bytes!("../testvectors/mldsa65_reference_sk.bin");
        let pk = include_bytes!("../testvectors/mldsa65_reference_pk.bin");
        let signer = MlDsa65Signer::from_verified_key_bytes(sk, pk).unwrap();
        // Stored secret survives the Zeroizing refactor byte-for-byte.
        assert_eq!(signer.secret_key_bytes(), &sk[..]);
        let hash = [0x37u8; 32];
        let sig = signer.sign_ticket_hash(&hash).unwrap();
        assert_eq!(sig.len(), ML_DSA65_SIGNATURE_LEN);
        signer.verify_ticket_hash(&hash, &sig).unwrap();
    }
}
