//! Agent Gateway identity proof (TASK-7.6.3 / `AGENT_K1_PROVE_IDENTITY`).
//!
//! Builds the EIP-191 (`0x19`) identity-proof preimage from **structured fields** and signs it with
//! the key whose identity it proves. Layout pinned by TASK-7.1 AC#15 (`identity_proof_v1`):
//!
//! ```text
//! 0x19 ‖ len(label)(1B) ‖ label ‖ chain_id(8B BE) ‖ len(env_id)(1B) ‖ env_id
//!      ‖ key_ref(32B) ‖ pubkey(65B) ‖ address(20B) ‖ verifier_nonce(32B)
//! ```
//!
//! The enclave signs ONLY these structured fields (no caller-controlled arbitrary bytes) over a
//! `keccak256` prehash via the secp256k1 RFC-6979 low-S recoverable signer. The verifier owns the
//! 32-byte nonce, so the proof is bound to a fresh challenge (live, non-replayable). The proof
//! binds the key by its **signed `address`** (derived here from the signing key, never caller-
//! supplied), so a caller cannot claim an address it does not control (TASK-7.3 trust model).
//!
//! Built only under the `agent-gateway` feature.

use crate::secp256k1::{keccak256, Keypair, RecoverableSignature, Secp256k1Error};

/// EIP-191 non-transaction domain byte (disjoint from eth RLP `≥0xc0` and TRON protobuf `0x0a`).
const EIP191_DOMAIN: u8 = 0x19;
/// Pinned identity-proof label (TASK-7.1 AC#15 / `identity_proof_v1`).
pub const IDENTITY_PROOF_LABEL: &str = "2d-hsm/agent-identity-proof/v1";

/// Errors from identity-proof construction. Coarse (no oracle detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProofError {
    /// `label` or `environment_identifier` exceeds the 1-byte length prefix (255 bytes).
    FieldTooLong,
    /// Signing failed.
    Sign,
}

impl From<Secp256k1Error> for IdentityProofError {
    fn from(_: Secp256k1Error) -> Self {
        // Collapse to a single signing error — never surface the underlying crypto detail.
        IdentityProofError::Sign
    }
}

/// Build the identity-proof preimage from structured fields (see module docs for the layout).
///
/// `pubkey_uncompressed` is `0x04 ‖ X ‖ Y`; `address` is the 20-byte eth body. The `label` and
/// `environment_identifier` each carry a 1-byte length prefix, so both must be ≤ 255 bytes.
pub fn identity_proof_preimage(
    chain_id: u64,
    environment_identifier: &str,
    key_ref: &[u8; 32],
    pubkey_uncompressed: &[u8; 65],
    address: &[u8; 20],
    verifier_nonce: &[u8; 32],
) -> Result<Vec<u8>, IdentityProofError> {
    let label = IDENTITY_PROOF_LABEL.as_bytes();
    let env = environment_identifier.as_bytes();
    if label.len() > 255 || env.len() > 255 {
        return Err(IdentityProofError::FieldTooLong);
    }
    let mut out =
        Vec::with_capacity(1 + 1 + label.len() + 8 + 1 + env.len() + 32 + 65 + 20 + 32);
    out.push(EIP191_DOMAIN);
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.push(env.len() as u8);
    out.extend_from_slice(env);
    out.extend_from_slice(key_ref);
    out.extend_from_slice(pubkey_uncompressed);
    out.extend_from_slice(address);
    out.extend_from_slice(verifier_nonce);
    Ok(out)
}

/// A signed identity proof: the recoverable signature plus the bound public identity it attests.
pub struct IdentityProof {
    pub signature: RecoverableSignature,
    pub pubkey_uncompressed: [u8; 65],
    pub address: [u8; 20],
    pub signing_hash: [u8; 32],
}

/// Sign an identity proof with `keypair` over the verifier-supplied nonce.
///
/// The bound `pubkey`/`address` are derived from `keypair` (on-curve by construction), so the proof
/// attests an address the signer actually controls; `key_ref` is the opaque keystore handle.
pub fn sign_identity_proof(
    keypair: &Keypair,
    chain_id: u64,
    environment_identifier: &str,
    key_ref: &[u8; 32],
    verifier_nonce: &[u8; 32],
) -> Result<IdentityProof, IdentityProofError> {
    let pubkey_uncompressed = keypair.public_key_uncompressed();
    let address = keypair.eth_address();
    let preimage = identity_proof_preimage(
        chain_id,
        environment_identifier,
        key_ref,
        &pubkey_uncompressed,
        &address,
        verifier_nonce,
    )?;
    let signing_hash = keccak256(&preimage);
    let signature = keypair.sign_prehashed(&signing_hash)?;
    Ok(IdentityProof { signature, pubkey_uncompressed, address, signing_hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const IDP: &str = include_str!("../testvectors/agent-gateway/identity_proof_v1.json");
    const KEYS: &str = include_str!("../testvectors/agent-gateway/keys.json");
    const PREIMAGE_BIN: &[u8] =
        include_bytes!("../testvectors/agent-gateway/identity_proof_v1.preimage.bin");
    const SIGNING_HASH_BIN: &[u8] =
        include_bytes!("../testvectors/agent-gateway/identity_proof_v1.signing_hash.bin");

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
    }

    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    fn fields() -> Value {
        serde_json::from_str::<Value>(IDP).unwrap()["fields"].clone()
    }

    fn transfer_keypair() -> Keypair {
        let k: Value = serde_json::from_str(KEYS).unwrap();
        let sk = arr32(k["transfer_key"]["privkey"].as_str().unwrap());
        Keypair::from_secret_bytes(&sk).unwrap()
    }

    #[test]
    fn preimage_matches_golden_vector() {
        let f = fields();
        let pre = identity_proof_preimage(
            f["chain_id"].as_u64().unwrap(),
            f["environment_identifier"].as_str().unwrap(),
            &arr32(f["key_ref"].as_str().unwrap()),
            &unhex(f["pubkey_uncompressed"].as_str().unwrap()).try_into().unwrap(),
            &unhex(f["address"].as_str().unwrap()).try_into().unwrap(),
            &arr32(f["verifier_nonce"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(pre[0], EIP191_DOMAIN, "EIP-191 domain byte");
        assert_eq!(pre, PREIMAGE_BIN, "preimage must be byte-exact vs identity_proof_v1.preimage.bin");
        assert_eq!(keccak256(&pre).as_slice(), SIGNING_HASH_BIN, "signing hash byte-exact");
    }

    #[test]
    fn sign_identity_proof_matches_golden_and_binds_address() {
        let f = fields();
        let kp = transfer_keypair();
        let proof = sign_identity_proof(
            &kp,
            f["chain_id"].as_u64().unwrap(),
            f["environment_identifier"].as_str().unwrap(),
            &arr32(f["key_ref"].as_str().unwrap()),
            &arr32(f["verifier_nonce"].as_str().unwrap()),
        )
        .unwrap();

        // The proof binds the signer's own derived address/pubkey (not caller-supplied).
        assert_eq!(proof.address.to_vec(), unhex(f["address"].as_str().unwrap()), "bound address");
        assert_eq!(
            proof.pubkey_uncompressed.to_vec(),
            unhex(f["pubkey_uncompressed"].as_str().unwrap()),
            "bound pubkey"
        );
        assert_eq!(proof.signing_hash.as_slice(), SIGNING_HASH_BIN, "signing hash");

        // Signature byte-exact vs the frozen golden signature, and low-S.
        let sig = &serde_json::from_str::<Value>(IDP).unwrap()["signature"];
        assert_eq!(proof.signature.r.to_vec(), unhex(sig["r"].as_str().unwrap()), "r");
        assert_eq!(proof.signature.s.to_vec(), unhex(sig["s"].as_str().unwrap()), "s");
        assert_eq!(
            proof.signature.recovery_id as u64,
            sig["recovery_id"].as_u64().unwrap(),
            "recovery_id"
        );

        // The recovered signer matches the bound pubkey (proof-of-possession).
        let recovered =
            crate::secp256k1::recover_pubkey_uncompressed(&proof.signing_hash, &proof.signature)
                .unwrap();
        assert_eq!(recovered, proof.pubkey_uncompressed, "recovered == bound pubkey");
    }

    #[test]
    fn env_id_length_prefixed_distinctly() {
        // Two different env-ids of different lengths must produce different preimages (the 1-byte
        // length prefix + bytes prevent any ambiguity / extension confusion).
        let key_ref = [0x01u8; 32];
        let pubkey = [0x04u8; 65];
        let address = [0x02u8; 20];
        let nonce = [0x03u8; 32];
        let a = identity_proof_preimage(1, "testnet", &key_ref, &pubkey, &address, &nonce).unwrap();
        let b = identity_proof_preimage(1, "mainnet", &key_ref, &pubkey, &address, &nonce).unwrap();
        let c = identity_proof_preimage(1, "test", &key_ref, &pubkey, &address, &nonce).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(c.len() < a.len(), "shorter env-id ⇒ shorter preimage");
    }
}
