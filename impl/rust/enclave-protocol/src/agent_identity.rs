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

use crate::agent_keystore::{KeyEntry, KeyPurpose, KeystoreBody};
use crate::secp256k1::{
    eth_address_from_uncompressed, keccak256, tron_address_from_body, Keypair, RecoverableSignature,
    Secp256k1Error,
};

/// EIP-191 non-transaction domain byte (disjoint from eth RLP `≥0xc0` and TRON protobuf `0x0a`).
const EIP191_DOMAIN: u8 = 0x19;
/// Pinned identity-proof label (TASK-7.1 AC#15 / `identity_proof_v1`).
pub const IDENTITY_PROOF_LABEL: &str = "2d-hsm/agent-identity-proof/v1";

/// Errors from identity-proof construction. Coarse (no oracle detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProofError {
    /// `label` exceeds the 1-byte length prefix (255 bytes).
    FieldTooLong,
    /// `environment_identifier` violates the TASK-7.1 §10.6 rules (1..=64, `[a-z0-9-]`, no
    /// leading/trailing/double hyphen).
    InvalidEnvironmentId,
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
    if label.len() > 255 {
        return Err(IdentityProofError::FieldTooLong);
    }
    // Enforce the TASK-7.1 §10.6 env-id rules here too (defense in depth): the dispatch path passes
    // the sealed, already-validated config value, but this is a `pub` helper.
    if !crate::agent_keystore::is_valid_environment_identifier(environment_identifier) {
        return Err(IdentityProofError::InvalidEnvironmentId);
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

/// Agent Gateway backend version reported with the public identity (TASK-7.1 §10).
pub const AGENT_GATEWAY_VERSION: u8 = 1;

/// The `AGENT_K1_PUBLIC_IDENTITY` response (TASK-7.3 §AC#4): the unified-account public identity for
/// one stored key. `key_purpose` is **non-authoritative** convenience metadata (returned over the
/// untrusted host path) — a verifier authenticates a key by its signed address, never by this field.
pub struct PublicIdentity {
    pub pubkey_uncompressed: [u8; 65],
    pub eth_address: [u8; 20],
    pub tron_address: String,
    pub key_ref: [u8; 32],
    pub key_purpose: KeyPurpose,
    pub agent_version: u8,
}

/// Look up a sealed `KeyEntry` by its opaque `key_ref` (linear scan over the sealed entry list).
/// Returns `None` if absent — the caller collapses not-found into the anti-oracle error band so it
/// is indistinguishable from a key-purpose mismatch (TASK-7.3 §error exposure).
pub fn find_entry<'a>(body: &'a KeystoreBody, key_ref: &[u8; 32]) -> Option<&'a KeyEntry> {
    body.entries.iter().find(|e| &e.key_ref == key_ref)
}

/// Build the `PUBLIC_IDENTITY` response from a sealed entry, deriving both addresses from the
/// entry's stored uncompressed SEC1 public identity. Re-validates the `0x04` prefix + on-curve point
/// (defense-in-depth — the keystore is trusted, but a malformed entry fails closed rather than
/// emitting a bogus address). Chain/environment/domain checks live in the dispatch layer.
pub fn public_identity_from_entry(entry: &KeyEntry) -> Result<PublicIdentity, Secp256k1Error> {
    let pubkey_uncompressed: [u8; 65] = entry
        .public_identity
        .as_slice()
        .try_into()
        .map_err(|_| Secp256k1Error::InvalidPublicKey)?;
    let eth_address = eth_address_from_uncompressed(&pubkey_uncompressed)?;
    let tron_address = tron_address_from_body(&eth_address);
    Ok(PublicIdentity {
        pubkey_uncompressed,
        eth_address,
        tron_address,
        key_ref: entry.key_ref,
        key_purpose: entry.purpose,
        agent_version: AGENT_GATEWAY_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{BackupExportMetadata, CreationMetadata, KeyAlgorithm};
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

    #[test]
    fn invalid_env_id_rejected() {
        let (key_ref, pubkey, address, nonce) = ([0x01u8; 32], [0x04u8; 65], [0x02u8; 20], [0x03u8; 32]);
        let too_long = "a".repeat(65);
        for bad in ["", "Main", "x_y", "-x", "x-", "a--b", "под", too_long.as_str()] {
            assert_eq!(
                identity_proof_preimage(1, bad, &key_ref, &pubkey, &address, &nonce),
                Err(IdentityProofError::InvalidEnvironmentId),
                "{bad:?} must be rejected"
            );
        }
        // valid env-id still builds.
        assert!(identity_proof_preimage(1, "mainnet", &key_ref, &pubkey, &address, &nonce).is_ok());
    }

    // --- PUBLIC_IDENTITY ---

    fn entry_from_keys(name: &str, purpose: KeyPurpose, key_ref: [u8; 32]) -> KeyEntry {
        let k: Value = serde_json::from_str(KEYS).unwrap();
        KeyEntry {
            key_ref,
            purpose,
            algorithm: KeyAlgorithm::Secp256k1,
            public_identity: unhex(k[name]["pubkey_uncompressed_sec1"].as_str().unwrap()),
            secret_scalar: zeroize::Zeroizing::new(vec![0u8; 32]), // unused by PUBLIC_IDENTITY
            creation_metadata: CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 },
            backup_export_metadata: BackupExportMetadata::default(),
        }
    }

    #[test]
    fn public_identity_derives_pinned_addresses() {
        let k: Value = serde_json::from_str(KEYS).unwrap();
        for (name, purpose) in [
            ("transfer_key", KeyPurpose::AgentTransferK1),
            ("treasury_key", KeyPurpose::AgentFaucetTreasuryK1),
        ] {
            let entry = entry_from_keys(name, purpose, [0x07; 32]);
            let id = public_identity_from_entry(&entry).unwrap();
            assert_eq!(
                id.pubkey_uncompressed.to_vec(),
                unhex(k[name]["pubkey_uncompressed_sec1"].as_str().unwrap()),
                "{name} pubkey"
            );
            assert_eq!(
                format!("0x{}", hex::encode(id.eth_address)),
                k[name]["eth_address"].as_str().unwrap(),
                "{name} eth address"
            );
            assert_eq!(id.tron_address, k[name]["tron_address"].as_str().unwrap(), "{name} TRON address");
            assert_eq!(id.key_purpose, purpose, "{name} purpose");
            assert_eq!(id.agent_version, AGENT_GATEWAY_VERSION);
        }
    }

    #[test]
    fn find_entry_by_key_ref() {
        use crate::agent_keystore::{AuditRing, FaucetState, KeystoreConfig};
        let body = KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "testnet".to_string(),
                admin_authority_pk: [0; 32],
                recovery_authority_pk: [0; 32],
                backup_recovery_wrapping_pubkey: vec![],
                monotonic_treasury_config_version: 0,
                authority_epoch: 0,
                anchor_root: [0; 32],
            },
            entries: vec![
                entry_from_keys("transfer_key", KeyPurpose::AgentTransferK1, [0x11; 32]),
                entry_from_keys("treasury_key", KeyPurpose::AgentFaucetTreasuryK1, [0x22; 32]),
            ],
            counters: vec![],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 0,
                max_effective_gas_fee_rate: 0,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
            },
            audit: AuditRing { records: vec![], capacity: 0, last_exported_seq: 0, next_seq: 0 },
            freshness_epoch: 0,
        };
        assert_eq!(find_entry(&body, &[0x11; 32]).unwrap().purpose, KeyPurpose::AgentTransferK1);
        assert_eq!(find_entry(&body, &[0x22; 32]).unwrap().purpose, KeyPurpose::AgentFaucetTreasuryK1);
        assert!(find_entry(&body, &[0xff; 32]).is_none(), "unknown key_ref ⇒ None");
    }
}
