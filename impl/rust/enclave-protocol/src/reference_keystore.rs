//! Deviceless REFERENCE agent keystore for the 0x40 contract-test server (TASK-23).
//!
//! Builds + installs a fixed, well-known agent keystore so a NON-SNP, cross-platform (Linux + macOS)
//! server can answer `PUBLIC_IDENTITY`/`PROVE_IDENTITY` with real identities and — behind the existing
//! preview features + an installed anti-rollback binding / mock commit channel — exercise the
//! signing/capability/configure paths. It composes the SAME pub seam the SNP boot path uses
//! ([`crate::agent_dispatch::install_agent_keystore`]); there is no new dispatch logic.
//!
//! **TEST KEYS ONLY — zero secrecy claim.** The transfer + treasury scalars are the PUBLIC, well-known
//! Anvil dev keys frozen in the TASK-22 golden vectors (`testvectors/agent-gateway/keys.json`); the
//! Ed25519 authority/anchor seeds are public constants. Sourcing the transfer key at
//! [`REFERENCE_TRANSFER_KEY_REF`] makes a `PUBLIC_IDENTITY` reply **byte-identical to the frozen
//! `resp_public_identity_v1.bin`**, so the deviceless server and the golden vectors share one source of
//! truth (pinned by `public_identity_matches_frozen_golden`).
//!
//! **Trust boundary (TASK-23 AC#4):** NO SNP attestation, NO anti-rollback durability, PUBLIC keys —
//! NEVER a production endpoint. The bin that installs this is release-banned (see `lib.rs`
//! `agent-contract-server`); the production path is the AF_VSOCK + SNP `twod-hsm-agent-gateway` bin.

use crate::agent_keystore::{
    AuditRing, CreationMetadata, FaucetState, KeyAlgorithm, KeyEntry, KeyPurpose, KeystoreBody,
    KeystoreConfig,
};
use crate::boot_agent_keystore::AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT;
use zeroize::Zeroizing;

// secp256k1 transfer-key scalar — Anvil acct0, frozen in testvectors/agent-gateway/keys.json
// (transfer_key). PUBLIC; the cross-validation test pins that this scalar + REFERENCE_TRANSFER_KEY_REF
// reproduce the frozen resp_public_identity_v1.bin (so a drift in keys.json breaks the test).
const REFERENCE_TRANSFER_SCALAR: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];
// secp256k1 faucet-treasury scalar — Anvil acct1, keys.json treasury_key. PUBLIC.
const REFERENCE_TREASURY_SCALAR: [u8; 32] = [
    0x59, 0xc6, 0x99, 0x5e, 0x99, 0x8f, 0x97, 0xa5, 0xa0, 0x04, 0x49, 0x66, 0xf0, 0x94, 0x53, 0x89,
    0xdc, 0x9e, 0x86, 0xda, 0xe8, 0x8c, 0x7a, 0x84, 0x12, 0xf4, 0x60, 0x3b, 0x6b, 0x78, 0x69, 0x0d,
];

/// Transfer-key handle — MATCHES the frozen `resp_public_identity_v1.bin` (TASK-22
/// `golden_response_bodies` keyed the response at `[0x33; 32]`), so a `PUBLIC_IDENTITY` request for this
/// `key_ref` against the reference body returns that exact frozen body.
pub const REFERENCE_TRANSFER_KEY_REF: [u8; 32] = [0x33; 32];
/// Faucet-treasury-key handle (distinct from the transfer handle; dedup-validated by `KeystoreBody`).
pub const REFERENCE_TREASURY_KEY_REF: [u8; 32] = [0x44; 32];

// Ed25519 authority/anchor seeds — PUBLIC test constants, derived through ed25519-dalek (never pasted
// verifying-key literals) so the body and a matching anti-rollback / commit signer can't split. The
// admin/recovery seeds + the environment + chain are ALIGNED with the TASK-22 frozen capability vectors
// (admin [7;32], recovery [9;32], env "env-prod-0", chain 11565 — see golden_capability_vectors), so the
// frozen `cap_full_*` / `req_generate_keys` / `req_configure_*` vectors VERIFY against this reference
// keystore (the mutating-op contract lane, wired in Slice 3). The anchor seed is what the contract
// server's mock commit channel signs acks with, against `anchor_root`. `pub(crate)`-visible via the body.
/// The anchor signing seed — `anchor_root` = its Ed25519 verifying key. `pub(crate)` so the contract
/// server's mock commit channel (Slice 3) signs acks with the SAME key the enclave verifies against.
pub(crate) const REFERENCE_ANCHOR_SEED: [u8; 32] = [0x42; 32];
const REFERENCE_ADMIN_SEED: [u8; 32] = [7u8; 32];
const REFERENCE_RECOVERY_SEED: [u8; 32] = [9u8; 32];

/// Reference scope `environment_identifier` (charset-valid per §10.6) — a **TEST** value (the literal
/// "prod" notwithstanding), matching the TASK-22 capability vectors so their frozen caps verify here.
pub const REFERENCE_ENVIRONMENT: &str = "env-prod-0";
/// Reference `twod_chain_id` (the crate-wide vector convention; matches the TASK-22 cap vectors).
pub const REFERENCE_CHAIN_ID: u64 = 11565;

/// Big-endian `[u8; 32]` (u256 wire form) of a `u64` — for the faucet caps/budget.
fn u256_be(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

/// The reference agent keystore body: a transfer key + a faucet treasury key (AC#2), admin/recovery
/// authorities + `anchor_root` + a funded faucet + caps. `pub` so a consumer / contract test can compute
/// the expected identities/bodies without installing the global. Models `lab_agent_smoke::smoke_body`
/// but standalone (no anchor stub / smoke-client surface) and with BOTH keys.
///
/// **Reachability:** PUBLIC_IDENTITY (no preview) works out of the box; PROVE_IDENTITY / SIGN_TRANSFER
/// are non-rollback-sensitive and work once their preview feature is enabled. The admin/recovery
/// authorities + `anchor_root` + the funded faucet are config for the **rollback-sensitive / mutating**
/// ops (SIGN_FAUCET_DISPENSE / GENERATE_KEYS / CONFIGURE_TREASURY) — those additionally need an installed
/// anti-rollback binding + a mock commit channel, which `run_contract_server` installs (behind the
/// mutating preview features) via `install_mutating_op_support` (Slice 3). With no mutating preview
/// enabled, that install is a no-op and the ops stay fail-closed (0x45/0x46). The authorities/env/chain
/// are ALIGNED with the TASK-22 capability vectors so those frozen caps verify against this body (pinned
/// by `task22_generate_keys_cap_verifies_against_reference_config`; round-trip-exercised by the
/// `contract_server` mutating tests).
pub fn reference_keystore_body() -> KeystoreBody {
    let anchor_root = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_ANCHOR_SEED)
        .verifying_key()
        .to_bytes();
    let admin_authority_pk = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_ADMIN_SEED)
        .verifying_key()
        .to_bytes();
    let recovery_authority_pk = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_RECOVERY_SEED)
        .verifying_key()
        .to_bytes();
    let transfer = crate::secp256k1::Keypair::from_secret_bytes(&REFERENCE_TRANSFER_SCALAR)
        .expect("REFERENCE_TRANSFER_SCALAR is a valid non-zero scalar < n");
    let treasury = crate::secp256k1::Keypair::from_secret_bytes(&REFERENCE_TREASURY_SCALAR)
        .expect("REFERENCE_TREASURY_SCALAR is a valid non-zero scalar < n");
    let key_entry = |key_ref, purpose, kp: &crate::secp256k1::Keypair, scalar: &[u8; 32]| KeyEntry {
        key_ref,
        purpose,
        algorithm: KeyAlgorithm::Secp256k1,
        public_identity: kp.public_key_uncompressed().to_vec(),
        secret_scalar: Zeroizing::new(scalar.to_vec()),
        creation_metadata: CreationMetadata { config_version: 0, counter_snapshot: 0, batch_id: 0 },
        backup_export_metadata: Default::default(),
    };
    KeystoreBody {
        config: KeystoreConfig {
            twod_chain_id: REFERENCE_CHAIN_ID,
            environment_identifier: REFERENCE_ENVIRONMENT.to_string(),
            admin_authority_pk,
            recovery_authority_pk,
            backup_recovery_wrapping_pubkey: vec![0x33; 1568],
            monotonic_treasury_config_version: 0,
            authority_epoch: 0,
            anchor_root,
        },
        entries: vec![
            key_entry(REFERENCE_TRANSFER_KEY_REF, KeyPurpose::AgentTransferK1, &transfer, &REFERENCE_TRANSFER_SCALAR),
            key_entry(REFERENCE_TREASURY_KEY_REF, KeyPurpose::AgentFaucetTreasuryK1, &treasury, &REFERENCE_TREASURY_SCALAR),
        ],
        counters: vec![],
        faucet: FaucetState {
            per_dispense_max_amount: u256_be(1_000_000),
            max_gas_limit: 21_000,
            max_effective_gas_fee_rate: 1_000_000_000,
            cumulative_native_spend: [0; 32],
            lifetime_spend: [0; 32],
            circuit_breaker_threshold: None,
            cumulative_signing_budget: u256_be(10_000_000),
        },
        audit: AuditRing { records: vec![], capacity: 256, last_exported_seq: 0, next_seq: 1 },
        freshness_epoch: 1,
        structural_version: 1,
        strict_recovery_counter: 0,
    }
}

/// Install [`reference_keystore_body`] as the process-global agent keystore via the same seam the SNP
/// boot path uses, so the deviceless server flips from the empty-store `0x41` profile to the agent
/// profile and answers `PUBLIC_IDENTITY` with a real identity. Returns the install result (`false` ⇒
/// empty measurement or a keystore already installed in this process — `install_agent_keystore` does NOT
/// run `validate()`; the reference body's validity is pinned separately by the AC#2 test); fail closed.
pub fn install_reference_agent_keystore() -> bool {
    crate::agent_dispatch::install_agent_keystore(
        reference_keystore_body(),
        AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    /// The reference body's `PUBLIC_IDENTITY([0x33;32])` reply is BYTE-IDENTICAL to the TASK-22 frozen
    /// `resp_public_identity_v1.bin` — the single-source-of-truth cross-check between the deviceless
    /// server and the golden vectors (a drift in keys.json / the transfer scalar / the key_ref breaks it).
    #[test]
    fn public_identity_matches_frozen_golden() {
        let _g = crate::agent_dispatch::lock_and_reset_agent_process_globals();
        assert!(install_reference_agent_keystore(), "reference keystore installs");

        // A PUBLIC_IDENTITY(2) request envelope for the reference transfer key_ref (keys {1,2,3,4,6}).
        let k = |n: u64| Value::Integer(n.into());
        let env = {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(
                &Value::Map(vec![
                    (k(1), Value::Integer((crate::agent_identity::AGENT_GATEWAY_VERSION as u64).into())),
                    (k(2), Value::Integer(2u64.into())),
                    (k(3), Value::Text(crate::agent_dispatch::COMMAND_DOMAIN.to_string())),
                    (k(4), Value::Bytes(b"contract-test:public-identity".to_vec())),
                    (k(6), Value::Bytes(REFERENCE_TRANSFER_KEY_REF.to_vec())),
                ]),
                &mut buf,
            )
            .unwrap();
            buf
        };

        let out = crate::agent_dispatch::handle_agent_gateway_frame(&env);
        let frozen: &[u8] = include_bytes!("../testvectors/agent-gateway/resp_public_identity_v1.bin");
        assert_eq!(
            out.as_slice(),
            frozen,
            "reference PUBLIC_IDENTITY reply must equal the TASK-22 frozen resp_public_identity_v1.bin",
        );
        crate::agent_dispatch::reset_agent_keystore_for_tests();
    }

    /// AC#2: the reference body carries BOTH a transfer key and a faucet treasury key, distinct handles,
    /// and a non-zero faucet budget (so the signing/faucet preview paths are reachable), and it passes
    /// the keystore `validate()` (so `install_agent_keystore` accepts it).
    #[test]
    fn reference_body_has_both_keys_and_funded_faucet() {
        let b = reference_keystore_body();
        assert_eq!(b.entries.len(), 2, "transfer + treasury");
        assert!(b.entries.iter().any(|e| e.key_ref == REFERENCE_TRANSFER_KEY_REF && e.purpose == KeyPurpose::AgentTransferK1));
        assert!(b.entries.iter().any(|e| e.key_ref == REFERENCE_TREASURY_KEY_REF && e.purpose == KeyPurpose::AgentFaucetTreasuryK1));
        assert_ne!(b.faucet.cumulative_signing_budget, [0u8; 32], "faucet budget is non-zero");
        assert!(b.validate().is_ok(), "reference body validates");
    }

    /// Couple BOTH reference scalars to the TASK-22 golden `keys.json` (the documented source of truth):
    /// the DERIVED uncompressed pubkeys must equal keys.json. The transfer key is also pinned via the
    /// frozen PUBLIC_IDENTITY response; this additionally pins the TREASURY scalar (which has no frozen
    /// response), so a rotation of keys.json breaks this test rather than silently drifting.
    #[test]
    fn reference_keys_match_task22_keys_json() {
        let keys: serde_json::Value =
            serde_json::from_str(include_str!("../testvectors/agent-gateway/keys.json")).unwrap();
        let unhex = |s: &str| hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap();
        let b = reference_keystore_body();
        let pubkey = |kr: [u8; 32]| b.entries.iter().find(|e| e.key_ref == kr).unwrap().public_identity.clone();
        assert_eq!(
            pubkey(REFERENCE_TRANSFER_KEY_REF),
            unhex(keys["transfer_key"]["pubkey_uncompressed_sec1"].as_str().unwrap()),
            "transfer pubkey == keys.json transfer_key",
        );
        assert_eq!(
            pubkey(REFERENCE_TREASURY_KEY_REF),
            unhex(keys["treasury_key"]["pubkey_uncompressed_sec1"].as_str().unwrap()),
            "treasury pubkey == keys.json treasury_key",
        );
    }

    /// The reference scope (admin authority / env / chain) is ALIGNED with the TASK-22 capability vectors:
    /// the frozen `cap_full_generate_keys_v1` cap (signed by admin `[7;32]` for env `env-prod-0`, counter 1)
    /// VERIFIES against this reference keystore's config (empty counter table → highest 0 + 1). Proves the
    /// Slice-3 mutating-op contract lane will accept the frozen vectors (not just PUBLIC_IDENTITY).
    #[test]
    fn task22_generate_keys_cap_verifies_against_reference_config() {
        let cap_bytes: &[u8] = include_bytes!("../testvectors/agent-gateway/cap_full_generate_keys_v1.bin");
        let cap = match ciborium::de::from_reader::<Value, _>(cap_bytes).unwrap() {
            Value::Map(m) => m,
            _ => panic!("cap_full is a CBOR map"),
        };
        let rid: &[u8] = b"0x40-golden:cap:generate-keys:v1";
        assert_eq!(
            crate::agent_capability::verify_capability(&cap, 1, rid, &reference_keystore_body().config, &[]),
            Ok(()),
            "frozen TASK-22 generate-keys cap must verify against the reference config",
        );
    }
}
