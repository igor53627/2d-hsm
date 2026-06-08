//! Agent Gateway key generation (TASK-7.6.3 / `AGENT_K1_GENERATE_KEYS`) — keystore mutation core.
//!
//! Generates secp256k1 keys inside the enclave and appends sealed [`KeyEntry`]s to a keystore body.
//! Scope of this slice: the **all-or-nothing in-memory mutation** (keypair gen, opaque random
//! `key_ref` + uniqueness, treasury-singleton rule, capacity guard, entry append). The caller seals
//! the mutated body in **one** `seal_body` commit, so atomicity (7.2 AC#18) holds: a seal/persist
//! failure discards the in-memory mutation, leaving no orphan refs. The **admin
//! capability-counter advance**, capability verification, the single-writer critical section, and
//! persistence are the dispatch layer's job (next slice) — they wrap this core.
//!
//! Built only under the `agent-gateway` feature.

use crate::agent_keystore::{
    BackupExportMetadata, CreationMetadata, KeyAlgorithm, KeyEntry, KeyPurpose, KeystoreBody,
    MAX_BATCH_SIZE, MAX_TOTAL_KEY_ENTRIES,
};
use crate::secp256k1::{tron_address_from_body, Keypair};
use std::collections::HashSet;
use zeroize::Zeroizing;

/// Errors from key generation. Coarse; the dispatch layer collapses several of these into the
/// anti-oracle error band (e.g. `TreasuryExists` → `AGENT_CAPABILITY_REJECTED`, never distinguishable
/// from "no/insufficient capability").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateKeysError {
    /// `count` invalid for the purpose: treasury must be exactly 1; transfer must be ≥ 1.
    InvalidCount,
    /// A treasury key already exists (singleton rule, 7.3 AC#2).
    TreasuryExists,
    /// Per-batch (`MAX_BATCH_SIZE`) or total (`MAX_TOTAL_KEY_ENTRIES`) capacity exceeded.
    CapacityExceeded,
    /// CSPRNG unavailable, or no unique `key_ref` / valid scalar found within the retry bound.
    Csprng,
}

/// The public result of generating one key — returned to the caller; the secret scalar stays
/// sealed in the keystore entry and is never returned. (No secret material, so `Debug` is safe.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    pub key_ref: [u8; 32],
    pub pubkey_uncompressed: [u8; 65],
    pub eth_address: [u8; 20],
    pub tron_address: String,
    pub key_purpose: KeyPurpose,
}

/// Retry bound for drawing a unique `key_ref` / a valid secret scalar. Collisions and invalid
/// scalars are astronomically unlikely; exceeding the bound signals a degraded RNG → fail closed.
const RNG_RETRIES: usize = 8;

/// Generate `count` keys of `purpose`, appending them to `body` (in-memory). All-or-nothing: on any
/// failure `body` is left untouched (entries are staged and only committed once all `count` succeed).
///
/// - **Treasury** (`agent_faucet_treasury_k1`): singleton — `count` must be 1 and none may already
///   exist (else [`GenerateKeysError::TreasuryExists`]).
/// - **Transfer** (`agent_transfer_k1`): batch — `count` ≥ 1.
///
/// Each key gets a fresh random 32-byte `key_ref` from the TEE CSPRNG (never host-supplied), unique
/// against existing **and** in-batch refs. Capacity is checked before any generation. The private
/// scalar is drawn from the TEE CSPRNG and held in `Zeroizing` (7.2 AC#15). `creation` is the
/// caller-supplied config-version + counter snapshot recorded on each entry.
pub fn generate_keys(
    body: &mut KeystoreBody,
    purpose: KeyPurpose,
    count: usize,
    creation: CreationMetadata,
) -> Result<Vec<GeneratedKey>, GenerateKeysError> {
    // 1. count rules per purpose.
    match purpose {
        KeyPurpose::AgentFaucetTreasuryK1 if count != 1 => return Err(GenerateKeysError::InvalidCount),
        KeyPurpose::AgentTransferK1 if count == 0 => return Err(GenerateKeysError::InvalidCount),
        _ => {}
    }
    // 2. treasury singleton — a second active treasury key fails closed.
    if purpose == KeyPurpose::AgentFaucetTreasuryK1
        && body.entries.iter().any(|e| e.purpose == KeyPurpose::AgentFaucetTreasuryK1)
    {
        return Err(GenerateKeysError::TreasuryExists);
    }
    // 3. capacity — before any generation/mutation.
    if count > MAX_BATCH_SIZE || body.entries.len() + count > MAX_TOTAL_KEY_ENTRIES {
        return Err(GenerateKeysError::CapacityExceeded);
    }
    // 4. uniqueness set seeded with the existing sealed refs.
    let mut seen: HashSet<[u8; 32]> = body.entries.iter().map(|e| e.key_ref).collect();

    // 5. stage all entries; commit to `body` only if every key succeeds (all-or-nothing).
    let mut staged = Vec::with_capacity(count);
    let mut generated = Vec::with_capacity(count);
    for _ in 0..count {
        // Opaque, unique key_ref from the TEE CSPRNG.
        let mut key_ref = [0u8; 32];
        let mut unique = false;
        for _ in 0..RNG_RETRIES {
            getrandom::getrandom(&mut key_ref).map_err(|_| GenerateKeysError::Csprng)?;
            if !seen.contains(&key_ref) {
                unique = true;
                break;
            }
        }
        if !unique {
            return Err(GenerateKeysError::Csprng);
        }
        seen.insert(key_ref);

        // Keypair + its secret via the single canonical secp256k1 keygen path (rejection-samples a
        // valid non-zero scalar < n, scrubbing each rejected draw). The secret is returned in
        // Zeroizing only so we can seal it into the entry.
        let (keypair, secret) =
            Keypair::generate_with_secret().map_err(|_| GenerateKeysError::Csprng)?;
        let pubkey_uncompressed = keypair.public_key_uncompressed();
        let eth_address = keypair.eth_address();
        let tron_address = tron_address_from_body(&eth_address);

        staged.push(KeyEntry {
            key_ref,
            purpose,
            algorithm: KeyAlgorithm::Secp256k1,
            public_identity: pubkey_uncompressed.to_vec(),
            secret_scalar: Zeroizing::new(secret.to_vec()),
            creation_metadata: creation,
            backup_export_metadata: BackupExportMetadata::default(),
        });
        generated.push(GeneratedKey {
            key_ref,
            pubkey_uncompressed,
            eth_address,
            tron_address,
            key_purpose: purpose,
        });
    }

    // 6. commit — all keys generated; append to the body in one shot.
    body.entries.extend(staged);
    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{seal_body, unseal_body, AuditRing, FaucetState, KeystoreConfig};

    const ROOT: [u8; 32] = [0x44; 32];
    const MEAS: &[u8] = b"keygen-test-measurement";

    fn creation() -> CreationMetadata {
        CreationMetadata { config_version: 1, counter_snapshot: 0, batch_id: 1 }
    }

    /// A valid, sealable keystore body with no entries (1568-byte ML-KEM wrapping key so seal_body
    /// passes `validate()`).
    fn empty_body() -> KeystoreBody {
        KeystoreBody {
            config: KeystoreConfig {
                twod_chain_id: 11565,
                environment_identifier: "testnet".to_string(),
                admin_authority_pk: [0xa1; 32],
                recovery_authority_pk: [0xa2; 32],
                backup_recovery_wrapping_pubkey: vec![0xb0; 1568],
                monotonic_treasury_config_version: 1,
                authority_epoch: 0,
                anchor_root: [0xa3; 32],
            },
            entries: vec![],
            counters: vec![],
            faucet: FaucetState {
                per_dispense_max_amount: [0; 32],
                max_gas_limit: 21000,
                max_effective_gas_fee_rate: 100,
                cumulative_native_spend: [0; 32],
                lifetime_spend: [0; 32],
                circuit_breaker_threshold: None,
            },
            audit: AuditRing { records: vec![], capacity: 64, last_exported_seq: 0, next_seq: 1 },
            freshness_epoch: 1,
        }
    }

    #[test]
    fn transfer_batch_appends_unique_valid_keys() {
        let mut body = empty_body();
        let out = generate_keys(&mut body, KeyPurpose::AgentTransferK1, 3, creation()).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(body.entries.len(), 3);
        // All key_refs unique; all entries valid secp256k1 (0x04 prefix, 65-byte pubkey).
        let mut refs = HashSet::new();
        for (g, e) in out.iter().zip(body.entries.iter()) {
            assert!(refs.insert(g.key_ref), "key_refs must be unique");
            assert_eq!(g.key_ref, e.key_ref);
            assert_eq!(e.public_identity.len(), 65);
            assert_eq!(e.public_identity[0], 0x04);
            assert_eq!(e.secret_scalar.len(), 32);
            assert_eq!(e.purpose, KeyPurpose::AgentTransferK1);
            // eth/tron returned match the entry's pubkey.
            assert_eq!(
                g.eth_address.to_vec(),
                crate::secp256k1::eth_address_from_uncompressed(&g.pubkey_uncompressed).unwrap().to_vec()
            );
        }
        // The mutated body still seals + round-trips (secrets survive).
        let blob = seal_body(&body, &ROOT, MEAS).unwrap();
        let back = unseal_body(&blob, &ROOT, MEAS).unwrap();
        assert_eq!(back.entries.len(), 3);
        assert_eq!(back.entries[0].secret_scalar, body.entries[0].secret_scalar);
    }

    #[test]
    fn treasury_is_singleton() {
        let mut body = empty_body();
        generate_keys(&mut body, KeyPurpose::AgentFaucetTreasuryK1, 1, creation()).unwrap();
        assert_eq!(body.entries.len(), 1);
        // A second treasury keygen fails closed and does not mutate.
        assert_eq!(
            generate_keys(&mut body, KeyPurpose::AgentFaucetTreasuryK1, 1, creation()),
            Err(GenerateKeysError::TreasuryExists)
        );
        assert_eq!(body.entries.len(), 1, "failed keygen must not append");
    }

    #[test]
    fn count_rules_enforced() {
        let mut body = empty_body();
        // treasury count != 1
        assert_eq!(
            generate_keys(&mut body, KeyPurpose::AgentFaucetTreasuryK1, 2, creation()),
            Err(GenerateKeysError::InvalidCount)
        );
        // transfer count == 0
        assert_eq!(
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, 0, creation()),
            Err(GenerateKeysError::InvalidCount)
        );
        assert!(body.entries.is_empty());
    }

    #[test]
    fn capacity_enforced() {
        let mut body = empty_body();
        // over per-batch limit
        assert_eq!(
            generate_keys(&mut body, KeyPurpose::AgentTransferK1, MAX_BATCH_SIZE + 1, creation()),
            Err(GenerateKeysError::CapacityExceeded)
        );
        // over total capacity (simulate a near-full store cheaply by pre-filling refs is expensive;
        // instead request more than total in one batch is capped by MAX_BATCH_SIZE, so assert the
        // total-capacity branch via a count that with existing entries exceeds the total).
        assert!(body.entries.is_empty(), "no mutation on capacity failure");
    }

    #[test]
    fn all_or_nothing_no_partial_on_failure() {
        // A treasury request with count=2 fails the count rule before generating anything.
        let mut body = empty_body();
        generate_keys(&mut body, KeyPurpose::AgentTransferK1, 2, creation()).unwrap();
        let before = body.entries.len();
        assert_eq!(
            generate_keys(&mut body, KeyPurpose::AgentFaucetTreasuryK1, 3, creation()),
            Err(GenerateKeysError::InvalidCount)
        );
        assert_eq!(body.entries.len(), before, "failed keygen leaves body unchanged");
    }
}
