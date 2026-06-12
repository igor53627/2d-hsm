//! TASK-7.7 5b-2c-iii **lab SNP live-smoke** surface — **TEST KEYS ONLY, release-banned**.
//!
//! Everything the aya live smoke needs that is not the real agent-gateway bin lives HERE, in one
//! in-crate module, so every smoke artifact (the minted smoke keystore, the lab anchor stub, the
//! host-side 0x40 client cores) reuses the crate's own canonical encoders/verifiers and is
//! cross-validated against the real serve/verify paths by deviceless tests — protocol drift between
//! the smoke tooling and the enclave is made unrepresentable before anything runs on SNP hardware.
//!
//! ## TEST KEYS ONLY
//! [`LAB_ANCHOR_TEST_SEED`] is a public, in-repo Ed25519 seed and [`SMOKE_SECRET_SCALAR`] is a
//! public secp256k1 scalar. They carry **no secrecy claim whatsoever**: they exist so the smoke
//! keystore fixture, the anchor stub and the client expectations are reproducible from one source.
//! The whole module is gated behind `lab-agent-smoke`, which is hard-banned from release builds by
//! a `compile_error!` in `lib.rs` (mirrors `lab-quote-smoke`); under plain `cfg(test)` it compiles
//! only for the freeze/cross-validation tests.
//!
//! The guest image does NOT enable this feature: the guest runs the real `twod-hsm-agent-gateway`
//! bin with `lab-agent-keystore-from-file` pointing at the fixture minted here.

// The mint constants/helpers land first (this commit); the anchor stub + client cores that consume
// them outside cfg(test) land in the follow-on commits of this slice. Mirror the agent_anchor
// staging discipline: allow dead-code in the non-test lib build only, remove when fully consumed.
#![cfg_attr(not(test), allow(dead_code))]

use crate::agent_keystore::{
    seal_keystore_with_nonce, AuditRing, CreationMetadata, FaucetState, KeyAlgorithm, KeyEntry,
    KeyPurpose, KeystoreBody, KeystoreConfig,
};
use crate::AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT;
use zeroize::Zeroizing;

/// **TEST KEYS ONLY** — public in-repo Ed25519 seed for the lab anchor stub. The smoke keystore's
/// `anchor_root` is the verifying key derived from this seed, so the stub (and only a holder of
/// this public constant) can sign freshness responses the smoke guest accepts. No secrecy claim;
/// the enclosing feature is release-banned.
pub(crate) const LAB_ANCHOR_TEST_SEED: [u8; 32] = [0x42; 32];

/// **TEST KEYS ONLY** — public secp256k1 secret scalar of the smoke keystore's single key entry
/// (a valid non-zero scalar `< n`). Public on purpose: the host-side client derives the expected
/// PUBLIC_IDENTITY reply (pubkey/eth/tron) from it via the crate's own `secp256k1` path.
pub(crate) const SMOKE_SECRET_SCALAR: [u8; 32] = [0x77; 32];

/// The smoke entry's opaque key handle (request key 6 of the PUBLIC_IDENTITY round-trip).
/// Distinct from every genesis literal so a mixed-up fixture fails loudly.
pub(crate) const SMOKE_KEY_REF: [u8; 32] = [0x11; 32];

/// Fixed seal nonce → byte-stable smoke golden blob (the only randomness in the seal).
/// Distinct from the genesis nonce (`[0x5d; 24]`).
pub(crate) const SMOKE_SEAL_NONCE: [u8; 24] = [0x5e; 24];

/// The committed reference provisioning root the smoke fixture is sealed under — the SAME root file
/// the producer lab fixtures use (`TWOD_HSM_PQ_SEAL_V1_ROOT_FILE` points here in the lab guest);
/// the agent/producer KDF domains are separated inside `agent_keystore`, not by distinct roots.
pub(crate) const SMOKE_SEAL_ROOT: &[u8; 32] =
    include_bytes!("../testvectors/seal_v1_provisioning_root.bin");

/// `environment_identifier` of the smoke scope (charset-valid per TASK-7.1 §10.6).
pub(crate) const SMOKE_ENVIRONMENT: &str = "lab-snp-smoke";

/// `twod_chain_id` of the smoke scope (matches the vector convention used across the crate).
pub(crate) const SMOKE_CHAIN_ID: u64 = 11565;

/// The minted 5b-2c-iii smoke keystore body — the single source feeding the committed fixture
/// (regen test), the lab anchor stub's scope/marks derivation AND the host-side client's expected
/// PUBLIC_IDENTITY reply. Differences from the genesis body, all load-bearing for the smoke:
/// `anchor_root` is derived from [`LAB_ANCHOR_TEST_SEED`] (the stub can actually sign for it, so
/// boot reaches `Ready`), and there is ONE key entry (so PUBLIC_IDENTITY returns a SUCCESS body,
/// not `0x42` — the zero-entry genesis stays the negative control).
pub(crate) fn smoke_body() -> KeystoreBody {
    let anchor_root = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED)
        .verifying_key()
        .to_bytes();
    // On-curve by construction: derive the public identity through the crate's own secp256k1 path,
    // never pasted hex (a stale literal here would split the fixture from the client expectations).
    let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR)
        .expect("SMOKE_SECRET_SCALAR is a valid non-zero scalar < n");
    KeystoreBody {
        config: KeystoreConfig {
            twod_chain_id: SMOKE_CHAIN_ID,
            environment_identifier: SMOKE_ENVIRONMENT.to_string(),
            // Distinct from the genesis `[0xa3; 32]` literals so fixture mix-ups fail loudly.
            admin_authority_pk: [0xa1; 32],
            recovery_authority_pk: [0xa2; 32],
            backup_recovery_wrapping_pubkey: vec![0x33; 1568],
            monotonic_treasury_config_version: 0,
            authority_epoch: 0,
            anchor_root,
        },
        entries: vec![KeyEntry {
            key_ref: SMOKE_KEY_REF,
            purpose: KeyPurpose::AgentTransferK1,
            algorithm: KeyAlgorithm::Secp256k1,
            public_identity: keypair.public_key_uncompressed().to_vec(),
            secret_scalar: Zeroizing::new(SMOKE_SECRET_SCALAR.to_vec()),
            creation_metadata: CreationMetadata {
                config_version: 0,
                counter_snapshot: 0,
                batch_id: 0,
            },
            backup_export_metadata: Default::default(),
        }],
        counters: vec![],
        faucet: FaucetState {
            per_dispense_max_amount: [0; 32],
            max_gas_limit: 0,
            max_effective_gas_fee_rate: 0,
            cumulative_native_spend: [0; 32],
            lifetime_spend: [0; 32],
            circuit_breaker_threshold: None,
        },
        audit: AuditRing { records: vec![], capacity: 256, last_exported_seq: 0, next_seq: 1 },
        freshness_epoch: 1,
        structural_version: 1,
        strict_recovery_counter: 0,
    }
}

/// Deterministic CBOR of `body` — exactly what `seal_body` encodes internally, so `unseal_body`
/// round-trips a blob sealed from this (mirrors the genesis helper in `boot_agent_keystore`).
fn cbor_of(body: &KeystoreBody) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(body, &mut buf).expect("smoke body encodes");
    buf
}

/// The byte-stable smoke golden blob: committed reference root + placeholder measurement + fixed
/// nonce. The placeholder measurement matches the genesis precedent — the real attested 48-byte
/// SNP launch measurement is the deferred production keystore-source slice, recorded as explicit
/// non-coverage in SMOKE-PASS-CRITERIA.
pub(crate) fn smoke_sealed_blob() -> Vec<u8> {
    seal_keystore_with_nonce(
        &cbor_of(&smoke_body()),
        SMOKE_SEAL_ROOT,
        AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT,
        &SMOKE_SEAL_NONCE,
    )
    .expect("smoke body seals")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_keystore::{unseal_body, MAX_KEYSTORE_BLOB_SIZE};
    use sha3::Digest;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn smoke_body_validates_and_round_trips() {
        let body = smoke_body();
        body.validate().expect("smoke body passes structural validation");
        let blob = smoke_sealed_blob();
        assert_eq!(&blob[8..10], &[0x00, 0x02], "format_version 2 in the header");
        assert!(blob.len() <= MAX_KEYSTORE_BLOB_SIZE, "smoke blob is re-installable");
        let unsealed =
            unseal_body(&blob, SMOKE_SEAL_ROOT, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT)
                .expect("smoke blob unseals");
        assert_eq!(unsealed, body);
    }

    #[test]
    fn smoke_anchor_root_is_derived_from_the_test_seed() {
        // The whole point of the minted fixture: the stub's seed-derived verifying key IS the
        // sealed anchor_root (the genesis fixture fails this by construction — [0xa3; 32]).
        let derived = ed25519_dalek::SigningKey::from_bytes(&LAB_ANCHOR_TEST_SEED)
            .verifying_key()
            .to_bytes();
        assert_eq!(smoke_body().config.anchor_root, derived);
    }

    #[test]
    fn smoke_marks_payload_digest_is_the_documented_75_bytes() {
        // Couples `compute_local_marks_digest`'s input for the EXACT provisioned smoke state
        // (empty counters, zero spend, strict_recovery_counter 0) to the frozen v1 marks grammar:
        // `a4 01 80 02 58 20 [32x00] 03 58 20 [32x00] 04 00` (75 bytes). The lab anchor stub
        // derives its response key-6 from this same digest, so a marks-grammar drift fails HERE,
        // deviceless, never as a mystery FailClosed(Inconsistent) on aya.
        let mut expected_payload = Vec::with_capacity(75);
        expected_payload.extend_from_slice(&[0xa4, 0x01, 0x80, 0x02, 0x58, 0x20]);
        expected_payload.extend_from_slice(&[0u8; 32]);
        expected_payload.extend_from_slice(&[0x03, 0x58, 0x20]);
        expected_payload.extend_from_slice(&[0u8; 32]);
        expected_payload.extend_from_slice(&[0x04, 0x00]);
        assert_eq!(expected_payload.len(), 75);
        let mut h = sha3::Sha3_256::new();
        h.update(crate::agent_keystore::MARKS_DOMAIN);
        h.update(&expected_payload);
        let expected_digest: [u8; 32] = h.finalize().into();
        assert_eq!(smoke_body().compute_local_marks_digest(), expected_digest);
    }

    #[test]
    fn agent_smoke_golden_blob_is_byte_exact() {
        // The in-source mint and the committed bytes must agree byte-for-byte — any deterministic-
        // CBOR / header / KeystoreBody-field drift flips this AND the guest's from-disk unseal.
        let committed: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin");
        assert_eq!(
            smoke_sealed_blob().as_slice(),
            committed,
            "smoke golden drifted; if the body layout/format_version changed intentionally, regen \
             via `regen_agent_smoke_golden_vector` (it re-mints the .json sidecar too) in the same \
             commit"
        );
        let body =
            unseal_body(committed, SMOKE_SEAL_ROOT, AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT)
                .expect("committed smoke golden unseals");
        assert_eq!(body, smoke_body());
    }

    #[test]
    fn agent_smoke_golden_sidecar_matches_blob() {
        // Field-coupled (not substring) sidecar check, mirroring the genesis discipline: a regen
        // that updates the blob but forgets the sidecar — or vice versa — fails CI. The regen test
        // mints BOTH files from the same constants, so passing this means they agree.
        use sha2::{Digest as _, Sha256};
        let blob: &[u8] =
            include_bytes!("../testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin");
        let sidecar = include_str!("../testvectors/agent-gateway/agent_keystore_smoke_v1.json");
        let v: serde_json::Value =
            serde_json::from_str(sidecar).expect("smoke sidecar must be valid JSON");
        let body = smoke_body();
        let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR).unwrap();
        assert_eq!(v["warning"].as_str(), Some("TEST KEYS ONLY"), "sidecar warning banner");
        assert_eq!(
            v["blob_sha256"].as_str(),
            Some(hex(&Sha256::digest(blob)).as_str()),
            "sidecar blob_sha256 drift — re-run the regen test (it re-mints both files)"
        );
        assert_eq!(v["blob_len_bytes"].as_u64(), Some(blob.len() as u64), "blob_len_bytes drift");
        assert_eq!(
            v["envelope"]["nonce_hex"].as_str(),
            Some(hex(&SMOKE_SEAL_NONCE).as_str()),
            "nonce_hex drift"
        );
        assert_eq!(
            v["seal_inputs"]["provisioning_root_hex"].as_str(),
            Some(hex(SMOKE_SEAL_ROOT).as_str()),
            "provisioning_root_hex drift"
        );
        assert_eq!(
            v["seal_inputs"]["enclave_measurement_hex"].as_str(),
            Some(hex(AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT).as_str()),
            "enclave_measurement_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["anchor_root_hex"].as_str(),
            Some(hex(&body.config.anchor_root).as_str()),
            "anchor_root_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["key_ref_hex"].as_str(),
            Some(hex(&SMOKE_KEY_REF).as_str()),
            "key_ref_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["public_identity_hex"].as_str(),
            Some(hex(&keypair.public_key_uncompressed()).as_str()),
            "public_identity_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["eth_address_hex"].as_str(),
            Some(hex(&keypair.eth_address()).as_str()),
            "eth_address_hex drift"
        );
        assert_eq!(
            v["smoke_identity"]["tron_address"].as_str(),
            Some(keypair.tron_address().as_str()),
            "tron_address drift"
        );
    }

    /// REGEN (manual): `cargo test --features agent-gateway,lab-agent-smoke \
    /// regen_agent_smoke_golden_vector -- --ignored --nocapture`, then commit BOTH files and re-run
    /// the suite (`git diff --exit-code` over `testvectors/` must be clean on a second regen —
    /// regen-idempotence). Unlike the genesis regen this mints the `.json` sidecar too, so the
    /// blob/sidecar pair can never be regenerated apart.
    #[test]
    #[ignore]
    fn regen_agent_smoke_golden_vector() {
        use sha2::{Digest as _, Sha256};
        let blob = smoke_sealed_blob();
        let body = smoke_body();
        let keypair = crate::secp256k1::Keypair::from_secret_bytes(&SMOKE_SECRET_SCALAR).unwrap();
        let bin_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testvectors/agent-gateway/agent_keystore_smoke_v1.sealed.bin"
        );
        std::fs::write(bin_path, &blob).expect("write smoke keystore blob");
        let sidecar = serde_json::json!({
            "_comment": "TASK-7.7 5b-2c-iii minted SMOKE keystore for the aya SNP live smoke. \
                 TEST KEYS ONLY — the anchor seed and the secp256k1 scalar are public in-repo \
                 constants (lab_agent_smoke.rs); never a production keystore. Re-mint BOTH files \
                 via `cargo test --features agent-gateway,lab-agent-smoke \
                 regen_agent_smoke_golden_vector -- --ignored --nocapture`; the \
                 agent_smoke_golden_* tests fail CI if either file drifts.",
            "warning": "TEST KEYS ONLY",
            "blob_file": "agent_keystore_smoke_v1.sealed.bin",
            "blob_len_bytes": blob.len(),
            "blob_sha256": hex(&Sha256::digest(&blob)),
            "envelope": {
                "keystore_magic_ascii": "2DAGTKS<NUL>",
                "keystore_format_version": 2,
                "aead": "XChaCha20Poly1305",
                "nonce_hex": hex(&SMOKE_SEAL_NONCE),
            },
            "seal_inputs": {
                "provisioning_root_file": "../seal_v1_provisioning_root.bin",
                "provisioning_root_hex": hex(SMOKE_SEAL_ROOT),
                "enclave_measurement_str": "agent-keystore-measurement-placeholder",
                "enclave_measurement_hex": hex(AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT),
                "enclave_measurement_note": "AGENT_KEYSTORE_BOOT_PLACEHOLDER_MEASUREMENT — the \
                     real attested 48-byte SNP launch measurement is the deferred production \
                     keystore-source slice (explicit smoke non-coverage).",
            },
            "smoke_identity": {
                "anchor_test_seed_hex": hex(&LAB_ANCHOR_TEST_SEED),
                "anchor_root_hex": hex(&body.config.anchor_root),
                "key_ref_hex": hex(&SMOKE_KEY_REF),
                "secret_scalar_hex": hex(&SMOKE_SECRET_SCALAR),
                "public_identity_hex": hex(&keypair.public_key_uncompressed()),
                "eth_address_hex": hex(&keypair.eth_address()),
                "tron_address": keypair.tron_address(),
            },
            "scope": {
                "twod_chain_id": SMOKE_CHAIN_ID,
                "environment_identifier": SMOKE_ENVIRONMENT,
                "freshness_epoch": 1,
                "structural_version": 1,
                "strict_recovery_counter": 0,
            },
        });
        let json_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testvectors/agent-gateway/agent_keystore_smoke_v1.json"
        );
        let pretty = serde_json::to_string_pretty(&sidecar).expect("sidecar serializes");
        std::fs::write(json_path, pretty + "\n").expect("write smoke keystore sidecar");
        eprintln!("wrote {} bytes -> {bin_path}\nwrote sidecar -> {json_path}", blob.len());
    }
}
