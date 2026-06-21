# Restore-Drill Evidence Handoff Contract

**Task:** TASK-26  
**Repos:** `2d-hsm` (ceremony source) → `2d` (evidence consumer)  
**Status:** v1 — pinned against TASK-24 (RESTORE_BACKUP handler, all 12 AC done) + TASK-13 (EXPORT_BACKUP + restore-ingress-v1 frozen format)

## 1. Ceremony + artifact version pins (AC#1)

| Artifact | Version constant | Value | Source file |
|---|---|---|---|
| RESTORE_BACKUP(8) ceremony handler | Feature flag `agent-backup-export-preview` | `v1` (the live handler; no separate ceremony version string — the handler IS the ceremony) | `agent_dispatch.rs:545` |
| restore-ingress-v1 payload format | `RESTORE_INGRESS_MAGIC` + `RESTORE_INGRESS_FORMAT_VERSION` | `"2DRIGV1\0"` + `1` (BE u16) | `agent_backup.rs:395-397` |
| restore-ingress-v1 envelope format | `RESTORE_INGRESS_ENVELOPE_MAGIC` + `RESTORE_INGRESS_ENVELOPE_FORMAT_VERSION` | `"2DAGRIE\0"` + `1` (BE u16) | `agent_backup.rs:622-624` |
| KEM-DEM domain separator | `RESTORE_INGRESS_KDF_DOMAIN` | `"2d-hsm-agent-restore-ingress-v1"` | `agent_backup.rs:630` |

The evidence bundle MUST record all four values. A drill run against a different version cannot produce valid production evidence — the 2D gate compares the bundle's version pins against these frozen constants.

## 2. Restore command contract for 2D orchestration (AC#2)

### Inputs (2D side → 2d-hsm ceremony)

The 2D node's `RestoreWriter.verify_completion/2` expects the ceremony to have run against a backup batch whose metadata matches the `attempt_started` row. The 2D side provides:

| Field | 2D source | Ceremony consumption |
|---|---|---|
| `backup_batch.id` | `operator.agent_key_backup_batches.id` | Identifies which batch's artifact was restored |
| `backup_batch.artifact_uri` | `operator.agent_key_backup_batches.artifact_uri` | The URI the operator fetched the encrypted blob from |
| `backup_batch.artifact_sha256` | `operator.agent_key_backup_batches.artifact_sha256` | Verified by the ceremony's AAD' `original_backup_digest` check |
| `backup_batch.artifact_size_bytes` | `operator.agent_key_backup_batches.artifact_size_bytes` | Verified by the ceremony's envelope parser (trailing-bytes rejection) |
| `attempt_started.id` | 2D audit row | The ceremony's `request_id` — binds this ceremony to this specific attempt |
| `attempt_started.attempt_challenge` | 2D audit row (32-byte nonce) | Consumed as the cap's `payload_binding` nonce (prevents replay against a different attempt) |
| `attempt_started.baseline_snapshot_sha256` | 2D audit row | Verified post-restore: the restored identity-set hash must match the baseline recorded when the batch reached `identity_verified` |

### Ceremony dispatch

```
AGENT_ENVELOPE {
    opcode: RESTORE_BACKUP (8),
    capability: recovery-authority-signed Ed25519 cap (is_recovery = true, bound to request_id + key_refs + backup_digest),
    payload: RestoreBackupRequest {
        ingress_envelope: Vec<u8>,       // the 2DAGRIE\0 v1 attested KEM-DEM blob
        original_backup: Vec<u8>,        // the 2DAGTBK\0 backup blob (for AAD' digest verification)
        requested_refs: Vec<[u8;32]>,    // the key_refs selector (which entries to restore)
        recovery_high_water: SignedHighWater,  // recovery-authority-signed forward-only counter marks
    },
    request_id: Vec<u8>,                 // = attempt_started.id (the 2D-committed nonce)
}
```

### Ceremony return (what 2D consumes)

The handler returns `AgentResponse::RestoreBackup { candidate: Box<KeystoreBody>, request_id }`. The 2D side does NOT receive the candidate body directly (it stays inside the enclave); instead, the host-side frame layer extracts:

| Return artifact | How extracted | What 2D records |
|---|---|---|
| Restored identity set | The frame layer reads each `KeyEntry.public_identity` from the sealed candidate and computes the `agent_restore_identity_set_v1` hash | `attempt_completed.restored_identity_set_sha256` |
| Challenge echo | `request_id` in the response == `request_id` in the request == `attempt_started.id` | `attempt_completed.attempt_challenge` (proves ceremony consumed the live nonce) |
| Ceremony success | No error code (0x00 ACK) | `attempt_completed.result = "success"` |

### Non-production fixture path

The fixture path uses the same handler (under `agent-backup-export-preview` feature flag) with a test-generated backup. The fixture's evidence bundle MUST carry `is_production: false` — the 2D gate rejects any bundle with this flag for production enablement. The fixture proves mechanical correctness only.

## 3. Challenge/nonce echo binding (AC#3)

### Where the echo lives

The `request_id` field of the `AGENT_ENVELOPE` is the challenge nonce. It flows:

1. **2D commits** `attempt_started` with a high-entropy `attempt_challenge` (32-byte random nonce).
2. **Operator** passes `attempt_started.id` as the ceremony's `request_id`.
3. **Ceremony** binds the `request_id` into the cap's `payload_binding` (`restore_canonical_params(requested_refs, backup_digest)` + `request_id`). A cap issued for one `request_id` cannot authorize a different one.
4. **Ceremony** returns `AgentResponse::RestoreBackup { request_id }` — the SAME value.
5. **2D** verifies `attempt_completed.attempt_challenge == the value it committed in attempt_started` AND `ceremony_response.request_id == attempt_started.id`.

### Replay prevention

A replay of a prior ceremony output against a fresh `attempt_started` is detected at step 3: the cap's `payload_binding` includes the `request_id`, and the handler verifies `expected_binding == verified.payload_binding` (compact 9499 HIGH #1). A different `request_id` produces a different `payload_binding`, so the cap does not match → `CapabilityRejected` (0x43).

## 4. Restored identity-set evidence shape (AC#4)

### 2D canonical entry shape (`agent_restore_identity_set_v1`)

```json
{
  "entries": [
    {
      "source_table": "agent_transfer_keys",
      "row_id": "uuid",
      "backend": "twod_hsm",
      "algorithm": "secp256k1",
      "key_ref": "hex-string",
      "status": "assigned",
      "address": "0x..."
    }
  ]
}
```

### 2d-hsm → 2D field mapping

The ceremony's restored `KeystoreBody.entries` (type `KeyEntry`) maps to the 2D identity-set entry as follows:

| 2D field | 2d-hsm KeyEntry field | Derivation |
|---|---|---|
| `source_table` | `KeyEntry.purpose` | `Transfer` → `"agent_transfer_keys"`; `FaucetTreasury` → `"agent_faucet_treasury_keys"` |
| `row_id` | (not in KeyEntry) | Derived from 2D's `backup_batch` row — the batch links to the original key rows; the ceremony restores the same entries |
| `backend` | (implicit) | Always `"twod_hsm"` (the ceremony IS the 2d-hsm backend) |
| `algorithm` | `KeyEntry.algorithm` | `Secp256k1` → `"secp256k1"` |
| `key_ref` | `KeyEntry.key_ref` | Hex-encode the 32-byte opaque handle |
| `status` | (not in KeyEntry) | Derived from the 2D batch's key-row status at baseline time (the ceremony restores the entries; the status is a 2D-side lifecycle field, not an enclave property) |
| `address` | `KeyEntry.public_identity` | Derive the 20-byte Ethereum address from the 65-byte uncompressed SEC1 public key: `keccak256(pubkey[1..65])[0..20]` |

The restored identity-set SHA-256 hash is computed over the canonical JSON of this entry set (sorted by `(source_table, row_id)`, lowercase strings, explicit nulls — same canonicalization as 2D's `RestoreCanonical.identity_set_hash/1`).

## 5. Production-readiness evidence bundle schema (AC#5)

```json
{
  "schema_version": "restore-drill-evidence-v1",
  "is_production": true,
  "environment": {
    "chain_id": 11565,
    "network_identifier": "mainnet",
    "environment_identifier": "production"
  },
  "ceremony": {
    "handler_feature": "agent-backup-export-preview",
    "restore_ingress_format_version": 1,
    "restore_ingress_envelope_format_version": 1,
    "kdf_domain": "2d-hsm-agent-restore-ingress-v1"
  },
  "batches": [
    {
      "backup_batch_id": "uuid",
      "artifact_uri": "file:///...",
      "artifact_sha256": "hex",
      "artifact_size_bytes": 12345,
      "attempt_started_event_id": "uuid",
      "attempt_completed_event_id": "uuid",
      "attempt_challenge_echo": "hex-32",
      "expected_identity_set_sha256": "hex",
      "restored_identity_set_sha256": "hex",
      "identity_match": true,
      "remediation_status": null
    }
  ],
  "sign_off": {
    "agent_gateway_operator_owner": "name/date/signature",
    "recovery_material_custodian": "name/date/signature"
  }
}
```

### Machine-checkable constraints

- `schema_version == "restore-drill-evidence-v1"` (hardcoded)
- `is_production == true` (fixture bundles set false)
- `ceremony.restore_ingress_format_version == 1`
- `ceremony.restore_ingress_envelope_format_version == 1`
- Every batch entry has `identity_match == true` (or a documented `remediation_status`)
- Every batch has `expected_identity_set_sha256 == restored_identity_set_sha256`
- `sign_off` has both fields non-empty

## 6. Production coverage rule (AC#6)

The bundle's `batches[]` array MUST include one entry for EVERY active production backup batch that is linked to:

- An enabled faucet treasury row (`operator.agent_faucet_treasury_keys` where `disabled_at IS NULL`), OR
- An assigned transfer key row (`operator.agent_transfer_keys` where `status = 'assigned'` or `status = 'generated_unbacked'`).

Batches NOT covered MUST have a documented `remediation_status` AND the linked 2D rows MUST be `disabled`/`retired` BEFORE `:agent_restore_provenance_enforced` is set `true`.

### Query (2D-side, run before enforcement)

```sql
SELECT b.id, b.purpose,
       EXISTS(SELECT 1 FROM operator.agent_faucet_treasury_keys k WHERE k.backup_batch_id = b.id AND k.disabled_at IS NULL) AS faucet_active,
       EXISTS(SELECT 1 FROM operator.agent_transfer_keys k WHERE k.backup_batch_id = b.id AND k.status IN ('assigned', 'generated_unbacked')) AS transfer_active
FROM operator.agent_key_backup_batches b
WHERE b.status = 'identity_verified';
```

Every row where `faucet_active OR transfer_active` must appear in the bundle.

## 7. Cross-repo handoff fixture (AC#7)

The fixture is a **2D-side test** that exercises the contract end-to-end against a non-production backup. It lives in the **2D repo** (not 2d-hsm) because it drives the 2D-side audit schema + writer + validator:

```
test/chain/agent_gateway/restore_drill_cross_repo_fixture_test.exs
```

### Fixture flow

1. **2D**: Insert a `backup_batch` + key rows → run `RestoreBaseline.record_identity_verified/2` to set baseline hashes.
2. **2D**: Call `RestoreWriter.start_attempt/1` to commit `attempt_started` with a challenge nonce.
3. **2d-hsm (stand-in)**: Build a test `RestoreBackupRequest` using the same backup batch's artifact metadata + the `attempt_started.id` as `request_id`. For the non-production fixture, a stand-in helper simulates the ceremony's identity-set output (the restored entries match the baseline entries).
4. **2D**: Call `RestoreWriter.verify_completion/2` with the simulated ceremony output → verifies `attempt_completed` row + success attachment.
5. **2D**: Call `RestoreProvenance.validator_for/3` → returns `true` for the restored batch.
6. **Validate**: The resulting evidence bundle passes the AC#5 schema constraints.

### Non-production stand-in rationale

The real RESTORE_BACKUP(8) handler (TASK-24) runs inside an enclave TEE and requires:
- A live SEV-SNP VM
- A published ephemeral ML-KEM-1024 key
- An attested ingress envelope (KEM-DEM re-wrapped)

These cannot run in ExUnit. The fixture uses a stand-in that preserves the contract's observable behavior (same identity-set output, same challenge echo, same request_id binding) without the enclave TEE. The 2D-side code paths (`RestoreWriter`, `RestoreProvenance.validator_for/3`, `RestoreAuditEvidence`) are identical whether the ceremony ran in a real TEE or the stand-in.

## 8. Scope exclusions (AC#8)

| Owned by | Surface |
|---|---|
| **2D TASK-132.5.3.x** (merged) | Audit schema, controlled writer, config loader, inventory monitor, provenance validator |
| **2d-hsm TASK-24** (done) | RESTORE_BACKUP(8) handler internals (KEM-DEM, AAD, wholesale-replace, counter seeding) |
| **2d-solidity TASK-1.4** | On-chain RecoveryTicket / MeasurementRegistry (disjoint per TASK-24 AC#12) |
| **Out of MVP** | Quorum / M-of-N recovery, classical hybrid X25519+ML-KEM, authority rotation |
| **TASK-26 (this contract)** | Cross-repo handoff artifact contract + evidence bundle schema + field mapping + coverage rule |
