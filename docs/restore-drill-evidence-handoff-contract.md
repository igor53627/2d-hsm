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
| `attempt_started.id` | 2D audit row | **The ceremony's `request_id` — the SOLE replay token.** Bound into the cap's `payload_binding` AND the recovery-authority high-water signature AND echoed in the RESTORE_BACKUP response (key 2). A cap+high-water minted for one `request_id` cannot authorize/verify under another ⇒ replay of a prior ceremony output against a fresh attempt is caught at BOTH the cap verify (payload_binding mismatch → 0x43) and the high-water verify (signature bound to request_id). **Nonce model RESOLUTION (was contradictory):** `attempt_started.id` MUST be a fresh high-entropy value per attempt (2D mints it — e.g. a UUID or a CSPRNG-drawn id), so `request_id` carries the challenge entropy directly. |
| `attempt_started.attempt_challenge` | 2D audit row (32-byte nonce) | **2D-side audit field, NOT a ceremony input.** `decode_restore_request` denies unknown fields — the RESTORE_BACKUP request carries NO `attempt_challenge` field, so the ceremony cannot consume or echo it. 2D records it for its own freshness tracking; it is not part of the ceremony's replay contract (the replay token is `request_id` above). If 2D wants the challenge on the wire, it folds it into `attempt_started.id` (= `request_id`). |
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

The handler returns `AgentResponse::RestoreBackup { candidate: Box<KeystoreBody>, request_id }`. The 2D side does NOT receive the candidate body directly (it stays inside the enclave). The RESTORE_BACKUP success wire body (§10.4 of the vsock wire-format spec; TASK-24 + TASK-28) is `{1: sealed_keystore_blob, 2: request_id_echo, 3: restored_identity_set, 4: attestation_report, 5: cert_chain}`. The sealed keystore (key 1) is **XChaCha20Poly1305 AEAD-encrypted** (`agent_keystore.rs`) — the host CANNOT read plaintext `KeyEntry` fields from it. So the **enclave-side frame layer** extracts the identity evidence from the plaintext candidate (before/around the seal) and emits it on the wire. **CRITICAL (compact-9698 HIGH): keys 2 + 3 are PLAINTEXT — 2D MUST verify key 4 (the completion attestation) BEFORE trusting them**, or a compromised host can forge the evidence. The attestation is a fresh SNP report whose `report_data` binds (request_id_echo, restored_identity_set_sha256, chain, env) to the attested enclave:

| Return artifact | Where on the wire | What 2D records |
|---|---|---|
| **Completion attestation (MUST verify first)** | **Key 4** — the SNP `attestation_report` (AMD-signed); **key 5** — its VCEK→ASK→ARK `cert_chain`. 2D verifies: the cert chain against the AMD root, the report's `measurement` == the expected enclave build, AND the report's `report_data` == `report_data_for_restore_completion(request_id_echo, restored_identity_set_sha256, chain, env)` (compact-9675 option A). **Only after this verifies** may 2D trust keys 2 + 3. | `attempt_completed.attestation_verified = true` (+ the report/cert bytes for audit) |
| Restored identity set | Key 3 — array of `{1: key_ref(32B), 2: public_identity(65B), 3: key_purpose}`, emitted PLAINTEXT. Trusted ONLY if key 4 verifies. 2D maps to `agent_restore_identity_set_v1` (§4) + derives the Ethereum address. | `attempt_completed.restored_identity_set_sha256` |
| Challenge echo | Key 2 — `request_id_echo` == `attempt_started.id` (cap-bound). Trusted ONLY if key 4 verifies (the attestation binds it). | `attempt_completed.request_id_echo` |
| Ceremony success | No error code (0x00 ACK) | `attempt_completed.result = "success"` |

`secret_scalar` is NEVER emitted. **A 2D implementation that records completion WITHOUT verifying key 4 leaves the host-forge attack open** — the enclave-side defense is useless if the consumer doesn't enforce it. NB the attestation binds the IDENTITY SET (key 3), not the sealed blob directly — sealed-blob substitution by the host is caught separately by the anchor anti-rollback at next-boot reconcile (strict_recovery_counter / structural_version), not by the completion attestation; 2D records the attested identity set, the host's persisted blob is verified on the enclave's next load.

### Non-production fixture path

The fixture path uses the same handler (under `agent-backup-export-preview` feature flag) with a test-generated backup. The fixture's evidence bundle MUST carry `is_production: false` — the 2D gate rejects any bundle with this flag for production enablement. The fixture proves mechanical correctness only.

## 3. Challenge/nonce echo binding (AC#3)

### Where the echo lives

The ceremony's `request_id` (envelope-level) is the replay token. It flows:

1. **2D commits** `attempt_started` with a high-entropy `id` (this becomes `request_id`; see §2 — `attempt_challenge` is a separate 2D audit field, NOT a ceremony input).
2. **Operator** passes `attempt_started.id` as the ceremony's `request_id`.
3. **Ceremony** binds the `request_id` into the cap's `payload_binding` (`restore_canonical_params(requested_refs, backup_digest)` + `request_id`) AND the recovery-authority high-water signature. A cap+high-water issued for one `request_id` cannot authorize/verify under another.
4. **Ceremony** echoes `request_id` in the RESTORE_BACKUP success body (key 2 — emitted by the enclave-side frame layer; the ceremony receives no `attempt_challenge`, see §2).
5. **2D** verifies `ceremony_response.request_id_echo == attempt_started.id` (the ceremony consumed 2D's live attempt) AND records its own `attempt_completed.attempt_challenge` from its committed `attempt_started.attempt_challenge` (a 2D-side consistency record, not a ceremony echo).

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
      "public_identity": "hex-65 (uncompressed SEC1 0x04‖X‖Y — from the RESTORE_BACKUP response key 3)",
      "status": "assigned",
      "address": "0x... (derived: keccak256(public_identity[1..65])[12..32])"
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
| `address` | `KeyEntry.public_identity` | Derive the 20-byte Ethereum address from the 65-byte uncompressed SEC1 public key: `keccak256(pubkey[1..65])[12..32]` (standard Ethereum derivation — the LAST 20 bytes of the 32-byte hash, matching `secp256k1.rs:address_from_uncompressed_xy`) |

**`restored_identity_set_sha256` — the EXACT pinned byte layout (compact-9675, TASK-28 attestation binding).** This hash is bound into the RESTORE_BACKUP completion attestation (§3) AND recorded in the bundle, so 2D + the enclave MUST compute it byte-identically. **Algorithm: SHA-2-256 (NIST FIPS 180-4) — NOT SHA-3 / Keccak.** Input is a fixed length-prefixed binary stream (NOT JSON — JSON canonicalization is 2D-internal only, NOT the attested form):

```
count(u64 big-endian)
for each entry, sorted ascending by key_ref (the 32-byte opaque handle):
    key_ref(32 bytes, raw)
    public_identity_len(u64 big-endian)
    public_identity(public_identity_len bytes — the 65-byte uncompressed SEC1, 0x04‖X‖Y)
    key_purpose(u64 big-endian; 1=agent_transfer_k1, 2=agent_faucet_treasury_k1)
```

2D reimplements this exact layout (`agent_dispatch.rs::compute_restored_identity_set_hash` is the reference). A mismatch (SHA-3 instead of SHA-2, wrong endianness, wrong sort, JSON vs binary) makes the attestation ALWAYS fail to verify — the cross-repo fixture (AC#7) is the only thing that catches a divergence; the enclave's own tests are symmetric (same fn binds + verifies) and will NOT catch it.

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
      "request_id_echo": "hex (== attempt_started.id; from the ceremony's RESTORE_BACKUP response key 2)",
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
- Every batch entry has `identity_match == true`. A batch that FAILED the identity check must NOT appear in `batches[]` — instead it is documented in a separate `remediation_log[]` array with its `backup_batch_id` + `remediation_status`. The linked 2D rows for remediated batches MUST be disabled/retired before enforcement.
- Every batch in `batches[]` has `expected_identity_set_sha256 == restored_identity_set_sha256`
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
