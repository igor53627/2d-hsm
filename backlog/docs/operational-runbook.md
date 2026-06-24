# 2d-hsm Operational Runbook

Covers deployment, key provisioning, attestation verification, monitoring, incident response, and failover design for the 2d-hsm TEE signing service.

**Related:**
- Provisioning: `backlog/docs/pq-seal-v1-provisioning-runbook.md`
- Protocol: `backlog/docs/vsock-api-wire-format-spec-draft.md`
- Security review: `backlog/docs/security-review-enclave-protocol-crate.md`
- Nix builds: `impl/nix/vm-hsm/flake.nix`

---

## 1. Deployment

### 1.1 Build the enclave image

```bash
cd impl/nix/vm-hsm
# Producer (Block Producer key):
nix build .#disk-production-lab          # lab: debug, reference seal root
nix build .#disk-production-lab-snp-rooted # SNP-derived root, sealed signer

# Agent Gateway:
nix build .#enclave-agent-gateway-release  # release binary (compile-only until driver wired)
```

The output is a bootable EFI qcow2 for SEV-SNP launch. The measurement manifest is produced by:
```bash
nix build .#measurement-manifest --out-link result
jq . result/manifest.json
```

### 1.2 Launch under SEV-SNP

```bash
# On the SNP host (e.g., aya — AMD Turin):
impl/scripts/aya-sev-snp/run-nix-snp-guest-smoke.sh    # basic boot check
impl/scripts/aya-sev-snp/run-nix-snp-sealed-boot.sh     # sealed-boot ceremony
impl/scripts/aya-sev-snp/run-nix-snp-agent-smoke.sh     # agent-gateway smoke
```

The enclave boots, performs the anti-rollback handshake against the host anchor relay, installs the sealed keystore, and begins serving on its vsock port.

### 1.3 Host-side relay

The host runs `host_anchor_relay` (built from `impl/rust/enclave-protocol/src/bin/host_anchor_relay.rs`):
```bash
nix build .#enclave-production-transport  # transport-only (no signer)
# Or from source:
cargo build --bin twod-hsm-host-anchor-relay --features agent-gateway,vsock-transport
```

The relay mediates enclave ↔ anchor communication and forwards 0x40 frames between the 2D chain and the enclave.

---

## 2. Key provisioning and rotation

### 2.1 PQ Block Producer key

See `pq-seal-v1-provisioning-runbook.md` for the full ceremony:

1. **Ceremony (trusted host):** Boot `disk-production-lab-print-ceremony` → capture the firmware-derived root → seal the ML-DSA-65 keypair against it → produce `ceremony-sealed-signer.bin`
2. **Deploy:** Boot `disk-production-lab-snp-rooted` with the ceremony blob → enclave unseals against the boot-derived root → serves with the real PQ key
3. **Measurement:** Record the launched enclave's measurement from the SNP report; pin it in the on-chain `MeasurementRegistry`

### 2.2 Agent Gateway keys

Agent keys (secp256k1) are minted INSIDE the enclave via `GENERATE_KEYS` (behind `agent-keygen-exec-preview`). The provisioning channel (`ProvisionSession`, TASK-25) is the attested install path for the initial keystore.

Key rotation = reprovision (new keystore via the attested channel) or GENERATE_KEYS (mints new keys, advances counters).

### 2.3 Backup and restore

- `EXPORT_BACKUP(7)` produces a `pq-agent-backup-v1` KEM-DEM blob sealed to the operator's offline recovery key
- `RESTORE_BACKUP(8)` re-encrypts to the destination TEE's attested ephemeral key
- Restore = new enclave identity (scope_id is excluded from the payload; old caps fail post-restore)

---

## 3. Attestation verification

### 3.1 What the enclave proves

The enclave's SNP attestation report binds:
- **Launch measurement** (the enclave binary's hash — AMD-signed, forge-proof)
- **REPORT_DATA** (guest-chosen 64 bytes — domain-separated per use case)
- **VCEK chain** (AMD-signed cert chain: VCEK → ASK → ARK)

### 3.2 Who verifies what

| Verifier | Checks |
|----------|--------|
| **Operator (provisioning)** | VCEK chain + measurement allowlist + REPORT_DATA nonce freshness |
| **2D chain (bridge signer)** | Measurement against `MeasurementRegistry` on-chain allowlist |
| **2D reader nodes** | Block signatures verify against the registered PQ pubkey |

### 3.3 Measurement pinning

The enclave measurement MUST be recorded on-chain before the key is trusted:
1. Boot the enclave on the production SNP host
2. Extract the measurement from the SNP report (GET_MEASUREMENT or boot attestation)
3. Call `MeasurementRegistry.register(measurement, pqPubkey)` on-chain (TASK-1.4)
4. Reader nodes now accept blocks signed by this key

---

## 4. Monitoring

### 4.1 What to monitor

| Signal | Source | Alert |
|--------|--------|-------|
| Enclave boot failure | journald (`[err] agent-gateway boot failed`) | Page — enclave cannot serve |
| Anti-rollback handshake failure | journald (`[warn]` AgentBootEvent) | Page — state rollback detected |
| Anchor relay unreachable | vsock connect timeout | Page — signing halted |
| Sealed keystore unseal failure | journald (`[err]` PqSigningUnavailable) | Page — key not available |
| Vsock serve loop blocked | No response to health check | Page — DoS or wedge |

### 4.2 Health check

The 2D bridge signer should periodically send `GET_STATUS` (opcode 0x30) over vsock. A healthy enclave responds within ~1ms. Timeout = 5s → alert.

### 4.3 Audit trail

The enclave maintains an in-enclave audit ring (sealed with the keystore):
- Every privileged op (GENERATE_KEYS, CONFIGURE_TREASURY, EXPORT/RESTORE) appends an `AuditRecord`
- `EXPORT_BACKUP` drains the ring into the backup blob
- The audit ring is the forensic record for incident response

---

## 5. Incident response

### 5.1 TEE compromise suspected

**Symptoms:** attestation measurement mismatch, unexpected key activity, anomaly in block production.

**Response:**
1. **Stop the enclave** — kill the guest VM; the PQ key cannot be extracted from TEE memory by the host
2. **Verify attestation** — re-launch + compare measurement against the on-chain registry
3. **If measurement matches** — the TEE is intact; investigate the host/relay side
4. **If measurement differs** — the enclave binary was substituted; revoke the key on-chain via `RecoveryTicket`
5. **Rotate the key** — provision a new PQ keypair, update `MeasurementRegistry`, notify 2D

### 5.2 TEE unavailability (host failure)

**Symptoms:** vsock connection refused, serve loop not responding.

**Response:**
1. **Failover to standby** (see §6)
2. **If no standby** — invoke recovery: `RecoveryTicket` activation on-chain allows a backup keyholder to resume block production
3. **Restore from backup** — `RESTORE_BACKUP(8)` on a new TEE instance with the sealed backup blob

### 5.3 Key compromise (offline recovery key stolen)

**Symptoms:** unauthorized `RESTORE_BACKUP` detected, or recovery key material found exfiltrated.

**Response:**
1. **Re-provision** — generate a new PQ keypair, seal against a new provisioning root
2. **Revoke old key** — `RecoveryTicket` on-chain
3. **Update MeasurementRegistry** — new measurement + new pubkey
4. **Audit** — check the audit ring for unauthorized ops before the re-provision

---

## 6. Failover design

### 6.1 Architecture

```
                    ┌─────────────┐
                    │  2D Chain   │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │ Host Relay  │
                    └──┬───────┬──┘
                       │       │
              ┌────────┘       └────────┐
              ▼                         ▼
    ┌─────────────────┐       ┌─────────────────┐
    │ Primary Enclave  │       │ Standby Enclave  │
    │ (Host A, SNP)   │       │ (Host B, SNP)   │
    │ PQ Key: K1      │       │ PQ Key: K2      │
    └─────────────────┘       └─────────────────┘
```

### 6.2 Active-passive (recommended MVP)

- **Primary:** serves all signing requests with key K1 (registered on-chain)
- **Standby:** booted + provisioned with key K2, NOT registered on-chain
- **Failover:** primary down → operator submits `RecoveryTicket` activating K2 → `MeasurementRegistry.register(K2_measurement, K2)` → standby begins serving
- **Split-brain prevention:** only ONE key is registered on-chain at a time; the `RecoveryTicket` is the atomic on-chain switch

### 6.3 Active-active (future, requires TASK-20 Option B)

- Both enclaves serve with the SAME key
- Requires a global append-only ledger (shared spend/counter authority) to prevent double-spend
- Not in scope for the MVP (documented non-goal in the anti-rollback design)

### 6.4 Failover demo (requires aya hardware)

1. Boot primary enclave (Host A) + standby (Host B)
2. Verify primary serves GET_STATUS → ok
3. Kill primary enclave
4. Submit RecoveryTicket on-chain (or simulate)
5. Verify standby serves GET_STATUS → ok
6. Verify standby signs with K2 (different from K1)

---

## 7. Trust boundaries

| Component | Trusted? | Rationale |
|-----------|----------|-----------|
| Enclave (TEE) | **Yes** | Hardware-isolated; key never leaves in plaintext |
| Host VM (parent) | **No** | Controls vsock, disk, scheduling; can wedge but not forge |
| Host relay | **No** | Forwards frames; Ed25519-verified against sealed anchor_root |
| Anchor (external) | **Semi** | Signs monotonic counter updates; compromise = DoS, not key theft |
| 2D chain | **Yes** | On-chain `MeasurementRegistry` is the ground truth for authorized keys |
| Operator (ceremony) | **High** | Handles offline recovery key; compromise = unauthorized restore |

---

## 8. References

- Vsock wire format: `backlog/docs/vsock-api-wire-format-spec-draft.md`
- Recovery tickets: `backlog/docs/permissionless-blockproducer-recovery-tickets.md`
- Anti-rollback: `backlog/docs/agent-gateway-anti-rollback.md`
- Security review: `backlog/docs/security-review-enclave-protocol-crate.md`
- Provisioning: `backlog/docs/pq-seal-v1-provisioning-runbook.md`
