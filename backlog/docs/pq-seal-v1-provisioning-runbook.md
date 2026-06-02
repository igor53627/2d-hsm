# PQ seal v1 — staging provisioning runbook

Operator procedures for provisioning the **ML-DSA-65 Block Producer key** into a 2d-hsm enclave using **seal v1**. This document covers **staging / CI** with the reference toolchain. Production adds platform-specific root derivation (vTPM / SNP VMPL / Nitro) — see §7.

**Related:**

- CLI reference: `impl/rust/pq-seal-v1/README.md`
- Protocol: `backlog/docs/vsock-api-wire-format-spec-draft.md` §2.1
- Implementation: `impl/README.md`, `impl/rust/enclave-protocol/src/pq_signer.rs`

---

## 1. Roles and trust boundaries

| Actor | Trust | Responsibilities |
|-------|--------|------------------|
| **Provisioning operator** | High | Generate or import PQ key; run `pq-seal-v1`; store sealed blob securely |
| **Enclave image builder** | High | Build `ml-dsa-65` enclave **without** `reference-seal-v1-root` in production |
| **Platform integration** | High | Call `set_pq_seal_v1_provisioning_root` at boot from hardware-backed secret |
| **Untrusted host (parent VM)** | Low | Deliver sealed blob file to enclave launcher; **must not** learn SK or provisioning root |

**Invariant:** Provisioning root and secret key bytes never traverse vsock. Only the **sealed blob** (ciphertext) and **attested measurement** are host-visible.

---

## 2. Prerequisites

- [ ] Target enclave **measurement** bytes fixed for this image build (PCR / policy hash / manifest digest — same definition the enclave uses at `install_sealed_pq_signer`).
- [ ] **Provisioning root** agreed for this environment (staging: 32-byte file; production: platform-derived).
- [ ] `pq-seal-v1` built: `cd impl/rust/pq-seal-v1 && cargo build --release`
- [ ] For §3 commands below, run from `impl/rust/pq-seal-v1` (binary: `./target/release/pq-seal-v1`)
- [ ] Enclave binary built with `ml-dsa-65`; production builds **without** `reference-seal-v1-root`
- [ ] `ProducerAttestationTrust` configured inside enclave (separate from PQ seal — §9.3 in vsock spec)

---

## 3. Staging ceremony (happy path)

### 3.1 Obtain measurement

Record the raw measurement file the enclave will use at boot, e.g. `./enclave.measurement` (opaque bytes, non-empty).

Optional check:

```bash
./target/release/pq-seal-v1 meas-digest --measurement-file ./enclave.measurement
# save digest hex for attestation log correlation
```

### 3.2 Key material

**Option A — generate new producer key (staging only):**

```bash
./target/release/pq-seal-v1 generate-keypair \
  --secret-key-out /secure/producer.sk.bin \
  --public-key-out /secure/producer.pk.bin
```

**Option B — use ceremony key** from your PKI / HSM export (4032 B SK, 1952 B PK).

Verify file sizes before sealing.

### 3.3 Seal blob (staging root)

```bash
./target/release/pq-seal-v1 seal \
  --measurement-file ./enclave.measurement \
  --secret-key-file /secure/producer.sk.bin \
  --public-key-file /secure/producer.pk.bin \
  --provisioning-root-file ../enclave-protocol/testvectors/seal_v1_provisioning_root.bin \
  -o /secure/producer-key.sealed
```

Expected: **6053** byte output; stderr includes `meas_digest=...`.

### 3.4 Verify before handoff

```bash
./target/release/pq-seal-v1 verify \
  --sealed-blob-file /secure/producer-key.sealed \
  --measurement-file ./enclave.measurement \
  --provisioning-root-file ../enclave-protocol/testvectors/seal_v1_provisioning_root.bin
```

Expected: exit code **0**; stderr `ok: sealed blob verifies for measurement` (proves AEAD decrypt under root + measurement only — not on-chain authorization; see §8).

### 3.5 Handoff to host

- Copy **only** `producer-key.sealed` to host-accessible storage (encrypted volume).
- **Do not** copy `producer.sk.bin` to the untrusted host.
- Wipe or lock SK files on the provisioning workstation per local policy.

---

## 4. Enclave boot (integration checklist)

Platform / enclave entry code (not vsock):

1. **Derive or load** 32-byte provisioning root → `set_pq_seal_v1_provisioning_root(root)` (once; second call errors).
2. Read sealed blob from enclave-local path → `install_sealed_pq_signer(blob, measurement)` (once per process).
3. Load `ProducerAttestationTrust` from sealed config / manifest (never from host ARM payload).

Staging shortcut: enclave built with `reference-seal-v1-root` skips step 1 if the embedded test root matches the CLI — **CI only**, not production.

---

## 5. Post-boot verification

After vsock is up:

| Check | Expected |
|-------|----------|
| `GET_MEASUREMENT.pq_signing_ready` | `true` |
| `GET_MEASUREMENT.pq_pubkey` | 1952 bytes; matches `producer.pk.bin` |
| `GET_MEASUREMENT.measurement` | Consistent with `./enclave.measurement` |
| `SIGN_AUTHORIZATION_TICKET` (recovery, armed) | Signature length **3309** bytes |
| Second `install_sealed_pq_signer` without restart | Error (no silent overwrite) |

If `pq_signing_ready` is false:

- Provisioning root not set (production build).
- Measurement mismatch vs blob `meas_digest`.
- AEAD decrypt fails but `meas_digest` matches → **provisioning root mismatch** (runtime `set_pq_seal_v1_provisioning_root` ≠ root used by `pq-seal-v1 seal`). Runtime platform root **overrides** embedded `reference-seal-v1-root`.
- Wrong blob magic / corrupt file.
- Feature `ml-dsa-65` disabled in enclave build.

---

## 6. Rotation and re-provisioning

| Event | Action |
|-------|--------|
| **New enclave image** (measurement changes) | New `seal` with same or rotated PQ key; new blob |
| **PQ key rotation** | Generate new keypair; new seal; update on-chain producer pubkey via governance |
| **Provisioning root rotation** | Re-seal all blobs; deploy enclave code that sets new root at boot |
| **Compromised host** | Assume blob at rest on host may be exfiltrated — ciphertext only safe if root stays in TEE; rotate key if root or SK exposure suspected |

Enclave restart clears in-memory signer; persistent armed state is future work (vsock spec §9.3).

---

## 7. Production differences (not automated yet)

| Staging | Production |
|---------|------------|
| `seal_v1_provisioning_root.bin` test vector | Root from vTPM / SNP VMPL / Nitro integration |
| `reference-seal-v1-root` feature in CI enclave | **Forbidden** in deploy artifacts |
| Manual measurement file | Measurement from attestation / launch API |

Full operator runbook (hot standby, attestation verification, monitoring, incident response) remains **TASK-1** acceptance criterion #5 — this document is the **PQ seal v1 slice** only.

---

## 8. Security reminders

- Provisioning root must be a **file** (`--provisioning-root-file`); never pass the root on the command line (argv / shell history).
- `generate-keypair` refuses to overwrite existing output paths (`create_new`); delete manually if re-running.
- SK may remain in process memory/swap after CLI exit; prefer air-gapped hosts or locked memory where policy requires it.
- Seal requires a working OS CSPRNG (`getrandom`); failure aborts with `CSPRNG unavailable`.
- Do not commit `producer.sk.bin`, custom provisioning roots, or sealed blobs to git.
- `pq-seal-v1 verify` does not prove the public key is authorized on-chain — only that AEAD decrypts under root + measurement.
- Host-supplied measurement at install must come from **enclave attestation**, not host-chosen arbitrary bytes in production.

---

## Revision log

| Date | Change |
|------|--------|
| 2026-06-02 | Initial staging runbook (platform root + `pq-seal-v1` CLI) |