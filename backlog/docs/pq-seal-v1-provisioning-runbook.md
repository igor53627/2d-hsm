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
- Platform root mutex poisoned → enclave/runtime fault (`pq seal platform root mutex poisoned`); **restart enclave** and investigate (not a provisioning-root mismatch).
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

## 7. Production differences

| Staging | Production |
|---------|------------|
| `seal_v1_provisioning_root.bin` test vector | Root from **`snp-derive-root`** (SEV-SNP firmware); vTPM / Nitro are future backends |
| `reference-seal-v1-root` feature in CI enclave | **Forbidden** in deploy artifacts |
| Manual measurement file | Measurement from attestation / launch API |

### 7.1 SEV-SNP firmware-derived root (`snp-derive-root`, TASK-1.1)

On a SEV-SNP guest the production provisioning root is **derived from the platform firmware**, not
supplied by the host. The `snp-derive-root` boot helper (`impl/rust/snp-derive-root`, Nix package
`.#snp-derive-root`) issues `SNP_GET_DERIVED_KEY` on the guest-only `/dev/sev-guest` and returns

```
root = SHA3-256("2d-hsm-pq-seal-v1-root" ‖ snp_derived_key)
```

where `snp_derived_key` is the 32-byte key the PSP derives from a platform secret bound, by default,
to the **launch MEASUREMENT** (`guest_field_select` bit 3) under the **VCEK** root key. The root is
therefore secret to the platform (the host cannot compute it), stable for a given image (unseals
across reboots), and image-specific (changes when the measurement changes). It lives in a separate
crate because the ioctl needs `unsafe`, which `enclave-protocol` forbids; the enclave still consumes
the root only as a file via `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE`.

**Provisioning ceremony (run ONCE inside the target image):**

1. Boot the target enclave image under SEV-SNP. Inside the guest, obtain the root:
   ```
   snp-derive-root --print            # 64-hex-char root to stdout (MEASUREMENT-bound, VCEK)
   ```
   The same value is reproduced on every boot of that image on that platform.
2. Seal the producer key **offline** against that root + the same launch measurement using the
   `pq-seal-v1` CLI (§3.3 / §3.4, substituting the derived root for the test vector).
3. Bake the sealed blob into the deploy artifact. On boot the enclave reads the root from
   `TWOD_HSM_PQ_SEAL_V1_ROOT_FILE` (written by a `snp-derive-root --out <path>` oneshot) and unseals.

**Measurement binding ⇒ re-seal on image change:** because the root is bound to MEASUREMENT, any
change to the enclave image (firmware, kernel, binary) changes the root and invalidates an existing
sealed blob. Re-run the ceremony for the new measurement (see §6 rotation).

**In-guest validation:** `snp-derive-root --selftest` checks the derived-key path without revealing
the secret — it confirms the key is non-zero, that MEASUREMENT binding actually changes the key, and
prints a SHA3-256 **commitment** of the root (stable across reboots ⇒ derivation is stable). The
`disk-production-lab-selftest` image runs this as a boot oneshot and logs PASS + the commitment to
the console.

> **Not yet automated end-to-end:** a fully sealed-boot mainnet artifact (blob sealed against the
> derived root, baked in) still requires the operator ceremony above — tracked by the TASK-1.6
> runbook / a provisioning step. vTPM and Nitro backends are future work (SNP first).

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
| 2026-06-02 | §5 poisoned-mutex troubleshooting; paths relative to `pq-seal-v1` cwd |
| 2026-06-06 | §7 production root via `snp-derive-root` (SEV-SNP firmware); ceremony + selftest (TASK-1.1) |