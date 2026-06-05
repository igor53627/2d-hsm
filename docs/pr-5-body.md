## Summary

Closes **TASK-1 / TASK-4 Phase B** (vsock staging + NixOS guest KVM smokes) and **TASK-5 Phase 1–2** (prod enclave in guest + lab PQ seal).

### Delivered

- AF_VSOCK staging + NixOS guest (`nix build .#vm`) with `TWOD_HSM_VSOCK_*` (systemd-safe)
- Host↔guest smokes on aya: Nix KVM (staging, prod transport, prod-lab) + **SEV-SNP Ubuntu guest** (`run-snp-smoke.sh`)
- `TWOD_*` env canonical names; vsock spec §2.4; review fixes through `d6a0cd2`
- **Smoke cache** (`TWOD_HSM_CACHE`, `warm-smoke-cache.sh`): nix out-links, qcow2, SNP golden disk — routine smokes ~60s on aya

### Guest outputs (read before deploy)

| Output | Purpose | Mainnet-safe? |
|--------|---------|---------------|
| `vm` | staging enclave | no (dev) |
| `vm-production` | release `enclave-vsock` + **lab** attestation VK | **no** — transport smoke only |
| `vm-production-lab` | lab PQ seal + `pq_signing_ready` smoke | **no** |

Platform production trust + SNP measurement → TASK-5 Phase 3 (follow-up PR).

### Not in this PR

- vTPM/SNP provisioning root (non-file)
- Real TEE measurement in `GET_MEASUREMENT` / manifest binding
- BP Elixir vsock E2E with live chain proof

## Smoke cache (aya operators)

Heavy assets live on the host at **`TWOD_HSM_CACHE`** (default `/var/cache/2d-hsm`), not in git:

| Path | Content |
|------|---------|
| `nix/` | Out-links: `enclave-staging`, `vm-hsm-runner-*` |
| `images/` | Nix `qcow2`, Ubuntu cloud img, `vm-disk-snp-ready.qcow2` (golden) |
| `firmware/` | Symlink to AMD `OVMF.fd` when installed |

**One-time warm-up** (after `flake.lock` change or fresh host):

```bash
cd impl/scripts/aya-sev-snp
./warm-smoke-cache.sh
# Optional SNP golden bake (needs /opt/amde-ovmf/OVMF.fd):
# TWOD_HSM_BAKE_SNPDISK=1 ./warm-smoke-cache.sh
```

**SNP Ubuntu guest notes:** cargo `enclave-vsock-staging` (glibc), bind `VMADDR_CID_ANY` (`4294967295`) inside VM; host connects to QEMU `guest-cid=42`. Golden boot skips cloud-init seed.

## Review gate (AGENTS.md)

| Step | Jobs / status |
|------|----------------|
| Reduced matrix | 6890 codex/security, 6891 gemini/security, 6892 claude/design |
| Full 2×3 floor | 6893–6898 (`pse-review-2x3.sh --dirty`) |
| Compact | **6900** — lab trust naming, phase table, smoke criteria |
| Post-`d6a0cd2` | Smoke-cache + SNP fixes (`679805a`…`d0ccd39`): infra/scripts; **aya 5/5 green** on `d0ccd39` (2026-06-05, two runs) |

High-risk paths: `impl/nix/**`, `impl/rust/enclave-protocol/**` (vsock, prod boot, lab seal).

Incremental matrix on latest dirty optional before merge; core protocol/matrix covered at `d6a0cd2` + operator verification below.

## Test plan (aya, HEAD `d0ccd39`)

```bash
cd /root/2d-hsm && git fetch && git checkout feat/task-1-vsock-staging-transport && git pull
cd impl/scripts/aya-sev-snp
./warm-smoke-cache.sh   # skip if /var/cache/2d-hsm already warm
./run-nix-enclave-staging.sh           # loopback ~2013 B, prod-enclave-v1
./run-nix-vm-guest-smoke.sh            # staging guest ~2013 B
./run-nix-vm-guest-smoke-prod.sh       # ~80 B, enclave-measurement-placeholder
./run-nix-vm-guest-smoke-prod-lab.sh   # ~2030 B, pq_signing_ready
./run-snp-smoke.sh                     # SNP ~2013 B, pq_signing_ready=true
```

**Verified 2026-06-05 on aya:** all five scripts passed twice in ~60–67s total with cache hits.

Details: `impl/scripts/aya-sev-snp/SMOKE-PASS-CRITERIA.md`, `impl/scripts/aya-sev-snp/README.md`

## Tasks

- TASK-1: vsock staging transport ✅
- TASK-4: Phase B NixOS guest + KVM smoke ✅
- TASK-5: Phase 1 ✅ Phase 2 ✅ Phase 3+ open (SNP launcher / platform seal → follow-up PR)