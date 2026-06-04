## Summary

Closes **TASK-1 / TASK-4 Phase B** (vsock staging + NixOS guest KVM smokes) and **TASK-5 Phase 1–2** (prod enclave in guest + lab PQ seal).

### Delivered

- AF_VSOCK staging + NixOS guest (`nix build .#vm`) with `TWOD_HSM_VSOCK_*` (systemd-safe)
- Host↔guest smokes on aya (KVM): staging, prod transport, prod-lab (`pq_signing_ready`)
- `TWOD_*` env canonical names; vsock spec §2.4; review fixes (`1e15893`, `d6ae1b9`, `73f9c98`)

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

## Review gate (AGENTS.md)

| Step | Jobs |
|------|------|
| Reduced matrix | 6890 codex/security, 6891 gemini/security, 6892 claude/design |
| Full 2×3 floor | 6893–6898 (`pse-review-2x3.sh --dirty`) |
| Compact | **6900** — resolved via docs (lab trust naming, phase table, smoke criteria) |

High-risk paths: `impl/nix/**`, `impl/rust/enclave-protocol/**` (vsock, prod boot, lab seal).

## Test plan (aya, `73f9c98`)

```bash
cd impl/scripts/aya-sev-snp
./run-nix-enclave-staging.sh      # loopback, ~2013 B, prod-enclave-v1
./run-nix-vm-guest-smoke.sh       # staging guest, prod-enclave-v1
./run-nix-vm-guest-smoke-prod.sh  # ~80 B, enclave-measurement-placeholder
./run-nix-vm-guest-smoke-prod-lab.sh  # ~2030 B, pq_signing_ready
```

Details: `impl/scripts/aya-sev-snp/SMOKE-PASS-CRITERIA.md`

## Tasks

- TASK-1: vsock staging transport
- TASK-4: Phase B NixOS guest + KVM smoke
- TASK-5: Phase 1 ✅ Phase 2 ✅ Phase 3+ open