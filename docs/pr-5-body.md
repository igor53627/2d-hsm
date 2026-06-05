## Summary

Closes **TASK-1 / TASK-4 Phase B** (vsock staging + NixOS guest KVM smokes) and **TASK-5 Phase 1–2** (prod enclave in guest + lab PQ seal).

### Delivered

- AF_VSOCK staging + NixOS guest (`nix build .#vm`) with `TWOD_HSM_VSOCK_*` (systemd-safe)
- Host↔guest smokes on aya: Nix KVM (staging, prod transport, prod-lab) + **SEV-SNP Ubuntu guest** (`run-snp-smoke.sh`)
- `TWOD_*` env canonical names; vsock spec §2.4; smoke cache (`TWOD_HSM_CACHE`, `warm-smoke-cache.sh`)
- **Transport hardening** (`7567206`…`a399826`): shared accept loop, idle read deadlines, poison→`exit(1)`, oversize close without wire frame, fail-closed `ARM_FOR_PRODUCTION` when `!pq_signing_ready`
- **Docs/backlog** (`3c4ecc3`, TASK-4/5): manifest ≠ on-chain TEE measurement; SNP launcher deferred to TASK-5 Phase 3

### Guest outputs (read before deploy)

| Output | Purpose | Mainnet-safe? |
|--------|---------|---------------|
| `vm` | staging enclave | no (dev) |
| `vm-production` | debug `enclave-production-transport` + **lab** attestation VK (`TRANSPORT_ONLY_MODE`) | **no** — transport smoke only |
| `vm-production-lab` | lab PQ seal + `pq_signing_ready` smoke | **no** |

Platform production trust + SNP measurement → TASK-5 Phase 3 (follow-up PR).

### Not in this PR

- vTPM/SNP provisioning root (non-file)
- Real TEE measurement in `GET_MEASUREMENT` / on-chain whitelist from manifest
- BP Elixir vsock E2E with live chain proof
- NixOS unified SNP launcher (`run-vm-hsm.sh` KVM-only today)

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
# Skip SNP golden bake (default is on when no golden disk exists; needs /opt/amde-ovmf/OVMF.fd):
# TWOD_HSM_BAKE_SNPDISK=0 ./warm-smoke-cache.sh
```

**SNP Ubuntu guest notes:** cargo `enclave-vsock-staging` (glibc), bind `VMADDR_CID_ANY` (`4294967295`) inside VM; host connects to QEMU `guest-cid=42`. Golden boot skips cloud-init seed.

## Review gate (AGENTS.md)

| Step | Jobs / status |
|------|----------------|
| Reduced matrix (PR core) | 6890–6892 + 2×3 6893–6898; compact **6900** |
| Branch design | **6983** claude/design Pass |
| Branch security | codex/gemini branch jobs degraded (UTF-8 binaries / gemini quota); retried on commits |
| Post-transport (`611de83`…`a399826`) | **7012** codex/security Pass, **7013** cursor+gemini-3.1-pro/security Pass, **7014** claude/design Pass; compact **7015** → fixed in `c630aa8`; compact **7025** Low closed in `a399826` |
| Roborev diff excludes | `.roborev.toml`: `**/*.sealed`, `**/*.bin` only (lockfiles in scope) |

High-risk paths: `impl/nix/**`, `impl/rust/enclave-protocol/**`, `backlog/docs/*vsock*`.

## Unit tests (local / CI)

```bash
cd impl/rust/enclave-protocol
cargo test                                    # default profile
cargo test --features test-support,demo-mock-sign
cargo test --features reference-test-key      # ML-DSA + wire-ARM shared-state test
```

Notable: `shared_enclave_state_wire_arm_rejects_second_hardfork_mldsa` — wire ARM on shared `EnclaveState`, then second hard-fork rejected across lock scopes.

## Test plan (aya, HEAD `a399826`)

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

**Verified 2026-06-05 on aya:** all five scripts passed twice in ~60–67s total with cache hits (baseline `d0ccd39`; re-run after merge if transport binaries changed).

Details: `impl/scripts/aya-sev-snp/SMOKE-PASS-CRITERIA.md`, `impl/scripts/aya-sev-snp/README.md`

## Tasks

- TASK-1: vsock staging transport ✅
- TASK-4: Phase B NixOS guest + KVM smoke ✅ (In Progress in backlog; SNP → TASK-5)
- TASK-5: Phase 1 ✅ Phase 2 ✅ Phase 3+ open (SNP launcher / platform seal → follow-up PR)