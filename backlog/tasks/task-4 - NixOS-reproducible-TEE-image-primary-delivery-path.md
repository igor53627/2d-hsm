---
id: TASK-4
title: NixOS reproducible TEE image as primary 2d-hsm delivery path
status: Done
assignee: []
created_date: '2026-06-04'
updated_date: '2026-06-06 13:46'
labels:
  - nix
  - nixos
  - tee
  - sev-snp
  - reproducible-build
  - attestation
dependencies:
  - TASK-2
  - TASK-3
references:
  - impl/rust/enclave-protocol
  - impl/scripts/aya-sev-snp
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - backlog/docs/authorization-tickets-precompile-spec-draft.md
  - backlog/docs/pq-seal-v1-provisioning-runbook.md
  - ~/pse/yolo/mainnet-deploy/sev-vm
priority: high
ordinal: 1500
parent: TASK-1
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->

### Decision (2026-06-04)

**Nix is the primary delivery path for production 2d-hsm TEE artifacts.**

| Layer | Primary | Secondary (dev / transition) |
|-------|---------|------------------------------|
| Enclave binary build | `nix build .#enclave` (flake, lockfile) | `cargo build --release` for fast local edit |
| Guest CVM image | NixOS minimal (`nix build .#vm` → qcow2) | Ubuntu cloud image + `impl/scripts/aya-sev-snp` (KVM smoke only) |
| SNP launch | **TASK-5 Phase 3** — `run-snp-smoke.sh` / Ubuntu guest today | `run-vm-hsm.sh` = **KVM only** (`SEV_MODE=snp` exits 2 until unified launcher) |
| Host (BP orchestrator) | **Unchanged** — Ubuntu + Elixir shim | Nix on BP host is out of scope |
| On-chain binding | TEE `measurement` + `forkSpecHash(manifest)` | — |

Rationale: TASK-1 Phase 2 requires a reproducible TEE image; Authorization Tickets bind `newMeasurement` on-chain; SNP boot on aya failed with Ubuntu+OVMF (`0xfee00000` LAPIC) while yolo NixOS disk path avoids OVMF. Nix gives A (deterministic build) + B-lite (auditable guest OS) without migrating the whole 2d stack.

**Not adopting:** full-2d-on-NixOS (nix-bitcoin model), colmena/sops in v1, copying yolo Mullvad/Node deploy into the HSM image.

### Goal

Deliver `impl/nix/vm-hsm/` so operators and CI can:

1. Build enclave + NixOS guest from one flake with a pinned `flake.lock`.
2. Publish a **build manifest** (artifact SHA256 + git/flake inputs for `forkSpecHash` helpers) — **not** a substitute for live TEE `measurement` until TASK-5 #4.
3. Run the same vsock smokes on aya (KVM first, SNP when QEMU supports `memory-backend-memfd-private`).
4. Feed BP integration: use manifest for **reproducible build identity** (`forkSpecHash` inputs); **on-chain producer `measurement` whitelist** must use TEE attestation from `GET_MEASUREMENT` (TASK-5 #4), not `protocol_measurement_label` in the JSON manifest.

### Relationship to on-chain policy

Production measurement in tickets comes from **TEE attestation** (`GET_MEASUREMENT.measurement` + platform report), **not** from Nix manifest labels or artifact SHA256 alone.

| Signal | Source | Use on-chain / BP |
|--------|--------|-------------------|
| **TEE `measurement`** | SNP/Nitro report via enclave (TASK-5 #4) | Producer whitelist, recovery tickets, arm binding |
| **Manifest `artifacts.*.sha256`** | CI `measurement-manifest` derivation | Reproducibility, `forkSpecHash(manifest)` over build inputs |
| **`protocol_measurement_label`** | Placeholder / staging label in JSON today | **Not** authoritative until TASK-5 wires real measurement |

The flake manifest closes the **operational build-attestation** side of authorization-tickets spec §11; it does **not** replace live TEE measurement for BP whitelist until TASK-5 Phase 3–4.

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->

- [x] #1 `impl/nix/vm-hsm/flake.nix` exists with outputs: `packages.enclave`, `packages.vm` (qcow2 or vm runner), `devShell`.
- [x] #2 `flake.lock` committed; CI workflow runs `nix build .#enclave` and `.#vm` on `x86_64-linux`.
- [x] #3 Documented **measurement manifest** format (JSON): `git_revision`, `flake_lock`, artifact SHA256, `fork_spec_hash_input` — see `scripts/write-measurement-manifest.sh`.
- [x] #4 Reproducibility: the measurement manifest (schema v2) publishes the production artifact SHA256 and the build is Nix-deterministic from the locked `flake.lock`. **Verified on aya (2026-06-06)**: `nix build .#enclave` then `nix build .#enclave --rebuild` rebuilt the derivation and the output was **byte-identical** (`checking outputs … REBUILD_OK`, no hash mismatch) — i.e. two builds → identical artifact. Production `enclave-vsock` sha256 = `772d63a132858015b7a515d1b6cdf97868d8236fa8939982614f7cb3e8805556`. TEE measurement is **real** (TASK-5 #4) and deterministic; note it pins **OVMF + launch-config, not the guest image** (identical across different guests — TASK-5 verifier-policy §3), so it is not an image fingerprint — image identity uses this artifact sha256 + `report_data`.
- [x] #5 NixOS guest module: systemd unit for HSM binary, `TWOD_HSM_VSOCK_*` bind (not `2D_HSM_*`), minimal firewall; **no** SSH, no extraneous services; `boot.loader.grub.enable = false`.
- [x] #6 `run-vm-hsm.sh` launches NixOS qcow2 on **KVM** (`SEV_MODE=none`); **SNP** explicitly deferred to TASK-5 #5 (script exits 2 for `SEV_MODE=snp`).
- [x] #7 Smoke on aya: Nix guest vsock smokes pass on **KVM** (staging + prod transport + prod-lab PQ); SNP pass/fail tracked under TASK-5.
- [x] #8 `impl/README.md` + `impl/nix/vm-hsm/README.md`: NixOS path primary; Ubuntu dev fallback; lab VM outputs marked non-mainnet.
- [x] #9 Branch roborev: Full matrix on PR branch (design Pass job 6983; security degraded — codex UTF-8 prompt, gemini quota); compact 6991; targeted commits re-verified.
- [x] #10 TASK-1 Phase 2 reproducible build path → satisfied via this flake + committed `Cargo.lock` (operational closure in TASK-5 for prod guest + measurement).

<!-- AC:END -->

## Implementation plan

<!-- SECTION:PLAN:BEGIN -->

### Phase A — Flake build (A only) — ~1 week

- `impl/nix/vm-hsm/flake.nix`, `enclave.nix` (build `enclave-protocol` with `release_build`, no staging features in prod output).
- `measurement.nix` + shell script: run staging binary or post-build attestation stub → emit manifest.
- GitHub Actions `nix-hsm.yml`.

### Phase B — NixOS guest (B-lite) — ~1 week

- `nixos-module.nix`: copy patterns from `~/pse/yolo/mainnet-deploy/sev-vm` (virtio, no GRUB, tmpfs for optional secrets) **without** Mullvad/Node/yolo-deploy unit.
- Package `enclave-vsock-staging` in default `.#vm`; **prod** `enclave-vsock` in guest → **TASK-5** (`.#vm-production`).
- `nix build .#vm` → qcow2 artifact.

### Phase C — aya integration — ~1 week

- `run-vm-hsm.sh`: KVM qcow2 launcher (done). SNP launcher unification → **TASK-5 Phase 3** (do not mark TASK-4 AC #6 SNP-complete until then).
- Extend README in `impl/scripts/aya-sev-snp/`.

### Phase D — BP / chain hook (documentation + shim policy) — ~3 days

- Document: CI manifest `fork_spec_hash_input` ↔ `forkSpecHash`; BP shim must reject `GET_MEASUREMENT.measurement` not matching on-chain producer after activation — **whitelist uses TEE measurement, not manifest placeholder label**.
- No main `2d` repo changes required in TASK-4 unless BP team requests; deliver contract doc under `backlog/docs/`.

### Phase E — Review gate

- Reduced matrix: security (codex, gemini) + design (claude-code) on `impl/nix/**`.
- `roborev compact --wait`; grep-verify HIGHs.

<!-- SECTION:PLAN:END -->

## Out of scope

- NixOS on Block Producer host or reader nodes.
- Bridge-specific second VM (follow-on: `vm-hsm-bridge` output or separate task).
- On-chain `MeasurementRegistry` whitelist precompile (design only; implement in 2d-solidity separately).
- Nitro EIF packaging (separate track if Nitro chosen; Espresso `nix-enclaver` as reference).
- Replacing `cargo test` / local Rust dev workflow.

## Related

- **TASK-1** (parent) — Phase 2 "Skeleton + CI + reproducible build for the TEE image"
- **TASK-2** (Done) — vsock API consumed inside NixOS guest
- **TASK-3** (Done) — measurement in attestation preimage; manifest must not break binding
- **TASK-5** — prod `enclave-vsock` in guest, platform PQ seal, SNP, real measurement (follow-on after Phase B smokes)
- `feat/task-1-vsock-staging-transport` branch work — merge or rebase before Phase C

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->

### Success / rollback criteria

| Signal | Action |
|--------|--------|
| AC #4 + #7 KVM green for 2 weeks | Mark TASK-4 Done; TASK-1 prod image path = Nix only |
| SNP blocked >4 weeks on infra | Ship prod with KVM attestation policy on lab; SNP sub-milestone stays open |
| Artifact SHA256 non-reproducible across CI | Fix flake inputs / `SOURCE_DATE_EPOCH` before relying on manifest |
| TEE measurement not wired (TASK-5 open) | Do not use manifest `protocol_measurement_label` for on-chain whitelist |

### References to copy

- **Launch:** `yolo/mainnet-deploy/sev-vm/run-deploy.sh` (QEMU SNP, no OVMF)
- **Guest shape:** `yolo/mainnet-deploy/sev-vm/flake.nix` (strip to HSM-only)
- **CI/hash:** Contrast-style flake + Cardano-style locked builds (process, not their K8s stack)

<!-- SECTION:NOTES:END -->
