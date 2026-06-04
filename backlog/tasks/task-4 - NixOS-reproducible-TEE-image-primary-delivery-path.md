---
id: TASK-4
title: NixOS reproducible TEE image as primary 2d-hsm delivery path
status: Planned
assignee: []
created_date: '2026-06-04'
updated_date: '2026-06-04'
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
| SNP launch | `run-vm-hsm.sh` (yolo-style: no OVMF, `memfd-private`) | Existing `run-guest-vm.sh` until SNP green |
| Host (BP orchestrator) | **Unchanged** — Ubuntu + Elixir shim | Nix on BP host is out of scope |
| On-chain binding | TEE `measurement` + `forkSpecHash(manifest)` | — |

Rationale: TASK-1 Phase 2 requires a reproducible TEE image; Authorization Tickets bind `newMeasurement` on-chain; SNP boot on aya failed with Ubuntu+OVMF (`0xfee00000` LAPIC) while yolo NixOS disk path avoids OVMF. Nix gives A (deterministic build) + B-lite (auditable guest OS) without migrating the whole 2d stack.

**Not adopting:** full-2d-on-NixOS (nix-bitcoin model), colmena/sops in v1, copying yolo Mullvad/Node deploy into the HSM image.

### Goal

Deliver `impl/nix/vm-hsm/` so operators and CI can:

1. Build enclave + NixOS guest from one flake with a pinned `flake.lock`.
2. Publish a **measurement manifest** (expected TEE measurement ↔ flake/git inputs).
3. Run the same vsock smokes on aya (KVM first, SNP when QEMU supports `memory-backend-memfd-private`).
4. Feed BP integration: whitelist active on-chain `measurement` against manifest from CI.

### Relationship to on-chain policy

Production measurement in tickets comes from **TEE attestation**, not from storing Nix fields in chain state. The flake manifest is committed off-chain and via `forkSpecHash` on hard-fork tickets (see authorization-tickets spec §11 open question #4 — this task closes the operational side).

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->

- [ ] #1 `impl/nix/vm-hsm/flake.nix` exists with outputs: `packages.enclave`, `packages.vm` (qcow2 or vm runner), `devShell`.
- [ ] #2 `flake.lock` committed; CI workflow runs `nix build .#enclave` and `.#vm` on `x86_64-linux`.
- [ ] #3 Documented **measurement manifest** format (JSON/CBOR): `git_revision`, `flake_lock`, `enclave_derivation`, `vm_derivation`, `protocol_version` → script computes hash for `forkSpecHash` helper.
- [ ] #4 Reproducibility: two CI builds from same lock → identical enclave measurement (or documented allowed variance); manifest published as CI artifact.
- [ ] #5 NixOS guest module: systemd unit for HSM binary, vsock bind, minimal firewall; **no** SSH, no extraneous services; `boot.loader.grub.enable = false`.
- [ ] #6 `impl/scripts/aya-sev-snp/run-vm-hsm.sh` (or equivalent) launches NixOS qcow2; documents `SEV_MODE=none` vs SNP and QEMU requirements.
- [ ] #7 Smoke on aya: `host-guest-vsock-smoke` passes with Nix-built guest (KVM minimum; SNP recorded pass/fail in task notes).
- [ ] #8 `impl/README.md` states NixOS path is **primary for production TEE**; Ubuntu path labeled dev/KVM fallback.
- [ ] #9 Reduced roborev matrix on new `impl/nix/**` (high-risk packaging + measurement binding); findings resolved before "Done".
- [ ] #10 TASK-1 notes: Phase 2 reproducible build AC explicitly satisfied via TASK-4 (link only; no duplicate implementation).

<!-- AC:END -->

## Implementation plan

<!-- SECTION:PLAN:BEGIN -->

### Phase A — Flake build (A only) — ~1 week

- `impl/nix/vm-hsm/flake.nix`, `enclave.nix` (build `enclave-protocol` with `release_build`, no staging features in prod output).
- `measurement.nix` + shell script: run staging binary or post-build attestation stub → emit manifest.
- GitHub Actions `nix-hsm.yml`.

### Phase B — NixOS guest (B-lite) — ~1 week

- `nixos-module.nix`: copy patterns from `~/pse/yolo/mainnet-deploy/sev-vm` (virtio, no GRUB, tmpfs for optional secrets) **without** Mullvad/Node/yolo-deploy unit.
- Package `enclave-vsock-staging` or prod binary per feature flags policy.
- `nix build .#vm` → qcow2 artifact.

### Phase C — aya integration — ~1 week

- `run-vm-hsm.sh`: QEMU line from yolo `run-deploy.sh` (`memfd-private`, `sev-snp-guest`).
- Extend README in `impl/scripts/aya-sev-snp/`.
- KVM smoke → attempt SNP; if blocked, document QEMU build dep (same as yolo).

### Phase D — BP / chain hook (documentation + shim policy) — ~3 days

- Document: CI manifest hash ↔ `forkSpecHash`; BP shim must reject `GET_MEASUREMENT` not matching `getCurrentProducer().measurement` after activation.
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
- `feat/task-1-vsock-staging-transport` branch work — merge or rebase before Phase C

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->

### Success / rollback criteria

| Signal | Action |
|--------|--------|
| AC #4 + #7 KVM green for 2 weeks | Mark TASK-4 Done; TASK-1 prod image path = Nix only |
| SNP blocked >4 weeks on infra | Ship prod with KVM attestation policy on lab; SNP sub-milestone stays open |
| Reproducibility fails (non-deterministic measurement) | Fix flake inputs before any mainnet fork ticket |

### References to copy

- **Launch:** `yolo/mainnet-deploy/sev-vm/run-deploy.sh` (QEMU SNP, no OVMF)
- **Guest shape:** `yolo/mainnet-deploy/sev-vm/flake.nix` (strip to HSM-only)
- **CI/hash:** Contrast-style flake + Cardano-style locked builds (process, not their K8s stack)

<!-- SECTION:NOTES:END -->