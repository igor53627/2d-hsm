---
id: TASK-5
title: Production HSM path — prod enclave in guest, platform PQ seal, SNP, real measurement
status: In Progress
assignee: []
created_date: '2026-06-05'
updated_date: '2026-06-05'
labels:
  - production
  - tee
  - sev-snp
  - vsock
  - pq-seal
  - attestation
dependencies:
  - TASK-4
  - TASK-1
  - TASK-3
references:
  - impl/nix/vm-hsm/nixos-module.nix
  - impl/nix/vm-hsm/enclave.nix
  - impl/rust/enclave-protocol/src/platform_provisioning_boot.rs
  - impl/scripts/aya-sev-snp/run-vm-hsm.sh
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - backlog/docs/pq-seal-v1-provisioning-runbook.md
  - backlog/docs/authorization-tickets-precompile-spec-draft.md
priority: high
ordinal: 1600
parent: TASK-4
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->

Close the gap between **staging smokes green on aya** and a **deployable production 2d-hsm** inside a confidential VM.

Today (2026-06-05, branch `feat/task-1-vsock-staging-transport`):

- Protocol + state machine + ML-DSA staging signer work in Rust.
- NixOS guest runs **`enclave-vsock-staging`** with `TWOD_HSM_VSOCK_*` — host→guest vsock smoke passes (KVM).
- **`.#vm-production`:** release `enclave-vsock` + lab attestation VK (transport smoke). **`.#vm-production-lab`:** debug `lab-production-vsock` + file PQ seal (`pq_signing_ready` smoke). Platform trust + PQ root from vTPM/SNP remain open (Phase 3).
- SNP launch on aya is not the smoke path; production `GET_MEASUREMENT` / manifest still use placeholder measurement labels.

This task is the **operational production milestone** after TASK-4 Phase B (transport + guest shell).

### Why Ed25519 is not “instead of PQ”

Normative split (vsock spec §2.1, §2.3, §9):

| Role | Algorithm | Where secret lives | What it proves |
|------|-----------|-------------------|----------------|
| **Authorization tickets & blocks** | **ML-DSA-65** | TEE — sealed PQ signer | Producer identity on-chain; `ticketHash` / block digests |
| **Producer Chain Attestation** | **Ed25519** | **Block Producer host** (not TEE) | Current chain view before arm/sign — **network second factor** vs untrusted vsock host |
| **TEE remote attestation** | Platform (SNP/Nitro report) | Platform | Which enclave **image** holds `pq_pubkey` |

Ed25519 does **not** replace PQ signing. The enclave **verifies** a 64-byte Ed25519 signature over `RecentChainProof` using a **pinned** `ProducerAttestationTrust` key that must **not** be derived from `pq_pubkey` (§9.3) — otherwise a host that knows the public PQ key could forge chain proofs and arm under a fake view.

PQ for every arm would be possible in theory but is deferred: larger wire size (3309 B), different provisioning/rotation story, and intentional **key separation** (chain-view signer ≠ long-term PQ producer key).

<!-- SECTION:DESCRIPTION:END -->

## Phase status (2026-06-05, branch `feat/task-1-vsock-staging-transport`)

| Phase | Scope | Status |
|-------|--------|--------|
| **1** | Prod `enclave-vsock` in NixOS guest (`.#vm-production`) | **Done** — transport smoke; lab trust VK only |
| **2** | Lab PQ seal (`.#vm-production-lab`, fail-closed boot) | **Done** — aya `pq_signing_ready` smoke |
| **3** | SNP launcher + real TEE measurement | **Open** |
| **4** | BP vsock + live `RecentChainProof` | **Open** |
| **5** | Review gate (Full matrix on material changes) | **Done** for PR #5 (roborev 6890–6900) |

## Acceptance Criteria

<!-- AC:BEGIN -->

- [x] #1 NixOS guest can run **`enclave-vsock`** (prod) behind flake output `.#vm-production` (`guestProfile` staging|production); default `.#vm` stays staging.
- [ ] #2 Guest image provisions **`TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE`** from sealed store or build-time secret injection policy (documented; never from vsock at runtime).
- [x] #3 Lab path: `lab-production-vsock` + `TWOD_HSM_PQ_SEAL_*` / sealed blob in `.#vm-production-lab` (file-based; **not** release). Platform vTPM/SNP hook still open.
- [ ] #4 `GET_MEASUREMENT` returns non-placeholder **`measurement`** for production profile when SNP/Nitro report is available; manifest schema documents artifact hash vs TEE measurement (TASK-4 README + `write-measurement-manifest.sh` updated; live measurement still open here).
- [ ] #5 `run-vm-hsm.sh` (or successor) launches NixOS qcow2 with **SNP attempted** on aya; pass/fail recorded; KVM fallback documented.
- [x] #6 `run-nix-vm-guest-smoke-prod-lab.sh` — prod guest + sealed blob + `VSOCK_SMOKE_REQUIRE_PQ_READY=1` (aya verify on merge).
- [x] #7 `impl/README.md` + `nix/vm-hsm/README.md` updated: production operator runbook (env, seal, trust, vsock CID); `impl/scripts/aya-sev-snp/SMOKE-PASS-CRITERIA.md`.
- [x] #8 Full roborev matrix (Reduced 6890–6892 + 2×3 6893–6898, compact 6900); doc resolution for lab-trust naming (not mainnet `vm-production`).
- [x] #9 TASK-4 notes link here for “prod enclave in guest + SNP + measurement” closure (TASK-4 In Progress; SNP + real measurement remain in this task).
- [ ] #10 **Mainnet gate:** NixOS module or flake refuses **lab** `ProducerAttestationTrust` / lab PQ seal when `services.twod-hsm.productionMode = true` (or equivalent); `vm-production` / `vm-production-lab` outputs remain explicitly non-mainnet until platform trust + measurement ship.

<!-- AC:END -->

## Implementation plan

<!-- SECTION:PLAN:BEGIN -->

### Phase 1 — Prod binary in guest (~3–5 days) — **Done** (transport smoke)

- Extend `nixos-module.nix`: `services.twod-hsm.enclavePackage` / mode switch (`staging` vs `production`).
- Systemd unit for `enclave-vsock` + required env (`TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE`, `TWOD_HSM_VSOCK_*`).
- Build-time or initrd injection for attestation trust VK (32 bytes) per §9.3 policy.

### Phase 2 — PQ seal in guest (~1 week)

- Integrate `pq-seal-v1` provisioning runbook into NixOS activation (test root in lab; platform root via vTPM/SNP when available).
- Fail-closed prod boot without sealed signer; staging flake output unchanged for aya dev smokes.

### Phase 3 — SNP launcher + measurement (~1 week)

- SNP path: extend or replace `run-vm-hsm.sh` (today **KVM-only**, exits for `SEV_MODE=snp`); align with yolo `memfd-private` / `sev-snp-guest` QEMU line or keep Ubuntu `run-snp-smoke.sh` until unified.
- Plumb platform report into `GET_MEASUREMENT`; update `write-measurement-manifest.sh` fields.
- Re-run aya smokes; document SNP vs KVM in task notes.

### Phase 4 — BP integration slice (~3 days, doc + shim)

- Document: BP holds Ed25519 **attestation signing** key; enclave holds **verify** key only.
- Elixir vsock client smoke (GET_MEASUREMENT → ARM with real `RecentChainProof` frame) — can be sub-task if scope grows.

### Phase 5 — Review gate

- Full matrix if prod boot / arming gating changes materially (`AGENTS.md` rules); else Reduced + compact.

<!-- SECTION:PLAN:END -->

## Out of scope

- Replacing Ed25519 Producer Chain Attestation with ML-DSA (design change; separate spec revision).
- On-chain `MeasurementRegistry` precompile implementation (2d-solidity repo).
- Nitro EIF packaging.
- Mainnet fork ticket submission E2E (coordination with 2d BP team).

## Related

- **TASK-4** (parent) — Nix flake + NixOS guest shell; Phase B smokes ✅ KVM staging
- **TASK-3** (Done) — Ed25519 `RecentChainProof` verification in enclave
- **TASK-1** (In Progress) — ML-DSA signing + seal v1 in TEE
- Branch: `feat/task-1-vsock-staging-transport` — merge before Phase 1

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->

### Current baseline (aya 2026-06-05)

| Check | Status |
|-------|--------|
| `run-nix-enclave-staging.sh` loopback | ✅ |
| `run-nix-vm-guest-smoke.sh` staging guest CID 42 | ✅ |
| `run-nix-vm-guest-smoke-prod-lab.sh` (`.#vm-production-lab`) | ✅ aya (`73f9c98`) |
| `run-nix-vm-guest-smoke-prod.sh` (transport only) | ✅ |
| Prod `nix build .#enclave` | ✅ build; ✅ optional guest via `vm-production` |
| SNP guest boot on aya | ❌ (KVM smokes only) |

### Success criteria

Prod guest smoke green + manifest documents real TEE measurement (or signed waiver) → ready for BP integration testing, not mainnet alone.

<!-- SECTION:NOTES:END -->