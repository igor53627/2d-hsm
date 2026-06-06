---
id: TASK-5
title: >-
  Production HSM path — prod enclave in guest, platform PQ seal, SNP, real
  measurement
status: In Progress
assignee: []
created_date: '2026-06-05'
updated_date: '2026-06-06 09:53'
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
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Close the gap between **staging smokes green on aya** and a **deployable production 2d-hsm** inside a confidential VM.

Today (2026-06-05, branch `feat/task-1-vsock-staging-transport`):

- Protocol + state machine + ML-DSA staging signer work in Rust.
- NixOS guest runs **`enclave-vsock-staging`** with `TWOD_HSM_VSOCK_*` — host→guest vsock smoke passes (KVM).
- **`.#vm-production`:** debug `enclave-production-transport` (`production-vsock` + `TRANSPORT_ONLY_MODE`) + lab attestation VK (transport smoke). **`.#vm-production-lab`:** debug `lab-production-vsock` + file PQ seal (`pq_signing_ready` smoke). Platform trust + PQ root from vTPM/SNP remain open (Phase 3).
- SNP launch on aya **works** for the Ubuntu guest (QEMU 10 + AMD OVMF; SEV-SNP active, golden disk boots) but is not yet the default smoke path, and the NixOS production guest does not boot under SNP yet (AC#5). Production `GET_MEASUREMENT` / manifest still use placeholder measurement labels until the enclave-side AC#4 wiring lands and the prod guest runs under SNP.

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

## Phase status (2026-06-06, AC#4 branch `feat/task-5-snp-report`)

| Phase | Scope | Status |
|-------|--------|--------|
| **1** | Prod `enclave-vsock` in NixOS guest (`.#vm-production`) | **Done** — transport smoke via `enclave-production-transport` (debug); lab trust VK only |
| **2** | Lab PQ seal (`.#vm-production-lab`, fail-closed boot) | **Done** — aya `pq_signing_ready` smoke |
| **3** | SNP launcher + real TEE measurement | **In progress** — AC#4 enclave-side + AC#5 NixOS-under-SNP launcher both **live-validated on aya** (`.#disk-production-lab` boots under SEV-SNP; GET_MEASUREMENT returns real 48B measurement, bytes=3210, pq_ready=true); manifest split and VCEK cert-chain/verifier spec remain |
| **4** | BP vsock + live `RecentChainProof` | **Open** |
| **5** | Review gate (Full matrix on material changes) | **Done** for PR #5 (roborev 6890–6900) |

## Acceptance Criteria

<!-- AC:BEGIN -->

- [x] #1 NixOS guest can run **`enclave-vsock`** (prod) behind flake output `.#vm-production` (`guestProfile` staging|production); default `.#vm` stays staging.
- [ ] #2 Guest image provisions **`TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE`** from sealed store or build-time secret injection policy (documented; never from vsock at runtime).
- [x] #3 Lab path: `lab-production-vsock` + `TWOD_HSM_PQ_SEAL_*` / sealed blob in `.#vm-production-lab` (file-based; **not** release). Platform vTPM/SNP hook still open.
- [ ] #4 `GET_MEASUREMENT` returns non-placeholder **`measurement`** for production profile when SNP/Nitro report is available; manifest schema documents artifact hash vs TEE measurement (TASK-4 README + `write-measurement-manifest.sh` updated; live measurement still open here).
- [x] #5 `run-vm-hsm.sh` (or successor) launches NixOS qcow2 with **SNP attempted** on aya; pass/fail recorded; KVM fallback documented. _(Successor `run-nix-snp-guest-smoke.sh` + bootable `.#disk-production-lab` landed; `run-vm-hsm.sh SEV_MODE=snp` now points there; KVM fallback `SEV_MODE=none` documented. **LIVE PASS on aya 2026-06-06**: NixOS prod guest booted under SEV-SNP, host smoke OK cid=42 with require_real=1, bytes=3210 — real 48B measurement + ~1184B VCEK report + pq_signing_ready=true.)_
- [x] #6 `run-nix-vm-guest-smoke-prod-lab.sh` — prod guest + sealed blob + `VSOCK_SMOKE_REQUIRE_PQ_READY=1` (aya verify on merge).
- [x] #7 `impl/README.md` + `nix/vm-hsm/README.md` updated: production operator runbook (env, seal, trust, vsock CID); `impl/scripts/aya-sev-snp/SMOKE-PASS-CRITERIA.md`.
- [x] #8 Full roborev matrix (Reduced 6890–6892 + 2×3 6893–6898, compact 6900); doc resolution for lab-trust naming (not mainnet `vm-production`).
- [x] #9 TASK-4 notes link here for “prod enclave in guest + SNP + measurement” closure (TASK-4 In Progress; SNP + real measurement remain in this task).
- [ ] #10 **Mainnet gate:** NixOS module or flake refuses **lab** `ProducerAttestationTrust` / lab PQ seal when `services.twod-hsm.productionMode = true` (or equivalent); `vm-production` / `vm-production-lab` outputs remain explicitly non-mainnet until platform trust + measurement ship.

<!-- AC:END -->

## Implementation Plan

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
| SNP guest boot on aya | ✅ Ubuntu guest (QEMU 10 + AMD OVMF; SEV-SNP active, golden boots); NixOS-under-SNP pending (AC#5) |

### Success criteria

Prod guest smoke green + manifest documents real TEE measurement (or signed waiver) → ready for BP integration testing, not mainnet alone.

Phase 3 / AC#4 progress (branch feat/task-5-snp-report): SNP boot ALREADY works on aya (EPYC 9375F, QEMU 10 + AMD OVMF, golden disk boots with SEV-SNP active) — the old 0xfee00000 LAPIC blocker notes are stale. Attestation interface = configfs-tsm (/sys/kernel/config/tsm/report), pure file I/O, fits #![forbid(unsafe_code)]; report 1184B, version 5, measurement@0x90[48], report_data@0x50[64] (verified vs a real captured report, committed as testvectors/snp_report_golden_v5.bin). Gap: Ubuntu cloud image kernel 6.8.0-117 ships NO sev-guest module (needs linux-modules-extra + modprobe; NixOS gets boot.kernelModules += sev-guest). Implemented: src/snp_report.rs (fetch+parse+report_data binding=SHA3-512(domain||pq_pubkey)), boot_capture_snp_measurement() hook in enclave_vsock.rs, measurement_response() returns real 48B measurement + raw report with graceful placeholder fallback (KVM/dev). Tests: default 62/0, reference-test-key 89/0; prod+staging binaries build. LIVE VALIDATED on aya: dump_snp_measurement example run inside the SNP guest returned measurement=3e39e33a...6b488 == the raw configfs-tsm capture. Remaining: roborev+PR; VCEK cert chain (auxblob) in attestation; manifest split (build-hash vs TEE measurement); AC#5 NixOS-qcow2 SNP launcher for prod-guest live GET_MEASUREMENT.

Attestation contract (AC#4): GET_MEASUREMENT.measurement = 48-byte SNP launch measurement (report offset 0x90); attestation = the raw signed SNP ATTESTATION_REPORT (1184B, VCEK-signed) with report_data echoing SHA3-512(domain||pq_pubkey) for key binding (verified before caching). DEFERRED (Phase-3 follow-up, not in this slice): bundling the VCEK->ASK->ARK cert chain (configfs-tsm auxblob) and publishing the verifier policy (expected measurement allowlist + chain validation steps) so relying parties have a complete contract. roborev Full Matrix (jobs 7106-7111, compact 7112) on the branch: fixed High fail-open (release builds now refuse to serve an operational signer without a real SNP measurement; dev/lab stay graceful), High NixOS configfs-tsm sandbox (ReadWritePaths=/sys/kernel/config/tsm for prod; needs live validation at AC#5), Medium report_data echo now verified before trust. default cargo test 64/0, reference-test-key 91/0, release prod build OK.

AC#5 (NixOS-under-SNP launcher, branch TBD — 2026-06-06): the KVM smokes drive the nixpkgs qemu-vm *runner* (config.system.build.vm), which embeds its own QEMU and injects the kernel directly — it has no hook for the SEV-SNP launch objects (sev-snp-guest / memory-backend-memfd / -bios AMD OVMF). So the SNP path needs a self-booting disk. Implemented: (1) `disk-image.nix` builds a bootable GPT/EFI qcow2 per profile via nixpkgs `make-disk-image.nix` (partitionTableType=efi → ESP label "ESP" + root label "nixos"; GRUB installed efiInstallAsRemovable → EFI/BOOT/BOOTX64.EFI so it boots under `-bios OVMF.fd` with NO persistent NVRAM, matching run-guest-vm.sh's SNP line which carries no pflash). (2) flake outputs `.#disk-production` (transport-only; placeholder measurement by design — no operational signer) and `.#disk-production-lab` (lab PQ seal → operational signer → real measurement under SNP). (3) `guest-profile.nix` extracted so vm.nix (KVM) and disk-image.nix (SNP) share the exact profile→enclave/trust/seal mapping; verified the `vm`/`vm-production`/`vm-production-lab` drvPaths are byte-identical after the refactor (eval on darwin). (4) `run-nix-snp-guest-smoke.sh`: builds `.#disk-production-lab`, copies to a writable qcow2, boots it via run-guest-vm.sh's proven SNP QEMU line (no cloud-init/SSH — enclave is a baked systemd unit), polls host→guest vsock with the new real-measurement gate; `SEV_MODE=none` = KVM fallback (gate auto-relaxed). (5) `run-vm-hsm.sh SEV_MODE=snp` now points at the new launcher instead of exit-2 manual hint. (6) `vsock_smoke_client.py` gained `VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT=1` → pure `assert_measurement_fields`: CBOR key 2 must be exactly 48 bytes and not the dev/staging labels (enclave-measurement-placeholder / prod-enclave-v1), key 3 a real ≥1024B report (not attestation-placeholder); 9/9 local unit checks pass. Local verification on darwin (no x86_64-linux builder): nix flake show + eval of both disk drvPaths (instantiate, distinct closures, nixos-disk-image w/ qcow2+vm-run builder), vm-* drvPaths unchanged, bash -n + shellcheck clean on launchers (two pre-existing SC2086 in smoke-cache-lib `$ssh_common` only), py_compile + assertion unit test green. LIVE VALIDATED on aya (EPYC, 2026-06-06) via a throwaway worktree at main(4294ab6)+patch: `nix build .#disk-production-lab` produced an nixos-disk-image qcow2 byte-reproducible vs the darwin eval; `run-nix-snp-guest-smoke.sh` booted it under SEV-SNP (run-guest-vm.sh "SEV-SNP guest (AMDSEV-style launch)"; guest reached full systemd login prompts), host→guest GET_MEASUREMENT returned require_real=1 OK: bytes=3210 (48B real launch measurement + ~1184B VCEK report + ML-DSA pubkey), pq_signing_ready=true; clean teardown. aya `/root/2d-hsm` checkout left untouched; image kept in /var/cache/2d-hsm. AC#5 = DONE.

Post-implementation /code-review (max effort, 2026-06-06) found + fixed: (H) KVM-fallback (SEV_MODE=none) was broken — the launcher left host-guest-vsock-smoke.sh's default text marker `prod-enclave-v1` (staging label) in place, which never matches the prod guest's `enclave-measurement-placeholder`; (H) documented `DISK_ATTR=disk-production` transport run failed because `VSOCK_SMOKE_REQUIRE_PQ_READY` was hardcoded to 1 but the transport profile has no signer; (H) the CI step that *built* `.#disk-production-lab` would need `requiredSystemFeatures=["kvm"]` (vmTools.runInLinuxVM) which GitHub runners can't be relied on to provide → would block the whole workflow. Fixes: launcher now derives `require_real` / `require_pq` / placeholder-marker from DISK_ATTR(lab vs transport) + SEV_MODE so every documented invocation works with zero manual env; CI step changed to `nix eval` the disk drvPath (no build, no kvm); plus quality fixes — qcow2 backing overlay + per-PID work disk (was a full ~2G `cp` per run, and a shared path that races concurrent runs), `copyChannel=false` (don't bake the nixpkgs channel into the appliance image), GRUB serial console for the `-nographic` boot, and the smoke's attestation length floor tightened 1024→1184 (real report size). RE-VALIDATED on aya after the fixes: `.#disk-production-lab` rebuilt (drvPath again == darwin eval) and `run-nix-snp-guest-smoke.sh` PASS under SNP (require_real=1 require_pq=1, bytes=3210). Still open in Phase 3: capture/publish the measurement allowlist value, VCEK->ASK->ARK cert-chain (auxblob) in attestation + verifier policy spec, manifest split (build-hash vs TEE measurement); configfs-tsm prod sandbox is exercised by this live boot (lab/debug build → graceful, gate not release-strict).
<!-- SECTION:NOTES:END -->

## Out of scope

- Replacing Ed25519 Producer Chain Attestation with ML-DSA (design change; separate spec revision).
- On-chain `MeasurementRegistry` precompile implementation (2d-solidity repo).
- Nitro EIF packaging.
- Mainnet fork ticket submission E2E (coordination with 2d BP team).

## Related

- **TASK-4** (dependency; see front matter) — Nix flake + NixOS guest shell; Phase B smokes ✅ KVM staging
- **TASK-3** (Done) — Ed25519 `RecentChainProof` verification in enclave
- **TASK-1** (In Progress) — ML-DSA signing + seal v1 in TEE
- Branch: `feat/task-1-vsock-staging-transport` — merge before Phase 1
