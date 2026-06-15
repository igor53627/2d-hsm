---
id: TASK-15
title: Agent Gateway transfer + faucet signing + caps impl (TASK-7.6.4)
status: To Do
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 08:46'
labels:
  - agent-gateway
  - implementation
dependencies:
  - TASK-12
  - TASK-13
  - TASK-14
ordinal: 19000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.4 implementation. Opcodes SIGN_TRANSFER(4), SIGN_FAUCET_DISPENSE(5), CONFIGURE_TREASURY(6). SIGN_TRANSFER: chain_id/from/empty-data checks, EIP-155 RLP keccak256, low-S sig, v=chain_id*2+35+rid, post-sign recovery==from. FAUCET_DISPENSE: recipient in active transfer set, checked u256 worst-case arithmetic, per-field caps, dual-counter debit sealed-before-emit, unbroadcast burn. CONFIGURE_TREASURY sub-ops + monotonic config_version + rotation carry-over. No generic digest. Golden vector ordinary_tx_v1. Depends on 7.6.1-7.6.3.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full Matrix (Reduced Matrix + the 2×3 concurrency floor from ~/pse/roborev/pse-review-2x3.sh; 3×3 vendor sign-off optional) + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).

**BLOCKING AC#5-FUNDING-GATE PRECONDITIONS (from the TASK-16 AC#5 Layer-1 gate's fail-open review, wf_a2cce791, 2026-06-15).** TASK-15 introduces the first PRODUCTION funding profile (an operational faucet/transfer signer), which ARMS the dormant AC#5 Layer-1 Nix gate (`guest-profile.nix`/`nixos-module.nix`/`flake.nix`, branch task-16-ac5-layer1-nix-funding-gate). The gate is correct + fail-closed on its INTENDED path, but two silent build-time fail-opens of fund custody MUST be closed when TASK-15 wires the signer — they cannot be implemented before the signer/endpoint exist:
1. **Arm via `agentTransferFaucetSignerPackage` (mechanism C).** The gate derives `agentAntiRollbackEnabled = (agentTransferFaucetSignerPackage != null)`. TASK-15 MUST install the operational funding signer through THIS exact guest-profile arg (and thread it + `agentAntiRollbackMode` + `antiRollbackResidualOptOut` through `disk-image.nix`/`vm.nix`). If the signer is wired via a different arg, the gate stays disarmed ⇒ a funding profile with mode "none" builds clean = fail-open. (Deriving from the installing arg is the structural mitigation — keep them the same arg.)
2. **Endpoint realness — stub→none `usesLab` downgrade (the §5 "a no-op can't pass" property).** The Layer-1 gate currently asserts only `mode != "none"`; a non-"none" mode pointed at a stub/lab/unreachable endpoint passes. TASK-15 MUST add the endpoint/credential override args + a `usesLab`-style downgrade (mirroring the trust/seal-fixture pattern) so a no-op endpoint counts as "none". Interim backstop: the live Layer-2b runtime gate hard-blocks rollback-sensitive ops unless a REAL `ANTI_ROLLBACK_BINDING` installs post-reconcile (a stub won't round-trip a signed anchor reconcile).
3. **Check robustness (hardening, optional):** `checks.agent-anti-rollback-gate` consumes the single-sourced predicate but does not instantiate the real nixos-module — a *deleted* assertion (vs a drifted one) is caught only once a real funding profile's `disk-image` output is CI-eval'd (which TASK-15 adds). Consider an `evalModules`-over-`nixos-module.nix` self-test asserting the assertions LIST fires.
<!-- SECTION:NOTES:END -->
