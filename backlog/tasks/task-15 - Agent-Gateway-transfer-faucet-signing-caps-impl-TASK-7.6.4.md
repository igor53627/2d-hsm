---
id: TASK-15
title: Agent Gateway transfer + faucet signing + caps impl (TASK-7.6.4)
status: Done
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-24 21:52'
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

**SLICE PLAN (mirrors slice-6 cadence; risk-tiered by opcode).** 15-1 = SIGN_TRANSFER (read-only, non-rollback-sensitive foundation: RLP/EIP-155 encoder + handler — DONE, branch task-15-1-sign-transfer). 15-2 = faucet foundations (add the `cumulative_budget` CEILING field to `FaucetState` ⇒ KEYSTORE_FORMAT_VERSION 2→3 + golden regen; checked-`u256` `[u8;32]` arithmetic module). 15-3 = SIGN_FAUCET_DISPENSE (recipient allowlist + per-field caps + worst-case dual-counter debit through the seal-before-emit seam, EpochOnly). 15-4 = CONFIGURE_TREASURY (sub-ops {set_limits, refill_budget, raise_lifetime_breaker, reset_lifetime_breaker} + monotonic config_version + the sub-op commit-bump classifier). 15-5 = AC#5 Nix gate arming (preconditions 1–3 above). 15-6 = faucet write-path SNP smoke on aya. (15-2 is the sealed-format prerequisite for 15-3; not "reserved".)

**15-3 REUSE MANDATE (so the `u256` canonical wire form can't drift).** SIGN_FAUCET_DISPENSE's `amount`/`gas_price` decode MUST reuse `agent_cbor::as_u256_minimal_be` (the single canonical-form source 15-1 added: bstr `0..=32`, no leading zero, over-width→fail-closed) — do NOT re-implement the check. Add golden rejection tests for over-width / non-minimal `amount` + `gas_price` mirroring 15-1's `rejects_invalid_requests`.

**TASK-18 UN-GATE CHECKLIST (before removing `agent-sign-transfer-preview` / `agent-keygen-exec-preview` from production).** SIGN_TRANSFER is NOT rollback-sensitive, so anti-rollback alone does NOT satisfy its gate — the preview MUST stay until ALL of: (a) the **AC#5 production funding profile** is provisioned (15-5: signer via `agentTransferFaucetSignerPackage` + the `usesLab` endpoint downgrade) and the Layer-1 Nix gate is ARMED (builds fail without a sanctioned anti-rollback mode); (b) the AC#10 measured/sealed opt-out's Rust verbatim-text + operator-sig verification lands (`sealed_optout_acknowledged` is a `false` stub today); (c) host-side credential-tier separation + OPA/Vault policy (TASK-16 remainder) gates who may invoke fund-moving opcodes; (d) production transfer/large-`u256` vector coverage + a release-build feature-behavior test (the preview-OFF NotConfigured posture); (e) the Full Matrix + compact recorded on the un-gate PR. Removing the gate after (only) anti-rollback is a fail-open.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All slices implemented + tested + shipped in prior PRs:
- 15-1 SIGN_TRANSFER: handler (agent_dispatch.rs:746) + EIP-155 RLP encoder (agent_transfer.rs) + low-S + golden vector. PR landed.
- 15-2 u256 arithmetic: u256.rs module + FaucetState cumulative_signing_budget. KEYSTORE_FORMAT_VERSION 3.
- 15-3 SIGN_FAUCET_DISPENSE: handler (agent_dispatch.rs:870) + accept_and_debit checked u256 + recipient allowlist (is_known_transfer_recipient) + dual-counter debit via commit_before_emit (EpochOnly) + golden vector. PR #85 Full Matrix clean.
- 15-4 CONFIGURE_TREASURY: all 4 sub-ops (set_limits/refill_budget/raise_lifetime_breaker/reset_lifetime_breaker) + monotonic config_version + configure_treasury_sub_op_bump_class (all Structural) + golden vectors. PR #87.
- 15-5 AC#5 Nix gate: armed via agentTransferFaucetSignerPackage derivation + ac5-funding-gate.nix predicate + usesLab downgrade pattern. guest-profile.nix + nixos-module.nix + flake.nix checks.
- 15-6 Faucet smoke: CI lane (cargo test --lib lab_agent_smoke + bin build) + nix eval (disk-production-lab-agent-faucet-smoke) + aya SNP smoke validated (PR #79).

607 tests pass with all 3 preview features. All preview features UN-GATED under TASK-18 18-7/18-8.

Residuals (all Low, non-blocking) tracked in TASK-20: decode_and_sign_eip155_transfer seam extraction (altitude), encode_agent_response fail-closed-arm fragility, recipient-allowlist perf.
<!-- SECTION:FINAL_SUMMARY:END -->
