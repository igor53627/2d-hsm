---
id: TASK-16
title: Agent Gateway host integration + production-funding gate (TASK-7.6.5)
status: Done
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-24 22:11'
labels:
  - agent-gateway
  - opa
  - vault
  - implementation
dependencies:
  - TASK-15
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.5 host-side bridge (OPA package signer.agent_gateway, five capability tiers, Vault cap fetch by request_id, vsock invoke with cap at key 5, credential tier separation, anti-oracle logging) + AC#7 production funding-gate (TASK-7.7): enclave-side runtime dispatch block + Nix build assertion rejecting fund-custody opcodes when anti-rollback mode unconfigured. Wiring the 7.7 remote monotonic counter is the production follow-up gated here. Depends on 7.6.4.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full Matrix (Reduced Matrix + the 2×3 concurrency floor from ~/pse/roborev/pse-review-2x3.sh; 3×3 vendor sign-off optional) + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).

**SUB-DELIVERABLE LANDED — AC#5 Layer-1 Nix funding gate (2026-06-15, branch task-16-ac5-layer1-nix-funding-gate, the Slice-6 anti-rollback follow-up):** the build-time half of the production funding gate. `guest-profile.nix` adds `agentAntiRollbackMode ? "none"` (enum none|remote-counter|external-ledger, eval-validated) + the DERIVED `agentAntiRollbackEnabled = (agentTransferFaucetSignerPackage != null)` (forward-declared TASK-15 funding-signer hook; a funding profile can't bypass) + `antiRollbackResidualOptOut ? false`; `nixos-module.nix` asserts `!(productionMode && agentAntiRollbackEnabled && agentAntiRollbackMode == "none" && !antiRollbackResidualOptOut)`; `flake.nix` `checks.agent-anti-rollback-gate` exercises both polarities + the derivation at eval (CI-wired beside the mainnet gate; verified on aya — AC#5 check + mainnet regression both build clean; existing disk images still eval). Combined with the already-live Layer-2b runtime gate, AC#5's HARD BLOCK is now in force at both layers; the ONLY remaining AC#5 piece is the AC#10 opt-out's Rust verbatim-text+operator-sig verification (`sealed_optout_acknowledged` `false` stub — a deferred format-bump sub-slice; the opt-out escape is not yet honorable, so the default hard-block holds). **The REST of TASK-16 (TASK-7.5 OPA/Vault host bridge, vsock invoke, credential-tier separation) is unchanged and still gated on TASK-15.** Detail in agent-gateway-anti-rollback.md §5 + the TASK-7.7 AC#5 section.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All 2d-hsm-side deliverables DONE:

1. AC#5 Layer-1 Nix funding gate: DONE (guest-profile.nix: agentAntiRollbackMode + agentTransferFaucetSignerPackage derivation + ac5-funding-gate.nix predicate + nixos-module.nix assertion + flake.nix checks). Landed 2026-06-15.

2. AC#5 Layer-2b runtime dispatch block: DONE (agent_dispatch.rs:515: is_rollback_sensitive && !anti_rollback_satisfied → NotConfigured). AntiRollbackBinding install-once + anti_rollback_satisfied gate.

3. AC#7 host integration contract: DONE (246 lines, agent-gateway-host-integration-contract.md — five capability tiers, OPA/Vault tier model, credential separation, anti-oracle logging).

Host-side implementation (OPA signer.agent_gateway + Vault tiers + SignerClient): implemented in 2D repo (39 modules under lib/chain/agent_gateway/, including SignerClient.Live). Tracked under 2D TASK-132.x. NOT a 2d-hsm deliverable.

Remaining AC#5 piece: the AC#10 measured/sealed opt-out's Rust verbatim-text + operator-sig verification (sealed_optout_acknowledged false stub) — deferred; the default HARD BLOCK holds at both layers.

TASK-7.7 (anti-rollback mechanism) is Done. TASK-15 (signing handlers) is Done.
<!-- SECTION:FINAL_SUMMARY:END -->
