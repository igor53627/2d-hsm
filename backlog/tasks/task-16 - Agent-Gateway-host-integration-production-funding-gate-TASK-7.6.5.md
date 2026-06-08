---
id: TASK-16
title: Agent Gateway host integration + production-funding gate (TASK-7.6.5)
status: To Do
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 08:46'
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
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full 3x3 vendor matrix + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).
<!-- SECTION:NOTES:END -->
