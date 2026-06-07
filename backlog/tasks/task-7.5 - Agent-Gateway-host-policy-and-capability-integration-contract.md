---
id: TASK-7.5
title: Agent Gateway host policy and capability integration contract
status: To Do
assignee: []
created_date: '2026-06-07 00:00'
labels:
  - agent-gateway
  - opa
  - vault
  - policy
dependencies:
  - TASK-7.1
  - TASK-7.2
  - TASK-7.4
references:
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
priority: high
ordinal: 7050
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define the host-side integration contract for 2D Agent Gateway callers: local validation, Agent OPA policy, Vault capability lookup, and `2d-hsm` command invocation. Host gates are defense in depth; the TEE remains the final non-bypassable signer policy boundary.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Runtime signing, faucet treasury signing, provisioning/refill, backup export, and restore/recovery capabilities are distinct.
- [ ] #2 Normal runtime credentials cannot generate keys, export backups, restore backups, sign arbitrary digests, or bypass TEE-enforced faucet caps.
- [ ] #3 OPA/Vault namespace examples are agent-specific and do not reuse bridge/operator paths; any shared Vault mount/root must still use distinct agent policy prefixes, issuing authorities, and audit paths. Vault material is authorization/capability material for TEE commands, not private keys or backup decrypt material.
- [ ] #4 The contract references the canonical capability taxonomy from TASK-7.1/TASK-7.2/TASK-7.4 and documents what checks are host-side only and what checks the TEE enforces again.
- [ ] #5 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Integration contract is documented for 2D app implementers.
- [ ] #2 Negative capability cases are covered by tests or vectors where code exists.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
