---
id: TASK-7.5
title: Agent Gateway host policy and capability integration contract
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-07 18:20'
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
  - backlog/docs/agent-gateway-host-integration-contract.md
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
- [x] #1 Runtime signing, faucet treasury signing, provisioning/refill, backup export, and restore/recovery capabilities are distinct.
- [x] #2 Normal runtime credentials cannot generate keys, export backups, restore backups, sign arbitrary digests, or bypass TEE-enforced faucet caps.
- [x] #3 OPA/Vault namespace examples are agent-specific and do not reuse bridge/operator paths; any shared Vault mount/root must still use distinct agent policy prefixes, issuing authorities, and audit paths. Vault material is authorization/capability material for TEE commands, not private keys or backup decrypt material.
- [x] #4 The contract references the canonical capability taxonomy from TASK-7.1/TASK-7.2/TASK-7.4 and documents what checks are host-side only and what checks the TEE enforces again.
- [x] #5 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design delivered in backlog/docs/agent-gateway-host-integration-contract.md (host-side contract; design-only; TEE is non-bypassable). Consumes the TEE capability taxonomy from TASK-7.1/7.2/7.4. Adds: the 5 distinct capability tiers as the host models them (T0 runtime, T1 treasury-provisioning/admin, T2 transfer-refill, T3 backup-export, T4 restore/recovery) (AC#1); agent-specific OPA package signer.agent_gateway + Vault secret/data/agent-gateway/{runtime,provision,export,recovery} with cross-tier-denied ACLs, distinct from bridge, and the Vault=authorization-material-not-keys boundary (AC#3); the host-vs-TEE check matrix per command + AC#2 no-privilege-escalation guarantees (AC#4/#2); the local->OPA->Vault->2d-hsm caller flow mirroring Chain.Bridge.Signer; negative-capability test requirements (DoD#2). Adopted: companion doc; operator pre-signs caps -> Vault (indexed by request_id) -> host forwards at key 5; coarse command_class folding (reset_breaker own recovery lane). Honest residuals: expiry/revocation host-side only (TEE has no clock; hard-revoke=counter-burn); transfer dest/amount limits OPA/host-only (no TEE per-agent cap); rollback-sensitive until TASK-7.7. AC #1-#4 addressed; AC #5 (roborev) run pre-merge.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Integration contract is documented for 2D app implementers.
- [ ] #2 Negative capability cases are covered by tests or vectors where code exists.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
