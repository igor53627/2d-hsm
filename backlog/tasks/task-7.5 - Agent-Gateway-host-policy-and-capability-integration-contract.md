---
id: TASK-7.5
title: Agent Gateway host policy and capability integration contract
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-07 18:27'
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
Design delivered in backlog/docs/agent-gateway-host-integration-contract.md (host-side contract; design-only; TEE non-bypassable). Consumes the TEE capability taxonomy from TASK-7.1/7.2/7.4. Five DISTINCT capabilities per AC#1: (1) runtime signing SIGN_TRANSFER, (2) faucet-treasury signing SIGN_FAUCET_DISPENSE — a distinct host class, not merged with runtime — (3) provisioning/refill, (4) backup-export, (5) restore/recovery; each a distinct OPA selector + Vault path + counter command_class. OPA package signer.agent_gateway; FIVE Vault paths secret/data/agent-gateway/{runtime-transfer,runtime-faucet,provision,export,recovery} with cross-tier-denied ACLs (migrated from the 2-path model); Vault = authorization material only, not keys/backup-decrypt. Host-vs-TEE split: TEE Frame gates (ALL opcodes) vs Capability gates (ONLY privileged {1,6,7,8}; runtime {4,5} + reads {2,3} carry no key-5 cap). Recovery counter SHARED by RESTORE_BACKUP + reset_lifetime_breaker (vsock §10.6). chain_id validated against the sealed value (11565 = example, not hardcoded). Honest residuals: expiry/revocation host-side only (counter-burn ceremony specified); transfer dest/amount limits OPA/host-only (no TEE per-agent cap); rollback-sensitive until TASK-7.7.

Roborev evidence (AC#5): 3x3 vendor matrix (codex+gemini+claude-code x security/design/default) on 671d307 -> 2 HIGH (AC#1 runtime/faucet tier-merge; §4 global-vs-capability gate split) + 5 MED + LOW; resolved in b5fb632 + OPA-input/notes follow-up; consolidated via roborev compact (job 7631, re-verified clean). AC #1-#4 addressed by this design; AC #5 evidenced here.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Integration contract is documented for 2D app implementers.
- [ ] #2 Negative capability cases are covered by tests or vectors where code exists.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
