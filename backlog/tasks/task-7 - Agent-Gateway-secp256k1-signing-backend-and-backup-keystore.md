---
id: TASK-7
title: Agent Gateway secp256k1 signing backend and backup keystore
status: To Do
assignee: []
created_date: '2026-06-07 00:00'
labels:
  - agent-gateway
  - secp256k1
  - tee
  - backup
dependencies:
  - TASK-2
  - TASK-5
references:
  - /Users/user/pse/2d/backlog/tasks/task-132.5 - Provision-dedicated-NetHSM-namespace-for-agent-faucet-and-transfer-signing.md
  - /Users/user/pse/2d/docs/superpowers/specs/2026-06-07-agent-signer-namespace-and-key-pool-design.md
  - impl/rust/enclave-protocol
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - backlog/docs/pq-seal-v1-provisioning-runbook.md
priority: high
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add a 2d-hsm Agent Gateway signing backend for ordinary 2D transfers using secp256k1/k1 keys inside the TEE. This lets Agent Gateway faucet and transfer MVPs submit today-compatible 2D transactions without depending on Nitrokey NetHSM for agent custody, while keeping a migration path to ML-DSA/PQ agent signatures after the 2D chain supports PQ account transactions.

The backend must provide agent-scoped key generation, public-key/address identity, structured transfer signing, and encrypted agent-keystore backup export. Plaintext private keys must never leave the TEE. Host-side OPA/Vault may gate access, but the TEE must enforce non-bypassable command/key-purpose invariants so a compromised host cannot turn 2d-hsm into a generic secp256k1 signing oracle.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The vsock/wire protocol defines agent-specific secp256k1 commands for batch key generation, public identity lookup, challenge signing or equivalent identity proof, structured ordinary-transfer signing, and encrypted agent-keystore backup export.
- [ ] #2 The TEE key store records key purpose metadata and distinguishes agent transfer keys, agent faucet treasury keys, producer PQ keys, AuthorizationTicket keys, and any future bridge keys; commands fail closed when the key purpose does not match the command.
- [ ] #3 Structured signing does not expose a generic `SIGN_DIGEST` oracle for agent keys. The TEE validates command domain, chain ID, key purpose, and canonical 2D transaction fields before producing a secp256k1 signature.
- [ ] #4 Agent key generation supports batch creation with opaque key refs suitable for high-volume Agent Gateway key-pool refill.
- [ ] #5 Encrypted agent-keystore backup export produces an opaque blob that can be stored by the 2D Agent Gateway filesystem backup sink; plaintext private keys and backup decrypt/restore material never leave the TEE/runtime boundary.
- [ ] #6 Backup encryption is designed for disaster recovery, not only same-process restart: the spec defines recovery wrapping/provisioning-root/quorum assumptions and clearly states what can and cannot be restored onto a new TEE instance.
- [ ] #7 Host-side integration keeps OPA/Vault style separation: runtime signing capability, provisioning/refill capability, and recovery material are separate, and no normal runtime credential can generate keys, export backups, or restore backups.
- [ ] #8 The 2d-hsm implementation does not reuse AuthorizationTicket commands, producer ML-DSA keys, or producer arming/network-second-factor state for Agent Gateway signing.
- [ ] #9 Tests cover command-domain separation, key-purpose mismatches, no generic digest signing, batch generation, public identity derivation, backup export opacity, and failure cases with no private-key leakage.
- [ ] #10 High-risk review follows this repo's AGENTS.md roborev matrix rules before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-06-07: Created as the 2d-hsm side of 2D `TASK-132.5`. The preferred Agent Gateway signer backend is now `2d-hsm` secp256k1 inside a TEE, not Nitrokey NetHSM. NetHSM may remain as a fallback/deferred backend, but Agent Gateway should not be designed around NetHSM-only key lifecycle or system backups.

The expected host-side pipeline remains similar to the existing NetHSM bridge signer pattern: local validation -> OPA agent policy -> Vault capability lookup -> signer backend. For 2d-hsm, this is only the host-side gate. The TEE must still enforce minimal policy internally because the host/vsock client can be compromised.

This task does not add PQ account transactions to 2D. It adds secp256k1 support so current ordinary transfers work unchanged. Future ML-DSA/PQ Agent Gateway transfers require a separate 2D chain/account-format task, likely related to 2D `TASK-24`.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Protocol/spec updates are written and reviewed.
- [ ] #2 Implementation tests pass for the new agent secp256k1 commands and backup export path.
- [ ] #3 No command path exposes plaintext private keys or generic unrestricted digest signing.
- [ ] #4 Roborev matrix/compact evidence is recorded per AGENTS.md for high-risk changes.
- [ ] #5 Final summary added before marking Done.
<!-- DOD:END -->
