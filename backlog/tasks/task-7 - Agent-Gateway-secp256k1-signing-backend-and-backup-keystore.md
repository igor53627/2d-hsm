---
id: TASK-7
title: Agent Gateway secp256k1 signing backend and backup keystore
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-07 18:01'
labels:
  - agent-gateway
  - secp256k1
  - tee
  - backup
dependencies:
  - TASK-2
  - TASK-5
  - TASK-6
references:
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
  - >-
    ../2d/backlog/tasks/task-132.5 -
    Provision-dedicated-2d-hsm-signer-namespace-for-agent-faucet-and-transfer-signing.md
  - ../2d/docs/specs/2026-06-07-agent-gateway-signer-2d-hsm-key-pool-design.md
  - impl/rust/enclave-protocol
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - backlog/docs/pq-seal-v1-provisioning-runbook.md
priority: high
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Umbrella task for adding a `2d-hsm` Agent Gateway signing backend for ordinary 2D transfers using secp256k1 keys inside the TEE. This lets Agent Gateway faucet and transfer MVPs submit today-compatible 2D transactions without depending on Nitrokey NetHSM for agent custody, while keeping a migration path to PQ agent signatures after the 2D chain supports PQ account transactions.

This task is intentionally split into smaller reviewable subtasks because it touches protocol, persistent key custody, backup/DR, and signing policy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 TASK-7.1 defines versioned Agent Gateway protocol/opcodes and command-domain separation.
- [x] #2 TASK-7.2 defines persistent multi-key agent keystore storage and encrypted backup/DR semantics.
- [x] #3 TASK-7.3 designs secp256k1 agent key generation and public identity derivation, including faucet treasury key generation.
- [x] #4 TASK-7.4 designs structured ordinary 2D transfer and faucet dispense signing without generic digest signing.
- [ ] #5 TASK-7.5 defines host integration for OPA/Vault capability separation.
- [ ] #6 TASK-7.6 implements the reviewed design or splits implementation into narrower child tasks before code begins; replacement tasks must cover protocol framing, keystore/backup, keygen/identity, signing/caps, and host integration.
- [ ] #7 TASK-7.7 defines the production anti-rollback mechanism or explicitly blocks production fund custody without it.
- [ ] #8 Production Agent Gateway signing runs as a separate signer role/profile from Block Producer signing, with separate endpoint/listener configuration, sealed state, keystore, authority roots, and command-family enablement; where a deployment runs both roles on shared host resources, resource controls (rate limits, quotas, or scheduling priority) prevent high-volume Agent Gateway keygen, backup-export, identity-proof, faucet, or transfer workloads from starving producer signing.
- [ ] #9 The design and implementation do not reuse AuthorizationTicket commands, producer ML-DSA keys, or producer arming/network-second-factor state for Agent Gateway signing.
- [ ] #10 High-risk review follows this repo's AGENTS.md roborev matrix rules before merge.
<!-- AC:END -->





## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Created as the 2d-hsm side of 2D `TASK-132.5`. The preferred Agent Gateway signer backend is `2d-hsm` secp256k1 inside a TEE, not Nitrokey NetHSM. NetHSM may remain as a fallback/deferred backend, but Agent Gateway should not be designed around NetHSM key lifecycle or system backups.

The expected host-side pipeline remains similar to the existing bridge signer pattern: local validation -> OPA agent policy -> Vault capability lookup -> signer backend. For `2d-hsm`, this is only the host-side gate. The TEE must still enforce command capabilities, key purpose, role/profile, and minimal spending policy internally because the host/vsock client can be compromised.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Design subtasks TASK-7.1 through TASK-7.5 and TASK-7.7 are complete or explicitly superseded.
- [ ] #2 TASK-7.6, or narrower implementation tasks replacing it, is complete before TASK-7 is marked Done; production fund custody remains blocked unless TASK-7.7's anti-rollback mechanism or funding block is active.
- [ ] #3 Protocol/spec updates are written and reviewed.
- [ ] #4 Implementation tasks preserve the invariant that no command path exposes plaintext private keys or generic unrestricted digest signing.
- [ ] #5 Roborev matrix/compact evidence is recorded per AGENTS.md for high-risk changes.
- [ ] #6 Final summary added before marking Done.
<!-- DOD:END -->
