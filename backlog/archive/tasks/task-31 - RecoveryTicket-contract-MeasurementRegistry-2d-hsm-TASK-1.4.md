---
id: TASK-31
title: RecoveryTicket contract + MeasurementRegistry (2d-hsm TASK-1.4)
status: To Do
assignee: []
created_date: '2026-06-23 20:06'
labels:
  - cross-repo
  - precompile
  - recovery
  - measurement-registry
  - 2d-hsm
dependencies: []
priority: high
ordinal: 33500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cross-repo task from 2d-hsm TASK-1.4. Implement the on-chain side of BlockProducer recovery:

**RecoveryTicket contract** — permissionless recovery ticket format/issuance/activation. Specs:
- `2d-hsm/backlog/docs/permissionless-blockproducer-recovery-tickets.md` (design: reserved 0x2D00...A0 address or a small recovery contract in 2d-solidity)
- `2d-hsm/backlog/docs/authorization-tickets-precompile-spec-draft.md` (detailed: AuthorizationTicket struct, Solidity ABI, proposed precompile address 0x2D00...A0, submission methods, storage layout, reader verification rules)

**MeasurementRegistry** — on-chain whitelist consuming the live-attested TEE measurement + report_data (NOT manifest labels). Reader nodes use this to accept blocks only from registered TEE measurements.

**Dependencies:**
- 2d-hsm TASK-2 (vsock wire format) — Done
- 2d-hsm TASK-5 (production SNP path) — Done
- 2d-hsm TASK-1.2 (SNP attestation verification) — Done

**DoD:** forge test passes + NatSpec + final summary.
<!-- SECTION:DESCRIPTION:END -->
