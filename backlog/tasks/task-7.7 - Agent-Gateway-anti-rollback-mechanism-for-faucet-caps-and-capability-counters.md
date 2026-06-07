---
id: TASK-7.7
title: Agent Gateway anti-rollback mechanism for faucet caps and capability counters
status: To Do
assignee: []
created_date: '2026-06-07 00:00'
labels:
  - agent-gateway
  - tee
  - anti-rollback
  - security
dependencies:
  - TASK-7.1
  - TASK-7.2
  - TASK-7.4
references:
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
priority: high
ordinal: 7070
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define the production anti-rollback mechanism for Agent Gateway sealed replay counters and faucet spend caps. Standard sealed storage gives confidentiality and integrity but cannot by itself stop a compromised host from rolling sealed state back, so production fund custody needs an external anti-rollback authority or an explicit funding block.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The design selects one anti-rollback mechanism for production fund custody: external append-only ledger, remote monotonic counter, operator-signed boot authorization with high-water marks, or another reviewed equivalent.
- [ ] #2 The mechanism covers administrative capability replay counters and faucet cumulative spend counters.
- [ ] #3 Restore and failover procedures seed counter high-water marks from authenticated material and never reset counters to zero from a stale backup.
- [ ] #4 Active-active clones of one faucet key remain prohibited unless the mechanism provides a global spend/capability ledger shared by every live clone.
- [ ] #5 If no production anti-rollback mechanism is available, the task defines the code/config/runbook gate that blocks material production fund custody for Agent Gateway faucet and transfer wallets.
- [ ] #6 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Anti-rollback design or production-funding block is documented.
- [ ] #2 Failure and rollback scenarios are covered by tests, vectors, or reviewed runbook validation where code does not yet exist.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
