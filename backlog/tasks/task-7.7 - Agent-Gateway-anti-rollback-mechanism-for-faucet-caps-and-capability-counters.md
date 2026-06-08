---
id: TASK-7.7
title: Agent Gateway anti-rollback mechanism for faucet caps and capability counters
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-08 07:10'
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
  - backlog/docs/agent-gateway-anti-rollback.md
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
- [x] #1 The design selects one anti-rollback mechanism for production fund custody: external append-only ledger, remote monotonic counter, operator-signed boot authorization with high-water marks (which must itself be replay-resistant — bound to a platform/hardware monotonic counter or a remote challenge-response — so a host cannot replay a stale sealed state together with its matching stale authorization), or another reviewed equivalent.
- [x] #2 The mechanism covers administrative capability replay counters and faucet cumulative spend counters.
- [x] #3 Restore and failover procedures seed counter high-water marks from authenticated material and never reset counters to zero from a stale backup.
- [x] #4 Active-active clones of one faucet key remain prohibited unless the mechanism provides a global spend/capability ledger shared by every live clone.
- [x] #5 If no production anti-rollback mechanism is available, the task defines the code/config/runbook gate that blocks material production fund custody for Agent Gateway faucet and transfer wallets.
- [x] #6 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design delivered in backlog/docs/agent-gateway-anti-rollback.md (design-only; impl TASK-7.6). Platform finding: SEV-SNP has NO per-enclave hardware monotonic counter (reported_tcb platform-wide; guest_svn not enforced-monotonic; no vTPM NV counter; snp-derive-root is a key) -> freshness anchor MUST be external. Selected mechanism: Option A = remote monotonic counter + epoch-lease (freshness_epoch in pq-seal-v1 AAD; on start reject blob with epoch < anchor-current; per-dispense bump+seal-before-emit). Default lease=1 synchronous (zero replay window); lease=N is an explicit per-treasury policy for low-value faucets (bounded loss). Covers BOTH capability counters AND faucet cumulative/lifetime spend + strict recovery counter (AC#2). Boot/restore seed from authenticated anchor marks, never zero/stale (AC#3). Active-active prohibited unless Option B (global append-only ledger), documented as the HA upgrade (AC#4). AC#5 production-funding gate: 2-layer fail-closed (Nix build assertion mirroring productionMode + Rust dispatch block on fund commands) + hard-block-default + a single audited opt-out recording the verbatim TASK-7.2 AC#10 residual ack + runbook. Anchor under separation-of-duties + itself anti-rollback-durable (quorum preferred high-value); fail-closed on anchor partition. AC #1-#5 addressed by this design; AC #6 (roborev) run pre-merge.

Roborev evidence (AC#6): 3x3 vendor matrix (codex+gemini+claude-code x security/design/default) on 524c8d8 -> 3 HIGH + 3 MED; consolidated via roborev compact (job 7704). Resolved: anchor mutual-authentication (signed nonce-bound anchor responses vs pinned/sealed anchor root — was one-directional); lease=N is NOT bounded naively -> requires anchor-visible lease IDs + consumed sub-cursor, admin/recovery/config always lease=1, production default lease=1; Nix gate enum drops standalone operator-signed-boot (replay-vulnerable); Rust fund-block adds AGENT_K1_CONFIGURE_TREASURY sub-ops; opt-out is measured/sealed (not host-settable) with defined relaxed layers.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Anti-rollback design or production-funding block is documented.
- [ ] #2 Failure and rollback scenarios are covered by tests, vectors, or reviewed runbook validation where code does not yet exist.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
