---
id: TASK-7.7
title: Agent Gateway anti-rollback mechanism for faucet caps and capability counters
status: Done
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-08 08:02'
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
Design delivered in backlog/docs/agent-gateway-anti-rollback.md (design-only; impl TASK-7.6). Platform: SEV-SNP has NO per-enclave hardware monotonic counter -> external anchor required. Selected Option A = remote monotonic counter + epoch-lease: freshness_epoch in the pq-agent-keystore-v1 ENCRYPTED BODY (format extension per 7.2 AC#16; NOT the pq-seal-v1 AAD); mutual-authenticated anchor handshake (agent-domain SNP report_data + Ed25519-signed anchor response vs pinned anchor_root); reject blob whose epoch != anchor-current (both < stale and > anchor-rollback fail closed); per-dispense bump+seal-before-emit. Default lease=1; a NAIVE lease=N is UNBOUNDED, so a safe lease=N requires anchor-visible per-spend consumed-cursor ack before emit, and admin/recovery/config advances are always lease=1; when the anchor is unavailable ALL fund custody fails closed (no offline window). Crash reconcile: the anchor records authoritative post-op marks and the enclave ADOPTS them (never guesses non-emission). Covers cap counters + faucet cumulative/lifetime spend + strict recovery counter (AC#2); boot/restore seed from authenticated marks never-zero (AC#3); active-active operator-procedural under A, enforced only by Option B global ledger (AC#4); AC#5 gate = 2-layer fail-closed (Nix assertion with explicit opt-out term + derived enabled; Rust block on rollback-sensitive commands, SIGN_TRANSFER excluded, EXPORT/RESTORE included) + hard-block-default + measured/sealed audited opt-out. Anchor under separation-of-duties + anti-rollback-durable; liveness-DoS is an accepted availability residual.

Roborev evidence (AC#6): 3x3 matrix on 524c8d8 -> 3 HIGH + 3 MED (job 7704); /code-review skill -> 40 candidates -> 15 findings; 9 PR bot comments resolved/replied (CodeRabbit confirmed); post-merge compact -> 3 more (anchor-unavailable, reconcile non-emission proof, stale notes) resolved.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Design delivered in backlog/docs/agent-gateway-anti-rollback.md (PR #33, squash e5d3213). Production anti-rollback for sealed replay counters + faucet spend caps. Platform: SEV-SNP has NO per-enclave hardware monotonic counter -> external anchor required. Selected Option A = remote monotonic counter + epoch-lease: freshness_epoch in the pq-agent-keystore-v1 encrypted body (format extension, version bump per 7.2 AC#16); mutual-authenticated anchor handshake (agent-domain SNP report_data + Ed25519-signed anchor response vs pinned anchor_root); reject blob with epoch < anchor-current AND > anchor-current (fail closed); per-dispense bump+seal-before-emit; default lease=1, safe lease=N only via per-spend anchor-ack (count-bounded, never time); crash-reconcile keyed by request_id. Covers cap counters + faucet cumulative/lifetime spend + strict recovery counter (AC#2); boot/restore seed from authenticated marks never-zero (AC#3); active-active operator-procedural under A, enforced only by Option B global ledger (AC#4); AC#5 funding gate = 2-layer fail-closed (Nix assertion with explicit opt-out term + derived enabled, Rust block on rollback-sensitive commands with SIGN_TRANSFER excluded/EXPORT+RESTORE included) + hard-block-default + measured/sealed audited opt-out. Verified by roborev 3x3 + compact + the /code-review skill (40->15) + all 9 PR bot comments resolved/replied (CodeRabbit confirmed). Implementation is TASK-7.6.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Anti-rollback design or production-funding block is documented.
- [x] #2 Failure and rollback scenarios are covered by tests, vectors, or reviewed runbook validation where code does not yet exist.
- [x] #3 Final summary added before marking Done.
<!-- DOD:END -->
