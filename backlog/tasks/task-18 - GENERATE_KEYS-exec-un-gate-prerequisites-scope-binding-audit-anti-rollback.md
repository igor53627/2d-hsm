---
id: TASK-18
title: >-
  GENERATE_KEYS exec un-gate prerequisites (scope-binding + audit +
  anti-rollback)
status: To Do
assignee: []
created_date: '2026-06-08 19:05'
labels:
  - agent-gateway
  - security
  - hardening
dependencies:
  - TASK-7.7
priority: high
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
GENERATE_KEYS live execution is implemented behind the off-by-default, release-banned agent-keygen-exec-preview feature (PR #44). Before it can be enabled in production these prerequisites — surfaced by the TASK-7.6.x Full Matrix as blockers for a host-untrusted fund-custody mutation — must land. Until then production verifies the capability then fails closed (AGENT_NOT_CONFIGURED).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 scope_target ↔ sealed-local-enclave-identity binding: bind cap.scope_target to a sealed enclave/fleet id (installed/derived at boot) and byte-compare before mutation, so an 'enclave-scoped' (scope_class=0) cap minted for enclave A cannot be replayed on a clone B (whose counter row for that tuple is empty) to mint a second treasury key — the AC#12 budget-multiplication guard. Enforce command-class scope_target (generate_transfer/generate_faucet) too.
- [ ] #2 AC#14 privileged-op audit record: append an AuditRecord (op, authority, counter, config_version) to candidate.audit in the same sealed commit as GENERATE_KEYS (and every privileged mutation), and enforce last_exported_seq backpressure (fail closed rather than overwrite un-exported entries).
- [ ] #3 Anti-rollback durable commit (TASK-7.7): the in-memory swap currently precedes host persistence, so a host can drop the returned sealed blob, reboot from the prior blob, and replay the one-shot capability to re-mint keys. Wire the freshness_epoch advance against the pinned anchor (or an equivalent durable monotonic anchor / persist-ack commit) so a consumed counter cannot be rolled back. Only then un-gate (remove the release ban / flip the feature on).
<!-- AC:END -->
