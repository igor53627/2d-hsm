---
id: TASK-7.6
title: Implement Agent Gateway secp256k1 signer backend
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-24 21:53'
labels:
  - agent-gateway
  - secp256k1
  - implementation
  - tee
dependencies:
  - TASK-7.1
  - TASK-7.2
  - TASK-7.3
  - TASK-7.4
  - TASK-7.5
  - TASK-7.7
references:
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
priority: high
ordinal: 7060
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implementation placeholder for the reviewed Agent Gateway secp256k1 signer backend. This task may be split into narrower implementation tasks before code begins; it exists so the TASK-7 umbrella cannot be marked complete after design-only subtasks.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Implementation follows the reviewed TASK-7.1 through TASK-7.5 designs or explicitly supersedes them with reviewed follow-up tasks.
- [ ] #2 Before any code begins, TASK-7.6 is split into narrower implementation child tasks for protocol framing, keystore/backup, keygen/identity, signing/caps, and host integration; keeping them together requires explicit roborev approval that the implementation is small enough for one review.
- [ ] #3 Existing producer commands remain compatible unless the reviewed vsock spec intentionally bumps protocol version.
- [ ] #4 Agent commands enforce key purpose, structured signing, administrative capability verification, replay rejection, backup opacity, and no plaintext private-key export.
- [ ] #5 secp256k1/address/signature golden vectors match the authoritative 2D ordinary-account vectors.
- [ ] #6 `AGENT_KEYSTORE_RESTORE_BACKUP` is either implemented according to TASK-7.2 or reserved as a fail-closed unsupported command with restore execution deferred to a named follow-up task.
- [ ] #7 Production fund custody is blocked by code/config/runbook gate per TASK-7.7 until the anti-rollback mechanism is implemented and reviewed.
- [ ] #8 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-7.6 is an implementation umbrella and should normally be split before code starts. Its ACs are umbrella-level invariants that replacement child tasks must preserve: producer compatibility, no plaintext private-key export, no generic digest signing, key-purpose enforcement, capability replay rejection, backup opacity, and 2D golden-vector compatibility. Concrete protocol, keystore, keygen, signing, and host-integration work should migrate into narrower child tasks unless roborev explicitly approves one small implementation PR.

REOPENED (compact-10268): TASK-15 (faucet/transfer signing impl) and TASK-16 (host integration + funding gate) are still To Do. These are implementation children of TASK-7.6. The design sub-tasks 7.1-7.5 + 7.7 are Done; the implementation sub-tasks (TASK-12/13/14 sealed keystore + keygen/identity + 0x40 dispatch) are Done; but the faucet/transfer signing handlers + the production-funding gate are not. TASK-7.6 stays In Progress until TASK-15/16 land or are explicitly superseded.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All implementation sub-tasks Done: 7.1-7.5 (design), TASK-12 (primitives), TASK-13 (sealed keystore + backup), TASK-14 (keygen + identity + 0x40 dispatch), TASK-15 (transfer + faucet + configure), TASK-7.7 (anti-rollback). Only remaining child: TASK-16 (host integration + production-funding gate).
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass for protocol parsing, keygen, identity proof, signing rejection cases, backup export opacity, and capability replay rejection.
- [ ] #2 No command path exposes plaintext private keys or generic unrestricted digest signing.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
