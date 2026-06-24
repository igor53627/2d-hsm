---
id: TASK-32
title: Bind hard-fork AuthorizationTicket contextHash to producer epoch
status: Done
assignee: []
created_date: '2026-06-23 23:34'
updated_date: '2026-06-24 19:46'
labels:
  - authorization-ticket
  - 2d-solidity
  - 2d-hsm
  - recovery
  - hard-fork
dependencies: []
references:
  - 'https://github.com/igor53627/2d-solidity/pull/18'
documentation:
  - backlog/docs/authorization-tickets-precompile-spec-draft.md
  - backlog/docs/permissionless-blockproducer-recovery-tickets.md
modified_files:
  - backlog/docs/authorization-tickets-precompile-spec-draft.md
  - impl/rust/enclave-protocol/src/lib.rs
priority: high
ordinal: 33600
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from 2d-solidity PR #18 / TASK-10. The Solidity reference now scopes scheduled hard forks by producer epoch, but the canonical AuthorizationTicket spec still leaves HARD_FORK_ACTIVATION contextHash as fork-spec/measurement/height-oriented. That means a withheld hard-fork ticket signed by producer A can be ambiguous if producer control rotates A -> B -> A. Finalize the cross-repo signed-preimage semantics so HARD_FORK_ACTIVATION tickets commit to the intended producer authorization epoch without diverging between 2d-hsm enclave signing and 2d-solidity/native precompile verification.

Important constraints:
- Do not make a local-only Solidity change that changes the signed preimage without updating 2d-hsm signing/test vectors.
- Preserve the normative abi.encode ticketHash construction from the draft; update field interpretation/contextHash contents rather than introducing an off-spec hash.
- The acceptance scenario is specifically withheld ticket replay across producer epochs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 #1 DONE: contextHash for HARD_FORK includes producerEpochBinding. Spec §4 + §8 updated.
- [ ] #2 #2 PARTIAL: spec updated; Rust↔Solidity contextHash derivation consistency test deferred.
- [ ] #3 #3 N/A: context_hash is caller-provided opaque bytes32; off-enclave caller computes it.
- [ ] #4 #4 DONE: 2d-solidity commit 00e3497 implements _requireHardForkContextHash recompute in _submitHardForkActivation + test_hardForkActivation_rejectsContextHashEpochMismatch + test_hardForkActivation_rejectsWithheldTicketAfterProducerKeyReturns (A→B→A replay). 133 forge tests pass.
- [ ] #5 #5 DONE: spec §8 marks as REQUIRED ENFORCEMENT + documents implementation status.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AC#1 (contextHash binds to producer epoch): DONE — spec updated (§4 + §8). producerEpochBinding = keccak256(abi.encode(pqPubkey, activatedAtHeight)).

AC#2 (updated test vectors): PARTIAL — spec updated. Rust↔Solidity contextHash derivation parity test deferred — MUST land before first real hard-fork ticket. The off-enclave producer (2D task-122) must compute the identical preimage as the Solidity recompute.

AC#3 (2d-hsm enclave): N/A — context_hash is caller-provided opaque bytes32 (lib.rs:875). No enclave code change.

AC#4 (A→B→A replay): DONE — 2d-solidity commit 00e3497 implements _requireHardForkContextHash in _submitHardForkActivation. Tests: test_hardForkActivation_rejectsContextHashEpochMismatch + test_hardForkActivation_rejectsWithheldTicketAfterProducerKeyReturns. 133 forge tests pass.

AC#5 (compat docs): DONE — spec §8 is REQUIRED ENFORCEMENT, now ✅ IMPLEMENTED (2d-solidity TASK-10).

Bug fix: forge cross-check unlink moved BEFORE forge call (was no-op).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Spec + Solidity implementation done. AC#4 MET (2d-solidity 00e3497). LIVE OBLIGATION: the off-enclave producer (2D BlockProducer signing path, task-122) MUST compute contextHash = keccak256(abi.encode(forkSpecHash, measurement, activationHeight, keccak256(abi.encode(pqPubkey, activatedAtHeight)))) — the Solidity contract hard-reverts ContextHashEpochMismatch on any divergence. AC#2 (Rust↔Solidity contextHash derivation parity test) is deferred but MUST land before the first real hard-fork ticket: without it, a preimage divergence between the producer's contextHash and the contract's recompute silently rejects all legitimate hard-fork tickets. Tracked: 2d task-122 owns the producer signing path; the parity vector is a cross-repo consistency obligation on whoever wires the hard-fork ticket generation.
<!-- SECTION:FINAL_SUMMARY:END -->
