---
id: TASK-32
title: Bind hard-fork AuthorizationTicket contextHash to producer epoch
status: To Do
assignee: []
created_date: '2026-06-23 23:34'
updated_date: '2026-06-24 00:42'
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
priority: high
ordinal: 33500
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
- [ ] #1 Hard-fork AuthorizationTicket contextHash semantics explicitly bind the ticket to the intended producer authorization epoch.
- [ ] #2 Canonical ticketHash preimage remains unambiguous and has updated test vectors/examples for enclave and Solidity implementations.
- [ ] #3 2d-hsm signing service/enclave ticket generation is updated to compute the same contextHash/preimage.
- [ ] #4 Replay/withheld-ticket scenario A -> B -> A is covered: a hard-fork ticket signed in the old A epoch cannot activate in a later A epoch.
- [ ] #5 Docs call out compatibility/migration impact for existing Solidity reference and native precompile.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-32 progress (2026-06-23):

AC#1 (contextHash binds to producer epoch): DONE — spec updated (§4 field definition + §8 verification rule). contextHash for HARD_FORK now includes producerEpochBinding = keccak256(pqPubkey || currentProducerActivatedAtHeight).

AC#2 (updated test vectors): PARTIAL — spec updated. Rust test vectors use opaque context_hash values (the enclave doesn't compute contextHash, the caller does). The contextHash derivation needs its own Rust↔Solidity consistency check (separate from the ticketHash forge cross-check) — deferred.

AC#3 (2d-hsm enclave updated): N/A — context_hash is caller-provided opaque bytes32 (AuthorizationTicketPayload.context_hash, lib.rs:875). The enclave signs whatever contextHash it receives; the CALLER must compute it with the epoch binding. No enclave code change needed.

AC#4 (A→B→A replay covered): NOT MET — the PRIMARY enforcement (contextHash recompute in _submitHardForkActivation) is NOT implemented in 2d-solidity RecoveryTicket.sol. The landed code (PR #18) treats contextHash as opaque bytes32 (line 281: only checks non-zero). The _producerEpochId storage scoping (line 439) keys off SUBMISSION-TIME producer, not signing-time epoch — so a withheld epoch-1 ticket submitted fresh in epoch-3 passes all checks and activates. BLOCKED on 2d-solidity task-10 implementing contextHash recompute+verify.

AC#5 (compatibility/migration docs): DONE — spec §8 documents the gap (⚠ NOT YET IMPLEMENTED) + 2d-solidity task-10 follow-up requirement.

Bug fix included: forge cross-check unlink was placed AFTER forge output (deleting fresh output before read) — moved to BEFORE the forge call so the Rust↔Solidity preimage cross-check actually executes.
<!-- SECTION:NOTES:END -->
