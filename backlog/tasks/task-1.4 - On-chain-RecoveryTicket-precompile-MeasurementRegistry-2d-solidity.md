---
id: TASK-1.4
title: On-chain RecoveryTicket precompile + MeasurementRegistry (2d-solidity)
status: In Progress
assignee: []
created_date: '2026-06-06 15:58'
updated_date: '2026-06-24 19:50'
labels:
  - on-chain
  - solidity
  - cross-repo
dependencies: []
parent_task_id: TASK-1
priority: medium
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cross-repo (2d-solidity). Implement the on-chain side: RecoveryTicket format/issuance/activation precompile (spec: permissionless-blockproducer-recovery-tickets.md, authorization-tickets-precompile-spec-draft.md) and a MeasurementRegistry whitelist consuming the live-attested TEE measurement + report_data (NOT manifest labels). Maps to TASK-1 #13.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Cross-repo status (2026-06-24): Solidity reference contracts DONE (2d-solidity task-10, PR #18 + 00e3497). 2D precompile structure EXISTS (authorization_tickets.ex) but ML-DSA-65 verify NIF not wired — precompile runs in :mock mode that rejects all tickets. The hard blocker is 2D TASK-122 AC#2 (verify_mldsa65/3 NIF).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
PARTIAL — cannot close. Status by component:
- 2d-solidity contracts (RecoveryTicket.sol + MeasurementRegistry.sol + contextHash epoch binding): DONE (PR #18 + commit 00e3497, 133 forge tests pass)
- 2D Authorization Tickets precompile structure + logic: EXISTS (lib/chain/precompiles/authorization_tickets.ex) but runs in :mock mode
- ML-DSA-65 verify NIF: NOT WIRED (Chain.Crypto.PQ.verify_mldsa65/3 raises — 2D TASK-122 AC#2). The precompile defaults to :mock which REJECTS all tickets (fail-closed safety invariant). Until the NIF lands, no authorization ticket can be accepted on-chain.
- SNP attestation verification in precompile: interface-only (IMeasurementVerifier), real verifier not implemented.

BLOCKER: 2D TASK-122 AC#2 (ML-DSA-65 verify NIF) is the hard blocker. Without it, the entire authorization tickets system (recovery + hard fork) is inert on-chain.

Cross-repo mapping:
- 2d-solidity task-10: DONE (Solidity reference contracts)
- 2D task-122: IN PROGRESS (precompile structure exists, NIF not wired)
- 2d-hsm TASK-32: DONE (contextHash epoch binding spec + Solidity enforcement)
<!-- SECTION:FINAL_SUMMARY:END -->
