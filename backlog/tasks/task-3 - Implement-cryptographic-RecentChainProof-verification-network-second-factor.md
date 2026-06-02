---
id: TASK-3
title: Implement cryptographic RecentChainProof verification (network second factor)
status: To Do
assignee: []
created_date: '2026-06-02 07:48'
updated_date: '2026-06-02 07:48'
labels:
  - security
  - tee
  - vsock
  - high-risk
dependencies:
  - TASK-2
references:
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - impl/rust/enclave-protocol/src/lib.rs
documentation:
  - AGENTS.md
priority: high
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
## Context

TASK-2 Phase 1 delivered structural gating for `ARM_FOR_PRODUCTION` and HARD_FORK_ACTIVATION signing (`RecentChainProof` typed fields, monotonicity, armed state, pubkey match, activation_height ordering). Roborev matrices on `cc8446f` flagged a **production blocker**: structural checks alone do not enforce "network as cryptographic second factor" — a compromised host can fabricate proofs with empty `proof_data`.

This task closes that gap in `enclave-protocol` before hard-fork or production arming signatures are trusted.

## Goal

Implement real cryptographic verification of `RecentChainProof` inside the TEE signing service reference crate, at both **arming** and **hard-fork sign** time, fail-closed.

## Scope

- Proof format design (minimal MVP verifiable by enclave without full node)
- Rust implementation replacing/extending `validate_recent_chain_proof`
- Integration with `arm_for_production` and `handle_sign_authorization_ticket_with_state` (type=1)
- Tests + spec updates
- High-risk review (3:3 + compact)

## Out of scope (initial increment)

- Full Ethereum-style light client inside enclave
- Elixir host shim (TASK-2 Phase 4)
- On-chain precompile changes
- Real ML-DSA signing (TASK-1)

## Related

- **Depends on:** TASK-2 (vsock API + Phase 1 state machine)
- **Feeds into:** TASK-1 AC #15 (network second factor in TEE)
- **Spec:** `backlog/docs/vsock-api-wire-format-spec-draft.md` § Phase 1 vs production readiness
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Specify the cryptographic proof format(s) accepted in RecentChainProof.proof_data (MVP: document + implement at least one verifiable format)
- [ ] #2 validate_recent_chain_proof verifies proof_data cryptographically at ARM_FOR_PRODUCTION (fail closed on empty/invalid proof)
- [ ] #3 Hard-fork (type=1) signing re-verifies proof at sign time; rejects if proof no longer valid
- [ ] #4 Negative tests: empty proof_data, missing signature_from_recent_producer, forged heights cannot arm or sign hard-fork
- [ ] #5 Re-arm policy requires strictly fresher proof than previous session (or document explicit Phase-2 policy)
- [ ] #6 Update vsock spec + TASK-2 notes: remove 'not production-ready' caveat once crypto gate is implemented
- [ ] #7 Full 3:3 roborev matrix + compact on the crypto verification increment (high-risk per AGENTS.md)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Created 2026-06-02 after cc8446f / 1ae4773 matrices. Production blocker explicitly tracked in TASK-2 implementation notes.
<!-- SECTION:NOTES:END -->
