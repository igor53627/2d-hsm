---
id: TASK-7.3
title: Agent Gateway secp256k1 keygen and public identity
status: Done
assignee: []
created_date: '2026-06-07 00:00'
labels:
  - agent-gateway
  - secp256k1
  - identity
dependencies:
  - TASK-7.1
  - TASK-7.2
references:
  - backlog/docs/agent-gateway-keygen-identity.md
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
  - ../2d/lib/chain/crypto/address.ex
priority: high
ordinal: 7030
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design secp256k1 key generation for `agent_faucet_treasury_k1` and `agent_transfer_k1` purposes, batch transfer-key creation, and public identity derivation compatible with ordinary 2D account addresses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Batch key generation creates enclave-assigned opaque transfer-key refs suitable for 2D Agent Gateway key-pool refill; the host cannot choose or overwrite key refs.
- [x] #2 Treasury key generation creates exactly one configured `agent_faucet_treasury_k1` key ref under a stronger provisioning capability than transfer-key refill; a second active treasury key generation request fails closed unless a later reviewed rotation protocol is active.
- [x] #3 The task references the authoritative 2D secp256k1 public-key encoding and address-derivation vector, then pins a frozen in-repo golden vector before implementing identity behavior.
- [x] #4 Public identity returns canonical public key encoding, derived 20-byte 2D address, key purpose, key ref, and protocol/build metadata; if TASK-7.1 delegates public-key encoding ownership, this task explicitly records the final encoding decision.
- [x] #5 Identity proof signing uses an EIP-191-style non-transaction domain beginning with `0x19`, includes a fresh verifier-provided challenge nonce, cannot sign arbitrary caller bytes, and its non-collision argument is checked against the authoritative 2D ordinary-transaction preimage vector pinned by TASK-7.1 and against future EIP-2718 typed-transaction domains; EIP-2718 disjointness relies on the reserved-and-never-assigned `0x19` transaction-type policy pinned by TASK-7.1 (structural separation from legacy/EIP-155 RLP preimages does not extend to typed transactions because `0x19` is a legal `TransactionType`).
- [x] #6 Test/vector requirements cover address derivation, duplicate/ref collision rejection, key-purpose mismatches, and treasury-vs-transfer generation permissions.
- [x] #7 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design delivered in `backlog/docs/agent-gateway-keygen-identity.md` (design-only; secp256k1
impl is TASK-7.6, signing is TASK-7.4). 7.3 consumes the TASK-7.1 protocol/vectors and TASK-7.2
keystore format and adds: keygen design (opaque **random 32-byte `key_ref`** assigned inside
the enclave; batch `agent_transfer_k1` vs **singleton** `agent_faucet_treasury_k1` with a
stronger provisioning capability + fail-closed second-treasury; atomic seal via 7.2; capacity)
(AC#1/#2); the `AGENT_K1_PUBLIC_IDENTITY` **dual eth+TRON** response and the confirmation that
the canonical pubkey encoding is **uncompressed 65-byte SEC1** (7.1 locked it) (AC#3/#4); the
`AGENT_K1_PROVE_IDENTITY` EIP-191 `0x19` non-collision argument vs eth-RLP / TRON-protobuf /
reserved-EIP-2718-`0x19` (AC#5); and the AC#6 test/vector requirements.

Locked decisions: random 32B `key_ref`; do not block 7.3 on 2D PR #144 (cited as tracked
cross-repo blocking dep for the `0x19` reservation); defer the live signed PROVE_IDENTITY
sample to 7.6; error codes reference the 7.1 §10.9 band; treasury-singleton via entry-list scan.

AC #1–#7 addressed: the roborev 3×3 matrix was run and its findings resolved in-PR — clarified treasury `key_ref` is random 32B (counter = capability counter, not the ref); serialized keygen (single-writer/CAS) so concurrent treasury keygens can't both append; documented the identity-proof trust model (binds by signed address; `key_purpose` non-authoritative); added the anti-oracle error-code mapping; `key_ref` uniqueness check; production-gated identity-proof signing on the 2D `0x19` reservation; updated the high-level design doc's pubkey-encoding line; and set parent TASK-7 → In Progress. **Roborev evidence:** 3×3 vendor matrix (codex+gemini+claude-code × security/design/default) jobs 7497–7505, consolidated via `roborev compact` (jobs 7510→7515); all design findings closed, residual items are documentation/process only.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Keygen and public identity protocol behavior is specified with test/vector requirements for the implementation task.
- [x] #2 The design preserves the invariant that no generated private key is exposed outside the TEE/runtime boundary.
- [x] #3 Final summary added before marking Done.
<!-- DOD:END -->
