---
id: TASK-7.1
title: Agent Gateway protocol opcodes and domain separation
status: To Do
assignee: []
created_date: '2026-06-07 00:00'
labels:
  - agent-gateway
  - protocol
  - tee
dependencies:
  - TASK-2
  - TASK-5
  - TASK-6
references:
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - ../2d/lib/chain/block_executor.ex
  - ../2d/lib/chain/crypto/address.ex
  - ../2d/lib/chain/crypto/envelope.ex
priority: high
ordinal: 7010
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Allocate versioned Agent Gateway wire commands for secp256k1 key generation, public identity, identity proof, structured transfer signing, faucet treasury dispense signing, encrypted backup export, and backup restore reservation. Agent commands must be separate from producer and AuthorizationTicket commands.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The vsock wire spec completes the Agent Gateway command-namespace section, building on the already-softened scope statement that allows a separate Agent Gateway secp256k1 path.
- [ ] #2 The wire spec first decides the outer/inner split for Agent Gateway framing. The preferred MVP is one outer Agent Gateway envelope `MessageType` under frame v1 with an inner agent-command version/opcode; if a frame-version bump or outer numeric range is chosen instead, the spec must justify the compatibility tradeoff.
- [ ] #3 Unknown Agent Gateway versions and commands fail closed.
- [ ] #4 Command payloads include explicit domain, role/profile, request id, and key ref or batch id where applicable.
- [ ] #5 Producer-profile signers reject Agent Gateway commands, and Agent Gateway-profile signers reject producer and AuthorizationTicket commands before touching command-specific state.
- [ ] #6 Privileged commands require a TEE-verified signed administrative capability that binds command-specific payload hash or exact command parameters; host-side Vault/OPA authorization alone is not accepted by the enclave.
- [ ] #7 The wire spec pins the administrative/recovery capability signature algorithm, public-key encoding, and trust-root key format.
- [ ] #8 The wire spec reserves a privileged treasury-configuration command with monotonic config versioning and explicit sub-operations for set-limits, budget refill, lifetime-breaker raise, and lifetime-breaker reset, each mapped to the required treasury-admin or recovery/quorum capability tier.
- [ ] #9 Administrative capability trust-root provisioning and contiguous monotonic-counter replay rejection are specified per `(authority, environment_identifier, scope_class, scope_target)` counter space; expiry timestamps and unbounded nonce sets are not used for replay protection.
- [ ] #10 `environment_identifier` encoding, length bounds, allowed characters, and canonical comparison rules are specified.
- [ ] #11 Administrative capabilities bind chain id, environment identifier, target enclave id or explicit fleet-wide marker, command scope, monotonic counter, and recovery/quorum counter-resync semantics; resync cannot replay to roll a scope backward and either targets a counter greater than the enclave's highest known value or uses an independent strict recovery counter.
- [ ] #12 Treasury budget-changing capabilities are enclave-scoped unless a global remote monotonic ledger is specified; fleet-wide capabilities cannot multiply a single faucet key's spend budget across cloned TEEs.
- [ ] #13 TASK-7.1 pins the authoritative 2D ordinary-transaction preimage as a frozen in-repo golden vector, not only as a live sibling-repo reference, for TASK-7.3 and TASK-7.4 to consume.
- [ ] #14 TASK-7.1 pins the canonical public-key encoding used on the wire for Agent Gateway public identity responses, or explicitly records that TASK-7.3 owns the final choice.
- [ ] #15 Identity-proof challenge signing uses an EIP-191-style non-transaction domain beginning with `0x19`, plus chain id, environment identifier, key ref, public key/address, and verifier-provided challenge nonce bound into the signed structure; the verifier, not the TEE, owns nonce freshness, and TASK-7.3 owns the non-collision proof against this TASK-7.1-pinned transaction vector and against future EIP-2718 typed transactions. Disjointness from legacy/EIP-155 RLP preimages is structural (the `0x19` prefix cannot begin an RLP list whose first byte is `>= 0xc0`); disjointness from EIP-2718 is not, because `0x19` is a legal `TransactionType` byte, so this AC also pins the constraint that 2D permanently reserves and never assigns typed-transaction type `0x19`, tracked by a matching reservation acceptance criterion on the 2D side (TASK-132.5 family) because the enclave cannot enforce a 2D type assignment.
- [ ] #16 TASK-7.1 explicitly decides whether `AGENT_K1_PUBLIC_IDENTITY` and `AGENT_K1_PROVE_IDENTITY` require an authenticated read capability or are exposed as local low-privilege identity commands.
- [ ] #17 Administrative authority rotation/revocation semantics are specified, including counter-scope migration or full re-provisioning as the documented fallback.
- [ ] #18 Default `scope_class` is specified for each non-financial privileged command, including transfer-refill key generation and backup export; the spec also states whether commands in the same scope share one strictly ordered counter stream or are split by command-class scope targets.
- [ ] #19 Structured error response codes and information-disclosure policy are specified for malformed requests, key-purpose mismatch, bad capability, and cap-exceeded cases.
- [ ] #20 The chosen framing model reserves either a single outer Agent Gateway envelope `MessageType` plus inner opcodes, or an explicitly bounded outer numeric range; both normal decode and peek/routing helpers fail closed or classify agent opcodes correctly without falling back to producer message types.
- [ ] #21 Test/vector requirements cover producer-command rejection for agent keys, agent-command rejection for producer keys, identity-proof-vs-transfer cross-domain oracle rejection, and existing producer frame decode compatibility after MessageType additions.
- [ ] #22 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Spec updates are committed.
- [ ] #2 Protocol tests or golden vectors cover the new commands.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
