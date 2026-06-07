---
id: TASK-7.1
title: Agent Gateway protocol opcodes and domain separation
status: In Progress
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
- [x] #1 The vsock wire spec completes the Agent Gateway command-namespace section, building on the already-softened scope statement that allows a separate Agent Gateway secp256k1 path.
- [x] #2 The wire spec first decides the outer/inner split for Agent Gateway framing. The preferred MVP is one outer Agent Gateway envelope `MessageType` under frame v1 with an inner agent-command version/opcode; if a frame-version bump or outer numeric range is chosen instead, the spec must justify the compatibility tradeoff.
- [x] #3 Unknown Agent Gateway versions and commands fail closed.
- [x] #4 Command payloads include explicit domain, role/profile, request id, and key ref or batch id where applicable.
- [x] #5 Producer-profile signers reject Agent Gateway commands, and Agent Gateway-profile signers reject producer and AuthorizationTicket commands before touching command-specific state.
- [x] #6 Privileged commands require a TEE-verified signed administrative capability that binds command-specific payload hash or exact command parameters; host-side Vault/OPA authorization alone is not accepted by the enclave.
- [x] #7 The wire spec pins the administrative/recovery capability signature algorithm, public-key encoding, and trust-root key format.
- [x] #8 The wire spec reserves a privileged treasury-configuration command with monotonic config versioning and explicit sub-operations for set-limits, budget refill, lifetime-breaker raise, and lifetime-breaker reset, each mapped to the required treasury-admin or recovery/quorum capability tier.
- [x] #9 Administrative capability trust-root provisioning and contiguous monotonic-counter replay rejection are specified per `(authority, environment_identifier, scope_class, scope_target)` counter space; expiry timestamps and unbounded nonce sets are not used for replay protection.
- [x] #10 `environment_identifier` encoding, length bounds, allowed characters, and canonical comparison rules are specified.
- [x] #11 Administrative capabilities bind chain id, environment identifier, target enclave id or explicit fleet-wide marker, command scope, monotonic counter, and recovery/quorum counter-resync semantics; resync cannot replay to roll a scope backward and either targets a counter greater than the enclave's highest known value or uses an independent strict recovery counter.
- [x] #12 Treasury budget-changing capabilities are enclave-scoped unless a global remote monotonic ledger is specified; fleet-wide capabilities cannot multiply a single faucet key's spend budget across cloned TEEs.
- [x] #13 TASK-7.1 pins the authoritative 2D ordinary-transaction preimage as a frozen in-repo golden vector, not only as a live sibling-repo reference, for TASK-7.3 and TASK-7.4 to consume.
- [x] #14 TASK-7.1 pins the canonical public-key encoding used on the wire for Agent Gateway public identity responses, or explicitly records that TASK-7.3 owns the final choice.
- [x] #15 Identity-proof challenge signing uses an EIP-191-style non-transaction domain beginning with `0x19`, plus chain id, environment identifier, key ref, public key/address, and verifier-provided challenge nonce bound into the signed structure; the verifier, not the TEE, owns nonce freshness, and TASK-7.3 owns the non-collision proof against this TASK-7.1-pinned transaction vector and against future EIP-2718 typed transactions. Disjointness from legacy/EIP-155 RLP preimages is structural (the `0x19` prefix cannot begin an RLP list whose first byte is `>= 0xc0`); disjointness from EIP-2718 is not, because `0x19` is a legal `TransactionType` byte, so this AC also pins the constraint that 2D permanently reserves and never assigns typed-transaction type `0x19`, tracked by a matching reservation acceptance criterion on the 2D side (TASK-132.5 family) because the enclave cannot enforce a 2D type assignment.
- [x] #16 TASK-7.1 explicitly decides whether `AGENT_K1_PUBLIC_IDENTITY` and `AGENT_K1_PROVE_IDENTITY` require an authenticated read capability or are exposed as local low-privilege identity commands.
- [x] #17 Administrative authority rotation/revocation semantics are specified, including counter-scope migration or full re-provisioning as the documented fallback.
- [x] #18 Default `scope_class` is specified for each non-financial privileged command, including transfer-refill key generation and backup export; the spec also states whether commands in the same scope share one strictly ordered counter stream or are split by command-class scope targets.
- [x] #19 Structured error response codes and information-disclosure policy are specified for malformed requests, key-purpose mismatch, bad capability, and cap-exceeded cases.
- [x] #20 The chosen framing model reserves either a single outer Agent Gateway envelope `MessageType` plus inner opcodes, or an explicitly bounded outer numeric range; both normal decode and peek/routing helpers fail closed or classify agent opcodes correctly without falling back to producer message types.
- [x] #21 Test/vector requirements cover producer-command rejection for agent keys, agent-command rejection for producer keys, identity-proof-vs-transfer cross-domain oracle rejection, and existing producer frame decode compatibility after MessageType additions.
- [x] #22 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Delivered:
- **Spec:** new §10 "Agent Gateway command namespace (secp256k1)" in `backlog/docs/vsock-api-wire-format-spec-draft.md` — framing (outer `MessageType 0x40` under frame v1, inner agent_version+opcode; band `0x40..0x4F` reserved); inner envelope + role/profile gate; opcode table 1–8 (+ reserved 9 `AGENT_K1_SIGN_TRON_TRANSFER`); per-command payloads; **Ed25519** admin/recovery capability wire format (signed CBOR map + `payload_binding` + domain prefix + sealed trust roots); `(authority, environment_identifier, scope_class, scope_target)` contiguous-counter scheme + env-id encoding + forward-only recovery resync + authority rotation; treasury config sub-ops; EIP-191 `0x19` identity proof + **low-privilege** read policy; structured error band `0x40–0x46` with anti-oracle collapsing; test/vector requirements.
- **Golden vectors:** `impl/rust/enclave-protocol/testvectors/agent-gateway/` — frozen eth EIP-155 ordinary-tx preimage/hash/sig/address (`chain_id=11565`), reserved TRON-protobuf vector, EIP-191 identity-proof preimage, dual eth/TRON keys, 3-way domain-separation witnesses. Generated authoritatively from 2D's own crypto and self-checked by signature recovery; generator + README checked in for reproducibility.
- **Fail-closed routing (AC#20):** fixed the latent fail-**open** `peek_msg_type_from_frame` (defaulted unknown types to `GetMeasurement`); now returns `Option`, classifies `0x40`, and error frames echo the raw type byte. Tests added (peek fail-closed, producer backward-compat, agent-frame recognized-but-fail-closed, raw-byte echo); full crate `cargo test` green.

Decisions recorded: capabilities **Ed25519**; identity reads **low-privilege**; canonical pubkey **uncompressed 65-byte SEC1**; **eth-surface MVP, TRON reserved** (unified-account model).

Cross-repo follow-up: 2D (TASK-132.5 family) must carry an AC permanently reserving EIP-2718 transaction-type `0x19` (the enclave cannot enforce a 2D type assignment).

AC #1–#22 addressed: the roborev 3×3 matrix (codex + gemini + claude-code × security / design / default, 9 cells) was run on this branch and its findings resolved in-PR — capability Ed25519 signature transmission (key 13), per-opcode authorization table (which opcodes require capability key 5), verify-order opcode/sub-op/request_id equality, recovery-resync disambiguation, `payload_binding` tuple, generator portability (`__DIR__`) + pinned 2D commit, and per-opcode schema ownership.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Spec updates are committed.
- [x] #2 Protocol tests or golden vectors cover the new commands.
- [x] #3 Final summary added before marking Done.
<!-- DOD:END -->
