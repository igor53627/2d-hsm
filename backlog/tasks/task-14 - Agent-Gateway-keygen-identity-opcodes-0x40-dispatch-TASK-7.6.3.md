---
id: TASK-14
title: Agent Gateway keygen + identity opcodes + 0x40 dispatch (TASK-7.6.3)
status: To Do
assignee: []
created_date: '2026-06-08 08:09'
labels:
  - agent-gateway
  - implementation
dependencies: []
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.3 + the deferred 0x40 dispatch wiring. Add AgentGateway Command/Response variants + wire.rs CBOR helpers; route opcodes AGENT_K1_GENERATE_KEYS(1), PUBLIC_IDENTITY(2), PROVE_IDENTITY(3) (replace fail-closed stub at lib.rs:1342). GENERATE_KEYS: opaque random key_ref, treasury singleton, atomic counter+entry seal. PUBLIC_IDENTITY dual eth+TRON. PROVE_IDENTITY EIP-191 0x19 + verifier nonce byte-exact vs identity_proof_v1. Producer/agent profile cross-rejection; collapsed error oracles. Depends on 7.6.1, 7.6.2.
<!-- SECTION:DESCRIPTION:END -->
