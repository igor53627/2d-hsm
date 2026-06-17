---
id: TASK-22
title: >-
  Publish byte-exact 0x40 golden vectors: request envelope + §10.5 capability
  preimage + response bodies
status: To Do
assignee: []
created_date: '2026-06-16 21:30'
labels:
  - agent-gateway
  - wire-vectors
  - cross-repo
  - task-7
dependencies: []
priority: high
ordinal: 26000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Downstream 2d (Chain.AgentGateway.SignerProtocol, TASK-132.5.2 slices 2/3) cannot byte-validate its Elixir CBOR codec against the enclave. Today testvectors/agent-gateway/ pins ONLY preimage/hash/sig artifacts (ordinary_tx_v1, identity_proof_v1, tron), sealed keystore blobs, and one boot-relay 0x41 frame — NO 0x40 request-envelope vector, NO §10.5 capability signed-preimage vector, NO response-body vector. vsock-api-wire-format-spec-draft.md §11 'Next Steps' still lists 'write concrete CBOR test vectors for the three most important messages'; the file is still 'Draft v0.2'. 2d's capability.ex/envelope.ex are hand-mirrored from agent_capability.rs/agent_dispatch.rs with only partial inline pins (CAP_DOMAIN prefix + 0xAB/0xAC map-header byte). Without frozen cross-language vectors, an Elixir<->Rust CBOR drift (map ordering, integer minimal-encoding, bstr-vs-uint like the just-fixed amount/gas_price u256 bug) is only caught when a live capability is REJECTED 0x40/0x43 AFTER the host already burned a monotonic counter slot under the no-retry policy. Generate vectors from the enclave encoder (the inverse of gen_agent_vectors.exs) and freeze under testvectors/agent-gateway/. Found by the 2026-06-17 cross-repo gap audit (consumer-side TASK-132.5.2).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Frozen byte-exact golden vector for the 0x40 request ENVELOPE (canonical CBOR int-key map keys 1..7: agent_version, opcode, command_domain, request_id, capability, key_ref, payload) under testvectors/agent-gateway/
- [ ] #2 Frozen byte-exact golden vector for the §10.5 CAPABILITY signed preimage (CAP_DOMAIN || canonical-CBOR(keys 1..12)) and the full capability map (keys 1..13), INCLUDING the `treasury_sub_op` contribution to the preimage/payload_binding for a CONFIGURE_TREASURY capability (sub_op-bound — distinct preimage per sub_op 0..=3). The cap must be minted with the **correct authority per sub-op tier** so it validates against the live verifier: sub-ops 0..=2 (set_limits/refill_budget/raise_lifetime_breaker) are admin-tier → signed by `admin_authority_pk` on the admin lane; sub-op 3 (reset_lifetime_breaker) is recovery-tier → signed by `recovery_authority_pk` on the recovery authority's own lane (a wrong-authority cap is rejected 0x43 — see §10.7). Use the established test keys (admin Ed25519 `[7u8;32]`, recovery `[9u8;32]`).
- [ ] #3 Frozen byte-exact golden vectors for response bodies: SIGN_TRANSFER (7-key), SIGN_FAUCET_DISPENSE (8-key, incl. sealed_keystore_blob), PUBLIC_IDENTITY (6-key), CONFIGURE_TREASURY ({1: sealed_keystore_blob}), and the §10.9 AgentError body {1:code,2:reason}
- [ ] #4 Negative 0x40 vectors for AC#7-class TEE-rejection assertions (wrong profile/purpose, non-contiguous counter, bad payload_binding). BEFORE freezing this set, resolve the stray-envelope-key-6 (`key_ref`) on CONFIGURE_TREASURY decision (the decoder currently ACCEPTS+ignores a key_ref on a CONFIGURE envelope — see the TASK-20 residual): either reject `env.key_ref.is_some()` for CONFIGURE as Malformed and ADD the negative vector, or document the ignore and explicitly EXCLUDE that vector — so the frozen negatives match the eventual strict-shape behavior.
- [ ] #5 Wire-format spec promoted past 'Draft v0.2' for the vectored messages, or the vectors README states the exact spec section + commit each vector is frozen against
<!-- AC:END -->
