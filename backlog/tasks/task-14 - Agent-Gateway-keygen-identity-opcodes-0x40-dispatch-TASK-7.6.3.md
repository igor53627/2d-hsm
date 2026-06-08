---
id: TASK-14
title: Agent Gateway keygen + identity opcodes + 0x40 dispatch (TASK-7.6.3)
status: Done
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 15:42'
labels:
  - agent-gateway
  - implementation
dependencies:
  - TASK-12
  - TASK-13
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.3 + the deferred 0x40 dispatch wiring. Add AgentGateway Command/Response variants + wire.rs CBOR helpers; route opcodes AGENT_K1_GENERATE_KEYS(1), PUBLIC_IDENTITY(2), PROVE_IDENTITY(3) (replace fail-closed stub at lib.rs:1342). GENERATE_KEYS: opaque random key_ref, treasury singleton, atomic counter+entry seal. PUBLIC_IDENTITY dual eth+TRON. PROVE_IDENTITY EIP-191 0x19 + verifier nonce byte-exact vs identity_proof_v1. Producer/agent profile cross-rejection; collapsed error oracles. Depends on 7.6.1, 7.6.2.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full Matrix (Reduced Matrix + the 2×3 concurrency floor from ~/pse/roborev/pse-review-2x3.sh; 3×3 vendor sign-off optional) + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged PR #38 (squash de8f6a7) behind the agent-gateway feature. Modules: agent_identity.rs (PROVE_IDENTITY EIP-191 0x19 preimage byte-exact vs identity_proof_v1 + sign; PUBLIC_IDENTITY find_entry + unified eth/TRON), agent_keygen.rs (GENERATE_KEYS all-or-nothing mutation core: opaque random key_ref + uniqueness, treasury singleton, capacity, Zeroizing secret via the unified secp256k1::generate_with_secret), agent_dispatch.rs (0x40 envelope decode + profile/version/domain/opcode gates + privilege routing + anti-oracle 0x40–0x46 band), and lib.rs frame integration (Command/Response::AgentGateway, replaced the lib.rs fail-closed stub, INSTALLED_KEYSTORE install-once slot). 132 tests; CI now runs the agent-gateway suite (two feature configs).

LIVE: PUBLIC_IDENTITY(2), PROVE_IDENTITY(3) end-to-end against the installed keystore. PROVE is gated behind the off-by-default `agent-prove-identity-preview` feature + a release_build compile_error ban until the 2D EIP-2718 0x19 reservation merges (2D PR #144). Producer/agent role isolation is compile-time enforced (ml-dsa-65 ⊥ agent-gateway).

DEFERRED (documented fail-closed seams; privileged opcodes reject 0x43 until then): full Ed25519 capability verify + contiguous-counter advance, GENERATE_KEYS live execution + re-seal/persist + candidate-body swap (7.2/7.6.x), runtime signing SIGN_TRANSFER/SIGN_FAUCET_DISPENSE (TASK-15/7.6.4), 13b ML-KEM DR backup, RESTORE ceremony.

Gate: Full Matrix (codex/gemini/claude-code/grok + 2×3) ×6 → No issues; /code-review max; cloud ultrareview (3 nits, fixed); ~8 compact rounds; 9 PR bot threads resolved+replied. The gate caught & fixed a real secret-leak (plain [u8;32] in PROVE), the role-isolation gap, the PROVE production gate, a CI blind spot (agent tests weren't run), and an unbounded-RNG hang.
<!-- SECTION:FINAL_SUMMARY:END -->
