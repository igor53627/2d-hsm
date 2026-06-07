---
id: TASK-7.4
title: Agent Gateway structured ordinary transfer signing
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-07 16:23'
labels:
  - agent-gateway
  - signing
  - secp256k1
dependencies:
  - TASK-7.1
  - TASK-7.2
  - TASK-7.3
references:
  - backlog/docs/agent-gateway-transfer-faucet-signing.md
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
  - ../2d/lib/chain/block_executor.ex
  - ../2d/lib/chain/crypto/envelope.ex
priority: high
ordinal: 7040
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design Agent Gateway signing as structured ordinary 2D transaction signing. The enclave must construct the canonical preimage internally and must not expose generic digest signing for agent keys. Faucet treasury signing is a distinct command with TEE-enforced spend caps.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The task consumes the frozen in-repo 2D ordinary-transaction golden vector pinned by TASK-7.1 before any implementation begins.
- [ ] #2 Signing input is semantic transaction fields, including chain id, from, to, amount, nonce, and gas fields used by that exact 2D ordinary transaction envelope.
- [ ] #3 The enclave verifies `from` equals the selected key ref's derived address and chain id equals 2D for both transfer-key signing and faucet treasury dispense signing.
- [ ] #4 The signature format, low-S rule, recovery id, and address recovery behavior are specified with test-vector requirements against 2D verifier expectations.
- [ ] #5 Transfer-key and faucet treasury MVP signing forbid non-empty data/memo for native dispenses; faucet treasury dispense also requires `to` to match a known `agent_transfer_k1` public identity in the TEE keystore, while documenting that this does not prevent two-step exfiltration through transfer keys until TEE-side transfer destination/amount limits exist; any future calldata support requires a separate semantically parsed command.
- [ ] #6 Faucet treasury signing enforces max amount, max gas limit, max effective gas fee rate for the pinned 2D transaction encoding, a mandatory refillable cumulative signing budget, and an optional quorum-resettable lifetime circuit breaker inside the TEE.
- [ ] #7 Cumulative spent accounting and treasury config version are sealed so they survive normal restart; rollback resistance against a compromised host requires TASK-7.7's anti-rollback mechanism or production-funding block. Normal config bumps do not reset cumulative spend, and budget increases require explicit treasury-refill capability.
- [ ] #8 Caps apply to checked `amount + gas_limit * effective_max_fee_rate` arithmetic and fail closed on overflow; if the pinned encoding supports EIP-1559-style fields, this uses `maxFeePerGas` rather than legacy `gas_price`.
- [ ] #9 The faucet spend debit is durably sealed before any faucet signature leaves the enclave, and failure to seal emits no signature; a dispense does not advance an administrative capability counter or write the treasury config version. Administrative capability-counter advancement and config-version updates are sealed by their own privileged commands (key generation, backup export/restore, and treasury configuration including its `refill_budget` sub-operation) before those commands return success.
- [ ] #10 Any budget refill, lifetime breaker raise/reset, or recovery override uses sealed accounting and a replay-protected treasury or recovery/quorum capability; host-controlled time never resets limits, and any spend-value reset is bound to a strict recovery counter and target value.
- [ ] #11 The design states that the cap is a signing-budget bound; failed, replacement, duplicate-nonce, or unbroadcast signatures still consume budget unless a reviewed reconciliation protocol exists.
- [ ] #12 ECDSA signing uses RFC 6979 deterministic nonce derivation or a vetted constant-time library with equivalent nonce safety; vectors cover deterministic signing and low-S normalization.
- [ ] #13 Agent keys cannot sign arbitrary caller-provided digests, and identity-proof challenges cannot be coerced into transfer signatures; TASK-7.4 consumes the TASK-7.3 proof against the TASK-7.1-pinned 2D ordinary-transaction preimage vector.
- [ ] #14 Throughput requirements state the expected faucet dispense rate, concurrent request serialization model, serialized sealed-state commit behavior, budget-remaining observability, and anti-rollback round-trip assumptions before implementation.
- [ ] #15 If treasury-key rotation is in scope (per the TASK-7.2 carry-over semantics), signing against a rotated/replacement `agent_faucet_treasury_k1` key continues to debit the carried-over cumulative signing-budget and lifetime-breaker counters and never signs against a counter reset to zero merely because the treasury key was replaced; absent an active reviewed rotation protocol, rotation remains fail-closed.
- [ ] #16 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design delivered in backlog/docs/agent-gateway-transfer-faucet-signing.md (design-only; secp256k1 signing impl is TASK-7.6). Consumes TASK-7.1 protocol + frozen ordinary_tx_v1 vector, TASK-7.2 faucet caps + seal-before-emit, TASK-7.3 keygen/identity. Adds: SIGN_TRANSFER structured-field -> EIP-155 preimage build + from/chain_id checks + low-S/recovery/v keyed to the 2D verifier + no caller digest + empty data; SIGN_FAUCET_DISPENSE to-must-be-known-transfer-key + worst-case checked-arithmetic caps (legacy gas_price) + dual sealed counters + signing-budget semantics; seal-before-emit + serialized commit + throughput statement + 7.4/7.7 boundary + residual; no-generic-digest + identity-proof non-coercion + key-purpose cross-rejection; conditional rotation carry-over; golden-vector/test requirements. Adopted: legacy gas_price (no EIP-1559 in pinned vector), rotation carry-over semantics only, no reconciliation (worst-case budget), anti-rollback assumptions toward 7.7, dispense-rate model + benchmark deferred to 7.6. AC #1-#15 addressed by this design; AC #16 (roborev matrix) run pre-merge.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Golden-vector requirements cover successful signing and rejection cases after the 2D transaction encoding is pinned.
- [ ] #2 Test requirements prove generic digest signing and identity-proof oracle coercion fail for agent key purposes.
- [ ] #3 Final summary added before marking Done.
<!-- DOD:END -->
