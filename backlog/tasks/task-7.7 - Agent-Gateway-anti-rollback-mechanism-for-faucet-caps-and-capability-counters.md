---
id: TASK-7.7
title: Agent Gateway anti-rollback mechanism for faucet caps and capability counters
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
updated_date: '2026-06-08 19:37'
labels:
  - agent-gateway
  - tee
  - anti-rollback
  - security
dependencies:
  - TASK-7.1
  - TASK-7.2
  - TASK-7.4
references:
  - backlog/docs/agent-gateway-anti-rollback.md
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
priority: high
ordinal: 7070
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define the production anti-rollback mechanism for Agent Gateway sealed replay counters and faucet spend caps. Standard sealed storage gives confidentiality and integrity but cannot by itself stop a compromised host from rolling sealed state back, so production fund custody needs an external anti-rollback authority or an explicit funding block.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The design selects one anti-rollback mechanism for production fund custody: external append-only ledger, remote monotonic counter, operator-signed boot authorization with high-water marks (which must itself be replay-resistant — bound to a platform/hardware monotonic counter or a remote challenge-response — so a host cannot replay a stale sealed state together with its matching stale authorization), or another reviewed equivalent.
- [x] #2 The mechanism covers administrative capability replay counters and faucet cumulative spend counters.
- [x] #3 Restore and failover procedures seed counter high-water marks from authenticated material and never reset counters to zero from a stale backup.
- [x] #4 Active-active clones of one faucet key remain prohibited unless the mechanism provides a global spend/capability ledger shared by every live clone.
- [x] #5 If no production anti-rollback mechanism is available, the task defines the code/config/runbook gate that blocks material production fund custody for Agent Gateway faucet and transfer wallets.
- [x] #6 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design delivered in backlog/docs/agent-gateway-anti-rollback.md (design here; the anti-rollback anchor IMPLEMENTATION is TASK-7.7's own — slices tracked below — while TASK-7.6 owns the secp256k1 signer backend it binds onto). Platform: SEV-SNP has NO per-enclave hardware monotonic counter -> external anchor required. Selected Option A = remote monotonic counter + epoch-lease: freshness_epoch in the pq-agent-keystore-v1 ENCRYPTED BODY (format extension per 7.2 AC#16; NOT the pq-seal-v1 AAD); mutual-authenticated anchor handshake (agent-domain SNP report_data + Ed25519-signed anchor response vs pinned anchor_root); on epoch != anchor-current never trust the stale blob's own marks (anti-rollback): ADOPT the anchor's authoritative counter/spend marks when they fully resolve the gap (bounded crash-reconcile), else FAIL CLOSED (epoch > anchor-current anchor-rollback, a structural key/config-mutation gap the anchor never held -> restore, or anchor unavailable); per-dispense bump+seal-before-emit. Default lease=1; a NAIVE lease=N is UNBOUNDED, so a safe lease=N requires anchor-visible per-spend consumed-cursor ack before emit, and admin/recovery/config advances are always lease=1; when the anchor is unavailable ALL fund custody fails closed (no offline window). Crash reconcile: the anchor records authoritative post-op marks (epoch + counter/spend high-water, NOT key material) and the enclave ADOPTS them for counter/spend gaps (never guesses non-emission); a structural key/config-mutation gap the anchor can't supply fails closed -> restore. Covers cap counters + faucet cumulative/lifetime spend + strict recovery counter (AC#2); boot/restore seed from authenticated marks never-zero (AC#3); active-active operator-procedural under A, enforced only by Option B global ledger (AC#4); AC#5 gate = 2-layer fail-closed (Nix assertion with explicit opt-out term + derived enabled; Rust block on rollback-sensitive commands, SIGN_TRANSFER excluded, EXPORT/RESTORE included) + hard-block-default + measured/sealed audited opt-out. Anchor under separation-of-duties + anti-rollback-durable; liveness-DoS is an accepted availability residual.

Roborev evidence (AC#6): 3x3 matrix on 524c8d8 -> 3 HIGH + 3 MED (job 7704); /code-review skill -> 40 candidates -> 15 findings; 9 PR bot comments resolved/replied (CodeRabbit confirmed); post-merge compact -> 3 more (anchor-unavailable, reconcile non-emission proof, stale notes) resolved.

The ACs/DoD above are the **design** acceptance (complete); this task stays In Progress to track the implementation slices below. The anchor module is TASK-7.7's own mechanism, built under the shared `agent-gateway` feature.

Implementation progress: **slice 1 — anchor-response verify + boot reconcile (verify-only)** landed in `impl/rust/enclave-protocol/src/agent_anchor.rs`. Pure, unit-tested with a mock anchor key (14 tests): strict **structural** validation of the decoded **v1-PROVISIONAL** freshness response map (keys 1..=7 always signed + optional 8/9 when chain-bound + key 13 Ed25519 sig) over the value-map API `verify_anchor_response`; the strict *canonical wire* decode for host bytes is now **landed** (sub-slice 1, PR-A) and reachable via `verify_anchor_response_bytes`, which the boot-wiring slice calls. `verify_strict` vs sealed `anchor_root`, scope `(twod_chain_id, environment_identifier)` + fresh-nonce echo binding, the §3 counter/spend-bounded `reconcile` (Fresh/AdoptForward/FailClosed{AnchorBehind,StructuralGap,Inconsistent}), and `anchor_handshake_report_data` (the SNP report_data the next slice's quote must commit to). Wire schema documented in design doc §8. **Status (post PR-B):** `structural_version` (key 5) is **FROZEN v1** and the `marks_digest` (key 6) **enclave encoder is FROZEN v1**; only key 6's cross-component contract (anchor data model) + the marks delivery/adoption path remain pinned/deferred. Nothing is wired at boot yet. Hybrid "Variant C" = §3 Option-A verify mechanism + optional chain-block binding (keys 8/9) so a chain-bridge anchor can back it without a wire change.

**Blocking implementation sub-slices (ordered; each gates the next; live GENERATE_KEYS un-gate via TASK-18 is LAST):**
1. **Strict canonical CBOR decoder** (shared with capability/dispatch) — **LANDED (PR-A, `src/agent_cbor.rs`)**: `strict_decode_map` rejects non-shortest ints, indefinite lengths, dup/out-of-order keys (every nesting level), reserved/tag/float (bool-only major 7), depth/size caps, and trailing bytes; wired into `decode_envelope` (envelope + nested cap/payload submaps); `verify_anchor_response_bytes` is the anchor entrypoint (dead-code until boot). Also consolidated the duplicated int-key accessors. ~22 unit + parity tests.
2. **Nonce plumbing** — CSPRNG source, single-use lifecycle, same nonce bound into the SNP quote `report_data` and into `expected_nonce`; replay-`(nonce,response)` negative test.
3. **Pin `structural_version`** — **LANDED (PR-B)**: sealed-body `u64` init 1, required (no serde default), forward-only, bumped per committed GENERATE_KEYS (LOCAL-ONLY + INERT — epoch advance deferred) via `checked_add`→SealFailed; CONFIGURE_TREASURY bump is a deferred handler (exhaustive-`match` obligation). `KEYSTORE_FORMAT_VERSION 1→2` (v1 never shipped, no reader). FROZEN in design doc §8.
4. **Pin `marks_payload`/`marks_digest`** — **LANDED (PR-B)**: `KeystoreBody::compute_local_marks_digest` = SHA3-256(MARKS_DOMAIN ‖ canonical-CBOR{1:sorted counter rows, 2:cumulative_native_spend 32B, 3:lifetime_spend 32B, 4:strict_recovery_counter}); scope_class as CBOR uint, env folded, length-prefixed, hand-derived genesis golden. `strict_recovery_counter` field added (init 0, mutators deferred). Enclave encoder FROZEN; **key-6 cross-component contract PINNED-BEFORE-ANCHOR-CO-SIGN** (anchor data model in §8). DEFERRED: the separate marks_payload delivery + recompute-before-adopt + **seeding** asserts adopted marks ≥ local (AC#3).
5. **Boot wiring (READ-SIDE only)** — SNP-quote fetch + host relay + the boot decode via `verify_anchor_response_bytes`. **Ordering guard:** boot `reconcile` MUST NOT gate any decision on `structural_version` until slice 6's atomic epoch+structural advance ships — otherwise a preview-sealed GENERATE_KEYS candidate (structural bumped, anchor epoch unchanged) fails closed `Inconsistent` on next boot. Until then `structural_version` stays inert; partial-init must not expose rollback-sensitive commands.
6. **Per-op epoch bump + seal-before-emit (lease=1)** — advances `freshness_epoch` + the anchor ack **ATOMICALLY with the `structural_version` bump** (this is the write-side that makes `structural_version` load-bearing/non-forgeable). Only after this lands may slice 5's `reconcile` gate on `structural_version`. (The atomicity invariant is owned HERE, not split with slice 5.)
7. **AC#5 funding gate** (Nix assertion + runtime block, TASK-16); optional `require_chain_binding` policy.

Review evidence for THIS implementation slice (PR #45, AGENTS.md Full Matrix on `impl/` state-machine logic): `/code-review` xhigh (7 finder angles) + **roborev Full Matrix on the branch** — codex security+design, gemini security+design, claude-code security+design, grok security (opencode xai/grok-4.3, confirmed `done` not skipped) — then `roborev compact --wait` consolidated 14 jobs → job 7941 (2 residual: the documented strict-decode deferral + a stale-text fix, both handled). PR review bots (gemini-code-assist, CodeRabbit, greptile) replied. (This is distinct from the 524c8d8 matrix, which covered the design doc.) Fixes folded in: single-predicate signed-preimage count; `chain_block_hash` surfaced on `AnchorState`; malformed/invalid-point/chain-downgrade+upgrade negative tests; contract docstrings (nonce freshness, strict-decode, monotone-marks seeding); wire format relabelled v1-PROVISIONAL with structural_version/marks_payload pinning deferred to the blocking sub-slices above; active-active scope claim corrected (Option A is not clone-safe). **Follow-up cleanup: DONE in PR-A** — the duplicated CBOR map accessors (`map_get`/`as_u64`/`as_bytes`/`as_bytes32`/`as_digest`) across agent_capability/agent_dispatch/agent_anchor are now a single `agent_cbor` `pub(crate)` home (`as_bytes_n::<N>` unifies the 32/64-byte reads).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Design delivered in backlog/docs/agent-gateway-anti-rollback.md (PR #33, squash e5d3213). Production anti-rollback for sealed replay counters + faucet spend caps. Platform: SEV-SNP has NO per-enclave hardware monotonic counter -> external anchor required. Selected Option A = remote monotonic counter + epoch-lease: freshness_epoch in the pq-agent-keystore-v1 encrypted body (format extension, version bump per 7.2 AC#16); mutual-authenticated anchor handshake (agent-domain SNP report_data + Ed25519-signed anchor response vs pinned anchor_root); on epoch != anchor-current never trust the stale blob's own marks (anti-rollback): ADOPT the anchor's counter/spend marks when they fully resolve the gap (bounded crash-reconcile), else FAIL CLOSED (epoch > anchor-current anchor-rollback, structural key/config gap -> restore, or anchor unavailable); per-dispense bump+seal-before-emit; default lease=1, safe lease=N only via per-spend anchor-ack (count-bounded, never time); crash-reconcile keyed by request_id. Covers cap counters + faucet cumulative/lifetime spend + strict recovery counter (AC#2); boot/restore seed from authenticated marks never-zero (AC#3); active-active operator-procedural under A, enforced only by Option B global ledger (AC#4); AC#5 funding gate = 2-layer fail-closed (Nix assertion with explicit opt-out term + derived enabled, Rust block on rollback-sensitive commands with SIGN_TRANSFER excluded/EXPORT+RESTORE included) + hard-block-default + measured/sealed audited opt-out. Verified by roborev 3x3 + compact + the /code-review skill (40->15) + all 9 PR bot comments resolved/replied (CodeRabbit confirmed). The DESIGN above is complete; the **anti-rollback anchor implementation is owned by TASK-7.7 itself** (slices tracked in the Implementation Notes — slice 1 `agent_anchor.rs` verify+reconcile landed), while TASK-7.6 owns the Agent Gateway secp256k1 signer backend it binds onto.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Anti-rollback design or production-funding block is documented.
- [x] #2 Failure and rollback scenarios are covered by tests, vectors, or reviewed runbook validation where code does not yet exist.
- [x] #3 Final summary added before marking Done.
<!-- DOD:END -->
