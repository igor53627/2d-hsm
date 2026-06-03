---
id: TASK-2
title: >-
  Design and implement vsock API + wire protocol for TEE signing service
  (Authorization Tickets + Hard Fork flows)
status: Ready for Review
assignee: []
created_date: '2026-05-31 18:38'
updated_date: '2026-06-03 12:00'
labels: []
dependencies:
  - TASK-3
references:
  - impl/rust/enclave-protocol
  - backlog/docs/vsock-api-wire-format-spec-draft.md
  - 2d136ac
  - fddd3f0
  - 6dced02
priority: high
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
## Context
We are implementing real hard fork support for 2D:
- Hard forks are signaled by the current Block Producer via HARD_FORK_ACTIVATION tickets.
- Tickets must be generated and signed inside the TEE.
- The TEE service must support network-as-second-factor checks (verifying recent on-chain state before arming for production or signing fork announcements).
- Communication between the 2D host (Block Producer / orchestrator) and the minimal PQ signing service inside the TEE happens over vsock (standard for Nitro Enclaves / SEV-SNP).

## Goal
Define and implement a clean, minimal, auditable vsock-based API + wire protocol between the host and the TEE signing service.

The API must support at minimum:
- Requesting the current TEE measurement + attestation.
- Generating and signing AuthorizationTicket (both PRODUCER_RECOVERY and HARD_FORK_ACTIVATION types).
- Arming / enabling the key for production under a specific authorized producer state.
- Network freshness / second-factor checks (host feeds recent chain state or proofs; enclave verifies before allowing sensitive operations).
- Transition to new code measurement on hard fork (at scheduled block height).

## Scope for this task
- Design the vsock protocol (command types, request/response formats, versioning).
- Define the exact message shapes (wire format) — prefer simple, easy-to-audit encoding (e.g. length-prefixed CBOR, or simple binary, or JSON for early versions).
- Specify the security model (what the enclave must verify before responding to each command).
- Produce a reference client library / shim (Elixir side) and the corresponding server implementation skeleton inside the Rust (or whatever language) TEE service.
- Document how the hard fork flow uses this API.

## Out of scope (for now)
- Full implementation of the entire signing service.
- The on-chain precompile itself (that is tracked separately).

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Clear protocol specification document exists (commands, formats, error handling, security invariants).
- [x] #2 Wire format is defined and justified (why this encoding).
- [x] #3 Security model for each command is documented (what the enclave checks before acting).
- [x] #4 Basic client (host side) and server (TEE side) skeletons are implemented and can exchange at least measurement + ticket signing requests. *(Elixir: GET_MEASUREMENT/GET_STATUS encoded natively; ARM/SIGN requests replayed from Rust `TestFixtures` — native Elixir ARM/SIGN encoders are follow-on.)*
- [x] #5 Hard Fork announcement flow is explicitly described end-to-end using this API.
- [x] #6 The design is reviewed against the Authorization Tickets spec and the hard fork requirements (producer-driven, scheduled at specific block height, header version change, TEE measurement binding).

## Related
- TASK-1 (parent)
- **TASK-3** (done — cryptographic `RecentChainProof` verification; unblocks AC #8 crypto gate)
- backlog/docs/authorization-tickets-precompile-spec-draft.md
- backlog/docs/authorization-tickets-wire-format-and-precompile-skeleton.md

This task is critical because we are doing a real hard fork mechanism, not a toy one. The vsock API is the trust boundary between the untrusted host and the TEE.
<!-- SECTION:DESCRIPTION:END -->

- [x] #7 Real ArmForProduction handler is implemented with actual enclave state tracking (armed status + the associated validated RecentChainProof). *(Structural + cryptographic validation — TASK-3 / Producer Chain Attestation v1.)*
- [x] #8 Hard-fork (type=1) AuthorizationTicket signing is properly gated: it succeeds only after the enclave has been successfully armed via ARM_FOR_PRODUCTION with a fresh, validated RecentChainProof. *(Crypto verification: TASK-3 / Producer Chain Attestation v1.)*
- [x] #9 Example and tests demonstrate the correct flow (ArmForProduction first, then Sign hard-fork) and negative cases (attempting to sign hard-fork without proper arming or with stale proof).
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Started work on A (2026-06-05):

- Choosing encoding
- Writing detailed message schemas (especially SIGN_AUTHORIZATION_TICKET and ARM_FOR_PRODUCTION, as they are critical for hard forks)

First concrete output will be an update to vsock-api-wire-format-spec-draft.md with:
- Encoding decision + justification
- Versioned message formats in CBOR
- Security requirements per command

Progress on A (2026-06-05):

Encoding chosen: Length-prefixed CBOR (with u32 length + u8 version + u8 msg_type framing).

Detailed schemas written for:
- GET_MEASUREMENT
- SIGN_AUTHORIZATION_TICKET (with strong security rules for hard fork case)
- ARM_FOR_PRODUCTION
- GET_STATUS

Document updated: vsock-api-wire-format-spec-draft.md

Security invariants for hard fork ticket signing are now explicitly called out.

Next: either refine these schemas based on feedback, or move to B (detailed hard fork flow using this API).

2026-06-05: Moved from pure spec phase into implementation.

- Created initial directory structure under impl/
- Started Phase 1 with the core Rust protocol crate: length-prefixed CBOR framing + first command (GetMeasurement) with full roundtrip + tests.
- Added framing_demo example.
- All new code is under the 3:3 high-risk review rules defined in .roborev.toml and AGENTS.md.

First small implementation artifact created. Next meaningful diff will immediately go through the full roborev matrix + compact.

Milestone 2026-06-05:
- First implementation increment committed: 0262bd5
  "feat: initial vsock protocol framing skeleton (Phase 1 start)"
- Full 3:3 roborev matrix triggered on this commit (the first real code review for the high-risk vsock protocol).
- This marks the official start of Phase 1 under the documented review process.

All future code increments in impl/ will follow the same: commit → matrix → compact → fixes.

2026-06-05 milestone:
- Post-matrix fixes committed as 69a4119: "fix: address roborev matrix findings on 0262bd5"
  - All main HIGH/MEDIUM contradictions from the first code matrix addressed (MAX size, framing interop, hard-fork precondition, recent_chain_proof, canonical payload).
- This cleanly closes the review loop on the first implementation increment before starting the next (SignAuthorizationTicket + canonical logic).

Ready for next increment.

2026-06-05:
- Next increment committed as 96d2022: "feat: add SignAuthorizationTicket + ArmForProduction skeletons with canonical payload"
- Full 3:3 matrix launched on this commit (codex security, gemini security, claude-code design).
- This follows the established rhythm: commit increment → matrix → (later) compact + fixes.

Waiting for matrix results before next work.

2026-06-05:
- Hardened Phase 1 increment committed as 402fdba ("feat: harden SignAuthorizationTicket + ArmForProduction (post-review polish)")
- Full 3:3 matrix launched on this commit.
- Contains the fixes for the Critical/High issues found in the previous matrix (real Keccak256, safe preimage construction, validation, etc.).
- Also includes significantly better examples and more tests.

This is the current "polished" state of the first major implementation chunk. Awaiting matrix results.

2026-06-05 (evening):
- The Medium from the 402fdba matrix (non-strict ticket_type validation / default-allow for unknown types) was fixed.
- validate_ticket_payload now does explicit match only on 0 and 1.
- Added test for unknown ticket types.
- This is a clean, targeted post-matrix fix.

The code is now in a stronger state. Ready for a new commit + matrix on the fixed version.

2026-06-05 (late):
- Targeted fix for the remaining Medium ("non-strict ticket_type") committed as 394b73a.
- Full 3:3 matrix launched on 394b73a.
- This cleanly closes the review loop on the previous findings before we expand the implementation further.

2026-06-05 (evening):
- User chose Option A: First lock the exact canonical preimage (`keccak256(abi.encode(...))`) in the spec as the single source of truth, including adding `newHeaderVersion` to the AuthorizationTicket struct.
- The precompile spec has been updated: the canonical construction is now normative (not "recommended").
- Implementation Plan updated to reflect the new phase ("Lock Canonical Preimage").

This is now the immediate focus before further Rust implementation of the signing path.

2026-06-05 (late):
- Per user choice of Option A: Started locking the canonical preimage.
- Made the exact `keccak256(abi.encode(...))` construction (including newHeaderVersion) normative in the precompile spec.
- Added newHeaderVersion field to the AuthorizationTicket struct.
- Launched light/fast 3:3 matrix on the spec change (dirty) to review the updated canonical definition before moving to Rust implementation.

2026-06-05 (late):
- Created small clean commit 3cc7d36 containing only the Option A spec changes (normative canonical preimage + newHeaderVersion field).
- Launched light/fast 3:3 matrix on this small commit to review the locked preimage definition before any Rust implementation.

2026-06-05 (late):
- Light matrix on 3cc7d36 completed.
- Claude-code Design flagged one new internal contradiction in the just-made-normative section: recovery newHeaderVersion comment said "0 or current version" vs rule "set to 0".
- One-line fix applied to struct comment for consistency.
- Small follow-up commit created to re-run light matrix and confirm the canonical preimage definition is now fully self-consistent before moving to Rust implementation.

2026-06-05 (very late):
- Light matrix on 3cc7d36 completed.
- Claude-code Design found one new internal wording contradiction in the just-locked normative section.
- One-line consistency fix committed as 7fc949c.
- New light/fast 3:3 matrix launched on 7fc949c to confirm the canonical preimage is now fully self-consistent.

2026-06-05 (very late):
- Option A phase completed: canonical preimage locked in spec (commits 3cc7d36 + consistency fix 7fc949c). Light matrices on both came back clean/Pass.
- Started implementation in Rust: `compute_canonical_ticket_hash` now produces the exact `abi.encode` layout matching the now-normative spec (replacing previous custom length-prefixed version).
- This is the first code written against the locked canonical definition.

2026-06-05 (late):
- Polished and hardened implementation + proper Forge JSON-exchange automation committed as e2ee43e.
- Includes: correct abi.encode-style canonical hash, ignored test vectors with clear "verify against Solidity" instructions, robust automated cross-check tests, improved examples, better error/skip messages, and cleanup of old calling conventions.
- Fresh full 3x3 roborev matrix launched on e2ee43e.

This is the current high-quality state of the first major implementation chunk after multiple review-fix cycles. Awaiting matrix results.

Compact (2026-06-05 / 2026-06-01):

Successfully closed the critical 'Lock Canonical Preimage (Option A)' + implementation + review loop for AuthorizationTicket hashing.

Key commits:
- e2ee43e: Robust automated Forge JSON-exchange cross-verification (the commit the user explicitly requested to commit + review).
- 8ea2957: Post-matrix fixes (full 8-word ABI head, .output() for tests, committed the Solidity ground-truth harness).
- 416d889: Final 1-line offset math correction.

Result of full 3:3 matrix on 416d889:
- codex security: Pass (no issues)
- gemini security: Pass (no issues)
- claude-code design: Pass (explicitly confirmed the fix matches the recommended remediation from prior reviews).

All tests green. The compute_canonical_ticket_hash now produces bit-for-bit identical output to Solidity keccak256(abi.encode(...)) for both ticket types.

This is the cryptographic foundation required for any future SIGN_AUTHORIZATION_TICKET implementation (both recovery and hard-fork paths).

Process artifacts (.roborev.toml + AGENTS.md) established and will be committed immediately after this edit.

Next: move to wiring this canonical logic into the actual vsock command handlers + network second-factor checks inside the enclave-protocol crate.

Autonomous application of parallel sub-agent proposals (2026-06-01, main agent, user hands-off):

After rolling back direct sub-agent edits (per 'agents do not fix' rule), the three tracks were reviewed and applied in priority order by the main agent:

**Track B (RecentChainProof) — applied**
- Full typed  struct + heavy security documentation (network second factor, anti-replay).
-  with structural + monotonicity checks (fail-closed).
-  now uses the typed struct instead of raw Vec<u8>.
- New error variant + coupling docs in SignAuthorizationTicketRequest.
- 8 new tests. All green.

**Track C (Forge cross-verification hardening) — applied**
- 5 new edge-case automated vectors (empty measurement, 32/33-byte boundary, 200-byte, extreme scalars).
- Centralized  helper with very loud actionable banners.
-  feature for hard CI mode (graceful by default).
- All 7 vectors now go through real Forge path when available.
- Updated comments emphasizing 'live contract' between TEE and precompile.

**Track A (real dispatch + Sign handler) — applied**
-  (deterministic, clearly marked as non-production).
-  (the only allowed signing path).
-  central dispatcher.
- 5 new roundtrip + negative dispatch tests using full framing.
-  example updated to use the real dispatcher.
- All tests green (26 total).

Current state:
-  → 26 passed.
- Example runs cleanly and produces real canonical hashes + 64-byte signatures.
- No changes to the already-reviewed canonical hash logic itself.

This completes the first major foundation increment for the vsock API (framing + typed proof + strong verification + real command handlers).

Next required step per AGENTS.md: commit + full 3:3 roborev matrix on the combined change.

[Correction to previous mangled note - 2026-06-01]

Clean summary of the autonomous application after commit 5a0e3e2:

All three tracks from the parallel sub-agent proposals were reviewed and applied in controlled fashion by the main agent (after explicit rollback of direct edits per policy):

**B (RecentChainProof) - applied**
- RecentChainProof struct with full security rationale.
- validate_recent_chain_proof function (structural + monotonicity checks, fail-closed).
- ArmForProductionRequest now uses typed proof.
- 8 dedicated tests + coupling docs in SignAuthorizationTicketRequest.

**C (Forge verification hardening) - applied**
- 5 new automated cross-check vectors exercising edge cases (empty measurement, 32/33-byte padding boundary, 200-byte, zero height + u64::MAX nonce).
- Centralized handle_forge_result helper with prominent 'LIVE CONTRACT' banners.
- New Cargo feature 'enforce-forge-crosscheck' (graceful skip by default, hard panic for CI).
- All vectors now route through real Forge when available.

**A (real handlers) - applied**
- compute_mock_pq_signature (deterministic, with explicit DO-NOT-USE marker).
- handle_sign_authorization_ticket (the single allowed signing path).
- dispatch_command central dispatcher.
- 5 new tests for framing + dispatch roundtrips and error cases.
- ticket_signing_demo example fully updated to use dispatch.

Result after 5a0e3e2:
- 26 tests passing.
- cargo run --example ticket_signing_demo works and shows real canonical hashes + signatures.
- No modifications to the already-reviewed compute_canonical_ticket_hash logic.

This is the combined foundation for the vsock command layer (framing from earlier + typed proof + strong verification + executable handlers).

Per process: this commit (5a0e3e2) now requires a fresh full 3:3 roborev matrix.

Post-matrix Low cleanup (2026-06-01):

Commit f01fd88 - fix: address remaining Low findings from 3:3 on 5369c3a

- GET_MEASUREMENT now correctly returns only type 0 in supported_ticket_types (hard-fork signing disabled in Phase 1 skeleton).
- Removed blanket hard-fork note from dispatch_command error path (was polluting type-0 recovery errors).
- Added regression test for the hard error path in validate_recent_chain_proof (non-empty tail without source_ticket_hash).

All 27 tests green. This closes the main consistency and test-quality Lows from the matrix on the safety fixes commit.

Current state of the vsock protocol crate:
- Solid framing + typed RecentChainProof with honest Phase 1 validation.
- dispatch_command + handle_sign_authorization_ticket with clear Phase 1 restrictions.
- Strong automated Forge cross-verification (including edge cases).
- Documentation is now much more honest about what is and is not enforced.

Next focus (short-term increments):
- Implement real ArmForProduction handler with actual state tracking.
- Add basic enclave state simulation so we can properly gate hard-fork signing.
- Make type-1 signing actually depend on successful arming + fresh proof.

Work started on AC #7 (2026-06-01):

Two small increments completed:
- Added EnclaveArmedState and EnclaveState types (with clear Phase 1 documentation).
- Added pure function arm_for_production that validates the proof and returns a new Armed state.

Changes compile cleanly. More steps (wiring + tests) planned before full review.

AC #7 work started (2026-06-01):

Two small steps completed:
- Added EnclaveArmedState and EnclaveState types (with Phase 1 documentation).
- Added arm_for_production pure function + dispatch_command_with_state (stateful API).
- Basic tests added. 29 tests passing.

Changes are uncommitted. Will run 3:3 matrix on current state before committing.

AC #7 increment committed as abd0cd4:

- EnclaveArmedState + EnclaveState types
- arm_for_production pure function
- dispatch_command_with_state (stateful API)
- Basic tests (29 total passing)

This is the first real step toward having a functional ArmForProduction handler with state tracking.

Will run fresh 3:3 matrix on this commit.

Next small increment on AC #7 (2026-06-01):

Committed as 21cdf1a - test: improve GetStatus observability and add arming test coverage (AC #7)

Changes:
- GetStatus in dispatch_command_with_state now returns real authorized_measurement and authorized_pq_pubkey when the enclave is in Armed state (instead of empty values).
- Added three targeted tests:
  - get_status_reflects_armed_state
  - arm_for_production_fails_with_invalid_proof
  - dispatch_arm_for_production_updates_state

Result: 31 tests passing, clean build.

This continues the small, reviewable increments approach for AC #7 (real ArmForProduction with state tracking).

Next: run 3:3 matrix on this commit.

Post-matrix follow-up (2026-06-01):

Small targeted fix committed as e7d5d09:

- Aligned vsock-api-wire-format-spec-draft.md GET_STATUS response fields
  with the rename done in 21cdf1a / f036dcc (current_* → authorized_*).
- Added Phase 1 semantic note.

This closes the last remaining Medium from the matrix on 21cdf1a.

Current state of AC #7 work:
- Solid minimal state tracking (EnclaveArmedState + EnclaveState)
- Functional arm_for_production + dispatch_command_with_state
- Improved GetStatus observability when armed
- Wire spec now in sync
- Good test coverage for the current Phase 1 behavior

Next: run fresh 3:3 matrix on the combined AC #7 increments (or decide on next small step).

AC #7 short-term progress (as of 2026-06-01):

Several small, reviewable increments completed toward real ArmForProduction with state tracking:

- abd0cd4: Added EnclaveArmedState + EnclaveState types + core arm_for_production function + dispatch_command_with_state (stateful API).
- 21cdf1a + f036dcc: Improved GetStatus observability when armed (now returns real authorized_* values) + added important regression and negative tests for arming. Also added explicit Phase-1 markers in tests.
- e7d5d09: Aligned vsock wire-format spec with the field rename (closed the last Medium from the matrix on 21cdf1a).

Current state:
- Functional (minimal) state tracking and arming logic through the main vsock API.
- 31 tests passing.
- Documentation and spec are now in sync and honest about Phase 1 limitations.
- Multiple clean or near-clean 3:3 matrices on these increments.

This gives a solid foundation for AC #7. The state machine is now observable and controllable from the host side in a controlled way.

Next short-term focus areas (to be prioritized):
- Strengthen GetStatus with more useful armed-state details.
- Add more comprehensive tests (re-arming rules, state transitions, negative cases).
- Update example to demonstrate realistic Arm → GetStatus → Sign flow.
- Prepare ground for AC #8 (gating hard-fork signing behind armed + fresh state).

Следующий маленький инкремент по AC #7 (2026-06-01):

- Улучшена наблюдаемость armed-состояния через GET_STATUS. Теперь при armed=true возвращаются два новых полезных поля:
  - armed_at_height — на какой высоте enclave успешно заармился;
  - proof_finalized_height — финализированная высота из proof’а, который использовался при arming. Это даёт хосту понимание, насколько свежий view сети был в момент arming.
- Обновлены связанные тесты (добавлены проверки новых полей).
- Значительно улучшен пример ticket_signing_demo:
  - Теперь он показывает более реалистичный и правильный flow: сначала ARM_FOR_PRODUCTION (с валидным proof), потом GET_STATUS (чтобы убедиться в состоянии), а затем попытка подписать hard-fork тикет.
  - Добавлен негативный сценарий — попытка подписать hard-fork тикет без предварительного arming (демонстрирует текущее Phase 1 ограничение).

Это естественное продолжение работы по AC #7 (реальное состояние + arming с возможностью наблюдения).

31 тест зелёный.

Matrix on e7d5d09 (2026-06-01):

Clean 3:3 matrix on the small targeted spec fix (alignment of GET_STATUS fields).

- Codex Security: Чисто
- Gemini Security: Чисто
- Claude-code Design: Pass (с одним Low)

Единственная находка (Low): небольшая рассогласованность формулировок будущего поведения поля между spec и кодом. Не блокер, но рекомендуется подровнять перед тем, как появятся клиенты.

Все предыдущие Medium по AC #7 теперь закрыты.

Current state of AC #7 work (solid foundation):
- EnclaveArmedState + EnclaveState types
- arm_for_production + dispatch_command_with_state
- Improved GetStatus observability when armed
- Wire spec in sync
- 31 tests, multiple clean/near-clean matrices

Next short-term steps to prioritize (small increments):
- Strengthen GetStatus with more useful armed-state details (armed_at_height, proof_finalized_height already done; can add more).
- Add more comprehensive tests (re-arming, state transitions, additional negative cases).
- Update example to demonstrate realistic Arm → GetStatus → Sign hard-fork flow.
- Prepare ground for AC #8 (gating hard-fork signing behind armed + fresh state).

Decision needed: which small step to take next.

Next small increment on AC #7 (2026-06-01):

Committed as 94435b4 - feat: expose source_ticket_hash via GetStatus when armed (AC #7)

- Added source_ticket_hash field to GetStatusResponse.
- Populated from EnclaveArmedState in the stateful dispatcher.
- Strengthened tests.

This field is important for auditing and future sign-time anti-replay (AC #8).

31 tests passing.

Next: run 3:3 matrix on this commit.

2026-06-02 — AC #8/#9 skeleton + post-matrix follow-up (cc8446f + follow-up commit):

**AC #8 (skeleton) — done:** stateful hard-fork gating (armed + pubkey + structural proof re-check + activation_height > proof.finalized_height).

**AC #9 — done:** tests + demo for Arm → Sign hard-fork and negative cases.

**3:3 matrix on cc8446f:** codex/gemini HIGH + claude design Fail — all cite the same known Phase 1 gap: structural-only `RecentChainProof`, not crypto. Accepted as open debt, not a regression of the gating logic.

**Follow-up (same advice):**
- Spec sync: GET_STATUS CBOR keys 5–9, `supported_ticket_types` semantics, Phase 1 vs production section in vsock spec.
- Policy: one hard-fork ticket per armed session.
- Rename/clarify `armed_at_height` → `authorized_activated_at_height` in code (honest semantics).
- Do **not** fake-fix with non-empty `proof_data` only.

**Production blocker → TASK-3:** cryptographic `RecentChainProof` verification before treating type=1 signatures as enforcing network second factor. See `task-3 - Implement-cryptographic-RecentChainProof-verification-network-second-factor.md`.

2026-06-02 — TASK-3 landed + doc sync (`2d136ac`, `fddd3f0`, `6dced02`):

- **TASK-3 Done:** Producer Chain Attestation v1 (Ed25519, pinned `ProducerAttestationTrust`, measurement in preimage). AC #7 note updated — no longer structural-only.
- **Wire:** `wire.rs` integer-key CBOR for `GET_STATUS` and `ARM_FOR_PRODUCTION` structured `RecentChainProof`.
- **Dispatch:** `dispatch_command` = recovery + GET_MEASUREMENT; stateful path required for arm/status/hard-fork.
- **Docs:** `impl/README.md`, root `README.md`, vsock spec §9.3, implementation plan progress section updated.
- **`enclave-protocol` tests:** ~62 default `cargo test`; **70** with `--features ml-dsa-65` (or `ml-dsa-65,pq-seal-provisioning`). Demos need `--features test-support`.

2026-06-03 — TASK-2 Phase 4 closure (reference host integration):

- **Wire:** integer-key CBOR for all four commands in `wire.rs`; `process_framed_with_shared_state` for multi-connection transports; `HostSession` for single-connection dev binaries only.
- **Transports:** `enclave-stdio-bridge` (stateless GET_MEASUREMENT), `enclave-stdio-session`, `enclave-uds-server` (dev stand-in: shared `EnclaveState`, same-UID socket trust — see `elixir-shim/README.md`).
- **Elixir:** `impl/elixir-shim/` — Framing, StdioClient, Socket, Session, TestFixtures; `mix test` (stdio + UDS). ARM/SIGN over UDS use Rust-exported frames, not native Elixir encoders.
- **AC #1–#3:** `backlog/docs/vsock-api-wire-format-spec-draft.md` v0.2 (commands, CBOR, security invariants per command).
- **AC #4:** Rust session/framing tests + Elixir UDS tests (`get_measurement`, `get_status`, `arm_for_production`, `sign_authorization_ticket` with fixtures). Integration tests use **64-byte mock** signatures (`demo-mock-sign`), not ML-DSA 3309 B.
- **AC #5:** Hard-fork flow in spec §8 + `ticket_signing_demo` / session tests (Arm → Sign type=1). *"End-to-end"* here means wire/protocol sequence; **operator runbook** is explicitly deferred.
- **AC #6:** Cross-reviewed with authorization-ticket specs (prior matrices on design artifacts + Reduced matrix + compact **6778** on branch after shared-state fix `47d141c`).

**Merge gate:** Initial Phase 4 required Full Matrix on `impl/` (per `AGENTS.md`). Post-merge follow-up: production AF_VSOCK must use shared state API (see implementation plan § next increments).

**Follow-on (not TASK-2):** production AF_VSOCK, operator runbook polish, live chain-tip refresh, light-client `proof_data` format `0x02+`, TASK-1 platform root in enclave images.

Parent plan: `backlog/docs/implementation-plan-vsock-api-and-hard-fork.md`.
<!-- SECTION:NOTES:END -->
