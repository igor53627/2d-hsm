# Implementation Plan: vsock API + Hard Fork Support (Post-Spec Phase)

**Date**: 2026-06-05 (progress update 2026-06-02)  
**Status**: Active plan — Phase 1 largely complete in reference crate; Phase 3 MVP (TASK-3) done
**Parent Tasks**: TASK-1, TASK-2  
**Governing Process**: Multi-Agent Code-Review Playbook (3:3 matrix + Compact + human gate for high-risk changes)

## Context and Lessons from the First Matrix

The initial 3×3 roborev matrix (codex security, gemini security, claude-code design) on the draft specs surfaced two HIGH design issues that were fixed before any code was written:
- Canonical signed payload / domain separation for HARD_FORK_ACTIVATION tickets.
- Mandatory, verified `recent_chain_proof` for `ARM_FOR_PRODUCTION` (enforcing "network as second factor").

This validated the decision to apply the full review process at the spec stage.

All future implementation work in this area is classified **High-risk** by default (see `.roborev.toml` and AGENTS.md).

## Guiding Principles for Implementation

- Security and correctness first. The vsock channel is the only trusted boundary between the untrusted host and the TEE.
- Review gates at every meaningful increment (no "big bang" implementation).
- Keep the implementation minimal and auditable.
- Hard fork flows (scheduled activation, measurement transition, header version enforcement) are first-class and must be exercised in tests/skeletons.
- Use the 3:3 matrix + `roborev compact` on every high-risk increment.

## Proposed Phased Plan

### Phase 0 – Finalize & Re-Review Specs (Short, 1–3 days)
- **v0.2 spec draft (2026-06-02):** `vsock-api-wire-format-spec-draft.md` — §2 ML-DSA-65, dual-path, attestation terminology (TEE vs Producer Chain Ed25519).
- Run **Reduced roborev matrix** (`security+codex`, `security+gemini`, `design+claude-code`) on dirty `backlog/docs/*vsock*` + `*authorization-ticket*`; then `roborev compact`.
- Full 3×3 + concurrency **required** if Reduced matrix finds any **HIGH**, or any change to `ticketHash` canonicalization / ML-DSA message binding (`ctx`, pure vs HashML-DSA), before marking v0.2 deliverable Done.
- Update this plan and AGENTS.md with any new invariants from compact.

**Deliverable**: v0.2 spec files marked reviewed via roborev Reduced + compact (record outcome in task notes).

### Phase 1 – Wire Protocol & Framing Skeletons (Core Foundation)
- Implement the length-prefixed CBOR framing + protocol version handling (both sides).
- Define and implement the minimal set of commands from the spec:
  - `GET_MEASUREMENT`
  - `SIGN_AUTHORIZATION_TICKET` (with correct canonical payload logic for both ticket types)
  - `ARM_FOR_PRODUCTION` (enforcing non-null verified proof)
  - `GET_STATUS`
- Basic request/response handling and error paths.
- Simple test harness (host ↔ mock enclave or two processes over vsock).

**High-risk areas in this phase**:
- Exact canonical encoding of tickets (must match the spec exactly).
- Proof validation logic inside the "enclave" side.
- Error handling that does not leak sensitive information.

**Review gate**: 3:3 matrix on the framing + command implementation diffs (especially the signing and arming paths). `roborev compact` required.

**Progress (2026-06-02) — reference crate `impl/rust/enclave-protocol/`:**

| Item | Status |
|------|--------|
| Framing + command handlers | Done |
| Canonical `ticketHash` + Forge cross-check | Done |
| `EnclaveState` + `arm_for_production` + `GET_STATUS` observability | Done (TASK-2 AC #7–#9) |
| Hard-fork gating (armed, pubkey, activation height, one per session) | Done (skeleton) |
| Structured `RecentChainProof` on the wire (`wire.rs` for ARM + GET_STATUS) | Done |
| Stateless vs stateful dispatch documented | Done (`6dced02`) |

### Phase 2 – Hard Fork Specific Flows (First-Class Citizen)
- End-to-end support for announcing and transitioning on a scheduled hard fork:
  - Signing a HARD_FORK_ACTIVATION ticket with the correct fields (`forkSpecHash`, `newHeaderVersion`).
  - Internal state in the enclave for "pending hard fork at height X with new measurement Y and header version Z".
  - Behavior around the activation height (refuse old-version signatures after the point, etc.).
- Integration points with the future header version field in 2D blocks.
- Simulation of a hard fork transition (including what a compromised host might try).

**Review gate**: Dedicated 3:3 matrix focused on the hard-fork state machine and transition logic. Must include concurrency lens.

### Phase 3 – Production Authorization & Network Second Factor (Strengthening)

**MVP complete (TASK-3, 2026-06-02):**

- Producer Chain Attestation v1: mandatory `proof_data` + Ed25519 `signature_from_recent_producer`
- Pinned `ProducerAttestationTrust` (not host-supplied; see spec §9.3)
- Verification at `ARM_FOR_PRODUCTION` and hard-fork sign time; re-arm monotonicity on `finalized_height`
- Reduced 3:3 matrix + compact on crypto increment; post-matrix fixes (`fddd3f0`, `6dced02`)

**Still open in this phase:**

- Full light-client / validator-set proofs in `proof_data` (format `0x02+`)
- Live chain-tip refresh between arming and signing
- Rate limiting / replay protection on sensitive commands beyond current tail checks
- Sealed persistence of armed state across enclave restart
- Logging / observability that does not leak secrets

**Review gate**: Full matrix + compact on major extensions to proof verification (light client, live tip).

### Phase 4 – Elixir Host Shim / Integration Layer (2D side)
- Clean client library or GenServer in Elixir that speaks the vsock protocol.
- Integration points with BlockProducer (how it requests tickets, arms the service, feeds chain state).
- Error mapping and operational surfaces (what operators see on the host side).
- Tests that exercise the full stack (host + enclave mock or real vsock).

**Review gate**: Matrix review of the integration code, especially anything that touches authorization state or chain data fed to the enclave.

### Phase 5 – Hardening, Testing & Documentation
- Property-based or model-based tests for the ticket canonicalization and proof validation.
- Negative testing (compromised host scenarios).
- Performance / latency baseline for the vsock roundtrips (important for block production).
- Operational runbook sections for the new vsock service.
- Final end-to-end hard fork simulation.

**Review gate**: Comprehensive matrix on the complete increment, plus any new high-risk surfaces discovered.

## Cross-Cutting Requirements (Every Phase)

- Every commit that touches high-risk paths triggers (or is manually run with) the 3:3 matrix.
- `roborev compact --wait` is executed after each matrix for high-risk changes.
- Findings are addressed or explicitly risk-accepted with rationale before moving to the next increment.
- The implementation must stay in sync with the reviewed specs (any divergence requires re-review of both).
- Progress is tracked in TASK-2 (and linked back to TASK-1).

## Immediate Next Actions (Recommended Order)

Following user choice of **Option A** (2026-06-05):

1. **Lock the canonical preimage in the spec first** (current phase).
   - The exact `keccak256(abi.encode(...))` structure, field order, and treatment of `newHeaderVersion` / `forkSpecHash` for both ticket types has been made normative in `authorization-tickets-precompile-spec-draft.md`.
   - `newHeaderVersion` field added to the `AuthorizationTicket` struct.

2. Re-run lightweight matrix (or at least security + design cells) on the spec update.
3. Only after the canonical preimage is locked and reviewed → implement the matching logic in the Rust crate (`enclave-protocol`).
4. The implementation must produce **bit-for-bit identical** `ticketHash` as the on-chain precompile using the now-normative `abi.encode` construction.

Previous steps (initial framing, first skeletons, post-matrix fixes up to 394b73a) are considered complete.

**Current status (2026-06-05, evening)**: 
- Option A ("Lock Canonical Preimage in spec first") completed for this cycle.
- The preimage is now internally consistent and normative (`keccak256(abi.encode(...))` including `newHeaderVersion` as a real field).
- Light matrices on the locking commits came back clean / Pass.
- Hardened implementation + robust Forge JSON-exchange automation (with proper ignored test vectors) committed as `e2ee43e`.
- Fresh full 3x3 roborev matrix launched on e2ee43e (codex security, gemini security, claude-code design).

This commit includes the polished `compute_canonical_ticket_hash` now matching the locked spec, plus reliable automated cross-checks.

We are now waiting for the matrix results on this commit before deciding on the next increment or further fixes.

**Post-matrix update (same day):** 
- The 3:3 matrix on `e2ee43e` (codex security + gemini security + claude-code design) returned **Fail**.
- Two independent HIGH findings (identical root cause):
  1. `compute_canonical_ticket_hash` emitted only 7 head words; the second dynamic offset for `pqPubkey` was missing → Rust preimage could never match the normative `abi.encode` in the spec / Solidity script.
  2. The automated cross-check helper (`compute_hash_via_forge`) did not compile (`output.stderr` referenced after `.status()` call) so the headline verification feature was dead + the entire test target was broken.
- Both HIGHs were fixed immediately in a targeted follow-up (this commit):
  - Correct 8-word ABI head with proper dynamic offsets + type-aware 0-forcing for recovery (to match the ground-truth script exactly).
  - Switched to `.output()` for proper stderr capture on Forge failures.
  - The Solidity harness (`CanonicalTicketHash.s.sol` + foundry.toml + README) is now committed so the cross-check is reproducible.
- Fresh 3:3 matrix launched on the fix commit (8ea2957).
- The matrix came back with a new HIGH (identical from codex security + gemini security + claude-code design): the `pqPubkey` offset value itself was still wrong (`32 + padding` instead of `32 + meas_len + padding`). This is the same class of DoS (enclave produces unverifiable tickets) as the original bugs on e2ee43e.
- Immediate 1-line correction committed as `416d889`.
- Fresh full 3:3 matrix launched on `416d889` (current HEAD).

The automated vectors now have a real chance of passing once `cd impl/solidity && forge install foundry-rs/forge-std --no-commit` is run (one-time per checkout).

This demonstrates the process working as intended: commit → matrix → immediate fix → re-matrix, with no shortcuts even on "small math" errors.

## Success Criteria for Moving to "Real" Implementation

- Specs have been through at least one full 3:3 + compact cycle and are stable.
- The canonical encoding and proof requirements are implemented and reviewed in the skeletons.
- The hard fork announcement + transition path has been exercised end-to-end in the skeletons and reviewed with the concurrency lens.
- The process (matrix → compact → fixes) has been followed without shortcuts.

This plan ensures we carry the same rigor that caught the two HIGH issues in the design phase into the actual code.

---

## Progress update (2026-06-02)

Phase 1 reference implementation, TASK-3 crypto gate, and **TASK-1 PQ seal v1** are **on `main`** (`enclave-protocol`; **~62** tests default `cargo test`, **74** with `ml-dsa-65,pq-seal-provisioning`, **80** with `reference-test-key`). Merged: `60eeefc` (PR #1) + TASK-2 `3af56b9` (PR #3). Documentation entry points:

- `impl/README.md` — build, dispatch APIs, `pq-seal-v1` CLI
- `backlog/docs/vsock-api-wire-format-spec-draft.md` — §2.1 seal v1 + §8–§9.3 (v0.2)
- `backlog/docs/pq-seal-v1-provisioning-runbook.md` — staging operator ceremony
- `backlog/tasks/task-3` — Done

**Recommended next increments (ordered):**

1. ~~**TASK-2 PR**~~ — **Done** (merged `main` @ `3af56b9`, 2026-06-03). Review ladder: `impl/README.md`.
2. **TASK-1 staging transport (PR #4, in progress)** — ML-DSA-65 on dev UDS: `staging-host`, `enclave-uds-staging`, fail-closed without sealed signer; `2D_HSM_ENCLAVE_STAGING_SOCKET` (separate from dev mock socket).
3. **TASK-1 platform provisioning root (in progress)** — `boot_configure_pq_seal_v1_platform_root` + optional `platform-provisioning-from-file` (labs); production hook from vTPM/SNP/Nitro; **release `compile_error`** on `reference-seal-v1-root` / `staging-host`.
4. **Production vsock** — AF_VSOCK transport (Nitro/SEV); reuse `wire.rs` + **`process_framed_with_shared_state`**. Depends on TASK-1 staging signer + platform root.
5. **TASK-1 follow-ups** — verify-path zeroization debt; full operator runbook.
6. **Phase 2 (plan)** — hard-fork transition state machine beyond ticket signing. Concurrency lens when implementing.

**Session status (2026-06-03):** TASK-2 **Done** on `main`. Active: **PR #4** staging UDS + **platform provisioning root** boot hook (items 2–3).

**Task board:** `backlog/tasks/task-{1,2,3}` updated with this plan.

---

*Historical note (2026-06-05):* The sections above through "Success Criteria" record the canonical-hash review cycle (`e2ee43e` → `416d889`). That work is complete; Phase 1 code followed and is now summarized in the Phase 1 progress table.