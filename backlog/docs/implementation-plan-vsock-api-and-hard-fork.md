# Implementation Plan: vsock API + Hard Fork Support (Post-Spec Phase)

**Date**: 2026-06-05  
**Status**: Draft plan following the first successful roborev matrix on the design specs  
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
- Incorporate any remaining feedback from the full matrix (once the last cell is fully analyzed).
- Re-run targeted matrix cells (or full 3:3) on the updated spec documents after the Codex HIGH fixes.
- Run `roborev compact` and record the outcome.
- Update this plan and AGENTS.md with any new invariants.
- **Review gate**: Full matrix + compact on the final spec revisions.

**Deliverable**: "v0.2" of the two main spec files, explicitly marked as reviewed via roborev.

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

### Phase 2 – Hard Fork Specific Flows (First-Class Citizen)
- End-to-end support for announcing and transitioning on a scheduled hard fork:
  - Signing a HARD_FORK_ACTIVATION ticket with the correct fields (`forkSpecHash`, `newHeaderVersion`).
  - Internal state in the enclave for "pending hard fork at height X with new measurement Y and header version Z".
  - Behavior around the activation height (refuse old-version signatures after the point, etc.).
- Integration points with the future header version field in 2D blocks.
- Simulation of a hard fork transition (including what a compromised host might try).

**Review gate**: Dedicated 3:3 matrix focused on the hard-fork state machine and transition logic. Must include concurrency lens.

### Phase 3 – Production Authorization & Network Second Factor (Strengthening)
- Full implementation of freshness proof validation (what formats are accepted, how the enclave verifies recent finalized state or authorization tickets).
- Rate limiting / replay protection on sensitive commands.
- Clear arming lifecycle and what happens on proof failure or stale state.
- Logging / observability that does not leak secrets.

**Review gate**: Full matrix + compact, with emphasis on the proof verification code path.

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

1. Finish analyzing the remaining matrix cell(s) and perform formal consolidation (`roborev compact` + manual synthesis).
2. Apply any final spec tweaks and re-run a lightweight matrix on the updated docs.
3. Update AGENTS.md and this plan with the exact outcome of the consolidation step.
4. **Done (2026-06-05)** — Initial framing + first command skeletons committed as `0262bd5` ("feat: initial vsock protocol framing skeleton (Phase 1 start)").
5. Full 3:3 matrix launched on commit 0262bd5 (codex security, gemini security, claude-code design). This is the first real code review under the high-risk process.

Next: After matrix results, address any findings, run `compact`, then expand the crate with SignAuthorizationTicket etc.

## Success Criteria for Moving to "Real" Implementation

- Specs have been through at least one full 3:3 + compact cycle and are stable.
- The canonical encoding and proof requirements are implemented and reviewed in the skeletons.
- The hard fork announcement + transition path has been exercised end-to-end in the skeletons and reviewed with the concurrency lens.
- The process (matrix → compact → fixes) has been followed without shortcuts.

This plan ensures we carry the same rigor that caught the two HIGH issues in the design phase into the actual code.

---

**Next concrete step for the team**: Confirm the consolidation of the first matrix is complete, then green-light the start of Phase 1 skeletons with the review gates explicitly scheduled.