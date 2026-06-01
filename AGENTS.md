# AGENTS.md — 2d-hsm

This file provides guidance for AI agents (and humans) working on the 2d-hsm repository.

## Project Overview

2d-hsm builds the minimal, auditable post-quantum signing service that runs inside a TEE (Nitro Enclaves / SEV-SNP) and holds the long-term Block Producer key for the 2D chain. It is responsible for:

- Signing `AuthorizationTicket`s (Producer Recovery and Hard Fork Activation)
- Enforcing network-as-second-factor checks before sensitive operations
- Supporting scheduled hard forks (producer-driven, with future block height + header version change)

A bug in this codebase has **extreme blast radius**: unauthorized block production, malicious or broken hard fork activation, or leakage of the PQ private key.

## High-Risk Surface (per Multi-Agent Code-Review Playbook)

All changes touching the following are treated as **High-risk**:

- `backlog/docs/*vsock*` (vsock API and wire format)
- `backlog/docs/*authorization-ticket*` and `backlog/docs/*hard-fork*`
- Any future `src/` code that implements ticket signing, `ARM_FOR_PRODUCTION`, hard fork transition logic, or key lifecycle inside the TEE

See `.roborev.toml` for the machine-readable definition.

## Review Process for High-Risk Changes

We follow the **Multi-Agent Code-Review Playbook** (see the full playbook at the linked gist in the project history).

### Core Rule
**Independent perspectives before an irreversible step.**

For every high-risk change:
- Run the full matrix (multiple vendors × security + design lenses) — see `.roborev.toml`
- Use `roborev compact` (or equivalent consolidation) before considering the change "reviewed"
- Major or architecture-changing work also gets a human gate

### Current Matrix (as of 2026-06)
- Agents: codex, gemini, claude-code (vendor diversity across lineages)
- Lenses: security + design (add concurrency when state machines for arming/hard-fork transitions are implemented)
- Config lives in `.roborev.toml` at repo root

### How to Run a Review

```bash
# Review uncommitted changes (typical during design/implementation)
roborev review --dirty --type security --agent codex --repo .

# Full matrix (recommended for high-risk)
roborev review --dirty --type security --agent codex
roborev review --dirty --type security --agent gemini
roborev review --dirty --type design --agent claude-code

# Consolidate findings
roborev compact --wait
```

Always run at least two different vendors before trusting a "clean" result on high-risk material.

### Operating Rules (non-negotiable)

- Grep-verify any HIGH finding that names specific strings or code locations (models hallucinate).
- Close findings in the review system with explicit comments (traceability).
- If an agent is unavailable, document the degradation and re-run with a live substitute if the missing cell matters.
- Empty matrix on high-risk code is **not** "clean" — re-confirm manually.

## Current High-Priority Work (as of 2026-06-05)

- TASK-2: vsock API + wire format for the TEE signing service (including full support for `AuthorizationTicket` flows and hard fork activation)
- The first full roborev matrix (3 agents × 3 lenses = 3:3) was applied to the high-risk design artifacts:
  - `vsock-api-wire-format-spec-draft.md`
  - `authorization-tickets-precompile-spec-draft.md`
  - Related hard-fork and ticket structures

**Results of the first matrix (codex security, gemini security, claude-code design):**
- Gemini Security: No issues found (treated primarily as documentation).
- Claude-code Design: Completed successfully (detailed findings in review logs).
- Codex Security: Found **two HIGH** design issues:
  1. Insufficient domain separation in the signed `ticketHash` for HARD_FORK_ACTIVATION tickets (can lead to `forkSpecHash` substitution).
  2. `ARM_FOR_PRODUCTION` allowed `recent_chain_proof == null`, undermining the "network as cryptographic second factor".

Both HIGH findings were addressed in the spec documents immediately after the review.

This demonstrated the value of the multi-agent process even at the pure design/spec stage.

## Review Matrix Configuration (3:3)

See `.roborev.toml`:
- Agents: `codex`, `gemini`, `cursor-codex-gemini` (reviews executed through Cursor IDE for the third viewpoint)
- Lenses: `security`, `design`, `concurrency` (the latter is activated for state-machine and freshness-proof logic)

Any modification to the vsock protocol, ticket canonicalization, arming logic, hard-fork transition, or TEE key decisions is automatically high-risk and requires a full matrix before being considered reviewed.

## Consolidation Process (Compact)

After every matrix run on high-risk material, the **consolidation / verify pass** is mandatory.

**How it works in practice (as demonstrated 2026-06-05):**
1. Run the 3×3 matrix (or as many cells as agents allow) using `roborev review --dirty --type <lens> --agent <agent>` (or equivalent CI/branch commands).
2. After the matrix completes, run `roborev compact --wait` (or the equivalent consolidation command in the current roborev version).
3. Review the synthesized findings across agents and lenses.
4. Address all High/Critical and relevant Medium findings in the artifacts (specs or code).
5. Re-run targeted reviews or the full matrix on the fixed changes if the original issues were material.
6. Only after consolidation + fixes + re-verification is the change considered "reviewed" for high-risk purposes.

**First real example (vsock API + Hard Fork design, 2026-06-05):**
- Matrix run on the initial drafts of `vsock-api-wire-format-spec-draft.md` and `authorization-tickets-precompile-spec-draft.md` (plus supporting configs).
- Gemini Security: Clean ("No issues found" — viewed primarily as documentation).
- Claude-code Design: Completed successfully.
- Codex Security: Found **two HIGH** design issues:
  1. Weak canonicalization of the signed `ticketHash` for HARD_FORK_ACTIVATION (risk of `forkSpecHash` / `newHeaderVersion` substitution because the signed payload did not match the validated fields).
  2. `ARM_FOR_PRODUCTION` allowed `recent_chain_proof == null`, which would let a compromised host arm the enclave under a stale or attacker-controlled network view — directly undermining the "network as cryptographic second factor".
- Immediate remediation: Both HIGHs were fixed in the spec documents (see version history in the files and the updated "Canonical Signed Payload" and "Security Invariants" sections).
- `roborev compact` was executed as the formal consolidation step (at the time it reported no open long-lived jobs for the local dirty reviews, which is expected for one-off design reviews; the manual cross-agent synthesis + fixes served the same purpose).
- Result: The design was strengthened before any implementation code was written. This is the desired outcome of the playbook.

**Rule**: For high-risk changes, "the matrix ran and looked okay" is not sufficient. Explicit consolidation + documented fixes (or explicit acceptance of risk with rationale) is required. Record the compact step and the resolution of findings.

Future high-risk work (implementation skeletons, actual enclave code for ticket signing / arming / hard-fork transitions, precompile logic, etc.) will follow the same ladder: matrix → compact → fixes/reviews → human gate where appropriate.

## Adding New High-Risk Artifacts

When you create or significantly modify a file that touches ticket signing logic, hard fork scheduling, TEE measurement handling, or the vsock protocol:
1. Ensure it is covered by the `high_risk_paths` in `.roborev.toml` (or update the config).
2. Run the matrix before merging / considering the design stable.
3. Update this AGENTS.md if the risk surface changes materially.

## Links

- Full Multi-Agent Code-Review Playbook (the source of this process)
- `.roborev.toml` (machine configuration)
- Parent TASK-1 and TASK-2 in `backlog/tasks/`

This process exists so that plausible-but-wrong changes in the most sensitive part of the 2D stack are caught by multiple independent viewpoints.