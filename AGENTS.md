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
- `impl/` — reference enclave protocol and signing state machine
- Any future `src/` code that implements ticket signing, `ARM_FOR_PRODUCTION`, hard fork transition logic, or key lifecycle inside the TEE

See `.roborev.toml` for the machine-readable definition.

## Review Process for High-Risk Changes

We follow the **Multi-Agent Code-Review Playbook** (see the full playbook at the linked gist in the project history).

### Core Rule
**Independent perspectives before an irreversible step.**

For every high-risk change:
- Run at least the **Reduced Matrix** (4 reviews: codex security, gemini security, claude-code design, grok security) — see "Reduced vs Full Matrix" below and `.roborev.toml`
- Use `roborev compact` (or equivalent consolidation) before considering the change "reviewed"
- Run the **Full Matrix** when the decision rules below require it
- Major or architecture-changing work also gets a human gate

### Current Matrix (as of 2026-06)
- Agents: codex, gemini, claude-code, grok (vendor diversity across lineages). Grok has no native roborev agent — it runs via the `opencode` agent (`--agent opencode --model xai/grok-4.3`, auth = `XAI_API_KEY` in the daemon env).
- Lenses: `security` + `design` (roborev CLI); **concurrency-sensitive** work adds `design` with `--reasoning maximum` (see `~/pse/roborev/pse-review-2x3.sh`)
- Config lives in `.roborev.toml` at repo root; shared scripts in `~/pse/roborev/`
- **grok-cell precondition (verify, don't assume):** the opencode/grok cell only authenticates if the roborev **daemon** has `XAI_API_KEY` in its env (true if the daemon was started from a login shell; if not, `roborev daemon restart` from one). A missing/empty key does **not** fail loudly: roborev maps the opencode agent's non-zero exit to status **`skipped`** (not `failed`), and **`roborev compact` ignores `skipped` jobs** — so an absent grok review is silently treated as clean unless you check. Therefore: confirm the grok cell actually reached **`done`** (run `roborev review --dirty --agent opencode --model xai/grok-4.3 --type security --wait` and check it returns a review, or inspect the job status), treat any non-`done` grok cell as a **gap, never as compacted-clean**, and if xAI is genuinely unavailable, note the missing cell explicitly rather than degrading silently to 3 cells.

### Reduced vs Full Matrix — Decision Rules

For high-risk work we distinguish two levels of review:

**Reduced Matrix** (default practical 4-review set)
- security + codex
- security + gemini
- design + claude-code
- security + grok (via the `opencode` agent, `xai/grok-4.3`)

This is the normal operating mode for incremental work inside an already-reviewed direction.

**Full Matrix** (more complete coverage)
- The four reviews above (the full Reduced Matrix, grok included — Full ⊇ Reduced), plus the **2×3 concurrency floor** from `~/pse/roborev/pse-review-2x3.sh` (codex + gemini × security + design + design-max), or equivalent manual cells with explicit `--model` per agent

**When Full Matrix is required (mandatory):**
- First introduction of significant state / state machine logic (e.g., `EnclaveState`, arming state, freshness tracking).
- The change meaningfully touches **two or more lenses** at the same time (security + design + concurrency concerns).
- Previous matrix on the same topic found HIGH findings (or multiple MEDIUMs that create doubt).
- We are making changes to core authorization / gating behavior (who can sign what, under which conditions, with which proof).
- Concurrency or ordering issues are material (e.g., interaction between `ARM_FOR_PRODUCTION`, `SIGN_AUTHORIZATION_TICKET`, and `GET_STATUS`).

**When Reduced Matrix is acceptable:**
- Small follow-up fixes or polish inside a direction that already passed a Full Matrix.
- Purely additive changes with narrow impact (e.g., adding a new test vector or improving an error message).
- The change is low-risk by nature and previous matrices on the area were clean.

**Rule of thumb:** When in doubt, run Full. The cost of one extra review is much lower than the cost of a missed HIGH on TEE signing or hard-fork logic.

After any matrix (Reduced or Full), the consolidation step (`roborev compact` or equivalent) + explicit resolution of findings remains mandatory.

### How to Run a Review

See the "Reduced vs Full Matrix" section above for when to use which level.

**Typical Reduced Matrix (most common):**
```bash
~/pse/roborev/pse-review-reduced.sh --dirty   # 4 cells: codex+gemini security, claude-code design, grok security
# …or run the cells by hand:
roborev review --dirty --type security --agent codex --model gpt-5.5
roborev review --dirty --type security --agent gemini --model gemini-3.1-pro-preview
roborev review --dirty --type design --agent claude-code --model opus
roborev review --dirty --type security --agent opencode --model xai/grok-4.3   # grok lens
```

**Full Matrix (when required by the rules above):**
```bash
# Reduced Matrix (all four cells above, grok included), then from repo root:
~/pse/roborev/pse-review-2x3.sh --dirty   # 2×3 concurrency floor
~/pse/roborev/pse-review-3x3.sh --dirty   # optional 3×3 vendor sign-off
```

After the matrix, always run consolidation:
```bash
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

See `.roborev.toml` for the full agent and lens list.

In practice we distinguish two operating modes (see "Reduced vs Full Matrix — Decision Rules" above):

- **Reduced Matrix** (the practical default for most incremental high-risk work)
- **Full Matrix** (required for first introduction of state machines, changes touching multiple lenses, after HIGH findings, etc.)

Any modification to the vsock protocol, ticket canonicalization, arming logic, hard-fork transition, or TEE key decisions is automatically high-risk and requires a matrix (Reduced or Full, per the rules) before being considered reviewed.

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