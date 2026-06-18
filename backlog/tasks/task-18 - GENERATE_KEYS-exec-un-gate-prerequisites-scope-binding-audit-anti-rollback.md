---
id: TASK-18
title: >-
  GENERATE_KEYS exec un-gate prerequisites (scope-binding + audit +
  anti-rollback)
status: To Do
assignee: []
created_date: '2026-06-08 19:05'
labels:
  - agent-gateway
  - security
  - hardening
dependencies:
  - TASK-7.7
priority: high
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
GENERATE_KEYS live execution is implemented behind the off-by-default, release-banned agent-keygen-exec-preview feature (PR #44). Before it can be enabled in production these prerequisites — surfaced by the TASK-7.6.x Full Matrix as blockers for a host-untrusted fund-custody mutation — must land. Until then production verifies the capability then fails closed (AGENT_NOT_CONFIGURED).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 scope_target ↔ sealed-local-enclave-identity binding: bind cap.scope_target to a sealed enclave/fleet id (installed/derived at boot) and byte-compare before mutation, so an 'enclave-scoped' (scope_class=0) cap minted for enclave A cannot be replayed on a clone B (whose counter row for that tuple is empty) to mint a second treasury key — the AC#12 budget-multiplication guard. Enforce command-class scope_target (generate_transfer/generate_faucet) too.
- [ ] #2 AC#14 privileged-op audit record: append an AuditRecord (op, authority, counter, config_version) to candidate.audit in the same sealed commit as GENERATE_KEYS (and every privileged mutation), and enforce last_exported_seq backpressure (fail closed rather than overwrite un-exported entries).
- [ ] #3 Anti-rollback durable commit (TASK-7.7): the in-memory swap currently precedes host persistence, so a host can drop the returned sealed blob, reboot from the prior blob, and replay the one-shot capability to re-mint keys. Wire the freshness_epoch advance against the pinned anchor (or an equivalent durable monotonic anchor / persist-ack commit) so a consumed counter cannot be rolled back. Only then un-gate (remove the release ban / flip the feature on).
<!-- AC:END -->

## Notes
<!-- SECTION:NOTES:BEGIN -->
**Understand phase (2026-06-19) — status + locked plan.**

AC#2 (audit) and AC#3 (durable anchor commit) are **DONE, preview-gated**: `record_audit` is wired into all three live handlers (4b/4c, PRs #96–#99) with backpressure in `record_audit`; `commit_before_emit` enforces seal→anchor-commit→swap (TASK-7.7 slice 6). They are satisfied for the preview build; un-gating is the remaining lift, contingent on AC#1.

AC#1 (scope-binding) is the remaining security blocker and needs a **sealed identity that does not exist yet** — `KeystoreConfig` has no per-enclave id, and measurement/anchor_root/treasury_id are all clone-identical.

**Locked maintainer decisions (2026-06-19):** (Q1) the sealed identity = a **provisioned random `enclave_id`** (+ a shared `fleet_id`) sealed into `KeystoreConfig` at provisioning — implementable now, no deferred real-SNP-measurement dependency. (Q2) **separate field** `enclave_scope_id` — `scope_target` STAYS the command-class lane label (counter-tuple semantics unchanged); the identity pin is an independent byte-compare. (Q3) AC#1 scope = **replay-on-empty-row guard ONLY**; the concurrent honest-clone double-budget hole (needs a global append-only ledger, "Option B") is an EXPLICIT non-goal, deferred + documented, tracked as a TASK-20/Option-B follow-up. (Q6) the production agent-gateway image + attested host-vsock keystore-install channel (**G3 — no production agent-gateway image exists today**; every build is debug + `lab-agent-keystore-from-file`) is carved into a **SEPARATE TASK** (independent of AC#1; needs nix/aya work).

**Un-gate is PER-OP** (each preview = an independent Cargo feature + `compile_error!` ban + `#[cfg(feature)]` dispatch arm). Safe order: prove-identity → sign-transfer → keygen → configure-treasury → sign-faucet → backup-export (LAST). **RESTORE stays banned** (no handler — TASK-24; export-only un-gates here). Per-op un-gate = remove the one `compile_error!` (lib.rs) + add the feature to the release `buildFeatures` (enclave.nix) + provision the runtime anti-rollback gate for rollback-sensitive ops — in ONE change.

**Slicing (this task = scope-binding feature; the production image is a separate task):**
- **18-1** (NEXT): add sealed `enclave_scope_id: [u8;32]` + `fleet_scope_id: [u8;32]` to `KeystoreConfig` (agent_keystore.rs:564), installed at provisioning. Sealed-body layout change ⇒ **`KEYSTORE_FORMAT_VERSION` 3→4** + re-freeze the genesis + smoke goldens + thread through ~22 `KeystoreConfig{}` constructors (no serde-default — required, fail-closed, like `structural_version`). Field INERT (no verifier change yet).
- **18-2**: the verifier byte-compare in `verify_capability_extract_inner` (agent_capability.rs, after the chain/env compare) — `scope_class==0`→`enclave_scope_id`, `scope_class==1`→`fleet_scope_id`; `0x43`; test clone-B-replay-of-A-cap ⇒ 0x43 with empty counter row.
- **18-3**: command-class `scope_target` validation (whitelist `{generate_transfer, generate_faucet, configure_treasury, ...}`; no handler trusts an unvalidated class).
- **18-4**: docs — AC#1 closes replay-on-empty-row, NOT active-active (Option B deferred); reconcile anti-rollback.md / vsock §10.6.
- **(separate task)** production agent-gateway release image + attested keystore-install channel (G3).
- **18-6..9**: per-op un-gate in the order above, after 18-2/18-3 + the production image.

Source: TASK-18 Understand workflow (2026-06-19, 5-agent). Full plan in the session transcript.
<!-- SECTION:NOTES:END -->
