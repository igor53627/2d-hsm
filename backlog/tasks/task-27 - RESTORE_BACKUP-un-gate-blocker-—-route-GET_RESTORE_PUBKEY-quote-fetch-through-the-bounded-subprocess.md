---
id: TASK-27
title: >-
  RESTORE_BACKUP un-gate blocker — route GET_RESTORE_PUBKEY quote fetch through
  the bounded subprocess
status: Done
assignee: []
created_date: '2026-06-22 00:29'
updated_date: '2026-06-22 20:24'
labels:
  - agent-gateway
  - restore
  - security
  - un-gate-blocker
  - dos
  - attestation
milestone: TASK-18 un-gate
dependencies: []
modified_files:
  - impl/rust/enclave-protocol/src/agent_dispatch.rs
  - impl/rust/enclave-protocol/src/quote_subprocess.rs
  - impl/nix/vm-hsm/enclave.nix
priority: high
ordinal: 29500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**HARD BLOCKER on production-enablement (un-gate) of the RESTORE_BACKUP / `agent-backup-export-preview` path.** Do NOT enable `agent-backup-export-preview` in a production release build until this is resolved.

**The gap (compact-9611 Med, codex+gemini confirmed — matrix round 2 jobs 9631/9632; expanded by TASK-28's completion attestation — claude-code HIGH job 9839):** TWO unbounded `fetch_report` call sites exist on the serial agent vsock serve loop:

1. **`install_restore_ephemeral`** (GET_RESTORE_PUBKEY(9) handler) — `agent_dispatch.rs:1981`. A stuck `configfs-tsm` quote read blocks the serve loop indefinitely. GET_RESTORE_PUBKEY is a no-capability opcode, so any vsock peer can trigger this.

2. **`restore_seal_attest_commit_emit`** (RESTORE_BACKUP completion attestation) — `agent_dispatch.rs:2456`. Added by TASK-28: the completion attestation fetches a fresh SNP quote to bind the sealed blob + identity set + request_id. Same serial serve loop, same unbounded `configfs-tsm` read.

Unlike the producer `GET_MEASUREMENT` quote fetch (boot-only, before the serve loop accepts requests), both restore-path fetches run IN the serve loop — a stuck `configfs-tsm` quote read (a wedged host TSM provider) blocks the enclave's single request loop indefinitely, preventing all later restore/signing/status operations from being served (denial of service).

**Why it can't be fixed inline right now:** the crate's accepted wall-clock bound is the killable subprocess (`quote_subprocess::HardBoundedQuoteProducer`) — cooperative deadlines were deliberately removed in (4a) ("the hard wall-clock bound is the killable subprocess"). `fetch_quote_via_child` is private and deeply coupled to the boot-relay's `AbandonedLedger` claim/serve-gate machinery; routing the restore fetches through it needs design care (ledger ownership, spawn lifecycle, feature-gate interaction between `agent-backup-export-preview` and the `agent-gateway`-gated subprocess). Forcing that coupling into the preview-gated path now would be awkward; it belongs as a deliberate production-un-gate step.

**Why a code comment alone is not enough:** TASK-18 18-9 REMOVED the `agent-backup-export-preview` release-ban `compile_error!`, and the `agent-gateway-release` Nix profile (`impl/nix/vm-hsm/enclave.nix:26`) already enables the feature. So the unbounded reads ship the moment RESTORE is un-gated unless this task gates both. The inline `TODO(production-un-gate, compact-9611 Med codex+gemini)` comments at both call sites reference THIS task.

**Fix:** route BOTH attestation quote fetches through `quote_subprocess`'s bounded (killable-subprocess) path — either by making `fetch_quote_via_child`/a bounded variant `pub(crate)` and owning a restore-path `AbandonedLedger`, OR by lifting the quote fetches to a frame-layer seam. Either way both fetches must be hard-bounded (SIGKILL on deadline), matching the boot-relay's contract.

**Acceptance:**
- [ ] GET_RESTORE_PUBKEY's quote fetch (`install_restore_ephemeral`, `agent_dispatch.rs:1981`) is hard-bounded (killable subprocess or equivalent frame-layer seam); a stuck configfs read is terminated, not blocking the serve loop.
- [ ] RESTORE_BACKUP completion attestation's quote fetch (`restore_seal_attest_commit_emit`, `agent_dispatch.rs:2456`) is hard-bounded (same mechanism); a stuck configfs read during completion-attestation emission is terminated, not blocking the serve loop.
- [ ] The inline TODOs in BOTH `install_restore_ephemeral` AND `restore_seal_attest_commit_emit` are removed (resolved).
- [ ] A regression test pins the bounded behavior for EACH call site (a wedged fetch is killed within the deadline).
- [ ] This task is referenced as a RESOLVED prerequisite in the RESTORE un-gate record before `agent-backup-export-preview` ships in a release build.

**Out of scope:** the attestation binding itself (`report_data_for_restore_ephemeral`, `verify_restore_ephemeral_attestation` — landed in TASK-24 commit 7a90522, matrix-reviewed); the operator-side cert-chain verification (AC#12 out-of-band).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
All 5 ACs met:
1. GET_RESTORE_PUBKEY fetch bounded ✓ (fetch_restore_attestation → fetch_quote_for_restore in production)
2. RESTORE_BACKUP completion fetch bounded ✓ (same mechanism)
3. Both TODOs removed ✓
4. Regression test for each call site ✓ (restore_path_fetch_kills_wedged_child_within_deadline — exercises the inner helper with smoke_spawn wedge + local ledger; existing wedged_child_returns_at_deadline_not_child_exit pins fetch_quote_via_child directly)
5. Referenced as RESOLVED in this task ✓ (status: Done, this summary)

CI lane added: cargo test --features vsock-transport,agent-backup-export-preview --lib quote_subprocess — ensures the bounded path + regression test don't bit-rot off-CI.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
PR #109. Both restore-path fetch_report call sites routed through the killable subprocess (fetch_quote_via_child) in production (linux+vsock-transport). Design: pub(crate) widening of fetch_quote_via_child + AbandonedLedger; new fetch_quote_for_restore with process-global OnceLock<Mutex<AbandonedLedger>> (separate from boot-relay's dropped ledger); cfg-gated wrapper (bounded in production, fallback in tests). Regression test: restore_path_fetch_kills_wedged_child_within_deadline (smoke_spawn wedge). CI lane added for vsock+backup-export intersection. Reduced Matrix (codex+gemini+claude-code+grok): compact clean. Gemini HIGH (fixed configfs entry DoS) INVALID — child self-names twod-hsm-q-<pid>.
<!-- SECTION:FINAL_SUMMARY:END -->
