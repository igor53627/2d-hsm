---
id: TASK-20
title: >-
  roborev residual findings from TASK-7.7 (d-ii) slices — doc-wording +
  test/code hardening
status: To Do
assignee: []
created_date: '2026-06-11 19:38'
labels: []
dependencies: []
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Captured from the roborev backlog drain (2026-06-11) so the 47 stale open consolidated-review rows on now-deleted squash-merged TASK-7.7 branches could be closed (audit-before-close per CLAUDE.md hygiene; compact cannot reach deleted-branch jobs). All 8 terminal-residual findings below are Low/Medium, non-blocking, from FULLY-merged+gated slices. NB the §8 doc has been rewritten many times since these fired (#56-#63) — verify each doc finding against CURRENT agent-gateway-anti-rollback.md before acting; some may already be resolved.

DOC-WORDING (§8 / task-docs — verify-against-current first):
- [8022 strict-cbor] §8 describes strict_decode_map as accepting "CBOR arrays and maps up to the caps", but it rejects any non-map TOP-LEVEL item (arrays only nested). Reword: requires a top-level definite-length map; nested arrays/maps allowed subject to caps.
- [8324 quote-hard-bound] §8 ε caveat: "the runtime hard bounds remain the per-leg deadlines themselves" is too strong for the QUOTE leg (spawn/setup + dispose/reap happen OUTSIDE the pipe deadline). Reword: only the cancellable pipe/channel WAITS are deadline-enforced at runtime; the ε product is nominal sizing arithmetic. (Likely partly addressed by the #60 "ε is NOMINAL, not a runtime ceiling" edits — verify.)
- [8325 boot-relay-quote-leaf] §8 ~829/871 contradiction: "two enforceable artifacts, not checklist lines" vs a later paragraph calling the (d) wrapper precondition "only a checklist obligation, not a compile error". (Likely STALE — the never-generic-Q + (d)-FULLY-CLOSED rewrites since #61-#63 reconciled this; verify it still exists.)
- [8024 ac5-funding-gate] The deferred owner-mapping assigns the AC#10 measured/sealed opt-out + Layer-2a release compile_error! to TASK-18, but TASK-18's ACs only track scope-binding/audit/durable-commit. Add explicit TASK-18 ACs (or notes) for those AC#5 deliverables so closing TASK-18 from its own ACs can't miss them.

CODE / TEST HARDENING:
- [8327 boot-handshake-driver, Medium] agent_anti_rollback_serve_gate is pub(crate) + raw booleans → in-crate wiring could bypass decide_serve and serve after FailClosed(BindingInstall) when a prior binding stays installed. Make the raw gate private to agent_boot_driver.rs; expose only decide_serve for handshake-backed boot (or a deliberately-named unwired wrapper). NB: (4b) run_boot_handshake_wired is the canonical entry now — confirm the raw gate has no remaining legit caller.
- [8310 boot-relay-protocol, Medium] No regression test for per-leg deadline freshness: MockChannel ignores the supplied channel deadline, so a future change reusing the quote deadline for the channel leg would pass while silently shrinking the relay budget. Add a fake quote/channel seam test that records both deadlines + injects quote latency + asserts the channel gets a freshly-computed deadline. (The §8 "wiring-enforced in round_trip_inner, re-verify on refactor" pin is the prose guard this would harden.)
- [8025 format-v2-structural-marks, Low] structural_version_zero_fails_validation only exercises validate() directly — wouldn't catch seal_body()/unseal_body() dropping the check at the sealed-blob boundary. Extend: assert seal_body() rejects structural_version=0, and that unseal_body() of an invalid-but-sealed body returns KeystoreError::InvalidStructuralVersion.
- [8494 quote-smoke, Low] The lab-only quoteSmokePackage Nix guard (quoteSmokePackage==null || !productionMode) has no FAIL-side regression check — a negative tryEval test (productionMode=true + quoteSmokePackage set ⇒ expect assertion failure) would make the guard self-testing. (Currently eval-enforced for the lab image + documented; declined inline at #63 as disproportionate, parked here.)

Source: roborev jobs 8022/8024/8025/8310/8324/8325/8327/8494 (terminal consolidations of the respective deleted branches). All other open rows on those branches were superseded-clean intermediate compacts.
<!-- SECTION:DESCRIPTION:END -->
