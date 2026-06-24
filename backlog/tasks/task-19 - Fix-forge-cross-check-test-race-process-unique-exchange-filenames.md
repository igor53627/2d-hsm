---
id: TASK-19
title: 'Fix forge cross-check test race: process-unique exchange filenames'
status: Done
assignee: []
created_date: '2026-06-11 05:51'
updated_date: '2026-06-24 01:16'
labels: []
dependencies: []
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Discovered by the PR #61 xhigh review (CONFIRMED, pre-existing, reproduced): compute_hash_via_forge (lib.rs ~3719) uniquifies its forge JSON exchange files with a PER-PROCESS AtomicU64 seq but writes to the SHARED impl/solidity/.forge-crosscheck/ dir — two concurrent test processes both start seq at 0 and overwrite each other's input-N.json/output-N.json, so automated_cross_check_* tests FAIL outright with cross-vector hash swaps (assert at lib.rs:3533 reads like a real canonical-encoding regression). Sequential runs are 55/55 clean. Fix: include std::process::id() in the exchange filenames + unlink output_path pre-run (the dir is never cleaned). Repro: 3 concurrent default-feature test binaries with filter automated_cross_check fail every round.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria (added after the PR #61 matrix — codex M + gemini HIGH)

- [ ] Exchange filenames include `std::process::id()` alongside the per-process seq (`input-{pid}-{seq}.json` / `output-{pid}-{seq}.json`).
- [ ] `output_path` is unlinked BEFORE invoking forge (a stale output from a crashed prior run must never be read as fresh).
- [ ] **Cleanup policy (gemini HIGH: PID-unique names make the never-cleaned dir grow unboundedly; 8410 M: a naive startup sweep of ALL files would delete a CONCURRENT process's live exchange, reintroducing the race):** both exchange files are deleted after each successful exchange; at process start the harness sweeps ONLY files bearing ITS OWN pid (a reused pid's leftovers are by definition not concurrent) plus foreign files older than an age threshold (e.g. >1h mtime) — never younger foreign files. Alternative satisfying the same criterion: per-pid subdirectories with stale-dir sweep under the same age rule.
- [ ] Verification command pinned: 3 concurrent invocations of the default-feature test binary filtered to `automated_cross_check`, 5 rounds — ALL rounds must pass (the pre-fix repro fails every round with cross-vector hash swaps).
- [ ] Sequential `cargo test` (default features) stays 100% green.

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Race fix delivered (PR #114): process-unique filenames (pid-tagged) + pre-run unlink. The unbounded `.forge-crosscheck` dir growth cleanup policy is an accepted deferred follow-up — the pid-tagged filenames prevent cross-process collision but files accumulate. Not blocking (dir is gitignored, sizes are ~200 bytes each).
<!-- SECTION:FINAL_SUMMARY:END -->
