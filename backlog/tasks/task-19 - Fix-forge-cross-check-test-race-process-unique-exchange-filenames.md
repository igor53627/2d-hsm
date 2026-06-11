---
id: TASK-19
title: 'Fix forge cross-check test race: process-unique exchange filenames'
status: To Do
assignee: []
created_date: '2026-06-11 05:51'
labels: []
dependencies: []
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Discovered by the PR #61 xhigh review (CONFIRMED, pre-existing, reproduced): compute_hash_via_forge (lib.rs ~3719) uniquifies its forge JSON exchange files with a PER-PROCESS AtomicU64 seq but writes to the SHARED impl/solidity/.forge-crosscheck/ dir — two concurrent test processes both start seq at 0 and overwrite each other's input-N.json/output-N.json, so automated_cross_check_* tests FAIL outright with cross-vector hash swaps (assert at lib.rs:3533 reads like a real canonical-encoding regression). Sequential runs are 55/55 clean. Fix: include std::process::id() in the exchange filenames + unlink output_path pre-run (the dir is never cleaned). Repro: 3 concurrent default-feature test binaries with filter automated_cross_check fail every round.
<!-- SECTION:DESCRIPTION:END -->
