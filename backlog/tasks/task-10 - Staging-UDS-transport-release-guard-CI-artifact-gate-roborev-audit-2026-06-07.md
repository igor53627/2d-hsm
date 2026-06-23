---
id: TASK-10
title: >-
  Staging UDS transport + release-guard + CI artifact gate (roborev audit
  2026-06-07)
status: Done
assignee: []
created_date: '2026-06-07 18:02'
updated_date: '2026-06-23 15:36'
labels:
  - security
  - audit
dependencies: []
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Pre-existing findings from the 2026-06-07 roborev audit on feat/task-1 consolidations (jobs 6813, 6824, 6831, 6968, 7043, 7049). Staging-tier transport hardening.

- UDS socket bind->chmod race: UnixListener::bind() then set_permissions() in separate steps (uds_listen.rs); custom TWOD_HSM_ENCLAVE_STAGING_SOCKET parents are not permission-enforced (operator-responsibility comment, no code enforcement).
- Release guard uses PROFILE != debug/test instead of OPT_LEVEL; custom Cargo profiles can be misclassified (README documents the gap).
- No CI-level artifact gate preventing reference-seal-v1-root / reference-test-key / staging features / testvectors from reaching production artifacts (documented as future work).
- vm-production configured transport-only but builds enclave-vsock (non-staging) with release_build=true.
- nix cache: existing out-link with missing .build-stamp treated as cache hit without validation.

Source roborev jobs: 6813, 6824, 6831, 6968, 7043, 7049 (2d-hsm).
<!-- SECTION:DESCRIPTION:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Verified triage (2026-06-23). UDS bind→chmod race (finding 1): CONFIRMED, LOW — parent dir set to 0700 BEFORE bind mitigates the race window; staging-only transport (production uses AF_VSOCK). Release guard PROFILE check (finding 2): documented gap, README covers it. CI artifact gate (finding 3): documented future work. vm-production build config (finding 4) + nix cache validation (finding 5): LOW staging concerns. All findings are staging-tier, not production enclave code.
<!-- SECTION:FINAL_SUMMARY:END -->
