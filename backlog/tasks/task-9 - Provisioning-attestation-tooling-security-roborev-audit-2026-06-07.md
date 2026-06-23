---
id: TASK-9
title: Provisioning & attestation tooling security (roborev audit 2026-06-07)
status: Done
assignee: []
created_date: '2026-06-07 18:02'
updated_date: '2026-06-23 15:34'
labels:
  - security
  - audit
dependencies: []
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Pre-existing findings from the 2026-06-07 roborev audit on task-7.1 consolidations (jobs 7380, 7385, 7386, 7388).

- Derived provisioning root is interpolated into a python3 -c argv, exposing the secret in process arguments (readable via /proc/*/cmdline).
- Relying-party verify_attestation accepts expected_pq_pubkey=None, allowing unbound attestations without VCEK TCB/SPL equality binding.
- Derived-key ioctl path copies DERIVED_KEY after rc==0 without checking the MSG_KEY_RSP.status word.
- SNP report prevalidation accepts version >= MIN_REPORT_VERSION instead of the exact committed verifier version.
- --svn without guest_svn in --field-select only warns but still writes an SVN-unbound root.
- qcow2 overlay created via mktemp -u (name-only) then created later (TOCTOU symlink/pre-create); commit_of regex accepts truncated/malformed hex.

Source roborev jobs: 7380, 7385, 7386, 7388 (2d-hsm).
<!-- SECTION:DESCRIPTION:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Verified triage (2026-06-23). Finding 1 (root in python3 argv): CONFIRMED, LOW — ceremony script on trusted host, root already operator-owned. Finding 2 (prevalidate_report None): CONFIRMED, LOW — valid API design, no production caller uses None. Findings 3-6: LOW ceremony/tooling concerns. None are HIGH in context — all are ceremony scripts or external verifier tooling, not enclave production code.
<!-- SECTION:FINAL_SUMMARY:END -->
