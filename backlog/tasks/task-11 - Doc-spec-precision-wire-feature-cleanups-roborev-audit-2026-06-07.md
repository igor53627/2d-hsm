---
id: TASK-11
title: Doc/spec precision + wire/feature cleanups (roborev audit 2026-06-07)
status: To Do
assignee: []
created_date: '2026-06-07 18:02'
labels:
  - documentation
  - audit
dependencies: []
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Doc/spec-precision + feature-flag findings from the 2026-06-07 roborev audit (jobs 7441, 7586, 7236, 6720, 6739, 6765, 6785, 7125, 6551, 6796, plus doc parts of 6589).

task-7.2 DR design: recovery-key custody wording inconsistent (line 71 'never in TEE' vs line 179); restore ingress envelope lacks explicit ingress_format_version + fail-closed unknown-version check; AAD' is raw concatenation without canonical encoding/length-prefixing; ingress_nonce value/derivation unspecified; test-vector claim that mutating any AAD' field fails decapsulation is imprecise (most AAD' fields are not ML-KEM inputs).
task-1.1 runbook: §7.2 understates root-custody risk and oversells fleet changes; measurement length only advisory (warns but proceeds); TASK-1.1 lacks an Acceptance Criteria section; manifest schema lacks operator verification metadata.
task-2 wire: ml-dsa-65 and test-support features mutually exclusive (blocks tests under pq-seal-provisioning); malformed-frame diagnostics hidden by message-type aliasing; ARM_FOR_PRODUCTION refusal response shape conflicting; integer-key CBOR migration lacks an explicit compatibility statement.
Stale docs: test counts 62/74/80 -> actual 71/90/97 (implementation-plan + task-2); 'Reduced 3:3' vs the 6-cell .roborev.toml CI; stale baseline references (task-5); missing trailing newline in enclave_uds_staging.rs.

Source roborev jobs: 7441, 7586, 7236, 6720, 6739, 6765, 6785, 7125, 6551, 6796 (2d-hsm).
<!-- SECTION:DESCRIPTION:END -->
