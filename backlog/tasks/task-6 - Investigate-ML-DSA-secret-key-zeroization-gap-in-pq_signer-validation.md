---
id: TASK-6
title: Investigate ML-DSA secret-key zeroization gap in pq_signer validation
status: To Do
assignee: []
created_date: '2026-06-05 19:23'
labels:
  - security
  - tee
  - pq-signing
  - roborev
dependencies: []
references:
  - roborev compact job 7078
  - 'https://github.com/igor53627/2d-hsm/issues/6'
modified_files:
  - impl/rust/enclave-protocol/src/pq_signer.rs
  - impl/rust/enclave-protocol/src/mldsa65.rs
priority: medium
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
roborev compact job 7078 surfaced an existing Medium finding: seal_mldsa65_keypair_v1_with_root / verify_sealed_blob_v1_with_root validate keypairs by constructing a temporary MlDsa65Signer. MlDsa65Signer documents that its SecretKey does not zeroize on drop, so validation can leave an extra parsed copy of long-term ML-DSA secret key material in heap memory after success or self-test failure. This was previously mirrored as GitHub issue #6, which is being closed in favor of local backlog tracking.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Determine whether temporary validation can avoid copying secret key material or guarantee zeroization.
- [ ] #2 If code changes are needed, add focused regression/security tests or documented verification.
- [ ] #3 Run the repo-required roborev matrix for high-risk enclave-protocol changes before merge.
<!-- AC:END -->
