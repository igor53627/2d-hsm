---
id: TASK-6
title: Investigate ML-DSA secret-key zeroization gap in pq_signer validation
status: In Progress
assignee: []
created_date: '2026-06-05 19:23'
updated_date: '2026-06-05 21:34'
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
- [x] #1 Determine whether temporary validation can avoid copying secret key material or guarantee zeroization.
- [x] #2 If code changes are needed, add focused regression/security tests or documented verification.
- [x] #3 Run the repo-required roborev matrix for high-risk enclave-protocol changes before merge.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Root cause: MlDsa65Signer stored pqcrypto SecretKey (Copy, no Drop/Zeroize); seal_mldsa65_keypair_v1_with_root / verify_sealed_blob_v1_with_root build a temporary signer to self-test the keypair, leaving a parsed secret-key copy in heap on drop. Crate is #![forbid(unsafe_code)], and pqcrypto exposes no mutable bytes / zeroize feature, so in-place scrub of SecretKey is impossible. Fix: store the secret as Zeroizing<Vec<u8>> (scrubbed on drop) and materialize the transient SecretKey per signature inside sign_ticket_hash. This scrubs every retained copy incl. the validation temporaries; the only residual is the ephemeral per-signature SecretKey (upstream Copy limitation, documented).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented on branch fix/task-6-mldsa-zeroize (src/mldsa65.rs only). Added regression+security tests: secret_key_storage_is_zeroize_on_drop (type-level ZeroizeOnDrop assertion on the field type) and zeroizing_secret_storage_roundtrips_and_signs. cargo test --features reference-test-key: 84 passed / 0 failed; prod builds (ml-dsa-65, production-vsock) green. AC#3 (roborev Reduced Matrix + compact) still pending before merge.

roborev Full Matrix (2x3) on 8c1dd59: jobs 7083-7088 (codex+gemini x security/design/design-max) + compact 7089. Verified findings: 1 Medium — secret_key_storage_is_zeroize_on_drop asserted Zeroizing<Vec<u8>> directly instead of the real MlDsa65Signer::secret_key field (ineffective regression guard). Resolved in amended HEAD 20a3f31: test now binds the ZeroizeOnDrop assertion to &signer.secret_key via inference (field regression -> compile error); from_key_bytes documented as unverified low-level constructor. Re-test 84/0 green. AC#3: matrix run + finding resolved; optional confirmatory re-review of 20a3f31 pending user call before merge.

Follow-up security re-review (codex+gemini security on bb2f5f0, jobs 7092/7093) + compact 7094 (also pulled post-commit-hook jobs 7090/7091): individual reviews clean, but verification surfaced 1 Low — generate_keypair() bound a Copy/non-zeroizing pqcrypto SecretKey (residual copy at generation) and was reachable under plain ml-dsa-65 (production-vsock), contradicting the 'only per-signature residual' doc. Resolved in HEAD 4553548: generate_keypair (zero callers) is now #[cfg(any(test, feature="pq-seal-provisioning"))]-gated (out of production API), keypair() fully-qualified to avoid unused-import, and the type/method docs corrected to cover both transient sites. production-vsock + ml-dsa-65 build clean; 84/0 tests.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Resolved the ML-DSA secret-key zeroization gap: MlDsa65Signer now stores the secret in Zeroizing<Vec<u8>> (scrubbed on drop), materializing the pqcrypto SecretKey only transiently per signature — so the validation signers built during sealing/provisioning no longer leave parsed key copies in heap. Crate is #![forbid(unsafe_code)] and pqcrypto SecretKey is Copy/non-zeroizing, so the residual transient (per-signature, and provisioning-only per-keypair) is an upstream limitation, documented. Tests: type-level ZeroizeOnDrop assertion bound to the real field + sign/verify roundtrip; 84/0 green; ml-dsa-65 + production-vsock build clean. Review: roborev Full Matrix (2x3) + security follow-up + compact; Medium (test not bound to field) and Low (generate_keypair residual + prod exposure) both resolved; generate_keypair cfg-gated out of production. HEAD 2f25263 on fix/task-6-mldsa-zeroize.
<!-- SECTION:FINAL_SUMMARY:END -->
