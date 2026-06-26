---
id: TASK-34
title: >-
  Constant-time-hardened ML-DSA-65 producer signing — migrate off PQClean clean
  (PQClean→PQ Code Package)
status: To Do
assignee: []
created_date: '2026-06-26 15:39'
updated_date: '2026-06-26 15:45'
labels:
  - security
  - constant-time
  - ml-dsa-65
  - crypto-migration
dependencies: []
priority: medium
ordinal: 35600
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Remediation owner for the ML-DSA-65 signing timing accepted-risk recorded in TASK-33 (mldsa65.rs doc note).

Residual risk (impact, not just mechanism): producer ticket signing runs through pqcrypto-mldsa, which wraps PQClean's *clean* ML-DSA-65 (Dilithium) reference. PQClean's README lists "No branching on secret data" and "No access to secret memory locations" as UNCHECKED, still-in-development goals — so the impl carries no constant-time guarantee and may branch on / index memory with secret-derived values; separately, ML-DSA's Fiat-Shamir-with-aborts loop has a data-dependent rejection-iteration count. The untrusted host can observe signing latency over vsock. This is key-adjacent timing exposure of the long-term fleet block-producer signing key (gated behind vsock latency observation) — materially more severe than the post-verify ct_eq capability gates TASK-33 hardened. The Dilithium zero-knowledge argument only bounds the published signature distribution, NOT wall-clock/microarchitectural timing.

Forcing function: PQClean is deprecated and scheduled to be archived read-only ~July 2026; its successor is the PQ Code Package (PQCA). This waiver must be revisited at/before that date.

Scope: evaluate + migrate producer ML-DSA-65 signing to a constant-time-hardened, maintained implementation (PQ Code Package / PQCA, or an audited equivalent), re-pin the FIPS 204 golden cross-check vectors (testvectors/mldsa65_crosscheck/ + 2D TASK-122 AC#2), and update/retire the mldsa65.rs accepted-risk note. Verify side-channel posture (e.g., dudect/valgrind-ctgrind on the signing path) rather than assuming it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Select a maintained, constant-time-hardened ML-DSA-65 implementation (PQ Code Package / PQCA or an audited equivalent) and justify the choice over pqcrypto-mldsa
- [ ] #2 Verify the signing path's constant-time / side-channel posture with a named method (e.g. dudect or valgrind ctgrind on the sign path), not assumed
- [ ] #3 Re-pin the FIPS 204 golden cross-check vectors (testvectors/mldsa65_crosscheck/ + 2D TASK-122 AC#2) against the new implementation
- [ ] #4 Migrate mldsa65.rs producer signing to the new implementation; all ml-dsa-65 feature tests pass
- [ ] #5 Update or retire the mldsa65.rs accepted-risk note and close the TASK-33 waiver linkage
<!-- AC:END -->
