---
id: TASK-34
title: >-
  Constant-time-hardened ML-DSA-65 producer signing — migrate off PQClean clean
  (PQClean→PQ Code Package)
status: To Do
assignee: []
created_date: '2026-06-26 15:39'
updated_date: '2026-06-26 16:20'
labels:
  - security
  - constant-time
  - ml-dsa-65
  - crypto-migration
dependencies:
  - TASK-33
priority: medium
ordinal: 35600
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Remediation owner for the ML-DSA-65 signing timing accepted-risk recorded in TASK-33 (mldsa65.rs doc note). Depends on / remediates TASK-33.

Residual risk (impact, not just mechanism): producer ticket signing runs through pqcrypto-mldsa, which wraps PQClean's clean ML-DSA-65 (Dilithium) reference. PQClean's README lists "No branching on secret data" and "No access to secret memory locations" as UNCHECKED, still-in-development goals — so the impl carries no constant-time guarantee and may branch on / index memory with secret-derived values; separately, ML-DSA's Fiat-Shamir-with-aborts loop has a data-dependent rejection-iteration count. The untrusted host can observe signing latency over vsock. This is key-adjacent timing exposure of the long-term fleet block-producer signing key — materially more severe than the post-verify ct_eq capability gates TASK-33 hardened. The Dilithium zero-knowledge argument only bounds the published signature distribution, NOT wall-clock/microarchitectural timing.

Forcing function: PQClean is scheduled to be archived read-only ~July 2026. read-only != removed — the pinned source stays usable but receives no further fixes (incl. the unchecked constant-time items), so treat the date as a review-by trigger, not a hard removal deadline. Successor: PQ Code Package (PQCA).

Downstream byte-exact contract (matrix Medium): the vectors in testvectors/mldsa65_crosscheck/ are a SHIPPED cross-repo contract consumed by 2D TASK-122 AC#2. FIPS 204 DETERMINISTIC signing is fully specified, so any conformant deterministic impl produces byte-identical signatures for the same (key, message) — the migration MUST select the deterministic mode and preserve byte-exact signatures (NO re-pin needed). Only a justified deviation (e.g. hedged/randomized signing) may change bytes, and then ONLY via a coordinated 2D TASK-122 vector update landed in lockstep — never a silent re-pin.

Integration constraint (matrix Low): enclave-protocol is #![forbid(unsafe_code)]. The replacement must arrive as a safe-Rust crate OR behind an isolated, audited FFI boundary (a separate unsafe-allowed shim crate), with reproducible builds, feature-gated like the current ml-dsa-65 path, and packaged into the NixOS enclave image.

Side-channel acceptance (matrix Medium): "verify CT posture" must define the leakage model (host-observable signing wall-clock over vsock + secret-dependent control-flow/memory), tested variables (secret key, message), tooling (dudect and/or valgrind ctgrind on the sign path), the pass threshold, and an explicit ruling on whether residual Fiat-Shamir rejection-loop iteration-count variance is acceptable (with rationale) — not a narrow run that misses the described threat.

Staging (matrix Medium — too broad as one task): split when actioned into (1) candidate selection + integration design; (2) integration spike (FFI/safe-crate boundary, build, feature gate); (3) side-channel validation harness + acceptance; (4) mldsa65.rs migration + byte-exact vector check; (5) downstream 2D coordination + retire the TASK-33 waiver.

Traceability: dependencies: [TASK-33]; mldsa65.rs cross-references this task. NB backlog/tasks/* is intentionally NOT in .roborev.toml high_risk_paths — task files are planning artifacts and the code they describe is reviewed via impl/; task-only edits do not auto-trigger the matrix by design.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Select a maintained, constant-time-hardened ML-DSA-65 implementation (PQ Code Package / PQCA or an audited equivalent); justify over pqcrypto-mldsa AND state the integration boundary preserving enclave-protocol's #![forbid(unsafe_code)] (safe-Rust crate, or isolated audited FFI shim)
- [ ] #2 Define + execute a side-channel acceptance test: leakage model (host vsock latency + secret-dependent control/memory), tooling (dudect and/or ctgrind on the sign path), pass threshold, and an explicit ruling on residual Fiat-Shamir iteration-count variance
- [ ] #3 Preserve deterministic byte-exact ML-DSA-65 signatures so testvectors/mldsa65_crosscheck/ + 2D TASK-122 AC#2 stay valid with NO re-pin; if a justified deviation requires new bytes, land a coordinated 2D TASK-122 vector update in lockstep (never a silent re-pin)
- [ ] #4 Migrate mldsa65.rs producer signing to the new implementation behind the existing feature gating + reproducible NixOS enclave packaging; all ml-dsa-65 feature tests pass
- [ ] #5 Update or retire the mldsa65.rs accepted-risk note and close the TASK-33 waiver linkage
- [ ] #6 Split this task into the five reviewable stages listed in the description before implementation starts
<!-- AC:END -->
