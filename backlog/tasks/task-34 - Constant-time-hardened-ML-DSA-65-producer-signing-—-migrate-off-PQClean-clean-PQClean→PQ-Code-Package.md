---
id: TASK-34
title: >-
  Constant-time-hardened ML-DSA-65 producer signing — migrate off PQClean clean
  (PQClean→PQ Code Package)
status: To Do
assignee: []
created_date: '2026-06-26 15:39'
updated_date: '2026-06-26 16:31'
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

Forcing function (soft): PQClean is scheduled to be archived read-only ~July 2026. read-only != removed — the pinned source keeps building but gets no further fixes (incl. the unchecked constant-time items). Treat ~July 2026 as a soft review-by for this waiver, not a hard deadline; re-evaluate priority at that point. Successor: PQ Code Package (PQCA).

Downstream interop contract (compact Medium — corrected): the vectors in testvectors/mldsa65_crosscheck/ are VERIFIER ACCEPTANCE TRIPLES (ticket_hash, signature, pubkey) that 2D TASK-122 AC#2's verify NIF must accept (pos_*) / reject (neg_*) — NOT byte-exact signing-output reproductions (confirmed: gen_golden_vectors.rs builds them via verify_detached_signature(...).is_ok()). Producer signing is HEDGED FIPS 204 (in-TEE CSPRNG; pqcrypto-mldsa detached_sign, no rnd override), so signing output is NOT byte-deterministic and there is no byte-exact signing contract. Consequence for the migration: a CT-hardened SIGNER swap keeps cross-repo interop automatically — any conformant ML-DSA signer emits signatures any conformant verifier (the 2D NIF) accepts, so the existing crosscheck triples stay valid WITHOUT a re-pin. Keep the hedged profile; only a deliberate, separately-specified protocol change to deterministic signing would alter this, and that is out of scope for a library swap.

Integration constraint: enclave-protocol is #![forbid(unsafe_code)]. The replacement must arrive as a safe-Rust crate OR behind an isolated, audited FFI boundary (a separate unsafe-allowed shim crate), with reproducible builds, feature-gated like the current ml-dsa-65 path, and packaged into the NixOS enclave image.

Side-channel acceptance: "verify CT posture" must define the leakage model (host-observable signing wall-clock over vsock + secret-dependent control-flow/memory), tested variables (secret key, message), tooling (dudect and/or valgrind ctgrind on the sign path), the pass threshold, and an explicit ruling on whether residual Fiat-Shamir rejection-loop iteration-count variance is acceptable (with rationale) — not a narrow run that misses the described threat. NB the hedged in-TEE CSPRNG draw is an EXPECTED per-signature variance, distinct from secret-dependent leakage.

Staging (too broad as one task): split when actioned into (1) candidate selection + integration design; (2) integration spike (FFI/safe-crate boundary, build, feature gate); (3) side-channel validation harness + acceptance; (4) mldsa65.rs migration + crosscheck-triple re-verification; (5) downstream 2D coordination + retire the TASK-33 waiver.

Traceability: dependencies: [TASK-33]; mldsa65.rs cross-references this task. NB backlog/tasks/* is intentionally NOT in .roborev.toml high_risk_paths — task files are planning artifacts and the code they describe is reviewed via impl/; task-only edits do not auto-trigger the matrix by design.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Select a maintained, constant-time-hardened ML-DSA-65 implementation (PQ Code Package / PQCA or an audited equivalent); justify over pqcrypto-mldsa AND state the integration boundary preserving enclave-protocol's #![forbid(unsafe_code)] (safe-Rust crate, or isolated audited FFI shim)
- [ ] #2 Define + execute a side-channel acceptance test: leakage model (host vsock latency + secret-dependent control/memory), tooling (dudect and/or ctgrind on the sign path), pass threshold, and an explicit ruling on residual Fiat-Shamir iteration-count variance (the hedged CSPRNG draw is expected variance, not leakage)
- [ ] #3 Preserve cross-repo verify interop: the existing testvectors/mldsa65_crosscheck/ verifier-acceptance triples must still pass 2D TASK-122 AC#2 under the migrated signer (FIPS 204 verification is signer-independent, so NO re-pin is expected); keep the hedged signing profile unless a deliberate, separately-specified deterministic-mode change is coordinated
- [ ] #4 Migrate mldsa65.rs producer signing to the new implementation behind the existing feature gating + reproducible NixOS enclave packaging; all ml-dsa-65 feature tests pass
- [ ] #5 Update or retire the mldsa65.rs accepted-risk note and close the TASK-33 waiver linkage
- [ ] #6 Split this task into the five reviewable stages listed in the description before implementation starts
<!-- AC:END -->
