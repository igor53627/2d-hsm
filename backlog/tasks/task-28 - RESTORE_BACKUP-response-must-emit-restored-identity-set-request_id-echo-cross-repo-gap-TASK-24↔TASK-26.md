---
id: TASK-28
title: >-
  RESTORE_BACKUP response must emit restored identity set + request_id echo
  (cross-repo gap TASK-24↔TASK-26)
status: Done
assignee: []
created_date: '2026-06-22 01:02'
updated_date: '2026-06-22 11:18'
labels:
  - agent-gateway
  - restore
  - security
  - cross-repo
  - evidence
  - wire-format
  - high
dependencies: []
modified_files:
  - impl/rust/enclave-protocol/src/agent_dispatch.rs
  - docs/restore-drill-evidence-handoff-contract.md
  - backlog/docs/vsock-api-wire-format-spec-draft.md
priority: high
ordinal: 30500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**HIGH cross-repo gap surfaced by compact 9651 (verified against the live code). Sits between TASK-24 (the RESTORE_BACKUP handler/response) and TASK-26 (the restore-drill evidence handoff contract to 2D TASK-132.5.3).**

**The gap:** `encode_restore_backup_response` (`impl/rust/enclave-protocol/src/agent_dispatch.rs`) emits ONLY `{1: sealed_keystore_blob}`. But TASK-26's contract (`docs/restore-drill-evidence-handoff-contract.md` §3 "Ceremony return — what 2D consumes") requires 2D to record:
- the **restored identity set** (`attempt_completed.restored_identity_set_sha256`), and
- the **challenge/request_id echo** (proves the ceremony consumed the live nonce — replay-prevention step 5: "2D verifies `ceremony_response.request_id == attempt_started.id`").

The contract §3 currently says "the host-side frame layer reads each `KeyEntry.public_identity` from the sealed candidate." That is **wrong for the live code**: the sealed keystore is **XChaCha20Poly1305 AEAD-encrypted** (`agent_keystore.rs:9,194`), so the host CANNOT read plaintext identities from the sealed blob. Only the enclave (holding the provisioning-root-derived AEAD key) can unseal it. So the restored identity set MUST be emitted by the **enclave-side** frame layer (which has the plaintext `candidate.entries` in hand around the seal step), and `request_id` MUST be echoed on the wire.

**Why this is HIGH, not cosmetic:** without the identity set on the wire, 2D cannot compute `restored_identity_set_sha256` → the `identity_match` production-readiness check (contract §5) is uncomputable from ceremony output → the funding gate cannot machine-verify the restore restored the EXPECTED keys. Without the `request_id` echo, replay-prevention step 5 is broken (2D cannot confirm the ceremony consumed its live nonce). The host cannot substitute either (the identities must come enclave-authenticated, not host-claimed, or the evidence is worthless).

**Fix (scope spans the two tasks — do NOT patch silently in one):**
- TASK-24 side (`encode_restore_backup_response`): extend the success body to carry the restored identity set (each restored entry's `key_ref` + `public_identity` + `key_purpose`, extracted from the plaintext candidate before/around the seal) AND the `request_id` echo. This is a wire-format change (new response keys beyond `{1: sealed_blob}`) → pin a golden + update `backlog/docs/vsock-api-wire-format-spec-draft.md` §10.4.
- TASK-26 side (contract doc): fix §3 to state the identity set + request_id are EMITTED by the enclave-side frame layer (not read from the sealed blob by the host), and align the §4/§5 schema accordingly. Also fix the other compact-9651 HIGH/Med contract findings: the `attempt_challenge` vs `request_id` nonce inconsistency (§2/§3), the missing `public_identity` field in `agent_restore_identity_set_v1` (§4), and the undefined `remediation_log[]` vs in-batch `remediation_status` (§5).

**Acceptance:**
- [ ] RESTORE_BACKUP success response carries the restored identity set + request_id echo (wire-format change + golden + spec §10.4 update).
- [ ] A test proves the host can derive `restored_identity_set_sha256` + verify the request_id echo from the response ALONE (no unsealing).
- [ ] TASK-26 contract §3/§4/§5 aligned to the emitted shape; the nonce model + remediation_log findings resolved.
- [ ] 2D-side (TASK-132.5.3) consumer updated to read the new fields (cross-repo coordination).

**Context:** TASK-24 was marked Done on its 12 ACs (the handler restores correctly) — those ACs do not explicitly require the response shape, but the ceremony's downstream contract (TASK-26) does. This task is the durable tracker so the HIGH gap is not hidden behind TASK-24's Done flip. Tracked jointly with TASK-26 (re-opened — its contract doc has the matching HIGH findings).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 RESTORE_BACKUP success response carries the restored identity set + request_id echo (wire-format change + golden + spec §10.4 update)
- [x] #2 A test proves the host can derive restored_identity_set_sha256 + verify the request_id echo from the response ALONE (no unsealing)
- [x] #3 TASK-26 contract §3/§4/§5 aligned to the emitted shape; the nonce model + remediation_log findings resolved
- [x] #4 2D-side (TASK-132.5.3) consumer updated to read the new fields (cross-repo coordination)
<!-- AC:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-06-22 07:38
---
Matrix round on the TASK-28 commits (jobs 9668-9671, 4 cells: codex/gemini security, claude-code design, grok security) + compact 9675: a HIGH finding multi-vendor agreed (codex+gemini+claude-code) — the response fields (key 2 request_id_echo, key 3 restored_identity_set) are UNAUTHENTICATED plaintext. A compromised host can FORGE the response (fresh request_id + old sealed blob + expected identities), so 2D accepting the evidence is defeated. This is the CORE remaining TASK-28 work: add enclave-verifiable completion evidence (a response signature or attestation over {opcode, chain/env, request_id_echo, restored_identity_set hash, sealed_blob_hash}) that 2D verifies before recording completion.

State of the 2d-hsm side (landed, committed 28a0f77..f464e9d): the response-shape change + the frame-layer extraction + the test + the wire-format spec + the contract §3/§4 alignment + the nonce-model resolution are all in place — they are the NECESSARY SUBSTRATE for the authenticated evidence (the binding signs OVER these fields). But they are NOT deliverable evidence on their own (forgeable). A ⚠️ UNAUTHENTICATED warning is on encode_restore_backup_response so the fields aren't trusted prematurely.

The authentication binding is a design decision (which enclave key signs — attestation quote vs a signature over the evidence; how 2D verifies; interaction with the bounded-subprocess quote-fetch concern from TASK-27). NOT done — gating on that design + the user's call on fix-now vs defer.
---

created: 2026-06-22 07:38
---
Also fixed (compact 9675 Med): the nonce-field naming — the ceremony echo is now consistently `request_id_echo` (was contradictory `attempt_challenge`/`attempt_challenge_echo` in §3 + the bundle schema); resolved per §2 (attempt_challenge is a 2D-side field, not a ceremony echo).
---

created: 2026-06-22 08:38
---
Option-A matrix (jobs 9693-9697) + compacts 9698/9703: the attestation binding is in + multi-vendor-reviewed. Findings closed: contract §3 now requires 2D to verify key 4 before trusting keys 2/3 (claude-code HIGH — the consumer-side enforcement); length-prefix env/request_id in report_data_for_restore_completion (codex Med — tuple-collision); 3 reject-path tests for verify_restore_completion_attestation (advisory — the positive test was symmetric).
---

created: 2026-06-22 08:38
---
DEFENSE-IN-DEPTH DEFERRED (codex+grok, compact 9703): report_data_for_restore_completion binds the identity set but NOT sha256(sealed_blob) — a host could in principle splice a different valid sealed blob. claude-code verified the realistic instance (replaying an older valid blob) is caught by the anchor anti-rollback at next-boot (strict_recovery_counter/structural_version). Binding sealed_blob_hash is the robust close but requires splitting the shared commit_before_emit seam (risk to the 5 other ops); deferred to a TASK-28 follow-up — documented inline + here, the anchor mitigates the realistic attack. NB: the compact will keep re-verifying this until either the binding lands or the finding is closed with this rationale — it is a tracked defense-in-depth, not a realistic-attack gap.
---

created: 2026-06-22 11:18
---
#5 — 2026-06-22 10:30

2D-side consumer update (AC#4) LANDED — commit a488d205 (2d repo, branch task-26.6.2-unhalt-prune).

**Changes:**
- Migration `20260622100000_add_attestation_to_restore_drill_completed.exs`: 5 new columns (request_id_echo, attestation_verified, attestation_report_sha256, attestation_cert_chain_sha256, sealed_blob_sha256) + CHECK constraints (success MUST have attestation_verified=true + all fields non-null/32-byte; failure MUST have all NULL).
- Schema (`RestoreDrillAttemptCompletedEvent`): `validate_success_evidence` requires attestation fields; `validate_attestation_verified` rejects `attestation_verified != true`.
- Writer (`RestoreWriter.verify_completion`): reads `attestation_verified` from DB, returns `{:error, :attestation_not_verified}` if not true.
- Provenance (`RestoreProvenance.row_matches?`): checks `completed_attestation_verified == true` — a batch without verified attestation cannot satisfy the funding gate.
- Audit evidence: `completed_events` snapshot includes the attestation fields.
- Tests: all 6 restore test files updated with attestation fields. New enforcement test: "rejects success completion without verified attestation". 554 tests pass, 0 failures.

**2d-hsm side (already done, compact-clean):** RESTORE_BACKUP response carries keys 2-5 (request_id_echo, restored_identity_set, attestation_report, cert_chain) + sealed_blob_sha256 binding (key 1). Completion attestation `report_data` binds the full 5-field tuple `(request_id_echo, restored_identity_set_sha256, sealed_blob_sha256, chain, env)` — SHA3-512, domain-separated. Three hash values using two algorithms (compact-9767/9772/9775 all resolved).

**Cross-repo contract (TASK-26, §3/§4/§5):** aligned to the emitted shape. The nonce model is resolved (request_id is the SOLE replay token). The contract requires 2D to verify key 4 before trusting keys 2/3.

All 4 TASK-28 acceptance criteria are now met. The attestation enforcement is defense-in-depth on top of the 2d-hsm anchor anti-rollback (next-boot strict_recovery_counter/structural_version reconcile).
---
<!-- COMMENTS:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
2D-side attestation enforcement (AC#4) landed (commit a488d205, 2d repo). Migration + schema + writer + provenance + audit evidence + 6 test files updated. 554 tests pass. 2d-hsm side compact-clean (9775). Cross-repo contract (TASK-26) aligned. All 4 ACs met.
<!-- SECTION:FINAL_SUMMARY:END -->
