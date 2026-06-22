---
id: TASK-26
title: >-
  Production restore-drill evidence handoff for Agent Gateway funding-gate
  provenance (cross-repo bridge to 2D TASK-132.5.3.3 / .4)
status: In Progress
assignee: []
created_date: '2026-06-19'
updated_date: '2026-06-22 01:03'
labels:
  - agent-gateway
  - restore
  - recovery
  - runbook
  - cross-repo
  - security
dependencies:
  - TASK-24
  - TASK-13
references:
  - >-
    ../2d/backlog/tasks/task-132.5.3.3 -
    Implement-restore-provenance-loader-config-and-inventory.md
  - >-
    ../2d/backlog/tasks/task-132.5.3.4 -
    Execute-restore-drill-and-break-glass-remediation-runbook.md
  - >-
    ../2d/backlog/tasks/task-132.5.3 -
    Execute-agent-signer-restore-drill-verification-before-production-funding.md
  - ../2d/docs/specs/2026-06-07-agent-gateway-signer-2d-hsm-key-pool-design.md
priority: high
ordinal: 28500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Defines the **cross-repo handoff artifact contract** between the `2d-hsm` restore ceremony and the `2D` node's Agent Gateway funding-gate provenance check. This is the bridge that 2D's `TASK-132.5.3.3` / `TASK-132.5.3.4` require before `:agent_restore_provenance_enforced` can be set `true` in production: 2D owns the audit schema, controlled writer, loader, and validator (all merged and tested against fixtures), but the **production-readiness evidence bundle** must come from / be co-produced with the `2d-hsm` restore ceremony, and that contract is currently untracked in either repo.

**Why this is distinct from TASK-24:** TASK-24 owns the enclave-local `RESTORE_BACKUP(8)` handler — *how* the ceremony restores a keystore inside an attested TEE (KEM-DEM re-wrap, AAD verify, wholesale-replace, counter seeding, `CommitBumpClass::RestoreCeremony`). TASK-26 owns *what the ceremony hands to the 2D node* so 2D's funding gate can prove a real restore happened against a real production batch: ceremony/artifact version pins, the challenge/nonce echo binding, the restored identity-set evidence shape, the evidence-bundle schema, and the cross-repo fixture that proves the two halves interlock. TASK-26 is a hard prerequisite for 2D's `TASK-132.5.3.4` production enablement and is blocked until TASK-24's handler exists (or a documented non-production stand-in is named).

**Scope:** tracking + contract task. It produces a documented, reviewed handoff contract plus a cross-repo fixture; it does not add enclave Rust (that is TASK-24) or 2D-side audit/writer/loader code (that is the merged 2D `TASK-132.5.3.x` series). This file lives under `backlog/tasks/`, which is not in `.roborev.toml`'s `high_risk_paths`, so it follows the normal backlog-task review path; the agent-gateway restore surfaces it *references* (enclave `impl/` and the 2D audit/writer path) are high-risk, but those edits land under TASK-24 and the 2D `TASK-132.5.3.x` tasks respectively, not here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 **Ceremony + artifact version pins.** Pin and publish the exact version strings the production restore drill consumes: the `RESTORE_BACKUP(8)` ceremony handler version (from TASK-24) and the `restore-ingress-v1` artifact format version (from TASK-13, frozen decoder + golden). These are the versions that MUST appear in the 2D-side production-readiness evidence bundle, so version drift between what a drill ran and what an operator attests is detectable at the 2D gate. A drill run against an unpinned or unreleased ceremony version cannot produce valid production evidence.
- [ ] #2 **Restore command contract for 2D orchestration.** Document the operator/RPC contract by which a production restore drill is driven against a given backup batch: inputs (`artifact_uri` / `artifact_sha256` / `artifact_size_bytes`, plus the 2D-committed `attempt_started` row's `id`, `attempt_challenge` nonce, and `baseline_snapshot_sha256` from 2D's audit schema), what the ceremony returns, and how restored identity evidence is surfaced so 2D can write its `attempt_completed` row. Name the non-production fixture path separately and prove it cannot satisfy the production bundle (mirrors 2D `TASK-132.5.3.4` — fixtures validate mechanics only).
- [ ] #3 **Challenge/nonce echo binding.** The restore ceremony must consume the 2D-committed `attempt_started` challenge/nonce and echo it in the restored evidence so 2D records it on `attempt_completed` (2D `TASK-132.5.3.4` AC#1 / `TASK-132.5.3` AC#1). Define exactly where the echo appears in the ceremony output and the binding that prevents a ceremony from claiming success without consuming the live challenge — i.e. a replay of a prior restore output against a fresh `attempt_started` is detectable and rejected by 2D.
- [ ] #4 **Restored identity-set evidence shape.** Restored key refs must derive a public identity set comparable to 2D's `agent_restore_identity_set_v1` canonical encoding (per entry: `source_table`, `row_id`, `backend`, `algorithm`, `key_ref`, `status`, `address`, `public_identity`) so expected vs restored identity-set SHA-256 hashes can be compared on 2D's `attempt_completed` row. Address-only evidence is insufficient (mirrors 2D `TASK-132.5.3` AC#8). Document the field-level mapping from the ceremony's restored key material to the 2D identity-set entry shape.
- [ ] #5 **Production-readiness evidence bundle schema.** Define the exact bundle schema that satisfies 2D `TASK-132.5.3.4`'s bundle contract: production environment + chain/network identity, 2d-hsm ceremony version, artifact format version, per-batch artifact URI/hash/size, the 2D-committed audit started/completed event ids, challenge/nonce echo evidence, expected + restored identity-set hashes, remediation status for any failed batches, and dual sign-off (Agent Gateway operator owner + recovery-material custodian). The schema must be machine-checkable so 2D's gate can refuse an incomplete or unsigned bundle.
- [ ] #6 **Production coverage rule.** The bundle must cover EVERY active production backup batch linked to an enabled faucet treasury row or an assigned transfer key row in 2D, OR name a documented operator-approved exclusion whose linked 2D rows were disabled/retired BEFORE 2D sets `:agent_restore_provenance_enforced = true`. Partial coverage cannot enable enforcement for the uncovered rows; this mirrors 2D `TASK-132.5.3.4` DoD#1 and `TASK-132.5.3` AC#10.
- [x] #7 **Cross-repo handoff fixture.** An automated fixture drives the full cross-repo path end-to-end against a non-production backup: 2D commits `attempt_started` → a restore ceremony (the real TASK-24 `RESTORE_BACKUP(8)` handler where available, otherwise a documented non-production stand-in that preserves the AC#1–#4 contract) echoes the challenge + restores the identity set → 2D records `attempt_completed` and `Chain.AgentGateway.RestoreWriter.verify_completion/2` links provenance → the resulting bundle is validated against the AC#5 schema AND 2D's `Chain.AgentGateway.RestoreProvenance.validator_for/3` returns `true` for the restored batch. This is the proof that the handoff contract is internally consistent and that 2D can flip provenance on once production evidence is produced.
- [ ] #8 **Scope exclusions (explicit).** Out of scope and explicitly owned elsewhere: the 2D-side audit schema, controlled writer, config loader, inventory monitor, and provenance validator (2D `TASK-132.5.3.1`/`.2`/`.3.3`, merged); the enclave-local `RESTORE_BACKUP(8)` handler internals (TASK-24); the on-chain `RecoveryTicket` / `MeasurementRegistry` (2d-solidity `TASK-1.4`, disjoint per TASK-24 AC#12); quorum / M-of-N recovery (single-key MVP). TASK-26 owns ONLY the cross-repo handoff artifact contract + the production ceremony execution evidence.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:IMPL_NOTES:BEGIN -->
AC#1-#8 contract document landed via PR #107 (merged into main). The contract covers: ceremony+artifact version pins, restore command contract, challenge/nonce echo binding, identity-set field mapping, evidence bundle schema, coverage rule, cross-repo fixture design, scope exclusions. Round-1 (cursor+greptile): fixed Ethereum address derivation [12..32 not 0..20], clarified payload_binding vs attempt_challenge, separated remediation_log from batches[] in the schema. AC#7 fixture test (the 2D-side end-to-end test) is a follow-up PR in the 2d repo — it was split out because it drives 2D-side code paths (RestoreWriter, validator, audit evidence).

**AC#7 stand-in caveat (claude-code design review job 9839, MEDIUM finding #3 — deferred, not dropped):** AC#7 permits "a documented non-production stand-in that preserves the AC#1–#4 contract" in place of the real enclave handler. Contract §4 states the cross-repo fixture (AC#7) is "the only thing that catches a divergence" between the enclave's `compute_restored_identity_set_hash` and 2D's reimplementation — but if the stand-in does not exercise the real enclave hash function, it cannot detect a SHA-2-vs-SHA-3 / endianness / sort mismatch, making the named safety net illusory. **Resolution:** the 2d-hsm side now exposes `compute_restored_identity_set_hash` + the §4 byte layout as a pinned known-answer vector (contract §4 + `agent_dispatch.rs:2847`). The 2D-side fixture (AC#7, landed as PR #218) MUST assert byte-equality against this pinned vector — not a stand-in reimplementation. Upgrading the fixture to call the real enclave hash (or assert the KAV) is a 2D-repo follow-up; the contract + code now provide the ground truth to pin against. The §4 claim is accurate once the fixture asserts against the real layout; until then the risk is a cross-repo hash mismatch that would surface as "attestation ALWAYS fails to verify" at integration, not a silent forge.
<!-- SECTION:IMPL_NOTES:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-06-22 01:03
---
Re-opened (was Done): compact 9651 surfaced verified HIGH findings in docs/restore-drill-evidence-handoff-contract.md that the Done flip did not address:

1. HIGH (§3): the contract says the host-side frame layer reads KeyEntry.public_identity from the sealed candidate, but the sealed keystore is XChaCha20Poly1305 AEAD-encrypted (agent_keystore.rs:9,194) — the host CANNOT read plaintext identities. The restored identity set + request_id echo must be EMITTED by the enclave-side frame layer in the RESTORE_BACKUP response. Tracked as TASK-28 (the response-shape gap, jointly with TASK-24).

2. HIGH (§2/§3 nonce model): attempt_challenge is described as the high-entropy nonce, but the ceremony binds/echoes request_id (= attempt_started.id) as the challenge — internally inconsistent.

3. MED (§4): agent_restore_identity_set_v1 entry omits public_identity.

4. MED (§5): schema carries batches[].remediation_status while constraints require a separate undefined remediation_log[].

The contract AC#1-#8 document is merged (PR #107) but these content issues mean the Done claim was premature. Keeping In Progress until the contract is aligned to the live code (TASK-28 owns the response-shape half; the nonce/schema fixes are TASK-26-internal).
---
<!-- COMMENTS:END -->

## Final Summary

PR #107 (2d-hsm, contract doc AC#1-8) + PR #218 (2d, fixture test AC#7). **Status: In Progress** — the contract doc + fixture landed, but compact-9651 surfaced HIGH content issues (AEAD-encrypted keystore means the host cannot read identities; nonce model contradiction; missing public_identity field; remediation_log schema). TASK-28 addressed the response-shape half; the nonce/schema fixes + AC re-verification remain before this task flips to Done.
<!-- SECTION:FINAL_SUMMARY:END -->

## Notes
<!-- SECTION:NOTES:BEGIN -->
**Why this task exists (the gap):** 2D's `TASK-132.5.3.3` has now closed its code/test surface — AC#1 (validator + faucet parity), AC#3 (sensitive-field classification), AC#4 (rollback), AC#6, AC#7 are all merged; the remaining AC#1/#2/#5 blockers are NOT 2D code, they are the external 2d-hsm restore ceremony + the evidence bundle it must produce. Neither repo currently tracks that handoff as a task: 2D `TASK-132.5.3.4` requires the bundle but does not reference TASK-24, and TASK-24 owns the enclave handler but not the 2D-facing evidence contract. TASK-26 closes that gap.

**Dependency logic:**
- Depends on **TASK-24** because AC#3/#4 (challenge echo + restored identity set) can only be proven against a real `RESTORE_BACKUP(8)` handler. Until TASK-24 lands, AC#7's fixture MAY run against a documented non-production stand-in, but the production bundle (AC#5/#6) cannot be valid and 2D's gate stays `false`.
- Depends on **TASK-13** for the frozen `restore-ingress-v1` decoder + golden that AC#1's artifact-format-version pin references.

**Not a dependency:** the on-chain `RecoveryTicket` (TASK-1.4) — disjoint BlockProducer subsystem; the agent restore path references it nowhere (mirrors TASK-24 AC#12).

**Suggested approach:** land in two review-friendly slices — (a) the contract docs (AC#1–#6: version pins, command contract, echo binding, identity-set mapping, bundle schema, coverage rule) as a single reviewed doc set; (b) the cross-repo fixture (AC#7) as a follow-up that proves (a). Slice (b) is blocked on TASK-24 for the real-handler path but can land the stand-in path early to de-risk the contract.

**Cross-repo linkage to add when this lands:** 2D's `TASK-132.5.3.4` should gain a `references:` entry pointing at this task, and its `dependencies:` should make the production-evidence prerequisite explicit. (Edit lands in the 2D repo.)
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Ceremony version + artifact format version are pinned and referenced from the evidence bundle schema (AC#1).
- [ ] #2 Restore command contract, challenge/nonce echo binding, and restored identity-set evidence mapping are documented and reviewed (AC#2/#3/#4).
- [ ] #3 Production-readiness evidence bundle schema is published and is the artifact 2D's `TASK-132.5.3.4` gate consumes (AC#5/#6).
- [ ] #4 Cross-repo handoff fixture passes (AC#7): against the real TASK-24 handler once landed; against a documented non-production stand-in until then, with 2D's production gate staying `false` until real production evidence is produced.
- [ ] #5 2D-side cross-reference edit (`TASK-132.5.3.4` → this task) is landed in the 2D repo.
- [ ] #6 Final summary added before marking Done.
<!-- DOD:END -->
