---
id: TASK-17
title: Keystore residual hardening + doc accuracy (roborev audit 2026-06-08)
status: Done
assignee: []
created_date: '2026-06-08 16:19'
updated_date: '2026-06-23 14:09'
labels:
  - agent-gateway
  - roborev
  - hardening
dependencies:
  - TASK-13
priority: medium
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two verified STILL_OPEN findings from the roborev audit/compact of the PR #37 (TASK-13/7.6.2 sealed keystore) review backlog on 2026-06-08. Both confirmed against current main during the audit-before-close drain; the originating roborev jobs (7818, 7838) were closed after capture here. Code path is keystore validate()/seal + the keystore backup-format design doc; gate-required (high_risk_paths) before merge.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 validate() rejects duplicate counter primary keys: KeystoreBody::validate() (agent_keystore.rs:478-486) dedups CounterEntry on (authority, environment_identifier, scope_class, scope_target) the same way entries are deduped on key_ref (DuplicateKeyRef, :462-476). Add a DuplicateCounter error variant + a regression test (two counter rows, same primary key, differing highest_accepted_counter -> err). Rationale: a duplicate high-water row makes the anti-rollback lookup ambiguous (which counter binds?); parity with the entry dedup, defense-in-depth on the AEAD-sealed blob.
- [ ] #2 Doc: max_batch_size enforcement wording clarified. agent-gateway-keystore-backup-format.md:90 says 'max_batch_size + total_capacity enforced before seal'. MAX_BATCH_SIZE IS enforced — at key-generation time (agent_keygen.rs:90, `count > MAX_BATCH_SIZE`), which runs before the caller seals — so 'before seal' is technically true; but it is NOT a seal-layer check in validate()/seal_body (agent_keystore.rs enforces only MAX_TOTAL_KEY_ENTRIES count at :457 and MAX_KEYSTORE_BLOB_SIZE/framing-reserve at :533). Tighten the doc to say: batch cap enforced at GENERATE_KEYS, seal-layer limits are total entry count + blob-size ceiling (the binding limit). NOTE: the earlier 'declared-and-unused' framing was wrong (it is used in agent_keygen.rs) — corrected here.
- [ ] #3 Doc: forward-migration vs v1-strict reconciled. agent-gateway-keystore-backup-format.md:104 describes reading a bounded window of prior versions + re-seal, but unseal rejects any version != KEYSTORE_FORMAT_VERSION(1) (agent_keystore.rs:192-194). Mark the bounded-window migration as target/future design (no prior version has ever shipped) so the doc matches the current v1-only strict check.
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All 3 ACs met. AC#1: DuplicateCounterTuple validation + test (already landed in TASK-7.7 5b-2e marks-grammar work). AC#2: max_batch_size wording tightened (enforced at GENERATE_KEYS, not seal-layer). AC#3: forward-migration marked as FUTURE DESIGN (current is v1-strict fail-closed).
<!-- SECTION:FINAL_SUMMARY:END -->
