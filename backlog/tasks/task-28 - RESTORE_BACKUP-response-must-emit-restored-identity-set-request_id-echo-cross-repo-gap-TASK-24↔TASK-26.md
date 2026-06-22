---
id: TASK-28
title: >-
  RESTORE_BACKUP response must emit restored identity set + request_id echo
  (cross-repo gap TASK-24↔TASK-26)
status: To Do
assignee: []
created_date: '2026-06-22 01:02'
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
