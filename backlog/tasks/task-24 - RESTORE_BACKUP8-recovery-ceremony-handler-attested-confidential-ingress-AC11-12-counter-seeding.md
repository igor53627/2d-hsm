---
id: TASK-24
title: >-
  RESTORE_BACKUP(8) recovery-ceremony handler (attested confidential ingress +
  AC#11/#12 counter seeding)
status: To Do
assignee: []
created_date: '2026-06-18 21:28'
labels:
  - agent-gateway
  - restore
  - recovery
  - crypto
  - anti-rollback
  - security
  - deferred-handler
dependencies:
  - TASK-13
  - TASK-7.2
  - TASK-7.7
  - TASK-18
priority: high
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`RESTORE_BACKUP(8)` ingests a `restore-ingress-v1` DR backup and reconstitutes the agent keystore state inside a fresh or wiped enclave — the recovery-tier counterpart to the now-live `EXPORT_BACKUP` (TASK-13b). It is the disaster-recovery path for the THIRD keying assumption (a newly-provisioned destination TEE), distinct from same-enclave restart and same-fleet keying, which use the sealed keystore directly.

It was deferred as the **TASK-7.6 AC#6 named-follow-up** (this is that task) because it is the hardest remaining privileged op: it needs the full **attested confidential-ingress ceremony** — a SECOND KEM-DEM re-wrap of the operator-decrypted backup to the destination enclave's ATTESTED ephemeral ML-KEM-1024 key, so plaintext key scalars only ever exist inside the attested destination TEE and never touch the untrusted host — plus the AC#11/#12 counter-seeding rules and an ENCLAVE-LOCAL commit-bump path that is deliberately NOT a generic monotone `++`.

Current state: RESTORE_BACKUP is the **last fail-closed stub** among privileged ops — no dispatch arm; it falls through the wildcard to `NotConfigured` (wire `0x45`) after the recovery cap verifies, pinned by `deferred_restore_backup_recovery_cap_reaches_not_configured` so the stub cannot silently become a no-op handler. The wire/format groundwork is DONE: the strict `parse_restore_ingress` decoder + the frozen `restore-ingress-v1` payload format + the restore-side reconstruction rules all exist from slice 4c-2a, and the payload deliberately **EXCLUDES** `structural_version`/`freshness_epoch`/`anchor_root` — so there is no non-monotone-`structural_version` footgun to install; those surfaces are re-derived enclave-locally. The commit class is already pinned `Structural` (a dropped/crashed `EpochOnly` RESTORE would `AdoptForward` and silently lose the restore while the `strict_recovery_counter` had already burned).

**NOTE — the attested-ingress envelope is the new design surface this slice must define:** the `restore-ingress-v1` PAYLOAD is frozen, but the outer ATTESTED IMPORT envelope (`2d-hsm-agent-restore-ingress-v1` re-wrap: byte layout, length-prefix widths, `ingress_nonce` width/source, the AAD' fields, the destination ephemeral-key handshake) is spec-only with NO frozen golden — this slice MUST pin it and land a `restore_ingress_envelope_v1` golden, mirroring the slice-1/4c-2a discipline.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Attested confidential-ingress envelope (decrypt + verify). Accept the backup only via the `2d-hsm-agent-restore-ingress-v1` import envelope (KEM-DEM re-wrapped to the destination's ATTESTED ephemeral ML-KEM-1024 public key); the enclave decapsulates with its ephemeral private key and verifies AAD' BEFORE import: (a) the attestation/measurement is ITS OWN; (b) `chain_id` + `environment_identifier` equal the sealed config (a testnet blob into a mainnet enclave fails closed); (c) the key-ref manifest hash + the original-backup digest match. Mutating ANY AAD' field fails decap/import. Define + freeze a `restore_ingress_envelope_v1` golden (byte layout, length-prefix widths, `ingress_nonce`). Plaintext scalars exist only inside the attested destination TEE — never on the host.
- [ ] #2 Decode via the existing `parse_restore_ingress` (magic `2DRIGV1\0`, version == 1, single CBOR value, no trailing bytes, `deny_unknown_fields`); version != 1 hard-rejected (no migration window).
- [ ] #3 Wholesale-replace the restorable state as ONE atomic set: `entries`, the config-identity subset, `counters`, `faucet`, audit RECORDS, `strict_recovery_counter` from the decoded `RestoreIngressData`. NEVER import the payload-excluded material (producer ML-DSA/AuthorizationTicket, runtime signing creds, the seal root, `anchor_root`, `structural_version`, `freshness_epoch`).
- [ ] #4 Enclave-local `structural_version` (never a backup install). Set it enclave-locally — choose + document `local+1` vs a `strict_recovery_counter`-seeded fresh value. `freshness_epoch`/`anchor_root` are the restoring enclave's own. A backup-supplied value is never installed (the payload carries none).
- [ ] #5 `CommitBumpClass::RestoreCeremony` distinct commit path — NOT the generic `advance_commit_epoch(Structural)` `++` — that admits an enclave-local `structural_version` != `local+1` while preserving monotonicity, and whose reconcile rule registers the recovery as a distinct (non-`AdoptForward`) transition. A dropped/crashed RESTORE seal ⇒ `StructuralGap`→restore-retry, never a silent rollback.
- [ ] #6 Strict recovery counter advance + AC#11/#12 seeding. Advance + seal the shared `strict_recovery_counter` (forward-only, strictly `> current highest`) before emit. Capability counters + faucet cumulative-spend seeded NEVER from zero and NEVER from the possibly-stale backup alone — only from authenticated recovery material / the anchor's authenticated current marks / a strict-recovery-counter-bound override, accepted ONLY if `target > enclave's highest known`. Restore that would LOWER a high-water is rejected; a fresh TEE with no authenticated high-water source is rejected (no zero-init). State whether the forward-only strict-recovery-counter GATE lives here vs at TASK-18 un-gate.
- [ ] #7 Reconstruct the EXCLUDED audit cursors per the frozen rule: `next_seq = max(record.seq)+1` (or 1 if none); `last_exported_seq = next_seq-1` (restored ring starts fully drained); `capacity` from RESTORE-time policy (NOT the backup) with `capacity >= audit_records.len()` — else FAIL CLOSED, never truncate restored records (AC#14).
- [ ] #8 Faucet consistency: restore the treasury key AND its eligible transfer-key allowlist as one consistent set, or fail faucet signing closed until the allowlist is reconstructed + verified. Active-active treasury-key clones without a global spend/capability ledger stay prohibited.
- [ ] #9 Manifest set-matching (order/multiplicity-INSENSITIVE): a `[A,A]` or non-body-order `KeyRefs` selector is the same export as `[A]`/body-order and MUST NOT be wrongly rejected.
- [ ] #10 Recovery cap tier (`is_recovery`): verify the Ed25519 cap against the sealed `recovery_authority_pk` (`8 => cap.is_recovery`); an admin-signed cap for a restore ⇒ `0x43`. The recovery AUTHORITY (authorizes) and the ML-KEM WRAPPING key (decrypts) are distinct roles — a restore authorized by the recovery authority but wrapped to an ML-KEM key != the sealed `backup_recovery_wrapping_pubkey` MUST fail.
- [ ] #11 Release-banned behind a preview feature (mirroring `agent-keygen-exec-preview`) until a TASK-18-style un-gate; non-preview builds keep the `NotConfigured` fail-closed stub. EVERY error path on the live arm (decap fail, AAD mismatch, version mismatch, capacity overflow, counter-would-lower, seal fail, missing channel) fails closed with NO partial import + NO counter/anchor advance — seal-before-emit holds (compute → commit → swap → emit; a deterministic seal failure commits nothing). Reuse the `finalize_privileged_candidate`/`commit_before_emit` shared seam (slice 6-7) rather than re-duplicating the finalize block.
- [ ] #12 On-chain RecoveryTicket / MeasurementRegistry (TASK-1.4, 2d-solidity) is EXPLICITLY OUT of scope — a disjoint BlockProducer subsystem with zero references from the agent RESTORE path. The "recovery authority"/"recovery counter" here are the agent-gateway TASK-7.2/7.7 mechanisms. Also out of scope: Vault cap-fetch, OPA, cap pre-signing, ML-KEM private-key custody / the offline re-wrap step, host-side expiry/revocation, quorum/M-of-N recovery (`recovery_key_id` reserved, single-key MVP), classical hybrid X25519+ML-KEM, and authority rotation (`authority_epoch` reserved — restore under a rotated authority needs full re-provisioning in MVP).
<!-- AC:END -->

## Notes
<!-- SECTION:NOTES:BEGIN -->
**Depends on:** TASK-13 (EXPORT/KEM-DEM + the `restore-ingress-v1` decoder + golden — the wire half), TASK-7.2 (DR-backup design — the AC#11/#12/#13 restore-seeding contract this consumes), TASK-7.7 (anti-rollback — owns the strict-recovery-counter + `CommitBumpClass`/reconcile; this handler is the OPEN consumer of the `RestoreCeremony` commit path), TASK-18 (privileged-op un-gate — the forward-only strict-recovery-counter GATE precondition, jointly owned with `reset_lifetime_breaker` which shares the same counter).

**Carries the TASK-20 RESTORE residuals** (now owned here): the commit-class / enclave-local structural_version / strict_recovery_counter reconcile rule (the footgun is RESOLVED by the 4c-2a exclusion); the manifest set-matching + keyless-export notes.

**NOT a dependency:** TASK-1.4 (on-chain RecoveryTicket / MeasurementRegistry) — disjoint, OUT of scope (AC#12).

**Suggested approach:** slice it like 13b/4c — pin the attested-ingress envelope + golden FIRST (the new frozen contract, AC#1), then the live handler (decode → wholesale-replace → enclave-local structural + RestoreCeremony commit → counter seeding → cursor reconstruction), each behind the preview with the full review gate. Confirm the EXPORT drain-before-append OPEN decision (TASK-20) since it determines which audit record lands in this backup vs the next.
<!-- SECTION:NOTES:END -->
