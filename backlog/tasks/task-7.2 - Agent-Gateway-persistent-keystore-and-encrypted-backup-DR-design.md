---
id: TASK-7.2
title: Agent Gateway persistent keystore and encrypted backup DR design
status: In Progress
assignee: []
created_date: '2026-06-07 00:00'
labels:
  - agent-gateway
  - backup
  - recovery
  - tee
dependencies:
  - TASK-7.1
  - TASK-5
  - TASK-6
references:
  - backlog/docs/agent-gateway-secp256k1-signer-design.md
  - backlog/docs/agent-gateway-keystore-backup-format.md
  - backlog/docs/pq-seal-v1-provisioning-runbook.md
priority: high
ordinal: 7020
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design the persistent multi-key agent keystore and encrypted backup blob semantics. The blob must be usable for disaster recovery under an explicit recovery ceremony, not merely same-process restart, and plaintext private keys must never leave the TEE/runtime boundary.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The new Agent Gateway keystore records key ref, purpose, algorithm, public identity, creation metadata, and backup/export metadata for agent keys only; existing producer ML-DSA/AuthorizationTicket custody remains in its current sealed-blob path unless a later reviewed task explicitly migrates it.
- [x] #2 Production Agent Gateway sealed state, keystore, authority roots, and provisioning capabilities are separate from producer sealed state and cannot store producer ML-DSA keys or AuthorizationTicket state.
- [x] #3 Backup blob format defines version, included key refs, encryption/authentication domain, recovery wrapping mechanism, and an authenticated header/manifest self-check that rejects truncated or malformed exports before success is returned.
- [x] #4 The design states whether restore is same-measurement only, same-fleet only, or allowed onto a newly provisioned TEE.
- [x] #5 The enclave enforces maximum batch size, total keystore capacity, and fail-closed behavior on full storage or persistence-write failure.
- [x] #6 Runtime signing credentials cannot generate keys, export backups, restore backups, or access recovery material; privileged commands require TEE-verified administrative capability.
- [x] #7 Export test requirements prove blobs are opaque to the host and do not contain plaintext private keys.
- [x] #8 Sealed state includes configured 2D chain id, environment identifier, administrative authority public key, recovery/quorum authority public key or threshold root, backup-recovery wrapping public material, highest accepted capability counter per `(authority, environment_identifier, scope_class, scope_target)` scope, faucet cap values, faucet cumulative spend counters, monotonic treasury config version, and required privileged-operation audit metadata.
- [x] #9 The pq-seal provisioning runbook is amended to describe choosing and installing the configured 2D chain id, operator-assigned environment identifier, administrative authority public key, recovery/quorum authority root, backup wrapping material, and initializing replay/cap state; the runbook covers wedged-scope counter recovery as an expected operational procedure.
- [x] #10 The design defines anti-rollback requirements for sealed counters or explicitly marks cumulative caps/replay counters as host-rollback-sensitive residual risk.
- [x] #11 Restore semantics prevent stale backup restore from rolling capability counters or faucet spend counters backwards; any recovery/quorum override is replay-protected by a target counter greater than the enclave's highest known value or by an independent strict recovery counter, with residual risk recorded.
- [x] #12 Restore onto a fresh TEE seeds capability and faucet spend high-water marks from authenticated recovery material, a remote monotonic ledger, or operator-signed boot authorization; it never defaults counters to zero from a stale backup.
- [x] #13 Cross-TEE DR backup wrapping is independent of the source enclave's local seal root; same-enclave restart and newly provisioned TEE restore keying assumptions are specified separately.
- [x] #14 Privileged-operation audit metadata has bounded retention plus an authenticated export or attested log-streaming path before required entries can roll over.
- [x] #15 The design specifies secp256k1 zeroization behavior directly and aligns it with TASK-6's decided zeroization outcome when available; it also states process-abort residual risk.
- [x] #16 Sealed keystore format versioning, fail-closed unknown-version handling, and reviewed forward-migration rules are specified.
- [x] #17 Treasury-key rotation is deferred or specified with counter carry-over semantics; spend counters never reset merely because a replacement treasury key is generated.
- [x] #18 Key generation atomically seals both administrative capability counter advancement and generated key metadata before returning usable refs; partial failures produce a recoverable/reconcilable signal rather than silent orphan refs.
- [x] #19 The agent keystore encryption key is derived from the provisioning root with domain-separated key derivation (HKDF or a SHA3-based KDF bound to a unique agent-keystore label, e.g. `2d-hsm-agent-keystore-v1`) so it cannot collide or overlap with producer ML-DSA key material derived from the same root.
- [x] #20 Roborev matrix/compact evidence is recorded before merge.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design delivered in `backlog/docs/agent-gateway-keystore-backup-format.md`: two new sealed
formats — `pq-agent-keystore-v1` (multi-key sealed keystore) and `pq-agent-backup-v1` (DR
backup) — reusing the `pq-seal-v1` AEAD / SHA3-KDF / header / AAD / `Zeroizing` primitives
and the SNP-derived provisioning root, with distinct magics + domain labels (AC#1/#2/#16/#19).
Covers the full sealed-state inventory (AC#8), multi-key entry list + capacity + atomic keygen
(AC#1/#5/#18), DR backup wrapping independent of the seal root (AC#3/#6/#13), restore scope +
never-zero/stale counter seeding (AC#4/#11/#12), the 7.2-vs-7.7 rollback boundary + residual
risk (AC#10), privilege model (AC#6), secp256k1 zeroization (AC#15), audit retention (AC#14),
runbook amendments (AC#9 → runbook §9), and golden-vector/test requirements (AC#7).

Locked decisions: reuse pq-seal-v1 primitives (new layouts); single operator recovery key for
DR wrapping (quorum descriptor reserved); **ML-KEM** (pure PQ) backup envelope — residual: no
classical hybrid layer, flagged for review; fresh-TEE restore onto an operator-approved
measurement allowlist; canonical CBOR; authority rotation deferred (epoch field reserved);
bounded audit ring + backpressure.

AC #1–#20 addressed: the roborev 3×3 matrix (codex + gemini + claude-code × security / design / default, 9 cells) was run on this branch and its findings resolved in-PR — corrected the ML-KEM **KEM-DEM** construction (ML-KEM-1024, no chosen DEK; payload key = KDF(shared secret)), defined the **confidential fresh-TEE restore ingress** (attested ephemeral re-wrap, reconciling "private key never in a production TEE"), added the backup **`payload_nonce`** + **cross-environment AAD binding** (chain_id/env_id) + `kem_ct`-in-AAD, big-endian header note, and replaced stale `design.md` line citations with section anchors.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Backup/restore semantics are documented before implementation.
- [x] #2 Test requirements cover export failure, malformed restore input, and no private-key leakage.
- [x] #3 Final summary added before marking Done.
<!-- DOD:END -->
