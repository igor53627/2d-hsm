---
id: TASK-33
title: >-
  Constant-time capability gates (scope_identity + payload_binding) + ML-DSA
  variable-time accepted-risk note
status: In Progress
assignee: []
created_date: '2026-06-26 14:57'
updated_date: '2026-06-26 16:43'
labels:
  - security
  - constant-time
  - agent-gateway
  - hardening
dependencies: []
priority: medium
ordinal: 34600
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Defense-in-depth: route the secret-adjacent 32-byte equality gates in the capability path through subtle::ct_eq (the house standard already used for the fund-custody marks_digest gate in agent_boot.rs:274-276), and record the producer ML-DSA-65 non-constant-time signing property as an explicit accepted-risk.

Behavior is UNCHANGED — these gates still fail closed on mismatch (0x43 CapabilityRejected); only the comparison is made constant-time. Each gate is post-verify_strict, so a malicious host cannot freely prefix-probe today, but the sealed scope ids and signed payload_binding digests are secret-adjacent and the house standard is constant-time.

Sites (all [u8;32]):
- agent_capability.rs:481 — cap.scope_identity vs sealed enclave_scope_id/fleet_scope_id (clone-replay guard, TASK-18 18-2b)
- agent_dispatch.rs:1090 — GENERATE_KEYS payload_binding
- agent_dispatch.rs:1322 — CONFIGURE_TREASURY payload_binding (agent-configure-treasury-preview)
- agent_dispatch.rs:1550 — EXPORT_BACKUP payload_binding (agent-backup-export-preview)
- agent_dispatch.rs:1736 — RESTORE_BACKUP payload_binding (opcode 8)

ML-DSA-65 accepted-risk: producer signing goes through pqcrypto-mldsa (PQClean clean impl). PQClean's README lists "No branching on secret data" and "No access to secret memory locations" as UNCHECKED, still-in-development goals, so the clean impl gives no constant-time guarantee at all (it may branch on, and index memory with, secret-derived values); separately, ML-DSA's Fiat-Shamir-with-aborts loop has a data-dependent rejection-iteration count. The untrusted host can observe signing latency over vsock. Accepted because the Dilithium/ML-DSA design only guarantees the published signature distribution is secret-independent (zero-knowledge), which BOUNDS but does NOT eliminate the wall-clock / microarchitectural timing exposure of a non-hardened reference impl. Eliminating it requires a constant-time-hardened ML-DSA (library swap), not a local change. Migration path: PQClean is deprecated (archived read-only ~July 2026); successor is the PQ Code Package (PQCA). Documented in mldsa65.rs.

Polarity invariant: ct_eq returns subtle::Choice; the fail-closed form is `if !bool::from(a.as_slice().ct_eq(b.as_slice())) { return Err(CapabilityRejected) }`. Dropping the `!` inverts the gate into accept-on-mismatch (capability bypass) — every converted site keeps a negative test (mismatch produces 0x43).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All 5 secret-adjacent 32-byte gates use subtle::ct_eq with fail-closed polarity (mismatch produces 0x43)
- [x] #2 Each converted gate has a negative test asserting mismatch produces CapabilityRejected (guards against polarity inversion)
- [x] #3 ML-DSA-65 variable-time signing recorded as accepted-risk with threat model in mldsa65.rs
- [x] #4 cargo test passes for the agent-gateway feature set (capability + dispatch + relevant preview features)
- [x] #5 Full Matrix + roborev compact return clean (no open issues)
<!-- AC:END -->



## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
5 gates converted to subtle::ct_eq with fail-closed `!bool::from(..ct_eq..)` polarity; behavior unchanged (mismatch still 0x43).

Enumeration method (exhaustiveness, AC#1): grepped the capability path for ==/!= over [u8;32] secret-derived values. Boundary = the capability authorization path only; sealing/AEAD tag verification is already subtle-backed (Poly1305) and out of scope. The non-capability `backup_rid != sealed_rid` compare (agent_dispatch.rs) is over public-key-derived ids (not secret) and intentionally left as plain !=.

Guarding negative tests (AC#2 — mismatch => 0x43; a polarity inversion flips the matching path and breaks the paired happy-path test, so both directions are pinned):
1. scope_identity -> agent_capability::tests::enclave_scoped_cap_rejected_on_clone_with_different_enclave_id (+ fleet_scoped_cap_binds_to_fleet_id_not_enclave_id)
2. GENERATE_KEYS -> agent_dispatch::tests::generate_keys_payload_binding_mismatch_rejected
3. CONFIGURE_TREASURY -> agent_dispatch::tests::configure_treasury::payload_binding_mismatch_0x43
4. EXPORT_BACKUP -> agent_dispatch::tests::export_backup::export_payload_binding_mismatch_rejected
5. RESTORE_BACKUP -> agent_dispatch::tests::restore_backup::restore_backup_payload_binding_mismatch_rejected (NEW; provably reaches the 5b gate because its setup mirrors the passing restore_backup_restores_entries_end_to_end exactly except the injected wrong pb_override)

ML-DSA accepted-risk remediation owner: TASK-34 (constant-time-hardened ML-DSA migration, PQClean->PQCA), referenced from the mldsa65.rs note.

Tests: cargo test green for agent-gateway (584), the preview combo agent-keygen-exec-preview+agent-configure-treasury-preview+agent-backup-export-preview (703), and ml-dsa-65+reference-test-key (144). cargo fmt --check clean.
<!-- SECTION:NOTES:END -->
