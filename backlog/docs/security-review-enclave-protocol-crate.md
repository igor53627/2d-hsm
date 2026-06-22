# Security Review: enclave-protocol Crate (TASK-1.7)

**Date:** 2026-06-22
**Scope:** Full security audit of `impl/rust/enclave-protocol/src/` (~52k lines)
**Threat model:** MALICIOUS HOST over vsock — arbitrary opcodes, payloads, replayed frames, timing control, configfs-tsm wedging, anchor channel manipulation
**Method:** 5 parallel analysis tracks (secret material flow, capability surface, attestation & anti-rollback, signing operations, error handling) + cross-verification of all HIGH/MEDIUM findings

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| HIGH     | 0     | — |
| MEDIUM   | 3     | TASK-29 (M-3), TASK-30 (M-1), M-2 accepted-risk |
| LOW      | 4     | Documented / deferred |
| INFO     | 3     | No action |

The crate demonstrates strong security discipline: fail-closed error handling on all critical paths, comprehensive AEAD sealing, zero unwrap/expect on untrusted input, sound capability verification, correct anti-rollback, and proper attestation binding. The PQ private key is correctly held in `Zeroizing<Vec<u8>>` with manual Debug redaction. No HIGH-severity exfiltration, bypass, or forge path was found.

Three MEDIUM findings relate to **secret-scrubbing gaps**: M-1 (ProvisionSession `derive(Debug)` over the provisioning root — a latent leak: no current code path Debug-formats the session, but `derive(Debug)` makes it trivial for a future change to do so via a panic message to journald, which is host-readable), M-2 (pqcrypto SecretKey transient — upstream limitation, no in-crate zeroize possible), M-3 (stale Cargo.toml docs — documentation, not a vulnerability). M-1 and M-2 require either a panic path that formats the session (M-1) or freed-memory access (M-2) to exploit — neither is a live exfiltration path today, but both violate the "all plaintext copies are scrubbed" invariant. Remediation: M-1 → TASK-30, M-3 → TASK-29, M-2 → accepted-risk waiver.

---

## MEDIUM Findings

### M-1: ProvisionSession derives Debug over the keystore provisioning root

**File:** `agent_provision.rs:959-962`
**Track:** Secret Material Flow

`ProvisionSession` is `#[derive(Debug)]` while holding `seal_root: [u8; 32]` — a bare `Copy` array with no `Drop`/`Zeroize`. `seal_root` IS the keystore provisioning root: `on_m3` passes `&self.seal_root` into `seal_body → derive_aead_key`, which derives the XChaCha20Poly1305 key encrypting EVERY secp256k1 secret scalar at rest.

Two violations:
- (a) Debug-formatting this struct (via `{:?}`, panic message, tracing span) prints all 32 root bytes — `[u8;32]`'s Debug emits every byte.
- (b) `[u8;32]` is `Copy` with no `Drop` — the root is NEVER scrubbed when the session is dropped. Every Copy through the M1→M4 handshake leaves un-scrubbed root bytes on the stack.

Contradicts the repo's own zeroize rule (`seal_root.rs:77-83`). The session ships in production (agent-gateway feature).

**Exploit:** A malicious host triggers any path that debug-formats ProvisionSession → provisioning root dumped to stderr/journald → host derives AEAD key → decrypts all sealed secp256k1 scalars offline.

**Fix:** Remove `#[derive(Debug)]` or impl manual Debug redacting `seal_root`. Change `seal_root: [u8;32]` to `Zeroizing<[u8;32]>`.

### M-2: Per-signature pqcrypto SecretKey copy (4032 bytes) never scrubbed

**File:** `mldsa65.rs:108-122`
**Track:** Secret Material Flow

Every `sign_ticket_hash` call materializes the full 4032-byte ML-DSA-65 secret key as `pqcrypto::SecretKey::from_bytes(...)`. pqcrypto's `SecretKey` is `Copy` with no `Drop`/`Zeroize`. When the transient goes out of scope, 4032 bytes remain in freed stack/heap memory. This is the **production signing hot path** — each signature leaves a fresh copy.

The stored long-term key IS correctly `Zeroizing<Vec<u8>>` (line 31). The issue is the per-signature transient copy. Acknowledged upstream limitation (pqcrypto type cannot self-scrub).

**Exploit:** A malicious host with enclave memory disclosure (side-channel, core dump, heap reuse) recovers a residual 4032-byte copy. Signing frequency amplifies exposure.

**Fix:** Document accepted-risk waiver with operator sign-off, or wrapper/fork that zeroizes on drop.

### M-3: PROVE_IDENTITY release-ban removed; Cargo.toml doc-comments stale

**File:** `lib.rs:86-88` (ban removed) vs `Cargo.toml:67-72` (still says "Never enable in production")
**Track:** Signing Operations

The `compile_error!` release-ban for `agent-prove-identity-preview` was INTENTIONALLY removed (TASK-18) because the 2D type-0x19 reservation MERGED (commit f3908deb). However:
- Cargo.toml:67-72 still says "Never enable in a production build before that reservation merges" — directly contradicts lib.rs.
- The collision-disjointness argument now depends on an external repo (2D) commit that this crate cannot assert, test, or pin.
- The 8 remaining `compile_error!` sites in lib.rs cover other features but NOT prove-identity.

**Exploit:** Not directly exploitable (the 2D reservation IS merged). The risk is operational: an operator reading Cargo.toml believes the feature is still release-banned; a future 2D regression removing the type-0x19 reservation would re-open the collision window with no compile-time guard here.

**Fix:** Update Cargo.toml doc-comments to match lib.rs (ban removed, 2D reservation merged). Consider pinning the 2D commit hash as a provenance reference.

---

## LOW Findings

### L-1: No distinctness check on admin_authority_pk vs recovery_authority_pk

**File:** `agent_keystore.rs:1007-1079` (KeystoreBody::validate)
**Track:** Capability Surface

`validate()` enforces scope-id distinctness (all-zero/identical rejected) but has NO equivalent for the two authority pubkeys. If provisioning seals `admin_pk == recovery_pk`, the tier check becomes vacuous — an admin key holder can forge a recovery-tier capability.

Not directly host-exploitable (the sealed config is AEAD-authenticated, set in-TEE at provisioning). Defense-in-depth completeness gap parallel to the existing scope-id guard.

**Fix:** Add `admin_authority_pk == recovery_authority_pk` and all-zero checks to `validate()`.

### L-2: Lab file-source root loaders read provisioning root into non-Zeroizing Vec

**File:** `boot_agent_keystore.rs:65-85`, `platform_provisioning_boot.rs:46-54`
**Track:** Secret Material Flow

Root read into `Vec<u8>` → `try_into::<[u8;32]>()` → Vec freed without zeroize. Behind lab/release-banned features (`lab-agent-keystore-from-file`), but the pattern is wrong and a production file-hook wired the same way would leak.

### L-3: Mutex poison recovery on INSTALLED_KEYSTORE (availability vs conservative tradeoff)

**File:** `agent_dispatch.rs:2509-2515`
**Track:** Error Handling

Poison recovery via `.unwrap_or_else(|p| p.into_inner())` continues serving after a dispatch panic. Safe today because the only mutation is an infallible single-assignment swap AFTER all fallible steps. Forward-looking: a future multi-step mutation under this lock could leave inconsistent state.

### L-4: `seal_backup_blob_with_m` (deterministic-encaps) not cfg-gated to test

**File:** `agent_backup.rs:200`
**Track:** Secret Material Flow

Private fn, NOT `#[cfg(test)]` — compiles in production. Production caller (`seal_backup_blob`) correctly draws `m` from CSPRNG. But a future caller with a fixed/reused `m` would cause catastrophic ChaCha20Poly1305 keystream reuse. Asymmetric with the test-gated `seal_restore_ingress_envelope_with_m`.

---

## INFO Findings

- **I-1:** `generate_keypair` leaves transient pqcrypto SecretKey unscrubbed (cfg-gated to provisioning/test — `mldsa65.rs:84-91`)
- **I-2:** Deterministic seed path (`install_restore_ephemeral_with_seed`) is properly cfg-gated — VERIFIED CLEAN (`agent_dispatch.rs:2027-2080`)
- **I-3:** Three distinct mutex poison-handling patterns (recover, fail-closed, exit) with no type-level enforcement (`agent_dispatch.rs` multiple sites)

---

## Clean Areas (Verified PASS)

| Area | Verdict | Summary |
|------|---------|---------|
| secp256k1 signing | CLEAN | `ZeroizeOnDrop` SigningKey, no Debug derive, no vsock leak |
| Key generation | CLEAN | `Zeroizing` scalar, CSPRNG draw, rejection-sampled with scrubbed rejects |
| Seal root | CLEAN | `Zeroizing` copy, install-once, explicit bare-Copy avoidance |
| Keystore seal/unseal | CLEAN | Pre-sized buffers (no realloc leak), `KeyEntry` redacting Debug |
| Restore-ephemeral decaps seed | CLEAN | `Zeroizing<[u8;64]>`, no Debug, explicit scrub after use |
| KEM-DEM backup envelope | CLEAN | SharedKey scrubbed, payload keys Zeroizing |
| PQ signer install | CLEAN | `Zeroizing` wrap, zeroize on all paths (success + fail) |
| Capability verification | CLEAN | Single chokepoint, Ed25519 verify + tier check + binding before handler |
| Anti-replay | CLEAN | Signed request_id + payload_binding + counter contiguity |
| SNP attestation binding | CLEAN | Measurement checked in every verify function |
| Anti-rollback | CLEAN | Monotonic reconcile, strict_recovery_counter, fail-closed |
| Anchor channel | CLEAN | Ed25519-verified, scope from sealed config, never host-trusted |
| Error handling (unwrap/expect) | CLEAN | Zero production unwrap on untrusted input |
| Seal-before-emit | CLEAN | Every mutation seals BEFORE emit; seal failure aborts, no partial state |
| CSPRNG failure | CLEAN | getrandom failure is fatal, no weak-randomness fallback |

---

## Recommendations (Priority Order)

1. **M-1:** Remove Debug from ProvisionSession + Zeroizing seal_root — highest priority (only Debug-over-secret struct, root is keystore AEAD master)
2. **M-3:** Update Cargo.toml doc-comments for all agent-*-preview features to match lib.rs (bans removed under TASK-18)
3. **L-1:** Add admin_pk != recovery_pk distinctness check to KeystoreBody::validate()
4. **M-2:** Document accepted-risk waiver for pqcrypto SecretKey transient (or pursue zeroizing fork)
5. **L-4:** Consider cfg-gating `seal_backup_blob_with_m` to test for symmetry
