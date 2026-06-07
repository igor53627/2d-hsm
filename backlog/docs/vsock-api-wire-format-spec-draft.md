# TEE Signing Service — vsock API + Wire Format Specification (Draft v0.1)

**Task**: TASK-2  
**Date**: 2026-06-05 (architecture update 2026-06-02)  
**Status**: Draft **v0.2** — post-TASK-3 crypto gate; ML-DSA-65 + dual-path aligned with 2d TASK-122 / theory-378 TASK-92.1.8  
**Goal**: Define the communication protocol between the 2D host (Block Producer) and the minimal post-quantum signing service running inside a TEE (Nitro Enclave / SEV-SNP).

**Changelog v0.2:** §2 cryptography profile (ML-DSA-65), dual-path (hot TEE vs slow MAYO-iO), terminology (TEE remote attestation vs Producer Chain Attestation). Wire sizes for PQ signatures (TASK-1). §2.4 AF_VSOCK bind env (`TWOD_HSM_VSOCK_*`, not `2D_HSM_*` — systemd-safe). Empty `pq_pubkey` when `pq_signing_ready == false` (transport/bootstrap); attestation↔key binding applies only when a signer is installed. Host migration: empty `pq_pubkey` is valid on the wire when `pq_signing_ready == false`. Legacy `2D_HSM_*` env names accepted until **protocol v2** (no removal date before first external deployment). Ready for roborev Reduced matrix on `backlog/docs/*vsock*`.

## 1. Why this API exists

The signing service runs inside a TEE. The host (Elixir Block Producer process) is untrusted.

All sensitive operations must happen inside the enclave:
- Holding and using the long-term PQ Block Producer key.
- Generating and signing `AuthorizationTicket` (both recovery and hard-fork types).
- Deciding whether it is allowed to sign blocks at all (network second factor + authorized producer state).
- Transitioning to a new code measurement during a hard fork.

The only communication channel we trust is **vsock** (AF_VSOCK).

## 2. Cryptography profile and dual-path architecture (2026-06)

### 2.1 Post-quantum signing (hot path — this service)

| Parameter | Value |
|-----------|--------|
| **Algorithm** | **ML-DSA** (FIPS 204) |
| **Parameter set** | **ML-DSA-65** (NIST Level III) — frozen for producer + tickets + on-chain verify (2d TASK-122) |
| **Implementation (target)** | [mldsa-native](https://github.com/pq-code-package/mldsa-native) / `mldsa-native-rs` inside the TEE (2d-hsm TASK-1) |
| **Signing mode** | Hedged (FIPS 204 default; not deterministic) |
| **Message form** | **Pure ML-DSA** over the raw 32-byte `ticketHash` (or block digest) — **not** HashML-DSA pre-hash |
| **Context `ctx`** | Empty (`len(ctx) = 0`) unless a future spec version defines a non-empty domain string (both enclave and 2d precompile must match) |
| **RNG** | Hedged signing requires a CSPRNG inside the TEE (platform TRNG / NSM-seeded `getrandom`); silent RNG failure must abort sign (fail closed) |
| **Wire sizes (production)** | `pq_pubkey` **1952** bytes when `pq_signing_ready == true`, else **empty** (`b''`); `signature` **3309** bytes per ML-DSA-65 |
| **Protocol version** | Two layers (must stay in sync): (1) **framed** byte after the 4-byte length prefix (`PROTOCOL_VERSION`, currently **1**); (2) **inner** CBOR map key `1` on ARM / GET_STATUS / SIGN payloads (also **1**). Stay on **v1** until an external deployment exists; use `pq_signing_ready` + signature length (3309 B) to detect mock-era peers |

**Default / production reference builds** do not embed a PQ secret key: `pq_signing_ready` is **false** and `SIGN_AUTHORIZATION_TICKET` returns `PqSigningUnavailable`. For local demos only, enable `test-support` + `demo-mock-sign` (64-byte mock PQ sig; `pq_signing_ready` stays **false**). For `cargo test` with real ML-DSA-65 sizes, enable `reference-test-key` (implies `ml-dsa-65`): tests install the NIST test-vector key via the v0 sealed-blob path — **not** a production signer and **not** enabled in standalone binaries. Hosts and precompiles **must not** treat 64-byte PQ signatures as valid on-chain.

**Production sealed-key provisioning (TASK-1):** The reference crate's **v0 XOR seal is unit-test only**. Production **unseal path** uses **seal v1** (AEAD + measurement digest + provisioning root). At enclave boot (not vsock): (1) `set_pq_seal_v1_provisioning_root(root)` once — root from platform integration (vTPM / SNP / Nitro; **not yet wired** in reference images), not the host; (2) `install_sealed_pq_signer(sealed_blob, enclave_measurement)`. **Seal** helpers live only under feature `pq-seal-provisioning` (offline `pq-seal-v1` CLI — absent from enclave deploy builds). Runbook: `backlog/docs/pq-seal-v1-provisioning-runbook.md`. Do not use v0 in deployable binaries.

**Sealed blob v1 (implemented in reference crate):**

| Field | Requirement |
|---|---|
| Version byte | `0x01` (`SEALED_BLOB_V1_VERSION`) |
| Binding | Ciphertext + MAC/AEAD must bind to enclave launch `measurement` and `pq_pubkey` (no host-chosen measurement in cleartext) |
| Key material | ML-DSA-65 SK + PK; install runs `from_verified_key_bytes` (sign+verify self-test) before accepting |
| Secrecy | Platform seal secret (vTPM / SNP VMPL / Nitro PCR-derived key) — **not** XOR of public inputs |
| Install | Once per enclave process; second install without restart returns error (no silent overwrite) |
| API | Same entrypoint: `install_sealed_pq_signer(sealed_blob, enclave_measurement)` at enclave boot only (not vsock) |

**v1 wire layout (reference crate):** `magic[8]="2DHSMV1\\0"` · `version=1` · `meas_digest[32]=SHA3-256("2d-hsm-pq-seal-v1-meas"‖measurement)` · `nonce[12]` · `ciphertext+tag` (ChaCha20-Poly1305 over `sk‖pk`, AAD = magic‖version‖meas_digest, key = SHA3-256("2d-hsm-pq-seal-v1-key"‖provisioning_root‖meas_digest)). Measurement bytes are **not** stored in cleartext.

Reference implementation status: v1 **unseal + install** in `ml-dsa-65` builds when a provisioning root is configured: `set_pq_seal_v1_provisioning_root` (production), or `reference-seal-v1-root` / `cargo test` (staging/CI only). **Seal:** `seal_mldsa65_keypair_v1_with_root` in library; offline **`pq-seal-v1`** CLI (`impl/rust/pq-seal-v1/README.md`). Sealed blob size **6053** bytes. Production TEE images must use a platform-derived root (vTPM / SNP VMPL / Nitro); **do not** ship `reference-seal-v1-root` or `testvectors/seal_v1_provisioning_root.bin` in deployment binaries.

**Scope of ML-DSA-65 inside this enclave:**
- Canonical block-root / header-digest signing (BlockProducer hot path).
- All `AuthorizationTicket` signatures (`SIGN_AUTHORIZATION_TICKET`).
- `pq_pubkey` returned by `GET_MEASUREMENT` / armed state (empty until PQ signer installed — see §8 GET_MEASUREMENT).

### 2.2 Dual-path policy (hot vs slow)

Production BlockProducer cryptography uses **two paths**. They use **different keys**, **different codebases**, and **different verify hooks**. This vsock API implements **only the hot path**.

| Path | Where | Crypto | Latency |
|------|-------|--------|---------|
| **Hot (normative here)** | `2d-hsm` TEE over vsock | ML-DSA-65 + §9 Producer Chain Attestation (Ed25519) | Every block (~2s); every ticket |
| **Slow (optional)** | `theory-378` GPU / MAYO-iO | **MAYO-iO** checkpoint (~5–10 min) | Bridge / strong finality anchor only |

**Non-goals on the hot path:**
- **ML-DSA inside iO** or Dilithium hybrid-iO (research in theory-378 only).
- **SPHINCS+ iO** as default slow path (2d TASK-120 worktree — oversized on-chain signatures).
- Slow-path artifacts **must not** alter vsock command schemas, `ticketHash` canonicalization, or `ProducerAttestationTrust` provisioning without a spec version bump.

Normative slow-path design: **theory-378 TASK-92.1.8**. Integration with 2d bridge revert policy is out of scope for v0.2 vsock.

### 2.3 Terminology: two different “attestation” concepts

| Term | Mechanism | Used for |
|------|-----------|----------|
| **TEE remote attestation** | Platform report (SEV-SNP / Nitro): `measurement` + `attestation` blob in `GET_MEASUREMENT` | Proving **which enclave image** holds `pq_pubkey`; permissionless recovery tickets |
| **Producer Chain Attestation** | **Ed25519** over §9.1 preimage (`RecentChainProof.signature_from_recent_producer`) | **Network second factor** before `ARM_FOR_PRODUCTION` / hard-fork sign; defends against **untrusted host** forging chain view |

Do **not** conflate them:
- TEE attestation does **not** prove current chain height or recovery tail.
- Producer Chain Attestation does **not** replace ML-DSA block or ticket signatures.
- The Ed25519 verifying key (`ProducerAttestationTrust`) is **not** derived from `pq_pubkey` (see §9.3).

User and bridge transactions on 2d remain **secp256k1** until a separate wallet PQ migration (2d TASK-24). The producer/recovery vsock surface described in this draft does not sign Ethereum-style user txs; the Agent Gateway extension is a separate command namespace with its own key purposes, policies, and versioned test vectors.

### 2.4 AF_VSOCK transport (bind address)

The reference enclave listens on **AF_VSOCK** before accepting framed commands (§5+). Operator configuration uses environment variables on the **guest** (TEE VM / enclave process):

| Variable | Required | Default (reference) | Semantics |
|----------|----------|---------------------|-----------|
| `TWOD_HSM_VSOCK_CID` | no | `4294967295` (`VMADDR_CID_ANY`) | VSock CID the enclave **binds** inside the guest (Nitro dev may use `3`; QEMU/SEV guests often set explicitly, e.g. `42`) |
| `TWOD_HSM_VSOCK_PORT` | no | `5000` | VSock port (service listener) |

**Naming rule:** Use the `TWOD_` prefix, not `2D_`. POSIX and **systemd** reject environment keys that start with a digit, so `2D_HSM_VSOCK_CID` in a unit file is silently ignored and the process falls back to defaults (misconfiguration).

**Legacy `2D_HSM_*` (sunset):** The reference crate accepts deprecated `2D_HSM_*` only when the canonical `TWOD_HSM_*` variable is unset (`env_config::var_twod`). Removal is planned for **wire/protocol v2** (next breaking version after the first external deployment); until v1 is retired in the field, operators must migrate unit files to `TWOD_*`.

**Host connect address (untrusted orchestrator):** The host connects to the guest using the hypervisor-assigned guest CID (e.g. QEMU `-device vhost-vsock-pci,guest-cid=42` → host uses CID **42**, while the guest may bind with `TWOD_HSM_VSOCK_CID=42` on virtio-vsock). Nitro loopback dev hosts often use CID `1` or `4294967295` (`VMADDR_CID_ANY`) for bind; production QEMU/SEV guests must match `guest-cid`.

**Addressing only:** `TWOD_HSM_VSOCK_CID` selects which local vsock address the enclave **binds** — it is **not** an authentication boundary. Default `VMADDR_CID_ANY` means “accept on whichever guest CID the hypervisor assigned”; security rests on TEE measurement, sealed PQ provisioning, and command invariants (§9), not on pinning this integer.

**Security:** Vsock is still an untrusted channel for *request content*; only the enclave-side bind + TEE measurement establish which process speaks the protocol. Framing and command semantics are unchanged by transport env.

**Fatal state (reference socket servers):** If the shared `EnclaveState` mutex is poisoned (panic while holding the lock), the reference `enclave-protocol` socket servers call `process::exit(1)` so a supervisor restarts a clean process (NixOS module: `Restart = "always"`, `RestartSec = 3`). This is fail-closed: corrupted in-memory authorization state is not served. Recovery assumes the poison trigger is not replayed on every reconnect (otherwise exit→restart cycles degrade availability). `exit` does not run Rust destructors; PQ key material relies on TEE memory teardown / platform guarantees rather than `Drop`-time zeroization.

## 3. Design Principles

- Minimal surface. Fewer commands = easier to audit and reason about.
- Explicit security invariants per command.
- Support the hard fork flow from day one (not bolted on later).
- Easy to implement correctly on both sides.
- Versioned from the beginning.
- Prefer simple, deterministic encoding over "nice" encoding.

## 4. High-Level Command Groups

We currently foresee four groups:

1. **Identity & Measurement**
   - Get current TEE measurement + remote attestation.
   - Get current public key.

2. **Ticket Operations** (core for recovery + hard forks)
   - Prepare / sign `AuthorizationTicket`.

3. **Production Authorization**
   - Arm the service for a specific authorized producer state (comes from on-chain).
   - Check current authorization status.
   - (Future) Request network freshness proof before arming.

4. **Hard Fork Transition**
   - Announce / prepare for upcoming hard fork (new measurement + scheduled block).
   - Switch active measurement at the scheduled height.

## 5. Proposed Command Set (v0.1)

All communication is request → response over a single vsock connection (or one connection per logical session).

### Encoding choice (to be decided in this task)

Options under consideration (in order of current preference):
- **Length-prefixed CBOR** (good balance of simplicity, determinism, and tooling).
- Simple binary (u32 length + tag + payload).
- JSON (only for very early prototyping — not recommended for production).

We will pick one and justify it in this document.

### Commands

#### 1. `GET_MEASUREMENT`

Request:
```cbor
{
  "cmd": "get_measurement",
  "version": 1
}
```

Response:
```cbor
{
  "measurement": h'....',           // raw SEV-SNP measurement or Nitro PCRs
  "attestation": h'....',           // TEE remote attestation document (platform — not §9 Ed25519)
  "pq_pubkey": h'....',             // empty when pq_signing_ready is false; 1952 bytes (ML-DSA-65) when true
  "supported_ticket_types": [0, 1], // static capability list (see formal CBOR section)
  "pq_signing_ready": false,
  "cert_chain": h'....'             // key 7: SNP VCEK->ASK->ARK chain (auxblob); optional, empty when absent
}
```

`supported_ticket_types` is a static capability list, not current readiness. Type 1 additionally requires armed state (`GET_STATUS`).

Security invariant: When `pq_signing_ready == true`, `measurement` and `pq_pubkey` MUST be bound together in the **TEE remote attestation** document (§2.3). When `pq_signing_ready == false`, `pq_pubkey` is empty (`b''`); hosts use `measurement` + `attestation` for image identity only — no operational PQ key is advertised yet.

**Operational readiness:** If `pq_signing_ready == false`, the enclave is **non-operational** for producer duties. Hosts and precompiles **MUST NOT** call `ARM_FOR_PRODUCTION`, register the enclave as the active producer, or expect valid on-chain PQ signatures. The enclave **MUST** reject `ARM_FOR_PRODUCTION` with a wire error until an operational PQ signer is installed.

#### 2. `SIGN_AUTHORIZATION_TICKET`

This is the most important command for both recovery and hard forks.

Request:
```cbor
{
  "cmd": "sign_authorization_ticket",
  "version": 1,
  "ticket": {
    "ticket_type": 0 | 1,           // 0 = PRODUCER_RECOVERY, 1 = HARD_FORK_ACTIVATION
    "nonce": 123,
    "context_hash": h'...',
    "activation_height": 1234567,
    "new_measurement": h'...',
    "pq_pubkey": h'...',
    "fork_spec_hash": h'...' | null,   // required for hard fork
    "new_header_version": 2 | null,    // for hard fork + header versioning
    "governance_ref": h'...' | null
  }
}
```

Response (on success):
```cbor
{
  "signature": h'...',    // ML-DSA-65: 3309 bytes (production); mock 64 B only with test-support
  "ticket_hash": h'...'   // the hash that was actually signed
}
```

On error: structured error with reason.

**Security rules the enclave must enforce** (aligned with §8 formal invariants — **AND**, not OR):
- For `ticket_type == 1` (Hard Fork): the enclave **must** be armed as the authorized producer **and** the request `pq_pubkey` **must** match the armed key (see also line 403).
- The enclave **must** have validated `RecentChainProof` at arming (network second factor); hard-fork sign **re-runs** that validation on the armed snapshot.
- `activation_height` **must** be strictly greater than `finalized_height` from the armed `RecentChainProof` (not merely “not in the past” vs wall-clock or chain tip).

#### 3. `ARM_FOR_PRODUCTION`

Tells the enclave "from now on you are allowed to sign blocks as the authorized producer with this state".

Request:
```cbor
{
  "cmd": "arm_for_production",
  "version": 1,
  "authorized_producer": {
    "pq_pubkey": h'...',
    "measurement": h'...',
    "activated_at_height": 1234560,
    "source_ticket_hash": h'...'
  },
  "recent_chain_state": { ... }   // proof or recent headers (for second factor)
}
```

Response:
```cbor
{ "status": "armed" | "refused", "reason": "..." }
```

#### 4. `GET_STATUS`

Simple liveness + current mode.

Response includes:
- Current armed state
- Current measurement + pubkey
- Whether it has seen a pending hard fork announcement
- Last known on-chain authorized producer (if it tracks it)

#### 5. `PREPARE_HARD_FORK` (optional but useful)

Allows the current producer to tell the enclave in advance about an upcoming hard fork.

This lets the enclave start refusing to sign blocks after a certain height unless it has transitioned, etc.

## 6. Hard Fork Flow using this API (end-to-end sketch)

1. Current producer decides to do a hard fork at block 1_500_000.
2. Host calls `PREPARE_HARD_FORK` (or directly `SIGN_AUTHORIZATION_TICKET` with type=1).
3. Enclave signs the `HARD_FORK_ACTIVATION` ticket (after checking it is still the authorized producer and has fresh enough chain view).
4. Host submits the ticket on-chain via the precompile.
5. When the chain approaches block 1_500_000:
   - Host calls `ARM_FOR_PRODUCTION` again with the new measurement (or the enclave switches internally).
6. After the scheduled height, the enclave only signs blocks if the header version matches the one announced in the ticket + it is using the new measurement.

## 7. Encoding Decision (A — done 2026-06-05)

**Chosen encoding: Length-prefixed CBOR with explicit protocol version**

### Rationale

- **Deterministic encoding** — critical because some payloads (especially tickets) may be hashed or have security implications.
- **Good tooling on both sides**:
  - Rust: `ciborium` + `serde` (very mature, used in many TEE projects).
  - Elixir: `cbor` or `ex_cbor` libraries exist and are usable.
- **Self-describing enough** for debugging, while still compact.
- **Easy to version** at the top level.
- Better than raw custom binary for auditability (readers can use standard CBOR tools).
- Better than JSON for production (smaller, faster, no string escaping issues, deterministic when using canonical CBOR).

**Rejected alternatives**:
- Pure custom binary → higher risk of subtle bugs in parsing.
- JSON → too verbose, non-deterministic by default, slower.
- MessagePack → similar to CBOR but less standardized in the TEE/attestation world.

### Framing (updated after Claude-code design review on commit 0262bd5, 2026-06-05)

Every message on the vsock is:

```
[ u32 total_length (big-endian) ]   // length of the bytes *following* this field
[ u8  protocol_version (currently 1) ]
[ u8  message_type ]
[ CBOR payload ]
```

- `total_length = 2 + payload.len()` (version + type + payload).
- This is the convention actually implemented in the reference crate (`enclave-protocol`).
- The previous wording ("includes the 6-byte header") was incorrect and has been aligned with the implementation to avoid interop breakage.

**Maximum frame size (normative):** `total_length` MUST NOT exceed **1 MiB** (`1_048_576` bytes). Host and enclave implementations MUST reject larger length prefixes before allocating the remainder of the frame. Reference constant: `enclave-protocol::MAX_MESSAGE_SIZE` (Rust); Elixir shim compares the same limit against `total_len` in `EnclaveProtocol.Framing`.

**Oversize length prefix (peer-visible behavior):** After reading the 4-byte `total_length`, if the value exceeds 1 MiB the implementation MUST NOT allocate the body. The reference **socket servers** (UDS/vsock `serve_framed_connection`) **close the connection without sending an application CBOR frame** (the request type is unknown — only the length prefix was read). Host clients building frames locally (Elixir `Framing`, smoke scripts) MUST reject oversize before send and return a local error (e.g. `{:frame_too_large, len}`) without transmitting the frame. In-process stdio/test helpers may encode a wire `Error` map when a full frame is already buffered; that path is not used on the production socket transport.

We will use **canonical CBOR** (RFC 7049 section 3.9) for all payloads where determinism matters.

---

## 8. Detailed Message Schemas (v1)

All CBOR payloads use integer keys for compactness and to avoid string comparison issues (maps with integer keys).

### Common types

```cbor
; Common error shape returned on failure
Error = {
  1: int,      ; error_code
  2: tstr      ; human readable reason (for logs only, not for logic)
}
```

### Command: GET_MEASUREMENT (message_type = 0x01)

**Request:**
```cbor
{ 1: 1 }   ; version
```

**Success Response:**
```cbor
{
  1: 1,                    ; version
  2: bytes,                ; measurement (raw SEV-SNP measurement or equivalent)
  3: bytes,                ; attestation document (full, as returned by the platform)
  4: bytes,                ; pq_pubkey — empty (0 bytes) when key 6 is false; 1952 bytes (ML-DSA-65) when key 6 is true
  5: [int]                 ; supported_ticket_types (e.g. [0, 1])
  6: bool,                 ; pq_signing_ready (false unless TEE has operational ML-DSA-65 signing key)
  7: bytes                 ; cert_chain — SNP VCEK->ASK->ARK chain (configfs-tsm auxblob); OPTIONAL/additive, empty when absent
}
```

**Semantics of `cert_chain` (key 7):** the SEV-SNP **VCEK→ASK→ARK** certificate chain (configfs-tsm `auxblob`) the relying party needs to verify `attestation` (key 3) to the pinned AMD root. It is **additive and backward-compatible** — a peer on the 1–6 schema omits it, and a decoder MUST default it to empty when absent. It MAY be empty even on SNP (provider didn't populate `auxblob`); the verifier then fetches the VCEK from AMD KDS by `chip_id` + `reported_tcb`. Full verification procedure: [`snp-attestation-verifier-policy.md`](./snp-attestation-verifier-policy.md). Note the launch `measurement` (key 2) anchors the **OVMF launch firmware + config**, not the guest image — see that policy §3.

**Semantics of `supported_ticket_types`:** This is a **static capability list** for the enclave image (which ticket types it can sign when all preconditions are met). It does **not** mean the enclave can sign type=1 right now. Readiness for hard-fork signing requires `GET_STATUS.armed == true` plus the rules in `SIGN_AUTHORIZATION_TICKET` below.

**Semantics of `pq_signing_ready`:** Operational PQ signer available **right now** (ML-DSA-65 installed via `install_sealed_pq_signer` after boot with a **v1** sealed blob and configured provisioning root). Default reference images set this to **false** even when `supported_ticket_types` includes `1`; hosts must not treat `false` as “ready to produce valid on-chain PQ signatures”. It becomes **true** only after successful v1 install at boot. The `reference-test-key` feature does **not** auto-enable readiness in any deployable binary.

**Error Response:** standard Error map.

**Security note:** When key `6` (`pq_signing_ready`) is **true**, `measurement` and `pq_pubkey` MUST be bound in the platform attestation document. When key `6` is **false**, key `4` is empty and hosts MUST NOT require a PQ key binding — only measurement/attestation image identity applies until provisioning completes. Hosts **MUST NOT** arm or treat the enclave as the signing producer while key `6` is **false**.

---

### Command: SIGN_AUTHORIZATION_TICKET (message_type = 0x10)

This is the most security-sensitive command.

**Request:**
```cbor
{
  1: 1,                    ; protocol version
  2: {                     ; ticket
    1: int,                ; ticket_type (0 = PRODUCER_RECOVERY, 1 = HARD_FORK_ACTIVATION)
    2: uint,               ; nonce
    3: bytes,              ; context_hash
    4: uint,               ; activation_height
    5: bytes,              ; new_measurement
    6: bytes,              ; pq_pubkey (the one that should sign this ticket)
    7: bytes / null,       ; fork_spec_hash (required when ticket_type=1)
    8: int / null,         ; new_header_version (recommended when ticket_type=1)
    9: bytes / null        ; governance_ref (currently ignored in v1 hard fork path)
  }
}
```

**Success Response:**
```cbor
{
  1: 1,
  2: bytes,                ; signature (ML-DSA-65 over canonical ticket hash, 3309 bytes)
  3: bytes                 ; ticket_hash (the exact value that was signed)
}
```

**Error Response:** standard Error + possibly additional fields (e.g. `current_armed_producer`).

**Critical Security Invariants (enclave MUST enforce):**

For `ticket_type == 1` (Hard Fork):
- The enclave **must** currently be armed as an authorized producer.
- `pq_pubkey` in the request **must** match the currently armed key.
- The enclave **should** have reasonably fresh on-chain view (network second factor) before signing a hard fork announcement.
- `activation_height` must be strictly greater than the `finalized_height` from the `RecentChainProof` captured at arming (the enclave's last known chain view for this session).
- `fork_spec_hash` must be non-null.
- At most **one** hard-fork ticket may be signed per armed session; a second attempt must be refused until re-arming with a **strictly fresher** `finalized_height` than the current session proof.
- At hard-fork sign time the enclave **re-runs** full `RecentChainProof` validation (structural + cryptographic) on the armed proof snapshot.

**TASK-3 (2026-06-02):** The reference `enclave-protocol` crate verifies Producer Chain Attestation v1 at arm and sign time (see §9.1).

For both types:
- The enclave must never sign a ticket where `pq_pubkey` does not match the key it actually controls.

---

### Command: ARM_FOR_PRODUCTION (message_type = 0x20)

**Request:**
```cbor
{
  1: 1,
  2: {                     ; authorized_state
    1: bytes,              ; pq_pubkey
    2: bytes,              ; measurement
    3: uint,               ; activated_at_height
    4: bytes               ; source_ticket_hash
  },
  3: {                     ; recent_chain_proof (mandatory structured proof — not opaque bytes)
    1: uint,               ; finalized_height
    2: bytes,              ; finalized_header_hash (32 bytes)
    3: [bytes],            ; recovery_history_tail (32-byte ticket hashes)
    4: bytes,              ; proof_data (Producer Chain Attestation v1 — see §9.1)
    5: bytes / null        ; signature_from_recent_producer (64-byte Ed25519)
  }
}
```

Encode/decode with integer map keys is implemented in `impl/rust/enclave-protocol/src/wire.rs` (`encode_arm_for_production_request` / `decode_arm_for_production_request`).

**Precondition:** `pq_signing_ready` MUST be **true** (operational ML-DSA signer installed). If **false**, the enclave MUST return a wire error and hosts MUST NOT send this command.

**Success Response:**
```cbor
{ 1: "armed" }
```

**Error Response:**
```cbor
{
  1: int,                  ; error_code
  2: tstr,
  3: { ... } / null        ; optional diagnostic info (e.g. current on-chain state the enclave saw)
}
```

**Security Invariants (updated after Codex security review + Claude-code design review, 2026-06-05):**
- When an operational PQ signer is installed (`pq_signing_ready == true`), the enclave **must** verify that `pq_pubkey` + `measurement` are consistent with its own attestation. When no signer is installed, `GET_MEASUREMENT` returns empty `pq_pubkey` and this binding does not apply.
- **`ARM_FOR_PRODUCTION` requires `pq_signing_ready == true`:** hosts **must not** arm a non-operational enclave; the enclave **must** reject the command otherwise (fail closed).
- `recent_chain_proof` **MUST NOT be null** for `ARM_FOR_PRODUCTION` (and for signing hard-fork tickets). A compromised host must not be able to arm the enclave or obtain signatures under a stale or attacker-chosen view.
- The enclave **must** reject (fail closed) if the proof is absent, stale, not properly rooted, or does not prove the expected authorization state.
- For HARD_FORK_ACTIVATION specifically: the enclave **must currently be armed** as the active producer **and** the `pq_pubkey` in the request **must** match the armed key (strong AND, not OR).

This is the concrete enforcement of "network as cryptographic second factor". The previous weaker wording was identified as a HIGH contradiction during reviews.

---

### Command: GET_STATUS (message_type = 0x30)

**Request:** `{ 1: 1 }`

**Response:**
```cbor
{
  1: 1,
  2: bool,                 ; armed
  3: bytes,                ; authorized_measurement  (value captured at ARM_FOR_PRODUCTION time)
  4: bytes,                ; authorized_pq_pubkey    (value captured at ARM_FOR_PRODUCTION time)
  5: int / null,           ; authorized_activated_at_height (on-chain producer activation height at arming)
  6: int / null,           ; proof_finalized_height (finalized_height from RecentChainProof used at arming)
  7: bytes / null,         ; source_ticket_hash (32 bytes, from AuthorizedProducerState at arming)
  8: int / null,           ; pending_hard_fork_height (set after a type=1 ticket is signed this session)
  9: int / null            ; last_known_block (Phase 1: same as proof_finalized_height — arming snapshot, not live tip)
}
```

**Field semantics (Phase 1 skeleton):**
- Fields 3–4 and 7 are fixed for the duration of an armed session (until re-arm or reset).
- Field 5 is the **on-chain authorized producer activation height**, not the chain tip at arming.
- Field 6 is how fresh the chain view was **at arming** (from `RecentChainProof.finalized_height`).
- Field 8 is populated after the first successful `SIGN_AUTHORIZATION_TICKET` with `ticket_type == 1` in this session; a second hard-fork sign is refused until re-arming.
- Field 9 does **not** track a live tip in Phase 1; it mirrors field 6 for host observability.

Future work (measurement transitions after hard forks, live tip tracking) may add or rename fields. This command is relatively safe and can be called frequently for monitoring.

**Reference encoding:** `encode_get_status_response` / `decode_get_status_response` in `wire.rs` (integer keys 1–9, key 1 = protocol version).

---

## 9. RecentChainProof — cryptographic MVP (TASK-3, 2026-06-02)

This section defines **Producer Chain Attestation** (Ed25519). It is independent of **TEE remote attestation** in `GET_MEASUREMENT` (§2.3).

### 9.1 Producer Chain Attestation v1 (implemented)

The reference enclave verifies this format at **`ARM_FOR_PRODUCTION`** and again at **hard-fork sign** time (fail closed).

**`proof_data` (exactly 33 bytes for format 0x01):**

| Offset | Size | Field |
|--------|------|--------|
| 0 | 1 | `format_id = 0x01` |
| 1 | 32 | `recovery_tail_digest = keccak256(concat recovery_history_tail hashes in order)` |

**`signature_from_recent_producer`:** mandatory **64-byte Ed25519** signature over:

```text
DOMAIN = "2d-hsm/RecentChainProof/v1\0"
|| be64(finalized_height)
|| finalized_header_hash[32]
|| be64(authorized.activated_at_height)
|| authorized.source_ticket_hash[32]
|| recovery_tail_digest[32]
|| be32(len(pq_pubkey)) || pq_pubkey
|| be32(len(measurement)) || measurement
```

**Verifying key (MVP):** a **pinned producer attestation Ed25519 public key** passed to the enclave as `ProducerAttestationTrust` (sealed config / attested provisioning). It must **not** be derived from public `pq_pubkey` — otherwise any host knowing the pubkey could forge proofs.

**Reference crate:** tests/demos enable the `test-support` feature and use `reference_test_attestation_trust()`; production enclaves load their own trust anchor from sealed config (never from the host over vsock).

**Structural checks (unchanged):** non-zero header hash, `finalized_height >= activated_at_height`, tail anti-replay when non-empty.

**Re-arm policy:** new proof must have `finalized_height` **strictly greater** than the previous armed session proof; trust anchor bytes must match the current session.

**Host obligation:** hold the attestation **signing** secret (block producer side only); outer CBOR fields must match the signed preimage.

### 9.2 Still deferred (not TASK-3)

1. **Live chain-tip refresh** between arming and signing (arming-time snapshot only).
2. **Full light-client** / validator-set proofs inside `proof_data` (future format `0x02+`).

PQ ticket signing inside the TEE remains TASK-1; this section only covers the network-second-factor gate.

### 9.3 Producer attestation trust anchor (provisioning)

**Threat model (MVP):** Defends against a **compromised vsock host** that tries to arm the enclave or obtain hard-fork signatures under a fabricated chain view. It does **not** defend against compromise of the block producer entity that holds the attestation signing secret (same principal as production). Full light-client verification is deferred to §9.2.

**Root of trust:** `ProducerAttestationTrust.attestation_verifying_key` — Ed25519 public key.

| Rule | Requirement |
|------|-------------|
| Provisioning | Loaded inside the TEE from **sealed storage**, enclave image manifest, or PCR-bound attested config — **never** from an `ARM_FOR_PRODUCTION` CBOR field or other host-controlled vsock payload. |
| Host role | Host may relay `RecentChainProof` bytes + signatures from the producer side, but cannot choose or override the verifying key passed to `dispatch_command_with_state`. |
| Rotation | New verifying keys require a new enclave image or an attested re-provisioning event; mid-session re-arm must use the **same** trust anchor bytes as the current armed session. |
| Restart | In-memory re-arm monotonicity (`finalized_height`) resets when the enclave process restarts; sealed state may persist armed metadata in a future phase. |
| Reference tests | `reference_test_attestation_*` is behind `cfg(test)` / `test-support` only — must not ship in production binaries. |

**Wire encoding:** `GET_STATUS` and `ARM_FOR_PRODUCTION` request/response bodies for the reference crate use integer CBOR map keys per §8 (`wire.rs`). Other commands may still use serde field names until migrated.

**Dispatch surfaces:**
- `dispatch_command` — recovery signing + `GET_MEASUREMENT` only; returns explicit errors for arm/status/hard-fork.
- `dispatch_command_with_state` — arming, status, hard-fork; requires enclave-supplied `ProducerAttestationTrust`.

---

## 10. Next Steps

- Run **roborev Reduced matrix** on this document (v0.2) + `authorization-tickets-precompile-spec-draft.md`, then `roborev compact`.
- Wire decode: reject 64-byte PQ signatures when `pq_signing_ready` is true / production profile (3309 B only).

- Finalize all error codes.
- Add `PREPARE_HARD_FORK_TRANSITION` command (or decide to do everything through `SIGN_AUTHORIZATION_TICKET` + later `ARM_FOR_PRODUCTION`).
- Write concrete CBOR test vectors for the three most important messages.
- Start minimal Rust + Elixir skeletons that can at least do GET_MEASUREMENT roundtrip.

Ready to continue with detailed hard fork flow (item B) after we lock the schemas above.

---

This document will be the single source of truth for the vsock protocol while we implement TASK-2.

Start working on choosing the encoding and writing the detailed command schemas.
