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

## 10. Agent Gateway command namespace (secp256k1) — TASK-7.1

A **separate** command namespace for the Agent Gateway secp256k1 signer (ordinary 2D
faucet/transfer signing). It does **not** reuse producer / AuthorizationTicket commands,
keys, or state (see `agent-gateway-secp256k1-signer-design.md`). Full design rationale
and per-AC mapping live in TASK-7.1; this section is the normative wire contract.

**Scope decisions locked in TASK-7.1:**
- **eth surface MVP, TRON reserved.** 2D is a *unified secp256k1 account*: one key →
  one 20-byte body (`keccak256(pubkey)[12:32]`), addressable as both eth `0x…` and
  TRON `T…` (Base58Check of `0x41‖body`), with two tx surfaces (EIP-155 RLP /
  keccak256, and TRON protobuf / sha256). The MVP signs **only the eth EIP-155 surface**;
  a TRON-signing opcode and golden-vector slot are **reserved** (§10.3, §10.8), and
  `AGENT_K1_PUBLIC_IDENTITY` returns **both** address encodings (§10.4).
- **Administrative/recovery capabilities use Ed25519** (§10.5).
- **`AGENT_K1_PUBLIC_IDENTITY` / `AGENT_K1_PROVE_IDENTITY` are low-privilege reads** (§10.4, §10.8).
- **Canonical public-key encoding: uncompressed 65-byte SEC1** (`0x04‖X‖Y`); compressed rejected (AC#14).

### 10.1 Framing model (AC#1, AC#2, AC#20)

One **outer** `message_type = 0x40` (`AgentGateway`) under the existing **frame v1**
(`protocol_version` stays `1`). The agent command set carries its **own** inner version
and opcode inside the CBOR payload, so it can evolve without a frame-version bump.

- Outer band **`0x40..0x4F` reserved** for Agent Gateway envelopes. Allocated: `0x40`
  (`AgentGateway`, host-initiated serve command); **`0x41` (`AgentBootRelay`, TASK-7.7 5b-2 —
  ENCLAVE-INITIATED anti-rollback boot handshake; NOT serve-dispatchable: `decode_wire_command`
  rejects an inbound `0x41` with a wire error)**; **`0x44` (`AgentAnchorMarksRelay`, TASK-7.7 5b-2e —
  ENCLAVE-INITIATED `AdoptForward` raw-marks fetch; same enclave-initiated/NOT-serve-dispatchable
  contract as `0x41` — `decode_wire_command` rejects an inbound `0x44` with a wire error)**;
  **`0x45` (`AgentAnchorCommitRelay`, TASK-7.7 slice 6 — ENCLAVE-INITIATED per-op seal-before-emit
  commit; same enclave-initiated/NOT-serve-dispatchable contract — `decode_wire_command` rejects an
  inbound `0x45` with a wire error)**. NB the outer `0x44`/`0x45` frame bytes are a DISJOINT namespace
  from the inner `AgentError` codes `0x44 AGENT_CAP_EXCEEDED` / `0x45 AGENT_NOT_CONFIGURED` (inner CBOR
  status keys, never outer frame types). `0x42..0x43` and `0x46..0x4F` unallocated. `0x50..0x7F` left
  for future producer/other families.
- **Why not a frame-version bump or a wide outer range:** producer frames
  (`0x01/0x10/0x20/0x30`) stay byte-identical and still decode (success criterion:
  "existing producer commands remain wire-compatible"), and inner opcodes are CBOR
  ints that cost no scarce outer bytes.

**Fail-closed at three checkpoints** (none may fall back to a producer type — AC#3/AC#20):
1. `decode_message`: `0x40 → AgentGateway`; `0x41 → AgentBootRelay`, `0x44 → AgentAnchorMarksRelay`,
   `0x45 → AgentAnchorCommitRelay` (all three then `decode_wire_command`-rejected as
   enclave-initiated/not-serve-dispatchable); `0x42..0x43`, `0x46..0xFF → UnknownMessageType`.
2. `peek_msg_type_from_frame` (routing/error-frame helper): returns *no* type for
   unrecognized bytes. This PR fixes a prior fail-**open** default (unknown types fell back
   to `GetMeasurement`): it now returns `Option<MessageType>` and an unrecognized request's
   error frame echoes the original type byte, never a producer type.
3. Inner agent decoder: validate `agent_version == AGENT_PROTOCOL_VERSION (=1)`, then
   match `opcode` against the exhaustive allow-list below; unknown version, opcode, or
   treasury sub-op → fail closed (`AGENT_MALFORMED`), no state touch.

### 10.2 Inner Agent Gateway envelope + role/profile gate (AC#4, AC#5)

CBOR integer-key map (canonical, per §8):

```
{
  1: agent_version (uint, = 1),
  2: opcode        (uint, see §10.3),
  3: command_domain(tstr, fixed = "2d-hsm/agent-gateway/v1"),
  4: request_id    (bstr, binds one request),
  5: capability    (map; REQUIRED only for privileged opcodes — see §10.3 table + §10.5; carries its Ed25519 signature at key 13),
  6: key_ref|batch_id (bstr, where applicable),
  7: payload       (map, per-command — §10.4)
}
```

**Role/profile gate (AC#5).** Before *any* command-specific state is touched:
a **producer-profile** signer rejects every Agent Gateway opcode; an
**Agent-Gateway-profile** signer rejects producer + AuthorizationTicket message types.
Mixed-role fixtures are permitted only in non-deployable tests.

### 10.3 Opcode allocation (AC#1)

| opcode | command | tier | scope (financial?) |
|--------|---------|------|--------------------|
| 1 | `AGENT_K1_GENERATE_KEYS` | privileged (provisioning/refill) | transfer pool: fleet allowed · faucet treasury: **enclave** |
| 2 | `AGENT_K1_PUBLIC_IDENTITY` | low-privilege read | — |
| 3 | `AGENT_K1_PROVE_IDENTITY` | low-privilege read | — |
| 4 | `AGENT_K1_SIGN_TRANSFER` | runtime signing | — |
| 5 | `AGENT_K1_SIGN_FAUCET_DISPENSE` | faucet treasury signing | — |
| 6 | `AGENT_K1_CONFIGURE_TREASURY` | treasury admin / recovery | **enclave** (AC#12) |
| 7 | `AGENT_KEYSTORE_EXPORT_BACKUP` | backup-export admin | enclave default |
| 8 | `AGENT_KEYSTORE_RESTORE_BACKUP` | recovery/quorum | recovery counter |
| **9** | `AGENT_K1_SIGN_TRON_TRANSFER` | **RESERVED** (eth-MVP + reserve-TRON) — fail-closed until a future task | — |
| 0, 10.. | reserved; decoder fails closed on any non-allow-listed opcode | | |

`CONFIGURE_TREASURY` sub-operations are an **inner discriminant** (not separate opcodes):
`0 set_limits, 1 refill_budget, 2 raise_lifetime_breaker, 3 reset_lifetime_breaker`
(AC#8), each validated by exhaustive allow-list and mapped to a capability tier (§10.7).

**Capability requirement per opcode** (resolves the inner-envelope key-5 condition):
- **No capability — low-privilege reads:** `PUBLIC_IDENTITY`, `PROVE_IDENTITY`.
- **No administrative capability — runtime signing:** `SIGN_TRANSFER`, `SIGN_FAUCET_DISPENSE`.
  These do **not** carry capability key 5; per the threat model they are reachable by any
  vsock caller, and their bound is the enclave-built canonical preimage (no caller digest),
  key-purpose, chain/env binding, and — for faucet — sealed spend caps, **not** an admin
  capability.
- **Capability key 5 REQUIRED — privileged:** `GENERATE_KEYS`, `CONFIGURE_TREASURY`
  (every sub-op), `EXPORT_BACKUP`, `RESTORE_BACKUP`. Missing/invalid key 5 ⇒ fail closed.

### 10.4 Per-command payloads (AC#1, AC#14)

Schemas (all CBOR int-key maps). `SIGN_TRANSFER`, `SIGN_FAUCET_DISPENSE`, and
`PUBLIC_IDENTITY` are fully specified here; the complete request/response maps for
`GENERATE_KEYS`/`PROVE_IDENTITY` are owned by TASK-7.3, `CONFIGURE_TREASURY` by TASK-7.4,
and `EXPORT_BACKUP`/`RESTORE_BACKUP` by TASK-7.2 — each consuming this envelope, capability,
and error contract, with the per-command map carried at envelope key 7:

- **`AGENT_K1_SIGN_TRANSFER`** (runtime; `agent_transfer_k1` only) — *semantic fields,
  never a caller digest*: `{1: chain_id, 2: from, 3: to(20B), 4: amount,
  5: nonce, 6: gas_limit, 7: gas_price, 8: data(empty in MVP)}`. **`chain_id` is NOT a
  hardcoded protocol constant**: the request `chain_id` MUST equal the **sealed
  `KeystoreConfig.twod_chain_id`** (the per-deployment value provisioned into the measured/sealed
  config — never request-authoritative), and the enclave rejects any other value. `11565` below is the
  **current 2D deployment / golden-vector value**, not a literal. The enclave builds the canonical
  EIP-155 preimage (`RLP([nonce, gas_price, gas, to, value, data, <sealed chain_id>, «», «»])`), hashes
  with keccak256, and returns a **low-S** signature + recovery id
  (`v = <sealed chain_id>*2+35+recovery_id`; e.g. `∈ {23165, 23166}` for chain_id 11565). Pinned by
  `testvectors/agent-gateway/ordinary_tx_v1.*`. **The exact CBOR wire types** — `amount`/`gas_price`
  as canonical minimal-big-endian `u256` byte strings (`0..=32` bytes, no leading zero; over-width
  rejected, never truncated), the success-response map `{1: signed_rlp, 2: r, 3: s, 4: recovery_id,
  5: v, 6: signing_hash, 7: from}`, and the §10.9 error-code split (request-shape → 0x40, key-related
  → 0x42) — are the TASK-15 impl decisions pinned in **`agent-gateway-transfer-faucet-signing.md` §1**,
  the source of truth for the SIGN_TRANSFER / SIGN_FAUCET_DISPENSE wire encoding.
- **`AGENT_K1_SIGN_FAUCET_DISPENSE`** (`agent_faucet_treasury_k1` only) — pure native
  transfer, `data` empty; `to` MUST match a known `agent_transfer_k1` identity in the
  keystore. TEE caps over worst-case `amount + gas_limit * effective_max_fee_rate`
  (checked arithmetic, fail-closed on overflow); two sealed counters debited
  **before** the signature is emitted. Request map = the **same 8-field map** as
  SIGN_TRANSFER; the success response is the SIGN_TRANSFER 7-key signed-tx map PLUS
  **key 8 = the new sealed keystore blob** the host persists (the debited faucet state —
  mirrors `GENERATE_KEYS` key 2). Because it debits sealed counters it is **mutating /
  rollback-sensitive (EpochOnly)** and routes through the seal→anchor-commit→swap→emit
  seam; production-gated behind the release-banned `agent-sign-faucet-preview` feature
  (full encoding + error bands in `agent-gateway-transfer-faucet-signing.md` §2).
- **`AGENT_K1_CONFIGURE_TREASURY`** (slice 15-4; treasury config — signs nothing) — request payload
  (envelope key 7) = `{1: sub_op, …per-sub-op fields}`, strict per-sub-op key count (extra/dup/unknown
  key ⇒ 0x40):
  - `0 set_limits` (admin): `{1:0, 2: per_dispense_max_amount (u256 minimal-BE), 3: max_gas_limit (u64),
    4: max_effective_gas_fee_rate (u64)}` — sets the limit triple atomically; spend/budget untouched.
  - `1 refill_budget` (admin): `{1:1, 2: new_cumulative_signing_budget (u256)}` — sets the budget ceiling
    AND resets `cumulative_native_spend → 0` (a fresh refill window); `lifetime_spend` untouched.
    `new_budget == 0` ⇒ 0x44 (would re-disable the faucet).
  - `2 raise_lifetime_breaker` (admin): `{1:2, 2: new_circuit_breaker_threshold (u256)}` — sets the
    lifetime breaker; `new_threshold < current lifetime_spend` ⇒ 0x44 (anti-inversion — would trip at once).
  - `3 reset_lifetime_breaker` (recovery): `{1:3, 2: target_lifetime_spend (u256)}` — clears the breaker,
    LOWERS `lifetime_spend` to `target` (`target > current` ⇒ 0x44), and advances `strict_recovery_counter`.
  `u256` fields reuse `as_u256_minimal_be` (over-width / non-minimal ⇒ 0x40). The cap's `payload_binding`
  canonical params are the canonical CBOR of this exact map (sub_op at key 1), and the handler ALSO
  asserts `request.sub_op == cap.treasury_sub_op` directly (§10.5 — load-bearing for tier separation, so an
  admin cap cannot drive the recovery-tier reset via a baked `payload_binding`). Success response =
  `{1: sealed_keystore_blob}`. EVERY sub-op bumps the monotonic `config_version`; `{0,1,2}` are
  **Structural** (also bump `structural_version`), `3` is **EpochOnly** (its full effect is the marks
  `lifetime_spend`/`strict_recovery_counter`). Mutating / rollback-sensitive ⇒ routes through the
  seal→anchor-commit→swap→emit seam; production-gated behind the release-banned
  `agent-configure-treasury-preview` feature. Error bands (anti-oracle, §10.9): request shape → 0x40;
  sub-op binding / `payload_binding` / non-enclave scope → 0x43; quantitative (zero budget / breaker
  inversion / reset overshoot / counter table) → 0x44; seal/commit or `config_version`/epoch overflow →
  0x46. There is **no 0x42 band** (no `key_ref` — treasury config is the singleton `FaucetState`).
- **`AGENT_K1_PUBLIC_IDENTITY`** response — `{1: pubkey (uncompressed 65B SEC1 0x04, AC#14),
  2: eth_address (20B), 3: tron_address (Base58Check of 0x41‖body), 4: key_ref,
  5: key_purpose, 6: backend_version}`. Returning **both** address encodings reflects the
  unified-account model (TRON-reserve decision).

### 10.5 Administrative / recovery capability (AC#6, AC#7, AC#11)

A TEE-verified, signed, parameter-binding token carried at inner-envelope key `5` for
privileged opcodes. **Host-side Vault/OPA authorization alone is never sufficient** (AC#6).

- **Algorithm:** Ed25519, 64-byte signature, **32-byte raw** public key (same family
  and sealed-trust-root pattern as `ProducerAttestationTrust`).
- **Trust roots (sealed at measured provisioning, never host-supplied):**
  `admin_authority_pk` and `recovery_authority_pk` (MVP quorum = one higher-tier
  recovery key). Bound to sealed state; never derived from `pq_pubkey`.
- **Signed structure** (canonical CBOR int-key map = the signed bytes), prefixed with the
  domain `"2d-hsm/agent-cap/v1\0"` before verification:

```
1 cap_format_version (=1)        7 scope_class (0=enclave,1=fleet; financial MUST be enclave)
2 command_opcode                 8 scope_target (enclave_id|fleet_id, command_class folded in)
3 treasury_sub_op (if opcode 6)  9 counter (monotonic for the tuple)
4 key_purpose (1=transfer,2=faucet) 10 request_id
5 chain_id (= sealed 11565)      11 payload_binding = keccak256(opcode ‖ sub_op ‖ request_id ‖ canonical command params)
6 environment_identifier (= sealed)  12 is_recovery (bool → verify vs recovery_authority_pk)
--- below is NOT part of the signed bytes ---
13 ed25519_signature (64B)
```

**Signature transmission.** The capability map carries the 64-byte Ed25519 signature at key
`13`. The signed message is `"2d-hsm/agent-cap/v1\0" ‖ canonical-CBOR({1..12})` — keys `1–12`
only, with key `13` excluded before verification — so "the capability map minus key 13 = the
signed bytes" is unambiguous and wire-stable.

The design doc's "key refs or batch/count" capability binding is covered transitively by
`payload_binding` (now `keccak256(opcode ‖ sub_op ‖ request_id ‖ canonical command params)`);
there is no separate key-ref field in the signed capability.

**Verify order (all before state touch):** role/profile gate → opcode allow-list →
`cap_format_version` → Ed25519 verify over keys `1–12` (key 13 excluded) vs the correct
sealed authority → `cap.command_opcode == request.opcode` **and** `cap.treasury_sub_op ==
request.sub_op` (opcode 6) **and** `cap.request_id == envelope.request_id` →
`chain_id`/`env`/`scope` equal sealed values → contiguous counter (§10.6) → `payload_binding
== keccak256(actual params)` → mutate + seal-before-return. The opcode/sub-op/request_id
equality checks stop a capability issued for one opcode/sub-op/request from authorizing
another (e.g. a `set_limits` cap cannot authorize `reset_lifetime_breaker`).

Capability tiers per command follow the design doc table (`agent-gateway-secp256k1-signer-design.md` §"Capability tiers").

### 10.6 Counter scheme + `environment_identifier` (AC#9, AC#10, AC#11, AC#12, AC#18)

Replay protection is **strict contiguity**, not timestamps or nonce sets (enclave time is
host-controlled).

- **Tuple:** `(authority, environment_identifier, scope_class, scope_target)`; sealed state
  holds the highest accepted counter per tuple.
- **Contiguity:** accept iff `incoming == highest + 1`; reject lower (replay) and gaps
  (skip-ahead); advance + seal before returning success.
- **Command-class split (AC#18 default):** fold `command_class` into `scope_target`
  (`generate_transfer`, `generate_faucet`, `configure_treasury`, `export_backup`,
  `restore_backup`) so a stalled/withheld capability for one class cannot wedge the others.
- **Default `scope_class`:** transfer-pool keygen — fleet allowed; faucet keygen and
  **all** treasury config — enclave required (AC#12, no budget multiplication across clones);
  export — enclave default; restore — recovery tier with an independent strict recovery
  counter.
- **`environment_identifier` (AC#10):** UTF-8, `1..=64` bytes, `[a-z0-9-]`, no
  leading/trailing/double hyphen; byte-exact case-sensitive compare against the sealed value;
  malformed → fail closed at decode.
- **Recovery resync (AC#11):** a recovery-authority capability resyncs a wedged scope
  **forward-only**: it sets the target tuple's counter strictly `>` its current highest
  **and** is itself sequenced by an independent strict recovery counter (one normative
  mechanism, not a choice). `RESTORE_BACKUP` and `reset_lifetime_breaker` share that same
  strict recovery counter. Audited; never rolls backward.
- **Authority rotation (AC#17):** `authority` is part of the tuple, so a new authority
  starts a fresh stream and retired-authority capabilities cannot replay. Fallback for
  authority compromise = full re-provisioning (residual risk documented).

### 10.7 Treasury configuration (AC#8, AC#12)

`AGENT_K1_CONFIGURE_TREASURY` sub-ops map to tiers: `set_limits`/`refill_budget`/
`raise_lifetime_breaker` = treasury-admin; `reset_lifetime_breaker` = recovery/quorum
(bound to a strict recovery counter and target value). Config version is monotonic and
sealed; a normal config bump does **not** reset cumulative spend. Two sealed faucet
counters (refillable cumulative budget + optional lifetime breaker). Enclave-scoped unless
a global remote monotonic ledger is specified (AC#12). All writes sealed before success.

### 10.8 Identity proof + read policy (AC#15, AC#16)

- **Layout (AC#15):** `0x19 ‖ len(label)(1B) ‖ label ("2d-hsm/agent-identity-proof/v1") ‖
  chain_id(8B BE) ‖ len(env_id)(1B) ‖ env_id ‖ key_ref(32B) ‖ pubkey(65B) ‖
  address(20B) ‖ verifier_nonce(32B)`, hashed with keccak256. Every variable-length field
  (label, env_id) is 1-byte length-prefixed so no future label/env-id change shifts the
  parse of later fixed-width fields. The **verifier** owns nonce freshness.
  Pinned by `testvectors/agent-gateway/identity_proof_v1.*`.
- **3-way domain separation (AC#15)** — disjoint by construction:

  | domain | first preimage byte | hash |
  |--------|---------------------|------|
  | eth EIP-155 tx | `≥0xc0` (RLP list; this vector `0xed`) | keccak256 |
  | TRON tx (reserved) | `0x0a` (protobuf field-1 tag) | sha256 |
  | identity proof | `0x19` (EIP-191) | keccak256 |

  Leading bytes are mutually distinct **and** the TRON surface uses a different hash. The
  enclave always builds each preimage itself and never signs a caller digest. **EIP-2718
  caveat:** `0x19` is a legal `TransactionType`, so disjointness from typed txs depends on
  the pinned policy that **2D permanently reserves/never assigns tx-type `0x19`** —
  tracked by a 2D-side AC in the TASK-132.5 family (the enclave cannot enforce it). This
  2D-side reservation is a **production gate**, not a gate on the TASK-7.3/7.4 *design*:
  `AGENT_K1_PROVE_IDENTITY` and any identity-proof signing must stay non-production / disabled
  until a **merged** 2D commit/test pins that tx-type `0x19` is reserved/rejected; the
  non-collision proof references that pinned artifact, and production fund custody (TASK-7.7)
  is gated regardless. Witnesses in `testvectors/agent-gateway/domain_separation.json`.
- **Read policy (AC#16):** `AGENT_K1_PUBLIC_IDENTITY` and `AGENT_K1_PROVE_IDENTITY` are
  **low-privilege local reads** — no administrative capability — but still validate command
  domain, key purpose, and chain/environment binding; `PROVE_IDENTITY` binds the fresh
  verifier-provided nonce.

### 10.9 Structured error codes + disclosure policy (AC#19)

Agent error band over the common `{1: code, 2: reason}` map; `reason` carries no secret in
deployable builds. Coarse classes the host needs are exposed; oracle-creating distinctions
are collapsed:

| code | meaning | disclosure |
|------|---------|-----------|
| `0x40 AGENT_MALFORMED` | bad CBOR / unknown version / opcode / sub-op / field / env-id format | syntax only |
| `0x41 AGENT_WRONG_PROFILE` | command disabled in this role/profile | needed for routing |
| `0x42 AGENT_KEY_PURPOSE_MISMATCH` | **collapses** key-not-found AND wrong-purpose | anti-oracle |
| `0x43 AGENT_CAPABILITY_REJECTED` | **collapses** bad sig / wrong authority / chain-env-scope / non-contiguous counter / payload-binding / retired authority | anti-oracle |
| `0x44 AGENT_CAP_EXCEEDED` | per-dispense/gas/budget/breaker exceeded or checked-overflow | distinct from malformed |
| `0x45 AGENT_NOT_CONFIGURED` | faucet signing before mandatory caps sealed | safe |
| `0x46 AGENT_SEAL_FAILED` | atomic sealed-commit failed; no signature/refs emitted | safe |

Agent codes `0x40–0x46` are deliberately disjoint from the producer/common error codes
(`1`, `2`), so both namespaces share one `{1: code, 2: reason}` map without collision.

Never expose key-existence, per-field capability failure, exact provisioning/sealing state,
or key-derivation detail.

### 10.10 Golden vectors + test/vector requirements (AC#13, AC#21, AC#22)

Frozen, self-checked, in-repo artifacts in
`impl/rust/enclave-protocol/testvectors/agent-gateway/` (provenance + regeneration in its
`README.md`): `ordinary_tx_v1.*` (AC#13 eth preimage/hash/sig/address, `chain_id=11565`),
`tron_transfer_v1.*` (reserved surface, for the §10.8 disjointness proof),
`identity_proof_v1.*`, `keys.json` (dual eth/TRON encodings), `domain_separation.json`.

Required tests (consumed by TASK-7.3/7.4/7.6, AC#21):
- Producer frames `0x01/0x10/0x20/0x30` still decode unchanged after adding `0x40`.
- `peek_msg_type_from_frame` returns no-type for unknown bytes `0x42`/`0xFF` (never `GetMeasurement`);
  `0x40 → AgentGateway`, `0x41 → AgentBootRelay`, `0x44 → AgentAnchorMarksRelay`,
  `0x45 → AgentAnchorCommitRelay` (TASK-7.7 5b-2/5b-2e/slice 6; all enclave-initiated, fail-closed in
  `decode_wire_command`). *(History: `0x41` previously peeked to no-type, allocated to `AgentBootRelay`
  in 5b-2; `0x44` → `AgentAnchorMarksRelay` in 5b-2e; `0x45` → `AgentAnchorCommitRelay` in slice 6 —
  unknown-frame coverage is now `0x42..0x43` + `0x46..`.)*
- Unknown `agent_version`/opcode/treasury-sub-op → `AGENT_MALFORMED`, no state touch.
- Role/profile cross-rejection matrix (producer↔agent), both before state touch.
- Key-purpose cross-rejection (transfer↔faucet; producer purposes rejected by agent commands).
- Identity-proof vs transfer cross-domain: the two preimages produce different hashes and
  `SIGN_TRANSFER` refuses an identity-proof-shaped input.
- Capability binding: mismatched `payload_binding`/authority/chain/env/scope or non-contiguous
  counter → `AGENT_CAPABILITY_REJECTED`; valid cap accepted, its replay rejected.
- Golden-vector self-consistency: rebuild eth preimage from JSON fields → keccak256 → equals
  `ordinary_tx_v1.signing_hash.bin`; pinned `r/s/v` recovers the expected `from` (low-S enforced).
- Roborev matrix recorded before merge (AC#22).

---

## 11. Next Steps

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
