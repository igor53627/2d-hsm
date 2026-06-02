# TEE Signing Service — vsock API + Wire Format Specification (Draft v0.1)

**Task**: TASK-2  
**Date**: 2026-06-05  
**Status**: Initial draft — ready for iteration  
**Goal**: Define the communication protocol between the 2D host (Block Producer) and the minimal post-quantum signing service running inside a TEE (Nitro Enclave / SEV-SNP).

## 1. Why this API exists

The signing service runs inside a TEE. The host (Elixir Block Producer process) is untrusted.

All sensitive operations must happen inside the enclave:
- Holding and using the long-term PQ Block Producer key.
- Generating and signing `AuthorizationTicket` (both recovery and hard-fork types).
- Deciding whether it is allowed to sign blocks at all (network second factor + authorized producer state).
- Transitioning to a new code measurement during a hard fork.

The only communication channel we trust is **vsock** (AF_VSOCK).

## 2. Design Principles

- Minimal surface. Fewer commands = easier to audit and reason about.
- Explicit security invariants per command.
- Support the hard fork flow from day one (not bolted on later).
- Easy to implement correctly on both sides.
- Versioned from the beginning.
- Prefer simple, deterministic encoding over "nice" encoding.

## 3. High-Level Command Groups

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

## 4. Proposed Command Set (v0.1)

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
  "attestation": h'....',           // full attestation document
  "pq_pubkey": h'....',             // current Dilithium/ML-DSA public key
  "supported_ticket_types": [0, 1]  // static capability list (see formal CBOR section)
}
```

`supported_ticket_types` is a static capability list, not current readiness. Type 1 additionally requires armed state (`GET_STATUS`).

Security invariant: The enclave must only return a measurement + key that are bound together in the attestation.

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
  "signature": h'...',
  "ticket_hash": h'...'   // the hash that was actually signed
}
```

On error: structured error with reason.

**Security rules the enclave must enforce** (this is critical):
- For `ticket_type == 1` (Hard Fork): the enclave must currently be armed as the active producer, or at least the `pq_pubkey` in the ticket must match the one it holds.
- The enclave may refuse to sign a hard fork ticket if it has not seen a valid network state proving that the current on-chain authorized producer matches its key (network second factor).
- The enclave should refuse to sign a hard fork ticket with `activation_height` in the past.

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

## 5. Hard Fork Flow using this API (end-to-end sketch)

1. Current producer decides to do a hard fork at block 1_500_000.
2. Host calls `PREPARE_HARD_FORK` (or directly `SIGN_AUTHORIZATION_TICKET` with type=1).
3. Enclave signs the `HARD_FORK_ACTIVATION` ticket (after checking it is still the authorized producer and has fresh enough chain view).
4. Host submits the ticket on-chain via the precompile.
5. When the chain approaches block 1_500_000:
   - Host calls `ARM_FOR_PRODUCTION` again with the new measurement (or the enclave switches internally).
6. After the scheduled height, the enclave only signs blocks if the header version matches the one announced in the ticket + it is using the new measurement.

## 6. Encoding Decision (A — done 2026-06-05)

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

We will use **canonical CBOR** (RFC 7049 section 3.9) for all payloads where determinism matters.

---

## 7. Detailed Message Schemas (v1)

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
  4: bytes,                ; pq_pubkey (current Dilithium/ML-DSA public key)
  5: [int]                 ; supported_ticket_types (e.g. [0, 1])
}
```

**Semantics of `supported_ticket_types`:** This is a **static capability list** for the enclave image (which ticket types it can sign when all preconditions are met). It does **not** mean the enclave can sign type=1 right now. Readiness for hard-fork signing requires `GET_STATUS.armed == true` plus the rules in `SIGN_AUTHORIZATION_TICKET` below.

**Error Response:** standard Error map.

**Security note:** The enclave must ensure that `measurement` + `pq_pubkey` are bound together in the attestation document.

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
  2: bytes,                ; signature (over the canonical ticket hash)
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

**TASK-3 (2026-06-02):** The reference `enclave-protocol` crate verifies Producer Chain Attestation v1 at arm and sign time (see §8.1).

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
    4: bytes,              ; proof_data (Producer Chain Attestation v1 — see §8.1)
    5: bytes / null        ; signature_from_recent_producer (64-byte Ed25519)
  }
}
```

Encode/decode with integer map keys is implemented in `impl/rust/enclave-protocol/src/wire.rs` (`encode_arm_for_production_request` / `decode_arm_for_production_request`).

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
- The enclave **must** verify that the `pq_pubkey` + `measurement` combination is consistent with its own attestation.
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

## 8. RecentChainProof — cryptographic MVP (TASK-3, 2026-06-02)

### 8.1 Producer Chain Attestation v1 (implemented)

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

### 8.2 Still deferred (not TASK-3)

1. **Live chain-tip refresh** between arming and signing (arming-time snapshot only).
2. **Full light-client** / validator-set proofs inside `proof_data` (future format `0x02+`).

PQ ticket signing inside the TEE remains TASK-1; this section only covers the network-second-factor gate.

### 8.3 Producer attestation trust anchor (provisioning)

**Threat model (MVP):** Defends against a **compromised vsock host** that tries to arm the enclave or obtain hard-fork signatures under a fabricated chain view. It does **not** defend against compromise of the block producer entity that holds the attestation signing secret (same principal as production). Full light-client verification is deferred to §8.2.

**Root of trust:** `ProducerAttestationTrust.attestation_verifying_key` — Ed25519 public key.

| Rule | Requirement |
|------|-------------|
| Provisioning | Loaded inside the TEE from **sealed storage**, enclave image manifest, or PCR-bound attested config — **never** from an `ARM_FOR_PRODUCTION` CBOR field or other host-controlled vsock payload. |
| Host role | Host may relay `RecentChainProof` bytes + signatures from the producer side, but cannot choose or override the verifying key passed to `dispatch_command_with_state`. |
| Rotation | New verifying keys require a new enclave image or an attested re-provisioning event; mid-session re-arm must use the **same** trust anchor bytes as the current armed session. |
| Restart | In-memory re-arm monotonicity (`finalized_height`) resets when the enclave process restarts; sealed state may persist armed metadata in a future phase. |
| Reference tests | `reference_test_attestation_*` is behind `cfg(test)` / `test-support` only — must not ship in production binaries. |

**Wire encoding:** `GET_STATUS` and `ARM_FOR_PRODUCTION` request/response bodies for the reference crate use integer CBOR map keys per §7 (`wire.rs`). Other commands may still use serde field names until migrated.

**Dispatch surfaces:**
- `dispatch_command` — recovery signing + `GET_MEASUREMENT` only; returns explicit errors for arm/status/hard-fork.
- `dispatch_command_with_state` — arming, status, hard-fork; requires enclave-supplied `ProducerAttestationTrust`.

---

## 9. Next Steps (still in A)

- Finalize all error codes.
- Add `PREPARE_HARD_FORK_TRANSITION` command (or decide to do everything through `SIGN_AUTHORIZATION_TICKET` + later `ARM_FOR_PRODUCTION`).
- Write concrete CBOR test vectors for the three most important messages.
- Start minimal Rust + Elixir skeletons that can at least do GET_MEASUREMENT roundtrip.

Ready to continue with detailed hard fork flow (item B) after we lock the schemas above.

---

This document will be the single source of truth for the vsock protocol while we implement TASK-2.

Start working on choosing the encoding and writing the detailed command schemas.
