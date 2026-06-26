# Producer wire-frame golden vectors (TASK-122 AC#3 / Step 3)

Frozen, in-repo test vectors that pin the **producer-side vsock wire protocol**
between the 2D BlockProducer host and the 2d-hsm TEE signing service. Consumed
cross-repo by the 2D Elixir producer signer client cross-check (TASK-122 AC#3).

This is the producer-protocol analogue of `../agent-gateway/` (which pins the
Agent Gateway opcode-0x40 envelope). The ML-DSA-65 signature/hash triples in
`../mldsa65_crosscheck/` pin the **signing primitive** (TASK-122 AC#2); the
vectors here pin the **producer wire framing + CBOR schemas** that a 2D vsock
client must speak and parse (TASK-122 AC#3).

## Provenance (authoritative)

`gen_producer_vectors.rs` generates these by calling the **reference Rust
encoder** (`enclave_protocol::encode_message` + the per-command
`encode_*_request`/`encode_*_response` helpers in `src/wire.rs`), so each frame
is byte-identical to what the production enclave server emits on the wire. The
2D Elixir client cross-check asserts byte-identical encode + struct-equal decode
against these frames — preventing a self-referential 2D-only codec from
diverging from the reference (the same anti-self-certification bar used for
TASK-122 AC#2/#4).

Regenerate (no crypto features required — the producer wire layer is plain
CBOR via ciborium, available with default features):

```sh
cargo run --example gen_producer_vectors
```

Output is deterministic (all field values are hardcoded constants, no key
generation or randomness); re-running produces byte-identical files. The Rust
parity oracle is `tests/producer_vectors.rs` (17 tests): every happy-path
vector is round-tripped through `decode_message` + the per-command decoder and
re-encoded to assert byte-identity with the frozen `.bin`; every negative
vector is rejected at the appropriate layer (frame version / message-type
dispatch / length-mismatch).

## Wire layout (spec §7)

```
[u32 total_length BE][u8 protocol_version = 1][u8 message_type][CBOR payload]
```

- `total_length = 2 + payload.len()` — EXCLUDES the 4-byte length prefix.
- Maximum `total_length` is 1 MiB (`MAX_MESSAGE_SIZE`).
- CBOR library is **ciborium 0.2** with default serialization: shortest-form
  definite-length encoding, **insertion-order** map keys (NOT canonical-sorted;
  this is why the 2D Elixir decoder uses the `:response` profile that lifts the
  strict canonical ordering requirement for enclave-emitted bodies).

## Files

### GET_MEASUREMENT (message_type = 0x01)

| File | What it pins |
|------|--------------|
| `req_get_measurement_v1.bin` | Request frame `{1:1}`. |
| `resp_get_measurement_operational_v1.bin` | Operational response: `pq_signing_ready=true`, 1952-byte ML-DSA-65 `pq_pubkey`, 48-byte measurement, 64-byte `cert_chain`. Hosts MAY arm. |
| `resp_get_measurement_transport_v1.bin` | Transport-only response: `pq_signing_ready=false`, **empty** `pq_pubkey` + `cert_chain`. Hosts MUST NOT arm or treat as producer (spec §8 GET_MEASUREMENT security note). |

### SIGN_AUTHORIZATION_TICKET (message_type = 0x10)

| File | What it pins |
|------|--------------|
| `req_sign_authorization_ticket_recovery_v1.bin` | PRODUCER_RECOVERY (type=0) request — `fork_spec_hash` + `new_header_version` null. |
| `req_sign_authorization_ticket_hardfork_v1.bin` | HARD_FORK_ACTIVATION (type=1) request — `fork_spec_hash=[0xEE;32]`, `new_header_version=2`. |
| `resp_sign_authorization_ticket_v1.bin` | Success response: 3309-byte ML-DSA-65 `signature`, 32-byte `ticket_hash`. |
| `resp_sign_authorization_ticket_error_v1.bin` | Wire-error response: code=2 `PqSigningUnavailable`. Frame echoes `0x10`; CBOR body is the `{1:int, 2:tstr}` error map. |

### ARM_FOR_PRODUCTION (message_type = 0x20)

| File | What it pins |
|------|--------------|
| `req_arm_for_production_v1.bin` | Request with full `authorized_state` (1952-byte `pq_pubkey`, 48-byte measurement, `source_ticket_hash`) + `RecentChainProof` (1-entry tail, 64-byte Ed25519 `signature_from_recent_producer`). |
| `resp_arm_for_production_armed_v1.bin` | Success response `{1:"armed"}`. |
| `resp_arm_for_production_refused_v1.bin` | Refuse response — wire error code=2 with reason text. |

### GET_STATUS (message_type = 0x30)

| File | What it pins |
|------|--------------|
| `req_get_status_v1.bin` | Request frame `{1:1}`. |
| `resp_get_status_armed_v1.bin` | Armed session: all fields populated (1952-byte `authorized_pq_pubkey`, full heights + `source_ticket_hash`). |
| `resp_get_status_disarmed_v1.bin` | Disarmed: `armed=false`, empty bytes, all optional fields null. |

### Negative framing vectors (rejected at the frame layer)

| File | What it pins |
|------|--------------|
| `neg_unknown_message_type_v1.bin` | Valid frame structure with **unknown** message-type byte `0x99`. MUST reject as `UnknownMessageType(153)` / `WireProtocol(_)` — never defaulted to a producer type (fail-closed routing, TASK-7.1 AC#20). |
| `neg_wrong_protocol_version_v1.bin` | Valid frame with **wrong** `protocol_version=99`. MUST reject as `InvalidVersion { got: 99, expected: 1 }`. |
| `neg_frame_length_mismatch_v1.bin` | `total_length=100` prefix but only 3 body bytes. MUST reject as an `Io` (frame length mismatch) error. |

## Manifest

`manifest.json` lists every vector with its byte count, description, the spec
section reference, and the CBOR library notes. `tests/producer_vectors.rs`
includes a `manifest_vector_count_matches_emitted_files` test that asserts the
manifest's declared count equals the number of `.bin` files on disk (so the
manifest cannot drift from reality).

## Cross-repo consumer

The 2D Elixir producer signer client (TASK-122 AC#3) copies these `.bin` files
to `test/fixtures/producer_signer_protocol/` and asserts via ExUnit that:

1. **Decode parity** — the Elixir frame codec + per-command CBOR decoder
   produces structurally equal values to the Rust oracle.
2. **Encode parity** — re-encoding the decoded value produces byte-identical
   bytes to the frozen `.bin`.
3. **Negative rejection** — the three `neg_*` frames reject with the documented
   error shapes.

This binds the 2D Elixir producer client to the reference Rust encoder — a
divergence in CBOR encoding, framing, or field order surfaces immediately as a
test failure rather than as a silent interop break on staging.
