# Implementation Area — 2d-hsm

This directory contains the reference implementation of the vsock protocol and enclave-side logic for the TEE signing service.

**All code here is high-risk** (see root `AGENTS.md` and `.roborev.toml`).

## Layout (as of 2026-06-02)

| Path | Role |
|------|------|
| `rust/enclave-protocol/` | Canonical wire format, state machine, ticket hashing, `RecentChainProof` crypto (TASK-3) |
| `rust/enclave-protocol/src/wire.rs` | Spec-aligned CBOR with **integer map keys** for `GET_STATUS` and `ARM_FOR_PRODUCTION` |
| `solidity/` | Ground-truth `abi.encode` + keccak for cross-checking `ticketHash` |
| `elixir-shim/` | Placeholder for the future 2D host client |

**Normative protocol spec:** `backlog/docs/vsock-api-wire-format-spec-draft.md` (§7 wire schemas, §8.1 attestation, §8.3 trust provisioning).

## What is implemented

- Length-prefixed CBOR framing (`encode_message` / `decode_message`)
- `GET_MEASUREMENT`, `SIGN_AUTHORIZATION_TICKET`, `ARM_FOR_PRODUCTION`, `GET_STATUS`
- Canonical `ticketHash` (Keccak256 + Solidity-aligned `abi.encode` preimage)
- Enclave state: `EnclaveState` / `EnclaveArmedState`, `arm_for_production`, re-arm monotonicity
- **Producer Chain Attestation v1** (TASK-3): Ed25519 over domain-separated preimage; pinned `ProducerAttestationTrust` (not derived from public `pq_pubkey`)
- Hard-fork gating: armed + crypto proof + pubkey match + one fork per session
- Wire helpers: `encode_get_status_response`, `encode_arm_for_production_request`, etc.

## Dispatch surfaces (important)

| API | Use when |
|-----|----------|
| `dispatch_command` | **Recovery tickets (type 0)** and `GET_MEASUREMENT` only. Returns explicit errors for arm / status / hard-fork. |
| `dispatch_command_with_state` | **Arming, GET_STATUS, hard-fork signing.** Requires `ProducerAttestationTrust` loaded **inside the enclave** (sealed config / attested provisioning — never from the host over vsock). |

`GET_MEASUREMENT.supported_ticket_types` lists image capabilities `[0, 1]`; type `1` still requires the stateful path and armed state.

## Review gates

Per `AGENTS.md`:

1. **Reduced matrix** (default for incremental high-risk work): codex security, gemini security, claude-code design.
2. **`roborev compact --wait`** after the matrix.
3. Address High/Critical and relevant Medium findings before treating the increment as reviewed.

Full matrix (+ concurrency lens) is required for first state-machine introduction, core gating changes, or after HIGH findings — see AGENTS.md.

TASK-2 / TASK-3 increments on this tree went through reduced matrix + compact (commits `2d136ac`, `fddd3f0`, `6dced02`).

## Building and testing

```bash
cd rust/enclave-protocol
cargo test
```

Optional CI gate for Solidity cross-check:

```bash
cd ../solidity && forge install foundry-rs/forge-std --no-commit
cd ../rust/enclave-protocol
cargo test --features enforce-forge-crosscheck
```

## Examples

```bash
cd rust/enclave-protocol

# Framing only
cargo run --example framing_demo

# Full Arm → GetStatus → Sign flow (needs test attestation keys)
cargo run --example ticket_signing_demo --features test-support
```

The `test-support` feature exposes `reference_test_attestation_signing_key` / `reference_test_attestation_trust` for local dev only — **do not enable in production enclave builds.**

## Still deferred

- Real ML-DSA / SLH-DSA signing inside the TEE (TASK-1)
- Live chain-tip refresh between arming and signing (arming-time snapshot only)
- Full light-client proofs in `proof_data` (format `0x02+`)
- Integer-key CBOR for all commands (only GET_STATUS + ARM request bodies use `wire.rs` today)
- Elixir host shim and real vsock transport

See `backlog/docs/implementation-plan-vsock-api-and-hard-fork.md` for phased roadmap.