# Implementation Area — 2d-hsm

This directory contains the reference implementation of the vsock protocol and enclave-side logic for the TEE signing service.

**All code here is high-risk** (see root `AGENTS.md` and `.roborev.toml`).

## Layout (as of 2026-06-02)

| Path | Role |
|------|------|
| `rust/enclave-protocol/` | Canonical wire format, state machine, ticket hashing, `RecentChainProof` crypto (TASK-3) |
| `rust/pq-seal-v1/` | Offline `pq-seal-v1` CLI for v1 sealed PQ blobs (provisioning workstation) |
| `rust/enclave-protocol/src/wire.rs` | Spec-aligned CBOR with **integer map keys** for all four commands |
| `rust/enclave-protocol/src/bin/` | `enclave-stdio-bridge` (stateless GET_MEASUREMENT), `enclave-stdio-session`, `enclave-uds-server` (dev transport) |
| `solidity/` | Ground-truth `abi.encode` + keccak for cross-checking `ticketHash` |
| `elixir-shim/` | Host client: framing, stdio GET_MEASUREMENT, UDS session (ARM/STATUS) — see `elixir-shim/README.md` |

**Normative protocol spec:** `backlog/docs/vsock-api-wire-format-spec-draft.md` (§8 wire schemas, §9.1 Producer Chain Attestation, §9.3 trust provisioning).

## What is implemented

- Length-prefixed CBOR framing (`encode_message` / `decode_message`)
- `GET_MEASUREMENT`, `SIGN_AUTHORIZATION_TICKET`, `ARM_FOR_PRODUCTION`, `GET_STATUS`
- Canonical `ticketHash` (Keccak256 + Solidity-aligned `abi.encode` preimage)
- Enclave state: `EnclaveState` / `EnclaveArmedState`, `arm_for_production`, re-arm monotonicity
- **Producer Chain Attestation v1** (TASK-3): Ed25519 over domain-separated preimage; pinned `ProducerAttestationTrust` (not derived from public `pq_pubkey`)
- Hard-fork gating: armed + crypto proof + pubkey match + one fork per session
- Wire helpers + `process_framed_with_session` / `HostSession` for stateful host↔enclave transports
- Dev transports: multi-frame stdio session + Unix domain socket server (TASK-2 Phase 4 stand-in for vsock)

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

**Accepted debt (security PR sign-off, 2026-06):** `produce_pq_signature` may return 64-byte mocks in `cfg(test)` / `demo-mock-sign` when no sealed signer is installed (production fail-closed). Production vsock (Nitro/SEV) wiring is out of scope for this repo increment.

## Building and testing

```bash
cd rust/enclave-protocol
cargo test --features ml-dsa-65,pq-seal-provisioning
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
cargo run --example ticket_signing_demo --features test-support,demo-mock-sign
```

The `test-support` feature exposes `reference_test_attestation_signing_key` / `reference_test_attestation_trust` for local dev only — **do not enable in production enclave builds.**

## ML-DSA-65 features (reference crate)

| Feature | Use |
|---------|-----|
| *(default, none)* | No PQ signing; `pq_signing_ready: false` |
| `ml-dsa-65` | ML-DSA-65 crypto + v1 sealed-key **unseal/install** at enclave boot (deploy feature) |
| `pq-seal-provisioning` | Seal/verify helpers + `secret_key_bytes` — **`pq-seal-v1` CLI only**, not enclave images |
| `reference-seal-v1-root` | Staging/CI only: test provisioning root for v1 seal/unseal (**not for deployment**) |
| `reference-test-key` | Implies `ml-dsa-65` + `reference-seal-v1-root`; NIST test-vector in unit tests |
| `test-support` | Reference Ed25519 attestation keys for local dev |
| `demo-mock-sign` | Enables 64 B mock PQ in `ticket_signing_demo` (`pq_signing_ready` stays false) |

v0 seal/unseal helpers compile only under `cargo test --features ml-dsa-65` (not in standalone binaries).

At boot (production):

1. Platform integration calls `set_pq_seal_v1_provisioning_root(root)` **once** (from vTPM / SNP VMPL / Nitro — not from vsock).
2. `install_sealed_pq_signer(sealed_blob, enclave_measurement)` with a **v1** blob (`2DHSMV1` magic).

Staging/CI may use `reference-seal-v1-root` or `cargo test` (embedded test root). v0 XOR is **unit-test only**. **Do not** ship `reference-seal-v1-root` in deployment images.

Do not pass `--all-features` (`ml-dsa-65` and `test-support` conflict).

### Offline seal v1 (`pq-seal-v1`)

- **CLI reference:** `rust/pq-seal-v1/README.md`
- **Staging runbook:** `backlog/docs/pq-seal-v1-provisioning-runbook.md`

Quick start: `cd rust/pq-seal-v1 && cargo build --release && ./target/release/pq-seal-v1 --help`

## Dev host ↔ enclave transports (TASK-2)

```bash
cd rust/enclave-protocol
cargo build --bin enclave-stdio-bridge
cargo build --bin enclave-stdio-session --bin enclave-uds-server --features test-support,demo-mock-sign

# UDS server (default ~/.2d-hsm/enclave.sock, mode 0600)
./target/debug/enclave-uds-server

# Elixir integration tests (starts UDS server in test setup)
cd ../../elixir-shim && mix test
```

## Still deferred (follow-on, not TASK-2 blockers)

- Platform-specific root derivation (vTPM / SNP VMPL / Nitro) in production enclave images
- Live chain-tip refresh between arming and signing (arming-time snapshot only)
- Full light-client proofs in `proof_data` (format `0x02+`)
- Production **AF_VSOCK** transport (Unix socket + stdio are reference dev paths)

See `backlog/docs/implementation-plan-vsock-api-and-hard-fork.md` for phased roadmap.