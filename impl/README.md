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
| `elixir-shim/` | Host client: framing, stdio GET_MEASUREMENT, UDS session — ARM/SIGN via Rust-exported frames — see `elixir-shim/README.md` |

**Normative protocol spec:** `backlog/docs/vsock-api-wire-format-spec-draft.md` (§8 wire schemas, §9.1 Producer Chain Attestation, §9.3 trust provisioning).

## What is implemented

- Length-prefixed CBOR framing (`encode_message` / `decode_message`)
- `GET_MEASUREMENT`, `SIGN_AUTHORIZATION_TICKET`, `ARM_FOR_PRODUCTION`, `GET_STATUS`
- Canonical `ticketHash` (Keccak256 + Solidity-aligned `abi.encode` preimage)
- Enclave state: `EnclaveState` / `EnclaveArmedState`, `arm_for_production`, re-arm monotonicity
- **Producer Chain Attestation v1** (TASK-3): Ed25519 over domain-separated preimage; pinned `ProducerAttestationTrust` (not derived from public `pq_pubkey`)
- Hard-fork gating: armed + crypto proof + pubkey match + one fork per session
- Wire helpers + `process_framed_with_shared_state` (one `EnclaveState` per enclave process); `HostSession` / `process_framed_with_session` for single-connection dev tools only
- Dev transports: multi-frame stdio session + UDS server with **shared** enclave state across connections (TASK-2 Phase 4 stand-in for vsock)

## Dispatch surfaces (important)

| API | Use when |
|-----|----------|
| `dispatch_command` | **Recovery tickets (type 0)** and `GET_MEASUREMENT` only. Returns explicit errors for arm / status / hard-fork. |
| `dispatch_command_with_state` | **Arming, GET_STATUS, hard-fork signing.** Requires `ProducerAttestationTrust` loaded **inside the enclave** (sealed config / attested provisioning — never from the host over vsock). |

`GET_MEASUREMENT.supported_ticket_types` lists image capabilities `[0, 1]`; type `1` still requires the stateful path and armed state.

## Review gates

Per `AGENTS.md`:

1. **Reduced matrix** only for incremental high-risk work that does not introduce significant state-machine logic or modify ticket-signing / `ARM_FOR_PRODUCTION` / hard-fork gating in `impl/**/*.rs`.
2. **`roborev compact --wait`** after the matrix.
3. Address High/Critical and relevant Medium findings before treating the increment as reviewed.

**Full matrix** (+ concurrency lens) is required for first state-machine introduction, core gating changes, and all `impl/**/*.rs` changes touching ticket signing, `ARM_FOR_PRODUCTION`, hard-fork transition, or key lifecycle — see AGENTS.md.

TASK-3 crypto verification used reduced matrix + compact (`2d136ac`, `fddd3f0`, `6dced02`).

### TASK-2 Phase 4 review record (PR #3 — do not merge on Reduced alone for the initial intro)

| Phase | Commits / topic | Matrix | Compact |
|-------|-----------------|--------|---------|
| Initial intro | stateful session, Elixir, wire | Reduced **6717–6721**, **6755–6757** + Full 2×3 **6758–6763** (`pse-review-2x3.sh`) | **6765** (2 HIGH → fixed before `47d141c`) |
| Shared-state fix | `47d141c` UDS anti-equivocation | Reduced **6773–6778** | **6778** (no code High) |
| Doc alignment | `8baa062` plan/README/spec | Reduced **6781–6783** | **6785** (doc gate wording; reconciled below) |

**Merge rule:** First introduction of `EnclaveState` over transport required **Full Matrix** (table row 1). Later rows are follow-ups inside that reviewed direction (Reduced + compact per `AGENTS.md`). Cite this table in PR description; do not mark the task “reviewed” with only the latest Reduced run.

**Accepted debt (security PR sign-off, 2026-06):** `produce_pq_signature` may return 64-byte mocks only under `test-support` / `demo-mock-sign` (or `ml-dsa-65` tests **without** `reference-test-key`). With `reference-test-key`, unit tests fail closed if the sealed signer is not installed. Production vsock (Nitro/SEV) wiring is out of scope for this repo increment.

## Building and testing

```bash
cd rust/enclave-protocol
# Seal/provisioning CLI + ML-DSA unit tests (no reference-key integration tests)
cargo test --features ml-dsa-65,pq-seal-provisioning

# Reference host session / wire integration (mutually exclusive with ml-dsa-65):
cargo test --features test-support,demo-mock-sign

# TASK-1 staging: real ML-DSA-65 + fail-closed SIGN (`reference-test-key` pulls seal + provisioning)
cargo test --features reference-test-key
cargo build --bin enclave-uds-staging --features staging-host
```

| Profile | Features | SIGN signature | Binaries |
|---------|----------|----------------|----------|
| Dev mock (TASK-2) | `test-support`, `demo-mock-sign` | 64-byte deterministic mock | `enclave-uds-server`, `enclave-stdio-session` |
| Staging (TASK-1 slice) | `staging-host` | ML-DSA-65 (3309 B); fail-closed without seal at boot | `enclave-uds-staging` |
| ML-DSA integration tests | `reference-test-key` | ML-DSA-65 (3309 B); fail-closed without `install_*` in test | (library tests only) |

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