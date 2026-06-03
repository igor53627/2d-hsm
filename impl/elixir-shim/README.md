# Elixir host shim (TASK-2 Phase 4)

Reference **2D host client** for the vsock wire protocol. Normative spec: `backlog/docs/vsock-api-wire-format-spec-draft.md`.

## Status

| Capability | Status |
|------------|--------|
| Length-prefixed framing | Done (`EnclaveProtocol.Framing`) |
| `GET_MEASUREMENT` integer-key CBOR | Done |
| Stateless stdio (`GET_MEASUREMENT` only) | Done (`EnclaveProtocol.StdioClient` + `enclave-stdio-bridge`) |
| Stateful UDS session | Done (`EnclaveProtocol.Session` + `enclave-uds-server`) |
| `ARM_FOR_PRODUCTION` / `GET_STATUS` over UDS | Done (integration tests) |
| Wire fixtures from Rust | Done (`EnclaveProtocol.TestFixtures` + `enclave-stdio-session export-*`) |
| Production AF_VSOCK | Follow-on (same framing/CBOR modules) |

## Prerequisites

- Elixir ~> 1.14
- Rust toolchain

## Quick start

```bash
# Stateless GET_MEASUREMENT
cd ../rust/enclave-protocol
cargo build --bin enclave-stdio-bridge
cd ../../elixir-shim
mix deps.get
mix test

# Full session tests (builds UDS + session binaries automatically)
mix test --only integration  # optional tag; default mix test runs all
```

## Layout

| Module | Role |
|--------|------|
| `EnclaveProtocol.Framing` | Frame encode/decode + GET_MEASUREMENT / GET_STATUS CBOR |
| `EnclaveProtocol.StdioClient` | One-shot stdio bridge for GET_MEASUREMENT |
| `EnclaveProtocol.Socket` | Unix domain socket read/write |
| `EnclaveProtocol.Session` | Stateful client (GET_MEASUREMENT, GET_STATUS, raw frames) |
| `EnclaveProtocol.TestFixtures` | Import pre-built ARM frames from Rust |

Production path: add a vsock-backed transport module reusing `Framing` + `Session` request helpers.

## High-risk review

This shim is part of **TASK-2 Phase 4** (stateful session, ARM, SIGN). Per `impl/README.md` and `AGENTS.md`, merge requires the **Full Matrix** (Reduced 3-review set + concurrency 2×3 floor where applicable) and `roborev compact --wait` — not Reduced alone. Framing/CBOR edits in this tree are never isolated from arming/signing gating.