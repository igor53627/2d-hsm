# Elixir host shim (TASK-2 Phase 4 start)

Reference **2D host client** for the vsock wire protocol. Normative spec: `backlog/docs/vsock-api-wire-format-spec-draft.md`.

## Status

| Capability | Status |
|------------|--------|
| Length-prefixed framing | Done (`EnclaveProtocol.Framing`) |
| `GET_MEASUREMENT` integer-key CBOR | Done (matches `enclave-protocol` `wire.rs`) |
| Stdio integration test | Done (`enclave-stdio-bridge` + `mix test`) |
| Real vsock transport | Not started |
| `ARM_FOR_PRODUCTION` / `GET_STATUS` / sign | Not started |

## Prerequisites

- Elixir ~> 1.14
- Rust toolchain (builds `enclave-stdio-bridge`)

## Quick start

```bash
# Rust bridge (one framed message on stdin → one on stdout)
cd ../rust/enclave-protocol
cargo build --bin enclave-stdio-bridge

# Elixir tests (builds bridge if missing)
cd ../../elixir-shim
mix deps.get
mix test
```

## Layout

| Module | Role |
|--------|------|
| `EnclaveProtocol.Framing` | Frame encode/decode + GET_MEASUREMENT CBOR |
| `EnclaveProtocol.StdioClient` | `System.cmd` adapter for local dev |

Production path will add a vsock-backed transport module; keep framing/CBOR shared.

## High-risk review

Changes to framing or CBOR layouts are **high-risk** (`impl/`). Run Reduced roborev matrix + `roborev compact` before merge (see root `AGENTS.md`).