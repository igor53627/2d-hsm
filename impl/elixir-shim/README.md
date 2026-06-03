# Elixir host shim (TASK-2 Phase 4)

Reference **2D host client** for the vsock wire protocol. Normative spec: `backlog/docs/vsock-api-wire-format-spec-draft.md`.

## Status

| Capability | Status |
|------------|--------|
| Length-prefixed framing (max frame **1 MiB**, spec § framing) | Done (`EnclaveProtocol.Framing`) |
| `GET_MEASUREMENT` / `GET_STATUS` request encoders | Done (native Elixir CBOR) |
| Stateless stdio (`GET_MEASUREMENT` only) | Done (`EnclaveProtocol.StdioClient` + `enclave-stdio-bridge`) |
| Stateful UDS session transport | Done (`EnclaveProtocol.Session` + `enclave-uds-server`) |
| `ARM_FOR_PRODUCTION` / `SIGN_AUTHORIZATION_TICKET` over UDS | Done in tests — **replay pre-built frames** from Rust (`TestFixtures`); native Elixir encoders not implemented |
| Wire fixtures from Rust | Done (`enclave-stdio-session export-*`) |
| Production AF_VSOCK | Follow-on — reuse `Framing` decoders + transport; add native ARM/SIGN encoders (or shared host builder) |

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
| `EnclaveProtocol.Framing` | Frame encode/decode; native encoders for GET_MEASUREMENT / GET_STATUS only |
| `EnclaveProtocol.StdioClient` | One-shot stdio bridge for GET_MEASUREMENT |
| `EnclaveProtocol.Socket` | Unix domain socket read/write |
| `EnclaveProtocol.Session` | Stateful transport; ARM/SIGN take **caller-supplied** request frames (see `TestFixtures`) |
| `EnclaveProtocol.TestFixtures` | Hex export of ARM / recovery-SIGN / hard-fork-SIGN frames from `enclave-stdio-session` |

**Production path:** vsock transport module + `Framing` response decoders + **new** `build_arm_for_production_request` / `build_sign_authorization_ticket_request` (or a shared host-side builder used by Elixir and Rust tests). Do not assume `Session` can construct security-critical requests today.

**Dev UDS trust boundary:** `enclave-uds-server` listens on `~/.2d-hsm/enclave.sock` (`0600`). Any **same-UID** local process that can open that path can issue ARM and SIGN — acceptable only as a disclosed dev stand-in, not production authorization.

## High-risk review

This shim is part of **TASK-2 Phase 4** (stateful session, ARM, SIGN). Per `impl/README.md` and `AGENTS.md`, merge requires the **Full Matrix** (Reduced 3-review set + concurrency 2×3 floor where applicable) and `roborev compact --wait` — not Reduced alone. Framing/CBOR edits in this tree are never isolated from arming/signing gating.