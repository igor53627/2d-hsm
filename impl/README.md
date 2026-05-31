# Implementation Area — 2d-hsm

This directory contains the actual implementation of the vsock protocol and related logic for the TEE signing service.

**All code here is High-risk** (see root `AGENTS.md` and `.roborev.toml`).

## Current Structure (as of 2026-06-05)

- `rust/enclave-protocol/` — Core Rust crate defining the canonical wire format (framing + CBOR message types).
  - This is the single source of truth for what bytes go over the wire.
  - Any change to framing, message types, or canonical encoding **must** go through the full 3:3 roborev matrix + `compact` before merge.

- `elixir-shim/` — Placeholder for the future clean Elixir client library that will talk to the enclave from the 2D host.

## Review Gates (mandatory)

1. Every non-trivial diff touching this area requires a 3×3 matrix review (codex + gemini + cursor-codex-gemini × security/design/concurrency).
2. After the matrix, run `roborev compact --wait`.
3. Address all High/Critical findings (and relevant Medium ones).
4. Only then is the increment considered reviewed.

This rule was established after the first successful matrix on the design specs (which caught two HIGH issues before any code was written).

## Getting Started (Phase 1)

See the phased plan in `backlog/docs/implementation-plan-vsock-api-and-hard-fork.md`.

Current focus: solid framing + the first few commands (`GET_MEASUREMENT`, `SIGN_AUTHORIZATION_TICKET`, `ARM_FOR_PRODUCTION`) with correct canonical payloads and mandatory freshness proofs.

**First reviewed increment**: commit `0262bd5` (framing + GetMeasurement).

All future changes here will be reviewed via the 3:3 roborev matrix + compact before being considered stable.

## Building the demo

```bash
cd rust/enclave-protocol
cargo run --example framing_demo
```

## Next Steps

See the Implementation Plan document for the ordered phases and explicit review checkpoints.