---
id: TASK-12
title: Agent Gateway secp256k1 primitives module (TASK-7.6.1)
status: In Progress
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 08:46'
labels:
  - agent-gateway
  - secp256k1
  - implementation
dependencies: []
ordinal: 16000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First implementation increment of TASK-7.6 (per AC#2 split). Pure crypto module src/secp256k1.rs behind a new agent-gateway cargo feature: keygen (getrandom CSPRNG 32B scalar in Zeroizing), uncompressed SEC1 pubkey (0x04||X||Y, reject compressed), eth address keccak256(X||Y)[12:32], TRON Base58Check(0x41||body20), RFC6979 deterministic + low-S recoverable signing (r,s,recovery_id), keccak256 prehash. NO opcode/keystore/dispatch (0x40 stub at lib.rs untouched). Deps: k256 0.13 (default-features=false, ecdsa+arithmetic), bs58, sha2. Validated byte-exact against testvectors/agent-gateway/{keys.json,ordinary_tx_v1.json,identity_proof_v1.json}. cargo test --features agent-gateway. Implements TASK-7.3 keygen-identity primitives; depends on nothing.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full 3x3 vendor matrix + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).
<!-- SECTION:NOTES:END -->
