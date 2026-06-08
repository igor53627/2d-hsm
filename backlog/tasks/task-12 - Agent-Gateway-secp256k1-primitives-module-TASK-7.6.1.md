---
id: TASK-12
title: Agent Gateway secp256k1 primitives module (TASK-7.6.1)
status: Done
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 09:13'
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
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full Matrix (Reduced Matrix + the 2×3 concurrency floor from ~/pse/roborev/pse-review-2x3.sh; 3×3 vendor sign-off optional) + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
src/secp256k1.rs merged (PR #34, squash) behind the agent-gateway cargo feature. Pure secp256k1 primitives: getrandom CSPRNG keygen (zeroize-on-drop SigningKey), uncompressed SEC1 pubkey, eth address `keccak256(X||Y)[12:32]` + TRON Base58Check (free helper fully validates the SEC1 point — 0x04 prefix + on-curve via VerifyingKey::from_sec1_bytes; infallible Keypair accessors by invariant share one derivation), RFC6979 deterministic low-S recoverable signing over a 32-byte keccak prehash (sign_prehashed is pub(crate) — no generic-digest entry), recover_pubkey_uncompressed; reject x-reduced recovery ids (>1). 8 tests pass byte-exact vs the frozen 2D vectors (keys.json/ordinary_tx_v1/identity_proof_v1) incl. v=23166 + recover==from + off-curve rejection; default build unchanged (zero producer regression). Verified by roborev matrix + compact + /code-review + CI green. POST-MERGE HARDENING (PR #35): the post-#34 compact flagged that the free helper only checked the 0x04 prefix (accepted off-curve coordinates); #35 added full on-curve validation (VerifyingKey::from_sec1_bytes) + regression test + deduped the address derivation, and corrected the review-gate wording across TASK-12..16. Deps k256 0.13/bs58/sha2. Next: TASK-14 (7.6.3 keygen+dispatch).
<!-- SECTION:FINAL_SUMMARY:END -->
