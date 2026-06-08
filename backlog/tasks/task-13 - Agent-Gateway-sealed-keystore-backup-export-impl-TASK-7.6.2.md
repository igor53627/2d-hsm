---
id: TASK-13
title: Agent Gateway sealed keystore + backup export impl (TASK-7.6.2)
status: In Progress
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 11:34'
labels:
  - agent-gateway
  - keystore
  - implementation
dependencies:
  - TASK-12
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.2 implementation. pq-agent-keystore-v1 sealed multi-key CBOR store (magic 2DAGTKS, XChaCha20Poly1305 [24-byte nonce — the keystore re-seals on every mutation under a fixed key, so it needs the extended nonce, unlike the producer's one-shot ChaCha20Poly1305] + SHA3-256 KDF under domain 2d-hsm-agent-keystore-v1-key, freshness_epoch + anchor_root fields per 7.7; reuse pq_signer.rs seal conventions, multi-key). KeyEntry, capability counter high-water table, faucet state (cumulative_spend + lifetime breaker), audit ring + last_exported_seq. EXPORT_BACKUP opaque ML-KEM-1024 blob + self-check; fail-closed unknown-version before decrypt. RESTORE ingress format reserved fail-closed (AC#6). Golden round-trip tests. Depends on 7.6.1.

Sliced for the Full-Matrix gate: **13a — sealed keystore core** (envelope + CBOR body + validation + golden vector; PR #37) delivers the at-rest store TASK-7.6.3 needs; **13b — DR backup** (pq-agent-backup-v1 ML-KEM-1024 KEM-DEM export + self-check) and the RESTORE fail-closed stub follow as a separate slice.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Roborev: high-risk Agent Gateway implementation slice (impl/rust/ signing path) — the Full Matrix (Reduced Matrix + the 2×3 concurrency floor from ~/pse/roborev/pse-review-2x3.sh; 3×3 vendor sign-off optional) + compact is mandatory before merge per AGENTS.md and the .roborev.toml high_risk_paths (impl/, src/, backlog/docs/*agent-gateway*).
<!-- SECTION:NOTES:END -->
