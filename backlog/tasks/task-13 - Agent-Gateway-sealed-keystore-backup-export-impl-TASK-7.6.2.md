---
id: TASK-13
title: Agent Gateway sealed keystore + backup export impl (TASK-7.6.2)
status: To Do
assignee: []
created_date: '2026-06-08 08:09'
labels:
  - agent-gateway
  - keystore
  - implementation
dependencies: []
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.2 implementation. pq-agent-keystore-v1 sealed multi-key CBOR store (magic 2DAGTKS, ChaCha20Poly1305 + SHA3-256 KDF under domain 2d-hsm-agent-keystore-v1-key, freshness_epoch + anchor_root fields per 7.7; mirror pq_signer.rs seal/unseal, multi-key). KeyEntry, capability counter high-water table, faucet state (cumulative_spend + lifetime breaker), audit ring + last_exported_seq. EXPORT_BACKUP opaque ML-KEM-1024 blob + self-check; fail-closed unknown-version before decrypt. RESTORE ingress format reserved fail-closed (AC#6). Golden round-trip tests. Depends on 7.6.1.
<!-- SECTION:DESCRIPTION:END -->
