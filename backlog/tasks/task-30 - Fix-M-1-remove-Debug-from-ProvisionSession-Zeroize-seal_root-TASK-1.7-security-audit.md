---
id: TASK-30
title: >-
  Fix M-1: remove Debug from ProvisionSession + Zeroize seal_root (TASK-1.7
  security audit)
status: Done
assignee: []
created_date: '2026-06-22 23:00'
updated_date: '2026-06-23 06:54'
labels:
  - security
  - hardening
  - TASK-1.7
dependencies: []
priority: high
ordinal: 32500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**MEDIUM finding from TASK-1.7 security audit.** ProvisionSession (agent_provision.rs:959) derives Debug while holding seal_root: [u8;32] — the keystore provisioning root that derives the AEAD key encrypting all secp256k1 scalars. derive(Debug) means any `{:?}` format of the session leaks all 32 root bytes to stderr/journald (host-readable). Additionally, [u8;32] is Copy with no Drop — the root is never scrubbed on session drop.

Fix: (1) remove #[derive(Debug)] or impl manual Debug redacting seal_root; (2) change seal_root from [u8;32] to Zeroizing<[u8;32]>.

Contradicts the repo's own zeroize rule (seal_root.rs:77-83).
<!-- SECTION:DESCRIPTION:END -->
