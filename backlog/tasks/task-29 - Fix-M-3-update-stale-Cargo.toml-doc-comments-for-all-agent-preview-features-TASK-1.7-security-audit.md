---
id: TASK-29
title: >-
  Fix M-3: update stale Cargo.toml doc-comments for all agent-*-preview features
  (TASK-1.7 security audit)
status: To Do
assignee: []
created_date: '2026-06-22 23:00'
labels:
  - security
  - documentation
  - TASK-1.7
dependencies: []
priority: medium
ordinal: 31500
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**MEDIUM finding from TASK-1.7 security audit.** Cargo.toml doc-comments for agent-prove-identity-preview, agent-keygen-exec-preview, agent-sign-transfer-preview, agent-sign-faucet-preview, agent-configure-treasury-preview still say "Production-gated OFF / Banned in release builds / Never enable in production" — but lib.rs confirms all bans were REMOVED under TASK-18 (lines 86-95). An operator reading Cargo.toml will believe these features are still release-banned when they are not.

Fix: update all 5 feature doc-comments in Cargo.toml to match lib.rs (ban removed, prerequisites met).
<!-- SECTION:DESCRIPTION:END -->
