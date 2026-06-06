---
id: TASK-1.3
title: >-
  Integrate with 2d signing path: NetHSM inventory +
  Chain.Bridge.Signer/OPA/Vault
status: To Do
assignee: []
created_date: '2026-06-06 15:58'
labels:
  - integration
  - cross-repo
  - elixir
dependencies: []
parent_task_id: TASK-1
priority: medium
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cross-repo (2d Elixir). (a) Inventory the exact ops Chain.Bridge.Signer performs against NetHSM incl. Elixir pre/post-processing (TASK-1 #7); (b) design the integration boundary with SignerPolicy + OPA + Vault credential brokering (#9); (c) implement + test the thin adapter from BlockProducer (producer namespace, low-latency fixed digest) and bridge paths (acceptance #6). Needs the 2d main repo.
<!-- SECTION:DESCRIPTION:END -->
