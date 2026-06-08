---
id: TASK-15
title: Agent Gateway transfer + faucet signing + caps impl (TASK-7.6.4)
status: To Do
assignee: []
created_date: '2026-06-08 08:09'
updated_date: '2026-06-08 08:24'
labels:
  - agent-gateway
  - implementation
dependencies:
  - TASK-12
  - TASK-13
  - TASK-14
ordinal: 19000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-7.4 implementation. Opcodes SIGN_TRANSFER(4), SIGN_FAUCET_DISPENSE(5), CONFIGURE_TREASURY(6). SIGN_TRANSFER: chain_id/from/empty-data checks, EIP-155 RLP keccak256, low-S sig, v=chain_id*2+35+rid, post-sign recovery==from. FAUCET_DISPENSE: recipient in active transfer set, checked u256 worst-case arithmetic, per-field caps, dual-counter debit sealed-before-emit, unbroadcast burn. CONFIGURE_TREASURY sub-ops + monotonic config_version + rotation carry-over. No generic digest. Golden vector ordinary_tx_v1. Depends on 7.6.1-7.6.3.
<!-- SECTION:DESCRIPTION:END -->
