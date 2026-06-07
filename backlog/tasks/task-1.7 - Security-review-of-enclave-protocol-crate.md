---
id: TASK-1.7
title: Security review of enclave-protocol crate
status: To Do
assignee: []
created_date: '2026-06-06 15:58'
labels:
  - security
  - review
dependencies: []
parent_task_id: TASK-1
priority: high
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Formal security review of the signing service (acceptance #2): key never leaves the TEE in plaintext, correct sealing/attestation usage, no obvious exfiltration paths, fail-closed on RNG/seal/attestation errors. Run /security-review on the crate + a focused threat-model pass (malicious host over vsock; supply-chain on the public image).
<!-- SECTION:DESCRIPTION:END -->
