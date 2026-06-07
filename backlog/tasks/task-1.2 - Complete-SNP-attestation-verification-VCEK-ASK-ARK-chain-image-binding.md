---
id: TASK-1.2
title: 'Complete SNP attestation verification: VCEK->ASK->ARK chain + image binding'
status: Done
assignee: []
created_date: '2026-06-06 15:58'
labels:
  - attestation
  - sev-snp
  - verifier
  - security
dependencies: []
parent_task_id: TASK-1
priority: high
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
snp_verify::prevalidate_report does the signature-INDEPENDENT checks only. Add the real verification: VCEK->ASK->ARK cert-chain to a pinned AMD ARK (ECDSA-P384 + X.509 + AMD KDS fallback when auxblob empty — it is empty on aya), TCB anti-rollback. Plus image binding (verifier-policy §3 gap): the launch measurement pins OVMF, not the guest image — bind the running image via measured boot / dm-verity / direct-kernel-hash. Likely a separate verifier crate or BP-side. Maps to TASK-1 #12 + acceptance #3.
<!-- SECTION:DESCRIPTION:END -->
