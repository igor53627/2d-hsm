---
id: TASK-1.1
title: Platform-derived PQ-seal + attestation-trust root (vTPM/SNP VMPL/Nitro)
status: To Do
assignee: []
created_date: '2026-06-06 15:58'
labels:
  - tee
  - sev-snp
  - pq-seal
  - attestation
  - mainnet
dependencies: []
parent_task_id: TASK-1
priority: high
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Keystone for real mainnet. Today the enclave uses LAB trust VK + lab PQ-seal root; the mainnet gate (TASK-5 AC#10) refuses lab fixtures under productionMode but no platform-DERIVED root exists yet. Implement boot_configure_pq_seal_v1_platform_root by deriving the seal/trust root from the platform (SEV-SNP derived key via /dev/sev-guest SNP_GET_DERIVED_KEY, or vTPM/Nitro), feeding guest-profile trustFileOverride/pqSealRootOverride/pqSealedSignerOverride. Design-first: the derived-key path needs an ioctl (not configfs file I/O), so decide the unsafe-helper boundary vs the forbid(unsafe) signing crate. Validate on aya. Maps to TASK-1 #6 (key mgmt), TASK-5 AC#2 (platform trust).
<!-- SECTION:DESCRIPTION:END -->
