---
id: TASK-1.1
title: Platform-derived PQ-seal + attestation-trust root (vTPM/SNP VMPL/Nitro)
status: Done
assignee: []
created_date: '2026-06-06 15:58'
updated_date: '2026-06-25 08:33'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
PR #120. Production platform-root-from-boot-file reader: release-safe feature that reads the SNP-derived provisioning root from the FIXED path /run/twod-hsm/pq-seal-root.bin (written by snp-derive-root --out at boot). NOT a host-settable env var. Wired for both producer (platform_provisioning_boot.rs) and agent (boot_agent_keystore.rs) paths. Added to agentGatewayRelease nix profile. Lab features (platform-provisioning-from-file, lab-agent-keystore-from-file) keep the env-var path + remain release-banned.

All existing infrastructure validated on aya: snp-derive-root binary (--out/--print/--selftest), ceremony scripts, disk-production-lab-snp-rooted, SMOKE-PASS-CRITERIA PASS.

Safety: rests on measured boot (NixOS image + snp-derive-root oneshot are part of the measured SNP launch). This is a platform integration precondition, not a crate code gap.

Remaining: TASK-1.3/1.4/1.5 are cross-repo (2D/2d-solidity).
<!-- SECTION:FINAL_SUMMARY:END -->
