---
id: TASK-1.6
title: Operational runbook + 2-instance failover demo
status: Done
assignee: []
created_date: '2026-06-06 15:58'
updated_date: '2026-06-24 01:16'
labels:
  - ops
  - docs
  - failover
dependencies: []
parent_task_id: TASK-1
priority: medium
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
(a) Operational runbook: deployment into TEE, PQ key provisioning/rotation inside TEE, attestation, monitoring, incident response for TEE compromise/unavailability (acceptance #5). (b) Basic failover between >=2 enclave instances on different hosts (primary down -> recovery ticket -> hot-standby activation), designed + documented + a demo on aya (acceptance #4).
<!-- SECTION:DESCRIPTION:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Runbook delivered (PR #115, 232 lines): deployment, provisioning, attestation, monitoring, incident response, failover design. The aya failover DEMO (§6.4) requires ≥2 SNP hosts and was not executed — deferred to a follow-up ops task when hardware is available.
<!-- SECTION:FINAL_SUMMARY:END -->
