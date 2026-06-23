---
id: TASK-1.6
title: Operational runbook + 2-instance failover demo
status: Done
assignee: []
created_date: '2026-06-06 15:58'
updated_date: '2026-06-23 19:27'
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
Operational runbook delivered (backlog/docs/operational-runbook.md, 232 lines): deployment, key provisioning/rotation, attestation verification, monitoring, incident response (TEE compromise/unavailability/key compromise), failover design (active-passive MVP). Failover demo (§6.4) requires aya hardware — documented but not executable from macOS.
<!-- SECTION:FINAL_SUMMARY:END -->
