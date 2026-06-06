---
id: TASK-1.5
title: >-
  Reader/light-client block verification (authorized producer + state
  transitions)
status: To Do
assignee: []
created_date: '2026-06-06 15:58'
labels:
  - verification
  - cross-repo
  - light-client
dependencies: []
parent_task_id: TASK-1
priority: medium
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Finalize the spec + implement reader-node/light-client rules that reject blocks from unauthorized producer keys or with invalid state transitions, including forged 'stay' transitions. Spec partial in this repo; impl is cross-repo (2d reader nodes). Maps to TASK-1 #14 + acceptance #9.
<!-- SECTION:DESCRIPTION:END -->
