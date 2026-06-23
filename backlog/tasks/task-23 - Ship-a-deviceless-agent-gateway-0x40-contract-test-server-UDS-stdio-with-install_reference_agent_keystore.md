---
id: TASK-23
title: >-
  Ship a deviceless agent-gateway 0x40 contract-test server (UDS/stdio) with
  install_reference_agent_keystore
status: Done
assignee: []
created_date: '2026-06-16 21:30'
updated_date: '2026-06-23 19:16'
labels:
  - agent-gateway
  - contract-test
  - cross-repo
  - task-7
dependencies: []
priority: high
ordinal: 27000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Downstream 2d (TASK-132.5.2 slice 4 live identity, slice 2 privileged opcodes, AC#7 TEE-rejection) cannot run a live 0x40 contract test — and 2d runs on Elixir/macOS. Today the ONLY agent-gateway 0x40 serve loop is AF_VSOCK + Linux + a full SNP anti-rollback boot handshake (agent_gateway_boot.rs / bin/agent_gateway_vsock.rs, #[cfg(target_os=linux)]). The UDS bins (enclave_uds_server / enclave_uds_staging) serve the PRODUCER ML-DSA-65 profile (role-isolation-exclusive with agent-gateway) and return 0x41 WrongProfile on agent opcodes; enclave_uds_server uses SharedEnclaveRuntime::reference_test() and installs NO agent keystore. The smoke client (twod_hsm_agent_smoke_client) is release-banned, Linux-only, needs a live SNP guest, and exercises only public-identity/idle phases. There is NO install_reference_agent_keystore helper anywhere in the repo (grep = 0). 2d's slice-3 Transport dials AF_UNIX only and its transport_uds_contract_test.exs documents the live PUBLIC_IDENTITY test as BLOCKED on this deliverable (tracked 2d-side as TASK-179). Needed: a test-only / deviceless agent-gateway server that speaks the 0x40 protocol over UDS (or stdio) WITHOUT a real SNP enclave, with a reference agent keystore installed, so the downstream consumer can contract-test PUBLIC_IDENTITY (and, behind preview features, the signing/capability/configure paths). Found by the 2026-06-17 cross-repo gap audit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A deviceless / non-SNP agent-gateway server binary or test harness serves the 0x40 protocol over AF_UNIX (or stdio) on Linux AND macOS, without requiring a live SNP guest or vsock
- [ ] #2 An install_reference_agent_keystore helper provisions a reference agent keystore (transfer key(s) + faucet treasury key) so PUBLIC_IDENTITY/PROVE_IDENTITY return real identities instead of 0x41/empty-store
- [ ] #3 The server can be driven by the downstream 2d AF_UNIX Transport for a live PUBLIC_IDENTITY 0x40 round-trip (unblocks 2d TASK-179); signing/capability paths reachable behind the existing preview features for slice-2 contract tests
- [ ] #4 Documented invocation (how 2d CI starts it) and its trust boundary vs the production AF_VSOCK/SNP serve path, so it is never mistaken for a production endpoint
- [ ] #5 The contract-test server is debug/test-only: when the preview-only signing/capability/configure paths are enabled it is NEVER built or promoted as a release artifact (release-banned the same way as the preview features it exposes — a release build with these paths must fail to compile / not ship the binary)
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped in PR #90 (MVP: PUBLIC_IDENTITY over UDS + install_reference_agent_keystore) + PR #91 (Slice 3: mutating ops GENERATE_KEYS/CONFIGURE_TREASURY/SIGN_FAUCET_DISPENSE via ReferenceCommitChannel). All 5 ACs met: cross-platform UDS server, reference keystore helper, 0x40 round-trip tested, documented invocation + trust boundary, release-banned via compile_error (lib.rs:107).
<!-- SECTION:FINAL_SUMMARY:END -->
