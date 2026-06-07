# 2d-hsm

Minimal, auditable post-quantum signing service (software HSM) designed to run inside Trusted Execution Environments (TEEs) for the 2d project.

## Purpose

The 2d blockchain project needs to perform post-quantum signatures (initially ML-DSA/Dilithium and SLH-DSA/SPHINCS+, later hybrid schemes) for BlockProducer canonical roots and bridge operations.

Current situation:
- 2d currently uses Nitrokey NetHSM (via REST API, brokered through Vault + OPA).
- As of mid-2026, the official Nitrokey NetHSM does not have production support for NIST post-quantum signature algorithms.
- The long-term architecture target for 2d is "software-NetHSM-in-TEE" (see `doc-3` in the main 2d repo).

Instead of waiting for vendor support or forking a heavy general-purpose HSM, this repository contains a purpose-built, minimal signing service that:
- Only implements what 2d actually needs.
- Runs inside confidential VMs / enclaves (AWS Nitro Enclaves, AMD SEV-SNP, etc.).
- Natively supports the required post-quantum algorithms from the beginning.
- Can later integrate hybrid iO schemes researched in the theory-378 project.

## Goals

- Very small, reviewable codebase.
- Strong focus on running inside TEEs with remote attestation.
- Clean integration path with the existing 2d signing infrastructure.
- Foundation for future hybrid (iO + classical) post-quantum signing.

## Non-Goals (at least initially)

- Full compatibility with the Nitrokey NetHSM REST API.
- General-purpose HSM features (clustering, advanced access control, etc.).
- Support for algorithms we don't currently need.

## Relationship to Other Repositories

- **2d** (main monorepo): Consumer of this service. Will call it for PQ signing operations.
- **theory-378**: Research on running heavy post-quantum schemes under iO. This service is expected to be one of the execution environments for hybrid schemes coming out of that research.

## Current Status

See `backlog/tasks/` for the full board (`backlog board`).

| Task | Status | Summary |
|------|--------|---------|
| **TASK-1** | In progress | Umbrella: minimal PQ signing service inside a TEE |
| **TASK-1.1** | In progress | Platform-derived PQ-seal + attestation-trust root (SEV-SNP `SNP_GET_DERIVED_KEY` / vTPM / Nitro) — mainnet keystone that replaces the lab fixtures |
| **TASK-1.2** | Done | SEV-SNP attestation verification: VCEK→ASK→ARK chain + image/chip binding (Turin product root) |
| **TASK-2** | Done | vsock API + wire protocol (`impl/rust/enclave-protocol/`): AuthorizationTickets + hard-fork flows |
| **TASK-3** | Done | Cryptographic `RecentChainProof` verification (Producer Chain Attestation v1) |
| **TASK-4** | Done | NixOS reproducible TEE image as the primary 2d-hsm delivery path |
| **TASK-5** | Done | Production enclave platform seal (SNP) + mainnet trust-provisioning gate |
| **TASK-6** | Done | ML-DSA secret-key zeroization in `pq_signer` validation |
| **TASK-7** | In progress | Agent Gateway secp256k1 signer — **7.1+7.2+7.3+7.4 merged** (#28 protocol/opcodes + domain separation + golden vectors; #29 sealed keystore + ML-KEM DR-backup format; #30 keygen + public identity; #31 structured transfer + faucet-dispense signing); **7.5 (host policy + capability integration) next**. Design: `backlog/docs/agent-gateway-secp256k1-signer-design.md`, `…-keystore-backup-format.md`, `…-keygen-identity.md`, `…-transfer-faucet-signing.md` |

**Reference implementation today:** ML-DSA-65 AuthorizationTicket signatures (sealed signer), length-prefixed CBOR vsock wire protocol with enclave arming / hard-fork gating, canonical ticket hashing, Producer Chain Attestation v1, relying-party SEV-SNP attestation (VCEK→ASK→ARK + image/chip binding), sealed-boot against the SNP-derived provisioning root, and a NixOS reproducible enclave image. Details: `impl/README.md`, `backlog/docs/vsock-api-wire-format-spec-draft.md`.

**In flight / next:** **TASK-1.1** platform-derived PQ-seal + trust root validated in a real TEE — the last gate before mainnet, since `productionMode` refuses lab fixtures — then **TASK-1.3** integration with the 2d signing path (Chain.Bridge.Signer / OPA / Vault). The **Agent Gateway secp256k1** backend (ordinary 2D faucet/transfer signing, a role separate from PQ block-producer signing): **TASK-7.1** (protocol opcodes + domain separation + golden vectors, #28), **TASK-7.2** (sealed keystore + ML-KEM encrypted backup/DR format, #29), **TASK-7.3** (secp256k1 keygen + public identity, #30), and **TASK-7.4** (structured ordinary-transfer + faucet-dispense signing, #31) merged; **TASK-7.5** (host policy + capability integration contract) is next. Staging PQ provisioning: `backlog/docs/pq-seal-v1-provisioning-runbook.md`.

## Development

This project uses the Backlog.md CLI for task tracking.

```bash
backlog board
```

## License

To be decided (likely Apache-2.0 or MIT, to be discussed).
