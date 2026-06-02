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

See `backlog/tasks/` for the full board.

| Task | Status | Summary |
|------|--------|---------|
| **TASK-2** | In progress | Vsock API + wire protocol (`impl/rust/enclave-protocol/`); **next:** Elixir shim + real vsock I/O |
| **TASK-3** | Done | Cryptographic `RecentChainProof` verification (Producer Chain Attestation v1) |
| **TASK-1** | In progress | ML-DSA-65 + seal v1 staging **merged** (`60eeefc`); platform root in real TEE + prod CI gate next |

**Reference implementation today:** ML-DSA-65 AuthorizationTicket signatures (when sealed signer installed), length-prefixed CBOR framing, canonical ticket hashing, enclave arming / hard-fork gating, Producer Chain Attestation v1. Details: `impl/README.md`, `backlog/docs/vsock-api-wire-format-spec-draft.md`.

**Next major increment:** **TASK-2** Elixir host shim + real vsock transport. **TASK-1 follow-ups:** platform `set_pq_seal_v1_provisioning_root`, no `reference-seal-v1-root` in prod builds. Staging PQ: `backlog/docs/pq-seal-v1-provisioning-runbook.md`.

## Development

This project uses the Backlog.md CLI for task tracking.

```bash
backlog board
```

## License

To be decided (likely Apache-2.0 or MIT, to be discussed).
