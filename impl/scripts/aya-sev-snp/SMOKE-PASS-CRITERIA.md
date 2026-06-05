# Smoke pass criteria (aya / CI)

Explicit expectations for PR #5 / TASK-4 Phase B verification. Scripts live in this directory.

## Nix path (preferred)

| Script | Flake VM | Pass signals |
|--------|----------|--------------|
| `run-nix-enclave-staging.sh` | none (host loopback) | `host-loopback-smoke: OK`; response contains `prod-enclave-v1`; ~2013 bytes |
| `run-nix-vm-guest-smoke.sh` | `.#vm` | `host-guest-vsock-smoke: OK cid=42 port=5000`; marker `prod-enclave-v1`; ~2013 bytes |
| `run-nix-vm-guest-smoke-prod.sh` | `.#vm-production` | OK cid=42; marker `enclave-measurement-placeholder`; ~80 bytes; **no** `pq_signing_ready` required |
| `run-nix-vm-guest-smoke-prod-lab.sh` | `.#vm-production-lab` | OK cid=42; marker `enclave-measurement-placeholder`; ~2030 bytes; CBOR key 6 = true (`pq_signing_ready`) |

Common: `GUEST_CID=42` matches QEMU `guest-cid=42` and guest `TWOD_HSM_VSOCK_CID=42`.

`vsock_smoke_client.py` decodes the GET_MEASUREMENT CBOR map (requires `cbor2`: `apt install python3-cbor2`).

## Ubuntu guest path (legacy)

| Script | Pass |
|--------|------|
| `host-loopback-smoke.sh` | `vsock-smoke: OK` on CID 1, staging measurement in body |
| `host-guest-vsock-smoke.sh` | OK on CID 42 after `guest-start-hsm.sh` |

## Review record (PR #5)

- **Reduced matrix:** roborev 6890–6892
- **Full matrix (2×3):** roborev 6893–6898 via `pse-review-2x3.sh --dirty`
- **Compact:** roborev 6900 — findings addressed in docs (lab trust naming, review gate, TASK-5 phases)