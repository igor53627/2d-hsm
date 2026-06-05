# Smoke pass criteria (aya / CI)

Explicit expectations for PR #5 / TASK-4 Phase B verification. Scripts live in this directory.

## Nix path (preferred)

| Script | Flake VM | Pass signals |
|--------|----------|--------------|
| `run-nix-enclave-staging.sh` | none (host loopback) | `host-loopback-smoke: OK`; response contains `prod-enclave-v1`; ~2013 bytes |
| `run-nix-vm-guest-smoke.sh` | `.#vm` | `host-guest-vsock-smoke: OK cid=42 port=5000`; marker `prod-enclave-v1`; ~2013 bytes |
| `run-nix-vm-guest-smoke-prod.sh` | `.#vm-production` | OK cid=42; marker `enclave-measurement-placeholder`; ~80 bytes; **no** `pq_signing_ready` required |
| `run-nix-vm-guest-smoke-prod-lab.sh` | `.#vm-production-lab` | OK cid=42; marker `enclave-measurement-placeholder`; ~2030 bytes; CBOR key 6 = true (`pq_signing_ready`) |

Common: host `GUEST_CID=42` matches QEMU `guest-cid=42`. NixOS guest binds `TWOD_HSM_VSOCK_CID=4294967295` (`VMADDR_CID_ANY`); Ubuntu SNP guest may use `VMADDR_CID_ANY` via `guest-start-hsm.sh`.

`vsock_smoke_client.py` decodes the GET_MEASUREMENT CBOR map (requires `cbor2`: `apt install python3-cbor2`).

## Ubuntu / SNP guest path

| Script | Pass |
|--------|------|
| `host-loopback-smoke.sh` | `host-loopback-smoke: OK` on CID 1; ~2013 bytes; `prod-enclave-v1` |
| `run-snp-smoke.sh` | Full E2E: SNP QEMU + `guest-start-hsm.sh` + vsock; OK cid=42; ~2013 bytes; `pq_signing_ready=true` |
| `host-guest-vsock-smoke.sh` | OK on CID 42 after manual `guest-start-hsm.sh` |

Requires `./warm-smoke-cache.sh` once (golden disk + cargo binary). Guest bind: `TWOD_HSM_VSOCK_BIND_CID=4294967295`; host: `GUEST_CID=42`.

## Review record (PR #5)

- **Reduced matrix:** roborev 6890–6892
- **Full matrix (2×3):** roborev 6893–6898 via `pse-review-2x3.sh --dirty`
- **Compact:** roborev 6900 — findings addressed in docs (lab trust naming, review gate, TASK-5 phases)
- **Operator sign-off:** aya 5/5 smokes on `d0ccd39` (2026-06-05), with `TWOD_HSM_CACHE`