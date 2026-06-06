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

## NixOS under SNP — real measurement (TASK-5 AC#5)

| Script | Flake disk | Pass signals |
|--------|------------|--------------|
| `run-nix-snp-guest-smoke.sh` | `.#disk-production-lab` | `[PASS] ... real_measurement=1, pq_ready=1`; CID 42; CBOR key 2 = **48 raw bytes** (not `enclave-measurement-placeholder` / `prod-enclave-v1`); key 3 = real SNP report (≥1184 B, not `attestation-placeholder`); key 6 = true |
| `SEV_MODE=none run-nix-snp-guest-smoke.sh` | `.#disk-production-lab` | KVM fallback boots; gate auto-relaxes to `require_real=0`, matches placeholder label; `pq_ready=1` (lab signer present even off-SNP) |
| `DISK_ATTR=disk-production run-nix-snp-guest-smoke.sh` | `.#disk-production` | boot-only (transport); auto `require_real=0 require_pq=0` (no operational signer ⇒ placeholder) |

Gates auto-adjust to disk + mode (lab+SNP ⇒ real measurement + pq; transport or
off-SNP ⇒ placeholder), so no manual `VSOCK_SMOKE_*` env is needed. The
real-measurement gate (`VSOCK_SMOKE_REQUIRE_REAL_MEASUREMENT=1`,
`assert_measurement_fields`) asserts a 48-byte launch measurement distinct from the
dev/staging labels plus a real (≥1184 B) VCEK-signed report — a structural smoke
check, not a cryptographic verifier (VCEK-chain validation is deferred). It is the
live counterpart to AC#4 (enclave-side capture) and needs an SNP host (aya EPYC); CI
only evals the disk-image derivation.

Requires `./warm-smoke-cache.sh` once (golden disk + cargo binary). Guest bind: `TWOD_HSM_VSOCK_BIND_CID=4294967295`; host: `GUEST_CID=42`.

## Review record (PR #5)

- **Reduced matrix:** roborev 6890–6892
- **Full matrix (2×3):** roborev 6893–6898 via `pse-review-2x3.sh --dirty`
- **Compact:** roborev 6900 — findings addressed in docs (lab trust naming, review gate, TASK-5 phases)
- **Operator sign-off:** aya 5/5 smokes on `d0ccd39` (2026-06-05), with `TWOD_HSM_CACHE`