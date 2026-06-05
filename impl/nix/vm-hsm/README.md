# vm-hsm — Nix flake (TASK-4)

Primary **production** delivery path for 2d-hsm TEE vsock binaries. Ubuntu/`cargo` on the host remain dev fallbacks until this flake is green on CI and aya.

## Quick start (Linux / `x86_64-linux`)

```bash
cd impl/nix/vm-hsm
nix flake lock                   # first time / after input bumps
nix build .#enclave              # release: bin/enclave-vsock
nix build .#enclave-staging      # debug: bin/enclave-vsock-staging (aya smokes)
nix build .#measurement-manifest # JSON artifact for CI / forkSpecHash input
cat result/manifest.json | jq .
```

### macOS (Apple Silicon)

Nix is installed via **Determinate Nix**; new shells load it from `/etc/zshrc`.

This flake targets **`x86_64-linux` only**. On a Mac you need one of:

1. **Native Linux builder** (Determinate): `determinate-nixd auth login` (FlakeHub) + access from Determinate — then  
   `nix build .#packages.x86_64-linux.enclave`
2. **Linux host** (e.g. aya, GitHub Actions) — recommended for first full build
3. **CI** — workflow `.github/workflows/nix-hsm.yml`

Pre-built `nixpkgs#legacyPackages.x86_64-linux.*` may work from cache; **compiling this Rust crate** needs a Linux builder or a Linux machine.

## Outputs

| Flake output | Binary | Features | Use |
|--------------|--------|----------|-----|
| `enclave` | `enclave-vsock` | `production-vsock` (release) | Production CVM (trust file at boot) |
| `enclave-production-transport` | `enclave-vsock` | `production-vsock` (debug) | `vm-production` guest only — transport smoke |
| `enclave-staging` | `enclave-vsock-staging` | `staging-vsock` | aya vsock smokes, `prod-enclave-v1` |
| `measurement-manifest` | `manifest.json` | — | Reproducibility + on-chain `forkSpecHash` helper (hashes release `.#enclave`, not transport debug) |

## Production runtime env

| Variable | Required | Purpose |
|----------|----------|---------|
| `TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE` | yes | 32-byte Ed25519 verifying key (producer attestation, not PQ key) |
| `TWOD_HSM_VSOCK_CID` / `TWOD_HSM_VSOCK_PORT` | no | vsock bind (NixOS guest defaults to `VMADDR_CID_ANY`; host uses QEMU `guest-cid`; see vsock spec §2.4) |
| Platform PQ seal / sealed signer | platform | `boot_configure_pq_seal_v1_platform_root` + `install_sealed_pq_signer` |

## Manifest schema (v1)

See `scripts/write-measurement-manifest.sh`. Fields include `git_revision`, `flake_lock` (hash of `flake.lock`), `artifacts.production.sha256`, and `fork_spec_hash_input` for 2d tooling.

**Not a TEE measurement source (until TASK-5 #4):** The manifest records **reproducible build inputs** (artifact SHA256 + git + lock hash). `protocol_measurement_label` for production is a **placeholder** (`enclave-measurement-placeholder`) matching the reference enclave until SNP/Nitro measurement is wired into `GET_MEASUREMENT`.

| Do | Do not |
|----|--------|
| Use `fork_spec_hash_input` for hard-fork **build reproducibility** tickets | Whitelist on-chain producer `measurement` from manifest JSON alone |
| Compare CI artifact SHA256 across rebuilds | Treat `protocol_measurement_label` as live attestation |
| Wait for TASK-5 #4 for BP whitelist against real TEE `measurement` | Deploy `vm-production` to mainnet (lab trust only — see below) |

Staging manifest label `prod-enclave-v1` matches the reference staging signer image, not production PQ provisioning.

## Phase B / TASK-5 guest profiles

> **Deployment warning:** None of the `vm-*` outputs below are mainnet Block Producer images.
> They use **lab/reference** attestation trust and (for `-lab`) file-based PQ seal. Do not ship
> `vm-production` or `vm-production-lab` to production without platform trust + SNP measurement (TASK-5 Phase 3).

| Flake output | Guest binary | Trust / seal | Use |
|--------------|--------------|--------------|-----|
| `vm` | `enclave-vsock-staging` | reference staging signer | Default aya guest smoke |
| `vm-production` | debug `enclave-vsock` (`enclave-production-transport`) | **lab** Ed25519 VK only (`lab-prod-fixtures`) | **Transport smoke** — `TWOD_HSM_TRANSPORT_ONLY_MODE=1`; no PQ seal |
| `vm-production-lab` | debug `lab-production-vsock` | lab VK + `TWOD_HSM_PQ_SEAL_*` files | Lab prod path; `pq_signing_ready` smoke |

Why `vm-production` still injects a **lab** trust file: `enclave-vsock` fails closed at boot without
`TWOD_HSM_PRODUCER_ATTESTATION_TRUST_FILE`. Platform-provisioned production VK is TASK-5 #2 (not merged here).

| | `vm-production` | `vm-production-lab` |
|--|-----------------|---------------------|
| Nix enclave attr | `enclave-production-transport` (debug `production-vsock`) | `enclave-production-lab` (`lab-production-vsock`) |
| PQ seal | no (`TRANSPORT_ONLY_MODE`) | yes (file-based, lab only) |
| Safe for mainnet | **no** | **no** |

Real TEE `measurement` in `GET_MEASUREMENT` → TASK-5 Phase 3 (SNP/Nitro).

## Related

- `backlog/tasks/task-4 - NixOS-reproducible-TEE-image-primary-delivery-path.md`
- `impl/rust/enclave-protocol/`
- `impl/scripts/aya-sev-snp/`